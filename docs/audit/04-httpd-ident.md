# A4 审查记录：hnc_httpd 应用识别 / 前台判断 / 流量分类 / 新应用发现

- 基线版本：v5.33.0-rc2
- 审查员前缀：A4
- 范围（daemon/hnc_httpd/）：app_time.go、app_usage.go、fg_engagement.go、fg_hmm.go、fg_model.go、flow_cls.go、flow_shape.go、fp_learn.go、fp_user_rules.go、startup_fp.go、traffic_ident.go、self_fg_truth.go、dpi_eval.go、dpi_eval_discover.go、api_discover.go、api_discover_shared.go、api_discover_suggest.go、api_dpi_history.go、api_dpi_v53.go
- 只记录真 bug，不改代码。

## 已审文件

- api_dpi_v53.go：无问题（读文件失败走 available=false；readJSON 无大小上限但文件由 dpid 写，属可信本地输入）
- fg_engagement.go：无问题
- flow_cls.go：A4-001、A4-002、A4-003；lint 提示 clsBigCats 未使用——核实为死代码，预测只对模型里出现过的类打分，不存在漏接逻辑
- flow_shape.go：无问题（fsSt 只在 app_usage 单 goroutine 改，fsPub 有锁；流表 16384 上限 + 结束 60 秒清理）
- app_usage.go：A4-005
- fp_learn.go：无问题（置信度恒有限，FPW 不会出现 NaN；绑定表有上限与空闲清理）
- fp_user_rules.go：A4-004
- app_time.go：A4-006；lint 提示 app_time.go:704 kind 初值被浪费——核实为无害死赋值（switch 每个分支都赋值或 continue）
- traffic_ident.go：无问题（identSt 全程在 appUsage.mu 下；各表有上限与按时间清理；暂缓连接的字节在共现窗口合上后随 released 补记）
- self_fg_truth.go：A4-007

## Bug

### A4-001 [P2][确认] 流量形状分类器样本池无上限：生产路径绕过 fcPoolAdd，内存与重训耗时只增不减
- **位置**：`daemon/hnc_httpd/flow_cls.go:371`（对照 `flow_cls.go:178` 的 `fcPoolAdd`）
- **触发 / 现象**：热点客户端持续使用（每条已识别、≥3 轮采样且已结束的流都收一条样本），httpd 长期不重启。`fcPool` 永不淘汰：每条样本约 150 字节，日均上万条连接时每天约 1.5 MB、按周按月线性涨；每 30 分钟重训（`flow_cls.go:390`）和每次 `/api/dpi_eval`（`flow_cls.go:436`）都要把整个池复制一遍再全量训练，耗时随之线性增长。文件头写的「池按类上限 2000 条、按时间淘汰」实际不成立。
- **原因**：唯一实现上限淘汰的 `fcPoolAdd` 只在 `flow_cls_test.go` 里被调用；生产路径 `flowClsTick` 直接追加：
  ```go
  fcPool = append(fcPool, added...)   // flow_cls.go:371，没有按类上限，也没有按时间淘汰
  ```
  测试 `flow_cls_test.go:124/246` 只验证了 fcPoolAdd 这个没人调用的函数，把「有上限」锁成了期望，掩盖了生产路径无上限。
- **建议修复**：`flowClsTick` 改成逐条走 fcPoolAdd（或在追加后按类裁到 fcPoolPerCat）；测试改为驱动 flowClsTick 来验证上限。

### A4-002 [P3][确认] 流量形状分类器「平均包长」一维的分箱边界单位错了，该维恒落第 0 箱（特征失效）
- **位置**：`daemon/hnc_httpd/flow_cls.go:113`（边界）、`flow_cls.go:146`（取值）
- **触发 / 现象**：任何连接。平均包长 psz 最大也就 1500 字节左右（GRO 聚合也不超过 64 KB），`log10(psz+1)` 最大约 3.2（GRO 极端约 4.8），永远小于第一条边界 5.2，所以第 7 维对所有样本都是 0 箱，训练和预测里这一维完全不提供信息；文件头和 CHANGELOG 宣称的「包长」特征实际不存在。
- **原因**：边界按自然对数（e^5.2≈181、e^7.3≈1480）或别的尺度写的，取值却用 log10：
  ```go
  {5.2, 5.9, 6.6, 7.3},    // 7  log10(平均包长 字节) ~160/500/1600/4k/…
  ...
  lg := func(x float64) float64 { return math.Log10(x + 1) }
  v[7] = fcBinOf(lg(f.psz), fcEdges[7])
  ```
  注释里的 160/500/1600/4k 对应的 log10 值应是 2.2/2.7/3.2/3.6。测试夹具 psz=1200/180/800 也全落 0 箱，所以测试没发现。
- **建议修复**：边界改成 log10 尺度（如 {2.2, 2.7, 3.2, 3.6}），并同步把 fcJSONVersion 加 1，让旧模型文件作废。

### A4-003 [P3][确认] 流量形状分类器的持久化模型在重启 30 分钟后被「只用重启后样本」训出的小模型覆盖
- **位置**：`daemon/hnc_httpd/flow_cls.go:388-399`
- **触发 / 现象**：httpd 重启（升级、看门狗拉起、关机重开）。样本池只在内存里，重启后为空；首轮读回 `data/flow_cls.json` 用上，但 30 分钟后的第一次重训只用这 30 分钟收到的少量样本训练，直接替换内存模型并覆盖写回文件，之前积累的模型丢掉。如果这 30 分钟里只收到一个大类的样本，NCat 里只有一类，`fcPredict` 对所有未识别连接都输出这一类、置信度 1.0。CHANGELOG 写的是「30 分钟增量重训」，实际是用内存池全量重训。
- **原因**：
  ```go
  if !haveModel || now.Sub(fcLastTrain) >= fcRetrainEvery {
      snap := append([]fcSample(nil), fcPool...)   // 只含本进程启动以来的样本
      if m := fcTrain(snap, now.Unix()); m != nil { // 没有最少样本数 / 最少类数门槛
          fcLiveModel = m
          _ = fcSaveModel(hncDir, m)                // 覆盖已存模型
  ```
- **建议修复**：把样本池（带上限）和模型一起持久化、启动时读回；或者在已存模型的计数上做增量合并；再加一个最少样本数 / 最少类数门槛，不够就不替换。

### A4-004 [P3][确认] 用户纠正规则文件读失败 / 损坏时当成空表，下一次「纠正」会把整份文件覆盖成只剩新规则
- **位置**：`daemon/hnc_httpd/fp_user_rules.go:97-108`（readDPIUserRules）、`fp_user_rules.go:385-427`（actionDPICorrect 写回）
- **触发 / 现象**：`data/dpi_user_rules.json` 被手工改坏（文件头明确说「手工改文件也能跟上」），或读文件遇到非「不存在」的错误（EACCES / EIO）。此时所有用户纠正规则已静默失效；用户随后在界面上再做一次「纠正」，`cur` 为 nil，`kept` 只含本次新增的规则，`writeDPIUserRules` 原子覆盖，原文件里的全部规则永久丢失，没有任何提示。
- **原因**：
  ```go
  b, err := os.ReadFile(dpiUserRulesPath(hncDir))
  if err != nil || len(b) > 1<<20 { return nil }      // 不区分「不存在」和「读失败 / 超大」
  if json.Unmarshal(b, &f) != nil { return nil }        // 损坏也当空表
  ...
  cur := readDPIUserRules(s.hncDir)                     // 写路径照样用它
  kept := make([]dpiUserRule, 0, len(cur)+len(add))
  ```
  同包里的 `readJSONInto`（action_candidate.go）已经按「损坏 = 报错、不覆盖」处理，这里没跟上。
- **建议修复**：写路径单独读：文件不存在才当空表；读失败 / 解析失败就拒绝写入并返回错误（或先把坏文件备份成 `.bad`）。

### A4-005 [P3][确认] /api/app_usage 按设备筛选时，「共现推断」字节没走 MAC 合并映射，合并过的旧 MAC 的推断字节被漏掉
- **位置**：`daemon/hnc_httpd/app_usage.go:471-478`
- **触发 / 现象**：设备换过 MAC 并已合并（macAliasResolver 把旧 MAC 历史归到新 MAC），查询 `/api/app_usage?mac=<新MAC>`。同一循环里 Hours（字节）和 Active（时长）都用 `resolve()` 把旧 MAC 归到新 MAC，Inferred 却直接比原始 MAC，旧 MAC 名下的推断字节被跳过：`inferred_bytes`（总量与 by_app 每行）偏小，界面上「推测」占比偏低，与同一行的 up/down 口径不一致。
- **原因**：
  ```go
  for mk, v := range d.Inferred {
      sep := strings.IndexByte(mk, '|')
      if sep < 0 || (mac != "" && mk[:sep] != mac) {   // 少了 resolve(mk[:sep])
  ```
  对照下面的 Active：`if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac)`。
- **建议修复**：改成 `resolve(mk[:sep]) != mac`，与 Hours / Active / srcAgg 保持一致。

### A4-006 [P3][确认] 应用时长上限 / 类别封锁配置文件损坏时静默当空表，管控失效，下一次设置会覆盖掉全部旧配置
- **位置**：`daemon/hnc_httpd/app_time.go:465-471`（loadAppControls），写回见 `app_time.go:821-837`、`851-867`、`914-935`
- **触发 / 现象**：`data/app_controls.json` 损坏（手工编辑出错、写满盘后残缺等）。`loadAppControls` 忽略解析错误返回空结构：所有设备的时长上限和类别封锁立即静默失效（家长管控「放行」），设备卡上也不再显示；用户随后对任何设备做一次 `app_time_limit_set` / `category_block_set`，就把只含这一条的配置原子写回，原文件里其余设备的配置永久丢失，没有任何提示。
- **原因**：
  ```go
  func loadAppControls(hncDir string) appControlsFile {
      var f appControlsFile
      if b, err := os.ReadFile(appControlsPath(hncDir)); err == nil {
          _ = json.Unmarshal(b, &f)          // 解析错误被丢弃
      }
      return f
  }
  ```
  三个动作都是「loadAppControls → 改一条 → saveAppControls」。
- **建议修复**：区分「文件不存在」与「读 / 解析失败」；写路径遇到后者拒绝写入并报错（或先备份坏文件），读路径在自检 / 告警里提示配置文件损坏。

### A4-007 [P3][确认] 本机前台真值不记录熄屏 / 关采集的时段，评估把这段时间都算成「上一个前台应用在前台」
- **位置**：`daemon/hnc_httpd/self_fg_truth.go:75-88`（采集循环），消费方 `startup_fp.go:1229-1250`（startupFGMatch）
- **触发 / 现象**：本机开着「本机流量归因」，用户在 App X 里熄屏（或关掉采集开关），几小时后亮屏。熄屏期间循环直接 `continue`，既不写「熄屏 / 无前台」标记，也不清 `lastPkg`；亮屏后如果前台还是 X 也不会写新行。`startupFGMatch` 用「≤ t 的最后一条记录」当 t 时刻的前台，于是整段熄屏时间都被当成 X 在前台：熄屏期间后台 App 被识别出的启动事件会被判错（或恰好是 X 时被判对），启动指纹交叉验证的 event_accuracy 失真。跨零点同理：当天文件里第一条记录之前的时段没有前台（`cur=""`），上一天延续下来的前台被判成无。
- **原因**：
  ```go
  if !selfFGEnabled(s.hncDir) || !screenOnNow() {
      iv = selfFGMaxInterval
      continue                      // 不写标记，lastPkg 保留
  }
  pkg, src := readForegroundPkg(runDumpsysCmd)
  if pkg == "" || pkg == lastPkg { ... continue }
  ```
- **建议修复**：进入熄屏 / 关采集时写一条 `pkg:""`（或 source:"screen_off"）的记录并清空 `lastPkg`；消费方把这类记录当作「无前台」。

