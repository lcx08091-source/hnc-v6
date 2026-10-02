# 工作文档:HNC v5.24.0-rc1「DPI 3.0 地基 · 本机标签工厂 + 识别自评」

> 本文档交给接手开发的 AI 编程助手(DeepSeek / GLM 等)执行。
> **请完整读完再动手。** 第 2 节的「边界」是硬约束,违反任何一条都视为任务失败。
> 背景资料:`docs/CODEMAP.md`(代码地图)、`docs/ROADMAP.md`(路线图 §A / §1)、`docs/API.md`(接口)、`CHANGELOG.md`(历史)。

---

## 0. 你在做什么(一句话)

让开热点的这台手机**用自己的流量给自己出「标准答案」**:本机上每条 TLS / QUIC 连接都能通过 UID 查到真实的 App 包名;把「包名 + 这条连接的域名 / 指纹」记成**带标签样本**,再用这些样本给 HNC 现有的识别方法**打分**(覆盖率、准确率、最常认错的应用),在设置页显示出来。

**v5.24 只做「采集样本 + 打分 + 显示」,不改变任何现有识别结果、不改变任何限速 / 封锁行为。**

---

## 1. 项目基本情况(必读)

- Android root 模块(KernelSU / SukiSU / Magisk),运行目录 `/data/local/hnc/`(代码里叫 `hncDir`),下有 `data/`(持久化)、`run/`(运行时,可丢)、`logs/`。
- 相关进程:
  - `hnc_dpid`(`src/dpid/`,Go):抓包识别。**本机抓包**在 `src/dpid/cmd/dpid/self_capture.go`,只在标志文件 `run/self_capture.enabled` 存在时运行(WebUI 的「本机流量归因」开关 / `POST /api/self/toggle` 控制)。
  - `hnc_httpd`(`daemon/hnc_httpd/`,Go):HTTP API + 汇总。路由注册在 `server.go`。
  - WebUI:`webroot/js/*.js`,**普通 `<script>`,共享全局作用域,按 index.html 顺序加载**,不要改成 ES module。
- Go 版本:httpd 是 `go 1.25.0`,dpid 是 `go 1.22`(以各自 `go.mod` 为准,不要改)。arm64 用 `CGO_ENABLED=0 GOOS=android GOARCH=arm64`;**32 位只做类型检查** `CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7`(android/arm 必须 cgo + NDK 链接,真 armv7 包由 CI 构建)。**不要新增任何第三方依赖。**
- 代码风格:注释用中文,跟随周边代码的密度与写法;Go 用 `gofmt`。

### 1.1 现成可用的代码(直接复用,不要重写)

| 需要 | 在哪 |
|---|---|
| 本机 TLS ClientHello 事件(含 SNI / JA4 / ALPN / 是否 QUIC / ECH / Partial) | `self_capture.go` 里 `h.Run(ctx, func(ev capture.Event){ case capture.EventTLSClientHello: ... })`,字段见 `src/dpid/capture/parse.go` 的 `Event` / `TLSInfo` |
| 远端地址 → 本机 UID / 包名 | `selfAttrib.LookupUID(ev.DstIP.String(), ev.DstPort)` 返回 `(uid, pkg, ok)`;`selfAttrib.PkgForUID(uid)`(`src/dpid/output/self_attrib.go`) |
| 域名 → 应用(规则库) | `classifyHost(host)`(`src/dpid/output/classify.go`),返回 `l3Rule{ID, Name, Category, ...}` |
| 包名 → 中文显示名 | `src/dpid/appmeta/labels.go` 的 `curatedLabels`,`appmeta.Resolver.Display(pkg)` |
| TLS 指纹学习表 | `daemon/hnc_httpd/fp_learn.go`:`fpFor(hncDir)` 取 store;`fpKeyOf(ja4, alpn, port)`、`fpPortClass(dport)`;条目 `(*fpEntry).verdict(now)` 返回 `fpVerdict{Top, TopName, Usable, Generic, Conf, ...}`。**读之前先看 `ingestLocked` 里 alpn / port 是怎么归一化的,必须用同样的方式拼 key。**访问 `st.m` 要持有 store 的锁(看现有代码怎么加锁) |
| IP 归属 | `daemon/hnc_httpd/ip_owner.go` 的 lookup(看 `ipOwnerConfigure` / 全局 db 的取法) |
| 原子写文件 | dpid:`src/dpid/output/state.go` 的 `atomicWrite`;httpd:`action_v511.go` 的 `writeFileAtomic` |
| 执行外部命令(带超时、防僵尸) | httpd:`action.go` 的 `hardenCmd(exec.CommandContext(...))` 模式 |
| 活动档位 / 是否亮屏 | `run/activity.json`(`power_activity.go`,字段 `screen_on`、`screen_known`、`level`) |
| 写 JSON 响应 | httpd 的 `writeJSON(w, code, v)` |
| 敏感只读接口登记 | `middleware.go` 的 `isSensitiveReadPath` |

---

## 2. 边界(硬约束)

### 2.1 不许动
1. **不改变任何现有识别输出**:`/api/devices`、`/api/connections`、`/api/app_usage`、`traffic_ident.go`、`fg_model.go`、`flow_shape.go`、`fp_learn.go` 的**判断逻辑**一律不改(只允许**只读**地调用它们的函数 / 读它们的数据)。
2. **不碰 tc / iptables / 限速 / 封锁 / 配额 / 分时段**:`bin/tc_manager.sh`、`bin/iptables_manager.sh`、`bin/apply_*.sh`、`bin/watchdog.sh`、`limit_policy.go`、`conn_blocks.go` 等不改。
3. **不改开机脚本与权限白名单**:`post-fs-data.sh`、`service.sh`、`customize.sh`。本任务**不新增任何二进制、不新增 shell 脚本**。
4. **不改数据格式**:已有的 `data/*.json`、`run/*.json` 结构不改;只新增文件。
5. **不改 CI**:`.github/workflows/` 不动。
6. **不引入第三方依赖**,不改 `go.mod` 的依赖列表。
7. **不做大重构**:不重命名 / 移动现有文件,不改现有函数签名。
8. **不上传任何数据**到网络;样本只存本机。

### 2.2 隐私要求
- 只采集**本机自己**的流量(`self_capture`),**绝不**采集热点客户端设备的数据作为样本。
- 样本里**不存**完整 URL、内容、Cookie;只存:时间、包名、SNI(域名)、JA4、ALPN、端口、是否 QUIC、远端 IP。
- 样本文件保留 **7 天**,自动删除;提供一键清除。

### 2.3 资源要求
- 新增后台循环必须遵守活动档位:**熄屏 / 档位为 `off` 或 `idle` 时不跑或降到很低频率**(参考 `power_sched.go` 的用法)。
- 样本写入**限流**:同一 `(pkg, sni, ja4)` 组合 10 分钟内只记一次;单日文件超过 **20 MB** 停止写入当天样本并在评估结果里标记 `capped:true`。
- 评估计算每次 < 1 秒(在样本量 10 万条以内)。

---

## 3. 任务拆分(按顺序做,每个任务独立可测)

### T1 · dpid:写本机带标签样本(✅ v5.24.0-rc1 已完成;计数快照见 `run/label_samples.stats.json`,T4 直接读它取 `skipped_system`)
**文件**:新建 `src/dpid/output/label_samples.go` + `label_samples_test.go`;在 `self_capture.go` 的 `EventTLSClientHello` 分支里**追加一次调用**(不改原有逻辑,原有 `ObserveSNI` 照常执行)。

**行为**:
- `LookupUID` 成功且 `pkg != ""` 时,构造样本并交给一个带缓冲的写入器(goroutine + channel,channel 满就丢弃,绝不阻塞抓包回调)。
- 去重:内存里 `map[pkg|sni|ja4]lastTs`,10 分钟内重复的不写;map 超过 5 万条时清空。
- 跳过:`pkg` 为空、SNI 为空、uid < 10000(系统 UID,可先跳过,写进评估结果的 `skipped_system` 计数)。
- 写入 `run/label_samples.YYYYMMDD.jsonl`(按本地日期),一行一个 JSON。
- 启动时和每天第一次写入时,删除 7 天前的 `label_samples.*.jsonl`。
- 单日文件 > 20 MB 时停止写,并写一个标记文件 `run/label_samples.YYYYMMDD.capped`。

**样本格式**(字段名固定,不要改):
```json
{"ts":1759380000,"pkg":"com.ss.android.ugc.aweme","uid":10234,
 "sni":"api.amemv.com","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","alpn":"h2",
 "dport":443,"quic":false,"ech":false,"partial":false,"rip":"203.107.13.2",
 "rule_id":"douyin","rule_name":"抖音"}
```
- `rule_id` / `rule_name`:用 `classifyHost(sni)` 在**写入时**算出(没命中就省略这两个字段)。这样 httpd 端不用再加载 dpid 的规则库。
- `alpn`:取 `TLSInfo.ALPN` 的第一个,没有就省略。

**单元测试**:去重、跳过规则、日期滚动、过期删除、超限停止、channel 满时不阻塞。

---

### T2 · httpd:本机前台真值采集
**文件**:新建 `daemon/hnc_httpd/self_fg_truth.go` + `_test.go`;在 `main.go` 启动处**加一行**启动它。

**行为**:
- 每 10 秒一次;**仅当** `run/activity.json` 里 `screen_known && screen_on` 时执行,否则跳过。
- 仅当标志文件 `run/self_capture.enabled` 存在时运行(和本机抓包同一个开关)。
- 取前台包名(依次尝试,第一个成功即用,每个命令超时 2 秒,用 `hardenCmd`):
  1. `dumpsys activity activities`,找含 `topResumedActivity` 或 `mResumedActivity` 的第一行;
  2. `dumpsys window`,找含 `mCurrentFocus` 或 `mFocusedApp` 的第一行;
  - 从行里用正则 `([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/` 取包名。
  - **注意**:ColorOS / Android 16 的输出格式可能不同,解析要宽松,失败就记 `source:"none"` 并在评估结果里体现,**不要 panic**。
- **只在前台包名变化时**写一行到 `run/self_fg.YYYYMMDD.jsonl`:
  ```json
  {"ts":1759380000,"pkg":"com.ss.android.ugc.aweme","source":"activities"}
  ```
- 同样 7 天过期删除。
- 输出解析函数要能单测:把真实格式的样例文本(自己构造几种:Android 12 / 14 / 16 风格)喂给解析函数测试。

**v5.24 只采集,不拿它评估**(前台评估留到 v5.25 做 HMM 时用)。评估结果里只报告「已记录多少次前台切换、最近一次是什么、取数方式」。

---

### T3 · 包名 → 应用 ID 对照表
**文件**:新建 `data/pkg_app_map.json`(数据)+ `tools/build_pkg_app_map.py`(生成脚本,纯标准库)+ httpd 里加载它的代码(放在 T4 的文件里即可)。

**格式**:
```json
{"schema":1,"map":{"com.ss.android.ugc.aweme":"douyin","com.ss.android.ugc.aweme.lite":"douyin", "com.tencent.mm":"wechat"}}
```
- 值是规则库里的应用 `id`(`data/dpi_rules.json` 与 `data/dpi_rules.d/*.json` 中每条规则的 `id`)。
- 生成方法:读 `src/dpid/appmeta/labels.go` 里 `curatedLabels` 的「包名 → 中文名」,再按中文名匹配规则库的 `app` 字段得到 `id`;匹配不上的列在脚本输出里,**由人工补**,不要猜。
- 一个应用可以对应多个包名(极速版、国际版等)。
- 评估时:真值 = `map[pkg]`;如果包名不在表里,真值记为 `"pkg:" + pkg`(这样仍能统计「这个包从来没被认出来」)。
- **`data/pkg_app_map.json` 要加进 `bin/artifact_sanity_check.sh` 的必需文件列表**(照着已有的 `data/ip_owner.bin` 那一行加,这是本任务唯一允许改的 shell 文件)。

---

### T4 · httpd:识别自评
**文件**:新建 `daemon/hnc_httpd/dpi_eval.go` + `dpi_eval_test.go`;`server.go` 注册路由;`middleware.go` 的 `isSensitiveReadPath` 加上新路径。

**计算**(每 10 分钟一次 + 接口可触发一次重算;熄屏且档位低时不跑):
1. 读最近 24 小时(可选 7 天)的 `label_samples.*.jsonl`。
2. 每条样本的真值 `truth` 由 T3 得出。
3. 对每条样本,分别算各方法的预测:
   - `rule`:样本里的 `rule_id`;
   - `fp`:用 `ja4 + alpn + fpPortClass(dport)` 去指纹表查 verdict,`Usable && !Generic` 时预测为 `Top`;
   - `owner`:IP 归属是 `app` 类时预测为 `_org:<key>`(只算「认出是哪家公司」,和真值比较时用「真值应用所属公司」——如果做不到映射,这一项只统计覆盖率不算准确率,并在结果里注明);
   - `combined`:按现有优先级 用户纠正 > 规则 > 指纹 的顺序取第一个有结果的(用户纠正规则读 `fp_user_rules.go` 的只读函数)。
4. 指标(每种方法都算):
   - `coverage` = 有预测的样本数 / 总样本数
   - `accuracy` = 预测 == 真值的样本数 / 有预测的样本数
   - `samples`、`predicted`、`correct`
5. 按应用汇总:每个真值应用的样本数、`combined` 的覆盖率与准确率;列出**最常认错的前 10 个**(真值 → 被认成什么、次数)和**最常认不出的前 10 个**(真值、样本数、最常见的 SNI 3 个)。
6. 结果写 `run/dpi_eval.json`,结构就是接口返回的结构。

**接口** `GET /api/dpi_eval[?days=1|7][&refresh=1]`:
```json
{"ok":true,"generated_at":1759380000,"days":1,"enabled":true,
 "samples":1234,"apps":37,"capped":false,"skipped_system":56,
 "methods":{
   "rule":    {"samples":1234,"predicted":980,"correct":951,"coverage":0.79,"accuracy":0.97},
   "fp":      {...}, "owner": {...}, "combined": {...}},
 "by_app":[{"truth":"douyin","name":"抖音","samples":210,"coverage":0.92,"accuracy":0.99}],
 "top_wrong":[{"truth":"douyin","pred":"toutiao","pred_name":"今日头条","n":12}],
 "top_unknown":[{"truth":"pkg:com.example.app","name":"com.example.app","n":40,"snis":["a.example.com"]}],
 "fg_truth":{"switches_24h":88,"last_pkg":"com.tencent.mm","last_ts":1759379900,"source":"activities"},
 "note":""}
```
- 本机抓包没开时:`enabled:false`,其他字段为空,`note` 说明「需要在设置里开启本机流量归因」。
- 动作 `dpi_eval_clear`(在 `action.go` 的 dispatch 里**新增一个 case**,不改其他 case):删除所有 `label_samples.*`、`self_fg.*`、`dpi_eval.json`。

**单元测试**:用构造的样本文件 + 构造的指纹表 / 对照表,验证每个指标的计算;空数据、全部未命中、包名不在对照表的情况;`days` 参数非法返回 400。

---

### T5 · WebUI:设置 → 应用识别 → 「识别自评」
**文件**:只改 `webroot/js/settings.js`(加函数 + 在「应用识别」分组里插入一个折叠项)、`webroot/js/main.js`(折叠展开时加载、清除按钮的点击处理)、`webroot/css/base.css`(如需少量样式,追加在文件末尾)。

**参照现成写法**:`settings.js` 里 v5.23 新加的 `dnsTakeoverFold()` / `loadDNS()` / `paintDNS()` 和 `fpFold()` / `loadFP()` / `paintFP()` —— **完全照这个模式写** `evalFold()` / `loadEval()` / `paintEval()`:
- 折叠 key 用 `'deval'`;展开时 `loadEval()`;内容容器 `<div id="eval-body">`,绘制后 `setAttribute('data-keep','')`(防止后台刷新覆盖,原理见 `core.js` 的 `morph`)。
- 在 `main.js` 的 `case 'fold':` 分支里,照 `if (opened && key === 'dnst') loadDNS();` 加一行。
- 显示内容:
  1. 本机流量归因没开 → 一句说明 + 按钮「去开启」(调用已有的本机流量归因开关接口)。
  2. 顶部四个数字:样本数、覆盖率、准确率(combined)、涉及应用数。
  3. 各方法一行:规则库 / 指纹 / IP 归属 的覆盖率与准确率。
  4. 「最常认错」「最常认不出」各前 5 条。
  5. 前台记录:24 小时切换次数、最近一次、取数方式(`none` 时提示「这台手机的系统没取到前台应用,v5.25 的前台评估可能不可用」)。
  6. 底部:「只用这台手机自己的流量,样本保存 7 天,不上传」+ 按钮「清除样本」(二次确认,用已有的 `confirmSheet`)。
- 切换 1 天 / 7 天:用 `seg('eval-days', [[1,'24 小时'],[7,'7 天']], ...)`,在 `main.js` 的分段控件处理里加 `k === 'eval-days'` 分支。
- 文案全部中文,口语化,和现有界面一致。

**不允许**:改其他页面、改现有折叠、改 `core.js` / `sheets.js` / `fx.js`、改 `index.html`(改 index.html 会破坏 CSP 哈希)。

---

### T6 · 版本与文档
1. `module.prop`:`version=v5.24.0-rc1`,`versionCode=5240001`。
2. `CHANGELOG.md`:在最上面(`## [5.23.0-rc1]` 之前)加 `## [5.24.0-rc1] - <日期>`,格式照 5.23 那段(Added / Changed / Fixed / 需真机验证)。
3. `webroot/changelog.html`:在最上面加一段,格式照 `<!-- v5.23.0-rc1 -->` 那段,写给普通用户看的大白话。
4. `docs/API.md`:末尾加「## 22. v5.24 识别自评」,写 `GET /api/dpi_eval`、动作 `dpi_eval_clear`、两个 jsonl 文件格式。
5. `docs/ROADMAP.md`:§A 表格里 v5.24 一行后面标「✅ 已完成(rc1)」。

---

## 4. 自检命令(提交前全部要过)

在仓库根目录:
```sh
# Go:两个模块分别
(cd daemon/hnc_httpd && gofmt -l . && go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /tmp/h64 . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && gofmt -l . && go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /tmp/d64 ./cmd/dpid \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd     # 编译残留会让测试失败

# 前端语法
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done

# 仓库自带检查
sh test/run_all.sh                    # 期望: ALL PASS(当前基线 415/416, 1 skipped;你新增测试后数字会变,但不能有 FAIL)
sh bin/version_consistency_check.sh   # failures=0
sh bin/ci_preflight.sh                # failures=0
python3 tools/build_pkg_app_map.py --check   # 你写的脚本需支持 --check:对照表与规则库一致
```
`gofmt -l` 必须没有输出。任何一步失败都要修好,**不许通过删除 / 跳过测试来变绿**。

---

## 5. 验收清单

- [ ] 第 2 节所有边界都没有违反(`git diff --stat` 里只出现第 3 节列出的文件 + 新增文件)。
- [ ] 本机抓包关闭时:不产生任何样本文件,`/api/dpi_eval` 返回 `enabled:false`,界面显示开启说明。
- [ ] 本机抓包开启、正常用手机 10 分钟后:`run/label_samples.<今天>.jsonl` 有内容,格式与 T1 一致;`/api/dpi_eval?refresh=1` 有数字。
- [ ] 熄屏时不采集前台、评估不跑。
- [ ] 「清除样本」后文件全部删除,界面回到空状态。
- [ ] 现有功能行为不变:`/api/devices`、`/api/connections`、`/api/app_usage` 的输出与改动前一致(同样输入下)。
- [ ] 第 4 节全部命令通过。
- [ ] 版本号、CHANGELOG、changelog.html、API.md、ROADMAP.md 已更新。

---

## 6. 提交方式

- 在分支 `claude/environment-config-ydr2ow` 上开发(或从它新建分支),**每个任务一个提交**,提交信息中文,格式:`v5.24 T1: dpid 写本机带标签样本`。
- **不要推送到 `main`**:推 main 会自动发版。全部完成、自检通过后告诉项目负责人,由他决定是否合并发版。
- 不要改 `CLAUDE.md`。

---

## 7. 常见坑

1. **抓包回调里不能阻塞**:写文件一律走 channel + 后台 goroutine。
2. **`dumpsys` 很慢且可能卡住**:必须带超时(2 秒)且用 `hardenCmd`,否则会留下僵尸进程。
3. **ColorOS 的 `dumpsys` 输出格式和原生不同**:解析失败要降级,不能崩。
4. **armv7 是 32 位**:`int` 只有 32 位,时间戳、字节数一律用 `int64` / `uint64`。
5. **时区**:文件按「本地日期」滚动,用 `time.Now()` 的本地时间(dpid 里有 `tzlocal` 包处理 Android 时区,参照它)。
6. **前端是全局作用域**:新函数名不要和现有函数重名(先 `grep -n "function 名字" webroot/js/*.js`)。
7. **morph 机制**:设置页重绘是「就地更新」,异步加载的内容容器必须加 `data-keep`,否则下次刷新会被清掉。
8. **不要改 `index.html`**:CSP 用的是内联脚本的 sha256 白名单,改了会白屏。
9. 改完 `data/` 下的文件,记得它会被打进刷机包;`docs/` 不会。

---

## 8. 做不完 / 遇到问题怎么办

- 某个现成函数的签名和本文档描述对不上:**以代码为准**,在提交说明里写清楚你怎么处理的,**不要为了迎合本文档去改现有函数**。
- 某项要求做不到(例如 IP 归属的准确率无法计算):按文档里给的降级方式做,并在 `note` 字段和提交说明里写明。
- 需要越过第 2 节边界才能完成:**停下来**,把问题写清楚交给项目负责人,不要自行越界。
