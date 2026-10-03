# 工作文档:HNC v5.27.0-rc1「DPI 新识别器 + 我的规则包」

> 交给接手开发的 AI 编程助手(GLM / 千问等)执行。**请完整读完再动手**,第 2 节「边界」是硬约束。
> 背景:`docs/CODEMAP.md`(代码地图,含「权威实现表」)、`docs/ROADMAP.md` §1(DPI 3.0 设计)、`CHANGELOG.md` 里 v5.24.0-rc1 / rc2(本机样本、前台真值、识别自评)。
> 基线:分支 `claude/environment-config-ydr2ow` 最新提交(v5.26.0-rc1 内容 + 本文档)。

---

## 0. 这一版做什么(一句话)

把路线图里欠下的 **DPI 新识别器**(QUIC 传输参数指纹、启动指纹、HMM 前台、规则库扩充)做出来,并加上用户要的 **「导出 / 导入我的规则包」**。
做之前先修两个会让「学到的规则」白学的老 bug(T1)。

**原则(沿用路线图):新识别器先「影子运行」—— 算出来、记下来、进识别自评对比,但默认不改变现有识别结果;确认更准再转正。** 每个任务第 3 节都写明了它「能改变什么、不能改变什么」。

---

## 1. 项目基本情况(必读)

### 1.1 通用
- Android root 模块,运行目录 `/data/local/hnc/`(代码里 `hncDir` / `HNC_DIR`):`data/` 持久化,`run/` 运行时(可丢),`etc/` 运行时配置,`logs/`。
- **两个 Go 模块**:
  - `daemon/hnc_httpd/`(module `hnc_httpd`,`go 1.25.0`):HTTP API + 大部分识别后处理。通过 `replace hnc.io/dpid => ../../src/dpid` 可以 import dpid 模块的包。
  - `src/dpid/`(module `hnc.io/dpid`,`go 1.22`):`cmd/dpid`(抓包识别)、`cmd/hnc_watchdog`、共享包。**`go 1.22` 不能用 1.23+ 的标准库 API**(如 `crypto/hkdf`、`maps`/`slices` 的新函数要先确认)。
  - 共享代码放 `src/dpid/` 下新建包。**不要改两个 `go.mod` 的 `go` 版本,不要加第三方依赖。**
- 编译:`CGO_ENABLED=0`;arm64 用 `GOOS=android GOARCH=arm64`;32 位只做类型检查 `GOOS=linux GOARCH=arm GOARM=7 go vet`。
- 工具脚本 `tools/*.py`:**纯标准库 Python 3**,开发时在电脑上跑,不上手机。
- Android 坑:
  1. Go 在 Android 上 `time.Local` 恒为 UTC,新进程 `main()` 要 `time.Local = tzlocal.Location()`;按「本地日期」分文件一律用 `tzlocal`。
  2. toybox 的 grep 不认 `\|`;shell 判断进程用 pidfile + `/proc/<pid>/cmdline`。
  3. shell 脚本开头照抄现有脚本的 PATH 加固写法。
  4. **编辑 shell 文件时注意别让编辑器把 Tab 换成空格**(v5.26 出过事:`json_escape` 里的 `s/<Tab>/ /g` 被换成两个空格)。

### 1.2 DPI 数据怎么流动(本版所有任务都基于这张图)

```
dpid(src/dpid/cmd/dpid)
 ├─ 抓热点客户端的包 → 每个 TLS / QUIC ClientHello:
 │    → run/dpi_flows.json      flowlog.go:环形 1024 条 / 最近 10 分钟,每条 {seq,ts,mac,cip,sport,dip,dport,proto,ja4,alpn,sni,app...}
 │    → run/dpi_ipname.json     ipname.go:目的 IP → 域名(DNS 应答 / SNI)
 └─ 抓本机自己的包(self_capture.go,需开关 run/self_capture.enabled)
      → run/label_samples.YYYYMMDD.jsonl   label_samples.go:本机样本 = 真实包名(UID 反查) + SNI/JA4…
                                           同一 (pkg,sni,ja4) 10 分钟内只记一次;本地日期分文件;保留 7 天

httpd(daemon/hnc_httpd)
 ├─ app_usage.go  每轮(10 秒,后台档 30 秒)读 conntrack,给每条连接定应用归属
 │    └─ fpSt.tick(fp_learn.go):按 seq 游标摄入 dpi_flows.json → 学 JA4 指纹 → 给「没有域名」的连接兜底归属
 ├─ fg_model.go   每轮按 (设备, 应用) 算分 → 选前台(带滞回)→ /api/devices[].fg + run/fg_timeline.*.json
 ├─ self_fg_truth.go  本机前台真值 run/self_fg.YYYYMMDD.jsonl(前台变化才记,10~60 秒探测一次)
 └─ dpi_eval.go   识别自评:拿本机样本当标准答案(真值 = data/pkg_app_map.json[pkg]),算各方法覆盖率/准确率
```

### 1.3 规则库
- **运行时**读 `etc/dpi_rules.d/*.json`(按文件名排序合并,同 id 后写覆盖前写;单文件上限 1 MiB,`rule.go` 的 `externalRulesSubsetMaxBytes`)。
- **出厂**规则在仓库 `data/dpi_rules.d/`(00~84 号 bucket),开机由 `service.sh` 同步到 `etc/dpi_rules.d/`。`data/dpi_rules.json` 是派生产物,改完 bucket 要跑 `python3 tools/dpi_rules_split.py sync-legacy`。
- 运行目录里**模块不发**的文件:`97-online-update.json`(在线更新)、`99-user-custom.json`(用户导入 / 「新发现的应用」确认后写这里)、`_auto_expanded.json`(dpid 自动扩展学到的子域名,`auto_expand.go`)、`_auto_promoted.json`(新应用晋升,`candidate.go`,需开关 `run/auto_promote.enabled`)。
- **规则 id 就是应用 id**:分类结果、`dpi_ipname.json` / `dpi_flows.json` 的 `app`、样本的 `rule_id`、httpd 的应用统计,全都直接用规则 id。
- 用户纠正:`data/dpi_user_rules.json`(`fp_user_rules.go`,kind = domain / ip / ja4)。
- 学到的 JA4 指纹:`data/fp_learned.json`(`fp_learn.go`);种子指纹 `data/fp_seed.json`(默认不发)。

### 1.4 前端约定
- 设置页 `webroot/js/settings.js`;DPI 相关折叠块在约 351 行 `encdnsSettingsHtml() + dnsTakeoverFold() + fpFold() + evalFold()` 一带,新折叠块照抄 `sFold(...)` 写法。
- 生成文件给用户下载:照抄 `debugBundle()`(约 688 行)—— 后端写到 `$HNC/exports/<name>`,前端非 KernelSU 环境用 `downloadExport(name, '/api/exports/'+name)`,KernelSU(`KSU` 为真)用 `shell('cp … /sdcard/Download/')`。
- 改完 `node --check webroot/js/*.js`。

---

## 2. 边界(硬约束)

1. **隐私与安全红线**:不做 SSL / TLS 中间人解密;不向任何设备注入、不 hook 其他设备;不新增采集内容(URL、请求体、Cookie、页面内容一律不碰),只用现有的元数据(SNI、JA4、QUIC Initial 里的传输参数、时间、字节数)。QUIC Initial 的解密是 RFC 9001 公开密钥的现有能力,只许读 ClientHello,不许扩展到其他包。
2. **新识别器默认影子运行**:T3 启动指纹、T4 HMM **不得改变**任何连接的应用归属、按应用限速、应用限时、类别封锁、tc / iptables。T4 只有用户在设置里主动切换引擎后才改变「前台显示 / 前台时间线」。T2 的 QUIC 参数只在现有指纹机制内细化(同样的纯度 / 支持度门槛),不新增归属来源。
3. **API 兼容**:现有接口字段一个不能少、含义不能变(可以加字段)。
4. **持久化格式只增不改**:`run/label_samples.*.jsonl`、`run/dpi_flows.json`、`data/fp_learned.json` 等只允许**加可选字段**;旧文件必须能照常读。
5. **省电**:不新增常驻循环 / goroutine 定时器,一律挂在现有循环上(app_usage 每轮、`fpSt.tick`);重活(扫样本文件)最多 30 分钟一次,且只在本机抓包开关打开时做;读文件一律有大小上限。
6. **不改**:CI(`.github/workflows/`)、`customize.sh`、`post-fs-data.sh`、tc / iptables / 限速 / 封锁脚本逻辑。`service.sh` 只许改 T1 指明的那一段。
7. **不许通过删除或跳过测试让测试变绿。**
8. **禁止凭记忆编造数据**:域名清单、包名对照必须来自给定数据源或你能确证的事实;拿不准的不要加(见 T5)。
9. 第 4 节「不做」清单里的东西一律不碰。

---

## 3. 任务(按顺序做,每个任务一个提交)

### T0 · 记录基线
跑一遍第 5 节全部自检命令,把结果写进提交说明(空提交即可)。维护者环境基线:`test/run_all.sh` → `ALL PASS: 451/452 (1 skipped)`;Go 两个模块 vet / test / 构建全过。你的沙箱若缺 toybox / root,有一批 `hnc_json` 相关失败,记下即可,之后每个任务都不能比基线差。

---

### T1 · 规则地基:学到的规则不再丢、不再被当成别的应用

**问题 1 · 开机把学到的规则删了。** `service.sh` 约 930~966 行每次开机 `rm -rf etc/dpi_rules.d` 再从模块复制,**只保留 `99-user-custom.json`**。结果:
- `_auto_expanded.json` / `_auto_promoted.json` 每次重启都没了(学到的东西要从头再学);
- `97-online-update.json`(在线更新)也没了,但版本号文件 `etc/dpi_rules_online.version` 还在 → 「检查更新」说已是最新,规则却已丢失。

**做法:**
1. 把这段同步逻辑搬到新脚本 `bin/dpi_rules_sync.sh <模块规则目录> <运行规则目录> <模块 module.prop 路径>`,`service.sh` 原位置改成调用它(失败只记日志,不阻断开机)。
2. 同步规则:
   - **保留**:`99-user-custom.json`、所有 `_*.json`。
   - **`97-online-update.json`**:模块版本没变才保留。模块版本 = module.prop 的 `versionCode`,每次同步后记到 `etc/.rules_sync_module_version`;版本变了(升级了模块)→ 删除 97 和 `etc/dpi_rules_online.version`。
   - **其余**:以模块为准(删掉旧的,复制模块的)。模块里删掉的旧 bucket 要跟着消失。
   - 实现:先把要保留的文件 `mv` 到同一文件系统下的临时目录,再删 / 复制,再挪回;**任何一步失败都要把保留文件挪回去**(不能因为 cp 失败把用户规则弄丢)。模块目录不存在时什么都不动。
3. 测试 `test/unit/test_dpi_rules_sync.sh`(临时目录模拟):保留 99 / `_auto_*` / `_imported`;同版本保留 97;升级后删 97 和版本文件;模块删掉的 bucket 被清掉;模块目录缺失时不动;cp 失败(把目标目录父目录设成只读等方式模拟)时保留文件仍在。

**问题 2 · 自动扩展的子域名被当成另一个应用。** `auto_expand.go:400` 生成的规则 id 是 `<父规则id>_autoexp_<后缀>`。规则 id 就是应用 id(见 1.3),所以学到的子域名在统计里变成**名字相同、id 不同的另一个应用**(数据被拆成两份),识别自评里也被判成「认错」(真值 `douyin`,预测 `douyin_autoexp_xxx`)。

**做法:**
1. **先写失败的测试**:加载父规则 + 一条带 `"_parent_rule_id"` 的子规则,对子域名分类,断言返回父 id。
2. `src/dpid/output/rule.go`:`externalRule` 增加 `ParentRuleID string \`json:"_parent_rule_id"\``。在**所有文件合并、按 id 去重之后**加一步「挂靠」:有 `ParentRuleID` 且父规则存在的规则,把它的 suffixes 并进父规则(去重),自身从列表移除;父规则不存在 → 保持独立规则(和现在一样)。
3. 检查 `auto_expand.go` / `candidate.go` 里有没有依赖「子规则独立存在」的逻辑(例如按 id 统计命中、用子 id 去重),逐个说明处理方式。`_auto_promoted.json`(没有父)行为不变。
4. 这个挂靠机制 T5(规则库扩充)、T6(导入规则包)都会用到。

**验收**:两个新测试通过;`go test ./...` 全过;重启模拟测试中学到的规则存活。

---

### T2 · QUIC 传输参数指纹

**背景**:HTTP/3(QUIC)的 ClientHello 里有扩展 `quic_transport_parameters`(类型 `0x0039`,草案版 `0xffa5`)。不同网络库(Cronet、quiche、OkHttp-QUIC、各家自研)给的参数组合不同,比 JA4 更能区分「这是哪个 App 的网络栈」。dpid 已经能解密 QUIC Initial 拿到 ClientHello(`capture/quic.go`),只是没读这个扩展。

**能改变什么**:只在现有 JA4 指纹学习 / 兜底归属内部把 QUIC 连接的指纹分得更细,门槛不变(纯度 ≥ 90% 等)。

**做法:**
1. 新文件 `src/dpid/output/qtp.go`,纯函数 `QUICTPFingerprint(raw []byte) string`:
   - 解析 `(varint id, varint len, value)` 序列(QUIC varint,RFC 9000 §16);任何越界 / 截断 → 返回 `""`。
   - 规范化成一个字符串:
     - 参数 id **升序排序**(不依赖发送顺序);
     - GREASE / 保留 id(`id % 31 == 27`)合并成一个 `G`(出现几次、具体 id 都不管);
     - 整数型参数带值:`0x01` max_idle_timeout、`0x03` max_udp_payload_size、`0x04` initial_max_data、`0x05`/`0x06`/`0x07` initial_max_stream_data_*、`0x08`/`0x09` initial_max_streams_*、`0x0a` ack_delay_exponent、`0x0b` max_ack_delay、`0x0e` active_connection_id_limit、`0x20` max_datagram_frame_size,写成 `id=值`;
     - `0x11` version_information:只取「可用版本列表」排序后拼接(不取 chosen version);
     - **其余一律只记「出现过」**(包括 `0x0f` initial_source_connection_id —— 每次随机;Google 私有参数里的 User-Agent 字符串 —— 不存原文)。
   - 输出 `"qtp1_" + sha256(规范串) 前 12 位十六进制`。
   - 另给 `QUICTPSummary(raw []byte) string` 返回规范串本身(≤ 256 字符,截断),仅供调试接口显示。
2. `capture`:在 ClientHello 扩展遍历处(`ja4.go` 的 `extractJA4Inputs` 循环或另写一个同样遍历的函数)取出 `0x0039` / `0xffa5` 的原始数据;`TLSInfo` 加 `QTP string`;**只在 QUIC 路径**(`parseQUIC`,`info.IsQUIC = true` 那里)填 `QTP`。
3. 透传(都是加可选字段):
   - `output.FlowRecord` 加 `QTP string \`json:"qtp,omitempty"\``,`cmd/dpid/flowfp.go` 的 `flowLog.Record(...)` 传进去;
   - `LabelSampleInput` / `LabelSample` 加 `QTP`(`json:"qtp,omitempty"`),`self_capture.go` 传 `ev.TLS.QTP`。
4. httpd `fp_learn.go`:
   - `fpFlowRec` 加 `QTP`;`fpEntry` 加 `QTP string \`json:"qtp,omitempty"\``;连接绑定(`fpBind`)也记 QTP。
   - **学习**:有 QTP 的记录,key = `fpKeyOf(ja4, alpn, port) + "|" + qtp`;没有的用旧 key。
   - **识别**:绑定的 ClientHello 有 QTP → 先查带 QTP 的 key;没有、不可用或判为通用 → 回落旧 key(旧版学到的 QUIC 条目只读兜底,随 14 天半衰期自然淘汰)。
   - `/api/dpi_fp` 每条加 `qtp`;`stats` 加 `flows_attributed_by_qtp`。
5. `dpi_eval.go`:`evalSample` 加 `QTP`;`fpPredict` 增加 qtp 参数(同上「先 QTP 后回落」)。结果新增 `quic` 段:`{samples, fp_ja4_only:{coverage,accuracy,judged}, fp_with_qtp:{…}}`,只统计 `quic=true` 的样本。
6. 前端:识别自评里 `quic.samples > 0` 时多一行「QUIC 指纹(含传输参数)覆盖 x% · 准确 y%(仅 JA4:覆盖 a% · 准确 b%)」;`fpFold` 的指纹列表显示 qtp 前 8 位(有的话)。
7. 测试(`qtp_test.go` 等):
   - 不同 GREASE id → 同一指纹;参数顺序打乱 → 同一指纹;`0x0f` 的值变 → 同一指纹;max_idle_timeout 变 → 不同指纹;截断 / 越界 varint → `""`;
   - 用 `capture/quic_test.go` 里现有的 RFC 9001 测试向量(若有)断言 QTP 非空且稳定;
   - fp_learn:带 QTP 的学习与「先 QTP 后回落」查找;旧 `fp_learned.json`(无 qtp 字段)能加载;
   - 样本 / flowlog JSON 往返(没有 qtp 的旧行照常解析)。

---

### T3 · 启动指纹(影子运行)

**背景**:App 冷启动 / 切回前台的头几秒,会按固定套路连一串域名(配置 → 统计 SDK → 自家 API → CDN)。单个域名可能是共享的(CDN、SDK),**一组域名一起出现**就能认出是哪个 App,而且这个事件本身就是「切换到前台」的秒级信号(T4 用)。

**能改变什么**:只产出「启动事件」供 T4、识别自评和调试接口使用。**不改任何连接的归属**。

**数据来源**:学习用本机样本(`run/label_samples.*.jsonl`,真值是包名,经 `data/pkg_app_map.json` 映射到应用 id;映射不到的包不学);识别用热点客户端的 `run/dpi_flows.json`(ClientHello 的 SNI 序列)。本版不用 DNS。

**做法**(新文件 `daemon/hnc_httpd/startup_fp.go`):
1. **token**:SNI 小写、去尾点;每个 label 里的连续数字换成 `#`(`v26-dy.ixigua.com` → `v#-dy.ixigua.com`,让分片编号不同的 CDN 主机算同一个);跳过 IP 字面量和 ECH 外层 public_name(`output.IsECHPublicName` 的逻辑,或 flow 记录的 `ech_outer`)。
2. **一次启动(训练)**:同一个包,和它上一条样本相隔 ≥ 600 秒(= 样本去重窗口,保证启动时的域名都会被记下)的那条样本算「启动时刻」;取该包 `[启动时刻, +8 秒]` 内的样本,按首次出现顺序去重得 token 列表;≥ 2 个 token 才算一次有效启动。
3. **学习表** `data/startup_fp.json`:每个应用 `{app_id, name, starts, tokens:{token: 次数}, last}`;计数按 **14 天半衰期**惰性衰减(照抄 `fp_learn.go` 的写法);最多 512 个应用,每个应用最多 64 个 token(按次数留前 64)。
   - **增量读样本**:游标 `{date, offset}` 存在同一文件里,每次只读新增的行;每次最多读 50000 行;**最多 30 分钟一次**,挂在 app_usage 每轮上做时间判断;只在 `run/self_capture.enabled` 存在时做;I/O 不得在 `appUsage.mu` / `fpSt.mu` 锁内。
   - token 频率 `f = 次数 / starts`;**特征 token** = `f ≥ 0.5` 且出现在 ≤ 2 个应用的特征集里(按 `f ≥ 0.5` 统计各 token 被几个应用用到)。
   - **可用**:`starts ≥ 3` 且特征 token ≥ 2 个。
4. **识别(客户端)**:在 `fpSt.tick` 解析出新的 dpi_flows 记录后(锁外)把 `seq` 新于上次的记录交给 `startupSt.observe(recs)`。每台设备(MAC 非空)保留最近 20 秒的 `(ts, token)`。每来一条记录,看窗口 `[ts−8s, ts]`:
   - 对每个可用应用 A:`matched` = 窗口里出现的 A 的特征 token;`recall = Σ f(matched) / Σ f(A 的全部特征 token)`;
   - 候选条件:`|matched| ≥ 2` 且 `recall ≥ 0.5`;取最高者,且领先第二名 ≥ 0.2;
   - 产出启动事件 `{mac, app_id, name, ts, score(0~100), matched}`;同一 `(mac, app)` 600 秒内只出一次。
   - 内存里保留最近 200 个事件;计数 `events_total` 等。
5. **接口** `GET /api/dpi_startup` → `{learned:[{app_id,name,starts,tokens:[{t,f}],usable}], events:[…], stats:{samples_read, starts_learned, apps_usable, events_total, last_learn}}`。
6. **识别自评**(`dpi_eval.go` 新增 `startup` 段,**按天交叉验证,防止拿训练数据考自己**):
   - 对样本里的每一天 d:用**其它天**的样本训练一张临时表(同第 2~3 步,不衰减),在 d 天的本机样本上跑第 4 步的识别(本机所有包的样本按时间混在一起,当成一台设备);
   - 真值:`run/self_fg.d.jsonl` 的前台切换(包名映射到应用 id,映射不到的跳过)。注意真值是 10~60 秒探测一次记下的,**会比真实切换晚最多 60 秒**;
   - 指标:切换识别率 = 有事件在 `[真值时刻−60s, 真值时刻+10s]` 内且应用相同的切换数 / 切换总数;事件准确率 = 事件时刻 `[−10s, +60s]` 内真值前台就是该应用的事件数 / 事件总数;事件与真值时刻差的中位数;
   - 样本不足 2 天时只返回 `note:"样本不足 2 天,无法交叉验证"`。
7. **前端**:识别自评里加一块「启动指纹:学会 N 个应用 · 切换识别率 x% · 事件准确 y%」;点开可看学会的应用列表(名字、启动次数、特征 token 数)。
8. **测试**:token 规范化;启动切分(600 秒间隔、8 秒窗口、< 2 token 丢弃);半衰期;特征 token / 可用判定;识别(A 特征 {a1,a2,a3}、B {b1,b2}:窗口有 a1,a2 → A;只有 a1 → 无;3 个应用共享的 token 不算;600 秒内不重复);交叉验证在合成的多天样本上给出预期数字;游标增量读(追加行后只读新行;文件被删 / 换天后正确续读)。

---

### T4 · HMM 前台(影子运行,可切换)

**背景**:现在的前台模型(`fg_model.go`)是「打分 + 滞回」,来回跳和切换慢都靠手调阈值。用 HMM(隐马尔可夫模型)的在线前向滤波:人不会每 10 秒换一次 App(转移概率很小),一次偶然的流量尖峰压不过「一直在用的那个」;而启动事件(T3)这种强证据能让它当轮切换。

**能改变什么**:默认只在后台算、只出对比统计。用户在设置里把引擎切到「新(实验)」后,`/api/devices[].fg` 的前台应用和前台时间线改由 HMM 决定。连接归属、限速、限时一律不变。

**做法**(新文件 `daemon/hnc_httpd/fg_hmm.go`,挂在 `fg_model.go` 上,不新开循环):
1. **状态**:每台设备 = 该设备 `d.apps` 里可当前台的应用(`fgCandidate`)+ 一个 `_none`(没有前台);最多 12 个,超了丢后验最低的;新出现的应用初始 log 先验 = `log(0.02)`。
2. **每轮**(在 `stepDevLocked` 算完各应用本轮分 `a.inst` 之后):
   - **转移**:`p_stay = exp(−dt/τ)`,`τ = 180 s`;各状态把 `1−p_stay` 的质量平均分给其他状态。
   - **观测**:`log L(a) = κ · inst_a / 100`(`κ = 4`);`log L(_none) = κ · θ / 100`(`θ = 20`,所有应用都很安静时 `_none` 占优);本轮该设备有 T3 启动事件的应用再 `+η`(`η = 2.5`)。
   - 后验在 log 空间归一化(log-sum-exp)。
   - **决定**:后验最大者 ≥ 0.55 → 它;否则当前前台后验 ≥ 0.25 → 保持;否则 `_none`。置信度 = `round(100 × 后验)`,再按现有规则封顶(`_org:` ≤ 60、隧道 ≤ 50、系统类 ≤ 50、共现为主 ≤ 70,复用 fg_model 已有的封顶逻辑)。
   - 两轮间隔 > 90 秒 → 该设备 HMM 重置(与经典模型一致)。
   - 常数集中在文件顶部,注释说明含义;测试锁「行为」不锁具体数值。
3. **引擎开关**:`data/dpi_experiment.json` `{"fg_engine":"classic"|"hmm"}`(按 mtime 缓存读取;缺失 = classic)。新增 action `dpi_fg_engine {engine}`(在 `action.go` 白名单里注册,参数校验),原子写。
4. **切换点**:`decideLocked` 里两套都算;`fg_engine=hmm` 时用 HMM 的决定去开 / 关时间线会话、填 `fgView` 的 `AppID / Name / Category / Confidence / Since`,`Reasons` 加一条「HMM 后验 xx%」;后台列表(`Background`)仍用经典模型的。
5. **对比统计**(无论选哪个引擎都记):每台有流量的设备每轮记两套引擎各自的「是否切换」「本轮前台」,累计到小时桶 `{rounds, agree_rounds, classic:{switches, short_segments}, hmm:{…}}`(short_segment = 持续 < 30 秒就结束的前台段);桶存 `run/fg_compare.json`,保留 7 天,每分钟随 fg 落盘写一次。接口 `GET /api/fg_compare?days=1|7` → 合计 + `switches_per_hour`、`short_per_hour`、`agree_pct`。
6. **前端**:设置 → DPI 加「前台识别引擎」两段选择 [经典] [新(实验)],下方显示「过去 24 小时:经典 切换 a 次/小时、短于 30 秒的 b 段;新 c 次/小时、d 段;两者一致 e%」,说明文字:「新引擎更不容易来回跳;切换后前台时间线从此刻起按新引擎记录」。
7. **测试**(合成观测序列,10 秒一轮):
   - 稳定使用 A,中间一轮 B 的分数冲高 → HMM 不切(而经典模型在同样输入下的行为写进测试注释作对比);
   - A → B 持续切换 → ≤ 2 轮内切到 B;
   - B 有启动事件 + 一轮活跃 → 当轮切到 B;
   - 全部安静 → 若干轮后 `_none`;
   - 间隔 > 90 秒 → 重置;
   - 引擎开关:classic 时 view 与改动前完全一致(对现有 `fg_model_test.go` 全部通过即可证明);hmm 时 view 取 HMM 结果;
   - 对比统计的计数与小时桶滚动。

> HMM 在本机真值上的评估本版不做(本机样本没有逐轮字节数,观测口径和客户端不同,硬算会误导)。对比只看客户端上的「来回跳」统计,加 T3 的切换识别率。

---

### T5 · 规则库扩充(开源域名清单)

**目标**:应用数从 189 提到 **≥ 300**(硬底线 +80),同时把 `data/pkg_app_map.json`(现在只有 60 个包)扩大,让识别自评有更多「可判对错」的样本。

**数据源**:[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)(MIT 许可)的 `data/` 目录。按清单名一个文件,行格式:`domain:x` 或裸 `x`(后缀匹配)、`full:x`(精确)、`keyword:` / `regexp:`(**跳过**)、`include:<清单名>`(展开,防循环)、行尾属性 `@ads`、`@cn`、`@!cn` 等、`#` 注释。

**做法:**
1. 工具 `tools/import_v2fly.py`(纯标准库):`--src <domain-list-community/data 目录> --map tools/v2fly_map.json --out data/dpi_rules.d/`。
   - `v2fly_map.json`:`{"<清单名>": {"id":"bilibili","app":"哔哩哔哩","category":"video"}, …}`。**只映射「一个清单 = 一个 App / 服务」的清单**;公司级大清单(tencent、alibaba、bytedance、baidu、google、microsoft、apple、amazon 等)**不映射**(会把一家公司的所有产品认成同一个 App)。
   - `id` 已存在于现有规则 → 生成 id `<id>_v2fly`、带 `"_parent_rule_id": "<id>"` 的规则(T1 的挂靠会把后缀并进去);id 不存在 → 新的独立规则。`category` 必须用现有规则里已经出现过的类别(见 `data/dpi_rules.d/*.json` 与 `webroot/js/devices.js` 的 `CAT_T`)。
   - 带 `@ads` 的行跳过(除非映射里 category 本来就是 ads 类)。
   - **冲突检查**:某个后缀在现有规则里已经归给**别的**应用(最长后缀匹配)→ 跳过并写进报告;后缀是 `data/auto_expand_blocklist.json` 里的共享基础设施 apex 本身、或只是一个公共后缀(`com`、`com.cn` 这类)→ 跳过。
   - 输出 `46-v2fly-a.json`、`46-v2fly-b.json`…(每个 ≤ 900 KB),格式同现有 bucket(`schema_version`、`subset`、`rules_version`),顶层加 `"source": "v2fly/domain-list-community@<commit>"`。
   - 打印报告:映射了多少清单、新增应用数、并入已有应用的后缀数、跳过数(按原因)。
2. 跑完 `python3 tools/dpi_rules_split.py sync-legacy`;确认 `data/dpi_rules.json` 仍 < 1 MiB(旧路径加载上限),超了在提交说明里写明,**不要改加载器**。
3. `tools/build_pkg_app_map.py` 的 `CURATED`:为新应用补「包名 → id」。**只加你确定无误的主流包名**(例如应用商店里官方 App 的包名),拿不准的不加;跑 `--check`。
4. 许可:新增 `THIRD_PARTY_NOTICES.md`,写明 domain-list-community 的名称、URL、使用的 commit、MIT 许可全文。
5. 测试:`tools/test_import_v2fly.py`(`python3 -m unittest`,用 `tools/testdata/v2fly/` 下的小夹具):`include` 展开与防循环、属性过滤、`keyword/regexp` 跳过、冲突跳过、公共后缀跳过、挂靠父规则、按大小拆文件。再加一个 Go 测试(dpid `output` 包):加载 `data/dpi_rules.d/` 全部文件 → 每个文件 ≤ 1 MiB、合法 JSON、规则 id 不重复、类别非空。
6. **如果你的环境拿不到 v2fly 数据**:只交付工具 + 映射表 + 测试夹具 + 测试,不生成 bucket,在提交说明里写明「待维护者用真实数据跑」。**绝对不要凭记忆写域名清单。**

---

### T6 · 导出 / 导入「我的规则包」

**目标**:把**这台手机自己学到的 / 用户自己加的**高可信规则打包导出(不含模块自带规则),可备份、可分享给另一台 HNC;另一台导入后立即生效。

**「我的」规则从哪来**(导出时汇总,全部只读):

| 来源 | 文件 | 导出条件 |
|---|---|---|
| 自动扩展的子域名 | `etc/dpi_rules.d/_auto_expanded.json` | 全部(本身有三重证据门槛) |
| 新应用晋升 | `etc/dpi_rules.d/_auto_promoted.json` | 全部(HIGH 档才会晋升) |
| 用户自定义 / 「新发现的应用」确认 | `etc/dpi_rules.d/99-user-custom.json` | 全部;若 id 与出厂规则相同,只导出出厂规则里没有的后缀 |
| 用户纠正 | `data/dpi_user_rules.json` | `kind=domain`、`kind=ja4`;**`kind=ip` 不导出**(会过期、与网络环境有关) |
| 学到的 JA4(+QTP)指纹 | `data/fp_learned.json` | 可用、非通用、置信度 ≥ 0.8、支持度 ≥ 50 |
| 启动指纹(T3) | `data/startup_fp.json` | 可用的应用;只导出特征 token 及其频率 |
| 已导入的别人的包 | `_imported.json` 等 | 默认**不导出**(勾选「包含已导入」才带上) |

**规则包格式**(`hnc-rulepack`,schema 1):
```json
{
  "format": "hnc-rulepack", "schema": 1,
  "created": "2026-10-05", "hnc_version": "v5.27.0-rc1", "note": "用户填的备注(可空)",
  "counts": {"domain_rules": 12, "suffixes": 40, "fingerprints": 5, "startup": 3},
  "domain_rules": [{"id": "douyin_autoexp_ab12", "app": "抖音", "category": "video",
                    "attach_to": "douyin", "suffixes": ["x.amemv.com"], "source": "auto_expanded"}],
  "fingerprints": [{"ja4": "q13d…", "alpn": "h3", "port": "443", "qtp": "qtp1_…",
                    "app_id": "douyin", "app": "抖音", "category": "video",
                    "purity": 0.97, "support": 120, "source": "learned"}],
  "startup": [{"app_id": "douyin", "app": "抖音", "category": "video", "starts": 12,
               "tokens": [{"t": "api#.amemv.com", "f": 0.92}]}]
}
```
**隐私**:包里**不得出现** MAC、IP、UID、包名、设备散列(`fp_learned` 的 `devs`)、`_evidence` 里的任何字段、精确到秒的时间。只有日期。

**做法:**
1. 新文件 `daemon/hnc_httpd/rulepack.go`:
   - `GET /api/dpi_rulepack?summary=1` → 各来源可导出条数(给前端显示)。
   - action `dpi_rulepack_export {note?, include_imported?}` → 生成规则包写到 `$HNC/exports/hnc-rulepack-YYYYMMDD-HHMMSS.json`,返回文件名(前端照抄 `debugBundle()` 的下载方式)。
   - `POST /api/dpi_rulepack {pack: "<json 文本>"}` 导入(用 `requireMutationN`,上限 1.2 MB,照抄 `apiDPIRules` 的写法;写操作记 `auditLog`)。
   - action `dpi_rulepack_clear` → 删除全部已导入内容。
2. **导入校验**(包可能来自别人,当不可信输入处理):
   - `format`/`schema` 必须匹配;未知顶层字段忽略;条数上限:域名后缀 ≤ 5000、指纹 ≤ 2000、启动指纹 ≤ 500,超了整包拒绝。
   - id:`^[a-z0-9_]{1,64}$`;后缀:合法主机名、≥ 2 段、≤ 253 字符、不是公共后缀本身、不是 `auto_expand_blocklist.json` 里的共享 apex 本身;类别:必须是本机规则里出现过的类别;JA4 用现有 `dpiJA4RE` 校验;qtp 必须匹配 `^qtp1_[0-9a-f]{12}$`。
   - **冲突跳过**:后缀在本机规则(不含已导入的)里按最长后缀匹配已经归给**别的应用** → 跳过。这条防止别人的包把关键域名(如微信)挂到被限时的应用上。
   - 返回报告:新增 / 合并 / 跳过(按原因分别计数),前端显示。
3. **落地**(都按 id / key 合并,重复导入幂等,原子写):
   - 域名规则 → `etc/dpi_rules.d/_imported.json`:id 改成 `imp_<原 id>`(避免和本机 id 撞车后「后写覆盖」把本机规则整条替换掉);`attach_to` 写成 `_parent_rule_id`(T1 的挂靠 → 后缀并进本机同名应用);加 `_source: "rulepack:<note>@<created>"`。T1 保证它重启不丢。写完按 `bin/dpi_rules_import.sh` 的 `rebind_dpi` 方式让 dpid 重载(先读 `rule.go` 的目录缓存逻辑确认需要什么)。
   - 指纹 → `data/fp_imported.json`;`fp_learn.go` 在「学习表之后、种子表之前」查它,同样遵守「学习表判为通用的指纹不用」。
   - 启动指纹 → `data/startup_fp_imported.json`;T3 识别时并入(同一应用本机学到的优先)。
4. **前端**:设置 → DPI 加折叠块「我的规则包」:
   - 摘要:「可导出:域名规则 N 条(自动扩展 a / 晋升 b / 自定义 c / 纠正 d)· 指纹 K 条 · 启动指纹 S 个应用」;
   - [导出](可填备注、勾选「包含已导入」)→ 下载 / 存到下载;
   - [导入]:选文件或粘贴文本 → 显示报告;
   - [清除已导入](二次确认);
   - 说明:「只包含这台手机自己学到的和你自己加的规则,不含模块自带规则,也不含任何设备的 MAC / IP。导入的规则只用来给流量贴应用标签;和本机规则冲突的条目会被跳过。」
5. **测试**:导出的来源汇总与过滤(ip 纠正不导出、通用指纹不导出、99 号文件只导出出厂没有的后缀);**隐私断言**(序列化结果里搜不到测试夹具中的 MAC / IP / UID / 包名);导入校验的每一条拒绝路径;冲突跳过;`imp_` 前缀与 `_parent_rule_id`;重复导入幂等;清除;导出 → 导入往返(另一个临时目录)后分类结果一致。

---

### T7 · 版本与文档
1. `module.prop`:`version=v5.27.0-rc1`,`versionCode=5270001`。
2. `CHANGELOG.md` 最上面加 `## [5.27.0-rc1] - <日期>`,格式参照 5.26.0-rc1:写清每个新识别器「现在是影子运行 / 能改变什么」、T1 修的两个老 bug、规则包的隐私边界、规则库新增多少应用(写实际数字)。
3. `webroot/changelog.html` 最上面加一段大白话。
4. `docs/ROADMAP.md` §A:v5.27 行标「rc1 ✅」并把内容改成实际完成的情况。
5. `docs/CODEMAP.md` 权威实现表加:启动指纹 → `startup_fp.go`;前台 HMM → `fg_hmm.go`;规则包 → `rulepack.go`;规则同步 → `bin/dpi_rules_sync.sh`;规则挂靠 → `rule.go`。
6. `docs/API.md` 末尾加「## 25. v5.27 变更」:`/api/dpi_startup`、`/api/fg_compare`、`/api/dpi_rulepack`、action `dpi_fg_engine` / `dpi_rulepack_export` / `dpi_rulepack_clear`、`/api/dpi_eval` 新增 `quic` / `startup` 段、`/api/dpi_fp` 新增 `qtp`、`dpi_flows.json` 与 `label_samples` 新增 `qtp` 字段。

---

## 4. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 用启动指纹改连接归属 / 限速 / 限时 | 先影子运行看准确率,确认更准再转正(以后的版本) |
| DNS 查询序列做启动指纹 | 本机样本只有 ClientHello 带真实包名,DNS 拿不到可靠真值 |
| 交互节拍、共现聚类、轻量分类器 | 路线图顺延到 v5.28「DPI 自学习」 |
| HMM 在本机真值上的评估 | 观测口径不同,见 T4 末尾说明 |
| 规则包在线分享 / 上传 / 订阅 | 需要服务器与隐私设计,待定 |
| 合并 `json_set.sh` 与 `hnc_json` | v5.26 已明确留到以后 |
| 任何 tc / iptables / 限速 / 封锁逻辑 | 不在本版范围 |

---

## 5. 自检命令(每个任务完成后都跑,全部通过才提交)

```sh
# Go
(cd daemon/hnc_httpd && gofmt -l $(git diff --name-only --diff-filter=AM HEAD~1 -- . | sed 's#daemon/hnc_httpd/##' | grep '\.go$') ; \
  go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && gofmt -l . ; go vet ./... && go test ./... && go test -race ./output/ ./capture/ \
  && for c in dpid hnc_watchdog dpid_supervisor; do CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null ./cmd/$c || exit 1; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd

# Python 工具
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/build_pkg_app_map.py --check
python3 tools/dpi_rules_split.py sync-legacy --dry-run

# shell
for f in $(git diff --name-only HEAD~1 -- '*.sh') service.sh; do [ -f "$f" ] && sh -n "$f" || echo "SYNTAX $f"; done
sh test/run_all.sh
sh bin/version_consistency_check.sh
sh bin/ci_preflight.sh

# 前端
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done
```
注:`daemon/hnc_httpd` 里有几个旧文件在基线就不满足 gofmt,**只要求你新增 / 修改的文件 gofmt 干净**,不要顺手格式化旧文件。

---

## 6. 验收清单

- [ ] 第 2 节边界无违反;新识别器默认不改变任何连接归属 / 限速 / 限时。
- [ ] 重启(用测试模拟)后 `_auto_expanded.json`、`_auto_promoted.json`、`_imported.json`、同版本的 `97-online-update.json` 都还在;升级模块后 97 与版本文件被清掉。
- [ ] 自动扩展学到的子域名分类结果是父应用 id。
- [ ] QUIC 样本带 `qtp`;指纹学习 / 识别「先 QTP 后回落」;旧 `fp_learned.json` 能加载;识别自评有 `quic` 段。
- [ ] 启动指纹:增量学习、30 分钟节流、只在本机抓包开着时做;客户端产出启动事件;识别自评有交叉验证的 `startup` 段。
- [ ] HMM:默认 classic 时现有 `fg_model_test.go` 全过、行为不变;切到 hmm 后前台与时间线由 HMM 决定;`/api/fg_compare` 有数。
- [ ] 规则库:应用数实际数字写进提交说明(目标 ≥ 300);每个 bucket ≤ 1 MiB;`THIRD_PARTY_NOTICES.md` 已加;没有凭记忆编造的域名。
- [ ] 规则包:导出不含 MAC / IP / UID / 包名;导入校验与冲突跳过有测试;往返一致。
- [ ] 第 5 节全部命令通过,`run_all.sh` 不比 T0 基线差。
- [ ] 版本号、CHANGELOG、changelog.html、ROADMAP、CODEMAP、API.md 已更新。

---

## 7. 提交方式

- 从 `claude/environment-config-ydr2ow` 最新提交新建分支 `ai/v5.27`,先记下基线:`BASE=$(git rev-parse HEAD)`。**每个任务一个提交**,提交信息中文:`v5.27 T2: QUIC 传输参数指纹`。
- 提交署名请用你自己的模型名(`git config user.name "GLM-5.3"` 之类),不要沿用别人的。
- 你的沙箱没有推送权限:用 `git format-patch $BASE..ai/v5.27 -o patches/` 导出补丁(README 里写上 `$BASE` 的值),连同每个任务的自检输出一起交给项目负责人。**不要推 main。**
- 不要改 `CLAUDE.md`。

## 8. 做不完 / 遇到问题怎么办

- 代码和本文档描述对不上:**以代码为准**,在提交说明里写清你怎么处理的。
- 必须越过第 2 节边界才能做:**停下**,该任务不提交,把问题写清楚交回。其余任务照常做。
- 依赖关系:T1 是 T5、T6 的前提;T2 → T3 → T4 有先后(T4 用 T3 的事件,T3 没做时 T4 的 `η` 项为 0 也能工作);T6 在 T2 / T3 没做时对应段落为空也要能工作。
- 时间不够时的优先级:**T1 > T6 > T2 > T5 > T3 > T4**。
