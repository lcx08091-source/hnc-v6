# 工作文档:HNC v5.29.0-rc1「稳定性 + 迁移 M2 / M3」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」是硬约束。
> 背景:`docs/ROADMAP.md` §A(v5.29 行)与 §B(迁移清单 M2 / M3)、`docs/CODEMAP.md`、`docs/WORK-v5.28.md` §1(看门狗结构、`runActionFn` / 动作记账 / 预算测试)、`CHANGELOG.md` 5.26.0-rc1 ~ 5.28.0-rc1。
> 基线:分支 `claude/environment-config-ydr2ow` 最新提交(v5.28.0-rc1 + 审查修复 + 本文档)。

---

## 0. 这一版做什么

1. **迁移 M2**:看门狗热点开着时每分钟的几项检查,改成 **Go 直接读内核 / 直接调命令**,不再每次起 `sh watchdog.sh`(851 行脚本)。shell 版保留为兜底和对照。目标:watchdog 热点空转 **< 20 CPU 秒/小时**。
2. **迁移 M3**:`hnc_offload_guard.sh` 和 `hnc_clsact_watchdog.sh` 两个常驻 shell 循环,改由 Go 看门狗调度。**逻辑先留在 shell**,只把「谁来按时调用」搬进 Go:常驻进程少 2 个。
3. **升级自检 + 自动回滚**:刷了坏包(核心进程起不来)能自动退回上一版。
4. **流量录制 / 回放**:真机录一小段握手元数据,开发机离线回放做 DPI 回归测试(解决「DPI 改动只能真机验证」)。
5. **兼容性报告**:一键导出本机能力报告(脱敏),方便排查不同 ROM。

**为什么先做 1、2**:v5.26 真机实测热点空转 612 CPU 秒/小时,其中 watchdog 530;v5.27 / v5.28 节流后剩下的开销几乎全是「每轮起 shell」。这一版是迁移清单里收益最大的一块。

---

## 1. 项目基本情况(必读)

沿用 `docs/WORK-v5.27.md` §1 与 `docs/WORK-v5.28.md` §1,这里只补本版相关的:

- **看门狗每轮(热点开着、健康时 60 秒)现在做的事**(`src/dpid/cmd/hnc_watchdog/main.go` `handleActive` + `budget.go`):
  | 动作 | 现在怎么做 | 内部实际做了什么 |
  |---|---|---|
  | `probe_hotspot` | `sh watchdog.sh action probe_hotspot` | `probe_valid_hotspot`:`sh device_detect.sh iface`(读 `run/iface.cache` / 调 `hnc_iface.sh`)→ `ip -4 addr show <口>` → 必须是私网 IPv4 → 输出 `"<口> <IP>"` |
  | `check_health` | 每轮 | `tc qdisc show dev <口>` 有 htb 的 root 或 `1:` 句柄;`/sys/class/net/<口>/ifindex` 与 `run/tc_ifindex_<口>` 一致;`iptables -w 2 -t mangle -S HNC_MARK` 存在;`-S HNC_RESTORE` 含 CONNMARK;`run/tc_restore_pending` 不存在。返回 0 健康 / 1 规则丢失 / 2 锁忙 |
  | `httpd_drift` | 5 分钟一次 | 读 `run/httpd.pid`、`run/httpd_bind_ip`、`data/rules.json` 的 `remote_enabled`,两种配置切换时杀 httpd 让它按新绑定重启 |
  | `tc_uplink_healthy` | 3 分钟一次 | 能力标记、`ifb0` 是否存在、`ifb0` 根 qdisc 是否 htb、热点口 ingress 是否有 `mirred → ifb0` 过滤器;缺了才调 `tc_manager.sh ensure_ingress` 修 |
  | `v6_sync.sh` | 每 60 秒 | IPv6 规则同步(本版不动) |
  | `stats_sample.sh` | 5 / 15 分钟 | 统计采样(本版不动) |
- **ColorOS 的坑**:系统自带的 `tc` 是魔改过的,`tc ... ingress` 关键字会被拒(所以 shell 里有 `ingress` 和 `parent ffff:` 两种写法)。仓库里已经有用 **netlink 直通**的 C 工具 `daemon/tc_netlink/`(`hnc_clsact_ctl`),说明「绕开 tc 二进制、直接用 netlink 读写」在这台手机上可行。
- **`hnc_offload_guard.sh`**(421 行):`daemon` 子命令是常驻循环(`tick` → `guard_plan_sleep` → 睡);**已有 `plan` 子命令 = 跑一轮 `tick` 并打印「下次睡几秒 早醒条件」**(`<秒> hotspot|clients|none`)。注意 `apply` 子命令里会 `ensure_daemon`(发现守护循环不在就重新拉起)。`check_offload.sh` 采样里有 `sleep 5`,所以一轮至少 5 秒。
- **`hnc_clsact_watchdog.sh`**(101 行):只在 `clsact_bpf_mode=on` 时由 `service.sh` 拉起,10 秒一轮调 `bin/hnc_clsact_ctl check <口>`(C 二进制,输出 JSON 含 `"ok":true`),不 OK 就 `install` + `hnc_clsact_sync.sh`。门控 `clsact_enabled` 每次都 `sh hnc_offload_guard.sh clsact_wanted`。
- **运行目录同步**:`service.sh` 的 `sync_runtime_from_moddir` 每次开机把模块目录(`/data/adb/modules/hotspot_network_control`)里的 `bin/`、`webroot/`、`daemon/` 等复制到运行目录 `/data/local/hnc/`;**真正运行的是运行目录里的副本**。
- **dpid 抓包**:`src/dpid/capture/`(`rawsocket.go` 收包、`parse.go` 解析出 `Event`:DNS / TLS ClientHello / QUIC Initial / HTTP),`cmd/dpid/main.go` 的回调把事件分发给各输出模块。

---

## 2. 边界(硬约束)

1. 隐私与安全红线照旧:不做中间人解密,不注入 / hook 任何设备,不新增采集内容。**录制(T4)只录握手类元数据包,默认关闭、限时、限大小、只存本机**。
2. **迁移的「行为一致」是硬要求**:M2 的 Go 实现在同样的系统状态下,结论必须与 shell 版一致(健康 / 不健康 / 锁忙、哪个口、什么 IP)。必须有对照机制(见 T1),不一致时**以 shell 结果为准**并记一次「不一致」。
3. **随时可回退**:M2 / M3 都要有开关,一个文件就能退回旧做法(不需要重刷模块)。
4. 不改 tc / iptables / 限速 / 封锁规则的**内容**;修复路径(`full_restore`、`ensure_ingress`、`clsact install`)仍调用现有 shell / C 工具。
5. API 兼容、持久化格式只增不改;不加第三方依赖,不改两个 `go.mod` 的 `go` 版本,`CGO_ENABLED=0`。
6. 不改 CI;`customize.sh`、`post-fs-data.sh` 只在 T3 明确允许的范围内改;`service.sh` 只改 T2 / T3 指明的地方。
7. 每个改动配「在改动前会失败」的测试并写明验证方法;shell 测试测行为,不许只 grep 源码。
8. **编辑器不许把 Tab 换成空格**(v5.26、v5.28 都出过事):提交前对所有改动的 Go 文件跑 `gofmt -l`,对改动的 shell 文件确认缩进与原文件一致。**不要声称「基线就不满足 gofmt」,除非你在基线提交上实际跑过并贴出结果。**
9. 第 4 节「不做」清单一律不碰。

---

## 3. 任务(按顺序做,每个任务一个提交)

### T0 · 记录基线
跑第 5 节全部自检命令,结果写进提交说明(空提交)。维护者环境基线:`test/run_all.sh` → `ALL PASS: 486/487 (1 skipped)`。

---

### T1 · 迁移 M2:看门狗每分钟的检查改成 Go 原生

**新包 `src/dpid/nlroute/`**(纯 Go,`syscall` 实现,不加依赖):
- `QdiscList(ifindex int) ([]Qdisc, error)`:NETLINK_ROUTE、`RTM_GETQDISC` + `NLM_F_DUMP`,解析 `tcmsg{family, ifindex, handle, parent}` 与属性 `TCA_KIND`(字符串)。`Qdisc{Kind string; Handle, Parent uint32}`。
- 解析函数要能**直接喂字节**测试(拆成 `parseQdiscMsgs([]byte)`),测试用手工构造的 netlink 报文覆盖:多条消息、`NLMSG_DONE`、`NLMSG_ERROR`、属性对齐、截断报文(必须返回错误,不能 panic)。
- 只读,不做任何写操作。

**Go 原生实现**(新文件 `src/dpid/cmd/hnc_watchdog/native.go`):
1. `nativeProbeHotspot()`:`ifacehint.Read(runDir, now)` 拿到口名(只用 5 分钟内新鲜的结果),再用 `net.InterfaceByName` + `Addrs()` 取 IPv4,必须是 10/8、172.16/12、192.168/16 私网且口名不是 `wlan0`。拿不到新鲜结果 → **返回「不确定」,由调用方退回 shell 版**(shell 版会顺带刷新 `iface_detect.json`)。
2. `nativeCheckHealth(iface)`:与 shell `check_health` 逐项对应 —— `run/tc_restore_pending` 存在 → 1;能力文件说不支持 tc_htb → 跳过 tc 检查(同 shell);`nlroute.QdiscList` 里有 kind=htb 且(parent = 根 `0xFFFFFFFF` 或 handle = `0x00010000`)否则 1;ifindex 对比;`iptables -w 2 -t mangle -S HNC_MARK` / `HNC_RESTORE` **由 Go 直接 exec iptables**(不经 sh),返回码语义完全照抄 shell(2 = 链真丢 → 1;其他非 0 → 锁忙 2;HNC_RESTORE 里没有 CONNMARK → 1)。保留 shell 版的 5 秒结果缓存语义(同一轮重复调用不重复执行)。
3. `nativeHttpdDrift()`:读同样三个文件(rules.json 用 `encoding/json` 只取 `remote_enabled`),两种场景的判断照抄;**需要动手时**(杀 httpd、撤 guard 规则)仍调 `runActionFn("httpd_drift")` 让 shell 执行,Go 只负责「需不需要」的判断。
4. `nativeUplinkHealthy(iface)`:能力标记文件判断照抄;`ifb0` 是否存在用 `net.InterfaceByName`;`ifb0` 根 qdisc 是否 htb 用 `nlroute`;ingress `mirred → ifb0` 过滤器的判断**由 Go 直接 exec `tc filter show dev <口> ingress`,失败再试 `parent ffff:`**(不经 sh;解析 netlink 过滤器嵌套 action 本版不做)。任何一项不满足 → 调 `runActionFn("tc_uplink_healthy")` 让 shell 去修(含它的 5 分钟重试冷却、失败计数、降级标记,逻辑不搬)。
5. **开关**:`run/wd_native.disabled` 存在 → 全部退回 shell 版(现有代码路径原样)。默认用原生。
6. **对照机制**:原生版每 30 分钟额外跑一次对应的 shell 动作,比较结论(probe 的口 / IP、health 的 0 / 1 / 2);不一致 → **本轮以 shell 结论为准**,记账 `native_mismatch`(进 `run/watchdog_actions.json`,自检「看门狗动作」行一并显示),日志写清两边结果。连续 3 次不一致的检查项自动退回 shell 版直到看门狗重启。
7. `budget_test.go` 更新预算:ACTIVE 健康 1 小时里**经 sh 的调用合计 ≤ 70**(v6_sync 60 + stats + 对照 + 偶发),原生检查不计入 sh 调用。
8. 测试:
   - `nlroute` 报文解析(见上);
   - 每个原生函数用假文件 / 假 `nlroute` / 假 exec(包级变量注入)覆盖 shell 版的每个分支,**测试用例名与 shell 分支一一对应**,并在注释里写出 shell 原文行号;
   - 对照机制:构造原生与 shell 结论不同 → 以 shell 为准 + 计数 + 连续 3 次后退回;
   - 开关文件:存在时只走 shell。

**验收**:预算测试通过;真机热点空转 1 小时,`/api/power` 的 watchdog < 20 CPU 秒(维护者实测);`native_mismatch` 为 0。

---

### T2 · 迁移 M3:offload / clsact 两个 shell 守护改由 Go 调度

**做法:**
1. **offload 兜底**:Go 看门狗新增一个后台任务(这是允许新增的唯一 goroutine —— 它替换掉一个常驻 shell 进程):
   - 启动 20 秒后第一次跑;每次 exec `sh bin/hnc_offload_guard.sh plan`(带 30 秒超时,经动作记账,动作名 `offload_guard_plan`),解析末行 `<秒> <早醒条件>`;
   - 睡对应秒数;早醒条件 `hotspot` = activity 显示热点开了、`clients` = 有在线设备时提前醒(复用 `actReader`,每 30 秒看一次);
   - 解析失败按 60 秒。
2. `hnc_offload_guard.sh`:
   - `ensure_daemon` 在 `run/offload_guard.owner` 内容为 `watchdog` 时**什么都不做**(否则 httpd 调 `apply` 会把 shell 守护循环拉回来);
   - `daemon` 子命令开头同样检查,owner 是 watchdog 就记一行日志退出。
3. **clsact 守护**:同一个后台任务里,当 `rules.json` 的 `clsact_bpf_mode` 为 `on`(或兼容旧键,判断逻辑照抄 `guard_mode`)且 `bin/hnc_clsact.o`、`bin/hnc_clsact_ctl` 都在时,每 10 秒 **Go 直接 exec `hnc_clsact_ctl check <口>`**(不经 sh),输出不含 `"ok":true` 才调 `sh bin/hnc_clsact_watchdog.sh repair <口>`。门控结果缓存 60 秒(不再每 10 秒 `sh hnc_offload_guard.sh clsact_wanted`)。
4. `service.sh`:Go 看门狗存在时写 `run/offload_guard.owner=watchdog`,**不再**拉起这两个 shell 守护;Go 看门狗缺失时保持旧行为。开关:`run/wd_m3.disabled` 存在 → 看门狗不接管,`service.sh` 照旧拉 shell 守护(下次开机生效,提交说明写清)。
5. `cleanup.sh`:停止时一并清 `run/offload_guard.owner`。
6. 测试:plan 输出解析(正常 / 坏行 / 空);早醒条件;owner 文件让 `ensure_daemon` / `daemon` 不起循环(shell 行为测试);clsact 门控与修复调用次数;预算测试加「offload 任务 1 小时 ≤ 60 次 sh(无设备时按 plan 的 300 秒应 ≤ 15)」。

**验收**:常驻进程少 2 个(自检进程段 / `/api/power` 不再出现 `offload_guard`、`clsact_wd` 的 shell 进程);offload 兜底状态文件 `run/offload_guard.json` 照常更新。

---

### T3 · 升级自检 + 自动回滚

**目标**:刷了坏包(新版核心进程起不来)时,自动退回上一版,并在界面告诉用户。**只看「核心进程能不能起来」,不看网络规则**(网络规则会因为各种原因暂时不健康,拿它做回滚条件会误伤)。

**做法:**
1. **快照**:`service.sh` 的 `sync_runtime_from_moddir` 在覆盖运行目录之前,如果模块 `versionCode` 与 `data/runtime_version` 记录的不同(= 刚升级),先把运行目录里的 `bin/`、`daemon/`、`webroot/` 打包到 `/data/local/hnc/.prev/`(只保留一份,先写临时目录再整体换,失败不影响开机),记下旧版本号;然后照常同步,写新的 `data/runtime_version`。
2. **升级观察期**:升级后的头 10 分钟,由 `service.sh` 的哨兵(它是 shell,不依赖新版 Go 二进制能不能跑)每 30 秒检查:`hnc_httpd` 进程活着(`run/httpd.pid` + `bin/hnc_proc.sh` 的 `pid_matches`)**并且** loopback 端口 8444 处于监听状态(读 `/proc/net/tcp` / `tcp6`,本地端口 `20FC`、状态 `0A`;手机上不保证有 curl / nc,不要依赖它们)、`hnc_watchdog` 活着(`pid_matches`)。
3. **触发回滚**:观察期内**连续 6 次(3 分钟)httpd 和 watchdog 都起不来**,或任一个**崩溃重启 ≥ 5 次** → 把 `.prev/` 恢复到运行目录,写 `data/rollback.json` `{from, to, reason, at}`,写 `data/rollback.pinned`(内容 = 新版 versionCode),重启核心进程。
4. **钉住**:`sync_runtime_from_moddir` 看到 `data/rollback.pinned` 且模块 versionCode 仍等于它 → **跳过同步**(否则下次开机又把坏版本拷回来);模块 versionCode 变了(用户刷了更新的包)→ 删 pinned,正常同步。
5. **界面**:`/api/health` 或 `/api/config` 带出 `rollback` 信息;前端顶部显示一条横幅「检测到 vX 启动失败,已自动退回 vY;请把诊断包发给开发者」,带「导出诊断包」按钮和「知道了」(写 `data/rollback.ack`)。自检加一行「升级状态」。
6. **开关**:`data/rollback.disabled` 存在 → 只记录不回滚。
7. **测试**(shell,临时目录模拟模块目录与运行目录):升级时生成快照;同版本重启不生成;观察期内模拟「httpd / watchdog 都起不来」6 次 → 回滚 + pinned;pinned 时跳过同步;刷更新版本后清 pinned;快照失败不影响开机;`rollback.disabled` 时只记录。

**验收**:维护者刷一个故意坏的包(例如把 `hnc_httpd` 换成空文件),3 分钟内自动退回上一版,界面出现横幅。

---

### T4 · 流量录制 / 回放(DPI 回归测试)

**做法:**
1. **录制(dpid)**:新开关文件 `run/capture_record.request`(内容 = 录制分钟数,1~30,默认 10)。dpid 看到后开始把**已经被解析成 DNS / TLS ClientHello / QUIC Initial / HTTP 请求头事件的原始包**写成标准 pcap 文件 `run/capture_rec/rec-YYYYMMDD-HHMMSS.pcap`(只写这几类包;单文件上限 20 MB;到时 / 到量即停并删除请求文件)。写盘在后台 goroutine,抓包回调里只做非阻塞入队(照抄 `label_samples.go` 的做法)。新增 action `capture_record {minutes}` / `capture_record_stop`,设置 → 诊断里加按钮,并显示「录制中 / 剩余时间 / 文件大小」;录完后把文件移到 `exports/`,并让 `api_export.go` 的 `isExportArchive` 认这类文件名,这样它会出现在现有「导出」列表里可下载。**界面明确提示:录制内容包含连接设备访问的域名,只存本机、请勿随意分享。**
2. **回放(开发机)**:新命令 `src/dpid/cmd/dpid_replay/`:读 pcap,逐包送进 `capture` 的同一套解析函数(复用,不复制代码),输出事件 JSON(每行一个:时间、类型、SNI、JA4、QTP、ALPN、DNS 名字、规则库分类结果)。
3. **回归测试**:`src/dpid/testdata/replay/` 放 2~3 个**人工合成**的 pcap(用测试代码生成,不放真机录制;覆盖 DNS、TLS 1.3 ClientHello、QUIC v1 Initial、ECH 外层、分片 ClientHello)和对应的期望输出;`go test` 跑回放并逐行比对。以后改解析器时,输出变化必须同时更新期望文件(在提交说明里解释为什么变)。
4. 测试:pcap 写入 / 读回;录制的大小与时长上限;只录指定类型;回放输出与期望一致。

---

### T5 · 兼容性报告

**做法**:action `compat_report` → 生成 `exports/hnc-compat-YYYYMMDD.json`,内容:模块版本、Android 版本 / 品牌 / 型号(`getprop`)、内核版本、root 方案(KernelSU / Magisk / SukiSU 的识别方式照抄自检)、`run/capabilities.json`、`run/qdisc_caps.json`、offload 兜底状态、dpid 守护选择(`run/dpid_launcher.choice`)、自检各段的状态汇总(只有 正常 / 警告 / 失败 的计数和项目 ID,不含具体值)、看门狗动作记账摘要。**脱敏**:不含 MAC、IP、SSID、热点密码、设备名、序列号、IMEI、任何 token;测试里用含这些内容的夹具断言输出里搜不到。设置 → 诊断加「导出兼容性报告」按钮(下载方式照抄诊断包)。

---

### T-last · 版本与文档
1. `module.prop`:`version=v5.29.0-rc1`,`versionCode=5290001`。
2. `CHANGELOG.md` 加 `## [5.29.0-rc1] - <日期>`:写清 M2 / M3 迁了什么、开关文件在哪、对照机制;回滚的触发条件与开关;录制的隐私边界。
3. `webroot/changelog.html` 加一段大白话。
4. `docs/ROADMAP.md`:§A v5.29 行标「rc1 ✅」;§B 的 M2、M3 标完成。
5. `docs/CODEMAP.md`:「手机上跑着的进程」去掉两个 shell 守护;权威实现表加 `nlroute`、`native.go`、回滚(`service.sh` + `data/rollback.*`)、`dpid_replay`。
6. `docs/API.md` 加「## 27. v5.29 变更」:新 action、`rollback` 字段、`native_mismatch`、开关文件清单(`run/wd_native.disabled`、`run/wd_m3.disabled`、`data/rollback.disabled`)。

---

## 4. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 用 netlink **写** tc / 改规则下发方式 | 迁移清单 M8(6.0) |
| 把 offload / clsact 的业务逻辑翻译成 Go | 本版只搬调度;逻辑迁移等 M2 / M3 在真机稳定后再说 |
| `v6_sync.sh`、`stats_sample.sh` 原生化 | 下一批 |
| 设备发现 hotspotd 改 Go、dpid 守护链收缩 | M4 / M5,v5.30 |
| 用网络规则健康状况触发回滚 | 误伤风险高,见 T3 |
| 录制完整流量 / 包内容 | 隐私红线 |

---

## 5. 自检命令(每个任务完成后都跑,全部通过才提交)

```sh
# Go(改动过的 Go 文件必须 gofmt 干净;不要整文件重排缩进)
for f in $(git diff --name-only HEAD~1 -- '*.go'); do [ -f "$f" ] && gofmt -l "$f"; done
(cd daemon/hnc_httpd && go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && go vet ./... && go test ./... && go test -race ./nlroute/ ./output/ ./cmd/hnc_watchdog/ \
  && for c in dpid hnc_watchdog dpid_supervisor dpid_replay; do CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null ./cmd/$c || exit 1; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd

# Python 工具
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/build_pkg_app_map.py --check
rm -rf tools/__pycache__

# shell
for f in $(git diff --name-only HEAD~1 -- '*.sh') service.sh bin/watchdog.sh; do [ -f "$f" ] && sh -n "$f" || echo "SYNTAX $f"; done
sh bin/pitfall_lint.sh
sh test/run_all.sh
sh bin/version_consistency_check.sh
sh bin/ci_preflight.sh

# 前端
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done
```

---

## 6. 验收清单

- [ ] T1:原生检查与 shell 版逐分支对应的测试齐全;对照机制与开关可用;预算测试「经 sh 调用 ≤ 70 次 / 小时」通过。
- [ ] T2:Go 看门狗接管时不再有 offload / clsact 的 shell 常驻进程;httpd 调 `apply` 不会把 shell 循环拉回来;开关可退回。
- [ ] T3:升级快照、观察期、回滚、钉住、解钉、开关都有 shell 行为测试;界面横幅。
- [ ] T4:录制有时长 / 大小上限且只录握手类包;回放用合成 pcap 的回归测试通过。
- [ ] T5:兼容性报告的脱敏有测试。
- [ ] 每个改动有「改动前会失败」的测试并写明验证方法;所有改动的 Go 文件 `gofmt -l` 为空。
- [ ] 第 5 节全部命令通过,`run_all.sh` 不比 T0 基线差。
- [ ] 版本号、CHANGELOG、changelog.html、ROADMAP、CODEMAP、API.md 已更新。

**维护者真机验收(发布前)**:热点空转 1 小时功耗截图(目标 watchdog < 20 CPU 秒、总计 < 100);重启后自检进程段与「看门狗动作」正常、`native_mismatch` 为 0;刷一个故意坏的包验证回滚。

---

## 7. 提交方式

- 从 `claude/environment-config-ydr2ow` 最新提交新建分支 `ai/v5.29`,先记下 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,中文提交信息:`v5.29 T1: 看门狗检查原生化(M2)`。
- 提交署名用你自己的模型名。
- 没有推送权限:`git format-patch $BASE..ai/v5.29 -o patches/`,README 写上 `$BASE`;有推送权限:推到 `ai/v5.29`,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 8. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
- 依赖:T1 用到 v5.28 的 `runActionFn` 与动作记账;T3 用到 v5.28 的 `bin/hnc_proc.sh`。
- 时间不够时的优先级:**T1 > T2 > T3 > T5 > T4**。
