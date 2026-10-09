# 工作文档:HNC v5.31.0-rc1「迁移 M4 方案 A:设备发现与名字解析搬进 Go」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」和第 3 节「测试纪律」是硬约束。
> 背景:`docs/ROADMAP.md` §A(v5.31 行)与 §B(迁移清单 M4)、`docs/CODEMAP.md`、`docs/WORK-v5.30.md`(§3 测试纪律原样沿用)、`CHANGELOG.md` 5.30.0-rc1 / rc2。
> 基线:v5.30.0-rc2(分支 `claude/new-session-hoxhbz` 最新提交;用户「发」过之后即 main)。

---

## 0. 这一版做什么(按优先级)

一句话:**设备发现(谁在线、IP 是多少)和设备名解析从 C 的 hotspotd 搬进 Go 看门狗;hotspotd 只留硬件加速兜底(offload 调度 / BPF limit_map / 控制接口里的 `OFFLOAD_*`)。C 版的发现代码不删,开关一切就退回。**

| 顺序 | 任务 | 一句话 |
|---|---|---|
| T1 | Go 版设备发现(写 `devices.json`) | 邻居表订阅 + 周期全量,语义与 hotspotd 一致,写出同格式的 `devices.json` |
| T2 | Go 版名字解析 | 手动名 → DHCP → mDNS → 缓存 → 厂商 → MAC 兜底,优先级和输出与 C 版一致 |
| T3 | 谁来发现:开关、只能一个写者、hotspotd 瘦身 | 默认值只写在一处、开关双向;hotspotd 加 `--no-discovery`;`device_detect.sh` 的 shell 兜底在 Go 模式下不写 |
| T4 | 控制接口与调用方 | `GET_DEVICES` / `REFRESH` / `STATUS` / `SIGUSR1` 在 Go 模式下的行为;调用点逐个列清 |
| T5 | 模拟设备验收 | 扩展 `test/sim/`:全字段影子比对、Go 模式全流程、运行中来回切换 |
| T-last | 版本与文档 | |

做不完时按 T3 > T1 > T2 > T4 > T5 取舍。**T2 没做完时,默认值必须保持 C 版**(没有名字解析的 Go 版不能当默认)。

---

## 1. 现状(必读)

### 1.1 hotspotd 现在干的事(`daemon/hotspotd/`,C,~6900 行)

- **在哪块网卡上找设备**:读 `run/hnc_state` 里的 `ACTIVE:<网卡>` 行,没有再读 `run/hotspot_iface`(`hotspotd.c read_hotspot_iface`)。同名网卡重建(热点重启后 ifindex 变)要能跟上(`refresh_hotspot_iface` 注释里有教训)。
- **发现**:启动时和每次 `SIGUSR1` 扫 `/proc/net/arp`(flags `0x0` 的跳过);平时订阅邻居表 netlink(`RTNLGRP_NEIGH`)。只认热点网卡上的条目。
- **离线**:每 30 秒检查一次,`now - last_seen > 90` 秒就把设备标成离线(`OFFLINE_CHECK_INTERVAL` / `OFFLINE_THRESHOLD`)。只要邻居表里还是 STALE(flags `0x2`),每次扫描都会刷新 `last_seen` —— **设备悄悄走了、没人给它发包时,它会一直算在线**。
- **写 `data/devices.json`**:只写在线设备(`write_json` 跳过 `!active`),`devices.json.tmp.<pid>` + rename 原子替换。每台一行对象,键是 MAC,字段:`ip mac hostname hostname_src iface rx_bytes tx_bytes status last_seen`(以 `write_json` 实际输出为准,逐字段核对)。
  - `status`:MAC 在 `data/rules.json` 的 `blacklist` 数组里 → `blocked`,否则 `allowed`。
  - `rx_bytes` / `tx_bytes`:写之前跑一次 `sh bin/iptables_manager.sh stats_all`(fork + exec,参数分开传),每行 `<ip> <rx> <tx>`,按 IP 对上。
- **名字**(优先级,见 `hotspotd.c resolve_hostname` 的注释,那是完整链的规范文档;生产路径是 `resolve_hostname_dhcp_only` + 异步 mDNS worker):
  1. 手动命名 `data/device_names.json`(`hostname_src = manual`);
  2. DHCP:`dumpsys network_stack` 里同时含 `hwAddr: <mac>` 和 `hostname: <名字>` 的行,取最后一条非垃圾名(`hnc_helpers.c hnc_ns_dhcp_pick_hostname`,`dhcp`);命中写进缓存;
  3. mDNS:异步队列调 `bin/mdns_resolve`(C 小程序,独立二进制)(`mdns`);命中写进缓存;
  4. 缓存 `data/hostname_cache.json`(`cache:dhcp` / `cache:mdns`);
  5. 厂商:`hnc_helpers.c` 里的 `HNC_OUI_TABLE`(约 900 条)+ `data/oui_overrides.json`;
  6. MAC 兜底:`hnc_mac_fallback`(例:`02:5a:00:00:00:03` → `00000003`,`hostname_src = mac`)。
  - 垃圾名(`null` / `localhost` / 纯数字 …)在 2、3、缓存回放三处都挡(v5.30 T1b)。Go 侧已有同一张表:`src/dpid/hostname`(`hostname.IsJunk`),三份名单有一致性测试 `test/unit/test_v530_junk_table_sync.sh`。
- **控制接口** `run/hotspotd.sock`(`hotspotd.c` 约 1180 行起):`GET_DEVICES`(原样回 `devices.json` 文件内容)、`REFRESH`(排一次扫描,回 `OK:queued`)、`STATUS`(`running:1 devices:N pid:P`)、`OFFLOAD_NOTIFY_LIMIT` / `OFFLOAD_STATUS` / `OFFLOAD_DISABLE_GLOBAL` / `OFFLOAD_RESTORE_GLOBAL`、`QUIT`。
- **硬件加速兜底**:`scheduler.c` / `upstream.c` / `offload/adapter_bpf.c` / `platform.c`(约 2400 行)—— **本版不动**。

### 1.2 谁在用

- **写 `devices.json` 的现在有两个**:hotspotd,以及 `bin/device_detect.sh` 的 `do_scan_shell`(hotspotd 不响应时的 shell ARP 兜底)。
- **读 `devices.json` 的约 43 个文件**(`grep -rln devices.json bin daemon/hnc_httpd src service.sh`)。格式不变它们就都不用改。
- **控制接口调用方**:
  - `bin/device_detect.sh`:`list` → `GET_DEVICES`(失败读文件);`status` → `STATUS`;`scan` → `kill -USR1 <hotspotd>`,然后看 `devices.json` 的 mtime 1 秒内变没变,没变就退回 shell 扫描。
  - `bin/hnc_ipc OFFLOAD_*`:`bin/apply_device_rule.sh`、`daemon/hnc_httpd/action_v5.go`、`bin/hnc_offload_guard.sh`、`service.sh`(约 806 行)—— 都是硬件加速兜底,本版不动。
- **谁拉起 hotspotd**:`service.sh` 经 `device_detect.sh daemon`;Go 看门狗 `main.go hotspotdDaemon()`(参数 `-d`,冷却 60 秒);去重:`service.sh prune_duplicate_hotspotd` 和看门狗每 10 分钟的 `prune_dup_hotspotd`。
- **v5.30 的影子**:`src/dpid/neigh`(netlink 邻居表 dump / 订阅,纯 syscall)+ `src/dpid/cmd/hnc_watchdog/m4_shadow.go`(每 5 分钟比对,`m4_checks` / `m4_mismatch`,开关 `run/wd_m4_shadow.disabled`)。

### 1.3 模拟设备(`test/sim/`,本版的主要验收手段)

不用手机、不用真设备:`test/sim/simnet.sh` 用 Linux 网桥当假热点、每台假设备是一个网络命名空间(真实出现在内核邻居表里),`fake/dumpsys` 冒充 DHCP 记录(能报 `null`),hotspotd 用本机 gcc 编(不带 BPF)在私有挂载空间里跑。`run_m4_sim.sh` 跑 6 步场景,每步用 `TestM4Sim`(`src/dpid/cmd/hnc_watchdog/m4_sim_test.go`,走看门狗真实的影子路径)确认两边一致。用法和原理见两个脚本的头注释;`HNC_SIM=1 sh test/run_all.sh` 一起跑。

v5.30.0-rc2 上的首次结果(写进你的设计里):
- 6 步全部一致;报 `null` / `localhost` 的设备被挡住(退回 MAC 名)。
- **设备离开后 Go(邻居表)约 6 秒发现,hotspotd 约 117 秒**(90 秒阈值 + 30 秒检查周期)。
- **悄悄离开**(没流量去找它,邻居表一直 STALE):两边都发现不了。
- **换 IP 后旧 IP 的表项以 STALE 留在邻居表里**:同一个 MAC 会有两个 IP,Go 接管后必须挑对(见 T1)。

**你的环境如果没有 root / 网络命名空间,跑不了 `test/sim`:场景照写、单测照写,在提交说明里写明「test/sim 未在本地跑」,审查时由维护者在云端容器里跑。**

---

## 2. 边界(硬约束)

1. 隐私与安全红线照旧:不做中间人解密,不注入 / hook 任何设备,不新增采集内容。mDNS 只发 hotspotd 现在就会发的查询(复用 `bin/mdns_resolve`,本版不用 Go 重写 mDNS)。
2. **任何时刻只能有一个写者写 `devices.json` 和 `hostname_cache.json`**(hotspotd / Go / `device_detect.sh` 的 shell 兜底三者之一)。切换时宁可有几秒谁都不写(文件保留上一版内容),也不许重叠。
3. **能回退、双向切、默认值只写在一处**:见 T3。不许写成「有 xxx.disabled 文件就关」这种只能单向关的形状 —— v5.32 正式版可能要把默认值改回 C 版,那必须是改一个常量 + 一个测试的事。
4. `devices.json` 格式:键、字段名、类型、取值范围与 hotspotd 输出一致;只许**增加**字段,不许改已有字段的含义。`hostname_cache.json` 同理(两边读写同一份,格式不变)。
5. hotspotd(C)只加 `--no-discovery` 及其分支,**不删发现代码**(删在 v5.32 之后、方案 A 稳了再说);硬件加速兜底那 ~2400 行不动。
6. API 兼容;不加第三方依赖;不改两个 `go.mod` 的 `go` 版本;`CGO_ENABLED=0`。
7. `service.sh` / `post-fs-data.sh` 只改 T3 / T4 指明的地方;插入点在函数定义之后、不在注释里。

---

## 3. 测试纪律

**原样沿用 `docs/WORK-v5.30.md` §3 的 9 条**(改动前会失败、不许同义反复、测接起来的样子、期望文件要有底线断言、测试密封、不改仓库文件、不靠 sleep、gofmt / 不写没跑过的结论、外部命令参数分开传)。本版加两条:

10. **模拟设备场景是验收的一部分**:T5 列的场景都要有;能跑的环境下全部通过才算完成。场景里的期望必须来自场景本身(加了哪几台、换了什么 IP),不许从被测程序的输出里抄。
11. **与 C 版对照的测试,比的是同一输入下两边的输出**(同一组假设备、同一份 `dumpsys` 输出、同一份 `device_names.json`),不是各自和一份手写期望比。

---

## 4. 任务

### T0 · 记录基线
跑第 6 节全部自检命令(含 `HNC_SIM=1 sh test/run_all.sh`,跑不了就写明),结果写进提交说明(空提交)。维护者环境基线:`sh test/run_all.sh` → `ALL PASS: 538/540 (2 skipped)`;`HNC_SIM=1` → `539/540 (1 skipped)`。

### T1 · Go 版设备发现
- 位置:纯逻辑放新包 `src/dpid/devscan`(名字随你,别和 `output/discover.go`「新发现的应用」混);看门狗里接线(`cmd/hnc_watchdog/m4_owner.go` 之类)。只在「Go 是写者」时运行。
- 输入:`neigh` 包订阅邻居表事件 + 每 30 秒全量 `DumpIf` 一次兜底(事件丢了也能追上);热点网卡按 §1.1 同样的顺序读,同名重建要跟上。
- **在线语义与 hotspotd 一致**(下游 43 个读者和在线时长都依赖它):条目可用(REACHABLE / STALE / DELAY / PROBE)就刷新 `last_seen`;不可用 / 消失后**仍保留 90 秒**才移出 `devices.json`(常量与 hotspotd 同名同值,写在一处)。不要因为 Go 能 6 秒发现就改成 6 秒 —— 那是行为变化,本版不做。
- **同一 MAC 多个 IP**(换 IP 后旧表项还在):按状态挑 —— REACHABLE > DELAY > PROBE > STALE;同状态取最近一次事件 / 确认的。要有单测,也要有 T5 的场景(`simnet.sh ip`)。
- **写文件**:同路径、同字段(§1.1)、原子替换(临时文件名和 hotspotd 的 `devices.json.tmp.<pid>` 区分开)、只写在线设备。写的节拍对齐 hotspotd(设备集合 / 名字变化尽快写、字节数周期刷新 —— 读 `hotspotd.c` 主循环和 `g_last_stats_update` 定出具体值,写进代码注释)。内容没变不写(省电)。
- `rx_bytes` / `tx_bytes`:同样调 `sh bin/iptables_manager.sh stats_all`(参数分开传、带超时);`status` 读 `rules.json` 的 `blacklist`。
- 单测:邻居事件序列 → 设备表(上线、换 IP、离开后 90 秒、热点网卡重建、非热点网卡忽略);写出的 JSON 与一份由 hotspotd 同输入写出的样例逐字段一致(时间戳除外)。

### T2 · Go 版名字解析
- 优先级与 `hostname_src` 取值和 C 版完全一致(§1.1 的 1–6)。
- DHCP:`exec dumpsys network_stack`(不经 shell,超时 500 ms),解析规则照搬 `hnc_ns_dhcp_pick_hostname`(同一行既有 MAC 又有 `hostname: `,取最后一条非垃圾名);垃圾名用 `hostname.IsJunk`。
- mDNS:复用 `bin/mdns_resolve`,异步、限队列长度和并发,超时与 C 版一致;不阻塞发现主循环。
- 缓存:读写同一份 `data/hostname_cache.json`,格式不变;只有当前写者写。
- **厂商表只留一份数据源**:把 `hnc_helpers.c` 的 `HNC_OUI_TABLE` 抽成一个数据文件(Go 用 `go:embed` 读),C 侧本版不改;加一条一致性测试(仿 `test_v530_junk_table_sync.sh`):数据文件与 C 表逐条相同,以后改任一边不同步就失败。`data/oui_overrides.json` 同样读。
- MAC 兜底与 `hnc_mac_fallback` 输出一致。
- 单测:每一级命中 / 跳过;垃圾名;缓存回放带 `cache:` 前缀;与 C 版同输入同输出(可以借 `daemon/hotspotd/test/` 里已有的 C 测试用例数据)。

### T3 · 谁来发现:开关、单写者、hotspotd 瘦身
- **默认值一处**:Go 里一个常量(例 `m4OwnerDefault = "go"`),本版 rc 默认 `go`(就是要在 rc 上验它)。**T2 没做完时默认必须是 `c`。**
- **开关**:`data/m4_owner`(放 `data/` 是因为要跨重启),内容 `go` 或 `c`,两个方向都能强制;文件不存在 = 用默认;内容不认识 = 用默认 + 记一行日志。看门狗每轮读(30 秒内生效),不用重启手机。
- **切换顺序(不重叠)**:
  - c → go:先让 hotspotd 停止发现(带 `--no-discovery` 重启,并确认它真的停了 —— 例如 `STATUS` 回 `discovery:0`),再启动 Go 写者;
  - go → c:先停 Go 写者(等它当前这次写完),再按原参数重启 hotspotd。
  - 中间几秒没人写可以,文件保留上一版。
- **hotspotd `--no-discovery`**:不扫 ARP、不处理邻居事件、不写 `devices.json`、不写 `hostname_cache.json`、不起 mDNS worker;硬件加速兜底、控制接口照常。看门狗 `hotspotdDaemon()` 按当前写者决定带不带这个参数;`service.sh` / `device_detect.sh daemon` 拉起时同样判断(或者统一交给看门狗,二选一,写清楚)。
- **`device_detect.sh` 的 shell 兜底**:Go 模式下不许写 `devices.json`(现在 hotspotd 不响应就会兜底写)。
- **v5.30 的影子比对**:Go 模式下停掉(hotspotd 不发现了,没东西可比);C 模式下照旧跑。
- **可见性**:`watchdog_actions.json` 增加当前写者、Go 写次数 / 失败次数;自检「看门狗动作」行显示「设备发现:Go 版 / C 版(开关 data/m4_owner)」。
- 测试:默认值、开关两种内容、坏内容;切换顺序(用假的 hotspotd 控制接口 / 进程,断言「先停后起」);`device_detect.sh` 在 Go 模式下不写文件。

### T4 · 控制接口与调用方
- `GET_DEVICES`:hotspotd 原样回文件内容,谁写的都一样 —— 不用改,加一条 Go 模式下的测试证明。
- `REFRESH` / `SIGUSR1`(`device_detect.sh scan`):Go 模式下要能触发 Go 立刻全量扫一次。建议 hotspotd 在 `--no-discovery` 时收到 `REFRESH` / `SIGUSR1` 就 touch `run/devices.refresh`,Go 写者每秒看一次它的 mtime;`device_detect.sh scan` 原来的「1 秒内 `devices.json` mtime 变了」判断在 Go 模式下照样成立。别的方案也行,写清楚。
- `STATUS`:`--no-discovery` 时追加 ` discovery:0`(只增不改),`devices:N` 改为数 `devices.json` 里的设备(否则会显示 0 台)。
- 把 §1.2 列的每个调用点在 Go 模式下的行为写进 `docs/CODEMAP.md`。

### T5 · 模拟设备验收(扩展 `test/sim/`)
1. **C 模式不退步**:现有 `run_m4_sim.sh` 全部通过。
2. **全字段影子**:C 模式下让 Go 写者以「演练」方式写到另一个文件(例 `run/devices.go.json`,只在测试 / 演练开关下),每一步与 hotspotd 的 `devices.json` 逐字段比(`last_seen` / 字节数除外):集合、IP、`hostname`、`hostname_src`、`iface`、`status`。场景要覆盖:DHCP 真名、垃圾名、不报名字(MAC 兜底)、`device_names.json` 手动名、`rules.json` 黑名单、换 IP。
3. **Go 模式全流程**:hotspotd 带 `--no-discovery` 跑,Go 写 `devices.json`,跑同样的 6 步场景,期望来自场景;断言 hotspotd 这段时间一次都没写(日志里没有 `JSON written`,或别的可靠证据)。
4. **运行中切换**:场景中途 c → go → c 各切一次,断言没有两个写者交替写(给两边的写各记一行带时间戳的日志,检查没有交错),切完结果仍与期望一致。
5. 能跑的环境下 `HNC_SIM=1 sh test/run_all.sh` 全过,并把 `m4_sim_report.txt`(和你新增场景的报告)贴进提交说明。
6. 选做:假设备里起一个最小 mDNS 应答(netns 里跑一个 Python 小脚本),让 mDNS 那一级也被覆盖。

### T-last · 版本与文档
- `module.prop`:`version=v5.31.0-rc1`,`versionCode=5310001`。
- `CHANGELOG.md` 加 `## [5.31.0-rc1] - <日期>`;`webroot/changelog.html` 加大白话一段(说清:设备发现换成新版、怎么退回旧版)。
- `docs/ROADMAP.md`:M4 行改成「方案 A ✅(开关 `data/m4_owner`)」;`docs/CODEMAP.md`:设备发现的新归属、单写者规则、控制接口在两种模式下的行为;`docs/API.md` 若自检 / 动作统计输出加了字段要补。

---

## 5. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 删 hotspotd 的发现代码 | 开关要能退回;v5.32 之后、方案 A 稳了再删 |
| 动硬件加速兜底(scheduler / upstream / adapter_bpf / `OFFLOAD_*`) | 方案 B,正式版之后;出错表现是「限速悄悄不生效」 |
| 用 Go 重写 mDNS 协议 | 复用 `bin/mdns_resolve`,降低风险 |
| 改「离线 90 秒」等在线语义 | 行为变化,和迁移混在一起没法判断谁出的问题 |
| 删 shell guard / Go supervisor | v5.32 瘦身 |
| 新界面、DPI、QoS 相关 | 不在本版范围 |

---

## 6. 自检命令(每个任务完成后都跑,全部通过才提交)

沿用 `docs/WORK-v5.30.md` §6 的全部命令,另加:

```sh
gcc -O1 -std=c11 -D_GNU_SOURCE -w -pthread -o /tmp/hotspotd_host \
  daemon/hotspotd/hotspotd.c daemon/hotspotd/hnc_helpers.c daemon/hotspotd/hostname_cache.c \
  daemon/hotspotd/oui_override.c daemon/hotspotd/mdns_worker.c daemon/hotspotd/platform.c \
  daemon/hotspotd/scheduler.c daemon/hotspotd/upstream.c daemon/hotspotd/offload/adapter.c \
  daemon/hotspotd/offload/adapter_null.c daemon/hotspotd/lsm/hnc_lsm_stub.c   # C 改动至少本机编过
(cd daemon/hotspotd/test && sh build.sh 2>/dev/null || true)                    # 已有 C 单测(有的话跑)
HNC_SIM=1 sh test/run_all.sh                                                     # 需要 root + 网络命名空间
```
有 NDK 时按 `.github/workflows/build.yml` 交叉编译 hotspotd;没有就在提交说明写明「C 改动未交叉编译」。

---

## 7. 验收清单

- [ ] T1:邻居事件 → 设备表的单测(上线 / 换 IP 挑新 IP / 离开 90 秒 / 网卡重建 / 非热点网卡忽略)在没有实现时失败。
- [ ] T2:每级名字来源的单测;厂商表一致性测试;与 C 版同输入同输出。
- [ ] T3:默认值只在一处、开关双向、坏内容回默认;切换「先停后起」测试;`device_detect.sh` Go 模式不写。
- [ ] T4:`REFRESH` / `SIGUSR1` / `STATUS` 在 Go 模式下的测试。
- [ ] T5:四类场景全部写好;能跑的环境下全过并贴报告。
- [ ] 第 3 节逐条自查;第 6 节全部通过,`run_all.sh` 不比 T0 基线差;gofmt 干净。
- [ ] 版本号、CHANGELOG、changelog.html、ROADMAP、CODEMAP、API.md 已更新。

**维护者真机验收(rc)**:装上后设备列表和以前一样(数量、IP、名字);改名 / 限速 / 封锁照常生效;建 `data/m4_owner` 写 `c` 能退回、写 `go` 能切回;待机一晚耗电与 v5.30 相比没有明显上升。**出现第 8 节任一问题,v5.32 正式版就把默认值改回 C 版**(见 `docs/WORK-v5.32.md`)。

---

## 8. 「有问题」的定义(v5.32 退路规则用,先定好免得到时候争)

v5.31 rc 在真机上出现以下任一条,v5.32 正式版把 `m4OwnerDefault` 改回 `c`(Go 版保留,`data/m4_owner=go` 可手动开),**正式版照常发,不为它推迟**:

1. 成规律地漏设备或多设备(不是刚连上 / 刚断开那几秒的时间差);
2. 设备 IP 对不上;
3. 设备名比 C 版差(同一台设备 C 版有真名,Go 版退回厂商名 / MAC);
4. 某台设备的限速 / 封锁没生效,而切回 C 版就好了;
5. 待机耗电或 CPU 明显上升(看门狗 `power_stats` 对比 v5.30);
6. 看门狗崩溃 / 被拉起次数上升。

---

## 9. 提交方式

- 从基线新建分支 `ai/v5.31`,先记下 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,中文提交信息:`v5.31 T1: ...`。署名用你自己的模型名。
- 没有推送权限:`git format-patch $BASE..ai/v5.31 -o patches/`,README 写上 `$BASE` 和第 6 节命令的**实际输出**;有推送权限:推到 `ai/v5.31`,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 10. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
- T2 做不完:T1 / T3 / T4 照交,**默认值留 `c`**,在提交说明里写明。
