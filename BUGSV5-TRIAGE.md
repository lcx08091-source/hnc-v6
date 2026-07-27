# BUGSv5 真机缺陷清单 · 代码侧分诊报告

> 来源:用户 2026-07-26 真机探测清单(realme GT 7 Pro / ColorOS 16 / kernel 6.6.89 / SukiSU)。
> 基线:HEAD `509262b`(v5.9.2)。15 条全部逐条对照**当前 main 源码**复查,对判为"已修/不存在"的结论额外做了对抗性交叉验证。
> 结论分布:still_open 10 · partial 5 · fixed_in_repo 0。其中 6 条推翻或改写了原报告的归因。

# HNC v6 真机缺陷清单 · 代码侧分诊报告

**基线**:HEAD `509262b` (v5.9.2) · 判定全部基于当前 main 源码,不引用报告原文结论
**核实口径**:15 条全部逐条对照代码复查,其中 6 条经对抗性交叉验证后**推翻或改写了报告的归因**

---

## 〇、先说三个影响全局的前提修正

1. **"真机跑旧构建"这个免责前提,对 dpid 侧全部结论无效。**
 `src/dpid/cmd/dpid/main.go:33` 的 `var version = "0.5.3-rc30.12.3-iface-retry"` 与真机上报串一字不差;`git log -- src/dpid/cmd/dpid/main.go` 显示最后一次改动是 `f6b5456`(v5.7.0-rc11),v5.8.x/v5.9.x **一次都没碰过**。所以 BUG-001/003/011/013 现象不能归因于旧构建,当前 main 就是这个状态。
2. **本批 15 条里没有一条可判 `fixed_in_repo`。** 唯一带 v5.9.x 修复成分的是 BUG-002(`ab1eb41` 的 7 天保留确实生效)与 BUG-005(`492b83b` 的 offload 横幅确实落地),但两者都只覆盖了部分路径,判 `partial`。
3. **"一次 CI 重编覆盖三个二进制"是伪成本。** `.github/workflows/build.yml` 每次 push main 都无条件重编全部二进制(hnc_httpd / hnc_dpid / hnc_watchdog / hnc_dpid_supervisor / hnc_launcher+fork_probe / hnc_tc_ingress / hotspotd+hnc_ipc+mdns_resolve,见 build.yml:152/162/175/191/232/243/263)。**改 1 个二进制和改 3 个,CI 成本完全一样。** 批次划分的真实约束是"真机验证成本"与"回归半径",不是重编次数。

---

## ① 总表

> 原始 BUGSv5.md 未随核实材料传入,"报告口径"列为核实记录中被引述的报告主张;标 `~` 者为推断。

| ID | 报告口径 | 实测状态 | 重估等级 | 一句话结论 |
|---|---|---|---|---|
| **BUG-001** | AP 接口重建后 dpid 不重绑 | **still_open** | **P0** | `runCapture` 的 `iface` 在循环外只取一次、`Handle` 无 ifindex 字段、Run 遇零包永久空转 → 改名/选错网卡/offload 三条路径永不自愈,且真机走的是无 netlink 监管的 C launcher |
| **BUG-003** | mode=ok 但 packets=0,无人发现 | **still_open** | **P1** | `mode=ok` 的语义只是"socket 开成功了",三个 watchdog 全部只看进程存活、零个读 `dpi_state.json` 的 packets,UI 还给绿点"正常·抓包中" |
| **BUG-011** | ip_app_map 长期为空 | **still_open** | **P1** | `IPAppMap.Record` 全仓库唯一写入路径挂在主抓包 EventFlow 上,与 001 连带;DNS/TLS 两条路径一条都不贡献;空表时 `apply_app_limits.sh` 直接 `exit 0`,应用级限速静默失效 |
| **BUG-002** | self_attrib 撑到 1.8GB | **partial** | **P1** | 7 天保留(`ab1eb41`)确实生效且启动首 tick 就删——但 trim 是按名逐日回推,只削尾巴不清大头;无单文件封顶、无 WebUI 清空、>30 天文件永不删 |
| **BUG-004** | hotspotd 把上游 wlan0 当热点客户端 | **still_open** | **P1** | `is_hotspot_iface()` 是反向黑名单,wlan0/eth/bt-pan 一律放行;netlink NEIGH 路径不按热点 ifindex 过滤、全链路零网段校验;同进程内 `upstream.c` 还认定 wlan0=上游,自相矛盾 |
| **BUG-014** | 日志 fd 跟着 .log.1 走 | **still_open** | **P2** | `log_rotate.sh` 用 `mv` 而非 copytruncate,而所有长驻 daemon 的 stdout 是 spawn 时一次性 O_APPEND fd;再轮两次 `rm -f $f.2` 会 unlink 掉仍被持有的 inode → 日志消失且空间不释放 |
| **BUG-008** | json_legacy_fallback 一直涨=hnc_json 坏了 | **still_open** | **P2** | **归因反转**:hnc_json 用 `exit 3` 表示"键不存在",三个 wrapper 把它和 rc=1/2/127 同等当故障计数;已本地实测复现。后果:SLA 面板显示一个无意义大数 + 400 行 legacy writer 永远无法退役 |
| **BUG-005** | 上行限速失效被 offload 旁路,且无止损 | **partial** | **P2** | 止损层 v5.9.1 已落地(横幅+文案显式覆盖上行+去掉默认关的开关);但检测是流量门控的(≥1MB/5s 才判 ACTIVE),没跑流量时永远不弹;**根因归因存疑**,仓库自己在 RMX5010 的对照实验反而否证 offload |
| **BUG-007** | ARCHITECTURE 路径/字段漂移 | **still_open** | **P2**(报告 P3) | 漂移面比报告大得多,且已污染可执行代码:`bin/diag/diag.sh:117-125` 读 `data/dpi_state.json`(实际在 run/)→ 诊断包对 DPI **恒定输出 MISSING**,把正常 dpid 误报成挂了 |
| **BUG-015** | README 版本号自相矛盾 + 链接指旧仓库 | **still_open** | **P2** | 根因是 `bin/inject_version_to_docs.sh` 写好了但**从未接进 CI**;README 会被打进刷机 zip,用户拿到的版本栏就是字面 `{{VERSION}}`;另有两条死链和两个 diag 脚本互指 |
| **BUG-009** | 目录 777 | **still_open** | **P2** | 仓库无一处 `chmod 777`——是 `mkdir -p` 无 mode + 引导脚本无 umask(继承 magiskd umask=0)的必然结果;唯一能修的 `json_set.sh init_dirs` 只有单测调用。0777 无 sticky → `run/local_admin.secret` 可被 unlink 重写伪造 |
| **BUG-006** | IPv6 完全不受限速管辖,推 6.0 | **partial** | **P2** | **报告显著低估现状**:`v6_sync.sh` + `ipt_dual()` 双栈链路从 v3.4.0 起完整存在且 6 类事件驱动。真缺口是统计纯 v4(v6 流量 UI 完全不计)、应用限速纯 v4、police 回退纯 v4,外加一条疑似死规则 |
| **BUG-012** | tc_state 快照 9 天不更新 | **partial** | **P3** | 稳态下不更新是设计(纯事件驱动,无心跳);但"快照没更新⇒tc 树没变"的反推不成立——`apply_app_limits.sh`(每 30s)与 `cleanup.sh` 两条真改 tc 的路径完全绕过快照,且消费端只判文件存在不判 ts |
| **BUG-013** | ipv6_capture 两个 JSON 互相矛盾 | **still_open** | **P3** | 两处是互不相干的硬编码常量:probe 恒 `false`、writer 构造函数恒 `true`,`SetMode` 不透传它。对照组 TLSReassembly/OffloadHint 走完整链路,证明这是遗漏不是设计 |
| **BUG-010** | portal 残留文件 | **partial** | **P3** | 报告若暗示"代码还在读写"——否决,唯一命中是未合入的 patch 文件;但 `cleanup.sh` 的 run/ 清理是白名单式逐项 rm,不含 portal_*,只有卸载才会带走 |

**分布**:still_open 10 · partial 5 · fixed_in_repo 0 · not_a_bug 0 · needs_device 0(但有 6 条带 needs_device 子问题,见 ④)

---

## ② 仍需修复项详列(按重估等级)

### P0

#### BUG-001 · dpid 抓包接口永不重绑

**根因链**
- `src/dpid/cmd/dpid/main.go:382` `iface := pr.APIface` —— 赋值在 `for {`(:384)**外面**,L384-562 全文无二次赋值
- `src/dpid/cmd/dpid/main.go:166` `probe.Run(...)` 全仓库唯一调用点;`:180` `capture.SetHotspotNets(nets)` 同样只在启动时调一次 → AP 换 IP 后 `capture/parse.go:304` 的方向推断永久错
- `src/dpid/capture/rawsocket.go:127` `Ifindex: ifc.Index` 只在 Open 那一刻解析;`Handle` 结构体(:43-69)**没有 ifindex 字段**,Run 路径零校验
- `src/dpid/capture/rawsocket.go:237-239` EAGAIN → `continue`,零包永久空转;Open 只在 Run 先返回后才重调 → 不重解析 ifindex
- **外部监管在真机上不生效**:`service.sh:637-682` 的 launcher 优先级是 `hnc_launcher`(C) > `hnc_dpid_guard.sh` > `hnc_dpid_supervisor`;**只有排最后的 Go supervisor 有 netlink 重绑**(`dpid_supervisor/main.go:572-601`),而 `src/launcher/hnc_launcher.c:391-490` 是纯 fork/waitpid/backoff,零 netlink、零 dpi_state 读取

**三条无论如何都不自愈的路径**(均产生 mode=ok+packets=0):
(a) AP 接口改名(wlan2→ap0/swlan0):iface 被钉死,永久对着错网卡或不存在的名字重试
(b) 启动期选错网卡:`iface.go:104-132` 中 `^wlan[1-9]\d*$` 对 wlan1/wlan2 同 rank,热点未拿到 IP/ARP 时 tie-break 落到 `a.Name < b.Name`(:131)选中 wlan1,之后永不纠正
(c) offload/桥接导致该网卡上就是收不到客流(`pr.OffloadHint` 只写 state,不影响任何判定)

> 诚实标注:"同名新 ifindex"这一子场景,内核 packet_notifier 置 `sk_err=ENETDOWN` 后可经 `main.go:574` 自愈,理论上不需修。但 (a)(b)(c) 与该内核细节无关。

**修复方案**
1. `capture/rawsocket.go`:`Handle` 加 `ifindex int` 字段,Open 时存入已有的 `ifc.Index`,导出 `Ifindex()`(仿 :172 的 `LinkType()`)
2. `main.go:382`:抽 `resolveAPIface(cfg)`(cfg.Iface 覆盖 → `run/hotspot_iface` hint → `capture.DiscoverAPCandidates()[0].Name`),与 supervisor 的 `getIface()`(`dpid_supervisor/main.go:191-207`)口径对齐,每轮循环重解析
3. 在 `main.go:444` 的 5s stats goroutine 旁加 15s 巡检 goroutine(同绑 attemptCtx),命中任一条件即 `attemptCancel()`:
 a. `/sys/class/net/<iface>/ifindex` != `h.Ifindex()`
 b. `resolveAPIface(cfg)` != 当前 iface
 c. **失聪判定**:`h.Stats().Packets` 连续 12 轮(3min)不增长 **且** 同期 `/sys/class/net/<iface>/statistics/rx_bytes` 有增长
4. 每次 Open 成功后重跑 `SetHotspotNets`(把 `main.go:178-190` 抽成函数,在 :406 前调用)
5. 新增 `rebind_count` 进 dpi_state,供 `/api/sla` 与 WebUI 观测

**工作量**:main.go 约 70-90 行 + rawsocket.go 约 6 行,含单测 1.5-2h
**CI 重编**:**必须**(hnc_dpid,arm64)。纯改源码不重编等于没修
**风险**:
- 失聪判定**必须**带 rx_bytes 门控。只用 `packets==0 持续 N 分钟` 会在夜间无客户端时反复重启 dpid,清空全部 clients/apps 聚合
- 重绑会把 `rawsocket.go:59-68` 的 atomic 计数器归零 → `dpi_state.stats.packets` 跳回 0,而 `webroot/index.html:7925` 的 `updateCounterTrend('pkts',...)` 假定单调递增。需在 Writer 侧累加历史总量,或接受趋势线断点
- iface flap 期间 b/c 可能连锁触发紧循环:保留 `main.go:556` 的 2s backoff,并给重绑次数设上限(60s 内 >5 次退到 30s 周期)
- 新增巡检后会与内核 ENETDOWN 路径"抢着重绑",需确认 `rawsocket.go:174-181` 的 `closeOnce` 足以避免 fd 复用竞态

---

### P1

#### BUG-003 · mode=ok 谎报"正常·抓包中"

**根因**
- `output/state.go:420-428` `SetMode` 是唯一写 `Mode` 的地方,原样赋值零校验
- `main.go:406` `sw.SetMode(ModeOK, ...)` 紧跟 Open 成功后无条件执行,**整个 attempt 生命周期内不复查**
- `main.go:637-648` `decideMode` 只看 DisableCapture/AFPacketAvailable/APIface,无任何流量条件
- 三个 watchdog 全部只看进程存活:`bin/watchdog.sh:459-517`(全函数不出现 dpi_state.json)、`hnc_watchdog/main.go:484-537`(从不打开 dpi_state.json)、`hnc_launcher.c:391-490`(零状态文件读取)
- 唯一读 dpi_state 的 `dpid_supervisor/main.go:362-368` 是对全文做 `"network is down"` 子串匹配,只在 dpid **已自报 blind** 后才命中
- `api_sla.go:74-76` 暴露的是 restart_count/crash_recent/heartbeat_age,没有 packets 没有 mode;`index.html:7877-7879` 给"正常·抓包中"+绿点,零交叉校验

**修复方案**(建议只做前两层)
1. **dpid 自报 degraded,不动 mode 语义**:5s goroutine 维护 `lastPkts` + `lastProgressAt`,配 rx_bytes 门控;`output.State` 新增 `health`("ok"/"degraded")与 `stall_seconds`,加 `SetHealth()`。**不要把 mode 翻成 blind** —— supervisor 的子串匹配与 UI 的 blind/waiting 分支都会被误触
2. **UI 说实话**:`index.html:7877` 的 `case 'ok'` 里加 `stall_seconds > 180 || (packets==0 && uptime_s > 300)` → 徽标转 warn,文案"已绑定但零抓包 · DPI 实际失效,请点重新绑定 DPI";:7942 圆点同步
3. (可选,慎做)`watchdog.sh:459` 末尾读 `health:degraded` → 冷却 ≥10min 调一次 `dpi_rebind.sh`

**工作量**:第1层 dpid ~47 行;第2层前端 ~15 行;第3层 shell ~25 行。合计 2-3h
**CI 重编**:第1层必须(hnc_dpid);**第2/3层纯前端+shell,可先单独发一版止血**
**风险**:
- rx_bytes 门控是核心不是可选项,否则把"没人用"报成"坏了",用户会学会忽略告警
- `bin/dpi_rebind.sh` 的 `write_state()` 手写 schema_version:1 极简模板,会覆盖掉 health 字段(重绑瞬间 UI 看到旧 schema);`api_dpi_v53.go:23` 是整文件透传所以安全,但要跑 `bin/json_regression_test.sh`
- **第3层风险最高**:`bin/dpi_rebind.sh` 顶部 rc11 注释记录过"两个管理者互相打架导致 dpid 反复死"的历史事故。**先做 BUG-001 让 dpid 自己修自己**,001 修完仍复现再上第3层

#### BUG-011 · ip_app_map 恒空 → 应用级限速静默失效

**根因**
- `output/ip_app_map.go:85-99` `Record` 的**唯一调用点**是 `output/state.go:636-638`,在 `applyRuleHitLocked`(:619)内
- `applyRuleHitLocked` 只被 `RecordFlow`(:595/:607)调用;`RecordFlow` 只被 `cmd/dpid/main.go:524` 调用,在主 AP 抓包的 `case capture.EventFlow` 分支里
- → 无 EventFlow ⇒ 恒空 ⇒ 30s flusher 照常成功写出空 JSON 和 0 字节 .flat,**永远不报错、日志一行不打**
- `bin/apply_app_limits.sh:112-116`:`.flat` 为空则 log 一行后 `exit 0`,对上游看起来是成功
- 两条独立于 001 的缺口:`bumpLabelLocked`(state.go:645-656)签名里**没有 remoteIP 参数**,DNS/SNI 路径不可能写 IPAppMap;`self_capture.go:293` 的 `ObserveSNI` 同样不喂
- `RecordFlow` 还有前置门槛:`state.go:560-564` 拒绝从 EventFlow 建客户端档案,依赖 DNS/TLS 先建档,而建档链依赖只设一次的 `hotspotNets`
- `IPAppMap.Size()`(:166-170)存在但**全仓库无调用者**,dpi_state 里没这个数字 → 长期为空只能人肉 cat 发现

**修复方案**
1. 先修 BUG-001(必要条件,主数据源就是 EventFlow)
2. **补 TLS 路径(收益最大)**:`bumpLabelLocked` 加 `remoteIP string` 形参,命中 `classifyHost` 后 Record;`RecordTLS`(:521)把已有的 remoteIP 传进去。TLS ClientHello 的 remoteIP 就是应用服务器 IP,语义正确
3. **DNS 路径必须用 Answers 不能用 remoteIP**(后者是 DNS 服务器,直接 Record 会把 8.8.8.8 标成某 app):把 `ev.DNS.Answers`(`capture/parse.go:33`)从 `main.go:509` 传进 RecordDNS,对每条非 `CNAME:` 前缀的答案 IP 按 qname 命中规则 Record
4. `IPAppObs` 加 `Src string`("flow"/"tls"/"dns"),禁止低置信来源在 5min 窗口内覆盖高置信来源
5. `Size()` 写进 dpi_state.stats,WebUI DPI 页加"IP→APP 映射: N 条";为 0 且 mode=ok 时黄色提示"应用级限速当前未生效"

**工作量**:约 70 行 / 3-4h 含单测
**CI 重编**:必须(hnc_dpid)。**收益完全被 001 卡着,排期上应同批交付**
**风险**:
- DNS 派生精度显著低于 flow 派生(浏览器 prefetch 会产生根本没访问的 IP),叠加 `ip_app_map.go:23` 的 last-writer-wins,共享 CDN IP 会被 DNS 抢走 → 给错误的 app 打 MARK,用户体验是"限了 A 结果 B 卡了"。**第4步的来源优先级不是可选项**
- `ipAppMapMaxEntries=2000`(:47)+ 5min 过期:补 DNS 后条目暴涨可能顶到上限,而 Flush 的截断(:120-123)按 LastSeen 降序——DNS 派生的"刚解析"条目时间戳更新会**优先留下**,恰恰是反的。截断需按来源加权
- `api_export.go:152-156` 把 ip_app_map.json 打进诊断包;shell 侧读 .flat 不受影响,但要确认 .flat 生成不被新字段带偏

#### BUG-002 · self_attrib 日志膨胀(partial)

**已生效部分**:`output/self_attrib.go:57` `SelfAttribRetainDays = 7`;`:630-642` 的日切 trim 挂在采样主循环里,四个生效条件全部成立(`lastTrimDay` 初值空 → 首个 5s tick 就删;trim 在 `isEnabled()` 门禁**之前**,自捕获关掉也照删;`jsonlDir` 来自 `main.go:283` 非空;`RunSampler` 在 `main.go:331` 无条件启动)。真机 1.8GB 属旧构建现象。

**仍缺三点**
1. `output/history.go:264-273` `trimDailyFiles` 只按名逐日回推 `os.Remove`,无 readdir:10 天数据只删第 8/9/10 天,前 8 天**按设计保留**(按 294MB/天仍达 1.5-2GB);**>30 天文件永不删**;非严格 `self_attrib.YYYYMMDD.jsonl` 命名永不删
2. **无单文件上限**:`self_attrib.go:694-702` 是裸 O_APPEND,写前不 Stat 不判大小;采样周期仍是 `SelfAttribInterval = 5s`(:51,一天 17280 条),单日 294MB 的路径原封不动
3. **无 WebUI 清空入口**:`server.go:130-146` 的 self 路由只有读+导出;`actionCleanupAll`(`action_v5.go:503-511`)调的 `cleanup.sh:178-179` 只删 hostname_cache 和 run/v6,不碰 `run/*.jsonl`

**修复方案**:① 加 `SelfAttribMaxDailyBytes = 32<<20`,`sampleOnce` 开文件前 Stat,超限跳过本 tick 并置 `JSONLCapped` 进 SelfState(不要静默丢);② `trimDailyFiles` 换 `filepath.Glob` + 文件名解析日期,保留"绝不删当天正在写的文件"这条不变量;③ `action.go` 加 `self_attrib_purge`,前端 APPS 区加按钮+二次确认
**工作量**:~90 行(Go 60 / 前端 30),半天
**CI 重编**:必须(hnc_dpid + hnc_httpd)
**风险**:readdir 版日期解析写错会误删当天文件——`src/dpid/output/trim_test.go` 已有骨架,必须扩"、>30 天也删 + 当天不删"用例;缩短保留期会影响 `api_export.go:144-146` 的 from/to 范围导出,需在 manifest 标注"已被保留期裁剪";glob 前缀严格锚定 `self_attrib.` 且校验 8 位日期

#### BUG-004 · hotspotd 把上游接口当热点客户端来源

**根因**
- `daemon/hotspotd/hotspotd.c:193-201` `is_hotspot_iface()` 是反向黑名单(skip: lo/rmnet/dummy/v4-/tun/p2p/r_rmnet),**wlan0/eth0/bt-pan 一律 return 1**
- `hotspotd.c:895-898` netlink NEIGH 路径**不按热点 ifindex 过滤**,只把 ifindex 翻名字再喂黑名单 → 内核在 wlan0(STA 口)学到的每条 ARP 邻居都会走到 :933-978 的"设备上线"分支,`alloc_device()` + `iface="wlan0"` 直接进 devices.json(`write_json` :566-607 对 iface 无再过滤)
- `hotspotd.c:649-659` scan_arp 同一黑名单,**零网段校验**(全文件 grep `192.168|subnet|inet_pton` 只在 mdns 分支 :1268 命中一次)
- 仓库自相矛盾:`daemon/hotspotd/upstream.c:131-133` 明确把 wlan0/wlan1 归为**上游**
- 前端只做了"误屏蔽"兜底(`index.html:6349-6362` 拉黑前弹确认,且硬编码 `'wlan0'`),设备列表/在线数/统计/限速下发一律照旧
- `hotspotd.c` 最后一次改动是 `479ad0b`(v5.9.0),与旧构建无关

**修复方案**(约 150 行 C):黑名单 → **白名单 + ifindex + 同网段**三重过滤
- A. 新增 AP 集合状态(`g_ap_name/g_ap_idx/g_ap_net/g_ap_mask/g_ap_n/g_ap_valid`),`ap_reload()` 来源优先级:`run/iface.cache`(`watchdog.sh:143` 写)→ rules.json 的 `hotspot_iface`(`watchdog.sh:836`)→ 枚举 `/sys/class/net` 中 UP 的 `ap*`/`swlan*`/`wlan[1-9]`/`rndis0`/`usb0`
- B. 失效钩子复用 `hotspotd.c:885-888` 已有的 RTM_NEWLINK/DELLINK 分支置 `g_ap_stamp=0`,每轮 drain 开头超 30s 重载
- C. `:895-898` 改 `ap_slot_by_index(ndm->ndm_ifindex)`(数值比较,顺带省掉 `if_indextoname` 的 ioctl);`:918` 后追加 `ap_subnet_ok()`
- D. `:659` scan_arp 改 `ap_slot_by_name` + 同网段
- E. **兜底路径(`g_ap_valid==0`)必须比现状更严不能更松**:保留原黑名单 + 硬排 wlan0/eth/bt-pan + 复用 `upstream_detect_via_proc_route()` 排掉当前上游 + 强制 RFC1918
- F. 一次性清污:`ap_reload()` 成功后把 devices.json 中 iface 不在白名单的条目丢弃后重写(否则 restore_rules 会继续给上游 IP 下 u32 filter)
- G. 前端 `index.html:6358` 的 `iface === 'wlan0'` → `iface !== state.hotspotIface`

**工作量**:C 侧 ~150 行 + 前端 1 行,约 1 天含回归
**CI 重编**:必须(hotspotd,arm64,libbpf submodule 链)
**风险(三个真坑)**:
1. **白名单来源不可靠会造成"0 设备"回归,比误报严重**:`run/iface.cache` 只在 `watchdog.sh:136-143` 的 active 探测里写且被 `CAP_PROBE_MIN_INTERVAL` 节流,热点刚起那几十秒可能为空或是上个 iface。**E 条兜底不是可选项**,必须保证"解析失败=退回旧行为+额外排上游",绝不能解析失败就全过滤掉
2. 别把合法 downstream 过滤掉:USB 网络共享(rndis0/usb0)、双频多 AP 都是真客户端,白名单必须是集合不是单值
3. ifindex 复用是**新引入**的风险(今天每条消息现查名字所以不存在):LINK 事件失效 + 同网段二次校验两层一起上才安全。另外同网段校验会把"刚连上、DHCP 未下发"的 169.254.x 条目丢掉(现状会显示),属行为变更需写 CHANGELOG

---

### P2

#### BUG-014 · 日志轮转让 daemon 的 fd 跟着旧 inode 走
**根因**:`bin/log_rotate.sh:55-63` 用 `mv` 三代轮转(脚本头 :24-27 把"下次 append open 会走新文件"这个假设写死,对 shell 的每行重开成立,对长驻 daemon 全不成立);写者端 `bin/hnc_dpid_guard.sh:424`、`src/launcher/hnc_launcher.c:308-315`、`dpid_supervisor/main.go:509-513`、`service.sh:866/920/937`、`bin/dpi_rebind.sh:110` 全是 spawn 时一次性 `>>`;dpid 收 SIGHUP 只打日志(`main.go:213-214`)。`watchdog.sh:198` 每 300s 触发一次 → dpid.log 过 1MB 就永久走进 .log.1,再轮两次被 `rm -f $f.2` unlink。同时 `api_v5.go:301-315` 的 allowedLogs 不含 .1/.2,WebUI 日志页看到的是空的新文件。附带:`hnc_launcher.c:93` `fopen(LOG_LAUNCHER,"a")` 缺 `e`(O_CLOEXEC),exec 出的 dpid 继承并 pin 住该 inode(同文件 :165 用了 CLOEXEC,说明是漏了)。
**修复**:① **止血,纯 shell**:rotate_one 改 copytruncate,`cp "$f" "$f.1" && : > "$f"`(**必须 `&&` 串联**,cp 失败绝不 truncate)。所有写者都用 O_APPEND,truncate 后写位置自动回头,不留稀疏洞,一处修好全部 daemon;② 根治:dpid 加 mutex 保护的日志 reopen 挂到 SIGHUP + 轮转后 `kill -HUP`;`hnc_launcher.c:93` 改 `"ae"`;allowedLogs 补 `.1/.2`
**工作量**:第1步 ~8 行/30min;第2步 ~60 行
**CI 重编**:第1步**不需要**;第2步需 hnc_dpid + hnc_launcher(C) + hnc_httpd
**风险**:copytruncate 丢 cp 与 truncate 之间的几行(日志场景可接受);SIGHUP reopen 必须 mutex 包住 io.Writer,直接换 `log.SetOutput` 有并发写风险;launcher 的 fd 泄漏只占 inode/fd 不影响正确性,**别为它单独发版**

#### BUG-008 · json_legacy_fallback 计数把"键不存在"当故障
**根因**:`bin/hnc_json:300/311`(及 get_device :388/391/394、C 版 `hnc_json.c:94`)用 `exit 3` 表示未命中;`bin/json_set.sh:580-591/596-607/618-628` 三个 wrapper 一律 `[ $rc -eq 0 ] || return $rc`,调用点 `:788-789/:817-818/:877-878` 无差别计数。已本地端到端实测:三次未命中 → count=3;命中不增。热路径必然一直涨:`device_detect.sh:220`(每轮对每台未命名设备 +1)、`apply_device_rule.sh:369/389-392`(一台无延迟设备 +5)、`tc_manager.sh:944/947`、`action_v5.go:140/:214`、`action_dev_sqm.go:48`。危害:`api_sla.go:82` → `index.html:11093` 把这个数当健康指标展示(正是本次报告被误导的直接原因);`CODE-ARCHITECTURE-REVIEW-v5.8.9.md:306` 定的"计数长期为 0 才能退役 400 行 legacy writer"因此**永远不可能达成**。
**修复**:三个调用点显式分流 `[ $rc -eq 3 ] && exit 0`(键不存在=正常空答案);另拆 `run/json_hnc_json_miss.count` 只记 rc=3;`test/unit/` 补"未命中后 count 仍为 0"回归
**工作量**:~20 行 / 1h
**CI 重编**:**不需要**(第3项拆计数才需重编 hnc_httpd)
**风险**:改前全量 grep 一遍 `json_set.sh (top_get|device_get|name_get)` 确认没有调用方靠非 0 退出码判断键缺失(已核对的 6 处都只读 stdout);**rc=2(文件缺失/JSON 非法)与 rc=1(锁超时,`hnc_json:103`)必须继续计数**,那才是真故障信号

#### BUG-005 · 上行限速与 offload(partial)
**已落地**:`index.html:2846-2857` 横幅文案显式写"导致下行/上行限速不生效或明显偏松";`:6115-6134` 触发条件不再依赖任何用户开关(旧实现那个默认关的开关问题已在 :6105-6107 自述并修掉);`api_v5.go` 的 runOffloadCheck 从子串收紧成整词;`main.go:185` 30s 刷缓存
**仍缺**:① 检测是流量门控的——`bin/check_offload.sh:38-66` 需窗口内 ≥1MB/5s(≈1.6Mbps)才判 ACTIVE,用户不跑流量时设上行限速永远看不到横幅,叠加 30s cache + 60s 前端轮询最坏 90s;② 横幅在 page-devices 顶部(:2838)而上行输入框在设备卡内(:9404),用户滚到卡片时横幅已出视口,且 dismiss 按 detail 走 sessionStorage
**根因归因存疑**:`check_offload.sh:12-21` 与 `CHANGELOG.md:206` 都记着 RMX5010 实测——手工置 `tether_limit_map[iif]=0` 前后 HTB 精度"无可观测变化"。更可能的嫌疑是 `tc_manager.sh:1110` 的 `install_ingress_mirred: mirred add FAILED (all paths) ... (上行限速将失效!)`
**修复**:① 把警告下沉到操作点(`index.html:9404-9414` 复用已有的 `.input-hint warn` 模式);② `check_offload.sh` 加第四态 `CAPABLE`(map 存在但增量不足,且 limit_map 里有本机上游 ifindex 条目)—— **只更新状态行不弹横幅**;③ 把 `tc_manager.sh:1110` 的 log_error 提到 WebUI(复用 `index.html:5385-5386` 的"tc 修复失败/上行失败"计数位),让用户能区分"offload 抢走了"和"mirred 压根没装上"
**工作量**:前端 ~20 行 + shell ~10 行,半天
**CI 重编**:**不需要**
**风险**:`CAPABLE` 若被接成弹窗条件,就会退回 v3.4.1 那个"map 存在就报警"的误报老路(`check_offload.sh:7-16` 记着这段历史);根因定性**需要真机**(见 ④)

#### BUG-007 · 文档漂移已污染可执行代码
**真 bug(把本条从 P3 抬到 P2 的关键)**:`bin/diag/diag.sh:117-125` 读 `$HNC/data/dpi_state.json`,而实际路径是 `run/`(`dpid/main.go:38/43/155` 写、`api_dpi_v53.go:23`/`api_self.go:49`/`api_export.go:139`/`server.go:661` 读,全部 run/)→ 诊断包 [11] 段**恒定输出 "dpi_state.json MISSING"**,而 `COMPATIBILITY.md:114` 正是叫用户跑这个脚本。另 `README.md:96` 指向的是另一个 diag 脚本(`bin/diag.sh`,路径正确),两份文档指两个脚本本身也是漂移。
**文档侧**:ARCHITECTURE.md 中 devices.json 路径(run/→data/)、dpi_state.json 路径(data/→run/)、`names.json`→`device_names.json`、stats 字段名(`pkts`→`packets`)、`iface`→`interface`、`uptime_sec`→`uptime_s`、mode 缺 `crash_loop`、顶层 `actives/rank/history_24h` 三个键在 `State` 结构体里根本不存在,以及 devices.json **根本不是** `{schema, hotspot_active, devices[]}` 结构而是**扁平 MAC→对象 map**(`hotspotd.c:561-607` 只写 9 个键;`vendor`/`first_seen` 全文件零命中,`online`/`rx_bps`/`tx_bps` 由 httpd `server.go:369-396` 注入)
**修复**:diag.sh 3 行 + ARCHITECTURE.md 约 25 行(含一整段 schema 重写);统一 README/COMPATIBILITY 指向同一个 diag 脚本;建议加 CI 护栏对 `/data/local/hnc/(run|data)/<file>` 与代码里 `filepath.Join` 对表
**工作量**:1-1.5h
**CI 重编**:**不需要**
**风险**:**别把报告结论抄进文档**——devices.json 是存在的,hotspotd.sock 不是它的替代品(两者并存,`device_detect.sh:70` 还会回落到 data/devices.json),写"已改用 sock"会制造新假文档;重写 schema 段要写清"httpd 注入字段 vs hotspotd 真写字段"的分界

#### BUG-015 · README 版本占位符未注入 + 链接指旧仓库
**根因**:`bin/inject_version_to_docs.sh` 写好了(:30 读 module.prop、:44-47 目标 README+ARCHITECTURE、:71-77 sed 替换、:58-66 已实现 `--check`),但 `.github/workflows/build.yml` **零调用**(grep `inject` 只命中 :304/309/312 三行 Go `-X main.version` 注入);`bin/version_consistency_check.sh`(CI 唯一版本护栏)不检查文档占位符;`README.md` **不在** zip 排除列表里(build.yml:345-375 排掉了 ARCHITECTURE/EVOLUTION/COMPATIBILITY/INSTRUCTIONS/CLAUDE.md 但没排 README)→ 用户装机拿到的版本栏就是字面 `{{VERSION}} ({{DATE}})`,而 module.prop 是 v5.9.2。另 `README.md:78/98` 指向 `hnc-v5` 仓库,`:120` HACKING.md 与 `:126` CONTRIBUTING.md 均不存在。README 最后一次改动是 `f6b5456`(v5.7.0-rc11),与旧构建无关。
**修复**:A. 改链接与死链;B. **接 CI**(checkout 之后、zip 之前插 `sh bin/inject_version_to_docs.sh` + `--check`,**不要 commit 回仓库**);C. `version_consistency_check.sh` 末尾加占位符残留检查
**工作量**:~30-45min
**CI 重编**:不需要,但**需跑一次完整 CI 验证注入真的生效**(`--check` 会自证)
**风险**:**只改 A 不做 B 是典型"修一半"**,下版依然是 `{{VERSION}}`;`sed -i` 若误加 git commit,下次 inject 会走到 :78-81 的 noop 分支,**从此永久锁死在某个旧版本号**——这是最危险的误修法;改 hnc-v5→hnc-v6 前需用户确认 GitHub 上公开发布仓的真实名(本环境 origin 走 local_proxy,只能证明本地配置)

#### BUG-009 · 关键目录 0777
**根因**:仓库**没有任何一处 chmod 777**,是"`mkdir -p` 无 mode + 引导脚本无 umask"在 Magisk/KSU(umask=0)下的必然结果。`post-fs-data.sh:12-14/46/60/77/177`、`service.sh:16/227/690`、`bin/v6_sync.sh:118` 全部裸 `mkdir -p`;全仓库 umask 只出现 3 次(`service.sh:421-423`)且是子 shell 隔离、只作用于 local_admin.secret 一个文件。唯一能修目录权限的 `json_set.sh:739-741 init_dirs` 分支,调用方只有 `test/unit/test_json_set.sh`,真机永远跑不到。Go 侧的 `MkdirAll(...,0755)` 全是空转(对已存在目录不改权限,且 post-fs-data 早已把目录建成 0777)。危害:0777 无 sticky → 能 traverse 进来的非 root 进程可 unlink/rename 掉 `run/local_admin.secret`(`middleware.go:433`)再写自己的,伪造 `X-HNC-Local-Admin` 拿到 root 级写 API;`data/tokens.json` 同理。缓解:SELinux 使 untrusted_app 访问不到,真实可利用面是其他 root 模块 / adb shell(uid 2000)—— 这是判 P2 不判 P1 的原因。
**修复**:只收顶层 + 敏感子目录,**不动 umask**。`post-fs-data.sh:14` 后 `chmod 700 $HNC_DIR data logs run`;:46/60/77 后给 bin/api/webroot/test/daemon/bpf 755;:177 后 `chmod 700 "$BACKUP_DIR"`;`service.sh:16`/`:690` 补同款(WebUI"重启后端"直接 fork service.sh 不经 post-fs-data);`v6_sync.sh:118` 后 700;`json_set.sh:741` 改 700/755 分级;test/unit 加 `stat -c %a` 断言
**工作量**:~10 行 shell / 30min
**CI 重编**:**不需要**
**风险**:**绝对不要用全局 `umask 077` 一把梭**——`post-fs-data.sh:47-51` 用 `cp -rf` 且不带 `-p`,而后面的 chmod 覆盖面不完整(:82 的 `chmod 755 bin/*.sh` glob 不递归,漏 `bin/diag/diag.sh`;:105-115 只覆盖 10 个白名单二进制名,漏 `bin/diag/fork_probe`、`bin/hnc_ndpi_probe`)→ 会掉到 0600 造成"文件在但不能执行"的静默回归。chmod 700 后非 root adb shell 不能直接 cat 日志(需先 su),已核实不影响任何生产路径(httpd 由 root 拉起;KSU WebUI 全走 ksu.exec;httpd serveIndex 读的是模块目录硬编码路径 `server.go:164`,不读 $HNC_DIR/webroot)

#### BUG-006 · IPv6 覆盖缺口(partial,报告严重低估现状)
**已存在(反证)**:`iptables_manager.sh:95/102-106/112-129/150-154` 的 `ipt_dual()` 双栈下发,HNC_RESTORE 的 CONNMARK restore(:191-194)与 HNC_SAVE(:213-217)、mark_device 的 MAC 兜底(:272-275)、黑白名单(:391/436-455)全部双栈;`bin/v6_sync.sh`(295 行,v3.4.0)从 iptables 反查限速设备 + `ip -6 neigh` 取活跃全局地址 + 下发 `protocol ipv6 u32 match ip6 dst/src` filter,由 `tc_manager.sh` set_limit 的**全部 7 个返回分支**(:1651-1701)、`watchdog.sh:833/886/1238-1242`、`iptables_manager.sh:363`、`hnc_watchdog/main.go:868-870` 六类事件驱动
**真缺口**:
- **a. 流量统计纯 v4**(最实际的痛点):`iptables_manager.sh:202/210-212/283-287/465/501` 明确 HNC_STATS v4 only,而 `device_detect.sh:298-300` 与 stats_sample.sh 全从它读字节 → **v6 流量 UI 完全不计**,速率曲线/日月配额系统性低估,现象是"限速明明生效,统计却几乎不动"
- **b. 应用级限速纯 v4**:`apply_app_limits.sh:213` 显式 `protocol ip` 无 v6 对应条;:221-226 打 mark 用裸 `iptables` 无 ip6tables 镜像 → 应用走 v6 即可完全绕过
- **c. IFB-less 上行 police 回退纯 v4**:`tc_manager.sh:800` 注释 "IPv4 only for now",:812-815 只有 `protocol ip`
- **d. fw 兜底 filter 疑似死规则(PLAUSIBLE)**:`tc_manager.sh:503-505` 的 `tc_filter_fw_set()` 是全仓库唯一**不带 `protocol` 关键字**的 `tc filter add`。iproute2 未指定 protocol 时 tcm_info 低 16 位留 0,内核 `tcf_classify` 只在 `tp->protocol == skb protocol || == ETH_P_ALL` 时才进 classifier,protocol=0 两条都不满足 → 若成立,`ensure_device_class`(:717-720)的"fw 备用分类路径"一直是空的,整套 MARK/CONNMARK 对 tc 分类无实际贡献(只对 HNC_STATS 和黑白名单有用)
- **e. v6_sync 时效性**:最坏 60s 一次(`watchdog.sh:1238`),privacy extensions 临时地址轮换后有最长 60s 全速窗口
**修复**:a 用"tc class 字节数 − v4 字节数"取 v6 分量(tc class 计数天然是 v4+v6 合计),**不要照抄 v4 的 per-IP RETURN**(v6 地址动态,正是 `:283` 放弃的原因);b 补 `protocol ipv6` filter + ip6tables 镜像(**前置依赖 ip_app_map 输出 v6 地址,要改 Go**);c 复制一份 v6 police;d 改 `protocol all`,**`:503` 与 `:1849` 两处 del 必须同步带 protocol 否则删不掉旧规则会堆积**;e 60s→15-20s 或复用 `run/dpid.netlink.event`
**工作量**:a 80-120 行 shell 0.5-1 天(不重编);b ~40 行 shell + Go(需重编)约 1 天;c ~15 行 2h;d 3 行**但必须先真机验证**;e ~5 行 30min
**风险**:d 未经真机验证前不要改——若判断错误,加 `protocol all` 会改变现有 filter 优先级排布

---

### P3

#### BUG-012 · tc_state 快照陈旧(partial)
**根因**:写者只有 `bin/tc_state_snapshot.sh`,自身无定时器;触发全靠 `tc_manager.sh:2311-2315` 的 `tc_snapshot_async` 在 :2329-2430 的命令分发里(init/cleanup/restore/set_limit/... 一条不漏),`watchdog.sh`/`service.sh` 全文 grep `snapshot|tc_state` **零命中** → 稳态下停在上次 init 是设计而非 bug。**但两条真改 tc 的路径完全绕过**:`apply_app_limits.sh` 被 `hnc_watchdog/main.go:955-983` 每 30s fork 一次做全量 iptables+tc 重建(:88-102 删、:208/213 建),全程不走分发器;`cleanup.sh:127-138` 直接删 root/ingress/ifb0 qdisc 同样不刷 → cleanup 后 tc_state.json 仍写着 `htb_ready:true` 与真实空树完全相反。消费端 `bin/diag.sh:256-264` 与 `bin/json_health_panel.sh:57` 只判文件存在不判 ts,会把 9 天前的快照报成"健康"。
**影响面小**:`webroot/` 与 `daemon/hnc_httpd/*.go` **均无** tc_state 引用;`json_diag_bundle.sh:197-198` 打包前会重跑,正式诊断包总是新鲜的。被误导的只有"直接 cat 排障"与那两行 ok。
**修复**:apply_app_limits 加 `_tc_changed` 标志、真动过才刷(**不要无条件每 30s 刷**,否则 tc_state.log 每天多 2880 行);cleanup.sh:140 前补一次同步 snapshot;diag.sh/json_health_panel.sh 从"文件存在"改成"存在且 `now - .ts <= 900`",超期报 warn ——**这是本条真正值得做的部分**
**工作量**:~20 行 shell / 30min · **不需要重编**
**风险**:`tc_snapshot_async` 是 `( ... ) &` 背景子 shell,而 `action.go:612-633` 的 runBin 用 `CombinedOutput()`(Wait 要等管道所有写端关闭),子 shell 自己的 fd1/fd2 仍握着管道。若给 snapshot 加周期/长耗时逻辑,**优先挂在 watchdog(纯 shell 父进程)而非 httpd 触发路径**;给 diag 加陈旧告警会让一批现存装机从 ok 变 warn,需写 CHANGELOG

#### BUG-013 · ipv6_capture 两个 JSON 恒矛盾
**根因**:`probe/capability.go:40` `IPv6Capture: false` 之后 Run() 剩余 40 行(:42-70)再没写过它;`output/state.go:402` NewWriter 里 `IPv6Capture: true` 硬编码,而 `SetMode`(:420-428)签名不含它、函数体不碰它。对照组 TLSReassembly 走完整链路(capability.go:38 → main.go:193/369/394/406/554 透传),证明是遗漏。**dpi_state 的 true 更接近事实**(`capture/bpf.go:84` 确实放行 0x86dd,`parse.go:215` 有 IsIPv6 路径),但带扩展头的 IPv6 包被 DROP(`bpf.go:8/118`),所以 true 也只是粗略近似。`grep ipv6_capture webroot/` 零命中,UI 从不渲染 → 无功能后果,只误导排障。
**修复**:capability.go:40 改真实探测(如 `capture.BPFSupportsIPv6()`);删 state.go:402 的硬编码;`SetMode` 加 `ipv6Capture bool` 参数并同步 7 个调用点(`main.go:134/160/193/369/394/406/554`)
**工作量**:~12 行 / 20-30min · **必须 CI 重编 hnc_dpid**
**风险**:加参数是破坏性签名改动,漏改会编译失败(这反而安全);**千万不要用可变参数或独立 setter"避免改调用点"**;注释里必须写明"IPv6 扩展头包不被捕获",别让 true 被读成完整 IPv6 支持

#### BUG-010 · portal 残留清理缺口(partial)
**根因**:`portal_pending|portal_sessions` 全树唯一命中是未合入的 `patches/HNC-v5_8_8-portal-0_1_4.patch:993-994`(带 `+` 前缀的 diff 新增行);`git show --stat 0e6f45b` 证实那次 commit 只改了 1 个 patch 文件。**但清理路径确实漏**:`cleanup.sh:177-181` 的 run/ 清理是白名单式逐项 rm(`*.pid`/`netevt_*`/`arp_hash`/`hotspotd.sock`/`dpid.netlink.event`/`hostname_cache`/`run/v6`/`scan_tmp.*` 等),**不含 portal_***,三种 mode 都清不掉;只有 `uninstall.sh:23` 的 `rm -rf run/` 会带走,而日常清理与 v5.8.9-portal→v5.9.x 升级都不走这条。同族的 `data/portal_config.json`、`logs/portal_*.jsonl` 连卸载都不删(`uninstall.sh:25` 明写不删 /data/local/hnc 本身)。叠加 BUG-009 的 run/ 0777 → patch 里 chmod 644 的会话表躺在人人可进的目录里。
**修复**:`cleanup.sh:179` 旁 + `post-fs-data.sh:167` 后 + `uninstall.sh:23` 后各加一行带守卫的 rm:`[ -f "$HNC_DIR/bin/portal_manager.sh" ] || rm -f ...`(portal 合入后该脚本必然存在)。**post-fs-data 那处是必须的**,cleanup 不是每次开机都跑
**工作量**:3-6 行 / 15min · **不需要重编**
**风险**:若将来真把 portal 合入 main,这几条 rm 会每次开机清空会话表(用户被强制重认证)甚至删掉配置——守卫只是保险,合入时应显式删掉这几行;`data/portal_config.json` 可能已被 `post-fs-data.sh:170-196` 的每日备份复制进最近 7 份 `.backup-*`,彻底清需动用户备份目录,**建议不做,只在 CHANGELOG 说明**

---

## ③ 建议的 v5.9.3 批次

### 分批原则(修正自"CI 重编成本"的前提)
CI 每次都全量重编,所以真正该分批的依据是:**(1) 是否需要真机验证才能确认没有回归;(2) 回归半径**。据此分三档发布。

### 🟢 v5.9.3 —— 纯 shell/前端/文档止血批(零 Go/C 改动,零真机验证前置)
可以**今天就发**,全部改动在真机上失败也只是回到现状,不会更糟。

| 项 | 内容 | 行数 |
|---|---|---|
| BUG-014 步骤1 | `log_rotate.sh` 改 copytruncate —— **一处修好全部长驻 daemon 的日志黑洞** | ~8 |
| BUG-008 | `json_set.sh` 三个调用点 rc=3 分流 + 单测 | ~20 |
| BUG-007 A | `bin/diag/diag.sh` 三处路径 data/→run/ + ARCHITECTURE.md 逐行勘误 + 统一 diag 脚本指向 | ~28 |
| BUG-015 A+B+C | README 链接/死链 + CI 接 `inject_version_to_docs.sh` + 版本护栏加占位符检查 | ~26 |
| BUG-009 | post-fs-data/service.sh/v6_sync/json_set 的 chmod 700/755 + 单测断言 | ~10 |
| BUG-010 | 三处带守卫的 portal 遗骸 rm | ~6 |
| BUG-012 步骤1+2 | apply_app_limits 条件刷快照 + cleanup 补一次 + diag/health_panel 加 900s 新鲜度判定 | ~20 |
| BUG-003 第2层 | `index.html:7877` mode×packets×uptime 交叉校验,零抓包时徽标转 warn(纯前端可独立判定,不依赖后端 health 字段) | ~15 |
| BUG-005 ①② | 上行输入框旁加 offload hint + `check_offload.sh` 加 `CAPABLE` 态(只改状态行) | ~30 |

**合计 ~165 行,全部 `sh -n` / `node --check` 可验。** 收益:止住日志黑洞、消掉 SLA 面板的假告警、让诊断包不再谎报 DPI 挂了、让 README 不再发出 `{{VERSION}}`、把"mode=ok 零抓包"这个 P1 的**可见性**先补上(即使 001 还没修,用户至少知道要点重新绑定)。

### 🟡 v5.9.4 —— dpid 单批重编(核心修复,需真机验证)
一次 CI 出全部二进制,但**验证焦点集中在 dpid 一个进程**,回归半径可控。

- **BUG-001**(P0,本批的理由):进程内重绑 + resolveAPIface + 15s 巡检 + rebind_count
- **BUG-003 第1层**:health/stall_seconds + SetHealth(与 001 的失聪判定共用同一套 rx_bytes 门控代码,**必须同批做,分开做会写两遍**)
- **BUG-011 步骤2-5**:TLS/DNS 路径补 Record + Src 来源优先级 + Size() 可观测(**收益完全被 001 卡着,必须同批**)
- **BUG-002**:单文件封顶 + readdir trim + `self_attrib_purge` action(顺带 hnc_httpd)
- **BUG-013**:IPv6Capture 透传(12 行,顺路清掉)
- **BUG-014 步骤2**:dpid SIGHUP 日志 reopen + `hnc_launcher.c:93` 加 `e` + allowedLogs 补 `.1/.2`

**真机验证清单**:重绑触发一次(手动 `ip link set wlan2 down/up`、改名)→ 确认 `capture started on ... attempt=N` 递增且 packets 恢复增长;夜间无客户端时观察 12h **不得**出现误重绑;`run/self_attrib.*.jsonl` 单文件不超 32MB。

### 🟠 v5.9.5 —— hotspotd 单独一版(BUG-004)
**不与 dpid 批混。** 理由:BUG-004 虽是 P1,但失败模式是"0 设备"——比现状的"多几个假设备"严重得多,必须能独立回滚。建议**再拆两阶段**:

- **阶段一(可进 v5.9.4 顺带)**:只做修复方案的 **E 条兜底加严** —— 保留现有黑名单,再硬排 wlan0/eth/bt-pan,再用 `upstream_detect_via_proc_route()` 排掉当前上游,再强制 RFC1918。**不引入白名单,不可能造成 0 设备**,能吃掉报告里 80% 的污染
- **阶段二(v5.9.5 或 6.0)**:才上 ifindex 白名单 + ap_reload + 同网段 + devices.json 清污。这部分依赖 `run/iface.cache` 的可靠性,必须有真机验证窗口

### 🔵 推后 / 推 6.0

| 项 | 理由 |
|---|---|
| BUG-006 a(v6 流量统计) | 80-120 行跨 3 个脚本 + 需真机对账,收益大但独立性强,单独排一版 |
| BUG-006 b(应用限速补 v6) | 前置依赖 ip_app_map 输出 v6 地址,而 ip_app_map 本身(BUG-011)还没恢复数据。**等 v5.9.4 上线确认 map 非空后再排** |
| BUG-006 c / e | P3,随下次 tc 相关改动搭车 |
| BUG-006 d(fw filter protocol) | **零成本真机验证优先**,验证结果决定 a/c 的设计,验证前不动代码 |
| BUG-005 根因 | 归因未定性(仓库自有实验反证 offload),等 ④ 的真机数据回来再决定是查 offload 还是查 `install_ingress_mirred` |
| BUG-003 第3层(watchdog 自动重绑) | **明确推后**。`dpi_rebind.sh` 顶部记录过"两个管理者互相打架导致 dpid 反复死"的事故,001 修完仍复现才上 |
| BUG-002 的 `.backup-*` 内 portal 残留清理 | 会动用户备份目录,只写 CHANGELOG 说明 |

---

## ④ 需要真机补采的数据

无一条判 `needs_device`(全部可静态定性),但以下 6 条的**归因精度**或**修复设计**依赖真机数据。建议一次性采完:

```sh
# ===== 通用环境 =====
uptime; date
cat /data/local/hnc/module.prop | head -4
/data/local/hnc/bin/hnc_dpid -version 2>/dev/null || grep -m1 version /data/local/hnc/run/dpi_state.json

# ===== BUG-001 / 003:确认是失聪还是闲置,以及走没走 ENETDOWN 自愈 =====
ip -o link | awk '{print $1,$2}'
for i in /sys/class/net/wlan*/ifindex /sys/class/net/ap*/ifindex; do echo "$i = $(cat $i)"; done
# 关键:rx_bytes 时序(隔 60s 采两次),有增长而 packets 不增 = 失聪;都不增 = 闲置
IF=wlan2; cat /sys/class/net/$IF/statistics/rx_bytes; sleep 60; cat /sys/class/net/$IF/statistics/rx_bytes
grep -c . /data/local/hnc/run/dpi_state.json
grep -oE '"mode":"[a-z_]+"|"packets":[0-9]+|"uptime_s":[0-9]+' /data/local/hnc/run/dpi_state.json
grep -E 'interface down/rebind retry|capture started on|stats: pkts=' /data/local/hnc/logs/dpid.log | tail -60
ls -l /data/local/hnc/logs/dpid.log*     # 顺带验证 BUG-014:.log 是否远小于 .log.1

# ===== BUG-011:ip_app_map 是否真空 + 应用限速是否静默失效 =====
ls -l /data/local/hnc/run/ip_app_map.json /data/local/hnc/run/ip_app_map.flat
head -c 300 /data/local/hnc/run/ip_app_map.json
grep -c . /data/local/hnc/data/app_limits.flat 2>/dev/null
grep 'no rules to apply' /data/local/hnc/logs/app_limit*.log | tail -5

# ===== BUG-006 d:fw 兜底 filter 到底有没有生效(决定 a/c 的设计,零成本)=====
IF=wlan2
tc filter show dev $IF parent 1:            # 看 fw filter 那条有没有 protocol / pref 是多少
tc -s filter show dev $IF parent 1:         # 看 fw 那条的 Sent 计数是不是恒 0
tc -s class show dev $IF                    # v4+v6 合计字节,与 HNC_STATS 的 v4 值对差即为 v6 分量
tc -s class show dev ifb0
iptables -t mangle -L HNC_STATS -n -v | head -20

# ===== BUG-005:上行限速失效到底是 offload 还是 mirred 没装上 =====
tc filter show dev $IF ingress              # 确认 pref 1 matchall→ifb0 在不在
grep 'install_ingress_mirred' /data/local/hnc/logs/tc_manager.log | tail -20
cat /sys/fs/bpf/tethering/map_offload_tether_stats_map 2>/dev/null   # 限速前
# … 跑一次大流量上传,实测速率 …
cat /sys/fs/bpf/tethering/map_offload_tether_stats_map 2>/dev/null   # 限速后
sh /data/local/hnc/bin/check_offload.sh

# ===== BUG-008:确认是否同时存在真实的 hnc_json 故障 =====
cat /data/local/hnc/run/json_legacy_fallback.count
awk '{for(i=1;i<=NF;i++) if($i ~ /^op=/) print $i}' /data/local/hnc/run/json_legacy_fallback.log | sort | uniq -c | sort -rn
#  ↑ 若出现 cfg / bl_add / name_set / tpl_set 这类【写】操作,那是另一条独立的真 bug

# ===== BUG-002 / 012 / 010:文件事实核对 =====
ls -l /data/local/hnc/run/self_attrib.*.jsonl; du -sh /data/local/hnc/run
ls -l --time-style=full-iso /data/local/hnc/run/tc_state.*
tail -50 /data/local/hnc/logs/tc_state.log
ls -l /data/local/hnc/run/portal_*.json /data/local/hnc/data/portal_config.json 2>/dev/null
stat -c '%a %n' /data/local/hnc /data/local/hnc/run /data/local/hnc/data /data/local/hnc/logs   # BUG-009 现状确认

# ===== BUG-004:确认 devices.json 里是否真有上游污染条目 =====
grep -oE '"iface":"[a-z0-9]+"' /data/local/hnc/data/devices.json | sort | uniq -c
ip route show table all | grep default
```

**另需用户人工确认(非命令)**:GitHub 上 `lcx08091-source/hnc-v5` 与 `hnc-v6` 哪个是当前公开发布仓 —— BUG-015 盲改链接可能把用户导向 404。

---

## ⑤ 交叉验证否决 / 改判的项

| # | 报告主张 | 复核结论 | 对修复的实际影响 |
|---|---|---|---|
| 1 | 现象都可归因"真机跑旧构建" | **前提否决(全局)**。`main.go:33` 版本串与真机上报一字不差,`git log` 显示 dpid main.go 自 v5.7.0-rc11 起未被触碰 | 若采信此前提,BUG-001/003/011/013 会被全部误判为"已修,升级即可"——**这是本次最危险的一个错误,已避免** |
| 2 | BUG-002 加了 7 天保留 → 1.8GB 会清零 | **改判 partial**。`trimDailyFiles`(`history.go:264-273`)按名逐日回推,只删第 8-10 天,前 8 天按设计保留(仍达 1.5-2GB),且 >30 天永不删、无单文件封顶 | 修复重心从"验证 trim 生效"转到"加单文件封顶 + readdir 重写",否则升级后用户会发现盘还是满的 |
| 3 | BUG-005 offload 旁路上行限速且无止损 | **改判 partial + 归因存疑**。`492b83b`(v5.9.1)已落地横幅、文案显式覆盖上行、去掉默认关的开关;而仓库自己在 RMX5010 的对照实验(手工置 limit_map=0 前后 HTB 精度无变化)**否证** offload 归因 | 避免了"再做一遍已有的止损";把排查方向指向 `tc_manager.sh:1110` 的 mirred 安装失败 |
| 4 | BUG-006 IPv6 完全不受限速管辖,推 6.0 | **反证**。`v6_sync.sh`(295 行,v3.4.0)+ `ipt_dual()` 双栈链路完整存在,由 6 类事件驱动 | 从"整条推 6.0"拆成 4 个独立小改动,其中最值钱的 v6 流量统计(a)是纯 shell 可近期交付;顺带挖出报告没提的 `tc_manager.sh:504` fw filter 缺 `protocol` 的疑似死规则 |
| 5 | BUG-007 devices.json 不存在,已改用 hotspotd.sock | **否决**。文件在 `data/devices.json` 且是主状态通道(`hotspotd.c:498/623` 写,httpd 5 处读);sock 是并存的 IPC 通道,`device_detect.sh:70` 无 socat/nc 时还会回落读该文件。真机大概率是热点没开 | 若把报告结论抄进文档会制造新的假文档;**同时挖出真 bug**:`bin/diag/diag.sh` 路径错导致诊断包对 DPI 恒报 MISSING → 本条从 P3 抬到 P2 |
| 6 | BUG-008 json_legacy_fallback 一直涨 = hnc_json 坏了 | **归因反转 + 本地实测复现**。`exit 3`(键不存在)被三个 wrapper 当故障计数;命中不增、未命中必增 | 修法从"查 hnc_json 为什么失败"变成"20 行改 rc 分流";并解锁了 `CODE-ARCHITECTURE-REVIEW-v5.8.9.md:306` 那条按现实现**永远不可能达成**的 legacy writer 退役条件 |
| 7 | BUG-009 目录被 chmod 777 | **归因修正**。仓库无一处 `chmod 777`,是 mkdir 无 mode + 引导脚本无 umask(继承 umask=0)的必然结果 | 直接决定修法:**不能用全局 `umask 077` 一把梭** —— `post-fs-data.sh:82/105-115` 的 chmod 覆盖面不完整(漏 `bin/diag/diag.sh`、`bin/hnc_ndpi_probe`),会造成"文件在但不能执行"的静默回归 |
| 8 | BUG-010 仓库还在读写 portal_* | **否决**。全树唯一命中是未合入的 `.patch` 文件里带 `+` 的 diff 行;`git show --stat 0e6f45b` 证实 portal 代码从未进过工作树 | 从"回滚 portal 代码"降级为"3 行清理脚本";并发现 `cleanup.sh:177-181` 是白名单式 rm(不是 `rm -rf run/*`),所以只有卸载才会带走 |
| 9 | BUG-012 快照 9 天不更新 ⇒ tc 树没变 | **反推不成立**,但挖出两条真绕过路径:`apply_app_limits.sh`(每 30s 全量重建 tc)与 `cleanup.sh`(直接删 root qdisc)完全不刷快照 | 从"加定时刷新"变成"补漏的两条路径 + 消费端加 ts 新鲜度判定";同时确认影响面很小(WebUI 与 httpd 都不读 tc_state) |
| 10 | BUG-004 ifindex 缓存失效 | **部分否决**:当前**根本没有缓存**(每条 NEIGH 现调 `if_indextoname`),该失败模式今天不存在 | ifindex 复用是**改进后才引入**的新风险,必须配 LINK 事件失效 + 同网段二次校验两层,只做一层不够 |
| 11 | BUG-001 报告的 154→163→167 重建链条 | **部分成立但需诚实标注**:同名新 ifindex 这一子场景,内核 packet_notifier 置 `sk_err=ENETDOWN` 后可经 `main.go:574` 自愈 | 判定不受影响(改名/选错网卡/offload 三条路径与该内核细节无关),但归因文案不能写死"重建必不自愈"——真要精确归因需要 ④ 里的 dpid.log 配对行 |

**核实过程中额外挖出、报告未提的问题**(已并入对应条目):
- `bin/diag/diag.sh:117-125` 路径错 → 诊断包对 DPI 恒报 MISSING(BUG-007)
- `bin/inject_version_to_docs.sh` 写好但从未接进 CI + README 两条死链(BUG-015)
- `tc_manager.sh:503-505` fw filter 缺 `protocol` 关键字,疑似整条 MARK→tc 分类路径是死的(BUG-006 d,PLAUSIBLE)
- `apply_app_limits.sh:112-116` 在 ip_app_map 为空时 `exit 0`,应用级限速静默变空操作(BUG-011)
- `hnc_launcher.c:93` 缺 O_CLOEXEC,exec 出的 dpid 永久 pin 住 dpid_launcher.log 的 inode(BUG-014)
- `IPAppMap.Size()`(`ip_app_map.go:166`)存在但全仓库无调用者,"映射表长期为空"只能人肉发现(BUG-011)
