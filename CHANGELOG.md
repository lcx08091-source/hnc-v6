# HNC 更新日志

> 格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) + [Semantic Versioning 2.0.0](https://semver.org/lang/zh-CN/).
>
> 版本号约定:`X.Y.Z` 主.次.补丁。开发期带 `-rcN` 后缀。`-mN` 表示 milestone 内部里程碑。
>
> 每个版本下分类:
> - **Added** — 新功能
> - **Changed** — 现有功能变更
> - **Fixed** — bug 修复
> - **Deprecated** — 即将移除的功能(下个大版本会删)
> - **Removed** — 本版本删除的功能
> - **Internals** — 内部架构、可观测性、文档,不直接面向用户

---

## [Unreleased]

正在开发中,合并到 v5.7.0 时清空。

### Fixed (v5.7.0-rc38, 2026-05-25)
- **审查报告真问题修复 · C+D 组(轻量补丁 + 防未然)**。收尾确认为真的轻量项:
  - **DELAY-1 delay_set/clear 多次 json 写非原子**(`daemon/hnc_httpd/action_v5.go`):此前循环逐字段 `json_set.sh device` 写 4 个字段,中途失败留半状态。改用 `json_set_batch.sh device`(→ `hnc_json set-device-batch`:一次校验/备份/锁/提交,原子);hnc_json 缺失时该脚本自动退回逐字段串行(行为等价)。
  - **ESC-1 hnc_json json/raw 值反斜杠转义**(`bin/hnc_json`):`set-top`/`set-object-key` 对 `json`/`raw` 类型**不转义**反斜杠,但 awk -v 对任何值都吃一层 C 风格转义 → 合法 JSON 如 `{"p":"a\\b"}` 被写成 `{"p":"a\b"}`(静默损坏)。**已实测复现并验证修复**:统一对所有类型 `sed 's/\\/\\\\/g'`,删除错误的 json|raw 特例 + 改正误导注释。
  - **SEC-1 uninstall 备份未收权**(`uninstall.sh`):`tokens.json.last` 含远程访问 token,备份目录默认 755/文件 644 → 有 root 的其他模块可读。改:备份目录 `chmod 700`、`tokens.json.last` `chmod 600`。
  - **M1 dpid_supervisor netlink 防抖失效**(`src/dpid/cmd/dpid_supervisor/main.go`,防未然):`lastRebind` 是 `runChild` 局部变量、每次调用归零,命中 netlink 事件赋值后立即 return → 下次又归零 → `IsZero()` 恒真 → 防抖永不触发(staticcheck SA4006)。修:`lastRebind` 提到 `mainLoop` 栈、按指针传入 `runChild`,跨调用保活。注:该 Go 二进制是"最后兜底"启动器,当前实际很少跑(主用 C launcher / shell guard),此修为将来启用预防。
  - **死代码/加固清扫**:删 `bin/watchdog.sh` 死变量 `PROBE_INTERVAL_ACTIVE`(全脚本 0 引用,稳态实走 `$INTERVAL`)、`bin/apply_device_rule.sh` 未用 `IFS_ORIG`、`daemon/hnc_httpd/action.go` 未用 `rateToKbit`/`rateToMbps`(staticcheck U1000);`post-fs-data.sh` 给 rm 路径加引号 + 开机同时清 `json.lock`(配合 rc36 LOCK-1 统一锁);WebUI 全局整形输入 `min` 由 1 改 0.1(对齐后端 64kbit 下限,避免 sub-floor 输入触发后端报错)。
  - **未改(评估后)**:`capture/bpf.go` 的 `syscall.AttachLsf` 虽 deprecated 但仍可用,换 `x/net/bpf` 是非平凡重构、风险>收益,暂留;`middleware.go` 的 S1008、`server.go` 的 nil-map range 判断纯属风格,改动鉴权/核心路径不值当,保留。
  - 含 `hnc_httpd` + `dpid`(Go)改动,**需 CI 重编**。`sh -n` + `go vet ./...` + `go test ./output/` + `android/arm64` 交叉编译 + ESC-1 实测全过。版本 rc37 → rc38(570138)。**至此审查报告确认为真的问题(A/B/C/D)全部处理完毕。**

### Changed (v5.7.0-rc37, 2026-05-25)
- **审查报告真问题修复 · B 组(打包瘦身)**。纯 CI/打包改动(`.github/workflows/build.yml` + `.gitignore`),无运行时代码变更:
  - **PKG-1 hnc_watchdog 未 strip + 可能过期**:`bin/hnc_watchdog` 此前是**提交进 git 的预编译二进制**,而 CI 从无构建步骤 → 发布的是陈旧(改了 `src/dpid/cmd/hnc_watchdog` 也不会重编)且未 strip(3.1M)的版本;service.sh 优先用它(L405)。修:① 加 CI 步骤从源码构建 `bin/hnc_watchdog`(`-trimpath -ldflags="-s -w"`,与 hnc_dpid 同款,并断言已 strip);② 从 git 取消跟踪 + 加进 `.gitignore`(对齐 hnc_dpid/hnc_httpd 的"CI 产物不入库"约定)。此后每次 CI 重编为最新 + 已 strip(2.6M)。注:CI 用 `GOOS=android` 产物为 dynamically-linked(linker64),与 hnc_dpid 一致、设备已验证可用。
  - **PKG-2 发行 zip 全量打包开发产物**:`zip -rqX . ` 仅排除了 tools/ground_truth → `src/`(8.7M)、`docs/`、`test/`、`third_party_build/`、`third_party_prebuilt/`、`daemon/**` 下 `.go/.c/.h` 源码、`PATCH-NOTES-*.md` / 设计类 `.md` 都进了刷机包。运行时一概不依赖(已核 service/post-fs-data/bin 无引用;Go/C 源码编译产物在 bin/);加排除后刷机包减约 9MB。保留 README/CHANGELOG/SECURITY + 运行时目录。
  - 仅打包/CI 改动,**需 CI 重新走流程**产出瘦身包;YAML 已校验。版本 rc36 → rc37(570137)。

### Fixed (v5.7.0-rc36, 2026-05-25)
- **第三方审查报告(基于 rc32)逐条核查后的真问题修复 · A 组(功能/正确性)**。用户把项目发给多个 AI 审查;我对照 rc35 源码逐条验证,本组修确认为真且影响正确性的项(误报/已修/by-design 见 CHANGELOG 末尾说明,不动代码):
  - **GS-1 全局整形 init_tc 一致性缺口**(`bin/tc_manager.sh`):`init_tc` 用 `DEFAULT_RATE` 建 `1:1`,而全局整形 ceil 此前只在 `restore_rules` 末段恢复。ROM 把根 qdisc 换成 mq/noqueue → `ensure_egress_htb_ready`→`init_tc` 重建 → 1:1 退回全速,UI 仍显示开启,直到下次 restore 才纠回。修:抽 `apply_global_shaper_if_enabled <iface>`,在 `init_tc` 建好 HTB 树后 + `restore_rules` 共用同一逻辑;树重建后立刻把 1:1 ceil 压回 WAN 带宽。`set_global_shaper` 内的 `ensure_egress_htb_ready` 在树已就绪时直接返回,不会递归回 init_tc(已验证)。
  - **LOCK-1 两套 JSON 锁并发写同一 rules.json**(`bin/hnc_json` + `bin/json_set.sh`):`hnc_json` 用 `run/hnc_json.lock`,`json_set.sh` 用 `run/json.lock`;直接调 hnc_json 的写者(`json_set_batch.sh`)与走 json_set.sh 的写者并发时互不见锁,且 json_set.sh 内部 `top`(经 hnc_json)与 `device`(legacy)就用了不同锁。**报告建议的"1 行改 LOCKDIR 对齐"会死锁**(json_set.sh 持 json.lock 再桥接 hnc_json,非重入 mkdir 锁自锁)。修:`hnc_json` 写路径现在也先抢同一把 `json.lock`(外层)+ 保留 `hnc_json.lock`(内层);新增 `HNC_JSON_OUTER_LOCK_HELD=1` env,json_set.sh 桥接前导出,被桥接的 hnc_json 跳过外层锁避免死锁;`reclaim_stale_lock_dir` 加 `ts>0` 守卫,避免误拆 json_set.sh 那把"只写 pid 不写 ts"的活锁。并发实测:交错 15×`json_set.sh top` + 15×`json_set_batch device` 12s 全完成、**零丢写、终态合法、无死锁、无残留锁**。
  - **TC-1 init_tc 失败仍返回 0**(`bin/tc_manager.sh`):root htb add 3 次重试彻底失败后只装 ingress mirred 却 `return 0`,误导调用方。修:ingress mirred 装好后 `return 1` 如实上报(`ensure_egress_htb_ready` 的后置树检查本就能纠正,这里让 CLI/调用方拿到准确状态)。
  - **GS-2 global_shaper_set 写入不检 rc**(`daemon/hnc_httpd/action_global_shaper.go`):on 路径前两次 `json_set.sh top`(down/up)与 off 路径写 enabled 都忽略了 rc → 半状态。修:三次写全检 rc;down/up 任一失败显式落 `enabled=false` 防半状态后返回 error;off 写 enabled 检 rc。
  - 含 `hnc_httpd`(Go)改动,**需 CI 重编**。`sh -n`(tc_manager/hnc_json/json_set)+ `go vet` + `android/arm64` 交叉编译 + 并发冒烟全过。版本 rc35 → rc36(570136)。
  - **审查报告中的误报/已修/by-design(不改)**:M1 dpid_supervisor 防抖确为 bug 但该 Go 二进制是"最后兜底"启动器、CI 不构建/git 不跟踪 → 实际不发布不运行(暂不动,留待 C/D 组顺手);"dpid/httpd 未 strip"误报(CI 已 `-s -w`,只 `bin/hnc_watchdog` 真未 strip,B 组处理);"json_set_batch 没人用"误报(`apply_device_rule.sh` 在用);"global_shaper_off 残留 down/up"为 by-design(WebUI 预填上次值,`enabled=false` 已阻止 restore);"shell 注入 / auth_required=false 放行 / loopback 任意 app 可写 / WebUI 假数据"均已 fail-closed 或前序版本已修。

### Added (v5.7.0-rc35, 2026-05-25)
- **VPN 飞轮排除:可视化(卡片徽标)+ 可管理(WebUI)+ 单元测试**(用户选定的三项打包)。承 rc33/34 的引擎,补齐 UX 与测试:
  - **① 应用卡片标注**(`src/dpid/output/state.go`·`self_attrib.go`·`candidate.go` + `webroot/index.html`):`SelfApp` 新增 `flywheel_excluded`,在 Snapshot 里按三种来源置位——内置清单 / 用户清单(`flywheelExcludePkgs`)/ 导管自动识别(新增 `conduitUIDs`,由 expander 每 tick `SetConduitUIDs` 发布)。「应用」页对被排除的应用显示「🛡️ VPN/代理 · 不学习规则」徽标;未排除且已知包名的卡片上有「排除 · 不学习此应用规则」按钮,一键加入。
  - **② WebUI 管理**(`daemon/hnc_httpd/action_flywheel.go` 新增 + `api_v5.go` + `webroot/index.html`):设置页新增「飞轮排除名单 · VPN/代理」卡片,展示/添加/删除你**自定义**的排除包名。新 action `flywheel_exclude_set`(op=add|remove,pkg 校验为合法包名)load-modify-store `etc/flywheel_exclude.json`(原子写,镜像 `action_candidate.go`);`/api/config` 新增 `flywheel_exclude_user` 供前端回读。内置清单 + 导管识别始终生效、不在此管理(文案已注明)。
  - **③ Go 单元测试**(`src/dpid/output/flywheel_exclude_test.go` 新增,该包此前零测试):覆盖 `loadFlywheelExcludePkgs`(内置常驻 / 用户合并去空格 / 坏 JSON 降级到内置)、`IsFlywheelExcludedUID`+`IsFlywheelExcludedPkg`(VPN/普通/未知 uid、空包名)、构造器播种、`classifyTier`(high/med/low/shared/blocklist/SharedLearned 六种路径)。`flywheelExcludeFile` 由 const 改 var 以便测试覆盖路径。
  - 含 `dpid` + `hnc_httpd`(Go)改动,**需 CI 重编两者**。`go vet ./...` + `go test ./output/`(6 测试全过)+ `android/arm64` 交叉编译 + `node --check`(两段内联 JS)全通过。版本 rc34 → rc35(570135)。

### Changed (v5.7.0-rc34, 2026-05-25)
- **扩充 VPN/代理飞轮排除清单**(`src/dpid/output/flywheel_exclude.go`,承 rc33,应用户要求"多收录开源 VPN")。从各项目 GitHub 仓库的 `build.gradle(.kts)` 里**核实 `applicationId`** 后扩充内置清单:
  - **本会话已核实**:`io.github.trojan_gfw.igniter`(Igniter/trojan-gfw)、`net.mullvad.mullvadvpn`(Mullvad,开源)、`eu.faircode.netguard`(NetGuard,开源)、`com.celzero.bravedns`(Rethink DNS+Firewall,开源)、`io.nekohasekai.sfa`(sing-box SFA)、`com.v2ray.ang`(v2rayNG)、`com.github.shadowsocks`、`app.hiddify.com`(Hiddify)。
  - **高把握新增**(权威文档/Play id):`org.outline.android.client`(Outline/Jigsaw)、`moe.matsuri.lite`(Matsuri)、`com.cloudflare.onedotonedotonedotone`(Cloudflare 1.1.1.1/WARP)、`com.windscribe.vpn`(Windscribe)、`com.surfshark.vpnclient.android`(Surfshark)、`com.adguard.android`(AdGuard)。
  - **截图佐证**:用户截图里的 Clash Meta for Android = `com.github.metacubex.clash.meta`,rc33 已在清单内。
  - 清单现覆盖 Clash 三件套 / v2rayNG / sing-box·SagerNet 家族(SFA·SagerNet·NekoBox·Matsuri)/ shadowsocks / trojan / WireGuard / OpenVPN(Connect + ics-openvpn)/ Tor·Orbot / 本地 VPN 防火墙(NetGuard·RethinkDNS·AdGuard)及主流商业 VPN(Proton·Nord·Express·Mullvad·Windscribe·Surfshark·WARP·Tailscale·Outline)。
  - 清单外的 VPN 仍由 rc33 的「导管型 uid 自动识别」(≥8 个陌生主域)兜底;用户也可编辑 `/data/local/hnc/etc/flywheel_exclude.json` 自行增删(5min 内热加载)。包名写错只是不匹配、无副作用。
  - 纯清单数据改动(`dpid` Go),**需 CI 重编 dpid**。`go vet ./...` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./...` 通过。版本 rc33 → rc34(570134)。

### Fixed (v5.7.0-rc33, 2026-05-25)
- **修飞轮把 VPN/代理应用的流量错记成它的规则**(`src/dpid/output/`,用户开 FlClash 时发现 `capcom.co.jp` 等被晋级成「FlClash」的规则)。
  - **根因**:dpid 靠内核 uid 地面真值(`/proc/net` socket 属主)把 SNI 归因到 app。但 VPN/代理(Clash/v2rayNG/sing-box…)开着时,它**重新发起**别的 app 的所有流量 → 这些被代理流量的 socket 属主 uid 就是 VPN 的 → 飞轮把它们的域名错挂到 VPN(走法2 晋级出 `autopromo_capcom_co_jp → FlClash`)。
  - **修法两层**(`flywheel_exclude.go` 新增 + `candidate.go`/`auto_expand.go`/`self_attrib.go` 改):
    - **① 显式排除清单**:内置常见 VPN/代理包名(FlClash `com.follow.clash`、Clash、v2rayNG、sing-box、shadowsocks、WireGuard、Tailscale、Orbot 等)+ 用户可编辑 `/data/local/hnc/etc/flywheel_exclude.json`(`{"exclude_pkgs":[...]}`,随 pkg 缓存 TTL 5min 热加载)。这些 uid 在**观察期**(走法1+走法2)就被跳过,从不进飞轮,镜像既有 `IsSystemUID` 的系统应用过滤。
    - **② 导管型 uid 自动识别**:一个 uid 在累积器里关联 ≥8 个**互不相关的陌生主域**(`conduitApexThreshold`)= 典型 VPN/代理/浏览器特征 → 禁止其**自动**晋级(手动一键 promote 仍可,用户说了算)。兜住清单没覆盖的长尾。
    - **③ 自动降级历史错误规则**:每 tick 扫已晋级规则,凡归因 uid/包名命中排除清单(按 `Evidence.UIDPkg` 稳健匹配,uid 回收也不怕)或被判为导管 → 删除该规则并标 `SharedLearned` 不再复活。用户现有的 `capcom→FlClash` 会在刷 rc33 后**自动清掉**。
  - **边界**:VPN 仍正常显示在「我的应用」列表(它确实有那些连接)——只是不再据其(代理的)流量造 app 规则。需要加别的 VPN 自己编辑 `flywheel_exclude.json` 即可。
  - 含 `dpid`(Go)改动,**需 CI 重编 dpid**。`go vet ./...` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./...` 通过。版本 rc32 → rc33(570133)。

### Added (v5.7.0-rc32, 2026-05-25)
- **全局带宽整形器(opt-in,默认关)—— 整个热点设 WAN 带宽上限 + AQM 抗 bufferbloat**(`bin/tc_manager.sh` / `daemon/hnc_httpd/action_global_shaper.go` / `api_v5.go` / `webroot/index.html`)。用户从 roadmap 选「手动填带宽·默认关」方案落地:
  - **原理**:给整个热点的 HTB 父类 `1:1` 的 `ceil` 设成 WAN 带宽(egress on AP iface = 客户端下载;`ifb0` = 客户端上传),并把默认类 `1:9999` 叶子升级成最优 AQM(`cake besteffort → fq_codel → sfq`)。HTB 借用模型下所有子类(每设备 class + 默认类)都借不出 `1:1` 的 ceil → 总吞吐受 WAN 瓶颈管;此时队列排在我们能管的叶子上,AQM 才压得住 bufferbloat(AQM 只在「我们就是瓶颈」时才有效)。
  - **后端**:新增 action `global_shaper_set`(`action_global_shaper.go`,params `enabled`/`rate_down`/`rate_up`,复用 `validateRate`,`tc_htb=false` 直接拒)→ `tc_manager.sh global_shaper <iface> <on|off> <down> <up>`(新增 `set_global_shaper` + `global_shaper_default_leaf`,走 `tc_action_lock` 串行 + 短重试)。状态持久化到 rules.json 顶层 `global_shaper_enabled/down/up`(`json_set.sh top`),`restore_rules` 重启后据此恢复,**关闭时复位 `1:1` 回 `DEFAULT_RATE`**。`/api/config` 暴露三字段供前端回读。
  - **前端(本机设置页)**:新增「全局带宽整形 · 进阶 · 默认关」卡片——开关 + WAN 上/下行带宽(Mbps,和宽带套餐一致)+「应用整形」按钮;`tc_htb=false` 时禁用(`isDownlinkLimitSupported` 门控);开关关闭即时下发 disable。WAN Mbps ↔ tc 速率字符串由 `wanMbpsToRate`/`rateToWanMbps` 在边界转换。
  - **诚实边界**:这是**固定**整形——填多少按多少限。蜂窝速率乱跳、固定值大部分时间偏差大(本内核大概率无 CAKE autorate 自适应),蜂窝收益有限;**稳定链路(光猫/WISP/WiFi 中继)才是主战场**。默认关 → 不开则完全不影响每设备限速/低延迟,**不用的人零风险**。UI/CHANGELOG 均如实标注。
  - 含 Go 改动,**需 CI 重编 hnc_httpd**。`sh -n`(tc_manager.sh)+ `node --check`(两段内联 JS)+ `go vet` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build` 均通过。版本 rc31 → rc32(570132)。

### Added (v5.7.0-rc31, 2026-05-25)
- **远程 WebUI 功能对齐本机 —— 设备卡片在用 app 展示 + 每设备低延迟开关**(`daemon/hnc_httpd/web/app.js`)。本机 KSU WebUI(`webroot/index.html`)在 rc20/rc22 加的两个能力此前远程 SPA 没有,这版补齐:
  - **① 设备卡片直接显示「在用」的 app**:`renderCard` 读 `/api/devices` 已带的 `dpi_apps`(dpid 按 MAC 上报的 `{name,category,confidence,count}`),在卡片正文渲染最多 4 个蓝色 app 标签,`confidence=low` 标「?」,hover 看分类/命中次数。和本机折叠卡一致——不藏二级页。
  - **② 每设备「低延迟(智能队列)」开关**:动作栏加「🚀 低延迟」按钮,开启后变「低延迟·关」+ 卡片亮蓝色「低延迟」角标;走后端已有的 `rule_sqm`(`actionDeviceSQMSet` → 叶子换 CAKE/fq_codel/sfq)。门控对齐本机:新增 `remoteCapBool()` 三态读 `/api/capabilities`,`tc_htb=false` 时禁用按钮(后端也会拒,前端先拦避免无谓往返);与延迟注入互斥(`delayOn` 时禁用,两者抢叶子)。
  - 走 `callAction('rule_sqm', {mac, enabled})` + 统一 `handleActionResult` toast/刷新链路,与远程已有的限速/延迟写操作一致(CSRF header、actionInFlight 去重、超时后强刷)。
  - web 资源经 `go:embed`(`embed.go`)打进 hnc_httpd 二进制,**本版需 CI 重编**。`node --check`(app.js)+ `go vet` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build` 均通过。版本 rc30 → rc31(570131)。

### Added (v5.7.0-rc30, 2026-05-25)
- **候选角标 —— 陌生主域待确认时,底部「应用」导航项亮红点**(`webroot/index.html`)。承 rc29:rc29 修好了「未匹配 SNI」卡如实讲走法2 的主域候选,但用户得**主动进应用页**才看得到。rc30 补全可发现性:
  - 新增 `updateAppsNavDot(self)` + `startCandidateBadgePoll()`:`init()` 里和 `startPolling()` 一起启动,**每 25s 跨页面轮询** `/api/dpi_state`,当 `self.candidate_high > 0`(走法2 累积到「证据充分、达 HIGH 可晋级」的全新主域名)时,在底部导航「应用」项右上角亮一颗红点(`.nav-dot`,带微光),提醒去「自动识别候选」区一键确认/拒绝。
  - 进应用页时 `appsLoad` 也会同步刷新角标(`updateAppsNavDot(self)`);候选清空后红点自动熄灭。
  - 为什么用 `candidate_high` 而非 `candidate_pending`:`pending` 含一两次命中的弱候选(window=1/hits=1,噪音多),`high` 才是达到晋级证据门槛的——只在「真的该看一眼」时打扰用户,避免角标常亮失去意义。
  - 纯前端,`node --check`(两段内联 JS)通过,不用重编。版本 rc29 → rc30(570130)。

### Fixed (v5.7.0-rc29, 2026-05-25)
- **修"未匹配的 SNI"卡误导 —— 它只讲陌生子域、无视陌生主域候选**(`webroot/index.html` `appsRenderUnmatched`,用户提出"飞轮有没有把陌生主域名加进去")。后端是**两条独立轨**:
  - 走法1 `unmatched_snis_pending` = 没匹配规则的**子域**(完整 SNI)→ auto-expand 队列。
  - 走法2 `candidate_pending` = **全新主域名(apex)** 累积器 → "自动识别候选"区(`appsRenderCandidates`,可一键 promote / 拒绝)。真机已证明在工作:`candidate_accum.json` 抓到 `claude.com`/`idouyinvod.com`/`proxyinfo.net`,`_auto_promoted.json` 已晋级 claude.com→Claude、抖音。
  - **bug**:`appsRenderUnmatched` 只看走法1,当子域队列为 0 时直接显示"✓ 规则集已覆盖所有抓到的 SNI · 没有陌生子域",**完全不提走法2 的主域候选** → 即使有 3 个全新主域在排队,也喊"全覆盖" → 用户误以为主域名没被识别。
  - **修复**:子域队列空、但 `candidate_pending > 0` 时,卡片改显示"子域已覆盖;另有 N 个陌生主域名在候选区(其中 M 个已达 HIGH 可晋级)· 见下方'自动识别候选'",指向走法2 审批区;真·两轨全空时文案补上"也没有陌生主域候选(走法2)"。
  - 说明(非本版改):走法2 自动晋级需 ≥3 窗口 + ≥6 命中(`candPromoteMinWindows/Hits`);真机候选多为 Windows=1/hits=1(app 只用过一两次),所以"已晋级 2"目前是手动 promote 的,自动晋级要该 app 多用几次累积到阈值才会触发——这是保守设计,不是 bug。纯前端,`node --check` 通过,不用重编。版本 rc28 → rc29(570129)。

### Changed (v5.7.0-rc28, 2026-05-25)
- **「开机自动开热点」补齐兼容性 + 自动降级**(`bin/hotspot_autostart.sh`,应用户提问)。
  - **启动逐级降级**:`1a` `start-softap -b any`(现代/ColorOS 主力,`-b any` 避开 band error 18)→ `1b` **不带 `-b` 的旧式 start-softap**(老 Android / 不认 `-b` 的 ROM 自动降级)→ `1c` 等 5s 重试一轮(WifiService 刚就绪首次可能失败)→ `2` `cmd tethering tether wifi` → `3` `svc wifi hotspot enable`。逐个尝试直到成功或全部失败(失败 `exit 1` + 记日志)。
  - **方法感知的 NAT**:记 `START_METHOD`。本地热点(`softap_local`,系统不做共享)才 `setup_nat` 自建 `ip_forward`+`MASQUERADE`+`FORWARD`;走系统原生共享(`2`/`3`,**自带 NAT**)则**跳过自建**,避免和系统 tetherctrl 的 NAT 冲突。
  - **出口自适应**(承 rc26):`detect_up_iface` 用 `ip route get` —— VPN(`tun0`)/ 蜂窝(`rmnet`)/ WiFi 上联自动切;VPN 关了下次起会自动改挂到 rmnet。NAT 接口轮询等就绪(承 rc27)。
  - 全程 best-effort:每步失败不致命、日志可查;彻底起不来时 UI 已如实提示改从系统设置开。`sh -n` 通过;纯 shell,不用重编。版本 rc27 → rc28(570128)。

### Fixed (v5.7.0-rc27, 2026-05-25)
- **开机自动开热点(含流量共享)真机端到端验证通过** + 加可靠性补丁(`bin/hotspot_autostart.sh`)。用户用 rc26 的等效命令实测:`start-softap -b any` 起本地热点(`wlan2` + `10.126.123.0/24`)→ `ip route get` 探出口(此机经 VPN `tun0`)→ `ip_forward`+`MASQUERADE`+`FORWARD` → **另一台设备连上能正常上网**。A 方案(本地热点 + 模块自建 NAT)在 ColorOS 上完整跑通。
  - **补丁**:`setup_nat` 起热点后由"固定 `sleep 2`"改为**轮询等热点接口拿到 IP(最多 ~8s)**。真机 `wlan2` 约 5s 才有 IP,开机时系统更忙,旧的 2s 可能在接口就绪前就放弃 → 漏挂 NAT → 客户端没网。轮询确保与已验证的手动流程一致。
  - 至此 ColorOS"开机自启热点"链路打通:rc24(异步不卡死)+ rc25(`start-softap -b any` / 删 `svc wifi enable` / 自建 NAT / UI 诚实标注)+ rc26(`ip route get` 出口探测)+ rc27(轮询接口就绪)。
  - `sh -n` 通过;纯 shell,不用重编。验证:刷后关手动热点 → 点「立即启动」或重启 → 另一台连上即可上网。版本 rc26 → rc27(570127)。

### Fixed (v5.7.0-rc26, 2026-05-25)
- **修 rc25 自建 NAT 的「上联口探测」bug**(`bin/hotspot_autostart.sh`)。真机干净测试(手动热点关闭)确认:`cmd wifi start-softap ... -b any` 后 **`wlan2` 起来并带 `10.126.123.0/24` 子网** → 本地热点会给客户端发 IP,A 方案地基成立。但 rc25 的 `detect_up_iface` 用 `ip route show default` 取上联接口 —— **Android 用策略路由(per-network 路由表),main 表常常没有 default route**,所以探到空 → `setup_nat` 走"找不到 up"分支直接跳过 → 客户端永远没网。
  - **修复**:`detect_up_iface` 改用 `ip route get 1.1.1.1` 解析实际互联网出口接口(`rmnet_data2` / VPN `tun0` 都能正确取到;纯 `${var#*dev }` 参数展开,不依赖 awk/sed)。这样 `setup_nat` 才能正确挂上 MASQUERADE。
  - 其余同 rc25:start-softap `-b any`、删 `svc wifi enable`、`stop` 撤 NAT、UI 诚实标注 ColorOS 限制。
  - ⚠ 仍需真机端到端验证:刷后**关掉手动热点** → 点「立即启动」(或 `hotspot_autostart.sh start-now`)→ 另一台设备连上 → 看能否上网。VPN(tun0)在跑时,转发流量能否过 VPN 取决于该 VPN 的实现,属另一回事。
  - `sh -n` 通过、参数解析已单测;纯 shell,不用重编。版本 rc25 → rc26(570126)。

### Fixed (v5.7.0-rc25, 2026-05-25)
- **开机自动开热点(ColorOS)真机诊断后修复**(`bin/hotspot_autostart.sh` + `webroot/index.html`)。真机 `cmd wifi` 探测结论:
  - `cmd tethering tether wifi` → **No shell command implementation**;`svc wifi hotspot` → 不存在 —— ColorOS **这两个兜底是死的**。
  - `cmd wifi start-softap` 能用,但**不带 `-b` 会撞频段** → `Soft AP start failed with tether error: 18`;`-b 5` / `-b any` **成功**。且它起的是**本地热点**(Android 明说 shell 命令不激活 internet tethering),系统不给它做 NAT/共享。
  - 之前脚本里的 `svc wifi enable` 是多余的(softap 不需要开 STA WiFi,实测 WiFi 关着也能起),反而会**无谓打开用户的 WiFi**。
  - **改动**:① start-softap 加 `-b any`(固件自选可用频段);② 删 `svc wifi enable`,只等 WifiService 可响应;③ **A 方向(自建共享)**:起热点成功后 `setup_nat` —— 检测上联(默认路由口)+ 本地热点口,`echo 1 > .../ip_forward` + `iptables -t nat MASQUERADE -o 上联` + `FORWARD` 放行(全 best-effort、幂等),让客户端用手机流量上网;`stop` 时 `teardown_nat` 撤掉;④ **B 方向(诚实标注)**:热点面板描述 + 技术说明如实写明 ColorOS 限制 + "没网就改从系统设置手动开"。
  - ⚠ **本地热点能否给客户端发 IP / NAT 后能否上网,仍需真机验证**(要先关掉手动热点再测,避免频段冲突)。若本地热点这条路在该机型不通,只能走系统设置——UI 已如实说明。
  - 纯 shell + 前端,`sh -n` / `node --check` 通过,不用重编。版本 rc24 → rc25(570125)。

### Fixed (v5.7.0-rc24, 2026-05-25)
- **热点「立即启动」后端超时 + WebUI 卡死**(真机)。根因两条叠加:(a) `bin/hotspot_autostart.sh` 的 `start` 子命令**无条件 sleep 开机延迟 `hotspot_delay`(默认 60s)**,手动「立即启动」也照睡;(b) `daemon/hnc_httpd/action_v5.go:actionHotspotStart` 用 `runBin` **同步**跑该脚本,而 `handleAction` 期间持**全局写锁 `stateMu.Lock()`** → 所有 `/api/devices`/`/api/live` 轮询被阻塞 → 前端 ~9s(curl `--max-time 6` + `withTimeout 9000`)必超时报「后端无响应」、UI 冻住。
  - **修复**:`hotspot_autostart.sh` 新增 `start-now`(= `start` 但跳过延迟,SELinux/wifi/重试逻辑复用);`actionHotspotStart` 改为 `runBinDetached(... "start-now")` **异步立即返回**(不持锁久等);`webroot/index.html` 「立即启动」处理改为触发后**轮询 `/api/live` 的 `hotspot_active`**(每 2s,最多 ~24s):起来了报「热点已启动」并刷新,超时报「未就绪,请看 hotspot.log」。不再卡死、不再误报超时。开机后台路径(`service.sh`)仍用 `start`(保留延迟)。
  - 注:能否真正点亮 AP 取决于 ColorOS 是否放行 `cmd wifi start-softap`/`cmd tethering`/`svc wifi hotspot enable`——失败需看 `/data/local/hnc/logs/hotspot.log` 定位,属环境问题。
- **每设备「低延迟」开关报 `SQM_APPLY_MODE=no_aqm`**(真机,rc22 的 TC_ACTION_BUSY 已修)。根因:`bin/tc_manager.sh:device_sqm_leaf` 只试 `cake` → `fq_codel`,你这台内核两者都装不上就 `return 1`。**修复**:cake/fq_codel 之后**加 `sfq perturb 10` 兜底**(每流公平、缓解 bufferbloat;`init_tc` 默认叶子早就 `fq_codel || sfq`,sfq 几乎必有),只有连 sfq 都没有才算真无 AQM;前端 `低延迟` 文案在无 CAKE/fq_codel 时提示「用 sfq 兜底(效果略弱)」。这样低延迟在更多内核上可用。
- 「低延迟 + 高速」其他优化(回应用户):核心是「HTB 限速做瓶颈 + AQM 叶子压队列延迟」,本版补全了叶子的 sfq 兜底;rc18 的 netem `limit` 按速率缩放已避免限速压低吞吐。全局带宽整形(整个热点抗 bufferbloat)属架构级,留待真机验证 A/B 后再议。
- 验证:`sh -n`(hotspot_autostart/tc_manager)、`go vet`+`CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build`、`node --check` 均通过。⚠ 有一处 Go 改动,需 CI 重编 `hnc_httpd`。版本 rc23 → rc24(570124)。

### Fixed (v5.7.0-rc23, 2026-05-25)
- **设置页"运行状态"面板整块是硬编码假值 → 改为真实数据**(`webroot/index.html`,设备卡+应用页"断连数据"扫描的结果)。原来 4 行全是写死字面量、无任何 JS/接口喂数据:hotspotd "PID 18432 · RES 4.2 MB"、tc 规则数 "11"、iptables "7 chains"、watchdog "运行中"——永远是这串假的。**修复**:进设置页(`refreshLocalDiagnostics`)时新增 `fetchRunStatus()`,本机 KSU WebUI 走 kexec 实采:hotspotd `pidof`+`/proc/$pid/status` 的 VmRSS、`tc qdisc/class` 对象数、`iptables/ip6tables -t mangle` 里 `0x800000` 规则数、`hnc_watchdog` 存活;采不到显示 `—`,远程(无 kexec)显示"远程不可读"——不再展示假数字。
- **"热点接口"行写死 wlan2 → 接真实接口**:改读 `state.hotspotIface`(来自 `/api/live`/`/api/iface_info`),非 wlan2 的设备不再显示错的接口。**删掉无真实来源的假"上联接口 rmnet0"行**(IFB 上联接口在运行期才探测,前端无可靠来源,留着只会误导)。
- **核实"开机自动开热点"是真的可用**(应用户要求):整条链路真实——UI 开关(`#hs-autostart` 4920)→ `hotspot_save` 写 `rules.json` 的 `hotspot_auto` → 开机 `service.sh:464` 读到 true 就跑 `hotspot_autostart.sh start` → 该脚本用 `cmd wifi start-softap`(A13+)/`cmd tethering tether wifi`/`svc wifi hotspot enable` 真启 AP 并补 SELinux;开关回读也已接 `cfg.hotspot_autostart`(11907)。**不是假功能**;能否真正点亮 AP 取决于 ColorOS 是否放行这些命令,需真机验证(开开关→重启→看 `logs/hotspot.log`)。
- 纯前端改动,`node --check` 通过,不用重编二进制。版本 rc22 → rc23(570123)。

### Fixed (v5.7.0-rc22, 2026-05-25)
- **每设备「低延迟」开关点了报 `TC_ACTION_BUSY=1`(rc20 功能的真机 bug)**(`bin/tc_manager.sh`)。根因:点开关的瞬间,tc 全局锁(`tc_action_lock`)被 watchdog 的 restore/health 等后台 tc 动作短暂占着,而 `set_sqm` 的 CLI 包装是 `tc_action_lock || exit 12`——抢不到锁就**立刻失败**。`set_limit`/`set_delay` 共用同一把锁但用户是在空窗期点的所以成功,`set_sqm` 不巧每次都撞上 → 一直"用不了"。**修复**:`set_sqm` 获取锁改为**短重试循环**(最多 12×0.25s ≈ 3s;`tc_action_lock` 本身还会回收 >25s 的陈旧锁),骑过 watchdog 的短暂占用再执行。
- **设备卡片"在用 app"一直空、看着像假的**(`webroot/index.html`)。`renderCard` 早就在**折叠卡片头部**(IP/MAC 下方)渲染 `dpiLine`("在用 [app 徽章]",rc5 加的),但前端设备模型(`fetchDevices` 的 `DEVICES.push`)**从没把 `/api/devices` 返回的 `dpi_apps` 字段映射进去** → `d.dpi_apps` 恒为空 → `dpiLine` 永远是空串 → 永不显示。不是假数据,是**数据没接上**(后端 `server.go dpiAppsByMAC` 一直在提供)。**修复**:模型补 `dpi_apps` 映射。这样 dpid 识别到该客户端流量后,**折叠状态的设备卡上直接显示"在用 XXX"**(无需展开进二级页)——正是你要的。识别为空仍属正常(dpid 还没抓到该客户端的流量)。
- 纯 shell + 前端改动,`sh -n` / `node --check` 通过,**不用重编二进制**。版本 rc21 → rc22(570122)。

### Removed (v5.7.0-rc21, 2026-05-24)
- **删除旧的全局 SQM(设置页那张复杂又基本用不上的卡)** —— rc20 的每设备「低延迟」开关已经取代它。彻底移除,避免留"假/死"代码:
  - **前端**(`webroot/index.html`):移除 SQM 设置卡 HTML(Smart Queue 行 + `.sqm-control-panel` 三排按钮)、`.sqm-*` CSS、全部 SQM JS(`normalizeSqm*`/`sqm*Label`/`sqmPresetDetail`/`applySqmStatus`/`updateSqmPanel`/`fetchSQM`/`setSqmBackend`/`fillCardWithSqmPreset`、`data-sqm-*` 与 `sqm-gray-diag` 点击处理、init 的 `fetchSQM()`/诊断页的 `await fetchSQM()`、`state.sqm*` 字段)、以及设备卡延迟区那个依赖 SQM 预设的"填入预设"按钮 + 处理。删后 grep 确认 index.html **零残留旧 SQM 引用**,`node --check` 双 script 块均通过。
  - **后端**:删 `daemon/hnc_httpd/api_sqm_v53.go`、`action_sqm_v53.go`;移除 `/api/sqm` 路由(`server.go`)、middleware loopback 白名单条目、`sqm_set` action 注册(`action.go`);删 `bin/sqm_manager.sh`、`bin/sqm_gray_diag.sh`。`go build`(android/arm64)通过 → 编译器确认无悬空引用。
  - **测试/CI**:删 5 个 `test/unit/test_sqm_v53*.sh`(测的是已删功能);从 `test_ci_preflight_artifact_gate.sh`/`test_artifact_release_rc5.sh` 的必需文件清单移除 `bin/sqm_manager.sh`;从 `bin/artifact_sanity_check.sh` 移除 `sqm_manager.sh` 必需项 + `/api/sqm` 符号校验。CI 关键路径(`ci_preflight.sh`/`build.sh`/`version_consistency_check.sh`)无 SQM 依赖,已确认不破。
  - 保留:每设备「低延迟」(`rule_sqm`/`set_sqm`/`device_sqm_leaf`/`sqm_enabled`)完整不动。已知遗留:`bin/rc_selfcheck_v53.sh`、`bin/hnc_cleanup_test_rules_v53.sh` 这两个 v5.3 手动诊断脚本里还提到 `/api/sqm`(非 CI、非运行时,404 时优雅降级),暂留。⚠ Go 改动需 CI 重编 `hnc_httpd`。版本 rc20 → rc21(570121)。

### Added (v5.7.0-rc20, 2026-05-24)
- **每设备「低延迟」开关 —— 做进设备卡片(取代设置页那个复杂的全局 SQM)**。展开任一设备卡 → 新的「低延迟」一键开关 → 把该设备 HTB class 的叶子 qdisc 换成 **CAKE/fq_codel(AQM)**,这台设备自己跑满时也跟手;关闭则换回按速率缩放的 netem 占位。
  - **为什么做成每设备**:全局 SQM 在设置页"太复杂、基本用不上";而"低延迟"恰恰是**单设备 + 已限速**时最有效(限速给这台造了瓶颈,队列就排在我们能管的叶子上,AQM 才压得住延迟)。UI hint 写明"配合限速效果最佳"。
  - **互斥**:与延迟/弱网注入互斥(同一个叶子:一个压低延迟、一个注入延迟)。卡片上注入了延迟时,低延迟开关禁用并提示;后端 `device_sqm_leaf` 也会在叶子已有真实 netem(delay/loss)时不抢。
  - **持久化 + restore**:`rules.json` per-device 加 `sqm_enabled`;开机/切热点 `restore_rules` 解析并 `set_sqm on` 恢复(连"只开低延迟、没限速"的设备也会建好 class + AQM 叶子),不会切热点后丢失。
  - **链路**(改动文件):前端卡片开关 `data-action="toggle-sqm"` → `applySqmBackend` → `apiAction('rule_sqm')`;Go `action_dev_sqm.go: actionDeviceSQMSet`(镜像 delay 路径:解析 iface/mark_id/ip,`tc_htb` 不支持则拒绝)→ `apply_device_rule.sh alloc_mid`(复用)+ `tc_manager.sh set_sqm`(新增 `set_sqm`/`device_sqm_leaf` + CLI dispatch)+ `json_set.sh device … sqm_enabled`;`action.go` 注册 `rule_sqm`;`server.go` 把 `sqm_enabled` 加进 `/api/devices` 字段白名单;`index.html` 设备模型加 `sqm`、卡片加低延迟 section + 点击处理。
  - cake 不支持自动退 fq_codel,都没有则提示无 AQM;`tc_htb` 不支持时开关在 UI 灰掉。⚠ **Go 改动,需 CI 重编 `hnc_httpd`**;`go vet` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build` + `node --check` + `sh -n` 均通过。(设置页旧全局 SQM 卡暂留,后续看是否简化/移除。)版本 rc19 → rc20(570120)。

### Fixed (v5.7.0-rc19, 2026-05-24)
- **修复"SQM 一点就报错"——设置页 SQM 任意按钮点了都弹「SQM 切换失败」**(`bin/sqm_manager.sh`)。根因:`actionSQMSet` → `sqm_manager.sh apply` → `apply_default_leaf` 是**增量**应用(只在已存在的 HTB 树上替换默认类 `1:9999` 的叶子 qdisc),它要求 `qdisc htb 1:` 和 `class htb 1:9999` 已经存在;**否则 `return 3`/`return 4` 硬失败**。但 HTB 队列树只在 `set_limit`(第一次给某设备设限速)时经 `ensure_egress_htb_ready→init_tc` **惰性创建**,开机 / 开热点都不主动建。**结果:只要你没给任何设备设过限速,点 SQM 的任意模式/档位都命中 rc=3「HTB root 1: not found」→ 前端每次 toast「SQM 切换失败: sqm apply failed」**——SQM 实际上从来没法独立用。
  - **修复**:`apply_default_leaf` 在热点网卡存在、但 HTB 根缺失时,先 `sh tc_manager.sh init "$iface"` 把树建起来(幂等,建 root + 默认类 1:9999 + fq_codel 叶子),再做增量叶子替换;若 bootstrap 仍失败(如内核真不支持 HTB),改为**优雅保存 `return 0`**(stderr/log 给 WARN)而不是硬报错——前端不再误报失败。默认类缺失同样改为优雅保存。
  - 这样 SQM 在"开了热点但没设任何限速"的常见场景下**能真正生效**(给默认类挂上 fq_codel/CAKE AQM 叶子),而不是一点就红。纯 shell,`sh -n` 通过,不用重编。
  - ⚠ 注:之前讨论的"把低延迟做成每设备卡片开关 / 全局带宽整形(`1:1` ceil)"是更大的方向,本版**先按下不表**,只修这个一点就报错的 bug。版本 rc18 → rc19(570119)。

### Changed (v5.7.0-rc18, 2026-05-24)
- **限速/延迟引擎:兼容性 + 优化(多代理审查后落地最值的两项,纯 `tc_manager.sh` shell 改动,不用重编)**。
  - **① 上行限速 police 兜底(兼容性,影响最大)**(`bin/tc_manager.sh`)。`capability_probe.sh` 早就会算出 `uplink_mode=police`——当 IFB/mirred 不可用(常见于 vendor wifi 驱动、缺 `act_mirred`/`ifb` 的 GKI)但 tc `police` 可用时,本可用 ingress police 限上行;**但 `tc_manager.sh` 从来没消费这个字段**,导致这些机器上行限速**静默失效**(就是界面"上行不支持"那批设备)。现在 `set_limit` 在 `uplink_supported_runtime` 为假时,先尝试 **逐客户端 ingress police(按源 IP,在热点网卡 `ffff:` 上,无需 IFB)**:`cap_uplink_mode_value`/`ensure_ingress_qdisc`/`set_uplink_police`/`clear_uplink_police`。成功 → `return 0`(完整生效,UI 如实显示上行已限);失败或无 police → `return 8`(只下行,与旧行为完全一致)。`set_limit` 清除路径与 `remove_device` 都加了 `clear_uplink_police` 清理。目前 IPv4(v6 上行 police 留作后续);best-effort,任何失败都不劣于"本来就没有上行"。
  - **② netem 队列 `limit` 按速率缩放(正确性/吞吐)**(`bin/tc_manager.sh`)。旧的固定 `limit 100` 在 >~50Mbit 时只有 ~1ms 缓冲,**尾丢把实际吞吐压到限速值以下、还多丢包**。新增 `netem_limit_pkts`(`packets ≈ rate_bps×(delay+jitter+50ms)/8/1500`,clamp `[100,20000]`)+ `rate_to_bps`:低速率仍是小队列(下限 100,**不增延迟**),高速率/带延迟按 BDP 放大。三处接入:`netem_leaf_replace_zero`(占位叶子用慷慨值,使不限速的默认类不再成瓶颈)、`set_netem_only`(延迟路径按"查到的类速率+延迟"算)、`set_limit` 设速率后回调新的 `tune_leaf_netem_limit` 把占位 netem 队列对齐到刚生效的实际速率(只动零延迟占位叶子,不碰真延迟/丢包 netem 与 fq_codel/cake SQM 叶子)。
  - **未改、确认是好的**:netem↔HTB 解耦、能力探测用真 dummy 网卡实测、C rtnetlink 工具绕 ColorOS 坏 tc、oplus-netd 占根 qdisc 时诚实退出。**eBPF 维持现状**(读 netd map 的字节统计本就稳、可移植;明确不引入 tc-bpf/XDP,那会按内核编译 BPF 对象、反而降兼容)。审查另记的 CAKE 补参数 / u32→flower 属架构级,留作可选大改。`sh -n` 通过,awk 数学已单测。版本 rc17 → rc18(570118)。

### Fixed (v5.7.0-rc17, 2026-05-24)
- **收尾根因 A 的最后一处 `/system/bin` 依赖:`hnc_watchdog`(Go 主守护)的硬编码 `/system/bin/sh`**。承 rc16 把 supervision 栈扫了一遍:
  - `dpid_supervisor`(Go 兜底 launcher)**本就完全免疫**——`realBin` 是绝对 `/data` 路径、netlink 走直接 syscall(不 shell out `ip`)、计时用 Go timer、只 `exec` 绝对路径的 dpid 二进制。无需改。
  - `dpid` 核心抓包**无任何 shell-out**;它的 `pm`/`dumpsys`/`cmd`/`app_process` 都是 Android 框架工具、**没有 toybox/busybox 替代**(PATH 兜底救不了),且都是 best-effort + 错误处理、优雅降级,不影响抓包。无需也无法改。
  - `hnc_watchdog`:**核心保活循环(让 launcher/dpid 不死)是纯 Go、免疫**(这也是真机上系统没崩的原因);但它的业务动作(`runAction` → `watchdog.sh action`,每周期)和定时任务(`v6_sync.sh`/`stats_sample.sh`/ndpi 启停/脚本运行)用的是**硬编码 `/system/bin/sh` 共 6 处**。`/system/bin` 被卸的那几秒,这些杂活会失败、跳过该周期,过会儿自恢复——非致命,但确属残留 `/system/bin` 依赖。
  - **修复**(`src/dpid/cmd/hnc_watchdog/main.go`):新增 `shellPath()` 帮手——有 `/system/bin/sh` 就用,没有就退到 `binDir + "/sh"`(rc13 预置的 mksh 副本;脚本是 mksh 方言,兜底必须 mksh、不能 busybox ash);**逐调用求值(不缓存)**,因为 `/system/bin` 会运行期来回变。六处 `exec.Command("/system/bin/sh", …)` 全改走 `shellPath()`。
  - ⚠ **Go 改动,需 CI 重编 `hnc_watchdog` 二进制**。`go vet` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build` 均通过。至此根因 A 在模块层可处理的部分全部做满:rc12(C launcher 自愈)+ rc13/rc15(`/data` 兜底工具)+ rc16(shell guard 去硬编码)+ rc17(Go watchdog 加 sh 兜底)。版本 rc16 → rc17(570117)。

### Fixed (v5.7.0-rc16, 2026-05-24)
- **补上 fallback shell guard 残留的硬编码 `/system/bin/*` 绝对路径(rc13 标注"留作后续"的那处)—— 真机数据定位后确认是最后一块短板**。诊断过程(真机 `mount` / `mountinfo` / `ps etime` / 模块清单):
  - 设备已在 **Magic Mount**(`magic_mount_rs` 元模块,`umount = false`)——不在 OverlayFS;且是 **system-as-root**(`/system/bin` 属根挂载、**不是可被单独 `umount` 的挂载点**),所以"切 Magic Mount / 调 SuSFS try_umount"对这台都不对症(改 SuSFS 纯属冒险削弱隐藏)。
  - "为什么现在才有":内核升到 **6.6 android15 GKI**,新内核**砍了内置自动挂载**,改由用户态元模块挂载;叠加 HNC rc6/rc7 把抓包改成 24h 常驻,于是早期命名空间未就绪的瞬时窗口天天被撞上。
  - 真机日志确认 ENOENT 全部来自 `hnc_dpid_guard.sh` 的**硬编码绝对路径**(`/system/bin/sleep`、`/system/bin/date`),它们**绕过 PATH**,所以 rc13 的 PATH 兜底救不到;且 guard 旧设计是 `ensure_path_or_die`"die-fast 等 watchdog 重启"。当前 boot 是 **C launcher 胜出**(launcher/dpid 稳定在线 3.5h、零 churn),guard 只是 boot 初瞬间跑了一下就被 C launcher 接管杀掉——所以系统当前是好的;但在 **C launcher 落选**(ColorOS fork/TLS 探测失败 → shell guard 成为主监管)的那些 boot 上,这些硬编码路径就会让 guard 反复 ENOENT、wedge,重现"必须重新绑定"。
  - **修复**(`bin/hnc_dpid_guard.sh`):把 `ensure_path_or_die` / `wait_for_clean_env` / `sleep_s` / 主循环心跳 / 锁接管里所有 `/system/bin/sleep`、`/system/bin/date` 绝对路径**改成裸命令**——PATH 已含 `/data/local/hnc/bin`(rc13 预置、`/data` 永不被卸),`/system/bin` 一旦消失自动 fallthrough 到 `/data` 副本,guard **不再 die、继续监管 dpid**;只有连 `/data` 兜底也没有(真·坏)才退出让 watchdog 重开。这把 rc13 标注"留作后续"的 fallback-only 硬编码路径清干净了。
  - 纯 shell 改动,`sh -n` 通过,不用重编任何二进制。⚠ 底层 SukiSU/元模块在运行期动挂载仍是 ROM/隐藏栈行为,模块只能"撞上也不崩";rc13/rc15 的预置 + 本版 guard 加固共同构成这层韧性。版本 rc15 → rc16(570116)。

### Changed (v5.7.0-rc15, 2026-05-24)
- **加固"无挂载模块"对根因 A(SukiSU 运行期卸 `/system/bin`)的韧性 —— 取外部 AI 建议的安全子集**。背景:把根因 A 的问题陈述发给外部 AI 咨询"能否从其他途径绕过",结论是"HNC 这种纯守护模块不该和 OverlayFS 全局 `/system` overlay 同命运"。我对其方案做了安全甄别后落地可安全的部分:
  - **⚠ 否决了它的头号建议(用 `busybox sh -o standalone` 跑常驻脚本)**:实测本仓库常驻脚本(watchdog.sh / hnc_dpid_guard.sh / service.sh 等)**大量使用 `[[ ]]` 和 `(( ))`**,这是 mksh/ksh 方言,**busybox `ash` 不支持**,换解释器会直接把脚本跑崩。解释器**继续用 mksh**(rc13 已把 mksh 复制到 `/data`)。
  - **`provision_fallback_tools` 升级**(`service.sh`):multicall 源**优先用常驻 `/data` 上的 KSU/Magisk busybox**(`/data/adb/ksu/bin/busybox` 等)——它永不被卸、且 applet 比 toybox 全(很多 ROM 的 toybox 不带 `awk`,而我们常驻循环 `awk` 用得很多);system 的 busybox/toybox 作兜底。applet 链接表从 11 个扩到含 `awk rm mkdir mv touch dirname basename stat readlink sort uniq find ln chmod chown id seq pidof ps xargs`,并**按二进制实际支持的 applet 列表(busybox `--list` / toybox 无参)安全建链**——探测不到就只建 toybox/busybox 都必有的核心集,绝不建出"调用即 unknown applet"的死链。
  - **修 `device_detect.sh` 的 PATH 缺口**:它是常驻 daemon 循环(`while true`),但 PATH 此前**漏了 `/data/local/hnc/bin`**(watchdog/iptables/guard 在 rc11/rc13 都补了,就它没补)→ `/system/bin` 被卸时它的裸命令(`awk`/`grep`/`sleep`)仍会 ENOENT。现已补上。
  - **新增空 `skip_mount` 文件**:本模块本就没有 `system/` 文件夹、不替换任何 `/system` 文件,`skip_mount` 显式声明"不参与 systemless 挂载"(KernelSU/Magisk 仅判存在;脚本/sepolicy/webroot 不受影响)。它不能阻止管理器对别的 overlay 做 umount,但让 HNC 明确不进入挂载规划。
  - **根治仍在用户侧**(模块无法自行决定挂载后端):优先把挂载模式从 OverlayFS 切到 **Magic Mount / Hybrid Mount 的 Magic 后端**(HNC 不往 `/system/bin` 放东西 → Magic Mount 下该路径无模块挂载可拆,大概率消除整体消失);或改成只对敏感 app 精准 umount,而非全局关 umount(避免削弱挂载层 root 隐藏)。namespace 隔离(`unshare`+private+bind pin)作为 OverlayFS 用户的实验性增强,暂不默认上。版本 rc14 → rc15(570115)。

### Fixed (v5.7.0-rc14, 2026-05-24)
- **WebUI 假代码审计 — 清掉"看着像真、其实是假数据或空操作"的前端代码**(分支 `webui-fake-code-audit`;全量通读 `webroot/index.html` 13032 行 + 远程 `daemon/hnc_httpd/web/app.js` + 27 个 Go handler)。结论:从 v9 demo 继承的 mock 数据绝大多数已被替换成真实后端源,残留 6 处:
  1. **(HIGH)展开单台设备选模板时静默空操作**(`webroot/index.html` `tpl-pick` 单设备分支)——批量模式走 `batchApply→applyLimitBackend`(真调后端),但**单台展开后选模板只改内存 `DEVICES` 数组 + 弹"已应用模板"成功 toast,从不发 `/api/action rule_set`**,tc/iptables 规则根本没下,下次轮询乐观值被真实数据覆盖、限速静默消失。改为真正 `applyLimitBackend`(两向都 0 走 `clearLimitBackend`)→ `requestForceRefresh` → 成功/失败如实 toast。
  2. **(MED)下拉刷新是假刷新**(`triggerRefresh`)——注释直写"模拟刷新 800ms",`setTimeout(900ms)` 后弹"已刷新设备列表"并只 `renderDeviceList()` 重渲内存数组,**从不向后端拉新数据**。改为 `requestForceRefresh()`(真走 `/api/live`+`/api/devices`)后再 toast。
  3. **(MED)"数据新鲜度"指示器结构性说谎**——后端 `/api/live` 硬编码 `snapshot_age_ms:0`、`snapshot_stale:false`,本地 UI 据此让 `#freshness-line` 永远显示"已更新 · 刚刚",永不过期(本构建后端每次请求都实时读文件、根本没有快照缓存,这个"快照年龄"概念在本分支不存在)。改为基于**客户端最近一次成功轮询的真实时间戳**(`state.lastPollOkAt`)计算新鲜度 + 1s ticker,轮询停滞会真的翻成"数据可能已过期 · 正在重试";后端从 `/api/live` 删掉这两个伪字段(远程 SPA 的消费者本就是死代码,无 DOM)。
  4. **(MED)`/api/metrics` 恒返回全 0 假计数**——`snapshot_age_ms/json_cache_hits/misses/shell_fallback_count/offload_check_count` 全是硬编码 0,设置页诊断面板把它们当真实指标渲染成"snapshot=0 · cache 0/0 · fallback=0"。改为后端诚实返回 `instrumented:false`(本构建实时读文件、无这些计数器),前端显示"实时读取 · 无快照缓存"。
  5. **(MED)候选区硬编码"当前 463 个规则"**(`appsRenderUnmatched` 的 `pending===0` 分支)——把一个写死的数字当作实时规则集大小展示(后端并无该字段可用)。删掉伪造数字,只保留"规则集已覆盖所有抓到的 SNI"的状态说明。
  6. **(MED)`fetchHnIp` 伪造 `192.168.1.1`**——拿不到本机 IP 时回退一个看似可用的假网关地址,远程访问卡片会显示 `https://192.168.1.1:8443` 让用户复制一个根本连不上的地址(函数注释本身写着"不再猜测")。改为返回空 + 卡片显示"无法获取本机 IP · 请确认热点已开启"。
  - 已核非问题(均为诚实实现,不改):设备/DPI/统计/告警/导出全部读真实 `/api/*`;所有控制按钮真调后端且失败如实报错;空状态("暂无数据"/"未启用"/禁用按钮)是诚实降级;模板/SQM 预设是用户配置默认值非假数据;`OUI_DB` 现为空 `{}` 是诚实"未知"回退;`crypto/rand` 仅用于 token/TLS 非伪造指标。纯前端 + Go handler 改动,无需重编 launcher。版本 rc13 → rc14(570114)。

### Added (v5.7.0-rc13, 2026-05-24)
- **/system/bin 卸载韧性(方案一,缓解根因 A)** — SukiSU/ColorOS 运行期会间歇性把 `/system/bin` 从模块脚本的挂载命名空间卸掉,导致常驻 shell(watchdog.sh / iptables_manager.sh)的裸命令 `sleep`/`sh`/... ENOENT 崩(日志:`full_init rc=-1`、`iptables_manager.sh: /system/bin/sleep: No such file`)。
  - `service.sh` 启动时(此刻 `/system` 仍正常)`provision_fallback_tools`:把 `/system/bin/toybox`(或 busybox)复制到 `/data/local/hnc/bin/.hnc_mc`,建 `sleep/head/tail/cat/printf/date/grep/sed/cut/tr/wc` applet 符号链接 + 复制 `mksh` 为 `sh`。`/data` 永不被卸。
  - `watchdog.sh` / `iptables_manager.sh` 的 PATH 追加 `/data/local/hnc/bin`(置于 `/system/bin` 之后,纯 fallback)。`/system/bin` 一旦消失,裸命令自动 fallthrough 到 `/data` 副本,不再崩。
  - **不向仓库提交任何二进制**(从设备现有 toybox 复制;容器无 NDK 无法产出 busybox)。设备若连 toybox 都没有才会退化——极罕见。
  - guard 的硬编码 `/system/bin/*`(fallback-only,rc12 已让 C launcher 为主)留作后续谨慎处理。根治仍建议用户在 SukiSU 管理器关"卸载模块挂载 / 调 Mount Namespace 模式"。版本 rc12 → rc13(570113)。

### Fixed (v5.7.0-rc12, 2026-05-24)
- **C launcher 自愈,堵上"launcher 活着但 dpid 永久没了"的盲区**(`src/launcher/hnc_launcher.c`,补 rc11)。外部审查(GPT)指出残留 P0:rc11 让 launcher 不再因单次外部 SIGTERM(rc=0)放弃,但**crash-loop / 启动见到旧 `dpid_crashflag` 时仍会永久放弃**(`run_supervise_loop` 崩溃超限 → `write_crash_flag()+return 1`;`main` 见 crashflag → `pause()` 死等)→ launcher 进程活着、`hnc_dpid` 子进程永远不被拉起、没人自动恢复,用户必须手动"重新绑定"。
  - 改为**自愈**:① crash-loop 触发 → 写崩溃标志(仅诊断)+ 冷却 `CRASH_COOLDOWN_SEC`(120s)+ 清标志 + 重置计数 + 继续监管,不再 `return 1` 永久退出;② 启动见到旧 crashflag → 冷却 120s + 清标志 + 正常监管,不再 `pause()` 死等用户删文件。被动只读守护进程应当自愈:制造崩溃风暴的瞬时原因(残留 shell guard、/system/bin 暂时蒸发)消退后,dpid 自动恢复。
  - launcher 内部版本 `0.1.0-rc30.12.30 → .31`(保持 CI sanity grep 的 `0.1.0-rc30.12` 前缀)。**需 CI 重编 hnc_launcher 二进制**。版本 rc11 → rc12(570112)。
  - ⚠ 根因 A(SukiSU 运行期把 /system/bin 从模块命名空间卸载)仍未根治,建议用户在 SukiSU 管理器调 Umount Modules / Mount Namespace 模式。

### Fixed (v5.7.0-rc11, 2026-05-24)
- **"开机必须点重新绑定 / 抓不到包"**(realme RMX5010 / Android16 / SukiSU,真机日志确诊)。根因有二:
  1. **ColorOS/SukiSU 运行期间间歇性把 `/system/bin/*` 从模块脚本的挂载命名空间移除**(日志反复 `/system/bin/{sleep,head,printf,sh}: No such file or directory`)→ shell guard 的 `get_iface` 用 `cat|head` 取到空 → 误判 iface 变更 → 杀 dpid churn;`sleep` ENOENT → guard `[FATAL]` 退出。
  2. **双监管互杀 dpid**:权威 launcher 是 C launcher(`hnc_launcher`,由 `hnc_watchdog` 保活),但 `dpi_rebind.sh`(重新绑定按钮)却另起一个**竞争的 shell guard** → 两个监管抢 dpid;一个 SIGTERM 掉 dpid,dpid 干净退出 rc=0,**C launcher 把 rc=0 当"人工停止"就放弃监管** → dpid 没人再拉 → 必须再点重新绑定 → 越点越坏。dpid 本身健康(连续跑 8 分钟 `tls=40 dns=1196`)。
  - **修复**:
    - `bin/dpi_rebind.sh`:不再启动 shell guard;改为清崩溃标志(`dpid_crashflag`/`dpid.crashflag`)、杀残留 shell guard/supervisor、只重启 dpid 子进程,让 C launcher 用新 iface 配置重拉(C launcher 缺失才回退 shell guard)。
    - `src/launcher/hnc_launcher.c`:dpid 在 launcher 未关闭(`g_shutdown` 假)时 rc=0 退出 → 当意外退出**重启**而非放弃(断开"必须重新绑定"致命链)。**需 CI 重编 hnc_launcher**。
    - `service.sh`:用 C launcher 时 `pkill` 残留 shell guard / Go supervisor,避免双监管。
    - `bin/hnc_dpid_guard.sh`:`get_iface` 取空(工具 ENOENT)不再触发 rebind(空=探测失败,保留当前 iface)。
  - ⚠ 根因是 SukiSU 卸载 /system/bin(root 管理器行为),模块只能"少受伤";建议在 SukiSU 管理器找挂载命名空间设置(umount modules / namespace 模式)。版本 rc10 → rc11(570111)。

### Fixed (v5.7.0-rc10, 2026-05-24)
- **导出下载在本机点了没反应** — 打包是成功的,坏在下载:`下载 zip` 是 `<a href="/api/exports/..">`,在本机 KSU WebUI(`file://`)下会被解析成 `file:///api/exports/..`(指向文件系统而非 http 守护进程),且带不了 loopback 鉴权头 → 点了无效(远程 `:8443` 浏览器正常)。新增 `appsDownloadExport(name,url)`:本机走 `ksu.exec` `cp` 到 `/sdcard/Download/` 并 toast;远程仍用原生 `<a download>`。两处下载入口(打包结果 + 最近导出列表)都改走它。
- **应用解析改用 `/data/system/packages.list`**(`self_attrib.go`)— uid→pkg 主源从 `pm list packages -U` 改为读 root 权威表 `/data/system/packages.list`(含全部已装包、更全更快、不会像 pm 那样偶发漏掉真 app;失败回退 pm)。修复部分真 app 显示「未识别 (pm 未解析)」(如 uid 10347/10111)。注:uid 0(root)/系统服务/隔离进程(99910111)本就无 app,仍显示未识别属正常。HNC 是 root 守护进程,无需也无法申请 QUERY_ALL_PACKAGES。版本 rc9 → rc10(570110)。

### Changed (v5.7.0-rc9, 2026-05-24)
- **过滤系统 app** — 本机的 OEM 系统 app(ColorOS 的 com.oplus/coloros/heytap 等,uid≥10000)此前会被飞轮归类(污染规则库,系统域名是 OEM 遥测、对识别别人设备无用)并塞满「我的应用」列表。
  - **判定**:`pm list packages -s` → 系统包集合(`self_attrib.go:loadSystemPkgs`,随 pkgCache 同 5min TTL 刷新;`IsSystemUID(uid)`)。按 uid 段切不掉这些(它们 uid≥10000),必须用包标志。
  - **飞轮挡**(`candidate.go`):`processCandidates` 折叠时跳过系统 uid → 系统 app 的 apex 不进候选累积器、不被晋级。某 apex 若同时被真实 app 用到,仍在该(非系统)uid 下正常累积。
  - **列表折叠**(`webroot/index.html` `appsRenderList`):`SelfApp.is_system` 为真的 app 折叠进可点开的「系统应用 N 个 ▾」灰显分组(默认收起),真实 app 不再被淹没。
  - `state.go` SelfApp 加 `is_system` 字段。版本 rc8 → rc9(versionCode 570109)。

### Changed (v5.7.0-rc8, 2026-05-24)
- **「未匹配的 SNI」块上移**(`webroot/index.html`,issue #1)——从 应用→我的应用 的整列 app **之后**移到 app 列表**之前**(接口行下方),不用划过几十个 app 才看到。纯 DOM 顺序调整,`appsRenderUnmatched` 按 id 渲染不受影响。

### Fixed (v5.7.0-rc8, 2026-05-24)
- **切热点后飞轮进度清零**(`src/dpid/output/candidate.go` + `auto_expand.go`,issue #2 核心)——切热点会让 supervisor 重启 dpid 2-3 次,而候选累积器是纯内存、每次重启重置;候选要 ≥3 个窗口才晋级,所以**在会切热点的设备上飞轮永远晋级不了**(比"显示清空"更严重的功能性 bug)。
  - 新增 `saveCandidateAccum`/`loadCandidateAccum`:`processCandidates` 每 tick 把 `acc.byApex` 原子写到 `run/candidate_accum.json`;`RunAutoExpander` 启动读回(缺失/损坏=空;>24h 陈旧项丢弃)。窗口数 / uid 集 / `SharedLearned` 跨重启累加 → 飞轮真正能推进到晋级。
  - 显示层的"切热点后 SNI/app 秒级空白"已由 rc7(dpid 保持运行)兜底,几秒自动重建;故本轮不做 dpi_state 回种(Option B)与进程内 rebind(Option C),留待真机验证后按需再加。版本 rc7 → rc8(versionCode 570108)。

### Fixed (v5.7.0-rc7, 2026-05-24)
- **dpid 只在热点开着时才运行(rc6"未上报 self 块"的真正根因)** — 读码 + 用户实测定位:
  - dpid 由三个 launcher 之一拉起,优先级 **C launcher(`hnc_launcher`)→ shell guard(`hnc_dpid_guard.sh`)→ Go supervisor(`hnc_dpid_supervisor`)**。
  - C launcher **不**门控热点(无条件跑 dpid),但它在 ColorOS 上常因 fork/TLS 探测失败被跳过 → 回退到 shell guard 或 Go supervisor;**这两个都只在热点 iface `ready` 时才启动 dpid**(否则只写一次性 waiting 状态、`continue`,从不拉起守护进程)。
  - 后果:热点没开时 dpid 根本没跑 → `dpi_state.json` 没有 self 块(界面显示「dpid 暂未上报 self 块」而非「采样器停止」)→ 自抓取/飞轮永远拿不到数据。而自抓取用的是本机自己的网卡(rmnet/wlan0)+ `/proc/net`,**本不该依赖热点**。
  - **修复**:`hnc_dpid_guard.sh` 与 `cmd/dpid_supervisor/main.go` 改为**无条件常驻拉起 dpid**——热点没就绪时 dpid 走 blind 模式(AP 抓取暂停,但 `main.go:303+` 的自抓取 + 飞轮 goroutine 照常跑),热点一就绪(netlink 事件或 3s 轮询)就自动 kill+rebind 升级成全量 AP 抓取。沿用各自原有的 grace/debounce/netlink 逻辑。C launcher 无需改(本就无条件)。
  - 配合 rc6 的 self-capture 常驻,本机 app 识别现在完全不依赖热点。版本 rc6 → rc7(versionCode 570107)。
  - ⚠️ 这是 dpid 生命周期核心改动,本容器无法跑安卓验证,需真机确认:热点关时应用 tab 应「运行中」、热点开时 AP 客户端识别仍正常、热点开关切换无重启抖动。

### Changed (v5.7.0-rc6, 2026-05-24)
- **self-capture 改为常驻(默认开)** — 自动识别飞轮(per-uid `/proc/net` 采样 + 自接口 AF_PACKET SNI 抓取)全靠 `run/self_capture.enabled` flag 驱动;此前默认关,用户不手动开「追踪本机应用流量」就永远没数据(界面一直「追踪状态:未就绪 / dpid 暂未上报 self 块」)。
  - `service.sh`(dpid 段)现在每次启动 `[ -f ] || : > "$RUN/self_capture.enabled"`,即默认常驻开;会话内仍可在 WebUI 临时关(删 flag),重启后恢复常驻。dpid 每 5s 读 flag,~5s 内生效。
  - UI:「追踪本机应用流量」卡加「✓ 常驻(默认开)」标注。
- **诊断说明**:读码确认 dpid 只要在跑就**无条件每 5s** 发布 self 块(`main.go:316-329`,关时 `enabled:false`)。所以若界面显示「dpid 暂未上报 self 块」(self=null,而非「采样器停止」),说明 **dpid 没在正常产出**(崩溃/crash-loop/capture 初始化失败),常驻 flag 救不了——需查 `logs/dpid.log` + `ps | grep hnc_dpid` 定位后端启动问题。

### Added (v5.7.0-rc5, 2026-05-24)
- **客户端识别展示 / 阶段5(上半)** — 设备 tab 现在每个连入热点的设备显示「在用什么 app」。
  - 数据本就存在:dpid 把每个客户端的 SNI 经 `classifyHost`(飞轮规则 + 实体库)分类成 app,写进 `dpi_state.json` 的 `clients[].top_apps`(按 client-key,含 `client_mac`)。
  - 新增 join:`hnc_httpd` `buildDevicesPayload` 调 `dpiAppsByMAC()` 读 `dpi_state.json`,按 MAC 把 `top_apps`(name/category/confidence/count,取前 5)挂到 `/api/devices` 每个设备的新字段 `dpi_apps`(server.go)。
  - 前端:`renderCard`(webroot/index.html)在 IP/MAC 行下渲染「在用 <app> · <app>」徽章,低置信度标 `?`,hover 显示分类 + 命中次数。
  - **纯展示、无新采集**;飞轮训练出的规则与实体库的效果直接体现在客户端识别上。本机 WebUI 已接;远程 SPA(app.js)的设备卡渲染留作后续。

### Changed (v5.7.0-rc4, 2026-05-24)
- **自建实体库扩到 166 条**(`data/entity_db.json`,+45)——重点补**国内 + OEM 共享基础设施**(西方公开库最弱的部分):
  - OEM:OPPO/HeyTap(heytapcs/heytapimage/heytapdownload/heytapmobi)、华为(hicloud/dbankcdn/dbankcloud)——对 ColorOS 设备尤其相关。
  - 国内大 app CDN/云:爱奇艺(qiyipic/iqiyipic/ppsimg/71.am/qy.net)、优酷(ykimg)、网易(126.net/127.net/ydstatic)、知乎(zhimg)、小红书(xhscdn)、拼多多(pddpic)、美团(meituan.net)、大众点评(dpfile)、饿了么(elemecdn)、虎牙(msstatic)、斗鱼(douyucdn.cn)、酷狗(kgimg)、汽车之家(autoimg)、58(58cdn.com.cn)、搜狐(itc.cn)、新浪(sinajs/sinastorage)、字节(toutiaocdn/toutiaoimg)。
  - 统计/广告/SDK:秒针 miaozhen、AdMaster、热云 reyun、Mintegral/rayjump、字节穿山甲 pangle、Unity、AppLovin、Vungle、Cloudflare insights;微软连通性检测(msftconnecttest/msftncsi)。
  - **均为自有整理的事实,未抄取任何第三方数据集**(Tracker Radar 等 CC-BY-NC-SA/GPL 不可再分发);继续排除会单独归属某 app 的 vendor apex(qq.com/oppo.com/iqiyi.com/zhihu.com 等不收)。
  - 纯数据增量:`dpid` 与 `service.sh` 无需改动,`entity_db.json` 的 `version` 升到 `2026-05-24.2`,service.sh 自动热替换 + 备份。版本 rc3 → rc4(versionCode 570104)。

### Added (v5.7.0-rc3, 2026-05-24)
- **自建实体库 / 阶段4** (`data/entity_db.json` + `src/dpid/output/entity.go`) — 121 条 HNC 自有整理的 `apex→{type,entity}`,覆盖全球+国内主流**共享基础设施**(CDN / 云存储 / 统计 / 广告 / 推送 SDK:Akamai/Cloudfront/Fastly、阿里云/腾讯云 myqcloud/百度云/字节 volces、友盟/TalkingData/神策、个推/极光 …)。
  - **license 干净**:全部自有整理,**不含任何第三方数据集**。明确放弃 DuckDuckGo Tracker Radar —— 它是 CC-BY-NC-SA(非商用 + 传染性 ShareAlike),打进公开模块会把整个模块拖成 NC-SA,法律上不可行。
  - **用途**:候选飞轮(走法2)的冷启动先验。`classifyTier` 在 uid 基数累积出来之前,凭实体库即可把 CDN/统计类 apex 首次出现就判为"共享",**不会被误归**到第一个命中它的 uid。
  - dpid 每 tick 读 `etc/entity_db.json`(缺失/损坏=空,绝不致命);`dpi_state` 加 `entity_db_size` 诊断;应用→设置 候选区显示"实体库 N 条已加载"。

### Internals (v5.7.0-rc3, 2026-05-24)
- `service.sh` 软装 `entity_db.json` 到 `etc/`,并按 `version` 字段升级(带 `.bak` 备份,保留用户编辑),与 `dpi_rules.json` 同范式。版本 rc2 → rc3(versionCode 570103)。

### Added (v5.7.0-rc2, 2026-05-23)
- **WebUI 候选审批 / 走法2 收尾** — 把"未匹配 SNI 候选审批"卡从"规划中"做成可用界面。应用→设置:
  - **自动晋级开关** (`/api/self/auto_promote/toggle` → `run/auto_promote.enabled`):开=HIGH 自动晋级写规则;关=影子模式(只统计,但仍可手动 promote)。
  - **候选队列** (`appsRenderCandidates` 读 `self.candidate_samples[]`):分「已晋级(可撤销)/ 待审(HIGH·MED)/ 共享(自动排除)」三组。
  - **一键 promote**(`candidate_promote` 动作)→ 写 `etc/candidate_decisions.json`;dpid 每 tick 读取,对该 apex **强制晋级**(按内核 uid 归到对应 app,`source=manual_promoted`,confidence=medium),**影子模式下也生效**。
  - **拒绝/撤销**(`candidate_reject` 动作)→ 追加进 `etc/auto_expand_blocklist.json`;dpid 已每 tick 热加载 → 该 apex 判为共享,永不归个人,且**自纠撤销**任何既有晋级。

### Changed (v5.7.0-rc2, 2026-05-23)
- dpid 候选累积器:MED 档也进 `candidate_samples`(供人工审队列),样例上限 12 → 40;`buildPromotedRule` 带 `source`(auto/manual)+ 对应 confidence/命名。

### Internals (v5.7.0-rc2, 2026-05-23)
- hnc_httpd 新增 `action_candidate.go`(promote/reject,走队列化 `/api/action`,域名正则校验 + 原子 tmp+rename,仿 `action_device_rename.go`)+ `apiAutoPromoteToggle`;`/api/self` 响应加 `auto_promote_enabled`。版本 rc1 → rc2(versionCode 570102)。

### Added (v5.7.0-rc1, 2026-05-23)
- **自动识别飞轮 / 走法2** (`src/dpid/output/candidate.go` 新增) — 给"全新 apex"(不匹配任何规则的域名)自动建规则。以内核 uid 为 ground truth,按 **uid 独占性 + 持续性** 给候选 apex 分档:
  - **HIGH** (单 uid + ≥3 窗口 & ≥6 次 + 非共享) → 自动归到该 uid 的应用 (用 live PackageManager label 命名)
  - **SHARED** (静态黑名单 / ≥3 个 uid / 学习到的共享) → 永不归个人 (治 CDN/统计域名误标)
  - **MED/LOW** → 证据不足或 2 uid 模糊,不动
  - **影子模式默认开**:累积+分档一直跑并写进 `dpi_state` (`candidate_pending/high/shared/promoted`),但**仅当 `auto_promote.enabled` 存在时才真写规则** (`_auto_promoted.json`)
  - **自纠**:已晋级 apex 之后又被第 2 个 uid 命中 → 自动撤销 + 标记学习共享,不再晋级
  - 只标注不动作、限量、原子写;应用 tab 状态行显示候选统计
- **真实系统应用名** (`tools/applabel/AppLabel.java` + `src/dpid/appmeta/pmlabels.go`) — 用 `app_process` 跑极小 dex 调 `PackageManager.getApplicationLabel()`,拿系统本地化名 (覆盖用户自装 / OEM 系统 / 分包 APK,不止 curated 的 ~200 条)。解析顺序:用户覆盖 → live PM label → curated → prettyFallback。失败 (无 app_process / SELinux 拦) 自动回退,绝不 panic。CI 新增 d8 编 dex 步骤。`dpi_state` 加 `app_label_source`/`live_label_count` 诊断。

### Changed (v5.7.0-rc1, 2026-05-23)
- **底栏导航 6 → 4**:设备 / 应用 / 分析 / 设置。"统计 + DPI" 合并成"分析"页顶部段控;"日志"并入"设置"子页。
- 应用 tab 优先用后端 `display_name` (放弃前端 21 条小字典),徽标取真实名首字 (中文优先)。

### Fixed (v5.7.0-rc1, 2026-05-23)
- **应用 tab 本机看不到数据**:`appsLoad`/toggle/export 等 7 处用裸 `fetch('/api/...')`,在 KSU `file://` 下 404 → 改走 `apiGet`/新增 `apiPostJSON` 的 ksu.exec 桥接,本机现可见 M1/M2 (per-uid 字节 + 应用名)。
- **远程面板 (`:8443`) 配对死循环**:未配对时直接进 dashboard 但所有 `/api/*` 返回 401,用户卡在"加载失败"到不了配对页。`app.js` 在中心 `fetchWithTimeout` 拦 401 → 自动跳 `/pair` (守卫防循环),并把 我的应用/导出 tab 的裸 fetch 也并入。

### Internals (v5.7.0-rc1, 2026-05-23)
- 建立**版本/更新日志规范**:每次更新 bump `module.prop` version (`-rcN`) + versionCode,并同步写 `CHANGELOG.md` 与应用内 `webroot/changelog.html`。本轮版本号从一直停滞的 `v5.7.0-m2` 推进到 `v5.7.0-rc1` (versionCode 570101)。

### Added (v5.7.0-m2, 2026-05-22)
- **app metadata 子系统** (`src/dpid/appmeta/` 新包) — 把 `com.tencent.mobileqq` 显示成 `QQ`、`com.ss.android.ugc.aweme` → `抖音` 等
  - 策划静态 label map: ~180 个最热门 app (腾讯 / 字节 / 阿里 / 米哈游 / 网易 / 银行 / VPN / 系统 app / 全球 app / AI 助手 ...)
  - 用户覆盖文件 `/data/local/hnc/etc/app_labels.json` 可热加载 (mtime stat 触发重读, ~5s 内生效, dpid 无需重启)
  - 兜底:`prettyFallback(pkg)` 把 `com.example.foo` 变 `Foo`
  - 零依赖,纯 map lookup,**任何 Android 设备 100% 工作**(不依赖 aapt/aapt2/APK 解析)
- `output.SelfApp` 新增字段 `display_name`
- `output.AppMetaResolver` 接口 + `SetAppMetaResolver` 方法,避免 output→appmeta 反向依赖
- Snapshot 中按 pkg 查 display name,每次都重算所以 override 文件改动会立刻生效

### Design choices (v5.7.0-m2)
- **不解析 APK** — 该方案在 spike 中被否决:此设备无 aapt/aapt2,APK 资源被严重混淆 (QQ 的 `r/i/eug.xml` 这种短名),AXML/ARSC parser 在混淆/分包/locale 边缘容易出错
- **不抓 icon** — 留给 M6 UI 重做用 "2 字母 + 哈希色块" 方案 (跟 hnc_ultimate_v2 设计稿一致)
- **不调 dumpsys** — dumpsys 输出含 labelRes ID 但要 ARSC 解析才有人话, 而且 grep 上下文易误匹配
- 策划 label 库放 `labels.go` 而非 JSON, 编译期 embed, 避免 runtime file IO 失败模式

### Validation (v5.7.0-m2 spike)
Ling 设备实测确认:
- `which aapt aapt2` 都返回空 → 不能依赖外部工具
- `cmd package --help` "Unknown command" → cmd 接口不稳
- `pm path com.tencent.mobileqq` 工作,base.apk 路径可拿到 → 但**用不到了**
- `dumpsys package <pkg>` 不直接给 label → 兜底也走不通
- 结论:策划 label map 是唯一兼容 100% 的路

### Added (v5.7.0-m1, 2026-05-22)
- **per-uid 字节统计子系统** (`src/dpid/bytestats/` 新包)
  - eBPF backend: 直接 bpf(2) syscall 读 `/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map` (Android 12+ 标配), raw syscall 实现 ~200 行不依赖第三方库, 实时零拷贝
  - dumpsys backend: 解 `dumpsys netstats detail` 文本输出做兜底, 4 秒 rate-limit 防止 fork 风暴
  - NoneSampler: 两个 backend 都不可用时的零数据降级, dpid 不崩
  - `Detect()` 启动时按 eBPF→dumpsys→none 顺序探测, log 一次结果
- `output.SelfApp` 新增字段: `rx_bytes` / `tx_bytes` (累计) + `rx_bytes_delta` / `tx_bytes_delta` (上次 sample 差值) + `byte_sampler_updated_at` (unix s)
- `output.SelfState` 新增字段: `byte_sampler_source` (`ebpf` | `dumpsys` | `none`)
- `output.SelfAttribAggregator.RecordBytes()` 方法: 每 5s tick, 维护 curr/prev counter, Snapshot 算 delta (underflow-safe clamp)
- `cmd/dpid/main.go` 加 `runByteSampler` goroutine, source="none" 时直接 return 不空转

### Internals (v5.7.0-m1)
- bytestats 包刻意不依赖 cilium/ebpf, raw bpf() syscall 实现自包含, 保持 go.mod 干净
- `output.ByteSample` 在 output 包内定义 (而非从 bytestats import), 避免反向依赖
- cmd/dpid 做翻译层 (bytestats.ByteCounts → output.ByteSample)

### Validation (v5.7.0-m1 spike)
Ling 设备实测确认 (Realme RMX5010, Android 16, SukiSU kernel 6.6.102):
- `/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map` 存在 mode `0060` owner root:net_bw_acct
- SELinux Enforcing 但 `su:s0` 能 open (DAC + MAC 都过)
- `dumpsys netstats detail` 输出格式跟 parser regex 完美对齐
- apexdata 文件存在但不用 (eBPF 同源数据但实时)

---

## [v5.7.0] — 计划中 (开发中)

**主题:从"极客仪表盘"到"普通人能用的工具"。**

v5.7 是 HNC 历史上第一次产品定位升级 —— 不再只是给极客看的运维仪表盘,而是任何 Android 用户都能直接看懂的网络管理工具。

### 路线图(milestone)

| M | 名称 | 状态 | 工期 |
|---|---|---|---|
| M1 | per-uid 字节统计 | ⏳ 研究中 | 2-3 天 |
| M2 | app metadata (icon + display name) | 待定 | 1 天 |
| M3 | 时间序列存储 (5-min 桶, 30 天保留) | 待定 | 1-2 天 |
| M4 | 事件流 (auto-expand / daemon / device 事件) | 待定 | 1 天 |
| M5 | RESTful API 契约层 (`/apps`, `/devices`, etc) | 待定 | 2-3 天 |
| M6 | apps tab UI 重做 (基于 hnc_ultimate_v2 视觉) | 待定 | 1-2 天 |
| M7 | 其他 tab (devices/traffic/logs/settings) UI 重做 | 待定 | 2-3 天 |
| M8 | 文档 + 测试 + 性能 | 待定 | 1 天 |
| M9 | v5.7.0 stable 发布 | 待定 | 0.5 天 |

**预计完成日期**:M1+M6 先做 (3-4 天能看到"形状"),整体 7-10 个开发日。

---

## [v5.6.0] — 2026-05-22 (本日发布)

**主题:看见自己设备的网络流量。**

实现 HNC 第一次把"自身设备上的 app 在访问什么"这件事做成端到端可见的产品。从 KSU 内核模块视角,通过 AF_PACKET 抓自己设备的网络流量,提取 SNI,跟 /proc/net 的 uid 关联,最后在 WebUI 上让用户看见。

### Added
- **rc1**: self-iface AF_PACKET 捕获子系统 (`cmd/dpid/self_capture.go` ~250 行)
  - 30s reconciler goroutine 重扫 self-eligible 接口 (rmnet/wlan0 等)
  - 受 `/data/local/hnc/run/self_capture.enabled` flag 文件控制
  - TLS ClientHello → LookupUID → RecordSNI 链路打通
- **rc2**: 走法 1 子域自动扩展 (`output/auto_expand.go` ~380 行)
  - 三重证据:apex 共享 + uid hit 计数 ≥10 + 不在 blocklist
  - 输出到 `/data/local/hnc/etc/dpi_rules.d/_auto_expanded.json`
  - 独立 flag `/data/local/hnc/run/auto_expand.enabled` (跟 self_capture 分开)
  - 初始 blocklist ~50 条 (Cloudflare/AWS/akamai/各种 analytics)
  - `SelfAttribAggregator` 加 `ObserveSNI` / `HitCount` / `PkgForUID` / `drainUnmatchedSNIs` 方法
- **rc3**: VPN tun 接口加入 self capture 候选 (Clash/WireGuard/Tailscale)
  - `self_iface.go` 把 tun/vpn/wg/tailscale 从 negative 挪到 positive
- **rc6**: WebUI 应用 tab hero 增加 "SNI 抓取" 计数
- **rc6**: 每个 app card 的规则 pill 显示 hit count,≥10 时变绿 + ✓
- **rc6**: WebUI 设置页加 auto-expand toggle (rc7 接通后端)
- **rc7**: 未匹配 SNI 候选块显示 (我的应用子页底部)
  - pending=0 显示 "✓ 规则集已覆盖" 解释性零状态
  - pending>0 显示 sample 候选 + ⚠ 计数
- **rc7**: httpd `POST /api/self/auto_expand/toggle` endpoint
  - 重构 `flipFlagFile` shared helper 给将来 toggle 类 endpoint 复用

### Fixed
- **rc3**: parser 链路层假设修复 (Qualcomm rmnet 是 ARPHRD_RAWIP=519, 不是以太帧)
  - 加 `parseRawIPPacket()` 跳过 14 字节以太头, 按 IP version 直接 dispatch
  - rawsocket.go Open 时读 `/sys/class/net/$iface/type` 存 Handle.linkType
- **rc4**: BPF 滤波器链路层修复 (rc3 之后实测 packets 仍 0)
  - 根因:kernel BPF 内核态按以太帧偏移读 IP 头中段当 etherType, 全部 silent reject
  - 加 `BuildFilterRawIP()` ~130 行, 所有偏移 -14, 入口用 IP version dispatch
  - Open 时按 linkType 选 filter

### Changed
- `SelfAttribAggregator.rulesByUID` 从 `map[int]map[string]struct{}` 升级为 `map[int]map[string]int` (counter, 供 auto-expand evidence #2 使用)
- `SelfApp.TopRules` 排序从字母序改为 hit count 降序 (WebUI 关心"最常用规则")

### Internals
- **rc5**: 可观测性导出 (auto-expand 调试盲区)
  - 新字段 `SelfApp.rule_hit_counts` (map: ruleID → 次数)
  - 新字段 `SelfState.unmatched_snis_pending` (队列大小)
  - 新字段 `SelfState.unmatched_sni_samples` (字典序前 20)
- **rc5**: auto-expander goroutine 入口加无条件启动日志
- **rc6**: `flipFlagFile` shared helper, 为 v5.7 toggle 基础设施铺路

### 产品价值校正(实测发现)
rc4 后实测显示:**整个 self-capture 子系统全栈工作**(rmnet/tun 抓 SNI, uid 归因准, kuaishou hit=12 跨阈值),但 `_auto_expanded.json` 始终不生成。诊断后(rc5 导出 unmatched 队列状态):**463 个规则 apex 已经覆盖所有看到的 SNI**,unmatched 队列长期为空。

**结论:v5.6 真正的产品价值是"让用户看见",不是"自动加规则"。** auto-expand 功能技术完整但实际很少触发(这是符合预期的状态,在 UI 上以绿色 ✓ 状态显式展示给用户)。

---

## [v5.5.0] — 2026-05-21

**主题:watchdog 真正成为 supervisor。**

v5.5 主线本来是 self_attrib 采样基础设施 + WebUI 应用 tab 骨架,但 rc1 部署后碰到一系列 watchdog 问题, rc3-rc6 几乎全在修 supervisor 的 bug, 让整个 daemon 拓扑真正做到"死了就自动起回来"。

### Added
- `SelfAttribAggregator` (`/proc/net` 采样器, uid→pkg 缓存)
- `DiscoverSelfCandidates` (self-eligible iface 选择器)
- WebUI 应用 tab 骨架 (3 子页: 我的应用 / 导出 / 设置)
- ARCHITECTURE.md 第 11 章 (v5.5+ 自身流量识别与规则闭环设计, 含走法 1 + 走法 2 hybrid 设计)
- 6 个 self 相关 API endpoint (`/api/self`, `/api/self/toggle`, `/api/self/ifaces`, `/api/self/attrib`, `/api/export`)

### Fixed
- **rc3**: ColorOS Go fork EPERM (spawnDaemon 去 Setsid)
- **rc4**: rc3 漏的同一坑 (ensureNDPIRunning 也去 Setsid)
- **rc5**: `watchdog.sh` EXIT trap 误报刷屏
  - 根因 (Ling 用 SIGQUIT goroutine dump 定位): action 子进程 case 后 `exit $?` 干净退出时, 全脚本 trap 误以为主循环崩了
  - 修:action 分发块入口加 `WDG_CLEAN_EXIT=1` 让 trap 在 action 模式 noop
- **rc6**: watchdog 自动重启 httpd 失效 (诊断鸣谢另一个 Claude 窗口)
  - 根因:`httpdDaemon().binPath` 写成 `binDir+"/hnc_httpd"` 但实际装在 `/daemon/hnc_httpd/hnc_httpd`
  - 错配导致 ensureDaemonRunning 走 "binary missing, silently skip" 分支, 永远不重启
- **rc6**: hnc_launcher 没人监督 (顺手补)
  - 加 `launcherDaemon()` spec, 加 supervision 块 (放在 dpid 之前, 因为 dpid short-circuit 依赖 launcher 活)

### Internals
- 整个 daemon 拓扑变成自洽自愈:
  ```
  hnc_watchdog (Go, 监督全部)
     ├─→ hotspotd     ← watchdog 直管
     ├─→ hnc_httpd    ← watchdog 直管 (rc6 修)
     ├─→ hnc_launcher ← watchdog 直管 (rc6 新增)
     │      └─→ hnc_dpid    ← launcher 自治 (rc3 引入)
  ```

### Removed
- `keepalive.sh` 兜底脚本 (rc6 之后多余, 留着无害但建议删)

---

## [v5.3.x] — 2025 年若干月 (历史)

详见 git log 和 ARCHITECTURE.md 第 3 章 "3 套 fallback 的历史原因"。简要:

- v5.3.0 nDPI 集成
- v5.3.x rcN ColorOS / SukiSU / kernel 6.6 平台适配的一连串补丁
- 引入 hnc_launcher (C) 绕过 Go fork EPERM (rc30.12 起)
- 引入 dpid_supervisor 然后又被 launcher 取代

## [v5.2.x] — 更早

详见 git log。主要是 nDPI/L3 规则系统、Hotspot Network Control 的核心 hotspotd + watchdog 主体, 以及 KSU 模块化打包。

---

## 维护规范

### 新 PR / commit 必须更新本文件

每个改动同 commit 在 `[Unreleased]` 下增加条目,**不要等到发版才补**。发版时把 `[Unreleased]` 下的内容挪到对应版本号下,加日期。

### 分类原则

- **Added**: 用户能感知的新功能 / 新 API endpoint / 新字段
- **Changed**: 现有功能改了行为 (即使是改善, 比如默认值变化、性能提升)
- **Fixed**: 是 bug 修复, 用户原来碰到过现在不再碰到
- **Internals**: 重构、加日志、改文档、加测试 — 不影响用户感知

模糊时优先 Internals,以保持其他三类 ("用户语言") 的纯净。

### 实测发现单独记录

像 v5.6 那种"做完发现产品假设跟现实不符"的真实数据校正,放在版本块底部独立段落 ("产品价值校正"),不混到 Added/Fixed/Changed 里。这种诚实的记录对维护者(包括将来的自己)价值很高。

### 致谢

bug 诊断如果是另一个 Claude 窗口 / GPT / 用户自己关键定位的,在条目里写明 "(诊断鸣谢: XXX)"。这不是客套, 是工程实践,**让未来排查类似问题的人知道哪些智能体在这类问题上有过经验**。
