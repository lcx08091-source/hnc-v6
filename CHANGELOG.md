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
