# 工作文档:HNC v5.26.0-rc1「去重收口」

> 交给接手开发的 AI 编程助手(千问等)执行。**请完整读完再动手**,第 2 节「边界」是硬约束。
> 背景:`docs/CODEMAP.md`(代码地图)、`docs/ROADMAP.md`、`CHANGELOG.md` 里 v5.25.0-rc1 / rc2 两段(看门狗问题的来龙去脉)。
> 基线:分支 `claude/environment-config-ydr2ow` 最新提交(v5.25.0-rc2)。

---

## 0. 为什么要做这一版(一句话)

HNC 有好几块功能**同时存在 2~5 份实现**(Go / shell / C 各写一份),以前只改其中一份,导致功能在真机上悄悄失效:
v5.25 刚查出 Go 版看门狗缺了「定时开关热点」「在线时长」「本地时区」「省电」四项,界面还因为另一份进程检测写法在 Android 上失灵而一直误报「watchdog 未运行」。

**本版目标:每块功能只留一份「权威实现」,其余要么删掉,要么改成调用它。不加任何新功能,用户可见行为除了修掉的不一致之外保持不变。**

---

## 1. 项目基本情况(必读)

- Android root 模块,运行目录 `/data/local/hnc/`(代码里 `hncDir` / `HNC_DIR`):`data/` 持久化,`run/` 运行时(可丢),`etc/` 运行时配置(dpid 规则库在 `etc/dpi_rules.d/`),`logs/`。
- **两个 Go 模块**:
  - `daemon/hnc_httpd/`(module `hnc_httpd`,`go 1.25.0`):HTTP API。它通过 `replace hnc.io/dpid => ../../src/dpid` **可以 import dpid 模块的包**(已在用 `hnc.io/dpid/alert`、`hnc.io/dpid/tzlocal`)。
  - `src/dpid/`(module `hnc.io/dpid`,`go 1.22`):`cmd/dpid`(抓包识别)、`cmd/hnc_watchdog`(看门狗,**真机实际运行的版本**)、`cmd/dpid_supervisor`(dpid 守护的 Go 版)、以及共享包 `activity/`、`alert/`、`tzlocal/` 等。
  - **共享代码放在 `src/dpid/` 下新建包**,两个模块都能用。不要改两个 `go.mod` 的 `go` 版本,不要加第三方依赖。
- 编译约束:`CGO_ENABLED=0`。arm64 用 `GOOS=android GOARCH=arm64`;**32 位只做类型检查** `GOOS=linux GOARCH=arm GOARM=7`(android/arm 需要 NDK,真 armv7 包由 CI 构建)。
- Android 坑(写代码时必须记住):
  1. **Go 在 Android 上 `time.Local` 恒为 UTC**,每个 Go 进程的 `main()` 必须 `time.Local = tzlocal.Location()`(httpd、hnc_watchdog 已设;新进程要设)。
  2. **toybox 的 grep 不认 BRE 的 `\|`**,`ps -ef` 列格式也和 GNU 不同。shell 里判断进程是否存在要用 pidfile + `/proc/<pid>/cmdline`,不要靠 `ps | grep`。
  3. 运行期 `/system/bin` 可能被卸掉,shell 脚本开头都有 PATH 加固,照抄现有脚本的写法。
- 两个看门狗的关系(T1 的背景):`service.sh` 优先启动 Go 版 `bin/hnc_watchdog`;它跑主循环,具体的 iptables / tc 动作通过 `sh bin/watchdog.sh action <名称>` 调用 shell 函数。`watchdog.sh` 不带参数运行时会进入它自己的 `while true` 主循环 —— 那是 rc30 之前的旧主循环,只在 Go 二进制缺失时兜底。CI 每次都编译 `hnc_watchdog`,`bin/artifact_sanity_check.sh` 也要求它存在,所以兜底分支实际上用不到,却一直在被人往里加功能。

---

## 2. 边界(硬约束)

1. **不加新功能、不改 UI 设计**。允许的 UI 改动只有:文案说明数据口径、删除指向已删除功能的入口。
2. **不改 tc / iptables / 限速 / 封锁的规则内容**(`bin/tc_manager.sh`、`bin/iptables_manager.sh`、`bin/apply_*.sh` 的逻辑不动)。
3. **API 返回结构保持兼容**:`/api/run_status`、`/api/proc_health`、`/api/usage_month`、`/api/alerts`、`/api/power` 现有字段一个不能少、含义不能变(可以加字段)。前端 `webroot/js/*.js` 依赖它们。
4. **持久化数据格式不改**:`data/*.json`、`run/alerts.jsonl`、`run/online_hours.jsonl`、`run/stats.*.jsonl`、`data/stats_raw.jsonl` 等格式不变;可以新增文件。
5. **不改 CI**(`.github/workflows/`)、不改 `customize.sh`、`post-fs-data.sh`。`service.sh` 只允许改第 3 节明确提到的地方。
6. **删代码前先证明没人用**:每删一个函数 / 脚本 / 文件,在提交说明里写出 `grep -rn` 的结果(调用方为零,或已全部改掉)。
7. **不许通过删除或跳过测试让测试变绿**。被删功能自身的测试可以随功能一起删,但要在提交说明里逐个列出删了哪些测试、为什么。
8. 本文档「不做」清单(第 4 节)里的东西一律不碰。

---

## 3. 任务(按顺序做,每个任务一个提交)

### T0 · 记录基线
在动手前跑一遍第 5 节的全部自检命令,把结果(尤其 `test/run_all.sh` 的 passed / failed 数、哪些失败)记到提交说明里。之后每个任务完成都不能比基线差。
> 参考:维护者环境里基线是 `ALL PASS: 415/416 (1 skipped)`;你的沙箱若缺 toybox / root,会有一批 `hnc_json` 相关用例失败,那是环境问题,记下即可。

---

### T1 · 看门狗只留一个主循环(Go 版)
**问题**:`bin/watchdog.sh` 里 `action` 分派(约 1022~1047 行)之后的整个旧主循环与 Go 版 `src/dpid/cmd/hnc_watchdog/main.go` 的 `mainLoop()` 重复,且已经分叉。

**做法**:
1. `watchdog.sh`:删除 action 分派之后的全部主循环代码(从 `# ── 主循环 v4.0.0-patch1.5` 开始到文件末尾)。在原位置改成:不带 `action` 参数直接运行时,打一行日志「主循环已由 bin/hnc_watchdog 承担,watchdog.sh 只提供 action」并 `exit 2`。
2. 删除**只被旧主循环用到**、没有任何 action 用到的函数(例如 `heartbeat`、`check_services`、`ensure_dpid_running`、`ensure_httpd_running` 等 —— **以 grep 结果为准**,逐个确认它不在任何 action 的调用链里,也不被其他脚本 `source` 后调用)。保留所有 action 需要的函数(`probe_valid_hotspot`、`check_health`、`full_restore`、`do_full_init`、`do_migrate` 等及其依赖)。
3. `service.sh` 第 688~696 行附近:去掉 `else sh watchdog.sh` 兜底分支;`hnc_watchdog` 不存在或不可执行时 `log "FATAL: bin/hnc_watchdog missing, watchdog not started"`,不启动 shell 版。
4. 同步测试与镜像:
   - `test/unit/test_power_activity.sh` 第 111~116 行对 `watchdog.sh` 里 `hnc_activity.sh` / `PROBE_INTERVAL_PENDING_QUIET` 的检查删掉或改为检查 Go 版(`src/dpid/cmd/hnc_watchdog/power.go` 的 `intervalIdleProbe`)。
   - `daemon/hnc_httpd/power_test.go` 的 `TestPowerShellMirrorConstants` 中 watchdog 那一段改为对比 `power.go` 的 `intervalIdleProbe`(读源码正则取值,方式同现在读 shell 常量);offload_guard 部分不变。
   - `power_sched.go` 顶部表格与 `watchdog_pending` 说明里的「shell 镜像」字样改成 Go 版。
5. `src/dpid/cmd/hnc_watchdog/main.go` 顶部注释里关于「shell fallback」的描述更新。

**验收**:`sh bin/watchdog.sh action check_health` 等所有 action 仍可用(`test/unit/test_v512_core_path.sh` 必须通过);`sh -n bin/watchdog.sh` 通过;`grep -n 'while true' bin/watchdog.sh` 无主循环;`test/unit/test_dns_takeover.sh` 里对 `watchdog.sh` 中 `dns_takeover.sh" remove` 出现 ≥2 次的断言仍成立(若你删的代码里包含其中一处,改测试前先确认另一条路径仍会调用它)。

---

### T2 · dpid 守护只认一个「当前守护者」
**问题**:dpid 有三种守护程序(C 版 `bin/hnc_launcher`、shell 版 `bin/hnc_dpid_guard.sh`、Go 版 `bin/hnc_dpid_supervisor`),`service.sh` 约 800~865 行按机型兼容性**选一个**(变量 `DPID_LAUNCHER`)。但:
- Go 看门狗 `ensureDaemonRunning(launcherDaemon())` **无条件**拉起 `hnc_launcher` —— 即使 service.sh 因为它在本机崩溃(TLS / Bionic 不兼容)而选了别的,看门狗也会每 30 秒重拉一次;
- `dpidDaemon()` 的 `guardBin` 又写死成 `hnc_dpid_supervisor`;
- `service.sh` 的哨兵循环(约 1100~1116 行)在某些分支里还会直接 `nohup $DPID_BIN`。
三方对「谁负责 dpid」各有一套判断。

**做法**:
1. `service.sh` 选定后把选择写进 `run/dpid_launcher.choice`(一行:`launcher` | `guard` | `supervisor` | `direct`),原子写(先写 `.tmp` 再 `mv`)。
2. Go 看门狗新增 `readLauncherChoice()`:按 choice 只监管对应那一个(`launcher` → `launcherDaemon()`;`guard` → 确认 `hnc_dpid_guard.sh` 在跑,不在则 `nohup sh bin/hnc_dpid_guard.sh`;`supervisor` → `hnc_dpid_supervisor`;`direct` 或文件不存在 → 保持现状行为)。其余两个**不再拉起**。
3. 哨兵循环里对 dpid 的直接拉起:只在 choice 为 `direct` 时执行。
4. 单元测试:choice 解析(含文件缺失、内容非法)。

**验收**:三种 choice 下看门狗只拉起对应守护程序(用函数级单测覆盖,不需要真机)。

---

### T3 · 「进程是否在跑」只留一份实现
**问题**:4 处各写一套:
- `daemon/hnc_httpd/action_v511.go` `runStatusScript`(shell 里 `pidof`)+ `readWatchdogState`(v5.25 刚加的 Go 版);
- `bin/rc17_process_health.sh`(`ps -ef | awk`,`/api/proc_health` 原样透传;`bin/debug_bundle.sh` 也调用);
- `daemon/hnc_httpd/selfcheck.go` 的 `scProcDefs` + `(*scCtx).findPID`;
- `daemon/hnc_httpd/power_stats.go` 的 `powerProcDefs` + `(powerFS).findPID`(**这份最完整**:pidfile → 校验 cmdline 关键字 → 扫 `/proc` 兜底)。

**做法**:
1. 新建共享包 `src/dpid/procfind/`:
   ```go
   type Spec struct {
       Name     string   // 展示名
       Key      string   // /proc/<pid>/cmdline 必须包含的子串(防 PID 复用)
       PIDFiles []string // run/ 下的 pidfile, 按顺序尝试
       ScanKey  string   // pidfile 都失效时扫 /proc 用的关键字; 空 = 不扫
   }
   type FS interface { ReadFile(path string) ([]byte, error); PIDs() []int }
   func OSFS() FS
   func Find(fs FS, runDir string, s Spec) int          // 0 = 没在跑
   func Specs() []Spec                                  // HNC 全部进程的唯一定义表
   ```
   逻辑以 `power_stats.go` 的 `findPID` 为准(cmdline 为空时视为匹配的特例也照搬)。`Specs()` 合并现有三张表(httpd / hotspotd / hnc_dpid / watchdog / dpid_guard / offload_guard / clsact_wd / hnc_launcher / dpid_supervisor),pidfile 与关键字取三张表里**真机验证过的**那份(watchdog 的 `ScanKey` 用 `hnc_watchdog`)。
2. 改用它:`power_stats.go`、`selfcheck.go`(保留现有测试的注入方式 —— 把现在的 fake 读文件包装成 `FS` 传进去)、`action_v511.go` 的 run_status(去掉 shell 脚本里的 `HP=$(pidof hotspotd...)` 段,hotspotd 也走 `procfind`;tc / iptables 规则计数仍可用 shell)。
3. `/api/proc_health` 改为 Go 实现,**JSON 字段与 `rc17_process_health.sh` 输出完全一致**(`schema_version / timestamp / status / detail / counts{hnc_httpd,hnc_dpid,hotspotd,watchdog_total,watchdog_main,dpid_guard_total,dpid_guard_main} / pidfiles{...}`),前端 `webroot/js/stats.js` 不用改。「主实例数」按 procfind 找到即 1;「子进程数」可按 cmdline 关键字计数。
4. 删除 `bin/rc17_process_health.sh`;`bin/debug_bundle.sh` 里对它的调用改为:由 httpd 在执行导出诊断包动作前把 proc_health 结果写到 `run/proc_health.json`,debug_bundle 拷贝这个文件(找到 httpd 里调用 `debug_bundle.sh` 的 action,在调用前写)。
5. 单测:`procfind` 用 fake FS 覆盖:pidfile 有效 / PID 被复用(cmdline 不含关键字)/ pidfile 失效走扫描 / 都找不到。

**验收**:四处显示一致(同一个 fake FS 下 run_status、selfcheck、power、proc_health 判断相同);`go test` 通过。

---

### T4 · 「本月流量」与「月度配额」只留一个口径
**问题**:同一台设备的「本月用量」现在有三种算法:
| 用在哪 | 数据源 | 周期 |
|---|---|---|
| 设备卡流量配额(会限速 / 断网)`limit_policy.go` | 防火墙计数器差分,与 DPI 增量取 max | 计费日 billing_day |
| 设置 → 告警 → 月度流量配额(只提醒)`src/dpid/alert/quota.go`,由 Go 看门狗每 5 分钟 `alert.Run` 执行 | 只用 DPI 增量 `run/stats.*.jsonl` | 自然月 |
| `GET /api/usage_month`(设备卡「本月」)`action_v512.go` | 只用 DPI 增量 | 自然月 |

**做法**(权威 = `limit_policy.go` 的 `limitCtl`,它已经对**所有**非模拟设备累加用量):
1. `limitCtl` 新增只读方法 `MonthUsage() map[string]uint64`(本计费月 rx+tx,= `max(自有累加, DPI 合计)`)。`tick()` 里 DPI 下限(`histMon`)目前只在 `len(c.policies) > 0` 时计算 → 改为:有策略、**或全局告警月度配额开启**、**或最近 5 分钟有人请求过 `/api/usage_month`** 时计算。
2. 全局告警月度配额迁到 httpd:在 `limitCtl` 每轮末尾,对**没有设置设备配额**的设备,用 `MonthUsage` 与 `alert` 配置里的 `monthly_quota{enabled, limit_bytes, warn_at_pct}` 比较,生成 `kind=monthly_quota` 告警。告警的 `ID` / `Detail` 文案 / 档位(warn / over)沿用 `quota.go` 的写法;去重用 `limitCtl` 状态里新增的 `GlobalAlertWarn` / `GlobalAlertOver`(存计费月 key),持久化随 `limit_ctl_state.json`(加字段,不改旧字段)。有设备配额的设备不再重复发全局告警(设备配额自己会告警,见 `maybeAlert`)。
3. 从 `alert.Run` 中删除月度配额检测(`alert.go` 第 348~352 行附近的调用);若 `quota.go` 里的函数再无人使用,连同其测试一并删除(`sumByMAC` 被 `anomaly.go` 使用,**保留**)。`QuotaCfg` 结构保留(配置格式不变)。
4. `/api/usage_month`:改为返回 `MonthUsage()`(字段与现在一致),周期改为计费月,顶层**新增** `period_start`。`limitCtl` 尚无数据(刚安装)的设备回退到现有 DPI 合计。
5. UI 文案(`webroot/js/settings.js` 告警 → 月度流量配额那一行的说明):改为「按计费日起算,与设备卡『本月』同一口径;单独设置了配额的设备按自己的配额提醒」。
6. 单测:有 / 无设备配额两种设备的全局告警、warn → over 升档、同月不重复、跨计费月重置、`usage_month` 回退。

**验收**:同一台设备在设备卡「本月」、配额进度条、告警里的用量数字相同。

---

### T5 · 热点网卡名只认 `hnc_iface.sh` 的结果
**问题**:`bin/hnc_iface.sh` 自 v5.20 起是「唯一权威探测器」,结果写在 `run/iface_detect.json`(`{"schema":1,"ts":..,"iface":"wlan2"|"",...}`)。但 dpid 侧还有三份各自判断:
- `src/dpid/capture/iface.go` `readHNCHint()`(读 `run/hotspot_iface`)+ `DiscoverAPCandidates()` 自己排序;
- `src/dpid/cmd/dpid_supervisor/main.go` `getIface()`(注释写着「照抄 guard.sh」,含写死的候选名表);
- `bin/hnc_dpid_guard.sh` `get_iface()`。

**做法**:
1. 新建共享包 `src/dpid/ifacehint/`:`func Read(runDir string, now time.Time) (iface string, ok bool)` —— 读 `iface_detect.json`,`iface` 非空且 `ts` 在 10 分钟内则用;否则回退读 `run/hotspot_iface`(格式校验同现在的 `readHNCHint`);都没有返回 `ok=false`。
2. `capture/iface.go` 的 `readHNCHint` 与 `dpid_supervisor` 的 `getIface` 第 2 步都改为调用 `ifacehint.Read`;各自原有的扫描兜底保留(只在 `ok=false` 时走)。
3. `hnc_dpid_guard.sh` `get_iface()`:在读 `hotspot_iface` 之前先读 `iface_detect.json` 的 `iface` 字段(用 shell 内建 / 已有的 `read_json_string_key` 之类工具,不新增依赖),同样做 10 分钟新鲜度判断。
4. 单测:新鲜 / 过期 / 空 iface / 文件损坏 / 回退 hotspot_iface。

**验收**:三处在同一组输入文件下给出相同网卡名。

---

### T6 · 时钟可信规则只留一份
**问题**:「时钟是否可信(≥2025 年 且 不早于高水位 − 600 秒)」有三份:`daemon/hnc_httpd/clock_guard.go` 的 `clockSaneAt`、`bin/hnc_clock.sh` 的 `hnc_clock_sane`、`src/dpid/cmd/hnc_watchdog/duties.go` 的 `clockSaneNow`(v5.25 刚加)。

**做法**:
1. 新建共享包 `src/dpid/clockhwm/`:常量 `MinUnix = 1735689600`、`BackTolerance = 600`;`func ReadHWM(path string) int64`;`func Sane(nowUnix, hwm int64) bool`。
2. `clock_guard.go` 的 `clockSaneAt` 与 hnc_watchdog 的 `clockSaneNow` 都改为调用它(`clock_guard.go` 的自愈、跳变检测逻辑**不动**,它是唯一会重置高水位的地方)。
3. 加一个 Go 测试解析 `bin/hnc_clock.sh` 里的 `HNC_CLOCK_MIN_TS` / `HNC_CLOCK_TOLERANCE`,断言与 `clockhwm` 常量相等(写法参照 `power_test.go` 的 `TestPowerShellMirrorConstants`)。shell 版保留(给 shell 脚本用),靠这个测试锁定一致。

---

### T7 · 告警写入只留一个函数
**问题**:往 `run/alerts.jsonl` 追加一行的代码有 5 份:`src/dpid/alert/alert.go` `appendAlert`、`daemon/hnc_httpd/app_time.go` `appendAlertJSONL`、`phone_usage.go` `puAppendAlert`,以及 `mac_merge.go`、`pair_guard.go` 里各自的写法。且 httpd 与看门狗两个进程会同时追加同一文件。

**做法**:
1. 在 `alert` 包导出 `func Append(path string, a Alert) error`:`O_APPEND` 打开后加 `syscall.Flock(fd, LOCK_EX)` 再写(一次 `Write` 写完整行),写完解锁。原 `appendAlert` 改为调用它。
2. httpd 里所有追加告警的地方改用 `alert.Append`,删除各自的副本。
3. 单测:并发 20 个 goroutine 各追加 50 条,结果文件每行都是合法 JSON,行数正确。

---

### T8 · 删除没上线的 C 版 JSON 工具
**问题**:`daemon/hotspotd/tools/hnc_json.c` + `build_hnc_json.sh` 有源码、有专门测试,但 **CI 从未编译、刷机包里没有 `bin/hnc_json_c`**。`bin/hnc_json` 里所有「先试 C helper」的分支、`bin/hnc_json_c_status.sh` 都是死代码。

**做法**:
1. 删除 `daemon/hotspotd/tools/hnc_json.c`、`daemon/hotspotd/tools/build_hnc_json.sh`、`bin/hnc_json_c_status.sh`。
2. `bin/hnc_json`:删除 `HNC_JSON_C` / `HNC_JSON_C_WRITE_ENABLE` 相关分支(只删「C helper 存在时」那一侧,shell 实现保持原样)。
3. 删除专测 C 桥的用例:`test/unit/test_hnc_json_c_bridge.sh`、`test_hnc_json_c_write_bridge.sh`、`test_hnc_json_c_write_gate.sh`(在提交说明里列出)。其余 `test_json_set_*_hnc_json_bridge.sh` 测的是 `json_set.sh → hnc_json(shell)`,**保留**。
4. `bin/json_diag_bundle.sh`、`bin/json_health_panel.sh` 里对 `hnc_json_c_status.sh` 的调用删掉;`webroot/json-health.html` 若展示了 C helper 状态,删掉那一块(只删展示,不改其他)。

---

### T9 · 版本与文档
1. `module.prop`:`version=v5.26.0-rc1`,`versionCode=5260001`。
2. `CHANGELOG.md` 最上面加 `## [5.26.0-rc1] - <日期>`,格式参照 5.25.0-rc2;重点写清:每块功能的「权威实现」是谁、删了什么、用户能感知的变化(月用量口径统一、告警配额按计费日)。
3. `webroot/changelog.html` 最上面加一段大白话。
4. `docs/CODEMAP.md`:「手机上跑着的进程」一节更新(看门狗只有 Go 版;dpid 守护由 `run/dpid_launcher.choice` 决定)。新增一节「权威实现表」:进程检测 → `procfind`;热点网卡 → `hnc_iface.sh` + `ifacehint`;时钟规则 → `clockhwm`;月用量 → `limitCtl`;告警写入 → `alert.Append`。
5. `docs/ROADMAP.md` §A 表格:插入 v5.26「去重收口」一行(✅ rc1),原 v5.26「DPI 3.0 自学习」顺延为 v5.27,后面依次顺延;v5.29 行里「移除 shell 版看门狗主循环」标注已在 v5.26 完成。
6. `docs/API.md` 末尾加「## 24. v5.26 变更」:`/api/usage_month` 周期与 `period_start`、`/api/proc_health` 改为 Go 实现(字段不变)、`run/dpid_launcher.choice`。

---

## 4. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 合并两条流量统计链路(`stats_sample.sh` → `data/stats_raw.jsonl`,与 dpid HistorySampler → `run/stats.*.jsonl`) | 不是重复:前者是防火墙计数器的**设备总流量**(统计页),后者是**按应用**的增量(应用历史、异常告警)。T4 只统一「月用量」这一个出口。 |
| 合并 `json_set.sh` 与 `hnc_json` / 合并各 `json_*` 诊断脚本 | 所有设置写入都经过它们,风险高、收益低,留到以后单独做。 |
| 删除任何一种 dpid 守护程序 | 不同 ROM 兼容性不同,三选一的机制要保留;T2 只解决「选定之后别人还在插手」。 |
| `activity.json` 的三个读取方(httpd / dpid `activity` 包 / `hnc_activity.sh`) | 一写多读是有意设计,已有镜像测试锁定数值。 |
| 用 Go 重写 tc / iptables 脚本 | 属于 6.0。 |

---

## 5. 自检命令(每个任务完成后都跑,全部通过才提交)

```sh
# Go
(cd daemon/hnc_httpd && gofmt -l $(git diff --name-only --diff-filter=AM HEAD~1 -- . | sed 's#daemon/hnc_httpd/##' | grep '\.go$') ; \
  go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && gofmt -l . ; go vet ./... && go test ./... && go test -race ./procfind/ ./ifacehint/ ./clockhwm/ ./alert/ \
  && for c in dpid hnc_watchdog dpid_supervisor; do CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null ./cmd/$c || exit 1; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd

# shell
for f in $(git diff --name-only HEAD~1 -- '*.sh') service.sh bin/watchdog.sh; do [ -f "$f" ] && sh -n "$f" || echo "SYNTAX $f"; done
sh test/run_all.sh
sh bin/version_consistency_check.sh
sh bin/ci_preflight.sh

# 前端
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done
```
注:`daemon/hnc_httpd` 里有几个旧文件(`api_export.go`、`main.go`、`server.go` 等)在基线就不满足 gofmt,**只要求你新增 / 修改的文件 gofmt 干净**,不要顺手格式化旧文件(会产生大量无关 diff)。

---

## 6. 验收清单

- [ ] 第 2 节边界无违反;`git diff --stat` 只涉及第 3 节点名的文件 + 新增文件。
- [ ] 每个删除都有「调用方为零」的 grep 证据写在提交说明里。
- [ ] `bin/watchdog.sh` 不再有主循环,所有 action 可用;`service.sh` 不再启动 shell 版看门狗。
- [ ] 看门狗只监管 `run/dpid_launcher.choice` 指定的 dpid 守护程序。
- [ ] 进程检测只有 `procfind` 一份;`/api/proc_health` 字段不变;`rc17_process_health.sh` 已删。
- [ ] 设备卡「本月」、配额、告警月度配额三处用量同源;`/api/usage_month` 字段不变(只多 `period_start`)。
- [ ] dpid / dpid_supervisor / guard 读到的热点网卡名与 `iface_detect.json` 一致。
- [ ] 时钟规则只有 `clockhwm` 一份 Go 实现,shell 版有镜像测试。
- [ ] 告警写入只有 `alert.Append` 一份,带文件锁。
- [ ] C 版 JSON 工具及其测试已删,`hnc_json` 只剩 shell 实现。
- [ ] 第 5 节全部命令通过,`run_all.sh` 不比 T0 基线差。
- [ ] 版本号、CHANGELOG、changelog.html、CODEMAP、ROADMAP、API.md 已更新。

---

## 7. 提交方式

- 从 `claude/environment-config-ydr2ow` 新建分支 `qwen/v5.26`,**每个任务一个提交**,提交信息中文:`v5.26 T3: 进程检测统一到 procfind`。
- 你的沙箱没有推送权限:用 `git format-patch claude/environment-config-ydr2ow..qwen/v5.26 -o patches/` 导出补丁,连同每个任务的自检输出一起交给项目负责人。**不要推 main。**
- 不要改 `CLAUDE.md`。

## 8. 做不完 / 遇到问题怎么办

- 代码和本文档描述对不上:**以代码为准**,在提交说明里写清你怎么处理的。
- 某个删除会让别处坏掉、或必须越过第 2 节边界:**停下**,该任务不提交,把问题写清楚交回。其余任务照常做(T1~T8 彼此独立,T9 最后做)。
- 时间不够时的优先级:T1 > T3 > T4 > T2 > T7 > T6 > T5 > T8。
