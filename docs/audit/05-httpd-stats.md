# A5 审计记录：hnc_httpd 统计 / 功耗 / 自检 / 模拟数据

- 基线版本：v5.33.0-rc2
- 审查员前缀：A5
- 范围（daemon/hnc_httpd/）：phone_usage.go、phone_usage_sim.go、phone_usage_upstream.go、selfcheck.go、selfcheck_api.go、stats_calibration.go、stats_days.go、stats_health.go、power_activity.go、power_hooks.go、power_sched.go、power_stats.go、clock_guard.go、proc_health.go、sim.go、sim_merge.go
- 只记录、不改代码。严重度：P0 远程可利用/数据丢失/断网/开机卡死；P1 常见路径功能错误或崩溃；P2 边界、泄漏、竞态、少见路径；P3 轻微隐患、文档不符。

## 已审文件

## Bug

### A5-001 [P2][确认] 跳变检测用 CLOCK_MONOTONIC，熄屏深睡眠一超 10 分钟就把整段本机流量丢掉
- **位置**：`daemon/hnc_httpd/clock_guard.go:74-77`、`daemon/hnc_httpd/clock_guard.go:339-345`；受害方 `daemon/hnc_httpd/phone_usage.go:604-607`
- **触发 / 现象**：热点关、熄屏时 phone_usage 每 300s（单调时钟）采一次。两次采样之间手机只要累计挂起（suspend）超过 10 分钟，`wall − mono > 10min` 就被判成 clockJump，`puStepCounters(nil, cur, false)` 重建基线，这段窗口里**醒着时**产生的本机流量（夜间相册备份、应用更新、推送下载等）全部不计。电池较多的场景（整晚熄屏）基本每个窗口都会命中，本月用量会系统性偏小，套餐预警跟着晚报。`clock_state.json` 的 `jumps` 也会一直涨。
- **原因**：
  ```go
  var monoStart = time.Now()
  func monoNow() time.Duration { return time.Since(monoStart) }   // CLOCK_MONOTONIC，不含挂起
  ...
  wall := now.Round(0).Sub(g.lastWall)
  mon := mono - g.lastMono
  if d := wall - mon; d > clockJumpThreshold || d < -clockJumpThreshold { v, delta = clockJump, d }
  ```
  文件头注释说「深睡眠期间无转发流量, 损失可忽略」，这个理由只对热点转发成立；phone_usage 记的是本机自己的流量，两次挂起之间醒着跑的后台流量会落在同一个被丢弃的窗口里。
- **建议修复**：跳变检测的「参考时钟」改用含挂起的 CLOCK_BOOTTIME（文件里已有 `bootUptime()` 读 `/proc/uptime`），这样挂起不再被误判为墙钟跳变，只有真正改时间才重建基线。

### A5-002 [P3][确认] 高水位「落后 6 小时自愈」计时在 httpd 重启后会从头算，与注释不符
- **位置**：`daemon/hnc_httpd/clock_guard.go:206-218`、`daemon/hnc_httpd/clock_guard.go:169`
- **触发 / 现象**：时钟落后高水位且「自动确定时间」关闭（或 `settings` 取不到）时，靠 6 小时自愈。httpd 在这 6 小时内重启（崩溃、升级、看门狗拉起）后，`behindSince` 重新从 -1 开始，6 小时重新计；反复重启则永远不自愈，按天落盘的写入器一直暂停。
- **原因**：注释写「计时用开机时长(clockBootUp), httpd 重启不会让 6 小时重新计」，但起点 `behindSince` 只存在内存里（`clockDirLocked` 新建时 `behindSince: -1`，`run/clock_state.json` 既不写它也不读它），换用开机时长只解决了「深睡眠不计时」，不能跨进程保留起点。
- **建议修复**：把「开始落后时的开机时长 + boot_id」写进 `run/clock_state.json` 并在 `clockDirLocked` 里读回；或者改注释说明现状。

### A5-003 [P1][疑似] `content query siminfo` 在只剩 PATH 的环境里跑，app_process 起不来，双卡卡槽识别和 netstats 分卡对账可能全部失效
- **位置**：`daemon/hnc_httpd/phone_usage_sim.go:72`、`daemon/hnc_httpd/phone_usage_sim.go:227-230`；`daemon/hnc_httpd/stats_calibration.go:713`、`daemon/hnc_httpd/stats_calibration.go:906-908`
- **触发 / 现象**：`/system/bin/content` 是 app_process 包装脚本（`exec app_process ... com.android.commands.content.Content`），Android 10+ 的 `AndroidRuntime::start` 在缺少 `ANDROID_ART_ROOT` / `ANDROID_I18N_ROOT` / `ANDROID_TZDATA_ROOT`（以及 `BOOTCLASSPATH`）时直接 LOG_FATAL。这里把子进程环境整个替换成 `PATH=...`，这些变量都没了，`content query` 很可能每次都失败，`subs` 为空。后果：① `puResolveSIM` 只能靠 `gsm.sim.operator.alpha`「只有一张卡有名字」兜底，双卡都插着的用户蜂窝流量全记到 `0|蜂窝(未知卡)`，`puAlertDecision` 只看卡 1/2，按卡套餐提醒永远不发；② `calMapSlot` 拿不到 subs，`NetstatsCellBySim` 全是 slot 0，`prefer` 模式与分卡漂移都用不上。`settings`（`cmd settings`）、`dumpsys`、`getprop`、`ip` 是原生程序，不受影响，所以问题只出在 `content`。
- **原因**：
  ```go
  cmd := hardenCmd(exec.CommandContext(ctx, path, args...))
  cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
  ...
  puRunCmd("content", "query", "--uri", "content://telephony/siminfo", ...)
  ```
  CHANGELOG v5.20 把「`content query content://telephony/siminfo` 在 ColorOS 16 的输出」列为「需真机验证」，自检也没有检查这一项。
- **还缺的证据**：真机上 `env -i PATH=/system/bin /system/bin/content query --uri content://telephony/siminfo` 是否报 `No ART directory specified with ANDROID_ART_ROOT`；或者看 `/api/phone_usage` 的 `sources.sim_source` 和双卡用户的 `by_sim` 是不是总落在 slot 0。
- **建议修复**：跑 `content` 时用 `append(os.Environ(), "PATH=...")` 继承 init 给的 ANDROID_* / BOOTCLASSPATH；或者改用原生的 `cmd`/`dumpsys isub` 拿卡槽信息。

### A5-004 [P3][确认] 套餐提醒先记「已发」再发送，`alert.Append` 失败后这一档本周期再也不会补发
- **位置**：`daemon/hnc_httpd/phone_usage.go:890-897`、`daemon/hnc_httpd/phone_usage.go:958-970`
- **触发 / 现象**：`run/alerts.jsonl` 暂时写不进（flock 超时、磁盘满、目录权限被改）时，`emitAlert` 返回错误，日志只打一行；但 `puAlertDecision` 已经把 `fired[key]`（越过 100% 时连 warn 档也一起）写好，随后 `saveStateLocked` 落盘，这张卡本周期的 80% / 100% 提醒就丢了。
- **原因**：
  ```go
  fired[key] = nowTs                       // puAlertDecision 里先标记
  ...
  if err := e.env.emitAlert(a); err != nil { log.Printf(...); continue }   // 失败不回滚
  ...
  if len(outs) > 0 { e.saveStateLocked(now) }
  ```
- **建议修复**：发送失败时从 `e.fired` 里删掉对应 key（over 档连同 warn 档），下一轮 5 分钟后重试。

