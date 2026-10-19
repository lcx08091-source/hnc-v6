# A8 审查记录：hnc_watchdog 与 dpid 支撑包

基线：v5.33.0-rc2

## 范围

- `src/dpid/cmd/hnc_watchdog/` 下全部非测试文件：actionstats、app_qos、budget、duties、m4_owner、m5、main、native、offload_sched、online_minutes、power
- `src/dpid/` 下：devscan、neigh、nlroute（netlink 解析）、procfind、devname（含 oui_table.txt 加载）、ifacehint、clockhwm、tzlocal、activity、hostname

## 已审文件

## Bug

### A8-001 [P1][确认] 规则健康检查把「链不存在」(iptables rc=1)当成「锁忙」，HNC_MARK / HNC_RESTORE 被删后永远不 full_restore
- **位置**：`src/dpid/cmd/hnc_watchdog/native.go:258-277`
- **触发 / 现象**：任何让 mangle 表里 `HNC_MARK` 或 `HNC_RESTORE` 链消失的事件（别的模块 / 应用执行 `iptables -t mangle -F; -X`、netd 重建表等），只要热点口的 htb 根还在，`iptables -w 2 -t mangle -S HNC_MARK` 返回 rc=1。代码只把 rc=2 当「链真丢」，rc=1 落进 `rc != 0 → natHealthBusy`，主循环按「临时故障，跳过本轮」处理，且 Busy 分支不打日志、不计数。结果是规则一直不恢复（设备打标、按设备限速全部失效），看门狗也不会报任何异常。
- **原因**：
  ```go
  out, rc, _ := execCommandFn("iptables", "-w", "2", "-t", "mangle", "-S", "HNC_MARK")
  if rc == 2 { return natHealthLost }
  if rc != 0 { return natHealthBusy }
  ```
  在本机实测 iptables v1.8.10（legacy 与 nft 两种后端，与 AOSP external/iptables 同为 1.8.x，`iptables_main` 都是 `exit(!ret)`）：链不存在时输出 `iptables: No chain/target/match by that name.`，**rc=1**；拿不到锁（`-w 1`）时 **rc=4**；空链 rc=0。iptables 不会对缺链返回 2（2 是 PARAMETER_PROBLEM，参数写错时才出现）。`native_test.go:233` 的测试桩伪造了 `"Bad chain name", rc=2`，所以测试是绿的。
- **建议修复**：按实际退出码判：rc=4（RESOURCE_PROBLEM，拿不到锁）→ Busy；rc=1 且输出含 `No chain` → Lost；其余非 0 → Unknown。测试桩改成真实的 rc / 输出。

### A8-002 [P2][确认] 设备发现的去抖 / 离线 / pending / 「立刻扫一次」都按墙钟计时，墙钟回拨后 devices.json 长时间不更新
- **位置**：`src/dpid/cmd/hnc_watchdog/m4_owner.go:249`、`:319-331`、`:445`；`src/dpid/devscan/devscan.go:287`、`:366`、`:386`
- **触发 / 现象**：热点开着时系统时间往回跳 Δ（手动改时间、NITZ/NTP 纠偏、开机 RTC 偏快后对时）。之后：
  1. `m4ShouldWrite` 里 `nowMs-lastWriteMs` 变成负数，一直小于 200，于是**去抖写在 Δ 时间内全部被挡住**，新设备不出现、走掉的设备不消失（只有强制刷新和停写者时的补写还能写）；
  2. `refreshDue` 的 `lastRefreshM` 是回拨前的墙钟，新的 `run/devices.refresh` mtime 都比它小，`device_detect.sh scan` 在 Δ 内一直等不到回执（WebUI「刷新」失效）；
  3. `EvictOffline` 用 `now.Sub(time.Unix(LastSeen,0))`，回拨后差值为负，设备在 Δ 内不会离线；往前跳超过 90 秒则所有设备同时被判离线、一起被踢掉；
  4. `PendingDue` 的 `now.Sub(time.Unix(pendingSince,0)) < 1s` 在 Δ 内恒成立，新设备的名字一直停在 MAC 尾号。
- **原因**：`monoMs := func() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }`，名字叫 mono，实际取的是墙钟（`UnixNano` 不带单调读数）；devscan 把 `LastSeen` / `pendingSince` / `lastResolve` 存成 Unix 秒，再用 `time.Unix(x,0)` 参与 `Sub`，同样只有墙钟。
- **建议修复**：去抖与 refresh 用进程内单调时钟（保存 `time.Time` 用 `Sub`，或用启动时刻加 `time.Since`）；devscan 内部计时字段改成带单调读数的 `time.Time`，`LastSeen` 只在渲染 JSON 时转成 Unix 秒；refresh 的 mtime 比较改成「mtime 变了」（`!=`），不要用「比上次大」。

### A8-003 [P2][确认] `run/m4_go_write.log` 每写一次 devices.json 追加一行，没有任何轮转或清理，持续增长
- **位置**：`src/dpid/cmd/hnc_watchdog/m4_owner.go:492`（`appendLine(m4GoWriteLog, ...)`）
- **触发 / 现象**：热点开着时，每个可用的邻居事件都会让 `applyOnlineLocked` 返回 true（`LastSeen` 每次都变），所以每个事件都会写一次 devices.json，也就追加一行（约 55 字节）。按 10 次/分钟估算，每天约 0.8 MB，长期开热点一年几百 MB，都落在 `/data/local/hnc/run`。`log_rotate.sh` 只处理 `logs/*.log`；post-fs-data 只删 `run/*.pid` 和一批点名的旧文件，不包括这个文件；`cleanup.sh` 也不删它。全仓库只有这一处写，没有任何地方截断它。
- **原因**：`_ = appendLine(m4GoWriteLog, time.Now().Format(...)+": "+out)`，并且 `m4GoWriteLog = runDir + "/m4_go_write.log"` 不在任何轮转范围内。
- **建议修复**：把文件移到 `logs/` 下，纳入 log_rotate；或者写入前检查大小，超过上限就截断或轮转（可以参考 `rotateLogIfBig`）。

### A8-004 [P2][疑似] 邻居事件订阅读出一次错（如 ENOBUFS）后，订阅 goroutine 静默退出，此后直到写者重启都只靠 30 秒全量兜底
- **位置**：`src/dpid/cmd/hnc_watchdog/m4_owner.go:255-268`；`src/dpid/neigh/neigh.go:258-266`
- **触发 / 现象**：订阅的是所有网卡、所有地址族的 RTNLGRP_NEIGH。写者主循环在 `writeOut→runStatsAll`（最长 3 秒）等处阻塞时，读 goroutine 把 64 格的 `events` 塞满后，会在 `events <- es` 上等待，内核 socket 缓冲随之溢出，`recvfrom` 返回 ENOBUFS。另外，`ParseMsgs` 对任何一条报文报错也会让 `Read()` 返回 err。读 goroutine 遇到 err 就直接 `return` 并关掉 socket，既不记日志也不重订阅。从此新设备上线、FAILED 下线都要等 30 秒一次的全量 dump 才发现，一直持续到热点关了再开、写者被重建为止。
- **原因**：
  ```go
  es, err := src.Read()
  if err != nil { return }
  ```
  `Sub.Read` 没有区分 ENOBUFS（可以恢复：继续读，再补一次全量）和真正的致命错误。
- **建议修复**：遇到 ENOBUFS 时记日志、通知主循环立刻做一次 FullSync，然后继续读；遇到其他错误时记日志，并在退避后重新 Subscribe。
- **缺的证据**：没有真机上 ENOBUFS 的日志（当前代码在这里也不记日志）。突发量需要在一次阻塞内超过约 200 条通知（rmem_default 大约 208 KB），常见场景下不容易达到。

