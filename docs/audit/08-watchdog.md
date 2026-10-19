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

