# A10 Shell 核心脚本审查记录

- 审查员：A10（子审查员）
- 基线版本：v5.33.0-rc2
- 范围：post-fs-data.sh、service.sh、customize.sh、uninstall.sh、META-INF/com/google/android/update-binary、bin/tc_manager.sh、bin/iptables_manager.sh、bin/apply_device_rule.sh、bin/hnc_json、bin/json_set.sh、bin/json_set_batch.sh、bin/hnc_lock.sh、bin/hnc_common.sh、bin/hnc_constants.sh、bin/hnc_iface.sh、bin/v6_sync.sh、bin/watchdog.sh、bin/hnc_offload_guard.sh、bin/hnc_rollback.sh、bin/hnc_runtime_sync.sh、bin/hnc_proc.sh、bin/hnc_compat.sh、bin/hnc_clsact_sync.sh
- 原则：只记真 bug，只记录不改代码。

## 已审文件

- bin/hnc_constants.sh：全文，无问题
- bin/hnc_common.sh：全文，无问题（函数基本只有 ahnc_migration.sh 和单测在用）
- bin/hnc_lock.sh：全文（stale 回收也有「判断 → 删除」非原子的问题，但有 gate 挡着，触发窗口比 hnc_json 小得多，不单独记）
- bin/hnc_json：全文 → A10-001、A10-002
- bin/json_set.sh：全文，无问题
- bin/json_set_batch.sh：全文，无问题
- bin/apply_device_rule.sh：全文 → A10-003（涉及 bl_del）
- bin/iptables_manager.sh：全文 → A10-003
- post-fs-data.sh：全文，无问题

## Bug

### A10-001 [P3][确认] hnc_json set-top 每写一次就在文件末尾多留一个空行，文件只增不减
- **位置**：`bin/hnc_json:402-437`（set_top_inner）
- **触发 / 现象**：任何走 set_top 的写（`json_set.sh top …`、`name_set`、`tpl_set`、`bl_add/bl_del`，Go 侧所有顶层开关都经由它）。在 scratchpad 实测：`{…}\n` 连写 3 次后文件尾变成 `}\n\n\n\n`，每次 +1 字节。rules.json / device_names.json 会随设置次数无限累积尾部空行，awk 逐行拼接 `s=s $0 "\n"` 的开销也随之增长。
- **原因**：set_device_inner / del_object_key_inner 都先做了 `sub(/\n$/, "", s)` 再 print，唯独 set_top_inner 没去掉末尾换行：
  ```
  BEGIN{ s="" }
  { s=s $0 "\n" }
  END{ n=length(s); i=skip_ws(1) ...
       if(k==key){ print substr(s,1,val_start-1) lit substr(s,ve+1); exit 0 }   # substr 已带 "\n"，print 再加 ORS
  ```
- **建议修复**：END 开头加 `sub(/\n+$/, "", s)`（顺带把已累积的空行收掉），与另外两个 inner 保持一致。

### A10-002 [P2][确认] hnc_json 的 json.lock 回收不是原子的，等锁者可能删掉别人刚建好的锁，导致两个写者同时进临界区、丢一次写
- **位置**：`bin/hnc_json:55-94`、`bin/hnc_json:100-103`
- **触发 / 现象**：
  1. 等锁超过 20 轮（约 2 秒，httpd 连发多个 json_set、watchdog/apply_device_rule 同时写时会出现）的等待者 W，恰好在新持锁者 H 执行 `mkdir` 之后、`echo $$ > pid` 之前检查到「没有 pid 文件」，就 `rm -rf` 掉 H 的锁目录；W 下一轮 mkdir 成功，H 写 pid 失败（`|| true` 吞掉）后照常往下写。两者都基于同一份旧文件生成候选，后 mv 的覆盖先 mv 的，一次设置被静默丢弃。
  2. 两个等待者同时回收同一把死锁：W1 `rm -rf` 后重新 mkdir 成功，W2 在 W1 mkdir 之前读到旧的死 pid，之后执行 `rm -rf` 把 W1 的新锁删掉。
  3. `_release_locks` 不核对锁目录里的 pid 就 `rm -rf "$LOCKDIR"`：本进程的锁若因 ts≥30s 被别人回收并重新持有，退出时会把别人的锁删掉。
- **原因**：
  ```
  if [ "$i" -gt 20 ] && [ ! -f "$_ld/pid" ]; then
    rm -rf "$_ld" 2>/dev/null || true
  ...
  lp="$(cat "$_rd/pid" ...)"; if [ -n "$lp" ] && ! kill -0 "$lp"; then rm -rf "$_rd"
  ...
  [ "$_LOCK_HELD" = "1" ] && rm -rf "$LOCKDIR"
  ```
  「判断 → 删除」之间没有任何原子性保证，删除的对象可能已经换了主人。
- **建议修复**：回收时先 `mv "$_ld" "$_ld.stale.$$"`（rename 是原子的），再核对改名后目录里的 pid/ts 是否就是刚才判定为陈旧的那一份，不是就放弃；「缺 pid」分支改为按锁目录 mtime 超过数秒才回收（和 hnc_lock.sh 的做法一致）；释放锁前核对 pid 是否为 `$$`。

### A10-003 [P1][确认] 拉黑时加的按 IP 双向 DROP 不记录 IP；设备离线后解除拉黑只删 MAC 规则，旧 IP 的 DROP 一直留着（本机重连或别的设备分到这个 IP 都会断网）
- **位置**：`bin/iptables_manager.sh:403-408`、`bin/iptables_manager.sh:431-434`、`bin/apply_device_rule.sh:513-524`
- **触发 / 现象**：设备 A（IP .50）在线时被拉黑，HNC_CTRL 里加了 `-s .50 -j DROP`、`-d .50 -j DROP`。A 被拉黑后上不了网，通常会断开；Go 设备扫描 90 秒未活跃就把它从 devices.json 剔除（`src/dpid/devscan/devscan.go:361`）。之后用户解除拉黑：`bl_del` 的 `get_ip` 取不到 IP，`get_rule_ip` 只有限过速的设备才有，于是调用 `blacklist_remove "" mac`，只删 MAC 规则，两条 IP DROP 残留。A 重连时 DHCP 多半还给它 .50，A 解除拉黑后仍然完全断网；或者别的设备分到 .50，整机被静默封掉（UI 上不在黑名单里）。残留会一直存在，直到下次热点重建或重启时 init flush HNC_CTRL。restore 路径只按 MAC 重加黑名单（`tc_manager.sh:2430` 传空 IP），所以这类 IP 规则只会来自运行期的 bl_add，也没有任何 GC。
- **原因**：
  ```
  # blacklist_add
  if [ -n "$ip" ]; then ... $IPT -t filter -A HNC_CTRL -s "$ip" -j DROP; $IPT ... -d "$ip" -j DROP; fi
  # blacklist_remove
  if [ -n "$ip" ]; then ipt_del_all ... -s "$ip" -j DROP; ipt_del_all ... -d "$ip" -j DROP; fi
  ```
  删除时用的 IP 是解除拉黑那一刻现查的，而不是加规则时用的那个；查不到就整段跳过。
- **建议修复**：blacklist_remove 改成扫描 `iptables -S HNC_CTRL`，把与该 MAC 相关的 IP 规则都删掉（加规则时可以给 IP 规则带上 `-m comment --comment hnc-bl:<mac>`，或把 IP 记进 rules.json）；更简单的办法是黑名单只用 MAC 规则（restore 路径本来就只按 MAC），去掉按 IP 的 DROP。

