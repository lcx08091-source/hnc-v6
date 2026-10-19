# A11 审查记录：bin/ 其余 shell 脚本

- 基线版本：v5.33.0-rc2（versionCode 5330002）
- 审查员前缀：A11
- 范围：bin/ 下除以下文件外的全部脚本（含 bin/diag/diag.sh）：
  tc_manager.sh、iptables_manager.sh、apply_device_rule.sh、hnc_json、json_set.sh、json_set_batch.sh、
  hnc_lock.sh、hnc_common.sh、hnc_constants.sh、hnc_iface.sh、v6_sync.sh、watchdog.sh、
  hnc_offload_guard.sh、hnc_rollback.sh、hnc_runtime_sync.sh、hnc_proc.sh、hnc_compat.sh、hnc_clsact_sync.sh
- 运行环境：Android /system/bin/sh（mksh）+ toybox

## 已审文件
- bin/pair_gen.sh（无确认 bug；mksh 32 位算术下 `[ "$num" -ge 0 ]` 会丢弃约一半随机数，10 次重试失败概率约 1/1024，影响可忽略，不单列）
- bin/hotspot_autostart.sh
- bin/pitfall_lint.sh（无 bug；P2 规则只查 `\|`，未覆盖 `\?` `\+` 与 bin/diag/、bin/hnc_json，见 A11-004）
- bin/tc_state_snapshot.sh
- bin/diag.sh
- bin/diag/diag.sh

## Bug

### A11-001 [P1][确认] 热点加密方式回退链末尾是 open：带密码的方式全失败时静默开出无密码热点
- **位置**：`bin/hotspot_autostart.sh:231-232`（经 `bin/hnc_compat.sh:281-286,313-321` 的 `HNC_SOFTAP_SECS` 链）、`bin/hotspot_autostart.sh:259-268`（旧固定顺序）
- **触发 / 现象**：WebUI 的 `validPass` 只校验 UTF-8 字节长度 8-63，允许非 ASCII 密码（如 `密码密码`）；Android 13+ `SoftApConfiguration.Builder.setPassphrase` 对 wpa2 / wpa3_transition 要求 ASCII，直接抛 IllegalArgumentException；设备不支持 WPA3-SAE SoftAP 时 wpa3 也失败；循环继续到 `open` → `cmd wifi start-softap <ssid> open <pass>` 成功（多余的 pass 参数被忽略）→ 开出**无密码**热点，任何人可连入蹭流量 / 访问热点内网。开机时 WifiService 刚就绪、前几种方式瞬时失败而 open 恰好成功也是同一结局。
- **原因**：
  ```sh
  for sec in $HNC_SOFTAP_SECS; do   # 默认 "wpa2 wpa3_transition wpa3 open"
      r=$(cmd wifi start-softap "$ssid" "$sec" "$pass" -b any 2>&1)
  ...
  for SEC in wpa2 wpa3 wpa3_transition open; do      # hotspot_autostart.sh:259
  ```
  用户配置了密码却把 `open` 当成普通候选，没有"有密码时禁止降级为 open"的约束；加上 A11-002，日志里也看不出用的是 open。
- **建议修复**：AP_PASS 非空时从候选里剔除 `open`（只有用户明确要开放热点时才用 open）；全部失败就报错退出。

### A11-002 [P3][确认] HNC_SOFTAP_SEC_USED 在 `$(...)` 子 shell 里赋值，父 shell 永远拿不到，日志 / softap_method.json 不记实际加密方式
- **位置**：`bin/hotspot_autostart.sh:232,236,247,253`
- **触发 / 现象**：任何一次热点启动成功。`log "started via $M${HNC_SOFTAP_SEC_USED:+ (sec=...)}"` 永远不带 sec，`hnc_softap_record "$USED" 1 "sec=$HNC_SOFTAP_SEC_USED"` 永远写 `sec=`；A11-001 降级成 open 时无从察觉。已用 mksh R59 验证：`R=$(f)` 中 f 设置的变量在父 shell 为空。
- **原因**：`RESULT=$(hnc_softap_try "$M" "$AP_SSID" "$AP_PASS")`——命令替换在子进程执行，`hnc_softap_try` 里的 `HNC_SOFTAP_SEC_USED="$sec"` 不回传。
- **建议修复**：让 `hnc_softap_try` 把输出写到临时文件 / 变量而不是用命令替换调用，或者把 sec 作为输出的一行回传再解析。

### A11-003 [P2][确认] 未在 WebUI 设 SSID / 密码时，"回退到系统热点配置"是死代码，实际起的是 MyHotspot / 12345678
- **位置**：`bin/hotspot_autostart.sh:209-214`
- **触发 / 现象**：用户只打开"开机自启"、没填 SSID / 密码（`hotspot_save` 允许 pass 为空）。Android 8+ 的热点配置存在 WifiApConfigStore / SoftAp XML，`settings get global wifi_ap_ssid|wifi_ap_password` 返回 `null` → 回落到硬编码 `MyHotspot` / `12345678`：①用户原有的系统热点名 / 密码被替换，已保存的客户端连不上；②热点用公开的弱口令运行。
- **原因**：
  ```sh
  [ -z "$AP_SSID" ] && AP_SSID="$(get_setting wifi_ap_ssid)"
  [ -z "$AP_PASS" ] && AP_PASS="$(get_setting wifi_ap_password)"
  [ -z "$AP_SSID" ] && AP_SSID="MyHotspot"
  [ -z "$AP_PASS" ] && AP_PASS="12345678"
  ```
- **建议修复**：未配置 SSID / 密码时不要自建配置（拒绝启动并在 WebUI 提示，或改用不覆盖系统配置的方式），去掉硬编码弱口令。

### A11-004 [P2][确认] get_rule_num 用 BRE 的 `\?`，toybox grep 不认 → hotspot_delay 永远读不到，开机延迟恒为 60s
- **位置**：`bin/hotspot_autostart.sh:62`
- **触发 / 现象**：WebUI 把开机延迟设为 10 → rules.json 写 `"hotspot_delay":10`（数字，见 json_set.sh:57-62 不在字符串字段名单里）。设备上 toybox grep 走 bionic 的 Spencer BRE（与项目已知"BRE 不认 `\|`"同源：GNU 扩展 `\| \? \+` 一并不支持），`\?` 被当字面 `?`，模式要求文本里出现 `-?` → 永不匹配 → `DELAY=${DELAY:-60}`。用户设的延迟被忽略。
- **原因**：`grep -o "\"$1\"[[:space:]]*:[[:space:]]*-\?[0-9][0-9.]*" "$RULES"`
- **建议修复**：改用 `grep -oE "\"$1\"[[:space:]]*:[[:space:]]*-?[0-9][0-9.]*"`；pitfall_lint 的 P2 规则顺带覆盖 `\?` / `\+`。

### A11-005 [P3][确认] teardown_nat 在停止时重新探测上联口，上联变化后旧的 MASQUERADE / FORWARD 规则残留
- **位置**：`bin/hotspot_autostart.sh:127-136`（对照 106-126）
- **触发 / 现象**：开热点时上联是 rmnet_data2（setup_nat 挂规则），之后切 VPN（`ip route get 1.1.1.1` 变成 tun0）或换卡 / 换 APN，再点"停止热点" → teardown 按新 up 删规则，删不到旧规则；再次开启又按新 up 追加一套。iptables nat/filter 里累积残留规则直到重启。另外从系统设置 / 快捷开关关热点时根本不会 teardown。
- **原因**：`up=$(detect_up_iface)` 在 setup 和 teardown 各算一次，没有把 setup 时实际用的 ap/up 记到 run/ 下。
- **建议修复**：setup_nat 把 `ap`/`up` 写入 `run/hotspot_nat.state`，teardown 按记录删除；或用自建子链挂规则，teardown 时整链 flush。

### A11-006 [P3][确认] `grep -c … || echo 0` 在零匹配时得到 "0\n0"，tc_state.json 变成非法 JSON
- **位置**：`bin/tc_state_snapshot.sh:50-51,68-69`；同类：`bin/diag.sh:142`
- **触发 / 现象**：热点口上还没有任何 tc filter（新装、未限速设备）或没有 class 时，`grep -c` 输出 `0` 且退出码 1，`|| echo 0` 再追加一行 `0`，变量值为 `0<换行>0`，写出 `"filter_count": 0\n0,` → run/tc_state.json 非法，诊断包 / json_diag_bundle 里的快照无法解析。diag.sh 同理：rules.json 无 `mark_id` 时 detail 里带换行，`--json` 模式下 RESULTS 按行拆分会多出一个 name 为 `0 设备 / …`、status 为空的假检查项。本机已验证 `x=$(grep -c '^class ' empty || echo 0)` 得到 `0\n0`。
- **原因**：`class_count=$(grep -c '^class ' "$class_file" 2>/dev/null || echo 0)`
- **建议修复**：改成 `class_count=$(grep -c … 2>/dev/null); class_count=${class_count:-0}` 或 `|| true`（capability_probe.sh:341 已按此修过）。

### A11-007 [P3][确认] bin/diag/diag.sh 用管道后的 `$?` 判结果，fork 探针结果恒为 0、"无 AVC denied" 恒被打印
- **位置**：`bin/diag/diag.sh:74-75`、`bin/diag/diag.sh:87-88`
- **触发 / 现象**：①fork_probe 失败（被 SELinux / seccomp 拒绝，正是这一节要查的"关键"问题）时仍打印 `result: 0`；②dmesg 里有 AVC denied 并已列出 10 行，紧接着仍打印"(无 … AVC denied — 这是好事)"，自相矛盾，误导维护者。
- **原因**：
  ```sh
  "$HNC/bin/fork_probe" /system/bin/true 2>&1 | sed 's/^/    /'
  echo "    result: $?"          # sed 的退出码
  dmesg 2>/dev/null | grep -iE "avc.*denied" | tail -10
  [ $? -ne 0 ] || echo "  (无 … AVC denied — 这是好事)"   # tail 的退出码恒 0
  ```
- **建议修复**：先把输出存变量 / 临时文件，单独取命令退出码；AVC 一节按"过滤后输出是否为空"判断。

