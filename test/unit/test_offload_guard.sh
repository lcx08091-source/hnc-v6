#!/system/bin/sh
# v5.18: hnc_offload_guard.sh —— tether offload 旁路自动兜底(auto/on/off + 迟滞)

GSCRIPT="$HNC_REPO_ROOT/bin/hnc_offload_guard.sh"

gseed() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs" "$HNC_TEST_DIR/bin" \
             "$HNC_TEST_DIR/sysnet/wlan2" "$HNC_TEST_DIR/stub"
    rm -f "$HNC_TEST_DIR/run/offload_guard"* 2>/dev/null
    echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
    _rules=$1
    [ -n "$_rules" ] || _rules='{"devices":{"aa:bb:cc:00:00:01":{"limit_enabled":true}}}'
    printf '%s\n' "$_rules" > "$HNC_TEST_DIR/data/rules.json"
    echo IDLE > "$HNC_TEST_DIR/check_state"
    : > "$HNC_TEST_DIR/ipc.log"
    cat > "$HNC_TEST_DIR/bin/hnc_ipc" <<'STUB'
#!/bin/sh
echo "$*" >> "$HNC_DIR/ipc.log"
case "$1" in
    OFFLOAD_DISABLE_GLOBAL|OFFLOAD_RESTORE_GLOBAL) echo "OK:OK" ;;
    *) echo OK ;;
esac
exit 0
STUB
    chmod +x "$HNC_TEST_DIR/bin/hnc_ipc"
    # tc 桩: 默认看不到 mirred(pref 1 空闲)
    cat > "$HNC_TEST_DIR/stub/tc" <<'STUB'
#!/bin/sh
[ -f "$HNC_DIR/tc_show" ] && cat "$HNC_DIR/tc_show"
exit 0
STUB
    chmod +x "$HNC_TEST_DIR/stub/tc"
}
grun() {
    HNC_TEST_MODE=1 HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" \
    HNC_GUARD_CHECK_CMD="cat $HNC_TEST_DIR/check_state" PATH="$HNC_TEST_DIR/stub:$PATH" \
        sh "$GSCRIPT" "$@" 2>/dev/null
}
gstatus() { grep -o "\"$1\":[^,}]*" "$HNC_TEST_DIR/run/offload_guard.json" 2>/dev/null | head -n1 | sed 's/^[^:]*://; s/"//g'; }

test_start "offload guard: mode resolution (default auto, legacy enabled → on, explicit mode wins)"
gseed '{"devices":{}}'
m1=$(grun mode)
gseed '{"clsact_bpf_enabled":true}'
m2=$(grun mode)
gseed '{"clsact_bpf_enabled":true,"clsact_bpf_mode":"off"}'
m3=$(grun mode)
gseed '{"clsact_bpf_mode":"bogus"}'
m4=$(grun mode)
[ "$m1" = auto ] && [ "$m2" = on ] && [ "$m3" = off ] && [ "$m4" = auto ] && test_pass || test_fail "m=$m1/$m2/$m3/$m4"

test_start "offload guard: auto + IDLE → no intervention, status written"
gseed
out=$(grun apply | tail -n1)
[ ! -s "$HNC_TEST_DIR/ipc.log" ] && [ "$(gstatus fallback_active)" = false ] && [ "$(gstatus mode)" = auto ] \
  && [ "$(gstatus offload_state)" = IDLE ] && echo "$out" | grep -q '"last_check":[1-9]' && test_pass || test_fail "out=$out ipc=$(cat "$HNC_TEST_DIR/ipc.log")"

test_start "offload guard: auto + ACTIVE → force slow path, re-asserted while suppressed"
gseed
echo ACTIVE > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null
fb1=$(gstatus fallback_active); since=$(gstatus since); sp=$(gstatus slowpath)
echo CAPABLE > "$HNC_TEST_DIR/check_state"   # 被我们压下去之后的样子
grun apply >/dev/null
n=$(grep -c OFFLOAD_DISABLE_GLOBAL "$HNC_TEST_DIR/ipc.log")
[ "$fb1" = true ] && [ "$sp" = ok ] && [ "$since" -gt 0 ] 2>/dev/null && [ "$n" = 2 ] \
  && [ "$(gstatus fallback_active)" = true ] && [ "$(gstatus since)" = "$since" ] \
  && ! grep -q RESTORE "$HNC_TEST_DIR/ipc.log" && test_pass || test_fail "fb1=$fb1 sp=$sp since=$since n=$n"

test_start "offload guard: hysteresis — restore only after 3 calm ticks (hotspot gone), re-notify limited devices"
gseed
echo ACTIVE > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null
rm -rf "$HNC_TEST_DIR/sysnet/wlan2"
grun apply >/dev/null; r1=$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")
grun apply >/dev/null; r2=$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")
grun apply >/dev/null; r3=$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")
[ "$r1" = 0 ] && [ "$r2" = 0 ] && [ "$r3" = 1 ] && [ "$(gstatus fallback_active)" = false ] \
  && grep -q "OFFLOAD_NOTIFY_LIMIT aa:bb:cc:00:00:01 1" "$HNC_TEST_DIR/ipc.log" && test_pass || test_fail "r=$r1/$r2/$r3"

test_start "offload guard: calm counter resets when hotspot comes back (no flapping)"
gseed
echo ACTIVE > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null
echo NOMAP > "$HNC_TEST_DIR/check_state"; grun apply >/dev/null; grun apply >/dev/null
echo IDLE > "$HNC_TEST_DIR/check_state";  grun apply >/dev/null
echo NOMAP > "$HNC_TEST_DIR/check_state"; grun apply >/dev/null; grun apply >/dev/null
[ "$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")" = 0 ] && [ "$(gstatus fallback_active)" = true ] && test_pass || test_fail "$(cat "$HNC_TEST_DIR/ipc.log")"

test_start "offload guard: switching to off restores what auto applied"
gseed
echo ACTIVE > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null
printf '{"clsact_bpf_mode":"off"}\n' > "$HNC_TEST_DIR/data/rules.json"
grun apply >/dev/null
[ "$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")" = 1 ] && [ "$(gstatus mode)" = off ] && [ "$(gstatus fallback_active)" = false ] \
  && grun apply >/dev/null && [ "$(grep -c RESTORE "$HNC_TEST_DIR/ipc.log")" = 1 ] && test_pass || test_fail "$(cat "$HNC_TEST_DIR/ipc.log")"

test_start "offload guard: on → always force slow path even when offload idle"
gseed '{"clsact_bpf_mode":"on"}'
grun apply >/dev/null
[ "$(grep -c OFFLOAD_DISABLE_GLOBAL "$HNC_TEST_DIR/ipc.log")" = 1 ] && [ "$(gstatus fallback_active)" = true ] \
  && [ "$(gstatus clsact)" = unavailable ] && test_pass || test_fail "$(cat "$HNC_TEST_DIR/run/offload_guard.json")"

test_start "offload guard: degrades silently without hnc_ipc / with NOMAP"
gseed
rm -f "$HNC_TEST_DIR/bin/hnc_ipc"
echo ACTIVE > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null; rc=$?
sp=$(gstatus slowpath)
gseed
echo NOMAP > "$HNC_TEST_DIR/check_state"
grun apply >/dev/null
[ "$rc" = 0 ] && [ "$sp" = unavailable ] && [ ! -s "$HNC_TEST_DIR/ipc.log" ] && [ "$(gstatus fallback_active)" = false ] \
  && test_pass || test_fail "rc=$rc sp=$sp"

test_start "offload guard: clsact_wanted gate (mode + pref1 mirred)"
gseed '{"clsact_bpf_mode":"on"}'
: > "$HNC_TEST_DIR/bin/hnc_clsact.o"
printf '#!/bin/sh\necho "{\\"ok\\":false,\\"bpf_filter\\":false}"\n' > "$HNC_TEST_DIR/bin/hnc_clsact_ctl"; chmod +x "$HNC_TEST_DIR/bin/hnc_clsact_ctl"
grun clsact_wanted wlan2; w_on=$?
echo "filter protocol all pref 1 matchall chain 0 action order 1: mirred (Egress Redirect to device ifb0) stolen" > "$HNC_TEST_DIR/tc_show"
grun clsact_wanted wlan2; w_mirred=$?
rm -f "$HNC_TEST_DIR/tc_show"
printf '{"clsact_bpf_mode":"auto"}\n' > "$HNC_TEST_DIR/data/rules.json"
grun clsact_wanted wlan2; w_auto=$?
printf '{"clsact_bpf_mode":"off"}\n' > "$HNC_TEST_DIR/data/rules.json"
grun clsact_wanted wlan2; w_off=$?
[ "$w_on" = 0 ] && [ "$w_mirred" = 1 ] && [ "$w_auto" = 1 ] && [ "$w_off" = 1 ] && test_pass || test_fail "on=$w_on mirred=$w_mirred auto=$w_auto off=$w_off"

test_start "offload guard: on + pref1 held by mirred → clsact skipped, uninstall never called"
gseed '{"clsact_bpf_mode":"on"}'
: > "$HNC_TEST_DIR/bin/hnc_clsact.o"
printf '#!/bin/sh\necho "$*" >> "$HNC_DIR/ctl.log"\necho "{\\"ok\\":false,\\"bpf_filter\\":false}"\n' > "$HNC_TEST_DIR/bin/hnc_clsact_ctl"; chmod +x "$HNC_TEST_DIR/bin/hnc_clsact_ctl"
echo "mirred (Egress Redirect to device ifb0) stolen" > "$HNC_TEST_DIR/tc_show"
grun apply >/dev/null
printf '{"clsact_bpf_mode":"off"}\n' > "$HNC_TEST_DIR/data/rules.json"
grun apply >/dev/null
! grep -q "install\|uninstall" "$HNC_TEST_DIR/ctl.log" 2>/dev/null && grep -q 'skipped_pref1_mirred' "$HNC_TEST_DIR/logs/offload_guard.log" \
  && test_pass || test_fail "ctl=$(cat "$HNC_TEST_DIR/ctl.log" 2>/dev/null)"

# ── v5.29 T2(M3): owner=watchdog 时 shell 常驻循环让位给 Go 看门狗 ──

test_start "offload guard: owner=watchdog 时 daemon 分支直接退出(不起循环)"
gseed '{"clsact_bpf_mode":"auto"}'
echo watchdog > "$HNC_TEST_DIR/run/offload_guard.owner"
rm -f "$HNC_TEST_DIR/run/offload_guard.pid"
timeout 10 env HNC_TEST_MODE=1 HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" \
    HNC_GUARD_CHECK_CMD="cat $HNC_TEST_DIR/check_state" PATH="$HNC_TEST_DIR/stub:$PATH" \
    sh "$GSCRIPT" daemon; rc=$?
[ $rc -eq 0 ] && [ ! -f "$HNC_TEST_DIR/run/offload_guard.pid" ] && test_pass || test_fail "rc=$rc pidfile_created=$([ -f "$HNC_TEST_DIR/run/offload_guard.pid" ] && echo yes || echo no)"

test_start "offload guard: 无 owner 时 daemon 正常路径(写 pidfile; 测试模式下 tick 后由 ensure 检查)"
gseed '{"clsact_bpf_mode":"auto"}'
rm -f "$HNC_TEST_DIR/run/offload_guard.owner" "$HNC_TEST_DIR/run/offload_guard.pid"
HNC_TEST_MODE=1 HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" \
    HNC_GUARD_CHECK_CMD="cat $HNC_TEST_DIR/check_state" PATH="$HNC_TEST_DIR/stub:$PATH" \
    timeout 10 sh "$GSCRIPT" plan >/dev/null 2>&1
rc=$?
[ $rc -eq 0 ] && test_pass || test_fail "plan rc=$rc(对照: Go 调度也走同一 plan 动作)"

test_start "offload guard: owner=watchdog 时 apply 不把 shell 循环拉回来(无 owner 时会)"
# 测试模式下 ensure_daemon 从不真起进程, 只看 pidfile 的话新旧代码都通过;
# 用 HNC_GUARD_SPAWN_LOG 记「这里会起守护」, 并先跑无 owner 的对照组。
gseed '{"clsact_bpf_mode":"auto"}'
rm -f "$HNC_TEST_DIR/run/offload_guard.owner" "$HNC_TEST_DIR/spawn.log"
HNC_GUARD_SPAWN_LOG="$HNC_TEST_DIR/spawn.log" grun apply >/dev/null 2>&1
_ctl=$(cat "$HNC_TEST_DIR/spawn.log" 2>/dev/null)
echo watchdog > "$HNC_TEST_DIR/run/offload_guard.owner"
rm -f "$HNC_TEST_DIR/spawn.log"
HNC_GUARD_SPAWN_LOG="$HNC_TEST_DIR/spawn.log" grun apply >/dev/null 2>&1
[ "$_ctl" = spawn ] && [ ! -f "$HNC_TEST_DIR/spawn.log" ] \
  && test_pass || test_fail "对照(无 owner)=$_ctl; owner=watchdog 时 spawn.log=$(cat "$HNC_TEST_DIR/spawn.log" 2>/dev/null)"
