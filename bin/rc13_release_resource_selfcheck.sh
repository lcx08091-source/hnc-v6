#!/system/bin/sh
# HNC v5.3.0-rc13 · release-resource / DPI guard selfcheck

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LOGS="$HNC_DIR/logs"
HTTP="http://127.0.0.1:8444"

ok=0
warn=0
fail=0

say() { printf '%s\n' "$*"; }
pass() { ok=$((ok+1)); say "[OK] $*"; }
notice() { warn=$((warn+1)); say "[WARN] $*"; }
bad() { fail=$((fail+1)); say "[FAIL] $*"; }

pid_alive() {
    p=$(cat "$1" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

json_field() {
    key="$1" file="$2"
    sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" 2>/dev/null | head -1
}

say "=== HNC rc13 release-resource selfcheck ==="
say "time=$(date '+%F %T' 2>/dev/null)"
say "hnc_dir=$HNC_DIR"
say

# Process checks
if pid_alive "$RUN/httpd.pid"; then pass "hnc_httpd pid alive ($(cat "$RUN/httpd.pid"))"; else bad "hnc_httpd not alive (run cleanup.sh restart or tap 重新拉起服务)"; fi
if pid_alive "$RUN/watchdog.pid"; then pass "watchdog pid alive ($(cat "$RUN/watchdog.pid"))"; else notice "watchdog pid not alive"; fi
if pid_alive "$RUN/hotspotd.pid"; then pass "hotspotd pid alive ($(cat "$RUN/hotspotd.pid"))"; else notice "hotspotd pid not alive (may be OK if hotspot is off)"; fi
if pid_alive "$RUN/dpid.pid"; then pass "dpid launcher pid alive ($(cat "$RUN/dpid.pid"))"; else notice "dpid launcher not alive"; fi
if pid_alive "$RUN/dpid.child.pid"; then pass "dpid capture child alive ($(cat "$RUN/dpid.child.pid"))"; else notice "dpid child not alive yet (guard may be waiting for iface)"; fi

say
# API checks
if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 3 "$HTTP/api/health" >/dev/null 2>&1; then pass "/api/health reachable"; else bad "/api/health not reachable"; fi
    if curl -fsS --max-time 5 "$HTTP/api/live" >/dev/null 2>&1; then pass "/api/live reachable"; else notice "/api/live not reachable"; fi
    if curl -fsS --max-time 5 "$HTTP/api/devices" >/dev/null 2>&1; then pass "/api/devices reachable"; else notice "/api/devices not reachable"; fi
else
    notice "curl not found; skip API checks"
fi

say
# DPI checks
if [ -f "$RUN/dpi_state.json" ]; then
    mode=$(json_field mode "$RUN/dpi_state.json")
    iface=$(json_field interface "$RUN/dpi_state.json")
    reason=$(json_field blind_reason "$RUN/dpi_state.json")
    say "dpi_state.mode=${mode:-unknown}"
    say "dpi_state.interface=${iface:-unknown}"
    [ -n "$reason" ] && say "dpi_state.reason=$reason"
    case "$mode" in
        ok) pass "DPI capture mode OK" ;;
        blind)
            case "$reason" in
                *"waiting for hotspot interface"*|*"network is down"*) notice "DPI guard waiting/rebinding; this should self-heal after hotspot iface is UP" ;;
                *) notice "DPI blind mode" ;;
            esac
            ;;
        disabled) notice "DPI disabled by config" ;;
        crash_loop) bad "DPI crash_loop; inspect $LOGS/dpid.log and remove $RUN/dpid.crashflag only after fixing cause" ;;
        *) notice "DPI mode unknown: ${mode:-missing}" ;;
    esac
else
    notice "dpi_state.json missing"
fi

iface_hint=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
[ -z "$iface_hint" ] && iface_hint=$(json_field interface "$RUN/dpi_state.json")
[ -z "$iface_hint" ] && iface_hint=wlan2
if [ -e "/sys/class/net/$iface_hint" ]; then
    line=$(ip -o link show "$iface_hint" 2>/dev/null | head -1)
    say "iface_line=$line"
    if echo "$line" | grep -q '<[^>]*UP[^>]*>'; then pass "$iface_hint is UP"; else notice "$iface_hint exists but not IFF_UP"; fi
else
    notice "$iface_hint does not exist"
fi

say
say "summary: ok=$ok warn=$warn fail=$fail"
[ "$fail" -gt 0 ] && exit 1
exit 0
