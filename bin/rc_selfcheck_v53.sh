#!/system/bin/sh
# HNC v5.3.0-rc5 · minimal runtime self-check for real devices.
# Read-only except writing a report under /data/local/hnc/run.

set +e
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/product/bin:/data/adb/magisk:/data/adb/ksu/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
REPORT="$RUN/rc_selfcheck_v53.latest"
HTTPD="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
MODULE_PROP1="/data/adb/modules/hotspot_network_control/module.prop"
MODULE_PROP2="$HNC_DIR/module.prop"
CURL=${CURL:-curl}
TC_BIN=${TC_BIN:-}
[ -n "$TC_BIN" ] || for c in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do [ -x "$c" ] && { TC_BIN="$c"; break; }; done
[ -n "$TC_BIN" ] || TC_BIN=$(command -v tc 2>/dev/null || echo tc)
mkdir -p "$RUN" 2>/dev/null || true

section(){ echo; echo "===== $* ====="; }
json_get_string(){ sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1; }
json_get_bool(){ sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$1" 2>/dev/null | head -1; }

{
    echo "HNC v5.3 runtime self-check · rc5"
    echo "time=$(date '+%F %T' 2>/dev/null)"
    echo "hnc_dir=$HNC_DIR"

    section "module.prop"
    if [ -f "$MODULE_PROP1" ]; then cat "$MODULE_PROP1"; elif [ -f "$MODULE_PROP2" ]; then cat "$MODULE_PROP2"; else echo "module.prop not found"; fi

    section "hnc_httpd binary/version"
    if [ -x "$HTTPD" ]; then
        "$HTTPD" -version 2>&1 || true
        if command -v strings >/dev/null 2>&1; then
            strings "$HTTPD" 2>/dev/null | grep -E '^v5\.3\.0-rc[0-9]+$|/api/sqm|apiSQMStatus|actionSQMSet' | sort -u
        else
            echo "strings not found; skipped embedded symbol check"
        fi
    else
        echo "hnc_httpd not executable: $HTTPD"
    fi

    section "hnc_httpd process"
    ps -A 2>/dev/null | grep '[h]nc_httpd' || ps 2>/dev/null | grep '[h]nc_httpd' || echo "hnc_httpd process not found"

    section "/api/sqm"
    API_TMP="$RUN/.rc_selfcheck_api_sqm.$$"
    if command -v "$CURL" >/dev/null 2>&1; then
        "$CURL" -s --max-time 3 http://127.0.0.1:8444/api/sqm > "$API_TMP" 2>&1
        cat "$API_TMP"
    else
        echo "curl not found"
        : > "$API_TMP"
    fi

    IFACE=$(json_get_string "$API_TMP" iface)
    ACTIVE=$(json_get_bool "$API_TMP" active)
    AVAIL=$(json_get_bool "$API_TMP" available)
    FQC=$(json_get_bool "$API_TMP" tc_fq_codel_supported)
    CAKE=$(json_get_bool "$API_TMP" tc_cake_supported)
    REC=$(json_get_string "$API_TMP" recommended_mode)
    [ -n "$IFACE" ] || IFACE=$(cat "$RUN/hotspot_iface" "$RUN/iface" 2>/dev/null | head -1)

    section "summary"
    echo "active=${ACTIVE:-unknown} available=${AVAIL:-unknown} iface=${IFACE:-unknown} fq_codel=${FQC:-unknown} cake=${CAKE:-unknown} recommended=${REC:-unknown}"
    if [ "$AVAIL" = "true" ] && [ -n "$REC" ]; then echo "[OK] /api/sqm reachable"; else echo "[WARN] /api/sqm unavailable or incomplete"; fi

    section "qdisc"
    if [ -n "$IFACE" ]; then
        "$TC_BIN" qdisc show dev "$IFACE" 2>&1
    else
        "$TC_BIN" qdisc show 2>&1 | head -120
    fi

    section "netem residue hint"
    if [ -n "$IFACE" ]; then
        NETEM_LINES=$($TC_BIN qdisc show dev "$IFACE" 2>/dev/null | grep ' netem ')
    else
        NETEM_LINES=$($TC_BIN qdisc show 2>/dev/null | grep ' netem ')
    fi
    if [ -n "$NETEM_LINES" ]; then
        echo "$NETEM_LINES"
        echo "[WARN] netem qdisc exists. If you are not intentionally testing delay/loss, clear the affected device rule or run hnc_cleanup_test_rules_v53.sh in dry-run first."
    else
        echo "[OK] no netem qdisc visible on selected scope"
    fi

    rm -f "$API_TMP" 2>/dev/null || true
} | tee "$REPORT"

echo
printf 'report=%s\n' "$REPORT"
exit 0
