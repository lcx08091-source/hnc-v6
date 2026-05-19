#!/system/bin/sh
# HNC v5.3.0-rc5 · SQM gray diagnostic bundle
# Read-only except for writing a local report under /data/local/hnc/run.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:/data/adb/ksu/bin:$PATH
HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
DATA="$HNC_DIR/data"
LOGS="$HNC_DIR/logs"
OUT_DIR="$RUN/sqm_gray_diag"
TS=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)
REPORT="$OUT_DIR/sqm_gray_diag-$TS.txt"
LATEST="$RUN/sqm_gray_diag.latest"
mkdir -p "$OUT_DIR" "$RUN" 2>/dev/null || exit 1

find_tc() {
    for c in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v tc 2>/dev/null || echo tc
}
TC_BIN=$(find_tc)
IFACE=${1:-$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n')}

section() { echo; echo "===== $* ====="; }
redact() { sed -E 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/XX:XX:XX:XX:XX:XX/g; s/([0-9]{1,3}\.){3}[0-9]{1,3}/x.x.x.x/g'; }

{
    echo "HNC SQM gray diagnostic · v5.3.0-rc5"
    echo "time=$TS"
    echo "hnc_dir=$HNC_DIR"
    echo "iface=$IFACE"

    section "module"
    cat /data/adb/modules/hotspot_network_control/module.prop 2>/dev/null || cat "$HNC_DIR/module.prop" 2>/dev/null || true

    section "httpd"
    "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" -version 2>/dev/null || true
    ps -A 2>/dev/null | grep hnc_httpd | grep -v grep || true

    section "sqm status"
    HNC="$HNC_DIR" HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/sqm_manager.sh" status "$IFACE" 2>&1 || true

    section "capabilities"
    cat "$RUN/capabilities.json" 2>/dev/null || true

    section "qdisc"
    if [ -n "$IFACE" ]; then
        "$TC_BIN" qdisc show dev "$IFACE" 2>&1 || true
        "$TC_BIN" class show dev "$IFACE" 2>&1 | head -120 || true
        "$TC_BIN" filter show dev "$IFACE" 2>&1 | head -160 || true
    else
        "$TC_BIN" qdisc show 2>&1 | head -160 || true
    fi

    section "rules summary"
    if [ -f "$DATA/rules.json" ]; then
        tr -d '\n' < "$DATA/rules.json" 2>/dev/null | cut -c1-3000 | redact
        echo
    fi

    section "logs tail"
    tail -80 "$LOGS/sqm.log" 2>/dev/null | redact || true
    tail -80 "$LOGS/tc.log" 2>/dev/null | redact || true

    section "system hints"
    uname -a 2>/dev/null || true
    getprop ro.product.model 2>/dev/null || true
    getprop ro.build.version.release 2>/dev/null || true
    settings get global tether_offload_disabled 2>/dev/null || true
} > "$REPORT" 2>&1

echo "$REPORT" > "$LATEST" 2>/dev/null || true
cat <<EOF
{"ok":true,"report":"$REPORT","iface":"$IFACE"}
EOF
