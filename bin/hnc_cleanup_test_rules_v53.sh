#!/system/bin/sh
# HNC v5.3.0-rc5 · cautious cleanup helper for HNC test netem leaves.
# Default is read-only. It never deletes root qdisc or clsact.

set +e
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/product/bin:/data/adb/magisk:/data/adb/ksu/bin:$PATH
HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
TC_BIN=${TC_BIN:-}
[ -n "$TC_BIN" ] || for c in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do [ -x "$c" ] && { TC_BIN="$c"; break; }; done
[ -n "$TC_BIN" ] || TC_BIN=$(command -v tc 2>/dev/null || echo tc)

ACTION=status
IFACE=""
PARENT=""
YES=0
for arg in "$@"; do
    case "$arg" in
        status|dry-run|--dry-run) ACTION=status ;;
        clear-parent) ACTION=clear_parent ;;
        clear-all-netem) ACTION=clear_all_netem ;;
        --yes|-y) YES=1 ;;
        --iface=*) IFACE=${arg#--iface=} ;;
        --parent=*) PARENT=${arg#--parent=} ;;
        -h|--help) cat <<'EOF_USAGE'
Usage:
  sh bin/hnc_cleanup_test_rules_v53.sh status [--iface=wlan2]
  sh bin/hnc_cleanup_test_rules_v53.sh clear-parent --iface=wlan2 --parent=1:85 --yes
  sh bin/hnc_cleanup_test_rules_v53.sh clear-all-netem --iface=wlan2 --yes

Notes:
  - Default/status mode is read-only.
  - clear-parent only deletes a netem qdisc whose parent is exactly 1:<classid>.
  - clear-all-netem only deletes netem qdiscs under parent 1:<classid> on the selected iface.
  - It never deletes root qdisc, clsact, HTB root, iptables, or JSON rules.
EOF_USAGE
        exit 0 ;;
        *) [ -z "$IFACE" ] && IFACE="$arg" || [ -z "$PARENT" ] && PARENT="$arg" ;;
    esac
done

json_get_string(){ sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1; }
if [ -z "$IFACE" ]; then
    TMP="$RUN/.cleanup_api_sqm.$$"
    if command -v curl >/dev/null 2>&1; then curl -s --max-time 2 http://127.0.0.1:8444/api/sqm > "$TMP" 2>/dev/null; IFACE=$(json_get_string "$TMP" iface); rm -f "$TMP" 2>/dev/null; fi
fi
[ -n "$IFACE" ] || IFACE=$(cat "$RUN/hotspot_iface" "$RUN/iface" 2>/dev/null | head -1)
[ -n "$IFACE" ] || { echo "[FAIL] iface unknown. Pass --iface=wlan2"; exit 1; }

list_netem_parents(){
    "$TC_BIN" qdisc show dev "$IFACE" 2>/dev/null \
        | awk '$2=="netem" {for(i=1;i<=NF;i++) if($i=="parent" && $(i+1) ~ /^1:[0-9A-Fa-f]+$/) print $(i+1)}' \
        | sort -u
}
line_for_parent(){ "$TC_BIN" qdisc show dev "$IFACE" parent "$1" 2>/dev/null | grep ' netem ' | head -1; }

printf 'HNC cleanup helper v5.3.0-rc5\niface=%s\naction=%s\n\n' "$IFACE" "$ACTION"
echo "current HNC-like netem leaves:"
PARENTS=$(list_netem_parents)
if [ -n "$PARENTS" ]; then
    for p in $PARENTS; do echo "  $p  $(line_for_parent "$p")"; done
else
    echo "  none"
fi

case "$ACTION" in
    status)
        echo
        echo "dry-run only. Add clear-parent/clear-all-netem with --yes to modify tc."
        exit 0 ;;
    clear_parent)
        echo "$PARENT" | grep -Eq '^1:[0-9A-Fa-f]+$' || { echo "[FAIL] unsafe or missing parent: $PARENT"; exit 1; }
        line=$(line_for_parent "$PARENT")
        [ -n "$line" ] || { echo "[OK] no netem qdisc at parent $PARENT"; exit 0; }
        [ "$YES" = "1" ] || { echo "[FAIL] refusing to modify without --yes"; exit 1; }
        echo "deleting netem qdisc dev=$IFACE parent=$PARENT"
        "$TC_BIN" qdisc del dev "$IFACE" parent "$PARENT" 2>&1
        exit $? ;;
    clear_all_netem)
        [ "$YES" = "1" ] || { echo "[FAIL] refusing to modify without --yes"; exit 1; }
        [ -n "$PARENTS" ] || { echo "[OK] no HNC-like netem leaves to delete"; exit 0; }
        RC=0
        for p in $PARENTS; do
            echo "deleting netem qdisc dev=$IFACE parent=$p"
            "$TC_BIN" qdisc del dev "$IFACE" parent "$p" 2>&1 || RC=1
        done
        exit $RC ;;
    *) echo "[FAIL] unknown action: $ACTION"; exit 2 ;;
esac
