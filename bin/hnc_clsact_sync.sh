#!/system/bin/sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# hnc_clsact_sync.sh — v5.34: 双栈同步限速设备的 MAC + IPv4 到 clsact BPF (mac_mark_map + ip_mark_map)
#
# 数据源: devices.json(在线设备 mac/ip) + rules.json(per-device mark_id)。
# 输出 "<mac|ip> <mark>" 喂给 hnc_clsact_ctl sync:
#   - 优先输出 "$mac $((MARK_BASE + mid))", 使 IPv4 与全部 RFC 4941 临时 IPv6 地址零延迟命中;
#   - 同时输出 "$ip $((MARK_BASE + mid))", 保持旧版 ip_mark_map 100% 兼容。

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"
DEVICES="$HNC_DIR/data/devices.json"
RULES="$HNC_DIR/data/rules.json"
MARK_BASE=8388608   # 0x800000

[ -x "$CTL" ] || exit 0
[ -f "$DEVICES" ] || exit 0
[ -f "$RULES" ] || exit 0

"$CTL" check "$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null | sed -n 's/^ACTIVE://p' | head -n1)" 2>/dev/null | grep -q '"map":true' || exit 0

emit_entries() {
    macs=$(grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"' "$DEVICES" | tr -d '"' | tr 'A-F' 'a-f' | sort -u)
    [ -n "$macs" ] || return 0

    for mac in $macs; do
        ip=""
        mid=""
        if [ -f "$HNC_DIR/bin/hnc_json" ]; then
            ip=$(sh "$HNC_DIR/bin/hnc_json" get-device "$DEVICES" "$mac" ip 2>/dev/null) || ip=""
            mid=$(sh "$HNC_DIR/bin/hnc_json" get-device "$RULES" "$mac" mark_id 2>/dev/null) || mid=""
        fi
        if [ -z "$ip" ]; then
            ip=$(tr -d '\r\n' < "$DEVICES" 2>/dev/null \
                | grep -oiE "\"$mac\"[[:space:]]*:[[:space:]]*\{[^{}]*\}" \
                | head -n 1 \
                | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([0-9.]+)".*/\1/p')
        fi
        if [ -z "$mid" ]; then
            mid=$(tr -d '\r\n' < "$RULES" 2>/dev/null \
                | grep -oiE "\"$mac\"[[:space:]]*:[[:space:]]*\{[^{}]*\}" \
                | head -n 1 \
                | sed -nE 's/.*"mark_id"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')
        fi

        case "$mid" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$mid" -ge 1 ] 2>/dev/null || continue
        [ "$mid" -le 99 ] 2>/dev/null || continue

        full_mark=$((MARK_BASE + mid))
        echo "$mac $full_mark"

        case "$ip" in
            *[!0-9.]* | "" | *..*) continue ;;
        esac
        echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || continue
        echo "$ip $full_mark"
    done
}

emit_entries | "$CTL" sync
rc=$?
echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-sync] rc=$rc" >> "$HNC_DIR/logs/offload_guard.log" 2>/dev/null
exit 0
