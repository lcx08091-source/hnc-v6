#!/system/bin/sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# hnc_clsact_sync.sh — v5.40.0: 双栈同步受控设备的 MAC + IPv4 + 全局 IPv6 到 clsact BPF
#
# 正交位域契约:
#   mid (1..99) -> 0x00800000 | (mid << 16) (例如 mid=5 -> 0x00850000)
#   输出 "<mac|ipv4|ipv6> <mark_hex>" 喂给 hnc_clsact_ctl sync:
#     - MAC 条目写入 mac_mark_map, 零延迟覆盖 IPv4 与全部 RFC 4941 临时 IPv6 地址;
#     - IPv4 条目写入 ip_mark_map, 保持 L3 兜底 100% 兼容;
#     - 活跃全局 IPv6 邻居一并输出, 供支持 v6 L3 map 的守护进程平滑消费。

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"
DEVICES="$HNC_DIR/data/devices.json"
RULES="$HNC_DIR/data/rules.json"

if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi
command -v hnc_dev_mark_hex >/dev/null 2>&1 || {
    hnc_dev_mark_hex() { printf '0x%08x\n' $(( 0x00800000 | ($1 << 16) )); }
}

[ -x "$CTL" ] || exit 0
[ -f "$DEVICES" ] || exit 0
[ -f "$RULES" ] || exit 0

IFACE=$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null | sed -n 's/^ACTIVE://p' | head -n1 | tr -d ' \r\n')
"$CTL" check "$IFACE" 2>/dev/null | grep -q '"map":true' || exit 0

V6_NEIGH=""
if [ -n "$IFACE" ] && command -v ip >/dev/null 2>&1; then
    V6_NEIGH=$(ip -6 neigh show dev "$IFACE" 2>/dev/null)
    [ -z "$V6_NEIGH" ] && V6_NEIGH=$(ip neigh show dev "$IFACE" 2>/dev/null)
fi

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

        mark_hex=$(hnc_dev_mark_hex "$mid") || continue
        echo "$mac $mark_hex"

        case "$ip" in
            *[!0-9.]* | "" | *..*) ;;
            *)
                if echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
                    echo "$ip $mark_hex"
                fi
                ;;
        esac

        if [ -n "$V6_NEIGH" ]; then
            printf '%s\n' "$V6_NEIGH" | awk -v m="$mac" -v mk="$mark_hex" '
                tolower($0) ~ m && $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $NF != "FAILED" && $NF != "INCOMPLETE" {
                    print tolower($1), mk
                }' | sort -u
        fi
    done
}

emit_entries | "$CTL" sync
rc=$?
echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-sync] rc=$rc" >> "$HNC_DIR/logs/offload_guard.log" 2>/dev/null
exit 0
