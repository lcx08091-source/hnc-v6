#!/system/bin/sh
# hnc_clsact_sync.sh — v5.40.0+: 双栈同步受控设备的 MAC + IPv4 + 全局 IPv6 到 clsact BPF
#
# 正交位域契约:
#   mid (1..99) -> 0x00800000 | (mid << 16) (例如 mid=5 -> 0x00850000)
#   输出 "<mac|ipv4|ipv6> <mark_hex>" 喂给 hnc_clsact_ctl sync:
#     - MAC 条目写入 mac_mark_map, 零延迟覆盖 IPv4 与全部 RFC 4941 临时 IPv6 地址;
#     - IPv4 条目写入 ip_mark_map, 保持 L3 兜底 100% 兼容;
#     - 活跃全局 IPv6 邻居一并输出, 供支持 v6 L3 map 的守护进程平滑消费。

HNC_DIR="${HNC_DIR:-/data/local/hnc}"

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

CTL="$HNC_DIR/bin/hnc_clsact_ctl"
DEVICES_FLAT="$HNC_DIR/run/devices.flat"
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
[ -f "$RULES" ] || exit 0

IFACE="${1:-$(sed -n 's/^ACTIVE://p' "$HNC_DIR/run/hnc_state" 2>/dev/null | head -n1 | tr -d ' \r\n')}"
case "$IFACE" in
    ''|*[!a-zA-Z0-9_.:-]*) exit 0 ;;
esac

_CHK=$("$CTL" check "$IFACE" 2>/dev/null)
printf '%s\n' "$_CHK" | grep -q '"map":true' || exit 0

if ! grep -qE '"mark_id"|"blacklist"' "$RULES" 2>/dev/null; then
    if printf '%s\n' "$_CHK" | grep -q '"ip_entries":0' && {
        ! printf '%s\n' "$_CHK" | grep -q '"mac_map":true' || printf '%s\n' "$_CHK" | grep -q '"mac_entries":0'
    }; then
        exit 0
    fi
    printf '' | "$CTL" sync
    rc=$?
    echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-sync] rc=$rc" >> "$HNC_DIR/logs/offload_guard.log" 2>/dev/null
    exit 0
fi

# 优先读取 run/devices.flat, 回退直接解析扁平 data/devices.json(绝不再对扁平 devices.json 调恒返空的 get-device)
extract_dev_mac_ip() {
    if [ -s "$DEVICES_FLAT" ]; then
        awk '
            !/^[[:space:]]*(#|$)/ {
                mac = ""; ip = ""
                for (i = 1; i <= NF; i++) {
                    tok = tolower($i)
                    if (mac == "" && tok ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/) mac = tok
                    else if (ip == "" && tok ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) ip = tok
                }
                if (mac != "" && !(mac in seen)) {
                    seen[mac] = 1
                    print mac, ip
                }
            }
        ' "$DEVICES_FLAT" 2>/dev/null
    elif [ -f "$DEVICES" ]; then
        awk '
            { s = s $0 " " }
            END {
                rest = s
                while (match(rest, /"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^{}]*\}/)) {
                    blk = substr(rest, RSTART, RLENGTH)
                    rest = substr(rest, RSTART + RLENGTH)
                    mac = tolower(substr(blk, 2, 17))
                    ip = ""
                    if (!match(blk, /"online"[[:space:]]*:[[:space:]]*false/) &&
                        match(blk, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                        ipseg = substr(blk, RSTART, RLENGTH)
                        sub(/.*"ip"[[:space:]]*:[[:space:]]*"/, "", ipseg)
                        sub(/"$/, "", ipseg)
                        ip = ipseg
                    }
                    if (!(mac in seen)) {
                        seen[mac] = 1
                        print mac, ip
                    }
                }
            }
        ' "$DEVICES" 2>/dev/null
    fi
}

extract_rule_mids() {
    awk '
        { s = s $0 " " }
        END {
            if (!match(s, /"devices"[[:space:]]*:[[:space:]]*\{/)) exit
            rest = substr(s, RSTART + RLENGTH)
            while (match(rest, /"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^{}]*\}/)) {
                blk = substr(rest, RSTART, RLENGTH)
                rest = substr(rest, RSTART + RLENGTH)
                mac = tolower(substr(blk, 2, 17))
                if (match(blk, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                    mseg = substr(blk, RSTART, RLENGTH)
                    sub(/.*:[[:space:]]*/, "", mseg)
                    print mac, mseg
                }
            }
        }
    ' "$RULES" 2>/dev/null
}

extract_blacklist_entries() {
    awk '
        { s = s $0 " " }
        END {
            if (!match(s, /"blacklist"[[:space:]]*:[[:space:]]*\[[^]]*\]/)) exit
            blseg = substr(s, RSTART, RLENGTH)
            while (match(blseg, /"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"/)) {
                mac = tolower(substr(blseg, RSTART + 1, 17))
                blseg = substr(blseg, RSTART + RLENGTH)
                if (!(mac in blseen)) {
                    blseen[mac] = 1
                    blorder[++bln] = mac
                }
            }
            if (bln == 0) exit
            if (match(s, /"devices"[[:space:]]*:[[:space:]]*\{/)) {
                rest = substr(s, RSTART + RLENGTH)
                while (match(rest, /"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^{}]*\}/)) {
                    blk = substr(rest, RSTART, RLENGTH)
                    rest = substr(rest, RSTART + RLENGTH)
                    dmac = tolower(substr(blk, 2, 17))
                    if (dmac in blseen) {
                        bip = ""
                        if (match(blk, /"blocked_ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                            ipseg = substr(blk, RSTART, RLENGTH)
                            sub(/.*"blocked_ip"[[:space:]]*:[[:space:]]*"/, "", ipseg)
                            sub(/"$/, "", ipseg)
                            bip = ipseg
                        } else if (match(blk, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                            ipseg = substr(blk, RSTART, RLENGTH)
                            sub(/.*"ip"[[:space:]]*:[[:space:]]*"/, "", ipseg)
                            sub(/"$/, "", ipseg)
                            bip = ipseg
                        }
                        blip[dmac] = bip
                    }
                }
            }
            for (i = 1; i <= bln; i++) {
                m = blorder[i]
                print m, blip[m]
            }
        }
    ' "$RULES" 2>/dev/null
}

emit_entries() {
    _devs=$(extract_dev_mac_ip)
    _bls=$(extract_blacklist_entries)
    [ -n "$_devs" ] || [ -n "$_bls" ] || return 0
    _mids=$(extract_rule_mids)
    _v6_loaded=0
    V6_NEIGH=""

    if [ -n "$_bls" ]; then
        _bl_mac_list=" $(printf '%s\n' "$_bls" | awk 'NF { printf "%s ", $1 }')"
        printf '%s\n' "$_bls" | while read -r bmac bip; do
            [ -n "$bmac" ] || continue
            echo "$bmac 0x00ff0000"
            if [ -n "$_devs" ]; then
                _live_bip=$(printf '%s\n' "$_devs" | awk -v m="$bmac" '$1 == m && $2 != "" { print $2; exit }')
                [ -n "$_live_bip" ] && bip="$_live_bip"
            fi
            case "$bip" in
                *[!0-9.]* | "" | *..*) ;;
                *)
                    if printf '%s\n' "$bip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
                        _reused_by_innocent=0
                        if [ -n "$_devs" ] && printf '%s\n' "$_devs" | awk -v ip="$bip" -v bls="$_bl_mac_list" '
                            $2 == ip && index(bls, " " $1 " ") == 0 { conflict = 1; exit }
                            END { exit !conflict }
                        '; then
                            _reused_by_innocent=1
                        fi
                        if [ "$_reused_by_innocent" = "0" ]; then
                            echo "$bip 0x00ff0000"
                        fi
                    fi
                    ;;
            esac
        done
    fi

    [ -n "$_devs" ] || return 0

    printf '%s\n' "$_devs" | while read -r mac ip; do
        [ -n "$mac" ] || continue
        if [ -n "$_bls" ] && printf '%s\n' "$_bls" | awk -v m="$mac" '$1 == m { found=1; exit } END { exit !found }'; then
            continue
        fi
        mid=$(printf '%s\n' "$_mids" | awk -v m="$mac" '$1 == m { print $2; exit }')
        if [ -z "$mid" ] && [ -f "$HNC_DIR/bin/hnc_json" ] && grep -qiF "\"$mac\"" "$RULES" 2>/dev/null; then
            mid=$(sh "$HNC_DIR/bin/hnc_json" get-device "$RULES" "$mac" mark_id 2>/dev/null) || mid=""
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
                if printf '%s\n' "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
                    echo "$ip $mark_hex"
                fi
                ;;
        esac

        if [ "$_v6_loaded" = 0 ]; then
            _v6_loaded=1
            if command -v ip >/dev/null 2>&1; then
                V6_NEIGH=$(ip -6 neigh show dev "$IFACE" 2>/dev/null)
                [ -z "$V6_NEIGH" ] && V6_NEIGH=$(ip neigh show dev "$IFACE" 2>/dev/null)
            fi
        fi
        if [ -n "$V6_NEIGH" ]; then
            printf '%s\n' "$V6_NEIGH" | awk -v m="$mac" -v mk="$mark_hex" '
                {
                    ip6 = tolower($1)
                    st = toupper($NF)
                    if (ip6 ~ /:/ && ip6 !~ /^(fe80:|ff)/ && st != "FAILED" && st != "INCOMPLETE") {
                        for (i = 2; i < NF; i++) {
                            if (tolower($i) == "lladdr" && tolower($(i+1)) == m) {
                                if (!(ip6 in seen6)) { seen6[ip6] = 1; print ip6, mk }
                                break
                            }
                        }
                    }
                }'
        fi
    done
}

emit_entries | "$CTL" sync
rc=$?
echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-sync] rc=$rc" >> "$HNC_DIR/logs/offload_guard.log" 2>/dev/null
exit 0
