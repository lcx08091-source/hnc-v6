#!/system/bin/sh
# hnc_clsact_sync.sh — 把限速设备的 ip→mark 灌进 clsact BPF 的 ip_mark_map
#
# 数据源: devices.json(在线设备 ip) + rules.json(per-device mark_id)。
# 输出行 "ip mark" 喂给 hnc_clsact_ctl sync;mark 是完整值
# HNC_MARK_BASE(0x800000) + mark_id(1..99), 与 iptables/tc fw 的值域一致
# (BPF 程序把这个值原样写进 skb->mark, 存裸 mark_id 会匹配不到 fw filter)。
#
# 触发点: tc_manager 安装 filter 后 / apply_device_rule 改规则后 /
#         clsact watchdog 修复后 / httpd clsact_check 前。

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"
DEVICES="$HNC_DIR/data/devices.json"
RULES="$HNC_DIR/data/rules.json"
MARK_BASE=8388608   # 0x800000, 与 bin/hnc_constants.sh 的 HNC_MARK_BASE 一致

[ -x "$CTL" ] || exit 0
[ -f "$DEVICES" ] || exit 0
[ -f "$RULES" ] || exit 0

# pin 的 map 必须已存在(由 install 创建), 不存在说明功能未装/未开, 静默退
"$CTL" check "$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null | sed -n 's/^ACTIVE://p' | head -n1)" 2>/dev/null | grep -q '"map":true' || exit 0

emit_entries() {
    # 1) 从 devices.json 提取 mac 列表(小写)
    macs=$(grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"' "$DEVICES" | tr -d '"' | tr 'A-F' 'a-f' | sort -u)
    [ -n "$macs" ] || return 0

    for mac in $macs; do
        ip=""
        mid=""
        if [ -x "$HNC_DIR/bin/hnc_json" ]; then
            ip=$("$HNC_DIR/bin/hnc_json" get-device "$DEVICES" "$mac" ip 2>/dev/null) || ip=""
            mid=$("$HNC_DIR/bin/hnc_json" get-device "$RULES" "$mac" mark_id 2>/dev/null) || mid=""
        fi
        # hnc_json 不可用时 awk 兜底(与 apply_device_rule.sh get_ip 同款形态:
        # 先定位 mac, 再在尾部找 "ip":"x.x.x.x", 数字段提取)
        if [ -z "$ip" ]; then
            ip=$(awk -v m="$mac" '
            BEGIN { found=0 }
            {
                idx = index($0, "\"" m "\"")
                if (idx > 0) {
                    tail = substr($0, idx)
                    if (match(tail, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                        seg = substr(tail, RSTART, RLENGTH)
                        if (match(seg, /[0-9.]+/)) {
                            print substr(seg, RSTART, RLENGTH)
                            found=1
                            exit
                        }
                    }
                }
            }
            END { if (!found) print "" }
            ' "$DEVICES")
        fi
        if [ -z "$mid" ]; then
            mid=$(grep -A20 "\"$mac\"" "$RULES" 2>/dev/null | grep -oE '"mark_id"[[:space:]]*:[[:space:]]*[0-9]+' | head -n1 | grep -oE '[0-9]+$')
        fi

        # 校验: ip 形态 + mark_id 1..99
        case "$ip" in
            *[!0-9.]* | "" | *..*) continue ;;
        esac
        echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || continue
        case "$mid" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$mid" -ge 1 ] 2>/dev/null || continue
        [ "$mid" -le 99 ] 2>/dev/null || continue

        echo "$ip $((MARK_BASE + mid))"
    done
}

emit_entries | "$CTL" sync
rc=$?
echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-sync] rc=$rc" >> "$HNC_DIR/logs/clsact_watchdog.log" 2>/dev/null
exit 0
