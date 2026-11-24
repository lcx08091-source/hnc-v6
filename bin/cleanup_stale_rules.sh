#!/system/bin/sh
# cleanup_stale_rules.sh — hotfix10
# 清理长期未见的 devices 规则记录,防止 rules.json 无限膨胀。
# 只删除 rules.json.devices[mac] 里的规则状态; 不删除 blacklist / whitelist / device_names。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
RULES="$HNC_DIR/data/rules.json"
DEVICES="$HNC_DIR/data/devices.json"
JSON_SET="$HNC_DIR/bin/json_set.sh"
[ -f "$JSON_SET" ] || JSON_SET="${0%/*}/json_set.sh"
APPLY="$HNC_DIR/bin/apply_device_rule.sh"
[ -f "$APPLY" ] || APPLY="${0%/*}/apply_device_rule.sh"
IPTM="$HNC_DIR/bin/iptables_manager.sh"
[ -f "$IPTM" ] || IPTM="${0%/*}/iptables_manager.sh"
LOG="$HNC_DIR/logs/cleanup_stale.log"
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi

log() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null || true
}

[ -f "$RULES" ] || { log "rules.json missing, skip"; exit 0; }

ttl_days=$(HNC="$HNC_DIR" sh "$JSON_SET" top_get stale_rule_ttl_days 2>/dev/null | awk 'NR==1{print; exit}')
[ -z "$ttl_days" ] && ttl_days=30
case "$ttl_days" in
    0) log "stale cleanup disabled (stale_rule_ttl_days=0)"; exit 0 ;;
    *[!0-9]*) log "invalid stale_rule_ttl_days='$ttl_days', skip"; exit 0 ;;
esac

now=$(date +%s 2>/dev/null) || now=0
[ "$now" -gt 0 ] || { log "date +%s failed, skip"; exit 0; }
# v5.20: 时钟不可信(未对时 / 落后高水位)时不判 TTL —— 跑到未来的时钟会把所有
# 规则都当成"长期未见"删掉。见 hnc_clock.sh。
if [ -f "$HNC_DIR/bin/hnc_clock.sh" ]; then
    . "$HNC_DIR/bin/hnc_clock.sh"
    hnc_clock_sane "$now" || { log "clock not trustworthy (now=$now high_water=$(hnc_clock_hwm)), skip"; exit 0; }
fi
threshold=$((now - ttl_days * 86400))

. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    gate_lock() { return 0; }
    gate_unlock() { return 0; }
}

gate_lock || { log "gate_lock failed, skip this round"; exit 1; }
# v5.12: gate 传递(同 tc_manager restore)。下面的 apply_device_rule clear 会 fork
# iptables_manager unmark,它的 mac_lock 见 gate 目录会等满 5s 退 11 —— 本脚本自己
# 持 gate 就自己把自己堵死:陈旧设备的 MARK 规则(v4+v6)永远删不掉,紧接着
# device_remove 又把 mark_id 释放,mid 复用后该 MAC 回来会被打上新主人的 mark。
# gate/pid 由 gate_lock 写为本进程 $$,hnc_lock.sh 校验一致才豁免门禁。
export HNC_GATE_HELD=$$

removed=0
scanned=0
skipped_online=0
skipped_no_seen=0

# 提取 devices 字典里的 MAC key(兼容单行与格式化多行 JSON, 跳过字符串值的 device_names)。
for mac in $(tr -d '\r\n' < "$RULES" 2>/dev/null \
           | grep -oE '"[0-9a-fA-F:]{17}"[[:space:]]*:[[:space:]]*\{' \
           | grep -oE '[0-9a-fA-F:]{17}' \
           | tr 'A-Z' 'a-z' \
           | sort -u); do
    scanned=$((scanned + 1))

    # 当前还在线的设备绝不自动清理,避免 last_seen_persist 尚未刷新时误删。
    if [ -f "$DEVICES" ] && grep -qi "\"$mac\"" "$DEVICES" 2>/dev/null; then
        skipped_online=$((skipped_online + 1))
        continue
    fi

    last_seen=$(HNC="$HNC_DIR" sh "$JSON_SET" device_get "$mac" last_seen_persist 2>/dev/null | awk 'NR==1{print; exit}')
    case "$last_seen" in
        ''|0) skipped_no_seen=$((skipped_no_seen + 1)); continue ;;
        *[!0-9]*) skipped_no_seen=$((skipped_no_seen + 1)); continue ;;
    esac

    if [ "$last_seen" -lt "$threshold" ]; then
        age_days=$(( (now - last_seen) / 86400 ))
        log "remove stale device=$mac last_seen=$last_seen age=${age_days}d ttl=${ttl_days}d"
        # best-effort 清限速/mark/tc; 失败也继续删除 rules entry,避免无限膨胀。
        HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" sh "$APPLY" clear "$mac" >> "$LOG" 2>&1 || log "WARN: clear failed for stale $mac (continuing)"
        HNC="$HNC_DIR" sh "$JSON_SET" device_remove "$mac" >> "$LOG" 2>&1 \
            && removed=$((removed + 1)) \
            || log "WARN: device_remove failed for stale $mac"
    fi
done

# C039: 双栈(IPv4 + IPv6)扫描 mangle/HNC_MARK, 严格按正交设备掩码 0x00ff0000 删齐
# 孤儿 --mac-source 与孤儿 -s/-d 规则(100% 禁碰低 16 位 0x0000ffff netd 路由位)。
_csr_resolve_ipt() {
    local _bin="$1" _w=""
    command -v "$_bin" >/dev/null 2>&1 || return 1
    if command -v hnc_ipt_wait_args >/dev/null 2>&1; then
        _w=$(hnc_ipt_wait_args "$_bin")
    else
        _w="-w 2"
        if [ -z "${HNC_TEST_MODE:-}" ] && [ -z "${MOCK_LOG:-}" ]; then
            "$_bin" -w 2 -t mangle -L -n >/dev/null 2>&1
            if [ $? -eq 2 ]; then
                "$_bin" -w -t mangle -L -n >/dev/null 2>&1
                [ $? -eq 2 ] && _w="" || _w="-w"
            fi
        fi
    fi
    if [ -n "$_w" ]; then
        printf '%s %s\n' "$_bin" "$_w"
    else
        printf '%s\n' "$_bin"
    fi
}

_csr_del_loop() {
    local _cmd="$1" _n=0
    shift
    # shellcheck disable=SC2086
    while $_cmd -t mangle -D HNC_MARK "$@" 2>/dev/null; do
        _n=$((_n + 1))
        [ "$_n" -ge 8 ] && break
    done
    return $_n
}

_csr_mask="${HNC_MARK_MASK:-0x00ff0000}"
_csr_ipt="${HNC_IPT:-}"
[ -n "$_csr_ipt" ] || _csr_ipt=$(_csr_resolve_ipt iptables 2>/dev/null || true)
_csr_ip6t="${HNC_IP6T:-}"
[ -n "$_csr_ip6t" ] || _csr_ip6t=$(_csr_resolve_ipt ip6tables 2>/dev/null || true)

_csr_rules_in="$RULES"
[ -r "$_csr_rules_in" ] || _csr_rules_in="/dev/null"
_csr_devs_in="/dev/null"
[ -f "$DEVICES" ] && [ -r "$DEVICES" ] && _csr_devs_in="$DEVICES"

_csr_unmarked=" "
orphan_deleted=0

for _csr_cmd in "$_csr_ipt" "$_csr_ip6t"; do
    [ -n "$_csr_cmd" ] || continue
    # shellcheck disable=SC2086
    _csr_dump=$($_csr_cmd -t mangle -S HNC_MARK 2>/dev/null) || _csr_dump=""
    [ -n "$_csr_dump" ] || continue

    _csr_ops=$(printf '%s\n' "$_csr_dump" | awk -v rf="$_csr_rules_in" -v df="$_csr_devs_in" '
        function hex_or_dec(s,    h, v, i, c, d) {
            s = tolower(s)
            gsub(/[^0-9a-fx]/, "", s)
            if (s == "") return -1
            if (s ~ /^0x/) {
                h = substr(s, 3)
                if (h == "") return -1
                v = 0
                for (i = 1; i <= length(h); i++) {
                    c = substr(h, i, 1)
                    d = index("0123456789abcdef", c) - 1
                    if (d < 0) return -1
                    v = v * 16 + d
                }
                return v
            }
            if (s ~ /^[0-9]+$/) return s + 0
            return -1
        }
        function strip_host_cidr(a) {
            sub(/\/(32|128)$/, "", a)
            return a
        }
        function is_mac_str(s) {
            return (s ~ /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/)
        }
        function parse_json_devices(path, is_online,    ln, js, n, i, c, ch, s, nt, tt, tv, sec, depth, cur_m, k, vt, vv) {
            js = ""
            while ((getline ln < path) > 0) js = js " " ln
            close(path)
            n = length(js); nt = 0; i = 1
            while (i <= n) {
                c = substr(js, i, 1)
                if (c == " " || c == "\t" || c == "\r" || c == "\n") { i++; continue }
                if (c == "{" || c == "}" || c == "[" || c == "]" || c == ":" || c == ",") {
                    tt[++nt] = c; tv[nt] = c; i++; continue
                }
                if (c == "\"") {
                    i++; s = ""
                    while (i <= n) {
                        ch = substr(js, i, 1)
                        if (ch == "\\") { s = s substr(js, i + 1, 1); i += 2; continue }
                        if (ch == "\"") { i++; break }
                        s = s ch; i++
                    }
                    tt[++nt] = "S"; tv[nt] = s; continue
                }
                s = ""
                while (i <= n) {
                    ch = substr(js, i, 1)
                    if (ch == " " || ch == "\t" || ch == "\r" || ch == "\n" || \
                        ch == "{" || ch == "}" || ch == "[" || ch == "]" || ch == ":" || ch == "," || ch == "\"") break
                    s = s ch; i++
                }
                tt[++nt] = "L"; tv[nt] = s
            }
            if (is_online) {
                cur_m = ""; depth = 0
                for (k = 1; k <= nt; k++) {
                    if (tt[k] == "{") { depth++; continue }
                    if (tt[k] == "}") { if (depth == 2) cur_m = ""; depth--; continue }
                    if (depth == 1 && tt[k] == "S" && tt[k+1] == ":" && tt[k+2] == "{") {
                        s = tolower(tv[k])
                        if (is_mac_str(s)) cur_m = s
                        continue
                    }
                    if (depth == 2 && cur_m != "" && tt[k] == "S" && tv[k] == "ip" && tt[k+1] == ":" && tt[k+2] == "S") {
                        on_ip[cur_m] = tv[k+2]; k += 2; continue
                    }
                }
                return
            }
            sec = 0; depth = 0; cur_m = ""
            for (k = 1; k <= nt; k++) {
                if (!sec) {
                    if (tt[k] == "S" && tv[k] == "devices" && tt[k+1] == ":" && tt[k+2] == "{") {
                        sec = 1; depth = 1; k += 2
                    }
                    continue
                }
                if (tt[k] == "{") { depth++; continue }
                if (tt[k] == "}") {
                    if (depth == 2) cur_m = ""
                    depth--
                    if (depth <= 0) { sec = 0; break }
                    continue
                }
                if (depth == 1 && tt[k] == "S" && tt[k+1] == ":" && tt[k+2] == "{") {
                    s = tolower(tv[k])
                    if (is_mac_str(s)) {
                        cur_m = s
                        dev_ok[cur_m] = 1
                    }
                    continue
                }
                if (depth == 2 && cur_m != "" && tt[k] == "S" && tt[k+1] == ":") {
                    vt = tt[k+2]; vv = tv[k+2]
                    if (tv[k] == "mark_id" && (vt == "L" || vt == "S") && vv ~ /^[0-9]+$/) {
                        dev_mid[cur_m] = vv + 0
                        mid_owner[vv + 0] = cur_m
                        k += 2; continue
                    }
                    if (tv[k] == "ip" && vt == "S" && vv != "") {
                        dev_ip[cur_m] = vv
                        k += 2; continue
                    }
                }
            }
        }
        BEGIN {
            parse_json_devices(rf, 0)
            parse_json_devices(df, 1)
        }
        $1 == "-A" && $2 == "HNC_MARK" {
            rmac = ""; rsrc = ""; rdst = ""; rxm = ""; mmk = ""
            inv = 0
            for (i = 3; i <= NF; i++) {
                if ($i == "!") { inv = 1; continue }
                if ($i == "--mac-source" && i < NF) { rmac = tolower($(i+1)); i++; continue }
                if ($i == "-s" && i < NF && !inv) { rsrc = $(i+1); i++; continue }
                if ($i == "-d" && i < NF && !inv) { rdst = $(i+1); i++; continue }
                if ($i == "--mark" && i < NF && !inv) { mmk = $(i+1); i++; continue }
                if ($i == "--set-xmark" && i < NF) { rxm = $(i+1); i++; continue }
                inv = 0
            }
            if (rxm == "" || index(rxm, "/") == 0) next
            split(rxm, mp, "/")
            v = hex_or_dec(mp[1])
            msk = hex_or_dec(mp[2])
            # 严守 0x00ff0000 (16711680) 正交设备掩码, 绝不触碰 0x0000ffff 低 16 位
            if (v < 0 || msk != 16711680 || (msk % 65536) != 0) next
            seg = int(v / 65536) % 256
            if (seg <= 128 || seg > 227) next
            mid = seg - 128
            mhex = sprintf("0x%08x", 8388608 + mid * 65536)

            orphan = 0
            if (rmac != "") {
                if (!(rmac in dev_ok)) {
                    orphan = 1
                } else if ((rmac in dev_mid) && dev_mid[rmac] != mid) {
                    orphan = 1
                } else if (rsrc != "") {
                    sip = strip_host_cidr(rsrc)
                    if (index(sip, ".") > 0 && (dev_ip[rmac] != "" || on_ip[rmac] != "") && sip != dev_ip[rmac] && sip != on_ip[rmac]) {
                        orphan = 1
                    }
                }
                if (orphan && !(rmac in dev_ok)) {
                    ip4 = strip_host_cidr(rsrc)
                    if (index(ip4, ".") == 0) ip4 = "-"
                    printf "UNMARK %s %d %s\n", rmac, mid, ip4
                }
            } else if (rsrc != "" || rdst != "") {
                if (!(mid in mid_owner)) {
                    orphan = 1
                } else {
                    om = mid_owner[mid]
                    chk_ip = strip_host_cidr(rdst != "" ? rdst : rsrc)
                    if (index(chk_ip, ".") > 0 && (dev_ip[om] != "" || on_ip[om] != "") && chk_ip != dev_ip[om] && chk_ip != on_ip[om]) {
                        orphan = 1
                    }
                }
            }
            if (!orphan) next

            if (rmac != "" && rsrc != "" && rdst == "") {
                printf "DEL_SMAC %s %s %s\n", rsrc, rmac, mhex
            } else if (rmac != "" && rsrc == "" && rdst == "" && mmk != "") {
                printf "DEL_MAC_MM %s %s %s\n", rmac, mmk, mhex
            } else if (rmac != "" && rsrc == "" && rdst == "") {
                printf "DEL_MAC %s - %s\n", rmac, mhex
            } else if (rmac == "" && rsrc != "" && rdst != "") {
                printf "DEL_SD %s %s %s\n", rsrc, rdst, mhex
            } else if (rmac == "" && rsrc != "") {
                printf "DEL_S %s - %s\n", rsrc, mhex
            } else if (rmac == "" && rdst != "") {
                printf "DEL_D %s - %s\n", rdst, mhex
            }
        }
    ')

    [ -n "$_csr_ops" ] || continue
    while read -r _op _a1 _a2 _a3; do
        [ -n "$_op" ] || continue
        case "$_op" in
            UNMARK)
                _ukey="$_a1:$_a2"
                case "$_csr_unmarked" in
                    *" $_ukey "*) ;;
                    *)
                        _csr_unmarked="$_csr_unmarked$_ukey "
                        _uip="$_a3"
                        [ "$_uip" = "-" ] && _uip=""
                        if [ -f "$IPTM" ]; then
                            HNC_DIR="$HNC_DIR" sh "$IPTM" unmark "$_uip" "$_a1" "$_a2" >> "$LOG" 2>&1 || true
                        fi
                        ;;
                esac
                ;;
            DEL_SMAC)
                _plain="${_a1%/*}"
                _csr_del_loop "$_csr_cmd" -s "$_a1" -m mac --mac-source "$_a2" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                if [ "$_plain" != "$_a1" ]; then
                    _csr_del_loop "$_csr_cmd" -s "$_plain" -m mac --mac-source "$_a2" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                    orphan_deleted=$((orphan_deleted + $?))
                fi
                ;;
            DEL_MAC_MM)
                _csr_del_loop "$_csr_cmd" -m mac --mac-source "$_a1" -m mark --mark "$_a2" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                _csr_del_loop "$_csr_cmd" -m mac --mac-source "$_a1" -m mark --mark "0x0/${_csr_mask}" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                ;;
            DEL_MAC)
                _csr_del_loop "$_csr_cmd" -m mac --mac-source "$_a1" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                ;;
            DEL_SD)
                _ps="${_a1%/*}"; _pd="${_a2%/*}"
                _csr_del_loop "$_csr_cmd" -s "$_a1" -d "$_a2" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                if [ "$_ps" != "$_a1" ] || [ "$_pd" != "$_a2" ]; then
                    _csr_del_loop "$_csr_cmd" -s "$_ps" -d "$_pd" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                    orphan_deleted=$((orphan_deleted + $?))
                fi
                ;;
            DEL_S)
                _ps="${_a1%/*}"
                _csr_del_loop "$_csr_cmd" -s "$_a1" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                if [ "$_ps" != "$_a1" ]; then
                    _csr_del_loop "$_csr_cmd" -s "$_ps" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                    orphan_deleted=$((orphan_deleted + $?))
                fi
                ;;
            DEL_D)
                _pd="${_a1%/*}"
                _csr_del_loop "$_csr_cmd" -d "$_a1" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                orphan_deleted=$((orphan_deleted + $?))
                if [ "$_pd" != "$_a1" ]; then
                    _csr_del_loop "$_csr_cmd" -d "$_pd" -j MARK --set-xmark "${_a3}/${_csr_mask}"
                    orphan_deleted=$((orphan_deleted + $?))
                fi
                ;;
        esac
    done <<EOF
$_csr_ops
EOF
done

unset HNC_GATE_HELD
gate_unlock
log "cleanup done scanned=$scanned removed=$removed orphan_mark_deleted=$orphan_deleted skipped_online=$skipped_online skipped_no_seen=$skipped_no_seen ttl_days=$ttl_days"
exit 0
