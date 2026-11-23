#!/system/bin/sh
# webui_guard.sh — v5.22 WebUI 访问白名单落到防火墙(filter/INPUT, v4 + v6)
#
# 为什么在防火墙层: HTTP 403 时 TLS 握手、配对页、PIN 接口都已经暴露给对方;
# 在 INPUT 链直接回 TCP RST, 非白名单客户端看到的就是 "connection refused"。
# hnc_httpd 里还有同配置的 Go 侧判定(webui_access.go)作纵深防御。
#
# 配置: data/webui_access.json(hnc_httpd 的 webui_access_set 动作是唯一写者, 单行 JSON)
#   {"mode":"all|allowlist|local_only","macs":["aa:bb:..","192.168.43.7","fd00::7"],"updated":N}
#   文件不存在 → all; 文件损坏 / mode 非法 → local_only(fail-closed, 与 Go 侧一致)
#
# 规则(独立链 HNC_WEBUI, 每个端口一条 `-I INPUT 1 -p tcp --dport <p> -j HNC_WEBUI`):
#   1. -i lo -j RETURN                         本机永远放行(KSU WebUI / 本机浏览器)
#   2. 蜂窝上行口(rmnet+/ccmni+/wwan+/seth_+/sipa_eth+)→ REJECT   任何模式都拒:
#      httpd 绑 0.0.0.0, 双栈下手机的蜂窝 IPv6 公网地址上 8443 同样在监听
#   3. all        → RETURN(其余交给 INPUT 后续规则, 与旧行为一致)
#      allowlist  → 每个 MAC: -m mac --mac-source <mac> -j RETURN
#                   每个本族 IP: -s <ip> -j RETURN;  其余 REJECT --reject-with tcp-reset
#      local_only → 其余 REJECT --reject-with tcp-reset
#   REJECT 不可用的内核退 DROP。放行用 RETURN 而不是 ACCEPT: 不越过 netd 自己的
#   INPUT 策略(fw_INPUT / bw_INPUT 等)。
# 幂等: 每次 apply 先 -F 链再重建; 跳转规则先 -C 再插, 重复跑不会叠加。
#
# 端口: HNC_WEBUI_PORTS(缺省 "8443 8080 8444" = HTTPS / HTTP→HTTPS 跳转 / loopback)
#
# 调用方: service.sh 在拉起 hnc_httpd 之前 apply; watchdog 全量恢复时 apply(自愈);
#         hnc_httpd 的 webui_access_set 动作改配置后 apply; cleanup.sh(all/restart)remove。
#
# 用法: webui_guard.sh apply|remove|status [--dry-run]
# 输出(最后一行): WEBUI_GUARD=applied mode=<m> entries=<n> v6=<0|1>
#                 WEBUI_GUARD=removed  |  WEBUI_GUARD=failed <原因>
# 退出码: 0 成功; 1 v4 规则落地失败; 2 用法错误
# 测试钩子: HNC_IPT / HNC_IP6T(iptables 命令, 可为桩), HNC_WEBUI_PORTS

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
CONF="$HNC_DIR/data/webui_access.json"
STATE="$HNC_DIR/run/webui_guard.state"
JSON_STATE="$HNC_DIR/run/webui_guard.json"
LOG="$HNC_DIR/logs/service.log"
CHAIN=HNC_WEBUI
PORTS=${HNC_WEBUI_PORTS:-"8443 8080 8444"}
CELL_IFACES="rmnet+ ccmni+ wwan+ seth_+ sipa_eth+ gti+ v4-+ clat+"
UPSTREAM_TUN_IFACES="tun+ wg+ ppp+ tailscale+ utun+ sing_tun+"
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}

CMD=${1:-apply}
DRY=0
JSON_OUT=0
[ "$2" = "--dry-run" ] && DRY=1
[ "$2" = "--json" ] && JSON_OUT=1
if [ "$CMD" = "--json" ]; then
    CMD=status
    JSON_OUT=1
fi

LAST_RUN_ERR=""
log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [webui_guard] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    local _err _rc
    _err=$("$@" 2>&1 >/dev/null)
    _rc=$?
    if [ "$_rc" -ne 0 ] && [ -n "$_err" ]; then
        LAST_RUN_ERR="$_err"
    fi
    return $_rc
}

if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$DRY" != "1" ]; then
    iptables -w 2 -L INPUT -n >/dev/null 2>&1 || {
        iptables -L INPUT -n >/dev/null 2>&1 && IPT="iptables"
    }
fi
if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$DRY" != "1" ] && command -v ip6tables >/dev/null 2>&1; then
    ip6tables -w 2 -L INPUT -n >/dev/null 2>&1 || {
        ip6tables -L INPUT -n >/dev/null 2>&1 && IP6T="ip6tables"
    }
fi

v6=0
if [ -n "$HNC_IP6T" ]; then
    v6=1
elif command -v ip6tables >/dev/null 2>&1 && $IP6T -L INPUT -n >/dev/null 2>&1; then
    v6=1
fi

valid_ifname() {
    case "$1" in ""|*[!a-zA-Z0-9_.-+]*) return 1 ;; esac
    [ "${#1}" -le 32 ]
}

detect_ap_iface() {
    local _ap="${HNC_WEBUI_AP_IFACE:-${HNC_WL_IFACE:-}}" _st _idj _ts _now _age _fresh _cand _f
    if [ -n "$_ap" ]; then
        valid_ifname "$_ap" && printf '%s' "$_ap"
        return 0
    fi
    # 若 hnc_state 存在: 非 ACTIVE:* (如 PENDING / PASSIVE) 直接认定当前无活跃热点,
    # 绝不回退读取陈旧的 iface_detect.json / hotspot_iface / data/rules.json!
    if [ -e "$HNC_DIR/run/hnc_state" ]; then
        [ -r "$HNC_DIR/run/hnc_state" ] || return 0
        _st=$(head -n 1 "$HNC_DIR/run/hnc_state" 2>/dev/null | tr -d ' \t\r\n')
        case "$_st" in
            ACTIVE:*)
                _ap="${_st#ACTIVE:}"
                valid_ifname "$_ap" && printf '%s' "$_ap"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    fi
    if [ -f "$HNC_DIR/run/iface_detect.json" ] && [ -r "$HNC_DIR/run/iface_detect.json" ]; then
        _idj=$(tr -d '\r\n' < "$HNC_DIR/run/iface_detect.json" 2>/dev/null) || _idj=""
        _ts=$(printf '%s' "$_idj" | grep -oE '"ts"[[:space:]]*:[[:space:]]*[0-9]+' | head -1 | sed 's/.*:[[:space:]]*//')
        _fresh=1
        if [ -n "$_ts" ]; then
            _now=$(date +%s 2>/dev/null || echo 0)
            case "$_now" in ''|*[!0-9]*) _now=0 ;; esac
            if [ "$_now" -gt 0 ] && [ "$_ts" -gt 0 ]; then
                _age=$((_now - _ts))
                [ "$_age" -gt "${HNC_IFACE_TTL:-120}" ] && _fresh=0
            fi
        fi
        if [ "$_fresh" = "1" ]; then
            _cand=$(printf '%s' "$_idj" | grep -oE '"iface"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
            if [ "$_cand" = "wlan0" ]; then
                if printf '%s' "$_idj" | grep -qE '"wlan0_ap"[[:space:]]*:[[:space:]]*true'; then
                    _ap="wlan0"
                elif [ -z "$_ts" ] && ! printf '%s' "$_idj" | grep -qE '"wlan0_ap"[[:space:]]*:[[:space:]]*false'; then
                    _ap="wlan0"
                fi
            elif [ -n "$_cand" ]; then
                _ap="$_cand"
            elif printf '%s' "$_idj" | grep -qE '"wlan0_ap"[[:space:]]*:[[:space:]]*true'; then
                _ap="wlan0"
            fi
        fi
    fi
    # 无 hnc_state 时的兜底文件仅允许非 wlan0 专用 AP 接口(防持久化 rules.json / 陈旧缓存误豁免公共 Wi-Fi wlan0)
    if [ -z "$_ap" ]; then
        for _f in "$HNC_DIR/run/hotspot_iface" "$HNC_DIR/run/active_iface" "$HNC_DIR/run/iface.cache"; do
            [ -f "$_f" ] && [ -r "$_f" ] || continue
            _cand=$(head -n 1 "$_f" 2>/dev/null | tr -d ' \t\r\n')
            if [ -n "$_cand" ] && [ "$_cand" != "wlan0" ]; then
                _ap="$_cand"
                break
            fi
        done
    fi
    if [ -z "$_ap" ] && [ -f "$HNC_DIR/data/rules.json" ] && [ -r "$HNC_DIR/data/rules.json" ]; then
        _cand=$(tr -d '\r\n' < "$HNC_DIR/data/rules.json" 2>/dev/null | grep -oE '"hotspot_iface"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        if [ -n "$_cand" ] && [ "$_cand" != "wlan0" ]; then
            _ap="$_cand"
        fi
    fi
    valid_ifname "$_ap" && printf '%s' "$_ap"
}

STA_AP_SAME=0
AP_IFACE_CACHE=""
check_sta_ap_same() {
    local _ap _idj _up="" _lup=""
    STA_AP_SAME=0
    _ap=$(detect_ap_iface)
    AP_IFACE_CACHE="$_ap"
    [ -n "$_ap" ] || return 1
    if [ -f "$HNC_DIR/run/iface_detect.json" ] && [ -r "$HNC_DIR/run/iface_detect.json" ]; then
        _idj=$(tr -d '\r\n' < "$HNC_DIR/run/iface_detect.json" 2>/dev/null) || _idj=""
        _up=$(printf '%s' "$_idj" | grep -oE '"upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        _lup=$(printf '%s' "$_idj" | grep -oE '"local_upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    fi
    if [ "$_ap" = "wlan0" ] || [ "$_up" = "$_ap" ] || [ "$_lup" = "$_ap" ]; then
        STA_AP_SAME=1
        return 0
    fi
    return 1
}

upstream_lan_ifaces() {
    local _ap _up="" _lup="" _idj _list="" _cand
    _ap=$(detect_ap_iface)
    if [ -f "$HNC_DIR/run/iface_detect.json" ] && [ -r "$HNC_DIR/run/iface_detect.json" ]; then
        _idj=$(tr -d '\r\n' < "$HNC_DIR/run/iface_detect.json" 2>/dev/null) || _idj=""
        _up=$(printf '%s' "$_idj" | grep -oE '"upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        _lup=$(printf '%s' "$_idj" | grep -oE '"local_upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    fi
    # 公共 Wi-Fi 上游 STA(wlan0): 仅当当前热点口不是 wlan0 时封堵, 保护单芯片 wlan0 AP 机型
    if [ "$_ap" != "wlan0" ]; then
        _list="wlan0"
    fi
    # 有线上游口 eth+: 只要当前热点口不是 eth* 即封堵
    case "$_ap" in
        eth*) ;;
        *) _list="$_list eth+" ;;
    esac
    # 动态识别到的其他非热点上游口(如双 Wi-Fi STA 副口 wlan1)
    for _cand in "$_up" "$_lup"; do
        valid_ifname "$_cand" || continue
        [ "$_cand" = "$_ap" ] && continue
        [ "$_cand" = "lo" ] && continue
        case "$_cand" in
            rmnet*|ccmni*|wwan*|seth_*|sipa_eth*|gti*|v4-*|clat*|eth*|tun*|wg*|ppp*|tailscale*|utun*|sing_tun*) continue ;;
        esac
        case " $_list " in
            *" $_cand "*) ;;
            *) _list="$_list $_cand" ;;
        esac
    done
    printf '%s' "${_list# }"
}

# ─── 配置解析 ────────────────────────────────────────────────────
MODE=all
ENTRIES=""
CONF_ERR=""
read_conf() {
    MODE=all
    ENTRIES=""
    CONF_ERR=""
    [ -e "$CONF" ] || return 0
    if [ ! -r "$CONF" ]; then
        log "WARN: $CONF permission denied, fail-closed to local_only"
        MODE=local_only
        CONF_ERR="permission_denied"
        return 0
    fi
    if ! _c=$(tr -d '\r\n' < "$CONF" 2>/dev/null); then
        log "WARN: $CONF read failed, fail-closed to local_only"
        MODE=local_only
        CONF_ERR="permission_denied"
        return 0
    fi
    MODE=$(printf '%s' "$_c" | grep -oE '"mode"[[:space:]]*:[[:space:]]*"[a-z_]*"' | head -1 \
           | sed 's/.*"\([a-z_]*\)"$/\1/')
    case "$MODE" in
        all|allowlist|local_only) ;;
        *) log "WARN: bad/missing mode in $CONF ('$MODE'), fail-closed to local_only"; MODE=local_only ;;
    esac
    _l=$(printf '%s' "$_c" | grep -oE '"macs"[[:space:]]*:[[:space:]]*\[[^]]*\]' | head -1 \
         | sed 's/^[^[]*\[//; s/\]$//' | tr ',' ' ' | tr -d '"')
    for _e in $_l; do
        _e=$(printf '%s' "$_e" | tr 'A-F' 'a-f')
        if is_mac "$_e" || is_ipv4 "$_e" || is_ipv6 "$_e"; then
            ENTRIES="$ENTRIES $_e"
        else
            log "WARN: skip invalid allowlist entry '$_e'"
        fi
    done
    unset _c _l _e
}

is_mac() {
    printf '%s' "$1" | grep -qE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
}
is_ipv4() {
    printf '%s' "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}
is_ipv6() {
    # 至少两个冒号, 只含 hex / 冒号 / 点(v4 尾); 排除 MAC
    is_mac "$1" && return 1
    printf '%s' "$1" | grep -qE '^[0-9a-f:.]+$' || return 1
    case "$1" in *:*:*) return 0 ;; esac
    return 1
}

# ─── 规则 ────────────────────────────────────────────────────────
reject_tail() {  # $1=iptables 命令
    run $1 -A $CHAIN -p tcp -j REJECT --reject-with tcp-reset || run $1 -A $CHAIN -j DROP
}

teardown() {  # $1=iptables 命令
    for _p in $PORTS; do
        _i=0
        while run $1 -D INPUT -p tcp --dport "$_p" -j $CHAIN; do
            _i=$((_i + 1)); [ "$_i" -ge 20 ] && break; [ "$DRY" = 1 ] && break
        done
    done
    run $1 -F $CHAIN
    run $1 -X $CHAIN
    unset _p _i
}

build() {  # $1=iptables 命令  $2=4|6
    _T=$1
    LAST_RUN_ERR=""
    _wan_lan=$(upstream_lan_ifaces)
    run $_T -N $CHAIN          # 已存在时失败, 无妨
    run $_T -F $CHAIN || return 1
    run $_T -A $CHAIN -i lo -j RETURN || return 1
    for _c in $CELL_IFACES $_wan_lan $UPSTREAM_TUN_IFACES; do
        run $_T -A $CHAIN -i "$_c" -p tcp -j REJECT --reject-with tcp-reset \
            || run $_T -A $CHAIN -i "$_c" -j DROP
    done
    case "$MODE" in
        all)
            run $_T -A $CHAIN -j RETURN || return 1
            ;;
        allowlist)
            for _e in $ENTRIES; do
                if is_mac "$_e"; then
                    run $_T -A $CHAIN -m mac --mac-source "$_e" -j RETURN \
                        || log "WARN: v$2 mac match failed for $_e (xt_mac missing?)"
                elif [ "$2" = 4 ] && is_ipv4 "$_e"; then
                    run $_T -A $CHAIN -s "$_e" -j RETURN
                elif [ "$2" = 6 ] && is_ipv6 "$_e"; then
                    run $_T -A $CHAIN -s "$_e" -j RETURN
                fi
            done
            reject_tail "$_T" || return 1
            ;;
        local_only)
            reject_tail "$_T" || return 1
            ;;
    esac
    for _p in $PORTS; do
        if ! run $_T -C INPUT -p tcp --dport "$_p" -j $CHAIN || [ "$DRY" = 1 ]; then
            run $_T -I INPUT 1 -p tcp --dport "$_p" -j $CHAIN || return 1
        fi
    done
    unset _T _c _e _p _wan_lan
    return 0
}

classify_ipt_err() {
    local _bin="${1%% *}"
    if [ "$DRY" != "1" ] && [ "$_bin" != "sh" ] && ! command -v "$_bin" >/dev/null 2>&1 && [ ! -x "$_bin" ]; then
        echo "node_missing"
        return 0
    fi
    case "$(printf '%s' "$LAST_RUN_ERR" | tr 'A-Z' 'a-z')" in
        *no\ such\ file*|*not\ found*|*does\ not\ exist*|*can\'t\ initialize*)
            echo "node_missing"
            ;;
        *)
            echo "permission_denied"
            ;;
    esac
}

write_state() {
    [ "$DRY" = 1 ] && return 0
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    local _stmp="$STATE.tmp.$$"
    if printf '%s\n' "$1" > "$_stmp" 2>/dev/null && [ -s "$_stmp" ]; then
        mv -f "$_stmp" "$STATE" 2>/dev/null || rm -f "$_stmp" 2>/dev/null || true
    else
        rm -f "$_stmp" 2>/dev/null || true
    fi
}

write_json_state() {  # $1=state $2=mode $3=entries $4=v4 $5=v6 $6=reason_code $7=detail
    [ "$DRY" = 1 ] && return 0
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    local _jtmp="$JSON_STATE.tmp.$$" _ts _det
    _ts=$(date +%s 2>/dev/null || echo 0)
    _det=$(printf '%s' "$7" | tr -d '"\\\r\n')
    if printf '{"state":"%s","mode":"%s","entries":%s,"ap_iface":"%s","v4":"%s","v6":"%s","reason_code":"%s","detail":"%s","ts":%s}\n' \
        "$1" "$2" "${3:-0}" "${AP_IFACE_CACHE:-}" "$4" "$5" "$6" "$_det" "$_ts" > "$_jtmp" 2>/dev/null && [ -s "$_jtmp" ]; then
        mv -f "$_jtmp" "$JSON_STATE" 2>/dev/null || rm -f "$_jtmp" 2>/dev/null || true
    else
        rm -f "$_jtmp" 2>/dev/null || true
    fi
}

count_entries() { set -- $ENTRIES; echo $#; }

case "$CMD" in
    apply)
        read_conf
        check_sta_ap_same || true
        n=$(count_entries)
        if ! build "$IPT" 4; then
            _f_rc=$(classify_ipt_err "$IPT")
            log "ERROR: v4 apply failed (mode=$MODE reason=$_f_rc)"
            write_state "failed mode=$MODE v4=fail reason_code=$_f_rc ts=$(date +%s 2>/dev/null || echo 0)"
            write_json_state "failed" "$MODE" "$n" "fail" "skip" "$_f_rc" "iptables v4 apply failed"
            echo "WEBUI_GUARD=failed v4"
            exit 1
        fi
        v6s=skip
        if [ "$v6" = 1 ]; then
            if build "$IP6T" 6; then v6s=ok; else v6s=fail; log "WARN: v6 apply failed (mode=$MODE)"; fi
        fi
        _ok_rc="ok"
        _ok_det="webui firewall guard active"
        if [ -n "$CONF_ERR" ]; then
            _ok_rc="$CONF_ERR"
            _ok_det="config unreadable, fail-closed to local_only"
        elif [ "$STA_AP_SAME" = "1" ]; then
            _ok_rc="sta_ap_same_iface"
            _ok_det="single-iface AP detected (${AP_IFACE_CACHE}), preserved AP access on shared interface"
        fi
        log "applied mode=$MODE entries=$n v6=$v6s reason_code=$_ok_rc ports=$PORTS"
        write_state "applied mode=$MODE entries=$n v4=ok v6=$v6s reason_code=$_ok_rc ts=$(date +%s 2>/dev/null || echo 0)"
        write_json_state "applied" "$MODE" "$n" "ok" "$v6s" "$_ok_rc" "$_ok_det"
        echo "WEBUI_GUARD=applied mode=$MODE entries=$n v6=$v6"
        ;;
    remove)
        AP_IFACE_CACHE=""
        teardown "$IPT"
        [ "$v6" = 1 ] && teardown "$IP6T"
        log "removed"
        write_state "removed reason_code=ok ts=$(date +%s 2>/dev/null || echo 0)"
        write_json_state "removed" "all" "0" "removed" "removed" "ok" "webui firewall guard removed"
        echo "WEBUI_GUARD=removed"
        ;;
    status)
        read_conf
        check_sta_ap_same || true
        _sn=$(count_entries)
        if [ "$JSON_OUT" = "1" ]; then
            if [ -r "$JSON_STATE" ] && [ -s "$JSON_STATE" ]; then
                cat "$JSON_STATE" 2>/dev/null
            else
                _s_rc="ok"
                [ -n "$CONF_ERR" ] && _s_rc="$CONF_ERR"
                [ -z "$CONF_ERR" ] && [ "$STA_AP_SAME" = "1" ] && _s_rc="sta_ap_same_iface"
                printf '{"state":"unknown","mode":"%s","entries":%s,"ap_iface":"%s","v4":"unknown","v6":"%s","reason_code":"%s","detail":"not applied yet","ts":0}\n' \
                    "$MODE" "$_sn" "${AP_IFACE_CACHE:-}" "$v6" "$_s_rc"
            fi
        else
            echo "mode=$MODE entries=$_sn ports=$PORTS v6=$v6"
            [ -f "$STATE" ] && [ -r "$STATE" ] && cat "$STATE" 2>/dev/null
        fi
        ;;
    *)
        echo "usage: webui_guard.sh apply|remove|status [--dry-run|--json]" >&2
        exit 2
        ;;
esac
exit 0
