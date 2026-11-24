#!/system/bin/sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# quic_block_sync.sh — v5.40.0 双栈「强制 QUIC 回落 TCP」全局开关 (IPv4 + IPv6)
#
# 做法: 独立链 HNC_QUIC 挂在双栈 filter/FORWARD 第 1 位:
#   - IPv4: -i <iface> -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable (缺 xt_REJECT 回退 DROP)
#   - IPv6: -i <iface> -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable (缺 ip6t_REJECT 回退 DROP)
# 输出契约(末行): QUIC_BLOCK=off | QUIC_BLOCK=pending | QUIC_BLOCK=on iface=<iface>

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
command -v hnc_fwd_insert_pos >/dev/null 2>&1 || {
    hnc_fwd_insert_pos() {
        local _c="$1" _t="$2" _p
        [ -n "$_c" ] && [ -n "$_t" ] || { echo 1; return 0; }
        _p=$($_c -t filter -S FORWARD 2>/dev/null | awk -v target="$_t" '
            BEGIN {
                ord["HNC_SCALPEL"]=1; ord["HNC_ISOLATE"]=2; ord["HNC_CTRL"]=3
                ord["HNC_WHITELIST"]=4; ord["HNC_QUIC"]=5; ord["HNC_QUIC_APPLIM"]=6
                ord["HNC_ENCDNS"]=7; ord["HNC_CONNBLK_DNS"]=8; ord["HNC_CONNBLK"]=9
                t_ord = ord[target] + 0; idx = 0; last_pred = 0
            }
            $1 == "-A" && $2 == "FORWARD" {
                idx++; ch = ""
                for (i = 3; i < NF; i++) if ($i == "-j" || $i == "-g") { ch = $(i+1); break }
                if (ch != "" && (ch in ord) && ord[ch] < t_ord) last_pred = idx
            }
            END { printf "%d\n", last_pred + 1 }
        ' 2>/dev/null)
        case "$_p" in ''|*[!0-9]*|0) _p=1 ;; esac
        printf '%s\n' "$_p"
    }
}
RULES="$HNC_DIR/data/rules.json"
LOG="$HNC_DIR/logs/service.log"
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v iptables >/dev/null 2>&1; then
    iptables -w 2 -t filter -L -n >/dev/null 2>&1
    if [ $? -eq 2 ]; then
        iptables -w -t filter -L -n >/dev/null 2>&1
        [ $? -eq 2 ] && IPT="iptables" || IPT="iptables -w"
    fi
fi
if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v ip6tables >/dev/null 2>&1; then
    ip6tables -w 2 -t filter -L -n >/dev/null 2>&1
    if [ $? -eq 2 ]; then
        ip6tables -w -t filter -L -n >/dev/null 2>&1
        [ $? -eq 2 ] && IP6T="ip6tables" || IP6T="ip6tables -w"
    fi
fi

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [quic_block] $*" >> "$LOG"; } 2>/dev/null; }
run() { "$@" 2>/dev/null; }

mode=false
if [ -f "$RULES" ]; then
    mode=$(tr -d '\r\n' < "$RULES" 2>/dev/null | grep -oE '"quic_block"[[:space:]]*:[[:space:]]*(true|false)' \
           | head -1 | grep -oE 'true|false')
    [ -n "$mode" ] || mode=false
fi

iface=${HNC_WL_IFACE:-}
if [ -z "$iface" ]; then
    case "$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null)" in
        ACTIVE:*)
            iface=$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null)
            iface=${iface#ACTIVE:}
            iface=$(printf '%s' "$iface" | tr -d ' \r\n')
            ;;
    esac
fi
case "$iface" in *[!A-Za-z0-9_.-]*) iface="" ;; esac

v6=0
_ip6_bin="${IP6T%% *}"
if command -v "$_ip6_bin" >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1; then
    v6=1
fi

teardown() {
    local T i
    for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
        [ -n "$T" ] || continue
        i=0
        while run $T -t filter -D FORWARD -j HNC_QUIC; do
            i=$((i + 1))
            [ "$i" -ge 20 ] && break
        done
        run $T -t filter -F HNC_QUIC
        run $T -t filter -X HNC_QUIC
    done
}

teardown
if [ "$mode" != "true" ]; then
    log "mode=off, chain removed"
    echo "QUIC_BLOCK=off"
    exit 0
fi
if [ -z "$iface" ]; then
    log "mode=on but hotspot iface unknown, deferred"
    echo "QUIC_BLOCK=pending"
    exit 0
fi

run $IPT -t filter -N HNC_QUIC
run $IPT -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable \
    || run $IPT -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j DROP
_qpos4=$(hnc_fwd_insert_pos "$IPT" HNC_QUIC)
run $IPT -t filter -I FORWARD "$_qpos4" -j HNC_QUIC || log "WARN: v4 link failed"
if [ "$v6" = 1 ]; then
    run $IP6T -t filter -N HNC_QUIC
    run $IP6T -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable \
        || run $IP6T -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j DROP
    _qpos6=$(hnc_fwd_insert_pos "$IP6T" HNC_QUIC)
    run $IP6T -t filter -I FORWARD "$_qpos6" -j HNC_QUIC || log "WARN: v6 link failed"
fi
log "mode=on iface=$iface v6=$v6"
echo "QUIC_BLOCK=on iface=$iface"
