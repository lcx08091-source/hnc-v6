#!/system/bin/sh
# quic_block_sync.sh — v5.40.0 双栈「强制 QUIC 回落 TCP」全局开关 (IPv4 + IPv6)
#
# 做法: 独立链 HNC_QUIC 挂在双栈 filter/FORWARD 第 1 位:
#   - IPv4: -i <iface> -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
#   - IPv6: -i <iface> -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable
# 输出契约(末行): QUIC_BLOCK=off | QUIC_BLOCK=pending | QUIC_BLOCK=on iface=<iface>

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES="$HNC_DIR/data/rules.json"
LOG="$HNC_DIR/logs/service.log"
DRY=0
[ "$1" = "--dry-run" ] && DRY=1
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [quic_block] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    "$@" 2>/dev/null
}

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

v6=0
_ip6_bin="${IP6T%% *}"
if command -v "$_ip6_bin" >/dev/null 2>&1; then
    if [ "$DRY" = "1" ] || $IP6T -t filter -L -n >/dev/null 2>&1; then
        v6=1
    fi
fi

teardown() {
    local T i
    for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
        [ -n "$T" ] || continue
        i=0
        while run $T -t filter -D FORWARD -j HNC_QUIC; do
            i=$((i + 1))
            [ "$i" -ge 20 ] && break
            [ "$DRY" = 1 ] && break
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
run $IPT -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
run $IPT -t filter -I FORWARD 1 -j HNC_QUIC || log "WARN: v4 link failed"
if [ "$v6" = 1 ]; then
    run $IP6T -t filter -N HNC_QUIC
    run $IP6T -t filter -A HNC_QUIC -i "$iface" -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable
    run $IP6T -t filter -I FORWARD 1 -j HNC_QUIC || log "WARN: v6 link failed"
fi
log "mode=on iface=$iface v6=$v6"
echo "QUIC_BLOCK=on iface=$iface"
