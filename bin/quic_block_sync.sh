#!/system/bin/sh
# quic_block_sync.sh — 「强制 QUIC 回落 TCP」开关落到 iptables(v5.14)
#
# 为什么: QUIC(HTTP/3, UDP 443)的握手虽然能被 dpid 解出域名, 但仍有盲区
# (加密的 gQUIC Q050+、私有协议、解析失败的包); 而同一个 App 走 TCP 时 TLS
# 握手里的 SNI 一定看得到。抖音/快手/B 站/YouTube 等在 UDP 443 被拒后都会
# 秒级回落到 TCP 443, 应用识别与限速都会更准。
# 代价: 首包慢几十毫秒; 极少数只支持 QUIC 的服务可能受影响。默认关闭。
#
# 做法: 独立链 HNC_QUIC 挂在 filter/FORWARD 第 1 位, 开启时对热点口进来的
# UDP 目的 443 回 REJECT(icmp port-unreachable) —— 用 REJECT 不用 DROP:
# DROP 要等客户端超时(数秒)才回落, REJECT 立即回落。
# 幂等, 随时可重跑。rules.json 顶层 quic_block=true|false。
#
# 调用方: hnc_httpd 的 quic_block_set 动作; watchdog 在 iptables init / 热点
#        接口迁移后(与 whitelist_sync.sh 同一位置)。
# 接口: HNC_WL_IFACE 优先, 否则取 run/hnc_state 的 ACTIVE:<iface>。
# 输出(最后一行): QUIC_BLOCK=off  或  QUIC_BLOCK=on iface=<iface>
# 用法: quic_block_sync.sh [--dry-run]

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
    case "$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null)" in ACTIVE:*) iface=$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null); iface=${iface#ACTIVE:} ;; esac
fi

v6=0
command -v ip6tables >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1 && v6=1

teardown() {
    for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
        [ -n "$T" ] || continue
        i=0
        while run $T -t filter -D FORWARD -j HNC_QUIC; do i=$((i + 1)); [ "$i" -ge 20 ] && break; [ "$DRY" = 1 ] && break; done
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
    # 热点没开: 什么都不挂, 等 watchdog 在热点起来后再同步
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
