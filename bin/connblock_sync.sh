#!/system/bin/sh
# connblock_sync.sh — 「封锁这个域名 / IP(仅这台设备)」落到 iptables(v5.16)
#
# 来源: WebUI 实时连接里点一条连接 → 封锁。hnc_httpd 把 data/conn_blocks.json
# (按设备的域名 / IP 封锁项)展开成 run/conn_blocks.flat —— 每行 "<mac> <ip>",
# 域名按 dpid 的 DNS/SNI 反查表展开成当前解析到的全部 IP, 反查表变化时 httpd
# 会重新展开并再次调用本脚本(域名换 IP 也能跟上)。
#
# 做法: 独立链 HNC_CONNBLK 挂在 filter/FORWARD 第 1 位; 每条
#   -m mac --mac-source <mac> -d <ip> -j REJECT
# 只拦这台设备发往该 IP 的包(客户端→外网方向, MAC 在热点口上可见);
# 用 REJECT 让 App 立刻失败而不是一直转圈。幂等, 随时可重跑。
#
# 调用方: hnc_httpd(conn_block_add/del、反查表变化); watchdog 在 iptables init /
#        热点接口迁移后(与 whitelist_sync.sh 同一位置)。
# 输出(最后一行): CONN_BLOCK=off  或  CONN_BLOCK=on rules=<条数>
# 用法: connblock_sync.sh [--dry-run]

HNC_DIR=${HNC_DIR:-/data/local/hnc}
FLAT="$HNC_DIR/run/conn_blocks.flat"
LOG="$HNC_DIR/logs/service.log"
DRY=0
[ "$1" = "--dry-run" ] && DRY=1
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
MAX_RULES=2000

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [connblock] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    "$@" 2>/dev/null
}

v6=0
command -v ip6tables >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1 && v6=1

for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
    [ -n "$T" ] || continue
    i=0
    while run $T -t filter -D FORWARD -j HNC_CONNBLK; do i=$((i + 1)); [ "$i" -ge 20 ] && break; [ "$DRY" = 1 ] && break; done
    run $T -t filter -F HNC_CONNBLK
    run $T -t filter -X HNC_CONNBLK
done

if [ ! -s "$FLAT" ]; then
    echo "CONN_BLOCK=off"
    exit 0
fi

run $IPT -t filter -N HNC_CONNBLK
[ "$v6" = 1 ] && run $IP6T -t filter -N HNC_CONNBLK
n=0
while read -r mac ip _; do
    case "$mac" in
        [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
        *) continue ;;
    esac
    case "$ip" in
        *[!0-9a-fA-F:.]*|"") continue ;;   # 只接受 IP 字面量, 防注入
        *:*) [ "$v6" = 1 ] || continue; T=$IP6T ;;
        *) T=$IPT ;;
    esac
    run $T -t filter -A HNC_CONNBLK -m mac --mac-source "$mac" -d "$ip" -j REJECT && n=$((n + 1))
    [ "$n" -ge "$MAX_RULES" ] && { log "WARN: rule cap $MAX_RULES reached"; break; }
done < "$FLAT"
run $IPT -t filter -I FORWARD 1 -j HNC_CONNBLK || log "WARN: v4 link failed"
[ "$v6" = 1 ] && { run $IP6T -t filter -I FORWARD 1 -j HNC_CONNBLK || log "WARN: v6 link failed"; }
log "rules=$n v6=$v6"
echo "CONN_BLOCK=on rules=$n"
