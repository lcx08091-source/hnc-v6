#!/system/bin/sh
# dns_takeover.sh — DPI v2「HNC DNS 接管」的 iptables 部分(由 hnc_httpd 调用)
#
# 打开后, 热点设备发给「网关自身地址」的 DNS(udp/tcp 53)被 DNAT 到 httpd 内的
# 转发器(默认 :15353)。转发器再把查询原样转给网关 :53(系统给热点用的解析器),
# 所以答案不变, 但 HNC 能精确记录每台设备查了什么、并在解析器层按设备封锁。
#
# 防环 / 安全:
#   · 只在 nat/PREROUTING 做, 且只匹配 -i <热点口> 的入包: 本机自己发出的包
#     (含转发器发往上游的查询)只走 OUTPUT, 永远不会被改写;
#   · 只 DNAT 目的地址 = 热点口自身地址的包; 设备写死的 8.8.8.8 等公共 DNS 不动;
#   · httpd 健康检查失败 / 停机 / 被杀(watchdog 发现)/ cleanup.sh 都会调 remove,
#     设备回到系统 DNS(fail-open)。
#
# 链(幂等, 每次 apply 先整体拆掉再建):
#   nat    HNC_DNSTK     挂 PREROUTING 第 1 位: -i <iface> -d <网关地址> -p udp|tcp --dport 53
#                        -j DNAT --to-destination <listen>:<port>
#   filter HNC_DNSTK_IN  挂 INPUT 第 1 位: -i <iface> -p udp|tcp --dport <port> -j ACCEPT
#   IPv6: ip6tables 有 nat 表且支持 DNAT 时同样建一份(每个 v6 地址 DNAT 到它自己的
#         [addr]:port); 否则输出 v6=unsupported, IPv6 DNS 不接管。
#
# 用法:
#   dns_takeover.sh apply <iface> <port> <listen4> <dst4,dst4..> [<v6addr,v6addr..>]
#     → 最后一行 DNSTK=on iface=<iface> port=<port> rules=<n> v6=<n|0|unsupported>
#   dns_takeover.sh remove      → DNSTK=off
#   dns_takeover.sh counters    → {"present":bool,"pkts":N,"v6_present":bool,"pkts_v6":N}
#                                 (DNAT 规则命中包数; nat 表只看每条连接的首包)
# 环境: HNC_IPT / HNC_IP6T 覆盖 iptables 命令(测试用)

HNC_DIR=${HNC_DIR:-/data/local/hnc}
LOG="$HNC_DIR/logs/service.log"
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
C_NAT=HNC_DNSTK
C_IN=HNC_DNSTK_IN

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [dns_takeover] $*" >> "$LOG"; } 2>/dev/null; }

has_v6() {
    if [ -n "${HNC_IP6T:-}" ]; then
        $IP6T -t filter -L -n >/dev/null 2>&1
        return
    fi
    command -v ip6tables >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1
}

teardown_family() {
    # $1 = iptables 命令
    _T=$1
    _i=0
    while $_T -t nat -D PREROUTING -j "$C_NAT" 2>/dev/null; do _i=$((_i + 1)); [ "$_i" -ge 20 ] && break; done
    _i=0
    while $_T -t filter -D INPUT -j "$C_IN" 2>/dev/null; do _i=$((_i + 1)); [ "$_i" -ge 20 ] && break; done
    $_T -t nat -F "$C_NAT" 2>/dev/null
    $_T -t nat -X "$C_NAT" 2>/dev/null
    $_T -t filter -F "$C_IN" 2>/dev/null
    $_T -t filter -X "$C_IN" 2>/dev/null
    return 0
}

teardown_all() {
    teardown_family "$IPT"
    has_v6 && teardown_family "$IP6T"
    return 0
}

valid_iface() { case "$1" in ""|*[!a-zA-Z0-9_.-]*) return 1 ;; esac; [ "${#1}" -le 32 ]; }
valid_port() {
    case "$1" in ""|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}
valid_v4() {
    case "$1" in ""|*[!0-9.]*) return 1 ;; esac
    _o=$(echo "$1" | awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i == "" || $i > 255) { print 0; exit } print 1; exit } { print 0 }')
    [ "$_o" = 1 ]
}
valid_v6() {
    case "$1" in ""|*[!0-9a-fA-F:]*) return 1 ;; *:*) ;; *) return 1 ;; esac
    [ "${#1}" -le 39 ]
}

# 统计某族 HNC_DNSTK 里 DNAT 规则的包数; 链不存在输出 "0 0"
counters_family() {
    if ! $1 -t nat -nL "$C_NAT" >/dev/null 2>&1; then
        echo "0 0"
        return
    fi
    $1 -t nat -nvxL "$C_NAT" 2>/dev/null | awk '
        BEGIN { p = 0 }
        $1 ~ /^[0-9]+$/ && $0 ~ /DNAT/ { p += $1 }
        END { printf "1 %d\n", p }'
}

case "$1" in
    remove)
        teardown_all
        log "removed"
        echo "DNSTK=off"
        exit 0
        ;;
    counters)
        set -- $(counters_family "$IPT")
        p4=${1:-0}; k4=${2:-0}
        p6=0; k6=0
        if has_v6; then
            set -- $(counters_family "$IP6T")
            p6=${1:-0}; k6=${2:-0}
        fi
        pres=false; [ "$p4" = 1 ] && pres=true
        pres6=false; [ "$p6" = 1 ] && pres6=true
        printf '{"present":%s,"pkts":%d,"v6_present":%s,"pkts_v6":%d}\n' "$pres" "$k4" "$pres6" "$k6"
        exit 0
        ;;
    apply) ;;
    *)
        echo "usage: dns_takeover.sh apply <iface> <port> <listen4> <dst4,..> [<v6,..>] | remove | counters" >&2
        exit 2
        ;;
esac

iface=$2; port=$3; listen4=$4; dst4=$5; dst6=$6
if ! valid_iface "$iface" || ! valid_port "$port" || ! valid_v4 "$listen4"; then
    echo "DNSTK=error bad_args"
    exit 2
fi
d4=""
for a in $(echo "$dst4" | tr ',' ' '); do
    valid_v4 "$a" && d4="$d4 $a"
done
[ -n "$d4" ] || d4=" $listen4"
d6=""
for a in $(echo "$dst6" | tr ',' ' '); do
    valid_v6 "$a" && d6="$d6 $a"
done

# 先整体拆(幂等), 再建
teardown_all

nr=0
fail=0
$IPT -t nat -N "$C_NAT" 2>/dev/null
$IPT -t filter -N "$C_IN" 2>/dev/null
for a in $d4; do
    for p in udp tcp; do
        if $IPT -t nat -A "$C_NAT" -i "$iface" -d "$a" -p "$p" --dport 53 -j DNAT --to-destination "$listen4:$port" 2>/dev/null; then
            nr=$((nr + 1))
        else
            fail=1
        fi
    done
done
for p in udp tcp; do
    $IPT -t filter -A "$C_IN" -i "$iface" -p "$p" --dport "$port" -j ACCEPT 2>/dev/null || fail=1
done
$IPT -t filter -I INPUT 1 -j "$C_IN" 2>/dev/null || fail=1
# 链接 PREROUTING 放最后: 前面任何一步失败都不让流量进来
if [ "$fail" = 0 ] && [ "$nr" -gt 0 ]; then
    $IPT -t nat -I PREROUTING 1 -j "$C_NAT" 2>/dev/null || fail=1
fi
if [ "$fail" != 0 ] || [ "$nr" = 0 ]; then
    teardown_all
    log "apply FAILED iface=$iface listen=$listen4:$port (rules=$nr) — removed, DNS untouched"
    echo "DNSTK=error apply_failed"
    exit 1
fi

v6=0
if [ -n "$d6" ]; then
    if has_v6 && $IP6T -t nat -N "$C_NAT" 2>/dev/null; then
        n6=0; f6=0
        for a in $d6; do
            for p in udp tcp; do
                if $IP6T -t nat -A "$C_NAT" -i "$iface" -d "$a" -p "$p" --dport 53 -j DNAT --to-destination "[$a]:$port" 2>/dev/null; then
                    n6=$((n6 + 1))
                else
                    f6=1
                fi
            done
        done
        if [ "$f6" = 0 ] && [ "$n6" -gt 0 ]; then
            $IP6T -t filter -N "$C_IN" 2>/dev/null
            for p in udp tcp; do
                $IP6T -t filter -A "$C_IN" -i "$iface" -p "$p" --dport "$port" -j ACCEPT 2>/dev/null || f6=1
            done
            $IP6T -t filter -I INPUT 1 -j "$C_IN" 2>/dev/null || f6=1
            [ "$f6" = 0 ] && { $IP6T -t nat -I PREROUTING 1 -j "$C_NAT" 2>/dev/null || f6=1; }
        fi
        if [ "$f6" = 0 ] && [ "$n6" -gt 0 ]; then
            v6=$n6
        else
            teardown_family "$IP6T"
            v6=unsupported
        fi
    else
        v6=unsupported
    fi
fi
log "applied iface=$iface listen=$listen4:$port dst4=$(echo $d4 | tr ' ' ',') rules=$nr v6=$v6"
echo "DNSTK=on iface=$iface port=$port rules=$nr v6=$v6"
