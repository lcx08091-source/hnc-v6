#!/system/bin/sh
# encdns_sync.sh — 加密 DNS 策略(v5.21)落到 iptables
#
# 为什么: 设备走 DoT(853)/ DoQ(udp 853)/ DoH(443)时, 热点看不到它查了哪些域名,
# 应用识别只能靠 TLS SNI; 「封锁域名」的 DNS 层也拦不住。把加密 DNS 挡掉后,
# Android「私人 DNS = 自动」、Chrome「安全 DNS = 自动」等会秒级回落到明文 53,
# dpid 就能看见每一次解析, 识别率和封锁效果都会明显提升。
#
# 档位(data/encdns.json, httpd 的 encdns_set 动作写; 形如
#   {"policy":"off|dot|strict","devices":{"aa:bb:cc:dd:ee:ff":"off|dot|strict"}}):
#   off    —— 不干预(默认)
#   dot    —— 拒绝 tcp/853(DoT, tcp-reset)与 udp/853(DoQ, icmp 端口不可达)
#   strict —— dot + 拦截公共 DoH 解析器:
#             · 解析器 IP(只提供 DNS 的地址, 如 8.8.8.8 / 1.1.1.1 / 223.5.5.5)
#               的 tcp/udp 443 → REJECT;
#             · 解析器主机名(dns.google、cloudflare-dns.com、doh.pub ...):
#               明文 DNS 查询(udp/tcp 53, qname 线格式后缀)→ DROP, 让 App 根本
#               拿不到 DoH 服务器地址; TLS ClientHello 里 SNI 等于该名字的 443
#               连接 → tcp-reset(覆盖共享 CDN IP 上的 DoH)。后两者需要 xt_string,
#               内核没有时静默只做 IP 层(caps 写 run/encdns_caps.json)。
#   名单: data/encdns_resolvers.txt(模块自带; /data/local/hnc/etc/ 下同名文件优先)。
#   范围: policy 作用于热点口(-i <iface>)上的全部设备; devices 按 MAC 覆盖
#         (包括 "off" = 这台设备不受全局策略影响)。热点没开(接口未知)时全局部分
#         延后, 按 MAC 的覆盖照常下发。
#
# 取舍(一定要让用户知道): 设备若把「私人 DNS」设成「指定主机名」(严格模式,
# 如 dns.google / dns.alidns.com), dot/strict 下它的 DoT 被拒后不会回落明文,
# 这台设备会整体「无法上网」(所有域名都解析失败)。遇到这种设备: 让用户把私人
# DNS 改成「自动」, 或在这里给它单独设 "off"。
#
# 链结构(幂等, 每次全量重建; IPv4 与 IPv6 各一份):
#   HNC_ENCDNS        挂 filter/INPUT 与 FORWARD 第 1 位(INPUT: 发给热点自身 dnsmasq
#                     的查询; FORWARD: 发往外网的一切), 按 MAC 覆盖在前(末尾 RETURN),
#                     全局(-i iface)在后; 只把 53/443/853 端口的包跳进子链。
#   HNC_ENCDNS_DOT    853 拒绝规则
#   HNC_ENCDNS_STRICT 先跳 DOT, 再是解析器 IP / SNI / DNS 名字规则
#
# 计数: encdns_sync.sh --counters 输出一行 JSON(iptables -nvxL 的包/字节计数):
#   {"chain":bool,"v6":bool,"dot":{"pkts","bytes"},"doh_ip":{..},"doh_sni":{..},
#    "doh_dns":{..},"total_pkts":N,"total_bytes":N,"v4_pkts":N,"v6_pkts":N}
#   包数 ≈ 被挡下的尝试次数(tcp-reset 后客户端的重试也会计入)。每次重同步清零。
#
# 调用方: hnc_httpd(encdns_set 动作、GET /api/encdns 读计数); watchdog 在 iptables
#        init / 热点接口迁移后(与 quic_block_sync.sh 同一位置)。
# 输出(最后一行): ENCDNS=off
#   或 ENCDNS=on global=<off|dot|strict|pending> devices=<n> rules=<n> string_layer=<1|0>
# 用法: encdns_sync.sh [--dry-run | --counters]
# 环境: HNC_ENCDNS_IFACE / HNC_WL_IFACE 指定热点口; HNC_ENCDNS_LIST 指定名单文件;
#       HNC_ENCDNS_REPROBE=1 强制重新探测 xt_string

HNC_DIR=${HNC_DIR:-/data/local/hnc}
CONF="$HNC_DIR/data/encdns.json"
CAPS="$HNC_DIR/run/encdns_caps.json"
LOG="$HNC_DIR/logs/service.log"
DRY=0
MODE=sync
case "$1" in
    --dry-run) DRY=1 ;;
    --counters) MODE=counters ;;
esac
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
MAX_DEVICES=64
C_MAIN=HNC_ENCDNS
C_DOT=HNC_ENCDNS_DOT
C_STRICT=HNC_ENCDNS_STRICT

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [encdns] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    "$@" 2>/dev/null
}

v6=0
command -v ip6tables >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1 && v6=1
[ -n "${HNC_IP6T:-}" ] && $IP6T -t filter -L -n >/dev/null 2>&1 && v6=1

# ── --counters: 解析 iptables -nvxL ─────────────────────────────────
# 每行前两列是 pkts / bytes(ip6tables 的 opt 列可能为空, 所以只按内容分类):
#   子链 DOT 里的规则                     → dot
#   子链 STRICT: STRING 且 dpt:53          → doh_dns
#               STRING 且 dpt:443          → doh_sni
#               其余 dpt:443               → doh_ip
#   跳转规则(target 为 HNC_ENCDNS_*)不计
counters_family() {
    # $1 = iptables 命令; 输出 "dot_p dot_b ip_p ip_b sni_p sni_b dns_p dns_b"
    {
        $1 -t filter -nvxL "$C_DOT" 2>/dev/null | sed 's/^/DOT /'
        $1 -t filter -nvxL "$C_STRICT" 2>/dev/null | sed 's/^/STRICT /'
    } | awk '
        BEGIN { dp=0; db=0; ip=0; ib=0; sp=0; sb=0; np=0; nb=0 }
        {
            ch = $1; p = $2; b = $3
            if (p !~ /^[0-9]+$/ || b !~ /^[0-9]+$/) next
            if ($4 ~ /^HNC_ENCDNS/) next
            if (ch == "DOT") { dp += p; db += b; next }
            if ($0 ~ /STRING/ && $0 ~ /dpt:53([^0-9]|$)/) { np += p; nb += b; next }
            if ($0 ~ /STRING/ && $0 ~ /dpt:443([^0-9]|$)/) { sp += p; sb += b; next }
            if ($0 ~ /dpt:443([^0-9]|$)/) { ip += p; ib += b; next }
        }
        END { printf "%d %d %d %d %d %d %d %d\n", dp, db, ip, ib, sp, sb, np, nb }'
}

if [ "$MODE" = counters ]; then
    chain=false
    $IPT -t filter -nL "$C_MAIN" >/dev/null 2>&1 && chain=true
    set -- $(counters_family "$IPT")
    a1=${1:-0}; a2=${2:-0}; a3=${3:-0}; a4=${4:-0}; a5=${5:-0}; a6=${6:-0}; a7=${7:-0}; a8=${8:-0}
    b1=0; b2=0; b3=0; b4=0; b5=0; b6=0; b7=0; b8=0
    v6j=false
    if [ "$v6" = 1 ]; then
        v6j=true
        set -- $(counters_family "$IP6T")
        b1=${1:-0}; b2=${2:-0}; b3=${3:-0}; b4=${4:-0}; b5=${5:-0}; b6=${6:-0}; b7=${7:-0}; b8=${8:-0}
    fi
    v4p=$((a1 + a3 + a5 + a7)); v6p=$((b1 + b3 + b5 + b7))
    tb=$((a2 + a4 + a6 + a8 + b2 + b4 + b6 + b8))
    printf '{"chain":%s,"v6":%s,"dot":{"pkts":%d,"bytes":%d},"doh_ip":{"pkts":%d,"bytes":%d},"doh_sni":{"pkts":%d,"bytes":%d},"doh_dns":{"pkts":%d,"bytes":%d},"total_pkts":%d,"total_bytes":%d,"v4_pkts":%d,"v6_pkts":%d}\n' \
        "$chain" "$v6j" $((a1 + b1)) $((a2 + b2)) $((a3 + b3)) $((a4 + b4)) $((a5 + b5)) $((a6 + b6)) $((a7 + b7)) $((a8 + b8)) \
        $((v4p + v6p)) "$tb" "$v4p" "$v6p"
    exit 0
fi

# ── 拆链(幂等)────────────────────────────────────────────────────────
for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
    [ -n "$T" ] || continue
    for C in INPUT FORWARD; do
        i=0
        while run $T -t filter -D "$C" -j "$C_MAIN"; do i=$((i + 1)); [ "$i" -ge 20 ] && break; [ "$DRY" = 1 ] && break; done
    done
    for CH in "$C_MAIN" "$C_STRICT" "$C_DOT"; do
        run $T -t filter -F "$CH"
    done
    for CH in "$C_MAIN" "$C_STRICT" "$C_DOT"; do
        run $T -t filter -X "$CH"
    done
done

# ── 读配置 ───────────────────────────────────────────────────────────
valid_policy() { case "$1" in off|dot|strict) return 0 ;; esac; return 1; }
flat=$(tr -d '\r\n\t ' < "$CONF" 2>/dev/null)
policy=$(printf '%s' "$flat" | grep -o '"policy":"[a-z]*"' | head -n1 | cut -d'"' -f4)
valid_policy "$policy" || policy=off
devlist=$(printf '%s' "$flat" | grep -o '"devices":{[^}]*}' | head -n1 \
    | grep -oE '"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}":"[a-z]+"' | tr -d '"' | tr ':' ' ' \
    | awk '{ printf "%s:%s:%s:%s:%s:%s %s\n", $1,$2,$3,$4,$5,$6,$7 }' | tr 'A-F' 'a-f')

ndev=0
need=0
[ "$policy" != off ] && need=1
if [ -n "$devlist" ]; then
    while read -r m p; do
        valid_policy "$p" || continue
        ndev=$((ndev + 1))
    done <<EOF
$devlist
EOF
fi
[ "$ndev" -gt 0 ] && need=1

if [ "$need" = 0 ]; then
    log "policy=off, no device overrides, chains removed"
    echo "ENCDNS=off"
    exit 0
fi

iface=${HNC_ENCDNS_IFACE:-${HNC_WL_IFACE:-}}
if [ -z "$iface" ]; then
    case "$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null)" in ACTIVE:*) iface=$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null); iface=${iface#ACTIVE:} ;; esac
fi
case "$iface" in *[!a-zA-Z0-9_.-]*) iface="" ;; esac

# ── 解析器名单 ───────────────────────────────────────────────────────
LIST=${HNC_ENCDNS_LIST:-}
if [ -z "$LIST" ]; then
    for f in "$HNC_DIR/etc/encdns_resolvers.txt" "$(cat "$HNC_DIR/run/service.path" 2>/dev/null)/data/encdns_resolvers.txt" \
             "$(dirname "$0")/../data/encdns_resolvers.txt"; do
        [ -s "$f" ] && { LIST=$f; break; }
    done
fi
if [ -n "$LIST" ] && [ -s "$LIST" ]; then
    entries=$(sed 's/#.*//' "$LIST" 2>/dev/null | tr -d '\r' | awk 'NF { print tolower($1) }')
else
    # 名单文件丢了: 内置最小集合, 保证 strict 仍有意义
    entries="dns.google
cloudflare-dns.com
dns.alidns.com
doh.pub
dns.quad9.net
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
223.5.5.5
223.6.6.6
1.12.12.12
120.53.53.53
2001:4860:4860::8888
2606:4700:4700::1111"
    log "WARN: resolver list not found, using built-in minimal set"
fi
hosts=""; ip4=""; ip6=""
for e in $entries; do
    case "$e" in
        *:*)
            case "$e" in *[!0-9a-f:/]*) continue ;; esac
            ip6="$ip6 $e" ;;
        *[!0-9./]*)
            case "$e" in ""|*[!a-z0-9.-]*|.*|*.|*..*) continue ;; esac
            hosts="$hosts $e" ;;
        *)
            case "$e" in *.*.*.*) ;; *) continue ;; esac
            ip4="$ip4 $e" ;;
    esac
done

# ── xt_string 探测(缓存到 CAPS, 早于本次开机则重测)─────────────────
probe_string() {
    [ "$DRY" = 1 ] && return 0
    $1 -t filter -N HNC_EDPROBE 2>/dev/null
    $1 -t filter -A HNC_EDPROBE -m string --algo bm --icase --hex-string '|03|com|00|' -j RETURN 2>/dev/null
    _prc=$?
    $1 -t filter -F HNC_EDPROBE 2>/dev/null
    $1 -t filter -X HNC_EDPROBE 2>/dev/null
    return $_prc
}
caps_get() { grep -o "\"$1\":[a-z0-9]*" "$CAPS" 2>/dev/null | head -n1 | sed 's/.*://'; }
caps_stale() {
    [ -n "$(caps_get string_layer)" ] || return 0
    _chk=$(caps_get checked); _up=$(cut -d. -f1 /proc/uptime 2>/dev/null); _now=$(date +%s 2>/dev/null)
    case "$_chk$_up$_now" in *[!0-9]*|"") return 1 ;; esac
    [ "$_chk" -lt $((_now - _up)) ]
}
S4=0; S6=0
need_strict=0
[ "$policy" = strict ] && need_strict=1
printf '%s\n' "$devlist" | grep -q ' strict$' && need_strict=1
if [ "$need_strict" = 1 ] && [ -n "$hosts" ]; then
    if [ "${HNC_ENCDNS_REPROBE:-0}" = 1 ] || caps_stale; then
        probe_string "$IPT" && S4=1
        [ "$v6" = 1 ] && probe_string "$IP6T" && S6=1
        _b4=false; [ "$S4" = 1 ] && _b4=true
        _b6=false; [ "$S6" = 1 ] && _b6=true
        [ "$DRY" = 1 ] || printf '{"string_layer":%s,"string_layer_v6":%s,"checked":%s}\n' "$_b4" "$_b6" "$(date +%s 2>/dev/null || echo 0)" > "$CAPS" 2>/dev/null
        log "xt_string probe: v4=$S4 v6=$S6"
    else
        [ "$(caps_get string_layer)" = true ] && S4=1
        [ "$(caps_get string_layer_v6)" = true ] && [ "$v6" = 1 ] && S6=1
    fi
fi

# 域名 → DNS 线格式 hex-string(|len|label...|00|); 非法返回 1
dns_hex() {
    case "$1" in
        ""|*[!a-z0-9.-]*|.*|*.|*..*) return 1 ;;
    esac
    [ "${#1}" -le 253 ] || return 1
    _out=""
    for _lab in $(echo "$1" | tr '.' ' '); do
        _len=${#_lab}
        [ "$_len" -ge 1 ] && [ "$_len" -le 63 ] || return 1
        _out="$_out|$(printf '%02x' "$_len")|$_lab"
    done
    echo "$_out|00|"
}
# SNI 扩展里的 HostName: name_type(00) + 2 字节长度 + 名字
sni_hex() { printf '|00%04x|%s' "${#1}" "$1"; }

nr=0
addr() { run "$@" && nr=$((nr + 1)); }

# ── 子链 ─────────────────────────────────────────────────────────────
build_family() {
    # $1 = iptables 命令, $2 = 4|6, $3 = 是否有 xt_string(1/0)
    _T=$1; _f=$2; _s=$3
    if [ "$_f" = 6 ]; then _icmp=icmp6-port-unreachable; _ips=$ip6; else _icmp=icmp-port-unreachable; _ips=$ip4; fi
    run $_T -t filter -N "$C_DOT"
    run $_T -t filter -N "$C_STRICT"
    run $_T -t filter -N "$C_MAIN"
    addr $_T -t filter -A "$C_DOT" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
    addr $_T -t filter -A "$C_DOT" -p udp --dport 853 -j REJECT --reject-with "$_icmp"
    run $_T -t filter -A "$C_STRICT" -j "$C_DOT"
    [ "$need_strict" = 1 ] || return 0
    for _ip in $_ips; do
        addr $_T -t filter -A "$C_STRICT" -d "$_ip" -p tcp --dport 443 -j REJECT --reject-with tcp-reset
        addr $_T -t filter -A "$C_STRICT" -d "$_ip" -p udp --dport 443 -j REJECT --reject-with "$_icmp"
    done
    if [ "$_s" = 1 ]; then
        for _h in $hosts; do
            _hx=$(dns_hex "$_h") || continue
            for _p in udp tcp; do
                addr $_T -t filter -A "$C_STRICT" -p "$_p" --dport 53 -m string --algo bm --icase --hex-string "$_hx" -j DROP
            done
            addr $_T -t filter -A "$C_STRICT" -p tcp --dport 443 -m string --algo bm --icase --hex-string "$(sni_hex "$_h")" -j REJECT --reject-with tcp-reset
        done
    fi
}

# 一个选择器(MAC 或热点口)→ 子链: 只把相关端口的包跳进去, 其余包一条规则就走完
jump_sel() {
    # $1 = iptables 命令, $2 = 子链, 其余 = 选择器参数
    _T=$1; _ch=$2; shift 2
    if [ "$_ch" = "$C_DOT" ]; then
        run $_T -t filter -A "$C_MAIN" "$@" -p tcp --dport 853 -j "$_ch"
        run $_T -t filter -A "$C_MAIN" "$@" -p udp --dport 853 -j "$_ch"
        return
    fi
    for _p in tcp udp; do
        for _d in 53 443 853; do
            run $_T -t filter -A "$C_MAIN" "$@" -p "$_p" --dport "$_d" -j "$_ch"
        done
    done
}
chain_for() { case "$1" in dot) echo "$C_DOT" ;; strict) echo "$C_STRICT" ;; *) echo "" ;; esac; }

gstate=$policy
[ "$policy" != off ] && [ -z "$iface" ] && gstate=pending
for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
    [ -n "$T" ] || continue
    if [ "$T" = "$IPT" ]; then fam=4; s=$S4; else fam=6; s=$S6; fi
    build_family "$T" "$fam" "$s"
    k=0
    if [ -n "$devlist" ]; then
        while read -r m p; do
            valid_policy "$p" || continue
            k=$((k + 1)); [ "$k" -gt "$MAX_DEVICES" ] && { log "WARN: device override cap $MAX_DEVICES reached"; break; }
            ch=$(chain_for "$p")
            [ -n "$ch" ] && jump_sel "$T" "$ch" -m mac --mac-source "$m"
            run $T -t filter -A "$C_MAIN" -m mac --mac-source "$m" -j RETURN
        done <<EOF
$devlist
EOF
    fi
    if [ "$gstate" = dot ] || [ "$gstate" = strict ]; then
        jump_sel "$T" "$(chain_for "$gstate")" -i "$iface"
    fi
    for C in INPUT FORWARD; do
        run $T -t filter -I "$C" 1 -j "$C_MAIN" || log "WARN: v$fam link $C failed"
    done
done
[ "$ndev" -gt "$MAX_DEVICES" ] && ndev=$MAX_DEVICES
log "global=$gstate iface=${iface:-?} devices=$ndev rules=$nr string_layer=$S4/$S6 v6=$v6"
echo "ENCDNS=on global=$gstate devices=$ndev rules=$nr string_layer=$S4"
