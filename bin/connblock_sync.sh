#!/system/bin/sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
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
# v5.18 DNS 层: httpd 另写 run/conn_blocks.dns(每行 "<mac> <domain>")。独立链
# HNC_CONNBLK_DNS 挂在 filter/INPUT 与 FORWARD 第 1 位(INPUT: 发给热点网关自身
# dnsmasq 的查询; FORWARD: 设备写死的公共 DNS), 每个 (mac, domain):
#   -m mac --mac-source <mac> -p udp|tcp --dport 53 \
#   -m string --algo bm --icase --hex-string "|06|google|03|com|00|" -j DROP
# qname 是长度前缀线格式, 带结尾 0 字节的后缀匹配 = 该域名及其全部子域名
# (www.google.com 的 |03|www|06|google|03|com|00| 包含它), 而 notgoogle.com
# 不会命中(google 前一字节是 't' 不是长度 06)。用 DROP 不用 REJECT: 对 DNS 服务器
# 回 ICMP 不可达可能让客户端把整个解析器判死, 影响其它域名; DROP 只让这一个名字超时。
# 需要 xt_string: 首次用到时在临时链里试加一条规则探测, 结果写
# run/connblock_caps.json {"dns_layer":bool,"dns_layer_v6":bool,"checked":ts}
# (httpd /api/config 的 conn_block_dns_layer 读它); 不支持则静默只做 IP 层。
# DoT(tcp/853): 仅对「有域名封锁的设备」REJECT(tcp-reset)。取舍: Android「私人
# DNS=自动」会因此回落明文 53, DNS 层才看得见; 代价是该设备若设了「私人 DNS=指定
# 主机名」(严格模式)将整体无法解析 —— 只影响主动设了域名封锁的设备, 可接受。
# DoH(443)无法区分, 仍只能靠 IP 层。
# 输出(最后一行): CONN_BLOCK=off  或  CONN_BLOCK=on rules=<条数>
#   有 DNS 列表时追加: " dns=<条数> dns_layer=<1|0>"
# 用法: connblock_sync.sh [--dry-run]
# 环境: HNC_CONNBLK_REPROBE=1 强制重新探测 xt_string

HNC_DIR=${HNC_DIR:-/data/local/hnc}
FLAT="$HNC_DIR/run/conn_blocks.flat"
DNSLIST="$HNC_DIR/run/conn_blocks.dns"
CAPS="$HNC_DIR/run/connblock_caps.json"
LOG="$HNC_DIR/logs/service.log"
DRY=0
[ "$1" = "--dry-run" ] && DRY=1
_CB_CUSTOM_IPT=0
if [ -n "${HNC_IPT:-}" ] || [ -n "${HNC_IP6T:-}" ] || [ -n "${HNC_TEST_MODE:-}" ]; then
    _CB_CUSTOM_IPT=1
fi
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
MAX_RULES=2000

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [connblock] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    "$@" 2>/dev/null
}

# 互斥锁: 防止 hnc_httpd 与 watchdog full_restore 并发拆建 HNC_CONNBLK* 链
CB_LOCK="$HNC_DIR/run/connblock.lock"
cb_lock() {
    [ "$DRY" = 1 ] && return 0
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    local _n=0 _lp _ts _now
    while ! mkdir "$CB_LOCK" 2>/dev/null; do
        _lp=$(cat "$CB_LOCK/pid" 2>/dev/null)
        _ts=$(cat "$CB_LOCK/ts" 2>/dev/null)
        _now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
            rm -rf "$CB_LOCK" 2>/dev/null
            continue
        fi
        case "$_ts:$_now" in
            *[!0-9:]*|:*) ;;
            *) [ "$_ts" -gt 0 ] && [ $((_now - _ts)) -ge 30 ] && rm -rf "$CB_LOCK" 2>/dev/null && continue ;;
        esac
        _n=$((_n + 1))
        [ "$_n" -ge 30 ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$$" > "$CB_LOCK/pid" 2>/dev/null
    date +%s > "$CB_LOCK/ts" 2>/dev/null
    return 0
}
cb_unlock() {
    rm -f "$HNC_DIR/run"/.cb_r*.$$ 2>/dev/null
    [ "$DRY" = 1 ] && return 0
    [ "$(cat "$CB_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$CB_LOCK" 2>/dev/null
}
cb_lock || true
trap 'cb_unlock' EXIT INT TERM

v6=0
command -v "${IP6T%% *}" >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1 && v6=1

_cb_teardown_all() {
    local T i C
    for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
        [ -n "$T" ] || continue
        i=0
        while run $T -t filter -D FORWARD -j HNC_CONNBLK; do i=$((i + 1)); [ "$i" -ge 20 ] && break; [ "$DRY" = 1 ] && break; done
        run $T -t filter -F HNC_CONNBLK
        run $T -t filter -X HNC_CONNBLK
        for C in INPUT FORWARD; do
            i=0
            while run $T -t filter -D "$C" -j HNC_CONNBLK_DNS; do i=$((i + 1)); [ "$i" -ge 20 ] && break; [ "$DRY" = 1 ] && break; done
        done
        run $T -t filter -F HNC_CONNBLK_DNS
        run $T -t filter -X HNC_CONNBLK_DNS
    done
}

if [ ! -s "$FLAT" ] && [ ! -s "$DNSLIST" ]; then
    _cb_teardown_all
    echo "CONN_BLOCK=off"
    exit 0
fi

# ── xt_string 探测(结果缓存到 CAPS, 每次开机/强制时重测)────────────
probe_string() {
    # $1 = iptables 命令; 在临时链里试加一条 string 规则
    [ "$DRY" = 1 ] && return 0
    $1 -t filter -N HNC_CBPROBE 2>/dev/null
    $1 -t filter -A HNC_CBPROBE -m string --algo bm --icase --hex-string '|03|com|00|' -j RETURN 2>/dev/null
    _prc=$?
    $1 -t filter -F HNC_CBPROBE 2>/dev/null
    $1 -t filter -X HNC_CBPROBE 2>/dev/null
    return $_prc
}
caps_get() { grep -o "\"$1\":[a-z0-9]*" "$CAPS" 2>/dev/null | head -n1 | sed 's/.*://'; }
# 缓存早于本次开机(内核/模块可能变了)就重测
caps_stale() {
    [ -n "$(caps_get dns_layer)" ] || return 0
    _chk=$(caps_get checked); _up=$(cut -d. -f1 /proc/uptime 2>/dev/null); _now=$(date +%s 2>/dev/null)
    [ -n "$_chk" ] && [ -n "$_up" ] && [ -n "$_now" ] || return 1
    case "$_chk$_up$_now" in *[!0-9]*) return 1 ;; esac
    [ "$_chk" -lt $((_now - _up)) ]
}
[ -f "$FLAT" ] || FLAT=/dev/null
DNS4=0; DNS6=0
if [ -s "$DNSLIST" ]; then
    if [ "${HNC_CONNBLK_REPROBE:-0}" = 1 ] || caps_stale; then
        probe_string "$IPT" && DNS4=1
        [ "$v6" = 1 ] && probe_string "$IP6T" && DNS6=1
        _b4=false; [ "$DNS4" = 1 ] && _b4=true
        _b6=false; [ "$DNS6" = 1 ] && _b6=true
        [ "$DRY" = 1 ] || printf '{"dns_layer":%s,"dns_layer_v6":%s,"checked":%s}\n' "$_b4" "$_b6" "$(date +%s 2>/dev/null || echo 0)" > "$CAPS" 2>/dev/null
        log "xt_string probe: v4=$DNS4 v6=$DNS6"
    else
        [ "$(caps_get dns_layer)" = true ] && DNS4=1
        [ "$(caps_get dns_layer_v6)" = true ] && [ "$v6" = 1 ] && DNS6=1
    fi
fi

_cb_restore_commit() {
    local _bin="$1" _f="$2" _fdrop="${2}.drop"
    "$_bin" -w 2 --noflush < "$_f" 2>/dev/null && return 0
    "$_bin" --noflush < "$_f" 2>/dev/null && return 0
    # REJECT -> DROP 原子回退(部分裁剪内核无 ipt_REJECT / ip6t_REJECT 模块)
    sed -e 's/-j REJECT --reject-with [^ ]*/-j DROP/g' -e 's/-j REJECT$/-j DROP/g' "$_f" > "$_fdrop" 2>/dev/null || return 1
    "$_bin" -w 2 --noflush < "$_fdrop" 2>/dev/null && return 0
    "$_bin" --noflush < "$_fdrop" 2>/dev/null && return 0
    return 1
}

# ── 真机原子快路径: 单趟 awk + iptables-restore -w 2 --noflush ────────
_USE_FAST=0
if [ "$DRY" != "1" ] && [ "$_CB_CUSTOM_IPT" = "0" ] && command -v iptables-restore >/dev/null 2>&1; then
    if [ "$v6" != "1" ] || command -v ip6tables-restore >/dev/null 2>&1; then
        _USE_FAST=1
    fi
fi

if [ "$_USE_FAST" = "1" ]; then
    _R4="$HNC_DIR/run/.cb_r4.$$"
    _R6="$HNC_DIR/run/.cb_r6.$$"
    _META="$HNC_DIR/run/.cb_rmeta.$$"
    _DNS_IN="$DNSLIST"
    [ -s "$_DNS_IN" ] || _DNS_IN=/dev/null
    if awk -v f4="$_R4" -v f6="$_R6" -v v6="$v6" -v d4="$DNS4" -v d6="$DNS6" -v cap="$MAX_RULES" '
        function valid_mac(m) {
            return (m ~ /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/)
        }
        function build_hex(dom,    nb, labs, i, L, out) {
            if (dom == "" || length(dom) > 253) return ""
            if (dom ~ /[^a-z0-9.-]/ || dom ~ /^\./ || dom ~ /\.$/ || dom ~ /\.\./) return ""
            nb = split(dom, labs, ".")
            out = ""
            for (i = 1; i <= nb; i++) {
                L = length(labs[i])
                if (L < 1 || L > 63) return ""
                out = out sprintf("|%02x|%s", L, labs[i])
            }
            return out "|00|"
        }
        BEGIN {
            n = 0; dn = 0
            print "*filter" > f4
            print ":HNC_CONNBLK - [0:0]" >> f4
            if (d4 == 1) print ":HNC_CONNBLK_DNS - [0:0]" >> f4
            if (v6 == 1) {
                print "*filter" > f6
                print ":HNC_CONNBLK - [0:0]" >> f6
                if (d6 == 1) print ":HNC_CONNBLK_DNS - [0:0]" >> f6
            }
            phase = 1
        }
        FNR == 1 && NR > 1 { phase = 2 }
        phase == 1 {
            if (n >= cap) next
            mac = $1; ip = $2
            if (!valid_mac(mac) || ip == "" || ip ~ /[^0-9a-fA-F:.]/) next
            if (index(ip, ":") > 0) {
                if (v6 != 1) next
                printf "-A HNC_CONNBLK -m mac --mac-source %s -d %s -j REJECT\n", mac, ip >> f6
                n++
            } else {
                printf "-A HNC_CONNBLK -m mac --mac-source %s -d %s -j REJECT\n", mac, ip >> f4
                n++
            }
            next
        }
        phase == 2 {
            if (d4 != 1 && d6 != 1) next
            if (dn >= cap) next
            mac = tolower($1); dom = tolower($2)
            if (!valid_mac(mac)) next
            hex = build_hex(dom)
            if (hex == "") next
            if (d4 == 1) {
                printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p udp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", mac, hex >> f4
                printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p tcp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", mac, hex >> f4
            }
            if (d6 == 1 && v6 == 1) {
                printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p udp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", mac, hex >> f6
                printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p tcp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", mac, hex >> f6
            }
            dn++
            if (!(mac in dot_seen)) {
                dot_seen[mac] = 1
                if (d4 == 1) {
                    printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p tcp --dport 853 -j REJECT --reject-with tcp-reset\n", mac >> f4
                    printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable\n", mac >> f4
                }
                if (d6 == 1 && v6 == 1) {
                    printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p tcp --dport 853 -j REJECT --reject-with tcp-reset\n", mac >> f6
                    printf "-A HNC_CONNBLK_DNS -m mac --mac-source %s -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable\n", mac >> f6
                }
            }
        }
        END {
            print "COMMIT" >> f4
            close(f4)
            if (v6 == 1) {
                print "COMMIT" >> f6
                close(f6)
            }
            printf "%d %d\n", n, dn
        }
    ' "$FLAT" "$_DNS_IN" > "$_META" 2>/dev/null; then
        _fast_ok=1
        _cb_restore_commit iptables-restore "$_R4" || _fast_ok=0
        if [ "$_fast_ok" = "1" ] && [ "$v6" = "1" ]; then
            _cb_restore_commit ip6tables-restore "$_R6" || _fast_ok=0
        fi
        if [ "$_fast_ok" = "1" ]; then
            read -r n dn < "$_META" 2>/dev/null
            rm -f "$HNC_DIR/run"/.cb_r*.$$ 2>/dev/null
            $IPT -t filter -C FORWARD -j HNC_CONNBLK 2>/dev/null || $IPT -t filter -I FORWARD 1 -j HNC_CONNBLK 2>/dev/null || log "WARN: v4 link failed"
            if [ "$v6" = "1" ]; then
                $IP6T -t filter -C FORWARD -j HNC_CONNBLK 2>/dev/null || $IP6T -t filter -I FORWARD 1 -j HNC_CONNBLK 2>/dev/null || log "WARN: v6 link failed"
            fi
            if [ "${dn:-0}" -gt 0 ]; then
                for C in INPUT FORWARD; do
                    if [ "$DNS4" = "1" ]; then
                        $IPT -t filter -C "$C" -j HNC_CONNBLK_DNS 2>/dev/null || $IPT -t filter -I "$C" 1 -j HNC_CONNBLK_DNS 2>/dev/null || log "WARN: v4 dns link $C failed"
                    fi
                    if [ "$DNS6" = "1" ] && [ "$v6" = "1" ]; then
                        $IP6T -t filter -C "$C" -j HNC_CONNBLK_DNS 2>/dev/null || $IP6T -t filter -I "$C" 1 -j HNC_CONNBLK_DNS 2>/dev/null || log "WARN: v6 dns link $C failed"
                    fi
                done
            else
                for T in "$IPT" "$([ "$v6" = 1 ] && echo "$IP6T")"; do
                    [ -n "$T" ] || continue
                    for C in INPUT FORWARD; do
                        i=0; while $T -t filter -D "$C" -j HNC_CONNBLK_DNS 2>/dev/null; do i=$((i + 1)); [ "$i" -ge 20 ] && break; done
                    done
                    $T -t filter -F HNC_CONNBLK_DNS 2>/dev/null
                    $T -t filter -X HNC_CONNBLK_DNS 2>/dev/null
                done
            fi
            log "rules=${n:-0} dns=${dn:-0} dns_layer=$DNS4/$DNS6 v6=$v6 (fast-restore)"
            if [ -s "$DNSLIST" ]; then
                echo "CONN_BLOCK=on rules=${n:-0} dns=${dn:-0} dns_layer=$DNS4"
            else
                echo "CONN_BLOCK=on rules=${n:-0}"
            fi
            exit 0
        fi
        log "WARN: iptables-restore fast path failed, falling back to per-rule mode"
    fi
    rm -f "$HNC_DIR/run"/.cb_r*.$$ 2>/dev/null
fi

# ── 兼容逐条路径(--dry-run / HNC_IPT / HNC_TEST_MODE / 无 iptables-restore) ──
_cb_teardown_all

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
    if run $T -t filter -A HNC_CONNBLK -m mac --mac-source "$mac" -d "$ip" -j REJECT; then
        n=$((n + 1))
    elif run $T -t filter -A HNC_CONNBLK -m mac --mac-source "$mac" -d "$ip" -j DROP; then
        n=$((n + 1))
    fi
    [ "$n" -ge "$MAX_RULES" ] && { log "WARN: rule cap $MAX_RULES reached"; break; }
done < "$FLAT"
run $IPT -t filter -I FORWARD 1 -j HNC_CONNBLK || log "WARN: v4 link failed"
[ "$v6" = 1 ] && { run $IP6T -t filter -I FORWARD 1 -j HNC_CONNBLK || log "WARN: v6 link failed"; }

# ── DNS 层 ───────────────────────────────────────────────────────────
dn=0
if [ -s "$DNSLIST" ] && { [ "$DNS4" = 1 ] || [ "$DNS6" = 1 ]; }; then
    [ "$DNS4" = 1 ] && run $IPT -t filter -N HNC_CONNBLK_DNS
    [ "$DNS6" = 1 ] && run $IP6T -t filter -N HNC_CONNBLK_DNS
    dot_macs=" "
    while read -r mac dom _; do
        case "$mac" in
            [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
            *) continue ;;
        esac
        mac=$(echo "$mac" | tr 'A-F' 'a-f')
        dom=$(echo "$dom" | tr 'A-Z' 'a-z')
        hex=$(dns_hex "$dom") || continue
        for T in "$([ "$DNS4" = 1 ] && echo "$IPT")" "$([ "$DNS6" = 1 ] && echo "$IP6T")"; do
            [ -n "$T" ] || continue
            for P in udp tcp; do
                run $T -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p "$P" --dport 53 \
                    -m string --algo bm --icase --hex-string "$hex" -j DROP
            done
        done
        dn=$((dn + 1))
        case "$dot_macs" in
            *" $mac "*) ;;
            *)
                dot_macs="$dot_macs$mac "
                if [ "$DNS4" = 1 ]; then
                    run $IPT -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p tcp --dport 853 -j REJECT --reject-with tcp-reset \
                        || run $IPT -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p tcp --dport 853 -j DROP
                    run $IPT -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable \
                        || run $IPT -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p udp --dport 853 -j DROP
                fi
                if [ "$DNS6" = 1 ]; then
                    run $IP6T -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p tcp --dport 853 -j REJECT --reject-with tcp-reset \
                        || run $IP6T -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p tcp --dport 853 -j DROP
                    run $IP6T -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable \
                        || run $IP6T -t filter -A HNC_CONNBLK_DNS -m mac --mac-source "$mac" -p udp --dport 853 -j DROP
                fi
                ;;
        esac
        [ "$dn" -ge "$MAX_RULES" ] && { log "WARN: dns rule cap $MAX_RULES reached"; break; }
    done < "$DNSLIST"
    for C in INPUT FORWARD; do
        [ "$DNS4" = 1 ] && { run $IPT -t filter -I "$C" 1 -j HNC_CONNBLK_DNS || log "WARN: v4 dns link $C failed"; }
        [ "$DNS6" = 1 ] && { run $IP6T -t filter -I "$C" 1 -j HNC_CONNBLK_DNS || log "WARN: v6 dns link $C failed"; }
    done
fi
log "rules=$n dns=$dn dns_layer=$DNS4/$DNS6 v6=$v6"
if [ -s "$DNSLIST" ]; then
    echo "CONN_BLOCK=on rules=$n dns=$dn dns_layer=$DNS4"
else
    echo "CONN_BLOCK=on rules=$n"
fi
