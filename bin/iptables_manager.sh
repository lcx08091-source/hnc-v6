#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
# rc13: 追加 /data/local/hnc/bin —— /system/bin 被卸时裸命令 fallthrough 到 /data 预置副本。
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# iptables_manager.sh — v3.4.1  双栈（IPv4 + IPv6）+ 安全 MARK 命名空间
#
# 【v3.4.1 关键修复】
#   MARK_BASE 从 0x10000 改为 0x800000，避开 ColorOS / Android netd 占用段。
#
#   背景：Android 上 fwmark 不是不透明值。netd 用 0x10000-0xdffff 段做
#   policy routing（ip rule 里能看到 fwmark 0x10063/0x1ffff lookup
#   local_network、0x10064/0x1ffff lookup rmnet_data2 等）。
#   旧 MARK_BASE=0x10000 + mark_id 1..99 落在 0x10001-0x10063 范围，
#   恰好和 ColorOS rmnet_data2 / local_network 等关键路由表的 mark
#   段冲突。被 mark 的包会被 ip rule 路由到错误的表，结果是设备看似
#   有限速但实际网络不可用（"网络受限"）。
#
#   新 MARK_BASE=0x800000（bit 23）完全空闲：
#     - Android netd 0x10000-0xdffff 段：避开
#     - VPN 0x60000+ 段：避开
#     - system uid 0xc0000+ 段：避开
#     - 0x800000+ 完全没人用
#   CONNMARK_MASK 同步扩到 0xffff0000（24 位），覆盖整个新段。
#
# 【v3.3.4 历史】双栈（IPv4 + IPv6）
#
# 核心改动（vs v3.3.3）:
#   1. 所有规则操作镜像到 ip6tables：mark / unmark / blacklist / whitelist / cleanup
#   2. v6 下行通过 CONNMARK save/restore 自动携带 mark，无需跟踪动态 IPv6 地址
#   3. CONNMARK mask 从 0xffff 扩为 0x1ffff，修复 mark_id > 0 时高位丢失的 bug
#      （旧 mask 只保留低 16 位，但 MARK_BASE=0x10000 刚好是第 17 位，
#        所以保存到 conntrack 时 mark 0x1003B 会被截断为 0x003B，
#        restore 后 tc fw filter 再也匹配不到 → v6 下行限速全部失效。
#        在 v4 侧不易察觉是因为 v4 下行还有一条 -d IP 规则直接打全 mark 兜底。)
#   4. $IP6T 不可用时优雅降级到纯 v4 模式（IPV6_OK=0，日志 warn）
#   5. 代码结构：引入 ipt_dual / ipt_dual_q / _ensure_chain / _ensure_link 助手
#
# 架构（v4+v6）:
#   mangle/PREROUTING  → HNC_RESTORE: CONNMARK → MARK
#   mangle/FORWARD     → HNC_MARK:
#                          v4: -s IP -m mac → MARK       (上行最精确)
#                              -m mac -m mark 0 → MARK   (上行 MAC 兜底)
#                              -d IP → MARK              (下行)
#                          v6: -m mac -m mark 0 → MARK   (上行)
#                                                        (下行靠 CONNMARK)
#                        HNC_STATS: 流量计数 (仅 v4，因需跟踪地址)
#   mangle/POSTROUTING → HNC_SAVE: MARK → CONNMARK
#   filter/FORWARD     → HNC_CTRL:
#                          MAC DROP + TCP REJECT (v4+v6)
#                          src/dst IP DROP       (仅 v4)
#                        HNC_WHITELIST: 白名单模式 (v4+v6)
#
# 为什么 v6 下行只靠 CONNMARK 而不加 -d 地址规则：
#   IPv6 隐私扩展（RFC 4941）会让客户端每几个小时换一次临时地址。
#   硬编码地址很快失效，定期扫描又增加复杂度和故障面。
#   CONNMARK 方案完全不依赖地址：
#     1. 上行第一个包被 MAC match 打 mark → HNC_SAVE 存入 conntrack
#     2. 下行回包在 PREROUTING 被 HNC_RESTORE 从 conntrack 取回 mark
#     3. tc fw filter 按 mark 分类到 HTB 限速 class
#   缺点是无法限速"无对应上行连接的下行流量"（极罕见），可接受。

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
# rc30.13.1 cleanup: RULES_FILE 在此文件无引用. 子调用走 sh json_set.sh 自己拼路径.
LOG=$HNC_DIR/logs/iptables.log

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [IPT] $*" >> "$LOG" 2>/dev/null || true
}

if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi
MARK_BASE="${HNC_MARK_BASE:-0x00800000}"
DEV_MARK_MASK="${HNC_MARK_MASK:-0x00ff0000}"
CONNMARK_MASK="${HNC_CONNMARK_MASK:-0xffff0000}"
command -v hnc_dev_mark_hex >/dev/null 2>&1 || {
    hnc_dev_mark_hex() { printf '0x%08x\n' $(( 0x00800000 | ($1 << 16) )); }
}

IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
_IPT_RESOLVED=0
_ipt_resolve() {
    [ "$_IPT_RESOLVED" = "1" ] && return 0
    _IPT_RESOLVED=1
    if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
        iptables -w 2 -t filter -L -n >/dev/null 2>&1 || {
            iptables -t filter -L -n >/dev/null 2>&1 && IPT="iptables"
        }
    fi
    if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -w 2 -t filter -L -n >/dev/null 2>&1 || {
            ip6tables -t filter -L -n >/dev/null 2>&1 && IP6T="ip6tables"
        }
    fi
}

# ═══════════════════════════════════════════════════════════════
# 双栈抽象: 按需懒探测并拆分 ipv6_mangle_ok / ipv6_filter_ok
# 缺 ip6table_mangle 时仍允许 *filter 表 IPv6 黑名单/白名单/客户端隔离生效
# ═══════════════════════════════════════════════════════════════
_IPV6_PROBED=0
IPV6_OK=0
_IPV6_FILTER_PROBED=0
IPV6_FILTER_OK=0

ipv6_mangle_ok() {
    _ipt_resolve
    if [ "$_IPV6_PROBED" = "0" ]; then
        _IPV6_PROBED=1
        if command -v "${IP6T%% *}" >/dev/null 2>&1 \
            && $IP6T -t mangle -L -n >/dev/null 2>&1; then
            IPV6_OK=1
        else
            IPV6_OK=0
        fi
    fi
    [ "$IPV6_OK" = "1" ]
}

ipv6_filter_ok() {
    _ipt_resolve
    if [ "$_IPV6_FILTER_PROBED" = "0" ]; then
        _IPV6_FILTER_PROBED=1
        if command -v "${IP6T%% *}" >/dev/null 2>&1 \
            && $IP6T -t filter -L -n >/dev/null 2>&1; then
            IPV6_FILTER_OK=1
        else
            IPV6_FILTER_OK=0
        fi
    fi
    [ "$IPV6_FILTER_OK" = "1" ]
}

ipv6_ok() {
    ipv6_mangle_ok
}

ipv6_table_ok() {
    case "$1" in
        filter) ipv6_filter_ok ;;
        *)      ipv6_mangle_ok ;;
    esac
}

ipt_dual() {
    _ipt_resolve
    local _tbl="filter"
    [ "$1" = "-t" ] && _tbl=$2
    $IPT "$@"
    local r4=$?
    if ipv6_table_ok "$_tbl"; then
        $IP6T "$@" 2>/dev/null || true
    fi
    return $r4
}

ipt_dual_q() {
    _ipt_resolve
    local _tbl="filter"
    [ "$1" = "-t" ] && _tbl=$2
    $IPT "$@" 2>/dev/null
    ipv6_table_ok "$_tbl" && $IP6T "$@" 2>/dev/null
    return 0
}

ipt_del_all() {
    _ipt_resolve
    local cmd=$1
    shift
    local i=0
    while $cmd "$@" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -ge 100 ] && break
    done
    return 0
}

ipt_dual_del_all() {
    _ipt_resolve
    local _tbl="filter"
    [ "$1" = "-t" ] && _tbl=$2
    ipt_del_all "$IPT" "$@"
    ipv6_table_ok "$_tbl" && ipt_del_all "$IP6T" "$@"
    return 0
}

_ensure_chain() {
    _ipt_resolve
    local table=$1 chain=$2
    $IPT -t "$table" -N "$chain" 2>/dev/null
    $IPT -t "$table" -F "$chain" 2>/dev/null
    if ipv6_table_ok "$table"; then
        $IP6T -t "$table" -N "$chain" 2>/dev/null
        $IP6T -t "$table" -F "$chain" 2>/dev/null
    fi
}

_ensure_link() {
    _ipt_resolve
    local table=$1 parent=$2 child=$3 pos=${4:-1}
    $IPT -t "$table" -C "$parent" -j "$child" 2>/dev/null \
        || $IPT -t "$table" -I "$parent" "$pos" -j "$child"
    if ipv6_table_ok "$table"; then
        $IP6T -t "$table" -C "$parent" -j "$child" 2>/dev/null \
            || $IP6T -t "$table" -I "$parent" "$pos" -j "$child" 2>/dev/null
    fi
}

_ensure_postrouting_tail() {
    _ipt_resolve
    local _cmd="$1" _ch="$2" _del_n _k
    if ! $_cmd -t mangle -C POSTROUTING -j "$_ch" 2>/dev/null; then
        $_cmd -t mangle -A POSTROUTING -j "$_ch"
        return $?
    fi
    _del_n=$($_cmd -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk -v ch="$_ch" '
        $1 ~ /^[0-9]+$/ {
            ln = $1 + 0
            max_ln = ln
            if ($2 == ch) { cnt++; eg_ln = ln }
        }
        END {
            if (cnt > 0 && (cnt > 1 || eg_ln < max_ln)) printf "%d\n", cnt
        }
    ')
    if [ -n "$_del_n" ]; then
        _k=0
        while [ "$_k" -lt "$_del_n" ]; do
            $_cmd -t mangle -D POSTROUTING -j "$_ch" 2>/dev/null || break
            _k=$((_k + 1))
        done
        $_cmd -t mangle -A POSTROUTING -j "$_ch"
    fi
}

_heal_postrouting_before_save() {
    _ipt_resolve
    local _cmd="$1" _ch="$2" _del_n _k _save_ln
    _del_n=$($_cmd -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk -v ch="$_ch" '
        $1 ~ /^[0-9]+$/ {
            ln = $1 + 0
            if ($2 == "HNC_SAVE" && save_ln == 0) save_ln = ln
            if ($2 == ch) { cnt++; max_ch = ln }
        }
        END {
            if (cnt > 0 && save_ln > 0 && (max_ch > save_ln || cnt > 1)) printf "%d\n", cnt
        }
    ')
    [ -n "$_del_n" ] || return 0
    _k=0
    while [ "$_k" -lt "$_del_n" ]; do
        $_cmd -t mangle -D POSTROUTING -j "$_ch" 2>/dev/null || break
        _k=$((_k + 1))
    done
    _save_ln=$($_cmd -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2 == "HNC_SAVE" {print $1; exit}')
    if [ -n "$_save_ln" ]; then
        $_cmd -t mangle -I POSTROUTING "$_save_ln" -j "$_ch" 2>/dev/null \
            || $_cmd -t mangle -A POSTROUTING -j "$_ch" 2>/dev/null
    else
        $_cmd -t mangle -A POSTROUTING -j "$_ch" 2>/dev/null
    fi
}

# 检测是否存在活跃 VPN 口(tun+/wg+/utun+/sing_tun+)且系统或该接口显式设了 disable_ipv6=1
_vpn_ipv6_disabled() {
    local _sys_net="${HNC_SYS_NET:-/sys/class/net}"
    local _proc_v6="${HNC_PROC_IPV6_CONF:-/proc/sys/net/ipv6/conf}"
    local _d _ifn _oper _flags _dis_all _dis_if
    _dis_all=$(cat "$_proc_v6/all/disable_ipv6" 2>/dev/null | tr -d ' \t\r\n')
    for _d in "$_sys_net"/tun* "$_sys_net"/wg* "$_sys_net"/utun* "$_sys_net"/sing_tun*; do
        [ -e "$_d" ] || continue
        _ifn=${_d##*/}
        _oper=$(cat "$_d/operstate" 2>/dev/null | tr -d ' \t\r\n')
        [ "$_oper" = "down" ] && continue
        _flags=$(cat "$_d/flags" 2>/dev/null | tr -d ' \t\r\n')
        case "$_flags" in
            0x*) [ $(( _flags & 1 )) -eq 0 ] && continue ;;
        esac
        _dis_if=$(cat "$_proc_v6/$_ifn/disable_ipv6" 2>/dev/null | tr -d ' \t\r\n')
        if [ "$_dis_all" = "1" ] || [ "$_dis_if" = "1" ]; then
            return 0
        fi
    done
    return 1
}

# ═══════════════════════════════════════════════════════════════
# 初始化所有链（v4 + v6）
# ═══════════════════════════════════════════════════════════════
init_chains() {
    ipv6_mangle_ok >/dev/null 2>&1 || true
    ipv6_filter_ok >/dev/null 2>&1 || true
    log "=== Init chains (ipv6_mangle=$IPV6_OK ipv6_filter=$IPV6_FILTER_OK) ==="

    for mod in xt_CONNMARK xt_connmark xt_mark xt_mac xt_conntrack xt_TCPMSS \
               nf_conntrack nf_conntrack_ipv6 nf_defrag_ipv6 \
               ip6t_REJECT ip6t_mac; do
        modprobe "$mod" 2>/dev/null || true
    done
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    if _vpn_ipv6_disabled; then
        log "Active VPN has disable_ipv6=1; skip enabling ipv6/conf/all/forwarding to prevent IPv6 leak"
    else
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    fi

    # ── HNC_PREROUTE_GUARD (mangle/PREROUTING): 清净高 16 位防 clsact 残留与代理碰撞 ──
    if $IPT -t mangle -S PREROUTING 2>/dev/null | grep -q 'HNC_RESTORE'; then
        ipt_dual_del_all -t mangle -D PREROUTING -j HNC_RESTORE
    fi
    _ensure_chain mangle HNC_PREROUTE_GUARD
    ipt_dual -t mangle -A HNC_PREROUTE_GUARD \
        -m mark --mark 0x00800000/0x00800000 \
        -j MARK --set-xmark 0x0/0xffff0000
    _ensure_link mangle PREROUTING HNC_PREROUTE_GUARD 1

    # ── HNC_RESTORE (mangle/FORWARD pos 1): CONNMARK → MARK ───
    _ensure_chain mangle HNC_RESTORE
    ipt_dual -t mangle -A HNC_RESTORE \
        -m connmark ! --mark "0x0/$CONNMARK_MASK" \
        -j CONNMARK --restore-mark \
        --nfmask "$CONNMARK_MASK" --ctmask "$CONNMARK_MASK"
    _ensure_link mangle FORWARD HNC_RESTORE 1

    # ── HNC_MARK (mangle/FORWARD pos 2): MAC/IP → MARK ────────
    _ensure_chain mangle HNC_MARK
    _ensure_link mangle FORWARD HNC_MARK 2

    # ── HNC_STATS (mangle/FORWARD pos 3): 双栈流量字节计数 (v4 + v6) ──
    if ! $IPT -t mangle -L HNC_STATS -n >/dev/null 2>&1; then
        $IPT -t mangle -N HNC_STATS 2>/dev/null
        rm -f "$HNC_DIR/run/stats_v6_map" "$HNC_DIR/run/stats_v6_retired" 2>/dev/null
    fi
    $IPT -t mangle -C FORWARD -j HNC_STATS 2>/dev/null \
        || $IPT -t mangle -I FORWARD 3 -j HNC_STATS 2>/dev/null \
        || $IPT -t mangle -A FORWARD -j HNC_STATS
    if ipv6_mangle_ok; then
        if ! $IP6T -t mangle -L HNC_STATS -n >/dev/null 2>&1; then
            $IP6T -t mangle -N HNC_STATS 2>/dev/null
            rm -f "$HNC_DIR/run/stats_v6_map" "$HNC_DIR/run/stats_v6_retired" 2>/dev/null
        fi
        $IP6T -t mangle -C FORWARD -j HNC_STATS 2>/dev/null \
            || $IP6T -t mangle -I FORWARD 3 -j HNC_STATS 2>/dev/null \
            || $IP6T -t mangle -A FORWARD -j HNC_STATS 2>/dev/null
    fi

    # ── HNC_TCPMSS (mangle/FORWARD): 双栈 TCPMSS 钳制防 VPN/CLAT/PPPoE 握手卡死(缺模块容错跳过) ──
    $IPT -t mangle -N HNC_TCPMSS 2>/dev/null || true
    $IPT -t mangle -F HNC_TCPMSS 2>/dev/null || true
    if $IPT -t mangle -A HNC_TCPMSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        $IPT -t mangle -C FORWARD -j HNC_TCPMSS 2>/dev/null \
            || $IPT -t mangle -I FORWARD 4 -j HNC_TCPMSS 2>/dev/null \
            || $IPT -t mangle -A FORWARD -j HNC_TCPMSS 2>/dev/null || true
    else
        ipt_del_all "$IPT" -t mangle -D FORWARD -j HNC_TCPMSS
        $IPT -t mangle -X HNC_TCPMSS 2>/dev/null || true
    fi
    if ipv6_mangle_ok; then
        $IP6T -t mangle -N HNC_TCPMSS 2>/dev/null || true
        $IP6T -t mangle -F HNC_TCPMSS 2>/dev/null || true
        if $IP6T -t mangle -A HNC_TCPMSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            $IP6T -t mangle -C FORWARD -j HNC_TCPMSS 2>/dev/null \
                || $IP6T -t mangle -I FORWARD 4 -j HNC_TCPMSS 2>/dev/null \
                || $IP6T -t mangle -A FORWARD -j HNC_TCPMSS 2>/dev/null || true
        else
            ipt_del_all "$IP6T" -t mangle -D FORWARD -j HNC_TCPMSS
            $IP6T -t mangle -X HNC_TCPMSS 2>/dev/null || true
        fi
    fi

    # ── HNC_SAVE (mangle/POSTROUTING pos 1): MARK → CONNMARK ──
    _ensure_chain mangle HNC_SAVE
    ipt_dual -t mangle -A HNC_SAVE \
        -m mark ! --mark "0x0/$CONNMARK_MASK" \
        -j CONNMARK --save-mark \
        --nfmask "$CONNMARK_MASK" --ctmask "$CONNMARK_MASK"
    _ensure_link mangle POSTROUTING HNC_SAVE 1

    # ── HNC_EGRESS_FIX (mangle/POSTROUTING tail): 修复 bw_mangle 冲刷并保护多蜂窝/VPN 出向 mark ──
    _ensure_chain mangle HNC_EGRESS_FIX
    for _eg_if in ccmni+ sipa_eth+ seth_+ gti+ wwan+ v4-+ clat+ tun+ wg+ tailscale+ utun+; do
        ipt_dual -t mangle -A HNC_EGRESS_FIX -o "$_eg_if" -j RETURN
    done
    ipt_dual -t mangle -A HNC_EGRESS_FIX \
        ! -o rmnet+ -m connmark --mark 0x00800000/0x00800000 \
        -j CONNMARK --restore-mark \
        --nfmask "$CONNMARK_MASK" --ctmask "$CONNMARK_MASK"
    for _pr_ch in HNC_APP_LIMIT_DOWN HNC_APP_QOS; do
        _heal_postrouting_before_save "$IPT" "$_pr_ch"
        ipv6_mangle_ok && _heal_postrouting_before_save "$IP6T" "$_pr_ch" 2>/dev/null || true
    done
    _ensure_postrouting_tail "$IPT" HNC_EGRESS_FIX
    if ipv6_mangle_ok; then
        _ensure_postrouting_tail "$IP6T" HNC_EGRESS_FIX 2>/dev/null || true
    fi

    # ── HNC_CTRL (filter/FORWARD): 黑名单 DROP ───────────────
    _ensure_chain filter HNC_CTRL
    _ensure_link filter FORWARD HNC_CTRL 1

    # ── HNC_WHITELIST (filter/FORWARD): 白名单模式 ───────────
    _ensure_chain filter HNC_WHITELIST
    _ensure_link filter FORWARD HNC_WHITELIST 2

    log "=== Chains initialized OK ==="
}

# ═══════════════════════════════════════════════════════════════
# 为设备打 MARK
# v4 上行：src IP+MAC (精确) + MAC 兜底 (应对 IP 未识别)
# v4 下行：dst IP
# v6 上行：MAC 兜底
# v6 下行：靠 HNC_RESTORE 从 conntrack 恢复 mark
# ═══════════════════════════════════════════════════════════════
mark_device() {
    local ip=$1 mac=$2 mark_id=$3
    local mark; mark=$(hnc_dev_mark_hex "$mark_id") || return 1
    [ -z "$ip" ] && { log "WARN: mark called with empty ip, skip"; return 1; }

    log "Marking $ip ($mac) mark=${mark}/${DEV_MARK_MASK}"

    _gc_stale_ips_for_mac "$mac" "$mark" "$ip" "$mark_id"

    # ── 清除可能的旧规则（幂等，仅限正交 xmark）──
    ipt_del_all "$IPT" -t mangle -D HNC_MARK -s "$ip" -m mac --mac-source "$mac" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
    ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$ip" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
    ipt_dual_del_all -t mangle -D HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark "0x0/${DEV_MARK_MASK}" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"

    # ── v4 上行：src IP + MAC（精确正交打标 [23:16]，绝不触碰低 16 位 netd netId）──
    $IPT -t mangle -A HNC_MARK \
        -s "$ip" -m mac --mac-source "$mac" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"

    # ── v4+v6 上行兜底：仅 MAC（-m mark --mark 0x0/0x00ff0000 判设备位为空）──
    ipt_dual -t mangle -A HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark "0x0/${DEV_MARK_MASK}" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"

    # ── v4 下行：dst IP ──
    $IPT -t mangle -A HNC_MARK \
        -d "$ip" -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"

    # ── v4 流量统计(幂等保计数)──
    _ensure_v4_stats_ip "$ip"

    echo "$mark"
}

# ═══════════════════════════════════════════════════════════════
# v3.4.11 P1-4: GC 陈旧 IP 规则
# 参数: mac (xx:xx:xx:xx:xx:xx) / mark (0x800001 格式) / current_ip (跳过的当前 IP)
# 行为: 扫描 HNC_MARK / HNC_STATS,删除所有不等于 current_ip 的 src/dst 规则
# ═══════════════════════════════════════════════════════════════
_gc_stale_ips_for_mac() {
    local mac=$1 mark=$2 cur_ip=$3 mark_id=${4:-0}
    local stale_ips ip_line mark_short
    mark_short=$(printf '0x%x' $(( 0x00800000 | (mark_id << 16) )))

    stale_ips=$($IPT -t mangle -S HNC_MARK 2>/dev/null | awk -v m="$mac" -v mk="$mark" -v mks="$mark_short" '
        function strip_cidr(ip) { sub(/\/32$/, "", ip); return ip }
        {
            has_mac = 0; has_mark = 0; src_ip = ""; dst_ip = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "--mac-source" && tolower($(i+1)) == tolower(m)) has_mac = 1
                if ($i == "--set-xmark" || $i == "--set-mark") {
                    tok = tolower($(i+1))
                    if (index(tok, tolower(mk)) == 1 || index(tok, tolower(mks)) == 1) has_mark = 1
                }
                if ($i == "-s") src_ip = strip_cidr($(i+1))
                if ($i == "-d") dst_ip = strip_cidr($(i+1))
            }
            # src 规则: 必须含 mac
            if (has_mac && src_ip != "") print src_ip
            # dst 规则: 含 mark 不含 mac
            if (!has_mac && has_mark && dst_ip != "") print dst_ip
        }
    ' | sort -u)

    # 步骤 2: 对每个非 cur_ip 的旧 IP,删除 src/dst/stats 规则
    # 注意:这里用 pipe-while 是 OK 的($IPT -D 是直接 syscall,不依赖循环内变量),
    # 但为了跟 device_detect.sh 风格一致 + 防御 ash subshell 的潜在问题,改用临时文件法
    [ -z "$stale_ips" ] && return 0
    local _gc_tmp=$HNC_DIR/run/.gc_$$
    printf '%s\n' "$stale_ips" > "$_gc_tmp"
    while IFS= read -r old_ip; do
        [ -z "$old_ip" ] && continue
        [ "$old_ip" = "$cur_ip" ] && continue
        log "GC stale IP: $old_ip (mac=$mac mark=$mark)"
        ipt_del_all "$IPT" -t mangle -D HNC_MARK -s "$old_ip" -m mac --mac-source "$mac" \
            -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
        ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$old_ip" \
            -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
        ipt_del_all "$IPT" -t mangle -D HNC_STATS -s "$old_ip" -j RETURN
        ipt_del_all "$IPT" -t mangle -D HNC_STATS -d "$old_ip" -j RETURN
    done < "$_gc_tmp"
    rm -f "$_gc_tmp"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 移除设备 MARK
# ═══════════════════════════════════════════════════════════════
unmark_device() {
    local ip=$1 mac=$2 mark_id=$3
    local mark; mark=$(hnc_dev_mark_hex "$mark_id") || return 0

    log "Unmarking $ip ($mac) mark=${mark}/${DEV_MARK_MASK}"

    # v4.0 Patch 4.b hotfix: unmark 是幂等清理操作 — 规则不存在 == 已清理成功
    # 之前函数最后一条 $IPT -D 失败时 return 非 0,导致 WebUI clearLimit 上报失败给用户
    # 实际场景:热点已关 / 链已被 cleanup / 这条规则之前根本没挂上 — 都不该是错误
    # 所有 -D 命令都 2>/dev/null,失败也继续,最后强制 return 0

    # v3.4.0：先清 v6 filter（trick：clear_one 从 $IPT 反查 mark_id，
    # 必须在删 $IPT 规则之前调用，否则它找不到 mark）
    sh "$HNC_DIR/bin/v6_sync.sh" clear "$mac" 2>/dev/null || true

    # v5.12: ip 为空(设备离线、rules.json 也无 IP)时只删 MAC-only 规则,
    # 不拼 `-s ""` 这类非法参数。
    if [ -n "$ip" ]; then
        ipt_del_all "$IPT" -t mangle -D HNC_MARK -s "$ip" -m mac --mac-source "$mac" \
            -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
        ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$ip" \
            -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"
    fi
    ipt_dual_del_all -t mangle -D HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark "0x0/${DEV_MARK_MASK}" \
        -j MARK --set-xmark "${mark}/${DEV_MARK_MASK}"

    # v5.35.1: 取消限速(unmark)时设备往往仍在线, 绝不删 HNC_STATS 计数规则,
    # 否则取消限速会清零累计字节并冻结统计直至下轮 ensure_stats_online;
    # 真正离线清理由 ensure_stats_online 双栈同步回收。
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 黑名单
# v4: MAC + 源 IP + 目标 IP 三重 DROP + TCP REJECT 立即断连
# v6: MAC DROP + TCP REJECT
# ═══════════════════════════════════════════════════════════════
blacklist_add() {
    local ip=$1 mac=$2
    log "Blacklist add: $ip ($mac)"

    # 清旧（幂等）
    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" -j DROP
    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" \
        -p tcp -j REJECT --reject-with tcp-reset
    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" -p tcp -j DROP

    # v4+v6：MAC DROP
    ipt_dual -t filter -A HNC_CTRL -m mac --mac-source "$mac" -j DROP

    # 仅 v4：按 IP 的 DROP（双向都拦）
    if [ -n "$ip" ]; then
        ipt_del_all "$IPT" -t filter -D HNC_CTRL -s "$ip" -j DROP
        ipt_del_all "$IPT" -t filter -D HNC_CTRL -d "$ip" -j DROP
        $IPT -t filter -A HNC_CTRL -s "$ip" -j DROP
        $IPT -t filter -A HNC_CTRL -d "$ip" -j DROP
    fi

    # TCP RESET 立即断现有连接（v4 + v6 独立处理，有 DROP 降级）
    $IPT -t filter -I HNC_CTRL 1 -m mac --mac-source "$mac" \
        -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null \
        || $IPT -t filter -I HNC_CTRL 1 -m mac --mac-source "$mac" -p tcp -j DROP

    if ipv6_filter_ok; then
        $IP6T -t filter -I HNC_CTRL 1 -m mac --mac-source "$mac" \
            -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null \
            || $IP6T -t filter -I HNC_CTRL 1 -m mac --mac-source "$mac" -p tcp -j DROP 2>/dev/null
    fi
}

blacklist_remove() {
    local ip=$1 mac=$2
    log "Blacklist remove: $ip ($mac)"

    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" -j DROP
    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" \
        -p tcp -j REJECT --reject-with tcp-reset
    ipt_dual_del_all -t filter -D HNC_CTRL -m mac --mac-source "$mac" -p tcp -j DROP

    if [ -n "$ip" ]; then
        ipt_del_all "$IPT" -t filter -D HNC_CTRL -s "$ip" -j DROP
        ipt_del_all "$IPT" -t filter -D HNC_CTRL -d "$ip" -j DROP
    fi
    # Patch 4.b: blacklist_remove 是幂等清理 — 同 unmark_device,强制 return 0
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 白名单模式（v4+v6）
# ═══════════════════════════════════════════════════════════════
# v5.11: HNC_WHITELIST 无条件挂在 FORWARD 上, 旧实现在链尾追加裸 DROP ——
# 从外网回来的应答包(源是公网、没有热点设备的 MAC)同样命中 DROP, 白名单
# 设备自己也上不了网。现在:
#   1. 链首放行 ESTABLISHED,RELATED(应答方向与已建立连接);
#   2. DROP 只拦从热点接口进来的包(-i <iface>); 拿不到接口时退回裸 DROP,
#      但有第 1 条兜底, 应答包不会被误杀。
whitelist_mode_on() {
    local iface=${1:-}
    [ -n "$iface" ] || iface=$(sed -n 's/^ACTIVE://p' "$HNC_DIR/run/hnc_state" 2>/dev/null | head -n 1)
    case "$iface" in *[!A-Za-z0-9_.-]*) iface="" ;; esac
    ipt_dual_q -t filter -D HNC_WHITELIST -j DROP
    [ -n "$iface" ] && ipt_dual_q -t filter -D HNC_WHITELIST -i "$iface" -j DROP
    ipt_dual_q -t filter -D HNC_WHITELIST -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    ipt_dual    -t filter -I HNC_WHITELIST 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    if [ -n "$iface" ]; then
        ipt_dual -t filter -A HNC_WHITELIST -i "$iface" -j DROP
    else
        ipt_dual -t filter -A HNC_WHITELIST -j DROP
    fi
    log "Whitelist mode ON (iface=${iface:-any})"
}

whitelist_mode_off() {
    _ipt_resolve
    $IPT -t filter -F HNC_WHITELIST 2>/dev/null
    ipv6_filter_ok && $IP6T -t filter -F HNC_WHITELIST 2>/dev/null
    log "Whitelist mode OFF"
}

whitelist_add() {
    local ip=$1 mac=$2
    ipt_dual_del_all -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j RETURN
    ipt_dual_del_all -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j ACCEPT
    ipt_dual -t filter -I HNC_WHITELIST 1 -m mac --mac-source "$mac" -j RETURN
    if [ -n "$ip" ]; then
        ipt_del_all "$IPT" -t filter -D HNC_WHITELIST -s "$ip" -j RETURN
        ipt_del_all "$IPT" -t filter -D HNC_WHITELIST -s "$ip" -j ACCEPT
        $IPT -t filter -I HNC_WHITELIST 1 -s "$ip" -j RETURN
    fi
    log "Whitelist add: $ip ($mac)"
}

whitelist_remove() {
    local ip=$1 mac=$2
    ipt_dual_del_all -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j RETURN
    ipt_dual_del_all -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j ACCEPT
    if [ -n "$ip" ]; then
        ipt_del_all "$IPT" -t filter -D HNC_WHITELIST -s "$ip" -j RETURN
        ipt_del_all "$IPT" -t filter -D HNC_WHITELIST -s "$ip" -j ACCEPT
    fi
    log "Whitelist remove: $ip ($mac)"
    return 0  # Patch 4.b: 幂等清理强制返 0,见 unmark_device
}

# ═══════════════════════════════════════════════════════════════
# 流量统计（双栈 v4 + v6）
# ═══════════════════════════════════════════════════════════════
# HNC_STATS 轻量互斥锁: 串行化 ensure_stats_online(结转 /128 退休字节 + 删内核规则)
# 与 stats_all(汇总内核实时字节 + stats_v6_retired), 消除并发读写导致的 2x 翻倍毛刺与归零重扣费。
STATS_LOCK_DIR="$HNC_DIR/run/stats_v6.lock"
stats_lock() {
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    local _n=0 _lp _ts _now
    while ! mkdir "$STATS_LOCK_DIR" 2>/dev/null; do
        _lp=$(cat "$STATS_LOCK_DIR/pid" 2>/dev/null)
        _ts=$(cat "$STATS_LOCK_DIR/ts" 2>/dev/null)
        _now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
            rm -rf "$STATS_LOCK_DIR" 2>/dev/null
            continue
        fi
        case "$_ts:$_now" in
            *[!0-9:]*|:*) ;;
            *) [ "$_ts" -gt 0 ] && [ $((_now - _ts)) -ge 15 ] && rm -rf "$STATS_LOCK_DIR" 2>/dev/null && continue ;;
        esac
        _n=$((_n + 1))
        [ "$_n" -ge 30 ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$$" > "$STATS_LOCK_DIR/pid" 2>/dev/null
    date +%s > "$STATS_LOCK_DIR/ts" 2>/dev/null
    return 0
}

stats_unlock() {
    [ "$(cat "$STATS_LOCK_DIR/pid" 2>/dev/null)" = "$$" ] && rm -rf "$STATS_LOCK_DIR" 2>/dev/null
    return 0
}

# 幂等维护单 IP 的 v4 HNC_STATS 规则:
#   - 缺则 -A 补齐(保住已有规则的累计字节, 不因重设限速清零);
#   - 若历史竞态留下了 >1 条同向重复规则, 仅裁掉多余副本保留 1 条。
_ensure_v4_stats_ip() {
    _ipt_resolve
    local ip=$1 _cnt _extra
    [ -z "$ip" ] && return 1
    $IPT -t mangle -L HNC_STATS -n >/dev/null 2>&1 || $IPT -t mangle -N HNC_STATS 2>/dev/null
    if ! $IPT -t mangle -C HNC_STATS -s "$ip" -j RETURN 2>/dev/null; then
        $IPT -t mangle -A HNC_STATS -s "$ip" -j RETURN 2>/dev/null || return 1
    else
        _cnt=$($IPT -t mangle -S HNC_STATS 2>/dev/null | awk -v t="$ip" '$1=="-A" && $3=="-s" && ($4==t || $4==t"/32") && $NF=="RETURN"{c++} END{print c+0}')
        _extra=$((_cnt - 1))
        while [ "$_extra" -gt 0 ]; do
            $IPT -t mangle -D HNC_STATS -s "$ip" -j RETURN 2>/dev/null || break
            _extra=$((_extra - 1))
        done
    fi
    if ! $IPT -t mangle -C HNC_STATS -d "$ip" -j RETURN 2>/dev/null; then
        $IPT -t mangle -A HNC_STATS -d "$ip" -j RETURN 2>/dev/null || return 1
    else
        _cnt=$($IPT -t mangle -S HNC_STATS 2>/dev/null | awk -v t="$ip" '$1=="-A" && $3=="-d" && ($4==t || $4==t"/32") && $NF=="RETURN"{c++} END{print c+0}')
        _extra=$((_cnt - 1))
        while [ "$_extra" -gt 0 ]; do
            $IPT -t mangle -D HNC_STATS -d "$ip" -j RETURN 2>/dev/null || break
            _extra=$((_extra - 1))
        done
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 清理所有规则（v4+v6）
# 双栈清理所有链 + 解绑所有 builtin 跳转
# ═══════════════════════════════════════════════════════════════
cleanup() {
    _ipt_resolve
    log "Cleanup all HNC rules..."

    # 解除 builtin 链上的 jump（v4+v6 双栈，循环 -D 清除可能的历史重复挂载）
    for entry in \
        "mangle PREROUTING  HNC_PREROUTE_GUARD" \
        "mangle PREROUTING  HNC_RESTORE" \
        "mangle FORWARD     HNC_RESTORE" \
        "mangle FORWARD     HNC_MARK"    \
        "mangle FORWARD     HNC_STATS"   \
        "mangle FORWARD     HNC_TCPMSS"  \
        "mangle POSTROUTING HNC_SAVE"    \
        "mangle POSTROUTING HNC_EGRESS_FIX" \
        "filter FORWARD     HNC_CTRL"    \
        "filter FORWARD     HNC_ISOLATE" \
        "filter FORWARD     HNC_WHITELIST"; do
        set -- $entry
        ipt_dual_del_all -t "$1" -D "$2" -j "$3"
    done

    # flush + delete 所有用户链（v4）
    for chain in HNC_PREROUTE_GUARD HNC_RESTORE HNC_MARK HNC_STATS HNC_TCPMSS HNC_SAVE HNC_EGRESS_FIX; do
        $IPT -t mangle -F "$chain" 2>/dev/null
        $IPT -t mangle -X "$chain" 2>/dev/null
    done
    for chain in HNC_CTRL HNC_ISOLATE HNC_WHITELIST; do
        $IPT -t filter -F "$chain" 2>/dev/null
        $IPT -t filter -X "$chain" 2>/dev/null
    done

    # flush + delete 所有用户链（v6，mangle 与 filter 独立判断）
    if ipv6_mangle_ok; then
        for chain in HNC_PREROUTE_GUARD HNC_RESTORE HNC_MARK HNC_STATS HNC_TCPMSS HNC_SAVE HNC_EGRESS_FIX; do
            $IP6T -t mangle -F "$chain" 2>/dev/null
            $IP6T -t mangle -X "$chain" 2>/dev/null
        done
    fi
    if ipv6_filter_ok; then
        for chain in HNC_CTRL HNC_ISOLATE HNC_WHITELIST; do
            $IP6T -t filter -F "$chain" 2>/dev/null
            $IP6T -t filter -X "$chain" 2>/dev/null
        done
    fi
    # 兜底回收应用限速与应用 QoS 孤儿链
    for _T in "$IPT" "$(ipv6_mangle_ok && echo "$IP6T")"; do
        [ -z "$_T" ] && continue
        for _ac in HNC_APP_LIMIT HNC_APP_LIMIT_UP HNC_APP_QOS_MARK; do
            for _k in 1 2 3 4; do $_T -t mangle -D FORWARD -j "$_ac" 2>/dev/null || break; done
        done
        for _ac in HNC_APP_LIMIT_DOWN HNC_APP_QOS; do
            for _k in 1 2 3 4; do $_T -t mangle -D POSTROUTING -j "$_ac" 2>/dev/null || break; done
        done
        for _ac in HNC_APP_LIMIT HNC_APP_LIMIT_UP HNC_APP_LIMIT_DOWN HNC_APP_QOS HNC_APP_QOS_IP HNC_APP_QOS_MARK \
                   $($_T -t mangle -S 2>/dev/null | awk '/^-N HNC_AL_C[0-9]+$/{print $2}'); do
            $_T -t mangle -F "$_ac" 2>/dev/null || true
            $_T -t mangle -X "$_ac" 2>/dev/null || true
        done
    done
    for _T in "$IPT" "$(ipv6_filter_ok && echo "$IP6T")"; do
        [ -z "$_T" ] && continue
        for _qc in HNC_QUIC HNC_QUIC_APPLIM; do
            for _k in 1 2 3 4; do $_T -t filter -D FORWARD -j "$_qc" 2>/dev/null || break; done
            $_T -t filter -F "$_qc" 2>/dev/null || true
            $_T -t filter -X "$_qc" 2>/dev/null || true
        done
    done
    rm -f "$HNC_DIR/run/stats_v6_map" "$HNC_DIR/run/stats_v6_retired" 2>/dev/null
    rm -rf "$HNC_DIR/run/stats_v6.lock" 2>/dev/null

    log "Cleanup complete"
}

# ═══════════════════════════════════════════════════════════════
# per-device 流量统计扩展（ensure_stats_online / stats_all）
# ═══════════════════════════════════════════════════════════════
#   stats_all
#     一次性输出所有 IP 的累计 rx/tx 字节,空格分隔,一行一个。
#     格式: <ip> <rx_bytes> <tx_bytes>
#     注: rx = download = 设备是 dst (-d ip 规则)
#         tx = upload   = 设备是 src (-s ip 规则)

# ensure_stats_online — 让 HNC_STATS 的 per-IP 计数规则与当前在线设备【对齐】:
#   - 在线 IP 缺规则 → 幂等补上(先 -C 检测、缺了才 -A,绝不删/重加,保住累计)
#   - 链里有但已不在线的 IP → 删掉(兜底防链无限增长; 该设备在线时已被采样过)
#
# 安全护栏: devices.json 缺失/解析不出任何在线 IP 时【只补不删】(空集不当作
# "全部离线"去清空整条链, 防 devices.json 半写/损坏瞬间误删所有计数)。
# 双栈 HNC_STATS 计数辅助 — 兼容有无 opt 列的 ip6tables -nvxL 输出
# AWK 内置 IPv6 规范化片段: 展开 :: 并去除每组前导 0, 消除 ip -6 neigh 与 ip6tables -nvxL 缩写差异
_IP6_CANON_AWK='
function canon_ip6(raw,    s, hal, nl, nr, L, R, z, out, i, h) {
    s = tolower(raw)
    sub(/\/[0-9]+$/, "", s)
    sub(/%.*/, "", s)
    if (s !~ /:/) return s
    if (index(s, "::") > 0) {
        split(s, hal, "::")
        nl = (hal[1] == "") ? 0 : split(hal[1], L, ":")
        nr = (hal[2] == "") ? 0 : split(hal[2], R, ":")
        z = 8 - nl - nr
        out = ""
        for (i = 1; i <= nl; i++) { h = L[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
        for (i = 1; i <= z; i++)  { out = (out == "" ? "0" : out ":0") }
        for (i = 1; i <= nr; i++) { h = R[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
        return out
    }
    nl = split(s, L, ":")
    out = ""
    for (i = 1; i <= nl; i++) { h = L[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
    return out
}
'

_ip6_stats_dump() {
    _ipt_resolve
    [ "$_IPV6_PROBED" = "1" ] && [ "$IPV6_OK" = "0" ] && return 0
    command -v "${IP6T%% *}" >/dev/null 2>&1 || return 0
    $IP6T -t mangle -L HNC_STATS -nvx 2>/dev/null | awk "$_IP6_CANON_AWK"'
    $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 == "RETURN" {
        b = $2 + 0
        mac = ""
        for (i = 4; i <= NF; i++) {
            if ($i == "MAC" && i < NF) { mac = tolower($(i+1)); break }
        }
        if (mac != "") {
            tx[mac] += b
            next
        }
        for (i = 4; i < NF; i++) {
            if ($i == "::/0" && $(i+1) != "::/0" && $(i+1) ~ /:/) {
                raw_dst = tolower($(i+1))
                sub(/\/128$/, "", raw_dst)
                dst = canon_ip6(raw_dst)
                rx[dst] += b
                if (!(dst in raw_of)) raw_of[dst] = raw_dst
                break
            }
        }
    }
    END {
        for (m in tx) printf "MAC %s %.0f\n", m, tx[m]
        for (d in rx) printf "DST %s %.0f %s\n", d, rx[d], raw_of[d]
    }'
}

ensure_stats_online() {
    _ipt_resolve
    local devices_flat="$HNC_DIR/run/devices.flat"
    local devices_file="$HNC_DIR/data/devices.json"
    local v6_map="$HNC_DIR/run/stats_v6_map"
    local v6_ret="$HNC_DIR/run/stats_v6_retired"

    stats_lock || return 0
    if ! $IPT -t mangle -L HNC_STATS -n >/dev/null 2>&1; then
        $IPT -t mangle -N HNC_STATS 2>/dev/null
        rm -f "$v6_map" "$v6_ret" 2>/dev/null
    fi
    $IPT -t mangle -C FORWARD -j HNC_STATS 2>/dev/null \
        || $IPT -t mangle -I FORWARD 3 -j HNC_STATS 2>/dev/null \
        || $IPT -t mangle -A FORWARD -j HNC_STATS 2>/dev/null
    if ipv6_mangle_ok; then
        if ! $IP6T -t mangle -L HNC_STATS -n >/dev/null 2>&1; then
            $IP6T -t mangle -N HNC_STATS 2>/dev/null
            rm -f "$v6_map" "$v6_ret" 2>/dev/null
        fi
        $IP6T -t mangle -C FORWARD -j HNC_STATS 2>/dev/null \
            || $IP6T -t mangle -I FORWARD 3 -j HNC_STATS 2>/dev/null \
            || $IP6T -t mangle -A FORWARD -j HNC_STATS 2>/dev/null
    fi

    local online_tmp="$HNC_DIR/run/.stats_online.$$"
    local mac_tmp="$HNC_DIR/run/.stats_mac.$$"
    local on_macs_tmp="$HNC_DIR/run/.stats_onmac.$$"
    : > "$mac_tmp"
    if [ -s "$devices_flat" ]; then
        awk -F'[ \t|]+' '
            /^[[:space:]]*#/ || NF < 2 { next }
            {
                m = ""; ip = ""
                for (i = 1; i <= NF; i++) {
                    if (m == "" && $i ~ /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/) m = tolower($i)
                    else if (ip == "" && $i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip = $i
                }
                if (m != "" && ip != "") printf "%s %s\n", ip, m
            }
        ' "$devices_flat" 2>/dev/null > "$mac_tmp"
    fi
    if [ ! -s "$mac_tmp" ]; then
        if [ ! -s "$devices_file" ]; then
            rm -f "$online_tmp" "$mac_tmp" "$on_macs_tmp" 2>/dev/null
            stats_unlock
            return 0
        fi
        # 校验 devices.json 为完整闭合 JSON: 避免半写/截断瞬间误判全部设备离线;
        # 若为合法空对象 "{}"(最后一台客户端已离线满 90s), 允许继续执行双栈离线清场!
        local _trimmed_first _trimmed_last _json_valid=0
        _trimmed_first=$(tr -d ' \t\r\n' < "$devices_file" 2>/dev/null | cut -c1)
        _trimmed_last=$(tr -d ' \t\r\n' < "$devices_file" 2>/dev/null | awk '{print substr($0, length($0), 1)}')
        [ "$_trimmed_first" = "{" ] && [ "$_trimmed_last" = "}" ] && _json_valid=1
        if [ "$_json_valid" != "1" ]; then
            rm -f "$online_tmp" "$mac_tmp" "$on_macs_tmp" 2>/dev/null
            stats_unlock
            return 0
        fi
        grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$devices_file" 2>/dev/null | \
        while IFS= read -r blk; do
            m=$(printf '%s' "$blk" | sed -nE 's/^"([0-9a-fA-F:]{17})".*/\1/p' | tr 'A-F' 'a-f')
            ip=$(printf '%s' "$blk" | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([0-9.]+)".*/\1/p')
            [ -n "$m" ] && [ -n "$ip" ] && printf '%s %s\n' "$ip" "$m"
        done > "$mac_tmp"
    fi
    awk '{print $2}' "$mac_tmp" | sort -u > "$on_macs_tmp"
    if [ -s "$mac_tmp" ]; then
        awk '{print $1}' "$mac_tmp" | sort -u > "$online_tmp"
    else
        grep -oE '"ip"[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' "$devices_file" 2>/dev/null \
            | sed -nE 's/.*"([0-9.]+)".*/\1/p' | sort -u > "$online_tmp"
    fi

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        _ensure_v4_stats_ip "$ip"
    done < "$online_tmp"

    # 合法数据源下(含 "{}" 全员离线): 清理已离线 IPv4 计数规则
    $IPT -t mangle -S HNC_STATS 2>/dev/null \
        | awk '/-j RETURN/{for(i=1;i<=NF;i++) if($i=="-s"||$i=="-d"){t=$(i+1); sub(/\/32$/,"",t); print t}}' \
        | sort -u | while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        grep -qxF "$ip" "$online_tmp" 2>/dev/null && continue
        ipt_del_all "$IPT" -t mangle -D HNC_STATS -s "$ip" -j RETURN
        ipt_del_all "$IPT" -t mangle -D HNC_STATS -d "$ip" -j RETURN
    done

    # IPv6 双栈设备流量计数闭环
    #   1) 在线 MAC: 幂等维护唯一一条 -m mac 上行计数与活跃邻居 -d <ip6>/128 下行计数;
    #   2) 在线设备过期的 RFC 4941 临时地址: 先把内核字节结转累加至 stats_v6_retired[mac], 再删 -d 规则, 零漏计零泄漏;
    #   3) 已离线设备(不在 on_macs_tmp): 同步删除 -m mac 与其名下全部 -d <ip6>/128 规则, 并清空 stats_v6_map/stats_v6_retired,
    #      保证 v4+v6 同步归零, 杜绝重连时 cur<prev 非对称残留引发 limit_policy 重复扣减配额!
    if ipv6_mangle_ok; then
        local iface neigh_tmp d6_now act_d6_tmp del_d6_tmp _cnt _extra _n6_raw
        iface=$(cat "$HNC_DIR/run/iface.cache" 2>/dev/null | tr -d '\r\n ')
        [ -z "$iface" ] && iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')

        # 1) 在线 MAC 上行规则补齐 + 去重; 离线 MAC 上行规则清理
        while IFS= read -r m; do
            [ -z "$m" ] && continue
            if ! $IP6T -t mangle -C HNC_STATS -m mac --mac-source "$m" -j RETURN 2>/dev/null; then
                $IP6T -t mangle -A HNC_STATS -m mac --mac-source "$m" -j RETURN 2>/dev/null
            else
                _cnt=$($IP6T -t mangle -S HNC_STATS 2>/dev/null | awk -v m="$m" 'tolower($0) ~ ("--mac-source " m " ") && $NF=="RETURN"{c++} END{print c+0}')
                _extra=$((_cnt - 1))
                while [ "$_extra" -gt 0 ]; do
                    $IP6T -t mangle -D HNC_STATS -m mac --mac-source "$m" -j RETURN 2>/dev/null || break
                    _extra=$((_extra - 1))
                done
            fi
        done < "$on_macs_tmp"

        $IP6T -t mangle -S HNC_STATS 2>/dev/null \
            | awk '/--mac-source/ && /-j RETURN/{for(i=1;i<NF;i++) if($i=="--mac-source") print tolower($(i+1))}' \
            | sort -u | while IFS= read -r m; do
            [ -z "$m" ] && continue
            grep -qxF "$m" "$on_macs_tmp" 2>/dev/null && continue
            ipt_del_all "$IP6T" -t mangle -D HNC_STATS -m mac --mac-source "$m" -j RETURN
        done

        # 2) 采集当前活跃的全局/ULA IPv6 邻居(仅限在线 MAC; ip -6 neigh 失败时回退 ip neigh)
        neigh_tmp="$HNC_DIR/run/.stats_n6.$$"
        act_d6_tmp="$HNC_DIR/run/.stats_act6.$$"
        del_d6_tmp="$HNC_DIR/run/.stats_del6.$$"
        d6_now="$HNC_DIR/run/.stats_d6now.$$"
        : > "$neigh_tmp"
        if [ -n "$iface" ] && [ -s "$on_macs_tmp" ]; then
            if ! _n6_raw=$(ip -6 neigh show dev "$iface" 2>/dev/null) || { [ -z "$_n6_raw" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
                _n6_raw=$(ip neigh show dev "$iface" 2>/dev/null)
            fi
            printf '%s\n' "$_n6_raw" | awk -v onf="$on_macs_tmp" "$_IP6_CANON_AWK"'
            BEGIN { while ((getline m < onf) > 0) if (m != "") on[m] = 1; close(onf) }
            $1 ~ /:/ {
                a = tolower($1)
                if (a ~ /^fe80:/ || a ~ /^ff/ || a == "::1" || a == "::") next
                st = $NF
                if (st == "FAILED" || st == "INCOMPLETE") next
                mac = ""
                for (i = 2; i <= NF; i++) {
                    if ($i == "lladdr" && i < NF) { mac = tolower($(i+1)); break }
                }
                if (mac in on) {
                    ca = canon_ip6(a)
                    if (!seen[ca]++) print ca, mac, a
                }
            }' > "$neigh_tmp"
        fi

        while read -r ca m raw_a; do
            [ -z "$ca" ] && continue
            if ! $IP6T -t mangle -C HNC_STATS -d "$raw_a/128" -j RETURN 2>/dev/null \
               && ! $IP6T -t mangle -C HNC_STATS -d "$ca/128" -j RETURN 2>/dev/null; then
                $IP6T -t mangle -A HNC_STATS -d "$raw_a/128" -j RETURN 2>/dev/null
            fi
        done < "$neigh_tmp"

        # 3) 读取当前内核 IPv6 HNC_STATS 计数: 对已不在活跃邻居表中的 /128 规则执行结转或离线淘汰
        _ip6_stats_dump > "$d6_now"
        : > "${v6_map}.tmp"
        : > "${v6_ret}.tmp"
        : > "$del_d6_tmp"
        awk -v nf="$neigh_tmp" -v onf="$on_macs_tmp" -v d6="$d6_now" \
            -v v6m="$v6_map" -v v6r="$v6_ret" \
            -v out_map="${v6_map}.tmp" -v out_ret="${v6_ret}.tmp" -v out_del="$del_d6_tmp" "$_IP6_CANON_AWK"'
        BEGIN {
            while ((getline m < onf) > 0) if (m != "") on[m] = 1
            close(onf)
            while ((getline ln < v6m) > 0) {
                split(ln, a, " ")
                if (a[1] != "" && a[2] != "") owner[canon_ip6(a[1])] = tolower(a[2])
            }
            close(v6m)
            while ((getline ln < nf) > 0) {
                split(ln, a, " ")
                if (a[1] != "" && a[2] != "") {
                    active[a[1]] = a[2]
                    owner[a[1]] = a[2]
                }
            }
            close(nf)
            while ((getline ln < v6r) > 0) {
                split(ln, a, " ")
                m = tolower(a[1])
                if (m in on) {
                    ret_rx[m] = a[2] + 0
                    ret_tx[m] = a[3] + 0
                }
            }
            close(v6r)
            while ((getline ln < d6) > 0) {
                split(ln, a, " ")
                if (a[1] != "DST") continue
                ca = a[2]; b = a[3] + 0; raw_d = (a[4] != "" ? a[4] : a[2])
                if (ca in active) continue
                own = owner[ca]
                if (own != "" && (own in on) && b > 0) {
                    ret_rx[own] += b
                }
                print raw_d > out_del
                if (raw_d != ca) print ca > out_del
                delete owner[ca]
            }
            close(d6)
            for (ca in active) {
                printf "%s %s\n", ca, active[ca] > out_map
            }
            for (m in ret_rx) {
                if ((m in on) && (ret_rx[m] > 0 || ret_tx[m] > 0)) {
                    printf "%s %.0f %.0f\n", m, ret_rx[m], ret_tx[m] > out_ret
                }
            }
        }'
        mv -f "${v6_map}.tmp" "$v6_map" 2>/dev/null || : > "$v6_map"
        mv -f "${v6_ret}.tmp" "$v6_ret" 2>/dev/null || : > "$v6_ret"

        # 4) 从内核链彻底删除已结转/已离线的 -d <ip6>/128 规则(含任何孤立 -d 规则)
        if [ -s "$del_d6_tmp" ]; then
            sort -u "$del_d6_tmp" | while IFS= read -r old6; do
                [ -z "$old6" ] && continue
                ipt_del_all "$IP6T" -t mangle -D HNC_STATS -d "$old6/128" -j RETURN
            done
        fi
        # 兜底清理 byte=0 或未命中 dump 的残留 -d 规则, 并裁除活跃 /128 的重复副本
        awk '{print $1}' "$neigh_tmp" > "$act_d6_tmp"
        $IP6T -t mangle -S HNC_STATS 2>/dev/null \
            | awk "$_IP6_CANON_AWK"'/-d / && /-j RETURN/{for(i=1;i<NF;i++) if($i=="-d"){raw=$(i+1); sub(/\/128$/,"",raw); print canon_ip6(raw), raw}}' \
            | awk '{cnt[$1]++; raw[$1]=$2} END{for(c in cnt) print c, cnt[c], raw[c]}' \
            | while read -r ca cnt raw6; do
            [ -z "$ca" ] && continue
            if ! grep -qxF "$ca" "$act_d6_tmp" 2>/dev/null; then
                ipt_del_all "$IP6T" -t mangle -D HNC_STATS -d "$raw6/128" -j RETURN
            elif [ "${cnt:-0}" -gt 1 ]; then
                _extra=$((cnt - 1))
                while [ "$_extra" -gt 0 ]; do
                    $IP6T -t mangle -D HNC_STATS -d "$raw6/128" -j RETURN 2>/dev/null || break
                    _extra=$((_extra - 1))
                done
            fi
        done
        rm -f "$neigh_tmp" "$act_d6_tmp" "$del_d6_tmp" "$d6_now" 2>/dev/null
    fi

    rm -f "$online_tmp" "$mac_tmp" "$on_macs_tmp" 2>/dev/null
    stats_unlock
}

stats_all() {
    _ipt_resolve
    local devices_flat="$HNC_DIR/run/devices.flat"
    local devices_file="$HNC_DIR/data/devices.json"
    local v6_map="$HNC_DIR/run/stats_v6_map"
    local v6_ret="$HNC_DIR/run/stats_v6_retired"
    local d4_tmp="$HNC_DIR/run/.s4.$$" d6_tmp="$HNC_DIR/run/.s6.$$" map_tmp="$HNC_DIR/run/.sm.$$"

    stats_lock || true
    $IPT -t mangle -L HNC_STATS -nvx 2>/dev/null > "$d4_tmp"
    _ip6_stats_dump > "$d6_tmp"
    : > "$map_tmp"
    # 优先读取 run/devices.flat 快路径(避免每轮正则切片 JSON), 缺失或无记录时回退 devices.json
    if [ -s "$devices_flat" ]; then
        awk -F'[ \t|]+' '
            /^[[:space:]]*#/ || NF < 2 { next }
            {
                m = ""; ip = ""
                for (i = 1; i <= NF; i++) {
                    if (m == "" && $i ~ /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/) m = tolower($i)
                    else if (ip == "" && $i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip = $i
                }
                if (m != "" && ip != "") printf "%s %s\n", ip, m
            }
        ' "$devices_flat" 2>/dev/null > "$map_tmp"
    fi
    if [ ! -s "$map_tmp" ] && [ -f "$devices_file" ]; then
        grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$devices_file" 2>/dev/null | \
        while IFS= read -r blk; do
            m=$(printf '%s' "$blk" | sed -nE 's/^"([0-9a-fA-F:]{17})".*/\1/p' | tr 'A-F' 'a-f')
            ip=$(printf '%s' "$blk" | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([0-9.]+)".*/\1/p')
            [ -n "$m" ] && [ -n "$ip" ] && printf '%s %s\n' "$ip" "$m"
        done > "$map_tmp"
    fi

    awk -v d4="$d4_tmp" -v d6="$d6_tmp" -v mp="$map_tmp" -v v6m="$v6_map" -v v6r="$v6_ret" "$_IP6_CANON_AWK"'
    BEGIN {
        while ((getline ln < mp) > 0) {
            split(ln, a, " ")
            if (a[1] != "" && a[2] != "" && !(a[2] in mac_ip)) mac_ip[a[2]] = a[1]
        }
        close(mp)
        while ((getline ln < v6m) > 0) {
            split(ln, a, " ")
            if (a[1] != "" && a[2] != "") ip6_owner[canon_ip6(a[1])] = tolower(a[2])
        }
        close(v6m)
        while ((getline ln < v6r) > 0) {
            split(ln, a, " ")
            if (a[1] != "") { ret_rx[tolower(a[1])] = a[2] + 0; ret_tx[tolower(a[1])] = a[3] + 0 }
        }
        close(v6r)
        # 兼容 legacy xtables(含 "--" opt 列, NF>=9, src=f[8] dst=f[9]) 与
        # Android 14-16 iptables-nft(空 opt 列, NF==8, src=f[7] dst=f[8]):
        # HNC_STATS 的 IPv4 规则无扩展 match, 末尾两列恒为 <src> <dst>。
        while ((getline ln < d4) > 0) {
            n = split(ln, f, " ")
            if (n >= 8 && f[1] ~ /^[0-9]+$/ && f[2] ~ /^[0-9]+$/ && f[3] == "RETURN") {
                src = f[n - 1]; dst = f[n]
                sub(/\/32$/, "", src); sub(/\/32$/, "", dst)
                if (src != "0.0.0.0/0" && dst == "0.0.0.0/0") { tx[src] += f[2] + 0; seen[src] = 1 }
                else if (src == "0.0.0.0/0" && dst != "0.0.0.0/0") { rx[dst] += f[2] + 0; seen[dst] = 1 }
            }
        }
        close(d4)
        while ((getline ln < d6) > 0) {
            split(ln, a, " ")
            if (a[1] == "MAC" && (a[2] in mac_ip)) {
                ip4 = mac_ip[a[2]]; tx[ip4] += a[3] + 0; seen[ip4] = 1
            } else if (a[1] == "DST") {
                m = ip6_owner[canon_ip6(a[2])]
                if (m != "" && (m in mac_ip)) {
                    ip4 = mac_ip[m]; rx[ip4] += a[3] + 0; seen[ip4] = 1
                }
            }
        }
        close(d6)
        for (m in ret_rx) {
            if (m in mac_ip) {
                ip4 = mac_ip[m]; rx[ip4] += ret_rx[m]; tx[ip4] += ret_tx[m]; seen[ip4] = 1
            }
        }
        for (ip in seen) printf "%s %.0f %.0f\n", ip, rx[ip] + 0, tx[ip] + 0
    }'
    rm -f "$d4_tmp" "$d6_tmp" "$map_tmp" 2>/dev/null
    stats_unlock
}

# ─── 命令分发 ────────────────────────────────────────────────
# v3.9.2 Patch 0: 写操作加锁,协调并发写入
#   - 单设备写(mark/unmark/blacklist/whitelist 操作): 按 MAC 加锁
#   - 全局写(init/cleanup/whitelist_on/whitelist_off): gate 锁
#   - 读(stats/stats_all/ensure_stats/reset_counters): 不加锁
# 锁失败(rc=11) 向上传递,调用方可选择重试或放弃。
# 见 bin/hnc_lock.sh 门禁模式说明。
. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    # hnc_lock.sh 不可用时降级为无锁模式,保持向后兼容
    # 这不应该在正常部署里发生,但测试环境 / 部分升级场景下可能
    mac_lock()    { return 0; }
    mac_unlock()  { return 0; }
    gate_lock()   { return 0; }
    gate_unlock() { return 0; }
}

case "$1" in
    # ═══ 全局写 gate 锁 ══════════════════════════════════════
    init)
        gate_lock || exit 11
        init_chains
        rc=$?
        gate_unlock
        exit $rc ;;
    cleanup)
        gate_lock || exit 11
        cleanup
        rc=$?
        gate_unlock
        exit $rc ;;
    whitelist_on)
        gate_lock || exit 11
        whitelist_mode_on "$2"
        rc=$?
        gate_unlock
        exit $rc ;;
    whitelist_off)
        gate_lock || exit 11
        whitelist_mode_off
        rc=$?
        gate_unlock
        exit $rc ;;

    # ═══ per-MAC 锁(参数 2 或 3 是 MAC) ══════════════════════
    # mark <ip> <mac> <mark_id>  → MAC 在 $3
    # unmark <ip> <mac> <mark_id> → MAC 在 $3
    # blacklist_add <ip> <mac>    → MAC 在 $3
    # blacklist_remove <ip> <mac> → MAC 在 $3
    # whitelist_add <ip> <mac>    → MAC 在 $3
    # whitelist_remove <ip> <mac> → MAC 在 $3
    mark)
        mac_lock "$3" || exit 11
        mark_device "$2" "$3" "$4"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;
    unmark)
        mac_lock "$3" || exit 11
        unmark_device "$2" "$3" "$4"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;
    blacklist_add)
        mac_lock "$3" || exit 11
        blacklist_add "$2" "$3"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;
    blacklist_remove)
        mac_lock "$3" || exit 11
        blacklist_remove "$2" "$3"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;
    whitelist_add)
        mac_lock "$3" || exit 11
        whitelist_add "$2" "$3"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;
    whitelist_remove)
        mac_lock "$3" || exit 11
        whitelist_remove "$2" "$3"
        rc=$?
        mac_unlock "$3"
        exit $rc ;;

    # ═══ 客户端隔离与统计 ════════════════════════════════════
    set_isolation)
        gate_lock || exit 11
        _ipt_resolve
        _iso_if=$2; _iso_on=$3
        for _T in "$IPT" "$(ipv6_filter_ok && echo "$IP6T")"; do
            [ -z "$_T" ] && continue
            for _k in 1 2 3 4; do $_T -t filter -D FORWARD -j HNC_ISOLATE 2>/dev/null || break; done
            $_T -t filter -F HNC_ISOLATE 2>/dev/null || true
            if [ "$_iso_on" = "on" ] || [ "$_iso_on" = "1" ] || [ "$_iso_on" = "true" ]; then
                [ -n "$_iso_if" ] || { gate_unlock; exit 1; }
                $_T -t filter -N HNC_ISOLATE 2>/dev/null || $_T -t filter -F HNC_ISOLATE 2>/dev/null
                $_T -t filter -A HNC_ISOLATE -i "$_iso_if" -o "$_iso_if" -j DROP 2>/dev/null
                $_T -t filter -I FORWARD 1 -j HNC_ISOLATE 2>/dev/null
            else
                $_T -t filter -X HNC_ISOLATE 2>/dev/null || true
            fi
        done
        gate_unlock
        exit 0 ;;
    ensure_stats_online) ensure_stats_online ;;
    stats_all)         stats_all ;;
    *)
        echo "Usage: $0 {init|mark|unmark|blacklist_add|blacklist_remove|"
        echo "           whitelist_add|whitelist_remove|whitelist_on|whitelist_off|"
        echo "           set_isolation|ensure_stats_online|stats_all|cleanup}"
        echo ""
        _ipt_root=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P)
        _ipt_ver=""
        for _ipt_p in "${_ipt_root:+$_ipt_root/module.prop}" "/data/local/hnc/module.prop" "/data/adb/modules/hotspot_net_ctl/module.prop"; do
            [ -n "$_ipt_p" ] && [ -f "$_ipt_p" ] || continue
            _ipt_ver=$(sed -n '/^version=/{s/^version=//p;q;}' "$_ipt_p" 2>/dev/null | tr -d ' \t\r\n"')
            [ -n "$_ipt_p" ] && [ -n "$_ipt_ver" ] && break
        done
        ipv6_mangle_ok >/dev/null 2>&1 || true
        ipv6_filter_ok >/dev/null 2>&1 || true
        echo "HNC ${_ipt_ver:-v6.1} 双栈支持（IPv4 + IPv6 · 保护低 16 位 netd 路由 netId）"
        echo "支持 ensure_stats_online / stats_all 双栈流量统计与 gate/mac 原子锁"
        echo "运行时检测：IPV6_OK=$IPV6_OK (filter=$IPV6_FILTER_OK)"
        echo ""
        echo "验证命令："
        echo "  $IPT  -t mangle -L HNC_MARK    -nv    # v4 MARK 规则"
        echo "  $IP6T -t mangle -L HNC_MARK    -nv    # v6 MARK 规则"
        echo "  $IPT  -t mangle -L HNC_RESTORE -nv    # v4 CONNMARK restore"
        echo "  $IP6T -t mangle -L HNC_RESTORE -nv    # v6 CONNMARK restore"
        echo "  $IPT  -t mangle -L HNC_SAVE    -nv    # v4 CONNMARK save"
        echo "  $IP6T -t mangle -L HNC_SAVE    -nv    # v6 CONNMARK save"
        echo "  $IPT  -t mangle -L HNC_STATS   -nvx   # v4 流量统计"
        exit 1 ;;
esac
