#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
# rc13: 追加 /data/local/hnc/bin —— /system/bin 被卸时裸命令 fallthrough 到 /data 预置副本。
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
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
#   CONNMARK_MASK 同步扩到 0xffffff（24 位），覆盖整个新段。
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
# rc30.13.1 cleanup: RULES_FILE 在此文件无引用. 子调用走 sh json_set.sh 自己拼路径.
LOG=$HNC_DIR/logs/iptables.log

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [IPT] $*" >> "$LOG" 2>/dev/null || true
}

# v4.0 Patch 1.6: [ERROR] 前缀便于 grep 故障排查
log_error() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [IPT] [ERROR] $*" >> "$LOG" 2>/dev/null || true
}

if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
    MARK_BASE="${HNC_MARK_BASE:-0x800000}"
else
    MARK_BASE=0x800000
fi
# rc30.13.1 cleanup: MARK_BLACKLIST=0xDEAD 是 v3.x 设想的"黑名单专用 mark"但从未启用,
# 黑名单实际走 filter/HNC_CTRL DROP 而不是 mangle MARK. 删 SC2034 死变量.
# CONNMARK 掩码：0xffffff 覆盖低 24 位，足以容纳 MARK_BASE(0x800000) + mark_id(1..99)
# v3.4.1：从 0x1ffff 扩到 0xffffff，配合新 MARK_BASE 避开 Android netd 命名空间
CONNMARK_MASK=0xffffff

# rc2 修 S7: 全文件 iptables/ip6tables 走 $IPT/$IP6T, 统一带 -w 2 xtables 锁.
# 没 -w 时 xtables 被占(watchdog + apply_device_rule 并发常见)会直接 EAGAIN 退,
# 规则部分应用 / 静默失败. -w 2 等最多 2 秒, 覆盖瞬时竞争.
# 例外: 下面 `command -v ip6tables` 探测必须用裸名, command -v 只能接 1 个 arg.
IPT="iptables -w 2"
IP6T="ip6tables -w 2"

# ═══════════════════════════════════════════════════════════════
# v3.3.4 双栈抽象
# ═══════════════════════════════════════════════════════════════

# 运行时检测 $IP6T 是否可用（部分裁剪内核可能没有 IPv6 netfilter）
IPV6_OK=0
if command -v ip6tables >/dev/null 2>&1 \
    && $IP6T -t mangle -L -n >/dev/null 2>&1; then
    IPV6_OK=1
fi

# 在 v4 和 v6 上同时执行同一条命令
# 仅用于协议无关的操作（CONNMARK / MARK / MAC match / 链创建）
# 调用方必须确保参数里不含 -s/-d 这种协议相关的地址参数
# 返回值取 v4 的返回码；v6 失败仅记 warn 日志，不影响流程
ipt_dual() {
    $IPT "$@"
    local r4=$?
    if [ "$IPV6_OK" = "1" ]; then
        # v4.0 patch3.b.2: v6 失败不打 WARN(SD8 Elite/IPA 卸载下 v6 链可能不存在,这是常态不是错误)
        # apply.log/iptables.log 之前每次 mark 都 4 行 WARN 太脏
        # 真要排查 v6, 直接看 $IP6T -t mangle -nL 就够
        $IP6T "$@" 2>/dev/null || true
    fi
    return $r4
}

# 同上，但忽略所有错误（用于幂等删除/清理场景）
ipt_dual_q() {
    $IPT "$@" 2>/dev/null
    [ "$IPV6_OK" = "1" ] && $IP6T "$@" 2>/dev/null
    return 0
}

# v5.1.0-rc1 hotfix: 删除旧规则时循环 -D 直到不存在,避免历史重复规则残留。
ipt_del_all() {
    local cmd=$1
    shift
    while $cmd "$@" 2>/dev/null; do :; done
    return 0
}

ipt_dual_del_all() {
    ipt_del_all "$IPT" "$@"
    [ "$IPV6_OK" = "1" ] && ipt_del_all "$IP6T" "$@"
    return 0
}

# 幂等创建并 flush 用户自定义链（v4+v6）
_ensure_chain() {
    local table=$1 chain=$2
    $IPT -t "$table" -N "$chain" 2>/dev/null
    $IPT -t "$table" -F "$chain" 2>/dev/null
    if [ "$IPV6_OK" = "1" ]; then
        $IP6T -t "$table" -N "$chain" 2>/dev/null
        $IP6T -t "$table" -F "$chain" 2>/dev/null
    fi
}

# 幂等将用户链挂到 builtin 链（v4+v6 独立判断，避免一边重复挂另一边漏挂）
_ensure_link() {
    local table=$1 parent=$2 child=$3 pos=${4:-1}
    $IPT -t "$table" -C "$parent" -j "$child" 2>/dev/null \
        || $IPT -t "$table" -I "$parent" "$pos" -j "$child"
    if [ "$IPV6_OK" = "1" ]; then
        $IP6T -t "$table" -C "$parent" -j "$child" 2>/dev/null \
            || $IP6T -t "$table" -I "$parent" "$pos" -j "$child" 2>/dev/null
    fi
}

# ═══════════════════════════════════════════════════════════════
# 初始化所有链（v4 + v6）
# ═══════════════════════════════════════════════════════════════
init_chains() {
    log "=== Init chains (ipv6=$IPV6_OK) ==="

    # 加载必要 netfilter 模块
    for mod in xt_CONNMARK xt_connmark xt_mark xt_mac xt_conntrack \
               nf_conntrack nf_conntrack_ipv6 nf_defrag_ipv6 \
               ip6t_REJECT ip6t_mac; do
        modprobe "$mod" 2>/dev/null || true
    done
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

    # ── HNC_RESTORE (mangle/PREROUTING): CONNMARK → MARK ──────
    # 下行方向已有连接的后续包直接恢复 mark，节省重复查询开销
    # 对 v6 而言是必需：下行没有 -d 地址规则兜底，全靠这个恢复
    _ensure_chain mangle HNC_RESTORE
    ipt_dual -t mangle -A HNC_RESTORE \
        -m connmark ! --mark 0 \
        -j CONNMARK --restore-mark \
        --nfmask "$CONNMARK_MASK" --ctmask "$CONNMARK_MASK"
    _ensure_link mangle PREROUTING HNC_RESTORE 1

    # ── HNC_MARK (mangle/FORWARD): MAC/IP → MARK ─────────────
    _ensure_chain mangle HNC_MARK
    _ensure_link mangle FORWARD HNC_MARK 1

    # ── HNC_STATS (mangle/FORWARD): 流量字节数 (v4 only) ──────
    $IPT -t mangle -N HNC_STATS 2>/dev/null
    $IPT -t mangle -F HNC_STATS 2>/dev/null
    $IPT -t mangle -C FORWARD -j HNC_STATS 2>/dev/null \
        || $IPT -t mangle -I FORWARD 2 -j HNC_STATS

    # ── HNC_SAVE (mangle/POSTROUTING): MARK → CONNMARK ────────
    # 上行新连接打完 mark 后存入 conntrack，下行回包才能 restore
    _ensure_chain mangle HNC_SAVE
    ipt_dual -t mangle -A HNC_SAVE \
        -m mark ! --mark 0 \
        -j CONNMARK --save-mark \
        --nfmask "$CONNMARK_MASK" --ctmask "$CONNMARK_MASK"
    _ensure_link mangle POSTROUTING HNC_SAVE 1

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
    local mark; mark=$(printf "0x%x" $((MARK_BASE + mark_id)))
    [ -z "$ip" ] && { log "WARN: mark called with empty ip, skip"; return 1; }

    log "Marking $ip ($mac) mark=$mark"

    # ── v3.4.11 P1-4 修复:GC 陈旧 IP 规则(DHCP renew 后旧 IP 规则积累) ──
    # 设备 IP 从 192.168.43.5 → 192.168.43.7 后,旧 IP 的 -s/-d 规则不会自动清,
    # 长跑几天 HNC_MARK / HNC_STATS 链会越来越长。
    #
    # 思路:
    #   1) 从 HNC_MARK 找出所有 mac source 是当前 mac 的 src 规则,提取 IP 集合
    #   2) 从 HNC_MARK 找出所有 mark 是当前 mark id 的 dst 规则,提取 IP 集合
    #   3) 合并去重,删除所有不等于当前 ip 的旧 IP 的 src/dst/stats 规则
    _gc_stale_ips_for_mac "$mac" "$mark" "$ip"

    # ── 清除可能的旧规则（幂等)──
    ipt_del_all "$IPT" -t mangle -D HNC_MARK -s "$ip" -m mac --mac-source "$mac" \
        -j MARK --set-mark "$mark"
    ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$ip" -j MARK --set-mark "$mark"
    ipt_dual_del_all -t mangle -D HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark 0 \
        -j MARK --set-mark "$mark"

    # ── v4 上行：src IP + MAC（最精确）──
    $IPT -t mangle -A HNC_MARK \
        -s "$ip" -m mac --mac-source "$mac" \
        -j MARK --set-mark "$mark"

    # ── v4+v6 上行兜底：仅 MAC（应对 IP 未就绪 / v6 无地址依赖）──
    # -m mark --mark 0 确保不重复 mark 已由 HNC_RESTORE 恢复的包
    ipt_dual -t mangle -A HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark 0 \
        -j MARK --set-mark "$mark"

    # ── v4 下行：dst IP ──
    # 不可省：CONNMARK restore 不一定覆盖所有情况（如新连接的第一个回包）
    $IPT -t mangle -A HNC_MARK \
        -d "$ip" -j MARK --set-mark "$mark"

    # ── v4 流量统计 ──
    # v6 无统计，因为需要跟踪动态地址（代价不值）
    ipt_del_all "$IPT" -t mangle -D HNC_STATS -s "$ip" -j RETURN
    ipt_del_all "$IPT" -t mangle -D HNC_STATS -d "$ip" -j RETURN
    $IPT -t mangle -A HNC_STATS -s "$ip" -j RETURN
    $IPT -t mangle -A HNC_STATS -d "$ip" -j RETURN

    echo "$mark"
}

# ═══════════════════════════════════════════════════════════════
# v3.4.11 P1-4: GC 陈旧 IP 规则
# 参数: mac (xx:xx:xx:xx:xx:xx) / mark (0x800001 格式) / current_ip (跳过的当前 IP)
# 行为: 扫描 HNC_MARK / HNC_STATS,删除所有不等于 current_ip 的 src/dst 规则
# ═══════════════════════════════════════════════════════════════
_gc_stale_ips_for_mac() {
    local mac=$1 mark=$2 cur_ip=$3
    local stale_ips ip_line

    # 步骤 1: 收集所有跟这个 mac/mark 关联的 IP(去重)
    # $IPT -S 输出格式示例:
    #   -A HNC_MARK -s 192.168.43.5/32 -m mac --mac-source aa:bb:cc:dd:ee:ff -j MARK --set-xmark 0x800001/0xffffffff
    #   -A HNC_MARK -d 192.168.43.5/32 -j MARK --set-xmark 0x800001/0xffffffff
    #
    # 用 awk 一次提取:
    #   - 含 --mac-source <mac> 的行 → 取 -s 后的 IP
    #   - 含 --set-xmark <mark> 但不含 --mac-source 的行 → 取 -d 后的 IP
    stale_ips=$($IPT -t mangle -S HNC_MARK 2>/dev/null | awk -v m="$mac" -v mk="$mark" '
        function strip_cidr(ip) { sub(/\/32$/, "", ip); return ip }
        {
            has_mac = 0; has_mark = 0; src_ip = ""; dst_ip = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "--mac-source" && $(i+1) == m) has_mac = 1
                if ($i == "--set-xmark" && index($(i+1), mk) == 1) has_mark = 1
                if ($i == "--set-mark"  && index($(i+1), mk) == 1) has_mark = 1
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
            -j MARK --set-mark "$mark"
        ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$old_ip" -j MARK --set-mark "$mark"
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
    local mark; mark=$(printf "0x%x" $((MARK_BASE + mark_id)))

    log "Unmarking $ip ($mac) mark=$mark"

    # v4.0 Patch 4.b hotfix: unmark 是幂等清理操作 — 规则不存在 == 已清理成功
    # 之前函数最后一条 $IPT -D 失败时 return 非 0,导致 WebUI clearLimit 上报失败给用户
    # 实际场景:热点已关 / 链已被 cleanup / 这条规则之前根本没挂上 — 都不该是错误
    # 所有 -D 命令都 2>/dev/null,失败也继续,最后强制 return 0

    # v3.4.0：先清 v6 filter（trick：clear_one 从 $IPT 反查 mark_id，
    # 必须在删 $IPT 规则之前调用，否则它找不到 mark）
    sh "$HNC_DIR/bin/v6_sync.sh" clear "$mac" 2>/dev/null || true

    ipt_del_all "$IPT" -t mangle -D HNC_MARK -s "$ip" -m mac --mac-source "$mac" \
        -j MARK --set-mark "$mark"
    ipt_del_all "$IPT" -t mangle -D HNC_MARK -d "$ip" -j MARK --set-mark "$mark"
    ipt_dual_del_all -t mangle -D HNC_MARK \
        -m mac --mac-source "$mac" -m mark --mark 0 \
        -j MARK --set-mark "$mark"

    ipt_del_all "$IPT" -t mangle -D HNC_STATS -s "$ip" -j RETURN
    ipt_del_all "$IPT" -t mangle -D HNC_STATS -d "$ip" -j RETURN

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

    if [ "$IPV6_OK" = "1" ]; then
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
whitelist_mode_on() {
    ipt_dual_q -t filter -D HNC_WHITELIST -j DROP
    ipt_dual    -t filter -A HNC_WHITELIST -j DROP
    log "Whitelist mode ON"
}

whitelist_mode_off() {
    $IPT -t filter -F HNC_WHITELIST 2>/dev/null
    [ "$IPV6_OK" = "1" ] && $IP6T -t filter -F HNC_WHITELIST 2>/dev/null
    log "Whitelist mode OFF"
}

whitelist_add() {
    local ip=$1 mac=$2
    ipt_dual_q -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j ACCEPT
    ipt_dual    -t filter -I HNC_WHITELIST 1 -m mac --mac-source "$mac" -j ACCEPT
    [ -n "$ip" ] && $IPT -t filter -I HNC_WHITELIST 1 -s "$ip" -j ACCEPT
    log "Whitelist add: $ip ($mac)"
}

whitelist_remove() {
    local ip=$1 mac=$2
    ipt_dual_q -t filter -D HNC_WHITELIST -m mac --mac-source "$mac" -j ACCEPT
    [ -n "$ip" ] && $IPT -t filter -D HNC_WHITELIST -s "$ip" -j ACCEPT 2>/dev/null
    log "Whitelist remove: $ip ($mac)"
    return 0  # Patch 4.b: 幂等清理强制返 0,见 unmark_device
}

# ═══════════════════════════════════════════════════════════════
# 流量统计（仅 v4）
# ═══════════════════════════════════════════════════════════════
get_stats() {
    local ip=$1
    # v3.4.4：修复 src/dst 写反 bug。
    # rx=download=设备是 dst($9),tx=upload=设备是 src($8)
    local upload; upload=$($IPT -t mangle -L HNC_STATS -nvx 2>/dev/null \
        | awk -v ip="$ip" 'NF>8 && $8==ip {sum+=$2} END{print sum+0}')
    local download; download=$($IPT -t mangle -L HNC_STATS -nvx 2>/dev/null \
        | awk -v ip="$ip" 'NF>8 && $9==ip {sum+=$2} END{print sum+0}')
    echo "{\"upload_bytes\":$upload,\"download_bytes\":$download}"
}

reset_counters() {
    $IPT -t mangle -Z HNC_STATS 2>/dev/null
    log "Counters reset"
}

# ═══════════════════════════════════════════════════════════════
# 清理所有规则（v4+v6）
# v3.3.4：双栈清理所有链 + 解绑所有 builtin 跳转
# ═══════════════════════════════════════════════════════════════
cleanup() {
    log "Cleanup all HNC rules..."

    # 解除 builtin 链上的 jump（v4+v6 双栈）
    for entry in \
        "mangle PREROUTING  HNC_RESTORE" \
        "mangle FORWARD     HNC_MARK"    \
        "mangle POSTROUTING HNC_SAVE"    \
        "filter FORWARD     HNC_CTRL"    \
        "filter FORWARD     HNC_WHITELIST"; do
        set -- $entry
        $IPT -t "$1" -D "$2" -j "$3" 2>/dev/null
        [ "$IPV6_OK" = "1" ] && $IP6T -t "$1" -D "$2" -j "$3" 2>/dev/null
    done
    # HNC_STATS 仅 v4
    $IPT -t mangle -D FORWARD -j HNC_STATS 2>/dev/null

    # flush + delete 所有用户链（v4）
    for chain in HNC_RESTORE HNC_MARK HNC_STATS HNC_SAVE; do
        $IPT -t mangle -F "$chain" 2>/dev/null
        $IPT -t mangle -X "$chain" 2>/dev/null
    done
    for chain in HNC_CTRL HNC_WHITELIST; do
        $IPT -t filter -F "$chain" 2>/dev/null
        $IPT -t filter -X "$chain" 2>/dev/null
    done

    # flush + delete 所有用户链（v6）
    if [ "$IPV6_OK" = "1" ]; then
        for chain in HNC_RESTORE HNC_MARK HNC_SAVE; do
            $IP6T -t mangle -F "$chain" 2>/dev/null
            $IP6T -t mangle -X "$chain" 2>/dev/null
        done
        for chain in HNC_CTRL HNC_WHITELIST; do
            $IP6T -t filter -F "$chain" 2>/dev/null
            $IP6T -t filter -X "$chain" 2>/dev/null
        done
    fi

    log "Cleanup complete"
}

# ═══════════════════════════════════════════════════════════════
# v3.4.4：per-device 流量统计扩展
# ═══════════════════════════════════════════════════════════════
#
# 背景：v3.4.3 之前，HNC_STATS 链只在 mark_device（限速/延迟）时
# 才会为某 IP 添加 RETURN 规则，所以"未限速"的设备没有计数。
# WebUI 上的"下行/上行"字段也因此永远显示 0。
#
# v3.4.4 新增两个命令，让 device_detect.sh 在每次扫描时为所有
# 在线设备维护统计规则，并一次性读出 rx/tx 字节：
#
#   ensure_stats <ip>
#     给某 IP 在 HNC_STATS 链里添加 -s/-d RETURN 规则。
#     用 $IPT -C 检查规则是否已存在,避免重复添加导致双倍计数。
#     mark_device 已经在添加同样规则,先检查再加完全幂等。
#
#   stats_all
#     一次性输出所有 IP 的累计 rx/tx 字节,空格分隔,一行一个。
#     格式: <ip> <rx_bytes> <tx_bytes>
#     注: rx = download = 设备是 dst (-d ip 规则)
#         tx = upload   = 设备是 src (-s ip 规则)
#     v3.4.3 之前的 get_stats 函数 src/dst 写反了,本版顺手修正。

ensure_stats() {
    local ip=$1
    [ -z "$ip" ] && return 1
    # hotfix10 S5: 避免 -C || -A TOCTOU 并发重复 RETURN 规则。
    # 先清理同 IP 现存重复规则,再追加唯一一对 -s/-d RETURN。
    $IPT -t mangle -L HNC_STATS -n >/dev/null 2>&1 || return 1
    ipt_del_all "$IPT" -t mangle -D HNC_STATS -s "$ip" -j RETURN
    ipt_del_all "$IPT" -t mangle -D HNC_STATS -d "$ip" -j RETURN
    $IPT -t mangle -A HNC_STATS -s "$ip" -j RETURN 2>/dev/null || return 1
    $IPT -t mangle -A HNC_STATS -d "$ip" -j RETURN 2>/dev/null || return 1
}

stats_all() {
    $IPT -t mangle -L HNC_STATS -nvx 2>/dev/null | awk '
    # $IPT -nvx 数据行:
    #   $1=pkts $2=bytes $3=target $4=prot $5=opt $6=in $7=out $8=source $9=destination
    # 跳过表头(第 1-2 行)和占位行 0.0.0.0/0 → 0.0.0.0/0
    $1 ~ /^[0-9]+$/ && NF >= 9 {
        if ($8 != "0.0.0.0/0" && $9 == "0.0.0.0/0") {
            # -s ip 规则 = 上传(设备发出)
            tx[$8] += $2
            seen[$8] = 1
        } else if ($8 == "0.0.0.0/0" && $9 != "0.0.0.0/0") {
            # -d ip 规则 = 下载(设备接收)
            rx[$9] += $2
            seen[$9] = 1
        }
    }
    END {
        for (ip in seen) {
            printf "%s %d %d\n", ip, rx[ip]+0, tx[ip]+0
        }
    }'
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
        whitelist_mode_on
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

    # ═══ 只读 / 只改 counter,不加锁 ═══════════════════════════
    stats)             get_stats "$2" ;;
    ensure_stats)      ensure_stats "$2" ;;
    stats_all)         stats_all ;;
    reset_counters)    reset_counters ;;
    *)
        echo "Usage: $0 {init|mark|unmark|blacklist_add|blacklist_remove|"
        echo "           whitelist_add|whitelist_remove|whitelist_on|whitelist_off|"
        echo "           stats|ensure_stats|stats_all|reset_counters|cleanup}"
        echo ""
        echo "v3.3.4 双栈支持（IPv4 + IPv6）"
        echo "v3.4.4 新增 ensure_stats / stats_all（per-device 流量统计）"
        echo "v3.9.2 Patch 0: 写操作由 hnc_lock.sh 的 gate / mac 锁保护"
        echo "运行时检测：IPV6_OK=$IPV6_OK"
        echo ""
        echo "验证命令："
        echo "  $IPT  -t mangle -L HNC_MARK    -nv    # v4 MARK 规则"
        echo "  $IP6T -t mangle -L HNC_MARK    -nv    # v6 MARK 规则"
        echo "  $IPT  -t mangle -L HNC_RESTORE -nv    # v4 CONNMARK restore"
        echo "  $IP6T -t mangle -L HNC_RESTORE -nv    # v6 CONNMARK restore"
        echo "  $IPT  -t mangle -L HNC_SAVE    -nv    # v4 CONNMARK save"
        echo "  $IP6T -t mangle -L HNC_SAVE    -nv    # v6 CONNMARK save"
        echo "  $IPT  -t mangle -L HNC_STATS   -nvx   # v4 流量统计(v3.4.4+)"
        exit 1 ;;
esac
