#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# v6_sync.sh — IPv6 地址 → tc u32 filter 周期性同步器
#
# v3.4.0 新增。解决 IPv6 限速问题：
#
# 旧路径（v3.3.x）依赖 iptables mark + CONNMARK + tc fw mark filter，
# 在 ColorOS 上有累积延迟使 v6 TCP 卡死。
#
# 新路径（v3.4.0）：
#   1. 周期性扫描 ip -6 neigh，得到每台设备当前活跃的 v6 地址
#   2. 直接在 tc 上加 u32 dst/src 地址匹配 filter
#   3. v6 包到达 wlan2 egress 时，被 tc u32 filter 立即分类到对应 class
#   4. 完全跳过 iptables mark / CONNMARK / hash table 查询
#   5. 延迟极低，TCP 不会因 RTT 飙升而崩溃
#
# 旧 mark 路径并存作为防御深度——如果 u32 filter 未及时更新（地址刚换），
# v6 包仍可经由 mark + CONNMARK 走另一条路径到同一个 class。
#
# 数据源：iptables HNC_MARK 链是"哪些设备有限速"的唯一真相源（不读 rules.json）。
# 这样避免了 python3 依赖和 grep 浮点截断之类的祖传 bug。
#
# 命令：
#   v6_sync.sh sync             — 全量同步所有有限速的设备（默认）
#   v6_sync.sh sync_one <mac>   — 只同步一台
#   v6_sync.sh clear <mac>      — 清掉一台的所有 v6 filter
#   v6_sync.sh status           — 显示当前每台设备的 v6 地址 → tc filter 映射

HNC_DIR=${HNC_DIR:-/data/local/hnc}
LOG=$HNC_DIR/logs/v6_sync.log
SNAP_DIR=$HNC_DIR/run/v6
IFB_IFACE=ifb0
PRIO_BASE=200    # v6 u32 filter 优先级 = 200 + mark_id（占 201-299 段）
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
    MARK_BASE="${HNC_MARK_BASE:-0x800000}"
else
    MARK_BASE=0x800000
fi

log() { echo "[$(date '+%H:%M:%S')] [V6] $*" >> "$LOG" 2>/dev/null; }

# ═══════════════════════════════════════════════════════════════
# 数据源：从 iptables HNC_MARK 提取 (mac, mark_hex) 对
# 输出每行 "MAC MARK_HEX" 形如 "e2:0d:4a:48:5d:40 0x80003b"
# ═══════════════════════════════════════════════════════════════
list_marked_devices() {
    iptables -t mangle -L HNC_MARK -n 2>/dev/null | awk '
    /MAC.*MARK set/ {
        mac=""; mark=""
        for (i=1; i<=NF; i++) {
            if ($i == "MAC") mac=$(i+1)
            if ($i == "set" && $(i-1) == "MARK") mark=$(i+1)
        }
        if (mac != "" && mark != "") print mac, mark
    }' | sort -u
}

# ═══════════════════════════════════════════════════════════════
# 拿一台设备当前活跃的 v6 地址
# 排除 link-local fe80::（不可路由）和 FAILED/INCOMPLETE 状态
# 同时排除 v4 地址（必须含 ":" 才算 v6）
#
# 注：Android 的 `ip -6 neigh` 可能不支持 -6 选项，先试 -6，
# 失败 fallback 到 `ip neigh`（输出含 v4+v6 混合，靠 awk 过滤）
# ═══════════════════════════════════════════════════════════════
get_v6_addrs() {
    local mac=$1 iface=$2
    local raw
    raw=$(ip -6 neigh show dev "$iface" 2>/dev/null)
    [ -z "$raw" ] && raw=$(ip neigh show dev "$iface" 2>/dev/null)
    echo "$raw" | awk -v mac="$mac" '
    {
        line=$0
        m=tolower(mac)
        # 必须：MAC 匹配 + 地址含冒号(v6) + 不是 link-local + 状态非失败
        if (tolower(line) ~ m && $1 ~ /:/ && $1 !~ /^fe80/) {
            state=$NF
            if (state != "FAILED" && state != "INCOMPLETE") print $1
        }
    }' | sort -u
}

# ═══════════════════════════════════════════════════════════════
# 同步一台设备的 v6 filter
# 算法：
#   1. 当前 v6 地址 vs 上次快照
#   2. 无变化 → 立即返回（最常见路径）
#   3. 有变化 → flush 该设备的 v6 filter prio 段，按当前地址重建
# ═══════════════════════════════════════════════════════════════
sync_one() {
    local mac=$1
    local iface=${2:-$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)}
    [ -z "$mac" ] && { log "WARN: sync_one called with empty mac"; return 1; }
    [ -z "$iface" ] && { log "WARN: sync_one no iface"; return 1; }

    # 找 mark_id（从 iptables）
    local mark_hex
    mark_hex=$(list_marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')
    if [ -z "$mark_hex" ]; then
        # 没限速 → 顺手清理可能残留的 v6 filter / 快照
        clear_one "$mac" "$iface"
        return 0
    fi

    # 0x80003b → 59
    local mark_id=$((mark_hex))
    mark_id=$((mark_id - MARK_BASE))
    if [ "$mark_id" -lt 1 ] || [ "$mark_id" -gt 99 ]; then
        log "WARN: invalid mark_id $mark_id for $mac (mark=$mark_hex)"
        return 1
    fi

    local prio=$((PRIO_BASE + mark_id))
    local snap="$SNAP_DIR/$mac"
    mkdir -p "$SNAP_DIR" 2>/dev/null

    # 当前活跃 v6 地址 vs 上次快照
    local cur prev
    cur=$(get_v6_addrs "$mac" "$iface")
    prev=""
    [ -f "$snap" ] && prev=$(cat "$snap" 2>/dev/null)

    # 无变化：跳过（最常见路径，零开销）
    if [ "$cur" = "$prev" ]; then
        return 0
    fi

    log "Sync $mac (mark=$mark_id prio=$prio): addresses changed"
    [ -n "$prev" ] && log "  prev: $(echo "$prev" | tr '\n' ' ')"
    log "  cur:  $(echo "$cur" | tr '\n' ' ')"

    # Flush 该设备的所有 v6 filter（egress + ingress）
    # 该设备独占 prio 段，不会误删别的设备
    tc filter del dev "$iface"     parent 1: prio "$prio" protocol ipv6 2>/dev/null
    tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null

    # 设备 v6 全失活 → 仅记录，不加 filter
    if [ -z "$cur" ]; then
        : > "$snap"
        log "  $mac: no active v6 addresses"
        return 0
    fi

    # 检查 ifb0 上是否有该 class（用户设了 up 限速时才会有）
    local has_ingress=0
    if tc class show dev "$IFB_IFACE" 2>/dev/null | grep -q "1:$mark_id "; then
        has_ingress=1
    fi

    # 重建 filter，每个地址一条
    local n=0 nfail=0
    for addr in $cur; do
        # Egress（下行限速）：wlan2 上 dst 匹配
        if tc filter add dev "$iface" parent 1: protocol ipv6 prio "$prio" u32 \
                match ip6 dst "$addr/128" flowid "1:$mark_id" 2>/dev/null; then
            n=$((n+1))
        else
            nfail=$((nfail+1))
            log "  WARN: egress filter add failed for $addr"
        fi

        # Ingress（上行限速）：ifb0 上 src 匹配（仅当 class 存在）
        if [ "$has_ingress" = "1" ]; then
            tc filter add dev "$IFB_IFACE" parent 1: protocol ipv6 prio "$prio" u32 \
                match ip6 src "$addr/128" flowid "1:$mark_id" 2>/dev/null
        fi
    done

    # 更新快照
    echo "$cur" > "$snap"
    log "  $mac: synced $n filter(s) (failed=$nfail, ingress=$has_ingress)"
}

# ═══════════════════════════════════════════════════════════════
# 清掉一台设备的所有 v6 filter（用于 unmark / 关限速场景）
# ═══════════════════════════════════════════════════════════════
clear_one() {
    local mac=$1
    local iface=${2:-$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)}
    [ -z "$mac" ] && return 1

    local snap="$SNAP_DIR/$mac"

    # 试图从快照文件读出该设备的 prio——但我们没存 prio
    # 改为：从 iptables 找 mark_hex（即使被 unmark 了，可能还在）
    local mark_hex
    mark_hex=$(list_marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')

    if [ -n "$mark_hex" ]; then
        local mark_id=$((mark_hex))
        mark_id=$((mark_id - MARK_BASE))
        local prio=$((PRIO_BASE + mark_id))
        tc filter del dev "$iface"     parent 1: prio "$prio" protocol ipv6 2>/dev/null
        tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null
        log "Clear $mac (mark=$mark_id prio=$prio): filters removed"
    else
        log "Clear $mac: no mark found, snapshot only"
    fi

    rm -f "$snap" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════
# 全量同步：遍历所有有限速的设备 + 清理孤儿快照
# ═══════════════════════════════════════════════════════════════
sync_all() {
    local iface
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    [ -z "$iface" ] && { log "WARN: sync_all no iface"; return 1; }

    local devices
    devices=$(list_marked_devices)

    # 没有任何限速设备 → 清理所有孤儿快照后返回
    if [ -z "$devices" ]; then
        if [ -d "$SNAP_DIR" ]; then
            for f in "$SNAP_DIR"/*; do
                [ -f "$f" ] || continue
                local mac; mac=$(basename "$f")
                clear_one "$mac" "$iface"
            done
        fi
        return 0
    fi

    # 同步每台有限速的设备
    local active_macs=""
    echo "$devices" | while read -r mac mark_hex; do
        [ -z "$mac" ] && continue
        sync_one "$mac" "$iface"
    done

    # 清理孤儿：快照存在但 iptables 已无 mark
    if [ -d "$SNAP_DIR" ]; then
        for f in "$SNAP_DIR"/*; do
            [ -f "$f" ] || continue
            local mac; mac=$(basename "$f")
            if ! echo "$devices" | awk -v m="$mac" '$1==m {found=1; exit} END{exit !found}'; then
                clear_one "$mac" "$iface"
            fi
        done
    fi
}

# ═══════════════════════════════════════════════════════════════
# 显示当前同步状态（人类可读）
# ═══════════════════════════════════════════════════════════════
show_status() {
    local iface
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    echo "=== HNC v6 sync status ==="
    echo "iface: $iface"
    echo "snap dir: $SNAP_DIR"
    echo ""

    local devices; devices=$(list_marked_devices)
    if [ -z "$devices" ]; then
        echo "(no marked devices)"
        return 0
    fi

    echo "$devices" | while read -r mac mark_hex; do
        [ -z "$mac" ] && continue
        local mark_id=$((mark_hex))
        mark_id=$((mark_id - MARK_BASE))
        local prio=$((PRIO_BASE + mark_id))
        echo "----------------------------------------"
        echo "Device $mac"
        echo "  mark_id=$mark_id (mark=$mark_hex) prio=$prio"
        local addrs; addrs=$(get_v6_addrs "$mac" "$iface")
        if [ -z "$addrs" ]; then
            echo "  active v6 addresses: (none)"
        else
            echo "  active v6 addresses:"
            echo "$addrs" | sed 's/^/    /'
        fi
        local fcount; fcount=$(tc filter show dev "$iface" parent 1: 2>/dev/null \
            | awk -v p="$prio" 'BEGIN{c=0} /^filter / && $0 ~ "pref "p" " {c++} END{print c}')
        echo "  egress filters on $iface: $fcount"
    done
}

# ─── 命令分发 ────────────────────────────────────────────────
case "${1:-sync}" in
    sync|sync_all)  sync_all ;;
    sync_one)       sync_one "$2" ;;
    clear)          clear_one "$2" ;;
    status)         show_status ;;
    *)
        echo "Usage: $0 {sync|sync_one MAC|clear MAC|status}" >&2
        exit 1 ;;
esac
