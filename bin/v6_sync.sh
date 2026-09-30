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
#   v6_sync.sh sync_macs <mac>… — 同步若干台(v5.20: httpd 邻居事件驱动, 合并后一次调用)
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

# v5.20: 地址宽限 + 每台上限
#   - 地址从邻居表消失(或短暂 FAILED/INCOMPLETE)后, 过滤器再保留 V6_GRACE 秒:
#     NDP 探测抖动时不至于先删后加、让设备在空窗里绕过限速; 超过宽限才真正删除。
#   - 每台设备最多 V6_MAX_ADDRS 个地址(按最近看到排序, 超出的最旧地址不装):
#     隐私地址轮换 + 宽限叠加时限制 u32 过滤器条数。
#   快照格式: 头行 "#hnc_v6 iface= mark= ing=" + 每行 "<地址> <最近看到的单调秒>"
#   (旧格式只有地址, 读入时按"刚看到"处理, 向后兼容)。
V6_GRACE=${HNC_V6_GRACE:-300}
V6_MAX_ADDRS=${HNC_V6_MAX_ADDRS:-16}
V6_LOCK="$HNC_DIR/run/v6_sync.lock"

# 单调秒: /proc/uptime(CLOCK_BOOTTIME, 不受墙钟跳变影响)。run/v6 开机即清
# (post-fs-data.sh), 快照里的时间戳不需要跨重启可比。测试可用 HNC_V6_NOW 注入。
v6_now() {
    if [ -n "$HNC_V6_NOW" ]; then echo "$HNC_V6_NOW"; return 0; fi
    local up _rest
    if read -r up _rest < /proc/uptime 2>/dev/null && [ -n "$up" ]; then
        echo "${up%%.*}"; return 0
    fi
    date +%s
}

_v6_sleep() {
    usleep 100000 2>/dev/null && return 0
    sleep 0.1 2>/dev/null && return 0
    sleep 1
}

# v5.20: 进程级互斥。watchdog 60s 周期全量同步与 httpd 事件驱动的 sync_macs 可能
# 同时跑; 同一 prio 段的 del/add 交错会留下重复或缺失的 filter。mkdir 原子锁,
# 持有者已死(pid 不在)则回收; 最多等 ~10s。
v6_lock() {
    local i=0 pid
    while ! mkdir "$V6_LOCK" 2>/dev/null; do
        pid=$(cat "$V6_LOCK/pid" 2>/dev/null)
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            rm -rf "$V6_LOCK" 2>/dev/null
            continue
        fi
        i=$((i+1))
        # pid 文件一直没写出来(持有者在 mkdir 与写 pid 之间被杀)→ 5s 后回收
        if [ -z "$pid" ] && [ "$i" -ge 50 ]; then
            rm -rf "$V6_LOCK" 2>/dev/null
            continue
        fi
        [ "$i" -ge 100 ] && return 1
        _v6_sleep
    done
    echo "$$" > "$V6_LOCK/pid" 2>/dev/null
    trap 'v6_unlock' EXIT
    trap 'v6_unlock; exit 130' INT TERM
    return 0
}

v6_unlock() {
    [ "$(cat "$V6_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$V6_LOCK" 2>/dev/null
    return 0
}

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

# 同一次调用内复用 iptables 读数(sync_all / sync_macs 一次读、逐台用)
_V6_MARKED_SET=""
_V6_MARKED=""
marked_devices() {
    if [ -z "$_V6_MARKED_SET" ]; then
        _V6_MARKED=$(list_marked_devices)
        _V6_MARKED_SET=1
    fi
    [ -n "$_V6_MARKED" ] && printf '%s\n' "$_V6_MARKED"
    return 0
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
#   1. 期望地址集 = 当前邻居地址 ∪ 宽限期内的旧地址, 按最近看到截取前 V6_MAX_ADDRS 个
#   2. 头行 + 地址集都没变且 filter 仍在 → 只刷新快照时间戳(最常见路径)
#   3. 只新增地址(临时地址轮换的典型情况)且旧 filter 仍在 → 只补新地址的 filter,
#      不 flush(避免重建空窗)
#   4. 其余(有地址过期 / 头行变化 / filter 丢失)→ flush 该设备 prio 段后按期望集重建
# ═══════════════════════════════════════════════════════════════
sync_one() {
    local mac=$1
    local iface=${2:-$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)}
    [ -z "$mac" ] && { log "WARN: sync_one called with empty mac"; return 1; }
    [ -z "$iface" ] && { log "WARN: sync_one no iface"; return 1; }
    mac=$(printf '%s' "$mac" | tr 'A-F' 'a-f')

    local snap="$SNAP_DIR/$mac"
    # 找 mark_id（从 iptables）
    local mark_hex
    mark_hex=$(marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')
    if [ -z "$mark_hex" ]; then
        # 没限速 → 顺手清理可能残留的 v6 filter / 快照(无快照 = 从没装过, 静默返回)
        [ -f "$snap" ] || return 0
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
    # v5.12: 与 tc_manager.sh _class_id_for_mark 保持一致 —— mark_id=1 的 class
    # 是 1:100(1:1 是 HTB 父类),否则 v6 filter flowid 指向父类,等于没分类。
    local cls=$mark_id
    [ "$mark_id" = "1" ] && cls=100
    mkdir -p "$SNAP_DIR" 2>/dev/null

    # 检查 ifb0 上是否有该 class（用户设了 up 限速时才会有）
    local has_ingress=0
    if tc class show dev "$IFB_IFACE" 2>/dev/null | grep -q "class htb 1:$cls "; then
        has_ingress=1
    fi

    # v5.12: 快照 = 头行(iface/mark/ingress) + 地址列表。
    # 旧快照只存地址,地址不变即 return,以下场景 v6 filter 永远不会重建,设备走
    # IPv6 时绕过限速:
    #   - 热点关→开 / ROM 换根 qdisc 触发 init_tc 重建 / 重启(run/v6 跨重启残留)
    #     → tc 树上的 filter 已没了,但地址没变;
    #   - 接口切换(wlan1→wlan2),新接口上从未加过 filter;
    #   - 先只限下行、后补上行限速:ifb0 class 新建,但 ingress filter 从未加。
    #   - mid 被重新分配:旧 prio 段的 filter 残留,指向别人的 class。
    # 头行记录这些维度,任一变化即重建;没变化时再核对 filter 是否仍在 tc 上。
    local hdr="#hnc_v6 iface=$iface mark=$mark_id ing=$has_ingress"
    local now; now=$(v6_now)
    local cur prev_all prev_hdr prev_list prev prev_mark prev_iface merged n_all
    cur=$(get_v6_addrs "$mac" "$iface")
    prev_all=""
    [ -f "$snap" ] && prev_all=$(cat "$snap" 2>/dev/null)
    prev_hdr=$(printf '%s\n' "$prev_all" | grep '^#hnc_v6 ' | head -1)
    prev_list=$(printf '%s\n' "$prev_all" | grep -v '^#' | awk 'NF')
    prev=$(printf '%s\n' "$prev_list" | awk 'NF{print $1}' | sort -u)
    prev_mark=$(printf '%s\n' "$prev_hdr" | sed -n 's/^#hnc_v6 .* mark=\([0-9]*\).*/\1/p' | head -1)
    prev_iface=$(printf '%s\n' "$prev_hdr" | sed -n 's/^#hnc_v6 iface=\([^ ]*\).*/\1/p' | head -1)

    # 期望集: "<地址> <最近看到>", 当前地址 = now; 旧地址保留原时间戳(旧格式无时间戳
    # 或时间戳在未来(uptime 回退)→ 视为刚看到); 超过宽限的丢弃; 按最近看到降序截断。
    merged=$( { printf '%s\n' "$cur" | awk -v n="$now" 'NF{print $1, n}'
                printf '%s\n' "$prev_list" | awk -v n="$now" 'NF{t=$2; if (t == "" || t !~ /^[0-9]+$/ || t+0 > n+0) t=n; print $1, t}'
              } | awk -v n="$now" -v g="$V6_GRACE" '
                NF { if (!($1 in ts) || $2+0 > ts[$1]+0) ts[$1]=$2 }
                END { for (a in ts) if (n - ts[a] < g) print ts[a], a }' \
              | sort -k1,1nr -k2,2 )
    n_all=$(printf '%s\n' "$merged" | awk 'NF' | wc -l | tr -d ' ')
    if [ "${n_all:-0}" -gt "$V6_MAX_ADDRS" ]; then
        log "  $mac: $n_all v6 addresses, capping to newest $V6_MAX_ADDRS"
    fi
    merged=$(printf '%s\n' "$merged" | awk -v max="$V6_MAX_ADDRS" 'NF && c < max {c++; print $2, $1}')
    local want
    want=$(printf '%s\n' "$merged" | awk 'NF{print $1}' | sort -u)
    local snap_new="$hdr"
    [ -n "$merged" ] && snap_new="$hdr
$merged"

    local filters_ok=0
    if tc filter show dev "$iface" parent 1: 2>/dev/null | grep -q "pref $prio " && \
       { [ "$has_ingress" != "1" ] || tc filter show dev "$IFB_IFACE" parent 1: 2>/dev/null | grep -q "pref $prio "; }; then
        filters_ok=1
    fi

    local added="" removed=""
    # 集合差: 同一条流里用前缀区分两边(不依赖 awk -v 传多行、也不依赖 grep -f)
    local diff
    diff=$( { printf '%s\n' "$prev" | awk 'NF{print "P", $1}'
              printf '%s\n' "$want" | awk 'NF{print "W", $1}'
            } | awk '$1=="P"{p[$2]=1} $1=="W"{w[$2]=1}
                     END{for (a in w) if (!(a in p)) print "+", a; for (a in p) if (!(a in w)) print "-", a}' | sort)
    added=$(printf '%s\n' "$diff" | awk '$1=="+"{print $2}')
    removed=$(printf '%s\n' "$diff" | awk '$1=="-"{print $2}')

    if [ "$hdr" = "$prev_hdr" ] && [ -z "$removed" ]; then
        if [ -z "$added" ]; then
            # 无变化(最常见路径)。无地址时无需核对;有地址时确认 filter 仍挂在 tc 上。
            if [ -z "$want" ] || [ "$filters_ok" = "1" ]; then
                [ "$snap_new" != "$prev_all" ] && printf '%s\n' "$snap_new" > "$snap"
                return 0
            fi
            log "Sync $mac (mark=$mark_id prio=$prio): filters missing on tc (tree rebuilt?), rebuilding"
        elif [ -z "$prev" ] || [ "$filters_ok" = "1" ]; then
            # 只新增(临时地址轮换): 只补新地址, 不 flush
            local n=0 nfail=0
            for addr in $added; do
                if tc filter add dev "$iface" parent 1: protocol ipv6 prio "$prio" u32 \
                        match ip6 dst "$addr/128" flowid "1:$cls" 2>/dev/null; then
                    n=$((n+1))
                else
                    nfail=$((nfail+1))
                    log "  WARN: egress filter add failed for $addr"
                fi
                if [ "$has_ingress" = "1" ]; then
                    tc filter add dev "$IFB_IFACE" parent 1: protocol ipv6 prio "$prio" u32 \
                        match ip6 src "$addr/128" flowid "1:$cls" 2>/dev/null
                fi
            done
            printf '%s\n' "$snap_new" > "$snap"
            log "Sync $mac (mark=$mark_id prio=$prio): +$(echo "$added" | tr '\n' ' ')(incremental, added=$n failed=$nfail ingress=$has_ingress)"
            return 0
        else
            log "Sync $mac (mark=$mark_id prio=$prio): new addresses but filters missing on tc, rebuilding"
        fi
    else
        log "Sync $mac (mark=$mark_id prio=$prio iface=$iface ingress=$has_ingress): state changed"
        [ -n "$removed" ] && log "  expired (>${V6_GRACE}s gone or capped): $(echo "$removed" | tr '\n' ' ')"
    fi
    [ -n "$prev" ] && log "  prev: $(echo "$prev" | tr '\n' ' ')"
    log "  want: $(echo "$want" | tr '\n' ' ')"

    # v5.12: mid 变了 → 旧 prio 段的 filter 也要清(否则指向已归别人的 class)
    if [ -n "$prev_mark" ] && [ "$prev_mark" != "$mark_id" ]; then
        local old_prio=$((PRIO_BASE + prev_mark))
        tc filter del dev "$iface"     parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
        tc filter del dev "$IFB_IFACE" parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
        [ -n "$prev_iface" ] && [ "$prev_iface" != "$iface" ] && \
            tc filter del dev "$prev_iface" parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
    fi
    # 接口换了: 旧接口若还在,把旧 filter 一并清掉
    if [ -n "$prev_iface" ] && [ "$prev_iface" != "$iface" ]; then
        tc filter del dev "$prev_iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
    fi

    # Flush 该设备的所有 v6 filter（egress + ingress）
    # 该设备独占 prio 段，不会误删别的设备
    tc filter del dev "$iface"     parent 1: prio "$prio" protocol ipv6 2>/dev/null
    tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null

    # 设备 v6 全失活(含宽限期已过) → 仅记录，不加 filter
    if [ -z "$want" ]; then
        printf '%s\n' "$snap_new" > "$snap"
        log "  $mac: no active v6 addresses"
        return 0
    fi

    # 重建 filter，每个地址一条
    local n=0 nfail=0
    for addr in $want; do
        # Egress（下行限速）：wlan2 上 dst 匹配
        if tc filter add dev "$iface" parent 1: protocol ipv6 prio "$prio" u32 \
                match ip6 dst "$addr/128" flowid "1:$cls" 2>/dev/null; then
            n=$((n+1))
        else
            nfail=$((nfail+1))
            log "  WARN: egress filter add failed for $addr"
        fi

        # Ingress（上行限速）：ifb0 上 src 匹配（仅当 class 存在）
        if [ "$has_ingress" = "1" ]; then
            tc filter add dev "$IFB_IFACE" parent 1: protocol ipv6 prio "$prio" u32 \
                match ip6 src "$addr/128" flowid "1:$cls" 2>/dev/null
        fi
    done

    # 更新快照
    printf '%s\n' "$snap_new" > "$snap"
    log "  $mac: synced $n filter(s) (failed=$nfail, ingress=$has_ingress)"
}

# v5.20: 同步若干台(httpd 邻居事件合并后调用)。iface / iptables 只读一次。
sync_macs() {
    local iface mac
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    [ -z "$iface" ] && { log "WARN: sync_macs no iface"; return 1; }
    for mac in "$@"; do
        case "$mac" in
            [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
            *) log "WARN: sync_macs: bad mac '$mac'"; continue ;;
        esac
        sync_one "$mac" "$iface"
    done
    return 0
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
    local mark_hex mark_id="" snap_iface=""
    mark_hex=$(marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')
    if [ -n "$mark_hex" ]; then
        mark_id=$((mark_hex))
        mark_id=$((mark_id - MARK_BASE))
    fi
    # v5.12: iptables 里已没有 mark(sync_all 孤儿清理 / 规则已被删)时,旧实现只删
    # 快照不删 filter → v6 u32 filter 残留;mid 复用给别的设备后,旧设备的 v6 流量
    # 被归进新设备的 class。改为从快照头行取回当时的 mark / iface。
    if [ -f "$snap" ]; then
        [ -n "$mark_id" ] || mark_id=$(sed -n 's/^#hnc_v6 .* mark=\([0-9]*\).*/\1/p' "$snap" 2>/dev/null | head -1)
        snap_iface=$(sed -n 's/^#hnc_v6 iface=\([^ ]*\).*/\1/p' "$snap" 2>/dev/null | head -1)
    fi

    case "$mark_id" in
        ''|*[!0-9]*)
            log "Clear $mac: no mark found, snapshot only" ;;
        *)
            local prio=$((PRIO_BASE + mark_id))
            [ -n "$iface" ] && tc filter del dev "$iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            [ -n "$snap_iface" ] && [ "$snap_iface" != "$iface" ] && \
                tc filter del dev "$snap_iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            log "Clear $mac (mark=$mark_id prio=$prio): filters removed" ;;
    esac

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
    devices=$(marked_devices)

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
_cmd=${1:-sync}
case "$_cmd" in
    sync|sync_all|sync_one|sync_macs|clear)
        mkdir -p "$HNC_DIR/run" 2>/dev/null
        if ! v6_lock; then
            log "WARN: $_cmd: another v6_sync still running after 10s, giving up (periodic sync will retry)"
            exit 11
        fi ;;
esac
case "$_cmd" in
    sync|sync_all)  sync_all ;;
    sync_one)       sync_one "$2" ;;
    sync_macs)      shift; sync_macs "$@" ;;
    clear)          clear_one "$2" ;;
    status)         show_status ;;
    *)
        echo "Usage: $0 {sync|sync_one MAC|sync_macs MAC...|clear MAC|status}" >&2
        exit 1 ;;
esac
