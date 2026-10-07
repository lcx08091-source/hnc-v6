#!/system/bin/sh
# hnc_offload_guard.sh — tether 硬件/BPF offload 旁路 HNC 限速的自动兜底(v5.18)
#
# ── 为什么是「强制 offload 走慢路径」而不是「clsact 打标」──────────────
# AOSP tethering offload 在两处挂 clsact ingress 程序(pref 2/3, schedcls/tether_*):
#   上行: 热点口(wlan2)ingress 的 tether_upstream{4,6} → bpf_redirect 到上游口 egress
#   下行: 上游口(rmnet/wlan0)ingress 的 tether_downstream{4,6} → bpf_redirect 到
#         热点口 egress
# HNC 自己:
#   上行: 热点口 ingress pref 1 matchall mirred → ifb0(install_ingress_mirred)。
#         它排在 AOSP pref 2/3 之前, 包被 STOLEN 到 ifb0, ifb 回注时带
#         tc_skip_classify, AOSP 上行程序根本看不到包 → 上行本来就不会被旁路。
#   下行: 热点口 egress HTB, 按 u32 dst IP(IPv4)分类, IPv6 只靠 iptables fw mark。
#         bpf_redirect 到热点口 egress 仍然经过根 qdisc(HTB), IPv4 u32 照样命中;
#         但被 offload 的包完全跳过 netfilter —— IPv6 没有 mark 掉进默认类
#         (不限速), iptables 统计/conntrack 字节(按应用流量)、FORWARD 里的封锁
#         规则对下行全部失效。
# hnc_clsact.bpf.c 只在热点口 ingress pref 1 按源 IPv4 设 skb->mark 后 TC_ACT_OK,
# 它 (a) 不阻止 AOSP 程序 bpf_redirect; (b) 只看上行方向, 而上行已被 mirred 截走、
# ifb0 上又是 u32 src 分类, mark 对 IPv4 无意义; (c) 不处理 IPv6。更糟的是它与
# HNC 自己的 mirred 抢同一个 pref 1(不同 kind 同 prio 内核直接 EINVAL)。
# 所以真正能打掉旁路的只有让 AOSP 程序自己放弃快路径: 把 tether limit_map 里
# 每个上游的额度写 0, 程序命中 0 额度就 TC_PUNT 回内核常规转发(hotspotd
# OFFLOAD_DISABLE_GLOBAL)。system_server 会在上游变化/统计轮询时改写 limit_map,
# 所以要周期性重申。clsact 打标只作为附带的 best-effort: 仅当 pref 1 没被 HNC
# 上行 mirred 占用时才装(实际上就是「本机不支持上行整形」的少数机型)。
#
# ── 模式(rules.json 顶层 clsact_bpf_mode)────────────────────────────
#   auto(默认): 每 60s 用 check_offload.sh 采样; 检测到 ACTIVE(5s 内 offload
#               转发 ≥1MB)→ 启用兜底并在之后每轮重申; 兜底会让 offload 统计
#               停止增长(我们自己压下去的), 所以「不再 ACTIVE」不能作为撤销依据 ——
#               撤销条件是热点关闭 / tether map 消失(NOMAP)连续 3 轮(迟滞, 防抖),
#               下次热点会话重新检测。
#   on:  热点在就始终强制慢路径 + 尝试 clsact 打标(= 旧 clsact_bpf_enabled=true)。
#   off: 什么都不做; 若之前由本脚本施加过兜底, 撤销(RESTORE_GLOBAL + 卸 clsact)。
# 兼容: 缺 clsact_bpf_mode 且旧键 clsact_bpf_enabled=true → on, 否则 auto。
#
# ── 降级 ───────────────────────────────────────────────────────────────
# 非 GKI / 无 /sys/fs/bpf/tethering(check=NOMAP)/ hotspotd 没跑(hnc_ipc 连不上)
# / 无 clsact 产物: 一律静默, 只在状态文件 detail 里写原因, 不报错退出。
#
# 状态文件 run/offload_guard.json(httpd /api/config 的 offload_guard 原样透出):
#   {"mode","offload_state","fallback_active","since","detail","last_check",
#    "slowpath","clsact","iface","hwnat"}
#   hwnat(v5.20, 仅 on 模式): n/a|none|disabled|skipped_qcom|skipped_not_mtk|detected_no_knob|failed
#   —— 详见 bin/hnc_mtk_hwnat.sh 与 run/mtk_hwnat.json
#
# 用法:
#   hnc_offload_guard.sh daemon              守护循环(service.sh 拉起)
#   hnc_offload_guard.sh apply               立即按当前模式跑一轮, stdout 末行输出状态 JSON
#   hnc_offload_guard.sh restore             撤销本脚本施加的一切(cleanup.sh 用)
#   hnc_offload_guard.sh mode                打印生效模式 auto|on|off
#   hnc_offload_guard.sh clsact_wanted [if]  exit 0 = 该装 clsact(tc_manager/watchdog 用)
#   hnc_offload_guard.sh plan                跑一轮并打印下一次 sleep 秒数与早醒条件(v5.22 功耗)

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
RUN="$HNC_DIR/run"
RULES="$HNC_DIR/data/rules.json"
LOG_FILE="$HNC_DIR/logs/offload_guard.log"
STATUS="$RUN/offload_guard.json"
STATE="$RUN/offload_guard.state"
CLSACT_FLAG="$RUN/offload_guard.clsact"
PIDFILE="$RUN/offload_guard.pid"
IPC="$HNC_DIR/bin/hnc_ipc"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"
CHECK_CMD="${HNC_GUARD_CHECK_CMD:-sh $HNC_DIR/bin/check_offload.sh}"
SYS_NET="${HNC_SYS_NET:-/sys/class/net}"
INTERVAL="${HNC_GUARD_INTERVAL:-60}"
RESTORE_AFTER="${HNC_GUARD_RESTORE_AFTER:-3}"
# v5.22 功耗: 热点未开/无在线设备且未在兜底时, 完整检测(check_offload.sh 含 sleep 5 采样)
# 放慢到 IDLE_INTERVAL, 期间每 IDLE_CHUNK 秒用内建命令看 run/activity.json, 一有设备立即检测。
# 兜底生效(fallback_active)时永远按 INTERVAL(≤60s)重申 —— system_server 会改写 limit_map。
IDLE_INTERVAL="${HNC_GUARD_IDLE_INTERVAL:-300}"
IDLE_CHUNK="${HNC_GUARD_IDLE_CHUNK:-30}"
IFB_IFACE="${IFB_IFACE:-ifb0}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [offload-guard] $*" >> "$LOG_FILE" 2>/dev/null; }
now_s() { date +%s 2>/dev/null || echo 0; }

# v5.22: activity.json 读取器(纯内建); 缺失时永不放慢
if [ -f "$HNC_DIR/bin/hnc_activity.sh" ]; then
    . "$HNC_DIR/bin/hnc_activity.sh"
elif [ -f "${0%/*}/hnc_activity.sh" ]; then
    . "${0%/*}/hnc_activity.sh"
fi
command -v hnc_act_load >/dev/null 2>&1 || {
    hnc_act_load() { ACT_OK=0; return 1; }
    hnc_act_sleep_until() { sleep "$1"; return 1; }
}
GUARD_LAST_MODE=""
GUARD_LAST_FB=0

# ── 模式解析 ─────────────────────────────────────────────────────────
guard_mode() {
    local v=""
    if [ -x "$HNC_DIR/bin/hnc_json" ]; then
        v=$("$HNC_DIR/bin/hnc_json" get-top "$RULES" clsact_bpf_mode 2>/dev/null | tr -d '"[:space:]')
    fi
    if [ -z "$v" ]; then
        v=$(grep -o '"clsact_bpf_mode"[[:space:]]*:[[:space:]]*"[a-z]*"' "$RULES" 2>/dev/null | head -n1 | sed 's/.*"\([a-z]*\)"$/\1/')
    fi
    case "$v" in
        auto|on|off) echo "$v"; return 0 ;;
    esac
    # 旧键兼容
    if grep -q '"clsact_bpf_enabled"[[:space:]]*:[[:space:]]*true' "$RULES" 2>/dev/null; then
        echo on
    else
        echo auto
    fi
}

# ── 热点接口 ─────────────────────────────────────────────────────────
hotspot_iface() {
    local s=""
    s=$(sed -n 's/^ACTIVE://p' "$RUN/hnc_state" 2>/dev/null | head -n1 | tr -d ' \r\n')
    case "$s" in *[!a-zA-Z0-9_.-]*) s="" ;; esac
    if [ -n "$s" ] && [ -e "$SYS_NET/$s" ]; then
        echo "$s"
        return 0
    fi
    return 1
}

# ── 小状态(key=val)────────────────────────────────────────────────
st_get() { sed -n "s/^$1=//p" "$STATE" 2>/dev/null | head -n1; }
st_save() {
    # $1 fallback $2 since $3 calm
    { echo "fallback=$1"; echo "since=$2"; echo "calm=$3"; } > "$STATE.tmp" 2>/dev/null && mv -f "$STATE.tmp" "$STATE" 2>/dev/null
}

json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }

write_status() {
    # $1 mode $2 state $3 fallback(0/1) $4 since $5 detail $6 slowpath $7 clsact $8 iface
    local fb=false
    [ "$3" = 1 ] && fb=true
    printf '{"mode":"%s","offload_state":"%s","fallback_active":%s,"since":%s,"detail":"%s","last_check":%s,"slowpath":"%s","clsact":"%s","iface":"%s","hwnat":"%s"}\n' \
        "$1" "$2" "$fb" "${4:-0}" "$(json_str "$5")" "$(now_s)" "$6" "$7" "$8" "${HWNAT_ST:-n/a}" > "$STATUS.tmp" 2>/dev/null \
        && mv -f "$STATUS.tmp" "$STATUS" 2>/dev/null
}

# ── 慢路径(hotspotd limit_map)──────────────────────────────────────
# 输出: ok | empty | unavailable | error
slowpath_disable() {
    [ -x "$IPC" ] || { echo unavailable; return; }
    local out rc
    out=$("$IPC" OFFLOAD_DISABLE_GLOBAL 2>/dev/null); rc=$?
    [ "$rc" = 0 ] || { echo unavailable; return; }
    case "$out" in
        *EMPTY*) echo empty ;;   # map 还没条目(冷启), 下一轮再写
        OK*) echo ok ;;
        *) echo error ;;
    esac
}

slowpath_restore() {
    [ -x "$IPC" ] || return 0
    "$IPC" OFFLOAD_RESTORE_GLOBAL >/dev/null 2>&1 || return 0
    # RESTORE_GLOBAL 会清空 hotspotd 调度器的「受限设备」集合(见 scheduler.c
    # hnc_scheduler_force_restore_global)。按 rules.json 重新通知, 让 hotspotd 对
    # 仍在限速的设备恢复它自己的 per-upstream disable(与 service.sh 恢复段同款)。
    local mac
    for mac in $(grep -oE '"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"[^}]*"limit_enabled"[[:space:]]*:[[:space:]]*true' "$RULES" 2>/dev/null \
                 | grep -oE '^"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"' | tr -d '"'); do
        "$IPC" OFFLOAD_NOTIFY_LIMIT "$mac" 1 >/dev/null 2>&1 || true
    done
}

# ── clsact 打标(附带, best-effort)────────────────────────────────
# pref 1 是否已被 HNC 上行 mirred 占用(不同 kind 同 prio → 内核 EINVAL; 而且
# mirred 在前时打标本就无意义, 见文件头)
pref1_held_by_mirred() {
    local ifc="$1"
    command -v tc >/dev/null 2>&1 || return 1
    tc filter show dev "$ifc" ingress 2>/dev/null | grep -qiE "mirred.*redirect.*$IFB_IFACE" && return 0
    tc filter show dev "$ifc" parent ffff: 2>/dev/null | grep -qiE "mirred.*redirect.*$IFB_IFACE" && return 0
    return 1
}

clsact_artifacts() { [ -f "$HNC_DIR/bin/hnc_clsact.o" ] && [ -x "$CTL" ]; }

clsact_ours_present() {
    "$CTL" check "$1" 2>/dev/null | grep -q '"bpf_filter":true'
}

# 输出: installed | skipped_pref1_mirred | unavailable | failed
clsact_apply() {
    local ifc="$1"
    clsact_artifacts || { echo unavailable; return; }
    [ -n "$ifc" ] || { echo unavailable; return; }
    if clsact_ours_present "$ifc"; then
        : > "$CLSACT_FLAG" 2>/dev/null
        echo installed; return
    fi
    if pref1_held_by_mirred "$ifc"; then
        echo skipped_pref1_mirred; return
    fi
    if "$CTL" install "$ifc" >> "$LOG_FILE" 2>&1; then
        : > "$CLSACT_FLAG" 2>/dev/null
        sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG_FILE" 2>&1 || true
        echo installed
    else
        echo failed
    fi
}

clsact_remove() {
    local ifc="$1"
    [ -f "$CLSACT_FLAG" ] || return 0
    rm -f "$CLSACT_FLAG" 2>/dev/null
    clsact_artifacts || return 0
    [ -n "$ifc" ] || return 0
    # 只在 check 确认 pref1 上是我们的 bpf filter 时才卸: 旧版 hnc_clsact_ctl 的
    # uninstall 不带 TCA_KIND, 会把同 pref/handle 的 HNC 上行 mirred 一起删掉。
    clsact_ours_present "$ifc" && "$CTL" uninstall "$ifc" >> "$LOG_FILE" 2>&1
    return 0
}

# ── clsact_wanted: 给 tc_manager / clsact watchdog 的统一闸门 ────────
clsact_wanted() {
    local ifc="$1" m
    clsact_artifacts || return 1
    m=$(guard_mode)
    case "$m" in
        on) ;;
        auto) [ -f "$CLSACT_FLAG" ] || [ "$(st_get fallback)" = 1 ] || return 1 ;;
        *) return 1 ;;
    esac
    [ -n "$ifc" ] && pref1_held_by_mirred "$ifc" && return 1
    return 0
}

# ── 一轮 ─────────────────────────────────────────────────────────────
# ── MTK HWNAT(v5.20, 实验性)────────────────────────────────────────
# 只在 on 模式调用 bin/hnc_mtk_hwnat.sh disable(它自己保证: 未检测到 → 不动作,
# 高通 → 绝不动作); 撤销兜底时 restore(无状态文件时是空操作)。详见该脚本头注释。
HWNAT="$HNC_DIR/bin/hnc_mtk_hwnat.sh"
HWNAT_ST="n/a"
hwnat_disable() {
    [ -f "$HWNAT" ] || { echo n/a; return 0; }
    HNC_DIR="$HNC_DIR" sh "$HWNAT" disable 2>/dev/null | tail -n1
}
hwnat_restore() {
    [ -f "$HWNAT" ] && [ -f "$RUN/mtk_hwnat.state" ] && HNC_DIR="$HNC_DIR" sh "$HWNAT" restore >/dev/null 2>&1
    return 0
}

do_restore() {
    # $1 iface(可空)
    slowpath_restore
    clsact_remove "$1"
    hwnat_restore
}

tick() {
    local mode ifc state fb since calm sp="n/a" cl="off" detail
    mode=$(guard_mode)
    ifc=$(hotspot_iface) || ifc=""
    fb=$(st_get fallback); [ "$fb" = 1 ] || fb=0
    since=$(st_get since); case "$since" in ''|*[!0-9]*) since=0 ;; esac
    calm=$(st_get calm);   case "$calm" in ''|*[!0-9]*) calm=0 ;; esac

    # 从 on 切到 auto/off: 之前关掉的 MTK HWNAT 立即恢复(auto 不碰 HWNAT)
    [ "$mode" != on ] && hwnat_restore
    if [ "$mode" = off ]; then
        if [ "$fb" = 1 ] || [ -f "$CLSACT_FLAG" ]; then
            do_restore "$ifc"
            log "mode=off: fallback restored"
        fi
        st_save 0 0 0
        write_status off "SKIPPED" 0 0 "已关闭: 不检测、不干预 offload" "n/a" "off" "$ifc"
        GUARD_LAST_MODE=off; GUARD_LAST_FB=0
        return 0
    fi

    if [ -z "$ifc" ]; then
        state="NOHOTSPOT"
    else
        state=$($CHECK_CMD 2>/dev/null | tail -n1 | tr -d ' \r\n')
        case "$state" in NOMAP|IDLE|CAPABLE|ACTIVE) ;; *) state="UNKNOWN" ;; esac
    fi

    local want=0
    if [ "$mode" = on ]; then
        [ -n "$ifc" ] && want=1
    else
        if [ "$state" = ACTIVE ]; then
            want=1
            calm=0
        elif [ "$fb" = 1 ]; then
            # 兜底中: offload 统计不增长是我们压的, 不作为撤销依据;
            # 只有热点没了 / tether map 没了才累计「平静」轮数(迟滞)
            case "$state" in
                NOHOTSPOT|NOMAP) calm=$((calm + 1)) ;;
                *) calm=0 ;;
            esac
            if [ "$calm" -ge "$RESTORE_AFTER" ]; then
                want=0
            else
                want=1
            fi
        fi
    fi

    if [ "$want" = 1 ]; then
        sp=$(slowpath_disable)
        cl=$(clsact_apply "$ifc")
        [ "$mode" = on ] && HWNAT_ST=$(hwnat_disable)
        if [ "$fb" != 1 ]; then
            since=$(now_s)
            log "fallback ON (mode=$mode offload=$state iface=$ifc slowpath=$sp clsact=$cl)"
        fi
        fb=1
        case "$sp" in
            ok)          detail="已强制 offload 走慢路径(limit_map=0, 每轮重申)" ;;
            empty)       detail="offload map 暂无条目, 下一轮重试" ;;
            unavailable) detail="hotspotd 未运行或无 hnc_ipc, 无法强制慢路径" ;;
            *)           detail="强制慢路径失败(见 hotspotd 日志)" ;;
        esac
        [ "$mode" = auto ] && [ "$state" = ACTIVE ] && detail="检测到 offload 正在旁路限速; $detail"
        [ "$cl" = skipped_pref1_mirred ] && detail="$detail; clsact 打标跳过(pref 1 为 HNC 上行 mirred, 上行本就先于 offload)"
        case "$HWNAT_ST" in
            disabled) detail="$detail; 已关闭 MTK HWNAT(实验性)" ;;
            detected_no_knob) detail="$detail; 检测到 MTK HWNAT 但无运行期开关(限速可能被旁路)" ;;
        esac
    else
        if [ "$fb" = 1 ]; then
            do_restore "$ifc"
            log "fallback OFF (offload=$state, calm=$calm)"
        fi
        fb=0; since=0; calm=0; sp="n/a"; cl="off"
        case "$state" in
            NOHOTSPOT) detail="热点未开启" ;;
            NOMAP)     detail="本机无 tether offload map(非 GKI 或未启用), 无需兜底" ;;
            IDLE)      detail="offload 未在转发, 无需兜底" ;;
            CAPABLE)   detail="本机具备 offload, 当前未在转发, 持续监测" ;;
            *)         detail="状态未知, 持续监测" ;;
        esac
    fi
    st_save "$fb" "$since" "$calm"
    write_status "$mode" "$state" "$fb" "$since" "$detail" "$sp" "$cl" "$ifc"
    GUARD_LAST_MODE=$mode; GUARD_LAST_FB=$fb
}

# v5.22: 本轮之后睡多久 → GUARD_PLAN_TOTAL; 早醒条件 → GUARD_PLAN_WAKE(空 = 普通 sleep)
# 只在「activity 新鲜 + 热点未开或无在线设备 + 未在兜底」时放慢(与 power_sched.go offload_guard 一致)。
guard_plan_sleep() {
    GUARD_PLAN_TOTAL=$INTERVAL
    GUARD_PLAN_WAKE=""
    [ "$GUARD_LAST_FB" = 1 ] && return 0
    hnc_act_load "$(now_s)" || return 0
    [ "$ACT_OK" = 1 ] || return 0
    case "$ACT_LEVEL" in
        hotspot_off|no_clients) ;;
        *) return 0 ;;
    esac
    [ "$IDLE_INTERVAL" -gt "$INTERVAL" ] 2>/dev/null || return 0
    GUARD_PLAN_TOTAL=$IDLE_INTERVAL
    # on 模式: 热点一开就要强制慢路径; auto: 没有客户端就不可能有 offload 转发
    if [ "$GUARD_LAST_MODE" = on ]; then GUARD_PLAN_WAKE=hotspot; else GUARD_PLAN_WAKE=clients; fi
}

ensure_daemon() {
    # v5.29 T2(M3): Go 看门狗接管调度(owner 文件)时, httpd 调 apply 也不
    # 把 shell 常驻循环拉回来 —— 调度权在 Go, tick 由 plan 动作按需执行。
    if [ "$(cat "$HNC_DIR/run/offload_guard.owner" 2>/dev/null)" = "watchdog" ]; then
        return 0
    fi
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q hnc_offload_guard "/proc/$pid/cmdline" 2>/dev/null; then
        return 0
    fi
    # 测试模式不真起守护; HNC_GUARD_SPAWN_LOG 给测试记一笔「这里会起」
    if [ -n "$HNC_TEST_MODE" ]; then
        [ -n "$HNC_GUARD_SPAWN_LOG" ] && echo spawn >> "$HNC_GUARD_SPAWN_LOG"
        return 0
    fi
    nohup sh "$0" daemon >> "$LOG_FILE" 2>&1 < /dev/null &
    echo $! > "$PIDFILE" 2>/dev/null
}

case "${1:-}" in
    daemon)
        # v5.29 T2(M3): Go 看门狗已接管(owner=watchdog)时不起循环,
        # 记一行日志退出 —— service.sh 旧版本 / 手工调用兜底场景。
        if [ "$(cat "$HNC_DIR/run/offload_guard.owner" 2>/dev/null)" = "watchdog" ]; then
            log "daemon skipped: owner=watchdog (Go watchdog scheduling)"
            exit 0
        fi
        echo $$ > "$PIDFILE" 2>/dev/null
        log "offload guard starting (interval=${INTERVAL}s)"
        # 开机稍等, 让热点/hotspotd 就绪
        [ -n "$HNC_TEST_MODE" ] || sleep 20
        while true; do
            tick
            guard_plan_sleep
            if [ -n "$GUARD_PLAN_WAKE" ]; then
                hnc_act_sleep_until "$GUARD_PLAN_TOTAL" "$IDLE_CHUNK" "$GUARD_PLAN_WAKE"
            else
                sleep "$INTERVAL"
            fi
        done
        ;;
    plan)
        # 测试/诊断: 跑一轮并打印「下一次睡多久 早醒条件」
        tick
        guard_plan_sleep
        echo "$GUARD_PLAN_TOTAL ${GUARD_PLAN_WAKE:-none}"
        ;;
    apply)
        tick
        ensure_daemon
        cat "$STATUS" 2>/dev/null
        ;;
    restore)
        do_restore "$(hotspot_iface)"
        st_save 0 0 0
        rm -f "$STATUS" 2>/dev/null
        ;;
    mode)
        guard_mode
        ;;
    clsact_wanted)
        clsact_wanted "${2:-$(hotspot_iface)}"
        exit $?
        ;;
    *)
        echo "usage: $0 daemon|apply|restore|mode|clsact_wanted [iface]|plan" >&2
        exit 4
        ;;
esac
exit 0
