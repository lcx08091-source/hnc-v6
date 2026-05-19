#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# tc_manager.sh — v3.2.0  Android 16 / KSU 强化版
#
# 核心修复（解释"限速时好时坏"根因）：
#
#  问题1 — 上传方向 TC 永不生效：
#    mirred redirect → ifb0 发生在 PREROUTING 之前
#    此时 iptables MARK=0，ifb0 fw filter 匹配不到，上传走 class 9999
#    修复：ifb0 改用 u32 src IP 匹配，完全不依赖 iptables mark
#
#  问题2 — 下载偶发绕过：
#    旧 burst = 128×Mbps KB → 2Mbps 时 256KB（约1秒数据量）太宽松
#    多线程同时命中 burst 窗口可轻松冲破限速线
#    修复：burst = 2.5×Mbps KB（约 20ms 数据量），严格限速
#
#  问题3 — 硬件 offload 绕过：
#    GRO/GSO/TSO 将小包合并成超大包，tc 按包整形时等效带宽翻倍
#    修复：init_tc 时通过 ethtool + sysfs 禁用全部 offload
#
#  问题4 — QUIC/多线程绕过：
#    fw mark 依赖 iptables 时序，新连接第一包 mark=0 走默认 class
#    修复：主分类改用 u32 IP 匹配（dst=下载, src=上传），fw mark 降为备用
#
# set_limit 签名（v3.2.0 新增第5参数）：
#   set_limit <iface> <mark_id> <down_mbps> <up_mbps> [ip]

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES_FILE=$HNC_DIR/data/rules.json
# rc3.1.30 Bug B 修复 · restore 时用 devices.json 的实时 IP, rules.json 只作 fallback
# devices.json 由 hotspotd C daemon 实时维护 (netlink RTGRP_NEIGH),
# rules.json 里的 ip 字段可能是上次会话的旧值 · 手机热点 NAT 段每次随机.
DEVICES_FILE=$HNC_DIR/data/devices.json
LOG=$HNC_DIR/logs/tc.log

# hotfix17.3: force stable system iproute2 binaries.
# KSU/SukiSU shells may resolve `tc` to a busybox/toybox implementation; probes
# showed /system/bin/tc accepts root HTB/netem on MIUI14 while the runtime path did not.
TC_BIN=${TC_BIN:-}
IP_BIN=${IP_BIN:-}
if [ -z "$TC_BIN" ]; then
    for _tc in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
        [ -x "$_tc" ] && { TC_BIN="$_tc"; break; }
    done
    [ -z "$TC_BIN" ] && TC_BIN=$(command -v tc 2>/dev/null || echo tc)
fi
if [ -z "$IP_BIN" ]; then
    for _ip in "$HNC_DIR/bin/hnc_ip" /system/bin/ip /vendor/bin/ip /system/xbin/ip; do
        [ -x "$_ip" ] && { IP_BIN="$_ip"; break; }
    done
    [ -z "$IP_BIN" ] && IP_BIN=$(command -v ip 2>/dev/null || echo ip)
fi
tc() { "$TC_BIN" "$@"; }
ip() { "$IP_BIN" "$@"; }

log() {
    # v3.5.0 P2-1: 路径不存在时不让 redirect 失败导致整个脚本退出
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [TC] $*" >> "$LOG" 2>/dev/null || true
}

# v4.0 Patch 1.6: [ERROR] 前缀便于 grep 故障排查
log_error() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [TC] [ERROR] $*" >> "$LOG" 2>/dev/null || true
}

# hotfix16.5: unified uplink capability gate.
# If capability_probe says IFB/mirred is unavailable, never try modprobe/ifb0/mirred
# from apply/init/restore/watchdog paths. Downlink HTB/netem stays usable.
CAP_FILE="$HNC_DIR/run/capabilities.json"
UPLINK_MARKER="$HNC_DIR/run/uplink_unsupported"
UPLINK_LOG_ONCE="$HNC_DIR/run/uplink_unsupported_logged"

# hotfix17.5: QoS profile for MIUI/root-HTB fallback.
# compat   = safer bursts, better compatibility with Android Wi-Fi drivers.
# precise  = smaller burst/cburst, closer speed cap, may increase CPU/latency.
QOS_MODE_FILE="$HNC_DIR/run/tc_qos_mode"
QOS_FALLBACK_MARKER="$HNC_DIR/run/tc_qos_fallback"
QOS_SCALE_FILE="$HNC_DIR/run/tc_qos_scale"

# v5.3 Smart Queue / SQM foundation. Default is off to keep v5.2.1 behavior.
# When enabled, delay-free device classes use fq_codel/CAKE leaf qdisc instead of
# the old netem-0ms placeholder. Any real delay/jitter/loss still forces netem.
SQM_MODE_FILE="$HNC_DIR/run/sqm_mode"
SQM_PROFILE_FILE="$HNC_DIR/run/sqm_profile"

json_top_string() {
    local key=$1 file=${2:-$RULES_FILE}
    [ -f "$file" ] || return 1
    tr -d '\n' < "$file" 2>/dev/null \
        | grep -oE '"'"$key"'"[[:space:]]*:[[:space:]]*"[^"]*"' 2>/dev/null \
        | head -1 \
        | sed 's/^[^:]*:[[:space:]]*"//; s/"$//'
}

qos_mode_raw() {
    local v
    v=$(cat "$QOS_MODE_FILE" 2>/dev/null | head -1 | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    [ -n "$v" ] || v=$(json_top_string tc_qos_mode | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    case "$v" in
        precise|precision|strict|accurate) echo precise ;;
        compat|compatible|safe|balance|balanced|"") echo compat ;;
        *) echo compat ;;
    esac
}

qos_mode() { qos_mode_raw; }
qos_precise_mode() { [ "$(qos_mode)" = "precise" ]; }

# hotfix17.6: root-HTB fallback rate calibration.
# Android Wi-Fi root HTB can report higher real throughput than configured rate
# because of driver/airtime buffering and speed-test bursts. The calibration scale
# is only applied when root HTB fallback is active, so normal full-path devices are
# unaffected.
qos_scale_raw() {
    local v
    v=$(cat "$QOS_SCALE_FILE" 2>/dev/null | head -1 | tr -d '\r\n %')
    [ -n "$v" ] || v=$(json_top_string tc_qos_scale | tr -d '\r\n %')
    case "$v" in
        ''|*[!0-9]*) v=100 ;;
    esac
    [ "$v" -lt 50 ] && v=50
    [ "$v" -gt 120 ] && v=120
    echo "$v"
}
qos_scale_percent() { qos_scale_raw; }

qos_root_fallback_active() {
    [ -f "$QOS_FALLBACK_MARKER" ] && return 0
    [ -f "$CAP_FILE" ] && grep -Eq '"downlink_mode"[[:space:]]*:[[:space:]]*"(root_htb|htb_root)"|"qos_fallback_required"[[:space:]]*:[[:space:]]*true' "$CAP_FILE" 2>/dev/null && return 0
    return 1
}

qos_effective_mbps_for_downlink() {
    local requested=${1:-0} scale mode saved
    mode=$(qos_mode)
    saved=$(cat "$QOS_SCALE_FILE" 2>/dev/null | head -1 | tr -d '\r\n %')
    [ -n "$saved" ] || saved=$(json_top_string tc_qos_scale 2>/dev/null | tr -d '\r\n %')
    scale=$(qos_scale_percent)
    # Precise mode defaults to 85% only when user has not saved a scale.
    if qos_root_fallback_active; then
        if [ -z "$saved" ] && [ "$mode" = "precise" ]; then
            scale=85
        fi
        awk -v v="$requested" -v s="$scale" 'BEGIN{printf "%.6f", (v+0)*s/100}'
    else
        awk -v v="$requested" 'BEGIN{printf "%.6f", v+0}'
    fi
}

qos_mark_root_fallback() {
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    echo root_htb > "$QOS_FALLBACK_MARKER" 2>/dev/null || true
}
qos_clear_root_fallback() { rm -f "$QOS_FALLBACK_MARKER" 2>/dev/null || true; }

sqm_mode_raw() {
    local v
    v=$(cat "$SQM_MODE_FILE" 2>/dev/null | head -1 | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    [ -n "$v" ] || v=$(json_top_string sqm_mode | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    case "$v" in
        off|disable|disabled|0|false|no|"") echo off ;;
        fq|fq-codel|fqcodel|fq_codel|lowlatency|low-latency) echo fq_codel ;;
        cake) echo cake ;;
        game|gaming) echo game ;;
        auto|smart|sqm) echo auto ;;
        *) echo off ;;
    esac
}

sqm_mode() { sqm_mode_raw; }

cap_string_value() {
    local key=$1
    [ -f "$CAP_FILE" ] || return 1
    tr -d '\n' < "$CAP_FILE" 2>/dev/null \
        | grep -oE '"'"$key"'"[[:space:]]*:[[:space:]]*"[^"]*"' 2>/dev/null \
        | head -1 \
        | sed 's/^[^:]*:[[:space:]]*"//; s/"$//'
}

sqm_cap_bool() { cap_bool_value "$1" 2>/dev/null || echo unknown; }

sqm_preferred_leaf() {
    local mode cake fqc rec
    mode=$(sqm_mode)
    [ "$mode" = "off" ] && { echo off; return 0; }
    cake=$(sqm_cap_bool tc_cake_supported)
    fqc=$(sqm_cap_bool tc_fq_codel_supported)
    case "$mode" in
        cake)
            [ "$cake" = "false" ] && { echo off; return 0; }
            echo cake ;;
        fq_codel|game)
            [ "$fqc" = "false" ] && { echo off; return 0; }
            echo fq_codel ;;
        auto)
            rec=$(cap_string_value sqm_recommended_mode 2>/dev/null || echo "")
            if [ "$rec" = "cake" ] && [ "$cake" != "false" ]; then echo cake; return 0; fi
            if [ "$fqc" != "false" ]; then echo fq_codel; return 0; fi
            [ "$cake" != "false" ] && { echo cake; return 0; }
            echo off ;;
        *) echo off ;;
    esac
}

leaf_qdisc_kind() {
    local dev=$1 class_id=$2
    tc qdisc show dev "$dev" 2>/dev/null | awk -v p="parent 1:$class_id" '$0 ~ p {print $2; exit}'
}

leaf_has_active_netem() {
    local dev=$1 class_id=$2 line delay loss
    line=$(tc qdisc show dev "$dev" parent "1:$class_id" 2>/dev/null | grep netem | head -1)
    [ -n "$line" ] || return 1
    delay=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="delay") {print $(i+1); exit}}')
    loss=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="loss") {print $(i+1); exit}}' | tr -d '%')
    case "$delay" in ""|0ms|0us|0s) delay=0 ;; *) return 0 ;; esac
    awk -v v="${loss:-0}" 'BEGIN{exit !(v+0 > 0)}' && return 0
    return 1
}

sqm_leaf_replace() {
    local dev=$1 class_id=$2 leaf_handle=$3 kind=${4:-}
    [ -n "$kind" ] || kind=$(sqm_preferred_leaf)
    case "$kind" in
        fq_codel)
            tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" fq_codel target 5ms interval 100ms quantum 1514 limit 1024 2>/dev/null && return 0
            tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" fq_codel 2>/dev/null && return 0
            ;;
        cake)
            # CAKE is optional and not universally present on Android. Keep options minimal.
            tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" cake besteffort 2>/dev/null && return 0
            tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" cake 2>/dev/null && return 0
            ;;
    esac
    return 1
}

netem_leaf_replace_zero() {
    local dev=$1 class_id=$2 leaf_handle=$3
    tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" netem delay 0ms limit 100 2>/dev/null && return 0
    tc qdisc del dev "$dev" parent "1:$class_id" 2>/dev/null || true
    tc qdisc add dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" netem delay 0ms limit 100 2>/dev/null
}

cap_bool_value() {
    local key=$1
    [ -f "$CAP_FILE" ] || return 1
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*true" "$CAP_FILE" 2>/dev/null; then
        echo true
        return 0
    fi
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*false" "$CAP_FILE" 2>/dev/null; then
        echo false
        return 0
    fi
    return 1
}

tc_htb_supported_runtime() {
    local v
    v=$(cap_bool_value tc_htb 2>/dev/null || echo unknown)
    [ "$v" = "false" ] && return 1
    return 0
}

tc_netem_supported_runtime() {
    local v
    v=$(cap_bool_value tc_netem 2>/dev/null || echo unknown)
    [ "$v" = "false" ] && return 1
    return 0
}

tc_limit_supported_runtime() {
    tc_htb_supported_runtime
}

tc_delay_supported_runtime() {
    tc_htb_supported_runtime && tc_netem_supported_runtime
}

log_tc_unsupported_once() {
    local where=${1:-tc} kind=${2:-tc}
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    local once="$HNC_DIR/run/${kind}_unsupported_logged"
    if [ ! -f "$once" ]; then
        log "$where: $kind unsupported by capabilities; skip tc operation and return fast"
        echo 1 > "$once" 2>/dev/null || true
    fi
}

cap_uplink_value() {
    [ -f "$CAP_FILE" ] || return 1
    if grep -q '"uplink_supported"[[:space:]]*:[[:space:]]*true' "$CAP_FILE" 2>/dev/null; then
        echo true
        return 0
    fi
    if grep -q '"uplink_supported"[[:space:]]*:[[:space:]]*false' "$CAP_FILE" 2>/dev/null; then
        echo false
        return 0
    fi
    return 1
}

uplink_supported_runtime() {
    [ -f "$UPLINK_MARKER" ] && return 1
    local v
    v=$(cap_uplink_value 2>/dev/null || echo unknown)
    [ "$v" = "false" ] && return 1
    # Unknown keeps legacy best-effort behavior so older installs without capabilities.json still work.
    return 0
}

log_uplink_unsupported_once() {
    local where=${1:-tc}
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    if [ ! -f "$UPLINK_MARKER" ]; then
        local now
        now=$(date +%s 2>/dev/null || echo 0)
        printf '%s\n' "{\"ifb_unsupported\":true,\"since\":$now,\"reason\":\"capability_probe uplink_supported=false\"}" > "$UPLINK_MARKER" 2>/dev/null || true
    fi
    if [ ! -f "$UPLINK_LOG_ONCE" ]; then
        log "$where: uplink unsupported by capabilities; skip IFB/mirred and use downlink-only / egress-only mode"
        echo 1 > "$UPLINK_LOG_ONCE" 2>/dev/null || true
    fi
}

# ═══════════════════════════════════════════════════════════════
# v3.3.1 浮点数比较助手
# 问题：shell 内置 `[ x -gt 0 ]` 对 "0.2" 这种小数直接报错，
# 导致 set_limit/set_delay 里所有 `if [ "${val:-0}" -gt 0 ]` 判断
# 在小数输入下统统走 false 分支，限速规则永远不会被创建。
# 症状：整数 Mbps 生效、小数 Mbps（0.1 / 0.2 / 0.5）完全不生效。
#
# 用法：gt0 "$var"            # $var > 0 ?
#       ge_val "$a" "$b"      # $a >= $b ?
# ═══════════════════════════════════════════════════════════════
gt0() {
    awk -v v="${1:-0}" 'BEGIN{exit !(v+0 > 0)}'
}
ge_val() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN{exit !(a+0 >= b+0)}'
}
lt_val() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN{exit !(a+0 < b+0)}'
}

# ─── 常量 ────────────────────────────────────────────────────
DEFAULT_RATE="1000mbit"
IFB_IFACE="ifb0"
FILTER_PRIO_FW=1       # fw mark filter（备用）
FILTER_PRIO_BASE=100   # u32 IP filter 基准优先级（每设备 100+class_id）

# rc3.1.34 修 #14: 防御 mark_id 非数字传入. 3 处 set_limit/set_delay/remove_device
# 之前 `printf "%d" "$mark_id"` 对非数字会输出 0 + stderr 报错 → class_id=0 →
# 跟 tc root class 冲突或全局影响. 上游 silent fail 漏出垃圾 mid 时整个 tc
# 链被污染. 用 case glob 校验, 仿 Go 端 intRE 模式.
_validate_mark_id() {
    local mid=$1
    case "$mid" in
        ''|*[!0-9]*)
            log "ERROR: invalid mark_id '$mid' (not a positive integer)"
            return 1 ;;
        *)
            # 范围检查: 1-99 跟 apply_device_rule.sh get_or_assign_mid 一致
            if [ "$mid" -lt 1 ] || [ "$mid" -gt 99 ]; then
                log "ERROR: mark_id '$mid' out of range [1,99]"
                return 1
            fi
            return 0 ;;
    esac
}

# ═══════════════════════════════════════════════════════════════
# 顶层辅助函数（Android ash 不支持嵌套函数定义）
# ═══════════════════════════════════════════════════════════════

rate_to_mbps_num() {
    local val=$1 n
    case "$val" in
        *[kK][bB][iI][tT]|*[kK][bB][pP][sS]|*[kK])
            n=$(printf '%s' "$val" | sed 's/[kK][bB][iI][tT]$//; s/[kK][bB][pP][sS]$//; s/[kK]$//')
            awk -v v="$n" 'BEGIN{printf "%.6f", (v+0)/1000}'
            ;;
        *[mM][bB][iI][tT]|*[mM][bB][pP][sS]|*[mM])
            n=$(printf '%s' "$val" | sed 's/[mM][bB][iI][tT]$//; s/[mM][bB][pP][sS]$//; s/[mM]$//')
            awk -v v="$n" 'BEGIN{printf "%.6f", v+0}'
            ;;
        *)
            awk -v v="$val" 'BEGIN{printf "%.6f", v+0}'
            ;;
    esac
}

mbps_to_rate() {
    local val=$1 mbps
    mbps=$(rate_to_mbps_num "$val")
    # 统一换算为 kbit 输出，兼顾小数精度；避免 tc 不接受 1.5mbit。
    if gt0 "$mbps"; then
        local kbps; kbps=$(awk -v v="$mbps" 'BEGIN{printf "%d", v*1000 + 0.5}')
        [ "${kbps:-0}" -lt 1 ] && kbps=1
        echo "${kbps}kbit"
    else
        echo "64kbit"
    fi
}

# burst/cburst strategy.
# hotfix17.5:
# - compat  : keep ~20ms bucket for driver tolerance.
# - precise : smaller bucket for root-HTB fallback, closer to requested MB/s.
# Very high DEFAULT_RATE classes keep a safe 200k bucket to avoid accidental
# throttling of delay-only/unlimited paths.
burst_for_rate() {
    local mbps mode
    mbps=$(rate_to_mbps_num "$1")
    mode=$(qos_mode)
    awk -v v="$mbps" -v m="$mode" '
      BEGIN {
        if (v <= 0) { print "16k"; exit }
        if (v >= 100) { print "200k"; exit }
        if (m == "precise") {
          b = int(v * 1.0);
          if (b < 8) b = 8;
          if (b > 64) b = 64;
        } else {
          b = int(v * 2.5);
          if (b < 16) b = 16;
          if (b > 256) b = 256;
        }
        print b "k"
      }'
}

qos_class_burst_for_rate() { burst_for_rate "$1"; }

# HTB class add-or-change（幂等）
tc_class_set() {
    local dev=$1 parent=$2 classid=$3; shift 3
    tc class change dev "$dev" parent "$parent" classid "$classid" htb "$@" 2>/dev/null && return 0
    tc class add   dev "$dev" parent "$parent" classid "$classid" htb "$@" 2>/dev/null && return 0
    return 1
}

# 确保 HTB class 有叶子 qdisc（无叶子时 pfifo 兜底偶发丢包）
tc_leaf_ensure() {
    local dev=$1 parent=$2 handle=$3
    tc qdisc change dev "$dev" parent "$parent" handle "$handle" fq_codel 2>/dev/null && return 0
    tc qdisc add   dev "$dev" parent "$parent" handle "$handle" fq_codel 2>/dev/null \
        || tc qdisc add dev "$dev" parent "$parent" handle "$handle" pfifo 2>/dev/null || true
}

# fw mark filter（备用，prio=1）
tc_filter_fw_set() {
    local dev=$1 mark=$2 flowid=$3
    tc filter del dev "$dev" parent 1: pref "$FILTER_PRIO_FW" handle "$mark" fw 2>/dev/null || true
    if tc filter add dev "$dev" parent 1: pref "$FILTER_PRIO_FW" handle "$mark" fw \
        flowid "$flowid" 2>/dev/null; then
        return 0
    fi
    log_error "fw filter add failed on $dev mark=$mark flowid=$flowid"
    return 1
}

# u32 dst IP filter（下载方向：热点→设备，按 dst IP 分类）
# 关键：不依赖 iptables mark，捕获所有协议（TCP/UDP/QUIC）
# v3.3.4：删除了原 IPv6 u32 分支——原代码用 $ip（IPv4 地址）做 "ip6 dst $ip/128"
#         永远不可能匹配，是静默失败的死代码。IPv6 流量现在完全靠 fw mark filter
#         （由 tc_filter_fw_set 注册）配合 iptables_manager.sh 的 CONNMARK 路径分类。
tc_filter_u32_dst() {
    local dev=$1 prio=$2 ip=$3 flowid=$4
    [ -z "$ip" ] && return 0
    tc filter del dev "$dev" parent 1: prio "$prio" 2>/dev/null || true
    tc filter add dev "$dev" parent 1: protocol ip prio "$prio" u32 \
        match ip dst "$ip/32" flowid "$flowid" 2>/dev/null \
        && log "u32 dst $ip → $flowid on $dev"
}

# u32 src IP filter（上传方向：设备→ifb0，按 src IP 分类）
# 核心修复：替代 fw mark，解决 mirred redirect 时序问题
# v3.3.4：同样删除了假的 IPv6 分支
tc_filter_u32_src() {
    local dev=$1 prio=$2 ip=$3 flowid=$4
    [ -z "$ip" ] && return 0
    tc filter del dev "$dev" parent 1: prio "$prio" 2>/dev/null || true
    tc filter add dev "$dev" parent 1: protocol ip prio "$prio" u32 \
        match ip src "$ip/32" flowid "$flowid" 2>/dev/null \
        && log "u32 src $ip → $flowid on $dev"
}

# netem qdisc add-or-change
netem_qdisc_set() {
    local dev=$1 parent=$2 handle=$3; shift 3
    tc qdisc change dev "$dev" parent "$parent" handle "$handle" netem "$@" 2>/dev/null && return 0
    tc qdisc del dev "$dev" parent "$parent" 2>/dev/null || true
    tc qdisc add dev "$dev" parent "$parent" handle "$handle" netem "$@" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════
# v3.3.2 设备 class 生命周期管理
#
# 【新架构】
# 限速（HTB rate）与延迟（netem）使用同一个 HTB class，但互不干扰：
#
#   class 1:$class_id  (HTB, rate = 限速值 或 DEFAULT_RATE 表示不限速)
#     └─ qdisc leaf: netem [delay Xms] limit 100
#                    （无延迟时仅 limit，不带 delay 参数）
#
# 【分工】
#   - ensure_device_class : 幂等创建 class + leaf netem + filter
#   - set_rate_only       : 仅改 class 的 rate/ceil/burst
#   - set_netem_only      : 仅改 leaf netem 参数
#   - class_exists        : 查询 class 是否存在（用于关闭分支保护 leaf）
#   - leaf_has_netem      : 查询 leaf 是否为 netem（兼容 v3.3.1 fq_codel 残留）
#
# 【解决 v3.3.1 的核心 bug】
#   原 set_limit 的 "关闭限速" 分支会 `tc class del`，连带删除挂在该
#   class 下的 netem qdisc → 关掉限速就误杀了延迟。反向也有类似问题
#   （换叶子 qdisc 会影响限速）。新架构下两者完全解耦：
#     - set_limit(0)  → 只 set_rate_only 为 DEFAULT_RATE，leaf netem 不动
#     - set_delay(0)  → 只 set_netem_only 为无延迟，class rate 不动
# ═══════════════════════════════════════════════════════════════

# 查询 class 是否存在
class_exists() {
    local dev=$1 class_id=$2
    tc class show dev "$dev" 2>/dev/null | grep -qF "class htb 1:$class_id "
}

# 查询 leaf qdisc 是否已是 netem（用于兼容 v3.3.1 fq_codel 残留的升级场景）
leaf_has_netem() {
    local dev=$1 class_id=$2
    tc qdisc show dev "$dev" 2>/dev/null \
        | grep -F "parent 1:$class_id " \
        | grep -q netem
}

# 幂等创建设备 class + leaf netem + filters
# 参数：dev class_id ip
# 方向由 dev 推断：$IFB_IFACE → src IP（上传），其他 → dst IP（下载）
#
# hotfix7: ColorOS 16 / kernel 6.6 上, 已存在 class 时 del+add 不是原子操作。
# set_limit 成功后再 set_delay 会进入旧 rebuild 路径: class del 成功, 但同
# classid add 失败, 导致之前的限速 class 被破坏。这里改为:
#   - class 已存在: tc class change 原地刷新 rate/ceil/burst, 不删 class, 不动 leaf/filter
#   - class 不存在: 首次创建仍用 tc class add
# leaf netem 同样优先 change, 不存在才 add。这样 set_limit ↔ set_delay 不再互相破坏。
ensure_device_class() {
    local dev=$1 class_id=$2 ip=$3
    local mark; mark=$(printf "0x%x" $((0x800000 + class_id)))
    local prio=$((FILTER_PRIO_BASE + class_id))
    local leaf_handle direction
    if [ "$dev" = "$IFB_IFACE" ]; then
        leaf_handle=$((class_id + 2000))
        direction=src
    else
        leaf_handle=$((class_id + 1000))
        direction=dst
    fi

    # 1. 读取当前 rate / netem, 但不删除已有 class。
    # v3.3.6 的 del+add 是为了刷新 cburst, 但在 ColorOS oplus_netd 接管 root htb
    # 时会出现 del 成功、add 失败的破坏性中间态。tc class change 可以原地刷新
    # rate/burst/cburst, 不触碰子 qdisc 和 filter, 是这里唯一安全的幂等路径。
    local saved_rate=""
    local saved_delay=""
    local saved_jitter=""
    local class_present=0
    if class_exists "$dev" "$class_id"; then
        class_present=1
        local class_line; class_line=$(tc class show dev "$dev" classid "1:$class_id" 2>/dev/null)
        if [ -n "$class_line" ]; then
            saved_rate=$(echo "$class_line" | awk '{for(i=1;i<=NF;i++) if($i=="rate") {print $(i+1); exit}}')
        fi
        local netem_line; netem_line=$(tc qdisc show dev "$dev" parent "1:$class_id" 2>/dev/null | grep netem)
        if [ -n "$netem_line" ]; then
            saved_delay=$(echo "$netem_line" | awk '{for(i=1;i<=NF;i++) if($i=="delay") {print $(i+1); exit}}')
            saved_jitter=$(echo "$netem_line" | awk '{for(i=1;i<=NF;i++) if($i=="delay") {print $(i+2); exit}}')
            case "$saved_delay" in
                0ms|0us|0s|"") saved_delay="" ;;
                *ms|*us|*s) ;;
                *) saved_delay="" ;;
            esac
            case "$saved_jitter" in
                *ms|*us|*s) ;;
                *) saved_jitter="" ;;
            esac
        fi
    fi

    # 2. class 生命周期: 已存在就 change, 不存在才 add。绝不在 ensure 路径 del class。
    local use_rate="${saved_rate:-$DEFAULT_RATE}"
    local use_burst; use_burst=$(qos_class_burst_for_rate "$use_rate")
    if [ "$class_present" = "1" ]; then
        if tc class change dev "$dev" parent 1:1 classid "1:$class_id" \
            htb rate "$use_rate" ceil "$use_rate" burst "$use_burst" cburst "$use_burst" 2>/dev/null; then
            log "  Updated class 1:$class_id on $dev (rate=$use_rate, no rebuild)"
        else
            # hotfix17.4: root qdisc may have been restored to mq after class was
            # observed. Rebuild HTB once and retry before failing.
            if [ "$dev" != "$IFB_IFACE" ] && ensure_egress_htb_ready "$dev" "ensure_device_class_change" && \
                tc class change dev "$dev" parent 1:1 classid "1:$class_id" \
                    htb rate "$use_rate" ceil "$use_rate" burst "$use_burst" cburst "$use_burst" 2>/dev/null; then
                log "  Updated class 1:$class_id on $dev after HTB self-heal"
            else
                log_error "ensure_device_class: class change failed dev=$dev class=1:$class_id (kept existing class, no del+add)"
                return 1
            fi
        fi
    else
        if [ "$dev" != "$IFB_IFACE" ]; then
            ensure_egress_htb_ready "$dev" "ensure_device_class" || return 1
        fi
        if tc class add dev "$dev" parent 1:1 classid "1:$class_id" \
            htb rate "$use_rate" ceil "$use_rate" burst "$use_burst" cburst "$use_burst" 2>/dev/null; then
            log "  Created class 1:$class_id on $dev (rate=$use_rate)"
        else
            if [ "$dev" != "$IFB_IFACE" ] && ensure_egress_htb_ready "$dev" "ensure_device_class_retry" && \
                tc class add dev "$dev" parent 1:1 classid "1:$class_id" \
                    htb rate "$use_rate" ceil "$use_rate" burst "$use_burst" cburst "$use_burst" 2>/dev/null; then
                log "  Created class 1:$class_id on $dev after HTB self-heal"
            else
                log_error "ensure_device_class: class add failed dev=$dev class=1:$class_id"
                return 1
            fi
        fi
    fi

    # 3. leaf qdisc: v5.3 adds optional SQM leaf for delay-free classes.
    # Existing active netem must be preserved; real delay/jitter/loss still wins over SQM.
    local leaf_kind; leaf_kind=$(sqm_preferred_leaf)
    if leaf_has_active_netem "$dev" "$class_id"; then
        : # keep real netem as-is; set_netem_only owns delay parameters.
    elif [ "$leaf_kind" != "off" ]; then
        if sqm_leaf_replace "$dev" "$class_id" "$leaf_handle" "$leaf_kind"; then
            log "  Set leaf ${leaf_handle}: $leaf_kind for SQM mode=$(sqm_mode)"
        else
            log_error "ensure_device_class: SQM leaf $leaf_kind failed dev=$dev class=1:$class_id; fallback netem-0ms"
            if ! netem_leaf_replace_zero "$dev" "$class_id" "$leaf_handle"; then
                log_error "ensure_device_class: fallback netem leaf failed dev=$dev class=1:$class_id"
                return 1
            fi
        fi
    elif leaf_has_netem "$dev" "$class_id"; then
        : # keep existing netem-0ms placeholder in default/off mode.
    else
        if netem_leaf_replace_zero "$dev" "$class_id" "$leaf_handle"; then
            log "  Created leaf netem ${leaf_handle}: (delay 0ms placeholder)"
        else
            log_error "ensure_device_class: leaf netem add failed dev=$dev class=1:$class_id"
            return 1
        fi
    fi

    # 4. 创建 u32 filter
（若有 IP）
    local u32_ok=0
    if [ -n "$ip" ]; then
        if [ "$direction" = "src" ]; then
            tc_filter_u32_src "$dev" "$prio" "$ip" "1:$class_id" && u32_ok=1 || \
                log_error "ensure_device_class: u32 src filter failed dev=$dev ip=$ip class=1:$class_id"
        else
            tc_filter_u32_dst "$dev" "$prio" "$ip" "1:$class_id" && u32_ok=1 || \
                log_error "ensure_device_class: u32 dst filter failed dev=$dev ip=$ip class=1:$class_id"
        fi
    fi

    # 5. 创建 fw 备用 filter。若没有 IP/u32,fw filter 是唯一分类路径,失败必须上报。
    if ! tc_filter_fw_set "$dev" "$mark" "1:$class_id"; then
        [ "$u32_ok" = "1" ] || return 1
    fi
    return 0
}

# 仅修改 class 的 rate/ceil/burst（不动 leaf qdisc）
# v3.3.5：cburst 必须和 burst 一起改，不然 cburst 永远是初始建 class 时的值
set_rate_only() {
    local dev=$1 class_id=$2 rate=$3 burst=$4
    tc_class_set "$dev" 1:1 "1:$class_id" rate "$rate" ceil "$rate" burst "$burst" cburst "$burst"
}

# 仅修改 leaf netem 参数（不动 class rate）
# 参数：dev class_id delay_ms jitter_ms loss
set_netem_only() {
    local dev=$1 class_id=$2 delay_ms=${3:-0} jitter_ms=${4:-0} loss=${5:-0}
    local leaf_handle
    if [ "$dev" = "$IFB_IFACE" ]; then
        leaf_handle=$((class_id + 2000))
    else
        leaf_handle=$((class_id + 1000))
    fi

    # 拼接 netem 参数。v3.3.2：无论 delay 是否为 0 都显式带上 `delay Xms`，
    # 避免部分 kernel 在 `tc qdisc change` 省略 delay 时保留旧值。
    # v3.4.11 P0-3 修复:之前 if gt0 delay 的 else 分支只输出 "delay 0ms",
    # 把 jitter 和 loss 都丢了,导致"只设丢包不设延迟"完全无效
    # (但前端 delay_enabled = (dl>0 || jt>0 || ls>0) 让 UI 显示已启用 → 严重视觉欺骗)。
    local args
    if gt0 "$delay_ms" || gt0 "$jitter_ms" || gt0 "$loss"; then
        if gt0 "$delay_ms"; then
            args="delay ${delay_ms}ms"
            gt0 "$jitter_ms" && args="$args ${jitter_ms}ms 25% distribution normal"
        else
            args="delay 0ms"
        fi
        gt0 "$loss" && args="$args loss ${loss}%"
    else
        args="delay 0ms"
    fi
    args="$args limit 100"  # v3.3.5: 同 ensure_device_class，避免 buffer bloat

    # v5.3: clearing delay can safely return to SQM leaf if the user enabled it.
    if ! gt0 "$delay_ms" && ! gt0 "$jitter_ms" && ! gt0 "$loss"; then
        local leaf_kind; leaf_kind=$(sqm_preferred_leaf)
        if [ "$leaf_kind" != "off" ]; then
            sqm_leaf_replace "$dev" "$class_id" "$leaf_handle" "$leaf_kind" && return 0
        fi
    fi

    # 幂等：优先 replace，兼容当前 leaf 不是 netem 的 v5.3 SQM 情况。
    # shellcheck disable=SC2086
    tc qdisc replace dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" netem $args 2>/dev/null && return 0
    tc qdisc del    dev "$dev" parent "1:$class_id" 2>/dev/null || true
    # shellcheck disable=SC2086
    tc qdisc add    dev "$dev" parent "1:$class_id" handle "${leaf_handle}:" netem $args 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════
# 禁用硬件加速 / offload
# 必须在 tc qdisc 建立之前调用，否则大包绕过整形层
# ═══════════════════════════════════════════════════════════════
disable_offload() {
    local iface=$1
    log "Disabling offload on $iface..."

    # 关闭 ethtool offload（GRO/GSO/TSO/LRO）
    # GRO 把多个小包合并为大包再交给网络栈，tc 按包整形时等效带宽倍增
    ethtool -K "$iface" gro off gso off tso off lro off 2>/dev/null || true
    ethtool -K "$iface" sg off rx-vlan-offload off tx-vlan-offload off 2>/dev/null || true

    # Android 特有 fastpath / 硬件转发加速（高通/联发科 SoC）
    for p in \
        /proc/sys/net/netfilter/nf_fastroute \
        /proc/sys/net/rmnet/nf_hook_enable   \
        /sys/kernel/hnk/nf_conntrack_skip    ; do
        [ -w "$p" ] && echo 0 > "$p" 2>/dev/null || true
    done

    # bridge-nf 确保桥接帧走 iptables（v3.4.1：很多 ColorOS 内核没编 bridge 模块，
    # /proc/sys/net/bridge 目录直接不存在。无害，静默忽略。）
    [ -w /proc/sys/net/bridge/bridge-nf-call-iptables ]  && echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables  2>/dev/null || true
    [ -w /proc/sys/net/bridge/bridge-nf-call-ip6tables ] && echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables 2>/dev/null || true

    # 关闭 RPS（部分配置下绕过 tc ingress）
    for q in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
        [ -w "$q" ] && echo 0 > "$q" 2>/dev/null || true
    done

    # 确保 conntrack 记账开启
    modprobe nf_conntrack 2>/dev/null || true
    echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || true

    # MTU 限制为 1500（防超大帧绕过整形）
    local mtu; mtu=$(cat /sys/class/net/"$iface"/mtu 2>/dev/null || echo 1500)
    [ "${mtu:-1500}" -gt 1500 ] && ip link set dev "$iface" mtu 1500 2>/dev/null || true

    log "Offload disabled OK"
}

# ─── 加载 IFB 模块 ───────────────────────────────────────────
load_ifb() {
    if ! uplink_supported_runtime; then
        log_uplink_unsupported_once "load_ifb"
        return 1
    fi
    modprobe ifb numifbs=2 2>/dev/null \
        || insmod /system/lib/modules/ifb.ko numifbs=2 2>/dev/null || true
    local i=0
    while [ $i -lt 3 ] && ! ip link show "$IFB_IFACE" >/dev/null 2>&1; do
        ip link add "$IFB_IFACE" type ifb 2>/dev/null || true
        i=$((i+1))
        usleep 200000 2>/dev/null || sleep 1
    done
    if ! ip link show "$IFB_IFACE" >/dev/null 2>&1; then
        log_error "load_ifb: $IFB_IFACE unavailable"
        return 1
    fi
    ip link set "$IFB_IFACE" up 2>/dev/null || true
    log "IFB $IFB_IFACE ready"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# v5.0 alpha.2 P0-0: 独立安装 ingress mirred (wlan2 → ifb0)
#
# 背景:
#   v4.x init_tc 把 mirred 安装放在 root htb add 之后的同一流程里。
#   ColorOS / RMX5010 上 wlan2 的 root htb 被 oplus-netd 预装, HNC 的
#   `tc qdisc add dev wlan2 root handle 1:` 会因 File exists 失败(tc.log
#   显示 "invalid argument 'root'", 是 ColorOS 定制 iproute2 的错误翻译),
#   init_tc 直接 return, 导致 ingress mirred 永远不装。
#
#   结果: 上行流量被 oplus pref 49152 mirred 抢到 ifb1, HNC 的 ifb0 永远
#   收不到数据包, 上行限速在 v4.x 所有版本都完全失效。
#
#   真机验证 (RMX5010 + SD8 Elite + ColorOS 16 + Android 16):
#   装前: 上行限速 2 Mbit/s 实际 45-55 Mbps (~22x 超标)
#   装后: 上行 2.16 Mbit/s (92% 精度)
#
# 设计:
#   - 跟 root htb add 完全解耦, 任何情况下都尝试装
#   - 用 matchall (而非 u32 match u32 0 0), 一条 filter 同时覆盖 v4+v6
#   - pref 1 抢在 ColorOS oplus-netd 的 pref 49152 之前
#   - 幂等: 重复调用会先 del 旧 filter 再 add
# ═══════════════════════════════════════════════════════════════
install_ingress_mirred_once() {
    local iface=$1
    [ -z "$iface" ] && { log_error "install_ingress_mirred: empty iface"; return 1; }

    # v5.0 alpha.2 hotfix4: iface 不存在时 silent skip
    # ColorOS 上 wlan2 按需创建, 热点没开时不存在。restore_rules / watchdog 会
    # 在热点没开时调我们, 此时 tc 报 "Cannot find device" 会被翻译成
    # "invalid argument 'ingress'" 等迷惑性错误。静默跳过, 等 wlan2 真的 UP
    # 再装。
    if ! ip link show "$iface" >/dev/null 2>&1; then
        log "install_ingress_mirred: $iface not present yet, skip (will retry when iface up)"
        return 0
    fi

    # v5.0 alpha.2 hotfix3: 直接用 ingress 简写, 不再用 parent spec 探测
    # ColorOS 定制 tc 有多重错误翻译:
    #   - hotfix1 以为要用 parent ffff:fff2 (因为某次 ingress 简写报错)
    #   - hotfix3 真机验证: ColorOS tc 反而不认 parent ffff:fff2, 只认 ingress 简写
    # 真机上 Ling 手动跑 "tc filter add dev wlan2 ingress prio 1 protocol all matchall..."
    # 永远成功, 改回这个语法。
    #
    # 如果 ingress 失败, 再试 parent ffff: (老式 ingress qdisc) 作为 fallback.

    # 确保有 ingress 挂点 (clsact 或老式 ingress qdisc 都行)
    if ! tc qdisc show dev "$iface" 2>/dev/null | grep -qE "clsact ffff:|ingress "; then
        # 什么都没有, 尝试装 clsact (优先) 或 ingress
        tc qdisc add dev "$iface" clsact 2>/dev/null \
            || tc qdisc add dev "$iface" handle ffff: ingress 2>/dev/null \
            || log_error "install_ingress_mirred: cannot add clsact/ingress qdisc on $iface"
    fi

    # 幂等: 先删可能残留的 pref 1
    tc filter del dev "$iface" ingress pref 1 2>/dev/null || true

    # 主路径: ingress 简写 + matchall (Ling 真机手动验证过能用)
    local _out
    _out=$(tc filter add dev "$iface" ingress prio 1 protocol all matchall \
           action mirred egress redirect dev "$IFB_IFACE" 2>&1)
    if [ -z "$_out" ]; then
        log "install_ingress_mirred: $iface ingress pref 1 matchall → $IFB_IFACE OK"
        return 0
    fi

    log_error "install_ingress_mirred: matchall failed: $_out, trying u32 fallback"

    # Fallback 1: ingress 简写 + u32 (旧内核)
    _out=$(tc filter add dev "$iface" ingress protocol ip prio 1 u32 \
           match u32 0 0 action mirred egress redirect dev "$IFB_IFACE" 2>&1)
    if [ -z "$_out" ]; then
        log "install_ingress_mirred: $iface ingress pref 1 u32 (v4 only) → $IFB_IFACE OK"
        tc filter add dev "$iface" ingress protocol ipv6 prio 2 u32 \
            match u32 0 0 action mirred egress redirect dev "$IFB_IFACE" 2>/dev/null || true
        return 0
    fi

    log_error "install_ingress_mirred: u32 also failed: $_out, trying parent ffff: fallback"

    # Fallback 2: 老式 parent ffff: (非 clsact 内核)
    tc filter del dev "$iface" parent ffff: pref 1 2>/dev/null || true
    _out=$(tc filter add dev "$iface" parent ffff: prio 1 protocol all matchall \
           action mirred egress redirect dev "$IFB_IFACE" 2>&1)
    if [ -z "$_out" ]; then
        log "install_ingress_mirred: $iface parent ffff: pref 1 matchall → $IFB_IFACE OK"
        return 0
    fi

    log_error "install_ingress_mirred: $iface mirred add FAILED (all paths): $_out (上行限速将失效!)"
    return 1
}

# v5.0 beta.1: netlink 直通路径 (方向 B)
#
# 背景: alpha.4 hotfix2 的异步 45s 长轮询能 work, 但用户重启后要等 30-45s
# 才能有上行限速. 用户感知不佳, 且 oplus-netd 如果改为 > 45s 窗口就会彻底
# 失败 (已见 RMX5010 真机偶发 FAILED after 15 attempts).
#
# 方向 B: 写一个独立 C 工具 hnc_tc_ingress, 绕过 /system/bin/tc 魔改二进制,
# 直接构造 RTM_NEWTFILTER netlink 消息发给内核 rtnetlink socket.
#
# 外部 AI 审查判定根因: ColorOS /system/bin/tc 在用户空间前置校验阶段就抛
# "invalid argument 'ingress'", netlink 消息根本没发给内核. 内核本身一直
# 能接受这消息. 绕过魔改 tc 之后, wlan2 一 UP 就能立即注入, 耗时 < 10ms.
#
# 集成策略:
#   1. 先试 netlink 直通工具 (10ms 成功)
#   2. 失败才回落 hotfix2 异步长轮询 (30-45s 后成功)
# 双保险, 支持所有 ROM (netlink 失败会优雅降级到 shell tc 路径)
install_ingress_mirred_via_netlink() {
    local iface=$1
    local netlink_bin="$HNC_DIR/bin/hnc_tc_ingress"

    # 工具缺失 → 调用方回落异步路径
    if [ ! -x "$netlink_bin" ]; then
        return 99
    fi

    # 确保 ifb0 存在 + UP (netlink 工具要求 ifb 已就绪)
    if ! ip link show "$IFB_IFACE" >/dev/null 2>&1; then
        modprobe ifb 2>/dev/null || true
        ip link add "$IFB_IFACE" type ifb 2>/dev/null || true
    fi
    ip link set "$IFB_IFACE" up 2>/dev/null || true

    # 调直通工具, 输出拼到我们自己日志
    local _out
    _out=$("$netlink_bin" "$iface" "$IFB_IFACE" 1 2>&1)
    local rc=$?
    if [ $rc -eq 0 ]; then
        log "install_ingress_mirred: via netlink OK (${_out})"
        return 0
    fi

    # netlink 失败原因分类
    case $rc in
        1) log_error "install_ingress_mirred: netlink iface '$iface' not found (rc=1)" ;;
        2) log_error "install_ingress_mirred: netlink ifb '$IFB_IFACE' not found (rc=2)" ;;
        3) log "install_ingress_mirred: netlink kernel reject (rc=3, ${_out}), will fallback" ;;
        4) log_error "install_ingress_mirred: netlink CLI error (rc=4, ${_out})" ;;
        *) log "install_ingress_mirred: netlink unknown rc=$rc (${_out}), will fallback" ;;
    esac
    return $rc
}

install_ingress_mirred() {
    local iface=$1
    [ -z "$iface" ] && { log_error "install_ingress_mirred: empty iface"; return 1; }

    if ! uplink_supported_runtime; then
        log_uplink_unsupported_once "install_ingress_mirred"
        return 0
    fi

    # 热点关了时 silent skip (hotfix4)
    if ! ip link show "$iface" >/dev/null 2>&1; then
        log "install_ingress_mirred: $iface not present yet, skip (will retry when iface up)"
        return 0
    fi

    # beta.1 优先路径: netlink 直通 (< 10ms, ColorOS 免受魔改 tc 阻塞)
    install_ingress_mirred_via_netlink "$iface"
    case $? in
        0)
            # netlink 路径成功, 不再跑 shell tc, 不启动异步 worker
            return 0
            ;;
        1)
            # iface missing: shell path will also fail.
            return 1
            ;;
        *)
            # netlink 不可用 (99) 或 kernel reject (3) 或其他 → 回落
            log "install_ingress_mirred: falling back to async shell tc path"
            ;;
    esac

    # === 回落路径 (alpha.4 hotfix2 + async worker) ===

    # 首次同步尝试
    install_ingress_mirred_once "$iface"
    if [ $? -eq 0 ]; then
        return 0
    fi

    log "install_ingress_mirred: initial shell attempt failed, spawning async worker (ColorOS race window)"

    # 后台 worker: 最多等 45s, 每 3s 重试一次
    (
        local attempt=1
        local max=15
        local sleep_s=3

        while [ $attempt -le $max ]; do
            sleep $sleep_s

            # 热点关了就退出
            if ! ip link show "$iface" >/dev/null 2>&1; then
                log "install_ingress_mirred (async): $iface gone, worker exit"
                exit 0
            fi

            # 每次重试前先试 netlink 一次 (可能工具现在起效了)
            install_ingress_mirred_via_netlink "$iface"
            if [ $? -eq 0 ]; then
                log "install_ingress_mirred (async): netlink succeeded on attempt $attempt"
                exit 0
            fi

            # 再试 shell tc
            local oplus_ready=0
            if tc filter show dev "$iface" ingress 2>/dev/null | grep -qE "pref (4[89][0-9]{3}|5[0-9]{4})"; then
                oplus_ready=1
            fi

            install_ingress_mirred_once "$iface"
            if [ $? -eq 0 ]; then
                if [ $oplus_ready -eq 1 ]; then
                    log "install_ingress_mirred (async): shell succeeded on attempt $attempt (oplus-netd ready detected)"
                else
                    log "install_ingress_mirred (async): shell succeeded on attempt $attempt"
                fi
                exit 0
            fi

            attempt=$((attempt + 1))
        done

        log_error "install_ingress_mirred (async): FAILED after $max attempts (~45s). Uplink shaping broken."
    ) >/dev/null 2>&1 &

    return 0
}

# hotfix17.2/17.3: Xiaomi/MIUI mq handling.
# Child leaves under qdisc mq look tempting, but Mi 10 rejects parent :1/0:1.
# Keep one best-effort child attempt for ROMs that allow it, then immediately
# fall back to root replace. Root replace with /system/bin/tc and WITHOUT r2q is
# verified on Mi 10 and restore-to-mq works in cleanup/probe.
try_mq_child_htb() {
    local iface=$1
    local parent out last_out
    [ -n "$iface" ] || return 1
    for parent in :1 0:1; do
        out=$(tc qdisc replace dev "$iface" parent "$parent" handle 1: htb default 9999 2>&1)
        if [ -z "$out" ]; then
            log "init_tc: mq child htb installed on $iface parent $parent"
            echo "$iface parent=$parent" > "$HNC_DIR/run/tc_mq_child_$iface" 2>/dev/null || true
            qos_clear_root_fallback
            return 0
        fi
        last_out=$out
    done
    log "init_tc: mq child htb unsupported on $iface, will try root HTB fallback: $last_out"
    return 1
}

root_htb_replace_verified() {
    local iface=$1 out
    out=$(tc qdisc replace dev "$iface" root handle 1: htb default 9999 2>&1)
    if [ -z "$out" ]; then
        echo "$iface" > "$HNC_DIR/run/tc_root_owned_$iface" 2>/dev/null || true
        qos_mark_root_fallback
        log "init_tc: root HTB installed on $iface via verified root fallback (qos=$(qos_mode))"
        return 0
    fi
    log_error "init_tc: verified root HTB fallback failed on $iface: $out"
    return 1
}


# hotfix17.4: just-in-time TC self-heal.
# MIUI14 may restore wlan1 root qdisc from HNC HTB back to mq after hotspot
# recreation/cleanup. set_limit/set_delay must not assume class 1:* still exists.
egress_htb_tree_ready() {
    local iface=$1
    [ -n "$iface" ] || return 1
    ip link show "$iface" >/dev/null 2>&1 || return 1
    tc qdisc show dev "$iface" 2>/dev/null | grep -q '^qdisc htb 1:' || return 1
    tc class show dev "$iface" 2>/dev/null | grep -q 'class htb 1:1' || return 1
    return 0
}

egress_root_summary() {
    local iface=$1
    tc qdisc show dev "$iface" 2>/dev/null | grep ' root' | head -1
}

ensure_egress_htb_ready() {
    local iface=$1 where=${2:-tc}
    [ -n "$iface" ] || { log_error "$where: empty iface, cannot ensure HTB"; return 1; }
    if ! ip link show "$iface" >/dev/null 2>&1; then
        log_error "$where: iface $iface missing, cannot ensure HTB"
        return 1
    fi
    if ! tc_limit_supported_runtime; then
        log_tc_unsupported_once "$where" "tc_htb"
        return 66
    fi
    if egress_htb_tree_ready "$iface"; then
        return 0
    fi

    local before
    before=$(egress_root_summary "$iface")
    log "$where: HNC HTB tree missing on $iface (root=${before:-none}); re-init before applying"
    init_tc "$iface" || {
        log_error "$where: init_tc failed while rebuilding HTB on $iface"
        return 1
    }
    if egress_htb_tree_ready "$iface"; then
        log "$where: HNC HTB tree rebuilt on $iface"
        return 0
    fi
    local after
    after=$(egress_root_summary "$iface")
    log_error "$where: HNC HTB tree still missing after init_tc on $iface (root=${after:-none})"
    return 1
}

# ═══════════════════════════════════════════════════════════════
# 初始化 TC 基础结构
# ═══════════════════════════════════════════════════════════════
init_tc() {
    local iface=${1:-$(sh "$HNC_DIR/bin/device_detect.sh" iface)}

    # v3.4.1: 参数验证。空 iface 或不存在的接口直接 return，
    # 避免 watchdog 误调时把 tc 命令带空参数运行（v3.4.0 真机日志里
    # 出现过 "tc: invalid argument '1:1'" 这类错误就是这里来的）
    if [ -z "$iface" ] || ! ip link show "$iface" >/dev/null 2>&1; then
        log_error "init_tc: skipped, invalid iface='$iface'"
        return 1
    fi

    log "=== TC init: $iface ==="

    if ! tc_limit_supported_runtime; then
        log_tc_unsupported_once "init_tc" "tc_htb"
        echo "TC_INIT_MODE=unsupported"
        return 0
    fi

    disable_offload "$iface"
    if uplink_supported_runtime; then
        load_ifb || log "init_tc: IFB unavailable; continuing downlink-only"
    else
        log_uplink_unsupported_once "init_tc"
    fi

    # ── Egress HTB（下载：热点→设备）────────────────────────
    # rc3.1.32: root htb add 冷启时可能失败 (wlan2 kernel 状态切换中, kernel tc
    # offload 锁等), 20:04:04 真机日志 `init_tc: failed to add root htb on wlan2`
    # 之后 return 1 导致 ifb0 + mirred 全没跑. 学 rc3.1.29 范式: 捕获 stderr +
    # 失败重试最多 3 次 (each retry sleep 1s). 手动 20 分钟后跑同样命令能成功,
    # 印证是时序问题.
    #
    # HNC_TEST_MODE=1 时跳过重试逻辑 · mock 环境的 tc 会 echo 调用记录到 stdout
    # (非空 != 失败), 新逻辑会误判. 测试只需验证命令组合正确性, 不验证重试,
    # 走单次 add 的老路径就够了.
    #
    # v5.0 alpha.3 P1: 不再无条件 del root qdisc
    # alpha.2 真机发现: 每次 init_tc (watchdog 10s 触发 + restore_rules 触发) 都
    # `tc qdisc del root` 把 wlan2 上已有的 class 1:80 清掉, 然后 restore_rules
    # 要重建所有 class. 如果 watchdog 在 restore 之间插一脚, class 临时消失,
    # 下行限速在那个窗口里飞。
    # 改为: 先检测, 是 htb root 就保留 (下面 add 会因 File exists 失败, 走复用
    # 分支); 不是 htb (比如 noqueue, 或 pfifo) 才删重建。
    # hotfix13: only reuse HNC-compatible root qdisc (htb handle 1:).
    # Other roots such as fq/fq_codel/cake/hfsc are not compatible with HNC classes
    # under 1:, so delete/rebuild instead of falsely preserving them.
    _htb_added_by_hnc=0
    _root_htb_ok=0
    _existing_root_line=$(tc qdisc show dev "$iface" 2>/dev/null | grep " root" | head -1)
    case "$_existing_root_line" in
        *"qdisc htb 1:"*root*)
            log "init_tc: reusing existing HNC-compatible root qdisc on $iface: $_existing_root_line"
            _root_htb_ok=1
            ;;
        "")
            ;;
        *"qdisc mq "*root*)
            log "init_tc: detected mq root on $iface; preserving ROM mq root and trying child HTB fallback"
            ;;
        *)
            log "init_tc: replacing incompatible root qdisc on $iface: $_existing_root_line"
            tc qdisc del dev "$iface" root 2>/dev/null || true
            ;;
    esac
    if [ "$_root_htb_ok" = "1" ]; then
        _htb_add_ok=1
    elif [ -n "$HNC_TEST_MODE" ]; then
        # 测试路径: 单次 add, 保持旧行为方便 mock 断言
        tc qdisc add dev "$iface" root handle 1: htb default 9999 2>/dev/null \
            || { log_error "init_tc: failed to add root htb on $iface (test mode)"; return 1; }
        _htb_add_ok=1     # v5.0 alpha.2 P0-0: 测试模式下也要设, 避免后续 return 0
        _htb_added_by_hnc=1
    else
        # 生产路径: 捕获 stderr + 重试 3 次
        _htb_add_ok=0
        _htb_retry=0

        # hotfix17.3: mq root devices first get one child-leaf attempt; if that
        # is unsupported, use verified root replace fallback.
        if echo "$_existing_root_line" | grep -q "qdisc mq"; then
            if try_mq_child_htb "$iface"; then
                _htb_add_ok=1
            elif root_htb_replace_verified "$iface"; then
                _htb_add_ok=1
                _htb_added_by_hnc=1
            fi
        fi

        while [ $_htb_add_ok -ne 1 ] && [ $_htb_retry -lt 3 ]; do
            _htb_out=$(tc qdisc replace dev "$iface" root handle 1: htb default 9999 2>&1)
            if [ -z "$_htb_out" ]; then
                _htb_add_ok=1
                _htb_added_by_hnc=1
                [ $_htb_retry -gt 0 ] && log "init_tc: root htb add succeeded on retry #$_htb_retry"
                break
            fi
            # v5.0 alpha.2 P0-0: 识别 "root qdisc 已被 ROM 预装" 的情况
            # ColorOS oplus-netd 在 wlan2 预装 htb 1: root, 再 add 会失败:
            #   上游 iproute2 报: RTNETLINK answers: File exists
            #   ColorOS 定制 tc 报: tc: invalid argument 'root' to 'command'
            # 此时检查现有 root qdisc 是否为 htb, 是则复用 (HNC 的 class 1:80
            # 会挂到这个已有 htb 下, set_limit 正常工作). 不是则按原逻辑重试.
            # hotfix16.2: fixed mq root fallback. Some ColorOS builds keep qdisc mq as an immutable root.
            # Attach HNC handle 1: under mq child :1 so existing class/filter code can work.
            # hotfix17.3: do not repeatedly re-try mq child leaves inside the retry loop.
            if echo "$_htb_out" | grep -qE "File exists|invalid argument 'root'"; then
                _existing_qdisc=$(tc qdisc show dev "$iface" 2>/dev/null | \
                                   grep "^qdisc htb 1:" | grep "root" | head -1)
                if [ -n "$_existing_qdisc" ]; then
                    log "init_tc: root htb already installed by ROM on $iface, reusing: $_existing_qdisc"
                    _htb_add_ok=1
                    break
                fi
            fi
            log_error "init_tc: root htb add failed (attempt $((_htb_retry+1))/3) on $iface: $_htb_out"
            # 冷启时序问题 retry 前 del 一次 (可能上次 add 部分成功了残留).
            # hotfix17.2: do not delete mq root between retries; qdisc replace root handles it.
            if ! echo "$_existing_root_line" | grep -q "qdisc mq"; then
                tc qdisc del dev "$iface" root 2>/dev/null || true
            fi
            sleep 1
            _htb_retry=$((_htb_retry + 1))
        done

        if [ $_htb_add_ok -eq 0 ]; then
            log_error "init_tc: root htb add FAILED after 3 retries on $iface, continuing to install ingress mirred anyway (上行仍需要)"
            # v5.0 alpha.2 P0-0: 不再 return 1
            # 即使 root htb add 失败, 也要装 ingress mirred, 不然上行限速直接挂.
            # 下行 class 可能因为没有 default 9999 class 表现略异, 但 set_limit
            # 的 ensure_device_class 会建自己的 class, 影响面仅限于未限速设备.
        fi
    fi

    # v5.0 alpha.2 P0-0: 独立装 ingress mirred, 与 root htb add 结果脱钩
    if uplink_supported_runtime; then
        install_ingress_mirred "$iface"
    else
        log_uplink_unsupported_once "init_tc"
    fi

    # 以下 class / ingress qdisc / ifb 等代码只在 root htb OK 时执行
    if [ "$_htb_add_ok" != "1" ]; then
        log "init_tc: skipping class/ingress/ifb setup due to root htb failure"
        return 0
    fi

    if [ "$_htb_added_by_hnc" = "1" ]; then
        echo "$iface" > "$HNC_DIR/run/tc_root_owned_$iface" 2>/dev/null || true
    fi
    tc class add dev "$iface" parent 1:  classid 1:1    htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null
    tc class add dev "$iface" parent 1:1 classid 1:9999 htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null
    tc qdisc add dev "$iface" parent 1:9999 handle 9999: fq_codel 2>/dev/null \
        || tc qdisc add dev "$iface" parent 1:9999 handle 9999: sfq perturb 10 2>/dev/null

    if uplink_supported_runtime; then
        # hotfix13: ingress mirred is installed only through install_ingress_mirred().
        # The old inline u32/matchall block could duplicate or delete the pref-1
        # redirect installed by the netlink/shell compatibility path.
        install_ingress_mirred "$iface" || log_error "init_tc: ingress mirred ensure failed on $iface"
        # ── IFB0 Egress HTB（上传整形）──────────────────────────
        # v5.0 alpha.3 P1: 同 wlan2, 保留已有 htb qdisc, 避免清掉 class 1:XX
        _ifb_root=$(tc qdisc show dev "$IFB_IFACE" 2>/dev/null | awk '$4 == "root" {print $2; exit}')
        case "$_ifb_root" in
            htb)
                log "init_tc: preserving existing ifb0 htb root"
                ;;
            *)
                tc qdisc del dev "$IFB_IFACE" root 2>/dev/null || true
                tc qdisc add dev "$IFB_IFACE" root handle 1: htb default 9999 2>/dev/null
                ;;
        esac
        # class 1:1 / 1:9999 add 是幂等的 (已存在会 silent fail, 无害)
        tc class add dev "$IFB_IFACE" parent 1:  classid 1:1    htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null
        tc class add dev "$IFB_IFACE" parent 1:1 classid 1:9999 htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null
        tc qdisc add dev "$IFB_IFACE" parent 1:9999 handle 9999: fq_codel 2>/dev/null \
            || tc qdisc add dev "$IFB_IFACE" parent 1:9999 handle 9999: sfq perturb 10 2>/dev/null
    else
        log_uplink_unsupported_once "init_tc"
        log "init_tc: skip IFB0 root/classes because uplink is unsupported"
    fi

    log "=== TC init OK ==="
}

# ═══════════════════════════════════════════════════════════════
# 设置设备限速
# 用法: set_limit <iface> <mark_id> <down_mbps> <up_mbps> [ip]
#
# v3.3.2 重构：限速与延迟完全解耦
#   - 启用限速：ensure_device_class（首次建 class+leaf+filter）+ set_rate_only
#   - 关闭限速：只把 rate 重置为 DEFAULT_RATE，不删 class，不碰 leaf netem
#   - 结果：关限速时若该设备还有延迟，延迟保持不变
# ═══════════════════════════════════════════════════════════════
# ─── v5.1 hotfix: ifb0 root htb 自愈 ──────────────────────
ensure_ifb_root_v1() {
    if ! uplink_supported_runtime; then
        log_uplink_unsupported_once "ensure_ifb_root_v1"
        return 1
    fi
    if ! ip link show "$IFB_IFACE" >/dev/null 2>&1; then
        load_ifb || return 1
    fi
    local _root
    _root=$(tc qdisc show dev "$IFB_IFACE" 2>/dev/null | awk '$4 == "root" {print $2; exit}')
    [ "$_root" = "htb" ] && return 0
    log "ensure_ifb_root_v1: ifb0 root='$_root' rebuilding htb"
    ip link set dev "$IFB_IFACE" up 2>/dev/null || true
    tc qdisc del dev "$IFB_IFACE" root 2>/dev/null || true
    tc qdisc add dev "$IFB_IFACE" root handle 1: htb default 9999 2>/dev/null || return 1
    tc class add dev "$IFB_IFACE" parent 1:  classid 1:1    htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null || true
    tc class add dev "$IFB_IFACE" parent 1:1 classid 1:9999 htb rate "$DEFAULT_RATE" ceil "$DEFAULT_RATE" burst 200k cburst 200k 2>/dev/null || true
    tc qdisc add dev "$IFB_IFACE" parent 1:9999 handle 9999: fq_codel 2>/dev/null || tc qdisc add dev "$IFB_IFACE" parent 1:9999 handle 9999: sfq perturb 10 2>/dev/null || true
    log "ensure_ifb_root_v1: rebuilt OK"
    return 0
}

# ─── v5.1 hotfix: wlan2 ingress pref 1 mirred 自愈 ─────
ensure_ingress_mirred_v1() {
    local iface=$1
    [ -z "$iface" ] && return 1
    if ! uplink_supported_runtime; then
        log_uplink_unsupported_once "ensure_ingress_mirred_v1"
        return 0
    fi
    # hotfix13: use the unified netlink/shell fallback path.
    # Accept matchall, u32 and parent ffff: variants instead of only pref-1 matchall.
    if tc filter show dev "$iface" ingress 2>/dev/null | grep -q "mirred.*redirect dev $IFB_IFACE"; then
        return 0
    fi
    if tc filter show dev "$iface" parent ffff: 2>/dev/null | grep -q "mirred.*redirect dev $IFB_IFACE"; then
        return 0
    fi
    log "ensure_ingress_mirred_v1: mirred missing on $iface, reinstalling via unified path"
    install_ingress_mirred "$iface"
    return $?
}

set_limit() {
    local iface=$1 mark_id=$2 down_mbps=${3:-0} up_mbps=${4:-0} ip=${5:-}
    _validate_mark_id "$mark_id" || return 1
    local class_id; class_id=$(printf "%d" "$mark_id")

    log "set_limit: mark=$mark_id ip=${ip:-(none)} dn=${down_mbps}M up=${up_mbps}M qos=$(qos_mode) scale=$(qos_scale_percent)%"

    # hotfix16.9: if capability_probe proved HTB unavailable, do not try to
    # create classes/qdiscs. On MIUI14 this used to block WebUI until timeout.
    if ! tc_limit_supported_runtime; then
        if gt0 "$down_mbps" || gt0 "$up_mbps"; then
            log_tc_unsupported_once "set_limit" "tc_htb"
            echo "LIMIT_APPLY_MODE=unsupported"
            return 66
        fi
        log_tc_unsupported_once "set_limit_clear" "tc_htb"
        echo "LIMIT_APPLY_MODE=unsupported_clear_skip"
        return 0
    fi

    # ── Egress（下载：热点→设备）──────────────────────────────
    if gt0 "$down_mbps"; then
        ensure_egress_htb_ready "$iface" "set_limit" || return 1
        ensure_device_class "$iface" "$class_id" "$ip" || return 1
        local dn_effective_mbps; dn_effective_mbps=$(qos_effective_mbps_for_downlink "$down_mbps")
        local dn_rate;  dn_rate=$(mbps_to_rate "$dn_effective_mbps")
        local dn_burst; dn_burst=$(burst_for_rate "$dn_effective_mbps")
        if ! set_rate_only "$iface" "$class_id" "$dn_rate" "$dn_burst"; then
            log_error "set_limit: egress rate set failed dev=$iface class=1:$class_id; retrying after HTB self-heal"
            ensure_egress_htb_ready "$iface" "set_limit_rate_retry" && ensure_device_class "$iface" "$class_id" "$ip" && \
                set_rate_only "$iface" "$class_id" "$dn_rate" "$dn_burst" || { log_error "set_limit: egress rate set failed after retry dev=$iface class=1:$class_id"; return 1; }
        fi
        log "  Egress 1:$class_id @ $dn_rate burst $dn_burst (requested=${down_mbps}M effective=${dn_effective_mbps}M)"
    else
        # 关限速：只重置 rate，保留 leaf netem（可能承载延迟）
        if class_exists "$iface" "$class_id"; then
            set_rate_only "$iface" "$class_id" "$DEFAULT_RATE" 200k || { log_error "set_limit: egress rate clear failed dev=$iface class=1:$class_id"; return 1; }
            log "  Egress 1:$class_id rate cleared (leaf preserved)"
        fi
    fi

    # ── Ingress（上传：设备→热点，通过 ifb0）────────────────
    # hotfix5: do not make downlink-only rules depend on IFB/mirred. Some Android
    # kernels/ROM states cannot prepare IFB immediately; downlink shaping can still
    # work, so only initialise IFB when an uplink limit is requested. When up=0,
    # best-effort clear an existing ifb class if it is present, but never fail the
    # whole downlink rule just because IFB is unavailable.
    if gt0 "$up_mbps"; then
        if ! uplink_supported_runtime; then
            log_uplink_unsupported_once "set_limit"
            log "  Ingress(ifb0) skipped: uplink unsupported; keeping downlink only"
            echo "LIMIT_APPLY_MODE=down_only"
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            return 8
        fi
        if ! ensure_ifb_root_v1; then
            log_error "set_limit: ensure_ifb_root_v1 failed, keeping downlink only"
            echo "LIMIT_APPLY_MODE=down_only"
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            return 8
        fi
        if ! ensure_ingress_mirred_v1 "$iface"; then
            log_error "set_limit: ensure_ingress_mirred_v1 failed, keeping downlink only"
            echo "LIMIT_APPLY_MODE=down_only"
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            return 8
        fi
        if ! ensure_device_class "$IFB_IFACE" "$class_id" "$ip"; then
            log_error "set_limit: ensure_device_class ifb0 failed, keeping downlink only"
            echo "LIMIT_APPLY_MODE=down_only"
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            return 8
        fi
        local up_rate;  up_rate=$(mbps_to_rate "$up_mbps")
        local up_burst; up_burst=$(burst_for_rate "$up_mbps")
        if ! set_rate_only "$IFB_IFACE" "$class_id" "$up_rate" "$up_burst"; then
            log_error "set_limit: ingress rate set failed, keeping downlink only"
            echo "LIMIT_APPLY_MODE=down_only"
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            return 8
        fi
        log "  Ingress(ifb0) 1:$class_id @ $up_rate burst $up_burst"
        echo "LIMIT_APPLY_MODE=full"
    else
        if class_exists "$IFB_IFACE" "$class_id"; then
            set_rate_only "$IFB_IFACE" "$class_id" "$DEFAULT_RATE" 200k || log_error "set_limit: ingress rate clear best-effort failed dev=$IFB_IFACE class=1:$class_id"
            log "  Ingress(ifb0) 1:$class_id rate cleared best-effort (leaf preserved)"
        else
            log "  Ingress(ifb0) skipped: up=0 and no existing class 1:$class_id"
        fi
        echo "LIMIT_APPLY_MODE=full"
    fi

    # v3.4.0：触发 v6 sync，让 IPv6 流量也能被这条限速规则覆盖
    # sync_all 是幂等的，对没有变化的设备零开销
    sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 设置延迟（netem）
# 用法: set_delay <iface> <mark_id> <delay_ms> [jitter_ms] [loss%] [ip]
#
# v3.3.2 重构：
#   - 启用延迟：ensure_device_class + set_netem_only（只改 leaf netem）
#   - 关闭延迟：只重置 leaf netem 为无延迟，不动 class rate
#   - 结果：关延迟时若该设备还有限速，限速保持不变
#
# v3.8.5 RTT 语义修复：
#   v3.3.2 以来 delay_ms 被每方向(egress wlan2 + ingress ifb0)各加一次,
#   用户 ping 看到的 RTT 是设置值的 2 倍。v3.3.2 作者意图是"真实弱网模拟"
#   (双向对称延迟),但用户心智模型是"RTT 增量"(ping 看到的数字)。
#
#   v3.8.5 修复:用户输入的 delay_ms 现在是 RTT 视角。内部除以 2 分给两个
#   方向,ping RTT 就会增加 delay_ms(+基础 RTT)。
#   - 奇数处理: egress 向上取整,ingress 向下取整(101 → 51 + 50)
#   - jitter 保持每方向原值(合并后 RTT jitter ≈ √2 × 单方向,精确除法需浮点,
#     不值得)
#   - loss 保持每方向原值(端到端 loss ≈ 2p,同样不做精确除)
#   - 所以 v3.8.5 的语义:delay 是 RTT,jitter/loss 是每方向(在 WebUI 说明)
#
#   实测:设 250ms,ping RTT 从 ~500ms 降到 ~270ms(250 + ~20 base RTT)✓
# ═══════════════════════════════════════════════════════════════
set_delay() {
    local iface=$1 mark_id=$2 delay_ms=${3:-0} jitter_ms=${4:-0} loss=${5:-0} ip=${6:-}
    _validate_mark_id "$mark_id" || return 1
    local class_id; class_id=$(printf "%d" "$mark_id")

    # v3.8.5: 把 RTT delay 除以 2 分给两个方向
    # egress 向上取整,ingress 向下取整(奇数精度保留)
    local delay_eg delay_ig
    if gt0 "$delay_ms"; then
        delay_eg=$(( (delay_ms + 1) / 2 ))
        delay_ig=$(( delay_ms / 2 ))
    else
        delay_eg=0
        delay_ig=0
    fi

    log "set_delay: mark=$mark_id ip=${ip:-(none)} RTT=${delay_ms}ms (eg ${delay_eg}ms + ig ${delay_ig}ms) jitter=${jitter_ms}ms loss=${loss}%"

    # hotfix16.9: netem path requires both HTB leaf classes and sch_netem.
    # If probe says unavailable, return immediately instead of trying qdisc ops.
    if ! tc_delay_supported_runtime; then
        if gt0 "$delay_ms" || gt0 "$jitter_ms" || gt0 "$loss"; then
            log_tc_unsupported_once "set_delay" "tc_netem"
            echo "DELAY_APPLY_MODE=unsupported"
            return 66
        fi
        log_tc_unsupported_once "set_delay_clear" "tc_netem"
        echo "DELAY_APPLY_MODE=unsupported_clear_skip"
        return 0
    fi

    # v3.5.0 alpha-2:P0-3 完整修复
    # v3.4.11 只修了 set_netem_only 内部逻辑,但 set_delay 的入口判断仍然是
    # `if gt0 delay_ms`,导致 loss-only(delay=0 jitter=0 loss=5)进入 else
    # 分支被当成"关闭延迟",把 netem 重置为 0 → loss 完全丢失。
    # 修复:入口判断改为 delay/jitter/loss 任一 > 0 都进入"启用"分支
    if gt0 "$delay_ms" || gt0 "$jitter_ms" || gt0 "$loss"; then
        # 先确保下行/egress HTB 树和 class；这是 MIUI14 ifb 不可用时必须保留的最小可用路径。
        ensure_egress_htb_ready "$iface" "set_delay" || return 1
        ensure_device_class "$iface" "$class_id" "$ip" || return 1

        # IFB/uplink 是 best-effort。失败不再短路整个 delay，否则 wlan1 会停留在 0ms placeholder。
        local ifb_ok=1
        if ! uplink_supported_runtime; then
            ifb_ok=0
            log_uplink_unsupported_once "set_delay"
            log "  set_delay: uplink unsupported, skip ifb0 path"
        else
            ensure_device_class "$IFB_IFACE" "$class_id" "$ip" || ifb_ok=0
        fi

        # IFB 可用: 用户输入 delay_ms 是 RTT, 平分到两个方向。
        # IFB 不可用: 把完整 delay_ms 打到 wlan egress, 让用户体感/ping 更接近期望值。
        local eg_apply ig_apply
        if [ "$ifb_ok" = "1" ]; then
            eg_apply=$delay_eg
            ig_apply=$delay_ig
        else
            eg_apply=$delay_ms
            ig_apply=0
        fi

        if ! set_netem_only "$iface" "$class_id" "$eg_apply" "$jitter_ms" "$loss"; then
            log_error "set_delay: egress netem set failed dev=$iface class=1:$class_id; retrying after HTB self-heal"
            ensure_egress_htb_ready "$iface" "set_delay_netem_retry" && ensure_device_class "$iface" "$class_id" "$ip" && \
                set_netem_only "$iface" "$class_id" "$eg_apply" "$jitter_ms" "$loss" \
                || { log_error "set_delay: egress netem set failed after retry dev=$iface class=1:$class_id"; return 1; }
        fi

        if [ "$ifb_ok" = "1" ]; then
            set_netem_only "$IFB_IFACE" "$class_id" "$ig_apply" "$jitter_ms" "$loss" \
                || { log_error "set_delay: ingress netem set failed dev=$IFB_IFACE class=1:$class_id"; return 1; }
            echo "DELAY_APPLY_MODE=full"
            log "  Netem applied (full duplex): RTT=${delay_ms}ms (eg=${eg_apply}ms + ig=${ig_apply}ms) jitter=${jitter_ms}ms loss=${loss}%"
        else
            echo "DELAY_APPLY_MODE=egress_only"
            log "  Netem applied EGRESS-ONLY: ${eg_apply}ms on $iface (IFB unavailable, jitter=${jitter_ms}ms loss=${loss}%)"
            return 0
        fi
    else
        # 关延迟：把 leaf netem 重置为无延迟，class 及 rate 不动
        if class_exists "$iface" "$class_id"; then
            set_netem_only "$iface" "$class_id" 0 0 0 || { log_error "set_delay: egress netem clear failed dev=$iface class=1:$class_id"; return 1; }
            log "  Delay cleared on $iface 1:$class_id (class+rate preserved)"
        fi
        if class_exists "$IFB_IFACE" "$class_id"; then
            set_netem_only "$IFB_IFACE" "$class_id" 0 0 0 || { log_error "set_delay: ingress netem clear failed dev=$IFB_IFACE class=1:$class_id"; return 1; }
            log "  Delay cleared on $IFB_IFACE 1:$class_id (class+rate preserved)"
        fi
    fi
}

set_all() {
    # hotfix16.4: set_limit / set_delay may return 8 for partial success
    # (downlink/egress applied, IFB uplink unavailable). Do not abort restore/apply in that case.
    local rc_limit rc_delay partial=0
    set_limit "$1" "$2" "$3" "$4" "${8:-}"
    rc_limit=$?
    [ "$rc_limit" = "8" ] && partial=1
    [ "$rc_limit" != "0" ] && [ "$rc_limit" != "8" ] && return "$rc_limit"

    set_delay "$1" "$2" "$5" "${6:-0}" "${7:-0}" "${8:-}"
    rc_delay=$?
    [ "$rc_delay" = "8" ] && partial=1
    [ "$rc_delay" != "0" ] && [ "$rc_delay" != "8" ] && return "$rc_delay"

    [ "$partial" = "1" ] && return 8
    return 0
}

# ─── 移除设备所有规则 ────────────────────────────────────────
remove_device() {
    local iface=$1 mark_id=$2
    _validate_mark_id "$mark_id" || return 1
    local class_id; class_id=$(printf "%d" "$mark_id")
    local mark; mark=$(printf "0x%x" $((0x800000 + mark_id)))
    local prio=$((FILTER_PRIO_BASE + class_id))
    for dev in "$iface" "$IFB_IFACE"; do
        tc filter del dev "$dev" parent 1: prio "$prio"         2>/dev/null || true
        tc filter del dev "$dev" parent 1: prio "$((prio+1))"   2>/dev/null || true
        tc filter del dev "$dev" parent 1: pref "$FILTER_PRIO_FW" handle "$mark" fw 2>/dev/null || true
        tc qdisc del dev "$dev" parent "1:$class_id" 2>/dev/null || true
        tc class del dev "$dev" classid "1:$class_id" 2>/dev/null || true
    done
    log "Removed TC rules: mark_id=$mark_id"
}

# ─── 恢复持久化规则 ──────────────────────────────────────────
# rc3.1.30 Bug B 修复 · 用 MAC 查 devices.json 里当前真实 IP
# devices.json 由 hotspotd C daemon 实时维护 (netlink RTGRP_NEIGH event-driven).
# 跟 apply_device_rule.sh 的 get_ip() 同逻辑 · 挪过来避免跨脚本 source 依赖.
# 找不到时返回空字符串 (调用方需 fallback).
get_current_ip() {
    local mac=$1
    [ -f "$DEVICES_FILE" ] || { echo ""; return; }
    awk -v m="$mac" '
    {
        idx = index($0, "\"" m "\"")
        if (idx > 0) {
            tail = substr($0, idx)
            if (match(tail, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                seg = substr(tail, RSTART, RLENGTH)
                if (match(seg, /[0-9.]+/)) {
                    print substr(seg, RSTART, RLENGTH)
                    exit
                }
            }
        }
    }
    ' "$DEVICES_FILE"
}


current_iface_prefix24() {
    local iface=$1 ip
    ip=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    [ -n "$ip" ] || return 1
    echo "$ip" | awk -F. 'NF==4{print $1"."$2"."$3"."}'
}

ip_prefix24() {
    echo "$1" | awk -F. 'NF==4{print $1"."$2"."$3"."}'
}

# v3.4.1：彻底移除 python3 依赖。改用纯 awk 解析 rules.json，
# 正确处理浮点数（v3.3.6 用 grep `[0-9]*` 会把 0.8 截断为 0 这种祖传 bug
# 已经修复，但仍依赖 python3。某些精简 ROM 没有 python3，restore 直接静默
# 失败，看起来"重启后规则丢了"。现在用 awk 一遍解析整个 MAC block，
# 输出 mark_id|ip|down|up|delay|jitter 格式。）
restore_rules() {
    log "Restoring rules from $RULES_FILE"
    [ -f "$RULES_FILE" ] || return 0
    local iface; iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface)
    local cur_prefix; cur_prefix=$(current_iface_prefix24 "$iface" 2>/dev/null)
    local limit_supported=1 delay_supported=1
    tc_limit_supported_runtime || limit_supported=0
    tc_delay_supported_runtime || delay_supported=0
    [ "$limit_supported" = "0" ] && log_tc_unsupported_once "restore_rules" "tc_htb"
    [ "$delay_supported" = "0" ] && log_tc_unsupported_once "restore_rules" "tc_netem"

    # v5.0 alpha.2 hotfix2: 强制装 ingress mirred (保证重启后上行限速生效)
    # watchdog 判定 "qdisc htb 1: 已存在" (oplus 装的) 时会跳过 init_tc, 导致
    # install_ingress_mirred 从没被调用。restore_rules 开头强制调一次, 幂等,
    # 保证 HNC 的 pref 1 matchall → ifb0 就位。
    if [ -n "$iface" ] && ip link show "$iface" >/dev/null 2>&1; then
        if uplink_supported_runtime; then
            install_ingress_mirred "$iface"
        else
            log_uplink_unsupported_once "restore_rules"
        fi
    fi

    # 提取所有设备 MAC（只匹配 devices 对象里有 mark_id 的条目）
    # rc3.1.34 修 #15: 之前 `grep -oE` 全文搜会把 blacklist 数组里的 MAC 也匹进来.
    # 这些 MAC 在下面 awk 找 `"$mac": {` 模式时永远 fail, fields 空 → continue.
    # 正确性 OK 但浪费 N 次全文件 awk 扫. 现在用 awk 锁定 devices section, 只在
    # 那里抽 MAC. brace counting 跟 #11 一样识别字符串 (hostname 含 brace).
    local macs; macs=$(awk '
    BEGIN { in_devices = 0; depth = 0; in_string = 0 }
    {
        line = $0
        i = 1
        while (i <= length(line)) {
            if (!in_devices) {
                # 找 "devices": {
                rest = substr(line, i)
                if (match(rest, /"devices"[[:space:]]*:[[:space:]]*\{/)) {
                    i += RSTART + RLENGTH - 1
                    in_devices = 1
                    depth = 1
                    in_string = 0
                    continue
                }
                i++
            } else {
                c = substr(line, i, 1)
                if (in_string) {
                    if (c == "\\") {
                        i += 2
                        continue
                    } else if (c == "\"") {
                        in_string = 0
                    }
                } else {
                    if (c == "\"") {
                        # 可能是 mac key, 试着抽 17 字符 mac
                        rest = substr(line, i)
                        if (match(rest, /^"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:/)) {
                            mac = substr(rest, 2, 17)
                            print tolower(mac)
                        }
                        in_string = 1
                    } else if (c == "{") {
                        depth++
                    } else if (c == "}") {
                        depth--
                        if (depth == 0) {
                            in_devices = 0  # devices section 结束
                        }
                    }
                }
                i++
            }
        }
    }' "$RULES_FILE" | sort -u)
    local restore_fail_streak=0
    for mac in $macs; do
        # v3.4.1：纯 awk 解析。先在 rules.json 里定位 "mac": { ... } 块，
        # 然后从块里逐字段抽 mark_id/ip/down_mbps/up_mbps/delay_ms/jitter_ms。
        # 不依赖 python3，浮点数原样保留。
        # rc3.1.34 修 #11: brace counting 必须跳过 JSON 字符串内的 `{` `}`.
        # 之前 hostname 含 `{` `}` (DHCP option 12 / mDNS, 罕见但合法字符) 会
        # 让 depth 计数错位 → block 边界错 → 后续 mark_id 字段抽不到 → 设备
        # restore 失败 (限速规则丢失). 加 in_string 状态机, 见 `"` 翻转状态,
        # 字符串内的 brace 不计入 depth. 同时识别 `\"` (转义引号不结束字符串)
        # 和 `\\` (转义反斜杠).
        local fields; fields=$(awk -v mac="$mac" '
        {
            pat = "\"" mac "\"[[:space:]]*:[[:space:]]*\\{"
            if (match($0, pat)) {
                start = RSTART + RLENGTH
                depth = 1
                in_string = 0
                i = start
                while (i <= length($0) && depth > 0) {
                    c = substr($0, i, 1)
                    if (in_string) {
                        if (c == "\\") {
                            # 转义序列, 跳过下一字符 (\" \\ 都不算字符串边界)
                            i++
                        } else if (c == "\"") {
                            in_string = 0
                        }
                    } else {
                        if (c == "\"") in_string = 1
                        else if (c == "{") depth++
                        else if (c == "}") depth--
                    }
                    i++
                }
                block = substr($0, start, i - start - 1)
                mark_id = ""; ip = ""; down = "0"; up = "0"; delay = "0"; jitter = "0"; loss = "0"
                n = split(block, parts, ",")
                for (j = 1; j <= n; j++) {
                    if (match(parts[j], /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); mark_id = s
                    } else if (match(parts[j], /"ip"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s); ip = s
                    } else if (match(parts[j], /"down_mbps"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); down = s
                    } else if (match(parts[j], /"up_mbps"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); up = s
                    } else if (match(parts[j], /"delay_ms"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); delay = s
                    } else if (match(parts[j], /"jitter_ms"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); jitter = s
                    } else if (match(parts[j], /"loss_pct"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        # rc5.1.1 修 S1: restore_rules 之前忽略了 loss_pct,
                        # 导致用户设置的丢包率每次重启都被清零 (下面 set_all
                        # 调用硬编码 "0"). 现在正确解析并传递.
                        s = substr(parts[j], RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", s); loss = s
                    }
                }
                if (mark_id != "") {
                    print mark_id "|" ip "|" down "|" up "|" delay "|" jitter "|" loss
                    exit
                }
            }
        }' "$RULES_FILE")
        [ -z "$fields" ] && continue

        local mark_id; mark_id=$(echo "$fields" | cut -d'|' -f1)
        local ip;      ip=$(echo      "$fields" | cut -d'|' -f2)
        local down;    down=$(echo    "$fields" | cut -d'|' -f3)
        local up;      up=$(echo      "$fields" | cut -d'|' -f4)
        local delay;   delay=$(echo   "$fields" | cut -d'|' -f5)
        local jitter;  jitter=$(echo  "$fields" | cut -d'|' -f6)
        local loss;    loss=$(echo    "$fields" | cut -d'|' -f7)
        [ -z "$mark_id" ] && continue

        # rc3.1.30 Bug B: 优先用 devices.json 里的实时 IP.
        # 手机热点 NAT 段每次随机 (Ling 实测从 10.41.31.x 漂到 10.206.148.x 漂到
        # 10.231.141.x), rules.json 里的 IP 可能是上次会话旧值, restore 时
        # tc u32 filter 装到旧 IP 新流量不 match, 限速/延迟全失效.
        # 实时 IP 查不到 (设备还没上线) 时保留 rules.json 的 fallback.
        # rc3.1.31: 补 else 分支打 stale log, 方便真机装机后 grep "no live IP" 计数
        # 走 stale 路径的规则数量 · 配合 do_full_init 里 +15s 的 delayed restore,
        # 期望第一次 restore 有若干 stale, 第二次 restore 全部收敛 (客户端已上线).
        local live_ip; live_ip=$(get_current_ip "$mac")
        if [ -n "$live_ip" ] && [ "$live_ip" != "$ip" ]; then
            log "  IP updated from rules.json($ip) to live($live_ip) for $mac"
            ip="$live_ip"
        elif [ -z "$live_ip" ]; then
            log "  no live IP for $mac in devices.json, using stale rules.json($ip)"
            # hotfix17.3: skip TC restore for stale offline rules from an old
            # hotspot subnet. Mi 10 changes NAT segments frequently; restoring
            # old 192.168.x.y rules can hold locks and break current actions.
            if [ -n "$ip" ] && [ -n "$cur_prefix" ]; then
                stale_prefix=$(ip_prefix24 "$ip")
                if [ -n "$stale_prefix" ] && [ "$stale_prefix" != "$cur_prefix" ]; then
                    log "  restore skip stale-offline $mac: rule ip=$ip not in current hotspot prefix ${cur_prefix}x"
                    continue
                fi
            fi
        fi

        local want_limit=0 want_delay=0
        if gt0 "${down:-0}" || gt0 "${up:-0}"; then want_limit=1; fi
        if gt0 "${delay:-0}" || gt0 "${jitter:-0}" || gt0 "${loss:-0}"; then want_delay=1; fi
        if [ "$want_limit" = "1" ] && [ "$limit_supported" = "0" ]; then
            log "  restore skip limit for $mac: tc_htb=false"
            down=0; up=0; want_limit=0
        fi
        if [ "$want_delay" = "1" ] && [ "$delay_supported" = "0" ]; then
            log "  restore skip delay for $mac: tc_netem/tc_htb unsupported"
            delay=0; jitter=0; loss=0; want_delay=0
        fi
        if [ "$want_limit" = "0" ] && [ "$want_delay" = "0" ]; then
            log "  restore skip tc for $mac: all tc features unsupported or rule is zero"
            continue
        fi

        log "Restoring: $mac mark=$mark_id ip=$ip dn=${down}M up=${up}M delay=${delay}ms loss=${loss}%"
        sh "$HNC_DIR/bin/iptables_manager.sh" mark "$ip" "$mac" "$mark_id"
        if set_all "$iface" "$mark_id" "${down:-0}" "${up:-0}" "${delay:-0}" "${jitter:-0}" "${loss:-0}" "$ip"; then
            restore_fail_streak=0
        else
            restore_fail_streak=$((restore_fail_streak + 1))
            log_error "restore_rules: failed for $mac mark=$mark_id streak=$restore_fail_streak"
            if [ "$restore_fail_streak" -ge 2 ]; then
                log_error "restore_rules: abort after 2 consecutive failures to avoid holding gate_lock/UI stall"
                break
            fi
        fi
    done

    # 恢复黑名单
    # 修复:旧逐行 in_bl 循环假设 "blacklist": [...] 跨行,但 json_set.sh bl_add
    # 写出的是单行格式 `"blacklist": ["aa:...","bb:..."]`,in_bl 在同一行先被
    # 置 1 立刻又被 ']' 置 0,后面 if 分支永远进不去 → 重启后黑名单从不恢复。
    # 改成:一次性抽整段 "blacklist":[...],再从段里抽所有 MAC,不依赖行边界。
    local bl_seg
    bl_seg=$(grep -oE '"blacklist"[[:space:]]*:[[:space:]]*\[[^]]*\]' "$RULES_FILE" 2>/dev/null)
    if [ -n "$bl_seg" ]; then
        echo "$bl_seg" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | while IFS= read -r bl_mac; do
            [ -n "$bl_mac" ] && sh "$HNC_DIR/bin/iptables_manager.sh" blacklist_add "" "$bl_mac"
        done
    fi
    log "Restore complete"
}

# ─── 状态 / 清理 ─────────────────────────────────────────────
show_status() {
    local iface=${1:-$(sh "$HNC_DIR/bin/device_detect.sh" iface)}
    echo "=== Egress TC: $iface ===" && tc qdisc show dev "$iface"
    tc class show dev "$iface" && echo "--- Filters ---" && tc filter show dev "$iface"
    echo "" && echo "=== Ingress TC (ifb0) ===" && tc qdisc show dev "$IFB_IFACE"
    tc class show dev "$IFB_IFACE" && echo "--- Filters ---" && tc filter show dev "$IFB_IFACE"
    echo "" && echo "--- Redirect filter on $iface ---" && tc filter show dev "$iface" parent ffff:
}

cleanup_tc() {
    local iface=${1:-$(sh "$HNC_DIR/bin/device_detect.sh" iface)}
    # hotfix13: delete root qdisc only when this boot actually created it.
    # Avoid removing ROM/other-module qdisc roots that HNC merely reused.
    if [ -n "$iface" ] && [ -f "$HNC_DIR/run/tc_root_owned_$iface" ]; then
        tc qdisc del dev "$iface" root 2>/dev/null || true
        rm -f "$HNC_DIR/run/tc_root_owned_$iface" 2>/dev/null || true
    else
        log "cleanup_tc: preserving root qdisc on $iface (not owned by HNC)"
    fi
    tc qdisc del dev "$iface" ingress 2>/dev/null || true
    tc qdisc del dev "$iface" clsact 2>/dev/null || true
    tc qdisc del dev "$IFB_IFACE" root 2>/dev/null || true
    ip link set dev "$IFB_IFACE" down 2>/dev/null || true
    ip link del "$IFB_IFACE" 2>/dev/null || true
    log "TC cleanup done"
}

# hotfix17.7: serialize TC writers and snapshot kernel state.
# This protects set_limit/set_delay/restore/cleanup from overlapping with each other
# when WebUI, watchdog, and delayed restore fire at the same time.
TC_ACTION_LOCK="$HNC_DIR/run/tc_action.lock"
TC_ACTION_STALE_SEC=25

tc_action_lock() {
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    local now old age owner
    now=$(date +%s 2>/dev/null || echo 0)
    if mkdir "$TC_ACTION_LOCK" 2>/dev/null; then
        echo "$$ $1 $now" > "$TC_ACTION_LOCK/owner" 2>/dev/null || true
        return 0
    fi
    old=$(awk '{print $3}' "$TC_ACTION_LOCK/owner" 2>/dev/null)
    owner=$(cat "$TC_ACTION_LOCK/owner" 2>/dev/null)
    [ -n "$old" ] || old=0
    age=$((now - old))
    if [ "$age" -ge "$TC_ACTION_STALE_SEC" ] 2>/dev/null; then
        log_error "tc_action_lock: stale lock age=${age}s owner=${owner}; reclaim"
        rm -rf "$TC_ACTION_LOCK" 2>/dev/null || true
        if mkdir "$TC_ACTION_LOCK" 2>/dev/null; then
            echo "$$ $1 $now" > "$TC_ACTION_LOCK/owner" 2>/dev/null || true
            return 0
        fi
    fi
    log "tc_action_lock: busy owner=${owner} requester=$1"
    echo "TC_ACTION_BUSY=1"
    return 1
}

tc_action_unlock() {
    rm -rf "$TC_ACTION_LOCK" 2>/dev/null || true
}

tc_snapshot_async() {
    local iface="$1"
    [ -x "$HNC_DIR/bin/tc_state_snapshot.sh" ] || return 0
    ( HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/tc_state_snapshot.sh" "$iface" >/dev/null 2>&1 ) &
}


# ─── 命令分发 ────────────────────────────────────────────────
# v3.9.2 Patch 0 锁策略:
#   - 全局写(init / cleanup / restore): gate 锁
#   - 单设备写(set_limit / set_delay / set_all / remove): 【不加锁】
#     假设调用方(WebUI / httpd)已经持有同 MAC 的 iptables per-MAC 锁。
#   - 只读(status): 不加锁
. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    gate_lock()   { return 0; }
    gate_unlock() { return 0; }
}

case "$1" in
    init)
        tc_action_lock init || exit 12
        gate_lock || { tc_action_unlock; exit 11; }
        init_tc "$2"
        rc=$?
        gate_unlock
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;
    cleanup)
        tc_action_lock cleanup || exit 12
        gate_lock || { tc_action_unlock; exit 11; }
        cleanup_tc "$2"
        rc=$?
        gate_unlock
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;
    restore)
        tc_action_lock restore || exit 12
        gate_lock || { tc_action_unlock; exit 11; }
        restore_rules
        rc=$?
        gate_unlock
        tc_snapshot_async "$(cat "$HNC_DIR/run/iface.cache" 2>/dev/null | head -1)"
        tc_action_unlock
        exit $rc ;;
    ensure_ingress)
        tc_action_lock ensure_ingress || exit 12
        ensure_ingress_mirred_v1 "$2"
        rc=$?
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;

    set_limit)
        tc_action_lock set_limit || exit 12
        set_limit "$2" "$3" "$4" "$5" "$6"
        rc=$?
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;
    set_delay)
        tc_action_lock set_delay || exit 12
        set_delay "$2" "$3" "$4" "$5" "$6" "$7"
        rc=$?
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;
    set_all)
        tc_action_lock set_all || exit 12
        set_all "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
        rc=$?
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;
    remove)
        tc_action_lock remove || exit 12
        remove_device "$2" "$3"
        rc=$?
        tc_snapshot_async "$2"
        tc_action_unlock
        exit $rc ;;

    status)     show_status "$2" ;;
    snapshot)   sh "$HNC_DIR/bin/tc_state_snapshot.sh" "$2" ;;
    *)
        echo "Usage: tc_manager.sh {init|set_limit|set_delay|set_all|remove|restore|ensure_ingress|status|snapshot|cleanup}"
        echo ""
        echo "v5.1.0-rc1-hotfix17.7: TC writer serialization + state snapshot"
        echo ""
        echo "验证限速命令："
        echo "  tc qdisc show dev \$IFACE"
        echo "  tc class show dev \$IFACE"
        echo "  tc filter show dev \$IFACE ingress"
        echo "  tc filter show dev ifb0"
        echo "  tc -s class show dev ifb0      # 查看上传流量字节数"
        echo "  iptables -t mangle -L HNC_MARK -nv"
        exit 1 ;;
esac
