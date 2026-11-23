#!/system/bin/sh
# hnc_mtk_hwnat.sh — 联发科(MediaTek)硬件 NAT 加速探测与「尽力关闭」(v5.20, 实验性)
#
# 背景: MTK 平台的 HWNAT / PPE(Packet Processing Engine)在热点转发时可让流量绕过
# netfilter 与 qdisc(与 AOSP BPF tether offload 同类问题), HNC 的限速 / 封锁因此失效。
# 高通平台没有这套东西(它的 offload 走 IPA, 由 hnc_offload_guard 的 limit_map 路径
# 处理), 本脚本在高通上绝不动作。
#
# 只在 hnc_offload_guard.sh 的 on 模式(用户显式开启「强制慢路径」)下被调用;
# auto/off 模式从不调用。没探测到任何 HWNAT 痕迹 → 什么都不做。
#
# 探测路径(存在即算检测到; 以 $HNC_HWNAT_ROOT 为前缀, 测试用):
#   /sys/kernel/debug/hnat           mtk_hnat(OpenWrt/MTK SDK, debugfs; 有 hook_toggle)
#   /proc/hnat                       老 MTK SDK 的 procfs 入口
#   /sys/module/*hnat*               hnat 内核模块(mtkhnat / hw_nat / mtk_hnat …)
#   /sys/kernel/debug/mtk_ppe        主线 mtk_eth_soc PPE(debugfs)
#   /sys/module/mtk_ppe*             同上(模块)
#   /proc/mddp /sys/kernel/mddp      MTK MDDP(调制解调器直通 tether offload; 仅上报)
# 关闭动作(只对存在且可写的开关):
#   <hnat>/hook_toggle   写 0(恢复时写回原值, 原值记在 run/mtk_hwnat.state)
#   /sys/module/*hnat*/parameters/hook_toggle|hnat_enable|ppe_enable  同上
# MDDP / 主线 PPE 没有安全的运行期开关, 只上报 "detected_no_knob"。
#
# 状态文件 run/mtk_hwnat.json:
#   {"experimental":true,"ts","soc","detected":bool,"paths":[..],"knobs":[..],
#    "action":"none|disabled|restored|skipped_qcom|skipped_not_mtk|detected_no_knob|failed",
#    "detail":".."}
# 用法: hnc_mtk_hwnat.sh detect|disable|restore|status   (disable/restore 末行打印 action)

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
RUN="$HNC_DIR/run"
R=${HNC_HWNAT_ROOT:-}
STATE="$RUN/mtk_hwnat.state"
OUT="$RUN/mtk_hwnat.json"
LOG_FILE="$HNC_DIR/logs/offload_guard.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) [mtk-hwnat] $*" >> "$LOG_FILE" 2>/dev/null; }

soc() {
    if [ -n "${HNC_SOC:-}" ]; then
        echo "$HNC_SOC"
    elif [ -f "$HNC_DIR/bin/hnc_compat.sh" ]; then
        HNC_COMPAT_LIB=1 . "$HNC_DIR/bin/hnc_compat.sh"
        hnc_soc_vendor
    elif [ -f "${0%/*}/hnc_compat.sh" ]; then
        HNC_COMPAT_LIB=1 . "${0%/*}/hnc_compat.sh"
        hnc_soc_vendor
    else
        echo "unknown"
    fi
}

# 输出检测到的路径(每行一个, 不带前缀 R)
detect_paths() {
    local p
    for p in /sys/kernel/debug/hnat /proc/hnat /sys/kernel/debug/mtk_ppe \
             /proc/mddp /sys/kernel/mddp /dev/mddp \
             /proc/sys/net/nf_conntrack_hnat_offload; do
        [ -e "$R$p" ] && echo "$p"
    done
    for p in "$R"/sys/module/*hnat* "$R"/sys/module/mtk_ppe* "$R"/sys/module/*mddp*; do
        [ -e "$p" ] && echo "${p#$R}"
    done
    return 0
}

# 输出存在的候选开关(不论是否可写, 用于区分 node_missing 与 permission_denied)
detect_existing_knobs() {
    local p
    for p in /sys/kernel/debug/hnat/hook_toggle /proc/hnat/hook_toggle \
             /sys/kernel/mddp/enable /proc/mddp/enable \
             /proc/sys/net/nf_conntrack_hnat_offload; do
        [ -e "$R$p" ] && echo "$p"
    done
    for p in "$R"/sys/module/*hnat*/parameters/hook_toggle "$R"/sys/module/*hnat*/parameters/hnat_enable \
             "$R"/sys/module/*hnat*/parameters/ppe_enable; do
        [ -e "$p" ] && echo "${p#$R}"
    done
    return 0
}

# 输出可写开关(不带前缀)
detect_knobs() {
    local p
    for p in /sys/kernel/debug/hnat/hook_toggle /proc/hnat/hook_toggle \
             /sys/kernel/mddp/enable /proc/mddp/enable \
             /proc/sys/net/nf_conntrack_hnat_offload; do
        [ -e "$R$p" ] && [ -w "$R$p" ] && echo "$p"
    done
    for p in "$R"/sys/module/*hnat*/parameters/hook_toggle "$R"/sys/module/*hnat*/parameters/hnat_enable \
             "$R"/sys/module/*hnat*/parameters/ppe_enable; do
        [ -e "$p" ] && [ -w "$p" ] && echo "${p#$R}"
    done
    return 0
}

jlist() {
    local x out="" first=1
    for x in $1; do
        [ $first -eq 1 ] || out="$out,"
        out="$out\"$x\""; first=0
    done
    echo "[$out]"
}

write_json() {  # $1 soc $2 paths $3 knobs $4 action $5 reason_code $6 detail
    local det=false _tmp
    [ -n "$2" ] && det=true
    mkdir -p "$RUN" 2>/dev/null || true
    _tmp="$OUT.tmp.$$"
    if printf '{"experimental":true,"ts":%s,"soc":"%s","detected":%s,"paths":%s,"knobs":%s,"action":"%s","state":"%s","reason_code":"%s","detail":"%s"}\n' \
        "$(date +%s 2>/dev/null || echo 0)" "$1" "$det" "$(jlist "$2")" "$(jlist "$3")" "$4" "$4" "$5" \
        "$(printf '%s' "$6" | tr -d '"\\\r\n')" > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
        mv -f "$_tmp" "$OUT" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
    else
        rm -f "$_tmp" 2>/dev/null || true
    fi
    echo "$4"
}

# 读开关当前值: 取首个 token 里的数字(debugfs 可能输出 "hook_toggle=1" 之类)
knob_val() {
    [ -e "$R$1" ] && [ -r "$R$1" ] || return 1
    head -c 64 "$R$1" 2>/dev/null | tr -c '0-9\n' ' ' | awk '{ print $1; exit }'
}

do_disable() {
    local s paths knobs exist_knobs k v changed=0 failed=0 missing_err=0 perm_err=0 _stmp
    s=$(soc)
    paths=$(detect_paths | tr '\n' ' ')
    exist_knobs=$(detect_existing_knobs | tr '\n' ' ')
    knobs=$(detect_knobs | tr '\n' ' ')
    case "$s" in
        qcom) write_json "$s" "$paths" "" skipped_qcom unsupported_soc "Qualcomm: 不动作(offload 走 IPA/BPF, 由 limit_map 路径处理)"; return 0 ;;
    esac
    if [ -z "$paths" ]; then
        if [ -d "$R/sys/kernel/debug" ] && [ ! -x "$R/sys/kernel/debug" ]; then
            write_json "$s" "" "" none permission_denied "debugfs 无访问权限, 未能读取 MTK HWNAT/PPE 节点"
        else
            write_json "$s" "" "" none node_missing "未检测到 MTK HWNAT/PPE"
        fi
        return 0
    fi
    if [ "$s" != mtk ] && [ "$s" != unknown ]; then
        write_json "$s" "$paths" "$knobs" skipped_not_mtk unsupported_soc "SoC=$s, 非联发科不动作"; return 0
    fi
    if [ -z "$knobs" ]; then
        if [ -n "$exist_knobs" ]; then
            write_json "$s" "$paths" "" detected_no_knob permission_denied "检测到 HWNAT/PPE/MDDP 开关节点但只读或无写权限"
        else
            write_json "$s" "$paths" "" detected_no_knob node_missing "检测到 HWNAT/PPE/MDDP 但无安全的运行期开关, 限速可能被旁路(实验性, 需真机确认)"
        fi
        return 0
    fi
    mkdir -p "$RUN" 2>/dev/null || true
    for k in $knobs; do
        if [ ! -e "$R$k" ]; then
            missing_err=1
            failed=1
            log "knob missing before write: $k"
            continue
        fi
        v=$(knob_val "$k") || v=""
        [ "$v" = 0 ] && continue
        # 首次关闭才记原值(重复调用不能把 0 记成原值)
        if ! grep -q "^$k=" "$STATE" 2>/dev/null; then
            _stmp="$STATE.tmp.$$"
            { [ -f "$STATE" ] && cat "$STATE" 2>/dev/null; printf '%s=%s\n' "$k" "${v:-1}"; } > "$_stmp" 2>/dev/null \
                && [ -s "$_stmp" ] && mv -f "$_stmp" "$STATE" 2>/dev/null \
                || { rm -f "$_stmp" 2>/dev/null; printf '%s=%s\n' "$k" "${v:-1}" >> "$STATE" 2>/dev/null || true; }
        fi
        if ( printf '0\n' > "$R$k" ) 2>/dev/null; then
            changed=1; log "disabled $k (was ${v:-?})"
        else
            perm_err=1
            failed=1; log "failed to write 0 to $k (EACCES/EPERM/EROFS)"
        fi
    done
    if [ "$failed" = 1 ] && [ "$changed" = 0 ]; then
        if [ "$perm_err" = 0 ] && [ "$missing_err" = 1 ]; then
            write_json "$s" "$paths" "$knobs" failed node_missing "开关节点在写入前消失(ENOENT)"
        else
            write_json "$s" "$paths" "$knobs" failed permission_denied "写开关失败(SELinux/只读/权限不足)"
        fi
    else
        write_json "$s" "$paths" "$knobs" disabled ok "已关闭 HWNAT hook(实验性; 撤销兜底时恢复原值)"
    fi
    return 0
}

do_restore() {
    local s paths knobs line k v n=0 missing_err=0 perm_err=0 _rtmp
    if [ ! -f "$STATE" ]; then
        if [ -f "$OUT" ]; then
            _rtmp="$OUT.tmp.$$"
            if sed -e 's/"action":"[a-z_]*"/"action":"none"/' \
                   -e 's/"state":"[a-z_]*"/"state":"none"/' "$OUT" > "$_rtmp" 2>/dev/null && [ -s "$_rtmp" ]; then
                mv -f "$_rtmp" "$OUT" 2>/dev/null || rm -f "$_rtmp" 2>/dev/null || true
            else
                rm -f "$_rtmp" 2>/dev/null || true
            fi
        fi
        echo none
        return 0
    fi
    while IFS= read -r line; do
        k=${line%%=*}; v=${line#*=}
        [ -n "$k" ] || continue
        case "$v" in ''|*[!0-9]*) v=1 ;; esac
        if [ ! -e "$R$k" ]; then
            missing_err=1
            log "skip restore missing knob $k"
            continue
        fi
        if ( printf '%s\n' "$v" > "$R$k" ) 2>/dev/null; then
            n=$((n + 1)); log "restored $k=$v"
        else
            perm_err=1
            log "failed to restore $k=$v (permission denied)"
        fi
    done < "$STATE"
    rm -f "$STATE" 2>/dev/null || true
    s=$(soc)
    paths=$(detect_paths | tr '\n' ' ')
    knobs=$(detect_knobs | tr '\n' ' ')
    if [ "$n" -eq 0 ] && [ "$perm_err" = 1 ]; then
        write_json "$s" "$paths" "$knobs" restored permission_denied "尝试恢复但无写权限"
    elif [ "$n" -eq 0 ] && [ "$missing_err" = 1 ]; then
        write_json "$s" "$paths" "$knobs" restored node_missing "原开关节点已不存在, 已清理状态"
    else
        write_json "$s" "$paths" "$knobs" restored ok "已恢复 $n 个开关"
    fi
    return 0
}

case "${1:-status}" in
    detect)
        s=$(soc)
        paths=$(detect_paths | tr '\n' ' ')
        exist_knobs=$(detect_existing_knobs | tr '\n' ' ')
        knobs=$(detect_knobs | tr '\n' ' ')
        _rc_det="ok"
        if [ "$s" = "qcom" ] || { [ "$s" != "mtk" ] && [ "$s" != "unknown" ]; }; then
            _rc_det="unsupported_soc"
        elif [ -z "$paths" ]; then
            if [ -d "$R/sys/kernel/debug" ] && [ ! -x "$R/sys/kernel/debug" ]; then
                _rc_det="permission_denied"
            else
                _rc_det="node_missing"
            fi
        elif [ -z "$knobs" ]; then
            if [ -n "$exist_knobs" ]; then
                _rc_det="permission_denied"
            else
                _rc_det="node_missing"
            fi
        fi
        write_json "$s" "$paths" "$knobs" none "$_rc_det" "仅探测" >/dev/null
        cat "$OUT" 2>/dev/null ;;
    disable) do_disable ;;
    restore) do_restore ;;
    status)
        if [ -r "$OUT" ] && [ -s "$OUT" ]; then
            cat "$OUT" 2>/dev/null
        else
            printf '{"experimental":true,"detected":false,"action":"none","state":"none","reason_code":"node_missing"}\n'
        fi ;;
    *) echo "usage: $0 detect|disable|restore|status" >&2; exit 2 ;;
esac
exit 0
