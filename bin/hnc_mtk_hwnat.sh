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

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
R=${HNC_HWNAT_ROOT:-}
STATE="$RUN/mtk_hwnat.state"
OUT="$RUN/mtk_hwnat.json"
LOG_FILE="$HNC_DIR/logs/offload_guard.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) [mtk-hwnat] $*" >> "$LOG_FILE" 2>/dev/null; }

soc() {
    if [ -f "$HNC_DIR/bin/hnc_compat.sh" ]; then
        HNC_COMPAT_LIB=1 . "$HNC_DIR/bin/hnc_compat.sh"
        hnc_soc_vendor
    else
        echo "${HNC_SOC:-unknown}"
    fi
}

# 输出检测到的路径(每行一个, 不带前缀 R)
detect_paths() {
    local p
    for p in /sys/kernel/debug/hnat /proc/hnat /sys/kernel/debug/mtk_ppe /proc/mddp /sys/kernel/mddp; do
        [ -e "$R$p" ] && echo "$p"
    done
    for p in "$R"/sys/module/*hnat* "$R"/sys/module/mtk_ppe*; do
        [ -e "$p" ] && echo "${p#$R}"
    done
    return 0
}

# 输出可写开关(不带前缀)
detect_knobs() {
    local p
    for p in /sys/kernel/debug/hnat/hook_toggle /proc/hnat/hook_toggle; do
        [ -w "$R$p" ] && echo "$p"
    done
    for p in "$R"/sys/module/*hnat*/parameters/hook_toggle "$R"/sys/module/*hnat*/parameters/hnat_enable \
             "$R"/sys/module/*hnat*/parameters/ppe_enable; do
        [ -w "$p" ] && echo "${p#$R}"
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

write_json() {  # $1 soc $2 paths $3 knobs $4 action $5 detail
    local det=false
    [ -n "$2" ] && det=true
    mkdir -p "$RUN" 2>/dev/null
    printf '{"experimental":true,"ts":%s,"soc":"%s","detected":%s,"paths":%s,"knobs":%s,"action":"%s","detail":"%s"}\n' \
        "$(date +%s 2>/dev/null || echo 0)" "$1" "$det" "$(jlist "$2")" "$(jlist "$3")" "$4" \
        "$(printf '%s' "$5" | tr -d '"\\\r\n')" > "$OUT.tmp.$$" 2>/dev/null && mv -f "$OUT.tmp.$$" "$OUT" 2>/dev/null
    echo "$4"
}

# 读开关当前值: 取首个 token 里的数字(debugfs 可能输出 "hook_toggle=1" 之类)
knob_val() { head -c 64 "$R$1" 2>/dev/null | tr -c '0-9\n' ' ' | awk '{ print $1; exit }'; }

do_disable() {
    local s paths knobs k v changed=0 failed=0
    s=$(soc)
    paths=$(detect_paths | tr '\n' ' ')
    knobs=$(detect_knobs | tr '\n' ' ')
    case "$s" in
        qcom) write_json "$s" "$paths" "" skipped_qcom "Qualcomm: 不动作(offload 走 IPA/BPF, 由 limit_map 路径处理)"; return 0 ;;
    esac
    if [ -z "$paths" ]; then
        write_json "$s" "" "" none "未检测到 MTK HWNAT/PPE"; return 0
    fi
    if [ "$s" != mtk ] && [ "$s" != unknown ]; then
        write_json "$s" "$paths" "$knobs" skipped_not_mtk "SoC=$s, 非联发科不动作"; return 0
    fi
    if [ -z "$knobs" ]; then
        write_json "$s" "$paths" "" detected_no_knob "检测到 HWNAT/PPE/MDDP 但无安全的运行期开关, 限速可能被旁路(实验性, 需真机确认)"
        return 0
    fi
    for k in $knobs; do
        v=$(knob_val "$k")
        [ "$v" = 0 ] && continue
        # 首次关闭才记原值(重复调用不能把 0 记成原值)
        grep -q "^$k=" "$STATE" 2>/dev/null || echo "$k=${v:-1}" >> "$STATE"
        if echo 0 > "$R$k" 2>/dev/null; then
            changed=1; log "disabled $k (was ${v:-?})"
        else
            failed=1; log "failed to write 0 to $k"
        fi
    done
    if [ "$failed" = 1 ] && [ "$changed" = 0 ]; then
        write_json "$s" "$paths" "$knobs" failed "写开关失败(SELinux/权限?)"
    else
        write_json "$s" "$paths" "$knobs" disabled "已关闭 HWNAT hook(实验性; 撤销兜底时恢复原值)"
    fi
    return 0
}

do_restore() {
    local s paths line k v n=0
    [ -f "$STATE" ] || { [ -f "$OUT" ] && sed -i 's/"action":"[a-z_]*"/"action":"none"/' "$OUT" 2>/dev/null; echo none; return 0; }
    while IFS= read -r line; do
        k=${line%%=*}; v=${line#*=}
        [ -n "$k" ] || continue
        case "$v" in ''|*[!0-9]*) v=1 ;; esac
        echo "$v" > "$R$k" 2>/dev/null && { n=$((n + 1)); log "restored $k=$v"; }
    done < "$STATE"
    rm -f "$STATE" 2>/dev/null
    s=$(soc)
    paths=$(detect_paths | tr '\n' ' ')
    write_json "$s" "$paths" "$(detect_knobs | tr '\n' ' ')" restored "已恢复 $n 个开关"
}

case "${1:-status}" in
    detect)
        s=$(soc); paths=$(detect_paths | tr '\n' ' ')
        write_json "$s" "$paths" "$(detect_knobs | tr '\n' ' ')" none "仅探测" >/dev/null
        cat "$OUT" 2>/dev/null ;;
    disable) do_disable ;;
    restore) do_restore ;;
    status) cat "$OUT" 2>/dev/null || echo '{}' ;;
    *) echo "usage: $0 detect|disable|restore|status" >&2; exit 2 ;;
esac
exit 0
