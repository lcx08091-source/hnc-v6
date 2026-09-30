#!/system/bin/sh
# qdisc_caps.sh — v5.20 低延迟 qdisc 兜底链(cake → fq_codel → fq → sfq → pfifo)
#
# 背景: 真机(GKI 6.6 / ColorOS)疑似没编 sch_cake / sch_fq_codel, 低延迟模式一直退 sfq。
# 很多 GKI 设备其实把这些调度器编成了 vendor 模块(.ko)只是没加载。本脚本:
#   1) 看 /proc/modules 是否已加载(仅记录; 内建模块不在 /proc/modules 里, 以 tc 探测为准)
#   2) 在一次性 dummy(建不了就 ifb, 再不行才用 lo 且只 add 不 replace)上
#      `tc qdisc replace dev <probe> root <kind>` 探测, 探完一定清理
#   3) 探测失败时尝试 `modprobe sch_xxx`(含 -d <dir>)与 `insmod <dir>/sch_xxx.ko`,
#      目录: /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules /lib/modules/$(uname -r)
#      加载成功后重新探测。只为"还没找到更好的"那几档加载模块; 已选出最优后,
#      更差的档位只做 tc 探测, 不去碰内核模块。
#   4) 按 cake → fq_codel → fq → sfq → pfifo 选第一个可用的, 写 run/qdisc_caps.json:
#      {schema, probed_at, boot_id, kernel, probe_dev, available:[..], chosen, reason,
#       aqm, default_leaf_aqm_eligible, order:[..], loaded_modules:[..],
#       tried:[{name, method, ok, err[, path]}]}
#   绝不大声失败: 任何错误只进 json/日志, 退出码恒 0。
#
# 用法:
#   qdisc_caps.sh probe [--force]  探测并写 json(模块加载每次开机只试一次; --force 强制再试)
#   qdisc_caps.sh chosen           打印已选 qdisc(无 json / 解析失败 → 空)
#   qdisc_caps.sh chain            打印低延迟叶子尝试顺序(从 chosen 起, 不含 pfifo;
#                                  chosen 未知或为 pfifo → 完整 cake fq_codel fq sfq)
#
# 测试钩子(环境变量): TC_BIN IP_BIN MODPROBE_BIN INSMOD_BIN
#   QDISC_CAPS_MODULE_DIRS QDISC_CAPS_PROC_MODULES QDISC_CAPS_BOOT_ID QDISC_CAPS_NOW

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
OUT="$RUN/qdisc_caps.json"
LOG="$HNC_DIR/logs/qdisc_caps.log"
QC_ORDER="cake fq_codel fq sfq pfifo"
QC_AQM_ORDER="cake fq_codel fq sfq"

qc_log() {
    [ -d "$HNC_DIR/logs" ] || mkdir -p "$HNC_DIR/logs" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [QDISC] $*" >> "$LOG" 2>/dev/null || true
}

qc_json_escape() {
    printf '%s' "$1" | tr -d '\r' | tr '\n\t' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-200
}

# ─── 读取(chosen / chain)──────────────────────────────────────
qc_read_chosen() {
    [ -f "$OUT" ] || return 0
    local v
    v=$(tr -d '\n' 2>/dev/null < "$OUT" | sed -n 's/.*"chosen"[[:space:]]*:[[:space:]]*"\([a-z_]*\)".*/\1/p' | head -1)
    case "$v" in
        cake|fq_codel|fq|sfq|pfifo) echo "$v" ;;
    esac
}

qc_chain() {
    local c k started=0 out=""
    c=$(qc_read_chosen)
    case "$c" in
        ''|pfifo) echo "$QC_AQM_ORDER"; return 0 ;;
    esac
    for k in $QC_AQM_ORDER; do
        [ "$k" = "$c" ] && started=1
        [ "$started" = 1 ] && out="$out $k"
    done
    echo "${out# }"
}

# ─── 探测 ─────────────────────────────────────────────────────
qc_find_tc() {
    if [ -n "$TC_BIN" ]; then echo "$TC_BIN"; return 0; fi
    local c
    for c in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v tc 2>/dev/null || echo tc
}
qc_find_ip() {
    if [ -n "$IP_BIN" ]; then echo "$IP_BIN"; return 0; fi
    local c
    for c in "$HNC_DIR/bin/hnc_ip" /system/bin/ip /vendor/bin/ip /system/xbin/ip; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v ip 2>/dev/null || echo ip
}

# 带超时执行(modprobe/insmod 在个别 ROM 上可能卡住)
qc_run_to() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 8 "$@"
    else
        "$@"
    fi
}

qc_module_for() {
    case "$1" in
        cake) echo sch_cake ;;
        fq_codel) echo sch_fq_codel ;;
        fq) echo sch_fq ;;
        sfq) echo sch_sfq ;;
        *) echo "" ;;   # pfifo = sch_fifo, 内核内建
    esac
}

qc_kind_args() {
    case "$1" in
        cake) echo "cake besteffort" ;;
        fq_codel) echo "fq_codel" ;;
        fq) echo "fq" ;;
        sfq) echo "sfq perturb 10" ;;
        pfifo) echo "pfifo" ;;
    esac
}

QC_TRIED=""
qc_tried_add() {
    # $1 name $2 method $3 ok(true/false) $4 err [$5 path]
    local item
    item="{\"name\":\"$1\",\"method\":\"$2\",\"ok\":$3,\"err\":\"$(qc_json_escape "$4")\""
    [ -n "$5" ] && item="$item,\"path\":\"$(qc_json_escape "$5")\""
    item="$item}"
    if [ -z "$QC_TRIED" ]; then QC_TRIED="$item"; else QC_TRIED="$QC_TRIED,$item"; fi
}

QC_DEV=""
QC_DEV_KIND=none
QC_DEV_CREATED=0
qc_setup_dev() {
    local short=$$
    case "$short" in ?????*) short=$(printf '%s' "$short" | tail -c 5) ;; esac
    local cand="hnc_q_${short}"
    if "$QC_IP" link add dev "$cand" type dummy >/dev/null 2>&1; then
        "$QC_IP" link set dev "$cand" up >/dev/null 2>&1 || true
        QC_DEV="$cand"; QC_DEV_KIND=dummy; QC_DEV_CREATED=1; return 0
    fi
    if "$QC_IP" link add dev "$cand" type ifb >/dev/null 2>&1; then
        "$QC_IP" link set dev "$cand" up >/dev/null 2>&1 || true
        QC_DEV="$cand"; QC_DEV_KIND=ifb; QC_DEV_CREATED=1; return 0
    fi
    # 最后手段: lo。只 add(lo 默认 noqueue, 已有自定义 root 时 add 会失败 → 记为无法探测),
    # 探完立即 del root 恢复。绝不 replace lo 的现有 qdisc。
    QC_DEV=lo; QC_DEV_KIND=lo; QC_DEV_CREATED=0
    return 0
}

qc_cleanup_dev() {
    [ -n "$QC_DEV" ] || return 0
    if [ "$QC_DEV_CREATED" = 1 ]; then
        "$QC_TC" qdisc del dev "$QC_DEV" root >/dev/null 2>&1 || true
        "$QC_IP" link del "$QC_DEV" >/dev/null 2>&1 || true
    fi
    QC_DEV=""
}

QC_ERR=""
# 探测某个 qdisc; 成功 return 0; 失败 QC_ERR=错误首行
qc_tc_probe() {
    local kind=$1 args out rc
    args=$(qc_kind_args "$kind")
    if [ "$QC_DEV_KIND" = lo ]; then
        # shellcheck disable=SC2086
        out=$("$QC_TC" qdisc add dev lo root handle 7fe1: $args 2>&1 >/dev/null); rc=$?
        [ "$rc" = 0 ] && "$QC_TC" qdisc del dev lo root >/dev/null 2>&1
    else
        # shellcheck disable=SC2086
        out=$("$QC_TC" qdisc replace dev "$QC_DEV" root $args 2>&1 >/dev/null); rc=$?
        "$QC_TC" qdisc del dev "$QC_DEV" root >/dev/null 2>&1 || true
    fi
    QC_ERR=$(printf '%s' "$out" | head -1)
    [ "$rc" = 0 ] && return 0
    [ -n "$QC_ERR" ] || QC_ERR="tc exit $rc"
    return 1
}

qc_module_dirs() {
    if [ -n "$QDISC_CAPS_MODULE_DIRS" ]; then
        echo "$QDISC_CAPS_MODULE_DIRS"
        return 0
    fi
    echo "/vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules /lib/modules/$(uname -r 2>/dev/null)"
}

QC_LOADED=""
# 尝试把 kind 对应模块载入并重探; 成功 return 0
qc_try_load() {
    local kind=$1 mod d ko out rc
    mod=$(qc_module_for "$kind")
    [ -n "$mod" ] || return 1
    local mp="${MODPROBE_BIN:-$(command -v modprobe 2>/dev/null)}"
    local im="${INSMOD_BIN:-$(command -v insmod 2>/dev/null)}"
    if [ -n "$mp" ]; then
        out=$(qc_run_to "$mp" "$mod" 2>&1); rc=$?
        if [ "$rc" = 0 ] && qc_tc_probe "$kind"; then
            qc_tried_add "$kind" modprobe true ""
            QC_LOADED="$QC_LOADED $mod"
            return 0
        fi
        [ "$rc" = 0 ] && out="modprobe ok but tc still fails: $QC_ERR"
        [ -n "$out" ] || out="exit $rc"
        qc_tried_add "$kind" modprobe false "$(printf '%s' "$out" | head -1)"
        for d in $(qc_module_dirs); do
            [ -f "$d/$mod.ko" ] || continue
            out=$(qc_run_to "$mp" -d "$d" "$mod" 2>&1); rc=$?
            if [ "$rc" = 0 ] && qc_tc_probe "$kind"; then
                qc_tried_add "$kind" modprobe_dir true "" "$d"
                QC_LOADED="$QC_LOADED $mod"
                return 0
            fi
            [ "$rc" = 0 ] && out="modprobe ok but tc still fails: $QC_ERR"
            [ -n "$out" ] || out="exit $rc"
            qc_tried_add "$kind" modprobe_dir false "$(printf '%s' "$out" | head -1)" "$d"
        done
    else
        qc_tried_add "$kind" modprobe false "modprobe not found"
    fi
    local found=0
    for d in $(qc_module_dirs); do
        ko="$d/$mod.ko"
        [ -f "$ko" ] || continue
        found=1
        if [ -z "$im" ]; then
            qc_tried_add "$kind" insmod false "insmod not found" "$ko"
            break
        fi
        out=$(qc_run_to "$im" "$ko" 2>&1); rc=$?
        if [ "$rc" = 0 ] && qc_tc_probe "$kind"; then
            qc_tried_add "$kind" insmod true "" "$ko"
            QC_LOADED="$QC_LOADED $mod"
            return 0
        fi
        [ "$rc" = 0 ] && out="insmod ok but tc still fails: $QC_ERR"
        [ -n "$out" ] || out="exit $rc"
        qc_tried_add "$kind" insmod false "$(printf '%s' "$out" | head -1)" "$ko"
    done
    [ "$found" = 0 ] && qc_tried_add "$kind" insmod false "no $mod.ko in module dirs"
    return 1
}

qc_proc_loaded() {
    local mod=$1 pm="${QDISC_CAPS_PROC_MODULES:-/proc/modules}"
    [ -n "$mod" ] || return 1
    grep -q "^$mod " "$pm" 2>/dev/null
}

qc_probe() {
    local force=${1:-} now boot prev_boot allow_load=1 kind mod chosen="" available="" reason="" skipped=""
    mkdir -p "$RUN" 2>/dev/null || true
    QC_TC=$(qc_find_tc)
    QC_IP=$(qc_find_ip)
    now=${QDISC_CAPS_NOW:-$(date +%s 2>/dev/null || echo 0)}
    boot=${QDISC_CAPS_BOOT_ID:-$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n')}
    prev_boot=$(tr -d '\n' 2>/dev/null < "$OUT" | sed -n 's/.*"boot_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    # 模块加载每次开机只试一次(watchdog 会周期重跑 capability_probe → 本脚本)。
    if [ "$force" != "--force" ] && [ -n "$boot" ] && [ "$boot" = "$prev_boot" ]; then
        allow_load=0
    fi
    # v5.20.1: capability_probe 发现本次开机 qdisc 探测超时过 → 只做 tc 探测, 不再加载模块
    local load_skip="skipped: already attempted this boot (use --force)"
    if [ -n "$QDISC_CAPS_NO_LOAD" ] && [ "$force" != "--force" ]; then
        allow_load=0
        load_skip="skipped: module loading timed out earlier this boot"
    fi

    trap 'qc_cleanup_dev' EXIT INT TERM
    qc_setup_dev

    for kind in $QC_ORDER; do
        mod=$(qc_module_for "$kind")
        if [ -n "$mod" ]; then
            if qc_proc_loaded "$mod"; then
                qc_tried_add "$kind" proc_modules true ""
            else
                qc_tried_add "$kind" proc_modules false "$mod not in /proc/modules (may be built-in)"
            fi
        fi
        if qc_tc_probe "$kind"; then
            qc_tried_add "$kind" tc_probe true ""
            available="$available $kind"
            [ -n "$chosen" ] || chosen=$kind
            continue
        fi
        qc_tried_add "$kind" tc_probe false "$QC_ERR"
        local perr="$QC_ERR"
        # 只为"还没选出"的档位加载模块
        if [ -z "$chosen" ] && [ -n "$mod" ]; then
            if [ "$allow_load" = 1 ]; then
                if qc_try_load "$kind"; then
                    available="$available $kind"
                    chosen=$kind
                    continue
                fi
            else
                qc_tried_add "$kind" module_load false "$load_skip"
            fi
        fi
        skipped="$skipped $kind($(printf '%s' "$perr" | cut -c1-60))"
    done
    qc_cleanup_dev
    trap - EXIT INT TERM

    available=${available# }
    local aqm=false eligible=false
    case "$chosen" in
        cake|fq_codel) aqm=true; eligible=true ;;
        fq|sfq) aqm=true ;;
    esac
    if [ -z "$chosen" ]; then
        reason="no qdisc passed the probe (probe_dev=$QC_DEV_KIND); callers fall back to trying the full chain"
    else
        reason="$chosen is the best available in order [$QC_ORDER]"
        [ -n "$skipped" ] && reason="$reason; unavailable:${skipped}"
    fi

    local avail_json="" k
    for k in $available; do avail_json="$avail_json\"$k\","; done
    avail_json="[${avail_json%,}]"
    local loaded_json="" m
    for m in $QC_LOADED; do loaded_json="$loaded_json\"$m\","; done
    loaded_json="[${loaded_json%,}]"
    local order_json="" o
    for o in $QC_ORDER; do order_json="$order_json\"$o\","; done
    order_json="[${order_json%,}]"

    local tmp="$OUT.tmp.$$"
    cat > "$tmp" <<EOF_QC
{
  "schema": 1,
  "probed_at": $now,
  "boot_id": "$(qc_json_escape "$boot")",
  "kernel": "$(qc_json_escape "$(uname -r 2>/dev/null)")",
  "tc_binary": "$(qc_json_escape "$QC_TC")",
  "probe_dev": "$QC_DEV_KIND",
  "module_load_attempted": $([ "$allow_load" = 1 ] && echo true || echo false),
  "order": $order_json,
  "available": $avail_json,
  "chosen": "$chosen",
  "reason": "$(qc_json_escape "$reason")",
  "aqm": $aqm,
  "default_leaf_aqm_eligible": $eligible,
  "loaded_modules": $loaded_json,
  "tried": [$QC_TRIED]
}
EOF_QC
    mv -f "$tmp" "$OUT" 2>/dev/null || { cp -f "$tmp" "$OUT" 2>/dev/null; rm -f "$tmp" 2>/dev/null; }
    chmod 644 "$OUT" 2>/dev/null || true
    qc_log "probe: dev=$QC_DEV_KIND available=[$available] chosen=${chosen:-none} loaded=[${QC_LOADED# }] load_attempted=$allow_load"
    echo "${chosen:-none}"
    return 0
}

case "${1:-probe}" in
    probe)  qc_probe "$2" ;;
    chosen) qc_read_chosen ;;
    chain)  qc_chain ;;
    *)      echo "Usage: qdisc_caps.sh {probe [--force]|chosen|chain}" ;;
esac
exit 0
