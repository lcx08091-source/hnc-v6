#!/system/bin/sh
# hnc_clsact_watchdog.sh — Ensure clsact BPF filter persists at pref 1
#
# 回移自 5.9.91 分叉并重写:
#  - 修其 repair 子命令缺失 bug(分叉的 httpd 调 "watchdog.sh repair <iface>",
#    而脚本把 $1 当接口名 → "repair" 被当成 iface 死循环空转);
#  - 不再用 /system/bin/tc 探测/安装(ColorOS 魔改 tc 会拒 ingress 关键字,
#    见 daemon/tc_netlink/README.md), 改走 hnc_clsact_ctl(netlink 直通);
#  - 去掉 set -euo pipefail(toybox sh 不支持 pipefail 的 ROM 上起不来);
#  - v5.18: 门控改为 hnc_offload_guard.sh clsact_wanted(clsact_bpf_mode:
#    on / auto 且兜底已启用; pref 1 被 HNC 上行 mirred 占用时不装), 不满足即退。
#
# 用法: hnc_clsact_watchdog.sh                (守护模式, 10s 循环)
#       hnc_clsact_watchdog.sh repair <iface> (单次修复, 供 httpd 调用)

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
LOG_FILE="$HNC_DIR/logs/clsact_watchdog.log"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-wdg] $*" >> "$LOG_FILE" 2>/dev/null; }

clsact_enabled() {
    # 与 tc_manager 的 _hnc_clsact_enabled 同语义(统一闸门在 offload guard)
    [ -f "$HNC_DIR/bin/hnc_clsact.o" ] || return 1
    [ -x "$CTL" ] || return 1
    [ -f "$HNC_DIR/bin/hnc_offload_guard.sh" ] || return 1
    sh "$HNC_DIR/bin/hnc_offload_guard.sh" clsact_wanted "$1" 2>/dev/null
}

get_hotspot_iface() {
    local state_file="$HNC_DIR/run/hnc_state"
    if [ -f "$state_file" ]; then
        local state
        state=$(cat "$state_file" 2>/dev/null)
        state="${state#ACTIVE:}"
        state=$(echo "$state" | head -n1 | tr -d ' \r\n')
        [ -n "$state" ] && { echo "$state"; return; }
    fi
    if [ -f "$HNC_DIR/run/hotspot_iface" ]; then
        local h
        h=$(head -n1 "$HNC_DIR/run/hotspot_iface" 2>/dev/null | tr -d ' \r\n')
        [ -n "$h" ] && { echo "$h"; return; }
    fi
    # v5.9.91: 探测序对齐 daemon/hotspotd/upstream.c 的 wlan2→ap0→swlan0
    # (旧表缺 swlan0 多了 wlan1 —— swlan0 机型上会把 BPF filter 挂到 STA
    # 接口,clsact_check 显示正常但实际拦不到任何热点包)
    for iface in wlan2 ap0 swlan0; do
        if ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return
        fi
    done
}

check_and_repair() {
    local iface="$1"
    [ -n "$iface" ] || return 0
    [ -x "$CTL" ] || return 0

    # clsact_ctl check 输出 {"ok":...,"qdisc":...,"bpf_filter":...,"map":...}
    local out
    out=$("$CTL" check "$iface" 2>/dev/null)
    case "$out" in
        *'"ok":true'*) return 0 ;;
    esac

    log "clsact state incomplete on $iface ($out), repairing"
    if "$CTL" install "$iface" >> "$LOG_FILE" 2>&1; then
        log "clsact repaired on $iface"
        # map 内容可能因换 map 丢失, 重灌
        sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG_FILE" 2>&1 || true
    else
        log "ERROR: clsact repair failed on $iface"
    fi
}

# ── 子命令分发 ──────────────────────────────────────────────
case "${1:-}" in
    repair)
        # 供 httpd actionClsactRepair 调用: 单次修复后退出
        _ri="${2:-$(get_hotspot_iface)}"
        clsact_enabled "$_ri" || { echo "clsact_bpf not wanted (mode/pref1 mirred)"; exit 0; }
        check_and_repair "$_ri"
        exit $?
        ;;
esac

# ── 守护模式 ────────────────────────────────────────────────
log "clsact watchdog starting"
while true; do
    IFACE="$(get_hotspot_iface)"
    if ! clsact_enabled "$IFACE"; then
        # 模式不要求 / pref 1 被 mirred 占用: 退出(service.sh 在 mode=on 时会再拉起)
        log "clsact not wanted (clsact_bpf_mode / pref1 mirred), watchdog exiting"
        exit 0
    fi
    if [ -n "$IFACE" ]; then
        check_and_repair "$IFACE"
    fi
    sleep 10
done
