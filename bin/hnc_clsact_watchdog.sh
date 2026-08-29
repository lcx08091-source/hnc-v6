#!/system/bin/sh
# hnc_clsact_watchdog.sh — Ensure clsact BPF filter persists at pref 1
#
# 回移自 5.9.91 分叉并重写:
#  - 修其 repair 子命令缺失 bug(分叉的 httpd 调 "watchdog.sh repair <iface>",
#    而脚本把 $1 当接口名 → "repair" 被当成 iface 死循环空转);
#  - 不再用 /system/bin/tc 探测/安装(ColorOS 魔改 tc 会拒 ingress 关键字,
#    见 daemon/tc_netlink/README.md), 改走 hnc_clsact_ctl(netlink 直通);
#  - 去掉 set -euo pipefail(toybox sh 不支持 pipefail 的 ROM 上起不来);
#  - 受 rules.json 顶层 clsact_bpf_enabled 开关门控(默认 false), 关闭即退。
#
# 用法: hnc_clsact_watchdog.sh                (守护模式, 10s 循环)
#       hnc_clsact_watchdog.sh repair <iface> (单次修复, 供 httpd 调用)

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
LOG_FILE="$HNC_DIR/logs/clsact_watchdog.log"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [clsact-wdg] $*" >> "$LOG_FILE" 2>/dev/null; }

clsact_enabled() {
    # 与 tc_manager 的 _hnc_clsact_enabled 同语义: obj+ctl 在且开关开
    [ -f "$HNC_DIR/bin/hnc_clsact.o" ] || return 1
    [ -x "$CTL" ] || return 1
    if [ -x "$HNC_DIR/bin/hnc_json" ]; then
        v=$("$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" clsact_bpf_enabled 2>/dev/null) && [ "$v" = "true" ] && return 0
    fi
    grep -q '"clsact_bpf_enabled"[[:space:]]*:[[:space:]]*true' "$HNC_DIR/data/rules.json" 2>/dev/null
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
        clsact_enabled || { echo "clsact_bpf not enabled"; exit 0; }
        check_and_repair "${2:-$(get_hotspot_iface)}"
        exit $?
        ;;
esac

# ── 守护模式 ────────────────────────────────────────────────
log "clsact watchdog starting"
while true; do
    if ! clsact_enabled; then
        # 开关被关掉: 退出(service.sh 重新开启开关时会再拉起)
        log "clsact_bpf_enabled=false, watchdog exiting"
        exit 0
    fi
    IFACE="$(get_hotspot_iface)"
    if [ -n "$IFACE" ]; then
        check_and_repair "$IFACE"
    fi
    sleep 10
done
