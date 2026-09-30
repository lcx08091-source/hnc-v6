#!/system/bin/sh
# debug_bundle.sh — HNC 通用诊断包导出器
#
# v5.9.9: 补上一个一直缺失的文件 —— WebUI 设置页的「导出诊断包」按钮
# (webroot/index.html 的 data-action="debug-bundle") 从第一版起就调
# $HNC/bin/debug_bundle.sh, 但仓库里从来没有这个脚本, 用户点了必报错。
# 本脚本按该按钮的文案承诺实现: 打包配置、快照、日志尾部和网络状态,
# 并对密码/token/secret 做脱敏。
#
# 用法:
#   sh /data/local/hnc/bin/debug_bundle.sh [输出目录]
#   默认输出目录 /sdcard/Download
#
# stdout 只打印最终产物路径(WebUI 直接把它 toast 出来), 其余日志走 stderr。

set +e

HNC="${HNC:-/data/local/hnc}"
MODDIR="${MODDIR:-/data/adb/modules/hotspot_network_control}"
BIN="$HNC/bin"
RUN="$HNC/run"
DATA="$HNC/data"
LOGS="$HNC/logs"

OUT_BASE="${1:-/sdcard/Download}"
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)"
OUT="$OUT_BASE/hnc-debug-$TS"
CMD="$OUT/cmd"
mkdir -p "$OUT" "$CMD" 2>/dev/null || {
    echo "cannot create $OUT" >&2
    exit 1
}

log() { echo "$*" >&2; }

# 脱敏: 把 password/pass/secret/token/pin/psk 的值替换为 <redacted>。
# 与 daemon/hnc_httpd/action.go 的 sensitiveKeys 保持同一组 key。
redact() {
    sed -E \
        -e 's/("(password|pass|secret|token|pin|psk|hotspot_pass)"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"<redacted>"/g' \
        -e 's/((password|pass|secret|token|pin|psk)[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/gI' \
        -e 's/(X-HNC-Local-Admin:[[:space:]]*)[^[:space:]]+/\1<redacted>/g'
}

copy_redacted() {
    src="$1"; dst="$2"
    [ -f "$src" ] || return 0
    mkdir -p "$(dirname "$dst")" 2>/dev/null
    redact < "$src" > "$dst" 2>/dev/null
}

run_cmd() {
    name="$1"; shift
    { echo "# $*"; "$@" 2>&1; } | redact > "$CMD/$name.txt" 2>/dev/null
}

# ── 1. 环境摘要 ─────────────────────────────────────────────
{
    echo "HNC debug bundle"
    echo "timestamp=$TS"
    echo "HNC=$HNC"
    echo "MODDIR=$MODDIR"
    echo "id=$(id 2>/dev/null)"
    echo "uname=$(uname -a 2>/dev/null)"
    echo "android=$(getprop ro.build.version.release 2>/dev/null) sdk=$(getprop ro.build.version.sdk 2>/dev/null)"
    echo "device=$(getprop ro.product.model 2>/dev/null) / $(getprop ro.product.manufacturer 2>/dev/null)"
    [ -f "$MODDIR/module.prop" ] && grep -E '^(version|versionCode)=' "$MODDIR/module.prop" 2>/dev/null
} > "$OUT/summary.txt" 2>/dev/null

# ── 2. 配置与状态 JSON(脱敏) ───────────────────────────────
for f in rules.json devices.json device_names.json templates.json app_limits.json; do
    copy_redacted "$DATA/$f" "$OUT/data/$f"
done
# remote_tokens.json 含凭据: 只留结构不留值
if [ -f "$DATA/remote_tokens.json" ]; then
    tr ',' '\n' < "$DATA/remote_tokens.json" 2>/dev/null \
        | grep -oE '"(token_id|label|created|last_seen|revoked)"' \
        | sort -u > "$OUT/data/remote_tokens.keys.txt" 2>/dev/null
fi
for f in dpi_state.json ip_app_map.json capabilities.json tc_state.json hnc_state; do
    copy_redacted "$RUN/$f" "$OUT/run/$f"
done

# ── 3. 日志尾部(每个 400 行) ────────────────────────────────
mkdir -p "$OUT/logs" 2>/dev/null
if [ -d "$LOGS" ]; then
    for lf in "$LOGS"/*.log; do
        [ -f "$lf" ] || continue
        tail -n 400 "$lf" 2>/dev/null | redact > "$OUT/logs/$(basename "$lf")" 2>/dev/null
    done
fi

# ── 4. 网络状态 ────────────────────────────────────────────
IFACE=$(sh "$BIN/device_detect.sh" iface 2>/dev/null | tr -d ' \r\n')
[ -n "$IFACE" ] && echo "iface=$IFACE" >> "$OUT/summary.txt"

run_cmd ip_addr        ip addr
run_cmd ip_route       ip route
run_cmd ip_link        ip link
[ -n "$IFACE" ] && {
    run_cmd tc_qdisc    tc qdisc show dev "$IFACE"
    run_cmd tc_class    tc class show dev "$IFACE"
    run_cmd tc_filter   tc filter show dev "$IFACE"
    run_cmd tc_ingress  tc filter show dev "$IFACE" ingress
}
run_cmd tc_ifb0        tc qdisc show dev ifb0
run_cmd iptables_mangle iptables -t mangle -L -n -v
run_cmd ip6tables_mangle ip6tables -t mangle -L -n -v
run_cmd proc_net_arp   cat /proc/net/arp

# ── 5. 进程与自检 ──────────────────────────────────────────
run_cmd ps_hnc         sh -c "ps -A 2>/dev/null | grep -i 'hnc\|hotspotd\|dpid' | grep -v grep"
[ -x "$BIN/diag.sh" ] && run_cmd diag sh "$BIN/diag.sh"
[ -x "$BIN/rc17_process_health.sh" ] && run_cmd process_health sh "$BIN/rc17_process_health.sh"
[ -x "$BIN/check_offload.sh" ] && run_cmd check_offload sh "$BIN/check_offload.sh"
[ -x "$BIN/json_health_panel.sh" ] && run_cmd json_health sh "$BIN/json_health_panel.sh"
# v5.9.9: clsact BPF (T1) 状态也进包 —— 实验功能的排障必需
if [ -x "$BIN/hnc_clsact_ctl" ] && [ -n "$IFACE" ]; then
    run_cmd clsact_check "$BIN/hnc_clsact_ctl" check "$IFACE"
    run_cmd clsact_pin sh -c "ls -l /sys/fs/bpf/hnc/ 2>&1"
fi

# ── 6. 打包 ────────────────────────────────────────────────
ARCHIVE="$OUT.tar.gz"
if (cd "$OUT_BASE" && tar -czf "$ARCHIVE" "$(basename "$OUT")" 2>/dev/null); then
    rm -rf "$OUT" 2>/dev/null
    chmod 644 "$ARCHIVE" 2>/dev/null
    echo "$ARCHIVE"
else
    # tar 不可用(部分精简 ROM): 保留目录形式
    log "tar unavailable, keeping directory form"
    chmod -R 755 "$OUT" 2>/dev/null
    echo "$OUT"
fi
exit 0
