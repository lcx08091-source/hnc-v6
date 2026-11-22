#!/system/bin/sh
# HNC 一键兼容性诊断脚本
# 用途: 在用户报告兼容性问题时, 收集所有关键信息.
# 输出: stdout (可重定向到文件)
# 使用: su -c '/data/local/hnc/bin/diag/diag.sh > /sdcard/hnc_diag.txt'
#
# 不会修改任何文件, 不会重启任何服务, 纯读取信息.
#
# 与 bin/diag.sh 的关系:
#   bin/diag.sh       —— 逐项判定型自检. 每项给 OK/WARN/FAIL, 支持 --json,
#                        退出码 0/1/2 有语义, 回答"现在健不健康".
#   bin/diag/diag.sh  —— 本脚本, 信息转储型. 不判定, 不返回错误码, 输出
#                        内核/ROM/root 框架/fork 兼容性等原始信息,
#                        回答"这台机器是什么环境", 用于汇报兼容性问题.
# 两者互补不互相替代; 报兼容性问题时建议两个都跑, 一起发给维护者.

HNC=${HNC:-/data/local/hnc}
_DIAG_ROOT=$(CDPATH='' cd -P -- "$(dirname -- "$0")/../.." 2>/dev/null && pwd -P)
MOD_VER=""
for _mp in "${_DIAG_ROOT:+$_DIAG_ROOT/module.prop}" "$HNC/module.prop" "/data/adb/modules/hotspot_net_ctl/module.prop" "/data/adb/modules/hotspot_network_control/module.prop"; do
    [ -n "$_mp" ] && [ -f "$_mp" ] || continue
    MOD_VER=$(sed -n '/^version=/{s/^version=//p;q;}' "$_mp" 2>/dev/null | tr -d ' \t\r\n"')
    [ -n "$MOD_VER" ] && break
done

echo "════════════════════════════════════════════════════════════════"
echo "  HNC Diagnostic Report (${MOD_VER:-unknown})"
echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════════════════════"
echo ""

echo "── [1] 系统信息 ────────────────────────────────────────────────"
echo "Kernel:   $(uname -r 2>/dev/null)"
echo "Build:    $(getprop ro.build.fingerprint 2>/dev/null)"
echo "ROM:      $(getprop ro.product.system.name 2>/dev/null) / $(getprop ro.build.version.release 2>/dev/null)"
echo "Device:   $(getprop ro.product.model 2>/dev/null) ($(getprop ro.product.manufacturer 2>/dev/null))"
echo "ColorOS:  $(getprop ro.build.version.oplusrom 2>/dev/null) $(getprop ro.build.version.opporom 2>/dev/null)"
echo "MIUI:     $(getprop ro.miui.ui.version.name 2>/dev/null)"
echo "OneUI:    $(getprop ro.build.version.oneui 2>/dev/null)"
echo "SELinux:  $(getenforce 2>/dev/null)"
echo ""

echo "── [2] Root 框架 ──────────────────────────────────────────────"
ksu_ver=$(getprop ro.boot.kernelsu.version 2>/dev/null)
[ -n "$ksu_ver" ] && echo "KernelSU: $ksu_ver"
[ -d /data/adb/ksu ] && echo "KSU dir:  /data/adb/ksu present"
[ -d /data/adb/magisk ] && echo "Magisk:   /data/adb/magisk present"
[ -d /data/adb/ap ] && echo "APatch:   /data/adb/ap present"
[ -f /data/adb/ksud ] && echo "ksud:     present"
which su 2>/dev/null
echo ""

echo "── [3] HNC 进程清单 ───────────────────────────────────────────"
ps -ef 2>/dev/null | grep -E "hnc_|hotspotd" | grep -v grep
echo ""

echo "── [4] 模块版本 ───────────────────────────────────────────────"
if [ -f /data/adb/modules/hotspot_net_ctl/module.prop ]; then
    cat /data/adb/modules/hotspot_net_ctl/module.prop
elif [ -f /data/adb/modules/hotspot_network_control/module.prop ]; then
    cat /data/adb/modules/hotspot_network_control/module.prop
elif [ -n "$_DIAG_ROOT" ] && [ -f "$_DIAG_ROOT/module.prop" ]; then
    cat "$_DIAG_ROOT/module.prop"
fi
echo ""

echo "── [5] HNC daemon 二进制信息 ─────────────────────────────────"
for bin in hnc_dpid hnc_httpd hnc_watchdog hnc_launcher hotspotd; do
    p="$HNC/bin/$bin"
    [ -x "$HNC/daemon/$bin/$bin" ] && p="$HNC/daemon/$bin/$bin"
    if [ -x "$p" ]; then
        size=$(wc -c < "$p" 2>/dev/null | tr -d ' ')
        _str_out=$(strings "$p" 2>/dev/null)
        ver=""
        if [ -n "$MOD_VER" ]; then
            ver=$(printf '%s\n' "$_str_out" | grep -oF "$MOD_VER" | head -1)
        fi
        if [ -z "$ver" ]; then
            ver=$(printf '%s\n' "$_str_out" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc|hotfix|hf)\.?[0-9A-Za-z._+-]+)?' | head -1)
        fi
        if [ -z "$ver" ]; then
            ver=$(printf '%s\n' "$_str_out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[-0-9A-Za-z._+]*' | grep -vE '^(0\.0\.0|127\.0\.0|255\.255\.)' | head -1)
        fi
        unset _str_out
        echo "  $bin: size=$size version=${ver:-N/A}"
    else
        echo "  $bin: MISSING"
    fi
done
echo ""

echo "── [6] fork+exec 兼容性测试 (关键) ────────────────────────────"
echo "  6. C fork+execv (fork_probe):"
if [ -x "$HNC/bin/fork_probe" ]; then
    "$HNC/bin/fork_probe" /system/bin/true 2>&1 | sed 's/^/    /'
    echo "    result: $?"
else
    echo "    fork_probe MISSING"
fi
echo ""

echo "── [7] /proc/self/status (安全机制) ──────────────────────────"
grep -E "^(Uid|Gid|Seccomp|NoNewPrivs|CapEff):" /proc/self/status 2>/dev/null
echo "SELinux context: $(cat /proc/self/attr/current 2>/dev/null | tr -d '\0\r\n')"
echo ""

echo "── [8] AVC denied (最近 dmesg) ───────────────────────────────"
_avc_hits=$(dmesg 2>/dev/null | grep -iE 'avc.*denied.*(hnc|dpid|hotspotd|launcher)' | tail -10)
if [ -n "$_avc_hits" ]; then
    printf '%s\n' "$_avc_hits"
else
    echo "  (无 hnc/dpid/hotspotd/launcher 相关 AVC denied — 这是好事)"
fi
unset _avc_hits
echo ""

echo "── [9] 热点接口状态 ───────────────────────────────────────────"
for iface in wlan2 ap0 wlan0; do
    if [ -d "/sys/class/net/$iface" ]; then
        state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
        echo "  $iface: state=$state"
        ip addr show "$iface" 2>/dev/null | grep -E "inet " | sed 's/^/    /'
    fi
done
echo ""
echo "  /proc/net/route (热点接口):"
head -1 /proc/net/route 2>/dev/null
grep -E "^(wlan|ap)" /proc/net/route 2>/dev/null
echo ""

echo "── [10] HNC capabilities.json (运行时探测结果) ─────────────"
if [ -f "$HNC/run/capabilities.json" ]; then
    cat "$HNC/run/capabilities.json"
else
    echo "  capabilities.json MISSING"
fi
echo ""

echo "── [11] HNC dpi_state.json (DPI 当前状态) ────────────────────"
DPI_STATE=""
for c in "$HNC/run/dpi_state.json" "$HNC/data/dpi_state.json"; do
    [ -f "$c" ] && { DPI_STATE="$c"; break; }
done
if [ -n "$DPI_STATE" ]; then
    echo "  path: $DPI_STATE"
    head -c 2000 "$DPI_STATE" 2>/dev/null
    echo ""
    echo "  (truncated, full file at $DPI_STATE)"
else
    echo "  dpi_state.json MISSING (run/ 与 data/ 均无 — dpid 可能未运行)"
fi
if [ -f "$HNC/run/dpid.crashflag" ]; then
    _cf_lines=$(wc -l < "$HNC/run/dpid.crashflag" 2>/dev/null | tr -d ' ')
    echo "  run/dpid.crashflag: PRESENT (lines=${_cf_lines:-0})"
    unset _cf_lines
else
    echo "  run/dpid.crashflag: absent (lines=0)"
fi
echo ""

echo "── [12] service.log 尾部 (最近 30 行) ──────────────────────"
if [ -f "$HNC/logs/service.log" ]; then
    tail -30 "$HNC/logs/service.log"
fi
echo ""

echo "── [13] dpid 日志尾部 (最近 20 行) ──────────────────────────"
DPI_LOG=""
for c in "$HNC/logs/dpid.log" "$HNC/logs/hnc_dpid.log"; do
    [ -f "$c" ] && { DPI_LOG="$c"; break; }
done
if [ -n "$DPI_LOG" ]; then
    echo "  path: $DPI_LOG"
    tail -20 "$DPI_LOG"
else
    echo "  dpid 日志 MISSING (logs/dpid.log 不存在)"
fi
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  报告生成完成"
echo "  如果你正在汇报兼容性问题, 请把这个完整输出发给项目维护者."
echo "════════════════════════════════════════════════════════════════"
