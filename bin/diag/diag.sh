#!/system/bin/sh
# HNC rc30.12 一键诊断脚本
# 用途: 在用户报告兼容性问题时, 收集所有关键信息.
# 输出: stdout (可重定向到文件)
# 使用: su -c '/data/local/hnc/bin/diag/diag.sh > /sdcard/hnc_diag.txt'
#
# 不会修改任何文件, 不会重启任何服务, 纯读取信息.

HNC=${HNC:-/data/local/hnc}
DIAG_BIN="$HNC/bin/diag"

echo "════════════════════════════════════════════════════════════════"
echo "  HNC Diagnostic Report"
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
if [ -f /data/adb/modules/hotspot_network_control/module.prop ]; then
    cat /data/adb/modules/hotspot_network_control/module.prop
fi
echo ""

echo "── [5] HNC daemon 二进制信息 ─────────────────────────────────"
for bin in hnc_dpid hnc_httpd hnc_watchdog hnc_launcher hotspotd; do
    p="$HNC/bin/$bin"
    [ -x "$HNC/daemon/$bin/$bin" ] && p="$HNC/daemon/$bin/$bin"
    if [ -x "$p" ]; then
        size=$(wc -c < "$p" 2>/dev/null)
        ver=$(strings "$p" 2>/dev/null | grep -oE "rc30\.[0-9.]+[-a-z]*" | head -1)
        echo "  $bin: size=$size version=${ver:-N/A}"
    else
        echo "  $bin: MISSING"
    fi
done
echo ""

echo "── [6] fork+exec 兼容性测试 (关键) ────────────────────────────"
echo "  6a. C fork+execv (fork_probe):"
if [ -x "$DIAG_BIN/fork_probe" ]; then
    "$DIAG_BIN/fork_probe" /system/bin/true 2>&1 | sed 's/^/    /'
    echo "    result: $?"
elif [ -x "$HNC/bin/fork_probe" ]; then
    "$HNC/bin/fork_probe" /system/bin/true 2>&1 | sed 's/^/    /'
    echo "    result: $?"
else
    echo "    fork_probe MISSING"
fi
echo ""

echo "  6b. Go fork+exec (gofork_probe):"
if [ -x "$DIAG_BIN/gofork_probe" ]; then
    "$DIAG_BIN/gofork_probe" 2>&1 | sed 's/^/    /'
    echo "    result: $?"
else
    echo "    gofork_probe not compiled (optional, see bin/diag/gofork_probe.go)"
fi
echo ""

echo "── [7] /proc/self/status (安全机制) ──────────────────────────"
grep -E "^(Uid|Gid|Seccomp|NoNewPrivs|CapEff):" /proc/self/status 2>/dev/null
echo "SELinux context: $(cat /proc/self/attr/current 2>/dev/null | tr -d '\0\r\n')"
echo ""

echo "── [8] AVC denied (最近 dmesg) ───────────────────────────────"
dmesg 2>/dev/null | grep -iE "avc.*denied" | tail -10
[ $? -ne 0 ] || echo "  (无 hnc/dpid/hotspotd/launcher 相关 AVC denied — 这是好事)"
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
if [ -f "$HNC/data/dpi_state.json" ]; then
    # 不 dump 全部 (太大), 只关键字段
    head -c 2000 "$HNC/data/dpi_state.json" 2>/dev/null
    echo ""
    echo "  (truncated, full file at $HNC/data/dpi_state.json)"
else
    echo "  dpi_state.json MISSING"
fi
echo ""

echo "── [12] service.log 尾部 (最近 30 行) ──────────────────────"
if [ -f "$HNC/logs/service.log" ]; then
    tail -30 "$HNC/logs/service.log"
fi
echo ""

echo "── [13] dpid 日志尾部 (最近 20 行) ──────────────────────────"
if [ -f "$HNC/logs/hnc_dpid.log" ]; then
    tail -20 "$HNC/logs/hnc_dpid.log"
fi
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  报告生成完成"
echo "  如果你正在汇报兼容性问题, 请把这个完整输出发给项目维护者."
echo "════════════════════════════════════════════════════════════════"
