#!/system/bin/sh
# customize.sh — HNC 安装期脚本
#
# Magisk(v20.4+)与 KernelSU / SukiSU 安装模块时都会 source 本文件:
#   - 运行时模块文件已解压到 $MODPATH(未设 SKIPUNZIP), 默认权限已套用
#     (目录 0755 / 文件 0644) —— 所以二进制的 0755 要在这里补。
#   - 可用 ui_print / abort / set_perm / set_perm_recursive; $ARCH / $IS64BIT /
#     $API 由安装环境导出(本脚本只把 $ARCH 当 ABI 探测的兜底)。
#
# 职责: 按设备 CPU ABI 选定二进制(见 bin/hnc_arch.sh 的包布局说明):
#   arm64-v8a / armeabi-v7a → 选用匹配的二进制; 包与设备不匹配或 x86/x86_64 → abort。
# 运行期路径(bin/<name>、daemon/hnc_httpd/hnc_httpd)保持不变, service.sh /
# post-fs-data.sh 及所有调用 bin/<binary> 的脚本无需改动。

[ -n "$MODPATH" ] || MODPATH=${0%/*}

if ! command -v ui_print >/dev/null 2>&1; then
    ui_print() { echo "$*"; }
fi
if ! command -v abort >/dev/null 2>&1; then
    abort() { ui_print "$*"; exit 1; }
fi

_HNC_CVER=$(sed -n '/^version=/{s/^version=//p;q;}' "$MODPATH/module.prop" 2>/dev/null | tr -d ' \t\r\n"')
_HNC_CVC=$(sed -n '/^versionCode=/{s/^versionCode=//p;q;}' "$MODPATH/module.prop" 2>/dev/null | tr -d ' \t\r\n"')
[ -n "$_HNC_CVER" ] && ui_print "- HNC $_HNC_CVER${_HNC_CVC:+ ($_HNC_CVC)}"
unset _HNC_CVER _HNC_CVC

if [ ! -f "$MODPATH/bin/hnc_arch.sh" ]; then
    abort "! 安装包损坏: 缺少 bin/hnc_arch.sh"
fi
. "$MODPATH/bin/hnc_arch.sh"

ui_print "- HNC: 检查 CPU 架构"
if ! hnc_arch_select "$MODPATH"; then
    abort "! HNC 安装中止(CPU 架构不匹配)"
fi

# 二进制与脚本可执行位(默认权限把文件设成了 0644)
if command -v set_perm_recursive >/dev/null 2>&1; then
    set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
    [ -f "$MODPATH/daemon/hnc_httpd/hnc_httpd" ] && set_perm "$MODPATH/daemon/hnc_httpd/hnc_httpd" 0 0 0755
    set_perm "$MODPATH/service.sh" 0 0 0755
    set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
    [ -f "$MODPATH/uninstall.sh" ] && set_perm "$MODPATH/uninstall.sh" 0 0 0755
    [ -f "$MODPATH/action.sh" ] && set_perm "$MODPATH/action.sh" 0 0 0755
else
    chmod -R 755 "$MODPATH/bin" 2>/dev/null
    for _s in "$MODPATH/daemon/hnc_httpd/hnc_httpd" "$MODPATH/service.sh" \
              "$MODPATH/post-fs-data.sh" "$MODPATH/uninstall.sh" "$MODPATH/action.sh"; do
        [ -f "$_s" ] && chmod 755 "$_s" 2>/dev/null
    done
    unset _s
fi
# 数据文件不需要 +x(bin/ 下的 .o / .dex / 标记文件)
for _f in "$MODPATH/bin/hnc_clsact.o" "$MODPATH/bin/hnc_applabel.dex" "$MODPATH/bin/hnc_pkg_abi"; do
    [ -f "$_f" ] && chmod 644 "$_f" 2>/dev/null
done
unset _f

# v5.40.1: 自动退役历史改名前遗留的 /data/adb/modules/hotspot_network_control 模块目录
# (RMX5010 真机实证: 新旧两个模块 ID 并存会导致开机双份 service.sh / 双份 hnc_httpd 抢占 :8443)
_LEGACY_MOD="/data/adb/modules/hotspot_network_control"
if [ -d "$_LEGACY_MOD" ] && [ "$MODPATH" != "$_LEGACY_MOD" ]; then
    ui_print "- HNC: 检测到历史旧模块目录 hotspot_network_control，已自动标记停用并安排重启清理"
    : > "$_LEGACY_MOD/disable" 2>/dev/null || true
    : > "$_LEGACY_MOD/remove" 2>/dev/null || true
fi
unset _LEGACY_MOD
