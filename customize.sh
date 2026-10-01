#!/system/bin/sh
# customize.sh — HNC 安装期脚本(v5.22)
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
else
    chmod -R 755 "$MODPATH/bin" 2>/dev/null
    chmod 755 "$MODPATH/daemon/hnc_httpd/hnc_httpd" "$MODPATH/service.sh" "$MODPATH/post-fs-data.sh" 2>/dev/null
fi
# 数据文件不需要 +x(bin/ 下的 .o / .dex / 标记文件)
for _f in "$MODPATH/bin/hnc_clsact.o" "$MODPATH/bin/hnc_applabel.dex" "$MODPATH/bin/hnc_pkg_abi"; do
    [ -f "$_f" ] && chmod 644 "$_f" 2>/dev/null
done
unset _f
