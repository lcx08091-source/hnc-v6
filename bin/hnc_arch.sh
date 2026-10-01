#!/system/bin/sh
# bin/hnc_arch.sh — v5.22 CPU ABI 选择(arm64-v8a / armeabi-v7a)
#
# 被 customize.sh(安装期, Magisk/KSU 安装环境)与 service.sh(运行期兜底)
# source; 也可直接执行: sh bin/hnc_arch.sh [device|pkg <root>|select <root>]
# (select 会就地应用覆盖层并删除覆盖层目录, 不是只读诊断)
#
# 包布局(两种都支持):
#   单 ABI 包 (CI 默认): 二进制就在原路径 bin/<name> + daemon/hnc_httpd/hnc_httpd,
#       bin/hnc_pkg_abi 写明本包 ABI(arm64-v8a / armeabi-v7a)。
#   通用包 (可选): 在上面基础上再带 bin/<abi>/<name> 覆盖层(hnc_httpd 也放在
#       bin/<abi>/hnc_httpd), 安装期按设备 ABI 把对应覆盖层拷到原路径, 然后删掉
#       所有覆盖层目录 —— 运行期路径与单 ABI 包完全一致, 其余脚本无需感知。
#
# 测试钩子: HNC_ABI_OVERRIDE(设备 ABI)、HNC_ABILIST_OVERRIDE(ABI 列表)。
# 只用 POSIX sh + toybox/busybox 常见 applet; 所有函数以 hnc_arch_ 前缀命名。

HNC_ARCH_ABIS="arm64-v8a armeabi-v7a"

_hnc_arch_say() {
    if command -v ui_print >/dev/null 2>&1; then ui_print "$*"; else echo "$*"; fi
}

# 规范化各种写法 → arm64-v8a | armeabi-v7a | x86_64 | x86 | unknown
hnc_arch_norm() {
    case "$1" in
        arm64-v8a|arm64|aarch64|armv8|armv8-a) echo arm64-v8a ;;
        armeabi-v7a|armeabi|arm|armv7|armv7l|armv7a|armv8l) echo armeabi-v7a ;;
        x86_64|x64|amd64) echo x86_64 ;;
        x86|i386|i486|i586|i686) echo x86 ;;
        *) echo unknown ;;
    esac
}

_hnc_arch_getprop() {
    command -v getprop >/dev/null 2>&1 || return 0
    getprop "$1" 2>/dev/null | tr -d '\r'
}

# 设备主 ABI。优先 ro.product.cpu.abi(用户态真实位宽; 64 位 CPU + 32 位系统的
# Android Go 机型这里是 armeabi-v7a, 而 uname -m 仍报 aarch64, 所以 uname 只做末位兜底)。
hnc_arch_device_abi() {
    local v
    if [ -n "${HNC_ABI_OVERRIDE:-}" ]; then hnc_arch_norm "$HNC_ABI_OVERRIDE"; return 0; fi
    v=$(_hnc_arch_getprop ro.product.cpu.abi)
    if [ -z "$v" ]; then
        v=$(hnc_arch_abilist | cut -d, -f1)
    fi
    # Magisk/KSU 安装环境导出的 $ARCH(arm / arm64 / x86 / x64)
    [ -z "$v" ] && v="${ARCH:-}"
    [ -z "$v" ] && v=$(uname -m 2>/dev/null)
    hnc_arch_norm "$v"
}

hnc_arch_abilist() {
    if [ -n "${HNC_ABILIST_OVERRIDE:-}" ]; then echo "$HNC_ABILIST_OVERRIDE"; return 0; fi
    _hnc_arch_getprop ro.product.cpu.abilist
}

# ELF e_machine → ABI(读文件头第 18-19 字节; 0xb7 = AArch64, 0x28 = ARM)
hnc_arch_elf_abi() {
    local m
    [ -f "$1" ] || { echo unknown; return 0; }
    command -v od >/dev/null 2>&1 || { echo unknown; return 0; }
    m=$(od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//')
    case "$m" in
        "b7 00") echo arm64-v8a ;;
        "28 00") echo armeabi-v7a ;;
        "3e 00") echo x86_64 ;;
        "03 00") echo x86 ;;
        *) echo unknown ;;
    esac
}

# 包(或运行目录)里原路径二进制的 ABI: 标记文件 > ELF 嗅探 > 历史默认 arm64-v8a
hnc_arch_pkg_abi() {
    local root="$1" v
    if [ -f "$root/bin/hnc_pkg_abi" ]; then
        v=$(head -n 1 "$root/bin/hnc_pkg_abi" 2>/dev/null | tr -d ' \r\n')
        v=$(hnc_arch_norm "$v")
        [ "$v" != unknown ] && { echo "$v"; return 0; }
    fi
    v=$(hnc_arch_elf_abi "$root/bin/hnc_dpid")
    [ "$v" = unknown ] && v=$(hnc_arch_elf_abi "$root/daemon/hnc_httpd/hnc_httpd")
    [ "$v" = unknown ] && v=arm64-v8a
    echo "$v"
}

# 把 <root>/bin/<abi>/ 覆盖层拷到原路径(hnc_httpd → daemon/hnc_httpd/hnc_httpd)。
hnc_arch_apply_overlay() {
    local root="$1" abi="$2" f n
    [ -d "$root/bin/$abi" ] || return 1
    for f in "$root/bin/$abi"/*; do
        [ -f "$f" ] || continue
        n=${f##*/}
        if [ "$n" = hnc_httpd ]; then
            mkdir -p "$root/daemon/hnc_httpd" 2>/dev/null
            rm -f "$root/daemon/hnc_httpd/hnc_httpd" 2>/dev/null
            cp -f "$f" "$root/daemon/hnc_httpd/hnc_httpd" || return 1
            chmod 755 "$root/daemon/hnc_httpd/hnc_httpd" 2>/dev/null
        else
            rm -f "$root/bin/$n" 2>/dev/null
            cp -f "$f" "$root/bin/$n" || return 1
            chmod 755 "$root/bin/$n" 2>/dev/null
        fi
    done
    echo "$abi" > "$root/bin/hnc_pkg_abi" 2>/dev/null
    return 0
}

hnc_arch_remove_overlays() {
    local a
    for a in $HNC_ARCH_ABIS; do
        [ -d "$1/bin/$a" ] && rm -rf "$1/bin/$a" 2>/dev/null
    done
    return 0
}

# 主入口: 为 <root> 选定与设备匹配的二进制。0 = 可用, 1 = 不支持/包不匹配(调用方 abort)。
hnc_arch_select() {
    local root="$1" dev pkg list
    dev=$(hnc_arch_device_abi)
    list=$(hnc_arch_abilist)
    _hnc_arch_say "- 设备 ABI: $dev${list:+ (abilist: $list)}"
    case "$dev" in
        arm64-v8a|armeabi-v7a) ;;
        *)
            _hnc_arch_say "! 不支持的 CPU 架构: $dev —— HNC 仅提供 arm64-v8a / armeabi-v7a 二进制"
            return 1 ;;
    esac
    if [ -d "$root/bin/$dev" ]; then
        if ! hnc_arch_apply_overlay "$root" "$dev"; then
            _hnc_arch_say "! 安装 $dev 二进制失败(拷贝出错)"
            return 1
        fi
        hnc_arch_remove_overlays "$root"
        _hnc_arch_say "- 已选用 $dev 二进制(通用包)"
        return 0
    fi
    hnc_arch_remove_overlays "$root"
    pkg=$(hnc_arch_pkg_abi "$root")
    if [ "$pkg" = "$dev" ]; then
        _hnc_arch_say "- 安装包 ABI: $pkg(匹配)"
        return 0
    fi
    case "$pkg" in
        arm64-v8a) _hnc_arch_say "! 这是 arm64 安装包, 但本机是 32 位系统($dev)。请改刷 HNC-*-armv7.zip" ;;
        armeabi-v7a) _hnc_arch_say "! 这是 armv7(32 位)安装包, 但本机是 $dev。请改刷 HNC-*-arm64.zip" ;;
        *) _hnc_arch_say "! 安装包 ABI($pkg)与设备($dev)不匹配" ;;
    esac
    return 1
}

# 直接执行时的诊断入口(source 时 $0 是调用者, 不触发)
case "${0##*/}" in
    hnc_arch.sh)
        case "${1:-device}" in
            device) hnc_arch_device_abi ;;
            pkg)    hnc_arch_pkg_abi "${2:-.}" ;;
            select) hnc_arch_select "${2:-.}" ;;
            *) echo "usage: sh hnc_arch.sh [device|pkg <root>|select <root>]" >&2; exit 2 ;;
        esac
        ;;
esac
