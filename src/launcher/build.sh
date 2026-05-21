#!/bin/sh
# build.sh — HNC launcher (C) 交叉编译
#
# 用 Android NDK 把 hnc_launcher.c 和 fork_probe.c 编成 arm64 二进制.
#
# 需要环境变量:
#   ANDROID_NDK_HOME  — NDK 根路径, 比如 ~/Library/Android/sdk/ndk/26.1.10909125
#                     或者 ~/Android/Sdk/ndk/26.x.x
#
# 用法:
#   sh build.sh                # 编两个二进制到当前目录
#   sh build.sh install        # 编完拷贝到 ../../bin/
#
# 验证:
#   编完后做几个 sanity check:
#     - file 输出含 "ELF 64-bit ... ARM aarch64"
#     - strings 含 "hnc_launcher" / "fork_probe" 关键字
#     - 大小: launcher ~700KB (静态), fork_probe ~7KB (动态)

set -eu

# ─── 1. NDK 检查 ──────────────────────────────────────────────────

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    # 试一下几个常见路径
    for candidate in \
        "$HOME/Library/Android/sdk/ndk"/*/ \
        "$HOME/Android/Sdk/ndk"/*/ \
        "/opt/android-ndk"*/ \
        "/usr/local/android-ndk"*/ ; do
        if [ -d "$candidate" ] && [ -d "$candidate/toolchains/llvm/prebuilt" ]; then
            ANDROID_NDK_HOME="${candidate%/}"
            break
        fi
    done
fi

if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    cat >&2 <<EOF
ERROR: ANDROID_NDK_HOME not set and auto-detect failed.

Install Android NDK r24+ (any version with API 24 sysroot works),
then set ANDROID_NDK_HOME, e.g.:

  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125

Or on macOS:
  export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/26.1.10909125
EOF
    exit 1
fi

echo "Using NDK: $ANDROID_NDK_HOME"

# ─── 2. 选 toolchain ──────────────────────────────────────────────

# 检测 host OS
HOST_TAG=""
case "$(uname -s)" in
    Linux)  HOST_TAG="linux-x86_64" ;;
    Darwin) HOST_TAG="darwin-x86_64" ;;
    *)
        echo "ERROR: unsupported host OS: $(uname -s)" >&2
        exit 1
        ;;
esac

# API level 24 = Android 7.0 = 最低支持版本 (HNC 模块自己要求 Android 11+,
# 但 NDK toolchain 用 24 兼容性最好)
API=24
CLANG="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android${API}-clang"

if [ ! -x "$CLANG" ]; then
    echo "ERROR: clang not found at $CLANG" >&2
    echo "  check NDK version (need r23+) and HOST_TAG ($HOST_TAG)" >&2
    exit 1
fi

echo "Using clang: $CLANG"
"$CLANG" --version | head -1

# ─── 3. 编译 ──────────────────────────────────────────────────────

cd "$(dirname "$0")"

COMMON_FLAGS="-O2 -Wall -Wextra -Wno-unused-parameter"

# rc30.12.28: Bionic (Android libc) 在 ARM64 要求 TLS segment 对齐至少 64 字节.
# 默认 toolchain 可能生成 8 字节对齐的 TLS, 导致 "TLS segment is underaligned" abort.
# 同时 max-page-size 在 Android 16K page 设备上也要设为 65536 才能 mmap 成功.
# 这两个 ld flag 都是 Android NDK 推荐的标准做法.
LDFLAGS_BIONIC="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"

echo ""
echo "Building fork_probe (dynamic)..."
"$CLANG" $COMMON_FLAGS $LDFLAGS_BIONIC -o fork_probe fork_probe.c
file fork_probe
ls -lh fork_probe

echo ""
echo "Building hnc_launcher (PIE, dynamic linked)..."
# rc30.12.28 三修: 之前用 -static 会因为静态链接 NDK 的 Bionic libc 时, TLS segment
# 默认 8 字节对齐, 但运行时 Bionic loader 要求 64 字节, 导致 'TLS segment is
# underaligned' abort.
#
# 真相: service.sh 是 Magisk/KSU 的 late_start service, 跑在 boot 5s 后, /system
# 早已 mount. 不需要 -static 来对抗 "post-fs-data 早期阶段 /system 未必 mount"
# 这个并不存在的问题. 改用普通 PIE (动态链接 /system/lib64/libc.so), 由 Bionic
# loader 解决 TLS 对齐, 跟 fork_probe 一样能正常跑.
#
# 副作用: launcher 大小从 ~700KB 变成 ~7KB (libc 不再嵌入). 不影响功能.
"$CLANG" $COMMON_FLAGS $LDFLAGS_BIONIC -o hnc_launcher hnc_launcher.c
file hnc_launcher
ls -lh hnc_launcher

# rc30.12.28: TLS 对齐诊断 (informational, never fails CI).
# Bionic ARM64 需要 TLS align >= 64; 默认 toolchain 出 8 字节会 abort.
# 这里只打印, 不 exit. 如果对齐错, 用户装机时 service.sh sentinel 会自动检测
# 'TLS segment is underaligned' abort 并 fallback 到 shell guard.
echo ""
echo "TLS alignment diag (informational):"
(
    set +e
    readelf -l hnc_launcher 2>/dev/null | grep -A 1 'TLS' | head -3 || true
) || true

# ─── 4. 简单 sanity check ─────────────────────────────────────────

echo ""
echo "Sanity check..."

# 验证关键字符串都在
# rc30.13.1 cleanup: 原版 sanity check 写死 "0.1.0-rc30.12" 字面字符串,
# 每次 launcher 想 bump 大版本 (比如 0.2.0) 都得改 build.sh, 是反模式.
# 改成正则前缀匹配, 接受任意 0.X.Y-rcN(.M)* 形式的版本号.
for s in "hnc_launcher" "/data/local/hnc/bin/hnc_dpid" "execv failed" "CRASH_LOOP"; do
    if ! strings hnc_launcher | grep -qF "$s"; then
        echo "  ERROR: hnc_launcher missing string: $s" >&2
        exit 1
    fi
done
# 版本字符串单独用正则匹配 (0\.[0-9]+\.[0-9]+-rc[0-9]+(\.[0-9]+)*)
if ! strings hnc_launcher | grep -qE '^0\.[0-9]+\.[0-9]+-rc[0-9]+(\.[0-9]+)*$'; then
    echo "  ERROR: hnc_launcher missing version string matching 0.X.Y-rcN(.M)*" >&2
    exit 1
fi

for s in "=== fork_probe v1 ===" "FORK FAILED" "EXECV FAILED" "RESULT: C fork+execv WORKS"; do
    if ! strings fork_probe | grep -qF "$s"; then
        echo "  ERROR: fork_probe missing string: $s" >&2
        exit 1
    fi
done

echo "  ✓ hnc_launcher: all expected strings present"
echo "  ✓ fork_probe:   all expected strings present"

# ─── 5. 可选: 拷贝到 bin/ ─────────────────────────────────────────

if [ "${1:-}" = "install" ]; then
    DEST="../../bin"
    echo ""
    echo "Installing to $DEST/..."
    cp -v hnc_launcher "$DEST/"
    cp -v fork_probe "$DEST/"
    chmod 755 "$DEST/hnc_launcher" "$DEST/fork_probe"
    echo "✓ installed to $DEST/"
fi

echo ""
echo "Done. Built artifacts:"
ls -lh hnc_launcher fork_probe
