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
echo "Building hnc_launcher (static)..."
# -static: 不依赖运行时 /system/lib64 (post-fs-data 早期可能未 mount)
# rc30.12.28: -static-pie 比纯 -static 更兼容 Bionic, 同时保留 ASLR.
"$CLANG" $COMMON_FLAGS $LDFLAGS_BIONIC -static -o hnc_launcher hnc_launcher.c
file hnc_launcher
ls -lh hnc_launcher

# rc30.12.28: 检查 TLS 对齐. readelf 看 .tbss / .tdata segment 的 align,
# 如果 < 64 就警告 (Bionic 会 abort).
echo ""
echo "Checking TLS alignment (must be >= 64 on Bionic ARM64)..."
TLS_ALIGN=$(readelf -l hnc_launcher 2>/dev/null | grep -A1 'TLS' | grep -oE 'Align: 0x[0-9a-f]+' | head -1 | grep -oE '0x[0-9a-f]+')
if [ -n "$TLS_ALIGN" ]; then
    TLS_ALIGN_DEC=$(printf "%d" "$TLS_ALIGN" 2>/dev/null)
    if [ "$TLS_ALIGN_DEC" -lt 64 ]; then
        echo "  ⚠ WARN: TLS alignment = $TLS_ALIGN ($TLS_ALIGN_DEC bytes), need >= 64 for Bionic"
        echo "    hnc_launcher will Abort with 'TLS segment is underaligned' on Android"
        echo "    NDK version: $("$CLANG" --version | head -1)"
        echo "    Try: NDK r25+ or add -Wl,--no-tls-align-relax"
    else
        echo "  ✓ TLS alignment = $TLS_ALIGN ($TLS_ALIGN_DEC bytes), Bionic-safe"
    fi
fi

# ─── 4. 简单 sanity check ─────────────────────────────────────────

echo ""
echo "Sanity check..."

# 验证关键字符串都在
for s in "hnc_launcher" "0.1.0-rc30.12" "/data/local/hnc/bin/hnc_dpid" "execv failed" "CRASH_LOOP"; do
    if ! strings hnc_launcher | grep -qF "$s"; then
        echo "  ERROR: hnc_launcher missing string: $s" >&2
        exit 1
    fi
done

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
