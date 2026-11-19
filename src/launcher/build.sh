#!/bin/sh
# build.sh — HNC launcher (C) 交叉编译
#
# 用 Android NDK 把 hnc_launcher.c 和 fork_probe.c 编成 arm64 / arm 二进制.
#
# 需要环境变量:
#   ANDROID_NDK_HOME  — NDK 根路径, 比如 ~/Library/Android/sdk/ndk/30.0.16248370
#                     或者 ~/Android/Sdk/ndk/30.x.x
#
# 用法:
#   sh build.sh                # 编两个 arm64 二进制到当前目录
#   sh build.sh arm64          # 编两个 arm64 二进制到当前目录
#   sh build.sh arm            # 编两个 armeabi-v7a 二进制到 out/arm/
#   sh build.sh install        # 编 arm64 并拷贝到 ../../bin/
#   sh build.sh install arm    # v5.22: 编 armeabi-v7a, 拷到 ../../bin/armeabi-v7a/
#                              # (第二个参数 = arch: arm64 默认 | arm)
#   sh build.sh host           # Host 本地 C11 预检编译
#
# 验证:
#   编完后做几个 sanity check:
#     - file 输出含 "ELF 64-bit ... ARM aarch64" (或 32-bit ARM)
#     - strings 含 "hnc_launcher" / "fork_probe" 关键字

set -eu

# ─── 0. 命令行参数解析与校验 ─────────────────────────────────────
DO_INSTALL=0
ARCH="arm64"

case "${1:-}" in
    "")
        ;;
    host)
        if [ $# -gt 1 ]; then
            echo "ERROR: unexpected extra argument after 'host': $2" >&2
            exit 1
        fi
        cd "$(dirname "$0")"
        CC="${CC:-gcc}"
        OUT="${HNC_HOST_OUT:-out/host}"
        mkdir -p "$OUT"
        HFLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Werror -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -fPIE"
        $CC $HFLAGS -o "$OUT/fork_probe" fork_probe.c -pie
        $CC $HFLAGS -o "$OUT/hnc_launcher" hnc_launcher.c -pie
        echo "Host build OK: $OUT/hnc_launcher $OUT/fork_probe"
        exit 0
        ;;
    install)
        if [ $# -gt 2 ]; then
            echo "ERROR: too many arguments (usage: $0 [install [arm64|arm] | arm64 | arm | host])" >&2
            exit 1
        fi
        DO_INSTALL=1
        ARCH="${2:-arm64}"
        ;;
    arm64|arm)
        if [ $# -gt 1 ]; then
            echo "ERROR: unexpected extra argument after '$1': $2" >&2
            exit 1
        fi
        ARCH="$1"
        ;;
    *)
        echo "ERROR: unknown argument '$1' (expected: install | host | arm64 | arm)" >&2
        exit 1
        ;;
esac

case "$ARCH" in
    arm64|arm) ;;
    *)
        echo "ERROR: unsupported arch: $ARCH (arm64|arm)" >&2
        exit 1
        ;;
esac

# ─── 1. NDK 检查 ──────────────────────────────────────────────────
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK:-}" ]; then
    ANDROID_NDK_HOME="$ANDROID_NDK"
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK_ROOT:-}" ]; then
    ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
fi

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

Install Android NDK r28+ (with API 28 sysroot),
then set ANDROID_NDK_HOME, e.g.:

  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/30.0.16248370

Or on macOS:
  export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/30.0.16248370
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

# v5.40.0 T1: 统一升级至 NDK r30 LTS / API 28 (Android 9.0+; HNC 模块本身要求 Android 11+)
API=28
case "$ARCH" in
    arm64) TRIPLE=aarch64-linux-android ;;
    arm)   TRIPLE=armv7a-linux-androideabi ;;
    *) echo "ERROR: unsupported arch: $ARCH (arm64|arm)" >&2; exit 1 ;;
esac
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
CLANG="$TOOLCHAIN/bin/${TRIPLE}${API}-clang"
STRIP="$TOOLCHAIN/bin/llvm-strip"

if [ ! -x "$CLANG" ]; then
    echo "ERROR: clang not found at $CLANG" >&2
    echo "  check NDK version (need API 28+) and HOST_TAG ($HOST_TAG)" >&2
    exit 1
fi

echo "Using clang: $CLANG"
"$CLANG" --version | head -1

# ─── 3. 编译 ──────────────────────────────────────────────────────

cd "$(dirname "$0")"

# v5.22: arm64 产物仍落在本目录(原行为, 这两个文件被 git 跟踪);
# 其他 arch 落到 out/<arch>/(gitignore), 不覆盖 arm64 的跟踪副本。
OUT="."
if [ "$ARCH" != "arm64" ]; then
    OUT="out/$ARCH"
    mkdir -p "$OUT"
fi

COMMON_FLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Wno-unused-parameter -D_GNU_SOURCE -DANDROID -D_FILE_OFFSET_BITS=64 -fPIE"

# rc30.12.28: Bionic (Android libc) 在 ARM64 要求 TLS segment 对齐至少 64 字节.
# 同时 max-page-size 在 Android 16K page 设备上设为 16384 以保证 ELF LOAD 段对齐.
# 仅在链接参数 LDFLAGS 中传递.
LDFLAGS_BIONIC="-pie -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"

echo ""
echo "Building fork_probe (dynamic)..."
"$CLANG" $COMMON_FLAGS -o "$OUT/fork_probe" fork_probe.c $LDFLAGS_BIONIC
[ -x "$STRIP" ] && "$STRIP" "$OUT/fork_probe"
file "$OUT/fork_probe"
ls -lh "$OUT/fork_probe"

echo ""
echo "Building hnc_launcher (PIE, dynamic linked)..."
"$CLANG" $COMMON_FLAGS -o "$OUT/hnc_launcher" hnc_launcher.c $LDFLAGS_BIONIC
[ -x "$STRIP" ] && "$STRIP" "$OUT/hnc_launcher"
file "$OUT/hnc_launcher"
ls -lh "$OUT/hnc_launcher"

# rc30.12.28: TLS 对齐诊断 (informational, never fails CI).
echo ""
echo "TLS alignment diag (informational):"
(
    set +e
    readelf -l "$OUT/hnc_launcher" 2>/dev/null | grep -A 1 'TLS' | head -3 || true
) || true

# ─── 4. 简单 sanity check ─────────────────────────────────────────

echo ""
echo "Sanity check..."

for s in "hnc_launcher" "/data/local/hnc/bin/hnc_dpid" "execv failed" "CRASH_LOOP"; do
    if ! strings "$OUT/hnc_launcher" | grep -qF "$s"; then
        echo "  ERROR: hnc_launcher missing string: $s" >&2
        exit 1
    fi
done
if ! strings "$OUT/hnc_launcher" | grep -qE '^0\.[0-9]+\.[0-9]+-rc[0-9]+(\.[0-9]+)*$'; then
    echo "  ERROR: hnc_launcher missing version string matching 0.X.Y-rcN(.M)*" >&2
    exit 1
fi

for s in "=== fork_probe v1 ===" "FORK FAILED" "EXECV FAILED" "RESULT: C fork+execv WORKS"; do
    if ! strings "$OUT/fork_probe" | grep -qF "$s"; then
        echo "  ERROR: fork_probe missing string: $s" >&2
        exit 1
    fi
done

echo "  ✓ hnc_launcher: all expected strings present"
echo "  ✓ fork_probe:   all expected strings present"

# ─── 5. 可选: 拷贝到 bin/ ─────────────────────────────────────────

if [ "$DO_INSTALL" -eq 1 ]; then
    DEST="../../bin"
    [ "$ARCH" = "arm" ] && DEST="../../bin/armeabi-v7a"
    mkdir -p "$DEST"
    echo ""
    echo "Installing to $DEST/..."
    cp -v "$OUT/hnc_launcher" "$DEST/"
    cp -v "$OUT/fork_probe" "$DEST/"
    chmod 755 "$DEST/hnc_launcher" "$DEST/fork_probe"
    echo "✓ installed to $DEST/"
fi

echo ""
echo "Done. Built artifacts:"
ls -lh "$OUT/hnc_launcher" "$OUT/fork_probe"
