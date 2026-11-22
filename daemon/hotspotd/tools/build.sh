#!/bin/bash
# tools/build.sh — 编译 hotspotd 独立工具 (hnc_ipc)
#
# 工具:
#   hnc_ipc          hotspotd UNIX socket 命令行客户端
#
# 用法:
#   export ANDROID_NDK=/path/to/android-ndk-r30
#   bash tools/build.sh [arm64|arm|x86_64|host] [tool]
#
#   tool 可选:
#     all              (默认) 编译 hnc_ipc
#     hnc_ipc          编译 hnc_ipc
#
# 输出:
#   tools/prebuilt/<arch>/hnc_ipc

set -e
cd "$(dirname "$0")"

ARCH=${1:-arm64}
TOOL=${2:-all}

HNC_VER=$(sed -n 's/^version=//p' ../../../module.prop 2>/dev/null | head -n 1 | tr -d '\r')
[ -n "$HNC_VER" ] || HNC_VER="dev"

OUTDIR="prebuilt/${ARCH}"
mkdir -p "$OUTDIR"

# 决定 compiler
if [ "$ARCH" = "host" ]; then
    CC="${CC:-gcc}"
    CFLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Werror -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -fPIE"
    LDFLAGS="-pie"
    echo "[build] Host build (Version: $HNC_VER)"
else
    case "$ARCH" in
        arm64)   TARGET=aarch64-linux-android;     API=28 ;;
        arm)     TARGET=armv7a-linux-androideabi;  API=28 ;;
        x86_64)  TARGET=x86_64-linux-android;      API=28 ;;
        *)       echo "Unknown arch: $ARCH"; exit 1 ;;
    esac

    if [ -z "${ANDROID_NDK:-}" ]; then
        ANDROID_NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    fi
    if [ -z "${ANDROID_NDK:-}" ] && [ -z "${CC:-}" ]; then
        echo "[build] ERROR: 请设置 ANDROID_NDK 或 CC"
        exit 1
    fi

    if [ -n "${ANDROID_NDK:-}" ]; then
        HOST_TAG=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
        TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
        CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
        [ -x "$TOOLCHAIN/bin/llvm-strip" ] && STRIP="$TOOLCHAIN/bin/llvm-strip"
    fi

    CFLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Werror -D_GNU_SOURCE -DANDROID -D_FILE_OFFSET_BITS=64 -fPIE"
    LDFLAGS="-pie -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
    echo "[build] Compiler: $CC  Target: $ARCH  Version: $HNC_VER"
fi

build_one() {
    local NAME=$1
    local MAIN=${NAME}.c
    local OUT=${OUTDIR}/${NAME}
    echo "[build] -> $OUT"
    # shellcheck disable=SC2086
    $CC $CFLAGS -DHNC_VERSION="\"${HNC_VER}\"" -o "$OUT" "$MAIN" $LDFLAGS
    [ "$ARCH" != "host" ] && "${STRIP:-strip}" "$OUT" 2>/dev/null || true
    ls -lh "$OUT" | awk '{print "         " $5 "  " $9}'
}

case "$TOOL" in
    all|hnc_ipc)
        build_one hnc_ipc
        ;;
    *)
        echo "Unknown tool: $TOOL (expected: all | hnc_ipc)"
        exit 1
        ;;
esac

echo "[build] Done."
