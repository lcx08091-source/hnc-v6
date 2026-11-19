#!/bin/bash
# tools/build.sh — 编译 v5.0 alpha.1 独立工具
#
# 工具:
#   platform_probe   平台探测 (host 模式可用, 字段会空)
#   offload_ctl      (removed v5.9.92 — 从不构建不随包; 真机验证用 termux 直接编)
#
# 用法:
#   export ANDROID_NDK=/path/to/android-ndk-r30
#   bash tools/build.sh [arm64|arm|x86_64|host] [tool]
#
#   tool 可选:
#     all              (默认) 编译两个工具
#     platform_probe   只编 platform_probe
#
# 输出:
#   tools/prebuilt/<arch>/<tool>

set -e
cd "$(dirname "$0")"

ARCH=${1:-arm64}
TOOL=${2:-all}

# 公共源码 (按需链入)
# alpha.2: 加 upstream.c (scheduler 依赖)
COMMON_SRCS="../hnc_helpers.c ../platform.c ../scheduler.c ../upstream.c ../offload/adapter.c ../offload/adapter_null.c ../offload/adapter_bpf.c"
COMMON_DEFS="-DHNC_HAVE_ADAPTER_BPF"

OUTDIR="prebuilt/${ARCH}"
mkdir -p "$OUTDIR"

# 决定 compiler
if [ "$ARCH" = "host" ]; then
    CC="${CC:-gcc}"
    CFLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Werror -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $COMMON_DEFS -fPIE"
    LDFLAGS="-pie -pthread"
    echo "[build] Host build (Android props will be empty)"
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

    CFLAGS="-O2 -std=c11 -Wall -Wextra -Wsign-compare -Werror -D_GNU_SOURCE -DANDROID -D_FILE_OFFSET_BITS=64 $COMMON_DEFS -fPIE -pthread"
    LDFLAGS="-pie -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
    echo "[build] Compiler: $CC  Target: $ARCH"
fi

build_one() {
    local NAME=$1
    local MAIN=${NAME}.c
    local OUT=${OUTDIR}/${NAME}
    echo "[build] -> $OUT"
    # hnc_ipc 是独立工具, 不需要 platform/scheduler/adapter 公共代码
    if [ "$NAME" = "hnc_ipc" ]; then
        # shellcheck disable=SC2086
        $CC $CFLAGS -o "$OUT" "$MAIN" $LDFLAGS
    else
        # shellcheck disable=SC2086
        $CC $CFLAGS -I.. -I../offload -o "$OUT" "$MAIN" $COMMON_SRCS $LDFLAGS
    fi
    [ "$ARCH" != "host" ] && "${STRIP:-strip}" "$OUT" 2>/dev/null || true
    ls -lh "$OUT" | awk '{print "         " $5 "  " $9}'
}

case "$TOOL" in
    all)
        build_one platform_probe
        build_one sched_test
        build_one hnc_ipc
        ;;
    platform_probe|sched_test|hnc_ipc)
        build_one "$TOOL"
        ;;
    *)
        echo "Unknown tool: $TOOL"
        exit 1
        ;;
esac

echo "[build] Done."
