#!/bin/bash
# tools/build.sh — 编译 v5.0 alpha.1 独立工具
#
# 工具:
#   platform_probe   平台探测 (host 模式可用, 字段会空)
#   offload_ctl      adapter 真机验证 CLI (需 root + Android)
#
# 用法:
#   export ANDROID_NDK=/path/to/android-ndk-r27
#   bash tools/build.sh [arm64|arm|x86_64|host] [tool]
#
#   tool 可选:
#     all              (默认) 编译两个工具
#     platform_probe   只编 platform_probe
#     offload_ctl      只编 offload_ctl
#
# 输出:
#   tools/prebuilt/<arch>/<tool>

set -e
cd "$(dirname "$0")"

ARCH=${1:-arm64}
TOOL=${2:-all}

# 公共源码 (按需链入)
# alpha.2: 加 upstream.c (scheduler 依赖)
COMMON_SRCS="../platform.c ../scheduler.c ../upstream.c ../offload/adapter.c ../offload/adapter_null.c ../offload/adapter_bpf.c"
COMMON_DEFS="-DHNC_HAVE_ADAPTER_BPF"

OUTDIR="prebuilt/${ARCH}"
mkdir -p "$OUTDIR"

# 决定 compiler
if [ "$ARCH" = "host" ]; then
    CC=gcc
    CFLAGS="-O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE $COMMON_DEFS"
    LDFLAGS="-pthread"
    echo "[build] Host build (Android props will be empty)"
else
    case "$ARCH" in
        arm64)   TARGET=aarch64-linux-android;     API=21 ;;
        arm)     TARGET=armv7a-linux-androideabi;  API=21 ;;
        x86_64)  TARGET=x86_64-linux-android;      API=21 ;;
        *)       echo "Unknown arch: $ARCH"; exit 1 ;;
    esac

    if [ -z "$ANDROID_NDK" ] && [ -z "$CC" ]; then
        echo "[build] ERROR: 请设置 ANDROID_NDK 或 CC"
        exit 1
    fi

    if [ -n "$ANDROID_NDK" ]; then
        HOST_TAG=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
        TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
        CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
    fi

    CFLAGS="-O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE -DANDROID $COMMON_DEFS -static-libgcc -fPIE"
    LDFLAGS="-pie -pthread"
    echo "[build] Compiler: $CC  Target: $ARCH"
fi

build_one() {
    local NAME=$1
    local MAIN=${NAME}.c
    local OUT=${OUTDIR}/${NAME}
    echo "[build] -> $OUT"
    # hnc_ipc 是独立工具, 不需要 platform/scheduler/adapter 公共代码
    if [ "$NAME" = "hnc_ipc" ]; then
        $CC $CFLAGS -o "$OUT" "$MAIN" $LDFLAGS
    else
        $CC $CFLAGS -I.. -I../offload -o "$OUT" "$MAIN" $COMMON_SRCS $LDFLAGS
    fi
    [ "$ARCH" != "host" ] && strip "$OUT" 2>/dev/null || true
    ls -lh "$OUT" | awk '{print "         " $5 "  " $9}'
}

case "$TOOL" in
    all)
        build_one platform_probe
        build_one offload_ctl
        build_one sched_test
        build_one hnc_ipc
        ;;
    platform_probe|offload_ctl|sched_test|hnc_ipc)
        build_one "$TOOL"
        ;;
    *)
        echo "Unknown tool: $TOOL"
        exit 1
        ;;
esac

echo "[build] Done."
