#!/usr/bin/env bash
# build.sh — Cross-compile hnc_clsact_ctl for Android via NDK + build the BPF object.
#
# 两件事:
#   1. clang -target bpf 编 ../../src/dpid/bpf/hnc_clsact.bpf.c → ../../bin/hnc_clsact.o
#      (形态对齐 daemon/hotspotd/build.sh 的 LSM guard BPF 编译; ubuntu CI 自带 clang)
#   2. NDK 编 main.c → ../../bin/hnc_clsact_ctl (形态对齐 daemon/tc_netlink/build.sh)
#
# Usage:
#   export ANDROID_NDK=/path/to/android-ndk   # 仅二进制需要; .o 只需 clang
#   bash build.sh [arch]                      # arch 默认 arm64
#
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail
cd "$(dirname "$0")"

ARCH="${1:-arm64}"
BINDIR="../../bin"
BPF_SRC="../../src/dpid/bpf/hnc_clsact.bpf.c"

mkdir -p "$BINDIR"

# ── 1. BPF object ─────────────────────────────────────────────
BPFCC="${BPFCC:-clang}"
if ! command -v "$BPFCC" >/dev/null 2>&1; then
    echo "[build] WARN: $BPFCC not found, skip BPF object build"
else
    "$BPFCC" -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
        -c "$BPF_SRC" -o "$BINDIR/hnc_clsact.o"
    if [ -f "$BINDIR/hnc_clsact.o" ]; then
        llvm-strip -g "$BINDIR/hnc_clsact.o" 2>/dev/null \
          || strip -g "$BINDIR/hnc_clsact.o" 2>/dev/null || true
        echo "[build] BPF object: $BINDIR/hnc_clsact.o"
        if command -v file >/dev/null 2>&1; then
            file "$BINDIR/hnc_clsact.o"
        fi
    fi
fi

# ── 2. hnc_clsact_ctl 二进制 ─────────────────────────────────
if [ "$ARCH" = "host" ]; then
    CC="${CC:-gcc}"
    CFLAGS="-O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE"
    # shellcheck disable=SC2086
    $CC $CFLAGS -o /tmp/hnc_clsact_ctl main.c -pie
    echo "[build] Host sanity build OK"
    exit 0
fi

case "$ARCH" in
    arm64)  TARGET=aarch64-linux-android; API=28 ;;
    *) echo "[build] ERROR: only arm64 supported" >&2; exit 1 ;;
esac

if [ -z "${ANDROID_NDK:-}" ]; then
    ANDROID_NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
fi
if [ -z "${ANDROID_NDK:-}" ] || [ ! -d "$ANDROID_NDK" ]; then
    echo "[build] ERROR: set ANDROID_NDK" >&2
    exit 1
fi

HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
STRIP="$TOOLCHAIN/bin/llvm-strip"

if [ ! -x "$CC" ]; then
    echo "[build] ERROR: compiler not found: $CC" >&2
    exit 1
fi

CFLAGS="-O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE -DANDROID -static-libgcc -fPIE"
# shellcheck disable=SC2086
$CC $CFLAGS -o "$BINDIR/hnc_clsact_ctl" main.c -pie

if [ -x "$STRIP" ]; then
    $STRIP "$BINDIR/hnc_clsact_ctl"
fi
chmod 755 "$BINDIR/hnc_clsact_ctl"
ls -lh "$BINDIR/hnc_clsact_ctl"
echo "[build] OK: $BINDIR/hnc_clsact_ctl"
