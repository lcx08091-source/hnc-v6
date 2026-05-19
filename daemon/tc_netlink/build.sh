#!/usr/bin/env bash
# build.sh — Cross-compile hnc_tc_ingress for Android via NDK.
#
# Requires Android NDK r25 or later (tested with r27c).
#
# Usage:
#   export ANDROID_NDK=/path/to/android-ndk-r27c   # or $ANDROID_NDK_HOME / $ANDROID_NDK_ROOT
#   bash build.sh [arch]
#
#     arch = arm64 (default) | arm | x86_64 | host
#
# Outputs:
#   out/<arch>/hnc_tc_ingress
#
# Env overrides:
#   HNC_NDK_API   Android API level (default 21)
#   CC            override compiler (mainly for the 'host' path)
#
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

cd "$(dirname "$0")"

ARCH="${1:-arm64}"
API="${HNC_NDK_API:-21}"
OUTDIR="out/${ARCH}"
SRC="hnc_tc_ingress.c"
BIN="hnc_tc_ingress"

mkdir -p "$OUTDIR"

if [ "$ARCH" = "host" ]; then
    # Host build is only useful for quick sanity testing on an x86_64 Linux
    # box (error-path behaviour, valgrind, strace comparison against tc).
    # The REAL target is arm64.
    CC="${CC:-gcc}"
    CFLAGS="-O2 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE"
    LDFLAGS=""
    echo "[build] Host build with $CC"
    echo "[build] $CC $CFLAGS -o $OUTDIR/$BIN $SRC $LDFLAGS"
    # shellcheck disable=SC2086
    $CC $CFLAGS -o "$OUTDIR/$BIN" "$SRC" $LDFLAGS
    ls -lh "$OUTDIR/$BIN"
    file "$OUTDIR/$BIN" 2>/dev/null || true
    echo "[build] OK: $OUTDIR/$BIN"
    exit 0
fi

case "$ARCH" in
    arm64)  TARGET=aarch64-linux-android    ;;
    arm)    TARGET=armv7a-linux-androideabi ;;
    x86_64) TARGET=x86_64-linux-android     ;;
    *) echo "[build] ERROR: unknown arch '$ARCH'" >&2; exit 1 ;;
esac

# Resolve NDK path: prefer explicit ANDROID_NDK, fall back to common aliases
if [ -z "${ANDROID_NDK:-}" ]; then
    ANDROID_NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
fi
if [ -z "${ANDROID_NDK:-}" ]; then
    echo "[build] ERROR: set ANDROID_NDK (or ANDROID_NDK_HOME / ANDROID_NDK_ROOT)" >&2
    exit 1
fi
if [ ! -d "$ANDROID_NDK" ]; then
    echo "[build] ERROR: ANDROID_NDK='$ANDROID_NDK' is not a directory" >&2
    exit 1
fi

HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
STRIP="$TOOLCHAIN/bin/llvm-strip"

if [ ! -x "$CC" ]; then
    echo "[build] ERROR: compiler not found: $CC" >&2
    echo "[build] Check ANDROID_NDK='$ANDROID_NDK' and HOST_TAG='$HOST_TAG'" >&2
    exit 1
fi

# -fPIE + -pie: required for Android 5+ (non-PIE binaries refuse to load).
# -static-libgcc: avoid libgcc.so dependency; keeps single binary portable
#   across NDK versions.
# We intentionally do NOT use -static (full static linking) because bionic
# libc is not designed to be linked statically on Android; dynamic linkage
# against /system/lib64/libc.so is the blessed path.
CFLAGS="-O2 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE -DANDROID -static-libgcc -fPIE"
LDFLAGS="-pie"

echo "[build] NDK:        $ANDROID_NDK"
echo "[build] Toolchain:  $TOOLCHAIN"
echo "[build] Target:     $TARGET API $API ($ARCH)"
echo "[build] CC:         $CC"
echo
echo "[build] $CC $CFLAGS -o $OUTDIR/$BIN $SRC $LDFLAGS"
# shellcheck disable=SC2086
$CC $CFLAGS -o "$OUTDIR/$BIN" "$SRC" $LDFLAGS

if [ -x "$STRIP" ]; then
    $STRIP "$OUTDIR/$BIN"
fi

echo
ls -lh "$OUTDIR/$BIN"
if command -v file >/dev/null 2>&1; then
    file "$OUTDIR/$BIN"
fi
echo "[build] OK: $OUTDIR/$BIN"

# HNC v5.0 beta.1 集成: 把产物拷到模块 bin/ (daemon/tc_netlink/ -> ../../bin/)
# 保持跟 daemon/hotspotd/build.sh 相同的习惯 (alpha.2 BINDIR fix)
if [ "$ARCH" = "arm64" ]; then
    BINDIR="../../bin"
    mkdir -p "$BINDIR"
    cp "$OUTDIR/$BIN" "$BINDIR/$BIN"
    chmod 755 "$BINDIR/$BIN"
    echo "[build] Copied to $BINDIR/$BIN"
fi
