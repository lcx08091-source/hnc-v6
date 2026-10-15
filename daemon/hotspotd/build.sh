#!/bin/bash
# daemon/hotspotd/build.sh — 使用 Android NDK 交叉编译 hotspotd
# v5.0.0-beta.4 hotfix6: 链接 libbpf 静态库
#
# 用法:
#   export ANDROID_NDK=/path/to/android-ndk
#   bash daemon/hotspotd/build.sh [arm64]

set -e
cd "$(dirname "$0")"

ARCH=${1:-arm64}

# v5.0.0-beta.4 hotfix6: 改用 libbpf, 删除手撸 lsm/hnc_lsm_loader.c 的
# sys_bpf 实现, 改为 libbpf 标准 API
# v5.8.7 (audit): offload(adapter_bpf.c)只用 libbpf 的 bpf() syscall 包装,不需要
# libelf/libz(唯一能拿到的 Android 预编译实为 glibc 版)。BPF LSM guard 当年因此只链 stub,
# v5.33 整块删了(见下方 build done 前的注释)。
SRCS="hotspotd.c hnc_helpers.c \
      platform.c scheduler.c upstream.c \
      offload/adapter.c offload/adapter_null.c offload/adapter_bpf.c"
OUTDIR=prebuilt/${ARCH}
OUT=${OUTDIR}/hotspotd

mkdir -p "$OUTDIR"

# ── NDK toolchain ──────────────────────────────────────────────
if [ -z "$ANDROID_NDK" ] && [ -z "$CC" ]; then
    echo "[build] ERROR: 请设置 ANDROID_NDK 或 CC"
    exit 1
fi

case "$ARCH" in
    arm64)   TARGET=aarch64-linux-android;  API=28 ;;
    arm)     TARGET=armv7a-linux-androideabi; API=28 ;;
    x86_64)  TARGET=x86_64-linux-android;   API=28 ;;
    *)       echo "Unknown arch: $ARCH"; exit 1 ;;
esac

if [ -n "$ANDROID_NDK" ]; then
    HOST_TAG=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
    TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
    CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
fi
# v5.22: 优先用 NDK llvm-strip —— host 的 GNU strip 不认 ARM/AArch64 ELF,
# 原来的 `strip ... || true` 实际静默失败, 产物从未被 strip。
STRIP=strip
[ -n "${TOOLCHAIN:-}" ] && [ -x "$TOOLCHAIN/bin/llvm-strip" ] && STRIP="$TOOLCHAIN/bin/llvm-strip"

# ── v5.0.0-beta.4 hotfix6: 编 third_party libs (zlib, libelf, libbpf) ──
# v5.22: 按 arch 分目录(与 build_libs.sh 同一规则), 防止 arm 链接到 arm64 的 libbpf.a
LIBS_OUT="$(cd ../../third_party_build && pwd)/_libs_out"
[ "$ARCH" != "arm64" ] && LIBS_OUT="$LIBS_OUT/$ARCH"
if [ ! -f "$LIBS_OUT/lib/libbpf.a" ]; then
    echo ""
    echo "=== Building third_party libs ==="
    (cd ../../third_party_build && HNC_LIBS_OUT="$LIBS_OUT" bash build_libs.sh "$ARCH")
fi

if [ ! -f "$LIBS_OUT/lib/libbpf.a" ]; then
    echo "[build] ERROR: libbpf.a missing after build_libs.sh"
    exit 1
fi

# ── 编译 hotspotd 主体 + 链接 libbpf ─────────────────────────
echo ""
echo "[build] Compiler: $CC"
echo "[build] Target:   $ARCH  Output: $OUT"
echo "[build] libs:     $LIBS_OUT/lib/libbpf.a (libelf/libz not linked)"

$CC \
    -O2 \
    -std=c11 \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -static-libgcc \
    -D_GNU_SOURCE \
    -DANDROID \
    -DHNC_HAVE_ADAPTER_BPF \
    -fPIE -pie \
    -pthread \
    -I"$LIBS_OUT/include" \
    -o "$OUT" \
    $SRCS \
    -Wl,--allow-multiple-definition \
    "$LIBS_OUT/lib/libbpf.a"
# v5.8.7 (audit): 不再链接 libelf.a/libz.a。hotspotd 仅用 libbpf 的 bpf() syscall
# 包装(bpf.c),不调 bpf_object__*/ring_buffer__*,故链接器不会拉入需要 libelf/libz
# 的 libbpf.c/elf.c/btf.c 目标 → 无需这两个库(且我们只有 glibc 版,链了反而炸)。


"$STRIP" "$OUT" 2>/dev/null || true
echo "[build] OK: $(ls -lh "$OUT" | awk '{print $5}')  $OUT"

# 复制到 bin/(v5.22: arm64 仍是 bin/ 原路径; arm → bin/armeabi-v7a/,
# 安装期由 customize.sh 按设备 ABI 覆盖到 bin/)
BINDIR=../../bin
[ "$ARCH" = "arm" ] && BINDIR=../../bin/armeabi-v7a
mkdir -p "$BINDIR"
cp "$OUT" "$BINDIR/hotspotd"
chmod 755 "$BINDIR/hotspotd"
echo "[build] Copied to $BINDIR/hotspotd"

# ── 编 hnc_ipc ─────────────────────────────────────────────
echo ""
echo "=== v5.0 tools build (hnc_ipc) ==="
if [ -d tools ]; then
    (cd tools && bash build.sh "$ARCH" hnc_ipc) || \
        echo "[build] WARN: hnc_ipc build failed"
    if [ -f "tools/prebuilt/${ARCH}/hnc_ipc" ]; then
        cp "tools/prebuilt/${ARCH}/hnc_ipc" "$BINDIR/hnc_ipc"
        chmod 755 "$BINDIR/hnc_ipc"
    fi
fi

# ── 编 mdns_resolve (自包含, 无 libbpf 依赖) ───────────────
# v5.8.3 (audit): 之前 mdns_resolve 是 ad-hoc 预编译、无构建脚本、CI 不重编。
# 它只用标准 POSIX 头, 单文件直接编即可, 纳入 build.sh 让 CI 一并重编。
echo ""
echo "=== mdns_resolve build ==="
if [ -f mdns_resolve.c ]; then
    $CC -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter \
        -D_GNU_SOURCE -DANDROID -fPIE -pie -pthread \
        -o "$BINDIR/mdns_resolve" mdns_resolve.c
    "$STRIP" "$BINDIR/mdns_resolve" 2>/dev/null || true
    chmod 755 "$BINDIR/mdns_resolve"
    echo "[build] OK: $(ls -lh "$BINDIR/mdns_resolve" | awk '{print $5}')  $BINDIR/mdns_resolve"
fi

# v5.33: BPF LSM limit_map guard 整块删除(lsm/ 目录: 永远返回「关闭」的 stub、
# 只做语法检查不链接的真 loader、BPF 程序源码与 3.3 MB vmlinux.h)。v5.8.7 起链接的
# 就是 stub —— 真 loader 需要 libelf/libz, 没有可用的 Android 静态版。要恢复从 git 历史取。

echo ""
echo "[build] === build done ==="
