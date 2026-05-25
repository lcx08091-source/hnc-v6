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
# v5.8.7 (audit): LSM guard 暂用 stub(见 lsm/hnc_lsm_stub.c)。真 loader 需
# libbpf 的 object-loading API → 牵出 libelf+libz;唯一能拿到的 Android 预编译
# 实为 glibc 版(链接报 __errno_location/__fxstat/dcgettext 等 glibc 符号)。
# offload(adapter_bpf.c)只用 libbpf 的 bpf() syscall 包装,不需要 libelf/libz,
# 故拆掉 LSM loader(本就可选/非致命/object 从不随包)即可让 CI 从源码编出 hotspotd。
SRCS="hotspotd.c hnc_helpers.c hostname_cache.c oui_override.c mdns_worker.c \
      platform.c scheduler.c upstream.c \
      offload/adapter.c offload/adapter_null.c offload/adapter_bpf.c \
      lsm/hnc_lsm_stub.c"
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

# ── v5.0.0-beta.4 hotfix6: 编 third_party libs (zlib, libelf, libbpf) ──
LIBS_OUT="$(cd ../../third_party_build && pwd)/_libs_out"
if [ ! -f "$LIBS_OUT/lib/libbpf.a" ]; then
    echo ""
    echo "=== Building third_party libs ==="
    (cd ../../third_party_build && bash build_libs.sh "$ARCH")
fi

if [ ! -f "$LIBS_OUT/lib/libbpf.a" ]; then
    echo "[build] ERROR: libbpf.a missing after build_libs.sh"
    exit 1
fi

# ── 编译 hotspotd 主体 + 链接 libbpf ─────────────────────────
echo ""
echo "[build] Compiler: $CC"
echo "[build] Target:   $ARCH  Output: $OUT"
echo "[build] libs:     $LIBS_OUT/lib/libbpf.a (libelf/libz not linked — LSM stubbed)"

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

strip "$OUT" 2>/dev/null || true
echo "[build] OK: $(ls -lh "$OUT" | awk '{print $5}')  $OUT"

# 复制到 bin/
BINDIR=../../bin
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
    strip "$BINDIR/mdns_resolve" 2>/dev/null || true
    chmod 755 "$BINDIR/mdns_resolve"
    echo "[build] OK: $(ls -lh "$BINDIR/mdns_resolve" | awk '{print $5}')  $BINDIR/mdns_resolve"
fi

# ── 编 BPF object (LSM 程序) ─────────────────────────────
echo ""
echo "=== v5.0.0-beta.4 BPF LSM build ==="
if [ -f lsm/vmlinux.h ] && [ -f lsm/hnc_limit_map_guard.bpf.c ]; then
    BPFCC="${BPFCC:-clang}"
    if ! command -v "$BPFCC" >/dev/null 2>&1; then
        echo "[build] WARN: $BPFCC not found, skip BPF compile"
    else
        BPF_OUT_DIR=../../bpf
        mkdir -p "$BPF_OUT_DIR"
        "$BPFCC" -O2 -g \
            -target bpf \
            -D__TARGET_ARCH_arm64 \
            -I"$LIBS_OUT/include" \
            -Ilsm \
            -c lsm/hnc_limit_map_guard.bpf.c \
            -o "$BPF_OUT_DIR/hnc_limit_map_guard.bpf.o" || \
            echo "[build] WARN: BPF compile failed"
        if [ -f "$BPF_OUT_DIR/hnc_limit_map_guard.bpf.o" ]; then
            llvm-strip -g "$BPF_OUT_DIR/hnc_limit_map_guard.bpf.o" 2>/dev/null \
              || strip -g "$BPF_OUT_DIR/hnc_limit_map_guard.bpf.o" 2>/dev/null \
              || true
            echo "[build] BPF object: $(ls -lh "$BPF_OUT_DIR/hnc_limit_map_guard.bpf.o" | awk '{print $5}')"
        fi
    fi
fi

echo ""
echo "[build] === build done ==="
