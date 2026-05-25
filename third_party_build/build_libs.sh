#!/bin/bash
# third_party_build/build_libs.sh — FINAL
# 策略: libelf.a + libz.a 来自预编译 (JiaHuann/libbpf-bootstrap-android, BSD-3),
# 只需用 NDK clang 编 libbpf 的 21 个 .c

set -e
ARCH="${1:-arm64}"
[ -z "$ANDROID_NDK" ] && { echo "ERROR: ANDROID_NDK env not set"; exit 1; }

case "$ARCH" in
    arm64) TARGET=aarch64-linux-android; API=28 ;;
    *) echo "Only arm64 supported"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TP_ROOT="$REPO_ROOT/third_party"
PREBUILT="$REPO_ROOT/third_party_prebuilt"
OUT="$SCRIPT_DIR/_libs_out"
HOST_TAG=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
CC="$TOOLCHAIN/bin/${TARGET}${API}-clang"
AR="$TOOLCHAIN/bin/llvm-ar"
RANLIB="$TOOLCHAIN/bin/llvm-ranlib"

CFLAGS_COMMON="-O2 -fPIC -D_GNU_SOURCE -Wno-everything"

mkdir -p "$OUT/include/bpf" "$OUT/include/linux" "$OUT/lib"

# ─── 0. 拷 prebuilt libelf.a + libz.a + headers ─────────────
echo "=== Copy prebuilt libelf + libz (from JiaHuann) ==="
cp "$PREBUILT/libelf/libelf.a" "$OUT/lib/"
cp "$PREBUILT/libz/libz.a"     "$OUT/lib/"
cp -r "$PREBUILT/libelf/include"/* "$OUT/include/" 2>/dev/null || true
cp "$PREBUILT/libz/include"/*.h    "$OUT/include/" 2>/dev/null || true
echo "  libelf.a:  $(ls -lh "$OUT/lib/libelf.a" | awk '{print $5}')"
echo "  libz.a:    $(ls -lh "$OUT/lib/libz.a" | awk '{print $5}')"
echo "  headers:   libelf.h=$([ -f "$OUT/include/libelf.h" ] && echo yes), zlib.h=$([ -f "$OUT/include/zlib.h" ] && echo yes)"

# ─── 1. 编 libbpf ────────────────────────────────────────
LIBBPF_SRC="$TP_ROOT/libbpf/src"
LIBBPF_INC="$TP_ROOT/libbpf/include"

[ ! -f "$LIBBPF_SRC/libbpf.h" ] && { echo "ERROR: third_party/libbpf missing"; exit 1; }

if [ ! -f "$OUT/lib/libbpf.a" ]; then
    echo ""
    echo "=== Building libbpf ==="
    LIBBPF_OBJ_DIR="$OUT/_obj/libbpf"
    mkdir -p "$LIBBPF_OBJ_DIR"

    # 拷 libbpf 头
    cp "$LIBBPF_SRC/libbpf.h"          "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf.h"             "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/btf.h"             "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf_helpers.h"     "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf_helper_defs.h" "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf_endian.h"      "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf_tracing.h"     "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/bpf_core_read.h"   "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/libbpf_common.h"   "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/libbpf_legacy.h"   "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/libbpf_version.h"  "$OUT/include/bpf/"
    cp "$LIBBPF_SRC/skel_internal.h"   "$OUT/include/bpf/" 2>/dev/null || true
    cp "$LIBBPF_SRC/usdt.bpf.h"        "$OUT/include/bpf/" 2>/dev/null || true
    cp -r "$LIBBPF_INC/uapi/linux"/* "$OUT/include/linux/" 2>/dev/null || true

    cd "$LIBBPF_SRC"
    # v5.8.6 (audit): NDK r27c 的 sanitized UAPI <linux/eventpoll.h> 把 EPOLLIN
    # 等宏定义成 (__poll_t)0xN, 但 NDK 的 <linux/types.h> 剥掉了 __poll_t typedef
    # → libbpf.c / ringbuf.c 编译报 "use of undeclared identifier '__poll_t'".
    # 补一个无害的宏定义(__poll_t 仅经 EPOLL* 宏间接使用, 定义为 unsigned 即可),
    # 这是 NDK 编 libbpf 的标准修法。不修则那两个文件不进 libbpf.a, 最终链接
    # hotspotd 时一堆 undefined symbol(libbpf_set_print/bpf_object__*/ring_buffer__*)。
    LIBBPF_CFLAGS="$CFLAGS_COMMON \
        -I$OUT/include \
        -I$LIBBPF_SRC \
        -I$LIBBPF_INC \
        -I$LIBBPF_INC/uapi \
        -DCOMPAT_NEED_REALLOCARRAY \
        -D__poll_t=unsigned \
        -Wno-implicit-function-declaration \
        -Wno-pointer-sign"

    FAILED=0
    for src in *.c; do
        case "$src" in
            linker.c) echo "  SKIP $src"; continue ;;
        esac
        echo "  CC libbpf/$src"
        if ! "$CC" $LIBBPF_CFLAGS -c "$src" -o "$LIBBPF_OBJ_DIR/${src%.c}.o"; then
            echo "  [WARN] libbpf/$src failed"
            FAILED=$((FAILED+1))
        fi
    done

    OBJ_COUNT=$(ls "$LIBBPF_OBJ_DIR"/*.o 2>/dev/null | wc -l)
    echo "[build_libs] libbpf: $OBJ_COUNT objects compiled, $FAILED failed"
    # v5.8.6 (audit): 任何 libbpf 源文件编译失败都 FATAL。之前只看 OBJ_COUNT>=15
    # 容忍少数失败 → 产出残缺 libbpf.a(缺 libbpf.c/ringbuf.c)→ 真正的报错被推迟到
    # 链接 hotspotd 时一堆 undefined symbol, 极难定位。现在编译阶段就失败、直接暴露
    # 真实的 C 编译错误。(linker.c 是有意 SKIP, 不计入 FAILED。)
    if [ "$FAILED" -gt 0 ]; then
        echo "[build_libs] ERROR: $FAILED libbpf source file(s) failed to compile — refusing to"
        echo "             produce an incomplete libbpf.a (would cause undefined-symbol link errors)."
        exit 1
    fi
    if [ "$OBJ_COUNT" -lt 15 ]; then
        echo "[build_libs] ERROR: too few libbpf objects ($OBJ_COUNT), need >=15"
        exit 1
    fi

    "$AR" rcs "$OUT/lib/libbpf.a" "$LIBBPF_OBJ_DIR"/*.o
    "$RANLIB" "$OUT/lib/libbpf.a"
    echo "[build_libs] libbpf.a OK ($(ls -lh "$OUT/lib/libbpf.a" | awk '{print $5}'))"
fi

echo ""
echo "=== ALL DONE ==="
ls -la "$OUT/lib/"
