/* v5.1 compat_stubs.c — space-filler for libelf's elf_compress.c
 *
 * Termux libelf-static 0.193 was built with zstd/bz2/lzma support,
 * but we don't ship those .a files and libbpf never loads BPF objects
 * with compressed sections. These stubs satisfy the linker without
 * bloating the binary. If libelf ever actually calls these (it won't
 * for our BPF .o files), the process will abort — by design.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#define STUB_ABORT(name) do { \
    fprintf(stderr, "[hnc_compat] FATAL: " name " called — " \
            "libelf tried to use compressed section but we don't link " \
            "compression libs. This should never happen for BPF objects.\n"); \
    abort(); \
} while (0)

/* ─── ZSTD stubs ─────────────────────────────────────── */
void *ZSTD_createCCtx(void)                          { STUB_ABORT("ZSTD_createCCtx");      return NULL; }
size_t ZSTD_freeCCtx(void *cctx)                     { (void)cctx; STUB_ABORT("ZSTD_freeCCtx"); return 0; }
size_t ZSTD_compressStream2(void *a, void *b, void *c, int d)
                                                     { (void)a; (void)b; (void)c; (void)d; STUB_ABORT("ZSTD_compressStream2"); return 0; }
size_t ZSTD_decompress(void *a, size_t b, const void *c, size_t d)
                                                     { (void)a; (void)b; (void)c; (void)d; STUB_ABORT("ZSTD_decompress"); return 0; }
unsigned ZSTD_isError(size_t code)                   { (void)code; return 0; }  /* 非严格:返 0 = 非错 */

/* ─── BZ2 stubs (libelf 可能也 link) ─────────────────────── */
int BZ2_bzBuffToBuffCompress(char *dst, unsigned *dst_len,
                              char *src, unsigned src_len,
                              int bs, int verb, int wf)
                                                     { (void)dst; (void)dst_len; (void)src; (void)src_len; (void)bs; (void)verb; (void)wf; STUB_ABORT("BZ2_bzBuffToBuffCompress"); return -1; }
int BZ2_bzBuffToBuffDecompress(char *dst, unsigned *dst_len,
                                char *src, unsigned src_len,
                                int small, int verb)
                                                     { (void)dst; (void)dst_len; (void)src; (void)src_len; (void)small; (void)verb; STUB_ABORT("BZ2_bzBuffToBuffDecompress"); return -1; }
