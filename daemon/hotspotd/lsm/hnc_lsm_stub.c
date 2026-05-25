/* hnc_lsm_stub.c — disabled stand-in for the BPF LSM Limit Map Guard.
 *
 * v5.8.7 (audit): the real hnc_lsm_loader.c uses libbpf's object-loading API
 * (bpf_object__open_file / ring_buffer__* / ...), which pulls in libelf + libz.
 * The only Android (bionic) prebuilt of those we had access to turned out to be
 * a glibc build (undefined __errno_location / __fxstat / dcgettext / ... at
 * link), and a correct bionic libelf is non-trivial to obtain/build in CI.
 *
 * The LSM guard is optional and non-fatal *by design* (see hnc_lsm_loader.h:
 * callers must handle DISABLED gracefully), and its BPF object was never shipped
 * in the module zip — so it has been dormant in every release anyway. To let CI
 * build hotspotd from source (the actually-shipped BPF tether offload in
 * adapter_bpf.c only needs libbpf's bpf() syscall wrappers — no libelf/libz),
 * we compile this stub instead of hnc_lsm_loader.c + compat_stubs.c and drop
 * libelf.a/libz.a from the link.
 *
 * Re-enabling later only needs a real bionic libelf.a/libz.a (e.g. Termux
 * libelf-static, which the original build used) + swapping this back to
 * hnc_lsm_loader.c in build.sh.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "hnc_lsm_loader.h"

#include <string.h>
#include <stdio.h>

int hnc_lsm_init(const char *bpf_object_path,
                 const char *target_limit_map_path,
                 uint32_t initial_ifindex)
{
    (void)bpf_object_path;
    (void)target_limit_map_path;
    (void)initial_ifindex;
    /* -2 = DISABLED (kernel/feature unavailable). Callers continue gracefully. */
    return -2;
}

int hnc_lsm_update_ifindex(uint32_t new_ifindex)
{
    (void)new_ifindex;
    return 0;
}

void hnc_lsm_shutdown(void)
{
}

void hnc_lsm_get_status(hnc_lsm_status_t *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->state = HNC_LSM_DISABLED;
    snprintf(out->fail_reason, sizeof(out->fail_reason),
             "LSM guard disabled in this build (no bionic libelf)");
}

int hnc_lsm_status_to_json_fragment(const hnc_lsm_status_t *st,
                                    char *buf, size_t buf_size)
{
    (void)st;
    if (!buf || buf_size == 0)
        return -1;
    int n = snprintf(buf, buf_size, "\"lsm\":{\"state\":\"disabled\"}");
    if (n < 0 || (size_t)n >= buf_size)
        return -1;
    return n;
}
