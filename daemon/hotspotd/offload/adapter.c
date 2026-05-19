/* offload/adapter.c — adapter 注册表 + 选举 + 错误码字符串
 *
 * v5.0 alpha.1
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "adapter.h"

#include <stddef.h>
#include <stdio.h>

/* ══════════════════════════════════════════════════════════
 * 错误码字符串
 * ══════════════════════════════════════════════════════════ */
const char *offload_err_str(offload_err_t e)
{
    switch (e) {
    case OFFLOAD_OK:        return "OK";
    case OFFLOAD_ENOTSUP:   return "ENOTSUP";
    case OFFLOAD_EPERM:     return "EPERM";
    case OFFLOAD_EINVAL:    return "EINVAL";
    case OFFLOAD_ENOENT:    return "ENOENT";
    case OFFLOAD_EAGAIN:    return "EAGAIN";
    case OFFLOAD_EINTERNAL: return "EINTERNAL";
    }
    return "UNKNOWN";
}

const char *offload_type_str(offload_type_t t)
{
    switch (t) {
    case OFFLOAD_NONE:        return "none";
    case OFFLOAD_QCOM_BPF:    return "qcom_bpf";
    case OFFLOAD_MTK_PPE:     return "mtk_ppe";
    case OFFLOAD_SAMSUNG_NSS: return "samsung_nss";
    case OFFLOAD_HISI_HINAT:  return "hisi_hinat";
    case OFFLOAD_UNKNOWN:     return "unknown";
    }
    return "invalid";
}

const char *offload_gran_str(offload_granularity_t g)
{
    switch (g) {
    case OFFLOAD_GRAN_NONE:         return "none";
    case OFFLOAD_GRAN_GLOBAL:       return "global";
    case OFFLOAD_GRAN_PER_UPSTREAM: return "per_upstream";
    case OFFLOAD_GRAN_PER_DEVICE:   return "per_device";
    }
    return "invalid";
}

/* ══════════════════════════════════════════════════════════
 * 注册表
 *
 * 顺序 = probe 优先级。adapter_null 永远在最后兜底。
 *
 * v5.0 alpha.1: 只有 null 是真实可用,bpf 在 alpha.2 接入。
 * 编译时通过 -DHNC_HAVE_ADAPTER_BPF 等宏控制是否纳入(允许在
 * 单元测试 host build 时关掉真实硬件 adapter)。
 * ══════════════════════════════════════════════════════════ */

extern offload_adapter_t adapter_null;

#ifdef HNC_HAVE_ADAPTER_BPF
extern offload_adapter_t adapter_bpf;
#endif

#ifdef HNC_HAVE_ADAPTER_PPE
extern offload_adapter_t adapter_ppe;
#endif

#ifdef HNC_HAVE_ADAPTER_NSS
extern offload_adapter_t adapter_nss;
#endif

offload_adapter_t *g_adapters[] = {
#ifdef HNC_HAVE_ADAPTER_BPF
    &adapter_bpf,
#endif
#ifdef HNC_HAVE_ADAPTER_PPE
    &adapter_ppe,
#endif
#ifdef HNC_HAVE_ADAPTER_NSS
    &adapter_nss,
#endif
    &adapter_null,         /* 必须最后,兜底 */
    NULL,
};

/* ══════════════════════════════════════════════════════════
 * 选举
 * ══════════════════════════════════════════════════════════ */

static offload_adapter_t *s_active = NULL;

offload_adapter_t *offload_select_adapter(void)
{
    for (int i = 0; g_adapters[i] != NULL; i++) {
        offload_adapter_t *a = g_adapters[i];
        if (a->probe == NULL) {
            /* 编程错误: adapter 必须有 probe */
            fprintf(stderr, "[offload] adapter '%s' missing probe(), skipping\n",
                    a->name ? a->name : "(noname)");
            continue;
        }
        int rc = a->probe();
        if (rc == 0) {
            fprintf(stderr, "[offload] selected adapter: %s (type=%s gran=%s)\n",
                    a->name,
                    offload_type_str(a->type),
                    offload_gran_str(a->granularity));
            s_active = a;
            return a;
        }
    }
    /* 不应发生: adapter_null.probe 永远返回 0 */
    fprintf(stderr, "[offload] FATAL: no adapter matched, including null!\n");
    return NULL;
}

offload_adapter_t *offload_active_adapter(void)
{
    if (s_active == NULL)
        return offload_select_adapter();
    return s_active;
}

void offload_set_active_adapter(offload_adapter_t *a)
{
    s_active = a;
}
