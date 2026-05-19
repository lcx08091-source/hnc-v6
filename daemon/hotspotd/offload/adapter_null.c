/* offload/adapter_null.c — 兜底 adapter, 永远 probe 成功
 *
 * 在以下场景生效:
 *   1) 平台没有任何已知 offload (老 Pixel / 模拟器 / ROM 自己关掉)
 *   2) 真实 adapter 探测失败 (BPF map 不存在, MTK 模块没装)
 *   3) 用户在 rules.json 强制 mode=tc_only
 *
 * 所有操作返回 OFFLOAD_OK 但什么都不做, scheduler 看到 OK 就继续
 * 走 tc 路径。这样核心调度器不需要知道"没有 offload"是个特殊情况。
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "adapter.h"

#include <string.h>

static int null_probe(void)
{
    return 0;   /* 永远匹配 */
}

static offload_err_t null_init(void)
{
    return OFFLOAD_OK;
}

static void null_shutdown(void)
{
}

static offload_err_t null_self_check(void)
{
    return OFFLOAD_OK;
}

static void null_status(offload_status_t *out)
{
    if (out == NULL)
        return;
    memset(out, 0, sizeof(*out));
    /* active = 0, last_refresh_ts = 0, 所有计数器为 0 */
}

static offload_err_t null_refresh_active(void)
{
    return OFFLOAD_OK;
}

static offload_err_t null_disable_global(void)
{
    return OFFLOAD_OK;
}

static offload_err_t null_restore_global(void)
{
    return OFFLOAD_OK;
}

offload_adapter_t adapter_null = {
    .name             = "null",
    .type             = OFFLOAD_NONE,
    .granularity      = OFFLOAD_GRAN_NONE,

    .probe            = null_probe,
    .init             = null_init,
    .shutdown         = null_shutdown,
    .self_check       = null_self_check,

    .status           = null_status,
    .refresh_active   = null_refresh_active,

    .disable_global   = null_disable_global,
    .restore_global   = null_restore_global,

    /* GRAN_NONE 不实现以下函数, scheduler 不会调 */
    .disable_upstream = NULL,
    .restore_upstream = NULL,
    .disable_device   = NULL,
    .restore_device   = NULL,
};
