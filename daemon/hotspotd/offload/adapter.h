/* offload/adapter.h — HNC v5.0 硬件 offload 抽象层接口
 *
 * 动机:
 *   v4.x 在 SD8 Elite + ColorOS 16 上验证了 tc clsact 优先级足够高,
 *   BPF tether offload 不会真旁路限速。但其他 ROM(HyperOS/PixelOS)
 *   和其他 SoC(MTK/Exynos/Kirin) 上 offload 路径可能更激进,tc 看
 *   不到包。v5.0 引入这个抽象层,让核心调度器在不同平台用统一接口
 *   触发"降级到 slow path"。
 *
 * 设计原则:
 *   1) 接口稳定,实现可换。adapter_bpf / adapter_ppe / adapter_nss /
 *      adapter_null 都符合 offload_adapter_t 契约,scheduler 不知道
 *      下面是哪种硬件。
 *   2) 探测优先级。多个 adapter 同时 probe 成功时,按 g_adapters[]
 *      数组顺序选第一个返回 0 的(adapter_null 永远在最后兜底)。
 *   3) 操作幂等。disable_* / restore_* 重复调用不应该爆炸,scheduler
 *      会因 health check 多次触发同一操作。
 *   4) 错误码统一。所有操作返回 OFFLOAD_OK / OFFLOAD_E*,不返回
 *      负数 errno,不返回 -1,日志在 adapter 内部打不向调用方传 errno。
 *   5) 热路径零阻塞。is_active / get_stats 必须 < 1ms 返回(读 cache)。
 *      真正的耗时采样由 scheduler 周期触发 refresh_*,adapter 内部
 *      维护 cache。
 *
 * v5.0 alpha.1 状态:
 *   - adapter_null:        ✅ 实现
 *   - adapter_bpf:         🚧 PER_UPSTREAM 模式实现中
 *   - adapter_ppe (MTK):   ⏳ v5.1 占位
 *   - adapter_nss (三星):  ⏳ v5.2 占位
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef HNC_OFFLOAD_ADAPTER_H
#define HNC_OFFLOAD_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* ══════════════════════════════════════════════════════════
 * 错误码
 * ══════════════════════════════════════════════════════════ */
typedef enum {
    OFFLOAD_OK            = 0,
    OFFLOAD_ENOTSUP       = 1,    /* adapter 不支持此操作(粒度不匹配等) */
    OFFLOAD_EPERM         = 2,    /* 权限不足(SELinux 拒绝 / 非 root) */
    OFFLOAD_EINVAL        = 3,    /* 参数非法(ifindex 不存在等) */
    OFFLOAD_ENOENT        = 4,    /* 资源不存在(map 文件被删等) */
    OFFLOAD_EAGAIN        = 5,    /* 暂时不可用(需稍后重试) */
    OFFLOAD_EINTERNAL     = 99,   /* 内部错误(syscall 异常等) */
} offload_err_t;

const char *offload_err_str(offload_err_t e);

/* ══════════════════════════════════════════════════════════
 * Adapter 类型与粒度
 * ══════════════════════════════════════════════════════════ */
typedef enum {
    OFFLOAD_NONE          = 0,    /* 无 offload, 纯 tc 路径 */
    OFFLOAD_QCOM_BPF      = 1,    /* 高通 + AOSP BPF tethering */
    OFFLOAD_MTK_PPE       = 2,    /* 联发科 PPE/HNAT */
    OFFLOAD_SAMSUNG_NSS   = 3,    /* 三星 NSS */
    OFFLOAD_HISI_HINAT    = 4,    /* 华为 HiNAT */
    OFFLOAD_UNKNOWN       = 99,   /* 探测到 offload 但不认识 */
} offload_type_t;

typedef enum {
    OFFLOAD_GRAN_NONE         = 0,    /* 不支持 bypass(adapter_null) */
    OFFLOAD_GRAN_GLOBAL       = 1,    /* 只能整体开关 */
    OFFLOAD_GRAN_PER_UPSTREAM = 2,    /* 按上游 ifindex */
    OFFLOAD_GRAN_PER_DEVICE   = 3,    /* 按设备 IP/MAC */
} offload_granularity_t;

const char *offload_type_str(offload_type_t t);
const char *offload_gran_str(offload_granularity_t g);

/* ══════════════════════════════════════════════════════════
 * Adapter 状态(scheduler 用于聚合展示给前端)
 * ══════════════════════════════════════════════════════════ */
typedef struct {
    /* offload 是否在主动转发流量(基于 stats 增长判断,需 refresh_active 周期更新) */
    int active;
    /* 最近一次 refresh_active 完成的时间戳(秒);0 = 从未刷新 */
    int64_t last_refresh_ts;
    /* 最近一次双采样的字节增量(rx + tx 总和) */
    uint64_t last_delta_bytes;
    /* 当前被 disable 的上游 ifindex 列表(per-upstream 模式) */
    int disabled_upstream_count;
    int disabled_upstream_ifindex[8];
    /* 全局 disable 是否生效(global 模式) */
    int globally_disabled;
} offload_status_t;

/* ══════════════════════════════════════════════════════════
 * Adapter 接口
 *
 * 函数指针为 NULL 表示该操作不支持。scheduler 调用前必须检查。
 * 简化模式: scheduler 只调与 granularity 匹配的函数,例如
 * granularity==PER_UPSTREAM 时只调 disable_upstream/restore_upstream,
 * 不调 disable_device/restore_device。
 * ══════════════════════════════════════════════════════════ */
typedef struct offload_adapter {
    /* 静态元数据(由 adapter 实现填) */
    const char            *name;            /* "bpf" / "ppe" / "nss" / "null" */
    offload_type_t         type;
    offload_granularity_t  granularity;

    /* ── 生命周期 ──
     * probe()    冷查询: 此 adapter 是否匹配当前平台。
     *            返回 0 = 匹配, 非 0 = 不匹配。不应有副作用,不开 fd。
     * init()     已被选中后调用。打开 fd / 申请资源。
     *            返回 OFFLOAD_OK 或具体错误。失败时 scheduler 会回落 null。
     * shutdown() 关闭资源。daemon 退出前调用。可重入。
     */
    int           (*probe)(void);
    offload_err_t (*init)(void);
    void          (*shutdown)(void);

    /* ── 兼容性自检 ──
     * 在 init() 之后调用一次,验证 map schema / 内核接口与编译期假设一致。
     * 返回 OFFLOAD_OK = 兼容, OFFLOAD_EINTERNAL = schema 漂移需禁用。
     */
    offload_err_t (*self_check)(void);

    /* ── 状态查询(热路径,必须 < 1ms 读 cache) ── */
    void          (*status)(offload_status_t *out);

    /* ── 周期刷新(调用方控制频率,通常 30s 一次) ──
     * refresh_active() 内部允许 sleep 5s 做 stats 双采样。
     * scheduler 在专门的 worker 线程或定时器中调用,不阻塞主循环。
     */
    offload_err_t (*refresh_active)(void);

    /* ── Global 操作(GLOBAL 及以上粒度都应实现) ── */
    offload_err_t (*disable_global)(void);
    offload_err_t (*restore_global)(void);

    /* ── Per-upstream 操作(PER_UPSTREAM 及以上粒度) ── */
    offload_err_t (*disable_upstream)(int ifindex);
    offload_err_t (*restore_upstream)(int ifindex);

    /* ── Per-device 操作(仅 PER_DEVICE 粒度) ──
     * mac:  6 字节, NULL = 不按 MAC 匹配
     * ip4:  IPv4 地址(网络字节序), 0 = 不按 v4 匹配
     * ip6:  NULL = 不按 v6 匹配
     * 三个参数至少一个非空,否则返回 OFFLOAD_EINVAL。
     */
    offload_err_t (*disable_device)(const uint8_t *mac,
                                    uint32_t ip4,
                                    const struct in6_addr *ip6);
    offload_err_t (*restore_device)(const uint8_t *mac,
                                    uint32_t ip4,
                                    const struct in6_addr *ip6);
} offload_adapter_t;

/* ══════════════════════════════════════════════════════════
 * 注册表 + 选举
 *
 * g_adapters[] 是 adapter.c 里编译期定义的 NULL-terminated 数组,
 * 顺序就是 probe 优先级。adapter_null 永远在最后,保证选举一定有结果。
 *
 * 典型使用:
 *
 *   offload_adapter_t *a = offload_select_adapter();
 *   if (a->init() != OFFLOAD_OK) { ... fallback ... }
 *   if (a->granularity >= OFFLOAD_GRAN_PER_UPSTREAM)
 *       a->disable_upstream(ifindex);
 * ══════════════════════════════════════════════════════════ */
extern offload_adapter_t *g_adapters[];   /* NULL-terminated */

/* 遍历 g_adapters 调 probe(), 返回第一个匹配的;
 * adapter_null 永远兜底,所以返回值永远非 NULL。
 *
 * 副作用: 在 hnc_log 中记录选举结果。
 */
offload_adapter_t *offload_select_adapter(void);

/* 返回当前选定的 adapter(必须先调过 offload_select_adapter)。
 * 在 scheduler 模块缓存,避免重复选举。
 */
offload_adapter_t *offload_active_adapter(void);

/* 设置当前 adapter(测试用 / 命令行强制覆盖)。
 * 传 NULL 重置为下次调用 offload_active_adapter() 时重新选举。
 */
void offload_set_active_adapter(offload_adapter_t *a);

#endif /* HNC_OFFLOAD_ADAPTER_H */
