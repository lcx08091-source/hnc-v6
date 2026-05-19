/* scheduler.h — HNC v5.0 offload 调度核心
 *
 * 职责:
 *   1) 启动时选举 + 初始化 adapter (失败回落 null)
 *   2) 维护"受限设备 mac 集合", 计数从 0→>0 时触发 adapter->disable_*,
 *      从 >0→0 时触发 adapter->restore_*
 *   3) 探测当前热点上游 ifindex (v5.0 alpha.1: 默认路由 oif)
 *   4) 启动 offload_worker pthread, 周期 (60s) 或显式触发 refresh_active
 *   5) 提供 summary 接口给 control socket / Go API
 *
 * 线程安全:
 *   - 所有公开函数加 sched.lock 保护内部状态
 *   - worker 线程独立 lock (sched.worker_lock + cond), 避免与主调度互锁
 *   - adapter->status() 是 lock-free 读 cache, 调度内部不需锁 adapter
 *
 * 与 hotspotd.c 的接口:
 *   - main() 早期调 hnc_scheduler_init()
 *   - 主 select() 循环加 control 命令分支:
 *       "OFFLOAD_NOTIFY_LIMIT <mac> <0|1>"  → notify_device_limit_changed
 *       "OFFLOAD_REFRESH"                    → request_refresh
 *       "OFFLOAD_STATUS"                     → get_summary + 序列化
 *       "OFFLOAD_DISABLE_GLOBAL"             → 强制全局 disable
 *       "OFFLOAD_RESTORE_GLOBAL"             → 强制全局 restore
 *   - SIGTERM/退出前调 hnc_scheduler_shutdown()
 *
 * 与 apply_device_rule.sh 的接口:
 *   - tc HTB 规则添加成功后:
 *       echo "OFFLOAD_NOTIFY_LIMIT $MAC 1" | socat - UNIX-CONNECT:/data/local/hnc/run/api.sock
 *   - tc HTB 规则删除成功后:
 *       echo "OFFLOAD_NOTIFY_LIMIT $MAC 0" | ...
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef HNC_SCHEDULER_H
#define HNC_SCHEDULER_H

#include <stdint.h>
#include <stddef.h>

#include "offload/adapter.h"

/* ══════════════════════════════════════════════════════════
 * 配置常量
 * ══════════════════════════════════════════════════════════ */

/* 受限设备 mac 集合最大容量
 * 256 已足够覆盖任何热点真实场景 (Android 通常上限 10 设备/热点) */
#define HNC_SCHED_MAX_LIMITED_DEVICES   256

/* 上游 ifname 缓存长度 */
#define HNC_SCHED_IFNAME_LEN            16

/* offload_worker 周期 refresh 间隔 (秒)
 * 与 hotspotd 主循环 60s health check 节奏对齐, 避免双重慢任务 */
#define HNC_SCHED_REFRESH_INTERVAL_SEC  60

/* ══════════════════════════════════════════════════════════
 * Summary 结构 (control socket 返回 + Go API 序列化)
 * ══════════════════════════════════════════════════════════ */

typedef struct {
    /* Adapter 元数据 */
    char     adapter_name[32];
    int      adapter_type;        /* offload_type_t cast */
    int      adapter_gran;        /* offload_granularity_t cast */

    /* Adapter 实时状态 (来自 adapter->status()) */
    int      active;
    int64_t  last_refresh_ts;
    uint64_t last_delta_bytes;
    int      globally_disabled;
    int      disabled_upstream_count;
    int      disabled_upstream_ifindex[8];

    /* Scheduler 内部状态 */
    int      limited_device_count;
    int      primary_upstream_ifindex;
    char     primary_upstream_ifname[HNC_SCHED_IFNAME_LEN];

    /* Worker 线程健康度 */
    int      worker_running;
    int64_t  worker_last_refresh_ts;
    /* refresh 完成计数, 单调递增。判断 "worker 是否真的跑了一轮" 比时间戳
     * 可靠 (后者秒精度, 同一秒内多次 refresh 看不出变化) */
    int64_t  worker_refresh_count;
} hnc_offload_summary_t;

/* ══════════════════════════════════════════════════════════
 * 公开 API (主线程调)
 * ══════════════════════════════════════════════════════════ */

/* 初始化: 探测 + 选举 + adapter init + 启动 worker 线程
 *
 * 返 0 = 成功 (即使 adapter 是 null 也算成功, scheduler 始终可用)
 * 返非 0 = 严重错误 (worker 线程无法启动等)
 */
int  hnc_scheduler_init(void);

/* 关闭: 停 worker + adapter shutdown
 * 可重入, 多次调用安全
 */
void hnc_scheduler_shutdown(void);

/* ── 通知 ── */

/* 设备 mac 的限速规则发生变化
 *   is_limited=1: tc 规则刚添加 / 已存在
 *   is_limited=0: tc 规则刚删除 / 不存在
 *
 * scheduler 维护 mac 集合 (添加/删除幂等), 集合规模从 0→>0 触发
 * adapter->disable_*, 从 >0→0 触发 adapter->restore_*
 *
 * mac 大小写不敏感, 内部统一小写存储
 *
 * 不阻塞 (adapter 操作 < 1ms 完成)
 */
void hnc_scheduler_notify_device_limit_changed(const char *mac, int is_limited);

/* 显式请求 refresh_active (会唤醒 worker 立刻跑 5s 双采样)
 * 不阻塞调用方, worker 异步完成
 */
void hnc_scheduler_request_refresh(void);

/* ── 强制操作 (control 命令直接驱动) ── */

/* 强制全局 disable, 不管 limited_count 状态 */
offload_err_t hnc_scheduler_force_disable_global(void);
/* 强制全局 restore, 同时清空 scheduler 内部 limited 集合 */
offload_err_t hnc_scheduler_force_restore_global(void);

/* ── 查询 ── */

/* 拿当前 summary, 非阻塞读
 * 输出固定结构, JSON 序列化由调用方 (hnc_httpd) 完成
 */
void hnc_scheduler_get_summary(hnc_offload_summary_t *out);

/* 序列化 summary 为 JSON 单行, 写入 buf
 * 返实际字节数 (不含 NUL), buf 不足返 -1
 *
 * 用于 control socket OFFLOAD_STATUS 命令的响应,
 * Go httpd 也直接调它而不是再序列化一遍
 */
int  hnc_scheduler_summary_to_json(const hnc_offload_summary_t *s,
                                    char *buf, size_t buf_size);

#endif /* HNC_SCHEDULER_H */
