/* hnc_lsm_loader.h — HNC v5.0 BPF LSM Limit Map Guard 用户态接口
 *
 * 提供给 hotspotd / scheduler 调用的简化 API:
 *   hnc_lsm_init()            — 加载 .bpf.o, populate ctrl, attach LSM
 *   hnc_lsm_update_ifindex()  — 上游变化时切换被保护的 ifindex
 *   hnc_lsm_shutdown()        — detach + close
 *   hnc_lsm_get_status()      — 查状态 (供 OFFLOAD_STATUS 报告)
 *
 * 设计原则:
 *   - 任何失败都不崩,只是把状态切到 FAILED, hotspotd 业务继续
 *   - 不依赖 libbpf 运行时库 (与 adapter_bpf.c 风格一致, 直接 sys_bpf)
 *   - 单实例 (一个 hotspotd 一个 LSM guard)
 *   - 线程安全: init/shutdown 主线程, get_status 任意线程
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef HNC_LSM_LOADER_H
#define HNC_LSM_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* LSM guard 状态机 */
typedef enum {
    HNC_LSM_DISABLED = 0,   /* 未启用: kernel 不支持 / 未 init */
    HNC_LSM_ACTIVE   = 1,   /* attach 成功, 拦截中 */
    HNC_LSM_FAILED   = 2,   /* attach 失败, 已降级 */
} hnc_lsm_state_t;

/* 状态 snapshot, 给 OFFLOAD_STATUS / WebUI */
typedef struct {
    hnc_lsm_state_t state;
    uint32_t        protected_map_id;
    uint32_t        protected_ifindex;
    uint32_t        hotspotd_pid;
    uint64_t        deny_count;       /* 累计 EPERM 拦截次数 */
    uint64_t        allow_count;      /* 累计放行 (含 hotspotd 自己) 次数 */
    int64_t         last_event_ts;    /* unix ts 秒 */
    char            last_caller_comm[16];
    char            fail_reason[128]; /* state=FAILED 时填 */
} hnc_lsm_status_t;

/* ─── API ─────────────────────────────────────────────────────────── */

/* 初始化 LSM guard
 *
 * bpf_object_path:        /data/local/hnc/bpf/hnc_limit_map_guard.bpf.o
 * target_limit_map_path:  /sys/fs/bpf/tethering/map_offload_tether_limit_map
 * initial_ifindex:        要保护的 ifindex (传 0 表示稍后 update)
 *
 * 返回值:
 *   0  = ACTIVE 成功 attach
 *  -1  = FAILED, 状态置 FAILED (查 get_status().fail_reason)
 *  -2  = DISABLED, kernel 不支持 BPF LSM (不致命)
 *
 * 调用方应该在 0 / -1 / -2 三种情况下都 graceful 继续。
 */
int  hnc_lsm_init(const char *bpf_object_path,
                  const char *target_limit_map_path,
                  uint32_t initial_ifindex);

/* 上游 ifindex 变化时调用 (ifindex 0 表示暂时无上游, 等价于 disable 拦截) */
int  hnc_lsm_update_ifindex(uint32_t new_ifindex);

/* 关闭 (detach link, close fds, 停 ringbuf consumer 线程) */
void hnc_lsm_shutdown(void);

/* 查询当前状态 (lock-free 拷贝, 任意线程可调) */
void hnc_lsm_get_status(hnc_lsm_status_t *out);

/* 序列化 LSM 状态为 JSON 片段 (不含外层 {})
 * 例如: "lsm":{"state":"active","deny_count":42,...}
 *
 * 返实际写入字节 (不含 NUL), buf 不足返 -1
 *
 * 这是个简化路径, 给 scheduler.c summary_to_json 拼接用 */
int  hnc_lsm_status_to_json_fragment(const hnc_lsm_status_t *st,
                                      char *buf, size_t buf_size);

#endif /* HNC_LSM_LOADER_H */
