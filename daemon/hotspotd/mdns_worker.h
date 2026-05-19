/* mdns_worker.h — HNC v3.8.4 异步 mDNS worker
 *
 * ═══ 设计目标 ═══
 *
 * v3.8.3 及之前,scan_arp 的 re-resolve 路径会同步调 resolve_hostname,
 * 其 mdns 分支最坏阻塞主循环 800ms (popen mdns_resolve -t 800)。
 * 每 60 秒触发一次(re-resolve 条件窗口),不致命,但偶尔会让 WebUI
 * 刷新卡顿、watchdog 观察到主循环 stall、netlink 短暂积压。
 *
 * v3.8.4 引入一个**单线程 worker**处理 re-resolve 的 mDNS 查询。
 * 主线程 scan_arp 不再同步调 resolve_hostname,而是 enqueue 一个任务
 * 到 worker 队列,继续处理 netlink 事件。Worker 独立跑 mDNS 查询,
 * 完成后把结果放到**结果队列**,主线程下次 tick 时 drain。
 *
 * ═══ 关键设计:双队列 + 结果队列模型 ═══
 *
 * - **工作队列 (task queue)**: 主线程 enqueue,worker dequeue
 * - **结果队列 (result queue)**: worker enqueue,主线程 drain
 * - **g_devs 依然是主线程独占**,零 g_devs 锁,零 scan_arp/write_json/nl 改动
 * - Worker 只调 try_mdns_resolve(纯函数,不访问 g_devs)
 * - 主线程 drain_results 时 find_device + 写回 hostname 都在主线程,安全
 *
 * 这是 actor 模型的思路:用消息传递代替共享状态。
 *
 * ═══ 容量和行为 ═══
 *
 * - 工作队列 16 条,满则丢任务(re-resolve 是 "尽力而为",下轮会重试)
 * - 结果队列 16 条,满则丢结果(极罕见,主线程每 tick 都 drain)
 * - 单 worker 线程,串行处理(一次最多 800ms)
 * - 停止时 pthread_join,等最后一个任务完成(最多等 1 秒)
 *
 * ═══ 线程安全 ═══
 *
 * - 两个独立 mutex 分别保护工作队列 / 结果队列
 * - cond 变量只用于工作队列(worker 阻塞等任务)
 * - 主线程 drain_results 是非阻塞的(try_lock 不用,进去就 drain 完就出)
 * - Worker 永远不访问 g_devs / g_ndev / g_dirty / 任何 hotspotd 全局
 * - try_mdns_resolve 本身是无状态的(读 mdns_resolve binary 不访问共享状态)
 *
 * ═══ 不处理的路径 ═══
 *
 * 以下路径依然同步,不走 worker:
 * - scan_arp fast 路径(hnc_resolve_hostname_fast)— 不查 mdns,无需异步
 * - process_pending_mdns(resolve_hostname_dhcp_only)— 只查 dhcp 不查 mdns
 * - 启动时的任何 hostname 查询(单次,无所谓)
 */

#ifndef HNC_MDNS_WORKER_H
#define HNC_MDNS_WORKER_H

#include <stddef.h>

#define HNC_MDNS_QUEUE_SIZE   16
#define HNC_MDNS_MAC_LEN      18
#define HNC_MDNS_IP_LEN       40
#define HNC_MDNS_HOSTNAME_LEN 64
#define HNC_MDNS_SRC_LEN      16

/* ══════════════════════════════════════════════════════════
 * try_mdns_resolve 的函数指针类型
 *
 * Worker 内部调 mDNS 查询时用这个函数指针,而不是直接引用 hotspotd.c 的
 * static try_mdns_resolve。这让 mdns_worker.c 不依赖 hotspotd.c,也让
 * 单元测试可以注入 mock。
 *
 * 生产环境 hotspotd 启动时调 hnc_mdns_worker_set_resolve_fn 注入真实函数。
 * ══════════════════════════════════════════════════════════ */
typedef int (*hnc_mdns_resolve_fn)(const char *ip, const char *mac,
                                    char *out, size_t outlen);

/* ══════════════════════════════════════════════════════════
 * 结果结构
 *
 * drain_results 返回的每一条结果。success = 1 表示 mDNS 命中,主线程应
 * 把 hostname/hostname_src 写回 g_devs;success = 0 表示未命中,主线程
 * 应该把对应设备的 hostname_src 标为 "mac"(从上次的标签降级)。
 * ══════════════════════════════════════════════════════════ */
typedef struct {
    char mac[HNC_MDNS_MAC_LEN];
    char hostname[HNC_MDNS_HOSTNAME_LEN];
    char hostname_src[HNC_MDNS_SRC_LEN];
    int  success;
} hnc_mdns_result_t;

/* ══════════════════════════════════════════════════════════
 * API
 * ══════════════════════════════════════════════════════════ */

/* 注入 mdns 解析函数(生产调 hotspotd 的 try_mdns_resolve,测试调 mock)。
 * 必须在 start 之前调用。*/
void hnc_mdns_worker_set_resolve_fn(hnc_mdns_resolve_fn fn);

/* 启动 worker 线程。成功返回 0,失败返回非 0(pthread_create errno)。*/
int hnc_mdns_worker_start(void);

/* 停止 worker:设置 stop flag,broadcast cond,join 线程。
 * 阻塞直到 worker 退出(最多等最后一个任务的 800ms + ε)。
 * 幂等,多次调用无害。*/
void hnc_mdns_worker_stop(void);

/* 主线程 enqueue 一个查询任务。
 * 成功返回 1,队列满返回 0(任务被丢弃,60 秒后下轮 re-resolve 会重试)。
 * 线程安全,非阻塞(mutex 只 lock 极短时间)。*/
int hnc_mdns_worker_enqueue(const char *mac, const char *ip);

/* 主线程从结果队列取出所有完成的结果到 out 数组。
 * 返回取出的条目数(0 到 out_max)。
 * 线程安全,非阻塞。主线程应每 tick 调用一次。*/
int hnc_mdns_worker_drain_results(hnc_mdns_result_t *out, int out_max);

/* 诊断:当前工作队列深度 / 结果队列深度。线程安全。*/
int hnc_mdns_worker_task_count(void);
int hnc_mdns_worker_result_count(void);

#endif /* HNC_MDNS_WORKER_H */
