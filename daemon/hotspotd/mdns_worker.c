/* mdns_worker.c — HNC v3.8.4 异步 mDNS worker 实现
 *
 * 见 mdns_worker.h 的设计说明。
 *
 * ═══ 关键实现注意 ═══
 *
 * 1. **锁粒度**: 两个独立 mutex (g_task_lock / g_res_lock),不嵌套。
 *    worker 处理任务时先 dequeue(g_task_lock),释放锁,再调 mdns 查询
 *    (无锁),再 enqueue 结果(g_res_lock)。**任何时刻最多持有 1 个锁**,
 *    不存在死锁可能。
 *
 * 2. **cond 用法**: 只 worker 在 cond_wait,主线程不 wait。
 *    这样避免了"惊群"或多个消费者竞争的复杂度。
 *
 * 3. **stop 时序**: stop flag 设为 1 → broadcast cond → join。
 *    worker 的循环条件是 `while (g_tc == 0 && !g_stop)`,所以 broadcast
 *    后 worker 会立刻重新检查 g_stop 并退出。
 *
 * 4. **未初始化调用保护**: enqueue/drain/count 在 worker 未 start 时
 *    也应该安全(返回 0 / 不崩)。这样 hotspotd.c 的集成可以放心在
 *    start 之前就有代码路径调它们(例如 signal handler 早于 worker
 *    start 触发)。
 *
 * 5. **多次 stop 幂等**: g_started 标志保证 stop 只 join 一次。
 *
 * 6. **mock 注入**: 默认 fn 指针是 NULL。如果 worker 启动时没注入,
 *    worker 会把所有任务标为 success=0。这让单元测试可以不注入 fn
 *    测试"队列机制本身"。
 */

#include "mdns_worker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

/* ══════════════════════════════════════════════════════════
 * 内部数据
 * ══════════════════════════════════════════════════════════ */

typedef struct {
    char mac[HNC_MDNS_MAC_LEN];
    char ip[HNC_MDNS_IP_LEN];
} hnc_mdns_task_t;

/* 工作队列 */
static hnc_mdns_task_t g_task_q[HNC_MDNS_QUEUE_SIZE];
static int g_task_head = 0;
static int g_task_tail = 0;
static int g_task_count = 0;
static pthread_mutex_t g_task_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_task_cond = PTHREAD_COND_INITIALIZER;

/* 结果队列 */
static hnc_mdns_result_t g_res_q[HNC_MDNS_QUEUE_SIZE];
static int g_res_head = 0;
static int g_res_tail = 0;
static int g_res_count = 0;
static pthread_mutex_t g_res_lock = PTHREAD_MUTEX_INITIALIZER;

/* 控制
 *
 * v3.8.4 Gemini 审查 P2: 删除 volatile 修饰 g_stop。
 * g_stop 的读写都在 g_task_lock 保护下(worker 读在 lock 内,
 * stop 函数写在 lock 内),mutex 的 release/unlock 和 acquire/lock
 * 构成 synchronizes-with 关系,保证写入可见性。volatile 既不必要
 * 也不充分(它不提供多线程内存序保证),属于 code smell。
 */
static pthread_t g_worker_thread;
static int g_stop = 0;
static int g_started = 0;
static hnc_mdns_resolve_fn g_resolve_fn = NULL;

/* ══════════════════════════════════════════════════════════
 * API 实现
 * ══════════════════════════════════════════════════════════ */

void hnc_mdns_worker_set_resolve_fn(hnc_mdns_resolve_fn fn) {
    g_resolve_fn = fn;
}

/* ══════════════════════════════════════════════════════════
 * worker 主循环
 * ══════════════════════════════════════════════════════════ */

static void worker_push_result(const char *mac, const char *hostname,
                                const char *src, int success) {
    pthread_mutex_lock(&g_res_lock);
    if (g_res_count >= HNC_MDNS_QUEUE_SIZE) {
        /* 结果队列满,丢结果(理论上不应该发生,主线程每 tick 都 drain)*/
        pthread_mutex_unlock(&g_res_lock);
        return;
    }
    hnc_mdns_result_t *r = &g_res_q[g_res_tail];
    memset(r, 0, sizeof(*r));
    /* v3.8.4 Gemini 审查 P2: strncpy 在 src 长度 >= limit 时不补 \0,
     * 虽然前面 memset 已经把整个结构清零保证了末尾是 \0,但规范做法是
     * 在 strncpy 后显式补 \0,防止未来有人优化掉 memset。*/
    strncpy(r->mac, mac, HNC_MDNS_MAC_LEN - 1);
    r->mac[HNC_MDNS_MAC_LEN - 1] = '\0';
    strncpy(r->hostname, hostname, HNC_MDNS_HOSTNAME_LEN - 1);
    r->hostname[HNC_MDNS_HOSTNAME_LEN - 1] = '\0';
    strncpy(r->hostname_src, src, HNC_MDNS_SRC_LEN - 1);
    r->hostname_src[HNC_MDNS_SRC_LEN - 1] = '\0';
    r->success = success;
    g_res_tail = (g_res_tail + 1) % HNC_MDNS_QUEUE_SIZE;
    g_res_count++;
    pthread_mutex_unlock(&g_res_lock);
}

static void *worker_fn(void *arg) {
    (void)arg;

    while (1) {
        hnc_mdns_task_t task;

        /* 等任务 */
        pthread_mutex_lock(&g_task_lock);
        while (g_task_count == 0 && !g_stop) {
            pthread_cond_wait(&g_task_cond, &g_task_lock);
        }
        if (g_stop) {
            /* hotfix17.8: stop 时立即退出,丢弃待处理队列。
             * mDNS 名称可在下次启动重新解析,不值得阻塞关机/重启路径。 */
            g_task_head = g_task_tail = g_task_count = 0;
            pthread_mutex_unlock(&g_task_lock);
            break;
        }
        task = g_task_q[g_task_head];
        g_task_head = (g_task_head + 1) % HNC_MDNS_QUEUE_SIZE;
        g_task_count--;
        pthread_mutex_unlock(&g_task_lock);

        /* 处理任务(无锁,调 mdns 查询) */
        char hostname[HNC_MDNS_HOSTNAME_LEN] = "";
        int success = 0;
        if (g_resolve_fn) {
            success = g_resolve_fn(task.ip, task.mac,
                                    hostname, sizeof(hostname));
        }

        /* 结果入队(无论成功失败,主线程需要知道这次查询"完了") */
        if (success) {
            worker_push_result(task.mac, hostname, "mdns", 1);
        } else {
            /* 失败:主线程应把 hostname_src 从 "pending" 降级到 "mac"
             * (但主线程会调 find_device 决定实际动作)*/
            worker_push_result(task.mac, "", "mac", 0);
        }
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════
 * start / stop
 * ══════════════════════════════════════════════════════════ */

int hnc_mdns_worker_start(void) {
    if (g_started) return 0;

    /* 重置状态(允许 stop 之后再 start,幂等) */
    g_stop = 0;
    g_task_head = g_task_tail = g_task_count = 0;
    g_res_head = g_res_tail = g_res_count = 0;

    /* v3.8.4 Gemini 审查 P1 修复: 在 pthread_create 之前屏蔽所有**异步**信号
     *
     * 原方案(sigfillset 全屏蔽)有 POSIX UB 风险:
     *   POSIX.1-2017 §2.4.3 明确规定,如果 SIGFPE/SIGILL/SIGSEGV/SIGBUS 在
     *   被 block 时被硬件产生,结果是 undefined。Linux 实现上内核会强制
     *   unblock 并强杀进程,但这是实现细节,不能依赖。
     *
     * 正确做法: sigfillset 后 sigdelset 剔除四个同步信号。
     *
     * 这样 worker 继承的 mask 屏蔽所有异步信号(SIGTERM/SIGINT/SIGUSR1 等)
     * 只投递给主线程,但同步信号(CPU 异常)依然会正常投递给触发它们的线程,
     * 触发标准的 tombstone/core dump 流程。
     *
     * 参考: POSIX.1-2017 "Signal Concepts" 和 Gemini 外部审查反馈。*/
    sigset_t full_set, old_set;
    sigfillset(&full_set);
    sigdelset(&full_set, SIGSEGV);  /* 段错误 */
    sigdelset(&full_set, SIGBUS);   /* 总线错误 */
    sigdelset(&full_set, SIGILL);   /* 非法指令 */
    sigdelset(&full_set, SIGFPE);   /* 浮点/除零 */
    pthread_sigmask(SIG_SETMASK, &full_set, &old_set);

    int rc = pthread_create(&g_worker_thread, NULL, worker_fn, NULL);

    /* 无论 pthread_create 成功失败,恢复主线程原 mask */
    pthread_sigmask(SIG_SETMASK, &old_set, NULL);

    if (rc != 0) {
        return rc;
    }
    g_started = 1;
    return 0;
}

void hnc_mdns_worker_stop(void) {
    if (!g_started) return;

    /* v3.8.4 审查反馈: 立刻把 g_started 置 0,防止重入。
     * 当前代码只在 main() 退出路径调用 stop(单线程),没有真实重入风险,
     * 但提前置 0 是防御性编程,成本为零,避免未来有人在 signal handler
     * 里误调 stop 导致 pthread_join 被调用两次(UB)。*/
    g_started = 0;

    pthread_mutex_lock(&g_task_lock);
    g_stop = 1;
    pthread_cond_broadcast(&g_task_cond);
    pthread_mutex_unlock(&g_task_lock);

    pthread_join(g_worker_thread, NULL);
}

/* ══════════════════════════════════════════════════════════
 * enqueue / drain
 * ══════════════════════════════════════════════════════════ */

int hnc_mdns_worker_enqueue(const char *mac, const char *ip) {
    if (!mac || !ip) return 0;
    if (!g_started) return 0;  /* 未启动,不接受任务 */

    pthread_mutex_lock(&g_task_lock);
    if (g_task_count >= HNC_MDNS_QUEUE_SIZE) {
        pthread_mutex_unlock(&g_task_lock);
        return 0;  /* 队列满,丢任务 */
    }
    hnc_mdns_task_t *t = &g_task_q[g_task_tail];
    memset(t, 0, sizeof(*t));
    /* v3.8.4 Gemini 审查 P2: 规范 strncpy 用法 */
    strncpy(t->mac, mac, HNC_MDNS_MAC_LEN - 1);
    t->mac[HNC_MDNS_MAC_LEN - 1] = '\0';
    strncpy(t->ip,  ip,  HNC_MDNS_IP_LEN - 1);
    t->ip[HNC_MDNS_IP_LEN - 1] = '\0';
    g_task_tail = (g_task_tail + 1) % HNC_MDNS_QUEUE_SIZE;
    g_task_count++;
    pthread_cond_signal(&g_task_cond);
    pthread_mutex_unlock(&g_task_lock);
    return 1;
}

int hnc_mdns_worker_drain_results(hnc_mdns_result_t *out, int out_max) {
    if (!out || out_max <= 0) return 0;

    int drained = 0;
    pthread_mutex_lock(&g_res_lock);
    while (g_res_count > 0 && drained < out_max) {
        out[drained] = g_res_q[g_res_head];
        g_res_head = (g_res_head + 1) % HNC_MDNS_QUEUE_SIZE;
        g_res_count--;
        drained++;
    }
    pthread_mutex_unlock(&g_res_lock);
    return drained;
}

int hnc_mdns_worker_task_count(void) {
    pthread_mutex_lock(&g_task_lock);
    int n = g_task_count;
    pthread_mutex_unlock(&g_task_lock);
    return n;
}

int hnc_mdns_worker_result_count(void) {
    pthread_mutex_lock(&g_res_lock);
    int n = g_res_count;
    pthread_mutex_unlock(&g_res_lock);
    return n;
}
