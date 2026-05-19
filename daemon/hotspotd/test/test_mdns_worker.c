/* test_mdns_worker.c — HNC v3.8.4 worker 单元测试
 *
 * 测试覆盖:
 *   - 基本 enqueue / drain
 *   - start / stop 幂等
 *   - 工作队列满丢任务
 *   - 多任务并发 (worker 串行处理)
 *   - stop 时排空剩余任务
 *   - resolve_fn 未注入时 success=0
 *   - 结果顺序(FIFO)
 *   - 压力:填满 → 抽干 → 再填
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include "mdns_worker.h"

static int pass = 0, fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ✓ %s\n", name); pass++; } \
    else { printf("  ✗ %s\n", name); fail++; } \
} while(0)

/* ══════════════════════════════════════════════════════════
 * Mock mDNS 解析函数
 * ══════════════════════════════════════════════════════════ */
static int g_mock_calls = 0;
static int g_mock_delay_us = 0;

static int mock_resolve(const char *ip, const char *mac, char *out, size_t outlen) {
    (void)ip;
    __sync_fetch_and_add(&g_mock_calls, 1);
    if (g_mock_delay_us > 0) usleep(g_mock_delay_us);

    /* 根据 MAC 最后一字节决定返回什么 */
    if (mac[strlen(mac) - 1] == 'x') {
        return 0;  /* 模拟失败 */
    }
    snprintf(out, outlen, "Host-%s", mac);
    return 1;
}

static void reset_mock(void) {
    g_mock_calls = 0;
    g_mock_delay_us = 0;
}

/* 等到 worker 处理完 task_count 个任务(或超时) */
static int wait_for_results(int expected, int timeout_ms) {
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        if (hnc_mdns_worker_result_count() >= expected &&
            hnc_mdns_worker_task_count() == 0) {
            return 1;
        }
        usleep(10 * 1000);
        elapsed += 10;
    }
    return 0;
}

int main(void) {
    hnc_mdns_result_t results[32];
    int n;

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 1: 未启动时的行为 ──\n");
    /* ──────────────────────────────────────────────────── */

    /* enqueue 在未启动时返回 0 */
    int rc = hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:01", "10.0.0.1");
    CHECK(rc == 0, "T01: 未启动 enqueue 返回 0");

    /* drain 在未启动时返回 0 */
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 0, "T02: 未启动 drain 返回 0");

    /* stop 未启动是幂等的(不 crash) */
    hnc_mdns_worker_stop();
    CHECK(1, "T03: 未启动 stop 不 crash");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 2: 基本启动和 enqueue/drain ──\n");
    /* ──────────────────────────────────────────────────── */

    reset_mock();
    hnc_mdns_worker_set_resolve_fn(mock_resolve);
    rc = hnc_mdns_worker_start();
    CHECK(rc == 0, "T04: start 返回 0");

    /* 启动后立即 count=0 */
    CHECK(hnc_mdns_worker_task_count() == 0, "T05: 启动后 task_count=0");
    CHECK(hnc_mdns_worker_result_count() == 0, "T06: 启动后 result_count=0");

    /* Enqueue 1 任务 */
    rc = hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:01", "10.0.0.1");
    CHECK(rc == 1, "T07: enqueue 返回 1");

    /* 等 worker 处理(mock 无延时,应该 < 50ms) */
    wait_for_results(1, 500);
    CHECK(g_mock_calls == 1, "T08: mock 被调用 1 次");

    /* Drain 结果 */
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 1, "T09: drain 返回 1 结果");
    CHECK(strcmp(results[0].mac, "aa:bb:cc:dd:ee:01") == 0, "T10: 结果 MAC 正确");
    CHECK(results[0].success == 1, "T11: 结果 success=1");
    CHECK(strncmp(results[0].hostname, "Host-", 5) == 0, "T12: 结果 hostname 正确");
    CHECK(strcmp(results[0].hostname_src, "mdns") == 0, "T13: 结果 src=mdns");

    /* Drain 空队列返回 0 */
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 0, "T14: 空队列 drain 返回 0");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 3: 失败任务 ──\n");
    /* ──────────────────────────────────────────────────── */

    /* MAC 以 x 结尾,mock 返回 0 */
    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:0x", "10.0.0.2");
    wait_for_results(1, 500);
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 1 && results[0].success == 0, "T15: 失败任务 success=0");
    CHECK(strcmp(results[0].hostname_src, "mac") == 0, "T16: 失败任务 src=mac");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 4: 多任务串行处理 (FIFO) ──\n");
    /* ──────────────────────────────────────────────────── */

    reset_mock();

    /* Enqueue 5 个任务 */
    for (int i = 0; i < 5; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:dd:ee:%02d", i);
        hnc_mdns_worker_enqueue(mac, "10.0.0.1");
    }
    CHECK(1, "T17: enqueue 5 个任务");

    wait_for_results(5, 1000);
    CHECK(g_mock_calls == 5, "T18: mock 被调用 5 次");

    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 5, "T19: drain 5 个结果");

    /* 验证 FIFO 顺序 */
    int order_ok = 1;
    for (int i = 0; i < 5; i++) {
        char expected[18];
        snprintf(expected, sizeof(expected), "aa:bb:cc:dd:ee:%02d", i);
        if (strcmp(results[i].mac, expected) != 0) {
            order_ok = 0;
            break;
        }
    }
    CHECK(order_ok, "T20: 结果按 FIFO 顺序");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 5: 队列满丢任务 ──\n");
    /* ──────────────────────────────────────────────────── */

    reset_mock();
    g_mock_delay_us = 100 * 1000;  /* 100ms 每个,确保任务堆积 */

    /* 第一个任务立即被 worker 取走开始处理(不占队列) */
    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:f0", "10.0.0.1");
    usleep(10 * 1000);  /* 等 worker 取走 */

    /* 填满 16 个槽 */
    int enqueued = 0;
    for (int i = 0; i < 20; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:dd:ee:%02x", i + 0x10);
        if (hnc_mdns_worker_enqueue(mac, "10.0.0.1")) {
            enqueued++;
        }
    }
    CHECK(enqueued == 16, "T21: 队列满时最多接受 16 个(实际接受了一些)");

    /* 等全部处理完 */
    int got = 0;
    for (int i = 0; i < 30 && got < enqueued + 1; i++) {
        usleep(100 * 1000);
        got += hnc_mdns_worker_drain_results(results, 32);
    }
    CHECK(got >= enqueued + 1, "T22: 所有接受的任务都被处理");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 6: stop 时排空剩余任务 ──\n");
    /* ──────────────────────────────────────────────────── */

    reset_mock();
    g_mock_delay_us = 20 * 1000;  /* 20ms */

    /* Enqueue 3 个任务 */
    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:a1", "10.0.0.1");
    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:a2", "10.0.0.1");
    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:a3", "10.0.0.1");

    /* 立即 stop — worker 应该把剩余任务处理完再退出 */
    hnc_mdns_worker_stop();

    /* Stop 后 drain 应该能拿到所有结果 */
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 3, "T23: stop 后剩余任务都完成(drain 3)");
    CHECK(g_mock_calls == 3, "T24: mock 被调用 3 次");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 7: 重启(start-stop-start) ──\n");
    /* ──────────────────────────────────────────────────── */

    reset_mock();
    g_mock_delay_us = 0;

    rc = hnc_mdns_worker_start();
    CHECK(rc == 0, "T25: 重新 start 返回 0");

    /* 再次 start 应该幂等 */
    rc = hnc_mdns_worker_start();
    CHECK(rc == 0, "T26: 重复 start 幂等返回 0");

    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:b1", "10.0.0.1");
    wait_for_results(1, 500);
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 1 && results[0].success == 1, "T27: 重启后功能正常");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 8: 结果队列 out_max 限制 ──\n");
    /* ──────────────────────────────────────────────────── */

    /* Enqueue 5 个任务,drain 时 out_max=2 */
    reset_mock();
    for (int i = 0; i < 5; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:dd:ee:c%d", i);
        hnc_mdns_worker_enqueue(mac, "10.0.0.1");
    }
    wait_for_results(5, 500);

    n = hnc_mdns_worker_drain_results(results, 2);
    CHECK(n == 2, "T28: drain out_max=2 返回 2");

    n = hnc_mdns_worker_drain_results(results, 2);
    CHECK(n == 2, "T29: 第二次 drain out_max=2 返回 2");

    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 1, "T30: 第三次 drain 返回剩下的 1 个");

    /* ──────────────────────────────────────────────────── */
    printf("\n── Section 9: 未注入 resolve_fn ──\n");
    /* ──────────────────────────────────────────────────── */

    hnc_mdns_worker_stop();
    hnc_mdns_worker_set_resolve_fn(NULL);  /* 清空 fn */
    hnc_mdns_worker_start();

    hnc_mdns_worker_enqueue("aa:bb:cc:dd:ee:d1", "10.0.0.1");
    wait_for_results(1, 500);
    n = hnc_mdns_worker_drain_results(results, 32);
    CHECK(n == 1 && results[0].success == 0,
          "T31: 未注入 fn 时所有任务 success=0");

    hnc_mdns_worker_stop();

    /* ──────────────────────────────────────────────────── */
    printf("\n═══ %d passed, %d failed ═══\n", pass, fail);
    /* ──────────────────────────────────────────────────── */
    return fail > 0 ? 1 : 0;
}
