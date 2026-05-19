/* tools/sched_test.c — scheduler 端到端测试
 *
 * 不接入 hotspotd, 直接驱动 scheduler API, 用于:
 *   1) host 上验证 notify → adapter 触发链
 *   2) RMX5010 上不打扰 hotspotd 的情况下复现 scheduler 行为
 *   3) v5.0 alpha.1 集成到 hotspotd.c 之前的最后一道关
 *
 * 用法:
 *   sched_test                    跑全套场景, 阻塞 ~15s
 *   sched_test --no-sleep         跳过 worker refresh 验证 (~1s)
 *   sched_test --quiet            只输出最终 PASS/FAIL
 *
 * 流程:
 *   1) init
 *   2) summary (验证 limited=0, primary_upstream 探测到)
 *   3) notify aa:bb:cc:dd:ee:01 limited=1 → 期望触发 disable_*
 *   4) notify aa:bb:cc:dd:ee:02 limited=1 → 不触发 (count 1→2)
 *   5) notify aa:bb:cc:dd:ee:01 limited=0 → 不触发 (count 2→1)
 *   6) notify aa:bb:cc:dd:ee:02 limited=0 → 期望触发 restore_*
 *   7) request_refresh + sleep 7s → 看 worker 跑完 refresh
 *   8) summary 验证 worker_last_refresh_ts 更新
 *   9) shutdown
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "../scheduler.h"
#include "../platform.h"
#include "../offload/adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_quiet = 0;
static int g_no_sleep = 0;
static int g_failures = 0;

#define LOG(...) do { if (!g_quiet) fprintf(stderr, __VA_ARGS__); } while (0)

#define ASSERT(cond, msg) do {                                  \
    if (!(cond)) {                                              \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
        g_failures++;                                           \
    } else {                                                    \
        LOG("PASS: %s\n", msg);                                 \
    }                                                           \
} while (0)

static void dump_summary(const char *tag)
{
    if (g_quiet) return;
    hnc_offload_summary_t s;
    hnc_scheduler_get_summary(&s);
    char buf[1024];
    int n = hnc_scheduler_summary_to_json(&s, buf, sizeof(buf));
    if (n < 0) {
        fprintf(stderr, "  [%s] (json overflow)\n", tag);
        return;
    }
    fprintf(stderr, "  [%s] %s\n", tag, buf);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0)    g_quiet = 1;
        if (strcmp(argv[i], "--no-sleep") == 0) g_no_sleep = 1;
    }

    LOG("=== sched_test ===\n\n");

    /* === 1. init === */
    LOG("[1] init\n");
    int rc = hnc_scheduler_init();
    ASSERT(rc == 0, "init returns 0");

    /* === 2. baseline summary === */
    LOG("\n[2] baseline summary\n");
    dump_summary("init");
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 0, "limited_device_count == 0 at boot");
        ASSERT(s.adapter_name[0] != '\0', "adapter name not empty");
        ASSERT(s.worker_running == 1, "worker_running == 1");
    }

    /* === 3. notify dev1 limited === */
    LOG("\n[3] notify dev1 limit=1 (count 0→1, expect disable trigger)\n");
    hnc_scheduler_notify_device_limit_changed("aa:bb:cc:dd:ee:01", 1);
    dump_summary("after dev1+");
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 1, "count after dev1+ == 1");
    }

    /* === 4. notify dev2 limited (no trigger) === */
    LOG("\n[4] notify dev2 limit=1 (count 1→2, no trigger)\n");
    hnc_scheduler_notify_device_limit_changed("AA:BB:CC:DD:EE:02", 1);
    dump_summary("after dev2+");
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 2, "count after dev2+ == 2");
    }

    /* === 5. dedup: notify dev1 limited again === */
    LOG("\n[5] notify dev1 limit=1 again (dedup, count stays 2)\n");
    hnc_scheduler_notify_device_limit_changed("aa:bb:cc:dd:ee:01", 1);
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 2, "dedup add: count stays 2");
    }

    /* === 6. case-insensitive: notify dev1 unlimited (mixed case) === */
    LOG("\n[6] notify dev1 limit=0 (case-insensitive remove)\n");
    hnc_scheduler_notify_device_limit_changed("Aa:Bb:Cc:Dd:Ee:01", 0);
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 1, "count after dev1- == 1");
    }

    /* === 7. notify dev2 unlimited (count 1→0, expect restore trigger) === */
    LOG("\n[7] notify dev2 limit=0 (count 1→0, expect restore trigger)\n");
    hnc_scheduler_notify_device_limit_changed("aa:bb:cc:dd:ee:02", 0);
    dump_summary("after dev2-");
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 0, "count after dev2- == 0");
    }

    /* === 8. invalid mac handling === */
    LOG("\n[8] invalid mac (should not crash)\n");
    hnc_scheduler_notify_device_limit_changed("not-a-mac", 1);
    hnc_scheduler_notify_device_limit_changed(NULL, 1);
    hnc_scheduler_notify_device_limit_changed("aa:bb:cc:dd:ee", 1);  /* short */
    {
        hnc_offload_summary_t s;
        hnc_scheduler_get_summary(&s);
        ASSERT(s.limited_device_count == 0, "invalid macs ignored");
    }

    /* === 9. force operations === */
    LOG("\n[9] force disable_global / restore_global\n");
    offload_err_t e1 = hnc_scheduler_force_disable_global();
    offload_err_t e2 = hnc_scheduler_force_restore_global();
    LOG("  force_disable_global: %s\n", offload_err_str(e1));
    LOG("  force_restore_global: %s\n", offload_err_str(e2));
    /* null adapter 返 OK; bpf adapter 在无 entry 时也返 OK */
    ASSERT(e1 == OFFLOAD_OK || e1 == OFFLOAD_ENOTSUP,
           "force_disable_global ok or notsup");
    ASSERT(e2 == OFFLOAD_OK || e2 == OFFLOAD_ENOTSUP,
           "force_restore_global ok or notsup");

    /* === 10. worker refresh === */
    if (!g_no_sleep) {
        LOG("\n[10] request worker refresh + wait 7s for it to complete...\n");
        int64_t before_count;
        {
            hnc_offload_summary_t s;
            hnc_scheduler_get_summary(&s);
            before_count = s.worker_refresh_count;
        }
        hnc_scheduler_request_refresh();
        sleep(7);
        {
            hnc_offload_summary_t s;
            hnc_scheduler_get_summary(&s);
            LOG("  worker_refresh_count: %lld → %lld\n",
                (long long)before_count, (long long)s.worker_refresh_count);
            ASSERT(s.worker_refresh_count > before_count,
                   "worker refresh count increased");
        }
    } else {
        LOG("\n[10] worker refresh: SKIPPED (--no-sleep)\n");
    }

    /* === 11. shutdown === */
    LOG("\n[11] shutdown\n");
    hnc_scheduler_shutdown();
    /* 二次调用应安全 */
    hnc_scheduler_shutdown();
    LOG("  (shutdown called twice, no crash)\n");

    LOG("\n=== Done. failures=%d ===\n", g_failures);
    if (g_quiet) printf("%s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
