/* test_no_discovery.c — v5.31 T3/T4: hotspotd --no-discovery 的可测部分。
 *
 * 方案 G(沿用 test_call_chain.c 的做法): #define HNC_TEST_MODE 后
 * include hotspotd.c, main() 和真实外部函数定义被排除, 只测纯逻辑:
 *   1. count_devices_in_file_at: 数 devices.json 里的设备数(STATUS 用)。
 *      覆盖: 两台正常设备 / hostname 含 "mac":" 字样不误数(mac 字段每台
 *      恰好一次)/ 空对象 / 文件不存在 → 0。
 *   2. g_no_discovery 默认 0(发现模式, 向后兼容)。
 *
 * 「改动前会失败」: v5.30 基线里没有 count_devices_in_file_at, 本文件
 * 在基线上编译失败(undefined reference)。
 *
 * 编译(在 test/unit/test_v531_no_discovery_c.sh 里):
 *   cc -std=c11 -D_GNU_SOURCE -o test_no_discovery test_no_discovery.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HNC_TEST_MODE 1
#include "../hotspotd.c"

/* mock 定义(替换被 HNC_TEST_MODE 屏蔽的真实定义; 同 test_call_chain.c) */
static int try_mdns_resolve(const char *ip, const char *mac,
                            char *out, size_t outlen) {
    (void)ip; (void)mac; (void)out; (void)outlen;
    return 0;
}
static int try_ns_dhcp_resolve(const char *mac, char *out, size_t outlen) {
    (void)mac; (void)out; (void)outlen;
    return 0;
}

/* offload 调度器桩(真实实现在 scheduler.c, 会拖 BPF 依赖; 本测试不碰它) */
int hnc_scheduler_init(void) { return -1; }
void hnc_scheduler_shutdown(void) {}
void hnc_scheduler_notify_device_limit_changed(const char *mac, int f) {
    (void)mac; (void)f;
}
void hnc_scheduler_request_refresh(void) {}
offload_err_t hnc_scheduler_force_disable_global(void) { return OFFLOAD_EEMPTY; }
offload_err_t hnc_scheduler_force_restore_global(void) { return OFFLOAD_EEMPTY; }
void hnc_scheduler_get_summary(hnc_offload_summary_t *out) {
    if (out) memset(out, 0, sizeof(*out));
}
int hnc_scheduler_summary_to_json(const hnc_offload_summary_t *s,
                                  char *buf, size_t cap) {
    (void)s; (void)buf; (void)cap;
    return -1;
}
const char *offload_err_str(offload_err_t e) { (void)e; return "STUB"; }
int hnc_mdns_worker_enqueue(const char *mac, const char *ip) {
    (void)mac; (void)ip;
    return -1;
}

static int g_fail = 0;

static void check(const char *name, int got, int want) {
    if (got != want) {
        printf("  FAIL %s: got %d want %d\n", name, got, want);
        g_fail++;
    } else {
        printf("  ok %s = %d\n", name, got);
    }
}

static void write_tmp(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror("write_tmp"); exit(2); }
    fputs(content, f);
    fclose(f);
}

int main(void) {
    const char *dir = getenv("TMPDIR");
    char p1[512], p2[512], p3[512];
    if (!dir || !*dir) dir = "/tmp";
    snprintf(p1, sizeof(p1), "%s/ndev_two.json", dir);
    snprintf(p2, sizeof(p2), "%s/ndev_odd.json", dir);
    snprintf(p3, sizeof(p3), "%s/ndev_empty.json", dir);

    /* 1) 两台设备: 每个 mac 字段数一次, key 里的 MAC 不多算 */
    write_tmp(p1,
        "{\"aa:bb:cc:dd:ee:01\":{\"ip\":\"192.168.43.101\",\"mac\":\"aa:bb:cc:dd:ee:01\"},"
        "\"aa:bb:cc:dd:ee:02\":{\"ip\":\"192.168.43.102\",\"mac\":\"aa:bb:cc:dd:ee:02\"}}");
    check("两台设备", count_devices_in_file_at(p1), 2);

    /* 2) hostname 恰好含 "mac":" 字样: 不多数(hostname 里是转义的, 真实场景
     *    是 hostname 含引号; 本用例验证只有字段级的 mac 被数) */
    write_tmp(p2,
        "{\"aa:bb:cc:dd:ee:01\":{\"ip\":\"1.2.3.4\",\"mac\":\"aa:bb:cc:dd:ee:01\","
        "\"hostname\":\"my \\\"mac\\\":\\\"x\",\"hostname_src\":\"manual\"}}");
    check("hostname 含引号不误数", count_devices_in_file_at(p2), 1);

    /* 3) 空对象 / 不存在 */
    write_tmp(p3, "{}");
    check("空对象", count_devices_in_file_at(p3), 0);
    check("文件不存在", count_devices_in_file_at("/nonexistent/xx.json"), 0);

    /* 4) g_no_discovery 默认关(向后兼容: 不带参数行为与 v5.30 一致) */
    check("默认发现模式", g_no_discovery, 0);

    printf(g_fail ? "FAIL: %d\n" : "OK test_no_discovery\n", g_fail);
    return g_fail ? 1 : 0;
}
