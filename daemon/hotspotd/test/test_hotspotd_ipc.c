/* test_hotspotd_ipc.c — v5.33: 只剩硬件加速兜底 + 控制接口的 hotspotd。
 *
 * 沿用方案 G: #define HNC_TEST_MODE 后 include hotspotd.c, main() / 打开 socket /
 * 信号 / PID 文件被排除, 测真实的 handle_client / nl_process /
 * count_devices_in_file_at(调度器用桩记调用次数):
 *   1. count_devices_in_file_at: 两台设备 / hostname 含 "mac":" 字样不误数 /
 *      空对象 / 文件不存在。
 *   2. 控制接口(socketpair 喂真实 handle_client):
 *      REFRESH → touch run/devices.refresh(Go 写者看到就全量扫), 回 OK:queued;
 *      STATUS  → running:1 devices:<数 devices.json> pid:<pid>;
 *      GET_DEVICES → 原样转发 devices.json; 不认识的命令 → ERR。
 *   3. nl_process: 链路事件(RTM_NEWLINK / DELLINK)请求 offload 重探, 邻居事件
 *      一律不管(设备发现归 Go 看门狗)。
 *
 * 「改动前会失败」: v5.32 的 hotspotd 默认(不带 --no-discovery)REFRESH 不碰
 * run/devices.refresh、STATUS 报自己设备表的台数; 也没有 g_devices_path /
 * g_refresh_path, 本文件在 v5.32 上编译失败。
 *
 * 编译(在 test/unit/test_v533_hotspotd_ipc_c.sh 里):
 *   cc -std=gnu11 -D_GNU_SOURCE -I.. -o t test_hotspotd_ipc.c ../hnc_helpers.c
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HNC_TEST_MODE 1
#include "../hotspotd.c"

/* offload 调度器桩(真实实现在 scheduler.c, 会拖 BPF 依赖) */
static int g_refresh_calls = 0;
int hnc_scheduler_init(void) { return -1; }
void hnc_scheduler_shutdown(void) {}
void hnc_scheduler_notify_device_limit_changed(const char *mac, int f) {
    (void)mac; (void)f;
}
void hnc_scheduler_request_refresh(void) { g_refresh_calls++; }
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

static int g_fail = 0;

static void check(const char *name, int got, int want) {
    if (got != want) {
        printf("  FAIL %s: got %d want %d\n", name, got, want);
        g_fail++;
    } else {
        printf("  ok %s = %d\n", name, got);
    }
}

static void check_str(const char *name, const char *got, const char *want) {
    if (strcmp(got, want) != 0) {
        printf("  FAIL %s: got [%s] want [%s]\n", name, got, want);
        g_fail++;
    } else {
        printf("  ok %s\n", name);
    }
}

static void write_tmp(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror("write_tmp"); exit(2); }
    fputs(content, f);
    fclose(f);
}

/* 经 socketpair 喂一条命令给真实的 handle_client, 收完回复(它会 close 自己那端) */
static void ipc(const char *req, char *resp, size_t cap) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    if (write(sv[1], req, strlen(req)) != (ssize_t)strlen(req)) { perror("write"); exit(2); }
    handle_client(sv[0]);
    size_t off = 0;
    for (;;) {
        ssize_t n = read(sv[1], resp + off, cap - 1 - off);
        if (n <= 0) break;
        off += (size_t)n;
        if (off >= cap - 1) break;
    }
    resp[off] = '\0';
    close(sv[1]);
}

/* 把一条 netlink 消息(只有头)经 datagram socketpair 喂给真实的 nl_process */
static void nl_feed(unsigned short type) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    struct { struct nlmsghdr h; char pad[64]; } m;
    memset(&m, 0, sizeof(m));
    m.h.nlmsg_len = NLMSG_LENGTH(32);
    m.h.nlmsg_type = type;
    if (write(sv[1], &m, m.h.nlmsg_len) < 0) { perror("write nl"); exit(2); }
    nl_process(sv[0]);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    const char *dir = getenv("TMPDIR");
    char p1[512], p2[512], p3[512], pr[512], want[256], resp[4096];
    if (!dir || !*dir) dir = "/tmp";
    snprintf(p1, sizeof(p1), "%s/ndev_two.json", dir);
    snprintf(p2, sizeof(p2), "%s/ndev_odd.json", dir);
    snprintf(p3, sizeof(p3), "%s/ndev_empty.json", dir);
    snprintf(pr, sizeof(pr), "%s/devices.refresh", dir);

    /* 1) count_devices_in_file_at */
    const char *two =
        "{\"aa:bb:cc:dd:ee:01\":{\"ip\":\"192.168.43.101\",\"mac\":\"aa:bb:cc:dd:ee:01\"},"
        "\"aa:bb:cc:dd:ee:02\":{\"ip\":\"192.168.43.102\",\"mac\":\"aa:bb:cc:dd:ee:02\"}}";
    write_tmp(p1, two);
    check("两台设备", count_devices_in_file_at(p1), 2);
    write_tmp(p2,
        "{\"aa:bb:cc:dd:ee:01\":{\"ip\":\"1.2.3.4\",\"mac\":\"aa:bb:cc:dd:ee:01\","
        "\"hostname\":\"my \\\"mac\\\":\\\"x\",\"hostname_src\":\"manual\"}}");
    check("hostname 含引号不误数", count_devices_in_file_at(p2), 1);
    write_tmp(p3, "{}");
    check("空对象", count_devices_in_file_at(p3), 0);
    check("文件不存在", count_devices_in_file_at("/nonexistent/xx.json"), 0);

    /* 2) 控制接口 */
    g_devices_path = p1;
    g_refresh_path = pr;
    unlink(pr);
    ipc("REFRESH\n", resp, sizeof(resp));
    check_str("REFRESH 回复", resp, "OK:queued\n");
    check("REFRESH touch 了 run/devices.refresh", access(pr, F_OK) == 0, 1);

    ipc("STATUS\n", resp, sizeof(resp));
    snprintf(want, sizeof(want), "running:1 devices:2 pid:%d\n", (int)getpid());
    check_str("STATUS 数 devices.json", resp, want);

    ipc("GET_DEVICES\n", resp, sizeof(resp));
    check_str("GET_DEVICES 原样转发", resp, two);

    ipc("SCAN_ARP\n", resp, sizeof(resp));
    check_str("不认识的命令", resp, "ERR:unknown command\n");

    /* 3) nl_process: 只管链路事件 */
    g_refresh_calls = 0;
    nl_feed(RTM_NEWLINK);
    check("RTM_NEWLINK → 重探 offload", g_refresh_calls, 1);
    nl_feed(RTM_DELLINK);
    check("RTM_DELLINK → 重探 offload", g_refresh_calls, 2);
    nl_feed(RTM_NEWNEIGH);
    nl_feed(RTM_DELNEIGH);
    check("邻居事件不管", g_refresh_calls, 2);

    printf(g_fail ? "FAIL: %d\n" : "OK test_hotspotd_ipc\n", g_fail);
    return g_fail ? 1 : 0;
}
