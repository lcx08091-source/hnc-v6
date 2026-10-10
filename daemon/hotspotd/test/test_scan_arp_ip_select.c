/* test_scan_arp_ip_select.c — v5.32 T2: 全量重扫时换过 IP 的设备不报回旧 IP。
 *
 * 方案 G(同 test_no_discovery.c): #define HNC_TEST_MODE 后 include hotspotd.c,
 * 只测纯逻辑:
 *   1. nl_parse_dump_msgs: RTM_GETNEIGH dump 报文解析 —— NDA_DST/NDA_LLADDR/
 *      NDA_CACHEINFO 提取, confirmed(u32, 距今 clock_t, USER_HZ=100) → 绝对
 *      时间换算; 家族 / 状态 / 全零 MAC 过滤(g_hs_iface 塞名字让 iface 过滤
 *      通过, ndm_ifindex 用 1=lo, host 上 if_indextoname(1) 稳定返回 "lo",
 *      所以塞 "lo" 当热点)。
 *   2. scan_apply_candidate: 同一 MAC 两条候选不同确认时间, 两种顺序都挑新;
 *      已知设备的 IP 只被更近确认的候选改写; confirmed_at=0(/proc 退路形态)
 *      与旧行为一致(无条件接受)。
 *
 * 「改动前会失败」: v5.31 基线里没有这两个函数, 本文件在基线上编译失败
 * (undefined reference)。行为层面的旧代码失败证据在模拟设备场景
 * (test/sim/run_m4_sim_v532.sh): 换 IP 后 SIGUSR1 重扫, 旧代码按
 * /proc/net/arp 行序覆盖, 可能报回旧 IP。
 *
 * 编译(test/unit/test_v532_scan_arp_c.sh):
 *   cc -std=gnu11 -Wall -D_GNU_SOURCE -o t test_scan_arp_ip_select.c \
 *      ../hotspotd.c ../hnc_helpers.c ../oui_override.c ../hostname_cache.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>

#define HNC_TEST_MODE 1
#include "../hotspotd.c"

/* mock 定义(同 test_no_discovery.c) */
static int try_mdns_resolve(const char *ip, const char *mac,
                            char *out, size_t outlen) {
    (void)ip; (void)mac; (void)out; (void)outlen;
    return 0;
}
static int try_ns_dhcp_resolve(const char *mac, char *out, size_t outlen) {
    (void)mac; (void)out; (void)outlen;
    return 0;
}
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
static int g_ok   = 0;

static void check_str(const char *name, const char *got, const char *want) {
    if (strcmp(got, want) != 0) {
        printf("  FAIL %s: got '%s' want '%s'\n", name, got, want);
        g_fail++;
    } else {
        printf("  ok %s = '%s'\n", name, got);
        g_ok++;
    }
}
static void check_long(const char *name, long got, long want) {
    if (got != want) {
        printf("  FAIL %s: got %ld want %ld\n", name, got, want);
        g_fail++;
    } else {
        printf("  ok %s = %ld\n", name, got);
        g_ok++;
    }
}

/* ── dump 报文构造器(小端假设仅用于测试机 x86/ARM, 字段用内核结构体本身) ── */
typedef struct {
    struct nlmsghdr nh;
    struct ndmsg    nd;
    char            payload[256];
} test_msg;

static size_t build_neigh_msg(test_msg *m, const char *ip, const char *mac,
                              uint16_t state, int with_cacheinfo,
                              uint32_t confirmed_ticks, uint8_t family) {
    memset(m, 0, sizeof(*m));
    size_t plen = 0;
    {
        struct rtattr *a = (struct rtattr *)(m->payload + plen);
        a->rta_type  = NDA_DST;
        a->rta_len   = RTA_LENGTH(4);
        struct in_addr ia;
        inet_pton(AF_INET, ip, &ia);
        memcpy(RTA_DATA(a), &ia, 4);
        plen += RTA_ALIGN(a->rta_len);
    }
    {
        struct rtattr *a = (struct rtattr *)(m->payload + plen);
        a->rta_type  = NDA_LLADDR;
        a->rta_len   = RTA_LENGTH(6);
        unsigned char mm[6] = {0};
        sscanf(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &mm[0],&mm[1],&mm[2],&mm[3],&mm[4],&mm[5]);
        memcpy(RTA_DATA(a), mm, 6);
        plen += RTA_ALIGN(a->rta_len);
    }
    if (with_cacheinfo) {
        struct rtattr *a = (struct rtattr *)(m->payload + plen);
        a->rta_type  = NDA_CACHEINFO;
        a->rta_len   = RTA_LENGTH(sizeof(struct nda_cacheinfo));
        struct nda_cacheinfo ci = { .ndm_confirmed = confirmed_ticks };
        memcpy(RTA_DATA(a), &ci, sizeof(ci));
        plen += RTA_ALIGN(a->rta_len);
    }
    m->nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg) + plen);
    m->nh.nlmsg_type  = RTM_NEWNEIGH;
    m->nh.nlmsg_flags = 0;
    m->nd.ndm_family  = family;
    m->nd.ndm_state   = state;
    m->nd.ndm_ifindex = 1; /* lo —— host 上 if_indextoname(1) 稳定为 "lo" */
    return NLMSG_ALIGN(m->nh.nlmsg_len);
}

/* cand 构造(测 scan_apply_candidate 用, 不走 netlink) */
static NeighCand mk_cand(const char *mac, const char *ip, time_t confirmed_at) {
    NeighCand c;
    memset(&c, 0, sizeof(c));
    strncpy(c.mac, mac, sizeof(c.mac)-1);
    strncpy(c.ip, ip, sizeof(c.ip)-1);
    strncpy(c.iface, "lo", sizeof(c.iface)-1);
    c.confirmed_at = confirmed_at;
    return c;
}

int main(void) {
    /* 热点 iface 塞 "lo": is_confirmed_hotspot_iface 直接比对 g_hs_iface */
    strncpy(g_hs_iface, "lo", sizeof(g_hs_iface)-1);
    time_t now_t = 1000000;

    /* ── 1. nl_parse_dump_msgs ─────────────────────────────────── */
    {
        test_msg m;
        size_t len = build_neigh_msg(&m, "192.168.43.101", "02:5a:00:00:00:01",
                                     NUD_REACHABLE, 1, 5000 /* ticks=50s 前 */, AF_INET);
        NeighCand c[4];
        int n = nl_parse_dump_msgs((const char *)&m, len, now_t, c, 4);
        check_long("1a) 解析出 1 条", n, 1);
        if (n == 1) {
            check_str("1b) ip", c[0].ip, "192.168.43.101");
            check_str("1c) mac 小写", c[0].mac, "02:5a:00:00:00:01");
            check_str("1d) iface=lo", c[0].iface, "lo");
            check_long("1e) confirmed_at = now - 50", (long)c[0].confirmed_at, (long)(now_t - 50));
        }

        /* 1f) AF_INET6 家族过滤 */
        len = build_neigh_msg(&m, "fe80::1", "02:5a:00:00:00:02",
                              NUD_REACHABLE, 1, 1, AF_INET6);
        n = nl_parse_dump_msgs((const char *)&m, len, now_t, c, 4);
        check_long("1f) AF_INET6 被过滤", n, 0);

        /* 1g) 无效状态(NUD_FAILED)过滤 */
        len = build_neigh_msg(&m, "192.168.43.103", "02:5a:00:00:00:03",
                              NUD_FAILED, 1, 1, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_t, c, 4);
        check_long("1g) NUD_FAILED 被过滤", n, 0);

        /* 1h) 无 CACHEINFO → confirmed_at=0(未知), 其余字段保留 */
        len = build_neigh_msg(&m, "192.168.43.104", "02:5a:00:00:00:04",
                              NUD_STALE, 0, 0, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_t, c, 4);
        check_long("1h) 无 CACHEINFO 也解析", n, 1);
        if (n == 1)
            check_long("1h2) confirmed_at 未知=0", (long)c[0].confirmed_at, 0);

        /* 1i) 全零 MAC 过滤 */
        len = build_neigh_msg(&m, "192.168.43.105", "00:00:00:00:00:00",
                              NUD_REACHABLE, 1, 1, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_t, c, 4);
        check_long("1i) 全零 MAC 被过滤", n, 0);

        /* 1j) 两帧拼接(一条有效一条无效) */
        char two[512];
        size_t l1 = build_neigh_msg((test_msg *)two, "192.168.43.106", "02:5a:00:00:00:06",
                                    NUD_REACHABLE, 1, 1, AF_INET);
        size_t l2 = build_neigh_msg((test_msg *)(two + l1), "192.168.43.107", "02:5a:00:00:00:07",
                                    NUD_FAILED, 1, 1, AF_INET);
        n = nl_parse_dump_msgs(two, l1 + l2, now_t, c, 4);
        check_long("1j) 两帧只收有效的一条", n, 1);
        if (n == 1) check_str("1j2) 是有效那条", c[0].mac, "02:5a:00:00:00:06");
    }

    /* ── 2. scan_apply_candidate: 顺序无关挑新 ──────────────────── */
    {
        memset(g_devs, 0, sizeof(g_devs));
        g_ndev = 0;

        /* 2a) 先旧后新: 最终新 IP */
        NeighCand old_c = mk_cand("02:5a:00:00:00:01", "192.168.43.101", now_t - 300);
        NeighCand new_c = mk_cand("02:5a:00:00:00:01", "192.168.43.201", now_t - 5);
        scan_apply_candidate(&old_c, now_t);
        scan_apply_candidate(&new_c, now_t);
        Device *d = find_device("02:5a:00:00:00:01");
        check_str("2a) 先旧后新 → 新 IP", d->ip, "192.168.43.201");
        check_long("2a2) confirmed 推进", (long)d->confirmed_at, (long)(now_t - 5));

        /* 2b) 先新后旧: 仍是新 IP */
        memset(g_devs, 0, sizeof(g_devs));
        scan_apply_candidate(&new_c, now_t);
        scan_apply_candidate(&old_c, now_t); /* 更旧的确认, 不许改写 IP */
        d = find_device("02:5a:00:00:00:01");
        check_str("2b) 先新后旧 → 仍新 IP", d->ip, "192.168.43.201");
        check_long("2b2) confirmed 不回退", (long)d->confirmed_at, (long)(now_t - 5));

        /* 2c) 已知设备(事件路径建的, confirmed_at=0) + dump 候选 → 接受(同旧行为) */
        memset(g_devs, 0, sizeof(g_devs));
        Device *e = alloc_device();
        strncpy(e->mac, "02:5a:00:00:00:02", sizeof(e->mac)-1);
        strncpy(e->ip, "192.168.43.102", sizeof(e->ip)-1);
        e->active = 1;
        NeighCand c2 = mk_cand("02:5a:00:00:00:02", "192.168.43.202", now_t - 10);
        scan_apply_candidate(&c2, now_t);
        check_str("2c) confirmed 未知时接受候选(旧行为)", e->ip, "192.168.43.202");
        check_long("2c2) accepted confirmed", (long)e->confirmed_at, (long)(now_t - 10));

        /* 2d) /proc 退路形态(confirmed_at=0)→ 无条件接受(旧行为), 同 MAC 后行赢 */
        memset(g_devs, 0, sizeof(g_devs));
        NeighCand p1 = mk_cand("02:5a:00:00:00:03", "192.168.43.103", 0);
        NeighCand p2 = mk_cand("02:5a:00:00:00:03", "192.168.43.203", 0);
        scan_apply_candidate(&p1, now_t);
        scan_apply_candidate(&p2, now_t);
        d = find_device("02:5a:00:00:00:03");
        check_str("2d) /proc 退路: 后行覆盖(旧行为)", d->ip, "192.168.43.203");

        /* 2e) 非热点 iface 过滤 */
        NeighCand bad = mk_cand("02:5a:00:00:00:04", "192.168.43.104", now_t - 1);
        strncpy(bad.iface, "rmnet_data0", sizeof(bad.iface)-1);
        int r = scan_apply_candidate(&bad, now_t);
        check_long("2e) 非热点 iface 不处理", r, 0);
    }

    printf(g_fail ? "\nFAIL: %d 处不对\n" : "\nok 全部 %d 项通过\n",
           g_fail ? g_fail : g_ok);
    return g_fail ? 1 : 0;
}
