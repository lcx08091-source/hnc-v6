/* test_scan_arp_ip_select.c — v5.32 T2: 全量重扫时换过 IP 的设备不报回旧 IP。
 *
 * 方案 G(同 test_no_discovery.c): #define HNC_TEST_MODE 后 include hotspotd.c,
 * 只测纯逻辑:
 *   1. nl_parse_dump_msgs: RTM_GETNEIGH dump 报文解析 —— NDA_DST/NDA_LLADDR/
 *      NDA_CACHEINFO 提取, confirmed(u32, 距今 clock_t, USER_HZ=100) → 单调
 *      时钟毫秒换算; 家族 / 状态 / 全零 MAC 过滤(g_hs_iface 塞名字让 iface 过滤
 *      通过, ndm_ifindex 用 1=lo, host 上 if_indextoname(1) 稳定返回 "lo",
 *      所以塞 "lo" 当热点)。
 *   2. scan_apply_candidate: 同一 MAC 两条候选不同确认时间, 两种顺序都挑新;
 *      已知设备的 IP 只被更近确认的候选改写; confirmed_ms=0(/proc 退路形态)
 *      与旧行为一致(无条件接受)。
 *   3. 审查补: 槽位复用不带上一台的确认时间 / 10ms 精度(1 秒内确认的两条不打平)/
 *      NLMSG_DONE / 事件换 IP 后不发包重扫。
 *   4. 审查补: 事件路径(真实的 nl_process, 经 socketpair 喂通知)—— 按模拟设备上实测
 *      的内核时序: 新表项回拨 60 秒、旧表项老化 STALE、旧表项被探测 PROBE, 都不许
 *      把 IP 抢回旧的。
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
#include <sys/socket.h>

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
static NeighCand mk_cand(const char *mac, const char *ip, long long confirmed_ms) {
    NeighCand c;
    memset(&c, 0, sizeof(c));
    strncpy(c.mac, mac, sizeof(c.mac)-1);
    strncpy(c.ip, ip, sizeof(c.ip)-1);
    strncpy(c.iface, "lo", sizeof(c.iface)-1);
    c.confirmed_ms = confirmed_ms;
    return c;
}

int main(void) {
    /* 热点 iface 塞 "lo": is_confirmed_hotspot_iface 直接比对 g_hs_iface */
    strncpy(g_hs_iface, "lo", sizeof(g_hs_iface)-1);
    time_t now_t = 1000000;           /* 墙上时钟(last_seen 等) */
    long long now_ms = 5000000;       /* 单调时钟毫秒(确认时刻) */

    /* ── 1. nl_parse_dump_msgs ─────────────────────────────────── */
    {
        test_msg m;
        size_t len = build_neigh_msg(&m, "192.168.43.101", "02:5a:00:00:00:01",
                                     NUD_REACHABLE, 1, 5000 /* ticks=50s 前 */, AF_INET);
        NeighCand c[4];
        int n = nl_parse_dump_msgs((const char *)&m, len, now_ms, c, 4, NULL);
        check_long("1a) 解析出 1 条", n, 1);
        if (n == 1) {
            check_str("1b) ip", c[0].ip, "192.168.43.101");
            check_str("1c) mac 小写", c[0].mac, "02:5a:00:00:00:01");
            check_str("1d) iface=lo", c[0].iface, "lo");
            check_long("1e) confirmed_ms = now - 50s", (long)c[0].confirmed_ms, (long)(now_ms - 50000));
        }

        /* 1f) AF_INET6 家族过滤 */
        len = build_neigh_msg(&m, "fe80::1", "02:5a:00:00:00:02",
                              NUD_REACHABLE, 1, 1, AF_INET6);
        n = nl_parse_dump_msgs((const char *)&m, len, now_ms, c, 4, NULL);
        check_long("1f) AF_INET6 被过滤", n, 0);

        /* 1g) 无效状态(NUD_FAILED)过滤 */
        len = build_neigh_msg(&m, "192.168.43.103", "02:5a:00:00:00:03",
                              NUD_FAILED, 1, 1, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_ms, c, 4, NULL);
        check_long("1g) NUD_FAILED 被过滤", n, 0);

        /* 1h) 无 CACHEINFO → confirmed_at=0(未知), 其余字段保留 */
        len = build_neigh_msg(&m, "192.168.43.104", "02:5a:00:00:00:04",
                              NUD_STALE, 0, 0, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_ms, c, 4, NULL);
        check_long("1h) 无 CACHEINFO 也解析", n, 1);
        if (n == 1)
            check_long("1h2) confirmed_ms 未知=0", (long)c[0].confirmed_ms, 0);

        /* 1i) 全零 MAC 过滤 */
        len = build_neigh_msg(&m, "192.168.43.105", "00:00:00:00:00:00",
                              NUD_REACHABLE, 1, 1, AF_INET);
        n = nl_parse_dump_msgs((const char *)&m, len, now_ms, c, 4, NULL);
        check_long("1i) 全零 MAC 被过滤", n, 0);

        /* 1j) 两帧拼接(一条有效一条无效) */
        char two[512];
        size_t l1 = build_neigh_msg((test_msg *)two, "192.168.43.106", "02:5a:00:00:00:06",
                                    NUD_REACHABLE, 1, 1, AF_INET);
        size_t l2 = build_neigh_msg((test_msg *)(two + l1), "192.168.43.107", "02:5a:00:00:00:07",
                                    NUD_FAILED, 1, 1, AF_INET);
        n = nl_parse_dump_msgs(two, l1 + l2, now_ms, c, 4, NULL);
        check_long("1j) 两帧只收有效的一条", n, 1);
        if (n == 1) check_str("1j2) 是有效那条", c[0].mac, "02:5a:00:00:00:06");
    }

    /* ── 2. scan_apply_candidate: 顺序无关挑新 ──────────────────── */
    {
        memset(g_devs, 0, sizeof(g_devs));
        g_ndev = 0;

        /* 2a) 先旧后新: 最终新 IP */
        NeighCand old_c = mk_cand("02:5a:00:00:00:01", "192.168.43.101", now_ms - 300000);
        NeighCand new_c = mk_cand("02:5a:00:00:00:01", "192.168.43.201", now_ms - 5000);
        scan_apply_candidate(&old_c, now_t);
        scan_apply_candidate(&new_c, now_t);
        Device *d = find_device("02:5a:00:00:00:01");
        check_str("2a) 先旧后新 → 新 IP", d->ip, "192.168.43.201");
        check_long("2a2) confirmed 推进", (long)d->confirmed_ms, (long)(now_ms - 5000));

        /* 2b) 先新后旧: 仍是新 IP */
        memset(g_devs, 0, sizeof(g_devs));
        scan_apply_candidate(&new_c, now_t);
        scan_apply_candidate(&old_c, now_t); /* 更旧的确认, 不许改写 IP */
        d = find_device("02:5a:00:00:00:01");
        check_str("2b) 先新后旧 → 仍新 IP", d->ip, "192.168.43.201");
        check_long("2b2) confirmed 不回退", (long)d->confirmed_ms, (long)(now_ms - 5000));

        /* 2c) 已知设备(事件路径建的, confirmed_ms=0) + dump 候选 → 接受(同旧行为) */
        memset(g_devs, 0, sizeof(g_devs));
        Device *e = alloc_device();
        strncpy(e->mac, "02:5a:00:00:00:02", sizeof(e->mac)-1);
        strncpy(e->ip, "192.168.43.102", sizeof(e->ip)-1);
        e->active = 1;
        NeighCand c2 = mk_cand("02:5a:00:00:00:02", "192.168.43.202", now_ms - 10000);
        scan_apply_candidate(&c2, now_t);
        check_str("2c) confirmed 未知时接受候选(旧行为)", e->ip, "192.168.43.202");
        check_long("2c2) accepted confirmed", (long)e->confirmed_ms, (long)(now_ms - 10000));

        /* 2d) /proc 退路形态(confirmed_ms=0)→ 无条件接受(旧行为), 同 MAC 后行赢 */
        memset(g_devs, 0, sizeof(g_devs));
        NeighCand p1 = mk_cand("02:5a:00:00:00:03", "192.168.43.103", 0);
        NeighCand p2 = mk_cand("02:5a:00:00:00:03", "192.168.43.203", 0);
        scan_apply_candidate(&p1, now_t);
        scan_apply_candidate(&p2, now_t);
        d = find_device("02:5a:00:00:00:03");
        check_str("2d) /proc 退路: 后行覆盖(旧行为)", d->ip, "192.168.43.203");

        /* 2e) 非热点 iface 过滤 */
        NeighCand bad = mk_cand("02:5a:00:00:00:04", "192.168.43.104", now_ms - 1000);
        strncpy(bad.iface, "rmnet_data0", sizeof(bad.iface)-1);
        int r = scan_apply_candidate(&bad, now_t);
        check_long("2e) 非热点 iface 不处理", r, 0);
    }

    /* ── 3. 审查修复 ─────────────────────────────────────────────── */
    {
        /* 3a) 槽位复用: 设备 A 离线(active=0)后, 新设备 B 占它的槽位。B 的确认
         *     时刻比 A 留下的旧 confirmed 早 —— 原实现不清 confirmed, B 的 IP
         *     被挡住, 报成 A 的 IP。 */
        memset(g_devs, 0, sizeof(g_devs));
        g_ndev = 0;
        NeighCand a = mk_cand("02:5a:00:00:00:0a", "192.168.43.110", now_ms - 10000);
        scan_apply_candidate(&a, now_t);
        Device *da = find_device("02:5a:00:00:00:0a");
        if (da) da->active = 0;   /* 离线(90 秒没动静 / NUD_FAILED) */
        NeighCand b = mk_cand("02:5a:00:00:00:0b", "192.168.43.111", now_ms - 100000);
        scan_apply_candidate(&b, now_t);
        Device *db = find_device("02:5a:00:00:00:0b");
        check_str("3a) 复用槽位的新设备用自己的 IP", db ? db->ip : "(none)", "192.168.43.111");

        /* 3b) 10ms 精度: 旧 IP 1.5 秒前确认、新 IP 1.2 秒前确认, 同一次 dump 里
         *     旧的排在前面。截到秒时两条都是「1 秒前」打平, 先到的旧 IP 赢。 */
        memset(g_devs, 0, sizeof(g_devs));
        test_msg mo, mn;
        char two[512];
        size_t lo = build_neigh_msg(&mo, "192.168.43.121", "02:5a:00:00:00:0c",
                                    NUD_STALE, 1, 150, AF_INET);
        size_t ln = build_neigh_msg(&mn, "192.168.43.122", "02:5a:00:00:00:0c",
                                    NUD_STALE, 1, 120, AF_INET);
        memcpy(two, &mo, lo);
        memcpy(two + lo, &mn, ln);
        NeighCand cs[4];
        int done = 0;
        int n = nl_parse_dump_msgs(two, lo + ln, now_ms, cs, 4, &done);
        for (int i = 0; i < n; i++) scan_apply_candidate(&cs[i], now_t);
        Device *dc = find_device("02:5a:00:00:00:0c");
        check_str("3b) 相差 0.3 秒也挑更近确认的", dc ? dc->ip : "(none)", "192.168.43.122");
        check_long("3b2) 没有 NLMSG_DONE 时 done=0", done, 0);

        /* 3c) NLMSG_DONE: 置 done, 其后的报文不再解析 */
        struct nlmsghdr dn;
        memset(&dn, 0, sizeof(dn));
        dn.nlmsg_len = NLMSG_LENGTH(sizeof(int));
        dn.nlmsg_type = NLMSG_DONE;
        char buf[512];
        size_t l1 = build_neigh_msg((test_msg *)buf, "192.168.43.131", "02:5a:00:00:00:0d",
                                    NUD_REACHABLE, 1, 1, AF_INET);
        memcpy(buf + l1, &dn, sizeof(dn));
        size_t l2 = NLMSG_ALIGN(dn.nlmsg_len);
        memset(buf + l1 + sizeof(dn), 0, l2 - sizeof(dn));
        size_t l3 = build_neigh_msg((test_msg *)(buf + l1 + l2), "192.168.43.132", "02:5a:00:00:00:0e",
                                    NUD_REACHABLE, 1, 1, AF_INET);
        done = 0;
        n = nl_parse_dump_msgs(buf, l1 + l2 + l3, now_ms, cs, 4, &done);
        check_long("3c) DONE 之前的一条", n, 1);
        check_long("3c2) done=1", done, 1);

        /* 3d) 事件换 IP → 不发包 → 重扫(交接文档要求的场景)。
         *     dump 记下 .141(10 秒前确认); 事件路径(nl_process)把 IP 改成
         *     .142, 不动 confirmed_ms; 之后重扫: .141 的确认时刻没变,
         *     .142 在事件之后确认过 → 不管顺序都得 .142。 */
        memset(g_devs, 0, sizeof(g_devs));
        NeighCand f1 = mk_cand("02:5a:00:00:00:0f", "192.168.43.141", now_ms - 10000);
        scan_apply_candidate(&f1, now_t);
        Device *df = find_device("02:5a:00:00:00:0f");
        if (df) strncpy(df->ip, "192.168.43.142", sizeof(df->ip)-1);  /* 事件路径 */
        NeighCand f2 = mk_cand("02:5a:00:00:00:0f", "192.168.43.142", now_ms - 3000);
        scan_apply_candidate(&f1, now_t);   /* 旧表项先到 */
        scan_apply_candidate(&f2, now_t);
        check_str("3d) 事件换 IP 后重扫(旧先到)仍是新 IP", df ? df->ip : "(none)", "192.168.43.142");
        scan_apply_candidate(&f2, now_t);
        scan_apply_candidate(&f1, now_t);   /* 旧表项后到 */
        check_str("3d2) 事件换 IP 后重扫(旧后到)仍是新 IP", df ? df->ip : "(none)", "192.168.43.142");
    }

    /* ── 4. 事件路径(nl_process)────────────────────────────────── */
    {
        memset(g_devs, 0, sizeof(g_devs));
        g_no_discovery = 0;
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
            printf("  FAIL socketpair\n");
            g_fail++;
        } else {
            const char *mac = "02:5a:00:00:00:41";
            /* 一条通知: ip / 状态 / 确认时间(多久前, 单位 10ms)。nl_process 用真实的
             * 单调时钟算确认时刻; 通知之间隔 20ms, 免得「刚确认」的两条打平(打平时
             * 保留当前 IP —— 真实场景里两条通知相隔数秒)。 */
            #define EV(ip, st, ticks) do { test_msg m; usleep(20000); \
                size_t l = build_neigh_msg(&m, ip, mac, st, 1, ticks, AF_INET); \
                if (send(sv[1], &m, l, 0) < 0) perror("send"); \
                nl_process(sv[0]); } while (0)
            Device *d;
            EV("192.168.43.141", NUD_REACHABLE, 0);
            d = find_device(mac);
            check_str("4a) 新设备 .141", d ? d->ip : "(none)", "192.168.43.141");
            /* 换 IP: 新表项刚建, STALE, 确认时间回拨 60 秒 —— 还没被确认, 不抢 */
            EV("192.168.43.142", NUD_STALE, 6000);
            check_str("4b) 新表项未确认前保留 .141", d ? d->ip : "(none)", "192.168.43.141");
            /* 约 5 秒后网关确认新 IP 可达 */
            EV("192.168.43.142", NUD_REACHABLE, 0);
            check_str("4c) 新 IP 被确认 → .142", d ? d->ip : "(none)", "192.168.43.142");
            /* 约 30 秒后旧表项老化成 STALE(最后确认在 30 秒前)*/
            EV("192.168.43.141", NUD_STALE, 3000);
            check_str("4d) 旧表项老化不改回 .141", d ? d->ip : "(none)", "192.168.43.142");
            /* 网关还有流量去找旧 IP: 旧表项 PROBE(最后确认在 80 秒前)*/
            EV("192.168.43.141", NUD_PROBE, 8000);
            check_str("4e) 旧表项被探测不抢回", d ? d->ip : "(none)", "192.168.43.142");
            /* 设备真的换回 .141 并被确认 → 跟过去 */
            EV("192.168.43.141", NUD_REACHABLE, 0);
            check_str("4f) 旧 IP 重新被确认 → .141", d ? d->ip : "(none)", "192.168.43.141");
            #undef EV
            close(sv[0]);
            close(sv[1]);
        }
    }

    printf(g_fail ? "\nFAIL: %d 处不对\n" : "\nok 全部 %d 项通过\n",
           g_fail ? g_fail : g_ok);
    return g_fail ? 1 : 0;
}
