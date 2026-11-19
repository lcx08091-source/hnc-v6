/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hnc_tc_ingress.c — Install tc clsact + matchall->mirred / dual-stack police via raw rtnetlink
 *
 * Purpose (HNC v5.40.0)
 * ---------------------
 * 1. Primary IFB steering path (decoupled from prio 1 clsact BPF):
 *        tc qdisc  add dev <iface> clsact
 *        tc filter replace dev <iface> ingress prio <prio> protocol all matchall \
 *            action mirred egress redirect dev <ifb_iface>
 *    Default <prio> is 2 so prio 1 remains exclusively reserved for `hnc_clsact.o`
 *    (which marks packets in skb->mark[23:16] and returns TC_ACT_UNSPEC).
 *
 * 2. Dual-stack GRO-safe `tc police` fallback (for GKI 6.1/6.6 kernels without IFB/mirred
 *    and ROMs whose /system/bin/tc rejects the "ingress" parent keyword):
 *        hnc_tc_ingress police <iface> <rate> [prio] [all|ip|ipv6|dual] [src_ip]
 *        hnc_tc_ingress police-del <iface> <prio> [all|ip|ipv6|dual]
 *    Enforces GRO-safe `burst = max(rate_bytes_per_sec / 8, 65536)` (>= 64 KB)
 *    and `mtu = 65535` across ETH_P_ALL or ETH_P_IP + ETH_P_IPV6.
 *
 * Legacy CLI Compatibility (100% preserved)
 * -----------------------------------------
 *     hnc_tc_ingress <iface> <ifb_iface> [prio]
 *
 * Return codes:
 *     0   installed OK, or already present (idempotent EEXIST)
 *     1   iface not found           (if_nametoindex == 0)
 *     2   ifb_iface not found
 *     3   netlink error             (socket/send/recv/kernel errno)
 *     4   CLI / usage error
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_mirred.h>

/* ── Constants ───────────────────────────────────────────────────────── */

#define HNC_TC_H_CLSACT_PARENT    0xFFFFFFF1U
#define HNC_TC_H_INGRESS_PARENT   0xFFFFFFF2U
#define HNC_TC_H_CLSACT_HANDLE    0xFFFF0000U

/* Default mirred priority = 2 to yield prio 1 to hnc_clsact BPF */
#define HNC_DEFAULT_MIRRED_PRIO   2
#define HNC_DEFAULT_POLICE_PRIO   300

/* Minimum GRO-safe police burst (64 KiB) and super-frame MTU (65535 B) */
#define HNC_POLICE_MIN_BURST      65536ULL
#define HNC_POLICE_MTU            65535U

#ifndef TCA_POLICE_RATE64
#define TCA_POLICE_RATE64         8
#endif

#define RTNL_REQ_BUF_SIZE         4096    /* accommodates 256-entry rtab + u32/matchall */
#define RTNL_RECV_BUF_SIZE        8192    /* ACK / NLMSG_ERROR recv buffer              */
#define RTNL_RECV_TIMEOUT_S       3       /* kernel ACKs are always fast                */
#define RTNL_MAX_RECV_TRIES       32      /* cap stray unmatched replies                */

/* Return codes — keep in sync with README.md and tc_manager.sh */
#define RC_OK                     0
#define RC_IFACE_NOT_FOUND        1
#define RC_IFB_NOT_FOUND          2
#define RC_NETLINK_ERROR          3
#define RC_USAGE                  4

/* ── Logging ─────────────────────────────────────────────────────────── */

#define LOGE(fmt, ...) \
    fprintf(stderr, "hnc_tc_ingress: " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    fprintf(stderr, "hnc_tc_ingress: " fmt "\n", ##__VA_ARGS__)

/* ── Union-backed rtnetlink request buffer (C11 provenance clean) ────── */

union nl_tc_req {
    struct {
        struct nlmsghdr n;
        struct tcmsg    t;
        char            buf[RTNL_REQ_BUF_SIZE];
    } m;
    unsigned char raw[sizeof(struct nlmsghdr) + sizeof(struct tcmsg) + RTNL_REQ_BUF_SIZE];
};

static int req_addattr_l(union nl_tc_req *req, int type,
                         const void *data, size_t alen)
{
    size_t len     = RTA_LENGTH(alen);
    size_t cur_off = NLMSG_ALIGN(req->m.n.nlmsg_len);
    size_t new_len = cur_off + RTA_ALIGN(len);

    if (new_len > sizeof(req->raw)) {
        errno = EMSGSIZE;
        return -1;
    }
    struct rtattr *rta = (struct rtattr *)(req->raw + cur_off);
    rta->rta_type = (unsigned short)type;
    rta->rta_len  = (unsigned short)len;
    if (alen > 0 && data != NULL)
        memcpy(RTA_DATA(rta), data, alen);
    req->m.n.nlmsg_len = (uint32_t)new_len;
    return 0;
}

static size_t req_nest_begin(union nl_tc_req *req, int type)
{
    size_t off = NLMSG_ALIGN(req->m.n.nlmsg_len);
    if (req_addattr_l(req, type, NULL, 0) < 0)
        return 0;
    return off;
}

static void req_nest_end(union nl_tc_req *req, size_t off)
{
    struct rtattr *nest = (struct rtattr *)(req->raw + off);
    size_t end_off = NLMSG_ALIGN(req->m.n.nlmsg_len);
    nest->rta_len = (unsigned short)(end_off - off);
}

/* ── Unsigned integer & rate parsers (32/64-bit armv7a/arm64 safe) ───── */

static int parse_prio_arg(const char *s, int *out_prio)
{
    if (!s || *s == '\0' || *s == '-' || *s == '+')
        return -1;
    char *endp = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &endp, 10);
    if (errno != 0 || endp == s || *endp != '\0' || v < 1ULL || v > 65535ULL)
        return -1;
    *out_prio = (int)v;
    return 0;
}

static int parse_rate_bytes_per_sec(const char *s, uint64_t *out_Bps)
{
    if (!s || !out_Bps)
        return -1;
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0' || *s == '-' || *s == '+')
        return -1;

    char *endp = NULL;
    errno = 0;
    unsigned long long val = strtoull(s, &endp, 10);
    if (errno != 0 || endp == s || val == 0ULL || val > 0xffffffffffffULL)
        return -1;

    uint64_t bps_bytes = 0;
    if (*endp == '\0' || strcasecmp(endp, "Bps") == 0 || strcmp(endp, "B") == 0) {
        bps_bytes = (uint64_t)val;
    } else if (strcasecmp(endp, "bit") == 0) {
        bps_bytes = (uint64_t)val / 8ULL;
    } else if (strcasecmp(endp, "kbit") == 0) {
        bps_bytes = ((uint64_t)val * 1000ULL) / 8ULL;
    } else if (strcasecmp(endp, "mbit") == 0) {
        bps_bytes = ((uint64_t)val * 1000000ULL) / 8ULL;
    } else if (strcasecmp(endp, "gbit") == 0) {
        bps_bytes = ((uint64_t)val * 1000000000ULL) / 8ULL;
    } else if (strcasecmp(endp, "kbps") == 0) {
        bps_bytes = (uint64_t)val * 1000ULL;
    } else if (strcasecmp(endp, "mbps") == 0) {
        bps_bytes = (uint64_t)val * 1000000ULL;
    } else {
        return -1;
    }

    if (bps_bytes == 0ULL)
        bps_bytes = 1ULL;
    *out_Bps = bps_bytes;
    return 0;
}

/* Pure C11 64x64->128 unsigned arithmetic (32-bit armeabi-v7a safe, pure uint64_t) */
typedef struct {
    uint64_t hi;
    uint64_t lo;
} hnc_u128_t;

static hnc_u128_t mul64x64_u128(uint64_t a, uint64_t b)
{
    uint64_t a0 = a & 0xffffffffULL;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffULL;
    uint64_t b1 = b >> 32;

    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;

    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffULL) + (p10 & 0xffffffffULL);
    hnc_u128_t res;
    res.lo = (p00 & 0xffffffffULL) | (mid << 32);
    res.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return res;
}

static uint32_t div_u128_u64_sat32(hnc_u128_t num, uint64_t den)
{
    if (den == 0ULL || num.hi >= den)
        return 0xffffffffU;
    if (num.hi == 0ULL) {
        uint64_t q0 = num.lo / den;
        return (q0 > 0xffffffffULL) ? 0xffffffffU : (uint32_t)q0;
    }

    uint64_t rem = num.hi;
    uint64_t q   = 0ULL;
    unsigned int bit = 64U;
    while (bit-- > 0U) {
        uint64_t carry = rem >> 63;
        rem = (rem << 1) | ((num.lo >> bit) & 1ULL);
        if (carry != 0ULL || rem >= den) {
            rem -= den;
            q |= (1ULL << bit);
        }
    }
    return (q > 0xffffffffULL) ? 0xffffffffU : (uint32_t)q;
}

static uint32_t calc_psched_ticks(uint64_t rate_Bps, uint64_t bytes)
{
    static uint32_t t2us = 0, us2t = 0;
    if (t2us == 0 || us2t == 0) {
        t2us = 1000U;
        us2t = 64U;
        FILE *fp = fopen("/proc/net/psched", "re");
        if (fp) {
            unsigned int a = 0, b = 0;
            if (fscanf(fp, "%08x %08x", &a, &b) == 2 && a > 0U && b > 0U) {
                t2us = a;
                us2t = b;
            }
            fclose(fp);
        }
    }
    if (rate_Bps == 0ULL)
        return 1U;

    hnc_u128_t num = mul64x64_u128(bytes, 1000000ULL * (uint64_t)t2us);
    hnc_u128_t den = mul64x64_u128(rate_Bps, (uint64_t)us2t);
    while (den.hi != 0ULL) {
        num.lo = (num.lo >> 1) | (num.hi << 63);
        num.hi >>= 1;
        den.lo = (den.lo >> 1) | (den.hi << 63);
        den.hi >>= 1;
    }
    uint32_t ticks = div_u128_u64_sat32(num, den.lo);
    return (ticks == 0U) ? 1U : ticks;
}

/* ── rtnetlink socket I/O ────────────────────────────────────────────── */

static uint32_t g_seq;

static int rtnl_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        LOGE("socket(AF_NETLINK): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOGE("bind(AF_NETLINK): %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct timeval tv = { .tv_sec = RTNL_RECV_TIMEOUT_S, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (g_seq == 0) {
        g_seq = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16);
        if (g_seq == 0) g_seq = 1;
    }
    return fd;
}

static int rtnl_send_ack(int fd, struct nlmsghdr *n, const char *what, int ignore_enoent)
{
    n->nlmsg_seq = ++g_seq;
    n->nlmsg_pid = 0;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    ssize_t sent;
    do {
        sent = sendto(fd, n, n->nlmsg_len, MSG_NOSIGNAL,
                      (struct sockaddr *)&sa, sizeof(sa));
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
        LOGE("%s: sendto: %s", what, strerror(errno));
        return -errno;
    }
    if ((size_t)sent != n->nlmsg_len) {
        LOGE("%s: short sendto (%zd of %u)", what, sent, n->nlmsg_len);
        return -EIO;
    }

    char         buf[RTNL_RECV_BUF_SIZE] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    for (int tries = 0; tries < RTNL_MAX_RECV_TRIES; tries++) {
        ssize_t len = recvmsg(fd, &msg, 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            LOGE("%s: recvmsg: %s", what, strerror(errno));
            return -errno;
        }
        if (len == 0) {
            LOGE("%s: recvmsg EOF on netlink", what);
            return -EIO;
        }

        size_t rem = (size_t)len;
        for (size_t off = 0; rem >= sizeof(struct nlmsghdr); ) {
            struct nlmsghdr *h = (struct nlmsghdr *)(buf + off);
            if (h->nlmsg_len < sizeof(struct nlmsghdr) || (size_t)h->nlmsg_len > rem)
                break;
            size_t step = NLMSG_ALIGN(h->nlmsg_len);
            if (step > rem)
                step = rem;
            off += step;
            rem -= step;
            if (h->nlmsg_seq != n->nlmsg_seq)
                continue;

            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    LOGE("%s: truncated NLMSG_ERROR (%u bytes)", what, h->nlmsg_len);
                    return -EBADMSG;
                }
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
                if (err->error == 0 || err->error == -EEXIST)
                    return 0;
                if (ignore_enoent && (err->error == -ENOENT || err->error == -EINVAL))
                    return 0;
                LOGE("%s: kernel rejected: %s (errno=%d)",
                     what, strerror(-err->error), -err->error);
                return err->error;
            }

            LOGE("%s: unexpected nlmsg_type=%u", what, h->nlmsg_type);
            return -EPROTO;
        }
    }
    LOGE("%s: exceeded %d unmatched netlink replies", what, RTNL_MAX_RECV_TRIES);
    return -EPROTO;
}

/* ── Build & send: RTM_NEWQDISC clsact ───────────────────────────────── */

static int install_clsact(int fd, int ifindex, const char *iface)
{
    union nl_tc_req req;
    memset(&req, 0, sizeof(req));

    req.m.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.m.n.nlmsg_type  = RTM_NEWQDISC;
    req.m.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

    req.m.t.tcm_family  = AF_UNSPEC;
    req.m.t.tcm_ifindex = ifindex;
    req.m.t.tcm_parent  = HNC_TC_H_CLSACT_PARENT;
    req.m.t.tcm_handle  = HNC_TC_H_CLSACT_HANDLE;

    if (req_addattr_l(&req, TCA_KIND, "clsact", sizeof("clsact")) < 0) {
        LOGE("clsact: addattr_l(TCA_KIND): %s", strerror(errno));
        return -errno;
    }

    int rc = rtnl_send_ack(fd, &req.m.n, "clsact qdisc add", 0);
    if (rc == 0)
        LOGI("clsact qdisc OK on %s (ifindex=%d)", iface, ifindex);
    return rc;
}

/* ── Build & send: RTM_NEWTFILTER matchall + mirred ──────────────────── */

static int append_mirred_action(union nl_tc_req *req, int ifb_ifindex)
{
    struct tc_mirred mirred;
    memset(&mirred, 0, sizeof(mirred));
    mirred.action  = TC_ACT_STOLEN;
    mirred.eaction = TCA_EGRESS_REDIR;
    mirred.ifindex = (uint32_t)ifb_ifindex;

    if (req_addattr_l(req, TCA_ACT_KIND, "mirred", sizeof("mirred")) < 0)
        return -errno;

    size_t act_opts = req_nest_begin(req, TCA_ACT_OPTIONS | NLA_F_NESTED);
    if (!act_opts) return -errno;

    if (req_addattr_l(req, TCA_MIRRED_PARMS, &mirred, sizeof(mirred)) < 0)
        return -errno;

    req_nest_end(req, act_opts);
    return 0;
}

static int install_matchall_filter(int fd,
                                   int iface_ifindex, int ifb_ifindex,
                                   int prio,
                                   const char *iface, const char *ifb_iface)
{
    union nl_tc_req req;
    memset(&req, 0, sizeof(req));

    req.m.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.m.n.nlmsg_type  = RTM_NEWTFILTER;
    req.m.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;

    req.m.t.tcm_family  = AF_UNSPEC;
    req.m.t.tcm_ifindex = iface_ifindex;
    req.m.t.tcm_parent  = HNC_TC_H_INGRESS_PARENT;
    req.m.t.tcm_handle  = 1U;
    req.m.t.tcm_info    = TC_H_MAKE((uint32_t)prio << 16, htons(ETH_P_ALL));

    if (req_addattr_l(&req, TCA_KIND, "matchall", sizeof("matchall")) < 0) {
        LOGE("matchall: addattr_l(TCA_KIND): %s", strerror(errno));
        return -errno;
    }

    size_t options = req_nest_begin(&req, TCA_OPTIONS);
    size_t ma_act  = req_nest_begin(&req, TCA_MATCHALL_ACT);
    size_t act_1   = req_nest_begin(&req, 1);
    if (!options || !ma_act || !act_1)
        return -EMSGSIZE;

    int rc = append_mirred_action(&req, ifb_ifindex);
    if (rc < 0) {
        LOGE("matchall: append_mirred_action: %s", strerror(-rc));
        return rc;
    }

    req_nest_end(&req, act_1);
    req_nest_end(&req, ma_act);
    req_nest_end(&req, options);

    rc = rtnl_send_ack(fd, &req.m.n, "matchall+mirred filter replace", 0);
    if (rc == 0)
        LOGI("matchall prio %d → %s (ifindex=%d) installed on %s",
             prio, ifb_iface, ifb_ifindex, iface);
    return rc;
}

/* ── Build & send: GRO-safe Dual-Stack `police` action ───────────────── */

static int append_police_action(union nl_tc_req *req, uint64_t rate_bytes_per_sec)
{
    uint64_t burst_bytes = rate_bytes_per_sec / 8ULL;
    if (burst_bytes < HNC_POLICE_MIN_BURST)
        burst_bytes = HNC_POLICE_MIN_BURST;

    const uint8_t cell_log = 8;
    uint32_t rtab[256];
    for (int i = 0; i < 256; i++) {
        uint64_t sz = (uint64_t)(i + 1) << cell_log;
        rtab[i] = calc_psched_ticks(rate_bytes_per_sec, sz);
    }

    struct tc_police pol;
    memset(&pol, 0, sizeof(pol));
    pol.action        = TC_POLICE_SHOT;
    pol.mtu           = HNC_POLICE_MTU;
    pol.burst         = calc_psched_ticks(rate_bytes_per_sec, burst_bytes);
    pol.rate.cell_log = cell_log;
    pol.rate.mpu      = 0;
    pol.rate.overhead = 0;
    pol.rate.cell_align = -1;
    pol.rate.rate     = (rate_bytes_per_sec >= 0xffffffffULL)
                            ? 0xffffffffU
                            : (uint32_t)rate_bytes_per_sec;

    if (req_addattr_l(req, TCA_ACT_KIND, "police", sizeof("police")) < 0)
        return -errno;

    size_t act_opts = req_nest_begin(req, TCA_ACT_OPTIONS | NLA_F_NESTED);
    if (!act_opts)
        return -EMSGSIZE;

    if (req_addattr_l(req, TCA_POLICE_TBF, &pol, sizeof(pol)) < 0)
        return -errno;
    if (req_addattr_l(req, TCA_POLICE_RATE, rtab, sizeof(rtab)) < 0)
        return -errno;
    if (rate_bytes_per_sec >= 0xffffffffULL) {
        if (req_addattr_l(req, TCA_POLICE_RATE64,
                          &rate_bytes_per_sec, sizeof(rate_bytes_per_sec)) < 0)
            return -errno;
    }

    req_nest_end(req, act_opts);
    return 0;
}

static int install_police_one_proto(int fd, int ifindex, int prio,
                                    uint16_t eth_proto, uint64_t rate_Bps,
                                    const char *src_ip, const char *iface)
{
    union nl_tc_req req;
    memset(&req, 0, sizeof(req));

    req.m.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.m.n.nlmsg_type  = RTM_NEWTFILTER;
    req.m.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;

    req.m.t.tcm_family  = AF_UNSPEC;
    req.m.t.tcm_ifindex = ifindex;
    req.m.t.tcm_parent  = HNC_TC_H_INGRESS_PARENT;
    req.m.t.tcm_info    = TC_H_MAKE((uint32_t)prio << 16, htons(eth_proto));

    if (src_ip != NULL && src_ip[0] != '\0') {
        struct {
            struct tc_u32_sel sel;
            struct tc_u32_key keys[4];
        } u32_pack;
        memset(&u32_pack, 0, sizeof(u32_pack));
        u32_pack.sel.flags = TC_U32_TERMINAL;

        if (eth_proto == ETH_P_IP) {
            struct in_addr v4;
            if (inet_pton(AF_INET, src_ip, &v4) != 1) {
                LOGE("invalid IPv4 src_ip '%s'", src_ip);
                return -EINVAL;
            }
            u32_pack.sel.nkeys   = 1;
            u32_pack.keys[0].val = v4.s_addr;
            u32_pack.keys[0].mask = 0xffffffffU;
            u32_pack.keys[0].off = 12;
        } else if (eth_proto == ETH_P_IPV6) {
            struct in6_addr v6;
            if (inet_pton(AF_INET6, src_ip, &v6) != 1) {
                LOGE("invalid IPv6 src_ip '%s'", src_ip);
                return -EINVAL;
            }
            u32_pack.sel.nkeys = 4;
            for (int k = 0; k < 4; k++) {
                memcpy(&u32_pack.keys[k].val, &v6.s6_addr[k * 4], 4);
                u32_pack.keys[k].mask = 0xffffffffU;
                u32_pack.keys[k].off  = 8 + k * 4;
            }
        } else {
            LOGE("src_ip matching requires protocol ip or ipv6");
            return -EINVAL;
        }

        req.m.t.tcm_handle = 0;
        if (req_addattr_l(&req, TCA_KIND, "u32", sizeof("u32")) < 0)
            return -errno;

        size_t opt_nest = req_nest_begin(&req, TCA_OPTIONS);
        if (!opt_nest)
            return -EMSGSIZE;

        size_t sel_bytes = sizeof(struct tc_u32_sel) +
                           (size_t)u32_pack.sel.nkeys * sizeof(struct tc_u32_key);
        if (req_addattr_l(&req, TCA_U32_SEL, &u32_pack, sel_bytes) < 0)
            return -errno;

        size_t u32_act = req_nest_begin(&req, TCA_U32_ACT);
        size_t act_1   = req_nest_begin(&req, 1);
        if (!u32_act || !act_1)
            return -EMSGSIZE;

        int rc = append_police_action(&req, rate_Bps);
        if (rc < 0)
            return rc;

        req_nest_end(&req, act_1);
        req_nest_end(&req, u32_act);
        req_nest_end(&req, opt_nest);
    } else {
        req.m.t.tcm_handle = 1U;
        if (req_addattr_l(&req, TCA_KIND, "matchall", sizeof("matchall")) < 0)
            return -errno;

        size_t options = req_nest_begin(&req, TCA_OPTIONS);
        size_t ma_act  = req_nest_begin(&req, TCA_MATCHALL_ACT);
        size_t act_1   = req_nest_begin(&req, 1);
        if (!options || !ma_act || !act_1)
            return -EMSGSIZE;

        int rc = append_police_action(&req, rate_Bps);
        if (rc < 0)
            return rc;

        req_nest_end(&req, act_1);
        req_nest_end(&req, ma_act);
        req_nest_end(&req, options);
    }

    uint64_t eff_burst = rate_Bps / 8ULL;
    if (eff_burst < HNC_POLICE_MIN_BURST)
        eff_burst = HNC_POLICE_MIN_BURST;

    int rc = rtnl_send_ack(fd, &req.m.n, "ingress police filter replace", 0);
    if (rc == 0) {
        LOGI("police prio %d proto=0x%04x rate=%lluB/s burst=%lluB mtu=%u installed on %s",
             prio, (unsigned)eth_proto,
             (unsigned long long)rate_Bps,
             (unsigned long long)eff_burst,
             HNC_POLICE_MTU, iface);
    }
    return rc;
}

static int delete_ingress_filter_prio(int fd, int ifindex, int prio, uint16_t eth_proto)
{
    union nl_tc_req req;
    memset(&req, 0, sizeof(req));

    req.m.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.m.n.nlmsg_type  = RTM_DELTFILTER;
    req.m.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    req.m.t.tcm_family  = AF_UNSPEC;
    req.m.t.tcm_ifindex = ifindex;
    req.m.t.tcm_parent  = HNC_TC_H_INGRESS_PARENT;
    req.m.t.tcm_handle  = 0;
    req.m.t.tcm_info    = TC_H_MAKE((uint32_t)prio << 16, htons(eth_proto));

    return rtnl_send_ack(fd, &req.m.n, "ingress filter delete", 1);
}

/* ── CLI entry point ─────────────────────────────────────────────────── */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s <iface> <ifb_iface> [prio]\n"
        "  %s police <iface> <rate> [prio] [all|ip|ipv6|dual] [src_ip]\n"
        "  %s police-del <iface> <prio> [all|ip|ipv6|dual]\n"
        "  %s del <iface> [prio]\n"
        "\n"
        "Mirred mode (default prio = %d, yielding prio 1 to clsact BPF):\n"
        "  tc qdisc  add dev <iface> clsact\n"
        "  tc filter replace dev <iface> ingress prio <prio> protocol all matchall \\\n"
        "      action mirred egress redirect dev <ifb_iface>\n"
        "\n"
        "Police mode (GRO-safe burst = max(rate_Bps/8, 65536), mtu = 65535, dual-stack):\n"
        "  Installs clsact ingress police filter(s) for ETH_P_ALL or ETH_P_IP + ETH_P_IPV6.\n"
        "\n"
        "Return codes:\n"
        "  0  OK (or EEXIST, idempotent)\n"
        "  1  iface not found\n"
        "  2  ifb_iface not found\n"
        "  3  netlink error\n"
        "  4  usage / invalid argument\n",
        argv0, argv0, argv0, argv0, HNC_DEFAULT_MIRRED_PRIO);
}

static int cmd_police(int argc, char **argv)
{
    if (argc < 4 || argc > 7) {
        usage(argv[0]);
        return RC_USAGE;
    }

    const char *iface   = argv[2];
    const char *ratestr = argv[3];
    uint64_t rate_Bps = 0;
    if (parse_rate_bytes_per_sec(ratestr, &rate_Bps) < 0) {
        LOGE("invalid rate '%s'", ratestr);
        return RC_USAGE;
    }

    int prio = HNC_DEFAULT_POLICE_PRIO;
    if (argc >= 5 && parse_prio_arg(argv[4], &prio) < 0) {
        LOGE("prio '%s' out of range (1..65535)", argv[4]);
        return RC_USAGE;
    }

    const char *proto_mode = (argc >= 6) ? argv[5] : "all";
    const char *src_ip     = (argc >= 7) ? argv[6] : NULL;

    if (src_ip && src_ip[0] != '\0' &&
        (strcmp(proto_mode, "all") == 0 || strcmp(proto_mode, "auto") == 0)) {
        proto_mode = strchr(src_ip, ':') ? "ipv6" : "ip";
    }

    unsigned iface_idx = if_nametoindex(iface);
    if (iface_idx == 0) {
        LOGE("iface '%s' not found: %s", iface, strerror(errno));
        return RC_IFACE_NOT_FOUND;
    }

    int fd = rtnl_open();
    if (fd < 0)
        return RC_NETLINK_ERROR;

    int rc = install_clsact(fd, (int)iface_idx, iface);
    if (rc < 0) {
        close(fd);
        return RC_NETLINK_ERROR;
    }

    if (strcmp(proto_mode, "all") == 0) {
        rc = install_police_one_proto(fd, (int)iface_idx, prio, ETH_P_ALL, rate_Bps, NULL, iface);
    } else if (strcmp(proto_mode, "ip") == 0 || strcmp(proto_mode, "ipv4") == 0) {
        rc = install_police_one_proto(fd, (int)iface_idx, prio, ETH_P_IP, rate_Bps, src_ip, iface);
    } else if (strcmp(proto_mode, "ipv6") == 0 || strcmp(proto_mode, "ip6") == 0) {
        rc = install_police_one_proto(fd, (int)iface_idx, prio, ETH_P_IPV6, rate_Bps, src_ip, iface);
    } else if (strcmp(proto_mode, "dual") == 0) {
        if (src_ip && src_ip[0] != '\0') {
            close(fd);
            LOGE("'dual' protocol mode cannot combine with a single-family src_ip");
            return RC_USAGE;
        }
        rc = install_police_one_proto(fd, (int)iface_idx, prio, ETH_P_IP, rate_Bps, NULL, iface);
        if (rc == 0) {
            int prio6 = (prio < 65535) ? (prio + 1) : prio;
            rc = install_police_one_proto(fd, (int)iface_idx, prio6, ETH_P_IPV6, rate_Bps, NULL, iface);
        }
    } else {
        close(fd);
        LOGE("unknown protocol mode '%s' (expected all|ip|ipv6|dual)", proto_mode);
        return RC_USAGE;
    }

    close(fd);
    if (rc == -EINVAL)
        return RC_USAGE;
    return (rc < 0) ? RC_NETLINK_ERROR : RC_OK;
}

static int cmd_police_del(int argc, char **argv)
{
    if (argc < 4 || argc > 5) {
        usage(argv[0]);
        return RC_USAGE;
    }
    const char *iface = argv[2];
    int prio = 0;
    if (parse_prio_arg(argv[3], &prio) < 0) {
        LOGE("prio '%s' out of range (1..65535)", argv[3]);
        return RC_USAGE;
    }
    const char *proto_mode = (argc >= 5) ? argv[4] : "all";

    unsigned iface_idx = if_nametoindex(iface);
    if (iface_idx == 0)
        return RC_OK;

    int fd = rtnl_open();
    if (fd < 0)
        return RC_NETLINK_ERROR;

    int rc = 0;
    if (strcmp(proto_mode, "all") == 0) {
        rc = delete_ingress_filter_prio(fd, (int)iface_idx, prio, ETH_P_ALL);
    } else if (strcmp(proto_mode, "ip") == 0 || strcmp(proto_mode, "ipv4") == 0) {
        rc = delete_ingress_filter_prio(fd, (int)iface_idx, prio, ETH_P_IP);
    } else if (strcmp(proto_mode, "ipv6") == 0 || strcmp(proto_mode, "ip6") == 0) {
        rc = delete_ingress_filter_prio(fd, (int)iface_idx, prio, ETH_P_IPV6);
    } else if (strcmp(proto_mode, "dual") == 0) {
        rc = delete_ingress_filter_prio(fd, (int)iface_idx, prio, ETH_P_IP);
        int prio6 = (prio < 65535) ? (prio + 1) : prio;
        int rc6 = delete_ingress_filter_prio(fd, (int)iface_idx, prio6, ETH_P_IPV6);
        if (rc == 0) rc = rc6;
    } else {
        close(fd);
        LOGE("unknown protocol mode '%s'", proto_mode);
        return RC_USAGE;
    }

    close(fd);
    return (rc < 0) ? RC_NETLINK_ERROR : RC_OK;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return RC_USAGE;
    }

    if (strcmp(argv[1], "police") == 0)
        return cmd_police(argc, argv);

    if (strcmp(argv[1], "police-del") == 0)
        return cmd_police_del(argc, argv);

    if (strcmp(argv[1], "del") == 0) {
        if (argc > 4) {
            usage(argv[0]);
            return RC_USAGE;
        }
        int dprio = HNC_DEFAULT_MIRRED_PRIO;
        if (argc == 4 && parse_prio_arg(argv[3], &dprio) < 0) {
            LOGE("prio '%s' out of range (1..65535)", argv[3]);
            return RC_USAGE;
        }
        unsigned idx = if_nametoindex(argv[2]);
        if (idx == 0)
            return RC_OK;
        int fd = rtnl_open();
        if (fd < 0)
            return RC_NETLINK_ERROR;
        int rc = delete_ingress_filter_prio(fd, (int)idx, dprio, ETH_P_ALL);
        close(fd);
        return (rc < 0) ? RC_NETLINK_ERROR : RC_OK;
    }

    int arg_off = 1;
    if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "replace") == 0 ||
        strcmp(argv[1], "redirect") == 0) {
        arg_off = 2;
    }

    int rem_args = argc - arg_off;
    if (rem_args < 2 || rem_args > 3) {
        usage(argv[0]);
        return RC_USAGE;
    }

    const char *iface     = argv[arg_off];
    const char *ifb_iface = argv[arg_off + 1];
    int prio = HNC_DEFAULT_MIRRED_PRIO;

    if (rem_args == 3) {
        if (parse_prio_arg(argv[arg_off + 2], &prio) < 0) {
            LOGE("prio '%s' out of range (1..65535)", argv[arg_off + 2]);
            return RC_USAGE;
        }
    }

    unsigned iface_idx = if_nametoindex(iface);
    if (iface_idx == 0) {
        LOGE("iface '%s' not found: %s", iface, strerror(errno));
        return RC_IFACE_NOT_FOUND;
    }

    unsigned ifb_idx = if_nametoindex(ifb_iface);
    if (ifb_idx == 0) {
        LOGE("ifb_iface '%s' not found: %s", ifb_iface, strerror(errno));
        return RC_IFB_NOT_FOUND;
    }

    int fd = rtnl_open();
    if (fd < 0)
        return RC_NETLINK_ERROR;

    int rc = install_clsact(fd, (int)iface_idx, iface);
    if (rc < 0) {
        close(fd);
        return RC_NETLINK_ERROR;
    }

    rc = install_matchall_filter(fd,
                                 (int)iface_idx, (int)ifb_idx,
                                 prio, iface, ifb_iface);
    close(fd);
    if (rc < 0)
        return RC_NETLINK_ERROR;

    return RC_OK;
}
