/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hnc_tc_ingress.c — Install tc clsact + matchall + mirred via raw rtnetlink
 *
 * Purpose
 * -------
 * HNC needs the following two tc operations on the hotspot uplink iface to
 * steer ingress traffic to an IFB device (so HTB can shape uplink):
 *
 *     tc qdisc  add dev <iface> clsact
 *     tc filter add dev <iface> ingress prio <prio> protocol all matchall \
 *         action mirred egress redirect dev <ifb_iface>
 *
 * On ColorOS 16 / realme GT 7 Pro, /system/bin/tc is a ROM-customised binary
 * whose user-space pre-validation rejects the "ingress" parent keyword during
 * the 30–45 s window between `wlan2` coming UP and `oplus-netd` finishing its
 * own qdisc-tree init. The kernel itself always accepts the netlink message,
 * so bypassing /system/bin/tc and talking rtnetlink directly gets us a clean
 * install at T+0 instead of T+30 s.
 *
 * Usage
 * -----
 *     hnc_tc_ingress <iface> <ifb_iface> [prio]
 *
 *     prio defaults to 1; range [1..65535].
 *
 * Return codes
 * ------------
 *     0   installed OK, or already present (idempotent EEXIST)
 *     1   iface not found           (if_nametoindex == 0)
 *     2   ifb_iface not found
 *     3   netlink error             (socket/send/recv/kernel errno)
 *     4   CLI / usage error
 *
 * stderr carries human-readable log lines; stdout is left empty so callers
 * can capture it without noise.
 *
 * Dependencies
 * ------------
 * Pure libc + Linux uapi headers only. No libnl, no libmnl, no libbpf.
 * Targets Android arm64 via NDK r27c (aarch64-linux-android21-clang); also
 * compiles on any Linux host with kernel headers ≥ 4.14.
 *
 * Style note
 * ----------
 * addattr_l / addattr_nest / addattr_nest_end are patterned after iproute2's
 * lib/libnetlink.c (GPL-2.0), which is what the canonical `tc` userspace
 * uses to build the exact same messages.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

/*
 * TC_H_CLSACT | TC_H_MIN_INGRESS == 0xFFFFFFF1 | 0x0000FFF2 == 0xFFFFFFF2.
 *
 * This is the "ingress" virtual parent used by `tc filter add dev X ingress`.
 * Defined literally so we don't depend on both macros being exported by
 * whatever version of <linux/pkt_sched.h> the NDK sysroot ships.
 */
#define HNC_TC_H_INGRESS_PARENT   0xFFFFFFF2U

/*
 * Conventional clsact qdisc handle: major=0xFFFF, minor=0x0000. The kernel
 * rewrites this internally anyway (see net/sched/sch_ingress.c), but iproute2
 * emits this exact value so we do too — fewer cross-kernel surprises.
 */
#define HNC_TC_H_CLSACT_HANDLE    0xFFFF0000U

#define RTNL_REQ_BUF_SIZE         1024    /* per-request scratch buffer      */
#define RTNL_RECV_BUF_SIZE        8192    /* ACK / NLMSG_ERROR recv buffer   */
#define RTNL_RECV_TIMEOUT_S       3       /* kernel ACKs are always fast     */

/* Return codes — keep in sync with README.md and SPEC. */
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

/* ── rtnetlink nlattr builders ───────────────────────────────────────── */

/* Address of the next rtattr slot inside an in-progress nlmsghdr. */
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/*
 * Append a flat attribute (type, data, alen) to the message at `n`, which is
 * backed by a buffer of total size `maxlen`. Returns 0 on success or -1 on
 * overflow (errno = EMSGSIZE).
 */
static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
                     const void *data, size_t alen)
{
    size_t        len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        errno = EMSGSIZE;
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = (unsigned short)type;
    rta->rta_len  = (unsigned short)len;
    if (alen > 0 && data != NULL)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = (uint32_t)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len));
    return 0;
}

/*
 * Open a nested attribute. The returned pointer must later be passed to
 * addattr_nest_end() to patch the length once the contents are written.
 * Returns NULL on overflow (errno set by addattr_l).
 *
 * NOTE: `type` is written verbatim — caller decides whether to OR in
 * NLA_F_NESTED. iproute2's wire convention for tc filters is to set that
 * flag only on TCA_ACT_OPTIONS, leaving TCA_OPTIONS / TCA_MATCHALL_ACT /
 * action-index nests with the plain type. We mirror that exactly so the
 * bytes we emit are byte-identical to `tc` for every kernel that `tc` works
 * against.
 */
static struct rtattr *addattr_nest(struct nlmsghdr *n, size_t maxlen, int type)
{
    struct rtattr *nest = NLMSG_TAIL(n);

    if (addattr_l(n, maxlen, type, NULL, 0) < 0)
        return NULL;
    return nest;
}

/* Patch nest->rta_len to cover everything written after addattr_nest(). */
static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (unsigned short)((char *)NLMSG_TAIL(n) - (char *)nest);
}

/* ── rtnetlink socket I/O ────────────────────────────────────────────── */

static uint32_t g_seq;  /* per-process sequence counter, seeded in rtnl_open */

/* Open + bind an AF_NETLINK/NETLINK_ROUTE socket. Returns fd or -1. */
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
    /* nl_pid = 0 → kernel auto-assigns to our PID; good enough for one-shot. */
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOGE("bind(AF_NETLINK): %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Defensive recv timeout — kernel ACKs in µs; anything slow is a bug. */
    struct timeval tv = { .tv_sec = RTNL_RECV_TIMEOUT_S, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (g_seq == 0) {
        g_seq = (uint32_t)(time(NULL) ^ ((uint32_t)getpid() << 16));
        if (g_seq == 0) g_seq = 1;
    }
    return fd;
}

/*
 * Send one already-filled request and wait for the single NLMSG_ERROR reply
 * that NLM_F_ACK guarantees.
 *
 * Return value:
 *     0              kernel ACKed with err->error == 0
 *     0              kernel returned -EEXIST (treated as idempotent success)
 *     negative errno kernel rejected the request, or I/O failed
 *
 * `what` is purely a log tag ("clsact qdisc add", etc.).
 */
static int rtnl_send_ack(int fd, struct nlmsghdr *n, const char *what)
{
    /* Stamp the request right before sending so seq is monotonic. */
    n->nlmsg_seq = ++g_seq;
    n->nlmsg_pid = 0;   /* reply routed back to our bound nl_pid */

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    ssize_t sent = sendto(fd, n, n->nlmsg_len, 0,
                          (struct sockaddr *)&sa, sizeof(sa));
    if (sent < 0) {
        LOGE("%s: sendto: %s", what, strerror(errno));
        return -errno;
    }
    if ((size_t)sent != n->nlmsg_len) {
        LOGE("%s: short sendto (%zd of %u)", what, sent, n->nlmsg_len);
        return -EIO;
    }

    char         buf[RTNL_RECV_BUF_SIZE];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    /* Loop until we get a reply with matching seq, or I/O fails. */
    for (;;) {
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

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
            /* Stray multicast or stale reply — skip. */
            if (h->nlmsg_seq != n->nlmsg_seq)
                continue;

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
                if (err->error == 0)
                    return 0;                       /* success ACK */
                if (err->error == -EEXIST)
                    return 0;                       /* idempotent  */
                LOGE("%s: kernel rejected: %s (errno=%d)",
                     what, strerror(-err->error), -err->error);
                return err->error;                  /* already negative */
            }

            /* Anything else with matching seq is unexpected for NEW* req. */
            LOGE("%s: unexpected nlmsg_type=%u", what, h->nlmsg_type);
            return -EPROTO;
        }
        /* No matching seq in this datagram — loop and read more. */
    }
}

/* ── Build & send: RTM_NEWQDISC clsact ───────────────────────────────── */

/*
 * Install the clsact qdisc on `ifindex`. Idempotent: EEXIST is success.
 * clsact replaces the legacy "ingress" qdisc from Linux 4.5 onwards and
 * exposes both ingress and egress filter hooks via the TC_H_MIN_INGRESS /
 * TC_H_MIN_EGRESS minor slots.
 */
static int install_clsact(int fd, int ifindex, const char *iface)
{
    struct {
        struct nlmsghdr n;
        struct tcmsg    t;
        char            buf[RTNL_REQ_BUF_SIZE];
    } req;
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_type  = RTM_NEWQDISC;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent  = TC_H_CLSACT;                   /* 0xFFFFFFF1 */
    req.t.tcm_handle  = HNC_TC_H_CLSACT_HANDLE;        /* 0xFFFF0000 */

    if (addattr_l(&req.n, sizeof(req), TCA_KIND,
                  "clsact", sizeof("clsact")) < 0) {
        LOGE("clsact: addattr_l(TCA_KIND): %s", strerror(errno));
        return -errno;
    }

    int rc = rtnl_send_ack(fd, &req.n, "clsact qdisc add");
    if (rc == 0)
        LOGI("clsact qdisc OK on %s (ifindex=%d)", iface, ifindex);
    return rc;
}

/* ── Build & send: RTM_NEWTFILTER matchall + mirred ──────────────────── */

/*
 * Append a single "mirred egress redirect dev <ifb>" action into the current
 * TCA_MATCHALL_ACT -> act[N] nested attribute. Caller is responsible for the
 * enclosing nest_end() calls.
 */
static int append_mirred_action(struct nlmsghdr *n, size_t maxlen,
                                int ifb_ifindex)
{
    struct tc_mirred mirred;
    memset(&mirred, 0, sizeof(mirred));
    /*
     * tc_gen embedded fields (index=0 capab=0 refcnt=0 bindcnt=0) left zero.
     * .action = TC_ACT_STOLEN tells the ingress path this skb is now owned
     * by the mirred action and must not be freed by the caller.
     */
    mirred.action  = TC_ACT_STOLEN;
    mirred.eaction = TCA_EGRESS_REDIR;   /* redirect (not mirror)  */
    mirred.ifindex = ifb_ifindex;

    if (addattr_l(n, maxlen, TCA_ACT_KIND,
                  "mirred", sizeof("mirred")) < 0)
        return -errno;

    /*
     * iproute2 emits TCA_ACT_OPTIONS with NLA_F_NESTED set (type | 0x8000).
     * All the OTHER nests (TCA_OPTIONS, TCA_MATCHALL_ACT, action-index)
     * are emitted with the plain type — we match that convention exactly
     * so our bytes are identical to `tc` on the wire.
     */
    struct rtattr *act_opts =
        addattr_nest(n, maxlen, TCA_ACT_OPTIONS | NLA_F_NESTED);
    if (!act_opts) return -errno;

    if (addattr_l(n, maxlen, TCA_MIRRED_PARMS,
                  &mirred, sizeof(mirred)) < 0)
        return -errno;

    addattr_nest_end(n, act_opts);
    return 0;
}

/*
 * Install a matchall classifier on the ingress slot of `iface_ifindex` with
 * a single mirred-egress-redirect action pointing at `ifb_ifindex`.
 *
 * Equivalent shell:
 *     tc filter add dev <iface> ingress prio <prio> protocol all matchall \
 *         action mirred egress redirect dev <ifb_iface>
 *
 * Idempotent: EEXIST on the same (parent, prio) is treated as success.
 */
static int install_matchall_filter(int fd,
                                   int iface_ifindex, int ifb_ifindex,
                                   int prio,
                                   const char *iface, const char *ifb_iface)
{
    struct {
        struct nlmsghdr n;
        struct tcmsg    t;
        char            buf[RTNL_REQ_BUF_SIZE];
    } req;
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_type  = RTM_NEWTFILTER;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = iface_ifindex;
    req.t.tcm_parent  = HNC_TC_H_INGRESS_PARENT;        /* 0xFFFFFFF2 */
    req.t.tcm_handle  = 0;                              /* let kernel pick */

    /*
     * tcm_info layout (u32, host byte order container):
     *   bits 31..16  prio   — plain integer major id
     *   bits 15.. 0  proto  — **stored in network byte order**
     *
     * In net/sched/cls_api.c the kernel does
     *     protocol = TC_H_MIN(t->tcm_info)
     * then compares against htons(ETH_P_ALL), so htons() here is mandatory.
     */
    req.t.tcm_info = TC_H_MAKE((uint32_t)prio << 16, htons(ETH_P_ALL));

    if (addattr_l(&req.n, sizeof(req), TCA_KIND,
                  "matchall", sizeof("matchall")) < 0) {
        LOGE("matchall: addattr_l(TCA_KIND): %s", strerror(errno));
        return -errno;
    }

    /*
     * Nested attribute tree:
     *   TCA_OPTIONS
     *     TCA_MATCHALL_ACT              (= the action list)
     *       [rta_type = 1]              (= action index 1; single action)
     *         TCA_ACT_KIND = "mirred"
     *         TCA_ACT_OPTIONS
     *           TCA_MIRRED_PARMS = struct tc_mirred
     */
    struct rtattr *options = addattr_nest(&req.n, sizeof(req), TCA_OPTIONS);
    if (!options) { LOGE("matchall: nest TCA_OPTIONS"); return -errno; }

    struct rtattr *ma_act = addattr_nest(&req.n, sizeof(req), TCA_MATCHALL_ACT);
    if (!ma_act)  { LOGE("matchall: nest TCA_MATCHALL_ACT"); return -errno; }

    /* Action index 1 — the rtattr type *is* the index. */
    struct rtattr *act_1 = addattr_nest(&req.n, sizeof(req), 1);
    if (!act_1)   { LOGE("matchall: nest act[1]"); return -errno; }

    int rc = append_mirred_action(&req.n, sizeof(req), ifb_ifindex);
    if (rc < 0) {
        LOGE("matchall: append_mirred_action: %s", strerror(-rc));
        return rc;
    }

    addattr_nest_end(&req.n, act_1);
    addattr_nest_end(&req.n, ma_act);
    addattr_nest_end(&req.n, options);

    rc = rtnl_send_ack(fd, &req.n, "matchall+mirred filter add");
    if (rc == 0)
        LOGI("matchall prio %d → %s (ifindex=%d) installed on %s",
             prio, ifb_iface, ifb_ifindex, iface);
    return rc;
}

/* ── CLI entry point ─────────────────────────────────────────────────── */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s <iface> <ifb_iface> [prio]\n"
        "\n"
        "Installs on <iface>:\n"
        "  tc qdisc  add dev <iface> clsact\n"
        "  tc filter add dev <iface> ingress prio <prio> protocol all matchall \\\n"
        "      action mirred egress redirect dev <ifb_iface>\n"
        "\n"
        "Arguments:\n"
        "  iface       upstream iface (e.g. wlan2) — must exist\n"
        "  ifb_iface   IFB redirect target (e.g. ifb0) — must exist & UP\n"
        "  prio        filter priority, 1..65535 (default 1)\n"
        "\n"
        "Return codes:\n"
        "  0  OK (or EEXIST, idempotent)\n"
        "  1  iface not found\n"
        "  2  ifb_iface not found\n"
        "  3  netlink error (kernel rejection / I/O failure)\n"
        "  4  usage / invalid argument\n",
        argv0);
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return RC_USAGE;
    }

    const char *iface     = argv[1];
    const char *ifb_iface = argv[2];

    int prio = 1;
    if (argc == 4) {
        char *endp = NULL;
        errno = 0;
        long v = strtol(argv[3], &endp, 10);
        if (errno != 0 || endp == argv[3] || *endp != '\0'
            || v < 1 || v > 65535) {
            LOGE("prio '%s' out of range (1..65535)", argv[3]);
            return RC_USAGE;
        }
        prio = (int)v;
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

    /* 1. clsact qdisc (idempotent, EEXIST is fine) */
    int rc = install_clsact(fd, (int)iface_idx, iface);
    if (rc < 0) {
        close(fd);
        return RC_NETLINK_ERROR;
    }

    /* 2. matchall ingress filter + mirred egress redirect action */
    rc = install_matchall_filter(fd,
                                 (int)iface_idx, (int)ifb_idx,
                                 prio, iface, ifb_iface);
    close(fd);
    if (rc < 0)
        return RC_NETLINK_ERROR;

    return RC_OK;
}
