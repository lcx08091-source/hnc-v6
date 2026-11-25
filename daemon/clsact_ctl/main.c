/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hnc_clsact_ctl — HNC v5.40.0 Dual-Stack clsact ingress/egress BPF loader & map manager
 *
 * Supports both legacy ip_mark_map (4B IPv4 -> 4B mark) and v5.34+ mac_mark_map
 * (8B padded L2 MAC -> 4B mark) + optional SEC("tc_egress") AOSP tether6 bypass guard.
 *
 * v5.40.0 orthogonal skb->mark bitfield normalization:
 *   - [15:0]  0x0000ffffU : Android netd netId / permission bits (preserved untouched)
 *   - [23:16] 0x00ff0000U : HNC per-device slot mark (0x00800000U | (mid << 16))
 *   - [31:24] 0xff000000U : HNC App/QoS tier marks (preserved untouched)
 *   Inputs in update/sync may pass raw mid (1..99), legacy (0x800000 + mid),
 *   or pre-encoded v5.40.0 orthogonal marks (0x00810000..0x00e30000).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include <linux/bpf.h>
#include <linux/elf.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>

#if defined(__NR_bpf)
#  define SYS_BPF_NO __NR_bpf
#elif defined(__aarch64__)
#  define SYS_BPF_NO 280
#elif defined(__arm__)
#  define SYS_BPF_NO 386
#elif defined(__x86_64__)
#  define SYS_BPF_NO 321
#elif defined(__i386__)
#  define SYS_BPF_NO 357
#else
#  error "unknown arch, define SYS_BPF_NO"
#endif

#ifndef HNC_VERSION
#define HNC_VERSION      "dev"
#endif

#define OBJ_PATH_DEFAULT "/data/local/hnc/bin/hnc_clsact.o"
#define PIN_DIR          "/sys/fs/bpf/hnc"
#define MAP_PIN          PIN_DIR "/ip_mark_map"
#define MAC_MAP_PIN      PIN_DIR "/mac_mark_map"
#define STATS_MAP_PIN    PIN_DIR "/dev_stats_map"

#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

#define TC_H_CLSACT_HANDLE   0xFFFF0000U
#define TC_H_CLSACT_PARENT   0xFFFFFFF1U
#define TC_H_INGRESS_PARENT  0xFFFFFFF2U
#define TC_H_EGRESS_PARENT   0xFFFFFFF3U
#define HNC_FILTER_PREF      1
#define HNC_FILTER_HANDLE    1
#define HNC_FILTER_KIND      "bpf"
#define HNC_PROG_NAME        "hnc_clsact"
#define HNC_EGRESS_NAME      "hnc_clsact_eg"

#define HNC_MARK_DEV_MASK    0x00ff0000U
#define HNC_MARK_DEV_VALID   0x00800000U
#define HNC_MARK_DROP        0xffffffffU

#ifndef TCA_BPF_FLAG_ACT_DIRECT
#define TCA_BPF_FLAG_ACT_DIRECT 1
#endif

#define HNC_BPF_OBJ_GET_INFO_BY_FD 15

#define R_BPF_64_64       1
#define BPF_PSEUDO_MAP_FD 1
#define BPF_LD_DW_IMM     0x18

#define RC_OK        0
#define RC_IFACE     1
#define RC_BPF       2
#define RC_NETLINK   3
#define RC_USAGE     4
#define RC_MAP       5

#define LOGE(...) do { fprintf(stderr, "clsact_ctl: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define LOGI(...) do { fprintf(stderr, "clsact_ctl: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)

struct mac_key {
    uint8_t  mac[6];
    uint16_t pad;
};

union bpf_attr_pad {
    union bpf_attr attr;
    char pad[128];
};

static int sys_bpf(int cmd, union bpf_attr_pad *a)
{
    return (int)syscall(SYS_BPF_NO, cmd, a, sizeof(union bpf_attr));
}

struct nl_tc_req {
    struct nlmsghdr n;
    struct tcmsg    t;
    uint8_t         attr_buf[512];
} __attribute__((aligned(NLMSG_ALIGNTO)));

_Static_assert(__builtin_offsetof(struct nl_tc_req, attr_buf) == NLMSG_LENGTH(sizeof(struct tcmsg)),
               "nl_tc_req header/payload offset mismatch");

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
                     const void *data, size_t alen)
{
    size_t off = NLMSG_ALIGN(n->nlmsg_len);
    size_t len = RTA_LENGTH(alen);
    if (off + RTA_ALIGN(len) > maxlen)
        return -1;
    struct rtattr hdr = {
        .rta_len  = (unsigned short)len,
        .rta_type = (unsigned short)type,
    };
    uint8_t *base = (uint8_t *)n;
    memcpy(base + off, &hdr, sizeof(hdr));
    if (alen && data)
        memcpy(base + off + RTA_LENGTH(0), data, alen);
    n->nlmsg_len = (uint32_t)(off + RTA_ALIGN(len));
    return 0;
}

static int addattr_nest(struct nlmsghdr *n, size_t maxlen, int type, size_t *nest_off_out)
{
    size_t off = NLMSG_ALIGN(n->nlmsg_len);
    if (addattr_l(n, maxlen, type, NULL, 0) < 0)
        return -1;
    *nest_off_out = off;
    return 0;
}

static void addattr_nest_end(struct nlmsghdr *n, size_t nest_off)
{
    uint8_t *base = (uint8_t *)n;
    struct rtattr hdr;
    memcpy(&hdr, base + nest_off, sizeof(hdr));
    hdr.rta_len = (unsigned short)(NLMSG_ALIGN(n->nlmsg_len) - nest_off);
    memcpy(base + nest_off, &hdr, sizeof(hdr));
}

static uint32_t g_seq;

static int rtnl_talk(int fd, struct nlmsghdr *req)
{
    uint8_t buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = req, .iov_len = req->nlmsg_len };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t sent;
    do {
        sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0)
        return -errno;

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int tries = 0; tries < 16; tries++) {
        ssize_t n;
        do {
            n = recv(fd, buf, sizeof(buf), 0);
        } while (n < 0 && errno == EINTR);
        if (n < 0)
            return -errno;
        if (n == 0)
            return -ECONNRESET;

        size_t rem = (size_t)n;
        for (size_t off = 0; rem >= sizeof(struct nlmsghdr); ) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof(h));
            if (h.nlmsg_len < sizeof(struct nlmsghdr) || (size_t)h.nlmsg_len > rem)
                break;
            size_t msg_off = off;
            size_t step = NLMSG_ALIGN(h.nlmsg_len);
            if (step > rem)
                step = rem;
            off += step;
            rem -= step;
            if (h.nlmsg_seq != g_seq)
                continue;
            if (h.nlmsg_type == NLMSG_ERROR) {
                if (h.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    return -EBADMSG;
                struct nlmsgerr e;
                memcpy(&e, buf + msg_off + NLMSG_LENGTH(0), sizeof(e));
                if (e.error == 0 || e.error == -EEXIST)
                    return 0;
                return e.error;
            }
            if (h.nlmsg_type == NLMSG_DONE)
                return 0;
        }
    }
    return -EPROTO;
}

static int rtnl_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        LOGE("socket(AF_NETLINK): %s", strerror(errno));
        return -1;
    }
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOGE("bind(AF_NETLINK): %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int clsact_qdisc_ensure(int nlfd, unsigned ifindex)
{
    struct nl_tc_req req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.t));
    req.n.nlmsg_type  = RTM_NEWQDISC;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.n.nlmsg_seq   = ++g_seq;
    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = (int)ifindex;
    req.t.tcm_parent  = TC_H_CLSACT_PARENT;
    req.t.tcm_handle  = TC_H_CLSACT_HANDLE;

    if (addattr_l(&req.n, sizeof(req), TCA_KIND, "clsact", strlen("clsact") + 1) < 0)
        return -EMSGSIZE;

    int rc = rtnl_talk(nlfd, &req.n);
    if (rc == 0)
        LOGI("clsact qdisc present/added (ifindex=%u)", ifindex);
    else
        LOGE("clsact qdisc add: %s", strerror(-rc));
    return rc;
}

static int bpf_filter_attach_dir(int nlfd, unsigned ifindex, uint32_t parent,
                                 int prog_fd, const char *prog_name)
{
    struct nl_tc_req req;
    size_t opt_off = 0;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.t));
    req.n.nlmsg_type  = RTM_NEWTFILTER;
    /* NLM_F_REPLACE is required so install/repair atomically swaps upgraded BPF
     * programs on handle 1 instead of silently leaving stale programs behind. */
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    req.n.nlmsg_seq   = ++g_seq;
    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = (int)ifindex;
    req.t.tcm_parent  = parent;
    req.t.tcm_info    = ((uint32_t)HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    req.t.tcm_handle  = HNC_FILTER_HANDLE;

    if (addattr_l(&req.n, sizeof(req), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return -EMSGSIZE;

    if (addattr_nest(&req.n, sizeof(req), TCA_OPTIONS, &opt_off) < 0)
        return -EMSGSIZE;
    uint32_t fd32 = (uint32_t)prog_fd;
    if (addattr_l(&req.n, sizeof(req), TCA_BPF_FD, &fd32, sizeof(fd32)) < 0)
        return -EMSGSIZE;
    if (addattr_l(&req.n, sizeof(req), TCA_BPF_NAME, prog_name,
                  strlen(prog_name) + 1) < 0)
        return -EMSGSIZE;
    uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    if (addattr_l(&req.n, sizeof(req), TCA_BPF_FLAGS, &flags, sizeof(flags)) < 0)
        return -EMSGSIZE;
    addattr_nest_end(&req.n, opt_off);

    int rc = rtnl_talk(nlfd, &req.n);
    if (rc == 0)
        LOGI("bpf filter (%s) attached at parent=0x%x pref=%d (fd=%d)",
             prog_name, parent, HNC_FILTER_PREF, prog_fd);
    else
        LOGE("bpf filter (%s) attach: %s", prog_name, strerror(-rc));
    return rc;
}

static int rtnl_query_hnc_filter(int fd, struct nlmsghdr *req)
{
    uint8_t buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = req, .iov_len = req->nlmsg_len };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t sent;
    do {
        sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0)
        return 0;

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int saw_tfilter = 0;
    int saw_bpf_name = 0;
    int name_matched = 0;

    for (int tries = 0; tries < 16; tries++) {
        ssize_t n;
        do {
            n = recv(fd, buf, sizeof(buf), 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return 0;

        size_t rem = (size_t)n;
        for (size_t off = 0; rem >= sizeof(struct nlmsghdr); ) {
            struct nlmsghdr h;
            memcpy(&h, buf + off, sizeof(h));
            if (h.nlmsg_len < sizeof(struct nlmsghdr) || (size_t)h.nlmsg_len > rem)
                break;
            size_t msg_off = off;
            size_t step = NLMSG_ALIGN(h.nlmsg_len);
            if (step > rem)
                step = rem;
            off += step;
            rem -= step;
            if (h.nlmsg_seq != g_seq)
                continue;

            if (h.nlmsg_type == RTM_NEWTFILTER &&
                (size_t)h.nlmsg_len >= NLMSG_LENGTH(sizeof(struct tcmsg))) {
                saw_tfilter = 1;
                size_t attr_off = NLMSG_SPACE(sizeof(struct tcmsg));
                if ((size_t)h.nlmsg_len > attr_off) {
                    size_t attr_rem = (size_t)h.nlmsg_len - attr_off;
                    const uint8_t *ap = buf + msg_off + attr_off;
                    while (attr_rem >= sizeof(struct rtattr)) {
                        struct rtattr rta;
                        memcpy(&rta, ap, sizeof(rta));
                        if (rta.rta_len < sizeof(struct rtattr) || (size_t)rta.rta_len > attr_rem)
                            break;
                        if ((rta.rta_type & 0x3fffU) == TCA_OPTIONS &&
                            (size_t)rta.rta_len > RTA_LENGTH(0)) {
                            size_t sub_rem = (size_t)rta.rta_len - RTA_LENGTH(0);
                            const uint8_t *sp = ap + RTA_LENGTH(0);
                            while (sub_rem >= sizeof(struct rtattr)) {
                                struct rtattr srta;
                                memcpy(&srta, sp, sizeof(srta));
                                if (srta.rta_len < sizeof(struct rtattr) || (size_t)srta.rta_len > sub_rem)
                                    break;
                                if ((srta.rta_type & 0x3fffU) == TCA_BPF_NAME &&
                                    (size_t)srta.rta_len > RTA_LENGTH(0)) {
                                    size_t pay_len = (size_t)srta.rta_len - RTA_LENGTH(0);
                                    char pname[64];
                                    size_t cp = pay_len < (sizeof(pname) - 1U) ? pay_len : (sizeof(pname) - 1U);
                                    memcpy(pname, sp + RTA_LENGTH(0), cp);
                                    pname[cp] = '\0';
                                    saw_bpf_name = 1;
                                    if (strncmp(pname, HNC_PROG_NAME, strlen(HNC_PROG_NAME)) == 0)
                                        name_matched = 1;
                                }
                                size_t sstep = RTA_ALIGN(srta.rta_len);
                                if (sstep > sub_rem)
                                    break;
                                sp += sstep;
                                sub_rem -= sstep;
                            }
                        }
                        size_t astep = RTA_ALIGN(rta.rta_len);
                        if (astep > attr_rem)
                            break;
                        ap += astep;
                        attr_rem -= astep;
                    }
                }
            } else if (h.nlmsg_type == NLMSG_ERROR) {
                if (h.nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    return 0;
                struct nlmsgerr e;
                memcpy(&e, buf + msg_off + NLMSG_LENGTH(0), sizeof(e));
                if (e.error != 0)
                    return 0;
                if (saw_bpf_name)
                    return name_matched;
                return saw_tfilter ? 1 : 1;
            } else if (h.nlmsg_type == NLMSG_DONE) {
                if (saw_bpf_name)
                    return name_matched;
                return saw_tfilter;
            }
        }
    }
    return 0;
}

static int bpf_filter_exists_dir(int nlfd, unsigned ifindex, uint32_t parent)
{
    struct nl_tc_req req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.t));
    req.n.nlmsg_type  = RTM_GETTFILTER;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq   = ++g_seq;
    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = (int)ifindex;
    req.t.tcm_parent  = parent;
    req.t.tcm_info    = ((uint32_t)HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    req.t.tcm_handle  = HNC_FILTER_HANDLE;
    if (addattr_l(&req.n, sizeof(req), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return 0;
    return rtnl_query_hnc_filter(nlfd, &req.n);
}

static int bpf_filter_detach_dir(int nlfd, unsigned ifindex, uint32_t parent)
{
    struct nl_tc_req req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.t));
    req.n.nlmsg_type  = RTM_DELTFILTER;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq   = ++g_seq;
    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = (int)ifindex;
    req.t.tcm_parent  = parent;
    req.t.tcm_info    = ((uint32_t)HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    req.t.tcm_handle  = HNC_FILTER_HANDLE;
    if (addattr_l(&req.n, sizeof(req), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return -EMSGSIZE;
    return rtnl_talk(nlfd, &req.n);
}

static int clsact_qdisc_exists(int nlfd, unsigned ifindex)
{
    struct nl_tc_req req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.t));
    req.n.nlmsg_type  = RTM_GETQDISC;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq   = ++g_seq;
    req.t.tcm_family  = AF_UNSPEC;
    req.t.tcm_ifindex = (int)ifindex;
    req.t.tcm_parent  = TC_H_CLSACT_PARENT;
    req.t.tcm_handle  = TC_H_CLSACT_HANDLE;
    return rtnl_talk(nlfd, &req.n) == 0;
}

/* ── Mini ELF Loader (Overflow & Alignment Hardened) ─────────────────── */

struct elf_ctx {
    uint8_t    *data;
    size_t      size;
    Elf64_Ehdr  eh;
    Elf64_Shdr *sh;
    const char *shstr;
    size_t      shstr_sz;
};

static int sh_type_needs_data(uint32_t t)
{
    return t != 0 && t != 8;
}

static int range_valid(uint64_t off, uint64_t len, size_t total)
{
    return off <= total && len <= total - (size_t)off;
}

static void elf_free(struct elf_ctx *c)
{
    if (!c)
        return;
    free(c->sh);
    free(c->data);
    memset(c, 0, sizeof(*c));
}

static int elf_load(struct elf_ctx *c, const char *path)
{
    memset(c, 0, sizeof(*c));
    FILE *f = fopen(path, "rbe");
    if (!f) {
        LOGE("open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < (long)sizeof(Elf64_Ehdr) || sz > (4L << 20) || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        LOGE("bad obj size %ld", sz);
        return -1;
    }
    c->data = malloc((size_t)sz);
    if (!c->data) {
        fclose(f);
        return -1;
    }
    c->size = (size_t)sz;
    if (fread(c->data, 1, c->size, f) != c->size) {
        fclose(f);
        free(c->data);
        c->data = NULL;
        LOGE("read %s failed", path);
        return -1;
    }
    fclose(f);

    memcpy(&c->eh, c->data, sizeof(c->eh));
    if (memcmp(c->eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        c->eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        c->eh.e_machine != EM_BPF) {
        LOGE("not an eBPF ELF object: %s", path);
        free(c->data);
        c->data = NULL;
        return -1;
    }
    uint64_t sh_bytes = (uint64_t)c->eh.e_shnum * sizeof(Elf64_Shdr);
    if (c->eh.e_shoff == 0 || c->eh.e_shnum == 0 ||
        c->eh.e_shentsize != sizeof(Elf64_Shdr) ||
        c->eh.e_shstrndx >= c->eh.e_shnum ||
        !range_valid(c->eh.e_shoff, sh_bytes, c->size)) {
        LOGE("bad section table");
        elf_free(c);
        return -1;
    }
    /* llvm-strip -g 剥离 DWARF 后可能重排 e_shoff 至 4 字节边界; 独立对齐拷贝避免误拒与 32 位 ARM SIGBUS */
    c->sh = malloc((size_t)sh_bytes);
    if (!c->sh) {
        elf_free(c);
        return -1;
    }
    memcpy(c->sh, c->data + c->eh.e_shoff, (size_t)sh_bytes);
    Elf64_Shdr *shstr_sh = &c->sh[c->eh.e_shstrndx];
    if (shstr_sh->sh_size == 0 ||
        !range_valid(shstr_sh->sh_offset, shstr_sh->sh_size, c->size)) {
        elf_free(c);
        return -1;
    }
    c->shstr    = (const char *)(c->data + shstr_sh->sh_offset);
    c->shstr_sz = (size_t)shstr_sh->sh_size;
    if (c->shstr[c->shstr_sz - 1] != '\0') {
        LOGE("unterminated shstrtab");
        elf_free(c);
        return -1;
    }
    for (int i = 0; i < c->eh.e_shnum; i++) {
        uint64_t so = c->sh[i].sh_offset, ss = c->sh[i].sh_size;
        if (c->sh[i].sh_name >= c->shstr_sz ||
            (sh_type_needs_data(c->sh[i].sh_type) && !range_valid(so, ss, c->size))) {
            LOGE("section %d out of bounds", i);
            elf_free(c);
            return -1;
        }
    }
    return 0;
}

static int sec_index(struct elf_ctx *c, const char *name)
{
    for (int i = 0; i < c->eh.e_shnum; i++) {
        if (c->sh[i].sh_name >= c->shstr_sz)
            continue;
        const char *n = c->shstr + c->sh[i].sh_name;
        if (strcmp(n, name) == 0)
            return i;
    }
    return -1;
}

static int get_sym_strtab(struct elf_ctx *c, int symi,
                          const uint8_t **out_sym_base, size_t *out_nsym,
                          const char **out_str, size_t *out_strsz)
{
    if (symi < 0 || symi >= c->eh.e_shnum)
        return -1;
    Elf64_Shdr *symsh = &c->sh[symi];
    if (symsh->sh_type != SHT_SYMTAB || symsh->sh_link >= (uint32_t)c->eh.e_shnum)
        return -1;
    Elf64_Shdr *strsh = &c->sh[symsh->sh_link];
    if (strsh->sh_type != SHT_STRTAB || strsh->sh_size == 0)
        return -1;
    const char *str = (const char *)(c->data + strsh->sh_offset);
    if (str[strsh->sh_size - 1] != '\0')
        return -1;
    *out_sym_base = c->data + symsh->sh_offset;
    *out_nsym     = (size_t)(symsh->sh_size / sizeof(Elf64_Sym));
    *out_str      = str;
    *out_strsz    = (size_t)strsh->sh_size;
    return 0;
}

static int create_named_map(struct elf_ctx *c, const char *want_sym,
                            uint32_t want_type, uint32_t want_ksz, uint32_t want_vsz,
                            int optional, uint32_t *out_actual_type)
{
    int mi = sec_index(c, "maps");
    if (mi < 0) {
        LOGE("no 'maps' section");
        return -1;
    }
    int symi = -1;
    for (int i = 0; i < c->eh.e_shnum; i++)
        if (c->sh[i].sh_type == SHT_SYMTAB) { symi = i; break; }

    const uint8_t *sym_base = NULL;
    const char *str = NULL;
    size_t nsym = 0, strsz = 0;
    if (get_sym_strtab(c, symi, &sym_base, &nsym, &str, &strsz) < 0) {
        LOGE("invalid symtab/strtab");
        return -1;
    }

    for (size_t k = 0; k < nsym; k++) {
        Elf64_Sym sym;
        memcpy(&sym, sym_base + k * sizeof(Elf64_Sym), sizeof(sym));
        if (sym.st_shndx != (uint16_t)mi || sym.st_name == 0 || sym.st_name >= strsz)
            continue;
        const char *name = str + sym.st_name;
        if (strcmp(name, want_sym) != 0)
            continue;
        if (!range_valid(sym.st_value, 5 * sizeof(uint32_t), (size_t)c->sh[mi].sh_size)) {
            LOGE("map def %s out of bounds", want_sym);
            return -1;
        }
        uint32_t d[5] = {0};
        memcpy(d, c->data + c->sh[mi].sh_offset + sym.st_value, sizeof(d));
        union bpf_attr_pad a;
        memset(&a, 0, sizeof(a));
        a.attr.map_type    = d[0];
        a.attr.key_size    = d[1];
        a.attr.value_size  = d[2];
        a.attr.max_entries = d[3];
        a.attr.map_flags   = d[4];
        if (a.attr.map_type != want_type ||
            a.attr.key_size != want_ksz || a.attr.value_size != want_vsz) {
            LOGE("unexpected map def %s: type=%u key=%u val=%u (want type=%u key=%u val=%u)",
                 want_sym, d[0], d[1], d[2], want_type, want_ksz, want_vsz);
            return -1;
        }
        int fd = sys_bpf(BPF_MAP_CREATE, &a);
        if (fd < 0 && want_type == BPF_MAP_TYPE_PERCPU_ARRAY &&
            (errno == EINVAL || errno == EPERM || errno == ENOTSUP)) {
            a.attr.map_type = BPF_MAP_TYPE_ARRAY;
            fd = sys_bpf(BPF_MAP_CREATE, &a);
        }
        if (fd < 0)
            LOGE("BPF_MAP_CREATE(%s): %s", want_sym, strerror(errno));
        else if (out_actual_type)
            *out_actual_type = a.attr.map_type;
        return fd;
    }
    if (!optional)
        LOGE("symbol %s not found in maps section", want_sym);
    return -2; /* -2 = symbol absent */
}

static int load_prog_sec(struct elf_ctx *c, const char *sec_name,
                         int ip_map_fd, int mac_map_fd, int stats_map_fd, int optional)
{
    int pi = sec_index(c, sec_name);
    if (pi < 0) {
        if (!optional)
            LOGE("no '%s' section", sec_name);
        return -1;
    }
    size_t insnsz = (size_t)c->sh[pi].sh_size;
    if (insnsz == 0 || insnsz % 8 != 0) {
        LOGE("bad %s section size %zu", sec_name, insnsz);
        return -1;
    }
    size_t ninsn = insnsz / 8;
    uint64_t *insns = malloc(insnsz);
    if (!insns)
        return -1;
    memcpy(insns, c->data + c->sh[pi].sh_offset, insnsz);

    for (int i = 0; i < c->eh.e_shnum; i++) {
        if (c->sh[i].sh_type != SHT_REL || c->sh[i].sh_info != (uint32_t)pi)
            continue;
        const uint8_t *sym_base = NULL;
        const char *str = NULL;
        size_t nsym = 0, strsz = 0;
        if (get_sym_strtab(c, (int)c->sh[i].sh_link, &sym_base, &nsym, &str, &strsz) < 0) {
            LOGE("bad reloc symtab for %s", sec_name);
            free(insns);
            return -1;
        }
        const uint8_t *rel_base = c->data + c->sh[i].sh_offset;
        size_t nrel = (size_t)(c->sh[i].sh_size / sizeof(Elf64_Rel));
        for (size_t k = 0; k < nrel; k++) {
            Elf64_Rel rel;
            memcpy(&rel, rel_base + k * sizeof(Elf64_Rel), sizeof(rel));
            uint32_t sym_idx = (uint32_t)ELF64_R_SYM(rel.r_info);
            uint32_t typ     = (uint32_t)ELF64_R_TYPE(rel.r_info);
            if (typ != R_BPF_64_64 || (rel.r_offset % 8ULL) != 0ULL ||
                rel.r_offset >= (uint64_t)insnsz ||
                ((uint64_t)insnsz - rel.r_offset) < 16ULL ||
                sym_idx >= nsym) {
                LOGE("unsupported or out-of-bounds relocation (type=%u sym=%u) in %s",
                     typ, sym_idx, sec_name);
                free(insns);
                return -1;
            }
            size_t insn_idx = (size_t)(rel.r_offset / 8ULL);
            Elf64_Sym sym;
            memcpy(&sym, sym_base + (size_t)sym_idx * sizeof(Elf64_Sym), sizeof(sym));
            if (sym.st_name >= strsz) {
                free(insns);
                return -1;
            }
            const char *sname = str + sym.st_name;
            int target_fd = -1;
            if (strcmp(sname, "ip_mark_map") == 0)
                target_fd = ip_map_fd;
            else if (strcmp(sname, "mac_mark_map") == 0)
                target_fd = mac_map_fd;
            else if (strcmp(sname, "dev_stats_map") == 0)
                target_fd = stats_map_fd;
            if (target_fd < 0) {
                LOGE("unresolved map symbol '%s' in %s", sname, sec_name);
                free(insns);
                return -1;
            }
            uint32_t w0[2], w1[2];
            memcpy(w0, &insns[insn_idx], sizeof(w0));
            memcpy(w1, &insns[insn_idx + 1], sizeof(w1));
            w0[0] = (w0[0] & 0xFFFF0F00u) | BPF_LD_DW_IMM | (BPF_PSEUDO_MAP_FD << 12);
            w0[1] = (uint32_t)target_fd;
            w1[1] = 0;
            memcpy(&insns[insn_idx], w0, sizeof(w0));
            memcpy(&insns[insn_idx + 1], w1, sizeof(w1));
        }
    }

    /* Two-phase BPF_PROG_LOAD: load silently first (log_level=0) so Linux 6.1 GKI
     * does not fail valid programs with -ENOSPC when verbose verifier logs exceed 64KB. */
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    a.attr.insns     = (uint64_t)(uintptr_t)insns;
    a.attr.insn_cnt  = (uint32_t)ninsn;
    a.attr.license   = (uint64_t)(uintptr_t)"GPL";
    a.attr.log_level = 0;
    a.attr.log_buf   = 0;
    a.attr.log_size  = 0;

    int fd = sys_bpf(BPF_PROG_LOAD, &a);
    if (fd < 0) {
        int load_errno = errno;
        const size_t log_cap = 512U * 1024U;
        char *logbuf = calloc(1, log_cap);
        if (logbuf) {
            memset(&a, 0, sizeof(a));
            a.attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
            a.attr.insns     = (uint64_t)(uintptr_t)insns;
            a.attr.insn_cnt  = (uint32_t)ninsn;
            a.attr.license   = (uint64_t)(uintptr_t)"GPL";
            a.attr.log_buf   = (uint64_t)(uintptr_t)logbuf;
            a.attr.log_size  = (uint32_t)log_cap;
            a.attr.log_level = 1;
            int retry_fd = sys_bpf(BPF_PROG_LOAD, &a);
            if (retry_fd >= 0) {
                free(logbuf);
                free(insns);
                return retry_fd;
            }
            logbuf[log_cap - 1] = '\0';
        }
        LOGE("BPF_PROG_LOAD(%s): %s", sec_name, strerror(load_errno));
        if (logbuf && logbuf[0])
            fprintf(stderr, "--- verifier log (%s) ---\n%s--------------------\n",
                    sec_name, logbuf);
        free(logbuf);
        errno = load_errno;
    }
    free(insns);
    return fd;
}

/* ── Pin / Map Helpers ───────────────────────────────────────────────── */

static int ensure_pin_dir(void)
{
    if (mkdir(PIN_DIR, 0755) == 0 || errno == EEXIST)
        return 0;
    LOGE("mkdir %s: %s", PIN_DIR, strerror(errno));
    return -1;
}

static int bpf_map_get_info_by_fd(int fd, struct bpf_map_info *info)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    memset(info, 0, sizeof(*info));
    a.attr.info.bpf_fd   = (uint32_t)fd;
    a.attr.info.info_len = (uint32_t)sizeof(*info);
    a.attr.info.info     = (uint64_t)(uintptr_t)info;
    return sys_bpf(HNC_BPF_OBJ_GET_INFO_BY_FD, &a);
}

static int get_or_pin_map(int new_fd, const char *pin_path,
                          uint32_t want_type, uint32_t want_ksz, uint32_t want_vsz,
                          int *was_existing)
{
    *was_existing = 0;
    if (new_fd < 0)
        return -1;
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)pin_path;
    int old = sys_bpf(BPF_OBJ_GET, &a);
    if (old >= 0) {
        struct bpf_map_info info;
        if (bpf_map_get_info_by_fd(old, &info) == 0 &&
            info.type == want_type &&
            info.key_size == want_ksz &&
            info.value_size == want_vsz) {
            close(new_fd);
            *was_existing = 1;
            return old;
        }
        LOGI("pinned map %s schema mismatch (type=%u key=%u val=%u, expected type=%u key=%u val=%u); recreating",
             pin_path, info.type, info.key_size, info.value_size,
             want_type, want_ksz, want_vsz);
        close(old);
        unlink(pin_path);
    }
    if (ensure_pin_dir() < 0) {
        close(new_fd);
        return -1;
    }
    unlink(pin_path);
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)pin_path;
    a.attr.bpf_fd   = (uint32_t)new_fd;
    if (sys_bpf(BPF_OBJ_PIN, &a) < 0) {
        LOGE("BPF_OBJ_PIN %s: %s", pin_path, strerror(errno));
        close(new_fd);
        return -1;
    }
    return new_fd;
}

static int open_pinned_path(const char *pin_path, int quiet)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)pin_path;
    int fd = sys_bpf(BPF_OBJ_GET, &a);
    if (fd < 0 && !quiet)
        LOGE("BPF_OBJ_GET %s: %s", pin_path, strerror(errno));
    return fd;
}

static int parse_mac_key(const char *s, struct mac_key *out)
{
    unsigned int b[6];
    char tail = 0;
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return -1;
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xffU)
            return -1;
        out->mac[i] = (uint8_t)b[i];
    }
    return 0;
}

/*
 * 32/64-bit safe mark parser & v5.40.0 orthogonal [23:16] bitfield normalizer:
 *   - Uses strtoull + 0xffffffffULL (zero tautological-compare warnings on 32-bit armv7a).
 *   - Raw slot IDs mid (1..99, up to 126)        -> 0x00800000U | (mid << 16)
 *   - Legacy marks (0x800000 + mid, 1..126)      -> 0x00800000U | (mid << 16)
 *   - Pre-encoded [23:16] (0x00810000..0x00fe0000, incl. 0x00810000..0x00e30000) -> preserved
 *   - Hard drop sentinel 0xffffffffU             -> preserved
 *   - Zero (0)                                   -> preserved only if allow_zero != 0
 */
static int parse_and_normalize_mark(const char *markstr, int allow_zero, uint32_t *out)
{
    if (!markstr || !out)
        return -1;
    while (isspace((unsigned char)*markstr))
        markstr++;
    if (*markstr == '\0' || *markstr == '-' || *markstr == '+')
        return -1;

    char *endp = NULL;
    errno = 0;
    unsigned long long raw_ull = strtoull(markstr, &endp, 0);
    if (errno != 0 || endp == markstr || *endp != '\0' || raw_ull > 0xffffffffULL)
        return -1;

    uint32_t raw = (uint32_t)raw_ull;
    if (raw == 0U) {
        if (!allow_zero)
            return -1;
        *out = 0U;
        return 0;
    }
    if (raw == HNC_MARK_DROP) {
        *out = HNC_MARK_DROP;
        return 0;
    }
    if (raw >= 1U && raw <= 126U) {
        *out = HNC_MARK_DEV_VALID | (raw << 16);
        return 0;
    }
    if (raw >= (HNC_MARK_DEV_VALID + 1U) && raw <= (HNC_MARK_DEV_VALID + 126U)) {
        uint32_t mid = raw - HNC_MARK_DEV_VALID;
        *out = HNC_MARK_DEV_VALID | (mid << 16);
        return 0;
    }
    if ((raw & HNC_MARK_DEV_VALID) != 0U &&
        (raw & 0x007f0000U) != 0U &&
        (raw & ~HNC_MARK_DEV_MASK) == 0U) {
        *out = raw;
        return 0;
    }
    /* Composite mark carrying valid [23:16] device bits: strip non-[23:16] bits */
    if ((raw & HNC_MARK_DEV_VALID) != 0U && (raw & 0x007f0000U) != 0U) {
        *out = raw & HNC_MARK_DEV_MASK;
        return 0;
    }
    return -1;
}

static int bpf_map_elem_update(int map_fd, const void *key, uint32_t mark)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.map_fd = (uint32_t)map_fd;
    a.attr.key    = (uint64_t)(uintptr_t)key;
    a.attr.value  = (uint64_t)(uintptr_t)&mark;
    a.attr.flags  = 0;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &a) < 0 ? -errno : 0;
}

static int bpf_map_get_next_any(int fd, const void *key, void *next_key)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.map_fd   = (uint32_t)fd;
    a.attr.key      = key ? (uint64_t)(uintptr_t)key : 0ULL;
    a.attr.next_key = (uint64_t)(uintptr_t)next_key;
    return sys_bpf(BPF_MAP_GET_NEXT_KEY, &a) < 0 ? -errno : 0;
}

static int bpf_map_delete_any(int fd, const void *key)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.map_fd = (uint32_t)fd;
    a.attr.key    = (uint64_t)(uintptr_t)key;
    return sys_bpf(BPF_MAP_DELETE_ELEM, &a) < 0 ? -errno : 0;
}

static int bpf_map_lookup_any(int fd, const void *key, void *val)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.map_fd = (uint32_t)fd;
    a.attr.key    = (uint64_t)(uintptr_t)key;
    a.attr.value  = (uint64_t)(uintptr_t)val;
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &a) < 0 ? -errno : 0;
}

#define HNC_CHECK_MAX_KEY_SZ 256U
#define HNC_CHECK_MAX_ITERS  65536U

/* Traverse a pinned kernel BPF map via BPF_MAP_GET_NEXT_KEY (or non-zero slot
 * scan for small ARRAY policy maps) to obtain real live entry counts.
 * Returns >= 0 entry count on success, or -1 if the map cannot be read. */
static int count_pinned_map_entries(const char *pin_path, uint32_t fallback_ksz,
                                    int *opened_out)
{
    if (opened_out)
        *opened_out = 0;
    int fd = open_pinned_path(pin_path, 1);
    if (fd < 0)
        return -1;
    if (opened_out)
        *opened_out = 1;

    struct bpf_map_info info;
    uint32_t ksz = fallback_ksz;
    uint32_t max_iters = 4096U;
    if (bpf_map_get_info_by_fd(fd, &info) == 0) {
        if (info.type == BPF_MAP_TYPE_ARRAY) {
            if (info.key_size != 4U || info.value_size == 0U ||
                info.value_size > 64U || info.max_entries > 4096U) {
                close(fd);
                return -1;
            }
            uint8_t val_buf[64];
            int nz = 0;
            for (uint32_t idx = 0U; idx < info.max_entries; idx++) {
                memset(val_buf, 0, sizeof(val_buf));
                if (bpf_map_lookup_any(fd, &idx, val_buf) != 0)
                    continue;
                for (uint32_t b = 0U; b < info.value_size; b++) {
                    if (val_buf[b] != 0U) {
                        nz++;
                        break;
                    }
                }
            }
            close(fd);
            return nz;
        }
        if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
            close(fd);
            return -1;
        }
        if (info.key_size == 0U || info.key_size > HNC_CHECK_MAX_KEY_SZ) {
            close(fd);
            return -1;
        }
        ksz = info.key_size;
        if (info.max_entries > 0U && info.max_entries <= 32768U)
            max_iters = info.max_entries * 2U + 64U;
        else
            max_iters = HNC_CHECK_MAX_ITERS;
    } else if (ksz == 0U || ksz > HNC_CHECK_MAX_KEY_SZ) {
        close(fd);
        return -1;
    }

    uint8_t cur_key[HNC_CHECK_MAX_KEY_SZ];
    uint8_t next_key[HNC_CHECK_MAX_KEY_SZ];
    memset(cur_key, 0, sizeof(cur_key));
    memset(next_key, 0, sizeof(next_key));

    int rc = bpf_map_get_next_any(fd, NULL, cur_key);
    if (rc == -ENOENT) {
        close(fd);
        return 0;
    }
    if (rc < 0) {
        close(fd);
        return -1;
    }

    int count = 1;
    for (uint32_t iter = 1U; iter < max_iters; iter++) {
        rc = bpf_map_get_next_any(fd, cur_key, next_key);
        if (rc == -ENOENT)
            break;
        if (rc < 0) {
            close(fd);
            return -1;
        }
        count++;
        memcpy(cur_key, next_key, ksz);
    }
    close(fd);
    return count;
}

static int count_first_readable_map(const char *const *paths, size_t npaths,
                                    uint32_t fallback_ksz, int *any_present_out)
{
    for (size_t i = 0U; i < npaths; i++) {
        struct stat st;
        if (any_present_out && stat(paths[i], &st) == 0)
            *any_present_out = 1;
        int opened = 0;
        int cnt = count_pinned_map_entries(paths[i], fallback_ksz, &opened);
        if (opened && any_present_out)
            *any_present_out = 1;
        if (cnt >= 0)
            return cnt;
    }
    return -1;
}

static void probe_tether_limit_state(int *present_out, int *readable_out,
                                     int *entries_out, int *nonzero_out)
{
    static const char *const kLimitPaths[] = {
        "/sys/fs/bpf/tether_limit_map",
        "/sys/fs/bpf/tethering/map_offload_tether_limit_map",
    };

    *readable_out = 0;
    *entries_out  = 0;
    *nonzero_out  = 0;

    for (size_t i = 0U; i < sizeof(kLimitPaths) / sizeof(kLimitPaths[0]); i++) {
        struct stat st;
        if (stat(kLimitPaths[i], &st) == 0)
            *present_out = 1;
        int fd = open_pinned_path(kLimitPaths[i], 1);
        if (fd < 0)
            continue;
        *present_out = 1;

        struct bpf_map_info info;
        if (bpf_map_get_info_by_fd(fd, &info) == 0) {
            if (info.key_size != sizeof(uint32_t) || info.value_size != sizeof(uint64_t)) {
                close(fd);
                continue;
            }
        }

        uint32_t cur_k = 0U, next_k = 0U;
        int rc = bpf_map_get_next_any(fd, NULL, &cur_k);
        if (rc == -ENOENT) {
            *readable_out = 1;
            close(fd);
            return;
        }
        if (rc < 0) {
            close(fd);
            continue;
        }

        int entries = 0, nonzero = 0;
        for (int guard = 0; guard < 256; guard++) {
            int nrc = bpf_map_get_next_any(fd, &cur_k, &next_k);
            uint64_t quota = 0ULL;
            entries++;
            if (bpf_map_lookup_any(fd, &cur_k, &quota) != 0 || quota != 0ULL)
                nonzero++;
            if (nrc == -ENOENT)
                break;
            if (nrc < 0) {
                close(fd);
                return;
            }
            cur_k = next_k;
        }
        *readable_out = 1;
        *entries_out  = entries;
        *nonzero_out  = nonzero;
        close(fd);
        return;
    }
}

static void json_escape_str(const char *src, char *dst, size_t cap)
{
    size_t j = 0;
    if (cap == 0)
        return;
    for (size_t i = 0; src[i] && j + 1 < cap; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == '"' || ch == '\\') {
            if (j + 2 >= cap) break;
            dst[j++] = '\\';
            dst[j++] = (char)ch;
        } else if (ch >= 0x20 && ch < 0x7f) {
            dst[j++] = (char)ch;
        }
    }
    dst[j] = '\0';
}

/* ── Subcommands ─────────────────────────────────────────────────────── */

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

static int verify_ether_iface(const char *iface)
{
    if (!iface || iface[0] == '\0' || iface[0] == '.' ||
        strchr(iface, '/') != NULL || strstr(iface, "..") != NULL) {
        LOGE("invalid iface name: %s", iface ? iface : "(null)");
        return -1;
    }

    char path[128];
    int n = snprintf(path, sizeof(path), "/sys/class/net/%s/type", iface);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        LOGE("iface path too long: %s", iface);
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            int sfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (sfd >= 0) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%.*s", IFNAMSIZ - 1, iface);
                int irc = ioctl(sfd, SIOCGIFHWADDR, &ifr);
                close(sfd);
                if (irc == 0) {
                    unsigned int hwtype = (unsigned int)(unsigned short)ifr.ifr_hwaddr.sa_family;
                    if (hwtype != (unsigned int)ARPHRD_ETHER) {
                        LOGE("iface %s rejected: link type=%u is not ARPHRD_ETHER (%d)",
                             iface, hwtype, ARPHRD_ETHER);
                        return -1;
                    }
                    return 0;
                }
            }
        }
        LOGE("open %s: %s", path, strerror(errno));
        return -1;
    }

    char buf[32];
    ssize_t r = read(fd, buf, sizeof(buf) - 1U);
    close(fd);
    if (r <= 0) {
        LOGE("read %s failed", path);
        return -1;
    }
    buf[r] = '\0';

    char *endp = NULL;
    errno = 0;
    long arphrd = strtol(buf, &endp, 0);
    if (errno != 0 || endp == buf) {
        LOGE("parse %s failed", path);
        return -1;
    }
    while (*endp && isspace((unsigned char)*endp))
        endp++;
    if (*endp != '\0' || arphrd != (long)ARPHRD_ETHER) {
        LOGE("iface %s rejected: link type=%ld is not ARPHRD_ETHER (%d)",
             iface, arphrd, ARPHRD_ETHER);
        return -1;
    }
    return 0;
}

static int egress_state_path(const char *iface, char *out, size_t cap)
{
    if (!iface || iface[0] == '\0' || iface[0] == '.' ||
        strchr(iface, '/') != NULL || strstr(iface, "..") != NULL)
        return -1;
    for (const char *p = iface; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch < 0x20U || isspace(ch))
            return -1;
    }
    const char *hnc_dir = getenv("HNC_DIR");
    if (!hnc_dir || hnc_dir[0] == '\0' || strstr(hnc_dir, "..") != NULL)
        hnc_dir = "/data/local/hnc";

    char run_dir[512];
    int rn = snprintf(run_dir, sizeof(run_dir), "%s/run", hnc_dir);
    if (rn <= 0 || (size_t)rn >= sizeof(run_dir))
        return -1;
    (void)mkdir(run_dir, 0755);

    int n = snprintf(out, cap, "%s/clsact_egress.%s", run_dir, iface);
    if (n <= 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void write_egress_state(const char *iface, int expected, int degraded, int err_code)
{
    char path[576];
    char tmp[600];
    if (egress_state_path(iface, path, sizeof(path)) < 0)
        return;
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        return;
    FILE *f = fopen(tmp, "we");
    if (!f)
        return;
    fprintf(f, "expected=%d\ndegraded=%d\nerr=%d\n", expected, degraded, err_code);
    if (fclose(f) == 0) {
        if (rename(tmp, path) != 0)
            unlink(tmp);
    } else {
        unlink(tmp);
    }
}

static void read_egress_state(const char *iface, int *expected_out, int *degraded_out)
{
    *expected_out = 0;
    *degraded_out = 0;
    char path[576];
    if (egress_state_path(iface, path, sizeof(path)) < 0)
        return;
    FILE *f = fopen(path, "re");
    if (!f)
        return;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "expected=1", 10) == 0)
            *expected_out = 1;
        else if (strncmp(line, "degraded=1", 10) == 0)
            *degraded_out = 1;
    }
    fclose(f);
}

static void remove_egress_state(const char *iface)
{
    char path[576];
    if (egress_state_path(iface, path, sizeof(path)) == 0)
        unlink(path);
}

static int cmd_install(const char *iface, const char *obj)
{
    unsigned ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        LOGE("iface %s not found", iface);
        return RC_IFACE;
    }
    if (verify_ether_iface(iface) != 0)
        return RC_IFACE;

    struct elf_ctx c;
    if (elf_load(&c, obj) < 0)
        return RC_BPF;

    uint32_t ip_type = BPF_MAP_TYPE_HASH;
    int raw_ip_fd = create_named_map(&c, "ip_mark_map", BPF_MAP_TYPE_HASH, 4U, 4U, 0, &ip_type);
    if (raw_ip_fd < 0) { elf_free(&c); return RC_BPF; }
    int ip_existed = 0;
    int ip_map_fd = get_or_pin_map(raw_ip_fd, MAP_PIN,
                                   ip_type, 4U, 4U, &ip_existed);
    if (ip_map_fd < 0) { elf_free(&c); return RC_BPF; }

    uint32_t mac_type = BPF_MAP_TYPE_HASH;
    int raw_mac_fd = create_named_map(&c, "mac_mark_map", BPF_MAP_TYPE_HASH,
                                      (uint32_t)sizeof(struct mac_key), 4U, 1, &mac_type);
    int mac_existed = 0;
    int mac_map_fd = -1;
    if (raw_mac_fd == -1) {
        /* Map symbol existed in ELF but BPF_MAP_CREATE failed */
        if (!ip_existed) unlink(MAP_PIN);
        close(ip_map_fd);
        elf_free(&c);
        return RC_BPF;
    }
    if (raw_mac_fd >= 0) {
        mac_map_fd = get_or_pin_map(raw_mac_fd, MAC_MAP_PIN,
                                    mac_type, (uint32_t)sizeof(struct mac_key), 4U,
                                    &mac_existed);
        if (mac_map_fd < 0) {
            if (!ip_existed) unlink(MAP_PIN);
            close(ip_map_fd);
            elf_free(&c);
            return RC_BPF;
        }
    }

    uint32_t stats_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    int raw_stats_fd = create_named_map(&c, "dev_stats_map", BPF_MAP_TYPE_PERCPU_ARRAY,
                                        4U, 24U, 1, &stats_type);
    int stats_existed = 0;
    int stats_map_fd = -1;
    if (raw_stats_fd == -1) {
        if (!ip_existed) unlink(MAP_PIN);
        if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
        close(ip_map_fd);
        if (mac_map_fd >= 0) close(mac_map_fd);
        elf_free(&c);
        return RC_BPF;
    }
    if (raw_stats_fd >= 0) {
        stats_map_fd = get_or_pin_map(raw_stats_fd, STATS_MAP_PIN,
                                      stats_type, 4U, 24U, &stats_existed);
        if (stats_map_fd < 0) {
            if (!ip_existed) unlink(MAP_PIN);
            if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
            close(ip_map_fd);
            if (mac_map_fd >= 0) close(mac_map_fd);
            elf_free(&c);
            return RC_BPF;
        }
    }

    int has_eg_sec = (mac_map_fd >= 0 && sec_index(&c, "tc_egress") >= 0) ? 1 : 0;
    int prog_in = load_prog_sec(&c, "tc", ip_map_fd, mac_map_fd, stats_map_fd, 0);
    int prog_eg = has_eg_sec ? load_prog_sec(&c, "tc_egress", ip_map_fd, mac_map_fd, stats_map_fd, 1) : -1;
    int eg_load_err = (has_eg_sec && prog_eg < 0) ? errno : 0;
    elf_free(&c);

    if (prog_in < 0) {
        if (prog_eg >= 0) close(prog_eg);
        if (!ip_existed) unlink(MAP_PIN);
        if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
        if (stats_map_fd >= 0 && !stats_existed) unlink(STATS_MAP_PIN);
        close(ip_map_fd);
        if (mac_map_fd >= 0) close(mac_map_fd);
        if (stats_map_fd >= 0) close(stats_map_fd);
        return RC_BPF;
    }

    int nlfd = rtnl_open();
    if (nlfd < 0) {
        close(prog_in);
        if (prog_eg >= 0) close(prog_eg);
        if (!ip_existed) unlink(MAP_PIN);
        if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
        if (stats_map_fd >= 0 && !stats_existed) unlink(STATS_MAP_PIN);
        close(ip_map_fd);
        if (mac_map_fd >= 0) close(mac_map_fd);
        if (stats_map_fd >= 0) close(stats_map_fd);
        return RC_NETLINK;
    }
    int rc = clsact_qdisc_ensure(nlfd, ifindex);
    if (rc == 0) {
        int in_rc = bpf_filter_attach_dir(nlfd, ifindex, TC_H_INGRESS_PARENT, prog_in, HNC_PROG_NAME);
        if (in_rc == 0) {
            if (prog_eg >= 0) {
                int eg_rc = bpf_filter_attach_dir(nlfd, ifindex, TC_H_EGRESS_PARENT, prog_eg, HNC_EGRESS_NAME);
                if (eg_rc == 0) {
                    write_egress_state(iface, 1, 0, 0);
                } else {
                    LOGI("WARN: tc_egress attach degraded on %s (%s); ingress active, downlink clsact accounting unavailable",
                         iface, strerror(-eg_rc));
                    write_egress_state(iface, 0, 1, -eg_rc);
                }
            } else if (has_eg_sec) {
                LOGI("WARN: tc_egress BPF load degraded on %s (%s); ingress active, downlink clsact accounting unavailable",
                     iface, strerror(eg_load_err ? eg_load_err : EINVAL));
                write_egress_state(iface, 0, 1, eg_load_err ? eg_load_err : EINVAL);
            } else {
                remove_egress_state(iface);
            }
        }
        rc = in_rc;
    }

    close(nlfd);
    close(prog_in);
    if (prog_eg >= 0) close(prog_eg);
    close(ip_map_fd);
    if (mac_map_fd >= 0) close(mac_map_fd);
    if (stats_map_fd >= 0) close(stats_map_fd);
    return rc == 0 ? RC_OK : RC_NETLINK;
}

static int cmd_check(const char *iface)
{
    static const char *const kAppPolicyPaths[] = {
        "/sys/fs/bpf/hnc_app_policy",
        PIN_DIR "/hnc_app_policy",
        PIN_DIR "/app_policy_map",
    };
    static const char *const kDown6Paths[] = {
        "/sys/fs/bpf/tether_downstream6_map",
        "/sys/fs/bpf/tethering/map_offload_tether_downstream6_map",
        "/sys/fs/bpf/map_offload_tether_downstream6_map",
    };
    static const char *const kDown4Paths[] = {
        "/sys/fs/bpf/tether_downstream4_map",
        "/sys/fs/bpf/tethering/map_offload_tether_downstream4_map",
    };
    static const char *const kUp6Paths[] = {
        "/sys/fs/bpf/tether_upstream6_map",
        "/sys/fs/bpf/tethering/map_offload_tether_upstream6_map",
    };
    static const char *const kUp4Paths[] = {
        "/sys/fs/bpf/tether_upstream4_map",
        "/sys/fs/bpf/tethering/map_offload_tether_upstream4_map",
    };

    unsigned ifindex = if_nametoindex(iface);
    int nlfd = rtnl_open();
    int qd = 0, fl = 0, eg = 0;
    if (nlfd >= 0 && ifindex != 0) {
        qd = clsact_qdisc_exists(nlfd, ifindex);
        fl = qd ? bpf_filter_exists_dir(nlfd, ifindex, TC_H_INGRESS_PARENT) : 0;
        eg = qd ? bpf_filter_exists_dir(nlfd, ifindex, TC_H_EGRESS_PARENT) : 0;
    }
    if (nlfd >= 0)
        close(nlfd);

    int mp = 0, mmp = 0, sp = 0, app_present = 0;
    int ip_cnt  = count_pinned_map_entries(MAP_PIN, 4U, &mp);
    int mac_cnt = count_pinned_map_entries(MAC_MAP_PIN, (uint32_t)sizeof(struct mac_key), &mmp);
    {
        int sfd = open_pinned_path(STATS_MAP_PIN, 1);
        if (sfd >= 0) {
            sp = 1;
            close(sfd);
        }
    }
    int app_cnt = count_first_readable_map(kAppPolicyPaths,
                                           sizeof(kAppPolicyPaths) / sizeof(kAppPolicyPaths[0]),
                                           4U, &app_present);
    int bpf_readable = (ip_cnt >= 0 || mac_cnt >= 0 || app_cnt >= 0) ? 1 : 0;

    int eg_expected = 0, eg_degraded_saved = 0;
    read_egress_state(iface, &eg_expected, &eg_degraded_saved);
    int is_ok = (qd && fl && mp && (!eg_expected || eg)) ? 1 : 0;
    int eg_degraded = (eg_degraded_saved || ((mmp || sp) && fl && !eg)) ? 1 : 0;
    int downlink_stats_ok = (qd && eg && sp) ? 1 : 0;

    int tether_present = 0, tether_lim_readable = 0;
    int tether_lim_entries = 0, tether_lim_nonzero = 0;
    probe_tether_limit_state(&tether_present, &tether_lim_readable,
                             &tether_lim_entries, &tether_lim_nonzero);

    int down6_cnt = count_first_readable_map(kDown6Paths, sizeof(kDown6Paths) / sizeof(kDown6Paths[0]),
                                             24U, &tether_present);
    int down4_cnt = count_first_readable_map(kDown4Paths, sizeof(kDown4Paths) / sizeof(kDown4Paths[0]),
                                             16U, &tether_present);
    int up6_cnt   = count_first_readable_map(kUp6Paths, sizeof(kUp6Paths) / sizeof(kUp6Paths[0]),
                                             24U, &tether_present);
    int up4_cnt   = count_first_readable_map(kUp4Paths, sizeof(kUp4Paths) / sizeof(kUp4Paths[0]),
                                             16U, &tether_present);

    int flow_total = 0;
    if (down6_cnt > 0) flow_total += down6_cnt;
    if (down4_cnt > 0) flow_total += down4_cnt;
    if (up6_cnt > 0)   flow_total += up6_cnt;
    if (up4_cnt > 0)   flow_total += up4_cnt;
    int tether_active = (flow_total > 0 && (!tether_lim_readable || tether_lim_nonzero > 0)) ? 1 : 0;

    char safe_iface[IFNAMSIZ * 2];
    json_escape_str(iface, safe_iface, sizeof(safe_iface));
    printf("{\"iface\":\"%s\",\"ok\":%s,\"qdisc\":%s,\"bpf_filter\":%s,\"map\":%s,\"mac_map\":%s,\"stats_map\":%s,\"egress_filter\":%s,\"egress_degraded\":%s,\"downlink_stats_ok\":%s,\"bpf_map_readable\":%s",
           safe_iface,
           is_ok ? "true" : "false",
           qd ? "true" : "false",
           fl ? "true" : "false",
           mp ? "true" : "false",
           mmp ? "true" : "false",
           sp ? "true" : "false",
           eg ? "true" : "false",
           eg_degraded ? "true" : "false",
           downlink_stats_ok ? "true" : "false",
           bpf_readable ? "true" : "false");
    if (ip_cnt >= 0)
        printf(",\"ip_entries\":%d", ip_cnt);
    if (mac_cnt >= 0)
        printf(",\"mac_entries\":%d", mac_cnt);
    printf(",\"app_policy_map\":%s,\"app_policy_entries\":%d,\"tether_bpf_present\":%s",
           app_present ? "true" : "false",
           app_cnt >= 0 ? app_cnt : 0,
           tether_present ? "true" : "false");
    if (tether_lim_readable) {
        printf(",\"tether_limit_zeroed\":%s,\"tether_limit_entries\":%d,\"tether_limit_nonzero\":%d",
               (tether_lim_nonzero == 0) ? "true" : "false",
               tether_lim_entries,
               tether_lim_nonzero);
    }
    printf(",\"tether_downstream6_entries\":%d,\"tether_flow_entries\":%d,\"tether_offload_active\":%s}\n",
           down6_cnt >= 0 ? down6_cnt : 0,
           flow_total,
           tether_active ? "true" : "false");
    return RC_OK;
}

static int cmd_update(const char *target, const char *markstr)
{
    uint32_t mark = 0;
    if (parse_and_normalize_mark(markstr, 1, &mark) < 0) {
        LOGE("invalid mark: %s", markstr);
        return RC_MAP;
    }
    struct mac_key mk;
    if (parse_mac_key(target, &mk) == 0) {
        int mfd = open_pinned_path(MAC_MAP_PIN, 0);
        if (mfd < 0)
            return RC_MAP;
        int rc = (mark == 0) ? bpf_map_delete_any(mfd, &mk) : bpf_map_elem_update(mfd, &mk, mark);
        close(mfd);
        return (rc == 0 || rc == -ENOENT) ? RC_OK : RC_MAP;
    }
    uint32_t ip_key;
    if (inet_pton(AF_INET, target, &ip_key) != 1) {
        LOGE("invalid ip or mac: %s", target);
        return RC_MAP;
    }
    int fd = open_pinned_path(MAP_PIN, 0);
    if (fd < 0)
        return RC_MAP;
    int rc = (mark == 0) ? bpf_map_delete_any(fd, &ip_key) : bpf_map_elem_update(fd, &ip_key, mark);
    close(fd);
    return (rc == 0 || rc == -ENOENT) ? RC_OK : RC_MAP;
}

static int cmd_sync(void)
{
    int ip_fd  = open_pinned_path(MAP_PIN, 0);
    if (ip_fd < 0)
        return RC_MAP;
    int mac_fd = open_pinned_path(MAC_MAP_PIN, 1);

    uint32_t active_ips[256];
    uint32_t active_ip_marks[256];
    size_t active_ip_cnt = 0;

    struct mac_key active_macs[256];
    uint32_t active_mac_marks[256];
    size_t active_mac_cnt = 0;

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        char keystr[64], markstr[64];
        if (sscanf(line, "%63s %63s", keystr, markstr) != 2 || keystr[0] == '#')
            continue;
        uint32_t mark = 0;
        if (parse_and_normalize_mark(markstr, 0, &mark) < 0)
            continue;

        struct mac_key mk;
        if (parse_mac_key(keystr, &mk) == 0) {
            int dup = 0;
            for (size_t i = 0; i < active_mac_cnt; i++) {
                if (memcmp(&active_macs[i], &mk, sizeof(mk)) == 0) {
                    active_mac_marks[i] = mark;
                    dup = 1;
                    break;
                }
            }
            if (!dup && active_mac_cnt < 256) {
                active_macs[active_mac_cnt] = mk;
                active_mac_marks[active_mac_cnt] = mark;
                active_mac_cnt++;
            }
            continue;
        }
        struct in_addr addr;
        if (inet_pton(AF_INET, keystr, &addr) == 1) {
            int dup = 0;
            for (size_t i = 0; i < active_ip_cnt; i++) {
                if (active_ips[i] == addr.s_addr) {
                    active_ip_marks[i] = mark;
                    dup = 1;
                    break;
                }
            }
            if (!dup && active_ip_cnt < 256) {
                active_ips[active_ip_cnt] = addr.s_addr;
                active_ip_marks[active_ip_cnt] = mark;
                active_ip_cnt++;
            }
        }
    }

    /* Prune stale entries BEFORE inserting new entries so full 256-entry maps
     * never reject new clients with -E2BIG. */
    int rem_ip = 0, rem_mac = 0;
    uint32_t cur_ip = 0, next_ip = 0;
    int irc = bpf_map_get_next_any(ip_fd, NULL, &cur_ip);
    for (int guard = 0; irc == 0 && guard < 1024; guard++) {
        int nrc = bpf_map_get_next_any(ip_fd, &cur_ip, &next_ip);
        int keep = 0;
        for (size_t i = 0; i < active_ip_cnt; i++) {
            if (active_ips[i] == cur_ip) { keep = 1; break; }
        }
        if (!keep && bpf_map_delete_any(ip_fd, &cur_ip) == 0)
            rem_ip++;
        cur_ip = next_ip;
        irc = nrc;
    }

    if (mac_fd >= 0) {
        struct mac_key cur_m, next_m;
        memset(&cur_m, 0, sizeof(cur_m));
        memset(&next_m, 0, sizeof(next_m));
        int mrc = bpf_map_get_next_any(mac_fd, NULL, &cur_m);
        for (int guard = 0; mrc == 0 && guard < 1024; guard++) {
            int nmrc = bpf_map_get_next_any(mac_fd, &cur_m, &next_m);
            int keep = 0;
            for (size_t i = 0; i < active_mac_cnt; i++) {
                if (memcmp(&active_macs[i], &cur_m, sizeof(struct mac_key)) == 0) {
                    keep = 1;
                    break;
                }
            }
            if (!keep && bpf_map_delete_any(mac_fd, &cur_m) == 0)
                rem_mac++;
            cur_m = next_m;
            mrc = nmrc;
        }
    }

    int n_ip = 0, n_mac = 0;
    for (size_t i = 0; i < active_ip_cnt; i++) {
        if (bpf_map_elem_update(ip_fd, &active_ips[i], active_ip_marks[i]) == 0)
            n_ip++;
    }
    if (mac_fd >= 0) {
        for (size_t i = 0; i < active_mac_cnt; i++) {
            if (bpf_map_elem_update(mac_fd, &active_macs[i], active_mac_marks[i]) == 0)
                n_mac++;
        }
        close(mac_fd);
    }

    close(ip_fd);
    LOGI("sync: updated ip=%d mac=%d, removed stale ip=%d mac=%d",
         n_ip, n_mac, rem_ip, rem_mac);
    return RC_OK;
}

static void detach_hnc_filters_on_ifindex(int nlfd, unsigned ifindex)
{
    if (ifindex == 0U || !clsact_qdisc_exists(nlfd, ifindex))
        return;
    if (bpf_filter_exists_dir(nlfd, ifindex, TC_H_INGRESS_PARENT))
        (void)bpf_filter_detach_dir(nlfd, ifindex, TC_H_INGRESS_PARENT);
    if (bpf_filter_exists_dir(nlfd, ifindex, TC_H_EGRESS_PARENT))
        (void)bpf_filter_detach_dir(nlfd, ifindex, TC_H_EGRESS_PARENT);
}

static int any_other_iface_has_hnc_clsact(int nlfd, unsigned skip_ifindex,
                                          const char *skip_iface,
                                          char *active_out, size_t active_cap)
{
    if (active_out && active_cap > 0U)
        active_out[0] = '\0';

    const char *sys_net = getenv("HNC_SYS_NET");
    if (!sys_net || sys_net[0] == '\0')
        sys_net = "/sys/class/net";

    DIR *dir = opendir(sys_net);
    if (!dir)
        return -1;

    struct dirent *de = NULL;
    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        if (name[0] == '\0' || name[0] == '.')
            continue;
        if (strcmp(name, "lo") == 0)
            continue;
        if (skip_iface && skip_iface[0] != '\0' && strcmp(name, skip_iface) == 0)
            continue;
        unsigned idx = if_nametoindex(name);
        if (idx == 0U || (skip_ifindex != 0U && idx == skip_ifindex))
            continue;
        if (!clsact_qdisc_exists(nlfd, idx))
            continue;
        if (bpf_filter_exists_dir(nlfd, idx, TC_H_INGRESS_PARENT) ||
            bpf_filter_exists_dir(nlfd, idx, TC_H_EGRESS_PARENT)) {
            if (active_out && active_cap > 0U)
                snprintf(active_out, active_cap, "%.*s", (int)(active_cap - 1U), name);
            closedir(dir);
            return 1;
        }
    }
    closedir(dir);
    return 0;
}

static void detach_all_ifaces_hnc_clsact(int nlfd)
{
    const char *sys_net = getenv("HNC_SYS_NET");
    if (!sys_net || sys_net[0] == '\0')
        sys_net = "/sys/class/net";

    DIR *dir = opendir(sys_net);
    if (!dir)
        return;

    struct dirent *de = NULL;
    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        if (name[0] == '\0' || name[0] == '.' || strcmp(name, "lo") == 0)
            continue;
        unsigned idx = if_nametoindex(name);
        if (idx != 0U)
            detach_hnc_filters_on_ifindex(nlfd, idx);
        remove_egress_state(name);
    }
    closedir(dir);
}

static int cmd_uninstall(const char *iface, int force_all)
{
    if (iface && strcmp(iface, "--all") == 0) {
        force_all = 1;
        iface = NULL;
    }

    int nlfd = rtnl_open();
    if (force_all) {
        int rc = RC_OK;
        if (nlfd >= 0) {
            if (iface && iface[0] != '\0') {
                unsigned ifindex = if_nametoindex(iface);
                if (ifindex != 0U)
                    detach_hnc_filters_on_ifindex(nlfd, ifindex);
                remove_egress_state(iface);
            } else {
                detach_all_ifaces_hnc_clsact(nlfd);
            }
            close(nlfd);
        } else {
            rc = RC_NETLINK;
        }
        unlink(MAP_PIN);
        unlink(MAC_MAP_PIN);
        unlink(STATS_MAP_PIN);
        return rc;
    }

    if (!iface || iface[0] == '\0')
        return RC_USAGE;

    if (nlfd < 0)
        return RC_NETLINK;

    unsigned ifindex = if_nametoindex(iface);
    if (ifindex != 0U)
        detach_hnc_filters_on_ifindex(nlfd, ifindex);
    remove_egress_state(iface);

    char active_other[IFNAMSIZ];
    int others = any_other_iface_has_hnc_clsact(nlfd, ifindex, iface,
                                                active_other, sizeof(active_other));
    close(nlfd);

    if (others == 0) {
        unlink(MAP_PIN);
        unlink(MAC_MAP_PIN);
        unlink(STATS_MAP_PIN);
    } else if (others > 0) {
        LOGI("uninstall %s: keeping global BPF pins (still active on %s)",
             iface, active_other);
    } else {
        LOGI("uninstall %s: keeping global BPF pins (unable to scan /sys/class/net)",
             iface);
    }
    return RC_OK;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage:\n"
        "  %s install   <iface> [obj_path]\n"
        "  %s repair    <iface> [obj_path]\n"
        "  %s check     <iface>\n"
        "  %s update    <ip|mac> <mark>\n"
        "  %s sync                     (reads '<ip|mac> <mark>' lines from stdin)\n"
        "  %s uninstall <iface|--all> [--all]\n"
        "  %s --version\n",
        prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return RC_USAGE; }
    const char *cmd = argv[1];
    if (strcmp(cmd, "--version") == 0) {
        printf("hnc_clsact_ctl %s\n", HNC_VERSION);
        return RC_OK;
    }
    if (strcmp(cmd, "install") == 0 || strcmp(cmd, "repair") == 0) {
        if (argc < 3) { usage(argv[0]); return RC_USAGE; }
        const char *obj = NULL;
        if (argc >= 4) {
            obj = argv[3];
        } else {
            const char *env_obj = getenv("HNC_CLSACT_OBJ");
            if (env_obj && env_obj[0] == '/' && strstr(env_obj, "..") == NULL)
                obj = env_obj;
            else
                obj = OBJ_PATH_DEFAULT;
        }
        return cmd_install(argv[2], obj);
    }
    if (strcmp(cmd, "check") == 0) {
        if (argc < 3) { usage(argv[0]); return RC_USAGE; }
        return cmd_check(argv[2]);
    }
    if (strcmp(cmd, "update") == 0) {
        if (argc < 4) { usage(argv[0]); return RC_USAGE; }
        return cmd_update(argv[2], argv[3]);
    }
    if (strcmp(cmd, "sync") == 0)
        return cmd_sync();
    if (strcmp(cmd, "uninstall") == 0) {
        if (argc < 3) { usage(argv[0]); return RC_USAGE; }
        int force_all = (argc >= 4 && strcmp(argv[3], "--all") == 0) ? 1 : 0;
        return cmd_uninstall(argv[2], force_all);
    }
    usage(argv[0]);
    return RC_USAGE;
}
