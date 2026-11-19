/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hnc_clsact_ctl — HNC Dual-Stack clsact ingress/egress BPF loader & map manager
 *
 * Supports both legacy ip_mark_map (4B IPv4 -> 4B mark) and v5.34 mac_mark_map
 * (8B padded L2 MAC -> 4B mark) + optional SEC("tc_egress") AOSP tether6 bypass guard.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
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

#define OBJ_PATH_DEFAULT "/data/local/hnc/bin/hnc_clsact.o"
#define PIN_DIR          "/sys/fs/bpf/hnc"
#define MAP_PIN          PIN_DIR "/ip_mark_map"
#define MAC_MAP_PIN      PIN_DIR "/mac_mark_map"

#define TC_H_CLSACT_HANDLE   0xFFFF0000U
#define TC_H_CLSACT_PARENT   0xFFFFFFF1U
#define TC_H_INGRESS_PARENT  0xFFFFFFF2U
#define TC_H_EGRESS_PARENT   0xFFFFFFF3U
#define HNC_FILTER_PREF      1
#define HNC_FILTER_HANDLE    1
#define HNC_FILTER_KIND      "bpf"
#define HNC_PROG_NAME        "hnc_clsact"
#define HNC_EGRESS_NAME      "hnc_clsact_eg"

#ifndef TCA_BPF_FLAG_ACT_DIRECT
#define TCA_BPF_FLAG_ACT_DIRECT 1
#endif

#define R_BPF_64_64       1
#define BPF_PSEUDO_MAP_FD 1
#define BPF_LD_DW_IMM     0x18

#define RC_OK        0
#define RC_IFACE     1
#define RC_BPF       2
#define RC_NETLINK   3
#define RC_USAGE     4
#define RC_MAP       5

#define LOGE(fmt, ...) fprintf(stderr, "clsact_ctl: " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stderr, "clsact_ctl: " fmt "\n", ##__VA_ARGS__)

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

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
                     const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
        return -1;
    struct rtattr *rta = NLMSG_TAIL(n);
    rta->rta_type = (unsigned short)type;
    rta->rta_len  = (unsigned short)len;
    if (alen && data)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = (uint32_t)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len));
    return 0;
}

static struct rtattr *addattr_nest(struct nlmsghdr *n, size_t maxlen, int type)
{
    struct rtattr *nest = NLMSG_TAIL(n);
    if (addattr_l(n, maxlen, type, NULL, 0) < 0)
        return NULL;
    return nest;
}

static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (unsigned short)((char *)NLMSG_TAIL(n) - (char *)nest);
}

static uint32_t g_seq;

static int rtnl_talk(int fd, struct nlmsghdr *req)
{
    char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
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

        int rem = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf;
             NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
            if (h->nlmsg_seq != g_seq)
                continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    return -EBADMSG;
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
                if (e->error == 0 || e->error == -EEXIST)
                    return 0;
                return e->error;
            }
            if (h->nlmsg_type == NLMSG_DONE)
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
    char buf[512] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_NEWQDISC;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = TC_H_CLSACT_PARENT;
    t->tcm_handle  = TC_H_CLSACT_HANDLE;

    if (addattr_l(n, sizeof(buf), TCA_KIND, "clsact", strlen("clsact") + 1) < 0)
        return -EMSGSIZE;

    int rc = rtnl_talk(nlfd, n);
    if (rc == 0)
        LOGI("clsact qdisc present/added (ifindex=%u)", ifindex);
    else
        LOGE("clsact qdisc add: %s", strerror(-rc));
    return rc;
}

static int bpf_filter_attach_dir(int nlfd, unsigned ifindex, uint32_t parent,
                                 int prog_fd, const char *prog_name)
{
    char buf[512] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;
    struct rtattr *opt;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_NEWTFILTER;
    /* NLM_F_REPLACE is required so install/repair atomically swaps upgraded BPF
     * programs on handle 1 instead of silently leaving stale programs behind. */
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = parent;
    t->tcm_info    = (HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    t->tcm_handle  = HNC_FILTER_HANDLE;

    if (addattr_l(n, sizeof(buf), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return -EMSGSIZE;

    opt = addattr_nest(n, sizeof(buf), TCA_OPTIONS);
    if (!opt)
        return -EMSGSIZE;
    uint32_t fd32 = (uint32_t)prog_fd;
    if (addattr_l(n, sizeof(buf), TCA_BPF_FD, &fd32, sizeof(fd32)) < 0)
        return -EMSGSIZE;
    if (addattr_l(n, sizeof(buf), TCA_BPF_NAME, prog_name,
                  strlen(prog_name) + 1) < 0)
        return -EMSGSIZE;
    uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    if (addattr_l(n, sizeof(buf), TCA_BPF_FLAGS, &flags, sizeof(flags)) < 0)
        return -EMSGSIZE;
    addattr_nest_end(n, opt);

    int rc = rtnl_talk(nlfd, n);
    if (rc == 0)
        LOGI("bpf filter (%s) attached at parent=0x%x pref=%d (fd=%d)",
             prog_name, parent, HNC_FILTER_PREF, prog_fd);
    else
        LOGE("bpf filter (%s) attach: %s", prog_name, strerror(-rc));
    return rc;
}

static int bpf_filter_exists_dir(int nlfd, unsigned ifindex, uint32_t parent)
{
    char buf[256] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_GETTFILTER;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = parent;
    t->tcm_info    = (HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    t->tcm_handle  = HNC_FILTER_HANDLE;
    if (addattr_l(n, sizeof(buf), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return 0;
    return rtnl_talk(nlfd, n) == 0;
}

static int bpf_filter_detach_dir(int nlfd, unsigned ifindex, uint32_t parent)
{
    char buf[256] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_DELTFILTER;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = parent;
    t->tcm_info    = (HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    t->tcm_handle  = HNC_FILTER_HANDLE;
    if (addattr_l(n, sizeof(buf), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return -EMSGSIZE;
    return rtnl_talk(nlfd, n);
}

static int clsact_qdisc_exists(int nlfd, unsigned ifindex)
{
    char buf[256] __attribute__((aligned(NLMSG_ALIGNTO)));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_GETQDISC;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = TC_H_CLSACT_PARENT;
    t->tcm_handle  = TC_H_CLSACT_HANDLE;
    return rtnl_talk(nlfd, n) == 0;
}

/* ── Mini ELF Loader (Overflow & Alignment Hardened) ─────────────────── */

struct elf_ctx {
    uint8_t    *data;
    size_t      size;
    Elf64_Ehdr *eh;
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

    c->eh = (Elf64_Ehdr *)c->data;
    if (memcmp(c->eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        c->eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        c->eh->e_machine != EM_BPF) {
        LOGE("not an eBPF ELF object: %s", path);
        free(c->data);
        c->data = NULL;
        return -1;
    }
    uint64_t sh_bytes = (uint64_t)c->eh->e_shnum * sizeof(Elf64_Shdr);
    if (c->eh->e_shoff == 0 || c->eh->e_shnum == 0 ||
        c->eh->e_shentsize != sizeof(Elf64_Shdr) ||
        c->eh->e_shstrndx >= c->eh->e_shnum ||
        !range_valid(c->eh->e_shoff, sh_bytes, c->size)) {
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
    memcpy(c->sh, c->data + c->eh->e_shoff, (size_t)sh_bytes);
    Elf64_Shdr *shstr_sh = &c->sh[c->eh->e_shstrndx];
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
    for (int i = 0; i < c->eh->e_shnum; i++) {
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
    for (int i = 0; i < c->eh->e_shnum; i++) {
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
    if (symi < 0 || symi >= c->eh->e_shnum)
        return -1;
    Elf64_Shdr *symsh = &c->sh[symi];
    if (symsh->sh_type != SHT_SYMTAB || symsh->sh_link >= c->eh->e_shnum)
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
                            uint32_t want_ksz, uint32_t want_vsz, int optional)
{
    int mi = sec_index(c, "maps");
    if (mi < 0) {
        LOGE("no 'maps' section");
        return -1;
    }
    int symi = -1;
    for (int i = 0; i < c->eh->e_shnum; i++)
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
        if (a.attr.map_type != BPF_MAP_TYPE_HASH ||
            a.attr.key_size != want_ksz || a.attr.value_size != want_vsz) {
            LOGE("unexpected map def %s: type=%u key=%u val=%u",
                 want_sym, d[0], d[1], d[2]);
            return -1;
        }
        int fd = sys_bpf(BPF_MAP_CREATE, &a);
        if (fd < 0)
            LOGE("BPF_MAP_CREATE(%s): %s", want_sym, strerror(errno));
        return fd;
    }
    if (!optional)
        LOGE("symbol %s not found in maps section", want_sym);
    return -2; /* -2 = symbol absent */
}

static int load_prog_sec(struct elf_ctx *c, const char *sec_name,
                         int ip_map_fd, int mac_map_fd, int optional)
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

    for (int i = 0; i < c->eh->e_shnum; i++) {
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
            uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
            uint32_t typ     = ELF64_R_TYPE(rel.r_info);
            size_t insn_idx  = (size_t)(rel.r_offset / 8);
            if (typ != R_BPF_64_64 || (rel.r_offset % 8) != 0 ||
                insn_idx + 1 >= ninsn || sym_idx >= nsym) {
                LOGE("unsupported or out-of-bounds relocation (type=%u sym=%u) in %s",
                     typ, sym_idx, sec_name);
                free(insns);
                return -1;
            }
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
            if (target_fd < 0) {
                LOGE("unresolved map symbol '%s' in %s", sname, sec_name);
                free(insns);
                return -1;
            }
            uint32_t *w = (uint32_t *)&insns[insn_idx];
            w[0] = (w[0] & 0xFFFF0F00u) | BPF_LD_DW_IMM | (BPF_PSEUDO_MAP_FD << 12);
            w[1] = (uint32_t)target_fd;
            uint32_t *w2 = (uint32_t *)&insns[insn_idx + 1];
            w2[1] = 0;
        }
    }

    char *logbuf = calloc(1, 1U << 16);
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    a.attr.insns     = (uint64_t)(uintptr_t)insns;
    a.attr.insn_cnt  = (uint32_t)ninsn;
    a.attr.license   = (uint64_t)(uintptr_t)"GPL";
    if (logbuf) {
        a.attr.log_buf   = (uint64_t)(uintptr_t)logbuf;
        a.attr.log_size  = 1U << 16;
        a.attr.log_level = 1;
    }
    int fd = sys_bpf(BPF_PROG_LOAD, &a);
    free(insns);
    if (fd < 0) {
        LOGE("BPF_PROG_LOAD(%s): %s", sec_name, strerror(errno));
        if (logbuf && logbuf[0])
            fprintf(stderr, "--- verifier log (%s) ---\n%s--------------------\n",
                    sec_name, logbuf);
    }
    free(logbuf);
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

static int get_or_pin_map(int new_fd, const char *pin_path, int *was_existing)
{
    *was_existing = 0;
    if (new_fd < 0)
        return -1;
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)pin_path;
    int old = sys_bpf(BPF_OBJ_GET, &a);
    if (old >= 0) {
        close(new_fd);
        *was_existing = 1;
        return old;
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

static int cmd_install(const char *iface, const char *obj)
{
    unsigned ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        LOGE("iface %s not found", iface);
        return RC_IFACE;
    }
    struct elf_ctx c;
    if (elf_load(&c, obj) < 0)
        return RC_BPF;

    int raw_ip_fd = create_named_map(&c, "ip_mark_map", 4, 4, 0);
    if (raw_ip_fd < 0) { elf_free(&c); return RC_BPF; }
    int ip_existed = 0;
    int ip_map_fd = get_or_pin_map(raw_ip_fd, MAP_PIN, &ip_existed);
    if (ip_map_fd < 0) { elf_free(&c); return RC_BPF; }

    int raw_mac_fd = create_named_map(&c, "mac_mark_map", sizeof(struct mac_key), 4, 1);
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
        mac_map_fd = get_or_pin_map(raw_mac_fd, MAC_MAP_PIN, &mac_existed);
        if (mac_map_fd < 0) {
            if (!ip_existed) unlink(MAP_PIN);
            close(ip_map_fd);
            elf_free(&c);
            return RC_BPF;
        }
    }

    int prog_in = load_prog_sec(&c, "tc", ip_map_fd, mac_map_fd, 0);
    int prog_eg = (mac_map_fd >= 0) ? load_prog_sec(&c, "tc_egress", ip_map_fd, mac_map_fd, 1) : -1;
    elf_free(&c);

    if (prog_in < 0) {
        if (prog_eg >= 0) close(prog_eg);
        if (!ip_existed) unlink(MAP_PIN);
        if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
        close(ip_map_fd);
        if (mac_map_fd >= 0) close(mac_map_fd);
        return RC_BPF;
    }

    int nlfd = rtnl_open();
    if (nlfd < 0) {
        close(prog_in);
        if (prog_eg >= 0) close(prog_eg);
        if (!ip_existed) unlink(MAP_PIN);
        if (mac_map_fd >= 0 && !mac_existed) unlink(MAC_MAP_PIN);
        close(ip_map_fd);
        if (mac_map_fd >= 0) close(mac_map_fd);
        return RC_NETLINK;
    }
    int rc = clsact_qdisc_ensure(nlfd, ifindex);
    if (rc == 0) {
        int in_rc = bpf_filter_attach_dir(nlfd, ifindex, TC_H_INGRESS_PARENT, prog_in, HNC_PROG_NAME);
        int eg_rc = -1;
        /* Always attempt egress attachment even if ingress pref 1 is held by
         * HNC's matchall->ifb0 filter, so tether6 egress bypass stays guarded. */
        if (prog_eg >= 0)
            eg_rc = bpf_filter_attach_dir(nlfd, ifindex, TC_H_EGRESS_PARENT, prog_eg, HNC_EGRESS_NAME);
        rc = (in_rc == 0 || eg_rc == 0) ? 0 : in_rc;
    }

    close(nlfd);
    close(prog_in);
    if (prog_eg >= 0) close(prog_eg);
    close(ip_map_fd);
    if (mac_map_fd >= 0) close(mac_map_fd);
    return rc == 0 ? RC_OK : RC_NETLINK;
}

static int cmd_check(const char *iface)
{
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
    int mp = 0, mmp = 0;
    int mfd = open_pinned_path(MAP_PIN, 1);
    if (mfd >= 0) { mp = 1; close(mfd); }
    int mmfd = open_pinned_path(MAC_MAP_PIN, 1);
    if (mmfd >= 0) { mmp = 1; close(mmfd); }
    char safe_iface[IFNAMSIZ * 2];
    json_escape_str(iface, safe_iface, sizeof(safe_iface));
    printf("{\"iface\":\"%s\",\"ok\":%s,\"qdisc\":%s,\"bpf_filter\":%s,\"map\":%s,\"mac_map\":%s,\"egress_filter\":%s}\n",
           safe_iface,
           (qd && fl && mp) ? "true" : "false",
           qd ? "true" : "false",
           fl ? "true" : "false",
           mp ? "true" : "false",
           mmp ? "true" : "false",
           eg ? "true" : "false");
    return RC_OK;
}

static int cmd_update(const char *target, const char *markstr)
{
    char *endp = NULL;
    errno = 0;
    unsigned long raw_mark = strtoul(markstr, &endp, 0);
    if (errno != 0 || endp == markstr || *endp != '\0' || raw_mark > 0xffffffffUL) {
        LOGE("invalid mark: %s", markstr);
        return RC_MAP;
    }
    uint32_t mark = (uint32_t)raw_mark;
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
        char *endp = NULL;
        errno = 0;
        unsigned long raw_m = strtoul(markstr, &endp, 0);
        if (errno != 0 || endp == markstr || *endp != '\0' || raw_m == 0 || raw_m > 0xffffffffUL)
            continue;
        uint32_t mark = (uint32_t)raw_m;

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
    while (irc == 0) {
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
        while (mrc == 0) {
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

static int cmd_uninstall(const char *iface)
{
    unsigned ifindex = if_nametoindex(iface);
    int rc = RC_OK;
    if (ifindex != 0) {
        int nlfd = rtnl_open();
        if (nlfd >= 0) {
            (void)bpf_filter_detach_dir(nlfd, ifindex, TC_H_INGRESS_PARENT);
            (void)bpf_filter_detach_dir(nlfd, ifindex, TC_H_EGRESS_PARENT);
            close(nlfd);
        } else {
            rc = RC_NETLINK;
        }
    }
    unlink(MAP_PIN);
    unlink(MAC_MAP_PIN);
    return rc;
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
        "  %s uninstall <iface>\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return RC_USAGE; }
    const char *cmd = argv[1];
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
        return cmd_uninstall(argv[2]);
    }
    usage(argv[0]);
    return RC_USAGE;
}
