/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hnc_clsact_ctl — HNC clsact ingress BPF 的加载/挂载/查护/map 写入工具
 *
 * 背景
 * ----
 * hnc_clsact.bpf.c 在热点接口 clsact ingress pref 1 按源 IP 给 skb->mark
 * 预设限速标记。本工具补齐 5.9.91 分叉缺失的 userspace 侧: 加载 ELF、
 * pin map、netlink 挂载 filter、按 devices/rules 数据刷新 map。
 *
 * 为什么不用 libbpf 的 object-loading API: 该 API 需要 libelf/libz, 本仓库
 * 工具链没有可用的 Android 版(hotspotd v5.8.7 已验证此路不通)。因此这里
 * 是裸 bpf(2) syscall 的迷你加载器, BPF 程序配合使用传统 bpf_map_def
 * (SEC("maps")), map 参数可直接从 ELF 节读出, 无需 BTF 解析。
 *
 * 用法
 * ----
 *   hnc_clsact_ctl install <iface>       加载+pin map+挂 filter(幂等)
 *   hnc_clsact_ctl check <iface>         输出 JSON 状态(qdisc/filter/map)
 *   hnc_clsact_ctl repair <iface>        = install(缺失项补齐)
 *   hnc_clsact_ctl update <ip> <mark>    单条写入 pin 的 map
 *   hnc_clsact_ctl sync                  从 stdin 读 "ip mark" 行全量刷 map
 *   hnc_clsact_ctl uninstall <iface>     删自己的 filter(NLM_F_EXCL 精确
 *                                        handle)+unpin map。不删 clsact
 *                                        qdisc —— AOSP tether filter 共用
 *                                        它, 删了会破坏硬件 offload。
 *
 * 退出码: 0=成功或已存在; 1=iface 不存在; 2=BPF 加载/pin 失败;
 *         3=netlink 失败; 4=用法错误; 5=map 操作失败。
 * 任何失败都不影响系统状态(已创建资源在失败路径上回收)。
 *
 * 依赖: 纯 libc + Linux uapi 头 + 裸 bpf(2)/rtnetlink。无 libbpf/libelf。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#include <linux/bpf.h>
#include <linux/elf.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>

/* ── 常量 ─────────────────────────────────────────────────────────────── */

/* arm64: bpf syscall 号 (asm-generic) */
#define SYS_BPF_NO 280

#define OBJ_PATH_DEFAULT "/data/local/hnc/bin/hnc_clsact.o"
#define PIN_DIR          "/sys/fs/bpf/hnc"
#define MAP_PIN          PIN_DIR "/ip_mark_map"

/* tc 常量(字面量定义, 不依赖 NDK sysroot 导出宏 —— 与 hnc_tc_ingress 同策略) */
#define TC_H_CLSACT_HANDLE   0xFFFF0000U
#define TC_H_CLSACT_PARENT   0xFFFFFFF1U
#define TC_H_INGRESS_PARENT  0xFFFFFFF2U  /* clsact/ingress 虚拟父 */
#define HNC_FILTER_PREF      1
#define HNC_FILTER_HANDLE    1
#define HNC_FILTER_KIND      "bpf"
#define HNC_PROG_NAME        "hnc_clsact"

/* TCA_BPF_FLAGS 里 direct-action 的 bit(uapi enum TCA_BPF_FLAG_ACT_DIRECT) */
#define TCA_BPF_FLAG_ACT_DIRECT 1

/* EM_BPF 重定位类型 */
#define R_BPF_64_64 1

/* BPF 指令(ld_imm64 的 src_reg 指示伪 map fd 加载) */
#define BPF_PSEUDO_MAP_FD 1
#define BPF_LD_DW_IMM     0x18  /* BPF_LD | BPF_DW | BPF_IMM */

/* 返回码 */
#define RC_OK        0
#define RC_IFACE     1
#define RC_BPF       2
#define RC_NETLINK   3
#define RC_USAGE     4
#define RC_MAP       5

#define LOGE(fmt, ...) fprintf(stderr, "clsact_ctl: " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stderr, "clsact_ctl: " fmt "\n", ##__VA_ARGS__)

/* ── bpf(2) syscall 封装(128B pad 保持 union ABI 稳定, dpid 同款) ────── */

union bpf_attr_pad {
    union bpf_attr attr;
    char pad[128];
};

static int sys_bpf(int cmd, union bpf_attr_pad *attr)
{
    return (int)syscall(SYS_BPF_NO, cmd, &attr->attr, sizeof(attr->attr));
}

/* ── rtnetlink 构造器(iproute2 风格, 抄 hnc_tc_ingress.c) ─────────────── */

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
                     const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
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
    /* 发送并等 ACK; EEXIST 按成功处理(幂等)。返回 0 ok / -errno。 */
    char buf[8192];
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = req, .iov_len = req->nlmsg_len };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t n = sendmsg(fd, &msg, 0);
    if (n < 0)
        return -errno;

    struct timeval tv = { .tv_sec = 3 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0)
        return -errno;
    for (struct nlmsghdr *h = (struct nlmsghdr *)buf;
         NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_seq != g_seq)
            continue;
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = NLMSG_DATA(h);
            if (e->error == 0 || e->error == -EEXIST)
                return 0;
            return e->error;
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

/* clsact qdisc add(幂等,EEXIST 即已存在) */
static int clsact_qdisc_ensure(int nlfd, unsigned ifindex)
{
    char buf[512];
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

/* pref 1 handle 1 的 bpf direct-action filter 挂载(NLM_F_CREATE|NLM_F_REPLACE) */
static int bpf_filter_attach(int nlfd, unsigned ifindex, int prog_fd)
{
    char buf[512];
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct tcmsg *t;
    struct rtattr *opt;

    memset(buf, 0, sizeof(buf));
    n->nlmsg_len   = NLMSG_LENGTH(sizeof(*t));
    n->nlmsg_type  = RTM_NEWTFILTER;
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    n->nlmsg_seq   = ++g_seq;
    t = NLMSG_DATA(n);
    t->tcm_family  = AF_UNSPEC;
    t->tcm_ifindex = (int)ifindex;
    t->tcm_parent  = TC_H_INGRESS_PARENT;
    /* tcm_info = prio<<16 | protocol(htons)。protocol all = ETH_P_ALL */
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
    if (addattr_l(n, sizeof(buf), TCA_BPF_NAME, HNC_PROG_NAME,
                  strlen(HNC_PROG_NAME) + 1) < 0)
        return -EMSGSIZE;
    uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    if (addattr_l(n, sizeof(buf), TCA_BPF_FLAGS, &flags, sizeof(flags)) < 0)
        return -EMSGSIZE;
    addattr_nest_end(n, opt);

    int rc = rtnl_talk(nlfd, n);
    if (rc == 0)
        LOGI("bpf filter attached at pref %d (fd=%d)", HNC_FILTER_PREF, prog_fd);
    else
        LOGE("bpf filter attach: %s", strerror(-rc));
    return rc;
}

/* 查询 pref1 filter 是否存在(GET, ENOENT=缺失) */
static int bpf_filter_exists(int nlfd, unsigned ifindex)
{
    char buf[256];
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
    t->tcm_parent  = TC_H_INGRESS_PARENT;
    t->tcm_info    = (HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    if (addattr_l(n, sizeof(buf), TCA_KIND, HNC_FILTER_KIND,
                  strlen(HNC_FILTER_KIND) + 1) < 0)
        return 0;
    return rtnl_talk(nlfd, n) == 0;
}

/* 删除自己的 pref1 filter(精确 handle, 不动 qdisc 与其他 filter) */
static int bpf_filter_detach(int nlfd, unsigned ifindex)
{
    char buf[256];
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
    t->tcm_parent  = TC_H_INGRESS_PARENT;
    t->tcm_info    = (HNC_FILTER_PREF << 16) | htons(ETH_P_ALL);
    t->tcm_handle  = HNC_FILTER_HANDLE;
    return rtnl_talk(nlfd, n);
}

/* clsact qdisc 是否存在 */
static int clsact_qdisc_exists(int nlfd, unsigned ifindex)
{
    char buf[256];
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

/* ── 迷你 ELF 加载器 ──────────────────────────────────────────────────── */

struct elf_ctx {
    uint8_t  *data;
    size_t    size;
    Elf64_Ehdr *eh;
    Elf64_Shdr *sh;
    const char *shstr;
};

static int elf_load(struct elf_ctx *c, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOGE("open %s: %s", path, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 << 20) {
        fclose(f);
        LOGE("bad obj size %ld", sz);
        return -1;
    }
    c->data = malloc(sz);
    c->size = (size_t)sz;
    if (fread(c->data, 1, c->size, f) != c->size) {
        fclose(f);
        LOGE("read %s failed", path);
        return -1;
    }
    fclose(f);

    c->eh = (Elf64_Ehdr *)c->data;
    if (memcmp(c->eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        c->eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        c->eh->e_machine != EM_BPF) {
        LOGE("not an eBPF ELF object: %s", path);
        return -1;
    }
    c->sh = (Elf64_Shdr *)(c->data + c->eh->e_shoff);
    c->shstr = (const char *)(c->data + c->sh[c->eh->e_shstrndx].sh_offset);
    return 0;
}

static int sec_index(struct elf_ctx *c, const char *name)
{
    for (int i = 0; i < c->eh->e_shnum; i++) {
        const char *n = c->shstr + c->sh[i].sh_name;
        if (strcmp(n, name) == 0)
            return i;
    }
    return -1;
}

/* 在 "maps" 节里找唯一 map 符号并 BPF_MAP_CREATE。返回 fd 或 -1。
 * 传统 bpf_map_def: 符号 st_value 是节内偏移, 定义体 7×u32。 */
static int create_map_from_maps_section(struct elf_ctx *c)
{
    int mi = sec_index(c, "maps");
    if (mi < 0) {
        LOGE("no 'maps' section (need legacy bpf_map_def style)");
        return -1;
    }
    /* 找 symtab */
    int symi = -1;
    for (int i = 0; i < c->eh->e_shnum; i++)
        if (c->sh[i].sh_type == SHT_SYMTAB) { symi = i; break; }
    if (symi < 0) {
        LOGE("no symtab");
        return -1;
    }
    Elf64_Shdr *symsh = &c->sh[symi];
    Elf64_Sym *syms = (Elf64_Sym *)(c->data + symsh->sh_offset);
    size_t nsym = symsh->sh_size / sizeof(Elf64_Sym);
    const char *str = (const char *)(c->data + c->sh[symsh->sh_link].sh_offset);

    for (size_t k = 0; k < nsym; k++) {
        if (syms[k].st_shndx != mi || syms[k].st_name == 0)
            continue;
        const char *name = str + syms[k].st_name;
        if (strcmp(name, "ip_mark_map") != 0)
            continue;
        if (syms[k].st_value + 7 * sizeof(uint32_t) > c->sh[mi].sh_size) {
            LOGE("map def out of bounds");
            return -1;
        }
        uint32_t *d = (uint32_t *)(c->data + c->sh[mi].sh_offset + syms[k].st_value);
        union bpf_attr_pad a;
        memset(&a, 0, sizeof(a));
        a.attr.map_type    = d[0];
        a.attr.key_size    = d[1];
        a.attr.value_size  = d[2];
        a.attr.max_entries = d[3];
        a.attr.map_flags   = d[4];
        if (a.attr.map_type != BPF_MAP_TYPE_HASH || a.attr.key_size != 4 ||
            a.attr.value_size != 4) {
            LOGE("unexpected map def: type=%u key=%u val=%u",
                 d[0], d[1], d[2]);
            return -1;
        }
        int fd = sys_bpf(BPF_MAP_CREATE, &a);
        if (fd < 0)
            LOGE("BPF_MAP_CREATE: %s", strerror(errno));
        return fd;
    }
    LOGE("symbol ip_mark_map not found in maps section");
    return -1;
}

/* 加载 "tc" 节的程序, patch map fd 伪指令。返回 prog fd 或 -1。 */
static int load_prog(struct elf_ctx *c, int map_fd)
{
    int pi = sec_index(c, "tc");
    if (pi < 0) {
        LOGE("no 'tc' section");
        return -1;
    }
    size_t insnsz = c->sh[pi].sh_size;
    if (insnsz == 0 || insnsz % 8 != 0) {
        LOGE("bad tc section size %zu", insnsz);
        return -1;
    }
    size_t ninsn = insnsz / 8;
    uint64_t *insns = malloc(insnsz);
    memcpy(insns, c->data + c->sh[pi].sh_offset, insnsz);

    /* 找 .rel"tc" 并 patch map 符号引用(R_BPF_64_64 → ld_imm64 伪 fd)。
     * bpf_insn 小端布局: u32#0 = code | regs<<8 | off<<16 (dst=bits8-11,
     * src=bits12-15), u32#1 = imm。伪 fd 加载: code=0x18(BPF_LD|BPF_DW|
     * BPF_IMM), src_reg=BPF_PSEUDO_MAP_FD, imm=fd(第二 insn 的 imm 是
     * 高 32 位, fd 恒 32 位故清零)。 */
    for (int i = 0; i < c->eh->e_shnum; i++) {
        if (c->sh[i].sh_type != SHT_REL || c->sh[i].sh_info != (uint32_t)pi)
            continue;
        int symi = (int)c->sh[i].sh_link;
        Elf64_Shdr *symsh = &c->sh[symi];
        Elf64_Sym *syms = (Elf64_Sym *)(c->data + symsh->sh_offset);
        const char *str =
            (const char *)(c->data + c->sh[symsh->sh_link].sh_offset);
        Elf64_Rel *rels = (Elf64_Rel *)(c->data + c->sh[i].sh_offset);
        size_t nrel = c->sh[i].sh_size / sizeof(Elf64_Rel);
        for (size_t k = 0; k < nrel; k++) {
            uint32_t sym = ELF64_R_SYM(rels[k].r_info);
            uint32_t typ = ELF64_R_TYPE(rels[k].r_info);
            size_t insn_idx = rels[k].r_offset / 8;
            if (typ != R_BPF_64_64 || insn_idx + 1 >= ninsn)
                continue;
            if (strcmp(str + syms[sym].st_name, "ip_mark_map") != 0)
                continue;
            uint32_t *w = (uint32_t *)&insns[insn_idx];
            w[0] = (w[0] & 0xFFFF0F00u) | BPF_LD_DW_IMM |
                   (BPF_PSEUDO_MAP_FD << 12);
            w[1] = (uint32_t)map_fd;
            uint32_t *w2 = (uint32_t *)&insns[insn_idx + 1];
            w2[1] = 0; /* 高 32 位 */
        }
    }

    char logbuf[1 << 16];
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    a.attr.insns     = (uint64_t)(uintptr_t)insns;
    a.attr.insn_cnt  = (uint32_t)ninsn;
    a.attr.license   = (uint64_t)(uintptr_t)"GPL";
    a.attr.log_buf   = (uint64_t)(uintptr_t)logbuf;
    a.attr.log_size  = sizeof(logbuf);
    a.attr.log_level = 1;
    int fd = sys_bpf(BPF_PROG_LOAD, &a);
    free(insns);
    if (fd < 0) {
        LOGE("BPF_PROG_LOAD: %s", strerror(errno));
        if (logbuf[0])
            fprintf(stderr, "--- verifier log ---\n%s--------------------\n", logbuf);
    }
    return fd;
}

/* ── pin / map 操作 ───────────────────────────────────────────────────── */

static int ensure_pin_dir(void)
{
    /* /sys/fs/bpf 在 Android 上是常驻 bpffs 挂载点(tethering map 就住在
     * 那里), 只需建我们的子目录。 */
    if (mkdir(PIN_DIR, 0755) == 0 || errno == EEXIST)
        return 0;
    LOGE("mkdir %s: %s", PIN_DIR, strerror(errno));
    return -1;
}

static int pin_map(int map_fd)
{
    if (ensure_pin_dir() < 0)
        return -1;
    /* 已有旧 pin: unlink 后重 pin(旧 map 的引用由旧 filter 持有, 安全) */
    unlink(MAP_PIN);
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)MAP_PIN;
    a.attr.bpf_fd   = (uint32_t)map_fd;
    if (sys_bpf(BPF_OBJ_PIN, &a) < 0) {
        LOGE("BPF_OBJ_PIN %s: %s", MAP_PIN, strerror(errno));
        return -1;
    }
    return 0;
}

static int open_pinned_map(void)
{
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)MAP_PIN;
    int fd = sys_bpf(BPF_OBJ_GET, &a);
    if (fd < 0)
        LOGE("BPF_OBJ_GET %s: %s (map not pinned?)", MAP_PIN, strerror(errno));
    return fd;
}

static int map_update(int map_fd, const char *ip, uint32_t mark)
{
    uint32_t key;
    if (inet_pton(AF_INET, ip, &key) != 1) {
        LOGE("invalid ip: %s", ip);
        return -1;
    }
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.map_fd = (uint32_t)map_fd;
    a.attr.key    = (uint64_t)(uintptr_t)&key;
    a.attr.value  = (uint64_t)(uintptr_t)&mark;
    a.attr.flags  = 0; /* BPF_ANY */
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) < 0) {
        LOGE("BPF_MAP_UPDATE_ELEM(%s): %s", ip, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── 子命令实现 ───────────────────────────────────────────────────────── */

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
    int map_fd = create_map_from_maps_section(&c);
    if (map_fd < 0) { free(c.data); return RC_BPF; }

    /* 若已有旧 pin: 复用旧 map(保住旧 filter 仍可用), 关闭新 fd */
    union bpf_attr_pad a;
    memset(&a, 0, sizeof(a));
    a.attr.pathname = (uint64_t)(uintptr_t)MAP_PIN;
    int old = sys_bpf(BPF_OBJ_GET, &a);
    if (old >= 0) {
        close(map_fd);
        map_fd = old;
    } else if (pin_map(map_fd) < 0) {
        close(map_fd);
        free(c.data);
        return RC_BPF;
    }

    int prog_fd = load_prog(&c, map_fd);
    free(c.data);
    if (prog_fd < 0) {
        if (old < 0) {
            unlink(MAP_PIN);
            close(map_fd);
        }
        return RC_BPF;
    }

    int nlfd = rtnl_open();
    if (nlfd < 0) {
        close(prog_fd);
        if (old < 0) { unlink(MAP_PIN); close(map_fd); }
        return RC_NETLINK;
    }
    int rc = clsact_qdisc_ensure(nlfd, ifindex);
    if (rc != 0) { close(nlfd); close(prog_fd); return RC_NETLINK; }
    rc = bpf_filter_attach(nlfd, ifindex, prog_fd);
    close(nlfd);
    close(prog_fd);
    if (rc != 0)
        return RC_NETLINK;
    return RC_OK;
}

static int cmd_check(const char *iface)
{
    unsigned ifindex = if_nametoindex(iface);
    int nlfd = rtnl_open();
    int qd = 0, fl = 0;
    if (nlfd >= 0) {
        qd = clsact_qdisc_exists(nlfd, ifindex);
        fl = qd ? bpf_filter_exists(nlfd, ifindex) : 0;
        close(nlfd);
    }
    int mp = 0;
    int mfd = open_pinned_map();
    if (mfd >= 0) { mp = 1; close(mfd); }
    /* watchdog 进程态由调用方(shell)另行 pgrep; 这里只报内核态三件 */
    printf("{\"iface\":\"%s\",\"ok\":%s,\"qdisc\":%s,\"bpf_filter\":%s,\"map\":%s}\n",
           iface,
           (qd && fl && mp) ? "true" : "false",
           qd ? "true" : "false",
           fl ? "true" : "false",
           mp ? "true" : "false");
    return RC_OK;
}

static int cmd_update(const char *ip, const char *markstr)
{
    uint32_t mark = (uint32_t)strtoul(markstr, NULL, 0);
    int fd = open_pinned_map();
    if (fd < 0)
        return RC_MAP;
    int rc = map_update(fd, ip, mark);
    close(fd);
    return rc == 0 ? RC_OK : RC_MAP;
}

static int cmd_sync(void)
{
    /* stdin 每行 "ip mark"(mark 为完整值 0x800000+id)。先全量写, 空行结束。
     * shell 侧(bin/hnc_clsact_sync.sh)负责从 devices/rules 提取换算。 */
    int fd = open_pinned_map();
    if (fd < 0)
        return RC_MAP;
    char line[256];
    int n = 0;
    while (fgets(line, sizeof(line), stdin)) {
        char ip[64], markstr[64];
        if (sscanf(line, "%63s %63s", ip, markstr) != 2)
            continue;
        if (map_update(fd, ip, (uint32_t)strtoul(markstr, NULL, 0)) == 0)
            n++;
    }
    close(fd);
    LOGI("sync: %d entries written", n);
    return RC_OK;
}

static int cmd_uninstall(const char *iface)
{
    unsigned ifindex = if_nametoindex(iface);
    int rc = RC_OK;
    if (ifindex != 0) {
        int nlfd = rtnl_open();
        if (nlfd >= 0) {
            bpf_filter_detach(nlfd, ifindex);
            close(nlfd);
        } else {
            rc = RC_NETLINK;
        }
    }
    /* 故意不删 clsact qdisc —— AOSP tether filter 共用它 */
    unlink(MAP_PIN);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        goto usage;
    const char *obj = getenv("HNC_CLSACT_OBJ");
    if (!obj || !*obj)
        obj = OBJ_PATH_DEFAULT;

    if (!strcmp(argv[1], "install") || !strcmp(argv[1], "repair")) {
        if (argc < 3)
            goto usage;
        return cmd_install(argv[2], obj);
    }
    if (!strcmp(argv[1], "check")) {
        if (argc < 3)
            goto usage;
        return cmd_check(argv[2]);
    }
    if (!strcmp(argv[1], "update")) {
        if (argc < 4)
            goto usage;
        return cmd_update(argv[2], argv[3]);
    }
    if (!strcmp(argv[1], "sync")) {
        return cmd_sync();
    }
    if (!strcmp(argv[1], "uninstall")) {
        if (argc < 3)
            goto usage;
        return cmd_uninstall(argv[2]);
    }

usage:
    fprintf(stderr,
        "usage: %s install|repair <iface>\n"
        "       %s check <iface>\n"
        "       %s update <ip> <mark>\n"
        "       %s sync < entries   (lines: \"<ip> <mark>\")\n"
        "       %s uninstall <iface>\n",
        argv[0], argv[0], argv[0], argv[0], argv[0]);
    return RC_USAGE;
}
