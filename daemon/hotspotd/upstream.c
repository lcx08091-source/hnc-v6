/* upstream.c — HNC v5.0 上游 ifindex 探测实现
 *
 * alpha.2: Tier 1 (ip route) + Tier 2 (/proc/net/route)
 * alpha.4 P0-C: + Tier 3 BPF upstream4_map 反查, 且 Tier 3 优先
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "upstream.h"
#include "hnc_helpers.h"   /* v5.9.0: hnc_run_cmd_timeout (Tier1 超时执行) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <pthread.h>

#ifndef __NR_bpf
#  if defined(__aarch64__)
#    define __NR_bpf 280
#  elif defined(__arm__)
#    define __NR_bpf 386
#  elif defined(__x86_64__)
#    define __NR_bpf 321
#  elif defined(__i386__)
#    define __NR_bpf 357
#  else
#    error "unknown arch, define __NR_bpf"
#  endif
#endif

/* BUG-004: 缓存已知热点接口名,防止上游探测把它误判为 upstream。
 * 由 upstream_detect_primary() 在每次探测前从状态文件刷新。
 * 空字符串表示尚未确认(早期启动)。 */
static char g_known_hs_iface[IFNAMSIZ] = {0};
static pthread_mutex_t g_hs_iface_lock = PTHREAD_MUTEX_INITIALIZER;

static void get_known_hs_iface(char out[IFNAMSIZ])
{
    pthread_mutex_lock(&g_hs_iface_lock);
    memcpy(out, g_known_hs_iface, IFNAMSIZ);
    out[IFNAMSIZ - 1] = '\0';
    pthread_mutex_unlock(&g_hs_iface_lock);
}

static void refresh_known_hs_iface(void)
{
    char buf[IFNAMSIZ] = {0};
    FILE *f;
    char line[256];

    /* Tier 1: hnc_state — ACTIVE:<iface> */
    f = fopen("/data/local/hnc/run/hnc_state", "re");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "ACTIVE:", 7) == 0) {
                char *nl = strpbrk(line + 7, "\r\n \t");
                if (nl) *nl = '\0';
                if (line[7] != '\0') {
                    snprintf(buf, sizeof(buf), "%.*s", (int)sizeof(buf) - 1, line + 7);
                    fclose(f);
                    goto done;
                }
            }
        }
        fclose(f);
    }

    /* Tier 2: hotspot_iface file */
    f = fopen("/data/local/hnc/run/hotspot_iface", "re");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            char *nl = strpbrk(line, "\r\n \t");
            if (nl) *nl = '\0';
            if (line[0] != '\0') {
                snprintf(buf, sizeof(buf), "%.*s", (int)sizeof(buf) - 1, line);
            }
        }
        fclose(f);
    }

done:
    if (buf[0] != '\0') {
        pthread_mutex_lock(&g_hs_iface_lock);
        snprintf(g_known_hs_iface, sizeof(g_known_hs_iface), "%s", buf);
        pthread_mutex_unlock(&g_hs_iface_lock);
    }
}

static int is_vpn_or_tunnel_iface(const char *name)
{
    if (!name || name[0] == '\0') return 0;
    return strncmp(name, "tun",   3) == 0 ||
           strncmp(name, "tap",   3) == 0 ||
           strncmp(name, "ppp",   3) == 0 ||
           strncmp(name, "wg",    2) == 0 ||
           strncmp(name, "gre",   3) == 0 ||
           strncmp(name, "ipsec", 5) == 0;
}

static int is_excluded_downstream_iface(const char *name, const char *hs_iface)
{
    if (!name || name[0] == '\0') return 1;
    if (hs_iface && hs_iface[0] != '\0' && strcmp(name, hs_iface) == 0)
        return 1;
    if (strcmp(name, "lo") == 0) return 1;
    if (strncmp(name, "dummy",   5) == 0) return 1;
    if (strncmp(name, "ifb",     3) == 0) return 1;
    if (strncmp(name, "r_rmnet", 7) == 0) return 1;
    if (strncmp(name, "wlan1",   5) == 0) return 1;
    if (strncmp(name, "wlan2",   5) == 0) return 1;
    if (strncmp(name, "wlan3",   5) == 0) return 1;
    if (strncmp(name, "softap",  6) == 0) return 1;
    if (strncmp(name, "ap_br_",  6) == 0) return 1;
    if (strncmp(name, "ap",      2) == 0) return 1;
    if (strncmp(name, "swlan",   5) == 0) return 1;
    if (strncmp(name, "wigig",   5) == 0) return 1;
    if (strncmp(name, "rndis",   5) == 0) return 1;
    if (strncmp(name, "ncm",     3) == 0) return 1;
    if (strncmp(name, "usb",     3) == 0) return 1;
    if (strncmp(name, "bt-pan",  6) == 0) return 1;
    if (strncmp(name, "p2p",     3) == 0) return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * Tier 1: 纯 C AF_NETLINK RTM_GETROUTE -> 无发包 UDP connect+getsockname
 *         -> 失败时回退 /system/bin/ip route get 8.8.8.8
 * ══════════════════════════════════════════════════════════ */

static int detect_via_netlink_getroute(const char *hs_iface,
                                       int *ifindex_out,
                                       char *ifname_out,
                                       size_t ifname_size,
                                       int *saw_excluded_out)
{
    if (saw_excluded_out) *saw_excluded_out = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_nl local_nl;
    memset(&local_nl, 0, sizeof(local_nl));
    local_nl.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&local_nl, sizeof(local_nl)) < 0) {
        close(fd);
        return -1;
    }

    char req_buf[128] __attribute__((aligned(NLMSG_ALIGNTO)));
    memset(req_buf, 0, sizeof(req_buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)req_buf;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type  = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = 1U;

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family  = AF_INET;
    rtm->rtm_dst_len = 32;

    uint32_t dst_ip = htonl(0x08080808U); /* 8.8.8.8 */
    struct rtattr *rta = (struct rtattr *)(req_buf + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = (unsigned short)RTA_LENGTH(sizeof(dst_ip));
    memcpy(RTA_DATA(rta), &dst_ip, sizeof(dst_ip));
    nlh->nlmsg_len = (uint32_t)(NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len));

    struct sockaddr_nl kern_nl;
    memset(&kern_nl, 0, sizeof(kern_nl));
    kern_nl.nl_family = AF_NETLINK;

    ssize_t sent;
    do {
        sent = sendto(fd, req_buf, nlh->nlmsg_len, MSG_NOSIGNAL,
                      (struct sockaddr *)&kern_nl, sizeof(kern_nl));
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
        close(fd);
        return -1;
    }

    char resp_buf[4096] __attribute__((aligned(NLMSG_ALIGNTO)));
    ssize_t n;
    do {
        n = recv(fd, resp_buf, sizeof(resp_buf), 0);
    } while (n < 0 && errno == EINTR);
    close(fd);
    if (n <= 0) return -1;

    size_t rem = (size_t)n;
    for (size_t off = 0; rem >= sizeof(struct nlmsghdr); ) {
        struct nlmsghdr *h = (struct nlmsghdr *)(resp_buf + off);
        if (h->nlmsg_len < sizeof(struct nlmsghdr) || (size_t)h->nlmsg_len > rem)
            break;
        size_t step = NLMSG_ALIGN(h->nlmsg_len);
        if (step > rem) step = rem;

        if (h->nlmsg_type == NLMSG_ERROR)
            return -1;

        if (h->nlmsg_type == RTM_NEWROUTE &&
            h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg))) {
            size_t attr_off = NLMSG_SPACE(sizeof(struct rtmsg));
            if ((size_t)h->nlmsg_len > attr_off) {
                size_t attr_rem = (size_t)h->nlmsg_len - attr_off;
                const char *ap = (const char *)h + attr_off;
                while (attr_rem >= sizeof(struct rtattr)) {
                    const struct rtattr *a = (const struct rtattr *)ap;
                    if (a->rta_len < sizeof(struct rtattr) || (size_t)a->rta_len > attr_rem)
                        break;
                    if (a->rta_type == RTA_OIF &&
                        (size_t)a->rta_len >= RTA_LENGTH(sizeof(uint32_t))) {
                        uint32_t oif = 0;
                        memcpy(&oif, RTA_DATA(a), sizeof(oif));
                        if (oif > 0U && oif <= 65535U) {
                            char iface[IFNAMSIZ] = {0};
                            if (if_indextoname(oif, iface) != NULL) {
                                if (is_vpn_or_tunnel_iface(iface) ||
                                    is_excluded_downstream_iface(iface, hs_iface)) {
                                    fprintf(stderr, "[upstream] Tier1(nl): skipping iface '%s'\n", iface);
                                    if (saw_excluded_out) *saw_excluded_out = 1;
                                    return -1;
                                }
                                *ifindex_out = (int)oif;
                                snprintf(ifname_out, ifname_size, "%s", iface);
                                return 0;
                            }
                        }
                    }
                    size_t astep = RTA_ALIGN(a->rta_len);
                    if (astep > attr_rem) break;
                    ap += astep;
                    attr_rem -= astep;
                }
            }
        }
        off += step;
        rem -= step;
    }
    return -1;
}

static int detect_via_udp_connect(const char *hs_iface,
                                  int *ifindex_out,
                                  char *ifname_out,
                                  size_t ifname_size,
                                  int *saw_excluded_out)
{
    if (saw_excluded_out) *saw_excluded_out = 0;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(53);
    dst.sin_addr.s_addr = htonl(0x08080808U); /* 8.8.8.8 — UDP connect 零发包 */

    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in local_sa;
    memset(&local_sa, 0, sizeof(local_sa));
    socklen_t slen = (socklen_t)sizeof(local_sa);
    if (getsockname(fd, (struct sockaddr *)&local_sa, &slen) != 0 ||
        local_sa.sin_family != AF_INET ||
        local_sa.sin_addr.s_addr == 0U ||
        (ntohl(local_sa.sin_addr.s_addr) >> 24) == 127U) {
        close(fd);
        return -1;
    }

    struct ifreq ifr_buf[64];
    memset(ifr_buf, 0, sizeof(ifr_buf));
    struct ifconf ifc;
    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = (int)sizeof(ifr_buf);
    ifc.ifc_req = ifr_buf;

    if (ioctl(fd, SIOCGIFCONF, &ifc) != 0 || ifc.ifc_len <= 0) {
        close(fd);
        return -1;
    }
    close(fd);

    size_t n_ifr = (size_t)ifc.ifc_len / sizeof(struct ifreq);
    for (size_t i = 0; i < n_ifr; i++) {
        if (ifr_buf[i].ifr_addr.sa_family != AF_INET)
            continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)&ifr_buf[i].ifr_addr;
        if (sa->sin_addr.s_addr != local_sa.sin_addr.s_addr)
            continue;

        char iface[IFNAMSIZ];
        snprintf(iface, sizeof(iface), "%.*s", IFNAMSIZ - 1, ifr_buf[i].ifr_name);
        if (is_vpn_or_tunnel_iface(iface) ||
            is_excluded_downstream_iface(iface, hs_iface)) {
            fprintf(stderr, "[upstream] Tier1(udp): skipping iface '%s'\n", iface);
            if (saw_excluded_out) *saw_excluded_out = 1;
            return -1;
        }
        unsigned int idx = if_nametoindex(iface);
        if (idx == 0U)
            continue;
        *ifindex_out = (int)idx;
        snprintf(ifname_out, ifname_size, "%s", iface);
        return 0;
    }
    return -1;
}

int upstream_detect_via_ip_route(int *ifindex_out,
                                  char *ifname_out,
                                  size_t ifname_size)
{
    if (!ifindex_out || !ifname_out || ifname_size < 2) return -1;

    char hs_iface[IFNAMSIZ];
    get_known_hs_iface(hs_iface);

    int saw_excluded = 0;
    if (detect_via_netlink_getroute(hs_iface, ifindex_out, ifname_out,
                                    ifname_size, &saw_excluded) == 0) {
        return 0;
    }
    if (saw_excluded) return -1;

    if (detect_via_udp_connect(hs_iface, ifindex_out, ifname_out,
                               ifname_size, &saw_excluded) == 0) {
        return 0;
    }
    if (saw_excluded) return -1;

    /* 仅当纯 C Netlink 与无发包 UDP 均失败时, 回退 /system/bin/ip */
    char out[4096];
    char *const cmd[] = { "/system/bin/ip", "route", "get", "8.8.8.8", NULL };
    int n = hnc_run_cmd_timeout(cmd, out, sizeof(out), 500);
    if (n <= 0) return -1;

    int found = 0;
    char *save = NULL;
    for (char *line = strtok_r(out, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        const char *dev = strstr(line, " dev ");
        if (!dev) continue;
        dev += 5;

        char iface[IFNAMSIZ] = {0};
        int i = 0;
        while (dev[i] && !isspace((unsigned char)dev[i]) && i < (int)sizeof(iface) - 1) {
            iface[i] = dev[i];
            i++;
        }
        if (i == 0) continue;

        if (is_vpn_or_tunnel_iface(iface) ||
            is_excluded_downstream_iface(iface, hs_iface)) {
            fprintf(stderr, "[upstream] Tier1(ip): skipping iface '%s'\n", iface);
            continue;
        }

        unsigned int idx = if_nametoindex(iface);
        if (idx == 0) continue;

        *ifindex_out = (int)idx;
        snprintf(ifname_out, ifname_size, "%s", iface);
        found = 1;
        break;
    }
    return found ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════
 * Tier 2: /proc/net/route 扫描 (放宽条件)
 * ══════════════════════════════════════════════════════════ */

static int looks_like_uplink_iface(const char *name)
{
    if (!name) return 0;
    char hs_iface[IFNAMSIZ];
    get_known_hs_iface(hs_iface);
    if (is_excluded_downstream_iface(name, hs_iface))
        return 0;

    if (strncmp(name, "rmnet",    5) == 0) return 1;
    if (strncmp(name, "ccmni",    5) == 0) return 1;
    if (strncmp(name, "sipa_eth", 8) == 0) return 1;
    if (strncmp(name, "seth_",    5) == 0) return 1;
    if (strncmp(name, "gti",      3) == 0) return 1;
    if (strncmp(name, "wwan",     4) == 0) return 1;
    if (strncmp(name, "eth",      3) == 0) return 1;
    if (strncmp(name, "ppp",      3) == 0) return 1;
    if (strcmp(name,  "wlan0")       == 0) return 1;
    return 0;
}

int upstream_detect_via_proc_route(int *ifindex_out,
                                    char *ifname_out,
                                    size_t ifname_size)
{
    if (!ifindex_out || !ifname_out || ifname_size < 2) return -1;

    FILE *f = fopen("/proc/net/route", "re");
    if (!f) return -1;

    char line[512];
    /* skip header */
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return -1;
    }

    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        char dest[16];
        unsigned int flags;
        if (sscanf(line, "%15s %15s %*s %x", iface, dest, &flags) != 3)
            continue;
        if (!(flags & 0x1)) continue;   /* RTF_UP */
        if (!looks_like_uplink_iface(iface)) continue;

        unsigned int idx = if_nametoindex(iface);
        if (idx == 0) continue;

        *ifindex_out = (int)idx;
        snprintf(ifname_out, ifname_size, "%s", iface);
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════
 * Tier 3: BPF upstream4_map 反查 (alpha.4 P0-C)
 *
 * 原理:
 *   ColorOS 有 BPF tethering. 当有流量经过 HNC, upstream4_map 已被 Android
 *   framework 填满 (flow → upstream info). 每条 value[0] 就是真实物理上游
 *   ifindex.
 *
 * 为什么 Tier 3 要先行 (优先于 Tier 1/2):
 *   1. 最准确: BPF map 里就是 framework 认定的物理上游, 跟 HTB offload 用的是
 *      同一个 ifindex, 写 limit 必然命中
 *   2. 最可靠: hotspotd 本身已经打开 BPF (adapter_bpf), 同一 SELinux 上下文下
 *      读另一个 map 不会被挡; 而 popen("ip ...") 在 daemon domain 下
 *      可能被阻挡
 *   3. 免 VPN 干扰: tun0/wg0 不会出现在 tethering BPF map 里 (framework 只
 *      给 physical upstream 建 entry)
 *
 * 实现:
 *   - 打开 /sys/fs/bpf/tethering/map_offload_tether_upstream4_map
 *   - 用 BPF_MAP_GET_NEXT_KEY 枚举 (key=NULL → first)
 *   - 读 value, value[0] = upstream ifindex (AOSP TetherUpstream4Value struct)
 *   - if_indextoname 转 ifname
 *
 * Value 结构 (AOSP packages/modules/Connectivity/Tethering/bpf_progs/offload.h):
 *   struct TetherUpstream4Value {
 *       __u32 oif;           ← value[0], 本函数要的
 *       struct ethhdr macHeader;
 *       __u16 pmtu;
 *       ...
 *   };
 *   只要前 4 字节 u32, 不需完整 struct 对齐
 * ══════════════════════════════════════════════════════════ */

#define BPF_UPSTREAM4_MAP  "/sys/fs/bpf/tethering/map_offload_tether_upstream4_map"

static long _sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int upstream_detect_via_bpf(int *ifindex_out,
                             char *ifname_out,
                             size_t ifname_size)
{
    if (!ifindex_out || !ifname_out || ifname_size < 2) return -1;

    /* 打开 upstream4_map */
    union bpf_attr oattr;
    memset(&oattr, 0, sizeof(oattr));
    oattr.pathname = (uint64_t)(uintptr_t)BPF_UPSTREAM4_MAP;
    long fd = _sys_bpf(BPF_OBJ_GET, &oattr, sizeof(oattr));
    if (fd < 0) {
        /* map 不存在 (ROM 没 tethering BPF) 或无权限 */
        fprintf(stderr, "[upstream] Tier3: open %s failed: %s\n",
                BPF_UPSTREAM4_MAP, strerror(errno));
        return -1;
    }

    /* key/value 尺寸不确定 (不同 ROM struct 略有差异), 用充足 buffer
     * 真实 TetherUpstream4Key ≈ 40 bytes, Value ≈ 24 bytes, 预留到 128 */
    unsigned char key[128];
    unsigned char next_key[128];
    unsigned char value[128];

    /* 校验 map schema: 防止 ROM 扩大 struct 或使用 PERCPU map 写爆栈缓冲 */
    struct bpf_map_info minfo;
    memset(&minfo, 0, sizeof(minfo));
    union bpf_attr iattr;
    memset(&iattr, 0, sizeof(iattr));
    iattr.info.bpf_fd   = (uint32_t)fd;
    iattr.info.info_len = (uint32_t)sizeof(minfo);
    iattr.info.info     = (uint64_t)(uintptr_t)&minfo;
    if (_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &iattr, sizeof(iattr)) < 0) {
        fprintf(stderr, "[upstream] Tier3: get_info failed: %s\n", strerror(errno));
        close((int)fd);
        return -1;
    }
    if (minfo.key_size == 0 || minfo.key_size > sizeof(key) ||
        minfo.value_size < sizeof(uint32_t) || minfo.value_size > sizeof(value) ||
        minfo.type == (uint32_t)BPF_MAP_TYPE_PERCPU_HASH ||
        minfo.type == (uint32_t)BPF_MAP_TYPE_PERCPU_ARRAY ||
        minfo.type == (uint32_t)BPF_MAP_TYPE_LRU_PERCPU_HASH ||
        minfo.type == 21U /* BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE */) {
        fprintf(stderr,
                "[upstream] Tier3: incompatible map schema (type=%u key=%u val=%u)\n",
                minfo.type, minfo.key_size, minfo.value_size);
        close((int)fd);
        return -1;
    }

    memset(key, 0, sizeof(key));
    memset(next_key, 0, sizeof(next_key));
    memset(value, 0, sizeof(value));

    /* 枚举第一个 key
     * beta.2 修: Linux 5.x+ 内核下 attr.key = NULL 可能被当作
     * "key 在 map 末尾" 返回 ENOENT (即使 map 非空). 6.6.102 实测真机命中.
     * 改用全零 key 作为种子: kernel 找第一个 > key 的, 如果 map 里没有全零
     * key (正常情况, 因为真实 key 是 flow 5-tuple), 就返回第一条.
     *
     * 某些 kernel 版本还要求 attr.key != 0 才有效, 我们直接传 key buffer 的
     * 指针, kernel 读到全零 key 会正常处理. */
    union bpf_attr nattr;
    memset(&nattr, 0, sizeof(nattr));
    nattr.map_fd   = (uint32_t)fd;
    nattr.key      = (uint64_t)(uintptr_t)key;       /* 全零种子, 不是 NULL */
    nattr.next_key = (uint64_t)(uintptr_t)next_key;
    int rc = (int)_sys_bpf(BPF_MAP_GET_NEXT_KEY, &nattr, sizeof(nattr));
    if (rc < 0) {
        /* 两种失败都合法: kernel 真空 (ENOENT) / 全零 key 恰好命中 map 末尾 */
        if (errno != ENOENT) {
            fprintf(stderr, "[upstream] Tier3: get_next_key failed: %s\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
        /* ENOENT: 可能 map 真空, 也可能全零 key 恰好 >= 所有真实 key.
         * 退一步: 再试 attr.key = NULL (老语义) */
        memset(&nattr, 0, sizeof(nattr));
        nattr.map_fd   = (uint32_t)fd;
        nattr.key      = 0;                           /* NULL = 老语义 */
        nattr.next_key = (uint64_t)(uintptr_t)next_key;
        rc = (int)_sys_bpf(BPF_MAP_GET_NEXT_KEY, &nattr, sizeof(nattr));
        if (rc < 0) {
            fprintf(stderr, "[upstream] Tier3: upstream4_map empty or unreachable (errno=%s)\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
    }

    /* 用 next_key lookup value */
    union bpf_attr lattr;
    memset(&lattr, 0, sizeof(lattr));
    lattr.map_fd = (uint32_t)fd;
    lattr.key    = (uint64_t)(uintptr_t)next_key;    /* beta.2: 用 next_key */
    lattr.value  = (uint64_t)(uintptr_t)value;
    rc = (int)_sys_bpf(BPF_MAP_LOOKUP_ELEM, &lattr, sizeof(lattr));
    close(fd);
    if (rc < 0) {
        fprintf(stderr, "[upstream] Tier3: lookup_elem failed: %s\n",
                strerror(errno));
        return -1;
    }

    /* value[0..3] = oif (upstream ifindex), little-endian */
    uint32_t oif = (uint32_t)value[0]
                 | ((uint32_t)value[1] << 8)
                 | ((uint32_t)value[2] << 16)
                 | ((uint32_t)value[3] << 24);
    if (oif == 0 || oif > 65535) {
        fprintf(stderr, "[upstream] Tier3: bogus oif=%u, skip\n", oif);
        return -1;
    }

    char name[IFNAMSIZ] = {0};
    if (if_indextoname(oif, name) == NULL) {
        fprintf(stderr, "[upstream] Tier3: if_indextoname(%u) failed\n", oif);
        return -1;
    }

    char hs_iface[IFNAMSIZ];
    get_known_hs_iface(hs_iface);
    if (is_vpn_or_tunnel_iface(name) ||
        is_excluded_downstream_iface(name, hs_iface)) {
        fprintf(stderr, "[upstream] Tier3: skipping excluded iface %s (oif=%u)\n", name, oif);
        return -1;
    }

    *ifindex_out = (int)oif;
    snprintf(ifname_out, ifname_size, "%s", name);
    fprintf(stderr, "[upstream] Tier3: found %s (ifindex=%d) via BPF upstream4_map\n",
            name, (int)oif);
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * Tier 4: BPF limit_map 反查 (beta.2 新增, 兜底 Tier 3)
 *
 * 原理:
 *   Android tethering framework 主动在 limit_map 里给每个 active upstream
 *   ifindex 写 U64_MAX 分配无限额度. 这是个 { u32 ifindex → u64 limit } 的
 *   简单 map, struct 不会变.
 *
 *   遍历 limit_map 所有 key (ifindex), 跳过已知 downstream (wlan2 ifindex
 *   一般是 31/32, 通过 hotspot iface 名反查), 第一个非 downstream ifindex
 *   就是 upstream.
 *
 * 为什么放 Tier 3 之后做兜底 (而不是直接取代 Tier 3):
 *   - limit_map 也可能包含已关闭的上游 (value=0, framework 暂未清理)
 *   - Tier 3 直接查 upstream4_map 更精确 (只含 active flow)
 *   - Tier 4 兜底适合 Tier 3 get_next_key 在新 kernel 下语义不兼容时
 *
 * 性能: 遍历少数几个 entry, 纯 BPF syscall, <1ms
 * ══════════════════════════════════════════════════════════ */

#define BPF_LIMIT_MAP_PATH  "/sys/fs/bpf/tethering/map_offload_tether_limit_map"

int upstream_detect_via_limit_map(int *ifindex_out,
                                   char *ifname_out,
                                   size_t ifname_size)
{
    if (!ifindex_out || !ifname_out || ifname_size < 2) return -1;

    union bpf_attr oattr;
    memset(&oattr, 0, sizeof(oattr));
    oattr.pathname = (uint64_t)(uintptr_t)BPF_LIMIT_MAP_PATH;
    long fd = _sys_bpf(BPF_OBJ_GET, &oattr, sizeof(oattr));
    if (fd < 0) {
        fprintf(stderr, "[upstream] Tier4: open %s failed: %s\n",
                BPF_LIMIT_MAP_PATH, strerror(errno));
        return -1;
    }

    /* 校验 limit_map key_size == 4, 防止魔改 ROM key_size > 4 导致栈溢出 */
    struct bpf_map_info minfo;
    memset(&minfo, 0, sizeof(minfo));
    union bpf_attr iattr;
    memset(&iattr, 0, sizeof(iattr));
    iattr.info.bpf_fd   = (uint32_t)fd;
    iattr.info.info_len = (uint32_t)sizeof(minfo);
    iattr.info.info     = (uint64_t)(uintptr_t)&minfo;
    if (_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &iattr, sizeof(iattr)) < 0) {
        fprintf(stderr, "[upstream] Tier4: get_info failed: %s\n", strerror(errno));
        close((int)fd);
        return -1;
    }
    if (minfo.key_size != 4U) {
        fprintf(stderr,
                "[upstream] Tier4: incompatible limit_map key_size=%u (expected 4)\n",
                minfo.key_size);
        close((int)fd);
        return -1;
    }

    /* 遍历 limit_map, 收集所有 ifindex
     * limit_map key 是 u32 ifindex, value 是 u64 limit
     * 最多 16 个上游 (够覆盖 rmnet_data0..5, wlan0/1/2, eth0, tun0 等) */
    uint32_t ifindexes[16];
    int count = 0;

    uint32_t prev_key = 0;
    uint32_t next_key = 0;
    uint32_t zero = 0;
    int first = 1;

    while (count < 16) {
        union bpf_attr nattr;
        memset(&nattr, 0, sizeof(nattr));
        nattr.map_fd   = (uint32_t)fd;
        nattr.next_key = (uint64_t)(uintptr_t)&next_key;
        if (first) {
            /* 首次用全零 key (不是 NULL), 兼容新老 kernel 语义 */
            nattr.key = (uint64_t)(uintptr_t)&zero;
        } else {
            nattr.key = (uint64_t)(uintptr_t)&prev_key;
        }

        int rc = (int)_sys_bpf(BPF_MAP_GET_NEXT_KEY, &nattr, sizeof(nattr));
        if (rc < 0) {
            if (first && errno == ENOENT) {
                /* 全零 key 失败, 试 NULL (老 kernel 语义) */
                memset(&nattr, 0, sizeof(nattr));
                nattr.map_fd   = (uint32_t)fd;
                nattr.key      = 0;
                nattr.next_key = (uint64_t)(uintptr_t)&next_key;
                rc = (int)_sys_bpf(BPF_MAP_GET_NEXT_KEY, &nattr, sizeof(nattr));
            }
            if (rc < 0) break;   /* 真的没了 */
        }

        ifindexes[count++] = next_key;
        prev_key = next_key;
        first = 0;
    }
    close((int)fd);

    if (count == 0) {
        fprintf(stderr, "[upstream] Tier4: limit_map empty\n");
        return -1;
    }

    /* 拿到 hotspot downstream ifindex (要跳过它) */
    unsigned wlan1_idx  = if_nametoindex("wlan1");
    unsigned wlan2_idx  = if_nametoindex("wlan2");
    unsigned wlan3_idx  = if_nametoindex("wlan3");
    unsigned ap0_idx    = if_nametoindex("ap0");
    unsigned swlan0_idx = if_nametoindex("swlan0");
    /* BUG-004: 也跳过已知热点接口的 ifindex */
    char hs_iface[IFNAMSIZ];
    get_known_hs_iface(hs_iface);
    unsigned hs_idx = hs_iface[0] ? if_nametoindex(hs_iface) : 0;

    /* 找第一个非 downstream / 非 VPN 的 ifindex */
    for (int i = 0; i < count; i++) {
        uint32_t idx = ifindexes[i];
        if (idx == 0) continue;
        if (wlan1_idx && idx == wlan1_idx) continue;
        if (wlan2_idx && idx == wlan2_idx) continue;
        if (wlan3_idx && idx == wlan3_idx) continue;
        if (ap0_idx && idx == ap0_idx) continue;
        if (swlan0_idx && idx == swlan0_idx) continue;
        if (hs_idx && idx == hs_idx) continue;

        char name[IFNAMSIZ] = {0};
        if (if_indextoname(idx, name) == NULL) continue;

        if (is_vpn_or_tunnel_iface(name) ||
            is_excluded_downstream_iface(name, hs_iface))
            continue;

        *ifindex_out = (int)idx;
        snprintf(ifname_out, ifname_size, "%s", name);
        fprintf(stderr, "[upstream] Tier4: found %s (ifindex=%u) via BPF limit_map\n",
                name, idx);
        return 0;
    }

    fprintf(stderr, "[upstream] Tier4: limit_map scanned %d entries, no viable upstream\n",
            count);
    return -1;
}

/* ══════════════════════════════════════════════════════════
 * 入口: 优先级 Tier 3 > Tier 4 > Tier 1 > Tier 2 (beta.2)
 *
 * beta.2 真机 RMX5010 6.6.102 发现 Tier 3 的 BPF_MAP_GET_NEXT_KEY 在新
 * kernel 上对 NULL key 语义不兼容, 总返回 ENOENT (即使 map 非空). 加
 * Tier 4 作为 BPF 层兜底, 从 limit_map (schema 稳定的 u32→u64 map) 反推.
 * ══════════════════════════════════════════════════════════ */

int upstream_detect_primary(int *ifindex_out,
                             char *ifname_out,
                             size_t ifname_size)
{
    /* BUG-004: 探测前刷新已知热点接口,让 looks_like_uplink_iface 排除它 */
    refresh_known_hs_iface();

    /* Tier 3: BPF upstream4_map 反查 (最准) */
    if (upstream_detect_via_bpf(ifindex_out, ifname_out, ifname_size) == 0) {
        return 0;
    }
    /* Tier 4: BPF limit_map 反查 (schema 稳定, 兼容性最好) */
    if (upstream_detect_via_limit_map(ifindex_out, ifname_out, ifname_size) == 0) {
        return 0;
    }
    /* Tier 1: ip route get (已过滤 VPN) */
    if (upstream_detect_via_ip_route(ifindex_out, ifname_out, ifname_size) == 0) {
        return 0;
    }
    /* Tier 2: /proc/net/route 启发式 (上面都失败才走) */
    if (upstream_detect_via_proc_route(ifindex_out, ifname_out, ifname_size) == 0) {
        return 0;
    }
    return -1;
}
