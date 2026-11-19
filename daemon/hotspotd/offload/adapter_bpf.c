/* offload/adapter_bpf.c — HNC v5.40.0 AOSP BPF tethering offload adapter
 *
 * 平台覆盖:
 *   - 高通 SDM/SM 系列 + 联发科 Dimensity + 展锐/Pixel Android 11–16 (AOSP BPF tethering)
 *   - 任何带 Mainline Connectivity/Tethering APEX 的 ROM 实现 (ColorOS/HyperOS/PixelOS/OneUI)
 *
 * v5.40.0 核心升级 (保留 100% offload_adapter_t 接口契约):
 *   1. 动态 Schema 感知流表清空 (BPF_OBJ_GET_INFO_BY_FD):
 *      动态读取真实 info.key_size (0 < key_size <= 256, 仅限 HASH / LRU_HASH),
 *      采用“先 GET_NEXT_KEY 再 DELETE_ELEM + ENOENT 回退重锚 + max_iters 熔断”安全清空
 *      downstream4_map、upstream4_map、downstream6_map、upstream6_map (无缝免疫
 *      12B -> 20B/24B Mainline APEX 变更) 与 downstream64_map。
 *   2. T+0 空表主动预锁 (Zero-Packet-Leak Pre-Seeding):
 *      当 disable_global 发现 map_offload_tether_limit_map 为空时, 主动扫描
 *      /sys/class/net 下处于 IFF_UP 的上游候选接口 (rmnet*, ccmni*, wlan*, eth*,
 *      v4-*, usb*, 排除 lo 及当前热点 AP 口, 最多预写 12 个以严守 max_entries=16),
 *      通过 if_nametoindex 以 BPF_ANY 预写入 uint64_t quota = 0 (绝不触碰 stats_map,
 *      防止破坏 BpfCoordinator 的 BPF_NOEXIST 初始化), 并同步清空存量流表!
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "adapter.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef BPF_OBJ_GET_INFO_BY_FD
#define BPF_OBJ_GET_INFO_BY_FD 15
#endif

/* ══════════════════════════════════════════════════════════
 * bpf() syscall wrapper (static hnc_bpf_* 命名杜绝与 libbpf.a 符号冲突)
 * ══════════════════════════════════════════════════════════ */

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

static inline uint64_t hnc_ptr_to_u64(const void *ptr)
{
    return (uint64_t)(uintptr_t)ptr;
}

static inline long hnc_sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static int hnc_bpf_obj_get(const char *pathname)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = hnc_ptr_to_u64(pathname);
    return (int)hnc_sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int hnc_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = hnc_ptr_to_u64(key);
    attr.value  = hnc_ptr_to_u64(value);
    return (int)hnc_sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int hnc_bpf_map_update_elem(int fd, const void *key, const void *value,
                                   uint64_t flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = hnc_ptr_to_u64(key);
    attr.value  = hnc_ptr_to_u64(value);
    attr.flags  = flags;
    return (int)hnc_sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int hnc_bpf_map_delete_elem(int fd, const void *key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = hnc_ptr_to_u64(key);
    return (int)hnc_sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int hnc_bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd   = (uint32_t)fd;
    attr.key      = key ? hnc_ptr_to_u64(key) : 0ULL;
    attr.next_key = hnc_ptr_to_u64(next_key);
    return (int)hnc_sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int hnc_bpf_obj_get_info_by_fd(int fd, struct bpf_map_info *info, uint32_t *info_len)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    memset(info, 0, sizeof(*info));
    attr.info.bpf_fd   = (uint32_t)fd;
    attr.info.info_len = *info_len;
    attr.info.info     = hnc_ptr_to_u64(info);
    int rc = (int)hnc_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    *info_len = attr.info.info_len;
    return rc;
}

static offload_err_t errno_to_offload(int e)
{
    switch (e) {
    case 0:           return OFFLOAD_OK;
    case EPERM:
    case EACCES:      return OFFLOAD_EPERM;
    case ENOENT:      return OFFLOAD_ENOENT;
    case EINVAL:      return OFFLOAD_EINVAL;
    case EAGAIN:
    case EBUSY:       return OFFLOAD_EAGAIN;
    default:          return OFFLOAD_EINTERNAL;
    }
}

/* ══════════════════════════════════════════════════════════
 * Map 路径与常量定义
 * ══════════════════════════════════════════════════════════ */

#define BPF_TETHER_DIR          "/sys/fs/bpf/tethering"
#define BPF_LIMIT_MAP           BPF_TETHER_DIR "/map_offload_tether_limit_map"
#define BPF_STATS_MAP           BPF_TETHER_DIR "/map_offload_tether_stats_map"
#define BPF_ERROR_MAP           BPF_TETHER_DIR "/map_offload_tether_error_map"
#define BPF_LEGACY_R_DOWN6_MAP  "/sys/fs/bpf/map_offload_tether_downstream6_map"
#define SYSFS_NET_DIR           "/sys/class/net"

/* 动态 key_size 安全栈上限与遍历熔断余量 */
#define HNC_BPF_MAX_KEY_SIZE      256U
#define HNC_BPF_EVICT_GUARD_EXTRA 64U

/* T+0 空表预锁最多写入 12 个活跃上游接口, 严守 AOSP limit_map max_entries=16 */
#define HNC_T0_PRESEED_MAX        12U

typedef struct {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
} tether_stats_t;

#define BPF_LIMIT_NONE  ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define BPF_LIMIT_ZERO  ((uint64_t)0ULL)

#define ACTIVE_THRESHOLD_BYTES  (1ULL * 1024 * 1024)
#define ACTIVE_SAMPLE_INTERVAL  5
#define MAX_DISABLED_UPSTREAMS  32

/* ══════════════════════════════════════════════════════════
 * Adapter 状态 (受 s_lock 互斥保护)
 * ══════════════════════════════════════════════════════════ */

static struct {
    int initialized;

    int fd_limit;
    int fd_stats;
    int fd_error;

    int      cached_active;
    int64_t  cached_refresh_ts;
    uint64_t cached_delta_bytes;
    uint64_t cached_last_total;

    int disabled_upstream_ifindex[MAX_DISABLED_UPSTREAMS];
    int disabled_upstream_count;

    int globally_disabled;
} s = {
    .initialized             = 0,
    .fd_limit                = -1,
    .fd_stats                = -1,
    .fd_error                = -1,
    .cached_active           = 0,
    .cached_refresh_ts       = 0,
    .cached_delta_bytes      = 0,
    .cached_last_total       = 0,
    .disabled_upstream_count = 0,
    .globally_disabled       = 0,
};

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
#define BPF_LOCK()   pthread_mutex_lock(&s_lock)
#define BPF_UNLOCK() pthread_mutex_unlock(&s_lock)

/* ══════════════════════════════════════════════════════════
 * fd 自愈与集合管理辅助
 * ══════════════════════════════════════════════════════════ */

static int reopen_fd(int *fd, const char *path)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
    int new_fd = hnc_bpf_obj_get(path);
    if (new_fd < 0) {
        fprintf(stderr, "[bpf] obj_get failed: %s (errno=%d %s)\n",
                path, errno, strerror(errno));
        return -1;
    }
    *fd = new_fd;
    return 0;
}

static int ensure_limit_fd(void)
{
    if (s.fd_limit >= 0) return 0;
    return reopen_fd(&s.fd_limit, BPF_LIMIT_MAP);
}

static int ensure_stats_fd(void)
{
    if (s.fd_stats >= 0) return 0;
    return reopen_fd(&s.fd_stats, BPF_STATS_MAP);
}

static int disabled_set_contains(int ifindex)
{
    for (int i = 0; i < s.disabled_upstream_count; i++)
        if (s.disabled_upstream_ifindex[i] == ifindex) return 1;
    return 0;
}

static void disabled_set_add(int ifindex)
{
    if (disabled_set_contains(ifindex)) return;
    if (s.disabled_upstream_count >= MAX_DISABLED_UPSTREAMS) {
        fprintf(stderr, "[bpf] disabled set full (max %d), dropping ifindex=%d\n",
                MAX_DISABLED_UPSTREAMS, ifindex);
        return;
    }
    s.disabled_upstream_ifindex[s.disabled_upstream_count++] = ifindex;
}

static void disabled_set_remove(int ifindex)
{
    for (int i = 0; i < s.disabled_upstream_count; i++) {
        if (s.disabled_upstream_ifindex[i] == ifindex) {
            s.disabled_upstream_ifindex[i] =
                s.disabled_upstream_ifindex[--s.disabled_upstream_count];
            return;
        }
    }
}

/* ══════════════════════════════════════════════════════════
 * 核心升级 1: 动态 key_size 安全清空 AOSP Tethering 流表
 * ══════════════════════════════════════════════════════════ */

static offload_err_t evict_single_flow_map_fd(int map_fd, uint32_t *evicted_out)
{
    if (evicted_out)
        *evicted_out = 0U;
    if (map_fd < 0)
        return OFFLOAD_EINTERNAL;

    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);
    if (hnc_bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0)
        return errno_to_offload(errno);

    if (info.key_size == 0U || info.key_size > HNC_BPF_MAX_KEY_SIZE)
        return OFFLOAD_EINVAL;

    if (info.type != BPF_MAP_TYPE_HASH && info.type != BPF_MAP_TYPE_LRU_HASH)
        return OFFLOAD_EINVAL;

    uint8_t cur_key[HNC_BPF_MAX_KEY_SIZE];
    uint8_t next_key[HNC_BPF_MAX_KEY_SIZE];
    memset(cur_key, 0, sizeof(cur_key));
    memset(next_key, 0, sizeof(next_key));

    if (hnc_bpf_map_get_next_key(map_fd, NULL, cur_key) != 0) {
        if (errno == ENOENT)
            return OFFLOAD_OK;
        return errno_to_offload(errno);
    }

    uint32_t max_entries = (info.max_entries > 0U && info.max_entries <= 65536U)
                               ? info.max_entries
                               : 1024U;
    uint32_t max_iters = max_entries * 2U + HNC_BPF_EVICT_GUARD_EXTRA;
    uint32_t evicted = 0U;

    for (uint32_t iter = 0U; iter < max_iters; iter++) {
        int next_rc  = hnc_bpf_map_get_next_key(map_fd, cur_key, next_key);
        int next_err = (next_rc != 0) ? errno : 0;

        /* 先缓存 next_key 再删除 cur_key, 防止内核哈希桶退回桶首导致死循环 */
        if (hnc_bpf_map_delete_elem(map_fd, cur_key) == 0) {
            evicted++;
        } else if (errno != ENOENT) {
            if (evicted_out)
                *evicted_out = evicted;
            return errno_to_offload(errno);
        }

        if (next_rc == 0) {
            memcpy(cur_key, next_key, info.key_size);
            continue;
        }

        if (next_err == ENOENT) {
            /* 若 cur_key 恰被并发删除或已到表尾, 从 NULL 重锚剩余首键 */
            if (hnc_bpf_map_get_next_key(map_fd, NULL, cur_key) != 0)
                break;
            continue;
        }

        break;
    }

    if (evicted_out)
        *evicted_out = evicted;
    return OFFLOAD_OK;
}

static offload_err_t evict_single_flow_map_path(const char *pin_path, uint32_t *evicted_out)
{
    if (evicted_out)
        *evicted_out = 0U;
    int fd = hnc_bpf_obj_get(pin_path);
    if (fd < 0)
        return errno_to_offload(errno);

    offload_err_t rc = evict_single_flow_map_fd(fd, evicted_out);
    close(fd);
    return rc;
}

static uint32_t evict_all_tether_flow_maps(void)
{
    static const char *const kFlowMaps[] = {
        BPF_TETHER_DIR "/map_offload_tether_downstream4_map",
        BPF_TETHER_DIR "/map_offload_tether_upstream4_map",
        BPF_TETHER_DIR "/map_offload_tether_downstream6_map",
        BPF_TETHER_DIR "/map_offload_tether_upstream6_map",
        BPF_TETHER_DIR "/map_offload_tether_downstream64_map",
    };

    uint32_t total_evicted = 0U;
    uint32_t opened = 0U;

    for (size_t i = 0U; i < sizeof(kFlowMaps) / sizeof(kFlowMaps[0]); i++) {
        uint32_t n = 0U;
        offload_err_t rc = evict_single_flow_map_path(kFlowMaps[i], &n);
        if (rc == OFFLOAD_OK) {
            opened++;
            total_evicted += n;
        }
    }

    /* Android 11 (R) 旧版 netd downstream6 兼容回退 */
    if (opened == 0U) {
        uint32_t r_ev = 0U;
        if (evict_single_flow_map_path(BPF_LEGACY_R_DOWN6_MAP, &r_ev) == OFFLOAD_OK)
            total_evicted += r_ev;
    }

    if (total_evicted > 0U)
        fprintf(stderr, "[bpf] evicted %u cached tethering flow entries\n", total_evicted);
    return total_evicted;
}

/* ══════════════════════════════════════════════════════════
 * 核心升级 2: T+0 空表主动扫描 IFF_UP 上游候选预写 quota=0
 * ══════════════════════════════════════════════════════════ */

static bool starts_with(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static void read_active_ap_ifname(char out[IFNAMSIZ])
{
    out[0] = '\0';
    const char *env_ap = getenv("HNC_AP_IFACE");
    if (env_ap && env_ap[0] != '\0') {
        snprintf(out, IFNAMSIZ, "%.*s", IFNAMSIZ - 1, env_ap);
        return;
    }

    const char *hnc_dir = getenv("HNC_DIR");
    if (!hnc_dir || hnc_dir[0] == '\0')
        hnc_dir = "/data/local/hnc";

    char state_path[PATH_MAX];
    int n = snprintf(state_path, sizeof(state_path), "%s/run/hnc_state", hnc_dir);
    if (n < 0 || (size_t)n >= sizeof(state_path))
        return;

    FILE *f = fopen(state_path, "re");
    if (!f)
        return;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ACTIVE:", 7) == 0) {
            char *nl = strpbrk(line + 7, "\r\n \t");
            if (nl) *nl = '\0';
            if (line[7] != '\0') {
                snprintf(out, IFNAMSIZ, "%.*s", IFNAMSIZ - 1, line + 7);
                break;
            }
        }
    }
    fclose(f);
}

static int classify_upstream_candidate(const char *ifname, const char *ap_ifname)
{
    if (!ifname || ifname[0] == '\0' || ifname[0] == '.')
        return 0;
    if (strcmp(ifname, "lo") == 0)
        return 0;
    if (ap_ifname && ap_ifname[0] != '\0' && strcmp(ifname, ap_ifname) == 0)
        return 0;

    if ((!ap_ifname || ap_ifname[0] == '\0') && strcmp(ifname, "wlan2") == 0)
        return 0;

    if (starts_with(ifname, "ifb") ||
        starts_with(ifname, "dummy") ||
        starts_with(ifname, "ap") ||
        starts_with(ifname, "swlan") ||
        starts_with(ifname, "softap") ||
        starts_with(ifname, "p2p") ||
        starts_with(ifname, "aware") ||
        starts_with(ifname, "rndis") ||
        starts_with(ifname, "ncm") ||
        starts_with(ifname, "bt-pan")) {
        return 0;
    }

    if (starts_with(ifname, "rmnet") ||
        starts_with(ifname, "r_rmnet") ||
        starts_with(ifname, "ccmni") ||
        strcmp(ifname, "wlan0") == 0 ||
        starts_with(ifname, "eth")) {
        return 1;
    }

    if (starts_with(ifname, "wlan") ||
        starts_with(ifname, "v4-") ||
        starts_with(ifname, "usb")) {
        return 2;
    }

    return 0;
}

static bool is_netdev_iff_up(const char *ifname)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s/flags", SYSFS_NET_DIR, ifname);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    char buf[64];
    ssize_t r = read(fd, buf, sizeof(buf) - 1U);
    close(fd);
    if (r <= 0)
        return false;
    buf[r] = '\0';

    char *endp = NULL;
    errno = 0;
    unsigned long long flags = strtoull(buf, &endp, 0);
    if (errno != 0 || endp == buf)
        return false;

    return ((flags & 0x1ULL) != 0ULL) && ((flags & 0x8ULL) == 0ULL);
}

typedef struct {
    uint32_t ifindex;
    int      prio;
    char     ifname[IFNAMSIZ];
} t0_cand_t;

static uint32_t preseed_t0_limit_map_locked(void)
{
    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);
    uint32_t cap = HNC_T0_PRESEED_MAX;

    if (hnc_bpf_obj_get_info_by_fd(s.fd_limit, &info, &info_len) == 0) {
        if (info.key_size != sizeof(uint32_t) || info.value_size != sizeof(uint64_t))
            return 0U;
        if (info.max_entries > 0U && info.max_entries < cap)
            cap = info.max_entries;
    }

    char ap_ifname[IFNAMSIZ];
    read_active_ap_ifname(ap_ifname);

    DIR *dir = opendir(SYSFS_NET_DIR);
    if (!dir)
        return 0U;

    t0_cand_t cands[64];
    size_t cand_cnt = 0U;
    struct dirent *de = NULL;

    while ((de = readdir(dir)) != NULL) {
        int prio = classify_upstream_candidate(de->d_name, ap_ifname);
        if (prio <= 0)
            continue;
        if (!is_netdev_iff_up(de->d_name))
            continue;
        unsigned int idx = if_nametoindex(de->d_name);
        if (idx == 0U)
            continue;

        bool dup = false;
        for (size_t k = 0U; k < cand_cnt; k++) {
            if (cands[k].ifindex == (uint32_t)idx) {
                dup = true;
                break;
            }
        }
        if (!dup && cand_cnt < (sizeof(cands) / sizeof(cands[0]))) {
            cands[cand_cnt].ifindex = (uint32_t)idx;
            cands[cand_cnt].prio    = prio;
            snprintf(cands[cand_cnt].ifname, IFNAMSIZ, "%.*s", IFNAMSIZ - 1, de->d_name);
            cand_cnt++;
        }
    }
    closedir(dir);

    const uint64_t zero_quota = BPF_LIMIT_ZERO;
    uint32_t preseeded = 0U;

    for (int target_prio = 1; target_prio <= 2 && preseeded < cap; target_prio++) {
        for (size_t i = 0U; i < cand_cnt && preseeded < cap; i++) {
            if (cands[i].prio != target_prio)
                continue;
            uint32_t key = cands[i].ifindex;
            if (hnc_bpf_map_update_elem(s.fd_limit, &key, &zero_quota, BPF_ANY) == 0) {
                disabled_set_add((int)key);
                preseeded++;
                fprintf(stderr, "[bpf] T+0 pre-seeded quota=0 on %s (ifindex=%u)\n",
                        cands[i].ifname, key);
            }
        }
    }

    return preseeded;
}

/* ══════════════════════════════════════════════════════════
 * stats_map 累计读取 (只读不写!)
 * ══════════════════════════════════════════════════════════ */

static uint64_t stats_total_bytes(void)
{
    if (ensure_stats_fd() != 0) return 0;

    uint32_t key = 0, next_key = 0;
    uint64_t total = 0;
    int has_prev = 0;

    for (int guard = 0; guard < 256; guard++) {
        int rc = hnc_bpf_map_get_next_key(s.fd_stats,
                                          has_prev ? &key : NULL,
                                          &next_key);
        if (rc != 0) {
            if (errno != ENOENT)
                fprintf(stderr, "[bpf] stats get_next_key errno=%d\n", errno);
            break;
        }

        tether_stats_t v;
        memset(&v, 0, sizeof(v));
        if (hnc_bpf_map_lookup_elem(s.fd_stats, &next_key, &v) == 0)
            total += v.rx_bytes + v.tx_bytes;

        key = next_key;
        has_prev = 1;
    }
    return total;
}

/* ══════════════════════════════════════════════════════════
 * Adapter 接口实现 (100% 保持 offload_adapter_t 签名契约)
 * ══════════════════════════════════════════════════════════ */

static int bpf_probe(void)
{
    struct stat st;
    if (stat(BPF_LIMIT_MAP, &st) != 0) return -1;
    return 0;
}

static offload_err_t bpf_init(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (s.initialized) {
        BPF_UNLOCK();
        return OFFLOAD_OK;
    }

    if (ensure_limit_fd() != 0) {
        ret = errno_to_offload(errno);
        BPF_UNLOCK();
        return ret;
    }
    if (ensure_stats_fd() != 0) {
        fprintf(stderr, "[bpf] init: stats_map open failed, will retry on refresh\n");
    }
    s.fd_error = hnc_bpf_obj_get(BPF_ERROR_MAP);

    s.initialized = 1;
    fprintf(stderr, "[bpf] init OK (limit_fd=%d stats_fd=%d error_fd=%d)\n",
            s.fd_limit, s.fd_stats, s.fd_error);
    BPF_UNLOCK();
    return ret;
}

static void bpf_shutdown(void)
{
    BPF_LOCK();
    if (!s.initialized) {
        BPF_UNLOCK();
        return;
    }
    if (s.fd_limit >= 0) { close(s.fd_limit); s.fd_limit = -1; }
    if (s.fd_stats >= 0) { close(s.fd_stats); s.fd_stats = -1; }
    if (s.fd_error >= 0) { close(s.fd_error); s.fd_error = -1; }
    s.initialized = 0;
    BPF_UNLOCK();
}

static offload_err_t bpf_self_check(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) {
        ret = errno_to_offload(errno);
        BPF_UNLOCK();
        return ret;
    }

    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);

    if (hnc_bpf_obj_get_info_by_fd(s.fd_limit, &info, &info_len) != 0) {
        fprintf(stderr, "[bpf] self_check: get_info_by_fd errno=%d\n", errno);
        BPF_UNLOCK();
        return OFFLOAD_EINTERNAL;
    }

    if (info.key_size != 4 || info.value_size != 8) {
        fprintf(stderr,
            "[bpf] self_check FAIL: limit_map schema drift "
            "(key_size=%u expected 4, value_size=%u expected 8)\n",
            info.key_size, info.value_size);
        BPF_UNLOCK();
        return OFFLOAD_EINTERNAL;
    }
    BPF_UNLOCK();
    return ret;
}

static void bpf_status(offload_status_t *out)
{
    if (out == NULL) return;
    BPF_LOCK();
    memset(out, 0, sizeof(*out));
    out->active            = s.cached_active;
    out->last_refresh_ts   = s.cached_refresh_ts;
    out->last_delta_bytes  = s.cached_delta_bytes;
    out->globally_disabled = s.globally_disabled;

    int n = s.disabled_upstream_count;
    int cap = (int)(sizeof(out->disabled_upstream_ifindex) /
                    sizeof(out->disabled_upstream_ifindex[0]));
    int src_cap = (int)(sizeof(s.disabled_upstream_ifindex) /
                        sizeof(s.disabled_upstream_ifindex[0]));
    if (n < 0) n = 0;
    if (n > cap) n = cap;
    if (n > src_cap) n = src_cap;
    out->disabled_upstream_count = n;
    for (int i = 0; i < n; i++)
        out->disabled_upstream_ifindex[i] = s.disabled_upstream_ifindex[i];
    BPF_UNLOCK();
}

static offload_err_t bpf_refresh_active(void)
{
    BPF_LOCK();
    uint64_t t1 = stats_total_bytes();
    if (t1 == 0 && s.fd_stats < 0) {
        s.cached_active = 0;
        BPF_UNLOCK();
        return OFFLOAD_ENOENT;
    }
    BPF_UNLOCK();

    if (offload_sleep_interruptible(ACTIVE_SAMPLE_INTERVAL) != 0)
        return OFFLOAD_EAGAIN;

    BPF_LOCK();
    uint64_t t2 = stats_total_bytes();
    uint64_t delta = (t2 >= t1) ? (t2 - t1) : 0;

    s.cached_delta_bytes = delta;
    s.cached_active      = (delta >= ACTIVE_THRESHOLD_BYTES) ? 1 : 0;
    s.cached_refresh_ts  = (int64_t)time(NULL);
    s.cached_last_total  = t2;
    BPF_UNLOCK();
    return OFFLOAD_OK;
}

static offload_err_t bpf_disable_upstream(int ifindex)
{
    offload_err_t ret = OFFLOAD_OK;
    if (ifindex <= 0) return OFFLOAD_EINVAL;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t key = (uint32_t)ifindex;
    uint64_t val = BPF_LIMIT_ZERO;

    if (hnc_bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
        disabled_set_add(ifindex);
        (void)evict_all_tether_flow_maps();
        ret = OFFLOAD_OK;
        goto out;
    }

    int e1 = errno;
    if (e1 == EBADF) {
        if (reopen_fd(&s.fd_limit, BPF_LIMIT_MAP) != 0) {
            ret = errno_to_offload(errno);
            goto out;
        }
        if (hnc_bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
            disabled_set_add(ifindex);
            (void)evict_all_tether_flow_maps();
            ret = OFFLOAD_OK;
            goto out;
        }
        e1 = errno;
    }

    if (e1 == ENOENT) {
        if (hnc_bpf_map_update_elem(s.fd_limit, &key, &val, BPF_ANY) == 0) {
            disabled_set_add(ifindex);
            (void)evict_all_tether_flow_maps();
            ret = OFFLOAD_OK;
            goto out;
        }
        fprintf(stderr, "[bpf] disable_upstream: BPF_ANY also failed errno=%d\n", errno);
        ret = errno_to_offload(errno);
        goto out;
    }

    fprintf(stderr, "[bpf] disable_upstream(%d) errno=%d %s\n",
            ifindex, e1, strerror(e1));
    ret = errno_to_offload(e1);
out:
    BPF_UNLOCK();
    return ret;
}

static offload_err_t bpf_restore_upstream(int ifindex)
{
    offload_err_t ret = OFFLOAD_OK;
    if (ifindex <= 0) return OFFLOAD_EINVAL;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t key = (uint32_t)ifindex;
    uint64_t val = BPF_LIMIT_NONE;

    if (hnc_bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
        disabled_set_remove(ifindex);
        ret = OFFLOAD_OK;
        goto out;
    }

    int e = errno;
    if (e == EBADF) {
        if (reopen_fd(&s.fd_limit, BPF_LIMIT_MAP) != 0) {
            ret = errno_to_offload(errno);
            goto out;
        }
        if (hnc_bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
            disabled_set_remove(ifindex);
            ret = OFFLOAD_OK;
            goto out;
        }
        e = errno;
    }

    if (e == ENOENT) {
        disabled_set_remove(ifindex);
        ret = OFFLOAD_OK;
        goto out;
    }

    fprintf(stderr, "[bpf] restore_upstream(%d) errno=%d %s\n",
            ifindex, e, strerror(e));
    ret = errno_to_offload(e);
out:
    BPF_UNLOCK();
    return ret;
}

static offload_err_t bpf_disable_global(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t cur_key = 0, next_key = 0;
    uint64_t val = BPF_LIMIT_ZERO;
    int touched = 0;
    int errs = 0;
    int iter_errno = 0;

    if (hnc_bpf_map_get_next_key(s.fd_limit, NULL, &cur_key) != 0) {
        if (errno == EBADF && reopen_fd(&s.fd_limit, BPF_LIMIT_MAP) == 0) {
            if (hnc_bpf_map_get_next_key(s.fd_limit, NULL, &cur_key) == 0)
                goto scan_existing;
        }
        if (errno != ENOENT) {
            iter_errno = errno;
            errs++;
            fprintf(stderr, "[bpf] disable_global get_next_key errno=%d\n", iter_errno);
        }
    } else {
scan_existing:
        for (int guard = 0; guard < 128; guard++) {
            int has_next = (hnc_bpf_map_get_next_key(s.fd_limit, &cur_key, &next_key) == 0);
            if (hnc_bpf_map_update_elem(s.fd_limit, &cur_key, &val, BPF_ANY) == 0) {
                disabled_set_add((int)cur_key);
                touched++;
            } else {
                errs++;
                fprintf(stderr, "[bpf] disable_global update ifindex=%u errno=%d\n",
                        cur_key, errno);
            }
            if (!has_next)
                break;
            cur_key = next_key;
        }
    }

    /* v5.40.0 T+0 空表主动预锁: 当 limit_map 为空时主动扫描 /sys/class/net 活跃上游预写 quota=0 */
    uint32_t preseeded = 0U;
    if (touched == 0 && errs == 0) {
        preseeded = preseed_t0_limit_map_locked();
        touched += (int)preseeded;
    }

    /* 同步清空五张存量流表 (downstream4/upstream4/downstream6/upstream6/downstream64) */
    uint32_t evicted = evict_all_tether_flow_maps();

    s.globally_disabled = (touched > 0 && errs == 0) ? 1 : s.globally_disabled;
    fprintf(stderr, "[bpf] disable_global: touched=%d (t0_preseeded=%u) evicted=%u errs=%d\n",
            touched, preseeded, evicted, errs);

    if (errs == 0 && touched == 0)            ret = OFFLOAD_EEMPTY;
    else if (errs == 0)                       ret = OFFLOAD_OK;
    else if (iter_errno != 0 && touched == 0) ret = errno_to_offload(iter_errno);
    else if (touched > 0)                     ret = OFFLOAD_OK;
    else                                      ret = OFFLOAD_EINTERNAL;
out:
    BPF_UNLOCK();
    return ret;
}

static offload_err_t bpf_restore_global(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t cur_key = 0, next_key = 0;
    uint64_t val = BPF_LIMIT_NONE;
    int touched = 0;
    int errs = 0;
    int iter_errno = 0;

    if (hnc_bpf_map_get_next_key(s.fd_limit, NULL, &cur_key) != 0) {
        if (errno != ENOENT) {
            iter_errno = errno;
            errs++;
            fprintf(stderr, "[bpf] restore_global get_next_key errno=%d\n", iter_errno);
        }
    } else {
        for (int guard = 0; guard < 128; guard++) {
            int has_next = (hnc_bpf_map_get_next_key(s.fd_limit, &cur_key, &next_key) == 0);
            if (hnc_bpf_map_update_elem(s.fd_limit, &cur_key, &val, BPF_EXIST) == 0) {
                disabled_set_remove((int)cur_key);
                touched++;
            } else if (errno != ENOENT) {
                errs++;
                fprintf(stderr, "[bpf] restore_global update ifindex=%u errno=%d\n",
                        cur_key, errno);
            }
            if (!has_next)
                break;
            cur_key = next_key;
        }
    }

    if (errs == 0) {
        s.globally_disabled = 0;
        s.disabled_upstream_count = 0;
    }
    fprintf(stderr, "[bpf] restore_global: touched=%d errs=%d\n", touched, errs);

    if (errs == 0 && touched == 0)            ret = OFFLOAD_EEMPTY;
    else if (errs == 0)                       ret = OFFLOAD_OK;
    else if (iter_errno != 0 && touched == 0) ret = errno_to_offload(iter_errno);
    else if (touched > 0)                     ret = OFFLOAD_OK;
    else                                      ret = OFFLOAD_EINTERNAL;
out:
    BPF_UNLOCK();
    return ret;
}

/* ══════════════════════════════════════════════════════════
 * Adapter 注册 (与 adapter.c 中 extern offload_adapter_t adapter_bpf 对齐)
 * ══════════════════════════════════════════════════════════ */

offload_adapter_t adapter_bpf = {
    .name             = "bpf",
    .type             = OFFLOAD_QCOM_BPF,
    .granularity      = OFFLOAD_GRAN_PER_UPSTREAM,

    .probe            = bpf_probe,
    .init             = bpf_init,
    .shutdown         = bpf_shutdown,
    .self_check       = bpf_self_check,

    .status           = bpf_status,
    .refresh_active   = bpf_refresh_active,

    .disable_global   = bpf_disable_global,
    .restore_global   = bpf_restore_global,

    .disable_upstream = bpf_disable_upstream,
    .restore_upstream = bpf_restore_upstream,

    .disable_device   = NULL,
    .restore_device   = NULL,
};
