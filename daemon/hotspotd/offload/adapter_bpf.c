/* offload/adapter_bpf.c — 高通 + AOSP BPF tethering offload adapter
 *
 * 平台覆盖:
 *   - 高通 SDM/SM 系列 + Android 11+ (AOSP BPF tethering)
 *   - 任何"标准 AOSP BPF tethering"的 ROM 实现 (ColorOS/HyperOS/PixelOS/...)
 *
 * 不覆盖:
 *   - MTK PPE        (走 adapter_ppe, v5.1)
 *   - 三星 NSS       (走 adapter_nss, v5.2)
 *   - 华为 HiNAT     (待研究)
 *
 * v5.0 alpha.1 实现范围: PER_UPSTREAM 粒度
 *   - disable_upstream(ifindex)  → limit_map[ifindex] = 0
 *   - restore_upstream(ifindex)  → limit_map[ifindex] = U64_MAX
 *   - disable_global / restore_global  遍历所有 entry
 *   - refresh_active             5s 双采样 stats_map, 总流量 >1MB 视为 active
 *
 * v5.x 计划: PER_DEVICE 粒度
 *   - 监听 conntrack NEW 事件
 *   - 删 downstream4/6_map 里目标 IP=被限速设备的 entry
 *   - 强制流量回落 slow path, tc HTB 接管
 *
 * 关键 BPF map 路径 (Android 11+ 稳定, 跨厂):
 *   /sys/fs/bpf/tethering/map_offload_tether_limit_map
 *       schema: u32 (upstream ifindex) → u64 (byte quota)
 *       U64_MAX = 无限额度 (offload 主路径)
 *       0       = 无额度 → BPF 程序返回 TC_ACT_PIPE → tc 接管
 *
 *   /sys/fs/bpf/tethering/map_offload_tether_stats_map
 *       schema: u32 (upstream ifindex) → TetherStatsValue (48 bytes)
 *       struct TetherStatsValue {
 *           u64 rxPackets, rxBytes, rxErrors;
 *           u64 txPackets, txBytes, txErrors;
 *       };
 *
 *   /sys/fs/bpf/tethering/map_offload_tether_error_map
 *       schema: u32 (error code) → u64 (count)
 *       (诊断用, 可选)
 *
 * 真机已验 (RMX5010, SD8 Elite, ColorOS 16, Android 16, kernel 6.6.102):
 *   - bpf_obj_get(limit_map) 在 KSU su context 下成功
 *   - bpf_map_update_elem 写 limit=0 持稳, framework 不立即回写
 *   - 100 次高频写入测试无 race
 *   - 见 HNC v4.x BPF/IPA 研究档案
 *
 * 错误处理策略:
 *   - syscall 返回 -1 → 按 errno 映射到 OFFLOAD_E* (EPERM/EACCES → EPERM,
 *     ENOENT → ENOENT, 其他 → EINTERNAL)
 *   - fd 缓存失效自愈: lookup/update 失败 errno=EBADF 时, 重新 obj_get 一次
 *   - 任何写操作失败 → log + 返错, 不假装成功
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

/* ══════════════════════════════════════════════════════════
 * bpf() syscall wrapper
 *
 * Android NDK 不带 libbpf, 直接走 syscall(__NR_bpf, ...)
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

static inline long sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* 打开 pinned map → fd (失败返 -1, 设 errno) */
static int bpf_obj_get(const char *pathname)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)pathname;
    long fd = sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    return (int)fd;
}

/* lookup_elem (失败 -1, errno) */
static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = (uint64_t)(uintptr_t)key;
    attr.value  = (uint64_t)(uintptr_t)value;
    return (int)sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* update_elem (失败 -1, errno) */
static int bpf_map_update_elem(int fd, const void *key, const void *value,
                                uint64_t flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = (uint64_t)(uintptr_t)key;
    attr.value  = (uint64_t)(uintptr_t)value;
    attr.flags  = flags;
    return (int)sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/* get_next_key — 用于遍历 map
 *   first call: key=NULL → 拿第一个 key 到 next_key
 *   后续:       key=current → 拿下一个 key 到 next_key
 *   返 -1 errno=ENOENT 表示遍历结束
 */
static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd   = (uint32_t)fd;
    attr.key      = (uint64_t)(uintptr_t)key;
    attr.next_key = (uint64_t)(uintptr_t)next_key;
    return (int)sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

/* obj_get_info_by_fd — 用于 self_check 验证 schema */
static int bpf_obj_get_info_by_fd(int fd, void *info, uint32_t *info_len)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd   = (uint32_t)fd;
    attr.info.info_len = *info_len;
    attr.info.info     = (uint64_t)(uintptr_t)info;
    int rc = (int)sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    *info_len = attr.info.info_len;
    return rc;
}

/* errno → offload_err_t */
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
 * Map 路径 (Android 11+ 稳定)
 * ══════════════════════════════════════════════════════════ */

#define BPF_LIMIT_MAP   "/sys/fs/bpf/tethering/map_offload_tether_limit_map"
#define BPF_STATS_MAP   "/sys/fs/bpf/tethering/map_offload_tether_stats_map"
#define BPF_ERROR_MAP   "/sys/fs/bpf/tethering/map_offload_tether_error_map"

/* TetherStatsValue 与 AOSP packages/modules/Connectivity/Tethering/
 * bpf_progs/offload.h 对齐 (48 bytes, 6 个 u64) */
typedef struct {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
} tether_stats_t;

#define BPF_LIMIT_NONE  ((uint64_t)0xFFFFFFFFFFFFFFFFULL)   /* U64_MAX = 无限额度 */
#define BPF_LIMIT_ZERO  ((uint64_t)0)                        /* 触发 fallback */

#define ACTIVE_THRESHOLD_BYTES  (1ULL * 1024 * 1024)         /* 1 MB / 5s = active */
#define ACTIVE_SAMPLE_INTERVAL  5                             /* 秒 */

/* rc43 (P2-15): 8 → 32。原来 8 个上游同时被禁(多 SIM+VPN+5G+WiFi 齐探)时,
 * 第 9 个会写进 BPF map 但本地集合丢记录 → status() 少报一项。真正的 disable/restore
 * 都直接遍历 BPF limit_map、不依赖本地集合,所以这只是显示瑕疵;把上限抬到 32(=128B,
 * 任何现实场景都用不满)实际消除溢出,比加 disable_global 兜底更简单、零递归风险。 */
#define MAX_DISABLED_UPSTREAMS  32

/* ══════════════════════════════════════════════════════════
 * Adapter 状态 (file-static, 与 hotspotd.c 风格一致)
 * ══════════════════════════════════════════════════════════ */

static struct {
    int initialized;

    /* 缓存的 map fd, -1 = 未打开 */
    int fd_limit;
    int fd_stats;
    int fd_error;

    /* refresh_active 缓存 */
    int      cached_active;
    int64_t  cached_refresh_ts;
    uint64_t cached_delta_bytes;
    uint64_t cached_last_total;        /* 上次采样的 rx+tx 总和, 0 = 未采过 */

    /* 已 disable 的 upstream ifindex 列表
     * 排序无关, 用于 status() 输出和 restore_global 的反向操作 */
    int disabled_upstream_ifindex[MAX_DISABLED_UPSTREAMS];
    int disabled_upstream_count;

    /* global disable 是否生效 */
    int globally_disabled;
} s = {
    .initialized        = 0,
    .fd_limit           = -1,
    .fd_stats           = -1,
    .fd_error           = -1,
    .cached_active      = 0,
    .cached_refresh_ts  = 0,
    .cached_delta_bytes = 0,
    .cached_last_total  = 0,
    .disabled_upstream_count = 0,
    .globally_disabled  = 0,
};

/* v5.1.0-rc1 hotfix: adapter 状态 s 和缓存 fd 可能被 scheduler worker、
 * status API、shutdown 路径并发访问,必须统一加锁。
 */
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
#define BPF_LOCK()   pthread_mutex_lock(&s_lock)
#define BPF_UNLOCK() pthread_mutex_unlock(&s_lock)

/* ══════════════════════════════════════════════════════════
 * fd 自愈: 打开 / 重新打开
 * ══════════════════════════════════════════════════════════ */

static int reopen_fd(int *fd, const char *path)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
    int new_fd = bpf_obj_get(path);
    if (new_fd < 0) {
        fprintf(stderr, "[bpf] obj_get failed: %s (errno=%d %s)\n",
                path, errno, strerror(errno));
        return -1;
    }
    *fd = new_fd;
    return 0;
}

/* 确保 limit_map fd 可用; 若失效自动重开 */
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

/* ══════════════════════════════════════════════════════════
 * 内部小工具: 已 disable 集合管理
 * ══════════════════════════════════════════════════════════ */

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
            /* 末尾元素填洞 */
            s.disabled_upstream_ifindex[i] =
                s.disabled_upstream_ifindex[--s.disabled_upstream_count];
            return;
        }
    }
}

/* ══════════════════════════════════════════════════════════
 * stats_map 累计读取
 *
 * 遍历所有 entry, 累加 rxBytes + txBytes, 返回总和。
 * 失败返 0 (调用方需用 last_total != 0 判断是否首次采样)
 * ══════════════════════════════════════════════════════════ */

static uint64_t stats_total_bytes(void)
{
    if (ensure_stats_fd() != 0) return 0;

    uint32_t key = 0, next_key = 0;
    uint64_t total = 0;
    int rc;
    int has_prev = 0;

    while (1) {
        rc = bpf_map_get_next_key(s.fd_stats,
                                  has_prev ? &key : NULL,
                                  &next_key);
        if (rc != 0) {
            if (errno == ENOENT) break;       /* 遍历结束 */
            fprintf(stderr, "[bpf] stats get_next_key errno=%d\n", errno);
            break;
        }

        tether_stats_t v;
        memset(&v, 0, sizeof(v));
        if (bpf_map_lookup_elem(s.fd_stats, &next_key, &v) == 0) {
            total += v.rx_bytes + v.tx_bytes;
        }
        /* 即使 lookup 失败也要继续遍历, 不卡死 */

        key = next_key;
        has_prev = 1;
    }
    return total;
}

/* ══════════════════════════════════════════════════════════
 * Adapter 接口实现
 * ══════════════════════════════════════════════════════════ */

static int bpf_probe(void)
{
    /* 文件存在即匹配; 真正的 bpf_syscall_ok 由 platform_probe 测过,
     * 这里再独立测一次确保 adapter 自己可达 */
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
        /* stats fd 失败不致命, refresh_active 会再试 */
        fprintf(stderr, "[bpf] init: stats_map open failed, will retry on refresh\n");
    }
    /* error_map 是 nice-to-have, init 时不强制 */
    s.fd_error = bpf_obj_get(BPF_ERROR_MAP);
    /* fd_error < 0 也 OK, status 不强依赖 */

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

/* self_check: 验证 limit_map schema 与编译期假设一致
 * key_size = 4 (u32 ifindex), value_size = 8 (u64 quota)
 * 万一未来 Connectivity APEX 改 schema, 这里报错让 scheduler 回落 null
 */
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
    memset(&info, 0, sizeof(info));
    uint32_t info_len = sizeof(info);

    if (bpf_obj_get_info_by_fd(s.fd_limit, &info, &info_len) != 0) {
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

    out->disabled_upstream_count = s.disabled_upstream_count;
    int n = s.disabled_upstream_count;
    int cap = (int)(sizeof(out->disabled_upstream_ifindex) /
                    sizeof(out->disabled_upstream_ifindex[0]));
    if (n > cap) n = cap;
    for (int i = 0; i < n; i++)
        out->disabled_upstream_ifindex[i] = s.disabled_upstream_ifindex[i];
    BPF_UNLOCK();
}

/* refresh_active: 5s 双采样 stats_map
 *
 * 阻塞 ACTIVE_SAMPLE_INTERVAL 秒 (sleep), 调用方应该在专门的 worker
 * 线程或定时器里跑, 不要在主循环。
 *
 * 算法:
 *   first_call: 采样 → 缓存 → 不判定 (active 字段保持原值 0)
 *   后续:       采样 → delta = total - cached_last_total
 *               delta >= 1MB → active=1, 否则 active=0
 *               缓存 total
 */
static offload_err_t bpf_refresh_active(void)
{
    BPF_LOCK();
    uint64_t t1 = stats_total_bytes();
    if (t1 == 0 && s.fd_stats < 0) {
        /* stats_map 不可用 */
        s.cached_active = 0;
        BPF_UNLOCK();
        return OFFLOAD_ENOENT;
    }
    BPF_UNLOCK();

    sleep(ACTIVE_SAMPLE_INTERVAL);

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

/* disable_upstream: limit_map[ifindex] = 0 → BPF 程序回落 slow path
 *
 * 行为:
 *   - 首先尝试 BPF_EXIST (仅当 entry 已存在时更新)
 *   - 若 entry 不存在 (errno=ENOENT, framework 还没创建), 用 BPF_ANY 创建
 *     这适配热点上游刚切换的瞬态 race
 *   - 写成功 → 加入 disabled_set, 后续 status() 反映
 */
static offload_err_t bpf_disable_upstream(int ifindex)
{
    offload_err_t ret = OFFLOAD_OK;
    if (ifindex <= 0) return OFFLOAD_EINVAL;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t key = (uint32_t)ifindex;
    uint64_t val = BPF_LIMIT_ZERO;

    /* 先 BPF_EXIST (常见路径) */
    if (bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
        disabled_set_add(ifindex);
        ret = OFFLOAD_OK;
        goto out;
    }

    int e1 = errno;
    if (e1 == EBADF) {
        /* fd 失效自愈 */
        if (reopen_fd(&s.fd_limit, BPF_LIMIT_MAP) != 0) {
            ret = errno_to_offload(errno);
            goto out;
        }
        if (bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
            disabled_set_add(ifindex);
            ret = OFFLOAD_OK;
            goto out;
        }
        e1 = errno;
    }

    if (e1 == ENOENT) {
        /* entry 不存在, 创建 */
        if (bpf_map_update_elem(s.fd_limit, &key, &val, BPF_ANY) == 0) {
            disabled_set_add(ifindex);
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

    if (bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
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
        if (bpf_map_update_elem(s.fd_limit, &key, &val, BPF_EXIST) == 0) {
            disabled_set_remove(ifindex);
            ret = OFFLOAD_OK;
            goto out;
        }
        e = errno;
    }

    if (e == ENOENT) {
        /* entry 不在, 那本来就没 disable 状态, 当作成功 */
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

/* disable_global: 遍历 limit_map 所有 entry, 全写 0
 *
 * 用于 mode=force_disable 或调度器决定彻底关 offload。
 * 遍历期间 framework 可能新增 entry (上游切换), 这是 race, 由后续
 * scheduler health check 负责重新扫描兜底, 这里不做循环重试。
 */
static offload_err_t bpf_disable_global(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t key = 0, next_key = 0;
    uint64_t val = BPF_LIMIT_ZERO;
    int has_prev = 0;
    int touched = 0;
    int errs = 0;
    int iter_errno = 0;

    while (1) {
        int rc = bpf_map_get_next_key(s.fd_limit,
                                       has_prev ? &key : NULL,
                                       &next_key);
        if (rc != 0) {
            if (errno == ENOENT) break;
            iter_errno = errno;
            errs++;
            fprintf(stderr, "[bpf] disable_global get_next_key errno=%d\n", iter_errno);
            break;
        }

        if (bpf_map_update_elem(s.fd_limit, &next_key, &val, BPF_EXIST) == 0) {
            disabled_set_add((int)next_key);
            touched++;
        } else {
            errs++;
            fprintf(stderr, "[bpf] disable_global update ifindex=%u errno=%d\n",
                    next_key, errno);
        }

        key = next_key;
        has_prev = 1;
    }

    s.globally_disabled = (touched > 0 && errs == 0) ? 1 : s.globally_disabled;
    fprintf(stderr, "[bpf] disable_global: touched=%d errs=%d\n", touched, errs);

    if (errs == 0)                  ret = OFFLOAD_OK;
    else if (iter_errno != 0 && touched == 0) ret = errno_to_offload(iter_errno);
    else if (touched > 0)           ret = OFFLOAD_OK;       /* 部分成功 */
    else                            ret = OFFLOAD_EINTERNAL;
out:
    BPF_UNLOCK();
    return ret;
}

static offload_err_t bpf_restore_global(void)
{
    offload_err_t ret = OFFLOAD_OK;
    BPF_LOCK();
    if (ensure_limit_fd() != 0) { ret = errno_to_offload(errno); goto out; }

    uint32_t key = 0, next_key = 0;
    uint64_t val = BPF_LIMIT_NONE;
    int has_prev = 0;
    int touched = 0;
    int errs = 0;
    int iter_errno = 0;

    while (1) {
        int rc = bpf_map_get_next_key(s.fd_limit,
                                       has_prev ? &key : NULL,
                                       &next_key);
        if (rc != 0) {
            if (errno == ENOENT) break;
            iter_errno = errno;
            errs++;
            fprintf(stderr, "[bpf] restore_global get_next_key errno=%d\n", iter_errno);
            break;
        }

        if (bpf_map_update_elem(s.fd_limit, &next_key, &val, BPF_EXIST) == 0) {
            disabled_set_remove((int)next_key);
            touched++;
        } else {
            errs++;
            fprintf(stderr, "[bpf] restore_global update ifindex=%u errno=%d\n",
                    next_key, errno);
        }

        key = next_key;
        has_prev = 1;
    }

    if (errs == 0) {
        s.globally_disabled = 0;
        s.disabled_upstream_count = 0;       /* 整体复位, 跟实际状态对齐 */
    }
    fprintf(stderr, "[bpf] restore_global: touched=%d errs=%d\n", touched, errs);

    if (errs == 0)                  ret = OFFLOAD_OK;
    else if (iter_errno != 0 && touched == 0) ret = errno_to_offload(iter_errno);
    else if (touched > 0)           ret = OFFLOAD_OK;
    else                            ret = OFFLOAD_EINTERNAL;
out:
    BPF_UNLOCK();
    return ret;
}

/* ══════════════════════════════════════════════════════════
 * Adapter 注册
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

    /* PER_DEVICE 留 v5.x */
    .disable_device   = NULL,
    .restore_device   = NULL,
};
