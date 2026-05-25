/* scheduler.c — HNC v5.0 offload 调度核心实现
 *
 * 设计要点见 scheduler.h
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "scheduler.h"
#include "platform.h"
#include "upstream.h"
#include "lsm/hnc_lsm_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include <net/if.h>
#include <sys/socket.h>

/* v5.0 alpha.3: rules.json 路径 (跟 hotspotd.c 对齐, 不用 include 避免循环) */
#ifndef RULES_JSON_PATH
#define RULES_JSON_PATH "/data/local/hnc/data/rules.json"
#endif

/* ══════════════════════════════════════════════════════════
 * 内部状态
 * ══════════════════════════════════════════════════════════ */

static struct {
    int               initialized;

    /* 选中的 adapter (init 时固定, shutdown 前不变) */
    offload_adapter_t *adapter;

    /* 主调度状态 lock */
    pthread_mutex_t   lock;

    /* 受限设备 mac 集合 (小写存储, 简单线性数组)
     *   "aa:bb:cc:dd:ee:ff\0" = 18 bytes per slot
     *   256 slot * 18 = 4.5 KB, cache 友好
     *   线性 find/insert/remove O(N), 256 大小下 < 1µs
     */
    char              limited_macs[HNC_SCHED_MAX_LIMITED_DEVICES][18];
    int               limited_count;

    /* 当前主上游 (默认路由的 oif)
     * v5.0 alpha.1: 启动时探测 + 在每次 0→>0 转换时重探一次
     * v5.0 beta:    upstream.c 模块替换 (RTM_NEWROUTE 监听)
     */
    int               primary_upstream_ifindex;
    char              primary_upstream_ifname[HNC_SCHED_IFNAME_LEN];

    /* worker 线程 */
    pthread_t         worker_tid;
    int               worker_started;
    int               worker_should_stop;
    int               worker_refresh_requested;
    int64_t           worker_last_refresh_ts;
    /* refresh 完成计数 (单调递增, 测试与前端可用于"refresh 是否真的发生"
     * 的判断, 不依赖 wall clock 秒精度) */
    int64_t           worker_refresh_count;

    pthread_mutex_t   worker_lock;
    pthread_cond_t    worker_cond;
} sched = {
    .initialized              = 0,
    .adapter                  = NULL,
    .limited_count            = 0,
    .primary_upstream_ifindex = 0,
    .primary_upstream_ifname  = {0},
    .worker_started           = 0,
    .worker_should_stop       = 0,
    .worker_refresh_requested = 0,
    .worker_last_refresh_ts   = 0,
    .worker_refresh_count     = 0,
};

/* ══════════════════════════════════════════════════════════
 * 内部小工具: mac 规范化 + 集合操作
 * ══════════════════════════════════════════════════════════ */

/* 规范化 mac: 小写, 严格 17 字符 "aa:bb:cc:dd:ee:ff"
 * 输入非法 (长度不对, 含非 hex/colon) → 返 -1
 * 输出始终 NUL-terminated
 */
static int normalize_mac(const char *in, char *out)
{
    if (in == NULL) return -1;
    for (int i = 0; i < 17; i++) {
        char c = in[i];
        if (c == '\0') return -1;
        if (i % 3 == 2) {
            if (c != ':') return -1;
            out[i] = ':';
        } else {
            if (!isxdigit((unsigned char)c)) return -1;
            out[i] = (char)tolower((unsigned char)c);
        }
    }
    out[17] = '\0';
    if (in[17] != '\0' && in[17] != '\n' && in[17] != ' ') return -1;
    return 0;
}

/* 在 limited_macs 中找 mac 的索引, 找不到返 -1
 * 调用方需持 sched.lock
 */
static int limited_set_find(const char *mac)
{
    for (int i = 0; i < sched.limited_count; i++)
        if (strcmp(sched.limited_macs[i], mac) == 0) return i;
    return -1;
}

/* 添加, 已存在/集合满 → 返 -1; 成功返 新索引
 * 调用方需持 sched.lock
 */
static int limited_set_add(const char *mac)
{
    if (limited_set_find(mac) >= 0) return -1;
    if (sched.limited_count >= HNC_SCHED_MAX_LIMITED_DEVICES) {
        fprintf(stderr, "[sched] limited set full (max %d), drop %s\n",
                HNC_SCHED_MAX_LIMITED_DEVICES, mac);
        return -1;
    }
    int idx = sched.limited_count++;
    snprintf(sched.limited_macs[idx], sizeof(sched.limited_macs[idx]), "%s", mac);
    return idx;
}

/* 移除, 不存在 → 返 -1; 成功返 0
 * 调用方需持 sched.lock
 */
static int limited_set_remove(const char *mac)
{
    int idx = limited_set_find(mac);
    if (idx < 0) return -1;
    /* 末尾元素填洞 */
    int last = --sched.limited_count;
    if (idx != last)
        memcpy(sched.limited_macs[idx], sched.limited_macs[last],
               sizeof(sched.limited_macs[idx]));
    sched.limited_macs[last][0] = '\0';
    return 0;
}


/* 精确判断 JSON block 内的布尔字段是否为 true。
 * 避免旧逻辑 `strstr(block, "true")` 把 delay_enabled:true 误判为 limit_enabled:true。
 * block 必须是临时 NUL-terminated 的对象片段。
 */
static int json_bool_true_in_block(const char *block, const char *key)
{
    if (block == NULL || key == NULL) return 0;

    char needle[96];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = block;
    while ((p = strstr(p, needle)) != NULL) {
        const char *q = p + strlen(needle);
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q != ':') { p = q; continue; }
        q++;
        while (*q && isspace((unsigned char)*q)) q++;
        if (strncmp(q, "true", 4) == 0) {
            char end = q[4];
            if (end == '\0' || end == ',' || end == '}' || isspace((unsigned char)end))
                return 1;
        }
        p = q;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * v5.0 alpha.3 P0-B: 启动时从 rules.json 重建 limited_macs
 *
 * 背景:
 *   alpha.2 真机暴露: 重启后 BPF offload fast path 跳过 HNC HTB,
 *   下行限速失效, 除非手动 apply_device_rule.sh 重新触发 scheduler notify。
 *   根因: scheduler.limited_macs 在进程重启后清空, 但 BPF map 里的 limit=0
 *   被 framework 5-30s 内回写为 U64_MAX, HNC 无从感知应重新写入。
 *
 * 策略:
 *   init 末尾扫 rules.json, 找所有 "limit_enabled":true 的 MAC, 直接填 set。
 *   如果 count > 0 → 触发一次 adapter disable, 重建 BPF offload 屏蔽。
 *
 * 为什么不走 notify_device_limit_changed:
 *   - notify 会对每个 MAC 做 refresh_primary_upstream + adapter_trigger
 *   - N 个设备 N 次探测 = 浪费. 直接填 set, 最后一次 trigger
 *
 * 解析方式:
 *   复用 hotspotd.c 的 fread 整文件 + strstr 找 devices section 的手法,
 *   避开 JSON 解析库依赖. rules.json 典型 < 8KB。
 *
 * 锁语义:
 *   调用方必须未持 sched.lock (本函数内部 lock)。只在 init 末尾调用。
 * ══════════════════════════════════════════════════════════ */

static int rebuild_from_rules(void)
{
    FILE *f = fopen(RULES_JSON_PATH, "r");
    if (!f) {
        fprintf(stderr, "[sched] rebuild: rules.json not found (%s), skip\n",
                RULES_JSON_PATH);
        return 0;    /* 没配置文件 = 无限速设备, 正常场景 */
    }

    /* rc39 (P1-5): 动态读整文件。旧的 static char buf[16384] 在 rules.json >16KB
     * (~80+ 限速设备) 时截断 → brace-count 找不到 devices 结尾 → return 0 →
     * limited 集合空 → BPF offload 不被 disable → 被限速流量静默走 fast-path 绕过
     * HTB。改用 fseek/ftell 取大小后 malloc 读全量(无 sys/stat.h 依赖)。 */
    long fsz = 0;
    if (fseek(f, 0, SEEK_END) == 0) { fsz = ftell(f); rewind(f); }
    /* v5.8.8 (audit): don't trust ftell. When fseek/ftell fail (fsz<=0) the
     * old code capped at 65536 and fread truncated any rules.json >64KB — the
     * exact truncation rc39 set out to fix, just on the ftell-failure path.
     * Read with a growing buffer so the whole file is consumed regardless. */
    size_t cap = (fsz > 0) ? (size_t)fsz + 1 : 65536;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "[sched] rebuild: OOM allocating %zu bytes, skip\n", cap);
        return 0;
    }
    size_t n = 0;
    for (;;) {
        if (n + 1 >= cap) {
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) {
                free(buf);
                fclose(f);
                fprintf(stderr, "[sched] rebuild: OOM growing to %zu bytes, skip\n", ncap);
                return 0;
            }
            buf = nb;
            cap = ncap;
        }
        size_t got = fread(buf + n, 1, cap - 1 - n, f);
        n += got;
        if (got == 0) break; /* EOF or read error */
    }
    fclose(f);
    if (n == 0) { free(buf); return 0; }
    buf[n] = '\0';

    /* 定位 devices section: "devices":{...} */
    char *dev_start = strstr(buf, "\"devices\"");
    if (!dev_start) { free(buf); return 0; }
    char *obj_start = strchr(dev_start, '{');
    if (!obj_start) { free(buf); return 0; }

    /* brace-counting 找 devices 对象结尾 (跳过嵌套, 跳过字符串内 brace)
     * hostname 里可能有 '{' 或 '}', 要识别 JSON 字符串 */
    int depth = 1;
    int in_string = 0;
    int escape = 0;
    char *dev_end = NULL;
    for (char *p = obj_start + 1; *p; p++) {
        if (escape) { escape = 0; continue; }
        if (*p == '\\') { escape = 1; continue; }
        if (*p == '"') { in_string = !in_string; continue; }
        if (in_string) continue;
        if (*p == '{') depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) { dev_end = p; break; }
        }
    }
    if (!dev_end) { free(buf); return 0; }
    *dev_end = '\0';   /* 临时截断, devices 对象仅存在这范围 */

    /* 扫每个 MAC-key + 它的 block (brace-match) */
    int added = 0;
    char *p = obj_start + 1;
    while (p < dev_end) {
        /* 找下一个 "aa:bb:cc:dd:ee:ff" MAC 字符串 (作为 key) */
        char *q = strchr(p, '"');
        if (!q || q >= dev_end) break;

        /* 必须是 17 字符 MAC 格式 */
        int is_mac = 0;
        if (q + 18 < dev_end && q[3] == ':' && q[6] == ':' &&
            q[9] == ':' && q[12] == ':' && q[15] == ':' && q[18] == '"') {
            is_mac = 1;
        }

        if (!is_mac) {
            /* skip this string */
            p = strchr(q + 1, '"');
            if (!p) break;
            p++;
            continue;
        }

        char mac_raw[18];
        memcpy(mac_raw, q + 1, 17);
        mac_raw[17] = '\0';

        /* 找这个 MAC 对应的 block: 冒号后 '{...}' */
        char *block_open = strchr(q + 19, '{');
        if (!block_open) break;

        /* brace-count 找 block 结尾 */
        int d = 1, in_s = 0, esc = 0;
        char *block_end = NULL;
        for (char *r = block_open + 1; r < dev_end && *r; r++) {
            if (esc) { esc = 0; continue; }
            if (*r == '\\') { esc = 1; continue; }
            if (*r == '"') { in_s = !in_s; continue; }
            if (in_s) continue;
            if (*r == '{') d++;
            else if (*r == '}') { d--; if (d == 0) { block_end = r; break; } }
        }
        if (!block_end) break;

        /* 在 block 内精确找 "limit_enabled": true */
        char saved = *(block_end + 1);
        *(block_end + 1) = '\0';
        int has_limit = json_bool_true_in_block(block_open, "limit_enabled");
        *(block_end + 1) = saved;

        if (has_limit) {
            char norm[18];
            if (normalize_mac(mac_raw, norm) == 0) {
                pthread_mutex_lock(&sched.lock);
                if (limited_set_add(norm) >= 0) {
                    added++;
                }
                pthread_mutex_unlock(&sched.lock);
            }
        }

        p = block_end + 1;
    }

    *dev_end = '}';   /* 复位 */

    if (added > 0) {
        fprintf(stderr, "[sched] rebuild: %d limited device(s) from rules.json\n",
                added);
    } else {
        fprintf(stderr, "[sched] rebuild: no limited devices in rules.json\n");
    }
    free(buf);
    return added;
}

/* ══════════════════════════════════════════════════════════
 * 上游探测 (alpha.2: 改用 upstream.c 三层 fallback)
 *
 * alpha.1 用 /proc/net/route main table default route, 在 ColorOS 策略路由下
 * 失败 (default 在 per-iface table). alpha.2 改走 upstream_detect_primary:
 *   Tier 1: ip route get 8.8.8.8 (策略路由感知, 最可靠)
 *   Tier 2: /proc/net/route 启发式扫描 (rmnet/wwan/eth 前缀)
 *   Tier 3: (留 alpha.3) BPF upstream4_map 反查
 * ══════════════════════════════════════════════════════════ */

/* 公开 wrap, 加锁 + 缓存
 * 仅在内部触发: init / 0→>0 转换时
 */
static void refresh_primary_upstream_locked(void)
{
    int idx = 0;
    char name[HNC_SCHED_IFNAME_LEN] = {0};
    if (upstream_detect_primary(&idx, name, sizeof(name)) == 0) {
        if (idx != sched.primary_upstream_ifindex ||
            strcmp(name, sched.primary_upstream_ifname) != 0) {
            fprintf(stderr, "[sched] primary upstream: %s (ifindex=%d)\n", name, idx);
        }
        sched.primary_upstream_ifindex = idx;
        snprintf(sched.primary_upstream_ifname,
                 sizeof(sched.primary_upstream_ifname), "%s", name);
    } else {
        fprintf(stderr, "[sched] primary upstream not found (all tiers failed)\n");
        /* 注: alpha.2 不再清零 cached 值 — 如果上次探到过, 保留它.
         * 网络切换瞬态 (uplink 短暂下线) 不应该清空 scheduler 认知, 否则
         * 下次 disable_upstream 会写到 ifindex=0, 毫无意义. */
        if (sched.primary_upstream_ifindex == 0) {
            sched.primary_upstream_ifname[0] = '\0';
        }
    }
}

/* ══════════════════════════════════════════════════════════
 * Adapter 触发 helper
 *
 * 根据 adapter granularity 选合适操作:
 *   PER_UPSTREAM → disable_upstream(primary_upstream)
 *   GLOBAL       → disable_global
 *   NONE         → no-op
 *
 * 调用方需持 sched.lock (读 primary_upstream)
 * adapter 调用本身不需 lock (adapter 内部自管)
 * ══════════════════════════════════════════════════════════ */

static void trigger_adapter_disable_locked(void)
{
    if (sched.adapter == NULL) return;
    offload_adapter_t *a = sched.adapter;

    switch (a->granularity) {
    case OFFLOAD_GRAN_PER_UPSTREAM: {
        if (sched.primary_upstream_ifindex <= 0) {
            /* alpha.2: upstream 探测全部 tier 失败时, 自动降级到 global disable
             * 避免 scheduler 集合 limited_count>0 但 BPF 从未被写入的尴尬。
             * 后果: 所有 upstream 都被禁 offload (跟 global 模式等价), 但
             * 对用户来说"限速生效"比"精准限某个上游但无效"重要。
             * 主要出现在 ColorOS 5G 策略路由 + 网络瞬态切换场景。 */
            if (a->disable_global) {
                offload_err_t e = a->disable_global();
                fprintf(stderr, "[sched] no primary upstream → fallback disable_global: %s\n",
                        offload_err_str(e));
            } else {
                fprintf(stderr, "[sched] no primary upstream AND no disable_global support\n");
            }
            return;
        }
        if (a->disable_upstream == NULL) {
            fprintf(stderr, "[sched] adapter %s missing disable_upstream\n", a->name);
            return;
        }
        offload_err_t e = a->disable_upstream(sched.primary_upstream_ifindex);
        fprintf(stderr, "[sched] disable_upstream(ifindex=%d ifname=%s): %s\n",
                sched.primary_upstream_ifindex,
                sched.primary_upstream_ifname,
                offload_err_str(e));
        break;
    }
    case OFFLOAD_GRAN_GLOBAL: {
        if (a->disable_global == NULL) return;
        offload_err_t e = a->disable_global();
        fprintf(stderr, "[sched] disable_global: %s\n", offload_err_str(e));
        break;
    }
    case OFFLOAD_GRAN_NONE:
    case OFFLOAD_GRAN_PER_DEVICE:    /* alpha.1 不实现 per-device 路径 */
    default:
        break;
    }
}

static void trigger_adapter_restore_locked(void)
{
    if (sched.adapter == NULL) return;
    offload_adapter_t *a = sched.adapter;

    switch (a->granularity) {
    case OFFLOAD_GRAN_PER_UPSTREAM: {
        /* alpha.2: 对称 fallback. 如果 disable 走的是 global 降级,
         * restore 也走 global 才能解, 否则 restore_upstream(0) 毫无意义。
         * 更稳的做法: 无条件走 restore_global — 因为我们拿不准当初 disable
         * 时到底写了哪个 ifindex (或全部), 一把 restore_global 把所有 entry
         * 都设回 U64_MAX 一定是正确的。 */
        if (a->restore_global) {
            offload_err_t e = a->restore_global();
            fprintf(stderr, "[sched] restore (via global): %s\n", offload_err_str(e));
        } else if (a->restore_upstream && sched.primary_upstream_ifindex > 0) {
            offload_err_t e = a->restore_upstream(sched.primary_upstream_ifindex);
            fprintf(stderr, "[sched] restore_upstream(ifindex=%d): %s\n",
                    sched.primary_upstream_ifindex, offload_err_str(e));
        }
        break;
    }
    case OFFLOAD_GRAN_GLOBAL: {
        if (a->restore_global == NULL) return;
        offload_err_t e = a->restore_global();
        fprintf(stderr, "[sched] restore_global: %s\n", offload_err_str(e));
        break;
    }
    case OFFLOAD_GRAN_NONE:
    case OFFLOAD_GRAN_PER_DEVICE:
    default:
        break;
    }
}

/* ══════════════════════════════════════════════════════════
 * Worker 线程
 *
 * 等待 worker_cond, 任一条件唤醒:
 *   1) worker_should_stop=1 → 退出
 *   2) worker_refresh_requested=1 → 立即跑 refresh_active
 *   3) timedwait 60s 超时 → 周期 refresh
 *
 * refresh_active 阻塞 5s (sleep), 期间 worker_lock 释放,
 * 主线程仍可 request_refresh / shutdown (会在下次循环检测到)
 * ══════════════════════════════════════════════════════════ */

static void *worker_main(void *arg)
{
    (void)arg;
    fprintf(stderr, "[sched] worker started (refresh interval %ds)\n",
            HNC_SCHED_REFRESH_INTERVAL_SEC);

    while (1) {
        pthread_mutex_lock(&sched.worker_lock);

        /* timed wait until: should_stop / refresh_requested / 60s timeout */
        if (!sched.worker_should_stop && !sched.worker_refresh_requested) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += HNC_SCHED_REFRESH_INTERVAL_SEC;
            pthread_cond_timedwait(&sched.worker_cond, &sched.worker_lock, &ts);
        }

        if (sched.worker_should_stop) {
            pthread_mutex_unlock(&sched.worker_lock);
            break;
        }
        sched.worker_refresh_requested = 0;
        pthread_mutex_unlock(&sched.worker_lock);

        /* beta.3: 周期性重探 primary upstream (cold-start race fix)
         *
         * 历史 bug (beta.1 / beta.2):
         *   refresh_primary_upstream_locked() 只在 3 个时机调用:
         *     1. hnc_scheduler_init() 启动一次
         *     2. rebuild_from_rules() 当 limited_count > 0 时
         *     3. notify_device_limit_changed() 在 0->>0 转换时
         *   一旦冷启动踩到 "BPF upstream4_map 还空" 窗口 (热点刚开/客户端还
         *   没流量), Tier3/Tier4 都 fail → primary_upstream_ifindex=0 永久
         *   保持. 之后 limited_count 持续 >0 不会再触发 0->>0,worker 60s
         *   只跑 refresh_active 不重探, 系统永远停留在 "fallback disable_global"
         *   状态. 实测 RMX5010 ColorOS 16 上 init 时机比 BPF map 填充早,
         *   100% 命中此 race.
         *
         * 修复:
         *   每个 worker 周期(60s)都重探一次. 状态变化时 (探到新 upstream
         *   或上游切换) 自动 re-trigger adapter 操作,与 0->>0 路径等价.
         *   纯 BPF 反查, 性能开销 < 1ms, 无副作用. */
        pthread_mutex_lock(&sched.lock);
        int prev_ifindex = sched.primary_upstream_ifindex;
        refresh_primary_upstream_locked();
        int now_ifindex = sched.primary_upstream_ifindex;
        /* 关键: 之前没探到 (=0) 现在探到了, 且当前有限速设备 → 立即触发
         * disable. 否则即便探到上游, adapter 状态还停留在
         * "fallback disable_global", 不会切换到精准 disable_upstream. */
        int need_retrigger = (prev_ifindex == 0 && now_ifindex > 0
                              && sched.limited_count > 0);
        /* 上游切换 (e.g. WiFi 下线切 4G): 老 ifindex 还在 disabled_set
         * 里, 新 ifindex 没被 disable. 也要 retrigger. */
        if (prev_ifindex > 0 && now_ifindex > 0 && prev_ifindex != now_ifindex
            && sched.limited_count > 0) {
            need_retrigger = 1;
        }
        if (need_retrigger) {
            fprintf(stderr, "[sched] periodic re-probe: upstream %d -> %d, retriggering disable\n",
                    prev_ifindex, now_ifindex);
            trigger_adapter_disable_locked();
        }
        pthread_mutex_unlock(&sched.lock);

        /* v5.0.0-beta.4: ifindex 变化时同步通知 LSM guard
         * (LSM 内部线程安全, 在 sched.lock 之外调用避免锁嵌套) */
        if (now_ifindex > 0 && now_ifindex != prev_ifindex) {
            hnc_lsm_update_ifindex((uint32_t)now_ifindex);
        }

        /* 跑 refresh (可能 sleep 5s) */
        if (sched.adapter && sched.adapter->refresh_active) {
            offload_err_t e = sched.adapter->refresh_active();
            if (e != OFFLOAD_OK) {
                fprintf(stderr, "[sched] refresh_active: %s\n", offload_err_str(e));
            }
        }
        /* 这两个 int64 计数被 hnc_scheduler_get_summary 跨线程读 —— 在 sched.lock
         * 下更新, 配合 get_summary 的加锁读, 消除 32 位 arm 上的撕裂读. */
        pthread_mutex_lock(&sched.lock);
        sched.worker_last_refresh_ts = (int64_t)time(NULL);
        sched.worker_refresh_count++;
        pthread_mutex_unlock(&sched.lock);
    }

    fprintf(stderr, "[sched] worker stopped\n");
    return NULL;
}

/* ══════════════════════════════════════════════════════════
 * 初始化 / 关闭
 * ══════════════════════════════════════════════════════════ */

int hnc_scheduler_init(void)
{
    if (sched.initialized) return 0;

    /* 探测平台 */
    platform_probe();

    /* 选 adapter */
    sched.adapter = offload_select_adapter();
    if (sched.adapter == NULL) {
        fprintf(stderr, "[sched] FATAL: no adapter selected (not even null!)\n");
        return -1;
    }

    /* init adapter, 失败回落 null */
    offload_err_t e = sched.adapter->init();
    if (e != OFFLOAD_OK) {
        fprintf(stderr, "[sched] adapter %s init failed: %s, falling back to null\n",
                sched.adapter->name, offload_err_str(e));
        /* 找 null adapter */
        extern offload_adapter_t adapter_null;
        sched.adapter = &adapter_null;
        offload_set_active_adapter(sched.adapter);
        sched.adapter->init();   /* null 永远成功 */
    } else {
        /* schema self-check */
        if (sched.adapter->self_check) {
            offload_err_t sc = sched.adapter->self_check();
            if (sc != OFFLOAD_OK) {
                fprintf(stderr, "[sched] adapter %s self_check FAIL: %s, falling back\n",
                        sched.adapter->name, offload_err_str(sc));
                sched.adapter->shutdown();
                extern offload_adapter_t adapter_null;
                sched.adapter = &adapter_null;
                offload_set_active_adapter(sched.adapter);
                sched.adapter->init();
            }
        }
    }

    /* 初始化 lock */
    pthread_mutex_init(&sched.lock, NULL);
    pthread_mutex_init(&sched.worker_lock, NULL);
    pthread_cond_init(&sched.worker_cond, NULL);

    /* 初次探测上游 */
    pthread_mutex_lock(&sched.lock);
    refresh_primary_upstream_locked();
    pthread_mutex_unlock(&sched.lock);

    /* 启动 worker 线程 */
    sched.worker_should_stop = 0;
    sched.worker_refresh_requested = 0;
    int rc = pthread_create(&sched.worker_tid, NULL, worker_main, NULL);
    if (rc != 0) {
        fprintf(stderr, "[sched] pthread_create worker failed: %d\n", rc);
        sched.adapter->shutdown();
        return -1;
    }
    sched.worker_started = 1;

    sched.initialized = 1;
    fprintf(stderr, "[sched] init OK (adapter=%s gran=%s upstream=%s/%d)\n",
            sched.adapter->name,
            offload_gran_str(sched.adapter->granularity),
            sched.primary_upstream_ifname,
            sched.primary_upstream_ifindex);

    /* v5.0.0-beta.4: 启动 BPF LSM Limit Map Guard
     *
     * 仅当 adapter 是 BPF 类型时才有意义 (null adapter 不操作 BPF map).
     * LSM 拦截 framework 对 limit_map 的 enforce 写, 保证 disable_upstream
     * 写入的 0 值持久生效, 真正关闭 fast path.
     *
     * 任何失败都不致命, hnc_lsm_init 内部状态机自管理. */
    if (sched.adapter && strcmp(sched.adapter->name, "bpf") == 0) {
        int lsm_rc = hnc_lsm_init(
            "/data/local/hnc/bpf/hnc_limit_map_guard.bpf.o",
            "/sys/fs/bpf/tethering/map_offload_tether_limit_map",
            (uint32_t)sched.primary_upstream_ifindex);
        if (lsm_rc == 0) {
            fprintf(stderr, "[sched] BPF LSM guard ACTIVE\n");
        } else if (lsm_rc == -2) {
            fprintf(stderr, "[sched] BPF LSM guard DISABLED (kernel/securityfs unavailable)\n");
        } else {
            fprintf(stderr, "[sched] BPF LSM guard FAILED, fallback to passive disable\n");
        }
    }

    /* v5.0 alpha.3 P0-B: 从 rules.json 重建 limited_macs
     * 如果有限速设备, 触发一次 adapter disable, 重建 BPF offload 屏蔽
     * 这样重启后不需要手动 apply_device_rule.sh, 限速自动恢复 */
    int rebuilt = rebuild_from_rules();
    if (rebuilt > 0) {
        pthread_mutex_lock(&sched.lock);
        /* 0 → >0 转换等价: 重新探测上游 + trigger disable
         * (notify 路径一致, 避免重复代码) */
        refresh_primary_upstream_locked();
        trigger_adapter_disable_locked();
        pthread_mutex_unlock(&sched.lock);
        fprintf(stderr, "[sched] rebuild: triggered adapter disable (count=%d upstream=%s/%d)\n",
                rebuilt,
                sched.primary_upstream_ifname,
                sched.primary_upstream_ifindex);
    }

    return 0;
}

void hnc_scheduler_shutdown(void)
{
    if (!sched.initialized) return;

    /* 停 worker */
    if (sched.worker_started) {
        pthread_mutex_lock(&sched.worker_lock);
        sched.worker_should_stop = 1;
        pthread_cond_signal(&sched.worker_cond);
        pthread_mutex_unlock(&sched.worker_lock);
        pthread_join(sched.worker_tid, NULL);
        sched.worker_started = 0;
    }

    /* shutdown adapter */
    if (sched.adapter && sched.adapter->shutdown) {
        sched.adapter->shutdown();
    }

    /* v5.0.0-beta.4: 关闭 BPF LSM guard */
    hnc_lsm_shutdown();

    pthread_mutex_destroy(&sched.lock);
    pthread_mutex_destroy(&sched.worker_lock);
    pthread_cond_destroy(&sched.worker_cond);

    sched.initialized = 0;
    fprintf(stderr, "[sched] shutdown done\n");
}

/* ══════════════════════════════════════════════════════════
 * Notify
 * ══════════════════════════════════════════════════════════ */

void hnc_scheduler_notify_device_limit_changed(const char *mac, int is_limited)
{
    if (!sched.initialized) return;

    char norm[18];
    if (normalize_mac(mac, norm) != 0) {
        fprintf(stderr, "[sched] notify: invalid mac '%s'\n", mac ? mac : "(null)");
        return;
    }

    int old_count, new_count;
    int triggered_disable = 0, triggered_restore = 0;

    pthread_mutex_lock(&sched.lock);
    old_count = sched.limited_count;

    if (is_limited) {
        limited_set_add(norm);    /* 已存在则 noop */
    } else {
        limited_set_remove(norm); /* 不存在则 noop */
    }
    new_count = sched.limited_count;

    /* 状态机: 0 → >0 / >0 → 0 */
    if (old_count == 0 && new_count > 0) {
        /* 重新探测上游 (上次可能是冷启时, 上游可能已切换) */
        refresh_primary_upstream_locked();
        triggered_disable = 1;
    } else if (old_count > 0 && new_count == 0) {
        triggered_restore = 1;
    }

    /* 注: trigger_* 内部不再读 limited_count, 只读 primary_upstream
     * 与 adapter 状态。adapter 操作本身已是线程安全 (file-static lock free)
     * 所以可以在持 sched.lock 时调 (调用 < 1ms 不会成为瓶颈) */
    if (triggered_disable)  trigger_adapter_disable_locked();
    if (triggered_restore)  trigger_adapter_restore_locked();

    pthread_mutex_unlock(&sched.lock);

    if (triggered_disable || triggered_restore) {
        /* 状态变化后请求 worker 立即 refresh, 让 active 状态尽快反映 */
        hnc_scheduler_request_refresh();
    }
}

void hnc_scheduler_request_refresh(void)
{
    if (!sched.initialized || !sched.worker_started) return;
    pthread_mutex_lock(&sched.worker_lock);
    sched.worker_refresh_requested = 1;
    pthread_cond_signal(&sched.worker_cond);
    pthread_mutex_unlock(&sched.worker_lock);
}

/* ══════════════════════════════════════════════════════════
 * 强制操作 (control 命令直接驱动)
 * ══════════════════════════════════════════════════════════ */

offload_err_t hnc_scheduler_force_disable_global(void)
{
    if (!sched.initialized || sched.adapter == NULL) return OFFLOAD_EINTERNAL;
    if (sched.adapter->disable_global == NULL)       return OFFLOAD_ENOTSUP;
    return sched.adapter->disable_global();
}

offload_err_t hnc_scheduler_force_restore_global(void)
{
    if (!sched.initialized || sched.adapter == NULL) return OFFLOAD_EINTERNAL;
    if (sched.adapter->restore_global == NULL)       return OFFLOAD_ENOTSUP;

    pthread_mutex_lock(&sched.lock);
    sched.limited_count = 0;     /* 强制 restore 隐含清空集合 */
    pthread_mutex_unlock(&sched.lock);

    return sched.adapter->restore_global();
}

/* ══════════════════════════════════════════════════════════
 * 查询
 * ══════════════════════════════════════════════════════════ */

void hnc_scheduler_get_summary(hnc_offload_summary_t *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));

    if (!sched.initialized || sched.adapter == NULL) {
        snprintf(out->adapter_name, sizeof(out->adapter_name), "uninitialized");
        return;
    }

    /* Adapter 元 + 状态 (lock-free) */
    snprintf(out->adapter_name, sizeof(out->adapter_name),
             "%s", sched.adapter->name);
    out->adapter_type = (int)sched.adapter->type;
    out->adapter_gran = (int)sched.adapter->granularity;

    offload_status_t st;
    memset(&st, 0, sizeof(st));
    if (sched.adapter->status) sched.adapter->status(&st);

    out->active                  = st.active;
    out->last_refresh_ts         = st.last_refresh_ts;
    out->last_delta_bytes        = st.last_delta_bytes;
    out->globally_disabled       = st.globally_disabled;
    out->disabled_upstream_count = st.disabled_upstream_count;
    int n = st.disabled_upstream_count;
    int cap = (int)(sizeof(out->disabled_upstream_ifindex) /
                    sizeof(out->disabled_upstream_ifindex[0]));
    if (n > cap) n = cap;
    for (int i = 0; i < n; i++)
        out->disabled_upstream_ifindex[i] = st.disabled_upstream_ifindex[i];

    /* Scheduler 内部 (加锁) */
    pthread_mutex_lock(&sched.lock);
    out->limited_device_count    = sched.limited_count;
    out->primary_upstream_ifindex = sched.primary_upstream_ifindex;
    snprintf(out->primary_upstream_ifname,
             sizeof(out->primary_upstream_ifname),
             "%s", sched.primary_upstream_ifname);
    out->worker_running          = sched.worker_started;
    out->worker_last_refresh_ts  = sched.worker_last_refresh_ts;
    out->worker_refresh_count    = sched.worker_refresh_count;
    pthread_mutex_unlock(&sched.lock);
}

int hnc_scheduler_summary_to_json(const hnc_offload_summary_t *s,
                                   char *buf, size_t buf_size)
{
    if (s == NULL || buf == NULL || buf_size == 0) return -1;

    /* disabled_upstream_ifindex JSON 数组 */
    char dis_arr[128] = "[]";
    if (s->disabled_upstream_count > 0) {
        char *p = dis_arr;
        char *end = dis_arr + sizeof(dis_arr);
        int written = snprintf(p, (size_t)(end - p), "[");
        if (written < 0 || written >= (end - p)) goto trunc;
        p += written;
        for (int i = 0; i < s->disabled_upstream_count && p < end; i++) {
            written = snprintf(p, (size_t)(end - p), "%s%d",
                               i ? "," : "",
                               s->disabled_upstream_ifindex[i]);
            if (written < 0 || written >= (end - p)) goto trunc;
            p += written;
        }
        if (p < end) snprintf(p, (size_t)(end - p), "]");
    }
    goto ok;
trunc:
    snprintf(dis_arr, sizeof(dis_arr), "[]");
ok:
    /* clang 默认 -std=c11 下 "label followed by declaration" 是 C23 扩展,
     * 加一个空语句让标签后跟语句而非声明 */
    (void)0;

    int n = snprintf(buf, buf_size,
        "{"
        "\"adapter\":{\"name\":\"%s\",\"type\":%d,\"granularity\":%d},"
        "\"active\":%s,"
        "\"last_refresh_ts\":%lld,"
        "\"last_delta_bytes\":%llu,"
        "\"globally_disabled\":%s,"
        "\"disabled_upstream_count\":%d,"
        "\"disabled_upstream_ifindex\":%s,"
        "\"limited_device_count\":%d,"
        "\"primary_upstream_ifindex\":%d,"
        "\"primary_upstream_ifname\":\"%s\","
        "\"worker_running\":%s,"
        "\"worker_last_refresh_ts\":%lld,"
        "\"worker_refresh_count\":%lld,",
        s->adapter_name,
        s->adapter_type,
        s->adapter_gran,
        s->active ? "true" : "false",
        (long long)s->last_refresh_ts,
        (unsigned long long)s->last_delta_bytes,
        s->globally_disabled ? "true" : "false",
        s->disabled_upstream_count,
        dis_arr,
        s->limited_device_count,
        s->primary_upstream_ifindex,
        s->primary_upstream_ifname,
        s->worker_running ? "true" : "false",
        (long long)s->worker_last_refresh_ts,
        (long long)s->worker_refresh_count
    );
    if (n < 0 || (size_t)n >= buf_size) return -1;

    /* v5.0.0-beta.4: 追加 LSM 状态片段 */
    hnc_lsm_status_t lsm_st;
    hnc_lsm_get_status(&lsm_st);
    int n2 = hnc_lsm_status_to_json_fragment(&lsm_st, buf + n, buf_size - n);
    if (n2 < 0) {
        /* 截断: 至少回滚最后逗号 */
        if (n > 0 && buf[n - 1] == ',') buf[n - 1] = '\0';
        n = (int)strlen(buf);
    } else {
        n += n2;
    }

    /* 闭合 } */
    if ((size_t)n + 2 >= buf_size) return -1;
    buf[n++] = '}';
    buf[n] = '\0';

    return n;
}
