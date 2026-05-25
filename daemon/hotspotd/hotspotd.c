/*
 * hotspotd.c — HNC 事件驱动设备监控 C daemon
 *
 * 架构：
 *   - 单进程 select() 事件循环（无线程，无 malloc 泄漏）
 *   - Netlink RTGRP_NEIGH 监听 ARP/邻居表变化（RTM_NEWNEIGH / RTM_DELNEIGH）
 *   - UNIX socket 提供 IPC（GET_DEVICES / REFRESH / STATUS / QUIT）
 *   - SIGUSR1 触发立即 ARP 补充扫描（device_detect.sh scan 兼容接口）
 *   - 原子写 devices.json（tmp + rename），保持与原 shell 逻辑完全兼容
 *
 * 与原项目的关系：
 *   - 完全替换 device_detect.sh daemon 模式的轮询循环
 *   - 输出同样的 /data/local/hnc/data/devices.json 格式
 *   - 若二进制不存在，service.sh 自动退回原 shell daemon（向下兼容）
 *
 * 编译：见 daemon/build.sh 和 daemon/Android.mk
 *
 * SPDX-License-Identifier: GPL-2.0
 */

/* v3.7.2: _GNU_SOURCE 用于 strcasestr (在 try_ns_dhcp_resolve 中) */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* hotfix10 C1: strcasecmp */
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>  /* v3.7.2: waitpid */
#include <sys/time.h>  /* v3.7.2: gettimeofday for 500ms timeout */

#include <arpa/inet.h>
#include <net/if.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/if_arp.h>

/* v3.6 Commit 2: 共享 helpers(should_re_resolve, json_escape,
 * lookup_manual_name, mac_fallback, resolve_hostname_fast)。
 * 之前这些函数在 hotspotd.c 里 static 实现 + test_hostname_helpers.c 里复制,
 * 现在主代码和测试都 #include 同一个头文件,link 同一个 hnc_helpers.o,
 * 彻底消除复制 drift。 */
#include "hnc_helpers.h"
#include "hostname_cache.h"  /* v3.8.1: DHCP/mDNS hostname 持久化 cache */
#include "oui_override.h"    /* v3.8.3 D3: 用户 OUI 覆盖 */
#include "mdns_worker.h"     /* v3.8.4: 异步 mDNS worker (re-resolve 路径) */
#include "platform.h"        /* v5.0: SoC/ROM/offload 探测 */
#include "scheduler.h"       /* v5.0: offload 调度核心 */

/* 兼容性宏：部分 libc/内核头文件版本不导出 NDM_RTA/NDM_PAYLOAD */
#ifndef NDM_RTA
#  define NDM_RTA(r)    ((struct rtattr *)(((char *)(r)) +                          NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDM_PAYLOAD
#  define NDM_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

/* ── 路径常量 ──────────────────────────────────────────────── */
#define HNC_DIR             "/data/local/hnc"
#define SOCK_PATH           HNC_DIR "/run/hotspotd.sock"
#define DEVICES_JSON        HNC_DIR "/data/devices.json"
/* v3.5.2 P0-A 修复:tmp 路径带 PID 后缀,避免跟 shell daemon 路径
 * (bin/device_detect.sh do_scan_shell 用 devices.json.tmp)的字节级冲突。
 * 虽然 P0-A 主线修复已经让 C daemon 和 shell daemon 不同时运行,这是纵深防御。 */
#define DEVICES_TMP_FMT     HNC_DIR "/data/devices.json.tmp.%d"
#define LOG_FILE            HNC_DIR "/logs/hotspotd.log"
#define PID_FILE            HNC_DIR "/run/hotspotd.pid"
#define ARP_PROC            "/proc/net/arp"
#define RULES_JSON          HNC_DIR "/data/rules.json"
#define DEVICE_NAMES_JSON   HNC_DIR "/data/device_names.json"   /* v3.5.0 P0-4 */
#define HOSTNAME_CACHE_JSON HNC_DIR "/data/hostname_cache.json" /* v3.8.1 A3 */
#define OUI_OVERRIDE_JSON   HNC_DIR "/data/oui_overrides.json"  /* v3.8.3 D3 */
#define MDNS_RESOLVE_BIN    HNC_DIR "/bin/mdns_resolve"         /* v3.5.0 P0-4 */
#define IPTABLES_MGR        HNC_DIR "/bin/iptables_manager.sh"  /* v3.5.1 P1-2 */

/* ── 设备表 ──────────────────────────────────────────────── */
#define MAX_DEVICES     128
#define MAC_STR_LEN     18      /* "aa:bb:cc:dd:ee:ff\0" */
#define IP_STR_LEN      16      /* "255.255.255.255\0" */
#define HN_LEN          64
#define IF_LEN          16
#define HN_SRC_LEN      12      /* "manual\0" "mdns\0" "dhcp\0" "arp\0" "mac\0" */

/* ARP 条目有效状态：NUD_REACHABLE | NUD_STALE | NUD_DELAY |
 *                    NUD_PROBE | NUD_PERMANENT | NUD_NOARP  */
#define NUD_VALID  (NUD_REACHABLE | NUD_STALE | NUD_DELAY | \
                    NUD_PROBE | NUD_PERMANENT | NUD_NOARP)

typedef struct {
    char    mac[MAC_STR_LEN];
    char    ip[IP_STR_LEN];
    char    hostname[HN_LEN];
    char    hostname_src[HN_SRC_LEN];   /* v3.5.0 P1-8: 跟 shell 路径对齐 */
    char    iface[IF_LEN];
    long    rx_bytes;
    long    tx_bytes;
    time_t  last_seen;
    time_t  last_resolve;               /* v3.5.0-rc R-2: 上次 resolve_hostname 时间,用于改名场景的 60s 时间窗口 re-resolve */
    time_t  pending_since;              /* v3.6 Commit 3: 挂 pending 状态的时间点,process_pending_mdns 读 */
    int     active;
    int     state;      /* NUD_* from netlink */
} Device;

static Device   g_devs[MAX_DEVICES];
static int      g_ndev = 0;          /* active device count */
static time_t   g_last_write = 0;    /* last devices.json write (wall-clock, legacy) */
static time_t   g_last_event = 0;    /* v3.5.0-rc R-1: last netlink event time, for de-bounce (legacy seconds) */
static int      g_dirty = 0;         /* device table changed since last write */

/* v3.9 / rc30.9: millisecond-precision counterparts for sub-second de-bounce.
 *
 * The original (time_t) precision is 1s, which made the smallest possible
 * de-bounce window 1 second — that became the floor on perceived device-join
 * latency. To compress the floor to ~200ms we keep parallel monotonic-clock
 * milliseconds versions, populated wherever the seconds versions are.
 *
 * Why parallel (not replacing): keeping the legacy variables avoids touching
 * other code paths that compare to time(NULL) for unrelated reasons.
 *
 * Why CLOCK_MONOTONIC: immune to wall-clock jumps (NTP, suspend/resume,
 * user changing time) which could otherwise hang de-bounce or fire write
 * storms.
 */
static long g_last_write_ms = 0;  /* monotonic ms */
static long g_last_event_ms = 0;  /* monotonic ms */
static long g_dirty_first_ms = 0; /* monotonic ms; reset to 0 after each write */

/* ── 全局 fd ──────────────────────────────────────────────── */
static int  g_nl_fd   = -1;   /* netlink socket */
static int  g_srv_fd  = -1;   /* UNIX socket server */
static FILE *g_log    = NULL;

/* ── 信号标志（volatile sig_atomic_t 保证信号安全）────────── */
static volatile sig_atomic_t g_need_scan   = 1;  /* 1=需要立即补充扫描 */
static volatile sig_atomic_t g_running     = 1;  /* 0=退出主循环 */

/* ══════════════════════════════════════════════════════════
   日志
══════════════════════════════════════════════════════════ */
static void hlog(const char *fmt, ...) {
    if (!g_log) return;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(g_log, "[%s] [HOTSPOTD] ", buf);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

/* ══════════════════════════════════════════════════════════
   设备表操作
══════════════════════════════════════════════════════════ */
static Device *find_device(const char *mac) {
    for (int i = 0; i < MAX_DEVICES; i++)
        if (g_devs[i].active && strcasecmp(g_devs[i].mac, mac) == 0)
            return &g_devs[i];
    return NULL;
}

static Device *alloc_device(void) {
    for (int i = 0; i < MAX_DEVICES; i++)
        if (!g_devs[i].active)
            return &g_devs[i];
    /* 表满：淘汰最老的条目 */
    Device *oldest = &g_devs[0];
    for (int i = 1; i < MAX_DEVICES; i++)
        if (g_devs[i].active && g_devs[i].last_seen < oldest->last_seen)
            oldest = &g_devs[i];
    hlog("WARN: device table full, evicting %s", oldest->mac);
    memset(oldest, 0, sizeof(*oldest));
    return oldest;
}

/* 忽略非热点接口（lo/rmnet/dummy/tun/p2p） */
static int is_hotspot_iface(const char *iface) {
    if (!iface || !*iface) return 0;
    const char *skip[] = {"lo","rmnet","dummy","v4-","tun","p2p","r_rmnet", NULL};
    for (int i = 0; skip[i]; i++)
        if (strncmp(iface, skip[i], strlen(skip[i])) == 0)
            return 0;
    return 1;
}

static void count_active(void) {
    g_ndev = 0;
    for (int i = 0; i < MAX_DEVICES; i++)
        if (g_devs[i].active) g_ndev++;
}

/* v3.6 Commit 2: should_re_resolve 已提取到 hnc_helpers.c
 * 调用点用 hnc_should_re_resolve(...) 替代 */

/* ══════════════════════════════════════════════════════════
   v3.5.0 P0-4: Hostname 解析(手动命名 + mDNS)

   之前 hotspotd 的 write_json() 直接输出 d->hostname(只含 MAC 兜底),
   完全忽略 device_names.json(手动命名)和 mDNS。shell 路径的
   get_hostname() 按优先级 mdns > dhcp > manual > mac 查询,但
   hotspotd 的 scan_arp 只做 mac 兜底。结果:同一设备在 shell 和 C 之间
   hostname 不一致,WebUI 显示不稳定。

   修复:
   1) lookup_manual_name() 读 device_names.json,按 mac 查手动命名
   2) try_mdns_resolve() 调 bin/mdns_resolve binary(跟 shell 路径共用)
   3) scan_arp 新设备时顺序调用:manual > mdns > mac,填充 hostname_src
   4) write_json 输出 hostname_src 字段

   性能:
   - lookup_manual_name 每次读文件(没缓存),但 device_names.json 通常 < 1KB,
     O(n) 解析可忽略。未来可以加 mtime-based 缓存
   - try_mdns_resolve 开 popen 子进程,每设备 ~200ms,只在新设备初次发现时调,
     不在每次 write_json 调
══════════════════════════════════════════════════════════ */

/* v3.6 Commit 2: lookup_manual_name 已提取到 hnc_helpers.c
 * 调用点用 hnc_lookup_manual_name(mac, DEVICE_NAMES_JSON, out, outlen) */

/* ══════════════════════════════════════════════════════════
 * v3.8.2 阶段 3 方案 G: I/O 函数前向声明
 * 
 * try_mdns_resolve 和 try_ns_dhcp_resolve 的真实定义被搬到文件底部的
 * #ifndef HNC_TEST_MODE 块里。这样当 test_call_chain.c 用
 * #include "hotspotd.c" 的方式构建测试二进制时,定义段被 #ifdef 屏蔽,
 * 测试文件可以自己提供同名 static mock 定义,编译器会把 resolve_hostname
 * 里对这两个函数的调用解析到测试里的 mock 上。
 * 
 * 生产编译不定义 HNC_TEST_MODE → 真实定义生效,行为完全不变。
 * ══════════════════════════════════════════════════════════ */
static int try_mdns_resolve(const char *ip, const char *mac,
                            char *out, size_t outlen) __attribute__((unused));
static int try_ns_dhcp_resolve(const char *mac,
                               char *out, size_t outlen) __attribute__((unused));


/* 综合 hostname 解析:manual > dhcp > mdns > mac
 * 填充 out 和 out_src
 *
 * v3.6 Commit 2: 这个函数仍然在 hotspotd.c,因为它调 try_mdns_resolve
 * (try_mdns_resolve 依赖 MDNS_RESOLVE_BIN 宏和 popen,不适合放 helpers)。
 * 但 manual 查找和 mac 兜底都走 hnc_helpers 的纯函数。
 *
 * v3.6 Commit 3 会引入 resolve_hostname_fast(不调 mdns,纯 manual + mac),
 * 让 scan_arp 主循环不阻塞,mdns 解析延后到异步路径。这个同步版本保留给
 * "需要立刻解出完整 hostname"的罕见路径(如果有的话)。
 *
 * v3.7.0: 加 dhcp(dumpsys network_stack)查询,放在 manual 之后 mdns 之前。
 * DHCP 是被动数据(客户端 DHCP 包里带的 option 12),零网络成本,35ms 完成。
 * 相比 mdns 的 800ms,优先级更高。
 *
 * v3.8.4: 生产代码不再调用这个函数(scan_arp 和 nl_process 改成
 * resolve_hostname_dhcp_only + 异步 mdns worker)。但保留函数定义,因为:
 *   1. test_call_chain.c (方案 G) 的 Section 1 测试依然调用它测试完整 6 级优先链
 *   2. 作为 "完整优先级链的规范文档" 有文档价值
 * 加 __attribute__((unused)) 避免 -Wunused-function warning。*/
__attribute__((unused))
static void resolve_hostname(const char *mac, const char *ip,
                             char *out_hn, size_t hn_len,
                             char *out_src, size_t src_len) {
    /* 1. 手动命名 */
    if (hnc_lookup_manual_name(mac, DEVICE_NAMES_JSON, out_hn, hn_len)) {
        snprintf(out_src, src_len, "manual");
        return;
    }

    /* 2. v3.7.0: DHCP hostname via dumpsys network_stack(同步 ~35ms)*/
    if (try_ns_dhcp_resolve(mac, out_hn, hn_len)) {
        snprintf(out_src, src_len, "dhcp");
        /* v3.8.1: 命中 DHCP 时更新 cache,为后续 ring buffer 滚出时兜底 */
        hnc_cache_update(mac, out_hn, "dhcp");
        return;
    }

    /* 3. mDNS(只在有 IP 时,同步 popen ~800ms)*/
    if (ip && *ip && try_mdns_resolve(ip, mac, out_hn, hn_len)) {
        snprintf(out_src, src_len, "mdns");
        /* v3.8.1: 命中 mDNS 时也更新 cache */
        hnc_cache_update(mac, out_hn, "mdns");
        return;
    }

    /* 4. v3.8.1: 持久化 cache 兜底
     * 如果之前这台设备 DHCP/mDNS 命中过,cache 里有记录,即使现在
     * dumpsys ring buffer 已滚出也能恢复真名。
     *
     * cache 里存的 src 是"原始识别来源",这里包一层 "cache:xxx" 标注,
     * WebUI 可以显示"这是从缓存读的,不是最新鲜的数据"。*/
    char cached_hn[HN_LEN];
    char cached_src[16];
    if (hnc_cache_lookup(mac, cached_hn, sizeof(cached_hn),
                         cached_src, sizeof(cached_src))) {
        strncpy(out_hn, cached_hn, hn_len - 1);
        out_hn[hn_len - 1] = '\0';
        /* src 标注为 "cache-<原始>",区别于 live 识别 */
        snprintf(out_src, src_len, "cache-%s", cached_src);
        return;
    }

    /* 5. v3.8.0: OUI 厂商表兜底 */
    if (hnc_lookup_oui(mac, out_hn, hn_len)) {
        snprintf(out_src, src_len, "oui");
        return;
    }

    /* 6. MAC 兜底(最后的 fallback) */
    hnc_mac_fallback(mac, out_hn, hn_len);
    snprintf(out_src, src_len, "mac");
}

/* ══════════════════════════════════════════════════════════
 * v3.7.2: resolve_hostname_dhcp_only — pending 路径专用,不含 mDNS
 *
 * 背景:
 *   v3.7.1 让 process_pending_mdns 调 resolve_hostname(完整链),初衷是让
 *   pending 路径能拿到 DHCP hostname(修 v3.7.0 的 bug)。但副作用:如果
 *   DHCP 没命中,会继续走 mDNS 分支,阻塞 800ms。Gemini 审查指出这是对
 *   v3.6 "不阻塞主循环" 承诺的 regression。
 *
 *   真实场景:30 台 Pixel 设备(不发 option 12)同时连入,每台 pending 处理
 *   耗时 500ms (dhcp 失败超时) + 800ms (mdns 失败),主循环被冻 40 秒。
 *   远超 v3.6 承诺的"最多 800ms 阻塞一次"。
 *
 * v3.7.2 修复策略:
 *   pending 路径只查 manual + dhcp + mac,**不查 mdns**。
 *   原理:
 *     - manual 由 fast 路径在调用前已经查过了(fast 没命中才走到这里),
 *       所以 pending 里再查 manual 只是 defensive(1ms,可忽略)
 *     - dhcp 35-500ms,对 Windows/小米/华为 命中率高
 *     - 其他情况 mac 兜底,pending 路径立即结束
 *   mDNS 推迟到后续 re-resolve 路径:
 *     - 60 秒后 scan_arp / nl_process 触发 hnc_should_re_resolve
 *     - 那时会调完整 resolve_hostname,包括 mDNS 分支
 *     - 用户视角:Pixel 设备装机瞬间显示 MAC 兜底,60 秒后变成 mDNS 名字
 *     - 比 v3.7.1 的"装机瞬间卡 800ms"好太多
 *
 * 性能:
 *   - pending 路径耗时上限从 ~1.3s (dhcp+mdns) 降到 ~500ms (dhcp only)
 *   - 对 30 台设备同时上线,总阻塞从 40 秒降到 15 秒
 *   - 15 秒仍然不完美(需要 v3.8 的 pthread 异步化彻底解决),但比 40 秒
 *     好太多,而且这是"最坏情况",现实基本不会触发
 * ══════════════════════════════════════════════════════════ */
static void resolve_hostname_dhcp_only(const char *mac,
                                       char *out_hn, size_t hn_len,
                                       char *out_src, size_t src_len) {
    /* 1. 手动命名(fast 路径已查过,这里是 defensive) */
    if (hnc_lookup_manual_name(mac, DEVICE_NAMES_JSON, out_hn, hn_len)) {
        snprintf(out_src, src_len, "manual");
        return;
    }

    /* 2. DHCP */
    if (try_ns_dhcp_resolve(mac, out_hn, hn_len)) {
        snprintf(out_src, src_len, "dhcp");
        hnc_cache_update(mac, out_hn, "dhcp");  /* v3.8.1: 更新 cache */
        return;
    }

    /* 3. v3.8.1: 持久化 cache 兜底
     * pending 路径不查 mDNS 避免阻塞,所以 cache 是 mDNS 命中结果的
     * 唯一"即时回放"机制。对于之前通过 mDNS 识别到的 iPhone/Mac 等,
     * 重连时 cache 能立即提供正确名字,不需要等 60s re-resolve */
    char cached_hn[HN_LEN];
    char cached_src[16];
    if (hnc_cache_lookup(mac, cached_hn, sizeof(cached_hn),
                         cached_src, sizeof(cached_src))) {
        strncpy(out_hn, cached_hn, hn_len - 1);
        out_hn[hn_len - 1] = '\0';
        snprintf(out_src, src_len, "cache-%s", cached_src);
        return;
    }

    /* 4. v3.8.0: OUI 厂商表兜底 */
    if (hnc_lookup_oui(mac, out_hn, hn_len)) {
        snprintf(out_src, src_len, "oui");
        return;
    }

    /* 5. MAC 兜底(不走 mDNS,避免主循环阻塞 800ms) */
    hnc_mac_fallback(mac, out_hn, hn_len);
    snprintf(out_src, src_len, "mac");
}

/* ══════════════════════════════════════════════════════════
   JSON 写出（原子 tmp+rename，与原 shell 格式 100% 兼容）
══════════════════════════════════════════════════════════ */

/* v3.5.1 P0-2 + v3.5.2 P2-F: JSON 字符串转义
 * 转义 " \ \n \r \t 和 0x00-0x1f 控制字符。
 *
 * P0-2 原因:之前 write_json 用 %s 直接输出 d->hostname,含 " 或 \(来自
 * lookup_manual_name 解码 device_names.json)→ JSON 破损 → WebUI 设备列表清空
 *
 * P2-F 原因:当 dst 空间不够时原 break 策略会在 UTF-8 多字节序列中间截断,
 * 留下孤立的 continuation bytes(0x80-0xBF),JSON 本身合法但 UI JSON.parse
 * 后 .hostname 里出现 replacement character 或乱码。
 * 修复:回退 UTF-8 边界后才写 NUL。
 *
 * UTF-8 规则回顾:
 *   0xxxxxxx             ASCII(1 字节)
 *   110xxxxx 10xxxxxx    2 字节
 *   1110xxxx 10xxxxxx × 2   3 字节(中文)
 *   11110xxx 10xxxxxx × 3   4 字节(emoji 等)
 *   10xxxxxx 是 continuation byte
 *   回退规则:从末尾往前扫,跳过所有 10xxxxxx 的 byte,直到找到一个 non-continuation。
 */
/* v3.6 Commit 2: json_escape 已提取到 hnc_helpers.c
 * 调用点用 hnc_json_escape(...) 替代 */

/* v3.5.1 P1-2: 调 iptables_manager.sh stats_all 读 per-device 流量字节
 * 之前 hotspotd 模式下 rx_bytes/tx_bytes 永远 0 → WebUI 流量统计完全失效。
 * 修复:write_json 之前 popen 一次,把输出按 IP 索引,匹配后填充 d->rx_bytes/tx_bytes。
 * stats_all 输出格式:每行 "<ip> <rx_bytes> <tx_bytes>"
 *
 * v3.5.2 P1-E: 加 5 秒 TTL 缓存。
 * 原因:iptables -L HNC_STATS -nvx 的成本是 O(chain 规则数),长时间运行后
 * HNC_STATS 可能有 500+ 条规则,每次 popen+awk+iptables 几百毫秒。
 * write_json 在 de-bounce 触发最短 1 秒一次 → 多次调用被阻塞。
 * 缓存策略:5 秒内重复调用直接 return,流量数字实时性轻微牺牲但主线程不停摆。
 */
static time_t g_last_stats_update = 0;

static void update_traffic_stats(void) {
    if (access(IPTABLES_MGR, X_OK) != 0) return;

    /* v3.5.2 P1-E: 5 秒 TTL 缓存 */
    time_t now = time(NULL);
    if (now - g_last_stats_update < 5) return;
    g_last_stats_update = now;

    /* rc3.1.15 修 P3 (review §2b): popen → fork+execlp 跟项目其他地方
     * (try_mdns_resolve / dumpsys) 风格统一. IPTABLES_MGR 是编译时常量
     * 不可注入, 但代码风格一致性 + 防御深度. */
    int pipefd[2];
    if (pipe(pipefd) < 0) return;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        /* 子进程 */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        execlp("sh", "sh", IPTABLES_MGR, "stats_all", (char *)NULL);
        _exit(127);
    }

    /* 父进程 · 用 fdopen 让 fgets 行解析逻辑零改动 */
    close(pipefd[1]);
    FILE *pf = fdopen(pipefd[0], "r");
    if (!pf) {
        close(pipefd[0]);
        /* 仍要 reap 子进程, 不然 zombie */
        int st;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        return;
    }

    char line[128];
    while (fgets(line, sizeof(line), pf) != NULL) {
        char ip[IP_STR_LEN];
        long rx, tx;
        if (sscanf(line, "%15s %ld %ld", ip, &rx, &tx) == 3) {
            for (int i = 0; i < MAX_DEVICES; i++) {
                if (g_devs[i].active && strcmp(g_devs[i].ip, ip) == 0) {
                    g_devs[i].rx_bytes = rx;
                    g_devs[i].tx_bytes = tx;
                    break;
                }
            }
        }
    }
    fclose(pf);  /* 同时 close pipefd[0] */

    int status;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    (void)status;
}

/* rc30.9: monotonic clock in milliseconds.
 *
 * Used for sub-second de-bounce decisions. CLOCK_MONOTONIC never goes
 * backwards and is unaffected by NTP / time-of-day changes. Return value
 * is opaque (process-relative) — only differences are meaningful.
 *
 * Failure (clock_gettime returns -1) is treated as 0 — caller will compute
 * a large positive delta and conservatively trigger a write, which is the
 * fail-safe direction.
 */
static long now_ms_mono(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec * 1000L + (long)ts.tv_nsec / 1000000L;
}

static void write_json(void) {
    /* v3.5.1 P1-2: 写 JSON 前先更新流量字节,否则 rx/tx 永远是 0 */
    update_traffic_stats();

    /* 读黑名单
     * v3.5.0 P1-7 修复:之前 fgets(line, 256) 读 rules.json,如果 30+ 设备
     * 全在 blacklist 一行,256 字节装不下 → strstr 检测不到 ']' → 截断丢失。
     * 改用 fread 一次性读整个文件到大 buffer(rules.json 通常 < 8KB) */
    char blacklist[MAX_DEVICES][MAC_STR_LEN];
    int  nbl = 0;
    FILE *rf = fopen(RULES_JSON, "r");
    if (rf) {
        /* hotfix10 C3: rules.json 可能超过 16KB。旧版 char buf[16384]
         * 会截断末尾 blacklist / devices 字段,导致黑名单状态错乱。
         * 这里按文件大小动态读取,设置 1MB 上限防止异常文件拖垮 daemon。 */
        char *buf = NULL;
        long sz = 0;
        if (fseek(rf, 0, SEEK_END) == 0) {
            sz = ftell(rf);
            if (sz < 0) sz = 0;
            rewind(rf);
        }
        if (sz > 0 && sz <= 1024 * 1024) {
            buf = (char *)malloc((size_t)sz + 1);
        }
        if (buf) {
            size_t n = fread(buf, 1, (size_t)sz, rf);
            buf[n] = '\0';

            /* 找 "blacklist": 然后从这个位置开始扫,到 ] 结束 */
            char *bl_start = strstr(buf, "\"blacklist\"");
            if (bl_start) {
                char *bl_end = strchr(bl_start, ']');
                if (bl_end) *bl_end = '\0';

                /* 提取所有 "xx:xx:xx:xx:xx:xx" 子串 */
                char *p = bl_start;
                while ((p = strchr(p, '"')) != NULL) {
                    p++;
                    if (strlen(p) >= 17 && p[2] == ':' && p[5] == ':' &&
                        p[8] == ':' && p[11] == ':' && p[14] == ':') {
                        if (nbl < MAX_DEVICES) {
                            strncpy(blacklist[nbl], p, 17);
                            blacklist[nbl][17] = '\0';
                            nbl++;
                        }
                    }
                }
            }
            free(buf);
        } else if (sz > 1024 * 1024) {
            hlog("WARN: rules.json too large (%ld bytes), skip blacklist parse", sz);
        }
        fclose(rf);
    }

    /* v3.5.2 P0-A: tmp 路径带 PID 后缀,避免跟 shell daemon 冲突 */
    char devices_tmp[256];
    snprintf(devices_tmp, sizeof(devices_tmp), DEVICES_TMP_FMT, (int)getpid());

    FILE *f = fopen(devices_tmp, "w");
    if (!f) { hlog("ERROR: cannot write %s: %s", devices_tmp, strerror(errno)); return; }

    fprintf(f, "{");
    int first = 1;
    /* v3.5.1 P2-6: 删除原 300s 离线判断(死代码)。
     * 离线清理由主循环 R-13 周期任务负责(每 30s 检查,90s 阈值)。
     * 之前两个判断并存,300s 永远触发不到(R-13 90s 先清),逻辑不清晰 */
    (void)0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        Device *d = &g_devs[i];
        if (!d->active) continue;

        /* 黑名单状态 */
        const char *status = "allowed";
        for (int b = 0; b < nbl; b++)
            if (strcmp(blacklist[b], d->mac) == 0) { status = "blocked"; break; }

        /* v3.5.0 P0-4: 输出 hostname_src 字段(默认 mac 兜底)
         *
         * v3.6.2 note: 本来想在这里把 "pending" 映射成 "mac" 输出,但这样需要
         * 重新交叉编译 arm64 binary,沙箱无 NDK 不方便。既然 WebUI 已经把 pending
         * 当作 mac 分支降级显示(不 crash),C 侧保持输出 "pending" 也是 OK 的 —
         * 只是 devices.json 里会短暂出现 "pending" 字符串,前端的 if/else 链走到
         * 最后的 mac 分支渲染。功能上等效,兼容性上 v3.5.2 的 WebUI 也能显示。 */
        const char *hn_src = (d->hostname_src[0]) ? d->hostname_src : "mac";

        /* v3.5.1 P0-2: hostname 必须 JSON-escape,否则用户名字含 " 或 \ 会破坏 JSON */
        char hn_escaped[HN_LEN * 6 + 4];  /* worst case: 每字节变 \u00xx */
        hnc_json_escape(d->hostname, hn_escaped, sizeof(hn_escaped));

        if (!first) fprintf(f, ",");
        fprintf(f,
            "\"%s\":{"
            "\"ip\":\"%s\","
            "\"mac\":\"%s\","
            "\"hostname\":\"%s\","
            "\"hostname_src\":\"%s\","
            "\"iface\":\"%s\","
            "\"rx_bytes\":%ld,"
            "\"tx_bytes\":%ld,"
            "\"status\":\"%s\","
            "\"last_seen\":%ld"
            "}",
            d->mac, d->ip, d->mac, hn_escaped, hn_src,
            d->iface, d->rx_bytes, d->tx_bytes,
            status, (long)d->last_seen);
        first = 0;
    }
    fprintf(f, "}");
    fflush(f);
    fclose(f);

    if (rename(devices_tmp, DEVICES_JSON) != 0) {
        hlog("ERROR: rename failed: %s", strerror(errno));
        unlink(devices_tmp);  /* 清理失败的 tmp */
    } else {
        count_active();
        g_last_write = time(NULL);
        g_dirty = 0;
        hlog("JSON written: %d device(s)", g_ndev);
    }
}

/* ══════════════════════════════════════════════════════════
   ARP 补充扫描（/proc/net/arp 读取，用于 SIGUSR1 / 初始化）
══════════════════════════════════════════════════════════ */
static void scan_arp(void) {
    FILE *f = fopen(ARP_PROC, "r");
    if (!f) return;

    char line[256];
    int  updated = 0;
    /* v3.5.2 P2-D: 显式消费 fgets 返回值,不然 -Wunused-result 会报警 */
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return;  /* /proc/net/arp 读不到表头 → 直接退出 */
    }

    while (fgets(line, sizeof(line), f)) {
        char ip[IP_STR_LEN], hw[8], flags[8], mac[MAC_STR_LEN], mask[8], iface[IF_LEN];
        if (sscanf(line, "%15s %7s %7s %17s %7s %15s",
                   ip, hw, flags, mac, mask, iface) != 6)
            continue;
        /* flags=0x0 表示无效 */
        if (strcmp(flags, "0x0") == 0) continue;
        /* 过滤全零 MAC */
        if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
        /* 过滤非热点接口 */
        if (!is_hotspot_iface(iface)) continue;

        /* MAC 转小写 */
        for (int i = 0; mac[i]; i++) mac[i] = tolower((unsigned char)mac[i]);

        Device *d = find_device(mac);
        time_t now_t = time(NULL);
        if (!d) {
            d = alloc_device();
            strncpy(d->mac, mac, sizeof(d->mac)-1);
            /* v3.6 Commit 3: scan_arp 不再调同步的 resolve_hostname
             * (原来每个新设备会 popen mdns_resolve -t 800,N 台设备最坏 N × 800ms
             * 主线程阻塞,这是 v3.5.2 CHANGELOG 承诺 v3.6 要修的 P0-B 剩余部分)。
             *
             * 新流程:快速解析(只 manual + mac 兜底,~1μs),如果是 mac 兜底就
             * 标 pending,主循环的 process_pending_mdns 下一次 tick 会异步
             * 调一次 mdns_resolve 把它升级成 mdns 或者确定降级为 mac。
             *
             * 用户感知:新设备立刻出现在 WebUI(hostname_src="pending"),1-N 秒后
             * 变成真名字。比 v3.5.2 的"卡几秒设备才出现"体验更好,而且主线程永远
             * 不会被一批新设备同时上线阻塞。 */
            hnc_resolve_hostname_fast(mac, ip, DEVICE_NAMES_JSON,
                                      d->hostname, sizeof(d->hostname),
                                      d->hostname_src, sizeof(d->hostname_src));
            d->last_resolve = now_t;
            /* 如果 fast 只拿到 mac 兜底,挂 pending 等异步 mdns */
            if (strcmp(d->hostname_src, "mac") == 0) {
                strncpy(d->hostname_src, "pending", sizeof(d->hostname_src)-1);
                d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                d->pending_since = now_t;
            }
        } else if (hnc_should_re_resolve(d->hostname_src, d->last_resolve, now_t)) {
            /* v3.5.0-rc R-2 + v3.5.2 P1-A:
             * re-resolve 条件(hostname_src=="mac" 或窗口过期)以前调完整的
             * resolve_hostname,其中 mdns 分支最坏阻塞 800ms。
             *
             * v3.8.4: 分两步
             *   1. 先同步调 dhcp_only(只查 manual/dhcp/cache/oui/mac,~35ms),
             *      大部分情况下 dhcp 或 cache 命中,直接返回真名
             *   2. 只有 dhcp_only 返回 src=="mac"(所有快速路径都失败)时,
             *      才 enqueue 到异步 worker 查 mdns
             *   3. Worker 结果在主循环下一个 tick 通过 drain_results 写回
             *
             * 这样 mdns 查询完全不阻塞 scan_arp,但绝大多数设备(有 DHCP hostname 或
             * cache 记录的)依然是同步解析,延迟不变。*/
            resolve_hostname_dhcp_only(mac,
                                       d->hostname, sizeof(d->hostname),
                                       d->hostname_src, sizeof(d->hostname_src));
            d->last_resolve = now_t;

            /* 如果 dhcp_only 最终落到 mac 兜底且有 IP,enqueue 异步 mdns 查询 */
            if (strcmp(d->hostname_src, "mac") == 0 && ip[0] != '\0') {
                if (hnc_mdns_worker_enqueue(mac, ip)) {
                    /* 成功入队,标记为 pending-mdns 让 UI 显示"正在查询" */
                    strncpy(d->hostname_src, "pending", sizeof(d->hostname_src)-1);
                    d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                    d->pending_since = now_t;
                }
                /* 队列满则保持 mac 兜底,下轮 re-resolve 会再试 */
            }
        }
        strncpy(d->ip,    ip,    sizeof(d->ip)-1);
        strncpy(d->iface, iface, sizeof(d->iface)-1);
        d->last_seen = now_t;
        d->active    = 1;
        d->state     = NUD_STALE; /* 保守估计 */
        updated++;
    }
    fclose(f);

    if (updated) {
        g_dirty = 1;
        hlog("ARP scan: %d entry/entries updated", updated);
        write_json();
    } else {
        hlog("ARP scan: no new entries");
    }
}

/* ══════════════════════════════════════════════════════════
   v3.6 Commit 3: 异步 pending mDNS 解析

   问题背景:
   v3.5.2 及之前,scan_arp 和 nl_process 新设备时同步调 resolve_hostname,
   里面 popen mdns_resolve -t 800 阻塞最多 800ms × N 设备。30 台设备同时
   上线 → 主线程卡 24 秒,期间 netlink 积压 ENOBUFS,设备从设备表消失。
   这是 v3.5.2 CHANGELOG 明确留给 v3.6 的"P0-B 核心修复"。

   解决方案(候选 B):
   1) scan_arp / nl_process 新设备时只做 manual + mac 兜底(hnc_resolve_hostname_fast)
   2) 如果落到 mac 兜底,标 hostname_src="pending" + pending_since=now
   3) 主循环每次 tick 调一次 process_pending_mdns:
      - 找 pending_since 最老的设备(FIFO 公平)
      - 如果挂 pending < 1 秒,跳过(给 netlink 事件 breathing room)
      - 调一次 try_mdns_resolve(仍同步,但**最多一次**),~800ms 内返回
      - 成功 → hostname_src="mdns"
      - 失败 → hostname_src="mac"(从 pending 降级,不再重试直到下次 should_re_resolve)
      - 无论成功失败都设 g_dirty=1 让 UI 刷新

   关键保证:
   - 一次主循环 tick 最多解 1 个 pending → 最坏 800ms,不累加
   - 跟 signal handler 无冲突(纯主线程)
   - 不引入新线程 / 锁,单线程模型不变
   - 不破坏 scan_arp / nl_process 的其他语义

   测试策略见 daemon/test/test_hostname_helpers.c 的 pending 场景测试。
══════════════════════════════════════════════════════════ */

/* 每个 pending 设备至少挂这么多秒才处理 — 见 hnc_helpers.h */
/* (HNC_PENDING_BREATHING_ROOM_SEC 在 hnc_helpers.h 定义) */

static void process_pending_mdns(void) {
    time_t now = time(NULL);
    Device *oldest = NULL;

    /* 找 pending_since 最老的 active + ready 设备
     * (ready 判断用 hnc_pending_ready 纯函数,统一规则,好测) */
    for (int i = 0; i < MAX_DEVICES; i++) {
        Device *d = &g_devs[i];
        if (!d->active) continue;
        if (!hnc_pending_ready(d->hostname_src, d->pending_since, now)) continue;
        if (oldest == NULL || d->pending_since < oldest->pending_since) {
            oldest = d;
        }
    }

    if (oldest == NULL) return;

    /* v3.7.2 修复:pending 路径改调 resolve_hostname_dhcp_only
     *
     * v3.6 - v3.7.0: 这里调 try_mdns_resolve,绕过 DHCP 查询 ← 被 v3.7.1 修
     * v3.7.1:        改调 resolve_hostname 完整链 ← 但引入 mDNS 阻塞 regression
     * v3.7.2 (now):  改调 resolve_hostname_dhcp_only,只查 manual+dhcp+mac,
     *                不查 mDNS。mDNS 推迟到后续 re-resolve 路径(60 秒后
     *                由 scan_arp / nl_process 触发)。
     *
     * 这样 pending 路径耗时上限从 ~1.3s 降到 ~500ms (dhcp 超时),主循环
     * 在 30 台 Pixel 同时上线的最坏场景下阻塞时间大幅减少。
     *
     * 对用户体验:
     *   - Mi-10 / Windows / 大部分 OEM Android:pending 路径立即命中 dhcp ✓
     *   - Pixel / LineageOS:pending 路径显示 MAC 兜底,60 秒后再尝试 mDNS
     *   - 对比 v3.7.1:Pixel 装机瞬间不再卡 800ms,体验更流畅
     *
     * Gemini 审查 P0-4 + P1-20 的修复。完整 mDNS 异步化(pthread worker)
     * 留到 v3.8。 */
    char new_hn[HN_LEN];
    char new_src[32];
    resolve_hostname_dhcp_only(oldest->mac,
                               new_hn, sizeof(new_hn),
                               new_src, sizeof(new_src));

    strncpy(oldest->hostname, new_hn, sizeof(oldest->hostname) - 1);
    oldest->hostname[sizeof(oldest->hostname) - 1] = '\0';
    strncpy(oldest->hostname_src, new_src, sizeof(oldest->hostname_src) - 1);
    oldest->hostname_src[sizeof(oldest->hostname_src) - 1] = '\0';

    hlog("pending→%s: %s (%s) → %s",
         new_src, oldest->mac, oldest->ip, oldest->hostname);

    oldest->last_resolve = now;
    oldest->pending_since = 0;  /* 清除 pending 状态 */
    g_dirty = 1;
    g_last_event = now;  /* 让 de-bounce 窗口认识到这是一次"事件",触发 write_json */
    g_last_event_ms = now_ms_mono();  /* rc30.9: ms-精度并行 */
}

/* ══════════════════════════════════════════════════════════
   Netlink：设置 + 解析 RTM_NEWNEIGH / RTM_DELNEIGH
══════════════════════════════════════════════════════════ */
static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) { hlog("ERROR: netlink socket: %s", strerror(errno)); return -1; }

    /* v3.5.2 P1-C: 把 netlink 接收缓冲区调到 1 MB,减少高负载下的
     * ENOBUFS 丢包。默认约 128 KB,30+ 客户端时一次事件风暴就可能溢出。 */
    int rcvbuf = 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        hlog("WARN: netlink SO_RCVBUF failed: %s", strerror(errno));
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        /* rc43 (P2-17): 加 RTMGRP_LINK —— 监听 iface 链路状态变化(WiFi↔4G 切换、
         * VPN tun 上下线等),用来即时通知 offload 调度器重探主上游,把原来最坏 60s
         * 的"换网后限速对新上游短暂失效"窗口缩到瞬时。NEIGH 仍用于设备表发现。 */
        .nl_groups = RTMGRP_NEIGH | RTMGRP_LINK,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        hlog("ERROR: netlink bind: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void nl_process(int fd) {
    char buf[8192];
    /* rc3.1.33 修 #4: drain loop. 之前一次 wakeup 只 recv 一次 8KB, 30+ 设备
     * 同时上线时 socket buffer (1MB) 余下数据要等下轮 select wakeup. 但 g_dirty=1
     * 时主循环 tv.tv_sec=1, 期间持续累积 → ENOBUFS → 触发同步 scan_arp 灾难
     * (v3.6 Commit 3 注释明确警告). v3.8.5 修了"一次 buffer 多消息" (NLMSG_OK
     * 循环), 这里修"一次 wakeup 多次 recv". 直到 EAGAIN 抽干. */
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;  /* 抽干了, 正常退出 */
            }
            /* v3.5.2 P1-C: 处理 ENOBUFS — netlink kernel buffer 溢出,丢包了,
             * 触发一次全量 scan_arp 重同步设备表,不然有设备会永久从视角消失 */
            if (errno == ENOBUFS) {
                hlog("WARN: netlink ENOBUFS, queueing full rescan");
                g_need_scan = 1;
            } else {
                hlog("WARN: netlink recv: %s", strerror(errno));
            }
            return;
        }
        if (n == 0) return;

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
        /* rc43 (P2-17): 链路状态变化 → 即时请求 offload 调度器重探主上游。
         * request_refresh 非阻塞(仅置 flag + cond_signal),未启用 offload 时是
         * 安全空操作;事件风暴会被 worker 合并成一次重探。不影响下面 NEIGH 处理。 */
        if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
            hnc_scheduler_request_refresh();
            continue;
        }
        if (nlh->nlmsg_type != RTM_NEWNEIGH && nlh->nlmsg_type != RTM_DELNEIGH)
            continue;

        struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nlh);
        if (ndm->ndm_family != AF_INET) continue;  /* 只处理 IPv4 */

        /* 获取接口名 */
        char iface[IF_LEN] = {0};
        if_indextoname(ndm->ndm_ifindex, iface);
        if (!is_hotspot_iface(iface)) continue;

        /* 提取 NDA_DST（IP）和 NDA_LLADDR（MAC） */
        char ip_str[IP_STR_LEN]   = {0};
        char mac_str[MAC_STR_LEN] = {0};
        struct rtattr *rta = NDM_RTA(ndm);
        int rta_len = NDM_PAYLOAD(nlh);

        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == NDA_DST && rta->rta_len == RTA_LENGTH(4)) {
                struct in_addr *addr = (struct in_addr *)RTA_DATA(rta);
                inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
            } else if (rta->rta_type == NDA_LLADDR && rta->rta_len == RTA_LENGTH(6)) {
                unsigned char *m = (unsigned char *)RTA_DATA(rta);
                snprintf(mac_str, sizeof(mac_str),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         m[0],m[1],m[2],m[3],m[4],m[5]);
            }
        }

        if (!*ip_str || !*mac_str) continue;

        if (nlh->nlmsg_type == RTM_DELNEIGH || !(ndm->ndm_state & NUD_VALID)) {
            /* 设备离线:标记非活跃,不立即删除(给 300s 宽限) */
            Device *d = find_device(mac_str);
            if (d) {
                /* 仅 NUD_FAILED / NUD_INCOMPLETE 才真正移除 */
                if (ndm->ndm_state & (NUD_FAILED | NUD_INCOMPLETE)) {
                    d->active = 0;
                    g_dirty   = 1;
                    g_last_event = time(NULL);  /* v3.5.0-rc R-1 */
                    g_last_event_ms = now_ms_mono();  /* rc30.9 */
                    hlog("DEL: %s (%s) state=0x%x", mac_str, ip_str, ndm->ndm_state);
                }
            }
        } else {
            /* 设备上线或更新 */
            Device *d = find_device(mac_str);
            time_t now_t = time(NULL);
            if (!d) {
                d = alloc_device();
                strncpy(d->mac, mac_str, sizeof(d->mac)-1);
                /* v3.6 Commit 3: 跟 scan_arp 同策略,netlink 回调路径绝对
                 * 不能阻塞(否则 netlink socket 积压 ENOBUFS)。
                 * 用 hnc_resolve_hostname_fast + pending 延后 mdns。 */
                hnc_resolve_hostname_fast(mac_str, ip_str, DEVICE_NAMES_JSON,
                                          d->hostname, sizeof(d->hostname),
                                          d->hostname_src, sizeof(d->hostname_src));
                d->last_resolve = now_t;
                if (strcmp(d->hostname_src, "mac") == 0) {
                    strncpy(d->hostname_src, "pending", sizeof(d->hostname_src)-1);
                    d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                    d->pending_since = now_t;
                }
            } else if (hnc_should_re_resolve(d->hostname_src, d->last_resolve, now_t)) {
                /* v3.5.0-rc R-2 + v3.5.2 P1-A: 已知设备的 re-resolve。
                 * v3.8.4: netlink 路径绝对不能阻塞 800ms (ENOBUFS 风险),
                 *         和 scan_arp 同策略:先同步 dhcp_only,mac 兜底
                 *         则 enqueue 异步 mdns worker。*/
                resolve_hostname_dhcp_only(mac_str,
                                           d->hostname, sizeof(d->hostname),
                                           d->hostname_src, sizeof(d->hostname_src));
                d->last_resolve = now_t;

                if (strcmp(d->hostname_src, "mac") == 0 && ip_str[0] != '\0') {
                    if (hnc_mdns_worker_enqueue(mac_str, ip_str)) {
                        strncpy(d->hostname_src, "pending", sizeof(d->hostname_src)-1);
                        d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                        d->pending_since = now_t;
                    }
                }
            }
            strncpy(d->ip,    ip_str, sizeof(d->ip)-1);
            strncpy(d->iface, iface,  sizeof(d->iface)-1);
            d->last_seen = now_t;
            d->active    = 1;
            d->state     = ndm->ndm_state;
            g_dirty      = 1;
            g_last_event = now_t;  /* v3.5.0-rc R-1: 更新事件时间戳给 de-bounce 用 */
            g_last_event_ms = now_ms_mono();  /* rc30.9 */
            hlog("NEW: %s (%s) on %s state=0x%x", mac_str, ip_str, iface, ndm->ndm_state);
        }
    }
    /* drain loop 一轮结束, 再 recv 看是否还有数据 (EAGAIN 时上面 return) */
    }

    /* v3.5.0-rc R-1: 不再"有变化立即 write_json"。
     * 仅 set g_dirty,主循环用 200ms de-bounce 合并连续事件。
     * 这避免了同一设备 5 秒内 state 变 3 次 → 3 次 write_json 的情况。
     * 实测:RMX5010 上单个客户端连接热点,5 秒内 6+ 个 state transition,
     * de-bounce 后合并为 1 次 write_json,文件 IO 减少 80%+
     * rc3.1.33 修 #4: drain loop 退出走 return 而非 fall-through 到这里, 注释保留. */
}

/* ══════════════════════════════════════════════════════════
   UNIX Socket Server（IPC）
══════════════════════════════════════════════════════════ */
static int unix_server_open(void) {
    unlink(SOCK_PATH);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { hlog("ERROR: unix socket: %s", strerror(errno)); return -1; }

    struct sockaddr_un su = {.sun_family = AF_UNIX};
    strncpy(su.sun_path, SOCK_PATH, sizeof(su.sun_path)-1);
    if (bind(fd, (struct sockaddr *)&su, sizeof(su)) < 0) {
        hlog("ERROR: unix bind: %s", strerror(errno));
        close(fd); return -1;
    }
    /* v3.6.2 P1-2 修复(Gemini 审查发现):socket 权限从 0666 收紧到 0600。
     *
     * 旧 0666 的风险:任何能访问 /data/local/hnc/run/ 目录的进程都能连
     * socket 并发 QUIT(杀 daemon)或高频 REFRESH(本地 DoS)。
     * /data/local/hnc 的 DAC 是 root:root,按理说普通 App 进不来,但:
     * 1. 纵深防御原则 — 上层目录权限一旦被意外放开,socket 层也要能挡
     * 2. 0666 是"所有人可读写",没有语义理由给非 root 进程开放
     * 3. hotspotd 和所有合法客户端(watchdog / device_detect.sh / WebUI 经
     *    kexec)都以 root 运行,0600 (仅 owner=root) 完全够用
     *
     * 如果未来要让非 root 进程通信,应该显式 chown + chmod 0660,而不是 0666。 */
    chmod(SOCK_PATH, 0600);
    /* v3.8.6 纵深防御: 显式 chown 到 root:root,即使创建时 umask 异常
     * 也保证只有 root 能访问。chown 失败不阻塞启动(本来就是 root 跑) */
    if (chown(SOCK_PATH, 0, 0) != 0) {
        hlog("WARN: chown SOCK_PATH failed: %s (continuing)", strerror(errno));
    }
    listen(fd, 8);
    return fd;
}


/* hotfix2: send() may legally perform a short write.
 * Use a small helper for IPC responses so GET_DEVICES and status JSON are not truncated
 * when the client/socket buffer is temporarily full. */
static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static void handle_client(int cfd) {
    /* v3.5.2 P1-B: 加读写超时防止恶意客户端挂起主线程
     * - 2 秒读超时:客户端连上但不发数据 → recv 超时后 close
     * - 5 秒写超时:客户端慢读或不读 → send 超时后 close
     * 之前没超时,一个坏客户端就能 DoS 整个 hotspotd */
    struct timeval tv_rd = {.tv_sec = 2, .tv_usec = 0};
    struct timeval tv_wr = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv_rd, sizeof(tv_rd));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv_wr, sizeof(tv_wr));

    char req[64] = {0};
    ssize_t n = recv(cfd, req, sizeof(req)-1, 0);
    if (n <= 0) { close(cfd); return; }
    req[n] = '\0';
    /* 去尾部空白 */
    for (int i = (int)strlen(req)-1; i >= 0 && (req[i]=='\n'||req[i]=='\r'||req[i]==' '); i--)
        req[i] = '\0';

    if (strcmp(req, "GET_DEVICES") == 0) {
        /* 直接发 JSON 文件内容 */
        FILE *f = fopen(DEVICES_JSON, "r");
        if (!f) { (void)send_all(cfd, "{}", 2); }
        else {
            char fbuf[65536];
            size_t rd;
            while ((rd = fread(fbuf, 1, sizeof(fbuf), f)) > 0) {
                /* hotfix2: 处理短写,避免设备较多时返回半截 JSON */
                if (send_all(cfd, fbuf, rd) != 0) break;
            }
            fclose(f);
        }
    } else if (strcmp(req, "REFRESH") == 0) {
        /* v3.5.2 P0-B 修复:REFRESH 不再同步调 scan_arp(那会 popen
         * mdns_resolve × N 设备,主线程阻塞几秒到几十秒)。
         * 只设 g_need_scan 标志,主循环下一次 select wakeup 会处理。
         *
         * v3.6 T2: 清 stats TTL 缓存,保证下次 write_json 重算 iptables stats,
         * 否则 REFRESH 后用户看到新 last_seen 但 rx/tx 是旧数据(UX 钝感)
         *
         * v3.6.2 P1-1 修复(Gemini 审查发现):不能把 g_last_stats_update 清成 0,
         * 因为那样任何能连 socket 的进程发高频 REFRESH 就能完全绕过 5s TTL,
         * 让主循环疯狂 popen iptables,打满 CPU → 本地 DoS / fork 炸弹风险。
         * 改成把 g_last_stats_update 拨回到"距 now 刚好 MIN_REFRESH_INTERVAL 秒前",
         * 这样 REFRESH 仍然能触发一次 stats 重算(如果距上次 > MIN 秒),
         * 但高频 REFRESH 不会比自然的 update_traffic_stats 更频繁。 */
        g_need_scan = 1;
        {
            time_t now = time(NULL);
            /* 最小重算间隔:2 秒。介于原 5s TTL 和 "完全绕过" 之间,
             * 既让 REFRESH 有意义(2s 内反应)又防止 DoS */
            const time_t MIN_REFRESH_INTERVAL = 2;
            if (now - g_last_stats_update > MIN_REFRESH_INTERVAL) {
                g_last_stats_update = now - MIN_REFRESH_INTERVAL;
            }
            /* else: 距上次重算不到 2 秒,不改 g_last_stats_update,
             * 让 update_traffic_stats 的 TTL 检查自然工作 */
        }
        (void)send_all(cfd, "OK:queued\n", 10);
    } else if (strcmp(req, "STATUS") == 0) {
        char resp[128];
        snprintf(resp, sizeof(resp), "running:1 devices:%d pid:%d\n",
                 g_ndev, (int)getpid());
        (void)send_all(cfd, resp, strlen(resp));
    } else if (strncmp(req, "OFFLOAD_NOTIFY_LIMIT ", 21) == 0) {
        /* v5.0: OFFLOAD_NOTIFY_LIMIT <mac> <0|1>
         * apply_device_rule.sh 在 tc 规则添加/删除后调 */
        char mac[32] = {0};
        int  flag    = -1;
        if (sscanf(req + 21, "%31s %d", mac, &flag) == 2 &&
            (flag == 0 || flag == 1)) {
            hnc_scheduler_notify_device_limit_changed(mac, flag);
            (void)send_all(cfd, "OK\n", 3);
        } else {
            (void)send_all(cfd, "ERR:bad args (expect MAC 0|1)\n", 30);
        }
    } else if (strcmp(req, "OFFLOAD_REFRESH") == 0) {
        hnc_scheduler_request_refresh();
        (void)send_all(cfd, "OK:queued\n", 10);
    } else if (strcmp(req, "OFFLOAD_STATUS") == 0) {
        hnc_offload_summary_t summ;
        hnc_scheduler_get_summary(&summ);
        char json[2048];
        int n = hnc_scheduler_summary_to_json(&summ, json, sizeof(json));
        if (n > 0) {
            (void)send_all(cfd, json, (size_t)n);
            (void)send_all(cfd, "\n", 1);
        } else {
            (void)send_all(cfd, "ERR:summary serialize\n", 22);
        }
    } else if (strcmp(req, "OFFLOAD_DISABLE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_disable_global();
        char resp[64];
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 e == OFFLOAD_OK ? "OK" : "ERR",
                 offload_err_str(e));
        (void)send_all(cfd, resp, strlen(resp));
    } else if (strcmp(req, "OFFLOAD_RESTORE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_restore_global();
        char resp[64];
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 e == OFFLOAD_OK ? "OK" : "ERR",
                 offload_err_str(e));
        (void)send_all(cfd, resp, strlen(resp));
    } else if (strcmp(req, "QUIT") == 0) {
        (void)send_all(cfd, "BYE\n", 4);
        g_running = 0;
    } else {
        (void)send_all(cfd, "ERR:unknown command\n", 20);
    }
    close(cfd);
}

/* ══════════════════════════════════════════════════════════
   信号处理
══════════════════════════════════════════════════════════ */
static void sig_usr1(int s) { (void)s; g_need_scan = 1; }
static void sig_term(int s) { (void)s; g_running   = 0; }

/* ══════════════════════════════════════════════════════════
   PID 文件
══════════════════════════════════════════════════════════ */

/* v3.5.2 P1-D + P2-A:
 * 1) write_pid 用 O_CREAT|O_EXCL 原子创建,如果文件已存在:
 *    - 读出旧 PID,kill -0 检查活不活
 *    - 活着 → 返回 -1 让 main 退出(不做 cleanup 避免误删别人的文件)
 *    - 死了 → unlink 旧文件,重试 O_EXCL 创建
 * 2) fopen/write 失败时打日志而不是静默
 *
 * 防止的场景:watchdog 重启 hotspotd 时并发拉起两个实例,
 * 第二个实例 O_EXCL 失败,检测到第一个实例活着 → 干净退出,
 * 不会 unlink 第一个实例的 PID 文件。
 */
static int write_pid(void) {
    int fd = open(PID_FILE, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        if (errno == EEXIST) {
            /* 文件已存在,检查里面的 PID 是否还活着 */
            FILE *rf = fopen(PID_FILE, "r");
            if (rf) {
                int old_pid = 0;
                if (fscanf(rf, "%d", &old_pid) == 1 && old_pid > 0) {
                    fclose(rf);
                    if (kill(old_pid, 0) == 0) {
                        /* 旧进程还活着,不要继续 */
                        hlog("ERROR: another hotspotd already running (PID=%d), exiting",
                             old_pid);
                        return -1;
                    }
                    /* 旧进程死了,清理 stale 文件 */
                    hlog("INFO: stale PID file (dead PID=%d), cleaning up", old_pid);
                } else {
                    fclose(rf);
                    hlog("WARN: PID file exists but unreadable, cleaning up");
                }
            }
            unlink(PID_FILE);
            /* 重试 O_EXCL 创建 */
            fd = open(PID_FILE, O_CREAT | O_EXCL | O_WRONLY, 0644);
            if (fd < 0) {
                hlog("ERROR: cannot create PID file after cleanup: %s", strerror(errno));
                return -1;
            }
        } else {
            hlog("ERROR: cannot create PID file: %s", strerror(errno));
            return -1;
        }
    }
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (write(fd, buf, n) != n) {
        hlog("WARN: write PID file short/failed: %s", strerror(errno));
    }
    close(fd);
    return 0;
}

/* v3.5.2 P1-D: cleanup 时验证 PID 文件里的 PID 是不是自己,
 * 是才删,不是说明别的实例已经 overwrite 了,不要删它的文件 */
static void cleanup_pid(void) {
    FILE *rf = fopen(PID_FILE, "r");
    if (!rf) return;
    int file_pid = 0;
    if (fscanf(rf, "%d", &file_pid) == 1 && file_pid == (int)getpid()) {
        fclose(rf);
        unlink(PID_FILE);
    } else {
        fclose(rf);
        /* PID 文件里不是自己 → 别的实例,保留 */
    }
}


/* ══════════════════════════════════════════════════════════
 * v3.8.2 方案 G: 测试可替换的 I/O 函数定义 + main()
 * 
 * 生产编译: 不定义 HNC_TEST_MODE,下面所有代码生效。
 * 测试编译 (test_call_chain.c 里 #define HNC_TEST_MODE + #include): 
 *   下面整段被跳过,测试文件自己提供 try_mdns_resolve / try_ns_dhcp_resolve
 *   的 static 定义,resolve_hostname 调用点会解析到测试 mock。
 *   main() 也被屏蔽,避免和测试 main() 冲突。
 * ══════════════════════════════════════════════════════════ */
#ifndef HNC_TEST_MODE

/* 调 bin/mdns_resolve <ip>,超时 1s
 * v3.5.1 P0-1 修复:之前传 "<ip> <mac>" 两个位置参数,但 mdns_resolve 的
 * argv 解析循环把任何非 flag 参数都赋给 ip,结果 ip 被 mac 覆盖,
 * inet_pton 必然失败,从来没真正发出过 mDNS 查询。
 * 修复:只传 ip,跟 shell 路径(`mdns_resolve -t 800 "$ip"`)一致 */
static int try_mdns_resolve(const char *ip, const char *mac, char *out, size_t outlen) {
    (void)mac;  /* 参数保留以兼容调用方,但不传给 binary */
    if (access(MDNS_RESOLVE_BIN, X_OK) != 0) return 0;
    if (!ip || !out || outlen == 0) return 0;

    /* rc3.1.15 修 P2 (review §2b): 防御性 ip 验证 + 改 fork+execlp 彻底脱离 shell.
     * 当前 ip 来源 (kernel /proc/net/arp + netlink RTM_NEWNEIGH) 都是 kernel
     * 严格格式化的 dotted-decimal, 实际不可注入. 但一旦未来引入第三方 ip 来源
     * (eBPF / userspace 库 / IPC), popen 拼字符串立即变 RCE. 跟 dumpsys 路径
     * (hotspotd.c:1156-1207) 的 execlp 防御深度风格统一. */
    struct in_addr tmp_ip;
    if (inet_pton(AF_INET, ip, &tmp_ip) != 1) {
        return 0;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        /* 子进程 */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        /* stderr 丢弃, 等价 popen 时的 2>/dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        execlp(MDNS_RESOLVE_BIN, "mdns_resolve", "-t", "800", ip, (char *)NULL);
        _exit(127);
    }

    /* 父进程 */
    close(pipefd[1]);
    out[0] = '\0';

    /* 读子进程 stdout, 最多 outlen-1 字节 */
    size_t total = 0;
    while (total < outlen - 1) {
        ssize_t n = read(pipefd[0], out + total, outlen - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;  /* EOF */
        total += (size_t)n;
    }
    out[total] = '\0';
    close(pipefd[0]);

    /* waitpid 等子进程结束, 拿退出码 (语义同原 pclose) */
    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    int rc = (w < 0) ? -1 : (WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* 去尾部换行 */
    size_t l = strlen(out);
    while (l > 0 && (out[l-1] == '\n' || out[l-1] == '\r')) {
        out[--l] = '\0';
    }

    /* v3.8.4 Gemini/第三方 AI 审查 P2: 检查退出码
     * 以前 popen+pclose 路径 (rc3.1.14 之前) 的退出码语义在新版同样适用 ·
     * 子进程必须 exit 0 才认为输出可信. 非零 → 查询失败, 即使有输出也清空. */
    if (rc != 0) {
        out[0] = '\0';
        return 0;
    }
    return (out[0] != '\0') ? 1 : 0;
}

/* ══════════════════════════════════════════════════════════
 * v3.7.0: try_ns_dhcp_resolve — 从 dumpsys network_stack 提取 hostname
 *
 * Android 14+ 的 NetworkStack mainline module 把所有 DHCP 事件写到
 * 内存 ring buffer,dumpsys network_stack 能 dump 出来。每条事件格式:
 *
 *   2026-04-13T16:43:31 - [wlan2.DHCP] Transmitting DhcpAckPacket with lease
 *     clientId: XXX, hwAddr: 7a:d6:f7:ce:ba:76, netAddr: 10.201.76.69/24,
 *     expTime: 4968921,hostname: Mi-10
 *
 * 只要客户端的 DHCP 包里带 option 12 (Host Name),这里就会出现。
 * 覆盖情况:
 *   - Windows (100%)、OEM Android (小米/华为,~80%)、部分 iOS (~40%)
 *   - 不覆盖:原生 Android (Pixel/LineageOS,Google 隐私移除)
 *
 * 耗时:真机实测 ~35ms (dumpsys binder 调用),输出 ~15 KB。
 *
 * ═══════════════════════════════════════════════════════════
 * v3.7.2 重写:放弃 popen + grep shell 管道,改用 fork + execlp + select
 * ═══════════════════════════════════════════════════════════
 *
 * Gemini 审查发现的 5 个缺陷,一次重构全部修复:
 *
 * 1) [RCE] popen("... | grep -iF %s ...", mac) 如果 mac 绕过白名单
 *    (比如 "11:22:33:44:55:66;reboot",我原来的 i==17 检查没查第 18 个
 *    字符是否是 \0) 就是命令注入。
 *    → 现在加 `mac[17] != '\0'` 严格校验。
 *    → 更重要:改用 execlp 直接 exec dumpsys,彻底抛弃 shell。
 *       MAC 作为 strcasestr 的字符串参数,零 shell 参与,不可能注入。
 *
 * 2) [阻塞] popen 没有超时。如果 system_server 卡死(ColorOS 后台杀手
 *    重载 / Doze 模式 / VPN 重试风暴时常见),dumpsys binder 调用无限挂起,
 *    hotspotd 主线程连带被冻死,watchdog 会误触发重启。
 *    → 改用 select() 硬超时 500ms。超时直接 SIGKILL 子进程。
 *
 * 3) [zombie] popen 原版通过 pclose 回收,但如果未来有人在循环里加
 *    提前 return(比如处理错误),pclose 会被跳过,留下僵尸进程。
 *    → waitpid(pid, ..., 0) 在所有退出路径都收割,零泄漏。
 *
 * 4) [截断] char line[1024] + fgets 对超长行会截断成两半,第二半
 *    可能误命中 "hostname: " 字串,解析到垃圾数据。
 *    → 不再按行读,而是一次性 read 全部到 32KB buffer,strtok_r 按 '\n'
 *       切分。单行长度只受 32KB 限制,真机 15KB 总输出远小于此。
 *
 * 5) [匹配精度] grep -iF <mac> 是裸全串匹配,理论上可能命中把 MAC
 *    当 hostname 的设备的其他字段。
 *    → 加约束:同时匹配 "hwAddr: <mac>" 和 "hostname: "。双锚点。
 *
 * 性能影响:
 *   - 正常路径:35ms (dumpsys 本身) + ~1ms (fork/exec/parse) ≈ 36ms
 *     比 popen 版的 35ms 多 1ms,几乎无感
 *   - 超时路径:最多 500ms,然后 SIGKILL + waitpid,主循环恢复
 *     比原版的"无限阻塞"是天壤之别
 *   - 内存:malloc 32KB 一次,退出前 free,无泄漏
 * ══════════════════════════════════════════════════════════ */
static int try_ns_dhcp_resolve(const char *mac, char *out, size_t outlen) {
    if (!mac || mac[0] == '\0') return 0;
    if (!out || outlen == 0) return 0;

    /* v3.7.2 修复 P0-1 (Gemini 发现):严格校验 MAC 字符串长度
     *
     * 原版 v3.7.0:
     *   for (i = 0; mac[i] && i < 17; i++) { 白名单 }
     *   if (i != 17) return 0;
     *
     * 漏洞:输入 "11:22:33:44:55:66;reboot" 时,循环校验前 17 个字符
     * (全合法),i 到达 17 退出循环,if 检查通过。但 mac[17] = ';'
     * 从未被检查,随后被原版 popen 的 %s 拼进 shell 命令导致 RCE。
     *
     * 虽然 v3.7.2 改用 execlp 后不再走 shell(从根本上杜绝了 RCE),
     * 但白名单校验本身的 bug 仍应修复:防御深度 + 下游可能假设 mac 是
     * 严格 17 字符 */
    int i;
    for (i = 0; mac[i] && i < 17; i++) {
        char c = mac[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F') ||
              c == ':')) {
            return 0;
        }
    }
    /* 必须精确 17 字符且第 18 个字符是 '\0' */
    if (i != 17 || mac[17] != '\0') return 0;

    /* ── 1. 创建 pipe + fork ─────────────────────────────── */
    int pipefd[2];
    if (pipe(pipefd) == -1) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        /* 子进程:重定向 stdout/stderr 后 exec dumpsys */
        close(pipefd[0]);                /* 关读端 */
        dup2(pipefd[1], STDOUT_FILENO);  /* stdout → pipe 写端 */
        close(pipefd[1]);

        /* 丢弃 stderr 避免 dumpsys 的 warning 污染父进程 log */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* 直接 exec dumpsys,无 shell 参与,零注入可能 */
        execlp("dumpsys", "dumpsys", "network_stack", (char *)NULL);
        /* exec 失败才会走到这里 */
        _exit(127);
    }

    /* ── 2. 父进程:非阻塞读 pipe,select 超时 500ms ─────── */
    close(pipefd[1]);  /* 父进程不写 pipe */

    /* 设 O_NONBLOCK,配合 select 做超时控制 */
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    /* 分配读缓冲区:dumpsys 实测 ~15KB,32KB 足够覆盖波动
     * 用 malloc 而非栈分配,避免撑爆 hotspotd 主线程的 8KB 栈 */
    const size_t BUF_CAP = 32 * 1024;
    char *buffer = (char *)malloc(BUF_CAP);
    if (!buffer) {
        close(pipefd[0]);
        /* hotfix2: malloc 失败时不要无限等 dumpsys,先杀再收割。 */
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        return 0;
    }

    size_t bytes_read = 0;
    /* v3.7.2: 500ms 总超时
     * 真机 dumpsys 正常 35ms,给 14 倍余量应对 system_server 短时抖动。
     * 超过 500ms 判为"系统卡死",放弃这次查询,避免 hotspotd 被拖死。
     * 这比 Gemini 建议的 150ms 宽松,但仍远低于 pending 路径原来的
     * 800ms(try_mdns_resolve)和"无限阻塞"(popen) */
    const int TIMEOUT_MS = 500;
    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    long deadline_us = (long)deadline.tv_sec * 1000000L + deadline.tv_usec
                       + (long)TIMEOUT_MS * 1000L;

    while (bytes_read < BUF_CAP - 1) {
        /* 计算剩余时间 */
        struct timeval now_tv;
        gettimeofday(&now_tv, NULL);
        long now_us = (long)now_tv.tv_sec * 1000000L + now_tv.tv_usec;
        long remain_us = deadline_us - now_us;
        if (remain_us <= 0) {
            /* 超时:SIGKILL 子进程,下面 waitpid 收割 */
            kill(pid, SIGKILL);
            break;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(pipefd[0], &readfds);

        struct timeval tv;
        tv.tv_sec  = remain_us / 1000000L;
        tv.tv_usec = remain_us % 1000000L;

        int ret = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;  /* 信号打断,重试 */
            break;                          /* 其他错误放弃 */
        }
        if (ret == 0) {
            /* select 超时:SIGKILL + break */
            kill(pid, SIGKILL);
            break;
        }

        if (FD_ISSET(pipefd[0], &readfds)) {
            ssize_t n = read(pipefd[0], buffer + bytes_read,
                            BUF_CAP - bytes_read - 1);
            if (n > 0) {
                bytes_read += (size_t)n;
            } else if (n == 0) {
                break;  /* EOF:子进程退出,数据读完 */
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;  /* read 错误 */
            }
        }
    }
    close(pipefd[0]);
    buffer[bytes_read] = '\0';

    /* v3.7.2: 收割子进程,防僵尸
     * waitpid 会阻塞直到子进程真的退出。如果上面 kill 了 SIGKILL,
     * 子进程几乎立刻就死,waitpid 毫秒级返回。如果是正常 EOF 路径,
     * 子进程本来就退出了,waitpid 立即返回。 */
    int status;
    waitpid(pid, &status, 0);

    /* ── 3. 内存中解析 buffer,找 hostname ──────────────── */
    /* 策略:strtok_r 按 '\n' 切分,每行检查:
     *   条件 A: strcasestr(line, mac) != NULL      // MAC 大小写不敏感
     *   条件 B: strstr(line, "hostname: ") != NULL // 有 hostname 字段
     *
     * v3.7.2 修复 P3-22:原版 popen 走 `grep -iF <mac>` 是裸全串匹配,
     * 理论上可能把包含 MAC 作为其他字段值的行误命中(例如某用户把设备
     * 手动命名为另一台设备的 MAC 字符串)。新版双锚点约束,匹配精度更高。
     *
     * 多行取最新:dumpsys ring buffer 按时间顺序,越后面越新 */
    char latest_hostname[HN_LEN] = "";
    char *saveptr = NULL;
    char *line = strtok_r(buffer, "\n", &saveptr);
    while (line != NULL) {
        /* 双锚点匹配 */
        if (strcasestr(line, mac) != NULL &&
            strstr(line, "hostname: ") != NULL) {

            const char *p = strstr(line, "hostname: ");
            p += 10;  /* 跳过 "hostname: " */

            /* 提取到 \r / , / 行尾 */
            char hn[HN_LEN];
            size_t j = 0;
            while (*p && *p != '\r' && *p != ',' && j < sizeof(hn) - 1) {
                hn[j++] = *p++;
            }
            hn[j] = '\0';

            /* 去尾部空格/tab */
            while (j > 0 && (hn[j-1] == ' ' || hn[j-1] == '\t')) {
                hn[--j] = '\0';
            }

            if (j > 0) {
                strncpy(latest_hostname, hn, sizeof(latest_hostname) - 1);
                latest_hostname[sizeof(latest_hostname) - 1] = '\0';
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(buffer);

    if (latest_hostname[0] != '\0') {
        strncpy(out, latest_hostname, outlen - 1);
        out[outlen - 1] = '\0';
        return 1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
   主函数
══════════════════════════════════════════════════════════ */
/* ══════════════════════════════════════════════════════════
 * v5.0.0-beta.4 hotfix3: SIGSEGV / SIGBUS / SIGABRT handler
 * 立刻把 fault address 落到 stderr (= log file), 不依赖 tombstone
 * ══════════════════════════════════════════════════════════ */
static void hnc_crash_handler(int sig, siginfo_t *info, void *ctx) {
    (void)info;
    (void)ctx;
    /* hotfix2: signal handler 内避免 snprintf/fsync 等非 async-signal-safe 调用。
     * 这里只写固定短消息,然后恢复默认处理器继续生成 tombstone。 */
    static const char msg[] = "\n[FATAL] hotspotd crash; re-raising for tombstone\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char *argv[]) {
    /* 简单参数：-d 后台化，-l <logfile> */
    int daemonize = 0;
    const char *logpath = LOG_FILE;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0)      daemonize = 1;
        else if (strcmp(argv[i], "-l") == 0 && i+1 < argc) logpath = argv[++i];
    }

    /* 后台化 */
    if (daemonize) {
        if (fork() > 0) exit(0);
        setsid();
        if (fork() > 0) exit(0);
        /* 重定向标准 IO
         * v5.0 beta.2: stdin/stdout 扔 /dev/null, stderr 重定向到 logpath,
         * 否则 upstream.c / scheduler.c 的 fprintf(stderr, ...) 日志全部丢黑洞.
         * 真机 RMX5010 alpha.3-beta.1 期间 Tier3 BPF 反查日志永远看不到就是
         * 这个 bug — 整整 5 个版本没排到. */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull,0); dup2(devnull,1); close(devnull); }
        /* stderr 写到日志文件 (同 g_log 路径, 追加模式, line-buffered) */
        int errfd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (errfd >= 0) { dup2(errfd, 2); close(errfd); }
    }
    /* 行缓冲 stderr, 保证每条 fprintf 立即写磁盘 (不等 4KB 块满)
     * beta.2: daemonize 重定向后 stderr 指日志文件, 默认块缓冲看不到实时日志 */
    setvbuf(stderr, NULL, _IOLBF, 0);

    /* v5.0.0-beta.4 hotfix3: 装 SIGSEGV/SIGBUS handler
     * 任何段错先把 fault address 写进日志, 再让 default handler 杀进程生成 tombstone */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = hnc_crash_handler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS,  &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
    }

    /* 日志 */
    g_log = fopen(logpath, "a");
    hlog("=== hotspotd %s started (PID=%d) ===", daemonize?"daemon":"fg", (int)getpid());
    /* v3.5.2 P2-E: g_log 加 FD_CLOEXEC,避免子进程(popen mdns_resolve 等)继承日志 fd */
    if (g_log) fcntl(fileno(g_log), F_SETFD, FD_CLOEXEC);

    /* PID 文件
     * v3.5.2 P1-D: 如果 write_pid 返回 -1(别的实例还活着),直接退出,
     * 跳过 cleanup 避免误删别人的 PID 文件 */
    if (write_pid() < 0) {
        if (g_log) fclose(g_log);
        return 0;  /* 干净退出,不走 cleanup */
    }

    /* 信号 */
    signal(SIGUSR1, sig_usr1);
    signal(SIGTERM, sig_term);
    signal(SIGINT,  sig_term);
    signal(SIGPIPE, SIG_IGN);

    /* Netlink socket */
    g_nl_fd = nl_open();
    if (g_nl_fd < 0) { hlog("FATAL: cannot open netlink"); goto cleanup; }

    /* UNIX socket server */
    g_srv_fd = unix_server_open();
    if (g_srv_fd < 0) { hlog("FATAL: cannot open UNIX socket"); goto cleanup; }

    hlog("Listening on netlink RTGRP_NEIGH + %s", SOCK_PATH);

    /* v3.8.1 A3: 加载持久化 hostname cache
     * 如果文件不存在(首次启动)load 返回 0,正常。
     * 如果加载成功,cache 里的旧记录会在 resolve_hostname 的第 4 级生效,
     * 让重连设备即使 dumpsys ring buffer 滚出也能显示真名。*/
    hnc_cache_init(HOSTNAME_CACHE_JSON);
    int cache_loaded = hnc_cache_load();
    hlog("hostname cache: loaded %d entries from %s",
         cache_loaded, HOSTNAME_CACHE_JSON);

    /* v3.8.3 D3: 加载用户 OUI 覆盖表
     * 如果文件不存在(用户没写过)load 返回 0,正常。
     * 如果加载成功,覆盖表会在 hnc_lookup_oui 的最前面生效,
     * 允许用户给特定前缀打精确标签或覆盖内置表。*/
    hnc_override_init(OUI_OVERRIDE_JSON);
    int override_loaded = hnc_override_load();
    hlog("oui override: loaded %d entries from %s",
         override_loaded, OUI_OVERRIDE_JSON);

    /* v3.8.4: 启动异步 mDNS worker
     *
     * Worker 只处理 re-resolve 路径(scan_arp 里 hnc_should_re_resolve 触发
     * 的 mdns 查询),这些以前会同步阻塞主循环最多 800ms。pending 路径
     * 用的是 resolve_hostname_dhcp_only,不查 mdns,不走 worker。
     *
     * Worker 通过函数指针注入 try_mdns_resolve,这样 mdns_worker.c
     * 不依赖 hotspotd.c 的 static 函数,单元测试可以注入 mock。
     *
     * 如果 worker 启动失败,hlog 警告但不 abort — 主循环可以继续跑,
     * re-resolve 路径会在 enqueue 失败后降级为 mac 兜底。*/
    hnc_mdns_worker_set_resolve_fn(try_mdns_resolve);
    int worker_rc = hnc_mdns_worker_start();
    if (worker_rc != 0) {
        hlog("WARN: mdns worker start failed (rc=%d), re-resolve will fall back to mac",
             worker_rc);
    } else {
        hlog("mdns worker: started (queue size %d)", HNC_MDNS_QUEUE_SIZE);
    }

    /* v5.0: 启动 offload scheduler (探测平台 + 选 adapter + 启 worker)
     *
     * 失败不致命: 内部会自动回落 null adapter, scheduler 仍可用,
     * 只是 disable_upstream / restore_upstream 变成 NOOP。
     * 这样 hotspotd 主路径 (设备扫描 / netlink / unix socket)
     * 完全不受 BPF 异常影响。 */
    int sched_rc = hnc_scheduler_init();
    if (sched_rc != 0) {
        hlog("WARN: scheduler init failed (rc=%d), offload control disabled",
             sched_rc);
    } else {
        hnc_offload_summary_t summ;
        hnc_scheduler_get_summary(&summ);
        hlog("scheduler: started (adapter=%s gran=%d upstream=%s/%d)",
             summ.adapter_name, summ.adapter_gran,
             summ.primary_upstream_ifname, summ.primary_upstream_ifindex);
    }

    /* 初始扫描 */
    scan_arp();

    /* v3.5.0-rc R-1: de-bounce 状态变量
     * dirty_since = 上次 g_dirty 从 0→1 的时刻
     * 主循环规则:dirty 后等 ~500ms 没有新事件才 write_json
     * 注意:用 wall-clock 秒精度,因为 select timeout 200ms 已经够细
     * 写法:dirty=1 且 (now - dirty_since >= 1) 才写,等价于"超过 1s 的 dirty"
     * (Linux time(NULL) 秒精度,所以 1s 是最小可表达 de-bounce 窗口) */
    time_t dirty_since = 0;

    /* v3.5.0-rc2 R-13: 周期性离线清理时间戳
     * hotspotd 是事件驱动的,设备静默离开(关 wifi/出门)不会触发 RTM_DELNEIGH。
     * 之前的离线判断只发生在 write_json 内,而 write_json 只在 dirty 时调用,
     * 结果设备走了之后 devices.json 永远含旧设备(直到 hotspotd 重启)。
     *
     * 修复:主循环每 OFFLINE_CHECK_INTERVAL 秒强制扫一遍 g_devs[],把
     * (now - last_seen) > OFFLINE_THRESHOLD 的设备 active=0,然后 set dirty
     * 触发 write_json 重写文件 */
    #define OFFLINE_CHECK_INTERVAL 30   /* 每 30s 检查一次 */
    #define OFFLINE_THRESHOLD       90   /* 90s 未活跃 = 离线 */
    time_t last_offline_check = time(NULL);

    /* ── 主事件循环 ────────────────────────────────────────── */
    while (g_running) {
        /* 处理 SIGUSR1 */
        if (g_need_scan) {
            g_need_scan = 0;
            hlog("SIGUSR1: manual ARP scan triggered");
            scan_arp();
        }

        /* v3.6 Commit 3: 每次 tick 异步解一个 pending 设备的 mDNS
         * 这解决 v3.5.2 遗留的 P0-B 核心:scan_arp/nl_process 里一批新设备
         * 同时上线时,主线程会被 N × 800ms 的同步 popen 阻塞。
         * 现在新设备只做快速解析,pending 设备由这里每秒处理一个,主线程永不阻塞超过 ~800ms。 */
        process_pending_mdns();

        /* v3.8.4: drain 异步 mDNS worker 的结果
         *
         * Worker 在独立线程完成 mDNS 查询(re-resolve 路径的 800ms 阻塞),
         * 把结果放到结果队列。主循环每 tick 来取一次,把 hostname 写回
         * 对应的 g_devs 条目。g_devs 依然是主线程独占,零锁。
         *
         * 如果某个 MAC 在查询期间已经下线或被别的路径更新,find_device
         * 会返回 NULL 或者已经被写成别的值,此时丢弃结果是安全的。
         *
         * 失败的查询(success=0)会把 hostname_src 从 "pending" 降级到
         * "mac",避免用户在 WebUI 看到永远的 "pending" 标签。*/
        {
            hnc_mdns_result_t mdns_results[HNC_MDNS_QUEUE_SIZE];
            int got = hnc_mdns_worker_drain_results(mdns_results, HNC_MDNS_QUEUE_SIZE);
            for (int i = 0; i < got; i++) {
                Device *d = find_device(mdns_results[i].mac);
                if (!d) continue;  /* 设备已下线或被清理,丢弃结果 */
                /* 只处理当前是 pending 状态的设备,避免覆盖 manual/dhcp
                 * 等更高优先级的结果(如果在查询期间被别的路径改过) */
                if (strcmp(d->hostname_src, "pending") != 0) continue;

                if (mdns_results[i].success) {
                    strncpy(d->hostname, mdns_results[i].hostname, sizeof(d->hostname)-1);
                    d->hostname[sizeof(d->hostname)-1] = '\0';
                    strncpy(d->hostname_src, "mdns", sizeof(d->hostname_src)-1);
                    d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                    /* v3.8.1: 命中 mdns 也更新持久化 cache */
                    hnc_cache_update(d->mac, d->hostname, "mdns");
                    hlog("async mdns: %s → %s", d->mac, d->hostname);
                } else {
                    /* 查询失败,从 pending 降级到 mac 兜底 */
                    hnc_mac_fallback(d->mac, d->hostname, sizeof(d->hostname));
                    strncpy(d->hostname_src, "mac", sizeof(d->hostname_src)-1);
                    d->hostname_src[sizeof(d->hostname_src)-1] = '\0';
                }
                g_dirty = 1;
                g_last_event = time(NULL);
                g_last_event_ms = now_ms_mono();  /* rc30.9 */
            }
        }

        time_t now = time(NULL);

        /* v3.5.0-rc2 R-13: 周期性离线清理 */
        if (now - last_offline_check >= OFFLINE_CHECK_INTERVAL) {
            int evicted = 0;
            for (int i = 0; i < MAX_DEVICES; i++) {
                Device *d = &g_devs[i];
                if (!d->active) continue;
                if (now - d->last_seen > OFFLINE_THRESHOLD) {
                    hlog("OFFLINE: %s (%s) silent for %lds, evicting",
                         d->mac, d->ip, (long)(now - d->last_seen));
                    d->active = 0;
                    evicted++;
                }
            }
            if (evicted > 0) {
                g_dirty = 1;
                g_last_event = now;  /* 也算事件,触发 de-bounce 写入 */
                g_last_event_ms = now_ms_mono();  /* rc30.9 */
            }
            last_offline_check = now;
        }

        /* rc30.9: sub-second de-bounce 算法
         *
         * 旧 (v3.5.0-rc R-1): time(NULL) 秒精度 →  最少等 1 秒才写, 设备
         *   连入感知延迟 1.5-2 秒.
         *
         * 新策略 (毫秒精度, monotonic clock):
         *   (1) 第一次见 dirty 且距上次 write ≥ 500ms  → 立即写
         *       (空闲了一阵, 新事件第一时间反映, 这是用户在意的 case)
         *
         *   (2) 否则进入合并窗口:
         *       - 距上次事件 ≥ 200ms (没新事件了, 可以合并到这里) → 写
         *       - 距首次 dirty ≥ 30000ms (30s 兜底, 防永远 dirty) → 写
         *
         *   (3) 硬限速: 距上次 write < 200ms 时永远不写 (防 ENOBUFS 风暴).
         *
         * 配合 select 超时从 1s/5s 降到 200ms/5s, 让合并窗口的"没新事件"
         * 判断能在 200ms 粒度上触发.
         *
         * 旧 dirty_since (秒级) 保留无用但不删, 避免动其他参考点.
         */
        if (g_dirty) {
            long now_ms = now_ms_mono();
            if (g_dirty_first_ms == 0) {
                g_dirty_first_ms = now_ms;
            }
            long since_last_write = (g_last_write_ms == 0)
                                    ? 1000000L  /* 从未写过, 视为很久没写 */
                                    : (now_ms - g_last_write_ms);
            long since_last_event = (g_last_event_ms == 0)
                                    ? 1000000L
                                    : (now_ms - g_last_event_ms);
            long elapsed_dirty    = now_ms - g_dirty_first_ms;

            int should_write = 0;

            if (since_last_write < 200) {
                /* 硬限速窗口内, 绝不写. 等下次 tick. */
                should_write = 0;
            } else if (elapsed_dirty < 50 && since_last_write >= 500) {
                /* 第一次 dirty (刚 dirty < 50ms) + 上次 write 已过 500ms.
                 * 这是 "用户场景": 设备刚连入 / 操作刚发生. 立即写. */
                should_write = 1;
            } else if (since_last_event >= 200) {
                /* 合并窗口结束: 200ms 没有新事件. 写. */
                should_write = 1;
            } else if (elapsed_dirty >= 30000) {
                /* 30s 兜底 (持续 dirty 也强制 flush). */
                should_write = 1;
            }

            if (should_write) {
                write_json();
                g_last_write_ms = now_ms;
                /* v3.8.1: cache save piggyback (跟 devices.json 共享 fsync 窗口) */
                if (hnc_cache_is_dirty()) {
                    if (hnc_cache_save() != 0) {
                        hlog("WARN: hostname cache save failed: %s", strerror(errno));
                    }
                }
                g_dirty_first_ms = 0;
                dirty_since = 0;  /* legacy, 保留兼容 */
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_nl_fd,  &rfds);
        FD_SET(g_srv_fd, &rfds);
        int maxfd = (g_nl_fd > g_srv_fd ? g_nl_fd : g_srv_fd) + 1;

        /* select timeout: dirty 时 200ms 让 de-bounce 窗口能在毫秒粒度收敛.
         * 非 dirty 时仍 5s 省 CPU.
         * rc30.9: 从 1s/5s 改到 200ms/5s; CPU 增量可忽略 (空 select wakeup ~微秒). */
        struct timeval tv;
        if (g_dirty) {
            tv.tv_sec = 0; tv.tv_usec = 200 * 1000;
        } else {
            tv.tv_sec = 5; tv.tv_usec = 0;
        }
        int ret = select(maxfd, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;  /* 信号打断,正常 */
            hlog("ERROR: select: %s", strerror(errno));
            break;
        }

        if (ret == 0) continue;  /* 超时,继续循环 */

        /* 处理 netlink 事件 */
        if (FD_ISSET(g_nl_fd, &rfds))
            nl_process(g_nl_fd);

        /* 处理 IPC 连接 */
        if (FD_ISSET(g_srv_fd, &rfds)) {
            int cfd = accept(g_srv_fd, NULL, NULL);
            if (cfd >= 0) handle_client(cfd);
        }
    }

cleanup:
    hlog("hotspotd shutting down");
    /* 最后写一次 JSON */
    if (g_dirty) write_json();
    /* v3.8.1: 最后 save 一次 hostname cache,保证关机前的识别结果落盘 */
    if (hnc_cache_is_dirty()) {
        hnc_cache_save();
        hlog("hostname cache: final save on shutdown");
    }

    /* v3.8.4: 停止异步 mDNS worker
     * 幂等,即使 worker 没启动也安全。最多等最后一个任务完成(~800ms)。
     * 必须在关 socket/unlink PID 之前,保证 worker 干净退出后再释放资源。*/
    hnc_mdns_worker_stop();

    /* v5.0: 停 scheduler (停 offload worker + adapter shutdown)
     * 幂等, 必须在关 socket 之前, 让 adapter 干净关 BPF map fd */
    hnc_scheduler_shutdown();

    if (g_nl_fd  >= 0) close(g_nl_fd);
    if (g_srv_fd >= 0) { close(g_srv_fd); unlink(SOCK_PATH); }
    /* v3.5.2 P1-D: 验证 PID 文件是自己的才 unlink */
    cleanup_pid();
    if (g_log) { hlog("=== hotspotd stopped ==="); fclose(g_log); }
    return 0;
}

#endif /* HNC_TEST_MODE */
