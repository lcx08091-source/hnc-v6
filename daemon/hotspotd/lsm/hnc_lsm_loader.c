/* hnc_lsm_loader.c — HNC v5.0 BPF LSM Limit Map Guard 用户态加载器
 *
 * v5.0.0-beta.4 hotfix6: 改为 libbpf 静态链接实现, 替代手撸 sys_bpf 路线
 *
 * 之前手撸版本碰到: BTF sanitize (BPF_BTF_LOAD ENOSPC), CO-RE 重定位, .rel.BTF
 * 等多个深坑. libbpf 的 bpf_object__load() 一行搞定全部这些 (BTF feature
 * detection + sanitize, CO-RE 重定位, map name resolve, prog attach).
 *
 * 链接: 静态 libbpf.a + libelf.a + libz.a (CI 用 NDK toolchain cross-compile).
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "hnc_lsm_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* 控制 map value (跟 .bpf.c 里 struct hnc_lsm_ctrl 严格对齐) */
struct hnc_lsm_ctrl_v {
    uint32_t protected_map_id;
    uint32_t protected_ifindex;
    uint32_t hotspotd_pid;
    uint32_t enabled;
};

/* ringbuf 事件 (跟 .bpf.c 里 struct hnc_lsm_event 严格对齐) */
struct hnc_lsm_event_v {
    uint64_t ts_ns;
    uint32_t caller_pid;
    uint32_t caller_uid;
    uint64_t attempted_value;
    uint32_t ifindex;
    uint32_t verdict;
    char     comm[16];
};

static struct {
    int                  initialized;
    struct bpf_object   *obj;
    struct bpf_program  *prog;
    struct bpf_link     *link;
    struct bpf_map      *ctrl_map;
    struct bpf_map      *events_map;
    int                  ctrl_map_fd;
    int                  events_map_fd;
    int                  target_limit_map_fd;

    struct ring_buffer  *rb;
    pthread_t            rb_thread;
    int                  rb_thread_started;
    int                  rb_should_stop;

    pthread_mutex_t      stat_lock;
    hnc_lsm_status_t     stat;
} g = {
    .ctrl_map_fd = -1,
    .events_map_fd = -1,
    .target_limit_map_fd = -1,
    .stat_lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ══════════════════════════════════════════════════════════
 * 工具
 * ══════════════════════════════════════════════════════════ */

static void set_fail(const char *fmt, ...)
{
    char tmp[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[lsm] FAIL: %s\n", tmp);
    fflush(stderr);
    pthread_mutex_lock(&g.stat_lock);
    g.stat.state = HNC_LSM_FAILED;
    snprintf(g.stat.fail_reason, sizeof(g.stat.fail_reason), "%s", tmp);
    pthread_mutex_unlock(&g.stat_lock);
}

/* libbpf 的 print callback, 把 libbpf 自身的 debug/info 写到 stderr */
static int libbpf_log_cb(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG) return 0;   /* 太吵, 跳过 */
    fprintf(stderr, "[libbpf] ");
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
    return 0;
}

/* 检查 /sys/kernel/security/lsm 是否含 "bpf" */
static int probe_bpf_lsm_active(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return -1;
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    (void)n;
    fclose(f);
    return strstr(buf, "bpf") != NULL ? 1 : 0;
}

/* ══════════════════════════════════════════════════════════
 * Ringbuf consumer
 * ══════════════════════════════════════════════════════════ */

static int ringbuf_handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct hnc_lsm_event_v)) return 0;
    const struct hnc_lsm_event_v *ev = (const struct hnc_lsm_event_v *)data;

    pthread_mutex_lock(&g.stat_lock);
    if (ev->verdict)
        g.stat.deny_count++;
    else
        g.stat.allow_count++;
    g.stat.last_event_ts = (int64_t)time(NULL);
    snprintf(g.stat.last_caller_comm, sizeof(g.stat.last_caller_comm), "%s", ev->comm);
    pthread_mutex_unlock(&g.stat_lock);

    /* v5.1 Plan B: counter-write 策略 — kprobe 只观察, 不能 deny,
     * 这里收到可疑 write 事件 → 立刻写 limit_map[ifindex]=0 盖掉
     * framework 刚写的 U64_MAX, 切断 fast path */
    if (ev->verdict && g.target_limit_map_fd >= 0) {
        uint32_t key = ev->ifindex;
        uint64_t zero = 0;
        int rc = bpf_map_update_elem(g.target_limit_map_fd, &key, &zero, BPF_ANY);
        uint64_t now_ns;
        {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        }
        uint64_t latency_us = (now_ns - ev->ts_ns) / 1000;
        fprintf(stderr,
                "[lsm] COUNTER-WRITE: comm=%s pid=%u ifindex=%u val=0x%llx "
                "rewrite=%s latency=%lluus\n",
                ev->comm, ev->caller_pid, ev->ifindex,
                (unsigned long long)ev->attempted_value,
                rc == 0 ? "OK" : strerror(errno),
                (unsigned long long)latency_us);
    }
    return 0;
}

static void *ringbuf_thread(void *arg)
{
    (void)arg;
    while (!g.rb_should_stop) {
        int n = ring_buffer__poll(g.rb, 200);   /* 200ms timeout */
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[lsm] ringbuf poll error: %d\n", n);
            break;
        }
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════ */

int hnc_lsm_init(const char *bpf_object_path,
                 const char *target_limit_map_path,
                 uint32_t initial_ifindex)
{
    if (g.initialized) return 0;
    g.stat.state = HNC_LSM_DISABLED;
    g.stat.hotspotd_pid = (uint32_t)getpid();

    libbpf_set_print(libbpf_log_cb);

    /* ─── Step 1: 检测 BPF LSM 可用(仅 info,不 gate) ─────
     * rc2 修 B4:
     *   原代码:probe 不到 BPF LSM → return -2 → kprobe 路径被堵死.
     *   这与 Plan B 的存在理由矛盾 (见 hnc_limit_map_guard.bpf.c 头注释):
     *   kprobe 依赖 CONFIG_KPROBES (ColorOS 保留), 不需要 BPF LSM
     *   在 /sys/kernel/security/lsm 里.
     *   现在: probe 只打日志, 失败不返回, 让 Step 7 attach_kprobe 自己决定. */
    int rc = probe_bpf_lsm_active();
    if (rc < 0) {
        if (mount("none", "/sys/kernel/security", "securityfs", 0, NULL) != 0
            && errno != EBUSY) {
            fprintf(stderr, "[lsm] step1: securityfs mount failed: %s "
                            "(continuing, Plan B does not require it)\n",
                    strerror(errno));
        } else {
            rc = probe_bpf_lsm_active();
        }
    }
    if (rc == 1) {
        fprintf(stderr, "[lsm] step1: BPF LSM present in kernel (info)\n");
    } else {
        fprintf(stderr, "[lsm] step1: BPF LSM NOT listed in "
                        "/sys/kernel/security/lsm; Plan B uses kprobe, "
                        "continuing to Step 7\n");
    }
    fflush(stderr);

    /* ─── Step 2: 拿目标 limit_map 的 map_id ───────────── */
    int fd = bpf_obj_get(target_limit_map_path);
    if (fd < 0) {
        set_fail("bpf_obj_get(%s): %s", target_limit_map_path, strerror(errno));
        return -1;
    }
    g.target_limit_map_fd = fd;

    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
        set_fail("bpf_obj_get_info_by_fd: %s", strerror(errno));
        return -1;
    }
    pthread_mutex_lock(&g.stat_lock);
    g.stat.protected_map_id = info.id;
    g.stat.protected_ifindex = initial_ifindex;
    pthread_mutex_unlock(&g.stat_lock);
    fprintf(stderr, "[lsm] step2: target limit_map id=%u\n", info.id); fflush(stderr);

    /* ─── Step 3: bpf_object__open_file ─────────────────── */
    fprintf(stderr, "[lsm] step3: bpf_object__open_file(%s)\n", bpf_object_path);
    fflush(stderr);
    g.obj = bpf_object__open_file(bpf_object_path, NULL);
    if (!g.obj || libbpf_get_error(g.obj)) {
        long err = libbpf_get_error(g.obj);
        set_fail("bpf_object__open_file: %s", strerror(-err));
        g.obj = NULL;
        return -1;
    }
    fprintf(stderr, "[lsm] step3: open OK\n"); fflush(stderr);

    /* ─── Step 4: bpf_object__load (BTF sanitize + CO-RE + verifier) ──── */
    fprintf(stderr, "[lsm] step4: bpf_object__load (libbpf 处理 BTF / CO-RE / verifier)\n");
    fflush(stderr);
    int load_err = bpf_object__load(g.obj);
    if (load_err) {
        set_fail("bpf_object__load: %s", strerror(-load_err));
        bpf_object__close(g.obj);
        g.obj = NULL;
        return -1;
    }
    fprintf(stderr, "[lsm] step4: load OK\n"); fflush(stderr);

    /* ─── Step 5: 拿 prog / map handles ─────────────────── */
    g.prog = bpf_object__find_program_by_name(g.obj, "hnc_check_bpf");
    if (!g.prog) {
        set_fail("find prog 'hnc_check_bpf' failed");
        bpf_object__close(g.obj); g.obj = NULL;
        return -1;
    }
    g.ctrl_map = bpf_object__find_map_by_name(g.obj, "hnc_ctrl_map");
    g.events_map = bpf_object__find_map_by_name(g.obj, "hnc_lsm_events");
    if (!g.ctrl_map || !g.events_map) {
        set_fail("find map ctrl/events failed");
        bpf_object__close(g.obj); g.obj = NULL;
        return -1;
    }
    g.ctrl_map_fd = bpf_map__fd(g.ctrl_map);
    g.events_map_fd = bpf_map__fd(g.events_map);
    fprintf(stderr, "[lsm] step5: prog + maps resolved (ctrl_fd=%d events_fd=%d)\n",
            g.ctrl_map_fd, g.events_map_fd);
    fflush(stderr);

    /* ─── Step 6: populate ctrl map ─────────────────────── */
    {
        struct hnc_lsm_ctrl_v v = {
            .protected_map_id  = g.stat.protected_map_id,
            .protected_ifindex = initial_ifindex,
            .hotspotd_pid      = (uint32_t)getpid(),
            .enabled           = 1,
        };
        uint32_t k = 0;
        if (bpf_map_update_elem(g.ctrl_map_fd, &k, &v, BPF_ANY) != 0) {
            set_fail("populate ctrl: %s", strerror(errno));
            bpf_object__close(g.obj); g.obj = NULL;
            return -1;
        }
        fprintf(stderr, "[lsm] step6: ctrl populated\n"); fflush(stderr);
    }

    /* ─── Step 7: attach kprobe to security_bpf ───────────────
     * v5.1 Plan B: ColorOS kernel 禁用 CONFIG_FUNCTION_TRACER,
     * BPF LSM / fentry attach 全部 -ENOTSUPP。改用 kprobe
     * (CONFIG_KPROBES=y,ColorOS 保留)。kprobe 只观察,
     * userspace 通过 ringbuf 收到事件后毫秒级 counter-write。 */
    fprintf(stderr, "[lsm] step7: bpf_program__attach_kprobe(security_bpf)\n");
    fflush(stderr);
    g.link = bpf_program__attach_kprobe(g.prog, false /* retprobe=false */,
                                         "security_bpf");
    if (!g.link || libbpf_get_error(g.link)) {
        long err = libbpf_get_error(g.link);
        set_fail("attach_kprobe: %s", strerror(-err));
        g.link = NULL;
        bpf_object__close(g.obj); g.obj = NULL;
        return -1;
    }
    fprintf(stderr, "[lsm] step7: kprobe attached to security_bpf\n");
    fflush(stderr);

    /* ─── Step 8: 启 ringbuf consumer 线程 ──────────────── */
    g.rb = ring_buffer__new(g.events_map_fd, ringbuf_handle_event, NULL, NULL);
    if (!g.rb) {
        set_fail("ring_buffer__new: %s", strerror(errno));
        bpf_link__destroy(g.link); g.link = NULL;
        bpf_object__close(g.obj); g.obj = NULL;
        return -1;
    }
    g.rb_should_stop = 0;
    if (pthread_create(&g.rb_thread, NULL, ringbuf_thread, NULL) != 0) {
        fprintf(stderr, "[lsm] WARN: ringbuf thread start failed\n");
    } else {
        g.rb_thread_started = 1;
    }
    fprintf(stderr, "[lsm] step8: ringbuf consumer started\n"); fflush(stderr);

    pthread_mutex_lock(&g.stat_lock);
    g.stat.state = HNC_LSM_ACTIVE;
    g.stat.fail_reason[0] = 0;
    pthread_mutex_unlock(&g.stat_lock);

    g.initialized = 1;
    fprintf(stderr, "[lsm] ACTIVE. protecting map_id=%u ifindex=%u hotspotd_pid=%u\n",
            g.stat.protected_map_id, initial_ifindex, (uint32_t)getpid());
    fflush(stderr);
    return 0;
}

int hnc_lsm_update_ifindex(uint32_t new_ifindex)
{
    if (!g.initialized || g.ctrl_map_fd < 0) return -1;
    struct hnc_lsm_ctrl_v v;
    uint32_t k = 0;
    if (bpf_map_lookup_elem(g.ctrl_map_fd, &k, &v) != 0) return -1;
    v.protected_ifindex = new_ifindex;
    if (bpf_map_update_elem(g.ctrl_map_fd, &k, &v, BPF_ANY) != 0) return -1;
    pthread_mutex_lock(&g.stat_lock);
    g.stat.protected_ifindex = new_ifindex;
    pthread_mutex_unlock(&g.stat_lock);
    fprintf(stderr, "[lsm] ifindex updated to %u\n", new_ifindex);
    return 0;
}

void hnc_lsm_shutdown(void)
{
    if (!g.initialized) return;

    g.rb_should_stop = 1;
    if (g.rb_thread_started) {
        pthread_join(g.rb_thread, NULL);
        g.rb_thread_started = 0;
    }
    if (g.rb) { ring_buffer__free(g.rb); g.rb = NULL; }
    if (g.link) { bpf_link__destroy(g.link); g.link = NULL; }
    if (g.obj) { bpf_object__close(g.obj); g.obj = NULL; }
    if (g.target_limit_map_fd >= 0) { close(g.target_limit_map_fd); g.target_limit_map_fd = -1; }

    g.initialized = 0;
    fprintf(stderr, "[lsm] shutdown complete\n");
}

void hnc_lsm_get_status(hnc_lsm_status_t *out)
{
    if (!out) return;
    pthread_mutex_lock(&g.stat_lock);
    *out = g.stat;
    pthread_mutex_unlock(&g.stat_lock);
}

int hnc_lsm_status_to_json_fragment(const hnc_lsm_status_t *st,
                                     char *buf, size_t buf_size)
{
    if (!st || !buf) return -1;
    const char *state_str =
        (st->state == HNC_LSM_ACTIVE)   ? "active"   :
        (st->state == HNC_LSM_FAILED)   ? "failed"   :
        (st->state == HNC_LSM_DISABLED) ? "disabled" : "unknown";

    int n = snprintf(buf, buf_size,
        "\"lsm\":{"
        "\"state\":\"%s\","
        "\"protected_map_id\":%u,"
        "\"protected_ifindex\":%u,"
        "\"hotspotd_pid\":%u,"
        "\"deny_count\":%llu,"
        "\"allow_count\":%llu,"
        "\"last_event_ts\":%lld,"
        "\"last_caller\":\"%s\","
        "\"fail_reason\":\"%s\""
        "}",
        state_str,
        st->protected_map_id,
        st->protected_ifindex,
        st->hotspotd_pid,
        (unsigned long long)st->deny_count,
        (unsigned long long)st->allow_count,
        (long long)st->last_event_ts,
        st->last_caller_comm,
        st->fail_reason);

    if (n < 0 || (size_t)n >= buf_size) return -1;
    return n;
}
