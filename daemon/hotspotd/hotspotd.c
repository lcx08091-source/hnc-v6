/*
 * hotspotd.c — HNC 硬件加速兜底 + 控制接口 C daemon
 *
 * v5.33 起设备发现只有 Go 版(看门狗 src/dpid/cmd/hnc_watchdog/m4_owner.go 的
 * 写者 + src/dpid/devscan / devname), hotspotd 原来的 C 版发现(邻居表事件 /
 * ARP 全量扫描 / 名字解析 / mDNS worker / 写 devices.json 与 hostname_cache.json)
 * 整块删除。剩下:
 *   - offload 调度(scheduler.c / upstream.c / BPF limit_map); netlink 只订阅
 *     RTMGRP_LINK —— 链路变化(WiFi↔4G、VPN 上下线)即时请求重探主上游;
 *   - UNIX socket 控制接口:
 *       GET_DEVICES        原样转发 data/devices.json(Go 写者的文件)
 *       REFRESH            touch run/devices.refresh(Go 写者看到就立刻全量扫)
 *       STATUS             "running:1 devices:N pid:P"(N 数 devices.json)
 *       OFFLOAD_NOTIFY_LIMIT <mac> <0|1> / OFFLOAD_REFRESH / OFFLOAD_STATUS /
 *       OFFLOAD_DISABLE_GLOBAL / OFFLOAD_RESTORE_GLOBAL
 *       QUIT
 *   - SIGUSR1 = REFRESH(旧调用方兼容)。
 * 旧参数 --no-discovery(v5.31–v5.32 的看门狗 / device_detect.sh 会带)照收不报错,
 * 现在本来就不发现。
 *
 * 编译：见 daemon/hotspotd/build.sh
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "scheduler.h"       /* v5.0: offload 调度核心 */

#ifndef HNC_VERSION
#define HNC_VERSION         "dev"
#endif

/* ── 路径与限制常量 ────────────────────────────────────────── */
#define HNC_DIR             "/data/local/hnc"
#define SOCK_PATH           HNC_DIR "/run/hotspotd.sock"
#define DEVICES_JSON        HNC_DIR "/data/devices.json"
#define REFRESH_FILE        HNC_DIR "/run/devices.refresh"
#define LOG_FILE            HNC_DIR "/logs/hotspotd.log"
#define PID_FILE            HNC_DIR "/run/hotspotd.pid"

#define HNC_LOG_MAX_BYTES   (4LL * 1024LL * 1024LL)
#define IPC_RD_TIMEOUT_MS   2000LL
#define IPC_TOT_TIMEOUT_MS  5000LL
#define NL_BATCH_PKT_CAP    64

/* 单测改路径用(test/test_hotspotd_ipc.c); 生产 = 上面的常量 */
static const char *g_devices_path = DEVICES_JSON;
static const char *g_refresh_path = REFRESH_FILE;

static FILE *g_log    = NULL;

/* ── 信号标志（volatile sig_atomic_t 保证信号安全）────────── */
static volatile sig_atomic_t g_need_refresh = 0;  /* SIGUSR1 → touch run/devices.refresh */
static volatile sig_atomic_t g_running      = 1;  /* 0=退出主循环 */

static int64_t mono_ms_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000L);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + (int64_t)(tv.tv_usec / 1000L);
}

/* ══════════════════════════════════════════════════════════
   日志 (超 4MB 自动 ftruncate 自救)
══════════════════════════════════════════════════════════ */
static void maybe_truncate_log(void) {
    if (!g_log) return;
    int lfd = fileno(g_log);
    if (lfd < 0) return;
    struct stat lst;
    if (fstat(lfd, &lst) == 0 && (int64_t)lst.st_size > HNC_LOG_MAX_BYTES) {
        fflush(g_log);
        if (ftruncate(lfd, 0) == 0)
            (void)lseek(lfd, 0, SEEK_SET);
    }
}

static void hlog(const char *fmt, ...) {
    if (!g_log) return;
    maybe_truncate_log();
    time_t t = time(NULL);
    struct tm tm_buf;
    char buf[32];
    localtime_r(&t, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(g_log, "[%s] [HOTSPOTD] ", buf);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

/* ══════════════════════════════════════════════════════════
   Netlink：只订阅链路事件(offload 重探主上游)
══════════════════════════════════════════════════════════ */
static void nl_process(int fd) {
    _Alignas(8) uint8_t buf[8192];
    /* 单轮最多处理 64 包, 防止链路事件风暴饿死 IPC / SIGTERM;
     * 剩余事件留待下一轮 poll 唤醒继续抽干。 */
    for (int pkt = 0; pkt < NL_BATCH_PKT_CAP && g_running; pkt++) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == ENOBUFS) {
                /* 丢了链路事件: 重探一次兜底 */
                hlog("WARN: netlink ENOBUFS, requesting offload refresh");
                hnc_scheduler_request_refresh();
            } else {
                hlog("WARN: netlink recv: %s", strerror(errno));
            }
            return;
        }
        if (n == 0) return;

        size_t rem = (size_t)n;
        for (size_t off = 0; rem >= sizeof(struct nlmsghdr); ) {
            struct nlmsghdr nlh;
            memcpy(&nlh, buf + off, sizeof(nlh));
            if (nlh.nlmsg_len < sizeof(struct nlmsghdr) || (size_t)nlh.nlmsg_len > rem)
                break;
            size_t step = NLMSG_ALIGN(nlh.nlmsg_len);
            if (step > rem)
                step = rem;
            off += step;
            rem -= step;
            if (nlh.nlmsg_type == RTM_NEWLINK || nlh.nlmsg_type == RTM_DELLINK) {
                hnc_scheduler_request_refresh();
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════
   UNIX Socket Server（IPC）
══════════════════════════════════════════════════════════ */

/* v5.31 T4: touch run/devices.refresh —— Go 写者(看门狗 m4_owner.go)每拍看
 * 它的 mtime, 变了就立刻全量扫一次并写 devices.json。open(O_CREAT) +
 * futimens 更新 mtime; 失败只记日志(「立即扫描」是加速项, 不是正确性
 * 依赖 —— Go 每 30 秒本来就有全量兜底)。
 * v5.33: device_detect.sh scan 自己写这个文件(带 nonce 等回执), 这里只给
 * REFRESH / SIGUSR1 的旧调用方用。 */
static void touch_refresh_file(void) {
    int fd = open(g_refresh_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        hlog("WARN: cannot touch %s: %s", g_refresh_path, strerror(errno));
        return;
    }
    struct timespec ts[2];
    clock_gettime(CLOCK_REALTIME, &ts[0]);
    ts[1] = ts[0];
    if (futimens(fd, ts) != 0) {
        hlog("WARN: futimens %s: %s", g_refresh_path, strerror(errno));
    }
    close(fd);
}

/* STATUS 的 devices:N 从 devices.json 数 —— 不解析 JSON(那是 Go 写者的文件),
 * 数 "mac":" 字面量出现次数(devices.json 每台设备恰好一个 mac 字段)。
 * devices.json 正常 < 32KB, 上限 1MB, 超限/不存在/读失败 → 0。展示用途,
 * 不做正确性判断。路径参数化给单测用。 */
static int count_devices_in_file_at(const char *path) {
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    long sz = 0;
    if (fseek(f, 0, SEEK_END) == 0) { sz = ftell(f); if (sz < 0) sz = 0; rewind(f); }
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return 0; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    const char pat[] = "\"mac\":\"";
    const size_t patlen = sizeof(pat) - 1;
    int n = 0;
    const char *p = buf;
    while ((p = strstr(p, pat)) != NULL) {
        n++;
        p += patlen;
    }
    free(buf);
    return n;
}

/* 基于 CLOCK_MONOTONIC 总截止时间与 g_running 的写辅助, 彻底防止慢速客户端逐字节拖死主线程 */
static int send_all_deadline(int fd, const void *buf, size_t len, int64_t deadline_ms) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len && g_running) {
        int64_t rem_ms = deadline_ms - mono_ms_now();
        if (rem_ms <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int wait_ms = (rem_ms > 500LL) ? 500 : (int)rem_ms;
            struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
            int prc = poll(&pfd, 1, wait_ms);
            if (prc == 0) continue;
            if (prc < 0 && errno == EINTR) continue;
            if (prc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                return -1;
            continue;
        }
        return -1;
    }
    return (off == len) ? 0 : -1;
}

static void handle_client(int cfd) {
    int64_t start_ms        = mono_ms_now();
    int64_t rd_deadline_ms  = start_ms + IPC_RD_TIMEOUT_MS;
    int64_t tot_deadline_ms = start_ms + IPC_TOT_TIMEOUT_MS;

    struct timeval tv_rd = {.tv_sec = 2, .tv_usec = 0};
    struct timeval tv_wr = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv_rd, sizeof(tv_rd));
    (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv_wr, sizeof(tv_wr));

    if (geteuid() == 0) {
        struct ucred cred;
        socklen_t clen = (socklen_t)sizeof(cred);
        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 ||
            clen != (socklen_t)sizeof(cred) || cred.uid != 0) {
            close(cfd);
            return;
        }
    }

    char req[64] = {0};
    size_t got = 0;
    int has_nl = 0;
    while (got < sizeof(req) - 1 && g_running) {
        int64_t rem_ms = rd_deadline_ms - mono_ms_now();
        if (rem_ms <= 0) break;

        ssize_t n = recv(cfd, req + got, sizeof(req) - 1 - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
            req[got] = '\0';
            char *nl = strchr(req, '\n');
            if (nl != NULL) {
                *nl = '\0';
                has_nl = 1;
                break;
            }
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int wait_ms = (rem_ms > 500LL) ? 500 : (int)rem_ms;
            struct pollfd pfd = { .fd = cfd, .events = POLLIN, .revents = 0 };
            int prc = poll(&pfd, 1, wait_ms);
            if (prc == 0) continue;
            if (prc < 0 && errno == EINTR) continue;
            if (prc < 0 || (pfd.revents & (POLLERR | POLLNVAL)))
                break;
            continue;
        }
        break;
    }
    if (got == 0 || !g_running) { close(cfd); return; }
    if (!has_nl) {
        (void)send_all_deadline(cfd, "ERR:incomplete command\n", 23, tot_deadline_ms);
        close(cfd);
        return;
    }
    /* 去尾部空白 */
    for (int i = (int)strlen(req)-1; i >= 0 && (req[i]=='\n'||req[i]=='\r'||req[i]==' '); i--)
        req[i] = '\0';

    if (strcmp(req, "GET_DEVICES") == 0) {
        /* 直接发 JSON 文件内容(Go 写者的 devices.json) */
        FILE *f = fopen(g_devices_path, "re");
        if (!f) { (void)send_all_deadline(cfd, "{}", 2, tot_deadline_ms); }
        else {
            char fbuf[65536];
            size_t rd;
            size_t sent_tot = 0;
            while (g_running && sent_tot < (size_t)HNC_LOG_MAX_BYTES &&
                   (rd = fread(fbuf, 1, sizeof(fbuf), f)) > 0) {
                if (mono_ms_now() >= tot_deadline_ms) break;
                if (send_all_deadline(cfd, fbuf, rd, tot_deadline_ms) != 0) break;
                sent_tot += rd;
            }
            fclose(f);
        }
    } else if (strcmp(req, "REFRESH") == 0) {
        touch_refresh_file();
        (void)send_all_deadline(cfd, "OK:queued\n", 10, tot_deadline_ms);
    } else if (strcmp(req, "STATUS") == 0) {
        char resp[128];
        snprintf(resp, sizeof(resp), "running:1 devices:%d pid:%d\n",
                 count_devices_in_file_at(g_devices_path), (int)getpid());
        (void)send_all_deadline(cfd, resp, strlen(resp), tot_deadline_ms);
    } else if (strncmp(req, "OFFLOAD_NOTIFY_LIMIT ", 21) == 0) {
        /* v5.0: OFFLOAD_NOTIFY_LIMIT <mac> <0|1>
         * apply_device_rule.sh 在 tc 规则添加/删除后调 */
        char mac[32] = {0};
        int  flag    = -1;
        if (sscanf(req + 21, "%31s %d", mac, &flag) == 2 &&
            (flag == 0 || flag == 1)) {
            hnc_scheduler_notify_device_limit_changed(mac, flag);
            (void)send_all_deadline(cfd, "OK\n", 3, tot_deadline_ms);
        } else {
            (void)send_all_deadline(cfd, "ERR:bad args (expect MAC 0|1)\n", 30, tot_deadline_ms);
        }
    } else if (strcmp(req, "OFFLOAD_REFRESH") == 0) {
        hnc_scheduler_request_refresh();
        (void)send_all_deadline(cfd, "OK:queued\n", 10, tot_deadline_ms);
    } else if (strcmp(req, "OFFLOAD_STATUS") == 0) {
        hnc_offload_summary_t summ;
        hnc_scheduler_get_summary(&summ);
        char json[2048];
        int jlen = hnc_scheduler_summary_to_json(&summ, json, sizeof(json));
        if (jlen > 0) {
            if (send_all_deadline(cfd, json, (size_t)jlen, tot_deadline_ms) == 0)
                (void)send_all_deadline(cfd, "\n", 1, tot_deadline_ms);
        } else {
            (void)send_all_deadline(cfd, "ERR:summary serialize\n", 22, tot_deadline_ms);
        }
    } else if (strcmp(req, "OFFLOAD_DISABLE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_disable_global();
        char resp[64];
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 (e == OFFLOAD_OK || e == OFFLOAD_EEMPTY) ? "OK" : "ERR",
                 offload_err_str(e));
        (void)send_all_deadline(cfd, resp, strlen(resp), tot_deadline_ms);
    } else if (strcmp(req, "OFFLOAD_RESTORE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_restore_global();
        char resp[64];
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 (e == OFFLOAD_OK || e == OFFLOAD_EEMPTY) ? "OK" : "ERR",
                 offload_err_str(e));
        (void)send_all_deadline(cfd, resp, strlen(resp), tot_deadline_ms);
    } else if (strcmp(req, "QUIT") == 0) {
        (void)send_all_deadline(cfd, "BYE\n", 4, tot_deadline_ms);
        g_running = 0;
    } else {
        (void)send_all_deadline(cfd, "ERR:unknown command\n", 20, tot_deadline_ms);
    }
    close(cfd);
}

/* ══════════════════════════════════════════════════════════
 * 以下只给生产 main 用(打开 socket / 信号 / PID 文件 / main)。
 * 单测(#define HNC_TEST_MODE 后 #include 本文件, 见 test/test_hotspotd_ipc.c)
 * 自带 main, 只测上面的 nl_process / handle_client / count_devices_in_file_at。
 * ══════════════════════════════════════════════════════════ */
#ifndef HNC_TEST_MODE

/* ── 全局 fd ──────────────────────────────────────────────── */
static int  g_nl_fd   = -1;   /* netlink socket(RTMGRP_LINK), -1 when degraded */
static int  g_srv_fd  = -1;   /* UNIX socket server */

static void write_best_effort(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void)write(fd, val, strlen(val));
    close(fd);
}

static void harden_daemon_process(void) {
    /* 防 LMKD 误杀 (-900) 并尽力迁入根 cgroup 逃离 app freezer / cached cgroup */
    write_best_effort("/proc/self/oom_score_adj", "-900\n");

    char pid_buf[32];
    snprintf(pid_buf, sizeof(pid_buf), "%d\n", (int)getpid());
    int cg_fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (cg_fd >= 0) {
        ssize_t w = write(cg_fd, pid_buf, strlen(pid_buf));
        close(cg_fd);
        if (w > 0) return;
    }
    write_best_effort("/dev/cg2_bpf/cgroup.procs", pid_buf);
}

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) { hlog("WARN: netlink socket unavailable: %s", strerror(errno)); return -1; }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        /* rc43 (P2-17): RTMGRP_LINK —— 监听 iface 链路状态变化(WiFi↔4G 切换、
         * VPN tun 上下线等),用来即时通知 offload 调度器重探主上游,把原来最坏 60s
         * 的"换网后限速对新上游短暂失效"窗口缩到瞬时。
         * v5.33: 设备发现归 Go 看门狗, 不再订阅邻居表事件。 */
        .nl_groups = RTMGRP_LINK,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        hlog("WARN: netlink bind unavailable: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int unix_server_open(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { hlog("ERROR: unix socket: %s", strerror(errno)); return -1; }

    struct sockaddr_un su = {.sun_family = AF_UNIX};
    strncpy(su.sun_path, SOCK_PATH, sizeof(su.sun_path)-1);
    /* 此时已持有 PID 文件内核级 flock 排他锁，可安全清理死进程残留套接字；
     * bind 前临时设 umask(0077)，使套接字节点落盘瞬间即为 0600，彻底消除 bind->chmod 竞态窗口 */
    unlink(SOCK_PATH);
    mode_t old_mask = umask(0077);
    int brc = bind(fd, (struct sockaddr *)&su, sizeof(su));
    umask(old_mask);
    if (brc < 0) {
        hlog("ERROR: unix bind: %s", strerror(errno));
        close(fd); return -1;
    }
    if (listen(fd, 8) < 0) {
        hlog("ERROR: unix listen: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}


/* ══════════════════════════════════════════════════════════
   信号处理
══════════════════════════════════════════════════════════ */
static void sig_usr1(int s) { (void)s; g_need_refresh = 1; }
static void sig_term(int s) { (void)s; g_running      = 0; }

/* ══════════════════════════════════════════════════════════
   PID 文件 (flock + st_dev/st_ino 一致性校验防 unlink 孤岛双实例)
══════════════════════════════════════════════════════════ */
static int g_pid_lock_fd = -1;

static int write_pid(void) {
    for (int attempt = 0; attempt < 4; attempt++) {
        int fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (fd < 0) {
            hlog("ERROR: cannot open PID file: %s", strerror(errno));
            return -1;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
            close(fd);
            hlog("ERROR: another hotspotd instance holds PID flock, exiting");
            return -1;
        }
        struct stat st_fd, st_path;
        if (fstat(fd, &st_fd) != 0 || stat(PID_FILE, &st_path) != 0 ||
            st_fd.st_dev != st_path.st_dev || st_fd.st_ino != st_path.st_ino) {
            close(fd);
            continue; /* 并发旧实例刚 unlink 了该孤岛 inode, 重试打开当前路径 */
        }
        if (ftruncate(fd, 0) == 0) {
            (void)lseek(fd, 0, SEEK_SET);
            char buf[32];
            int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
            if (n <= 0 || write(fd, buf, (size_t)n) != n) {
                hlog("WARN: write PID file short/failed: %s", strerror(errno));
            }
        }
        g_pid_lock_fd = fd; /* 随进程生命周期保持打开 */
        return 0;
    }
    hlog("ERROR: failed to acquire stable inode lock on %s", PID_FILE);
    return -1;
}

static void cleanup_pid(void) {
    if (g_pid_lock_fd >= 0) {
        struct stat st_fd, st_path;
        if (fstat(g_pid_lock_fd, &st_fd) == 0 &&
            stat(PID_FILE, &st_path) == 0 &&
            st_fd.st_dev == st_path.st_dev &&
            st_fd.st_ino == st_path.st_ino) {
            unlink(PID_FILE);
        }
        close(g_pid_lock_fd);
        g_pid_lock_fd = -1;
    }
}


/* ══════════════════════════════════════════════════════════
 * v5.0.0-beta.4 hotfix3: SIGSEGV / SIGBUS / SIGABRT handler
 * 立刻把 fault address 落到 stderr (= log file), 不依赖 tombstone
 * ══════════════════════════════════════════════════════════ */
static struct sigaction g_orig_sigsegv;
static struct sigaction g_orig_sigbus;
static struct sigaction g_orig_sigabrt;

static void hnc_crash_handler(int sig, siginfo_t *info, void *ctx) {
    int saved_errno = errno;
    static const char msg[] = "\n[FATAL] hotspotd crash; chaining for tombstone\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);

    const struct sigaction *orig = NULL;
    if (sig == SIGSEGV)      orig = &g_orig_sigsegv;
    else if (sig == SIGBUS)  orig = &g_orig_sigbus;
    else if (sig == SIGABRT) orig = &g_orig_sigabrt;

    /* Chain to Android Bionic's debuggerd handler if installed so tombstones
     * capture exact faulting registers/PC; otherwise restore SIG_DFL & unblock. */
    if (orig && (orig->sa_flags & SA_SIGINFO) && orig->sa_sigaction &&
        orig->sa_sigaction != hnc_crash_handler) {
        sigaction(sig, orig, NULL);
        errno = saved_errno;
        orig->sa_sigaction(sig, info, ctx);
    }

    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, NULL);

    sigset_t unblk;
    sigemptyset(&unblk);
    sigaddset(&unblk, sig);
    sigprocmask(SIG_UNBLOCK, &unblk, NULL);
    errno = saved_errno;
    raise(sig);
}

int main(int argc, char *argv[]) {
    /* 简单参数：--version 输出版本，-d 后台化，-l <logfile>；--no-discovery 照收 */
    int daemonize = 0;
    const char *logpath = LOG_FILE;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("hotspotd %s\n", HNC_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "-d") == 0)      daemonize = 1;
        else if (strcmp(argv[i], "--no-discovery") == 0) { /* 旧参数, 忽略 */ }
        else if (strcmp(argv[i], "-l") == 0 && i+1 < argc) logpath = argv[++i];
    }

    /* 后台化 */
    if (daemonize) {
        pid_t p1 = fork();
        if (p1 < 0) { perror("hotspotd: fork1"); return 1; }
        if (p1 > 0) _exit(0);
        (void)setsid();
        pid_t p2 = fork();
        if (p2 < 0) { perror("hotspotd: fork2"); _exit(1); }
        if (p2 > 0) _exit(0);

        int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        int errfd = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (errfd >= 0) {
            dup2(errfd, STDERR_FILENO);
            if (errfd > STDERR_FILENO) close(errfd);
        }
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
        sigaction(SIGSEGV, &sa, &g_orig_sigsegv);
        sigaction(SIGBUS,  &sa, &g_orig_sigbus);
        sigaction(SIGABRT, &sa, &g_orig_sigabrt);
    }

    /* 日志 */
    g_log = fopen(logpath, "ae");
    hlog("=== hotspotd %s (%s) started (PID=%d) ===",
         HNC_VERSION, daemonize ? "daemon" : "fg", (int)getpid());
    hlog("offload + control socket only (device discovery is the Go watchdog's)");
    /* v3.5.2 P2-E: g_log 加 FD_CLOEXEC,避免子进程继承日志 fd */
    if (g_log) fcntl(fileno(g_log), F_SETFD, FD_CLOEXEC);

    /* PID 文件: 若别的实例还活着则直接干净退出, 跳过 cleanup */
    if (write_pid() < 0) {
        if (g_log) fclose(g_log);
        return 0;
    }

    harden_daemon_process();

    /* 信号 (sigaction 无 SA_RESTART, 确保 SIGTERM/SIGINT/SIGHUP 即时打断阻塞调用) */
    {
        struct sigaction sa_t, sa_u, sa_ign;
        memset(&sa_t, 0, sizeof(sa_t));
        sa_t.sa_handler = sig_term;
        sigemptyset(&sa_t.sa_mask);
        sigaction(SIGTERM, &sa_t, NULL);
        sigaction(SIGINT,  &sa_t, NULL);
        sigaction(SIGHUP,  &sa_t, NULL);

        memset(&sa_u, 0, sizeof(sa_u));
        sa_u.sa_handler = sig_usr1;
        sigemptyset(&sa_u.sa_mask);
        sigaction(SIGUSR1, &sa_u, NULL);

        memset(&sa_ign, 0, sizeof(sa_ign));
        sa_ign.sa_handler = SIG_IGN;
        sigemptyset(&sa_ign.sa_mask);
        sigaction(SIGPIPE, &sa_ign, NULL);
    }

    /* Netlink socket: 若被 SELinux 拒绝则降级 g_nl_fd = -1, 依靠 scheduler 周期巡检继续服务 IPC */
    g_nl_fd = nl_open();
    if (g_nl_fd < 0) {
        g_nl_fd = -1;
        hlog("WARN: netlink RTMGRP_LINK unavailable (SELinux denied?), degraded to periodic timer mode");
    }

    /* UNIX socket server */
    g_srv_fd = unix_server_open();
    if (g_srv_fd < 0) { hlog("FATAL: cannot open UNIX socket"); goto cleanup; }

    hlog("Listening on %s + %s",
         g_nl_fd >= 0 ? "netlink RTMGRP_LINK" : "timer-only (netlink disabled)",
         SOCK_PATH);

    /* v5.0: 启动 offload scheduler (探测平台 + 选 adapter + 启 worker)
     *
     * 失败不致命: 内部会自动回落 null adapter, scheduler 仍可用,
     * 只是 disable_upstream / restore_upstream 变成 NOOP。
     * 这样 hotspotd 的控制接口(netlink / unix socket)完全不受 BPF 异常影响。 */
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

    /* ── 主事件循环 ────────────────────────────────────────── */
    while (g_running) {
        maybe_truncate_log();

        if (g_need_refresh) {
            g_need_refresh = 0;
            touch_refresh_file();
        }

        struct pollfd pfds[2];
        nfds_t nfds = 0;
        int nl_idx = -1, srv_idx = -1;
        if (g_nl_fd >= 0) {
            nl_idx = (int)nfds;
            pfds[nfds].fd      = g_nl_fd;
            pfds[nfds].events  = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }
        if (g_srv_fd >= 0) {
            srv_idx = (int)nfds;
            pfds[nfds].fd      = g_srv_fd;
            pfds[nfds].events  = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        /* 5s 超时兜住 SIGUSR1 信号窗口与周期日志尺寸自检 */
        int ret = poll(pfds, nfds, 5000);
        if (ret < 0) {
            if (errno == EINTR) continue;  /* 信号打断,正常 */
            hlog("ERROR: poll: %s", strerror(errno));
            break;
        }
        if (ret == 0) continue;

        if (nl_idx >= 0 && (pfds[nl_idx].revents & (POLLIN | POLLERR)))
            nl_process(g_nl_fd);

        if (srv_idx >= 0 && (pfds[srv_idx].revents & POLLIN)) {
            for (int acc = 0; acc < 16 && g_running; acc++) {
                int cfd = accept4(g_srv_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (cfd < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                handle_client(cfd);
            }
        }
    }

cleanup:
    hlog("hotspotd shutting down");
    /* v5.0: 停 scheduler (停 offload worker + adapter shutdown)
     * 幂等, 必须在关 socket 之前, 让 adapter 干净关 BPF map fd */
    hnc_scheduler_shutdown();

    if (g_nl_fd  >= 0) close(g_nl_fd);
    if (g_srv_fd >= 0) { close(g_srv_fd); unlink(SOCK_PATH); }
    cleanup_pid();
    if (g_log) { hlog("=== hotspotd stopped ==="); fclose(g_log); }
    return 0;
}

#endif /* HNC_TEST_MODE */
