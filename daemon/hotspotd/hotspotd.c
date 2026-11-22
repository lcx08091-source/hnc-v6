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
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
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

/* ── 路径常量 ──────────────────────────────────────────────── */
#define HNC_DIR             "/data/local/hnc"
#define SOCK_PATH           HNC_DIR "/run/hotspotd.sock"
#define DEVICES_JSON        HNC_DIR "/data/devices.json"
#define REFRESH_FILE        HNC_DIR "/run/devices.refresh"
#define LOG_FILE            HNC_DIR "/logs/hotspotd.log"
#define PID_FILE            HNC_DIR "/run/hotspotd.pid"

/* 单测改路径用(test/test_hotspotd_ipc.c); 生产 = 上面的常量 */
static const char *g_devices_path = DEVICES_JSON;
static const char *g_refresh_path = REFRESH_FILE;

static FILE *g_log    = NULL;

/* ── 信号标志（volatile sig_atomic_t 保证信号安全）────────── */
static volatile sig_atomic_t g_need_refresh = 0;  /* SIGUSR1 → touch run/devices.refresh */
static volatile sig_atomic_t g_running      = 1;  /* 0=退出主循环 */

/* ══════════════════════════════════════════════════════════
   日志
══════════════════════════════════════════════════════════ */
static void hlog(const char *fmt, ...) {
    if (!g_log) return;
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
    char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
    /* 一次 wakeup 抽干到 EAGAIN(rc3.1.33 #4)。事件风暴会被调度器 worker 合并
     * 成一次重探, 这里每条链路事件都请求一次也没关系(只置 flag + cond_signal)。 */
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
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
            struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + off);
            if (nlh->nlmsg_len < sizeof(struct nlmsghdr) || (size_t)nlh->nlmsg_len > rem)
                break;
            size_t step = NLMSG_ALIGN(nlh->nlmsg_len);
            if (step > rem)
                step = rem;
            off += step;
            rem -= step;
            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
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

/* hotfix2: send() may legally perform a short write.
 * Use a small helper for IPC responses so GET_DEVICES and status JSON are not truncated
 * when the client/socket buffer is temporarily full. */
static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
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
     * - 5 秒写超时:客户端慢读或不读 → send 超时后 close */
    struct timeval tv_rd = {.tv_sec = 2, .tv_usec = 0};
    struct timeval tv_wr = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv_rd, sizeof(tv_rd));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv_wr, sizeof(tv_wr));

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
    ssize_t n;
    do {
        n = recv(cfd, req, sizeof(req)-1, 0);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) { close(cfd); return; }
    req[n] = '\0';
    /* 去尾部空白 */
    for (int i = (int)strlen(req)-1; i >= 0 && (req[i]=='\n'||req[i]=='\r'||req[i]==' '); i--)
        req[i] = '\0';

    if (strcmp(req, "GET_DEVICES") == 0) {
        /* 直接发 JSON 文件内容(Go 写者的 devices.json) */
        FILE *f = fopen(g_devices_path, "re");
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
        /* Go 写者看到 run/devices.refresh 的 mtime 变了就立刻全量扫一次。
         * 高频 REFRESH 只是反复 touch 一个文件, Go 写者那边每拍最多扫一次。 */
        touch_refresh_file();
        (void)send_all(cfd, "OK:queued\n", 10);
    } else if (strcmp(req, "STATUS") == 0) {
        char resp[128];
        snprintf(resp, sizeof(resp), "running:1 devices:%d pid:%d\n",
                 count_devices_in_file_at(g_devices_path), (int)getpid());
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
        int jlen = hnc_scheduler_summary_to_json(&summ, json, sizeof(json));
        if (jlen > 0) {
            (void)send_all(cfd, json, (size_t)jlen);
            (void)send_all(cfd, "\n", 1);
        } else {
            (void)send_all(cfd, "ERR:summary serialize\n", 22);
        }
    } else if (strcmp(req, "OFFLOAD_DISABLE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_disable_global();
        char resp[64];
        /* v5.9.0: EEMPTY(map 空, 无事可做)对 IPC 调用方保持 OK 前缀
         * (契约不破坏, 仓库内无解析者但保守处理), 细节段透出 "EMPTY"。 */
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 (e == OFFLOAD_OK || e == OFFLOAD_EEMPTY) ? "OK" : "ERR",
                 offload_err_str(e));
        (void)send_all(cfd, resp, strlen(resp));
    } else if (strcmp(req, "OFFLOAD_RESTORE_GLOBAL") == 0) {
        offload_err_t e = hnc_scheduler_force_restore_global();
        char resp[64];
        snprintf(resp, sizeof(resp), "%s:%s\n",
                 (e == OFFLOAD_OK || e == OFFLOAD_EEMPTY) ? "OK" : "ERR",
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
 * 以下只给生产 main 用(打开 socket / 信号 / PID 文件 / main)。
 * 单测(#define HNC_TEST_MODE 后 #include 本文件, 见 test/test_hotspotd_ipc.c)
 * 自带 main, 只测上面的 nl_process / handle_client / count_devices_in_file_at。
 * ══════════════════════════════════════════════════════════ */
#ifndef HNC_TEST_MODE

/* ── 全局 fd ──────────────────────────────────────────────── */
static int  g_nl_fd   = -1;   /* netlink socket(RTMGRP_LINK) */
static int  g_srv_fd  = -1;   /* UNIX socket server */

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) { hlog("ERROR: netlink socket: %s", strerror(errno)); return -1; }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        /* rc43 (P2-17): RTMGRP_LINK —— 监听 iface 链路状态变化(WiFi↔4G 切换、
         * VPN tun 上下线等),用来即时通知 offload 调度器重探主上游,把原来最坏 60s
         * 的"换网后限速对新上游短暂失效"窗口缩到瞬时。
         * v5.33: 设备发现归 Go 看门狗, 不再订阅邻居表事件。 */
        .nl_groups = RTMGRP_LINK,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        hlog("ERROR: netlink bind: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int unix_server_open(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
static int g_pid_lock_fd = -1;

static int write_pid(void) {
    /* v7: 采用内核级 flock 排他锁替代脆弱的 kill(old_pid, 0) 检查，
     * 彻底杜绝 Android pid_max=32768 下 PID 撞号复用导致永久拒启，进程崩溃内核自动解锁 */
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
    if (ftruncate(fd, 0) == 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (write(fd, buf, (size_t)n) != n) {
            hlog("WARN: write PID file short/failed: %s", strerror(errno));
        }
    }
    g_pid_lock_fd = fd; /* 随进程生命周期保持打开 */
    return 0;
}

/* v3.5.2 P1-D: cleanup 时验证 PID 文件里的 PID 是不是自己,
 * 是才删,不是说明别的实例已经 overwrite 了,不要删它的文件 */
static void cleanup_pid(void) {
    FILE *rf = fopen(PID_FILE, "re");
    if (rf) {
        int file_pid = 0;
        if (fscanf(rf, "%d", &file_pid) == 1 && file_pid == (int)getpid()) {
            fclose(rf);
            unlink(PID_FILE);
        } else {
            fclose(rf);
        }
    }
    if (g_pid_lock_fd >= 0) {
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
    /* 简单参数：-d 后台化，-l <logfile>；--no-discovery 照收(v5.33 起本来就不发现) */
    int daemonize = 0;
    const char *logpath = LOG_FILE;
    for (int i = 1; i < argc; i++) {
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
    hlog("=== hotspotd %s started (PID=%d) ===", daemonize?"daemon":"fg", (int)getpid());
    hlog("v5.33: offload + control socket only (device discovery is the Go watchdog's)");
    /* v3.5.2 P2-E: g_log 加 FD_CLOEXEC,避免子进程继承日志 fd */
    if (g_log) fcntl(fileno(g_log), F_SETFD, FD_CLOEXEC);

    /* PID 文件
     * v3.5.2 P1-D: 如果 write_pid 返回 -1(别的实例还活着),直接退出,
     * 跳过 cleanup 避免误删别人的 PID 文件 */
    if (write_pid() < 0) {
        if (g_log) fclose(g_log);
        return 0;  /* 干净退出,不走 cleanup */
    }

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

    /* Netlink socket */
    g_nl_fd = nl_open();
    if (g_nl_fd < 0) { hlog("FATAL: cannot open netlink"); goto cleanup; }

    /* UNIX socket server */
    g_srv_fd = unix_server_open();
    if (g_srv_fd < 0) { hlog("FATAL: cannot open UNIX socket"); goto cleanup; }

    hlog("Listening on netlink RTMGRP_LINK + %s", SOCK_PATH);

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
        if (g_need_refresh) {
            g_need_refresh = 0;
            touch_refresh_file();
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_nl_fd,  &rfds);
        FD_SET(g_srv_fd, &rfds);
        int maxfd = (g_nl_fd > g_srv_fd ? g_nl_fd : g_srv_fd) + 1;

        /* 5s 超时只为兜住「SIGUSR1 恰好落在检查 g_need_refresh 之后、select 之前」 */
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        int ret = select(maxfd, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;  /* 信号打断,正常 */
            hlog("ERROR: select: %s", strerror(errno));
            break;
        }
        if (ret == 0) continue;

        if (FD_ISSET(g_nl_fd, &rfds))
            nl_process(g_nl_fd);

        if (FD_ISSET(g_srv_fd, &rfds)) {
            int cfd = accept4(g_srv_fd, NULL, NULL, SOCK_CLOEXEC);
            if (cfd >= 0) handle_client(cfd);
        }
    }

cleanup:
    hlog("hotspotd shutting down");
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
