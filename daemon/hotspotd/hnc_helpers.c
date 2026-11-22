/* hnc_helpers.c — HNC shared C helpers 实现
 *
 * v3.6 Commit 2:从 hotspotd.c 提取的纯 helper 函数。
 * 见 hnc_helpers.h 的设计说明。
 * v5.33: 设备发现(名字解析 / OUI / 垃圾名 / pending)随 hotspotd 的 C 版发现
 * 一起删除(只留 Go 版, src/dpid/devname), 这里只剩 offload 代码用的两个。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "hnc_helpers.h"

#include <stdint.h>

#include <stdio.h>
#include <string.h>
/* v5.9.0: hnc_run_cmd_timeout 依赖 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>

/* ══════════════════════════════════════════════════════════
 * json_escape — 含 UTF-8 边界回退 (v3.5.2 P2-F)
 * ══════════════════════════════════════════════════════════ */
void hnc_json_escape(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) return;
    size_t j = 0;
    int truncated = 0;
    /* 循环条件 j + 1 < dst_size: 留 1 字节给末尾 NUL。
     * 每个 escape 分支自己再检查需要的额外字节,不够就 break。 */
    for (size_t i = 0; src[i] && j + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 0x20) {
            if (j + 6 >= dst_size) { truncated = 1; break; }
            j += snprintf(dst + j, dst_size - j, "\\u%04x", c);
        } else {
            /* 普通 ASCII 或 UTF-8 字节 */
            dst[j++] = (char)c;
        }
    }

    /* UTF-8 边界回退:如果因 buffer 不够退出,确保不留残缺多字节序列 */
    if (truncated || (src[0] && j + 1 >= dst_size)) {
        /* 从末尾往前找 last non-continuation byte */
        size_t k = j;
        while (k > 0 && ((unsigned char)dst[k-1] & 0xC0) == 0x80) {
            k--;
        }
        /* dst[k-1] 是 ASCII 或 lead byte */
        if (k > 0) {
            unsigned char lead = (unsigned char)dst[k-1];
            size_t needed = 0;
            if ((lead & 0x80) == 0) {
                needed = 0;                /* ASCII,完整 */
            } else if ((lead & 0xE0) == 0xC0) {
                needed = 1;                /* 2-byte lead */
            } else if ((lead & 0xF0) == 0xE0) {
                needed = 2;                /* 3-byte lead (中文) */
            } else if ((lead & 0xF8) == 0xF0) {
                needed = 3;                /* 4-byte lead (emoji) */
            }
            size_t have = j - k;
            if (have < needed) {
                /* 不完整,删掉整个残缺字符 */
                j = k - 1;
            }
        }
    }

    dst[j] = '\0';
}

/* ══════════════════════════════════════════════════════════
 * hnc_run_cmd_timeout — 带总超时的子进程执行 (v5.9.0)
 * 见 hnc_helpers.h 的接口说明。
 * ══════════════════════════════════════════════════════════ */
static int64_t hnc_mono_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000L);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
}

static int hnc_dup2_nocloexec(int fd, int target) {
    if (fd == target) {
        int fl = fcntl(target, F_GETFD);
        if (fl < 0) return -1;
        if (fl & FD_CLOEXEC) {
            if (fcntl(target, F_SETFD, fl & ~FD_CLOEXEC) < 0) return -1;
        }
        return target;
    }
    return dup2(fd, target);
}

int hnc_run_cmd_timeout(char *const argv[], char *buf, size_t cap, int timeout_ms) {
    if (argv == NULL || argv[0] == NULL || buf == NULL || cap < 2 || timeout_ms <= 0)
        return -1;
    buf[0] = '\0';

    int pipefd[2];
    /* pipe2(O_CLOEXEC) prevents concurrent multithreaded fork() calls from
     * inheriting sibling pipe write ends and delaying EOF until timeout. */
    if (pipe2(pipefd, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        struct sigaction sa_dfl;
        memset(&sa_dfl, 0, sizeof(sa_dfl));
        sa_dfl.sa_handler = SIG_DFL;
        sigemptyset(&sa_dfl.sa_mask);
        sigaction(SIGPIPE, &sa_dfl, NULL);

        close(pipefd[0]);
        if (hnc_dup2_nocloexec(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        if (pipefd[1] != STDOUT_FILENO)
            close(pipefd[1]);

        int devnull_in = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull_in >= 0) {
            (void)hnc_dup2_nocloexec(devnull_in, STDIN_FILENO);
            if (devnull_in != STDIN_FILENO) close(devnull_in);
        }
        int devnull_err = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull_err >= 0) {
            (void)hnc_dup2_nocloexec(devnull_err, STDERR_FILENO);
            if (devnull_err != STDERR_FILENO) close(devnull_err);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    /* Use 64-bit CLOCK_MONOTONIC microseconds: avoids 32-bit signed long
     * overflow UB on armeabi-v7a and wall-clock jumps during NITZ/NTP sync. */
    int64_t deadline_us = hnc_mono_us() + (int64_t)timeout_ms * 1000LL;

    size_t got = 0;
    int killed = 0;
    while (got < cap - 1) {
        int64_t remain_us = deadline_us - hnc_mono_us();
        if (remain_us <= 0) {
            kill(pid, SIGKILL);
            killed = 1;
            break;
        }

        int64_t remain_ms = (remain_us + 999LL) / 1000LL;
        if (remain_ms < 1) remain_ms = 1;
        if (remain_ms > INT_MAX) remain_ms = INT_MAX;

        struct pollfd pfd = {
            .fd      = pipefd[0],
            .events  = POLLIN,
            .revents = 0,
        };
        int ret = poll(&pfd, 1, (int)remain_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            kill(pid, SIGKILL);
            killed = 1;
            break;
        }
        if (pfd.revents & POLLNVAL) {
            break;
        }

        ssize_t n = read(pipefd[0], buf + got, cap - 1 - got);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        if (n == 0) break;
        got += (size_t)n;
    }

    if (!killed && got >= cap - 1) kill(pid, SIGKILL);

    close(pipefd[0]);

    int status;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    (void)status;

    buf[got] = '\0';
    return (int)got;
}
