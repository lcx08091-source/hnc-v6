/* hnc_helpers.c — HNC shared C helpers 实现
 *
 * v3.6 Commit 2:从 hotspotd.c 提取的纯 helper 函数。
 * 见 hnc_helpers.h 的设计说明。
 * v5.33: 设备发现(名字解析 / OUI / 垃圾名 / pending)随 hotspotd 的 C 版发现
 * 一起删除(只留 Go 版, src/dpid/devname), 这里只剩 offload 代码用的两个。
 */

#include "hnc_helpers.h"

#include <stdio.h>
#include <string.h>
/* v5.9.0: hnc_run_cmd_timeout 依赖 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
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
int hnc_run_cmd_timeout(char *const argv[], char *buf, size_t cap, int timeout_ms) {
    if (argv == NULL || argv[0] == NULL || buf == NULL || cap < 2 || timeout_ms <= 0)
        return -1;
    buf[0] = '\0';

    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* 子进程: stdout → pipe, stderr → /dev/null */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    /* 父进程: O_NONBLOCK + select 截止循环 (EINTR-safe) */
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    struct timeval tv_now;
    gettimeofday(&tv_now, NULL);
    long deadline_us = (long)tv_now.tv_sec * 1000000L + tv_now.tv_usec
                       + (long)timeout_ms * 1000L;

    size_t got = 0;
    int killed = 0;
    while (got < cap - 1) {
        gettimeofday(&tv_now, NULL);
        long now_us = (long)tv_now.tv_sec * 1000000L + tv_now.tv_usec;
        long remain_us = deadline_us - now_us;
        if (remain_us <= 0) {
            kill(pid, SIGKILL);
            killed = 1;
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pipefd[0], &rfds);
        struct timeval tv = {
            .tv_sec  = remain_us / 1000000L,
            .tv_usec = remain_us % 1000000L,
        };
        int ret = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            /* 超时 */
            kill(pid, SIGKILL);
            killed = 1;
            break;
        }

        ssize_t n = read(pipefd[0], buf + got, cap - 1 - got);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        if (n == 0) break;   /* EOF: 子进程关闭了写端 */
        got += (size_t)n;
    }

    /* buffer 写满但子进程还在产出 → 杀掉,避免它阻塞在写满的 pipe 上
     * (close 读端后它也会收 SIGPIPE,kill 只是让 waitpid 确定性快返) */
    if (!killed && got >= cap - 1) kill(pid, SIGKILL);

    close(pipefd[0]);

    int status;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    (void)status;

    buf[got] = '\0';
    return (int)got;
}
