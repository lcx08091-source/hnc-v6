/* tools/hnc_ipc.c — hotspotd unix socket 命令行客户端
 *
 * 给 shell 脚本 (apply_device_rule.sh / watchdog.sh / 诊断脚本) 用,
 * 替代 socat / nc -U 等可能不在 toybox 里的工具。
 *
 * 用法:
 *   hnc_ipc <cmd> [arg...]
 *   echo "<cmd> [arg...]" | hnc_ipc -
 *
 * 例子:
 *   hnc_ipc OFFLOAD_NOTIFY_LIMIT aa:bb:cc:dd:ee:ff 1
 *   hnc_ipc OFFLOAD_STATUS
 *   hnc_ipc REFRESH
 *   hnc_ipc GET_DEVICES > /tmp/devices.json
 *
 * 环境变量:
 *   HNC_SOCK         覆盖默认 socket 路径
 *   HNC_IPC_TIMEOUT  覆盖默认超时 (秒, 默认 3)
 *
 * 退出码:
 *   0   命令发送 + 响应接收成功
 *   1   参数错误
 *   2   socket() 失败
 *   3   connect 失败 (hotspotd 没起 / 路径错 / SELinux 拒)
 *   4   send 失败
 *   5   recv 全无返回 (写超时 / hotspotd hang)
 *
 * 设计上不解析响应内容, 原样输出到 stdout, 让调用方决定怎么用。
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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef HNC_VERSION
#define HNC_VERSION        "dev"
#endif

#define DEFAULT_SOCK_PATH  "/data/local/hnc/run/hotspotd.sock"
#define DEFAULT_TIMEOUT    3
#define CMD_BUF_SIZE       1024
#define RESP_CHUNK_SIZE    16384U
#define MAX_RESP_BYTES     (4U * 1024U * 1024U)

static int build_cmd_from_argv(int argc, char **argv, char *out, size_t out_size)
{
    size_t pos = 0;
    for (int i = 1; i < argc; i++) {
        int n = snprintf(out + pos, out_size - pos, "%s%s",
                         i > 1 ? " " : "", argv[i]);
        if (n < 0 || pos + (size_t)n >= out_size) return -1;
        pos += (size_t)n;
    }
    /* 追加换行 (hotspotd 命令解析期望) */
    if (pos + 1U >= out_size) return -1;
    out[pos++] = '\n';
    out[pos]   = '\0';
    return (int)pos;
}

static int read_cmd_from_stdin(char *out, size_t out_size)
{
    if (fgets(out, (int)out_size, stdin) == NULL) return -1;
    /* 确保以换行结尾 */
    size_t len = strlen(out);
    if (len == 0) return -1;
    if (out[len - 1] != '\n') {
        if (len + 1U >= out_size) return -1;
        out[len++] = '\n';
        out[len]   = '\0';
    }
    return (int)len;
}

static int is_cmd_get_devices(const char *cmd)
{
    while (*cmd == ' ' || *cmd == '\t')
        cmd++;
    if (strncmp(cmd, "GET_DEVICES", 11) != 0)
        return 0;
    cmd += 11;
    while (*cmd == ' ' || *cmd == '\t' || *cmd == '\r' || *cmd == '\n')
        cmd++;
    return *cmd == '\0';
}

static int is_complete_json_object(const char *buf, size_t len)
{
    size_t start = 0;
    while (start < len && (buf[start] == ' ' || buf[start] == '\t' ||
                           buf[start] == '\r' || buf[start] == '\n')) {
        start++;
    }
    if (start >= len || buf[start] != '{')
        return 0;

    size_t end = len;
    while (end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t' ||
                           buf[end - 1] == '\r' || buf[end - 1] == '\n')) {
        end--;
    }
    if (end <= start || buf[end - 1] != '}')
        return 0;

    int depth = 0;
    int in_str = 0;
    int esc = 0;
    for (size_t i = start; i < end; i++) {
        char c = buf[i];
        if (esc) {
            esc = 0;
            continue;
        }
        if (in_str) {
            if (c == '\\')
                esc = 1;
            else if (c == '"')
                in_str = 0;
            continue;
        }
        if (c == '"') {
            in_str = 1;
        } else if (c == '{') {
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth < 0)
                return 0;
            if (depth == 0 && i + 1 < end)
                return 0;
        }
    }
    return (!in_str && !esc && depth == 0) ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("hnc_ipc %s\n", HNC_VERSION);
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s <cmd> [arg...]    send command from argv\n"
            "  %s -                  read command from stdin\n"
            "  %s --version          print version and exit\n"
            "\n"
            "env:\n"
            "  HNC_SOCK         socket path (default %s)\n"
            "  HNC_IPC_TIMEOUT  timeout in seconds (default %d)\n",
            argv[0], argv[0], argv[0], DEFAULT_SOCK_PATH, DEFAULT_TIMEOUT);
        return 1;
    }

    {
        struct sigaction sa_ign;
        memset(&sa_ign, 0, sizeof(sa_ign));
        sa_ign.sa_handler = SIG_IGN;
        sigemptyset(&sa_ign.sa_mask);
        (void)sigaction(SIGPIPE, &sa_ign, NULL);
    }

    char cmd[CMD_BUF_SIZE];
    int cmd_len;
    if (argc == 2 && strcmp(argv[1], "-") == 0) {
        cmd_len = read_cmd_from_stdin(cmd, sizeof(cmd));
    } else {
        cmd_len = build_cmd_from_argv(argc, argv, cmd, sizeof(cmd));
    }
    if (cmd_len <= 0) {
        fprintf(stderr, "hnc_ipc: command too long or empty\n");
        return 1;
    }
    int is_get_devices = is_cmd_get_devices(cmd);

    /* socket */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("hnc_ipc: socket"); return 2; }

    /* timeout */
    int timeout = DEFAULT_TIMEOUT;
    const char *t_env = getenv("HNC_IPC_TIMEOUT");
    if (t_env) {
        int v = atoi(t_env);
        if (v > 0 && v < 300) timeout = v;
    }
    struct timeval tv = { .tv_sec = timeout, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* connect — validate env override to prevent attacker-controlled socket paths */
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;

    const char *sock_path = getenv("HNC_SOCK");
    if (sock_path && *sock_path &&
        strncmp(sock_path, "/data/", 6) == 0 &&
        strstr(sock_path, "..") == NULL &&
        strlen(sock_path) < sizeof(sa.sun_path)) {
        /* env override accepted: must be under /data/, no "..", fits in sun_path */
    } else {
        sock_path = DEFAULT_SOCK_PATH;
    }

    /* sun_path 标准 108 bytes, snprintf 替代 strncpy 消除截断告警 */
    int pn = snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sock_path);
    if (pn < 0 || (size_t)pn >= sizeof(sa.sun_path)) {
        fprintf(stderr, "hnc_ipc: socket path too long\n");
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "hnc_ipc: connect %s: %s\n", sock_path, strerror(errno));
        close(fd);
        return 3;
    }

    /* send all (handle EINTR / short write / EPIPE without SIGPIPE) */
    size_t sent_off = 0;
    while (sent_off < (size_t)cmd_len) {
        ssize_t n = send(fd, cmd + sent_off, (size_t)cmd_len - sent_off, MSG_NOSIGNAL);
        if (n > 0) {
            sent_off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        fprintf(stderr, "hnc_ipc: send: %s\n", strerror(errno));
        close(fd);
        return 4;
    }

    /* 流式循环接收并写出到 stdout (硬上限 4MB), 修复 >64KB devices.json 静默截断;
     * 对 GET_DEVICES 先缓存在内存校验完整闭合 JSON 对象后再写出, 防止对端超时截断被当正常返回 0 */
    char buf[RESP_CHUNK_SIZE];
    char *json_buf = NULL;
    size_t json_cap = 0;
    size_t total = 0;
    char last_byte = '\0';
    int recv_err = 0;

    while (total < MAX_RESP_BYTES) {
        size_t want = sizeof(buf);
        if (MAX_RESP_BYTES - total < want)
            want = MAX_RESP_BYTES - total;

        ssize_t n = recv(fd, buf, want, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (total > 0) {
                fprintf(stderr, "hnc_ipc: recv error after %zu bytes: %s\n",
                        total, strerror(errno));
                recv_err = 1;
            }
            break;
        }
        if (n == 0) break;     /* 对端正常关闭 */

        size_t chunk = (size_t)n;
        if (is_get_devices) {
            if (total + chunk > json_cap) {
                size_t ncap = json_cap ? json_cap : RESP_CHUNK_SIZE;
                while (ncap < total + chunk && ncap < MAX_RESP_BYTES) {
                    if (ncap > MAX_RESP_BYTES / 2U)
                        ncap = MAX_RESP_BYTES;
                    else
                        ncap *= 2U;
                }
                char *nb = realloc(json_buf, ncap);
                if (!nb) {
                    fprintf(stderr, "hnc_ipc: out of memory (%zu bytes)\n", ncap);
                    free(json_buf);
                    close(fd);
                    return 5;
                }
                json_buf = nb;
                json_cap = ncap;
            }
            memcpy(json_buf + total, buf, chunk);
        } else {
            if (fwrite(buf, 1, chunk, stdout) != chunk || ferror(stdout)) {
                fprintf(stderr, "hnc_ipc: stdout write failed\n");
                close(fd);
                return 4;
            }
        }
        last_byte = buf[chunk - 1];
        total += chunk;
    }

    if (total == MAX_RESP_BYTES) {
        char extra = 0;
        ssize_t rem;
        do {
            rem = recv(fd, &extra, 1, 0);
        } while (rem < 0 && errno == EINTR);
        if (rem > 0) {
            fprintf(stderr, "hnc_ipc: response exceeds 4MB limit\n");
            free(json_buf);
            close(fd);
            return 5;
        }
    }
    close(fd);

    if (total == 0 || recv_err) {
        if (total == 0)
            fprintf(stderr, "hnc_ipc: no response (timeout %ds)\n", timeout);
        free(json_buf);
        return 5;
    }

    if (is_get_devices) {
        if (!is_complete_json_object(json_buf, total)) {
            fprintf(stderr, "hnc_ipc: truncated or malformed GET_DEVICES response (%zu bytes)\n",
                    total);
            free(json_buf);
            return 5;
        }
        if (fwrite(json_buf, 1, total, stdout) != total || ferror(stdout)) {
            fprintf(stderr, "hnc_ipc: stdout write failed\n");
            free(json_buf);
            return 4;
        }
        free(json_buf);
        json_buf = NULL;
    }

    /* hotspotd 响应可能不带换行, 给个收尾 (但若已有 \n 则不加) */
    if (last_byte != '\n') {
        if (fputc('\n', stdout) == EOF) {
            fprintf(stderr, "hnc_ipc: stdout putc failed\n");
            return 4;
        }
    }
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "hnc_ipc: stdout flush failed\n");
        return 4;
    }
    return 0;
}
