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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>

#define DEFAULT_SOCK_PATH  "/data/local/hnc/run/hotspotd.sock"
#define DEFAULT_TIMEOUT    3
#define CMD_BUF_SIZE       1024
#define RESP_BUF_SIZE      65536

static int build_cmd_from_argv(int argc, char **argv, char *out, size_t out_size)
{
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        int n = snprintf(out + pos, out_size - pos, "%s%s",
                         i > 1 ? " " : "", argv[i]);
        if (n < 0 || (size_t)(pos + n) >= out_size) return -1;
        pos += n;
    }
    /* 追加换行 (hotspotd 命令解析期望) */
    if ((size_t)(pos + 1) >= out_size) return -1;
    out[pos++] = '\n';
    out[pos]   = '\0';
    return pos;
}

static int read_cmd_from_stdin(char *out, size_t out_size)
{
    if (fgets(out, out_size, stdin) == NULL) return -1;
    /* 确保以换行结尾 */
    int len = (int)strlen(out);
    if (len == 0) return -1;
    if (out[len - 1] != '\n') {
        if ((size_t)(len + 1) >= out_size) return -1;
        out[len++] = '\n';
        out[len]   = '\0';
    }
    return len;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s <cmd> [arg...]    send command from argv\n"
            "  %s -                  read command from stdin\n"
            "\n"
            "env:\n"
            "  HNC_SOCK         socket path (default %s)\n"
            "  HNC_IPC_TIMEOUT  timeout in seconds (default %d)\n",
            argv[0], argv[0], DEFAULT_SOCK_PATH, DEFAULT_TIMEOUT);
        return 1;
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

    /* socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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

    /* connect */
    const char *sock_path = getenv("HNC_SOCK");
    if (!sock_path || !*sock_path) sock_path = DEFAULT_SOCK_PATH;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    /* sun_path 标准 108 bytes, 防截断 */
    strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "hnc_ipc: connect %s: %s\n", sock_path, strerror(errno));
        close(fd);
        return 3;
    }

    /* send */
    ssize_t sent = send(fd, cmd, (size_t)cmd_len, 0);
    if (sent < 0) {
        fprintf(stderr, "hnc_ipc: send: %s\n", strerror(errno));
        close(fd);
        return 4;
    }

    /* recv 全部, 写到 stdout
     * hotspotd 单次响应可能 KB 级 (GET_DEVICES 设备多时), 用大 buffer 累计
     * 直到对端关闭或读到空。 */
    char buf[RESP_BUF_SIZE];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(buf)) {
        ssize_t n = recv(fd, buf + total, sizeof(buf) - (size_t)total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;     /* 对端关 */
        total += n;
    }
    close(fd);

    if (total <= 0) {
        fprintf(stderr, "hnc_ipc: no response (timeout %ds)\n", timeout);
        return 5;
    }

    fwrite(buf, 1, (size_t)total, stdout);
    /* hotspotd 响应可能不带换行, 给个收尾 (但若已有 \n 则不加) */
    if (buf[total - 1] != '\n') fputc('\n', stdout);
    return 0;
}
