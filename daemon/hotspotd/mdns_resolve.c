/*
 * mdns_resolve.c — HNC v3.4.6 主动 mDNS 反向查询工具
 *
 * 用法:
 *   mdns_resolve <ipv4>          查询 IP 对应的 .local 主机名
 *   mdns_resolve -t 800 <ipv4>   自定义超时(ms),默认 800
 *   mdns_resolve -v <ipv4>       verbose,打印诊断信息到 stderr
 *
 * 输出:
 *   成功 → 一行 hostname (去掉 .local 尾巴),exit 0
 *   失败 → 空,exit 1
 *
 * 协议: RFC 6762 (Multicast DNS) 反向 PTR 查询
 *   1. 构造 DNS query: <reversed-ip>.in-addr.arpa PTR IN
 *      例如 IP 10.193.171.30 → 30.171.193.10.in-addr.arpa
 *   2. UNICAST 阶段: sendto <ip>:5353/UDP, recvfrom 等待响应
 *      RFC 6762 §5.5 要求设备支持单播 mDNS 查询(QU bit)
 *   3. UNICAST 失败/超时 → 兜底 MULTICAST: sendto 224.0.0.251:5353
 *      传统 mDNS 行为,所有同链路 mDNS responder 都会收到
 *      需要 setsockopt IP_MULTICAST_TTL=255 (RFC 6762 §11)
 *   4. 解析响应 answer section,提取 PTR rdata
 *      处理 DNS name compression (0xC0 prefix → offset jump)
 *      最大跳转 16 次防止恶意循环
 *   5. 把 hostname 末尾的 ".local" 或 ".local." 剥掉,输出剩余部分
 *
 * 编译 (NDK aarch64, 16K page-size aligned):
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
 *     -static -O2 -Wall -Wextra -Wl,-z,max-page-size=16384 \
 *     -o mdns_resolve mdns_resolve.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MDNS_PORT       5353
#define MDNS_MULTICAST  "224.0.0.251"
#define MAX_PKT         1500
#define MAX_NAME_JUMPS  16     /* 防 name compression 循环 */
#define MAX_NAME_LEN    256
#define DEFAULT_TIMEOUT 800    /* ms */

static int verbose = 0;
#define VLOG(...) do { if (verbose) fprintf(stderr, "[mdns] " __VA_ARGS__); } while (0)

/* ── DNS query 包构造 ─────────────────────────────────────── */

/* 把 "30.171.193.10.in-addr.arpa" 编码成 DNS labels:
 *   \x02 "30" \x03 "171" \x03 "193" \x02 "10"
 *   \x07 "in-addr" \x04 "arpa" \x00
 * 返回写入字节数,失败 -1 */
static int encode_dns_name(const char *name, uint8_t *out, size_t outlen)
{
    size_t n = strlen(name);
    if (n + 2 > outlen) return -1;

    size_t pos = 0;
    size_t i = 0;
    while (i < n) {
        /* 找下一个 dot 或结尾 */
        size_t j = i;
        while (j < n && name[j] != '.') j++;
        size_t label_len = j - i;
        if (label_len == 0 || label_len > 63) return -1;
        if (pos + 1 + label_len + 1 > outlen) return -1;
        out[pos++] = (uint8_t)label_len;
        memcpy(out + pos, name + i, label_len);
        pos += label_len;
        i = j + 1;  /* 跳过 dot */
        if (j == n) break;
    }
    out[pos++] = 0;  /* root label */
    return (int)pos;
}

/* 构造 IPv4 反向 PTR 查询包。
 * ip_str 例如 "10.193.171.30"
 * 写入 buf,返回包长度,失败 -1 */
static int build_query(const char *ip_str, uint8_t *buf, size_t buflen, uint16_t txid)
{
    /* 反转 IP */
    unsigned a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;

    char qname[64];
    snprintf(qname, sizeof(qname), "%u.%u.%u.%u.in-addr.arpa", d, c, b, a);

    if (buflen < 12 + 64 + 4) return -1;

    /* DNS header */
    buf[0] = txid >> 8;     /* ID hi */
    buf[1] = txid & 0xFF;   /* ID lo */
    buf[2] = 0x00;          /* QR=0 OPCODE=0 AA=0 TC=0 RD=0 */
    buf[3] = 0x00;          /* RA=0 Z=0 RCODE=0 */
    buf[4] = 0x00; buf[5] = 0x01;  /* QDCOUNT = 1 */
    buf[6] = 0x00; buf[7] = 0x00;  /* ANCOUNT = 0 */
    buf[8] = 0x00; buf[9] = 0x00;  /* NSCOUNT = 0 */
    buf[10]= 0x00; buf[11]= 0x00;  /* ARCOUNT = 0 */

    int n = encode_dns_name(qname, buf + 12, buflen - 12 - 4);
    if (n < 0) return -1;

    size_t pos = 12 + (size_t)n;
    /* QTYPE = PTR (0x000C) */
    buf[pos++] = 0x00; buf[pos++] = 0x0C;
    /* QCLASS = IN (0x0001), 不设 unicast-response bit (0x8000)
       因为 unicast 模式下我们直接 sendto unicast,响应自然是 unicast */
    buf[pos++] = 0x00; buf[pos++] = 0x01;

    return (int)pos;
}

/* ── DNS 响应解析 ─────────────────────────────────────────── */

/* 从 pkt[*off] 开始解析 DNS name(支持 compression pointer),
 * 把解码后的 name 写入 out (max outlen 字节, NUL terminated)。
 * 返回:成功 → 0 并把 *off 推进到 name 后(不跨过被 jump 的部分),失败 -1 */
static int decode_dns_name(const uint8_t *pkt, size_t pktlen,
                           size_t *off, char *out, size_t outlen)
{
    size_t out_pos = 0;
    size_t cur = *off;
    int jumps = 0;
    int jumped = 0;
    size_t after_first_label = 0;  /* 第一次跳转之前的下一个位置 */

    while (1) {
        if (cur >= pktlen) return -1;
        uint8_t len = pkt[cur];

        if (len == 0) {
            cur++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            /* compression pointer (2 bytes) */
            if (cur + 1 >= pktlen) return -1;
            uint16_t ptr = ((len & 0x3F) << 8) | pkt[cur + 1];
            if (!jumped) after_first_label = cur + 2;
            jumped = 1;
            jumps++;
            if (jumps > MAX_NAME_JUMPS) return -1;
            if (ptr >= pktlen) return -1;
            cur = ptr;
            continue;
        }

        if (len > 63) return -1;  /* 非法 label 长度 */
        if (cur + 1 + len > pktlen) return -1;

        if (out_pos + len + 1 >= outlen) return -1;
        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, pkt + cur + 1, len);
        out_pos += len;

        cur += 1 + len;
    }

    out[out_pos] = '\0';
    *off = jumped ? after_first_label : cur;
    return 0;
}

/* 解析响应包,找出第一个 PTR answer 的 rdata。
 * v3.5.0 P1-9: 加 rname 验证 — multicast 模式下任何设备都能广播 PTR 回答,
 * 必须验证 rname == 我们查询的 <reversed>.in-addr.arpa,防止恶意伪造。
 * expected_rname: NULL = 不验证(unicast 模式安全),非 NULL = 验证字符串完全匹配
 * 写入 hostname out。返回 0 成功,-1 失败 */
static int parse_response(const uint8_t *pkt, size_t pktlen, char *out, size_t outlen,
                          const char *expected_rname)
{
    if (pktlen < 12) { VLOG("response too short: %zu\n", pktlen); return -1; }

    /* DNS header */
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    if ((flags & 0x8000) == 0) { VLOG("not a response (QR=0)\n"); return -1; }

    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    VLOG("response: qd=%u an=%u flags=0x%04x\n", qdcount, ancount, flags);
    if (ancount == 0) { VLOG("no answer\n"); return -1; }

    size_t off = 12;

    /* 跳过 question section */
    for (uint16_t i = 0; i < qdcount; i++) {
        char dummy[MAX_NAME_LEN];
        if (decode_dns_name(pkt, pktlen, &off, dummy, sizeof(dummy)) < 0) return -1;
        if (off + 4 > pktlen) return -1;
        off += 4;  /* QTYPE + QCLASS */
    }

    /* 遍历 answer section,找第一个 PTR */
    for (uint16_t i = 0; i < ancount; i++) {
        char rname[MAX_NAME_LEN];
        if (decode_dns_name(pkt, pktlen, &off, rname, sizeof(rname)) < 0) return -1;
        if (off + 10 > pktlen) return -1;
        uint16_t rtype = (pkt[off] << 8) | pkt[off+1];
        /* uint16_t rclass = (pkt[off+2] << 8) | pkt[off+3]; */
        /* uint32_t ttl = ... */
        uint16_t rdlen = (pkt[off+8] << 8) | pkt[off+9];
        off += 10;
        if (off + rdlen > pktlen) return -1;

        VLOG("answer[%u]: name=%s type=0x%04x rdlen=%u\n", i, rname, rtype, rdlen);

        /* v3.5.0 P1-9: 验证 rname 跟我们查询的一致(防 multicast 伪造) */
        if (expected_rname != NULL && strcasecmp(rname, expected_rname) != 0) {
            VLOG("rname mismatch: got %s expected %s, skipping\n", rname, expected_rname);
            off += rdlen;
            continue;
        }

        if (rtype == 0x000C) {  /* PTR */
            size_t rdata_off = off;
            if (decode_dns_name(pkt, pktlen, &rdata_off, out, outlen) == 0) {
                VLOG("PTR rdata: %s\n", out);
                return 0;
            }
            return -1;
        }

        off += rdlen;
    }

    VLOG("no PTR answer found\n");
    return -1;
}

/* 把 "Mi-10.local" / "Mi-10.local." → "Mi-10" */
static void strip_local_suffix(char *name)
{
    size_t n = strlen(name);
    /* 去尾部 dot */
    while (n > 0 && name[n-1] == '.') { name[n-1] = '\0'; n--; }
    /* 去尾部 .local */
    if (n > 6 && strcasecmp(name + n - 6, ".local") == 0) {
        name[n-6] = '\0';
    }
}

/* ── 网络收发 ─────────────────────────────────────────────── */

static int set_socket_timeout(int fd, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* 单次 query 尝试。target_ip = NULL 时走 multicast。
 * 返回 0 成功(out 填好),-1 失败 */
static int try_query(const char *src_ip, const char *target_ip, int timeout_ms,
                     char *out, size_t outlen)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { VLOG("socket: %s\n", strerror(errno)); return -1; }

    /* 绑定本地 5353 ? — 不绑,因为 mDNS responder 已经占用了。
       让 kernel 随机分配端口,响应回来仍然能收到。
       这跟标准 mDNS 行为略有不同,但 unicast 5353 查询的设备一般会
       正确回到 source port。multicast 模式下也能工作,因为我们用
       带超时的 recvfrom 主动等待。 */

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (target_ip == NULL) {
        /* multicast: TTL = 255 (RFC 6762 §11) */
        unsigned char ttl = 255;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    }

    set_socket_timeout(fd, timeout_ms);

    /* 构造 query packet */
    uint8_t pkt[MAX_PKT];
    uint16_t txid = (uint16_t)(time(NULL) & 0xFFFF);
    int qlen = build_query(src_ip, pkt, sizeof(pkt), txid);
    if (qlen < 0) { VLOG("build_query failed\n"); close(fd); return -1; }

    /* v3.5.0 P1-9: 构造 expected_rname 给 parse_response 验证 */
    char expected_rname[64];
    {
        unsigned int a, b, c, d;
        if (sscanf(src_ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            snprintf(expected_rname, sizeof(expected_rname),
                     "%u.%u.%u.%u.in-addr.arpa", d, c, b, a);
        } else {
            expected_rname[0] = '\0';  /* 构造失败,parse 跳过验证 */
        }
    }

    /* sendto */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MDNS_PORT);
    if (inet_pton(AF_INET, target_ip ? target_ip : MDNS_MULTICAST, &dst.sin_addr) != 1) {
        VLOG("inet_pton failed\n");
        close(fd);
        return -1;
    }

    VLOG("sendto %s:%d (%d bytes, txid=0x%04x)\n",
         target_ip ? target_ip : MDNS_MULTICAST, MDNS_PORT, qlen, txid);

    if (sendto(fd, pkt, qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        VLOG("sendto: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* recvfrom — 可能收到多个响应(尤其 multicast),挑第一个匹配 txid 的 */
    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        long elapsed_ms = (t_now.tv_sec - t_start.tv_sec) * 1000 +
                          (t_now.tv_nsec - t_start.tv_nsec) / 1000000;
        if (elapsed_ms >= timeout_ms) {
            VLOG("timeout after %ld ms\n", elapsed_ms);
            close(fd);
            return -1;
        }
        set_socket_timeout(fd, (int)(timeout_ms - elapsed_ms));

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                VLOG("recv timeout\n");
            } else {
                VLOG("recvfrom: %s\n", strerror(errno));
            }
            close(fd);
            return -1;
        }
        if (n < 12) continue;

        uint16_t reply_txid = (pkt[0] << 8) | pkt[1];
        VLOG("recv %zd bytes from %s txid=0x%04x\n",
             n, inet_ntoa(from.sin_addr), reply_txid);
        /* mDNS responses sometimes use txid=0 (broadcast/multicast announcement),
           but our unicast query expects matching txid. Be lenient: accept any. */
        (void)reply_txid;

        if (parse_response(pkt, (size_t)n, out, outlen,
                           expected_rname[0] ? expected_rname : NULL) == 0) {
            close(fd);
            return 0;
        }
        /* 不匹配的响应,继续等下一个 */
    }
}

/* ── main ─────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "HNC v3.4.6 mDNS Reverse Resolver\n\n"
        "用法:\n"
        "  %s [-t ms] [-v] <ipv4>\n\n"
        "选项:\n"
        "  -t <ms>   超时(毫秒),默认 800\n"
        "  -v        verbose,打印诊断到 stderr\n\n"
        "示例:\n"
        "  %s 10.193.171.30\n"
        "  %s -t 1500 -v 192.168.43.5\n",
        prog, prog, prog);
}

int main(int argc, char *argv[])
{
    int timeout_ms = DEFAULT_TIMEOUT;
    const char *ip = NULL;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[i+1]);
            if (timeout_ms <= 0 || timeout_ms > 10000) timeout_ms = DEFAULT_TIMEOUT;
            i += 2;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
            i++;
        } else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 1;
        } else {
            ip = argv[i];
            i++;
        }
    }

    if (!ip) { usage(argv[0]); return 1; }

    /* 验证 IPv4 格式 */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip, &tmp) != 1) {
        VLOG("invalid IPv4: %s\n", ip);
        return 1;
    }

    char hostname[MAX_NAME_LEN] = {0};

    /* 第一次:unicast 直接打到目标 IP — 大多数现代设备会响应 */
    VLOG("=== unicast attempt ===\n");
    if (try_query(ip, ip, timeout_ms / 2, hostname, sizeof(hostname)) == 0) {
        strip_local_suffix(hostname);
        if (hostname[0]) {
            printf("%s\n", hostname);
            return 0;
        }
    }

    /* 第二次:multicast 兜底 — 老设备只回多播 */
    VLOG("=== multicast attempt ===\n");
    memset(hostname, 0, sizeof(hostname));
    if (try_query(ip, NULL, timeout_ms / 2, hostname, sizeof(hostname)) == 0) {
        strip_local_suffix(hostname);
        if (hostname[0]) {
            printf("%s\n", hostname);
            return 0;
        }
    }

    return 1;
}
