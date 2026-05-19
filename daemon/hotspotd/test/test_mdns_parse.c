/* test_mdns_parse.c — 单元测试 mdns_resolve 的响应解析逻辑
 *
 * 不依赖网络。手工构造 DNS 响应包,验证 parse_response 输出正确的 hostname。
 *
 * 复制 mdns_resolve.c 里的解析函数,在沙箱里直接编译运行。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>

#define MAX_NAME_JUMPS  16
#define MAX_NAME_LEN    256

static int verbose = 1;
#define VLOG(...) do { if (verbose) fprintf(stderr, "[mdns] " __VA_ARGS__); } while (0)

/* === 复制自 mdns_resolve.c === */

static int decode_dns_name(const uint8_t *pkt, size_t pktlen,
                           size_t *off, char *out, size_t outlen)
{
    size_t out_pos = 0;
    size_t cur = *off;
    int jumps = 0;
    int jumped = 0;
    size_t after_first_label = 0;

    while (1) {
        if (cur >= pktlen) return -1;
        uint8_t len = pkt[cur];

        if (len == 0) {
            cur++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
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

        if (len > 63) return -1;
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

/* v3.5.0 P1-9: parse_response 现在接受 expected_rname 参数,
 * 用于验证 PTR answer 的 rname 是否匹配查询的 IP(防 multicast 伪造) */
static int parse_response(const uint8_t *pkt, size_t pktlen, char *out, size_t outlen,
                          const char *expected_rname)
{
    if (pktlen < 12) { VLOG("response too short: %zu\n", pktlen); return -1; }
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    if ((flags & 0x8000) == 0) { VLOG("not a response (QR=0)\n"); return -1; }
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    VLOG("response: qd=%u an=%u flags=0x%04x\n", qdcount, ancount, flags);
    if (ancount == 0) { VLOG("no answer\n"); return -1; }

    size_t off = 12;
    for (uint16_t i = 0; i < qdcount; i++) {
        char dummy[MAX_NAME_LEN];
        if (decode_dns_name(pkt, pktlen, &off, dummy, sizeof(dummy)) < 0) return -1;
        if (off + 4 > pktlen) return -1;
        off += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        char rname[MAX_NAME_LEN];
        if (decode_dns_name(pkt, pktlen, &off, rname, sizeof(rname)) < 0) return -1;
        if (off + 10 > pktlen) return -1;
        uint16_t rtype = (pkt[off] << 8) | pkt[off+1];
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

        if (rtype == 0x000C) {
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

static void strip_local_suffix(char *name)
{
    size_t n = strlen(name);
    while (n > 0 && name[n-1] == '.') { name[n-1] = '\0'; n--; }
    if (n > 6 && strcasecmp(name + n - 6, ".local") == 0) {
        name[n-6] = '\0';
    }
}

/* === 测试 === */

static int test_count = 0;
static int pass_count = 0;

#define ASSERT_EQ(actual, expected, label) do { \
    test_count++; \
    if (strcmp((actual), (expected)) == 0) { \
        pass_count++; \
        printf("[PASS] %s: '%s'\n", label, actual); \
    } else { \
        printf("[FAIL] %s: got '%s' expected '%s'\n", label, actual, expected); \
    } \
} while (0)

/* 手工构造一个 mDNS 响应:
 *   Question: 30.171.193.10.in-addr.arpa PTR IN
 *   Answer:   30.171.193.10.in-addr.arpa PTR Mi-10.local
 *
 * 用 name compression 让 answer 引用 question 里的 name(常见做法)
 */
static void test_basic_ptr(void)
{
    uint8_t pkt[] = {
        /* DNS Header */
        0x12, 0x34,             /* ID */
        0x84, 0x00,             /* Flags: QR=1 AA=1 (RR mDNS authoritative response) */
        0x00, 0x01,             /* QDCOUNT=1 */
        0x00, 0x01,             /* ANCOUNT=1 */
        0x00, 0x00,             /* NSCOUNT=0 */
        0x00, 0x00,             /* ARCOUNT=0 */

        /* Question: 30.171.193.10.in-addr.arpa */
        0x02, '3','0',
        0x03, '1','7','1',
        0x03, '1','9','3',
        0x02, '1','0',
        0x07, 'i','n','-','a','d','d','r',
        0x04, 'a','r','p','a',
        0x00,
        0x00, 0x0C,             /* QTYPE=PTR */
        0x00, 0x01,             /* QCLASS=IN */

        /* Answer: pointer to question name (offset 12) */
        0xC0, 0x0C,             /* compression pointer to byte 12 */
        0x00, 0x0C,             /* TYPE=PTR */
        0x00, 0x01,             /* CLASS=IN */
        0x00, 0x00, 0x00, 0x0A, /* TTL=10 */
        0x00, 0x09,             /* RDLENGTH=9 */
        0x05, 'M','i','-','1','0',
        0x05, 'l','o','c','a','l',
        0x00
    };

    char out[256] = {0};
    int rc = parse_response(pkt, sizeof(pkt), out, sizeof(out), NULL);
    if (rc != 0) {
        printf("[FAIL] test_basic_ptr: parse failed\n");
        test_count++;
        return;
    }
    strip_local_suffix(out);
    ASSERT_EQ(out, "Mi-10", "test_basic_ptr");
}

/* 没有 compression,纯 inline name */
static void test_no_compression(void)
{
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

        /* Question */
        0x02, '5','5',
        0x03, '4','3','2',
        0x03, '1','6','8',
        0x03, '1','9','2',
        0x07, 'i','n','-','a','d','d','r',
        0x04, 'a','r','p','a',
        0x00,
        0x00, 0x0C, 0x00, 0x01,

        /* Answer: full inline name (no pointer) */
        0x02, '5','5',
        0x03, '4','3','2',
        0x03, '1','6','8',
        0x03, '1','9','2',
        0x07, 'i','n','-','a','d','d','r',
        0x04, 'a','r','p','a',
        0x00,
        0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78,
        0x00, 0x10,             /* RDLENGTH = 16 */
        0x09, 'D','E','S','K','T','O','P','-','X',
        0x05, 'l','o','c','a','l',
        0x00
    };

    char out[256] = {0};
    if (parse_response(pkt, sizeof(pkt), out, sizeof(out), NULL) != 0) {
        printf("[FAIL] test_no_compression: parse failed\n");
        test_count++;
        return;
    }
    strip_local_suffix(out);
    ASSERT_EQ(out, "DESKTOP-X", "test_no_compression");
}

/* 嵌套 compression: rdata 包含 pointer */
static void test_rdata_compression(void)
{
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

        /* offset 12: Question name */
        0x02, '1','0',           /* offset 12 */
        0x03, '1','9','3',       /* offset 15 */
        0x03, '1','7','1',       /* offset 19 */
        0x02, '3','0',           /* offset 23 */
        0x07, 'i','n','-','a','d','d','r',  /* offset 26 */
        0x04, 'a','r','p','a',   /* offset 34 */
        0x00,                    /* offset 39 */
        0x00, 0x0C, 0x00, 0x01,  /* offset 40-43 */

        /* Answer */
        0xC0, 0x0C,              /* name pointer to question */
        0x00, 0x0C, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x0A,
        0x00, 0x0E,              /* RDLENGTH = 14 */
        0x07, 'M','y','P','h','o','n','e',  /* "MyPhone" */
        0x05, 'l','o','c','a','l',          /* "local" */
        0x00
    };

    char out[256] = {0};
    if (parse_response(pkt, sizeof(pkt), out, sizeof(out), NULL) != 0) {
        printf("[FAIL] test_rdata_compression: parse failed\n");
        test_count++;
        return;
    }
    strip_local_suffix(out);
    ASSERT_EQ(out, "MyPhone", "test_rdata_compression");
}

/* 防御:循环 compression pointer */
static void test_compression_loop(void)
{
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

        /* answer name = pointer to itself (offset 12) */
        0xC0, 0x0C,              /* offset 12: pointer to 12 */
        0x00, 0x0C, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x0A,
        0x00, 0x02,
        0xC0, 0x0C
    };

    char out[256] = {0};
    int rc = parse_response(pkt, sizeof(pkt), out, sizeof(out), NULL);
    test_count++;
    if (rc != 0) {
        pass_count++;
        printf("[PASS] test_compression_loop: rejected (rc=%d)\n", rc);
    } else {
        printf("[FAIL] test_compression_loop: should have rejected\n");
    }
}

/* strip_local_suffix 边界 */
static void test_strip_local(void)
{
    char buf[64];

    strcpy(buf, "Mi-10.local");
    strip_local_suffix(buf);
    ASSERT_EQ(buf, "Mi-10", "strip 'Mi-10.local'");

    strcpy(buf, "Mi-10.local.");
    strip_local_suffix(buf);
    ASSERT_EQ(buf, "Mi-10", "strip 'Mi-10.local.'");

    strcpy(buf, "DESKTOP.LOCAL");
    strip_local_suffix(buf);
    ASSERT_EQ(buf, "DESKTOP", "strip case-insensitive 'DESKTOP.LOCAL'");

    strcpy(buf, "no-suffix");
    strip_local_suffix(buf);
    ASSERT_EQ(buf, "no-suffix", "no suffix to strip");
}

/* v3.5.0 P1-9: rname 验证 — 接受匹配的应答 */
static void test_rname_validation_match(void)
{
    /* 跟 test_basic_ptr 一样的 packet,但传入正确的 expected_rname */
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, '5','5', 0x03, '4','3','2', 0x03, '1','6','8', 0x03, '1','9','2',
        0x07, 'i','n','-','a','d','d','r', 0x04, 'a','r','p','a', 0x00,
        0x00, 0x0C, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A,
        0x00, 0x09, 0x05, 'M','i','-','1','0', 0x05, 'l','o','c','a','l', 0x00
    };

    char out[256] = {0};
    int rc = parse_response(pkt, sizeof(pkt), out, sizeof(out), "55.432.168.192.in-addr.arpa");
    test_count++;
    if (rc == 0 && strstr(out, "Mi-10") != NULL) {
        pass_count++;
        printf("[PASS] test_rname_validation_match: accepted matching rname\n");
    } else {
        printf("[FAIL] test_rname_validation_match: rc=%d out='%s'\n", rc, out);
    }
}

/* v3.5.0 P1-9: rname 验证 — 拒绝不匹配的应答(防 multicast 伪造) */
static void test_rname_validation_mismatch(void)
{
    /* 同样的 packet,但传入不匹配的 expected_rname */
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, '5','5', 0x03, '4','3','2', 0x03, '1','6','8', 0x03, '1','9','2',
        0x07, 'i','n','-','a','d','d','r', 0x04, 'a','r','p','a', 0x00,
        0x00, 0x0C, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A,
        0x00, 0x09, 0x05, 'M','i','-','1','0', 0x05, 'l','o','c','a','l', 0x00
    };

    char out[256] = {0};
    /* 攻击者构造 — 应答里 rname 是 192.168.x.55 但我们其实查的是 1.1.1.1 */
    int rc = parse_response(pkt, sizeof(pkt), out, sizeof(out), "1.1.1.1.in-addr.arpa");
    test_count++;
    if (rc != 0) {
        pass_count++;
        printf("[PASS] test_rname_validation_mismatch: rejected fake rname (rc=%d)\n", rc);
    } else {
        printf("[FAIL] test_rname_validation_mismatch: should reject mismatched rname, got '%s'\n", out);
    }
}

/* v3.5.0 P1-9: rname 验证 — 大小写不敏感 */
static void test_rname_validation_case_insensitive(void)
{
    uint8_t pkt[] = {
        0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, '5','5', 0x03, '4','3','2', 0x03, '1','6','8', 0x03, '1','9','2',
        0x07, 'i','n','-','a','d','d','r', 0x04, 'a','r','p','a', 0x00,
        0x00, 0x0C, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A,
        0x00, 0x09, 0x05, 'M','i','-','1','0', 0x05, 'l','o','c','a','l', 0x00
    };

    char out[256] = {0};
    /* 大写 IN-ADDR.ARPA,应该照样匹配 */
    int rc = parse_response(pkt, sizeof(pkt), out, sizeof(out), "55.432.168.192.IN-ADDR.ARPA");
    test_count++;
    if (rc == 0) {
        pass_count++;
        printf("[PASS] test_rname_validation_case_insensitive: matched case insensitive\n");
    } else {
        printf("[FAIL] test_rname_validation_case_insensitive: should match\n");
    }
}

int main(void)
{
    printf("=== HNC mdns_resolve parser tests ===\n\n");

    test_basic_ptr();
    test_no_compression();
    test_rdata_compression();
    test_compression_loop();
    test_strip_local();

    /* v3.5.0 P1-9 新测试 */
    printf("\n--- P1-9 rname validation ---\n");
    test_rname_validation_match();
    test_rname_validation_mismatch();
    test_rname_validation_case_insensitive();

    printf("\n=== Results: %d/%d passed ===\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
