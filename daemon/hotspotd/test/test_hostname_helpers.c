/* test_hostname_helpers.c — 单元测试 hotspotd 的 hostname 解析逻辑
 *
 * 测试 v3.5.0-beta1 P0-4 + P1-8 修复:
 *   - lookup_manual_name() 正确读取 device_names.json
 *   - resolve_hostname() 优先级 manual > mdns > mac
 *   - mac 兜底与 shell 路径对齐(后 8 字符,去冒号)
 *
 * v3.6 Commit 2: 不再复制 helper 函数,改用 #include "../hnc_helpers.h"
 * 主代码和测试 link 同一个 hnc_helpers.o,彻底消除 drift 风险。
 *
 * 编译:
 *   cd daemon/test
 *   gcc -Wall -Wextra -o test_hostname_helpers \
 *       test_hostname_helpers.c ../hnc_helpers.c
 *   ./test_hostname_helpers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

/* v3.6 Commit 2: 共享 helper 实现 */
#include "../hnc_helpers.h"

/* 兼容测试代码对旧 macro 的引用 */
#define MAC_STR_LEN  HNC_MAC_STR_LEN
#define HN_LEN       HNC_HN_LEN
#define HN_SRC_LEN   HNC_HN_SRC_LEN

/* 测试用临时路径(每个 process pid 独立) */
static char DEVICE_NAMES_JSON[256];

/* v3.6 Commit 2: 测试 wrapper — 跟 v3.5 的签名保持一致,让测试调用点不用改
 * 内部转发给 hnc_helpers 的参数化版本,传入测试路径 */
static int lookup_manual_name(const char *mac, char *out, size_t outlen) {
    return hnc_lookup_manual_name(mac, DEVICE_NAMES_JSON, out, outlen);
}

static void mac_fallback(const char *mac, char *out_hn, size_t hn_len) {
    hnc_mac_fallback(mac, out_hn, hn_len);
}

/* === 测试基础设施 === */
static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ(expected, actual, name) do {                              \
    if (strcmp((expected), (actual)) == 0) {                                \
        g_pass++;                                                           \
        printf("  ✓ %s\n", name);                                           \
    } else {                                                                \
        g_fail++;                                                           \
        printf("  ✗ %s\n    expected: %s\n    actual:   %s\n",              \
               name, expected, actual);                                     \
    }                                                                       \
} while (0)

#define ASSERT_INT_EQ(expected, actual, name) do {                          \
    if ((expected) == (actual)) {                                           \
        g_pass++;                                                           \
        printf("  ✓ %s\n", name);                                           \
    } else {                                                                \
        g_fail++;                                                           \
        printf("  ✗ %s\n    expected: %d\n    actual:   %d\n",              \
               name, (int)(expected), (int)(actual));                       \
    }                                                                       \
} while (0)

static void write_test_file(const char *content) {
    FILE *f = fopen(DEVICE_NAMES_JSON, "w");
    if (!f) { perror("write_test_file"); exit(1); }
    fputs(content, f);
    fclose(f);
}

/* === 测试用例 === */

static void test_lookup_manual_name_empty_file(void) {
    write_test_file("{}");
    char out[HN_LEN] = "x";
    int rc = lookup_manual_name("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    ASSERT_INT_EQ(0, rc, "empty file returns 0");
}

static void test_lookup_manual_name_basic(void) {
    write_test_file("{\"aa:bb:cc:dd:ee:ff\":\"Living Room TV\"}");
    char out[HN_LEN] = "";
    int rc = lookup_manual_name("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    ASSERT_INT_EQ(1, rc, "basic lookup returns 1");
    ASSERT_EQ("Living Room TV", out, "basic lookup value");
}

static void test_lookup_manual_name_chinese(void) {
    write_test_file("{\"aa:bb:cc:dd:ee:ff\":\"客厅平板\"}");
    char out[HN_LEN] = "";
    int rc = lookup_manual_name("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    ASSERT_INT_EQ(1, rc, "chinese lookup returns 1");
    ASSERT_EQ("客厅平板", out, "chinese name preserved");
}

static void test_lookup_manual_name_multiple(void) {
    write_test_file(
        "{\"11:11:11:11:11:11\":\"Phone\","
        "\"22:22:22:22:22:22\":\"Laptop\","
        "\"33:33:33:33:33:33\":\"Tablet\"}");
    char out[HN_LEN] = "";
    lookup_manual_name("22:22:22:22:22:22", out, sizeof(out));
    ASSERT_EQ("Laptop", out, "lookup middle entry");

    out[0] = '\0';
    lookup_manual_name("33:33:33:33:33:33", out, sizeof(out));
    ASSERT_EQ("Tablet", out, "lookup last entry");

    out[0] = '\0';
    lookup_manual_name("11:11:11:11:11:11", out, sizeof(out));
    ASSERT_EQ("Phone", out, "lookup first entry");
}

static void test_lookup_manual_name_not_found(void) {
    write_test_file("{\"aa:bb:cc:dd:ee:01\":\"Phone\"}");
    char out[HN_LEN] = "x";
    int rc = lookup_manual_name("aa:bb:cc:dd:ee:99", out, sizeof(out));
    ASSERT_INT_EQ(0, rc, "missing mac returns 0");
}

static void test_lookup_manual_name_case_insensitive(void) {
    write_test_file("{\"aa:bb:cc:dd:ee:ff\":\"TV\"}");
    char out[HN_LEN] = "";
    /* hotspotd 内 mac 已经 lower,但万一有 bug 测一下 */
    int rc = lookup_manual_name("AA:BB:CC:DD:EE:FF", out, sizeof(out));
    ASSERT_INT_EQ(1, rc, "uppercase mac matches lowercase entry");
    ASSERT_EQ("TV", out, "case insensitive value");
}

static void test_lookup_manual_name_escape_quote(void) {
    /* 文件内 a\"b → 解码后 a"b */
    write_test_file("{\"aa:bb:cc:dd:ee:ff\":\"Bob\\\"s TV\"}");
    char out[HN_LEN] = "";
    lookup_manual_name("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    ASSERT_EQ("Bob\"s TV", out, "escape quote decoded");
}

static void test_lookup_no_file(void) {
    unlink(DEVICE_NAMES_JSON);
    char out[HN_LEN] = "x";
    int rc = lookup_manual_name("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    ASSERT_INT_EQ(0, rc, "missing file returns 0");
}

/* === mac_fallback 测试 (P1-8 对齐 shell) === */

static void test_mac_fallback_standard(void) {
    char out[HN_LEN] = "";
    mac_fallback("aa:bb:cc:dd:ee:ff", out, sizeof(out));
    /* shell: aa:bb:cc:dd:ee:ff → aabbccddeeff → tail -c 9 → "ccddeeff" (8 字符) */
    ASSERT_EQ("ccddeeff", out, "standard MAC fallback");
}

static void test_mac_fallback_short(void) {
    char out[HN_LEN] = "";
    mac_fallback("11:22:33", out, sizeof(out));
    /* 去冒号: "112233", 长度 6 < 8, 全部输出 */
    ASSERT_EQ("112233", out, "short MAC returns full");
}

static void test_mac_fallback_no_colon(void) {
    char out[HN_LEN] = "";
    mac_fallback("aabbccddeeff", out, sizeof(out));
    /* 已经无冒号: "aabbccddeeff", 取后 8 → "ccddeeff" */
    ASSERT_EQ("ccddeeff", out, "MAC without colons");
}

/* === v3.5.0-rc R-2 / v3.5.2 P1-A / v3.6 Commit 2: re-resolve 触发条件测试 ===
 *
 * v3.6 Commit 2 修复:
 * v3.5.2 P1-A 只是"复制真签名+真实现"作为过渡,现在 hnc_helpers.c 提供了
 * hnc_should_re_resolve(),测试直接 #include 头文件调用真实函数,彻底消除
 * 复制 drift 风险。
 *
 * 如果主代码改阈值(60s → 30s),测试会立即观察到差异——因为它调的是同一个
 * link-time symbol,不是平行宇宙的副本。
 */

/* 测试 wrapper:保持跟 v3.5.2 的调用签名兼容,内部转发给 hnc_helpers */
static int should_re_resolve(const char *hostname_src, time_t last_resolve, time_t now) {
    return hnc_should_re_resolve(hostname_src, last_resolve, now);
}

static void test_re_resolve_mac_fallback_immediate(void) {
    int rc = should_re_resolve("mac", (time_t)1000, (time_t)1005);
    ASSERT_INT_EQ(1, rc, "mac fallback always re-resolves");
}

static void test_re_resolve_manual_within_window(void) {
    int rc = should_re_resolve("manual", (time_t)1000, (time_t)1030);
    ASSERT_INT_EQ(0, rc, "manual within 60s window: no re-resolve");
}

static void test_re_resolve_manual_after_window(void) {
    int rc = should_re_resolve("manual", (time_t)1000, (time_t)1060);
    ASSERT_INT_EQ(1, rc, "manual after 60s window: re-resolve");
}

static void test_re_resolve_manual_long_after(void) {
    int rc = should_re_resolve("manual", (time_t)1000, (time_t)1300);
    ASSERT_INT_EQ(1, rc, "manual after 5min: re-resolve");
}

static void test_re_resolve_mdns_within_window(void) {
    int rc = should_re_resolve("mdns", (time_t)1000, (time_t)1059);
    ASSERT_INT_EQ(0, rc, "mdns at 59s: no re-resolve");
}

static void test_re_resolve_mdns_at_exactly_60(void) {
    int rc = should_re_resolve("mdns", (time_t)1000, (time_t)1060);
    ASSERT_INT_EQ(1, rc, "mdns at exactly 60s: re-resolve (>= boundary)");
}

/* === v3.5.1 P0-2 / v3.6 Commit 2: json_escape 测试 ===
 *
 * v3.6 Commit 2: 从复制改为调用 hnc_helpers.c 的 hnc_json_escape,
 * 测试和主代码完全 link 同一个 symbol。 */

/* 测试 wrapper:签名兼容 */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    hnc_json_escape(src, dst, dst_size);
}

static void test_json_escape_plain(void) {
    char out[64];
    json_escape("hello", out, sizeof(out));
    ASSERT_EQ("hello", out, "plain ascii unchanged");
}

static void test_json_escape_double_quote(void) {
    char out[64];
    json_escape("My \"Phone\"", out, sizeof(out));
    ASSERT_EQ("My \\\"Phone\\\"", out, "double quote escaped");
}

static void test_json_escape_backslash(void) {
    char out[64];
    json_escape("a\\b", out, sizeof(out));
    ASSERT_EQ("a\\\\b", out, "backslash escaped");
}

static void test_json_escape_newline(void) {
    char out[64];
    json_escape("line1\nline2", out, sizeof(out));
    ASSERT_EQ("line1\\nline2", out, "newline escaped");
}

static void test_json_escape_tab_cr(void) {
    char out[64];
    json_escape("a\tb\rc", out, sizeof(out));
    ASSERT_EQ("a\\tb\\rc", out, "tab and CR escaped");
}

static void test_json_escape_control_char(void) {
    char out[64];
    /* C 字符串字面量 trap: "a\x01b" 实际是 "a" + char(0x1b)
     * 因为 \x 后接任意多 hex 字符。用八进制 \001 (最多 3 位) 避开 */
    json_escape("a\001b", out, sizeof(out));
    /* 期望 8 字符: a, \, u, 0, 0, 0, 1, b */
    const char *expected = "a\\u0001b";
    ASSERT_EQ(expected, out, "control char 0x01 as backslash u 0001 b");
}

static void test_json_escape_chinese_unchanged(void) {
    char out[128];
    json_escape("测试设备", out, sizeof(out));
    ASSERT_EQ("测试设备", out, "Chinese UTF-8 unchanged");
}

static void test_json_escape_empty(void) {
    char out[64];
    json_escape("", out, sizeof(out));
    ASSERT_EQ("", out, "empty string unchanged");
}

static void test_json_escape_truncation_safe(void) {
    char out[10];
    /* "a\"b\"c\"d\"e" → 9 chars + NUL,正好刚刚够 */
    json_escape("aaaaaaaaaa", out, sizeof(out));
    /* 应该是 "aaaaaaaaa" (9 char + NUL),最后一个 a 被截 */
    ASSERT_INT_EQ(9, (int)strlen(out), "small buffer truncates safely");
}

/* === v3.5.2 P2-F: UTF-8 边界回退测试 ===
 *
 * buffer 不够时不应切断 UTF-8 多字节序列,否则 JSON 合法但 UI 里显示乱码。
 * "测" = 0xE6 0xB5 0x8B (3 字节)
 * "试" = 0xE8 0xAF 0x95
 * "设" = 0xE8 0xAE 0xBE
 * "备" = 0xE5 0xA4 0x87
 */

static void test_json_escape_utf8_rollback_mid(void) {
    /* 4 个中文 = 12 字节,dst 只有 10 字节(9 可用 + NUL) → 应该写 3 个完整字符(9 字节),
     * 不能有残缺的第 4 个字符 */
    char out[10];
    json_escape("测试设备", out, sizeof(out));
    /* 期望 "测试设" = 9 字节 + NUL */
    ASSERT_INT_EQ(9, (int)strlen(out), "UTF-8 rollback: 9 bytes = 3 complete chars");
    ASSERT_EQ("测试设", out, "UTF-8 rollback: 3 complete Chinese chars");
}

static void test_json_escape_utf8_rollback_tight(void) {
    /* dst 只有 4 字节,最多能放 1 个 3-byte 中文字符 */
    char out[4];
    json_escape("测试", out, sizeof(out));
    /* 期望 "测" = 3 字节 + NUL */
    ASSERT_INT_EQ(3, (int)strlen(out), "UTF-8 rollback tight: 1 char");
    ASSERT_EQ("测", out, "UTF-8 rollback tight: first char only");
}

static void test_json_escape_utf8_no_truncation(void) {
    /* dst 足够大,不应触发回退 */
    char out[32];
    json_escape("测试", out, sizeof(out));
    ASSERT_EQ("测试", out, "UTF-8 complete in big buffer");
}

static void test_json_escape_utf8_cant_fit_lead_byte(void) {
    /* dst 太小,连一个 lead byte 都塞不下会怎样 */
    char out[3];
    json_escape("测", out, sizeof(out));
    /* 3 byte 字符,dst[0..1] 写 lead+cont1,循环条件 j+1<3 让 j 停在 1,然后第 3 字节
     * 因为 j+1>=3 不写 → j=2 是 continuation byte → 回退到 j=0。
     * 最终 dst = "" */
    ASSERT_INT_EQ(0, (int)strlen(out), "UTF-8 too small for even one char → empty");
}

/* === v3.6 Commit 3: pending 状态机测试 ===
 *
 * 测试 scan_arp 异步 mDNS 解析的几个核心不变量:
 *
 *   1) hnc_pending_ready 对非 pending 状态永远返回 0
 *   2) hnc_pending_ready 在 breathing room 内返回 0
 *   3) hnc_pending_ready 在 breathing room 过后返回 1
 *   4) hnc_resolve_hostname_fast 对有 manual 的设备直接返回 manual
 *   5) hnc_resolve_hostname_fast 对没 manual 的设备返回 mac(不做 mdns)
 *
 * 这些测试覆盖了 pending 状态机的"规则判定"部分。
 * FIFO 选择(最老的 pending)在 hotspotd.c 的 process_pending_mdns 里内联,
 * 就一个 `<` 比较,不单独测。
 */

static void test_pending_ready_mac_src_returns_false(void) {
    /* hostname_src="mac" 不是 pending,永远不 ready */
    int rc = hnc_pending_ready("mac", 1000, 2000);
    ASSERT_INT_EQ(0, rc, "pending_ready: mac src → not ready");
}

static void test_pending_ready_manual_src_returns_false(void) {
    /* hostname_src="manual" 不是 pending,永远不 ready */
    int rc = hnc_pending_ready("manual", 1000, 2000);
    ASSERT_INT_EQ(0, rc, "pending_ready: manual src → not ready");
}

static void test_pending_ready_mdns_src_returns_false(void) {
    /* hostname_src="mdns" 不是 pending,永远不 ready */
    int rc = hnc_pending_ready("mdns", 1000, 2000);
    ASSERT_INT_EQ(0, rc, "pending_ready: mdns src → not ready");
}

static void test_pending_ready_in_breathing_room(void) {
    /* hostname_src="pending",pending_since=1000,now=1000:
     * 刚标 pending 的同一秒,breathing room 未过,跳过 */
    int rc = hnc_pending_ready("pending", 1000, 1000);
    ASSERT_INT_EQ(0, rc, "pending_ready: just-pending (0s) → not ready");
}

static void test_pending_ready_at_breathing_room_boundary(void) {
    /* now - pending_since == 1 秒,刚好达到 breathing room 阈值 */
    int rc = hnc_pending_ready("pending", 1000, 1001);
    ASSERT_INT_EQ(1, rc, "pending_ready: at 1s boundary → ready");
}

static void test_pending_ready_after_breathing_room(void) {
    /* 已经挂 pending 5 秒,肯定 ready */
    int rc = hnc_pending_ready("pending", 1000, 1005);
    ASSERT_INT_EQ(1, rc, "pending_ready: 5s after → ready");
}

static void test_pending_ready_null_src(void) {
    /* 防御性:hostname_src 为 NULL 不应崩,返回 0 */
    int rc = hnc_pending_ready(NULL, 1000, 2000);
    ASSERT_INT_EQ(0, rc, "pending_ready: NULL src → not ready (no crash)");
}

/* === v3.6 Commit 3: resolve_hostname_fast 测试 ===
 *
 * fast 版本跟同步版本的区别:
 *   - 优先级只有 manual > mac(没有 mdns,因为 fast 绝不 popen)
 *   - 调用者负责之后异步解 mdns
 */

static void test_resolve_fast_manual_hit(void) {
    /* 写一个手动命名,fast 应该直接返回 manual */
    write_test_file("{\"aa:bb:cc:dd:ee:ff\":\"我的手机\"}");
    char hn[HN_LEN], src[HN_SRC_LEN];
    hnc_resolve_hostname_fast("aa:bb:cc:dd:ee:ff", "192.168.1.10",
                              DEVICE_NAMES_JSON, hn, sizeof(hn), src, sizeof(src));
    ASSERT_EQ("我的手机", hn, "fast: manual hit → hostname");
    ASSERT_EQ("manual", src, "fast: manual hit → src=manual");
}

static void test_resolve_fast_mac_fallback(void) {
    /* 清空文件,fast 应该落到 mac 兜底(不做 mdns) */
    write_test_file("{}");
    char hn[HN_LEN], src[HN_SRC_LEN];
    hnc_resolve_hostname_fast("aa:bb:cc:dd:ee:ff", "192.168.1.10",
                              DEVICE_NAMES_JSON, hn, sizeof(hn), src, sizeof(src));
    ASSERT_EQ("ccddeeff", hn, "fast: no manual → mac fallback hostname");
    ASSERT_EQ("mac", src, "fast: no manual → src=mac (caller should promote to pending)");
}

static void test_resolve_fast_case_insensitive_manual(void) {
    /* manual 查找大小写不敏感 */
    write_test_file("{\"AA:BB:CC:DD:EE:FF\":\"UpperCase\"}");
    char hn[HN_LEN], src[HN_SRC_LEN];
    hnc_resolve_hostname_fast("aa:bb:cc:dd:ee:ff", "192.168.1.10",
                              DEVICE_NAMES_JSON, hn, sizeof(hn), src, sizeof(src));
    ASSERT_EQ("UpperCase", hn, "fast: case-insensitive mac match");
    ASSERT_EQ("manual", src, "fast: case-insensitive → src=manual");
}

/* === main === */

int main(void) {
    snprintf(DEVICE_NAMES_JSON, sizeof(DEVICE_NAMES_JSON),
             "/tmp/hnc_test_device_names_%d.json", (int)getpid());

    printf("════════════════════════════════════════\n");
    printf("  hotspotd hostname helpers 测试\n");
    printf("════════════════════════════════════════\n\n");

    printf("── lookup_manual_name ──\n");
    test_lookup_manual_name_empty_file();
    test_lookup_manual_name_basic();
    test_lookup_manual_name_chinese();
    test_lookup_manual_name_multiple();
    test_lookup_manual_name_not_found();
    test_lookup_manual_name_case_insensitive();
    test_lookup_manual_name_escape_quote();
    test_lookup_no_file();

    printf("\n── mac_fallback (P1-8 shell 对齐) ──\n");
    test_mac_fallback_standard();
    test_mac_fallback_short();
    test_mac_fallback_no_colon();

    printf("\n── re-resolve 触发条件 (v3.5.0-rc R-2) ──\n");
    test_re_resolve_mac_fallback_immediate();
    test_re_resolve_manual_within_window();
    test_re_resolve_manual_after_window();
    test_re_resolve_manual_long_after();
    test_re_resolve_mdns_within_window();
    test_re_resolve_mdns_at_exactly_60();

    printf("\n── json_escape (v3.5.1 P0-2) ──\n");
    test_json_escape_plain();
    test_json_escape_double_quote();
    test_json_escape_backslash();
    test_json_escape_newline();
    test_json_escape_tab_cr();
    test_json_escape_control_char();
    test_json_escape_chinese_unchanged();
    test_json_escape_empty();
    test_json_escape_truncation_safe();

    printf("\n── json_escape UTF-8 边界回退 (v3.5.2 P2-F) ──\n");
    test_json_escape_utf8_rollback_mid();
    test_json_escape_utf8_rollback_tight();
    test_json_escape_utf8_no_truncation();
    test_json_escape_utf8_cant_fit_lead_byte();

    printf("\n── pending 状态机 (v3.6 Commit 3) ──\n");
    test_pending_ready_mac_src_returns_false();
    test_pending_ready_manual_src_returns_false();
    test_pending_ready_mdns_src_returns_false();
    test_pending_ready_in_breathing_room();
    test_pending_ready_at_breathing_room_boundary();
    test_pending_ready_after_breathing_room();
    test_pending_ready_null_src();

    printf("\n── resolve_hostname_fast (v3.6 Commit 3) ──\n");
    test_resolve_fast_manual_hit();
    test_resolve_fast_mac_fallback();
    test_resolve_fast_case_insensitive_manual();

    /* 清理 */
    unlink(DEVICE_NAMES_JSON);

    printf("\n════════════════════════════════════════\n");
    if (g_fail == 0) {
        printf("  ALL PASS: %d/%d\n", g_pass, g_pass);
    } else {
        printf("  FAIL: %d failed, %d passed\n", g_fail, g_pass);
    }
    printf("════════════════════════════════════════\n");

    return (g_fail == 0) ? 0 : 1;
}
