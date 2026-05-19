/* test_oui_override.c — HNC v3.8.3 D3 单元测试 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oui_override.h"

static int pass = 0, fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ✓ %s\n", name); pass++; } \
    else { printf("  ✗ %s\n", name); fail++; } \
} while(0)

#define TEST_PATH "/tmp/hnc_test_override.json"

static void write_file(const char *content) {
    FILE *f = fopen(TEST_PATH, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

int main(void) {
    char out[64];
    int rc;

    /* ─────────────────────────────────────────── */
    printf("\n── Section 1: init / reset / count ──\n");
    /* ─────────────────────────────────────────── */

    hnc_override_init(TEST_PATH);
    CHECK(hnc_override_count() == 0, "T01: 初始化后 count 为 0");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 2: 文件加载基本功能 ──\n");
    /* ─────────────────────────────────────────── */

    write_file("{\"28:6c:07\":\"小米手机\",\"b8:27:eb\":\"树莓派\"}");
    int loaded = hnc_override_load();
    CHECK(loaded == 2, "T02: 加载 2 条");
    CHECK(hnc_override_count() == 2, "T03: count 为 2");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:aa:bb:cc", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "小米手机") == 0,
          "T04: lookup 小米前缀命中");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("b8:27:eb:12:34:56", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "树莓派") == 0,
          "T05: lookup 树莓派前缀命中");

    rc = hnc_override_lookup("00:00:00:00:00:00", out, sizeof(out));
    CHECK(rc == 0, "T06: 未定义的前缀不命中");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 3: 格式宽松性 ──\n");
    /* ─────────────────────────────────────────── */

    /* 大写 MAC query */
    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6C:07:AA:BB:CC", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "小米手机") == 0, "T07: 大写 MAC query");

    /* 短 key(无冒号)在文件里 */
    hnc_override_reset();
    write_file("{\"286c07\":\"Xiaomi\",\"B827EB\":\"Pi\"}");
    loaded = hnc_override_load();
    CHECK(loaded == 2, "T08: 无冒号 key 加载");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:11:22:33", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "Xiaomi") == 0, "T09: 无冒号 key 被 query 命中");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("b8:27:eb:aa:bb:cc", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "Pi") == 0, "T10: 大写 hex key 被小写 query 命中");

    /* 横线分隔符 */
    hnc_override_reset();
    write_file("{\"28-6c-07\":\"Dashed\"}");
    loaded = hnc_override_load();
    CHECK(loaded == 1, "T11: 横线分隔符加载");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:00:00:00", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "Dashed") == 0, "T12: 横线 key 被冒号 query 命中");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 4: JSON 特殊字符 ──\n");
    /* ─────────────────────────────────────────── */

    hnc_override_reset();
    write_file("{\"28:6c:07\":\"Name with \\\"quotes\\\"\"}");
    loaded = hnc_override_load();
    CHECK(loaded == 1, "T13: 含 quotes 的 label 加载");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:11:22:33", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "Name with \"quotes\"") == 0,
          "T14: quotes 正确解码");

    hnc_override_reset();
    write_file("{\"28:6c:07\":\"Line1\\nLine2\"}");
    hnc_override_load();
    memset(out, 0, sizeof(out));
    hnc_override_lookup("28:6c:07:11:22:33", out, sizeof(out));
    CHECK(strcmp(out, "Line1\nLine2") == 0, "T15: 换行正确解码");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 5: 错误处理 ──\n");
    /* ─────────────────────────────────────────── */

    /* 文件不存在 */
    unlink(TEST_PATH);
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 0, "T16: 文件不存在返回 0");

    /* 空文件 */
    write_file("");
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 0, "T17: 空文件返回 0");

    /* 垃圾数据 */
    write_file("this is not json");
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 0, "T18: 垃圾数据不 crash,返回 0");

    /* 损坏 JSON */
    write_file("{\"28:6c:07\":\"unclosed");
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 0, "T19: 损坏 JSON 不 crash");

    /* 非法 key(不是合法 hex) */
    write_file("{\"not_a_mac\":\"something\",\"28:6c:07\":\"valid\"}");
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 1, "T20: 非法 key 跳过,合法 key 保留");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:11:22:33", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "valid") == 0, "T21: 合法 key 依然能查到");

    /* key 不够 6 hex */
    write_file("{\"28:6c\":\"too_short\"}");
    hnc_override_reset();
    loaded = hnc_override_load();
    CHECK(loaded == 0, "T22: 短于 6 hex 的 key 跳过");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 6: LAA MAC 支持 ──\n");
    /* ─────────────────────────────────────────── */

    /* override 对 LAA MAC 不跳过(这是它跟 hnc_lookup_oui 的关键区别) */
    hnc_override_reset();
    write_file("{\"7a:d6:f7\":\"Mi-10 随机\"}");
    loaded = hnc_override_load();
    CHECK(loaded == 1, "T23: LAA 前缀加载");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("7a:d6:f7:ce:ba:76", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "Mi-10 随机") == 0,
          "T24: LAA MAC(0x7a)override 命中(区别于 OUI 表)");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 7: 重复 key 去重 ──\n");
    /* ─────────────────────────────────────────── */

    hnc_override_reset();
    write_file("{\"28:6c:07\":\"first\",\"28:6c:07\":\"second\"}");
    loaded = hnc_override_load();
    CHECK(loaded == 1, "T25: 重复 key 只占 1 槽");

    memset(out, 0, sizeof(out));
    rc = hnc_override_lookup("28:6c:07:11:22:33", out, sizeof(out));
    CHECK(rc == 1 && strcmp(out, "second") == 0, "T26: 重复 key 保留最后值");

    /* ─────────────────────────────────────────── */
    printf("\n── Section 8: 清理 ──\n");
    /* ─────────────────────────────────────────── */

    unlink(TEST_PATH);
    CHECK(1, "T27: 清理文件");

    printf("\n═══ %d passed, %d failed ═══\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
