/* test_hostname_junk.c — v5.30 T1b: 垃圾主机名("null" 等)当作没有名字
 *
 * 由 test/unit/test_v530_hostname_junk_c.sh 编译运行:
 *   cc -o t test_hostname_junk.c ../hnc_helpers.c ../oui_override.c ../hostname_cache.c
 * 覆盖:
 *   - hnc_hostname_is_junk 名单 / 大小写 / 首尾空白 / 纯数字 / 空串 / NULL
 *   - hnc_ns_dhcp_pick_hostname(try_ns_dhcp_resolve 的解析段): 后来的 "null"
 *     不覆盖更早的真名; 只有 "null" → 没找到
 *   - hnc_cache_update 不收垃圾名; 旧版本落盘的 "null" 缓存不回放
 * 「改动前会失败」: v5.29 的 DHCP 解析取最后一行(= "null"), cache 照收。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hnc_helpers.h"
#include "hostname_cache.h"

static int pass = 0, fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ✓ %s\n", name); pass++; } \
    else { printf("  ✗ %s\n", name); fail++; } \
} while (0)

int main(int argc, char **argv) {
    const char *tmpdir = argc > 1 ? argv[1] : "/tmp";

    printf("── hnc_hostname_is_junk ──\n");
    const char *junk[] = { "null", "NULL", " Null ", "(null)", "nil", "none", "(none)",
                           "undefined", "unknown", "UNKNOWN", "localhost",
                           "localhost.localdomain", "*", "-", "", "   ", "\t", "0", "12345" };
    for (size_t i = 0; i < sizeof(junk) / sizeof(junk[0]); i++) {
        char name[96];
        snprintf(name, sizeof(name), "junk: \"%s\"", junk[i]);
        CHECK(hnc_hostname_is_junk(junk[i]) == 1, name);
    }
    CHECK(hnc_hostname_is_junk(NULL) == 1, "junk: NULL 指针");
    const char *good[] = { "Mi-10", "nullify", "iPhone", "localhost2", "123abc", "a",
                           "Johns-MacBook", "客厅电视", "-x", "none-pc" };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        char name[96];
        snprintf(name, sizeof(name), "good: \"%s\"", good[i]);
        CHECK(hnc_hostname_is_junk(good[i]) == 0, name);
    }

    printf("── hnc_ns_dhcp_pick_hostname ──\n");
    char buf[1024], out[64];
    snprintf(buf, sizeof(buf),
             "2026-10-07T10:00:00 - [wlan2.DHCP] Transmitting DhcpAckPacket hwAddr: 7A:D6:F7:CE:BA:76, netAddr: 10.0.0.2/24, hostname: Mi-10\n"
             "2026-10-07T10:01:00 - [wlan2.DHCP] Transmitting DhcpAckPacket hwAddr: 11:22:33:44:55:66, hostname: Other\n"
             "2026-10-07T10:02:00 - [wlan2.DHCP] Transmitting DhcpAckPacket hwAddr: 7a:d6:f7:ce:ba:76, hostname: null\n");
    strcpy(out, "untouched");
    CHECK(hnc_ns_dhcp_pick_hostname(buf, "7a:d6:f7:ce:ba:76", out, sizeof(out)) == 1 &&
          strcmp(out, "Mi-10") == 0, "dhcp: 后来的 \"null\" 不覆盖更早的真名");
    snprintf(buf, sizeof(buf),
             "x - hwAddr: aa:bb:cc:dd:ee:ff, hostname: null\n"
             "y - hwAddr: aa:bb:cc:dd:ee:ff, hostname: (none) \r\n");
    strcpy(out, "untouched");
    CHECK(hnc_ns_dhcp_pick_hostname(buf, "aa:bb:cc:dd:ee:ff", out, sizeof(out)) == 0 &&
          strcmp(out, "untouched") == 0, "dhcp: 只有垃圾名 → 没找到, out 不动");
    snprintf(buf, sizeof(buf),
             "a - hwAddr: aa:bb:cc:dd:ee:01, hostname: First\n"
             "b - hwAddr: aa:bb:cc:dd:ee:01, hostname: Second  \n");
    CHECK(hnc_ns_dhcp_pick_hostname(buf, "aa:bb:cc:dd:ee:01", out, sizeof(out)) == 1 &&
          strcmp(out, "Second") == 0, "dhcp: 多行取最新 + 去尾部空格(原行为)");

    printf("── hostname cache ──\n");
    char path[512];
    snprintf(path, sizeof(path), "%s/hnc_junk_cache.json", tmpdir);
    unlink(path);
    hnc_cache_init(path);
    CHECK(hnc_cache_update("aa:bb:cc:dd:ee:02", "null", "dhcp") == 0 && hnc_cache_count() == 0,
          "cache: update 拒收 \"null\"");
    CHECK(hnc_cache_update("aa:bb:cc:dd:ee:02", "Pixel-7", "mdns") == 1, "cache: 真名照收");
    CHECK(hnc_cache_update("aa:bb:cc:dd:ee:02", "undefined", "mdns") == 0, "cache: 垃圾名不覆盖已有真名");
    char hn[64], src[12];
    CHECK(hnc_cache_lookup("aa:bb:cc:dd:ee:02", hn, sizeof(hn), src, sizeof(src)) == 1 &&
          strcmp(hn, "Pixel-7") == 0, "cache: 真名仍可查");

    /* 旧版本落盘的 "null" 条目: load 进来但 lookup 不回放 */
    FILE *f = fopen(path, "w");
    if (f) {
        fputs("{\"aa:bb:cc:dd:ee:03\":{\"h\":\"null\",\"s\":\"dhcp\",\"t\":1790000000},"
              "\"aa:bb:cc:dd:ee:04\":{\"h\":\"Desk\",\"s\":\"dhcp\",\"t\":1790000000}}\n", f);
        fclose(f);
    }
    hnc_cache_init(path);
    int loaded = hnc_cache_load();
    CHECK(loaded >= 1, "cache: 旧缓存文件可加载");
    CHECK(hnc_cache_lookup("aa:bb:cc:dd:ee:03", hn, sizeof(hn), src, sizeof(src)) == 0,
          "cache: 存量 \"null\" 条目不回放");
    CHECK(hnc_cache_lookup("aa:bb:cc:dd:ee:04", hn, sizeof(hn), src, sizeof(src)) == 1 &&
          strcmp(hn, "Desk") == 0, "cache: 同文件里的真名照常回放");
    unlink(path);

    printf("═══ %d passed, %d failed ═══\n", pass, fail);
    return fail ? 1 : 0;
}
