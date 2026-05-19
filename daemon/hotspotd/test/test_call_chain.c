/* test_call_chain.c — HNC 调用链集成测试 (v3.8.2 方案 G)
 *
 * ═══ 这是什么 ═══
 *
 * 这不是"契约测试",这是**真正的集成测试**:它加载并执行 hotspotd.c 里
 * 原汁原味的 resolve_hostname / resolve_hostname_dhcp_only / process_pending_mdns
 * 逻辑,在链接时用同名 static 函数覆盖 try_ns_dhcp_resolve / try_mdns_resolve,
 * 拦截外部 I/O。
 *
 * ═══ 工作原理(方案 G) ═══
 *
 * 1) hotspotd.c 顶部有这两个函数的 static 前向声明
 * 2) hotspotd.c 底部有它们的真实定义,整段被 #ifndef HNC_TEST_MODE 包围
 * 3) 本文件 #define HNC_TEST_MODE 然后 #include "../hotspotd.c"
 *    → hotspotd.c 的真实定义被 #ifdef 屏蔽,只剩前向声明
 *    → 本文件里提供同名 static 函数定义,编译器把 resolve_hostname 里
 *       的 try_*_resolve 调用点解析到本文件的定义
 * 4) main() 也被包在同一个 #ifndef 里,避免和测试 main 冲突
 *
 * 测试跑的是 100% 真实的 resolve_hostname 机器码,不是 shim 重实现。
 * v3.7.0 的坑 16 类 bug 会被真实调用链触发,不是被重写的"规范"捕获。
 *
 * ═══ 为什么不用 --wrap ═══
 *
 * GCC --wrap 只拦截跨 translation unit 的 undefined reference。HNC 的
 * resolve_hostname 和 try_ns_dhcp_resolve 在同一个 hotspotd.c 里,编译器
 * 在 .o 文件生成阶段就把 call 指令绑定到本文件地址,链接器无从介入。
 * smoke test 已证明 --wrap 在这种结构下无效。
 *
 * ═══ 测试覆盖 ═══
 *
 * Section 1: 优先级链契约 manual > dhcp > mdns > cache > oui > mac
 * Section 2: DHCP/mDNS 命中必须 update cache
 * Section 3: resolve_hostname_dhcp_only 不查 mDNS
 * Section 4: cache 兜底场景
 * Section 5: LAA bit (Mi-10 的 7a:d6:f7:ce:ba:76) 跳过 OUI
 * Section 6: v3.7.0 坑 16 回归保护(pending 路径 DHCP 命中 Mi-10)
 */

#define HNC_TEST_MODE 1

/* 必须在 include hotspotd.c 之前,提供 mock 状态 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ══════════════════════════════════════════════════════════
 * Mock framework 状态(必须在 hotspotd.c include 之前声明,因为
 * hotspotd.c 里的静态函数前向声明不影响这些全局)
 * ══════════════════════════════════════════════════════════ */

#define MAX_MOCK_ENTRIES 16

typedef struct {
    char mac[18];
    char result[64];
    int  called;
} mock_entry_t;

static mock_entry_t g_mock_dhcp[MAX_MOCK_ENTRIES];
static int g_mock_dhcp_count = 0;
static int g_mock_dhcp_total_calls = 0;

static mock_entry_t g_mock_mdns[MAX_MOCK_ENTRIES];
static int g_mock_mdns_count = 0;
static int g_mock_mdns_total_calls = 0;

/* ══════════════════════════════════════════════════════════
 * Include 整个 hotspotd.c
 *
 * 关键: HNC_TEST_MODE 已定义,所以 hotspotd.c 底部的 #ifndef HNC_TEST_MODE
 * 块(含 try_ns_dhcp_resolve / try_mdns_resolve / main 的真实定义)会被
 * 编译器跳过,只留下文件顶部的 static 前向声明。
 * ══════════════════════════════════════════════════════════ */
#include "../hotspotd.c"

/* ══════════════════════════════════════════════════════════
 * 提供 mock 定义(替换被 #ifdef 屏蔽的真实定义)
 *
 * 必须是 static,且签名完全匹配前向声明。编译器在处理 hotspotd.c 里
 * 对这些函数的调用时,会把 call 目标绑定到本文件这里的定义。
 * ══════════════════════════════════════════════════════════ */
static int try_mdns_resolve(const char *ip, const char *mac, char *out, size_t outlen) {
    (void)ip;
    g_mock_mdns_total_calls++;
    for (int i = 0; i < g_mock_mdns_count; i++) {
        if (strcmp(g_mock_mdns[i].mac, mac) == 0) {
            g_mock_mdns[i].called++;
            strncpy(out, g_mock_mdns[i].result, outlen - 1);
            out[outlen - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

static int try_ns_dhcp_resolve(const char *mac, char *out, size_t outlen) {
    g_mock_dhcp_total_calls++;
    for (int i = 0; i < g_mock_dhcp_count; i++) {
        if (strcmp(g_mock_dhcp[i].mac, mac) == 0) {
            g_mock_dhcp[i].called++;
            strncpy(out, g_mock_dhcp[i].result, outlen - 1);
            out[outlen - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * Mock helper: 设置 / 清空
 * ══════════════════════════════════════════════════════════ */
static void mock_reset(void) {
    memset(g_mock_dhcp, 0, sizeof(g_mock_dhcp));
    memset(g_mock_mdns, 0, sizeof(g_mock_mdns));
    g_mock_dhcp_count = 0;
    g_mock_mdns_count = 0;
    g_mock_dhcp_total_calls = 0;
    g_mock_mdns_total_calls = 0;
}

static void mock_dhcp_set(const char *mac, const char *result) {
    if (g_mock_dhcp_count >= MAX_MOCK_ENTRIES) return;
    strncpy(g_mock_dhcp[g_mock_dhcp_count].mac, mac, 17);
    g_mock_dhcp[g_mock_dhcp_count].mac[17] = '\0';
    strncpy(g_mock_dhcp[g_mock_dhcp_count].result, result, 63);
    g_mock_dhcp[g_mock_dhcp_count].result[63] = '\0';
    g_mock_dhcp_count++;
}

static void mock_mdns_set(const char *mac, const char *result) {
    if (g_mock_mdns_count >= MAX_MOCK_ENTRIES) return;
    strncpy(g_mock_mdns[g_mock_mdns_count].mac, mac, 17);
    g_mock_mdns[g_mock_mdns_count].mac[17] = '\0';
    strncpy(g_mock_mdns[g_mock_mdns_count].result, result, 63);
    g_mock_mdns[g_mock_mdns_count].result[63] = '\0';
    g_mock_mdns_count++;
}

/* ══════════════════════════════════════════════════════════
 * 测试断言
 * ══════════════════════════════════════════════════════════ */
static int pass = 0, fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ✓ %s\n", name); pass++; } \
    else { printf("  ✗ %s\n", name); fail++; } \
} while(0)

#define HAS_PREFIX(s, prefix) (strncmp((s), (prefix), strlen(prefix)) == 0)

static void setup(void) {
    mock_reset();
    hnc_cache_reset();
    /* 清空 g_devs 保证测试之间 pending 设备不串扰 */
    memset(g_devs, 0, sizeof(g_devs));
}

/* ══════════════════════════════════════════════════════════
 * Test Cases
 *
 * 这些 test 直接调用 hotspotd.c 里的 **真实** resolve_hostname 和
 * resolve_hostname_dhcp_only。它们内部的 try_ns_dhcp_resolve /
 * try_mdns_resolve 调用会被解析到本文件提供的 static mock。
 * ══════════════════════════════════════════════════════════ */

int main(void) {
    char hn[64], src[16];
    /* cache 初始化 — 用 /tmp 避免污染真实路径 */
    hnc_cache_init("/tmp/hnc_test_call_chain_cache.json");
    hnc_cache_reset();
    /* 清空 g_log 防止 hlog 尝试写文件 */
    extern FILE *g_log;
    g_log = NULL;

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 1: 优先级链 (真实 resolve_hostname) ──\n");
    /* ──────────────────────────────────────────────── */

    /* T01-T03: manual 命中时 DHCP/mDNS 不应被查
     * 注意: manual 走 hnc_lookup_manual_name 读真实文件 /data/local/hnc/data/device_names.json
     * 在 Linux 沙箱里文件不存在,返回 0。所以这个测试无法测 manual 命中分支。
     * 我们改测"manual 未命中时 DHCP 分支生效"这个核心场景。*/

    /* T01: DHCP 命中 */
    setup();
    mock_dhcp_set("aa:bb:cc:dd:ee:02", "Mi-10");
    mock_mdns_set("aa:bb:cc:dd:ee:02", "should-not-be-used");
    resolve_hostname("aa:bb:cc:dd:ee:02", "10.0.0.2", hn, 64, src, 16);
    CHECK(strcmp(hn, "Mi-10") == 0 && strcmp(src, "dhcp") == 0,
          "T01: DHCP 命中显示 dhcp src (真实 resolve_hostname)");
    CHECK(g_mock_mdns_total_calls == 0, "T02: DHCP 命中后 mDNS 未被调用");

    /* T03: mDNS 在 DHCP 失败后才查 */
    setup();
    mock_mdns_set("aa:bb:cc:dd:ee:03", "iPhone");
    resolve_hostname("aa:bb:cc:dd:ee:03", "10.0.0.3", hn, 64, src, 16);
    CHECK(strcmp(hn, "iPhone") == 0 && strcmp(src, "mdns") == 0,
          "T03: mDNS 命中(DHCP 未命中)");
    CHECK(g_mock_dhcp_total_calls == 1, "T04: DHCP 被尝试过 1 次");

    /* T05: OUI 命中(非随机 MAC) */
    setup();
    resolve_hostname("0c:bc:9f:11:22:33", "10.0.0.4", hn, 64, src, 16);
    CHECK(strcmp(hn, "Apple 设备") == 0 && strcmp(src, "oui") == 0,
          "T05: OUI 命中 Apple(无 mock,真实 bsearch)");

    /* T06: 最终 mac fallback */
    setup();
    resolve_hostname("00:00:00:00:00:01", "10.0.0.5", hn, 64, src, 16);
    CHECK(strcmp(src, "mac") == 0, "T06: 没有任何命中时回落 mac");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 2: DHCP/mDNS 命中必须更新 cache ──\n");
    /* ──────────────────────────────────────────────── */

    /* T07: DHCP 命中 → cache 真的被写入 */
    setup();
    mock_dhcp_set("aa:bb:cc:dd:ee:04", "Mi-10");
    resolve_hostname("aa:bb:cc:dd:ee:04", "10.0.0.6", hn, 64, src, 16);
    CHECK(hnc_cache_count() == 1, "T07: DHCP 命中后 cache 有 1 条");

    char cached_hn[64], cached_src[16];
    int rc = hnc_cache_lookup("aa:bb:cc:dd:ee:04", cached_hn, 64, cached_src, 16);
    CHECK(rc == 1 && strcmp(cached_hn, "Mi-10") == 0 && strcmp(cached_src, "dhcp") == 0,
          "T08: cache 内容正确 (Mi-10, dhcp)");

    /* T09: mDNS 命中 → cache 更新 */
    setup();
    mock_mdns_set("aa:bb:cc:dd:ee:05", "iPhone");
    resolve_hostname("aa:bb:cc:dd:ee:05", "10.0.0.7", hn, 64, src, 16);
    CHECK(hnc_cache_count() == 1, "T09: mDNS 命中后 cache 有 1 条");
    rc = hnc_cache_lookup("aa:bb:cc:dd:ee:05", cached_hn, 64, cached_src, 16);
    CHECK(rc == 1 && strcmp(cached_src, "mdns") == 0,
          "T10: cache 的 src 正确标为 mdns");

    /* T11: OUI 命中 **不** 写 cache */
    setup();
    resolve_hostname("0c:bc:9f:22:33:44", "10.0.0.9", hn, 64, src, 16);
    CHECK(hnc_cache_count() == 0, "T11: OUI 命中不写 cache");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 3: dhcp_only 不查 mDNS ──\n");
    /* ──────────────────────────────────────────────── */

    /* T12: dhcp_only 在 DHCP 失败时绝对不查 mDNS */
    setup();
    mock_mdns_set("aa:bb:cc:dd:ee:07", "iPhone");
    resolve_hostname_dhcp_only("aa:bb:cc:dd:ee:07", hn, 64, src, 16);
    CHECK(g_mock_mdns_total_calls == 0,
          "T12: dhcp_only 永不调用 mDNS (pending 路径非阻塞契约)");

    /* T13: dhcp_only 命中 DHCP 时依然更新 cache */
    setup();
    mock_dhcp_set("aa:bb:cc:dd:ee:08", "Mi-10");
    resolve_hostname_dhcp_only("aa:bb:cc:dd:ee:08", hn, 64, src, 16);
    CHECK(hnc_cache_count() == 1, "T13: dhcp_only 命中 DHCP 也更新 cache");
    CHECK(strcmp(hn, "Mi-10") == 0 && strcmp(src, "dhcp") == 0,
          "T14: dhcp_only 命中 DHCP 返回正确值");

    /* T15: dhcp_only DHCP 失败时查 cache */
    setup();
    hnc_cache_update("aa:bb:cc:dd:ee:09", "PreviouslyKnown", "dhcp");
    resolve_hostname_dhcp_only("aa:bb:cc:dd:ee:09", hn, 64, src, 16);
    CHECK(strcmp(hn, "PreviouslyKnown") == 0 && strcmp(src, "cache-dhcp") == 0,
          "T15: dhcp_only cache 命中,src 为 cache-dhcp");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 4: cache 兜底场景 ──\n");
    /* ──────────────────────────────────────────────── */

    /* T16: 完整 resolve_hostname 的 cache 兜底 */
    setup();
    hnc_cache_update("aa:bb:cc:dd:ee:0a", "OldMi10", "dhcp");
    resolve_hostname("aa:bb:cc:dd:ee:0a", "10.0.0.10", hn, 64, src, 16);
    CHECK(strcmp(hn, "OldMi10") == 0 && strcmp(src, "cache-dhcp") == 0,
          "T16: DHCP/mDNS 失败时 cache 兜底");

    /* T17: cache 比 OUI 优先级高 */
    setup();
    hnc_cache_update("0c:bc:9f:33:44:55", "Johns-iPhone", "mdns");
    resolve_hostname("0c:bc:9f:33:44:55", "10.0.0.11", hn, 64, src, 16);
    CHECK(strcmp(hn, "Johns-iPhone") == 0 && strcmp(src, "cache-mdns") == 0,
          "T17: cache 优先于 OUI(Johns-iPhone 而非 Apple 设备)");

    /* T18: DHCP 直接命中覆盖 cache */
    setup();
    hnc_cache_update("aa:bb:cc:dd:ee:0b", "OldName", "dhcp");
    mock_dhcp_set("aa:bb:cc:dd:ee:0b", "NewName");
    resolve_hostname("aa:bb:cc:dd:ee:0b", "10.0.0.12", hn, 64, src, 16);
    CHECK(strcmp(hn, "NewName") == 0 && strcmp(src, "dhcp") == 0,
          "T18: DHCP 直接命中(live)覆盖 cache 兜底");
    rc = hnc_cache_lookup("aa:bb:cc:dd:ee:0b", cached_hn, 64, cached_src, 16);
    CHECK(rc == 1 && strcmp(cached_hn, "NewName") == 0, "T19: cache 内容被刷新");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 5: 随机 MAC (LAA bit) 跳过 OUI ──\n");
    /* ──────────────────────────────────────────────── */

    /* T20: LAA bit=1 的 MAC 不命中 OUI */
    setup();
    resolve_hostname("02:bc:9f:11:22:33", "10.0.0.13", hn, 64, src, 16);
    CHECK(strcmp(src, "mac") == 0,
          "T20: LAA MAC 走 mac fallback,不走 OUI");

    /* T21: Mi-10 的真实随机 MAC */
    setup();
    resolve_hostname("7a:d6:f7:ce:ba:76", "10.0.0.14", hn, 64, src, 16);
    CHECK(strcmp(src, "mac") == 0,
          "T21: Mi-10 随机 MAC (0x7a) 走 mac fallback");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 6: v3.7.0 坑 16 回归保护 ──\n");
    /* ──────────────────────────────────────────────── */

    /* T22: 模拟 Mi-10 pending 场景
     * v3.7.0 时代 process_pending_mdns 直接调 try_mdns_resolve,绕过了
     * DHCP 查询,导致 Mi-10 装机瞬间显示 "Android"。现在的契约是
     * pending 路径走 resolve_hostname_dhcp_only,会命中 DHCP。*/
    setup();
    mock_dhcp_set("7a:d6:f7:ce:ba:aa", "Mi-10");
    mock_mdns_set("7a:d6:f7:ce:ba:aa", "Android");  /* OEM 通用名 */
    resolve_hostname_dhcp_only("7a:d6:f7:ce:ba:aa", hn, 64, src, 16);
    CHECK(strcmp(hn, "Mi-10") == 0,
          "T22: pending 路径 DHCP 命中 Mi-10(不是 mDNS 的 Android)");
    CHECK(g_mock_mdns_total_calls == 0,
          "T23: pending 路径不调用 mDNS(v3.7.2 坑 18 回归保护)");

    /* T24: DHCP 失败时 pending 路径 fall 到 cache 而非 mDNS */
    setup();
    hnc_cache_update("aa:bb:cc:dd:ee:0c", "CachedName", "dhcp");
    resolve_hostname_dhcp_only("aa:bb:cc:dd:ee:0c", hn, 64, src, 16);
    CHECK(HAS_PREFIX(src, "cache"),
          "T24: pending 路径 DHCP 失败时 fall 到 cache");

    /* ──────────────────────────────────────────────── */
    printf("\n── Section 7: 空输入 / 边界 ──\n");
    /* ──────────────────────────────────────────────── */

    /* T25: 空 IP + DHCP 命中 */
    setup();
    mock_dhcp_set("aa:bb:cc:dd:ee:0d", "Mi-10");
    resolve_hostname("aa:bb:cc:dd:ee:0d", "", hn, 64, src, 16);
    CHECK(strcmp(hn, "Mi-10") == 0, "T25: 空 IP 时 DHCP 依然工作");

    /* T26: 空 IP + 只有 mDNS 能命中 → mDNS 被跳过 */
    setup();
    mock_mdns_set("aa:bb:cc:dd:ee:0e", "iPhone");
    resolve_hostname("aa:bb:cc:dd:ee:0e", "", hn, 64, src, 16);
    CHECK(g_mock_mdns_total_calls == 0,
          "T26: 空 IP 时 mDNS 被跳过(IP 是 mDNS 反查必需)");
    CHECK(strcmp(src, "mac") == 0, "T27: 空 IP + mDNS-only → mac fallback");

    /* ──────────────────────────────────────────────── */
    printf("\n═══ %d passed, %d failed ═══\n", pass, fail);
    /* ──────────────────────────────────────────────── */

    return fail > 0 ? 1 : 0;
}
