/* hostname_cache.c — HNC DHCP/mDNS hostname 持久化 cache 实现
 *
 * 见 hostname_cache.h 的设计说明。
 *
 * 实现细节:
 *   - 线性数组存储(1024 条上限,无哈希表,省代码)
 *   - load/save 使用简单 JSON 格式,跟 devices.json 同样风格
 *   - save 走原子 tmp+rename,避免半写文件
 *   - lookup/update 是 O(N) 线性扫描,N=1024 在 Cortex-A 上 ~3μs,可接受
 */

#include "hostname_cache.h"
#include "hnc_helpers.h"  /* hnc_json_escape */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

/* ══════════════════════════════════════════════════════════
 * 全局状态(单线程模型,无锁)
 * ══════════════════════════════════════════════════════════ */
static hnc_cache_entry_t g_cache[HNC_CACHE_MAX_ENTRIES];
static int g_cache_dirty = 0;
static char g_cache_path[256] = "";

/* ══════════════════════════════════════════════════════════
 * 内部辅助: MAC 大小写不敏感比较
 * ══════════════════════════════════════════════════════════ */
static int mac_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    for (int i = 0; i < 17; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        if (ca == '\0') return 1;
    }
    /* 检查第 18 个字符都是 '\0' */
    return a[17] == '\0' && b[17] == '\0';
}

/* ══════════════════════════════════════════════════════════
 * init
 * ══════════════════════════════════════════════════════════ */
void hnc_cache_init(const char *cache_path) {
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_dirty = 0;
    if (cache_path && *cache_path) {
        strncpy(g_cache_path, cache_path, sizeof(g_cache_path) - 1);
        g_cache_path[sizeof(g_cache_path) - 1] = '\0';
    } else {
        g_cache_path[0] = '\0';
    }
}

/* ══════════════════════════════════════════════════════════
 * reset (测试用)
 * ══════════════════════════════════════════════════════════ */
void hnc_cache_reset(void) {
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_dirty = 0;
}

/* ══════════════════════════════════════════════════════════
 * count
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_count(void) {
    int n = 0;
    for (int i = 0; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].active) n++;
    }
    return n;
}

/* ══════════════════════════════════════════════════════════
 * is_dirty
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_is_dirty(void) {
    return g_cache_dirty;
}

/* ══════════════════════════════════════════════════════════
 * lookup
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_lookup(const char *mac,
                     char *out_hn, size_t hn_len,
                     char *out_src, size_t src_len) {
    if (!mac || !out_hn || hn_len == 0 || !out_src || src_len == 0) return 0;

    for (int i = 0; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (!g_cache[i].active) continue;
        if (mac_eq(g_cache[i].mac, mac)) {
            strncpy(out_hn, g_cache[i].hostname, hn_len - 1);
            out_hn[hn_len - 1] = '\0';
            strncpy(out_src, g_cache[i].src, src_len - 1);
            out_src[src_len - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * update
 *
 * 先查是否存在,存在则覆盖。
 * 不存在则找第一个空槽插入。
 * 都满就淘汰最旧条目(LRU by updated_at)。
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_update(const char *mac, const char *hostname, const char *src) {
    if (!mac || !hostname || !src) return 0;
    if (!*mac || !*hostname || !*src) return 0;

    time_t now = time(NULL);

    /* 第 1 遍:查是否已存在 */
    for (int i = 0; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (!g_cache[i].active) continue;
        if (mac_eq(g_cache[i].mac, mac)) {
            /* 存在,看内容有没有变 */
            int changed = 0;
            if (strncmp(g_cache[i].hostname, hostname, sizeof(g_cache[i].hostname)) != 0) changed = 1;
            if (strncmp(g_cache[i].src, src, sizeof(g_cache[i].src)) != 0) changed = 1;

            if (changed) {
                strncpy(g_cache[i].hostname, hostname, sizeof(g_cache[i].hostname) - 1);
                g_cache[i].hostname[sizeof(g_cache[i].hostname) - 1] = '\0';
                strncpy(g_cache[i].src, src, sizeof(g_cache[i].src) - 1);
                g_cache[i].src[sizeof(g_cache[i].src) - 1] = '\0';
                g_cache[i].updated_at = now;
                g_cache_dirty = 1;
                return 1;
            }
            /* 内容没变也刷新 updated_at,以便 LRU 保护热条目 */
            g_cache[i].updated_at = now;
            return 0;  /* 无 substantive change,不需要 save */
        }
    }

    /* 第 2 遍:找第一个空槽 */
    for (int i = 0; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (!g_cache[i].active) {
            g_cache[i].active = 1;
            strncpy(g_cache[i].mac, mac, sizeof(g_cache[i].mac) - 1);
            g_cache[i].mac[sizeof(g_cache[i].mac) - 1] = '\0';
            strncpy(g_cache[i].hostname, hostname, sizeof(g_cache[i].hostname) - 1);
            g_cache[i].hostname[sizeof(g_cache[i].hostname) - 1] = '\0';
            strncpy(g_cache[i].src, src, sizeof(g_cache[i].src) - 1);
            g_cache[i].src[sizeof(g_cache[i].src) - 1] = '\0';
            g_cache[i].updated_at = now;
            g_cache_dirty = 1;
            return 1;
        }
    }

    /* 第 3 遍:cache 满,淘汰最旧条目 */
    int oldest_idx = 0;
    time_t oldest_ts = g_cache[0].updated_at;
    for (int i = 1; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].updated_at < oldest_ts) {
            oldest_ts = g_cache[i].updated_at;
            oldest_idx = i;
        }
    }
    strncpy(g_cache[oldest_idx].mac, mac, sizeof(g_cache[oldest_idx].mac) - 1);
    g_cache[oldest_idx].mac[sizeof(g_cache[oldest_idx].mac) - 1] = '\0';
    strncpy(g_cache[oldest_idx].hostname, hostname, sizeof(g_cache[oldest_idx].hostname) - 1);
    g_cache[oldest_idx].hostname[sizeof(g_cache[oldest_idx].hostname) - 1] = '\0';
    strncpy(g_cache[oldest_idx].src, src, sizeof(g_cache[oldest_idx].src) - 1);
    g_cache[oldest_idx].src[sizeof(g_cache[oldest_idx].src) - 1] = '\0';
    g_cache[oldest_idx].updated_at = now;
    g_cache_dirty = 1;
    return 1;
}

/* ══════════════════════════════════════════════════════════
 * load
 *
 * JSON 格式:
 * {
 *   "7a:d6:f7:ce:ba:76": {"h":"Mi-10","s":"dhcp","t":1776102264},
 *   "1c:ba:8c:11:22:33": {"h":"Pixel 7","s":"dhcp","t":1776100000}
 * }
 *
 * 解析策略: 一次 fread 整个文件,然后 substring 匹配每个 key/value。
 * 文件最多 ~100 KB(1024 条 × 100B),8KB buffer 不够,用 128KB 大 buffer。
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_load(void) {
    if (g_cache_path[0] == '\0') return 0;

    FILE *f = fopen(g_cache_path, "r");
    if (!f) return 0;  /* 文件不存在,正常(首次启动) */

    /* 读整个文件 */
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 256 * 1024) {
        /* 空文件或过大(可能损坏) */
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }

    char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return 0; }
    size_t n = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    if (n == 0) { free(buf); return 0; }
    buf[n] = '\0';

    /* 简单 JSON 解析: 找每一条 "<17 char mac>":{"h":"...","s":"...","t":<num>}
     * 不做完整 JSON parsing,因为我们知道 save 的格式稳定。
     * 匹配模式: "<mac>":{"h":"<hostname>","s":"<src>","t":<number>}
     */
    int loaded = 0;
    char *p = buf;
    while ((p = strstr(p, "\":{\"h\":\"")) != NULL) {
        /* p 指向 "":{"h":"... 的冒号前的 "。
         * 向前找到 key 的开始 " */
        char *key_end = p;
        /* key 是 17 字符 MAC,前面应该是 " */
        if (key_end - buf < 18) { p++; continue; }
        char *key_start = key_end - 17;
        if (*(key_start - 1) != '"') { p++; continue; }

        /* 提取 MAC */
        char mac[18];
        memcpy(mac, key_start, 17);
        mac[17] = '\0';

        /* hostname 起点 */
        char *hn_start = p + strlen("\":{\"h\":\"");
        /* hostname 结尾: 找下一个未转义的 " */
        char hn[64];
        size_t j = 0;
        char *q = hn_start;
        while (*q && *q != '"' && j < sizeof(hn) - 1) {
            if (*q == '\\' && *(q+1)) {
                /* 反转义
                 * rc3.1.15 修 P3 (review §2b): 加 \uXXXX 解析跟 hnc_json_escape
                 * 写出格式对称. 之前只处理 \n \r \t, 其他 \\X 直接输出 X — 写出
                 * control char 的 \u00xx 在 reload 时变成 6 字符字面量 "u0000"
                 * 而不是真正的 control char. 现在补全, 不引入 cJSON 依赖. */
                char c = *(q+1);
                if      (c == 'n') { hn[j++] = '\n'; q += 2; }
                else if (c == 'r') { hn[j++] = '\r'; q += 2; }
                else if (c == 't') { hn[j++] = '\t'; q += 2; }
                else if (c == '"') { hn[j++] = '"';  q += 2; }
                else if (c == '\\') { hn[j++] = '\\'; q += 2; }
                else if (c == '/') { hn[j++] = '/';  q += 2; }
                else if (c == 'b') { hn[j++] = '\b'; q += 2; }
                else if (c == 'f') { hn[j++] = '\f'; q += 2; }
                else if (c == 'u' && q[2] && q[3] && q[4] && q[5]) {
                    /* \uXXXX 4 位 hex.
                     * hnc_json_escape 只对 < 0x20 control char 写 \u00xx,
                     * 所以这里只处理 BMP 0x0000-0x00FF 段, 写成单字节.
                     * 0x0080-0x00FF 段是 Latin-1 补充, 严格 UTF-8 应为 2 字节
                     * 0xC2 0xXX, 但 hostname 这种短字符串场景,我们写出和读入
                     * 是同一程序 → 对称即可, 不必跟 RFC 8259 完全一致. */
                    char hex[5] = {q[2], q[3], q[4], q[5], 0};
                    char *endp = NULL;
                    unsigned long cp = strtoul(hex, &endp, 16);
                    if (endp == hex + 4) {
                        if (cp < 0x80) {
                            hn[j++] = (char)cp;
                        } else if (cp < 0x800 && j + 1 < sizeof(hn) - 1) {
                            /* 2-byte UTF-8 */
                            hn[j++] = (char)(0xC0 | (cp >> 6));
                            hn[j++] = (char)(0x80 | (cp & 0x3F));
                        } else if (j + 2 < sizeof(hn) - 1) {
                            /* 3-byte UTF-8 (BMP) */
                            hn[j++] = (char)(0xE0 | (cp >> 12));
                            hn[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                            hn[j++] = (char)(0x80 | (cp & 0x3F));
                        }
                        q += 6;
                    } else {
                        /* hex 解析失败, 当字面量保留 */
                        hn[j++] = c;
                        q += 2;
                    }
                }
                else               { hn[j++] = c; q += 2; }
            } else {
                hn[j++] = *q++;
            }
        }
        hn[j] = '\0';
        if (*q != '"') { p++; continue; }

        /* src 起点: 跳过 ","s":" */
        char *src_marker = strstr(q, ",\"s\":\"");
        if (!src_marker) { p++; continue; }
        char *src_start = src_marker + strlen(",\"s\":\"");
        char src[12];
        size_t k = 0;
        char *r = src_start;
        while (*r && *r != '"' && k < sizeof(src) - 1) {
            src[k++] = *r++;
        }
        src[k] = '\0';
        if (*r != '"') { p++; continue; }

        /* 插入(不经 update,因为不想打 dirty 标志) */
        if (loaded < HNC_CACHE_MAX_ENTRIES && j > 0 && k > 0) {
            g_cache[loaded].active = 1;
            strncpy(g_cache[loaded].mac, mac, sizeof(g_cache[loaded].mac) - 1);
            g_cache[loaded].mac[sizeof(g_cache[loaded].mac) - 1] = '\0';
            strncpy(g_cache[loaded].hostname, hn, sizeof(g_cache[loaded].hostname) - 1);
            g_cache[loaded].hostname[sizeof(g_cache[loaded].hostname) - 1] = '\0';
            strncpy(g_cache[loaded].src, src, sizeof(g_cache[loaded].src) - 1);
            g_cache[loaded].src[sizeof(g_cache[loaded].src) - 1] = '\0';
            /* updated_at 可选解析,失败就用 0 */
            char *ts_marker = strstr(r, ",\"t\":");
            if (ts_marker) {
                long ts = strtol(ts_marker + strlen(",\"t\":"), NULL, 10);
                g_cache[loaded].updated_at = (time_t)ts;
            } else {
                g_cache[loaded].updated_at = 0;
            }
            loaded++;
        }
        p = r + 1;
    }

    free(buf);
    g_cache_dirty = 0;  /* 刚 load 完,没有未保存改动 */
    return loaded;
}

/* ══════════════════════════════════════════════════════════
 * save
 *
 * 原子写: 先写 tmp.<pid>,再 rename。
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_save(void) {
    if (g_cache_path[0] == '\0') return -1;

    char tmp_path[280];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", g_cache_path, (int)getpid());

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    fputc('{', f);
    int first = 1;
    for (int i = 0; i < HNC_CACHE_MAX_ENTRIES; i++) {
        if (!g_cache[i].active) continue;
        if (!first) fputc(',', f);
        first = 0;

        /* escape hostname for JSON */
        char esc_hn[128];
        hnc_json_escape(g_cache[i].hostname, esc_hn, sizeof(esc_hn));

        fprintf(f, "\"%s\":{\"h\":\"%s\",\"s\":\"%s\",\"t\":%ld}",
                g_cache[i].mac, esc_hn, g_cache[i].src,
                (long)g_cache[i].updated_at);
    }
    fputc('}', f);
    fputc('\n', f);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp_path);
        return -1;
    }
    fclose(f);

    if (rename(tmp_path, g_cache_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    g_cache_dirty = 0;
    return 0;
}
