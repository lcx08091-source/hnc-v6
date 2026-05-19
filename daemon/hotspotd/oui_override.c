/* oui_override.c — HNC v3.8.3 D3 实现
 *
 * 用户 OUI 覆盖文件加载和查询。
 * 见 oui_override.h 的设计说明。
 *
 * 实现细节:
 *   - 线性数组存储(256 条上限,bsearch 不必要,线性扫描 256 条 ~1μs)
 *   - JSON 解析:简单 substring 匹配,不做完整 JSON parsing
 *   - 加载失败不 crash,返回 0
 *   - load 时把 mac 前缀标准化为小写无冒号 6-hex 字符串
 */

#include "oui_override.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    int  active;
    char prefix[7];                         /* 6 hex lowercase + \0 */
    char label[HNC_OVERRIDE_LABEL_LEN];     /* UTF-8 */
} hnc_override_entry_t;

static hnc_override_entry_t g_overrides[HNC_OVERRIDE_MAX_ENTRIES];
static int g_override_count = 0;
static char g_override_path[256] = "";

/* ══════════════════════════════════════════════════════════
 * 辅助: 把 MAC 前缀标准化
 *
 * 输入可能是:
 *   "28:6c:07"     → "286c07"
 *   "286c07"       → "286c07"
 *   "28-6C-07"     → "286c07"
 *   "28:6C:07:..." → "286c07" (只取前 6 hex)
 *
 * 返回: 0 = 成功, -1 = 输入格式非法
 * ══════════════════════════════════════════════════════════ */
static int normalize_prefix(const char *in, char *out) {
    int count = 0;
    for (size_t i = 0; in[i] && count < 6; i++) {
        char c = in[i];
        if (c == ':' || c == '-' || c == ' ') continue;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            out[count++] = (char)tolower((unsigned char)c);
        } else {
            return -1;  /* 非法字符 */
        }
    }
    out[count] = '\0';
    return (count == 6) ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════
 * init / reset / count
 * ══════════════════════════════════════════════════════════ */
void hnc_override_init(const char *path) {
    memset(g_overrides, 0, sizeof(g_overrides));
    g_override_count = 0;
    if (path && *path) {
        strncpy(g_override_path, path, sizeof(g_override_path) - 1);
        g_override_path[sizeof(g_override_path) - 1] = '\0';
    } else {
        g_override_path[0] = '\0';
    }
}

void hnc_override_reset(void) {
    memset(g_overrides, 0, sizeof(g_overrides));
    g_override_count = 0;
}

int hnc_override_count(void) {
    return g_override_count;
}

/* ══════════════════════════════════════════════════════════
 * lookup
 * ══════════════════════════════════════════════════════════ */
int hnc_override_lookup(const char *mac, char *out, size_t outlen) {
    if (!mac || !out || outlen == 0) return 0;
    if (g_override_count == 0) return 0;

    char key[7];
    if (normalize_prefix(mac, key) != 0) return 0;

    for (int i = 0; i < g_override_count; i++) {
        if (!g_overrides[i].active) continue;
        if (memcmp(g_overrides[i].prefix, key, 6) == 0) {
            strncpy(out, g_overrides[i].label, outlen - 1);
            out[outlen - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * load
 *
 * 解析策略: 找每一条 "KEY":"VALUE" 模式。
 * KEY 必须能 normalize 成 6 hex,否则跳过这条。
 * VALUE 是 JSON 字符串(支持 \" \\ \n \r \t 转义)。
 * ══════════════════════════════════════════════════════════ */

/* 从 [*p, end) 寻找下一个 '"',跳过转义的 \"。
 * 返回指向 '"' 的指针,未找到返回 NULL。*/
static const char *find_unescaped_quote(const char *p, const char *end) {
    while (p < end) {
        if (*p == '\\') {
            p += 2;  /* 跳过转义序列 */
            continue;
        }
        if (*p == '"') return p;
        p++;
    }
    return NULL;
}

/* 把 JSON escape 序列解码到 out,返回写入字节数(不含 NUL) */
static size_t decode_json_string(const char *src, size_t src_len,
                                  char *out, size_t out_size) {
    if (out_size == 0) return 0;
    size_t j = 0;
    for (size_t i = 0; i < src_len && j + 1 < out_size; i++) {
        if (src[i] == '\\' && i + 1 < src_len) {
            char c = src[i + 1];
            if      (c == 'n')  out[j++] = '\n';
            else if (c == 'r')  out[j++] = '\r';
            else if (c == 't')  out[j++] = '\t';
            else if (c == '"')  out[j++] = '"';
            else if (c == '\\') out[j++] = '\\';
            else if (c == '/')  out[j++] = '/';
            else                out[j++] = c;
            i++;
        } else {
            out[j++] = src[i];
        }
    }
    out[j] = '\0';
    return j;
}

int hnc_override_load(void) {
    if (g_override_path[0] == '\0') return 0;

    FILE *f = fopen(g_override_path, "r");
    if (!f) return 0;  /* 不存在,正常 */

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 16 * 1024) {
        /* 过大或空 */
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

    const char *end = buf + n;
    const char *p = buf;
    int loaded = 0;

    while (p < end && loaded < HNC_OVERRIDE_MAX_ENTRIES) {
        /* 找 key 起始 " */
        while (p < end && *p != '"') p++;
        if (p >= end) break;
        p++;  /* 跳过 " */

        /* key 内容到下一个未转义 " */
        const char *key_start = p;
        const char *key_end = find_unescaped_quote(p, end);
        if (!key_end) break;

        char key_raw[64];
        size_t key_len = (size_t)(key_end - key_start);
        if (key_len >= sizeof(key_raw)) {
            /* key 太长,跳过这条(同时要跳过对应的 value) */
            p = key_end + 1;
            goto skip_value;
        }
        memcpy(key_raw, key_start, key_len);
        key_raw[key_len] = '\0';

        p = key_end + 1;

        /* 找 : */
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (p >= end || *p != ':') continue;
        p++;

        /* 找 value 起始 " */
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (p >= end || *p != '"') continue;
        p++;

        /* value 内容 */
        const char *val_start = p;
        const char *val_end = find_unescaped_quote(p, end);
        if (!val_end) break;

        /* 现在 normalize key,如果非法就跳过这条(不占槽) */
        char normalized[7];
        if (normalize_prefix(key_raw, normalized) != 0) {
            p = val_end + 1;
            continue;
        }

        /* 检查是否已存在(重复 key 只保留最后一个) */
        int existing_idx = -1;
        for (int i = 0; i < loaded; i++) {
            if (memcmp(g_overrides[i].prefix, normalized, 6) == 0) {
                existing_idx = i;
                break;
            }
        }

        int slot;
        if (existing_idx >= 0) {
            slot = existing_idx;
        } else {
            slot = loaded;
        }

        g_overrides[slot].active = 1;
        memcpy(g_overrides[slot].prefix, normalized, 7);

        /* 解码 value 到 label */
        size_t val_len = (size_t)(val_end - val_start);
        decode_json_string(val_start, val_len,
                           g_overrides[slot].label,
                           sizeof(g_overrides[slot].label));

        if (existing_idx < 0) loaded++;

        p = val_end + 1;
        continue;

    skip_value:
        /* 跳过 value 部分,避免其 " 被误认为下一条的 key */
        while (p < end && *p != ':') p++;
        if (p < end) p++;
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (p < end && *p == '"') {
            p++;
            const char *vq = find_unescaped_quote(p, end);
            if (vq) p = vq + 1;
        }
    }

    free(buf);
    g_override_count = loaded;
    return loaded;
}
