/* hnc_helpers.c — HNC shared C helpers 实现
 *
 * v3.6 Commit 2:从 hotspotd.c 提取的纯 helper 函数。
 * 见 hnc_helpers.h 的设计说明。
 */

#include "hnc_helpers.h"
#include "oui_override.h"  /* v3.8.3 D3: 用户 OUI 覆盖 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ══════════════════════════════════════════════════════════
 * should_re_resolve
 * ══════════════════════════════════════════════════════════ */
int hnc_should_re_resolve(const char *hostname_src, time_t last_resolve, time_t now) {
    if (strcmp(hostname_src, "mac") == 0) return 1;
    if ((now - last_resolve) >= 60) return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * json_escape — 含 UTF-8 边界回退 (v3.5.2 P2-F)
 * ══════════════════════════════════════════════════════════ */
void hnc_json_escape(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) return;
    size_t j = 0;
    int truncated = 0;
    /* 循环条件 j + 1 < dst_size: 留 1 字节给末尾 NUL。
     * 每个 escape 分支自己再检查需要的额外字节,不够就 break。 */
    for (size_t i = 0; src[i] && j + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= dst_size) { truncated = 1; break; }
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 0x20) {
            if (j + 6 >= dst_size) { truncated = 1; break; }
            j += snprintf(dst + j, dst_size - j, "\\u%04x", c);
        } else {
            /* 普通 ASCII 或 UTF-8 字节 */
            dst[j++] = (char)c;
        }
    }

    /* UTF-8 边界回退:如果因 buffer 不够退出,确保不留残缺多字节序列 */
    if (truncated || (src[0] && j + 1 >= dst_size)) {
        /* 从末尾往前找 last non-continuation byte */
        size_t k = j;
        while (k > 0 && ((unsigned char)dst[k-1] & 0xC0) == 0x80) {
            k--;
        }
        /* dst[k-1] 是 ASCII 或 lead byte */
        if (k > 0) {
            unsigned char lead = (unsigned char)dst[k-1];
            size_t needed = 0;
            if ((lead & 0x80) == 0) {
                needed = 0;                /* ASCII,完整 */
            } else if ((lead & 0xE0) == 0xC0) {
                needed = 1;                /* 2-byte lead */
            } else if ((lead & 0xF0) == 0xE0) {
                needed = 2;                /* 3-byte lead (中文) */
            } else if ((lead & 0xF8) == 0xF0) {
                needed = 3;                /* 4-byte lead (emoji) */
            }
            size_t have = j - k;
            if (have < needed) {
                /* 不完整,删掉整个残缺字符 */
                j = k - 1;
            }
        }
    }

    dst[j] = '\0';
}

/* ══════════════════════════════════════════════════════════
 * mac_fallback — 跟 shell 路径对齐 (v3.5.0 P1-8)
 *
 * "aa:bb:cc:dd:ee:ff" → 去冒号 → "aabbccddeeff" → 后 8 字符 → "ccddeeff"
 * ══════════════════════════════════════════════════════════ */
void hnc_mac_fallback(const char *mac, char *out, size_t outlen) {
    if (outlen == 0) return;
    char no_colon[13];  /* 12 hex chars + \0 */
    size_t ci = 0;
    for (size_t i = 0; mac[i] && ci < sizeof(no_colon) - 1; i++) {
        if (mac[i] != ':') no_colon[ci++] = mac[i];
    }
    no_colon[ci] = '\0';
    /* 取后 8 字符 */
    const char *suffix = (ci >= 8) ? (no_colon + ci - 8) : no_colon;
    snprintf(out, outlen, "%s", suffix);
}

/* ══════════════════════════════════════════════════════════
 * lookup_manual_name — 从 device_names.json 查手动命名
 *
 * 参数化:不再依赖 DEVICE_NAMES_JSON macro,路径由调用方传入。
 * 这让测试可以用临时文件路径跑,不需要污染真实 /data/local/hnc/。
 * ══════════════════════════════════════════════════════════ */
int hnc_lookup_manual_name(const char *mac, const char *names_path,
                           char *out, size_t outlen) {
    if (!names_path || !*names_path) return 0;
    FILE *f = fopen(names_path, "r");
    if (!f) return 0;

    /* v3.5.0 P1-7: device_names.json 通常整个文件 < 4KB,
     * 用大 buffer 一次读完,避免 fgets 截断风险 */
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';

    /* 查找 "mac":"name" 子串(case-insensitive mac) */
    char pattern[32];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", mac);

    /* rc3.1.34 修 #65: 子串搜索必须锚边界. 之前任意 buf 位置只要后续字符匹配
     * pattern 就成功. 实际场景 mac 永远 17 字符 + name_set 在写入前 escape, 当前
     * 攻击不通. 但脆: 如果未来 mac 字段变长 / device_names.json 出现大写 mac
     * 同时小写 mac 的混合, 子串 prefix 重叠会导致误匹. 加锚: pattern 前一字节
     * 必须是 `{` 或 `,` (json 对象分隔符) 或 string 起始. 最简单做法: 先扫一遍
     * 把无关 escape 处理掉, 但开销大. 这里用最小修法: 只接受 pattern 跟在
     * `{` `,` 或行首 ` \t\n\r` 之后的位置, 同时上一个非空白字符必须是 `{` 或 `,`. */
    char *p = buf;
    while (*p) {
        /* strcasestr 不是 POSIX,手工实现 */
        char *m = pattern, *q = p;
        while (*m && *q && tolower((unsigned char)*q) == tolower((unsigned char)*m)) {
            q++; m++;
        }
        if (*m == '\0') {
            /* 候选匹配, 检查锚边界: 往左扫到第一个非空白字符,
             * 必须是 `{` 或 `,` (即 mac 是合法的 JSON object key, 不是嵌在 value 里) */
            char *anchor = p - 1;
            while (anchor >= buf && (*anchor == ' ' || *anchor == '\t' ||
                                      *anchor == '\n' || *anchor == '\r')) {
                anchor--;
            }
            int anchored = (anchor < buf) ||  /* buf 起始, p 是文件开头 */
                           (*anchor == '{') || (*anchor == ',');
            if (!anchored) {
                /* 误匹: 在 value 内或其他位置. 跳过这个 `"`, 继续往后找 */
                p++;
                continue;
            }
            /* 真匹配, q 指向 name 起始 */
            size_t i = 0;
            while (*q && *q != '"' && i < outlen - 1) {
                /* 处理 JSON escape: \" \\ */
                if (*q == '\\' && (q[1] == '"' || q[1] == '\\')) {
                    out[i++] = q[1];
                    q += 2;
                } else {
                    out[i++] = *q++;
                }
            }
            out[i] = '\0';
            return (i > 0) ? 1 : 0;
        }
        p++;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * resolve_hostname_fast — 快速解析,不含 mdns
 *
 * v3.6:scan_arp / nl_process 调用这个版本,保证不阻塞主循环。
 * mdns 解析延后到主循环的 process_pending_mdns() 异步处理(Commit 3)。
 *
 * 优先级:manual > mac 兜底
 * ══════════════════════════════════════════════════════════ */
void hnc_resolve_hostname_fast(const char *mac, const char *ip,
                               const char *names_path,
                               char *out_hn, size_t hn_len,
                               char *out_src, size_t src_len) {
    (void)ip;  /* fast 模式不需要 ip(只 manual + mac 兜底) */

    /* 1) 手动命名 */
    if (hnc_lookup_manual_name(mac, names_path, out_hn, hn_len)) {
        snprintf(out_src, src_len, "manual");
        return;
    }

    /* 2) MAC 兜底 */
    hnc_mac_fallback(mac, out_hn, hn_len);
    snprintf(out_src, src_len, "mac");
}

/* ══════════════════════════════════════════════════════════
 * pending_ready — 判断 pending 设备是否应该被异步 mDNS 解析
 *
 * 见 hnc_helpers.h 详细说明。纯函数,好测。
 * ══════════════════════════════════════════════════════════ */
int hnc_pending_ready(const char *hostname_src, time_t pending_since, time_t now) {
    if (!hostname_src) return 0;
    if (strcmp(hostname_src, "pending") != 0) return 0;
    if (now - pending_since < HNC_PENDING_BREATHING_ROOM_SEC) return 0;
    return 1;
}

/* ══════════════════════════════════════════════════════════
 * v3.8.0: OUI 厂商查表
 *
 * 表内容:444 条 top 厂商 OUI (Apple / Xiaomi / Huawei / OPPO / vivo /
 * Samsung / Dell / HP / Lenovo / Microsoft / Google / Intel / Sony /
 * Nintendo / Amazon / Raspberry-Pi / Espressif / Philips / TP-Link)
 *
 * 覆盖目标:中国大陆 90%+ 的常见终端设备前缀
 *
 * 数据来源:Wireshark manuf 文件 + IEEE OUI registry 手工筛选
 *          排序后 bsearch 查找,O(log N) ~9 次比较
 * ══════════════════════════════════════════════════════════ */

#include <stdlib.h>  /* bsearch */

typedef struct {
    unsigned int prefix;  /* 24-bit OUI: 0xAABBCC */
    const char  *vendor;
} hnc_oui_entry_t;

/* 按 prefix 升序排列(编译时排序,便于 bsearch) */
static const hnc_oui_entry_t HNC_OUI_TABLE[] = {
    { 0x000048, "Epson" },
    { 0x0000AA, "Canon" },
    { 0x00026F, "Epson" },
    { 0x000272, "HP" },
    { 0x000393, "Apple" },
    { 0x0005CD, "Denon" },
    { 0x00065B, "Dell" },
    { 0x000678, "Denon" },
    { 0x0006F5, "Denon" },
    { 0x000824, "Toshiba" },
    { 0x000874, "Dell" },
    { 0x000883, "HP" },
    { 0x000BDB, "Dell" },
    { 0x000C29, "Dell" },
    { 0x000D6F, "IKEA" },
    { 0x000E58, "Sonos" },
    { 0x000F1F, "Dell" },
    { 0x000F5D, "Sony" },
    { 0x001018, "TP-Link" },
    { 0x001143, "Dell" },
    { 0x001240, "Hikvision" },
    { 0x00125A, "Microsoft" },
    { 0x001315, "PlayStation" },
    { 0x001319, "Intel" },
    { 0x001343, "Denon" },
    { 0x001346, "D-Link" },
    { 0x0013A9, "Sony" },
    { 0x0013E8, "Intel" },
    { 0x00146C, "Apple" },
    { 0x0014C2, "HP" },
    { 0x0015B9, "Samsung" },
    { 0x0015E9, "D-Link" },
    { 0x0016CB, "Apple" },
    { 0x001788, "Philips-Hue" },
    { 0x00178B, "Philips" },
    { 0x0017A4, "HP" },
    { 0x0017C9, "Samsung" },
    { 0x0017EA, "Philips" },
    { 0x0017EF, "Philips" },
    { 0x0017FA, "Microsoft" },
    { 0x001821, "Dahua" },
    { 0x00188B, "Dell" },
    { 0x0019FD, "Nintendo" },
    { 0x001A11, "Google" },
    { 0x001A80, "Sony" },
    { 0x001B11, "D-Link" },
    { 0x001B2F, "Netgear" },
    { 0x001B58, "Panasonic" },
    { 0x001BA9, "Brother" },
    { 0x001BCF, "Intel" },
    { 0x001BFC, "ASUS" },
    { 0x001CD2, "Panasonic" },
    { 0x001D25, "Samsung" },
    { 0x001DBA, "Sony" },
    { 0x001E4F, "Dell" },
    { 0x001E75, "LG" },
    { 0x001E7D, "Vizio" },
    { 0x001E8C, "ASUS" },
    { 0x001E8F, "Canon" },
    { 0x001FA7, "PlayStation" },
    { 0x001FE3, "LG" },
    { 0x0020D8, "Denon" },
    { 0x002127, "TP-Link" },
    { 0x002129, "Linksys" },
    { 0x00212F, "Intel" },
    { 0x00215C, "Apple" },
    { 0x0021CC, "Lenovo" },
    { 0x0021D1, "Samsung" },
    { 0x002215, "ASUS" },
    { 0x002248, "Microsoft" },
    { 0x002255, "Canon" },
    { 0x00225F, "Microsoft" },
    { 0x00228E, "D-Link" },
    { 0x0022C9, "Microsoft" },
    { 0x0022D7, "Nintendo" },
    { 0x0022F9, "Google" },
    { 0x0022FA, "Lenovo" },
    { 0x0022FB, "Intel" },
    { 0x002339, "Samsung" },
    { 0x002369, "Panasonic" },
    { 0x002401, "D-Link" },
    { 0x002419, "Hikvision" },
    { 0x002454, "Samsung" },
    { 0x00247E, "Dell" },
    { 0x002481, "HP" },
    { 0x0024A3, "Canon" },
    { 0x0024BE, "Sony" },
    { 0x0024D7, "ASUS" },
    { 0x002500, "Apple" },
    { 0x002555, "Toshiba" },
    { 0x002564, "Lenovo" },
    { 0x002568, "Huawei" },
    { 0x002608, "Apple" },
    { 0x00265D, "Samsung" },
    { 0x002674, "Canon" },
    { 0x0026B0, "Apple" },
    { 0x0026BB, "Apple" },
    { 0x0026E2, "LG" },
    { 0x0026E8, "Samsung" },
    { 0x0026EF, "Toshiba" },
    { 0x0026F2, "Netgear" },
    { 0x0026F3, "D-Link" },
    { 0x002709, "Nintendo" },
    { 0x002721, "Intel" },
    { 0x002E76, "Microsoft" },
    { 0x003077, "Lenovo" },
    { 0x003EE1, "Harman" },
    { 0x004096, "Huawei" },
    { 0x00464B, "Huawei" },
    { 0x00480F, "Epson" },
    { 0x008000, "HP" },
    { 0x008092, "Brother" },
    { 0x008EF2, "Xiaomi" },
    { 0x00904C, "Harman" },
    { 0x009E25, "Amazon" },
    { 0x00A0DE, "Yamaha" },
    { 0x00A0EE, "Yamaha" },
    { 0x00C2C6, "Intel" },
    { 0x00D9D1, "PlayStation" },
    { 0x00E0FC, "Huawei" },
    { 0x026F70, "Epson" },
    { 0x0400A0, "Garmin" },
    { 0x0403D6, "Nintendo" },
    { 0x040CCE, "Apple" },
    { 0x0418D6, "Ubiquiti" },
    { 0x041CE1, "Vizio" },
    { 0x042665, "Apple" },
    { 0x0427E2, "Ubiquiti" },
    { 0x044EAF, "Tesla" },
    { 0x04795F, "Huawei" },
    { 0x047D7B, "Yamaha" },
    { 0x04924A, "ASUS" },
    { 0x049E70, "Hisense" },
    { 0x04A316, "Bose" },
    { 0x04A8B8, "Panasonic" },
    { 0x04BD70, "Huawei" },
    { 0x04CF8C, "Aqara" },
    { 0x04DB56, "Apple" },
    { 0x080027, "Apple" },
    { 0x080046, "Sony" },
    { 0x08053B, "Vizio" },
    { 0x0808C2, "LG" },
    { 0x0820EF, "Epson" },
    { 0x082994, "Bose" },
    { 0x082E5F, "Apple" },
    { 0x08606E, "ASUS" },
    { 0x087ED6, "Intel" },
    { 0x088620, "TCL" },
    { 0x08DF1F, "Harman" },
    { 0x08FD0E, "Sony" },
    { 0x0C1DAF, "Xiaomi" },
    { 0x0C37DC, "Huawei" },
    { 0x0C47C9, "Amazon" },
    { 0x0C54A5, "Hikvision" },
    { 0x0C715D, "Samsung" },
    { 0x0C77A6, "Apple" },
    { 0x0C8463, "Intel" },
    { 0x0C8BFD, "Lenovo" },
    { 0x0C96BF, "Huawei" },
    { 0x0C9D92, "ASUS" },
    { 0x0CB2B7, "Bose" },
    { 0x0CBC9F, "Apple" },
    { 0x0CE0DC, "Canon" },
    { 0x0CFCBF, "OPPO" },
    { 0x1023B9, "Samsung" },
    { 0x1027F5, "TP-Link" },
    { 0x102AB3, "Xiaomi" },
    { 0x1049BB, "Samsung" },
    { 0x1065A3, "Vizio" },
    { 0x10683F, "LG" },
    { 0x107B44, "ASUS" },
    { 0x10BF48, "OPPO" },
    { 0x10BFDC, "Hisense" },
    { 0x10C61F, "Huawei" },
    { 0x10C6FC, "OPPO" },
    { 0x10DA43, "Netgear" },
    { 0x10DDB1, "Apple" },
    { 0x141023, "Xiaomi" },
    { 0x14109F, "Apple" },
    { 0x1427EA, "TP-Link" },
    { 0x142D27, "Samsung" },
    { 0x145A05, "Apple" },
    { 0x146D62, "Toshiba" },
    { 0x147517, "Lenovo" },
    { 0x14914A, "Linksys" },
    { 0x149192, "Samsung" },
    { 0x1499E2, "Apple" },
    { 0x14BD61, "Apple" },
    { 0x14CC20, "TP-Link" },
    { 0x14D64D, "D-Link" },
    { 0x14DAE9, "ASUS" },
    { 0x14F42A, "OPPO" },
    { 0x170880, "Philips" },
    { 0x17880B, "Philips" },
    { 0x181EB0, "Samsung" },
    { 0x18549B, "TCL" },
    { 0x18595F, "Xiaomi" },
    { 0x1866DA, "Dell" },
    { 0x18749C, "Amazon" },
    { 0x1885C5, "OPPO" },
    { 0x18AF8F, "Apple" },
    { 0x18BC5A, "Tesla" },
    { 0x18E73D, "Nintendo" },
    { 0x1C1B0D, "Microsoft" },
    { 0x1C1B68, "Epson" },
    { 0x1C1D67, "Huawei" },
    { 0x1C232C, "Samsung" },
    { 0x1C35F1, "Hisense" },
    { 0x1C36BB, "Apple" },
    { 0x1C3BF3, "TP-Link" },
    { 0x1C4593, "Canon" },
    { 0x1C5A3E, "Xiaomi" },
    { 0x1C61B4, "TP-Link" },
    { 0x1C69A5, "Intel" },
    { 0x1C7EE5, "D-Link" },
    { 0x1C872C, "ASUS" },
    { 0x1C9E46, "Canon" },
    { 0x1CAF05, "Samsung" },
    { 0x1CAFF7, "D-Link" },
    { 0x1CB72C, "Lenovo" },
    { 0x1CBA8C, "Google" },
    { 0x1CBDB9, "D-Link" },
    { 0x2004B7, "Dell" },
    { 0x2009CE, "Bose" },
    { 0x200BC7, "Huawei" },
    { 0x201A06, "Intel" },
    { 0x201F3B, "LG" },
    { 0x203CAE, "Linksys" },
    { 0x203DBD, "Huawei" },
    { 0x204E6B, "Hisense" },
    { 0x204E7F, "Netgear" },
    { 0x2085FE, "Hikvision" },
    { 0x20A2E4, "Apple" },
    { 0x20C6EB, "Panasonic" },
    { 0x240AC4, "Espressif" },
    { 0x243739, "Google" },
    { 0x2462AB, "Espressif" },
    { 0x2469A5, "Huawei" },
    { 0x246F28, "Espressif" },
    { 0x2477E5, "Canon" },
    { 0x24A06E, "Fitbit" },
    { 0x24A160, "Espressif" },
    { 0x24A43C, "Ubiquiti" },
    { 0x24DA9B, "Fitbit" },
    { 0x24DBAC, "OPPO" },
    { 0x24E314, "Apple" },
    { 0x28107B, "D-Link" },
    { 0x28186E, "Microsoft" },
    { 0x281878, "Microsoft" },
    { 0x2827BF, "Samsung" },
    { 0x28312A, "Huawei" },
    { 0x283737, "Apple" },
    { 0x28395E, "Samsung" },
    { 0x283CE4, "Huawei" },
    { 0x284180, "Hikvision" },
    { 0x28570E, "Hikvision" },
    { 0x286C07, "Xiaomi" },
    { 0x288088, "Netgear" },
    { 0x2882A4, "Xiaomi" },
    { 0x288335, "Samsung" },
    { 0x2887BA, "TP-Link" },
    { 0x289AFA, "Samsung" },
    { 0x28A02B, "Apple" },
    { 0x28B448, "Huawei" },
    { 0x28E31F, "Xiaomi" },
    { 0x2C1F23, "Apple" },
    { 0x2C27D7, "Toshiba" },
    { 0x2C30B5, "Netgear" },
    { 0x2C54CF, "LG" },
    { 0x2C56DC, "ASUS" },
    { 0x2C58E8, "Huawei" },
    { 0x2C598A, "LG" },
    { 0x2C9D1E, "Huawei" },
    { 0x2C9FFB, "Canon" },
    { 0x2CAA8E, "Wyze" },
    { 0x2CAB00, "Huawei" },
    { 0x2CABA4, "Vizio" },
    { 0x2CAE2B, "Samsung" },
    { 0x2CB05D, "Netgear" },
    { 0x2CBC10, "Sony" },
    { 0x2CCF67, "OPPO" },
    { 0x30038A, "OPPO" },
    { 0x30055C, "Brother" },
    { 0x300D43, "Harman" },
    { 0x30150E, "Huawei" },
    { 0x302432, "Apple" },
    { 0x30469A, "Netgear" },
    { 0x30595B, "OPPO" },
    { 0x305A3A, "ASUS" },
    { 0x307C30, "Hisense" },
    { 0x308D99, "Google" },
    { 0x30AEA4, "Espressif" },
    { 0x30B5C2, "TP-Link" },
    { 0x30C7AE, "Samsung" },
    { 0x30F9ED, "Sony" },
    { 0x34145F, "Samsung" },
    { 0x344DF7, "LG" },
    { 0x345A60, "Hisense" },
    { 0x3460F9, "OPPO" },
    { 0x346BD3, "TP-Link" },
    { 0x3480B3, "Xiaomi" },
    { 0x348741, "Samsung" },
    { 0x349B1F, "Samsung" },
    { 0x349FB1, "Samsung" },
    { 0x34AF2C, "Nintendo" },
    { 0x34B354, "Huawei" },
    { 0x34D270, "Amazon" },
    { 0x34DE1A, "OPPO" },
    { 0x34E2FD, "Sony" },
    { 0x380566, "Toshiba" },
    { 0x381A52, "ASUS" },
    { 0x382C4A, "HP" },
    { 0x384B76, "OPPO" },
    { 0x3859F9, "Lenovo" },
    { 0x38A4ED, "Xiaomi" },
    { 0x38AA3C, "Samsung" },
    { 0x38C986, "Apple" },
    { 0x38CA73, "LG" },
    { 0x38D40B, "Samsung" },
    { 0x38F73D, "Amazon" },
    { 0x3C0518, "Samsung" },
    { 0x3C0754, "Apple" },
    { 0x3C1B6F, "Dahua" },
    { 0x3C22FB, "Apple" },
    { 0x3C2AF4, "Epson" },
    { 0x3C5A37, "LG" },
    { 0x3C5CC4, "Ring" },
    { 0x3C71BF, "Espressif" },
    { 0x3C84A6, "TP-Link" },
    { 0x3C9544, "Panasonic" },
    { 0x3C970E, "Lenovo" },
    { 0x3CEF8C, "Dahua" },
    { 0x3CF011, "Lenovo" },
    { 0x403FFC, "Fitbit" },
    { 0x404E36, "Samsung" },
    { 0x40831D, "Apple" },
    { 0x4083DE, "Huawei" },
    { 0x409C28, "Nintendo" },
    { 0x40A69D, "Panasonic" },
    { 0x40A6D9, "Apple" },
    { 0x40A8F0, "HP" },
    { 0x40B0FA, "LG" },
    { 0x40B4CD, "Amazon" },
    { 0x40B837, "Samsung" },
    { 0x40B89A, "Samsung" },
    { 0x40B8A8, "Google" },
    { 0x40EC99, "Hisense" },
    { 0x40ED98, "Garmin" },
    { 0x40F201, "Arlo" },
    { 0x440319, "Hikvision" },
    { 0x441EA1, "HP" },
    { 0x444C0C, "Huawei" },
    { 0x4457DC, "Amazon" },
    { 0x44650D, "Amazon" },
    { 0x447DA5, "Amazon" },
    { 0x448A5B, "Harman" },
    { 0x449163, "Apple" },
    { 0x44B57E, "Fitbit" },
    { 0x44D244, "Epson" },
    { 0x44D9E7, "Ubiquiti" },
    { 0x48137E, "Samsung" },
    { 0x48435A, "Huawei" },
    { 0x48437C, "Apple" },
    { 0x484971, "LG" },
    { 0x4852BE, "Amazon" },
    { 0x485B39, "ASUS" },
    { 0x4865EE, "Intel" },
    { 0x48A98A, "Google" },
    { 0x48D6D5, "Bose" },
    { 0x48E729, "Espressif" },
    { 0x4C0BBE, "Microsoft" },
    { 0x4C11AE, "Espressif" },
    { 0x4C11BF, "Dahua" },
    { 0x4C1A3A, "Yamaha" },
    { 0x4C1FCC, "Huawei" },
    { 0x4C3275, "Apple" },
    { 0x4C5E0C, "MikroTik" },
    { 0x4C60DE, "Netgear" },
    { 0x4C7C5F, "Apple" },
    { 0x4C99E3, "Hikvision" },
    { 0x4CB16C, "Huawei" },
    { 0x4CBCA5, "Samsung" },
    { 0x4CBE14, "Brother" },
    { 0x4CEBD6, "Espressif" },
    { 0x4CF59C, "Hisense" },
    { 0x4CF95D, "Huawei" },
    { 0x4CFCAA, "Tesla" },
    { 0x50022A, "Tuya" },
    { 0x500291, "Espressif" },
    { 0x500809, "Lenovo" },
    { 0x501500, "Xiaomi" },
    { 0x50465D, "ASUS" },
    { 0x50640D, "Xiaomi" },
    { 0x5065F3, "HP" },
    { 0x50C4DD, "Hisense" },
    { 0x50C7BF, "TP-Link" },
    { 0x50CB1D, "Intel" },
    { 0x50CCF8, "Samsung" },
    { 0x50CD22, "OPPO" },
    { 0x50DCE7, "Amazon" },
    { 0x50EAD6, "Xiaomi" },
    { 0x50EC50, "Aqara" },
    { 0x541DD9, "Google" },
    { 0x542696, "Samsung" },
    { 0x54423E, "Sony" },
    { 0x544249, "Sony" },
    { 0x546CEB, "Lenovo" },
    { 0x548998, "Vizio" },
    { 0x54A050, "ASUS" },
    { 0x54A51B, "Huawei" },
    { 0x54CF36, "Tesla" },
    { 0x54E1AD, "Lenovo" },
    { 0x54E43A, "Apple" },
    { 0x584498, "Xiaomi" },
    { 0x5849BA, "TCL" },
    { 0x586AB1, "Hikvision" },
    { 0x58820A, "Microsoft" },
    { 0x58A2B5, "LG" },
    { 0x58B035, "Apple" },
    { 0x58B10F, "Samsung" },
    { 0x58BDA3, "Nintendo" },
    { 0x58C38B, "Samsung" },
    { 0x58EF68, "Linksys" },
    { 0x58FB84, "Xiaomi" },
    { 0x5C0A5B, "Amazon" },
    { 0x5C1B7D, "Xiaomi" },
    { 0x5C3C27, "Toshiba" },
    { 0x5C497D, "Samsung" },
    { 0x5C5B35, "Google" },
    { 0x5C628B, "TP-Link" },
    { 0x5C7D5E, "Huawei" },
    { 0x5CA5E6, "Lenovo" },
    { 0x5CA86A, "Huawei" },
    { 0x5CAAFD, "Sonos" },
    { 0x5CB524, "Sony" },
    { 0x5CCF7F, "Espressif" },
    { 0x5CD998, "D-Link" },
    { 0x5CF207, "Hikvision" },
    { 0x5CF6DC, "Samsung" },
    { 0x5CF938, "Apple" },
    { 0x5CF9DD, "Dell" },
    { 0x603570, "Intel" },
    { 0x6038E0, "Linksys" },
    { 0x60455E, "Microsoft" },
    { 0x60A44C, "ASUS" },
    { 0x60A4B7, "TP-Link" },
    { 0x60D819, "Lenovo" },
    { 0x60DE44, "Huawei" },
    { 0x60E3AC, "LG" },
    { 0x64004A, "Dell" },
    { 0x64006A, "Lenovo" },
    { 0x64090C, "Xiaomi" },
    { 0x640980, "Xiaomi" },
    { 0x64166D, "Google" },
    { 0x641CB0, "Huawei" },
    { 0x6466B3, "Google" },
    { 0x6468BC, "Hisense" },
    { 0x64A651, "Huawei" },
    { 0x64B853, "Samsung" },
    { 0x64CC2E, "Xiaomi" },
    { 0x64EB8C, "Epson" },
    { 0x6805CA, "Epson" },
    { 0x680AE2, "Tuya" },
    { 0x681599, "Canon" },
    { 0x687251, "Ubiquiti" },
    { 0x689C70, "Apple" },
    { 0x68A86D, "Apple" },
    { 0x68AAD2, "Google" },
    { 0x68AB1E, "Intel" },
    { 0x68B1D6, "Canon" },
    { 0x68C63A, "Espressif" },
    { 0x68D93C, "Apple" },
    { 0x68DBF5, "Amazon" },
    { 0x68DD26, "OPPO" },
    { 0x68DFDD, "Xiaomi" },
    { 0x68EBAE, "Samsung" },
    { 0x6C05D7, "OPPO" },
    { 0x6C0B84, "Lenovo" },
    { 0x6C2F2C, "Samsung" },
    { 0x6C3B6B, "MikroTik" },
    { 0x6C5CDE, "TCL" },
    { 0x6C5F1C, "Xiaomi" },
    { 0x6CAAB3, "Google" },
    { 0x6CB0CE, "Netgear" },
    { 0x6CD032, "LG" },
    { 0x7016CF, "Google" },
    { 0x70288B, "Samsung" },
    { 0x7054F5, "Huawei" },
    { 0x705AB6, "Lenovo" },
    { 0x7085C2, "Intel" },
    { 0x709E29, "PlayStation" },
    { 0x70A8E3, "Huawei" },
    { 0x70BC10, "Microsoft" },
    { 0x70D7A7, "OPPO" },
    { 0x70DEE2, "Apple" },
    { 0x70F927, "Samsung" },
    { 0x742344, "Xiaomi" },
    { 0x7451BA, "LG" },
    { 0x747548, "Amazon" },
    { 0x749975, "Bose" },
    { 0x74CD42, "Panasonic" },
    { 0x74D55B, "Tesla" },
    { 0x74D637, "Amazon" },
    { 0x74E14A, "Harman" },
    { 0x74E5F9, "Intel" },
    { 0x7811DC, "Aqara" },
    { 0x781848, "Lenovo" },
    { 0x7824AF, "ASUS" },
    { 0x78282A, "Sonos" },
    { 0x7828CA, "Sonos" },
    { 0x782BCB, "Xiaomi" },
    { 0x784558, "Ubiquiti" },
    { 0x784F43, "Vizio" },
    { 0x78542E, "D-Link" },
    { 0x78595E, "Samsung" },
    { 0x789508, "Canon" },
    { 0x78BDBC, "Samsung" },
    { 0x78CA39, "Apple" },
    { 0x78D752, "Huawei" },
    { 0x78F882, "Samsung" },
    { 0x7C1CF1, "Huawei" },
    { 0x7C1DD9, "Xiaomi" },
    { 0x7C1E52, "Microsoft" },
    { 0x7C2EBD, "Google" },
    { 0x7C49EB, "Xiaomi" },
    { 0x7C6193, "Samsung" },
    { 0x7C6D62, "Apple" },
    { 0x7C70BC, "Arlo" },
    { 0x7C76C8, "Intel" },
    { 0x7C78B2, "Wyze" },
    { 0x7C7D3D, "Huawei" },
    { 0x7C9EBD, "Espressif" },
    { 0x7CA61D, "Sony" },
    { 0x7CA9B5, "Panasonic" },
    { 0x7CBB8A, "Nintendo" },
    { 0x7CC2C6, "Google" },
    { 0x7CED8D, "Microsoft" },
    { 0x802AA8, "Ubiquiti" },
    { 0x803773, "TCL" },
    { 0x805EC0, "HP" },
    { 0x80656D, "Samsung" },
    { 0x80910A, "Toshiba" },
    { 0x80927A, "Brother" },
    { 0x80AFCA, "Xiaomi" },
    { 0x80F73E, "OPPO" },
    { 0x84119E, "Samsung" },
    { 0x841B5E, "Netgear" },
    { 0x841B77, "Epson" },
    { 0x8425DB, "Samsung" },
    { 0x845387, "Vizio" },
    { 0x848999, "Panasonic" },
    { 0x84A8E4, "Huawei" },
    { 0x84C9B2, "D-Link" },
    { 0x84D6D0, "Amazon" },
    { 0x84DBAC, "Huawei" },
    { 0x84F3EB, "Espressif" },
    { 0x84FD27, "IKEA" },
    { 0x88329B, "Samsung" },
    { 0x88408E, "Huawei" },
    { 0x8863DF, "Apple" },
    { 0x88708C, "Lenovo" },
    { 0x8871E5, "Amazon" },
    { 0x887DDE, "Canon" },
    { 0x88C663, "Apple" },
    { 0x88C9D0, "LG" },
    { 0x88CEFA, "Huawei" },
    { 0x88D7F6, "ASUS" },
    { 0x8C1645, "Intel" },
    { 0x8C53C3, "Hisense" },
    { 0x8C56C5, "Nintendo" },
    { 0x8C8590, "Bose" },
    { 0x8CAAB5, "Espressif" },
    { 0x8CBEBE, "Xiaomi" },
    { 0x8CDCD4, "Huawei" },
    { 0x902B34, "Huawei" },
    { 0x90840D, "Apple" },
    { 0x90940E, "D-Link" },
    { 0x90B21F, "Apple" },
    { 0x90B6ED, "Samsung" },
    { 0x9407A9, "Xiaomi" },
    { 0x94181B, "Ubiquiti" },
    { 0x941A72, "Huawei" },
    { 0x9422C8, "Panasonic" },
    { 0x9457A5, "HP" },
    { 0x94B97E, "Espressif" },
    { 0x94D29B, "OPPO" },
    { 0x94EB2C, "Google" },
    { 0x94F3B1, "Sonos" },
    { 0x9809CF, "OPPO" },
    { 0x983B8F, "Garmin" },
    { 0x9852B1, "Samsung" },
    { 0x98A7B0, "Microsoft" },
    { 0x98B8E3, "Apple" },
    { 0x98CDAC, "Shelly" },
    { 0x98D6F7, "LG" },
    { 0x98DF82, "Hikvision" },
    { 0x98E743, "Dell" },
    { 0x98E8FA, "Nintendo" },
    { 0x98ED5C, "Tesla" },
    { 0x98F4AB, "Espressif" },
    { 0x98FA9B, "Xiaomi" },
    { 0x9C14C3, "Dahua" },
    { 0x9C2883, "Huawei" },
    { 0x9C28EF, "Huawei" },
    { 0x9C3DCF, "Netgear" },
    { 0x9C53CD, "TP-Link" },
    { 0x9C5CF9, "Yamaha" },
    { 0x9C93E4, "Google" },
    { 0x9C99A0, "Xiaomi" },
    { 0x9CAE4E, "Epson" },
    { 0x9CB2B2, "Huawei" },
    { 0x9CE063, "Samsung" },
    { 0xA002DC, "Amazon" },
    { 0xA00BBA, "TCL" },
    { 0xA020A6, "Espressif" },
    { 0xA021B7, "Netgear" },
    { 0xA039F7, "LG" },
    { 0xA040A0, "Netgear" },
    { 0xA0510B, "Lenovo" },
    { 0xA07591, "Samsung" },
    { 0xA081B5, "Huawei" },
    { 0xA086C6, "Xiaomi" },
    { 0xA0B4A5, "Samsung" },
    { 0xA0BD1D, "Dahua" },
    { 0xA0C589, "OPPO" },
    { 0xA0C9A0, "Microsoft" },
    { 0xA0D3C1, "HP" },
    { 0xA0EDCD, "Apple" },
    { 0xA0F6FD, "Bose" },
    { 0xA41F72, "Dell" },
    { 0xA42BB0, "TP-Link" },
    { 0xA434D9, "Samsung" },
    { 0xA4506B, "Google" },
    { 0xA475DC, "Amazon" },
    { 0xA4770C, "Harman" },
    { 0xA4778D, "Google" },
    { 0xA486C7, "LG" },
    { 0xA48CDB, "Tuya" },
    { 0xA48E0A, "Lenovo" },
    { 0xA4B197, "Apple" },
    { 0xA4BA76, "Huawei" },
    { 0xA4CF12, "Espressif" },
    { 0xA4D1D2, "Apple" },
    { 0xA4DA22, "Google" },
    { 0xA4DA32, "Xiaomi" },
    { 0xA4DDE6, "Canon" },
    { 0xA4EE57, "Epson" },
    { 0xA855F1, "Google" },
    { 0xA87DC3, "Xiaomi" },
    { 0xA87EEA, "Samsung" },
    { 0xA8C83A, "Huawei" },
    { 0xA8D2E0, "TCL" },
    { 0xA8E3EE, "PlayStation" },
    { 0xAC16B6, "HP" },
    { 0xAC180E, "Epson" },
    { 0xAC220B, "ASUS" },
    { 0xAC293A, "Apple" },
    { 0xAC2DA3, "OPPO" },
    { 0xAC63BE, "Amazon" },
    { 0xAC8F3B, "Lenovo" },
    { 0xAC92A4, "Xiaomi" },
    { 0xAC9B0A, "Sony" },
    { 0xAC9E17, "ASUS" },
    { 0xACB966, "Hikvision" },
    { 0xACBC32, "Amazon" },
    { 0xACCF23, "Panasonic" },
    { 0xACE215, "Huawei" },
    { 0xACF108, "LG" },
    { 0xB02A43, "Lenovo" },
    { 0xB03956, "Netgear" },
    { 0xB047BF, "Ring" },
    { 0xB0481A, "Apple" },
    { 0xB0487A, "TP-Link" },
    { 0xB05B99, "Huawei" },
    { 0xB065BD, "Apple" },
    { 0xB06EBF, "ASUS" },
    { 0xB06FE0, "OPPO" },
    { 0xB0C554, "Arlo" },
    { 0xB0DF3A, "Samsung" },
    { 0xB0E235, "Xiaomi" },
    { 0xB0E43F, "Microsoft" },
    { 0xB0E892, "Epson" },
    { 0xB0EC71, "OPPO" },
    { 0xB407F9, "Sony" },
    { 0xB40B44, "Samsung" },
    { 0xB42E99, "Harman" },
    { 0xB45D50, "Canon" },
    { 0xB47443, "Xiaomi" },
    { 0xB47956, "Tuya" },
    { 0xB47C9C, "Amazon" },
    { 0xB49691, "HP" },
    { 0xB499BA, "HP" },
    { 0xB4CD27, "Huawei" },
    { 0xB4E62D, "Espressif" },
    { 0xB4FBE4, "Yamaha" },
    { 0xB8098A, "Apple" },
    { 0xB81DAA, "LG" },
    { 0xB827EB, "Raspberry-Pi" },
    { 0xB83765, "Lenovo" },
    { 0xB853AC, "Apple" },
    { 0xB857D8, "Samsung" },
    { 0xB868D4, "TCL" },
    { 0xB869F4, "MikroTik" },
    { 0xB88A60, "Intel" },
    { 0xB89678, "Harman" },
    { 0xB89A2A, "Microsoft" },
    { 0xB8A175, "Vizio" },
    { 0xB8A386, "D-Link" },
    { 0xB8AE6E, "Nintendo" },
    { 0xB8D812, "Harman" },
    { 0xB8E937, "Sonos" },
    { 0xBC0294, "Hikvision" },
    { 0xBC20BA, "Samsung" },
    { 0xBC52B7, "Apple" },
    { 0xBC5436, "Apple" },
    { 0xBC5FF4, "Intel" },
    { 0xBC60A7, "Sony" },
    { 0xBC7E8F, "Vizio" },
    { 0xBC8A1E, "LG" },
    { 0xBC8CCD, "Samsung" },
    { 0xBCAEC5, "ASUS" },
    { 0xBCD177, "TP-Link" },
    { 0xBCDDC2, "Espressif" },
    { 0xBCE10D, "Huawei" },
    { 0xBCE2BE, "Samsung" },
    { 0xC02C5C, "OPPO" },
    { 0xC02FAF, "Samsung" },
    { 0xC03EBA, "Apple" },
    { 0xC03F0E, "Netgear" },
    { 0xC05627, "Hikvision" },
    { 0xC0954D, "Canon" },
    { 0xC0C1C0, "Linksys" },
    { 0xC0C9E3, "TP-Link" },
    { 0xC0F6BF, "Garmin" },
    { 0xC40415, "Netgear" },
    { 0xC40BCB, "Vizio" },
    { 0xC4438F, "LG" },
    { 0xC4576E, "Samsung" },
    { 0xC45BBE, "Espressif" },
    { 0xC46699, "Xiaomi" },
    { 0xC46AB7, "Xiaomi" },
    { 0xC46E1F, "TP-Link" },
    { 0xC485C8, "Huawei" },
    { 0xC4A2CA, "Panasonic" },
    { 0xC4A366, "Huawei" },
    { 0xC4AD34, "MikroTik" },
    { 0xC4B741, "Hikvision" },
    { 0xC4E3EB, "Google" },
    { 0xC4F081, "Xiaomi" },
    { 0xC80210, "LG" },
    { 0xC8193E, "Samsung" },
    { 0xC81F66, "Dell" },
    { 0xC82A14, "Apple" },
    { 0xC82B96, "Espressif" },
    { 0xC863F1, "PlayStation" },
    { 0xC87B23, "Huawei" },
    { 0xC8BCC8, "Xiaomi" },
    { 0xC8BE19, "D-Link" },
    { 0xC8C9A3, "Espressif" },
    { 0xC8D719, "Linksys" },
    { 0xC8DF84, "Espressif" },
    { 0xC8E265, "Hisense" },
    { 0xC8E9EE, "TCL" },
    { 0xC8F733, "Microsoft" },
    { 0xCC2D8C, "LG" },
    { 0xCC2DE0, "MikroTik" },
    { 0xCC348E, "LG" },
    { 0xCC50E3, "Espressif" },
    { 0xCC52AF, "Microsoft" },
    { 0xCC96A0, "Huawei" },
    { 0xCCB255, "D-Link" },
    { 0xCCB8A8, "Xiaomi" },
    { 0xD017C2, "ASUS" },
    { 0xD022BE, "Google" },
    { 0xD03A2E, "Xiaomi" },
    { 0xD03F27, "Wyze" },
    { 0xD04F7E, "Apple" },
    { 0xD0667B, "Huawei" },
    { 0xD06C9A, "Lenovo" },
    { 0xD07E28, "HP" },
    { 0xD0817A, "Apple" },
    { 0xD0C5D3, "Garmin" },
    { 0xD0C8A1, "Fitbit" },
    { 0xD0CF5E, "IKEA" },
    { 0xD0DFC7, "Samsung" },
    { 0xD44B5E, "PlayStation" },
    { 0xD45D64, "ASUS" },
    { 0xD4610F, "TCL" },
    { 0xD4619D, "Apple" },
    { 0xD481D7, "Dell" },
    { 0xD487D8, "Samsung" },
    { 0xD48890, "Samsung" },
    { 0xD4970B, "Xiaomi" },
    { 0xD4AE52, "Dell" },
    { 0xD4B110, "Huawei" },
    { 0xD4CA6D, "MikroTik" },
    { 0xD4E8B2, "Hikvision" },
    { 0xD831CF, "Samsung" },
    { 0xD8490B, "Huawei" },
    { 0xD86BF7, "Yamaha" },
    { 0xD89C67, "Toshiba" },
    { 0xD89D67, "HP" },
    { 0xD89EF3, "Microsoft" },
    { 0xD8BFC0, "Tuya" },
    { 0xD8D43C, "Sony" },
    { 0xDC2B2A, "Apple" },
    { 0xDC2B61, "Apple" },
    { 0xDC4427, "Tesla" },
    { 0xDC4F22, "Tuya" },
    { 0xDC537C, "Intel" },
    { 0xDC72AD, "Huawei" },
    { 0xDC9FDB, "Ubiquiti" },
    { 0xDCA632, "Raspberry-Pi" },
    { 0xDCA904, "Apple" },
    { 0xDCCB8E, "OPPO" },
    { 0xE0191D, "OPPO" },
    { 0xE0469A, "Netgear" },
    { 0xE05FB9, "Vizio" },
    { 0xE06266, "Samsung" },
    { 0xE063DA, "Ubiquiti" },
    { 0xE0A71C, "Hisense" },
    { 0xE0ACCB, "Apple" },
    { 0xE0BB9E, "Epson" },
    { 0xE0DB55, "Dell" },
    { 0xE0E751, "Nintendo" },
    { 0xE4115B, "HP" },
    { 0xE425E7, "Apple" },
    { 0xE42F26, "OPPO" },
    { 0xE43E12, "Intel" },
    { 0xE45F01, "Raspberry-Pi" },
    { 0xE46F13, "Netgear" },
    { 0xE46F3B, "HP" },
    { 0xE488B9, "Canon" },
    { 0xE48B7F, "Apple" },
    { 0xE48D8C, "MikroTik" },
    { 0xE4A471, "Intel" },
    { 0xE4BD4B, "Huawei" },
    { 0xE4C63D, "Apple" },
    { 0xE4E0C5, "Samsung" },
    { 0xE8039A, "Samsung" },
    { 0xE80601, "Aqara" },
    { 0xE8088B, "Huawei" },
    { 0xE85354, "Samsung" },
    { 0xE869FC, "Tuya" },
    { 0xE88D28, "Apple" },
    { 0xE892A4, "LG" },
    { 0xE89309, "TCL" },
    { 0xE8CC18, "TP-Link" },
    { 0xE8CD2D, "Huawei" },
    { 0xE8DE27, "TP-Link" },
    { 0xEC0E03, "Nintendo" },
    { 0xEC1BBD, "Philips-Hue" },
    { 0xEC64C9, "Espressif" },
    { 0xEC71DB, "Reolink" },
    { 0xEC8916, "Lenovo" },
    { 0xEC9A74, "HP" },
    { 0xECB5FA, "IKEA" },
    { 0xECEBB8, "Microsoft" },
    { 0xECF4BB, "Dell" },
    { 0xF01DBC, "Microsoft" },
    { 0xF0272D, "Amazon" },
    { 0xF04141, "Hikvision" },
    { 0xF08173, "Samsung" },
    { 0xF08A76, "OPPO" },
    { 0xF094E3, "TP-Link" },
    { 0xF09FC2, "Ubiquiti" },
    { 0xF0B429, "Xiaomi" },
    { 0xF0BF97, "Sony" },
    { 0xF0D2F1, "Amazon" },
    { 0xF0DBF8, "Apple" },
    { 0xF0F61C, "Apple" },
    { 0xF0F6C1, "Sonos" },
    { 0xF42981, "OPPO" },
    { 0xF430B9, "HP" },
    { 0xF4559C, "Huawei" },
    { 0xF46B8C, "Vizio" },
    { 0xF48B32, "Xiaomi" },
    { 0xF48C50, "Apple" },
    { 0xF48CEB, "D-Link" },
    { 0xF48FFD, "Xiaomi" },
    { 0xF49F54, "Samsung" },
    { 0xF4B301, "Intel" },
    { 0xF4C714, "Huawei" },
    { 0xF4F15A, "Apple" },
    { 0xF4F5D8, "Xiaomi" },
    { 0xF4F5E8, "Google" },
    { 0xF80CF3, "LG" },
    { 0xF81EDF, "Apple" },
    { 0xF83DFF, "Huawei" },
    { 0xF83F51, "Google" },
    { 0xF84DFC, "Hikvision" },
    { 0xF895C7, "LG" },
    { 0xF8A45F, "Xiaomi" },
    { 0xF8B156, "Dell" },
    { 0xF8E903, "TCL" },
    { 0xFC0FE6, "OPPO" },
    { 0xFC253F, "Apple" },
    { 0xFC4BBC, "Fitbit" },
    { 0xFC4DD4, "Canon" },
    { 0xFC5F49, "Dahua" },
    { 0xFC6479, "Xiaomi" },
    { 0xFCA183, "Amazon" },
    { 0xFCA667, "Amazon" },
    { 0xFCC2DE, "OPPO" },
    { 0xFCECDA, "Ubiquiti" },
    { 0xFCF152, "Sony" },
    { 0xFCF8AE, "Intel" },
};

#define HNC_OUI_TABLE_SIZE (sizeof(HNC_OUI_TABLE) / sizeof(HNC_OUI_TABLE[0]))

/* bsearch 比较器:key 是 unsigned int *,elem 是 hnc_oui_entry_t * */
static int hnc_oui_cmp(const void *key, const void *elem) {
    unsigned int k = *(const unsigned int *)key;
    unsigned int e = ((const hnc_oui_entry_t *)elem)->prefix;
    if (k < e) return -1;
    if (k > e) return 1;
    return 0;
}

/* 单个 hex 字符转 0-15,非法返回 -1 */
static int hnc_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hnc_lookup_oui(const char *mac, char *out, size_t outlen) {
    if (!mac || !out || outlen == 0) return 0;
    if (outlen < 16) return 0;  /* 至少放得下 "Vendor 设备\0" */

    /* v3.8.3 D3: 用户 OUI 覆盖查询(优先级最高)
     *
     * 用户在 /data/local/hnc/data/oui_overrides.json 里写的 MAC 前缀标签
     * 优先于内置 OUI 表。这允许:
     *   1. 用户给特定前缀打精确标签 ("小米手机" 而非 "Xiaomi 设备")
     *   2. 用户给 LAA MAC(虚拟机/Docker)打标签 —— 下面的 LAA 检查只影响
     *      内置表查询,不影响 override
     *   3. 用户覆盖内置表的错误或不够具体的条目
     *
     * override 在 LAA 检查之前,是有意设计的。如果用户手动给 LAA MAC 命名,
     * 我们应该尊重用户的选择。*/
    if (hnc_override_lookup(mac, out, outlen)) {
        return 1;
    }

    /* 1) 解析前 3 字节(6 hex + 2 colon) */
    /* 格式:"XX:XX:XX:XX:XX:XX" → 取 mac[0..1], mac[3..4], mac[6..7] */
    int b0h = hnc_hex_val(mac[0]);
    int b0l = hnc_hex_val(mac[1]);
    int b1h = hnc_hex_val(mac[3]);
    int b1l = hnc_hex_val(mac[4]);
    int b2h = hnc_hex_val(mac[6]);
    int b2l = hnc_hex_val(mac[7]);

    if (b0h < 0 || b0l < 0 || b1h < 0 || b1l < 0 || b2h < 0 || b2l < 0) {
        return 0;
    }
    if (mac[2] != ':' || mac[5] != ':') return 0;

    unsigned int byte0 = (unsigned int)((b0h << 4) | b0l);
    unsigned int byte1 = (unsigned int)((b1h << 4) | b1l);
    unsigned int byte2 = (unsigned int)((b2h << 4) | b2l);

    /* 2) 随机 MAC 检测:locally-administered bit (bit 1 of byte 0)
     *
     * IEEE 802.3 规定:
     *   - bit 0 of byte 0 = 1 → multicast (不会出现在客户端 MAC)
     *   - bit 1 of byte 0 = 1 → locally-administered (随机/虚拟 MAC)
     *
     * Android 10+ 默认对每个 SSID 生成随机 MAC,这些 MAC 都设了 LAA bit。
     * 查 OUI 表毫无意义(会返回伪造的"厂商"),直接跳过。*/
    if (byte0 & 0x02) {
        return 0;  /* 随机 MAC,让调用方走 mac 兜底 */
    }

    /* 3) 组成 24-bit key */
    unsigned int key = (byte0 << 16) | (byte1 << 8) | byte2;

    /* 4) bsearch */
    const hnc_oui_entry_t *hit = (const hnc_oui_entry_t *)bsearch(
        &key,
        HNC_OUI_TABLE,
        HNC_OUI_TABLE_SIZE,
        sizeof(HNC_OUI_TABLE[0]),
        hnc_oui_cmp
    );
    if (!hit) return 0;

    /* 5) 格式化为 "<Vendor> 设备"
     * "设备" 是 UTF-8 6 字节,加上 Vendor 最长 ~12 字符 + 空格 + \0,
     * 总共 ≤ 20 字节,outlen ≥ 16 检查已保证安全 */
    snprintf(out, outlen, "%s 设备", hit->vendor);
    return 1;
}
