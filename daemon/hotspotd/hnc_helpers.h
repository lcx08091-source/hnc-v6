/* hnc_helpers.h — HNC shared C helpers
 *
 * v3.6 Commit 2:把 hotspotd.c 里的纯 helper 函数提取到这个文件,
 * 主代码和测试都 #include,彻底消除 v3.5.1 P1-3 和 v3.5.2 P1-A 的复制 drift。
 *
 * 设计原则:
 *   1) 所有函数都是纯函数或只依赖传入的参数/文件路径
 *   2) 不依赖 hotspotd.c 的全局状态(g_devs / g_log 等)
 *   3) 不依赖 hotspotd.c 的 macro 定义(DEVICE_NAMES_JSON 等),路径由调用方传入
 *   4) 测试代码可以直接 #include 这个头文件,link hnc_helpers.o,跟主代码跑同一个实现
 */

#ifndef HNC_HELPERS_H
#define HNC_HELPERS_H

#include <stddef.h>
#include <time.h>

/* ══════════════════════════════════════════════════════════
 * Buffer 大小约定(跟 hotspotd.c 的 Device 结构对齐)
 * ══════════════════════════════════════════════════════════ */
#define HNC_HN_LEN        64    /* hostname 最大长度 */
#define HNC_HN_SRC_LEN    12    /* hostname_src 最大长度("manual"/"mdns"/"mac"/"pending") */
#define HNC_MAC_STR_LEN   18    /* "aa:bb:cc:dd:ee:ff\0" */
#define HNC_IP_STR_LEN    16    /* "255.255.255.255\0" */

/* ══════════════════════════════════════════════════════════
 * should_re_resolve — re-resolve 时间窗口判断
 *
 * 触发条件:
 *   1) hostname_src == "mac" 兜底 → 立即重试(user 可能刚命名)
 *   2) now - last_resolve >= 60 秒 → 窗口过期(可能改名/mDNS 缓存更新)
 *
 * 返回:1 = 需要重新解析,0 = 保持现状
 * ══════════════════════════════════════════════════════════ */
int hnc_should_re_resolve(const char *hostname_src, time_t last_resolve, time_t now);

/* ══════════════════════════════════════════════════════════
 * json_escape — JSON 字符串转义
 *
 * 转义 " \ \n \r \t 和 0x00-0x1f 控制字符。
 * 非 ASCII 字节(UTF-8 多字节)原样保留。
 * 如果 dst_size 不够,会回退到最近完整 UTF-8 字符边界(不留残缺 continuation)。
 * 输出始终 NUL-terminated。
 * ══════════════════════════════════════════════════════════ */
void hnc_json_escape(const char *src, char *dst, size_t dst_size);

/* ══════════════════════════════════════════════════════════
 * mac_fallback — MAC 地址兜底 hostname
 *
 * 跟 shell 路径 `echo "$mac" | tr -d ':' | tail -c 9` 对齐:
 *   "aa:bb:cc:dd:ee:ff" → "ccddeeff"(后 8 hex 字符)
 * ══════════════════════════════════════════════════════════ */
void hnc_mac_fallback(const char *mac, char *out, size_t outlen);

/* ══════════════════════════════════════════════════════════
 * lookup_manual_name — 从 device_names.json 查手动命名
 *
 * 参数:
 *   mac        — 查询的 MAC 地址(case-insensitive)
 *   names_path — device_names.json 的完整路径(NULL 或文件不存在 → 返回 0)
 *   out, outlen — 输出 buffer
 *
 * 返回:1 = 找到(out 被填充),0 = 未找到
 *
 * 实现细节:
 *   - 一次 fread 读整个文件(最大 8KB),避免 fgets 截断
 *   - 匹配 "mac":"name" 子串,大小写不敏感
 *   - 处理 JSON escape: \" → " 和 \\ → \
 * ══════════════════════════════════════════════════════════ */
int hnc_lookup_manual_name(const char *mac, const char *names_path,
                           char *out, size_t outlen);

/* ══════════════════════════════════════════════════════════
 * resolve_hostname_fast — 快速 hostname 解析(不含 mdns,不阻塞)
 *
 * 优先级:manual(本地文件,极快)> mac 兜底
 * 不调用 mdns_resolve,所以永远不 popen,永远不阻塞。
 * v3.6 用于 scan_arp / nl_process 这种在主循环里被调用的路径。
 *
 * 参数:
 *   mac, ip    — 设备信息
 *   names_path — device_names.json 路径
 *   out_hn, hn_len     — 输出 hostname
 *   out_src, src_len   — 输出 hostname_src ("manual" / "mac")
 * ══════════════════════════════════════════════════════════ */
void hnc_resolve_hostname_fast(const char *mac, const char *ip,
                               const char *names_path,
                               char *out_hn, size_t hn_len,
                               char *out_src, size_t src_len);

/* ══════════════════════════════════════════════════════════
 * pending_ready — 判断一个 pending 设备现在是否应该被处理
 *
 * v3.6 Commit 3 — 支持异步 mDNS 解析(候选 B "pending" 模式)
 *
 * 规则:
 *   1) hostname_src 必须是 "pending"(否则返回 0)
 *   2) 从 pending_since 到 now 必须 >= HNC_PENDING_BREATHING_ROOM_SEC
 *      (避免设备刚被标 pending 立刻就 spawn popen,给 netlink 一点时间
 *       消化事件风暴)
 *
 * 返回: 1 = 应该处理,0 = 跳过(未 pending 或 breathing room 未过)
 *
 * 注意这是个纯函数,不读/写全局状态,容易单元测试。
 * process_pending_mdns() 的 FIFO 选择逻辑在 hotspotd.c 里内联
 * (就一个 pending_since < 比较),不单独提取。
 * ══════════════════════════════════════════════════════════ */
#define HNC_PENDING_BREATHING_ROOM_SEC  1

int hnc_pending_ready(const char *hostname_src, time_t pending_since, time_t now);

/* ══════════════════════════════════════════════════════════
 * lookup_oui — 从 MAC 地址前 3 字节查厂商名 (v3.8.0)
 *
 * 用途:DHCP/mDNS/cache 全部未命中时,在 mac 兜底之前的最后一道挽救。
 *      把纯 MAC 后缀 "d69d0fa1" 升级为 "Apple 设备" / "Xiaomi 设备",
 *      对原生 Android(Pixel / LineageOS)等不发 DHCP option 12 的设备
 *      显著改善用户体验。
 *
 * 行为:
 *   1) 随机 MAC (locally-administered bit, mac[0] & 0x02) → 返回 0,不查表
 *      (Android 10+ 默认开 MAC 随机化,查 OUI 无意义)
 *   2) 从 mac 前 6 hex 字符提取 24-bit 前缀,bsearch OUI 表
 *   3) 命中 → out 填入 "<Vendor> 设备",返回 1
 *   4) 未命中 → 返回 0
 *
 * 参数:
 *   mac      — "aa:bb:cc:dd:ee:ff" 格式,17 字符
 *   out      — 输出 buffer
 *   outlen   — 输出 buffer 长度
 *
 * 返回:1 = 命中,0 = 跳过或未命中
 *
 * 性能:表为编译时静态数组,bsearch O(log N),N≈444,平均 ~9 次比较,<1μs。
 * ══════════════════════════════════════════════════════════ */
int hnc_lookup_oui(const char *mac, char *out, size_t outlen);

#endif /* HNC_HELPERS_H */
