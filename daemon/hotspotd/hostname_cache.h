/* hostname_cache.h — HNC DHCP/mDNS hostname 持久化 cache
 *
 * v3.8.1: Gemini P1-7 审查指出的问题 —— dumpsys network_stack 的 ring buffer
 * 只保留最近的 DHCP 事件,长租期设备或系统压力大时 buffer 滚出。HNC 的
 * try_ns_dhcp_resolve 返回空 → 降级到 OUI 或 MAC 兜底,用户看到"正确的
 * 设备名"突然变成"Xiaomi 设备"或"D69D0FA1"。
 *
 * 解决方案: 一旦 hotspotd 通过 DHCP 或 mDNS 成功识别出设备真名,就把
 * (mac → hostname, src, timestamp) 写入一个持久化 cache 文件。后续查询时,
 * 如果 DHCP/mDNS 都失败,fall back 到 cache。重启 hotspotd 时从磁盘恢复。
 *
 * 优先级链变化:
 *   v3.8.0: manual > dhcp > mdns > oui > mac
 *   v3.8.1: manual > dhcp > mdns > CACHE > oui > mac
 *                                   ^^^^^
 *
 * 设计原则:
 *   1) 独立文件 /data/local/hnc/data/hostname_cache.json,不污染 devices.json
 *   2) 纯内存 + 磁盘持久化,无数据库,无索引
 *   3) 启动时 load 一次,正常运行期 lookup/update 都在内存
 *   4) de-bounce save,避免频繁 fsync
 *   5) 不过期,MAC 碰撞由上游优先级(DHCP)自动修复
 *   6) 固定大小上限(MAX=1024),满了淘汰最旧条目
 *
 * 线程安全: 当前纯单线程使用,无锁。v3.8.4 引入 pthread 时需要加互斥。
 */

#ifndef HNC_HOSTNAME_CACHE_H
#define HNC_HOSTNAME_CACHE_H

#include <stddef.h>
#include <time.h>

/* cache 容量上限
 * 真实场景: 家庭热点一年不超过 1000 独立 MAC,1024 够用数年。
 * 文件大小: 1024 * ~100B ≈ 100 KB,无压力 */
#define HNC_CACHE_MAX_ENTRIES  1024

/* 单条 cache 记录 */
typedef struct {
    int    active;            /* 1 = 有效,0 = 空槽 */
    char   mac[18];           /* XX:XX:XX:XX:XX:XX\0 */
    char   hostname[64];      /* HN_LEN */
    char   src[12];           /* "dhcp" / "mdns" */
    time_t updated_at;        /* 最后一次 update 的 unix 时间 */
} hnc_cache_entry_t;

/* ══════════════════════════════════════════════════════════
 * hnc_cache_init — 初始化 cache(清零内存,设置文件路径)
 *
 * 调用时机: hotspotd 启动时,在 load 之前调用一次
 * ══════════════════════════════════════════════════════════ */
void hnc_cache_init(const char *cache_path);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_load — 从磁盘读取 cache 到内存
 *
 * 调用时机: hotspotd 启动,init 之后
 * 返回: 成功加载的条目数;文件不存在 → 返回 0(正常,首次启动)
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_load(void);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_save — 把内存 cache 写入磁盘(原子 tmp+rename)
 *
 * 调用时机: write_json 的 de-bounce 窗口触发,或 hotspotd 退出时
 * 返回: 0 = 成功, -1 = 失败
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_save(void);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_lookup — 查询 cache
 *
 * 参数:
 *   mac      — 查询的 MAC
 *   out_hn   — 输出 hostname
 *   hn_len   — 输出 buffer 长度
 *   out_src  — 输出 原始 src ("dhcp" / "mdns")
 *   src_len  — 输出 src buffer 长度
 *
 * 返回: 1 = 命中, 0 = 未命中
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_lookup(const char *mac,
                     char *out_hn, size_t hn_len,
                     char *out_src, size_t src_len);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_update — 更新 cache 条目(成功识别后调用)
 *
 * 参数:
 *   mac      — MAC 地址
 *   hostname — 识别到的 hostname
 *   src      — 识别来源 ("dhcp" / "mdns")
 *
 * 行为:
 *   - 如果 mac 已在 cache → 覆盖 hostname/src/updated_at
 *   - 如果 mac 不在 cache,且有空槽 → 插入
 *   - 如果 cache 满 → 淘汰最旧条目(LRU by updated_at)
 *
 * 调用后 cache 变 dirty,下次 hnc_cache_save 会写盘
 *
 * 返回: 1 = 发生了改变(需要 save), 0 = 没变化(完全相同的数据)
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_update(const char *mac, const char *hostname, const char *src);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_is_dirty — cache 是否有未保存的改动
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_is_dirty(void);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_count — 当前 cache 中的有效条目数
 * (测试和诊断用)
 * ══════════════════════════════════════════════════════════ */
int hnc_cache_count(void);

/* ══════════════════════════════════════════════════════════
 * hnc_cache_reset — 清空 cache(测试用)
 * ══════════════════════════════════════════════════════════ */
void hnc_cache_reset(void);

#endif /* HNC_HOSTNAME_CACHE_H */
