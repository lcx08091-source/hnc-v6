/* oui_override.h — HNC v3.8.3 D3: 用户 OUI 覆盖
 *
 * 允许用户在 /data/local/hnc/data/oui_overrides.json 里写自定义的
 * MAC 前缀 → 设备标签 映射,运行时优先于内置 OUI 表生效。
 *
 * 用途:
 *   - 用户给家里的特定厂商设备打精确标签 ("小米手机" 而非 "Xiaomi 设备")
 *   - 用户给 LAA MAC(虚拟机/Docker)打标签(内置 OUI 表会跳过 LAA)
 *   - 用户覆盖内置表错误或不够具体的条目
 *
 * 文件格式(宽松 JSON):
 *   {
 *     "28:6c:07": "小米手机",
 *     "b8:27:eb": "树莓派",
 *     "ccb8a8":   "ESP32 传感器"
 *   }
 *
 *   - Key: 6 hex chars MAC 前缀,带冒号或不带都接受,大小写不敏感
 *   - Value: UTF-8 字符串,最长 63 字节
 *
 * 容量:
 *   - 最多 256 条(用户自定义一般不会超过)
 *   - 文件大小上限 16 KB
 *
 * 失败策略:
 *   - 文件不存在 → 正常(用户没写过),覆盖表为空
 *   - 文件损坏 / 格式错 → hlog 警告,覆盖表为空,不 crash
 *   - 条目超过 256 → 只加载前 256 条,hlog 警告
 *
 * 线程安全:单线程模型,无锁。v3.8.4 pthread 时需要加互斥。
 */

#ifndef HNC_OUI_OVERRIDE_H
#define HNC_OUI_OVERRIDE_H

#include <stddef.h>

#define HNC_OVERRIDE_MAX_ENTRIES   256
#define HNC_OVERRIDE_LABEL_LEN     64

/* ══════════════════════════════════════════════════════════
 * hnc_override_init — 初始化覆盖模块(清零内存,设置文件路径)
 * 调用时机: hotspotd 启动时,load 之前
 * ══════════════════════════════════════════════════════════ */
void hnc_override_init(const char *path);

/* ══════════════════════════════════════════════════════════
 * hnc_override_load — 从磁盘读取覆盖文件到内存
 * 返回: 加载的条目数;文件不存在 → 返回 0(正常)
 * ══════════════════════════════════════════════════════════ */
int hnc_override_load(void);

/* ══════════════════════════════════════════════════════════
 * hnc_override_lookup — 查询用户覆盖表
 *
 * 参数:
 *   mac     — "aa:bb:cc:dd:ee:ff" 格式
 *   out     — 输出 buffer
 *   outlen  — 输出 buffer 长度
 *
 * 返回:1 = 命中,0 = 未命中
 *
 * 注意:跟 hnc_lookup_oui 不同,**不检查 LAA bit**。用户可能想给
 * 自己的虚拟机/Docker 容器的 LAA MAC 打标签。
 * ══════════════════════════════════════════════════════════ */
int hnc_override_lookup(const char *mac, char *out, size_t outlen);

/* ══════════════════════════════════════════════════════════
 * hnc_override_count — 当前加载的条目数(诊断/测试用)
 * ══════════════════════════════════════════════════════════ */
int hnc_override_count(void);

/* ══════════════════════════════════════════════════════════
 * hnc_override_reset — 清空内存表(测试用)
 * ══════════════════════════════════════════════════════════ */
void hnc_override_reset(void);

#endif /* HNC_OUI_OVERRIDE_H */
