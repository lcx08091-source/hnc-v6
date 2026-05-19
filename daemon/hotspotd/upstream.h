/* upstream.h — HNC v5.0 alpha.2 上游 ifindex 探测
 *
 * 背景:
 *   alpha.1 用 /proc/net/route 找 default route, 在 ColorOS + 5G 多上游环境下
 *   失败 — default route 不在 main table, 而在 per-iface table (rmnet_data3 等)。
 *   真机现象: `ip route show` 看 main table 无 default, 但 BPF limit_map 里
 *   ifindex=30 (rmnet_data3) 正在转发流量。
 *
 * alpha.2 策略 (按优先级 fallback):
 *
 *   Tier 1: popen "ip route get 8.8.8.8"
 *     - Android 策略路由查询 (uid=0 视角, 与 hotspotd 一致)
 *     - 输出稳定: "8.8.8.8 via X dev <ifname> table Y src Z uid 0"
 *     - 正则抓 "dev (\S+)" 转 ifindex
 *     - 覆盖 95% 场景, 包括 ColorOS/HyperOS 多表路由
 *
 *   Tier 2: 扫 /proc/net/route 全部条目 (不限 default)
 *     - Tier 1 失败 (无网络/无 ip 命令) 时兜底
 *     - 选第一个 RTF_UP 且 iface 名以 rmnet/wwan/eth/wlan 开头的
 *
 *   Tier 3: BPF upstream4_map 反查
 *     - 最可靠 ground truth (正在转发的 ifindex 就在 value 里)
 *     - 要求 offload 已在工作 (有流量经过)
 *     - 实测 ColorOS value 第一个 u32 就是 upstream_ifindex
 *     - 留 alpha.3 启用, alpha.2 先不加复杂度
 *
 * 调用语义:
 *   int upstream_detect_primary(int *ifindex_out, char *ifname_out, size_t size);
 *   返回 0 = 找到, 写入 *ifindex_out 与 ifname_out
 *   返回 -1 = 所有 tier 都失败 (保持调用方上次缓存的值)
 *
 * 性能:
 *   Tier 1 popen 开销 ~5-10ms, 只在 scheduler 集合 0→>0 转换时触发, 不频繁
 *   Tier 2 读 /proc/net/route 纯 userspace, <1ms
 *
 * 线程安全:
 *   popen 在 pthread 环境下安全, 无全局状态
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef HNC_UPSTREAM_H
#define HNC_UPSTREAM_H

#include <stddef.h>

/* 探测当前 Android 用户 (uid=0) 视角的主上游 ifindex + ifname
 *
 * 成功:
 *   返回 0, *ifindex_out > 0, ifname_out 填入 NUL-terminated iface name
 *
 * 失败:
 *   返回 -1, 两个输出参数不变 (调用方可沿用上次缓存)
 */
int upstream_detect_primary(int *ifindex_out,
                             char *ifname_out,
                             size_t ifname_size);

/* 内部 tier 测试 hook, 仅单元测试用
 * 生产代码请直接调 upstream_detect_primary */
int upstream_detect_via_ip_route(int *ifindex_out,
                                  char *ifname_out,
                                  size_t ifname_size);

int upstream_detect_via_proc_route(int *ifindex_out,
                                    char *ifname_out,
                                    size_t ifname_size);

/* alpha.4 P0-C: Tier 3 BPF upstream4_map 反查
 * 直接从 tethering BPF map 读取 oif (upstream ifindex)
 * 比 popen("ip") 更可靠 (daemon SELinux 下 popen 可能被挡), 也免 VPN 干扰 */
int upstream_detect_via_bpf(int *ifindex_out,
                             char *ifname_out,
                             size_t ifname_size);

#endif /* HNC_UPSTREAM_H */
