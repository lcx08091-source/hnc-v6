// SPDX-License-Identifier: GPL-2.0
/* hnc_clsact.bpf.c — HNC T1 tier: clsact ingress BPF program
 *
 * 回移自 5.9.91 分叉,修复其字节序 bug:
 * 旧版 `if (proto != 0x0800)` 在小端 arm64 上恒真(skb->protocol 是网络序,
 * 读出 0x0008),每个 IPv4 包都在首行提前返回,打标逻辑从未执行过。
 *
 * 挂载在 clsact ingress pref 1(AOSP tether offload filter 之前),
 * 按源 IP 查 map 给 skb->mark 预设限速标记。
 *
 * map value 语义(与分叉版的关键差异): 必须存【完整 mark】=
 * HNC_MARK_BASE(0x800000) + mark_id(1..99), 与 iptables HNC_MARK 链和
 * tc fw filter handle 用的值域一致(map 写者 clsact_ctl 负责换算)。
 * 分叉版若存裸 mark_id 会匹配不到任何 fw filter。
 *
 * map 用传统 bpf_map_def(SEC("maps")) 而非 BTF .maps: clsact_ctl 是裸
 * syscall 迷你加载器(无 libelf), 传统风格可直接从 ELF 节读 map 参数。
 */

#include "vmlinux_clsact.h"

char LICENSE[] SEC("license") = "GPL";

/* source IP (u32, network byte order) → full tc mark (u32)
 * 由 clsact_ctl 加载时创建并 pin 到 /sys/fs/bpf/hnc/ip_mark_map,
 * update/sync 子命令刷新内容。 */
struct bpf_map_def SEC("maps") ip_mark_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = 4,
    .value_size  = 4,
    .max_entries = 256,   /* max 256 concurrent hotspot clients */
};

SEC("tc")
int hnc_clsact_ingress(struct __sk_buff *skb)
{
	/* skb->protocol 是网络序 —— 必须 bpf_htons 后再比较 */
	__u16 proto = skb->protocol;
	if (proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* IP 头在以太网头(14B)之后; src 在 IP 头 offset 12 */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + 14 > data_end)
		return TC_ACT_OK;

	struct iphdr *iph = data + 14;
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;

	if (iph->version != 4 || iph->ihl < 5)
		return TC_ACT_OK;

	__u32 src_ip = iph->saddr;  /* network byte order */

	__u32 *mark = bpf_map_lookup_elem(&ip_mark_map, &src_ip);
	if (mark && *mark != 0) {
		skb->mark = *mark;
	}

	return TC_ACT_OK;
}
