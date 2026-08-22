/* vmlinux_clsact.h — Minimal vmlinux types for clsact BPF program
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 * 只含 hnc_clsact.bpf.c 需要的最小类型定义,避免引入完整 vmlinux.h。
 * (回移自 5.9.91 分叉,补上其缺失的字节序宏——这正是分叉版字节序 bug 的根因)
 */
#ifndef __VMLINUX_CLSACT_H__
#define __VMLINUX_CLSACT_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;

/* TC return codes */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* ETH_P_IP */
#define ETH_P_IP 0x0800

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1

/* 字节序: eBPF tc 程序里 skb->protocol 是 __be16(网络序)。arm64 恒为小端,
 * 网络序 0x0800 的字节 08 00 以本机 u16 读出是 0x0008 —— 直接 != 0x0800
 * 比较恒真(分叉版 bug: 每个 IPv4 包都在首行被跳过,打标永不执行)。
 * 形态照抄 libbpf bpf_endian.h 的 __bpf_htons。 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#else
#define bpf_htons(x) (x)
#endif

/* 传统 map 定义结构(iproute2 风格, SEC("maps"))。
 * 不用 BTF .maps 风格的原因: 本仓库的 C 工具链没有可链接的 libelf/libz
 * (见 daemon/hotspotd/build.sh 的 v5.8.7 注释), clsact_ctl 是裸 syscall
 * 迷你加载器 —— 传统 map_def 让加载器直接从 ELF "maps" 节读参数,
 * 无需 BTF 解析。内核对所有版本都支持该风格。 */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_idx;
    __u32 numa_node;
};

/* struct __sk_buff — minimal definition for tc BPF programs */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
};

/* struct iphdr — minimal IPv4 header */
struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

/* BPF helper: map_lookup_elem (helper ID 1) */
extern void *bpf_map_lookup_elem(void *map, const void *key);

/* BPF map definition macros (normally from bpf_helpers.h) */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* SEC helper */
#define SEC(name) __attribute__((section(name), used))

#endif /* __VMLINUX_CLSACT_H__ */
