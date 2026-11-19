/* vmlinux_clsact.h — Minimal vmlinux types for clsact BPF program
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef __VMLINUX_CLSACT_H__
#define __VMLINUX_CLSACT_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;

/* TC return codes */
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

/* Orthogonal v5.40.0 skb->mark bitfields:
 *   [15:0]  0x0000ffffU : Reserved untouched for Android netd netId / permission bits
 *   [23:16] 0x00ff0000U : HNC per-device slot mark (0x00800000U | (mid << 16))
 *   [31:24] 0xff000000U : Reserved untouched for HNC App/QoS tier marks
 */
#define HNC_MARK_DEV_MASK   0x00ff0000U
#define HNC_MARK_DEV_VALID  0x00800000U
#define HNC_MARK_DROP       0xffffffffU

/* EtherTypes */
#ifndef ETH_P_IP
#define ETH_P_IP      0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6    0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q   0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD  0x88A8
#endif

/* IPv6 Next Header / IPPROTO numbers */
#define IPPROTO_HOPOPTS   0
#define IPPROTO_TCP       6
#define IPPROTO_UDP       17
#define IPPROTO_ROUTING   43
#define IPPROTO_FRAGMENT  44
#define IPPROTO_AH        51
#define IPPROTO_ICMPV6    58
#define IPPROTO_DSTOPTS   60

/* BPF map types */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#else
#error "Unknown __BYTE_ORDER__"
#endif

#ifndef __always_inline
#define __always_inline __inline __attribute__((always_inline))
#endif

/* Legacy iproute2-style map definition (parsed directly by clsact_ctl without libelf/BTF) */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_idx;
    __u32 numa_node;
};

/* 8-byte aligned L2 MAC key for dual-stack IPv4 + RFC 4941 IPv6 matching */
struct mac_key {
    __u8  mac[6];
    __u16 pad;
};

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

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

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl:4;
    __u8 version:4;
#else
    __u8 version:4;
    __u8 ihl:4;
#endif
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

/* Direct BPF helper IDs (const + unused avoids .data emission at -O0 and unused warnings) */
static void *(* const bpf_map_lookup_elem)(void *map, const void *key)
    __attribute__((unused)) = (void *)1;
static long (* const bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len)
    __attribute__((unused)) = (void *)39;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define SEC(name) __attribute__((section(name), used))

#endif /* __VMLINUX_CLSACT_H__ */
