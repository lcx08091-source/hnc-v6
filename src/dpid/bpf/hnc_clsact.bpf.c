// SPDX-License-Identifier: GPL-2.0
/* hnc_clsact.bpf.c — HNC Dual-Stack Bidirectional clsact BPF program
 *
 * Verifier hardened for Linux 5.10 / 5.15 / 6.1 / 6.6 (arm64 + armv7):
 *   - Strict __always_inline helpers (no BPF-to-BPF .text relocations).
 *   - Zero void* arithmetic (-Wpointer-arith / ISO C11 clean).
 *   - 2-byte aligned packet reads (safe on armv7 NET_IP_ALIGN=2 without
 *     CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS).
 *   - Constant-offset 2-layer VLAN (802.1Q / 802.1ad QinQ) header unwrap.
 *   - Bounded 4-layer IPv6 extension header walker exempting ICMPv6 NDP/MLD
 *     control packets (types 130..137, 143) so rate-limited clients never drop
 *     Neighbor Solicitation / Advertisement or MLDv2 (Hop-by-Hop) under load.
 */

#include "vmlinux_clsact.h"

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") ip_mark_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = 4,
    .value_size  = 4,
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") mac_mark_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct mac_key),
    .value_size  = 4,
    .max_entries = 256,
};

static __always_inline void copy_mac_key(struct mac_key *key, const __u8 *addr)
{
    /* Ethernet dst/src offsets (0 and 6) are always 2-byte aligned regardless
     * of NET_IP_ALIGN (0 on arm64/x86, 2 on armv7). Using three u16 copies
     * avoids 4-byte unaligned packet loads on strict-alignment 32-bit ARM. */
    const __u16 *src = (const __u16 *)addr;
    __u16 *dst = (__u16 *)key->mac;
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    key->pad = 0;
}

/* Walk up to 4 IPv6 extension headers (HBH, Routing, Fragment, DestOpts, AH)
 * and return 1 if the packet is an ICMPv6 NDP/MLD control frame (130..137, 143)
 * that must not be throttled or dropped in a congested client HTB leaf. */
static __always_inline int is_ipv6_ndp_ctrl(struct __sk_buff *skb, __u32 l3_off)
{
    __u32 base_off = l3_off & 0x3eU;
    __u32 pull_v6 = (base_off + 40U) & 0x7fU;
    const __u8 *data = (const __u8 *)(long)skb->data;
    const __u8 *data_end = (const __u8 *)(long)skb->data_end;
    const __u8 *v6h = data + base_off;

    if (v6h + 40 > data_end) {
        if (skb->len < pull_v6 || bpf_skb_pull_data(skb, pull_v6) < 0)
            return 0;
        data = (const __u8 *)(long)skb->data;
        data_end = (const __u8 *)(long)skb->data_end;
        v6h = data + base_off;
        if (v6h + 40 > data_end)
            return 0;
    }

    if ((v6h[0] >> 4) != 6)
        return 0;

    __u8 nexthdr = v6h[6];
    if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)
        return 0;

    __u32 cur_off = base_off + 40U;

#ifdef __clang__
#pragma unroll
#else
#pragma GCC unroll 4
#endif
    for (int i = 0; i < 4; i++) {
        if (nexthdr == IPPROTO_ICMPV6)
            break;
        if (nexthdr != IPPROTO_HOPOPTS &&
            nexthdr != IPPROTO_ROUTING &&
            nexthdr != IPPROTO_FRAGMENT &&
            nexthdr != IPPROTO_DSTOPTS &&
            nexthdr != IPPROTO_AH)
            return 0;

        __u32 safe_off = cur_off & 0x1ffU;
        const __u8 *ext = data + safe_off;
        if (ext + 8 > data_end) {
            __u32 need = safe_off + 8U;
            if (skb->len < need || bpf_skb_pull_data(skb, need) < 0)
                return 0;
            data = (const __u8 *)(long)skb->data;
            data_end = (const __u8 *)(long)skb->data_end;
            ext = data + safe_off;
            if (ext + 8 > data_end)
                return 0;
        }

        __u8 nh = ext[0];
        __u32 hdrlen;
        if (nexthdr == IPPROTO_FRAGMENT) {
            /* Non-initial IPv6 fragment (offset bits 15..3 != 0) has no L4 hdr */
            if (ext[2] != 0 || (ext[3] & 0xF8U) != 0)
                return 0;
            hdrlen = 8U;
        } else if (nexthdr == IPPROTO_AH) {
            hdrlen = ((__u32)ext[1] + 2U) * 4U;
        } else {
            hdrlen = ((__u32)ext[1] + 1U) * 8U;
        }
        if (hdrlen < 8U || hdrlen > 64U)
            return 0;

        cur_off = safe_off + hdrlen;
        nexthdr = nh;
    }

    if (nexthdr != IPPROTO_ICMPV6)
        return 0;

    __u32 icmp_off = cur_off & 0x1ffU;
    const __u8 *icmp6 = data + icmp_off;
    if (icmp6 + 2 > data_end) {
        __u32 need = icmp_off + 2U;
        if (skb->len < need || bpf_skb_pull_data(skb, need) < 0)
            return 0;
        data = (const __u8 *)(long)skb->data;
        data_end = (const __u8 *)(long)skb->data_end;
        icmp6 = data + icmp_off;
        if (icmp6 + 2 > data_end)
            return 0;
    }

    __u8 type = icmp6[0];
    if ((type >= 130 && type <= 137) || type == 143)
        return 1;
    return 0;
}

/* Constant-offset L2 + 2-deep VLAN (802.1Q / 802.1ad) parser.
 * Saves MAC key onto stack before any VLAN pull_data can invalidate data. */
static __always_inline int parse_l2_hdr(struct __sk_buff *skb, int use_src_mac,
                                        struct mac_key *out_mac,
                                        __u16 *out_proto, __u32 *out_l3_off)
{
    __u32 proto = skb->protocol;
    if (proto != bpf_htons(ETH_P_IP) &&
        proto != bpf_htons(ETH_P_IPV6) &&
        proto != bpf_htons(ETH_P_8021Q) &&
        proto != bpf_htons(ETH_P_8021AD))
        return -1;

    const __u8 *data = (const __u8 *)(long)skb->data;
    const __u8 *data_end = (const __u8 *)(long)skb->data_end;
    if (data + 14 > data_end) {
        if (skb->len < 14 || bpf_skb_pull_data(skb, 14) < 0)
            return -1;
        data = (const __u8 *)(long)skb->data;
        data_end = (const __u8 *)(long)skb->data_end;
        if (data + 14 > data_end)
            return -1;
    }

    copy_mac_key(out_mac, use_src_mac ? (data + 6) : data);

    __u16 h_proto = *(const __u16 *)(data + 12);
    __u32 l3_off = 14;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        if (data + 18 > data_end) {
            if (skb->len < 18 || bpf_skb_pull_data(skb, 18) < 0)
                return -1;
            data = (const __u8 *)(long)skb->data;
            data_end = (const __u8 *)(long)skb->data_end;
            if (data + 18 > data_end)
                return -1;
        }
        h_proto = *(const __u16 *)(data + 16);
        l3_off = 18;

        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            if (data + 22 > data_end) {
                if (skb->len < 22 || bpf_skb_pull_data(skb, 22) < 0)
                    return -1;
                data = (const __u8 *)(long)skb->data;
                data_end = (const __u8 *)(long)skb->data_end;
                if (data + 22 > data_end)
                    return -1;
            }
            h_proto = *(const __u16 *)(data + 20);
            l3_off = 22;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
        return -1;

    *out_proto = h_proto;
    *out_l3_off = l3_off;
    return 0;
}

SEC("tc")
int hnc_clsact_ingress(struct __sk_buff *skb)
{
    struct mac_key key = { .pad = 0 };
    __u16 h_proto = 0;
    __u32 l3_off = 14;

    if (parse_l2_hdr(skb, 1, &key, &h_proto, &l3_off) < 0)
        return TC_ACT_OK;

    if (h_proto == bpf_htons(ETH_P_IPV6) && is_ipv6_ndp_ctrl(skb, l3_off))
        return TC_ACT_OK;

    __u32 *m_mac = bpf_map_lookup_elem(&mac_mark_map, &key);
    if (m_mac && *m_mac != 0) {
        skb->mark = (skb->mark & ~0x00ffffffU) | (*m_mac & 0x00ffffffU);
        return TC_ACT_OK;
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        __u32 ip_off = l3_off & 0x3eU;
        __u32 need = ip_off + 20U;
        const __u8 *data = (const __u8 *)(long)skb->data;
        const __u8 *data_end = (const __u8 *)(long)skb->data_end;
        const __u8 *nh = data + ip_off;

        if (nh + 20 > data_end) {
            if (skb->len < need || bpf_skb_pull_data(skb, need) < 0)
                return TC_ACT_OK;
            data = (const __u8 *)(long)skb->data;
            data_end = (const __u8 *)(long)skb->data_end;
            nh = data + ip_off;
            if (nh + 20 > data_end)
                return TC_ACT_OK;
        }

        /* Byte 0 of IPv4 header is always (version << 4) | ihl on wire;
         * reading nh[0] avoids 4-byte struct iphdr alignment UB at L2+14/22. */
        __u8 ver_ihl = nh[0];
        if ((ver_ihl >> 4) != 4 || (ver_ihl & 0x0fU) < 5)
            return TC_ACT_OK;

        __u32 src_ip = 0;
        const __u16 *sip = (const __u16 *)(nh + 12);
        __u16 *dip = (__u16 *)&src_ip;
        dip[0] = sip[0];
        dip[1] = sip[1];

        __u32 *m_ip = bpf_map_lookup_elem(&ip_mark_map, &src_ip);
        if (m_ip && *m_ip != 0)
            skb->mark = (skb->mark & ~0x00ffffffU) | (*m_ip & 0x00ffffffU);
    }

    return TC_ACT_OK;
}

SEC("tc_egress")
int hnc_clsact_egress(struct __sk_buff *skb)
{
    if ((skb->mark & 0x00800000U) != 0)
        return TC_ACT_OK;

    struct mac_key key = { .pad = 0 };
    __u16 h_proto = 0;
    __u32 l3_off = 14;

    if (parse_l2_hdr(skb, 0, &key, &h_proto, &l3_off) < 0)
        return TC_ACT_OK;

    if (h_proto == bpf_htons(ETH_P_IPV6) && is_ipv6_ndp_ctrl(skb, l3_off))
        return TC_ACT_OK;

    __u32 *m_mac = bpf_map_lookup_elem(&mac_mark_map, &key);
    if (m_mac && *m_mac != 0)
        skb->mark = (skb->mark & ~0x00ffffffU) | (*m_mac & 0x00ffffffU);

    return TC_ACT_OK;
}
