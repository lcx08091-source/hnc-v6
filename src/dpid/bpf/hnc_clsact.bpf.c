// SPDX-License-Identifier: GPL-2.0
/* hnc_clsact.bpf.c — HNC v6.1 Vector Dual-Stack Bidirectional clsact BPF program
 *
 * Verifier hardened for Linux 5.10 / 5.15 / 6.1 / 6.6 (arm64 + armv7):
 *   - Strict __always_inline helpers (no BPF-to-BPF .text relocations).
 *   - Zero void* arithmetic (-Wpointer-arith / ISO C11 clean).
 *   - 1-byte / 2-byte aligned packet reads (safe on armv7 NET_IP_ALIGN=2 without
 *     CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS).
 *   - Constant-offset 2-layer VLAN (802.1Q / 802.1ad QinQ) header unwrap;
 *     ARP (ETH_P_ARP 0x0806) and non-IP/IPv6 frames immediately exempted.
 *   - Bounded 4-layer IPv6 extension header walker exempting ICMPv6 NDP/RA/MLDv2
 *     control packets (types 130..137, 143) so rate-limited clients never drop
 *     Router/Neighbor Solicitation/Advertisement or MLDv2 under load.
 *   - Per-device slot PERCPU telemetry map (dev_stats_map: rx_bytes / tx_bytes /
 *     packets) indexed by slot mid = (mark >> 16) & 0x7f.
 *   - Pre-IFB uplink realtime game/voice fast-lane promotion on clsact ingress
 *     BEFORE prio 2 matchall->mirred (ifb0): promotes DSCP EF/VA/CS5 and small
 *     bidirectional symmetric / game UDP payloads (strictly excluding DHCP, DNS,
 *     mDNS, NTP, QUIC-443/80) via skb->priority = 6 and HNC_QOS_TIER1 [25:24],
 *     preserving [15:0] Android netd netId, [23:16] device mid, and [31:26] app_limit.
 *   - Always returns TC_ACT_UNSPEC (-1) after marking so clsact continues
 *     evaluating prio 2 matchall->mirred (ifb0) or police filters.
 */

#include "vmlinux_clsact.h"

#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

#define HNC_MARK_QOS_MASK    0x03000000U
#define HNC_MARK_QOS_TIER1   0x01000000U
#define HNC_MARK_APPLIM_MASK 0xfc000000U
#define HNC_TC_PRIO_RT       6U
#define HNC_DEV_SLOTS_MAX    128U

/* DSCP values (top 6 bits of IPv4 TOS / IPv6 Traffic Class) */
#define HNC_DSCP_CS5 40U
#define HNC_DSCP_VA  44U
#define HNC_DSCP_EF  46U
#define HNC_DSCP_CS6 48U

struct dev_stats_val {
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 packets;
} __attribute__((aligned(8)));

_Static_assert(sizeof(__u32) == 4U && _Alignof(__u32) == 4U,
               "ip_mark_map / dev_stats_map 32-bit key/value size and alignment mismatch");
_Static_assert(sizeof(struct mac_key) == 8U && _Alignof(struct mac_key) >= 2U &&
               __builtin_offsetof(struct mac_key, pad) == 6U,
               "mac_mark_map key struct layout mismatch");
_Static_assert(sizeof(struct dev_stats_val) == 24U && _Alignof(struct dev_stats_val) == 8U &&
               __builtin_offsetof(struct dev_stats_val, tx_bytes) == 8U &&
               __builtin_offsetof(struct dev_stats_val, packets) == 16U,
               "dev_stats_map value struct 8-byte alignment mismatch");

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

struct bpf_map_def SEC("maps") dev_stats_map = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct dev_stats_val),
    .max_entries = HNC_DEV_SLOTS_MAX,
};

static __always_inline const __u8 *skb_data_ptr(const struct __sk_buff *skb)
{
    return (const __u8 *)(long)(*(const volatile __u32 *)&skb->data);
}

static __always_inline const __u8 *skb_data_end_ptr(const struct __sk_buff *skb)
{
    return (const __u8 *)(long)(*(const volatile __u32 *)&skb->data_end);
}

/* Byte-wise wire readers preserving network byte representation in memory
 * (matches bpf_htons() and inet_pton() map keys without any pointer casts or
 * unaligned multi-byte loads on strict-alignment 32-bit ARMv7). */
static __always_inline __u16 load_wire_u16(const __u8 *p)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (__u16)(((__u16)p[0]) | ((__u16)p[1] << 8));
#else
    return (__u16)(((__u16)p[0] << 8) | ((__u16)p[1]));
#endif
}

static __always_inline __u32 load_wire_u32(const __u8 *p)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((__u32)p[0]) |
           ((__u32)p[1] << 8) |
           ((__u32)p[2] << 16) |
           ((__u32)p[3] << 24);
#else
    return ((__u32)p[0] << 24) |
           ((__u32)p[1] << 16) |
           ((__u32)p[2] << 8) |
           ((__u32)p[3]);
#endif
}

static __always_inline void copy_mac_key(struct mac_key *key, const __u8 *addr)
{
    key->mac[0] = addr[0];
    key->mac[1] = addr[1];
    key->mac[2] = addr[2];
    key->mac[3] = addr[3];
    key->mac[4] = addr[4];
    key->mac[5] = addr[5];
    key->pad = 0;
}

static __always_inline void account_dev_stats(struct __sk_buff *skb, __u32 mark_val, int is_rx)
{
    __u32 dev_bits = mark_val & HNC_MARK_DEV_MASK;
    if ((dev_bits & HNC_MARK_DEV_VALID) == 0U)
        return;

    __u32 slot = (dev_bits >> 16) & 0x7fU;
    if (slot == 0U || slot >= HNC_DEV_SLOTS_MAX)
        return;

    struct dev_stats_val *st = bpf_map_lookup_elem(&dev_stats_map, &slot);
    if (!st)
        return;

    if (is_rx)
        st->rx_bytes += (__u64)skb->len;
    else
        st->tx_bytes += (__u64)skb->len;
    st->packets += 1ULL;
}

static __always_inline int is_excluded_ctrl_or_bulk_udp(__u16 sp, __u16 dp)
{
    /* Never promote DHCPv4/v6, DNS/DoT/DoQ/mDNS/LLMNR, NTP, SNMP, NetBIOS,
     * SSDP, or HTTP/3 QUIC (80/443). */
    if (sp == 53U || dp == 53U ||
        sp == 67U || dp == 67U || sp == 68U || dp == 68U ||
        sp == 546U || dp == 546U || sp == 547U || dp == 547U ||
        sp == 80U || dp == 80U || sp == 443U || dp == 443U ||
        sp == 123U || dp == 123U || sp == 161U || dp == 161U ||
        sp == 137U || dp == 137U || sp == 138U || dp == 138U ||
        sp == 853U || dp == 853U || sp == 1900U || dp == 1900U ||
        sp == 5353U || dp == 5353U || sp == 5355U || dp == 5355U)
        return 1;
    return 0;
}

static __always_inline int is_realtime_udp_ports(__u16 sp, __u16 dp, __u32 pkt_len)
{
    if (sp < 1024U || dp < 1024U)
        return 0;
    if (is_excluded_ctrl_or_bulk_udp(sp, dp))
        return 0;

    /* 1. Well-known real-time mobile MOBA / FPS / VoIP / WebRTC STUN-RTP bands */
    if ((dp >= 3478U && dp <= 3481U) ||
        (dp >= 5000U && dp <= 5550U) ||
        (dp >= 7000U && dp <= 8100U) ||
        (dp >= 9000U && dp <= 10100U) ||
        (dp >= 17000U && dp <= 18100U) ||
        (dp >= 22101U && dp <= 22102U) ||
        (dp >= 27015U && dp <= 27050U) ||
        (dp >= 30000U && dp <= 30500U))
        return 1;

    /* 2. Small-payload bidirectional symmetric UDP port signature */
    if (pkt_len >= 46U && pkt_len <= 256U) {
        if (sp == dp)
            return 1;
        if ((sp >> 10) == (dp >> 10))
            return 1;
        if (sp >= 10000U && dp >= 10000U && pkt_len <= 220U)
            return 1;
    }

    return 0;
}

static __always_inline void apply_realtime_uplink_boost(struct __sk_buff *skb)
{
    skb->priority = HNC_TC_PRIO_RT;
    /* Only set [25:24] Tier-1 mark if [31:26] per-app limit slot is unset,
     * preserving [15:0] netd netId and [23:16] per-device slot untouched. */
    if ((skb->mark & HNC_MARK_APPLIM_MASK) == 0U)
        skb->mark = (skb->mark & ~HNC_MARK_QOS_MASK) | HNC_MARK_QOS_TIER1;
}

/* Pre-classify uplink realtime game/voice frames on clsact ingress BEFORE
 * prio 2 matchall->mirred redirects the skb to ifb0 (which runs ahead of
 * Netfilter PREROUTING/FORWARD). */
static __always_inline void promote_uplink_realtime_pkt(struct __sk_buff *skb,
                                                        __u16 h_proto,
                                                        __u32 l3_off)
{
    __u32 pkt_len = skb->len;
    if (pkt_len > 576U)
        return;

    __u32 base_off = l3_off & 0x3eU;
    const __u8 *data = skb_data_ptr(skb);
    const __u8 *data_end = skb_data_end_ptr(skb);

    if (h_proto == bpf_htons(ETH_P_IP)) {
        const __u8 *nh = data + base_off;
        if (nh + 20 > data_end) {
            __u32 need = (base_off + 20U) & 0x7fU;
            if (pkt_len < need || bpf_skb_pull_data(skb, need) < 0)
                return;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            nh = data + base_off;
            if (nh + 20 > data_end)
                return;
        }

        __u8 ver_ihl = nh[0];
        if ((ver_ihl >> 4) != 4)
            return;
        __u32 ihl_bytes = ((__u32)(ver_ihl & 0x0fU)) * 4U;
        if (ihl_bytes < 20U || ihl_bytes > 60U)
            return;

        __u8 dscp = nh[1] >> 2;
        __u8 proto = nh[9];
        /* Non-first IPv4 fragments carry no UDP port header */
        __u16 frag = ((__u16)nh[6] << 8) | (__u16)nh[7];
        if ((frag & 0x1fffU) != 0U)
            return;

        if (dscp == HNC_DSCP_EF || dscp == HNC_DSCP_VA ||
            dscp == HNC_DSCP_CS5 || dscp == HNC_DSCP_CS6) {
            if (proto != IPPROTO_UDP) {
                apply_realtime_uplink_boost(skb);
                return;
            }
        }

        if (proto != IPPROTO_UDP || pkt_len > 320U)
            return;

        __u32 udp_off = (base_off + ihl_bytes) & 0x7fU;
        const __u8 *uh = data + udp_off;
        if (uh + 8 > data_end) {
            __u32 need_u = (udp_off + 8U) & 0xffU;
            if (pkt_len < need_u || bpf_skb_pull_data(skb, need_u) < 0)
                return;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            uh = data + udp_off;
            if (uh + 8 > data_end)
                return;
        }

        __u16 sp = ((__u16)uh[0] << 8) | (__u16)uh[1];
        __u16 dp = ((__u16)uh[2] << 8) | (__u16)uh[3];
        if (is_excluded_ctrl_or_bulk_udp(sp, dp))
            return;

        if (dscp == HNC_DSCP_EF || dscp == HNC_DSCP_VA ||
            dscp == HNC_DSCP_CS5 || dscp == HNC_DSCP_CS6 ||
            is_realtime_udp_ports(sp, dp, pkt_len)) {
            apply_realtime_uplink_boost(skb);
        }
        return;
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        const __u8 *v6h = data + base_off;
        if (v6h + 40 > data_end) {
            __u32 need6 = (base_off + 40U) & 0x7fU;
            if (pkt_len < need6 || bpf_skb_pull_data(skb, need6) < 0)
                return;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            v6h = data + base_off;
            if (v6h + 40 > data_end)
                return;
        }

        if ((v6h[0] >> 4) != 6)
            return;

        __u8 dscp6 = ((v6h[0] & 0x0fU) << 2) | (v6h[1] >> 6);
        __u8 nh6 = v6h[6];

        if (nh6 != IPPROTO_UDP) {
            if (dscp6 == HNC_DSCP_EF || dscp6 == HNC_DSCP_VA ||
                dscp6 == HNC_DSCP_CS5 || dscp6 == HNC_DSCP_CS6) {
                apply_realtime_uplink_boost(skb);
            }
            return;
        }

        if (pkt_len > 340U)
            return;

        __u32 udp6_off = (base_off + 40U) & 0x7fU;
        const __u8 *uh6 = data + udp6_off;
        if (uh6 + 8 > data_end) {
            __u32 need_u6 = (udp6_off + 8U) & 0xffU;
            if (pkt_len < need_u6 || bpf_skb_pull_data(skb, need_u6) < 0)
                return;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            uh6 = data + udp6_off;
            if (uh6 + 8 > data_end)
                return;
        }

        __u16 sp6 = ((__u16)uh6[0] << 8) | (__u16)uh6[1];
        __u16 dp6 = ((__u16)uh6[2] << 8) | (__u16)uh6[3];
        if (is_excluded_ctrl_or_bulk_udp(sp6, dp6))
            return;

        if (dscp6 == HNC_DSCP_EF || dscp6 == HNC_DSCP_VA ||
            dscp6 == HNC_DSCP_CS5 || dscp6 == HNC_DSCP_CS6 ||
            is_realtime_udp_ports(sp6, dp6, pkt_len)) {
            apply_realtime_uplink_boost(skb);
        }
    }
}

static __always_inline int apply_dev_mark_and_stats(struct __sk_buff *skb,
                                                    __u32 mark_val,
                                                    int is_rx,
                                                    __u16 h_proto,
                                                    __u32 l3_off)
{
    if (mark_val == HNC_MARK_DROP)
        return TC_ACT_SHOT;
    if ((mark_val & HNC_MARK_DEV_MASK) != 0U) {
        skb->mark = (skb->mark & ~HNC_MARK_DEV_MASK) | (mark_val & HNC_MARK_DEV_MASK);
        account_dev_stats(skb, mark_val, is_rx);
    }
    if (is_rx)
        promote_uplink_realtime_pkt(skb, h_proto, l3_off);
    return TC_ACT_UNSPEC;
}

/* Walk up to 4 IPv6 extension headers (HBH, Routing, Fragment, DestOpts, AH)
 * and return 1 if the packet is an ICMPv6 NDP/RA/MLDv2 control frame (130..137, 143)
 * that must not be throttled or dropped in a congested client HTB leaf. */
static __always_inline int is_ipv6_ndp_ctrl(struct __sk_buff *skb, __u32 l3_off)
{
    __u32 base_off = l3_off & 0x3eU;
    const __u8 *data = skb_data_ptr(skb);
    const __u8 *data_end = skb_data_end_ptr(skb);
    const __u8 *v6h = data + base_off;

    if (v6h + 40 > data_end) {
        __u32 pull_v6 = (base_off + 40U) & 0x7fU;
        if (skb->len < pull_v6 || bpf_skb_pull_data(skb, pull_v6) < 0)
            return 0;
        data = skb_data_ptr(skb);
        data_end = skb_data_end_ptr(skb);
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
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
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
        data = skb_data_ptr(skb);
        data_end = skb_data_end_ptr(skb);
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
 * Rejects ARP (0x0806) and all non-IP/IPv6 EtherTypes immediately (-1 -> TC_ACT_UNSPEC).
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

    const __u8 *data = skb_data_ptr(skb);
    const __u8 *data_end = skb_data_end_ptr(skb);
    if (data + 14 > data_end) {
        if (skb->len < 14 || bpf_skb_pull_data(skb, 14) < 0)
            return -1;
        data = skb_data_ptr(skb);
        data_end = skb_data_end_ptr(skb);
        if (data + 14 > data_end)
            return -1;
    }

    copy_mac_key(out_mac, use_src_mac ? (data + 6) : data);

    __u16 h_proto = load_wire_u16(data + 12);
    __u32 l3_off = 14;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        if (data + 18 > data_end) {
            if (skb->len < 18 || bpf_skb_pull_data(skb, 18) < 0)
                return -1;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            if (data + 18 > data_end)
                return -1;
        }
        h_proto = load_wire_u16(data + 16);
        l3_off = 18;

        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            if (data + 22 > data_end) {
                if (skb->len < 22 || bpf_skb_pull_data(skb, 22) < 0)
                    return -1;
                data = skb_data_ptr(skb);
                data_end = skb_data_end_ptr(skb);
                if (data + 22 > data_end)
                    return -1;
            }
            h_proto = load_wire_u16(data + 20);
            l3_off = 22;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
        return -1;

    /* Validate L3 IPv4/IPv6 version nibble at l3_off before any mac_mark_map lookup */
    __u32 base_off = l3_off & 0x3eU;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        const __u8 *nh = data + base_off;
        if (nh + 20 > data_end) {
            __u32 need4 = (base_off + 20U) & 0x7fU;
            if (skb->len < need4 || bpf_skb_pull_data(skb, need4) < 0)
                return -1;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            nh = data + base_off;
            if (nh + 20 > data_end)
                return -1;
        }
        if ((nh[0] >> 4) != 4 || (nh[0] & 0x0fU) < 5U)
            return -1;
    } else {
        const __u8 *v6h = data + base_off;
        if (v6h + 40 > data_end) {
            __u32 need6 = (base_off + 40U) & 0x7fU;
            if (skb->len < need6 || bpf_skb_pull_data(skb, need6) < 0)
                return -1;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            v6h = data + base_off;
            if (v6h + 40 > data_end)
                return -1;
        }
        if ((v6h[0] >> 4) != 6)
            return -1;
    }

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
        return TC_ACT_UNSPEC;

    if (h_proto == bpf_htons(ETH_P_IPV6) && is_ipv6_ndp_ctrl(skb, l3_off))
        return TC_ACT_UNSPEC;

    __u32 *m_mac = bpf_map_lookup_elem(&mac_mark_map, &key);
    if (m_mac && *m_mac != 0)
        return apply_dev_mark_and_stats(skb, *m_mac, 1, h_proto, l3_off);

    if (h_proto == bpf_htons(ETH_P_IP)) {
        __u32 ip_off = l3_off & 0x3eU;
        const __u8 *data = skb_data_ptr(skb);
        const __u8 *data_end = skb_data_end_ptr(skb);
        const __u8 *nh = data + ip_off;

        if (nh + 20 > data_end) {
            __u32 need = ip_off + 20U;
            if (skb->len < need || bpf_skb_pull_data(skb, need) < 0)
                return TC_ACT_UNSPEC;
            data = skb_data_ptr(skb);
            data_end = skb_data_end_ptr(skb);
            nh = data + ip_off;
            if (nh + 20 > data_end)
                return TC_ACT_UNSPEC;
        }

        /* Byte 0 of IPv4 header is always (version << 4) | ihl on wire;
         * reading nh[0] avoids 4-byte struct iphdr alignment UB at L2+14/22. */
        __u8 ver_ihl = nh[0];
        if ((ver_ihl >> 4) != 4 || (ver_ihl & 0x0fU) < 5)
            return TC_ACT_UNSPEC;

        __u32 src_ip = load_wire_u32(nh + 12);

        __u32 *m_ip = bpf_map_lookup_elem(&ip_mark_map, &src_ip);
        if (m_ip && *m_ip != 0)
            return apply_dev_mark_and_stats(skb, *m_ip, 1, h_proto, l3_off);
    }

    /* Even for unmarked (unthrottled) gaming clients, promote realtime uplink
     * packets BEFORE ifb0 redirect so Vector Express 1:8010 prio 0 catches them! */
    promote_uplink_realtime_pkt(skb, h_proto, l3_off);
    return TC_ACT_UNSPEC;
}

SEC("tc_egress")
int hnc_clsact_egress(struct __sk_buff *skb)
{
    if (skb->mark == HNC_MARK_DROP)
        return TC_ACT_SHOT;

    if ((skb->mark & HNC_MARK_DEV_VALID) != 0) {
        account_dev_stats(skb, skb->mark, 0);
        return TC_ACT_UNSPEC;
    }

    struct mac_key key = { .pad = 0 };
    __u16 h_proto = 0;
    __u32 l3_off = 14;

    if (parse_l2_hdr(skb, 0, &key, &h_proto, &l3_off) < 0)
        return TC_ACT_UNSPEC;

    if (h_proto == bpf_htons(ETH_P_IPV6) && is_ipv6_ndp_ctrl(skb, l3_off))
        return TC_ACT_UNSPEC;

    __u32 *m_mac = bpf_map_lookup_elem(&mac_mark_map, &key);
    if (m_mac && *m_mac != 0)
        return apply_dev_mark_and_stats(skb, *m_mac, 0, h_proto, l3_off);

    return TC_ACT_UNSPEC;
}
