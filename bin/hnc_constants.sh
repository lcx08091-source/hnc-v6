#!/system/bin/sh
# hnc_constants.sh — HNC v5.40.0 全局统一 32 位正交 skb->mark 位域契约
#
# 位域分配 (必须与 Go / C / eBPF 100% 严丝合缝对齐):
#   [15:0]  0x0000ffff : Android netd netId 与网络权限位 —— 100% 严禁触碰!
#   [23:16] 0x00ff0000 : 客户端设备 ID 段 (HNC_MARK_BASE=0x00800000, mid 1..99 -> 0x00800000 | (mid << 16))
#   [25:24] 0x03000000 : 设备内三档 app_qos 段 (Tier1=0x01000000, Tier2=0x00000000, Tier3=0x03000000)
#   [31:26] 0xfc000000 : 设备内单应用限速 app_limits 槽位段 (slot 1..63 -> (slot << 26))
#   [31:16] 0xffff0000 : CONNMARK 保存与恢复总掩码

HNC_NETD_MASK=0x0000ffff

HNC_MARK_BASE=0x00800000
HNC_MARK_MASK=0x00ff0000
HNC_MARK_SHIFT=16

HNC_QOS_MASK=0x03000000
HNC_QOS_SHIFT=24
HNC_QOS_TIER1=0x01000000
HNC_QOS_TIER2=0x00000000
HNC_QOS_TIER3=0x03000000

HNC_APPLIM_MASK=0xfc000000
HNC_APPLIM_SHIFT=26

HNC_CONNMARK_MASK=0xffff0000

# 输入设备 mid (1..99), 输出标准 8 位小写十六进制设备 mark (如 mid=1 -> 0x00810000, mid=59 -> 0x00bb0000)
hnc_dev_mark_hex() {
    local _mid="${1:-0}"
    case "$_mid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$_mid" -lt 1 ] || [ "$_mid" -gt 99 ]; then
        return 1
    fi
    printf '0x%08x\n' $(( 0x00800000 | (_mid << 16) ))
}

# 输入单应用限速槽位 slot (1..63), 输出标准 8 位小写十六进制应用 mark (如 slot=1 -> 0x04000000)
hnc_applim_mark_hex() {
    local _slot="${1:-0}"
    case "$_slot" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$_slot" -lt 1 ] || [ "$_slot" -gt 63 ]; then
        return 1
    fi
    printf '0x%02x000000\n' $(( (_slot & 63) << 2 ))
}

# 从 iptables -L/-S 输出的 mark 令牌解析 mid (1..99), 同时兼容:
#   - v5.40+ 新编码: 0x00810000, 0x810000/0xff0000, 0x05851234 (复合打标)
#   - v5.38- 旧编码: 0x800001, 0x80003b/0xffffffff
hnc_parse_mid_from_mark() {
    local _raw="${1:-}"
    _raw="${_raw%%/*}"
    [ -n "$_raw" ] || return 1
    awk -v s="$_raw" 'BEGIN {
        s = tolower(s)
        gsub(/[^0-9a-fx]/, "", s)
        if (s == "") exit 1
        if (s ~ /^0x/) {
            hex = substr(s, 3)
            val = 0
            for (i = 1; i <= length(hex); i++) {
                c = substr(hex, i, 1)
                d = index("0123456789abcdef", c) - 1
                if (d < 0) exit 1
                val = val * 16 + d
            }
        } else if (s ~ /^[0-9]+$/) {
            val = s + 0
        } else {
            exit 1
        }
        # 优先解析 [23:16] 新正交段: 0x81..0xe3 (0x80 + 1..99)
        seg = int(val / 65536) % 256
        if (seg > 128 && seg <= 227) {
            print seg - 128
            exit 0
        }
        # 兼容旧编码 0x800000 + mid (seg == 128, 低 16 位为 1..99)
        low16 = val % 65536
        if (seg == 128 && low16 >= 1 && low16 <= 99) {
            print low16
            exit 0
        }
        exit 1
    }'
}
