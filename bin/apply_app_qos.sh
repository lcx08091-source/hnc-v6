#!/system/bin/sh
# apply_app_qos.sh — HNC v5.30 T4: 应用感知 QoS 初版(默认关, 逐台开)
#
# 用法:
#   apply_app_qos.sh                         按 run/app_qos.plan 全量对齐(看门狗调)
#   apply_app_qos.sh teardown <iface> <mid>  只拆一台(tc_manager remove_device 调)
#
# 读:
#   run/app_qos.plan  —— Go 看门狗(src/dpid/cmd/hnc_watchdog/app_qos.go)按
#                        rules.json 的 devices[mac].app_qos + dpid 的
#                        run/ip_app_map.json(识别类别, 只读)生成:
#                          iface <热点网卡>
#                          dev <mark_id> <mac> <ip>
#                          ip <档位 1=实时 3=后台> <远端 IPv4>
#                        (交互档 = 默认, 不列; 认不出的连接自然进交互档)
# 写:
#   run/app_qos.state —— 每行 "<iface> <class_id>", tc_manager.sh 据此跳过这些
#                        class 的叶子操作; 没有设备开时删除。
#   run/app_qos.sig   —— 上次下发的计划签名(没变且子 class 都在 → 不重下发)。
#
# 结构(只做下行 = 热点网卡出方向; 上行在 ifb0 上, mirred 早于 iptables, 包上
# 还没有 mark, 按 mark 分档做不了):
#   class 1:<设备>(已有, rate R / ceil C, 不改 —— 设备总限速不变)
#     ├─ 1:<a000+mid*4+1>  实时  htb rate R×50% ceil C prio 0  叶子 fq_codel
#     ├─ 1:<a000+mid*4+2>  交互  htb rate R×35% ceil C prio 1  叶子 fq_codel
#     └─ 1:<a000+mid*4+3>  后台  htb rate R×15% ceil C prio 2  叶子 fq_codel
#   设备 class 上的过滤器(HTB 在内部节点上接着查):
#     prio 1  fw handle 0x200000/0x600000 → 实时; 0x600000/0x600000 → 后台
#     prio 9  u32 match u32 0 0(兜底)    → 交互
#   根上 pref 50  fw handle 0x800000+mid/0x9fffff → 设备 class(带档位位的包也能
#     进设备 class; 原有 pref 1 的 fw 是精确匹配)。
#   class 号段: 0xa004..0xa18f(设备 1:2..1:100、默认 1:9999=0x9999、应用限速
#     0x9001..0x9998 都不冲突); 叶子句柄 0xb004..0xb18f。
#
# mark 位分配(CONNMARK 掩码 0xffffff 内):
#   bit 0..6    mark_id(1..99)              设备(iptables_manager.sh)
#   bit 23      0x800000                    设备 mark 基数
#   bit 20      0x100000(0x900000 = 23+20)  应用限速(apply_app_limits.sh, 低 12 位为序号)
#   bit 21..22  0x600000                    本脚本: 档位(01 实时 / 11 后台; 00 = 交互)
#   本脚本只用 MARK --set-xmark <档位>/0x600000 改这两位, 不碰其它位的含义; 规则
#   挂在 mangle/POSTROUTING 末尾(HNC_SAVE 之后), 档位位不进 conntrack。
#   带应用限速位(bit 20)的包不打档位, 应用限速照旧。
#
# 关闭(默认): 看门狗发现没有设备开、也没有 run/app_qos.state 时根本不调本脚本;
# 本脚本在空计划 + 无状态时同样不发任何命令。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
PLAN="$RUN/app_qos.plan"
STATE="$RUN/app_qos.state"
SIG="$RUN/app_qos.sig"
LOG="$HNC_DIR/logs/app_qos.log"
TCM="$HNC_DIR/bin/tc_manager.sh"

CHAIN=HNC_APP_QOS
CHAIN_IP=HNC_APP_QOS_IP
TIER_MASK=0x600000
TIER_RT=0x200000
TIER_BG=0x600000
ROOT_PREF=50
INNER_PREF_FW=1
INNER_PREF_ALL=9

mkdir -p "$HNC_DIR/logs" "$RUN" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] $*" >> "$LOG" 2>/dev/null; }

# mark_id → 设备 class 号(与 tc_manager.sh _class_id_for_mark 一致: mid=1 → 100)
class_for_mid() { if [ "$1" = "1" ]; then echo 100; else printf '%d' "$1"; fi; }
# mark_id + 档位(1 实时 / 2 交互 / 3 后台)→ 子 class 次号(十六进制, 不带 0x)
child_minor() { printf '%x' $((0xa000 + $1 * 4 + $2)); }
leaf_major() { printf '%x' $((0xb000 + $1 * 4 + $2)); }
dev_mark() { printf '0x%x' $((0x800000 + $1)); }

# rate / ceil 文本(tc class show: 10Mbit / 512Kbit / 1Gbit / 64000bit)→ kbit 整数
to_kbit() {
    awk -v v="$1" 'BEGIN{
        n = v + 0; u = v; sub(/^[0-9.]+/, "", u); u = tolower(u)
        if (u ~ /^g/) k = n * 1000000; else if (u ~ /^m/) k = n * 1000; else if (u ~ /^k/) k = n; else k = n / 1000
        k = int(k + 0.5); if (k < 1) k = 1; print k }'
}

# 设备 class 的 rate / ceil(kbit), 输出 "R C"; class 不在返回 1
class_rate_ceil() {
    tc class show dev "$1" classid "1:$2" 2>/dev/null | awk '
        $1 == "class" { for (i = 1; i <= NF; i++) { if ($i == "rate") r = $(i+1); if ($i == "ceil") c = $(i+1) } }
        END { if (r == "") exit 1; if (c == "") c = r; print r, c }'
}

# 拆一台: 内部过滤器、3 个子 class(叶子随之删除)、根上 pref 50 的 fw。
teardown_dev() {
    local iface=$1 mid=$2 cid t
    cid=$(class_for_mid "$mid")
    tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    for t in 1 2 3; do
        tc class del dev "$iface" classid "1:$(child_minor "$mid" "$t")" 2>/dev/null || true
    done
    tc filter del dev "$iface" parent 1: pref "$ROOT_PREF" handle "$(dev_mark "$mid")" fw 2>/dev/null || true
    log "teardown $iface mid=$mid class=1:$cid"
}

# 子 class 都还在吗(看门狗 / restore 重建过 tc 树后会丢)
children_ok() {
    local iface=$1 mid=$2 out t
    out=$(tc class show dev "$iface" parent "1:$(class_for_mid "$mid")" 2>/dev/null)
    for t in 1 2 3; do
        echo "$out" | grep -q "class htb 1:$(child_minor "$mid" "$t") " || return 1
    done
    return 0
}

# 建一台: 子 class(rate 50/35/15, ceil = 父 ceil, prio 0/1/2)+ 叶子 + 过滤器。
build_dev() {
    local iface=$1 mid=$2 ip=$3 cid rc rate ceil rk t r p minor
    cid=$(class_for_mid "$mid")
    rc=$(class_rate_ceil "$iface" "$cid")
    if [ -z "$rc" ]; then
        # 没有限速 / 延迟规则的设备没有自己的 class → 让 tc_manager 建一个(不限速)
        sh "$TCM" ensure_class "$iface" "$mid" "$ip" >/dev/null 2>&1
        rc=$(class_rate_ceil "$iface" "$cid")
        [ -z "$rc" ] && { log "skip mid=$mid: no device class 1:$cid on $iface"; return 1; }
    fi
    rate=${rc% *}; ceil=${rc#* }
    rk=$(to_kbit "$rate")
    for t in 1 2 3; do
        case $t in 1) p=0; r=$((rk * 50 / 100)) ;; 2) p=1; r=$((rk * 35 / 100)) ;; *) p=2; r=$((rk * 15 / 100)) ;; esac
        [ "$r" -lt 1 ] && r=1
        minor=$(child_minor "$mid" "$t")
        tc class change dev "$iface" parent "1:$cid" classid "1:$minor" htb rate "${r}kbit" ceil "$ceil" prio "$p" 2>/dev/null \
            || tc class add dev "$iface" parent "1:$cid" classid "1:$minor" htb rate "${r}kbit" ceil "$ceil" prio "$p" 2>/dev/null \
            || { log "class 1:$minor add failed (mid=$mid)"; return 1; }
        tc qdisc replace dev "$iface" parent "1:$minor" handle "$(leaf_major "$mid" "$t"):" fq_codel 2>/dev/null \
            || tc qdisc replace dev "$iface" parent "1:$minor" handle "$(leaf_major "$mid" "$t"):" pfifo 2>/dev/null || true
    done
    tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null
    tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null
    tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null
    tc filter del dev "$iface" parent 1: pref "$ROOT_PREF" handle "$(dev_mark "$mid")" fw 2>/dev/null || true
    tc filter add dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$(dev_mark "$mid")/0x9fffff" fw flowid "1:$cid" 2>/dev/null
    log "built $iface mid=$mid class=1:$cid rate=$rate ceil=$ceil (50/35/15)"
    return 0
}

ipt_remove() {
    # 最多删 4 次(重复挂的跳转也清掉; 有上限, 不依赖 -D 失败来退出循环)
    for _i in 1 2 3 4; do iptables -t mangle -D POSTROUTING -j "$CHAIN" 2>/dev/null || break; done
    iptables -t mangle -F "$CHAIN" 2>/dev/null; iptables -t mangle -X "$CHAIN" 2>/dev/null
    iptables -t mangle -F "$CHAIN_IP" 2>/dev/null; iptables -t mangle -X "$CHAIN_IP" 2>/dev/null
    return 0
}

# iptables(IPv4): POSTROUTING 末尾 → HNC_APP_QOS(按设备 IP 选下行包, 跳过带应用
# 限速位的)→ HNC_APP_QOS_IP(按远端 IP 打档位位)。
ipt_build() {
    iptables -t mangle -N "$CHAIN" 2>/dev/null || iptables -t mangle -F "$CHAIN"
    iptables -t mangle -N "$CHAIN_IP" 2>/dev/null || iptables -t mangle -F "$CHAIN_IP"
    awk '$1 == "dev" && $4 != "" { print $4 }' "$PLAN" | while read -r ip; do
        iptables -t mangle -A "$CHAIN" -d "$ip" -m mark --mark 0x0/0x100000 -j "$CHAIN_IP"
    done
    awk '$1 == "ip" { print $2, $3 }' "$PLAN" | while read -r tier ip; do
        case "$tier" in 1) bits=$TIER_RT ;; 3) bits=$TIER_BG ;; *) continue ;; esac
        iptables -t mangle -A "$CHAIN_IP" -s "$ip" -j MARK --set-xmark "$bits/$TIER_MASK"
    done
    iptables -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null || iptables -t mangle -A POSTROUTING -j "$CHAIN"
}

# ─── teardown 子命令 ──────────────────────────────────────────────────
if [ "$1" = "teardown" ]; then
    [ -n "$2" ] && [ -n "$3" ] || exit 1
    teardown_dev "$2" "$3"
    cid=$(class_for_mid "$3")
    if [ -f "$STATE" ]; then
        grep -vx "$2 $cid" "$STATE" > "$STATE.tmp" 2>/dev/null
        if [ -s "$STATE.tmp" ]; then mv -f "$STATE.tmp" "$STATE"; else rm -f "$STATE.tmp" "$STATE" "$SIG"; fi
    fi
    exit 0
fi

# ─── 全量对齐 ─────────────────────────────────────────────────────────
IFACE=$(awk '$1 == "iface" { print $2; exit }' "$PLAN" 2>/dev/null)
NDEV=$(awk '$1 == "dev"' "$PLAN" 2>/dev/null | wc -l | tr -d ' ')
[ -n "$IFACE" ] || NDEV=0

# 关闭: 没有设备开、也没有残留状态 → 一条命令都不发
if [ "${NDEV:-0}" -eq 0 ] && [ ! -f "$STATE" ]; then
    exit 0
fi

# 计划没变且子 class 都在 → 不重下发(看门狗每 30 秒调一次)
NEWSIG=$(cksum < "$PLAN" 2>/dev/null | awk '{print $1 "-" $2}')
if [ "${NDEV:-0}" -gt 0 ] && [ -f "$STATE" ] && [ "$(cat "$SIG" 2>/dev/null)" = "$NEWSIG" ]; then
    _all_ok=1
    for _mid in $(awk '$1 == "dev" { print $2 }' "$PLAN"); do
        children_ok "$IFACE" "$_mid" || { _all_ok=0; break; }
    done
    [ "$_all_ok" = 1 ] && exit 0
fi

# 1) 新状态先落盘(tc_manager ensure_class 据此判断叶子归谁)
OLD_STATE=$(cat "$STATE" 2>/dev/null)
: > "$STATE.tmp"
awk '$1 == "dev" { print $2 }' "$PLAN" 2>/dev/null | while read -r mid; do
    echo "$IFACE $(class_for_mid "$mid")" >> "$STATE.tmp"
done
if [ -s "$STATE.tmp" ]; then
    mv -f "$STATE.tmp" "$STATE"
else
    rm -f "$STATE.tmp" "$STATE"
fi

# 2) 旧状态里有、新计划里没有(关了 / 换了网卡)→ 拆, 再让 tc_manager 按原设置补回
#    设备 class 的叶子(拆完它变回叶子, 内核只给了个 pfifo)
echo "$OLD_STATE" | while read -r s_if s_cid; do
    [ -n "$s_if" ] || continue
    grep -qx "$s_if $s_cid" "$STATE" 2>/dev/null && continue
    s_mid=$s_cid; [ "$s_cid" = "100" ] && s_mid=1
    teardown_dev "$s_if" "$s_mid"
    sh "$TCM" ensure_class "$s_if" "$s_mid" "" >/dev/null 2>&1 || true
done

# 3) 计划里的设备 → 建
awk '$1 == "dev" { print $2, $4 }' "$PLAN" 2>/dev/null | while read -r mid ip; do
    build_dev "$IFACE" "$mid" "$ip" || true
done

# 4) iptables
if [ -f "$STATE" ]; then
    ipt_build
    echo "$NEWSIG" > "$SIG"
else
    ipt_remove
    rm -f "$SIG"
fi
exit 0
