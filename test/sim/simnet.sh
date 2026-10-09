#!/bin/bash
# test/sim/simnet.sh — 模拟设备: 在 Linux 开发机 / CI 上造一个「假热点」和若干台「假设备」,
# 不需要手机、不需要真的去连设备。只用于测试, 不进模块包(test/ 整个不打包)。
#
# 原理: 假热点 = 一个 Linux 网桥(默认 hncsim0, 网关 192.168.43.1/24, 和手机热点一样的网段);
# 每台假设备 = 一个独立的网络命名空间(netns), 用一对 veth 插在网桥上, 有自己的 MAC / IP。
# 假设备发包时, 内核的邻居表(ARP)里会真实出现它 —— hotspotd 读 /proc/net/arp + netlink、
# Go 的 neigh 包 dump 邻居表, 看到的都是真东西, 不是 mock。
# 「名字」: 手机上 hotspotd 从 `dumpsys network_stack` 的 DHCP 记录里取设备名; 这里用
# test/sim/fake/dumpsys 冒充, 它输出 $HNC_SIM_DIR/dhcp_events, add / ip 子命令往里追加记录
# (可以故意报 null / localhost 这种垃圾名)。
#
# 用法(要 root 和 iproute2; 也可以在 `unshare -rn` 出来的独立网络空间里跑, 不碰本机网络):
#   bash test/sim/simnet.sh up                          建假热点
#   bash test/sim/simnet.sh add NAME MAC IP [主机名]    加一台假设备并让它发一个包(邻居表里出现)
#   bash test/sim/simnet.sh poke NAME                   让它再发一个包(刷新邻居表, 像在用网)
#   bash test/sim/simnet.sh ip NAME 新IP [主机名]       换 IP(模拟 DHCP 重新分配)
#   bash test/sim/simnet.sh del NAME [--quiet]          拔掉这台设备; 默认网关再去找它一次,
#                                                       邻居表几秒后变 FAILED(--quiet 不找, 留成 STALE)
#   bash test/sim/simnet.sh list                        列出假设备和网关邻居表
#   bash test/sim/simnet.sh down                        全部拆掉
#   bash test/sim/simnet.sh hotspotd start|stop|log     在本机编译并跑 hotspotd(见 hotspotd_cmd 注释)
#
# NAME: 小写字母 / 数字, 1–10 个字符(veth 名字长度有限)。状态目录 $HNC_SIM_DIR(默认 /tmp/hnc_sim)。
set -u

SIM_IF=${HNC_SIM_IF:-hncsim0}
SIM_NET=${HNC_SIM_NET:-192.168.43}
SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}
NS_PREFIX=hncsim_
REPO=$(cd "$(dirname "$0")/../.." && pwd)

die() { echo "simnet: $*" >&2; exit 2; }

need_env() {
    [ "$(id -u)" = 0 ] || die "需要 root(或在 unshare -rn 里跑)"
    command -v ip >/dev/null 2>&1 || die "缺 iproute2(ip 命令)"
    # 手机上绝不跑: hotspotd 子命令会在私有挂载空间里盖住 /data/local/hnc, 网桥也会和真热点抢网段
    command -v getprop >/dev/null 2>&1 && die "这是给 Linux 开发机 / CI 用的, 不要在手机上跑"
    mkdir -p "$SIM_DIR" || die "建不了 $SIM_DIR"
    [ -f "$SIM_DIR/dhcp_events" ] || : > "$SIM_DIR/dhcp_events"
    [ -f "$SIM_DIR/devices" ] || : > "$SIM_DIR/devices"
}

valid_name() { case "$1" in ''|*[!a-z0-9]*) return 1 ;; esac; [ ${#1} -le 10 ]; }
valid_mac() { echo "$1" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; }
valid_ip() { echo "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; }

# 状态文件一行一台: NAME MAC IP [主机名]
dev_field() { awk -v n="$1" -v f="$2" '$1 == n { print $f; exit }' "$SIM_DIR/devices"; }
dev_set() {
    awk -v n="$1" '$1 != n' "$SIM_DIR/devices" > "$SIM_DIR/devices.tmp"
    [ -n "${2:-}" ] && echo "$2" >> "$SIM_DIR/devices.tmp"
    mv "$SIM_DIR/devices.tmp" "$SIM_DIR/devices"
}

# 冒充 NetworkStack 的 DHCP 事件行(格式见 daemon/hotspotd/hotspotd.c try_ns_dhcp_resolve 注释)
dhcp_event() {
    echo "$(date +%Y-%m-%dT%H:%M:%S) - [$SIM_IF.DHCP] Transmitting DhcpAckPacket with lease clientId: sim, hwAddr: $1, netAddr: $2/24, expTime: 3600,hostname: $3" >> "$SIM_DIR/dhcp_events"
}

cmd_up() {
    ip link show "$SIM_IF" >/dev/null 2>&1 || ip link add "$SIM_IF" type bridge || die "建不了网桥 $SIM_IF"
    ip link set "$SIM_IF" type bridge forward_delay 0 2>/dev/null
    # 网桥 MAC 必须钉死: 不钉时它取所有端口里最小的 MAC, 插新设备可能让它变 → 内核清空这块网卡的
    # 邻居表(neigh_changeaddr), 前面加的设备全从 ARP 表里消失。真热点网卡的 MAC 也是固定的。
    ip link set "$SIM_IF" address 02:00:00:43:00:01
    ip addr replace "$SIM_NET.1/24" dev "$SIM_IF" || die "设不了网关地址"
    ip link set "$SIM_IF" up
    echo "假热点 $SIM_IF 已就绪: 网关 $SIM_NET.1/24"
}

# 刚插上的 veth 头几百毫秒可能还没通(载波 / 网桥端口状态), 包会丢 —— 重发到网关邻居表里出现它为止(最多约 3 秒)
cmd_poke() {
    ns=$NS_PREFIX$1 addr=$(dev_field "$1" 3) i=0
    [ -n "$addr" ] || die "没有 $1"
    while [ $i -lt 15 ]; do
        ip netns exec "$ns" bash -c "echo hnc-sim > /dev/udp/$SIM_NET.1/9" 2>/dev/null || die "$1 发包失败"
        sleep 0.2
        ip neigh show "$addr" dev "$SIM_IF" 2>/dev/null | grep -q lladdr && return 0
        i=$((i + 1))
    done
    echo "simnet: $1($addr)发了包, 但网关邻居表里还没有它" >&2
    return 1
}

cmd_add() {
    name=$1 mac=$(echo "$2" | tr 'A-F' 'a-f') addr=$3 hn=${4:-}
    valid_name "$name" || die "名字只能是小写字母 / 数字, 最多 10 个字符: $name"
    valid_mac "$mac" || die "MAC 格式不对: $2"
    valid_ip "$addr" || die "IP 格式不对: $addr"
    [ -z "$(dev_field "$name" 1)" ] || die "$name 已存在"
    ip link show "$SIM_IF" >/dev/null 2>&1 || cmd_up >/dev/null
    ns=$NS_PREFIX$name
    ip netns add "$ns" || die "建不了 netns $ns"
    ip link add "hsv_$name" type veth peer name "hsp_$name" || die "建不了 veth"
    ip link set "hsp_$name" netns "$ns"
    ip -n "$ns" link set "hsp_$name" name eth0
    ip -n "$ns" link set eth0 address "$mac"
    ip -n "$ns" addr add "$addr/24" dev eth0
    ip -n "$ns" link set lo up
    ip -n "$ns" link set eth0 up
    ip -n "$ns" route add default via "$SIM_NET.1" 2>/dev/null
    ip link set "hsv_$name" master "$SIM_IF"
    ip link set "hsv_$name" up
    dev_set "$name" "$name $mac $addr $hn"
    [ -n "$hn" ] && dhcp_event "$mac" "$addr" "$hn"
    cmd_poke "$name"
    echo "加了 $name: $mac $addr${hn:+ 主机名 $hn}"
}

cmd_ip() {
    name=$1 new=$2 hn=${3:-}
    old=$(dev_field "$name" 3); mac=$(dev_field "$name" 2)
    [ -n "$old" ] || die "没有 $name"
    valid_ip "$new" || die "IP 格式不对: $new"
    ns=$NS_PREFIX$name
    ip -n "$ns" addr del "$old/24" dev eth0 2>/dev/null
    ip -n "$ns" addr add "$new/24" dev eth0 || die "设不了新 IP"
    ip -n "$ns" route replace default via "$SIM_NET.1" 2>/dev/null
    [ -n "$hn" ] || hn=$(dev_field "$name" 4)
    dev_set "$name" "$name $mac $new $hn"
    [ -n "$hn" ] && dhcp_event "$mac" "$new" "$hn"
    cmd_poke "$name"
    echo "$name: $old → $new"
}

cmd_del() {
    name=$1 quiet=${2:-}
    addr=$(dev_field "$name" 3)
    [ -n "$addr" ] || die "没有 $name"
    ip netns del "$NS_PREFIX$name" 2>/dev/null
    ip link del "hsv_$name" 2>/dev/null
    dev_set "$name" ""
    # 网关再找它一次 → 邻居表 DELAY → PROBE → 几秒后 FAILED(手机上设备走了以后, 有流量指向它时也是这样)
    [ "$quiet" = "--quiet" ] || bash -c "echo hnc-sim > /dev/udp/$addr/9" 2>/dev/null
    echo "拔掉了 $name($addr)"
}

cmd_list() {
    echo "== 假设备($SIM_DIR/devices)"; cat "$SIM_DIR/devices"
    echo "== $SIM_IF 邻居表"; ip neigh show dev "$SIM_IF" 2>/dev/null
}

cmd_down() {
    [ -f "$SIM_DIR/hotspotd.pid" ] && hotspotd_cmd stop >/dev/null
    for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^$NS_PREFIX"); do
        ip netns del "$ns"
    done
    ip link del "$SIM_IF" 2>/dev/null
    : > "$SIM_DIR/devices"; : > "$SIM_DIR/dhcp_events"
    echo "假热点和假设备都拆掉了"
}

# hotspotd 在本机跑: 用本机 gcc 编(不带 BPF 硬件加速, offload 走 null 适配器), 在私有挂载空间里把
# $HNC_SIM_DIR/hnc 绑到 /data/local/hnc(hotspotd 的路径写死在代码里), 外面的 /data 不受影响
# (只会留下一个空的挂载点目录)。热点网卡由 run/hnc_state 的 ACTIVE:<网桥> 告诉它; PATH 里放
# test/sim/fake, `dumpsys` 和 `iptables_manager.sh stats_all` 都是假的。产出: $HNC_SIM_DIR/hnc/data/devices.json。
hotspotd_cmd() {
    hnc=$SIM_DIR/hnc pidf=$SIM_DIR/hotspotd.pid
    case "${1:-}" in
    start)
        [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null && { echo "hotspotd 已在跑"; return 0; }
        command -v gcc >/dev/null 2>&1 || die "缺 gcc"
        mkdir -p "$SIM_DIR/bin" "$hnc/run" "$hnc/data" "$hnc/logs" "$hnc/bin"
        hs=$REPO/daemon/hotspotd
        gcc -O1 -std=c11 -D_GNU_SOURCE -w -pthread -o "$SIM_DIR/bin/hotspotd" \
            "$hs/hotspotd.c" "$hs/hnc_helpers.c" "$hs/hostname_cache.c" "$hs/oui_override.c" "$hs/mdns_worker.c" \
            "$hs/platform.c" "$hs/scheduler.c" "$hs/upstream.c" \
            "$hs/offload/adapter.c" "$hs/offload/adapter_null.c" "$hs/lsm/hnc_lsm_stub.c" || die "hotspotd 编译失败"
        cp "$REPO/test/sim/fake/iptables_manager.sh" "$hnc/bin/iptables_manager.sh"
        echo "ACTIVE:$SIM_IF" > "$hnc/run/hnc_state"
        echo "$SIM_IF" > "$hnc/run/hotspot_iface"
        [ -f "$hnc/data/rules.json" ] || echo '{"devices":{}}' > "$hnc/data/rules.json"
        mkdir -p /data/local/hnc 2>/dev/null || die "建不了挂载点 /data/local/hnc"
        # v5.31 T5: HNC_SIM_HOTSPOTD_ARGS 透传给 hotspotd(Go 模式场景传 --no-discovery)
        HNC_SIM_DIR=$SIM_DIR PATH="$REPO/test/sim/fake:$PATH" \
            unshare -m --propagation private sh -c 'mount --bind "$1" /data/local/hnc && exec "$2" ${3:-}' sh "$hnc" "$SIM_DIR/bin/hotspotd" "${HNC_SIM_HOTSPOTD_ARGS:-}" \
            > "$SIM_DIR/hotspotd.out" 2>&1 &
        echo $! > "$pidf"
        sleep 1
        kill -0 "$(cat "$pidf")" 2>/dev/null || { cat "$SIM_DIR/hotspotd.out" >&2; die "hotspotd 没起来"; }
        echo "hotspotd 已启动(pid $(cat "$pidf")), 设备表: $hnc/data/devices.json"
        ;;
    stop)
        [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null
        rm -f "$pidf"; echo "hotspotd 已停"
        ;;
    log) cat "$hnc/logs/hotspotd.log" "$SIM_DIR/hotspotd.out" 2>/dev/null ;;
    *) die "hotspotd start|stop|log" ;;
    esac
}

[ $# -ge 1 ] || { sed -n '2,24p' "$0"; exit 2; }
need_env
c=$1; shift
case "$c" in
    up) cmd_up ;;
    add) [ $# -ge 3 ] || die "add NAME MAC IP [主机名]"; cmd_add "$@" ;;
    poke) [ $# -ge 1 ] || die "poke NAME"; cmd_poke "$1" ;;
    ip) [ $# -ge 2 ] || die "ip NAME 新IP [主机名]"; cmd_ip "$@" ;;
    del) [ $# -ge 1 ] || die "del NAME [--quiet]"; cmd_del "$@" ;;
    list) cmd_list ;;
    down) cmd_down ;;
    hotspotd) hotspotd_cmd "$@" ;;
    *) die "不认识的子命令 $c(up / add / poke / ip / del / list / down / hotspotd)" ;;
esac
