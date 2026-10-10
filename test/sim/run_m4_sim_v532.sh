#!/bin/bash
# test/sim/run_m4_sim_v532.sh — v5.32 T2: C 版重扫不报回旧 IP(hotspotd scan_arp)。
# 前置: run_m4_sim.sh / run_m4_sim_v531.sh 不动、照跑; 本脚本补 WORK §T2 的
# 模拟设备场景(C 模式):
#
#   设备换 IP 后不再发包(邻居表项全部 STALE 化), 直接 SIGUSR1 让 hotspotd
#   重扫, 以及重启 hotspotd(初始化也走 scan_arp), 各重复几轮 —— 每次读
#   devices.json 都必须是新 IP。旧代码按 /proc/net/arp 行序覆盖 d->ip
#   (「旧行为看顺序, 要多试」); 新代码走 netlink RTM_GETNEIGH dump, 按
#   NDA_CACHEINFO 的最近确认时间单调合并, 与行序无关。
#
#   注意: simnet 的 `ip` 子命令末尾固定 poke 一次 —— 相当于真实世界里 DHCP
#   交换让新表项出现(REACHABLE)。之后不再发包, 等表项 STALE(35 秒)再重扫,
#   新旧表项状态相同, 只有「最近确认时间」可分胜负 —— 这正是要测的点。
#
# 要 root、iproute2、gcc(go 不需要 —— 场景只跑 hotspotd)。
# 报告: $HNC_SIM_DIR/m4_sim_v532_report.txt。

set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export HNC_SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" = 0 ] || skip "需要 root"
for c in ip gcc unshare; do command -v "$c" >/dev/null 2>&1 || skip "缺 $c"; done
if [ "${HNC_SIM_INNER:-}" != 1 ]; then
    HNC_SIM_INNER=1 exec unshare --net --mount --propagation private bash "$0" "$@"
fi
ip link set lo up 2>/dev/null

SIM="bash $REPO/test/sim/simnet.sh"
HNC=$HNC_SIM_DIR/hnc
REPORT=$HNC_SIM_DIR/m4_sim_v532_report.txt
FAILS=0
mkdir -p "$HNC_SIM_DIR"
: > "$REPORT"
say() { echo "$*" | tee -a "$REPORT"; }
fail() { say "  ✗ $*"; FAILS=$((FAILS + 1)); }

# ip_of <mac>: devices.json 里该设备当前的 ip(取 "mac":"..." 前缀对象的 ip)
ip_of() {
    grep -o "\"$1\":{\"ip\":\"[0-9.]*\"" "$HNC/data/devices.json" 2>/dev/null \
        | head -1 | sed 's/.*"ip":"//; s/"$//'
}
# wait_ip <mac> <want-ip> <秒>: 时限内 devices.json 变成目标 IP
wait_ip() {
    mac=$1 want=$2 limit=$3 t0=$(date +%s)
    while [ "$(ip_of "$mac")" != "$want" ]; do
        [ $(( $(date +%s) - t0 )) -ge "$limit" ] && return 1
        sleep 1
    done
    return 0
}
# stale_all <秒>: 等邻居表项全部 STALE(不发包)
stale_all() { say "    (等 $1s 让邻居表项 STALE 化, 不发包)"; sleep "$1"; }

$SIM down >/dev/null 2>&1
rm -rf "$HNC"
$SIM up >/dev/null || exit 1
$SIM hotspotd start >/dev/null || exit 1
trap '$SIM down >/dev/null 2>&1' EXIT

MAC=02:5a:00:00:00:01
say "== v5.32 T2 模拟设备: C 版重扫不报回旧 IP $(date '+%F %T') =="

say "1. tv 连上(.101)"
$SIM add tv $MAC 192.168.43.101 Redmi-TV >/dev/null
wait_ip "$MAC" 192.168.43.101 30 || fail "初始设备没出现" 

# SIGUSR1 轮: 换 IP → poke 一次 → STALE 化 → 不发包直接 SIGUSR1 重扫
i=0
for newip in 192.168.43.111 192.168.43.112 192.168.43.113; do
    i=$((i + 1))
    say "2.$i 换 IP → $newip, STALE 后 SIGUSR1 重扫(不发包)"
    $SIM ip tv "$newip" >/dev/null
    stale_all 35
    kill -USR1 "$(cat "$HNC_SIM_DIR/hotspotd.pid" 2>/dev/null)" 2>/dev/null || fail "SIGUSR1 没送达(hotspotd.pid?)"
    if wait_ip "$MAC" "$newip" 10; then
        say "  ✓ SIGUSR1 重扫报的是新 IP $newip"
    else
        fail "SIGUSR1 重扫后 devices.json 不是 $newip(现在是 $(ip_of "$MAC"))"
    fi
done

# 重启轮: 换 IP → poke 一次 → STALE 化 → 重启 hotspotd(初始化也走 scan_arp)
i=0
for newip in 192.168.43.121 192.168.43.122; do
    i=$((i + 1))
    say "3.$i 换 IP → $newip, STALE 后重启 hotspotd"
    $SIM ip tv "$newip" >/dev/null
    stale_all 35
    $SIM hotspotd stop >/dev/null
    $SIM hotspotd start >/dev/null || { fail "hotspotd 重启失败"; break; }
    if wait_ip "$MAC" "$newip" 20; then
        say "  ✓ 重启后初始扫描报的是新 IP $newip"
    else
        fail "重启后 devices.json 不是 $newip(现在是 $(ip_of "$MAC"))"
    fi
done

# 佐证: 邻居表里确实还留着旧表项(不然上面赢的是"没得选", 不算证明)
say "4. 邻居表里的历史表项(应有多条, 全 STALE)"
ip neigh show dev hncsim0 2>/dev/null | tee -a "$REPORT"
NEIGH_N=$(ip neigh show dev hncsim0 2>/dev/null | grep -c "$MAC")
if [ "$NEIGH_N" -ge 3 ]; then
    say "  ✓ 同 MAC 历史表项 $NEIGH_N 条 —— 重扫是在多表项里挑的, 不是没得选"
else
    say "  (邻居表只有 $NEIGH_N 条同 MAC 表项; GC 比预期快, 场景强度打折)"
fi

say "== 结果: $([ "$FAILS" = 0 ] && echo "全部通过" || echo "$FAILS 处不对") · 报告 $REPORT =="
[ "$FAILS" = 0 ]
