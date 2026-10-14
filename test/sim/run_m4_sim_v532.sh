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
# 场景 6(审查补): 换 IP 后 C / Go 两个写者都不许跳回旧 IP(TestM4SimNoFlipBack)。
#
# T3 场景(5): 退路演练 —— 默认值换成 c(TestM4SimDefaultC): 模拟 v5.31 升级上来
# 的手机(无 data/m4_owner、run/m4_owner.current 还是上次的 go、hotspotd 以
# --no-discovery 跑) → 默认 c 后一轮内 hotspotd 恢复发现写出全部设备 → 默认
# 换回 go → 切到 Go 版; 两边写日志不交错(照 run_m4_sim_v531.sh 场景 4)。
#
# 要 root、iproute2、gcc、go、mount。
# 报告: $HNC_SIM_DIR/m4_sim_v532_report.txt。

set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export HNC_SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" = 0 ] || skip "需要 root"
for c in ip gcc go mount unshare; do command -v "$c" >/dev/null 2>&1 || skip "缺 $c"; done
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
# 审查补: 场景必须真的让 hotspotd 在多条表项里挑(测试纪律第 12 条)。
# neigh_n <mac>: 网关邻居表里该 MAC 的有效表项数
neigh_n() { ip neigh show dev hncsim0 2>/dev/null | grep -i "lladdr $1 " | grep -cE 'REACHABLE|STALE|DELAY|PROBE'; }
# need_choice <mac>: 重扫前该 MAC 至少两条有效表项, 否则这一轮「没得选」, 记失败
need_choice() {
    n=$(neigh_n "$1")
    if [ "${n:-0}" -ge 2 ]; then
        say "    (邻居表里该设备 $n 条有效表项, 重扫要挑)"
    else
        fail "邻居表里该设备只有 ${n:-0} 条有效表项 —— 这一轮测不到「挑哪条」"
    fi
}
# wait_reach <ip> <秒>: 等网关确认这个 IP 可达(REACHABLE)。刚连上就换 IP 的话, 网关
# 对旧 IP 的回包探测落空、旧表项直接 FAILED, 邻居表里只剩新 IP(审查时第 1 轮就是这样)。
wait_reach() {
    t0=$(date +%s)
    until ip neigh show "$1" dev hncsim0 2>/dev/null | grep -q REACHABLE; do
        [ $(( $(date +%s) - t0 )) -ge "$2" ] && return 1
        sleep 0.5
    done
}

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
wait_reach 192.168.43.101 15 || fail "网关 15 秒内没确认 .101 可达"

# SIGUSR1 轮: 换 IP → poke 一次 → STALE 化 → 不发包直接 SIGUSR1 重扫
i=0
for newip in 192.168.43.111 192.168.43.112 192.168.43.113; do
    i=$((i + 1))
    say "2.$i 换 IP → $newip, STALE 后 SIGUSR1 重扫(不发包)"
    $SIM ip tv "$newip" >/dev/null
    stale_all 35
    need_choice "$MAC"
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
    need_choice "$MAC"
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

# ── 5. T3 退路演练(要 go): 默认值换成 c 这条路改了就能用 ──────────────
SIMNET=$REPO/test/sim/simnet.sh
expect() { awk 'NF >= 3 { printf "%s %s;", $2, $3 }' "$HNC_SIM_DIR/devices"; }
run_test() {
    name=$1 test=$2; shift 2
    out=$(env HNC_SIM_IFACE=hncsim0 HNC_SIM_EXPECT="$(expect)" HNC_SIM_NAMES="$NAMES" HNC_SIM_BLOCKED="" "$@" \
        "$HNC_SIM_DIR/m4sim532.test" -test.run "^$test\$" -test.count=1 -test.v 2>&1)
    if echo "$out" | grep -q -- "--- PASS: $test"; then
        say "  ✓ $name"
        echo "$out" | grep -E '^\s+m4_sim_v53[12]_test.go:[0-9]+: [0-9]\.' | sed 's/^\s*m4_sim_v53[12]_test.go:[0-9]*: /      /' | tee -a "$REPORT"
    else
        fail "$name"
        echo "$out" | grep -E 'm4_sim_v53[12]_test.go|FAIL|panic' | tail -40 | sed 's/^/      /' | tee -a "$REPORT"
    fi
}

say "5. T3 退路演练: 默认值换成 c —— 模拟 v5.31 升级上来的手机(无开关文件)"
# tv 带名字固定在 .122(dhcp_events 里给它一条新 IP 的记录, 名字解析稳定)
$SIM ip tv 192.168.43.122 Redmi-TV >/dev/null
sleep 1
$SIM poke tv >/dev/null
NAMES='02:5a:00:00:00:01=Redmi-TV@dhcp'
# 看门狗代码走正式路径: 模拟目录绑到 /data/local/hnc(v531 场景同款)
mkdir -p /data/local/hnc && mount --bind "$HNC" /data/local/hnc || { fail "绑不了 /data/local/hnc"; }
cp "$HNC_SIM_DIR/bin/hotspotd" "$HNC/bin/hotspotd"
export PATH="$REPO/test/sim/fake:$PATH"
(cd "$REPO/src/dpid" && CGO_ENABLED=0 go test -c -o "$HNC_SIM_DIR/m4sim532.test" ./cmd/hnc_watchdog/) || { fail "测试二进制编译失败"; }
# 前置: hotspotd 换 --no-discovery(上次会话按 go 拉起的), 没有开关文件, current 还是 go
$SIM hotspotd stop >/dev/null
HNC_SIM_HOTSPOTD_ARGS="--no-discovery" $SIM hotspotd start >/dev/null || { fail "hotspotd 起不来"; }
rm -f "$HNC/data/m4_owner"
printf 'go\n' > "$HNC/run/m4_owner.current"
run_test "默认 c → hotspotd 恢复发现写出全部设备 → 默认 go → 切 Go 版; 写者不交错" TestM4SimDefaultC \
    HNC_SIM_DEFAULT=1 HNC_SIM_SIMNET="$SIMNET"

# ── 6. 审查补: 换 IP 后不许跳回旧 IP(C 事件路径 + Go 写者, 同一邻居表同时比) ──
# 审查时在这里复现: C 版约 30 秒后被旧表项老化的通知改回旧 IP; 网关还有流量去找旧 IP
# 时 C 和 Go 都被旧表项 PROBE 的通知抢回旧 IP, 旧表项 FAILED 后一直停在失效的 IP 上。
say "6. 换 IP 后不许跳回旧 IP(C 与 Go 同一邻居表; 不用网 75 秒 + 网关还去找旧 IP)"
$SIM hotspotd stop >/dev/null
$SIM hotspotd start >/dev/null || fail "hotspotd 起不来"
run_test "两边换 IP 后 10 秒内报出新 IP, 之后不跳回旧 IP" TestM4SimNoFlipBack \
    HNC_SIM_FLIP=1 HNC_SIM_SIMNET="$SIMNET"

say "== 结果: $([ "$FAILS" = 0 ] && echo "全部通过" || echo "$FAILS 处不对") · 报告 $REPORT =="
[ "$FAILS" = 0 ]
