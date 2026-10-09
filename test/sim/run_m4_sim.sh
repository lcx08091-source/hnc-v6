#!/bin/bash
# test/sim/run_m4_sim.sh — 用模拟设备跑一遍「Go 版设备发现 vs hotspotd」对照(迁移 M4 的验收数据),
# 不用手机、不用真设备。要 root、iproute2、gcc、go(Linux 开发机 / CI / Claude 的云端容器都行)。
#
#   sudo bash test/sim/run_m4_sim.sh          # 跑完打印报告, 有一步不对就退出码 1
#
# 默认在一个新的网络 + 挂载命名空间里跑(unshare -nm), 不碰本机网络; 报告写到
# $HNC_SIM_DIR/m4_sim_report.txt(默认 /tmp/hnc_sim)。缺工具时打印原因并以 77 退出(当作跳过)。
#
# 每一步: 用 simnet.sh 改假设备 → 等两边收敛(在时限内反复跑 TestM4Sim, 见
# src/dpid/cmd/hnc_watchdog/m4_sim_test.go: 走看门狗真实的影子路径, 要求 Go 与 hotspotd 无差异,
# 且两边都等于场景期望)→ 记下用了几秒。另外检查报垃圾名(null / localhost)的设备没被起成垃圾名。
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export HNC_SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" = 0 ] || skip "需要 root"
for c in ip gcc go unshare python3; do command -v "$c" >/dev/null 2>&1 || skip "缺 $c"; done
if [ "${HNC_SIM_INNER:-}" != 1 ]; then
    HNC_SIM_INNER=1 exec unshare --net --mount --propagation private bash "$0" "$@"
fi
ip link set lo up 2>/dev/null

SIM="bash $REPO/test/sim/simnet.sh"
HNC=$HNC_SIM_DIR/hnc
REPORT=$HNC_SIM_DIR/m4_sim_report.txt
FAILS=0
mkdir -p "$HNC_SIM_DIR"
: > "$REPORT"
say() { echo "$*" | tee -a "$REPORT"; }

$SIM down >/dev/null 2>&1
rm -rf "$HNC"
$SIM up >/dev/null || exit 1
$SIM hotspotd start >/dev/null || exit 1
(cd "$REPO/src/dpid" && CGO_ENABLED=0 go test -c -o "$HNC_SIM_DIR/m4sim.test" ./cmd/hnc_watchdog/) || { echo "编译 TestM4Sim 失败"; exit 1; }
trap '$SIM down >/dev/null 2>&1' EXIT

GHOSTS=""   # 悄悄离开的设备: 内核邻居表还留着(STALE), 两边都应该还认为它在
expect() {
    awk 'NF >= 3 { printf "%s %s;", $2, $3 }' "$HNC_SIM_DIR/devices"
    printf '%s' "$GHOSTS"
}

# check 名称 时限秒: 时限内反复对照, 直到通过
check() {
    name=$1 limit=$2 t0=$(date +%s) out=""
    while :; do
        out=$(HNC_SIM_IFACE=hncsim0 HNC_SIM_HNC_DIR=$HNC HNC_SIM_EXPECT="$(expect)" HNC_SIM_OUT=$HNC_SIM_DIR/last_shadow.json \
            "$HNC_SIM_DIR/m4sim.test" -test.run '^TestM4Sim$' 2>&1) && break
        if [ $(( $(date +%s) - t0 )) -ge "$limit" ]; then
            say "  ✗ $name: ${limit} 秒内没对上"
            echo "$out" | grep -E 'm4_sim_test|不一致|期望' | sed 's/^/      /' | tee -a "$REPORT"
            FAILS=$((FAILS + 1)); return 1
        fi
        sleep 1
    done
    say "  ✓ $name: $(( $(date +%s) - t0 )) 秒对上(期望 $(expect | tr ';' '\n' | grep -c .) 台)"
}

# 报垃圾名的设备: devices.json 里的名字不能是垃圾名, 也不能标成来自 DHCP
check_junk() {
    for mac in "$@"; do
        r=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])).get(sys.argv[2],{}); print(d.get("hostname",""), d.get("hostname_src",""))' "$HNC/data/devices.json" "$mac" 2>/dev/null)
        case "$(echo "$r" | awk '{print tolower($1)}')" in
            null|localhost|unknown|"") say "  ✗ 垃圾名没挡住: $mac → $r"; FAILS=$((FAILS + 1)) ;;
            *) case "$r" in *" dhcp") say "  ✗ $mac 的名字被标成 DHCP 来源: $r"; FAILS=$((FAILS + 1)) ;; *) say "  ✓ 垃圾名挡住了: $mac → $r" ;; esac ;;
        esac
    done
}

# 离开: 分别记下 Go(邻居表变 FAILED / 消失)和 hotspotd(devices.json 里没了)各用了几秒
leave_timing() {
    mac=$1 addr=$2 t0=$(date +%s) tg="" th=""
    while [ $(( $(date +%s) - t0 )) -lt 180 ]; do
        now=$(( $(date +%s) - t0 ))
        [ -z "$tg" ] && ! ip neigh show "$addr" dev hncsim0 | grep -Eq 'REACHABLE|STALE|DELAY|PROBE' && tg=$now
        [ -z "$th" ] && ! grep -q "\"$mac\"" "$HNC/data/devices.json" 2>/dev/null && th=$now
        [ -n "$tg" ] && [ -n "$th" ] && break
        sleep 1
    done
    say "  · 离开后: Go(邻居表)${tg:-超时} 秒发现, hotspotd ${th:-超时} 秒发现 —— 影子比对要求同一差异连续 2 轮(10 分钟)才计数, 这段时间差不算不一致"
}

say "== M4 模拟设备对照 $(date '+%F %T') · hotspotd 本机编译(无 BPF) · Go 走看门狗影子路径"

say "1. 6 台设备连上(其中 2 台 DHCP 报垃圾名 null / localhost, 1 台不报名字)"
$SIM add tv    02:5a:00:00:00:01 192.168.43.101 Redmi-TV >/dev/null
$SIM add pad   02:5a:00:00:00:02 192.168.43.102 null >/dev/null
$SIM add mac   02:5a:00:00:00:03 192.168.43.103 MacBook-Air >/dev/null
$SIM add phone 02:5a:00:00:00:04 192.168.43.104 localhost >/dev/null
$SIM add watch 02:5a:00:00:00:05 192.168.43.105 >/dev/null
$SIM add pc    02:5a:00:00:00:06 192.168.43.106 DESKTOP-7Q2 >/dev/null
check "6 台都看到" 30
check_junk 02:5a:00:00:00:02 02:5a:00:00:00:04

say "2. pad 换 IP(.102 → .112, 模拟 DHCP 重新分配; 旧 IP 的表项还留在邻居表里)"
$SIM ip pad 192.168.43.112 >/dev/null
check "两边都换成新 IP" 30

say "3. tv 离开(之后有流量去找它 → 邻居表几秒后 FAILED)"
$SIM del tv >/dev/null
leave_timing 02:5a:00:00:00:01 192.168.43.101
check "两边都移除了 tv" 150

say "4. watch 悄悄离开(没有流量去找它 → 邻居表一直 STALE)"
$SIM del watch --quiet >/dev/null
GHOSTS="02:5a:00:00:00:05 192.168.43.105;"
check "两边都还认为 watch 在(与真机一致: 没人找它就发现不了它走了)" 15

say "5. tv 换个 IP 回来(.121)"
$SIM add tv 02:5a:00:00:00:01 192.168.43.121 Redmi-TV >/dev/null
check "两边都认出 tv 回来了" 30

say "6. 一下子连进 5 台"
for i in 7 8 9 10 11; do
    $SIM add "d$i" "02:5a:00:00:00:$(printf %02x "$i")" "192.168.43.$((100 + i))" >/dev/null
done
check "5 台都看到" 30

say "== 结果: $([ "$FAILS" = 0 ] && echo "全部通过" || echo "$FAILS 处不对") · 报告 $REPORT"
[ "$FAILS" = 0 ]
