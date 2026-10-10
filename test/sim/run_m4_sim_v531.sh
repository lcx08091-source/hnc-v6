#!/bin/bash
# test/sim/run_m4_sim_v531.sh — v5.31 T5: 模拟设备验收(M4 方案 A)。v5.31 审查时重写:
# GLM 交来的版本没有在 root 环境跑过 —— 路径没重定向全(看门狗读的是真实 /data/local/hnc)、
# 不等异步名字解析、设备名 mac_ 不合 simnet 的命名规则、「运行中切换」没有经过看门狗的切换代码。
#
#   sudo bash test/sim/run_m4_sim_v531.sh       # 报告: $HNC_SIM_DIR/m4_sim_v531_report.txt
#
# 场景(前置: run_m4_sim.sh 的 C 模式对照照跑, 由 test_v530_sim_m4.sh 负责):
#   2「全字段影子」: hotspotd 正常发现, 一个演练写者只写 run/devices.go.json, 与 hotspotd 的
#     devices.json 逐字段比(last_seen / 字节除外): 集合、ip、名字(DHCP 真名 / 垃圾名 / 不报 /
#     手动名)、iface、status(黑名单 / 解除黑名单)、换 IP。
#   3「Go 模式」: hotspotd 带 --no-discovery, Go 写者写 devices.json; hotspotd 一次都不写。
#   4「运行中切换」(TestM4SimOwner): 看门狗真实的 owner 管理器在真进程上: 开机纠偏 → c→go
#     (60 秒冷却内)→ Go 模式新设备 → go→c, 两边写日志不交错。
#
# 整个场景在独立的网络 + 挂载命名空间里; 模拟目录绑到 /data/local/hnc, 看门狗代码走正式路径。
# 要 root、iproute2、gcc、go、unshare; 缺了以 77 退出(当作跳过)。
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export HNC_SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" = 0 ] || skip "需要 root"
for c in ip gcc go unshare mount; do command -v "$c" >/dev/null 2>&1 || skip "缺 $c"; done
if [ "${HNC_SIM_INNER:-}" != 1 ]; then
    HNC_SIM_INNER=1 exec unshare --net --mount --propagation private bash "$0" "$@"
fi
ip link set lo up 2>/dev/null

SIMNET=$REPO/test/sim/simnet.sh
SIM="bash $SIMNET"
HNC=$HNC_SIM_DIR/hnc
REPORT=$HNC_SIM_DIR/m4_sim_v531_report.txt
FAILS=0
mkdir -p "$HNC_SIM_DIR"
: > "$REPORT"
say() { echo "$*" | tee -a "$REPORT"; }
fail() { say "  ✗ $*"; FAILS=$((FAILS + 1)); }

$SIM down >/dev/null 2>&1
rm -rf "$HNC"
$SIM up >/dev/null || exit 1
$SIM hotspotd start >/dev/null || exit 1     # 编好 hotspotd, 建好 $HNC 目录树
mkdir -p /data/local/hnc && mount --bind "$HNC" /data/local/hnc || { echo "绑不了 /data/local/hnc"; exit 1; }
cp "$HNC_SIM_DIR/bin/hotspotd" "$HNC/bin/hotspotd"   # 看门狗切换 / 纠偏时从这里拉起
export PATH="$REPO/test/sim/fake:$PATH"              # 假 dumpsys: Go 的名字解析和它拉起的 hotspotd 都用
(cd "$REPO/src/dpid" && CGO_ENABLED=0 go test -c -o "$HNC_SIM_DIR/m4sim531.test" ./cmd/hnc_watchdog/) || { echo "编译失败"; exit 1; }
cleanup() {
    [ -f "$HNC/run/hotspotd.pid" ] && kill "$(cat "$HNC/run/hotspotd.pid")" 2>/dev/null
    $SIM down >/dev/null 2>&1
}
trap cleanup EXIT

expect() { awk 'NF >= 3 { printf "%s %s;", $2, $3 }' "$HNC_SIM_DIR/devices"; }
NAMES=""
BLOCKED=""
# run_test 名称 测试名 [额外环境…]: 跑一次(测试自己在时限内反复比到对上)
run_test() {
    name=$1 test=$2; shift 2
    out=$(env HNC_SIM_IFACE=hncsim0 HNC_SIM_EXPECT="$(expect)" HNC_SIM_NAMES="$NAMES" HNC_SIM_BLOCKED="$BLOCKED" "$@" \
        "$HNC_SIM_DIR/m4sim531.test" -test.run "^$test\$" -test.count=1 -test.v 2>&1)
    if echo "$out" | grep -q -- "--- PASS: $test"; then
        say "  ✓ $name"
        echo "$out" | grep -E '^\s+m4_sim_v531_test.go:[0-9]+: [0-9]\.' | sed 's/^\s*m4_sim_v531_test.go:[0-9]*: /      /' | tee -a "$REPORT"
    else
        fail "$name"
        echo "$out" | grep -E 'm4_sim_v531_test.go|FAIL|panic' | head -20 | sed 's/^/      /' | tee -a "$REPORT"
    fi
}
hotspotd_pid() { cat "$HNC/run/hotspotd.pid" 2>/dev/null; }

say "== v5.31 T5 · $(date '+%F %T') =="
say "场景 2: 全字段影子 —— hotspotd 正常发现, 演练写者只写 run/devices.go.json, 逐字段比"
echo '{"02:5a:00:00:00:03":"客厅的Mac"}' > "$HNC/data/device_names.json"
echo '{"devices":{},"blacklist":["02:5a:00:00:00:04"]}' > "$HNC/data/rules.json"
$SIM add tv    02:5a:00:00:00:01 192.168.43.101 Redmi-TV >/dev/null
$SIM add pad   02:5a:00:00:00:02 192.168.43.102 null >/dev/null
$SIM add mbp   02:5a:00:00:00:03 192.168.43.103 >/dev/null
$SIM add phone 02:5a:00:00:00:04 192.168.43.104 localhost >/dev/null
$SIM add watch 02:5a:00:00:00:05 192.168.43.105 >/dev/null
NAMES='02:5a:00:00:00:01=Redmi-TV@dhcp;02:5a:00:00:00:02=00000002@mac;02:5a:00:00:00:03=客厅的Mac@manual;02:5a:00:00:00:04=00000004@mac;02:5a:00:00:00:05=00000005@mac'
BLOCKED='02:5a:00:00:00:04'
say "1. 5 台(DHCP 真名 / 垃圾名 null / 手动名 / 垃圾名 localhost 且在黑名单 / 不报名字)"
run_test "5 台逐字段一致" TestM4SimV531 HNC_SIM_MODE=fields
say "2. pad 换 IP(.102 → .112)"
$SIM ip pad 192.168.43.112 >/dev/null
run_test "两边都换到新 IP" TestM4SimV531 HNC_SIM_MODE=fields
say "3. 解除黑名单(phone → allowed; SIGUSR1 让 hotspotd 重扫重写)"
echo '{"devices":{},"blacklist":[]}' > "$HNC/data/rules.json"
BLOCKED=''
kill -USR1 "$(hotspotd_pid)" 2>/dev/null
# C 版重扫 ARP 时, 换过 IP 的 pad 新旧两条 STALE 表项挑哪个看 /proc/net/arp 顺序(老问题, 可能
# 报回旧 IP; Go 版按内核的「最近确认」挑)。让 pad 发个包(真实设备在用网时就是这样), 两边都跟上新 IP。
sleep 1
$SIM poke pad >/dev/null
run_test "phone 两边都是 allowed" TestM4SimV531 HNC_SIM_MODE=fields

say "场景 3: Go 模式 —— hotspotd --no-discovery, Go 写 devices.json"
$SIM hotspotd stop >/dev/null
HNC_SIM_HOTSPOTD_ARGS="--no-discovery" $SIM hotspotd start >/dev/null || exit 1
$SIM hotspotd log 2>/dev/null | grep -q "discovery: DISABLED" \
    && say "  ✓ hotspotd 以 --no-discovery 启动" || fail "hotspotd 日志没有 discovery: DISABLED"
say "4. Go 写者写出 5 台(名字 / 黑名单同上)"
run_test "Go 写者 5 台与期望一致" TestM4SimV531 HNC_SIM_MODE=go
say "5. Go 模式下换 IP(pad .112 → .122)"
$SIM ip pad 192.168.43.122 >/dev/null
run_test "Go 写者换到新 IP" TestM4SimV531 HNC_SIM_MODE=go
if $SIM hotspotd log 2>/dev/null | awk '/discovery: DISABLED/{d=1} d && /JSON written/' | grep -q .; then
    fail "hotspotd 在 --no-discovery 下写过 devices.json(日志有 JSON written)"
else
    say "  ✓ hotspotd 在 --no-discovery 下一次都没写"
fi

say "场景 4: 运行中切换 —— 看门狗的 owner 管理器在真进程上(此时 hotspotd 仍是 --no-discovery)"
run_test "开机纠偏 → c→go(冷却内)→ Go 模式新设备 → go→c, 写者不交错" TestM4SimOwner \
    HNC_SIM_OWNER=1 HNC_SIM_SIMNET="$SIMNET" HNC_SIM_OLD_IPS="02:5a:00:00:00:02=192.168.43.102,192.168.43.112"

say "== 结果: $([ "$FAILS" = 0 ] && echo "全部通过" || echo "$FAILS 处不对") · 报告 $REPORT"
[ "$FAILS" = 0 ]
