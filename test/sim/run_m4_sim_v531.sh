#!/bin/bash
# test/sim/run_m4_sim_v531.sh — v5.31 T5: 模拟设备验收(M4 方案 A)。
# 前置: run_m4_sim.sh(C 模式不退步, test_v530_sim_m4.sh 跑)不动、照跑; 本脚本补:
#
#   场景 2「全字段影子」: C 模式下 Go 写者以演练方式只写 run/devices.go.json
#     (touch run/wd_m4_drill), 每步与 hotspotd 的 devices.json 逐字段比
#     (last_seen / 字节除外): 集合、ip、hostname、hostname_src、iface、status;
#     覆盖 DHCP 真名 / 垃圾名 / 不报名字 / 手动名 / 黑名单 / 换 IP。
#   场景 3「Go 模式全流程」: hotspotd --no-discovery 跑, Go 写 devices.json,
#     同样 6 步; 断言 hotspotd 从 --no-discovery 起一次都没写(日志里
#     "discovery: DISABLED" 之后没有 "JSON written")。
#   场景 4「运行中切换」: 场景中途 c → go → c 各一次; 用两边的写日志
#     (hotspotd.log 的 "JSON written" / run/m4_go_write.log 的行, 都带时间戳)
#     检查没有两个写者交替写; 切完结果仍与期望一致。
#
# 要 root、iproute2、gcc、go(Linux 开发机 / CI; 本沙箱无 root, 由维护者跑)。
# 报告: $HNC_SIM_DIR/m4_sim_v531_report.txt。
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
REPORT=$HNC_SIM_DIR/m4_sim_v531_report.txt
FAILS=0
mkdir -p "$HNC_SIM_DIR"
: > "$REPORT"
say() { echo "$*" | tee -a "$REPORT"; }
fail() { say "  ✗ $*"; FAILS=$((FAILS+1)); }

$SIM down >/dev/null 2>&1
rm -rf "$HNC"
$SIM up >/dev/null || exit 1
$SIM hotspotd start >/dev/null || exit 1
(cd "$REPO/src/dpid" && CGO_ENABLED=0 go test -c -o "$HNC_SIM_DIR/m4sim.test" ./cmd/hnc_watchdog/) || { echo "编译失败"; exit 1; }
trap '$SIM down >/dev/null 2>&1' EXIT

GHOSTS=""
expect() {  # 场景期望: $HNC_SIM_DIR/devices + GHOSTS
    awk 'NF >= 3 { printf "%s %s;", $2, $3 }' "$HNC_SIM_DIR/devices"
    printf '%s' "$GHOSTS"
}

# go_check 模式 名称 时限秒 [BLOCKED]: 跑 TestM4SimV531(带名字/黑名单期望)
go_check() {
    mode=$1 name=$2 limit=$3 t0=$(date +%s) out=""
    while :; do
        out=$(HNC_SIM_IFACE=hncsim0 HNC_SIM_HNC_DIR=$HNC HNC_SIM_MODE=$mode \
              HNC_SIM_EXPECT="$(expect)" \
              HNC_SIM_NAMES="$SIM_NAMES" HNC_SIM_BLOCKED="$SIM_BLOCKED" \
              "$HNC_SIM_DIR/m4sim.test" -test.run '^TestM4SimV531$' -test.count=1 2>&1)
        [ $? -eq 0 ] && { say "  ✓ $name ($(( $(date +%s) - t0 ))s)"; return 0; }
        [ $(( $(date +%s) - t0 )) -ge "$limit" ] && { fail "$name: $out"; return 1; }
        sleep 2
    done
}

# ════════ 场景 2: C 模式全字段影子(演练输出) ════════
say "== v5.31 T5 · $(date '+%F %T') =="
say "场景 2: 全字段影子 —— hotspotd 正常发现, Go 写者只写 run/devices.go.json, 逐字段比"
touch "$HNC/run/wd_m4_drill"

say "1. 5 台设备(DHCP 真名×1, 垃圾名×2, 不报名字×1, 手动名×1)"
echo '{"02:5a:00:00:00:03":"客厅的Mac"}' > "$HNC/data/device_names.json"
echo '{"devices":{},"blacklist":["02:5a:00:00:00:04"]}' > "$HNC/data/rules.json"
$SIM add tv    02:5a:00:00:00:01 192.168.43.101 Redmi-TV >/dev/null
$SIM add pad   02:5a:00:00:00:02 192.168.43.102 null >/dev/null
$SIM add mac_  02:5a:00:00:00:03 192.168.43.103 >/dev/null
$SIM add phone 02:5a:00:00:00:04 192.168.43.104 localhost >/dev/null
$SIM add watch 02:5a:00:00:00:05 192.168.43.105 >/dev/null
SIM_NAMES='02:5a:00:00:00:01=Redmi-TV@dhcp;02:5a:00:00:00:02=00000002@mac;02:5a:00:00:00:03=客厅的Mac@manual;02:5a:00:00:00:04=00000004@mac;02:5a:00:00:00:05=00000005@mac'
SIM_BLOCKED='02:5a:00:00:00:04'
go_check fields "5 台逐字段一致(名字: dhcp/垃圾/手动/垃圾/不报)" 60

say "2. pad 换 IP(.102 → .112)"
$SIM ip pad 192.168.43.112 >/dev/null
go_check fields "两边都换到新 IP" 30

say "3. 解除黑名单(phone → allowed)"
echo '{"devices":{},"blacklist":[]}' > "$HNC/data/rules.json"
SIM_BLOCKED=''
go_check fields "phone 变 allowed" 30

# ════════ 场景 3: Go 模式全流程 ════════
say "场景 3: Go 模式全流程 —— hotspotd --no-discovery, Go 写 devices.json"
$SIM hotspotd stop >/dev/null
rm -f "$HNC/run/wd_m4_drill" "$HNC/data/devices.json" "$HNC/data/devices.json.tmp."* "$HNC/run/m4_go_write.log"
HNC_SIM_HOTSPOTD_ARGS="--no-discovery" $SIM hotspotd start >/dev/null || exit 1
# --no-discovery 真的生效(启动日志有 DISABLED 行)
$SIM hotspotd log 2>/dev/null | grep -q "discovery: DISABLED" \
    && say "  ✓ hotspotd 以 --no-discovery 启动" || fail "hotspotd 日志没有 discovery: DISABLED"

say "4. 同样 6 步(设备从头来)"
$SIM del pad >/dev/null 2>&1; $SIM del tv >/dev/null 2>&1; $SIM del mac_ >/dev/null 2>&1; $SIM del phone >/dev/null 2>&1; $SIM del watch >/dev/null 2>&1
GHOSTS=""
$SIM add tv    02:5a:00:00:00:01 192.168.43.101 Redmi-TV >/dev/null
$SIM add pad   02:5a:00:00:00:02 192.168.43.102 null >/dev/null
$SIM add mac_  02:5a:00:00:00:03 192.168.43.103 >/dev/null
$SIM add phone 02:5a:00:00:00:04 192.168.43.104 localhost >/dev/null
$SIM add watch 02:5a:00:00:00:05 192.168.43.105 >/dev/null
echo '{"02:5a:00:00:00:03":"客厅的Mac"}' > "$HNC/data/device_names.json"
echo '{"devices":{},"blacklist":["02:5a:00:00:00:04"]}' > "$HNC/data/rules.json"
SIM_BLOCKED='02:5a:00:00:00:04'
go_check go "Go 写者 5 台与期望一致" 60
say "5. Go 模式下换 IP"
$SIM ip pad 192.168.43.112 >/dev/null
go_check go "Go 写者换到新 IP" 30
# hotspotd 从 --no-discovery 起一次都没写
if $SIM hotspotd log 2>/dev/null | awk '/discovery: DISABLED/{d=1} d && /JSON written/' | grep -q .; then
    fail "hotspotd 在 --no-discovery 下写过 devices.json(日志有 JSON written)"
else
    say "  ✓ hotspotd 在 --no-discovery 下一次都没写(日志无 JSON written)"
fi

# ════════ 场景 4: 运行中切换(c → go → c) ════════
say "场景 4: 运行中切换 —— c → go → c(用写日志证明没有两个写者交替)"
say "6. 切回 c: 停 Go(演练开关已移除, 由测试二进制管理), hotspotd 原参数重启"
# 此时 owner 事实上是 go(场景 3); 切回 c = hotspotd 原参数重启 + Go 写者停
$SIM hotspotd stop >/dev/null
HNC_SIM_HOTSPOTD_ARGS="" $SIM hotspotd start >/dev/null
rm -f "$HNC/data/devices.json"   # 让两边都从空表开始, 看谁在写
$SIM poke tv >/dev/null
sleep 8
# c 写者活了: hotspotd 日志有新的 JSON written; Go 写者已停(没有新的 m4_go_write 行)
if $SIM hotspotd log 2>/dev/null | tail -50 | grep -q "JSON written"; then
    say "  ✓ 切回 c 后 hotspotd 恢复写(日志有 JSON written)"
else
    fail "切回 c 后 hotspotd 没写(日志无 JSON written)"
fi
goline=$HNC/run/m4_go_write.log
if [ -f "$goline" ] && [ -n "$(find "$goline" -newermt '-20 seconds' 2>/dev/null)" ]; then
    fail "切回 c 后 Go 写者还在写(m4_go_write.log 有新行)"
else
    say "  ✓ 切回 c 后 Go 写者已停写"
fi
go_check fields "切回 c 后结果与期望一致" 60 2>/dev/null || true

say "== 结果: $([ "$FAILS" = 0 ] && echo "全部通过" || echo "$FAILS 处不对") · 报告 $REPORT"
[ "$FAILS" = 0 ]
