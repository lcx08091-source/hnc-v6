#!/bin/bash
# test/sim/run_devscan_sim.sh — 模拟设备上的设备发现验收(v5.33: 只剩 Go 一份)。
# 不用手机、不用真设备。要 root、iproute2、go、mount、unshare(Linux 开发机 / CI /
# Claude 的云端容器都行):
#
#   sudo bash test/sim/run_devscan_sim.sh       # 约 4 分钟, 有一步不对就退出码 1
#
# 在一个新的网络 + 挂载命名空间里跑(不碰本机网络), 模拟目录绑到 /data/local/hnc,
# 看门狗的生产写者(src/dpid/cmd/hnc_watchdog 的 newM4GoRunner)照正式路径写
# data/devices.json; 场景在 devscan_sim_test.go 的 TestDevscanSim 里(合并自 v5.30–v5.32
# 那三套 C / Go 对照场景)。报告: $HNC_SIM_DIR/devscan_sim_report.txt。缺工具以 77 退出(跳过)。
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export HNC_SIM_DIR=${HNC_SIM_DIR:-/tmp/hnc_sim}

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" = 0 ] || skip "需要 root"
for c in ip go mount unshare; do command -v "$c" >/dev/null 2>&1 || skip "缺 $c"; done
if [ "${HNC_SIM_INNER:-}" != 1 ]; then
    HNC_SIM_INNER=1 exec unshare --net --mount --propagation private bash "$0" "$@"
fi
ip link set lo up 2>/dev/null

SIMNET=$REPO/test/sim/simnet.sh
SIM="bash $SIMNET"
HNC=$HNC_SIM_DIR/hnc
REPORT=$HNC_SIM_DIR/devscan_sim_report.txt
mkdir -p "$HNC_SIM_DIR"
: > "$REPORT"
say() { echo "$*" | tee -a "$REPORT"; }

$SIM down >/dev/null 2>&1
rm -rf "$HNC"
mkdir -p "$HNC/data" "$HNC/run" "$HNC/logs" "$HNC/bin"
$SIM up >/dev/null || exit 1
trap '$SIM down >/dev/null 2>&1' EXIT
mkdir -p /data/local/hnc && mount --bind "$HNC" /data/local/hnc || { say "绑不了 /data/local/hnc"; exit 1; }
export PATH="$REPO/test/sim/fake:$PATH"   # 假 dumpsys(DHCP 名字)
(cd "$REPO/src/dpid" && CGO_ENABLED=0 go test -c -o "$HNC_SIM_DIR/devscan_sim.test" ./cmd/hnc_watchdog/) \
    || { say "测试二进制编译失败"; exit 1; }

say "== 设备发现模拟验收(Go) $(date '+%F %T') =="
out=$(HNC_SIM_DEVSCAN=1 HNC_SIM_IFACE=hncsim0 HNC_SIM_SIMNET="$SIMNET" HNC_SIM_REPO="$REPO" \
    "$HNC_SIM_DIR/devscan_sim.test" -test.run '^TestDevscanSim$' -test.count=1 -test.v -test.timeout 15m 2>&1)
echo "$out" | grep -E 'devscan_sim_test.go:[0-9]+:' | sed 's/^\s*devscan_sim_test.go:[0-9]*: /  /' | tee -a "$REPORT"
if echo "$out" | grep -q -- '--- PASS: TestDevscanSim'; then
    say "== 结果: 全部通过 · 报告 $REPORT =="
    exit 0
fi
echo "$out" | grep -E 'FAIL|panic' | head -10 | tee -a "$REPORT"
say "== 结果: 有不对的步骤(见上面 ✗ / 期望) · 报告 $REPORT =="
exit 1
