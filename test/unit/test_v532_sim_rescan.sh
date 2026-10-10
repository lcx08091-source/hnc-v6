#!/system/bin/sh
# test/unit/test_v532_sim_rescan.sh — v5.32 模拟设备验收(test/sim/run_m4_sim_v532.sh)
# 接进 run_all: C 版重扫不报回旧 IP(换 IP 后 SIGUSR1 重扫 / 重启 hotspotd)。
# 要 root + 网络 / 挂载命名空间 + gcc → 默认跳过; 设 HNC_SIM=1 才跑。
# 工具不全时脚本以 77 退出, 记为跳过。

test_start "模拟设备: v5.32 C 版重扫不报回旧 IP(换 IP 后 SIGUSR1 / 重启, 每次都是新 IP)"
if [ "${HNC_SIM:-}" != 1 ]; then
    test_skip "设 HNC_SIM=1 才跑(要 root 和网络命名空间, 约 4–5 分钟)"
else
    _sim_out=$(PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/local/go/bin:/opt/go/bin" HNC_SIM_DIR="${HNC_TEST_DIR}-sim532" bash "$HNC_REPO_ROOT/test/sim/run_m4_sim_v532.sh" 2>&1)
    _sim_rc=$?
    if [ "$_sim_rc" -eq 0 ]; then
        test_pass
    elif [ "$_sim_rc" -eq 77 ]; then
        test_skip "$(echo "$_sim_out" | tail -1)"
    else
        test_fail "$(echo "$_sim_out" | grep -E '✗|结果' | head -20)"
    fi
fi
