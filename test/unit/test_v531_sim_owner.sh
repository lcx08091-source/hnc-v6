#!/system/bin/sh
# test/unit/test_v531_sim_owner.sh — v5.31 模拟设备验收(test/sim/run_m4_sim_v531.sh)接进 run_all:
# 全字段影子 / Go 模式 / 看门狗真实的运行中切换(开机纠偏、冷却内切换、写者不交错)。
#
# 要 root + 网络 / 挂载命名空间 + gcc + go, 一次约 2–3 分钟 → 默认跳过; 设 HNC_SIM=1 才跑。
# 工具不全时脚本以 77 退出, 记为跳过。

test_start "模拟设备: v5.31 设备发现换写者(全字段影子 / Go 模式 / 运行中切换)"
if [ "${HNC_SIM:-}" != 1 ]; then
    test_skip "设 HNC_SIM=1 才跑(要 root 和网络命名空间, 约 2–3 分钟)"
else
    # run_all 把 PATH 收窄到系统目录; ip 在 sbin, go 常装在 /usr/local/go/bin → 补上
    _sim_out=$(PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/local/go/bin:/opt/go/bin" HNC_SIM_DIR="${HNC_TEST_DIR}-sim531" bash "$HNC_REPO_ROOT/test/sim/run_m4_sim_v531.sh" 2>&1)
    _sim_rc=$?
    if [ "$_sim_rc" -eq 0 ]; then
        test_pass
    elif [ "$_sim_rc" -eq 77 ]; then
        test_skip "$(echo "$_sim_out" | tail -1)"
    else
        test_fail "$(echo "$_sim_out" | grep -E '✗|结果|      ' | head -20)"
    fi
fi
