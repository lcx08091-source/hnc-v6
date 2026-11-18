#!/system/bin/sh
# test/unit/test_v533_sim_devscan.sh — 模拟设备上的设备发现验收(test/sim/run_devscan_sim.sh)
# 接进 run_all。v5.33 起只剩 Go 一份, 原 v5.30 / v5.31 / v5.32 三套 C / Go 对照场景合并成一套。
# 要 root + 网络 / 挂载命名空间 + go → 默认跳过; 设 HNC_SIM=1 才跑。工具不全时脚本以 77
# 退出, 记为跳过。

test_start "模拟设备: 设备发现(Go)—— 名字 / 黑名单 / 刷新回执 / 换 IP 不跳回 / 离开下线 / 悄悄离开 / 重连 / 一次连 5 台"
if [ "${HNC_SIM:-}" != 1 ]; then
    test_skip "设 HNC_SIM=1 才跑(要 root 和网络命名空间, 约 4 分钟)"
else
    _sim_out=$(PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/local/go/bin:/opt/go/bin" HNC_SIM_DIR="${HNC_TEST_DIR}-simdev" bash "$HNC_REPO_ROOT/test/sim/run_devscan_sim.sh" 2>&1)
    _sim_rc=$?
    if [ "$_sim_rc" -eq 0 ]; then
        test_pass
    elif [ "$_sim_rc" -eq 77 ]; then
        test_skip "$(echo "$_sim_out" | tail -1)"
    else
        test_fail "$(echo "$_sim_out" | grep -E '✗|期望|没对上|结果|FAIL' | head -20)"
    fi
fi
