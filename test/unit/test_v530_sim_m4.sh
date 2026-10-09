#!/system/bin/sh
# test/unit/test_v530_sim_m4.sh — 模拟设备上的 M4 对照(test/sim/run_m4_sim.sh)接进 run_all。
#
# 要 root + 网络命名空间 + gcc + go, 一次约 2 分钟 → 默认跳过; 设 HNC_SIM=1 才跑
# (Linux 开发机 / Claude 云端容器: `HNC_SIM=1 sh test/run_all.sh`)。工具不全时脚本以 77 退出, 记为跳过。

test_start "模拟设备: Go 版设备发现与 hotspotd 对照(连上 / 换 IP / 离开 / 悄悄离开 / 回来 / 一次连 5 台)"
if [ "${HNC_SIM:-}" != 1 ]; then
    test_skip "设 HNC_SIM=1 才跑(要 root 和网络命名空间, 约 2 分钟)"
else
    # run_all 把 PATH 收窄到系统目录; ip 在 sbin, go 常装在 /usr/local/go/bin → 补上
    _sim_out=$(PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/local/go/bin:/opt/go/bin" HNC_SIM_DIR="${HNC_TEST_DIR}-sim" bash "$HNC_REPO_ROOT/test/sim/run_m4_sim.sh" 2>&1)
    _sim_rc=$?
    if [ "$_sim_rc" -eq 0 ]; then
        test_pass
    elif [ "$_sim_rc" -eq 77 ]; then
        test_skip "$(echo "$_sim_out" | tail -1)"
    else
        test_fail "$(echo "$_sim_out" | grep -E '✗|结果|      ' | head -20)"
    fi
fi
