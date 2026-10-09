#!/bin/sh
# test/sim/fake/iptables_manager.sh — 模拟设备用: hotspotd 每次写设备表前调 `stats_all` 取每台设备的字节数,
# 格式每行 "<ip> <rx_bytes> <tx_bytes>"。模拟环境不计流量, 输出 $HNC_SIM_DIR/stats(没有就空)。
[ "${1:-}" = "stats_all" ] || exit 0
cat "${HNC_SIM_DIR:-/tmp/hnc_sim}/stats" 2>/dev/null
exit 0
