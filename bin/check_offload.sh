#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# HNC v3.4.3 — 智能 BPF tether offload 检测
#
# 背景:
#   v3.4.1 引入硬件卸载警告横幅,检测逻辑是
#     ls /sys/fs/bpf/tethering/ | grep -c map_offload_tether
#   只要 BPF map 文件存在就报警。
#
#   问题: 在 RMX5010 (SD8 Elite/Android 16/kernel 6.6.102) 等机型上,
#   /sys/fs/bpf/tethering/ 下的 map 文件确实存在,但 HNC 的 tc clsact
#   filter 优先级高于 schedcls/tether_*,流量在被 BPF 加速路径处理之前
#   已经被 tc 截走,BPF 程序的 stats_map 几乎不增长。也就是 "BPF map 存在
#   但实际没在工作",横幅是误报。
#
#   2026-04 调研结论(参见 CHANGELOG v3.4.3): 在 RMX5010 上手工写
#   tether_limit_map[iif]=0 强制 BPF 走 TC_PUNT 路径,前后对比 tc HTB
#   限速精度无可观测变化(24Mbit→22.74Mbps / 40Mbit→35.55Mbps),证明
#   该机型上 BPF 不旁路 tc。
#
# 新方案:
#   采样 tether_stats_map 两次,间隔 5 秒,只有 rxBytes+txBytes 总和
#   增长 >= 1MB 时才认为 BPF 在主动转发流量,值得报警。
#
# 输出 (stdout):
#   NOMAP    — /sys/fs/bpf/tethering/ 下没有 stats_map (老内核/非 GKI),不报警
#   IDLE     — map 存在但 5 秒内 rxBytes+txBytes 增长 < 1MB,BPF 没在工作,不报警
#   ACTIVE   — 5 秒内增长 >= 1MB,BPF 正在主动转发流量,显示横幅
#
# stats_map 行格式 (来自 AOSP TetherStatsValue 结构):
#   <iif>: {rxPackets,rxBytes,rxErrors,txPackets,txBytes,txErrors,}
#   例如: 20: {890421,1098331340,0,446664,52994213,0,}
#   字段顺序: $1=iif $2=rxPackets $3=rxBytes $4=rxErrors $5=txPackets $6=txBytes $7=txErrors
#   (用 tr 把 ':' '{' '}' ',' 全替换成空格后)

P=/sys/fs/bpf/tethering/map_offload_tether_stats_map
THRESHOLD=1048576   # 1 MB,5 秒内增长低于这个值就算 IDLE

[ -f "$P" ] || { echo NOMAP; exit 0; }

# 读出所有 entry 的 rxBytes + txBytes 总和。
# 如果 stats_map 是空的,grep '^[0-9]' 不会匹配任何行,awk END 输出 0。
read_total() {
    cat "$P" 2>/dev/null \
      | grep '^[0-9]' \
      | tr ':{},' '    ' \
      | awk '{s+=$3+$6} END{print s+0}'
}

S1=$(read_total)
sleep 5
S2=$(read_total)

# 防御: 如果两次读出来都是空字符串(权限问题),按 NOMAP 处理避免误报
[ -z "$S1" ] && S1=0
[ -z "$S2" ] && S2=0

DELTA=$((S2 - S1))

if [ "$DELTA" -ge "$THRESHOLD" ]; then
    echo ACTIVE
else
    echo IDLE
fi
