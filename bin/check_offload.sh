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
#   IDLE     — map 存在但 5 秒内 rxBytes+txBytes 增长 < 1MB,且静态探测也没
#              看到 offload 痕迹,BPF 没在工作,不报警
#   CAPABLE  — v5.9.3 新增 (BUG-005 ②)。增量同样不足 1MB (所以不是 ACTIVE),
#              但静态探测到本机确实具备/已挂载 AOSP tether offload:
#              tc filter 链里挂着 schedcls/tether_upstream4|6 这类程序,
#              或 tether limit_map/stats_map 里已有 ifindex 条目。
#              含义是"这台机器有 offload 能力、程序已就位,只是当前窗口
#              没有流量经过",而不是"offload 正在抢限速"。
#              **不报警、不弹横幅**,只用于状态行让用户看清设备能力 ——
#              一旦把 CAPABLE 接成弹窗条件,就退回 v3.4.1 那个"map 存在
#              就报警"的误报老路(见上面那段历史)。
#              httpd api_v5.go 的 runOffloadCheck 按整词判 active,
#              "capable" 不在关键字表里,老后端拿到也只会当未知态忽略。
#   ACTIVE   — 5 秒内增长 >= 1MB,BPF 正在主动转发流量,显示横幅
#
# 状态优先级: NOMAP > ACTIVE > CAPABLE > IDLE
# (NOMAP/ACTIVE/IDLE 三态的判定条件与 v5.9.2 完全一致,CAPABLE 只从原来
#  会输出 IDLE 的那部分里细分出来,不改变任何既有语义。)
#
# stats_map 行格式 (来自 AOSP TetherStatsValue 结构):
#   <iif>: {rxPackets,rxBytes,rxErrors,txPackets,txBytes,txErrors,}
#   例如: 20: {890421,1098331340,0,446664,52994213,0,}
#   字段顺序: $1=iif $2=rxPackets $3=rxBytes $4=rxErrors $5=txPackets $6=txBytes $7=txErrors
#   (用 tr 把 ':' '{' '}' ',' 全替换成空格后)

# v5.9.3: 目录抽出成变量,只为本地/单测能构造 map 样本做验证。
# 生产路径不设 HNC_BPF_TETHER_DIR,取值与之前的硬编码完全一致。
BPF_DIR="${HNC_BPF_TETHER_DIR:-/sys/fs/bpf/tethering}"
P="$BPF_DIR/map_offload_tether_stats_map"
LIMIT_MAP="$BPF_DIR/map_offload_tether_limit_map"
THRESHOLD=1048576   # 1 MB,5 秒内增长低于这个值就不算 ACTIVE

[ -f "$P" ] || { echo NOMAP; exit 0; }

# 读出所有 entry 的 rxBytes + txBytes 总和。
# 如果 stats_map 是空的,grep '^[0-9]' 不会匹配任何行,awk END 输出 0。
read_total() {
    cat "$P" 2>/dev/null \
      | grep '^[0-9]' \
      | tr ':{},' '    ' \
      | awk '{s+=$3+$6} END{print s+0}'
}

# ── v5.9.3 (BUG-005 ②): 静态能力探测 ────────────────────────────
# 背景: 上面的判定是流量门控的,用户"设了上行限速但当前没跑流量"时必然
# 落到 IDLE,状态行永远显示"未在转发",看不出这台机器到底有没有 offload
# 能力 —— 排障时分不清"没能力"和"有能力但此刻闲着"。
# 这里补一个不依赖流量的只读探测,命中任一条即认为具备/已挂载:
#   a) tc filter 链里挂着 AOSP 的 schedcls/tether_{upstream,downstream}{4,6}
#      程序 → offload 程序确实已经挂在网卡上
#   b) tether limit_map / stats_map 里已有 ifindex 条目 → 内核侧已经为某个
#      上游建过 offload 表项
# 严格只读。缺 tc、无权限、读不到都一律当作未命中(退回 IDLE),
# 绝不因为环境不全就报错退出 —— 这个脚本被 httpd 每 30s 拉一次,
# 它的 stdout 必须始终只有一个状态词。

# map 里有没有以 ifindex 开头的数据行
map_has_entry() {
    [ -f "$1" ] || return 1
    grep -q '^[0-9]' "$1" 2>/dev/null
}

# tc filter 链里有没有 AOSP tether offload 程序
tc_has_tether_prog() {
    command -v tc >/dev/null 2>&1 || return 1
    [ -d /sys/class/net ] || return 1
    for d in /sys/class/net/*; do
        [ -e "$d" ] || continue
        i=${d##*/}
        # 环回与隧道伪设备不可能挂 tether offload,跳过省几次 fork
        case "$i" in
            lo|sit*|tunl*|ip6tnl*|ip_vti*|ip6_vti*|dummy*|gre*|ip6gre*) continue ;;
        esac
        # AOSP 把 tether_{upstream,downstream}{4,6}_{ether,rawip} 挂在
        # clsact 的 ingress 上,tc filter show ... ingress 能看到程序名
        if tc filter show dev "$i" ingress 2>/dev/null \
             | grep -qE 'tether_(upstream|downstream)[46]'; then
            return 0
        fi
    done
    return 1
}

offload_capable() {
    tc_has_tether_prog && return 0
    map_has_entry "$LIMIT_MAP" && return 0
    map_has_entry "$P" && return 0
    return 1
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
elif offload_capable; then
    # 有能力/已挂载,但当前窗口没流量 —— 只更新状态行,不报警
    echo CAPABLE
else
    echo IDLE
fi
