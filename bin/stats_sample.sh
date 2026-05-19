#!/system/bin/sh
# stats_sample.sh — HNC v3.9.1 周期采样器
#
# 每 5 min 从 iptables HNC_STATS 读累计字节,按 MAC 聚合后 append 到
# data/stats_raw.jsonl。watchdog.sh 主循环在每轮末尾调一次。
#
# 输出格式(单行 JSON,每行一条):
#   {"ts":<unix>,"mac":"aa:..","rx":<cum_bytes>,"tx":<cum_bytes>}
#
# 注意这里存的是**累计字节数**而非 delta,因为:
#   - 跨重启 / cleanup 归零导致的跳变,在 rollup 时用 max(0, cur-prev) 处理
#   - 累计值原子可读,delta 需要两次采样才有意义,进程崩溃后丢第一个样不易补
#
# rollup 时才把累计转成日聚合。见 stats_rollup.sh。

# PATH 健壮性
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RAW_FILE="$HNC_DIR/data/stats_raw.jsonl"
DEVICES_FILE="$HNC_DIR/data/devices.json"
LOG="$HNC_DIR/logs/stats.log"
IPT_MGR="$HNC_DIR/bin/iptables_manager.sh"

# 可通过环境变量覆盖用于测试
STATS_ALL_CMD=${STATS_ALL_CMD:-"sh $IPT_MGR stats_all"}

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [STATS] $*" >> "$LOG" 2>/dev/null || true
}

mkdir -p "$(dirname "$RAW_FILE")" 2>/dev/null

# ═══════════════════════════════════════════════════════════════
# 1. 从 iptables 拿当前累计 stats(IP -> rx,tx)
# ═══════════════════════════════════════════════════════════════
# stats_all 输出格式: "<ip> <rx_bytes> <tx_bytes>",每行一台
# HNC_STATS 链没初始化的话 stats_all 输出空,直接退出,不写空采样

stats_out=$(eval "$STATS_ALL_CMD" 2>/dev/null)
if [ -z "$stats_out" ]; then
    # 热点没开 / iptables 链没建 / 没设备连接,都走这里,不算错误
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 2. 构建 IP -> MAC 映射(从 devices.json)
# ═══════════════════════════════════════════════════════════════
# devices.json 格式: {"mac":{"ip":"...","mac":"..",...}, ...}
# 只需要 ip 和 mac 两个字段,单行 JSON,awk 按 '":' 分块提即可。
# 设备下线但还没从 devices.json 清出去也没关系,MAC 还在就能用。

if [ ! -f "$DEVICES_FILE" ]; then
    log "WARN: devices.json missing, sample skipped"
    exit 0
fi

# 用 grep -oE 提出每个设备块,再用 sed 拆 mac / ip
# 为什么不用 awk while match:POSIX awk 的 match() 在循环里对 line=rest 的语义,
# 不同实现(gawk / busybox awk / toybox awk)行为微妙不同,真机用 toybox 最稳。
# grep -oE 走固定 regex,各平台一致。两步法稍慢但清晰可靠。
ip_to_mac=$(grep -oE '"([0-9a-f]{2}:){5}[0-9a-f]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$DEVICES_FILE" 2>/dev/null | \
while IFS= read -r block; do
    # block 形如 "aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:..","hostname":...}
    # 取 key(开头引号之间的 MAC)
    mac=$(echo "$block" | sed -nE 's/^"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})".*/\1/p')
    # 取 ip 字段值
    ip=$(echo "$block" | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')
    [ -n "$mac" ] && [ -n "$ip" ] && echo "$ip $mac"
done)

if [ -z "$ip_to_mac" ]; then
    # devices.json 存在但没设备,也是正常情况
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 3. 按 MAC 聚合(同一 MAC 多个 IP 的字节相加)
# ═══════════════════════════════════════════════════════════════
# stats_out: "<ip> <rx> <tx>"
# ip_to_mac: "<ip> <mac>"
# 用 awk 做 join:先读 ip_to_mac 建表,再读 stats_out 累加

ts=$(date +%s 2>/dev/null)
[ -z "$ts" ] && { log "WARN: date +%s failed"; exit 1; }

# 临时文件传 ip_to_mac 给 awk(避免 -v 二次转义)
MAP_TMP="$HNC_DIR/run/stats_map.$$"
printf '%s\n' "$ip_to_mac" > "$MAP_TMP"
trap 'rm -f "$MAP_TMP" 2>/dev/null' EXIT INT TERM

aggregated=$(echo "$stats_out" | awk -v mapfile="$MAP_TMP" -v ts="$ts" '
BEGIN {
    # 读 IP -> MAC 映射
    while ((getline line < mapfile) > 0) {
        split(line, a, " ")
        if (a[1] != "" && a[2] != "") ip2mac[a[1]] = a[2]
    }
    close(mapfile)
}
# stats_out: ip rx tx
$1 != "" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
    mac = ip2mac[$1]
    if (mac == "") next  # IP 没对应 MAC(可能是网关或已完全下线),跳过
    rx[mac] += $2
    tx[mac] += $3
}
END {
    for (mac in rx) {
        printf "{\"ts\":%d,\"mac\":\"%s\",\"rx\":%d,\"tx\":%d}\n", ts, mac, rx[mac], tx[mac]
    }
}
')

rm -f "$MAP_TMP" 2>/dev/null

if [ -z "$aggregated" ]; then
    # 所有 IP 都没在 devices.json 找到 MAC,或者所有字节都是 0
    # 不写空采样,直接退出
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 4. Append 到 raw 文件
# ═══════════════════════════════════════════════════════════════
# 用 >> 追加,不做原子写:单次采样丢失 / 半写可接受(rollup 容忍部分损坏行)。
# 追加操作在 POSIX 下对 < 4KB 是原子的,我们一次最多 50 台 × ~80 字节 ≈ 4KB,
# 边界情况下可能有部分行损坏,awk rollup 会跳过不合法的行。

echo "$aggregated" >> "$RAW_FILE"

# hotfix21.7: optional shadow stats stream for the v5.2 migration.
# Legacy stats remains the source of truth. Shadow stats only runs when one of
# these opt-in switches is present:
#   HNC_STATS_SHADOW_ENABLE=1
#   data/config.json {"stats_shadow_enabled":true}
#   run/stats_shadow.enabled created by stats_shadow_control.sh enable
shadow_enabled="${HNC_STATS_SHADOW_ENABLE:-}"
shadow_reason="env"
if [ -z "$shadow_enabled" ]; then
    shadow_reason="config"
    if [ -f "$HNC_DIR/data/config.json" ] && grep -q '"stats_shadow_enabled"[[:space:]]*:[[:space:]]*true' "$HNC_DIR/data/config.json" 2>/dev/null; then
        shadow_enabled=1
    fi
fi
if [ -z "$shadow_enabled" ]; then
    shadow_reason="flag"
    if [ -f "$HNC_DIR/run/stats_shadow.enabled" ]; then
        shadow_enabled=1
    fi
fi
case "$shadow_enabled" in
    1|true|TRUE|yes|YES)
        if [ -x "$HNC_DIR/bin/stats_shadow_sample.sh" ]; then
            sh "$HNC_DIR/bin/stats_shadow_sample.sh" >> "$LOG" 2>&1 || log "WARN: shadow sample failed (rc=$?)"
        else
            log "WARN: shadow enabled by $shadow_reason but stats_shadow_sample.sh missing"
        fi
        ;;
esac


# 设备数量(调试用,不常写日志避免 log 涨)
lines=$(echo "$aggregated" | wc -l)
# 每 12 轮(= 1 小时)写一次心跳日志
hour=$(( (ts / 300) % 12 ))
if [ "$hour" = "0" ]; then
    log "sampled $lines device(s) at $(date '+%H:%M')"
fi

# ═══════════════════════════════════════════════════════════════
# 5. 检测日期变化 → 触发 rollup(昨日 raw → daily)
# ═══════════════════════════════════════════════════════════════
# 跨日标志文件记录上次采样的日期。首次启动时没文件,跳过 rollup。

MARKER="$HNC_DIR/run/stats_last_date"
today=$(date +%Y-%m-%d 2>/dev/null)
last_date=$(cat "$MARKER" 2>/dev/null)

if [ -n "$today" ] && [ -n "$last_date" ] && [ "$today" != "$last_date" ]; then
    log "date changed: $last_date -> $today, triggering rollup"
    sh "$HNC_DIR/bin/stats_rollup.sh" "$last_date" >> "$LOG" 2>&1 || \
        log "WARN: rollup failed (rc=$?)"
fi
echo "$today" > "$MARKER" 2>/dev/null

exit 0
