#!/system/bin/sh
# stats_sample.sh — HNC v3.9.1 周期采样器
#
# 每 5 min 从 iptables HNC_STATS 读累计字节,按 MAC 聚合后 append 到
# data/stats_raw.jsonl。Go 看门狗 bin/hnc_watchdog 按 duties.go statsSampleDue 节拍调用。
#
# 输出格式(单行 JSON,每行一条):
#   {"ts":<unix>,"mac":"aa:..","rx":<cum_bytes>,"tx":<cum_bytes>}
#
# 注意这里存的是**累计字节数**而非 delta,因为:
#   - 跨重启 / cleanup 归零导致的跳变,在 rollup 时用 max(0, cur-prev) 处理
#   - 累计值原子可读,delta 需要两次采样才有意义,进程崩溃后丢第一个样不易补
#
# rollup 时才把累计转成日聚合。见 stats_rollup.sh。

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

RAW_FILE="$HNC_DIR/data/stats_raw.jsonl"
DEVICES_FLAT="$HNC_DIR/run/devices.flat"
DEVICES_FILE="$HNC_DIR/data/devices.json"
LOG="$HNC_DIR/logs/stats.log"
IPT_MGR="$HNC_DIR/bin/iptables_manager.sh"

# 可通过环境变量覆盖用于测试（直接执行，不使用 eval）
STATS_ALL_CMD=${STATS_ALL_CMD:-""}

_run_stats_all() {
  if [ -n "$STATS_ALL_CMD" ]; then
    # shellcheck disable=SC2086
    $STATS_ALL_CMD
  else
    sh "$IPT_MGR" stats_all
  fi
}

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [STATS] $*" >> "$LOG" 2>/dev/null || true
}

mkdir -p "$(dirname "$RAW_FILE")" "$HNC_DIR/run" 2>/dev/null

# ═══════════════════════════════════════════════════════════════
# 0a. 时钟可信闸门前置(不可信时严禁写采样或写 stats_last_date, 保 test_hnc_clock.sh:67)
# ═══════════════════════════════════════════════════════════════
ts=""
CLOCK_JUMPED=""
if [ -f "$HNC_DIR/bin/hnc_clock.sh" ]; then
    . "$HNC_DIR/bin/hnc_clock.sh"
    ts=$(hnc_clock_now)
    [ -z "$ts" ] && { log "WARN: date +%s failed"; exit 1; }
    if ! hnc_clock_sane "$ts"; then
        log "WARN: clock not trustworthy (ts=$ts high_water=$(hnc_clock_hwm)), sample skipped"
        exit 0
    fi
    if _jd=$(hnc_clock_jump stats_sample "$ts"); then
        CLOCK_JUMPED=$_jd
        log "clock jumped ${_jd}s vs uptime since last sample"
    fi
    hnc_clock_note "$ts"
else
    ts=$(date +%s 2>/dev/null)
    [ -z "$ts" ] && { log "WARN: date +%s failed"; exit 1; }
fi

MARKER="$HNC_DIR/run/stats_last_date"

# _check_daily_rollup <write_if_missing>:
# 空载退出前($1=0)若存在昨日 stats_last_date 且已跨零点, 照常触发 stats_rollup.sh 防止昨日柱图归零;
# 有实际采样落盘后($1=1)同时在首次运行时初始化 stats_last_date。
_check_daily_rollup() {
    local _init_marker="${1:-0}" today last_date _update_marker=0 _rrc
    today=$(date -d "@$ts" +%Y-%m-%d 2>/dev/null)
    [ -z "$today" ] && today=$(date +%Y-%m-%d 2>/dev/null)
    last_date=$(cat "$MARKER" 2>/dev/null)
    if [ -n "$today" ] && [ -n "$last_date" ] && [ "$today" != "$last_date" ]; then
        [ -n "$CLOCK_JUMPED" ] && log "note: date change coincides with a clock jump (${CLOCK_JUMPED}s)"
        log "date changed: $last_date -> $today, triggering rollup"
        if sh "$HNC_DIR/bin/stats_rollup.sh" "$last_date" >> "$LOG" 2>&1; then
            _update_marker=1
        else
            _rrc=$?
            _update_marker=0
            log "WARN: rollup failed (rc=$_rrc), keeping stats_last_date=$last_date for retry"
        fi
    elif [ "$_init_marker" = "1" ]; then
        _update_marker=1
    fi
    if [ "$_update_marker" = "1" ] && [ -n "$today" ]; then
        echo "$today" > "$MARKER" 2>/dev/null
    fi
}

# ═══════════════════════════════════════════════════════════════
# 0b. 对齐 HNC_STATS 的 per-IP 计数规则(rc46)
# ═══════════════════════════════════════════════════════════════
if [ -z "$HNC_TEST_MODE" ] && [ -x "$IPT_MGR" ]; then
    sh "$IPT_MGR" ensure_stats_online >/dev/null 2>&1 || true
fi

# ═══════════════════════════════════════════════════════════════
# 1. 从 iptables 拿当前累计 stats(IP -> rx,tx)
# ═══════════════════════════════════════════════════════════════
stats_out=$(_run_stats_all 2>/dev/null)
if [ -z "$stats_out" ]; then
    _check_daily_rollup 0
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 2. 构建 IP -> MAC 映射(优先读 run/devices.flat, 回退单趟 awk 解析 devices.json, 消除逐设备 sed 风暴)
# ═══════════════════════════════════════════════════════════════
if [ ! -s "$DEVICES_FLAT" ] && [ ! -f "$DEVICES_FILE" ]; then
    log "WARN: devices.flat and devices.json missing, sample skipped"
    _check_daily_rollup 0
    exit 0
fi

if [ -s "$DEVICES_FLAT" ]; then
    ip_to_mac=$(awk '
        !/^[[:space:]]*(#|$)/ {
            mac = ""; ip = ""
            for (i = 1; i <= NF; i++) {
                tok = tolower($i)
                if (mac == "" && tok ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/) mac = tok
                else if (ip == "" && tok ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) ip = tok
            }
            if (ip != "" && mac != "") print ip, mac
        }
    ' "$DEVICES_FLAT" 2>/dev/null)
else
    ip_to_mac=$(awk '
        { s = s $0 " " }
        END {
            rest = s
            while (match(rest, /"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^{}]*\}/)) {
                blk = substr(rest, RSTART, RLENGTH)
                rest = substr(rest, RSTART + RLENGTH)
                mac = tolower(substr(blk, 2, 17))
                if (match(blk, /"ip"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                    ip = substr(blk, RSTART, RLENGTH)
                    sub(/.*"ip"[[:space:]]*:[[:space:]]*"/, "", ip)
                    sub(/"$/, "", ip)
                    if (ip != "") print ip, mac
                }
            }
        }
    ' "$DEVICES_FILE" 2>/dev/null)
fi

if [ -z "$ip_to_mac" ]; then
    _check_daily_rollup 0
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 3. 按 MAC 聚合(同一 MAC 多个 IP 的字节相加)
# ═══════════════════════════════════════════════════════════════
MAP_TMP="$HNC_DIR/run/stats_map.$$"
printf '%s\n' "$ip_to_mac" > "$MAP_TMP"
trap 'rm -f "$MAP_TMP" 2>/dev/null' EXIT INT TERM

aggregated=$(echo "$stats_out" | awk -v mapfile="$MAP_TMP" -v ts="$ts" '
BEGIN {
    while ((getline line < mapfile) > 0) {
        split(line, a, " ")
        if (a[1] != "" && a[2] != "") ip2mac[a[1]] = a[2]
    }
    close(mapfile)
}
$1 != "" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
    mac = ip2mac[$1]
    if (mac == "") next
    rx[mac] += ($2 + 0)
    tx[mac] += ($3 + 0)
}
END {
    for (mac in rx) {
        printf "{\"ts\":%.0f,\"mac\":\"%s\",\"rx\":%.0f,\"tx\":%.0f}\n", ts + 0, mac, rx[mac], tx[mac]
    }
}
')

rm -f "$MAP_TMP" 2>/dev/null

if [ -z "$aggregated" ]; then
    # 所有 IP 都没在 devices.json 找到 MAC,或者所有字节都是 0
    # 不写空采样,但检查跨零点归档后退出
    _check_daily_rollup 0
    exit 0
fi

# ═══════════════════════════════════════════════════════════════
# 4. Append 到 raw 文件
# ═══════════════════════════════════════════════════════════════
# 用 >> 追加,不做原子写:单次采样丢失 / 半写可接受(rollup 容忍部分损坏行)。
# 追加操作在 POSIX 下对 < 4KB 是原子的,我们一次最多 50 台 × ~80 字节 ≈ 4KB,
# 边界情况下可能有部分行损坏,awk rollup 会跳过不合法的行。

echo "$aggregated" >> "$RAW_FILE"

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
_check_daily_rollup 1

exit 0
