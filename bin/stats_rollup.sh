#!/system/bin/sh
# stats_rollup.sh — HNC v3.9.1 日聚合脚本
#
# 用法:
#   stats_rollup.sh <YYYY-MM-DD>    聚合指定日期,通常是昨天
#   stats_rollup.sh                 聚合昨天(默认)
#
# 输入: data/stats_raw.jsonl      (累计字节采样,每 5 min 一条)
# 输出: data/stats_daily.jsonl    (每日 delta,每 MAC 一条)
#
# 算法:
# 1. 从 raw 里筛出 target_date 的所有行,按 MAC 分组,时间排序
# 2. 对每个 MAC: 当天 delta = max(0, cur - prev) 的累加
#    其中 prev:
#      - 第一个采样点: prev = 0(当天没历史 → 从 0 算起,保守估计低于真值)
#      - 之后的采样点: prev = 上一条的 cur
#      - 跳变(cur < prev): delta = 0,prev 更新为 cur(从新累计起点继续)
# 3. 每 MAC 输出一行 {"date":"YYYY-MM-DD","mac":"..","rx":N,"tx":N,"name":".."} 到 daily
# 4. 清理 raw: 保留 < 48 小时内的采样点,删掉更早的(给下次 rollup 留安全边界)
# 5. 清理 daily: 保留最近 90 天

HNC_DIR=${HNC_DIR:-/data/local/hnc}

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
DAILY_FILE="$HNC_DIR/data/stats_daily.jsonl"
DEVICES_FILE="$HNC_DIR/data/devices.json"
NAMES_FILE="$HNC_DIR/data/device_names.json"
LOG="$HNC_DIR/logs/stats.log"

RAW_RETAIN_HOURS=${RAW_RETAIN_HOURS:-48}    # raw 保留窗口
DAILY_RETAIN_DAYS=${DAILY_RETAIN_DAYS:-90}  # daily 保留窗口

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ROLLUP] $*" >> "$LOG" 2>/dev/null || true
}

# 纯 POSIX awk 儒略日/格里高利历 <-> Unix 纪元秒换算(兼容 Android 15/16 one-true-awk)
_tz_offset_str() {
    date +%z 2>/dev/null || echo "+0000"
}

epoch_to_ymd_posix() {
    awk -v ts="${1:-0}" -v tz="$(_tz_offset_str)" 'BEGIN {
        off = 0
        if (tz ~ /^[+-][0-9][0-9][0-9][0-9]$/) {
            sgn = (substr(tz, 1, 1) == "-") ? -1 : 1
            off = sgn * ((substr(tz, 2, 2) + 0) * 3600 + (substr(tz, 4, 2) + 0) * 60)
        }
        lt = (ts + 0) + off
        z = int(lt >= 0 ? lt / 86400 : (lt - 86399) / 86400) + 719468
        era = int((z >= 0 ? z : z - 146096) / 146097)
        doe = z - era * 146097
        yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
        y = yoe + era * 400
        doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
        mp = int((5 * doy + 2) / 153)
        d = doy - int((153 * mp + 2) / 5) + 1
        m = mp + (mp < 10 ? 3 : -9)
        if (m <= 2) y = y + 1
        printf "%04d-%02d-%02d\n", y, m, d
    }'
}

ymd_to_start_epoch_posix() {
    awk -v ymd="$1" -v tz="$(_tz_offset_str)" 'BEGIN {
        if (split(ymd, a, "-") != 3) exit 1
        y = a[1] + 0; m = a[2] + 0; d = a[3] + 0
        off = 0
        if (tz ~ /^[+-][0-9][0-9][0-9][0-9]$/) {
            sgn = (substr(tz, 1, 1) == "-") ? -1 : 1
            off = sgn * ((substr(tz, 2, 2) + 0) * 3600 + (substr(tz, 4, 2) + 0) * 60)
        }
        yr = y - (m <= 2 ? 1 : 0)
        era = int((yr >= 0 ? yr : yr - 399) / 400)
        yoe = yr - era * 400
        mo = m + (m > 2 ? -3 : 9)
        doy = int((153 * mo + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        days = era * 146097 + doe - 719468
        printf "%.0f\n", days * 86400 - off
    }'
}

uint_gt() {
    _ug_a="${1:-0}"; _ug_b="${2:-0}"
    case "$_ug_a" in ''|*[!0-9]*) _ug_a=0 ;; esac
    case "$_ug_b" in ''|*[!0-9]*) _ug_b=0 ;; esac
    while [ "${_ug_a#0}" != "$_ug_a" ]; do _ug_a=${_ug_a#0}; done; [ -n "$_ug_a" ] || _ug_a=0
    while [ "${_ug_b#0}" != "$_ug_b" ]; do _ug_b=${_ug_b#0}; done; [ -n "$_ug_b" ] || _ug_b=0
    [ "${#_ug_a}" -gt "${#_ug_b}" ] && return 0
    [ "${#_ug_a}" -lt "${#_ug_b}" ] && return 1
    awk 'BEGIN { exit !(ARGV[1] > ARGV[2]) }' "$_ug_a" "$_ug_b"
}

# v5.20: 时钟不可信时整轮跳过 —— raw/daily 保留期清理用当前时间算截止点(跑到
# 未来的时钟会把历史全删), .backup-YYYYMMDD 也会用错的日期。见 hnc_clock.sh。
if [ -f "$HNC_DIR/bin/hnc_clock.sh" ]; then
    . "$HNC_DIR/bin/hnc_clock.sh"
    if ! hnc_clock_sane; then
        log "clock not trustworthy (now=$(date +%s 2>/dev/null) high_water=$(hnc_clock_hwm)), rollup skipped"
        exit 0
    fi
fi

TARGET_DATE=${1:-$(date -d 'yesterday' +%Y-%m-%d 2>/dev/null)}
if [ -z "$TARGET_DATE" ]; then
    now=$(date +%s 2>/dev/null || echo 0)
    yesterday_ts=$(awk -v n="$now" 'BEGIN { printf "%.0f\n", (n + 0) - 86400 }')
    TARGET_DATE=$(date -d "@$yesterday_ts" +%Y-%m-%d 2>/dev/null)
    [ -n "$TARGET_DATE" ] || TARGET_DATE=$(epoch_to_ymd_posix "$yesterday_ts" 2>/dev/null)
fi
if [ -z "$TARGET_DATE" ]; then
    log "ERROR: cannot compute yesterday date"
    exit 1
fi
if ! printf '%s' "$TARGET_DATE" | grep -Eq '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'; then
    log "ERROR: invalid TARGET_DATE '$TARGET_DATE' (expected YYYY-MM-DD)"
    exit 1
fi

# v4.0 Patch 1.6: raw 缺失时只跳过 stats 聚合,logs 备份仍要跑
if [ ! -f "$RAW_FILE" ]; then
    log "raw file missing, skipping stats rollup (logs backup will still run)"
    SKIP_STATS=1
fi

if [ -z "$SKIP_STATS" ]; then
log "rollup for $TARGET_DATE"
_raw_bytes=$(wc -c < "$RAW_FILE" 2>/dev/null | tr -dc '0-9')
if uint_gt "${_raw_bytes:-0}" "2147483647"; then
    log "WARN: $RAW_FILE exceeds 2.14GB (${_raw_bytes} bytes), processing with 64-bit float awk"
fi

# ═══════════════════════════════════════════════════════════════
# 1. 先构建 MAC → name 映射(给输出的 daily 行加可读名)
# ═══════════════════════════════════════════════════════════════
MAC_NAMES_TMP="$HNC_DIR/run/rollup_names.$$"
mkdir -p "$HNC_DIR/run" 2>/dev/null
: > "$MAC_NAMES_TMP"

# device_names.json (扁平 {"mac":"name",...})
if [ -f "$NAMES_FILE" ]; then
    grep -oE '"[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}"[[:space:]]*:[[:space:]]*"[^"]*"' "$NAMES_FILE" 2>/dev/null | \
    while IFS= read -r pair; do
        m=$(echo "$pair" | sed -nE 's/^"([0-9a-f:]+)".*/\1/p')
        n=$(echo "$pair" | sed -nE 's/.*:[[:space:]]*"([^"]*)".*/\1/p')
        [ -n "$m" ] && [ -n "$n" ] && echo "$m	$n" >> "$MAC_NAMES_TMP"
    done
fi

# devices.json hostname 兜底(不覆盖已有的 manual)
if [ -f "$DEVICES_FILE" ]; then
    grep -oE '"([0-9a-f]{2}:){5}[0-9a-f]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$DEVICES_FILE" 2>/dev/null | \
    while IFS= read -r block; do
        m=$(echo "$block" | sed -nE 's/^"([0-9a-f:]+)".*/\1/p')
        h=$(echo "$block" | sed -nE 's/.*"hostname"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')
        [ -z "$m" ] && continue
        [ -z "$h" ] && continue
        if ! grep -qE "^${m}	" "$MAC_NAMES_TMP" 2>/dev/null; then
            echo "$m	$h" >> "$MAC_NAMES_TMP"
        fi
    done
fi

# ═══════════════════════════════════════════════════════════════
# 2. awk 处理 raw: 筛 target_date,按 MAC 分组,算 delta
# ═══════════════════════════════════════════════════════════════

DATE_START=$(date -d "$TARGET_DATE 00:00:00" +%s 2>/dev/null)
DATE_END=$(date -d "$TARGET_DATE 23:59:59" +%s 2>/dev/null)
if [ -z "$DATE_START" ] || [ -z "$DATE_END" ]; then
    DATE_START=$(ymd_to_start_epoch_posix "$TARGET_DATE" 2>/dev/null)
    [ -n "$DATE_START" ] && DATE_END=$(awk -v ds="$DATE_START" 'BEGIN { printf "%.0f\n", (ds + 0) + 86399 }')
fi

if [ -z "$DATE_START" ] || [ "$DATE_START" = "0" ]; then
    log "ERROR: cannot compute date range for $TARGET_DATE"
    rm -f "$MAC_NAMES_TMP"
    exit 1
fi

AGG_TMP="$HNC_DIR/run/rollup_agg.$$"
awk -v ds="$DATE_START" -v de="$DATE_END" -v target="$TARGET_DATE" \
    -v namesfile="$MAC_NAMES_TMP" '
BEGIN {
    ds = ds + 0
    de = de + 0
    while ((getline line < namesfile) > 0) {
        split(line, a, "\t")
        if (a[1] != "") names[a[1]] = a[2]
    }
    close(namesfile)
}
{
    if (!match($0, /"ts"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    ts = s + 0
    if (ts < ds || ts > de) next

    if (!match($0, /"mac"[[:space:]]*:[[:space:]]*"[^"]*"/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
    mac = s

    if (!match($0, /"rx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    rx_cur = s + 0

    if (!match($0, /"tx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    tx_cur = s + 0

    if (mac in last_rx) {
        d_rx = rx_cur - last_rx[mac]
        d_tx = tx_cur - last_tx[mac]
        if (d_rx < 0) d_rx = 0
        if (d_tx < 0) d_tx = 0
        sum_rx[mac] += d_rx
        sum_tx[mac] += d_tx
    }
    last_rx[mac] = rx_cur
    last_tx[mac] = tx_cur
    seen[mac] = 1
}
END {
    for (mac in seen) {
        rx = sum_rx[mac] + 0
        tx = sum_tx[mac] + 0
        name = (mac in names) ? names[mac] : ""
        gsub(/\\/, "\\\\", name)
        gsub(/"/, "\\\"", name)
        printf "{\"date\":\"%s\",\"mac\":\"%s\",\"rx\":%.0f,\"tx\":%.0f,\"name\":\"%s\"}\n", \
            target, mac, rx, tx, name
    }
}' "$RAW_FILE" > "$AGG_TMP"

agg_count=$(wc -l < "$AGG_TMP" 2>/dev/null | tr -d ' ')
log "aggregated $agg_count device-days for $TARGET_DATE"

# ═══════════════════════════════════════════════════════════════
# 3. Append 到 daily,但先去重(可能之前已经跑过同一天的 rollup)
# ═══════════════════════════════════════════════════════════════
if [ -s "$AGG_TMP" ]; then
    if [ -f "$DAILY_FILE" ]; then
        FILTER_TMP="${DAILY_FILE}.filter.$$"
        grep -Fv "\"date\":\"$TARGET_DATE\"" "$DAILY_FILE" > "$FILTER_TMP" 2>/dev/null
        _grc=$?
        if [ "$_grc" -le 1 ] && cat "$AGG_TMP" >> "$FILTER_TMP" 2>/dev/null; then
            mv -f "$FILTER_TMP" "$DAILY_FILE"
        else
            log "ERROR: failed to update $DAILY_FILE (grep_rc=$_grc), keeping existing file"
            rm -f "$FILTER_TMP" 2>/dev/null || true
        fi
    else
        FILTER_TMP="${DAILY_FILE}.new.$$"
        if cp "$AGG_TMP" "$FILTER_TMP" 2>/dev/null; then
            mv -f "$FILTER_TMP" "$DAILY_FILE"
        else
            rm -f "$FILTER_TMP" 2>/dev/null || true
        fi
    fi
fi
rm -f "$AGG_TMP" "$MAC_NAMES_TMP"

# ═══════════════════════════════════════════════════════════════
# 4. 清理 raw: 只保留最近 RAW_RETAIN_HOURS 小时
# ═══════════════════════════════════════════════════════════════
NOW_TS=$(date +%s 2>/dev/null || echo 0)
CUTOFF=$(awk -v now="$NOW_TS" -v h="$RAW_RETAIN_HOURS" 'BEGIN { printf "%.0f\n", (now + 0) - (h + 0) * 3600 }')
PRUNE_TMP="${RAW_FILE}.prune.$$"
awk -v cutoff="$CUTOFF" '
BEGIN { cutoff = cutoff + 0 }
{
    if (match($0, /"ts"[[:space:]]*:[[:space:]]*[0-9]+/)) {
        s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
        if ((s + 0) >= cutoff) print
    }
}' "$RAW_FILE" > "$PRUNE_TMP" && mv "$PRUNE_TMP" "$RAW_FILE"

raw_after=$(wc -l < "$RAW_FILE" 2>/dev/null | tr -d ' ')
log "raw pruned: $raw_after lines remain (> $RAW_RETAIN_HOURS h)"

# ═══════════════════════════════════════════════════════════════
# 5. 清理 daily: 保留最近 DAILY_RETAIN_DAYS 天
# ═══════════════════════════════════════════════════════════════
if [ -f "$DAILY_FILE" ]; then
    DAILY_CUTOFF_TS=$(awk -v now="$NOW_TS" -v d="$DAILY_RETAIN_DAYS" 'BEGIN { printf "%.0f\n", (now + 0) - (d + 0) * 86400 }')
    CUTOFF_DATE=$(date -d "@$DAILY_CUTOFF_TS" +%Y-%m-%d 2>/dev/null)
    [ -n "$CUTOFF_DATE" ] || CUTOFF_DATE=$(epoch_to_ymd_posix "$DAILY_CUTOFF_TS" 2>/dev/null)
    if [ -n "$CUTOFF_DATE" ]; then
        PRUNE_TMP="${DAILY_FILE}.prune.$$"
        awk -v cutoff="$CUTOFF_DATE" '
        {
            if (match($0, /"date"[[:space:]]*:[[:space:]]*"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
                if (s >= cutoff) print
            }
        }' "$DAILY_FILE" > "$PRUNE_TMP" && mv "$PRUNE_TMP" "$DAILY_FILE"
    fi
fi

fi  # end: if [ -z "$SKIP_STATS" ]

# ═══════════════════════════════════════════════════════════════
# v4.0 Patch 1.6: 日志备份(跟 stats rollup 一起做,每日一次)
# logs/ 打 tar.gz 存到 data/.backup-YYYYMMDD/,保留 7 天
# 轮转过的 .1 .2 已经存进 tarball,因此今天之前的 logs 都有备份
# ═══════════════════════════════════════════════════════════════
BACKUP_RETAIN_DAYS=${BACKUP_RETAIN_DAYS:-7}
LOGS_DIR="$HNC_DIR/logs"
BACKUP_ROOT="$HNC_DIR/data"
TODAY=$(date +%Y%m%d)
BACKUP_DIR="$BACKUP_ROOT/.backup-$TODAY"

if [ -d "$LOGS_DIR" ]; then
    mkdir -p "$BACKUP_DIR" 2>/dev/null
    # 每天覆盖写同一个 tarball(允许日内多次 rollup 不爆数量)
    TARBALL="$BACKUP_DIR/logs.tar.gz"
    tar czf "$TARBALL.tmp" -C "$HNC_DIR" logs 2>/dev/null && \
        mv "$TARBALL.tmp" "$TARBALL" && \
        log "logs backup created: $TARBALL ($(stat -c %s "$TARBALL" 2>/dev/null) bytes)"
    # rc3.1.14 修 P2-D (review): 备份策略统一 post-fs-data 的"按名字排序保留最新 N 个".
    # 之前 find -mtime +N 在用户调系统时间 (出国旅游 / NTP 异常) 时, 时间跳变可能误删今天的
    # 或误留 1 年前的. 按名字排序 (.backup-YYYYMMDD 字典序 ≈ 时间序) 不受时钟影响.
    BACKUP_LIST=$(ls -d "$BACKUP_ROOT"/.backup-* 2>/dev/null | sort -r)
    n=0
    for dir in $BACKUP_LIST; do
        n=$((n + 1))
        if [ "$n" -gt "$BACKUP_RETAIN_DAYS" ]; then
            rm -rf "$dir" 2>/dev/null && log "logs backup pruned: $dir"
        fi
    done
fi

exit 0
