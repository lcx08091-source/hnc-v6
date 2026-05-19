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

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
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

TARGET_DATE=${1:-$(date -d 'yesterday' +%Y-%m-%d 2>/dev/null)}
if [ -z "$TARGET_DATE" ]; then
    # date -d 在 toybox 不一定支持,fallback:根据当前时间戳减 86400
    now=$(date +%s)
    yesterday_ts=$((now - 86400))
    TARGET_DATE=$(date -d "@$yesterday_ts" +%Y-%m-%d 2>/dev/null)
fi
if [ -z "$TARGET_DATE" ]; then
    # 还不行的话用 awk 手动算
    TARGET_DATE=$(awk 'BEGIN { t = systime() - 86400; print strftime("%Y-%m-%d", t) }' 2>/dev/null)
fi
if [ -z "$TARGET_DATE" ]; then
    log "ERROR: cannot compute yesterday date (no date -d, no awk strftime)"
    exit 1
fi

# v4.0 Patch 1.6: raw 缺失时只跳过 stats 聚合,logs 备份仍要跑
# (装机前几天没 raw,但 logs 照样每日备份)
if [ ! -f "$RAW_FILE" ]; then
    log "raw file missing, skipping stats rollup (logs backup will still run)"
    SKIP_STATS=1
fi

if [ -z "$SKIP_STATS" ]; then
log "rollup for $TARGET_DATE"

# ═══════════════════════════════════════════════════════════════
# 1. 先构建 MAC → name 映射(给输出的 daily 行加可读名)
# ═══════════════════════════════════════════════════════════════
# 优先级:device_names.json(手动) > devices.json 的 hostname
# 仅用于友好显示,不是计算依据,失败时输出空串

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
        # 去重:只在 mac 还没有记录时加
        # 用 grep -E + 行首锚点(-F 不支持锚点)
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
    # awk 兜底
    DATE_START=$(awk -v d="$TARGET_DATE" 'BEGIN {
        split(d, a, "-")
        t = mktime(a[1]" "a[2]" "a[3]" 00 00 00")
        print t
    }')
    DATE_END=$((DATE_START + 86399))
fi

if [ -z "$DATE_START" ] || [ "$DATE_START" = "0" ]; then
    log "ERROR: cannot compute date range for $TARGET_DATE"
    rm -f "$MAC_NAMES_TMP"
    exit 1
fi

# 聚合输出(一行一台 mac)
AGG_TMP="$HNC_DIR/run/rollup_agg.$$"
awk -v ds="$DATE_START" -v de="$DATE_END" -v target="$TARGET_DATE" \
    -v namesfile="$MAC_NAMES_TMP" '
BEGIN {
    # 读 name 映射
    while ((getline line < namesfile) > 0) {
        split(line, a, "\t")
        if (a[1] != "") names[a[1]] = a[2]
    }
    close(namesfile)
}
# 解析 JSON 每行: {"ts":N,"mac":"..","rx":N,"tx":N}
# 不用完整 JSON 解析,靠字段位置确定的格式做 regex 提取
{
    # ts
    if (!match($0, /"ts"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    ts = s + 0
    if (ts < ds || ts > de) next

    # mac
    if (!match($0, /"mac"[[:space:]]*:[[:space:]]*"[^"]*"/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
    mac = s

    # rx
    if (!match($0, /"rx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    rx_cur = s + 0

    # tx
    if (!match($0, /"tx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    tx_cur = s + 0

    # 按 MAC 聚 delta(按时间顺序处理:因为 raw 是 append-only 按时间追加的)
    # 跳变 (cur < prev):delta=0,重置 prev = cur
    if (mac in last_rx) {
        d_rx = rx_cur - last_rx[mac]
        d_tx = tx_cur - last_tx[mac]
        if (d_rx < 0) d_rx = 0
        if (d_tx < 0) d_tx = 0
        sum_rx[mac] += d_rx
        sum_tx[mac] += d_tx
    }
    # 首次见此 mac: 不加 delta(prev 视为 0 等价于第一次采样 = 基线)
    last_rx[mac] = rx_cur
    last_tx[mac] = tx_cur
    seen[mac] = 1
}
END {
    for (mac in seen) {
        # 无流量的设备也输出 0(方便图表"某天没使用"可见)
        rx = sum_rx[mac] + 0
        tx = sum_tx[mac] + 0
        name = (mac in names) ? names[mac] : ""
        # 转义 name 的 " 和 \(JSON 安全)
        gsub(/\\/, "\\\\", name)
        gsub(/"/, "\\\"", name)
        printf "{\"date\":\"%s\",\"mac\":\"%s\",\"rx\":%d,\"tx\":%d,\"name\":\"%s\"}\n", \
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
        # 过滤掉已有的 target_date 记录,再追加新的
        FILTER_TMP="${DAILY_FILE}.filter.$$"
        grep -v "\"date\":\"$TARGET_DATE\"" "$DAILY_FILE" > "$FILTER_TMP" 2>/dev/null || : > "$FILTER_TMP"
        cat "$AGG_TMP" >> "$FILTER_TMP"
        mv "$FILTER_TMP" "$DAILY_FILE"
    else
        cp "$AGG_TMP" "$DAILY_FILE"
    fi
fi
rm -f "$AGG_TMP" "$MAC_NAMES_TMP"

# ═══════════════════════════════════════════════════════════════
# 4. 清理 raw: 只保留最近 RAW_RETAIN_HOURS 小时
# ═══════════════════════════════════════════════════════════════
NOW_TS=$(date +%s)
CUTOFF=$((NOW_TS - RAW_RETAIN_HOURS * 3600))
PRUNE_TMP="${RAW_FILE}.prune.$$"
awk -v cutoff="$CUTOFF" '
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
    CUTOFF_DATE=$(date -d "@$((NOW_TS - DAILY_RETAIN_DAYS * 86400))" +%Y-%m-%d 2>/dev/null)
    if [ -z "$CUTOFF_DATE" ]; then
        CUTOFF_DATE=$(awk -v t="$((NOW_TS - DAILY_RETAIN_DAYS * 86400))" \
            'BEGIN { print strftime("%Y-%m-%d", t) }' 2>/dev/null)
    fi
    if [ -n "$CUTOFF_DATE" ]; then
        PRUNE_TMP="${DAILY_FILE}.prune.$$"
        awk -v cutoff="$CUTOFF_DATE" '
        {
            if (match($0, /"date"[[:space:]]*:[[:space:]]*"[0-9]{4}-[0-9]{2}-[0-9]{2}"/)) {
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
