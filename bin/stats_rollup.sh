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

MAC_NAMES_TMP=""
AGG_TMP=""
FILTER_TMP=""
RAW_PRUNE_TMP=""
DAILY_PRUNE_TMP=""
_raw_locked=0
_rollup_cleanup() {
    if [ "${_raw_locked:-0}" = "1" ]; then
        flock -u 8 8>&8 2>/dev/null || true
        exec 8>&- 2>/dev/null || true
        _raw_locked=0
    fi
    rm -f ${MAC_NAMES_TMP:+"$MAC_NAMES_TMP"} \
          ${AGG_TMP:+"$AGG_TMP"} \
          ${FILTER_TMP:+"$FILTER_TMP"} \
          ${RAW_PRUNE_TMP:+"$RAW_PRUNE_TMP"} \
          ${DAILY_PRUNE_TMP:+"$DAILY_PRUNE_TMP"} 2>/dev/null || true
}
trap '_rollup_cleanup' EXIT
trap '_rollup_cleanup; trap - EXIT; exit 130' INT
trap '_rollup_cleanup; trap - EXIT; exit 143' TERM

if [ -z "$SKIP_STATS" ]; then
log "rollup for $TARGET_DATE"
_raw_bytes=$(wc -c < "$RAW_FILE" 2>/dev/null | tr -dc '0-9')
if uint_gt "${_raw_bytes:-0}" "2147483647"; then
    log "WARN: $RAW_FILE exceeds 2.14GB (${_raw_bytes} bytes), processing with 64-bit float awk"
fi

# ═══════════════════════════════════════════════════════════════
# 1. 先构建 MAC → name 映射(给输出的 daily 行加可读名, 识别 \" 与 \\ 转义)
# ═══════════════════════════════════════════════════════════════
MAC_NAMES_TMP="$HNC_DIR/run/rollup_names.$$"
mkdir -p "$HNC_DIR/run" 2>/dev/null
: > "$MAC_NAMES_TMP"

# device_names.json (扁平 {"mac":"name",...}) — 识别 \" 等转义序列
if [ -f "$NAMES_FILE" ]; then
    awk '
    function ch(i){ return substr(s, i, 1) }
    function skip_ws(i){ while (i <= n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function parse_string(i,   j, c, out, esc) {
        out = ""; esc = 0
        if (ch(i) != "\"") return 0
        for (j = i + 1; j <= n; j++) {
            c = ch(j)
            if (esc) {
                if (c == "n" || c == "r" || c == "t" || c == "b" || c == "f") out = out " "
                else out = out c
                esc = 0
                continue
            }
            if (c == "\\") { esc = 1; continue }
            if (c == "\"") { str_val = out; return j + 1 }
            if (c == "\t" || c == "\r" || c == "\n") out = out " "
            else if (c >= " " && c != sprintf("%c", 127)) out = out c
        }
        return 0
    }
    function skip_val(i,   j, c, dep, ins, esc, ni) {
        i = skip_ws(i); c = ch(i)
        if (c == "\"") { ni = parse_string(i); return ni ? ni : n + 1 }
        if (c == "{" || c == "[") {
            dep = 0; ins = 0; esc = 0
            for (j = i; j <= n; j++) {
                c = ch(j)
                if (ins) { if (esc) esc = 0; else if (c == "\\") esc = 1; else if (c == "\"") ins = 0; continue }
                if (c == "\"") { ins = 1; continue }
                if (c == "{" || c == "[") dep++
                else if (c == "}" || c == "]") { dep--; if (dep <= 0) return j + 1 }
            }
            return n + 1
        }
        for (j = i; j <= n; j++) { c = ch(j); if (c == "," || c == "}" || c == "]" || c ~ /[ \t\r\n]/) return j }
        return n + 1
    }
    BEGIN { s = "" }
    { s = s $0 "\n" }
    END {
        n = length(s); i = skip_ws(1)
        if (ch(i) != "{") exit 0
        i++
        while (i <= n) {
            i = skip_ws(i); c = ch(i)
            if (c == "}" || c == "") break
            if (c == ",") { i++; continue }
            if (c != "\"") break
            ni = parse_string(i); if (!ni) break
            k = tolower(str_val); i = skip_ws(ni)
            if (ch(i) != ":") break
            i = skip_ws(i + 1)
            if (ch(i) == "\"") {
                ni = parse_string(i); if (!ni) break
                v = str_val; i = ni
                if (k ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && v != "") print k "\t" v
            } else {
                i = skip_val(i)
            }
        }
    }' "$NAMES_FILE" >> "$MAC_NAMES_TMP" 2>/dev/null
fi

# devices.json hostname 兜底(不覆盖已有的 manual, 识别字符串转义与花括号嵌套)
if [ -f "$DEVICES_FILE" ]; then
    awk -v existing="$MAC_NAMES_TMP" '
    function ch(i){ return substr(s, i, 1) }
    function skip_ws(i){ while (i <= n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function parse_string(i,   j, c, out, esc) {
        out = ""; esc = 0
        if (ch(i) != "\"") return 0
        for (j = i + 1; j <= n; j++) {
            c = ch(j)
            if (esc) {
                if (c == "n" || c == "r" || c == "t" || c == "b" || c == "f") out = out " "
                else out = out c
                esc = 0
                continue
            }
            if (c == "\\") { esc = 1; continue }
            if (c == "\"") { str_val = out; return j + 1 }
            if (c == "\t" || c == "\r" || c == "\n") out = out " "
            else if (c >= " " && c != sprintf("%c", 127)) out = out c
        }
        return 0
    }
    function skip_val(i,   j, c, dep, ins, esc, ni) {
        i = skip_ws(i); c = ch(i)
        if (c == "\"") { ni = parse_string(i); return ni ? ni : n + 1 }
        if (c == "{" || c == "[") {
            dep = 0; ins = 0; esc = 0
            for (j = i; j <= n; j++) {
                c = ch(j)
                if (ins) { if (esc) esc = 0; else if (c == "\\") esc = 1; else if (c == "\"") ins = 0; continue }
                if (c == "\"") { ins = 1; continue }
                if (c == "{" || c == "[") dep++
                else if (c == "}" || c == "]") { dep--; if (dep <= 0) return j + 1 }
            }
            return n + 1
        }
        for (j = i; j <= n; j++) { c = ch(j); if (c == "," || c == "}" || c == "]" || c ~ /[ \t\r\n]/) return j }
        return n + 1
    }
    function extract_hostname(os, oe,   p, c, ni, fk) {
        p = skip_ws(os + 1)
        while (p < oe) {
            p = skip_ws(p); c = ch(p)
            if (c == "}" || c == "") return ""
            if (c == ",") { p++; continue }
            if (c != "\"") return ""
            ni = parse_string(p); if (!ni) return ""
            fk = str_val; p = skip_ws(ni)
            if (ch(p) != ":") return ""
            p = skip_ws(p + 1)
            if (fk == "hostname" && ch(p) == "\"") {
                ni = parse_string(p)
                return ni ? str_val : ""
            }
            p = skip_val(p)
        }
        return ""
    }
    BEGIN {
        while ((getline line < existing) > 0) {
            t = index(line, "\t")
            if (t > 1) have[substr(line, 1, t - 1)] = 1
        }
        close(existing)
        s = ""
    }
    { s = s $0 "\n" }
    END {
        n = length(s); i = skip_ws(1)
        if (ch(i) != "{") exit 0
        i++
        while (i <= n) {
            i = skip_ws(i); c = ch(i)
            if (c == "}" || c == "") break
            if (c == ",") { i++; continue }
            if (c != "\"") break
            ni = parse_string(i); if (!ni) break
            k = tolower(str_val); i = skip_ws(ni)
            if (ch(i) != ":") break
            i = skip_ws(i + 1)
            ve = skip_val(i)
            if (k ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && ch(i) == "{" && !(k in have)) {
                hn = extract_hostname(i, ve)
                if (hn != "") {
                    have[k] = 1
                    print k "\t" hn
                }
            }
            i = ve
        }
    }' "$DEVICES_FILE" >> "$MAC_NAMES_TMP" 2>/dev/null
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
    exit 1
fi

AGG_TMP="$HNC_DIR/run/rollup_agg.$$"
awk -v ds="$DATE_START" -v de="$DATE_END" -v target="$TARGET_DATE" \
    -v namesfile="$MAC_NAMES_TMP" '
BEGIN {
    ds = ds + 0
    de = de + 0
    while ((getline line < namesfile) > 0) {
        t = index(line, "\t")
        if (t > 1) names[substr(line, 1, t - 1)] = substr(line, t + 1)
    }
    close(namesfile)
}
{
    if (!match($0, /"ts"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    ts = s + 0
    if (ts > de) next

    if (!match($0, /"mac"[[:space:]]*:[[:space:]]*"[^"]*"/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
    mac = s

    if (!match($0, /"rx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    rx_cur = s + 0

    if (!match($0, /"tx"[[:space:]]*:[[:space:]]*[0-9]+/)) next
    s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
    tx_cur = s + 0

    if (ts < ds) {
        if (!(mac in pre_ts) || ts >= pre_ts[mac]) {
            pre_ts[mac] = ts
            pre_rx[mac] = rx_cur
            pre_tx[mac] = tx_cur
        }
        next
    }

    if (!(mac in last_rx) && (mac in pre_rx)) {
        last_rx[mac] = pre_rx[mac]
        last_tx[mac] = pre_tx[mac]
    }

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
        if [ "$_grc" -le 1 ] && cat "$AGG_TMP" >> "$FILTER_TMP" 2>/dev/null && mv -f "$FILTER_TMP" "$DAILY_FILE"; then
            FILTER_TMP=""
        else
            log "ERROR: failed to update $DAILY_FILE (grep_rc=$_grc), keeping existing file"
            rm -f "$FILTER_TMP" 2>/dev/null || true
            FILTER_TMP=""
            exit 1
        fi
    else
        FILTER_TMP="${DAILY_FILE}.new.$$"
        if cp "$AGG_TMP" "$FILTER_TMP" 2>/dev/null && mv -f "$FILTER_TMP" "$DAILY_FILE"; then
            FILTER_TMP=""
        else
            log "ERROR: failed to create $DAILY_FILE"
            rm -f "$FILTER_TMP" 2>/dev/null || true
            FILTER_TMP=""
            exit 1
        fi
    fi
fi
rm -f "$AGG_TMP" "$MAC_NAMES_TMP"
AGG_TMP=""; MAC_NAMES_TMP=""

# ═══════════════════════════════════════════════════════════════
# 4. 清理 raw: 只保留最近 RAW_RETAIN_HOURS 小时 (与 stats_sample 追加共享 flock 互斥)
# ═══════════════════════════════════════════════════════════════
NOW_TS=$(date +%s 2>/dev/null || echo 0)
CUTOFF=$(awk -v now="$NOW_TS" -v h="$RAW_RETAIN_HOURS" 'BEGIN { printf "%.0f\n", (now + 0) - (h + 0) * 3600 }')
RAW_PRUNE_TMP="${RAW_FILE}.prune.$$"
STATS_RAW_LOCK="$HNC_DIR/run/stats_raw.lock"
_raw_locked=0
if command -v flock >/dev/null 2>&1 && ( exec 8>"$STATS_RAW_LOCK" ) 2>/dev/null; then
    exec 8>"$STATS_RAW_LOCK"
    if flock -x 8 8>&8 2>/dev/null; then
        _raw_locked=1
    else
        exec 8>&- 2>/dev/null || true
    fi
fi
if awk -v cutoff="$CUTOFF" '
BEGIN { cutoff = cutoff + 0 }
{
    if (match($0, /"ts"[[:space:]]*:[[:space:]]*[0-9]+/)) {
        s = substr($0, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", s)
        if ((s + 0) >= cutoff) print
    }
}' "$RAW_FILE" > "$RAW_PRUNE_TMP" && mv -f "$RAW_PRUNE_TMP" "$RAW_FILE"; then
    RAW_PRUNE_TMP=""
fi
if [ "$_raw_locked" = "1" ]; then
    flock -u 8 8>&8 2>/dev/null || true
    exec 8>&- 2>/dev/null || true
    _raw_locked=0
fi

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
        DAILY_PRUNE_TMP="${DAILY_FILE}.prune.$$"
        if awk -v cutoff="$CUTOFF_DATE" '
        {
            if (match($0, /"date"[[:space:]]*:[[:space:]]*"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/.*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
                if (s >= cutoff) print
            }
        }' "$DAILY_FILE" > "$DAILY_PRUNE_TMP" && mv "$DAILY_PRUNE_TMP" "$DAILY_FILE"; then
            DAILY_PRUNE_TMP=""
        fi
    fi
fi

fi  # end: if [ -z "$SKIP_STATS" ]

# ═══════════════════════════════════════════════════════════════
# v4.0 Patch 1.6 + P1-31: 日志备份(后台异步 + 独立超时, 关闭继承 stdio/fd,
# 避免 stats_sample.sh:89 同步等待大体积 logs 打包撞看门狗 15s 超时!)
# ═══════════════════════════════════════════════════════════════
BACKUP_RETAIN_DAYS=${BACKUP_RETAIN_DAYS:-7}
LOGS_DIR="$HNC_DIR/logs"
BACKUP_ROOT="$HNC_DIR/data"
TODAY=$(date +%Y%m%d)
BACKUP_DIR="$BACKUP_ROOT/.backup-$TODAY"

if [ -d "$LOGS_DIR" ]; then
    (
        exec </dev/null >/dev/null 2>&1
        exec 8>&- 9>&- 2>/dev/null || true
        mkdir -p "$BACKUP_DIR" 2>/dev/null || exit 0
        chmod 700 "$BACKUP_DIR" 2>/dev/null || true
        TARBALL="$BACKUP_DIR/logs.tar.gz"
        _bg_tar_tmp="$TARBALL.tmp.$$.$(date +%s 2>/dev/null || echo 0)"
        trap 'rm -f "$_bg_tar_tmp" 2>/dev/null || true' EXIT INT TERM
        _tar_ok=0
        if command -v timeout >/dev/null 2>&1 && timeout 1 true >/dev/null 2>&1; then
            timeout 25 tar czf "$_bg_tar_tmp" -C "$HNC_DIR" logs 2>/dev/null && _tar_ok=1
        elif command -v timeout >/dev/null 2>&1 && timeout -t 1 true >/dev/null 2>&1; then
            timeout -t 25 tar czf "$_bg_tar_tmp" -C "$HNC_DIR" logs 2>/dev/null && _tar_ok=1
        else
            tar czf "$_bg_tar_tmp" -C "$HNC_DIR" logs 2>/dev/null && _tar_ok=1
        fi
        if [ "$_tar_ok" = "1" ] && mv -f "$_bg_tar_tmp" "$TARBALL" 2>/dev/null; then
            _bg_tar_tmp=""
            log "logs backup created: $TARBALL ($(stat -c %s "$TARBALL" 2>/dev/null) bytes)"
        else
            rm -f "$_bg_tar_tmp" 2>/dev/null || true
        fi
        BACKUP_LIST=$(ls -d "$BACKUP_ROOT"/.backup-* 2>/dev/null | sort -r)
        n=0
        for dir in $BACKUP_LIST; do
            n=$((n + 1))
            if [ "$n" -gt "$BACKUP_RETAIN_DAYS" ]; then
                rm -rf "$dir" 2>/dev/null && log "logs backup pruned: $dir"
            fi
        done
    ) &
fi

exit 0
