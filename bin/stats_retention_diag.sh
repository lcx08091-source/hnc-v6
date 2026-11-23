#!/system/bin/sh
# HNC hotfix21.2 stats retention/config diagnostics helper
# Read-only checker for stats retention settings and file growth before v5.2.
# It never edits stats files, JSON files, tc, iptables, watchdog, or WebUI state.

set +e
HNC_DIR="${HNC_DIR:-${HNC:-/data/local/hnc}}"
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
  case "$_he" in /bin/hnc_env.sh) continue ;; esac
  if [ -f "$_he" ]; then . "$_he"; break; fi
done
unset _he
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
LOGS="$HNC_DIR/logs"
BIN="$HNC_DIR/bin"
RAW_FILE="${HNC_STATS_RAW_FILE:-$DATA/stats_raw.jsonl}"
DAILY_FILE="${HNC_STATS_DAILY_FILE:-$DATA/stats_daily.jsonl}"
ROLLUP_SH="${HNC_STATS_ROLLUP_SH:-$BIN/stats_rollup.sh}"
MODE="${1:-json}"

# Runtime knobs. These match stats_rollup.sh defaults unless overridden.
RAW_RETAIN_HOURS="${RAW_RETAIN_HOURS:-48}"
DAILY_RETAIN_DAYS="${DAILY_RETAIN_DAYS:-90}"
RAW_MAX_BYTES="${HNC_STATS_RAW_MAX_BYTES:-10485760}"       # 10 MiB soft warning
DAILY_MAX_BYTES="${HNC_STATS_DAILY_MAX_BYTES:-5242880}"    # 5 MiB soft warning
TAIL_SCAN_LINES="${HNC_STATS_RETENTION_SCAN_LINES:-20000}"

json_escape() {
  printf '%s' "$1" | tr '\r\n	' '   ' | awk '{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, " "); gsub(/\t/, " "); printf "%s", $0 }'
}

num_or_zero() {
  case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}

is_num() {
  case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

# 防 mksh 32 位有符号整数(>2.14GB)溢出的十进制无符号大于比较
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

file_size() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  _sz=$(stat -c %s "$f" 2>/dev/null | tr -dc '0-9')
  [ -n "$_sz" ] || _sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9')
  echo "${_sz:-0}"
}

line_count() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -l < "$f" 2>/dev/null | tr -d ' '
}

rollup_default() {
  case "$1" in
    RAW_RETAIN_HOURS) echo 48 ;;
    DAILY_RETAIN_DAYS) echo 90 ;;
    *) echo "" ;;
  esac
}

scan_raw() {
  f="$1"; cutoff="$2"; max_lines="$3"
  if [ ! -f "$f" ]; then
    echo "false 0 0 0 0 0 0"
    return
  fi
  tail -n "$max_lines" "$f" 2>/dev/null | awk -v cutoff="$cutoff" '
  BEGIN { cutoff = cutoff + 0 }
  function get_num(line, key,    r,s) {
    r="\"" key "\"[[:space:]]*:[[:space:]]*[0-9]+"
    if (match(line, r)) { s=substr(line,RSTART,RLENGTH); sub(/.*:[[:space:]]*/,"",s); return s+0 }
    return -1
  }
  {
    scanned++
    ts=get_num($0,"ts")
    if (ts >= 0) {
      valid++
      if (oldest == 0 || ts < oldest) oldest=ts
      if (ts > newest) newest=ts
      if (cutoff > 0 && ts < cutoff) old++
    } else invalid++
  }
  END { printf "true %.0f %.0f %.0f %.0f %.0f %.0f", scanned+0, valid+0, invalid+0, old+0, oldest+0, newest+0 }
  '
}

date_to_num() {
  d="$1"
  case "$d" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) echo "$(echo "$d" | tr -d '-')" ;;
    *) echo 0 ;;
  esac
}

# 纯 POSIX awk 儒略日/格里高利历换算(彻底移除 Android 15/16 one-true-awk 不支持的纪元格式化扩展)
epoch_to_ymd_posix() {
  awk -v ts="${1:-0}" -v tz="$(date +%z 2>/dev/null || echo +0000)" 'BEGIN {
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

cutoff_date_approx() {
  days="$1"
  now="$(date +%s 2>/dev/null)"
  now="$(num_or_zero "$now")"
  if uint_gt "$now" "0" && is_num "$days"; then
    ts="$(awk -v n="$now" -v dy="$days" 'BEGIN { printf "%.0f\n", (n + 0) - (dy + 0) * 86400 }')"
    d="$(date -d "@$ts" +%Y-%m-%d 2>/dev/null)"
    if [ -z "$d" ]; then
      d="$(epoch_to_ymd_posix "$ts" 2>/dev/null)"
    fi
    echo "$d"
  else
    echo ""
  fi
}

scan_daily() {
  f="$1"; cutoff_date="$2"; max_lines="$3"
  cutoff_num="$(date_to_num "$cutoff_date")"
  if [ ! -f "$f" ]; then
    echo "false 0 0 0 0 0 0"
    return
  fi
  tail -n "$max_lines" "$f" 2>/dev/null | awk -v cutoff="$cutoff_num" '
  BEGIN { cutoff = cutoff + 0 }
  function get_str(line, key,    r,s) {
    r="\"" key "\"[[:space:]]*:[[:space:]]*\"[^\"]*\""
    if (match(line, r)) { s=substr(line,RSTART,RLENGTH); sub(/.*:[[:space:]]*\"/,"",s); sub(/\"$/,"",s); return s }
    return ""
  }
  function dnum(d,    s) { s=d; gsub(/-/,"",s); return s+0 }
  {
    scanned++
    d=get_str($0,"date")
    if (d ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
      valid++
      dn=dnum(d)
      if (oldest == 0 || dn < oldest) oldest=dn
      if (dn > newest) newest=dn
      if (cutoff > 0 && dn < cutoff) old++
    } else invalid++
  }
  END { printf "true %.0f %.0f %.0f %.0f %.0f %.0f", scanned+0, valid+0, invalid+0, old+0, oldest+0, newest+0 }
  '
}

STATUS="ok"
WARNINGS=0
FAILURES=0

add_warn() { WARNINGS=$((WARNINGS+1)); [ "$STATUS" = "ok" ] && STATUS="warn"; }
add_fail() { FAILURES=$((FAILURES+1)); STATUS="fail"; }

if ! is_num "$RAW_RETAIN_HOURS"; then add_fail; RAW_RETAIN_HOURS_NUM=0; else RAW_RETAIN_HOURS_NUM="$RAW_RETAIN_HOURS"; fi
if ! is_num "$DAILY_RETAIN_DAYS"; then add_fail; DAILY_RETAIN_DAYS_NUM=0; else DAILY_RETAIN_DAYS_NUM="$DAILY_RETAIN_DAYS"; fi
if uint_gt "24" "$RAW_RETAIN_HOURS_NUM" || uint_gt "$RAW_RETAIN_HOURS_NUM" "720"; then add_warn; fi
if uint_gt "7" "$DAILY_RETAIN_DAYS_NUM" || uint_gt "$DAILY_RETAIN_DAYS_NUM" "730"; then add_warn; fi

RAW_SIZE="$(file_size "$RAW_FILE")"; RAW_LINES="$(line_count "$RAW_FILE")"
DAILY_SIZE="$(file_size "$DAILY_FILE")"; DAILY_LINES="$(line_count "$DAILY_FILE")"
RAW_SIZE="$(num_or_zero "$RAW_SIZE")"; RAW_LINES="$(num_or_zero "$RAW_LINES")"
DAILY_SIZE="$(num_or_zero "$DAILY_SIZE")"; DAILY_LINES="$(num_or_zero "$DAILY_LINES")"

uint_gt "$RAW_SIZE" "$(num_or_zero "$RAW_MAX_BYTES")" && add_warn
uint_gt "$DAILY_SIZE" "$(num_or_zero "$DAILY_MAX_BYTES")" && add_warn

NOW="$(date +%s 2>/dev/null)"; NOW="$(num_or_zero "$NOW")"
RAW_CUTOFF=0
uint_gt "$NOW" "0" && RAW_CUTOFF="$(awk -v n="$NOW" -v h="$RAW_RETAIN_HOURS_NUM" 'BEGIN { printf "%.0f\n", (n + 0) - (h + 0) * 3600 }')"
DAILY_CUTOFF_DATE="$(cutoff_date_approx "$DAILY_RETAIN_DAYS_NUM")"

set -- $(scan_raw "$RAW_FILE" "$RAW_CUTOFF" "$TAIL_SCAN_LINES")
RAW_EXISTS="$1"; RAW_SCANNED="$(num_or_zero "$2")"; RAW_VALID="$(num_or_zero "$3")"; RAW_INVALID="$(num_or_zero "$4")"; RAW_OLD="$(num_or_zero "$5")"; RAW_OLDEST="$(num_or_zero "$6")"; RAW_NEWEST="$(num_or_zero "$7")"
set -- $(scan_daily "$DAILY_FILE" "$DAILY_CUTOFF_DATE" "$TAIL_SCAN_LINES")
DAILY_EXISTS="$1"; DAILY_SCANNED="$(num_or_zero "$2")"; DAILY_VALID="$(num_or_zero "$3")"; DAILY_INVALID="$(num_or_zero "$4")"; DAILY_OLD="$(num_or_zero "$5")"; DAILY_OLDEST="$(num_or_zero "$6")"; DAILY_NEWEST="$(num_or_zero "$7")"

uint_gt "$RAW_INVALID" "0" && add_warn
uint_gt "$DAILY_INVALID" "0" && add_warn
uint_gt "$RAW_OLD" "0" && add_warn
uint_gt "$DAILY_OLD" "0" && add_warn

ROLLUP_DEFAULT_RAW="$(rollup_default RAW_RETAIN_HOURS)"
ROLLUP_DEFAULT_DAILY="$(rollup_default DAILY_RETAIN_DAYS)"
[ -z "$ROLLUP_DEFAULT_RAW" ] && add_warn
[ -z "$ROLLUP_DEFAULT_DAILY" ] && add_warn

TS="$NOW"
case "$MODE" in
  text|status)
    echo "HNC stats retention diagnostics"
    echo "timestamp=$TS"
    echo "status=$STATUS warnings=$WARNINGS failures=$FAILURES"
    echo "hnc_dir=$HNC_DIR"
    echo "raw_file=$RAW_FILE bytes=$RAW_SIZE lines=$RAW_LINES scanned=$RAW_SCANNED old_lines=$RAW_OLD invalid_lines=$RAW_INVALID retain_hours=$RAW_RETAIN_HOURS_NUM cutoff_ts=$RAW_CUTOFF"
    echo "daily_file=$DAILY_FILE bytes=$DAILY_SIZE lines=$DAILY_LINES scanned=$DAILY_SCANNED old_lines=$DAILY_OLD invalid_lines=$DAILY_INVALID retain_days=$DAILY_RETAIN_DAYS_NUM cutoff_date=$DAILY_CUTOFF_DATE"
    echo "rollup_defaults raw_hours=$ROLLUP_DEFAULT_RAW daily_days=$ROLLUP_DEFAULT_DAILY rollup_sh=$ROLLUP_SH"
    ;;
  *)
    cat <<JSON
{"ok":true,"timestamp":$TS,"status":"$(json_escape "$STATUS")","warnings":$WARNINGS,"failures":$FAILURES,"config":{"raw_retain_hours":$(num_or_zero "$RAW_RETAIN_HOURS_NUM"),"daily_retain_days":$(num_or_zero "$DAILY_RETAIN_DAYS_NUM"),"raw_max_bytes":$(num_or_zero "$RAW_MAX_BYTES"),"daily_max_bytes":$(num_or_zero "$DAILY_MAX_BYTES"),"scan_lines":$(num_or_zero "$TAIL_SCAN_LINES"),"rollup_default_raw_hours":$(num_or_zero "$ROLLUP_DEFAULT_RAW"),"rollup_default_daily_days":$(num_or_zero "$ROLLUP_DEFAULT_DAILY")},"paths":{"raw":"$(json_escape "$RAW_FILE")","daily":"$(json_escape "$DAILY_FILE")","rollup":"$(json_escape "$ROLLUP_SH")"},"raw":{"exists":$RAW_EXISTS,"bytes":$RAW_SIZE,"lines":$RAW_LINES,"scanned_lines":$RAW_SCANNED,"valid_lines":$RAW_VALID,"invalid_lines":$RAW_INVALID,"older_than_retention_lines":$RAW_OLD,"oldest_ts":$RAW_OLDEST,"newest_ts":$RAW_NEWEST,"cutoff_ts":$RAW_CUTOFF},"daily":{"exists":$DAILY_EXISTS,"bytes":$DAILY_SIZE,"lines":$DAILY_LINES,"scanned_lines":$DAILY_SCANNED,"valid_lines":$DAILY_VALID,"invalid_lines":$DAILY_INVALID,"older_than_retention_lines":$DAILY_OLD,"oldest_date_num":$DAILY_OLDEST,"newest_date_num":$DAILY_NEWEST,"cutoff_date":"$(json_escape "$DAILY_CUTOFF_DATE")"}}
JSON
    ;;
esac
