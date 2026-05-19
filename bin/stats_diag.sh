#!/system/bin/sh
# HNC hotfix21.0 stats diagnostics helper
# Read-only status for stats_raw.jsonl / stats_daily.jsonl before the v5.2
# stats overhaul. Safe to run from WebUI diagnostics, Termux, or debug bundles.

set +e
HNC_DIR="${HNC_DIR:-${HNC:-/data/local/hnc}}"
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
LOGS="$HNC_DIR/logs"
RAW_FILE="${HNC_STATS_RAW_FILE:-$DATA/stats_raw.jsonl}"
DAILY_FILE="${HNC_STATS_DAILY_FILE:-$DATA/stats_daily.jsonl}"
MARKER="$RUN/stats_last_date"
LOG="$LOGS/stats.log"
MODE="${1:-json}"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

num_or_zero() {
  case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}

file_size() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -c < "$f" 2>/dev/null | tr -d ' '
}

line_count() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -l < "$f" 2>/dev/null | tr -d ' '
}

stats_jsonl_summary() {
  f="$1"; kind="$2"
  if [ ! -f "$f" ]; then
    echo '"exists": false, "bytes": 0, "lines": 0, "valid_lines": 0, "invalid_lines": 0, "unique_macs": 0, "oldest_ts": 0, "newest_ts": 0, "latest_age_sec": 0'
    return
  fi
  now="$(date +%s 2>/dev/null)"
  now="$(num_or_zero "$now")"
  bytes="$(file_size "$f")"
  lines="$(line_count "$f")"
  out="$(awk -v kind="$kind" -v now="$now" '
  function mac_seen(m) { if (m != "" && !(m in macs)) { macs[m]=1; uniq++ } }
  function get_num(line, key,    r,s) {
    r="\\\"" key "\\\"[[:space:]]*:[[:space:]]*[0-9]+"
    if (match(line, r)) { s=substr(line,RSTART,RLENGTH); sub(/.*:[[:space:]]*/,"",s); return s+0 }
    return -1
  }
  function get_str(line, key,    r,s) {
    r="\\\"" key "\\\"[[:space:]]*:[[:space:]]*\\\"[^\\\"]*\\\""
    if (match(line, r)) { s=substr(line,RSTART,RLENGTH); sub(/.*:[[:space:]]*\\\"/,"",s); sub(/\\\"$/,"",s); return s }
    return ""
  }
  {
    total++
    if (kind == "raw") {
      ts=get_num($0,"ts"); mac=get_str($0,"mac"); rx=get_num($0,"rx"); tx=get_num($0,"tx")
      if (ts >= 0 && mac != "" && rx >= 0 && tx >= 0) {
        valid++; mac_seen(mac)
        if (oldest == 0 || ts < oldest) oldest=ts
        if (ts > newest) newest=ts
      } else invalid++
    } else {
      date=get_str($0,"date"); mac=get_str($0,"mac"); rx=get_num($0,"rx"); tx=get_num($0,"tx")
      if (date != "" && mac != "" && rx >= 0 && tx >= 0) { valid++; mac_seen(mac) } else invalid++
    }
  }
  END {
    if (kind == "raw" && newest > 0 && now > newest) age=now-newest; else age=0
    printf "%d %d %d %d %d %d %d", total+0, valid+0, invalid+0, uniq+0, oldest+0, newest+0, age+0
  }' "$f" 2>/dev/null)"
  set -- $out
  total="$(num_or_zero "$1")"
  valid="$(num_or_zero "$2")"
  invalid="$(num_or_zero "$3")"
  unique="$(num_or_zero "$4")"
  oldest="$(num_or_zero "$5")"
  newest="$(num_or_zero "$6")"
  age="$(num_or_zero "$7")"
  [ -n "$lines" ] || lines="$total"
  echo "\"exists\": true, \"bytes\": $(num_or_zero "$bytes"), \"lines\": $(num_or_zero "$lines"), \"valid_lines\": $valid, \"invalid_lines\": $invalid, \"unique_macs\": $unique, \"oldest_ts\": $oldest, \"newest_ts\": $newest, \"latest_age_sec\": $age"
}

RAW_SUMMARY="$(stats_jsonl_summary "$RAW_FILE" raw)"
DAILY_SUMMARY="$(stats_jsonl_summary "$DAILY_FILE" daily)"
MARKER_VALUE="$(cat "$MARKER" 2>/dev/null | head -1)"
LOG_EXISTS=false
[ -f "$LOG" ] && LOG_EXISTS=true
LAST_LOG=""
[ -f "$LOG" ] && LAST_LOG="$(tail -1 "$LOG" 2>/dev/null)"
TS="$(date +%s 2>/dev/null)"
TS="$(num_or_zero "$TS")"
RAW_RETAIN_HOURS="${RAW_RETAIN_HOURS:-48}"
DAILY_RETAIN_DAYS="${DAILY_RETAIN_DAYS:-90}"

case "$MODE" in
  text|status)
    echo "HNC stats diagnostics"
    echo "timestamp=$TS"
    echo "hnc_dir=$HNC_DIR"
    echo "raw_file=$RAW_FILE"
    echo "daily_file=$DAILY_FILE"
    echo "marker=$MARKER_VALUE"
    echo "log_exists=$LOG_EXISTS"
    echo "raw={ $RAW_SUMMARY }"
    echo "daily={ $DAILY_SUMMARY }"
    ;;
  *)
    cat <<JSON
{"ok":true,"timestamp":$TS,"hnc_dir":"$(json_escape "$HNC_DIR")","retention":{"raw_hours":$(num_or_zero "$RAW_RETAIN_HOURS"),"daily_days":$(num_or_zero "$DAILY_RETAIN_DAYS")},"files":{"raw":"$(json_escape "$RAW_FILE")","daily":"$(json_escape "$DAILY_FILE")","marker":"$(json_escape "$MARKER")","log":"$(json_escape "$LOG")"},"raw":{$RAW_SUMMARY},"daily":{$DAILY_SUMMARY},"marker":"$(json_escape "$MARKER_VALUE")","log":{"exists":$LOG_EXISTS,"last":"$(json_escape "$LAST_LOG")"}}
JSON
    ;;
esac
