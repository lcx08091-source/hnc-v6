#!/system/bin/sh
# stats_shadow_diag.sh — hotfix21.7 read-only diagnostics for shadow stats.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
BIN="$HNC_DIR/bin"
RAW="$DATA/stats_shadow_raw.jsonl"
DAILY="$DATA/stats_shadow_daily.jsonl"
CONFIG="$DATA/config.json"
MARKER="$RUN/stats_shadow_last_date"
FLAG="$RUN/stats_shadow.enabled"
MODE=${1:-json}
NOW=$(date +%s 2>/dev/null)
case "$NOW" in ''|*[!0-9]*) NOW=0 ;; esac

file_size() { [ -f "$1" ] && wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
line_count() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

enabled="false"
reason="disabled_by_default"
env_value="${HNC_STATS_SHADOW_ENABLE:-}"
env_state="unset"
case "$env_value" in
  1|true|TRUE|yes|YES) enabled="true"; reason="env:HNC_STATS_SHADOW_ENABLE"; env_state="enabled" ;;
  0|false|FALSE|no|NO) enabled="false"; reason="env:HNC_STATS_SHADOW_ENABLE"; env_state="disabled" ;;
  *)
    if [ -f "$CONFIG" ] && grep -q '"stats_shadow_enabled"[[:space:]]*:[[:space:]]*true' "$CONFIG" 2>/dev/null; then
      enabled="true"; reason="config:stats_shadow_enabled"
    elif [ -f "$FLAG" ]; then
      enabled="true"; reason="flag:stats_shadow.enabled"
    fi
    ;;
esac
flag_enabled=false
[ -f "$FLAG" ] && flag_enabled=true
control_helper_present=false
[ -x "$BIN/stats_shadow_control.sh" ] && control_helper_present=true

raw_exists=false
[ -f "$RAW" ] && raw_exists=true
raw_lines=$(line_count "$RAW")
raw_size=$(file_size "$RAW")
invalid_lines=0
legacy_no_date_lines=0
last_ts=0
unique_devices=0
unique_dates=0
if [ -f "$RAW" ]; then
  invalid_lines=$(awk '
  BEGIN{bad=0}
  {
    new_re = "^\\{\"schema\":1,\"ts\":[0-9]+,\"date\":\"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\",\"device_id\":\"mac:[0-9a-f:]+\",\"mac\":\"[0-9a-f:]+\",\"rx\":[0-9]+,\"tx\":[0-9]+,\"ips\":\"[0-9.,]*\",\"ip_count\":[0-9]+,\"source\":\"iptables\"\\}$"
    old_re = "^\\{\"schema\":1,\"ts\":[0-9]+,\"device_id\":\"mac:[0-9a-f:]+\",\"mac\":\"[0-9a-f:]+\",\"rx\":[0-9]+,\"tx\":[0-9]+,\"ips\":\"[0-9.,]*\",\"ip_count\":[0-9]+,\"source\":\"iptables\"\\}$"
    if ($0 !~ new_re && $0 !~ old_re) bad++
  }
  END{print bad+0}' "$RAW" 2>/dev/null)
  legacy_no_date_lines=$(grep -vc '"date":"' "$RAW" 2>/dev/null)
  last_ts=$(awk 'match($0, /"ts":[0-9]+/) { s=substr($0,RSTART,RLENGTH); sub(/.*:/,"",s); if ((s+0)>last) last=s+0 } END{print last+0}' "$RAW" 2>/dev/null)
  unique_devices=$(sed -nE 's/.*"device_id":"(mac:[0-9a-f:]+)".*/\1/p' "$RAW" 2>/dev/null | sort -u | wc -l | tr -d ' ')
  unique_dates=$(sed -nE 's/.*"date":"([0-9]{4}-[0-9]{2}-[0-9]{2})".*/\1/p' "$RAW" 2>/dev/null | sort -u | wc -l | tr -d ' ')
fi

daily_exists=false
[ -f "$DAILY" ] && daily_exists=true
daily_lines=$(line_count "$DAILY")
daily_size=$(file_size "$DAILY")
daily_invalid_lines=0
daily_unique_dates=0
daily_unique_devices=0
last_daily_date=""
if [ -f "$DAILY" ]; then
  daily_invalid_lines=$(awk '
  BEGIN{bad=0}
  $0 !~ /^\{"schema":1,"date":"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]","device_id":"mac:[0-9a-f:]+","mac":"[0-9a-f:]+","rx":[0-9]+,"tx":[0-9]+,"samples":[0-9]+,"baseline":"[^"]+","source":"shadow_rollup","updated_ts":[0-9]+\}$/ {bad++}
  END{print bad+0}' "$DAILY" 2>/dev/null)
  daily_unique_dates=$(sed -nE 's/.*"date":"([0-9]{4}-[0-9]{2}-[0-9]{2})".*/\1/p' "$DAILY" 2>/dev/null | sort -u | wc -l | tr -d ' ')
  daily_unique_devices=$(sed -nE 's/.*"device_id":"(mac:[0-9a-f:]+)".*/\1/p' "$DAILY" 2>/dev/null | sort -u | wc -l | tr -d ' ')
  last_daily_date=$(sed -nE 's/.*"date":"([0-9]{4}-[0-9]{2}-[0-9]{2})".*/\1/p' "$DAILY" 2>/dev/null | sort | tail -1)
fi

last_marker=""
[ -f "$MARKER" ] && last_marker=$(cat "$MARKER" 2>/dev/null)

stale_seconds=0
if [ "$NOW" -gt 0 ] && [ "$last_ts" -gt 0 ]; then stale_seconds=$((NOW - last_ts)); fi
status="ok"
[ "$invalid_lines" -gt 0 ] && status="warn"
[ "$daily_invalid_lines" -gt 0 ] && status="warn"

if [ "$MODE" = "text" ]; then
  cat <<EOF2
HNC stats shadow diagnostics
status=$status
enabled=$enabled
reason=$reason
env_state=$env_state
flag_enabled=$flag_enabled
control_helper_present=$control_helper_present
control_helper=$BIN/stats_shadow_control.sh
flag_file=$FLAG
sample_helper=$BIN/stats_shadow_sample.sh
rollup_helper=$BIN/stats_shadow_rollup.sh
raw_file=$RAW
raw_exists=$raw_exists
raw_lines=$raw_lines
raw_size_bytes=$raw_size
invalid_lines=$invalid_lines
legacy_no_date_lines=$legacy_no_date_lines
unique_devices=$unique_devices
unique_dates=$unique_dates
last_ts=$last_ts
stale_seconds=$stale_seconds
daily_file=$DAILY
daily_exists=$daily_exists
daily_lines=$daily_lines
daily_size_bytes=$daily_size
daily_invalid_lines=$daily_invalid_lines
daily_unique_dates=$daily_unique_dates
daily_unique_devices=$daily_unique_devices
last_daily_date=$last_daily_date
last_marker=$last_marker
EOF2
  exit 0
fi

cat <<EOF2
{"ok":true,"status":"$status","enabled":$enabled,"reason":"$reason","env_state":"$env_state","flag_enabled":$flag_enabled,"control_helper_present":$control_helper_present,"control_helper":"$BIN/stats_shadow_control.sh","flag_file":"$FLAG","sample_helper":"$BIN/stats_shadow_sample.sh","rollup_helper":"$BIN/stats_shadow_rollup.sh","raw_file":"$RAW","raw_exists":$raw_exists,"raw_lines":${raw_lines:-0},"raw_size_bytes":${raw_size:-0},"invalid_lines":${invalid_lines:-0},"legacy_no_date_lines":${legacy_no_date_lines:-0},"unique_devices":${unique_devices:-0},"unique_dates":${unique_dates:-0},"last_ts":${last_ts:-0},"stale_seconds":${stale_seconds:-0},"daily_file":"$DAILY","daily_exists":$daily_exists,"daily_lines":${daily_lines:-0},"daily_size_bytes":${daily_size:-0},"daily_invalid_lines":${daily_invalid_lines:-0},"daily_unique_dates":${daily_unique_dates:-0},"daily_unique_devices":${daily_unique_devices:-0},"last_daily_date":"$last_daily_date","last_marker":"$last_marker"}
EOF2
exit 0
