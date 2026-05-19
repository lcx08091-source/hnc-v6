#!/system/bin/sh
# stats_migration_readiness.sh — HNC v5.2-rc1.16 stats migration readiness gate
# Read-only helper. It does not enable shadow stats, switch WebUI source, or modify stats data.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
BIN="$HNC_DIR/bin"
MODE=${1:-json}
OUT_JSON="$RUN/stats_migration_readiness.json"
OUT_TXT="$RUN/stats_migration_readiness.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

file_lines() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -l < "$f" 2>/dev/null | tr -d ' ' | sed 's/[^0-9].*$//'
}

file_size() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -c < "$f" 2>/dev/null | tr -d ' ' | sed 's/[^0-9].*$//'
}

status_of() {
  v="$1"
  s="$(printf '%s' "$v" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' )"
  [ -n "$s" ] || s="unknown"
  echo "$s"
}

num_key_of() {
  key="$1"; body="$2"; def="$3"
  val="$(printf '%s' "$body" | sed -n 's/.*"'"$key"'":\([0-9][0-9]*\).*/\1/p' )"
  case "$val" in ''|*[!0-9]*) printf '%s' "$def" ;; *) printf '%s' "$val" ;; esac
}

bool_has() { [ -x "$BIN/$1" ] && echo true || echo false; }

helper_json() {
  h="$1"
  if [ -x "$BIN/$h" ]; then
    sh "$BIN/$h" json 2>/dev/null
  else
    echo '{"ok":false,"status":"missing"}'
  fi
}

metric_get() {
  f="$1"; key="$2"; def="$3"
  val="$(sed -n "s/^$key=//p" "$f" 2>/dev/null | tail -1)"
  [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"
}

num_sane() {
  v="$1"; def="$2"
  case "$v" in ''|*[!0-9]*) printf '%s' "$def" ;; *) printf '%s' "$v" ;; esac
}

legacy_raw="$DATA/stats_raw.jsonl"
legacy_daily="$DATA/stats_daily.jsonl"
shadow_raw="$DATA/stats_shadow_raw.jsonl"
shadow_daily="$DATA/stats_shadow_daily.jsonl"
legacy_raw_lines=$(file_lines "$legacy_raw")
legacy_daily_lines=$(file_lines "$legacy_daily")
shadow_raw_lines=$(file_lines "$shadow_raw")
shadow_daily_lines=$(file_lines "$shadow_daily")
legacy_raw_size=$(file_size "$legacy_raw")
legacy_daily_size=$(file_size "$legacy_daily")
shadow_raw_size=$(file_size "$shadow_raw")
shadow_daily_size=$(file_size "$shadow_daily")

shadow_json="$(helper_json stats_shadow_diag.sh)"
shadow_control_json="$(helper_json stats_shadow_control.sh)"
source_json="$(helper_json stats_source_diag.sh)"
compare_json="$(helper_json stats_compare.sh)"
retention_json="$(helper_json stats_retention_diag.sh)"
identity_json="$(helper_json stats_identity_diag.sh)"

shadow_status="$(status_of "$shadow_json")"
shadow_control_status="$(status_of "$shadow_control_json")"
source_status="$(status_of "$source_json")"
compare_status="$(status_of "$compare_json")"
retention_status="$(status_of "$retention_json")"
identity_status="$(status_of "$identity_json")"

compare_total_keys="$(num_key_of total_keys "$compare_json" 0)"
compare_matched_keys="$(num_key_of matched_keys "$compare_json" 0)"
compare_missing_in_legacy="$(num_key_of missing_in_legacy "$compare_json" 0)"
compare_missing_in_shadow="$(num_key_of missing_in_shadow "$compare_json" 0)"
compare_mismatched_keys="$(num_key_of mismatched_keys "$compare_json" 0)"
compare_unique_macs="$(num_key_of unique_macs "$compare_json" 0)"

has_shadow_diag=$(bool_has stats_shadow_diag.sh)
has_shadow_rollup=$(bool_has stats_shadow_rollup.sh)
has_shadow_control=$(bool_has stats_shadow_control.sh)
has_source_diag=$(bool_has stats_source_diag.sh)
has_compare=$(bool_has stats_compare.sh)
has_retention=$(bool_has stats_retention_diag.sh)
has_identity=$(bool_has stats_identity_diag.sh)

shadow_has_raw=false
shadow_has_daily=false
[ "$shadow_raw_lines" != 0 ] && shadow_has_raw=true
[ "$shadow_daily_lines" != 0 ] && shadow_has_daily=true

shadow_latest_ts=0
shadow_latest_date=""
shadow_raw_devices=0
shadow_raw_total_rx=0
shadow_raw_total_tx=0
shadow_daily_latest_date=""
shadow_daily_devices=0
shadow_daily_samples=0
shadow_daily_total_rx=0
shadow_daily_total_tx=0
shadow_zero_only=true

RAW_METRICS="$RUN/stats_migration_readiness.shadow_raw.$$"
DAILY_METRICS="$RUN/stats_migration_readiness.shadow_daily.$$"
trap 'rm -f "$RAW_METRICS" "$DAILY_METRICS" 2>/dev/null' EXIT INT TERM

if [ -f "$shadow_raw" ]; then
  awk '
function str_field(line, key,    pat, val) {
  pat = "\"" key "\":\"[^\"]*\""
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub("^\"" key "\":\"", "", val); sub("\"$", "", val); return val }
  return ""
}
function num_field(line, key,    pat, val) {
  pat = "\"" key "\":[0-9]+"
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub(".*:", "", val); return val + 0 }
  return 0
}
{
  ts=num_field($0,"ts"); date=str_field($0,"date"); mac=str_field($0,"mac"); devid=str_field($0,"device_id"); rxv=num_field($0,"rx"); txv=num_field($0,"tx")
  if (ts > latest_ts) latest_ts=ts
  if (date != "" && date >= latest_date) latest_date=date
  if (mac == "" && devid != "") mac=devid
  if (mac != "") devices[mac]=1
  total_rx += rxv; total_tx += txv
}
END {
  for (m in devices) device_count++
  print "latest_ts=" latest_ts+0
  print "latest_date=" latest_date
  print "devices=" device_count+0
  print "total_rx=" total_rx+0
  print "total_tx=" total_tx+0
}' "$shadow_raw" > "$RAW_METRICS" 2>/dev/null
  shadow_latest_ts="$(metric_get "$RAW_METRICS" latest_ts 0)"
  shadow_latest_date="$(metric_get "$RAW_METRICS" latest_date '')"
  shadow_raw_devices="$(metric_get "$RAW_METRICS" devices 0)"
  shadow_raw_total_rx="$(metric_get "$RAW_METRICS" total_rx 0)"
  shadow_raw_total_tx="$(metric_get "$RAW_METRICS" total_tx 0)"
fi

if [ -f "$shadow_daily" ]; then
  awk '
function str_field(line, key,    pat, val) {
  pat = "\"" key "\":\"[^\"]*\""
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub("^\"" key "\":\"", "", val); sub("\"$", "", val); return val }
  return ""
}
function num_field(line, key,    pat, val) {
  pat = "\"" key "\":[0-9]+"
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub(".*:", "", val); return val + 0 }
  return 0
}
{
  date=str_field($0,"date"); mac=str_field($0,"mac"); devid=str_field($0,"device_id"); rxv=num_field($0,"rx"); txv=num_field($0,"tx"); samples=num_field($0,"samples")
  if (date != "" && date >= latest_date) latest_date=date
  if (mac == "" && devid != "") mac=devid
  if (mac != "") devices[mac]=1
  total_samples += samples; total_rx += rxv; total_tx += txv
}
END {
  for (m in devices) device_count++
  print "latest_date=" latest_date
  print "devices=" device_count+0
  print "samples=" total_samples+0
  print "total_rx=" total_rx+0
  print "total_tx=" total_tx+0
}' "$shadow_daily" > "$DAILY_METRICS" 2>/dev/null
  shadow_daily_latest_date="$(metric_get "$DAILY_METRICS" latest_date '')"
  shadow_daily_devices="$(metric_get "$DAILY_METRICS" devices 0)"
  shadow_daily_samples="$(metric_get "$DAILY_METRICS" samples 0)"
  shadow_daily_total_rx="$(metric_get "$DAILY_METRICS" total_rx 0)"
  shadow_daily_total_tx="$(metric_get "$DAILY_METRICS" total_tx 0)"
fi

shadow_latest_ts="$(num_sane "$shadow_latest_ts" 0)"
shadow_raw_devices="$(num_sane "$shadow_raw_devices" 0)"
shadow_raw_total_rx="$(num_sane "$shadow_raw_total_rx" 0)"
shadow_raw_total_tx="$(num_sane "$shadow_raw_total_tx" 0)"
shadow_daily_devices="$(num_sane "$shadow_daily_devices" 0)"
shadow_daily_samples="$(num_sane "$shadow_daily_samples" 0)"
shadow_daily_total_rx="$(num_sane "$shadow_daily_total_rx" 0)"
shadow_daily_total_tx="$(num_sane "$shadow_daily_total_tx" 0)"

[ $((shadow_raw_total_rx + shadow_raw_total_tx + shadow_daily_total_rx + shadow_daily_total_tx)) -gt 0 ] && shadow_zero_only=false

shadow_state="no_shadow_data"
shadow_quality="missing"
if [ "$shadow_has_raw" = true ] && [ "$shadow_has_daily" = true ]; then
  shadow_state="shadow_rollup_seen"
  shadow_quality="observed"
elif [ "$shadow_has_raw" = true ]; then
  shadow_state="shadow_raw_seen"
  shadow_quality="warmup"
fi

if [ "$shadow_has_raw" = true ] && [ "$shadow_raw_devices" -eq 0 ]; then
  shadow_quality="warn_no_devices"
elif [ "$shadow_has_daily" = true ] && [ "$shadow_daily_samples" -eq 0 ]; then
  shadow_quality="warn_no_daily_samples"
elif [ "$shadow_has_raw" = true ] && [ "$shadow_zero_only" = true ]; then
  shadow_quality="observed_zero_traffic"
fi

compare_quality="not_available"
if [ "$compare_total_keys" -gt 0 ]; then
  compare_quality="compared"
  if [ "$compare_mismatched_keys" -gt 0 ] || [ "$compare_missing_in_shadow" -gt 0 ]; then
    compare_quality="warn_drift"
  elif [ "$compare_missing_in_legacy" -gt 0 ]; then
    compare_quality="shadow_only"
  fi
elif [ "$shadow_has_daily" = true ]; then
  compare_quality="shadow_only_or_legacy_empty"
fi

READY=false
STATUS="not_ready"
REASON="shadow stats is not ready for default WebUI or v5.2 switch"

case "$shadow_status $shadow_control_status $source_status $compare_status $retention_status $identity_status" in
  *fail*|*bad*|*error*)
    STATUS="blocked"
    REASON="one or more stats diagnostics reported failure"
    ;;
  *)
    if [ "$has_shadow_diag" = true ] && [ "$has_shadow_rollup" = true ] && [ "$has_source_diag" = true ] && [ "$has_compare" = true ] && [ "$shadow_has_raw" = true ] && [ "$shadow_has_daily" = true ]; then
      READY=true
      STATUS="ready"
      REASON="shadow raw/daily data is visible to readiness; legacy/shadow comparison diagnostics are available"
    elif [ "$shadow_has_raw" = true ] && [ "$shadow_has_daily" = false ]; then
      STATUS="warmup"
      REASON="shadow raw exists but shadow daily rollup has not been produced yet"
    elif [ "$shadow_has_raw" = false ]; then
      STATUS="not_ready"
      REASON="shadow raw data is empty or missing"
    else
      STATUS="not_ready"
      REASON="required shadow stats helpers are missing or incomplete"
    fi
    ;;
esac

if [ "$READY" = true ]; then
  RECOMMENDATION="safe to test optional shadow WebUI source; keep legacy as default until several builds compare cleanly"
else
  RECOMMENDATION="keep legacy stats as default; continue collecting shadow stats and diagnostics"
fi

{
  echo "HNC stats migration readiness"
  echo "status=$STATUS"
  echo "ready=$READY"
  echo "reason=$REASON"
  echo "recommendation=$RECOMMENDATION"
  echo "shadow_state=$shadow_state"
  echo "shadow_quality=$shadow_quality"
  echo "compare_quality=$compare_quality"
  echo "shadow_status=$shadow_status"
  echo "shadow_control_status=$shadow_control_status"
  echo "source_status=$source_status"
  echo "compare_status=$compare_status"
  echo "retention_status=$retention_status"
  echo "identity_status=$identity_status"
  echo "legacy_raw_lines=$legacy_raw_lines"
  echo "legacy_daily_lines=$legacy_daily_lines"
  echo "shadow_raw_lines=$shadow_raw_lines"
  echo "shadow_daily_lines=$shadow_daily_lines"
  echo "shadow_latest_ts=$shadow_latest_ts"
  echo "shadow_latest_date=$shadow_latest_date"
  echo "shadow_raw_devices=$shadow_raw_devices"
  echo "shadow_raw_total_rx=$shadow_raw_total_rx"
  echo "shadow_raw_total_tx=$shadow_raw_total_tx"
  echo "shadow_daily_latest_date=$shadow_daily_latest_date"
  echo "shadow_daily_devices=$shadow_daily_devices"
  echo "shadow_daily_samples=$shadow_daily_samples"
  echo "shadow_daily_total_rx=$shadow_daily_total_rx"
  echo "shadow_daily_total_tx=$shadow_daily_total_tx"
  echo "compare_total_keys=$compare_total_keys"
  echo "compare_matched_keys=$compare_matched_keys"
  echo "compare_missing_in_legacy=$compare_missing_in_legacy"
  echo "compare_missing_in_shadow=$compare_missing_in_shadow"
  echo "compare_mismatched_keys=$compare_mismatched_keys"
  echo "compare_unique_macs=$compare_unique_macs"
  echo "has_shadow_diag=$has_shadow_diag"
  echo "has_shadow_rollup=$has_shadow_rollup"
  echo "has_shadow_control=$has_shadow_control"
  echo "has_source_diag=$has_source_diag"
  echo "has_compare=$has_compare"
} > "$OUT_TXT"

cat > "$OUT_JSON" <<JSON
{"ok":true,"status":"$(json_escape "$STATUS")","ready":$READY,"reason":"$(json_escape "$REASON")","recommendation":"$(json_escape "$RECOMMENDATION")","shadow_state":"$(json_escape "$shadow_state")","shadow_quality":"$(json_escape "$shadow_quality")","shadow_raw_lines":$shadow_raw_lines,"shadow_daily_lines":$shadow_daily_lines,"shadow_latest_ts":$shadow_latest_ts,"shadow_raw_devices":$shadow_raw_devices,"shadow_raw_total_rx":$shadow_raw_total_rx,"shadow_raw_total_tx":$shadow_raw_total_tx,"shadow_daily_samples":$shadow_daily_samples,"shadow_daily_devices":$shadow_daily_devices,"shadow_daily_total_rx":$shadow_daily_total_rx,"shadow_daily_total_tx":$shadow_daily_total_tx,"compare_quality":"$(json_escape "$compare_quality")","compare_total_keys":$compare_total_keys,"compare_matched_keys":$compare_matched_keys,"compare_missing_in_legacy":$compare_missing_in_legacy,"compare_missing_in_shadow":$compare_missing_in_shadow,"compare_mismatched_keys":$compare_mismatched_keys,"compare_unique_macs":$compare_unique_macs,"components":{"shadow":"$(json_escape "$shadow_status")","shadow_control":"$(json_escape "$shadow_control_status")","source":"$(json_escape "$source_status")","compare":"$(json_escape "$compare_status")","retention":"$(json_escape "$retention_status")","identity":"$(json_escape "$identity_status")"},"helpers":{"stats_shadow_diag":$has_shadow_diag,"stats_shadow_rollup":$has_shadow_rollup,"stats_shadow_control":$has_shadow_control,"stats_source_diag":$has_source_diag,"stats_compare":$has_compare,"stats_retention_diag":$has_retention,"stats_identity_diag":$has_identity},"files":{"legacy_raw":{"path":"$(json_escape "$legacy_raw")","lines":$legacy_raw_lines,"size":$legacy_raw_size},"legacy_daily":{"path":"$(json_escape "$legacy_daily")","lines":$legacy_daily_lines,"size":$legacy_daily_size},"shadow_raw":{"path":"$(json_escape "$shadow_raw")","lines":$shadow_raw_lines,"size":$shadow_raw_size,"latest_ts":$shadow_latest_ts,"latest_date":"$(json_escape "$shadow_latest_date")","devices":$shadow_raw_devices,"total_rx":$shadow_raw_total_rx,"total_tx":$shadow_raw_total_tx},"shadow_daily":{"path":"$(json_escape "$shadow_daily")","lines":$shadow_daily_lines,"size":$shadow_daily_size,"latest_date":"$(json_escape "$shadow_daily_latest_date")","devices":$shadow_daily_devices,"samples":$shadow_daily_samples,"total_rx":$shadow_daily_total_rx,"total_tx":$shadow_daily_total_tx}},"comparison":{"status":"$(json_escape "$compare_status")","quality":"$(json_escape "$compare_quality")","total_keys":$compare_total_keys,"matched_keys":$compare_matched_keys,"missing_in_legacy":$compare_missing_in_legacy,"missing_in_shadow":$compare_missing_in_shadow,"mismatched_keys":$compare_mismatched_keys,"unique_macs":$compare_unique_macs},"paths":{"json":"$(json_escape "$OUT_JSON")","text":"$(json_escape "$OUT_TXT")"}}
JSON

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  json|*) cat "$OUT_JSON" ;;
esac
exit 0
