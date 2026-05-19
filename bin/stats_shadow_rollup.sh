#!/system/bin/sh
# stats_shadow_rollup.sh — HNC v5.2-rc1.19 shadow stats daily rollup
#
# This is part of the v5.2 stats migration shadow path. It only reads/writes
# shadow stats files and never replaces the legacy stats pipeline.
#
# Usage:
#   sh stats_shadow_rollup.sh YYYY-MM-DD
#
# Output:
#   data/stats_shadow_daily.jsonl

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
LOG="$HNC_DIR/logs/stats.log"
RAW="$DATA/stats_shadow_raw.jsonl"
DAILY="$DATA/stats_shadow_daily.jsonl"
TARGET_DATE="$1"

log() {
  [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [STATS_SHADOW_ROLLUP] $*" >> "$LOG" 2>/dev/null || true
}

case "$TARGET_DATE" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *) echo "usage: $0 YYYY-MM-DD" >&2; exit 2 ;;
esac

mkdir -p "$DATA" "$RUN" 2>/dev/null
[ -f "$RAW" ] || { log "raw missing, skip target=$TARGET_DATE"; exit 0; }

TMP_ROLL="$RUN/stats_shadow_rollup.$$"
TMP_DAILY="$RUN/stats_shadow_daily.$$"
trap 'rm -f "$TMP_ROLL" "$TMP_DAILY" 2>/dev/null' EXIT INT TERM

now=$(date +%s 2>/dev/null)
case "$now" in ''|*[!0-9]*) now=0 ;; esac

awk -v target="$TARGET_DATE" -v now="$now" '
function str_field(line, key,    pat, val) {
  pat = "\"" key "\":\"[^\"]*\""
  if (match(line, pat)) {
    val = substr(line, RSTART, RLENGTH)
    sub("^\"" key "\":\"", "", val)
    sub("\"$", "", val)
    return val
  }
  return ""
}
function num_field(line, key,    pat, val) {
  pat = "\"" key "\":[0-9]+"
  if (match(line, pat)) {
    val = substr(line, RSTART, RLENGTH)
    sub(".*:", "", val)
    return val + 0
  }
  return -1
}
function set_base(id, mac, rxv, txv, tsv) {
  if (id == "") return
  if (base_seen[id] == "" || tsv >= base_seen[id]) {
    base_seen[id] = tsv
    base_rx[id] = rxv
    base_tx[id] = txv
    base_mac[id] = mac
  }
}
function add_flag(id, flag) {
  if (id == "" || flag == "") return
  if (baseline_flag[id] == "") baseline_flag[id] = flag
  else if (index("+" baseline_flag[id] "+", "+" flag "+") == 0) baseline_flag[id] = baseline_flag[id] "+" flag
}
function begin_target(id, mac, rxv, txv, tsv) {
  if (base_seen[id] != "") {
    prev_rx[id] = base_rx[id]
    prev_tx[id] = base_tx[id]
    baseline_type[id] = "previous_day"
  } else {
    # With no previous-day baseline, the first same-day sample is the baseline.
    # It must not zero an already accumulated segment when later samples reset.
    prev_rx[id] = rxv
    prev_tx[id] = txv
    baseline_type[id] = "first_sample"
    prev_set[id] = 1
    last_seen[id] = tsv
    last_mac[id] = mac
    return 0
  }
  prev_set[id] = 1
  return 1
}
function add_delta(id, cur_rx, cur_tx,    drx, dtx) {
  drx = cur_rx - prev_rx[id]
  dtx = cur_tx - prev_tx[id]

  if (drx >= 0) total_rx[id] += drx
  else {
    add_flag(id, "counter_reset")
    if (cur_rx > 0) total_rx[id] += cur_rx
    else add_flag(id, "zero_reset_preserved")
  }

  if (dtx >= 0) total_tx[id] += dtx
  else {
    add_flag(id, "counter_reset")
    if (cur_tx > 0) total_tx[id] += cur_tx
    else add_flag(id, "zero_reset_preserved")
  }
}
{
  datev = str_field($0, "date")
  # hotfix21.3 rows have no date. Leave them for diagnostics instead of trying
  # non-portable epoch conversion on Android/toybox.
  if (datev == "") next
  id = str_field($0, "device_id")
  mac = str_field($0, "mac")
  rxv = num_field($0, "rx")
  txv = num_field($0, "tx")
  tsv = num_field($0, "ts")
  if (id == "" || mac == "" || rxv < 0 || txv < 0 || tsv < 0) next

  if (datev < target) {
    set_base(id, mac, rxv, txv, tsv)
    next
  }
  if (datev != target) next

  samples[id]++
  last_mac[id] = mac
  last_seen[id] = tsv

  if (prev_set[id] == "") {
    if (!begin_target(id, mac, rxv, txv, tsv)) next
  }

  add_delta(id, rxv, txv)
  prev_rx[id] = rxv
  prev_tx[id] = txv
}
END {
  for (id in samples) {
    btype = baseline_type[id]
    if (btype == "") btype = "first_sample"
    if (baseline_flag[id] != "") btype = btype "+" baseline_flag[id]
    printf "{\"schema\":1,\"date\":\"%s\",\"device_id\":\"%s\",\"mac\":\"%s\",\"rx\":%d,\"tx\":%d,\"samples\":%d,\"baseline\":\"%s\",\"source\":\"shadow_rollup\",\"updated_ts\":%d}\n", target, id, last_mac[id], total_rx[id], total_tx[id], samples[id], btype, now
  }
}' "$RAW" > "$TMP_ROLL"

# Idempotent replacement: keep rows for other dates, then append target rows.
if [ -f "$DAILY" ]; then
  awk -v target="$TARGET_DATE" '$0 !~ ("\"date\":\"" target "\"") { print }' "$DAILY" > "$TMP_DAILY"
else
  : > "$TMP_DAILY"
fi

[ -s "$TMP_ROLL" ] && cat "$TMP_ROLL" >> "$TMP_DAILY"
mv -f "$TMP_DAILY" "$DAILY"
rows=$(wc -l < "$TMP_ROLL" 2>/dev/null | tr -d ' ')
log "rolled target=$TARGET_DATE rows=${rows:-0}"
exit 0
