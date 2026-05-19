#!/system/bin/sh
# stats_compare.sh — HNC hotfix21.5 old-vs-shadow stats diagnostics
#
# Read-only comparator for the v5.2 stats migration. It compares legacy
# stats_daily.jsonl against shadow stats_shadow_daily.jsonl by date + MAC.
# It never modifies legacy or shadow stats files; it only writes diagnostic
# output under run/ for JSON health/debug bundle consumption.
#
# Usage:
#   sh stats_compare.sh json
#   sh stats_compare.sh text

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
LEGACY="$DATA/stats_daily.jsonl"
SHADOW="$DATA/stats_shadow_daily.jsonl"
OUT_JSON="$RUN/stats_compare.json"
OUT_TXT="$RUN/stats_compare.txt"
MODE=${1:-json}

mkdir -p "$RUN" 2>/dev/null

file_size() { [ -f "$1" ] && wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
line_count() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'; }

legacy_exists=false
shadow_exists=false
[ -f "$LEGACY" ] && legacy_exists=true
[ -f "$SHADOW" ] && shadow_exists=true
legacy_lines=$(line_count "$LEGACY")
shadow_lines=$(line_count "$SHADOW")
legacy_size=$(file_size "$LEGACY")
shadow_size=$(file_size "$SHADOW")

TMP_METRICS="$RUN/stats_compare.metrics.$$"
TMP_LEGACY="$RUN/stats_compare.legacy.$$"
TMP_SHADOW="$RUN/stats_compare.shadow.$$"
trap 'rm -f "$TMP_METRICS" "$TMP_LEGACY" "$TMP_SHADOW" 2>/dev/null' EXIT INT TERM

[ -f "$LEGACY" ] && cp "$LEGACY" "$TMP_LEGACY" 2>/dev/null || : > "$TMP_LEGACY"
[ -f "$SHADOW" ] && cp "$SHADOW" "$TMP_SHADOW" 2>/dev/null || : > "$TMP_SHADOW"

awk '
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
function norm_mac(v) {
  sub(/^mac:/, "", v)
  return tolower(v)
}
function abs(v) { return v < 0 ? -v : v }
function pct(diff, base) { if (base <= 0) return diff > 0 ? 100000 : 0; return int((diff * 10000) / base) }
function addrow(kind, line,    date, mac, devid, rxv, txv, key) {
  date = str_field(line, "date")
  mac = norm_mac(str_field(line, "mac"))
  devid = norm_mac(str_field(line, "device_id"))
  if (mac == "" && devid != "") mac = devid
  rxv = num_field(line, "rx")
  txv = num_field(line, "tx")
  if (date == "" || mac == "" || rxv < 0 || txv < 0) {
    if (kind == "legacy") legacy_invalid++
    else shadow_invalid++
    return
  }
  key = date SUBSEP mac
  dates[date] = 1
  macs[mac] = 1
  keys[key] = 1
  if (kind == "legacy") {
    legacy_seen[key] = 1; legacy_rx[key] += rxv; legacy_tx[key] += txv
  } else {
    shadow_seen[key] = 1; shadow_rx[key] += rxv; shadow_tx[key] += txv
  }
}
FILENAME == ARGV[1] { addrow("legacy", $0); next }
FILENAME == ARGV[2] { addrow("shadow", $0); next }
END {
  threshold_bytes = 4096
  threshold_pct = 1000   # 10.00%, measured in basis points
  for (k in keys) {
    total_keys++
    if (!legacy_seen[k]) { missing_in_legacy++; if (sample_missing_legacy == "") sample_missing_legacy = k; continue }
    if (!shadow_seen[k]) { missing_in_shadow++; if (sample_missing_shadow == "") sample_missing_shadow = k; continue }
    matched++
    drx = shadow_rx[k] - legacy_rx[k]
    dtx = shadow_tx[k] - legacy_tx[k]
    arx = abs(drx); atx = abs(dtx)
    brx = legacy_rx[k] > shadow_rx[k] ? legacy_rx[k] : shadow_rx[k]
    btx = legacy_tx[k] > shadow_tx[k] ? legacy_tx[k] : shadow_tx[k]
    prx = pct(arx, brx); ptx = pct(atx, btx)
    if (arx > max_rx_diff) max_rx_diff = arx
    if (atx > max_tx_diff) max_tx_diff = atx
    if (prx > max_pct_bp) max_pct_bp = prx
    if (ptx > max_pct_bp) max_pct_bp = ptx
    if ((arx > threshold_bytes && prx > threshold_pct) || (atx > threshold_bytes && ptx > threshold_pct)) {
      mismatched++
      if (sample_mismatch == "") sample_mismatch = k ":legacy_rx=" legacy_rx[k] ":shadow_rx=" shadow_rx[k] ":legacy_tx=" legacy_tx[k] ":shadow_tx=" shadow_tx[k]
    }
  }
  for (d in dates) unique_dates++
  for (m in macs) unique_macs++
  status = "ok"
  if (legacy_invalid > 0 || shadow_invalid > 0 || missing_in_legacy > 0 || missing_in_shadow > 0 || mismatched > 0) status = "warn"
  print "status=" status
  print "legacy_invalid_lines=" legacy_invalid+0
  print "shadow_invalid_lines=" shadow_invalid+0
  print "total_keys=" total_keys+0
  print "matched_keys=" matched+0
  print "missing_in_legacy=" missing_in_legacy+0
  print "missing_in_shadow=" missing_in_shadow+0
  print "mismatched_keys=" mismatched+0
  print "unique_dates=" unique_dates+0
  print "unique_macs=" unique_macs+0
  print "max_rx_diff=" max_rx_diff+0
  print "max_tx_diff=" max_tx_diff+0
  print "max_pct_bp=" max_pct_bp+0
  print "sample_missing_legacy=" sample_missing_legacy
  print "sample_missing_shadow=" sample_missing_shadow
  print "sample_mismatch=" sample_mismatch
}' "$TMP_LEGACY" "$TMP_SHADOW" > "$TMP_METRICS" 2>/dev/null

get_metric() {
  key="$1"
  sed -n "s/^$key=//p" "$TMP_METRICS" 2>/dev/null | tail -1
}

status=$(get_metric status); [ -n "$status" ] || status=warn
legacy_invalid=$(get_metric legacy_invalid_lines); case "$legacy_invalid" in ''|*[!0-9]*) legacy_invalid=0 ;; esac
shadow_invalid=$(get_metric shadow_invalid_lines); case "$shadow_invalid" in ''|*[!0-9]*) shadow_invalid=0 ;; esac
total_keys=$(get_metric total_keys); case "$total_keys" in ''|*[!0-9]*) total_keys=0 ;; esac
matched_keys=$(get_metric matched_keys); case "$matched_keys" in ''|*[!0-9]*) matched_keys=0 ;; esac
missing_in_legacy=$(get_metric missing_in_legacy); case "$missing_in_legacy" in ''|*[!0-9]*) missing_in_legacy=0 ;; esac
missing_in_shadow=$(get_metric missing_in_shadow); case "$missing_in_shadow" in ''|*[!0-9]*) missing_in_shadow=0 ;; esac
mismatched_keys=$(get_metric mismatched_keys); case "$mismatched_keys" in ''|*[!0-9]*) mismatched_keys=0 ;; esac
unique_dates=$(get_metric unique_dates); case "$unique_dates" in ''|*[!0-9]*) unique_dates=0 ;; esac
unique_macs=$(get_metric unique_macs); case "$unique_macs" in ''|*[!0-9]*) unique_macs=0 ;; esac
max_rx_diff=$(get_metric max_rx_diff); case "$max_rx_diff" in ''|*[!0-9]*) max_rx_diff=0 ;; esac
max_tx_diff=$(get_metric max_tx_diff); case "$max_tx_diff" in ''|*[!0-9]*) max_tx_diff=0 ;; esac
max_pct_bp=$(get_metric max_pct_bp); case "$max_pct_bp" in ''|*[!0-9]*) max_pct_bp=0 ;; esac
sample_missing_legacy=$(get_metric sample_missing_legacy)
sample_missing_shadow=$(get_metric sample_missing_shadow)
sample_mismatch=$(get_metric sample_mismatch)

cat > "$OUT_TXT" <<EOF2
HNC stats compare diagnostics
status=$status
legacy_file=$LEGACY
legacy_exists=$legacy_exists
legacy_lines=$legacy_lines
legacy_size_bytes=$legacy_size
legacy_invalid_lines=$legacy_invalid
shadow_file=$SHADOW
shadow_exists=$shadow_exists
shadow_lines=$shadow_lines
shadow_size_bytes=$shadow_size
shadow_invalid_lines=$shadow_invalid
total_keys=$total_keys
matched_keys=$matched_keys
missing_in_legacy=$missing_in_legacy
missing_in_shadow=$missing_in_shadow
mismatched_keys=$mismatched_keys
unique_dates=$unique_dates
unique_macs=$unique_macs
max_rx_diff=$max_rx_diff
max_tx_diff=$max_tx_diff
max_pct_bp=$max_pct_bp
sample_missing_legacy=$sample_missing_legacy
sample_missing_shadow=$sample_missing_shadow
sample_mismatch=$sample_mismatch
EOF2

cat > "$OUT_JSON" <<EOF2
{"ok":true,"status":"$(json_escape "$status")","legacy_file":"$(json_escape "$LEGACY")","legacy_exists":$legacy_exists,"legacy_lines":${legacy_lines:-0},"legacy_size_bytes":${legacy_size:-0},"legacy_invalid_lines":$legacy_invalid,"shadow_file":"$(json_escape "$SHADOW")","shadow_exists":$shadow_exists,"shadow_lines":${shadow_lines:-0},"shadow_size_bytes":${shadow_size:-0},"shadow_invalid_lines":$shadow_invalid,"total_keys":$total_keys,"matched_keys":$matched_keys,"missing_in_legacy":$missing_in_legacy,"missing_in_shadow":$missing_in_shadow,"mismatched_keys":$mismatched_keys,"unique_dates":$unique_dates,"unique_macs":$unique_macs,"max_rx_diff":$max_rx_diff,"max_tx_diff":$max_tx_diff,"max_pct_bp":$max_pct_bp,"sample_missing_legacy":"$(json_escape "$sample_missing_legacy")","sample_missing_shadow":"$(json_escape "$sample_missing_shadow")","sample_mismatch":"$(json_escape "$sample_mismatch")"}
EOF2

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  *) cat "$OUT_JSON" ;;
esac
exit 0
