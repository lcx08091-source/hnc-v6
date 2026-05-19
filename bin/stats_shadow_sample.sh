#!/system/bin/sh
# stats_shadow_sample.sh — HNC v5.2-rc1.15 shadow stats writer
#
# Optional v5.2 migration stream. Disabled by default from stats_sample.sh;
# when enabled, it writes MAC/device_id based cumulative samples into
# stats_shadow_raw.jsonl and triggers shadow rollup across date changes.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
LOG="$HNC_DIR/logs/stats.log"
RAW_FILE="$DATA/stats_shadow_raw.jsonl"
DEVICES_FILE="$DATA/devices.json"
IPT_MGR="$HNC_DIR/bin/iptables_manager.sh"
STATS_ALL_CMD=${STATS_ALL_CMD:-"sh $IPT_MGR stats_all"}

extract_device_ips() {
  grep -oE '"ip"[[:space:]]*:[[:space:]]*"([0-9]{1,3}\.){3}[0-9]{1,3}"' "$DEVICES_FILE" 2>/dev/null | \
    sed -nE 's/.*"(([0-9]{1,3}\.){3}[0-9]{1,3})".*/\1/p' | \
    awk '$0 != "" && !seen[$0]++'
}

ensure_shadow_stats_rules() {
  [ -f "$IPT_MGR" ] || return 1
  local count=0
  local ip
  for ip in $(extract_device_ips); do
    case "$ip" in
      *.*.*.*) ;;
      *) continue ;;
    esac
    sh "$IPT_MGR" ensure_stats "$ip" >/dev/null 2>&1 && count=$((count + 1))
  done
  [ "$count" -gt 0 ] && log "stats_all empty; ensured $count shadow stats rule(s), retrying"
  [ "$count" -gt 0 ]
}

log() {
  [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [STATS_SHADOW] $*" >> "$LOG" 2>/dev/null || true
}

mkdir -p "$DATA" "$RUN" 2>/dev/null

if [ ! -f "$DEVICES_FILE" ]; then
  log "WARN: devices.json missing, shadow sample skipped"
  exit 0
fi

stats_out=$(eval "$STATS_ALL_CMD" 2>/dev/null)
if [ -z "$stats_out" ]; then
  ensure_shadow_stats_rules || true
  stats_out=$(eval "$STATS_ALL_CMD" 2>/dev/null)
fi
[ -n "$stats_out" ] || exit 0

ts=$(date +%s 2>/dev/null)
case "$ts" in ''|*[!0-9]*) log "WARN: date +%s failed"; exit 1 ;; esac
today=$(date +%Y-%m-%d 2>/dev/null)
case "$today" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) today="unknown" ;; esac

MAP_TMP="$RUN/stats_shadow_map.$$"
OUT_TMP="$RUN/stats_shadow_out.$$"
trap 'rm -f "$MAP_TMP" "$OUT_TMP" 2>/dev/null' EXIT INT TERM
: > "$MAP_TMP"

grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$DEVICES_FILE" 2>/dev/null | \
while IFS= read -r block; do
  mac=$(echo "$block" | sed -nE 's/^"([0-9a-fA-F:]+)".*/\1/p' | tr 'A-F' 'a-f')
  ip=$(echo "$block" | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')
  [ -n "$mac" ] && [ -n "$ip" ] && echo "$ip $mac" >> "$MAP_TMP"
done

[ -s "$MAP_TMP" ] || exit 0

printf '%s\n' "$stats_out" | awk -v mapfile="$MAP_TMP" -v ts="$ts" -v today="$today" '
BEGIN {
  while ((getline line < mapfile) > 0) {
    split(line, a, " ")
    if (a[1] != "" && a[2] != "") ip2mac[a[1]] = a[2]
  }
  close(mapfile)
}
$1 != "" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
  ip = $1
  mac = ip2mac[ip]
  if (mac == "") next
  rx[mac] += $2
  tx[mac] += $3
  if (ips[mac] == "") {
    ips[mac] = ip
    ip_count[mac] = 1
  } else if (index("," ips[mac] ",", "," ip ",") == 0) {
    ips[mac] = ips[mac] "," ip
    ip_count[mac]++
  }
}
END {
  for (mac in rx) {
    device_id = "mac:" mac
    printf "{\"schema\":1,\"ts\":%d,\"date\":\"%s\",\"device_id\":\"%s\",\"mac\":\"%s\",\"rx\":%d,\"tx\":%d,\"ips\":\"%s\",\"ip_count\":%d,\"source\":\"iptables\"}\n", ts, today, device_id, mac, rx[mac], tx[mac], ips[mac], ip_count[mac]
  }
}' > "$OUT_TMP"

[ -s "$OUT_TMP" ] || exit 0
cat "$OUT_TMP" >> "$RAW_FILE"
lines=$(wc -l < "$OUT_TMP" 2>/dev/null | tr -d ' ')
log "shadow sampled ${lines:-0} device(s)"

# hotfix21.4: shadow daily rollup trigger. This is separate from the legacy
# stats_last_date marker and only affects stats_shadow_daily.jsonl.
MARKER="$RUN/stats_shadow_last_date"
last_date=$(cat "$MARKER" 2>/dev/null)
if [ "$today" != "unknown" ] && [ -n "$last_date" ] && [ "$today" != "$last_date" ]; then
  if [ -x "$HNC_DIR/bin/stats_shadow_rollup.sh" ]; then
    log "shadow date changed: $last_date -> $today, rolling $last_date"
    sh "$HNC_DIR/bin/stats_shadow_rollup.sh" "$last_date" >> "$LOG" 2>&1 || log "WARN: shadow rollup failed (rc=$?)"
  else
    log "WARN: stats_shadow_rollup.sh missing"
  fi
fi
[ "$today" != "unknown" ] && echo "$today" > "$MARKER" 2>/dev/null

exit 0
