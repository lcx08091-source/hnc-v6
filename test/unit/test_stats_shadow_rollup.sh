#!/system/bin/sh
# hotfix21.4 stats shadow rollup tests
set -eu

ROOT_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP_BASE="$ROOT_DIR/.tmp/test_stats_shadow_rollup.$$"
rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE/data" "$TMP_BASE/run" "$TMP_BASE/logs"

cat > "$TMP_BASE/data/stats_shadow_raw.jsonl" <<'JSON'
{"schema":1,"ts":1000,"date":"2026-04-25","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":100,"tx":50,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
{"schema":1,"ts":2000,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":160,"tx":90,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
{"schema":1,"ts":3000,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":260,"tx":140,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
{"schema":1,"ts":2100,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:02","mac":"aa:bb:cc:dd:ee:02","rx":20,"tx":30,"ips":"192.168.43.11","ip_count":1,"source":"iptables"}
{"schema":1,"ts":3100,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:02","mac":"aa:bb:cc:dd:ee:02","rx":80,"tx":55,"ips":"192.168.43.11","ip_count":1,"source":"iptables"}
{"schema":1,"ts":4000,"date":"2026-04-27","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":300,"tx":160,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
JSON

HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_rollup.sh" 2026-04-26
[ -f "$TMP_BASE/data/stats_shadow_daily.jsonl" ]

grep -q '"date":"2026-04-26"' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"device_id":"mac:aa:bb:cc:dd:ee:01"' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"rx":160' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"tx":90' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"baseline":"previous_day"' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"device_id":"mac:aa:bb:cc:dd:ee:02"' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"rx":60' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"tx":25' "$TMP_BASE/data/stats_shadow_daily.jsonl"
grep -q '"baseline":"first_sample"' "$TMP_BASE/data/stats_shadow_daily.jsonl"

# Rollup is idempotent: re-running for the same date must replace rows, not duplicate them.
HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_rollup.sh" 2026-04-26
count=$(grep -c '"date":"2026-04-26"' "$TMP_BASE/data/stats_shadow_daily.jsonl")
[ "$count" = "2" ]

OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_diag.sh" json)"
echo "$OUT" | grep -q '"daily_lines":2'
echo "$OUT" | grep -q '"daily_invalid_lines":0'
echo "$OUT" | grep -q '"daily_unique_devices":2'

rm -rf "$TMP_BASE"
echo "test_stats_shadow_rollup.sh: OK"

# rc1.19: same-day counter reset to 0 must not erase already accumulated daily traffic.
TMP_RESET="$ROOT_DIR/.tmp/test_stats_shadow_rollup_reset.$$"
rm -rf "$TMP_RESET"
mkdir -p "$TMP_RESET/data" "$TMP_RESET/run" "$TMP_RESET/logs"
cat > "$TMP_RESET/data/stats_shadow_raw.jsonl" <<'JSON'
{"schema":1,"ts":1777465121,"date":"2026-04-29","device_id":"mac:8a:47:4c:9f:24:54","mac":"8a:47:4c:9f:24:54","rx":227138,"tx":3952,"ips":"10.183.150.52","ip_count":1,"source":"iptables"}
{"schema":1,"ts":1777465407,"date":"2026-04-29","device_id":"mac:8a:47:4c:9f:24:54","mac":"8a:47:4c:9f:24:54","rx":56021628,"tx":48556148,"ips":"10.183.150.52","ip_count":1,"source":"iptables"}
{"schema":1,"ts":1777467005,"date":"2026-04-29","device_id":"mac:8a:47:4c:9f:24:54","mac":"8a:47:4c:9f:24:54","rx":201628922,"tx":149591042,"ips":"10.183.150.52","ip_count":1,"source":"iptables"}
{"schema":1,"ts":1777476663,"date":"2026-04-29","device_id":"mac:8a:47:4c:9f:24:54","mac":"8a:47:4c:9f:24:54","rx":0,"tx":0,"ips":"10.214.37.52","ip_count":1,"source":"iptables"}
JSON
HNC_DIR="$TMP_RESET" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_rollup.sh" 2026-04-29
grep -q '"rx":201401784' "$TMP_RESET/data/stats_shadow_daily.jsonl"
grep -q '"tx":149587090' "$TMP_RESET/data/stats_shadow_daily.jsonl"
grep -q '"samples":4' "$TMP_RESET/data/stats_shadow_daily.jsonl"
grep -q '"baseline":"first_sample+counter_reset+zero_reset_preserved"' "$TMP_RESET/data/stats_shadow_daily.jsonl"
rm -rf "$TMP_RESET"
echo "test_stats_shadow_rollup_reset.sh: OK"
