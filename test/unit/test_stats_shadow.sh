#!/system/bin/sh
# hotfix21.4 stats shadow writer + diagnostics smoke tests
set -eu

ROOT_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP_BASE="$ROOT_DIR/.tmp/test_stats_shadow.$$"
rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE/data" "$TMP_BASE/run" "$TMP_BASE/logs" "$TMP_BASE/bin"

cat > "$TMP_BASE/data/devices.json" <<'JSON'
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:01"},"aa:bb:cc:dd:ee:02":{"ip":"192.168.43.11","mac":"aa:bb:cc:dd:ee:02"}}
JSON

STATS_ALL_CMD='printf "%s\n" "192.168.43.10 100 50" "192.168.43.11 20 30" "192.168.43.99 999 999"' \
  HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_sample.sh"

[ -f "$TMP_BASE/data/stats_shadow_raw.jsonl" ]
lines=$(wc -l < "$TMP_BASE/data/stats_shadow_raw.jsonl" | tr -d ' ')
[ "$lines" = "2" ]
grep -q '"date":"' "$TMP_BASE/data/stats_shadow_raw.jsonl"
grep -q '"device_id":"mac:aa:bb:cc:dd:ee:01"' "$TMP_BASE/data/stats_shadow_raw.jsonl"
grep -q '"source":"iptables"' "$TMP_BASE/data/stats_shadow_raw.jsonl"
[ -f "$TMP_BASE/run/stats_shadow_last_date" ]

OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 HNC_STATS_SHADOW_ENABLE=1 sh "$ROOT_DIR/bin/stats_shadow_diag.sh" json)"
echo "$OUT" | grep -q '"enabled":true'
echo "$OUT" | grep -q '"raw_lines":2'
echo "$OUT" | grep -q '"unique_devices":2'
echo "$OUT" | grep -q '"invalid_lines":0'
echo "$OUT" | grep -q '"rollup_helper":'

TXT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_diag.sh" text)"
echo "$TXT" | grep -q 'HNC stats shadow diagnostics'
echo "$TXT" | grep -q 'rollup_helper='
echo "$TXT" | grep -q 'daily_file='


# rc1.15: when stats_all is empty because HNC_STATS has no per-device rules yet,
# shadow sampling should opportunistically ensure rules from devices.json and retry.
TMP_FALLBACK="$ROOT_DIR/.tmp/test_stats_shadow_ensure.$$"
rm -rf "$TMP_FALLBACK"
mkdir -p "$TMP_FALLBACK/data" "$TMP_FALLBACK/run" "$TMP_FALLBACK/logs" "$TMP_FALLBACK/bin"
cat > "$TMP_FALLBACK/data/devices.json" <<'JSON'
{"aa:bb:cc:dd:ee:03":{"ip":"192.168.43.12","mac":"aa:bb:cc:dd:ee:03"}}
JSON
cat > "$TMP_FALLBACK/bin/iptables_manager.sh" <<'SH'
#!/system/bin/sh
STATE="$HNC_DIR/run/ensure_called"
case "$1" in
  stats_all)
    if [ -f "$STATE" ]; then
      printf '%s\n' "192.168.43.12 1234 567"
    fi
    ;;
  ensure_stats)
    echo "$2" >> "$STATE"
    ;;
esac
exit 0
SH
HNC_DIR="$TMP_FALLBACK" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_shadow_sample.sh"
[ -f "$TMP_FALLBACK/run/ensure_called" ]
grep -q '^192\.168\.43\.12$' "$TMP_FALLBACK/run/ensure_called"
[ -f "$TMP_FALLBACK/data/stats_shadow_raw.jsonl" ]
grep -q '"device_id":"mac:aa:bb:cc:dd:ee:03"' "$TMP_FALLBACK/data/stats_shadow_raw.jsonl"
grep -q '"rx":1234' "$TMP_FALLBACK/data/stats_shadow_raw.jsonl"
grep -q '"tx":567' "$TMP_FALLBACK/data/stats_shadow_raw.jsonl"
rm -rf "$TMP_FALLBACK"


# rc1.16: readiness / gray report / review bundle should surface shadow raw,
# shadow daily, and legacy-vs-shadow comparison signals.
TMP_REPORT="$ROOT_DIR/.tmp/test_stats_shadow_report.$$"
rm -rf "$TMP_REPORT"
mkdir -p "$TMP_REPORT/data" "$TMP_REPORT/run" "$TMP_REPORT/logs" "$TMP_REPORT/bin"

cat > "$TMP_REPORT/data/stats_shadow_raw.jsonl" <<'JSON'
{"schema":1,"ts":1777455337,"date":"2026-04-29","device_id":"mac:aa:bb:cc:dd:ee:04","mac":"aa:bb:cc:dd:ee:04","rx":100,"tx":50,"ips":"192.168.43.14","ip_count":1,"source":"iptables"}
JSON
cat > "$TMP_REPORT/data/stats_shadow_daily.jsonl" <<'JSON'
{"schema":1,"date":"2026-04-29","device_id":"mac:aa:bb:cc:dd:ee:04","mac":"aa:bb:cc:dd:ee:04","rx":100,"tx":50,"samples":1,"baseline":"first_sample","source":"shadow_rollup","updated_ts":1777455337}
JSON
cat > "$TMP_REPORT/data/stats_daily.jsonl" <<'JSON'
{"schema":1,"date":"2026-04-29","device_id":"mac:aa:bb:cc:dd:ee:04","mac":"aa:bb:cc:dd:ee:04","rx":100,"tx":50,"samples":1,"source":"legacy"}
JSON
: > "$TMP_REPORT/data/stats_raw.jsonl"

cp "$ROOT_DIR/bin/stats_compare.sh" "$TMP_REPORT/bin/stats_compare.sh"
cp "$ROOT_DIR/bin/stats_migration_readiness.sh" "$TMP_REPORT/bin/stats_migration_readiness.sh"
chmod 755 "$TMP_REPORT/bin/stats_compare.sh" "$TMP_REPORT/bin/stats_migration_readiness.sh"

for h in stats_shadow_diag.sh stats_shadow_control.sh stats_source_diag.sh stats_retention_diag.sh stats_identity_diag.sh stats_shadow_rollup.sh; do
  cat > "$TMP_REPORT/bin/$h" <<'SH'
#!/system/bin/sh
echo '{"ok":true,"status":"ok","enabled":true}'
SH
  chmod 755 "$TMP_REPORT/bin/$h"
done

READINESS="$(HNC_DIR="$TMP_REPORT" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_migration_readiness.sh" json)"
echo "$READINESS" | grep -q '"shadow_state":"shadow_rollup_seen"'
echo "$READINESS" | grep -q '"shadow_quality":"observed"'
echo "$READINESS" | grep -q '"compare_quality":"compared"'
echo "$READINESS" | grep -q '"samples":1'
echo "$READINESS" | grep -q '"matched_keys":1'

for h in stats_v52_install_selfcheck.sh stats_v52_web_status.sh stats_v52_device_check.sh stats_v52_rc_smoke.sh stats_v52_rc1_switch.sh stats_v52_rc_control.sh stats_health_summary.sh; do
  cat > "$TMP_REPORT/bin/$h" <<'SH'
#!/system/bin/sh
name="$(basename "$0")"
case "$name" in
  stats_v52_install_selfcheck.sh) echo '{"ok":true,"status":"pass","install_ready":true,"first_boot_safe":true,"safe_to_enable_rc":true}' ;;
  stats_v52_web_status.sh) echo '{"ok":true,"status":"pass","severity":"ok"}' ;;
  stats_v52_device_check.sh) echo '{"ok":true,"status":"pass","rc_enable_ready":true}' ;;
  stats_v52_rc1_switch.sh) echo '{"ok":true,"status":"pass","legacy_default_preserved":true,"rc1_enabled":false,"rc_enabled":false,"default_source":"legacy"}' ;;
  *) echo '{"ok":true,"status":"pass"}' ;;
esac
SH
  chmod 755 "$TMP_REPORT/bin/$h"
done
cp "$ROOT_DIR/bin/stats_v52_gray_report.sh" "$TMP_REPORT/bin/stats_v52_gray_report.sh"
chmod 755 "$TMP_REPORT/bin/stats_v52_gray_report.sh"

GRAY="$(HNC_DIR="$TMP_REPORT" MODDIR="$TMP_REPORT" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_v52_gray_report.sh" json)"
echo "$GRAY" | grep -q '"shadow_state":"shadow_rollup_seen"'
echo "$GRAY" | grep -q '"compare_quality":"compared"'
echo "$GRAY" | grep -q '"shadow_daily_samples":1'

REVIEW="$(HNC_DIR="$TMP_REPORT" MODDIR="$TMP_REPORT" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_v52_review_bundle.sh" json)"
echo "$REVIEW" | grep -q '"shadow_state":"shadow_rollup_seen"'
echo "$REVIEW" | grep -q '"compare_quality":"compared"'

rm -rf "$TMP_REPORT"

rm -rf "$TMP_BASE"
echo "test_stats_shadow.sh: OK"
