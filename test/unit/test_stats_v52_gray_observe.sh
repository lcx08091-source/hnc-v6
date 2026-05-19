#!/system/bin/sh
# Unit test for stats_v52_gray_observe.sh.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
WORK="${TMPDIR:-/tmp}/hnc_test_gray_observe_$$"
HNC_DIR="$WORK/hnc"
rm -rf "$WORK"
mkdir -p "$HNC_DIR/bin" "$HNC_DIR/run" "$HNC_DIR/data" "$HNC_DIR/logs"

cp "$ROOT/bin/stats_v52_gray_observe.sh" "$HNC_DIR/bin/stats_v52_gray_observe.sh"
chmod 755 "$HNC_DIR/bin/stats_v52_gray_observe.sh"

cat > "$HNC_DIR/module.prop" <<'EOF'
id=hotspot_network_control
version=v5.2.0-rc1.21
versionCode=520031
EOF

cat > "$HNC_DIR/data/devices.json" <<'JSON'
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:01","status":"online","active":true},"aa:bb:cc:dd:ee:02":{"ip":"192.168.43.11","mac":"aa:bb:cc:dd:ee:02","status":"blocked","active":true}}
JSON

cat > "$HNC_DIR/bin/stats_migration_readiness.sh" <<'SH2'
#!/bin/sh
cat <<'EOF'
HNC stats migration readiness
status=ready
shadow_state=shadow_rollup_seen
shadow_quality=observed
shadow_raw_lines=2
shadow_daily_lines=1
shadow_daily_samples=2
shadow_latest_ts=1777455337
shadow_raw_total_rx=1000
shadow_raw_total_tx=400
shadow_daily_total_rx=1000
shadow_daily_total_tx=400
compare_quality=compared
compare_matched_keys=2
compare_missing_in_legacy=0
compare_missing_in_shadow=0
compare_mismatched_keys=0
EOF
SH2
chmod 755 "$HNC_DIR/bin/stats_migration_readiness.sh"

for h in stats_v52_gray_report.sh stats_v52_review_bundle.sh; do
  cat > "$HNC_DIR/bin/$h" <<'SH2'
#!/bin/sh
case "$(basename "$0")" in
  stats_v52_gray_report.sh) echo 'status=pass' ;;
  stats_v52_review_bundle.sh) echo 'status=pass' ;;
esac
SH2
  chmod 755 "$HNC_DIR/bin/$h"
done
cat > "$HNC_DIR/bin/stats_v52_rc1_switch.sh" <<'SH2'
#!/bin/sh
cat <<'EOF'
status=disabled
legacy_default_preserved=true
default_source=legacy
rc1_enabled=false
rc_enabled=false
EOF
SH2
chmod 755 "$HNC_DIR/bin/stats_v52_rc1_switch.sh"

HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text > "$WORK/out.txt"
HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" json > "$WORK/out.json"
HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" markdown > "$WORK/out.md"

grep -q 'status=pass' "$WORK/out.txt"
grep -q 'traffic_state=traffic_seen' "$WORK/out.txt"
grep -q 'devices_total=2' "$WORK/out.txt"
grep -q 'devices_blocked=1' "$WORK/out.txt"
grep -q 'compare_quality=compared' "$WORK/out.txt"
grep -q '"status":"pass"' "$WORK/out.json"
grep -q '"traffic_state":"traffic_seen"' "$WORK/out.json"
grep -q '"devices_blocked":1' "$WORK/out.json"
grep -q 'rc1.21 实机灰度 checklist' "$WORK/out.md"
[ -f "$HNC_DIR/run/stats_v52_gray_observe.json" ]
[ -f "$HNC_DIR/run/stats_v52_gray_observe.txt" ]
[ -f "$HNC_DIR/run/stats_v52_gray_observe.md" ]

# Zero-traffic shadow should stay observable but warn, not fail.
cat > "$HNC_DIR/bin/stats_migration_readiness.sh" <<'SH2'
#!/bin/sh
cat <<'EOF'
status=ready
shadow_state=shadow_rollup_seen
shadow_quality=observed_zero_traffic
shadow_raw_lines=1
shadow_daily_lines=1
shadow_daily_samples=1
shadow_latest_ts=1777455337
shadow_raw_total_rx=0
shadow_raw_total_tx=0
shadow_daily_total_rx=0
shadow_daily_total_tx=0
compare_quality=warn_drift
compare_matched_keys=0
compare_missing_in_legacy=1
compare_missing_in_shadow=1
compare_mismatched_keys=0
EOF
SH2
chmod 755 "$HNC_DIR/bin/stats_migration_readiness.sh"
HNC_TEST_MODE=1 HNC_V52_OBSERVE_REFRESH=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text > "$WORK/warn.txt"
grep -q 'status=warn' "$WORK/warn.txt"
grep -q 'traffic_state=zero_traffic_observed' "$WORK/warn.txt"

# rc1.21: positive totals must override stale observed_zero_traffic readiness quality.
cat > "$HNC_DIR/bin/stats_migration_readiness.sh" <<'SH2'
#!/bin/sh
cat <<'EOF'
status=ready
shadow_state=shadow_rollup_seen
shadow_quality=observed_zero_traffic
shadow_raw_lines=11
shadow_daily_lines=2
shadow_daily_samples=11
shadow_latest_ts=1777478345
shadow_raw_total_rx=1870012253
shadow_raw_total_tx=471750798
shadow_daily_total_rx=574660971
shadow_daily_total_tx=198851760
compare_quality=warn_drift
compare_matched_keys=0
compare_missing_in_legacy=2
compare_missing_in_shadow=14
compare_mismatched_keys=0
EOF
SH2
chmod 755 "$HNC_DIR/bin/stats_migration_readiness.sh"
HNC_TEST_MODE=1 HNC_V52_OBSERVE_REFRESH=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text > "$WORK/positive_override.txt"
grep -q 'traffic_state=traffic_seen' "$WORK/positive_override.txt"
grep -q 'shadow_quality=observed' "$WORK/positive_override.txt"

# Default mode should auto-rollup only when raw samples exist, and should not
# implicitly run the shadow sampler. Explicit sample mode still calls both
# sample and rollup helpers.
cat > "$HNC_DIR/bin/stats_shadow_sample.sh" <<'SH2'
#!/bin/sh
echo sample >> "$HNC_DIR/run/sample_called"
SH2
cat > "$HNC_DIR/bin/stats_shadow_rollup.sh" <<'SH2'
#!/bin/sh
echo "$1" >> "$HNC_DIR/run/rollup_called"
SH2
chmod 755 "$HNC_DIR/bin/stats_shadow_sample.sh" "$HNC_DIR/bin/stats_shadow_rollup.sh"

rm -f "$HNC_DIR/data/stats_shadow_raw.jsonl" "$HNC_DIR/run/sample_called" "$HNC_DIR/run/rollup_called"
HNC_TEST_MODE=1 HNC_V52_OBSERVE_REFRESH=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text > "$WORK/no_raw.txt"
[ ! -f "$HNC_DIR/run/sample_called" ]
[ ! -f "$HNC_DIR/run/rollup_called" ]
grep -q 'auto_rollup_used=false' "$WORK/no_raw.txt"

cat > "$HNC_DIR/data/stats_shadow_raw.jsonl" <<'JSON'
{"schema":1,"ts":1777455337,"date":"2026-04-29","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":400,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
{"schema":1,"ts":1777465337,"date":"2026-04-29","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":2000,"tx":800,"ips":"192.168.43.10","ip_count":1,"source":"iptables"}
JSON
rm -f "$HNC_DIR/run/sample_called" "$HNC_DIR/run/rollup_called"
HNC_TEST_MODE=1 HNC_V52_OBSERVE_REFRESH=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text > "$WORK/auto_rollup.txt"
[ ! -f "$HNC_DIR/run/sample_called" ]
[ -f "$HNC_DIR/run/rollup_called" ]
grep -q '^2026-04-29$' "$HNC_DIR/run/rollup_called"
grep -q 'auto_rollup_used=true' "$WORK/auto_rollup.txt"
grep -q 'auto_rollup_date=2026-04-29' "$WORK/auto_rollup.txt"

rm -f "$HNC_DIR/run/sample_called" "$HNC_DIR/run/rollup_called"
HNC_TEST_MODE=1 HNC_V52_OBSERVE_SAMPLE=1 HNC_V52_OBSERVE_REFRESH=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_observe.sh" text >/dev/null
[ -f "$HNC_DIR/run/sample_called" ]
[ -f "$HNC_DIR/run/rollup_called" ]

rm -rf "$WORK"
echo "[OK] stats_v52_gray_observe"
