#!/system/bin/sh
# test/unit/test_stats.sh — stats_sample.sh + stats_rollup.sh 单元测试

SAMPLE="$HNC_REPO_ROOT/bin/stats_sample.sh"
ROLLUP="$HNC_REPO_ROOT/bin/stats_rollup.sh"

ss() {
    HNC_DIR="$HNC_TEST_DIR" \
    STATS_ALL_CMD="echo \"$1\"" \
    sh "$SAMPLE"
}

seed_devices() {
    mkdir -p "$HNC_TEST_DIR/data"
    cat > "$HNC_TEST_DIR/data/devices.json" <<EOF
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:01","hostname":"Mi-10","hostname_src":"mdns"},"aa:bb:cc:dd:ee:02":{"ip":"192.168.43.20","mac":"aa:bb:cc:dd:ee:02","hostname":"iPhone","hostname_src":"manual"}}
EOF
}

# ═══ sample ═══════════════════════════════════════════════
test_start "sample: writes one JSONL line per MAC"
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_raw.jsonl"
ss "192.168.43.10 12345 67890
192.168.43.20 50000 30000" >/dev/null 2>&1
n=$(wc -l < "$HNC_TEST_DIR/data/stats_raw.jsonl" 2>/dev/null | tr -d ' ')
assert_eq "2" "$n" "should have 2 lines" && test_pass

test_start "sample: JSON has required fields"
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_raw.jsonl"
ss "192.168.43.10 111 222" >/dev/null 2>&1
line=$(head -1 "$HNC_TEST_DIR/data/stats_raw.jsonl")
assert_contains "$line" '"ts"' && \
    assert_contains "$line" '"mac":"aa:bb:cc:dd:ee:01"' && \
    assert_contains "$line" '"rx":111' && \
    assert_contains "$line" '"tx":222' && test_pass

test_start "sample: IP without MAC mapping is skipped"
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_raw.jsonl"
ss "192.168.43.10 500 600
192.168.99.99 9999 9999" >/dev/null 2>&1
n=$(wc -l < "$HNC_TEST_DIR/data/stats_raw.jsonl" 2>/dev/null | tr -d ' ')
assert_eq "1" "$n" "only known MAC should be recorded" && test_pass

test_start "sample: empty stats_all produces no file changes"
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_raw.jsonl"
ss "" >/dev/null 2>&1
if [ ! -f "$HNC_TEST_DIR/data/stats_raw.jsonl" ]; then
    test_pass
elif [ ! -s "$HNC_TEST_DIR/data/stats_raw.jsonl" ]; then
    test_pass
else
    test_fail "raw file should be empty when no stats"
fi

test_start "sample: missing devices.json does not crash"
rm -f "$HNC_TEST_DIR/data/devices.json" "$HNC_TEST_DIR/data/stats_raw.jsonl"
ss "192.168.43.10 100 200" >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "should not crash" && test_pass

# ═══ rollup ═══════════════════════════════════════════════
test_start "rollup: computes delta correctly with spike handling"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
T0=$YESTERDAY_TS
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$T0,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
{"ts":$((T0+3600)),"mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":200}
{"ts":$((T0+7200)),"mac":"aa:bb:cc:dd:ee:01","rx":3000,"tx":600}
{"ts":$((T0+10800)),"mac":"aa:bb:cc:dd:ee:01","rx":2000,"tx":400}
{"ts":$((T0+14400)),"mac":"aa:bb:cc:dd:ee:01","rx":4000,"tx":800}
EOF
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
line=$(head -1 "$HNC_TEST_DIR/data/stats_daily.jsonl")
# 预期: (1000-0)+(3000-1000)+max(0,2000-3000)+(4000-2000) = 5000
assert_contains "$line" '"rx":5000' && \
    assert_contains "$line" '"tx":1000' && test_pass

test_start "rollup: filters samples outside target date"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
TWO_DAYS_TS=$(($(date +%s) - 172800))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$TWO_DAYS_TS,"mac":"aa:bb:cc:dd:ee:01","rx":99999,"tx":99999}
{"ts":$YESTERDAY_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
{"ts":$((YESTERDAY_TS+3600)),"mac":"aa:bb:cc:dd:ee:01","rx":500,"tx":100}
EOF
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
line=$(head -1 "$HNC_TEST_DIR/data/stats_daily.jsonl")
assert_contains "$line" '"rx":500' && \
    assert_not_contains "$line" '99999' && test_pass

test_start "rollup: dedupes when run twice for same date"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$YESTERDAY_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
{"ts":$((YESTERDAY_TS+3600)),"mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":200}
EOF
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
n=$(wc -l < "$HNC_TEST_DIR/data/stats_daily.jsonl" | tr -d ' ')
assert_eq "1" "$n" "should have exactly 1 line after two rollups" && test_pass

test_start "rollup: uses manual name from device_names.json"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$YESTERDAY_TS,"mac":"aa:bb:cc:dd:ee:02","rx":0,"tx":0}
{"ts":$((YESTERDAY_TS+3600)),"mac":"aa:bb:cc:dd:ee:02","rx":500,"tx":100}
EOF
seed_devices
cat > "$HNC_TEST_DIR/data/device_names.json" <<EOF
{"aa:bb:cc:dd:ee:02":"客厅 iPhone"}
EOF
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
line=$(head -1 "$HNC_TEST_DIR/data/stats_daily.jsonl")
assert_contains "$line" '客厅 iPhone' && test_pass

test_start "rollup: falls back to hostname when no manual name"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$YESTERDAY_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
{"ts":$((YESTERDAY_TS+3600)),"mac":"aa:bb:cc:dd:ee:01","rx":500,"tx":100}
EOF
seed_devices
rm -f "$HNC_TEST_DIR/data/device_names.json"
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
line=$(head -1 "$HNC_TEST_DIR/data/stats_daily.jsonl")
assert_contains "$line" 'Mi-10' && test_pass

test_start "rollup: prunes raw older than retention window"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
OLD_TS=$(($(date +%s) - 200*3600))
RECENT_TS=$(($(date +%s) - 3600))
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
{"ts":$OLD_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
{"ts":$RECENT_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
EOF
seed_devices
RAW_RETAIN_HOURS=48 HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "2020-01-01" >/dev/null 2>&1
n=$(wc -l < "$HNC_TEST_DIR/data/stats_raw.jsonl" | tr -d ' ')
assert_eq "1" "$n" "old sample should be pruned" && test_pass

test_start "rollup: tolerates malformed JSONL lines"
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
YESTERDAY_TS=$(($(date +%s) - 86400))
YESTERDAY_DATE=$(date -d "@$YESTERDAY_TS" +%Y-%m-%d 2>/dev/null)
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<EOF
garbage not json
{"ts":$YESTERDAY_TS,"mac":"aa:bb:cc:dd:ee:01","rx":0,"tx":0}
partial line {"ts":
{"ts":$((YESTERDAY_TS+3600)),"mac":"aa:bb:cc:dd:ee:01","rx":500,"tx":100}
EOF
seed_devices
rm -f "$HNC_TEST_DIR/data/stats_daily.jsonl"
HNC_DIR="$HNC_TEST_DIR" sh "$ROLLUP" "$YESTERDAY_DATE" >/dev/null 2>&1
rc=$?
line=$(head -1 "$HNC_TEST_DIR/data/stats_daily.jsonl" 2>/dev/null)
assert_eq "0" "$rc" "should not crash" && \
    assert_contains "$line" '"rx":500' "should still extract valid data" && test_pass
