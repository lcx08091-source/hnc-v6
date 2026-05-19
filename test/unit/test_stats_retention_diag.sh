#!/system/bin/sh
# hotfix21.2 stats_retention_diag.sh regression tests

SCRIPT="$HNC_REPO_ROOT/bin/stats_retention_diag.sh"

seed_stats_files() {
  mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs" "$HNC_TEST_DIR/bin"
  cp -f "$HNC_REPO_ROOT/bin/stats_rollup.sh" "$HNC_TEST_DIR/bin/stats_rollup.sh" 2>/dev/null || true
  now="$(date +%s 2>/dev/null)"
  case "$now" in ''|*[!0-9]*) now=1714000000 ;; esac
  old=1
  cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<JSON
{"ts":$old,"mac":"aa:bb:cc:dd:ee:01","rx":100,"tx":50}
{"ts":$now,"mac":"aa:bb:cc:dd:ee:01","rx":200,"tx":80}
not json
JSON
  cat > "$HNC_TEST_DIR/data/stats_daily.jsonl" <<JSON
{"date":"1970-01-01","mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":2000}
{"date":"2099-01-01","mac":"aa:bb:cc:dd:ee:01","rx":1001,"tx":2001}
bad daily
JSON
}

test_start "stats_retention_diag: reports old and invalid lines"
seed_stats_files
out=$(HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$SCRIPT" json 2>/dev/null)
assert_contains "$out" '"status":"warn"' && \
  assert_contains "$out" '"raw_retain_hours":48' && \
  assert_contains "$out" '"daily_retain_days":90' && \
  assert_contains "$out" '"invalid_lines":1' && \
  assert_contains "$out" '"older_than_retention_lines":1' && test_pass

test_start "stats_retention_diag: text mode includes retention summary"
seed_stats_files
out=$(HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$SCRIPT" text 2>/dev/null)
assert_contains "$out" 'HNC stats retention diagnostics' && \
  assert_contains "$out" 'raw_file=' && \
  assert_contains "$out" 'daily_file=' && \
  assert_contains "$out" 'rollup_defaults' && test_pass

test_start "stats_retention_diag: invalid retention config is fail"
seed_stats_files
out=$(HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 RAW_RETAIN_HOURS=bad sh "$SCRIPT" json 2>/dev/null)
assert_contains "$out" '"status":"fail"' && \
  assert_contains "$out" '"failures":1' && test_pass

