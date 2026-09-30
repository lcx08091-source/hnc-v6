#!/system/bin/sh
# test/unit/test_hnc_clock.sh — v5.20 bin/hnc_clock.sh 时钟健壮性 helper + 各 shell 写入器的闸门

CLK="$HNC_REPO_ROOT/bin/hnc_clock.sh"
T2026=1790000000   # 2026-09-21

clk() {
    HNC_DIR="$HNC_TEST_DIR" sh "$CLK" "$@"
}

# ═══ sane ════════════════════════════════════════════════
test_start "hnc_clock sane: 1970 / 2000 / 2024 不可信, 2026 可信"
r1970=0; HNC_CLOCK_NOW=0 clk sane || r1970=1
r2000=0; HNC_CLOCK_NOW=946684800 clk sane || r2000=1
r2024=0; HNC_CLOCK_NOW=1735000000 clk sane || r2024=1
r2026=0; HNC_CLOCK_NOW=$T2026 clk sane || r2026=1
rbad=0; HNC_CLOCK_NOW=abc clk sane || rbad=1
assert_eq "1 1 1 0 1" "$r1970 $r2000 $r2024 $r2026 $rbad" "年份闸门" && test_pass

test_start "hnc_clock sane: 落后高水位 > 600s 不可信, 容忍 600s 内的回拨"
echo "$T2026" > "$HNC_TEST_DIR/data/clock_hwm"
a=0; HNC_CLOCK_NOW=$((T2026 - 1000)) clk sane || a=1
b=0; HNC_CLOCK_NOW=$((T2026 - 500)) clk sane || b=1
c=0; HNC_CLOCK_NOW=$((T2026 + 86400)) clk sane || c=1
assert_eq "1 0 0" "$a $b $c" "高水位闸门" && test_pass

# ═══ note ════════════════════════════════════════════════
test_start "hnc_clock note: 推进高水位(节流 300s), 不可信时不写"
HNC_CLOCK_NOW=100 clk note
v0=$([ -f "$HNC_TEST_DIR/data/clock_hwm" ] && echo written || echo none)
HNC_CLOCK_NOW=$T2026 clk note
v1=$(cat "$HNC_TEST_DIR/data/clock_hwm" 2>/dev/null)
HNC_CLOCK_NOW=$((T2026 + 100)) clk note
v2=$(cat "$HNC_TEST_DIR/data/clock_hwm" 2>/dev/null)
HNC_CLOCK_NOW=$((T2026 + 400)) clk note
v3=$(cat "$HNC_TEST_DIR/data/clock_hwm" 2>/dev/null)
assert_eq "none $T2026 $T2026 $((T2026 + 400))" "$v0 $v1 $v2 $v3" "高水位推进(1970 不写)" && test_pass

# ═══ jump ════════════════════════════════════════════════
test_start "hnc_clock jump: 墙钟与 uptime 偏差 > 600s 判跳变(前跳/回跳), 重启不误判"
o1=$(HNC_CLOCK_NOW=$T2026 HNC_CLOCK_UPTIME=1000 clk jump t); r1=$?
o2=$(HNC_CLOCK_NOW=$((T2026 + 300)) HNC_CLOCK_UPTIME=1300 clk jump t); r2=$?
o3=$(HNC_CLOCK_NOW=$((T2026 + 7500)) HNC_CLOCK_UPTIME=1600 clk jump t); r3=$?
o4=$(HNC_CLOCK_NOW=$((T2026 + 3900)) HNC_CLOCK_UPTIME=1900 clk jump t); r4=$?
o5=$(HNC_CLOCK_NOW=$((T2026 + 9000)) HNC_CLOCK_UPTIME=50 clk jump t); r5=$?
assert_eq "1 1 0 0 1" "$r1 $r2 $r3 $r4 $r5" "跳变判定" && \
    assert_eq "6900" "$o3" "前跳偏差" && \
    assert_eq "-3900" "$o4" "回跳偏差" && test_pass

# ═══ stats_sample 闸门 ══════════════════════════════════════
seed_devices_clk() {
    cat > "$HNC_TEST_DIR/data/devices.json" <<EOF
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:01"}}
EOF
    printf '%s\n' "192.168.43.10 111 222" > "$HNC_TEST_DIR/stats_all.in"
}
ss_clk() {
    HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 STATS_ALL_CMD="cat $HNC_TEST_DIR/stats_all.in" \
        sh "$HNC_REPO_ROOT/bin/stats_sample.sh" >/dev/null 2>&1
}

test_start "stats_sample: 时钟落后高水位 → 不采样、不写 stats_last_date"
seed_devices_clk
echo 9999999999 > "$HNC_TEST_DIR/data/clock_hwm"
ss_clk
assert_file_not_exists "$HNC_TEST_DIR/data/stats_raw.jsonl" "不可信时不能写采样" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/stats_last_date" "不可信时不能写跨日标记" && \
    assert_contains "$(cat "$HNC_TEST_DIR/logs/stats.log" 2>/dev/null)" "clock not trustworthy" && test_pass

test_start "stats_sample: 时钟可信 → 正常采样并推进高水位"
seed_devices_clk
ss_clk
assert_file_exists "$HNC_TEST_DIR/data/stats_raw.jsonl" && \
    assert_file_exists "$HNC_TEST_DIR/data/clock_hwm" "应记下高水位" && test_pass

# ═══ stats_rollup 闸门 ══════════════════════════════════════
test_start "stats_rollup: 时钟不可信 → 不清理 daily、不建 .backup"
echo 9999999999 > "$HNC_TEST_DIR/data/clock_hwm"
echo '{"date":"2026-01-01","mac":"aa:bb:cc:dd:ee:01","rx":1,"tx":1}' > "$HNC_TEST_DIR/data/stats_daily.jsonl"
echo '{"ts":1767225600,"mac":"aa:bb:cc:dd:ee:01","rx":1,"tx":1}' > "$HNC_TEST_DIR/data/stats_raw.jsonl"
HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/stats_rollup.sh" 2026-01-01 >/dev/null 2>&1
assert_contains "$(cat "$HNC_TEST_DIR/data/stats_daily.jsonl")" '"date":"2026-01-01"' "daily 不能被清" && \
    assert_contains "$(cat "$HNC_TEST_DIR/data/stats_raw.jsonl")" '"ts":1767225600' "raw 不能被清" && \
    assert_eq "" "$(ls -d "$HNC_TEST_DIR"/data/.backup-* 2>/dev/null)" "不能建备份目录" && test_pass

# ═══ cleanup_stale_rules 闸门 ═══════════════════════════════
test_start "cleanup_stale_rules: 时钟不可信 → 跳过 TTL 判定"
echo 9999999999 > "$HNC_TEST_DIR/data/clock_hwm"
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"stale_rule_ttl_days":30,"devices":{"cc:cc:cc:cc:cc:07":{"mark_id":7,"down_mbps":5,"limit_enabled":true,"last_seen_persist":1000}},"blacklist":[],"whitelist":[]}
EOF
echo '{}' > "$HNC_TEST_DIR/data/devices.json"
HNC_DIR="$HNC_TEST_DIR" HNC="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/cleanup_stale_rules.sh" >/dev/null 2>&1
assert_contains "$(cat "$HNC_TEST_DIR/logs/cleanup_stale.log" 2>/dev/null)" "clock not trustworthy" && \
    assert_contains "$(cat "$HNC_TEST_DIR/data/rules.json")" "cc:cc:cc:cc:cc:07" "规则不能被删" && test_pass
