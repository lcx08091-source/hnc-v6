#!/system/bin/sh
# test/unit/test_templates.sh — json_set.sh tpl_* 子命令单元测试

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"
TPL_FILE="$HNC_TEST_DIR/data/templates.json"

js() {
    HNC="$HNC_TEST_DIR" sh "$JSON_SET" "$@"
}

# ═══ tpl_list on missing file ════════════════════════════
test_start "tpl_list on missing file returns empty object"
rm -f "$TPL_FILE"
out=$(js tpl_list)
assert_eq "{}" "$out" "should return {} when file missing" && test_pass

# ═══ tpl_set creates file + first entry ══════════════════
test_start "tpl_set creates templates.json with first entry"
rm -f "$TPL_FILE"
js tpl_set "gaming" 50 20 0 0 0
assert_file_exists "$TPL_FILE" && \
    assert_json_valid "$TPL_FILE" && test_pass

test_start "tpl_set first entry has correct numeric fields"
rm -f "$TPL_FILE"
js tpl_set "gaming" 50 20 100 10 2
content=$(cat "$TPL_FILE")
assert_contains "$content" '"gaming"' && \
    assert_contains "$content" '"down_mbps":50' && \
    assert_contains "$content" '"up_mbps":20' && \
    assert_contains "$content" '"delay_ms":100' && \
    assert_contains "$content" '"jitter_ms":10' && \
    assert_contains "$content" '"loss_pct":2' && test_pass

# ═══ tpl_set overwrite existing ══════════════════════════
test_start "tpl_set overwrites existing template"
rm -f "$TPL_FILE"
js tpl_set "gaming" 50 20 0 0 0
js tpl_set "gaming" 100 50 0 0 0
content=$(cat "$TPL_FILE")
# 只应该有一个 gaming, 且新值生效
count=$(echo "$content" | grep -oE '"gaming"' | wc -l)
assert_eq "1" "$count" "gaming should appear once" && \
    assert_contains "$content" '"down_mbps":100' && test_pass

# ═══ multiple templates ══════════════════════════════════
test_start "tpl_set with 3 templates preserves all"
rm -f "$TPL_FILE"
js tpl_set "a" 10 5 0 0 0
js tpl_set "b" 20 10 0 0 0
js tpl_set "c" 30 15 0 0 0
content=$(cat "$TPL_FILE")
assert_contains "$content" '"a"' && \
    assert_contains "$content" '"b"' && \
    assert_contains "$content" '"c"' && \
    assert_json_valid "$TPL_FILE" && test_pass

# ═══ tpl_del middle entry ════════════════════════════════
test_start "tpl_del removes middle entry, keeps others"
rm -f "$TPL_FILE"
js tpl_set "a" 10 5 0 0 0
js tpl_set "b" 20 10 0 0 0
js tpl_set "c" 30 15 0 0 0
js tpl_del "b"
content=$(cat "$TPL_FILE")
assert_contains "$content" '"a"' && \
    assert_not_contains "$content" '"b"' && \
    assert_contains "$content" '"c"' && \
    assert_json_valid "$TPL_FILE" && test_pass

# ═══ tpl_del last entry ══════════════════════════════════
test_start "tpl_del on only entry leaves empty object"
rm -f "$TPL_FILE"
js tpl_set "a" 10 5 0 0 0
js tpl_del "a"
content=$(cat "$TPL_FILE")
assert_eq "{}" "$content" "should be empty object" && test_pass

# ═══ tpl_del non-existent ════════════════════════════════
test_start "tpl_del on non-existent template is no-op"
rm -f "$TPL_FILE"
js tpl_set "a" 10 5 0 0 0
js tpl_del "does_not_exist"
rc=$?
assert_eq "0" "$rc" "should succeed silently" && \
    assert_json_valid "$TPL_FILE" && test_pass

# ═══ 数字校验(防 NaN/负数/字母注入到 JSON) ═══════════════
test_start "tpl_set rejects negative numbers"
rm -f "$TPL_FILE"
js tpl_set "evil" -5 10 0 0 0 2>/dev/null
rc=$?
assert_exit_nonzero "$rc" "should reject negative" && test_pass

test_start "tpl_set rejects NaN"
js tpl_set "evil" NaN 10 0 0 0 2>/dev/null
rc=$?
assert_exit_nonzero "$rc" "should reject NaN" && test_pass

test_start "tpl_set rejects non-numeric"
js tpl_set "evil" abc 10 0 0 0 2>/dev/null
rc=$?
assert_exit_nonzero "$rc" "should reject alpha" && test_pass

# ═══ shell 注入尝试 ═══════════════════════════════════════
test_start "tpl_set with shell metachars in name does not execute"
rm -f "$TPL_FILE"
CANARY="$HNC_TEST_DIR/canary_should_not_exist"
rm -f "$CANARY"
# 真实攻击:如果 name 没转义,`; touch CANARY; #` 会跑
js tpl_set '"; touch '"$CANARY"'; #' 10 5 0 0 0 2>/dev/null
if [ ! -f "$CANARY" ]; then
    assert_json_valid "$TPL_FILE" && test_pass
else
    rm -f "$CANARY"
    test_fail "canary file created - shell injection succeeded"
fi

# ═══ 中文 + emoji name ═══════════════════════════════════
test_start "tpl_set with Chinese + emoji name round-trips"
rm -f "$TPL_FILE"
js tpl_set "游戏🎮" 50 20 0 0 0
content=$(cat "$TPL_FILE")
assert_contains "$content" '游戏' && \
    assert_json_valid "$TPL_FILE" && test_pass

# ═══ 浮点数字 ═════════════════════════════════════════════
test_start "tpl_set accepts float values"
rm -f "$TPL_FILE"
js tpl_set "slow" 0.5 0.25 0 0 0
content=$(cat "$TPL_FILE")
assert_contains "$content" '"down_mbps":0.5' && \
    assert_contains "$content" '"up_mbps":0.25' && test_pass

# ═══ lock(并发写安全) ════════════════════════════════════
test_start "concurrent tpl_set does not corrupt JSON"
rm -f "$TPL_FILE"
for i in 1 2 3 4 5; do
    js tpl_set "tpl$i" "$((i*10))" "$i" 0 0 0 >/dev/null 2>&1 &
done
wait
assert_json_valid "$TPL_FILE" && test_pass
