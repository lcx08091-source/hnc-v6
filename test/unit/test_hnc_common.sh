#!/system/bin/sh
# test_hnc_common.sh — bin/hnc_common.sh 单元测试 (since v5.3.0-rc30.12.35)
#
# 覆盖 hnc_log* / hnc_sq / hnc_json_get_top / hnc_lock_* / hnc_is_uint*.

# 找到 hnc_common.sh. 测试环境: 仓库根有 bin/hnc_common.sh; 装机环境: /data/local/hnc/bin/.
if [ -r "$HNC_REPO_ROOT/bin/hnc_common.sh" ]; then
    . "$HNC_REPO_ROOT/bin/hnc_common.sh"
elif [ -r "/data/local/hnc/bin/hnc_common.sh" ]; then
    . "/data/local/hnc/bin/hnc_common.sh"
else
    test_start "hnc_common.sh present"
    test_skip "hnc_common.sh not found"
    return
fi

# ─── hnc_log_init / hnc_log ─────────────────────────────────
test_start "hnc_log_init creates log dir + initial log line"
rm -rf "$HNC_TEST_DIR/log_subdir"
hnc_log_init "$HNC_TEST_DIR/log_subdir/test.log" "TESTTAG"
hnc_log "first line"
assert_eq "0" "$?" "hnc_log should succeed" || return
[ -f "$HNC_TEST_DIR/log_subdir/test.log" ] || { test_fail "log file not created"; return; }
grep -q "TESTTAG.*first line" "$HNC_TEST_DIR/log_subdir/test.log" || { test_fail "log line missing tag/content"; return; }
test_pass

test_start "hnc_log without init goes to stdout"
# 重置内部状态
_HNC_LOG_PATH=""
_HNC_LOG_TAG=""
out=$(hnc_log "stdout test")
case "$out" in
    *"stdout test"*) test_pass ;;
    *) test_fail "expected 'stdout test' in stdout, got: $out" ;;
esac

# ─── hnc_log_error 写 stderr ──────────────────────────────
test_start "hnc_log_error writes to stderr"
err=$(hnc_log_error "an error" 2>&1 1>/dev/null)
case "$err" in
    *"[ERROR]"*"an error"*) test_pass ;;
    *) test_fail "expected [ERROR] an error in stderr, got: $err" ;;
esac

# ─── hnc_sq shell-quote ───────────────────────────────────
test_start "hnc_sq handles simple string"
out=$(hnc_sq "hello")
assert_eq "'hello'" "$out" || return
test_pass

test_start "hnc_sq escapes single quote"
out=$(hnc_sq "it's")
assert_eq "'it'\\''s'" "$out" || return
test_pass

test_start "hnc_sq result is safe for sh -c eval"
val="hello'world"
expected="$val"
# 用 hnc_sq 拼接成 echo 命令, 应该原样输出
got=$(sh -c "echo $(hnc_sq "$val")")
assert_eq "$expected" "$got" || return
test_pass

# ─── hnc_json_get_top ────────────────────────────────────
test_start "hnc_json_get_top reads top-level string key"
TMP="$HNC_TEST_DIR/test_json.json"
cat > "$TMP" <<'EOF'
{
  "iface": "wlan0",
  "ssid": "test_network",
  "nested": {
    "iface": "should_not_match"
  }
}
EOF
out=$(hnc_json_get_top "$TMP" "iface")
assert_eq "wlan0" "$out" || return
test_pass

test_start "hnc_json_get_top missing key returns empty"
out=$(hnc_json_get_top "$TMP" "nonexistent_key")
assert_eq "" "$out" || return
test_pass

test_start "hnc_json_get_top missing file returns non-zero"
hnc_json_get_top "/nonexistent/path.json" "anykey"
assert_ne "0" "$?" "missing file should fail" || return
test_pass

# ─── hnc_lock_* ──────────────────────────────────────────
test_start "hnc_lock_acquire succeeds on fresh lock"
LOCK="$HNC_TEST_DIR/test.lock"
rm -f "$LOCK"
hnc_lock_acquire "$LOCK"
assert_eq "0" "$?" "fresh lock should succeed" || return
[ -f "$LOCK" ] || { test_fail "lock file not created"; return; }
test_pass

test_start "hnc_lock_release removes lockfile"
hnc_lock_release "$LOCK"
[ ! -f "$LOCK" ] || { test_fail "lockfile still exists after release"; return; }
test_pass

test_start "hnc_lock_acquire fails when current process holds lock"
# 用真实 pid (我们自己的 PID) 模拟"持锁者还活着"
echo $$ > "$LOCK"
hnc_lock_acquire "$LOCK"
assert_ne "0" "$?" "should refuse when active holder exists" || return
rm -f "$LOCK"
test_pass

test_start "hnc_lock_acquire succeeds when stale lock (dead PID)"
# 用 PID 1 之外的几乎不可能存在的高位 PID
echo "99999" > "$LOCK"
hnc_lock_acquire "$LOCK"
assert_eq "0" "$?" "stale lock should be re-acquirable" || return
rm -f "$LOCK"
test_pass

# ─── hnc_is_uint / hnc_is_uint_gt0 ────────────────────────
test_start "hnc_is_uint accepts 0 and positives"
hnc_is_uint "0" && hnc_is_uint "42" && hnc_is_uint "100"
assert_eq "0" "$?" "0/42/100 should be uint" || return
test_pass

test_start "hnc_is_uint rejects empty / negative / non-digits"
! hnc_is_uint "" && ! hnc_is_uint "-1" && ! hnc_is_uint "abc" && ! hnc_is_uint "1.5"
assert_eq "0" "$?" "empty / negative / abc / 1.5 should be rejected" || return
test_pass

test_start "hnc_is_uint_gt0 accepts positive only"
hnc_is_uint_gt0 "1" && hnc_is_uint_gt0 "100"
assert_eq "0" "$?" "1/100 should be uint_gt0" || return
test_pass

test_start "hnc_is_uint_gt0 rejects 0"
! hnc_is_uint_gt0 "0"
assert_eq "0" "$?" "0 should not be uint_gt0" || return
test_pass
