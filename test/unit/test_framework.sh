#!/system/bin/sh
# test/unit/test_framework.sh — 测试框架自检
# 这个测试存在的意义:确保 lib.sh 的 assert/mock 自身工作正常
# 必须 100% 通过,否则任何其他测试结果都不可信

test_start "assert_eq with equal values"
assert_eq "abc" "abc" "should match" && test_pass

test_start "assert_eq with different values (expect this to FAIL on purpose)"
# 这个测试故意测 assert 的失败路径
# 不能直接调 assert_eq + test_pass(那样会真失败)
# 我们用 subshell 验证 assert 函数行为
result=$( ( assert_eq "a" "b" "purposely different" >/dev/null 2>&1; echo $?; ) )
# assert_eq 失败时 return 1,所以 result 应该是 1
if [ "$result" = "1" ]; then
    test_pass
else
    test_fail "assert_eq did not return 1 on mismatch (got: $result)"
fi

test_start "assert_contains positive case"
assert_contains "hello world" "world" && test_pass

test_start "assert_contains negative case"
result=$( ( assert_contains "hello" "xyz" >/dev/null 2>&1; echo $?; ) )
if [ "$result" = "1" ]; then
    test_pass
else
    test_fail "assert_contains should return 1 (got: $result)"
fi

test_start "assert_file_exists positive"
echo "data" > "$HNC_TEST_DIR/exists.txt"
assert_file_exists "$HNC_TEST_DIR/exists.txt" && test_pass

test_start "assert_file_exists negative"
result=$( ( assert_file_exists "$HNC_TEST_DIR/nope.txt" >/dev/null 2>&1; echo $?; ) )
if [ "$result" = "1" ]; then
    test_pass
else
    test_fail "should return 1 for missing file (got: $result)"
fi

test_start "assert_json_valid positive"
echo '{"a":1,"b":[2,3]}' > "$HNC_TEST_DIR/test.json"
assert_json_valid "$HNC_TEST_DIR/test.json" && test_pass

test_start "assert_json_valid catches unbalanced braces"
echo '{"a":1' > "$HNC_TEST_DIR/bad.json"
result=$( ( assert_json_valid "$HNC_TEST_DIR/bad.json" >/dev/null 2>&1; echo $?; ) )
if [ "$result" = "1" ]; then
    test_pass
else
    test_fail "should detect unbalanced braces (got: $result)"
fi

test_start "mock_setup creates shell function mocks"
mock_setup
# v3.5.0 alpha-1: mock 现在是 shell function 不是 binary
# 验证 function 已定义
if type iptables 2>&1 | grep -q "function\|is a function\|()"; then
    test_pass
else
    # busybox sh 的 type 输出可能是 "iptables is a shell function"
    # 或者 "function" 关键字。退而求其次:直接调用看是否走 mock
    iptables --test-mock 2>/dev/null
    if [ -f "$MOCK_LOG" ] && grep -q "iptables|--test-mock" "$MOCK_LOG"; then
        test_pass
    else
        test_fail "mock function not active"
    fi
fi
mock_teardown

test_start "mock records command calls"
mock_setup
iptables -t mangle -A FOO -j ACCEPT
iptables -t nat -L
if grep -q "iptables|-t mangle -A FOO" "$MOCK_LOG" && \
   grep -q "iptables|-t nat -L" "$MOCK_LOG"; then
    test_pass
else
    test_fail "mock did not record calls correctly
    log content:
$(cat "$MOCK_LOG")"
fi
mock_teardown

test_start "assert_mock_called positive"
mock_setup
tc qdisc add dev wlan0 root htb
assert_mock_called "tc|qdisc add dev wlan0 root htb" && test_pass
mock_teardown

test_start "assert_mock_called negative"
mock_setup
tc qdisc add dev wlan0 root htb
result=$( ( assert_mock_called "ip|link" >/dev/null 2>&1; echo $?; ) )
if [ "$result" = "1" ]; then
    test_pass
else
    test_fail "should fail for missing call"
fi
mock_teardown

test_start "mock_set_stdout produces fixed output"
mock_setup
mock_set_stdout iptables "fake output line 1"
output=$(iptables -L)
assert_eq "fake output line 1" "$output" "stdout should match" && test_pass
mock_teardown

test_start "mock_set_exit produces non-zero exit"
mock_setup
mock_set_exit iptables 2
iptables -L
rc=$?
assert_eq "2" "$rc" "exit code should be 2" && test_pass
mock_teardown

test_start "mock_call_count counts correctly"
mock_setup
iptables -L
iptables -L
iptables -F
count=$(mock_call_count "iptables|-L")
assert_eq "2" "$count" "should count 2 -L calls" && test_pass
mock_teardown
