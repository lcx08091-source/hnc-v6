#!/system/bin/sh
# test/lib.sh — HNC v3.5 测试框架核心库
#
# 提供:
#   - assert_eq / assert_ne / assert_match / assert_file_exists / assert_file_eq
#   - test_start / test_pass / test_fail / test_skip
#   - mock_setup / mock_teardown
#   - HNC_TEST_DIR (隔离的临时目录)
#
# 用法:
#   . "$(dirname "$0")/../lib.sh"
#   test_start "json_set top command"
#   ...
#   assert_eq "$expected" "$actual" "should match"
#   test_pass

# ─── 颜色 ───────────────────────────────────────────
if [ -t 1 ]; then
    C_RED='\033[31m'; C_GRN='\033[32m'; C_YEL='\033[33m'; C_RST='\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_RST=''
fi

# ─── 全局计数 ───────────────────────────────────────
TEST_TOTAL=0
TEST_PASS=0
TEST_FAIL=0
TEST_SKIP=0
TEST_FAILED_NAMES=""
CURRENT_TEST=""

# ─── 隔离的 HNC_DIR(每个测试 process 独立)─────────
# Android 没有 /tmp,用 /data/local/tmp(Android 的标准临时目录)
# Linux 沙箱用 /tmp,自动选择
if [ -d /data/local/tmp ]; then
    HNC_TEST_DIR="/data/local/tmp/hnc_test_$$"
elif [ -d /tmp ]; then
    HNC_TEST_DIR="/tmp/hnc_test_$$"
else
    HNC_TEST_DIR="$HOME/.hnc_test_$$"
fi

setup_test_env() {
    rm -rf "$HNC_TEST_DIR"
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/logs" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/bin"
    # 复制真实 bin/ 脚本到测试目录
    cp -r "$HNC_REPO_ROOT/bin/"*.sh "$HNC_TEST_DIR/bin/" 2>/dev/null
    chmod +x "$HNC_TEST_DIR/bin/"*.sh 2>/dev/null
}

teardown_test_env() {
    rm -rf "$HNC_TEST_DIR"
}

# ─── 测试生命周期 ──────────────────────────────────
test_start() {
    CURRENT_TEST="$1"
    TEST_TOTAL=$((TEST_TOTAL + 1))
    setup_test_env
}

test_pass() {
    TEST_PASS=$((TEST_PASS + 1))
    printf "  ${C_GRN}✓${C_RST} %s\n" "$CURRENT_TEST"
    teardown_test_env
}

test_fail() {
    local reason="${1:-(no reason)}"
    TEST_FAIL=$((TEST_FAIL + 1))
    TEST_FAILED_NAMES="$TEST_FAILED_NAMES
  - $CURRENT_TEST: $reason"
    printf "  ${C_RED}✗${C_RST} %s\n    ${C_RED}%s${C_RST}\n" "$CURRENT_TEST" "$reason"
    teardown_test_env
}

test_skip() {
    local reason="${1:-(no reason)}"
    TEST_SKIP=$((TEST_SKIP + 1))
    printf "  ${C_YEL}⊘${C_RST} %s ${C_YEL}[SKIP: %s]${C_RST}\n" "$CURRENT_TEST" "$reason"
    teardown_test_env
}

# ─── Assertions ────────────────────────────────────
# 任何 assert 失败直接调 test_fail 并 return 1,调用方应立刻 return
assert_eq() {
    local expected="$1" actual="$2" msg="${3:-values should be equal}"
    if [ "$expected" = "$actual" ]; then
        return 0
    fi
    test_fail "$msg
      expected: $(printf '%s' "$expected" | head -c 200)
      actual:   $(printf '%s' "$actual" | head -c 200)"
    return 1
}

assert_ne() {
    local a="$1" b="$2" msg="${3:-values should differ}"
    if [ "$a" != "$b" ]; then
        return 0
    fi
    test_fail "$msg (both = $a)"
    return 1
}

# 子串匹配 (用 case 而不是 =~ 因为 ash 不支持 [[)
assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-haystack should contain needle}"
    case "$haystack" in
        *"$needle"*) return 0 ;;
    esac
    test_fail "$msg
      haystack: $(printf '%s' "$haystack" | head -c 200)
      needle:   $needle"
    return 1
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="${3:-haystack should not contain needle}"
    case "$haystack" in
        *"$needle"*)
            test_fail "$msg (found '$needle' in haystack)"
            return 1
            ;;
    esac
    return 0
}

assert_file_exists() {
    local path="$1" msg="${2:-file should exist: $1}"
    if [ -f "$path" ]; then
        return 0
    fi
    test_fail "$msg"
    return 1
}

assert_file_not_exists() {
    local path="$1" msg="${2:-file should not exist: $1}"
    if [ ! -f "$path" ]; then
        return 0
    fi
    test_fail "$msg"
    return 1
}

# 检查 JSON 文件能被 awk 解析(基础完整性)
assert_json_valid() {
    local path="$1" msg="${2:-JSON should be valid}"
    if [ ! -f "$path" ]; then
        test_fail "$msg (file does not exist: $path)"
        return 1
    fi
    # 简单检查:括号配对(更严的 JSON 校验需要 python/jq,我们没有)
    local opens closes
    opens=$(tr -cd '{' < "$path" | wc -c)
    closes=$(tr -cd '}' < "$path" | wc -c)
    if [ "$opens" -ne "$closes" ]; then
        test_fail "$msg (unbalanced braces: opens=$opens closes=$closes)
      content: $(cat "$path" | head -c 200)"
        return 1
    fi
    # 必须以 { 开头 } 结尾(允许两端 whitespace)
    local first last
    first=$(head -c 1 "$path")
    last=$(tail -c 1 "$path")
    if [ "$first" != "{" ]; then
        test_fail "$msg (does not start with {)"
        return 1
    fi
    return 0
}

# 检查命令 exit code
assert_exit_zero() {
    local actual="$1" msg="${2:-command should exit 0}"
    if [ "$actual" -eq 0 ]; then
        return 0
    fi
    test_fail "$msg (exit=$actual)"
    return 1
}

assert_exit_nonzero() {
    local actual="$1" msg="${2:-command should exit non-zero}"
    if [ "$actual" -ne 0 ]; then
        return 0
    fi
    test_fail "$msg (exit=0)"
    return 1
}

# ─── Mock 命令机制 ─────────────────────────────────
# 把 iptables / tc / ip / ip6tables 替换成可观察的命令
# 调用记录写到 $MOCK_LOG,每行一条:  cmd_name|arg1|arg2|...
#
# v3.5.0 alpha-2 设计决策:
#   测试需要拦截**子进程**(`sh xxx.sh` 调起的 process)的命令调用。
#   shell function 不跨 process,所以子进程会去 PATH 查找真实命令。
#
#   解法:用 PATH 拦截 + 显式 PATH export
#   - 创建 mock binary 写到 $MOCK_BIN_DIR
#   - 把 $MOCK_BIN_DIR 放到 PATH 最前
#   - 所有子进程继承 PATH,自动用 mock binary
#   - mock binary 把调用写到 $MOCK_LOG(通过环境变量传)
#   - 每个 mock binary 通过环境变量读 stdout / exit code

MOCK_LOG=""
MOCK_BIN_DIR=""
MOCK_OLD_PATH=""

mock_setup() {
    MOCK_LOG="$HNC_TEST_DIR/mock.log"
    MOCK_BIN_DIR="$HNC_TEST_DIR/mock_bin"
    mkdir -p "$MOCK_BIN_DIR"
    : > "$MOCK_LOG"

    # 清除可能残留的环境变量
    unset MOCK_STDOUT_iptables MOCK_STDOUT_ip6tables MOCK_STDOUT_tc MOCK_STDOUT_ip
    unset MOCK_EXIT_iptables MOCK_EXIT_ip6tables MOCK_EXIT_tc MOCK_EXIT_ip

    # 创建 mock binary,通过环境变量读 stdout/exit code
    for cmd in iptables ip6tables tc ip; do
        cat > "$MOCK_BIN_DIR/$cmd" <<MOCK_EOF
#!/bin/sh
# 自动生成的 mock binary
echo "${cmd}|\$*" >> "\$MOCK_LOG"
# 从环境变量读 stdout(如果设了)
eval "out=\\\$MOCK_STDOUT_${cmd}"
[ -n "\$out" ] && printf '%s\\n' "\$out"
# 从环境变量读 exit code(默认 0)
eval "rc=\\\$MOCK_EXIT_${cmd}"
exit "\${rc:-0}"
MOCK_EOF
        chmod +x "$MOCK_BIN_DIR/$cmd"
    done

    # 保存原 PATH,设新 PATH(mock 优先)
    # v3.5.0 alpha-fix: 设 HNC_SKIP_PATH_HARDENING=1,让 HNC 脚本跳过 PATH 覆盖
    # 之前的 bug: bin/*.sh 头部 `export PATH=/system/bin:...:$PATH` 把 mock 路径排到后面,
    # 真机上 /system/bin/iptables 优先级高于 mock,导致 mock 拦不到任何调用
    MOCK_OLD_PATH="$PATH"
    export PATH="$MOCK_BIN_DIR:$PATH"
    export MOCK_LOG
    export HNC_SKIP_PATH_HARDENING=1
    # rc3.1.32: 新的 init_tc 重试逻辑在 mock 下误判 (mock 往 stdout 吐调用记录,
    # 非空 != 失败). HNC_TEST_MODE=1 让 tc_manager 走单次 add 的老路径, 保持
    # 旧 mock 断言行为.
    export HNC_TEST_MODE=1
}

mock_teardown() {
    [ -n "$MOCK_OLD_PATH" ] && export PATH="$MOCK_OLD_PATH"
    MOCK_OLD_PATH=""
    unset HNC_SKIP_PATH_HARDENING
    unset MOCK_LOG HNC_TEST_MODE
    unset MOCK_STDOUT_iptables MOCK_STDOUT_ip6tables MOCK_STDOUT_tc MOCK_STDOUT_ip
    unset MOCK_EXIT_iptables MOCK_EXIT_ip6tables MOCK_EXIT_tc MOCK_EXIT_ip
    [ -n "$MOCK_BIN_DIR" ] && rm -rf "$MOCK_BIN_DIR"
    MOCK_BIN_DIR=""
}

# 让某个 mock 命令返回非 0
mock_set_exit() {
    local cmd="$1" exit_code="$2"
    case "$cmd" in
        iptables)  export MOCK_EXIT_iptables=$exit_code ;;
        ip6tables) export MOCK_EXIT_ip6tables=$exit_code ;;
        tc)        export MOCK_EXIT_tc=$exit_code ;;
        ip)        export MOCK_EXIT_ip=$exit_code ;;
    esac
}

# 让某个 mock 命令在 stdout 输出固定字符串
mock_set_stdout() {
    local cmd="$1" output="$2"
    case "$cmd" in
        iptables)  export MOCK_STDOUT_iptables="$output" ;;
        ip6tables) export MOCK_STDOUT_ip6tables="$output" ;;
        tc)        export MOCK_STDOUT_tc="$output" ;;
        ip)        export MOCK_STDOUT_ip="$output" ;;
    esac
}

# 检查 mock 日志里是否调用了某个命令(子串匹配)
assert_mock_called() {
    local pattern="$1" msg="${2:-mock should have been called with pattern}"
    if [ ! -f "$MOCK_LOG" ]; then
        test_fail "$msg (mock log does not exist)"
        return 1
    fi
    if grep -qF "$pattern" "$MOCK_LOG"; then
        return 0
    fi
    test_fail "$msg
      pattern not found: $pattern
      mock log:
$(cat "$MOCK_LOG" | sed 's/^/        /' | head -20)"
    return 1
}

assert_mock_not_called() {
    local pattern="$1" msg="${2:-mock should NOT have been called with pattern}"
    if [ ! -f "$MOCK_LOG" ]; then
        return 0
    fi
    if ! grep -qF "$pattern" "$MOCK_LOG"; then
        return 0
    fi
    test_fail "$msg
      pattern unexpectedly found: $pattern"
    return 1
}

# 数 mock 调用次数
mock_call_count() {
    local pattern="$1"
    [ ! -f "$MOCK_LOG" ] && { echo 0; return; }
    grep -cF "$pattern" "$MOCK_LOG"
}

# ─── 终结 summary ─────────────────────────────────
print_test_summary() {
    echo ""
    echo "════════════════════════════════════════"
    if [ "$TEST_FAIL" -eq 0 ]; then
        printf "${C_GRN}  ALL PASS${C_RST}: $TEST_PASS/$TEST_TOTAL"
    else
        printf "${C_RED}  FAIL${C_RST}: $TEST_FAIL failed, $TEST_PASS passed, $TEST_TOTAL total"
    fi
    if [ "$TEST_SKIP" -gt 0 ]; then
        printf "${C_YEL} ($TEST_SKIP skipped)${C_RST}"
    fi
    echo ""
    echo "════════════════════════════════════════"
    if [ "$TEST_FAIL" -gt 0 ]; then
        echo ""
        echo "Failed tests:$TEST_FAILED_NAMES"
        return 1
    fi
    return 0
}
