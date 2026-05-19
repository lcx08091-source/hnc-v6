#!/system/bin/sh
# test/run_all.sh — HNC v3.5 测试主入口
#
# 用法:
#   sh test/run_all.sh                    # 跑所有单元测试
#   sh test/run_all.sh unit               # 同上
#   sh test/run_all.sh unit/test_json     # 跑单个测试文件
#   sh test/run_all.sh -v                 # verbose(打印每个 mock 调用)
#
# 退出码:
#   0 = all pass
#   1 = some failed
#   2 = test framework error

# 强制干净 PATH(防止 user app 干扰)
export PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin

# 仓库根目录(test/ 的父目录)
HNC_REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export HNC_REPO_ROOT

cd "$HNC_REPO_ROOT" || exit 2

if [ ! -d test/unit ]; then
    echo "ERROR: test/unit directory not found at $HNC_REPO_ROOT/test/unit"
    exit 2
fi

# Source the framework lib
. "$HNC_REPO_ROOT/test/lib.sh"

# 解析参数
FILTER=""
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        unit) FILTER="unit" ;;
        unit/*) FILTER="$arg" ;;
        *) FILTER="$arg" ;;
    esac
done

[ -z "$FILTER" ] && FILTER="unit"

echo "════════════════════════════════════════"
echo "  HNC v3.5 测试套件"
echo "  仓库: $HNC_REPO_ROOT"
echo "  过滤: $FILTER"
echo "════════════════════════════════════════"
echo ""

# 找匹配的测试文件
TEST_FILES=""
if [ -f "$HNC_REPO_ROOT/test/$FILTER.sh" ]; then
    TEST_FILES="$HNC_REPO_ROOT/test/$FILTER.sh"
elif [ -d "$HNC_REPO_ROOT/test/$FILTER" ]; then
    TEST_FILES=$(find "$HNC_REPO_ROOT/test/$FILTER" -name "test_*.sh" -type f | sort)
else
    echo "ERROR: filter '$FILTER' matches no files"
    exit 2
fi

# 跑每个测试文件
for test_file in $TEST_FILES; do
    rel_path=${test_file#$HNC_REPO_ROOT/}
    echo "── $rel_path ──"
    # 在 subshell 里跑,避免测试文件污染主 shell
    # 但 TEST_PASS / TEST_FAIL 等计数需要持久化 → 用临时文件传递
    # v3.5.0 alpha-fix: Android /tmp 不存在,用 /data/local/tmp
    if [ -d /data/local/tmp ]; then
        counter_file="/data/local/tmp/hnc_test_counters_$$"
    else
        counter_file="/tmp/hnc_test_counters_$$"
    fi
    (
        . "$HNC_REPO_ROOT/test/lib.sh"
        # rc30.12.14: 给测试一个可靠的当前测试文件路径.
        # 老逻辑下测试用 "$(dirname $0)/../.." 推 ROOT, 但 source 上下文 $0 是 runner,
        # 导致推出 /tmp/.. 这种错误根. 现在 export HNC_TEST_FILE 让测试优先用它.
        export HNC_TEST_FILE="$test_file"
        . "$test_file"
        # 写出计数到临时文件
        echo "$TEST_TOTAL $TEST_PASS $TEST_FAIL $TEST_SKIP" > "$counter_file"
        echo "$TEST_FAILED_NAMES" >> "$counter_file"
    )
    if [ -f "$counter_file" ]; then
        read -r ftotal fpass ffail fskip < "$counter_file"
        TEST_TOTAL=$((TEST_TOTAL + ftotal))
        TEST_PASS=$((TEST_PASS + fpass))
        TEST_FAIL=$((TEST_FAIL + ffail))
        TEST_SKIP=$((TEST_SKIP + fskip))
        # 失败名字(从第二行起)
        failed=$(tail -n +2 "$counter_file")
        if [ -n "$failed" ]; then
            TEST_FAILED_NAMES="$TEST_FAILED_NAMES$failed"
        fi
        rm -f "$counter_file"
    fi
done

print_test_summary
