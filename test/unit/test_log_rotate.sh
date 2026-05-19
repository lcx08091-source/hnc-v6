#!/system/bin/sh
# test/unit/test_log_rotate.sh — Patch 1.6 log_rotate.sh 单元测试

LR="$HNC_REPO_ROOT/bin/log_rotate.sh"

# ─── helpers ────────────────────────────────────────────────────

# 造一个指定大小的文件(bytes,通过 dd)
# 用 bs=1024 一次写 1KB 块,比 bs=1 快百倍;bytes < 1024 时补 1 块
make_size() {
    local path=$1
    local bytes=$2
    local blocks=$((bytes / 1024))
    [ "$blocks" -lt 1 ] && blocks=1
    dd if=/dev/zero of="$path" bs=1024 count=$blocks 2>/dev/null
}

# 调 log_rotate 单文件模式
lr_one() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_TEST_MODE=1 \
        sh "$LR" "$@"
}

# 调 log_rotate check 模式
lr_check() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_TEST_MODE=1 \
        sh "$LR" check
}

# 初始化 logs 目录
init_logs() {
    rm -rf "$HNC_TEST_DIR/logs"
    mkdir -p "$HNC_TEST_DIR/logs"
}

# ═══ 单文件模式 ═════════════════════════════════════════════════

test_start "single: under threshold → no rotate"
init_logs
make_size "$HNC_TEST_DIR/logs/foo.log" 1024   # 1 KB
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576   # 1 MB 阈值
assert_file_exists "$HNC_TEST_DIR/logs/foo.log" "原文件保留"
assert_file_not_exists "$HNC_TEST_DIR/logs/foo.log.1" "未生成 .1"
test_pass

test_start "single: over threshold → rotate .log → .1"
init_logs
make_size "$HNC_TEST_DIR/logs/foo.log" 2097152   # 2 MB
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576      # 1 MB 阈值
assert_file_exists "$HNC_TEST_DIR/logs/foo.log.1" ".1 已生成"
# 原 .log 被 rename, 新的空 .log 应该存在
assert_file_exists "$HNC_TEST_DIR/logs/foo.log" "新空 .log"
sz=$(wc -c < "$HNC_TEST_DIR/logs/foo.log" | tr -d ' ')
assert_eq "0" "$sz" "新 .log 是空的"
test_pass

test_start "single: 3-generation overwrite (.2 dropped)"
init_logs
# 造 3 代大文件触发连续轮转
make_size "$HNC_TEST_DIR/logs/foo.log" 2097152
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
# 现在有 .log(空) + .1(2MB)
make_size "$HNC_TEST_DIR/logs/foo.log" 2097152
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
# 现在有 .log(空) + .1(2MB) + .2(2MB, 最早那个)
make_size "$HNC_TEST_DIR/logs/foo.log" 2097152
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
# 第 3 次: .2 被覆盖, .1→.2, log→.1
assert_file_exists "$HNC_TEST_DIR/logs/foo.log" "新 .log"
assert_file_exists "$HNC_TEST_DIR/logs/foo.log.1" ".1 存在"
assert_file_exists "$HNC_TEST_DIR/logs/foo.log.2" ".2 存在"
assert_file_not_exists "$HNC_TEST_DIR/logs/foo.log.3" "没有 .3(只留三代)"
test_pass

test_start "single: nonexistent file → no error"
init_logs
lr_one "$HNC_TEST_DIR/logs/does_not_exist.log" 1024
rc=$?
assert_eq "0" "$rc" "不存在的文件应静默成功"
test_pass

test_start "single: custom threshold respected"
init_logs
make_size "$HNC_TEST_DIR/logs/foo.log" 100
# 50 bytes 阈值 → 应该 rotate
lr_one "$HNC_TEST_DIR/logs/foo.log" 50
assert_file_exists "$HNC_TEST_DIR/logs/foo.log.1" "小阈值下触发 rotate"
test_pass

# ═══ check 模式(批量) ══════════════════════════════════════════

test_start "check: rotates all >1MB logs in logs/"
init_logs
make_size "$HNC_TEST_DIR/logs/a.log" 2097152
make_size "$HNC_TEST_DIR/logs/b.log" 2097152
make_size "$HNC_TEST_DIR/logs/c.log" 1024      # 不达阈值
lr_check
assert_file_exists "$HNC_TEST_DIR/logs/a.log.1" "a 被轮转"
assert_file_exists "$HNC_TEST_DIR/logs/b.log.1" "b 被轮转"
assert_file_not_exists "$HNC_TEST_DIR/logs/c.log.1" "c 未触发"
test_pass

test_start "check: empty logs dir → no error"
init_logs
lr_check
rc=$?
assert_eq "0" "$rc" "空目录应 ok"
test_pass

test_start "check: missing logs dir → no error"
rm -rf "$HNC_TEST_DIR/logs"
lr_check
rc=$?
assert_eq "0" "$rc" "没有 logs 目录也应 ok"
test_pass

# ═══ 原子性(rename 不会撕开) ══════════════════════════════════

test_start "atomicity: rotated file keeps original content"
init_logs
# 写个有内容的 log
printf 'line 1\nline 2\nline 3\n' > "$HNC_TEST_DIR/logs/foo.log"
# 补到超过阈值(在内容后追加 bytes)
make_size "$HNC_TEST_DIR/logs/padding" 1048576
cat "$HNC_TEST_DIR/logs/padding" >> "$HNC_TEST_DIR/logs/foo.log"
rm "$HNC_TEST_DIR/logs/padding"

lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576

# 验证 .1 里仍然有原始前三行
head -3 "$HNC_TEST_DIR/logs/foo.log.1" | grep -q "line 1"
assert_eq "0" "$?" "原文件内容保留在 .1 中"
test_pass
