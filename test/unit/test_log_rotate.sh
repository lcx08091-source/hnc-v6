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

# ═══ v5.9.3 BUG-014 · copytruncate 语义 ═══════════════════════════
#
# 老实现用 `mv "$f" "$f.1"` 轮转,假设"进程用 append 模式,mv 后下次 append
# open 会走新文件"。这个假设只对每行重开文件的 shell 成立;长驻 daemon
# (hnc_dpid / hnc_httpd / hotspotd / watchdog / launcher)的 stdout/stderr 是
# spawn 那一刻一次性打开的 O_APPEND fd,永远不会重新 open。mv 只改目录项不动
# inode → 轮转后它们的 fd 继续往 foo.log.1 里写(真机实测 dpid 的 fd 1/2 双双
# 指向 dpid.log.1),再轮两次 `rm -f $f.2` 就把仍被持有的 inode unlink 掉:
# 日志彻底消失,磁盘空间也要等进程退出才回收。
#
# 下面三条锁死修复后的语义:inode 不变 + 已打开的 fd 继续写进新 .log +
# cp 失败绝不截断。

test_start "BUG-014: rotate keeps the SAME inode for .log (copytruncate)"
init_logs
make_size "$HNC_TEST_DIR/logs/foo.log" 2097152
ino_before=$(stat -c %i "$HNC_TEST_DIR/logs/foo.log" 2>/dev/null)
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
ino_after=$(stat -c %i "$HNC_TEST_DIR/logs/foo.log" 2>/dev/null)
# inode 号相同 = 没有 rename、没有重建 → daemon 手里的 fd 仍然指着它
assert_ne "" "$ino_before" "应能读到轮转前的 inode 号" && \
    assert_eq "$ino_before" "$ino_after" "轮转后 .log 必须是同一个 inode" && \
    test_pass

test_start "BUG-014: an already-open append fd keeps writing to the new .log"
init_logs
printf 'before-rotate\n' > "$HNC_TEST_DIR/logs/foo.log"
make_size "$HNC_TEST_DIR/logs/padding" 1048576
cat "$HNC_TEST_DIR/logs/padding" >> "$HNC_TEST_DIR/logs/foo.log"
rm -f "$HNC_TEST_DIR/logs/padding"
# 模拟长驻 daemon:开一个 O_APPEND fd 并**全程不关**,跨越轮转继续写
exec 9>> "$HNC_TEST_DIR/logs/foo.log"
lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
echo "after-rotate-from-held-fd" >&9
exec 9>&-
# 修复前:这行会落进 foo.log.1(旧 inode);修复后必须落进 foo.log
grep -q "after-rotate-from-held-fd" "$HNC_TEST_DIR/logs/foo.log"
assert_eq "0" "$?" "轮转后持有的 fd 必须继续写进新 .log(而不是 .log.1)" && \
    assert_file_exists "$HNC_TEST_DIR/logs/foo.log.1" ".1 仍保存了轮转前的内容" && \
    test_pass

test_start "BUG-014: cp failure must NOT truncate the original log"
init_logs
printf 'must-survive\n' > "$HNC_TEST_DIR/logs/foo.log"
make_size "$HNC_TEST_DIR/logs/padding" 1048576
cat "$HNC_TEST_DIR/logs/padding" >> "$HNC_TEST_DIR/logs/foo.log"
rm -f "$HNC_TEST_DIR/logs/padding"
# 模拟磁盘满 / 只读挂载:用 PATH 前置一个必然失败的 cp。
# (不能靠 chmod 让 cp 失败 —— 测试可能以 root 跑,root 无视权限位)
if [ -x /system/bin/sh ]; then _sb='#!/system/bin/sh'; else _sb='#!/bin/sh'; fi
mkdir -p "$HNC_TEST_DIR/failbin"
{ echo "$_sb"; echo 'exit 1'; } > "$HNC_TEST_DIR/failbin/cp"
chmod 755 "$HNC_TEST_DIR/failbin/cp"
PATH="$HNC_TEST_DIR/failbin:$PATH" lr_one "$HNC_TEST_DIR/logs/foo.log" 1048576
rc=$?
# 关键不变量:cp 失败时原文件必须原样留着,绝不能从"没轮转"升级成"被清空"
sz_after=$(wc -c < "$HNC_TEST_DIR/logs/foo.log" | tr -d ' ')
grep -q "must-survive" "$HNC_TEST_DIR/logs/foo.log" && hit=0 || hit=1
rm -rf "$HNC_TEST_DIR/failbin"
assert_eq "0" "$hit" "cp 失败时原日志内容必须完好(cp 与 truncate 必须 && 串联)" && \
    assert_ne "0" "$sz_after" "cp 失败时原日志不得被截断成 0 字节" && \
    assert_ne "0" "$rc" "cp 失败应返回非 0,让调用方能看出异常" && \
    test_pass
