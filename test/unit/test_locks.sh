#!/system/bin/sh
# test/unit/test_locks.sh — hnc_lock.sh 并发安全单元测试
#
# 设计原则(防 flaky):
#   1. 用文件系统屏障同步,不靠 sleep 估时序
#   2. 关键点预埋 _hook,worker 通过 .ack 文件确认到位
#   3. 断言最终状态,不断言中间时序
#   4. CI 友好: 不依赖 iptables 内核,不需要 root
#
# Hook 握手流程:
#   主测试:                             worker:
#     touch hook.after_mac_acquire       ... mac_lock ...
#                                        到达 hook,touch hook.after_mac_acquire.ack
#     等 .ack 出现(轮询有上限)         阻塞在 while hook 存在
#     验证其他 worker 的行为
#     rm hook.after_mac_acquire          hook 消失 → 继续执行
#     wait worker 完成
#
# 这个握手保证"主测试开始验证时,worker 确实已经抢到锁并被卡住"
# 消除了 worker 启动快慢的时序不确定性。

LOCK_SH="$HNC_REPO_ROOT/bin/hnc_lock.sh"

# ═══ 辅助函数 ═══════════════════════════════════════════════════

# 初始化 test dir 的锁状态(每个测试都 call)
lock_test_init() {
    rm -rf "$HNC_TEST_DIR/run/lock"
    mkdir -p "$HNC_TEST_DIR/run/lock/mac"
    rm -rf "$HNC_TEST_DIR/worktmp"
    mkdir -p "$HNC_TEST_DIR/worktmp"
}

# 等文件出现(带超时,单位 = 10ms 轮数)
wait_file() {
    local path=$1
    local max=${2:-200}  # 默认 2 秒
    local i=0
    while [ $i -lt $max ]; do
        [ -e "$path" ] && return 0
        _sleep_10ms
        i=$((i+1))
    done
    return 1
}

# 等文件消失
wait_file_gone() {
    local path=$1
    local max=${2:-200}
    local i=0
    while [ $i -lt $max ]; do
        [ ! -e "$path" ] && return 0
        _sleep_10ms
        i=$((i+1))
    done
    return 1
}

# 精细睡眠,跨环境兼容
_sleep_10ms() {
    usleep 10000 2>/dev/null && return 0
    sleep 0.01 2>/dev/null && return 0
    sleep 1
}
_sleep_100ms() {
    usleep 100000 2>/dev/null && return 0
    sleep 0.1 2>/dev/null && return 0
    sleep 1
}
_sleep_300ms() {
    usleep 300000 2>/dev/null && return 0
    sleep 0.3 2>/dev/null && return 0
    sleep 1
}

# 启动一个 mac_lock 后台 worker,用 hook 卡在持锁状态
# 参数: <worker_id> <mac>
# 返回: worker PID 写到 $HNC_TEST_DIR/worktmp/pid.$id
start_hooked_worker() {
    local wid=$1
    local mac=$2
    local wd="$HNC_TEST_DIR/worktmp"
    (
        export HNC_DIR="$HNC_TEST_DIR"
        export HNC_LOCK_HOOK="$wd/hook"
        export HNC_SKIP_PATH_HARDENING=1
        # worker 脚本:抢 mac 锁,成功后通过 hook 卡住
        sh "$LOCK_SH" mac_lock "$mac"
        rc=$?
        echo "$rc" > "$wd/rc.$wid"
        echo "done" > "$wd/done.$wid"
    ) &
    echo $! > "$wd/pid.$wid"
}

# ═══ 基础功能 ═══════════════════════════════════════════════════

test_start "mac_lock: acquire and release"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "aa:bb:cc:dd:ee:01"
rc=$?
has_dir=0
[ -d "$HNC_TEST_DIR/run/lock/mac/aa:bb:cc:dd:ee:01" ] && has_dir=1
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_unlock "aa:bb:cc:dd:ee:01"
gone=0
[ ! -d "$HNC_TEST_DIR/run/lock/mac/aa:bb:cc:dd:ee:01" ] && gone=1
assert_eq "0" "$rc" && \
    assert_eq "1" "$has_dir" "lockdir should exist after lock" && \
    assert_eq "1" "$gone" "lockdir should be gone after unlock" && test_pass

test_start "gate_lock: acquire and release"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_lock
rc=$?
has_dir=0
[ -d "$HNC_TEST_DIR/run/lock/gate" ] && has_dir=1
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock
gone=0
[ ! -d "$HNC_TEST_DIR/run/lock/gate" ] && gone=1
assert_eq "0" "$rc" && \
    assert_eq "1" "$has_dir" && \
    assert_eq "1" "$gone" && test_pass

# ═══ MAC 输入校验 ═══════════════════════════════════════════════

test_start "mac_lock: rejects path traversal"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "../etc" 2>/dev/null
rc=$?
# 检查 MAC_LOCK_DIR 下没有任何 ../etc 名字的目录,没有 run/lock/etc
has_escape=0
[ -d "$HNC_TEST_DIR/run/lock/etc" ] && has_escape=1
[ -d "$HNC_TEST_DIR/run/lock/mac/../etc" ] && has_escape=1
assert_eq "1" "$rc" "should reject" && \
    assert_eq "0" "$has_escape" "no escape dir created" && test_pass

test_start "mac_lock: rejects empty string"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "" 2>/dev/null
assert_eq "1" "$?" && test_pass

test_start "mac_lock: rejects short mac"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "aa:bb" 2>/dev/null
assert_eq "1" "$?" && test_pass

test_start "mac_lock: rejects shell metachar"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "aa:bb:cc:dd:ee:ff; rm -rf /tmp/canary" 2>/dev/null
rc=$?
# canary 不应被创建
[ -e /tmp/canary ] && test_fail "shell injection occurred" && rm -f /tmp/canary
assert_eq "1" "$rc" "should reject" && test_pass

test_start "mac_lock: uppercase normalized to lowercase"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "AA:BB:CC:DD:EE:01"
rc=$?
# 锁目录应该是小写
has_lower=0; has_upper=0
[ -d "$HNC_TEST_DIR/run/lock/mac/aa:bb:cc:dd:ee:01" ] && has_lower=1
[ -d "$HNC_TEST_DIR/run/lock/mac/AA:BB:CC:DD:EE:01" ] && has_upper=1
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_unlock "AA:BB:CC:DD:EE:01"
assert_eq "0" "$rc" && \
    assert_eq "1" "$has_lower" "lockdir should be lowercase" && \
    assert_eq "0" "$has_upper" "no uppercase dir" && test_pass

# ═══ 同 MAC 互斥 ════════════════════════════════════════════════

test_start "mac_lock: same MAC mutual exclusion (hooked)"
lock_test_init
wd="$HNC_TEST_DIR/worktmp"
MAC="aa:bb:cc:dd:ee:01"
touch "$wd/hook.after_mac_acquire"
start_hooked_worker "A" "$MAC"
# 等 A 到位(抢锁成功后卡在 hook)
if ! wait_file "$wd/hook.after_mac_acquire.ack" 200; then
    test_fail "worker A did not reach hook in 2s"
else
    # A 已经持锁,现在主测试尝试抢同 MAC(不该能抢到)
    # 5 秒超时太长,临时改用极短超时:直接探测是否阻塞
    # 方法:启动 worker B(非 hook 模式),观察它是否在 200ms 内能完成
    (
        export HNC_DIR="$HNC_TEST_DIR"
        export HNC_SKIP_PATH_HARDENING=1
        # B 不挂 hook,尝试抢同 MAC 应该超时(5 秒)
        # 但我们只等 300ms,然后认定"仍在阻塞"
        sh "$LOCK_SH" mac_lock "$MAC"
        echo "$?" > "$wd/rc.B"
        echo "done" > "$wd/done.B"
    ) &
    bpid=$!
    # 300ms 后 B 应该还在 mac_lock 里等
    _sleep_300ms
    if [ -e "$wd/done.B" ]; then
        test_fail "B should still be blocked but completed"
    else
        # B 阻塞成功,现在放行 A,B 会自然抢到锁
        rm -f "$wd/hook.after_mac_acquire"
        if wait_file "$wd/done.A" 200 && wait_file "$wd/done.B" 600; then
            # A 和 B 都完成,且 B 的 rc 应该是 0(A 释放后 B 抢到)
            rc_a=$(cat "$wd/rc.A")
            rc_b=$(cat "$wd/rc.B")
            assert_eq "0" "$rc_a" "A rc" && assert_eq "0" "$rc_b" "B rc" && test_pass
        else
            test_fail "timed out waiting for A or B to complete"
        fi
    fi
    wait 2>/dev/null
fi

# ═══ 不同 MAC 可以并发 ═════════════════════════════════════════

test_start "mac_lock: different MACs acquire concurrently"
lock_test_init
wd="$HNC_TEST_DIR/worktmp"
touch "$wd/hook.after_mac_acquire"
start_hooked_worker "A" "aa:bb:cc:dd:ee:01"
start_hooked_worker "B" "aa:bb:cc:dd:ee:02"
# 两个 worker 应该都能抢到自己的锁并到达 hook
# 轮询两个 ack 都出现
got_both=0
i=0
while [ $i -lt 300 ]; do
    ack_count=$(ls "$wd"/hook.after_mac_acquire.ack 2>/dev/null | wc -l)
    # 注意: 两个 worker 用同一个 hook 文件,.ack 只有一个
    # 所以改成看锁目录是否都存在
    a_locked=0; b_locked=0
    [ -d "$HNC_TEST_DIR/run/lock/mac/aa:bb:cc:dd:ee:01" ] && a_locked=1
    [ -d "$HNC_TEST_DIR/run/lock/mac/aa:bb:cc:dd:ee:02" ] && b_locked=1
    if [ $a_locked = 1 ] && [ $b_locked = 1 ]; then
        got_both=1
        break
    fi
    _sleep_10ms
    i=$((i+1))
done
# 放行两个 worker
rm -f "$wd/hook.after_mac_acquire"
wait 2>/dev/null
if [ $got_both = 1 ]; then
    test_pass
else
    test_fail "two different MACs should lock concurrently, but didn't both appear in 3s"
fi

# ═══ gate 阻塞 per-MAC ═════════════════════════════════════════

test_start "gate_lock: blocks subsequent mac_lock"
lock_test_init
wd="$HNC_TEST_DIR/worktmp"
# 先抢 gate
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_lock
if [ $? -ne 0 ]; then
    test_fail "initial gate_lock failed"
else
    # 启动一个 worker 尝试抢 per-MAC 锁,应该被 gate 挡住
    (
        export HNC_DIR="$HNC_TEST_DIR"
        export HNC_SKIP_PATH_HARDENING=1
        sh "$LOCK_SH" mac_lock "aa:bb:cc:dd:ee:01"
        echo "$?" > "$wd/rc.M"
        echo "done" > "$wd/done.M"
    ) &
    # 300ms 后 M 应该还在等(gate 阻塞)
    _sleep_300ms
    if [ -e "$wd/done.M" ]; then
        test_fail "mac_lock should be blocked by gate but completed"
        HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock
    else
        # 放 gate,M 应该马上抢到
        HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock
        if wait_file "$wd/done.M" 300; then
            rc_m=$(cat "$wd/rc.M")
            assert_eq "0" "$rc_m" && test_pass
        else
            test_fail "M did not complete after gate release"
        fi
    fi
    wait 2>/dev/null
fi

# ═══ per-MAC 期间 gate 等待 ═════════════════════════════════════

test_start "gate_lock: waits for existing mac_lock to release"
lock_test_init
wd="$HNC_TEST_DIR/worktmp"
touch "$wd/hook.after_mac_acquire"
start_hooked_worker "M" "aa:bb:cc:dd:ee:01"
# 等 M 到位
if ! wait_file "$wd/hook.after_mac_acquire.ack" 200; then
    test_fail "M did not reach hook"
else
    # 启动 gate worker
    (
        export HNC_DIR="$HNC_TEST_DIR"
        export HNC_SKIP_PATH_HARDENING=1
        sh "$LOCK_SH" gate_lock
        echo "$?" > "$wd/rc.G"
        echo "done" > "$wd/done.G"
    ) &
    # G 应该抢到 gate 但在阶段 2 等 M 释放,所以 done.G 不应出现
    _sleep_300ms
    if [ -e "$wd/done.G" ]; then
        test_fail "gate should be blocked by mac_lock but completed"
    else
        # 放 M
        rm -f "$wd/hook.after_mac_acquire"
        # 等 M 和 G 都完成
        if wait_file "$wd/done.M" 300 && wait_file "$wd/done.G" 300; then
            rc_m=$(cat "$wd/rc.M"); rc_g=$(cat "$wd/rc.G")
            HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock 2>/dev/null
            assert_eq "0" "$rc_m" "M rc" && assert_eq "0" "$rc_g" "G rc" && test_pass
        else
            test_fail "M or G did not finish"
        fi
    fi
    wait 2>/dev/null
fi

# ═══ stale 锁恢复 ═══════════════════════════════════════════════

test_start "mac_lock: reclaims stale lock from dead PID"
lock_test_init
MAC="aa:bb:cc:dd:ee:01"
# 伪造 stale 锁:mkdir + 写一个不存在的 PID
mkdir -p "$HNC_TEST_DIR/run/lock/mac/$MAC"
# 用一个极大 PID,系统里肯定没这个进程
echo "9999999" > "$HNC_TEST_DIR/run/lock/mac/$MAC/pid"
# 现在尝试抢,应该在 20 轮后检测到 stale 并回收,最终成功
start=$(date +%s)
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "$MAC"
rc=$?
end=$(date +%s)
elapsed=$((end - start))
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_unlock "$MAC"
# 应 <= 5 秒(远低于超时)
# 放宽到 <= 4 秒,20 轮 × 100ms ≈ 2 秒检测 + 一点余量
if [ "$rc" = "0" ] && [ "$elapsed" -le 4 ]; then
    test_pass
else
    test_fail "rc=$rc elapsed=${elapsed}s (expected rc=0, elapsed<=4s)"
fi

test_start "mac_lock: does NOT reclaim if PID still alive"
lock_test_init
MAC="aa:bb:cc:dd:ee:02"
mkdir -p "$HNC_TEST_DIR/run/lock/mac/$MAC"
# 用一个真实活着的 PID(当前 shell 的父)
echo "$$" > "$HNC_TEST_DIR/run/lock/mac/$MAC/pid"
# 尝试抢应该超时(因为 PID 活着不拆)
start=$(date +%s)
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "$MAC" 2>/dev/null
rc=$?
end=$(date +%s)
elapsed=$((end - start))
# 清理(人工 rmdir)
rm -rf "$HNC_TEST_DIR/run/lock/mac/$MAC"
# 期望 rc=11 且耗时 >= 4 秒(接近 5 秒超时)
if [ "$rc" = "11" ] && [ "$elapsed" -ge 4 ]; then
    test_pass
else
    test_fail "rc=$rc elapsed=${elapsed}s (expected rc=11, elapsed>=4s)"
fi

# ═══ 超时 ═══════════════════════════════════════════════════════

test_start "mac_lock: returns 11 on timeout"
lock_test_init
MAC="aa:bb:cc:dd:ee:03"
wd="$HNC_TEST_DIR/worktmp"
# 启动一个 worker 永远持锁(hook 不被放行)
touch "$wd/hook.after_mac_acquire"
start_hooked_worker "H" "$MAC"
if ! wait_file "$wd/hook.after_mac_acquire.ack" 200; then
    test_fail "H did not reach hook"
else
    # 第二次抢同 MAC 应该超时
    start=$(date +%s)
    HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_lock "$MAC" 2>/dev/null
    rc=$?
    end=$(date +%s)
    elapsed=$((end - start))
    # 放行 H 清理
    rm -f "$wd/hook.after_mac_acquire"
    wait 2>/dev/null
    # rc 应 = 11,耗时在 [4, 7] 区间(5 秒 ± 容忍)
    if [ "$rc" = "11" ] && [ "$elapsed" -ge 4 ] && [ "$elapsed" -le 7 ]; then
        test_pass
    else
        test_fail "rc=$rc elapsed=${elapsed}s (expected rc=11, elapsed in [4,7])"
    fi
fi

# ═══ gate 并发:两个 gate 互斥 ══════════════════════════════════

test_start "gate_lock: two concurrent gates serialize"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_lock
rc1=$?
# 第二个 gate 应该超时
start=$(date +%s)
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_lock 2>/dev/null
rc2=$?
end=$(date +%s)
elapsed=$((end - start))
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock
if [ "$rc1" = "0" ] && [ "$rc2" = "11" ] && [ "$elapsed" -ge 4 ]; then
    test_pass
else
    test_fail "rc1=$rc1 rc2=$rc2 elapsed=${elapsed}"
fi

# ═══ unlock 幂等 ════════════════════════════════════════════════

test_start "mac_unlock: idempotent on unheld lock"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" mac_unlock "aa:bb:cc:dd:ee:04" >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "unlock should succeed on non-held lock" && test_pass

test_start "gate_unlock: idempotent on unheld gate"
lock_test_init
HNC_DIR="$HNC_TEST_DIR" sh "$LOCK_SH" gate_unlock >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" && test_pass
