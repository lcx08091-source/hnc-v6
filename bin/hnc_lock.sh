#!/system/bin/sh
# hnc_lock.sh — HNC v3.9.2 Patch 0 锁管理库
#
# 提供两种锁原语,用门禁(gate)模式协调:
#   - mac_lock / mac_unlock    per-MAC 独占锁(允许不同 MAC 并发)
#   - gate_lock / gate_unlock  全局独占锁(等所有 per-MAC 释放)
#
# 协议:
#   per-MAC 写操作流程:
#     1. 等 gate/ 不存在
#     2. mkdir mac/$MAC/
#     3. 二次检查 gate/ 不存在(关闭 1→2 之间的 race window)
#     4. 执行
#     5. rmdir mac/$MAC/
#
#   gate 操作流程:
#     1. mkdir gate/
#     2. 等所有 mac/*/ 释放(5 秒超时)
#     3. 执行
#     4. rmdir gate/
#
# 失败策略:
#   - 5 秒超时 → 返回 11(调用方可选择重试或放弃)
#   - gate 超时等 per-MAC 时保守让步(rmdir gate 并返回 11,不强拆 per-MAC)
#   - stale 锁(PID 已死)在 20 轮检查后自动回收
#
# 用法(在其他 shell 脚本里 source):
#   . "$HNC_DIR/bin/hnc_lock.sh"
#   mac_lock "$mac" || exit 11
#   ... do work ...
#   mac_unlock "$mac"
#
# 也支持独立运行,供单测调用:
#   sh hnc_lock.sh mac_lock aa:bb:cc:dd:ee:01
#   sh hnc_lock.sh gate_lock

# PATH 健壮性(保持和项目其他 shell 一致)
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
LOCK_ROOT="$HNC_DIR/run/lock"
MAC_LOCK_DIR="$LOCK_ROOT/mac"
GATE_LOCK="$LOCK_ROOT/gate"

# 超时常数(和 json_set.sh 一致, 50 轮 × 100ms = 5 秒)
_LOCK_TIMEOUT_ROUNDS=50
_LOCK_STALE_CHECK_ROUND=20  # 第 20 轮开始检查 stale

mkdir -p "$MAC_LOCK_DIR" 2>/dev/null

# ═══ 内部工具 ═══════════════════════════════════════════════════

# 短睡眠(100ms),兼容多种环境
# Android toybox / busybox 通常有 usleep 微秒
# Debian/Alpine CI 容器 sleep 支持小数
# 老 POSIX 严格 shell 只支持整秒 sleep
# 按精度优先级依次尝试: usleep(us) > sleep 0.1 > sleep 1
_short_sleep() {
    usleep 100000 2>/dev/null && return 0
    sleep 0.1 2>/dev/null && return 0
    sleep 1
}

# 测试 hook 点。生产模式 HNC_LOCK_HOOK 未设置 → 立即返回(零开销分支)
# 测试模式下主测试 touch $HNC_LOCK_HOOK.<label> 让 worker 卡住,
# 然后 rm 该文件放行。worker 进入 hook 时 touch .ack 文件
# 通知主测试"我已到达并被挂起",消除主测试的时序假设。
_hook() {
    [ -z "$HNC_LOCK_HOOK" ] && return 0
    local hook_file="$HNC_LOCK_HOOK.$1"
    local ack_file="${hook_file}.ack"
    if [ -e "$hook_file" ]; then
        touch "$ack_file"  # Ack: 告诉主测试 worker 已就位
        local waited=0
        while [ -e "$hook_file" ] && [ $waited -lt 500 ]; do
            usleep 10000 2>/dev/null || sleep 1
            waited=$((waited+1))
        done
    fi
}

# MAC 地址规范化 + 严格白名单
# 拒绝 ../ / 空 / 带 shell metachar / 长度不对的输入
# 防止通过目录名攻击创建任意锁目录
# 成功输出小写 MAC 到 stdout,失败 stderr 报错并 rc=1
_mac_sanitize() {
    local raw=$1
    [ -z "$raw" ] && { echo "mac_sanitize: empty" >&2; return 1; }
    local m=$(echo "$raw" | tr 'A-Z' 'a-z' 2>/dev/null)
    case "$m" in
        [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])
            echo "$m"
            return 0 ;;
        *)
            echo "mac_sanitize: invalid mac '$raw'" >&2
            return 1 ;;
    esac
}

# 检查 stale 锁(锁目录存在但持有者 PID 已死)
# 返回 0 = 成功回收 stale 锁
# 返回 1 = 锁还活着(PID 存活或 PID 文件刚写未完成),不要拆
#
# rc3.1.34 修 #27/#22: 之前空 PID 文件场景永远 return 1, 如果某进程 mkdir
# lockdir 成功但在 `echo $$ > pid` 之前崩了 (kill -9 / OOM 杀子进程 / 父进程
# trap 异常退出绕过 EXIT trap), pid 文件永远不会出现, 锁永久卡住. 之前其他
# 进程要等到 _LOCK_TIMEOUT_ROUNDS (默认 50 轮 = 5s) 才超时返 11, 但**下次**
# 调用还是同样卡 5s, 模块整体被一个被遗忘的 lockdir 永久拖累.
#
# 修法: 用 lockdir mtime 判断空 PID 持续多久. 正常进程 mkdir → echo 之间是
# μs 级, 5 秒以上仍然空 PID 必然是异常退出. 用 stat -c %Y (busybox / coreutils
# 都支持). Android 普遍 toybox/busybox 都 OK.
_try_reclaim_stale() {
    local lockdir=$1
    local holder
    holder=$(cat "$lockdir/pid" 2>/dev/null)
    if [ -z "$holder" ]; then
        # 空 PID 文件: 检查 lockdir 创建多久了
        local mtime now age
        mtime=$(stat -c %Y "$lockdir" 2>/dev/null) || mtime=0
        now=$(date +%s)
        age=$((now - mtime))
        if [ "$mtime" -gt 0 ] && [ "$age" -gt 5 ]; then
            # mkdir 5 秒后仍未写 pid → 必然是 mkdir 后崩溃, 安全回收
            rm -f "$lockdir/pid" 2>/dev/null
            rmdir "$lockdir" 2>/dev/null
            return 0
        fi
        return 1
    fi
    # PID 还活着: 不拆
    if kill -0 "$holder" 2>/dev/null; then
        return 1
    fi
    # PID 已死: 安全回收
    rm -f "$lockdir/pid" 2>/dev/null
    rmdir "$lockdir" 2>/dev/null
    return 0
}

# ═══ per-MAC 锁 ═════════════════════════════════════════════════

# mac_lock <mac>
# 成功: rc=0,锁已持有
# 失败: rc=1 (mac 非法) 或 rc=11 (超时)
mac_lock() {
    local mac
    mac=$(_mac_sanitize "$1") || return 1

    local lockdir="$MAC_LOCK_DIR/$mac"
    local i=0

    while [ $i -lt $_LOCK_TIMEOUT_ROUNDS ]; do
        # 1. 门禁检查: gate 被占 → 等
        if [ -d "$GATE_LOCK" ]; then
            _short_sleep
            i=$((i+1))
            continue
        fi

        # 2. 尝试抢 per-MAC 锁
        if mkdir "$lockdir" 2>/dev/null; then
            echo "${HNC_LOCK_HOLDER_PID:-$$}" > "$lockdir/pid"

            # 3. 双重检查: 抢锁过程中 gate 刚好出现?
            # 如果是,让步给 gate,释放自己的 mac 锁
            if [ -d "$GATE_LOCK" ]; then
                rm -f "$lockdir/pid"
                rmdir "$lockdir" 2>/dev/null
                _short_sleep
                i=$((i+1))
                continue
            fi

            # 4. 测试 hook(生产无开销)
            _hook "after_mac_acquire"

            return 0
        fi

        # 抢锁失败(别人占着): 第 20 轮起检查 stale
        if [ $i -eq $_LOCK_STALE_CHECK_ROUND ]; then
            _try_reclaim_stale "$lockdir"
        fi

        _short_sleep
        i=$((i+1))
    done

    return 11  # 超时
}

# mac_unlock <mac>
# 非严格: 即使锁不是自己的或已不存在,也返回 0
# 设计考虑: 调用方退出路径多,unlock 报错反而掩盖真正的错误
mac_unlock() {
    local mac
    mac=$(_mac_sanitize "$1") || return 0
    local lockdir="$MAC_LOCK_DIR/$mac"
    rm -f "$lockdir/pid" 2>/dev/null
    rmdir "$lockdir" 2>/dev/null
    return 0
}

# ═══ gate 全局锁 ════════════════════════════════════════════════

# gate_lock
# 成功: rc=0
# 失败: rc=11 (超时)
# 超时分两种:
#   - 抢 gate/ 本身超时(别的全局操作持有)
#   - 抢到 gate/ 但等 mac/*/ 释放超时(有 per-MAC 操作卡住)
# 两种都保守让步: 释放 gate(如果已抢到)再返回 11
gate_lock() {
    local i=0
    local acquired=0  # 明确标记是否真的通过 mkdir 抢到锁

    # 阶段 1: 抢 gate/
    while [ $i -lt $_LOCK_TIMEOUT_ROUNDS ]; do
        if mkdir "$GATE_LOCK" 2>/dev/null; then
            echo "${HNC_LOCK_HOLDER_PID:-$$}" > "$GATE_LOCK/pid"
            acquired=1
            break
        fi

        # stale 检查
        if [ $i -eq $_LOCK_STALE_CHECK_ROUND ]; then
            _try_reclaim_stale "$GATE_LOCK"
        fi

        _short_sleep
        i=$((i+1))
    done

    if [ $acquired -ne 1 ]; then
        return 11  # gate 超时,别的 gate 持有中
    fi

    _hook "after_gate_acquire"

    # 阶段 2: 等所有 per-MAC 释放
    # 注意: 此时已经抢到 gate,新的 mac_lock 会被挡住(步骤 1 检查 gate)
    # 只需要等已经在执行的 per-MAC 自然结束
    local j=0
    while [ $j -lt $_LOCK_TIMEOUT_ROUNDS ]; do
        # ls -A: list 非隐藏文件(包括目录)
        # 2>/dev/null: MAC_LOCK_DIR 不存在时静默
        local active
        active=$(ls -A "$MAC_LOCK_DIR" 2>/dev/null)
        if [ -z "$active" ]; then
            # 全部释放
            _hook "after_gate_all_clear"
            return 0
        fi

        # 对每个卡住的 mac 锁检查 stale(持有者死了就拆)
        # 这样 gate 不被一个崩溃的 per-MAC 持有者无限卡住
        for dir in "$MAC_LOCK_DIR"/*; do
            [ -d "$dir" ] || continue
            _try_reclaim_stale "$dir"
        done

        _short_sleep
        j=$((j+1))
    done

    # 阶段 2 超时: per-MAC 有活进程还在跑,保守让步
    # 不强拆 per-MAC(那会破坏并发安全)
    rm -f "$GATE_LOCK/pid" 2>/dev/null
    rmdir "$GATE_LOCK" 2>/dev/null
    return 11
}

gate_unlock() {
    rm -f "$GATE_LOCK/pid" 2>/dev/null
    rmdir "$GATE_LOCK" 2>/dev/null
    return 0
}

# ═══ 独立运行入口(供单测调用) ══════════════════════════════════
# 当被 source 时 $0 是父脚本的名字,下面的 dispatch 不会触发
# 当 `sh hnc_lock.sh <cmd>` 直接调用时,会走到下面
#
# 独立入口模式的陷阱: `sh hnc_lock.sh lock` 子 shell 退出后,
# $$ 这个 PID 就消失了,下次 stale check 会误判成死进程回收锁。
# 解决: 允许通过 --holder <pid> 指定归属 PID(测试场景使用父 shell $$)。
# 未指定时使用 PPID(父进程),这样 `sh hnc_lock.sh gate_lock` 的锁
# 归属给调用方 shell 而不是短命子 shell。
_script_name=$(basename "$0" 2>/dev/null)
case "$_script_name" in
    hnc_lock.sh|hnc_lock)
        CMD=$1
        shift 2>/dev/null

        # 可选 --holder <pid> 指定归属进程(测试用)
        HOLDER_PID=""
        if [ "$1" = "--holder" ]; then
            HOLDER_PID=$2
            shift 2
        fi
        # 没指定就用父进程 PID,避免短命子 shell 退出后锁孤立
        [ -z "$HOLDER_PID" ] && HOLDER_PID=$PPID

        # 覆盖内部 acquire 函数的 PID 写入
        # 通过环境变量,在锁实现里读取
        export HNC_LOCK_HOLDER_PID="$HOLDER_PID"

        case "$CMD" in
            mac_lock)   mac_lock   "$@"; exit $? ;;
            mac_unlock) mac_unlock "$@"; exit $? ;;
            gate_lock)  gate_lock;       exit $? ;;
            gate_unlock) gate_unlock;    exit $? ;;
            *)
                echo "Usage: $0 {mac_lock|mac_unlock|gate_lock|gate_unlock} [--holder PID] [mac]" >&2
                exit 1 ;;
        esac
        ;;
esac
