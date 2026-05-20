#!/system/bin/sh
# bin/hnc_common.sh — HNC 公共 shell 函数库 (since v5.3.0-rc30.12.35)
#
# 用法: 在脚本顶部加:
#   . /data/local/hnc/bin/hnc_common.sh
#   hnc_log_init "/data/local/hnc/logs/myscript.log" "MYSCRIPT"
#   hnc_log "started"
#
# 兼容: Android /system/bin/sh (mksh) + BusyBox sh. 不依赖 bash, 不用 [[ ]] / array.
#
# rc30.12.35 (TASK-d Stage 2): 本文件只是 Stage 2 落地, 现有 22 个脚本不动.
# Stage 3 (v5.3.1+) 才逐个迁移现有脚本到本库.

# ─── 路径常量 ─────────────────────────────────────────────
# shellcheck disable=SC2034  # 这些变量给 source 本库的脚本用, 不在本文件用
HNC_DIR="${HNC_DIR:-/data/local/hnc}"
# shellcheck disable=SC2034
HNC_BIN="$HNC_DIR/bin"
# shellcheck disable=SC2034
HNC_ETC="$HNC_DIR/etc"
# shellcheck disable=SC2034
HNC_RUN="$HNC_DIR/run"
# shellcheck disable=SC2034
HNC_LOGS="$HNC_DIR/logs"
# shellcheck disable=SC2034
HNC_DATA="$HNC_DIR/data"

# ─── 日志 ────────────────────────────────────────────────
# 内部状态 (调用 hnc_log_init 后设置)
_HNC_LOG_PATH=""
_HNC_LOG_TAG=""
_HNC_LOG_ROTATE_BYTES=262144  # 256 KB

# hnc_log_init <log_path> [tag]
# 初始化 log 路径 + tag 前缀, 自动 mkdir + rotate >256KB.
hnc_log_init() {
    _HNC_LOG_PATH="$1"
    _HNC_LOG_TAG="${2:-}"
    mkdir -p "$(dirname "$_HNC_LOG_PATH")" 2>/dev/null

    # rotate 大文件 (>256 KB)
    if [ -f "$_HNC_LOG_PATH" ]; then
        sz=$(stat -c %s "$_HNC_LOG_PATH" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$_HNC_LOG_ROTATE_BYTES" ]; then
            mv "$_HNC_LOG_PATH" "${_HNC_LOG_PATH}.1" 2>/dev/null
        fi
    fi
}

# hnc_log <msg...>
# 标准 log. 没调过 hnc_log_init 走 stdout (兼容 capability_probe 这种探针).
hnc_log() {
    if [ -z "$_HNC_LOG_PATH" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]${_HNC_LOG_TAG:+ [$_HNC_LOG_TAG]} $*"
        return
    fi
    if [ -n "$_HNC_LOG_TAG" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$_HNC_LOG_TAG] $*" >> "$_HNC_LOG_PATH" 2>/dev/null || true
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$_HNC_LOG_PATH" 2>/dev/null || true
    fi
}

# hnc_log_error <msg...>
# 同 hnc_log 但加 [ERROR] 标 + 写 stderr (供 supervisor / watchdog 解析).
hnc_log_error() {
    if [ -n "$_HNC_LOG_TAG" ]; then
        line="[$(date '+%Y-%m-%d %H:%M:%S')] [$_HNC_LOG_TAG] [ERROR] $*"
    else
        line="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*"
    fi
    # 同时写日志文件 (如果初始化过) 和 stderr
    if [ -n "$_HNC_LOG_PATH" ]; then
        echo "$line" >> "$_HNC_LOG_PATH" 2>/dev/null || true
    fi
    echo "$line" >&2
}

# ─── shell quote ─────────────────────────────────────────
# hnc_sq <str>
# 用于安全拼接 sh -c "$(...)" 之类的命令字符串. 把单引号转义.
# mksh 兼容 (不用 bash 的 ${var@Q}).
hnc_sq() {
    # 替换 ' → '\''
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# ─── JSON 顶层 key 读取 ─────────────────────────────────
# hnc_json_get_top <file> <key>
# 局限: 只读顶层 key 的字符串值, 不支持嵌套/数组/数字. 嵌套用 jq (如果有).
hnc_json_get_top() {
    file="$1"; key="$2"
    [ -r "$file" ] || return 1
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" 2>/dev/null | head -1
}

# ─── 锁文件 (简单 singleton) ──────────────────────────────
# hnc_lock_acquire <lockfile>
#   返回 0 = 拿到锁, 1 = 已有活跃进程持锁
# hnc_lock_release <lockfile>
#   释放锁 (删 lockfile)
#
# 注: 简单锁, 不防止 race condition 边界. 适合 cron-like 防重入.
# 不适合短窗口下两个进程同时启动的互斥. 需要强语义用 mkdir 原子锁或 flock.
hnc_lock_acquire() {
    lockfile="$1"
    if [ -f "$lockfile" ]; then
        old_pid=$(cat "$lockfile" 2>/dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            return 1
        fi
    fi
    echo $$ > "$lockfile"
    return 0
}

hnc_lock_release() {
    rm -f "$1" 2>/dev/null
}

# ─── 数字校验 (常见于规则参数校验) ──────────────────────
# hnc_is_uint <s>  → 0 if s 是非负整数, else 1
hnc_is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# hnc_is_uint_gt0 <s>  → 0 if s 是正整数 (>0), else 1
hnc_is_uint_gt0() {
    hnc_is_uint "$1" || return 1
    [ "$1" -gt 0 ]
}
