#!/system/bin/sh
# bin/log_rotate.sh — Patch 1.6 · 通用日志轮转
#
# 目的:
#   防止 HNC 的日志文件(watchdog.log/httpd.log/service.log 等)长期追加
#   吃光 /data 空间。当文件 > SIZE_LIMIT 时,做三代轮转:
#     foo.log.2 → (删除)
#     foo.log.1 → foo.log.2
#     foo.log   → foo.log.1  (新 foo.log 会被下一条写入自动创建)
#
# 用法:
#   sh log_rotate.sh <file>                 # 默认 1 MB 阈值
#   sh log_rotate.sh <file> <size_bytes>    # 自定义阈值
#   sh log_rotate.sh check                  # 一次性轮转 HNC logs/ 下所有 *.log
#
# 设计:
#   - 不追加不读内容,只 mv,开销极小
#   - 轮转时原子性: 先 mv .1→.2,再 mv .log→.1,如果中间 crash 最多丢
#     一小段但不会导致双份(mv 是原子的)
#   - 不尝试通知正在写 log 的进程(进程用 append 模式,mv 后下次 write
#     自动创建新文件;已经打开的 fd 会写到"已改名"的旧文件里,但下次 append
#     open 会走新文件,小量丢失可接受)
#   - 0 返回表示成功(轮转过 or 没达阈值);非 0 表示异常

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
DEFAULT_SIZE_LIMIT=1048576   # 1 MB

# get_size <file>  → bytes (文件不存在返 0)
get_size() {
    local f=$1
    [ -f "$f" ] || { echo 0; return; }
    # stat -c 在 Android/Linux 都支持;BSD/macOS 不支持但不是目标平台
    local sz
    sz=$(stat -c %s "$f" 2>/dev/null)
    if [ -z "$sz" ]; then
        # fallback: wc -c
        sz=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
    fi
    echo "${sz:-0}"
}

# rotate_one <file> <size_limit>
rotate_one() {
    local f=$1
    local limit=${2:-$DEFAULT_SIZE_LIMIT}
    local sz
    sz=$(get_size "$f")

    # 未达阈值 → 什么都不做
    [ "$sz" -lt "$limit" ] 2>/dev/null && return 0

    # 达到阈值 → 三代轮转
    # 先删最老的 .2,再把 .1 → .2,最后 .log → .1
    rm -f "$f.2" 2>/dev/null
    [ -f "$f.1" ] && mv "$f.1" "$f.2" 2>/dev/null
    mv "$f" "$f.1" 2>/dev/null

    # 创建空的新日志(保持权限/属性)
    touch "$f" 2>/dev/null
    chmod 644 "$f" 2>/dev/null

    return 0
}

# rotate_all_logs  — 扫 $HNC_DIR/logs/ 下所有 *.log
rotate_all_logs() {
    local dir="$HNC_DIR/logs"
    [ -d "$dir" ] || return 0
    for f in "$dir"/*.log; do
        [ -f "$f" ] || continue
        rotate_one "$f" "$DEFAULT_SIZE_LIMIT"
    done
}

# ─── main ─────────────────────────────────────────────────

case "$1" in
    check)
        rotate_all_logs
        ;;
    "")
        echo "Usage:"
        echo "  log_rotate.sh <file> [size_bytes]"
        echo "  log_rotate.sh check                  # rotate all logs/*.log"
        exit 1
        ;;
    *)
        # rotate 单个文件
        if [ ! -f "$1" ] && [ ! -e "$1" ]; then
            # 文件不存在也 OK,静默退出(调用者不用先判断)
            exit 0
        fi
        rotate_one "$1" "${2:-$DEFAULT_SIZE_LIMIT}"
        ;;
esac
