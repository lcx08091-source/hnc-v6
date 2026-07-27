#!/system/bin/sh
# bin/log_rotate.sh — Patch 1.6 · 通用日志轮转
#
# 目的:
#   防止 HNC 的日志文件(watchdog.log/httpd.log/service.log 等)长期追加
#   吃光 /data 空间。当文件 > SIZE_LIMIT 时,做三代轮转:
#     foo.log.2 → (删除)
#     foo.log.1 → foo.log.2
#     foo.log   → 拷贝成 foo.log.1,然后原地截断 foo.log(inode 不变)
#
# 用法:
#   sh log_rotate.sh <file>                 # 默认 1 MB 阈值
#   sh log_rotate.sh <file> <size_bytes>    # 自定义阈值
#   sh log_rotate.sh check                  # 一次性轮转 HNC logs/ 下所有 *.log
#
# 设计(v5.9.3 BUG-014 起改为 copytruncate 语义):
#   - .1 → .2 仍用 mv(.1/.2 只由本脚本 cp 出来,没有任何进程持有它们)
#   - .log → .1 改成 "cp 出副本 + 就地截断原文件",**不换 inode**
#   - 0 返回表示成功(轮转过 or 没达阈值);非 0 表示异常
#
# 为什么不能再用 mv(v5.9.3 BUG-014 真机根因):
#   老实现的假设是"进程用 append 模式,mv 后下次 append open 会走新文件"。
#   这个假设只对"每写一行重开一次文件"的 shell 成立,对长驻 daemon 全不成立 ——
#   hnc_dpid / hnc_httpd / hotspotd / watchdog / launcher 的 stdout/stderr 都是
#   spawn 那一刻一次性打开的 O_APPEND fd(见 service.sh 的 `>> log 2>&1`、
#   hnc_dpid_guard.sh、hnc_launcher.c、dpid_supervisor),它们永远不会重新 open。
#   mv 只改目录项不动 inode → 轮转后 daemon 的 fd 继续往 foo.log.1 里写
#   (真机实测 dpid 的 fd 1/2 双双指向 dpid.log.1),而 WebUI 日志页读的是那个
#   空的新 foo.log;再轮两次,`rm -f $f.2` 会 unlink 掉仍被持有的 inode →
#   日志彻底消失、磁盘空间也不释放(inode 到进程退出才回收)。
#   copytruncate 后 inode 不变,所有写者都是 O_APPEND,truncate 之后内核会把
#   写位置带回文件头,不会留稀疏洞。一处修好全部长驻 daemon。
#   代价:cp 与 truncate 之间新写入的几行会丢 —— 日志场景可接受。

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

    # 达到阈值 → 三代轮转(保留份数与阈值判定同旧版,只把最后一步换成 copytruncate)
    # 先删最老的 .2,再把 .1 → .2(.1/.2 无人持有,mv 安全且省一次拷贝)
    rm -f "$f.2" 2>/dev/null
    [ -f "$f.1" ] && mv "$f.1" "$f.2" 2>/dev/null

    # v5.9.3 BUG-014:.log → .1 用 copytruncate。
    # cp 与 truncate **必须** && 串联:cp 失败(磁盘满 / 只读 / 被删)时绝不能
    # 截断原文件,否则就从"日志没轮转"升级成"日志被清空"。
    if cp "$f" "$f.1" 2>/dev/null; then
        chmod 644 "$f.1" 2>/dev/null
        # `: > "$f"` 是 O_TRUNC 打开已存在的 inode,不 unlink 不重建,
        # 长驻 daemon 手里的 fd 依旧指向同一个 inode,继续写进新的 foo.log。
        : > "$f" 2>/dev/null
    else
        # cp 失败:原文件原样留着,下一轮再试。返回非 0 让调用方能看出异常。
        return 1
    fi

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
