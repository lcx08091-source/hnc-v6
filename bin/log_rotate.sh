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
#   hnc_launcher.c、看门狗的 spawnDaemon),它们永远不会重新 open。
#   mv 只改目录项不动 inode → 轮转后 daemon 的 fd 继续往 foo.log.1 里写
#   (真机实测 dpid 的 fd 1/2 双双指向 dpid.log.1),而 WebUI 日志页读的是那个
#   空的新 foo.log;再轮两次,`rm -f $f.2` 会 unlink 掉仍被持有的 inode →
#   日志彻底消失、磁盘空间也不释放(inode 到进程退出才回收)。
#   copytruncate 后 inode 不变,所有写者都是 O_APPEND,truncate 之后内核会把
#   写位置带回文件头,不会留稀疏洞。一处修好全部长驻 daemon。
#   代价:cp 与 truncate 之间新写入的几行会丢 —— 日志场景可接受。

HNC_DIR=${HNC_DIR:-/data/local/hnc}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

DEFAULT_SIZE_LIMIT=1048576          # 1 MB
EXPORTS_MAX_FILES=${HNC_EXPORTS_MAX_FILES:-10}
EXPORTS_MAX_BYTES=${HNC_EXPORTS_MAX_BYTES:-134217728}  # 128 MB

# 防 mksh 32 位有符号整数(>2.14GB)溢出的十进制无符号小于比较
uint_lt() {
    _ul_a="${1:-0}"; _ul_b="${2:-0}"
    case "$_ul_a" in ''|*[!0-9]*) _ul_a=0 ;; esac
    case "$_ul_b" in ''|*[!0-9]*) _ul_b=0 ;; esac
    while [ "${_ul_a#0}" != "$_ul_a" ]; do _ul_a=${_ul_a#0}; done; [ -n "$_ul_a" ] || _ul_a=0
    while [ "${_ul_b#0}" != "$_ul_b" ]; do _ul_b=${_ul_b#0}; done; [ -n "$_ul_b" ] || _ul_b=0
    [ "${#_ul_a}" -lt "${#_ul_b}" ] && return 0
    [ "${#_ul_a}" -gt "${#_ul_b}" ] && return 1
    awk 'BEGIN { exit !(ARGV[1] < ARGV[2]) }' "$_ul_a" "$_ul_b"
}

# get_size <file>  → bytes (文件不存在返 0)
get_size() {
    local f=$1
    [ -f "$f" ] || { echo 0; return; }
    local sz
    sz=$(stat -c %s "$f" 2>/dev/null | tr -dc '0-9')
    if [ -z "$sz" ]; then
        sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9')
    fi
    echo "${sz:-0}"
}

# rotate_one <file> <size_limit>
rotate_one() {
    local f=$1
    local limit=${2:-$DEFAULT_SIZE_LIMIT}
    local sz
    sz=$(get_size "$f")

    # 未达阈值 → 什么都不做(使用无符号比较防止 >2.14GB 溢出为负数漏转)
    uint_lt "$sz" "$limit" && return 0

    rm -f "$f.2" 2>/dev/null
    [ -f "$f.1" ] && mv "$f.1" "$f.2" 2>/dev/null

    # v5.9.3 BUG-014: .log → .1 用 copytruncate, cp 失败绝不截断原文件
    if cp "$f" "$f.1" 2>/dev/null; then
        chmod 644 "$f.1" 2>/dev/null
        : > "$f" 2>/dev/null
    else
        return 1
    fi

    chmod 644 "$f" 2>/dev/null
    return 0
}

# prune_exports_dir — 清理 exports/ 超配额旧文件(保留最近 10 个且总大小 <= 128MB, 跳过 .staging)
prune_exports_dir() {
    local exp_dir="${HNC_EXPORTS_DIR:-$HNC_DIR/exports}"
    [ -d "$exp_dir" ] || return 0
    local _fn _sz
    ls -1t "$exp_dir" 2>/dev/null | while IFS= read -r _fn; do
        case "$_fn" in ''|.*) continue ;; esac
        [ -f "$exp_dir/$_fn" ] || continue
        _sz=$(get_size "$exp_dir/$_fn")
        printf '%s\t%s\n' "$_sz" "$_fn"
    done | awk -F '\t' -v max_n="$EXPORTS_MAX_FILES" -v max_b="$EXPORTS_MAX_BYTES" '
        BEGIN { max_n += 0; max_b += 0; kept = 0; over = 0 }
        NF >= 2 {
            idx++
            sz = $1 + 0
            if (over || idx > max_n || (kept + sz) > max_b) {
                over = 1
                print $2
            } else {
                kept += sz
            }
        }
    ' | while IFS= read -r _del; do
        [ -n "$_del" ] && rm -f "$exp_dir/$_del" 2>/dev/null || true
    done
    return 0
}

# rotate_all_logs — 扫 $HNC_DIR/logs/*.log + 轮转 run/m4_go_write.log + 清理 exports/
rotate_all_logs() {
    local dir="$HNC_DIR/logs"
    if [ -d "$dir" ]; then
        for f in "$dir"/*.log; do
            [ -f "$f" ] || continue
            rotate_one "$f" "$DEFAULT_SIZE_LIMIT"
        done
    fi
    if [ -f "$HNC_DIR/run/m4_go_write.log" ]; then
        rotate_one "$HNC_DIR/run/m4_go_write.log" "${HNC_M4_LOG_MAX_BYTES:-$DEFAULT_SIZE_LIMIT}" || true
    fi
    prune_exports_dir
    return 0
}

# ─── main ─────────────────────────────────────────────────

case "$1" in
    check)
        rotate_all_logs
        ;;
    "")
        echo "Usage:"
        echo "  log_rotate.sh <file> [size_bytes]"
        echo "  log_rotate.sh check                  # rotate all logs/*.log + m4_go_write.log + prune exports/"
        exit 1
        ;;
    *)
        if [ ! -f "$1" ] && [ ! -e "$1" ]; then
            exit 0
        fi
        rotate_one "$1" "${2:-$DEFAULT_SIZE_LIMIT}"
        ;;
esac
