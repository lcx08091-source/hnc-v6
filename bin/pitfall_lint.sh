#!/system/bin/sh
# pitfall_lint.sh — v5.28 A4: 老坑自动检查(把几次真机事故变成 lint 规则)
#
# 五条规则(每条都有 test/unit/test_pitfall_lint.sh 里的触发用例):
#   P1 时区: src/dpid/cmd/*/main.go 与 daemon/hnc_httpd/main.go 里用到
#      time.Now(或按日期分文件, 如 "20060102")的 main 包必须出现
#      tzlocal.Location()。否则日志/按天文件落在 UTC, 排障时时间全错。
#   P2 toybox grep: bin/*.sh、service.sh 里不许出现 BRE 的 \| (Android
#      toybox grep 不支持 \| alternation, 静静不匹配)。要 alternation 用
#      grep -E 'a|b'。
#   P3 进程检测: Go 代码(非测试)里不许新增 exec.Command("pidof"/"ps");
#      shell 里不许新增 `ps -ef | grep`(ps|awk 的兜底路径是 A3 保留的,
#      判活一律走 /proc, 见 bin/hnc_proc.sh)。
#   P4 告警写入: alert.Append(src/dpid/alert)之外不许直接写
#      alerts.jsonl(绕过锁与滚动截断)。
#   P5 Tab: json_escape 的 sed `s/<Tab>/ /g` 必须是字面 Tab 字符。
#      `\t` 转义是 GNU 扩展, 严格 POSIX sed 不认; 被编辑器展开成空格更糟。
#
# 存量白名单: bin/pitfall_lint.allow, 一行一个 `文件:规则:原因`(路径相对
# 仓库根)。白名单只放行基线已有的命中, 新增违规照样失败。
#
# 用法: sh bin/pitfall_lint.sh [仓库根目录](默认 = 脚本所在目录的上一级)
# 退出码: 0 = 无新增违规; 1 = 有(逐行列出); 2 = 环境/用法错误

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
if [ ! -d "$ROOT" ] || [ ! -f "$ROOT/service.sh" ]; then
    echo "pitfall_lint: 仓库根目录不对: $ROOT" >&2
    exit 2
fi
ALLOW="$ROOT/bin/pitfall_lint.allow"

# 工作文件(不碰仓库内容; Android 无 /tmp 时退回 /data/local/tmp)
TMPD="$(mktemp -d 2>/dev/null)" || {
    TMPD="${TMPDIR:-/data/local/tmp}/pitfall_lint.$$"
    mkdir -p "$TMPD" 2>/dev/null || { echo "pitfall_lint: no temp dir" >&2; exit 2; }
}
VF="$TMPD/violations"
: > "$VF"

viol() { # viol <相对路径> <规则> <原因>
    printf '%s:%s:%s\n' "$1" "$2" "$3" >> "$VF"
}

rel() {
    case "$1" in
        "$ROOT"/*) printf '%s\n' "${1#"$ROOT"/}" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

TAB="$(printf '\t')"

# ── P1 时区 ───────────────────────────────────────────────────────────
for f in "$ROOT"/src/dpid/cmd/*/main.go "$ROOT/daemon/hnc_httpd/main.go"; do
    [ -f "$f" ] || continue
    case "$f" in */bin/pitfall_lint.sh) continue ;; esac
    if grep -q 'time\.Now' "$f" || grep -q '20060102' "$f"; then
        grep -q 'tzlocal\.Location' "$f" || \
            viol "$(rel "$f")" P1 "main 包用 time.Now/按日期分文件, 却没有 tzlocal.Location()"
    fi
done

# ── P2 toybox grep 的 BRE \| ──────────────────────────────────────────
for f in "$ROOT"/bin/*.sh "$ROOT/service.sh"; do
    [ -f "$f" ] || continue
    case "$f" in */bin/pitfall_lint.sh) continue ;; esac # lint 自身的规则文本会命中
    if grep -q '\\|' "$f"; then
        viol "$(rel "$f")" P2 "含 BRE \\| (toybox grep 不支持, 用 grep -E 'a|b')"
    fi
done

# ── P3 进程检测: Go(非测试)不许 exec.Command("ps"/"pidof") ────────────
find "$ROOT/src" "$ROOT/daemon" -name '*.go' ! -name '*_test.go' -type f 2>/dev/null |
while IFS= read -r f; do
    if grep -q 'Command("ps"' "$f" || grep -q 'Command("pidof"' "$f"; then
        viol "$(rel "$f")" P3 "Go 里直接 exec ps/pidof(判活权威 = procfind / /proc)"
    fi
done

# ── P3 进程检测: shell 不许 `ps -ef | grep` ───────────────────────────
for f in "$ROOT"/bin/*.sh "$ROOT/service.sh"; do
    [ -f "$f" ] || continue
    case "$f" in */bin/pitfall_lint.sh) continue ;; esac
    if grep -q 'ps -ef[^|]*| *grep' "$f"; then
        viol "$(rel "$f")" P3 "shell 里 ps -ef | grep(判活走 /proc, 兜底用 ps|awk)"
    fi
done

# ── P4 告警写入: alert.Append 之外不许直接写 alerts.jsonl ─────────────
find "$ROOT/src" "$ROOT/daemon" -name '*.go' ! -name '*_test.go' -type f 2>/dev/null |
while IFS= read -r f; do
    case "$f" in
        */src/dpid/alert/*) continue ;; # alert.Append 的家
    esac
    grep -n 'alerts\.jsonl' "$f" 2>/dev/null |
    while IFS= read -r line; do
        case "$line" in
            *OpenFile*|*WriteFile*|*os.Create*|*O_APPEND*)
                viol "$(rel "$f")" P4 "直接写 alerts.jsonl(必须走 alert.Append)"
                ;;
        esac
    done
done

# ── P5 Tab(只查 sed 形式的 json_escape; awk gsub(/\t/) 是真 Tab 语义)──
for f in "$ROOT"/bin/*.sh; do
    [ -f "$f" ] || continue
    case "$f" in */bin/pitfall_lint.sh) continue ;; esac
    grep -q 'json_escape' "$f" || continue
    if sed -n '/json_escape()/,/^}/p' "$f" | grep -q 'sed'; then
        if ! sed -n '/json_escape()/,/^}/p' "$f" | grep -q "s/$TAB/ /g"; then
            viol "$(rel "$f")" P5 "json_escape 的 sed s/<Tab>/ /g 不是字面 Tab(\\t 转义或被展开)"
        fi
    fi
done

# ── 对照白名单, 只报新增(字面匹配, 路径里的 . 不会误当通配)────────────
NEWF="$TMPD/new"
: > "$NEWF"
while IFS= read -r v; do
    [ -n "$v" ] || continue
    path=${v%%:*}
    rest=${v#*:}
    rule=${rest%%:*}
    if [ -f "$ALLOW" ] && awk -F: -v k="$path:$rule" \
        'index($0, k ":") == 1 { f = 1; exit } END { exit !f }' "$ALLOW" 2>/dev/null; then
        continue
    fi
    printf '%s\n' "$v" >> "$NEWF"
done < "$VF"

if [ -s "$NEWF" ]; then
    echo "pitfall_lint: 发现新增违规(规则说明见 bin/pitfall_lint.sh 文件头):"
    cat "$NEWF"
    echo ""
    echo "存量豁免要写进 bin/pitfall_lint.allow(一行一个 文件:规则:原因)。"
    rm -rf "$TMPD"
    exit 1
fi
rm -rf "$TMPD"
exit 0
