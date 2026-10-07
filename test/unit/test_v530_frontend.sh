#!/system/bin/sh
# test/unit/test_v530_frontend.sh — v5.30 前端逻辑(在线时长分钟显示 / 垃圾主机名兜底)。
# 用 test/js/extract_fns.js 从 webroot/js/core.js 抽出真实函数在 node 里跑。
# run_all.sh 把 PATH 收窄到系统目录, node 常装在 /opt/node*/bin、/usr/local/bin → 一并找。

_v530_node=$(command -v node 2>/dev/null)
if [ -z "$_v530_node" ]; then
    for _c in /opt/node*/bin/node /usr/local/bin/node; do
        [ -x "$_c" ] && { _v530_node="$_c"; break; }
    done
fi

_v530_case() {
    test_start "v5.30 前端: $2"
    if [ -z "$_v530_node" ]; then
        test_skip "node not found"
        return 0
    fi
    _out=$("$_v530_node" "$HNC_REPO_ROOT/test/js/v530_frontend.js" "$HNC_REPO_ROOT" "$1" 2>&1)
    if [ $? -eq 0 ]; then
        test_pass
    else
        test_fail "$_out"
    fi
}

_v530_case online_text "在线时长 < 60 显示分钟, ≥ 60 显示小时, 0 不显示"
_v530_case online_min_map "online_min 优先, 旧后端 hours×60 兜底"
_v530_case online_paint "设备卡片写入「今日在线 N 分钟」"
