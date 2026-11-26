#!/system/bin/sh
# test/unit/test_v530_frontend.sh — v5.30 前端逻辑(在线时长分钟显示 / 垃圾主机名兜底)。
# 用 test/js/extract_fns.js 从 webroot/js/core.js 抽出真实函数在 node 里跑。
# run_all.sh 把 PATH 收窄到系统目录, node 常装在 /opt/node*/bin、/usr/local/bin → 一并找。

_V530_STANDALONE=0
if ! command -v test_start >/dev/null 2>&1; then
    _V530_STANDALONE=1
    HNC_REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
    export HNC_REPO_ROOT
    . "$HNC_REPO_ROOT/test/lib.sh"
fi

_v530_node=$(command -v node 2>/dev/null)
if [ -z "$_v530_node" ]; then
    for _c in ${PREFIX:+"$PREFIX/bin/node"} /opt/node*/bin/node /usr/local/bin/node; do
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
_v530_case junk_name "垃圾主机名表(null / localhost / 纯数字 …)"
_v530_case dev_name "设备名兜底链跳过垃圾名, 手动命名不过滤"
_v530_case disc_shared "新发现的应用: 共享基础设施显示为「公共服务」"
_v530_case app_qos_of "设备「按应用分优先级」开关回读"
_v530_case glass_tint_vars "玻璃浓度 0–100 → --gx-up / --gx-dn"
_v530_case glass_tint_apply "玻璃浓度写 / 删 <html> 上的变量, 标准档全删"
_v530_case glass_tint_label "玻璃浓度档位名"
_v530_case glass_tint_pick "玻璃浓度档位点选: setGlassTint 立即生效、持久化与边界钳制"
_v530_case wp_blur_dim_step "壁纸景深与遮罩步进: syncWpNumericVars / setWpBlur / setWpDim"
_v530_case webroot_zero_range "前端零拖动滑条: webroot 零 <input type=range> 与零旧滑条类名"
_v530_case liquid_tint_css "液态玻璃填充按浓度插值, 标准档 = 旧版数值"
_v530_case nav_solid "液态玻璃顶栏: 内容滚到下面时变统一实底"
_v530_case lg_variants "液态玻璃三版本辅助函数: normLgVariant / lgVariantLabel 归一化与文案"

test_start "v5.30 前端: webroot 包含 pure / prism / dew 三版本样式选择器"
_lg_miss=""
for _lg_v in pure prism dew; do
    if ! grep -q "data-lg-variant=\"$_lg_v\"" "$HNC_REPO_ROOT/webroot/index.html" "$HNC_REPO_ROOT/webroot/css/liquid.css" 2>/dev/null; then
        _lg_miss="${_lg_miss:+$_lg_miss, }data-lg-variant=\"$_lg_v\""
    fi
done
if [ -z "$_lg_miss" ]; then
    test_pass
else
    test_fail "webroot/index.html 与 webroot/css/liquid.css 均缺少: $_lg_miss"
fi

test_start "v5.30 前端: webroot/js/settings.js 包含 data-lg-variant-pick 版本切换控件"
if grep -q 'data-lg-variant-pick' "$HNC_REPO_ROOT/webroot/js/settings.js" 2>/dev/null; then
    test_pass
else
    test_fail "webroot/js/settings.js 未找到 data-lg-variant-pick"
fi

test_start "v5.30 前端: tools/ui_mock/build.js 支持 --variant=prism 与 --variant=dew 独立预览构建"
if [ -z "$_v530_node" ]; then
    test_skip "node not found"
else
    _lg_build_out=$(
        _lg_base=""
        for _d in "${TMPDIR:-}" /data/local/tmp /tmp "${HOME:-}"; do
            [ -n "$_d" ] && [ -d "$_d" ] && [ -w "$_d" ] && { _lg_base="$_d"; break; }
        done
        [ -z "$_lg_base" ] && _lg_base="."
        _lg_tmp=$(mktemp -d "$_lg_base/.tmp_lg_XXXXXX" 2>/dev/null)
        if [ -z "$_lg_tmp" ] || [ ! -d "$_lg_tmp" ]; then
            _lg_tmp="$_lg_base/.tmp_lg_$$"
            mkdir -p "$_lg_tmp" || { echo "mkdir tmp failed"; exit 1; }
        fi
        trap 'rm -rf "$_lg_tmp"' EXIT INT TERM
        _b1=$("$_v530_node" "$HNC_REPO_ROOT/tools/ui_mock/build.js" --variant=prism "$_lg_tmp/prism.html" 2>&1) || { echo "build prism failed: $_b1"; exit 1; }
        grep -q 'data-lg-variant="prism"' "$_lg_tmp/prism.html" || { echo "prism.html 缺少 data-lg-variant=\"prism\""; exit 1; }
        grep -q 'window.__HNC_PREVIEW_VARIANT__="prism"' "$_lg_tmp/prism.html" || { echo "prism.html 缺少 __HNC_PREVIEW_VARIANT__"; exit 1; }
        grep -q 'Hyalite' "$_lg_tmp/prism.html" || { echo "prism.html 缺少 Hyalite"; exit 1; }
        if grep -q '<script src="hyalite.js"></script>' "$_lg_tmp/prism.html"; then
            echo "prism.html 仍残留未内联的 hyalite.js"
            exit 1
        fi
        _b2=$("$_v530_node" "$HNC_REPO_ROOT/tools/ui_mock/build.js" "$_lg_tmp/dew.html" --variant=dew 2>&1) || { echo "build dew failed: $_b2"; exit 1; }
        grep -q 'data-lg-variant="dew"' "$_lg_tmp/dew.html" || { echo "dew.html 缺少 data-lg-variant=\"dew\""; exit 1; }
        grep -q 'window.__HNC_PREVIEW_VARIANT__="dew"' "$_lg_tmp/dew.html" || { echo "dew.html 缺少 __HNC_PREVIEW_VARIANT__"; exit 1; }
        rm -rf "$_lg_tmp"
    )
    if [ $? -eq 0 ]; then
        test_pass
    else
        test_fail "$_lg_build_out"
    fi
fi

if [ "$_V530_STANDALONE" = "1" ]; then
    teardown_test_env
    echo "summary: total=$TEST_TOTAL pass=$TEST_PASS fail=$TEST_FAIL"
    [ "$TEST_FAIL" -eq 0 ] || exit 1
    exit 0
fi
