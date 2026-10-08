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
_v530_case junk_name "垃圾主机名表(null / localhost / 纯数字 …)"
_v530_case dev_name "设备名兜底链跳过垃圾名, 手动命名不过滤"
_v530_case disc_shared "新发现的应用: 共享基础设施显示为「公共服务」"
_v530_case app_qos_of "设备「按应用分优先级」开关回读"
_v530_case glass_tint_vars "玻璃浓度 0–100 → --gx-up / --gx-dn"
_v530_case glass_tint_apply "玻璃浓度写 / 删 <html> 上的变量, 标准档全删"
_v530_case glass_tint_label "玻璃浓度档位名"
_v530_case glass_tint_input "玻璃浓度滑块: 拖动实时、松手才存、标准档吸附"
_v530_case liquid_tint_css "液态玻璃填充按浓度插值, 标准档 = 旧版数值"
_v530_case nav_solid "液态玻璃顶栏: 内容滚到下面时变统一实底"
