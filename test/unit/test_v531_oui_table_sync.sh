#!/system/bin/sh
# test/unit/test_v531_oui_table_sync.sh — v5.31 T2: 厂商表只留一份数据源。
# tools/extract_oui.py 从 daemon/hotspotd/hnc_helpers.c 的 HNC_OUI_TABLE
# 抽出 src/dpid/devname/oui_table.txt(Go 用 go:embed 读); 这里重新抽一遍
# 与库内文件逐字节比对 —— 以后改任一边不同步就失败
# (仿 test_v530_junk_table_sync.sh)。
#
# 注意: 备份必须在 test_start 之后创建 —— test_start 的 setup_test_env 会
# 先 rm -rf 整个 HNC_TEST_DIR, 备份放里面且建在之前的话会在 cmp 前被删掉。

_ot_root="$HNC_REPO_ROOT"

test_start "v5.31 OUI 厂商表: 重新抽取与库内数据文件逐字节一致"
_ot_save="$HNC_TEST_DIR/oui_backup.txt"
cp "$_ot_root/src/dpid/devname/oui_table.txt" "$_ot_save" 2>/dev/null
python3 "$_ot_root/tools/extract_oui.py" >/dev/null 2>&1
_ot_rc=$?
if [ "$_ot_rc" != "0" ]; then
    test_fail "extract_oui.py 跑不动(rc=$_ot_rc)"
elif cmp -s "$_ot_save" "$_ot_root/src/dpid/devname/oui_table.txt"; then
    test_pass
else
    test_fail "数据文件与 C 表不同步, 已重新生成(需要提交)"
fi

test_start "v5.31 OUI 厂商表: 条数合理(≥ 400)且 OUI 无重复"
_ot_n=$(wc -l < "$_ot_root/src/dpid/devname/oui_table.txt" 2>/dev/null)
_ot_dup=$(cut -f1 "$_ot_root/src/dpid/devname/oui_table.txt" 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_ot_n" -ge 400 ] && [ "$_ot_dup" = "0" ]; then
    test_pass
else
    test_fail "条数 $_ot_n / 重复 $_ot_dup"
fi
