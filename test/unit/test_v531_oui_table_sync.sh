#!/system/bin/sh
# test/unit/test_v531_oui_table_sync.sh — v5.31 T2: 厂商表只留一份数据源。
# v5.31 起 Go 用 src/dpid/devname/oui_table.txt(go:embed), 当时从 C 版
# hnc_helpers.c 的 HNC_OUI_TABLE 抽出并逐字节比对; v5.33 C 版设备发现删除后
# 这个文件就是唯一数据源, 这里只查格式: 每行「6 位十六进制 OUI<Tab>厂商」,
# 条数合理, OUI 不重复, 按 OUI 有序(Go 二分查找的前提)。

_ot_file="$HNC_REPO_ROOT/src/dpid/devname/oui_table.txt"

test_start "v5.31 OUI 厂商表: 只剩 Go 一份(C 表与抽取脚本已删)"
if grep -q 'HNC_OUI_TABLE' "$HNC_REPO_ROOT/daemon/hotspotd/hnc_helpers.c" 2>/dev/null \
   || [ -e "$HNC_REPO_ROOT/tools/extract_oui.py" ]; then
    test_fail "C 表或 tools/extract_oui.py 还在"
else
    test_pass
fi

test_start "v5.31 OUI 厂商表: 格式对、条数合理(≥ 400)、OUI 无重复且有序"
_ot_n=$(wc -l < "$_ot_file" 2>/dev/null)
_ot_bad=$(grep -cvE "$(printf '^[0-9A-F]{6}\t[^\t]+$')" "$_ot_file" 2>/dev/null)
_ot_dup=$(cut -f1 "$_ot_file" 2>/dev/null | sort | uniq -d | wc -l)
_ot_unsorted=$(cut -f1 "$_ot_file" 2>/dev/null | LC_ALL=C sort -c 2>&1 | wc -l)
if [ "$_ot_n" -ge 400 ] && [ "$_ot_bad" = "0" ] && [ "$_ot_dup" = "0" ] && [ "$_ot_unsorted" = "0" ]; then
    test_pass
else
    test_fail "条数 $_ot_n / 格式不对 $_ot_bad 行 / 重复 $_ot_dup / 无序 $_ot_unsorted"
fi
