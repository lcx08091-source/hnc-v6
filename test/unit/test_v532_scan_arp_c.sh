#!/system/bin/sh
# test/unit/test_v532_scan_arp_c.sh — v5.32 T2: hotspotd 全量重扫选最近确认的 IP
# (nl_parse_dump_msgs / scan_apply_candidate 纯逻辑, 21 项断言)。照
# test_v531_no_discovery_c.sh: 本机 cc 编(hotspotd.c 由测试文件 #include,
# 不出现在命令行), 没有 cc → SKIP。

_v532c_cc=""
for _c in cc gcc clang; do
    command -v "$_c" >/dev/null 2>&1 && { _v532c_cc="$_c"; break; }
done

test_start "v5.32 hotspotd scan_arp: 同 MAC 多条候选挑最近确认, 已知设备 IP 只进不退(基线无此函数, 编译失败)"
if [ -z "$_v532c_cc" ]; then
    test_skip "no host C compiler"
else
    _v532c_dir="$HNC_TEST_DIR/cbuild532"
    mkdir -p "$_v532c_dir"
    _hd="$HNC_REPO_ROOT/daemon/hotspotd"
    if ! _v532c_err=$("$_v532c_cc" -std=gnu11 -Wall -D_GNU_SOURCE -I"$_hd" -o "$_v532c_dir/t" \
            "$_hd/test/test_scan_arp_ip_select.c" "$_hd/hnc_helpers.c" "$_hd/oui_override.c" \
            "$_hd/hostname_cache.c" 2>&1); then
        test_fail "compile failed: $_v532c_err"
    else
        _v532c_out=$(TMPDIR="$_v532c_dir" "$_v532c_dir/t" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass
        else
            test_fail "$(printf '%s\n' "$_v532c_out" | grep 'FAIL')"
        fi
    fi
fi
