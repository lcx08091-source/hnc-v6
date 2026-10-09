#!/system/bin/sh
# test/unit/test_v531_no_discovery_c.sh — v5.31 T3/T4: hotspotd --no-discovery
# 的 host 编译单测(daemon/hotspotd/test/test_no_discovery.c; STATUS 数设备、
# 默认发现模式)。仿 test_v530_hostname_junk_c.sh: 本机 cc 编, 没有 cc → SKIP。

_v531c_cc=""
for _c in cc gcc clang; do
    command -v "$_c" >/dev/null 2>&1 && { _v531c_cc="$_c"; break; }
done

test_start "v5.31 hotspotd --no-discovery: STATUS 数 devices.json 设备数(改动前无此函数, 编译失败)"
if [ -z "$_v531c_cc" ]; then
    test_skip "no host C compiler"
else
    _v531c_dir="$HNC_TEST_DIR/cbuild531"
    mkdir -p "$_v531c_dir"
    _hd="$HNC_REPO_ROOT/daemon/hotspotd"
    if ! _v531c_err=$("$_v531c_cc" -std=gnu11 -Wall -D_GNU_SOURCE -I"$_hd" -o "$_v531c_dir/t" \
            "$_hd/test/test_no_discovery.c" "$_hd/hnc_helpers.c" "$_hd/oui_override.c" \
            "$_hd/hostname_cache.c" 2>&1); then
        test_fail "compile failed: $_v531c_err"
    else
        _v531c_out=$(TMPDIR="$_v531c_dir" "$_v531c_dir/t" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass
        else
            test_fail "$(printf '%s\n' "$_v531c_out" | grep 'FAIL')"
        fi
    fi
fi
