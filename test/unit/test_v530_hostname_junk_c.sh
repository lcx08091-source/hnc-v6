#!/system/bin/sh
# test/unit/test_v530_hostname_junk_c.sh — v5.30 T1b: hotspotd C 侧垃圾主机名过滤。
# 用本机 cc 把 daemon/hotspotd/test/test_hostname_junk.c 与被测源文件编在一起跑
# (只是 host 编译验证逻辑; 真机二进制仍由 CI 用 NDK 交叉编译)。没有 cc → SKIP。

_v530c_cc=""
for _c in cc gcc clang; do
    command -v "$_c" >/dev/null 2>&1 && { _v530c_cc="$_c"; break; }
done

test_start "v5.30 hotspotd: 垃圾主机名(null 等)当作没有名字"
if [ -z "$_v530c_cc" ]; then
    test_skip "no host C compiler"
else
    _v530c_dir="$HNC_TEST_DIR/cbuild"
    mkdir -p "$_v530c_dir"
    _hd="$HNC_REPO_ROOT/daemon/hotspotd"
    if ! _v530c_err=$("$_v530c_cc" -std=gnu11 -Wall -D_GNU_SOURCE -I"$_hd" -o "$_v530c_dir/t" \
            "$_hd/test/test_hostname_junk.c" "$_hd/hnc_helpers.c" "$_hd/oui_override.c" "$_hd/hostname_cache.c" 2>&1); then
        test_fail "compile failed: $_v530c_err"
    else
        _v530c_out=$("$_v530c_dir/t" "$_v530c_dir" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass
        else
            test_fail "$(printf '%s\n' "$_v530c_out" | grep '✗')"
        fi
    fi
fi
