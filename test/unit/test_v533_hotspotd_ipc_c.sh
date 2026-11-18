#!/system/bin/sh
# test/unit/test_v533_hotspotd_ipc_c.sh — v5.33: hotspotd 只剩硬件加速兜底 + 控制接口
# (C 版设备发现删除, 只留 Go 版)。host 编译跑 daemon/hotspotd/test/test_hotspotd_ipc.c
# (REFRESH / STATUS / GET_DEVICES / 链路事件); 本机没有 cc → SKIP。
# 真机二进制仍由 CI 用 NDK 交叉编译。

_v533c_cc=""
for _c in cc gcc clang; do
    command -v "$_c" >/dev/null 2>&1 && { _v533c_cc="$_c"; break; }
done

test_start "v5.33 hotspotd 控制接口: REFRESH 交给 Go 写者 / STATUS 数 devices.json / 只管链路事件"
if [ -z "$_v533c_cc" ]; then
    test_skip "no host C compiler"
else
    _v533c_dir="$HNC_TEST_DIR/cbuild533"
    mkdir -p "$_v533c_dir"
    _hd="$HNC_REPO_ROOT/daemon/hotspotd"
    if ! _v533c_err=$("$_v533c_cc" -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -I"$_hd" \
            -o "$_v533c_dir/t" "$_hd/test/test_hotspotd_ipc.c" "$_hd/hnc_helpers.c" 2>&1); then
        test_fail "compile failed: $_v533c_err"
    else
        _v533c_out=$(TMPDIR="$_v533c_dir" "$_v533c_dir/t" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass
        else
            test_fail "$(printf '%s\n' "$_v533c_out" | grep 'FAIL')"
        fi
    fi
fi

test_start "v5.33 hotspotd: C 版设备发现代码已删(不订阅邻居事件、不写 devices.json)"
_hd="$HNC_REPO_ROOT/daemon/hotspotd"
if grep -qE 'RTMGRP_NEIGH|scan_arp|write_json|resolve_hostname|/proc/net/arp' "$_hd/hotspotd.c"; then
    test_fail "hotspotd.c 里还有发现代码: $(grep -nE 'RTMGRP_NEIGH|scan_arp|write_json|resolve_hostname|/proc/net/arp' "$_hd/hotspotd.c" | head -3)"
elif ls "$_hd"/hostname_cache.c "$_hd"/oui_override.c "$_hd"/mdns_worker.c >/dev/null 2>&1; then
    test_fail "发现用的 C 源文件还在"
elif grep -qE 'hostname_cache\.c|oui_override\.c|mdns_worker\.c' "$_hd/build.sh"; then
    test_fail "build.sh 还在编发现用的源文件"
else
    test_pass
fi
