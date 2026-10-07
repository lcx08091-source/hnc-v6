#!/system/bin/sh
# test/unit/test_v530_junk_table_sync.sh — v5.30 T1b: 垃圾主机名表三处一致。
# hotspotd(C)/ Go(hnc.io/dpid/hostname, dpid 与 httpd 共用)/ 前端(JS)各有
# 一份名单(语言不同, 不能共用代码), 这里把三份抽出来排序比对, 防止以后只改一处。

_jt_root="$HNC_REPO_ROOT"
# C: HNC_JUNK_HOSTNAMES[] = { ... };
_jt_c=$(sed -n '/HNC_JUNK_HOSTNAMES\[\] = {/,/};/p' "$_jt_root/daemon/hotspotd/hnc_helpers.c" \
    | grep -o '"[^"]*"' | tr -d '"' | sort | tr '\n' ' ')
# Go: var junk = map[string]bool{ ... }
_jt_go=$(sed -n '/^var junk = map\[string\]bool{/,/^}/p' "$_jt_root/src/dpid/hostname/junk.go" \
    | grep -o '"[^"]*": true' | sed 's/": true//; s/"//' | sort | tr '\n' ' ')
# JS: isJunkName 里的数组字面量
_jt_js=$(sed -n '/^function isJunkName(/,/^}/p' "$_jt_root/webroot/js/core.js" \
    | grep 'indexOf' | grep -o "'[^']*'" | tr -d "'" | sort | tr '\n' ' ')

test_start "v5.30 垃圾主机名表: C / Go / 前端三处一致"
if [ -z "$_jt_c" ] || [ "$(echo "$_jt_c" | wc -w)" -lt 11 ]; then
    test_fail "C 名单没抽到: [$_jt_c]"
elif [ "$_jt_c" != "$_jt_go" ]; then
    test_fail "Go 与 C 不一致: C=[$_jt_c] go=[$_jt_go]"
elif [ "$_jt_c" != "$_jt_js" ]; then
    test_fail "前端与 C 不一致: C=[$_jt_c] js=[$_jt_js]"
else
    test_pass
fi
