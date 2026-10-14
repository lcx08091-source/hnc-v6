#!/system/bin/sh
# test/unit/test_v530_junk_table_sync.sh — v5.30 T1b: 垃圾主机名表多处一致。
# Go(hnc.io/dpid/hostname, dpid / httpd / devname 共用)与前端(JS)各有一份
# 名单(语言不同, 不能共用代码), 这里把两份抽出来排序比对, 防止以后只改一处。
# (v5.33: C 版 hotspotd 不再解析名字, 它那份随 C 版发现一起删了。)

_jt_root="$HNC_REPO_ROOT"
# Go: var junk = map[string]bool{ ... }
_jt_go=$(sed -n '/^var junk = map\[string\]bool{/,/^}/p' "$_jt_root/src/dpid/hostname/junk.go" \
    | grep -o '"[^"]*": true' | sed 's/": true//; s/"//' | sort | tr '\n' ' ')
# JS: isJunkName 里的数组字面量
_jt_js=$(sed -n '/^function isJunkName(/,/^}/p' "$_jt_root/webroot/js/core.js" \
    | grep 'indexOf' | grep -o "'[^']*'" | tr -d "'" | sort | tr '\n' ' ')

test_start "v5.30 垃圾主机名表: Go / 前端两处一致"
if [ -z "$_jt_go" ] || [ "$(echo "$_jt_go" | wc -w)" -lt 11 ]; then
    test_fail "Go 名单没抽到: [$_jt_go]"
elif [ "$_jt_go" != "$_jt_js" ]; then
    test_fail "前端与 Go 不一致: go=[$_jt_go] js=[$_jt_js]"
else
    test_pass
fi
