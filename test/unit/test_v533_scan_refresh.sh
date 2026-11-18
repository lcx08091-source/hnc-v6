#!/system/bin/sh
# test/unit/test_v533_scan_refresh.sh — v5.33: device_detect.sh 只留对外接口。
#   - scan: 写 nonce 到 run/devices.refresh, 等 Go 写者把同一个 nonce 写进
#     run/devices.refresh.ack, 再数 devices.json(WebUI「刷新」的返回值);
#     写者不在(热点没开 / 看门狗没跑)2 秒后照现有文件数, 不再退回 shell ARP 扫描;
#   - daemon: 只拉 hotspotd, 不再进 shell 轮询(旧代码没有 hotspotd 二进制时
#     进 daemon_shell_fallback 死循环)。
# 「改动前会失败」: v5.32 的 scan 不写 run/devices.refresh(第 1 条拿不到 3);
# daemon 在没有 hotspotd 时不返回(第 3 条超时)。

_sr_js3='{"aa:bb:cc:00:00:01":{"ip":"192.168.43.101","mac":"aa:bb:cc:00:00:01"},"aa:bb:cc:00:00:02":{"ip":"192.168.43.102","mac":"aa:bb:cc:00:00:02"},"aa:bb:cc:00:00:03":{"ip":"192.168.43.103","mac":"aa:bb:cc:00:00:03"}}'
_sr_js2='{"aa:bb:cc:00:00:01":{"ip":"192.168.43.101","mac":"aa:bb:cc:00:00:01"},"aa:bb:cc:00:00:02":{"ip":"192.168.43.102","mac":"aa:bb:cc:00:00:02"}}'

test_start "v5.33 device_detect scan: 等 Go 写者回执 nonce 后按新 devices.json 计数"
printf '%s' '{}' > "$HNC_TEST_DIR/data/devices.json"
# 假 Go 写者: 看到新的 nonce 就写 3 台的 devices.json, 然后回执同一个 nonce
_sr_dir="$HNC_TEST_DIR" _sr_js="$_sr_js3" sh -c '
    last=""; i=0
    while [ $i -lt 100 ]; do
        n=$(cat "$_sr_dir/run/devices.refresh" 2>/dev/null)
        if [ -n "$n" ] && [ "$n" != "$last" ]; then
            printf %s "$_sr_js" > "$_sr_dir/data/devices.json"
            printf "%s\n" "$n" > "$_sr_dir/run/devices.refresh.ack"
            last=$n
        fi
        sleep 0.05; i=$((i+1))
    done' &
_sr_pid=$!
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" scan 2>/dev/null)
_sr_nonce=$(cat "$HNC_TEST_DIR/run/devices.refresh" 2>/dev/null)
_sr_ack=$(cat "$HNC_TEST_DIR/run/devices.refresh.ack" 2>/dev/null)
kill "$_sr_pid" 2>/dev/null; wait "$_sr_pid" 2>/dev/null
if [ "$out" != "3" ]; then
    test_fail "scan 应返回 Go 写者这次写出的 3 台, 得 '$out'"
elif [ -z "$_sr_nonce" ] || [ "$_sr_nonce" != "$_sr_ack" ]; then
    test_fail "nonce / 回执不一致: refresh='$_sr_nonce' ack='$_sr_ack'"
else
    test_pass
fi

test_start "v5.33 device_detect scan: 没有写者时 ~2 秒后按现有文件计数, 不做 shell 扫描"
printf '%s' "$_sr_js2" > "$HNC_TEST_DIR/data/devices.json"
_sr_t0=$(date +%s)
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" scan 2>/dev/null)
rc=$?
_sr_el=$(( $(date +%s) - _sr_t0 ))
if [ "$rc" != "0" ] || [ "$out" != "2" ]; then
    test_fail "rc=$rc out='$out'(应 0 / 2)"
elif [ "$_sr_el" -gt 4 ]; then
    test_fail "等了 ${_sr_el} 秒(上限约 2 秒)"
elif [ "$(cat "$HNC_TEST_DIR/data/devices.json")" != "$_sr_js2" ]; then
    test_fail "devices.json 被改写了(不应再有 shell 扫描写者)"
else
    test_pass
fi

test_start "v5.33 device_detect daemon: 没有 hotspotd 二进制时直接返回, 不进 shell 轮询"
rm -f "$HNC_TEST_DIR/bin/hotspotd"
if command -v timeout >/dev/null 2>&1; then
    HNC_DIR="$HNC_TEST_DIR" timeout 15 sh "$HNC_REPO_ROOT/bin/device_detect.sh" daemon >/dev/null 2>&1
    rc=$?
    if [ "$rc" != "0" ]; then
        test_fail "daemon 应立即返回 0, rc=$rc(124 = 超时: 进了 shell 轮询)"
    elif [ -f "$HNC_TEST_DIR/run/detect.pid" ]; then
        test_fail "不应再写 run/detect.pid(shell 轮询的 pid)"
    else
        test_pass
    fi
else
    test_skip "no timeout(1)"
fi

test_start "v5.33 device_detect.sh: shell 扫描 / 名字解析 / 旧网卡探测链已删"
_sr_left=$(grep -v '^[[:space:]]*#' "$HNC_REPO_ROOT/bin/device_detect.sh" \
    | grep -nE 'do_scan_shell|daemon_shell_fallback|get_hostname|mdns_resolve|dumpsys|/proc/net/arp|get_hotspot_iface_legacy|m4_owner|kill -USR1')
if [ -n "$_sr_left" ]; then
    test_fail "还在: $(printf '%s' "$_sr_left" | head -3)"
else
    test_pass
fi
