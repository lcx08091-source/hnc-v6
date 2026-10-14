#!/system/bin/sh
# test/unit/test_v532_scan_count.sh — v5.32 T1: 设备扫描计数不再恒为 1。
# devices.json 是单行紧凑 JSON(C / Go 两个写者都这么写), 之前按「含 "mac" 的
# 行数」数恒为 1。修复: 数 "mac":" 的出现次数, 以新子命令 `device_detect.sh
# count` 暴露(旧代码没有该子命令, 回 Usage / exit 1 —— 改动前必失败)。

test_start "v5.32 device_detect count: 单行 devices.json 按出现次数计, 不按行"
_i=0; _js=""
while [ $_i -lt 10 ]; do
    _suf=$(printf '%02x' $_i)
    _js="${_js}\"aa:bb:cc:dd:ee:${_suf}\":{\"ip\":\"192.168.43.10${_suf}\",\"mac\":\"aa:bb:cc:dd:ee:${_suf}\"},"
    _i=$((_i+1))
done
_js="{${_js%,}}"
printf '%s' "$_js" > "$HNC_TEST_DIR/data/devices.json"
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" count 2>/dev/null)
rc=$?
if [ "$rc" != "0" ]; then
    test_fail "count 子命令退出码 $rc(旧代码: 无此子命令回 Usage)"
elif [ "$out" != "10" ]; then
    test_fail "单行 10 台设备应数出 10, 得 $out(旧逻辑按行数恒为 1)"
else
    test_pass
fi

test_start "v5.32 device_detect count: 转义 hostname 里的 \"mac\" 不误数"
printf '%s' '{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.101","mac":"aa:bb:cc:dd:ee:01","hostname":"my\"mac\":\"x"}}' > "$HNC_TEST_DIR/data/devices.json"
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" count 2>/dev/null)
if [ "$out" = "1" ]; then
    test_pass
else
    test_fail "转义 hostname 不应误数, 得 $out"
fi

test_start "v5.32 device_detect count: 文件不存在按 0"
rm -f "$HNC_TEST_DIR/data/devices.json"
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" count 2>/dev/null)
if [ "$out" = "0" ]; then
    test_pass
else
    test_fail "无文件应得 0, 得 $out"
fi

# 审查补: 测接起来的样子 —— WebUI「刷新」走 actionRefresh → `device_detect.sh scan`
# → do_scan_via_daemon, 返回值就是界面上的设备数。用一个假 hotspotd(收到
# SIGUSR1 就写一份单行 3 台的 devices.json)驱动真实的 scan 分支。
test_start "v5.32 device_detect scan: 经 hotspotd(SIGUSR1)扫描返回的设备数按出现次数计"
mkdir -p "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
_cnt_js='{"aa:bb:cc:00:00:01":{"ip":"192.168.43.101","mac":"aa:bb:cc:00:00:01"},"aa:bb:cc:00:00:02":{"ip":"192.168.43.102","mac":"aa:bb:cc:00:00:02"},"aa:bb:cc:00:00:03":{"ip":"192.168.43.103","mac":"aa:bb:cc:00:00:03"}}'
printf '%s' '{}' > "$HNC_TEST_DIR/data/devices.json"
touch -d '2020-01-01 00:00:00' "$HNC_TEST_DIR/data/devices.json" 2>/dev/null \
    || touch -t 202001010000 "$HNC_TEST_DIR/data/devices.json"
_cnt_out="$HNC_TEST_DIR/data/devices.json" _cnt_js="$_cnt_js" sh -c '
    trap "printf %s \"\$_cnt_js\" > \"\$_cnt_out\"" USR1
    i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done' &
_cnt_pid=$!
echo "$_cnt_pid" > "$HNC_TEST_DIR/run/hotspotd.pid"
sleep 0.2
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" scan 2>/dev/null)
kill "$_cnt_pid" 2>/dev/null; wait "$_cnt_pid" 2>/dev/null
rm -f "$HNC_TEST_DIR/run/hotspotd.pid"
if [ "$out" = "3" ]; then
    test_pass
else
    test_fail "单行 3 台设备, scan 应返回 3, 得 '$out'(旧逻辑按行数恒为 1)"
fi
