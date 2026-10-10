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
