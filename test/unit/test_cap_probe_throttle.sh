#!/system/bin/sh
# v5.27: watchdog action capability_probe 节流 —— Go 看门狗每轮(60 秒)都调它,
# 旧的 30 秒节流等于每分钟跑一次完整能力探测(真机热点空转 watchdog ≈ 530 CPU 秒/小时)。

cap_stub() {
    printf '#!/bin/sh\necho x >> "%s/run/cap_calls"\n' "$HNC_TEST_DIR" > "$HNC_TEST_DIR/bin/capability_probe.sh"
    chmod +x "$HNC_TEST_DIR/bin/capability_probe.sh"
    rm -f "$HNC_TEST_DIR/run/cap_calls" "$HNC_TEST_DIR/run/capability_probe_last"
}
cap_calls() { [ -f "$HNC_TEST_DIR/run/cap_calls" ] && wc -l < "$HNC_TEST_DIR/run/cap_calls" | tr -d ' ' || echo 0; }
cap_run() { HNC_DIR="$HNC_TEST_DIR" sh "$HNC_TEST_DIR/bin/watchdog.sh" action capability_probe "$1" >/dev/null 2>&1; }

test_start "cap_probe: 同一网卡 2 分钟前测过 → 不重测(旧版 30 秒节流会每分钟重测)"
mock_setup; cap_stub
echo "$(( $(date +%s) - 120 ))" > "$HNC_TEST_DIR/run/capability_probe_last"  # 旧格式, 新旧代码都能解析
cap_run wlan2; cap_run wlan2
assert_eq "0" "$(cap_calls)" "同网卡 6 小时内不应重测" && test_pass
mock_teardown

test_start "cap_probe: 网卡变了立即重测"
mock_setup; cap_stub
cap_run wlan2; cap_run ap0
assert_eq "2" "$(cap_calls)" "换网卡应重测" && test_pass
mock_teardown

test_start "cap_probe: 标记早于本次开机 → 重测"
mock_setup; cap_stub
echo "1000 wlan2" > "$HNC_TEST_DIR/run/capability_probe_last"
cap_run wlan2
assert_eq "1" "$(cap_calls)" "上次开机的标记不算数" && test_pass
mock_teardown

test_start "cap_probe: 超过 6 小时重测; 旧格式(只有秒数)按同网卡处理"
mock_setup; cap_stub
now=$(date +%s)
echo "$now" > "$HNC_TEST_DIR/run/capability_probe_last"
cap_run wlan2
c1=$(cap_calls)
echo "$((now - 21700)) wlan2" > "$HNC_TEST_DIR/run/capability_probe_last"
cap_run wlan2
assert_eq "0" "$c1" "旧格式且刚测过不应重测" && assert_eq "1" "$(cap_calls)" "超过 6 小时应重测" && test_pass
mock_teardown
