#!/system/bin/sh
# v5.26 T6: 时钟可信规则只留一份(clockhwm)。

test_start "clockhwm: 共享包存在且常量齐备"
[ -f "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm.go" ] \
  && grep -q 'MinUnix int64 = 1735689600' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm.go" \
  && grep -q 'BackTolerance int64 = 600' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm.go" \
  && grep -q 'func ReadHWM(path string) int64' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm.go" \
  && grep -q 'func Sane(nowUnix, hwm int64) bool' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm.go" && test_pass || test_fail "clockhwm 包缺失"

test_start "clockhwm: httpd 与看门狗两侧都委托共享包"
grep -q 'clockhwm.Sane' "$HNC_REPO_ROOT/daemon/hnc_httpd/clock_guard.go" \
  && grep -q 'clockhwm.Sane' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/duties.go" \
  && grep -q 'clockhwm.ReadHWM' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/duties.go" && test_pass || test_fail "两侧未接入"

test_start "clockhwm: clock_guard 自愈与跳变检测逻辑保留"
grep -q 'clockMinYear' "$HNC_REPO_ROOT/daemon/hnc_httpd/clock_guard.go" \
  && grep -q 'clockJumpThreshold' "$HNC_REPO_ROOT/daemon/hnc_httpd/clock_guard.go" \
  && grep -q 'clockHWMHealAfter' "$HNC_REPO_ROOT/daemon/hnc_httpd/clock_guard.go" && test_pass || test_fail "自愈逻辑被误删"

test_start "clockhwm: shell 版常量由镜像测试锁定"
grep -q 'HNC_CLOCK_MIN_TS=1735689600' "$HNC_REPO_ROOT/bin/hnc_clock.sh" \
  && grep -q 'HNC_CLOCK_TOLERANCE=600' "$HNC_REPO_ROOT/bin/hnc_clock.sh" \
  && grep -q 'TestShellMirrorConstants' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm_test.go" && test_pass || test_fail "shell 镜像未锁定"

test_start "clockhwm: 单测覆盖 Sane 边界与 ReadHWM 解析"
grep -q 'TestSane' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm_test.go" \
  && grep -q 'TestReadHWM' "$HNC_REPO_ROOT/src/dpid/clockhwm/clockhwm_test.go" && test_pass || test_fail "单测缺失"
