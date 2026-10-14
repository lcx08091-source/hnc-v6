#!/system/bin/sh
# v5.26 T2: dpid 守护者唯一权威 run/dpid_launcher.choice
# service.sh 探测后原子落盘; Go 看门狗按 choice 监管, 救命路径改写 direct。
# v5.33: 只剩 launcher | direct 两个值(shell guard / Go supervisor 已删)。

test_start "dpid_choice: service.sh 探测后原子写入 dpid_launcher.choice"
grep -q 'dpid_launcher.choice' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'c_launcher).*_dpid_choice="launcher"' "$HNC_REPO_ROOT/service.sh" \
  && grep -q '\*).*_dpid_choice="direct"' "$HNC_REPO_ROOT/service.sh" \
  && ! grep -qE '_dpid_choice="(guard|supervisor)"' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'choice.tmp' "$HNC_REPO_ROOT/service.sh" && test_pass || test_fail "persist block missing"

test_start "dpid_choice: 看门狗救命路径把 choice 原子改写为 direct"
grep -q 'writeLauncherChoice("direct")' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/m5.go" \
  && grep -q 'launcher broken (abort detected), fallback to direct dpid' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/m5.go" \
  && test_pass || test_fail "rescue rewrite missing"

test_start "dpid_choice: Go 看门狗按 choice 两路监管(launcher | direct)"
grep -q 'func readLauncherChoice' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func parseLauncherChoice' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func superviseDpidM5' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/m5.go" \
  && ! grep -qE 'func (dpidGuardPlan|ensureShellGuardRunning|superviseDpidLegacy)' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/"*.go \
  && test_pass || test_fail "Go-side hooks wrong"

test_start "dpid_choice: 单测文件存在且被 go test 收录"
[ -f "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/launcher_choice_test.go" ] \
  && grep -q 'func TestParseLauncherChoice' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/launcher_choice_test.go" \
  && grep -q 'func TestM5OldChoiceValuesTreatedAsMissing' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/m5_test.go" \
  && test_pass || test_fail "unit test missing"

test_start "dpid_choice: 开机清掉上次会话的 choice"
grep -q 'rm -f "$HNC_DIR/run/dpid_launcher.choice"' "$HNC_REPO_ROOT/post-fs-data.sh" && test_pass || test_fail "stale choice"
