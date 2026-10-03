#!/system/bin/sh
# v5.26 T2: dpid 守护者唯一权威 run/dpid_launcher.choice
# service.sh 探测后原子落盘; sentinel 救命路径改写 direct; Go 看门狗按 choice 监管。

test_start "dpid_choice: service.sh 探测后原子写入 dpid_launcher.choice"
grep -q 'dpid_launcher.choice' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'c_launcher).*_dpid_choice="launcher"' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'shell_guard).*_dpid_choice="guard"' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'go_supervisor).*_dpid_choice="supervisor"' "$HNC_REPO_ROOT/service.sh" \
  && grep -q 'choice.tmp' "$HNC_REPO_ROOT/service.sh" && test_pass || test_fail "persist block missing"

test_start "dpid_choice: sentinel 救命路径把 choice 原子改写为 direct"
grep -q "printf 'direct" "$HNC_REPO_ROOT/service.sh" \
  && [ "$(grep -c "printf 'direct" "$HNC_REPO_ROOT/service.sh")" -ge 1 ] \
  && grep -q 'launcher broken (abort detected), fallback to direct dpid' "$HNC_REPO_ROOT/service.sh" && test_pass || test_fail "rescue rewrite missing"

test_start "dpid_choice: Go 看门狗按 choice 四路监管"
grep -q 'func readLauncherChoice' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func dpidGuardPlan' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func ensureShellGuardRunning' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func dpidDaemonDirect' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" \
  && grep -q 'func findLiveByCmdlineSub' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" && test_pass || test_fail "Go-side hooks missing"

test_start "dpid_choice: 单测文件存在且被 go test 收录"
[ -f "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/launcher_choice_test.go" ] \
  && grep -q 'func TestDpidGuardPlan' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/launcher_choice_test.go" && test_pass || test_fail "unit test missing"
