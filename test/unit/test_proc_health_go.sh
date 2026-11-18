#!/system/bin/sh
# v5.26 T3: /api/proc_health 由 Go(procfind)实现, rc17_process_health.sh 已删。

test_start "proc_health: rc17 shell 脚本已删除"
[ ! -f "$HNC_REPO_ROOT/bin/rc17_process_health.sh" ] && test_pass || test_fail "rc17 仍存在"

test_start "proc_health: Go 实现存在且 JSON 字段齐全"
[ -f "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" ] \
  && grep -q 'schema_version' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" \
  && grep -q 'watchdog_main' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" \
  && grep -q 'dpid_guard_main' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" \
  && grep -q 'dpid_child' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" \
  && grep -q 'pidfile 不可用' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" && test_pass || test_fail "Go 实现缺失"

test_start "proc_health: 四处调用方全部走 procfind"
grep -q 'procfind' "$HNC_REPO_ROOT/daemon/hnc_httpd/selfcheck.go" \
  && grep -q 'procfind' "$HNC_REPO_ROOT/daemon/hnc_httpd/power_stats.go" \
  && grep -q 'procfind' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health.go" \
  && grep -q 'HNC_HP=' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v511.go" \
  && [ "$(grep -cF 'HP=$(pidof' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v511.go")" = "0" ] \
  && [ "$(grep -cF 'pidof", d.Pidof' "$HNC_REPO_ROOT/daemon/hnc_httpd/selfcheck.go")" = "0" ] && test_pass || test_fail "procfind 未接齐"

test_start "proc_health: debug_bundle 拷贝 run/proc_health.json, 不再引用 rc17"
grep -q 'proc_health.json' "$HNC_REPO_ROOT/bin/debug_bundle.sh" \
  && ! grep -q 'run_cmd process_health sh ' "$HNC_REPO_ROOT/bin/debug_bundle.sh" \
  && grep -q 'proc_health.json' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v511.go" && test_pass || test_fail "debug_bundle 未改"

test_start "proc_health: 共享包与单测存在"
[ -f "$HNC_REPO_ROOT/src/dpid/procfind/procfind.go" ] \
  && [ -f "$HNC_REPO_ROOT/src/dpid/procfind/procfind_test.go" ] \
  && [ -f "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health_test.go" ] \
  && grep -q 'func TestBuildProcHealth' "$HNC_REPO_ROOT/daemon/hnc_httpd/proc_health_test.go" && test_pass || test_fail "单测缺失"
