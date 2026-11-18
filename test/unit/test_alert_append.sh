#!/system/bin/sh
# v5.26 T7: 告警写入只留一个函数(alert.Append, 带 flock)。

test_start "alert_append: alert 包导出带 flock 的 Append"
grep -q 'func Append(path string, a Alert) error' "$HNC_REPO_ROOT/src/dpid/alert/alert.go" \
  && grep -q 'syscall.Flock' "$HNC_REPO_ROOT/src/dpid/alert/alert.go" \
  && grep -q 'LOCK_EX' "$HNC_REPO_ROOT/src/dpid/alert/alert.go" \
  && grep -q 'func appendAlert' "$HNC_REPO_ROOT/src/dpid/alert/alert.go" && test_pass || test_fail "Append 未导出"

test_start "alert_append: httpd 侧四个副本已删除"
[ "$(grep -c 'func appendAlertJSONL' "$HNC_REPO_ROOT/daemon/hnc_httpd/app_time.go")" = "0" ] \
  && [ "$(grep -c 'func puAppendAlert' "$HNC_REPO_ROOT/daemon/hnc_httpd/phone_usage.go")" = "0" ] \
  && ! grep -rq 'appendAlertJSONL\|puAppendAlert' "$HNC_REPO_ROOT/daemon/hnc_httpd/" && test_pass || test_fail "副本残留"

test_start "alert_append: httpd 全部写入点改走 alert.Append"
grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/app_time.go" \
  && grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/mac_merge.go" \
  && grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/pair_guard.go" \
  && grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/dns_takeover.go" \
  && grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" \
  && grep -q 'alert.Append' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" \
  && [ "$(grep -c 'os.O_APPEND' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" "$HNC_REPO_ROOT/daemon/hnc_httpd/app_time.go" "$HNC_REPO_ROOT/daemon/hnc_httpd/phone_usage.go" "$HNC_REPO_ROOT/daemon/hnc_httpd/mac_merge.go" "$HNC_REPO_ROOT/daemon/hnc_httpd/pair_guard.go" | grep -cv ':0$')" = "0" ] && test_pass || test_fail "写入点未统一"

test_start "alert_append: 并发单测存在"
grep -q 'TestAppendConcurrent' "$HNC_REPO_ROOT/src/dpid/alert/append_test.go" \
  && grep -q 'TestAppendSingleLineJSON' "$HNC_REPO_ROOT/src/dpid/alert/append_test.go" && test_pass || test_fail "并发单测缺失"
