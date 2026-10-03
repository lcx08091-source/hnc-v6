#!/system/bin/sh
# v5.26 T4: 月用量只留 limitCtl 一个口径。

test_start "quota_global: dpid alert 包的月度配额检测已移除"
[ ! -f "$HNC_REPO_ROOT/src/dpid/alert/quota.go" ] \
  && ! grep -q 'detectMonthlyQuota' "$HNC_REPO_ROOT/src/dpid/alert/alert.go" \
  && ! grep -q 'detectMonthlyQuota' "$HNC_REPO_ROOT/src/dpid/alert/anomaly_test.go" && test_pass || test_fail "alert 包仍含月度配额检测"

test_start "quota_global: limitCtl 提供 MonthUsage 权威出口"
grep -q 'func (c \*limitCtl) MonthUsage()' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" \
  && grep -q 'func (c \*limitCtl) MonthUsageSplit' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" \
  && grep -q 'func (c \*limitCtl) checkGlobalQuotaLocked' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" \
  && grep -q 'GlobalAlertWarn' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" \
  && grep -q 'GlobalAlertOver' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" && test_pass || test_fail "limitCtl 权威出口缺失"

test_start "quota_global: tick 的 DPI 下限条件含全局配额与 usage_month 请求"
grep -q 'globalQuotaOn() || now.Sub(c.usageMonthAt) < limitUsageMonthKeep' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" \
  && grep -q 'const limitUsageMonthKeep = 30 \* time.Minute' "$HNC_REPO_ROOT/daemon/hnc_httpd/limit_policy.go" \
  && grep -q 'func (c \*limitCtl) NoteUsageMonthRequest' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global.go" \
  && grep -q 'NoteUsageMonthRequest()' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v512.go" && test_pass || test_fail "tick 条件未扩展"

test_start "quota_global: usage_month 新增 period_start 并走权威口径"
grep -q 'period_start' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v512.go" \
  && grep -q 'MonthUsageSplit()' "$HNC_REPO_ROOT/daemon/hnc_httpd/action_v512.go" && test_pass || test_fail "usage_month 未改口径"

test_start "quota_global: 设置页文案改为计费月口径"
grep -q '按计费日起算' "$HNC_REPO_ROOT/webroot/js/settings.js" && test_pass || test_fail "settings.js 文案未改"

test_start "quota_global: 单测覆盖五种场景"
grep -q 'TestGlobalQuotaWarnOverNoDevicePolicy' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global_test.go" \
  && grep -q 'TestGlobalQuotaSkipsDeviceWithQuota' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global_test.go" \
  && grep -q 'TestGlobalQuotaNewMonthResets' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global_test.go" \
  && grep -q 'TestMonthUsageAndFallback' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global_test.go" \
  && grep -q 'TestMonthUsagePrefersBiggerSource' "$HNC_REPO_ROOT/daemon/hnc_httpd/quota_global_test.go" && test_pass || test_fail "单测缺失"
