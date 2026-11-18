#!/system/bin/sh
# v5.26 T5: 热点网卡名只认 hnc_iface.sh 的结果。

test_start "ifacehint: 共享包存在且语义齐备"
[ -f "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" ] \
  && grep -q 'func Read(runDir string, now time.Time) (string, bool)' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'FreshWindow = 10 \* time.Minute' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'iface_detect.json' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'hotspot_iface' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" && test_pass || test_fail "ifacehint 包缺失"

test_start "ifacehint: dpid 侧 Go 调用方接入"
# v5.33: shell guard / Go supervisor 已删, dpid 侧只剩 capture 一个调用方
grep -q 'ifacehint.Read' "$HNC_REPO_ROOT/src/dpid/capture/iface.go" && test_pass || test_fail "Go 调用方未接入"

test_start "ifacehint: 单测覆盖五种场景"
[ -f "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" ] \
  && grep -q 'TestReadFreshDetect' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadStaleDetectFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadEmptyIfaceFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadCorruptDetectFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadFutureTsRejected' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" && test_pass || test_fail "单测缺失"
