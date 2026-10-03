#!/system/bin/sh
# v5.26 T5: 热点网卡名只认 hnc_iface.sh 的结果。

test_start "ifacehint: 共享包存在且语义齐备"
[ -f "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" ] \
  && grep -q 'func Read(runDir string, now time.Time) (string, bool)' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'FreshWindow = 10 \* time.Minute' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'iface_detect.json' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" \
  && grep -q 'hotspot_iface' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint.go" && test_pass || test_fail "ifacehint 包缺失"

test_start "ifacehint: dpid 侧两个 Go 调用方接入"
grep -q 'ifacehint.Read' "$HNC_REPO_ROOT/src/dpid/capture/iface.go" \
  && grep -q 'ifacehint.Read' "$HNC_REPO_ROOT/src/dpid/cmd/dpid_supervisor/main.go" && test_pass || test_fail "Go 调用方未接入"

test_start "ifacehint: guard.sh 的 get_iface 优先读 iface_detect.json"
grep -q 'v5.26 T5' "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" \
  && grep -B 2 -A 1 'read_json_string_key iface "\$RUN/iface_detect.json"' "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" | grep -q 'ts' \
  && grep -q '\-le 600' "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" \
  && grep -q 'hotspot_iface' "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" && test_pass || test_fail "guard get_iface 未改"

test_start "ifacehint: 单测覆盖五种场景"
[ -f "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" ] \
  && grep -q 'TestReadFreshDetect' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadStaleDetectFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadEmptyIfaceFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadCorruptDetectFallsBack' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" \
  && grep -q 'TestReadFutureTsRejected' "$HNC_REPO_ROOT/src/dpid/ifacehint/ifacehint_test.go" && test_pass || test_fail "单测缺失"

test_start "ifacehint: guard.sh json_escape 仍把 Tab 换成空格(防编辑器把 Tab 改成空格)"
grep -q "$(printf 's/\t/ /g')" "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" && test_pass || test_fail "json_escape tab rule lost"
