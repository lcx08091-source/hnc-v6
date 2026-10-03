#!/system/bin/sh
# v5.26 T8: 删除未上线的 C 版 JSON 工具。

test_start "hnc_json_c: 源文件与脚本已删除"
[ ! -f "$HNC_REPO_ROOT/daemon/hotspotd/tools/hnc_json.c" ] \
  && [ ! -f "$HNC_REPO_ROOT/daemon/hotspotd/tools/build_hnc_json.sh" ] \
  && [ ! -f "$HNC_REPO_ROOT/bin/hnc_json_c_status.sh" ] \
  && [ ! -f "$HNC_REPO_ROOT/test/unit/test_hnc_json_c_bridge.sh" ] \
  && [ ! -f "$HNC_REPO_ROOT/test/unit/test_hnc_json_c_write_bridge.sh" ] \
  && [ ! -f "$HNC_REPO_ROOT/test/unit/test_hnc_json_c_write_gate.sh" ] && test_pass || test_fail "C 版文件残留"

test_start "hnc_json_c: bin/hnc_json 不再引用 C helper"
[ "$(grep -c 'HNC_JSON_C' "$HNC_REPO_ROOT/bin/hnc_json")" = "0" ] \
  && [ "$(grep -c 'hnc_json_c_try' "$HNC_REPO_ROOT/bin/hnc_json")" = "0" ] \
  && grep -q 'hnc_json hotfix20.8 shell' "$HNC_REPO_ROOT/bin/hnc_json" && test_pass || test_fail "hnc_json 仍引用 C helper"

test_start "hnc_json_c: ci_preflight 检查已移除"
[ "$(grep -c 'HNC_JSON_C_MACHINE' "$HNC_REPO_ROOT/bin/ci_preflight.sh")" = "0" ] \
  && [ "$(grep -c 'ZIPTMP.hnc_json_c' "$HNC_REPO_ROOT/bin/ci_preflight.sh")" = "0" ] \
  && grep -q 'v5.26 T8' "$HNC_REPO_ROOT/bin/ci_preflight.sh" && test_pass || test_fail "ci_preflight 残留"

test_start "hnc_json_c: 诊断脚本不再引用 status helper"
[ "$(grep -c 'hnc_json_c_status' "$HNC_REPO_ROOT/bin/json_health_panel.sh")" = "0" ] \
  && [ "$(grep -c 'hnc_json_c_status' "$HNC_REPO_ROOT/bin/json_diag_bundle.sh")" = "0" ] && test_pass || test_fail "诊断脚本残留"

test_start "hnc_json_c: gate 测试的 host-helper 用例已移除"
! grep -q 'rejects host hnc_json_c' "$HNC_REPO_ROOT/test/unit/test_ci_preflight_artifact_gate.sh" && test_pass || test_fail "gate 用例残留"

test_start "hnc_json_c: ci_preflight 拒绝打进包里的旧 hnc_json_c"
grep -q "fail \"artifact contains bin/hnc_json_c" "$HNC_REPO_ROOT/bin/ci_preflight.sh" && test_pass || test_fail "artifact 拒绝检查缺失"

test_start "hnc_json_c: 全仓无功能性引用(仅剩 v5.26 注释 / ci_preflight 的拒绝检查)"
if grep -rn 'hnc_json_c' "$HNC_REPO_ROOT/bin/" "$HNC_REPO_ROOT/service.sh" "$HNC_REPO_ROOT/customize.sh" 2>/dev/null \
   | grep -v 'v5.26' | grep -v "^$HNC_REPO_ROOT/bin/ci_preflight.sh:.*grep -qE '(^|/)bin/hnc_json_c\$'" | grep -q .; then
  test_fail "功能性引用残留"
else
  test_pass
fi
