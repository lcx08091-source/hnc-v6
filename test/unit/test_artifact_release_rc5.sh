#!/system/bin/sh
# v5.3.0-rc5 artifact picker regression tests

make_minimal_module_zip_rc5() {
    out="$1"
    d="$HNC_TEST_DIR/min_module_rc5"
    rm -rf "$d"
    mkdir -p "$d/daemon/hnc_httpd" "$d/webroot" "$d/bin"
    cp "$HNC_REPO_ROOT/module.prop" "$d/module.prop"
    cp "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" "$d/daemon/hnc_httpd/hnc_httpd"
    # In source-patch tests the checked-in binary may still be the previous rc;
    # align module.prop to the embedded binary version so artifact_sanity_check
    # can validate the mechanism without requiring Go compilation in the test VM.
    if command -v strings >/dev/null 2>&1; then
        embedded_ver=$(strings "$d/daemon/hnc_httpd/hnc_httpd" | grep -E '^v5\.3\.0-rc[0-9]+$' | tail -1)
        [ -n "$embedded_ver" ] && sed -i "s/^version=.*/version=$embedded_ver/" "$d/module.prop"
    fi
    cp "$HNC_REPO_ROOT/webroot/index.html" "$d/webroot/index.html"
    cp "$HNC_REPO_ROOT/webroot/json-health.html" "$d/webroot/json-health.html"
    cp "$HNC_REPO_ROOT/bin/sqm_manager.sh" "$d/bin/sqm_manager.sh"
    cp "$HNC_REPO_ROOT/bin/capability_probe.sh" "$d/bin/capability_probe.sh"
    (cd "$d" && zip -q -r "$out" .)
}

test_start "v5.3 rc5 artifact_pick_flashable accepts a direct module ZIP"
if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then test_skip "zip/unzip unavailable"; return; fi
[ -f "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" ] || { test_skip "hnc_httpd binary unavailable in source tree"; return; }
direct="$HNC_TEST_DIR/HNC-v5_3_0-rc5-arm64.zip"
outdir="$HNC_TEST_DIR/picked_direct"
make_minimal_module_zip_rc5 "$direct"
out=$(sh "$HNC_REPO_ROOT/bin/artifact_pick_flashable.sh" "$direct" "$outdir" 2>&1); rc=$?
assert_eq "0" "$rc" "direct module zip should pass artifact picker" || return
assert_contains "$out" 'source ZIP already has module.prop at root' "picker should detect direct flashable zip" || return
assert_contains "$out" 'flashable_artifact=' "picker should print flashable_artifact path" || return
test_pass

test_start "v5.3 rc5 artifact_pick_flashable extracts Actions outer wrapper ZIP"
if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then test_skip "zip/unzip unavailable"; return; fi
[ -f "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" ] || { test_skip "hnc_httpd binary unavailable in source tree"; return; }
inner="$HNC_TEST_DIR/HNC-v5_3_0-rc5-arm64.zip"
outer="$HNC_TEST_DIR/actions-download-rc5.zip"
outdir="$HNC_TEST_DIR/picked_outer"
make_minimal_module_zip_rc5 "$inner"
(cd "$HNC_TEST_DIR" && zip -q "$outer" "$(basename "$inner")")
out=$(sh "$HNC_REPO_ROOT/bin/artifact_pick_flashable.sh" "$outer" "$outdir" 2>&1); rc=$?
assert_eq "0" "$rc" "outer wrapper should be accepted after extracting inner module zip" || return
assert_contains "$out" 'outer wrapper' "picker should identify Actions outer wrapper" || return
assert_contains "$out" 'inner flashable ZIP extracted' "picker should extract inner flashable zip" || return
assert_contains "$out" "flashable_artifact=$outdir/$(basename "$inner")" "picker should print extracted inner path" || return
test_pass
