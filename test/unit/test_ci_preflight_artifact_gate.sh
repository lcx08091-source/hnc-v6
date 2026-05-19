#!/system/bin/sh
# hotfix20.9: artifact checks must catch stale module.prop and host hnc_json_c.

make_repo_fixture() {
    root="$1"
    mkdir -p "$root/bin" "$root/webroot" "$root/daemon/hnc_httpd" "$root/test/unit" 2>/dev/null
    cat > "$root/module.prop" <<'PROP'
version=v5.1.0-rc1-hotfix20.9
versionCode=509209
PROP
    echo '<html></html>' > "$root/webroot/index.html"
    echo '<html></html>' > "$root/webroot/json-health.html"
    : > "$root/daemon/hnc_httpd/hnc_httpd"
    chmod 755 "$root/daemon/hnc_httpd/hnc_httpd"
    for f in json_guard.sh json_set.sh json_doctor.sh json_diag_bundle.sh json_set_batch.sh tc_manager.sh watchdog.sh; do
      echo '#!/system/bin/sh' > "$root/bin/$f"
      echo 'exit 0' >> "$root/bin/$f"
      chmod 755 "$root/bin/$f"
    done
    echo '#!/system/bin/sh' > "$root/bin/json_regression_test.sh"
    echo 'exit 0' >> "$root/bin/json_regression_test.sh"
    chmod 755 "$root/bin/json_regression_test.sh"
    cp "$HNC_REPO_ROOT/bin/ci_preflight.sh" "$root/bin/ci_preflight.sh"
    chmod 755 "$root/bin/ci_preflight.sh"
}

if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    test_start "ci_preflight artifact gate requires zip/unzip"
    test_skip "zip/unzip unavailable"
else
    test_start "ci_preflight artifact accepts matching module without C helper"
    repo="$HNC_TEST_DIR/repo_ok"
    make_repo_fixture "$repo"
    ( cd "$repo" && zip -q "$HNC_TEST_DIR/ok.zip" module.prop webroot/index.html webroot/json-health.html daemon/hnc_httpd/hnc_httpd )
    out="$(cd "$repo" && sh bin/ci_preflight.sh --artifact "$HNC_TEST_DIR/ok.zip" 2>&1)"
    rc=$?
    assert_eq "0" "$rc" "preflight should pass matching artifact" || return
    assert_contains "$out" "artifact version matches source" || return
    test_pass

    test_start "ci_preflight artifact rejects host hnc_json_c"
    repo="$HNC_TEST_DIR/repo_bad"
    make_repo_fixture "$repo"
    mkdir -p "$repo/bin"
    # Minimal ELF-ish header with e_machine = 0x003e at offset 18 (x86_64 host).
    { printf '\177ELF'; dd if=/dev/zero bs=1 count=14 2>/dev/null; printf '\076\000'; } > "$repo/bin/hnc_json_c"
    chmod 755 "$repo/bin/hnc_json_c"
    ( cd "$repo" && zip -q "$HNC_TEST_DIR/bad.zip" module.prop webroot/index.html webroot/json-health.html daemon/hnc_httpd/hnc_httpd bin/hnc_json_c )
    out="$(cd "$repo" && rm -f bin/hnc_json_c && sh bin/ci_preflight.sh --artifact "$HNC_TEST_DIR/bad.zip" 2>&1)"
    rc=$?
    assert_ne "0" "$rc" "preflight should fail host helper artifact" || return
    assert_contains "$out" "artifact hnc_json_c is not Android ARM/AArch64 ELF" || return
    test_pass
fi
