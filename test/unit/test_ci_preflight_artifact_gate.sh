#!/system/bin/sh
# hotfix20.9: artifact checks must catch stale module.prop and host hnc_json_c.
#
# rc30.12.34 (TASK-B2): fixture 跟当前 artifact_sanity_check.sh 必需文件集对齐.
# 同 test_artifact_release_rc5.sh 的修法.

# 当前 sanity gate 强制要求的全部文件 (跟 bin/artifact_sanity_check.sh 一致)
_REQ_FILES="
webroot/index.html
webroot/json-health.html
bin/sqm_manager.sh
bin/capability_probe.sh
daemon/hnc_httpd/hnc_httpd
bin/hnc_dpid
bin/dpi_rules_import.sh
data/dpi_rules.json
bin/ndpi_lab_probe.sh
bin/ndpi_lab_status.sh
bin/ndpi_lab_sample.sh
data/dpi_ndpi_config.json
bin/hnc_ndpi_probe
"

make_repo_fixture() {
    root="$1"
    mkdir -p "$root/bin" "$root/webroot" "$root/daemon/hnc_httpd" "$root/data" "$root/test/unit" 2>/dev/null
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
    # rc30.12.34 (TASK-B2): 补 sanity 必需文件. 来自 baseline 仓库 cp, 缺则占位.
    for relpath in $_REQ_FILES; do
        dst="$root/$relpath"
        mkdir -p "$(dirname "$dst")" 2>/dev/null
        [ -f "$dst" ] && continue  # 已被上面的固定逻辑写过则跳过
        if [ -f "$HNC_REPO_ROOT/$relpath" ]; then
            cp "$HNC_REPO_ROOT/$relpath" "$dst"
        else
            echo "# placeholder for $relpath (test fixture)" > "$dst"
        fi
        # 给 .sh 和 binary 加 exec 权限
        case "$relpath" in
            bin/*) chmod 755 "$dst" 2>/dev/null ;;
        esac
    done
}

# rc30.12.34 (TASK-B2): zip_ok_artifact() helper, 把 fixture 里所有必需文件都打包
# 进 zip (而不是只打 4 个), 这样 sanity gate 不会因为缺文件 fail.
_zip_ok_artifact() {
    repo="$1"; zipfile="$2"
    # shellcheck disable=SC2086  # $_REQ_FILES 故意 word splitting 成多个 arg
    (cd "$repo" && zip -q "$zipfile" module.prop $_REQ_FILES)
}

if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    test_start "ci_preflight artifact gate requires zip/unzip"
    test_skip "zip/unzip unavailable"
else
    test_start "ci_preflight artifact accepts matching module without C helper"
    repo="$HNC_TEST_DIR/repo_ok"
    make_repo_fixture "$repo"
    _zip_ok_artifact "$repo" "$HNC_TEST_DIR/ok.zip"
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
    # 跟 ok artifact 一样打全 sanity 必需文件 + 多打一个 host hnc_json_c
    # shellcheck disable=SC2086  # $_REQ_FILES 故意 word splitting
    (cd "$repo" && zip -q "$HNC_TEST_DIR/bad.zip" module.prop $_REQ_FILES bin/hnc_json_c)
    out="$(cd "$repo" && rm -f bin/hnc_json_c && sh bin/ci_preflight.sh --artifact "$HNC_TEST_DIR/bad.zip" 2>&1)"
    rc=$?
    assert_ne "0" "$rc" "preflight should fail host helper artifact" || return
    assert_contains "$out" "artifact hnc_json_c is not Android ARM/AArch64 ELF" || return
    test_pass
fi
