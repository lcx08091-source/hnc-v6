#!/system/bin/sh
# v5.3.0-rc5 artifact picker regression tests
#
# rc30.12.34 (TASK-B2): fixture 跟当前 artifact_sanity_check.sh 必需文件集对齐.
# baseline rc30.12.30 的 sanity gate 加了 hnc_dpid / dpi_rules.json / nDPI 等 7 个
# 必需文件, fixture 没跟, 导致这两个 unit test 红灯. 不改业务功能, 只把测试夹具
# 补全跟得上当前 sanity gate.

# 当前 artifact_sanity_check.sh 强制要求的所有文件 (跟 bin/artifact_sanity_check.sh
# L54 的 `for req in ...; do` 保持完全一致)
_REQUIRED_FILES_v5_3_rc5="
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

make_minimal_module_zip_rc5() {
    out="$1"
    d="$HNC_TEST_DIR/min_module_rc5"
    rm -rf "$d"
    mkdir -p "$d/daemon/hnc_httpd" "$d/webroot" "$d/bin" "$d/data"
    cp "$HNC_REPO_ROOT/module.prop" "$d/module.prop"
    cp "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" "$d/daemon/hnc_httpd/hnc_httpd"
    # In source-patch tests the checked-in binary may still be the previous rc;
    # align module.prop to the embedded binary version so artifact_sanity_check
    # can validate the mechanism without requiring Go compilation in the test VM.
    if command -v strings >/dev/null 2>&1; then
        embedded_ver=$(strings "$d/daemon/hnc_httpd/hnc_httpd" | grep -E '^v5\.3\.0-rc[0-9]+$' | tail -1)
        [ -n "$embedded_ver" ] && sed -i "s/^version=.*/version=$embedded_ver/" "$d/module.prop"
    fi
    # rc30.12.34 (TASK-B2): 把当前 sanity 必需的全部文件都拷过来.
    # 之前只拷 module.prop/2 webroot/2 bin 共 5 个, 现在 sanity 要 13 个, 缺 8 个.
    # 如果 baseline 仓库里缺某个文件 (例如新加的 ndpi 文件还没 commit), 单测会用
    # 这里的 fallback 生成空占位, 让测试至少不会因为 cp 失败 abort.
    for relpath in $_REQUIRED_FILES_v5_3_rc5; do
        src="$HNC_REPO_ROOT/$relpath"
        dst="$d/$relpath"
        mkdir -p "$(dirname "$dst")" 2>/dev/null
        if [ -f "$src" ]; then
            cp "$src" "$dst"
        else
            # 没有就放占位文件让 sanity 至少能看到 path 存在 (sanity 主要检查
            # 文件路径 + ELF magic, 不深查内容)
            echo "# placeholder for $relpath (test fixture)" > "$dst"
        fi
    done
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
