#!/system/bin/sh
# v5.3.0-rc5 artifact picker regression tests
#
# rc30.12.34 (TASK-B2): fixture 跟当前 artifact_sanity_check.sh 必需文件集对齐.
# baseline rc30.12.30 的 sanity gate 加了 hnc_dpid / dpi_rules.json 等必需
# 必需文件, fixture 没跟, 导致这两个 unit test 红灯. 不改业务功能, 只把测试夹具
# 补全跟得上当前 sanity gate.

# 当前 artifact_sanity_check.sh 强制要求的所有文件
# v5.22: 直接从 artifact_sanity_check.sh 的 "for req in ..." 读(与
# test_ci_preflight_artifact_gate.sh 同法) —— 手抄清单曾落后于 gate(缺 clsact 产物、
# WebUI 的 css/js), 一有 hnc_httpd 二进制本用例就恒 FAIL。
_REQUIRED_FILES_v5_3_rc5=$(sed -n 's/^for req in \(.*\); do$/\1/p' "$HNC_REPO_ROOT/bin/artifact_sanity_check.sh" | head -1)
[ -n "$_REQUIRED_FILES_v5_3_rc5" ] || _REQUIRED_FILES_v5_3_rc5="
LICENSE
webroot/index.html
webroot/json-health.html
bin/capability_probe.sh
daemon/hnc_httpd/hnc_httpd
bin/hnc_dpid
bin/dpi_rules_import.sh
data/dpi_rules.d/00-core-meta.json
"
case " $_REQUIRED_FILES_v5_3_rc5 " in
    *" LICENSE "*) ;;
    *) _REQUIRED_FILES_v5_3_rc5="$_REQUIRED_FILES_v5_3_rc5 LICENSE" ;;
esac

_rc5_detect_httpd_ver() {
    local bin="$1" cur_ver="$2" v=""
    if [ -n "$cur_ver" ] && grep -a -F "$cur_ver" "$bin" >/dev/null 2>&1; then
        printf '%s' "$cur_ver"
        return 0
    fi
    if command -v strings >/dev/null 2>&1; then
        v=$({ strings -a "$bin" 2>/dev/null || strings "$bin" 2>/dev/null; } \
            | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+(\.[0-9]+){0,3})?(-(hotfix|hf)[0-9]+(\.[0-9]+)?)?$' \
            | grep -v '^v[01]\.' | tail -1)
    fi
    printf '%s' "$v"
}

make_minimal_module_zip_rc5() {
    out="$1"
    d="$HNC_TEST_DIR/min_module_rc5"
    rm -rf "$d"
    mkdir -p "$d/daemon/hnc_httpd" "$d/webroot" "$d/bin" "$d/data"
    cp "$HNC_REPO_ROOT/module.prop" "$d/module.prop"
    cp "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" "$d/daemon/hnc_httpd/hnc_httpd"
    [ -f "$HNC_REPO_ROOT/LICENSE" ] && cp "$HNC_REPO_ROOT/LICENSE" "$d/LICENSE"
    # In source-patch tests the checked-in binary may still be the previous rc;
    # align module.prop to the embedded binary version so artifact_sanity_check
    # can validate the mechanism without requiring Go compilation in the test VM.
    cur_ver=$(awk -F= '$1=="version"{print $2; exit}' "$d/module.prop" 2>/dev/null | tr -d '\r')
    embedded_ver=$(_rc5_detect_httpd_ver "$d/daemon/hnc_httpd/hnc_httpd" "$cur_ver")
    if [ -n "$embedded_ver" ] && [ "$embedded_ver" != "$cur_ver" ]; then
        sed -i "s/^version=.*/version=$embedded_ver/" "$d/module.prop"
    fi
    # 检测 hnc_httpd 的 ELF 架构, 缺省 native 二进制占位与 pkg_abi 与之保持一致
    _httpd_m=""
    if command -v od >/dev/null 2>&1; then
        _httpd_m=$(od -An -tx1 -j18 -N2 "$d/daemon/hnc_httpd/hnc_httpd" 2>/dev/null | awk '{print $1 " " $2}')
    fi
    if [ "$_httpd_m" = "28 00" ]; then
        echo "armeabi-v7a" > "$d/bin/hnc_pkg_abi"
    fi
    # rc30.12.34 (TASK-B2): 把当前 sanity 必需的全部文件都拷过来.
    # 如果 baseline 仓库里缺某个文件 (例如 CI 现编的二进制还没产出), 单测会用
    # 这里的 fallback 生成占位(ELF 占位匹配期望 ABI + 名称标记).
    for relpath in $_REQUIRED_FILES_v5_3_rc5; do
        src="$HNC_REPO_ROOT/$relpath"
        dst="$d/$relpath"
        mkdir -p "$(dirname "$dst")" 2>/dev/null
        [ -f "$dst" ] && continue
        if [ -f "$src" ]; then
            cp "$src" "$dst"
        else
            case "$relpath" in
                bin/hnc_dpid|bin/hnc_clsact_ctl)
                    if [ "$_httpd_m" = "28 00" ]; then
                        { printf '\177ELF\001\001\001'; dd if=/dev/zero bs=1 count=11 2>/dev/null; printf '\050\000'; printf '\nhnc_dpid\n'; } > "$dst"
                    else
                        { printf '\177ELF\002\001\001'; dd if=/dev/zero bs=1 count=11 2>/dev/null; printf '\267\000'; printf '\nhnc_dpid\n'; } > "$dst"
                    fi
                    chmod 755 "$dst"
                    ;;
                *)
                    echo "# placeholder for $relpath (test fixture)" > "$dst"
                    ;;
            esac
        fi
    done
    (cd "$d" && zip -q -r "$out" .)
}

_rc5_check_prereq() {
    if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        test_skip "zip/unzip unavailable"
        return 1
    fi
    if [ ! -f "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" ]; then
        test_skip "hnc_httpd binary unavailable in source tree"
        return 1
    fi
    _pver=$(awk -F= '$1=="version"{print $2; exit}' "$HNC_REPO_ROOT/module.prop" 2>/dev/null | tr -d '\r')
    _ever=$(_rc5_detect_httpd_ver "$HNC_REPO_ROOT/daemon/hnc_httpd/hnc_httpd" "$_pver")
    if [ -z "$_ever" ]; then
        test_skip "hnc_httpd binary is unversioned dev build"
        return 1
    fi
    return 0
}

test_start "v5.3 rc5 artifact_pick_flashable accepts a direct module ZIP"
_rc5_check_prereq || return
direct="$HNC_TEST_DIR/HNC-v5_3_0-rc5-arm64.zip"
outdir="$HNC_TEST_DIR/picked_direct"
make_minimal_module_zip_rc5 "$direct"
out=$(sh "$HNC_REPO_ROOT/bin/artifact_pick_flashable.sh" "$direct" "$outdir" 2>&1); rc=$?
assert_eq "0" "$rc" "direct module zip should pass artifact picker" || return
assert_contains "$out" 'source ZIP already has module.prop at root' "picker should detect direct flashable zip" || return
assert_contains "$out" 'flashable_artifact=' "picker should print flashable_artifact path" || return
test_pass

test_start "v5.3 rc5 artifact_pick_flashable extracts Actions outer wrapper ZIP"
_rc5_check_prereq || return
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
