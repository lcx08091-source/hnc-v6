#!/system/bin/sh
# test/unit/test_v533_ci_emulation.sh — 在「没有 /system/bin/sh」的环境里跑 CI 的 shell 步骤。
#
# GitHub 的 Linux runner 没有 /system/bin/sh, 真机运行期 /system/bin 也可能被卸(SukiSU);
# 本机容器却有(环境准备时装的), 所以「脚本靠 shebang 直接执行另一个脚本」在本地全绿、
# 推 main 才挂(rc2 首推: json_set.sh 直接执行 hnc_json → rc 127, ci_preflight 失败)。
# 这里把仓库拷一份, 所有 #!/system/bin/sh 改成不存在的 #!/nonexistent/sh, 再按
# .github/workflows/build.yml 的顺序跑构建前的 shell 步骤:
#   version_consistency_check → ci_preflight(含 json_regression_test、pitfall lint)
#   → inject_version_to_docs + --check
# 「改动前会失败」: 在 rc2 首推的那版(json_set.sh 的 hj() 直接执行 "$HNC_JSON")上
# ci_preflight 报 rc=127 失败。

R="$HNC_REPO_ROOT"
# 拷贝树放在 HNC_TEST_DIR 旁边(test_start 每次都会清空 HNC_TEST_DIR), 文件末尾删掉
T="${HNC_TEST_DIR}.ci"
rm -rf "$T"; mkdir -p "$T/.logs"

# 拷入库的文件(加上还没 add 的新文件); 没有 git(真机)就整个拷。third_party 不参与这些步骤。
if command -v git >/dev/null 2>&1 && git -C "$R" rev-parse --git-dir >/dev/null 2>&1; then
    (cd "$R" && git ls-files -co --exclude-standard | grep -v '^third_party/' | while IFS= read -r f; do
        [ -f "$f" ] || continue
        mkdir -p "$T/$(dirname "$f")" && cp -p "$f" "$T/$f"
    done)
else
    cp -rp "$R/." "$T/"
    rm -rf "$T/.git" "$T/third_party"
fi

# 所有 /system/bin/sh 的 shebang → 不存在的解释器
n=0
for f in $(find "$T" -type f \( -name '*.sh' -o -path "$T/bin/*" \)); do
    first=$(head -n1 "$f" 2>/dev/null | tr -d '\000')
    case "$first" in
        '#!/system/bin/sh'*) sed -i '1s|^#!/system/bin/sh|#!/nonexistent/sh|' "$f"; n=$((n + 1)) ;;
    esac
done
# CI 的 "chmod 755 bin/*.sh service.sh post-fs-data.sh"
chmod 755 "$T"/bin/*.sh "$T/service.sh" "$T/post-fs-data.sh" 2>/dev/null

ci_step() { # $1 = 日志名, 其余 = 命令(在拷贝树里跑)
    _log="$T/.logs/$1.log"; shift
    (cd "$T" && "$@") > "$_log" 2>&1
}

test_start "v5.33 CI 模拟: 没有 /system/bin/sh 时 version_consistency_check 通过"
ci_step vcc sh bin/version_consistency_check.sh; rc=$?
if [ "$n" -lt 100 ]; then
    test_fail "只改到 $n 个 shebang(拷贝不全?)"
elif [ "$rc" -ne 0 ]; then
    test_fail "rc=$rc: $(tail -5 "$T/.logs/vcc.log" | tr '\n' ' ')"
else
    test_pass
fi

test_start "v5.33 CI 模拟: 没有 /system/bin/sh 时 ci_preflight(含 JSON 回归、pitfall lint)通过"
ci_step preflight sh bin/ci_preflight.sh; rc=$?
L="$T/.logs/preflight.log"
if [ "$rc" -ne 0 ]; then
    test_fail "rc=$rc: $(grep -E '^\[(FAIL|ERROR)\]' "$L" | head -3 | tr '\n' ' ')"
elif ! grep -q 'json regression test passed' "$L"; then
    test_fail "json_regression_test 没跑到"
elif grep -qE 'rc=12[67]|nonexistent/sh|not found' "$L"; then
    test_fail "日志里有执行失败: $(grep -E 'rc=12[67]|nonexistent/sh|not found' "$L" | head -2 | tr '\n' ' ')"
else
    test_pass
fi

test_start "v5.33 CI 模拟: 没有 /system/bin/sh 时 inject_version_to_docs + --check 通过"
ci_step inject sh -c 'sh bin/inject_version_to_docs.sh && sh bin/inject_version_to_docs.sh --check'; rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc: $(tail -5 "$T/.logs/inject.log" | tr '\n' ' ')"

rm -rf "$T"
