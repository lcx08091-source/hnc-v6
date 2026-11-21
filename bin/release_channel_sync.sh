#!/system/bin/sh
# bin/release_channel_sync.sh — HNC v6.1+ 源码仓一键清理与测试通道同步助手
# 在 Termux 家目录 ~/hnc-v6 解压覆盖包后执行:
#   sh bin/release_channel_sync.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MOD_VER="$(sed -n 's/^version=//p' module.prop | head -1 | tr -d ' \\r\\n')"
MOD_VC="$(sed -n 's/^versionCode=//p' module.prop | head -1 | tr -d ' \\r\\n')"
if [ -z "$MOD_VER" ] || [ -z "$MOD_VC" ]; then
    echo "[FAIL] 无法从 module.prop 读取 version / versionCode" >&2
    exit 1
fi
echo "[SYNC] 目标版本: $MOD_VER (versionCode=$MOD_VC)"

# 1. 移除历史遗留的 LICENSE.TODO
if [ -f LICENSE.TODO ]; then
    rm -f LICENSE.TODO
    echo "[OK] 已移除遗留草稿 LICENSE.TODO (正式 LICENSE 已就位)"
fi

# 2. 同步 Go 源码兜底版本号(仅改精确字面量, 严格保留 0.5.4- 前缀契约)
DPID_TAG="0.5.4-${MOD_VER}"
if [ -d src/dpid ]; then
    find src/dpid -type f -name '*.go' ! -name '*_test.go' | while IFS= read -r gf; do
        if grep -Fq '0.5.4-rc30.12.5-v600-vectorsplt' "$gf" 2>/dev/null; then
            sed "s~0\\.5\\.4-rc30\\.12\\.5-v600-vectorsplt~$DPID_TAG~g" "$gf" > "$gf.tmp.$$" && mv -f "$gf.tmp.$$" "$gf"
            echo "[OK] 已同步 dpid 内部标识 -> $DPID_TAG ($gf)"
        fi
    done
fi
if [ -d daemon/hnc_httpd ]; then
    find daemon/hnc_httpd -type f -name '*.go' ! -name '*_test.go' | while IFS= read -r hf; do
        if grep -Eq 'version[[:space:]]*=[[:space:]]*"v6\\.0\\.[01]"' "$hf" 2>/dev/null; then
            sed -e "s~\\(version[[:space:]]*=[[:space:]]*\\)\"v6\\.0\\.[01]\"~\\1\"$MOD_VER\"~g" \
                -e "s~\\(versionCode[[:space:]]*=[[:space:]]*\\)\"600000[01]\"~\\1\"$MOD_VC\"~g" \
                "$hf" > "$hf.tmp.$$" && mv -f "$hf.tmp.$$" "$hf"
            echo "[OK] 已同步 hnc_httpd 源码默认兜底版本 -> $MOD_VER ($hf)"
        fi
    done
fi

# 3. 若存在 GitHub Actions 工作流且装有 python3, 补齐预发布 prerelease 保护与 *.TODO 排除
WF=".github/workflows/build.yml"
if [ -f "$WF" ] && command -v python3 >/dev/null 2>&1; then
    MOD_VER="$MOD_VER" python3 - "$WF" <<'PYEOF'
import re, sys

wf_path = sys.argv[1]
with open(wf_path, "r", encoding="utf-8") as f:
    txt = f.read()
orig = txt

def patch_zip_line(m):
    line = m.group(0)
    if "*.TODO" in line or "LICENSE.TODO" in line:
        return line
    return line + " '*.TODO'"

txt = re.sub(r"zip\s+-r[0-9a-zA-Z-]*\s+\S+\s+\S+\s+-x[^\n]*", patch_zip_line, txt)

if "softprops/action-gh-release" in txt and "prerelease:" not in txt:
    txt = re.sub(
        r"(uses:\s*softprops/action-gh-release@[^\n]+\n(?:\s+if:[^\n]+\n)?\s+with:\n)",
        r"\1          prerelease: ${{ contains(env.MOD_VER, '-alpha') || contains(env.MOD_VER, '-beta') || contains(env.MOD_VER, '-rc') || contains(github.ref_name, '-alpha') || contains(github.ref_name, '-beta') || contains(github.ref_name, '-rc') }}\n"
        r"          make_latest: ${{ !(contains(env.MOD_VER, '-alpha') || contains(env.MOD_VER, '-beta') || contains(env.MOD_VER, '-rc') || contains(github.ref_name, '-alpha') || contains(github.ref_name, '-beta') || contains(github.ref_name, '-rc')) }}\n",
        txt,
        count=1,
    )

if "gh release create" in txt and "--prerelease" not in txt:
    txt = txt.replace(
        "gh release create ",
        'PRE_FLAGS=""; case "$MOD_VER" in *-alpha*|*-beta*|*-rc*) PRE_FLAGS="--prerelease --latest=false" ;; esac; gh release create $PRE_FLAGS ',
    )

if txt != orig:
    with open(wf_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt)
    print("[OK] 已加固 .github/workflows/build.yml (预发布 prerelease 隔离 + *.TODO 排除)")
else:
    print("[OK] .github/workflows/build.yml 已具备预发布保护或无需改动")
PYEOF
fi

# 4. 恢复全部脚本 0755 权限
chmod 755 ./*.sh bin/*.sh 2>/dev/null || true
for d in daemon/* src/launcher tools; do
    [ -d "$d" ] || continue
    for s in "$d"/*.sh; do
        [ -f "$s" ] && chmod 755 "$s" 2>/dev/null || true
    done
done

# 5. 执行双门禁自检
echo "[CHECK] 运行 bin/version_consistency_check.sh ..."
sh bin/version_consistency_check.sh
echo "[CHECK] 运行 bin/ci_preflight.sh ..."
sh bin/ci_preflight.sh
echo "[DONE] $MOD_VER ($MOD_VC) 净屋换牌校验全绿，可直接 git add -A && git commit && git push origin main"
