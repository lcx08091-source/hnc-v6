#!/system/bin/sh
failures=0
warnings=0
ok() { echo "[OK] $*"; }
warn() { warnings=$((warnings + 1)); echo "[WARN] $*"; }
fail() { failures=$((failures + 1)); echo "[FAIL] $*"; }
MODULE_PROP="module.prop"
if [ ! -f "$MODULE_PROP" ]; then
  fail "module.prop not found"
else
  VERSION="$(sed -n 's/^version=//p' "$MODULE_PROP" | head -1)"
  VERSION_CODE="$(sed -n 's/^versionCode=//p' "$MODULE_PROP" | head -1)"
  echo "module.prop: $VERSION / $VERSION_CODE"
  # v5.9.0: 正则与 bin/ci_preflight.sh 统一为同一表达式(此前两处各写一份且
  # 互相矛盾:这里强制 -hotfix、那里强制 -rc + -hf,v5.8.9-portal 手工发布
  # 正好从两条缝里穿过)。不匹配从 warn 升级为 fail —— 版本格式是发布护栏,
  # 不是建议。接受:
  #   v5.9.0                       (正式版, 三段, 无后缀)
  #   v5.3.0-rc30 / -rc30.12 / -rc30.12.18 / -rc30.12.18.1  (rc 一至四段)
  #   v5.1.0-rc1-hotfix17.3        (rc + hotfix 旧风格)
  #   v5.3.0-rc30.12-hf2           (rc + hf 新风格)
  #   v5.9.0-hotfix1               (正式版 + hotfix)
  if printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+(\.[0-9]+){0,3})?(-(hotfix|hf)[0-9]+(\.[0-9]+)?)?$'; then ok "module version format is accepted"; else fail "module version format is unexpected: $VERSION"; fi
  if printf '%s\n' "$VERSION_CODE" | grep -Eq '^[0-9]+$'; then ok "versionCode is numeric"; else fail "versionCode is not numeric"; fi
fi
if [ -f daemon/hnc_httpd/hnc_httpd ]; then
  OLD_HTTPD_HITS="$(grep -aInE 'hnc_httpd v5\.1\.0-rc1-hotfix4|v5\.1\.0-rc1-hotfix4|hotfix4 starting|main\.version=v5\.1\.0-rc1-hotfix4' daemon/hnc_httpd/hnc_httpd 2>/dev/null | head -20 || true)"
  if [ -n "$OLD_HTTPD_HITS" ]; then printf '%s\n' "$OLD_HTTPD_HITS"; fail "old hnc_httpd hotfix4 runtime string found"; else ok "no hotfix4 runtime string found"; fi
else
  warn "daemon/hnc_httpd/hnc_httpd not found"
fi
if [ -d webroot ]; then
  OLD_WEBUI_HITS="$(grep -RIna --binary-files=text -E 'v5\.1\.0-rc1-hotfix(4|10|16\.7|17\.3)' webroot 2>/dev/null | grep -vE 'webroot/changelog\.html|webroot/json-health\.html' | head -20 || true)"
  if [ -n "$OLD_WEBUI_HITS" ]; then printf '%s\n' "$OLD_WEBUI_HITS"; fail "obvious old WebUI runtime version strings found"; else ok "no obvious old WebUI runtime version strings"; fi
else
  warn "webroot not found"
fi
# ── v5.9.3 · BUG-015 C: 文档版本占位符残留检查 ─────────────────
# bin/inject_version_to_docs.sh 负责把 README/ARCHITECTURE 里的 {{VERSION}} /
# {{DATE}} 换成 module.prop 的真实版本,脚本写好很久但一直没接进 CI,而
# README 又没被排除出刷机 zip → 用户装机看到的版本栏就是字面 {{VERSION}}。
# 这里是护栏的另一侧(注入那一侧由 CI 步骤负责,本脚本不做替换):
#   打包/发布路径 → fail(拦住带占位符的包出门)
#   平时/本地开发 → warn(仓库里保留占位符是正常状态,注入只发生在打包步,
#                        结果不 commit 回仓库 —— 一旦 commit,下次 inject 会
#                        走 noop 分支,版本号从此永久锁死在某个旧版)
# "打包/发布路径"判定: 只认显式的 HNC_RELEASE_CHECK=1。
# 刻意不拿 GITHUB_REF=refs/tags/v* 自动升级成 fail —— 本步骤在 build.yml 里
# 排在打包之前, 而注入发生在打包步骤, tag 构建跑到这里时占位符本来就还在,
# 自动 fail 会把"步骤顺序"误报成"文档没注入", 直接卡死发布。
# 接 CI 的正确姿势: 在 inject_version_to_docs.sh 之后再调一次本脚本(或
# 直接调 inject --check), 那一次带 HNC_RELEASE_CHECK=1, 严格拦。
# 扫描目标与 inject 脚本的 DOC_FILES 保持同步(能读到就直接取它的清单,
# 读不到再退回硬编码),避免两处清单各写一份又互相漂移。
# 注意只扫这份清单: inject 脚本自身、分诊/变更记录里的 {{VERSION}} 是正常文本。
INJECT_SH="bin/inject_version_to_docs.sh"
PLACEHOLDER_DOCS=""
if [ -f "$INJECT_SH" ]; then
  PLACEHOLDER_DOCS="$(sed -n '/^DOC_FILES="/,/^"$/p' "$INJECT_SH" 2>/dev/null | grep -E '^[A-Za-z0-9_./-]+\.md$' | tr '\n' ' ')"
fi
PLACEHOLDER_DOCS="$(printf '%s' "$PLACEHOLDER_DOCS" | sed 's/[[:space:]]*$//')"
[ -n "$PLACEHOLDER_DOCS" ] || PLACEHOLDER_DOCS="README.md ARCHITECTURE.md"
RELEASE_PATH=0
[ "${HNC_RELEASE_CHECK:-0}" = "1" ] && RELEASE_PATH=1
# tag 构建但没置该变量: 只在 warn 文案里点一句, 不改判定
TAG_BUILD=0
case "${GITHUB_REF:-}" in refs/tags/v*) TAG_BUILD=1 ;; esac
PLACEHOLDER_HITS=""
for d in $PLACEHOLDER_DOCS; do
  [ -f "$d" ] || continue
  if grep -qE '\{\{(VERSION|DATE)\}\}' "$d" 2>/dev/null; then
    PLACEHOLDER_HITS="$PLACEHOLDER_HITS $d"
  fi
done
if [ -n "$PLACEHOLDER_HITS" ]; then
  if [ "$RELEASE_PATH" = "1" ]; then
    fail "unresolved {{VERSION}}/{{DATE}} placeholders on release path:$PLACEHOLDER_HITS (run 'sh bin/inject_version_to_docs.sh' before packaging)"
  else
    HINT="expected in-tree; injected at packaging time by bin/inject_version_to_docs.sh"
    [ "$TAG_BUILD" = "1" ] && HINT="$HINT; tag build detected — re-run this check with HNC_RELEASE_CHECK=1 AFTER the inject step to hard-fail"
    warn "unresolved {{VERSION}}/{{DATE}} placeholders:$PLACEHOLDER_HITS ($HINT)"
  fi
else
  ok "no unresolved doc version placeholders ($PLACEHOLDER_DOCS)"
fi
echo "summary: failures=$failures warnings=$warnings"
[ "$failures" -gt 0 ] && exit 1
exit 0
