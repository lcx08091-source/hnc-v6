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
  # v5.9.0 / v6.1+: 正则与 bin/ci_preflight.sh 统一为同一表达式。
  # 接受:
  #   v6.1.0                       (正式版, 三段, versionCode 整万 XXYY0000)
  #   v6.1.0-alpha.1 / -beta.2 / -rc.1 (v6.1+ 预发布走廊 XXYY9101..XXYY9999)
  #   v5.3.0-rc30 / -rc30.12.18    (历史 rc 一至四段)
  #   v5.9.0-hotfix1 / -hf2        (正式版或 rc + hotfix/hf)
  if printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+(\.[0-9]+){0,3})?(-(hotfix|hf)[0-9]+(\.[0-9]+)?)?$'; then ok "module version format is accepted"; else fail "module version format is unexpected: $VERSION"; fi
  MOD_DESC="$(sed -n '/^description=/{s/^description=//p;q;}' "$MODULE_PROP" | tr -d '\r')"
  DESC_VERS="$(printf '%s\n' "$MOD_DESC" | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*' || true)"
  if [ -n "$DESC_VERS" ]; then
    DESC_BAD=0
    for _dv in $DESC_VERS; do
      [ "$_dv" = "$VERSION" ] || DESC_BAD=1
    done
    if [ "$DESC_BAD" -eq 0 ]; then
      ok "module.prop description embeds exact $VERSION"
    else
      fail "module.prop description version token mismatch (expected $VERSION, got: $DESC_VERS)"
    fi
  fi
  if printf '%s\n' "$VERSION_CODE" | grep -Eq '^[1-9][0-9]{6,8}$'; then
    VC_REM=$(( VERSION_CODE % 10000 ))
    case "$VERSION" in
      *-alpha*)
        if [ "$VC_REM" -ge 9101 ] && [ "$VC_REM" -le 9199 ]; then ok "alpha versionCode corridor valid ($VERSION_CODE)"; else fail "alpha versionCode ($VERSION_CODE) must end in 9101..9199"; fi ;;
      *-beta*)
        if [ "$VC_REM" -ge 9201 ] && [ "$VC_REM" -le 9299 ]; then ok "beta versionCode corridor valid ($VERSION_CODE)"; else fail "beta versionCode ($VERSION_CODE) must end in 9201..9299"; fi ;;
      *-rc*)
        if [ "$VC_REM" -ge 9301 ] && [ "$VC_REM" -le 9999 ]; then ok "rc versionCode corridor valid ($VERSION_CODE)"; else fail "rc versionCode ($VERSION_CODE) must end in 9301..9999"; fi ;;
      *)
        if [ "$VC_REM" -lt 9100 ]; then ok "stable versionCode corridor valid ($VERSION_CODE)"; else fail "stable versionCode ($VERSION_CODE) collides with pre-release corridor >=9100"; fi ;;
    esac
  fi
  VER_BARE="${VERSION#v}"
  if [ -f CHANGELOG.md ]; then
    CL_SEC="$(awk -v ver="$VER_BARE" 'index($0, "## [" ver "]") == 1 {found=1; next} found && /^## \[/ {exit} found {print}' CHANGELOG.md | tr -d ' \t\r\n')"
    if [ -n "$CL_SEC" ]; then ok "CHANGELOG.md has non-empty section for [$VER_BARE]"; else fail "CHANGELOG.md missing or empty section for ## [$VER_BARE]"; fi
  fi
  if [ -f COMPATIBILITY.md ]; then
    COMPAT_VER="$(sed -n 's/^\*\*当前版本\*\*:[[:space:]]*\([^[:space:]]*\).*/\1/p' COMPATIBILITY.md | head -n 1 | tr -d '\r')"
    COMPAT_BODY_VERS="$(grep -Eo 'HNC `v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*`' COMPATIBILITY.md 2>/dev/null | sed 's/^HNC `//;s/`$//' || true)"
    COMPAT_BAD=0
    [ "$COMPAT_VER" = "$VERSION" ] || COMPAT_BAD=1
    for _cv in $COMPAT_BODY_VERS; do
      [ "$_cv" = "$VERSION" ] || COMPAT_BAD=1
    done
    if [ "$COMPAT_BAD" -eq 0 ] && [ -n "$COMPAT_VER" ]; then
      ok "COMPATIBILITY.md matches $VERSION"
    else
      fail "COMPATIBILITY.md version mismatch (expected $VERSION, got '${COMPAT_VER:-missing}')"
    fi
  fi
  if [ -f webroot/changelog.html ]; then
    if grep -Fq "data-version=\"$VERSION\"" webroot/changelog.html; then
      ok "webroot/changelog.html contains $VERSION entry"
      CL_HTML_LINE="$(grep -F "data-version=\"$VERSION\"" webroot/changelog.html | head -n 1)"
      case "$CL_HTML_LINE" in
        *data-version-code=*)
          if printf '%s\n' "$CL_HTML_LINE" | grep -Fq "data-version-code=\"$VERSION_CODE\""; then
            ok "webroot/changelog.html data-version-code matches $VERSION_CODE"
          else
            fail "webroot/changelog.html data-version-code mismatch for $VERSION (expected $VERSION_CODE)"
          fi ;;
      esac
    else
      fail "webroot/changelog.html missing data-version=\"$VERSION\""
    fi
  fi
  if [ -f webroot/json-health.html ]; then
    if grep -Fq "data-ui-ver=\"$VERSION\"" webroot/json-health.html && grep -Fq ">HNC $VERSION</span>" webroot/json-health.html; then
      ok "webroot/json-health.html embeds $VERSION"
    else
      fail "webroot/json-health.html UI version mismatch (expected $VERSION)"
    fi
  fi
  if [ -f data/dpi_ja4_fingerprints.json ]; then
    DFP_VER="$(sed -n 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' data/dpi_ja4_fingerprints.json | head -n 1 | tr -d '\r')"
    if [ "$DFP_VER" = "hnc-dfp-$VERSION" ]; then
      ok "data/dpi_ja4_fingerprints.json matches hnc-dfp-$VERSION"
    else
      fail "data/dpi_ja4_fingerprints.json rules_version mismatch (expected hnc-dfp-$VERSION, got '$DFP_VER')"
    fi
  fi
  if [ -d data/dpi_rules.d ]; then
    _cur_ok=0
    _cur_bad=0
    for _rf in data/dpi_rules.d/*.json; do
      [ -f "$_rf" ] || continue
      _rbn="${_rf##*/}"
      [ "$_rbn" = "46-v2fly-a.json" ] && continue
      _sub="${_rbn%.json}"
      _rv="$(sed -n 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_rf" | head -n 1 | tr -d '\r')"
      if [ "$_rbn" = "00-core-meta.json" ]; then
        _exp_rv="hnc-curated-${VERSION}-dedup#${_sub}"
      else
        _exp_rv="hnc-curated-${VERSION}#${_sub}"
      fi
      if [ "$_rv" = "$_exp_rv" ]; then
        _cur_ok=$((_cur_ok + 1))
      else
        fail "$_rf rules_version mismatch (expected '$_exp_rv', got '$_rv')"
        _cur_bad=$((_cur_bad + 1))
      fi
    done
    if [ "$_cur_bad" -eq 0 ] && [ "$_cur_ok" -gt 0 ]; then
      ok "data/dpi_rules.d curated rules_version matches $VERSION ($_cur_ok files, 46-v2fly-a.json skipped)"
    fi
  fi
  if [ -f webroot/js/settings.js ]; then
    SET_VER="$(sed -n "s/.*HNC_UI_VER[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" webroot/js/settings.js | head -n 1 | tr -d '\r')"
    SET_VC="$(sed -n "s/.*HNC_UI_VC[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" webroot/js/settings.js | head -n 1 | tr -d '\r')"
    if [ "$SET_VER" = "$VERSION" ] && [ "$SET_VC" = "$VERSION_CODE" ]; then
      ok "webroot/js/settings.js matches $VERSION / $VERSION_CODE"
    else
      fail "webroot/js/settings.js version mismatch (expected $VERSION / $VERSION_CODE, got '${SET_VER:-missing}' / '${SET_VC:-missing}')"
    fi
  fi
  if [ -f webroot/js/vector_v6.js ]; then
    VEC_VERS="$(grep -Eo 'HNC v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*' webroot/js/vector_v6.js 2>/dev/null | awk '{print $2}' || true)"
    if [ -n "$VEC_VERS" ]; then
      VEC_BAD=0
      for _vv in $VEC_VERS; do
        [ "$_vv" = "$VERSION" ] || VEC_BAD=1
      done
      if [ "$VEC_BAD" -eq 0 ]; then
        ok "webroot/js/vector_v6.js embeds exact $VERSION"
      else
        fail "webroot/js/vector_v6.js version mismatch (expected $VERSION, got: $(printf '%s' "$VEC_VERS" | tr '\n' ' '))"
      fi
    elif grep -Fq "$VERSION" webroot/js/vector_v6.js; then
      ok "webroot/js/vector_v6.js embeds $VERSION"
    else
      fail "webroot/js/vector_v6.js missing current version $VERSION"
    fi
  fi
  if [ -f tools/ui_mock/fake_api.js ]; then
    FAKE_VER="$(sed -n "s/.*META\.version[[:space:]]*:[[:space:]]*'\([^']*\)'.*/\1/p" tools/ui_mock/fake_api.js | head -n 1 | tr -d '\r')"
    FAKE_VC="$(sed -n "s/.*META\.versionCode[[:space:]]*||[[:space:]]*'\([^']*\)'.*/\1/p" tools/ui_mock/fake_api.js | head -n 1 | tr -d '\r')"
    FAKE_STALE="$(grep -Eo 'hnc-curated-v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?' tools/ui_mock/fake_api.js 2>/dev/null | sed 's/-dedup$//' | grep -vxF "hnc-curated-$VERSION" | head -n 1 || true)"
    if [ "$FAKE_VER" = "$VERSION" ] && [ "$FAKE_VC" = "$VERSION_CODE" ] && [ -z "$FAKE_STALE" ]; then
      ok "tools/ui_mock/fake_api.js matches $VERSION / $VERSION_CODE"
    else
      fail "tools/ui_mock/fake_api.js version mismatch (expected $VERSION / $VERSION_CODE, got '${FAKE_VER:-missing}' / '${FAKE_VC:-missing}'${FAKE_STALE:+, stale '$FAKE_STALE'})"
    fi
  fi
  if [ ! -f update.json ]; then
    fail "update.json not found"
  else
    UPD_VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' update.json | head -n 1 | tr -d '\r')"
    UPD_VC="$(sed -n 's/.*"versionCode"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' update.json | head -n 1 | tr -d '\r')"
    UPD_ZIP="$(sed -n 's/.*"zipUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' update.json | head -n 1 | tr -d '\r')"
    UPD_CL="$(sed -n 's/.*"changelog"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' update.json | head -n 1 | tr -d '\r')"
    case "$VERSION" in
      *-alpha*|*-beta*|*-rc*)
        UPD_BAD=0
        if [ -z "$UPD_VER" ]; then
          fail "update.json version is empty during pre-release"
          UPD_BAD=1
        else
          case "$UPD_VER" in
            *-alpha*|*-beta*|*-rc*)
              fail "update.json points to pre-release $UPD_VER; keep update.json frozen on latest stable during alpha/beta/rc"
              UPD_BAD=1 ;;
          esac
        fi
        case "$UPD_ZIP" in
          *-alpha*|*-beta*|*-rc*)
            fail "update.json zipUrl points to pre-release artifact: $UPD_ZIP"
            UPD_BAD=1 ;;
        esac
        case "$UPD_CL" in
          *-alpha*|*-beta*|*-rc*)
            fail "update.json changelog points to pre-release ref: $UPD_CL"
            UPD_BAD=1 ;;
        esac
        if [ -z "$UPD_VC" ] || ! printf '%s\n' "$UPD_VC" | grep -Eq '^[1-9][0-9]*$'; then
          fail "update.json versionCode is missing or non-numeric: '$UPD_VC'"
          UPD_BAD=1
        else
          UPD_VC_REM=$(( UPD_VC % 10000 ))
          if [ "$UPD_VC_REM" -ge 9100 ]; then
            fail "update.json versionCode ($UPD_VC) collides with pre-release corridor (% 10000 = $UPD_VC_REM >= 9100)"
            UPD_BAD=1
          fi
          if [ -z "$VERSION_CODE" ] || ! [ "$UPD_VC" -lt "$VERSION_CODE" ] 2>/dev/null; then
            fail "update.json versionCode ($UPD_VC) must stay below pre-release ($VERSION_CODE)"
            UPD_BAD=1
          fi
        fi
        if [ "$UPD_BAD" -eq 0 ]; then
          ok "pre-release OTA guard: update.json stays pinned on stable ($UPD_VER / $UPD_VC < $VERSION_CODE)"
        fi ;;
      *)
        UPD_BAD=0
        VER_SAFE="$(printf '%s' "$VERSION" | tr '.+' '__')"
        case "$UPD_ZIP" in
          *-alpha*|*-beta*|*-rc*)
            fail "update.json zipUrl points to pre-release artifact on stable release: $UPD_ZIP"
            UPD_BAD=1 ;;
        esac
        case "$UPD_ZIP" in
          https://*/releases/download/"$VERSION"/HNC-"$VER_SAFE"-arm64.zip) ;;
          *)
            fail "update.json zipUrl must target https://.../releases/download/$VERSION/HNC-${VER_SAFE}-arm64.zip (got: '$UPD_ZIP')"
            UPD_BAD=1 ;;
        esac
        case "$UPD_CL" in
          *-alpha*|*-beta*|*-rc*)
            fail "update.json changelog points to pre-release ref on stable release: $UPD_CL"
            UPD_BAD=1 ;;
        esac
        case "$UPD_CL" in
          https://*/"$VERSION"/CHANGELOG.md) ;;
          *)
            fail "update.json changelog must target https://.../$VERSION/CHANGELOG.md (got: '$UPD_CL')"
            UPD_BAD=1 ;;
        esac
        if [ -z "$UPD_VC" ] || ! printf '%s\n' "$UPD_VC" | grep -Eq '^[1-9][0-9]*$' || [ "$UPD_VC" -le 6000001 ]; then
          fail "stable update.json versionCode ($UPD_VC) must be > 6000001"
          UPD_BAD=1
        fi
        if [ -n "$UPD_VER" ] && [ "$UPD_VER" = "$VERSION" ] && [ "$UPD_VC" = "$VERSION_CODE" ]; then
          [ "$UPD_BAD" -eq 0 ] && ok "update.json matches stable release ($UPD_VER / $UPD_VC, url verified)"
        else
          fail "stable module.prop ($VERSION / $VERSION_CODE) differs from update.json ($UPD_VER / $UPD_VC)"
        fi ;;
    esac
  fi
  if printf '%s\n' "$VERSION_CODE" | grep -Eq '^[0-9]+$'; then ok "versionCode is numeric"; else fail "versionCode is not numeric"; fi
fi
if [ -f daemon/hnc_httpd/hnc_httpd ]; then
  OLD_HTTPD_HITS="$(grep -aInE 'hnc_httpd v5\.1\.0-rc1-hotfix4|v5\.1\.0-rc1-hotfix4|hotfix4 starting|main\.version=v5\.1\.0-rc1-hotfix4' daemon/hnc_httpd/hnc_httpd 2>/dev/null | head -20 || true)"
  if [ -n "$OLD_HTTPD_HITS" ]; then printf '%s\n' "$OLD_HTTPD_HITS"; fail "old hnc_httpd hotfix4 runtime string found"; else ok "no hotfix4 runtime string found"; fi
else
  warn "daemon/hnc_httpd/hnc_httpd not found"
fi
if [ "${HNC_RELEASE_CHECK:-0}" = "1" ] && [ -n "${VERSION:-}" ]; then
  for _rbin in daemon/hnc_httpd/hnc_httpd bin/hnc_dpid bin/hnc_watchdog bin/hnc_launcher bin/hotspotd bin/hnc_clsact_ctl bin/mdns_resolve bin/hnc_ipc; do
    if [ -f "$_rbin" ]; then
      if grep -a -qF "$VERSION" "$_rbin" 2>/dev/null; then
        ok "$_rbin embeds $VERSION"
      else
        fail "$_rbin missing module version $VERSION"
      fi
    fi
  done
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
