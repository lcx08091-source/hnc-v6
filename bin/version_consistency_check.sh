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
echo "summary: failures=$failures warnings=$warnings"
[ "$failures" -gt 0 ] && exit 1
exit 0
