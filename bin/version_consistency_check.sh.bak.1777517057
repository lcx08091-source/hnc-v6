#!/system/bin/sh
# HNC version consistency check. Conservative: fails only on obvious stale runtime versions.
set +e
FAIL=0
WARN=0
say(){ printf '%s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); say "[FAIL] $*"; }
warn(){ WARN=$((WARN+1)); say "[WARN] $*"; }
ok(){ say "[OK] $*"; }

[ -f module.prop ] || { fail "module.prop missing"; exit 1; }
VER="$(awk -F= '$1=="version"{print $2; exit}' module.prop)"
VC="$(awk -F= '$1=="versionCode"{print $2; exit}' module.prop)"
say "module.prop: $VER / $VC"

if echo "$VER" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+-hotfix[0-9]+(\.[0-9]+)?$'; then
  ok "module version format looks valid"
else
  warn "module version format is unexpected"
fi
if echo "$VC" | grep -Eq '^[0-9]+$'; then
  ok "versionCode is numeric"
else
  fail "versionCode is not numeric"
fi

if grep -R "hnc_httpd v5\.1\.0-rc1-hotfix4\|hotfix4 starting" -n daemon/hnc_httpd 2>/dev/null | head -20; then
  fail "old hnc_httpd hotfix4 runtime string found"
else
  ok "no hotfix4 runtime string found"
fi

OLD_WEB="$(grep -R "v5\.1\.0-rc1-hotfix1[0-7]" -n webroot 2>/dev/null | grep -v 'changelog' | head -20)"
if [ -n "$OLD_WEB" ]; then
  warn "old WebUI version strings outside changelog:"
  say "$OLD_WEB"
else
  ok "no obvious old WebUI runtime version strings"
fi

say "summary: failures=$FAIL warnings=$WARN"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
