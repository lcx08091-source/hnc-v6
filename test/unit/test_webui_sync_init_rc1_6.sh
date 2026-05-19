#!/system/bin/sh
# Static regression check for v5.2-rc1.6 WebUI synchronous init guard.
set -u
ROOT="${HNC_TEST_ROOT:-$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)}"
HTML="$ROOT/webroot/index.html"
PROP="$ROOT/module.prop"
fail=0
ok() { echo "[OK] $1"; }
bad() { echo "[FAIL] $1"; fail=1; }
contains() { LC_ALL=C grep -q "$1" "$HTML" 2>/dev/null; }
not_contains() { ! LC_ALL=C grep -q "$1" "$HTML" 2>/dev/null; }
[ -f "$HTML" ] || { echo "[FAIL] missing webroot/index.html"; exit 1; }
contains "v5.2-rc1.6" && ok "rc1.6 marker exists" || bad "rc1.6 marker missing"
contains "var __hncInitPromise = init();" && ok "init starts synchronously" || bad "init is not started synchronously"
contains "init sync err" && ok "sync init throw path is guarded" || bad "missing sync init throw guard"
contains "document.documentElement.classList.remove('booting');" && ok "booting is removed directly" || bad "missing direct booting removal"
contains "data-boot-finished" && ok "boot finished marker exists" || bad "missing boot finished marker"
not_contains "setTimeout(() => { init().catch" && ok "setTimeout init scheduling removed" || bad "setTimeout init scheduling still exists"
if [ -f "$PROP" ]; then
  # 只检查版本格式合法 (vX.Y.Z-rcN.N), 不硬编码具体版本号
  LC_ALL=C grep -qE 'version=v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+\.[0-9]+' "$PROP" && ok "module.prop version format" || bad "module.prop version format invalid"
  LC_ALL=C grep -qE 'versionCode=[0-9]+' "$PROP" && ok "module.prop versionCode exists" || bad "module.prop versionCode missing"
fi
exit "$fail"
