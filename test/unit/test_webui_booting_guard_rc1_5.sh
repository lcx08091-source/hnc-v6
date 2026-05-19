#!/system/bin/sh
# Static regression check for v5.2-rc1.5 WebUI booting guard.
set -u
ROOT="${HNC_TEST_ROOT:-$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)}"
HTML="$ROOT/webroot/index.html"
fail=0
check() {
  if grep -q "$1" "$HTML" 2>/dev/null; then
    echo "[OK] $2"
  else
    echo "[FAIL] $2"
    fail=1
  fi
}
[ -f "$HTML" ] || { echo "[FAIL] missing webroot/index.html"; exit 1; }
check "function finishBootVisual" "finishBootVisual exists"
check "booting fallback timeout" "fallback timeout exists"
check "finishBootVisual();" "finishBootVisual is called"
check "WebUI booting 状态兜底" "booting guard comment exists"
check "booting 可视兜底" "booting visible fallback CSS exists"
exit "$fail"
