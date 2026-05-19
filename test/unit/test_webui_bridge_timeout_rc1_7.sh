#!/system/bin/sh
# Static regression test for v5.2-rc1.7 WebUI bridge timeout and first-paint guard.
set -eu

ROOT="${1:-.}"
HTML="$ROOT/webroot/index.html"
[ -f "$HTML" ] || { echo "missing webroot/index.html" >&2; exit 1; }

grep -q 'function withTimeout' "$HTML"
grep -q 'withTimeout(kexec(cmd), 8000' "$HTML"
grep -q 'withTimeout(kexec(cmd), 9000' "$HTML"
grep -q 'function renderBarsPlaceholder' "$HTML"
grep -q 'renderBarsPlaceholder' "$HTML"
grep -q 'function waitForFirstPaintBeforeBridge' "$HTML"
grep -q 'await waitForFirstPaintBeforeBridge()' "$HTML"
grep -q 'bridge-status-card' "$HTML"
grep -q 'data-action="bridge-retry"' "$HTML"

# The initial skeleton section must not call renderBars() before health, because renderBars() calls /api/stats.
if awk '/首屏骨架前置/{flag=1} /health 不通时跳过数据拉取/{flag=0} flag{print}' "$HTML" | grep -q 'renderBars();'; then
  echo "renderBars() must not run before health in rc1.7 skeleton" >&2
  exit 1
fi

# init must remain synchronous, not setTimeout(() => init()).
if grep -q 'setTimeout(() => { init()' "$HTML"; then
  echo "init must not be scheduled only by setTimeout" >&2
  exit 1
fi

echo '[OK] webui bridge timeout rc1.7 static'
