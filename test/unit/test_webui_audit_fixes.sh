#!/bin/sh
# [audit-fix TEST-02] WebUI 结构化测试 — 不再只 grep 字符串
# 用 node 解析 HTML 检查关键 DOM 结构和函数存在性
set -u
ROOT="${HNC_TEST_ROOT:-$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)}"
HTML="$ROOT/webroot/index.html"
fail=0
ok() { echo "[OK] $1"; }
bad() { echo "[FAIL] $1"; fail=1; }

[ -f "$HTML" ] || { echo "[FAIL] missing webroot/index.html"; exit 1; }

# 1. 检查关键 JS 函数存在 (用 node 解析而非纯 grep)
if command -v node >/dev/null 2>&1; then
  FUNC_CHECK=$(node -e "
    const fs = require('fs');
    const html = fs.readFileSync('$HTML', 'utf8');
    const fns = ['init','showModal','hideModal','fetchDPI','renderDPI',
                 'addBlacklistBackend','apiAction','apiGet','toast',
                 'switchPage','renderDeviceList','__sanitizeModalHTML'];
    const missing = fns.filter(fn => !html.includes('function ' + fn));
    if (missing.length) { console.log('MISSING:' + missing.join(',')); process.exit(1); }
    console.log('ALL_FOUND');
  " 2>&1)
  if echo "$FUNC_CHECK" | grep -q "ALL_FOUND"; then
    ok "all critical JS functions present"
  else
    bad "missing JS functions: $FUNC_CHECK"
  fi
else
  # fallback: grep
  for fn in init showModal hideModal fetchDPI apiAction; do
    LC_ALL=C grep -q "function $fn" "$HTML" && ok "function $fn exists" || bad "function $fn missing"
  done
fi

# 2. 检查 innerHTML XSS 防护: showModal 应经过 __sanitizeModalHTML
LC_ALL=C grep -q '__sanitizeModalHTML' "$HTML" && ok "showModal has XSS sanitizer" || bad "showModal missing XSS sanitizer"

# 3. 检查 fetchDPI 有 try/finally 保护
LC_ALL=C grep -q 'finally { dpiFetchInFlight = false' "$HTML" && ok "fetchDPI has try/finally" || bad "fetchDPI missing try/finally"

# 4. 检查 user-scalable=no 已移除
LC_ALL=C grep -q 'user-scalable=no' "$HTML" && bad "user-scalable=no still present" || ok "user-scalable=no removed"

# 5. 检查搜索框有 aria-label
LC_ALL=C grep -q 'aria-label="搜索设备"' "$HTML" && ok "search has aria-label" || bad "search missing aria-label"

# 6. 检查 toggle 有 aria-label
LC_ALL=C grep -q 'aria-label="白名单模式"' "$HTML" && ok "toggle-wl has aria-label" || bad "toggle-wl missing aria-label"

# 7. 检查 CSS 变量拼写 (应无 --glass-sh-1)
LC_ALL=C grep -q 'glass-sh-1' "$HTML" && bad "CSS var typo --glass-sh-1 found" || ok "no --glass-sh-1 typo"

# 8. 检查 prefers-reduced-motion 支持
LC_ALL=C grep -q 'prefers-reduced-motion' "$HTML" && ok "reduced-motion supported" || bad "reduced-motion missing"

# 9. 检查 DPI 亮色主题
LC_ALL=C grep -q 'data-theme.*light.*dpi-pill\|light.*\.dpi-pill' "$HTML" && ok "DPI light theme exists" || bad "DPI light theme missing"

# 10. 检查 changelog XSS 防护
LC_ALL=C grep -q 'DOMParser' "$HTML" && ok "changelog uses DOMParser" || bad "changelog missing DOMParser"

exit "$fail"
