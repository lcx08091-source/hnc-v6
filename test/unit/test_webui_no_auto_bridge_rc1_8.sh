#!/system/bin/sh
# v5.2-rc1.8 static regression: WebUI must not call KSU bridge automatically during boot.
set -eu
ROOT="${1:-.}"
HTML="$ROOT/webroot/index.html"
[ -f "$HTML" ] || { echo "missing webroot/index.html"; exit 1; }

grep -q "v5.2-rc1.8 · WebUI transport guard" "$HTML" || { echo "missing rc1.8 transport guard"; exit 1; }
grep -q "let __hncAllowBridgeTransport = false" "$HTML" || { echo "bridge transport must default false"; exit 1; }
grep -q "fetchJsonWithTimeout" "$HTML" || { echo "missing fetchJsonWithTimeout"; exit 1; }
grep -q "bridge-force-retry" "$HTML" || { echo "missing explicit bridge-force-retry action"; exit 1; }
grep -q "禁用主 WebUI 内嵌 JSON 健康入口" "$HTML" || { echo "legacy JSON health auto exec not disabled"; exit 1; }

grep -q "重试直连" "$HTML" || { echo "default retry should be direct fetch"; exit 1; }
grep -q "强制桥接" "$HTML" || { echo "advanced bridge opt-in button missing"; exit 1; }

echo "[OK] webui no auto bridge rc1.8"
