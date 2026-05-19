#!/system/bin/sh
# v5.2-rc1.9 static regression: WebUI delayed auto bridge after first paint.
set -eu
ROOT="${1:-.}"
HTML="$ROOT/webroot/index.html"
PROP="$ROOT/module.prop"
[ -f "$HTML" ] || { echo "FAIL: missing webroot/index.html"; exit 1; }
[ -f "$PROP" ] || { echo "FAIL: missing module.prop"; exit 1; }

grep -q 'version=v5.2.0-rc1.9' "$PROP" || { echo "FAIL: module.prop version not rc1.9"; exit 1; }
grep -q 'versionCode=520019' "$PROP" || { echo "FAIL: module.prop versionCode not 520019"; exit 1; }

grep -q 'tryDelayedAutoBridgeHealth' "$HTML" || { echo "FAIL: missing delayed auto bridge helper"; exit 1; }
grep -q '__hncAutoBridgeAttempted' "$HTML" || { echo "FAIL: missing one-shot auto bridge guard"; exit 1; }
grep -q 'sleepMs(1200)' "$HTML" || { echo "FAIL: missing 1.2s delayed bridge wait"; exit 1; }
grep -q "__hncEnableBridgeTransport('auto-delayed')" "$HTML" || { echo "FAIL: missing auto delayed bridge enable"; exit 1; }
grep -q "__hncEnableBridgeTransport('manual-force')" "$HTML" || { echo "FAIL: missing manual force bridge path"; exit 1; }
grep -q '__hncPreferBridgeTransport' "$HTML" || { echo "FAIL: missing bridge preference after success"; exit 1; }
grep -q 'HTTP 直连失败，准备自动桥接' "$HTML" || { echo "FAIL: missing visible auto bridge status"; exit 1; }
grep -q '首屏已经完成渲染；先尝试 WebView HTTP 直连' "$HTML" || { echo "FAIL: missing first-paint safe status message"; exit 1; }

# Should keep rc1.8 safety: no bridge before initial skeleton render.
line_skeleton=$(grep -n 'renderDeviceList();   // 空骨架' "$HTML" | head -1 | cut -d: -f1)
line_auto=$(grep -n 'tryDelayedAutoBridgeHealth' "$HTML" | tail -1 | cut -d: -f1)
[ -n "$line_skeleton" ] && [ -n "$line_auto" ] || { echo "FAIL: cannot locate skeleton/auto bridge lines"; exit 1; }
[ "$line_skeleton" -lt "$line_auto" ] || { echo "FAIL: auto bridge appears before skeleton render"; exit 1; }

echo "[OK] webui delayed auto bridge rc1.9 static"
