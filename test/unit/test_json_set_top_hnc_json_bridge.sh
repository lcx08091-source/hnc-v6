#!/system/bin/sh
# hotfix19.1 regression: json_set.sh top should safely bridge to hnc_json
# and still preserve JSON when strings contain comma, right-brace, quotes,
# backslashes, Chinese text, booleans, numbers and null.

set -eu

ROOT="${HNC_TEST_ROOT:-/tmp/hnc-json-set-top-bridge-$$}"
mkdir -p "$ROOT/bin" "$ROOT/data" "$ROOT/run"

if [ -x "./bin/json_set.sh" ]; then
  SRC_BIN="./bin"
elif [ -x "../../bin/json_set.sh" ]; then
  SRC_BIN="../../bin"
else
  echo "cannot locate bin/json_set.sh" >&2
  exit 2
fi

cp "$SRC_BIN/json_set.sh" "$ROOT/bin/json_set.sh"
cp "$SRC_BIN/hnc_json" "$ROOT/bin/hnc_json"
[ -x "$SRC_BIN/json_guard.sh" ] && cp "$SRC_BIN/json_guard.sh" "$ROOT/bin/json_guard.sh" || true
chmod 755 "$ROOT/bin"/*.sh "$ROOT/bin/hnc_json" 2>/dev/null || true

export HNC="$ROOT"
export HNC_SKIP_PATH_HARDENING=1
export HNC_TEST_MODE=1

cat > "$ROOT/data/rules.json" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[]}
JSON

sh "$ROOT/bin/json_set.sh" top hotspot_ssid '我家,客房} "x" \\ test'
sh "$ROOT/bin/json_set.sh" top whitelist_mode true
sh "$ROOT/bin/json_set.sh" top speed_factor 0.85
sh "$ROOT/bin/json_set.sh" top optional_value null

sh "$ROOT/bin/hnc_json" validate "$ROOT/data/rules.json"

ssid=$(sh "$ROOT/bin/hnc_json" get-top "$ROOT/data/rules.json" hotspot_ssid)
case "$ssid" in
  *'我家,客房'*'test'*) : ;;
  *) echo "ssid not preserved: $ssid" >&2; exit 1 ;;
esac

wm=$(sh "$ROOT/bin/hnc_json" get-top "$ROOT/data/rules.json" whitelist_mode)
[ "$wm" = "true" ] || { echo "whitelist_mode mismatch: $wm" >&2; exit 1; }

sf=$(sh "$ROOT/bin/hnc_json" get-top "$ROOT/data/rules.json" speed_factor)
[ "$sf" = "0.85" ] || { echo "speed_factor mismatch: $sf" >&2; exit 1; }

ov=$(sh "$ROOT/bin/hnc_json" get-top "$ROOT/data/rules.json" optional_value)
[ "$ov" = "null" ] || { echo "optional_value mismatch: $ov" >&2; exit 1; }

# Verify the legacy fallback still exists by hiding hnc_json for one write.
mv "$ROOT/bin/hnc_json" "$ROOT/bin/hnc_json.off"
sh "$ROOT/bin/json_set.sh" top fallback_name 'fallback,ok}'
if [ -x "$ROOT/bin/json_guard.sh" ]; then
  sh "$ROOT/bin/json_guard.sh" "$ROOT/data/rules.json" >/dev/null 2>&1 || {
    echo "fallback write produced invalid JSON" >&2
    cat "$ROOT/data/rules.json" >&2
    exit 1
  }
fi

rm -rf "$ROOT"
echo "PASS test_json_set_top_hnc_json_bridge"
