#!/system/bin/sh
# hotfix19.2 regression: json_set.sh top_get should prefer hnc_json get-top,
# decode JSON string literals back to the historical unquoted output format,
# and preserve legacy fallback when hnc_json is unavailable.

set -eu

ROOT="${HNC_TEST_ROOT:-/tmp/hnc-json-set-top-get-bridge-$$}"
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
{"version":1,"hotspot_ssid":"我家,客房} \\\"x\\\" \\\\ test","whitelist_mode":true,"speed_factor":0.85,"optional_value":null,"devices":{},"blacklist":[]}
JSON

ssid=$(sh "$ROOT/bin/json_set.sh" top_get hotspot_ssid)
case "$ssid" in
  *'我家,客房}'*'"x"'*'\ test'*) : ;;
  *) echo "top_get ssid mismatch: $ssid" >&2; exit 1 ;;
esac

wm=$(sh "$ROOT/bin/json_set.sh" top_get whitelist_mode)
[ "$wm" = "true" ] || { echo "whitelist_mode mismatch: $wm" >&2; exit 1; }

sf=$(sh "$ROOT/bin/json_set.sh" top_get speed_factor)
[ "$sf" = "0.85" ] || { echo "speed_factor mismatch: $sf" >&2; exit 1; }

ov=$(sh "$ROOT/bin/json_set.sh" top_get optional_value)
[ "$ov" = "null" ] || { echo "optional_value mismatch: $ov" >&2; exit 1; }

# Verify legacy fallback still works when hnc_json is missing.
mv "$ROOT/bin/hnc_json" "$ROOT/bin/hnc_json.off"
fallback=$(sh "$ROOT/bin/json_set.sh" top_get whitelist_mode 2>/dev/null)
[ "$fallback" = "true" ] || { echo "fallback mismatch: $fallback" >&2; exit 1; }

rm -rf "$ROOT"
echo "PASS test_json_set_top_get_hnc_json_bridge"
