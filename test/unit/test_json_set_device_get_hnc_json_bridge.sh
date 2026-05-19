#!/usr/bin/env sh
set -eu

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP="${TMPDIR:-/tmp}/hnc-json-device-get-test-$$"
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/hnc/data" "$TMP/hnc/run" "$TMP/bin"

cat > "$TMP/hnc/data/rules.json" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{"aa:bb:cc:dd:ee:ff":{"mark_id":32,"note":"hello, brace } comma, quote \" 中文","limit_enabled":true,"down_mbps":0.75}},"blacklist":[]}
JSON

cat > "$TMP/bin/hnc_json_exec" <<EOF2
#!/usr/bin/env sh
exec sh "$ROOT/bin/hnc_json" "\$@"
EOF2
chmod 755 "$TMP/bin/hnc_json_exec"

out="$(HNC="$TMP/hnc" HNC_SKIP_PATH_HARDENING=1 HNC_JSON="$TMP/bin/hnc_json_exec" sh "$ROOT/bin/json_set.sh" device_get aa:bb:cc:dd:ee:ff mark_id)"
[ "$out" = "32" ] || { echo "mark_id mismatch: $out" >&2; exit 1; }

out="$(HNC="$TMP/hnc" HNC_SKIP_PATH_HARDENING=1 HNC_JSON="$TMP/bin/hnc_json_exec" sh "$ROOT/bin/json_set.sh" device_get aa:bb:cc:dd:ee:ff limit_enabled)"
[ "$out" = "true" ] || { echo "bool mismatch: $out" >&2; exit 1; }

out="$(HNC="$TMP/hnc" HNC_SKIP_PATH_HARDENING=1 HNC_JSON="$TMP/bin/hnc_json_exec" sh "$ROOT/bin/json_set.sh" device_get aa:bb:cc:dd:ee:ff down_mbps)"
[ "$out" = "0.75" ] || { echo "number mismatch: $out" >&2; exit 1; }

out="$(HNC="$TMP/hnc" HNC_SKIP_PATH_HARDENING=1 HNC_JSON="$TMP/bin/hnc_json_exec" sh "$ROOT/bin/json_set.sh" device_get aa:bb:cc:dd:ee:ff note)"
case "$out" in
  *"brace } comma, quote"*"中文"*) : ;;
  *) echo "string mismatch: $out" >&2; exit 1 ;;
esac

raw="$(sh "$ROOT/bin/hnc_json" get-device "$TMP/hnc/data/rules.json" aa:bb:cc:dd:ee:ff note)"
case "$raw" in
  '"'*) : ;;
  *) echo "hnc_json get-device should return JSON literal, got: $raw" >&2; exit 1 ;;
esac

echo "PASS: json_set device_get hnc_json bridge"
