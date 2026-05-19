#!/system/bin/sh
# Minimal regression tests for bin/hnc_json bootstrap frontend.
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
HNC_JSON="$ROOT/bin/hnc_json"
TMP="${TMPDIR:-/tmp}/hnc_json_test_$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

fail(){ echo "FAIL: $*" >&2; exit 1; }

cat > "$TMP/a.json" <<'JSON'
{"hotspot_ssid":"我家,客房}","enabled":true,"n":123,"s":"quote \" ok"}
JSON

"$HNC_JSON" validate "$TMP/a.json" || fail validate
v="$($HNC_JSON get-top "$TMP/a.json" hotspot_ssid)" || fail get_ssid
case "$v" in '"我家,客房}"') : ;; *) fail "bad hotspot_ssid: $v" ;; esac

cat > "$TMP/bad.json" <<'JSON'
{"a":"unterminated}
JSON
if "$HNC_JSON" validate "$TMP/bad.json"; then
  fail "bad json accepted"
fi

echo "OK test_hnc_json"
