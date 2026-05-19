#!/system/bin/sh
# hotfix20.2 regression test: optional hnc_json_c read-only bridge
set -eu

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
HNC_JSON="$ROOT/bin/hnc_json"
BUILD="$ROOT/daemon/hotspotd/tools/build_hnc_json.sh"
TMP="${TMPDIR:-/tmp}/hnc_json_c_bridge_$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

fail(){ echo "FAIL: $*" >&2; exit 1; }

cat > "$TMP/a.json" <<'JSON'
{"hotspot_ssid":"我家,客房}","enabled":true,"n":123,"obj":{"x":1}}
JSON
cat > "$TMP/bad.json" <<'JSON'
{"a":"unterminated}
JSON

# Shell fallback must work even when the C helper is absent or disabled.
HNC_JSON_C_DISABLE=1 "$HNC_JSON" validate "$TMP/a.json" || fail "shell fallback validate failed"
v="$(HNC_JSON_C_DISABLE=1 "$HNC_JSON" get-top "$TMP/a.json" hotspot_ssid)" || fail "shell fallback get-top failed"
case "$v" in '"我家,客房}"') : ;; *) fail "bad fallback get-top value: $v" ;; esac
if HNC_JSON_C_DISABLE=1 "$HNC_JSON" validate "$TMP/bad.json"; then
  fail "shell fallback accepted bad JSON"
fi

# If a compiler is available, build and exercise the optional C helper.
if command -v cc >/dev/null 2>&1; then
  CC=cc sh "$BUILD" "$TMP/hnc_json_c" >/dev/null || fail "C helper build failed"
elif command -v clang >/dev/null 2>&1; then
  CC=clang sh "$BUILD" "$TMP/hnc_json_c" >/dev/null || fail "C helper build failed"
else
  echo "[SKIP] no C compiler available; shell fallback tested"
  echo "[OK] hnc_json C bridge regression passed"
  exit 0
fi

cp "$TMP/hnc_json_c" "$ROOT/bin/hnc_json_c.test"
chmod 755 "$ROOT/bin/hnc_json_c.test"
# Point the frontend at the test helper by temporarily copying it to the runtime name.
rm -f "$ROOT/bin/hnc_json_c"
cp "$TMP/hnc_json_c" "$ROOT/bin/hnc_json_c"
chmod 755 "$ROOT/bin/hnc_json_c"
trap 'rm -f "$ROOT/bin/hnc_json_c" "$ROOT/bin/hnc_json_c.test"; rm -rf "$TMP"' EXIT

"$HNC_JSON" validate "$TMP/a.json" || fail "C bridge validate failed"
v="$("$HNC_JSON" get-top "$TMP/a.json" n)" || fail "C bridge get-top n failed"
[ "$v" = "123" ] || fail "bad C bridge get-top n: $v"
v="$("$HNC_JSON" get-top "$TMP/a.json" obj)" || fail "C bridge get-top obj failed"
case "$v" in '{"x":1}') : ;; *) fail "bad C bridge get-top obj: $v" ;; esac
if "$HNC_JSON" validate "$TMP/bad.json"; then
  fail "C bridge accepted bad JSON"
fi

rm -f "$ROOT/bin/hnc_json_c"
echo "[OK] hnc_json C bridge regression passed"
