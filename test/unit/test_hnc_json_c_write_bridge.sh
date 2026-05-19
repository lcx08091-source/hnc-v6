#!/bin/sh
# hotfix20.5/20.6/20.7 regression test: optional hnc_json_c write bridge.
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
BUILD="$ROOT/daemon/hotspotd/tools/build_hnc_json.sh"
TMPBASE="${TMPDIR:-$ROOT/.tmp}"
TMP="$TMPBASE/hnc_json_c_write_bridge_$$"
BUILT="$TMP/hnc_json_c"
mkdir -p "$TMPBASE" "$TMP"
cleanup() { rm -rf "$TMP"; rm -f "$ROOT/bin/hnc_json_c"; }
trap cleanup EXIT INT TERM

fail() { echo "[FAIL] $*" >&2; exit 1; }

if command -v cc >/dev/null 2>&1; then
  cc -Os -Wall -Wextra -Werror -o "$BUILT" "$ROOT/daemon/hotspotd/tools/hnc_json.c" || fail "C helper build failed"
  cp "$BUILT" "$ROOT/bin/hnc_json_c" || fail "C helper copy failed"
  chmod 755 "$ROOT/bin/hnc_json_c"
elif command -v clang >/dev/null 2>&1; then
  clang -Os -Wall -Wextra -Werror -o "$BUILT" "$ROOT/daemon/hotspotd/tools/hnc_json.c" || fail "C helper build failed"
  cp "$BUILT" "$ROOT/bin/hnc_json_c" || fail "C helper copy failed"
  chmod 755 "$ROOT/bin/hnc_json_c"
else
  echo "[SKIP] no host C compiler"
  exit 0
fi

export HNC_JSON_C_ALLOW_HOST=1
export HNC="$TMP/hnc"
mkdir -p "$HNC/run" "$HNC/data"

NAMES="$HNC/data/device_names.json"
printf '{}\n' > "$NAMES"
sh "$ROOT/bin/hnc_json" set-object-key "$NAMES" 'aa:bb:cc:dd:ee:ff' '测试, right} quote" slash\' str || fail "set-object-key failed"
grep -q 'aa:bb:cc:dd:ee:ff' "$NAMES" || fail "name key missing"
grep -q '\\"' "$NAMES" || fail "quote was not escaped"
sh "$ROOT/bin/hnc_json" del-object-key "$NAMES" 'aa:bb:cc:dd:ee:ff' || fail "del-object-key failed"
! grep -q 'aa:bb:cc:dd:ee:ff' "$NAMES" || fail "name key still present"

RULES="$HNC/data/rules.json"
printf '{"version":1,"blacklist":[]}\n' > "$RULES"
sh "$ROOT/bin/hnc_json" add-array-unique "$RULES" blacklist 'aa:bb:cc:dd:ee:ff' || fail "array add failed"
sh "$ROOT/bin/hnc_json" add-array-unique "$RULES" blacklist 'aa:bb:cc:dd:ee:ff' || fail "duplicate array add failed"
[ "$(grep -o 'aa:bb:cc:dd:ee:ff' "$RULES" | wc -l | tr -d ' ')" = "1" ] || fail "duplicate blacklist entry"
sh "$ROOT/bin/hnc_json" del-array-value "$RULES" blacklist 'aa:bb:cc:dd:ee:ff' || fail "array del failed"
! grep -q 'aa:bb:cc:dd:ee:ff' "$RULES" || fail "blacklist entry still present"

TOKENS="$HNC/data/remote_tokens.json"
printf '{"version":1,"tokens":{"tok_A":{"hash":"h","revoked":false},"tok_B":{"hash":"h","revoked":false}}}\n' > "$TOKENS"
sh "$ROOT/bin/hnc_json" token-revoke "$TOKENS" tok_A || fail "token revoke failed"
grep -q '"tok_A":{"hash":"h","revoked":true}' "$TOKENS" || fail "tok_A not revoked"
grep -q '"tok_B":{"hash":"h","revoked":false}' "$TOKENS" || fail "tok_B unexpectedly changed"
sh "$ROOT/bin/hnc_json" token-revoke-all "$TOKENS" || fail "token revoke all failed"
! grep -q '"revoked":false' "$TOKENS" || fail "revoked false remains"

echo "[OK] hnc_json C write bridge test passed"
