#!/system/bin/sh
# hotfix19.7 regression test: device_names.json name_set/name_get/name_del use hnc_json object-key safely
set -eu
DIR="${TMPDIR:-/tmp}/hnc_test_names_$$"
mkdir -p "$DIR/bin" "$DIR/data" "$DIR/run" "$DIR/backups"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/hnc_json" "$DIR/bin/hnc_json"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/json_set.sh" "$DIR/bin/json_set.sh"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/json_guard.sh" "$DIR/bin/json_guard.sh" 2>/dev/null || true
chmod 755 "$DIR/bin/hnc_json" "$DIR/bin/json_set.sh" "$DIR/bin/json_guard.sh" 2>/dev/null || true
export HNC="$DIR"
export HNC_JSON="$DIR/bin/hnc_json"
export HNC_TEST_MODE=1
MAC="AA:BB:CC:DD:EE:FF"
MAC_L="aa:bb:cc:dd:ee:ff"
NAME='Phone, with } brace, quote " slash \\ 中文'
sh "$DIR/bin/json_set.sh" name_set "$MAC" "$NAME"
"$DIR/bin/hnc_json" validate "$DIR/data/device_names.json"
GOT=$(sh "$DIR/bin/json_set.sh" name_get "$MAC_L")
[ "$GOT" = "$NAME" ] || { echo "name_get mismatch: $GOT" >&2; exit 1; }
RAW=$("$DIR/bin/hnc_json" get-object-key "$DIR/data/device_names.json" "$MAC_L")
echo "$RAW" | grep -q 'Phone, with } brace'
echo "$RAW" | grep -q '中文'
sh "$DIR/bin/json_set.sh" name_del "$MAC_L"
"$DIR/bin/hnc_json" validate "$DIR/data/device_names.json"
if "$DIR/bin/hnc_json" get-object-key "$DIR/data/device_names.json" "$MAC_L" >/dev/null 2>&1; then
  echo "name_del failed to remove key" >&2
  exit 1
fi
# Deleting a missing key must stay valid and no-op.
sh "$DIR/bin/json_set.sh" name_del "$MAC_L"
"$DIR/bin/hnc_json" validate "$DIR/data/device_names.json"
rm -rf "$DIR"
echo "test_json_set_names_hnc_json_bridge: OK"
