#!/system/bin/sh
# hotfix19.8 regression test: templates.json tpl_set/tpl_del use hnc_json object-key JSON safely
set -eu
DIR="${TMPDIR:-/tmp}/hnc_test_templates_$$"
mkdir -p "$DIR/bin" "$DIR/data" "$DIR/run" "$DIR/backups"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/hnc_json" "$DIR/bin/hnc_json"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/json_set.sh" "$DIR/bin/json_set.sh"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/json_guard.sh" "$DIR/bin/json_guard.sh" 2>/dev/null || true
chmod 755 "$DIR/bin/hnc_json" "$DIR/bin/json_set.sh" "$DIR/bin/json_guard.sh" 2>/dev/null || true
export HNC="$DIR"
export HNC_JSON="$DIR/bin/hnc_json"
export HNC_TEST_MODE=1

TPL='Game, } quote " slash \\ 中文'
sh "$DIR/bin/json_set.sh" tpl_set "$TPL" 50 20 30 5 0.5
"$DIR/bin/hnc_json" validate "$DIR/data/templates.json"
RAW=$("$DIR/bin/hnc_json" get-object-key "$DIR/data/templates.json" "$TPL")
echo "$RAW" | grep -q '"down_mbps":50'
echo "$RAW" | grep -q '"up_mbps":20'
echo "$RAW" | grep -q '"delay_ms":30'
echo "$RAW" | grep -q '"jitter_ms":5'
echo "$RAW" | grep -q '"loss_pct":0.5'
case "$RAW" in
  \{*) : ;;
  *) echo "template value should be JSON object, got: $RAW" >&2; exit 1 ;;
esac

# Updating an ordinary template should replace the object, not stringify it.
sh "$DIR/bin/json_set.sh" tpl_set normal 10 4 0 0 0
sh "$DIR/bin/json_set.sh" tpl_set normal 11 5 1 2 0
"$DIR/bin/hnc_json" validate "$DIR/data/templates.json"
RAW2=$("$DIR/bin/hnc_json" get-object-key "$DIR/data/templates.json" normal)
echo "$RAW2" | grep -q '"down_mbps":11'
echo "$RAW2" | grep -q '"up_mbps":5'
if echo "$RAW2" | grep -q '"down_mbps":10'; then
  echo "template update left stale value" >&2
  exit 1
fi

sh "$DIR/bin/json_set.sh" tpl_del "$TPL"
"$DIR/bin/hnc_json" validate "$DIR/data/templates.json"
if "$DIR/bin/hnc_json" get-object-key "$DIR/data/templates.json" "$TPL" >/dev/null 2>&1; then
  echo "tpl_del failed to remove key" >&2
  exit 1
fi
# Deleting a missing key must remain a valid no-op.
sh "$DIR/bin/json_set.sh" tpl_del "$TPL"
"$DIR/bin/hnc_json" validate "$DIR/data/templates.json"
rm -rf "$DIR"
echo "test_json_set_templates_hnc_json_bridge: OK"
