#!/system/bin/sh
# hotfix19.6 regression test: json_set_batch uses hnc_json set-device-batch atomically
set -eu
DIR="${TMPDIR:-/tmp}/hnc_test_batch_$$"
mkdir -p "$DIR/bin" "$DIR/data" "$DIR/run" "$DIR/backups"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/hnc_json" "$DIR/bin/hnc_json"
cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/json_set_batch.sh" "$DIR/bin/json_set_batch.sh"
chmod 755 "$DIR/bin/hnc_json" "$DIR/bin/json_set_batch.sh"
cat > "$DIR/data/rules.json" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
JSON
export HNC="$DIR"
export RULES="$DIR/data/rules.json"
export HNC_JSON="$DIR/bin/hnc_json"
export HNC_TEST_MODE=1
MAC="aa:bb:cc:dd:ee:ff"
sh "$DIR/bin/json_set_batch.sh" device "$MAC" nickname 'Phone, with } brace' note 'quote " and slash \\ 中文' down_mbps 1.5 limit_enabled true
"$DIR/bin/hnc_json" validate "$RULES"
NICK=$("$DIR/bin/hnc_json" get-device "$RULES" "$MAC" nickname)
NOTE=$("$DIR/bin/hnc_json" get-device "$RULES" "$MAC" note)
DN=$("$DIR/bin/hnc_json" get-device "$RULES" "$MAC" down_mbps)
LE=$("$DIR/bin/hnc_json" get-device "$RULES" "$MAC" limit_enabled)
echo "$NICK" | grep -q 'Phone, with } brace'
echo "$NOTE" | grep -q 'quote'
[ "$DN" = "1.5" ]
[ "$LE" = "true" ]
rm -rf "$DIR"
echo "test_json_set_batch_atomic_hnc_json: OK"
