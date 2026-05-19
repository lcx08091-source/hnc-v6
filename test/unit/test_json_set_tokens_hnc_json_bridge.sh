#!/system/bin/sh
# hotfix20.0 regression test: remote token revoke paths use hnc_json safely
set -eu

BASE="${TMPDIR:-/tmp}/hnc_json_tokens_test.$$"
ROOT="$BASE/root"
SRC_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
mkdir -p "$ROOT/bin" "$ROOT/data" "$ROOT/run"
cp "$SRC_DIR/bin/json_set.sh" "$ROOT/bin/json_set.sh"
cp "$SRC_DIR/bin/hnc_json" "$ROOT/bin/hnc_json"
cp "$SRC_DIR/bin/json_guard.sh" "$ROOT/bin/json_guard.sh" 2>/dev/null || true
chmod 755 "$ROOT/bin"/*.sh "$ROOT/bin/hnc_json" 2>/dev/null || true

cat > "$ROOT/data/remote_tokens.json" <<'JSON'
{"version":1,"tokens":{"tok_one":{"hash":"h1","created":1,"last_seen":2,"label":"Phone, 中文 } quote \" slash \\","ip_hint":"192.168.43.2","revoked":false},"tok_two":{"hash":"h2","created":3,"last_seen":4,"label":"Laptop","ip_hint":"192.168.43.3","revoked":false}}}
JSON

HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke tok_one
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke missing_token

if command -v grep >/dev/null 2>&1; then
  grep -q '"tok_one".*"revoked":true' "$ROOT/data/remote_tokens.json" || { echo "tok_one not revoked" >&2; cat "$ROOT/data/remote_tokens.json" >&2; exit 1; }
  grep -q '"tok_two".*"revoked":false' "$ROOT/data/remote_tokens.json" || { echo "tok_two changed unexpectedly" >&2; cat "$ROOT/data/remote_tokens.json" >&2; exit 1; }
  grep -q 'Phone, 中文 } quote' "$ROOT/data/remote_tokens.json" || { echo "special label lost" >&2; cat "$ROOT/data/remote_tokens.json" >&2; exit 1; }
fi

HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke_all

if command -v grep >/dev/null 2>&1; then
  grep -q '"tok_one".*"revoked":true' "$ROOT/data/remote_tokens.json" || { echo "tok_one lost after revoke_all" >&2; cat "$ROOT/data/remote_tokens.json" >&2; exit 1; }
  grep -q '"tok_two".*"revoked": true' "$ROOT/data/remote_tokens.json" || grep -q '"tok_two".*"revoked":true' "$ROOT/data/remote_tokens.json" || { echo "tok_two not revoked by revoke_all" >&2; cat "$ROOT/data/remote_tokens.json" >&2; exit 1; }
fi

if [ -x "$ROOT/bin/json_guard.sh" ]; then
  sh "$ROOT/bin/json_guard.sh" "$ROOT/data/remote_tokens.json" >/dev/null
fi

rm -rf "$BASE"
echo "[OK] remote tokens hnc_json bridge regression passed"
