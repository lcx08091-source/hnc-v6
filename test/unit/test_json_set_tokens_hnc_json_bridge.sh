#!/system/bin/sh
# v5.9.0 regression test: token revoke 单写者化(marker 桥)
# (前身是 hotfix20.0 的 hnc_json 桥接回归;文件名保留避免动 runner。
#  桥接已删除: shell 侧撤销只排队 run/token_revoke.request,不碰
#  remote_tokens.json —— 该文件唯一运行期写者是 hnc_httpd。)
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

before_sum=$(md5sum "$ROOT/data/remote_tokens.json" | awk '{print $1}')

HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke tok_one
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke missing_token

REQ="$ROOT/run/token_revoke.request"
[ -f "$REQ" ] || { echo "request file not created" >&2; exit 1; }
grep -qx 'tok_one' "$REQ" || { echo "tok_one not queued" >&2; cat "$REQ" >&2; exit 1; }
grep -qx 'missing_token' "$REQ" || { echo "missing_token not queued" >&2; cat "$REQ" >&2; exit 1; }

HNC="$ROOT" sh "$ROOT/bin/json_set.sh" token_revoke_all
grep -qx 'ALL' "$REQ" || { echo "ALL not queued by revoke_all" >&2; cat "$REQ" >&2; exit 1; }

# 单写者不变量: shell 撤销路径绝不改 remote_tokens.json(含特殊字符 label
# 原样保留 —— 旧桥接时代最容易翻车的场景现在天然免疫)
after_sum=$(md5sum "$ROOT/data/remote_tokens.json" | awk '{print $1}')
[ "$before_sum" = "$after_sum" ] || {
    echo "remote_tokens.json was modified by shell revoke path (single-writer violated)" >&2
    cat "$ROOT/data/remote_tokens.json" >&2
    exit 1
}
grep -q 'Phone, 中文 } quote' "$ROOT/data/remote_tokens.json" || { echo "special label lost" >&2; exit 1; }

if [ -x "$ROOT/bin/json_guard.sh" ]; then
  sh "$ROOT/bin/json_guard.sh" "$ROOT/data/remote_tokens.json" >/dev/null
fi

rm -rf "$BASE"
echo "[OK] token revoke single-writer (marker bridge) regression passed"
