#!/system/bin/sh
# Static regression test for v5.2-rc1.10 WebUI bridge transport hint.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
HTML="$ROOT/webroot/index.html"
fail(){ echo "[FAIL] $*" >&2; exit 1; }
pass(){ echo "[OK] $*"; }
[ -f "$HTML" ] || fail "missing webroot/index.html"
grep -q "HNC_TRANSPORT_HINT_KEY" "$HTML" || fail "missing transport hint key"
grep -q "__hncRememberBridgeTransport('auto-delayed')" "$HTML" || fail "auto bridge success does not remember bridge"
grep -q "__hncRememberBridgeTransport('manual-force')" "$HTML" || fail "manual force success does not remember bridge"
grep -q "__hncHasBridgeHint()" "$HTML" || fail "init does not read saved bridge hint"
grep -q "bridge-reset-mode" "$HTML" || fail "missing reset connection mode button/action"
grep -q "__hncForgetBridgeTransport();" "$HTML" || fail "missing bridge hint clear path"
grep -q "version=v5.2.0-rc1.10" "$ROOT/module.prop" || fail "module.prop version not rc1.10"
grep -q "versionCode=520020" "$ROOT/module.prop" || fail "module.prop versionCode not 520020"
pass "webui bridge hint rc1.10 static checks"
