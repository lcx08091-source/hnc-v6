#!/usr/bin/env sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP="$ROOT/.tmp/test_stats_v52_rc_smoke"
rm -rf "$TMP"
mkdir -p "$TMP/bin" "$TMP/run"
cp "$ROOT/bin/stats_v52_rc_smoke.sh" "$TMP/bin/"
chmod 755 "$TMP/bin/stats_v52_rc_smoke.sh"
export HNC_TEST_MODE=1
export HNC="$TMP"
export HNC_DIR="$TMP"

mkhelper() {
  name="$1"; body="$2"
  {
    echo '#!/usr/bin/env sh'
    echo "$body"
  } > "$TMP/bin/$name"
  chmod 755 "$TMP/bin/$name"
}

assert_nonempty_json_field() {
  json="$1"
  key="$2"
  if printf '%s' "$json" | grep "\"$key\":\"\"" >/dev/null; then
    echo "empty json field: $key" >&2
    echo "$json" >&2
    exit 1
  fi
}

assert_json_has_status() {
  json="$1"
  status="$2"
  printf '%s' "$json" | grep "\"status\":\"$status\"" >/dev/null
  assert_nonempty_json_field "$json" status
  assert_nonempty_json_field "$json" recommendation
  assert_nonempty_json_field "$json" json
  assert_nonempty_json_field "$json" text
}

out="$(sh "$TMP/bin/stats_v52_rc_smoke.sh" json)"
assert_json_has_status "$out" fail
printf '%s' "$out" | grep '"v52_rc_control":"missing"' >/dev/null

mkhelper stats_v52_rc_control.sh 'echo "{\"ok\":true,\"status\":\"disabled\",\"enabled\":false}"'
mkhelper stats_migration_readiness.sh 'echo "{\"ok\":true,\"status\":\"ready\",\"ready\":true}"'
out="$(sh "$TMP/bin/stats_v52_rc_smoke.sh" json)"
assert_json_has_status "$out" disabled
printf '%s' "$out" | grep '"rc_enabled":false' >/dev/null

mkhelper stats_v52_rc_control.sh 'echo "{\"ok\":true,\"status\":\"enabled\",\"enabled\":true}"'
mkhelper stats_shadow_diag.sh 'echo "{\"ok\":true,\"status\":\"ok\"}"'
mkhelper stats_compare.sh 'echo "{\"ok\":true,\"status\":\"ok\"}"'
mkhelper stats_source_diag.sh 'echo "{\"ok\":true,\"status\":\"legacy\"}"'
out="$(sh "$TMP/bin/stats_v52_rc_smoke.sh" json)"
assert_json_has_status "$out" pass
printf '%s' "$out" | grep '"stats_compare":"ok"' >/dev/null
printf '%s' "$out" | grep '"stats_source":"legacy"' >/dev/null

mkhelper stats_compare.sh 'echo "{\"ok\":true,\"status\":\"fail\"}"'
out="$(sh "$TMP/bin/stats_v52_rc_smoke.sh" json)"
assert_json_has_status "$out" fail
printf '%s' "$out" | grep '"stats_compare":"fail"' >/dev/null

# Escaping regression: helper output with newline in an ignored field must not
# make status/recommendation/path fields collapse to empty strings.
mkhelper stats_source_diag.sh 'printf "{\"ok\":true,\"status\":\"legacy\",\"note\":\"line1\\nline2\\\\quoted\"}\n"'
out="$(sh "$TMP/bin/stats_v52_rc_smoke.sh" json)"
assert_json_has_status "$out" fail

rm -rf "$TMP"
echo "[OK] stats_v52_rc_smoke"
