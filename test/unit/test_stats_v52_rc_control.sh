#!/usr/bin/env sh
set -eu

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP="$ROOT/.tmp/test_stats_v52_rc_control.$$"
rm -rf "$TMP"
mkdir -p "$TMP/bin" "$TMP/run" "$TMP/data"

cp "$ROOT/bin/stats_v52_rc_control.sh" "$TMP/bin/stats_v52_rc_control.sh"
chmod 755 "$TMP/bin/stats_v52_rc_control.sh"

cat > "$TMP/bin/stats_migration_readiness.sh" <<'SH'
#!/usr/bin/env sh
case "${HNC_TEST_READINESS:-not_ready}" in
  ready) echo '{"ok":true,"status":"ready","ready":true}' ;;
  blocked) echo '{"ok":true,"status":"blocked","ready":false}' ;;
  *) echo '{"ok":true,"status":"not_ready","ready":false}' ;;
esac
SH
chmod 755 "$TMP/bin/stats_migration_readiness.sh"

export HNC="$TMP"
export HNC_TEST_MODE=1
export HNC_SKIP_PATH_HARDENING=1

out="$(sh "$TMP/bin/stats_v52_rc_control.sh" json)"
printf '%s' "$out" | grep '"status":"disabled"' >/dev/null
[ ! -f "$TMP/run/stats_v52_rc.enabled" ]

set +e
sh "$TMP/bin/stats_v52_rc_control.sh" enable >"$TMP/enable_refuse.txt" 2>&1
rc=$?
set -e
[ "$rc" = 2 ]
[ ! -f "$TMP/run/stats_v52_rc.enabled" ]

HNC_TEST_READINESS=ready sh "$TMP/bin/stats_v52_rc_control.sh" enable >/dev/null
[ -f "$TMP/run/stats_v52_rc.enabled" ]
out="$(HNC_TEST_READINESS=ready sh "$TMP/bin/stats_v52_rc_control.sh" json)"
printf '%s' "$out" | grep '"status":"enabled"' >/dev/null

sh "$TMP/bin/stats_v52_rc_control.sh" disable >/dev/null
[ ! -f "$TMP/run/stats_v52_rc.enabled" ]

rm -rf "$TMP"
echo "PASS test_stats_v52_rc_control"
