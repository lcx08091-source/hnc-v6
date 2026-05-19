#!/usr/bin/env sh
set -eu

ROOT="${TMPDIR:-$(pwd)/.tmp}/hnc_stats_health_summary_test.$$"
rm -rf "$ROOT" 2>/dev/null || true
mkdir -p "$ROOT/bin" "$ROOT/run" "$ROOT/data"

cp "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../../bin/stats_health_summary.sh" "$ROOT/bin/stats_health_summary.sh"
chmod 755 "$ROOT/bin/stats_health_summary.sh"

mkhelper() {
  name="$1"
  status="$2"
  cat > "$ROOT/bin/$name" <<EOF2
#!/usr/bin/env sh
echo '{"ok":true,"status":"$status"}'
EOF2
  chmod 755 "$ROOT/bin/$name"
}

for pair in \
  'stats_diag.sh ok' \
  'stats_identity_diag.sh ok' \
  'stats_retention_diag.sh ok' \
  'stats_shadow_diag.sh ok' \
  'stats_shadow_control.sh ok' \
  'stats_source_diag.sh legacy' \
  'stats_compare.sh ok' \
  'stats_migration_readiness.sh ready' \
  'stats_v52_rc_control.sh disabled' \
  'stats_v52_rc_smoke.sh disabled'
do
  set -- $pair
  mkhelper "$1" "$2"
done

HNC="$ROOT" HNC_TEST_MODE=1 sh "$ROOT/bin/stats_health_summary.sh" json > "$ROOT/out.warn.json"
grep -q '"status":"warn"' "$ROOT/out.warn.json"
grep -q '"stats_shadow_control":"ok"' "$ROOT/out.warn.json"
grep -q '"stats_compare":"ok"' "$ROOT/out.warn.json"
grep -q '"stats_v52_rc_smoke":"disabled"' "$ROOT/out.warn.json"
if grep -q '"status":""' "$ROOT/out.warn.json"; then exit 1; fi
if grep -q '"recommendation":""' "$ROOT/out.warn.json"; then exit 1; fi
[ -f "$ROOT/run/stats_health_summary.json" ]
[ -f "$ROOT/run/stats_health_summary.txt" ]

mkhelper stats_v52_rc_control.sh enabled
mkhelper stats_v52_rc_smoke.sh pass
HNC="$ROOT" HNC_TEST_MODE=1 sh "$ROOT/bin/stats_health_summary.sh" json > "$ROOT/out.ok.json"
grep -q '"status":"ok"' "$ROOT/out.ok.json"
grep -q '"stats_v52_rc_smoke":"pass"' "$ROOT/out.ok.json"
if grep -q '"status":""' "$ROOT/out.ok.json"; then exit 1; fi
if grep -q '"recommendation":""' "$ROOT/out.ok.json"; then exit 1; fi

mkhelper stats_compare.sh fail
HNC="$ROOT" HNC_TEST_MODE=1 sh "$ROOT/bin/stats_health_summary.sh" json > "$ROOT/out.fail.json"
grep -q '"status":"fail"' "$ROOT/out.fail.json"
grep -q '"stats_compare":"fail"' "$ROOT/out.fail.json"
if grep -q '"status":""' "$ROOT/out.fail.json"; then exit 1; fi
if grep -q '"recommendation":""' "$ROOT/out.fail.json"; then exit 1; fi

rm -rf "$ROOT" 2>/dev/null || true

echo "PASS stats_health_summary"
