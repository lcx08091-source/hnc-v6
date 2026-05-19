#!/usr/bin/env sh
set -eu

TMPDIR="${TMPDIR:-/tmp}/hnc_stats_v52_install_selfcheck.$$"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR/bin" "$TMPDIR/run" "$TMPDIR/webroot"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
cp "$ROOT/bin/stats_v52_install_selfcheck.sh" "$TMPDIR/bin/stats_v52_install_selfcheck.sh"
chmod 755 "$TMPDIR/bin/stats_v52_install_selfcheck.sh"

cat > "$TMPDIR/module.prop" <<'EOS'
id=hotspot_network_control
name=Hotspot Network Control
version=v5.2.0-rc1.3
versionCode=520013
EOS
cat > "$TMPDIR/webroot/json-health.html" <<'EOS'
<div>v5.2 RC / 灰度状态</div>
<script>const key = 'v52_web_status_raw';</script>
EOS

make_helper() {
  name="$1"; body="$2"
  cat > "$TMPDIR/bin/$name" <<EOS
#!/usr/bin/env sh
cat <<'JSON'
$body
JSON
EOS
  chmod 755 "$TMPDIR/bin/$name"
}

make_helper stats_v52_rc1_switch.sh '{"ok":true,"status":"disabled","rc1_enabled":false,"rc_enabled":false,"default_source":"legacy","legacy_default_preserved":true,"note":"rollback supported"}'
# Include rollback text so the static rollback grep passes.
echo '# rollback' >> "$TMPDIR/bin/stats_v52_rc1_switch.sh"
make_helper stats_v52_web_status.sh '{"ok":true,"status":"disabled","severity":"ok","default_source":"legacy","legacy_default_preserved":true}'
make_helper stats_v52_device_check.sh '{"ok":true,"status":"pass","rc_enable_ready":true}'
for h in stats_v52_rc_control.sh stats_v52_rc_smoke.sh stats_v52_diag_bundle.sh stats_health_summary.sh stats_migration_readiness.sh stats_compare.sh stats_source_diag.sh stats_shadow_control.sh json_health_panel.sh json_diag_bundle.sh; do
  make_helper "$h" '{"ok":true,"status":"ok"}'
done

HNC="$TMPDIR" MODDIR="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_install_selfcheck.sh" json > "$TMPDIR/out.json"
grep -q '"status":"pass"' "$TMPDIR/out.json"
grep -q '"install_ready":true' "$TMPDIR/out.json"
grep -q '"first_boot_safe":true' "$TMPDIR/out.json"
grep -q '"safe_to_enable_rc":true' "$TMPDIR/out.json"
grep -q '"default_source":"legacy"' "$TMPDIR/out.json"
grep -q '"legacy_default_preserved":true' "$TMPDIR/out.json"
[ -f "$TMPDIR/run/stats_v52_install_selfcheck.json" ]
[ -f "$TMPDIR/run/stats_v52_install_selfcheck.txt" ]

make_helper stats_v52_rc1_switch.sh '{"ok":true,"status":"enabled","rc1_enabled":true,"rc_enabled":true,"default_source":"shadow","legacy_default_preserved":false}'
echo '# rollback' >> "$TMPDIR/bin/stats_v52_rc1_switch.sh"
HNC="$TMPDIR" MODDIR="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_install_selfcheck.sh" json > "$TMPDIR/out_shadow.json"
grep -q '"status":"fail"' "$TMPDIR/out_shadow.json"
grep -q 'default stats source is shadow' "$TMPDIR/out_shadow.json"
grep -q 'legacy_default_preserved is false' "$TMPDIR/out_shadow.json"

rm -f "$TMPDIR/bin/stats_v52_rc_smoke.sh"
HNC="$TMPDIR" MODDIR="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_install_selfcheck.sh" json > "$TMPDIR/out_missing.json"
grep -q '"status":"fail"' "$TMPDIR/out_missing.json"
grep -q 'missing executable helper stats_v52_rc_smoke.sh' "$TMPDIR/out_missing.json"

echo "[OK] stats_v52_install_selfcheck"
