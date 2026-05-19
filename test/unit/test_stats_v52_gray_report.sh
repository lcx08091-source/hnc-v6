#!/bin/sh
# Unit test for stats_v52_gray_report.sh. Uses stub helpers only.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
WORK="${TMPDIR:-/tmp}/hnc_test_gray_report_$$"
HNC_DIR="$WORK/hnc"
mkdir -p "$HNC_DIR/bin" "$HNC_DIR/run"

cp "$ROOT/bin/stats_v52_gray_report.sh" "$HNC_DIR/bin/stats_v52_gray_report.sh"
chmod 755 "$HNC_DIR/bin/stats_v52_gray_report.sh"

cat > "$HNC_DIR/module.prop" <<'EOF'
id=hotspot_network_control
version=v5.2.0-rc1.3
versionCode=520013
EOF

make_helper() {
  name="$1"
  json="$2"
  text="$3"
  cat > "$HNC_DIR/bin/$name" <<EOF
#!/bin/sh
case "\${1:-text}" in
  json) printf '%s\n' '$json' ;;
  *) printf '%s\n' '$text' ;;
esac
EOF
  chmod 755 "$HNC_DIR/bin/$name"
}

make_helper stats_v52_install_selfcheck.sh '{"ok":true,"status":"pass","install_ready":true,"first_boot_safe":true,"safe_to_enable_rc":true}' 'selfcheck pass'
make_helper stats_v52_web_status.sh '{"ok":true,"status":"pass","severity":"ok"}' 'web status ok'
make_helper stats_v52_device_check.sh '{"ok":true,"status":"pass","rc_enable_ready":true}' 'device check pass'
make_helper stats_compare.sh '{"ok":true,"status":"pass"}' 'compare pass'
make_helper stats_migration_readiness.sh '{"ok":true,"status":"ready"}' 'readiness ready'
make_helper stats_v52_rc_smoke.sh '{"ok":true,"status":"pass"}' 'smoke pass'
make_helper stats_v52_rc1_switch.sh '{"ok":true,"status":"disabled","rc1_enabled":false,"rc_enabled":false,"default_source":"legacy","legacy_default_preserved":true}' 'rc1 disabled legacy'
make_helper stats_v52_rc_control.sh '{"ok":true,"status":"disabled"}' 'rc control disabled'
make_helper stats_source_diag.sh '{"ok":true,"status":"pass"}' 'source pass'
make_helper stats_shadow_diag.sh '{"ok":true,"status":"pass"}' 'shadow pass'
make_helper stats_health_summary.sh '{"ok":true,"status":"pass"}' 'health pass'

HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_report.sh" text > "$WORK/out.txt"
HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_report.sh" json > "$WORK/out.json"
HNC_TEST_MODE=1 HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" MODDIR="$HNC_DIR" sh "$HNC_DIR/bin/stats_v52_gray_report.sh" markdown > "$WORK/out.md"

grep -q 'status=pass' "$WORK/out.txt"
grep -q 'gray_ready=true' "$WORK/out.txt"
grep -q '"status":"pass"' "$WORK/out.json"
grep -q '"gray_ready":true' "$WORK/out.json"
grep -q '# HNC v5.2-rc1.3 灰度观察报告' "$WORK/out.md"
grep -q 'install selfcheck' "$WORK/out.md"
grep -q 'RC smoke' "$WORK/out.md"

[ -f "$HNC_DIR/run/stats_v52_gray_report.json" ]
[ -f "$HNC_DIR/run/stats_v52_gray_report.txt" ]
[ -f "$HNC_DIR/run/stats_v52_gray_report.md" ]

rm -rf "$WORK"
echo "[OK] stats_v52_gray_report"
