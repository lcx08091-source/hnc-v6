#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
SCRIPT="$ROOT/bin/stats_v52_review_bundle.sh"
TMP="${TMPDIR:-/tmp}/hnc_test_review_bundle.$$"
rm -rf "$TMP"
mkdir -p "$TMP/bin" "$TMP/run" "$TMP/mod" "$TMP/out"
trap 'rm -rf "$TMP"' EXIT INT TERM

cp "$SCRIPT" "$TMP/bin/stats_v52_review_bundle.sh"
chmod 755 "$TMP/bin/stats_v52_review_bundle.sh"
cat > "$TMP/module.prop" <<MP
version=v5.2.0-rc1.4
versionCode=520014
MP
cat > "$TMP/mod/module.prop" <<MP
version=v5.2.0-rc1.4
versionCode=520014
MP

mkhelper() {
  name="$1"; json="$2"; text="$3"; md="$4"
  cat > "$TMP/bin/$name" <<H
#!/usr/bin/env sh
case "\${1:-text}" in
  json) printf '%s\n' '$json' ;;
  markdown|md) printf '%s\n' '$md' ;;
  *) printf '%s\n' '$text' ;;
esac
H
  chmod 755 "$TMP/bin/$name"
}

mkhelper stats_v52_gray_report.sh '{"status":"pass","review_ready":true,"gray_ready":true,"token":"SECRET","ip":"192.168.43.2","mac":"AA:BB:CC:DD:EE:FF"}' 'gray pass token SECRET ip 192.168.43.2 mac AA:BB:CC:DD:EE:FF' '# Gray pass token SECRET 192.168.43.2 AA:BB:CC:DD:EE:FF'
mkhelper stats_v52_install_selfcheck.sh '{"status":"pass"}' 'self pass' '# self pass'
mkhelper stats_v52_web_status.sh '{"status":"pass","severity":"ok"}' 'web pass' '# web pass'
mkhelper stats_v52_device_check.sh '{"status":"pass"}' 'device pass' '# device pass'
mkhelper stats_v52_rc_smoke.sh '{"status":"pass"}' 'smoke pass' '# smoke pass'
mkhelper stats_migration_readiness.sh '{"status":"ready"}' 'ready' '# ready'
mkhelper stats_compare.sh '{"status":"pass"}' 'compare pass' '# compare pass'
mkhelper stats_v52_rc1_switch.sh '{"status":"pass","legacy_default_preserved":true,"rc1_enabled":false,"default_source":"legacy"}' 'rc1 pass' '# rc1 pass'
mkhelper stats_health_summary.sh '{"status":"pass"}' 'health pass' '# health pass'

TEXT="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" MODDIR="$TMP/mod" HNC_V52_REVIEW_OUT="$TMP/out" sh "$TMP/bin/stats_v52_review_bundle.sh" text)"
JSON="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" MODDIR="$TMP/mod" HNC_V52_REVIEW_OUT="$TMP/out" sh "$TMP/bin/stats_v52_review_bundle.sh" json)"
MD="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" MODDIR="$TMP/mod" HNC_V52_REVIEW_OUT="$TMP/out" sh "$TMP/bin/stats_v52_review_bundle.sh" markdown)"
BUNDLE_PATH="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" MODDIR="$TMP/mod" HNC_V52_REVIEW_OUT="$TMP/out" sh "$TMP/bin/stats_v52_review_bundle.sh" bundle)"

printf '%s\n' "$TEXT" | grep -q 'status=pass'
printf '%s\n' "$JSON" | grep -q '"status": "pass"'
printf '%s\n' "$MD" | grep -q '脱敏灰度审查包'
printf '%s\n' "$MD" | grep -q '<ipv4>'
printf '%s\n' "$MD" | grep -q '<mac>'
printf '%s\n' "$JSON" | grep -q '"redaction_enabled": true'
[ -d "$BUNDLE_PATH" ]
[ -f "$BUNDLE_PATH/review.md" ]
! grep -R '192.168.43.2\|AA:BB:CC:DD:EE:FF\|"token":"SECRET"' "$BUNDLE_PATH" >/dev/null 2>&1

echo '[OK] stats_v52_review_bundle'
