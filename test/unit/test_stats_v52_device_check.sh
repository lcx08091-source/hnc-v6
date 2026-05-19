#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
SCRIPT="$ROOT/bin/stats_v52_device_check.sh"
[ -f "$SCRIPT" ] || { echo "missing stats_v52_device_check.sh" >&2; exit 1; }

TMP="${TMPDIR:-/tmp}/hnc_stats_v52_device_check.$$"
rm -rf "$TMP"
mkdir -p "$TMP/bin" "$TMP/run" "$TMP/data"
trap 'rm -rf "$TMP"' EXIT INT TERM

cp "$SCRIPT" "$TMP/bin/stats_v52_device_check.sh"
chmod 755 "$TMP/bin/stats_v52_device_check.sh"
cat > "$TMP/module.prop" <<'EOF_PROP'
version=v5.1.0-rc1-hotfix22.4
versionCode=509224
EOF_PROP
printf '{"tc_htb":true,"tc_netem":true,"uplink_supported":false}\n' > "$TMP/run/capabilities.json"
: > "$TMP/data/stats_raw.jsonl"
: > "$TMP/data/stats_daily.jsonl"
: > "$TMP/data/stats_shadow_raw.jsonl"
: > "$TMP/data/stats_shadow_daily.jsonl"

default_helper() {
  name="$1"
  status="$2"
  extra="$3"
  cat > "$TMP/bin/$name" <<EOF_HELPER
#!/usr/bin/env sh
cat <<'EOF_JSON'
{"ok":true,"status":"$status"$extra}
EOF_JSON
EOF_HELPER
  chmod 755 "$TMP/bin/$name"
}

install_helpers() {
  default_helper stats_v52_diag_bundle.sh pass ''
  default_helper stats_health_summary.sh ok ''
  default_helper stats_v52_rc_control.sh disabled ',"enabled":false'
  default_helper stats_v52_rc_smoke.sh disabled ''
  default_helper stats_migration_readiness.sh ready ',"ready":true'
  default_helper stats_compare.sh ok ''
  default_helper stats_source_diag.sh ok ''
  default_helper stats_shadow_diag.sh ok ''
  default_helper stats_shadow_control.sh ok ''
  default_helper stats_identity_diag.sh ok ''
  default_helper stats_retention_diag.sh ok ''
  default_helper stats_diag.sh ok ''
}

install_helpers
out="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" sh "$TMP/bin/stats_v52_device_check.sh" json)"
echo "$out" | grep -q '"status":"warn"' || { echo "expected warn when RC disabled but ready" >&2; echo "$out" >&2; exit 1; }
echo "$out" | grep -q '"stage":"ready_rc_disabled"' || { echo "expected ready_rc_disabled stage" >&2; echo "$out" >&2; exit 1; }
echo "$out" | grep -q '"version":"v5.1.0-rc1-hotfix22.4"' || { echo "expected module version in output" >&2; echo "$out" >&2; exit 1; }

# Enabled RC must pass only when readiness=true and smoke=pass.
default_helper stats_v52_rc_control.sh enabled ',"enabled":true'
default_helper stats_v52_rc_smoke.sh pass ''
out="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" sh "$TMP/bin/stats_v52_device_check.sh" json)"
echo "$out" | grep -q '"status":"pass"' || { echo "expected pass with enabled clean RC" >&2; echo "$out" >&2; exit 1; }
echo "$out" | grep -q '"stage":"rc_enabled"' || { echo "expected rc_enabled stage" >&2; echo "$out" >&2; exit 1; }

# Enabled RC with failed smoke must fail.
default_helper stats_v52_rc_smoke.sh fail ''
out="$(HNC_TEST_MODE=1 HNC_DIR="$TMP" sh "$TMP/bin/stats_v52_device_check.sh" json)"
echo "$out" | grep -q '"status":"fail"' || { echo "expected fail with enabled RC and failed smoke" >&2; echo "$out" >&2; exit 1; }
echo "$out" | grep -q 'disable RC' || { echo "expected disable RC recommendation" >&2; echo "$out" >&2; exit 1; }

# Text mode should write a readable report.
HNC_TEST_MODE=1 HNC_DIR="$TMP" sh "$TMP/bin/stats_v52_device_check.sh" text > "$TMP/out.txt"
grep -q '^HNC v5.2 stats real-device check' "$TMP/out.txt"
grep -q '^status=' "$TMP/out.txt"
grep -q '^stats_v52_rc_smoke=fail' "$TMP/out.txt"

# Static safety: no capability probe or network stack mutation.
! grep -v '^#' "$SCRIPT" | grep -q 'capability_probe.sh'
! grep -v '^#' "$SCRIPT" | grep -Eq '(^|[[:space:]])tc[[:space:]]|iptables|ip6tables'

echo "[OK] stats_v52_device_check"
