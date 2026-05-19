#!/usr/bin/env sh
set -eu

TMPDIR="${TMPDIR:-/tmp}/hnc_stats_v52_rc1_switch.$$"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR/bin" "$TMPDIR/run" "$TMPDIR/data"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
cp "$ROOT/bin/stats_v52_rc1_switch.sh" "$TMPDIR/bin/stats_v52_rc1_switch.sh"
chmod 755 "$TMPDIR/bin/stats_v52_rc1_switch.sh"

cat > "$TMPDIR/bin/stats_v52_rc_control.sh" <<'EOS'
#!/usr/bin/env sh
RUN="${HNC:-/tmp}/run"
mkdir -p "$RUN"
case "${1:-json}" in
  enable)
    if [ "${BLOCK_RC:-0}" = 1 ]; then
      echo '{"ok":true,"status":"blocked","enabled":false}' > "$RUN/stats_v52_rc_control.json"
      exit 2
    fi
    echo enabled > "$RUN/stats_v52_rc.enabled"
    echo '{"ok":true,"status":"enabled","enabled":true}' > "$RUN/stats_v52_rc_control.json"
    ;;
  disable)
    rm -f "$RUN/stats_v52_rc.enabled"
    echo '{"ok":true,"status":"disabled","enabled":false}' > "$RUN/stats_v52_rc_control.json"
    ;;
  json|status|text|*)
    if [ -f "$RUN/stats_v52_rc.enabled" ]; then
      echo '{"ok":true,"status":"enabled","enabled":true}'
    else
      echo '{"ok":true,"status":"ready","enabled":false}'
    fi
    ;;
esac
EOS
chmod 755 "$TMPDIR/bin/stats_v52_rc_control.sh"

cat > "$TMPDIR/bin/stats_shadow_control.sh" <<'EOS'
#!/usr/bin/env sh
RUN="${HNC:-/tmp}/run"
mkdir -p "$RUN"
case "${1:-json}" in
  enable) echo enabled > "$RUN/stats_shadow.enabled" ;;
  disable) rm -f "$RUN/stats_shadow.enabled" ;;
  json|status|text|*)
    if [ -f "$RUN/stats_shadow.enabled" ]; then
      echo '{"ok":true,"status":"ok","effective_enabled":true}'
    else
      echo '{"ok":true,"status":"ok","effective_enabled":false}'
    fi
    ;;
esac
EOS
chmod 755 "$TMPDIR/bin/stats_shadow_control.sh"

cat > "$TMPDIR/bin/stats_v52_device_check.sh" <<'EOS'
#!/usr/bin/env sh
echo '{"ok":true,"status":"pass","rc_enable":{"ready":true,"gate":"pass"}}'
EOS
chmod 755 "$TMPDIR/bin/stats_v52_device_check.sh"

cat > "$TMPDIR/bin/stats_source_diag.sh" <<'EOS'
#!/usr/bin/env sh
echo '{"ok":true,"status":"ok","default_source":"legacy"}'
EOS
chmod 755 "$TMPDIR/bin/stats_source_diag.sh"

HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_rc1_switch.sh" json > "$TMPDIR/status1.json"
grep -q '"status":"disabled"' "$TMPDIR/status1.json"
grep -q '"default_source":"legacy"' "$TMPDIR/status1.json"
grep -q '"legacy_default_preserved":true' "$TMPDIR/status1.json"

HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_rc1_switch.sh" enable > "$TMPDIR/enable.txt"
[ -f "$TMPDIR/run/stats_v52_rc.enabled" ]
[ -f "$TMPDIR/run/stats_shadow.enabled" ]
[ -f "$TMPDIR/run/stats_v52_rc1.enabled" ]
grep -q 'status=enabled' "$TMPDIR/enable.txt"
grep -q 'default_source=legacy' "$TMPDIR/enable.txt"

HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_rc1_switch.sh" rollback > "$TMPDIR/rollback.txt"
[ ! -f "$TMPDIR/run/stats_v52_rc.enabled" ]
[ ! -f "$TMPDIR/run/stats_shadow.enabled" ]
[ ! -f "$TMPDIR/run/stats_v52_rc1.enabled" ]
grep -q 'status=disabled' "$TMPDIR/rollback.txt"

BLOCK_RC=1 HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$TMPDIR/bin/stats_v52_rc1_switch.sh" enable > "$TMPDIR/blocked.txt" 2>&1 && exit 1 || true
grep -q 'status=blocked' "$TMPDIR/blocked.txt"
[ ! -f "$TMPDIR/run/stats_v52_rc1.enabled" ]

echo "[OK] stats_v52_rc1_switch"
