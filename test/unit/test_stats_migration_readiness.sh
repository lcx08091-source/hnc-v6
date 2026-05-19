#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP="$ROOT/.tmp/test_stats_migration_readiness.$$"
rm -rf "$TMP"
mkdir -p "$TMP/bin" "$TMP/data" "$TMP/run"
cp "$ROOT/bin/stats_migration_readiness.sh" "$TMP/bin/"
chmod 755 "$TMP/bin/stats_migration_readiness.sh"

cat > "$TMP/data/stats_raw.jsonl" <<'EOF2'
{"date":"2026-04-27","mac":"aa:bb:cc:dd:ee:ff","rx":100,"tx":200}
EOF2
cat > "$TMP/data/stats_daily.jsonl" <<'EOF2'
{"date":"2026-04-27","mac":"aa:bb:cc:dd:ee:ff","rx":100,"tx":200}
EOF2
cat > "$TMP/data/stats_shadow_raw.jsonl" <<'EOF2'
{"date":"2026-04-27","device_id":"aa:bb:cc:dd:ee:ff","rx":100,"tx":200}
EOF2
cat > "$TMP/data/stats_shadow_daily.jsonl" <<'EOF2'
{"date":"2026-04-27","device_id":"aa:bb:cc:dd:ee:ff","rx":100,"tx":200}
EOF2

for h in stats_shadow_diag.sh stats_shadow_control.sh stats_source_diag.sh stats_compare.sh stats_retention_diag.sh stats_identity_diag.sh; do
  cat > "$TMP/bin/$h" <<'EOF2'
#!/usr/bin/env sh
echo '{"ok":true,"status":"ok"}'
EOF2
  chmod 755 "$TMP/bin/$h"
done
cat > "$TMP/bin/stats_shadow_rollup.sh" <<'EOF2'
#!/usr/bin/env sh
exit 0
EOF2
chmod 755 "$TMP/bin/stats_shadow_rollup.sh"

OUT="$(HNC="$TMP" HNC_TEST_MODE=1 sh "$TMP/bin/stats_migration_readiness.sh" json)"
echo "$OUT" | grep '"status":"ready"' >/dev/null
echo "$OUT" | grep '"ready":true' >/dev/null
[ -f "$TMP/run/stats_migration_readiness.json" ]
[ -f "$TMP/run/stats_migration_readiness.txt" ]

rm -rf "$TMP"
echo "test_stats_migration_readiness: OK"
