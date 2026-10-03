#!/system/bin/sh
# HNC hotfix18.5 JSON/debug bundle collector
# Collects JSON health status, backup inventory, guard results, and TC snapshot
# without modifying live JSON files. Safe to run from Termux/root:
#   su -c 'sh /data/local/hnc/bin/json_diag_bundle.sh'

set +e

HNC="${HNC:-/data/local/hnc}"
MODDIR="${MODDIR:-/data/adb/modules/hotspot_network_control}"
BIN="$HNC/bin"
RUN="$HNC/run"
DATA="$HNC/data"
LOGS="$HNC/logs"
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)"
OUT_BASE="${HNC_JSON_DIAG_OUT:-/sdcard/Download}"
OUT="$OUT_BASE/hnc-json-debug-$TS"
CMD="$OUT/cmd"
mkdir -p "$OUT" "$CMD" 2>/dev/null

log() { echo "$*" | tee -a "$OUT/collect.log" >/dev/null; }
copy_if_exists() {
  src="$1"; dst="$2"
  [ -e "$src" ] || return 0
  mkdir -p "$(dirname "$dst")" 2>/dev/null
  cp -af "$src" "$dst" 2>/dev/null
}
run_cmd() {
  name="$1"; shift
  log "### $name"
  log "# $*"
  "$@" > "$CMD/$name.txt" 2>&1
  rc=$?
  echo "$rc" > "$CMD/$name.rc"
  return "$rc"
}

# Basic environment metadata
{
  echo "HNC JSON debug bundle"
  echo "timestamp=$TS"
  echo "HNC=$HNC"
  echo "MODDIR=$MODDIR"
  echo "id=$(id 2>/dev/null)"
  [ -f "$MODDIR/module.prop" ] && grep -E '^(version|versionCode|description)=' "$MODDIR/module.prop"
} > "$OUT/summary.txt"

# JSON doctor/guard status. status/list are read-only.
if [ -x "$BIN/json_doctor.sh" ]; then
  run_cmd json_doctor_status sh "$BIN/json_doctor.sh" status
  run_cmd json_doctor_list sh "$BIN/json_doctor.sh" list
else
  echo "missing json_doctor.sh" > "$CMD/json_doctor_status.txt"
  echo 127 > "$CMD/json_doctor_status.rc"
fi

if [ -x "$BIN/json_guard.sh" ]; then
  for f in rules.json device_names.json templates.json remote_tokens.json devices.json; do
    [ -f "$DATA/$f" ] || continue
    safe="$(echo "$f" | tr '/.' '__')"
    run_cmd "json_guard_$safe" sh "$BIN/json_guard.sh" "$DATA/$f"
  done
else
  echo "missing json_guard.sh" > "$CMD/json_guard_missing.txt"
fi

# Legacy JSON fallback telemetry is read-only and helps decide whether legacy
# fallback paths can safely be removed in later releases.
if [ -x "$BIN/json_legacy_fallback_status.sh" ]; then
  run_cmd json_legacy_fallback_status sh "$BIN/json_legacy_fallback_status.sh" status
  run_cmd json_legacy_fallback_json sh "$BIN/json_legacy_fallback_status.sh" json
fi
copy_if_exists "$RUN/json_legacy_fallback.log" "$OUT/run/json_legacy_fallback.log"
copy_if_exists "$RUN/json_legacy_fallback.count" "$OUT/run/json_legacy_fallback.count"

# hnc_json (shell) version — v5.26 起只有 shell 实现。
if [ -x "$BIN/hnc_json" ]; then
  run_cmd hnc_json_version sh "$BIN/hnc_json" version
fi

# Stats diagnostics are read-only and collected before the v5.2 stats overhaul.
# Do not copy full raw/daily files into the bundle by default; they may become large.
if [ -x "$BIN/stats_diag.sh" ]; then
  run_cmd stats_diag_json sh "$BIN/stats_diag.sh" json
  run_cmd stats_diag_text sh "$BIN/stats_diag.sh" text
fi
if [ -x "$BIN/stats_identity_diag.sh" ]; then
  run_cmd stats_identity_diag_json sh "$BIN/stats_identity_diag.sh" json
  run_cmd stats_identity_diag_text sh "$BIN/stats_identity_diag.sh" text
fi
if [ -x "$BIN/stats_retention_diag.sh" ]; then
  run_cmd stats_retention_diag_json sh "$BIN/stats_retention_diag.sh" json
  run_cmd stats_retention_diag_text sh "$BIN/stats_retention_diag.sh" text
fi
if [ -x "$BIN/stats_health_summary.sh" ]; then
  run_cmd stats_health_summary_json sh "$BIN/stats_health_summary.sh" json
  run_cmd stats_health_summary_text sh "$BIN/stats_health_summary.sh" text
fi
mkdir -p "$OUT/stats_tail" 2>/dev/null
[ -f "$DATA/stats_raw.jsonl" ] && tail -200 "$DATA/stats_raw.jsonl" > "$OUT/stats_tail/stats_raw.tail.jsonl" 2>/dev/null
[ -f "$DATA/stats_daily.jsonl" ] && tail -200 "$DATA/stats_daily.jsonl" > "$OUT/stats_tail/stats_daily.tail.jsonl" 2>/dev/null
copy_if_exists "$RUN/stats_last_date" "$OUT/run/stats_last_date"
copy_if_exists "$RUN/stats_health_summary.json" "$OUT/run/stats_health_summary.json"
copy_if_exists "$RUN/stats_health_summary.txt" "$OUT/run/stats_health_summary.txt"

# Generate TC snapshot if helper exists; do not fail bundle if it is absent.
if [ -x "$BIN/tc_state_snapshot.sh" ]; then
  run_cmd tc_state_snapshot sh "$BIN/tc_state_snapshot.sh"
fi

# Copy generated health/snapshot artifacts.
copy_if_exists "$RUN/json_health.json" "$OUT/run/json_health.json"
copy_if_exists "$RUN/json_health.txt" "$OUT/run/json_health.txt"
copy_if_exists "$RUN/tc_state.json" "$OUT/run/tc_state.json"
for f in "$RUN"/tc_state.*.txt "$RUN"/capabilities*.json "$RUN"/capabilities*.log; do
  [ -e "$f" ] && copy_if_exists "$f" "$OUT/run/$(basename "$f")"
done

# Backup inventory and small latest backup samples for recovery debugging.
BACKUP_DIR="$DATA/.json_backups"
if [ -d "$BACKUP_DIR" ]; then
  ls -la "$BACKUP_DIR" > "$OUT/json_backups.list.txt" 2>&1
  # Copy only newest backups, capped, so the debug bundle does not become huge.
  mkdir -p "$OUT/json_backups_latest" 2>/dev/null
  ls -t "$BACKUP_DIR" 2>/dev/null | head -20 | while read -r bf; do
    [ -n "$bf" ] && copy_if_exists "$BACKUP_DIR/$bf" "$OUT/json_backups_latest/$bf"
  done
else
  echo "no backup dir: $BACKUP_DIR" > "$OUT/json_backups.list.txt"
fi

# Copy live JSON files for parse debugging. These may contain local IP/MAC/device names;
# HNC debug bundles already include operational metadata, so keep this explicit.
mkdir -p "$OUT/live_json" 2>/dev/null
for f in rules.json device_names.json templates.json remote_tokens.json devices.json; do
  copy_if_exists "$DATA/$f" "$OUT/live_json/$f"
done

# Recent logs: limited tail only.
mkdir -p "$OUT/log_tail" 2>/dev/null
for lf in "$LOGS"/*.log; do
  [ -f "$lf" ] || continue
  bn="$(basename "$lf")"
  tail -300 "$lf" > "$OUT/log_tail/$bn.tail.txt" 2>/dev/null
done

# Produce machine-readable manifest.
{
  echo "{"
  echo "  \"ok\": true,"
  echo "  \"timestamp\": \"$TS\","
  echo "  \"hnc\": \"$HNC\","
  echo "  \"moddir\": \"$MODDIR\","
  echo "  \"has_json_doctor\": $([ -x "$BIN/json_doctor.sh" ] && echo true || echo false),"
  echo "  \"has_json_guard\": $([ -x "$BIN/json_guard.sh" ] && echo true || echo false),"
  echo "  \"has_tc_snapshot\": $([ -x "$BIN/tc_state_snapshot.sh" ] && echo true || echo false),"
  echo "  \"has_legacy_fallback_status\": $([ -x "$BIN/json_legacy_fallback_status.sh" ] && echo true || echo false),"
  echo "  \"has_hnc_json\": $([ -x "$BIN/hnc_json" ] && echo true || echo false),"
  echo "  \"has_stats_diag\": $([ -x "$BIN/stats_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_identity_diag\": $([ -x "$BIN/stats_identity_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_retention_diag\": $([ -x "$BIN/stats_retention_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_health_summary\": $([ -x "$BIN/stats_health_summary.sh" ] && echo true || echo false)"
  echo "}"
} > "$OUT/manifest.json"

# Pack automatically.
cd "$OUT_BASE" 2>/dev/null && tar -czf "hnc-json-debug-$TS.tar.gz" "hnc-json-debug-$TS" 2>/dev/null

cat <<EOF2
HNC JSON debug bundle created:
  $OUT

Send this file if present:
  $OUT_BASE/hnc-json-debug-$TS.tar.gz
EOF2
