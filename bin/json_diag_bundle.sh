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

# hnc_json C helper diagnostics are read-only and help verify whether CI packaged
# an Android ARM helper, whether writes are still opt-in, and what fallback is active.
if [ -x "$BIN/hnc_json_c_status.sh" ]; then
  run_cmd hnc_json_c_status sh "$BIN/hnc_json_c_status.sh"
fi
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
if [ -x "$BIN/stats_shadow_diag.sh" ]; then
  run_cmd stats_shadow_diag_json sh "$BIN/stats_shadow_diag.sh" json
  run_cmd stats_shadow_diag_text sh "$BIN/stats_shadow_diag.sh" text
fi
if [ -x "$BIN/stats_shadow_control.sh" ]; then
  run_cmd stats_shadow_control_json sh "$BIN/stats_shadow_control.sh" json
  run_cmd stats_shadow_control_text sh "$BIN/stats_shadow_control.sh" text
fi
if [ -x "$BIN/stats_source_diag.sh" ]; then
  run_cmd stats_source_diag_json sh "$BIN/stats_source_diag.sh" json
  run_cmd stats_source_diag_text sh "$BIN/stats_source_diag.sh" text
fi
if [ -x "$BIN/stats_compare.sh" ]; then
  run_cmd stats_compare_json sh "$BIN/stats_compare.sh" json
  run_cmd stats_compare_text sh "$BIN/stats_compare.sh" text
fi
if [ -x "$BIN/stats_health_summary.sh" ]; then
  run_cmd stats_health_summary_json sh "$BIN/stats_health_summary.sh" json
  run_cmd stats_health_summary_text sh "$BIN/stats_health_summary.sh" text
fi
if [ -x "$BIN/stats_migration_readiness.sh" ]; then
  run_cmd stats_migration_readiness_json sh "$BIN/stats_migration_readiness.sh" json
  run_cmd stats_migration_readiness_text sh "$BIN/stats_migration_readiness.sh" text
fi
if [ -x "$BIN/stats_v52_rc_control.sh" ]; then
  run_cmd stats_v52_rc_control_json sh "$BIN/stats_v52_rc_control.sh" json
  run_cmd stats_v52_rc_control_text sh "$BIN/stats_v52_rc_control.sh" text
fi
if [ -x "$BIN/stats_v52_rc1_switch.sh" ]; then
  run_cmd stats_v52_rc1_switch_json sh "$BIN/stats_v52_rc1_switch.sh" json
  run_cmd stats_v52_rc1_switch_text sh "$BIN/stats_v52_rc1_switch.sh" text
fi
if [ -x "$BIN/stats_v52_rc_smoke.sh" ]; then
  run_cmd stats_v52_rc_smoke_json sh "$BIN/stats_v52_rc_smoke.sh" json
  run_cmd stats_v52_rc_smoke_text sh "$BIN/stats_v52_rc_smoke.sh" text
fi
if [ -x "$BIN/stats_v52_diag_bundle.sh" ]; then
  run_cmd stats_v52_diag_bundle_json sh "$BIN/stats_v52_diag_bundle.sh" json
  run_cmd stats_v52_diag_bundle_text sh "$BIN/stats_v52_diag_bundle.sh" text
fi
if [ -x "$BIN/stats_v52_device_check.sh" ]; then
  run_cmd stats_v52_device_check_json sh "$BIN/stats_v52_device_check.sh" json
  run_cmd stats_v52_device_check_text sh "$BIN/stats_v52_device_check.sh" text
fi
if [ -x "$BIN/stats_v52_install_selfcheck.sh" ]; then
  run_cmd stats_v52_install_selfcheck_json sh "$BIN/stats_v52_install_selfcheck.sh" json
  run_cmd stats_v52_install_selfcheck_text sh "$BIN/stats_v52_install_selfcheck.sh" text
fi
if [ -x "$BIN/stats_v52_gray_report.sh" ]; then
  run_cmd stats_v52_gray_report_json sh "$BIN/stats_v52_gray_report.sh" json
  run_cmd stats_v52_gray_report_text sh "$BIN/stats_v52_gray_report.sh" text
  run_cmd stats_v52_gray_report_markdown sh "$BIN/stats_v52_gray_report.sh" markdown
fi
if [ -x "$BIN/stats_v52_review_bundle.sh" ]; then
  run_cmd stats_v52_review_bundle_json sh "$BIN/stats_v52_review_bundle.sh" json
  run_cmd stats_v52_review_bundle_text sh "$BIN/stats_v52_review_bundle.sh" text
  run_cmd stats_v52_review_bundle_markdown sh "$BIN/stats_v52_review_bundle.sh" markdown
fi
mkdir -p "$OUT/stats_tail" 2>/dev/null
[ -f "$DATA/stats_raw.jsonl" ] && tail -200 "$DATA/stats_raw.jsonl" > "$OUT/stats_tail/stats_raw.tail.jsonl" 2>/dev/null
[ -f "$DATA/stats_daily.jsonl" ] && tail -200 "$DATA/stats_daily.jsonl" > "$OUT/stats_tail/stats_daily.tail.jsonl" 2>/dev/null
[ -f "$DATA/stats_shadow_raw.jsonl" ] && tail -200 "$DATA/stats_shadow_raw.jsonl" > "$OUT/stats_tail/stats_shadow_raw.tail.jsonl" 2>/dev/null
[ -f "$DATA/stats_shadow_daily.jsonl" ] && tail -200 "$DATA/stats_shadow_daily.jsonl" > "$OUT/stats_tail/stats_shadow_daily.tail.jsonl" 2>/dev/null
copy_if_exists "$RUN/stats_last_date" "$OUT/run/stats_last_date"
copy_if_exists "$RUN/stats_shadow_last_date" "$OUT/run/stats_shadow_last_date"
copy_if_exists "$RUN/stats_shadow.enabled" "$OUT/run/stats_shadow.enabled"
copy_if_exists "$RUN/stats_webui_source" "$OUT/run/stats_webui_source"
copy_if_exists "$RUN/stats_v52_rc.enabled" "$OUT/run/stats_v52_rc.enabled"
copy_if_exists "$RUN/stats_v52_rc1.enabled" "$OUT/run/stats_v52_rc1.enabled"
copy_if_exists "$RUN/stats_compare.json" "$OUT/run/stats_compare.json"
copy_if_exists "$RUN/stats_compare.txt" "$OUT/run/stats_compare.txt"
copy_if_exists "$RUN/stats_health_summary.json" "$OUT/run/stats_health_summary.json"
copy_if_exists "$RUN/stats_health_summary.txt" "$OUT/run/stats_health_summary.txt"
copy_if_exists "$RUN/stats_migration_readiness.json" "$OUT/run/stats_migration_readiness.json"
copy_if_exists "$RUN/stats_migration_readiness.txt" "$OUT/run/stats_migration_readiness.txt"
copy_if_exists "$RUN/stats_v52_rc_control.json" "$OUT/run/stats_v52_rc_control.json"
copy_if_exists "$RUN/stats_v52_rc_control.txt" "$OUT/run/stats_v52_rc_control.txt"
copy_if_exists "$RUN/stats_v52_rc1_switch.json" "$OUT/run/stats_v52_rc1_switch.json"
copy_if_exists "$RUN/stats_v52_rc1_switch.txt" "$OUT/run/stats_v52_rc1_switch.txt"
copy_if_exists "$RUN/stats_v52_rc_smoke.json" "$OUT/run/stats_v52_rc_smoke.json"
copy_if_exists "$RUN/stats_v52_rc_smoke.txt" "$OUT/run/stats_v52_rc_smoke.txt"
copy_if_exists "$RUN/stats_v52_diag_bundle.json" "$OUT/run/stats_v52_diag_bundle.json"
copy_if_exists "$RUN/stats_v52_diag_bundle.txt" "$OUT/run/stats_v52_diag_bundle.txt"
copy_if_exists "$RUN/stats_v52_device_check.json" "$OUT/run/stats_v52_device_check.json"
copy_if_exists "$RUN/stats_v52_device_check.txt" "$OUT/run/stats_v52_device_check.txt"
copy_if_exists "$RUN/stats_v52_install_selfcheck.json" "$OUT/run/stats_v52_install_selfcheck.json"
copy_if_exists "$RUN/stats_v52_install_selfcheck.txt" "$OUT/run/stats_v52_install_selfcheck.txt"
copy_if_exists "$RUN/stats_v52_gray_report.json" "$OUT/run/stats_v52_gray_report.json"
copy_if_exists "$RUN/stats_v52_gray_report.txt" "$OUT/run/stats_v52_gray_report.txt"
copy_if_exists "$RUN/stats_v52_gray_report.md" "$OUT/run/stats_v52_gray_report.md"
copy_if_exists "$RUN/stats_v52_gray_report_bundle.path" "$OUT/run/stats_v52_gray_report_bundle.path"
copy_if_exists "$RUN/stats_v52_review_bundle.json" "$OUT/run/stats_v52_review_bundle.json"
copy_if_exists "$RUN/stats_v52_review_bundle.txt" "$OUT/run/stats_v52_review_bundle.txt"
copy_if_exists "$RUN/stats_v52_review_bundle.md" "$OUT/run/stats_v52_review_bundle.md"
copy_if_exists "$RUN/stats_v52_review_bundle.path" "$OUT/run/stats_v52_review_bundle.path"
copy_if_exists "$RUN/stats_v52_review_bundle_archive.path" "$OUT/run/stats_v52_review_bundle_archive.path"

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
  echo "  \"has_hnc_json_c_status\": $([ -x "$BIN/hnc_json_c_status.sh" ] && echo true || echo false),"
  echo "  \"has_stats_diag\": $([ -x "$BIN/stats_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_identity_diag\": $([ -x "$BIN/stats_identity_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_retention_diag\": $([ -x "$BIN/stats_retention_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_shadow_diag\": $([ -x "$BIN/stats_shadow_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_shadow_control\": $([ -x "$BIN/stats_shadow_control.sh" ] && echo true || echo false),"
  echo "  \"has_stats_shadow_rollup\": $([ -x "$BIN/stats_shadow_rollup.sh" ] && echo true || echo false),"
  echo "  \"has_stats_source_diag\": $([ -x "$BIN/stats_source_diag.sh" ] && echo true || echo false),"
  echo "  \"has_stats_compare\": $([ -x "$BIN/stats_compare.sh" ] && echo true || echo false),"
  echo "  \"has_stats_health_summary\": $([ -x "$BIN/stats_health_summary.sh" ] && echo true || echo false),"
  echo "  \"has_stats_migration_readiness\": $([ -x "$BIN/stats_migration_readiness.sh" ] && echo true || echo false),"
  echo "  \"has_stats_v52_rc_control\": $([ -x "$BIN/stats_v52_rc_control.sh" ] && echo true || echo false),"
  echo '  "has_stats_v52_rc_smoke": '$([ -x "$BIN/stats_v52_rc_smoke.sh" ] && echo true || echo false)', '
  echo "  \"has_stats_v52_diag_bundle\": $([ -x "$BIN/stats_v52_diag_bundle.sh" ] && echo true || echo false),"
  echo "  \"has_stats_v52_device_check\": $([ -x "$BIN/stats_v52_device_check.sh" ] && echo true || echo false),"
  echo "  \"has_stats_v52_rc1_switch\": $([ -x "$BIN/stats_v52_rc1_switch.sh" ] && echo true || echo false),"
  echo "  \"has_stats_v52_install_selfcheck\": $([ -x "$BIN/stats_v52_install_selfcheck.sh" ] && echo true || echo false),"
  echo "  \"has_stats_v52_review_bundle\": $([ -x "$BIN/stats_v52_review_bundle.sh" ] && echo true || echo false)"
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
