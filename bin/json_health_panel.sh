#!/system/bin/sh
# HNC hotfix18.6 JSON health panel backend
# Read-only summary for WebUI/KSU. Does not modify live JSON.

set +e
HNC="${HNC:-/data/local/hnc}"
BIN="$HNC/bin"
RUN="$HNC/run"
DATA="$HNC/data"
BACKUP_DIR="$DATA/.json_backups"
TS="$(date +%s 2>/dev/null || echo 0)"

json_escape() {
  # keep Android ash compatible; enough for short status strings/paths
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

file_ok() {
  f="$1"
  [ -f "$f" ] || { echo missing; return; }
  if [ -x "$BIN/json_guard.sh" ]; then
    sh "$BIN/json_guard.sh" "$f" >/dev/null 2>&1 && echo ok || echo bad
  else
    echo unknown
  fi
}

DOC_RC=127
DOC_MSG="json_doctor.sh missing"
if [ -x "$BIN/json_doctor.sh" ]; then
  DOC_OUT="$(sh "$BIN/json_doctor.sh" status 2>&1)"
  DOC_RC=$?
  DOC_MSG="$DOC_OUT"
fi

OVERALL="ok"
[ "$DOC_RC" = "0" ] || OVERALL="warn"

RULES_STATUS="$(file_ok "$DATA/rules.json")"
NAMES_STATUS="$(file_ok "$DATA/device_names.json")"
TPL_STATUS="$(file_ok "$DATA/templates.json")"
TOK_STATUS="$(file_ok "$DATA/remote_tokens.json")"
DEV_STATUS="$(file_ok "$DATA/devices.json")"

for s in "$RULES_STATUS" "$NAMES_STATUS" "$TPL_STATUS" "$TOK_STATUS" "$DEV_STATUS"; do
  [ "$s" = bad ] && OVERALL="fail"
  [ "$s" = missing ] && [ "$OVERALL" = ok ] && OVERALL="warn"
done

BACKUP_COUNT=0
[ -d "$BACKUP_DIR" ] && BACKUP_COUNT="$(ls "$BACKUP_DIR" 2>/dev/null | wc -l | tr -d ' ')"
LATEST_BACKUP=""
[ -d "$BACKUP_DIR" ] && LATEST_BACKUP="$(ls -t "$BACKUP_DIR" 2>/dev/null | head -1)"

LAST_BUNDLE="$(ls -t /sdcard/Download/hnc-json-debug-*.tar.gz 2>/dev/null | head -1)"
HAS_TC_STATE=false
[ -f "$RUN/tc_state.json" ] && HAS_TC_STATE=true
HAS_CAP=false
[ -f "$RUN/capabilities.json" ] && HAS_CAP=true

LEGACY_FALLBACK_COUNT=0
[ -f "$RUN/json_legacy_fallback.count" ] && LEGACY_FALLBACK_COUNT="$(cat "$RUN/json_legacy_fallback.count" 2>/dev/null)"
case "$LEGACY_FALLBACK_COUNT" in *[!0-9]*|"") LEGACY_FALLBACK_COUNT=0 ;; esac
LEGACY_FALLBACK_LAST=""
[ -f "$RUN/json_legacy_fallback.log" ] && LEGACY_FALLBACK_LAST="$(tail -1 "$RUN/json_legacy_fallback.log" 2>/dev/null)"
HAS_LEGACY_FALLBACK_STATUS=false
[ -x "$BIN/json_legacy_fallback_status.sh" ] && HAS_LEGACY_FALLBACK_STATUS=true
[ "$LEGACY_FALLBACK_COUNT" != 0 ] && [ "$OVERALL" = ok ] && OVERALL="warn"

HNC_JSON_C_STATUS_RAW=""
HNC_JSON_C_STATUS_PRESENT=false
if [ -x "$BIN/hnc_json_c_status.sh" ]; then
  HNC_JSON_C_STATUS_PRESENT=true
  HNC_JSON_C_STATUS_RAW="$(sh "$BIN/hnc_json_c_status.sh" 2>/dev/null)"
fi


STATS_DIAG_RAW=""
STATS_DIAG_PRESENT=false
if [ -x "$BIN/stats_diag.sh" ]; then
  STATS_DIAG_PRESENT=true
  STATS_DIAG_RAW="$(sh "$BIN/stats_diag.sh" json 2>/dev/null)"
fi

STATS_IDENTITY_RAW=""
STATS_IDENTITY_PRESENT=false
if [ -x "$BIN/stats_identity_diag.sh" ]; then
  STATS_IDENTITY_PRESENT=true
  STATS_IDENTITY_RAW="$(sh "$BIN/stats_identity_diag.sh" json 2>/dev/null)"
fi

STATS_RETENTION_RAW=""
STATS_RETENTION_PRESENT=false
if [ -x "$BIN/stats_retention_diag.sh" ]; then
  STATS_RETENTION_PRESENT=true
  STATS_RETENTION_RAW="$(sh "$BIN/stats_retention_diag.sh" json 2>/dev/null)"
fi
STATS_SHADOW_RAW=""
STATS_SHADOW_PRESENT=false
STATS_SHADOW_ROLLUP_PRESENT=false
if [ -x "$BIN/stats_shadow_diag.sh" ]; then
  STATS_SHADOW_PRESENT=true
  STATS_SHADOW_RAW="$(sh "$BIN/stats_shadow_diag.sh" json 2>/dev/null)"
fi
[ -x "$BIN/stats_shadow_rollup.sh" ] && STATS_SHADOW_ROLLUP_PRESENT=true

STATS_SHADOW_CONTROL_RAW=""
STATS_SHADOW_CONTROL_PRESENT=false
if [ -x "$BIN/stats_shadow_control.sh" ]; then
  STATS_SHADOW_CONTROL_PRESENT=true
  STATS_SHADOW_CONTROL_RAW="$(sh "$BIN/stats_shadow_control.sh" json 2>/dev/null)"
fi

STATS_SOURCE_RAW=""
STATS_SOURCE_PRESENT=false
if [ -x "$BIN/stats_source_diag.sh" ]; then
  STATS_SOURCE_PRESENT=true
  STATS_SOURCE_RAW="$(sh "$BIN/stats_source_diag.sh" json 2>/dev/null)"
fi

STATS_COMPARE_RAW=""
STATS_COMPARE_PRESENT=false
if [ -x "$BIN/stats_compare.sh" ]; then
  STATS_COMPARE_PRESENT=true
  STATS_COMPARE_RAW="$(sh "$BIN/stats_compare.sh" json 2>/dev/null)"
fi

STATS_HEALTH_RAW=""
STATS_HEALTH_PRESENT=false
if [ -x "$BIN/stats_health_summary.sh" ]; then
  STATS_HEALTH_PRESENT=true
  STATS_HEALTH_RAW="$(sh "$BIN/stats_health_summary.sh" json 2>/dev/null)"
  case "$STATS_HEALTH_RAW" in
    *'"status":"fail"'*) OVERALL="fail" ;;
    *'"status":"warn"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_MIGRATION_READINESS_RAW=""
STATS_MIGRATION_READINESS_PRESENT=false
if [ -x "$BIN/stats_migration_readiness.sh" ]; then
  STATS_MIGRATION_READINESS_PRESENT=true
  STATS_MIGRATION_READINESS_RAW="$(sh "$BIN/stats_migration_readiness.sh" json 2>/dev/null)"
  case "$STATS_MIGRATION_READINESS_RAW" in
    *'"status":"blocked"'*) OVERALL="fail" ;;
    *'"status":"not_ready"'*|*'"status":"warmup"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi


STATS_V52_RC_RAW=""
STATS_V52_RC_PRESENT=false
if [ -x "$BIN/stats_v52_rc_control.sh" ]; then
  STATS_V52_RC_PRESENT=true
  STATS_V52_RC_RAW="$(sh "$BIN/stats_v52_rc_control.sh" json 2>/dev/null)"
  case "$STATS_V52_RC_RAW" in
    *'"status":"blocked"'*|*'"status":"enabled_not_ready"'*) OVERALL="fail" ;;
    *'"status":"disabled"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_RC_SMOKE_RAW=""
STATS_V52_RC_SMOKE_PRESENT=false
if [ -x "$BIN/stats_v52_rc_smoke.sh" ]; then
  STATS_V52_RC_SMOKE_PRESENT=true
  STATS_V52_RC_SMOKE_RAW="$(sh "$BIN/stats_v52_rc_smoke.sh" json 2>/dev/null)"
  case "$STATS_V52_RC_SMOKE_RAW" in
    *'"status":"fail"'*) OVERALL="fail" ;;
    *'"status":"warn"'*|*'"status":"disabled"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_DIAG_BUNDLE_RAW=""
STATS_V52_DIAG_BUNDLE_PRESENT=false
if [ -x "$BIN/stats_v52_diag_bundle.sh" ]; then
  STATS_V52_DIAG_BUNDLE_PRESENT=true
  STATS_V52_DIAG_BUNDLE_RAW="$(sh "$BIN/stats_v52_diag_bundle.sh" json 2>/dev/null)"
  case "$STATS_V52_DIAG_BUNDLE_RAW" in
    *'"status":"fail"'*) OVERALL="fail" ;;
    *'"status":"warn"'*|*'"status":"disabled"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_DEVICE_CHECK_RAW=""
STATS_V52_DEVICE_CHECK_PRESENT=false
if [ -x "$BIN/stats_v52_device_check.sh" ]; then
  STATS_V52_DEVICE_CHECK_PRESENT=true
  STATS_V52_DEVICE_CHECK_RAW="$(sh "$BIN/stats_v52_device_check.sh" json 2>/dev/null)"
  case "$STATS_V52_DEVICE_CHECK_RAW" in
    *'"status":"fail"'*) OVERALL="fail" ;;
    *'"status":"warn"'*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_RC1_SWITCH_RAW=""
STATS_V52_RC1_SWITCH_PRESENT=false
if [ -x "$BIN/stats_v52_rc1_switch.sh" ]; then
  STATS_V52_RC1_SWITCH_PRESENT=true
  STATS_V52_RC1_SWITCH_RAW="$(sh "$BIN/stats_v52_rc1_switch.sh" json 2>/dev/null)"
  case "$STATS_V52_RC1_SWITCH_RAW" in
    *"status":"blocked"*|*"status":"drift"*) OVERALL="fail" ;;
    *"legacy_default_preserved":false*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_WEB_STATUS_RAW=""
STATS_V52_WEB_STATUS_PRESENT=false
if [ -x "$BIN/stats_v52_web_status.sh" ]; then
  STATS_V52_WEB_STATUS_PRESENT=true
  STATS_V52_WEB_STATUS_RAW="$(sh "$BIN/stats_v52_web_status.sh" json 2>/dev/null)"
  case "$STATS_V52_WEB_STATUS_RAW" in
    *"severity":"fail"*) OVERALL="fail" ;;
    *"severity":"warn"*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi
STATS_V52_INSTALL_SELFCHECK_RAW=""
STATS_V52_INSTALL_SELFCHECK_PRESENT=false
if [ -x "$BIN/stats_v52_install_selfcheck.sh" ]; then
  STATS_V52_INSTALL_SELFCHECK_PRESENT=true
  STATS_V52_INSTALL_SELFCHECK_RAW="$(sh "$BIN/stats_v52_install_selfcheck.sh" json 2>/dev/null)"
  case "$STATS_V52_INSTALL_SELFCHECK_RAW" in
    *"status":"fail"*) OVERALL="fail" ;;
    *"status":"warn"*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_GRAY_REPORT_RAW=""
STATS_V52_GRAY_REPORT_PRESENT=false
if [ -x "$BIN/stats_v52_gray_report.sh" ]; then
  STATS_V52_GRAY_REPORT_PRESENT=true
  STATS_V52_GRAY_REPORT_RAW="$(sh "$BIN/stats_v52_gray_report.sh" json 2>/dev/null)"
  case "$STATS_V52_GRAY_REPORT_RAW" in
    *"status":"fail"*) OVERALL="fail" ;;
    *"status":"warn"*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi

STATS_V52_REVIEW_BUNDLE_RAW=""
STATS_V52_REVIEW_BUNDLE_PRESENT=false
if [ -x "$BIN/stats_v52_review_bundle.sh" ]; then
  STATS_V52_REVIEW_BUNDLE_PRESENT=true
  STATS_V52_REVIEW_BUNDLE_RAW="$(sh "$BIN/stats_v52_review_bundle.sh" json 2>/dev/null)"
  case "$STATS_V52_REVIEW_BUNDLE_RAW" in
    *"status":"fail"*) OVERALL="fail" ;;
    *"status":"warn"*) [ "$OVERALL" = ok ] && OVERALL="warn" ;;
  esac
fi


# Refresh json_health files if doctor exists, but status is read-only.
[ -x "$BIN/json_doctor.sh" ] && sh "$BIN/json_doctor.sh" status >/dev/null 2>&1

cat <<JSON
{
  "ok": true,
  "timestamp": $TS,
  "overall": "$(json_escape "$OVERALL")",
  "json_doctor_rc": "$DOC_RC",
  "json_doctor_message": "$(json_escape "$DOC_MSG")",
  "files": {
    "rules.json": "$(json_escape "$RULES_STATUS")",
    "device_names.json": "$(json_escape "$NAMES_STATUS")",
    "templates.json": "$(json_escape "$TPL_STATUS")",
    "remote_tokens.json": "$(json_escape "$TOK_STATUS")",
    "devices.json": "$(json_escape "$DEV_STATUS")"
  },
  "backup_count": $BACKUP_COUNT,
  "latest_backup": "$(json_escape "$LATEST_BACKUP")",
  "last_bundle": "$(json_escape "$LAST_BUNDLE")",
  "has_tc_state": $HAS_TC_STATE,
  "has_capabilities": $HAS_CAP,
  "legacy_fallback": {
    "count": $LEGACY_FALLBACK_COUNT,
    "last": "$(json_escape "$LEGACY_FALLBACK_LAST")",
    "has_status_helper": $HAS_LEGACY_FALLBACK_STATUS,
    "log": "$(json_escape "$RUN/json_legacy_fallback.log")",
    "count_file": "$(json_escape "$RUN/json_legacy_fallback.count")"
  },
  "hnc_json_c": {
    "has_status_helper": $HNC_JSON_C_STATUS_PRESENT,
    "status_raw": "$(json_escape "$HNC_JSON_C_STATUS_RAW")"
  },
  "stats": {
    "has_diag_helper": $STATS_DIAG_PRESENT,
    "status_raw": "$(json_escape "$STATS_DIAG_RAW")",
    "has_identity_diag_helper": $STATS_IDENTITY_PRESENT,
    "identity_raw": "$(json_escape "$STATS_IDENTITY_RAW")",
    "has_retention_diag_helper": $STATS_RETENTION_PRESENT,
    "retention_raw": "$(json_escape "$STATS_RETENTION_RAW")",
    "has_shadow_diag_helper": $STATS_SHADOW_PRESENT,
    "has_shadow_rollup_helper": $STATS_SHADOW_ROLLUP_PRESENT,
    "shadow_raw": "$(json_escape "$STATS_SHADOW_RAW")",
    "has_shadow_control_helper": $STATS_SHADOW_CONTROL_PRESENT,
    "shadow_control_raw": "$(json_escape "$STATS_SHADOW_CONTROL_RAW")",
    "has_source_diag_helper": $STATS_SOURCE_PRESENT,
    "source_raw": "$(json_escape "$STATS_SOURCE_RAW")",
    "has_compare_helper": $STATS_COMPARE_PRESENT,
    "compare_raw": "$(json_escape "$STATS_COMPARE_RAW")",
    "has_health_summary_helper": $STATS_HEALTH_PRESENT,
    "health_summary_raw": "$(json_escape "$STATS_HEALTH_RAW")",
    "has_migration_readiness_helper": $STATS_MIGRATION_READINESS_PRESENT,
    "migration_readiness_raw": "$(json_escape "$STATS_MIGRATION_READINESS_RAW")",
    "has_v52_rc_control_helper": $STATS_V52_RC_PRESENT,
    "v52_rc_control_raw": "$(json_escape "$STATS_V52_RC_RAW")",
    "has_v52_rc_smoke_helper": $STATS_V52_RC_SMOKE_PRESENT,
    "v52_rc_smoke_raw": "$(json_escape "$STATS_V52_RC_SMOKE_RAW")"
    ,"has_v52_diag_bundle_helper": $STATS_V52_DIAG_BUNDLE_PRESENT,
    "v52_diag_bundle_raw": "$(json_escape "$STATS_V52_DIAG_BUNDLE_RAW")",
    "has_v52_device_check_helper": $STATS_V52_DEVICE_CHECK_PRESENT,
    "v52_device_check_raw": "$(json_escape "$STATS_V52_DEVICE_CHECK_RAW")",
    "has_v52_rc1_switch_helper": $STATS_V52_RC1_SWITCH_PRESENT,
    "v52_rc1_switch_raw": "$(json_escape "$STATS_V52_RC1_SWITCH_RAW")",
    "has_v52_web_status_helper": $STATS_V52_WEB_STATUS_PRESENT,
    "v52_web_status_raw": "$(json_escape "$STATS_V52_WEB_STATUS_RAW")",
    "has_v52_install_selfcheck_helper": $STATS_V52_INSTALL_SELFCHECK_PRESENT,
    "v52_install_selfcheck_raw": "$(json_escape "$STATS_V52_INSTALL_SELFCHECK_RAW")"
    ,"has_v52_gray_report_helper": $STATS_V52_GRAY_REPORT_PRESENT,
    "v52_gray_report_raw": "$(json_escape "$STATS_V52_GRAY_REPORT_RAW")"
    ,"has_v52_review_bundle_helper": $STATS_V52_REVIEW_BUNDLE_PRESENT,
    "v52_review_bundle_raw": "$(json_escape "$STATS_V52_REVIEW_BUNDLE_RAW")"
  },
  "paths": {
    "json_health_json": "$(json_escape "$RUN/json_health.json")",
    "json_health_txt": "$(json_escape "$RUN/json_health.txt")",
    "backup_dir": "$(json_escape "$BACKUP_DIR")"
  }
}
JSON
