#!/system/bin/sh
# stats_v52_diag_bundle.sh — v5.2 stats diagnostic aggregator (since v5.2-hotfix22.3)
# Read-only single-entry diagnostic for staged v5.2 stats migration.
# It does not enable/disable RC, rewrite stats files, or touch tc/iptables/watchdog.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
MODE=${1:-json}
OUT_JSON="$RUN/stats_v52_diag_bundle.json"
OUT_TXT="$RUN/stats_v52_diag_bundle.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape_into() {
  in="$1"
  outvar="$2"
  out=""
  while [ -n "$in" ]; do
    c=${in%"${in#?}"}
    in=${in#?}
    case "$c" in
      \\) out="${out}\\\\" ;;
      '"') out="${out}\\\"" ;;
      *) out="${out}${c}" ;;
    esac
  done
  eval "$outvar=\$out"
}

helper_json() {
  h="$1"
  if [ -x "$BIN/$h" ]; then
    sh "$BIN/$h" json 2>/dev/null
  else
    echo '{"ok":false,"status":"missing"}'
  fi
}

present_of() { [ -x "$BIN/$1" ] && echo true || echo false; }

status_of_into() {
  v="$1"
  out="$2"
  case "$v" in
    *\"status\":\"*\"*)
      s=${v#*\"status\":\"}
      s=${s%%\"*}
      [ -n "$s" ] || s="unknown"
      ;;
    *) s="unknown" ;;
  esac
  eval "$out=\$s"
}

bool_of_into() {
  key="$1"
  v="$2"
  out="$3"
  prefix="\"$key\":"
  case "$v" in
    *"$prefix"true*) b=true ;;
    *"$prefix"false*) b=false ;;
    *) b=false ;;
  esac
  eval "$out=\$b"
}

class_of_status() {
  case "$1" in
    ok|pass|ready|enabled|legacy|shadow) echo ok ;;
    disabled) echo disabled ;;
    warn|unknown|missing|not_ready|warmup) echo warn ;;
    fail|bad|error|blocked|enabled_not_ready) echo fail ;;
    *) echo warn ;;
  esac
}

DIAG_JSON="$(helper_json stats_diag.sh)"; status_of_into "$DIAG_JSON" DIAG_STATUS
IDENTITY_JSON="$(helper_json stats_identity_diag.sh)"; status_of_into "$IDENTITY_JSON" IDENTITY_STATUS
RETENTION_JSON="$(helper_json stats_retention_diag.sh)"; status_of_into "$RETENTION_JSON" RETENTION_STATUS
SHADOW_JSON="$(helper_json stats_shadow_diag.sh)"; status_of_into "$SHADOW_JSON" SHADOW_STATUS
SHADOW_CONTROL_JSON="$(helper_json stats_shadow_control.sh)"; status_of_into "$SHADOW_CONTROL_JSON" SHADOW_CONTROL_STATUS
SOURCE_JSON="$(helper_json stats_source_diag.sh)"; status_of_into "$SOURCE_JSON" SOURCE_STATUS
COMPARE_JSON="$(helper_json stats_compare.sh)"; status_of_into "$COMPARE_JSON" COMPARE_STATUS
READINESS_JSON="$(helper_json stats_migration_readiness.sh)"; status_of_into "$READINESS_JSON" READINESS_STATUS; bool_of_into ready "$READINESS_JSON" READINESS_READY
RC_JSON="$(helper_json stats_v52_rc_control.sh)"; status_of_into "$RC_JSON" RC_STATUS; bool_of_into enabled "$RC_JSON" RC_ENABLED
SMOKE_JSON="$(helper_json stats_v52_rc_smoke.sh)"; status_of_into "$SMOKE_JSON" SMOKE_STATUS
SUMMARY_JSON="$(helper_json stats_health_summary.sh)"; status_of_into "$SUMMARY_JSON" SUMMARY_STATUS

HAS_DIAG=$(present_of stats_diag.sh)
HAS_IDENTITY=$(present_of stats_identity_diag.sh)
HAS_RETENTION=$(present_of stats_retention_diag.sh)
HAS_SHADOW=$(present_of stats_shadow_diag.sh)
HAS_SHADOW_CONTROL=$(present_of stats_shadow_control.sh)
HAS_SOURCE=$(present_of stats_source_diag.sh)
HAS_COMPARE=$(present_of stats_compare.sh)
HAS_READINESS=$(present_of stats_migration_readiness.sh)
HAS_RC=$(present_of stats_v52_rc_control.sh)
HAS_SMOKE=$(present_of stats_v52_rc_smoke.sh)
HAS_SUMMARY=$(present_of stats_health_summary.sh)

STATUS="pass"
RECOMMENDATION="v5.2 stats diagnostic bundle is healthy; continue staged monitoring"

# RC disabled is safe, but not a pass for switching. Keep it distinct so UI/diagnostics
# can show that legacy stats should remain the default.
if [ "$RC_ENABLED" != true ] || [ "$SMOKE_STATUS" = disabled ] || [ "$RC_STATUS" = disabled ]; then
  STATUS="disabled"
  RECOMMENDATION="v5.2 stats RC is disabled; keep legacy stats active and use diagnostics for readiness tracking"
fi

for s in "$DIAG_STATUS" "$IDENTITY_STATUS" "$RETENTION_STATUS" "$SHADOW_STATUS" "$SHADOW_CONTROL_STATUS" "$SOURCE_STATUS" "$COMPARE_STATUS" "$READINESS_STATUS" "$RC_STATUS" "$SMOKE_STATUS" "$SUMMARY_STATUS"; do
  c="$(class_of_status "$s")"
  case "$c" in
    fail) STATUS="fail" ;;
    warn) [ "$STATUS" = pass ] && STATUS="warn" ;;
  esac
done

# If RC is enabled, readiness and smoke must be clean.
if [ "$RC_ENABLED" = true ]; then
  if [ "$READINESS_READY" != true ] || [ "$READINESS_STATUS" != ready ]; then
    STATUS="fail"
    RECOMMENDATION="v5.2 stats RC is enabled but migration readiness is not ready; disable RC and inspect diagnostics"
  elif [ "$SMOKE_STATUS" != pass ]; then
    STATUS="fail"
    RECOMMENDATION="v5.2 stats RC is enabled but smoke gate did not pass; disable RC and collect a diagnostic bundle"
  fi
fi

if [ "$STATUS" = fail ] && [ "$RECOMMENDATION" = "v5.2 stats diagnostic bundle is healthy; continue staged monitoring" ]; then
  RECOMMENDATION="v5.2 stats diagnostics found a failing component; do not switch stats source and collect diagnostics"
elif [ "$STATUS" = warn ]; then
  RECOMMENDATION="v5.2 stats diagnostics have warnings; keep legacy fallback and collect more samples"
fi

{
  echo "HNC v5.2 stats diagnostic bundle"
  echo "status=$STATUS"
  echo "recommendation=$RECOMMENDATION"
  echo "stats_health_summary=$SUMMARY_STATUS"
  echo "stats_v52_rc_control=$RC_STATUS"
  echo "stats_v52_rc_enabled=$RC_ENABLED"
  echo "stats_v52_rc_smoke=$SMOKE_STATUS"
  echo "stats_migration_readiness=$READINESS_STATUS"
  echo "stats_migration_ready=$READINESS_READY"
  echo "stats_compare=$COMPARE_STATUS"
  echo "stats_source=$SOURCE_STATUS"
  echo "stats_shadow=$SHADOW_STATUS"
  echo "stats_shadow_control=$SHADOW_CONTROL_STATUS"
  echo "stats_diag=$DIAG_STATUS"
  echo "stats_identity=$IDENTITY_STATUS"
  echo "stats_retention=$RETENTION_STATUS"
} > "$OUT_TXT"

json_escape_into "$STATUS" E_STATUS
json_escape_into "$RECOMMENDATION" E_RECOMMENDATION
json_escape_into "$SUMMARY_STATUS" E_SUMMARY
json_escape_into "$RC_STATUS" E_RC
json_escape_into "$SMOKE_STATUS" E_SMOKE
json_escape_into "$READINESS_STATUS" E_READINESS
json_escape_into "$COMPARE_STATUS" E_COMPARE
json_escape_into "$SOURCE_STATUS" E_SOURCE
json_escape_into "$SHADOW_STATUS" E_SHADOW
json_escape_into "$SHADOW_CONTROL_STATUS" E_SHADOW_CONTROL
json_escape_into "$DIAG_STATUS" E_DIAG
json_escape_into "$IDENTITY_STATUS" E_IDENTITY
json_escape_into "$RETENTION_STATUS" E_RETENTION
json_escape_into "$OUT_JSON" E_OUT_JSON
json_escape_into "$OUT_TXT" E_OUT_TXT

printf '{"ok":true,"status":"%s","recommendation":"%s","helpers":{"stats_health_summary":%s,"stats_v52_rc_control":%s,"stats_v52_rc_smoke":%s,"stats_migration_readiness":%s,"stats_compare":%s,"stats_source_diag":%s,"stats_shadow_diag":%s,"stats_shadow_control":%s,"stats_diag":%s,"stats_identity_diag":%s,"stats_retention_diag":%s},"components":{"stats_health_summary":"%s","stats_v52_rc_control":"%s","stats_v52_rc_enabled":%s,"stats_v52_rc_smoke":"%s","stats_migration_readiness":"%s","stats_migration_ready":%s,"stats_compare":"%s","stats_source":"%s","stats_shadow":"%s","stats_shadow_control":"%s","stats_diag":"%s","stats_identity":"%s","stats_retention":"%s"},"paths":{"json":"%s","text":"%s"}}\n' \
  "$E_STATUS" "$E_RECOMMENDATION" "$HAS_SUMMARY" "$HAS_RC" "$HAS_SMOKE" "$HAS_READINESS" "$HAS_COMPARE" "$HAS_SOURCE" "$HAS_SHADOW" "$HAS_SHADOW_CONTROL" "$HAS_DIAG" "$HAS_IDENTITY" "$HAS_RETENTION" \
  "$E_SUMMARY" "$E_RC" "$RC_ENABLED" "$E_SMOKE" "$E_READINESS" "$READINESS_READY" "$E_COMPARE" "$E_SOURCE" "$E_SHADOW" "$E_SHADOW_CONTROL" "$E_DIAG" "$E_IDENTITY" "$E_RETENTION" "$E_OUT_JSON" "$E_OUT_TXT" > "$OUT_JSON"

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  *) cat "$OUT_JSON" ;;
esac
exit 0
