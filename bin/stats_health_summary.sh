#!/system/bin/sh
# stats_health_summary.sh — HNC hotfix22.2 stats health summary
# Read-only aggregator for staged v5.2 stats migration.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
MODE=${1:-json}
OUT_JSON="$RUN/stats_health_summary.json"
OUT_TXT="$RUN/stats_health_summary.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape_into() {
  in="$1"
  outvar="$2"
  out=""
  while [ -n "$in" ]; do
    c=${in%"${in#?}"}
    in=${in#?}
    case "$c" in
      \\) out="${out}\\\\"
        ;;
      '"') out="${out}\\\""
        ;;
      *) out="${out}${c}"
        ;;
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

status_of() {
  v="$1"
  case "$v" in
    *\"status\":\"*\"*)
      s=${v#*\"status\":\"}
      s=${s%%\"*}
      [ -n "$s" ] || s="unknown"
      echo "$s"
      ;;
    *) echo "unknown" ;;
  esac
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

_j="$(helper_json stats_diag.sh)"; status_of_into "$_j" DIAG_STATUS
_j="$(helper_json stats_identity_diag.sh)"; status_of_into "$_j" IDENT_STATUS
_j="$(helper_json stats_retention_diag.sh)"; status_of_into "$_j" RET_STATUS
_j="$(helper_json stats_shadow_diag.sh)"; status_of_into "$_j" SHADOW_STATUS
_j="$(helper_json stats_shadow_control.sh)"; status_of_into "$_j" SHADOW_CONTROL_STATUS
_j="$(helper_json stats_source_diag.sh)"; status_of_into "$_j" SOURCE_STATUS
_j="$(helper_json stats_compare.sh)"; status_of_into "$_j" COMPARE_STATUS
_j="$(helper_json stats_migration_readiness.sh)"; status_of_into "$_j" READINESS_STATUS
_j="$(helper_json stats_v52_rc_control.sh)"; status_of_into "$_j" V52_RC_STATUS
_j="$(helper_json stats_v52_rc_smoke.sh)"; status_of_into "$_j" V52_RC_SMOKE_STATUS

OVERALL="ok"
RECOMMENDATION="stats diagnostics look healthy"
for s in "$DIAG_STATUS" "$IDENT_STATUS" "$RET_STATUS" "$SHADOW_STATUS" "$SHADOW_CONTROL_STATUS" "$SOURCE_STATUS" "$COMPARE_STATUS" "$READINESS_STATUS" "$V52_RC_STATUS" "$V52_RC_SMOKE_STATUS"; do
  case "$s" in
    fail|bad|error|blocked|enabled_not_ready) OVERALL="fail" ;;
    warn|missing|unknown|not_ready|warmup|disabled) [ "$OVERALL" = "ok" ] && OVERALL="warn" ;;
  esac
done
if [ "$OVERALL" = "fail" ]; then
  RECOMMENDATION="do not switch to new stats; inspect diagnostics bundle first"
elif [ "$OVERALL" = "warn" ]; then
  RECOMMENDATION="keep legacy stats active; shadow stats may need more samples or cleanup"
fi

HAS_DIAG=$(present_of stats_diag.sh)
HAS_ID=$(present_of stats_identity_diag.sh)
HAS_RET=$(present_of stats_retention_diag.sh)
HAS_SHADOW=$(present_of stats_shadow_diag.sh)
HAS_SHADOW_CONTROL=$(present_of stats_shadow_control.sh)
HAS_SOURCE=$(present_of stats_source_diag.sh)
HAS_COMPARE=$(present_of stats_compare.sh)
HAS_READINESS=$(present_of stats_migration_readiness.sh)
HAS_V52_RC=$(present_of stats_v52_rc_control.sh)
HAS_V52_RC_SMOKE=$(present_of stats_v52_rc_smoke.sh)

{
  echo "HNC stats health summary"
  echo "status=$OVERALL"
  echo "recommendation=$RECOMMENDATION"
  echo "stats_diag=$DIAG_STATUS"
  echo "stats_identity=$IDENT_STATUS"
  echo "stats_retention=$RET_STATUS"
  echo "stats_shadow=$SHADOW_STATUS"
  echo "stats_shadow_control=$SHADOW_CONTROL_STATUS"
  echo "stats_source=$SOURCE_STATUS"
  echo "stats_compare=$COMPARE_STATUS"
  echo "stats_migration_readiness=$READINESS_STATUS"
  echo "stats_v52_rc_control=$V52_RC_STATUS"
  echo "stats_v52_rc_smoke=$V52_RC_SMOKE_STATUS"
  echo "has_stats_diag=$HAS_DIAG"
  echo "has_stats_identity_diag=$HAS_ID"
  echo "has_stats_retention_diag=$HAS_RET"
  echo "has_stats_shadow_diag=$HAS_SHADOW"
  echo "has_stats_shadow_control=$HAS_SHADOW_CONTROL"
  echo "has_stats_source_diag=$HAS_SOURCE"
  echo "has_stats_compare=$HAS_COMPARE"
  echo "has_stats_migration_readiness=$HAS_READINESS"
  echo "has_stats_v52_rc_control=$HAS_V52_RC"
  echo "has_stats_v52_rc_smoke=$HAS_V52_RC_SMOKE"
} > "$OUT_TXT"

json_escape_into "$OVERALL" EO
json_escape_into "$RECOMMENDATION" ER
json_escape_into "$DIAG_STATUS" ED
json_escape_into "$IDENT_STATUS" EI
json_escape_into "$RET_STATUS" ET
json_escape_into "$SHADOW_STATUS" ES
json_escape_into "$SHADOW_CONTROL_STATUS" ESC
json_escape_into "$SOURCE_STATUS" ESO
json_escape_into "$COMPARE_STATUS" EC
json_escape_into "$READINESS_STATUS" EM
json_escape_into "$V52_RC_STATUS" EV
json_escape_into "$V52_RC_SMOKE_STATUS" EK
json_escape_into "$OUT_JSON" EJ
json_escape_into "$OUT_TXT" EX

printf '{"ok":true,"status":"%s","recommendation":"%s","helpers":{"stats_diag":%s,"stats_identity_diag":%s,"stats_retention_diag":%s,"stats_shadow_diag":%s,"stats_shadow_control":%s,"stats_source_diag":%s,"stats_compare":%s,"stats_migration_readiness":%s,"stats_v52_rc_control":%s,"stats_v52_rc_smoke":%s},"components":{"stats_diag":"%s","stats_identity":"%s","stats_retention":"%s","stats_shadow":"%s","stats_shadow_control":"%s","stats_source":"%s","stats_compare":"%s","stats_migration_readiness":"%s","stats_v52_rc_control":"%s","stats_v52_rc_smoke":"%s"},"paths":{"json":"%s","text":"%s"}}\n' \
  "$EO" "$ER" "$HAS_DIAG" "$HAS_ID" "$HAS_RET" "$HAS_SHADOW" "$HAS_SHADOW_CONTROL" "$HAS_SOURCE" "$HAS_COMPARE" "$HAS_READINESS" "$HAS_V52_RC" "$HAS_V52_RC_SMOKE" \
  "$ED" "$EI" "$ET" "$ES" "$ESC" "$ESO" "$EC" "$EM" "$EV" "$EK" "$EJ" "$EX" > "$OUT_JSON"

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  *) cat "$OUT_JSON" ;;
esac
exit 0
