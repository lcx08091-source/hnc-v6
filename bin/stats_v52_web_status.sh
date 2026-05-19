#!/system/bin/sh
# stats_v52_web_status.sh — compact read-only v5.2 RC status for WebUI.
# It aggregates existing v5.2 diagnostics into a small JSON/TXT card payload.
# Read-only: does not enable RC, does not change stats source, and does not touch
# tc/iptables/watchdog/network rules.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
OUT_JSON="$RUN/stats_v52_web_status.json"
OUT_TXT="$RUN/stats_v52_web_status.txt"
TS="$(date +%s 2>/dev/null || echo 0)"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
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
  body="$1"
  case "$body" in *\"status\":\"*\"*) s=${body#*\"status\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo unknown ;; esac
}

bool_key_of() {
  key="$1"; body="$2"
  case "$body" in *\"$key\":true*) echo true ;; *\"$key\":false*) echo false ;; *) echo false ;; esac
}

str_key_of() {
  key="$1"; body="$2"; def="$3"
  case "$body" in *\"$key\":\"*\"*) s=${body#*\"$key\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo "$def" ;; esac
}

rc1_json="$(helper_json stats_v52_rc1_switch.sh)"
device_json="$(helper_json stats_v52_device_check.sh)"
smoke_json="$(helper_json stats_v52_rc_smoke.sh)"
readiness_json="$(helper_json stats_migration_readiness.sh)"
health_json="$(helper_json stats_health_summary.sh)"
compare_json="$(helper_json stats_compare.sh)"
source_json="$(helper_json stats_source_diag.sh)"
shadow_json="$(helper_json stats_shadow_control.sh)"

rc1_status="$(status_of "$rc1_json")"
device_status="$(status_of "$device_json")"
smoke_status="$(status_of "$smoke_json")"
readiness_status="$(status_of "$readiness_json")"
health_status="$(status_of "$health_json")"
compare_status="$(status_of "$compare_json")"
source_status="$(status_of "$source_json")"
shadow_status="$(status_of "$shadow_json")"

rc1_enabled="$(bool_key_of rc1_enabled "$rc1_json")"
rc_enabled="$(bool_key_of rc_enabled "$rc1_json")"
shadow_effective="$(bool_key_of shadow_effective_enabled "$rc1_json")"
legacy_default_preserved="$(bool_key_of legacy_default_preserved "$rc1_json")"
rc_enable_ready="$(bool_key_of rc_enable_ready "$device_json")"
default_source="$(str_key_of default_source "$rc1_json" legacy)"

status="$rc1_status"
severity="ok"
phase="legacy_default"
recommendation="legacy stats is default; run device_check before enabling v5.2 RC"

[ "$rc1_enabled" = true ] && phase="v52_rc1_gray"
[ "$rc1_enabled" = true ] && recommendation="monitor stats_compare/readiness/smoke; run rollback on anomalies"
[ "$rc1_enabled" = false ] && [ "$rc_enable_ready" = true ] && recommendation="device gate is ready; v5.2 RC can be enabled manually when you want to gray test"

case "$rc1_status" in
  blocked|drift|fail) severity="fail"; phase="blocked"; recommendation="run rollback/disable and inspect device_check before retrying" ;;
  enabled) severity="ok" ;;
  disabled) severity="ok" ;;
  *) severity="warn" ;;
esac

case "$health_status $device_status $smoke_status $readiness_status $compare_status" in
  *fail*|*blocked*) severity="fail" ;;
  *warn*|*not_ready*|*warmup*) [ "$severity" = ok ] && severity="warn" ;;
esac

[ "$legacy_default_preserved" = false ] && [ "$severity" = ok ] && severity="warn"
[ "$default_source" != legacy ] && [ "$severity" = ok ] && severity="warn"

{
  echo "HNC v5.2 RC WebUI status"
  echo "status=$status"
  echo "severity=$severity"
  echo "phase=$phase"
  echo "rc1_enabled=$rc1_enabled"
  echo "rc_enabled=$rc_enabled"
  echo "shadow_effective_enabled=$shadow_effective"
  echo "default_source=$default_source"
  echo "legacy_default_preserved=$legacy_default_preserved"
  echo "rc_enable_ready=$rc_enable_ready"
  echo "health_status=$health_status"
  echo "device_check_status=$device_status"
  echo "smoke_status=$smoke_status"
  echo "readiness_status=$readiness_status"
  echo "compare_status=$compare_status"
  echo "source_status=$source_status"
  echo "shadow_status=$shadow_status"
  echo "recommendation=$recommendation"
} > "$OUT_TXT"

cat > "$OUT_JSON" <<JSON
{"ok":true,"timestamp":$TS,"status":"$(json_escape "$status")","severity":"$(json_escape "$severity")","phase":"$(json_escape "$phase")","rc1_enabled":$rc1_enabled,"rc_enabled":$rc_enabled,"shadow_effective_enabled":$shadow_effective,"default_source":"$(json_escape "$default_source")","legacy_default_preserved":$legacy_default_preserved,"rc_enable_ready":$rc_enable_ready,"health_status":"$(json_escape "$health_status")","device_check_status":"$(json_escape "$device_status")","smoke_status":"$(json_escape "$smoke_status")","readiness_status":"$(json_escape "$readiness_status")","compare_status":"$(json_escape "$compare_status")","source_status":"$(json_escape "$source_status")","shadow_status":"$(json_escape "$shadow_status")","recommendation":"$(json_escape "$recommendation")","paths":{"json":"$(json_escape "$OUT_JSON")","text":"$(json_escape "$OUT_TXT")"}}
JSON

case "${1:-text}" in
  json) cat "$OUT_JSON" ;;
  *) cat "$OUT_TXT" ;;
esac
exit 0
