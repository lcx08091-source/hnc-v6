#!/system/bin/sh
# stats_v52_device_check.sh — HNC hotfix22.4 v5.2 stats real-device pre-RC check
# Read-only one-shot checker for real-device v5.2 stats RC validation.
# It does not enable/disable RC, rewrite stats files, run capability_probe, or touch tc/iptables/watchdog.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
DATA="$HNC_DIR/data"
MODE=${1:-json}
OUT_JSON="$RUN/stats_v52_device_check.json"
OUT_TXT="$RUN/stats_v52_device_check.txt"
BUNDLE="$RUN/stats_v52_device_check_bundle.tgz"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  in="$1"
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
  printf '%s' "$out"
}

one_line() { printf '%s' "$1" | tr '\r\n\t' '   ' | cut -c1-220; }

getprop_safe() {
  k="$1"
  if command -v getprop >/dev/null 2>&1; then
    getprop "$k" 2>/dev/null | head -1 | tr -d '\r' | cut -c1-160
  else
    echo ""
  fi
}

file_lines() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -l < "$f" 2>/dev/null | tr -d ' ' | sed 's/[^0-9].*$//'
}

file_size() {
  f="$1"
  [ -f "$f" ] || { echo 0; return; }
  wc -c < "$f" 2>/dev/null | tr -d ' ' | sed 's/[^0-9].*$//'
}

present_of() { [ -x "$BIN/$1" ] && echo true || echo false; }

helper_json() {
  h="$1"
  if [ -x "$BIN/$h" ]; then
    sh "$BIN/$h" json 2>/dev/null
  else
    echo '{"ok":false,"status":"missing"}'
  fi
}

status_of_into() {
  v="$1"
  case "$v" in
    *\"status\":\"*\"*)
      s=${v#*\"status\":\"}
      s=${s%%\"*}
      [ -n "$s" ] || s="unknown"
      ;;
    *) s="unknown" ;;
  esac
  printf '%s' "$s"
}

bool_of_into() {
  key="$1"
  v="$2"
  prefix="\"$key\":"
  case "$v" in
    *"$prefix"true*) b=true ;;
    *"$prefix"false*) b=false ;;
    *) b=false ;;
  esac
  printf '%s' "$b"
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

module_version=""
module_code=""
if [ -f "$HNC_DIR/module.prop" ]; then
  module_version="$(sed -n 's/^version=//p' "$HNC_DIR/module.prop" 2>/dev/null | head -1 | tr -d '\r')"
  module_code="$(sed -n 's/^versionCode=//p' "$HNC_DIR/module.prop" 2>/dev/null | head -1 | tr -d '\r')"
fi
[ -n "$module_version" ] || module_version="unknown"
[ -n "$module_code" ] || module_code="unknown"

manufacturer="$(getprop_safe ro.product.manufacturer)"
brand="$(getprop_safe ro.product.brand)"
model="$(getprop_safe ro.product.model)"
device="$(getprop_safe ro.product.device)"
android_release="$(getprop_safe ro.build.version.release)"
android_sdk="$(getprop_safe ro.build.version.sdk)"
build_incremental="$(getprop_safe ro.build.version.incremental)"
kernel="$(uname -r 2>/dev/null | head -1 | tr -d '\r' | cut -c1-160)"
[ -n "$kernel" ] || kernel="unknown"
iface="$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n' | cut -c1-80)"
[ -n "$iface" ] || iface="unknown"

capabilities_json_present=false
[ -s "$RUN/capabilities.json" ] && capabilities_json_present=true
cap_summary=""
if [ -s "$RUN/capabilities.json" ]; then
  cap_summary="$(tr '\r\n\t' '   ' < "$RUN/capabilities.json" 2>/dev/null | cut -c1-500)"
fi

legacy_raw="$DATA/stats_raw.jsonl"
legacy_daily="$DATA/stats_daily.jsonl"
shadow_raw="$DATA/stats_shadow_raw.jsonl"
shadow_daily="$DATA/stats_shadow_daily.jsonl"
legacy_raw_lines=$(file_lines "$legacy_raw")
legacy_daily_lines=$(file_lines "$legacy_daily")
shadow_raw_lines=$(file_lines "$shadow_raw")
shadow_daily_lines=$(file_lines "$shadow_daily")
legacy_raw_size=$(file_size "$legacy_raw")
legacy_daily_size=$(file_size "$legacy_daily")
shadow_raw_size=$(file_size "$shadow_raw")
shadow_daily_size=$(file_size "$shadow_daily")

DIAG_BUNDLE_JSON="$(helper_json stats_v52_diag_bundle.sh)"; DIAG_BUNDLE_STATUS=$(status_of_into "$DIAG_BUNDLE_JSON")
SUMMARY_JSON="$(helper_json stats_health_summary.sh)"; SUMMARY_STATUS=$(status_of_into "$SUMMARY_JSON")
RC_JSON="$(helper_json stats_v52_rc_control.sh)"; RC_STATUS=$(status_of_into "$RC_JSON"); RC_ENABLED=$(bool_of_into enabled "$RC_JSON")
SMOKE_JSON="$(helper_json stats_v52_rc_smoke.sh)"; SMOKE_STATUS=$(status_of_into "$SMOKE_JSON")
READINESS_JSON="$(helper_json stats_migration_readiness.sh)"; READINESS_STATUS=$(status_of_into "$READINESS_JSON"); READINESS_READY=$(bool_of_into ready "$READINESS_JSON")
COMPARE_JSON="$(helper_json stats_compare.sh)"; COMPARE_STATUS=$(status_of_into "$COMPARE_JSON")
SOURCE_JSON="$(helper_json stats_source_diag.sh)"; SOURCE_STATUS=$(status_of_into "$SOURCE_JSON")
SHADOW_JSON="$(helper_json stats_shadow_diag.sh)"; SHADOW_STATUS=$(status_of_into "$SHADOW_JSON")
SHADOW_CONTROL_JSON="$(helper_json stats_shadow_control.sh)"; SHADOW_CONTROL_STATUS=$(status_of_into "$SHADOW_CONTROL_JSON")
IDENTITY_JSON="$(helper_json stats_identity_diag.sh)"; IDENTITY_STATUS=$(status_of_into "$IDENTITY_JSON")
RETENTION_JSON="$(helper_json stats_retention_diag.sh)"; RETENTION_STATUS=$(status_of_into "$RETENTION_JSON")
BASE_DIAG_JSON="$(helper_json stats_diag.sh)"; BASE_DIAG_STATUS=$(status_of_into "$BASE_DIAG_JSON")

HAS_DIAG_BUNDLE=$(present_of stats_v52_diag_bundle.sh)
HAS_SUMMARY=$(present_of stats_health_summary.sh)
HAS_RC=$(present_of stats_v52_rc_control.sh)
HAS_SMOKE=$(present_of stats_v52_rc_smoke.sh)
HAS_READINESS=$(present_of stats_migration_readiness.sh)
HAS_COMPARE=$(present_of stats_compare.sh)
HAS_SOURCE=$(present_of stats_source_diag.sh)
HAS_SHADOW=$(present_of stats_shadow_diag.sh)
HAS_SHADOW_CONTROL=$(present_of stats_shadow_control.sh)
HAS_IDENTITY=$(present_of stats_identity_diag.sh)
HAS_RETENTION=$(present_of stats_retention_diag.sh)
HAS_BASE_DIAG=$(present_of stats_diag.sh)

STATUS="pass"
STAGE="monitor"
RECOMMENDATION="real-device v5.2 stats checks are clean; continue staged monitoring with legacy rollback available"

for s in "$DIAG_BUNDLE_STATUS" "$SUMMARY_STATUS" "$RC_STATUS" "$SMOKE_STATUS" "$READINESS_STATUS" "$COMPARE_STATUS" "$SOURCE_STATUS" "$SHADOW_STATUS" "$SHADOW_CONTROL_STATUS" "$IDENTITY_STATUS" "$RETENTION_STATUS" "$BASE_DIAG_STATUS"; do
  c="$(class_of_status "$s")"
  case "$c" in
    fail) STATUS="fail" ;;
    warn) [ "$STATUS" = pass ] && STATUS="warn" ;;
  esac
done

if [ "$HAS_DIAG_BUNDLE" != true ] || [ "$HAS_SUMMARY" != true ] || [ "$HAS_RC" != true ] || [ "$HAS_SMOKE" != true ] || [ "$HAS_READINESS" != true ] || [ "$HAS_COMPARE" != true ]; then
  STATUS="fail"
  STAGE="blocked"
  RECOMMENDATION="required v5.2 stats diagnostic helpers are missing; do not enter v5.2 RC"
elif [ "$RC_ENABLED" = true ]; then
  STAGE="rc_enabled"
  if [ "$SMOKE_STATUS" != pass ] || [ "$READINESS_READY" != true ]; then
    STATUS="fail"
    RECOMMENDATION="v5.2 stats RC is enabled but smoke/readiness is not clean; disable RC and collect diagnostics"
  elif [ "$STATUS" = pass ]; then
    RECOMMENDATION="v5.2 stats RC is enabled and checks pass; continue real-device monitoring before default switch"
  fi
elif [ "$READINESS_READY" = true ] && [ "$SMOKE_STATUS" = disabled ]; then
  STAGE="ready_rc_disabled"
  [ "$STATUS" = pass ] && STATUS="warn"
  RECOMMENDATION="readiness is ready but RC is disabled; safe to start controlled v5.2-rc1 testing, keep legacy default"
elif [ "$READINESS_STATUS" = blocked ]; then
  STATUS="fail"
  STAGE="blocked"
  RECOMMENDATION="stats migration readiness is blocked; keep legacy stats and inspect failing diagnostics"
elif [ "$READINESS_STATUS" = warmup ] || [ "$READINESS_STATUS" = not_ready ] || [ "$SMOKE_STATUS" = disabled ]; then
  [ "$STATUS" = pass ] && STATUS="warn"
  STAGE="warmup"
  RECOMMENDATION="v5.2 stats is still warming up or RC is disabled; keep legacy stats and collect more real-device samples"
fi

NOW=$(date +%s 2>/dev/null || echo 0)

{
  echo "HNC v5.2 stats real-device check"
  echo "status=$STATUS"
  echo "stage=$STAGE"
  echo "recommendation=$RECOMMENDATION"
  echo "module_version=$module_version"
  echo "module_version_code=$module_code"
  echo "manufacturer=$manufacturer"
  echo "brand=$brand"
  echo "model=$model"
  echo "device=$device"
  echo "android_release=$android_release"
  echo "android_sdk=$android_sdk"
  echo "build_incremental=$build_incremental"
  echo "kernel=$kernel"
  echo "hotspot_iface=$iface"
  echo "capabilities_json_present=$capabilities_json_present"
  echo "stats_v52_diag_bundle=$DIAG_BUNDLE_STATUS"
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
  echo "stats_identity=$IDENTITY_STATUS"
  echo "stats_retention=$RETENTION_STATUS"
  echo "stats_diag=$BASE_DIAG_STATUS"
  echo "legacy_raw_lines=$legacy_raw_lines"
  echo "legacy_daily_lines=$legacy_daily_lines"
  echo "shadow_raw_lines=$shadow_raw_lines"
  echo "shadow_daily_lines=$shadow_daily_lines"
  echo "json=$OUT_JSON"
  echo "text=$OUT_TXT"
} > "$OUT_TXT"

# Optional local bundle for copying out after a real-device run. This only archives
# generated diagnostics and does not mutate live stats data.
if [ "$MODE" = bundle ] || [ "$MODE" = collect ]; then
  oldpwd="$(pwd 2>/dev/null || echo /)"
  cd "$RUN" 2>/dev/null || true
  if command -v tar >/dev/null 2>&1; then
    tar -czf "$BUNDLE" \
      stats_v52_device_check.json stats_v52_device_check.txt \
      stats_v52_diag_bundle.json stats_v52_diag_bundle.txt \
      stats_health_summary.json stats_health_summary.txt \
      stats_v52_rc_control.json stats_v52_rc_control.txt \
      stats_v52_rc_smoke.json stats_v52_rc_smoke.txt \
      stats_migration_readiness.json stats_migration_readiness.txt \
      stats_compare.json stats_compare.txt \
      stats_source_diag.json stats_shadow_diag.json stats_retention_diag.json stats_identity_diag.json \
      capabilities.json 2>/dev/null || true
  fi
  cd "$oldpwd" 2>/dev/null || true
fi

E_STATUS=$(json_escape "$STATUS")
E_STAGE=$(json_escape "$STAGE")
E_RECOMMENDATION=$(json_escape "$RECOMMENDATION")
E_MODULE_VERSION=$(json_escape "$module_version")
E_MODULE_CODE=$(json_escape "$module_code")
E_MANUFACTURER=$(json_escape "$manufacturer")
E_BRAND=$(json_escape "$brand")
E_MODEL=$(json_escape "$model")
E_DEVICE=$(json_escape "$device")
E_ANDROID_RELEASE=$(json_escape "$android_release")
E_ANDROID_SDK=$(json_escape "$android_sdk")
E_BUILD_INCREMENTAL=$(json_escape "$build_incremental")
E_KERNEL=$(json_escape "$kernel")
E_IFACE=$(json_escape "$iface")
E_DIAG_BUNDLE=$(json_escape "$DIAG_BUNDLE_STATUS")
E_SUMMARY=$(json_escape "$SUMMARY_STATUS")
E_RC=$(json_escape "$RC_STATUS")
E_SMOKE=$(json_escape "$SMOKE_STATUS")
E_READINESS=$(json_escape "$READINESS_STATUS")
E_COMPARE=$(json_escape "$COMPARE_STATUS")
E_SOURCE=$(json_escape "$SOURCE_STATUS")
E_SHADOW=$(json_escape "$SHADOW_STATUS")
E_SHADOW_CONTROL=$(json_escape "$SHADOW_CONTROL_STATUS")
E_IDENTITY=$(json_escape "$IDENTITY_STATUS")
E_RETENTION=$(json_escape "$RETENTION_STATUS")
E_BASE_DIAG=$(json_escape "$BASE_DIAG_STATUS")
E_CAP_SUMMARY=$(json_escape "$cap_summary")
E_OUT_JSON=$(json_escape "$OUT_JSON")
E_OUT_TXT=$(json_escape "$OUT_TXT")
E_BUNDLE=$(json_escape "$BUNDLE")

printf '{"ok":true,"status":"%s","stage":"%s","recommendation":"%s","timestamp":%s,"module":{"version":"%s","version_code":"%s"},"device":{"manufacturer":"%s","brand":"%s","model":"%s","device":"%s","android_release":"%s","android_sdk":"%s","build_incremental":"%s","kernel":"%s","hotspot_iface":"%s"},"helpers":{"stats_v52_diag_bundle":%s,"stats_health_summary":%s,"stats_v52_rc_control":%s,"stats_v52_rc_smoke":%s,"stats_migration_readiness":%s,"stats_compare":%s,"stats_source_diag":%s,"stats_shadow_diag":%s,"stats_shadow_control":%s,"stats_identity_diag":%s,"stats_retention_diag":%s,"stats_diag":%s},"components":{"stats_v52_diag_bundle":"%s","stats_health_summary":"%s","stats_v52_rc_control":"%s","stats_v52_rc_enabled":%s,"stats_v52_rc_smoke":"%s","stats_migration_readiness":"%s","stats_migration_ready":%s,"stats_compare":"%s","stats_source":"%s","stats_shadow":"%s","stats_shadow_control":"%s","stats_identity":"%s","stats_retention":"%s","stats_diag":"%s"},"files":{"legacy_raw":{"lines":%s,"size":%s},"legacy_daily":{"lines":%s,"size":%s},"shadow_raw":{"lines":%s,"size":%s},"shadow_daily":{"lines":%s,"size":%s}},"capabilities":{"present":%s,"summary":"%s"},"paths":{"json":"%s","text":"%s","bundle":"%s"}}\n' \
  "$E_STATUS" "$E_STAGE" "$E_RECOMMENDATION" "$NOW" "$E_MODULE_VERSION" "$E_MODULE_CODE" \
  "$E_MANUFACTURER" "$E_BRAND" "$E_MODEL" "$E_DEVICE" "$E_ANDROID_RELEASE" "$E_ANDROID_SDK" "$E_BUILD_INCREMENTAL" "$E_KERNEL" "$E_IFACE" \
  "$HAS_DIAG_BUNDLE" "$HAS_SUMMARY" "$HAS_RC" "$HAS_SMOKE" "$HAS_READINESS" "$HAS_COMPARE" "$HAS_SOURCE" "$HAS_SHADOW" "$HAS_SHADOW_CONTROL" "$HAS_IDENTITY" "$HAS_RETENTION" "$HAS_BASE_DIAG" \
  "$E_DIAG_BUNDLE" "$E_SUMMARY" "$E_RC" "$RC_ENABLED" "$E_SMOKE" "$E_READINESS" "$READINESS_READY" "$E_COMPARE" "$E_SOURCE" "$E_SHADOW" "$E_SHADOW_CONTROL" "$E_IDENTITY" "$E_RETENTION" "$E_BASE_DIAG" \
  "$legacy_raw_lines" "$legacy_raw_size" "$legacy_daily_lines" "$legacy_daily_size" "$shadow_raw_lines" "$shadow_raw_size" "$shadow_daily_lines" "$shadow_daily_size" "$capabilities_json_present" "$E_CAP_SUMMARY" "$E_OUT_JSON" "$E_OUT_TXT" "$E_BUNDLE" > "$OUT_JSON"

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  bundle|collect)
    cat "$OUT_TXT"
    [ -f "$BUNDLE" ] && echo "bundle=$BUNDLE"
    ;;
  *) cat "$OUT_JSON" ;;
esac
exit 0
