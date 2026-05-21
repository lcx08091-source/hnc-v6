#!/system/bin/sh
# stats_v52_install_selfcheck.sh — v5.2-rc1.14 install/first-boot safety self-check.
# Read-only: verifies gray stats wiring, legacy-default preservation, rollback
# availability, and diagnostic helper presence. It does not enable RC, does not
# switch stats source, and does not touch tc/iptables/watchdog/network rules.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
OUT_JSON="$RUN/stats_v52_install_selfcheck.json"
OUT_TXT="$RUN/stats_v52_install_selfcheck.txt"
TS="$(date +%s 2>/dev/null || echo 0)"
MODE=${1:-text}
HELPER_TIMEOUT=${HNC_HELPER_TIMEOUT:-8}
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

FAILS=0
WARNS=0
ISSUES=""
add_issue() {
  level="$1"; shift
  msg="$*"
  case "$level" in
    fail) FAILS=$((FAILS+1));;
    warn) WARNS=$((WARNS+1));;
  esac
  if [ -n "$ISSUES" ]; then ISSUES="$ISSUES; $level:$msg"; else ISSUES="$level:$msg"; fi
}

run_helper_json() {
  h="$1"
  if [ ! -f "$BIN/$h" ] || [ ! -r "$BIN/$h" ]; then
    printf '%s' "{\"ok\":false,\"status\":\"missing\",\"helper\":\"$h\"}"
    return 0
  fi
  out="$(sh "$BIN/$h" json 2>/dev/null)"
  if [ -n "$out" ]; then
    printf '%s' "$out"
  else
    printf '%s' "{\"ok\":false,\"status\":\"empty\",\"helper\":\"$h\"}"
  fi
}

helper_json() {
  run_helper_json "$1"
}

status_of() {
  body="$1"
  case "$body" in *\"status\":\"*\"*) s=${body#*\"status\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo unknown ;; esac
}

severity_of() {
  body="$1"
  case "$body" in *\"severity\":\"*\"*) s=${body#*\"severity\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo unknown ;; esac
}

bool_key_of() {
  key="$1"; body="$2"
  case "$body" in *\"$key\":true*) echo true ;; *\"$key\":false*) echo false ;; *) echo false ;; esac
}

str_key_of() {
  key="$1"; body="$2"; def="$3"
  case "$body" in *\"$key\":\"*\"*) s=${body#*\"$key\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo "$def" ;; esac
}

exists_exec() {
  f="$1"
  [ -f "$BIN/$f" ] && [ -r "$BIN/$f" ]
}

# Required helpers for v5.2-rc1 gray safety and diagnostics.
REQUIRED="stats_v52_rc1_switch.sh stats_v52_web_status.sh stats_v52_device_check.sh stats_v52_rc_control.sh stats_v52_rc_smoke.sh stats_v52_diag_bundle.sh stats_health_summary.sh stats_migration_readiness.sh stats_compare.sh stats_source_diag.sh stats_shadow_control.sh json_health_panel.sh json_diag_bundle.sh stats_v52_install_selfcheck.sh stats_v52_gray_report.sh stats_v52_review_bundle.sh"
for h in $REQUIRED; do
  exists_exec "$h" || add_issue fail "missing helper $h"
done

# module.prop may live under MODDIR on installed devices, or under HNC_DIR in tests/source trees.
MODULE_PROP=""
[ -f "$MODDIR/module.prop" ] && MODULE_PROP="$MODDIR/module.prop"
[ -z "$MODULE_PROP" ] && [ -f "$HNC_DIR/module.prop" ] && MODULE_PROP="$HNC_DIR/module.prop"
VERSION="unknown"
VERSION_CODE="unknown"
if [ -n "$MODULE_PROP" ]; then
  VERSION="$(awk -F= '$1=="version"{print $2; exit}' "$MODULE_PROP" 2>/dev/null)"
  VERSION_CODE="$(awk -F= '$1=="versionCode"{print $2; exit}' "$MODULE_PROP" 2>/dev/null)"
  case "$VERSION" in
    v5.2.0-rc1.*|v5.2.0-rc1) : ;;
    *) add_issue warn "module version is $VERSION, expected v5.2.0-rc1.x" ;;
  esac
else
  add_issue warn "module.prop not found under MODDIR or HNC_DIR"
fi

# WebUI wiring check. json-health.html may be served from HNC_DIR or module root.
JSON_HEALTH_HTML=""
[ -f "$HNC_DIR/webroot/json-health.html" ] && JSON_HEALTH_HTML="$HNC_DIR/webroot/json-health.html"
[ -z "$JSON_HEALTH_HTML" ] && [ -f "$MODDIR/webroot/json-health.html" ] && JSON_HEALTH_HTML="$MODDIR/webroot/json-health.html"
WEBUI_WIRED=false
if [ -n "$JSON_HEALTH_HTML" ]; then
  if grep -q 'v52_web_status_raw' "$JSON_HEALTH_HTML" 2>/dev/null; then
    WEBUI_WIRED=true
  else
    add_issue fail "json-health.html missing v52_web_status_raw wiring"
  fi
else
  add_issue warn "json-health.html not found under HNC_DIR or MODDIR"
fi

# Rollback support check is static and does not execute rollback.
ROLLBACK_AVAILABLE=false
if [ -f "$BIN/stats_v52_rc1_switch.sh" ] && grep -q 'rollback' "$BIN/stats_v52_rc1_switch.sh" 2>/dev/null; then
  ROLLBACK_AVAILABLE=true
else
  add_issue fail "stats_v52_rc1_switch.sh rollback path not detected"
fi

RC1_JSON="$(helper_json stats_v52_rc1_switch.sh)"
WEB_JSON="$(helper_json stats_v52_web_status.sh)"
DEVICE_JSON="$(helper_json stats_v52_device_check.sh)"

RC1_STATUS="$(status_of "$RC1_JSON")"
WEB_STATUS="$(status_of "$WEB_JSON")"
WEB_SEVERITY="$(severity_of "$WEB_JSON")"
DEVICE_STATUS="$(status_of "$DEVICE_JSON")"
RC1_ENABLED="$(bool_key_of rc1_enabled "$RC1_JSON")"
RC_ENABLED="$(bool_key_of rc_enabled "$RC1_JSON")"
LEGACY_DEFAULT_PRESERVED="$(bool_key_of legacy_default_preserved "$RC1_JSON")"
RC_ENABLE_READY="$(bool_key_of rc_enable_ready "$DEVICE_JSON")"
DEFAULT_SOURCE="$(str_key_of default_source "$RC1_JSON" legacy)"

case "$RC1_STATUS" in blocked|drift|fail) add_issue fail "rc1 switch status is $RC1_STATUS" ;; missing|unknown) add_issue fail "rc1 switch status is $RC1_STATUS" ;; esac
case "$WEB_SEVERITY" in fail) add_issue fail "web status severity is fail" ;; warn) add_issue warn "web status severity is warn" ;; unknown) add_issue warn "web status severity is unknown" ;; esac
case "$DEVICE_STATUS" in fail|blocked) add_issue fail "device check status is $DEVICE_STATUS" ;; warn|not_ready|warmup) add_issue warn "device check status is $DEVICE_STATUS" ;; missing|unknown) add_issue warn "device check status is $DEVICE_STATUS" ;; esac

# v5.2-rc1.x must preserve legacy as the default stats source.
if [ "$DEFAULT_SOURCE" != legacy ]; then
  add_issue fail "default stats source is $DEFAULT_SOURCE, expected legacy"
fi
if [ "$LEGACY_DEFAULT_PRESERVED" != true ]; then
  add_issue fail "legacy_default_preserved is false"
fi

if [ -f "$RUN/stats_webui_source" ]; then
  SRC_OVERRIDE="$(cat "$RUN/stats_webui_source" 2>/dev/null)"
  case "$SRC_OVERRIDE" in shadow) add_issue warn "stats_webui_source override is shadow" ;; esac
fi

STATUS="pass"
[ "$WARNS" -gt 0 ] && STATUS="warn"
[ "$FAILS" -gt 0 ] && STATUS="fail"
INSTALL_READY=false
FIRST_BOOT_SAFE=false
SAFE_TO_ENABLE_RC=false
[ "$FAILS" -eq 0 ] && INSTALL_READY=true
[ "$FAILS" -eq 0 ] && [ "$LEGACY_DEFAULT_PRESERVED" = true ] && [ "$DEFAULT_SOURCE" = legacy ] && FIRST_BOOT_SAFE=true
[ "$FAILS" -eq 0 ] && [ "$RC_ENABLE_READY" = true ] && [ "$ROLLBACK_AVAILABLE" = true ] && SAFE_TO_ENABLE_RC=true

RECOMMENDATION="installation wiring looks safe; keep legacy default and monitor v5.2 diagnostics"
[ "$STATUS" = warn ] && RECOMMENDATION="review warnings before enabling v5.2 RC; legacy default is still expected"
[ "$STATUS" = fail ] && RECOMMENDATION="do not enable v5.2 RC; fix failed install/self-check items or run rollback"

{
  echo "HNC v5.2-rc1.14 install/first-boot self-check"
  echo "status=$STATUS"
  echo "install_ready=$INSTALL_READY"
  echo "first_boot_safe=$FIRST_BOOT_SAFE"
  echo "safe_to_enable_rc=$SAFE_TO_ENABLE_RC"
  echo "version=$VERSION"
  echo "versionCode=$VERSION_CODE"
  echo "module_prop=$MODULE_PROP"
  echo "json_health_html=$JSON_HEALTH_HTML"
  echo "webui_wired=$WEBUI_WIRED"
  echo "rollback_available=$ROLLBACK_AVAILABLE"
  echo "rc1_status=$RC1_STATUS"
  echo "web_status=$WEB_STATUS"
  echo "web_severity=$WEB_SEVERITY"
  echo "device_check_status=$DEVICE_STATUS"
  echo "rc1_enabled=$RC1_ENABLED"
  echo "rc_enabled=$RC_ENABLED"
  echo "default_source=$DEFAULT_SOURCE"
  echo "legacy_default_preserved=$LEGACY_DEFAULT_PRESERVED"
  echo "rc_enable_ready=$RC_ENABLE_READY"
  echo "failures=$FAILS"
  echo "warnings=$WARNS"
  echo "issues=$ISSUES"
  echo "recommendation=$RECOMMENDATION"
} > "$OUT_TXT"

cat > "$OUT_JSON" <<JSON
{"ok":true,"timestamp":$TS,"status":"$(json_escape "$STATUS")","install_ready":$INSTALL_READY,"first_boot_safe":$FIRST_BOOT_SAFE,"safe_to_enable_rc":$SAFE_TO_ENABLE_RC,"version":"$(json_escape "$VERSION")","versionCode":"$(json_escape "$VERSION_CODE")","module_prop":"$(json_escape "$MODULE_PROP")","json_health_html":"$(json_escape "$JSON_HEALTH_HTML")","webui_wired":$WEBUI_WIRED,"rollback_available":$ROLLBACK_AVAILABLE,"rc1_status":"$(json_escape "$RC1_STATUS")","web_status":"$(json_escape "$WEB_STATUS")","web_severity":"$(json_escape "$WEB_SEVERITY")","device_check_status":"$(json_escape "$DEVICE_STATUS")","rc1_enabled":$RC1_ENABLED,"rc_enabled":$RC_ENABLED,"default_source":"$(json_escape "$DEFAULT_SOURCE")","legacy_default_preserved":$LEGACY_DEFAULT_PRESERVED,"rc_enable_ready":$RC_ENABLE_READY,"failures":$FAILS,"warnings":$WARNS,"issues":"$(json_escape "$ISSUES")","recommendation":"$(json_escape "$RECOMMENDATION")","paths":{"json":"$(json_escape "$OUT_JSON")","text":"$(json_escape "$OUT_TXT")"}}
JSON

case "$MODE" in
  json) cat "$OUT_JSON" ;;
  *) cat "$OUT_TXT" ;;
esac
exit 0
