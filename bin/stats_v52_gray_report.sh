#!/system/bin/sh
# stats_v52_gray_report.sh — v5.2-rc1.16 shadow-aware gray observation report exporter.
# Read-only: aggregates v5.2 stats gray-release signals for human review.
# It does not enable RC, switch stats source, or touch tc/iptables/watchdog.
# rc1.14: uses cached helper outputs by default to avoid repeated slow diagnostics.
# rc1.16: surfaces shadow raw/daily readiness and legacy/shadow comparison signals.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
OUT_BASE=${HNC_V52_REPORT_OUT:-/sdcard/Download}
MODE=${1:-text}
TS="$(date +%s 2>/dev/null || echo 0)"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)"
OUT_JSON="$RUN/stats_v52_gray_report.json"
OUT_TXT="$RUN/stats_v52_gray_report.txt"
OUT_MD="$RUN/stats_v52_gray_report.md"
# Default fast mode: prefer cached helper output if it already exists.
# Set HNC_V52_REPORT_REFRESH=1 to force re-running helpers.
FAST_CACHE=${HNC_V52_REPORT_FAST:-1}
REFRESH=${HNC_V52_REPORT_REFRESH:-0}
FULL_RAW=${HNC_V52_REPORT_FULL:-0}
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

cache_path() {
  h="$1"; ext="$2"
  base=${h%.sh}
  printf '%s/%s.%s' "$RUN" "$base" "$ext"
}

run_helper_direct() {
  h="$1"; mode="$2"; missing_fallback="$3"; empty_fallback="$4"
  if [ ! -f "$BIN/$h" ] || [ ! -r "$BIN/$h" ]; then
    printf '%b' "$missing_fallback"
    return 0
  fi
  out="$(sh "$BIN/$h" "$mode" 2>/dev/null)"
  if [ -n "$out" ]; then
    printf '%s' "$out"
  else
    printf '%b' "$empty_fallback"
  fi
}

cached_helper() {
  h="$1"; mode="$2"; missing_fallback="$3"; empty_fallback="$4"
  cache="$(cache_path "$h" "$mode")"
  if [ "$FAST_CACHE" = 1 ] && [ "$REFRESH" != 1 ] && [ -s "$cache" ]; then
    cat "$cache" 2>/dev/null
    return 0
  fi
  run_helper_direct "$h" "$mode" "$missing_fallback" "$empty_fallback"
}

helper_json() {
  h="$1"
  cached_helper "$h" json "{\"ok\":false,\"status\":\"missing\",\"helper\":\"$h\"}" "{\"ok\":false,\"status\":\"empty\",\"helper\":\"$h\"}"
}

helper_text_cached() {
  h="$1"
  cache="$(cache_path "$h" txt)"
  [ -s "$cache" ] && { head -120 "$cache" 2>/dev/null; return 0; }
  # Some helpers use .text rarely; support both just in case.
  cache2="$(cache_path "$h" text)"
  [ -s "$cache2" ] && { head -120 "$cache2" 2>/dev/null; return 0; }
  printf 'cached text unavailable for %s; status is summarized above\n' "$h"
}

helper_text_full_or_cached() {
  h="$1"
  if [ "$FULL_RAW" = 1 ]; then
    run_helper_direct "$h" text "missing helper: $h\n" "empty helper output: $h\n" | head -120
  else
    helper_text_cached "$h"
  fi
}

str_key_of() {
  key="$1"; body="$2"; def="$3"
  val="$(printf '%s' "$body" | sed -n 's/.*"'"$key"'":"\([^"]*\)".*/\1/p' )"
  [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"
}

bool_key_of() {
  key="$1"; body="$2"
  case "$body" in *\"$key\":true*) echo true ;; *\"$key\":false*) echo false ;; *) echo false ;; esac
}

num_key_of() {
  key="$1"; body="$2"; def="$3"
  val="$(printf '%s' "$body" | sed -n 's/.*"'"$key"'":\([0-9][0-9]*\).*/\1/p' )"
  case "$val" in ''|*[!0-9]*) printf '%s' "$def" ;; *) printf '%s' "$val" ;; esac
}

mark_level() {
  level="$1"; reason="$2"
  case "$level" in
    fail) FAILS=$((FAILS+1)) ;;
    warn) WARNS=$((WARNS+1)) ;;
    pass) PASSES=$((PASSES+1)) ;;
  esac
  [ -n "$reason" ] || return 0
  if [ -n "$OBSERVATIONS" ]; then OBSERVATIONS="$OBSERVATIONS; $level:$reason"; else OBSERVATIONS="$level:$reason"; fi
}

module_version() {
  mp=""
  [ -f "$MODDIR/module.prop" ] && mp="$MODDIR/module.prop"
  [ -z "$mp" ] && [ -f "$HNC_DIR/module.prop" ] && mp="$HNC_DIR/module.prop"
  if [ -n "$mp" ]; then
    VERSION="$(awk -F= '$1=="version"{print $2; exit}' "$mp" 2>/dev/null)"
    VERSION_CODE="$(awk -F= '$1=="versionCode"{print $2; exit}' "$mp" 2>/dev/null)"
    MODULE_PROP="$mp"
  else
    VERSION="unknown"; VERSION_CODE="unknown"; MODULE_PROP=""
  fi
}

# Fast path note:
# If the user has just run install_selfcheck/device_check before this report,
# rc1.14 reads those cached outputs instead of launching the full diagnostic tree
# again. This keeps the report responsive on Android WebView/Termux shells.
module_version

SELF_JSON="$(helper_json stats_v52_install_selfcheck.sh)"
WEB_JSON="$(helper_json stats_v52_web_status.sh)"
DEVICE_JSON="$(helper_json stats_v52_device_check.sh)"
COMPARE_JSON="$(helper_json stats_compare.sh)"
READINESS_JSON="$(helper_json stats_migration_readiness.sh)"
SMOKE_JSON="$(helper_json stats_v52_rc_smoke.sh)"
RC1_JSON="$(helper_json stats_v52_rc1_switch.sh)"
RC_CONTROL_JSON="$(helper_json stats_v52_rc_control.sh)"
SOURCE_JSON="$(helper_json stats_source_diag.sh)"
SHADOW_JSON="$(helper_json stats_shadow_diag.sh)"
HEALTH_JSON="$(helper_json stats_health_summary.sh)"

SELF_STATUS="$(str_key_of status "$SELF_JSON" unknown)"
WEB_STATUS="$(str_key_of status "$WEB_JSON" unknown)"
WEB_SEVERITY="$(str_key_of severity "$WEB_JSON" unknown)"
DEVICE_STATUS="$(str_key_of status "$DEVICE_JSON" unknown)"
COMPARE_STATUS="$(str_key_of status "$COMPARE_JSON" unknown)"
READINESS_STATUS="$(str_key_of status "$READINESS_JSON" unknown)"
SMOKE_STATUS="$(str_key_of status "$SMOKE_JSON" unknown)"
RC1_STATUS="$(str_key_of status "$RC1_JSON" unknown)"
RC_CONTROL_STATUS="$(str_key_of status "$RC_CONTROL_JSON" unknown)"
SOURCE_STATUS="$(str_key_of status "$SOURCE_JSON" unknown)"
SHADOW_STATUS="$(str_key_of status "$SHADOW_JSON" unknown)"
HEALTH_STATUS="$(str_key_of status "$HEALTH_JSON" unknown)"

SHADOW_STATE="$(str_key_of shadow_state "$READINESS_JSON" unknown)"
SHADOW_QUALITY="$(str_key_of shadow_quality "$READINESS_JSON" unknown)"
COMPARE_QUALITY="$(str_key_of compare_quality "$READINESS_JSON" unknown)"
SHADOW_RAW_LINES="$(num_key_of shadow_raw_lines "$READINESS_JSON" 0)"
SHADOW_DAILY_SAMPLES="$(num_key_of shadow_daily_samples "$READINESS_JSON" 0)"
SHADOW_LATEST_TS="$(num_key_of shadow_latest_ts "$READINESS_JSON" 0)"
COMPARE_TOTAL_KEYS="$(num_key_of total_keys "$READINESS_JSON" 0)"
COMPARE_MATCHED_KEYS="$(num_key_of matched_keys "$READINESS_JSON" 0)"
COMPARE_MISMATCHED_KEYS="$(num_key_of mismatched_keys "$READINESS_JSON" 0)"
COMPARE_MISSING_IN_SHADOW="$(num_key_of missing_in_shadow "$READINESS_JSON" 0)"
COMPARE_MISSING_IN_LEGACY="$(num_key_of missing_in_legacy "$READINESS_JSON" 0)"

SAFE_TO_ENABLE_RC="$(bool_key_of safe_to_enable_rc "$SELF_JSON")"
FIRST_BOOT_SAFE="$(bool_key_of first_boot_safe "$SELF_JSON")"
INSTALL_READY="$(bool_key_of install_ready "$SELF_JSON")"
RC_ENABLE_READY="$(bool_key_of rc_enable_ready "$DEVICE_JSON")"
LEGACY_DEFAULT_PRESERVED="$(bool_key_of legacy_default_preserved "$RC1_JSON")"
RC1_ENABLED="$(bool_key_of rc1_enabled "$RC1_JSON")"
RC_ENABLED="$(bool_key_of rc_enabled "$RC1_JSON")"
DEFAULT_SOURCE="$(str_key_of default_source "$RC1_JSON" legacy)"

FAILS=0
WARNS=0
PASSES=0
OBSERVATIONS=""

case "$SELF_STATUS" in pass) mark_level pass "install selfcheck pass" ;; warn) mark_level warn "install selfcheck warn" ;; fail|blocked|missing|unknown) mark_level fail "install selfcheck $SELF_STATUS" ;; *) mark_level warn "install selfcheck $SELF_STATUS" ;; esac
case "$WEB_SEVERITY" in ok|pass) mark_level pass "web status severity $WEB_SEVERITY" ;; warn) mark_level warn "web status severity warn" ;; fail) mark_level fail "web status severity fail" ;; *) mark_level warn "web status severity $WEB_SEVERITY" ;; esac
case "$DEVICE_STATUS" in pass|ready) mark_level pass "device check $DEVICE_STATUS" ;; warn|warmup|not_ready|disabled) mark_level warn "device check $DEVICE_STATUS" ;; fail|blocked|missing|unknown) mark_level fail "device check $DEVICE_STATUS" ;; *) mark_level warn "device check $DEVICE_STATUS" ;; esac
case "$COMPARE_STATUS" in pass|ok|ready) mark_level pass "stats compare $COMPARE_STATUS" ;; warn|drift|disabled|warmup|not_ready|unknown) mark_level warn "stats compare $COMPARE_STATUS" ;; fail|blocked|missing) mark_level warn "stats compare $COMPARE_STATUS" ;; *) mark_level warn "stats compare $COMPARE_STATUS" ;; esac
case "$READINESS_STATUS" in ready|pass|ok) mark_level pass "readiness $READINESS_STATUS" ;; not_ready|warmup|disabled) mark_level warn "readiness $READINESS_STATUS" ;; blocked|fail|missing|unknown) mark_level fail "readiness $READINESS_STATUS" ;; *) mark_level warn "readiness $READINESS_STATUS" ;; esac
case "$SHADOW_STATE" in shadow_rollup_seen) mark_level pass "shadow raw/daily visible" ;; shadow_raw_seen) mark_level warn "shadow raw visible but daily rollup missing" ;; no_shadow_data|unknown) mark_level warn "shadow data not visible" ;; *) mark_level warn "shadow state $SHADOW_STATE" ;; esac
case "$SHADOW_QUALITY" in observed|observed_zero_traffic) mark_level pass "shadow quality $SHADOW_QUALITY" ;; warmup|warn_no_devices|warn_no_daily_samples|missing|unknown) mark_level warn "shadow quality $SHADOW_QUALITY" ;; *) mark_level warn "shadow quality $SHADOW_QUALITY" ;; esac
case "$COMPARE_QUALITY" in compared|shadow_only|shadow_only_or_legacy_empty) mark_level pass "compare quality $COMPARE_QUALITY" ;; warn_drift) mark_level warn "compare quality warn_drift" ;; not_available|unknown) mark_level warn "compare quality $COMPARE_QUALITY" ;; *) mark_level warn "compare quality $COMPARE_QUALITY" ;; esac
case "$SMOKE_STATUS" in pass|ok) mark_level pass "smoke $SMOKE_STATUS" ;; disabled|warn|warmup) mark_level warn "smoke $SMOKE_STATUS" ;; fail|blocked|missing|unknown) mark_level fail "smoke $SMOKE_STATUS" ;; *) mark_level warn "smoke $SMOKE_STATUS" ;; esac
case "$RC1_STATUS" in pass|ok|disabled|ready) mark_level pass "rc1 switch $RC1_STATUS" ;; warn|not_ready|warmup) mark_level warn "rc1 switch $RC1_STATUS" ;; blocked|drift|fail|missing|unknown) mark_level fail "rc1 switch $RC1_STATUS" ;; *) mark_level warn "rc1 switch $RC1_STATUS" ;; esac

if [ "$DEFAULT_SOURCE" != legacy ]; then mark_level fail "default source is $DEFAULT_SOURCE, expected legacy for rc1.x"; fi
if [ "$LEGACY_DEFAULT_PRESERVED" != true ]; then mark_level fail "legacy_default_preserved is false"; fi

OVERALL="pass"
[ "$WARNS" -gt 0 ] && OVERALL="warn"
[ "$FAILS" -gt 0 ] && OVERALL="fail"

REVIEW_READY=false
GRAY_READY=false
SAFE_ROLLBACK_EXPECTED=true
[ "$FAILS" -eq 0 ] && REVIEW_READY=true
[ "$FAILS" -eq 0 ] && [ "$SAFE_TO_ENABLE_RC" = true ] && [ "$RC_ENABLE_READY" = true ] && GRAY_READY=true

RECOMMENDATION="v5.2-rc1.16 gray observation looks clean; keep legacy default while monitoring shadow stats before any wider rollout"
[ "$OVERALL" = warn ] && RECOMMENDATION="keep legacy default; review warnings and continue gray observation before enabling or widening v5.2 stats"
[ "$OVERALL" = fail ] && RECOMMENDATION="do not enable or widen v5.2 stats; keep legacy default and fix failed gray-check items or rollback"

SELF_TEXT="$(helper_text_full_or_cached stats_v52_install_selfcheck.sh | head -60)"
WEB_TEXT="$(helper_text_full_or_cached stats_v52_web_status.sh | head -60)"
DEVICE_TEXT="$(helper_text_full_or_cached stats_v52_device_check.sh | head -80)"
COMPARE_TEXT="$(helper_text_full_or_cached stats_compare.sh | head -80)"
READINESS_TEXT="$(helper_text_full_or_cached stats_migration_readiness.sh | head -80)"
SMOKE_TEXT="$(helper_text_full_or_cached stats_v52_rc_smoke.sh | head -80)"
RC1_TEXT="$(helper_text_full_or_cached stats_v52_rc1_switch.sh | head -70)"

cat > "$OUT_TXT" <<TXT
HNC v5.2-rc1.16 gray observation report
status=$OVERALL
review_ready=$REVIEW_READY
gray_ready=$GRAY_READY
version=$VERSION
versionCode=$VERSION_CODE
module_prop=$MODULE_PROP
legacy_default_preserved=$LEGACY_DEFAULT_PRESERVED
default_source=$DEFAULT_SOURCE
rc1_enabled=$RC1_ENABLED
rc_enabled=$RC_ENABLED
install_ready=$INSTALL_READY
first_boot_safe=$FIRST_BOOT_SAFE
safe_to_enable_rc=$SAFE_TO_ENABLE_RC
rc_enable_ready=$RC_ENABLE_READY
selfcheck_status=$SELF_STATUS
web_status=$WEB_STATUS
web_severity=$WEB_SEVERITY
device_check_status=$DEVICE_STATUS
compare_status=$COMPARE_STATUS
readiness_status=$READINESS_STATUS
smoke_status=$SMOKE_STATUS
rc1_switch_status=$RC1_STATUS
rc_control_status=$RC_CONTROL_STATUS
source_status=$SOURCE_STATUS
shadow_status=$SHADOW_STATUS
health_status=$HEALTH_STATUS
failures=$FAILS
warnings=$WARNS
passes=$PASSES
observations=$OBSERVATIONS
fast_cache=$FAST_CACHE
refresh=$REFRESH
full_raw=$FULL_RAW
recommendation=$RECOMMENDATION
paths.json=$OUT_JSON
paths.text=$OUT_TXT
paths.markdown=$OUT_MD
TXT

cat > "$OUT_MD" <<MD
# HNC v5.2-rc1.16 灰度观察报告

## 结论

- overall: **$OVERALL**
- review_ready: **$REVIEW_READY**
- gray_ready: **$GRAY_READY**
- recommendation: $RECOMMENDATION

## 版本与默认状态

- version: $VERSION
- versionCode: $VERSION_CODE
- default_source: $DEFAULT_SOURCE
- legacy_default_preserved: $LEGACY_DEFAULT_PRESERVED
- rc1_enabled: $RC1_ENABLED
- rc_enabled: $RC_ENABLED

## 关键门禁

| 项目 | 状态 |
|---|---|
| install selfcheck | $SELF_STATUS |
| WebUI gray status | $WEB_STATUS / severity=$WEB_SEVERITY |
| real-device check | $DEVICE_STATUS |
| stats compare | $COMPARE_STATUS |
| migration readiness | $READINESS_STATUS |
| RC smoke | $SMOKE_STATUS |
| RC1 switch | $RC1_STATUS |
| RC control | $RC_CONTROL_STATUS |
| source diag | $SOURCE_STATUS |
| shadow diag | $SHADOW_STATUS |
| health summary | $HEALTH_STATUS |

## Shadow 数据识别

- shadow_state: $SHADOW_STATE
- shadow_quality: $SHADOW_QUALITY
- shadow_raw_lines: $SHADOW_RAW_LINES
- shadow_daily_samples: $SHADOW_DAILY_SAMPLES
- shadow_latest_ts: $SHADOW_LATEST_TS
- compare_quality: $COMPARE_QUALITY
- compare_total_keys: $COMPARE_TOTAL_KEYS
- compare_matched_keys: $COMPARE_MATCHED_KEYS
- compare_missing_in_legacy: $COMPARE_MISSING_IN_LEGACY
- compare_missing_in_shadow: $COMPARE_MISSING_IN_SHADOW
- compare_mismatched_keys: $COMPARE_MISMATCHED_KEYS

## 安全开关

- install_ready: $INSTALL_READY
- first_boot_safe: $FIRST_BOOT_SAFE
- safe_to_enable_rc: $SAFE_TO_ENABLE_RC
- rc_enable_ready: $RC_ENABLE_READY
- safe_rollback_expected: $SAFE_ROLLBACK_EXPECTED

## 性能模式

- fast_cache: $FAST_CACHE
- refresh: $REFRESH
- full_raw: $FULL_RAW

说明：rc1.16 默认复用刚刚生成的 helper 缓存，避免同一批诊断在灰度报告和审查包里重复执行。需要强制全量刷新时可执行：

\`HNC_V52_REPORT_REFRESH=1 sh /data/local/hnc/bin/stats_v52_gray_report.sh markdown\`

## 观察记录

$OBSERVATIONS

## 原始输出摘要

### install selfcheck

\`\`\`text
$SELF_TEXT
\`\`\`

### WebUI status

\`\`\`text
$WEB_TEXT
\`\`\`

### real-device check

\`\`\`text
$DEVICE_TEXT
\`\`\`

### stats compare

\`\`\`text
$COMPARE_TEXT
\`\`\`

### migration readiness

\`\`\`text
$READINESS_TEXT
\`\`\`

### RC smoke

\`\`\`text
$SMOKE_TEXT
\`\`\`

### RC1 switch

\`\`\`text
$RC1_TEXT
\`\`\`
MD

cat > "$OUT_JSON" <<JSON
{"ok":true,"status":"$(json_escape "$OVERALL")","timestamp":$TS,"version":"$(json_escape "$VERSION")","versionCode":"$(json_escape "$VERSION_CODE")","review_ready":$REVIEW_READY,"gray_ready":$GRAY_READY,"legacy_default_preserved":$LEGACY_DEFAULT_PRESERVED,"default_source":"$(json_escape "$DEFAULT_SOURCE")","rc1_enabled":$RC1_ENABLED,"rc_enabled":$RC_ENABLED,"install_ready":$INSTALL_READY,"first_boot_safe":$FIRST_BOOT_SAFE,"safe_to_enable_rc":$SAFE_TO_ENABLE_RC,"rc_enable_ready":$RC_ENABLE_READY,"fast_cache":$FAST_CACHE,"refresh":$REFRESH,"full_raw":$FULL_RAW,"failures":$FAILS,"warnings":$WARNS,"passes":$PASSES,"shadow_state":"$(json_escape "$SHADOW_STATE")","shadow_quality":"$(json_escape "$SHADOW_QUALITY")","shadow_raw_lines":$SHADOW_RAW_LINES,"shadow_daily_samples":$SHADOW_DAILY_SAMPLES,"shadow_latest_ts":$SHADOW_LATEST_TS,"compare_quality":"$(json_escape "$COMPARE_QUALITY")","compare_total_keys":$COMPARE_TOTAL_KEYS,"compare_matched_keys":$COMPARE_MATCHED_KEYS,"compare_missing_in_legacy":$COMPARE_MISSING_IN_LEGACY,"compare_missing_in_shadow":$COMPARE_MISSING_IN_SHADOW,"compare_mismatched_keys":$COMPARE_MISMATCHED_KEYS,"signals":{"selfcheck_status":"$(json_escape "$SELF_STATUS")","web_status":"$(json_escape "$WEB_STATUS")","web_severity":"$(json_escape "$WEB_SEVERITY")","device_check_status":"$(json_escape "$DEVICE_STATUS")","compare_status":"$(json_escape "$COMPARE_STATUS")","readiness_status":"$(json_escape "$READINESS_STATUS")","smoke_status":"$(json_escape "$SMOKE_STATUS")","rc1_switch_status":"$(json_escape "$RC1_STATUS")","rc_control_status":"$(json_escape "$RC_CONTROL_STATUS")","source_status":"$(json_escape "$SOURCE_STATUS")","shadow_status":"$(json_escape "$SHADOW_STATUS")","health_status":"$(json_escape "$HEALTH_STATUS")"},"observations":"$(json_escape "$OBSERVATIONS")","recommendation":"$(json_escape "$RECOMMENDATION")","paths":{"json":"$(json_escape "$OUT_JSON")","text":"$(json_escape "$OUT_TXT")","markdown":"$(json_escape "$OUT_MD")"}}
JSON

make_bundle() {
  BUNDLE_DIR="$OUT_BASE/hnc-v52-rc1.16-gray-$STAMP"
  mkdir -p "$BUNDLE_DIR/cmd" 2>/dev/null || return 1
  cp -af "$OUT_TXT" "$BUNDLE_DIR/summary.txt" 2>/dev/null
  cp -af "$OUT_MD" "$BUNDLE_DIR/report.md" 2>/dev/null
  cp -af "$OUT_JSON" "$BUNDLE_DIR/report.json" 2>/dev/null
  for f in stats_v52_install_selfcheck stats_v52_web_status stats_v52_device_check stats_compare stats_migration_readiness stats_v52_rc_smoke stats_v52_rc1_switch stats_v52_rc_control stats_source_diag stats_shadow_diag stats_health_summary; do
    [ -s "$RUN/$f.json" ] && cp -af "$RUN/$f.json" "$BUNDLE_DIR/cmd/$f.json" 2>/dev/null
    [ -s "$RUN/$f.txt" ] && cp -af "$RUN/$f.txt" "$BUNDLE_DIR/cmd/$f.txt" 2>/dev/null
  done
  echo "$BUNDLE_DIR"
}

case "$MODE" in
  json) cat "$OUT_JSON" ;;
  markdown|md) cat "$OUT_MD" ;;
  bundle) make_bundle ;;
  *) cat "$OUT_TXT" ;;
esac
exit 0
