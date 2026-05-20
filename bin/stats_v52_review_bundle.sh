#!/system/bin/sh
# stats_v52_review_bundle.sh — scrubbed shadow-review bundle exporter (since v5.2-rc1.16)
# Read-only: generates a sanitized bundle that can be sent to Claude/Gemini/GPT.
# It does not enable RC, switch stats source, or touch tc/iptables/watchdog.
# rc1.14: consumes stats_v52_gray_report cache instead of re-running the whole helper tree.
# rc1.16: includes shadow raw/daily readiness and legacy/shadow comparison signals.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
OUT_BASE=${HNC_V52_REVIEW_OUT:-/sdcard/Download}
MODE=${1:-text}
TS="$(date +%s 2>/dev/null || echo 0)"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)"
OUT_JSON="$RUN/stats_v52_review_bundle.json"
OUT_TXT="$RUN/stats_v52_review_bundle.txt"
OUT_MD="$RUN/stats_v52_review_bundle.md"
REFRESH=${HNC_V52_REPORT_REFRESH:-0}
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

redact_stream() {
  sed \
    -e 's/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/<ipv4>/g' \
    -e 's/[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]/<mac>/g' \
    -e 's/"token"[[:space:]]*:[[:space:]]*"[^"]*"/"token":"<redacted>"/g' \
    -e 's/"secret"[[:space:]]*:[[:space:]]*"[^"]*"/"secret":"<redacted>"/g' \
    -e 's/"password"[[:space:]]*:[[:space:]]*"[^"]*"/"password":"<redacted>"/g' \
    -e 's/"auth"[[:space:]]*:[[:space:]]*"[^"]*"/"auth":"<redacted>"/g' \
    -e 's/[A-Za-z0-9._%+-][A-Za-z0-9._%+-]*@[A-Za-z0-9.-][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z]*/<email>/g'
}

run_or_read_gray_json() {
  if [ "$REFRESH" != 1 ] && [ -s "$RUN/stats_v52_gray_report.json" ]; then
    cat "$RUN/stats_v52_gray_report.json" 2>/dev/null
    return 0
  fi
  if [ -f "$BIN/stats_v52_gray_report.sh" ] && [ -r "$BIN/stats_v52_gray_report.sh" ]; then
    sh "$BIN/stats_v52_gray_report.sh" json 2>/dev/null
  else
    echo '{"ok":false,"status":"missing","helper":"stats_v52_gray_report.sh"}'
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

module_version

GRAY_JSON="$(run_or_read_gray_json | redact_stream)"
GRAY_STATUS="$(str_key_of status "$GRAY_JSON" unknown)"
REVIEW_READY="$(bool_key_of review_ready "$GRAY_JSON")"
GRAY_READY="$(bool_key_of gray_ready "$GRAY_JSON")"
LEGACY_DEFAULT_PRESERVED="$(bool_key_of legacy_default_preserved "$GRAY_JSON")"
RC1_ENABLED="$(bool_key_of rc1_enabled "$GRAY_JSON")"
DEFAULT_SOURCE="$(str_key_of default_source "$GRAY_JSON" legacy)"

SELF_STATUS="$(str_key_of selfcheck_status "$GRAY_JSON" unknown)"
WEB_STATUS="$(str_key_of web_status "$GRAY_JSON" unknown)"
WEB_SEVERITY="$(str_key_of web_severity "$GRAY_JSON" unknown)"
DEVICE_STATUS="$(str_key_of device_check_status "$GRAY_JSON" unknown)"
SMOKE_STATUS="$(str_key_of smoke_status "$GRAY_JSON" unknown)"
READINESS_STATUS="$(str_key_of readiness_status "$GRAY_JSON" unknown)"
COMPARE_STATUS="$(str_key_of compare_status "$GRAY_JSON" unknown)"
RC1_STATUS="$(str_key_of rc1_switch_status "$GRAY_JSON" unknown)"
HEALTH_STATUS="$(str_key_of health_status "$GRAY_JSON" unknown)"
SHADOW_STATE="$(str_key_of shadow_state "$GRAY_JSON" unknown)"
SHADOW_QUALITY="$(str_key_of shadow_quality "$GRAY_JSON" unknown)"
COMPARE_QUALITY="$(str_key_of compare_quality "$GRAY_JSON" unknown)"
SHADOW_RAW_LINES="$(num_key_of shadow_raw_lines "$GRAY_JSON" 0)"
SHADOW_DAILY_SAMPLES="$(num_key_of shadow_daily_samples "$GRAY_JSON" 0)"
SHADOW_LATEST_TS="$(num_key_of shadow_latest_ts "$GRAY_JSON" 0)"
COMPARE_TOTAL_KEYS="$(num_key_of compare_total_keys "$GRAY_JSON" 0)"
COMPARE_MATCHED_KEYS="$(num_key_of compare_matched_keys "$GRAY_JSON" 0)"
COMPARE_MISMATCHED_KEYS="$(num_key_of compare_mismatched_keys "$GRAY_JSON" 0)"
COMPARE_MISSING_IN_SHADOW="$(num_key_of compare_missing_in_shadow "$GRAY_JSON" 0)"
COMPARE_MISSING_IN_LEGACY="$(num_key_of compare_missing_in_legacy "$GRAY_JSON" 0)"

STATUS=pass
REASON="scrubbed review bundle generated; legacy default preserved"
case "$GRAY_STATUS:$SELF_STATUS:$DEVICE_STATUS:$SMOKE_STATUS" in
  *fail*|*blocked*|*missing*|*unknown*) STATUS=fail; REASON="one or more gray-review inputs are failed/missing/unknown" ;;
  *warn*|*not_ready*|*warmup*|*disabled*) STATUS=warn; REASON="one or more gray-review inputs are warnings or still warming up" ;;
esac
case "$SHADOW_STATE:$SHADOW_QUALITY:$COMPARE_QUALITY" in
  *warn_drift*|*warn_no_devices*|*warn_no_daily_samples*) [ "$STATUS" = pass ] && STATUS=warn; REASON="shadow or compare signals need review" ;;
  *no_shadow_data*|*unknown*|*missing*) [ "$STATUS" = pass ] && STATUS=warn; REASON="shadow data is not fully visible in gray report" ;;
esac
[ "$LEGACY_DEFAULT_PRESERVED" = true ] || { STATUS=fail; REASON="legacy default is not preserved"; }
[ "$DEFAULT_SOURCE" = legacy ] || { STATUS=fail; REASON="default source is not legacy"; }

RECOMMENDATION="send this scrubbed bundle to reviewers; keep legacy stats default during v5.2-rc1.x observation"
[ "$STATUS" = warn ] && RECOMMENDATION="send this bundle for review, but keep legacy default and do not widen gray rollout until warnings are understood"
[ "$STATUS" = fail ] && RECOMMENDATION="do not enable or widen v5.2 stats; keep legacy default and fix failed/missing review inputs first"

GRAY_MD=""
if [ -s "$RUN/stats_v52_gray_report.md" ]; then
  GRAY_MD="$(head -260 "$RUN/stats_v52_gray_report.md" 2>/dev/null | redact_stream)"
else
  GRAY_MD="# gray report markdown cache unavailable\nRun: sh /data/local/hnc/bin/stats_v52_gray_report.sh markdown"
fi

cat > "$OUT_TXT" <<TXT
HNC v5.2-rc1.16 scrubbed review bundle status
status=$STATUS
reason=$REASON
recommendation=$RECOMMENDATION
version=$VERSION
versionCode=$VERSION_CODE
module_prop=$MODULE_PROP
review_ready=$REVIEW_READY
gray_ready=$GRAY_READY
legacy_default_preserved=$LEGACY_DEFAULT_PRESERVED
default_source=$DEFAULT_SOURCE
rc1_enabled=$RC1_ENABLED
gray_report_status=$GRAY_STATUS
install_selfcheck_status=$SELF_STATUS
web_status=$WEB_STATUS
web_severity=$WEB_SEVERITY
device_check_status=$DEVICE_STATUS
smoke_status=$SMOKE_STATUS
readiness_status=$READINESS_STATUS
compare_status=$COMPARE_STATUS
shadow_state=$SHADOW_STATE
shadow_quality=$SHADOW_QUALITY
shadow_raw_lines=$SHADOW_RAW_LINES
shadow_daily_samples=$SHADOW_DAILY_SAMPLES
shadow_latest_ts=$SHADOW_LATEST_TS
compare_quality=$COMPARE_QUALITY
compare_total_keys=$COMPARE_TOTAL_KEYS
compare_matched_keys=$COMPARE_MATCHED_KEYS
compare_missing_in_legacy=$COMPARE_MISSING_IN_LEGACY
compare_missing_in_shadow=$COMPARE_MISSING_IN_SHADOW
compare_mismatched_keys=$COMPARE_MISMATCHED_KEYS
rc1_switch_status=$RC1_STATUS
health_summary_status=$HEALTH_STATUS
redaction=enabled
fast_cache=1
refresh=$REFRESH
paths.json=$OUT_JSON
paths.text=$OUT_TXT
paths.markdown=$OUT_MD
TXT

cat > "$OUT_MD" <<MD
# HNC v5.2-rc1.16 脱敏灰度审查包

## 结论

- status: **$STATUS**
- reason: $REASON
- recommendation: $RECOMMENDATION

## 版本与默认策略

- version: $VERSION
- versionCode: $VERSION_CODE
- default_source: $DEFAULT_SOURCE
- legacy_default_preserved: $LEGACY_DEFAULT_PRESERVED
- rc1_enabled: $RC1_ENABLED

## 灰度门禁摘要

| 项目 | 状态 |
|---|---|
| gray report | $GRAY_STATUS |
| install selfcheck | $SELF_STATUS |
| WebUI status | $WEB_STATUS / severity=$WEB_SEVERITY |
| device check | $DEVICE_STATUS |
| smoke | $SMOKE_STATUS |
| readiness | $READINESS_STATUS |
| compare | $COMPARE_STATUS |
| rc1 switch | $RC1_STATUS |
| health summary | $HEALTH_STATUS |

## Shadow / 对比摘要

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

## 性能模式

- fast_cache: 1
- refresh: $REFRESH

说明：rc1.16 默认复用灰度报告缓存，不再二次重跑全部 helper。需要强制全量刷新时可执行：

\`HNC_V52_REPORT_REFRESH=1 sh /data/local/hnc/bin/stats_v52_review_bundle.sh markdown\`

## 脱敏说明

本报告会尽量脱敏 IPv4、MAC、邮箱、token、password、secret、auth 等字段。它适合发给 Claude / Gemini / GPT 做交叉审查。完整原始日志仍应只留在本机。

## 给其他 AI 的审查问题

请重点审查：

1. v5.2 stats 灰度是否仍保持 legacy stats 默认。
2. 是否存在 readiness 通过但 device_check/smoke/compare 没有通过的矛盾。
3. 是否应该继续观察，还是可以进入 v5.2-rc2。
4. 是否有任何会误触发 stats RC enable、切换默认 stats source、破坏回滚路径的风险。
5. 报告中是否仍有疑似隐私或敏感字段没有被脱敏。

## gray_report 摘要

\`\`\`text
$GRAY_MD
\`\`\`
MD

cat > "$OUT_JSON" <<JSON
{"ok":true,"status":"$(json_escape "$STATUS")","timestamp":$TS,"version":"$(json_escape "$VERSION")","versionCode":"$(json_escape "$VERSION_CODE")","reason":"$(json_escape "$REASON")","recommendation":"$(json_escape "$RECOMMENDATION")","redaction_enabled":true,"fast_cache":true,"refresh":$REFRESH,"review_ready":$REVIEW_READY,"gray_ready":$GRAY_READY,"legacy_default_preserved":$LEGACY_DEFAULT_PRESERVED,"default_source":"$(json_escape "$DEFAULT_SOURCE")","rc1_enabled":$RC1_ENABLED,"shadow_state":"$(json_escape "$SHADOW_STATE")","shadow_quality":"$(json_escape "$SHADOW_QUALITY")","shadow_raw_lines":$SHADOW_RAW_LINES,"shadow_daily_samples":$SHADOW_DAILY_SAMPLES,"shadow_latest_ts":$SHADOW_LATEST_TS,"compare_quality":"$(json_escape "$COMPARE_QUALITY")","compare_total_keys":$COMPARE_TOTAL_KEYS,"compare_matched_keys":$COMPARE_MATCHED_KEYS,"compare_missing_in_legacy":$COMPARE_MISSING_IN_LEGACY,"compare_missing_in_shadow":$COMPARE_MISSING_IN_SHADOW,"compare_mismatched_keys":$COMPARE_MISMATCHED_KEYS,"signals":{"gray_report_status":"$(json_escape "$GRAY_STATUS")","install_selfcheck_status":"$(json_escape "$SELF_STATUS")","web_status":"$(json_escape "$WEB_STATUS")","web_severity":"$(json_escape "$WEB_SEVERITY")","device_check_status":"$(json_escape "$DEVICE_STATUS")","smoke_status":"$(json_escape "$SMOKE_STATUS")","readiness_status":"$(json_escape "$READINESS_STATUS")","compare_status":"$(json_escape "$COMPARE_STATUS")","rc1_switch_status":"$(json_escape "$RC1_STATUS")","health_summary_status":"$(json_escape "$HEALTH_STATUS")"},"paths":{"json":"$(json_escape "$OUT_JSON")","text":"$(json_escape "$OUT_TXT")","markdown":"$(json_escape "$OUT_MD")"}}
JSON

make_bundle() {
  BUNDLE_DIR="$OUT_BASE/hnc-v52-rc1.16-review-$STAMP"
  mkdir -p "$BUNDLE_DIR/cmd" "$BUNDLE_DIR/run" 2>/dev/null || return 1
  cp -af "$OUT_TXT" "$BUNDLE_DIR/summary.txt" 2>/dev/null
  cp -af "$OUT_MD" "$BUNDLE_DIR/review.md" 2>/dev/null
  cp -af "$OUT_JSON" "$BUNDLE_DIR/review.json" 2>/dev/null
  cp -af "$RUN/stats_v52_gray_report.md" "$BUNDLE_DIR/cmd/stats_v52_gray_report.md" 2>/dev/null
  cp -af "$RUN/stats_v52_gray_report.json" "$BUNDLE_DIR/cmd/stats_v52_gray_report.json" 2>/dev/null
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
