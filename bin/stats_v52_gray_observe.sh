#!/system/bin/sh
# stats_v52_gray_observe.sh — HNC v5.2-rc1.21 real-device gray observation helper.
# Observation-only helper. It does not enable v5.2 RC, switch stats source,
# or touch tc/watchdog/limit/delay. By default it refreshes the derived
# same-day shadow rollup when raw samples exist so daily totals are not stale.
# Set HNC_V52_OBSERVE_SAMPLE=1 to run one explicit shadow sample first.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
BIN="$HNC_DIR/bin"
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
MODE=${1:-text}
OUT_JSON="$RUN/stats_v52_gray_observe.json"
OUT_TXT="$RUN/stats_v52_gray_observe.txt"
OUT_MD="$RUN/stats_v52_gray_observe.md"
TS="$(date +%s 2>/dev/null || echo 0)"
DO_SAMPLE=${HNC_V52_OBSERVE_SAMPLE:-0}
DO_REFRESH=${HNC_V52_OBSERVE_REFRESH:-0}
DO_AUTO_ROLLUP=${HNC_V52_OBSERVE_AUTO_ROLLUP:-1}
NEED_REFRESH=0
AUTO_ROLLUP_USED=false
AUTO_ROLLUP_DATE=
mkdir -p "$RUN" 2>/dev/null

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

kv_get() {
  f="$1"; key="$2"; def="$3"
  [ -f "$f" ] || { printf '%s' "$def"; return; }
  val="$(awk -F= -v k="$key" '$1==k{v=$0; sub("^[^=]*=","",v)} END{print v}' "$f" 2>/dev/null)"
  [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"
}

file_lines() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
num() { case "$1" in ''|*[!0-9]*) echo "${2:-0}" ;; *) echo "$1" ;; esac; }
bool() { case "$1" in true|false) echo "$1" ;; 1|yes|YES|TRUE) echo true ;; *) echo false ;; esac; }
positive_num() { case "$1" in ""|*[!0-9]*) return 1 ;; *[1-9]*) return 0 ;; *) return 1 ;; esac; }

run_text_helper() {
  h="$1"; out="$2"; mode_arg=${3:-text}
  if [ "$DO_REFRESH" = 1 ] || [ "$DO_REFRESH" = true ] || [ "$NEED_REFRESH" = 1 ] || [ ! -s "$out" ]; then
    if [ -x "$BIN/$h" ]; then
      sh "$BIN/$h" "$mode_arg" > "$out.tmp" 2>/dev/null && mv -f "$out.tmp" "$out" || rm -f "$out.tmp" 2>/dev/null
    fi
  fi
}

latest_raw_date() {
  f="$DATA/stats_shadow_raw.jsonl"
  [ -s "$f" ] || return 1
  awk '
function str_field(line, key,    pat, val) {
  pat = "\"" key "\":\"[^\"]*\""
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub("^\"" key "\":\"", "", val); sub("\"$", "", val); return val }
  return ""
}
function num_field(line, key,    pat, val) {
  pat = "\"" key "\":[0-9]+"
  if (match(line, pat)) { val = substr(line, RSTART, RLENGTH); sub(".*:", "", val); return val + 0 }
  return 0
}
{
  d = str_field($0, "date")
  ts = num_field($0, "ts")
  if (d ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
    if (ts >= latest_ts) { latest_ts = ts; latest_date = d }
    else if (latest_date == "") latest_date = d
  }
}
END { if (latest_date != "") print latest_date }' "$f" 2>/dev/null
}

maybe_sample() {
  case "$DO_SAMPLE" in 1|true|TRUE|yes|YES) ;; *) return 0 ;; esac
  [ -x "$BIN/stats_shadow_sample.sh" ] && sh "$BIN/stats_shadow_sample.sh" >/dev/null 2>&1 || true
  rollup_date="$(latest_raw_date)"
  [ -n "$rollup_date" ] || rollup_date="$(date +%Y-%m-%d 2>/dev/null)"
  case "$rollup_date" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      [ -x "$BIN/stats_shadow_rollup.sh" ] && sh "$BIN/stats_shadow_rollup.sh" "$rollup_date" >/dev/null 2>&1 || true
      AUTO_ROLLUP_DATE="$rollup_date"
      ;;
  esac
  NEED_REFRESH=1
}

maybe_auto_rollup() {
  case "$DO_AUTO_ROLLUP" in 0|false|FALSE|no|NO) return 0 ;; esac
  case "$DO_SAMPLE" in 1|true|TRUE|yes|YES) return 0 ;; esac
  [ -s "$DATA/stats_shadow_raw.jsonl" ] || return 0
  [ -x "$BIN/stats_shadow_rollup.sh" ] || return 0
  rollup_date="$(latest_raw_date)"
  [ -n "$rollup_date" ] || rollup_date="$(date +%Y-%m-%d 2>/dev/null)"
  case "$rollup_date" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      sh "$BIN/stats_shadow_rollup.sh" "$rollup_date" >/dev/null 2>&1 || true
      AUTO_ROLLUP_USED=true
      AUTO_ROLLUP_DATE="$rollup_date"
      NEED_REFRESH=1
      ;;
  esac
}

devices_summary() {
  DEV_TOTAL=0; DEV_WITH_IP=0; DEV_ONLINE=0; DEV_BLOCKED=0; DEV_ACTIVE=0
  f="$DATA/devices.json"
  [ -f "$f" ] || return 0
  tmp="$RUN/stats_v52_gray_observe.devices.$$"
  grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$f" > "$tmp" 2>/dev/null || :
  [ -f "$tmp" ] || return 0
  DEV_TOTAL="$(wc -l < "$tmp" 2>/dev/null | tr -d ' ')"
  DEV_WITH_IP="$(grep -c '"ip"[[:space:]]*:[[:space:]]*"[0-9]' "$tmp" 2>/dev/null || :)"
  DEV_ONLINE="$(grep -c '"status"[[:space:]]*:[[:space:]]*"online"' "$tmp" 2>/dev/null || :)"
  DEV_BLOCKED="$(grep -c '"status"[[:space:]]*:[[:space:]]*"blocked"' "$tmp" 2>/dev/null || :)"
  DEV_ACTIVE="$(grep -c '"active"[[:space:]]*:[[:space:]]*true' "$tmp" 2>/dev/null || :)"
  rm -f "$tmp" 2>/dev/null
  DEV_TOTAL="$(num "$DEV_TOTAL" 0)"; DEV_WITH_IP="$(num "$DEV_WITH_IP" 0)"; DEV_ONLINE="$(num "$DEV_ONLINE" 0)"; DEV_BLOCKED="$(num "$DEV_BLOCKED" 0)"; DEV_ACTIVE="$(num "$DEV_ACTIVE" 0)"
}

module_version() {
  MODULE_PROP=""
  [ -f "$MODDIR/module.prop" ] && MODULE_PROP="$MODDIR/module.prop"
  [ -z "$MODULE_PROP" ] && [ -f "$HNC_DIR/module.prop" ] && MODULE_PROP="$HNC_DIR/module.prop"
  VERSION=unknown; VERSION_CODE=unknown
  if [ -n "$MODULE_PROP" ]; then
    VERSION="$(awk -F= '$1=="version"{print $2; exit}' "$MODULE_PROP" 2>/dev/null)"; [ -n "$VERSION" ] || VERSION=unknown
    VERSION_CODE="$(awk -F= '$1=="versionCode"{print $2; exit}' "$MODULE_PROP" 2>/dev/null)"; [ -n "$VERSION_CODE" ] || VERSION_CODE=unknown
  fi
}

maybe_sample
maybe_auto_rollup
READINESS_TXT="$RUN/stats_migration_readiness.txt"
GRAY_TXT="$RUN/stats_v52_gray_report.txt"
REVIEW_TXT="$RUN/stats_v52_review_bundle.txt"
RC_TXT="$RUN/stats_v52_rc1_switch.txt"
run_text_helper stats_migration_readiness.sh "$READINESS_TXT" text
run_text_helper stats_v52_gray_report.sh "$GRAY_TXT" text
run_text_helper stats_v52_review_bundle.sh "$REVIEW_TXT" text
run_text_helper stats_v52_rc1_switch.sh "$RC_TXT" text
module_version
devices_summary

readiness_status="$(kv_get "$READINESS_TXT" status unknown)"
gray_status="$(kv_get "$GRAY_TXT" status unknown)"
review_status="$(kv_get "$REVIEW_TXT" status unknown)"
shadow_state="$(kv_get "$READINESS_TXT" shadow_state no_shadow_data)"
shadow_quality="$(kv_get "$READINESS_TXT" shadow_quality missing)"
compare_quality="$(kv_get "$READINESS_TXT" compare_quality not_available)"
shadow_raw_lines="$(num "$(kv_get "$READINESS_TXT" shadow_raw_lines "$(file_lines "$DATA/stats_shadow_raw.jsonl")")" 0)"
shadow_daily_lines="$(num "$(kv_get "$READINESS_TXT" shadow_daily_lines "$(file_lines "$DATA/stats_shadow_daily.jsonl")")" 0)"
shadow_daily_samples="$(num "$(kv_get "$READINESS_TXT" shadow_daily_samples 0)" 0)"
shadow_latest_ts="$(num "$(kv_get "$READINESS_TXT" shadow_latest_ts 0)" 0)"
shadow_raw_total_rx="$(num "$(kv_get "$READINESS_TXT" shadow_raw_total_rx 0)" 0)"
shadow_raw_total_tx="$(num "$(kv_get "$READINESS_TXT" shadow_raw_total_tx 0)" 0)"
shadow_daily_total_rx="$(num "$(kv_get "$READINESS_TXT" shadow_daily_total_rx 0)" 0)"
shadow_daily_total_tx="$(num "$(kv_get "$READINESS_TXT" shadow_daily_total_tx 0)" 0)"
compare_matched_keys="$(num "$(kv_get "$READINESS_TXT" compare_matched_keys 0)" 0)"
compare_missing_in_legacy="$(num "$(kv_get "$READINESS_TXT" compare_missing_in_legacy 0)" 0)"
compare_missing_in_shadow="$(num "$(kv_get "$READINESS_TXT" compare_missing_in_shadow 0)" 0)"
compare_mismatched_keys="$(num "$(kv_get "$READINESS_TXT" compare_mismatched_keys 0)" 0)"
legacy_default_preserved="$(bool "$(kv_get "$RC_TXT" legacy_default_preserved true)")"
default_source="$(kv_get "$RC_TXT" default_source legacy)"
rc1_enabled="$(bool "$(kv_get "$RC_TXT" rc1_enabled false)")"
rc_enabled="$(bool "$(kv_get "$RC_TXT" rc_enabled false)")"

case "$shadow_latest_ts" in 0|'') sample_age=0 ;; *) sample_age=$((TS - shadow_latest_ts)); [ "$sample_age" -lt 0 ] && sample_age=0 ;; esac
# Do not add these counters with shell arithmetic. On some Android shells,
# totals above 2 GiB can wrap a signed 32-bit intermediate and make positive
# traffic look non-positive. Treat any positive component as traffic_seen.
if positive_num "$shadow_raw_total_rx" || positive_num "$shadow_raw_total_tx" || positive_num "$shadow_daily_total_rx" || positive_num "$shadow_daily_total_tx"; then
  traffic_state=traffic_seen
  case "$shadow_quality" in
    observed_zero_traffic|missing|warmup|warn_no_daily_samples) shadow_quality=observed ;;
  esac
elif [ "$shadow_raw_lines" -gt 0 ] || [ "$shadow_daily_lines" -gt 0 ]; then
  traffic_state=zero_traffic_observed
else
  traffic_state=no_shadow_traffic
fi

status=pass
reason="shadow observation is usable"
recommendation="continue real-device gray observation with legacy default preserved"
case "$shadow_state" in shadow_rollup_seen|shadow_raw_seen) ;; *) status=fail; reason="shadow raw/daily data is not visible"; recommendation="enable shadow sampling and run rc1.15 sample/rollup checks before widening observation" ;; esac
if [ "$status" != fail ] && [ "$traffic_state" != traffic_seen ]; then status=warn; reason="shadow is visible but traffic is still zero or not yet observed"; recommendation="keep legacy default and run the rc1.21 real-traffic checklist"; fi
if [ "$status" != fail ]; then case "$compare_quality" in compared|match|pass|ok) ;; *) status=warn; reason="legacy/shadow comparison still needs review"; recommendation="collect more real traffic samples, then rerun gray observe/report before optional source switching" ;; esac; fi
if [ "$legacy_default_preserved" != true ] || [ "$default_source" != legacy ] || [ "$rc1_enabled" = true ] || [ "$rc_enabled" = true ]; then status=fail; reason="legacy default or RC disabled guard is not preserved"; recommendation="rollback to legacy default before continuing gray observation"; fi
sample_requested=false; case "$DO_SAMPLE" in 1|true|TRUE|yes|YES) sample_requested=true ;; esac
refresh_requested=false; case "$DO_REFRESH" in 1|true|TRUE|yes|YES) refresh_requested=true ;; esac
auto_rollup_used=$AUTO_ROLLUP_USED
auto_rollup_date=$AUTO_ROLLUP_DATE

cat > "$OUT_TXT" <<EOF
HNC v5.2-rc1.21 gray observation
status=$status
reason=$reason
recommendation=$recommendation
version=$VERSION
versionCode=$VERSION_CODE
module_prop=$MODULE_PROP
legacy_default_preserved=$legacy_default_preserved
default_source=$default_source
rc1_enabled=$rc1_enabled
rc_enabled=$rc_enabled
readiness_status=$readiness_status
gray_report_status=$gray_status
review_bundle_status=$review_status
shadow_state=$shadow_state
shadow_quality=$shadow_quality
traffic_state=$traffic_state
shadow_raw_lines=$shadow_raw_lines
shadow_daily_lines=$shadow_daily_lines
shadow_daily_samples=$shadow_daily_samples
shadow_latest_ts=$shadow_latest_ts
sample_age_seconds=$sample_age
shadow_raw_total_rx=$shadow_raw_total_rx
shadow_raw_total_tx=$shadow_raw_total_tx
shadow_daily_total_rx=$shadow_daily_total_rx
shadow_daily_total_tx=$shadow_daily_total_tx
compare_quality=$compare_quality
compare_matched_keys=$compare_matched_keys
compare_missing_in_legacy=$compare_missing_in_legacy
compare_missing_in_shadow=$compare_missing_in_shadow
compare_mismatched_keys=$compare_mismatched_keys
devices_total=$DEV_TOTAL
devices_with_ip=$DEV_WITH_IP
devices_online=$DEV_ONLINE
devices_blocked=$DEV_BLOCKED
devices_active=$DEV_ACTIVE
sample_requested=$sample_requested
refresh_requested=$refresh_requested
auto_rollup_used=$auto_rollup_used
auto_rollup_date=$auto_rollup_date
EOF

cat > "$OUT_JSON" <<EOF
{"ok":true,"status":"$(json_escape "$status")","reason":"$(json_escape "$reason")","recommendation":"$(json_escape "$recommendation")","version":"$(json_escape "$VERSION")","versionCode":"$(json_escape "$VERSION_CODE")","module_prop":"$(json_escape "$MODULE_PROP")","legacy_default_preserved":$legacy_default_preserved,"default_source":"$(json_escape "$default_source")","rc1_enabled":$rc1_enabled,"rc_enabled":$rc_enabled,"readiness_status":"$(json_escape "$readiness_status")","gray_report_status":"$(json_escape "$gray_status")","review_bundle_status":"$(json_escape "$review_status")","shadow_state":"$(json_escape "$shadow_state")","shadow_quality":"$(json_escape "$shadow_quality")","traffic_state":"$(json_escape "$traffic_state")","shadow_raw_lines":$shadow_raw_lines,"shadow_daily_lines":$shadow_daily_lines,"shadow_daily_samples":$shadow_daily_samples,"shadow_latest_ts":$shadow_latest_ts,"sample_age_seconds":$sample_age,"shadow_raw_total_rx":$shadow_raw_total_rx,"shadow_raw_total_tx":$shadow_raw_total_tx,"shadow_daily_total_rx":$shadow_daily_total_rx,"shadow_daily_total_tx":$shadow_daily_total_tx,"compare_quality":"$(json_escape "$compare_quality")","compare_matched_keys":$compare_matched_keys,"compare_missing_in_legacy":$compare_missing_in_legacy,"compare_missing_in_shadow":$compare_missing_in_shadow,"compare_mismatched_keys":$compare_mismatched_keys,"devices_total":$DEV_TOTAL,"devices_with_ip":$DEV_WITH_IP,"devices_online":$DEV_ONLINE,"devices_blocked":$DEV_BLOCKED,"devices_active":$DEV_ACTIVE,"sample_requested":$sample_requested,"refresh_requested":$refresh_requested,"auto_rollup_used":$auto_rollup_used,"auto_rollup_date":"$(json_escape "$auto_rollup_date")"}
EOF

cat > "$OUT_MD" <<EOF
# HNC v5.2-rc1.21 灰度观察

- status: $status
- reason: $reason
- recommendation: $recommendation
- version: $VERSION / $VERSION_CODE
- legacy default: $legacy_default_preserved, source=$default_source, rc1_enabled=$rc1_enabled, rc_enabled=$rc_enabled

## Shadow

- state: $shadow_state
- quality: $shadow_quality
- traffic: $traffic_state
- raw lines: $shadow_raw_lines
- daily lines: $shadow_daily_lines
- daily samples: $shadow_daily_samples
- latest ts: $shadow_latest_ts
- sample age seconds: $sample_age
- raw rx/tx: $shadow_raw_total_rx / $shadow_raw_total_tx
- daily rx/tx: $shadow_daily_total_rx / $shadow_daily_total_tx
- auto rollup: $auto_rollup_used ${auto_rollup_date:+($auto_rollup_date)}

## Legacy vs Shadow

- compare quality: $compare_quality
- matched: $compare_matched_keys
- missing in legacy: $compare_missing_in_legacy
- missing in shadow: $compare_missing_in_shadow
- mismatched: $compare_mismatched_keys

## Devices

- total: $DEV_TOTAL
- with IP: $DEV_WITH_IP
- online: $DEV_ONLINE
- blocked: $DEV_BLOCKED
- active: $DEV_ACTIVE

## rc1.21 实机灰度 checklist

- [ ] 单设备连热点刷网页后，shadow rx/tx 增长
- [ ] 单设备测速后，shadow/legacy 对比不出现大幅异常
- [ ] 设备断开再连接后，MAC 归属不变
- [ ] 热点重启后，shadow sample/rollup 仍能生成
- [ ] blocked 设备状态能被报告识别，不误判为 source 切换失败
- [ ] 多设备同时连接时，devices_total 与 shadow device 数大致一致
- [ ] 跨日或手动指定日期 rollup 后，daily 样本继续累加
EOF

case "$MODE" in json) cat "$OUT_JSON" ;; md|markdown) cat "$OUT_MD" ;; text|txt|*) cat "$OUT_TXT" ;; esac
