#!/system/bin/sh
# stats_v52_rc1_switch.sh — controlled gray switch (since v5.2-rc1)
# Safe staged entry for v5.2 stats RC testing. Legacy stats remains default.
# It toggles only the existing v5.2 RC flag + shadow sampling flag and offers
# one-command rollback. It does not touch tc/iptables/watchdog or rewrite stats.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
MODE=${1:-status}
RC_FLAG="$RUN/stats_v52_rc.enabled"
RC1_FLAG="$RUN/stats_v52_rc1.enabled"
OUT_JSON="$RUN/stats_v52_rc1_switch.json"
OUT_TXT="$RUN/stats_v52_rc1_switch.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape() { printf '%s' "$1"; }

helper_json() {
  h="$1"
  if [ -x "$BIN/$h" ]; then sh "$BIN/$h" json 2>/dev/null; else echo '{"ok":false,"status":"missing"}'; fi
}

status_of() {
  body="$1"
  case "$body" in *\"status\":\"*\"*) s=${body#*\"status\":\"}; s=${s%%\"*}; echo "$s" ;; *) echo unknown ;; esac
}

bool_key_of() {
  key="$1"; body="$2"
  case "$body" in *\"$key\":true*) echo true ;; *\"$key\":false*) echo false ;; *) echo false ;; esac
}

default_source_of() {
  body="$1"
  case "$body" in *\"default_source\":\"shadow\"*) echo shadow ;; *) echo legacy ;; esac
}

write_report() {
  status="$1"; reason="$2"; recommendation="$3"; rc_status="$4"; shadow_status="$5"; device_status="$6"; source_status="$7"; shadow_effective="$8"; default_source="$9"
  rc_enabled=false; rc1_enabled=false
  [ -f "$RC_FLAG" ] && rc_enabled=true
  [ -f "$RC1_FLAG" ] && rc1_enabled=true
  [ -n "$shadow_effective" ] || shadow_effective=false
  [ -n "$default_source" ] || default_source=legacy
  legacy_default_preserved=false
  [ "$default_source" = legacy ] && legacy_default_preserved=true

  {
    echo "HNC v5.2-rc1 stats gray switch"
    echo "status=$status"
    echo "rc1_enabled=$rc1_enabled"
    echo "rc_enabled=$rc_enabled"
    echo "shadow_effective_enabled=$shadow_effective"
    echo "default_source=$default_source"
    echo "legacy_default_preserved=$legacy_default_preserved"
    echo "rc_status=$rc_status"
    echo "shadow_status=$shadow_status"
    echo "device_check_status=$device_status"
    echo "source_status=$source_status"
    echo "reason=$reason"
    echo "recommendation=$recommendation"
    echo "rc_flag=$RC_FLAG"
    echo "rc1_flag=$RC1_FLAG"
  } > "$OUT_TXT"

  printf '{"ok":true,"status":"%s","rc1_enabled":%s,"rc_enabled":%s,"shadow_effective_enabled":%s,"default_source":"%s","legacy_default_preserved":%s,"rc_status":"%s","shadow_status":"%s","device_check_status":"%s","source_status":"%s","reason":"%s","recommendation":"%s","paths":{"rc_flag":"%s","rc1_flag":"%s","json":"%s","text":"%s"}}\n' \
    "$(json_escape "$status")" "$rc1_enabled" "$rc_enabled" "$shadow_effective" "$(json_escape "$default_source")" "$legacy_default_preserved" \
    "$(json_escape "$rc_status")" "$(json_escape "$shadow_status")" "$(json_escape "$device_status")" "$(json_escape "$source_status")" \
    "$(json_escape "$reason")" "$(json_escape "$recommendation")" \
    "$(json_escape "$RC_FLAG")" "$(json_escape "$RC1_FLAG")" "$(json_escape "$OUT_JSON")" "$(json_escape "$OUT_TXT")" > "$OUT_JSON"
}

report_status() {
  rc_json="$(helper_json stats_v52_rc_control.sh)"
  shadow_json="$(helper_json stats_shadow_control.sh)"
  device_json="$(helper_json stats_v52_device_check.sh)"
  source_json="$(helper_json stats_source_diag.sh)"
  rc_status="$(status_of "$rc_json")"
  shadow_status="$(status_of "$shadow_json")"
  device_status="$(status_of "$device_json")"
  source_status="$(status_of "$source_json")"
  shadow_effective="$(bool_key_of effective_enabled "$shadow_json")"
  default_source="$(default_source_of "$source_json")"

  if [ -f "$RC1_FLAG" ] && [ -f "$RC_FLAG" ]; then
    write_report enabled "v5.2-rc1 gray switch is enabled; legacy remains default source" "monitor stats_compare/readiness/smoke; run rollback on anomalies" "$rc_status" "$shadow_status" "$device_status" "$source_status" "$shadow_effective" "$default_source"
  elif [ -f "$RC1_FLAG" ] && [ ! -f "$RC_FLAG" ]; then
    write_report drift "v5.2-rc1 flag exists but base RC flag is missing" "run rollback, then re-enable only after device_check is clean" "$rc_status" "$shadow_status" "$device_status" "$source_status" "$shadow_effective" "$default_source"
  else
    write_report disabled "v5.2-rc1 gray switch is disabled; legacy stats is still default" "enable only after stats_v52_device_check reports rc_enable_ready=true" "$rc_status" "$shadow_status" "$device_status" "$source_status" "$shadow_effective" "$default_source"
  fi
}

do_enable() {
  if [ ! -x "$BIN/stats_v52_rc_control.sh" ]; then write_report blocked "stats_v52_rc_control.sh is missing" "do not enter v5.2-rc1 without RC guard" missing unknown unknown unknown false legacy; cat "$OUT_TXT"; exit 2; fi
  if [ ! -x "$BIN/stats_shadow_control.sh" ]; then write_report blocked "stats_shadow_control.sh is missing" "do not enter v5.2-rc1 without shadow sampling rollback" unknown missing unknown unknown false legacy; cat "$OUT_TXT"; exit 2; fi

  sh "$BIN/stats_v52_rc_control.sh" enable >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    rc_status="$(status_of "$(helper_json stats_v52_rc_control.sh)")"
    write_report blocked "base RC control refused enable" "run stats_v52_device_check.sh json and fix readiness/device gate before enabling" "$rc_status" unknown unknown unknown false legacy
    cat "$OUT_TXT"; exit 2
  fi

  sh "$BIN/stats_shadow_control.sh" enable >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    sh "$BIN/stats_v52_rc_control.sh" disable >/dev/null 2>&1
    rm -f "$RC1_FLAG" 2>/dev/null
    write_report blocked "shadow sampling enable failed; base RC flag was rolled back" "inspect stats_shadow_control.sh before retrying" rolled_back fail unknown unknown false legacy
    cat "$OUT_TXT"; exit 2
  fi

  { echo "enabled_at=$(date +%s 2>/dev/null || echo 0)"; echo "default_source=legacy"; echo "shadow_sampling=enabled"; echo "note=v5.2-rc1 gray switch keeps legacy as default source"; } > "$RC1_FLAG"
  write_report enabled "v5.2-rc1 gray switch enabled with legacy default preserved" "monitor diagnostics; use rollback if compare/readiness/smoke becomes abnormal" enabled ok checked ok true legacy
}

do_disable() {
  [ -x "$BIN/stats_shadow_control.sh" ] && sh "$BIN/stats_shadow_control.sh" disable >/dev/null 2>&1
  [ -x "$BIN/stats_v52_rc_control.sh" ] && sh "$BIN/stats_v52_rc_control.sh" disable >/dev/null 2>&1
  rm -f "$RC1_FLAG" 2>/dev/null
  write_report disabled "v5.2-rc1 gray switch disabled and rollback completed" "legacy stats remains default; inspect diagnostics before re-enabling" disabled disabled unknown ok false legacy
}

case "$MODE" in
  enable) do_enable ;;
  disable|rollback) do_disable ;;
  json|status|text|*) report_status ;;
esac

case "$MODE" in json) cat "$OUT_JSON" ;; *) cat "$OUT_TXT" ;; esac
exit 0
