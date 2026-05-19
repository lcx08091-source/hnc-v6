#!/system/bin/sh
# stats_v52_rc_control.sh — HNC hotfix22.0 guarded v5.2 stats RC control
# Safe control helper. It does not rewrite stats files and does not change tc/iptables/watchdog.
# It only creates/removes a small runtime flag after readiness checks.
#
# Usage:
#   sh stats_v52_rc_control.sh status|json|text
#   sh stats_v52_rc_control.sh enable      # requires readiness=ready unless HNC_FORCE_V52_RC=1
#   sh stats_v52_rc_control.sh disable

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
MODE=${1:-status}
FLAG="$RUN/stats_v52_rc.enabled"
OUT_JSON="$RUN/stats_v52_rc_control.json"
OUT_TXT="$RUN/stats_v52_rc_control.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

now_ts() { date +%s 2>/dev/null || echo 0; }

readiness_json() {
  if [ -x "$BIN/stats_migration_readiness.sh" ]; then
    sh "$BIN/stats_migration_readiness.sh" json 2>/dev/null
  else
    echo '{"ok":false,"status":"missing","ready":false}'
  fi
}

json_status_of() {
  printf '%s' "$1" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1
}

json_ready_of() {
  printf '%s' "$1" | sed -n 's/.*"ready":\(true\|false\).*/\1/p' | head -1
}

write_report() {
  status="$1"
  enabled="$2"
  ready="$3"
  reason="$4"
  recommendation="$5"
  readiness_status="$6"
  flag_exists=false
  [ -f "$FLAG" ] && flag_exists=true
  ts="$(now_ts)"

  {
    echo "HNC v5.2 stats RC control"
    echo "status=$status"
    echo "enabled=$enabled"
    echo "flag_exists=$flag_exists"
    echo "ready=$ready"
    echo "readiness_status=$readiness_status"
    echo "reason=$reason"
    echo "recommendation=$recommendation"
    echo "flag=$FLAG"
  } > "$OUT_TXT"

  printf '{"ok":true,"status":"%s","enabled":%s,"flag_exists":%s,"ready":%s,"readiness_status":"%s","reason":"%s","recommendation":"%s","timestamp":%s,"paths":{"flag":"%s","json":"%s","text":"%s"}}\n' \
    "$(json_escape "$status")" "$enabled" "$flag_exists" "$ready" "$(json_escape "$readiness_status")" "$(json_escape "$reason")" "$(json_escape "$recommendation")" "$ts" \
    "$(json_escape "$FLAG")" "$(json_escape "$OUT_JSON")" "$(json_escape "$OUT_TXT")" > "$OUT_JSON"
}

report_status() {
  rj="$(readiness_json)"
  rs="$(json_status_of "$rj")"
  rr="$(json_ready_of "$rj")"
  [ -n "$rs" ] || rs="unknown"
  [ -n "$rr" ] || rr=false
  enabled=false
  status="disabled"
  reason="v5.2 stats RC switch is not enabled"
  recommendation="keep legacy stats as default; enable only after readiness reports ready"

  if [ -f "$FLAG" ]; then
    enabled=true
    if [ "$rr" = true ]; then
      status="enabled"
      reason="v5.2 stats RC flag is enabled and readiness is ready"
      recommendation="continue monitoring compare/readiness diagnostics and keep rollback path available"
    else
      status="enabled_not_ready"
      reason="v5.2 stats RC flag exists but readiness is not ready"
      recommendation="disable RC flag and inspect stats diagnostics before switching"
    fi
  else
    case "$rs" in
      ready)
        status="ready"
        reason="readiness gate reports ready but RC flag remains disabled"
        recommendation="safe to test RC flag manually; keep legacy fallback available"
        ;;
      blocked)
        status="blocked"
        reason="readiness gate is blocked"
        recommendation="do not enable v5.2 stats RC"
        ;;
      warmup|not_ready|missing|unknown|*)
        status="disabled"
        reason="readiness gate is not ready"
        recommendation="keep collecting shadow stats and compare diagnostics"
        ;;
    esac
  fi
  write_report "$status" "$enabled" "$rr" "$reason" "$recommendation" "$rs"
}

case "$MODE" in
  enable)
    rj="$(readiness_json)"
    rs="$(json_status_of "$rj")"
    rr="$(json_ready_of "$rj")"
    [ -n "$rs" ] || rs="unknown"
    [ -n "$rr" ] || rr=false
    if [ "$rr" = true ] || [ "$HNC_FORCE_V52_RC" = 1 ]; then
      {
        echo "enabled_at=$(now_ts)"
        echo "readiness_status=$rs"
        echo "forced=${HNC_FORCE_V52_RC:-0}"
      } > "$FLAG"
      write_report "enabled" true "$rr" "v5.2 stats RC flag enabled" "monitor stats_compare and stats_migration_readiness; disable on anomalies" "$rs"
    else
      write_report "blocked" false "$rr" "readiness is not ready; refused to enable RC flag" "run stats diagnostics or set HNC_FORCE_V52_RC=1 only for controlled testing" "$rs"
      cat "$OUT_TXT"
      exit 2
    fi
    ;;
  disable)
    rm -f "$FLAG" 2>/dev/null
    rj="$(readiness_json)"
    rs="$(json_status_of "$rj")"; [ -n "$rs" ] || rs="unknown"
    rr="$(json_ready_of "$rj")"; [ -n "$rr" ] || rr=false
    write_report "disabled" false "$rr" "v5.2 stats RC flag disabled" "legacy stats remains the safe default" "$rs"
    ;;
  json|status|text|*)
    report_status
    ;;
esac

case "$MODE" in
  json) cat "$OUT_JSON" ;;
  *) cat "$OUT_TXT" ;;
esac
exit 0
