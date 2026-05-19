#!/system/bin/sh
# HNC hotfix20.4 legacy JSON fallback observer
# Read-only by default. Helps decide whether legacy JSON paths can be pruned in
# a later release without silently breaking devices.

set +e

HNC="${HNC:-/data/local/hnc}"
RUN="$HNC/run"
LOG="${JSON_LEGACY_FALLBACK_LOG:-$RUN/json_legacy_fallback.log}"
COUNT="${JSON_LEGACY_FALLBACK_COUNT:-$RUN/json_legacy_fallback.count}"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

read_count() {
  if [ -f "$COUNT" ]; then
    c="$(cat "$COUNT" 2>/dev/null)"
    case "$c" in *[!0-9]*|'') echo 0 ;; *) echo "$c" ;; esac
  else
    echo 0
  fi
}

last_line() {
  [ -f "$LOG" ] && tail -1 "$LOG" 2>/dev/null || true
}

summary_ops() {
  [ -f "$LOG" ] || return 0
  # Lines are like: timestamp json_set op=name_set reason=object-set
  awk '{ for (i=1;i<=NF;i++) if ($i ~ /^op=/) { sub(/^op=/,"",$i); c[$i]++ } } END { for (k in c) print k, c[k] }' "$LOG" 2>/dev/null | sort
}

cmd="${1:-status}"
case "$cmd" in
  status)
    echo "HNC legacy JSON fallback status"
    echo "count=$(read_count)"
    echo "log=$LOG"
    echo "last=$(last_line)"
    echo "ops:"
    summary_ops | while read -r op n; do
      [ -n "$op" ] && echo "  $op=$n"
    done
    ;;
  json)
    ts="$(date +%s 2>/dev/null || echo 0)"
    cnt="$(read_count)"
    last="$(last_line)"
    echo "{"
    echo "  \"ok\": true,"
    echo "  \"timestamp\": $ts,"
    echo "  \"count\": $cnt,"
    echo "  \"log\": \"$(json_escape "$LOG")\","
    echo "  \"last\": \"$(json_escape "$last")\","
    echo "  \"ops\": {"
    first=1
    summary_ops | while read -r op n; do
      [ -n "$op" ] || continue
      if [ "$first" = 1 ]; then first=0; else printf ',\n'; fi
      printf '    "%s": %s' "$(json_escape "$op")" "$n"
    done
    echo ""
    echo "  }"
    echo "}"
    ;;
  reset)
    mkdir -p "$RUN" 2>/dev/null || true
    : > "$LOG" 2>/dev/null || true
    echo 0 > "$COUNT" 2>/dev/null || true
    echo "reset legacy fallback telemetry"
    ;;
  *)
    echo "usage: $0 [status|json|reset]" >&2
    exit 2
    ;;
esac
