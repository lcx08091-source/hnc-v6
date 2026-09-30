#!/system/bin/sh
# stats_health_summary.sh — HNC hotfix22.2 stats health summary
# Read-only aggregator for the live (iptables/legacy) stats diagnostics.
# v6.x: v5.2 shadow/compare/migration/rc helpers were removed; only the three
# live diag helpers (stats_diag / stats_identity_diag / stats_retention_diag)
# are aggregated now.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
BIN="$HNC_DIR/bin"
RUN="$HNC_DIR/run"
MODE=${1:-json}
OUT_JSON="$RUN/stats_health_summary.json"
OUT_TXT="$RUN/stats_health_summary.txt"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  in="$1"
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
  printf '%s' "$out"
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
  case "$v" in
    *\"status\":\"*\"*)
      s=${v#*\"status\":\"}
      s=${s%%\"*}
      [ -n "$s" ] || s="unknown"
      ;;
    # stats_diag / stats_identity_diag 不输出 status 字段, 只有 "ok":true
    *\"ok\":true*) s="ok" ;;
    *) s="unknown" ;;
  esac
  printf '%s' "$s"
}

_j="$(helper_json stats_diag.sh)"; DIAG_STATUS=$(status_of_into "$_j")
_j="$(helper_json stats_identity_diag.sh)"; IDENT_STATUS=$(status_of_into "$_j")
_j="$(helper_json stats_retention_diag.sh)"; RET_STATUS=$(status_of_into "$_j")

OVERALL="ok"
RECOMMENDATION="stats diagnostics look healthy"
for s in "$DIAG_STATUS" "$IDENT_STATUS" "$RET_STATUS"; do
  case "$s" in
    fail|bad|error|blocked) OVERALL="fail" ;;
    warn|missing|unknown) [ "$OVERALL" = "ok" ] && OVERALL="warn" ;;
  esac
done
if [ "$OVERALL" = "fail" ]; then
  RECOMMENDATION="stats diagnostics failed; inspect diagnostics bundle first"
elif [ "$OVERALL" = "warn" ]; then
  RECOMMENDATION="stats diagnostics incomplete; check stats sampler / retention"
fi

HAS_DIAG=$(present_of stats_diag.sh)
HAS_ID=$(present_of stats_identity_diag.sh)
HAS_RET=$(present_of stats_retention_diag.sh)

{
  echo "HNC stats health summary"
  echo "status=$OVERALL"
  echo "recommendation=$RECOMMENDATION"
  echo "stats_diag=$DIAG_STATUS"
  echo "stats_identity=$IDENT_STATUS"
  echo "stats_retention=$RET_STATUS"
  echo "has_stats_diag=$HAS_DIAG"
  echo "has_stats_identity_diag=$HAS_ID"
  echo "has_stats_retention_diag=$HAS_RET"
} > "$OUT_TXT"

EO=$(json_escape "$OVERALL")
ER=$(json_escape "$RECOMMENDATION")
ED=$(json_escape "$DIAG_STATUS")
EI=$(json_escape "$IDENT_STATUS")
ET=$(json_escape "$RET_STATUS")
EJ=$(json_escape "$OUT_JSON")
EX=$(json_escape "$OUT_TXT")

printf '{"ok":true,"status":"%s","recommendation":"%s","helpers":{"stats_diag":%s,"stats_identity_diag":%s,"stats_retention_diag":%s},"components":{"stats_diag":"%s","stats_identity":"%s","stats_retention":"%s"},"paths":{"json":"%s","text":"%s"}}\n' \
  "$EO" "$ER" "$HAS_DIAG" "$HAS_ID" "$HAS_RET" \
  "$ED" "$EI" "$ET" "$EJ" "$EX" > "$OUT_JSON"

case "$MODE" in
  text|status) cat "$OUT_TXT" ;;
  *) cat "$OUT_JSON" ;;
esac
exit 0
