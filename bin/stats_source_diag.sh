#!/system/bin/sh
# stats_source_diag.sh — HNC hotfix21.8 WebUI/API stats source diagnostic
# Read-only helper. It does not change stats source or write stats data.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
BIN="$HNC_DIR/bin"
MODE=${1:-json}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
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

legacy_available=false
shadow_available=false
if [ "$legacy_raw_lines" != 0 ] || [ "$legacy_daily_lines" != 0 ]; then legacy_available=true; fi
if [ "$shadow_raw_lines" != 0 ] || [ "$shadow_daily_lines" != 0 ]; then shadow_available=true; fi

shadow_control_raw=""
shadow_effective=false
if [ -x "$BIN/stats_shadow_control.sh" ]; then
  shadow_control_raw="$(sh "$BIN/stats_shadow_control.sh" json 2>/dev/null)"
  case "$shadow_control_raw" in *'"effective_enabled":true'*) shadow_effective=true ;; esac
fi

status="ok"
recommendation="keep WebUI stats source on legacy until shadow has comparable samples"
if [ "$shadow_available" = true ] && [ "$shadow_effective" = true ]; then
  status="ok"
  recommendation="shadow stats is available for optional WebUI comparison"
elif [ "$shadow_available" = true ]; then
  status="warn"
  recommendation="shadow stats data exists but shadow sampling is not currently enabled"
fi

case "$MODE" in
  text|status)
    cat <<EOF2
HNC stats source diagnostic
status=$status
api_supported_sources=legacy,shadow
default_source=legacy
legacy_available=$legacy_available
shadow_available=$shadow_available
shadow_effective_enabled=$shadow_effective
legacy_raw_lines=$legacy_raw_lines
legacy_daily_lines=$legacy_daily_lines
shadow_raw_lines=$shadow_raw_lines
shadow_daily_lines=$shadow_daily_lines
recommendation=$recommendation
EOF2
    ;;
  json|*)
    cat <<EOF2
{"ok":true,"status":"$(json_escape "$status")","api_supported_sources":["legacy","shadow"],"default_source":"legacy","legacy_available":$legacy_available,"shadow_available":$shadow_available,"shadow_effective_enabled":$shadow_effective,"recommendation":"$(json_escape "$recommendation")","files":{"legacy_raw":{"path":"$(json_escape "$legacy_raw")","lines":$legacy_raw_lines,"size":$legacy_raw_size},"legacy_daily":{"path":"$(json_escape "$legacy_daily")","lines":$legacy_daily_lines,"size":$legacy_daily_size},"shadow_raw":{"path":"$(json_escape "$shadow_raw")","lines":$shadow_raw_lines,"size":$shadow_raw_size},"shadow_daily":{"path":"$(json_escape "$shadow_daily")","lines":$shadow_daily_lines,"size":$shadow_daily_size}},"shadow_control_raw":"$(json_escape "$shadow_control_raw")"}
EOF2
    ;;
esac
exit 0
