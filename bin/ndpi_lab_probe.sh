#!/system/bin/sh
# ndpi_lab_probe.sh — HNC v5.3.0-rc24.1 optional nDPI bridge probe
# Safe by default: this script only detects optional external nDPI binaries and
# writes a status JSON. It does not start NFQUEUE, does not redirect DNS, and
# does not alter offload/tc/iptables.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
ETC="$HNC_DIR/etc"
LOG_DIR="$HNC_DIR/logs"
CONF="$ETC/dpi_ndpi_config.json"
STATE="$RUN/ndpi_lab_state.json"
LOG="$LOG_DIR/ndpi_lab.log"
mkdir -p "$RUN" "$ETC" "$LOG_DIR" 2>/dev/null || true

json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }
read_json_string(){ key="$1"; file="$2"; sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" 2>/dev/null | head -1; }
read_json_bool(){ key="$1"; file="$2"; sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$file" 2>/dev/null | head -1; }

write_state(){
  mode="$1"; reason="$2"; engine="$3"; version="$4"; iface="$5"; enabled="$6"
  now=$(date +%s 2>/dev/null || echo 0)
  er=$(json_escape "$reason"); ee=$(json_escape "$engine"); ev=$(json_escape "$version"); ei=$(json_escape "$iface")
  [ "$enabled" = "true" ] || enabled=false
  bundled=false
  case "$engine" in
    "$HNC_DIR"/bin/hnc_ndpi_probe|"$HNC_DIR"/bin/ndpiReader|"$HNC_DIR"/bin/hnc_dpid_ndpi) bundled=true ;;
  esac
  cat > "$STATE.tmp" <<EOF_STATE
{"schema_version":"1.0","generated_at":$now,"available":$([ -n "$engine" ] && echo true || echo false),"enabled":$enabled,"mode":"$mode","reason":"$er","engine_path":"$ee","engine_version":"$ev","iface":"$ei","bundled":$bundled,"dangerous_path":false,"note":"optional nDPI-lab bridge only; HNC built-in Go dpid remains the default engine"}
EOF_STATE
  mv -f "$STATE.tmp" "$STATE" 2>/dev/null || true
}

# Install default config if module copied data/ but runtime etc does not yet have it.
if [ ! -f "$CONF" ] && [ -f "$HNC_DIR/data/dpi_ndpi_config.json" ]; then
  cp -f "$HNC_DIR/data/dpi_ndpi_config.json" "$CONF" 2>/dev/null || true
  chmod 644 "$CONF" 2>/dev/null || true
fi

ENABLED=$(read_json_bool enabled "$CONF")
[ -z "$ENABLED" ] && ENABLED=false
ENGINE=$(read_json_string engine_path "$CONF")
[ -z "$ENGINE" ] && ENGINE="$HNC_DIR/bin/ndpiReader"
IFACE=$(read_json_string iface "$CONF")
[ -z "$IFACE" ] && IFACE=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=wlan2

# Accept either official ndpiReader or future HNC-specific wrapper names.
FOUND=""
for c in "$ENGINE" "$HNC_DIR/bin/ndpiReader" "$HNC_DIR/bin/hnc_ndpi_probe" "$HNC_DIR/bin/hnc_dpid_ndpi"; do
  [ -n "$c" ] && [ -x "$c" ] && { FOUND="$c"; break; }
done

if [ -z "$FOUND" ]; then
  write_state "missing_engine" "nDPI engine not found; expected bundled hnc_ndpi_probe or external ndpiReader under /data/local/hnc/bin" "" "" "$IFACE" "$ENABLED"
  echo "missing_engine: ndpiReader/hnc_ndpi_probe not found" >> "$LOG"
  exit 0
fi

# Version probe only. Avoid running capture by default because nDPI CLI flags vary by build.
VER=$($FOUND --version 2>&1 | head -1)
[ -z "$VER" ] && VER=$($FOUND -h 2>&1 | head -1)
write_state "available" "nDPI engine detected; sample capture is available via ndpi_lab_sample.sh" "$FOUND" "$VER" "$IFACE" "$ENABLED"
echo "available engine=$FOUND iface=$IFACE version=$VER" >> "$LOG"
exit 0
