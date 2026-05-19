#!/system/bin/sh
# dpi_rebind.sh — HNC v5.3.0-rc17
# Manual DPI rebind helper.  Safe for WebUI button use: stop stale dpid/guard,
# refresh dpi_config.json with the current hotspot iface, then relaunch guard.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
LOG_DIR="$HNC_DIR/logs"
ETC="$HNC_DIR/etc"
LOG="$LOG_DIR/dpi_rebind.log"
CONFIG="$ETC/dpi_config.json"
GUARD="$HNC_DIR/bin/hnc_dpid_guard.sh"
DPID="$HNC_DIR/bin/hnc_dpid"

mkdir -p "$RUN" "$LOG_DIR" "$ETC" 2>/dev/null || true
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [DPI-REBIND] $*" >> "$LOG" 2>/dev/null || true; }
json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }

get_iface(){
    if [ -n "$1" ]; then echo "$1"; return 0; fi
    cfg=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" 2>/dev/null | head -1)
    [ -n "$cfg" ] && { echo "$cfg"; return 0; }
    hint=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
    [ -n "$hint" ] && { echo "$hint"; return 0; }
    if [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
        det=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | head -1)
        [ -n "$det" ] && { echo "$det"; return 0; }
    fi
    echo wlan2
}

write_state(){
    iface=$(json_escape "$1")
    reason=$(json_escape "$2")
    now=$(date +%s 2>/dev/null || echo 0)
    cat > "$RUN/dpi_state.json.tmp" <<EOF_STATE
{"schema_version":1,"timestamp":$now,"version":"0.1.0-rc1.2-fixed+rc17-manual","mode":"blind","interface":"$iface","uptime_s":0,"blind_reason":"$reason","stats":{"packets":0,"dns_events":0,"tls_events":0,"kernel_drops":0,"ignored_packets":0,"parse_errors":0}}
EOF_STATE
    mv -f "$RUN/dpi_state.json.tmp" "$RUN/dpi_state.json" 2>/dev/null || true
}

kill_pidfile(){
    f="$1"
    p=$(cat "$f" 2>/dev/null)
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
        log "TERM pidfile $f pid=$p"
        kill "$p" 2>/dev/null || true
    fi
    rm -f "$f" 2>/dev/null || true
}

IFACE=$(get_iface "$1")
log "manual rebind requested iface=$IFACE"
write_state "$IFACE" "manual DPI rebind requested; restarting guard/capture on $IFACE"

echo "$IFACE" > "$RUN/hotspot_iface" 2>/dev/null || true
printf '{"iface":"%s","log_level":"info"}\n' "$IFACE" > "$CONFIG" 2>/dev/null || true
chmod 644 "$CONFIG" 2>/dev/null || true

# Stop supervised and direct capture paths.  Do pid files first, then name-based
# cleanup for stale rc13/rc14 shells that may no longer have a valid pid file.
for f in "$RUN/dpid_guard.pid" "$RUN/dpid.monitor.pid" "$RUN/dpid.child.pid" "$RUN/dpid.pid"; do
    kill_pidfile "$f"
done

if command -v pidof >/dev/null 2>&1; then
    for n in hnc_dpid; do
        for p in $(pidof "$n" 2>/dev/null); do
            [ -n "$p" ] && { log "KILL $n pid=$p"; kill -9 "$p" 2>/dev/null || true; }
        done
    done
fi

for p in $(ps -ef 2>/dev/null | grep '[h]nc_dpid_guard.sh' | awk '{print $2}'); do
    [ -n "$p" ] && { log "KILL dpid_guard pid=$p"; kill -9 "$p" 2>/dev/null || true; }
done
rm -rf "$RUN/dpid_guard.lock" 2>/dev/null || true
sleep 1

if [ -x "$GUARD" ]; then
    log "starting guard $GUARD"
    nohup sh "$GUARD" >> "$LOG_DIR/dpid_guard.log" 2>&1 &
    echo $! > "$RUN/dpid_guard.pid"
    echo "ok: guard restarted pid=$(cat "$RUN/dpid_guard.pid" 2>/dev/null) iface=$IFACE"
elif [ -x "$DPID" ]; then
    log "guard missing; starting dpid directly"
    nohup "$DPID" -config "$CONFIG" >> "$LOG_DIR/dpid.log" 2>&1 &
    echo $! > "$RUN/dpid.pid"
    echo "ok: dpid restarted pid=$(cat "$RUN/dpid.pid" 2>/dev/null) iface=$IFACE"
else
    log "failed: hnc_dpid missing"
    echo "failed: hnc_dpid missing" >&2
    exit 1
fi
exit 0
