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
LAUNCHER_C="$HNC_DIR/bin/hnc_launcher"
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

# rc11: the authoritative launcher is the C launcher (hnc_launcher), kept alive
# by hnc_watchdog. The OLD rebind killed it (via dpid_guard.pid) and started a
# COMPETING shell guard → two managers fighting over dpid (one SIGTERMs it, the
# other treats rc=0 as "stop" and gives up) → dpid dies → user must rebind
# again, forever. New behaviour: clear crash flags, kill any STALE shell guard /
# Go supervisor (NOT the C launcher), restart only the dpid CHILD so the C
# launcher respawns it with the refreshed iface config.

# Clear crash flags so the launcher/dpid actually (re)start. The C launcher
# enters "observe mode" (no restart) while dpid_crashflag exists; dpid has its
# own dpid.crashflag.
rm -f "$RUN/dpid_crashflag" "$RUN/dpid.crashflag" 2>/dev/null || true

# Kill stale shell guard / Go supervisor only — leave the C launcher alone.
for p in $(ps -ef 2>/dev/null | grep -E '[h]nc_dpid_guard\.sh|[h]nc_dpid_supervisor' | awk '{print $2}'); do
    [ -n "$p" ] && { log "KILL stale launcher pid=$p"; kill -9 "$p" 2>/dev/null || true; }
done
rm -rf "$RUN/dpid_guard.lock" 2>/dev/null || true

# Restart only the dpid child; the launcher respawns it with the new config.
kill_pidfile "$RUN/dpid.child.pid"
kill_pidfile "$RUN/dpid.pid"
if command -v pidof >/dev/null 2>&1; then
    for p in $(pidof hnc_dpid 2>/dev/null); do
        [ -n "$p" ] && { log "KILL hnc_dpid pid=$p"; kill -9 "$p" 2>/dev/null || true; }
    done
fi
sleep 1

# Ensure a launcher is alive. Prefer the C launcher (robust, no /system/bin
# dependency; hnc_watchdog normally keeps it up). Only fall back to the shell
# guard if the C launcher binary is missing.
if ps -ef 2>/dev/null | grep -q '[h]nc_launcher'; then
    log "C launcher alive; dpid will respawn on iface=$IFACE"
    echo "ok: rebound iface=$IFACE (C launcher respawns dpid within ~2s)"
elif [ -x "$LAUNCHER_C" ]; then
    log "starting C launcher $LAUNCHER_C"
    nohup "$LAUNCHER_C" >> "$LOG_DIR/dpid_guard.log" 2>&1 &
    echo $! > "$RUN/dpid_guard.pid"
    echo "ok: C launcher started pid=$(cat "$RUN/dpid_guard.pid" 2>/dev/null) iface=$IFACE"
elif [ -x "$GUARD" ]; then
    log "C launcher missing; fallback to shell guard"
    nohup sh "$GUARD" >> "$LOG_DIR/dpid_guard.log" 2>&1 &
    echo $! > "$RUN/dpid_guard.pid"
    echo "ok: guard restarted pid=$(cat "$RUN/dpid_guard.pid" 2>/dev/null) iface=$IFACE"
elif [ -x "$DPID" ]; then
    log "no launcher; starting dpid directly"
    nohup "$DPID" -config "$CONFIG" >> "$LOG_DIR/dpid.log" 2>&1 &
    echo $! > "$RUN/dpid.pid"
    echo "ok: dpid restarted pid=$(cat "$RUN/dpid.pid" 2>/dev/null) iface=$IFACE"
else
    log "failed: hnc_dpid missing"
    echo "failed: hnc_dpid missing" >&2
    exit 1
fi
exit 0
