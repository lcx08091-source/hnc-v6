#!/system/bin/sh
# hnc_dpid_guard.sh — HNC v5.3.0-rc17
# Purpose:
#   Keep passive DPI capture responsive when Android recreates or briefly downs
#   the hotspot interface.  The hnc_dpid binary is intentionally side-effect
#   free; this guard only controls its lifecycle and writes a waiting state.
#
# Strategy:
#   1. Treat Android AP interfaces as ready when they are clearly usable, not
#      only when operstate=up.  Some ROMs keep wlan2 in UNKNOWN/DORMANT while
#      tethering and AF_PACKET capture already work.
#   2. Use a fast startup retry window: 0 / 100 / 200 / 500 ms / 1 s / 1.5 s / 2 s.
#   3. Use ip monitor link/address when available to kill/rebind immediately on
#      interface changes; fall back to a low-frequency 3 s check.
#   4. If dpid reports "network is down", restart it after a short backoff; do
#      not get stuck forever waiting for a perfect operstate.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH='/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin'

# rc29.4: PATH self-heal.
#
# Real-device crash observed in rc29.3 dpid_guard.log: after ~100 seconds of
# normal operation, /system/bin/head, /system/bin/sleep, /system/bin/printf
# all started returning ENOENT, locking the guard into a busy loop for
# 3+ minutes (sleep failing means no actual backoff, so it spammed errors).
# Hypothesis: KSU/SukiSU occasionally re-mounts /system or otherwise scrubs
# environment of long-running shell processes; mksh on Android is also known
# to occasionally lose env on subshell forks.
#
# Defense in depth:
#   1. Hard-set PATH at top, including /data/local/hnc/bin fallback copies.
#   2. ensure_path_or_die: bare commands fall through to /data when /system/bin
#      is unmounted; only exit (code 99, watchdog respawns) if even the /data
#      fallback is gone. rc16: was "die on any /system/bin loss" before the
#      /data fallback (rc13 provision_fallback_tools) existed.
#   3. sleep_s uses bare sleep (PATH fallthrough) and propagates failure.
ensure_path_or_die() {
    # rc16: 改用裸命令 — PATH 含 /data/local/hnc/bin 兜底副本(service.sh 开机预置,
    # /data 永不被卸)。SukiSU 运行期卸掉 /system/bin 时,sleep 自动 fallthrough 到
    # /data 副本,守护不再 die、能继续监管 dpid(这正是"必须重新绑定"的根因之一)。
    if sleep 0 2>/dev/null; then
        return 0
    fi
    export PATH='/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin'
    if sleep 0 2>/dev/null; then
        return 0
    fi
    # 连 /data 兜底都没有(真·坏)才退出, 让 watchdog 重开一个干净环境的 guard。
    echo "[$(date +%H:%M:%S 2>/dev/null)] [DPID-GUARD] [FATAL] sleep unavailable even via /data fallback, exiting for clean restart" >> "$LOG" 2>/dev/null
    exit 99
}

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LOG_DIR="$HNC_DIR/logs"
LOG="$LOG_DIR/dpid_guard.log"
REAL_BIN="$HNC_DIR/bin/hnc_dpid"
CONFIG="$HNC_DIR/etc/dpi_config.json"
PID_FILE="$RUN/dpid.pid"
GUARD_PID_FILE="$RUN/dpid_guard.pid"
# rc29.4: heartbeat. Main loop writes current epoch to this file every iteration.
# Lock-takeover code uses staleness of this file to detect a wedged guard whose
# PID is still "alive" (e.g. stuck in a busy loop because env got poisoned)
# but isn't doing useful work anymore.
HEARTBEAT_FILE="$RUN/dpid_guard.heartbeat"
CHILD_PID_FILE="$RUN/dpid.child.pid"
MON_PID_FILE="$RUN/dpid.monitor.pid"
EVENT_FILE="$RUN/dpid.netlink.event"
LOCKDIR="$RUN/dpid_guard.lock"
START_TS=$(date +%s 2>/dev/null || echo 0)
OWNS_LOCK=0

mkdir -p "$RUN" "$LOG_DIR" 2>/dev/null || true

# rc29.5: post-fs-data namespace defense.
#
# Root cause analysis (rc29.4 real-device evidence):
#   - service.sh runs in KSU/SukiSU post-fs-data hook, where Android init is
#     still mounting /data and KSU is bind-mounting module overlays to /system.
#   - service.sh forks the guard with `nohup ... &`, so the guard inherits
#     the in-flux mount namespace from that early-boot moment.
#   - That namespace may not yet have a usable /system/bin (the bind-mount
#     happens after our fork), so /system/bin/sleep, /system/bin/head, etc.
#     all return ENOENT when the guard tries to use them.
#   - With sleep returning ENOENT, the guard's normal backoff loops execute
#     instantaneously, producing a 100%-CPU busy-loop that writes 50+ error
#     lines per second and never recovers.
#   - The user has to manually click "重新绑定 DPI" — this triggers a fresh
#     fork via hnc_httpd → su → sh, which inherits the post-boot clean
#     namespace and therefore works.
#
# Mitigation: before entering the main loop, sit in a low-cost wait that
# does NOT depend on /system/bin tools. Use mksh built-ins only. Don't
# leave the wait until /system/bin/sleep and /system/bin/date both work,
# which means the bind-mount has settled and we're in a sane env.
#
# Implementation uses `read -t 1 ... </dev/null` as the sleep primitive
# (POSIX shell built-in, doesn't need any binary). Falls back to a
# $SECONDS-based busy-loop if `read -t` isn't honored.
wait_for_clean_env() {
    tries=0
    max_tries=300  # ~5 min total ceiling; should normally heal in <30s
    while [ "$tries" -lt "$max_tries" ]; do
        # Check both: sleep works AND date works. Both must function for
        # the guard's main loop to be useful.
        if sleep 0 2>/dev/null && date +%s >/dev/null 2>&1; then
            if [ "$tries" -gt 0 ]; then
                echo "[$(date '+%H:%M:%S' 2>/dev/null)] [DPID-GUARD] env healed after ${tries}s wait" >> "$LOG" 2>/dev/null
            fi
            return 0
        fi
        tries=$((tries + 1))
        # ~1s wait without depending on /system/bin/*.
        # mksh's read is a built-in; -t timeout works without external sleep.
        IFS= read -t 1 _trash </dev/null 2>/dev/null
        rd_rc=$?
        if [ "$rd_rc" -ne 0 ] && [ "$rd_rc" -ne 142 ]; then
            # read -t not honored on this mksh. Last-resort fallback: SECONDS
            # is a mksh built-in that auto-increments every wall-clock second.
            # Burn one second worth of CPU as a sleep substitute. Ugly but
            # zero-dependency.
            start_sec=$SECONDS
            while [ "$SECONDS" -eq "$start_sec" ]; do : ; done
        fi
    done
    # 5 min ceiling — env really broken. Abort and let watchdog respawn.
    echo "[DPID-GUARD] [FATAL] env not usable after 5min, exiting for watchdog respawn" >> "$LOG" 2>/dev/null
    exit 99
}

# Guard against entering the main loop with /system/bin tools missing.
wait_for_clean_env

log() {
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S' 2>/dev/null)] [DPID-GUARD] $*" >> "$LOG" 2>/dev/null || true
}

sleep_s() {
    # rc29.4: absolute path. If both fail, /system might be transiently
    # unmounted or env is poisoned — die so watchdog respawns us with
    # a clean environment rather than burning CPU in a sleep-less loop.
    sleep "$1" 2>/dev/null && return 0
    sleep 1 2>/dev/null && return 0
    ensure_path_or_die  # this exits if truly broken
    return 0
}

json_escape() {
    # Small shell-safe JSON string escape for status messages.
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'
}

write_waiting_state() {
    # rc29.1: hand off blind-state writing to dpid itself so the JSON matches
    # whatever schema the running dpid build expects. Previously this function
    # wrote a hand-rolled schema_version=1 template, which became visibly
    # malformed once dpid moved to schema 2.0 (rc28.1.x / rc29) — the WebUI
    # would render the page in a half-broken state until the user clicked
    # "重新绑定 DPI" (which restarted dpid and produced a proper schema 2.0
    # file).
    #
    # The dpid binary supports `-write-blind-state <reason>` since rc29.1
    # which writes one full dpi_state.json snapshot and exits. If for some
    # reason the binary doesn't support that flag (e.g. someone hand-installs
    # an older dpid), we fall back to leaving any existing dpi_state.json
    # alone — better stale data than wrong-schema data.
    local iface="$1"
    local reason="$2"

    if [ ! -x "$REAL_BIN" ]; then
        return 0
    fi

    "$REAL_BIN" \
        -config "$CONFIG" \
        -write-blind-state "$reason" \
        -blind-iface "$iface" \
        >> "$LOG" 2>&1 \
        || log "WARN: write-blind-state via dpid failed (binary too old?); leaving dpi_state.json untouched"
}

read_json_string_key() {
    local key="$1" file="$2"
    [ -f "$file" ] || return 1
    # Good enough for dpi_config.json's flat string keys.
    sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -1
}

read_json_bool_key() {
    local key="$1" file="$2"
    [ -f "$file" ] || return 1
    sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$file" | head -1
}

get_iface() {
    local cfg_iface hint detected
    cfg_iface=$(read_json_string_key iface "$CONFIG" 2>/dev/null)
    if [ -n "$cfg_iface" ]; then
        printf '%s\n' "$cfg_iface"
        return 0
    fi
    hint=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
    if [ -n "$hint" ]; then
        printf '%s\n' "$hint"
        return 0
    fi
    if [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
        detected=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | head -1)
        if [ -n "$detected" ]; then
            printf '%s\n' "$detected"
            return 0
        fi
    fi
    printf '%s\n' wlan2
}

iface_exists() {
    [ -n "$1" ] && [ -e "/sys/class/net/$1" ]
}

iface_up() {
    local iface="$1" line op
    [ -n "$iface" ] || return 1
    [ -e "/sys/class/net/$iface" ] || return 1
    line=$(ip -o link show "$iface" 2>/dev/null | head -1)
    echo "$line" | grep -q '<[^>]*UP[^>]*>' && return 0
    # Some Android Wi-Fi/AP interfaces report operstate=unknown while IFF_UP is
    # true.  Accept unknown only when the link exists and ip(8) did not say DOWN.
    op=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
    [ "$op" = "up" ] && return 0
    echo "$line" | grep -q 'state UNKNOWN' && ! echo "$line" | grep -q 'state DOWN' && return 0
    return 1
}

iface_has_ipv4() {
    local iface="$1"
    [ -n "$iface" ] || return 1
    ip -4 addr show "$iface" 2>/dev/null | grep -q 'inet ' && return 0
    return 1
}

iface_has_arp_clients() {
    local iface="$1"
    [ -n "$iface" ] || return 1
    awk -v ifc="$iface" 'NR>1 && $6==ifc && $4!="00:00:00:00:00:00" {found=1} END{exit found?0:1}' /proc/net/arp 2>/dev/null
}

hotspot_hint_matches_iface() {
    local iface="$1" hint
    [ -n "$iface" ] || return 1
    hint=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
    [ -n "$hint" ] && [ "$hint" = "$iface" ] && return 0
    return 1
}

iface_ready() {
    # rc16: Android AP interfaces may report operstate=unknown/dormant even
    # when tethering works.  Starting hnc_dpid is cheap and side-effect free, so
    # prefer trying capture over staying in blind/waiting forever.
    local iface="$1"
    iface_exists "$iface" || return 1
    iface_up "$iface" && return 0
    iface_has_ipv4 "$iface" && return 0
    iface_has_arp_clients "$iface" && return 0
    hotspot_hint_matches_iface "$iface" && return 0
    return 1
}

iface_ready_reason() {
    local iface="$1" op carrier ip4 arp hint line
    op=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
    carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null)
    ip4="no"; iface_has_ipv4 "$iface" && ip4="yes"
    arp="no"; iface_has_arp_clients "$iface" && arp="yes"
    hint=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
    line=$(ip -o link show "$iface" 2>/dev/null | head -1)
    printf 'operstate=%s carrier=%s ipv4=%s arp_clients=%s hint=%s link=%s' "${op:-unknown}" "${carrier:-unknown}" "$ip4" "$arp" "${hint:-none}" "$line"
}

kill_child() {
    local child
    child=$(cat "$CHILD_PID_FILE" 2>/dev/null)
    if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
        kill "$child" 2>/dev/null || true
        # rc40 (P2-18): give dpid up to ~2s to flush state + tear down BPF/ringbuf
        # cleanly before SIGKILL (old 0.2s was too short → pinned BPF resources
        # could leak). Poll so we still return promptly when it exits early.
        _i=0
        while [ "$_i" -lt 10 ] && kill -0 "$child" 2>/dev/null; do
            sleep_s 0.2
            _i=$((_i + 1))
        done
        kill -0 "$child" 2>/dev/null && kill -9 "$child" 2>/dev/null || true
    fi
    rm -f "$CHILD_PID_FILE" 2>/dev/null || true
}

cleanup_guard() {
    [ "${OWNS_LOCK:-0}" = "1" ] || exit 0
    local mon
    kill_child
    mon=$(cat "$MON_PID_FILE" 2>/dev/null)
    [ -n "$mon" ] && kill "$mon" 2>/dev/null || true
    rm -f "$MON_PID_FILE" "$GUARD_PID_FILE" "$CHILD_PID_FILE" 2>/dev/null || true
    # 兼容旧版：只在 dpid.pid 指向本 guard 时才删除，避免误删真实 child pid。
    old_main=$(cat "$PID_FILE" 2>/dev/null)
    [ "$old_main" = "$$" ] && rm -f "$PID_FILE" 2>/dev/null || true
    rm -rf "$LOCKDIR" 2>/dev/null || true
}
trap cleanup_guard EXIT INT TERM

# rc14: dpid guard must be single-instance.  Do not share dpid.pid with
# the real capture child; use dpid_guard.pid for the supervisor and keep
# dpid.child.pid for the hnc_dpid child.
if ! mkdir "$LOCKDIR" 2>/dev/null; then
    old=$(cat "$GUARD_PID_FILE" 2>/dev/null)
    if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
        # rc29.4: PID 活着, 但 heartbeat 是不是 fresh? 如果 60+ 秒没更新,
        # 那个老 guard 就是死锁状态 (busy loop / 卡住), 强制接管.
        hb=$(cat "$HEARTBEAT_FILE" 2>/dev/null)
        now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$hb" ] && [ "$now" -gt 0 ] && [ $((now - hb)) -lt 60 ]; then
            log "another guard already running pid=$old (heartbeat fresh)"
            exit 0
        fi
        log "guard pid=$old alive but heartbeat stale ($((now - hb))s); taking over"
        kill -9 "$old" 2>/dev/null || true
        sleep 0.3 2>/dev/null
    else
        # If a previous rc16 child shell left a stale lock behind, release it.
        log "stale guard lock without live guard pid; releasing"
    fi
    rm -rf "$LOCKDIR" 2>/dev/null || true
    mkdir "$LOCKDIR" 2>/dev/null || exit 0
fi
OWNS_LOCK=1
echo $$ > "$GUARD_PID_FILE"
# Best-effort compatibility: expose the guard pid to old watchdog only when no
# dpid.pid exists.  New rc14 watchdog reads dpid_guard.pid.
[ ! -s "$PID_FILE" ] && echo $$ > "$PID_FILE" 2>/dev/null || true

if [ ! -x "$REAL_BIN" ]; then
    write_waiting_state "" "hnc_dpid binary missing; DPI disabled"
    log "missing binary: $REAL_BIN"
    exit 0
fi

start_monitor() {
    command -v ip >/dev/null 2>&1 || return 0
    ( ip monitor link address 2>/dev/null | while IFS= read -r line; do
          iface=$(get_iface)
          # rc29.3: 只对 hotspot iface 自己的事件反应. 之前 *wlan*|*ap*|*swlan*|*rndis*|*usb*
          # 这种宽匹配的副作用是: wlan0 (主 Wi-Fi 5G) DOWN/UP, ap0 (有些机器的 AP 控制接口),
          # rndis0 (USB tethering) 这些跟 wlan2 上的 dpid 完全无关的接口抖动也会触发 rebind.
          # 用户最后看到的就是"每隔几分钟必须手动点重新绑定 DPI".
          #
          # 现在只匹配两类:
          #   1. 当前 hotspot iface 自己 ($iface, 一般是 wlan2)
          #   2. iface 还没确定时 (iface 为空), 任何 ap*/swlan* 候选都接受 (启动期发现用)
          #
          # 跨接口副作用主接口 (wlan0/eth0/rmnet0) 一律忽略.
          matched=""
          if [ -n "$iface" ]; then
              case "$line" in
                  *" $iface:"*|*" $iface@"*|*"$iface "*) matched=1 ;;
              esac
          else
              case "$line" in
                  *" ap0:"*|*" ap1:"*|*" swlan0:"*|*" wlan1:"*|*" wlan2:"*|*" rndis0:"*) matched=1 ;;
              esac
          fi
          if [ -n "$matched" ]; then
              date +%s > "$EVENT_FILE" 2>/dev/null || true
              child=$(cat "$CHILD_PID_FILE" 2>/dev/null)
              if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
                  log "netlink event for iface=$iface, request immediate rebind: $line"
                  kill "$child" 2>/dev/null || true
              fi
          fi
      done ) &
    echo $! > "$MON_PID_FILE"
    log "netlink monitor started pid=$(cat "$MON_PID_FILE" 2>/dev/null)"
}

start_monitor

# Fast retry offsets after startup or after an interface-loss event.
FAST_DELAYS="0 0.1 0.2 0.5 1 1.5 2"
fast_index=1
last_iface=""
last_event_seen=""

while true; do
    # rc29.4: every iteration — verify env is still usable, refresh heartbeat.
    ensure_path_or_die
    date +%s > "$HEARTBEAT_FILE" 2>/dev/null

    disabled=$(read_json_bool_key disable_capture "$CONFIG" 2>/dev/null)
    iface=$(get_iface)

    # v5.7.0-rc7: always launch the real dpid daemon, even when the hotspot
    # iface isn't ready. dpid self-selects blind mode for AP capture but keeps
    # running self-capture (/proc/net + self-iface SNI) + the auto-id flywheel,
    # which use the phone's OWN interfaces, not the AP. We rebind to full capture
    # once the iface becomes ready (netlink event or the periodic check in the
    # monitor loop below). Previously the not-ready branches wrote a one-shot
    # blind state and 'continue'd WITHOUT launching dpid, so self-capture and the
    # flywheel were dead whenever the hotspot was off.
    launch_blind=0
    if [ "$disabled" = "true" ]; then
        log "disable_capture=true; launching real dpid (it writes the disabled state)"
    elif ! iface_exists "$iface" || ! iface_ready "$iface"; then
        launch_blind=1
        log "hotspot iface $iface not ready; launching dpid BLIND (self-capture still runs): $(iface_ready_reason "$iface" 2>/dev/null)"
    fi

    if [ "$iface" != "$last_iface" ]; then
        log "target iface changed: $last_iface -> $iface"
        last_iface="$iface"
    fi
    fast_index=1

    log "launching hnc_dpid on iface=$iface (blind=$launch_blind)"
    "$REAL_BIN" -config "$CONFIG" >> "$LOG_DIR/dpid.log" 2>&1 &
    child=$!
    echo "$child" > "$CHILD_PID_FILE"

    # rc29.2: startup grace + debounce
    #
    # rc29.0/rc29.1 problem: every netlink link/address event in the first few
    # seconds caused an immediate kill+rebind. ColorOS 16's tethering stack
    # emits ~6-8 events in the first 200 ms of hotspot up (IPv4 assign,
    # IPv6 SLAAC, IPv6 RA, accept_ra writes, ...). That made dpid restart
    # 8 times back-to-back, blowing the crash_loop counter and forcing the
    # user to manually click "重新绑定 DPI" to recover.
    #
    # Two mitigations:
    #   GRACE_S       - the first N seconds after spawning child, ignore any
    #                   netlink event (assume settling).
    #   DEBOUNCE_S    - after the grace period, two rebinds must be at least
    #                   N seconds apart. Coalesces bursts of late events.
    GRACE_S=5
    DEBOUNCE_S=4
    last_rebind_ts=0

    # Monitor child.  During the first 5 s use a 200 ms cadence to catch the
    # exact wlan up/race window; after that use 3 s to save power.
    child_start=$(date +%s 2>/dev/null || echo 0)
    while kill -0 "$child" 2>/dev/null; do
        now=$(date +%s 2>/dev/null || echo 0)
        age=$((now - child_start))
        cur_iface=$(get_iface)
        ev=$(cat "$EVENT_FILE" 2>/dev/null)
        if [ -n "$ev" ] && [ "$ev" != "$last_event_seen" ]; then
            # rc29.2 grace: ignore link/addr events in first GRACE_S seconds.
            if [ "$age" -lt "$GRACE_S" ]; then
                last_event_seen="$ev"
                log "ignore netlink event in startup grace (age=${age}s < ${GRACE_S}s)"
                sleep_s 0.2
                continue
            fi
            # rc29.2 debounce: coalesce bursts.
            since_last=$((now - last_rebind_ts))
            if [ "$last_rebind_ts" -gt 0 ] && [ "$since_last" -lt "$DEBOUNCE_S" ]; then
                last_event_seen="$ev"
                log "debounce netlink event (last rebind ${since_last}s ago < ${DEBOUNCE_S}s)"
                sleep_s 0.2
                continue
            fi
            last_event_seen="$ev"
            last_rebind_ts="$now"
            log "event file changed; rechecking capture binding"
            kill "$child" 2>/dev/null || true
            break
        fi
        # rc11: only rebind on a REAL iface change. When /system/bin tools
        # (head/cat) transiently vanish from our mount namespace (SukiSU/ColorOS),
        # get_iface returns EMPTY — that must NOT be read as "iface changed to
        # nothing" (which caused spurious kill+rebind churn). Empty = unknown,
        # keep the current binding.
        if [ -n "$cur_iface" ] && [ "$cur_iface" != "$iface" ]; then
            log "iface changed while running: $iface -> $cur_iface; rebind"
            kill "$child" 2>/dev/null || true
            break
        fi
        if [ "$disabled" != "true" ]; then
            if [ "$launch_blind" = "1" ]; then
                # v5.7.0-rc7: launched blind (no usable hotspot) — dpid is running
                # self-capture meanwhile. Upgrade to full AP capture as soon as the
                # iface becomes usable. Don't treat "not ready" as a fault here.
                if iface_ready "$iface"; then
                    log "hotspot iface $iface became ready; rebind to full capture"
                    kill "$child" 2>/dev/null || true
                    break
                fi
            else
                if ! iface_ready "$iface"; then
                    # rc29.2: grace for transient DORMANT→UP transitions in first GRACE_S.
                    if [ "$age" -lt "$GRACE_S" ]; then
                        log "iface $iface not ready (age=${age}s < ${GRACE_S}s, grace period); leaving dpid alone"
                        sleep_s 0.2
                        continue
                    fi
                    write_waiting_state "$iface" "hotspot interface $iface is not currently usable; rc17 guard is rebinding; $(iface_ready_reason "$iface")"
                    log "iface $iface not ready while running; rebind when usable: $(iface_ready_reason "$iface")"
                    kill "$child" 2>/dev/null || true
                    break
                fi
                if grep -qi 'network is down' "$RUN/dpi_state.json" 2>/dev/null; then
                    # rc12 failure: dpid started during the AP iface down/up window
                    # and stayed blind. Kill so next iteration binds after IFF_UP.
                    log "dpi_state reports network is down; restart capture immediately"
                    kill "$child" 2>/dev/null || true
                    break
                fi
            fi
        fi
        if [ "$age" -lt 5 ]; then sleep_s 0.2; else sleep_s 3; fi
    done
    wait "$child" 2>/dev/null || true
    rm -f "$CHILD_PID_FILE" 2>/dev/null || true

    # Small damping: event-driven kills restart immediately after this; genuine
    # repeated failure gets the short backoff first and then the 3 s fallback.
    sleep_s 0.2
    fast_index=1
done
