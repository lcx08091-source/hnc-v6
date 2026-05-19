#!/system/bin/sh
# apply_app_limits.sh — HNC v5.3.0-rc30.6
#
# Per-(client_mac, app_id) downlink rate limiter.
#
# Reads:
#   $HNC_DIR/data/app_limits.flat       — user config (one entry per line)
#                                          <mac> <app_id> <down_mbps>
#   $HNC_DIR/run/ip_app_map.flat        — dpid's observation (every 30s)
#                                          <ip> <app_id>
#   $HNC_DIR/data/devices.json          — hotspotd's active client table
#                                          (used to resolve mac → client_ip)
#   $HNC_DIR/run/active_iface           — current hotspot iface (e.g. wlan2)
#
# Writes:
#   iptables -t mangle -A HNC_APP_LIMIT  — MARK rules per (client_ip → app_ip)
#   tc class add  parent 1:1 classid 1:<id> htb rate <limit>mbit
#   tc filter add parent 1: prio 200 handle <mark> fw flowid 1:<id>
#
# Mark range: APP_MARK_BASE = 0x900000, avoids the 0x800000 range used by
# per-device limits in iptables_manager.sh / tc_manager.sh.
#
# Class id range: 0x9000-0xffff (36864-65535). Stays away from per-device
# classes which live in 1:100-1:9999.
#
# Idempotent: full rebuild each call. No state is kept between invocations.
# Costs ~50ms per call on Pixel-class hw for a handful of limits.
#
# Invocation: hnc_watchdog calls every 30s, OR immediately when
# /run/app_limit.dirty marker is present (set by hnc_httpd after a
# successful POST /api/action app_limit_set/clear).

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
LIMITS_FLAT="$HNC_DIR/data/app_limits.flat"
IP_APP_FLAT="$HNC_DIR/run/ip_app_map.flat"
DEVICES="$HNC_DIR/data/devices.json"
DIRTY="$HNC_DIR/run/app_limit.dirty"
LOG="$HNC_DIR/logs/app_limits.log"

APP_MARK_BASE_DEC=9437184   # 0x900000 — fwmark 高位避开 0x800000 device mark
APP_CLASS_MINOR_BASE=36864  # 0x9000 — tc classid minor in [0x9000, 0xffff]
CHAIN=HNC_APP_LIMIT
FILTER_PRIO=200

mkdir -p "$HNC_DIR/logs" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

# rotate log if >256 KB
if [ -f "$LOG" ]; then
    sz=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 262144 ] && mv "$LOG" "${LOG}.1" 2>/dev/null
fi

# Always clear dirty marker at start — even if we early-exit below.
rm -f "$DIRTY" 2>/dev/null

# Locate current iface. Multiple fallbacks because watchdog may not have
# written run/active_iface yet on a cold boot.
IFACE=""
[ -f "$HNC_DIR/run/active_iface" ] && IFACE=$(cat "$HNC_DIR/run/active_iface" 2>/dev/null | head -1 | tr -d '\r\n ')
if [ -z "$IFACE" ] && [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
    IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')
fi
[ -z "$IFACE" ] && { log "no iface, exit"; exit 0; }

# ─── Step 1: clean up old rules ───────────────────────────────────────
# Both iptables HNC_APP_LIMIT chain and tc app classes / filters.

ensure_chain() {
    iptables -t mangle -N $CHAIN 2>/dev/null
    # Append (not insert) so HNC_APP_LIMIT runs AFTER HNC_MARK in the
    # FORWARD chain. iptables MARK overwrites the previous mark by default,
    # so app-level rules win over device-level rules — which matches user
    # mental model: "I specifically configured 抖音 to 1 Mbps, that should
    # apply even if the device has its own overall limit".
    if ! iptables -t mangle -C FORWARD -j $CHAIN 2>/dev/null; then
        iptables -t mangle -A FORWARD -j $CHAIN 2>/dev/null
    fi
}

ensure_chain
iptables -t mangle -F $CHAIN 2>/dev/null

# Remove app-range tc classes (0x9000-0xfff0 — our reserved minor range).
tc class show dev "$IFACE" 2>/dev/null | \
    awk '$1=="class" && $2=="htb" {print $3}' | \
    while IFS= read -r cid; do
        # cid like "1:9001" with hex minor — convert to decimal for range check.
        minor_hex=$(echo "$cid" | awk -F: '{print $2}')
        # printf to dec; tolerant of leading 0x or bare hex
        minor_dec=$(printf '%d' "0x$minor_hex" 2>/dev/null)
        [ -z "$minor_dec" ] && continue
        if [ "$minor_dec" -ge 36864 ] && [ "$minor_dec" -le 65520 ]; then
            tc class del dev "$IFACE" classid "$cid" 2>/dev/null
        fi
    done

# Remove app-range filters (prio 200).
tc filter del dev "$IFACE" parent 1: prio $FILTER_PRIO 2>/dev/null

# ─── Step 2: read configs ─────────────────────────────────────────────

if [ ! -s "$LIMITS_FLAT" ]; then
    # No active limits — clean exit, chain stays empty.
    log "no app_limits configured (cleaned old rules)"
    exit 0
fi

# Bail if dpid hasn't produced an ip→app map yet (e.g. just rebooted).
if [ ! -s "$IP_APP_FLAT" ]; then
    log "ip_app_map.flat empty, no rules to apply (dpid still warming up?)"
    exit 0
fi

# ─── Step 3: resolve mac → client_ip from devices.json ────────────────
#
# devices.json is JSON; we don't have jq. We extract per-MAC IPs with a
# tolerant grep+sed — same shape as elsewhere in HNC.
#
# Expected key per device:
#   "aa:bb:cc:dd:ee:01": {"ip":"192.168.43.50", ...}
#
# Limitation: we only capture the FIRST ip-field-of-each-mac-record. Good
# enough — hotspotd stores one IPv4 per MAC.

resolve_mac_ip() {
    local mac=$1
    [ -f "$DEVICES" ] || return 1
    # devices.json shape: { "mac1": { "ip":"...", ... }, "mac2": {...} }
    # The file is usually one long line (no pretty-print). We scan
    # left-to-right for the target mac's entry, then capture the FIRST
    # "ip":"..." occurring AFTER that key.
    #
    # Note: a naive awk-per-line search is fragile on a single-line file
    # because all fields collapse onto one record. Switch to sed-driven
    # extraction which handles both pretty-printed and minified shapes:
    #
    #   1) Find the substring starting at "<mac>":{
    #   2) Within that, capture the first "ip":"<v4>"
    sed -n 's/.*"'"$mac"'":{[^}]*"ip":"\([0-9.]*\)".*/\1/p' "$DEVICES" | head -1
}

# ─── Step 4: build mark-id table (stable order from app_limits.flat) ──
#
# We index limits by line number to get a stable, unique mark per (mac,app).
# That gives us a small mark range (max ~100 entries) and matching tc class
# minors.

mark_for_index() {
    # 32-bit fwmark, no upper-bound issue. index 0-based.
    echo "0x$(printf '%x' $((APP_MARK_BASE_DEC + 1 + $1)))"
}

classid_for_index() {
    # tc classid minor MUST fit in 16 bits (max 0xffff = 65535). We use the
    # 0x9000-0xfff0 range; up to ~4000 distinct (mac, app) limits.
    # 1:9001, 1:9002, ..., 1:fff0
    local minor=$((APP_CLASS_MINOR_BASE + 1 + $1))
    if [ "$minor" -gt 65520 ]; then
        # Past the safe window. Drop. apply log will note skipped entries.
        echo ""
        return
    fi
    echo "1:$(printf '%x' $minor)"
}

# ─── Step 5: walk limits, build rules ─────────────────────────────────

i=0
applied=0
skipped=0
while IFS=' ' read -r MAC APP RATE; do
    [ -z "$MAC" ] && continue
    case "$MAC" in '#'*) continue ;; esac

    CLIENT_IP=$(resolve_mac_ip "$MAC")
    if [ -z "$CLIENT_IP" ]; then
        log "skip $MAC/$APP: client not online"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    # Pull all IPs currently mapped to this app from ip_app_map.flat.
    APP_IPS=$(awk -v want="$APP" '$2 == want {print $1}' "$IP_APP_FLAT" | sort -u)
    if [ -z "$APP_IPS" ]; then
        log "skip $MAC/$APP: no IPs observed for app yet"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    MARK=$(mark_for_index $i)
    CID=$(classid_for_index $i)
    if [ -z "$CID" ]; then
        log "skip $MAC/$APP: classid space exhausted (>4000 entries)"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi
    RATE_MBIT=$(printf '%.2f' "$RATE")

    # Create a tc class for this (mac, app) under root.
    # Parent is 1:1 to inherit overall root rate; rate=ceil for hard cap.
    tc class add dev "$IFACE" parent 1:1 classid "$CID" htb \
        rate "${RATE_MBIT}mbit" ceil "${RATE_MBIT}mbit" \
        burst 32k cburst 32k 2>/dev/null

    # Filter: any packet bearing this mark goes to the class.
    tc filter add dev "$IFACE" protocol ip parent 1: prio $FILTER_PRIO \
        handle "$MARK" fw flowid "$CID" 2>/dev/null

    # iptables MARK: for every (CLIENT_IP, APP_IP) pair, both directions.
    # We only need downlink (server -> client) to enforce a download cap,
    # but writing both directions makes the same chain reusable for future
    # upload caps without rule churn.
    for IP in $APP_IPS; do
        iptables -t mangle -A $CHAIN -d "$CLIENT_IP" -s "$IP" \
            -j MARK --set-mark "$MARK" 2>/dev/null
        iptables -t mangle -A $CHAIN -s "$CLIENT_IP" -d "$IP" \
            -j MARK --set-mark "$MARK" 2>/dev/null
    done

    n_ips=$(echo "$APP_IPS" | wc -l)
    log "applied $MAC ($CLIENT_IP) / $APP / ${RATE_MBIT}mbit / $n_ips ip(s) / mark=$MARK class=$CID"
    applied=$((applied + 1))
    i=$((i + 1))
done < "$LIMITS_FLAT"

log "summary: applied=$applied skipped=$skipped"
