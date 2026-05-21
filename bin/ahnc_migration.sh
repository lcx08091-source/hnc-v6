#!/system/bin/sh
# bin/ahnc_migration.sh — one-shot migration from AHNC v0.x to HNC v5.5.0
#
# v5.5.0 absorbs the AHNC satellite module's functionality. This script
# handles the data side of the merge:
#
#   - Migrates /data/local/ahnc/self-conns.YYYYMMDD.jsonl → renamed to
#     /data/local/hnc/run/self_attrib.YYYYMMDD.jsonl (only the most recent
#     7 days). This preserves the per-uid history Ling already collected.
#
#   - Drops everything else from AHNC:
#     - hotspot pcap files (HNC's eBPF already parsed them in real-time)
#     - export zips (already shared with Claude or stale)
#     - foreground samples (HNC will sample on its own going forward)
#     - mirror tracking files (redundant since we're inside HNC now)
#
#   - Tells the user via marker file what was done; doesn't auto-delete
#     /data/local/ahnc until they confirm. Removes the AHNC KSU module
#     reference if present.
#
# Triggered by service.sh on every boot, but uses a marker file to ensure
# the actual migration runs exactly once.

. /data/adb/modules/hotspot_network_control/bin/hnc_common.sh 2>/dev/null || {
    # Standalone fallback — only used if hnc_common.sh is missing
    HNC_DIR=/data/local/hnc
    log() { echo "$(date +'%F %T') ahnc-migration: $*" >&2; }
}

AHNC_DIR=/data/local/ahnc
HNC_RUN=$HNC_DIR/run
MARKER=$HNC_RUN/.ahnc_migration_done
AHNC_KSU_MODULE=/data/adb/modules/ahnc-capture

# Already done?
if [ -f "$MARKER" ]; then
    exit 0
fi

# No AHNC data → nothing to do, just place marker
if [ ! -d "$AHNC_DIR" ]; then
    mkdir -p "$HNC_RUN"
    {
        echo "no_ahnc_data_found"
        echo "ts=$(date +%s)"
    } > "$MARKER"
    exit 0
fi

log "starting AHNC → HNC v5.5.0 migration"
mkdir -p "$HNC_RUN"

# ─── Migrate self-conns.YYYYMMDD.jsonl → self_attrib.YYYYMMDD.jsonl ───
#
# These are the only AHNC files that contain genuinely useful state HNC
# doesn't already have. Last 7 days only.
migrated_count=0
seven_days_ago_epoch=$(( $(date +%s) - 7*86400 ))
for f in "$AHNC_DIR"/self-conns.*.jsonl; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    # Extract YYYYMMDD
    day=$(echo "$base" | sed -n 's/^self-conns\.\([0-9]*\)\.jsonl$/\1/p')
    [ -n "$day" ] || continue
    # Convert YYYYMMDD to epoch (approximate via day comparison; busybox-friendly)
    if [ "$day" -lt "$(date -d "@$seven_days_ago_epoch" +%Y%m%d 2>/dev/null || \
                       date -r "$seven_days_ago_epoch" +%Y%m%d 2>/dev/null)" ]; then
        # Older than 7 days, skip
        continue
    fi
    target=$HNC_RUN/self_attrib.$day.jsonl
    if [ -f "$target" ]; then
        log "skip $base (target $target already exists)"
        continue
    fi
    cp "$f" "$target" && migrated_count=$((migrated_count + 1))
    log "migrated $base → self_attrib.$day.jsonl"
done

# ─── Write marker (idempotency lock) ────────────────────────────────
{
    echo "ahnc_dir=$AHNC_DIR"
    echo "files_migrated=$migrated_count"
    echo "ts=$(date +%s)"
    echo "hnc_version=v5.5.0"
    echo ""
    echo "# AHNC migration complete. Safe-to-remove items:"
    echo "#   - The AHNC KSU module: $AHNC_KSU_MODULE"
    echo "#   - The AHNC data dir:   $AHNC_DIR"
    echo "# To clean up:"
    echo "#   rm -rf $AHNC_DIR"
    echo "#   (and uninstall the AHNC module from KSU manager)"
} > "$MARKER"

# ─── Stop AHNC daemon if running ────────────────────────────────────
if pidof ahnc_capture > /dev/null 2>&1; then
    log "stopping live ahnc_capture daemon"
    pkill -TERM -f ahnc_capture
    sleep 2
    pkill -KILL -f ahnc_capture 2>/dev/null
fi

# ─── Tell user (notification via marker; service.sh logs the path) ───
log "migration complete: $migrated_count file(s) carried over"
log "see $MARKER for cleanup instructions"
log "AHNC module at $AHNC_KSU_MODULE can be uninstalled from KSU manager"

exit 0
