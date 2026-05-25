#!/system/bin/sh
# json_set_batch.sh - hotfix19.6 hnc_json atomic batch bridge
# Usage: sh json_set_batch.sh device <MAC> <field1> <val1> [<field2> <val2> ...]
#
# This script intentionally keeps the public CLI stable, but routes each field
# through hnc_json set-device when available. That avoids the historical regex
# batch writer and also avoids the extra json_set.sh bridge layer introduced in
# hotfix18.2. Multi-field writes are still correctness-first serial writes; a
# future native hnc_json set-device-batch can restore true atomic batch writes.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC=${HNC:-/data/local/hnc}
RULES=${RULES:-$HNC/data/rules.json}
SCRIPT_DIR=${0%/*}
[ "$SCRIPT_DIR" = "$0" ] && SCRIPT_DIR="."
HNC_JSON=${HNC_JSON:-$SCRIPT_DIR/hnc_json}
JSON_SET=${JSON_SET:-$SCRIPT_DIR/json_set.sh}

# hotfix20.1: record when the hnc_json batch writer is missing and the legacy
# serial fallback is used. Best-effort only; never make recovery writes fail
# because telemetry cannot be persisted.
JSON_LEGACY_FALLBACK_LOG=${JSON_LEGACY_FALLBACK_LOG:-$HNC/run/json_legacy_fallback.log}
JSON_LEGACY_FALLBACK_COUNT=${JSON_LEGACY_FALLBACK_COUNT:-$HNC/run/json_legacy_fallback.count}
json_batch_legacy_fallback_warn() {
    local reason="$1"
    local ts cnt
    ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date 2>/dev/null || echo unknown)
    mkdir -p "$HNC/run" 2>/dev/null || true
    printf '%s json_set_batch op=device-batch reason=%s\n' "$ts" "$reason" >> "$JSON_LEGACY_FALLBACK_LOG" 2>/dev/null || true
    if [ -f "$JSON_LEGACY_FALLBACK_COUNT" ]; then
        cnt=$(cat "$JSON_LEGACY_FALLBACK_COUNT" 2>/dev/null)
        case "$cnt" in *[!0-9]*|'') cnt=0 ;; esac
    else
        cnt=0
    fi
    cnt=$((cnt + 1))
    echo "$cnt" > "$JSON_LEGACY_FALLBACK_COUNT" 2>/dev/null || true
    echo "json_set_batch: [WARN] hnc_json set-device-batch unavailable, using legacy serial fallback; count=$cnt" >&2
}

usage() {
    echo "usage: $0 device <MAC> <k> <v> [<k> <v> ...]" >&2
    exit 2
}

infer_type() {
    v="$1"
    case "$v" in
        true|false) echo bool ;;
        null) echo null ;;
        -[0-9]*|[0-9]*)
            if echo "$v" | grep -Eq '^-?[0-9]+([.][0-9]+)?$'; then
                echo num
            else
                echo str
            fi
            ;;
        *) echo str ;;
    esac
}

valid_field() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
        *) return 0 ;;
    esac
}

[ "$1" = "device" ] || usage
shift
MAC=${1:-}; shift || true
[ -n "$MAC" ] || { echo "missing MAC" >&2; exit 2; }
echo "$MAC" | grep -qiE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' || { echo "bad MAC: $MAC" >&2; exit 2; }
[ $# -ge 2 ] && [ $(( $# % 2 )) -eq 0 ] || { echo "need k v pairs" >&2; exit 2; }

mkdir -p "$HNC/data" "$HNC/run" 2>/dev/null || true
[ -f "$RULES" ] || cat > "$RULES" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
JSON

# Prefer native hnc_json set-device-batch. This performs one validation,
# one backup, one lock, and one final commit for the whole field set.
if [ -x "$HNC_JSON" ]; then
    # Pin to HNC's root-only run/ dir, not ${TMPDIR:-/data/local/tmp} (the latter
    # is world-writable on Android and $$ is predictable → symlink-redirect risk
    # on the batch args, which carry MAC + field values).
    TMP_ARGS_FILE="$HNC/run/.hnc_json_batch_args.$$"
    : > "$TMP_ARGS_FILE" || exit 1
    while [ $# -ge 2 ]; do
        K=$1; V=$2; shift 2
        valid_field "$K" || { rm -f "$TMP_ARGS_FILE"; echo "bad field: $K" >&2; exit 2; }
        T=$(infer_type "$V")
        printf '%s\n%s\n%s\n' "$K" "$V" "$T" >> "$TMP_ARGS_FILE"
    done
    set --
    while IFS= read -r line; do
        set -- "$@" "$line"
    done < "$TMP_ARGS_FILE"
    rm -f "$TMP_ARGS_FILE"
    "$HNC_JSON" set-device-batch "$RULES" "$MAC" "$@"
    rc=$?
    [ $rc -eq 0 ] || { echo "json_set_batch: hnc_json set-device-batch failed rc=$rc" >&2; exit $rc; }
    exit 0
fi

# Legacy fallback: use json_set.sh device, which itself may use hnc_json if this
# script is invoked from an older package layout. Kept for recovery builds.
json_batch_legacy_fallback_warn "missing-hnc_json-batch"
while [ $# -ge 2 ]; do
    K=$1; V=$2; shift 2
    valid_field "$K" || { echo "bad field: $K" >&2; exit 2; }
    sh "$JSON_SET" device "$MAC" "$K" "$V"
    rc=$?
    [ $rc -eq 0 ] || { echo "json_set_batch: json_set failed field=$K rc=$rc" >&2; exit $rc; }
done
exit 0
