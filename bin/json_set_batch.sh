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
    # v5.11: 旧实现把 k/v/type 逐行写进 /data/local/tmp/hnc_json_batch_args.$$ 再按行读回:
    #   - 值里含换行就会错位成别的 k/v/type 三元组(写错字段或类型);
    #   - /data/local/tmp 对 adb shell(uid 2000)可写、文件名可预测, root 往里 `: >`
    #     会跟随预先放置的符号链接截断任意文件;
    #   - 目录不可写时整个批量写直接失败, 被中断时临时文件残留。
    # 改为在位置参数里原地轮转: 每取出一对 k v, 就把 k v type 追加到 "$@" 末尾,
    # 处理完 n 对后 "$@" 恰好只剩三元组。无临时文件, 值原样保留。
    npairs=$(( $# / 2 ))
    i=0
    while [ "$i" -lt "$npairs" ]; do
        K=$1; V=$2; shift 2
        valid_field "$K" || { echo "bad field: $K" >&2; exit 2; }
        T=$(infer_type "$V")
        set -- "$@" "$K" "$V" "$T"
        i=$((i + 1))
    done
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
