#!/system/bin/sh
# cleanup_offline_devices.sh — rc29
# WebUI 主动触发的"清理所有离线设备"。
#
# 跟 cleanup_stale_rules.sh 的区别:
#   - cleanup_stale_rules.sh 按 last_seen_persist 30 天 TTL 后台清理
#   - 本脚本是用户主动点击, 立即清, 无 TTL
#
# 行为:
#   - 默认: 只清 status != online 且 rules.json.devices[mac] 为空 的设备
#   - --include-with-rules: 连规则一起删 (apply_device_rule.sh clear + device_remove)
#
# 输出:
#   - stderr: 日志
#   - stdout: JSON {removed: N, kept_with_rules: M, skipped_online: K}
#
# 必须走 hnc_lock 的 gate_lock, 跟 cleanup_stale_rules.sh 一样,
# 避免和 hotspotd 并发写 devices.json (rc28.1.x P0-A 教训)。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
DEVICES="$HNC_DIR/data/devices.json"
RULES="$HNC_DIR/data/rules.json"
JSON_SET="$HNC_DIR/bin/json_set.sh"
APPLY="$HNC_DIR/bin/apply_device_rule.sh"
LOG="$HNC_DIR/logs/cleanup_offline.log"

INCLUDE_RULES=0
for arg in "$@"; do
    case "$arg" in
        --include-with-rules) INCLUDE_RULES=1 ;;
        *) ;;
    esac
done

log() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null || true
}

emit_json() {
    # $1=removed $2=kept_with_rules $3=skipped_online
    printf '{"ok":true,"removed":%d,"kept_with_rules":%d,"skipped_online":%d}\n' "$1" "$2" "$3"
}

emit_err() {
    # $1=reason
    printf '{"ok":false,"error":%s}\n' "$1"
}

[ -f "$DEVICES" ] || { emit_err '"devices.json missing"'; exit 0; }

. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    gate_lock()   { return 0; }
    gate_unlock() { return 0; }
}

gate_lock || {
    log "gate_lock failed, abort"
    emit_err '"gate_lock failed"'
    exit 1
}

removed=0
kept_with_rules=0
skipped_online=0

# device_has_rule mac → 0 if mac has at least one limit/delay/whitelist rule.
# We check rules.json.devices[mac] for any of: limit_*, delay_*, whitelist=true.
# Defensive: tolerate malformed JSON by treating as "no rule".
device_has_rule() {
    mac="$1"
    [ -f "$RULES" ] || return 1
    block=$(grep -oE "\"$mac\":[[:space:]]*\\{[^}]*\\}" "$RULES" 2>/dev/null | head -1)
    [ -z "$block" ] && return 1
    echo "$block" | grep -qE '"(limit_down|limit_up)":[[:space:]]*"[1-9]' && return 0
    echo "$block" | grep -qE '"delay_ms":[[:space:]]*[1-9]' && return 0
    echo "$block" | grep -qE '"whitelist":[[:space:]]*true' && return 0
    return 1
}

# Walk devices.json, collecting each MAC + its status.
# We use grep+sed rather than full JSON parse because the rest of HNC works
# the same way and this is the established pattern in cleanup_stale_rules.sh.
macs=$(grep -oE '"[0-9a-fA-F:]{17}":[[:space:]]*\{' "$DEVICES" 2>/dev/null \
       | sed -E 's/^"//; s/":[[:space:]]*\{$//' \
       | awk 'length($0)==17' \
       | sort -u)

for mac in $macs; do
    # Pull the per-device JSON block.
    block=$(grep -oE "\"$mac\":[[:space:]]*\\{[^}]*\\}" "$DEVICES" 2>/dev/null | head -1)
    [ -z "$block" ] && continue

    status=$(printf '%s' "$block" | grep -oE '"status":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"status":[[:space:]]*"([^"]*)".*/\1/')

    if [ "$status" = "online" ]; then
        skipped_online=$((skipped_online + 1))
        continue
    fi

    if device_has_rule "$mac"; then
        if [ "$INCLUDE_RULES" -eq 1 ]; then
            log "clean offline+rules mac=$mac (--include-with-rules)"
            HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" sh "$APPLY" clear "$mac" >> "$LOG" 2>&1 \
                || log "WARN: apply clear failed for $mac"
            HNC="$HNC_DIR" sh "$JSON_SET" device_remove "$mac" >> "$LOG" 2>&1 \
                && removed=$((removed + 1)) \
                || log "WARN: device_remove failed for $mac"
        else
            kept_with_rules=$((kept_with_rules + 1))
        fi
        continue
    fi

    # offline + no rule → always remove
    log "clean offline mac=$mac"
    HNC="$HNC_DIR" sh "$JSON_SET" device_remove "$mac" >> "$LOG" 2>&1 \
        && removed=$((removed + 1)) \
        || log "WARN: device_remove failed for $mac"
done

gate_unlock

log "cleanup_offline done removed=$removed kept_with_rules=$kept_with_rules skipped_online=$skipped_online include_rules=$INCLUDE_RULES"

emit_json "$removed" "$kept_with_rules" "$skipped_online"
exit 0
