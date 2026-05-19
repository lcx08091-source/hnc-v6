#!/system/bin/sh
# cleanup_stale_rules.sh — hotfix10
# 清理长期未见的 devices 规则记录,防止 rules.json 无限膨胀。
# 只删除 rules.json.devices[mac] 里的规则状态; 不删除 blacklist / whitelist / device_names。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES="$HNC_DIR/data/rules.json"
DEVICES="$HNC_DIR/data/devices.json"
JSON_SET="$HNC_DIR/bin/json_set.sh"
APPLY="$HNC_DIR/bin/apply_device_rule.sh"
LOG="$HNC_DIR/logs/cleanup_stale.log"

log() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null || true
}

[ -f "$RULES" ] || { log "rules.json missing, skip"; exit 0; }

ttl_days=$(HNC="$HNC_DIR" sh "$JSON_SET" top_get stale_rule_ttl_days 2>/dev/null | awk 'NR==1{print; exit}')
[ -z "$ttl_days" ] && ttl_days=30
case "$ttl_days" in
    0) log "stale cleanup disabled (stale_rule_ttl_days=0)"; exit 0 ;;
    *[!0-9]*) log "invalid stale_rule_ttl_days='$ttl_days', skip"; exit 0 ;;
esac

now=$(date +%s 2>/dev/null) || now=0
[ "$now" -gt 0 ] || { log "date +%s failed, skip"; exit 0; }
threshold=$((now - ttl_days * 86400))

. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    gate_lock() { return 0; }
    gate_unlock() { return 0; }
}

gate_lock || { log "gate_lock failed, skip this round"; exit 1; }

removed=0
scanned=0
skipped_online=0
skipped_no_seen=0

# 提取 devices 字典里的 MAC key。rules.json 当前是单行 JSON,所以 grep 足够。
for mac in $(grep -oE '"[0-9a-fA-F:]{17}"[[:space:]]*:' "$RULES" 2>/dev/null \
           | sed 's/^"//; s/"[[:space:]]*:$//' \
           | tr 'A-Z' 'a-z' \
           | sort -u); do
    scanned=$((scanned + 1))

    # 当前还在线的设备绝不自动清理,避免 last_seen_persist 尚未刷新时误删。
    if [ -f "$DEVICES" ] && grep -qi "\"$mac\"" "$DEVICES" 2>/dev/null; then
        skipped_online=$((skipped_online + 1))
        continue
    fi

    last_seen=$(HNC="$HNC_DIR" sh "$JSON_SET" device_get "$mac" last_seen_persist 2>/dev/null | awk 'NR==1{print; exit}')
    case "$last_seen" in
        ''|0) skipped_no_seen=$((skipped_no_seen + 1)); continue ;;
        *[!0-9]*) skipped_no_seen=$((skipped_no_seen + 1)); continue ;;
    esac

    if [ "$last_seen" -lt "$threshold" ]; then
        age_days=$(( (now - last_seen) / 86400 ))
        log "remove stale device=$mac last_seen=$last_seen age=${age_days}d ttl=${ttl_days}d"
        # best-effort 清限速/mark/tc; 失败也继续删除 rules entry,避免无限膨胀。
        HNC_DIR="$HNC_DIR" HNC="$HNC_DIR" sh "$APPLY" clear "$mac" >> "$LOG" 2>&1 || log "WARN: clear failed for stale $mac (continuing)"
        HNC="$HNC_DIR" sh "$JSON_SET" device_remove "$mac" >> "$LOG" 2>&1 \
            && removed=$((removed + 1)) \
            || log "WARN: device_remove failed for stale $mac"
    fi
done

gate_unlock
log "cleanup done scanned=$scanned removed=$removed skipped_online=$skipped_online skipped_no_seen=$skipped_no_seen ttl_days=$ttl_days"
exit 0
