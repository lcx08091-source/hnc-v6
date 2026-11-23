#!/system/bin/sh

HNC_DIR=${HNC_DIR:-/data/local/hnc}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded
# device_detect.sh — HNC 设备检测的命令行入口
#
# v5.33 起设备发现只有一份: Go 看门狗(src/dpid/cmd/hnc_watchdog/m4_owner.go)订阅
# 内核邻居表、解析名字、写 data/devices.json。本脚本原来的 shell 轮询 / shell ARP
# 扫描兜底、shell 名字解析(dumpsys / mdns_resolve / run/hostname_cache)和热点网卡
# 的旧探测链全部删除, 只剩对外接口:
#   scan    让 Go 写者立刻全量扫一次(写 nonce 到 run/devices.refresh, 等它把同一个
#           nonce 写进 run/devices.refresh.ack, 最多约 2 秒), 输出设备数
#           (WebUI「刷新」走这里)
#   daemon  开机拉起 hotspotd(硬件加速兜底 + 控制接口; 看门狗之后每轮会盯它)
#   iface   热点网卡名(bin/hnc_iface.sh, 带 5 分钟缓存)
#   count   devices.json 里的设备数

DEVICES_FILE=$HNC_DIR/data/devices.json
LOG=$HNC_DIR/logs/detect.log
HOTSPOTD_BIN=$HNC_DIR/bin/hotspotd
HOTSPOTD_PID=$HNC_DIR/run/hotspotd.pid
REFRESH_FILE=$HNC_DIR/run/devices.refresh
REFRESH_ACK=$HNC_DIR/run/devices.refresh.ack

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [DETECT] $1" >> "$LOG" 2>/dev/null || true
}

# hotspotd 是否在线
hotspotd_alive() {
    local pid
    pid=$(cat "$HOTSPOTD_PID" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# 单网卡机型权威判定: 仅当 run/iface_detect.json 明确标记 authoritative=true 且 wlan0_ap=true 时放行 wlan0
is_authoritative_wlan0_ap() {
    local _jf="$HNC_DIR/run/iface_detect.json"
    [ -f "$_jf" ] || return 1
    grep -q '"authoritative"[[:space:]]*:[[:space:]]*true' "$_jf" 2>/dev/null \
        && grep -q '"wlan0_ap"[[:space:]]*:[[:space:]]*true' "$_jf" 2>/dev/null
}

# ── 热点接口检测 ─────────────────────────────────────────────
get_hotspot_iface() {
    if [ -f "$HNC_DIR/bin/hnc_iface.sh" ]; then
        HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/hnc_iface.sh" get
        return
    fi
    log "WARN: $HNC_DIR/bin/hnc_iface.sh 不在(安装不完整), 探测不了热点网卡"
    return 1
}

# ── 设备计数 ─────────────────────────────────────────────────
count_devices_from_json() {
    awk 'BEGIN{n=0} {n+=gsub(/"mac":"/, "x")} END{print n+0}' "$1" 2>/dev/null || echo 0
}

# ── scan: 让 Go 写者立刻全量扫一次 ───────────────────────────
do_scan() {
    local nonce ack i cnt
    nonce="$$-$(date +%s)"
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    printf '%s\n' "$nonce" > "$REFRESH_FILE.tmp.$$" 2>/dev/null \
        && mv -f "$REFRESH_FILE.tmp.$$" "$REFRESH_FILE" 2>/dev/null
    i=0 ack=""
    while [ $i -lt 20 ]; do
        ack=$(cat "$REFRESH_ACK" 2>/dev/null)
        [ "$ack" = "$nonce" ] && break
        if sleep 0.1 2>/dev/null; then
            i=$((i + 1))
        else
            sleep 1
            i=$((i + 10))
        fi
    done
    cnt=$(count_devices_from_json "$DEVICES_FILE")
    if [ "$ack" = "$nonce" ]; then
        log "scan: ${cnt} device(s)"
    else
        log "scan: Go 写者 2 秒内没回执(热点没开或看门狗没在跑), 按现有 devices.json 计 ${cnt} 台"
    fi
    echo "$cnt"
}

# ── daemon: 开机拉起 hotspotd ─────────────────────────────────
daemon_mode() {
    log "=== Daemon mode starting ==="

    local SPAWNLOCK="$HNC_DIR/run/daemon.spawn"
    local waited=0
    while ! mkdir "$SPAWNLOCK" 2>/dev/null; do
        waited=$((waited + 1))
        if [ $waited -ge 10 ]; then
            log "WARN: daemon spawn lock timeout after 10s, forcing"
            rmdir "$SPAWNLOCK" 2>/dev/null
            mkdir "$SPAWNLOCK" 2>/dev/null
            break
        fi
        sleep 1
    done

    if hotspotd_alive; then
        log "hotspotd already running (PID=$(cat "$HOTSPOTD_PID" 2>/dev/null))"
    elif [ -x "$HOTSPOTD_BIN" ]; then
        log "Starting hotspotd: $HOTSPOTD_BIN"
        "$HOTSPOTD_BIN" -d -l "$HNC_DIR/logs/hotspotd.log"
        sleep 2
        if hotspotd_alive; then
            log "hotspotd running (PID=$(cat "$HOTSPOTD_PID" 2>/dev/null))"
        else
            log "WARN: hotspotd 没起来(看门狗会再拉; 设备发现在 Go 看门狗, 不受影响)"
        fi
    else
        log "hotspotd binary not found (硬件加速兜底不可用; 设备发现在 Go 看门狗, 不受影响)"
    fi
    rmdir "$SPAWNLOCK" 2>/dev/null
    return 0
}

# ── 命令分发 ────────────────────────────────────────────────
case "${1:-scan}" in
    scan)
        do_scan
        ;;
    daemon)
        daemon_mode
        ;;
    iface)
        IFACE_CACHE="$HNC_DIR/run/iface.cache"
        if [ -f "$IFACE_CACHE" ]; then
            cache_ts=$(stat -c %Y "$IFACE_CACHE" 2>/dev/null || echo 0)
            now_ts=$(date +%s)
            if [ -n "$cache_ts" ] && [ $((now_ts - cache_ts)) -lt 300 ]; then
                cached=$(cat "$IFACE_CACHE" 2>/dev/null)
                if [ -n "$cached" ] && { [ "$cached" != "wlan0" ] || is_authoritative_wlan0_ap; } && \
                   ip addr show "$cached" 2>/dev/null | grep -q 'inet '; then
                    echo "$cached"
                    exit 0
                fi
            fi
        fi
        mkdir -p "$HNC_DIR/run" 2>/dev/null
        detected=$(get_hotspot_iface)
        if [ -n "$detected" ] && { [ "$detected" != "wlan0" ] || is_authoritative_wlan0_ap; }; then
            [ "$detected" != "wlan0" ] && echo "$detected" > "$IFACE_CACHE" 2>/dev/null
            echo "$detected"
        else
            exit 1
        fi
        ;;
    count)
        echo "$(count_devices_from_json "$DEVICES_FILE")"
        ;;
    *)
        echo "Usage: $0 [scan|daemon|iface|count]"
        exit 1
        ;;
esac
