#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# hotspot_autostart.sh — 开机自动启动 WiFi 热点
# 用法: start [ssid] [pass] | stop | status
#
# v3.3.0 配置源修复：
#   用户级配置（hotspot_auto / hotspot_ssid / hotspot_pass /
#   hotspot_delay / hotspot_charging_only / hotspot_time_*）
#   现在统一从 rules.json 读取，与 WebUI 写入源保持一致。
#   同时移除原 start) 块里引号写坏的影子 get_cfg_* 函数，
#   统一走 get_rule_* 助手。
# rc3.1.13.1: config.json 已自 rc3.1.13 弃用 (字段全部迁移到 rules.json),
#   保留 1 个版本观察期, rc3.1.14+ 删除. 本脚本不再引用 config.json.

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES=$HNC_DIR/data/rules.json
LOG=$HNC_DIR/logs/hotspot.log

log() { echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S')] [HOTSPOT] $1" >> $LOG; }

# ─── 从 rules.json 读取用户级字段 ─────────────────────────────
# 字符串字段（带引号的 JSON 字符串）
# rc3.1.34 修 #48: 之前 `grep -o "...":"[^"]*"` 在字段含 `\"` (escape 引号)
# 时被切断 → SSID 截断 / 密码截断, 用户登录失败莫名其妙. 实际 SSID 标准允许
# `"` 字符 (32 字节内任意 UTF-8). 改用 awk 状态机, 识别 \" \\ \n \r \t \/
# 等 JSON escape 序列, 完整还原 string value. 同步覆盖 get_rule_str 一处, 数值
# / 布尔字段不受影响 (不会含转义字符).
get_rule_str() {
    awk -v key="$1" '
    {
        pat = "\"" key "\"[[:space:]]*:[[:space:]]*\""
        if (match($0, pat)) {
            i = RSTART + RLENGTH
            out = ""
            while (i <= length($0)) {
                c = substr($0, i, 1)
                if (c == "\\" && i + 1 <= length($0)) {
                    nc = substr($0, i+1, 1)
                    if      (nc == "\"") out = out "\""
                    else if (nc == "\\") out = out "\\"
                    else if (nc == "n")  out = out "\n"
                    else if (nc == "r")  out = out "\r"
                    else if (nc == "t")  out = out "\t"
                    else if (nc == "/")  out = out "/"
                    else                 out = out nc
                    i += 2
                } else if (c == "\"") {
                    print out
                    exit
                } else {
                    out = out c
                    i++
                }
            }
        }
    }' "$RULES" 2>/dev/null
}
# 数值字段
get_rule_num() {
    grep -o "\"$1\"[[:space:]]*:[[:space:]]*-\?[0-9][0-9.]*" "$RULES" 2>/dev/null \
        | head -1 | sed 's/.*:[[:space:]]*//'
}
# 布尔字段
get_rule_bool() {
    grep -o "\"$1\"[[:space:]]*:[[:space:]]*\(true\|false\)" "$RULES" 2>/dev/null \
        | head -1 | sed 's/.*:[[:space:]]*//'
}

get_setting() {
    local val=$(settings get global "$1" 2>/dev/null)
    [ "$val" = "null" ] || [ -z "$val" ] && echo "" || echo "$val"
}

CMD=${1:-start}

case "$CMD" in

start)
    log "=== Hotspot autostart begin ==="

    # ── 0. 读取用户配置（全部来自 rules.json）────────────────
    # v3.4.9: 删除充电限制 / 时间段限制(用户用不上,徒增配置复杂度)
    DELAY=$(get_rule_num hotspot_delay)
    DELAY=${DELAY:-60}

    log "Config: delay=${DELAY}s"

    # 检查:开机延迟（等待系统稳定）
    if [ "$DELAY" -gt 0 ] 2>/dev/null; then
        log "Waiting ${DELAY}s before starting hotspot (boot delay)..."
        sleep "$DELAY"
    fi

    log "All checks passed, proceeding to start hotspot"

    # ── 1. 注入 SELinux 策略 ────────────────────────────────
    log "Injecting SELinux policies..."
    KSU_BIN="/data/adb/ksu/bin/ksud"
    MAGISK_POLICY=$(command -v magiskpolicy 2>/dev/null)

    inject_rule() {
        [ -x "$KSU_BIN" ]   && "$KSU_BIN" sepolicy patch "$1" 2>/dev/null && return 0
        [ -n "$MAGISK_POLICY" ] && "$MAGISK_POLICY" --live "$1" 2>/dev/null && return 0
        return 1
    }

    for RULE in \
        "allow shell network_stack:binder { call transfer }" \
        "allow shell tethering_service:binder { call transfer }" \
        "allow shell wifi_service:binder { call transfer }" \
        "allow shell network_stack:service_manager find" \
        "allow shell tethering_service:service_manager find" \
        "allow su network_stack:binder { call transfer }" \
        "allow su tethering_service:binder { call transfer }" \
        "allow su wifi_service:binder { call transfer }" \
        "allow su network_stack:service_manager find" \
        "allow su tethering_service:service_manager find" \
        "allow system_app tethering_service:binder { call transfer }" \
        "allow platform_app tethering_service:binder { call transfer }"; do
        inject_rule "$RULE"
    done
    sleep 1

    # ── 2. 等待 WifiService 就绪 ────────────────────────────
    log "Waiting for WifiService..."
    svc wifi enable 2>/dev/null || true
    i=0
    while [ $i -lt 30 ]; do
        [ -n "$(cmd wifi status 2>/dev/null)" ] && break
        sleep 2; i=$((i+1))
    done
    log "WifiService check done (${i} retries)"

    # ── 3. 读取 SSID / 密码（v3.3.0：改从 rules.json）─────
    AP_SSID="${2:-$(get_rule_str hotspot_ssid)}"
    AP_PASS="${3:-$(get_rule_str hotspot_pass)}"
    [ -z "$AP_SSID" ] && AP_SSID="$(get_setting wifi_ap_ssid)"
    [ -z "$AP_PASS" ] && AP_PASS="$(get_setting wifi_ap_password)"
    [ -z "$AP_SSID" ] && AP_SSID="MyHotspot"
    [ -z "$AP_PASS" ] && AP_PASS="12345678"
    log "SSID=$AP_SSID"

    # ── 4. 启动热点（多方法兜底）───────────────────────────
    STARTED=0

    # 方法1: cmd wifi start-softap（Android 13+）
    for attempt in 1 2 3; do
        for SEC in wpa2 wpa3 wpa3_transition open; do
            RESULT=$(cmd wifi start-softap "$AP_SSID" "$SEC" "$AP_PASS" 2>&1)
            echo "$RESULT" | grep -qi "started\|success" && STARTED=1 && log "started via cmd wifi (sec=$SEC)" && break 2
        done
        [ "$STARTED" = "1" ] && break
        [ "$attempt" -lt 3 ] && sleep 5
    done

    # 方法2: cmd tethering
    if [ "$STARTED" = "0" ]; then
        cmd tethering tether wifi 2>/dev/null && STARTED=1 && log "started via cmd tethering"
    fi

    # 方法3: svc
    if [ "$STARTED" = "0" ]; then
        svc wifi hotspot enable 2>/dev/null && STARTED=1 && log "started via svc"
    fi

    if [ "$STARTED" = "1" ]; then
        rm -f "$HNC_DIR/run/uplink_unsupported" "$HNC_DIR/run/uplink_fail_count" "$HNC_DIR/run/uplink_unsupported_logged" 2>/dev/null || true
        log "=== Hotspot autostart SUCCESS ==="
    else
        log "=== Hotspot autostart FAILED ==="; exit 1
    fi
    ;;

stop)
    log "Stopping hotspot..."
    cmd wifi stop-softap 2>/dev/null \
        || cmd tethering untether wifi 2>/dev/null \
        || svc wifi hotspot disable 2>/dev/null
    log "Stop command sent"
    ;;

status)
    ison=0
    for iface in ap0 wlan1 wlan2 wlan3 swlan0; do
        ip addr show "$iface" 2>/dev/null | grep -q 'inet ' && ison=1 && break
    done
    [ "$ison" = "0" ] && cmd wifi status 2>/dev/null | grep -qi "ap started\|hotspot" && ison=1
    echo $ison
    ;;

*)
    echo "Usage: $0 {start|stop|status} [ssid] [password]"
    exit 1
    ;;
esac
