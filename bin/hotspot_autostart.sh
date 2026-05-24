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

# rc25: ColorOS 不支持命令行开「带网络共享」的热点(cmd tethering 无 shell 实现、
# svc wifi 无 hotspot 子命令);cmd wifi start-softap 只起「本地热点」(Android 明说
# 不激活 internet tethering)。所以这里手动做 NAT:把本地热点接口的流量
# MASQUERADE 到上联(默认路由)接口,让连上的设备能用手机流量上网。
# 全程 best-effort:失败只是没网,不影响热点起来(日志会记;否则请从系统设置开)。
detect_up_iface() {
    # rc26: Android 用策略路由(per-network 路由表),main 表常无 default route,
    # `ip route show default` 探不到。改用 `ip route get` 探实际互联网出口接口。
    _r=$(ip route get 1.1.1.1 2>/dev/null)
    case "$_r" in
        *" dev "*) _r=${_r#*dev }; echo "${_r%% *}" ;;
    esac
}
detect_ap_iface() {
    _up="$1"
    for _i in ap0 wlan1 wlan2 wlan3 swlan0 wlan0; do
        [ "$_i" = "$_up" ] && continue
        ip addr show "$_i" 2>/dev/null | grep -q 'inet ' && { echo "$_i"; return; }
    done
}
setup_nat() {
    up=$(detect_up_iface)
    # rc27: 轮询等本地热点接口拿到 IP(最多 ~8s)。开机时系统忙,固定 sleep 2 可能
    # 还没就绪 → 找不到接口 → NAT 没挂 → 客户端没网。真机实测 wlan2 约 5s 才有 IP。
    ap=""; _t=0
    while [ "$_t" -lt 8 ]; do
        ap=$(detect_ap_iface "$up"); [ -n "$ap" ] && break
        sleep 1; _t=$((_t + 1))
    done
    if [ -z "$ap" ] || [ -z "$up" ]; then
        log "NAT: 找不到 ap=[$ap] / up=[$up](等了 ${_t}s),跳过 —— 客户端可能没网,请改从系统设置开热点"
        return 0
    fi
    log "NAT: ap=$ap up=$up(${_t}s 就绪)"
    log "NAT: ap=$ap up=$up,启用 ip_forward + MASQUERADE + FORWARD"
    { echo 1 > /proc/sys/net/ipv4/ip_forward; } 2>/dev/null || sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    iptables -t nat -C POSTROUTING -o "$up" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$up" -j MASQUERADE 2>/dev/null || true
    iptables -C FORWARD -i "$ap" -o "$up" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ap" -o "$up" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -i "$up" -o "$ap" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$up" -o "$ap" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    log "NAT: done (ap=$ap up=$up)"
}
teardown_nat() {
    up=$(detect_up_iface)
    [ -n "$up" ] && iptables -t nat -D POSTROUTING -o "$up" -j MASQUERADE 2>/dev/null || true
    ap=$(detect_ap_iface "$up")
    if [ -n "$ap" ] && [ -n "$up" ]; then
        iptables -D FORWARD -i "$ap" -o "$up" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$up" -o "$ap" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi
    log "NAT: torn down"
}

CMD=${1:-start}

case "$CMD" in

start|start-now)
    log "=== Hotspot autostart begin (cmd=$CMD) ==="

    # ── 0. 读取用户配置（全部来自 rules.json）────────────────
    # v3.4.9: 删除充电限制 / 时间段限制(用户用不上,徒增配置复杂度)
    DELAY=$(get_rule_num hotspot_delay)
    DELAY=${DELAY:-60}
    # rc24: 手动「立即启动」(start-now) 跳过开机延迟 —— 开机后台路径用 start 保留延迟,
    # 但 WebUI 点立即启动若也睡 60s 会让 Go action 超时 + WebUI 卡死。
    [ "$CMD" = "start-now" ] && DELAY=0

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
    # rc25: 不再 svc wifi enable —— softap 不需要开 STA WiFi(真机实测 WiFi 关着也能起),
    # 之前 enable 会无谓打开用户的 WiFi。仅等 WifiService 可响应即可。
    log "Waiting for WifiService..."
    i=0
    while [ $i -lt 15 ]; do
        [ -n "$(cmd wifi status 2>/dev/null)" ] && break
        sleep 1; i=$((i+1))
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

    # 方法1: cmd wifi start-softap（Android 13+ 主力,真机唯一可用)
    # rc25: 加 -b any —— 真机实测不带 -b 时默认频段会撞(error 18),-b any 让固件自选
    # 可用频段后成功起来。SEC 仍按 wpa2→wpa3→… 兜底。
    for attempt in 1 2 3; do
        for SEC in wpa2 wpa3 wpa3_transition open; do
            RESULT=$(cmd wifi start-softap "$AP_SSID" "$SEC" "$AP_PASS" -b any 2>&1)
            echo "$RESULT" | grep -qi "started\|success" && STARTED=1 && log "started via cmd wifi (sec=$SEC -b any)" && break 2
        done
        [ "$STARTED" = "1" ] && break
        [ "$attempt" -lt 3 ] && sleep 5
    done

    # 方法2/3(cmd tethering / svc wifi hotspot)在 ColorOS 上无 shell 实现,保留仅作
    # 其他 ROM 兜底;ColorOS 走不到这里。
    if [ "$STARTED" = "0" ]; then
        cmd tethering tether wifi 2>/dev/null && STARTED=1 && log "started via cmd tethering"
    fi
    if [ "$STARTED" = "0" ]; then
        svc wifi hotspot enable 2>/dev/null && STARTED=1 && log "started via svc"
    fi

    if [ "$STARTED" = "1" ]; then
        rm -f "$HNC_DIR/run/uplink_unsupported" "$HNC_DIR/run/uplink_fail_count" "$HNC_DIR/run/uplink_unsupported_logged" 2>/dev/null || true
        # rc25: 本地热点没有系统 tethering 的 NAT,手动补一份,让客户端能上网。
        setup_nat
        log "=== Hotspot autostart SUCCESS ==="
    else
        log "=== Hotspot autostart FAILED ==="; exit 1
    fi
    ;;

stop)
    log "Stopping hotspot..."
    teardown_nat   # rc25: 先撤我们加的 NAT 规则
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
    echo "Usage: $0 {start|start-now|stop|status} [ssid] [password]"
    exit 1
    ;;
esac
