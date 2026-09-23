#!/system/bin/sh
# whitelist_sync.sh — 按 rules.json 把白名单模式真正落到 iptables(v5.11)
#
# 背景: 此前 WebUI 的「白名单模式」开关(action whitelist_set)只把
# rules.json 顶层 whitelist_mode 写成 true/false, 从来没有任何地方调用
# iptables_manager.sh 的 whitelist_on / whitelist_add —— HNC_WHITELIST 链
# 永远是空的, 开关打开后不拦截任何设备(视觉欺骗)。
#
# 本脚本是白名单的唯一执行入口, 幂等, 随时可重跑:
#   1. 先整链清空(whitelist_off);
#   2. whitelist_mode=false → 到此为止;
#   3. whitelist_mode=true  → 把 rules.json.devices 里 "whitelist":true 的
#      每台设备按 MAC(+当前 IP)放行, 最后在链尾追加 DROP。
# 链挂在 filter/FORWARD 上, 只拦截经热点转发出去的流量; 设备访问本机
# (DHCP/DNS/WebUI :8443)走 INPUT, 不受影响, 所以不会把管理端锁在外面。
#
# 调用方: hnc_httpd 的 whitelist_set / device_whitelist_set 动作,
#        以及 watchdog / service.sh 在 iptables_manager.sh init 之后。
#
# 输出(最后一行): WHITELIST=off  或  WHITELIST=on count=<放行台数>
# 用法: whitelist_sync.sh [--dry-run]   (--dry-run 只打印将执行的动作)

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES="$HNC_DIR/data/rules.json"
DEVICES="$HNC_DIR/data/devices.json"
IPTM="$HNC_DIR/bin/iptables_manager.sh"
LOG="$HNC_DIR/logs/service.log"
DRY=0
[ "$1" = "--dry-run" ] && DRY=1

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [whitelist_sync] $*" >> "$LOG"; } 2>/dev/null; }

ipt() {
    if [ "$DRY" = "1" ]; then
        echo "DRY: iptables_manager.sh $*"
        return 0
    fi
    sh "$IPTM" "$@" >> "$LOG" 2>&1
}

mode=false
if [ -f "$RULES" ]; then
    mode=$(grep -oE '"whitelist_mode"[[:space:]]*:[[:space:]]*(true|false)' "$RULES" 2>/dev/null \
           | head -1 | grep -oE 'true|false')
    [ -n "$mode" ] || mode=false
fi

ipt whitelist_off || log "whitelist_off rc=$?"

if [ "$mode" != "true" ]; then
    log "mode=off, chain flushed"
    echo "WHITELIST=off"
    exit 0
fi

# 只取 devices 对象里 "whitelist":true 的条目。块内不含嵌套对象(与
# cleanup_offline_devices.sh 的 device_has_rule 同一约定)。
# rules.json / devices.json 可能是多行格式化的, grep 按行匹配会漏掉跨行的块 ——
# 先压成一行再匹配。
FLAT_RULES=$(tr -d '\r\n' < "$RULES" 2>/dev/null)
FLAT_DEVS=""
[ -f "$DEVICES" ] && FLAT_DEVS=$(tr -d '\r\n' < "$DEVICES" 2>/dev/null)
macs=$(printf '%s' "$FLAT_RULES" | grep -oE '"[0-9a-fA-F:]{17}"[[:space:]]*:[[:space:]]*\{[^}]*"whitelist"[[:space:]]*:[[:space:]]*true[^}]*\}' 2>/dev/null \
       | grep -oE '^"[0-9a-fA-F:]{17}"' | tr -d '"' | tr 'A-F' 'a-f' | sort -u)

count=0
for mac in $macs; do
    # MAC 已由正则约束为 17 位 hex+冒号; IP 只接受点分十进制, 否则只按 MAC 放行
    ip=""
    if [ -n "$FLAT_DEVS" ]; then
        blk=$(printf '%s' "$FLAT_DEVS" | grep -oiE "\"$mac\"[[:space:]]*:[[:space:]]*\\{[^}]*\\}" 2>/dev/null | head -1)
        ip=$(printf '%s' "$blk" | grep -oE '"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    fi
    ipt whitelist_add "$ip" "$mac" || log "whitelist_add $mac rc=$?"
    count=$((count + 1))
done

ipt whitelist_on || log "whitelist_on rc=$?"
log "mode=on allowed=$count"
echo "WHITELIST=on count=$count"
