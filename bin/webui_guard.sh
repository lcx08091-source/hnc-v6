#!/system/bin/sh
# webui_guard.sh — v5.22 WebUI 访问白名单落到防火墙(filter/INPUT, v4 + v6)
#
# 为什么在防火墙层: HTTP 403 时 TLS 握手、配对页、PIN 接口都已经暴露给对方;
# 在 INPUT 链直接回 TCP RST, 非白名单客户端看到的就是 "connection refused"。
# hnc_httpd 里还有同配置的 Go 侧判定(webui_access.go)作纵深防御。
#
# 配置: data/webui_access.json(hnc_httpd 的 webui_access_set 动作是唯一写者, 单行 JSON)
#   {"mode":"all|allowlist|local_only","macs":["aa:bb:..","192.168.43.7","fd00::7"],"updated":N}
#   文件不存在 → all; 文件损坏 / mode 非法 → local_only(fail-closed, 与 Go 侧一致)
#
# 规则(独立链 HNC_WEBUI, 每个端口一条 `-I INPUT 1 -p tcp --dport <p> -j HNC_WEBUI`):
#   1. -i lo -j RETURN                         本机永远放行(KSU WebUI / 本机浏览器)
#   2. 蜂窝上行口(rmnet+/ccmni+/wwan+/seth_+/sipa_eth+)→ REJECT   任何模式都拒:
#      httpd 绑 0.0.0.0, 双栈下手机的蜂窝 IPv6 公网地址上 8443 同样在监听
#   3. all        → RETURN(其余交给 INPUT 后续规则, 与旧行为一致)
#      allowlist  → 每个 MAC: -m mac --mac-source <mac> -j RETURN
#                   每个本族 IP: -s <ip> -j RETURN;  其余 REJECT --reject-with tcp-reset
#      local_only → 其余 REJECT --reject-with tcp-reset
#   REJECT 不可用的内核退 DROP。放行用 RETURN 而不是 ACCEPT: 不越过 netd 自己的
#   INPUT 策略(fw_INPUT / bw_INPUT 等)。
# 幂等: 每次 apply 先 -F 链再重建; 跳转规则先 -C 再插, 重复跑不会叠加。
#
# 端口: HNC_WEBUI_PORTS(缺省 "8443 8080 8444" = HTTPS / HTTP→HTTPS 跳转 / loopback)
#
# 调用方: service.sh 在拉起 hnc_httpd 之前 apply; watchdog 全量恢复时 apply(自愈);
#         hnc_httpd 的 webui_access_set 动作改配置后 apply; cleanup.sh(all/restart)remove。
#
# 用法: webui_guard.sh apply|remove|status [--dry-run]
# 输出(最后一行): WEBUI_GUARD=applied mode=<m> entries=<n> v6=<0|1>
#                 WEBUI_GUARD=removed  |  WEBUI_GUARD=failed <原因>
# 退出码: 0 成功; 1 v4 规则落地失败; 2 用法错误
# 测试钩子: HNC_IPT / HNC_IP6T(iptables 命令, 可为桩), HNC_WEBUI_PORTS

HNC_DIR=${HNC_DIR:-/data/local/hnc}
CONF="$HNC_DIR/data/webui_access.json"
STATE="$HNC_DIR/run/webui_guard.state"
LOG="$HNC_DIR/logs/service.log"
CHAIN=HNC_WEBUI
PORTS=${HNC_WEBUI_PORTS:-"8443 8080 8444"}
CELL_IFACES="rmnet+ ccmni+ wwan+ seth_+ sipa_eth+"
IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}

CMD=${1:-apply}
DRY=0
[ "$2" = "--dry-run" ] && DRY=1

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [webui_guard] $*" >> "$LOG"; } 2>/dev/null; }
run() {
    if [ "$DRY" = "1" ]; then echo "DRY: $*"; return 0; fi
    "$@" 2>/dev/null
}

v6=0
if [ -n "$HNC_IP6T" ]; then
    v6=1
elif command -v ip6tables >/dev/null 2>&1 && $IP6T -L INPUT -n >/dev/null 2>&1; then
    v6=1
fi

# ─── 配置解析 ────────────────────────────────────────────────────
MODE=all
ENTRIES=""
read_conf() {
    MODE=all
    ENTRIES=""
    [ -f "$CONF" ] || return 0
    _c=$(tr -d '\r\n' < "$CONF" 2>/dev/null)
    MODE=$(printf '%s' "$_c" | grep -oE '"mode"[[:space:]]*:[[:space:]]*"[a-z_]*"' | head -1 \
           | sed 's/.*"\([a-z_]*\)"$/\1/')
    case "$MODE" in
        all|allowlist|local_only) ;;
        *) log "WARN: bad/missing mode in $CONF ('$MODE'), fail-closed to local_only"; MODE=local_only ;;
    esac
    _l=$(printf '%s' "$_c" | grep -oE '"macs"[[:space:]]*:[[:space:]]*\[[^]]*\]' | head -1 \
         | sed 's/^[^[]*\[//; s/\]$//' | tr ',' ' ' | tr -d '"')
    for _e in $_l; do
        _e=$(printf '%s' "$_e" | tr 'A-F' 'a-f')
        if is_mac "$_e" || is_ipv4 "$_e" || is_ipv6 "$_e"; then
            ENTRIES="$ENTRIES $_e"
        else
            log "WARN: skip invalid allowlist entry '$_e'"
        fi
    done
    unset _c _l _e
}

is_mac() {
    printf '%s' "$1" | grep -qE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
}
is_ipv4() {
    printf '%s' "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}
is_ipv6() {
    # 至少两个冒号, 只含 hex / 冒号 / 点(v4 尾); 排除 MAC
    is_mac "$1" && return 1
    printf '%s' "$1" | grep -qE '^[0-9a-f:.]+$' || return 1
    case "$1" in *:*:*) return 0 ;; esac
    return 1
}

# ─── 规则 ────────────────────────────────────────────────────────
reject_tail() {  # $1=iptables 命令
    run $1 -A $CHAIN -p tcp -j REJECT --reject-with tcp-reset || run $1 -A $CHAIN -j DROP
}

teardown() {  # $1=iptables 命令
    for _p in $PORTS; do
        _i=0
        while run $1 -D INPUT -p tcp --dport "$_p" -j $CHAIN; do
            _i=$((_i + 1)); [ "$_i" -ge 20 ] && break; [ "$DRY" = 1 ] && break
        done
    done
    run $1 -F $CHAIN
    run $1 -X $CHAIN
    unset _p _i
}

build() {  # $1=iptables 命令  $2=4|6
    _T=$1
    run $_T -N $CHAIN          # 已存在时失败, 无妨
    run $_T -F $CHAIN || return 1
    run $_T -A $CHAIN -i lo -j RETURN || return 1
    for _c in $CELL_IFACES; do
        run $_T -A $CHAIN -i "$_c" -p tcp -j REJECT --reject-with tcp-reset \
            || run $_T -A $CHAIN -i "$_c" -j DROP
    done
    case "$MODE" in
        all)
            run $_T -A $CHAIN -j RETURN || return 1
            ;;
        allowlist)
            for _e in $ENTRIES; do
                if is_mac "$_e"; then
                    run $_T -A $CHAIN -m mac --mac-source "$_e" -j RETURN \
                        || log "WARN: v$2 mac match failed for $_e (xt_mac missing?)"
                elif [ "$2" = 4 ] && is_ipv4 "$_e"; then
                    run $_T -A $CHAIN -s "$_e" -j RETURN
                elif [ "$2" = 6 ] && is_ipv6 "$_e"; then
                    run $_T -A $CHAIN -s "$_e" -j RETURN
                fi
            done
            reject_tail "$_T" || return 1
            ;;
        local_only)
            reject_tail "$_T" || return 1
            ;;
    esac
    for _p in $PORTS; do
        if ! run $_T -C INPUT -p tcp --dport "$_p" -j $CHAIN || [ "$DRY" = 1 ]; then
            run $_T -I INPUT 1 -p tcp --dport "$_p" -j $CHAIN || return 1
        fi
    done
    unset _T _c _e _p
    return 0
}

write_state() {
    [ "$DRY" = 1 ] && return 0
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    { printf '%s\n' "$1" > "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"; } 2>/dev/null
}

count_entries() { set -- $ENTRIES; echo $#; }

case "$CMD" in
    apply)
        read_conf
        n=$(count_entries)
        if ! build "$IPT" 4; then
            log "ERROR: v4 apply failed (mode=$MODE)"
            write_state "failed mode=$MODE v4=fail ts=$(date +%s)"
            echo "WEBUI_GUARD=failed v4"
            exit 1
        fi
        v6s=skip
        if [ "$v6" = 1 ]; then
            if build "$IP6T" 6; then v6s=ok; else v6s=fail; log "WARN: v6 apply failed (mode=$MODE)"; fi
        fi
        log "applied mode=$MODE entries=$n v6=$v6s ports=$PORTS"
        write_state "applied mode=$MODE entries=$n v4=ok v6=$v6s ts=$(date +%s)"
        echo "WEBUI_GUARD=applied mode=$MODE entries=$n v6=$v6"
        ;;
    remove)
        teardown "$IPT"
        [ "$v6" = 1 ] && teardown "$IP6T"
        log "removed"
        write_state "removed ts=$(date +%s)"
        echo "WEBUI_GUARD=removed"
        ;;
    status)
        read_conf
        echo "mode=$MODE entries=$(count_entries) ports=$PORTS v6=$v6"
        [ -f "$STATE" ] && cat "$STATE"
        ;;
    *)
        echo "usage: webui_guard.sh apply|remove|status [--dry-run]" >&2
        exit 2
        ;;
esac
exit 0
