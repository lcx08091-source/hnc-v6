#!/system/bin/sh
# hnc_iface.sh — HNC 唯一权威的热点接口探测器 + 接口名分类表(v5.20)
#
# 为什么要有它: 此前热点口散落在 device_detect.sh(get_hotspot_iface)、
# hotspot_autostart.sh(detect_ap_iface)、hotspotd(黑名单)、dpid(自扫)、httpd
# (hnc_state→iface.cache→rules.json)各自判定, 名单互不一致(有的认 swlan0 不认
# ap_br_*, 有的把 wlan1 副 STA 当热点)。本文件是 shell 侧唯一实现; httpd 读它写的
# run/iface_detect.json; 接口名模式表与 Go 侧 daemon/hnc_httpd/iface_patterns.go
# 逐字一致(iface_patterns_test.go 读本文件校验, 改一边不改另一边测试直接挂)。
#
# ── 探测顺序(每一步都要求接口真实存在; 标 * 的是权威来源, 可返回 wlan0)────────
#   0* override     rules.json 顶层 hotspot_iface(WebUI「热点接口偏好」, auto=空):
#                   接口存在且有 IPv4 才生效, 否则继续探测(防止偏好指向已消失的接口)
#   1* tethering    `dumpsys tethering`(Android 11+ Tethering mainline 模块)/
#                   `dumpsys connectivity tethering`(Android 8–10): "Tether state:" 段
#                   的 `<iface> - TetheredState`(优先)或 `LocalHotspotState`,
#                   只取 Wi-Fi 类接口(USB/BT/以太/p2p 另行上报)
#   2* tetherctrl   iptables tetherctrl_FORWARD 的 `-i <iface>` ACCEPT 规则(netd 维护,
#                   与 v3.4.1 起的旧实现同款; 不要求 IPv4, 与旧行为一致)。跳过
#                   RELATED,ESTABLISHED 回程规则(其 -i 是上游, Wi-Fi 上游时就是 wlan0)
#                   以及当前上游 / 带 default route 的接口
#   3* wifi_softap  `dumpsys wifi` 的 SoftApManager `mApInterfaceName: <iface>`
#   4  scan         名字像 AP(ap0 / ap_br_* / swlan0 / softap0; 次选 wlan1+ / wigig0)
#                   且 UP、有 RFC1918 IPv4、没有任何路由表里的 default route(= 不是
#                   STA/上游)、不是当前上游; 有 ARP 邻居的优先
#   都失败 → 空, exit 1(绝不兜底 wlan0 —— 见 device_detect.sh v4.0.0-patch1.4 事故)
# 成本控制: 步骤 1/3 的 dumpsys 只在「存在带私网 IPv4、无 default route、非蜂窝」
#   的候选接口时才跑(热点关着时整轮只有一次 ip addr + 一次 ip route, 无 dumpsys);
#   dumpsys 带 timeout(有 timeout 命令时)。
#
# ── 输出契约(给 watchdog / 自检 / httpd / WebUI)────────────────────────────────
#   run/iface_detect.json   每次探测覆盖写(原子 mv):
#     {"schema":1,"ts":<unix>,"iface":"wlan2"|"","method":"override|tethering|
#      tetherctrl|wifi_softap|scan|none","authoritative":true|false,"ipv4":"10.x.x.1",
#      "wlan0_ap":bool,"override":"<pref>","override_state":"none|ok|invalid",
#      "tethered":[..所有 TetheredState 接口..],"local_only":[..LocalHotspotState..],
#      "wifi_tether":[..],"usb_tether":[..],"bt_tether":[..],"eth_tether":[..],
#      "upstream":"rmnet_data2","upstream_class":"cell|wifi|eth|usb|other|",
#      "candidates":[..],"sig":"<候选签名>","scope_note":"..."}
#   run/hotspot_iface       探测成功且值变化时写一行接口名(dpid / hotspotd / clsact 的 hint)
#   run/iface.cache         同上(非 wlan0 时), 与 device_detect.sh iface 缓存同一文件
#   USB(rndis0/usb0/ncm0)/ 蓝牙(bt-pan)/ 以太网共享: 只探测并上报, HNC 的限速 /
#   封锁只作用于 Wi-Fi 热点口 —— 这些共享方式的客户端不在管控范围内(见 COMPATIBILITY)。
#
# ── 用法 ───────────────────────────────────────────────────────────────────────
#   hnc_iface.sh detect        强制重新探测, stdout 输出接口名(失败 exit 1)
#   hnc_iface.sh get           读缓存(TTL + 候选签名未变 + 接口仍有 IPv4), 否则重新探测
#   hnc_iface.sh info          get 后输出 run/iface_detect.json
#   hnc_iface.sh invalidate    删除缓存(热点开关/切换后调用)
#   hnc_iface.sh upstream      输出 "<上游接口> <分类>"
#   hnc_iface.sh classify <if> 输出接口分类: cell|ap|ap_maybe|wifi_sta|usb|bt|eth|p2p|ignore|other
#   hnc_iface.sh patterns      打印模式表
# 作为库: HNC_IFACE_LIB=1 . hnc_iface.sh  (只定义函数, 不执行 CLI)
# 测试钩子: HNC_SYS_NET(默认 /sys/class/net)、HNC_PROC_NET_ARP(默认 /proc/net/arp)、
#           HNC_IFACE_TTL(默认 60)、PATH 上的 dumpsys/ip/iptables 桩。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

HNC_DIR=${HNC_DIR:-/data/local/hnc}
_HI_RUN="$HNC_DIR/run"
_HI_JSON="$_HI_RUN/iface_detect.json"
_HI_SYS_NET=${HNC_SYS_NET:-/sys/class/net}
_HI_ARP=${HNC_PROC_NET_ARP:-/proc/net/arp}
_HI_TTL=${HNC_IFACE_TTL:-60}
_HI_LOG="$HNC_DIR/logs/detect.log"

# ─── 接口名模式表(POSIX ERE, 同一字符串 Go RE2 也能用; 与 iface_patterns.go 逐字一致)──
# 蜂窝上游: 高通 rmnet_dataN / 三星 Exynos & Tensor rmnetN / 联发科 ccmniN /
#           展锐(Unisoc)seth_lteN 与新平台 sipa_ethN / 老三星展锐 seth_wN 等 / 通用 wwanN。
#           不含 v4-*(clat)、r_rmnet*(反向)、rmnet_ipa/mhi/usb*(物理聚合口)。
HNC_CELL_IFACE_ERE='^(rmnet_data[0-9]+|rmnet[0-9]+|ccmni[0-9]+|seth_[a-z]+[0-9]+|sipa_eth[0-9]+|wwan[0-9]+)$'
# 明确是 AP 的名字: MTK/Pixel ap0、双频桥接 ap_br_wlanX(Android 12+)、三星 swlan0、softap0
HNC_AP_IFACE_ERE='^(ap[0-9]*|ap_br_[a-z0-9_]+|softap[0-9]+|swlan[0-9]+)$'
# 可能是 AP 也可能是副 STA(STA+STA 双 Wi-Fi)的名字: 需要额外证据(无 default route)
HNC_AP_MAYBE_IFACE_ERE='^(wlan[1-9][0-9]*|wigig[0-9]+)$'
HNC_USB_TETHER_ERE='^(rndis[0-9]+|usb[0-9]+|ncm[0-9]+)$'
HNC_BT_TETHER_ERE='^bt-pan[0-9]*$'
HNC_ETH_IFACE_ERE='^eth[0-9]+$'
HNC_P2P_IFACE_ERE='^p2p'
# 永不作为热点/上游的虚拟口
HNC_IGNORE_IFACE_ERE='^(lo|dummy[0-9]*|v4-.*|tun[0-9]*|ifb[0-9]*|r_rmnet.*|rmnet_(ipa|mhi|usb).*|ip6tnl[0-9]*|sit[0-9]*|gre[0-9]*|gretap[0-9]*|erspan[0-9]*|ip_vti[0-9]*|ip6_vti[0-9]*|ip6gre[0-9]*|bond[0-9]*|umts_dm[0-9]*|clat.*)$'

# hnc_iface_class <name>  —— 一次 awk 完成(同一组 ERE 字符串, 不逐条 fork grep)
hnc_iface_class() {
    [ -n "$1" ] || { echo ignore; return; }
    printf '%s\n' "$1" | awk -v ig="$HNC_IGNORE_IFACE_ERE" -v ce="$HNC_CELL_IFACE_ERE" -v ap="$HNC_AP_IFACE_ERE" \
        -v am="$HNC_AP_MAYBE_IFACE_ERE" -v us="$HNC_USB_TETHER_ERE" -v bt="$HNC_BT_TETHER_ERE" \
        -v et="$HNC_ETH_IFACE_ERE" -v pp="$HNC_P2P_IFACE_ERE" '
        NR == 1 {
            if ($0 ~ ig) c = "ignore"; else if ($0 ~ ce) c = "cell"; else if ($0 ~ ap) c = "ap"
            else if ($0 ~ am) c = "ap_maybe"; else if ($0 == "wlan0") c = "wifi_sta"
            else if ($0 ~ us) c = "usb"; else if ($0 ~ bt) c = "bt"; else if ($0 ~ et) c = "eth"
            else if ($0 ~ pp) c = "p2p"; else c = "other"
            print c; exit }'
}

# Wi-Fi 类(可作为 Wi-Fi 热点口): ap / ap_maybe / wifi_sta(wlan0, 仅权威来源) / other
_hi_wifiish() {
    case "$(hnc_iface_class "$1")" in ap|ap_maybe|wifi_sta|other) return 0 ;; esac
    return 1
}

_hi_log() {
    [ -d "$HNC_DIR/logs" ] || return 0
    echo "[$(date '+%H:%M:%S' 2>/dev/null)] [IFACE] $*" >> "$_HI_LOG" 2>/dev/null || true
}

# 带超时执行(dumpsys 在系统服务卡死时会挂住)
_hi_to() {
    local t="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$t" "$@"
    else
        "$@"
    fi
}

_hi_is_private() {
    case "$1" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    esac
    return 1
}

_hi_exists() { [ -n "$1" ] && [ -e "$_HI_SYS_NET/$1" ]; }

_hi_is_up() {
    local f
    f=$(cat "$_HI_SYS_NET/$1/flags" 2>/dev/null) || return 1
    case "$f" in 0x*[!0-9a-fA-Fx]*|0x) return 1 ;; 0x*) ;; *[!0-9]*|'') return 1 ;; esac
    [ $(( f & 1 )) -eq 1 ] 2>/dev/null
}

# ─── 一次性采集(每次 detect 只 fork 一次 ip addr / ip route)──────────────────
# _HI_ADDR4: 每行 "<iface> <ipv4>"
_hi_collect() {
    _HI_ADDR4=$(ip -4 -o addr show 2>/dev/null | awk '
        { for (i = 1; i < NF; i++) if ($i == "inet") {
              n = $2; sub(/:$/, "", n); sub(/@.*/, "", n)
              a = $(i+1); sub(/\/.*/, "", a); print n, a; break } }')
    # 任意路由表里带 default route 的接口(STA / 蜂窝 / VPN)—— AP 口不会有
    _HI_DEFRT=$(ip route show table all 2>/dev/null | awk '
        $1 == "default" { for (i = 1; i < NF; i++) if ($i == "dev") print $(i+1) }' | sort -u | tr '\n' ' ')
    _HI_UPSTREAM=""
    local t r
    for t in 1.1.1.1 223.5.5.5 8.8.8.8; do
        r=$(ip route get "$t" 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }')
        [ -n "$r" ] && { _HI_UPSTREAM="$r"; break; }
    done
}

_hi_ipv4_of() {
    printf '%s\n' "$_HI_ADDR4" | awk -v n="$1" '$1 == n { print $2; exit }'
}
_hi_private_ipv4_of() {
    local a
    for a in $(printf '%s\n' "$_HI_ADDR4" | awk -v n="$1" '$1 == n { print $2 }'); do
        _hi_is_private "$a" && { echo "$a"; return 0; }
    done
    return 1
}
_hi_has_defrt() { case " $_HI_DEFRT " in *" $1 "*) return 0 ;; esac; return 1; }

_hi_neigh_count() {
    awk -v n="$1" 'NR > 1 && $6 == n && $3 != "0x0" && $4 != "00:00:00:00:00:00" { c++ } END { print c + 0 }' "$_HI_ARP" 2>/dev/null || echo 0
}

# 候选: 有私网 IPv4、非 ignore/蜂窝、无 default route
_hi_candidates() {
    local n c out=""
    for n in $(printf '%s\n' "$_HI_ADDR4" | awk '{ print $1 }' | sort -u); do
        c=$(hnc_iface_class "$n")
        case "$c" in ignore|cell) continue ;; esac
        _hi_has_defrt "$n" && continue
        _hi_private_ipv4_of "$n" >/dev/null || continue
        out="$out $n"
    done
    echo "${out# }"
}

# ─── 数据源解析 ───────────────────────────────────────────────────────────────
# 输出 "<iface> <State>" 行
_hi_tether_states() {
    local out
    out=$(_hi_to 5 dumpsys tethering 2>/dev/null)
    case "$out" in
        *"State - lastError"*|*"Tether state"*) ;;
        *) out=$(_hi_to 5 dumpsys connectivity tethering 2>/dev/null) ;;
    esac
    _HI_TETHER_RAW="$out"
    printf '%s\n' "$out" | awk '
        /^[[:space:]]*[A-Za-z0-9_.:@-]+ - [A-Za-z]+State/ {
            sub(/^[[:space:]]+/, ""); split($0, a, " - "); print a[1], a[2] }'
}

_hi_tether_upstream() {
    printf '%s\n' "$_HI_TETHER_RAW" | awk '
        /Current upstream interface/ {
            s = $0; sub(/.*:[[:space:]]*/, "", s); gsub(/[][,]/, " ", s)
            n = split(s, a, " ")
            for (i = 1; i <= n; i++) if (a[i] != "" && a[i] != "null" && a[i] !~ /^v4-/) { print a[i]; exit } }'
}

_hi_tetherctrl_ifaces() {
    iptables -t filter -L tetherctrl_FORWARD -n -v 2>/dev/null \
        | awk '$3 == "ACCEPT" && $6 != "*" && $6 != "" && $0 !~ /RELATED|ESTABLISHED/ { print $6 }'
}

_hi_softap_iface() {
    _hi_to 8 dumpsys wifi 2>/dev/null | awk '
        /mApInterfaceName[:=]/ { v = $0; sub(/.*mApInterfaceName[:=][[:space:]]*/, "", v); sub(/[[:space:],].*/, "", v)
            if (v != "" && v != "null") { print v; exit } }'
}

_hi_read_override() {
    local v=""
    if [ -f "$HNC_DIR/bin/hnc_json" ]; then
        v=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface 2>/dev/null) || v=""
    fi
    if [ -z "$v" ]; then
        v=$(sed -n 's/.*"hotspot_iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$HNC_DIR/data/rules.json" 2>/dev/null | head -n1)
    fi
    v=$(printf '%s' "$v" | tr -d '[:space:]')
    case "$v" in \"*\") v=${v#\"}; v=${v%\"} ;; esac
    case "$v" in auto|null) v="" ;; esac
    case "$v" in *[!A-Za-z0-9_.:-]*) v="" ;; esac
    echo "$v"
}

_hi_jlist() {
    local x out="" first=1
    for x in $1; do
        [ $first -eq 1 ] || out="$out,"
        out="$out\"$x\""; first=0
    done
    echo "[$out]"
}

# 候选签名: 热点开/关/换口都会改变它(get 用来判断缓存是否过期)
_hi_sig() {
    local n s=""
    for n in $1; do s="$s$n=$(_hi_ipv4_of "$n");"; done
    echo "${s}ov=$2"
}

# ─── 主探测 ───────────────────────────────────────────────────────────────────
# 设置 HI_IFACE HI_METHOD HI_AUTH, 写 run/iface_detect.json; 成功 return 0
hnc_iface_detect() {
    HI_IFACE=""; HI_METHOD=none; HI_AUTH=false
    local ov ov_state=none cands states="" tethered="" local_only="" wifi_t="" usb_t="" bt_t="" eth_t=""
    local n st c ip up upc best bestscore score
    _HI_TETHER_RAW=""
    _hi_collect
    cands=$(_hi_candidates)

    # 0. 用户偏好
    ov=$(_hi_read_override)
    if [ -n "$ov" ]; then
        if _hi_exists "$ov" && [ -n "$(_hi_ipv4_of "$ov")" ]; then
            ov_state=ok; HI_IFACE="$ov"; HI_METHOD=override; HI_AUTH=true
        else
            ov_state=invalid
        fi
    fi

    # 1. Tethering 服务(有候选才跑 dumpsys; 顺便收集 USB/BT/以太共享)
    if [ -n "$cands" ]; then
        states=$(_hi_tether_states)
        while read -r n st; do
            [ -n "$n" ] || continue
            c=$(hnc_iface_class "$n")
            case "$st" in
                TetheredState)
                    tethered="$tethered $n"
                    case "$c" in
                        usb) usb_t="$usb_t $n" ;;
                        bt) bt_t="$bt_t $n" ;;
                        eth) eth_t="$eth_t $n" ;;
                        p2p|ignore|cell) ;;
                        *) wifi_t="$wifi_t $n" ;;
                    esac ;;
                LocalHotspotState)
                    local_only="$local_only $n" ;;
            esac
        done <<EOF
$states
EOF
        # 未经 tethering 服务上报、但名字/地址明显是 USB/BT 共享的也记上
        for n in $cands; do
            c=$(hnc_iface_class "$n")
            case "$c" in
                usb) case " $usb_t " in *" $n "*) ;; *) usb_t="$usb_t $n" ;; esac ;;
                bt)  case " $bt_t " in *" $n "*) ;; *) bt_t="$bt_t $n" ;; esac ;;
            esac
        done
        if [ -z "$HI_IFACE" ]; then
            for n in $wifi_t $local_only; do
                _hi_wifiish "$n" || continue
                _hi_exists "$n" || continue
                [ -n "$(_hi_ipv4_of "$n")" ] || continue
                HI_IFACE="$n"; HI_METHOD=tethering; HI_AUTH=true; break
            done
        fi
    fi

    # 2. netd tetherctrl_FORWARD(旧实现同款, 不看 IPv4)
    if [ -z "$HI_IFACE" ]; then
        for n in $(_hi_tetherctrl_ifaces); do
            _hi_wifiish "$n" || continue
            [ "$n" = "$_HI_UPSTREAM" ] && continue
            _hi_has_defrt "$n" && continue
            HI_IFACE="$n"; HI_METHOD=tetherctrl; HI_AUTH=true; break
        done
    fi

    # 3. WifiService SoftApManager
    if [ -z "$HI_IFACE" ] && [ -n "$cands" ]; then
        n=$(_hi_softap_iface)
        if [ -n "$n" ] && _hi_wifiish "$n" && _hi_exists "$n" && [ -n "$(_hi_ipv4_of "$n")" ] \
           && ! _hi_has_defrt "$n"; then
            HI_IFACE="$n"; HI_METHOD=wifi_softap; HI_AUTH=true
        fi
    fi

    # 4. 启发式扫描
    if [ -z "$HI_IFACE" ] && [ -n "$cands" ]; then
        best=""; bestscore=0
        for n in $cands; do
            [ "$n" = "$_HI_UPSTREAM" ] && continue
            c=$(hnc_iface_class "$n")
            case "$c" in
                ap) score=30 ;;
                ap_maybe) score=20 ;;
                other) score=0 ;;
                *) continue ;;
            esac
            _hi_is_up "$n" || continue
            [ "$(_hi_neigh_count "$n")" -gt 0 ] 2>/dev/null && score=$((score + 10))
            # 名字不认识的接口必须有邻居才算(旧 ARP 法的兜底语义)
            [ "$score" -ge 10 ] || continue
            if [ "$score" -gt "$bestscore" ]; then best="$n"; bestscore=$score; fi
        done
        [ -n "$best" ] && { HI_IFACE="$best"; HI_METHOD=scan; HI_AUTH=false; }
    fi

    # 非权威来源绝不返回 wlan0
    if [ "$HI_IFACE" = wlan0 ] && [ "$HI_AUTH" != true ]; then
        HI_IFACE=""; HI_METHOD=none
    fi

    ip=""; [ -n "$HI_IFACE" ] && ip=$(_hi_private_ipv4_of "$HI_IFACE" || _hi_ipv4_of "$HI_IFACE")
    up="$_HI_UPSTREAM"
    n=$(_hi_tether_upstream); [ -n "$n" ] && up="$n"
    upc=""
    if [ -n "$up" ]; then
        case "$(hnc_iface_class "${up#v4-}")" in
            cell) upc=cell ;; wifi_sta|ap_maybe) upc=wifi ;; eth) upc=eth ;; usb) upc=usb ;; *) upc=other ;;
        esac
    fi
    local wl0=false; [ "$HI_IFACE" = wlan0 ] && wl0=true

    mkdir -p "$_HI_RUN" 2>/dev/null
    printf '{"schema":1,"ts":%s,"iface":"%s","method":"%s","authoritative":%s,"ipv4":"%s","wlan0_ap":%s,"override":"%s","override_state":"%s","tethered":%s,"local_only":%s,"wifi_tether":%s,"usb_tether":%s,"bt_tether":%s,"eth_tether":%s,"upstream":"%s","upstream_class":"%s","candidates":%s,"sig":"%s","scope_note":"limits apply to the Wi-Fi hotspot iface only; USB/BT/Ethernet tethering clients are reported but not managed"}\n' \
        "$(date +%s 2>/dev/null || echo 0)" "$HI_IFACE" "$HI_METHOD" "$HI_AUTH" "$ip" "$wl0" "$ov" "$ov_state" \
        "$(_hi_jlist "$tethered")" "$(_hi_jlist "$local_only")" "$(_hi_jlist "$wifi_t")" "$(_hi_jlist "$usb_t")" \
        "$(_hi_jlist "$bt_t")" "$(_hi_jlist "$eth_t")" "$up" "$upc" "$(_hi_jlist "$cands")" "$(_hi_sig "$cands" "$ov")" \
        > "$_HI_JSON.tmp.$$" 2>/dev/null && mv -f "$_HI_JSON.tmp.$$" "$_HI_JSON" 2>/dev/null

    if [ -n "$HI_IFACE" ]; then
        if [ "$(head -n1 "$_HI_RUN/hotspot_iface" 2>/dev/null)" != "$HI_IFACE" ]; then
            echo "$HI_IFACE" > "$_HI_RUN/hotspot_iface.tmp.$$" 2>/dev/null && mv -f "$_HI_RUN/hotspot_iface.tmp.$$" "$_HI_RUN/hotspot_iface" 2>/dev/null
            _hi_log "hotspot iface -> $HI_IFACE (method=$HI_METHOD usb=[${usb_t# }] bt=[${bt_t# }] upstream=$up)"
        fi
        [ "$HI_IFACE" != wlan0 ] && echo "$HI_IFACE" > "$_HI_RUN/iface.cache" 2>/dev/null
        return 0
    fi
    return 1
}

_hi_json_field() {
    sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" "$_HI_JSON" 2>/dev/null | head -n1
}

# 带缓存的读取: TTL 内、候选签名未变、接口仍有 IPv4(或为 tetherctrl 结果)→ 直接用
hnc_iface_get() {
    local ts now iface sig method cands
    if [ -f "$_HI_JSON" ]; then
        ts=$(sed -n 's/.*"ts":\([0-9]*\).*/\1/p' "$_HI_JSON" 2>/dev/null | head -n1)
        now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$ts" ] && [ $((now - ts)) -ge 0 ] && [ $((now - ts)) -lt "$_HI_TTL" ]; then
            iface=$(_hi_json_field iface)
            sig=$(_hi_json_field sig)
            method=$(_hi_json_field method)
            _hi_collect
            cands=$(_hi_candidates)
            if [ "$sig" = "$(_hi_sig "$cands" "$(_hi_read_override)")" ]; then
                if [ -z "$iface" ]; then
                    return 1
                fi
                if [ -n "$(_hi_ipv4_of "$iface")" ] || [ "$method" = tetherctrl ]; then
                    echo "$iface"
                    return 0
                fi
            fi
        fi
    fi
    hnc_iface_detect && echo "$HI_IFACE"
}

hnc_iface_invalidate() { rm -f "$_HI_JSON" 2>/dev/null; return 0; }

if [ "${HNC_IFACE_LIB:-0}" != 1 ]; then
    case "${1:-get}" in
        detect) hnc_iface_detect && echo "$HI_IFACE" ;;
        get) hnc_iface_get ;;
        info) hnc_iface_get >/dev/null; cat "$_HI_JSON" 2>/dev/null ;;
        invalidate) hnc_iface_invalidate ;;
        upstream)
            _hi_collect
            [ -n "$_HI_UPSTREAM" ] || exit 1
            echo "$_HI_UPSTREAM $(hnc_iface_class "${_HI_UPSTREAM#v4-}")" ;;
        classify) hnc_iface_class "$2" ;;
        patterns)
            echo "cell=$HNC_CELL_IFACE_ERE"; echo "ap=$HNC_AP_IFACE_ERE"; echo "ap_maybe=$HNC_AP_MAYBE_IFACE_ERE"
            echo "usb=$HNC_USB_TETHER_ERE"; echo "bt=$HNC_BT_TETHER_ERE"; echo "ignore=$HNC_IGNORE_IFACE_ERE" ;;
        *) echo "usage: $0 detect|get|info|invalidate|upstream|classify <iface>|patterns" >&2; exit 2 ;;
    esac
fi
