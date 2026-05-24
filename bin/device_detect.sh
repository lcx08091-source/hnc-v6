#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
# rc15: 追加 /data/local/hnc/bin —— device_detect.sh 是常驻 daemon 循环(while true),
# /system/bin 被卸时裸命令(awk/grep/sleep...)要能 fallthrough 到 /data 预置副本。
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
# device_detect.sh — HNC 设备检测（C daemon 代理 + shell 兜底）
#
# 【增量重构 v2.5.4 → v3.0.0】
# ✅ 保留全部对外接口：scan | daemon | list | iface | status
# 🔄 scan:   SIGUSR1 → C daemon → shell ARP fallback
# 🔄 daemon: 启动 hotspotd(C) → 失败则 shell 轮询 fallback
# 🔄 list:   socket GET_DEVICES → cat 文件 fallback
# ✅ iface:  完全不变
# 输出格式与原 shell 版本 100% 兼容
#
# ════════════════════════════════════════════════════════════════════
# ✅ v3.5.0+ hotspotd C daemon 状态:已启用,生产可用
# ════════════════════════════════════════════════════════════════════
# v3.4.x LTS 期 hotspotd 是实验性的(P0-4 / P1-2 / P1-7 / P1-8 都没修),
# 当时建议不要启用。v3.5.0-beta1 修了所有已知 bug,真机验证通过:
#
#   ✅ P0-4 修复:hotspotd 现在调 lookup_manual_name + try_mdns_resolve,
#                hostname 解析跟 shell 路径完全一致(优先级 manual > mdns > mac)
#   ✅ P1-2 修复:watchdog.sh 用 -d 参数重启 hotspotd
#   ✅ P1-7 修复:write_json 用 fread(16384) 读黑名单,30+ 设备不再截断
#   ✅ P1-8 修复:Device struct 加 hostname_src 字段,MAC 兜底对齐 shell 算法
#   ✅ v3.5.0-rc R-1 修复:nl_process 加 1s de-bounce,合并连续 netlink 事件
#   ✅ v3.5.0-rc R-2 修复:resolve_hostname 60s 时间窗口,改名后 60s 内自动生效
#
# 真机验证(RMX5010 SD8 Elite / Android 16 / kernel 6.6.102 / SukiSU):
#   - hotspotd 稳定运行(无 crash / 无 OOM / 无 SELinux deny)
#   - netlink RTMGRP_NEIGH 在新内核工作正常
#   - resolve_hostname 全部 4 个测试用例(mac/manual/mdns/rename)通过
#
# v3.5.0+ 默认启用 hotspotd(如果 binary 存在)。Shell daemon 仍是 fallback,
# 但实测情况:hotspotd 一旦启动就不会回退到 shell。
# ════════════════════════════════════════════════════════════════════

HNC_DIR=${HNC_DIR:-/data/local/hnc}
DEVICES_FILE=$HNC_DIR/data/devices.json
RULES_FILE=$HNC_DIR/data/rules.json
LOG=$HNC_DIR/logs/detect.log
HOTSPOTD_BIN=$HNC_DIR/bin/hotspotd
HOTSPOTD_PID=$HNC_DIR/run/hotspotd.pid
HOTSPOTD_SOCK=$HNC_DIR/run/hotspotd.sock
CACHE_FILE=$HNC_DIR/run/hostname_cache

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [DETECT] $1" >> "$LOG" 2>/dev/null || true
}

# C daemon 是否在线
hotspotd_alive() {
    local pid
    pid=$(cat "$HOTSPOTD_PID" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# UNIX socket 查询
socket_query() {
    local cmd=$1
    if command -v socat >/dev/null 2>&1; then
        echo "$cmd" | socat -t 2 - UNIX-CONNECT:"$HOTSPOTD_SOCK" 2>/dev/null
    elif command -v nc >/dev/null 2>&1; then
        echo "$cmd" | nc -U "$HOTSPOTD_SOCK" 2>/dev/null
    else
        cat "$DEVICES_FILE" 2>/dev/null
    fi
}

# ── 热点接口检测 ─────────────────────────────────────────────
# v3.4.1 修复：之前优先用 /proc/net/arp，但当热点没开 / 没设备连接时
# ARP 表为空，会降级遍历 /sys/class/net/ 匹配到手机本机 WiFi 接口
# wlan0（不是热点！），导致 HNC 在错误的接口上跑 init_tc 污染本机网络。
#
# 新方案：优先读 Android tetherctrl_FORWARD iptables 链。Android tethering
# 服务会自动维护这个链，包含 `-i <hotspot_iface> -o <upstream_iface> -j ACCEPT`
# 这样的规则。第一个 in 接口就是当前热点接口，这是绝对准确的。
# tetherctrl 链不存在或为空时再降级到旧的 ARP / 接口扫描方法。
get_hotspot_iface() {
    # 方法 1：tetherctrl iptables 链（最准确，只要热点开着就有）
    # 必须用 -v 才有接口列。awk 字段：$3=target $6=in_iface $7=out_iface
    local tc_iface
    tc_iface=$(iptables -t filter -L tetherctrl_FORWARD -n -v 2>/dev/null \
        | awk '$3 == "ACCEPT" && $6 != "*" && $6 !~ /^(lo|rmnet|dummy|v4-|tun|p2p)/ { print $6; exit }')
    [ -n "$tc_iface" ] && echo "$tc_iface" && return

    # 方法 2：ARP 表（热点开但 tetherctrl 链不存在的旧设备）
    local arp_iface
    arp_iface=$(awk '
        NR>1 && $3!="0x0" && $6!~/^(lo|rmnet|dummy|v4-|tun|p2p|wlan0$)/ {cnt[$6]++}
        END {for(k in cnt) print cnt[k], k}
    ' /proc/net/arp 2>/dev/null | sort -rn | awk '{print $2}' | head -1)
    [ -n "$arp_iface" ] && echo "$arp_iface" && return

    # 方法 3：常见接口名扫描（不含 wlan0，避免命中本机 WiFi）
    for iface in ap0 wlan1 wlan2 wlan3 wlan4 swlan0 swlan1 rndis0 usb0; do
        ip addr show "$iface" 2>/dev/null | grep -q 'inet ' && echo "$iface" && return
    done

    # 方法 4：兜底扫 /sys/class/net/，但严格排除 wlan0
    for iface in $(ls /sys/class/net/ 2>/dev/null | grep -E '^(wlan[1-9]|ap[0-9]|swlan)'); do
        ip addr show "$iface" 2>/dev/null | grep -q 'inet ' && echo "$iface" && return
    done

    # 真的什么都找不到时返回空，让上层处理
    # （v3.4.1：不再返回 wlan0 兜底，因为 wlan0 是本机 WiFi 不是热点）
    return 1
}

# ── scan via C daemon (SIGUSR1) ─────────────────────────────
do_scan_via_daemon() {
    local pid
    pid=$(cat "$HOTSPOTD_PID" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
    # rc3.1.34 修 #13: 之前 SIGUSR1 后无条件 return 0, 即使 hotspotd 卡死 (主循环
    # block 在 mdns_worker stop / mdns_resolve / 文件 IO) signal handler 能注册
    # 但 g_need_scan=1 不被处理 → devices.json 永远不更新. 调用方
    # `do_scan_via_daemon || do_scan_shell` 永远走 daemon 分支 → shell fallback
    # 永不接管. 修法: SIGUSR1 后 stat devices.json mtime 比对, 1 秒内未刷新视为
    # daemon 卡死, return 1 让 caller fallback. 注意 `sleep 1` 不能完全保证
    # daemon 来得及响应, 但绝大多数正常场景 hotspotd write_json 是 ms 级.
    local before_mtime
    before_mtime=$(stat -c %Y "$DEVICES_FILE" 2>/dev/null || echo 0)
    kill -USR1 "$pid" 2>/dev/null
    sleep 1
    local after_mtime
    after_mtime=$(stat -c %Y "$DEVICES_FILE" 2>/dev/null || echo 0)
    if [ "$after_mtime" -le "$before_mtime" ]; then
        log "scan via SIGUSR1: daemon did not update devices.json (likely stuck), falling back"
        return 1
    fi
    local cnt
    cnt=$(awk 'BEGIN{n=0} /"mac"/{n++} END{print n}' "$DEVICES_FILE" 2>/dev/null || echo 0)
    log "scan via SIGUSR1: ${cnt} device(s)"
    echo "$cnt"
    return 0
}

# ── hostname 缓存 (TTL=600s) ────────────────────────────────
hostname_cached() {
    local mac=$1 now
    now=$(date +%s)
    [ -f "$CACHE_FILE" ] || return 1
    # Fix #6: cache uses '|' delimiter, must specify -F'|'
    awk -F'|' -v mac="$mac" -v now="$now" '
        $1==mac && (now-$3)<600 { print $2; found=1; exit }
        END { if(!found) exit 1 }
    ' "$CACHE_FILE" 2>/dev/null
}

hostname_cache_set() {
    local mac=$1 name=$2 now
    now=$(date +%s)
    [ -z "$name" ] && return
    mkdir -p "$(dirname "$CACHE_FILE")"
    if [ -f "$CACHE_FILE" ]; then
        grep -v "^$mac|" "$CACHE_FILE" > ${CACHE_FILE}.tmp 2>/dev/null || true
        echo "$mac|$name|$now" >> ${CACHE_FILE}.tmp
        mv ${CACHE_FILE}.tmp "$CACHE_FILE"
    else
        echo "$mac|$name|$now" > "$CACHE_FILE"
    fi
}

# v3.4.11 兼容 #2: 探测 mdns_resolve 是否能在当前 CPU 架构上跑
# bin/mdns_resolve 只编译了 aarch64,armv7/x86_64 设备执行会 "exec format error"
# 用 -h 跑一次(立刻 exit,不发任何 UDP 包),exit code 0 = 能跑,非 0 = 架构不兼容
# 结果缓存到 $HNC_DIR/run/.mdns_ok 文件,后续不再探测
_mdns_usable() {
    local probe="$HNC_DIR/run/.mdns_probe"
    if [ -f "$probe" ]; then
        # 缓存命中
        [ "$(cat "$probe" 2>/dev/null)" = "ok" ]
        return
    fi
    # 首次探测
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    if [ ! -x "$HNC_DIR/bin/mdns_resolve" ]; then
        echo "no" > "$probe"
        return 1
    fi
    # 跑一次 -h(只输出 usage,不发包,不阻塞),只看是否能 exec 成功
    "$HNC_DIR/bin/mdns_resolve" -h >/dev/null 2>&1
    local rc=$?
    # exec format error 通常 exit 126,正常 -h 通常 exit 0 或 1
    # 任何能成功 fork+exec 的(rc < 126)都算可用
    if [ $rc -lt 126 ]; then
        echo "ok" > "$probe"
        log "mdns_resolve compatible (rc=$rc)"
        return 0
    else
        echo "no" > "$probe"
        log "mdns_resolve incompatible (rc=$rc), arch mismatch likely"
        return 1
    fi
}

get_hostname() {
    local ip=$1 mac=$2 name=""

    # v3.7.0: 优先级链 (高 → 低):
    #   1. 手动命名 (data/device_names.json,用户说了算)
    #   2. 已缓存的发现结果 (10 分钟 TTL,避免每次扫描都跑 mDNS)
    #   3. dumpsys network_stack DHCP (★ v3.7 新增,最可靠的 hostname 源)
    #      - Android 14+ 的 NetworkStack 把所有 DHCP 事件记录到 ring buffer
    #      - 从 logs 里提取 DhcpAckPacket/Offering 行的 hostname 字段
    #      - Windows/小米/华为等 OEM ROM 的设备会发 option 12,100% 命中
    #      - 原生 Android (Pixel) 不发 option 12,此路径失败降级到 mDNS
    #      - 不需要 root 特权,普通 dumpsys 就能看到
    #      - 35ms 耗时 / 16 KB 输出,可以每次 scan 都调
    #   4. mDNS 主动发现 (bin/mdns_resolve unicast + multicast)
    #   5. dnsmasq leases (在 ColorOS 上为空,但 LineageOS/原生 Android 有用)
    #   6. (调用方 fallback) MAC 后 8 位

    # 1. 手动命名
    local manual
    manual=$(sh "$HNC_DIR/bin/json_set.sh" name_get "$mac" 2>/dev/null)
    if [ -n "$manual" ]; then
        echo "$manual|manual"
        return
    fi

    # 2. 缓存
    local cached
    cached=$(hostname_cached "$mac") && {
        # 缓存里也存了来源标记 (cache 文件 v3.4.6 升级:第二个字段可能是
        # "name|src",兼容旧格式 "name")
        case "$cached" in
            *\|*) echo "$cached" ;;
            *)    echo "$cached|cache" ;;
        esac
        return
    }

    # 3. v3.7.0: dumpsys network_stack DHCP hostname
    # ───────────────────────────────────────────────
    # 格式示例:
    #   2026-04-13T16:43:31 - [wlan2.DHCP.Repository] Offering new generated lease
    #     clientId: 017AD6F7CEBA76, hwAddr: 7a:d6:f7:ce:ba:76, netAddr: 10.201.76.69/24,
    #     expTime: 4968921,hostname: Mi-10
    #
    # grep 策略:
    #   - 按 "hwAddr: <MAC>" 匹配对应设备
    #   - tail -1 取最新一条(ring buffer 按时间排序,越晚越靠后)
    #   - sed 提取 "hostname: ..." 到行尾
    local ns_name
    ns_name=$(dumpsys network_stack 2>/dev/null | \
              grep -iE "hwAddr: *$mac.*hostname: " | \
              tail -1 | \
              sed -E 's/.*hostname: //; s/ *$//')
    if [ -n "$ns_name" ]; then
        hostname_cache_set "$mac" "$ns_name|dhcp"
        echo "$ns_name|dhcp"
        return
    fi

    # 4. mDNS 主动发现
    # v3.4.11 兼容 #2:不仅检查文件可执行,还检查 CPU 架构兼容性
    # mdns_resolve 只编译了 aarch64,armv7/x86_64 设备执行会 "exec format error"
    # _mdns_usable() 首次调用时探测并缓存结果,后续直接读
    if _mdns_usable && [ -n "$ip" ]; then
        local mdns_name
        mdns_name=$("$HNC_DIR/bin/mdns_resolve" -t 800 "$ip" 2>/dev/null)
        if [ -n "$mdns_name" ]; then
            hostname_cache_set "$mac" "$mdns_name|mdns"
            echo "$mdns_name|mdns"
            return
        fi
    fi

    # 5. dnsmasq leases (legacy,ColorOS 上为空)
    for f in /data/misc/dhcp/dnsmasq.leases \
              /data/vendor/dhcp/dnsmasq.leases \
              /data/misc/wifi/hostapd/dnsmasq.leases \
              /data/misc/wifi/dnsmasq.leases; do
        [ -f "$f" ] || continue
        name=$(awk -v m="$mac" '
            { ref=tolower(m); gsub(/:/,"",ref)
              cur=tolower($2); gsub(/:/,"",cur)
              if(cur==ref && $4!="*" && $4!="") {print $4; exit} }
        ' "$f" 2>/dev/null)
        [ -n "$name" ] && break
    done
    if [ -n "$name" ]; then
        hostname_cache_set "$mac" "$name|dhcp"
        echo "$name|dhcp"
        return
    fi

    # 6. 没有结果,调用方处理 fallback
    echo ""
}

# ── shell ARP 直读扫描（C daemon 不可用时的兜底）────────────
# v3.4.4：扫描完成后从 iptables HNC_STATS 链拿真实 rx/tx 字节,
# 替代 v3.4.3 之前硬编码的 0。
# v3.4.6：get_hostname 改成返回 "name|src" 格式,临时文件多一列
# 存 hostname_src,最终写入 devices.json 的 hostname_src 字段供
# WebUI 显示来源图标(✏️ manual / 🔍 mdns / 📡 dhcp / 无 mac)。
#
# 流程:
#   (1) 第一遍扫 ARP,把每个设备的基础 info(含 hostname + 来源)暂存
#   (2) 收集到的 IP 列表全部 ensure_stats(已有则幂等跳过)
#   (3) 一次性 stats_all 拿所有 IP 的字节计数(O(1) iptables 调用)
#   (4) 第三遍读临时文件 + stats 数据组装最终 JSON
#
# 注意:第三遍循环里复用第一遍设的 $ts(扫描开始时间戳),所有
# 设备共享同一个 last_seen — 这是有意的,反映"本次扫描时刻"。
do_scan_shell() {
    local ts iface gw pfx rules blacklist
    ts=$(date +%s)
    rules=$(cat "$RULES_FILE" 2>/dev/null || echo '{}')
    blacklist=$(echo "$rules" | grep -o '"blacklist":\[[^]]*\]' | \
        grep -oE '"[0-9a-fA-F:]{17}"' | tr -d '"' | tr 'A-Z' 'a-z')
    # rc3.1.34 修 #12: 之前正则只匹小写 [0-9a-f], 但用户/外部脚本写 blacklist 时
    # 可能用大写 (json_set.sh bl_add 内部 lowercase 但手动编辑 rules.json /
    # 第三方导入数据可能保留大写). 大写 MAC 在 grep 阶段直接漏判 → blacklist
    # 集合不含此 MAC → 下面 line 356 grep "^$mac$" 永远 fail → status=allowed →
    # iptables 规则在 (因为 apply_device_rule.sh bl_add 自己 lower 后挂规则)
    # 但 UI 显示"未封锁" → split-brain. 现在 case-insensitive grep + tr 统一小写.

    iface=$(get_hotspot_iface 2>/dev/null)
    gw=$(ip addr show "$iface" 2>/dev/null | \
        awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    [ -n "$gw" ] && {
        local pfx
        pfx=$(echo "$gw" | cut -d. -f1-3)
        ping -b -c 1 -W 1 "${pfx}.255" >/dev/null 2>&1 &
    }

    # 临时文件:每行存 ip|mac|hn|hn_src|dev|status
    local TMP="$HNC_DIR/run/scan_tmp.$$"
    # v3.4.11 P1-6 修复:第二个临时文件存 ARP 扫描结果
    # 之前用 `done <<EOF $(awk ...) EOF`,某些 busybox ash 实现会把整个 while 跑在 subshell,
    # 导致循环外 count=0 / online_ips="" → 第二遍 ensure_stats 跳过 → 流量数据全 0
    # 改用临时文件 + `done < "$ARP_TMP"`,POSIX 保证文件重定向不创建 subshell
    local ARP_TMP="$HNC_DIR/run/scan_arp.$$"
    mkdir -p "$HNC_DIR/run" 2>/dev/null
    : > "$TMP"
    # v3.5.0 P2-3: 进程异常退出时清理临时文件,避免 /run 累积垃圾
    # v3.6.1 P1-shellrace: 加 devices.json.tmp.$$ 清理(以防 printf/mv 之间死亡)
    trap 'rm -f "$TMP" "$ARP_TMP" "${TMP}.newmacs" "${TMP}.oldblocks" "${DEVICES_FILE}.tmp.$$" 2>/dev/null' EXIT INT TERM

    # v5.3.0-rc9 P1: strict ARP scan whitelist.
    # Only accept entries on the currently detected hotspot iface. The old
    # blacklist filter could accidentally include upstream/USB/non-hotspot ARP
    # entries and expose them as controllable hotspot clients.
    if [ -n "$iface" ]; then
        awk -v want="$iface" 'NR>1 && $3!="0x0" && $4!="00:00:00:00:00:00" && $1~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $6==want {print $1"|"$4"|"$6}' /proc/net/arp 2>/dev/null > "$ARP_TMP"
    else
        : > "$ARP_TMP"
    fi

    local count=0
    local online_ips=""

    # ── 第一遍:扫 ARP,生成基础 device info ──
    # 用 < "$ARP_TMP" 而不是 <<EOF $(...) EOF,确保 while 在当前 shell 跑(变量不丢)
    while IFS='|' read -r ip mac dev; do
        [ -z "$ip" ] && continue
        mac=$(echo "$mac" | tr 'A-Z' 'a-z')
        count=$((count+1))
        online_ips="$online_ips $ip"

        # v3.4.6: get_hostname 返回 "name|src",空字符串表示 fallback
        local hn_raw hn hn_src
        hn_raw=$(get_hostname "$ip" "$mac")
        if [ -n "$hn_raw" ]; then
            # 拆分 name|src
            hn=${hn_raw%|*}
            hn_src=${hn_raw##*|}
        else
            hn=""
            hn_src=""
        fi
        # 兜底:MAC 后 8 位
        if [ -z "$hn" ]; then
            hn=$(echo "$mac" | tr -d ':' | tail -c 9)
            hn_src="mac"
        fi

        local status="allowed"
        echo "$blacklist" | grep -q "^$mac$" && status="blocked"

        printf '%s|%s|%s|%s|%s|%s\n' "$ip" "$mac" "$hn" "$hn_src" "$dev" "$status" >> "$TMP"
    done < "$ARP_TMP"
    rm -f "$ARP_TMP"

    # ── 第二遍:同步 stats 链 + 一次性读所有字节计数 ──
    local stats_data=""
    if [ "$count" -gt 0 ]; then
        for ip in $online_ips; do
            sh "$HNC_DIR/bin/iptables_manager.sh" ensure_stats "$ip" >/dev/null 2>&1
        done
        stats_data=$(sh "$HNC_DIR/bin/iptables_manager.sh" stats_all 2>/dev/null)
    fi

    # ── 第三遍:用 stats 数据填充 rx_bytes/tx_bytes,组装最终 JSON ──
    # ts 沿用第一遍的扫描开始时间戳(所有设备共享同一 last_seen)
    local json="{" first=1
    while IFS='|' read -r ip mac hn hn_src dev status; do
        [ -z "$ip" ] && continue
        local rx=0 tx=0
        if [ -n "$stats_data" ]; then
            local line
            line=$(echo "$stats_data" | awk -v i="$ip" '$1==i {print $2" "$3; exit}')
            if [ -n "$line" ]; then
                rx=$(echo "$line" | cut -d' ' -f1)
                tx=$(echo "$line" | cut -d' ' -f2)
                [ -z "$rx" ] && rx=0
                [ -z "$tx" ] && tx=0
            fi
        fi
        # JSON 转义 hostname(中文/特殊字符)
        # v3.4.11 P0-5 修复:加 tr -d '\000-\037' 去掉所有 0x00-0x1f 控制字符。
        # mDNS PTR label 协议层允许任意字节,含 \n 会破坏 JSON,
        # 让 JSON.parse 失败 → 整个设备列表清空。
        local hn_json
        hn_json=$(printf '%s' "$hn" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')
        [ $first -eq 0 ] && json="$json,"
        json="${json}\"${mac}\":{\"ip\":\"$ip\",\"mac\":\"$mac\",\"hostname\":\"$hn_json\",\"hostname_src\":\"$hn_src\",\"iface\":\"$dev\",\"rx_bytes\":$rx,\"tx_bytes\":$tx,\"status\":\"$status\",\"last_seen\":$ts}"
        first=0
    done < "$TMP"

    # v5.3.0-rc8 P0: tolerant merge for recently-seen devices.
    # ARP entries can be garbage-collected while iptables/tc rules and user UI
    # expectations are still valid. Preserve devices seen within GRACE_SEC as
    # status=stale so daemon actions can still resolve the MAC/device entry.
    local GRACE_SEC=180
    if [ -f "$DEVICES_FILE" ]; then
        awk -F'|' '{print tolower($2)}' "$TMP" 2>/dev/null | sort -u > "${TMP}.newmacs"
        grep -oE '"[0-9a-fA-F:]{17}":\{[^}]*"last_seen":[0-9]+[^}]*\}' "$DEVICES_FILE" 2>/dev/null \
            > "${TMP}.oldblocks" || : > "${TMP}.oldblocks"
        if [ -s "${TMP}.oldblocks" ]; then
            while IFS= read -r block; do
                [ -z "$block" ] && continue
                local old_mac old_ls age entry_body
                old_mac=$(printf '%s' "$block" | grep -oE '^"[0-9a-fA-F:]{17}"' | tr -d '"' | tr 'A-Z' 'a-z')
                [ -z "$old_mac" ] && continue
                old_ls=$(printf '%s' "$block" | grep -oE '"last_seen":[0-9]+' | grep -oE '[0-9]+$')
                [ -z "$old_ls" ] && continue
                age=$(( ts - old_ls ))
                [ "$age" -lt 0 ] && continue
                [ "$age" -gt "$GRACE_SEC" ] && continue
                if grep -qx "$old_mac" "${TMP}.newmacs" 2>/dev/null; then
                    continue
                fi
                entry_body=$(printf '%s' "$block" | sed 's/^"[0-9a-fA-F:]\{17\}"://')
                entry_body=$(printf '%s' "$entry_body" | sed 's/"status":"[^"]*"/"status":"stale"/')
                [ $first -eq 0 ] && json="$json,"
                json="${json}\"${old_mac}\":${entry_body}"
                first=0
            done < "${TMP}.oldblocks"
        fi
        rm -f "${TMP}.oldblocks" "${TMP}.newmacs" 2>/dev/null
    fi
    json="${json}}"

    rm -f "$TMP" "${TMP}.oldblocks" "${TMP}.newmacs" 2>/dev/null
    # v3.6.1 P1-shellrace 修复:用带 PID 后缀的 tmp 文件,避免多个 shell scan
    # 并发时对 devices.json.tmp 字节级竞争写入导致 JSON 字段错位。
    #
    # 真实事故(2026-04-13):用户点"释放所有资源"后,hotspotd 被 cleanup 杀掉,
    # WebUI 在 90 秒内多次触发 device_detect.sh scan(人为快速点"刷新" 或 WebUI
    # 自动 doRefresh 触发 shell fallback 路径)。几次 scan 的执行窗口重叠,
    # 两个 printf > devices.json.tmp 并发 write 字节交错,产生看似合法但字段
    # 错位的 JSON,例如 "iface":"","status":"wlan2|allowed"(iface 变空串,
    # status 吃掉了 wlan2 + | + allowed 的拼接)。
    #
    # hotspotd.c v3.5.2 P0-A 的 DEVICES_TMP_FMT 已经用 "devices.json.tmp.%d"
    # 格式(带 PID 后缀,作为纵深防御),shell 侧应该对齐。
    #
    # $$ 是当前 shell 的 PID,每个 scan 子进程唯一。mv 是原子操作(kernel 保证
    # rename 的原子性),所以谁后 mv 谁赢,但至少每个 tmp 文件本身是完整的 JSON。
    local tmp_out="${DEVICES_FILE}.tmp.$$"
    printf '%s' "$json" > "$tmp_out" && mv "$tmp_out" "$DEVICES_FILE"
    log "shell scan: $count device(s)"
    echo "$count"
}

# ── 热点状态 / Doze 检测 ─────────────────────────────────────
is_hotspot_up() {
    local iface
    iface=$(get_hotspot_iface)
    ip addr show "$iface" 2>/dev/null | grep -q 'inet '
}

is_doze_mode() {
    cmd power get-idle-mode 2>/dev/null | grep -qiE "^deep$|^light$" && return 0
    local lvl
    lvl=$(dumpsys battery 2>/dev/null | awk '/level:/{print $2}')
    [ -n "$lvl" ] && [ "$lvl" -lt 5 ] 2>/dev/null && return 0
    return 1
}

arp_hash() {
    awk 'NR>1 && $3!="0x0" {print $1,$4,$6}' /proc/net/arp 2>/dev/null | \
        md5sum | awk '{print $1}'
}

# ── Shell 轮询兜底 (只在 hotspotd 不可用时运行) ─────────────
daemon_shell_fallback() {
    log "=== Shell daemon fallback started (PID=$$) ==="
    echo $$ > "$HNC_DIR/run/detect.pid"
    [ -f "$DEVICES_FILE" ] || echo '{}' > "$DEVICES_FILE"

    local last_count=-1 last_hash="" interval=60 no_ap_rounds=0

    while true; do
        if is_doze_mode; then
            interval=120; sleep $interval; continue
        fi

        if ! is_hotspot_up; then
            no_ap_rounds=$((no_ap_rounds+1))
            if [ "$last_count" -gt 0 ] || [ "$last_count" = "-1" ]; then
                echo '{}' > "$DEVICES_FILE"; last_count=0; log "Hotspot down"
            fi
            [ "$no_ap_rounds" -gt 5 ] && interval=60 || interval=15
            sleep $interval; continue
        fi
        no_ap_rounds=0

        local cur_hash need_scan=0
        cur_hash=$(arp_hash)
        # v3.3.0：原逻辑 `[ last_count > 0 ] && need_scan=1` 让 arp_hash
        # 缓存在有设备时完全失效，每 8 秒强制重扫但 shell 扫描并不抓
        # 流量字节数（rx/tx 都写 0），纯粹浪费 CPU。移除。
        [ "$cur_hash" != "$last_hash" ] && need_scan=1
        [ "$last_count" = "-1" ]        && need_scan=1

        if [ "$need_scan" = "1" ]; then
            local count
            count=$(do_scan_shell)
            last_hash=$(arp_hash)
            if [ "$count" -gt 0 ]; then
                interval=8
                [ "$count" != "$last_count" ] && log "Devices: $last_count -> $count"
            else
                interval=30
                [ "$last_count" -gt 0 ] && log "All devices gone"
            fi
            last_count=$count
        fi
        sleep $interval
    done
}

# ── daemon 模式：优先 C daemon ──────────────────────────────
daemon_mode() {
    log "=== Daemon mode starting ==="

    # v3.5.2 P0-A 修复:daemon spawn 锁防止并发启动两个 hotspotd
    # (watchdog 重启 hotspotd 的同时,如果 device_detect.sh daemon 也被 spawn,
    #  两个 path 会各自启动一个 hotspotd 实例,导致 unix socket bind 冲突
    #  + pid 文件互相覆盖 + devices.json 损坏)
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
    # v3.6 T4: 不用 trap 释放锁,因为 ash 下 trap + rmdir 组合在 SIGKILL 不可靠。
    # 依赖上面 10 秒 force-break 兜底。所有正常路径(return 0 / daemon_shell_fallback
    # 进入前)都会手动 rmdir SPAWNLOCK。

    if [ -x "$HOTSPOTD_BIN" ]; then
        log "Starting C daemon: $HOTSPOTD_BIN"
        # -d: 后台化（自己 fork），写 PID 到 HOTSPOTD_PID
        "$HOTSPOTD_BIN" -d -l "$HNC_DIR/logs/hotspotd.log"
        sleep 2
        if hotspotd_alive; then
            log "C daemon running (PID=$(cat $HOTSPOTD_PID 2>/dev/null))"
            # C daemon 已接管，本进程可退出
            # v3.5.2 P0-A:释放 spawn 锁,让后续 watchdog 重启操作可以进入
            rmdir "$SPAWNLOCK" 2>/dev/null
            return 0
        fi
        log "WARN: C daemon failed, falling back to shell poll"
    else
        log "hotspotd binary not found, using shell daemon"
    fi

    # shell fallback 进入长跑,在进入前释放 spawn 锁
    rmdir "$SPAWNLOCK" 2>/dev/null
    daemon_shell_fallback
}

# ── 命令分发 ────────────────────────────────────────────────
case "${1:-scan}" in
    scan)
        if hotspotd_alive; then
            do_scan_via_daemon || do_scan_shell
        else
            do_scan_shell
        fi
        ;;
    daemon)
        daemon_mode
        ;;
    list)
        if hotspotd_alive && \
           (command -v socat >/dev/null 2>&1 || command -v nc >/dev/null 2>&1); then
            socket_query "GET_DEVICES"
        else
            cat "$DEVICES_FILE" 2>/dev/null || echo '{}'
        fi
        ;;
    iface)
        # v3.4.1：iface 检测加文件缓存（5 分钟）
        # 旧版每次调用都跑 awk 解析 /proc/net/arp，结果在 wlan0 / wlan2 之间反复
        # 横跳（取决于 ARP 表临时状态），导致 watchdog 误判"接口变化"触发 full_restore，
        # 一晚上 158 次。加文件缓存彻底屏蔽抖动。
        #
        # 但缓存有副作用：如果检测时热点没开，get_hotspot_iface 可能返回错误结果，
        # 然后被缓存 5 分钟。所以：
        #   1. 只缓存有效结果（非空 + 非 wlan0）
        #   2. 缓存 miss 时如果 get_hotspot_iface 失败，输出 wlan0 但不写缓存
        #      （让下次调用重新检测，热点开了就能拿到正确值）
        IFACE_CACHE="$HNC_DIR/run/iface.cache"
        if [ -f "$IFACE_CACHE" ]; then
            cache_ts=$(stat -c %Y "$IFACE_CACHE" 2>/dev/null || echo 0)
            now_ts=$(date +%s)
            if [ -n "$cache_ts" ] && [ $((now_ts - cache_ts)) -lt 300 ]; then
                cached=$(cat "$IFACE_CACHE" 2>/dev/null)
                if [ -n "$cached" ] && [ "$cached" != "wlan0" ]; then
                    echo "$cached"
                    exit 0
                fi
            fi
        fi
        # 缓存失效或缓存值无效，重新检测
        mkdir -p "$HNC_DIR/run" 2>/dev/null
        detected=$(get_hotspot_iface)
        if [ -n "$detected" ] && [ "$detected" != "wlan0" ]; then
            # 有效值才写缓存
            echo "$detected" > "$IFACE_CACHE" 2>/dev/null
            echo "$detected"
        else
            # v4.0.0-patch1.4: 不再输出 wlan0 兜底。
            # 原因:patch1.x 阶段真机事故 — 热点 bootstrap 中 get_hotspot_iface
            # 返回空,这里兜底 wlan0 后 watchdog 拿到 "wlan0" → 查 IPv4 拿到
            # 上游 WiFi IP(如 10.24.23.45)→ httpd 绑上游地址 → 远端从热点
            # 子网访问永远不通(ERR_CONNECTION_REFUSED)。
            # 新行为:返回空 + exit 1,让调用方(watchdog/service.sh)明确
            # "热点未就绪",自己决定 retry 或 defer。
            exit 1
        fi
        ;;
    status)
        if hotspotd_alive; then
            socket_query "STATUS"
        else
            # v3.3.0 修复：case 分支运行在顶层而非函数内部，ash 严格模式
            # 下不允许 `local`。直接用普通变量。
            dpid=$(cat "$HNC_DIR/run/detect.pid" 2>/dev/null)
            echo "shell_daemon pid=${dpid:-none}"
        fi
        ;;
    *)
        echo "Usage: $0 [scan|daemon|list|iface|status]"
        exit 1
        ;;
esac
