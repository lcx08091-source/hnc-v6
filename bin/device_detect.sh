#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
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
#   list    设备表 JSON(hotspotd GET_DEVICES, 不在就直接读文件)
#   iface   热点网卡名(bin/hnc_iface.sh, 带 5 分钟缓存)
#   status  hotspotd STATUS
#   count   devices.json 里的设备数

HNC_DIR=${HNC_DIR:-/data/local/hnc}
DEVICES_FILE=$HNC_DIR/data/devices.json
LOG=$HNC_DIR/logs/detect.log
HOTSPOTD_BIN=$HNC_DIR/bin/hotspotd
HOTSPOTD_PID=$HNC_DIR/run/hotspotd.pid
HOTSPOTD_SOCK=$HNC_DIR/run/hotspotd.sock
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
# v5.20 起唯一权威探测器是 bin/hnc_iface.sh(偏好 → dumpsys tethering → tetherctrl →
# dumpsys wifi softap → AP 名扫描, 并写 run/iface_detect.json)。v5.33 删掉了本脚本
# 里那条「hnc_iface.sh 缺失时」的旧探测链(两份实现, 判断还不一样)。
get_hotspot_iface() {
    if [ -f "$HNC_DIR/bin/hnc_iface.sh" ]; then
        HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/hnc_iface.sh" get
        return
    fi
    log "WARN: $HNC_DIR/bin/hnc_iface.sh 不在(安装不完整), 探测不了热点网卡"
    return 1
}

# ── 设备计数(v5.32 T1) ───────────────────────────────────────
# devices.json 是单行紧凑 JSON(Go 写者这么写), 之前按「含 "mac" 的
# 行数」数恒为 1; 改为数 "mac":" 的出现次数(与 hotspotd STATUS 数设备的
# 口径一致)。函数独立出来, count 与 scan 子命令共用。
count_devices_from_json() {
    awk 'BEGIN{n=0} {n+=gsub(/"mac":"/, "x")} END{print n+0}' "$1" 2>/dev/null || echo 0
}

# ── scan: 让 Go 写者立刻全量扫一次(v5.33) ───────────────────
# 写 nonce(本进程 pid + 时间)到 run/devices.refresh(tmp + mv, 写者看到的总是完整
# 内容), Go 写者每拍(≤0.5 秒)看 mtime, 全量扫 + 强制写 devices.json 后把同一个
# nonce 写进 run/devices.refresh.ack。等到回执 = 这次扫描已落盘; 2 秒没等到(热点
# 没开 / 看门狗没在跑)就照现有 devices.json 数, 记一行日志。
# 原来: SIGUSR1 给 hotspotd, 1 秒后比 devices.json 的秒级 mtime, 没变就退回 shell
# ARP 扫描(同一秒里写过一次就误判, 还多出一份发现实现)。
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
# hotspotd 只剩硬件加速兜底和控制接口(设备发现在 Go 看门狗); 起不来不影响设备列表,
# 看门狗每轮 ensureDaemonRunning 会再拉。
daemon_mode() {
    log "=== Daemon mode starting ==="

    # v3.5.2 P0-A: spawn 锁防止与看门狗并发拉起两个 hotspotd
    # (unix socket bind 冲突 + pid 文件互相覆盖)
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
        # -d: 后台化(自己 fork), 写 PID 到 HOTSPOTD_PID
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
                # v5.12: 命中缓存也要确认接口还在且有 IPv4。热点从 wlan2 换到
                # wlan1/ap0(重开换频段、USB 共享等)后,旧实现最长 5 分钟内仍返回
                # 已消失的旧接口:watchdog probe 因"无 IPv4"判为热点关闭而不迁移,
                # apply_device_rule / tc_manager / v6_sync 把规则打到旧接口上全失败。
                # 校验失败就落到下面重新探测(只多一次 ip addr,不影响防抖初衷)。
                if [ -n "$cached" ] && [ "$cached" != "wlan0" ] && \
                   ip addr show "$cached" 2>/dev/null | grep -q 'inet '; then
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
            echo "hotspotd not running"
        fi
        ;;
    count)
        # v5.32 T1: 数 devices.json 里的设备数(单行 JSON 按出现次数, 不按行)
        echo "$(count_devices_from_json "$DEVICES_FILE")"
        ;;
    *)
        echo "Usage: $0 [scan|daemon|list|iface|status|count]"
        exit 1
        ;;
esac
