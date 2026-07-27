#!/system/bin/sh
# apply_app_limits.sh — HNC v5.3.0-rc30.6
#
# Per-(client_mac, app_id) downlink rate limiter.
#
# Reads:
#   $HNC_DIR/data/app_limits.flat       — user config (one entry per line)
#                                          <mac> <app_id> <down_mbps>
#   $HNC_DIR/run/ip_app_map.flat        — dpid's observation (every 30s)
#                                          <ip> <app_id>
#   $HNC_DIR/data/devices.json          — hotspotd's active client table
#                                          (used to resolve mac → client_ip)
#   $HNC_DIR/run/active_iface           — current hotspot iface (e.g. wlan2)
#
# Writes:
#   iptables -t mangle -A HNC_APP_LIMIT  — MARK rules per (client_ip → app_ip)
#   tc class add  parent 1:1 classid 1:<id> htb rate <limit>mbit
#   tc filter add parent 1: prio 200 handle <mark> fw flowid 1:<id>
#
# Mark range: APP_MARK_BASE = 0x900000, avoids the 0x800000 range used by
# per-device limits in iptables_manager.sh / tc_manager.sh.
#
# Class id range: 0x9000-0xffff (36864-65535). Stays away from per-device
# classes which live in 1:100-1:9999.
#
# Idempotent: full rebuild each call. No state is kept between invocations.
# Costs ~50ms per call on Pixel-class hw for a handful of limits.
#
# Invocation: hnc_watchdog calls every 30s, OR immediately when
# /run/app_limit.dirty marker is present (set by hnc_httpd after a
# successful POST /api/action app_limit_set/clear).

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LIMITS_FLAT="$HNC_DIR/data/app_limits.flat"
IP_APP_FLAT="$HNC_DIR/run/ip_app_map.flat"
DEVICES="$HNC_DIR/data/devices.json"
DIRTY="$HNC_DIR/run/app_limit.dirty"
LOG="$HNC_DIR/logs/app_limits.log"

# v5.9.3 BUG-012 步骤1 / BUG-011 连带:两个可观测性文件
APP_SIG_FILE="$RUN/app_limits.applied.sig"        # 上一轮实际下发的 tc 规则签名
INACTIVE_MARKER="$RUN/app_limits_inactive.marker" # "配了限速但没生效"的 marker

APP_MARK_BASE_DEC=9437184   # 0x900000 — fwmark 高位避开 0x800000 device mark
APP_CLASS_MINOR_BASE=36864  # 0x9000 — tc classid minor in [0x9000, 0xffff]
CHAIN=HNC_APP_LIMIT
FILTER_PRIO=200

mkdir -p "$HNC_DIR/logs" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

# rotate log if >256 KB
if [ -f "$LOG" ]; then
    sz=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 262144 ] && mv "$LOG" "${LOG}.1" 2>/dev/null
fi

# Always clear dirty marker at start — even if we early-exit below.
rm -f "$DIRTY" 2>/dev/null

mkdir -p "$RUN" 2>/dev/null

# ─── v5.9.3 BUG-012 步骤1:tc 快照条件触发 ─────────────────────────────
#
# 本脚本被 hnc_watchdog 每 30s fork 一次,做的是自己那套 iptables + tc 全量重建
# (下面 Step 1 删 / Step 5 建),**完全不经过 tc_manager.sh 的命令分发器**,
# 而 tc_snapshot_async 只挂在那个分发器上 → run/tc_state.json 可以停在几天前
# (真机实测 9 天),bin/diag.sh / json_health_panel.sh 只判文件存在就报健康。
#
# 关键是"条件触发":每 30s 无条件刷会让 logs/tc_state.log 每天多 2880 行。
# 判据取"本轮下发的 tc 规则签名"(classid=rate 的集合)——
#   - 只包含真正影响 tc 树的东西,不含 ip_app_map 那些随时抖动的 IP 数量,
#     否则 dpid 每观测到一个新 IP 就会误触发一次;
#   - 规则集没变时,删了再原样加回去,tc 树的最终状态一致,快照没有刷新价值。
#
# 同步跑而不是 tc_manager.sh 那种 `( ... ) &`:hnc_watchdog 用
# cmd.Stdout/Stderr = io.Discard,os/exec 会为非 *os.File 的 Writer 建管道,
# Wait() 要等所有写端关闭 —— 后台子 shell 会继承那两个管道把 Wait 挂住。
APP_SIG=""

tc_snapshot_if_changed() {
    prev=$(cat "$APP_SIG_FILE" 2>/dev/null)
    [ "$prev" = "$APP_SIG" ] && return 0
    printf '%s\n' "$APP_SIG" > "$APP_SIG_FILE" 2>/dev/null
    log "tc app rules changed ['$prev' -> '$APP_SIG'], refreshing tc_state snapshot"
    [ -x "$HNC_DIR/bin/tc_state_snapshot.sh" ] || return 0
    HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/tc_state_snapshot.sh" "$IFACE" >/dev/null 2>&1
    return 0
}

# Locate current iface. Multiple fallbacks because watchdog may not have
# written run/active_iface yet on a cold boot.
IFACE=""
[ -f "$HNC_DIR/run/active_iface" ] && IFACE=$(cat "$HNC_DIR/run/active_iface" 2>/dev/null | head -1 | tr -d '\r\n ')
if [ -z "$IFACE" ] && [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
    IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')
fi
[ -z "$IFACE" ] && { log "no iface, exit"; exit 0; }

# ─── Step 1: clean up old rules ───────────────────────────────────────
# Both iptables HNC_APP_LIMIT chain and tc app classes / filters.

ensure_chain() {
    iptables -t mangle -N $CHAIN 2>/dev/null
    # Append (not insert) so HNC_APP_LIMIT runs AFTER HNC_MARK in the
    # FORWARD chain. iptables MARK overwrites the previous mark by default,
    # so app-level rules win over device-level rules — which matches user
    # mental model: "I specifically configured 抖音 to 1 Mbps, that should
    # apply even if the device has its own overall limit".
    if ! iptables -t mangle -C FORWARD -j $CHAIN 2>/dev/null; then
        iptables -t mangle -A FORWARD -j $CHAIN 2>/dev/null
    fi
}

ensure_chain
iptables -t mangle -F $CHAIN 2>/dev/null

# Remove app-range tc classes (0x9000-0xfff0 — our reserved minor range).
tc class show dev "$IFACE" 2>/dev/null | \
    awk '$1=="class" && $2=="htb" {print $3}' | \
    while IFS= read -r cid; do
        # cid like "1:9001" with hex minor — convert to decimal for range check.
        minor_hex=$(echo "$cid" | awk -F: '{print $2}')
        # printf to dec; tolerant of leading 0x or bare hex
        minor_dec=$(printf '%d' "0x$minor_hex" 2>/dev/null)
        [ -z "$minor_dec" ] && continue
        if [ "$minor_dec" -ge 36864 ] && [ "$minor_dec" -le 65520 ]; then
            tc class del dev "$IFACE" classid "$cid" 2>/dev/null
        fi
    done

# Remove app-range filters (prio 200).
tc filter del dev "$IFACE" parent 1: prio $FILTER_PRIO 2>/dev/null

# ─── Step 2: read configs ─────────────────────────────────────────────

if [ ! -s "$LIMITS_FLAT" ]; then
    # No active limits — clean exit, chain stays empty.
    log "no app_limits configured (cleaned old rules)"
    # v5.9.3 BUG-011:用户压根没配应用限速,不算"失效",清掉 marker。
    rm -f "$INACTIVE_MARKER" 2>/dev/null
    # v5.9.3 BUG-012:上面 Step 1 可能刚删掉了上一轮的 app class/filter,
    # 空签名 != 上一轮签名时说明 tc 树确实变了,要刷快照。
    tc_snapshot_if_changed
    exit 0
fi

# Bail if dpid hasn't produced an ip→app map yet (e.g. just rebooted).
if [ ! -s "$IP_APP_FLAT" ]; then
    # ─── v5.9.3 BUG-011 连带:别再静默失效 ─────────────────────────────
    # ip_app_map.flat 的唯一生产者是 dpid 主抓包路径上的 IPAppMap.Record;
    # dpid 一旦选错网卡 / 接口重建后不重绑(BUG-001),这张表就恒空,而这里
    # 只 log 一行普通句子后 exit 0,对 hnc_watchdog 看起来完全成功。
    # 用户侧的观感是"应用级限速配了但毫无作用",却完全不知道断在哪一环。
    # 现在:① 一条固定可 grep 的串 HNC_APP_LIMIT_INACTIVE;
    #       ② run/ 里落 marker(首次失效的时间戳)+ 连续失效轮次计数,
    #          让 diag / 人工 cat 能一眼定位到"是 dpid 没产出映射,
    #          不是限速配置写错了"。30s 一轮,streak×30 秒即失效时长。
    n_cfg=$(grep -c . "$LIMITS_FLAT" 2>/dev/null)
    case "$n_cfg" in *[!0-9]*|'') n_cfg=0 ;; esac
    # marker 格式(两行,故意保持人眼可读 + 好 parse):
    #   第 1 行 = 本次连续失效的起始 unix ts(跨轮保留,不被覆盖)
    #   第 2 行 = 连续失效轮次
    since=$(sed -n '1p' "$INACTIVE_MARKER" 2>/dev/null)
    case "$since" in *[!0-9]*|'') since=$(date +%s 2>/dev/null || echo 0) ;; esac
    streak=$(sed -n '2p' "$INACTIVE_MARKER" 2>/dev/null)
    case "$streak" in *[!0-9]*|'') streak=0 ;; esac
    streak=$((streak + 1))
    printf '%s\n%s\n' "$since" "$streak" > "$INACTIVE_MARKER" 2>/dev/null
    log "HNC_APP_LIMIT_INACTIVE: ip_app_map.flat empty/missing — 应用级限速未生效 (configured=$n_cfg entries, streak=$streak rounds since=$since, dpid 未产出 IP→APP 映射; 排查: run/dpi_state.json 的 stats.packets 是否在涨)"
    tc_snapshot_if_changed
    exit 0
fi
# 走到这里说明映射有数据了,清掉失效 marker。
rm -f "$INACTIVE_MARKER" 2>/dev/null

# ─── Step 3: resolve mac → client_ip from devices.json ────────────────
#
# devices.json is JSON; we don't have jq. We extract per-MAC IPs with a
# tolerant grep+sed — same shape as elsewhere in HNC.
#
# Expected key per device:
#   "aa:bb:cc:dd:ee:01": {"ip":"192.168.43.50", ...}
#
# Limitation: we only capture the FIRST ip-field-of-each-mac-record. Good
# enough — hotspotd stores one IPv4 per MAC.

resolve_mac_ip() {
    local mac=$1
    [ -f "$DEVICES" ] || return 1
    # devices.json shape: { "mac1": { "ip":"...", ... }, "mac2": {...} }
    # The file is usually one long line (no pretty-print). We scan
    # left-to-right for the target mac's entry, then capture the FIRST
    # "ip":"..." occurring AFTER that key.
    #
    # Note: a naive awk-per-line search is fragile on a single-line file
    # because all fields collapse onto one record. Switch to sed-driven
    # extraction which handles both pretty-printed and minified shapes:
    #
    #   1) Find the substring starting at "<mac>":{
    #   2) Within that, capture the first "ip":"<v4>"
    sed -n 's/.*"'"$mac"'":{[^}]*"ip":"\([0-9.]*\)".*/\1/p' "$DEVICES" | head -1
}

# ─── Step 4: build mark-id table (stable order from app_limits.flat) ──
#
# We index limits by line number to get a stable, unique mark per (mac,app).
# That gives us a small mark range (max ~100 entries) and matching tc class
# minors.

mark_for_index() {
    # 32-bit fwmark, no upper-bound issue. index 0-based.
    echo "0x$(printf '%x' $((APP_MARK_BASE_DEC + 1 + $1)))"
}

classid_for_index() {
    # tc classid minor MUST fit in 16 bits (max 0xffff = 65535). We use the
    # 0x9000-0xfff0 range; up to ~4000 distinct (mac, app) limits.
    # 1:9001, 1:9002, ..., 1:fff0
    local minor=$((APP_CLASS_MINOR_BASE + 1 + $1))
    if [ "$minor" -gt 65520 ]; then
        # Past the safe window. Drop. apply log will note skipped entries.
        echo ""
        return
    fi
    echo "1:$(printf '%x' $minor)"
}

# ─── Step 5: walk limits, build rules ─────────────────────────────────

i=0
applied=0
skipped=0
while IFS=' ' read -r MAC APP RATE; do
    [ -z "$MAC" ] && continue
    case "$MAC" in '#'*) continue ;; esac

    CLIENT_IP=$(resolve_mac_ip "$MAC")
    if [ -z "$CLIENT_IP" ]; then
        log "skip $MAC/$APP: client not online"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    # Pull all IPs currently mapped to this app from ip_app_map.flat.
    APP_IPS=$(awk -v want="$APP" '$2 == want {print $1}' "$IP_APP_FLAT" | sort -u)
    if [ -z "$APP_IPS" ]; then
        log "skip $MAC/$APP: no IPs observed for app yet"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    MARK=$(mark_for_index $i)
    CID=$(classid_for_index $i)
    if [ -z "$CID" ]; then
        log "skip $MAC/$APP: classid space exhausted (>4000 entries)"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi
    RATE_MBIT=$(printf '%.2f' "$RATE")

    # Create a tc class for this (mac, app) under root.
    # Parent is 1:1 to inherit overall root rate; rate=ceil for hard cap.
    tc class add dev "$IFACE" parent 1:1 classid "$CID" htb \
        rate "${RATE_MBIT}mbit" ceil "${RATE_MBIT}mbit" \
        burst 32k cburst 32k 2>/dev/null

    # Filter: any packet bearing this mark goes to the class.
    tc filter add dev "$IFACE" protocol ip parent 1: prio $FILTER_PRIO \
        handle "$MARK" fw flowid "$CID" 2>/dev/null

    # iptables MARK: for every (CLIENT_IP, APP_IP) pair, both directions.
    # We only need downlink (server -> client) to enforce a download cap,
    # but writing both directions makes the same chain reusable for future
    # upload caps without rule churn.
    for IP in $APP_IPS; do
        iptables -t mangle -A $CHAIN -d "$CLIENT_IP" -s "$IP" \
            -j MARK --set-mark "$MARK" 2>/dev/null
        iptables -t mangle -A $CHAIN -s "$CLIENT_IP" -d "$IP" \
            -j MARK --set-mark "$MARK" 2>/dev/null
    done

    n_ips=$(echo "$APP_IPS" | wc -l)
    # v5.9.3 BUG-012:只把真正影响 tc 树的部分(classid + rate)累进签名。
    # 故意不含 n_ips / IP 列表 —— 那些只改 iptables MARK 规则,tc 的
    # class/qdisc/filter 一个字节都不变,算进去会让快照被 dpid 的 IP 抖动带着
    # 每 30s 刷一次,正好是要避免的那种日志噪声。
    APP_SIG="$APP_SIG$CID=$RATE_MBIT,"
    log "applied $MAC ($CLIENT_IP) / $APP / ${RATE_MBIT}mbit / $n_ips ip(s) / mark=$MARK class=$CID"
    applied=$((applied + 1))
    i=$((i + 1))
done < "$LIMITS_FLAT"

# 注:while 用的是重定向 `< "$LIMITS_FLAT"` 而不是管道,循环体在当前 shell 里
# 跑,所以 APP_SIG / applied / skipped 的累加在这里是可见的。
log "summary: applied=$applied skipped=$skipped"

# v5.9.3 BUG-012 步骤1:本轮 tc 规则集与上一轮不同才刷快照。
tc_snapshot_if_changed
