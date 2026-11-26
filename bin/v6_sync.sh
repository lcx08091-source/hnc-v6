#!/system/bin/sh

# PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# v6_sync.sh — IPv6 地址 → tc u32 filter 周期性同步器
#
# v3.4.0 新增。解决 IPv6 限速问题：
#
# 旧路径（v3.3.x）依赖 iptables mark + CONNMARK + tc fw mark filter，
# 在 ColorOS 上有累积延迟使 v6 TCP 卡死。
#
# 新路径（v3.4.0）：
#   1. 周期性扫描 ip -6 neigh，得到每台设备当前活跃的 v6 地址
#   2. 直接在 tc 上加 u32 dst/src 地址匹配 filter
#   3. v6 包到达 wlan2 egress 时，被 tc u32 filter 立即分类到对应 class
#   4. 完全跳过 iptables mark / CONNMARK / hash table 查询
#   5. 延迟极低，TCP 不会因 RTT 飙升而崩溃
#
# 旧 mark 路径并存作为防御深度——如果 u32 filter 未及时更新（地址刚换），
# v6 包仍可经由 mark + CONNMARK 走另一条路径到同一个 class。
#
# 数据源：iptables HNC_MARK 链是"哪些设备有限速"的唯一真相源（不读 rules.json）。
# 这样避免了 python3 依赖和 grep 浮点截断之类的祖传 bug。
#
# 命令：
#   v6_sync.sh sync             — 全量同步所有有限速的设备（默认）
#   v6_sync.sh sync_one <mac>   — 只同步一台
#   v6_sync.sh sync_macs <mac>… — 同步若干台(v5.20: httpd 邻居事件驱动, 合并后一次调用)
#   v6_sync.sh clear <mac>      — 清掉一台的所有 v6 filter
#   v6_sync.sh status           — 显示当前每台设备的 v6 地址 → tc filter 映射

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
LOG=$HNC_DIR/logs/v6_sync.log
SNAP_DIR=$HNC_DIR/run/v6
IFB_IFACE=ifb0
PRIO_BASE=200    # v6 u32 filter 优先级 = 200 + mark_id（占 201-299 段）
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi
MARK_BASE="${HNC_MARK_BASE:-0x00800000}"
DEV_MARK_MASK="${HNC_MARK_MASK:-0x00ff0000}"
command -v hnc_dev_mark_hex >/dev/null 2>&1 || {
    hnc_dev_mark_hex() { printf '0x%08x\n' $(( 0x00800000 | ($1 << 16) )); }
}
command -v hnc_parse_mid_from_mark >/dev/null 2>&1 || {
    hnc_parse_mid_from_mark() {
        local _r="${1%%/*}"
        local _v=$((_r))
        local _seg=$(( (_v >> 16) & 0xff ))
        if [ "$_seg" -gt 128 ] && [ "$_seg" -le 227 ]; then echo $((_seg - 128)); return 0; fi
        local _low=$(( _v & 0xffff ))
        if [ "$_seg" -eq 128 ] && [ "$_low" -ge 1 ] && [ "$_low" -le 99 ]; then echo "$_low"; return 0; fi
        return 1
    }
}

IP6T=${HNC_IP6T:-"ip6tables -w 2"}
_V6_IP6T_PROBED=0
_V6_IP6T_OK=0
_v6_probe_wait_bin() {
    local _b="$1" _rc
    "$_b" -w 2 -t filter -L -n >/dev/null 2>&1
    _rc=$?
    if [ "$_rc" -eq 2 ]; then
        "$_b" -w -t filter -L -n >/dev/null 2>&1
        _rc=$?
        if [ "$_rc" -eq 2 ]; then
            printf '%s\n' "$_b"
        else
            printf '%s -w\n' "$_b"
        fi
    else
        # rc=0 或 rc=4(短暂 xtables 锁竞争超时)等非语法错误: 保持 -w 2 绝不误剥!
        printf '%s -w 2\n' "$_b"
    fi
}
v6_ip6t_mangle_ok() {
    if [ "$_V6_IP6T_PROBED" = "0" ]; then
        _V6_IP6T_PROBED=1
        if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v ip6tables >/dev/null 2>&1; then
            IP6T=$(_v6_probe_wait_bin ip6tables)
        fi
        if command -v "${IP6T%% *}" >/dev/null 2>&1 && $IP6T -t mangle -L HNC_MARK -n >/dev/null 2>&1; then
            _V6_IP6T_OK=1
        else
            _V6_IP6T_OK=0
        fi
    fi
    [ "$_V6_IP6T_OK" = "1" ]
}

_V6_CANON_AWK='
function canon_ip6(raw,    s, hal, nl, nr, L, R, z, out, i, h) {
    s = tolower(raw)
    sub(/\/[0-9]+$/, "", s)
    sub(/%.*/, "", s)
    if (s !~ /:/) return s
    if (index(s, "::") > 0) {
        split(s, hal, "::")
        nl = (hal[1] == "") ? 0 : split(hal[1], L, ":")
        nr = (hal[2] == "") ? 0 : split(hal[2], R, ":")
        z = 8 - nl - nr
        out = ""
        for (i = 1; i <= nl; i++) { h = L[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
        for (i = 1; i <= z; i++)  { out = (out == "" ? "0" : out ":0") }
        for (i = 1; i <= nr; i++) { h = R[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
        return out
    }
    nl = split(s, L, ":")
    out = ""
    for (i = 1; i <= nl; i++) { h = L[i]; sub(/^0+/, "", h); if (h == "") h = "0"; out = (out == "" ? h : out ":" h) }
    return out
}
'

# 同步维护 ip6tables -t mangle HNC_MARK -d <ip6>/128 -j MARK --set-xmark <dev_hex>/0x00ff0000
# 防止 IPv6 下行包在无 conntrack 标时因缺 [23:16] 设备标被 Vector Express 1:8010(prio 5) 抢走。
# 注: 真实内核 ip6tables -t mangle -S HNC_MARK 恒至少输出 "-N HNC_MARK"(_cur6 非空), 走精确差量增删;
#     无状态单测 mock 下 _cur6 为空串, 仅对本轮应装列表(_add_hint)下发 -A。
_sync_ip6_hnc_mark() {
    local _mid="$1" _want="$2" _add_hint="${3:-}" _steady="${4:-0}"
    case "$_mid" in ''|*[!0-9]*) return 0 ;; esac
    v6_ip6t_mangle_ok || return 0
    local _dhex _mshort _cur6 _d_raw _d_cnt _k _a6
    _dhex=$(hnc_dev_mark_hex "$_mid") || return 0
    _mshort=$(printf '0x%x' $(( 0x00800000 | (_mid << 16) )))
    _cur6=$($IP6T -t mangle -S HNC_MARK 2>/dev/null)
    if [ -n "$_cur6" ]; then
        printf '%s\n' "$_cur6" | awk -v mk="$_dhex" -v mks="$_mshort" -v want="$_want" "$_V6_CANON_AWK"'
            BEGIN {
                n = split(want, wa, "\n")
                for (i = 1; i <= n; i++) if (wa[i] != "") wset[canon_ip6(wa[i])] = 1
            }
            $1 == "-A" && $2 == "HNC_MARK" {
                hm = 0; hk = 0; d = ""
                for (i = 3; i <= NF; i++) {
                    if ($i == "--mac-source") hm = 1
                    if ($i == "--set-xmark" || $i == "--set-mark") {
                        t = tolower($(i+1))
                        if (index(t, tolower(mk)) == 1 || index(t, tolower(mks)) == 1) hk = 1
                    }
                    if ($i == "-d") d = $(i+1)
                }
                if (!hm && hk && d != "") {
                    cd = canon_ip6(d)
                    if (!(cd in wset)) {
                        del_cnt[d]++
                    } else if (seen_ok[cd]++) {
                        del_cnt[d]++
                    }
                }
            }
            END {
                for (d in del_cnt) printf "%d %s\n", del_cnt[d], d
            }' | while read -r _d_cnt _d_raw; do
            [ -n "$_d_raw" ] || continue
            _k=0
            while [ "$_k" -lt "${_d_cnt:-1}" ] && [ "$_k" -lt 8 ]; do
                $IP6T -t mangle -D HNC_MARK -d "$_d_raw" -j MARK --set-xmark "${_dhex}/${DEV_MARK_MASK}" 2>/dev/null || break
                _k=$((_k + 1))
            done
        done
        for _a6 in $_want; do
            if printf '%s\n' "$_cur6" | awk -v mk="$_dhex" -v mks="$_mshort" -v a="$_a6" "$_V6_CANON_AWK"'
                BEGIN { target = canon_ip6(a); hit = 0 }
                $1 == "-A" && $2 == "HNC_MARK" {
                    hm = 0; hk = 0; d = ""
                    for (i = 3; i <= NF; i++) {
                        if ($i == "--mac-source") hm = 1
                        if ($i == "--set-xmark" || $i == "--set-mark") {
                            t = tolower($(i+1))
                            if (index(t, tolower(mk)) == 1 || index(t, tolower(mks)) == 1) hk = 1
                        }
                        if ($i == "-d") d = $(i+1)
                    }
                    if (!hm && hk && d != "" && canon_ip6(d) == target) { hit = 1; exit }
                }
                END { exit !hit }'; then
                continue
            fi
            $IP6T -t mangle -A HNC_MARK -d "${_a6}/128" -j MARK --set-xmark "${_dhex}/${DEV_MARK_MASK}" 2>/dev/null || true
        done
    else
        if [ "$_steady" != "1" ] || [ -z "${HNC_TEST_MODE:-}" ]; then
            for _a6 in $_add_hint; do
                $IP6T -t mangle -A HNC_MARK -d "${_a6}/128" -j MARK --set-xmark "${_dhex}/${DEV_MARK_MASK}" 2>/dev/null || true
            done
        fi
    fi
}

_clear_ip6_hnc_mark() {
    local _mid="$1" _snap_addrs="${2:-}"
    case "$_mid" in ''|*[!0-9]*) return 0 ;; esac
    v6_ip6t_mangle_ok || return 0
    local _dhex _mshort _cur6 _d_cnt _d_raw _k _a6 _cleaned=" "
    _dhex=$(hnc_dev_mark_hex "$_mid") || return 0
    _mshort=$(printf '0x%x' $(( 0x00800000 | (_mid << 16) )))
    _cur6=$($IP6T -t mangle -S HNC_MARK 2>/dev/null)
    if [ -n "$_cur6" ]; then
        for _d_raw in $(printf '%s\n' "$_cur6" | awk -v mk="$_dhex" -v mks="$_mshort" '
            $1 == "-A" && $2 == "HNC_MARK" {
                hm = 0; hk = 0; d = ""
                for (i = 3; i <= NF; i++) {
                    if ($i == "--mac-source") hm = 1
                    if ($i == "--set-xmark" || $i == "--set-mark") {
                        t = tolower($(i+1))
                        if (index(t, tolower(mk)) == 1 || index(t, tolower(mks)) == 1) hk = 1
                    }
                    if ($i == "-d") d = $(i+1)
                }
                if (!hm && hk && d != "") print d
            }' | sort -u); do
            _k=0
            while [ "$_k" -lt 8 ] && $IP6T -t mangle -D HNC_MARK -d "$_d_raw" -j MARK --set-xmark "${_dhex}/${DEV_MARK_MASK}" 2>/dev/null; do
                _k=$((_k + 1))
            done
            _cleaned="${_cleaned}${_d_raw%/128} "
        done
    else
        for _a6 in $_snap_addrs; do
            [ -n "$_a6" ] || continue
            $IP6T -t mangle -D HNC_MARK -d "${_a6}/128" -j MARK --set-xmark "${_dhex}/${DEV_MARK_MASK}" 2>/dev/null || true
        done
    fi
}

log() { echo "[$(date '+%H:%M:%S')] [V6] $*" >> "$LOG" 2>/dev/null; }

# v5.20: 地址宽限 + 每台上限
#   - 地址从邻居表消失(或短暂 FAILED/INCOMPLETE)后, 过滤器再保留 V6_GRACE 秒:
#     NDP 探测抖动时不至于先删后加、让设备在空窗里绕过限速; 超过宽限才真正删除。
#   - 每台设备最多 V6_MAX_ADDRS 个地址(优先保留 REACHABLE/DELAY/PROBE, 再排 STALE,
#     最后按最近看到排序, 超出的最旧地址不装): 隐私地址轮换 + 宽限叠加时限制过滤器条数。
#   快照格式: 头行 "#hnc_v6 iface= mark= ing=" + 每行 "<地址> <最近看到的单调秒>"
#   (旧格式只有地址, 读入时按"刚看到"处理, 向后兼容)。
V6_GRACE=${HNC_V6_GRACE:-300}
V6_MAX_ADDRS=${HNC_V6_MAX_ADDRS:-16}
V6_LOCK="$HNC_DIR/run/v6_sync.lock"

# 单调秒: /proc/uptime(CLOCK_BOOTTIME, 不受墙钟跳变影响)。run/v6 开机即清
# (post-fs-data.sh), 快照里的时间戳不需要跨重启可比。测试可用 HNC_V6_NOW 注入。
v6_now() {
    if [ -n "$HNC_V6_NOW" ]; then echo "$HNC_V6_NOW"; return 0; fi
    local up _rest
    if read -r up _rest < /proc/uptime 2>/dev/null && [ -n "$up" ]; then
        echo "${up%%.*}"; return 0
    fi
    date +%s
}

_v6_sleep() {
    usleep 100000 2>/dev/null && return 0
    sleep 0.1 2>/dev/null && return 0
    sleep 1
}

# v5.20: 进程级互斥。watchdog 60s 周期全量同步与 httpd 事件驱动的 sync_macs 可能
# 同时跑; 同一 prio 段的 del/add 交错会留下重复或缺失的 filter。mkdir 原子锁,
# 持有者已死(pid 不在)则回收; 最多等 ~10s。
v6_lock() {
    local i=0 pid
    while ! mkdir "$V6_LOCK" 2>/dev/null; do
        pid=$(cat "$V6_LOCK/pid" 2>/dev/null)
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            rm -rf "$V6_LOCK" 2>/dev/null
            continue
        fi
        i=$((i+1))
        # pid 文件一直没写出来(持有者在 mkdir 与写 pid 之间被杀)→ 5s 后回收
        if [ -z "$pid" ] && [ "$i" -ge 50 ]; then
            rm -rf "$V6_LOCK" 2>/dev/null
            continue
        fi
        [ "$i" -ge 100 ] && return 1
        _v6_sleep
    done
    echo "$$" > "$V6_LOCK/pid" 2>/dev/null
    trap 'v6_unlock' EXIT
    trap 'v6_unlock; exit 130' INT TERM
    return 0
}

v6_unlock() {
    [ "$(cat "$V6_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$V6_LOCK" 2>/dev/null
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 数据源：从 iptables HNC_MARK 提取 (mac, mark_hex) 对
# 输出每行 "MAC MARK_HEX" 形如 "e2:0d:4a:48:5d:40 0x00bb0000/0x00ff0000"
# ═══════════════════════════════════════════════════════════════
_parse_hnc_mark_raw() {
    local _in="$1" _out
    [ -n "$_in" ] || return 0
    _out=$(printf '%s\n' "$_in" | awk '
    /MAC/ && /MARK/ {
        mac=""; mark=""
        for (i=1; i<=NF; i++) {
            if ($i == "MAC") mac=tolower($(i+1))
            if (($i == "set" || $i == "xset") && $(i-1) == "MARK") mark=$(i+1)
        }
        if (mac != "" && mark != "") print mac, mark
    }' | sort -u)
    if [ -z "$_out" ]; then
        _out=$(printf '%s\n' "$_in" | awk '
        /--mac-source/ && /--set-(x)?mark/ {
            mac=""; mark=""
            for (i=1; i<=NF; i++) {
                if ($i == "--mac-source") mac=tolower($(i+1))
                if ($i == "--set-xmark" || $i == "--set-mark") mark=$(i+1)
            }
            if (mac != "" && mark != "") print mac, mark
        }' | sort -u)
    fi
    [ -n "$_out" ] && printf '%s\n' "$_out"
}

list_marked_devices() {
    local raw _rc parsed raw6 parsed6
    if [ -n "${HNC_IPT:-}" ]; then
        raw=$($HNC_IPT -t mangle -L HNC_MARK -n 2>/dev/null) || return 1
    else
        raw=$(iptables -w 2 -t mangle -L HNC_MARK -n 2>/dev/null)
        _rc=$?
        if [ "$_rc" -ne 0 ]; then
            # 仅当退出码为 2(非法参数, 真不支持 -w)时才降级尝试 -w / 无 -w;
            # 退出码 4(xtables.lock 锁竞争超时)绝不剥离 -w 2!
            if [ "$_rc" -eq 2 ] && [ -z "${HNC_TEST_MODE:-}" ]; then
                raw=$(iptables -w -t mangle -L HNC_MARK -n 2>/dev/null)
                _rc=$?
                if [ "$_rc" -eq 2 ]; then
                    raw=$(iptables -t mangle -L HNC_MARK -n 2>/dev/null) || return 1
                elif [ "$_rc" -ne 0 ]; then
                    return 1
                fi
            else
                return 1
            fi
        fi
    fi
    parsed=$(_parse_hnc_mark_raw "$raw")
    if [ -z "$parsed" ] && v6_ip6t_mangle_ok; then
        raw6=$($IP6T -t mangle -L HNC_MARK -n 2>/dev/null) && parsed6=$(_parse_hnc_mark_raw "$raw6")
        [ -n "$parsed6" ] && parsed="$parsed6"
    fi
    [ -n "$parsed" ] && printf '%s\n' "$parsed"
    return 0
}

# 同一次调用内复用 iptables 读数(sync_all / sync_macs 一次读、逐台用)
_V6_MARKED_SET=""
_V6_MARKED=""
_V6_MARKED_ERR=0
marked_devices() {
    if [ -z "$_V6_MARKED_SET" ]; then
        if _V6_MARKED=$(list_marked_devices); then
            _V6_MARKED_ERR=0
        else
            _V6_MARKED=""
            _V6_MARKED_ERR=1
        fi
        _V6_MARKED_SET=1
    fi
    [ "$_V6_MARKED_ERR" = 1 ] && return 1
    [ -n "$_V6_MARKED" ] && printf '%s\n' "$_V6_MARKED"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 拿一台设备当前活跃的 v6 地址(带状态优先级)
#   tier=2: REACHABLE / DELAY / PROBE / PERMANENT (当前真实活跃地址)
#   tier=1: STALE 等其他非失败邻居状态
# 排除 link-local fe80:: / 多播 ff00::/8 及 FAILED/INCOMPLETE 状态
# ═══════════════════════════════════════════════════════════════
get_v6_addrs_ranked() {
    local mac=$1 iface=$2
    local raw
    raw=$(ip -6 neigh show dev "$iface" 2>/dev/null)
    [ -z "$raw" ] && raw=$(ip neigh show dev "$iface" 2>/dev/null)
    printf '%s\n' "$raw" | awk -v mac="$mac" '
    {
        line = tolower($0)
        m = tolower(mac)
        if (index(line, m) > 0 && $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $1 != "::") {
            st = toupper($NF)
            if (st == "FAILED" || st == "INCOMPLETE") next
            t = (st == "REACHABLE" || st == "DELAY" || st == "PROBE" || st == "PERMANENT") ? 2 : 1
            if (!($1 in tier) || t > tier[$1]) tier[$1] = t
        }
    }
    END {
        for (a in tier) printf "%d %s\n", tier[a], a
    }'
}

get_v6_addrs() {
    get_v6_addrs_ranked "$1" "$2" | awk 'NF>=2{print $2}' | sort -u
}

# ═══════════════════════════════════════════════════════════════
# 同步一台设备的 v6 filter
# ═══════════════════════════════════════════════════════════════
_v6_valid_mac() {
    case "$1" in
        [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F])
            return 0 ;;
        *) return 1 ;;
    esac
}

_write_snap_filtered() {
    # $1 = snap 文件路径, $2 = hdr, $3 = merged("<addr> <ts>" 每行), $4 = 空格包裹的失败地址 " a1 a2 "
    local _sf=$1 _shdr=$2 _sm=$3 _sbad=$4 _body
    if [ -z "$_sm" ]; then
        printf '%s\n' "$_shdr" > "${_sf}.tmp" && mv -f "${_sf}.tmp" "$_sf"
        return 0
    fi
    if [ -n "$_sbad" ] && [ "$_sbad" != " " ]; then
        _body=$(printf '%s\n' "$_sm" | awk -v bad="$_sbad" 'NF && index(bad, " " $1 " ") == 0 { print }')
    else
        _body="$_sm"
    fi
    if [ -n "$_body" ]; then
        printf '%s\n%s\n' "$_shdr" "$_body" > "${_sf}.tmp" && mv -f "${_sf}.tmp" "$_sf"
    else
        printf '%s\n' "$_shdr" > "${_sf}.tmp" && mv -f "${_sf}.tmp" "$_sf"
    fi
}

sync_one() {
    local mac=$1
    local iface=${2:-$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)}
    [ -z "$mac" ] && { log "WARN: sync_one called with empty mac"; return 1; }
    if ! _v6_valid_mac "$mac"; then
        log "WARN: sync_one: invalid mac '$mac'"
        return 1
    fi
    [ -z "$iface" ] && { log "WARN: sync_one no iface"; return 1; }
    mac=$(printf '%s' "$mac" | tr 'A-F' 'a-f')

    local snap="$SNAP_DIR/$mac"
    # 找 mark_id（从 iptables）
    local mark_hex
    mark_hex=$(marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')
    if [ -z "$mark_hex" ]; then
        [ -f "$snap" ] || return 0
        clear_one "$mac" "$iface"
        return 0
    fi

    local mark_id
    mark_id=$(hnc_parse_mid_from_mark "$mark_hex" 2>/dev/null) || mark_id=""
    if [ -z "$mark_id" ] || [ "$mark_id" -lt 1 ] || [ "$mark_id" -gt 99 ]; then
        log "WARN: invalid mark_id '$mark_id' for $mac (mark=$mark_hex)"
        return 1
    fi

    local prio=$((PRIO_BASE + mark_id))
    local cls=$mark_id
    [ "$mark_id" = "1" ] && cls=100
    mkdir -p "$SNAP_DIR" 2>/dev/null

    # 检查 ifb0 上是否有该 class（用户设了 up 限速时才会有）
    local has_ingress=0
    if tc class show dev "$IFB_IFACE" 2>/dev/null | grep -q "class htb 1:$cls "; then
        has_ingress=1
    fi

    local hdr="#hnc_v6 iface=$iface mark=$mark_id ing=$has_ingress"
    local now; now=$(v6_now)
    local cur_ranked prev_all prev_hdr prev_list prev prev_mark prev_iface merged n_all
    cur_ranked=$(get_v6_addrs_ranked "$mac" "$iface")
    prev_all=""
    [ -f "$snap" ] && prev_all=$(cat "$snap" 2>/dev/null)
    prev_hdr=$(printf '%s\n' "$prev_all" | grep '^#hnc_v6 ' | head -n 1)
    prev_list=$(printf '%s\n' "$prev_all" | grep -v '^#' | awk 'NF')
    prev=$(printf '%s\n' "$prev_list" | awk 'NF{print $1}' | sort -u)
    prev_mark=$(printf '%s\n' "$prev_hdr" | sed -n 's/^#hnc_v6 .* mark=\([0-9]*\).*/\1/p' | head -n 1)
    prev_iface=$(printf '%s\n' "$prev_hdr" | sed -n 's/^#hnc_v6 iface=\([^ ]*\).*/\1/p' | head -n 1)

    # 期望集: 优先保留 REACHABLE/DELAY/PROBE(tier=2), 其次 STALE(tier=1), 最后宽限期内旧地址(tier=0),
    # 按 (tier 降序, 最近看到时间戳降序, 地址字典序) 截取前 V6_MAX_ADDRS 条!
    merged=$( { printf '%s\n' "$cur_ranked" | awk -v n="$now" 'NF>=2{print $1, $2, n}'
                printf '%s\n' "$prev_list" | awk -v n="$now" 'NF{t=$2; if (t == "" || t !~ /^[0-9]+$/ || t+0 > n+0) t=n; print 0, $1, t}'
              } | awk -v n="$now" -v g="$V6_GRACE" '
                NF >= 3 {
                    tr = $1 + 0; a = $2; t = $3 + 0
                    if (!(a in ts) || t > ts[a]) ts[a] = t
                    if (!(a in tier) || tr > tier[a]) tier[a] = tr
                }
                END {
                    for (a in ts) if (n - ts[a] < g) printf "%d %d %s\n", tier[a], ts[a], a
                }' \
              | sort -k1,1nr -k2,2nr -k3,3 )
    n_all=$(printf '%s\n' "$merged" | awk 'NF' | wc -l | tr -d ' ')
    if [ "${n_all:-0}" -gt "$V6_MAX_ADDRS" ]; then
        log "  $mac: $n_all v6 addresses, capping to newest $V6_MAX_ADDRS"
    fi
    merged=$(printf '%s\n' "$merged" | awk -v max="$V6_MAX_ADDRS" 'NF>=3 && c < max {c++; print $3, $2}')
    local want
    want=$(printf '%s\n' "$merged" | awk 'NF{print $1}' | sort -u)
    local snap_new="$hdr"
    [ -n "$merged" ] && snap_new="$hdr
$merged"

    local filters_ok=0
    if tc filter show dev "$iface" parent 1: 2>/dev/null | grep -q "pref $prio " && \
       { [ "$has_ingress" != "1" ] || tc filter show dev "$IFB_IFACE" parent 1: 2>/dev/null | grep -q "pref $prio "; }; then
        filters_ok=1
    fi

    local added="" removed=""
    local diff
    diff=$( { printf '%s\n' "$prev" | awk 'NF{print "P", $1}'
              printf '%s\n' "$want" | awk 'NF{print "W", $1}'
            } | awk '$1=="P"{p[$2]=1} $1=="W"{w[$2]=1}
                     END{for (a in w) if (!(a in p)) print "+", a; for (a in p) if (!(a in w)) print "-", a}' | sort)
    added=$(printf '%s\n' "$diff" | awk '$1=="+"{print $2}')
    removed=$(printf '%s\n' "$diff" | awk '$1=="-"{print $2}')

    if [ "$hdr" = "$prev_hdr" ] && [ -z "$removed" ]; then
        if [ -z "$added" ]; then
            if [ -z "$want" ] || [ "$filters_ok" = "1" ]; then
                [ -n "$want" ] && _sync_ip6_hnc_mark "$mark_id" "$want" "" 1
                [ "$snap_new" != "$prev_all" ] && { printf '%s\n' "$snap_new" > "${snap}.tmp" && mv -f "${snap}.tmp" "$snap"; }
                return 0
            fi
            log "Sync $mac (mark=$mark_id prio=$prio): filters missing on tc (tree rebuilt?), rebuilding"
        elif [ -z "$prev" ] || [ "$filters_ok" = "1" ]; then
            # 只新增(临时地址轮换): 只补新地址, 不 flush; 严格检查上下行返回码后再写快照!
            local n=0 nfail=0 fail_addrs=" " _eg_ok _ig_ok
            for addr in $added; do
                _eg_ok=0; _ig_ok=1
                if tc filter add dev "$iface" parent 1: protocol ipv6 prio "$prio" u32 \
                        match ip6 dst "$addr/128" flowid "1:$cls" 2>/dev/null; then
                    _eg_ok=1
                else
                    log "  WARN: egress filter add failed for $addr"
                fi
                if [ "$has_ingress" = "1" ]; then
                    if ! tc filter add dev "$IFB_IFACE" parent 1: protocol ipv6 prio "$prio" u32 \
                            match ip6 src "$addr/128" flowid "1:$cls" 2>/dev/null; then
                        _ig_ok=0
                        log "  WARN: ingress filter add failed for $addr on $IFB_IFACE"
                    fi
                fi
                if [ "$_eg_ok" = "1" ] && [ "$_ig_ok" = "1" ]; then
                    n=$((n+1))
                else
                    nfail=$((nfail+1))
                    fail_addrs="${fail_addrs}${addr} "
                fi
            done
            _sync_ip6_hnc_mark "$mark_id" "$want" "$added" 0
            _write_snap_filtered "$snap" "$hdr" "$merged" "$fail_addrs"
            log "Sync $mac (mark=$mark_id prio=$prio): +$(echo "$added" | tr '\n' ' ')(incremental, added=$n failed=$nfail ingress=$has_ingress)"
            [ "$nfail" -eq 0 ]
            return $?
        else
            log "Sync $mac (mark=$mark_id prio=$prio): new addresses but filters missing on tc, rebuilding"
        fi
    else
        log "Sync $mac (mark=$mark_id prio=$prio iface=$iface ingress=$has_ingress): state changed"
        [ -n "$removed" ] && log "  expired (>${V6_GRACE}s gone or capped): $(echo "$removed" | tr '\n' ' ')"
    fi
    [ -n "$prev" ] && log "  prev: $(echo "$prev" | tr '\n' ' ')"
    log "  want: $(echo "$want" | tr '\n' ' ')"

    if [ -n "$prev_mark" ] && [ "$prev_mark" != "$mark_id" ]; then
        local old_prio=$((PRIO_BASE + prev_mark))
        tc filter del dev "$iface"     parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
        tc filter del dev "$IFB_IFACE" parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
        [ -n "$prev_iface" ] && [ "$prev_iface" != "$iface" ] && \
            tc filter del dev "$prev_iface" parent 1: prio "$old_prio" protocol ipv6 2>/dev/null
        _clear_ip6_hnc_mark "$prev_mark" "$prev"
    fi
    if [ -n "$prev_iface" ] && [ "$prev_iface" != "$iface" ]; then
        tc filter del dev "$prev_iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
    fi

    tc filter del dev "$iface"     parent 1: prio "$prio" protocol ipv6 2>/dev/null
    tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null

    if [ -z "$want" ]; then
        _sync_ip6_hnc_mark "$mark_id" "" "" 0
        printf '%s\n' "$snap_new" > "${snap}.tmp" && mv -f "${snap}.tmp" "$snap"
        log "  $mac: no active v6 addresses"
        return 0
    fi

    # 重建 filter，每个地址一条，严格核验上下行返回码再写快照
    local n=0 nfail=0 fail_addrs=" " _eg_ok _ig_ok
    for addr in $want; do
        _eg_ok=0; _ig_ok=1
        if tc filter add dev "$iface" parent 1: protocol ipv6 prio "$prio" u32 \
                match ip6 dst "$addr/128" flowid "1:$cls" 2>/dev/null; then
            _eg_ok=1
        else
            log "  WARN: egress filter add failed for $addr"
        fi
        if [ "$has_ingress" = "1" ]; then
            if ! tc filter add dev "$IFB_IFACE" parent 1: protocol ipv6 prio "$prio" u32 \
                    match ip6 src "$addr/128" flowid "1:$cls" 2>/dev/null; then
                _ig_ok=0
                log "  WARN: ingress filter add failed for $addr on $IFB_IFACE"
            fi
        fi
        if [ "$_eg_ok" = "1" ] && [ "$_ig_ok" = "1" ]; then
            n=$((n+1))
        else
            nfail=$((nfail+1))
            fail_addrs="${fail_addrs}${addr} "
        fi
    done

    _sync_ip6_hnc_mark "$mark_id" "$want" "$want" 0
    _write_snap_filtered "$snap" "$hdr" "$merged" "$fail_addrs"
    log "  $mac: synced $n filter(s) (failed=$nfail, ingress=$has_ingress)"
    [ "$nfail" -eq 0 ]
}

# v5.20: 同步若干台(httpd 邻居事件合并后调用)。iface / iptables 只读一次。
sync_macs() {
    local iface mac
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    [ -z "$iface" ] && { log "WARN: sync_macs no iface"; return 1; }
    for mac in "$@"; do
        case "$mac" in
            [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]) ;;
            *) log "WARN: sync_macs: bad mac '$mac'"; continue ;;
        esac
        sync_one "$mac" "$iface"
    done
    return 0
}

# ═══════════════════════════════════════════════════════════════
# 清掉一台设备的所有 v6 filter（用于 unmark / 关限速场景）
# ═══════════════════════════════════════════════════════════════
clear_one() {
    local mac=$1
    local iface=${2:-$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)}
    [ -z "$mac" ] && return 1
    if ! _v6_valid_mac "$mac"; then
        log "WARN: clear_one: invalid mac '$mac'"
        return 1
    fi
    mac=$(printf '%s' "$mac" | tr 'A-F' 'a-f')

    local snap="$SNAP_DIR/$mac"

    # 试图从快照文件读出该设备的 prio——但我们没存 prio
    # 改为：从 iptables 找 mark_hex（即使被 unmark 了，可能还在）
    local mark_hex mark_id="" snap_iface="" snap_addrs=""
    mark_hex=$(marked_devices | awk -v m="$mac" '$1==m {print $2; exit}')
    if [ -n "$mark_hex" ]; then
        mark_id=$(hnc_parse_mid_from_mark "$mark_hex" 2>/dev/null) || mark_id=""
    fi
    # v5.12: iptables 里已没有 mark(sync_all 孤儿清理 / 规则已被删)时,旧实现只删
    # 快照不删 filter → v6 u32 filter 残留;mid 复用给别的设备后,旧设备的 v6 流量
    # 被归进新设备的 class。改为从快照头行取回当时的 mark / iface。
    if [ -f "$snap" ]; then
        [ -n "$mark_id" ] || mark_id=$(sed -n 's/^#hnc_v6 .* mark=\([0-9]*\).*/\1/p' "$snap" 2>/dev/null | head -n 1)
        snap_iface=$(sed -n 's/^#hnc_v6 iface=\([^ ]*\).*/\1/p' "$snap" 2>/dev/null | head -n 1)
        snap_addrs=$(grep -v '^#' "$snap" 2>/dev/null | awk 'NF{print $1}' | sort -u)
    fi

    case "$mark_id" in
        ''|*[!0-9]*)
            log "Clear $mac: no mark found, snapshot only" ;;
        *)
            local prio=$((PRIO_BASE + mark_id))
            [ -n "$iface" ] && tc filter del dev "$iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            tc filter del dev "$IFB_IFACE" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            [ -n "$snap_iface" ] && [ "$snap_iface" != "$iface" ] && \
                tc filter del dev "$snap_iface" parent 1: prio "$prio" protocol ipv6 2>/dev/null
            _clear_ip6_hnc_mark "$mark_id" "$snap_addrs"
            log "Clear $mac (mark=$mark_id prio=$prio): filters removed" ;;
    esac

    rm -f "$snap" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════
# 全量同步：遍历所有有限速的设备 + 清理孤儿快照
# ═══════════════════════════════════════════════════════════════
sync_all() {
    local iface
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    [ -z "$iface" ] && { log "WARN: sync_all no iface"; return 1; }

    local devices
    if ! devices=$(marked_devices); then
        log "WARN: sync_all aborted — iptables -w 2 HNC_MARK read failed (xtables lock contention?)"
        return 1
    fi

    # 没有任何限速设备 → 清理所有孤儿快照后返回
    if [ -z "$devices" ]; then
        if [ -d "$SNAP_DIR" ]; then
            for f in "$SNAP_DIR"/*; do
                [ -f "$f" ] || continue
                local mac; mac=$(basename "$f")
                clear_one "$mac" "$iface"
            done
        fi
        return 0
    fi

    # 同步每台有限速的设备
    local active_macs=""
    echo "$devices" | while read -r mac mark_hex; do
        [ -z "$mac" ] && continue
        sync_one "$mac" "$iface"
    done

    # 清理孤儿：快照存在但 iptables 已无 mark
    if [ -d "$SNAP_DIR" ]; then
        for f in "$SNAP_DIR"/*; do
            [ -f "$f" ] || continue
            local mac; mac=$(basename "$f")
            if ! echo "$devices" | awk -v m="$mac" '$1==m {found=1; exit} END{exit !found}'; then
                clear_one "$mac" "$iface"
            fi
        done
    fi
}

# ═══════════════════════════════════════════════════════════════
# 显示当前同步状态（人类可读）
# ═══════════════════════════════════════════════════════════════
show_status() {
    local iface _v6_root _v6_ver="" _mp
    _v6_root=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P)
    for _mp in "${_v6_root:+$_v6_root/module.prop}" "$HNC_DIR/module.prop" "/data/adb/modules/hotspot_net_ctl/module.prop"; do
        [ -n "$_mp" ] && [ -f "$_mp" ] || continue
        _v6_ver=$(sed -n '/^version=/{s/^version=//p;q;}' "$_mp" 2>/dev/null | tr -d ' \t\r\n"')
        [ -n "$_v6_ver" ] && break
    done
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    echo "=== HNC ${_v6_ver:+$_v6_ver }v6 sync status ==="
    echo "iface: $iface"
    echo "snap dir: $SNAP_DIR"
    echo ""

    local devices; devices=$(list_marked_devices)
    if [ -z "$devices" ]; then
        echo "(no marked devices)"
        return 0
    fi

    echo "$devices" | while read -r mac mark_hex; do
        [ -z "$mac" ] && continue
        local mark_id
        mark_id=$(hnc_parse_mid_from_mark "$mark_hex" 2>/dev/null) || continue
        local prio=$((PRIO_BASE + mark_id))
        echo "----------------------------------------"
        echo "Device $mac"
        echo "  mark_id=$mark_id (mark=$mark_hex) prio=$prio"
        local addrs; addrs=$(get_v6_addrs "$mac" "$iface")
        if [ -z "$addrs" ]; then
            echo "  active v6 addresses: (none)"
        else
            echo "  active v6 addresses:"
            echo "$addrs" | sed 's/^/    /'
        fi
        local fcount; fcount=$(tc filter show dev "$iface" parent 1: 2>/dev/null \
            | awk -v p="$prio" 'BEGIN{c=0} /^filter / && $0 ~ "pref "p" " {c++} END{print c}')
        echo "  egress filters on $iface: $fcount"
    done
}

# ─── 命令分发 ────────────────────────────────────────────────
_cmd=${1:-sync}
case "$_cmd" in
    sync|sync_all|sync_one|sync_macs|clear)
        mkdir -p "$HNC_DIR/run" 2>/dev/null
        if ! v6_lock; then
            log "WARN: $_cmd: another v6_sync still running after 10s, giving up (periodic sync will retry)"
            exit 11
        fi ;;
esac
case "$_cmd" in
    sync|sync_all)  sync_all ;;
    sync_one)       sync_one "$2" ;;
    sync_macs)      shift; sync_macs "$@" ;;
    clear)          clear_one "$2" ;;
    status)         show_status ;;
    *)
        echo "Usage: $0 {sync|sync_one MAC|sync_macs MAC...|clear MAC|status}" >&2
        exit 1 ;;
esac
