#!/system/bin/sh

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

if [ -z "${HNC_TEST_MODE:-}" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ]; then
    if [ -x /system/bin/tc ]; then TC_BIN=/system/bin/tc; else TC_BIN=$(command -v tc 2>/dev/null || echo tc); fi
    if [ -x /system/bin/ip ]; then IP_BIN=/system/bin/ip; else IP_BIN=$(command -v ip 2>/dev/null || echo ip); fi
else
    TC_BIN=${TC_BIN:-$(command -v tc 2>/dev/null || echo tc)}
    IP_BIN=${IP_BIN:-$(command -v ip 2>/dev/null || echo ip)}
fi

# HNC v3.4.3+ — 智能 BPF tether offload 检测
# 输出 (stdout): NOMAP | IDLE | CAPABLE | ACTIVE
# 状态优先级: NOMAP > ACTIVE > CAPABLE > IDLE

BPF_DIR="${HNC_BPF_TETHER_DIR:-/sys/fs/bpf/tethering}"
P="$BPF_DIR/map_offload_tether_stats_map"
LIMIT_MAP="$BPF_DIR/map_offload_tether_limit_map"
THRESHOLD=1048576   # 1 MB, 5 秒内增长低于这个值就不算 ACTIVE

[ -f "$P" ] || { echo NOMAP; exit 0; }

# 读出所有 entry 的 rxBytes + txBytes 总和。
# 使用 printf "%.0f\n" 彻底根治 >1e9 时默认 print 输出科学计数法 3.05e+09 导致 shell 算术崩溃!
read_total() {
    cat "$P" 2>/dev/null \
      | grep '^[0-9]' \
      | tr ':{},' '    ' \
      | awk '{s+=$3+$6} END{printf "%.0f\n", s+0}'
}

# map 里有没有以 ifindex 开头的数据行
map_has_entry() {
    [ -f "$1" ] || return 1
    grep -q '^[0-9]' "$1" 2>/dev/null
}

# tc filter 链里有没有 AOSP tether offload 程序(优先走 /system/bin/tc)
tc_has_tether_prog() {
    command -v "$TC_BIN" >/dev/null 2>&1 || [ -x "$TC_BIN" ] || return 1
    _sys_net="${HNC_SYS_NET:-/sys/class/net}"
    [ -d "$_sys_net" ] || return 1
    for d in "$_sys_net"/*; do
        [ -e "$d" ] || continue
        i=${d##*/}
        case "$i" in
            lo|sit*|tunl*|ip6tnl*|ip_vti*|ip6_vti*|dummy*|gre*|ip6gre*) continue ;;
        esac
        if "$TC_BIN" filter show dev "$i" ingress 2>/dev/null \
             | grep -qE 'tether_(upstream|downstream)[46]'; then
            return 0
        fi
    done
    return 1
}

offload_capable() {
    tc_has_tether_prog && return 0
    map_has_entry "$LIMIT_MAP" && return 0
    map_has_entry "$P" && return 0
    return 1
}

# 在 awk 64 位浮点内完成差值比较, 彻底避开 mksh 2147483647 32 位有符号整数溢出
is_active_delta() {
    awk -v s1="${1:-0}" -v s2="${2:-0}" -v th="$THRESHOLD" 'BEGIN {
        d = (s2 + 0) - (s1 + 0)
        exit !(d >= (th + 0))
    }'
}

S1=$(read_total)
sleep "${HNC_OFFLOAD_SLEEP:-5}"
S2=$(read_total)

[ -z "$S1" ] && S1=0
[ -z "$S2" ] && S2=0

if is_active_delta "$S1" "$S2"; then
    echo ACTIVE
elif offload_capable; then
    echo CAPABLE
else
    echo IDLE
fi
