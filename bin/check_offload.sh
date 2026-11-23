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

# HNC v3.4.3+ — 智能 BPF tether offload 检测 (v6.1.0-rc.4 异构节点容错增强)
# 默认输出 (stdout): NOMAP | IDLE | CAPABLE | ACTIVE
# --json / status 输出 JSON, 并原子落盘 $HNC_DIR/run/check_offload.json (含 reason_code)
# 状态优先级: NOMAP > ACTIVE > CAPABLE > IDLE

MODE_ARG="${1:-}"
BPF_DIR="${HNC_BPF_TETHER_DIR:-/sys/fs/bpf/tethering}"
P="$BPF_DIR/map_offload_tether_stats_map"
LIMIT_MAP="$BPF_DIR/map_offload_tether_limit_map"
OUT_JSON="$HNC_DIR/run/check_offload.json"
THRESHOLD=1048576   # 1 MB, 5 秒内增长低于这个值就不算 ACTIVE

if [ "$MODE_ARG" = "status" ]; then
    if [ -r "$OUT_JSON" ] && [ -s "$OUT_JSON" ]; then
        cat "$OUT_JSON" 2>/dev/null
    else
        printf '{"state":"NOMAP","available":false,"reason_code":"node_missing","detail":"status not sampled yet","ts":0}\n'
    fi
    exit 0
fi

emit_result() {
    _st="$1"
    _rc_code="$2"
    _det=$(printf '%s' "$3" | tr -d '"\\\r\n')
    _avail=true
    case "$_rc_code" in
        node_missing|permission_denied|unsupported_soc) _avail=false ;;
    esac
    _ts=$(date +%s 2>/dev/null || echo 0)
    _j=$(printf '{"state":"%s","available":%s,"reason_code":"%s","detail":"%s","ts":%s}' \
        "$_st" "$_avail" "$_rc_code" "$_det" "$_ts")
    if [ -d "$HNC_DIR/run" ] || mkdir -p "$HNC_DIR/run" 2>/dev/null; then
        _tmp="${OUT_JSON}.tmp.$$"
        if printf '%s\n' "$_j" > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
            mv -f "$_tmp" "$OUT_JSON" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
        else
            rm -f "$_tmp" 2>/dev/null || true
        fi
    fi
    if [ "$MODE_ARG" = "--json" ]; then
        printf '%s\n' "$_j"
    else
        echo "$_st"
    fi
    exit 0
}

# tc filter 链里有没有 AOSP tether offload 程序(优先走 /system/bin/tc)
tc_has_tether_prog() {
    command -v "$TC_BIN" >/dev/null 2>&1 || [ -x "$TC_BIN" ] || return 1
    _sys_net="${HNC_SYS_NET:-/sys/class/net}"
    [ -d "$_sys_net" ] && [ -r "$_sys_net" ] || return 1
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

# map 里有没有以 ifindex 开头的数据行
map_has_entry() {
    [ -f "$1" ] && [ -r "$1" ] || return 1
    grep -q '^[0-9]' "$1" 2>/dev/null
}

offload_capable() {
    tc_has_tether_prog && return 0
    map_has_entry "$LIMIT_MAP" && return 0
    map_has_entry "$P" && return 0
    return 1
}

# 节点缺失(ENOENT)与无权限(EACCES/EPERM/SELinux)分级判定
_bpf_parent="${BPF_DIR%/*}"
if [ -n "$_bpf_parent" ] && [ -e "$_bpf_parent" ] && [ ! -x "$_bpf_parent" ]; then
    if tc_has_tether_prog; then
        emit_result CAPABLE permission_denied "bpf parent directory not searchable"
    fi
    emit_result NOMAP permission_denied "bpf parent directory not searchable"
fi
if [ ! -e "$BPF_DIR" ]; then
    emit_result NOMAP node_missing "tether bpf directory missing"
fi
if [ ! -r "$BPF_DIR" ] || [ ! -x "$BPF_DIR" ]; then
    if tc_has_tether_prog; then
        emit_result CAPABLE permission_denied "tether bpf directory permission denied"
    fi
    emit_result NOMAP permission_denied "tether bpf directory permission denied"
fi
if [ ! -e "$P" ]; then
    emit_result NOMAP node_missing "tether stats map node missing"
fi
if [ ! -f "$P" ]; then
    emit_result NOMAP node_missing "tether stats map is not a regular node"
fi
if [ ! -r "$P" ]; then
    if tc_has_tether_prog; then
        emit_result CAPABLE permission_denied "tether stats map unreadable"
    fi
    emit_result NOMAP permission_denied "tether stats map unreadable"
fi

# 读出所有 entry 的 rxBytes + txBytes 总和。
# 显式校验 cat 退出码以捕获 SELinux open/read EACCES, 并用 printf "%.0f\n" 杜绝科学计数法。
_RAW1=$(cat "$P" 2>/dev/null)
_CAT_RC=$?
if [ "$_CAT_RC" -ne 0 ]; then
    if tc_has_tether_prog; then
        emit_result CAPABLE permission_denied "tether stats map read denied by kernel or SELinux"
    fi
    emit_result NOMAP permission_denied "tether stats map read denied by kernel or SELinux"
fi

sum_map_bytes() {
    printf '%s\n' "$1" \
      | grep '^[0-9]' \
      | tr ':{},' '    ' \
      | awk '{s+=$3+$6} END{printf "%.0f\n", s+0}'
}

# 在 awk 64 位浮点内完成差值比较, 彻底避开 mksh 2147483647 32 位有符号整数溢出
is_active_delta() {
    awk -v s1="${1:-0}" -v s2="${2:-0}" -v th="$THRESHOLD" 'BEGIN {
        d = (s2 + 0) - (s1 + 0)
        exit !(d >= (th + 0))
    }'
}

S1=$(sum_map_bytes "$_RAW1")
sleep "${HNC_OFFLOAD_SLEEP:-5}"
_RAW2=$(cat "$P" 2>/dev/null) || _RAW2=""
S2=$(sum_map_bytes "$_RAW2")

[ -z "$S1" ] && S1=0
[ -z "$S2" ] && S2=0

if is_active_delta "$S1" "$S2"; then
    emit_result ACTIVE qcom_tether_bpf_active "bpf tether offload actively forwarding"
elif offload_capable; then
    emit_result CAPABLE ok "bpf tether offload capable"
else
    emit_result IDLE ok "bpf tether offload idle"
fi
