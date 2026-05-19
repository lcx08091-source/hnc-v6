#!/system/bin/sh
# HNC hotfix17.0 capability_probe.sh
# Safe tc capability probe using a disposable dummy interface. The result is
# written to /data/local/hnc/run/capabilities.json and consumed by WebUI,
# tc_manager.sh, watchdog.sh and hnc_httpd.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:/data/adb/ksu/bin:$PATH

HNC=${HNC:-/data/local/hnc}
RUN="$HNC/run"
LOGDIR="$HNC/logs"
OUT="$RUN/capabilities.json"
RAW="$RUN/capabilities.raw.log"
mkdir -p "$RUN" "$LOGDIR" 2>/dev/null || true

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [CAP] $*"; }
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r//g; s/$/\\n/' | tr -d '\n' | sed 's/\\n$//'
}

find_bin() {
    # Prefer a future bundled full iproute2 tc if present; otherwise use system tc.
    for c in "$HNC/bin/hnc_tc" "$HNC/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v tc 2>/dev/null && return 0
    echo tc
}

TC_BIN=$(find_bin)
IP_BIN=$(command -v ip 2>/dev/null || echo ip)
# rc1.22 webfix4: Linux IFNAMSIZ limits ifname to 15 chars (16 with NUL).
# Old names "hnc_probe_dummy_$$" etc were 16-21 chars and got rejected by
# `ip link add` ("dev not a valid ifname"), making capability_probe wrongly
# conclude IFB/HTB/netem/mirred are all unsupported even when the kernel
# fully supports them. Use compact prefixes; PID's last 5 digits keep names
# unique within reasonable concurrency.
__shortpid=$$
case "$__shortpid" in
    ?????*) __shortpid=$(printf '%s' "$__shortpid" | tail -c 5) ;;
esac
DUMMY="hnc_p_d_${__shortpid}"
PEER="hnc_p_p_${__shortpid}"
IFB="hnc_p_i_${__shortpid}"
TMPERR="$RUN/cap_probe_err.$$"

cleanup() {
    "$TC_BIN" qdisc del dev "$DUMMY" root >/dev/null 2>&1 || true
    "$TC_BIN" qdisc del dev "$DUMMY" clsact >/dev/null 2>&1 || true
    "$TC_BIN" qdisc del dev "$DUMMY" ingress >/dev/null 2>&1 || true
    "$IP_BIN" link del "$DUMMY" >/dev/null 2>&1 || true
    "$IP_BIN" link del "$PEER" >/dev/null 2>&1 || true
    "$IP_BIN" link del "$IFB" >/dev/null 2>&1 || true
    rm -f "$TMPERR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

run_tc() {
    : > "$TMPERR"
    "$TC_BIN" "$@" > /dev/null 2>"$TMPERR"
}
run_ip() {
    : > "$TMPERR"
    "$IP_BIN" "$@" > /dev/null 2>"$TMPERR"
}
last_err() { head -1 "$TMPERR" 2>/dev/null | tr '\r\n' ' ' | cut -c1-180; }

probe_root_qdisc() {
    # $1=name, rest=tc args after qdisc replace dev DUMMY root
    "$TC_BIN" qdisc del dev "$DUMMY" root >/dev/null 2>&1 || true
    : > "$TMPERR"
    "$TC_BIN" qdisc replace dev "$DUMMY" root "$@" > /dev/null 2>"$TMPERR"
}

reset_ingress() {
    "$TC_BIN" qdisc del dev "$DUMMY" clsact >/dev/null 2>&1 || true
    "$TC_BIN" qdisc del dev "$DUMMY" ingress >/dev/null 2>&1 || true
}
ensure_ingress_parent() {
    # rc1.22 webfix5: prefer 'ingress' qdisc over 'clsact' for filter probes.
    # Older Android iproute2 (e.g. ss171113 on ColorOS) doesn't accept
    # 'parent ffff:' (the ingress shorthand) when the actual qdisc is clsact;
    # it returns "RTNETLINK answers: Invalid argument" or
    # "Unknown action \"noact\", hence option \"drop\" is unparsable",
    # making mirred/u32/matchall/flower probes spuriously fail even though
    # the kernel fully supports them. ingress qdisc with parent ffff: is the
    # most compatible combination across iproute2 versions.
    reset_ingress
    if run_tc qdisc add dev "$DUMMY" ingress; then
        echo ingress
        return 0
    fi
    if run_tc qdisc add dev "$DUMMY" clsact; then
        echo clsact
        return 0
    fi
    echo none
    return 1
}

# Basic tc binary check.
TC_VERSION=$({ "$TC_BIN" -V 2>&1 || true; } | head -1 | tr '\r\n' ' ' | cut -c1-160)
[ -n "$TC_VERSION" ] || TC_VERSION="unknown"
TC_BINARY_OK=false
run_tc qdisc show >/dev/null 2>&1 && TC_BINARY_OK=true

DUMMY_CREATE=false
PEER_CREATE=false
if run_ip link add dev "$DUMMY" type dummy; then
    DUMMY_CREATE=true
    run_ip link set dev "$DUMMY" up || true
fi
if run_ip link add dev "$PEER" type dummy; then
    PEER_CREATE=true
    run_ip link set dev "$PEER" up || true
fi

# Defaults: null means unknown/unsafe to decide. Existing HNC gates only disable on explicit false.
TC_HTB=null; TC_HTB_ERR=""
TC_TBF=null; TC_TBF_ERR=""
TC_FQ_CODEL=null; TC_FQ_CODEL_ERR=""
TC_CAKE=null; TC_CAKE_ERR=""
TC_CAKE_AUTORATE=null; TC_CAKE_AUTORATE_ERR=""
TC_NETEM=null; TC_NETEM_ERR=""
TC_INGRESS=null; TC_CLSACT=null; TC_U32=null; TC_FLOWER=null; TC_MATCHALL=null; TC_POLICE=null; TC_MIRRED=null
TC_U32_ERR=""; TC_FLOWER_ERR=""; TC_MATCHALL_ERR=""; TC_POLICE_ERR=""; TC_MIRRED_ERR=""

if [ "$DUMMY_CREATE" = true ] && [ "$TC_BINARY_OK" = true ]; then
    if probe_root_qdisc handle 1: htb default 9999; then TC_HTB=true; else TC_HTB=false; TC_HTB_ERR=$(last_err); fi
    if probe_root_qdisc tbf rate 1mbit burst 32kbit latency 400ms; then TC_TBF=true; else TC_TBF=false; TC_TBF_ERR=$(last_err); fi
    # v5.3 Smart Queue foundation: detect low-latency qdiscs on dummy only.
    # CAKE/fq_codel are optional; never use them unless a later layer explicitly enables SQM.
    if probe_root_qdisc fq_codel; then TC_FQ_CODEL=true; else TC_FQ_CODEL=false; TC_FQ_CODEL_ERR=$(last_err); fi
    if probe_root_qdisc cake; then TC_CAKE=true; else TC_CAKE=false; TC_CAKE_ERR=$(last_err); fi
    if [ "$TC_CAKE" = true ]; then
        if probe_root_qdisc cake autorate-ingress; then TC_CAKE_AUTORATE=true; else TC_CAKE_AUTORATE=false; TC_CAKE_AUTORATE_ERR=$(last_err); fi
    else
        TC_CAKE_AUTORATE=false
        TC_CAKE_AUTORATE_ERR="$TC_CAKE_ERR"
    fi
    if probe_root_qdisc netem delay 50ms; then TC_NETEM=true; else TC_NETEM=false; TC_NETEM_ERR=$(last_err); fi
    "$TC_BIN" qdisc del dev "$DUMMY" root >/dev/null 2>&1 || true

    reset_ingress
    if run_tc qdisc add dev "$DUMMY" ingress; then TC_INGRESS=true; else TC_INGRESS=false; fi
    reset_ingress
    if run_tc qdisc add dev "$DUMMY" clsact; then TC_CLSACT=true; else TC_CLSACT=false; fi

    PARENT=$(ensure_ingress_parent)
    if [ "$PARENT" != none ]; then
        if run_tc filter add dev "$DUMMY" parent ffff: protocol ip prio 10 u32 match ip src 0.0.0.0/0; then
            TC_U32=true
        else
            TC_U32=false; TC_U32_ERR=$(last_err)
        fi
        "$TC_BIN" filter del dev "$DUMMY" parent ffff: >/dev/null 2>&1 || true

        if run_tc filter add dev "$DUMMY" parent ffff: protocol ip prio 11 u32 match ip src 0.0.0.0/0 police rate 1mbit burst 32k drop; then
            TC_POLICE=true
        else
            TC_POLICE=false; TC_POLICE_ERR=$(last_err)
        fi
        "$TC_BIN" filter del dev "$DUMMY" parent ffff: >/dev/null 2>&1 || true

        if [ "$PEER_CREATE" = true ] && run_tc filter add dev "$DUMMY" parent ffff: protocol ip prio 12 u32 match ip src 0.0.0.0/0 action mirred egress redirect dev "$PEER"; then
            TC_MIRRED=true
        else
            TC_MIRRED=false; TC_MIRRED_ERR=$(last_err)
        fi
        "$TC_BIN" filter del dev "$DUMMY" parent ffff: >/dev/null 2>&1 || true

        if run_tc filter add dev "$DUMMY" parent ffff: protocol ip prio 13 matchall action drop; then
            TC_MATCHALL=true
        else
            TC_MATCHALL=false; TC_MATCHALL_ERR=$(last_err)
        fi
        "$TC_BIN" filter del dev "$DUMMY" parent ffff: >/dev/null 2>&1 || true

        if run_tc filter add dev "$DUMMY" parent ffff: protocol ip prio 14 flower src_ip 0.0.0.0/0 action drop; then
            TC_FLOWER=true
        else
            TC_FLOWER=false; TC_FLOWER_ERR=$(last_err)
        fi
        "$TC_BIN" filter del dev "$DUMMY" parent ffff: >/dev/null 2>&1 || true
    fi
fi

IFB_CREATE=false
if run_ip link add dev "$IFB" type ifb; then
    IFB_CREATE=true
    run_ip link del "$IFB" || true
fi

# Compatibility + mode decisions.
UPLINK_SUPPORTED=false
[ "$IFB_CREATE" = true ] && [ "$TC_MIRRED" = true ] && [ "$TC_HTB" = true ] && UPLINK_SUPPORTED=true
UPLINK_POLICE_SUPPORTED=false
[ "$TC_POLICE" = true ] && UPLINK_POLICE_SUPPORTED=true

DOWNLINK_MODE=unknown
if [ "$TC_HTB" = true ]; then DOWNLINK_MODE=htb; elif [ "$TC_TBF" = true ]; then DOWNLINK_MODE=tbf_global; elif [ "$TC_HTB" = false ]; then DOWNLINK_MODE=unsupported; fi
# v5.2.1 D-1: 当 qos_fallback_required=true 时, downlink_mode 改为 root_htb.
# 背景: webroot/index.html:3702 和 tc_manager.sh:127 都判 downlink_mode == 'root_htb'
# 来决定是否走 fallback, 但 capability_probe 之前从来不写这个值. 那两处判定一直
# 是死代码, 仅靠旁边的 qos_fallback_required 字段救场. D-1 让 enum 真正对齐:
# fallback 模式下输出 root_htb (语义: 走 root htb 而不是 mq child htb).
if [ -s "$RUN/tc_qos_fallback" ] && [ "$DOWNLINK_MODE" = "htb" ]; then
    DOWNLINK_MODE=root_htb
fi
UPLINK_MODE=unsupported
if [ "$UPLINK_SUPPORTED" = true ]; then UPLINK_MODE=ifb_htb; elif [ "$UPLINK_POLICE_SUPPORTED" = true ]; then UPLINK_MODE=police; fi
DELAY_MODE=unknown
if [ "$TC_NETEM" = true ] && [ "$TC_HTB" = true ]; then DELAY_MODE=netem; elif [ "$TC_NETEM" = false ] || [ "$TC_HTB" = false ]; then DELAY_MODE=unsupported; fi
SQM_SUPPORTED=false
SQM_RECOMMENDED_MODE=off
if [ "$TC_FQ_CODEL" = true ] || [ "$TC_CAKE" = true ]; then
    SQM_SUPPORTED=true
    if [ "$TC_CAKE" = true ]; then SQM_RECOMMENDED_MODE=cake; else SQM_RECOMMENDED_MODE=fq_codel; fi
fi

IFACE=""
[ -f "$RUN/iface.cache" ] && IFACE=$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n')
REAL_QDISC=""
if [ -n "$IFACE" ]; then
    REAL_QDISC=$("$TC_BIN" qdisc show dev "$IFACE" 2>&1 | head -3 | tr '\r\n' ' ' | cut -c1-240)
fi

# hotfix17.5: surface root-HTB fallback and QoS profile to WebUI.
QOS_MODE=$(cat "$RUN/tc_qos_mode" 2>/dev/null | head -1 | tr -d '\r\n ' | tr 'A-Z' 'a-z')
case "$QOS_MODE" in precise|precision|strict|accurate) QOS_MODE=precise ;; *) QOS_MODE=compat ;; esac
QOS_FALLBACK_REQUIRED=false
[ -s "$RUN/tc_qos_fallback" ] && QOS_FALLBACK_REQUIRED=true

NOW=$(date +%s 2>/dev/null || echo 0)

# ═══════════════════════════════════════════════════════════════════════════════
# rc30.12 新增: fork / launcher / 安全机制 兼容性探测
# 为什么:Go runtime 用 CLONE_VM|CLONE_VFORK 在某些国产 ROM (ColorOS 16 + SukiSU)
# 被内核 hook 拦截, fork+exec 必报 EPERM. C bionic fork 不带 CLONE_VM, 不受影响.
# 详见 PATCH-NOTES-v5.3.0-rc30.12.3.md 和 ARCHITECTURE.md.
# 这些字段被 WebUI 设置页"兼容性能力"卡片读取, 也供 diag.sh 一键诊断.
# ═══════════════════════════════════════════════════════════════════════════════

# C fork+execv 是否工作 (用 fork_probe 验证)
FORK_PROBE_PRESENT=false
C_FORK_OK=false
if [ -x "$HNC/bin/fork_probe" ]; then
    FORK_PROBE_PRESENT=true
    if "$HNC/bin/fork_probe" /system/bin/true >/dev/null 2>&1; then
        C_FORK_OK=true
    fi
fi

# Go fork+execv 是否工作 (用 gofork_probe 验证, 可能没有)
GO_FORK_TESTED=false
GO_FORK_OK=false
if [ -x "$HNC/bin/diag/gofork_probe" ]; then
    GO_FORK_TESTED=true
    if "$HNC/bin/diag/gofork_probe" >/dev/null 2>&1; then
        GO_FORK_OK=true
    fi
fi

# 推断:内核是否拦截 CLONE_VM
# 如果 C fork ok 但 Go fork 失败, 几乎必然是 CLONE_VM hook 拦截
KERNEL_BLOCKS_CLONE_VM=false
if [ "$GO_FORK_TESTED" = "true" ] && [ "$C_FORK_OK" = "true" ] && [ "$GO_FORK_OK" = "false" ]; then
    KERNEL_BLOCKS_CLONE_VM=true
fi

# 当前使用的 launcher 路径
SELECTED_LAUNCHER="unknown"
if pidof hnc_launcher >/dev/null 2>&1; then
    SELECTED_LAUNCHER="c_launcher"
elif pgrep -f "hnc_dpid_guard.sh" >/dev/null 2>&1; then
    SELECTED_LAUNCHER="shell_guard"
elif pidof hnc_dpid_supervisor >/dev/null 2>&1; then
    SELECTED_LAUNCHER="go_supervisor"
fi

# hnc_launcher 是否存在
HNC_LAUNCHER_PRESENT=false
[ -x "$HNC/bin/hnc_launcher" ] && HNC_LAUNCHER_PRESENT=true

# dpid 是否含 rc30.12.3 字符串匹配 retry 修复
DPID_HAS_IFACE_RETRY=false
DPID_VERSION="unknown"
if [ -x "$HNC/bin/hnc_dpid" ]; then
    if strings "$HNC/bin/hnc_dpid" 2>/dev/null | grep -q "iface-retry"; then
        DPID_HAS_IFACE_RETRY=true
    fi
    DPID_VERSION=$(strings "$HNC/bin/hnc_dpid" 2>/dev/null | grep -oE "0\\.5\\.3-rc[0-9.]+[-a-z]*" | head -1)
    [ -z "$DPID_VERSION" ] && DPID_VERSION="unknown"
fi

# SELinux 状态
SELINUX_ENFORCING=false
if [ -x /system/bin/getenforce ]; then
    case "$(/system/bin/getenforce 2>/dev/null)" in
        Enforcing) SELINUX_ENFORCING=true ;;
    esac
fi

# 最近 24h 内 HNC 相关 AVC denied 计数
SELINUX_AVC_DENIED_COUNT=0
if [ -r /dev/kmsg ] || dmesg >/dev/null 2>&1; then
    SELINUX_AVC_DENIED_COUNT=$(dmesg 2>/dev/null | grep -ciE "avc.*denied.*(hnc|dpid|hotspotd|launcher)" 2>/dev/null || echo 0)
fi

# 当前进程的 Seccomp / NoNewPrivs / CapEff
SECCOMP_ACTIVE=false
NO_NEW_PRIVS=false
CAP_EFF_FULL=false
if [ -r "/proc/self/status" ]; then
    SEC_VAL=$(grep '^Seccomp:' /proc/self/status 2>/dev/null | awk '{print $2}')
    [ "$SEC_VAL" != "0" ] && [ -n "$SEC_VAL" ] && SECCOMP_ACTIVE=true
    NNP_VAL=$(grep '^NoNewPrivs:' /proc/self/status 2>/dev/null | awk '{print $2}')
    [ "$NNP_VAL" = "1" ] && NO_NEW_PRIVS=true
    CAP_EFF=$(grep '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')
    # CapEff=000001ffffffffff 是 full caps (41 bits, ambient included)
    case "$CAP_EFF" in 000001ffffffffff|1ffffffffff|ffffffffff) CAP_EFF_FULL=true ;; esac
fi

# 当前进程的 SELinux domain
SU_DOMAIN="unknown"
if [ -r /proc/self/attr/current ]; then
    SU_DOMAIN=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\0\r\n' | cut -c1-64)
    [ -z "$SU_DOMAIN" ] && SU_DOMAIN="unknown"
fi

TMP="$OUT.tmp.$$"
cat > "$TMP" <<EOF_JSON
{
  "schema": 2,
  "generated_at": $NOW,
  "probe": "hotfix17_dummy_sandbox",
  "tc_binary": "$(json_escape "$TC_BIN")",
  "tc_binary_source": "$(case "$TC_BIN" in "$HNC"/*) echo bundled ;; *) echo system ;; esac)",
  "tc_binary_ok": $TC_BINARY_OK,
  "tc_version": "$(json_escape "$TC_VERSION")",
  "dummy_create": $DUMMY_CREATE,
  "dummy_iface": "$(json_escape "$DUMMY")",
  "probe_iface": "$(json_escape "$IFACE")",
  "probe_iface_qdisc": "$(json_escape "$REAL_QDISC")",
  "tc_qos_mode": "$(json_escape "$QOS_MODE")",
  "qos_fallback_required": $QOS_FALLBACK_REQUIRED,

  "tc_htb": $TC_HTB,
  "tc_htb_supported": $TC_HTB,
  "tc_htb_error": "$(json_escape "$TC_HTB_ERR")",
  "tc_tbf_supported": $TC_TBF,
  "tc_tbf_error": "$(json_escape "$TC_TBF_ERR")",
  "tc_fq_codel": $TC_FQ_CODEL,
  "tc_fq_codel_supported": $TC_FQ_CODEL,
  "tc_fq_codel_error": "$(json_escape "$TC_FQ_CODEL_ERR")",
  "tc_cake": $TC_CAKE,
  "tc_cake_supported": $TC_CAKE,
  "tc_cake_error": "$(json_escape "$TC_CAKE_ERR")",
  "tc_cake_autorate_ingress_supported": $TC_CAKE_AUTORATE,
  "tc_cake_autorate_ingress_error": "$(json_escape "$TC_CAKE_AUTORATE_ERR")",
  "sqm_supported": $SQM_SUPPORTED,
  "sqm_recommended_mode": "$(json_escape "$SQM_RECOMMENDED_MODE")",
  "tc_netem": $TC_NETEM,
  "tc_netem_supported": $TC_NETEM,
  "tc_netem_error": "$(json_escape "$TC_NETEM_ERR")",
  "tc_ingress_supported": $TC_INGRESS,
  "tc_clsact_supported": $TC_CLSACT,
  "tc_u32_supported": $TC_U32,
  "tc_u32_error": "$(json_escape "$TC_U32_ERR")",
  "tc_flower_supported": $TC_FLOWER,
  "tc_flower_error": "$(json_escape "$TC_FLOWER_ERR")",
  "tc_matchall": $TC_MATCHALL,
  "tc_matchall_supported": $TC_MATCHALL,
  "tc_matchall_error": "$(json_escape "$TC_MATCHALL_ERR")",
  "tc_police_supported": $TC_POLICE,
  "tc_police_error": "$(json_escape "$TC_POLICE_ERR")",
  "tc_mirred": $TC_MIRRED,
  "tc_mirred_supported": $TC_MIRRED,
  "tc_mirred_error": "$(json_escape "$TC_MIRRED_ERR")",
  "tc_ifb": $IFB_CREATE,
  "tc_ifb_create": $IFB_CREATE,
  "ifb_supported": $IFB_CREATE,

  "uplink_supported": $UPLINK_SUPPORTED,
  "uplink_police_supported": $UPLINK_POLICE_SUPPORTED,
  "downlink_mode": "$(json_escape "$DOWNLINK_MODE")",
  "uplink_mode": "$(json_escape "$UPLINK_MODE")",
  "delay_mode": "$(json_escape "$DELAY_MODE")",

  "fork_compat_schema": 1,
  "c_fork_supported": $C_FORK_OK,
  "go_fork_supported": $GO_FORK_OK,
  "go_fork_tested": $GO_FORK_TESTED,
  "kernel_blocks_clone_vm": $KERNEL_BLOCKS_CLONE_VM,
  "selected_launcher": "$(json_escape "$SELECTED_LAUNCHER")",
  "fork_probe_present": $FORK_PROBE_PRESENT,
  "hnc_launcher_present": $HNC_LAUNCHER_PRESENT,
  "dpid_has_iface_retry": $DPID_HAS_IFACE_RETRY,
  "dpid_version": "$(json_escape "$DPID_VERSION")",

  "selinux_enforcing": $SELINUX_ENFORCING,
  "selinux_avc_denied_recent": $SELINUX_AVC_DENIED_COUNT,
  "seccomp_active": $SECCOMP_ACTIVE,
  "no_new_privs": $NO_NEW_PRIVS,
  "cap_eff_full": $CAP_EFF_FULL,
  "su_domain": "$(json_escape "$SU_DOMAIN")"
}
EOF_JSON

mv -f "$TMP" "$OUT" 2>/dev/null || cp -f "$TMP" "$OUT" 2>/dev/null
chmod 644 "$OUT" 2>/dev/null || true

{
    log "tc=$TC_BIN version=$TC_VERSION dummy=$DUMMY_CREATE htb=$TC_HTB tbf=$TC_TBF fq_codel=$TC_FQ_CODEL cake=$TC_CAKE cake_autorate=$TC_CAKE_AUTORATE netem=$TC_NETEM ifb=$IFB_CREATE mirred=$TC_MIRRED police=$TC_POLICE"
    log "modes: downlink=$DOWNLINK_MODE uplink=$UPLINK_MODE delay=$DELAY_MODE sqm=$SQM_RECOMMENDED_MODE qos=$QOS_MODE fallback=$QOS_FALLBACK_REQUIRED iface=$IFACE qdisc=$REAL_QDISC"
} | tee "$RAW" 2>/dev/null


# rc1.22 webfix6: clear stale "unsupported" markers when probe re-confirms support.
# These markers are written by tc_manager.sh / watchdog.sh on first failure and
# never cleared; once they exist runtime checks short-circuit to "unsupported"
# even if subsequent probes confirm capability is fine. Clear them here so a
# successful re-probe heals all dependent code paths.
if [ "$UPLINK_SUPPORTED" = true ]; then
    rm -f "$RUN/uplink_unsupported" "$RUN/uplink_fail_count" "$RUN/uplink_unsupported_logged" 2>/dev/null || true
fi
if [ "$TC_HTB" = true ] && [ "$TC_NETEM" = true ]; then
    rm -f "$RUN/tc_netem_unsupported_logged" "$RUN/tc_htb_unsupported_logged" 2>/dev/null || true
fi
if [ "$DOWNLINK_MODE" = "htb" ]; then
    # 真正精确模式 (mq child htb 等高精度路径) confirmed; 清 root-htb fallback marker.
    # v5.2.1 D-1 修复后, "精确模式" = downlink_mode=="htb" (非 root_htb / htb_root / tbf_global).
    # 之前这里判 "!= root_htb && != htb_root", 由于 probe 从不写 root_htb, 条件永远成立,
    # 每次 probe 都清 fallback marker — 把 fallback 状态意外重置. 现在显式只有 htb 时才清.
    rm -f "$RUN/tc_qos_fallback" 2>/dev/null || true
fi

exit 0
