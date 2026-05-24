#!/system/bin/sh
# HNC v5.3 Smart Queue / SQM manager
# Low-risk controller for fq_codel/CAKE leaf mode. It never rewrites system BPF,
# never replaces the hotspot root qdisc directly, and defaults to off.
# v5.3.0-rc7: apply is incremental and only touches the default HTB leaf (1:9999).
# v5.3.0-rc10: if the hotspot iface is absent/offline, settings are saved and
# apply is skipped successfully instead of surfacing a generic SQM failure.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:/data/adb/ksu/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
DATA="$HNC_DIR/data"
LOG="$HNC_DIR/logs/sqm.log"
CAP_FILE="$RUN/capabilities.json"
RULES_FILE="$DATA/rules.json"
SQM_MODE_FILE="$RUN/sqm_mode"
SQM_PROFILE_FILE="$RUN/sqm_profile"
SQM_PRESET_FILE="$RUN/sqm_preset"
SQM_DIAG_LAST="$RUN/sqm_gray_diag.latest"
mkdir -p "$RUN" "$DATA" "$(dirname "$LOG")" 2>/dev/null || true

log() { echo "[$(date '+%H:%M:%S')] [SQM] $*" >> "$LOG" 2>/dev/null || true; }
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r//g; s/$/\\n/' | tr -d '\n' | sed 's/\\n$//'; }

find_tc() {
    for c in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v tc 2>/dev/null || echo tc
}
TC_BIN=$(find_tc)

iface_exists() {
    local iface=$1
    [ -n "$iface" ] || return 1
    if command -v ip >/dev/null 2>&1; then
        ip link show dev "$iface" >/dev/null 2>&1 && return 0
    fi
    [ -d "/sys/class/net/$iface" ] && return 0
    return 1
}

json_top_string() {
    local key=$1 file=${2:-$RULES_FILE}
    [ -f "$file" ] || return 1
    tr -d '\n' < "$file" 2>/dev/null \
        | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1
}

norm_mode() {
    local v
    v=$(printf '%s' "$1" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    case "$v" in
        off|disable|disabled|0|false|no|"") echo off ;;
        fq|fq-codel|fqcodel|fq_codel|lowlatency|low-latency) echo fq_codel ;;
        cake) echo cake ;;
        game|gaming) echo game ;;
        auto|smart|sqm) echo auto ;;
        *) echo invalid ;;
    esac
}


norm_profile() {
    local v
    v=$(printf '%s' "$1" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    case "$v" in
        balanced|balance|default|"") echo balanced ;;
        game|gaming) echo game ;;
        bulk|download|downloading) echo bulk ;;
        custom) echo custom ;;
        *) echo balanced ;;
    esac
}

norm_preset() {
    local v
    v=$(printf '%s' "$1" | tr -d '\r\n ' | tr 'A-Z' 'a-z')
    case "$v" in
        off|none|clear|0|false|no|"") echo off ;;
        balanced|balance|normal|default) echo balanced ;;
        game|gaming|lowlatency|low-latency) echo game ;;
        weak|weaknet|weak-net|drift|jitter) echo weaknet ;;
        poor|bad|badnet|bad-net) echo poor ;;
        extreme|lab|stress) echo extreme ;;
        custom) echo custom ;;
        *) echo invalid ;;
    esac
}

current_preset() {
    local v
    v=$(cat "$SQM_PRESET_FILE" 2>/dev/null | head -1)
    [ -n "$v" ] || v=$(json_top_string sqm_preset 2>/dev/null || echo off)
    norm_preset "$v"
}

preset_field() {
    local preset field
    preset=$(norm_preset "$1")
    field=$2
    case "$preset:$field" in
        off:label) echo "关闭" ;; off:mode) echo off ;; off:profile) echo balanced ;; off:down) echo 0 ;; off:up) echo 0 ;; off:delay) echo 0 ;; off:jitter) echo 0 ;; off:loss) echo 0 ;; off:note) echo "不改变设备规则，仅关闭预设选择" ;;
        balanced:label) echo "均衡低延迟" ;; balanced:mode) echo auto ;; balanced:profile) echo balanced ;; balanced:down) echo 0 ;; balanced:up) echo 0 ;; balanced:delay) echo 0 ;; balanced:jitter) echo 0 ;; balanced:loss) echo 0 ;; balanced:note) echo "优先降低排队延迟，不主动制造弱网" ;;
        game:label) echo "游戏优先" ;; game:mode) echo game ;; game:profile) echo game ;; game:down) echo 10 ;; game:up) echo 10 ;; game:delay) echo 20 ;; game:jitter) echo 5 ;; game:loss) echo 0 ;; game:note) echo "适合游戏/语音，轻微延迟用于复现抖动，不强制应用" ;;
        weaknet:label) echo "弱网测试" ;; weaknet:mode) echo auto ;; weaknet:profile) echo custom ;; weaknet:down) echo 1 ;; weaknet:up) echo 0.5 ;; weaknet:delay) echo 200 ;; weaknet:jitter) echo 50 ;; weaknet:loss) echo 3 ;; weaknet:note) echo "用于单设备弱网复现，选择后 WebUI 可一键填入限速/延迟输入框" ;;
        poor:label) echo "较差网络" ;; poor:mode) echo auto ;; poor:profile) echo custom ;; poor:down) echo 0.5 ;; poor:up) echo 0.25 ;; poor:delay) echo 350 ;; poor:jitter) echo 90 ;; poor:loss) echo 6 ;; poor:note) echo "更激进的测试档，建议只对测试设备使用" ;;
        extreme:label) echo "极差实验" ;; extreme:mode) echo off ;; extreme:profile) echo custom ;; extreme:down) echo 0.2 ;; extreme:up) echo 0.1 ;; extreme:delay) echo 800 ;; extreme:jitter) echo 150 ;; extreme:loss) echo 10 ;; extreme:note) echo "实验室压力档，不建议日常使用" ;;
        custom:label) echo "自定义" ;; custom:mode) echo auto ;; custom:profile) echo custom ;; custom:down) echo 0 ;; custom:up) echo 0 ;; custom:delay) echo 0 ;; custom:jitter) echo 0 ;; custom:loss) echo 0 ;; custom:note) echo "保留用户自定义输入" ;;
        *) echo "" ;;
    esac
}

preset_one_json() {
    case "$(norm_preset "$1")" in
        off) echo '{"id":"off","label":"关闭","mode":"off","profile":"balanced","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"不改变设备规则，仅关闭预设选择"}' ;;
        balanced) echo '{"id":"balanced","label":"均衡低延迟","mode":"auto","profile":"balanced","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"优先降低排队延迟，不主动制造弱网"}' ;;
        game) echo '{"id":"game","label":"游戏优先","mode":"game","profile":"game","down_mbps":10,"up_mbps":10,"delay_ms":20,"jitter_ms":5,"loss_pct":0,"note":"适合游戏/语音，轻微延迟用于复现抖动，不强制应用"}' ;;
        weaknet) echo '{"id":"weaknet","label":"弱网测试","mode":"auto","profile":"custom","down_mbps":1,"up_mbps":0.5,"delay_ms":200,"jitter_ms":50,"loss_pct":3,"note":"用于单设备弱网复现，选择后 WebUI 可一键填入限速/延迟输入框"}' ;;
        poor) echo '{"id":"poor","label":"较差网络","mode":"auto","profile":"custom","down_mbps":0.5,"up_mbps":0.25,"delay_ms":350,"jitter_ms":90,"loss_pct":6,"note":"更激进的测试档，建议只对测试设备使用"}' ;;
        extreme) echo '{"id":"extreme","label":"极差实验","mode":"off","profile":"custom","down_mbps":0.2,"up_mbps":0.1,"delay_ms":800,"jitter_ms":150,"loss_pct":10,"note":"实验室压力档，不建议日常使用"}' ;;
        custom) echo '{"id":"custom","label":"自定义","mode":"auto","profile":"custom","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"保留用户自定义输入"}' ;;
        *) return 1 ;;
    esac
}

presets_json_array() {
    cat <<'EOF_PRESETS'
[{"id":"off","label":"关闭","mode":"off","profile":"balanced","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"不改变设备规则，仅关闭预设选择"},{"id":"balanced","label":"均衡低延迟","mode":"auto","profile":"balanced","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"优先降低排队延迟，不主动制造弱网"},{"id":"game","label":"游戏优先","mode":"game","profile":"game","down_mbps":10,"up_mbps":10,"delay_ms":20,"jitter_ms":5,"loss_pct":0,"note":"适合游戏/语音，轻微延迟用于复现抖动，不强制应用"},{"id":"weaknet","label":"弱网测试","mode":"auto","profile":"custom","down_mbps":1,"up_mbps":0.5,"delay_ms":200,"jitter_ms":50,"loss_pct":3,"note":"用于单设备弱网复现，选择后 WebUI 可一键填入限速/延迟输入框"},{"id":"poor","label":"较差网络","mode":"auto","profile":"custom","down_mbps":0.5,"up_mbps":0.25,"delay_ms":350,"jitter_ms":90,"loss_pct":6,"note":"更激进的测试档，建议只对测试设备使用"},{"id":"extreme","label":"极差实验","mode":"off","profile":"custom","down_mbps":0.2,"up_mbps":0.1,"delay_ms":800,"jitter_ms":150,"loss_pct":10,"note":"实验室压力档，不建议日常使用"},{"id":"custom","label":"自定义","mode":"auto","profile":"custom","down_mbps":0,"up_mbps":0,"delay_ms":0,"jitter_ms":0,"loss_pct":0,"note":"保留用户自定义输入"}]
EOF_PRESETS
}

write_preset() {
    local preset=$1 mode profile
    preset=$(norm_preset "$preset")
    [ "$preset" = invalid ] && return 2
    echo "$preset" > "$SQM_PRESET_FILE" 2>/dev/null || return 1
    mode=$(preset_field "$preset" mode)
    profile=$(preset_field "$preset" profile)
    [ -n "$mode" ] && write_mode "$mode" >/dev/null 2>&1 || true
    [ -n "$profile" ] && echo "$profile" > "$SQM_PROFILE_FILE" 2>/dev/null || true
    if [ -z "$HNC_TEST_MODE" ] && [ -x "$HNC_DIR/bin/json_set.sh" ]; then
        HNC="$HNC_DIR" sh "$HNC_DIR/bin/json_set.sh" top sqm_preset "$preset" >/dev/null 2>&1 || true
        [ -n "$profile" ] && HNC="$HNC_DIR" sh "$HNC_DIR/bin/json_set.sh" top sqm_profile "$profile" >/dev/null 2>&1 || true
    fi
    log "preset set to $preset mode=$mode profile=$profile"
}

current_mode() {
    local v
    v=$(cat "$SQM_MODE_FILE" 2>/dev/null | head -1)
    [ -n "$v" ] || v=$(json_top_string sqm_mode 2>/dev/null || echo off)
    norm_mode "$v"
}

cap_bool() {
    local key=$1
    [ -f "$CAP_FILE" ] || { echo unknown; return 0; }
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*true" "$CAP_FILE" 2>/dev/null; then echo true; return 0; fi
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*false" "$CAP_FILE" 2>/dev/null; then echo false; return 0; fi
    echo unknown
}

cap_string() {
    local key=$1
    [ -f "$CAP_FILE" ] || return 1
    tr -d '\n' < "$CAP_FILE" 2>/dev/null \
        | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1
}

recommended_mode() {
    local cake fqc rec
    cake=$(cap_bool tc_cake_supported)
    fqc=$(cap_bool tc_fq_codel_supported)
    rec=$(cap_string sqm_recommended_mode 2>/dev/null || echo "")
    [ -n "$rec" ] && [ "$rec" != "off" ] && { echo "$rec"; return 0; }
    [ "$cake" = true ] && { echo cake; return 0; }
    [ "$fqc" = true ] && { echo fq_codel; return 0; }
    echo off
}

mode_available() {
    local mode=$1 cake fqc
    cake=$(cap_bool tc_cake_supported)
    fqc=$(cap_bool tc_fq_codel_supported)
    case "$mode" in
        off) return 0 ;;
        fq_codel|game) [ "$fqc" != false ] ;;
        cake) [ "$cake" != false ] ;;
        auto) [ "$cake" != false ] || [ "$fqc" != false ] ;;
        *) return 1 ;;
    esac
}

write_mode() {
    local mode=$1
    echo "$mode" > "$SQM_MODE_FILE" 2>/dev/null || return 1
    if [ -z "$HNC_TEST_MODE" ] && [ -x "$HNC_DIR/bin/json_set.sh" ]; then
        HNC="$HNC_DIR" sh "$HNC_DIR/bin/json_set.sh" top sqm_mode "$mode" >/dev/null 2>&1 || true
    fi
    log "mode set to $mode"
}

# v5.3.0-rc7: choose the actual leaf qdisc to apply. CAKE is never attempted
# unless capability_probe confirmed it; unsupported CAKE falls back to fq_codel.
effective_leaf_for_apply() {
    local mode cake fqc rec
    mode=$(current_mode)
    cake=$(cap_bool tc_cake_supported)
    fqc=$(cap_bool tc_fq_codel_supported)
    case "$mode" in
        off) echo off ;;
        cake)
            if [ "$cake" = true ]; then echo cake; elif [ "$fqc" != false ]; then echo fq_codel; else echo off; fi ;;
        fq_codel|game)
            if [ "$fqc" != false ]; then echo fq_codel; else echo off; fi ;;
        auto)
            rec=$(recommended_mode)
            if [ "$rec" = cake ] && [ "$cake" = true ]; then echo cake; return 0; fi
            if [ "$fqc" != false ]; then echo fq_codel; return 0; fi
            if [ "$cake" = true ]; then echo cake; return 0; fi
            echo off ;;
        *) echo off ;;
    esac
}

leaf_has_active_netem_on_parent() {
    local iface=$1 parent=$2 line delay loss
    line=$($TC_BIN qdisc show dev "$iface" 2>/dev/null | grep "parent $parent" | grep netem | head -1)
    [ -n "$line" ] || return 1
    delay=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="delay") {print $(i+1); exit}}')
    loss=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="loss") {print $(i+1); exit}}' | tr -d '%')
    case "$delay" in ""|0ms|0us|0s) : ;; *) return 0 ;; esac
    awk -v v="${loss:-0}" 'BEGIN{exit !(v+0 > 0)}' && return 0
    return 1
}

apply_default_leaf() {
    local iface=${1:-} kind out rc=0
    [ -n "$iface" ] || iface=$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n')
    if [ -z "$iface" ]; then
        log "apply skipped reason=iface-unknown; settings saved"
        echo "WARN: hotspot iface unknown; SQM settings saved; open hotspot to apply" >&2
        return 0
    fi
    if ! iface_exists "$iface"; then
        log "apply skipped iface=$iface reason=iface-not-present; settings saved"
        echo "WARN: hotspot iface '$iface' is not present; SQM settings saved; open hotspot to apply" >&2
        return 0
    fi

    kind=$(effective_leaf_for_apply)
    out=$($TC_BIN qdisc show dev "$iface" 2>/dev/null || true)
    if ! echo "$out" | grep -q 'qdisc htb 1:'; then
        # rc19: SQM apply used to hard-fail (rc=3 "HTB root not found") whenever no
        # per-device limit had ever been set — the HTB tree is built lazily on the
        # first set_limit and nothing builds it on hotspot-up, so on a normal hotspot
        # EVERY SQM click errored ("SQM 切换失败"). Bootstrap the tree here so SQM
        # works standalone (applies the AQM leaf on the default class 1:9999).
        log "apply: HTB root missing on $iface; bootstrapping via tc_manager.sh init"
        sh "$HNC_DIR/bin/tc_manager.sh" init "$iface" >/dev/null 2>&1 || true
        out=$($TC_BIN qdisc show dev "$iface" 2>/dev/null || true)
        if ! echo "$out" | grep -q 'qdisc htb 1:'; then
            log "apply skipped iface=$iface reason=htb-bootstrap-failed; settings saved"
            echo "WARN: HTB tree could not be created on $iface; SQM settings saved, will apply once limiting is active" >&2
            return 0
        fi
    fi
    if ! $TC_BIN class show dev "$iface" 2>/dev/null | grep -q 'class htb 1:9999'; then
        log "apply skipped iface=$iface reason=default-class-missing-after-init; settings saved"
        echo "WARN: default class 1:9999 not present on $iface; SQM settings saved" >&2
        return 0
    fi

    # Do not overwrite a real netem default leaf. Device-specific netem classes are
    # separate, but this guard protects unusual fallback layouts.
    if leaf_has_active_netem_on_parent "$iface" '1:9999'; then
        log "apply skipped iface=$iface parent=1:9999 reason=active-netem-preserved"
        echo "WARN: default parent 1:9999 has active netem; SQM leaf preserved" >&2
        return 0
    fi

    case "$kind" in
        fq_codel)
            $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: fq_codel target 5ms interval 100ms quantum 1514 limit 1024 2>/dev/null                 || $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: fq_codel 2>/dev/null                 || rc=$? ;;
        cake)
            $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: cake besteffort 2>/dev/null                 || $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: cake 2>/dev/null                 || rc=$?
            if [ "${rc:-0}" -ne 0 ] && [ "$(cap_bool tc_fq_codel_supported)" != false ]; then
                rc=0
                $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: fq_codel target 5ms interval 100ms quantum 1514 limit 1024 2>/dev/null                     || $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: fq_codel 2>/dev/null                     || rc=$?
                kind=fq_codel
            fi ;;
        off)
            $TC_BIN qdisc replace dev "$iface" parent 1:9999 handle 9999: netem delay 0ms limit 100 2>/dev/null                 || { $TC_BIN qdisc del dev "$iface" parent 1:9999 2>/dev/null || true; $TC_BIN qdisc add dev "$iface" parent 1:9999 handle 9999: netem delay 0ms limit 100 2>/dev/null; }                 || rc=$? ;;
        *)
            echo "ERROR: unsupported leaf '$kind'" >&2
            return 5 ;;
    esac

    if [ "${rc:-0}" -ne 0 ]; then
        log "incremental apply failed iface=$iface kind=$kind rc=$rc"
        echo "ERROR: incremental qdisc replace failed iface=$iface kind=$kind" >&2
        return "$rc"
    fi
    log "incremental apply ok iface=$iface parent=1:9999 handle=9999 kind=$kind"
    return 0
}

status_json() {
    local iface=${1:-} mode rec cake fqc autorate supported active qdisc profile preset leaf detected reason lastdiag iface_present can_apply
    [ -n "$iface" ] || iface=$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n')
    iface_present=false
    can_apply=false
    if iface_exists "$iface"; then
        iface_present=true
    fi
    mode=$(current_mode)
    rec=$(recommended_mode)
    cake=$(cap_bool tc_cake_supported)
    fqc=$(cap_bool tc_fq_codel_supported)
    autorate=$(cap_bool tc_cake_autorate_ingress_supported)
    supported=false
    mode_available "$mode" && supported=true
    if [ "$mode" = off ]; then
        active=false
    elif [ "$iface_present" = true ]; then
        active=$supported
    else
        active=false
    fi
    profile=$(cat "$SQM_PROFILE_FILE" 2>/dev/null | head -1 | tr -d '\r\n')
    [ -n "$profile" ] || profile=balanced
    preset=$(current_preset)
    leaf=$(recommended_mode)
    qdisc=""
    detected=none
    if [ "$iface_present" = true ]; then
        qdisc=$("$TC_BIN" qdisc show dev "$iface" 2>/dev/null | head -10 | tr '\r\n' ' ' | cut -c1-520)
        echo "$qdisc" | grep -q ' fq_codel ' && detected=fq_codel
        echo "$qdisc" | grep -q ' cake ' && detected=cake
        [ "$detected" = none ] && echo "$qdisc" | grep -q ' netem ' && detected=netem
        [ "$detected" = none ] && echo "$qdisc" | grep -q ' htb ' && detected=htb
        if [ "$mode" != off ] && [ "$supported" = true ] && echo "$qdisc" | grep -q 'qdisc htb 1:'; then
            can_apply=true
        fi
    fi
    if [ "$iface_present" != true ]; then
        reason="热点未开启或热点接口不存在，SQM 设置已保存；开启热点后再应用"
    elif [ "$supported" = false ]; then
        reason="当前模式未被能力探测确认，保持兼容链路"
    elif [ "$mode" = off ]; then
        reason="SQM 已关闭"
    else
        reason="SQM 可用；delay/jitter/loss 非零时仍由 netem 优先接管"
    fi
    lastdiag=$(cat "$SQM_DIAG_LAST" 2>/dev/null | head -1)
    cat <<EOF_JSON
{
  "schema": 3,
  "mode": "$(json_escape "$mode")",
  "profile": "$(json_escape "$profile")",
  "preset": "$(json_escape "$preset")",
  "preset_detail": $(preset_one_json "$preset" | tr -d '\n'),
  "presets": $(presets_json_array),
  "recommended_mode": "$(json_escape "$rec")",
  "recommended_leaf": "$(json_escape "$leaf")",
  "detected_leaf": "$(json_escape "$detected")",
  "active": $active,
  "available": true,
  "iface_present": $iface_present,
  "hotspot_active": $iface_present,
  "can_apply": $can_apply,
  "mode_supported": $supported,
  "tc_fq_codel_supported": $fqc,
  "tc_cake_supported": $cake,
  "tc_cake_autorate_ingress_supported": $autorate,
  "iface": "$(json_escape "$iface")",
  "tc_binary": "$(json_escape "$TC_BIN")",
  "qdisc_head": "$(json_escape "$qdisc")",
  "last_diag": "$(json_escape "$lastdiag")",
  "reason": "$(json_escape "$reason")"
}
EOF_JSON
}

usage() {
    cat <<EOF_USAGE
Usage: sqm_manager.sh <command> [args]

Commands:
  status [iface]          Print SQM status JSON
  get-mode                Print current mode
  set-mode <mode>         Persist mode: off | fq_codel | cake | auto | game
  set-profile <profile>   Persist profile: balanced | game | bulk | custom
  presets                 Print built-in game/weak-network presets JSON
  get-preset              Print current preset
  set-preset <preset>     Persist preset: off | balanced | game | weaknet | poor | extreme | custom
  recommended             Print recommended mode from capabilities.json
  apply [iface]           Incrementally replace default leaf qdisc parent 1:9999
                         If iface is absent/offline, only save settings and return success.

Notes:
  - Default mode is off; v5.2.1 behavior is preserved.
  - fq_codel/cake only affects delay-free leaves; apply only touches default class 1:9999.
  - Any real netem delay/jitter/loss still forces netem.
EOF_USAGE
}

cmd=${1:-status}
case "$cmd" in
    status)
        status_json "$2" ;;
    get-mode)
        current_mode ;;
    recommended)
        recommended_mode ;;
    presets)
        presets_json_array ;;
    get-preset)
        current_preset ;;
    set-preset)
        preset=$(norm_preset "$2")
        if [ "$preset" = invalid ]; then
            echo "ERROR: invalid preset '$2'" >&2
            exit 2
        fi
        write_preset "$preset" || exit $?
        status_json ;;
    set-mode)
        mode=$(norm_mode "$2")
        if [ "$mode" = invalid ]; then
            echo "ERROR: invalid mode '$2'" >&2
            exit 2
        fi
        if ! mode_available "$mode"; then
            echo "WARN: mode '$mode' not confirmed by capabilities; saving anyway for future probe" >&2
        fi
        write_mode "$mode" || exit 1
        status_json ;;
    set-profile)
        profile=$(norm_profile "$2")
        echo "$profile" > "$SQM_PROFILE_FILE" 2>/dev/null || exit 1
        if [ -z "$HNC_TEST_MODE" ] && [ -x "$HNC_DIR/bin/json_set.sh" ]; then
            HNC="$HNC_DIR" sh "$HNC_DIR/bin/json_set.sh" top sqm_profile "$profile" >/dev/null 2>&1 || true
        fi
        log "profile set to $profile"
        status_json ;;
    apply)
        iface=${2:-$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n')}
        apply_default_leaf "$iface" || rc=$?
        rc=${rc:-0}
        log "apply requested iface=$iface rc=$rc mode=$(current_mode) leaf=$(effective_leaf_for_apply)"
        status_json "$iface"
        exit "$rc" ;;
    -h|--help|help)
        usage ;;
    *)
        usage >&2
        exit 2 ;;
esac
