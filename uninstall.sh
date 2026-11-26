#!/system/bin/sh
# HNC uninstall hook
# Magisk / KernelSU 卸载模块时会自动调用此脚本

umask 077

HNC=${HNC_DIR:-/data/local/hnc}
MODDIR=${0%/*}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

# 提前读取持久化的 tether_offload_disabled 原值(在 cleanup.sh 与删目录之前捕获!)
ORIG_VAL=""
if [ -f "$HNC/data/orig_tether_offload_disabled" ]; then
    ORIG_VAL=$(tr -d ' \t\r\n' < "$HNC/data/orig_tether_offload_disabled" 2>/dev/null)
elif [ -f "$HNC/run/orig_tether_offload_disabled" ]; then
    ORIG_VAL=$(tr -d ' \t\r\n' < "$HNC/run/orig_tether_offload_disabled" 2>/dev/null)
fi
case "$ORIG_VAL" in
    0|1|null) ;;
    *[!0-9]*|"") ORIG_VAL="" ;;
esac

# 清 tc / iptables / 停 daemon（不依赖 +x 位，回退支持模块目录内 cleanup.sh）
if [ -f "$HNC/bin/cleanup.sh" ]; then
    HNC_DIR="$HNC" HNC_UNINSTALL=1 HNC_ALLOW_FULL_STOP=1 sh "$HNC/bin/cleanup.sh" all 2>/dev/null
elif [ -f "$MODDIR/bin/cleanup.sh" ]; then
    HNC_DIR="$HNC" HNC_UNINSTALL=1 HNC_ALLOW_FULL_STOP=1 sh "$MODDIR/bin/cleanup.sh" all 2>/dev/null
fi
rm -rf /sys/fs/bpf/hnc 2>/dev/null || true

# 留下一个 tombstone (用户重装时不会误导)
# rc38 (SEC-1): 备份目录收权 700 + 全部备份文件 600（rules.json 含 hotspot_pass，
# remote_tokens.json 含已配对远程管理凭据）。
_BACKUP_DIR=${HNC_BACKUP_DIR:-/data/local/hnc_backup}
mkdir -p "$_BACKUP_DIR" 2>/dev/null
chmod 700 "$_BACKUP_DIR" 2>/dev/null || true
for _bf in rules.json device_names.json templates.json remote_tokens.json tokens.json \
           self_firewall.json mac_aliases.json conn_blocks.json app_limits.json \
           limit_policies.json autorate.json alerts_config.json app_controls.json \
           dns_takeover.json encdns.json dpi_user_rules.json phone_usage_config.json \
           dpi_experiment.json device_ident_override.json startup_fp.json fp_prototypes.json \
           dpi_self_config.json leakguard_config.json vector_express.json update_leash.json \
           thermo_cruise.json rmac_policy.json webui_access.json dpi_fp_prototypes.json \
           self_policy.json; do
    if [ -f "$HNC/data/$_bf" ]; then
        cp -f "$HNC/data/$_bf" "$_BACKUP_DIR/${_bf}.last" 2>/dev/null
        chmod 600 "$_BACKUP_DIR/${_bf}.last" 2>/dev/null || true
    fi
done
for _v6f in "$HNC"/data/v6_*.json; do
    [ -f "$_v6f" ] || continue
    _v6bn=${_v6f##*/}
    cp -f "$_v6f" "$_BACKUP_DIR/${_v6bn}.last" 2>/dev/null
    chmod 600 "$_BACKUP_DIR/${_v6bn}.last" 2>/dev/null || true
done
unset _bf _v6f _v6bn _BACKUP_DIR

# 删除运行状态 (pid / lock / pair pending / bpf 状态) 与压制备份文件
umount -l "$HNC/run" 2>/dev/null || true
rm -rf "$HNC/run" 2>/dev/null
rm -f "$HNC/data/orig_tether_offload_disabled" "$HNC/data/offload_suppressed_by_hnc" 2>/dev/null || true

# 还原用户原 tether_offload_disabled 设置:
# 若在 post-fs-data 阶段卸载导致 system_server 尚未就绪(settings 失败或 boot_completed!=1),
# 派生脱离模块目录的后台进程等待 sys.boot_completed=1 后 100% 还原用户手机设置!
if [ -n "$ORIG_VAL" ] && [ "$ORIG_VAL" != "1" ]; then
    _SETTINGS_CMD="${HNC_SETTINGS_BIN:-settings}"
    _restored_sync=0
    if [ "${HNC_TEST_MODE:-0}" = "1" ] || [ -n "${HNC_SETTINGS_BIN:-}" ] || [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ]; then
        if command -v "$_SETTINGS_CMD" >/dev/null 2>&1; then
            if [ "$ORIG_VAL" = "null" ]; then
                if "$_SETTINGS_CMD" delete global tether_offload_disabled >/dev/null 2>&1; then
                    _v_chk=$("$_SETTINGS_CMD" get global tether_offload_disabled 2>/dev/null | tr -d ' \t\r\n')
                    case "$_v_chk" in null|"") _restored_sync=1 ;; esac
                fi
            else
                if "$_SETTINGS_CMD" put global tether_offload_disabled "$ORIG_VAL" >/dev/null 2>&1; then
                    _v_chk=$("$_SETTINGS_CMD" get global tether_offload_disabled 2>/dev/null | tr -d ' \t\r\n')
                    [ "$_v_chk" = "$ORIG_VAL" ] && _restored_sync=1
                fi
            fi
        fi
    fi
    if [ "$_restored_sync" = "0" ]; then
        _U_SH="/system/bin/sh"
        [ -x "$_U_SH" ] || _U_SH="sh"
        if [ "${HNC_TEST_MODE:-0}" != "1" ] || [ -n "${HNC_SETTINGS_BIN:-}" ]; then
            (
                cd / 2>/dev/null || true
                nohup "$_U_SH" -c '
                    orig="$1"; hnc_d="$2"; sbin="$3"; poll="${4:-2}"
                    export PATH="/system/bin:/system/xbin:/vendor/bin:${PATH:-}"
                    i=0
                    while [ "$i" -lt 90 ] && [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
                        sleep "$poll"
                        i=$((i + 1))
                    done
                    j=0
                    while [ "$j" -lt 10 ]; do
                        if [ "$orig" = "null" ]; then
                            "$sbin" delete global tether_offload_disabled >/dev/null 2>&1
                            v=$("$sbin" get global tether_offload_disabled 2>/dev/null | tr -d " \t\r\n")
                            case "$v" in null|"") rm -f "$hnc_d/data/orig_tether_offload_disabled" "$hnc_d/data/offload_suppressed_by_hnc" 2>/dev/null; exit 0 ;; esac
                        else
                            "$sbin" put global tether_offload_disabled "$orig" >/dev/null 2>&1
                            v=$("$sbin" get global tether_offload_disabled 2>/dev/null | tr -d " \t\r\n")
                            if [ "$v" = "$orig" ]; then rm -f "$hnc_d/data/orig_tether_offload_disabled" "$hnc_d/data/offload_suppressed_by_hnc" 2>/dev/null; exit 0; fi
                        fi
                        sleep "$poll"
                        j=$((j + 1))
                    done
                ' _ "$ORIG_VAL" "$HNC" "$_SETTINGS_CMD" "${HNC_UNINSTALL_POLL_SEC:-2}" </dev/null >/dev/null 2>&1 &
            )
        fi
    fi
    unset _SETTINGS_CMD _restored_sync _v_chk _U_SH
fi
unset ORIG_VAL

# 不删 /data/local/hnc/ 本身 - 让用户手动删 (保留 logs 供排查)
echo "HNC uninstalled. Config backed up to /data/local/hnc_backup/"
echo "To fully remove: rm -rf /data/local/hnc /data/local/hnc_backup"
