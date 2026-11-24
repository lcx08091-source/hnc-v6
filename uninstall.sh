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

# 删除运行状态 (pid / lock / pair pending / bpf 状态)
umount -l "$HNC/run" 2>/dev/null || true
rm -rf "$HNC/run" 2>/dev/null

# 不删 /data/local/hnc/ 本身 - 让用户手动删 (保留 logs 供排查)
echo "HNC uninstalled. Config backed up to /data/local/hnc_backup/"
echo "To fully remove: rm -rf /data/local/hnc /data/local/hnc_backup"
