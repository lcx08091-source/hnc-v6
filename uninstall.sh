#!/system/bin/sh
# HNC uninstall hook
# Magisk / KernelSU 卸载模块时会自动调用此脚本

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
umask 077

HNC=${HNC_DIR:-/data/local/hnc}
MODDIR=${0%/*}

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
mkdir -p /data/local/hnc_backup 2>/dev/null
chmod 700 /data/local/hnc_backup 2>/dev/null || true
for _bf in rules.json device_names.json templates.json remote_tokens.json tokens.json; do
    if [ -f "$HNC/data/$_bf" ]; then
        cp -f "$HNC/data/$_bf" "/data/local/hnc_backup/${_bf}.last" 2>/dev/null
        chmod 600 "/data/local/hnc_backup/${_bf}.last" 2>/dev/null || true
    fi
done
unset _bf

# 删除运行状态 (pid / lock / pair pending / bpf 状态)
umount -l "$HNC/run" 2>/dev/null || true
rm -rf "$HNC/run" 2>/dev/null

# 不删 /data/local/hnc/ 本身 - 让用户手动删 (保留 logs 供排查)
echo "HNC uninstalled. Config backed up to /data/local/hnc_backup/"
echo "To fully remove: rm -rf /data/local/hnc /data/local/hnc_backup"
