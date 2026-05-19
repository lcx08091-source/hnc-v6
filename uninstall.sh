#!/system/bin/sh
# HNC uninstall hook
# Magisk / KernelSU 卸载模块时会自动调用此脚本

HNC=/data/local/hnc

# 清 tc / iptables / 停 daemon
[ -x "$HNC/bin/cleanup.sh" ] && HNC_UNINSTALL=1 HNC_ALLOW_FULL_STOP=1 sh "$HNC/bin/cleanup.sh" all 2>/dev/null

# 留下一个 tombstone (用户重装时不会误导)
mkdir -p /data/local/hnc_backup
[ -f "$HNC/data/rules.json" ] && cp "$HNC/data/rules.json" /data/local/hnc_backup/rules.json.last 2>/dev/null
[ -f "$HNC/data/device_names.json" ] && cp "$HNC/data/device_names.json" /data/local/hnc_backup/device_names.json.last 2>/dev/null
# rc2 修 N3: 备 tokens.json 让重装后已配对客户端/远程 token 不丢
[ -f "$HNC/data/tokens.json" ] && cp "$HNC/data/tokens.json" /data/local/hnc_backup/tokens.json.last 2>/dev/null

# 删除运行状态 (pid / lock / pair pending)
rm -rf "$HNC/run" 2>/dev/null

# 不删 /data/local/hnc/ 本身 - 让用户手动删 (保留 logs 供排查)
echo "HNC uninstalled. Config backed up to /data/local/hnc_backup/"
echo "To fully remove: rm -rf /data/local/hnc /data/local/hnc_backup"
