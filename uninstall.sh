#!/system/bin/sh
# HNC uninstall hook
# Magisk / KernelSU 卸载模块时会自动调用此脚本

HNC=/data/local/hnc

# 清 tc / iptables / 停 daemon
[ -x "$HNC/bin/cleanup.sh" ] && HNC_UNINSTALL=1 HNC_ALLOW_FULL_STOP=1 sh "$HNC/bin/cleanup.sh" all 2>/dev/null

# 留下一个 tombstone (用户重装时不会误导)
# rc38 (SEC-1): 备份目录收权 700 + 备份文件 600。tokens.json 含远程访问 token,
# 默认 755/644 会让有 root 的其他模块读到。先 mkdir 再 chmod,确保后续 cp 进去的
# 文件落在受限目录内。
mkdir -p /data/local/hnc_backup
chmod 700 /data/local/hnc_backup 2>/dev/null || true
[ -f "$HNC/data/rules.json" ] && cp "$HNC/data/rules.json" /data/local/hnc_backup/rules.json.last 2>/dev/null
[ -f "$HNC/data/device_names.json" ] && cp "$HNC/data/device_names.json" /data/local/hnc_backup/device_names.json.last 2>/dev/null
# rc2 修 N3: 备 tokens.json 让重装后已配对客户端/远程 token 不丢
[ -f "$HNC/data/tokens.json" ] && cp "$HNC/data/tokens.json" /data/local/hnc_backup/tokens.json.last 2>/dev/null
chmod 600 /data/local/hnc_backup/tokens.json.last 2>/dev/null || true

# 删除运行状态 (pid / lock / pair pending)
rm -rf "$HNC/run" 2>/dev/null

# 不删 /data/local/hnc/ 本身 - 让用户手动删 (保留 logs 供排查)
echo "HNC uninstalled. Config backed up to /data/local/hnc_backup/"
echo "To fully remove: rm -rf /data/local/hnc /data/local/hnc_backup"
