#!/system/bin/sh
# post-fs-data.sh — 在文件系统挂载后、Zygote启动前执行
# 此阶段主要做目录初始化和文件权限设置

# v3.5.0 alpha-0:PATH 健壮性(见 service.sh 同段注释)
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

MODDIR=${0%/*}
HNC_DIR=/data/local/hnc

# 创建持久化数据目录
mkdir -p $HNC_DIR/data
mkdir -p $HNC_DIR/logs
mkdir -p $HNC_DIR/run

# rc3.1.30 Bug A 修复 · 清内核重启跨不过去的运行时状态
# 旧 $RUN/hnc_state 是 watchdog 持久化的 "PENDING" / "ACTIVE:<iface>" 状态.
# 内核重启后 iptables/tc/ifb 全空,但这个文件还是 ACTIVE:wlan2 (磁盘持久),
# 导致 watchdog 启动时跳过 do_full_init 永远不恢复规则 (Ling 真机实证:
# 18:30 重启后 watchdog.log 无任何 do_full_init 输出, 谎报 alive=ok).
# 清掉 → watchdog 进 PENDING → 配合 rc3.1.30 watchdog.sh 的"首轮立刻 probe"
# 改动, ~100ms 内跑完 iptables init + tc init + tc restore.
rm -f $HNC_DIR/run/hnc_state 2>/dev/null
rm -rf $HNC_DIR/run/hnc_json.lock 2>/dev/null

# 初始化规则文件 · rc3.1.13 起 auth_required 也在这
[ ! -f $HNC_DIR/data/rules.json ] && cat > $HNC_DIR/data/rules.json << 'EOF'
{
  "version": 1,
  "whitelist_mode": false,
  "auth_required": false,
  "devices": {},
  "blacklist": [],
  "whitelist": []
}
EOF

# rc3.1.13: config.json 弃用 · 不再创建默认
# 历史上 config.json 承载 auth_required (cfg_set 写) + 4 个死字段
# (api_port/poll_interval/watchdog_interval/log_level 没人读) +
# hotspot_iface (watchdog 写但没人读). 字段分裂导致 rc3.1.9~12 P0 反复.
# rc3.1.13 起所有活字段统一到 rules.json, config.json 只做单向迁移.
# (迁移块在下方 cp -rf 后执行, 不依赖目标目录残留脚本)

# Fix #7: 先建目录，再统一复制（去除重复操作）
mkdir -p $HNC_DIR/bin $HNC_DIR/api $HNC_DIR/webroot $HNC_DIR/test
cp -rf $MODDIR/bin/* $HNC_DIR/bin/ 2>/dev/null || true
cp -rf $MODDIR/api/* $HNC_DIR/api/ 2>/dev/null || true
cp -rf $MODDIR/webroot/* $HNC_DIR/webroot/ 2>/dev/null || true
# v3.5.0 alpha: 复制测试框架(让 user 能在真机跑 sh test/run_all.sh)
cp -rf $MODDIR/test/* $HNC_DIR/test/ 2>/dev/null || true

# v4.0.0-patch1.1 hotfix: daemon/hnc_httpd binary 精细 copy
# post-fs-data.sh 之前只 copy bin/api/webroot/test,漏了 daemon/,
# 导致 v4.0.0-patch1 的远程访问 binary 根本没进 data 目录,
# service.sh 找 $HNC_DIR/daemon/hnc_httpd/hnc_httpd 永远 miss,
# 结果 remote_enabled=true 也启动不了 httpd (用户报告:浏览器 ERR_CONNECTION_REFUSED)
# 只 copy 产物 binary,不 copy .c 源 / README / build.sh / web/(web 已 //go:embed 进 binary)
if [ -f "$MODDIR/daemon/hnc_httpd/hnc_httpd" ]; then
    mkdir -p $HNC_DIR/daemon/hnc_httpd
    if ! cmp -s "$MODDIR/daemon/hnc_httpd/hnc_httpd" "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null; then
        cp -f "$MODDIR/daemon/hnc_httpd/hnc_httpd" "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        echo "[HNC] hotfix17.3: refreshed runtime hnc_httpd binary from module" >> $HNC_DIR/logs/boot.log
    fi
    chmod 755 $HNC_DIR/daemon/hnc_httpd/hnc_httpd 2>/dev/null
fi

# v5.0.0-beta.4: 部署 BPF LSM Limit Map Guard object
# hotspotd 启动时从 /data/local/hnc/bpf/hnc_limit_map_guard.bpf.o 加载,
# 然后 BPF_PROG_LOAD + attach 到 lsm/bpf hook, 拦截 framework 对
# limit_map 的覆盖写, 真正关闭 BPF tethering offload fast path.
#
# 部署失败/缺文件不致命: scheduler 内 hnc_lsm_init 会 graceful 降级,
# 走 beta.3 的"周期重探 + adapter disable_upstream + 接受 framework 覆盖"
# 路径, 业务正常但失去精准防御。
if [ -f "$MODDIR/bpf/hnc_limit_map_guard.bpf.o" ]; then
    mkdir -p $HNC_DIR/bpf
    cp -f $MODDIR/bpf/hnc_limit_map_guard.bpf.o $HNC_DIR/bpf/ 2>/dev/null || true
    chmod 644 $HNC_DIR/bpf/hnc_limit_map_guard.bpf.o 2>/dev/null
fi

chmod 755 $HNC_DIR/bin/*.sh
# v5.0 beta.1 修: 单独 chmod 所有无后缀二进制
# post-fs-data.sh 原来只 chmod *.sh, 但 bin/ 下的 C 二进制 (hotspotd / hnc_ipc /
# hnc_tc_ingress / mdns_resolve) 没 .sh 后缀, 权限不被保证是 755.
# 真机 RMX5010 装 beta.1 后 hnc_tc_ingress 权限 644 → 不能 exec →
# install_ingress_mirred_via_netlink 回落 → 上行限速失败.
#
# rc30.8 补: hnc_dpid_supervisor (rc30.0 加) + hnc_watchdog (rc30.1 加).
# 之前漏掉这两个, 真机 RMX5010 装 rc30.7 后 supervisor 权限 644 → 不能 exec →
# watchdog 退回老 hnc_dpid_guard.sh, 导致 3 个 guard.sh 实例残留 (本来 supervisor
# 就是为了消除这个混乱的).
#
# rc30.11 关键修复: 这个 chmod 块原来只 chmod $HNC_DIR/bin/, 但
# post-fs-data.sh 跑时 sync_runtime_from_moddir 还没执行 (那是 service.sh 干的),
# /data/local/hnc/bin/ 里文件可能还没拷过来. 真机 RMX5010 装 rc30.10 后碰到
# supervisor 文件是 644, 导致 Go watchdog fork+exec 报 EPERM, 整个后端起不来.
# rc30.11 修复: 同时也 chmod $MODDIR/bin/, 这样 sync_runtime_from_moddir 用
# cp 拷过去时权限就正确, 不依赖 service.sh 后续再 chmod.
#
# 另外加 chcon — SukiSU/KSU 给模块目录的文件设的是 u:object_r:system_file:s0,
# 但 cp 到 /data/local/hnc/bin 后 context 变成 system_data_file:s0, 在 ColorOS 16
# 这种加固系统上, Go runtime fork+exec system_data_file 的 binary 会被某条
# 策略拒掉 (现象是 EPERM, 但 AVC log 不打). 强制设回 system_file:s0 兜底.
for _dir in "$MODDIR/bin" "$HNC_DIR/bin"; do
    [ -d "$_dir" ] || continue
    for _b in hotspotd hnc_ipc hnc_tc_ingress mdns_resolve hnc_json \
              hnc_dpid hnc_dpid_supervisor hnc_watchdog \
              hnc_launcher fork_probe; do
        if [ -f "$_dir/$_b" ]; then
            chmod 755 "$_dir/$_b"
            chcon u:object_r:system_file:s0 "$_dir/$_b" 2>/dev/null || true
        fi
    done
done
# hnc_httpd 在 daemon/hnc_httpd/ 单独处理
for _dir in "$MODDIR/daemon/hnc_httpd" "$HNC_DIR/daemon/hnc_httpd"; do
    if [ -f "$_dir/hnc_httpd" ]; then
        chmod 755 "$_dir/hnc_httpd"
        chcon u:object_r:system_file:s0 "$_dir/hnc_httpd" 2>/dev/null || true
    fi
done
chmod 755 $HNC_DIR/api/server.sh 2>/dev/null
chmod 755 $HNC_DIR/test/run_all.sh 2>/dev/null
chmod 755 $HNC_DIR/test/lib.sh 2>/dev/null
chmod 755 $HNC_DIR/test/unit/*.sh 2>/dev/null

# rc3.1.13.1 修 P0 (review §1): 单向迁移块必须在 cp -rf 之后,
# 不能依赖 $HNC_DIR/bin/json_set.sh 的残留版本 (上一版可能不存在 top 子命令).
# 优先用 $MODDIR/bin/json_set.sh, 兜底 $HNC_DIR/bin/. 严格检查 rc.
# 单向迁移: 老装机 config.json.auth_required → rules.json.auth_required
# (仅在 rules.json 没有 auth_required 字段时迁移, 避免覆盖用户在新版的设置)
# 注: auth_required=false 也会被迁移. 这是用户主动选择的状态,
#     迁移的是"用户的设定"而非"开启状态". 不要改成 [ "$OLD_AUTH" = "true" ].
if [ -f $HNC_DIR/data/config.json ] && [ -f $HNC_DIR/data/rules.json ]; then
    if ! grep -q '"auth_required"' $HNC_DIR/data/rules.json 2>/dev/null; then
        # rc3.1.13.1: grep -E 兼容 pretty-printed JSON (跨行) 和字符串值 (true/"true"/True/TRUE)
        OLD_AUTH=$(grep -oE '"auth_required"[[:space:]]*:[[:space:]]*"?(true|false|True|TRUE|False|FALSE)"?' \
                   $HNC_DIR/data/config.json 2>/dev/null \
                   | grep -oE '(true|false|True|TRUE|False|FALSE)' | tr 'A-Z' 'a-z' | head -1)
        if [ -n "$OLD_AUTH" ]; then
            JSON_SET=$MODDIR/bin/json_set.sh
            [ -f "$JSON_SET" ] || JSON_SET=$HNC_DIR/bin/json_set.sh
            if HNC=$HNC_DIR sh "$JSON_SET" top auth_required "$OLD_AUTH" >> $HNC_DIR/logs/boot.log 2>&1; then
                echo "[HNC] rc3.1.13 migrate OK: auth_required=$OLD_AUTH from config.json to rules.json" >> $HNC_DIR/logs/boot.log
            else
                rc=$?
                echo "[HNC] rc3.1.13 migrate FAILED rc=$rc (script=$JSON_SET, value=$OLD_AUTH)" >> $HNC_DIR/logs/boot.log
            fi
        fi
    fi
    # config.json 文件本身保留不删 · 留一个版本观察期, rc3.1.14+ 再清.
    # 观察期检测 (review §6 P1): 监控 config.json mtime 漂移, 看是否还有写者
    if [ -d $HNC_DIR/run ]; then
        CFG_MTIME=$(stat -c %Y $HNC_DIR/data/config.json 2>/dev/null)
        LAST_MTIME=$(cat $HNC_DIR/run/config_json_mtime 2>/dev/null)
        if [ -n "$LAST_MTIME" ] && [ -n "$CFG_MTIME" ] && [ "$CFG_MTIME" != "$LAST_MTIME" ]; then
            echo "[HNC] WARN: config.json mtime changed during deprecation observation (was $LAST_MTIME, now $CFG_MTIME) — something is still writing it" >> $HNC_DIR/logs/boot.log
        fi
        [ -n "$CFG_MTIME" ] && echo "$CFG_MTIME" > $HNC_DIR/run/config_json_mtime 2>/dev/null
    fi
    # 用户手编 config.json 后无反馈检测 (review §1 P2)
    if [ $HNC_DIR/data/config.json -nt $HNC_DIR/data/rules.json ] 2>/dev/null; then
        echo "[HNC] WARN: config.json was modified after rules.json — but config.json is DEPRECATED since rc3.1.13. Edits to it are IGNORED. Edit rules.json instead." >> $HNC_DIR/logs/boot.log
    fi
fi
chmod 644 $HNC_DIR/data/rules.json 2>/dev/null
[ -f $HNC_DIR/data/config.json ] && chmod 644 $HNC_DIR/data/config.json

# v3.4.9: 自动备份用户数据 — 每天首次开机时备份 data/ 目录
# (rules.json / device_names.json / devices.json),保留最近 7 天。
# 防止 HNC 升级 / JSON schema 变更 / 用户误操作导致配置丢失。
TODAY=$(date +%Y%m%d 2>/dev/null)
if [ -n "$TODAY" ]; then
    BACKUP_DIR="$HNC_DIR/data/.backup-$TODAY"
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR" 2>/dev/null
        # 只备份 .json 文件,不备份 .backup-* 子目录(避免递归)
        for f in $HNC_DIR/data/*.json; do
            [ -f "$f" ] && cp "$f" "$BACKUP_DIR/" 2>/dev/null
        done
        echo "[HNC] backup: created $BACKUP_DIR" >> $HNC_DIR/logs/boot.log
    fi

    # 清理 7 天前的备份(简化:按目录名排序保留最新 7 个)
    BACKUP_LIST=$(ls -d $HNC_DIR/data/.backup-* 2>/dev/null | sort -r)
    KEEP=7
    n=0
    for dir in $BACKUP_LIST; do
        n=$((n+1))
        if [ "$n" -gt "$KEEP" ]; then
            rm -rf "$dir" 2>/dev/null
            echo "[HNC] backup: pruned $dir" >> $HNC_DIR/logs/boot.log
        fi
    done
fi

# PID文件清理（防上次未正常退出）
rm -f $HNC_DIR/run/*.pid

# v3.5.0 P2-6: 日志轮转 — 启动时检查每个 .log 文件,>10MB 的轮转一次
# 之前 HNC 没有日志轮转,长跑(几周)后 logs 目录可能涨到几百 MB
# 简单策略:超过 10MB 就 mv 到 .log.1(覆盖之前的 .1),原文件清空
# 这会丢失约 1/2 的历史(.1 → 删除,.log → .1),但避免无限增长
LOG_MAX_BYTES=$((10 * 1024 * 1024))
for logf in $HNC_DIR/logs/*.log; do
    [ -f "$logf" ] || continue
    size=$(wc -c < "$logf" 2>/dev/null)
    if [ -n "$size" ] && [ "$size" -gt "$LOG_MAX_BYTES" ]; then
        mv "$logf" "${logf}.1" 2>/dev/null
        : > "$logf"
        echo "[HNC] logrotate: $logf rotated (was ${size} bytes)" >> $HNC_DIR/logs/boot.log
    fi
done

echo "[HNC] post-fs-data: initialization complete" >> $HNC_DIR/logs/boot.log
