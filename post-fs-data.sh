#!/system/bin/sh
# post-fs-data.sh — 在文件系统挂载后、Zygote启动前执行
# 此阶段主要做目录初始化和文件权限设置

# v5.9.3 BUG-009:引导脚本继承 magiskd/KSU 的 umask=0,裸 `mkdir -p` 建出来的
# 目录就是 0777、裸 `>` 建出来的文件就是 0666 —— 仓库里一处 chmod 777 都没有,
# 真机上那一堆 0777 全是这么来的。这里显式定 umask。
umask 022

MODDIR=${0%/*}
HNC_DIR=/data/local/hnc

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "${HNC_DIR:-/data/local/hnc}/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

# v5.40.1: 若当前运行在 hotspot_net_ctl, 立即停用并标记移除残留的旧版 hotspot_network_control,
# 防止紧随其后的 late_start 阶段被旧模块拉起第二份 service.sh 覆盖运行目录。
if [ "$MODDIR" != "/data/adb/modules/hotspot_network_control" ] && [ -d "/data/adb/modules/hotspot_network_control" ]; then
    : > "/data/adb/modules/hotspot_network_control/disable" 2>/dev/null || true
    : > "/data/adb/modules/hotspot_network_control/remove" 2>/dev/null || true
fi

# 创建持久化数据目录
mkdir -p "$HNC_DIR/data"
mkdir -p "$HNC_DIR/logs"
mkdir -p "$HNC_DIR/run"
# v5.9.3 BUG-009:已存在的老装机目录不会被 umask 影响(mkdir -p 对已存在目录
# 不改权限),必须显式收。data/ 有 tokens.json、run/ 有 local_admin.secret,
# 两者都是"拿到就等于 root 级写 API"的凭据,只留 root 可进。
# 已核实不影响任何生产路径:HNC 全部组件由 root 拉起,KSU WebUI 走 ksu.exec,
# httpd 读的 index.html 是模块目录的硬编码路径而不是 $HNC_DIR/webroot。
chmod 700 "$HNC_DIR" "$HNC_DIR/data" "$HNC_DIR/logs" "$HNC_DIR/run" 2>/dev/null

# rc3.1.30 Bug A 修复 · 清内核重启跨不过去的运行时状态
# 旧 $RUN/hnc_state 是 watchdog 持久化的 "PENDING" / "ACTIVE:<iface>" 状态.
# 内核重启后 iptables/tc/ifb 全空,但这个文件还是 ACTIVE:wlan2 (磁盘持久),
# 导致 watchdog 启动时跳过 do_full_init 永远不恢复规则 (Ling 真机实证:
# 18:30 重启后 watchdog.log 无任何 do_full_init 输出, 谎报 alive=ok).
# 清掉 → watchdog 进 PENDING → 配合 rc3.1.30 watchdog.sh 的"首轮立刻 probe"
# 改动, ~100ms 内跑完 iptables init + tc init + tc restore.
rm -f "$HNC_DIR/run/hnc_state" 2>/dev/null
rm -rf "$HNC_DIR/run/hnc_json.lock" "$HNC_DIR/run/json.lock" 2>/dev/null
# v5.12: 同理清掉其它"只对本次开机有效"的运行期状态(内核 tc/iptables 已全空):
#   - run/lock(gate / per-MAC 锁)、tc_action.lock: 上次关机时若正持锁,目录连同
#     旧 pid 留下;开机后 PID 被别的活进程复用 → hnc_lock 的 kill -0 判"持有者活着"
#     永不回收 → gate_lock 恒超时,restore / 限速分配全部 rc=11。
#   - tc_root_owned_*: cleanup 据此判断"本次开机 HNC 自建的 root qdisc 才删";
#     跨重启残留会让 cleanup 删掉 ROM 自己的 root qdisc(本次是复用而非自建)。
#   - tc_mq_child_* / tc_qos_fallback / tc_ifindex_*: 上次建树方式与接口 ifindex,
#     跨重启残留会误导 QoS 缩放与 watchdog 的接口重建判断。
#   - v6/(v6_sync 快照)、iface.cache: 上次会话的地址/接口,开机后必须重新探测。
rm -rf "$HNC_DIR/run/lock" "$HNC_DIR/run/tc_action.lock" "$HNC_DIR/run/v6" \
       "$HNC_DIR/run/stats_v6.lock" "$HNC_DIR/run/app_limits.lock" \
       "$HNC_DIR/run/app_qos.lock" "$HNC_DIR/run/connblock.lock" \
       "$HNC_DIR/run/daemon.spawn" "$HNC_DIR"/run/*.lock 2>/dev/null
rm -rf "$HNC_DIR"/run/tc_action.lock.stale.* "$HNC_DIR"/run/offload_guard.* 2>/dev/null
rm -f "$HNC_DIR"/run/tc_root_owned_* "$HNC_DIR"/run/tc_mq_child_* "$HNC_DIR"/run/tc_ifindex_* \
      "$HNC_DIR/run/tc_qos_fallback" "$HNC_DIR/run/iface.cache" \
      "$HNC_DIR/run/tc_restore_pending" "$HNC_DIR/run/stats_v6_map" \
      "$HNC_DIR/run/stats_v6_retired" "$HNC_DIR/run/app_limits.full.sig" \
      "$HNC_DIR/run/app_limits.devs" "$HNC_DIR/run/mtk_hwnat.state" \
      "$HNC_DIR/run/clsact.state" "$HNC_DIR/run/tmpfs_unavailable" \
      "$HNC_DIR/run/app_qos.sig" "$HNC_DIR/run/app_qos.state" 2>/dev/null
# v5.26 T2: dpid 守护者选择是本次开机的探测结果。上次会话的 choice(尤其 sentinel
# 救命改写的 direct)不能带进新开机: Go 看门狗比 service.sh 落盘 choice 更早启动,
# 读到旧 direct 会直拉 dpid, 随后 service.sh 又起 launcher → 双 dpid。缺失时看门狗按旧行为。
rm -f "$HNC_DIR/run/dpid_launcher.choice" "$HNC_DIR/run/dpid_launcher.choice.tmp" 2>/dev/null
# v5.33: 「只留一份」—— 设备发现写者开关 / 影子比对 / 演练、shell 扫描的名字缓存与
# pid、dpid 守护的旧开关都没有读者了, 旧版本留下的文件清掉(不清也不影响, 只是免得
# 有人以为改它们还有用)。
rm -f "$HNC_DIR/data/m4_owner" "$HNC_DIR/run/m4_owner.current" "$HNC_DIR/run/wd_m4_drill" \
      "$HNC_DIR/run/devices.go.json" "$HNC_DIR/run/devices.go.json.tmp" \
      "$HNC_DIR/run/m4_shadow.json" "$HNC_DIR/run/wd_m4_shadow.disabled" \
      "$HNC_DIR/run/hostname_cache" "$HNC_DIR/run/detect.pid" "$HNC_DIR/run/arp_hash" \
      "$HNC_DIR/run/wd_m5.disabled" "$HNC_DIR/run/wd_m3.disabled" "$HNC_DIR/run/offload_guard.owner" \
      "$HNC_DIR/run/offload_guard.pid" "$HNC_DIR/run/clsact_wd.pid" \
      "$HNC_DIR/run/wd_native.disabled" "$HNC_DIR/run/httpd_bind_ip" "$HNC_DIR/run/httpd.wanted" \
      "$HNC_DIR/run/json_legacy_fallback.log" "$HNC_DIR/run/json_legacy_fallback.count" \
      "$HNC_DIR/run/.ahnc_migration_done" "$HNC_DIR/run/dpid_crashflag" \
      "$HNC_DIR/etc/dpi_rules.json" 2>/dev/null
# 运行目录里从没用过的 api/(模块里就没有)和 test/(测试不进安装包): 空的就删
rmdir "$HNC_DIR/api" "$HNC_DIR/test" 2>/dev/null

# 初始化规则文件 · rc3.1.13 起 auth_required 也在这
[ ! -f "$HNC_DIR/data/rules.json" ] && cat > "$HNC_DIR/data/rules.json" << 'EOF'
{
  "version": 1,
  "whitelist_mode": false,
  "auth_required": true,
  "devices": {},
  "blacklist": [],
  "whitelist": []
}
EOF

# v5.33: 旧开关键 clsact_bpf_enabled(v5.9.7)一次性迁成 clsact_bpf_mode 后删除。之前
# httpd / offload guard / 设置页各自「缺 mode 时看旧键」, 切模式时还要同步写旧键。
if grep -q '"clsact_bpf_enabled"' "$HNC_DIR/data/rules.json" 2>/dev/null; then
    if ! grep -q '"clsact_bpf_mode"' "$HNC_DIR/data/rules.json" 2>/dev/null; then
        _cm=auto
        grep -q '"clsact_bpf_enabled"[[:space:]]*:[[:space:]]*true' "$HNC_DIR/data/rules.json" 2>/dev/null && _cm=on
        HNC="$HNC_DIR" sh "$MODDIR/bin/hnc_json" set-top "$HNC_DIR/data/rules.json" clsact_bpf_mode "$_cm" str 2>/dev/null
    fi
    grep -q '"clsact_bpf_mode"' "$HNC_DIR/data/rules.json" 2>/dev/null && \
        HNC="$HNC_DIR" sh "$MODDIR/bin/hnc_json" del-object-key "$HNC_DIR/data/rules.json" clsact_bpf_enabled 2>/dev/null
fi

# config.json 弃用 · 不再创建默认, 仅做单向迁移
_HNC_PFD_VER=$(sed -n '/^version=/{s/^version=//p;q;}' "$MODDIR/module.prop" 2>/dev/null | tr -d ' \t\r\n"')
echo "[HNC] === post-fs-data (${_HNC_PFD_VER:-unknown}) starting ===" >> "$HNC_DIR/logs/boot.log"

# v5.29 T3: 升级快照 + 钉住检查, 必须在下面的 cp 之前 —— 本脚本每次开机都
# 比 service.sh 先把模块文件拷进运行目录, 快照放在 service.sh 里打包到的已经
# 是新版, 钉住也挡不住这里把坏版本拷回来。rc=3 = 坏版本已钉住且模块没换新包
# → 跳过 bin/webroot/httpd 的同步, 用 .prev 恢复过的旧文件开机。
_HNC_RB=0
if [ -f "$MODDIR/bin/hnc_rollback.sh" ]; then
    HNC_RB_LOG="$HNC_DIR/logs/rollback.log" sh "$MODDIR/bin/hnc_rollback.sh" snapshot "$MODDIR" "$HNC_DIR"
    _HNC_RB=$?
fi
[ "$_HNC_RB" = 3 ] && echo "[HNC] rollback: version pinned, skip runtime sync (staying on .prev)" >> "$HNC_DIR/logs/boot.log"

# v5.33: 模块 → 运行目录的同步(bin/ webroot/ hnc_httpd + 原生二进制 chmod / chcon)只有
# bin/hnc_runtime_sync.sh 一份, service.sh 也调它。之前这里还拷从来不存在的 api/ 和不进
# 安装包的 test/。回滚钉住(rc=3)时只修权限, 不同步。
if [ "$_HNC_RB" = 3 ]; then
    sh "$MODDIR/bin/hnc_runtime_sync.sh" perms "$MODDIR" "$HNC_DIR" >> "$HNC_DIR/logs/boot.log" 2>&1
else
    sh "$MODDIR/bin/hnc_runtime_sync.sh" sync "$MODDIR" "$HNC_DIR" >> "$HNC_DIR/logs/boot.log" 2>&1
fi

# 早阶预置 .hnc_mc 与白名单 applet 软链(解决 Android 11-13 + Magisk 开机缺 awk / base64 / strings / paste)
if ! command -v hnc_provision_fallback_tools >/dev/null 2>&1; then
    for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh"; do
        case "$_he" in /bin/hnc_env.sh) continue ;; esac
        if [ -f "$_he" ]; then . "$_he"; break; fi
    done
    unset _he
fi
if command -v hnc_provision_fallback_tools >/dev/null 2>&1; then
    hnc_provision_fallback_tools "$HNC_DIR" "$MODDIR" >> "$HNC_DIR/logs/boot.log" 2>&1 || true
fi

# 单向迁移: 老装机 config.json.auth_required → rules.json.auth_required
# (仅在 rules.json 没有 auth_required 字段时迁移, 避免覆盖用户在新版的设置)
if [ -f "$HNC_DIR/data/config.json" ] && [ -f "$HNC_DIR/data/rules.json" ]; then
    if ! grep -q '"auth_required"' "$HNC_DIR/data/rules.json" 2>/dev/null; then
        OLD_AUTH=$(grep -oE '"auth_required"[[:space:]]*:[[:space:]]*"?(true|false|True|TRUE|False|FALSE)"?' \
                   "$HNC_DIR/data/config.json" 2>/dev/null \
                   | grep -oE '(true|false|True|TRUE|False|FALSE)' | tr 'A-Z' 'a-z' | head -n 1)
        if [ -n "$OLD_AUTH" ]; then
            JSON_SET="$MODDIR/bin/json_set.sh"
            [ -f "$JSON_SET" ] || JSON_SET="$HNC_DIR/bin/json_set.sh"
            if HNC="$HNC_DIR" sh "$JSON_SET" top auth_required "$OLD_AUTH" >> "$HNC_DIR/logs/boot.log" 2>&1; then
                echo "[HNC] migrate OK: auth_required=$OLD_AUTH from config.json to rules.json" >> "$HNC_DIR/logs/boot.log"
            else
                rc=$?
                echo "[HNC] migrate FAILED rc=$rc (script=$JSON_SET, value=$OLD_AUTH)" >> "$HNC_DIR/logs/boot.log"
            fi
        fi
    fi
    if [ -d "$HNC_DIR/run" ]; then
        CFG_MTIME=$(stat -c %Y "$HNC_DIR/data/config.json" 2>/dev/null)
        LAST_MTIME=$(cat "$HNC_DIR/run/config_json_mtime" 2>/dev/null)
        if [ -n "$LAST_MTIME" ] && [ -n "$CFG_MTIME" ] && [ "$CFG_MTIME" != "$LAST_MTIME" ]; then
            echo "[HNC] WARN: config.json mtime changed during deprecation observation (was $LAST_MTIME, now $CFG_MTIME) — something is still writing it" >> "$HNC_DIR/logs/boot.log"
        fi
        [ -n "$CFG_MTIME" ] && echo "$CFG_MTIME" > "$HNC_DIR/run/config_json_mtime" 2>/dev/null
    fi
    if [ "$HNC_DIR/data/config.json" -nt "$HNC_DIR/data/rules.json" ] 2>/dev/null; then
        echo "[HNC] WARN: config.json was modified after rules.json — config.json is DEPRECATED and edits to it are IGNORED. Edit rules.json instead." >> "$HNC_DIR/logs/boot.log"
    fi
fi
chmod 644 "$HNC_DIR/data/rules.json" 2>/dev/null
[ -f "$HNC_DIR/data/config.json" ] && chmod 644 "$HNC_DIR/data/config.json"

# 自动备份用户数据 — 每天首次开机时备份 data/ 目录, 保留最近 7 天。
TODAY=$(date +%Y%m%d 2>/dev/null)
# post-fs-data 往往早于 NTP 对时 —— 时钟不可信时不建 .backup-<错日期>
if [ -n "$TODAY" ] && [ -f "$HNC_DIR/bin/hnc_clock.sh" ] && \
   ! HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/hnc_clock.sh" sane 2>/dev/null; then
    echo "[HNC] backup: skipped, clock not trustworthy ($(date +%s 2>/dev/null))" >> "$HNC_DIR/logs/boot.log"
    TODAY=""
fi
if [ -n "$TODAY" ]; then
    BACKUP_DIR="$HNC_DIR/data/.backup-$TODAY"
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR" 2>/dev/null
        chmod 700 "$BACKUP_DIR" 2>/dev/null
        for f in "$HNC_DIR"/data/*.json; do
            [ -f "$f" ] && cp "$f" "$BACKUP_DIR/" 2>/dev/null
        done
        echo "[HNC] backup: created $BACKUP_DIR" >> "$HNC_DIR/logs/boot.log"
    fi

    BACKUP_LIST=$(ls -d "$HNC_DIR"/data/.backup-* 2>/dev/null | sort -r)
    KEEP=7
    n=0
    for dir in $BACKUP_LIST; do
        n=$((n+1))
        if [ "$n" -gt "$KEEP" ]; then
            rm -rf "$dir" 2>/dev/null
            echo "[HNC] backup: pruned $dir" >> "$HNC_DIR/logs/boot.log"
        fi
    done
fi

# PID文件清理（防上次未正常退出）
rm -f "$HNC_DIR"/run/*.pid

if [ ! -f "$HNC_DIR/bin/portal_manager.sh" ]; then
    rm -f "$HNC_DIR/run/portal_pending.json" "$HNC_DIR/run/portal_sessions.json" 2>/dev/null
fi

# 日志轮转 — 启动时检查每个 .log 文件, >10MB 的三级轮转一次(防 mksh >2.14GB 32 位有符号溢出)
LOG_MAX_BYTES=10485760
for logf in "$HNC_DIR"/logs/*.log; do
    [ -f "$logf" ] || continue
    size=$(wc -c < "$logf" 2>/dev/null | tr -dc '0-9')
    while [ "${size#0}" != "$size" ]; do size=${size#0}; done
    if [ -n "$size" ] && { [ "${#size}" -gt "${#LOG_MAX_BYTES}" ] || { [ "${#size}" -eq "${#LOG_MAX_BYTES}" ] && [ "$size" -gt "$LOG_MAX_BYTES" ] 2>/dev/null; }; }; then
        [ -f "${logf}.2" ] && rm -f "${logf}.2"
        [ -f "${logf}.1" ] && mv "${logf}.1" "${logf}.2"
        [ -f "$logf" ] && mv "$logf" "${logf}.1"
        touch "$logf"
        echo "[HNC] logrotate: $logf rotated (was ${size} bytes, 3-level)" >> "$HNC_DIR/logs/boot.log"
    fi
done

echo "[HNC] post-fs-data (${_HNC_PFD_VER:-unknown}): initialization complete" >> "$HNC_DIR/logs/boot.log"
unset _HNC_PFD_VER
