#!/system/bin/sh

# v3.8.6 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# diag.sh — HNC 自检脚本 (hotfix18.5)
# rc3.1.34 修 #28: 之前固定写 v3.8.6 的版本号字面, 每次发版都过期. 改成版本前缀
# 不带具体补丁号. 真实版本以 module.prop 为准 (script 内可读 $HNC_DIR/module.prop).
#
# 用法:
#   sh /data/local/hnc/bin/diag.sh
#   sh /data/local/hnc/bin/diag.sh --json     # 输出 JSON 格式
#
# 检查核心系统状态,每项 OK / FAIL / WARN,
# 帮助快速定位问题。LTS 版本必备的故障排查工具。
#
# 退出码:
#   0 = 全部 OK
#   1 = 有 FAIL
#   2 = 有 WARN(非致命但需注意)

HNC=${HNC:-/data/local/hnc}
JSON_MODE=0
[ "$1" = "--json" ] && JSON_MODE=1

# ── 输出辅助 ────────────────────────────────────────────
PASS=0
WARN=0
FAIL=0
RESULTS=""

ok()   { PASS=$((PASS+1)); RESULTS="$RESULTS$1|OK|$2
"; [ $JSON_MODE -eq 0 ] && printf '  \033[32m✓\033[0m %-22s %s\n' "$1" "$2"; }
warn() { WARN=$((WARN+1)); RESULTS="$RESULTS$1|WARN|$2
"; [ $JSON_MODE -eq 0 ] && printf '  \033[33m!\033[0m %-22s %s\n' "$1" "$2"; }
fail() { FAIL=$((FAIL+1)); RESULTS="$RESULTS$1|FAIL|$2
"; [ $JSON_MODE -eq 0 ] && printf '  \033[31m✗\033[0m %-22s %s\n' "$1" "$2"; }

# rc5.1.1 修 H2: 提前读 VER, 标题能显示实际版本
MODDIR=/data/adb/modules/hotspot_network_control
[ -f "$MODDIR/module.prop" ] && VER=$(grep "^version=" "$MODDIR/module.prop" | cut -d= -f2) || VER="unknown"

[ $JSON_MODE -eq 0 ] && {
    echo ""
    echo "  HNC $VER 自检"
    echo "  ──────────────────────────────────────────────"
}

# ── [1/14] HNC 安装目录 ──────────────────────────────────
# v3.8.6 修复:module.prop 在 Magisk/KernelSU 模块目录,
# 不在 $HNC 运行目录。之前检查 $HNC/module.prop 永远 FAIL,
# 因为 HNC 从 v3.5 开始就没这个文件(只有 bin/data/logs/run)。
MODDIR=/data/adb/modules/hotspot_network_control
if [ -d "$HNC" ]; then
    if [ -d "$HNC/bin" ] && [ -d "$HNC/data" ] && [ -f "$MODDIR/module.prop" ]; then
        VER=$(grep "^version=" "$MODDIR/module.prop" | cut -d= -f2)
        ok "安装目录" "$HNC ($VER)"
    elif [ -d "$HNC/bin" ] && [ -d "$HNC/data" ]; then
        warn "安装目录" "$HNC 齐全但 module.prop 位置异常($MODDIR 未找到)"
    else
        fail "安装目录" "$HNC 存在但缺关键子目录"
    fi
else
    fail "安装目录" "$HNC 不存在"
fi

# ── [2/14] 关键脚本 ──────────────────────────────────────
MISSING=""
for f in device_detect.sh iptables_manager.sh tc_manager.sh json_set.sh watchdog.sh; do
    [ -f "$HNC/bin/$f" ] || MISSING="$MISSING $f"
done
if [ -z "$MISSING" ]; then
    ok "shell 脚本" "5 个核心脚本就位"
else
    fail "shell 脚本" "缺失:$MISSING"
fi

# ── [3/14] mdns_resolve 二进制 ──────────────────────────
if [ -x "$HNC/bin/mdns_resolve" ]; then
    SIZE=$(stat -c %s "$HNC/bin/mdns_resolve" 2>/dev/null || echo 0)
    if [ "$SIZE" -gt 100000 ]; then
        ok "mDNS 工具" "二进制存在 (${SIZE} bytes)"
    else
        warn "mDNS 工具" "文件存在但尺寸异常 (${SIZE} bytes)"
    fi
else
    warn "mDNS 工具" "未安装,自动命名功能不可用"
fi

# ── [4/14] iptables 链 ──────────────────────────────────
# rc5.1.1 修 H1: 之前检查 HNC_LIMIT_DOWN/UP 两个链根本不存在, 结果永远
# 只能命中 4 个里的 2 个, 永远报 WARN. 实际 iptables_manager.sh 创建的
# 链是 HNC_RESTORE/HNC_MARK/HNC_SAVE/HNC_STATS (另外还有 HNC_CTRL/
# HNC_WHITELIST 但非必须). 这里只检查核心 4 条.
HAS_MARK=0; HAS_RESTORE=0; HAS_SAVE=0; HAS_STATS=0
iptables -t mangle -L HNC_MARK    -n >/dev/null 2>&1 && HAS_MARK=1
iptables -t mangle -L HNC_RESTORE -n >/dev/null 2>&1 && HAS_RESTORE=1
iptables -t mangle -L HNC_SAVE    -n >/dev/null 2>&1 && HAS_SAVE=1
iptables -t mangle -L HNC_STATS   -n >/dev/null 2>&1 && HAS_STATS=1
SUM=$((HAS_MARK + HAS_RESTORE + HAS_SAVE + HAS_STATS))
if [ "$SUM" -eq 4 ]; then
    ok "iptables 链" "4 个 HNC 核心链都存在 (MARK/RESTORE/SAVE/STATS)"
elif [ "$SUM" -gt 0 ]; then
    warn "iptables 链" "$SUM/4 存在, 可能未完全初始化"
else
    fail "iptables 链" "0/4 — HNC 后端未运行"
fi

# ── [5/14] tc qdisc ─────────────────────────────────────
IFACE=$(sh "$HNC/bin/device_detect.sh" iface 2>/dev/null)
if [ -n "$IFACE" ]; then
    if tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb"; then
        ok "tc qdisc" "htb 已附加到 $IFACE"
    else
        warn "tc qdisc" "$IFACE 上没有 htb (限速未启用?)"
    fi
else
    warn "tc qdisc" "无法识别热点 iface"
fi

# ── [6/14] watchdog 进程 ────────────────────────────────
WD_COUNT=$(pgrep -f "watchdog.sh" 2>/dev/null | wc -l)
if [ "$WD_COUNT" -gt 0 ]; then
    WD_PID=$(pgrep -f "watchdog.sh" 2>/dev/null | head -1)
    ok "watchdog" "运行中 (pid=$WD_PID)"
else
    warn "watchdog" "未运行(可能未启用自启)"
fi

# ── [7/14] 数据文件 ──────────────────────────────────────
RULES_COUNT=0
DEV_COUNT=0
NAMES_COUNT=0
[ -f "$HNC/data/rules.json" ] && RULES_COUNT=$(grep -c '"mark_id"' "$HNC/data/rules.json" 2>/dev/null || echo 0)
[ -f "$HNC/data/devices.json" ] && DEV_COUNT=$(grep -oE '"[0-9a-f:]{17}"' "$HNC/data/devices.json" 2>/dev/null | wc -l)
[ -f "$HNC/data/device_names.json" ] && NAMES_COUNT=$(grep -oE '"[0-9a-f:]{17}":' "$HNC/data/device_names.json" 2>/dev/null | wc -l)
ok "数据文件" "rules=$RULES_COUNT 设备 / devices=$DEV_COUNT 在线 / names=$NAMES_COUNT 命名"

# ── [8/14] hostname 缓存 ────────────────────────────────
if [ -f "$HNC/run/hostname_cache" ]; then
    CACHE_LINES=$(wc -l < "$HNC/run/hostname_cache" 2>/dev/null || echo 0)
    ok "hostname 缓存" "$CACHE_LINES 条记录"
else
    warn "hostname 缓存" "未生成(扫描尚未运行?)"
fi

# ── [9/14] 数据备份(v3.4.9 新增) ────────────────────────
BACKUP_COUNT=$(ls -d "$HNC/data/.backup-"* 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 0 ]; then
    LATEST=$(ls -dt "$HNC/data/.backup-"* 2>/dev/null | head -1 | sed "s|.*\.backup-||")
    ok "数据备份" "$BACKUP_COUNT 个备份,最近 $LATEST"
else
    warn "数据备份" "尚无备份(等下次开机自动创建)"
fi

# ── [10/14] 日志目录 ────────────────────────────────────
if [ -d "$HNC/logs" ]; then
    LOG_SIZE=$(du -sk "$HNC/logs" 2>/dev/null | awk '{print $1}')
    LOG_FILES=$(ls "$HNC/logs" 2>/dev/null | wc -l)
    if [ "${LOG_SIZE:-0}" -gt 10240 ]; then
        warn "日志目录" "$LOG_FILES 文件 / ${LOG_SIZE}K (超过 10MB,建议清理)"
    else
        ok "日志目录" "$LOG_FILES 文件 / ${LOG_SIZE:-0}K"
    fi
else
    warn "日志目录" "$HNC/logs 不存在"
fi

# ── [11/14] KSU 环境 ────────────────────────────────────
if [ -x /data/adb/ksu/bin/ksud ]; then
    KSU_VER=$(/data/adb/ksu/bin/ksud --version 2>/dev/null | head -1)
    ok "KSU 环境" "${KSU_VER:-detected}"
elif [ -x /data/adb/ksud ]; then
    ok "KSU 环境" "ksud 检测到"
else
    warn "KSU 环境" "未检测到 ksud (可能 Magisk 环境)"
fi

# ── [12/14] SELinux 模式 ─────────────────────────────────
SE_MODE=$(getenforce 2>/dev/null)
if [ "$SE_MODE" = "Enforcing" ]; then
    ok "SELinux" "Enforcing (正常)"
elif [ "$SE_MODE" = "Permissive" ]; then
    warn "SELinux" "Permissive (调试模式)"
else
    warn "SELinux" "无法读取状态"
fi

# ── [13/14] hotspotd daemon 状态(v3.8.6 重写) ───────────
# 之前(v3.4.11 时代): hotspotd 是实验功能,默认不启用,
#   检查 bin/hotspotd 存在 → WARN "LTS 期不应启用"
# 现在(v3.5+ 时代): hotspotd 是默认 daemon,不存在才奇怪
#   检查 binary + 进程存活
if [ -e "$HNC/bin/hotspotd" ]; then
    HPID=$(pidof hotspotd 2>/dev/null | head -1)
    if [ -n "$HPID" ]; then
        ok "hotspotd daemon" "running (pid=$HPID)"
    else
        warn "hotspotd daemon" "binary 存在但未运行(watchdog 会在 60s 内拉起)"
    fi
else
    warn "hotspotd daemon" "binary 未部署,shell fallback 模式(v3.5+ 不推荐)"
fi

# ── [14/14] dumpsys network_stack 格式探针(v3.8.6) ───────
# v3.7.0 加入的 DHCP hostname 识别功能,依赖 `dumpsys network_stack` 输出里
# 同时包含 "hwAddr: " 和 "hostname: " 两个字段。Android mainline 模块没有
# 稳定的 API 合约,将来 Google 改了输出格式 HNC 会静默失效(WebUI 所有
# 设备都变成 MAC 兜底或 OUI 兜底)。
#
# Gemini P1-6 审查指出的问题。这个探针让格式变化**在启动时立刻暴露**,
# 不是等到某个用户抱怨"为什么所有设备都变名字了"才发现。
#
# 检查策略:
#   1. 能跑 dumpsys network_stack 且有输出(root 权限正常)
#   2. 输出至少包含一次 "hwAddr: "
#   3. 输出至少包含一次 "hostname: "
#
# 三个都 OK → 格式匹配 v3.7+ 预期
# 有输出但缺 hwAddr/hostname → 格式已变,WARN + 建议升级
# 无输出 / 命令失败 → WARN(可能 root 受限 / Android < 14)
NS_OUT=$(dumpsys network_stack 2>/dev/null | head -200)
if [ -z "$NS_OUT" ]; then
    warn "dumpsys 格式探针" "dumpsys network_stack 无输出(Android < 14 或 root 受限),DHCP hostname 识别将降级"
else
    HAS_HWADDR=$(printf '%s' "$NS_OUT" | grep -c "hwAddr: ")
    HAS_HOSTNAME=$(printf '%s' "$NS_OUT" | grep -c "hostname: ")
    if [ "$HAS_HWADDR" -gt 0 ] && [ "$HAS_HOSTNAME" -gt 0 ]; then
        ok "dumpsys 格式探针" "hwAddr + hostname 锚点齐全(DHCP 识别功能可用)"
    elif [ "$HAS_HWADDR" -gt 0 ]; then
        warn "dumpsys 格式探针" "有 hwAddr 但无 hostname 字段,可能 ring buffer 暂时无 DHCP 事件,或格式已变"
    elif [ "$HAS_HOSTNAME" -gt 0 ]; then
        warn "dumpsys 格式探针" "有 hostname 但无 hwAddr 字段,格式异常,建议升级 HNC"
    else
        warn "dumpsys 格式探针" "输出存在但无 hwAddr/hostname 字段,Android 版本格式已变,HNC 需要更新"
    fi
fi

# ── [15/16] JSON 健康状态(hotfix18.5) ───────────────────
# hotfix18.3/18.4 引入 json_guard/json_doctor 后,diag 也显示 JSON 健康情况。
# 这里只调用只读 status,不会修改 live JSON。
if [ -x "$HNC/bin/json_doctor.sh" ]; then
    JSON_STATUS_OUT=$(sh "$HNC/bin/json_doctor.sh" status 2>/dev/null)
    JSON_STATUS_RC=$?
    if [ "$JSON_STATUS_RC" -eq 0 ]; then
        ok "JSON 健康" "rules/names/templates/tokens 校验通过"
    else
        warn "JSON 健康" "json_doctor status rc=$JSON_STATUS_RC,建议运行 json_diag_bundle.sh 导出诊断包"
    fi
else
    warn "JSON 健康" "json_doctor.sh 未安装(hotfix18.4+ 应存在)"
fi

# ── [16/16] JSON 备份与 TC 快照(hotfix18.5) ─────────────
JSON_BACKUP_COUNT=$(ls "$HNC/data/.json_backups"/* 2>/dev/null | wc -l)
HAS_TC_STATE=0
[ -f "$HNC/run/tc_state.json" ] && HAS_TC_STATE=1
if [ "$JSON_BACKUP_COUNT" -gt 0 ] && [ "$HAS_TC_STATE" -eq 1 ]; then
    ok "诊断快照" "json_backups=$JSON_BACKUP_COUNT / tc_state.json 已生成"
elif [ "$JSON_BACKUP_COUNT" -gt 0 ]; then
    warn "诊断快照" "json_backups=$JSON_BACKUP_COUNT / tc_state.json 未生成"
elif [ "$HAS_TC_STATE" -eq 1 ]; then
    warn "诊断快照" "无 JSON 备份 / tc_state.json 已生成"
else
    warn "诊断快照" "无 JSON 备份且无 tc_state.json,可运行 json_diag_bundle.sh"
fi

# ── 汇总输出 ────────────────────────────────────────────
if [ $JSON_MODE -eq 1 ]; then
    # JSON 输出
    printf '{"version":"%s","pass":%d,"warn":%d,"fail":%d,"checks":[' "$VER" "$PASS" "$WARN" "$FAIL"
    FIRST=1
    echo "$RESULTS" | while IFS='|' read -r name status detail; do
        [ -z "$name" ] && continue
        [ "$FIRST" = "1" ] || printf ','
        FIRST=0
        # 转义双引号
        ed=$(printf '%s' "$detail" | sed 's/"/\\"/g')
        printf '{"name":"%s","status":"%s","detail":"%s"}' "$name" "$status" "$ed"
    done
    printf ']}\n'
else
    echo ""
    echo "  ──────────────────────────────────────────────"
    printf "  汇总: \033[32m%d OK\033[0m  \033[33m%d WARN\033[0m  \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "  ⚠ 检测到失败项,请查看上方 ✗ 标记"
        echo "  日志路径: $HNC/logs/"
        echo "  GitHub: 报 issue 时请附上本输出"
    elif [ "$WARN" -gt 0 ]; then
        echo ""
        echo "  ✓ 系统基本正常,有少量警告(非致命)"
    else
        echo ""
        echo "  ✓ 系统完全正常"
    fi
    echo ""
fi

# ── 退出码 ──────────────────────────────────────────────
[ "$FAIL" -gt 0 ] && exit 1
[ "$WARN" -gt 0 ] && exit 2
exit 0
