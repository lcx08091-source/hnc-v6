#!/system/bin/sh
# capture.sh — Ground-Truth 抓包工具
# 在你 root 手机上跑, 用 tcpdump + dumpsys 同时抓:
#   1. 全部 TCP/UDP 流量 (pcap 格式)
#   2. 当前前台 App 包名 (时间戳对齐)
# 抓完发 Claude 处理, 自动生成"App→域名/IP/端口"映射

set -e

# ============ 配置 ============
DURATION=${1:-300}  # 默认 5 分钟, 命令行参数可覆盖
IFACE=${2:-wlan0}   # 默认 wlan0, 如果你切到 4G 可改成 rmnet_data0 之类

OUTDIR=/sdcard/Download/sni-ground-truth
mkdir -p "$OUTDIR"

TS=$(date +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/trace-$TS.pcap"
LOG="$OUTDIR/foreground-$TS.log"
META="$OUTDIR/meta-$TS.json"

# ============ 检查环境 ============
echo "─── SNI Ground-Truth 抓包工具 ───"
echo "时长:   ${DURATION} 秒"
echo "网卡:   $IFACE"
echo "输出:   $OUTDIR"
echo

# 看 tcpdump 在不在
if ! command -v tcpdump >/dev/null 2>&1; then
  echo "❌ tcpdump 没装. 请先在 Termux 跑: pkg install tcpdump root-repo"
  echo "   或在 root shell 跑: apt install tcpdump"
  exit 1
fi

# 看 root 权限
if [ "$(id -u)" != "0" ]; then
  echo "⚠ 不是 root, tcpdump 可能抓不到所有包"
  echo "  建议: su 切到 root 再跑这个脚本"
fi

# 看网卡是否存在
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "❌ 网卡 $IFACE 不存在. 用 ip link 看看你的真实网卡名"
  echo "可用网卡:"
  ip -o link show 2>/dev/null | awk '{print "  " $2}' | head -10
  exit 1
fi

# ============ 写入元数据 ============
cat > "$META" <<EOF
{
  "schema": "sni-ground-truth-v1",
  "started_at": "$(date -Iseconds 2>/dev/null || date)",
  "duration_seconds": $DURATION,
  "iface": "$IFACE",
  "device_model": "$(getprop ro.product.model 2>/dev/null || echo unknown)",
  "android_version": "$(getprop ro.build.version.release 2>/dev/null || echo unknown)",
  "host_arch": "$(uname -m)"
}
EOF

echo "── 开始抓包 ──"

# ============ 启动 tcpdump (后台) ============
# -s 200: 每包只抓前 200 字节 (够看 TLS ClientHello SNI + IP + 端口, 文件小很多)
# -w pcap: 写文件
# 过滤: 不抓 ARP/ICMP, 只要 IP 包
tcpdump -i "$IFACE" -s 200 -w "$PCAP" \
  '(tcp or udp) and not arp' \
  >/dev/null 2>&1 &
TD_PID=$!
echo "  tcpdump 已启动 PID=$TD_PID, 输出: $PCAP"

# 等 1 秒确认 tcpdump 真启起来
sleep 1
if ! kill -0 $TD_PID 2>/dev/null; then
  echo "❌ tcpdump 启动失败. 看错误:"
  tcpdump -i "$IFACE" -s 200 -c 1 2>&1 | head -5
  exit 1
fi

# ============ 同时记录前台 App ============
(
  END_TIME=$(($(date +%s) + DURATION))
  while [ "$(date +%s)" -lt "$END_TIME" ]; do
    TS=$(date +%s)
    # dumpsys 拿当前前台 App
    # 优先用 mCurrentFocus, 兜底用 mResumedActivity
    PKG=$(dumpsys window 2>/dev/null | grep -E 'mCurrentFocus|mFocusedApp' | head -1 \
          | sed -E 's/.* ([a-zA-Z0-9._]+)\/[a-zA-Z0-9._]+.*/\1/' | head -1)
    if [ -z "$PKG" ] || [ "$PKG" = "null" ]; then
      PKG=$(dumpsys activity 2>/dev/null | grep -m1 'mResumedActivity' \
            | sed -E 's/.* ([a-zA-Z0-9._]+)\/[a-zA-Z0-9._]+.*/\1/')
    fi
    echo "$TS ${PKG:-unknown}"
    sleep 1
  done
) > "$LOG" 2>/dev/null &
LOG_PID=$!
echo "  前台记录 PID=$LOG_PID, 输出: $LOG"

# ============ 提示 + 等待 ============
echo
echo "🟢 抓包中... ${DURATION} 秒"
echo
echo "💡 现在请:"
echo "   1. 切到你想标注的 App"
echo "   2. 用一会儿 (点击/玩游戏/刷视频, 越真实越好)"
echo "   3. 切到下一个 App, 重复"
echo "   4. 推荐每个 App 至少用 60 秒"
echo
echo "⏱ 倒计时:"

# 倒计时显示 (每 10 秒一次)
START=$(date +%s)
while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  REMAINING=$((DURATION - ELAPSED))
  [ "$REMAINING" -le 0 ] && break
  
  # 看进程还在不在
  if ! kill -0 $TD_PID 2>/dev/null; then
    echo "  ⚠ tcpdump 异常退出"
    break
  fi
  
  printf "\r  ⏳ 剩余 %3d 秒... " "$REMAINING"
  sleep 10
done
echo

# ============ 停止 ============
echo "── 停止抓包 ──"
kill $TD_PID 2>/dev/null
kill $LOG_PID 2>/dev/null
sleep 1
kill -9 $TD_PID 2>/dev/null
kill -9 $LOG_PID 2>/dev/null

# 文件大小报告
echo
echo "✅ 抓包完成"
echo "   pcap:  $PCAP ($(du -h "$PCAP" 2>/dev/null | awk '{print $1}'))"
echo "   log:   $LOG ($(du -h "$LOG" 2>/dev/null | awk '{print $1}'))"
echo "   meta:  $META"
echo
echo "📤 下一步: 把以下 3 个文件发给 Claude:"
echo "   $PCAP"
echo "   $LOG"
echo "   $META"
