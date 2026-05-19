#!/system/bin/sh
# ndpi_continuous.sh — HNC v5.3.0-rc28.0 持续模式 nDPI 观察器
#
# 跟一次性的 ndpi_lab_sample.sh 不同, 这个脚本让 hnc_ndpi_probe 作为常驻
# daemon 长期运行, 周期性 (每 60 秒) 输出 per-flow CSV, 然后由解析器抽取:
#   1. QUIC ClientHello SNI (nDPI 自带 RFC 9001 Initial 解密)
#   2. TLS over TCP/443 SNI
#   3. DNS query/answer (用于 ipToHost 反查)
# 最终写入 quic_dns_observations.json 给 WebUI 读.
#
# 关键设计:
#   * PID 锁文件防止重复启动
#   * trap 处理 SIGTERM/SIGINT 干净退出 (不留孤儿子进程)
#   * CSV 滚动: 每 ROTATE_SEC 秒 rename 一次, 上一段被 parse 后删除
#   * 限制 max 内存增长 - 通过 ndpiReader 自己的 LRU
#
# 默认关闭 (要从 settings UI 打开).

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
ETC="$HNC_DIR/etc"
LOG_DIR="$HNC_DIR/logs"
BIN_DIR="$HNC_DIR/bin"

PIDFILE="$RUN/ndpi_continuous.pid"
LOGFILE="$LOG_DIR/ndpi_continuous.log"
CSV_CURRENT="$RUN/ndpi_continuous_current.csv"
CSV_PENDING="$RUN/ndpi_continuous_pending.csv"
OBS_JSON="$RUN/quic_dns_observations.json"
IPTOHOST_JSON="$RUN/ip_to_host.json"

ROTATE_SEC="${HNC_NDPI_ROTATE_SEC:-60}"
MAX_OBS="${HNC_NDPI_MAX_OBS:-500}"

mkdir -p "$RUN" "$LOG_DIR" 2>/dev/null || true

log() { echo "[$(date +%Y-%m-%dT%H:%M:%S 2>/dev/null)] $*" >> "$LOGFILE" 2>/dev/null; }

# 找接口
IFACE=$(sed -n 's/.*"hotspot_iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=wlan2

# 命令分发
ACTION="${1:-start}"

case "$ACTION" in
  start)
    # 检查 PID 锁
    if [ -f "$PIDFILE" ]; then
      old_pid=$(cat "$PIDFILE" 2>/dev/null)
      if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
        log "already running pid=$old_pid"
        echo "{\"status\":\"already_running\",\"pid\":$old_pid}"
        exit 0
      else
        rm -f "$PIDFILE"
      fi
    fi

    # 找 probe 二进制
    PROBE="$BIN_DIR/hnc_ndpi_probe"
    if [ ! -x "$PROBE" ]; then
      log "probe binary missing: $PROBE"
      echo "{\"status\":\"error\",\"error\":\"probe_missing\"}"
      exit 1
    fi

    log "starting continuous mode iface=$IFACE rotate=${ROTATE_SEC}s"
    echo "$$" > "$PIDFILE"

    # trap: 收到 TERM/INT 时 kill ndpi 子进程
    NDPI_PID=""
    cleanup() {
      log "cleanup, killing ndpi pid=$NDPI_PID"
      [ -n "$NDPI_PID" ] && kill "$NDPI_PID" 2>/dev/null
      sleep 1
      [ -n "$NDPI_PID" ] && kill -9 "$NDPI_PID" 2>/dev/null
      rm -f "$PIDFILE" "$CSV_CURRENT" "$CSV_PENDING"
      exit 0
    }
    trap cleanup TERM INT EXIT

    # 主循环: 每 ROTATE_SEC 秒重启一次 ndpi probe, parse 上一段输出
    while true; do
      # 启动新一段 ndpi 抓包
      rm -f "$CSV_CURRENT"
      "$PROBE" -i "$IFACE" -s "$ROTATE_SEC" -C "$CSV_CURRENT" >/dev/null 2>&1 &
      NDPI_PID=$!

      # 等到下一个 rotate 周期 (probe 自己会按 -s 退出)
      i=0
      while [ "$i" -lt "$((ROTATE_SEC + 3))" ]; do
        kill -0 "$NDPI_PID" 2>/dev/null || break
        sleep 1
        i=$((i + 1))
      done

      # 如果还在跑, 强杀
      if kill -0 "$NDPI_PID" 2>/dev/null; then
        kill "$NDPI_PID" 2>/dev/null
        sleep 1
        kill -9 "$NDPI_PID" 2>/dev/null
      fi
      NDPI_PID=""

      # parse 这一段 CSV
      if [ -f "$CSV_CURRENT" ]; then
        mv -f "$CSV_CURRENT" "$CSV_PENDING" 2>/dev/null
        sh "$BIN_DIR/ndpi_parse_observations.sh" "$CSV_PENDING" "$OBS_JSON" "$IPTOHOST_JSON" "$MAX_OBS" 2>>"$LOGFILE"
        rm -f "$CSV_PENDING"
      fi
    done
    ;;

  stop)
    if [ -f "$PIDFILE" ]; then
      pid=$(cat "$PIDFILE" 2>/dev/null)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log "stopping pid=$pid"
        kill "$pid" 2>/dev/null
        sleep 2
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
        rm -f "$PIDFILE"
        echo "{\"status\":\"stopped\"}"
      else
        rm -f "$PIDFILE"
        echo "{\"status\":\"not_running\"}"
      fi
    else
      echo "{\"status\":\"not_running\"}"
    fi
    ;;

  status)
    if [ -f "$PIDFILE" ]; then
      pid=$(cat "$PIDFILE" 2>/dev/null)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "{\"status\":\"running\",\"pid\":$pid,\"iface\":\"$IFACE\",\"rotate_sec\":$ROTATE_SEC}"
      else
        rm -f "$PIDFILE"
        echo "{\"status\":\"stale_pidfile\"}"
      fi
    else
      echo "{\"status\":\"not_running\"}"
    fi
    ;;

  *)
    echo "usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
