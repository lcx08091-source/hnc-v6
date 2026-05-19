#!/system/bin/sh
# rc16_startup_selfcheck.sh — lightweight runtime health snapshot
# Usage: sh /data/local/hnc/bin/rc16_startup_selfcheck.sh

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
RUN="$HNC_DIR/run"
OUT="$RUN/rc16_startup_selfcheck.txt"
mkdir -p "$RUN" 2>/dev/null || true
{
  echo "=== HNC rc16 startup selfcheck ==="
  date 2>/dev/null || true
  echo
  echo "--- processes ---"
  ps -ef 2>/dev/null | grep -E 'hnc_httpd|hnc_dpid|dpid_guard|watchdog|hotspotd' | grep -v grep || true
  echo
  echo "--- http api ---"
  for ep in /api/live /api/dpi_state /api/dpi_probe; do
    echo "[$ep]"
    curl -sS --connect-timeout 1 --max-time 3 "http://127.0.0.1:8444$ep" 2>&1 | head -c 600
    echo
  done
  echo
  echo "--- iface ---"
  IFACE=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
  [ -z "$IFACE" ] && IFACE=wlan2
  echo "iface=$IFACE"
  ip -o link show "$IFACE" 2>/dev/null || true
  echo "operstate=$(cat /sys/class/net/$IFACE/operstate 2>/dev/null)"
  echo "carrier=$(cat /sys/class/net/$IFACE/carrier 2>/dev/null)"
  ip -4 addr show "$IFACE" 2>/dev/null || true
  echo
  echo "--- arp ---"
  cat /proc/net/arp 2>/dev/null || true
} > "$OUT" 2>&1
cat "$OUT"
