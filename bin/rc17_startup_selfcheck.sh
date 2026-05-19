#!/system/bin/sh
# rc17_startup_selfcheck.sh — quick runtime selfcheck after boot/restart/hotspot toggle
HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
OUT="$RUN/rc17_startup_selfcheck.txt"
mkdir -p "$RUN" 2>/dev/null || true
{
  echo "=== HNC rc17 startup selfcheck ==="
  date 2>/dev/null || true
  echo
  echo "--- process health ---"
  if [ -x "$HNC_DIR/bin/rc17_process_health.sh" ]; then
    sh "$HNC_DIR/bin/rc17_process_health.sh"
  else
    ps -ef 2>/dev/null | grep -E 'hnc_httpd|hnc_dpid|hnc_dpid_guard|watchdog.sh|hotspotd' | grep -v grep
  fi
  echo
  echo "--- dpi api ---"
  curl -s http://127.0.0.1:8444/api/dpi_state 2>/dev/null | head -c 500; echo
  curl -s http://127.0.0.1:8444/api/dpi_probe 2>/dev/null | head -c 500; echo
} > "$OUT" 2>&1
cat "$OUT"
