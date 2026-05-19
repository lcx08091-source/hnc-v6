#!/system/bin/sh
HNC_DIR=${HNC_DIR:-/data/local/hnc}
STATE="$HNC_DIR/run/ndpi_lab_state.json"
if [ ! -f "$STATE" ]; then
  sh "$HNC_DIR/bin/ndpi_lab_probe.sh" >/dev/null 2>&1 || true
fi
cat "$STATE" 2>/dev/null || echo '{"available":false,"mode":"no_state"}'
