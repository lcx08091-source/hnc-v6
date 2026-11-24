#!/system/bin/sh
# HNC hotfix17.7: lightweight TC state snapshot.
# Read-only. It never changes qdisc/class/filter state.

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LOG="$HNC_DIR/logs/tc_state.log"
mkdir -p "$RUN" "$HNC_DIR/logs" 2>/dev/null || true

pick_bin() {
  b="$1"
  for x in "$HNC_DIR/bin/hnc_$b" "$HNC_DIR/bin/$b" "/system/bin/$b" "/vendor/bin/$b" "/system/xbin/$b"; do
    [ -x "$x" ] && { echo "$x"; return; }
  done
  command -v "$b" 2>/dev/null || echo "$b"
}
TC_BIN=${TC_BIN:-$(pick_bin tc)}
IP_BIN=${IP_BIN:-$(pick_bin ip)}
TC() { "$TC_BIN" "$@"; }
IP() { "$IP_BIN" "$@"; }

iface="$1"
[ -n "$iface" ] || iface=$(cat "$RUN/iface.cache" 2>/dev/null | head -1 | tr -d '\r\n ')
[ -n "$iface" ] || iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | head -1 | tr -d '\r\n ')

qdisc_first=""
root_kind="unknown"
class_count=0
filter_count=0
htb_ready=false
netem_seen=false
fallback="false"
qos_mode=$(cat "$RUN/tc_qos_mode" 2>/dev/null | head -1 | tr -d '\r\n ')
qos_scale=$(cat "$RUN/tc_qos_scale" 2>/dev/null | head -1 | tr -d '\r\n %')
[ -n "$qos_mode" ] || qos_mode="compat"
[ -n "$qos_scale" ] || qos_scale="100"
[ -f "$RUN/tc_qos_fallback" ] && fallback="true"

if [ -n "$iface" ] && IP link show dev "$iface" >/dev/null 2>&1; then
  rm -f "$RUN"/tc_state.*.txt 2>/dev/null || true
  _qd_out=$(TC -s qdisc show dev "$iface" 2>&1 || true)
  _cl_out=$(TC -s class show dev "$iface" 2>&1 || true)
  _fl_out=$(TC filter show dev "$iface" 2>&1 || true)
  qdisc_first=$(printf '%s\n' "$_qd_out" | sed -n '1p')
  root_kind=$(printf '%s\n' "$qdisc_first" | awk '{print $2}')
  printf '%s\n' "$_qd_out" | grep -q '^qdisc htb 1:' 2>/dev/null && htb_ready=true
  printf '%s\n' "$_qd_out" | grep -q 'netem' 2>/dev/null && netem_seen=true
  class_count=$(printf '%s\n' "$_cl_out" | awk '/^class /{c++} END{print c+0}')
  filter_count=$(printf '%s\n' "$_fl_out" | awk '/^filter /{c++} END{print c+0}')
  unset _qd_out _cl_out _fl_out
else
  qdisc_first="iface missing"
fi

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
now=$(date +%s 2>/dev/null || echo 0)
_tc_tmp="$RUN/tc_state.json.tmp.$$"
cat > "$_tc_tmp" <<JSON
{
  "ok": true,
  "ts": $now,
  "iface": "$(esc "$iface")",
  "tc_bin": "$(esc "$TC_BIN")",
  "root_kind": "$(esc "$root_kind")",
  "qdisc_first": "$(esc "$qdisc_first")",
  "htb_ready": $htb_ready,
  "netem_seen": $netem_seen,
  "class_count": $class_count,
  "filter_count": $filter_count,
  "qos_fallback": $fallback,
  "qos_mode": "$(esc "$qos_mode")",
  "qos_scale": "$(esc "$qos_scale")"
}
JSON
mv -f "$_tc_tmp" "$RUN/tc_state.json" 2>/dev/null || {
  cp -f "$_tc_tmp" "$RUN/tc_state.json" 2>/dev/null || true
  rm -f "$_tc_tmp" 2>/dev/null || true
}

{
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] iface=$iface root=$root_kind htb_ready=$htb_ready netem=$netem_seen class=$class_count filter=$filter_count fallback=$fallback qos=$qos_mode scale=$qos_scale"
  echo "  qdisc: $qdisc_first"
} >> "$LOG" 2>/dev/null || true

cat "$RUN/tc_state.json"
