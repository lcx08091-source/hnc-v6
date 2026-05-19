#!/system/bin/sh
# HNC hotfix21.1 stats identity diagnostics helper
# Read-only checker for the IP -> MAC identity map used by stats_sample.sh.
# It helps detect stale devices.json / DHCP IP reuse risks before the v5.2
# stats overhaul. It never edits devices.json, rules.json, stats files, tc, or iptables.

set +e
HNC_DIR="${HNC_DIR:-${HNC:-/data/local/hnc}}"
DATA="$HNC_DIR/data"
DEVICES_FILE="${HNC_DEVICES_FILE:-$DATA/devices.json}"
RAW_FILE="${HNC_STATS_RAW_FILE:-$DATA/stats_raw.jsonl}"
MODE="${1:-json}"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

num_or_zero() {
  case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}

TMP_BASE="${TMPDIR:-$HNC_DIR/run}"
mkdir -p "$TMP_BASE" 2>/dev/null || TMP_BASE="."
DEV_MAP="$TMP_BASE/stats_identity_devices.$$"
RAW_MACS="$TMP_BASE/stats_identity_raw_macs.$$"
DUP_IPS="$TMP_BASE/stats_identity_dup_ips.$$"
trap 'rm -f "$DEV_MAP" "$RAW_MACS" "$DUP_IPS" 2>/dev/null' EXIT INT TERM
: > "$DEV_MAP"
: > "$RAW_MACS"
: > "$DUP_IPS"

# devices.json is expected to be flat: {"mac":{"ip":"...","mac":"...","online":...},...}
# Keep this parser intentionally conservative and read-only; it is diagnostics only.
if [ -f "$DEVICES_FILE" ]; then
  grep -oE '"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"[[:space:]]*:[[:space:]]*\{[^}]*\}' "$DEVICES_FILE" 2>/dev/null | \
  while IFS= read -r block; do
    key_mac=$(echo "$block" | sed -nE 's/^"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})".*/\1/p' | tr 'A-F' 'a-f')
    field_mac=$(echo "$block" | sed -nE 's/.*"mac"[[:space:]]*:[[:space:]]*"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})".*/\1/p' | tr 'A-F' 'a-f')
    ip=$(echo "$block" | sed -nE 's/.*"ip"[[:space:]]*:[[:space:]]*"([0-9]{1,3}(\.[0-9]{1,3}){3})".*/\1/p')
    online=$(echo "$block" | sed -nE 's/.*"online"[[:space:]]*:[[:space:]]*(true|false).*/\1/p')
    [ -z "$field_mac" ] && field_mac="$key_mac"
    [ -z "$online" ] && online="unknown"
    [ -n "$key_mac" ] && printf '%s %s %s %s\n' "$ip" "$key_mac" "$field_mac" "$online" >> "$DEV_MAP"
  done
fi

# Recent raw MACs. We only need distinct MACs and keep the scan bounded.
if [ -f "$RAW_FILE" ]; then
  tail -500 "$RAW_FILE" 2>/dev/null | awk '
  function get_str(line, key,    r,s) {
    r="\"" key "\"[[:space:]]*:[[:space:]]*\"[^\"]*\""
    if (match(line, r)) { s=substr(line,RSTART,RLENGTH); sub(/.*:[[:space:]]*\"/,"",s); sub(/\"$/,"",s); return s }
    return ""
  }
  {
    mac=tolower(get_str($0,"mac"))
    if (mac ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && !(mac in seen)) { seen[mac]=1; print mac }
  }' > "$RAW_MACS"
fi

# Count devices and identity inconsistencies.
if [ -s "$DEV_MAP" ]; then
  DEV_STATS=$(awk '
  $2 != "" {
    total++
    if ($1 != "") { with_ip++; ip_count[$1]++ }
    if ($2 != $3) mismatch++
    if ($4 == "true") online++
  }
  END {
    dup=0
    for (ip in ip_count) if (ip_count[ip] > 1) dup++
    printf "%d %d %d %d %d", total+0, with_ip+0, online+0, mismatch+0, dup+0
  }' "$DEV_MAP")
  set -- $DEV_STATS
  DEVICES_TOTAL=$(num_or_zero "$1")
  DEVICES_WITH_IP=$(num_or_zero "$2")
  DEVICES_ONLINE=$(num_or_zero "$3")
  MAC_MISMATCH=$(num_or_zero "$4")
  DUP_IP_COUNT=$(num_or_zero "$5")
  awk '$1 != "" { ip_count[$1]++; rows[$1]=rows[$1] "," $2 } END { for (ip in ip_count) if (ip_count[ip] > 1) { sub(/^,/,"",rows[ip]); print ip "=" rows[ip] } }' "$DEV_MAP" > "$DUP_IPS"
else
  DEVICES_TOTAL=0
  DEVICES_WITH_IP=0
  DEVICES_ONLINE=0
  MAC_MISMATCH=0
  DUP_IP_COUNT=0
fi

RAW_MAC_COUNT=$(wc -l < "$RAW_MACS" 2>/dev/null | tr -d ' ')
RAW_MAC_COUNT=$(num_or_zero "$RAW_MAC_COUNT")
UNKNOWN_RAW_MACS=0
if [ -s "$RAW_MACS" ]; then
  UNKNOWN_RAW_MACS=$(awk 'NR==FNR { dev[$2]=1; next } $1 != "" && !($1 in dev) { n++ } END { print n+0 }' "$DEV_MAP" "$RAW_MACS" 2>/dev/null)
fi
UNKNOWN_RAW_MACS=$(num_or_zero "$UNKNOWN_RAW_MACS")
DUP_IP_LIST=$(paste -sd ';' "$DUP_IPS" 2>/dev/null)

RISK="ok"
if [ ! -f "$DEVICES_FILE" ]; then
  RISK="missing_devices"
elif [ "$DUP_IP_COUNT" -gt 0 ]; then
  RISK="duplicate_ip"
elif [ "$MAC_MISMATCH" -gt 0 ]; then
  RISK="mac_mismatch"
elif [ "$UNKNOWN_RAW_MACS" -gt 0 ]; then
  RISK="raw_unknown_mac"
fi

TS=$(date +%s 2>/dev/null)
TS=$(num_or_zero "$TS")

case "$MODE" in
  text|status)
    echo "HNC stats identity diagnostics"
    echo "timestamp=$TS"
    echo "hnc_dir=$HNC_DIR"
    echo "devices_file=$DEVICES_FILE"
    echo "raw_file=$RAW_FILE"
    echo "risk=$RISK"
    echo "devices_total=$DEVICES_TOTAL"
    echo "devices_with_ip=$DEVICES_WITH_IP"
    echo "devices_online=$DEVICES_ONLINE"
    echo "mac_mismatch=$MAC_MISMATCH"
    echo "duplicate_ip_count=$DUP_IP_COUNT"
    echo "duplicate_ips=$DUP_IP_LIST"
    echo "recent_raw_macs=$RAW_MAC_COUNT"
    echo "recent_raw_unknown_macs=$UNKNOWN_RAW_MACS"
    ;;
  *)
    cat <<JSON
{"ok":true,"timestamp":$TS,"hnc_dir":"$(json_escape "$HNC_DIR")","risk":"$(json_escape "$RISK")","files":{"devices":"$(json_escape "$DEVICES_FILE")","raw":"$(json_escape "$RAW_FILE")"},"devices":{"total":$DEVICES_TOTAL,"with_ip":$DEVICES_WITH_IP,"online":$DEVICES_ONLINE,"mac_mismatch":$MAC_MISMATCH,"duplicate_ip_count":$DUP_IP_COUNT,"duplicate_ips":"$(json_escape "$DUP_IP_LIST")"},"recent_raw":{"macs":$RAW_MAC_COUNT,"unknown_macs":$UNKNOWN_RAW_MACS}}
JSON
    ;;
esac
