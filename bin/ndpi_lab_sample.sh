#!/system/bin/sh
# ndpi_lab_sample.sh — HNC v5.3.0-rc25.0 optional nDPI one-shot sample
# Safe by default: runs nDPI for a short bounded duration only. It does not
# alter tc/iptables/DNS/offload and does not replace the built-in Go dpid.
# rc24.4: fixes pps/Mb/s parsing and emits structured JSON for WebUI cards.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
ETC="$HNC_DIR/etc"
LOG_DIR="$HNC_DIR/logs"
CONF="$ETC/dpi_ndpi_config.json"
STATE="$RUN/ndpi_lab_state.json"
SAMPLE="$RUN/ndpi_lab_sample.txt"
SAMPLE_STATE="$RUN/ndpi_lab_sample_state.json"
SAMPLE_JSON="$RUN/ndpi_lab_sample_structured.json"
LOG="$LOG_DIR/ndpi_lab.log"
mkdir -p "$RUN" "$ETC" "$LOG_DIR" 2>/dev/null || true

json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g'; }
read_json_string(){ key="$1"; file="$2"; sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" 2>/dev/null | head -1; }
read_json_bool(){ key="$1"; file="$2"; sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$file" 2>/dev/null | head -1; }
num_or_zero(){ v="$1"; case "$v" in ''|*[!0-9.]*|.*.*.*) echo 0 ;; *) echo "$v" ;; esac; }
int_or_zero(){ v="$1"; case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac; }

build_structured_json(){
  now=$(date +%s 2>/dev/null || echo 0)
  engine="$1"; iface="$2"; dur="$3"; timed="$4"
  actual=$(awk '/Actual Memory:/{print $3; exit}' "$SAMPLE" 2>/dev/null); actual=$(num_or_zero "$actual")
  peak=$(awk '/Peak Memory:/{print $3; exit}' "$SAMPLE" 2>/dev/null); peak=$(num_or_zero "$peak")
  flows=$(awk '/Unique flows:/{print $3; exit}' "$SAMPLE" 2>/dev/null); flows=$(int_or_zero "$flows")
  # rc24.4: parse by unit tokens instead of fixed fields. Some ndpiReader
  # builds vary spacing; fixed-field parsing can mistake pps for Mb/sec.
  ndpi_pps=$(awk '/nDPI throughput:/{for(i=1;i<=NF;i++) if($i=="pps"){print $(i-1); exit}}' "$SAMPLE" 2>/dev/null); ndpi_pps=$(num_or_zero "$ndpi_pps")
  ndpi_mbps=$(awk '/nDPI throughput:/{for(i=1;i<=NF;i++) if($i=="Mb/sec" || $i=="Mbit/sec"){print $(i-1); exit}}' "$SAMPLE" 2>/dev/null); ndpi_mbps=$(num_or_zero "$ndpi_mbps")
  traffic_pps=$(awk '/Traffic throughput:/{for(i=1;i<=NF;i++) if($i=="pps"){print $(i-1); exit}}' "$SAMPLE" 2>/dev/null); traffic_pps=$(num_or_zero "$traffic_pps")
  traffic_mbps=$(awk '/Traffic throughput:/{for(i=1;i<=NF;i++) if($i=="Mb/sec" || $i=="Mbit/sec"){print $(i-1); exit}}' "$SAMPLE" 2>/dev/null); traffic_mbps=$(num_or_zero "$traffic_mbps")
  ip_packets=$(awk '/IP packets:/{print $3; exit}' "$SAMPLE" 2>/dev/null); ip_packets=$(int_or_zero "$ip_packets")
  tcp_packets=$(awk '/TCP Packets:/{print $3; exit}' "$SAMPLE" 2>/dev/null); tcp_packets=$(int_or_zero "$tcp_packets")
  udp_packets=$(awk '/UDP Packets:/{print $3; exit}' "$SAMPLE" 2>/dev/null); udp_packets=$(int_or_zero "$udp_packets")
  unknown_flows=$(awk '/Unknown[[:space:]]+packets:/{for(i=1;i<=NF;i++) if($i=="flows:"){print $(i+1); exit}}' "$SAMPLE" 2>/dev/null); unknown_flows=$(int_or_zero "$unknown_flows")
  dpi_flows=$(awk '/Confidence:[[:space:]]+DPI[[:space:]]/{print $3; exit}' "$SAMPLE" 2>/dev/null); dpi_flows=$(int_or_zero "$dpi_flows")

  protocols=$(awk '
    BEGIN{inside=0; first=1}
    function esc(s){gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s}
    /^Detected protocols:/{inside=1; next}
    inside && /^Protocol statistics:/{exit}
    inside && /^[[:space:]]*$/{next}
    inside && /packets:/ {
      line=$0; gsub(/^[ \t]+/,"",line)
      name=line; sub(/[ \t]+packets:.*/,"",name)
      packets=line; sub(/.*packets:[ \t]*/,"",packets); sub(/[ \t]+bytes:.*/,"",packets)
      bytes=line; sub(/.*bytes:[ \t]*/,"",bytes); sub(/[ \t]+flows:.*/,"",bytes)
      flows=line; sub(/.*flows:[ \t]*/,"",flows); sub(/[ \t].*/,"",flows)
      if(packets !~ /^[0-9]+$/) packets=0
      if(bytes !~ /^[0-9]+$/) bytes=0
      if(flows !~ /^[0-9]+$/) flows=0
      if(!first) printf ","
      printf "{\"name\":\"%s\",\"packets\":%s,\"bytes\":%s,\"flows\":%s}", esc(name), packets, bytes, flows
      first=0
    }' "$SAMPLE" 2>/dev/null)
  risks=$(awk '
    BEGIN{inside=0; first=1}
    function esc(s){gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s}
    /^Risk stats /{inside=1; next}
    inside && /NOTE:/{exit}
    inside && /^[[:space:]]*$/{next}
    inside && /\[/ {
      line=$0; gsub(/^[ \t]+/,"",line)
      b=index(line,"["); if(b <= 1) next
      left=substr(line,1,b-1); gsub(/[ \t]+$/,"",left)
      n=split(left,a,/ +/); if(n < 2) next
      count=a[n]; if(count !~ /^[0-9]+$/) next
      name=a[1]; for(i=2;i<n;i++) name=name " " a[i]
      pct=substr(line,b+1); gsub(/^[^0-9.]*/,"",pct); sub(/[^0-9.].*/,"",pct); if(pct !~ /^[0-9.]+$/) pct=0
      if(!first) printf ","
      printf "{\"name\":\"%s\",\"flows\":%s,\"percent\":%s}", esc(name), count, pct
      first=0
    }' "$SAMPLE" 2>/dev/null)
  ee=$(json_escape "$engine"); ei=$(json_escape "$iface")
  [ "$timed" = "true" ] || timed=false
  cat > "$SAMPLE_JSON.tmp" <<EOF_JSON
{"schema_version":"1.3","generated_at":$now,"mode":"sampled","engine_path":"$ee","iface":"$ei","duration_s":$dur,"timed_out":$timed,"sample_path":"$SAMPLE","metrics":{"actual_memory_mb":$actual,"peak_memory_mb":$peak,"unique_flows":$flows,"unknown_flows":$unknown_flows,"dpi_flows":$dpi_flows,"ndpi_pps":$ndpi_pps,"ndpi_mbps":$ndpi_mbps,"traffic_pps":$traffic_pps,"traffic_mbps":$traffic_mbps,"ip_packets":$ip_packets,"tcp_packets":$tcp_packets,"udp_packets":$udp_packets},"protocols":[${protocols}],"risks":[${risks}],"note":"nDPI Lab is one-shot sample only; results are informational and never trigger blocking or throttling"}
EOF_JSON
  mv -f "$SAMPLE_JSON.tmp" "$SAMPLE_JSON" 2>/dev/null || true
}

write_sample_state(){
  mode="$1"; reason="$2"; engine="$3"; iface="$4"; dur="$5"; timed="$6"
  now=$(date +%s 2>/dev/null || echo 0)
  bytes=$(wc -c < "$SAMPLE" 2>/dev/null || echo 0)
  summary=$(grep -E 'Actual Memory|Peak Memory|Unique flows|nDPI throughput|Traffic throughput|Unknown[[:space:]]+packets|DNS[[:space:]]+packets|HTTP[[:space:]]+packets|TLS[[:space:]]+packets|QUIC[[:space:]]+packets|QQ[[:space:]]+packets|Sina\(Weibo\)|Xiaomi[[:space:]]+packets' "$SAMPLE" 2>/dev/null | head -40 | tr '\n' '; ')
  er=$(json_escape "$reason"); ee=$(json_escape "$engine"); ei=$(json_escape "$iface"); es=$(json_escape "$summary")
  [ "$timed" = "true" ] || timed=false
  [ "$mode" = "sampled" ] && build_structured_json "$engine" "$iface" "$dur" "$timed"
  cat > "$SAMPLE_STATE.tmp" <<EOF_STATE
{"schema_version":"1.1","generated_at":$now,"mode":"$mode","reason":"$er","engine_path":"$ee","iface":"$ei","duration_s":$dur,"timed_out":$timed,"sample_path":"$SAMPLE","structured_path":"$SAMPLE_JSON","sample_bytes":$bytes,"summary":"$es"}
EOF_STATE
  mv -f "$SAMPLE_STATE.tmp" "$SAMPLE_STATE" 2>/dev/null || true
}

DUR="$1"
case "$DUR" in ''|*[!0-9]*) DUR=10 ;; esac
[ "$DUR" -lt 3 ] && DUR=3
[ "$DUR" -gt 30 ] && DUR=30

if [ ! -f "$CONF" ] && [ -f "$HNC_DIR/data/dpi_ndpi_config.json" ]; then
  cp -f "$HNC_DIR/data/dpi_ndpi_config.json" "$CONF" 2>/dev/null || true
  chmod 644 "$CONF" 2>/dev/null || true
fi
ENGINE=$(read_json_string engine_path "$CONF")
[ -z "$ENGINE" ] && ENGINE="$HNC_DIR/bin/hnc_ndpi_probe"
IFACE=$(read_json_string iface "$CONF")
[ -z "$IFACE" ] && IFACE=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
[ -z "$IFACE" ] && IFACE=wlan2

FOUND=""
for c in "$ENGINE" "$HNC_DIR/bin/hnc_ndpi_probe" "$HNC_DIR/bin/ndpiReader" "$HNC_DIR/bin/hnc_dpid_ndpi"; do
  [ -n "$c" ] && [ -x "$c" ] && { FOUND="$c"; break; }
done
if [ -z "$FOUND" ]; then
  echo "nDPI engine not found" > "$SAMPLE"
  write_sample_state "missing_engine" "nDPI engine not found" "" "$IFACE" "$DUR" false
  cat "$SAMPLE"
  exit 0
fi

rm -f "$SAMPLE.tmp" "$SAMPLE" "$SAMPLE_JSON"
echo "HNC nDPI one-shot sample" > "$SAMPLE.tmp"
echo "engine=$FOUND iface=$IFACE duration=${DUR}s" >> "$SAMPLE.tmp"
echo "started_at=$(date 2>/dev/null)" >> "$SAMPLE.tmp"
echo "" >> "$SAMPLE.tmp"

"$FOUND" -i "$IFACE" -s "$DUR" >> "$SAMPLE.tmp" 2>&1 &
pid=$!

# rc28: cleanup trap - 如果 shell 被 KSU bridge 中断 (用户切走), 杀掉子 ndpi 不留孤儿
cleanup_sample() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
  fi
  # 兜底: 杀掉所有 hnc_ndpi_probe (防止僵尸)
  pkill -f "$HNC_DIR/bin/hnc_ndpi_probe" 2>/dev/null || true
}
trap cleanup_sample TERM INT HUP EXIT

limit=$((DUR + 8))
i=0
timed_out=false
while [ "$i" -lt "$limit" ]; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
  i=$((i + 1))
done
if kill -0 "$pid" 2>/dev/null; then
  timed_out=true
  kill "$pid" 2>/dev/null || true
  sleep 1
  kill -9 "$pid" 2>/dev/null || true
  echo "" >> "$SAMPLE.tmp"
  echo "WARN: nDPI sample timed out and was stopped after ${limit}s" >> "$SAMPLE.tmp"
fi
mv -f "$SAMPLE.tmp" "$SAMPLE" 2>/dev/null || true
write_sample_state "sampled" "nDPI one-shot sample finished" "$FOUND" "$IFACE" "$DUR" "$timed_out"
echo "sampled engine=$FOUND iface=$IFACE duration=${DUR}s timed_out=$timed_out" >> "$LOG"
cat "$SAMPLE"
echo
echo "--- sample_state ---"
cat "$SAMPLE_STATE" 2>/dev/null || true
echo
echo "--- sample_structured ---"
cat "$SAMPLE_JSON" 2>/dev/null || true
exit 0
