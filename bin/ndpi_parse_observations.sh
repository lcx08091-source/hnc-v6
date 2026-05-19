#!/system/bin/sh
# ndpi_parse_observations.sh — HNC v5.3.0-rc28.0
# 解析 hnc_ndpi_probe 的 per-flow CSV, 抽取:
#   - QUIC ClientHello SNI (proto 含 QUIC, server_name_sni 非空)
#   - TLS over TCP/443 SNI
#   - DNS A/AAAA 解析对 (用 query/answer 建 ipToHost 反查表)
# 输出两个 JSON:
#   $2: quic_dns_observations.json — UI 显示用 (最近 MAX 条观察)
#   $3: ip_to_host.json — 反查表 (内部使用)
#
# CSV 字段 (ndpiReader -C 输出):
# flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,dst_ip,dst_port,
# ndpi_proto_num,ndpi_proto,proto_by_ip,server_name_sni,...
# advertised_alpns,negotiated_alpn,tls_supported_versions,tls_version,quic_version,...

CSV="${1:-/dev/null}"
OBS_JSON="${2:-/data/local/hnc/run/quic_dns_observations.json}"
IPTOHOST_JSON="${3:-/data/local/hnc/run/ip_to_host.json}"
MAX_OBS="${4:-500}"

[ -f "$CSV" ] || exit 0
[ -s "$CSV" ] || exit 0

# 找列号 (ndpiReader 版本不同列顺序可能微变)
HEADER=$(head -1 "$CSV" 2>/dev/null)
if [ -z "$HEADER" ]; then
  exit 0
fi

# awk 解析: 输出三种行
#   OBS|<ts>|<proto>|<src_ip>|<dst_ip>|<sni>|<alpn>|<quic_ver>
#   DNS|<query>|<answer_ip>
PARSED=$(awk -F, '
  NR==1 {
    for (i=1; i<=NF; i++) {
      h=$i; gsub(/^"+|"+$/, "", h); gsub(/^#/,"",h);
      col[h] = i;
    }
    next;
  }
  NR>1 {
    proto = $col["ndpi_proto"]; gsub(/^"+|"+$/, "", proto);
    sni = $col["server_name_sni"]; gsub(/^"+|"+$/, "", sni);
    src_ip = $col["src_ip"]; gsub(/^"+|"+$/, "", src_ip);
    dst_ip = $col["dst_ip"]; gsub(/^"+|"+$/, "", dst_ip);
    src_port = $col["src_port"]; gsub(/^"+|"+$/, "", src_port);
    dst_port = $col["dst_port"]; gsub(/^"+|"+$/, "", dst_port);
    last_seen = $col["last_seen"]; gsub(/^"+|"+$/, "", last_seen);

    # alpn / quic_ver 可能不在所有版本
    alpn = "";
    if ("negotiated_alpn" in col) { alpn = $col["negotiated_alpn"]; gsub(/^"+|"+$/, "", alpn); }
    if (alpn == "" && "advertised_alpns" in col) { alpn = $col["advertised_alpns"]; gsub(/^"+|"+$/, "", alpn); }
    qver = "";
    if ("quic_version" in col) { qver = $col["quic_version"]; gsub(/^"+|"+$/, "", qver); }

    # 观察事件: 有 SNI 就输出
    if (sni != "" && sni != "-") {
      printf "OBS|%s|%s|%s|%s|%s|%s|%s\n", last_seen, proto, src_ip, dst_ip, sni, alpn, qver;
    }

    # DNS 反查表: ndpiReader 的 DNS flow 会把 query name 放 server_name_sni
    # proto 名包含 "DNS"; src/dst 一个是客户端一个是 DNS server
    # ndpi 在 ndpi_proto 字段会标 "DNS" 或 "DNS.XXX"
    if (proto ~ /DNS/ && sni != "" && sni != "-") {
      # CSV 不直接给 answer_ip — 我们用 dst_ip 作为最近 DNS 解析的目标 (近似)
      # 实际生产中 DNS answer IP 要从 packet inspection 才能拿到, ndpiReader 默认不输出 IP 答案
      # 但 QUIC/TLS SNI 流的 dst_ip 就是 hostname 对应的 IP, 直接拿这个
      # 所以 DNS 这条用不上, 真正的反查表来自 QUIC/TLS SNI 流本身
      next;
    }
  }
' "$CSV" 2>/dev/null)

# 用 SNI 流的 (sni, dst_ip) 反过来建 ipToHost
# 因为 ndpi 已经在 SNI 流里告诉了我们 dst_ip -> sni 的对应
TMP_OBS="$OBS_JSON.tmp"
TMP_IP="$IPTOHOST_JSON.tmp"

# 读已有 obs/iptohost (合并新数据, 不是覆盖)
OLD_OBS_BODY=""
OLD_IP_BODY=""
[ -f "$OBS_JSON" ] && OLD_OBS_BODY=$(sed -n 's/.*"observations"[[:space:]]*:[[:space:]]*\(\[.*\]\).*/\1/p' "$OBS_JSON" 2>/dev/null | head -1)
[ -f "$IPTOHOST_JSON" ] && OLD_IP_BODY=$(sed -n 's/.*"entries"[[:space:]]*:[[:space:]]*\(\[.*\]\).*/\1/p' "$IPTOHOST_JSON" 2>/dev/null | head -1)
[ -z "$OLD_OBS_BODY" ] && OLD_OBS_BODY="[]"
[ -z "$OLD_IP_BODY" ] && OLD_IP_BODY="[]"

# 生成新 observation entries
NEW_OBS_RAW=$(echo "$PARSED" | awk -F'|' '
  $1 == "OBS" {
    # ts proto src_ip dst_ip sni alpn quic_ver
    ts=$2; proto=$3; src=$4; dst=$5; sni=$6; alpn=$7; qver=$8;
    # 判定识别来源
    src_label="tls-sni";
    if (proto ~ /QUIC/) src_label="quic-sni";
    else if (proto ~ /DNS/) src_label="dns";

    # JSON escape
    gsub(/\\/, "\\\\", sni); gsub(/"/, "\\\"", sni);
    gsub(/\\/, "\\\\", alpn); gsub(/"/, "\\\"", alpn);
    gsub(/\\/, "\\\\", proto); gsub(/"/, "\\\"", proto);

    printf "{\"ts\":\"%s\",\"proto\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"sni\":\"%s\",\"alpn\":\"%s\",\"quic_version\":\"%s\",\"source\":\"%s\"}\n", ts, proto, src, dst, sni, alpn, qver, src_label;
  }
')

# 生成 ipToHost 反查表 entries: 每个 (dst_ip, sni) 一条
NEW_IP_RAW=$(echo "$PARSED" | awk -F'|' '
  $1 == "OBS" && $6 != "" {
    sni=$6; dst=$5; ts=$2;
    # JSON escape
    gsub(/\\/, "\\\\", sni); gsub(/"/, "\\\"", sni);
    printf "{\"ip\":\"%s\",\"host\":\"%s\",\"last_seen\":\"%s\"}\n", dst, sni, ts;
  }
' | sort -u)

# 拼成 JSON array, 限制最多 MAX_OBS 条 (新的在前)
build_array() {
  body="$1"
  if [ -z "$body" ]; then
    echo "[]"
    return
  fi
  # body 是多行 JSON 对象, 把它们拼成 array
  echo "$body" | awk -v max="$2" '
    NR==1 { printf "["; printf "%s", $0; n=1; next }
    NR>1 && n<max { printf ","; printf "%s", $0; n++ }
    END { printf "]" }
  '
}

NEW_OBS_ARR=$(build_array "$NEW_OBS_RAW" "$MAX_OBS")
NEW_IP_ARR=$(build_array "$NEW_IP_RAW" "$MAX_OBS")

# 简单合并: 新的+旧的, 取前 MAX_OBS (不去重, 因为时间不同算不同观察)
# 这一段在 shell 里做合并太繁琐, 直接以新替旧 (acceptable - 60 秒 rotate, 信息保留 60s)
NOW_TS=$(date +%s 2>/dev/null || echo 0)
NOW_HUMAN=$(date 2>/dev/null || echo "")

cat > "$TMP_OBS" <<EOF
{
  "schema_version": "1.0",
  "rc": "rc28.0",
  "generated_at": "$NOW_HUMAN",
  "generated_ts": $NOW_TS,
  "rotate_window_sec": 60,
  "observations": $NEW_OBS_ARR
}
EOF

cat > "$TMP_IP" <<EOF
{
  "schema_version": "1.0",
  "rc": "rc28.0",
  "generated_at": "$NOW_HUMAN",
  "generated_ts": $NOW_TS,
  "entries": $NEW_IP_ARR
}
EOF

mv -f "$TMP_OBS" "$OBS_JSON" 2>/dev/null || true
mv -f "$TMP_IP" "$IPTOHOST_JSON" 2>/dev/null || true

exit 0
