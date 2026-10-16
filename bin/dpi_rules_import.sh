#!/system/bin/sh
# dpi_rules_import.sh — HNC v5.3.0-rc20.1
# Import/export/reset DPI L3 domain rule library without reflashing.
# Runtime rule path (v5.9.92): /data/local/hnc/etc/dpi_rules.d/99-user-custom.json
#
# v5.9.92 修: 导入此前写 legacy 单文件 etc/dpi_rules.json, 而 dpid 自
# rc30.12.31 起优先读 etc/dpi_rules.d/*.json (99-user-custom 最后加载、
# 覆盖策展规则), 且 service.sh 每次开机从模块目录重同步 dpi_rules.d/ ——
# legacy 单文件在正常情况下永不被读取, 用户导入"成功"却静默无效。
# 现在导入/重置全部改走 99-user-custom.json(99-前缀保证用户规则最后合并、
# 可覆盖策展集)。v5.33: 单文件 dpi_rules.json 删除, --install-default(把整套策展
# 规则再拷一份进用户文件, 效果等同 --reset)随之删除; --export 只导出用户规则。
# Safe scope: only writes DPI rule JSON and optionally triggers dpi_rebind.sh.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-$(cat "$HNC_DIR/run/service.path" 2>/dev/null)}
[ -z "$MODDIR" ] && MODDIR=/data/adb/modules/hotspot_network_control
ETC="$HNC_DIR/etc"
RUN="$HNC_DIR/run"
LOG_DIR="$HNC_DIR/logs"
DST="$ETC/dpi_rules.d/99-user-custom.json"
LOG="$LOG_DIR/dpi_rules_import.log"

mkdir -p "$ETC" "$ETC/dpi_rules.d" "$RUN" "$LOG_DIR" 2>/dev/null || true
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [DPI-RULES] $*" >> "$LOG" 2>/dev/null || true; }
fail(){ echo "ERR: $*" >&2; log "ERR: $*"; exit 1; }

json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g'; }
write_state_note(){
  now=$(date +%s 2>/dev/null || echo 0)
  msg=$(json_escape "$1")
  iface=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
  iface=$(json_escape "$iface")
  cat > "$RUN/dpi_rules_last_import.json.tmp" <<EOF_STATE
{"timestamp":$now,"message":"$msg","path":"$DST","iface":"$iface"}
EOF_STATE
  mv -f "$RUN/dpi_rules_last_import.json.tmp" "$RUN/dpi_rules_last_import.json" 2>/dev/null || true
}

validate_rules(){
  f="$1"
  [ -s "$f" ] || fail "rules file is empty"
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  [ "$sz" -le 524288 ] || fail "rules file too large: $sz bytes"
  grep -q '"rules"[[:space:]]*:' "$f" 2>/dev/null || fail "missing top-level rules array"
  grep -q '"rules_version"[[:space:]]*:' "$f" 2>/dev/null || log "WARN: missing rules_version; dpid will use external"
  # Lightweight brace sanity. Android base system usually has no jq, so avoid jq dependency.
  first=$(tr -d ' \t\r\n' < "$f" | cut -c1 2>/dev/null)
  [ "$first" = "{" ] || fail "not a JSON object"
  return 0
}

rebind_dpi(){
  if [ "${HNC_DPI_RULES_NO_REBIND:-0}" = "1" ]; then return 0; fi
  if [ -x "$HNC_DIR/bin/dpi_rebind.sh" ]; then
    iface=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1)
    [ -z "$iface" ] && iface=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1)
    [ -z "$iface" ] && iface=wlan2
    sh "$HNC_DIR/bin/dpi_rebind.sh" "$iface" >/dev/null 2>&1 || true
  fi
}

case "$1" in
  --export)
    # 导出用户导入的规则(99-user-custom)。策展集不导出(那属于模块本体,
    # 由 data/dpi_rules.d/ 版本化维护)。
    if [ -f "$DST" ]; then cat "$DST"
    else echo '{"schema_version":"1.0","rules_version":"empty","rules":[]}'; fi
    exit 0
    ;;
  --reset)
    rm -f "$DST" 2>/dev/null || true
    write_state_note "user-imported rules removed; curated rules active"
    log "reset custom rules"
    rebind_dpi
    echo "ok: user-imported DPI rules removed; curated rules active"
    exit 0
    ;;
  --stdin|"")
    TMP="$DST.tmp.$$"
    cat > "$TMP" || fail "read stdin failed"
    ;;
  *)
    SRC="$1"
    [ -f "$SRC" ] || fail "source file not found: $SRC"
    TMP="$DST.tmp.$$"
    cp -f "$SRC" "$TMP" || fail "copy source failed"
    ;;
esac

validate_rules "$TMP"
mv -f "$TMP" "$DST" || fail "install rules failed"
chmod 644 "$DST" 2>/dev/null || true
write_state_note "user rules imported as dpi_rules.d/99-user-custom.json"
log "imported custom rules to $DST"
rebind_dpi
echo "ok: imported DPI rules to $DST (user subset, merged last by dpid)"
