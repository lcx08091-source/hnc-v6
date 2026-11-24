#!/system/bin/sh
# dpi_rules_import.sh — Import/export/reset DPI L3 domain rule library without reflashing.
# Runtime rule path: /data/local/hnc/etc/dpi_rules.d/99-user-custom.json
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
if [ -z "$MODDIR" ]; then [ -d /data/adb/modules/hotspot_net_ctl ] && MODDIR=/data/adb/modules/hotspot_net_ctl || MODDIR=/data/adb/modules/hotspot_network_control; fi
ETC="$HNC_DIR/etc"
RUN="$HNC_DIR/run"
LOG_DIR="$HNC_DIR/logs"
DST="$ETC/dpi_rules.d/99-user-custom.json"
LOG="$LOG_DIR/dpi_rules_import.log"

mkdir -p "$ETC" "$ETC/dpi_rules.d" "$RUN" "$LOG_DIR" 2>/dev/null || true
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [DPI-RULES] $*" >> "$LOG" 2>/dev/null || true; }
TMP=""
IN_TMP=""
_imp_cleanup(){
  [ -n "${TMP:-}" ] && rm -f "$TMP" 2>/dev/null || true
  [ -n "${IN_TMP:-}" ] && rm -f "$IN_TMP" 2>/dev/null || true
}
trap '_imp_cleanup' EXIT
trap '_imp_cleanup; trap - EXIT; exit 130' INT
trap '_imp_cleanup; trap - EXIT; exit 143' TERM

fail(){ _imp_cleanup; echo "ERR: $*" >&2; log "ERR: $*"; exit 1; }

json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g'; }
write_state_note(){
  now=$(date +%s 2>/dev/null || echo 0)
  msg=$(json_escape "$1")
  iface=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1 | tr -d '\r\n')
  iface=$(json_escape "$iface")
  _note_tmp="$RUN/dpi_rules_last_import.json.tmp.$$"
  if cat > "$_note_tmp" 2>/dev/null <<EOF_STATE && [ -s "$_note_tmp" ]; then
{"timestamp":$now,"message":"$msg","path":"$DST","iface":"$iface"}
EOF_STATE
    mv -f "$_note_tmp" "$RUN/dpi_rules_last_import.json" 2>/dev/null || rm -f "$_note_tmp" 2>/dev/null || true
  else
    rm -f "$_note_tmp" 2>/dev/null || true
  fi
}

validate_rules(){
  f="$1"
  [ -s "$f" ] || fail "rules file is empty"
  sz=$(wc -c < "$f" 2>/dev/null | tr -dc '0-9')
  [ "${sz:-0}" -le 524288 ] || fail "rules file too large: $sz bytes"
  grep -q '"rules"[[:space:]]*:' "$f" 2>/dev/null || fail "missing top-level rules array"
  grep -q '"rules_version"[[:space:]]*:' "$f" 2>/dev/null || log "WARN: missing rules_version; dpid will use external"
  # Lightweight brace/string sanity via json_guard.sh when present, fallback to awk state machine.
  first=$(tr -d ' \t\r\n' < "$f" | cut -c1 2>/dev/null)
  [ "$first" = "{" ] || fail "not a JSON object"
  for _jg in "$HNC_DIR/bin/json_guard.sh" "${MODDIR:-}/bin/json_guard.sh" "${0%/*}/json_guard.sh"; do
    if [ -f "$_jg" ]; then
      sh "$_jg" "$f" >/dev/null 2>&1 || fail "invalid JSON syntax"
      break
    fi
  done
  return 0
}

merge_rules_json(){
  _old="$1"
  _new="$2"
  awk '
  function ch(s, i) { return substr(s, i, 1) }
  function skip_ws(s, n, i) { while (i <= n && ch(s, i) ~ /[ \t\r\n]/) i++; return i }
  function parse_str(s, n, i,   j, c, out, esc) {
    out = ""; esc = 0
    if (ch(s, i) != "\"") return 0
    for (j = i + 1; j <= n; j++) {
      c = ch(s, j)
      if (esc) { out = out c; esc = 0; continue }
      if (c == "\\") { esc = 1; continue }
      if (c == "\"") { p_val = out; return j + 1 }
      out = out c
    }
    return 0
  }
  function val_end(s, n, i,   j, c, dep, ins, esc, ni) {
    i = skip_ws(s, n, i); c = ch(s, i)
    if (c == "\"") { ni = parse_str(s, n, i); return ni ? ni : n + 1 }
    if (c == "{" || c == "[") {
      dep = 0; ins = 0; esc = 0
      for (j = i; j <= n; j++) {
        c = ch(s, j)
        if (ins) { if (esc) esc = 0; else if (c == "\\") esc = 1; else if (c == "\"") ins = 0; continue }
        if (c == "\"") { ins = 1; continue }
        if (c == "{" || c == "[") dep++
        else if (c == "}" || c == "]") { dep--; if (dep <= 0) return j + 1 }
      }
      return n + 1
    }
    for (j = i; j <= n; j++) { c = ch(s, j); if (c == "," || c == "}" || c == "]" || c ~ /[ \t\r\n]/) return j }
    return n + 1
  }
  function extract_rule_id(s, os, oe,   p, c, ni, fk) {
    p = skip_ws(s, oe, os + 1)
    while (p < oe) {
      p = skip_ws(s, oe, p); c = ch(s, p)
      if (c == "}" || c == "") return ""
      if (c == ",") { p++; continue }
      if (c != "\"") return ""
      ni = parse_str(s, oe, p); if (!ni) return ""
      fk = p_val; p = skip_ws(s, oe, ni)
      if (ch(s, p) != ":") return ""
      p = skip_ws(s, oe, p + 1)
      if (fk == "id" && ch(s, p) == "\"") {
        ni = parse_str(s, oe, p)
        return ni ? p_val : ""
      }
      p = val_end(s, oe, p)
    }
    return ""
  }
  function esc_json_str(x,   i, c, out) {
    out = ""
    for (i = 1; i <= length(x); i++) {
      c = substr(x, i, 1)
      if (c == "\\") out = out "\\\\"
      else if (c == "\"") out = out "\\\""
      else if (c >= " ") out = out c
    }
    return out
  }
  function parse_doc(s, tag,   n, i, c, ni, k, ve, p, re, rid, raw) {
    n = length(s); i = skip_ws(s, n, 1)
    if (ch(s, i) != "{") return 0
    i++
    while (i <= n) {
      i = skip_ws(s, n, i); c = ch(s, i)
      if (c == "}" || c == "") break
      if (c == ",") { i++; continue }
      if (c != "\"") return 0
      ni = parse_str(s, n, i); if (!ni) return 0
      k = p_val; i = skip_ws(s, n, ni)
      if (ch(s, i) != ":") return 0
      i = skip_ws(s, n, i + 1)
      ve = val_end(s, n, i)
      if (k == "schema_version" && ch(s, i) == "\"") {
        if (parse_str(s, n, i) && p_val != "") meta_sv[tag] = p_val
      } else if (k == "rules_version" && ch(s, i) == "\"") {
        if (parse_str(s, n, i) && p_val != "") meta_rv[tag] = p_val
      } else if (k == "rules" && ch(s, i) == "[") {
        p = skip_ws(s, ve, i + 1)
        while (p < ve) {
          p = skip_ws(s, ve, p); c = ch(s, p)
          if (c == "]" || c == "") break
          if (c == ",") { p++; continue }
          if (c != "{") return 0
          re = val_end(s, ve, p)
          raw = substr(s, p, re - p)
          gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", raw)
          rid = extract_rule_id(s, p, re)
          if (tag == "old") {
            old_n++
            old_raw[old_n] = raw
            old_id[old_n] = rid
          } else {
            if (rid != "" && (rid in new_idx)) {
              new_raw[new_idx[rid]] = raw
            } else {
              new_n++
              new_raw[new_n] = raw
              new_id[new_n] = rid
              if (rid != "") new_idx[rid] = new_n
            }
          }
          p = re
        }
      }
      i = ve
    }
    return 1
  }
  BEGIN {
    old_f = ARGV[1]; new_f = ARGV[2]; ARGV[1] = ""; ARGV[2] = ""
    s_old = ""; s_new = ""
    while ((getline ln < old_f) > 0) s_old = s_old ln "\n"
    close(old_f)
    while ((getline ln < new_f) > 0) s_new = s_new ln "\n"
    close(new_f)
    old_n = 0; new_n = 0
    if (!parse_doc(s_old, "old")) exit 1
    if (!parse_doc(s_new, "new")) exit 1
    sv = (meta_sv["new"] != "") ? meta_sv["new"] : ((meta_sv["old"] != "") ? meta_sv["old"] : "1.0")
    rv = (meta_rv["new"] != "") ? meta_rv["new"] : ((meta_rv["old"] != "") ? meta_rv["old"] : "user-merged")
    out_n = 0
    for (i = 1; i <= old_n; i++) {
      rid = old_id[i]
      if (rid != "" && (rid in new_idx)) {
        if (emitted[rid]) continue
        emitted[rid] = 1
        out_n++
        out_raw[out_n] = new_raw[new_idx[rid]]
      } else {
        if (rid != "") {
          if (emitted[rid]) continue
          emitted[rid] = 1
        }
        out_n++
        out_raw[out_n] = old_raw[i]
      }
    }
    for (j = 1; j <= new_n; j++) {
      rid = new_id[j]
      if (rid != "" && emitted[rid]) continue
      if (rid != "") emitted[rid] = 1
      out_n++
      out_raw[out_n] = new_raw[j]
    }
    printf "{\n  \"schema_version\": \"%s\",\n  \"rules_version\": \"%s\",\n  \"rules\": [", esc_json_str(sv), esc_json_str(rv)
    for (k = 1; k <= out_n; k++) {
      printf "%s\n    %s", (k > 1 ? "," : ""), out_raw[k]
    }
    if (out_n > 0) printf "\n  ]\n}\n"
    else printf "]\n}\n"
  }' "$_old" "$_new"
}

rebind_dpi(){
  if [ "${HNC_DPI_RULES_NO_REBIND:-0}" = "1" ]; then return 0; fi
  if [ -x "$HNC_DIR/bin/dpi_rebind.sh" ] || [ -f "$HNC_DIR/bin/dpi_rebind.sh" ]; then
    iface=$(cat "$RUN/hotspot_iface" 2>/dev/null | head -1 | tr -d ' \r\n')
    [ -z "$iface" ] && iface=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/dpi_config.json" 2>/dev/null | head -1 | tr -d ' \r\n')
    [ -z "$iface" ] && iface=auto
    HNC_DPI_REBIND_KEEP_CONFIG=1 sh "$HNC_DIR/bin/dpi_rebind.sh" "$iface" >/dev/null 2>&1 || true
  fi
}

MERGE_MODE=0
case "${1:-}" in
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
  --merge)
    MERGE_MODE=1
    shift
    case "${1:-}" in
      --stdin|"")
        IN_TMP="$DST.in.$$"
        cat > "$IN_TMP" || fail "read stdin failed"
        ;;
      --*)
        fail "unknown option: $1"
        ;;
      *)
        SRC="$1"
        [ -f "$SRC" ] || fail "source file not found: $SRC"
        IN_TMP="$DST.in.$$"
        cp -f "$SRC" "$IN_TMP" || fail "copy source failed"
        ;;
    esac
    ;;
  --stdin|"")
    TMP="$DST.tmp.$$"
    cat > "$TMP" || fail "read stdin failed"
    ;;
  --*)
    fail "unknown option: $1"
    ;;
  *)
    SRC="$1"
    if [ "${2:-}" = "--merge" ]; then
      MERGE_MODE=1
      [ -f "$SRC" ] || fail "source file not found: $SRC"
      IN_TMP="$DST.in.$$"
      cp -f "$SRC" "$IN_TMP" || fail "copy source failed"
    else
      [ -f "$SRC" ] || fail "source file not found: $SRC"
      TMP="$DST.tmp.$$"
      cp -f "$SRC" "$TMP" || fail "copy source failed"
    fi
    ;;
esac

if [ "$MERGE_MODE" = "1" ]; then
  validate_rules "$IN_TMP"
  TMP="$DST.tmp.$$"
  if [ -s "$DST" ] && grep -q '"rules"[[:space:]]*:' "$DST" 2>/dev/null; then
    merge_rules_json "$DST" "$IN_TMP" > "$TMP" || fail "merge rules failed"
  else
    cp -f "$IN_TMP" "$TMP" || fail "stage rules failed"
  fi
  rm -f "$IN_TMP" 2>/dev/null || true
  IN_TMP=""
fi

validate_rules "$TMP"
if [ -s "$TMP" ] && mv -f "$TMP" "$DST"; then
  TMP=""
else
  fail "install rules failed"
fi
chmod 644 "$DST" 2>/dev/null || true
if [ "$MERGE_MODE" = "1" ]; then
  write_state_note "user rules merged into dpi_rules.d/99-user-custom.json"
  log "merged custom rules into $DST"
  rebind_dpi
  echo "ok: merged DPI rules into $DST (by id, existing rules preserved)"
else
  write_state_note "user rules imported as dpi_rules.d/99-user-custom.json"
  log "imported custom rules to $DST"
  rebind_dpi
  echo "ok: imported DPI rules to $DST (user subset, merged last by dpid)"
fi
