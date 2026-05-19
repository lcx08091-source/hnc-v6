#!/system/bin/sh
# HNC hotfix20.7 JSON writer regression smoke test.
# It runs against a temporary HNC data dir and tries values that used to break
# grep/awk JSON writers: comma, brace, quote, backslash, unicode.

set +e
ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
JSON_SET="$ROOT/bin/json_set.sh"
JSON_GUARD="$ROOT/bin/json_guard.sh"
FAIL=0

say(){ printf '%s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); say "[FAIL] $*"; }
ok(){ say "[OK] $*"; }

TMPBASE="${TMPDIR:-$ROOT/.tmp}"
mkdir -p "$TMPBASE" 2>/dev/null || TMPBASE="$ROOT"
TMP="$TMPBASE/hnc-json-regression-$$"
OUT="$TMPBASE/hnc_json_regression.$$.out"
mkdir -p "$TMP/data" "$TMP/run" "$TMP/logs"

cat > "$TMP/data/rules.json" <<'JSON'
{
  "hotspot_ssid": "old",
  "hotspot_iface": "",
  "blacklist": [],
  "devices": {
    "aa:bb:cc:dd:ee:ff": {
      "ip": "192.168.43.10",
      "down_mbps": 0,
      "up_mbps": 0,
      "note": "old"
    }
  },
  "templates": {}
}
JSON
cat > "$TMP/data/device_names.json" <<'JSON'
{}
JSON
cat > "$TMP/data/templates.json" <<'JSON'
{}
JSON
cat > "$TMP/data/remote_tokens.json" <<'JSON'
{}
JSON

export HNC="$TMP"
export HNC_DIR="$TMP"
export HNC_DATA_DIR="$TMP/data"
export HNC_RUN_DIR="$TMP/run"
export HNC_LOG_DIR="$TMP/logs"

check_json(){
  f="$1"
  if [ -x "$JSON_GUARD" ]; then
    sh "$JSON_GUARD" "$f" >/dev/null 2>&1
    [ $? -eq 0 ] && return 0
  fi
  awk '
  BEGIN{str=0;esc=0;br=0;ba=0;ok=1}
  { for(i=1;i<=length($0);i++){c=substr($0,i,1); if(str){ if(esc){esc=0}else if(c=="\\"){esc=1}else if(c=="\""){str=0} } else { if(c=="\"")str=1; else if(c=="{")br++; else if(c=="}")br--; else if(c=="[")ba++; else if(c=="]")ba--; if(br<0||ba<0)ok=0 } } }
  END{exit !(!str && br==0 && ba==0 && ok)}' "$f"
}

run_json_set(){
  name="$1"; shift
  if [ ! -x "$JSON_SET" ]; then
    fail "json_set.sh not executable: $JSON_SET"
    return 1
  fi
  sh "$JSON_SET" "$@" >"$OUT" 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    fail "$name command failed rc=$rc: sh json_set.sh $*"
    cat "$OUT"
    return 1
  fi
  return 0
}

SSID='我家,客房 } "slash\\end'
NOTE='note, with } brace and "quote" and 中文'
NAME='设备,名称 } "x" \\ y'
TPL='模板,名称 } "z"'

run_json_set "top-special-ssid" top hotspot_ssid "$SSID"
check_json "$TMP/data/rules.json" && ok "rules.json valid after top special ssid" || fail "rules.json invalid after top special ssid"

grep -F '我家,客房' "$TMP/data/rules.json" >/dev/null && ok "SSID comma preserved" || fail "SSID comma not found"

run_json_set "device-note-special" device aa:bb:cc:dd:ee:ff note "$NOTE"
check_json "$TMP/data/rules.json" && ok "rules.json valid after device note" || fail "rules.json invalid after device note"

grep -F 'note, with' "$TMP/data/rules.json" >/dev/null && ok "device note comma preserved" || fail "device note not found"

if sh "$JSON_SET" name_set aa:bb:cc:dd:ee:ff "$NAME" >"$OUT" 2>&1; then
  check_json "$TMP/data/device_names.json" && ok "device_names.json valid after name_set" || fail "device_names invalid after name_set"
else
  say "[WARN] name_set not supported or failed in this tree; output:"; cat "$OUT"
fi

if sh "$JSON_SET" tpl_set "$TPL" down_mbps 1 >"$OUT" 2>&1; then
  check_json "$TMP/data/templates.json" && ok "templates.json valid after tpl_set" || fail "templates invalid after tpl_set"
else
  say "[WARN] tpl_set not supported or failed in this tree; output:"; cat "$OUT"
fi

rm -rf "$TMP" "$OUT"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
