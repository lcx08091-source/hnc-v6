#!/system/bin/sh
# HNC hotfix18.6 WebUI JSON debug export wrapper
# Runs json_diag_bundle.sh and prints a small JSON response with the generated path.

set +e
HNC="${HNC:-${HNC_DIR:-/data/local/hnc}}"
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
  case "$_he" in /bin/hnc_env.sh) continue ;; esac
  if [ -f "$_he" ]; then . "$_he"; break; fi
done
unset _he
BIN="$HNC/bin"
RUN="$HNC/run"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | tr '\r\n	' '   ' | tr -d '\000-\010\013\014\016-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'
}

if [ ! -x "$BIN/json_diag_bundle.sh" ]; then
  echo '{"ok":false,"error":"json_diag_bundle.sh missing"}'
  exit 1
fi

OUT="$(sh "$BIN/json_diag_bundle.sh" 2>&1)"
RC=$?
LATEST="$(ls -t /sdcard/Download/hnc-json-debug-*.tar.gz 2>/dev/null | head -1)"
[ -n "$LATEST" ] && echo "$LATEST" > "$RUN/json_diag_last.txt"

cat <<JSON
{
  "ok": $([ "$RC" = 0 ] && echo true || echo false),
  "rc": $RC,
  "path": "$(json_escape "$LATEST")",
  "output": "$(json_escape "$OUT")"
}
JSON
exit "$RC"
