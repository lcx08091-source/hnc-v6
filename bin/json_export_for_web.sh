#!/system/bin/sh
# HNC hotfix18.6 WebUI JSON debug export wrapper
# Runs json_diag_bundle.sh and prints a small JSON response with the generated path.

set +e
HNC="${HNC:-/data/local/hnc}"
BIN="$HNC/bin"
RUN="$HNC/run"
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
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
