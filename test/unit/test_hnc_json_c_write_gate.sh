#!/usr/bin/env sh
# hotfix20.8: optional hnc_json_c writes must be opt-in.
set -eu

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMPBASE="${TMPDIR:-$ROOT/.tmp}"
mkdir -p "$TMPBASE"
TMP="$TMPBASE/hnc-json-c-write-gate-$$"
mkdir -p "$TMP/bin" "$TMP/data" "$TMP/run"

cleanup(){ rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

cp "$ROOT/bin/hnc_json" "$TMP/bin/hnc_json"
chmod 755 "$TMP/bin/hnc_json"
cat > "$TMP/bin/hnc_json_c" <<'SH'
#!/usr/bin/env sh
mkdir -p "${HNC:-/tmp}/run"
echo "$1" >> "${HNC:-/tmp}/run/c_calls"
case "$1" in
  version)
    echo "fake hnc_json_c"
    exit 0
    ;;
  set-object-key|object-set)
    file="$2"; key="$3"
    printf '{"%s":"c-helper"}\n' "$key" > "$file"
    exit 0
    ;;
  *)
    exit 127
    ;;
esac
SH
chmod 755 "$TMP/bin/hnc_json_c"

export HNC="$TMP"
export HNC_DIR="$TMP"
export HNC_JSON_C_ALLOW_HOST=1
unset HNC_JSON_C_WRITE_ENABLE

echo '{}' > "$TMP/data/device_names.json"
sh "$TMP/bin/hnc_json" set-object-key "$TMP/data/device_names.json" 'aa:bb:cc:dd:ee:ff' 'shell-path' str

if [ -f "$TMP/run/c_calls" ]; then
  echo "[FAIL] C helper was called even though HNC_JSON_C_WRITE_ENABLE is unset" >&2
  cat "$TMP/run/c_calls" >&2
  exit 1
fi

grep -F 'shell-path' "$TMP/data/device_names.json" >/dev/null || {
  echo "[FAIL] shell fallback did not write expected value" >&2
  cat "$TMP/data/device_names.json" >&2
  exit 1
}

export HNC_JSON_C_WRITE_ENABLE=1
sh "$TMP/bin/hnc_json" set-object-key "$TMP/data/device_names.json" 'aa:bb:cc:dd:ee:ff' 'c-path' str

grep -F 'set-object-key' "$TMP/run/c_calls" >/dev/null || {
  echo "[FAIL] C helper was not called after HNC_JSON_C_WRITE_ENABLE=1" >&2
  exit 1
}
grep -F 'c-helper' "$TMP/data/device_names.json" >/dev/null || {
  echo "[FAIL] C helper did not write expected marker" >&2
  cat "$TMP/data/device_names.json" >&2
  exit 1
}

echo "[OK] hnc_json_c write gate works"
