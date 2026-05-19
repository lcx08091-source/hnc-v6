#!/system/bin/sh
# Build helper for the optional hnc_json C helper.
# hotfix20.8: refuse accidental host/Linux helper builds unless explicitly allowed.
# Default output path is the module runtime location bin/hnc_json_c when the
# script is run from the source tree; pass an explicit output path to override.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." 2>/dev/null && pwd)"
CC="${CC:-clang}"
OUT="${1:-$ROOT/bin/hnc_json_c}"
TMPBASE="${TMPDIR:-$ROOT/.tmp}"
TMP="$TMPBASE/hnc_json_c.$$"
mkdir -p "$(dirname "$OUT")" "$TMPBASE"

TARGET="$($CC -dumpmachine 2>/dev/null || true)"
case "$TARGET $CC" in
  *android*|*aarch64-linux-android*|*armv7a-linux-androideabi*) : ;;
  *)
    if [ "${HNC_JSON_C_ALLOW_HOST:-0}" != "1" ]; then
      echo "build_hnc_json: refusing host helper build target='${TARGET:-unknown}' cc='$CC'" >&2
      echo "build_hnc_json: set CC to Android NDK clang, or HNC_JSON_C_ALLOW_HOST=1 for unit tests only" >&2
      exit 2
    fi
    ;;
esac

"$CC" -Os -Wall -Wextra -Werror -o "$TMP" "$DIR/hnc_json.c"
cp -f "$TMP" "$OUT"
rm -f "$TMP"
chmod 755 "$OUT"
echo "$OUT"
