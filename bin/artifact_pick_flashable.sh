#!/system/bin/sh
# HNC flashable module ZIP extractor & verifier (v6.1+).
# Safe: only reads/extracts ZIP files and optionally runs artifact_sanity_check.sh.

set +e
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
SANITY="$SCRIPT_DIR/artifact_sanity_check.sh"
[ -f "$SANITY" ] || SANITY="bin/artifact_sanity_check.sh"
SRC="$1"
OUTDIR="$2"
FAIL=0
WARN=0
say(){ printf '%s\n' "$*"; }
ok(){ say "[OK] $*"; }
warn(){ WARN=$((WARN+1)); say "[WARN] $*"; }
fail(){ FAIL=$((FAIL+1)); say "[FAIL] $*"; }
usage(){ cat <<'EOF_USAGE'
Usage: sh bin/artifact_pick_flashable.sh <downloaded-artifact.zip> [output-dir]

Purpose:
  GitHub Actions often downloads an outer wrapper ZIP that contains the real
  flashable HNC module ZIP. This script detects that case, extracts the inner
  module ZIP, then runs artifact_sanity_check.sh on the real package.

Output:
  Prints flashable_artifact=<path> on success.
EOF_USAGE
}

[ -z "$SRC" ] || [ "$SRC" = "-h" ] || [ "$SRC" = "--help" ] && { usage; [ -z "$SRC" ] && exit 2 || exit 0; }
[ -f "$SRC" ] || { fail "artifact not found: $SRC"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }
command -v unzip >/dev/null 2>&1 || { fail "unzip not found"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }

BASE_TMP=${TMPDIR:-/tmp}
[ -d "$BASE_TMP" ] || BASE_TMP="."
[ -n "$OUTDIR" ] || OUTDIR="$BASE_TMP/hnc_flashable_artifact.$$"
mkdir -p "$OUTDIR" 2>/dev/null || { fail "cannot create output dir: $OUTDIR"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }
LIST="$OUTDIR/.artifact_list.$$"
unzip -l "$SRC" > "$LIST" 2>/dev/null || { fail "cannot list zip: $SRC"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }
ENTRIES="$OUTDIR/.artifact_entries.$$"
awk 'NR>3 && $0 !~ /---------/ {print $4}' "$LIST" | sed '/^$/d' > "$ENTRIES"

_APF_VER=$(awk -F= '$1=="version"{print $2; exit}' "$SCRIPT_DIR/../module.prop" 2>/dev/null | tr -d '\r')
say "HNC flashable artifact picker ${_APF_VER:-v6.1}"
say "source=$SRC"
say "outdir=$OUTDIR"

if grep -x 'module.prop' "$ENTRIES" >/dev/null 2>&1; then
    ok "source ZIP already has module.prop at root; it is directly flashable"
    FLASHABLE="$SRC"
else
    NESTED=$(grep -E '\.zip$' "$ENTRIES" | sed '/^$/d')
    NESTED_COUNT=$(printf '%s\n' "$NESTED" | sed '/^$/d' | wc -l | tr -d ' ')
    INNER=""
    if [ "$NESTED_COUNT" = "1" ]; then
        INNER=$(printf '%s\n' "$NESTED" | head -n 1)
    elif [ "$NESTED_COUNT" -gt 1 ] 2>/dev/null; then
        # GitHub Actions outer artifact bundles HNC-*.zip alongside dpi-rules.zip.
        # Prefer a unique HNC-*.zip entry; otherwise inspect nested zips for a unique root module.prop.
        HNC_CANDS=$(printf '%s\n' "$NESTED" | grep -E '(^|/)HNC-[^/]*\.zip$' | sed '/^$/d')
        HNC_COUNT=$(printf '%s\n' "$HNC_CANDS" | sed '/^$/d' | wc -l | tr -d ' ')
        if [ "$HNC_COUNT" = "1" ]; then
            INNER=$(printf '%s\n' "$HNC_CANDS" | head -n 1)
        else
            PROBE_TMP="$OUTDIR/.probe_inner.$$.zip"
            MOD_CANDS=""
            MOD_COUNT=0
            while IFS= read -r _cand; do
                [ -n "$_cand" ] || continue
                if unzip -p "$SRC" "$_cand" > "$PROBE_TMP" 2>/dev/null && [ -s "$PROBE_TMP" ]; then
                    if unzip -l "$PROBE_TMP" 2>/dev/null | awk 'NR>3 && $0 !~ /---------/ {print $4}' | grep -x 'module.prop' >/dev/null 2>&1; then
                        MOD_CANDS="$_cand"
                        MOD_COUNT=$((MOD_COUNT + 1))
                    fi
                fi
            done <<EOF_NESTED
$NESTED
EOF_NESTED
            rm -f "$PROBE_TMP" 2>/dev/null || true
            if [ "$MOD_COUNT" = "1" ]; then
                INNER="$MOD_CANDS"
            fi
        fi
    fi
    if [ -n "$INNER" ]; then
        warn "source looks like an Actions outer wrapper (nested_zips=$NESTED_COUNT); extracting inner ZIP: $INNER"
        unzip -p "$SRC" "$INNER" > "$OUTDIR/$(basename "$INNER")" 2>/dev/null
        FLASHABLE="$OUTDIR/$(basename "$INNER")"
        [ -s "$FLASHABLE" ] && ok "inner flashable ZIP extracted: $FLASHABLE" || fail "failed to extract inner ZIP: $INNER"
    else
        fail "module.prop not at root and nested zip count is $NESTED_COUNT; cannot identify one flashable module ZIP"
    fi
fi

if [ -n "$FLASHABLE" ] && [ -f "$FLASHABLE" ]; then
    if [ -f "$SANITY" ]; then
        say "running artifact sanity check on: $FLASHABLE"
        sh "$SANITY" "$FLASHABLE"
        RC=$?
        [ "$RC" = "0" ] && ok "flashable artifact sanity passed" || fail "flashable artifact sanity failed rc=$RC"
    else
        warn "artifact_sanity_check.sh missing; skipped strict sanity check"
    fi
fi

rm -f "$LIST" "$ENTRIES" 2>/dev/null || true
say "summary: failures=$FAIL warnings=$WARN"
[ "$FAIL" -eq 0 ] || exit 1
say "flashable_artifact=$FLASHABLE"
exit 0
