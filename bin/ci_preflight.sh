#!/system/bin/sh
# HNC v5.3.0-rc20.0 preflight checker
# Runs in Termux/Android shell or GitHub Actions bash/sh.
# Usage:
#   sh bin/ci_preflight.sh                 # source tree checks
#   sh bin/ci_preflight.sh --artifact ZIP  # also inspect built module ZIP/artifact ZIP

set +e
ROOT="$(pwd)"
ARTIFACT=""
FAIL=0
WARN=0

say(){ printf '%s\n' "$*"; }
ok(){ say "[OK] $*"; }
warn(){ WARN=$((WARN+1)); say "[WARN] $*"; }
fail(){ FAIL=$((FAIL+1)); say "[FAIL] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --artifact) shift; ARTIFACT="$1" ;;
    --artifact=*) ARTIFACT="${1#--artifact=}" ;;
  esac
  shift
done

say "HNC preflight v5.3.0-rc25.0"
say "root=$ROOT"

# 1. Patch residue check
RESIDUE="$(find . -path './.git' -prune -o \( -name '*.rej' -o -name '*.orig' \) -print 2>/dev/null | head -50)"
if [ -n "$RESIDUE" ]; then
  fail "patch residue found (.rej/.orig):"
  say "$RESIDUE"
else
  ok "no .rej/.orig residue"
fi

# 2. Secrets / accidental home repo files
SECRET_HITS="$(find . -path './.git' -prune -o \( -path './.ssh/*' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name '*_ed25519' -o -name '*_rsa' -o -name '*.pem' \) -print 2>/dev/null | head -50)"
if [ -n "$SECRET_HITS" ]; then
  fail "possible private key / .ssh files in repo:"
  say "$SECRET_HITS"
else
  ok "no obvious private keys/.ssh files"
fi

# 3. module.prop sanity
if [ ! -f module.prop ]; then
  fail "module.prop missing"
else
  VER="$(awk -F= '$1=="version"{print $2; exit}' module.prop)"
  VC="$(awk -F= '$1=="versionCode"{print $2; exit}' module.prop)"
  say "module.prop version=$VER versionCode=$VC"
  if echo "$VER" | grep -Eq '^v[0-9]+.[0-9]+.[0-9]+-rc[0-9]+(.[0-9]+)?(-hotfix[0-9]+(.[0-9]+)?)?$'; then
    ok "module.prop version format looks valid"
  else
    warn "module.prop version format is unexpected"
  fi
  if echo "$VC" | grep -Eq '^[0-9]+$'; then
    ok "module.prop versionCode is numeric"
  else
    fail "module.prop versionCode is not numeric"
  fi
fi

# 4. Required files
for f in webroot/index.html webroot/json-health.html bin/json_guard.sh bin/json_set.sh bin/json_doctor.sh bin/json_diag_bundle.sh bin/stats_diag.sh bin/stats_identity_diag.sh bin/stats_retention_diag.sh bin/stats_shadow_sample.sh bin/stats_shadow_rollup.sh bin/stats_shadow_diag.sh bin/stats_shadow_control.sh bin/stats_source_diag.sh bin/stats_compare.sh bin/stats_health_summary.sh bin/stats_migration_readiness.sh bin/stats_v52_rc_control.sh bin/stats_v52_rc_smoke.sh bin/stats_v52_diag_bundle.sh bin/stats_v52_device_check.sh bin/stats_v52_rc1_switch.sh bin/stats_v52_web_status.sh bin/stats_v52_install_selfcheck.sh bin/stats_v52_gray_report.sh bin/stats_v52_review_bundle.sh bin/hnc_dpid bin/dpi_rules_import.sh data/dpi_rules.json bin/ndpi_lab_probe.sh bin/ndpi_lab_status.sh bin/ndpi_lab_sample.sh data/dpi_ndpi_config.json bin/hnc_ndpi_probe; do
  if [ -e "$f" ]; then ok "required file exists: $f"; else warn "required file missing: $f"; fi
done

# 5. Executable bits, source tree check only.
for f in service.sh post-fs-data.sh bin/json_set.sh bin/json_set_batch.sh bin/json_guard.sh bin/json_doctor.sh bin/json_diag_bundle.sh bin/stats_diag.sh bin/stats_identity_diag.sh bin/stats_retention_diag.sh bin/stats_shadow_sample.sh bin/stats_shadow_rollup.sh bin/stats_shadow_diag.sh bin/stats_shadow_control.sh bin/stats_source_diag.sh bin/stats_compare.sh bin/stats_health_summary.sh bin/stats_migration_readiness.sh bin/stats_v52_rc_control.sh bin/stats_v52_rc_smoke.sh bin/stats_v52_diag_bundle.sh bin/stats_v52_device_check.sh bin/stats_v52_rc1_switch.sh bin/stats_v52_web_status.sh bin/stats_v52_install_selfcheck.sh bin/stats_v52_gray_report.sh bin/stats_v52_review_bundle.sh bin/tc_manager.sh bin/watchdog.sh bin/hnc_dpid bin/dpi_rules_import.sh bin/ndpi_lab_probe.sh bin/ndpi_lab_status.sh bin/ndpi_lab_sample.sh bin/hnc_ndpi_probe daemon/hnc_httpd/build.sh; do
  [ -e "$f" ] || continue
  if [ -x "$f" ]; then ok "executable: $f"; else fail "not executable: $f"; fi
done

# 6. hnc_httpd binary/source sanity
if [ -f daemon/hnc_httpd/hnc_httpd ]; then
  if [ -x daemon/hnc_httpd/hnc_httpd ]; then ok "hnc_httpd binary exists and executable"; else fail "hnc_httpd binary exists but is not executable"; fi
else
  warn "daemon/hnc_httpd/hnc_httpd not present in source tree; CI must build it before packaging"
fi


# 6a. hnc_dpid binary sanity. DPI WebUI/API is useless on fresh installs if
# the real observer binary is missing from the package/source tree.
if [ -f bin/hnc_dpid ]; then
  if [ -x bin/hnc_dpid ]; then ok "hnc_dpid binary exists and executable"; else fail "hnc_dpid binary exists but is not executable"; fi
  if [ -s bin/hnc_dpid ]; then ok "hnc_dpid binary is non-empty"; else fail "hnc_dpid binary is empty"; fi
  if command -v od >/dev/null 2>&1; then
    DPID_MACHINE="$(od -An -tx1 -j18 -N2 bin/hnc_dpid 2>/dev/null | awk '{print $1 " " $2}')"
    case "$DPID_MACHINE" in
      "b7 00") ok "hnc_dpid is AArch64 ELF: $DPID_MACHINE" ;;
      "28 00") warn "hnc_dpid is 32-bit ARM ELF: $DPID_MACHINE; expected arm64 package?" ;;
      *) fail "bin/hnc_dpid is not Android ARM/AArch64 ELF: machine='$DPID_MACHINE'" ;;
    esac
  else
    warn "od unavailable; cannot inspect bin/hnc_dpid architecture"
  fi
  if command -v strings >/dev/null 2>&1; then
    DPID_MARKERS="$(strings bin/hnc_dpid 2>/dev/null | grep -E '0\.1\.0-rc1\.2-fixed|0\.1\.0-rc1\.3|0\.2\.0-l2-rc19|0\.3\.0-l3-rc20|0\.3\.1-l3-rc20\.1|0\.4\.0-rc23|hnc_dpid' | head -5)"
    if [ -n "$DPID_MARKERS" ]; then ok "hnc_dpid contains expected version/name marker"; else fail "hnc_dpid missing expected version/name marker"; fi
  else
    warn "strings unavailable; cannot inspect hnc_dpid version/name marker"
  fi
else
  fail "bin/hnc_dpid missing; DPI observer will not work on fresh installs"
fi

# 6b. Optional hnc_json_c helper architecture sanity.
# The source tree must not accidentally ship a Linux/x86 helper binary; Android
# packages should only contain an Android ARM/AArch64 build, or no helper at all.
if [ -e bin/hnc_json_c ]; then
  if command -v od >/dev/null 2>&1; then
    HNC_JSON_C_MACHINE="$(od -An -tx1 -j18 -N2 bin/hnc_json_c 2>/dev/null | awk '{print $1 " " $2}')"
    case "$HNC_JSON_C_MACHINE" in
      "b7 00"|"28 00") ok "hnc_json_c looks like Android ARM ELF: $HNC_JSON_C_MACHINE" ;;
      *) fail "bin/hnc_json_c is not Android ARM/AArch64 ELF: machine='$HNC_JSON_C_MACHINE'" ;;
    esac
  else
    warn "od unavailable; cannot inspect bin/hnc_json_c architecture"
  fi
else
  ok "optional hnc_json_c is absent from source tree; CI may build Android copy"
fi

# 7. Version drift warning: detect very old hotfix strings in live web/go files.
OLD_HITS="$(grep -R "hotfix4\|hotfix10\|hotfix16\.7\|hotfix17\.3" -n webroot daemon/hnc_httpd 2>/dev/null | head -30)"
if [ -n "$OLD_HITS" ]; then
  warn "old hotfix strings found; verify they are changelog-only, not runtime version:"
  say "$OLD_HITS"
else
  ok "no obvious stale runtime hotfix strings"
fi

# 8. Optional JSON regression test
if [ -x bin/json_regression_test.sh ]; then
  say "running bin/json_regression_test.sh"
  sh bin/json_regression_test.sh
  RC=$?
  if [ "$RC" = "0" ]; then ok "json regression test passed"; else fail "json regression test failed rc=$RC"; fi
else
  warn "bin/json_regression_test.sh missing/skipped"
fi

# 8b. v5.2 RC WebUI status wiring check
if [ -f webroot/json-health.html ]; then
  if grep -q 'v5.2 RC / 灰度状态' webroot/json-health.html && grep -q 'v52_web_status_raw' webroot/json-health.html; then
    ok "json-health page exposes v5.2 RC gray status"
  else
    fail "json-health page missing v5.2 RC gray status card"
  fi
else
  fail "webroot/json-health.html missing"
fi
if [ -x bin/stats_v52_web_status.sh ]; then
  ok "v5.2 WebUI status helper exists"
else
  fail "bin/stats_v52_web_status.sh missing or not executable"
fi
if [ -x bin/stats_v52_install_selfcheck.sh ]; then
  ok "v5.2 install self-check helper exists"
  if grep -q 'ROLLBACK_AVAILABLE' bin/stats_v52_install_selfcheck.sh && grep -q 'legacy_default_preserved' bin/stats_v52_install_selfcheck.sh; then
    ok "v5.2 install self-check verifies rollback and legacy-default safety"
  else
    fail "v5.2 install self-check missing rollback/legacy-default guard"
  fi
else
  fail "bin/stats_v52_install_selfcheck.sh missing or not executable"
fi
if [ -x bin/stats_v52_gray_report.sh ]; then
  ok "v5.2 gray observation report helper exists"
  if grep -q 'stats_v52_install_selfcheck' bin/stats_v52_gray_report.sh && grep -q 'stats_v52_device_check' bin/stats_v52_gray_report.sh && grep -q 'markdown' bin/stats_v52_gray_report.sh; then
    ok "v5.2 gray report aggregates selfcheck/device checks and markdown output"
  else
    fail "v5.2 gray report missing required aggregation/markdown markers"
  fi
else
  fail "bin/stats_v52_gray_report.sh missing or not executable"
fi
if [ -x bin/stats_v52_review_bundle.sh ]; then
  ok "v5.2 scrubbed review bundle helper exists"
  if grep -q 'redact_stream' bin/stats_v52_review_bundle.sh && grep -q 'stats_v52_gray_report' bin/stats_v52_review_bundle.sh && grep -q 'Claude / Gemini / GPT' bin/stats_v52_review_bundle.sh; then
    ok "v5.2 review bundle has redaction and gray-report markers"
  else
    fail "v5.2 review bundle missing required redaction/review markers"
  fi
else
  fail "bin/stats_v52_review_bundle.sh missing or not executable"
fi
# 9. Artifact ZIP checks, if supplied.
if [ -n "$ARTIFACT" ]; then
  if [ ! -f "$ARTIFACT" ]; then
    fail "artifact not found: $ARTIFACT"
  elif ! command -v unzip >/dev/null 2>&1; then
    warn "unzip not available; artifact checks skipped"
  else
    say "checking artifact=$ARTIFACT"
    TMPBASE="${TMPDIR:-$ROOT/.tmp}"
    mkdir -p "$TMPBASE" 2>/dev/null || TMPBASE="$ROOT"
    ZIPTMP="$TMPBASE/hnc_zip_test.$$"
    CHECK_ARTIFACT="$ARTIFACT"

    # v5.3.0-rc5: accept GitHub Actions outer wrapper downloads for inspection,
    # but always validate the actual inner flashable module ZIP. This avoids the
    # false workflow where the outer artifact passes upload but users accidentally
    # try to flash it.
    if [ -f bin/artifact_pick_flashable.sh ]; then
      PICK_DIR="$TMPBASE/hnc_flashable_pick.$$"
      PICK_OUT="$TMPBASE/hnc_flashable_pick.$$.log"
      sh bin/artifact_pick_flashable.sh "$ARTIFACT" "$PICK_DIR" > "$PICK_OUT" 2>&1
      PICK_RC=$?
      cat "$PICK_OUT"
      PICKED="$(awk -F= '$1=="flashable_artifact"{print $2}' "$PICK_OUT" | tail -1)"
      if [ "$PICK_RC" = "0" ] && [ -n "$PICKED" ] && [ -f "$PICKED" ]; then
        CHECK_ARTIFACT="$PICKED"
        [ "$CHECK_ARTIFACT" = "$ARTIFACT" ] && ok "artifact is directly flashable" || warn "using extracted inner flashable artifact for checks: $CHECK_ARTIFACT"
      else
        fail "artifact flashable picker failed rc=$PICK_RC"
      fi
    else
      warn "bin/artifact_pick_flashable.sh missing; wrapper auto-detection skipped"
    fi

    unzip -t "$CHECK_ARTIFACT" >"$ZIPTMP" 2>&1
    if [ $? -eq 0 ]; then ok "artifact zip integrity OK"; else fail "artifact zip integrity failed"; cat "$ZIPTMP"; fi
    LIST="$(unzip -l "$CHECK_ARTIFACT" 2>/dev/null)"
    echo "$LIST" | grep -E '\.rej|\.orig' >/dev/null && fail "artifact contains .rej/.orig" || ok "artifact has no .rej/.orig"
    echo "$LIST" | grep -E '(^|/)(\.ssh|id_rsa|id_ed25519|.*_ed25519|.*_rsa|.*\.pem)' >/dev/null && fail "artifact may contain secrets" || ok "artifact has no obvious secrets"
    echo "$LIST" | grep -E 'daemon/hnc_httpd/hnc_httpd$' >/dev/null && ok "artifact contains hnc_httpd" || fail "artifact missing daemon/hnc_httpd/hnc_httpd"
    echo "$LIST" | grep -E 'bin/hnc_dpid$' >/dev/null && ok "artifact contains hnc_dpid" || fail "artifact missing bin/hnc_dpid"
    echo "$LIST" | grep -E 'webroot/index.html$' >/dev/null && ok "artifact contains webroot/index.html" || fail "artifact missing webroot/index.html"
    echo "$LIST" | grep -E 'webroot/json-health.html$' >/dev/null && ok "artifact contains json-health.html" || warn "artifact missing json-health.html"

    # hotfix20.9: artifact-level version and optional C helper checks. This
    # catches the common mistake where CI builds an old module.prop, or a host
    # x86 hnc_json_c accidentally gets packaged into the Android module.
    MOD_ENTRY="$(echo "$LIST" | awk '{print $4}' | grep -E '(^|/)module\.prop$' | head -1)"
    if [ -n "$MOD_ENTRY" ]; then
      unzip -p "$CHECK_ARTIFACT" "$MOD_ENTRY" > "$ZIPTMP.module.prop" 2>/dev/null
      ZIP_VER="$(awk -F= '$1=="version"{print $2; exit}' "$ZIPTMP.module.prop" 2>/dev/null)"
      ZIP_VC="$(awk -F= '$1=="versionCode"{print $2; exit}' "$ZIPTMP.module.prop" 2>/dev/null)"
      SRC_VER="$(awk -F= '$1=="version"{print $2; exit}' module.prop 2>/dev/null)"
      SRC_VC="$(awk -F= '$1=="versionCode"{print $2; exit}' module.prop 2>/dev/null)"
      say "artifact module.prop version=$ZIP_VER versionCode=$ZIP_VC"
      [ -n "$ZIP_VER" ] && [ "$ZIP_VER" = "$SRC_VER" ] && ok "artifact version matches source" || fail "artifact version mismatch: source=$SRC_VER artifact=$ZIP_VER"
      [ -n "$ZIP_VC" ] && [ "$ZIP_VC" = "$SRC_VC" ] && ok "artifact versionCode matches source" || fail "artifact versionCode mismatch: source=$SRC_VC artifact=$ZIP_VC"
    else
      fail "artifact missing module.prop"
    fi

    DPID_ENTRY="$(echo "$LIST" | awk '{print $4}' | grep -E '(^|/)bin/hnc_dpid$' | head -1)"
    if [ -n "$DPID_ENTRY" ]; then
      unzip -p "$CHECK_ARTIFACT" "$DPID_ENTRY" > "$ZIPTMP.hnc_dpid" 2>/dev/null
      if [ -s "$ZIPTMP.hnc_dpid" ]; then
        ok "artifact hnc_dpid can be extracted"
        if command -v od >/dev/null 2>&1; then
          DM="$(od -An -tx1 -j18 -N2 "$ZIPTMP.hnc_dpid" 2>/dev/null | awk '{print $1 " " $2}')"
          case "$DM" in
            "b7 00") ok "artifact hnc_dpid is AArch64 ELF: $DM" ;;
            "28 00") warn "artifact hnc_dpid is 32-bit ARM ELF: $DM; expected arm64 package?" ;;
            *) fail "artifact hnc_dpid is not Android ARM/AArch64 ELF: machine='$DM'" ;;
          esac
        else
          warn "od unavailable; cannot inspect artifact hnc_dpid architecture"
        fi
        if command -v strings >/dev/null 2>&1; then
          DPID_ART_MARKERS="$(strings "$ZIPTMP.hnc_dpid" 2>/dev/null | grep -E '0\.1\.0-rc1\.2-fixed|0\.1\.0-rc1\.3|0\.2\.0-l2-rc19|0\.3\.0-l3-rc20|0\.3\.1-l3-rc20\.1|0\.4\.0-rc23|hnc_dpid' | head -5)"
          if [ -n "$DPID_ART_MARKERS" ]; then ok "artifact hnc_dpid contains expected version/name marker"; else fail "artifact hnc_dpid missing expected version/name marker"; fi
        fi
      else
        fail "artifact hnc_dpid present but extraction failed or produced empty file"
      fi
    else
      fail "artifact missing bin/hnc_dpid"
    fi

    C_ENTRY="$(echo "$LIST" | awk '{print $4}' | grep -E '(^|/)bin/hnc_json_c$' | head -1)"
    if [ -n "$C_ENTRY" ]; then
      unzip -p "$CHECK_ARTIFACT" "$C_ENTRY" > "$ZIPTMP.hnc_json_c" 2>/dev/null
      if [ -s "$ZIPTMP.hnc_json_c" ] && command -v od >/dev/null 2>&1; then
        CM="$(od -An -tx1 -j18 -N2 "$ZIPTMP.hnc_json_c" 2>/dev/null | awk '{print $1 " " $2}')"
        case "$CM" in
          "b7 00"|"28 00") ok "artifact hnc_json_c is Android ARM ELF: $CM" ;;
          *) fail "artifact hnc_json_c is not Android ARM/AArch64 ELF: machine='$CM'" ;;
        esac
      else
        fail "artifact hnc_json_c present but cannot inspect ELF machine"
      fi
    else
      ok "artifact has no optional hnc_json_c helper"
    fi

    echo "$LIST" | awk '{print $4}' | grep -E '\.zip$' >/dev/null && warn "artifact contains nested zip; verify this is not an Actions outer wrapper" || ok "artifact has no nested zip"

    # v5.3.0-rc5: strict sanity runs on CHECK_ARTIFACT, which is either the
    # original direct module ZIP or the extracted inner module ZIP.
    if [ -x bin/artifact_sanity_check.sh ]; then
      say "running bin/artifact_sanity_check.sh on $CHECK_ARTIFACT"
      sh bin/artifact_sanity_check.sh "$CHECK_ARTIFACT"
      RC=$?
      if [ "$RC" = "0" ]; then ok "artifact sanity check passed"; else fail "artifact sanity check failed rc=$RC"; fi
    else
      warn "bin/artifact_sanity_check.sh missing; strict artifact sanity gate skipped"
    fi

    rm -f "$ZIPTMP" "$ZIPTMP.module.prop" "$ZIPTMP.hnc_json_c" "$ZIPTMP.hnc_dpid" "$PICK_OUT" 2>/dev/null || true
  fi
fi

say "summary: failures=$FAIL warnings=$WARN"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
