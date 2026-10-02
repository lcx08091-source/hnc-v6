#!/system/bin/sh
# HNC v5.3.0-rc20.0 · flashable artifact sanity checker
# Detect GitHub Actions outer ZIP wrappers and stale hnc_httpd binaries before install.

set +e
ZIP="$1"
FAIL=0
WARN=0
TMPBASE="${TMPDIR:-/tmp}"
[ -d "$TMPBASE" ] || TMPBASE="."
TMP="$TMPBASE/hnc_artifact_check.$$"
say(){ printf '%s\n' "$*"; }
ok(){ say "[OK] $*"; }
warn(){ WARN=$((WARN+1)); say "[WARN] $*"; }
fail(){ FAIL=$((FAIL+1)); say "[FAIL] $*"; }
cleanup(){ rm -rf "$TMP" "$TMP".* 2>/dev/null; }
trap cleanup EXIT INT TERM
usage(){ cat <<'EOF_USAGE'
Usage: sh bin/artifact_sanity_check.sh <HNC-module.zip>
Checks direct flashability, nested ZIPs, required files, hnc_httpd/hnc_dpid ELF arch, embedded versions and v5.3 SQM/DPI symbols.
EOF_USAGE
}
[ -z "$ZIP" ] || [ "$ZIP" = "-h" ] || [ "$ZIP" = "--help" ] && { usage; [ -z "$ZIP" ] && exit 2 || exit 0; }
[ -f "$ZIP" ] || { fail "artifact not found: $ZIP"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }
command -v unzip >/dev/null 2>&1 || { fail "unzip not found; cannot inspect artifact"; say "summary: failures=$FAIL warnings=$WARN"; exit 1; }

say "HNC artifact sanity check v5.3.0-rc25.0"
say "artifact=$ZIP"
unzip -t "$ZIP" >"$TMP.unzip_test" 2>&1
[ $? -eq 0 ] && ok "zip integrity OK" || { fail "zip integrity failed"; cat "$TMP.unzip_test"; }
unzip -l "$ZIP" > "$TMP.list" 2>/dev/null
awk 'NR>3 && $0 !~ /---------/ {print $4}' "$TMP.list" | sed '/^$/d' > "$TMP.entries"
TOTAL_ENTRIES=$(wc -l < "$TMP.entries" 2>/dev/null | tr -d ' ')
ROOT_MODULE=$(grep -x 'module.prop' "$TMP.entries" | head -1)
ANY_MODULE=$(grep -E '(^|/)module\.prop$' "$TMP.entries" | head -1)
NESTED_ZIPS=$(grep -E '\.zip$' "$TMP.entries" | sed '/^$/d')
NESTED_COUNT=$(printf '%s\n' "$NESTED_ZIPS" | sed '/^$/d' | wc -l | tr -d ' ')

# v5.22: 期望 ABI —— HNC_EXPECT_ABI 环境变量 > 包内 bin/hnc_pkg_abi > 历史默认 arm64-v8a。
# arm64 包: AArch64 = OK, 32 位 ARM = WARN(保持旧行为); armv7 包: ARM = OK, 其他 = FAIL。
EXPECT_ABI="${HNC_EXPECT_ABI:-}"
if [ -z "$EXPECT_ABI" ] && grep -x 'bin/hnc_pkg_abi' "$TMP.entries" >/dev/null 2>&1; then
  EXPECT_ABI=$(unzip -p "$ZIP" bin/hnc_pkg_abi 2>/dev/null | head -n 1 | tr -d ' \r\n')
fi
[ -n "$EXPECT_ABI" ] || EXPECT_ABI=arm64-v8a
case "$EXPECT_ABI" in
  arm64-v8a)   WANT_MACHINE="b7 00" ;;
  armeabi-v7a) WANT_MACHINE="28 00" ;;
  *) fail "unknown expected ABI: $EXPECT_ABI"; WANT_MACHINE="?" ;;
esac
say "expected ABI=$EXPECT_ABI"

if [ -n "$ROOT_MODULE" ]; then
  ok "module.prop is at ZIP root; package is directly flashable"
else
  fail "module.prop is not at ZIP root; do not flash this ZIP directly"
  if [ "$TOTAL_ENTRIES" = "1" ] && [ "$NESTED_COUNT" = "1" ]; then
    fail "this looks like a GitHub Actions outer wrapper containing an inner module ZIP: $NESTED_ZIPS"
  elif [ -n "$ANY_MODULE" ]; then
    fail "module.prop exists only under a subdirectory: $ANY_MODULE"
  else
    fail "module.prop missing from artifact"
  fi
fi
[ "$NESTED_COUNT" -gt 0 ] && fail "artifact contains nested ZIP(s); use the inner module ZIP or fix packaging: $(printf '%s' "$NESTED_ZIPS" | tr '\n' ' ')" || ok "artifact has no nested ZIP"
grep -E '\.rej$|\.orig$' "$TMP.entries" >/dev/null && fail "artifact contains .rej/.orig patch residue" || ok "artifact has no .rej/.orig residue"
grep -E '(^|/)(\.ssh|id_rsa|id_ed25519|.*_ed25519|.*_rsa|.*\.pem)$' "$TMP.entries" >/dev/null && fail "artifact may contain private key/secret files" || ok "artifact has no obvious private key/secret files"
for req in webroot/index.html webroot/css/base.css webroot/css/apple.css webroot/css/liquid.css webroot/js/core.js webroot/js/fx.js webroot/js/devices.js webroot/js/apps.js webroot/js/stats.js webroot/js/settings.js webroot/js/sheets.js webroot/js/main.js webroot/json-health.html bin/capability_probe.sh daemon/hnc_httpd/hnc_httpd bin/hnc_dpid bin/dpi_rules_import.sh data/dpi_rules.json data/ip_owner.bin bin/hnc_clsact_ctl bin/hnc_clsact.o bin/hnc_clsact_watchdog.sh bin/hnc_clsact_sync.sh bin/hnc_offload_guard.sh bin/debug_bundle.sh bin/tc_manager.sh bin/watchdog.sh customize.sh bin/hnc_arch.sh; do
  grep -x "$req" "$TMP.entries" >/dev/null && ok "required file exists: $req" || fail "required file missing at ZIP root path: $req"
done

VER=""; VC=""
if [ -n "$ROOT_MODULE" ]; then
  unzip -p "$ZIP" module.prop > "$TMP.module.prop" 2>/dev/null
  VER=$(awk -F= '$1=="version"{print $2; exit}' "$TMP.module.prop" 2>/dev/null)
  VC=$(awk -F= '$1=="versionCode"{print $2; exit}' "$TMP.module.prop" 2>/dev/null)
  say "module.prop version=$VER versionCode=$VC"
  [ -n "$VER" ] && ok "module.prop version is present" || fail "module.prop version missing"
  echo "$VC" | grep -Eq '^[0-9]+$' && ok "module.prop versionCode is numeric" || fail "module.prop versionCode is not numeric"
fi

# v5.3.0-rc20.0: hnc_dpid must be packaged. rc17 accidentally omitted it,
# which made fresh installs lose the DPI observer even though the WebUI/API existed.
if grep -x 'bin/hnc_dpid' "$TMP.entries" >/dev/null; then
  mkdir -p "$TMP.extract" 2>/dev/null
  unzip -p "$ZIP" bin/hnc_dpid > "$TMP.extract/hnc_dpid" 2>/dev/null
  if [ -s "$TMP.extract/hnc_dpid" ]; then
    ok "hnc_dpid binary can be extracted"
    if command -v od >/dev/null 2>&1; then
      DPID_MACHINE=$(od -An -tx1 -j18 -N2 "$TMP.extract/hnc_dpid" 2>/dev/null | awk '{print $1 " " $2}')
      case "$DPID_MACHINE" in
        "$WANT_MACHINE") ok "hnc_dpid matches $EXPECT_ABI: machine=$DPID_MACHINE" ;;
        "28 00") warn "hnc_dpid is 32-bit ARM ELF: machine=$DPID_MACHINE; expected $EXPECT_ABI package?" ;;
        "b7 00") fail "hnc_dpid is AArch64 ELF in a $EXPECT_ABI package: machine=$DPID_MACHINE" ;;
        *) fail "hnc_dpid is not Android ARM/AArch64 ELF, machine=$DPID_MACHINE" ;;
      esac
    else
      warn "od not available; skipped hnc_dpid ELF machine check"
    fi
    if command -v strings >/dev/null 2>&1; then
      strings "$TMP.extract/hnc_dpid" > "$TMP.dpid.strings" 2>/dev/null
      if grep -F '0.1.0-rc1.2-fixed' "$TMP.dpid.strings" >/dev/null || grep -F '0.1.0-rc1.3' "$TMP.dpid.strings" >/dev/null || grep -F '0.2.0-l2-rc19' "$TMP.dpid.strings" >/dev/null || grep -F '0.3.0-l3-rc20' "$TMP.dpid.strings" >/dev/null || grep -F '0.3.1-l3-rc20.1' "$TMP.dpid.strings" >/dev/null || grep -F 'hnc_dpid' "$TMP.dpid.strings" >/dev/null; then
        ok "hnc_dpid contains expected version/name marker"
      else
        fail "hnc_dpid missing expected version/name marker; binary may be stale or wrong"
      fi
    else
      warn "strings not available; skipped hnc_dpid version/name marker check"
    fi
  else
    fail "hnc_dpid extraction failed or produced empty file"
  fi
fi

if grep -x 'daemon/hnc_httpd/hnc_httpd' "$TMP.entries" >/dev/null; then
  mkdir -p "$TMP.extract" 2>/dev/null
  unzip -p "$ZIP" daemon/hnc_httpd/hnc_httpd > "$TMP.extract/hnc_httpd" 2>/dev/null
  if [ -s "$TMP.extract/hnc_httpd" ]; then
    ok "hnc_httpd binary can be extracted"
    if command -v od >/dev/null 2>&1; then
      MACHINE=$(od -An -tx1 -j18 -N2 "$TMP.extract/hnc_httpd" 2>/dev/null | awk '{print $1 " " $2}')
      case "$MACHINE" in "$WANT_MACHINE") ok "hnc_httpd matches $EXPECT_ABI: machine=$MACHINE" ;; "28 00") warn "hnc_httpd is 32-bit ARM ELF: machine=$MACHINE; expected $EXPECT_ABI package?" ;; "b7 00") fail "hnc_httpd is AArch64 ELF in a $EXPECT_ABI package: machine=$MACHINE" ;; *) fail "hnc_httpd is not Android ARM/AArch64 ELF, machine=$MACHINE" ;; esac
    else warn "od not available; skipped hnc_httpd ELF machine check"; fi
    if command -v strings >/dev/null 2>&1; then
      strings "$TMP.extract/hnc_httpd" > "$TMP.httpd.strings" 2>/dev/null
      [ -n "$VER" ] && { grep -F "$VER" "$TMP.httpd.strings" >/dev/null && ok "hnc_httpd embeds module version $VER" || fail "hnc_httpd does not embed module version $VER; Go binary may be stale"; }
      case "$VER" in v5.3.*)
        grep -F '/api/dpi_state' "$TMP.httpd.strings" >/dev/null && ok "hnc_httpd contains /api/dpi_state" || fail "hnc_httpd missing /api/dpi_state"
        grep -F '/api/dpi_probe' "$TMP.httpd.strings" >/dev/null && ok "hnc_httpd contains /api/dpi_probe" || fail "hnc_httpd missing /api/dpi_probe"
        grep -F 'apiDPIState' "$TMP.httpd.strings" >/dev/null && ok "hnc_httpd contains apiDPIState" || fail "hnc_httpd missing apiDPIState"
        grep -F 'apiDPIProbe' "$TMP.httpd.strings" >/dev/null && ok "hnc_httpd contains apiDPIProbe" || fail "hnc_httpd missing apiDPIProbe" ;;
      esac
    else warn "strings not available; skipped hnc_httpd version/API symbol checks"; fi
  else fail "hnc_httpd extraction failed or produced empty file"; fi
fi
# v5.22: 全部原生二进制 ABI 一致性(混架构是多 ABI
# 打包最可能出的错: 某个构建步骤忘了传 arch, arm64 产物混进 armv7 包)。
# (customize.sh / bin/hnc_arch.sh 已并入上方 required file 清单)
_elf_machine() { # <zip-entry> → "b7 00" / "28 00" / ...
  unzip -p "$ZIP" "$1" 2>/dev/null | head -c 20 > "$TMP.elfhdr" 2>/dev/null
  od -An -tx1 -j18 -N2 "$TMP.elfhdr" 2>/dev/null | awk '{print $1 " " $2}'
}
if command -v od >/dev/null 2>&1; then
  for b in bin/hotspotd bin/hnc_ipc bin/mdns_resolve bin/hnc_tc_ingress bin/hnc_clsact_ctl \
           bin/hnc_launcher bin/fork_probe bin/hnc_dpid bin/hnc_watchdog bin/hnc_dpid_supervisor \
           daemon/hnc_httpd/hnc_httpd; do
    grep -x "$b" "$TMP.entries" >/dev/null || continue
    M=$(_elf_machine "$b")
    [ "$M" = "$WANT_MACHINE" ] && ok "ABI $EXPECT_ABI: $b" || fail "ABI mismatch: $b machine='$M' (want $WANT_MACHINE for $EXPECT_ABI)"
  done
  # 可选的通用包覆盖层 bin/<abi>/*: 每层内二进制必须与该层 ABI 一致
  for ov in arm64-v8a armeabi-v7a; do
    case "$ov" in arm64-v8a) OW="b7 00" ;; *) OW="28 00" ;; esac
    for b in $(grep -E "^bin/$ov/[^/]+$" "$TMP.entries"); do
      M=$(_elf_machine "$b")
      [ "$M" = "$OW" ] && ok "overlay ABI $ov: $b" || fail "overlay ABI mismatch: $b machine='$M' (want $OW)"
    done
  done
else
  warn "od not available; skipped per-binary ABI consistency check"
fi

say "summary: failures=$FAIL warnings=$WARN"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
