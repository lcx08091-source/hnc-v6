#!/system/bin/sh
# v5.20: bin/hnc_compat.sh(root 方案 / busybox / SoC / 开热点方法链)+ bin/hnc_mtk_hwnat.sh

CSCRIPT="$HNC_REPO_ROOT/bin/hnc_compat.sh"
HWSCRIPT="$HNC_REPO_ROOT/bin/hnc_mtk_hwnat.sh"

cx_init() {
    CX="$HNC_TEST_DIR/cx"
    rm -rf "$CX"; mkdir -p "$CX/adb" "$CX/appdata" "$CX/mock" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
    : > "$CX/props"; : > "$CX/calls"
    cat > "$CX/mock/getprop" <<'M'
#!/bin/sh
sed -n "s/^$1=//p" "$CX/props" | head -n1
M
    # cmd 桩: `cmd wifi help` → $CX/wifi_help; `cmd -l` → $CX/cmd_l;
    # `cmd wifi start-softap ...` → 依 $CX/softap_ok_args 决定成功/失败
    cat > "$CX/mock/cmd" <<'M'
#!/bin/sh
echo "cmd $*" >> "$CX/calls"
case "$1 $2" in
    "wifi help"|"wifi -h") cat "$CX/wifi_help" 2>/dev/null ;;
    "-l "*|"-l") cat "$CX/cmd_l" 2>/dev/null ;;
    "tethering help") cat "$CX/tethering_help" 2>/dev/null || echo "No shell command implementation." ;;
    "tethering tether") [ -f "$CX/tether_ok" ] && { echo ok; exit 0; }; echo "Unknown command"; exit 1 ;;
    "wifi start-softap")
        if grep -qxF -- "$*" "$CX/softap_ok_args" 2>/dev/null; then echo "Soft AP started successfully"
        else echo "Soft AP failed to start. Please check config parameters"; fi ;;
esac
exit 0
M
    cat > "$CX/mock/svc" <<'M'
#!/bin/sh
echo "svc $*" >> "$CX/calls"
case "$*" in
    wifi) cat "$CX/svc_help" 2>/dev/null || echo "Control the Wi-Fi manager
usage: svc wifi [enable|disable]" ;;
esac
exit 0
M
    chmod +x "$CX/mock/"*
    export CX
}
crun() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_ADB_DIR="$CX/adb" HNC_APP_DATA_DIR="$CX/appdata" \
    PATH="$CX/mock:$PATH" sh "$CSCRIPT" "$@" 2>/dev/null
}
# 在子 shell 里 source 库执行一段代码
clib() {
    ( export HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_ADB_DIR="$CX/adb" HNC_APP_DATA_DIR="$CX/appdata" \
             PATH="$CX/mock:$PATH"
      unset KSU APATCH KSU_VER KSU_VER_CODE APATCH_VER MAGISK_VER
      HNC_COMPAT_LIB=1 . "$CSCRIPT"
      eval "$1" ) 2>/dev/null
}
mkexe() { mkdir -p "$(dirname "$1")"; printf '#!/bin/sh\necho "%s"\n' "${2:-}" > "$1"; chmod +x "$1"; }
jf() { sed -n "s/.*\"$2\":\\(\"[^\"]*\"\\|\\[[^]]*\\]\\|[a-z0-9]*\\).*/\\1/p" "$HNC_TEST_DIR/run/$1" 2>/dev/null | head -n1; }

WIFI_HELP_A12='Wi-Fi (wifi) commands:
  start-softap <ssid> (open|wpa2|wpa3|wpa3_transition|owe|owe_transition) <passphrase> [-b 2|5|6|any|bridged|bridged_2_5|bridged_2_6|bridged_5_6] [-x] [-w 2|5|6] [-f <int> [<int>]]
    Start softap with provided params
    Note that the shell command doesn'"'"'t activate internet tethering.
  stop-softap
  start-lohs <ssid> (open|wpa2|wpa3|wpa3_transition|owe|owe_transition) <passphrase> [-b 2|5|6|any]'
WIFI_HELP_A11='Wi-Fi (wifi) commands:
  start-softap <ssid> (open|wpa2) <passphrase>
    Start softap with provided params
  stop-softap'
WIFI_HELP_A10='Wi-Fi (wifi) commands:
  set-ipreach-disconnect enabled|disabled
  set-poll-rssi-interval-msecs <int>'

# ─── root 方案 ────────────────────────────────────────────────────────────
test_start "compat root: SukiSU (ksud + manager data dir) → ksu busybox first, module WebUI"
cx_init
mkexe "$CX/adb/ksud" "ksud 1.0.5"; mkexe "$CX/adb/ksu/bin/busybox"; mkexe "$CX/adb/magisk/busybox"
mkdir -p "$CX/appdata/com.sukisu.ultra"
echo "ro.build.version.sdk=36" >> "$CX/props"; echo "ro.soc.manufacturer=QTI" >> "$CX/props"
crun root >/dev/null
assert_eq '"sukisu"' "$(jf root_env.json root)" && assert_eq '"kernelsu"' "$(jf root_env.json root_family)" \
  && assert_eq "\"$CX/adb/ksu/bin/busybox\"" "$(jf root_env.json busybox)" && assert_eq true "$(jf root_env.json module_webui)" \
  && assert_eq '"qcom"' "$(jf root_env.json soc)" && assert_eq 36 "$(jf root_env.json sdk)" \
  && assert_eq "http://127.0.0.1:8444" "$(cat "$HNC_TEST_DIR/run/webui_url")" \
  && assert_json_valid "$HNC_TEST_DIR/run/root_env.json" && test_pass

test_start "compat root: Magisk → magisk busybox, no module WebUI, webui_url written"
cx_init
mkdir -p "$CX/adb/magisk"; mkexe "$CX/adb/magisk/busybox"
crun root >/dev/null
assert_eq '"magisk"' "$(jf root_env.json root)" && assert_eq false "$(jf root_env.json module_webui)" \
  && assert_eq "\"$CX/adb/magisk/busybox\"" "$(jf root_env.json busybox)" \
  && assert_file_exists "$HNC_TEST_DIR/run/webui_url" && test_pass

test_start "compat root: APatch (apd) wins over leftover magisk dir; ap busybox first"
cx_init
mkexe "$CX/adb/apd"; mkexe "$CX/adb/ap/bin/busybox"; mkdir -p "$CX/adb/magisk"; mkexe "$CX/adb/magisk/busybox"
r=$(clib 'hnc_root_detect; echo "$HNC_ROOT $(hnc_busybox)"')
assert_eq "apatch $CX/adb/ap/bin/busybox" "$r" && test_pass

test_start "compat root: env KSU=true beats filesystem traces; KSU-Next variant"
cx_init
mkdir -p "$CX/adb/magisk" "$CX/appdata/com.rifsxd.ksunext"; mkexe "$CX/adb/ksu/bin/busybox"
r=$(clib 'KSU=true; KSU_VER=v1.0.9; hnc_root_detect; echo "$HNC_ROOT_FAMILY $HNC_ROOT $(hnc_busybox_candidates | head -n1)"')
assert_eq "kernelsu ksu_next $CX/adb/ksu/bin/busybox" "$r" && test_pass

test_start "compat root: nothing installed → unknown, no busybox, still valid JSON"
cx_init
crun root >/dev/null
assert_eq '"unknown"' "$(jf root_env.json root)" && assert_json_valid "$HNC_TEST_DIR/run/root_env.json" && test_pass

# ─── SoC ─────────────────────────────────────────────────────────────────
test_start "compat soc: manufacturer / platform / hardware fallbacks"
cx_init
s=""
for p in "ro.soc.manufacturer=Mediatek" "ro.board.platform=mt6983" "ro.board.platform=ums9230" \
         "ro.soc.manufacturer=Google" "ro.board.platform=s5e9925" "ro.board.platform=kalama" "ro.hardware=qcom" "x=y"; do
    echo "$p" > "$CX/props"
    s="$s $(crun soc)"
done
assert_eq " mtk mtk unisoc tensor exynos qcom qcom unknown" "$s" && test_pass

# ─── 开热点方法链 ─────────────────────────────────────────────────────────
test_start "softap chain: Android 12+ → softap_band first, sec from help, lohs reported"
cx_init
printf '%s\n' "$WIFI_HELP_A12" > "$CX/wifi_help"
out=$(crun softap-probe)
assert_eq "softap_band softap" "$out" && assert_eq '"wpa2 wpa3_transition wpa3 open"' "$(jf softap_method.json sec)" \
  && assert_eq true "$(jf softap_method.json lohs)" && assert_json_valid "$HNC_TEST_DIR/run/softap_method.json" && test_pass

test_start "softap chain: Android 11 (no -b) → softap only, wpa2/open"
cx_init
printf '%s\n' "$WIFI_HELP_A11" > "$CX/wifi_help"
out=$(crun softap-probe)
assert_eq "softap" "$out" && assert_eq '"wpa2 open"' "$(jf softap_method.json sec)" && test_pass

test_start "softap chain: Android 10 (no start-softap) → empty chain unless ROM tethering/svc exists"
cx_init
printf '%s\n' "$WIFI_HELP_A10" > "$CX/wifi_help"
o1=$(crun softap-probe)
printf 'activity\ntethering\nwifi\n' > "$CX/cmd_l"; echo "Tethering commands: tether <type>" > "$CX/tethering_help"
printf 'usage: svc wifi [enable|disable]\n       svc wifi hotspot [enable|disable]\n' > "$CX/svc_help"
o2=$(crun softap-probe)
assert_eq "" "$o1" && assert_eq "tethering_cmd svc_hotspot" "$o2" && test_pass

test_start "softap chain: AOSP cmd tethering without shell impl is not used"
cx_init
printf '%s\n' "$WIFI_HELP_A12" > "$CX/wifi_help"; printf 'tethering\nwifi\n' > "$CX/cmd_l"
out=$(crun softap-probe)
assert_eq "softap_band softap" "$out" && test_pass

test_start "softap try: -b rejected → falls to plain start-softap, records method"
cx_init
printf '%s\n' "$WIFI_HELP_A12" > "$CX/wifi_help"
echo "wifi start-softap MyAP wpa2 secret123" > "$CX/softap_ok_args"
r=$(clib 'hnc_softap_probe; for m in $HNC_SOFTAP_CHAIN; do hnc_softap_try "$m" MyAP secret123 >/dev/null && { hnc_softap_record "$m" 1 "sec=$HNC_SOFTAP_SEC_USED"; echo "$m $HNC_SOFTAP_SEC_USED"; break; }; done')
assert_eq "softap wpa2" "$r" && assert_eq '"softap"' "$(jf softap_method.json last_method)" \
  && assert_eq true "$(jf softap_method.json last_ok)" && assert_contains "$(cat "$CX/calls")" "start-softap MyAP wpa2 secret123 -b any" && test_pass

# ─── hotspot_autostart 走方法链 ───────────────────────────────────────────
test_start "hotspot_autostart start-now: uses probed chain and records softap_method.json"
cx_init
cp "$HNC_REPO_ROOT/bin/hnc_compat.sh" "$HNC_TEST_DIR/bin/" 2>/dev/null
printf '%s\n' "$WIFI_HELP_A12" > "$CX/wifi_help"
echo "wifi start-softap HNCAP wpa2 pass12345 -b any" > "$CX/softap_ok_args"
mkdir -p "$HNC_TEST_DIR/data"
echo '{"hotspot_ssid":"HNCAP","hotspot_pass":"pass12345"}' > "$HNC_TEST_DIR/data/rules.json"
cat > "$CX/mock/ip" <<'M'
#!/bin/sh
exit 0
M
cat > "$CX/mock/iptables" <<'M'
#!/bin/sh
exit 0
M
chmod +x "$CX/mock/ip" "$CX/mock/iptables"
HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 PATH="$CX/mock:$PATH" sh "$HNC_REPO_ROOT/bin/hotspot_autostart.sh" start-now >/dev/null 2>&1
assert_eq '"softap_band"' "$(jf softap_method.json last_method)" && assert_eq true "$(jf softap_method.json last_ok)" \
  && assert_contains "$(cat "$HNC_TEST_DIR/logs/hotspot.log")" "started via softap_band" && test_pass

# ─── MTK HWNAT ────────────────────────────────────────────────────────────
hwrun() { HNC_DIR="$HNC_TEST_DIR" HNC_HWNAT_ROOT="$CX/root" HNC_SOC="$1" sh "$HWSCRIPT" "$2" 2>/dev/null | tail -n1; }

test_start "mtk hwnat: MTK + hook_toggle → disable writes 0, restore writes original back"
cx_init
mkdir -p "$CX/root/sys/kernel/debug/hnat"; echo 1 > "$CX/root/sys/kernel/debug/hnat/hook_toggle"
a1=$(hwrun mtk disable); v1=$(cat "$CX/root/sys/kernel/debug/hnat/hook_toggle")
a2=$(hwrun mtk disable)    # 幂等: 不能把 0 记成原值
a3=$(hwrun mtk restore); v3=$(cat "$CX/root/sys/kernel/debug/hnat/hook_toggle")
assert_eq "disabled" "$a1" && assert_eq 0 "$v1" && assert_eq "disabled" "$a2" && assert_eq "restored" "$a3" && assert_eq 1 "$v3" \
  && assert_json_valid "$HNC_TEST_DIR/run/mtk_hwnat.json" && test_pass

test_start "mtk hwnat: never acts on Qualcomm even if a hnat path exists"
cx_init
mkdir -p "$CX/root/sys/kernel/debug/hnat"; echo 1 > "$CX/root/sys/kernel/debug/hnat/hook_toggle"
a=$(hwrun qcom disable)
assert_eq "skipped_qcom" "$a" && assert_eq 1 "$(cat "$CX/root/sys/kernel/debug/hnat/hook_toggle")" && test_pass

test_start "mtk hwnat: nothing detected → none; MDDP only → detected_no_knob"
cx_init
a1=$(hwrun mtk disable)
mkdir -p "$CX/root/proc/mddp"
a2=$(hwrun mtk disable)
assert_eq "none" "$a1" && assert_eq "detected_no_knob" "$a2" && test_pass

test_start "offload guard on-mode calls hwnat; auto-mode restores it"
cx_init
cp "$HNC_REPO_ROOT/bin/hnc_mtk_hwnat.sh" "$HNC_TEST_DIR/bin/"
mkdir -p "$HNC_TEST_DIR/sysnet/wlan2" "$HNC_TEST_DIR/data"
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
echo '{"clsact_bpf_mode":"on","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
echo IDLE > "$CX/check_state"
mkdir -p "$CX/root/sys/kernel/debug/hnat"; echo 1 > "$CX/root/sys/kernel/debug/hnat/hook_toggle"
grun2() { HNC_TEST_MODE=1 HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" HNC_HWNAT_ROOT="$CX/root" HNC_SOC=mtk \
          HNC_GUARD_CHECK_CMD="cat $CX/check_state" sh "$HNC_REPO_ROOT/bin/hnc_offload_guard.sh" apply >/dev/null 2>&1; }
grun2; v1=$(cat "$CX/root/sys/kernel/debug/hnat/hook_toggle"); st=$(jf offload_guard.json hwnat)
echo '{"clsact_bpf_mode":"auto","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
grun2; v2=$(cat "$CX/root/sys/kernel/debug/hnat/hook_toggle")
assert_eq 0 "$v1" && assert_eq '"disabled"' "$st" && assert_eq 1 "$v2" "auto mode must restore HWNAT" && test_pass
