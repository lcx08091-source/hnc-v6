#!/system/bin/sh
# hnc_compat.sh — 跨机型 / 跨 ROM / 跨 root 方案的兼容层(v5.20)
#
# 提供(作为库 HNC_COMPAT_LIB=1 . hnc_compat.sh, 或 CLI):
#   root 方案识别  KernelSU / SukiSU-Ultra / KernelSU-Next / APatch / Magisk
#                  → 对应 busybox 路径、是否有模块 WebUI(Magisk 没有)
#   SoC 厂商识别   qcom / mtk / unisoc / exynos / tensor / unknown(HWNAT 等按厂商开关)
#   PATH 审计      关键命令是否可解析, /system/bin 被卸时哪些能从 /data 兜底
#   开热点方法链   先探测(cmd wifi help / cmd -l / svc wifi)再按可用性排序,
#                  记录哪种方法真的成功过(给自检 / WebUI 报告)
#
# ── 输出契约(run/)──────────────────────────────────────────────────────────────
#   run/root_env.json   {"schema":1,"ts","root":"sukisu|kernelsu|ksu_next|apatch|magisk|unknown",
#                        "root_family":"kernelsu|apatch|magisk|unknown","root_version":"..",
#                        "root_label":"SukiSU|KernelSU 系(可能为 SukiSU)|..","root_confidence":"high|medium|low|",
#                        "root_hint":"maybe_sukisu|","root_evidence":["susfs","ksud_major_ge3",..],
#                        "busybox":"/data/adb/ksu/bin/busybox"|"","module_webui":bool,
#                        "webui_url":"http://127.0.0.1:8444","sdk":36,"release":"16",
#                        "soc":"qcom|mtk|...","kernel":"6.6.x","path_missing":[..],
#                        "path_dynamic_only":[..]}
#   run/webui_url       一行 URL(Magisk 无模块 WebUI: 用浏览器打开它, 用登录密码/配对码登录)
#   run/softap_method.json
#                       {"schema":1,"ts","sdk":36,"probe":{"softap":bool,"band_flag":bool,
#                        "sec":"open wpa2 ..","tethering_cmd":bool,"svc_hotspot":bool,"lohs":bool},
#                        "chain":["softap_band","softap",..],"last_method":"softap_band",
#                        "last_ok":true|false|null,"last_ts":0,"last_detail":".."}
#
# CLI:
#   hnc_compat.sh root          探测并写 root_env.json + webui_url, 打印 JSON
#   hnc_compat.sh busybox       打印应使用的 busybox 路径(没有则 exit 1)
#   hnc_compat.sh soc           打印 SoC 厂商
#   hnc_compat.sh path-audit    打印 "name<TAB>path|MISSING<TAB>kind"
#   hnc_compat.sh softap-probe  探测开热点方法并写 softap_method.json, 打印 chain
#   hnc_compat.sh resolve <cmd> 打印可执行路径(含 busybox applet 兜底 "bb cmd")
# 测试钩子: HNC_ADB_DIR(默认 /data/adb)、HNC_APP_DATA_DIR(默认 /data/data)、
#           HNC_SOC(强制 SoC)、PATH 上的 getprop / cmd / svc 桩。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && [ "${HNC_COMPAT_LIB:-0}" != 1 ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

HNC_DIR=${HNC_DIR:-/data/local/hnc}
_HC_RUN="$HNC_DIR/run"
_HC_ADB=${HNC_ADB_DIR:-/data/adb}
_HC_APPDATA=${HNC_APP_DATA_DIR:-/data/data}
HNC_WEBUI_PORT=${HNC_WEBUI_PORT:-8444}

_hc_getprop() { getprop "$1" 2>/dev/null | tr -d '\r'; }

# ─── root 方案 ────────────────────────────────────────────────────────────────
# 设置 HNC_ROOT HNC_ROOT_FAMILY HNC_ROOT_VER
hnc_root_detect() {
    HNC_ROOT=unknown; HNC_ROOT_FAMILY=unknown; HNC_ROOT_VER=""
    # 1) 模块脚本环境变量(KernelSU/APatch 文档保证 boot 脚本里有; Magisk 只在安装期有)
    if [ "${KSU:-}" = true ]; then
        HNC_ROOT_FAMILY=kernelsu; HNC_ROOT_VER="${KSU_VER:-}${KSU_VER_CODE:+ ($KSU_VER_CODE)}"
    elif [ "${APATCH:-}" = true ]; then
        HNC_ROOT_FAMILY=apatch; HNC_ROOT_VER="${APATCH_VER:-}${APATCH_VER_CODE:+ ($APATCH_VER_CODE)}"
    # 2) 文件系统痕迹(换过 root 方案会残留旧目录: 按 ksu > apatch > magisk 取当前在用的)
    elif [ -x "$_HC_ADB/ksud" ] || [ -x "$_HC_ADB/ksu/bin/ksud" ]; then
        HNC_ROOT_FAMILY=kernelsu
    elif [ -x "$_HC_ADB/apd" ] || [ -x "$_HC_ADB/ap/bin/apd" ]; then
        HNC_ROOT_FAMILY=apatch
    elif [ -d "$_HC_ADB/magisk" ] || command -v magisk >/dev/null 2>&1; then
        HNC_ROOT_FAMILY=magisk
        HNC_ROOT_VER="${MAGISK_VER:-$(magisk -v 2>/dev/null | head -n1)}"
    fi
    HNC_ROOT=$HNC_ROOT_FAMILY
    HNC_ROOT_CONF=""; HNC_ROOT_EVIDENCE=""; HNC_ROOT_LABEL=""
    if [ "$HNC_ROOT_FAMILY" = kernelsu ]; then
        # v5.20.1: KernelSU 分支识别(best-effort, 按证据强弱):
        #   强: ksud -V 含 "suki" / SukiSU-Ultra 管理器数据目录 com.sukisu.ultra
        #   中: ksud --help 有 kpm 子命令 / /data/adb/kpm(KPM 内核补丁模块是 SukiSU 独有于 KSU 系)
        #   弱: SuSFS(SukiSU 常见但官方 KSU / KSU-Next 也能装)、ksud 主版本 ≥3(官方/Next 仍是 1.x–2.x)
        #   只有弱证据 → root=kernelsu, root_hint=maybe_sukisu, 显示 "KernelSU 系(可能为 SukiSU)"。
        #   真机 RMX5010: `ksud -V` = "KernelSU ksud 4.2.0-rc1 (uapi: 2)"(不含 suki)。
        local kv="" kh="" b strong=0 medium=0 weak=0 maj
        for b in "$_HC_ADB/ksud" "$_HC_ADB/ksu/bin/ksud"; do
            [ -x "$b" ] || continue
            kv=$("$b" -V 2>/dev/null | head -n1)
            kh=$("$b" --help 2>/dev/null | head -n 80)
            break
        done
        [ -z "$HNC_ROOT_VER" ] && HNC_ROOT_VER="$kv"
        _hc_ev() { HNC_ROOT_EVIDENCE="$HNC_ROOT_EVIDENCE $1"; }
        if printf '%s %s' "$kv" "$HNC_ROOT_VER" | grep -qi suki; then strong=1; _hc_ev ksud_version_sukisu; fi
        if [ -d "$_HC_APPDATA/com.sukisu.ultra" ]; then strong=1; _hc_ev manager_com.sukisu.ultra; fi
        if printf '%s\n' "$kh" | grep -qiE '^[[:space:]]+kpm([[:space:]]|$)'; then medium=1; _hc_ev ksud_kpm_cmd; fi
        if [ -d "$_HC_ADB/kpm" ]; then medium=1; _hc_ev adb_kpm_dir; fi
        if [ -e "$_HC_ADB/ksu/bin/ksu_susfs" ] || [ -d "$_HC_ADB/modules/susfs4ksu" ] || [ -e "$_HC_ADB/ksu/susfs4ksu" ]; then
            weak=1; _hc_ev susfs
        fi
        maj=$(printf '%s %s' "$kv" "$HNC_ROOT_VER" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1 | cut -d. -f1)
        case "$maj" in ''|*[!0-9]*) ;; *) [ "$maj" -ge 3 ] && { weak=1; _hc_ev ksud_major_ge3; } ;; esac
        if [ "$strong" = 1 ] || [ "$medium" = 1 ]; then
            HNC_ROOT=sukisu; HNC_ROOT_LABEL=SukiSU
            [ "$strong" = 1 ] && HNC_ROOT_CONF=high || HNC_ROOT_CONF=medium
        elif [ -d "$_HC_APPDATA/com.rifsxd.ksunext" ] || printf '%s %s' "$kv" "$HNC_ROOT_VER" | grep -qi next; then
            HNC_ROOT=ksu_next; HNC_ROOT_LABEL=KernelSU-Next; HNC_ROOT_CONF=high
        elif [ "$weak" = 1 ]; then
            HNC_ROOT_CONF=low; HNC_ROOT_LABEL="KernelSU 系(可能为 SukiSU)"
        else
            HNC_ROOT_CONF=medium; HNC_ROOT_LABEL=KernelSU
        fi
        HNC_ROOT_EVIDENCE=${HNC_ROOT_EVIDENCE# }
    fi
    case "$HNC_ROOT_FAMILY" in
        apatch) HNC_ROOT_LABEL=APatch ;; magisk) HNC_ROOT_LABEL=Magisk ;; unknown) HNC_ROOT_LABEL="" ;;
    esac
    HNC_ROOT_VER=$(printf '%s' "$HNC_ROOT_VER" | tr -d '"\\\r\n')
}

# 候选 busybox(当前 root 方案的排最前; 都是 /data 上的静态二进制, /system/bin 被卸也能用)
hnc_busybox_candidates() {
    [ -n "$HNC_ROOT_FAMILY" ] || hnc_root_detect
    case "$HNC_ROOT_FAMILY" in
        kernelsu) echo "$_HC_ADB/ksu/bin/busybox" ;;
        apatch)   echo "$_HC_ADB/ap/bin/busybox" ;;
        magisk)   echo "$_HC_ADB/magisk/busybox" ;;
    esac
    echo "$_HC_ADB/ksu/bin/busybox"
    echo "$_HC_ADB/ap/bin/busybox"
    echo "$_HC_ADB/magisk/busybox"
    echo /system/xbin/busybox
    echo /system/bin/busybox
}

hnc_busybox() {
    local c
    for c in $(hnc_busybox_candidates); do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    return 1
}

# hnc_resolve_bin <cmd>: PATH → 常见目录 → /data/local/hnc/bin → busybox applet
hnc_resolve_bin() {
    local n="$1" d bb p
    p=$(command -v "$n" 2>/dev/null) && [ -n "$p" ] && { echo "$p"; return 0; }
    for d in /system/bin /system/xbin /vendor/bin /apex/com.android.runtime/bin /apex/com.android.tethering/bin \
             "$HNC_DIR/bin"; do
        [ -x "$d/$n" ] && { echo "$d/$n"; return 0; }
    done
    bb=$(hnc_busybox) || return 1
    "$bb" --list 2>/dev/null | grep -qx "$n" && { echo "$bb $n"; return 0; }
    return 1
}

# 关键命令审计。kind: applet(可由 /data busybox 兜底)| dynamic(依赖 /system/bin/linker64,
# /system/bin 被卸时任何副本都跑不起来, 只能等挂载恢复)
HNC_CRITICAL_APPLETS="sh awk sed grep cat head tail cut tr sort date sleep mkdir mv rm stat"
HNC_CRITICAL_DYNAMIC="ip iptables ip6tables tc cmd dumpsys getprop settings svc"
hnc_path_audit() {
    local n p
    for n in $HNC_CRITICAL_APPLETS; do
        p=$(hnc_resolve_bin "$n") || p=MISSING
        printf '%s\t%s\tapplet\n' "$n" "$p"
    done
    for n in $HNC_CRITICAL_DYNAMIC; do
        p=$(hnc_resolve_bin "$n") || p=MISSING
        printf '%s\t%s\tdynamic\n' "$n" "$p"
    done
}

# ─── SoC 厂商 ─────────────────────────────────────────────────────────────────
hnc_soc_vendor() {
    [ -n "${HNC_SOC:-}" ] && { echo "$HNC_SOC"; return; }
    local m p h
    m=$(_hc_getprop ro.soc.manufacturer | tr 'A-Z' 'a-z')
    p=$(_hc_getprop ro.board.platform | tr 'A-Z' 'a-z')
    h=$(_hc_getprop ro.hardware | tr 'A-Z' 'a-z')
    case "$m" in
        qti|qualcomm*) echo qcom; return ;;
        mediatek*|mtk) echo mtk; return ;;
        unisoc*|spreadtrum*) echo unisoc; return ;;
        google) echo tensor; return ;;
        samsung*) echo exynos; return ;;
    esac
    case "$p" in
        mt[0-9]*|mt*) echo mtk; return ;;
        ums*|sp[0-9]*|sc[0-9]*|uis*) echo unisoc; return ;;
        exynos*|s5e*|universal*) echo exynos; return ;;
        gs[0-9]*|zuma*|zumapro*|laguna*) echo tensor; return ;;
        msm*|sdm*|sm[0-9]*|kona|lahaina|taro|kalama|pineapple|sun|canoe|parrot|crow|holi|bengal|lito|trinket|atoll|blair|niobe|volcano|cliffs) echo qcom; return ;;
    esac
    case "$h" in
        qcom*) echo qcom ;;
        mt*) echo mtk ;;
        exynos*|s5e*) echo exynos ;;
        ums*|sp*) echo unisoc ;;
        *) echo unknown ;;
    esac
}

_hc_jlist() {
    local x out="" first=1
    for x in $1; do
        [ $first -eq 1 ] || out="$out,"
        out="$out\"$x\""; first=0
    done
    echo "[$out]"
}

hnc_write_root_env() {
    hnc_root_detect
    local bb webui=false url sdk rel soc kern missing="" dynmiss="" line n p k
    bb=$(hnc_busybox) || bb=""
    case "$HNC_ROOT_FAMILY" in kernelsu|apatch) webui=true ;; esac
    url="http://127.0.0.1:$HNC_WEBUI_PORT"
    sdk=$(_hc_getprop ro.build.version.sdk); case "$sdk" in ''|*[!0-9]*) sdk=0 ;; esac
    rel=$(_hc_getprop ro.build.version.release | tr -d '"\\')
    soc=$(hnc_soc_vendor)
    kern=$(uname -r 2>/dev/null | tr -d '"\\')
    while IFS='	' read -r n p k; do
        [ "$p" = MISSING ] || continue
        missing="$missing $n"
        [ "$k" = dynamic ] && dynmiss="$dynmiss $n"
    done <<EOF
$(hnc_path_audit)
EOF
    mkdir -p "$_HC_RUN" 2>/dev/null
    local hint=""; [ "$HNC_ROOT" = kernelsu ] && [ "$HNC_ROOT_CONF" = low ] && hint=maybe_sukisu
    printf '{"schema":1,"ts":%s,"root":"%s","root_family":"%s","root_version":"%s","root_label":"%s","root_confidence":"%s","root_hint":"%s","root_evidence":%s,"busybox":"%s","module_webui":%s,"webui_url":"%s","sdk":%s,"release":"%s","soc":"%s","kernel":"%s","path_missing":%s,"path_dynamic_only":%s}\n' \
        "$(date +%s 2>/dev/null || echo 0)" "$HNC_ROOT" "$HNC_ROOT_FAMILY" "$HNC_ROOT_VER" "$HNC_ROOT_LABEL" "$HNC_ROOT_CONF" "$hint" "$(_hc_jlist "$HNC_ROOT_EVIDENCE")" "$bb" "$webui" "$url" \
        "$sdk" "$rel" "$soc" "$kern" "$(_hc_jlist "$missing")" "$(_hc_jlist "$dynmiss")" \
        > "$_HC_RUN/root_env.json.tmp.$$" 2>/dev/null && mv -f "$_HC_RUN/root_env.json.tmp.$$" "$_HC_RUN/root_env.json" 2>/dev/null
    echo "$url" > "$_HC_RUN/webui_url" 2>/dev/null
    chmod 644 "$_HC_RUN/root_env.json" "$_HC_RUN/webui_url" 2>/dev/null
    return 0
}

# ─── 开热点方法链 ─────────────────────────────────────────────────────────────
# AOSP 事实(Android 11–16, WifiShellCommand / Tethering):
#   - `cmd wifi start-softap <ssid> <sec> <pass> [-b 2|5|6|any|bridged..]` 自 Android 11
#     起存在(Android 10 及以前没有); -b 选项随版本增加; sec 类型 11=open|wpa2,
#     12+=open|wpa2|wpa3|wpa3_transition|owe|owe_transition。帮助文本明确写
#     "the shell command doesn't activate internet tethering" → 起的是不带 NAT 的热点,
#     HNC 需自建 NAT(hotspot_autostart.sh setup_nat)。
#   - Tethering mainline 模块没有公开的 shell 命令: `cmd tethering` 在 AOSP 上不存在或
#     只有测试用子命令; 个别 ROM 有实现 → 只在 `cmd -l` 列出且 help 里有 tether 时尝试。
#   - `svc wifi` 在 AOSP 只有 enable/disable(无 hotspot); 个别定制 ROM 有 → 同样先看 help。
#   - `cmd wifi start-lohs`(本地热点, 无上网共享)仅上报, 不作为开热点方法。
# 设置 HNC_SOFTAP_CHAIN HNC_SOFTAP_SECS 以及 _HC_P_* 探测结果
hnc_softap_probe() {
    local help tl svc
    help=$(cmd wifi help 2>&1)
    case "$help" in *start-softap*) ;; *) help="$help
$(cmd wifi -h 2>&1)" ;; esac
    _HC_P_SOFTAP=false; _HC_P_BAND=false; _HC_P_TETHER=false; _HC_P_SVC=false; _HC_P_LOHS=false
    HNC_SOFTAP_SECS=""
    case "$help" in *start-softap*) _HC_P_SOFTAP=true ;; esac
    case "$help" in *start-lohs*) _HC_P_LOHS=true ;; esac
    if [ "$_HC_P_SOFTAP" = true ]; then
        printf '%s\n' "$help" | grep 'start-softap' | grep -q -- '-b ' && _HC_P_BAND=true
        # "start-softap <ssid> (open|wpa2|wpa3|...) <passphrase>" → 支持的加密类型
        HNC_SOFTAP_SECS=$(printf '%s\n' "$help" | grep 'start-softap <' | head -n1 | sed -n 's/.*(\([a-z0-9_|]*\)).*/\1/p' | tr '|' ' ')
    fi
    tl=$(cmd -l 2>/dev/null)
    if printf '%s\n' "$tl" | grep -qx tethering; then
        case "$(cmd tethering help 2>&1)" in
            *"No shell command implementation"*|*"Unknown command"*|*"Can't find service"*) ;;
            *[Tt]ether*) _HC_P_TETHER=true ;;
        esac
    fi
    svc=$(svc wifi 2>&1)
    case "$svc" in *hotspot*) _HC_P_SVC=true ;; esac

    HNC_SOFTAP_CHAIN=""
    [ "$_HC_P_SOFTAP" = true ] && [ "$_HC_P_BAND" = true ] && HNC_SOFTAP_CHAIN="softap_band"
    [ "$_HC_P_SOFTAP" = true ] && HNC_SOFTAP_CHAIN="$HNC_SOFTAP_CHAIN softap"
    [ "$_HC_P_TETHER" = true ] && HNC_SOFTAP_CHAIN="$HNC_SOFTAP_CHAIN tethering_cmd"
    [ "$_HC_P_SVC" = true ] && HNC_SOFTAP_CHAIN="$HNC_SOFTAP_CHAIN svc_hotspot"
    HNC_SOFTAP_CHAIN="${HNC_SOFTAP_CHAIN# }"
    # 帮助文本没列出加密类型时用旧默认
    [ -n "$HNC_SOFTAP_SECS" ] || HNC_SOFTAP_SECS="wpa2 wpa3 wpa3_transition open"
    # 按偏好排序并只保留支持的
    local s ordered=""
    for s in wpa2 wpa3_transition wpa3 open; do
        case " $HNC_SOFTAP_SECS " in *" $s "*) ordered="$ordered $s" ;; esac
    done
    HNC_SOFTAP_SECS="${ordered# }"
    [ -n "$HNC_SOFTAP_SECS" ] || HNC_SOFTAP_SECS="wpa2 open"
    _hc_softap_write "" null 0 ""
    return 0
}

# _hc_softap_write <last_method> <true|false|null> <last_ts> <detail>
_hc_softap_write() {
    local sdk
    sdk=$(_hc_getprop ro.build.version.sdk); case "$sdk" in ''|*[!0-9]*) sdk=0 ;; esac
    mkdir -p "$_HC_RUN" 2>/dev/null
    printf '{"schema":1,"ts":%s,"sdk":%s,"probe":{"softap":%s,"band_flag":%s,"sec":"%s","tethering_cmd":%s,"svc_hotspot":%s,"lohs":%s},"chain":%s,"last_method":"%s","last_ok":%s,"last_ts":%s,"last_detail":"%s"}\n' \
        "$(date +%s 2>/dev/null || echo 0)" "$sdk" "$_HC_P_SOFTAP" "$_HC_P_BAND" "$HNC_SOFTAP_SECS" "$_HC_P_TETHER" "$_HC_P_SVC" "$_HC_P_LOHS" \
        "$(_hc_jlist "$HNC_SOFTAP_CHAIN")" "$1" "$2" "$3" "$(printf '%s' "$4" | tr -d '"\\\r\n' | cut -c1-160)" \
        > "$_HC_RUN/softap_method.json.tmp.$$" 2>/dev/null && mv -f "$_HC_RUN/softap_method.json.tmp.$$" "$_HC_RUN/softap_method.json" 2>/dev/null
}

# hnc_softap_record <method> <ok 1|0> <detail>
hnc_softap_record() {
    local ok=false
    [ "$2" = 1 ] && ok=true
    _hc_softap_write "$1" "$ok" "$(date +%s 2>/dev/null || echo 0)" "$3"
}

# hnc_softap_try <method> <ssid> <pass>: 跑一次; 成功 return 0 并设置 HNC_SOFTAP_SEC_USED
# 输出(stdout)最后一次命令结果, 供日志
hnc_softap_try() {
    local m="$1" ssid="$2" pass="$3" sec r
    HNC_SOFTAP_SEC_USED=""
    case "$m" in
        softap_band|softap)
            for sec in $HNC_SOFTAP_SECS; do
                if [ "$m" = softap_band ]; then
                    r=$(cmd wifi start-softap "$ssid" "$sec" "$pass" -b any 2>&1)
                else
                    r=$(cmd wifi start-softap "$ssid" "$sec" "$pass" 2>&1)
                fi
                case "$r" in
                    *[Ff]ailed*|*[Ee]rror*|*[Ii]nvalid*) ;;
                    *[Ss]tarted*|*[Ss]uccess*) HNC_SOFTAP_SEC_USED="$sec"; echo "$r"; return 0 ;;
                esac
            done
            echo "$r"; return 1 ;;
        tethering_cmd)
            r=$(cmd tethering tether wifi 2>&1); local rc=$?
            echo "$r"
            [ $rc -eq 0 ] || return 1
            case "$r" in *[Ee]rror*|*[Ff]ail*|*[Uu]nknown*|*"No shell"*) return 1 ;; esac
            return 0 ;;
        svc_hotspot)
            r=$(svc wifi hotspot enable 2>&1); local rc2=$?
            echo "$r"
            [ $rc2 -eq 0 ] || return 1
            case "$r" in *[Ee]rror*|*[Uu]sage*|*[Uu]nknown*) return 1 ;; esac
            return 0 ;;
    esac
    return 1
}

if [ "${HNC_COMPAT_LIB:-0}" != 1 ]; then
    case "${1:-root}" in
        root) hnc_write_root_env; cat "$_HC_RUN/root_env.json" 2>/dev/null ;;
        busybox) hnc_busybox ;;
        soc) hnc_soc_vendor ;;
        path-audit) hnc_path_audit ;;
        softap-probe) hnc_softap_probe; echo "$HNC_SOFTAP_CHAIN" ;;
        resolve) hnc_resolve_bin "$2" ;;
        *) echo "usage: $0 root|busybox|soc|path-audit|softap-probe|resolve <cmd>" >&2; exit 2 ;;
    esac
fi
