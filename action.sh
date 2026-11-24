#!/system/bin/sh
# action.sh — Magisk (v27+) / KernelSU / APatch 模块「操作(Action)」按钮入口
#
# KernelSU / APatch 原生通过模块根 webroot/index.html 提供内置 WebUI（无需 webroot.sh）；
# Magisk 没有内置 WebView，点击模块卡片上的「操作」按钮会执行本脚本：
#   1) 检查 hnc_httpd 状态（未运行则尝试拉起 service.sh）；
#   2) 生成一次性本地免密配对链接（pair_gen.sh）或回退 http://127.0.0.1:8444；
#   3) 通过 Android ActivityManager 拉起系统浏览器直达控制面板。

MODDIR=${0%/*}
HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

BASE_URL="http://127.0.0.1:8444"
LOOP_PORT="8444"
if [ -f "$RUN/webui_url" ]; then
    _u=$(head -n 1 "$RUN/webui_url" 2>/dev/null | tr -d ' \t\r\n')
    case "$_u" in
        http://127.0.0.1:*|http://localhost:*)
            BASE_URL="${_u%/}"
            _p="${BASE_URL##*:}"
            _p="${_p%%/*}"
            case "$_p" in ''|*[!0-9]*) ;; *) LOOP_PORT="$_p" ;; esac
            ;;
    esac
fi
URL="$BASE_URL"

_port_ready() {
    _pr_port="${1:-8444}"
    _pr_hex=$(printf '%04X' "$_pr_port" 2>/dev/null)
    [ -n "$_pr_hex" ] || _pr_hex="20FC"
    if [ ! -r /proc/net/tcp ] && [ ! -r /proc/net/tcp6 ]; then
        return 0
    fi
    awk -v hp=":$_pr_hex" '
        toupper($2) ~ (hp "$") && toupper($4) == "0A" { ok = 1; exit }
        END { exit !ok }
    ' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

_httpd_ready() {
    _hr_pid=$(head -n 1 "$RUN/httpd.pid" 2>/dev/null | tr -dc '0-9')
    [ -n "$_hr_pid" ] && kill -0 "$_hr_pid" 2>/dev/null || return 1
    _port_ready "$LOOP_PORT"
}

_is_service_sh_pid() {
    _isp_p="$1"
    _isp_proot="${HNC_PROC_ROOT:-/proc}"
    case "$_isp_p" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_isp_p" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_isp_p" = "$PPID" ] && return 1
    kill -0 "$_isp_p" 2>/dev/null || [ "$_isp_proot" != "/proc" ] || return 1
    [ -r "$_isp_proot/$_isp_p/cmdline" ] || return 1
    _isp_a0=$(tr '\000' '\n' < "$_isp_proot/$_isp_p/cmdline" 2>/dev/null | sed -n '1p')
    _isp_a1=$(tr '\000' '\n' < "$_isp_proot/$_isp_p/cmdline" 2>/dev/null | sed -n '2p')
    case "$_isp_a0" in
        */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$MODDIR/service.sh")
            return 0
            ;;
    esac
    case "${_isp_a0##*/}" in
        sh|mksh|ash|dash|busybox|toybox)
            [ "$_isp_a1" = "-c" ] && return 1
            case "$_isp_a1" in
                */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$MODDIR/service.sh")
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

_service_starting() {
    _ss_proot="${HNC_PROC_ROOT:-/proc}"
    if [ -f "$RUN/service.pid" ]; then
        _ss_spid=$(head -n 1 "$RUN/service.pid" 2>/dev/null | tr -dc '0-9')
        if [ -n "$_ss_spid" ] && _is_service_sh_pid "$_ss_spid"; then
            return 0
        fi
    fi
    _ss_sent=""
    if [ -f "$RUN/sentinel.pid" ]; then
        _ss_sent=$(head -n 1 "$RUN/sentinel.pid" 2>/dev/null | tr -dc '0-9')
        if [ -n "$_ss_sent" ] && _is_service_sh_pid "$_ss_sent"; then
            return 1
        fi
    fi
    [ -d "$_ss_proot" ] || return 1
    for _ss_d in "$_ss_proot"/[0-9]*; do
        [ -r "$_ss_d/cmdline" ] || continue
        _ss_p=${_ss_d##*/}
        [ -n "$_ss_sent" ] && [ "$_ss_p" = "$_ss_sent" ] && continue
        if _is_service_sh_pid "$_ss_p"; then
            return 0
        fi
    done
    return 1
}

if ! _httpd_ready; then
    if _service_starting; then
        echo "- HNC: 检测到服务正在启动中，等待 WebUI 就绪..."
    elif [ -f "$MODDIR/service.sh" ]; then
        echo "- HNC: WebUI 守护进程未就绪，正在后台唤醒服务..."
        mkdir -p "$HNC_DIR/logs" 2>/dev/null
        nohup sh "$MODDIR/service.sh" </dev/null >>"$HNC_DIR/logs/service.log" 2>&1 &
    fi
    if [ -f "$MODDIR/service.sh" ] || _service_starting; then
        # 最多等待 12 秒(24 * 0.5s), 轮询 httpd.pid 存活且 :8444 监听就绪
        _wait_i=0
        while [ "$_wait_i" -lt 24 ]; do
            _httpd_ready && break
            if usleep 500000 2>/dev/null; then
                _wait_i=$((_wait_i + 1))
            elif sleep 0.5 2>/dev/null; then
                _wait_i=$((_wait_i + 1))
            else
                sleep 1
                _wait_i=$((_wait_i + 2))
            fi
        done
    fi
fi

PAIR_PIN=""
PAIR_SH="$HNC_DIR/bin/pair_gen.sh"
[ -f "$PAIR_SH" ] || PAIR_SH="$MODDIR/bin/pair_gen.sh"
if [ -f "$PAIR_SH" ]; then
    _pair=$(HNC_DIR="$HNC_DIR" sh "$PAIR_SH" url 2>/dev/null | head -n 1 | tr -d ' \t\r\n')
    case "$_pair" in
        http://127.0.0.1:*|http://localhost:*)
            URL="$_pair"
            case "$_pair" in
                *prefill=*)
                    PAIR_PIN="${_pair#*prefill=}"
                    PAIR_PIN="${PAIR_PIN%%&*}"
                    ;;
            esac
            ;;
    esac
fi
if [ -z "$PAIR_PIN" ] && [ -f "$RUN/pair_pending" ]; then
    PAIR_PIN=$(sed -n '1p' "$RUN/pair_pending" 2>/dev/null | tr -dc '0-9')
fi

GW_IP=""
if [ -f "$RUN/iface_detect.json" ]; then
    GW_IP=$(sed -n 's/.*"ipv4"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1/p' "$RUN/iface_detect.json" 2>/dev/null | head -n 1)
fi
if [ -z "$GW_IP" ]; then
    for _if_f in "$RUN/hotspot_iface" "$RUN/iface.cache"; do
        [ -f "$_if_f" ] || continue
        _ifn=$(head -n 1 "$_if_f" 2>/dev/null | tr -d ' \t\r\n')
        [ -n "$_ifn" ] || continue
        GW_IP=$(ip -4 -o addr show dev "$_ifn" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="inet"){a=$(i+1); sub(/\/.*/,"",a); print a; exit}}')
        [ -n "$GW_IP" ] && break
    done
fi
if [ -z "$GW_IP" ]; then
    GW_IP=$(ip -4 -o addr show dev wlan0 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="inet"){a=$(i+1); sub(/\/.*/,"",a); print a; exit}}')
fi

echo "- HNC 本机管理地址: $BASE_URL"
echo "- HNC 免密配对入口: $URL"
if [ -n "$GW_IP" ]; then
    echo "- HNC 局域网管理地址: https://${GW_IP}:8443"
else
    echo "- HNC 局域网管理地址: https://<网关IP>:8443 (开启热点或接入局域网后可用)"
fi
if [ -n "$PAIR_PIN" ]; then
    echo "- HNC 应急配对 PIN: $PAIR_PIN (120 秒内有效)"
fi

if command -v am >/dev/null 2>&1; then
    if am start --user 0 -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1 \
       || am start -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1; then
        echo "- 已在浏览器中打开 HNC 面板"
    else
        echo "- 自动拉起浏览器失败，请手动复制上方地址到浏览器打开"
    fi
fi
exit 0
