#!/system/bin/sh
# action.sh — Magisk (v27+) / KernelSU / APatch 模块「操作(Action)」按钮入口
#
# KernelSU / APatch 原生通过模块根 webroot/index.html 提供内置 WebUI（无需 webroot.sh）；
# Magisk 没有内置 WebView，点击模块卡片上的「操作」按钮会执行本脚本：
#   1) 检查 hnc_httpd 状态（未运行则尝试拉起 service.sh）；
#   2) 生成一次性本地免密配对链接（pair_gen.sh）或回退 http://127.0.0.1:8444；
#   3) 通过 Android ActivityManager 拉起系统浏览器直达控制面板。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

MODDIR=${0%/*}
HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"

URL="http://127.0.0.1:8444"
if [ -f "$RUN/webui_url" ]; then
    _u=$(head -n 1 "$RUN/webui_url" 2>/dev/null | tr -d ' \t\r\n')
    case "$_u" in
        http://127.0.0.1:*|http://localhost:*) URL="$_u" ;;
    esac
fi

HTTPD_PID=$(head -n 1 "$RUN/httpd.pid" 2>/dev/null | tr -dc '0-9')
if [ -z "$HTTPD_PID" ] || ! kill -0 "$HTTPD_PID" 2>/dev/null; then
    echo "- HNC: WebUI 守护进程未就绪，正在后台唤醒服务..."
    if [ -f "$MODDIR/service.sh" ]; then
        mkdir -p "$HNC_DIR/logs" 2>/dev/null
        nohup sh "$MODDIR/service.sh" </dev/null >>"$HNC_DIR/logs/service.log" 2>&1 &
        sleep 2
    fi
fi

if [ -f "$HNC_DIR/bin/pair_gen.sh" ]; then
    _pair=$(HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/pair_gen.sh" url 2>/dev/null | head -n 1 | tr -d ' \t\r\n')
    case "$_pair" in
        http://127.0.0.1:*|http://localhost:*) URL="$_pair" ;;
    esac
fi

echo "- HNC 控制面板地址: $URL"
if command -v am >/dev/null 2>&1; then
    am start -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1 \
        && echo "- 已在浏览器中打开 HNC 面板" \
        || echo "- 自动拉起浏览器失败，请手动复制上方地址到浏览器打开"
fi
exit 0
