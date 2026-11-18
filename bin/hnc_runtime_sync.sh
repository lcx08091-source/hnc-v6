#!/system/bin/sh
# hnc_runtime_sync.sh — 模块目录 → 运行目录(/data/local/hnc)的同步, 唯一一份(v5.33)。
#
# 用法:
#   hnc_runtime_sync.sh sync  <MODDIR> <HNC_DIR>   拷文件 + 修权限
#   hnc_runtime_sync.sh perms <MODDIR> <HNC_DIR>   只修权限(回滚钉住时: 运行目录留着 .prev 恢复的旧文件)
# 日志行写 stdout, 调用方重定向到自己的日志。
#
# post-fs-data.sh(每次开机)与 service.sh(WebUI「重启后端」直接 fork service.sh, 不经
# post-fs-data)都调它。v5.33 之前两边各写一份: 拷贝目录不一样(post-fs-data 还拷从来不存在
# 的 api/ 和不进安装包的 test/)、httpd 换不换的判断不一样、原生二进制的 chmod / chcon 清单
# 抄了两遍。
#
#   1. bin/ 与 webroot/ 整个拷过去(cp -rf, 运行目录里多出来的旧文件由 service.sh 的旧文件
#      清理负责)。
#   2. daemon/hnc_httpd/hnc_httpd 内容变了才换: 先停掉旧 httpd(手动重启服务时它还占着
#      8444), 再拷(rc14 / hotfix17.3)。
#   3. 原生二进制 chmod 755 + chcon system_file, 模块目录与运行目录都做: cp 后 context
#      变成 system_data_file, ColorOS 16 / SukiSU 上 Go fork+exec 报 EPERM(rc30.11, 真机
#      RMX5010 实测); 模块目录先修好, cp 出来的权限就对。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

MODE=$1
MODDIR=$2
HNC_DIR=$3
case "$MODE" in sync|perms) ;; *) echo "usage: $0 sync|perms <MODDIR> <HNC_DIR>" >&2; exit 2 ;; esac
[ -d "$MODDIR" ] && [ -n "$HNC_DIR" ] || { echo "usage: $0 $MODE <MODDIR> <HNC_DIR>" >&2; exit 2; }
RUN="$HNC_DIR/run"

# 原生二进制(无 .sh 后缀, 不被 *.sh 的 chmod 覆盖)。hnc_httpd 在 daemon/hnc_httpd/ 单独处理。
NATIVE_BINS="hotspotd hnc_ipc hnc_tc_ingress mdns_resolve hnc_json hnc_dpid hnc_watchdog hnc_launcher fork_probe hnc_clsact_ctl"

fix_exec() {
    [ -f "$1" ] || return 0
    chmod 755 "$1" 2>/dev/null
    chcon u:object_r:system_file:s0 "$1" 2>/dev/null || true
}

fix_perms() {
    for _dir in "$MODDIR/bin" "$HNC_DIR/bin"; do
        [ -d "$_dir" ] || continue
        chmod 755 "$_dir"/*.sh 2>/dev/null
        for _b in $NATIVE_BINS; do fix_exec "$_dir/$_b"; done
    done
    fix_exec "$MODDIR/daemon/hnc_httpd/hnc_httpd"
    fix_exec "$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
}

if [ "$MODE" = perms ]; then
    fix_perms
    exit 0
fi

echo "runtime sync: $MODDIR -> $HNC_DIR"
# v5.9.3 BUG-009: 资源目录 755(这里没有凭据; 顶层 / data / logs / run 的 700 由调用方收)
mkdir -p "$HNC_DIR/bin" "$HNC_DIR/webroot" "$HNC_DIR/daemon/hnc_httpd" 2>/dev/null
chmod 755 "$HNC_DIR/bin" "$HNC_DIR/webroot" "$HNC_DIR/daemon" "$HNC_DIR/daemon/hnc_httpd" 2>/dev/null
fix_perms   # 先修模块目录, cp 出来的权限就对
cp -rf "$MODDIR/bin/"* "$HNC_DIR/bin/" 2>/dev/null || true
cp -rf "$MODDIR/webroot/"* "$HNC_DIR/webroot/" 2>/dev/null || true

H_MOD="$MODDIR/daemon/hnc_httpd/hnc_httpd"
H_RUN="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
if [ ! -f "$H_MOD" ]; then
    echo "runtime sync WARN: module hnc_httpd missing at $H_MOD"
elif ! cmp -s "$H_MOD" "$H_RUN" 2>/dev/null; then
    # 旧 httpd 还在跑就先停(占着 8444, 新进程起不来)。只认 pidfile 里确是 hnc_httpd 的 pid,
    # 再兜底 pidof(手动重启时 pidfile 可能已被删)。
    _old=""
    if [ -f "$RUN/httpd.pid" ]; then
        _old=$(tr -d ' \r\n' < "$RUN/httpd.pid" 2>/dev/null)
        case "$_old" in ''|*[!0-9]*) _old="" ;; esac
        [ -n "$_old" ] && ! tr '\000' ' ' < "/proc/$_old/cmdline" 2>/dev/null | grep -q 'hnc_httpd' && _old=""
    fi
    for _p in $_old $(pidof hnc_httpd 2>/dev/null); do
        kill -9 "$_p" 2>/dev/null && echo "runtime sync: stopped old hnc_httpd pid=$_p"
    done
    rm -f "$RUN/httpd.pid" "$H_RUN" 2>/dev/null
    cp -f "$H_MOD" "$H_RUN" 2>/dev/null || true
    fix_exec "$H_RUN"
    echo "runtime sync: refreshed hnc_httpd binary from module"
fi
fix_perms
exit 0
