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

MODE=$1
MODDIR=$2
HNC_DIR=$3

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "${HNC_DIR:-/data/local/hnc}/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

case "$MODE" in sync|perms) ;; *) echo "usage: $0 sync|perms <MODDIR> <HNC_DIR>" >&2; exit 2 ;; esac
[ -d "$MODDIR" ] && [ -n "$HNC_DIR" ] || { echo "usage: $0 $MODE <MODDIR> <HNC_DIR>" >&2; exit 2; }
RUN="$HNC_DIR/run"

# 原生二进制(无 .sh 后缀, 不被 *.sh 的 chmod 覆盖; 纯脚本 hnc_json 单独 chmod 755 不混入原生清单)。
NATIVE_BINS="hotspotd hnc_ipc hnc_tc_ingress mdns_resolve hnc_dpid hnc_watchdog hnc_launcher fork_probe hnc_clsact_ctl"

fix_exec() {
    [ -f "$1" ] || return 0
    chmod 755 "$1" 2>/dev/null
    chcon u:object_r:system_file:s0 "$1" 2>/dev/null || true
}

fix_perms() {
    for _dir in "$MODDIR/bin" "$HNC_DIR/bin"; do
        [ -d "$_dir" ] || continue
        chmod 755 "$_dir"/*.sh 2>/dev/null || true
        [ -f "$_dir/hnc_json" ] && chmod 755 "$_dir/hnc_json" 2>/dev/null || true
        if [ -d "$_dir/diag" ]; then
            chmod 755 "$_dir/diag" 2>/dev/null || true
            for _df in "$_dir/diag"/*; do
                [ -f "$_df" ] || continue
                chmod 755 "$_df" 2>/dev/null || true
            done
        fi
        for _b in $NATIVE_BINS; do fix_exec "$_dir/$_b"; done
    done
    fix_exec "$HNC_DIR/bin/.hnc_mc"
    fix_exec "$HNC_DIR/bin/sh"
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
if [ -f "$MODDIR/module.prop" ]; then
    cp -f "$MODDIR/module.prop" "$HNC_DIR/module.prop" 2>/dev/null || true
    chmod 644 "$HNC_DIR/module.prop" 2>/dev/null || true
fi

_first_tok() { set -- $1; printf '%s' "${1:-}"; }
_first_two_tok() { set -- $1; printf '%s:%s' "${1:-}" "${2:-}"; }

H_MOD="$MODDIR/daemon/hnc_httpd/hnc_httpd"
H_RUN="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
_need_httpd=0
if [ ! -f "$H_MOD" ]; then
    echo "runtime sync WARN: module hnc_httpd missing at $H_MOD"
elif [ ! -s "$H_RUN" ]; then
    _need_httpd=1
elif command -v cmp >/dev/null 2>&1; then
    cmp -s "$H_MOD" "$H_RUN" 2>/dev/null || _need_httpd=1
elif command -v sha256sum >/dev/null 2>&1; then
    _s_mod=$(_first_tok "$(sha256sum "$H_MOD" 2>/dev/null)")
    _s_run=$(_first_tok "$(sha256sum "$H_RUN" 2>/dev/null)")
    if [ -z "$_s_mod" ] || [ "$_s_mod" != "$_s_run" ]; then
        _need_httpd=1
    fi
elif command -v cksum >/dev/null 2>&1; then
    _c_mod=$(_first_two_tok "$(cksum "$H_MOD" 2>/dev/null)")
    _c_run=$(_first_two_tok "$(cksum "$H_RUN" 2>/dev/null)")
    if [ "$_c_mod" = ":" ] || [ "$_c_mod" != "$_c_run" ]; then
        _need_httpd=1
    fi
else
    echo "runtime sync WARN: cmp/sha256sum/cksum unavailable, forcing refresh of $H_RUN"
    _need_httpd=1
fi
if [ "$_need_httpd" = "1" ]; then
    _h_tmp="$H_RUN.new.$$"
    if cp -f "$H_MOD" "$_h_tmp" 2>/dev/null && [ -s "$_h_tmp" ]; then
        fix_exec "$_h_tmp"
        # 旧 httpd 还在跑就先停(占着 8444, 新进程起不来)。
        # 严格校验 comm 与 argv[0] 基底名为 hnc_httpd 且排除 $$/$PPID; 沙箱模式下仅读沙箱 pidfile, 绝不扫宿主机 /proc。
        _is_real_httpd_pid() {
            _irp="$1"
            case "$_irp" in ''|*[!0-9]*) return 1 ;; esac
            [ "$_irp" = "$$" ] && return 1
            [ -n "${PPID:-}" ] && [ "$_irp" = "$PPID" ] && return 1
            [ -r "/proc/$_irp/cmdline" ] || return 1
            if [ -r "/proc/$_irp/comm" ]; then
                _irc=$(tr -d '\r\n' < "/proc/$_irp/comm" 2>/dev/null)
                [ "$_irc" = "hnc_httpd" ] || return 1
            fi
            _ira0=$(tr '\000' '\n' < "/proc/$_irp/cmdline" 2>/dev/null | head -n 1)
            [ "${_ira0##*/}" = "hnc_httpd" ]
        }
        _old=""
        if [ -f "$RUN/httpd.pid" ]; then
            _old=$(tr -d ' \r\n' < "$RUN/httpd.pid" 2>/dev/null)
            _is_real_httpd_pid "$_old" || _old=""
        fi
        _proc_httpds=""
        if [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
            for _pd in /proc/[0-9]*; do
                [ -r "$_pd/cmdline" ] || continue
                _pp=${_pd##*/}
                _is_real_httpd_pid "$_pp" && _proc_httpds="$_proc_httpds $_pp"
            done
            for _pp in $(pidof hnc_httpd 2>/dev/null); do
                _is_real_httpd_pid "$_pp" || continue
                case " $_proc_httpds " in *" $_pp "*) ;; *) _proc_httpds="$_proc_httpds $_pp" ;; esac
            done
        fi
        for _p in $_old $_proc_httpds; do
            [ -n "$_p" ] && kill -9 "$_p" 2>/dev/null && echo "runtime sync: stopped old hnc_httpd pid=$_p"
        done
        rm -f "$RUN/httpd.pid" 2>/dev/null
        if mv -f "$_h_tmp" "$H_RUN" 2>/dev/null; then
            fix_exec "$H_RUN"
            echo "runtime sync: refreshed hnc_httpd binary from module"
        else
            rm -f "$_h_tmp" 2>/dev/null || true
            echo "runtime sync WARN: failed to replace $H_RUN"
        fi
    else
        rm -f "$_h_tmp" 2>/dev/null || true
        echo "runtime sync WARN: failed to stage $H_MOD -> $_h_tmp, keeping existing hnc_httpd"
    fi
fi
fix_perms
exit 0
