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
fix_perms   # 先修模块目录权限与 SELinux 上下文

_first_tok() { set -- $1; printf '%s' "${1:-}"; }
_first_two_tok() { set -- $1; printf '%s:%s' "${1:-}" "${2:-}"; }

# _files_same <src> <dst>: 内容完全一致返回 0, 否则返回 1
_files_same() {
    _fs_a="$1"
    _fs_b="$2"
    [ -f "$_fs_a" ] && [ -f "$_fs_b" ] && [ ! -L "$_fs_b" ] || return 1
    if command -v cmp >/dev/null 2>&1; then
        cmp -s "$_fs_a" "$_fs_b" 2>/dev/null && return 0
        return 1
    elif command -v sha256sum >/dev/null 2>&1; then
        _s_a=$(_first_tok "$(sha256sum "$_fs_a" 2>/dev/null)")
        _s_b=$(_first_tok "$(sha256sum "$_fs_b" 2>/dev/null)")
        [ -n "$_s_a" ] && [ "$_s_a" = "$_s_b" ] && return 0
        return 1
    elif command -v cksum >/dev/null 2>&1; then
        _c_a=$(_first_two_tok "$(cksum "$_fs_a" 2>/dev/null)")
        _c_b=$(_first_two_tok "$(cksum "$_fs_b" 2>/dev/null)")
        [ "$_c_a" != ":" ] && [ "$_c_a" = "$_c_b" ] && return 0
        return 1
    fi
    return 1
}

_is_native_bin_name() {
    case " $NATIVE_BINS .hnc_mc sh hnc_httpd " in
        *" $1 "*) return 0 ;;
    esac
    return 1
}

# _sync_file <src> <dst> <default_mode>: 差异检测 + 同目录 .tmp.$$ + mv -f 原子覆盖(根治 ETXTBSY 与半截文件)
_sync_file() {
    _sf_src="$1"
    _sf_dst="$2"
    _sf_mode="${3:-644}"
    [ -e "$_sf_src" ] || [ -L "$_sf_src" ] || return 0
    _sf_tmp="${_sf_dst}.tmp.$$"
    if [ -L "$_sf_src" ]; then
        rm -f "$_sf_tmp" 2>/dev/null || true
        if cp -af "$_sf_src" "$_sf_tmp" 2>/dev/null; then
            mv -f "$_sf_tmp" "$_sf_dst" 2>/dev/null || rm -f "$_sf_tmp" 2>/dev/null || true
        else
            rm -f "$_sf_tmp" 2>/dev/null || true
            cp -af "$_sf_src" "$_sf_dst" 2>/dev/null || true
        fi
        return 0
    fi
    [ -f "$_sf_src" ] || return 0
    if _files_same "$_sf_src" "$_sf_dst"; then
        chmod "$_sf_mode" "$_sf_dst" 2>/dev/null || true
        return 0
    fi
    rm -f "$_sf_tmp" 2>/dev/null || true
    if cp -f "$_sf_src" "$_sf_tmp" 2>/dev/null && { [ ! -s "$_sf_src" ] || [ -s "$_sf_tmp" ]; }; then
        chmod "$_sf_mode" "$_sf_tmp" 2>/dev/null || true
        if _is_native_bin_name "${_sf_dst##*/}"; then
            fix_exec "$_sf_tmp"
        fi
        mv -f "$_sf_tmp" "$_sf_dst" 2>/dev/null || rm -f "$_sf_tmp" 2>/dev/null || true
    else
        rm -f "$_sf_tmp" 2>/dev/null || true
    fi
}

_sync_tree() {
    _st_src="$1"
    _st_dst="$2"
    _st_defmode="${3:-644}"
    [ -d "$_st_src" ] || return 0
    mkdir -p "$_st_dst" 2>/dev/null || true
    chmod 755 "$_st_dst" 2>/dev/null || true
    rm -f "$_st_dst"/*.tmp.* "$_st_dst"/.[!.]*.tmp.* 2>/dev/null || true
    for _st_item in "$_st_src"/*; do
        [ -e "$_st_item" ] || [ -L "$_st_item" ] || continue
        _st_bn=${_st_item##*/}
        case "$_st_bn" in *.tmp.*|*.new.*) continue ;; esac
        if [ -d "$_st_item" ] && [ ! -L "$_st_item" ]; then
            ( _sync_tree "$_st_item" "$_st_dst/$_st_bn" "$_st_defmode" )
        else
            _st_m="$_st_defmode"
            if [ -x "$_st_item" ] || _is_native_bin_name "$_st_bn"; then
                _st_m=755
            fi
            _sync_file "$_st_item" "$_st_dst/$_st_bn" "$_st_m"
        fi
    done
}

D_MOD="$MODDIR/bin/hnc_dpid"
D_RUN="$HNC_DIR/bin/hnc_dpid"
_need_dpid_restart=0
if [ -f "$D_MOD" ] && { [ ! -s "$D_RUN" ] || ! _files_same "$D_MOD" "$D_RUN"; }; then
    _need_dpid_restart=1
fi

_sync_tree "$MODDIR/bin" "$HNC_DIR/bin" 755
_sync_tree "$MODDIR/webroot" "$HNC_DIR/webroot" 644
if [ -f "$MODDIR/module.prop" ]; then
    _sync_file "$MODDIR/module.prop" "$HNC_DIR/module.prop" 644
fi

if [ "$_need_dpid_restart" = "1" ] && [ -s "$D_RUN" ] && _files_same "$D_MOD" "$D_RUN"; then
    _dp_proot="${HNC_PROC_ROOT:-/proc}"
    _is_real_dpid_pid() {
        _idp="$1"
        case "$_idp" in ''|*[!0-9]*) return 1 ;; esac
        [ "$_idp" = "$$" ] && return 1
        [ -n "${PPID:-}" ] && [ "$_idp" = "$PPID" ] && return 1
        [ -r "$_dp_proot/$_idp/cmdline" ] || return 1
        if [ -r "$_dp_proot/$_idp/comm" ]; then
            _idc=$(tr -d '\r\n' < "$_dp_proot/$_idp/comm" 2>/dev/null)
            [ "$_idc" = "hnc_dpid" ] || return 1
        fi
        _ida0=$(tr '\000' '\n' < "$_dp_proot/$_idp/cmdline" 2>/dev/null | head -n 1)
        [ "${_ida0##*/}" = "hnc_dpid" ]
    }
    _dpid_pids=""
    for _dpf in "$RUN/dpid.child.pid" "$RUN/dpid.pid"; do
        [ -f "$_dpf" ] || continue
        _cand_dp=$(tr -d ' \r\n' < "$_dpf" 2>/dev/null)
        if _is_real_dpid_pid "$_cand_dp"; then
            case " $_dpid_pids " in *" $_cand_dp "*) ;; *) _dpid_pids="$_dpid_pids $_cand_dp" ;; esac
        fi
    done
    if [ "$_dp_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
        for _pd in "$_dp_proot"/[0-9]*; do
            [ -r "$_pd/cmdline" ] || continue
            _pp=${_pd##*/}
            if _is_real_dpid_pid "$_pp"; then
                case " $_dpid_pids " in *" $_pp "*) ;; *) _dpid_pids="$_dpid_pids $_pp" ;; esac
            fi
        done
        if [ "$_dp_proot" = "/proc" ]; then
            for _pp in $(pidof hnc_dpid 2>/dev/null); do
                _is_real_dpid_pid "$_pp" || continue
                case " $_dpid_pids " in *" $_pp "*) ;; *) _dpid_pids="$_dpid_pids $_pp" ;; esac
            done
        fi
    fi
    if [ -n "$_dpid_pids" ]; then
        for _p in $_dpid_pids; do
            [ -n "$_p" ] && kill "$_p" 2>/dev/null || true
        done
        sleep 0.2 2>/dev/null || sleep 1
        for _p in $_dpid_pids; do
            [ -z "$_p" ] && continue
            if kill -0 "$_p" 2>/dev/null; then
                kill -9 "$_p" 2>/dev/null || true
            fi
            echo "runtime sync: stopped old hnc_dpid pid=$_p for refreshed binary"
        done
        rm -f "$RUN/dpid.pid" "$RUN/dpid.child.pid" 2>/dev/null || true
    fi
fi

H_MOD="$MODDIR/daemon/hnc_httpd/hnc_httpd"
H_RUN="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
_need_httpd=0
if [ ! -f "$H_MOD" ]; then
    echo "runtime sync WARN: module hnc_httpd missing at $H_MOD"
elif [ ! -s "$H_RUN" ]; then
    _need_httpd=1
elif ! _files_same "$H_MOD" "$H_RUN"; then
    if ! command -v cmp >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1 && ! command -v cksum >/dev/null 2>&1; then
        echo "runtime sync WARN: cmp/sha256sum/cksum unavailable, forcing refresh of $H_RUN"
    fi
    _need_httpd=1
fi
if [ "$_need_httpd" = "1" ]; then
    _h_tmp="$H_RUN.tmp.$$"
    rm -f "$_h_tmp" 2>/dev/null || true
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
