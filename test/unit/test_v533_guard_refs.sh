#!/system/bin/sh
# test/unit/test_v533_guard_refs.sh — v5.33「只留一份」删了一大堆之后的防回归守卫。
#
# 删代码最容易留下的坑不是删错了什么, 而是「还有人在用」: 调用方漏改、清单漏改、
# 两端约定只改了一端。这里把这些约定全部钉成断言, 以后谁再删 / 改名都会在这里红:
#   1. v5.33 删掉的 82 个 shell 函数, 发布包里的 shell 不再调用(防止从旧分支 / 旧补丁带回来);
#   2. 脚本之间互相调用一律 `sh 脚本`(CI 的 Linux 与运行期被卸的 /system/bin 都没有 /system/bin/sh),
#      被调的脚本都在; Go 里引用的 bin/ 脚本都在, 原生二进制都在运行期同步的 chmod / chcon 清单里;
#   3. WebUI 调的每个 /api/ 路径都注册了, 每个 action 都在 httpd 分发里;
#   4. Go 看门狗的动作名与 watchdog.sh 的分发标签双向一致, 分发目标函数都有定义;
#   5. 每个看门狗动作在沙箱里真跑一遍: 没有「命令不存在 / 文件打不开 / 语法错」;
#   6. JSON 脚本在只给 HNC_DIR 时读写的是同一个目录(v5.33 前 watchdog.sh 读 $HNC_DIR、
#      json_set.sh / hnc_json 只认 $HNC —— 测试和任何只传 HNC_DIR 的调用都写到默认目录);
#   7. post-fs-data 开机清掉的 v5.33 旧文件, 代码里没人再读写。
# 「改动前会失败」: 5 / 6 —— full_init 把 hotspot_iface 写进 /data/local/hnc 而不是沙箱;
# capability_probe 首次跑报「cannot open run/capability_probe_last」(读重定向写在 2>/dev/null
# 前面, 报错没被吞)。其余是对现状的锁定(故意改回旧写法时会红, 见 CHANGELOG)。

R="$HNC_REPO_ROOT"

# 发布包里的 shell(test/ tools/ src/ docs/ 不进安装包)
SHIPPED_SH="$R/service.sh $R/post-fs-data.sh $R/customize.sh $R/uninstall.sh $(ls "$R"/bin/*.sh "$R"/bin/diag/*.sh) $R/bin/hnc_json"
# 发布的 Go 源码(不含 _test.go)
GO_SRC=$(ls "$R"/daemon/hnc_httpd/*.go $(find "$R/src/dpid" -name '*.go') | grep -v '_test\.go$')
# WebUI(changelog.html 是历史记录, 不算)
UI_SRC="$R/webroot/index.html $R/webroot/glass.html $R/webroot/json-health.html $(ls "$R"/webroot/js/*.js)"

# 去掉注释(整行 # 与「空白 + #」起的行尾注释), 再把 \ 续行接成一行
strip_sh() {
    sed -e 's/^[[:space:]]*#.*//' -e 's/[[:space:]]#.*$//' "$1" | sed -e :a -e '/\\$/N; s/\\\n//; ta'
}
strip_go() {
    sed -e 's|^[[:space:]]*//.*||' -e 's|[[:space:]]//[[:space:]].*||' "$1"
}
rel() { echo "${1#$R/}"; }

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: 删掉的 82 个 shell 函数, 发布包里不再调用"
# cdd26f0~1(v5.32.x)有、v5.33 没有的函数(token_revoke / token_revoke_all 仍是
# json_set.sh 的子命令名, 不算)。
REMOVED_FNS="_mdns_usable _verify_pid acquire_json_lock arp_hash atomic_write awk_v_escape
check_and_repair check_health check_httpd_bind_drift cleanup_guard clsact_enabled
daemon_shell_fallback do_scan_shell do_scan_via_daemon dpid_alive ensure_daemon
ensure_path_or_die get_hostname get_hotspot_iface_legacy guard_poll_interval guarded_commit
hnc_act_quiet hnc_act_sleep_until hnc_json_decode_string_literal hnc_json_type_for_value
hostname_cache_set hostname_cached hotspot_hint_matches_iface httpd_guard_install
httpd_guard_remove iface_exists iface_has_arp_clients iface_has_ipv4 iface_ready
iface_ready_reason iface_up infer_type is_doze_mode is_hotspot_up
json_array_add_string_top_safe json_array_del_string_top_safe json_backup_file
json_batch_legacy_fallback_warn json_blacklist_add_hnc_json json_blacklist_del_hnc_json
json_device_get_hnc_json json_encode json_escape_string_inner json_legacy_fallback_warn
json_name_del_hnc_json json_name_get_hnc_json json_name_set_hnc_json
json_object_del_safe_file json_object_set_safe_file json_prune_backups
json_remove_device_safe json_string_encode json_top_get_hnc_json json_tpl_del_hnc_json
json_tpl_set_hnc_json json_update_device_safe json_update_top_hnc_json
json_update_top_safe json_validate_file kill_child last_line launcher_alive_count
m5_enabled probe_valid_hotspot read_count read_json_bool_key read_json_string_key
reclaim_stale_lock safe_backup_current set_map_field set_map_field_inner sleep_s
start_monitor summary_ops sync_runtime_from_moddir wait_for_clean_env write_waiting_state"
n=0; for fn in $REMOVED_FNS; do n=$((n + 1)); done
bad=""
for f in $SHIPPED_SH; do
    body=$(strip_sh "$f")
    for fn in $REMOVED_FNS; do
        # 命令位置出现(前面是行首 / 空白 / ; & | ( `, 后面是空白 / ; ) ` / 行尾);
        # 函数定义 fn() 与 case 标签 fn) / fn| 不算
        hit=$(printf '%s\n' "$body" | grep -nE "(^|[;&|({\`[:space:]])$fn([[:space:]]|;|\$|\)|\`)" \
            | grep -vE "^[0-9]+:[[:space:]]*$fn[[:space:]]*\(\)|^[0-9]+:[[:space:]]*\(?$fn[|)]" | head -1)
        [ -n "$hit" ] && bad="$bad $(rel "$f"):$fn@${hit%%:*}"
    done
done
assert_eq 82 "$n" "名单条数" && { [ -z "$bad" ] && test_pass || test_fail "还在调用:$bad"; }

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: shell 调脚本一律 sh 脚本(不靠 shebang), 被调的脚本都在"
bad=""; cnt=0
CMDPOS='(^|[;&|(`]|\bthen|\bdo|\belse|\$\(|nohup|timeout [0-9]+|exec)[[:space:]]*'
for f in $SHIPPED_SH; do
    body=$(strip_sh "$f")
    # (a) 直接执行 "$X/bin/foo.sh" / "$X/hnc_json"(不带 sh)
    hit=$(printf '%s\n' "$body" | grep -nE "$CMDPOS\"?[\$][{]?[A-Za-z_0-9]+[}]?(/bin)?/([A-Za-z0-9_.-]+\.sh|hnc_json)\"?([[:space:]]|\$|;|\))" \
        | grep -vE '\[ -[fxer] |rm -f|cp |chmod|cat |mv ' | head -1)
    [ -n "$hit" ] && bad="$bad $(rel "$f"):shebang@${hit%%:*}"
    # (b) 变量里放脚本路径再直接执行("$HNC_JSON" set-top ...)
    # (值是路径: 以 $ 或 / 开头、不含空格; "sh $X/foo.sh" 这种自带 sh 的不算)
    for v in $(grep -oE '^[[:space:]]*(local[[:space:]]+)?[A-Z_][A-Z0-9_]*="?(\$\{[A-Z_]+:-)?[$/][^ "]*(\.sh|hnc_json)[}"]*[[:space:]]*$' "$f" \
               | sed -E 's/^[[:space:]]*(local[[:space:]]+)?//; s/=.*//' | sort -u); do
        hit=$(printf '%s\n' "$body" | grep -nE "$CMDPOS\"?[\$][{]?$v[}]?\"?([[:space:]]|\$|;|\))" | head -1)
        [ -n "$hit" ] && bad="$bad $(rel "$f"):\$$v@${hit%%:*}"
    done
    # (c) sh / . 调的脚本必须存在
    for n in $(printf '%s\n' "$body" | grep -oE "(^|[;&|(\`[:space:]])(sh|\.|exec|nohup sh)[[:space:]]+\"?[\$][{]?[A-Za-z_0-9%/*]+[}]?(/bin)?/[A-Za-z0-9_.-]+" \
               | sed -E 's|.*/||' | sort -u); do
        cnt=$((cnt + 1))
        [ -e "$R/bin/$n" ] || [ -e "$R/$n" ] || [ -e "$R/bin/diag/$n" ] || bad="$bad $(rel "$f"):missing:$n"
    done
done
[ "$cnt" -ge 40 ] || bad="$bad 只认出 $cnt 处 sh 调用(正则失效?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: Go 引用的 bin/ 脚本都在, 原生二进制都在运行期同步的 chmod / chcon 清单里"
NATIVE_BINS=$(sed -n 's/^NATIVE_BINS="\(.*\)"$/\1/p' "$R/bin/hnc_runtime_sync.sh")
bad=""; cnt=0
refs=$(for f in $GO_SRC; do
    strip_go "$f" | grep -oE '"bin", *"[^"]+"|"bin/[^"]+"|binDir *\+ *"/[^"]+"|run(Bin|BinDetached|Exe)\([^,]+, *"[^"]+"' \
        | sed -E 's/run(Bin|BinDetached|Exe)\([^,]+, *//; s/^"bin", *//; s/^binDir *\+ *"\//"/; s/^"bin\//"/; s/"//g; s/ .*//'
done | sort -u)
for n in $refs; do
    cnt=$((cnt + 1))
    case "$n" in
        *.sh) [ -f "$R/bin/$n" ] || bad="$bad missing:$n" ;;
        sh|hnc_httpd) ;;   # sh = 看门狗自带的 sh 兜底(可选); hnc_httpd 在 daemon/ 单独同步
        *) case " $NATIVE_BINS " in *" $n "*) ;; *) bad="$bad not-in-NATIVE_BINS:$n" ;; esac ;;
    esac
done
# 清单里的每一个: 要么仓库里就有(hnc_json), 要么 CI 构建出来(build.yml 里点名)
for n in $NATIVE_BINS; do
    [ -f "$R/bin/$n" ] || grep -q "bin/$n\b\|\b$n\b" "$R/.github/workflows/build.yml" || bad="$bad unbuilt:$n"
done
[ "$cnt" -ge 30 ] || bad="$bad 只认出 $cnt 处引用(正则失效?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: WebUI 调的 /api/ 路径都注册了, action 都在 httpd 分发里"
routes=$(cat $GO_SRC | grep -oE 'mux\.Handle(Func)?\("[^"]+"' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)
dispatch=$(awk '/^func dispatchAction\(/{f=1} f{print} f&&/^}/{exit}' "$R/daemon/hnc_httpd/action.go" \
    | grep -E '^[[:space:]]*case "' | grep -oE '"[a-z_0-9]+"' | tr -d '"' | sort -u)
bad=""; np=0; na=0
for p in $(cat $UI_SRC | grep -oE "['\"\`]/api/[a-zA-Z0-9_/.-]*" | tr -d "'\"\`" | sort -u); do
    np=$((np + 1))
    case "$p" in
        /api/self/) # selfToggle 拼 '/api/self/' + data-selftog
            for t in $(cat $UI_SRC | grep -oE 'data-selftog=[\\]?"[^"\\]+' | sed 's/.*"//' | sort -u); do
                echo "$routes" | grep -qx "/api/self/$t" || bad="$bad route:/api/self/$t"
            done ;;
        */) echo "$routes" | grep -qx "$p" || bad="$bad route:$p" ;;
        *) echo "$routes" | grep -qx "$p" || echo "$routes" | grep -qx "$p/" || bad="$bad route:$p" ;;
    esac
done
for a in $(cat $UI_SRC | grep -oE "action\([[:space:]]*['\"][a-z_0-9]+['\"]" | grep -oE "['\"][a-z_0-9]+['\"]" | tr -d "'\"" | sort -u); do
    na=$((na + 1))
    echo "$dispatch" | grep -qx "$a" || bad="$bad action:$a"
done
# json-health.html(KSU 本机页)直接调的脚本
for n in $(grep -oE 'bin/[A-Za-z0-9_.-]+\.sh' "$R/webroot/json-health.html" | sed 's|bin/||' | sort -u); do
    [ -f "$R/bin/$n" ] || bad="$bad json-health:$n"
done
[ "$np" -ge 40 ] && [ "$na" -ge 60 ] || bad="$bad 只认出 $np 个路径 / $na 个 action(正则失效?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: Go 看门狗的动作名 == watchdog.sh 分发标签, 分发目标都有定义"
go_acts=$(cat $(ls "$R"/src/dpid/cmd/hnc_watchdog/*.go | grep -v '_test\.go$') \
    | grep -oE 'runAction(Fn)?\("[a-z_]+"' | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u)
disp=$(awk '/^if \[ "\$\{1:-\}" = "action" \]; then/{f=1} f&&/case "\$_action" in/{g=1; next} g&&/esac/{exit} g{print}' "$R/bin/watchdog.sh")
sh_acts=$(printf '%s\n' "$disp" | grep -oE '^[[:space:]]*[a-z_]+\)' | tr -d ' )' | sort -u)
bad=""
for a in $go_acts; do echo "$sh_acts" | grep -qx "$a" || bad="$bad go-only:$a"; done
for a in $sh_acts; do echo "$go_acts" | grep -qx "$a" || bad="$bad sh-only:$a"; done
# 分发目标函数: watchdog.sh 自己或它 source 的库里定义
libs="$R/bin/watchdog.sh $R/bin/hnc_proc.sh $R/bin/hnc_activity.sh $R/bin/hnc_constants.sh"
for fn in $(printf '%s\n' "$disp" | grep -E '^[[:space:]]*[a-z_]+\)' | sed -E 's/^[[:space:]]*[a-z_]+\)[[:space:]]*//; s/[[:space:]].*//' | sort -u); do
    grep -qE "^[[:space:]]*$fn[[:space:]]*\(\)" $libs || bad="$bad undefined:$fn"
done
n=$(echo $go_acts | wc -w)
[ "$n" -ge 9 ] || bad="$bad 只认出 $n 个动作(正则失效?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"

# ─────────────────────────────────────────────────────────────────────────────
# 沙箱: 运行目录 = $HNC_TEST_DIR/wd; 命令全换成只记账的桩(iptables / tc / ip / getprop /
# settings / cmd / pidof / pkill …), 不碰真网卡、真进程。
wd_sandbox() {
    W="$HNC_TEST_DIR/wd"; MB="$HNC_TEST_DIR/wd_mock"
    mkdir -p "$W/data" "$W/logs" "$W/run" "$W/bin" "$W/etc" "$MB" "$HNC_TEST_DIR/wd_proc"
    cp "$R"/bin/*.sh "$R/bin/hnc_json" "$W/bin/"
    chmod 755 "$W"/bin/*.sh "$W/bin/hnc_json"
    printf '%s' '{"version":1,"devices":{},"blacklist":[],"whitelist":[]}' > "$W/data/rules.json"
    for c in iptables ip6tables iptables-save ip6tables-save iptables-restore tc ip getprop setprop settings \
             cmd dumpsys ndc svc chcon pm am logcat iw pidof pkill killall; do
        printf '#!/bin/sh\necho "%s|$*" >> "%s/calls.log"\n[ "%s" = pidof ] && exit 1\nexit 0\n' \
            "$c" "$HNC_TEST_DIR/wd_mock" "$c" > "$MB/$c"
        chmod 755 "$MB/$c"
    done
}
wd_run() { # $@ = action + 参数; 输出合并到 stdout
    (unset HNC; PATH="$MB:$PATH" HNC_DIR="$W" HNC_SKIP_PATH_HARDENING=1 HNC_TEST_MODE=1 \
        HNC_PROC_ROOT="$HNC_TEST_DIR/wd_proc" sh "$W/bin/watchdog.sh" action "$@" 2>&1)
}

test_start "v5.33 守卫: 每个看门狗动作在沙箱里真跑: 无「命令不存在 / 打不开 / 语法错」, 写的是沙箱"
wd_sandbox
bad=""
for a in $go_acts; do
    case "$a" in
        full_init)        args="wlan2 192.168.43.1" ;;
        migrate)          args="wlan2 wlan3 192.168.43.1" ;;
        capability_probe) args="wlan2" ;;
        full_restore)     args="guard_test" ;;
        *)                args="" ;;
    esac
    out=$(wd_run "$a" $args); rc=$?
    case "$rc" in 64|126|127) bad="$bad $a:rc=$rc" ;; esac
    e=$(printf '%s\n' "$out" | grep -iE 'not found|no such file|can.t open|cannot open|syntax error|bad substitution|unexpected' | head -1)
    [ -n "$e" ] && bad="$bad [$a] $e"
done
# full_init / migrate 在没有用户偏好时把热点网卡写进 rules.json —— 必须是沙箱这份
c=$(tr -d ' \n' < "$W/data/rules.json")
case "$c" in *'"hotspot_iface":"wlan'*) ;; *) bad="$bad hotspot_iface-not-in-sandbox:$c" ;; esac
assert_json_valid "$W/data/rules.json" && { [ -z "$bad" ] && test_pass || test_fail "$bad"; }

test_start "v5.33 守卫: 只给 HNC_DIR(不给 HNC)时 JSON 脚本读写同一个目录"
J="$HNC_TEST_DIR/jd"; mkdir -p "$J/data" "$J/run" "$J/bin"
cp "$R/bin/json_set.sh" "$R/bin/json_set_batch.sh" "$R/bin/hnc_json" "$R/bin/json_guard.sh" "$J/bin/"
printf '%s' '{"version":1,"devices":{},"blacklist":[]}' > "$J/data/rules.json"
(unset HNC; HNC_DIR="$J" sh "$J/bin/json_set.sh" top hotspot_ssid guard >/dev/null 2>&1); r1=$?
(unset HNC; HNC_DIR="$J" sh "$J/bin/json_set_batch.sh" device aa:bb:cc:dd:ee:01 up_mbps 7 >/dev/null 2>&1); r2=$?
(unset HNC; HNC_DIR="$J" sh "$J/bin/hnc_json" set-top "$J/data/rules.json" x 1 num >/dev/null 2>&1); r3=$?
nbak=$(ls "$J/data/.json_backups/" 2>/dev/null | grep -c '^rules\.json\..*\.bak$')
c=$(tr -d ' \n' < "$J/data/rules.json")
assert_eq "0 0 0" "$r1 $r2 $r3" "rc" && assert_contains "$c" '"hotspot_ssid":"guard"' && \
    assert_contains "$c" '"up_mbps":7' && assert_contains "$c" '"x":1' && \
    { [ "$nbak" -ge 1 ] || { test_fail "备份没落在 HNC_DIR/data/.json_backups"; false; }; } && \
    assert_file_not_exists "$J/run/json.lock" "锁应在 HNC_DIR/run 下且已释放" && test_pass

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: post-fs-data 开机清掉的旧文件, 代码里没人再读写"
stale=$(awk '/^# v5.33: 「只留一份」/{f=1} f&&/^rm -f/{g=1} g{print} g&&/2>\/dev\/null$/{exit}' "$R/post-fs-data.sh" \
    | grep -oE '/(run|data|etc)/[A-Za-z0-9_.-]+"' | tr -d '"')
bad=""; n=0
others=$(printf '%s\n' $SHIPPED_SH $GO_SRC $(find "$R/src" "$R/daemon" -name '*.c' -o -name '*.h') $UI_SRC | grep -v '/post-fs-data\.sh$')
for p in $stale; do
    n=$((n + 1))
    d=${p#/}; d=${d%%/*}; b=${p##*/}
    # 以「目录/文件名」或 Go 的 "目录", "文件名" 形式出现, 且不是 rm / os.Remove 那一行
    e='([^A-Za-z0-9_.-]|$)'   # 文件名右边界(\b 会把 hostname_cache.json 当成 hostname_cache)
    pat="$d/$b$e|\"$d\", *\"$b\"|(RUN|run|Run|DATA|data|ETC|etc)(_DIR|Dir)?[}\"]*/$b$e|runDir *\\+ *\"/$b\""
    for f in $others; do
        case "$f" in *.go) body=$(strip_go "$f") ;; *.sh|*/hnc_json) body=$(strip_sh "$f") ;; *) body=$(cat "$f") ;; esac
        hit=$(printf '%s\n' "$body" | grep -nE "$pat" | grep -vE 'rm -f|rm -rf|os\.Remove' | head -1)
        [ -n "$hit" ] && bad="$bad $b<-$(rel "$f")@${hit%%:*}"
    done
done
[ "$n" -ge 15 ] || bad="$bad 只认出 $n 个旧文件(清单格式变了?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"

# ─────────────────────────────────────────────────────────────────────────────
test_start "v5.33 守卫: 测试 UI(tools/ui_mock)的假后端只提供 httpd 真有的接口和动作"
# 预览页(HNC 界面预览)里能点的, 真机上都得有: 删了接口 / 动作就要同时删假后端那份。
F="$R/tools/ui_mock/fake_api.js"
bad=""; nr=0; na=0
for p in $(grep -oE "^[[:space:]]*'/api/[a-zA-Z0-9_/.-]*'" "$F" | tr -d " '" | sort -u); do
    nr=$((nr + 1))
    echo "$routes" | grep -qx "$p" || echo "$routes" | grep -qx "$p/" || bad="$bad route:$p"
done
# 动作表: 行首的键(值可能是函数名) + 同一行里再跟的「名字: function」
act_block=$(awk '/^  var ACT = \{/{f=1; next} f&&/^  \};/{exit} f' "$F")
for a in $( { printf '%s\n' "$act_block" | grep -oE '^    [a-z_0-9]+:'
              printf '%s\n' "$act_block" | grep -oE '(^|[^A-Za-z0-9_.])[a-z_0-9]+: function' | grep -oE '[a-z_0-9]+:'; } \
            | tr -d ' :' | sort -u); do
    na=$((na + 1))
    echo "$dispatch" | grep -qx "$a" || bad="$bad action:$a"
done
[ "$nr" -ge 40 ] && [ "$na" -ge 60 ] || bad="$bad 只认出 $nr 个路由 / $na 个动作(fake_api.js 结构变了?)"
[ -z "$bad" ] && test_pass || test_fail "$bad"
