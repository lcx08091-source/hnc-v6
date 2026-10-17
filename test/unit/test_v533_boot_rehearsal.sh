#!/system/bin/sh
# test/unit/test_v533_boot_rehearsal.sh — 开机演练: 在沙箱里真跑一遍 post-fs-data.sh + service.sh。
#
# v5.33 删了一大堆(shell 扫描兜底、守护链、双写者、legacy JSON、旧开关……), 两个开机脚本
# 和它们拉起的脚本是最容易「还在调已经删掉的东西」的地方, 单元测试又覆盖不到整条开机链。
# 这里搭一个假模块目录 + 假运行目录(真实脚本, 只把写死的 /data/local/hnc 换成沙箱路径),
# 原生二进制换成记录参数的桩, iptables / tc / ip / getprop / ps / pidof / pkill … 换成只记账的
# 桩(不碰真网卡、真进程), 先跑 post-fs-data.sh 再跑 service.sh, 然后检查:
#   - 两个脚本都正常跑完, 输出和日志里没有「命令不存在 / 文件打不开 / 语法错」;
#   - 运行目录同步对了(hnc_json / hnc_runtime_sync.sh / hnc_proc.sh / httpd), 旧文件与旧键
#     清掉 / 迁好, 权限收紧;
#   - 拉起的进程参数对: httpd 只带 -hnc-dir, 看门狗不带参数, hotspotd -d, C launcher 被选中;
#   - DPI 规则只同步 dpi_rules.d/, 没有 etc/dpi_rules.json;
#   - 收尾后沙箱里的进程一个不剩。
# 真机(有 /system/build.prop)上跳过: 会和正在跑的 HNC 抢 pidfile / 端口。
# 「改动前会失败」: rc2 之前 service.sh 带 -bind 0.0.0.0 拉 httpd、post-fs-data 没有
# clsact 旧键迁移块; 只传 HNC_DIR 的子脚本(json_set.sh 等)写到默认目录。

R="$HNC_REPO_ROOT"
SB="${HNC_TEST_DIR}.boot"     # test_start 每次都会清空 HNC_TEST_DIR, 沙箱放旁边, 文件末尾删
MOD="$SB/hnc_mod"; RT="$SB/rt"; MB="$SB/mock"; CALLS="$SB/calls.log"

if [ -f /system/build.prop ]; then
    test_start "v5.33 开机演练: post-fs-data.sh + service.sh"
    test_skip "真机上不跑(会和正在运行的 HNC 抢 pidfile / 端口)"
    return 0 2>/dev/null || exit 0
fi

SH_BIN=$(command -v sh)

# 原生二进制桩: 记下 argv; hotspotd -d 自己后台化并写 pidfile; launcher --version 正常退;
# fork_probe 直接成功; 其余常驻(命令行里带沙箱路径, 收尾时按路径收掉)。
make_stub() { # $1 = 路径
    cat > "$1" <<EOF
#!$SH_BIN
echo "\${0##*/} \$*" >> "$CALLS"
case "\${0##*/}:\$1" in
    hotspotd:-d) ( while :; do sleep 1; done ) & echo \$! > "\$HNC_DIR/run/hotspotd.pid"; exit 0 ;;
    *:--version|*:-v) echo "stub 0.0.0"; exit 0 ;;
    fork_probe:*|hnc_ipc:*|hnc_clsact_ctl:*|mdns_resolve:*|hnc_tc_ingress:*) exit 0 ;;
esac
while :; do sleep 1; done
EOF
    chmod 755 "$1"
}

# 系统命令桩(记账)。getprop 回答开机完成 / ABI; ip link show 报一个 wlan2; ps 只有表头。
make_mocks() {
    mkdir -p "$MB"
    for c in iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore \
             tc setprop settings cmd dumpsys ndc svc chcon pm am logcat iw resetprop pidof pkill killall; do
        printf '#!%s\necho "%s $*" >> "%s"\n[ "%s" = pidof ] || [ "%s" = pkill ] && exit 1\nexit 0\n' \
            "$SH_BIN" "$c" "$CALLS" "$c" "$c" > "$MB/$c"
    done
    cat > "$MB/getprop" <<EOF
#!$SH_BIN
case "\$1" in
    sys.boot_completed) echo 1 ;;
    ro.product.cpu.abi) echo arm64-v8a ;;
    ro.product.cpu.abilist) echo arm64-v8a,armeabi-v7a ;;
    ro.build.version.release) echo 16 ;;
    ro.build.version.sdk) echo 36 ;;
    *) echo "" ;;
esac
EOF
    cat > "$MB/ip" <<EOF
#!$SH_BIN
echo "ip \$*" >> "$CALLS"
case "\$*" in
    *link*show*) echo "3: wlan2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 3000" ;;
esac
exit 0
EOF
    printf '#!%s\necho "UID PID PPID C STIME TTY TIME CMD"\nexit 0\n' "$SH_BIN" > "$MB/ps"
    chmod 755 "$MB"/*
}

# 沙箱里的进程: 命令行里带 "$SB/" 的(脚本 / 桩 / service.sh 的子 shell)。比较在 shell 里做,
# 不把路径放进任何子进程的 argv(否则 grep 自己也会被算进去)。
sandbox_pids() {
    for _d in /proc/[0-9]*; do
        _p=${_d#/proc/}
        [ "$_p" = "$$" ] && continue
        _c=$(tr '\000' ' ' < "$_d/cmdline" 2>/dev/null)
        case "$_c" in *"$SB/"*) printf '%s ' "$_p" ;; esac
    done
}
sandbox_kill_all() {
    for _i in 1 2 3 4 5; do
        _ps=$(sandbox_pids)
        [ -z "$_ps" ] && return 0
        kill -9 $_ps 2>/dev/null
        sleep 1
    done
    [ -z "$(sandbox_pids)" ]
}

boot_env() { # 跑开机脚本的环境: 桩优先, HNC_DIR / HNC 指沙箱(service.sh 不 export, 子脚本靠环境)
    env PATH="$MB:$PATH" HNC_DIR="$RT" HNC="$RT" HNC_SKIP_PATH_HARDENING=1 HNC_TEST_MODE=1 "$@"
}

# 「命令不存在 / 打不开 / 语法错」类输出(不含已知无害的: 没有 busybox 时 --list 的报错等)
error_lines() { # $@ = 文件
    cat "$@" 2>/dev/null | grep -iE 'not found|no such file|can.t open|cannot open|syntax error|bad substitution|unexpected|permission denied|cannot execute' \
        | grep -vE 'hnc_mc|\.hnc_mc' | head -5
}

# ─── 搭沙箱 ──────────────────────────────────────────────────────────────────
rm -rf "$SB"; mkdir -p "$MOD/daemon/hnc_httpd" "$RT"
make_mocks
cp -r "$R/bin" "$R/webroot" "$R/data" "$MOD/"
cp "$R/module.prop" "$MOD/"
echo arm64-v8a > "$MOD/bin/hnc_pkg_abi"
for s in post-fs-data.sh service.sh; do
    sed "s|/data/local/hnc|$RT|g" "$R/$s" > "$MOD/$s"
done
make_stub "$MOD/daemon/hnc_httpd/hnc_httpd"
for b in hotspotd hnc_watchdog hnc_launcher hnc_dpid fork_probe hnc_ipc hnc_tc_ingress mdns_resolve hnc_clsact_ctl; do
    make_stub "$MOD/bin/$b"
done
# 旧版本装机留下的状态: 旧开关键、v5.33 旧文件、上次的 pid / 状态、从没用过的 api/ test/
mkdir -p "$RT/data" "$RT/run" "$RT/etc" "$RT/logs" "$RT/api" "$RT/test"
printf '%s' '{"version":1,"auth_required":false,"clsact_bpf_enabled":true,"devices":{},"blacklist":[],"whitelist":[]}' \
    > "$RT/data/rules.json"
for f in data/m4_owner run/m4_owner.current run/wd_m5.disabled run/wd_m3.disabled run/httpd_bind_ip \
         run/httpd.wanted run/json_legacy_fallback.count run/json_legacy_fallback.log etc/dpi_rules.json \
         run/hnc_state run/old.pid; do
    echo stale > "$RT/$f"
done

# ─── 1. post-fs-data.sh ───────────────────────────────────────────────────
test_start "v5.33 开机演练: post-fs-data.sh 跑完, 同步 / 清旧 / 迁移 / 权限都对"
boot_env sh "$MOD/post-fs-data.sh" > "$SB/pfd.out" 2>&1; rc=$?
bad=""
[ "$rc" = 0 ] || bad="$bad rc=$rc"
grep -q 'post-fs-data: initialization complete' "$RT/logs/boot.log" 2>/dev/null || bad="$bad 没跑完"
for f in bin/hnc_json bin/hnc_runtime_sync.sh bin/hnc_proc.sh bin/json_set.sh bin/watchdog.sh \
         webroot/index.html; do
    [ -f "$RT/$f" ] || bad="$bad missing:$f"
done
[ -x "$RT/daemon/hnc_httpd/hnc_httpd" ] && [ -x "$RT/bin/hnc_watchdog" ] || bad="$bad 原生二进制没同步/不可执行"
for f in data/m4_owner run/m4_owner.current run/wd_m5.disabled run/wd_m3.disabled run/httpd_bind_ip \
         run/httpd.wanted run/json_legacy_fallback.count run/json_legacy_fallback.log etc/dpi_rules.json \
         run/hnc_state run/old.pid; do
    [ -e "$RT/$f" ] && bad="$bad stale-left:$f"
done
[ -e "$RT/api" ] || [ -e "$RT/test" ] && bad="$bad api/test-left"
c=$(tr -d ' \n' < "$RT/data/rules.json")
case "$c" in *'"clsact_bpf_mode":"on"'*) ;; *) bad="$bad no-mode:$c" ;; esac
case "$c" in *clsact_bpf_enabled*) bad="$bad old-key-left" ;; esac
for d in "$RT" "$RT/data" "$RT/run" "$RT/logs"; do
    [ "$(stat -c %a "$d" 2>/dev/null)" = 700 ] || bad="$bad perm:${d#$SB/}=$(stat -c %a "$d" 2>/dev/null)"
done
e=$(error_lines "$SB/pfd.out" "$RT/logs/boot.log")
[ -n "$e" ] && bad="$bad 报错: $e"
assert_json_valid "$RT/data/rules.json" && { [ -z "$bad" ] && test_pass || test_fail "$bad"; }

# ─── 2. service.sh ────────────────────────────────────────────────────────
test_start "v5.33 开机演练: service.sh 跑完, 拉起的进程与参数对(httpd 只带 -hnc-dir)"
: > "$CALLS"
boot_env timeout 120 sh "$MOD/service.sh" > "$SB/svc.out" 2>&1; rc=$?
sleep 4   # 后台的能力探测 / device_detect daemon / offload recovery 跑完
bad=""
[ "$rc" = 0 ] || bad="$bad rc=$rc"
L="$RT/logs/service.log"
grep -q '=== All services started ===' "$L" 2>/dev/null || bad="$bad 没跑到 All services started"
grep -q 'sentinel started' "$L" 2>/dev/null || bad="$bad 哨兵没起"
h=$(grep '^hnc_httpd ' "$CALLS" | head -1)
[ "$h" = "hnc_httpd -hnc-dir $RT" ] || bad="$bad httpd-args:[$h]"
[ "$(grep -c '^hnc_httpd ' "$CALLS")" = 1 ] || bad="$bad httpd 拉了 $(grep -c '^hnc_httpd ' "$CALLS") 次"
w=$(grep '^hnc_watchdog' "$CALLS" | head -1)
[ "$w" = "hnc_watchdog " ] || bad="$bad watchdog-args:[$w]"
grep -q "^hotspotd -d -l $RT/logs/hotspotd.log" "$CALLS" || bad="$bad hotspotd 没按 -d 拉起"
grep -q '^hnc_launcher $' "$CALLS" || bad="$bad launcher 没起"
[ "$(cat "$RT/run/dpid_launcher.choice" 2>/dev/null)" = launcher ] || bad="$bad choice=$(cat "$RT/run/dpid_launcher.choice" 2>/dev/null)"
[ "$(cat "$RT/run/service.path" 2>/dev/null)" = "$MOD" ] || bad="$bad service.path"
grep -q '\-bind' "$CALLS" && bad="$bad 带了 -bind"
assert_eq "" "$bad" "service.sh" && test_pass

test_start "v5.33 开机演练: service.sh 的数据落地(规则目录 / 管理员密钥 / auth 迁移)都在沙箱"
bad=""
n=$(ls "$RT"/etc/dpi_rules.d/*.json 2>/dev/null | wc -l)
[ "$n" -ge 10 ] || bad="$bad dpi_rules.d=$n"
[ -e "$RT/etc/dpi_rules.json" ] && bad="$bad etc/dpi_rules.json"
s=$(cat "$RT/run/local_admin.secret" 2>/dev/null)
case "$s" in *[!0-9a-f]*|'') bad="$bad secret-bad" ;; esac
[ "${#s}" = 64 ] || bad="$bad secret-len=${#s}"
[ "$(stat -c %a "$RT/run/local_admin.secret" 2>/dev/null)" = 600 ] || bad="$bad secret-perm"
c=$(tr -d ' \n' < "$RT/data/rules.json")
case "$c" in *'"auth_required":true'*) ;; *) bad="$bad auth_required:$c" ;; esac
[ -s "$RT/run/root_env.json" ] || bad="$bad no-root_env"
assert_json_valid "$RT/data/rules.json" && { [ -z "$bad" ] && test_pass || test_fail "$bad"; }

test_start "v5.33 开机演练: 开机输出和各日志里没有「命令不存在 / 打不开 / 语法错」"
e=$(error_lines "$SB/svc.out" "$RT"/logs/*.log)
[ -z "$e" ] && test_pass || test_fail "$e"

test_start "v5.33 开机演练: 收尾后沙箱里的进程一个不剩"
n=$(echo $(sandbox_pids) | wc -w)
[ "$n" -ge 3 ] || echo "  (注意: 收尾前只有 $n 个沙箱进程)"
if sandbox_kill_all; then test_pass; else test_fail "还剩: $(sandbox_pids)"; fi

rm -rf "$SB"
