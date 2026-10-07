#!/system/bin/sh
# v5.29 T3: hnc_rollback.sh —— 升级自检 + 自动回滚
#
# 模拟: 临时目录当模块目录(module.prop)+ 运行目录; /proc 判活和端口
# 没法在沙箱造 → 用可注入的桩(HNC_RB_PROC_OVERRIDE / HNC_RB_PORT_OVERRIDE)
# 覆盖 pidfile_pid_matches / rb_port_listening 两个外部依赖。

RBSCRIPT="$HNC_REPO_ROOT/bin/hnc_rollback.sh"

rbseed() {
    MOD="$HNC_TEST_DIR/mod"; HNC="$HNC_TEST_DIR/hnc"
    rm -rf "$MOD" "$HNC"
    mkdir -p "$MOD/bin" "$HNC/bin" "$HNC/data" "$HNC/run" \
             "$HNC/daemon/hnc_httpd" "$HNC/webroot" "$HNC/stub"
    printf 'id=hnc\nversion=v5.29.0-rc1\nversionCode=%s\n' "${1:-5290001}" > "$MOD/module.prop"
    # 运行目录里放旧版本的文件(内容可辨)
    echo "OLD-BIN-v528" > "$HNC/bin/hnc_watchdog"
    echo "OLD-HTTPD-v528" > "$HNC/daemon/hnc_httpd/hnc_httpd"
    echo "OLD-WEB-v528" > "$HNC/webroot/index.html"
    echo "${2:-5280001}" > "$HNC/data/runtime_version"
    # 桩: pidfile_pid_matches / rb_port_listening
    cat > "$HNC/stub/proc_override.sh" <<'STUB'
pidfile_pid_matches() { [ -f "$1" ]; }
rb_port_listening() { [ "$HNC_RB_PORT_OK" = 1 ]; }
STUB
    : > "$HNC/run/httpd.pid"
    : > "$HNC/run/watchdog.pid"
}

rbrun() {
    HNC_RB_STUB="$HNC/stub/proc_override.sh" HNC_RB_PORT_OK="${HNC_RB_PORT_OK:-0}" \
    HNC_RB_LOG="$HNC_TEST_DIR/rb.log" \
        sh "$RBSCRIPT" "$@"
}

test_start "rollback: 升级时生成 .prev 快照 + 记新版本 + 观察期开启"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC"; rc=$?
[ $rc -eq 0 ] \
  && [ "$(cat "$HNC/.prev/version" 2>/dev/null)" = 5280001 ] \
  && [ "$(grep -c OLD-BIN "$HNC/.prev/bin/hnc_watchdog" 2>/dev/null)" = 1 ] \
  && [ "$(cat "$HNC/data/runtime_version")" = 5290001 ] \
  && [ -f "$HNC/data/rollback.observing" ] \
  && test_pass || test_fail "rc=$rc prev=$(ls "$HNC/.prev" 2>/dev/null | tr '\n' ' ') rv=$(cat "$HNC/data/runtime_version" 2>/dev/null)"

test_start "rollback: 同版本重启不生成快照、不开观察期"
rbseed 5290001 5290001
rbrun snapshot "$MOD" "$HNC"; rc=$?
[ $rc -eq 0 ] && [ ! -d "$HNC/.prev" ] && [ ! -f "$HNC/data/rollback.observing" ] \
  && test_pass || test_fail "rc=$rc prev_exists=$([ -d "$HNC/.prev" ] && echo yes)"

test_start "rollback: 观察期内连续 6 次核心进程起不来 → 回滚 + 钉住"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
# 模拟新版文件同步(内容可辨)
echo "NEW-BIN-v529" > "$HNC/bin/hnc_watchdog"
rbrun observe "$HNC"; r1=$?
rbrun observe "$HNC"; r2=$?
rbrun observe "$HNC"; r3=$?
rbrun observe "$HNC"; r4=$?
rbrun observe "$HNC"; r5=$?
rbrun observe "$HNC"; r6=$?
[ $r6 -eq 9 ] \
  && [ "$(grep -c OLD-BIN "$HNC/bin/hnc_watchdog" 2>/dev/null)" = 1 ] \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = 5290001 ] \
  && [ "$(cat "$HNC/data/runtime_version")" = 5280001 ] \
  && grep -q rolled_back "$HNC/data/rollback.json" \
  && grep -q '"from":"5290001","to":"5280001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "r6=$r6 bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) pin=$(cat "$HNC/data/rollback.pinned" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 前几轮失败但第 5 轮进程起来了 → 不回滚(streak 清零)"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
i=0; while [ $i -lt 4 ]; do rbrun observe "$HNC" >/dev/null 2>&1; i=$((i+1)); done
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1   # 这轮全活
HNC_RB_PORT_OK=0 rbrun observe "$HNC" >/dev/null 2>&1; r=$?  # 又挂一轮: streak=1
[ $r -ne 9 ] && [ ! -f "$HNC/data/rollback.json" ] && [ "$(cat "$HNC/data/rollback.failstreak")" = 1 ] \
  && test_pass || test_fail "r=$r streak=$(cat "$HNC/data/rollback.failstreak" 2>/dev/null) json=$([ -f "$HNC/data/rollback.json" ] && echo yes)"

test_start "rollback: pinned 时 snapshot 跳过同步(rc=3)"
rbseed 5290001 5290001   # 模块版本 = pinned 版本
echo 5290001 > "$HNC/data/rollback.pinned"
rbrun snapshot "$MOD" "$HNC"; rc=$?
[ $rc -eq 3 ] && test_pass || test_fail "rc=$rc(应 3)"

test_start "rollback: 刷了更新版本 → 解钉 + 正常快照"
rbseed 5300001 5290001
echo 5290001 > "$HNC/data/rollback.pinned"
rbrun snapshot "$MOD" "$HNC"; rc=$?
[ $rc -eq 0 ] && [ ! -f "$HNC/data/rollback.pinned" ] \
  && [ "$(cat "$HNC/.prev/version")" = 5290001 ] && test_pass \
  || test_fail "rc=$rc pin=$([ -f "$HNC/data/rollback.pinned" ] && echo yes) prev=$(cat "$HNC/.prev/version" 2>/dev/null)"

test_start "rollback: 快照失败(打包错误)不影响开机(仍返回 0 记新版本)"
rbseed 5290001 5280001
rm -rf "$HNC/bin"               # 让 cp 失败(源没了; 打包链进 else)
rbrun snapshot "$MOD" "$HNC"; rc=$?
[ $rc -eq 0 ] && [ "$(cat "$HNC/data/runtime_version")" = 5290001 ] && [ ! -d "$HNC/.prev/bin" ] \
  && test_pass || test_fail "rc=$rc rv=$(cat "$HNC/data/runtime_version" 2>/dev/null)"

test_start "rollback: rollback.disabled 时只记录不回滚"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
echo "NEW-BIN-v529" > "$HNC/bin/hnc_watchdog"
: > "$HNC/data/rollback.disabled"
i=0; while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; i=$((i+1)); done
r=$?
[ "$r" = 0 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog")" = NEW-BIN-v529 ] \
  && [ ! -f "$HNC/data/rollback.pinned" ] \
  && grep -q recorded_only "$HNC/data/rollback.json" \
  && test_pass || test_fail "r=$r bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: status 打印 rollback.json"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
rbrun observe "$HNC" >/dev/null 2>&1
out=$(rbrun status "$HNC")
[ -z "$out" ] && [ ! -f "$HNC/data/rollback.json" ] && test_pass || test_fail "status 应为空(未回滚), got: $out"

# ── v5.29 审查修复 ──────────────────────────────────────────────────

# 桩: pidfile 非空即「活着」(pid 由用例写)
rbstub_alive() {
    cat > "$HNC/stub/proc_override.sh" <<'STUB'
pidfile_pid_matches() { [ -s "$1" ]; }
rb_port_listening() { [ "$HNC_RB_PORT_OK" = 1 ]; }
STUB
}

test_start "rollback: 健康开机首轮 pid 只记基线; 之后 3 次正常重启不误回滚"
# rc1: 首轮 lastpid 为空 → httpd/watchdog 各 +1 = 2, 再有 3 次重启(热点 IP
# 变化让 httpd 重绑之类)就凑满 5 → 好好的新版被回滚。
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
rbstub_alive
echo 1001 > "$HNC/run/httpd.pid"; echo 2001 > "$HNC/run/watchdog.pid"
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
for p in 1002 1003 1004; do
    echo "$p" > "$HNC/run/httpd.pid"
    HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
done
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1; r=$?
[ "$r" = 0 ] && [ ! -f "$HNC/data/rollback.json" ] && [ "$(cat "$HNC/data/rollback.restarts")" = 3 ] \
  && test_pass || test_fail "r=$r restarts=$(cat "$HNC/data/rollback.restarts" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 崩溃循环(基线之后 pid 变 5 次)→ 回滚"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
echo "NEW-BIN-v529" > "$HNC/bin/hnc_watchdog"
rbstub_alive
echo 2001 > "$HNC/run/watchdog.pid"
r=0
for p in 1000 1001 1002 1003 1004 1005; do
    echo "$p" > "$HNC/run/httpd.pid"
    HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1; r=$?
done
[ "$r" = 9 ] && grep -q 'restarts=5' "$HNC/data/rollback.json" \
  && [ "$(grep -c OLD-BIN "$HNC/bin/hnc_watchdog" 2>/dev/null)" = 1 ] \
  && test_pass || test_fail "r=$r json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: pidfile 暂时消失再出现新 pid → 仍算一次重启(基线不丢)"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
rbstub_alive
echo 1001 > "$HNC/run/httpd.pid"; echo 2001 > "$HNC/run/watchdog.pid"
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
: > "$HNC/run/httpd.pid"                       # 被杀, 还没重拉
HNC_RB_PORT_OK=0 rbrun observe "$HNC" >/dev/null 2>&1
echo 1002 > "$HNC/run/httpd.pid"
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
[ "$(cat "$HNC/data/rollback.restarts")" = 1 ] \
  && test_pass || test_fail "restarts=$(cat "$HNC/data/rollback.restarts" 2>/dev/null)(应 1)"

# post-fs-data.sh 每次开机都比 service.sh 先把模块文件拷进运行目录。rc1 把
# 快照放在 service.sh(还错插进了文件头注释里, 根本执行不到): 就算放对,
# 打进 .prev 的也已经是新版, 钉住也挡不住 post-fs-data 把坏版本拷回来。
# 这里在沙箱里真跑 post-fs-data.sh(HNC_DIR 换成临时目录)。
pfd_seed() {
    rbseed "$1" "$2"
    rm -rf "$MOD"; mkdir -p "$MOD/bin" "$MOD/daemon/hnc_httpd" "$MOD/webroot"
    printf 'id=hnc\nversion=vX\nversionCode=%s\n' "$1" > "$MOD/module.prop"
    cp "$HNC_REPO_ROOT/bin/hnc_rollback.sh" "$MOD/bin/"
    echo "NEW-BIN" > "$MOD/bin/hnc_watchdog"
    echo "NEW-HTTPD" > "$MOD/daemon/hnc_httpd/hnc_httpd"
    echo "NEW-WEB" > "$MOD/webroot/index.html"
    sed "s#^HNC_DIR=/data/local/hnc\$#HNC_DIR=$HNC#" "$HNC_REPO_ROOT/post-fs-data.sh" > "$MOD/post-fs-data.sh"
}
pfd_run() { HNC_TEST_MODE=1 sh "$MOD/post-fs-data.sh" >/dev/null 2>&1; }

test_start "rollback: post-fs-data 升级开机 → .prev 是旧版, 运行目录换成新版"
pfd_seed 5290001 5280001
pfd_run
[ "$(cat "$HNC/.prev/bin/hnc_watchdog" 2>/dev/null)" = OLD-BIN-v528 ] \
  && [ "$(cat "$HNC/.prev/daemon/hnc_httpd/hnc_httpd" 2>/dev/null)" = OLD-HTTPD-v528 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog")" = NEW-BIN ] \
  && [ "$(cat "$HNC/daemon/hnc_httpd/hnc_httpd")" = NEW-HTTPD ] \
  && [ -f "$HNC/data/rollback.observing" ] \
  && test_pass || test_fail "prev=$(cat "$HNC/.prev/bin/hnc_watchdog" 2>/dev/null) run=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null)"

test_start "rollback: post-fs-data 钉住时不把坏版本拷回运行目录"
pfd_seed 5290001 5280001
echo 5290001 > "$HNC/data/rollback.pinned"   # 上次开机已回滚并钉住 5290001
pfd_run
[ "$(cat "$HNC/bin/hnc_watchdog")" = OLD-BIN-v528 ] \
  && [ "$(cat "$HNC/daemon/hnc_httpd/hnc_httpd")" = OLD-HTTPD-v528 ] \
  && [ ! -f "$HNC/data/rollback.observing" ] \
  && test_pass || test_fail "bin=$(cat "$HNC/bin/hnc_watchdog") httpd=$(cat "$HNC/daemon/hnc_httpd/hnc_httpd")"

test_start "rollback: 新的回滚记录清掉上一次的「知道了」(否则横幅被旧 ack 藏掉)"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
: > "$HNC/data/rollback.ack"          # 上一次回滚用户点过「知道了」
i=0; while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; i=$((i+1)); done
[ -f "$HNC/data/rollback.json" ] && [ ! -f "$HNC/data/rollback.ack" ] \
  && test_pass || test_fail "ack 仍在: $(ls "$HNC/data")"
