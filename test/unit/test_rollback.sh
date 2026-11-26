#!/system/bin/sh
# v5.29 T3: hnc_rollback.sh —— 升级自检 + 自动回滚
#
# 模拟: 临时目录当模块目录(module.prop)+ 运行目录; /proc 判活和端口
# 没法在沙箱造 → 用可注入的桩(HNC_RB_PROC_OVERRIDE / HNC_RB_PORT_OVERRIDE)
# 覆盖 pidfile_pid_matches / rb_port_listening 两个外部依赖。

_RB_STANDALONE=0
if ! command -v test_start >/dev/null 2>&1; then
    _RB_STANDALONE=1
    HNC_REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
    export HNC_REPO_ROOT
    . "$HNC_REPO_ROOT/test/lib.sh"
fi

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

test_start "rollback: 已清退子命令 status 返回退出码 4"
rbseed 5290001 5280001
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
rbrun observe "$HNC" >/dev/null 2>&1
out=$(rbrun status "$HNC" 2>/dev/null); rc=$?
[ "$rc" -eq 4 ] && [ -z "$out" ] && [ ! -f "$HNC/data/rollback.json" ] && test_pass || test_fail "未知子命令 status 应返回 rc=4 且 stdout 为空, got: rc=$rc out=$out"

# ── v5.29 审查修复 ──────────────────────────────────────────────────

# 桩: pidfile 非空即「活着」(pid 由用例写)
# v5.32 审查: 用例里的假 pid 一律 > 4194304(Linux pid_max 上限)—— 回滚会对
# pidfile 里的 pid 真的 kill -9, 写 1005 / 2001 这种小号在容器里会杀掉真实进程
# (审查时就把 run_all 本身杀了)。
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
echo 90001001 > "$HNC/run/httpd.pid"; echo 90002001 > "$HNC/run/watchdog.pid"
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
for p in 90001002 90001003 90001004; do
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
echo 90002001 > "$HNC/run/watchdog.pid"
r=0
for p in 90001000 90001001 90001002 90001003 90001004 90001005; do
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
echo 90001001 > "$HNC/run/httpd.pid"; echo 90002001 > "$HNC/run/watchdog.pid"
HNC_RB_PORT_OK=1 rbrun observe "$HNC" >/dev/null 2>&1
: > "$HNC/run/httpd.pid"                       # 被杀, 还没重拉
HNC_RB_PORT_OK=0 rbrun observe "$HNC" >/dev/null 2>&1
echo 90001002 > "$HNC/run/httpd.pid"
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
    cp "$HNC_REPO_ROOT/bin/hnc_runtime_sync.sh" "$MOD/bin/"   # v5.33: 同步只此一份, post-fs-data 调它
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

test_start "rollback: 6000001 -> 6009202 -> 6009301 跨预发布连刷全程锁住 6000001 黄金 .prev 快照"
rbseed 6009202 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-beta.2\nversionCode=6009202\n' > "$MOD/module.prop"
echo "GOLDEN-BIN-v601" > "$HNC/bin/hnc_watchdog"
echo "GOLDEN-HTTPD-v601" > "$HNC/daemon/hnc_httpd/hnc_httpd"
echo "GOLDEN-WEB-v601" > "$HNC/webroot/index.html"
rbrun snapshot "$MOD" "$HNC"; rc1=$?
# 模拟 beta.2 同步运行并在观察期结束后继续升刷 rc.1 (6009301)
echo "BETA2-BIN" > "$HNC/bin/hnc_watchdog"
echo "BETA2-HTTPD" > "$HNC/daemon/hnc_httpd/hnc_httpd"
echo "BETA2-WEB" > "$HNC/webroot/index.html"
rm -f "$HNC/data/rollback.observing"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.1\nversionCode=6009301\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc2=$?
echo "RC1-BROKEN-BIN" > "$HNC/bin/hnc_watchdog"
i=0; r_obs=0
while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; r_obs=$?; i=$((i+1)); done
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] \
  && [ "$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')" = "6000001" ] \
  && [ "$r_obs" -eq 9 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null)" = "GOLDEN-BIN-v601" ] \
  && [ "$(cat "$HNC/data/runtime_version" 2>/dev/null | tr -d ' \r\n')" = "6000001" ] \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = "6009301" ] \
  && grep -q '"from":"6009301","to":"6000001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "rc1=$rc1 rc2=$rc2 robs=$r_obs prev=$(cat "$HNC/.prev/version" 2>/dev/null) bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 6000001 -> 6009301 -> 6009302 (rc.2) 走廊回退 + 全量配置快照白名单恢复"
rbseed 6009301 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.1\nversionCode=6009301\n' > "$MOD/module.prop"
echo "GOLDEN-BIN-v601" > "$HNC/bin/hnc_watchdog"
for _cfg in leakguard_config.json vector_express.json update_leash.json thermo_cruise.json \
            rmac_policy.json webui_access.json dpi_fp_prototypes.json self_policy.json v6_custom_slot.json; do
    printf '{"golden":"%s"}\n' "$_cfg" > "$HNC/data/$_cfg"
done
printf '{"token":"keep-live"}\n' > "$HNC/data/remote_tokens.json"
rbrun snapshot "$MOD" "$HNC"; rc_s1=$?
rm -f "$HNC/data/rollback.observing"
echo "RC1-BIN" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.2\nversionCode=6009302\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_s2=$?
echo "RC2-BROKEN-BIN" > "$HNC/bin/hnc_watchdog"
for _cfg in leakguard_config.json vector_express.json update_leash.json thermo_cruise.json \
            rmac_policy.json webui_access.json dpi_fp_prototypes.json self_policy.json v6_custom_slot.json; do
    printf '{"corrupted_by_rc2":"%s"}\n' "$_cfg" > "$HNC/data/$_cfg"
done
printf '{"token":"updated-live"}\n' > "$HNC/data/remote_tokens.json"
i=0; r_rc2=0
while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; r_rc2=$?; i=$((i+1)); done
_cfg_ok=1
for _cfg in leakguard_config.json vector_express.json update_leash.json thermo_cruise.json \
            rmac_policy.json webui_access.json dpi_fp_prototypes.json self_policy.json v6_custom_slot.json; do
    grep -q "\"golden\":\"$_cfg\"" "$HNC/data/$_cfg" 2>/dev/null || _cfg_ok=0
done
[ "$rc_s1" -eq 0 ] && [ "$rc_s2" -eq 0 ] && [ "$r_rc2" -eq 9 ] && [ "$_cfg_ok" -eq 1 ] \
  && grep -q '"token":"updated-live"' "$HNC/data/remote_tokens.json" \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = "6009302" ] \
  && grep -q '"from":"6009302","to":"6000001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "s1=$rc_s1 s2=$rc_s2 r=$r_rc2 cfg_ok=$_cfg_ok json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 6000001 -> 6009301 -> 6009302 -> 6009303 (rc.3) 连刷全程保护 v6.0.1 (6000001) 黄金 .prev 底包"
rbseed 6009301 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.1\nversionCode=6009301\n' > "$MOD/module.prop"
echo "GOLDEN-BIN-v601" > "$HNC/bin/hnc_watchdog"
echo "GOLDEN-HTTPD-v601" > "$HNC/daemon/hnc_httpd/hnc_httpd"
echo "GOLDEN-WEB-v601" > "$HNC/webroot/index.html"
rbrun snapshot "$MOD" "$HNC"; rc_r1=$?
rm -f "$HNC/data/rollback.observing"
echo "RC1-BIN" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.2\nversionCode=6009302\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_r2=$?
_prev_after_rc2="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
rm -f "$HNC/data/rollback.observing"
echo "RC2-BIN" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.3\nversionCode=6009303\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_r3=$?
_prev_after_rc3="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
echo "RC3-BROKEN-BIN" > "$HNC/bin/hnc_watchdog"
i=0; r_rc3=0
while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; r_rc3=$?; i=$((i+1)); done
[ "$rc_r1" -eq 0 ] && [ "$rc_r2" -eq 0 ] && [ "$rc_r3" -eq 0 ] \
  && [ "$_prev_after_rc2" = "6000001" ] && [ "$_prev_after_rc3" = "6000001" ] \
  && [ "$r_rc3" -eq 9 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null)" = "GOLDEN-BIN-v601" ] \
  && [ "$(cat "$HNC/data/runtime_version" 2>/dev/null | tr -d ' \r\n')" = "6000001" ] \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = "6009303" ] \
  && grep -q '"from":"6009303","to":"6000001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "r1=$rc_r1 r2=$rc_r2 r3=$rc_r3 prev2=$_prev_after_rc2 prev3=$_prev_after_rc3 obs=$r_rc3 bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 6009302 (rc.2) 升正式版 6010000 (v6.1.0) 保黄金底包, 6010000 稳定后接班新黄金 .prev"
rbseed 6009302 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.2\nversionCode=6009302\n' > "$MOD/module.prop"
echo "GOLDEN-601" > "$HNC/bin/hnc_watchdog"
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
rm -f "$HNC/data/rollback.observing"
echo "RC2-LIVE" > "$HNC/bin/hnc_watchdog"
# rc.2 (6009302) -> 正式版 v6.1.0 (6010000): 仍锁住 6000001 黄金底包以防 6010000 坏包退回测试版
printf 'id=hotspot_net_ctl\nversion=v6.1.0\nversionCode=6010000\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_ga=$?
_prev_on_ga="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
# 6010000 观察期通过后升 v6.1.1 (6010001): 6010000 作为正式版接班成为新 .prev
rm -f "$HNC/data/rollback.observing"
echo "STABLE-610" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.1\nversionCode=6010001\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_next=$?
_prev_on_next="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
[ "$rc_ga" -eq 0 ] && [ "$_prev_on_ga" = "6000001" ] \
  && [ "$rc_next" -eq 0 ] && [ "$_prev_on_next" = "6010000" ] \
  && [ "$(cat "$HNC/.prev/bin/hnc_watchdog" 2>/dev/null)" = "STABLE-610" ] \
  && test_pass || test_fail "rc_ga=$rc_ga prev_ga=$_prev_on_ga rc_next=$rc_next prev_next=$_prev_on_next"

test_start "rollback: 6000001 -> 6009303 -> 6009304 (v6.1.0-rc.4) 连刷保护黄金底包并支持异常回退与 6010000 接班"
rbseed 6009303 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.3\nversionCode=6009303\n' > "$MOD/module.prop"
echo "GOLDEN-BIN-v601" > "$HNC/bin/hnc_watchdog"
echo "GOLDEN-HTTPD-v601" > "$HNC/daemon/hnc_httpd/hnc_httpd"
echo "GOLDEN-WEB-v601" > "$HNC/webroot/index.html"
rbrun snapshot "$MOD" "$HNC"; rc_r3s=$?
rm -f "$HNC/data/rollback.observing"
echo "RC3-BIN" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.4\nversionCode=6009304\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_r4s=$?
_prev_after_rc4="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
echo "RC4-BROKEN-BIN" > "$HNC/bin/hnc_watchdog"
i=0; r_rc4_obs=0
while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; r_rc4_obs=$?; i=$((i+1)); done
[ "$rc_r3s" -eq 0 ] && [ "$rc_r4s" -eq 0 ] \
  && [ "$_prev_after_rc4" = "6000001" ] \
  && [ "$r_rc4_obs" -eq 9 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null)" = "GOLDEN-BIN-v601" ] \
  && [ "$(cat "$HNC/data/runtime_version" 2>/dev/null | tr -d ' \r\n')" = "6000001" ] \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = "6009304" ] \
  && grep -q '"from":"6009304","to":"6000001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "r3=$rc_r3s r4=$rc_r4s prev4=$_prev_after_rc4 obs=$r_rc4_obs bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: 6000001 -> 6009309 -> 6009310 (v6.1.0-rc.10) 连刷保护黄金底包并支持异常回退与 6010000 接班"
rbseed 6009309 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.9\nversionCode=6009309\n' > "$MOD/module.prop"
echo "GOLDEN-BIN-v601" > "$HNC/bin/hnc_watchdog"
echo "GOLDEN-HTTPD-v601" > "$HNC/daemon/hnc_httpd/hnc_httpd"
echo "GOLDEN-WEB-v601" > "$HNC/webroot/index.html"
rbrun snapshot "$MOD" "$HNC"; rc_r9b=$?
rm -f "$HNC/data/rollback.observing"
echo "RC9-BIN" > "$HNC/bin/hnc_watchdog"
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.10\nversionCode=6009310\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC"; rc_r10s=$?
_prev_after_rc10="$(cat "$HNC/.prev/version" 2>/dev/null | tr -d ' \r\n')"
echo "RC10-BROKEN-BIN" > "$HNC/bin/hnc_watchdog"
i=0; r_rc10_obs=0
while [ $i -lt 6 ]; do rbrun observe "$HNC" >/dev/null 2>&1; r_rc10_obs=$?; i=$((i+1)); done
[ "$rc_r9b" -eq 0 ] && [ "$rc_r10s" -eq 0 ] \
  && [ "$_prev_after_rc10" = "6000001" ] \
  && [ "$r_rc10_obs" -eq 9 ] \
  && [ "$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null)" = "GOLDEN-BIN-v601" ] \
  && [ "$(cat "$HNC/data/runtime_version" 2>/dev/null | tr -d ' \r\n')" = "6000001" ] \
  && [ "$(cat "$HNC/data/rollback.pinned" 2>/dev/null | tr -d ' \r\n')" = "6009310" ] \
  && grep -q '"from":"6009310","to":"6000001"' "$HNC/data/rollback.json" \
  && test_pass || test_fail "r9=$rc_r9b r10=$rc_r10s prev10=$_prev_after_rc10 obs=$r_rc10_obs bin=$(cat "$HNC/bin/hnc_watchdog" 2>/dev/null) json=$(cat "$HNC/data/rollback.json" 2>/dev/null)"

test_start "rollback: C005 单调观察窗防 NTP 跳变击穿 + 兼容旧单字段格式"
rbseed 6009310 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.10\nversionCode=6009310\n' > "$MOD/module.prop"
HNC_RB_NOW_OVERRIDE=1700000000 HNC_RB_UPTIME_OVERRIDE=12.34 HNC_RB_BOOT_ID_OVERRIDE="boot-uuid-a1" \
    rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
_obs_saved="$(cat "$HNC/data/rollback.observing" 2>/dev/null | tr -d '\r\n')"
# NTP 挂钟向前暴跳 +95000000s, 但同 boot_id 下单调秒仅推进 45s (<600) -> 严禁提前清观察窗
HNC_RB_NOW_OVERRIDE=1795000000 HNC_RB_UPTIME_OVERRIDE=57.89 HNC_RB_BOOT_ID_OVERRIDE="boot-uuid-a1" \
    rbrun observe "$HNC" >/dev/null 2>&1
_still_obs=0; [ -f "$HNC/data/rollback.observing" ] && _still_obs=1
_streak_after_ntp="$(cat "$HNC/data/rollback.failstreak" 2>/dev/null | tr -d ' \r\n')"
# 单调秒推进至 615s (615 - 12 = 603 >= 600), 即使挂钟回调小于 600 也准时结束观察窗
HNC_RB_NOW_OVERRIDE=1700000100 HNC_RB_UPTIME_OVERRIDE=615.00 HNC_RB_BOOT_ID_OVERRIDE="boot-uuid-a1" \
    rbrun observe "$HNC" >/dev/null 2>&1
_closed_mono=0; [ ! -f "$HNC/data/rollback.observing" ] && _closed_mono=1
# 旧单字段格式无缝回退挂钟差
echo "1700000000" > "$HNC/data/rollback.observing"
HNC_RB_NOW_OVERRIDE=1700000605 rbrun observe "$HNC" >/dev/null 2>&1
_closed_legacy=0; [ ! -f "$HNC/data/rollback.observing" ] && _closed_legacy=1
[ "$_obs_saved" = "1700000000 12 boot-uuid-a1" ] && [ "$_still_obs" -eq 1 ] && [ "$_streak_after_ntp" = "1" ] \
  && [ "$_closed_mono" -eq 1 ] && [ "$_closed_legacy" -eq 1 ] \
  && test_pass || test_fail "obs=[$_obs_saved] still=$_still_obs streak=$_streak_after_ntp mono=$_closed_mono legacy=$_closed_legacy"

test_start "rollback: C007 回滚核验 cmdline/comm 停止核心守护进程且不误杀复用 PID"
rbseed 6009310 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.10\nversionCode=6009310\n' > "$MOD/module.prop"
rbrun snapshot "$MOD" "$HNC" >/dev/null 2>&1
FPROC="$HNC_TEST_DIR/fake_proc"
mkdir -p "$FPROC"
sleep 30 &
_real_dpid=$!
sleep 30 &
_reused_sys=$!
mkdir -p "$FPROC/$_real_dpid" "$FPROC/$_reused_sys"
printf '/data/local/hnc/bin/hnc_dpid\000-config\000' > "$FPROC/$_real_dpid/cmdline"
printf 'hnc_dpid\n' > "$FPROC/$_real_dpid/comm"
printf 'system_server\000' > "$FPROC/$_reused_sys/cmdline"
printf 'system_server\n' > "$FPROC/$_reused_sys/comm"
echo "$_real_dpid" > "$HNC/run/dpid.pid"
echo "$_reused_sys" > "$HNC/run/hotspotd.pid"
i=0
while [ $i -lt 6 ]; do
    HNC_PROC_ROOT="$FPROC" rbrun observe "$HNC" >/dev/null 2>&1
    i=$((i+1))
done
wait "$_real_dpid" 2>/dev/null || true
_dpid_dead=0; kill -0 "$_real_dpid" 2>/dev/null || _dpid_dead=1
_sys_alive=0; kill -0 "$_reused_sys" 2>/dev/null && _sys_alive=1
kill "$_reused_sys" 2>/dev/null || true
wait "$_reused_sys" 2>/dev/null || true
[ "$_dpid_dead" -eq 1 ] && [ "$_sys_alive" -eq 1 ] \
  && [ ! -f "$HNC/run/dpid.pid" ] && [ ! -f "$HNC/run/hotspotd.pid" ] \
  && test_pass || test_fail "dpid_dead=$_dpid_dead sys_alive=$_sys_alive"

test_start "rollback: C008 升级新包 v6.1.0-rc.10 (6009310) 解钉时自动清理陈旧 rollback.json 与 rollback.ack"
rbseed 6009310 6000001
printf 'id=hotspot_net_ctl\nversion=v6.1.0-rc.10\nversionCode=6009310\n' > "$MOD/module.prop"
echo "6009309" > "$HNC/data/rollback.pinned"
printf '{"from":"6009309","to":"6000001","reason":"failstreak=6","at":1795430000,"action":"rolled_back"}\n' > "$HNC/data/rollback.json"
: > "$HNC/data/rollback.ack"
rbrun snapshot "$MOD" "$HNC"; rc_c8=$?
[ "$rc_c8" -eq 0 ] && [ ! -f "$HNC/data/rollback.pinned" ] \
  && [ ! -f "$HNC/data/rollback.json" ] && [ ! -f "$HNC/data/rollback.ack" ] \
  && test_pass || test_fail "rc=$rc_c8 files=$(ls "$HNC/data" 2>/dev/null | tr '\n' ' ')"

if [ "$_RB_STANDALONE" = "1" ]; then
    teardown_test_env
    echo "summary: total=$TEST_TOTAL pass=$TEST_PASS fail=$TEST_FAIL"
    [ "$TEST_FAIL" -eq 0 ] || exit 1
    exit 0
fi
