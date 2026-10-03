#!/system/bin/sh
# v5.22 功耗: bin/hnc_activity.sh(run/activity.json 读取器)+ offload guard 空闲放慢

ACT_LIB="$HNC_REPO_ROOT/bin/hnc_activity.sh"
GSCRIPT="$HNC_REPO_ROOT/bin/hnc_offload_guard.sh"

# 写一行 activity.json(字段顺序与 httpd Activity 结构一致)
# $1 ts $2 level $3 screen_on $4 screen_known $5 hotspot_active $6 clients $7 webui
act_write() {
    printf '{"ts":%s,"level":"%s","screen_on":%s,"screen_known":%s,"screen_source":"backlight","hotspot_active":%s,"hotspot_iface":"wlan2","clients_online":%s,"webui_active":%s,"sse_clients":0,"last_api_ago_s":-1,"ct_precise":true,"known":true}\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" > "$HNC_TEST_DIR/run/activity.json"
}

test_start "activity: 解析 + 新鲜度 + quiet"
NOW=$(date +%s)
act_write "$NOW" hotspot_off false true false 0 false
r=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; echo "$ACT_OK $ACT_LEVEL $ACT_SCREEN_OFF $ACT_SCREEN_ON $ACT_HOTSPOT $ACT_CLIENTS $ACT_WEBUI"; hnc_act_quiet && echo quiet' _ "$ACT_LIB" "$NOW")
exp="1 hotspot_off 1 0 0 0 0
quiet"
[ "$r" = "$exp" ] && test_pass || test_fail "got [$r]"

test_start "activity: 过期 / 缺文件 / 坏文件 → ACT_OK=0 且保守(视为热点开、有设备、有界面)"
NOW=$(date +%s)
act_write $((NOW - 600)) hotspot_off false true false 0 false
r1=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; echo "$ACT_OK"' _ "$ACT_LIB" "$NOW")
rm -f "$HNC_TEST_DIR/run/activity.json"
r2=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; echo "$? $ACT_OK $ACT_HOTSPOT $ACT_CLIENTS $ACT_WEBUI"' _ "$ACT_LIB" "$NOW")
echo 'garbage' > "$HNC_TEST_DIR/run/activity.json"
r3=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; echo "$? $ACT_OK"' _ "$ACT_LIB" "$NOW")
act_write $((NOW + 3600)) no_clients true true true 0 false
r4=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; echo "$ACT_OK"' _ "$ACT_LIB" "$NOW")
[ "$r1" = 0 ] && [ "$r2" = "1 0 1 1 1" ] && [ "$r3" = "1 0" ] && [ "$r4" = 0 ] && test_pass || test_fail "r1=$r1 r2=$r2 r3=$r3 r4=$r4"

test_start "activity: 亮屏 / 界面在看 → 不 quiet; 屏幕未知 → 既不算亮也不算灭"
NOW=$(date +%s)
act_write "$NOW" background true true true 2 false
a=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; hnc_act_quiet && echo q || echo n; echo "$ACT_SCREEN_ON $ACT_CLIENTS"' _ "$ACT_LIB" "$NOW" | tr '\n' ' ')
act_write "$NOW" active false true true 2 true
b=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; hnc_act_quiet && echo q || echo n' _ "$ACT_LIB" "$NOW")
act_write "$NOW" active false false true 2 false
c=$(HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_load "$2"; hnc_act_quiet && echo q || echo n; echo "$ACT_SCREEN_OFF$ACT_SCREEN_ON"' _ "$ACT_LIB" "$NOW" | tr '\n' ' ')
[ "$a" = "n 1 2 " ] && [ "$b" = n ] && [ "$c" = "n 00 " ] && test_pass || test_fail "a=[$a] b=[$b] c=[$c]"

test_start "activity: hnc_act_sleep_until 热点一起来就提前返回"
NOW=$(date +%s)
act_write "$NOW" hotspot_off false true false 0 false
( sleep 1; act_write "$NOW" no_clients false true true 0 false ) &
t0=$(date +%s)
HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_sleep_until 6 1 hotspot' _ "$ACT_LIB"
rc=$?
t1=$(date +%s)
wait
# clients 条件: 热点开了但没设备 → 不提前, 睡满
HNC_DIR="$HNC_TEST_DIR" sh -c '. "$1"; hnc_act_sleep_until 2 1 clients' _ "$ACT_LIB"
rc2=$?
[ "$rc" = 0 ] && [ $((t1 - t0)) -le 4 ] && [ "$rc2" = 1 ] && test_pass || test_fail "rc=$rc dt=$((t1 - t0)) rc2=$rc2"

# ── offload guard: 空闲放慢(plan 子命令) ───────────────────────────
gseed() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs" "$HNC_TEST_DIR/bin" "$HNC_TEST_DIR/sysnet/wlan2"
    echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
    printf '%s\n' "${1:-{\"devices\":{}}}" > "$HNC_TEST_DIR/data/rules.json"
    echo IDLE > "$HNC_TEST_DIR/check_state"
    cat > "$HNC_TEST_DIR/bin/hnc_ipc" <<'STUB'
#!/bin/sh
echo "OK:OK"
STUB
    chmod +x "$HNC_TEST_DIR/bin/hnc_ipc"
}
grun() {
    HNC_TEST_MODE=1 HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" \
    HNC_GUARD_CHECK_CMD="cat $HNC_TEST_DIR/check_state" sh "$GSCRIPT" "$@" 2>/dev/null
}

test_start "offload guard plan: 热点开 + 有设备 → 60s(不放慢)"
gseed
act_write "$(date +%s)" background false true true 2 false
p=$(grun plan)
[ "$p" = "60 none" ] && test_pass || test_fail "plan=$p"

test_start "offload guard plan: 无在线设备且未兜底 → 300s, 有设备就早醒"
gseed
act_write "$(date +%s)" no_clients true true true 0 false
p=$(grun plan)
[ "$p" = "300 clients" ] && test_pass || test_fail "plan=$p"

test_start "offload guard plan: 兜底中(ACTIVE)即使无设备也保持 60s 重申"
gseed
act_write "$(date +%s)" no_clients true true true 0 false
echo ACTIVE > "$HNC_TEST_DIR/check_state"
p=$(grun plan)
[ "$p" = "60 none" ] && test_pass || test_fail "plan=$p"

test_start "offload guard plan: activity 过期/缺失 → 60s(httpd 不在时不冒险放慢)"
gseed
act_write $(( $(date +%s) - 3600 )) hotspot_off false true false 0 false
p1=$(grun plan)
rm -f "$HNC_TEST_DIR/run/activity.json"
p2=$(grun plan)
[ "$p1" = "60 none" ] && [ "$p2" = "60 none" ] && test_pass || test_fail "p1=$p1 p2=$p2"

test_start "offload guard plan: on 模式 + 热点未开 → 300s, 热点一开就早醒"
gseed '{"clsact_bpf_mode":"on"}'
rm -rf "$HNC_TEST_DIR/sysnet/wlan2"
act_write "$(date +%s)" hotspot_off false true false 0 false
p=$(grun plan)
[ "$p" = "300 hotspot" ] && test_pass || test_fail "plan=$p"

test_start "watchdog/dpid guard: 引入 hnc_activity.sh 且 sh -n 通过"
ok=1
for f in watchdog.sh hnc_offload_guard.sh hnc_dpid_guard.sh hnc_activity.sh; do
    sh -n "$HNC_REPO_ROOT/bin/$f" 2>/dev/null || ok=0
done
grep -q 'hnc_activity.sh' "$HNC_REPO_ROOT/bin/watchdog.sh" || ok=0
grep -q 'hnc_activity.sh' "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" || ok=0
# v5.26 T1: shell 主循环已删, 改查 Go 版 power.go 的 intervalIdleProbe。
grep -q 'intervalIdleProbe' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/power.go" || ok=0
[ "$ok" = 1 ] && test_pass || test_fail "syntax/wiring"
