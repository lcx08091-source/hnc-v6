#!/system/bin/sh
# test/unit/test_v520_qdisc_precision.sh — v5.20
#   A. 低延迟 qdisc 兜底链: bin/qdisc_caps.sh 选择器(mock tc/ip/modprobe/insmod)+
#      tc_manager 按 chosen 下发叶子 / 默认叶子 AQM 开关
#   B. 限速精度: calc_class_args 参数表(rate/ceil/burst/quantum)+ 校准比例语义
#   C. 应用限速跳过共享 CDN IP(与 daemon/hnc_httpd/app_limit_shared_test.go 同一组数据)

QC="$HNC_REPO_ROOT/bin/qdisc_caps.sh"
TCM="$HNC_REPO_ROOT/bin/tc_manager.sh"

# ─── qdisc_caps mock 环境 ─────────────────────────────────────
# MOCK_QC_OK="sfq pfifo"         tc 探测直接成功的 qdisc
# MOCK_QC_MODPROBE_OK="sch_x"    modprobe 能加载的模块(加载后对应 qdisc 探测成功)
# MOCK_QC_INSMOD_OK="sch_x"      insmod <dir>/sch_x.ko 能加载的模块
qc_mock_setup() {
    QCM="$HNC_TEST_DIR/qcmock"
    mkdir -p "$QCM/state" "$QCM/mods"
    : > "$QCM/calls.log"
    cat > "$QCM/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$QCM_DIR/calls.log"
case "$*" in
    *"qdisc replace dev "*" root "*|*"qdisc add dev "*" root "*)
        kind=$(echo "$*" | sed -n 's/.* root \(handle [^ ]* \)\{0,1\}\([a-z_]*\).*/\2/p')
        mod=""
        case "$kind" in cake) mod=sch_cake ;; fq_codel) mod=sch_fq_codel ;; fq) mod=sch_fq ;; sfq) mod=sch_sfq ;; esac
        case " $MOCK_QC_OK " in *" $kind "*) exit 0 ;; esac
        [ -n "$mod" ] && [ -f "$QCM_DIR/state/$mod" ] && exit 0
        echo "Error: Specified qdisc kind is unknown." >&2
        exit 2 ;;
esac
exit 0
EOF
    cat > "$QCM/ip" <<'EOF'
#!/bin/sh
echo "ip|$*" >> "$QCM_DIR/calls.log"
exit 0
EOF
    cat > "$QCM/modprobe" <<'EOF'
#!/bin/sh
echo "modprobe|$*" >> "$QCM_DIR/calls.log"
for a in "$@"; do m=$a; done
case " $MOCK_QC_MODPROBE_OK " in *" $m "*) : > "$QCM_DIR/state/$m"; exit 0 ;; esac
echo "modprobe: FATAL: Module $m not found" >&2
exit 1
EOF
    cat > "$QCM/insmod" <<'EOF'
#!/bin/sh
echo "insmod|$*" >> "$QCM_DIR/calls.log"
m=$(basename "$1" .ko)
case " $MOCK_QC_INSMOD_OK " in *" $m "*) : > "$QCM_DIR/state/$m"; exit 0 ;; esac
echo "insmod: failed to load $1: Operation not permitted" >&2
exit 1
EOF
    chmod +x "$QCM/tc" "$QCM/ip" "$QCM/modprobe" "$QCM/insmod"
    : > "$QCM/proc_modules"
    export QCM_DIR="$QCM"
}
qc_run() {
    HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 HNC_SKIP_PATH_HARDENING=1 \
        TC_BIN="$QCM/tc" IP_BIN="$QCM/ip" MODPROBE_BIN="$QCM/modprobe" INSMOD_BIN="$QCM/insmod" \
        QDISC_CAPS_MODULE_DIRS="$QCM/mods" QDISC_CAPS_PROC_MODULES="$QCM/proc_modules" \
        QDISC_CAPS_BOOT_ID="${QC_BOOT:-boot-1}" QDISC_CAPS_NOW=1700000000 \
        sh "$QC" "$@"
}
qc_json() { cat "$HNC_TEST_DIR/run/qdisc_caps.json" 2>/dev/null; }
qc_unset() { unset MOCK_QC_OK MOCK_QC_MODPROBE_OK MOCK_QC_INSMOD_OK QCM_DIR QC_BOOT; }

test_start "qdisc_caps: 全部可用 → chosen=cake, 不碰内核模块, 探测设备被清理"
qc_mock_setup
export MOCK_QC_OK="cake fq_codel fq sfq pfifo"
out=$(qc_run probe)
j=$(qc_json)
assert_eq "cake" "$out" "stdout 应为 chosen" && \
    assert_json_valid "$HNC_TEST_DIR/run/qdisc_caps.json" && \
    assert_contains "$j" '"chosen": "cake"' && \
    assert_contains "$j" '"available": ["cake","fq_codel","fq","sfq","pfifo"]' && \
    assert_contains "$j" '"default_leaf_aqm_eligible": true' && \
    assert_not_contains "$(cat "$QCM/calls.log")" "modprobe|" "有 cake 时不应加载模块" && \
    assert_contains "$(cat "$QCM/calls.log")" "ip|link del hnc_q_" "一次性 dummy 必须删除" && test_pass
qc_unset

test_start "qdisc_caps: 内核缺 cake/fq_codel, modprobe sch_fq_codel 成功 → chosen=fq_codel"
qc_mock_setup
export MOCK_QC_OK="sfq pfifo" MOCK_QC_MODPROBE_OK="sch_fq_codel"
out=$(qc_run probe)
j=$(qc_json)
assert_eq "fq_codel" "$out" && \
    assert_json_valid "$HNC_TEST_DIR/run/qdisc_caps.json" && \
    assert_contains "$j" '{"name":"fq_codel","method":"modprobe","ok":true,"err":""}' "tried 应记录 modprobe 成功" && \
    assert_contains "$j" '{"name":"cake","method":"modprobe","ok":false' "tried 应记录 cake modprobe 失败" && \
    assert_contains "$j" '"loaded_modules": ["sch_fq_codel"]' && \
    assert_contains "$j" '"available": ["fq_codel","sfq","pfifo"]' && \
    assert_not_contains "$(cat "$QCM/calls.log")" "modprobe|sch_sfq" "已选出 fq_codel 后不应再加载更差档位模块" && test_pass
qc_unset

test_start "qdisc_caps: modprobe 失败, insmod <dir>/sch_cake.ko 成功 → chosen=cake"
qc_mock_setup
export MOCK_QC_OK="sfq pfifo" MOCK_QC_INSMOD_OK="sch_cake"
: > "$QCM/mods/sch_cake.ko"
out=$(qc_run probe)
j=$(qc_json)
assert_eq "cake" "$out" && \
    assert_contains "$j" '"method":"insmod","ok":true' && \
    assert_contains "$j" "\"path\":\"$QCM/mods/sch_cake.ko\"" && \
    assert_contains "$(cat "$QCM/calls.log")" "insmod|$QCM/mods/sch_cake.ko" && test_pass
qc_unset

test_start "qdisc_caps: 什么都加载不了 → chosen=sfq, reason 说明原因, chain 只剩 sfq"
qc_mock_setup
export MOCK_QC_OK="sfq pfifo"
out=$(qc_run probe)
j=$(qc_json)
chain=$(qc_run chain)
assert_eq "sfq" "$out" && \
    assert_contains "$j" '"aqm": true' && \
    assert_contains "$j" '"default_leaf_aqm_eligible": false' && \
    assert_contains "$j" 'unavailable: cake(' "reason 应列出不可用的档位" && \
    assert_eq "sfq" "$chain" "chain 从 chosen 起" && test_pass
qc_unset

test_start "qdisc_caps: 同一次开机不重复尝试模块加载(--force 例外)"
qc_mock_setup
export MOCK_QC_OK="sfq pfifo"
qc_run probe >/dev/null
: > "$QCM/calls.log"
qc_run probe >/dev/null
j=$(qc_json)
assert_not_contains "$(cat "$QCM/calls.log")" "modprobe|" "同 boot_id 第二次不应 modprobe" && \
    assert_contains "$j" '"module_load_attempted": false' && \
    assert_contains "$j" 'skipped: already attempted this boot' || { qc_unset; true; }
if [ -n "$QCM_DIR" ]; then
    : > "$QCM/calls.log"
    qc_run probe --force >/dev/null
    assert_contains "$(cat "$QCM/calls.log")" "modprobe|sch_cake" "--force 应重新尝试" && test_pass
fi
qc_unset

test_start "qdisc_caps: 连 pfifo 都探测失败 → chosen 为空, chain 回落完整链, 仍 exit 0"
qc_mock_setup
export MOCK_QC_OK=""
out=$(qc_run probe); rc=$?
chain=$(qc_run chain)
assert_eq "0" "$rc" "绝不大声失败" && \
    assert_eq "none" "$out" && \
    assert_contains "$(qc_json)" '"chosen": ""' && \
    assert_eq "cake fq_codel fq sfq" "$chain" && test_pass
qc_unset

# ─── tc_manager 消费 qdisc_caps ─────────────────────────────────
tcm() { HNC_DIR="$HNC_TEST_DIR" sh "$TCM" "$@"; }
write_caps() { printf '{"schema":1,"chosen":"%s","available":[]}\n' "$1" > "$HNC_TEST_DIR/run/qdisc_caps.json"; }
TC_TREE="qdisc htb 1: root refcnt 2 r2q 10 default 0x9999
class htb 1:1 root rate 1Gbit ceil 1Gbit
class htb 1:5 parent 1:1 leaf 1005: prio 0 rate 1Gbit
class htb 1:9999 parent 1:1 leaf 9999: prio 0 rate 1Gbit"

test_start "tc_manager qdisc_caps: chosen=fq_codel → 默认叶子 AQM 开; tc_leaf_aqm=off 覆盖"
mock_setup
write_caps fq_codel
o1=$(tcm qdisc_caps)
echo off > "$HNC_TEST_DIR/run/tc_leaf_aqm"
o2=$(tcm qdisc_caps)
assert_contains "$o1" "chain=fq_codel,fq,sfq" && \
    assert_contains "$o1" "default_leaf_aqm=true" && \
    assert_contains "$o2" "tc_leaf_aqm=off" && \
    assert_contains "$o2" "default_leaf_aqm=false" && test_pass
mock_teardown

test_start "tc_manager qdisc_caps: chosen=sfq(auto)→ 默认叶子保持 netem; 无 json → 完整链"
mock_setup
write_caps sfq
o1=$(tcm qdisc_caps)
rm -f "$HNC_TEST_DIR/run/qdisc_caps.json"
o2=$(tcm qdisc_caps)
assert_contains "$o1" "default_leaf_aqm=false" && \
    assert_contains "$o1" "chain=sfq " && \
    assert_contains "$o2" "chain=cake,fq_codel,fq,sfq" && test_pass
mock_teardown

test_start "set_sqm on: chosen=sfq → 只下发 sfq, 不试 cake/fq_codel, 输出 SQM_QDISC=sfq"
mock_setup
mock_set_stdout tc "$TC_TREE"
write_caps sfq
out=$(tcm set_sqm wlan2 5 on 192.168.43.5 2>/dev/null)
assert_mock_called "parent 1:5 handle 1005: sfq perturb 10" && \
    assert_mock_not_called "handle 1005: cake" && \
    assert_mock_not_called "handle 1005: fq_codel" && \
    assert_contains "$out" "SQM_QDISC=sfq" && test_pass
mock_teardown

test_start "set_sqm on: chosen=cake → cake besteffort 叶子"
mock_setup
mock_set_stdout tc "$TC_TREE"
write_caps cake
out=$(tcm set_sqm wlan2 5 on 192.168.43.5 2>/dev/null)
assert_mock_called "handle 1005: cake besteffort" && \
    assert_contains "$out" "SQM_QDISC=cake" && test_pass
mock_teardown

test_start "set_limit: tc_leaf_aqm auto + chosen=fq_codel → 设备叶子 fq_codel 而非 netem 占位"
mock_setup
mock_set_stdout tc "$TC_TREE"
write_caps fq_codel
tcm set_limit wlan2 5 10 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "parent 1:5 handle 1005: fq_codel target 5ms" && \
    assert_mock_not_called "parent 1:5 handle 1005: netem" && test_pass
mock_teardown

test_start "set_limit: tc_leaf_aqm=off → 保持旧 netem-0ms 占位"
mock_setup
mock_set_stdout tc "$TC_TREE"
write_caps fq_codel
echo '{"devices":{},"tc_leaf_aqm":"off"}' > "$HNC_TEST_DIR/data/rules.json"
tcm set_limit wlan2 5 10 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "parent 1:5 handle 1005: netem delay 0ms" && \
    assert_mock_not_called "handle 1005: fq_codel" && test_pass
mock_teardown

test_start "set_delay 真实延迟: 即使默认叶子 AQM 开也必须用 netem"
mock_setup
mock_set_stdout tc "$TC_TREE"
write_caps fq_codel
tcm set_delay wlan2 5 80 0 0 192.168.43.5 >/dev/null 2>&1
# ensure_device_class 可能先放默认叶子, 但最后一次落在 1005: 上的必须是 netem
last=$(grep 'handle 1005: ' "$MOCK_LOG" | tail -1)
assert_mock_called "handle 1005: netem delay 40ms" "RTT 80 → 下行 40ms netem" && \
    assert_contains "$last" "netem delay 40ms" "最终叶子必须是 netem" && test_pass
mock_teardown

# ─── B. 限速参数表 ──────────────────────────────────────────────
# 行格式: <mbps> <mode> <rate> <burst> <quantum>
RATE_TABLE="0.064 compat 64kbit 3k 1514
0.1 compat 100kbit 3k 1514
0.5 compat 500kbit 8k 6250
1 compat 1000kbit 16k 12500
2 compat 2000kbit 16k 25000
10 compat 10000kbit 25k 60000
50 compat 50000kbit 125k 60000
99 compat 99000kbit 248k 60000
100 compat 100000kbit 250k 60000
300 compat 300000kbit 750k 60000
999 compat 999000kbit 2498k 60000
1000 compat 1000000kbit 200k 60000
0.1 precise 100kbit 3k 1514
0.5 precise 500kbit 4k 6250
1 precise 1000kbit 8k 12500
10 precise 10000kbit 10k 60000
99 precise 99000kbit 64k 60000
150 precise 150000kbit 200k 60000
300 precise 300000kbit 300k 60000
1000 precise 1000000kbit 200k 60000"

test_start "calc_class_args: rate/ceil/burst/quantum 参数表(compat + precise, 0.064~1000 Mbps)"
mock_setup
bad=""
echo "$RATE_TABLE" | while read -r mbps mode rate burst quantum; do
    echo "$mode" > "$HNC_TEST_DIR/run/tc_qos_mode"
    got=$(tcm calc_class_args "$mbps" down)
    want="rate=$rate ceil=$rate burst=$burst cburst=$burst quantum=$quantum scale=100 root_fallback=false qos_mode=$mode"
    case "$got" in *"$want"*) ;; *) echo "$mbps/$mode: got [$got] want [$want]" ;; esac
done > "$HNC_TEST_DIR/table.err"
bad=$(cat "$HNC_TEST_DIR/table.err")
assert_eq "" "$bad" "参数表不匹配" && test_pass
mock_teardown

test_start "burst 窗口: 1~100Mbps 与 v5.19 旧算法一致(compat 2.5k/Mbps, 下限 16k)"
mock_setup
bad=""
for v in 1 2 6 7 10 40 64 80 99; do
    old=$(awk -v v="$v" 'BEGIN{b=int(v*2.5); if(b<16)b=16; if(b>256)b=256; print b}')
    new=$(tcm calc_class_args "$v" down | sed -n 's/.* burst=\([0-9]*\)k .*/\1/p')
    d=$((new - old)); [ "$d" -lt 0 ] && d=$((-d))
    [ "$d" -le 1 ] || bad="$bad $v:old=$old,new=$new"
done
assert_eq "" "$bad" "1~100Mbps 不应偏离旧 burst(仅 ±1k 取整差)" && test_pass
mock_teardown

test_start "set_limit 下发显式 quantum, ceil=rate"
mock_setup
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 5 300 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "classid 1:5 htb rate 300000kbit ceil 300000kbit burst 750k cburst 750k quantum 60000" && test_pass
mock_teardown

test_start "set_limit: tc 拒绝 quantum 时退回旧参数(不带 quantum)"
mock_setup
cat > "$MOCK_BIN_DIR/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$MOCK_LOG"
case "$*" in *" quantum "*" 60000"*|*"quantum 60000"*) exit 1 ;; esac
[ -n "$MOCK_STDOUT_tc" ] && printf '%s\n' "$MOCK_STDOUT_tc"
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/tc"
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 5 300 0 192.168.43.5 >/dev/null 2>&1; rc=$?
assert_eq "0" "$rc" "quantum 被拒不能让限速失败" && \
    assert_mock_called "classid 1:5 htb rate 300000kbit ceil 300000kbit burst 750k cburst 750k" && test_pass
mock_teardown

# ─── 校准比例(tc_qos_scale 100/85/75)语义 ──────────────────────
test_start "校准比例: 非 root-HTB 兜底时即使存了 75 也不缩放"
mock_setup
echo 75 > "$HNC_TEST_DIR/run/tc_qos_scale"
out=$(tcm calc_class_args 10 down)
assert_contains "$out" "effective_mbps=10.000000 rate=10000kbit" && \
    assert_contains "$out" "scale=100 root_fallback=false" && test_pass
mock_teardown

test_start "校准比例: root-HTB 兜底 + 保存 75 → 下行 10M 实下 7.5M"
mock_setup
echo root_htb > "$HNC_TEST_DIR/run/tc_qos_fallback"
echo 75 > "$HNC_TEST_DIR/run/tc_qos_scale"
out=$(tcm calc_class_args 10 down)
assert_contains "$out" "effective_mbps=7.500000 rate=7500kbit" && \
    assert_contains "$out" "scale=75 root_fallback=true" && test_pass
mock_teardown

test_start "校准比例: root-HTB 兜底 + precise + 未保存 → 默认 85"
mock_setup
echo root_htb > "$HNC_TEST_DIR/run/tc_qos_fallback"
echo precise > "$HNC_TEST_DIR/run/tc_qos_mode"
out=$(tcm calc_class_args 10 down)
assert_contains "$out" "effective_mbps=8.500000 rate=8500kbit" && \
    assert_contains "$out" "scale=85" && test_pass
mock_teardown

test_start "校准比例: 上行永不缩放; 越界值夹到 50"
mock_setup
echo root_htb > "$HNC_TEST_DIR/run/tc_qos_fallback"
echo 30 > "$HNC_TEST_DIR/run/tc_qos_scale"
up=$(tcm calc_class_args 10 up)
dn=$(tcm calc_class_args 10 down)
assert_contains "$up" "effective_mbps=10.000000 rate=10000kbit" && \
    assert_contains "$dn" "effective_mbps=5.000000 rate=5000kbit" && \
    assert_contains "$dn" "scale=50" && test_pass
mock_teardown

# ─── C. 应用限速跳过共享 CDN IP ────────────────────────────────
seed_app_limits() {
    echo "wlan2" > "$HNC_TEST_DIR/run/active_iface"
    printf '%s\n%s\n' "aa:bb:cc:dd:ee:01 douyin 2" "aa:bb:cc:dd:ee:01 bilibili 1" > "$HNC_TEST_DIR/data/app_limits.flat"
    printf '1.1.1.1 douyin\n2.2.2.2 douyin\n3.3.3.3 douyin\n1.1.1.1 douyin\n5.5.5.5 bilibili\n' > "$HNC_TEST_DIR/run/ip_app_map.flat"
    echo '{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.9","status":"allowed"}}' > "$HNC_TEST_DIR/data/devices.json"
    cat > "$HNC_TEST_DIR/run/dpi_ipname.json" <<'EOF'
{"schema":1,"generated_at":1,"entries":{"1.1.1.1":{"name":"v1.douyinvod.com","src":"sni","ts":1,"app":"douyin","app_name":"抖音","category":"video"},"2.2.2.2":{"name":"x.akamaized.net","src":"dns","ts":1,"app":"akamai_cdn","app_name":"Akamai CDN","category":"cdn"},"5.5.5.5":{"name":"a.weixin.qq.com","src":"dns","ts":1,"app":"weixin","category":"social"}}}
EOF
}
run_aal() { HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1; }

test_start "apply_app_limits: 反查到其他应用/CDN 的 IP 不打 mark, 统计写入 ipstats"
mock_setup
seed_app_limits
echo '{"devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
run_aal
st=$(cat "$HNC_TEST_DIR/run/app_limits_ipstats.flat" 2>/dev/null)
assert_mock_called "43.9 -s 1.1.1.1 -j MARK" && \
    assert_mock_called "43.9 -s 3.3.3.3 -j MARK" && \
    assert_mock_not_called "2.2.2.2" "akamai_cdn 共享 IP 不能被限速" && \
    assert_mock_not_called "5.5.5.5" "反查为微信的 IP 不能算给 bilibili" && \
    assert_contains "$st" "aa:bb:cc:dd:ee:01 douyin 3 1 2" && \
    assert_contains "$st" "aa:bb:cc:dd:ee:01 bilibili 1 1 0" && \
    assert_contains "$(cat "$HNC_TEST_DIR/logs/app_limits.log")" "all 1 IP(s) are shared" && test_pass
mock_teardown

test_start "apply_app_limits: 逃生口 app_limit_include_shared_ips=true → 共享 IP 照旧限速"
mock_setup
seed_app_limits
echo '{"devices":{},"app_limit_include_shared_ips":true}' > "$HNC_TEST_DIR/data/rules.json"
run_aal
assert_mock_called "43.9 -s 2.2.2.2 -j MARK" && \
    assert_mock_called "43.9 -s 5.5.5.5 -j MARK" && \
    assert_contains "$(cat "$HNC_TEST_DIR/run/app_limits_ipstats.flat")" "douyin 3 0 3" && test_pass
mock_teardown

test_start "apply_app_limits: 无反查表时不误判, 应用 class 用共享算法的 burst/quantum"
mock_setup
seed_app_limits
rm -f "$HNC_TEST_DIR/run/dpi_ipname.json"
run_aal
assert_mock_called "43.9 -s 2.2.2.2 -j MARK" && \
    assert_mock_called "classid 1:9001 htb rate 2000kbit ceil 2000kbit burst 16k cburst 16k quantum 25000" && \
    assert_mock_called "classid 1:9002 htb rate 1000kbit ceil 1000kbit burst 16k cburst 16k quantum 12500" && test_pass
mock_teardown
