#!/system/bin/sh
# test/unit/test_v530_app_qos.sh — v5.30 T4: 应用感知 QoS(默认关, 逐台开)。
#
#  1. 关闭(默认)时 tc_manager.sh 的命令序列与 v5.29 逐条一致: 同一套 mock 场景
#     (init / set_limit / set_delay / set_sqm / remove …)的 tc / ip 调用记录, 与
#     test/golden/tc_manager_v529_cmds.txt(由 v5.29 的 tc_manager.sh 生成)比对。
#     golden 只在 UPDATE_TESTDATA=1 时重新生成(从 git 取 v5.29 版本), 平时只读;
#     并有底线断言(必须含建 class / netem / filter 等关键命令), 防止把空输出锁进去。
#  2. apply_app_qos.sh: 关闭时零命令; 开启时 3 个子 class(rate 50/35/15、ceil =
#     父 ceil、prio 0/1/2)、内部过滤器、根 pref 50 掩码 fw、iptables 档位规则;
#     不改设备 class 本身(总限速不变); 计划没变且子 class 都在 → 不重下发;
#     关掉 → 拆干净并让 tc_manager 补回叶子。
#  3. tc_manager.sh 对 app QoS 管着的 class 跳过叶子操作(延迟 netem 等), 限速照改;
#     remove 先拆子 class。
# 「改动前会失败」: v5.29 没有 apply_app_qos.sh / ensure_class / 叶子保护(2、3 全失败)。

AQ_V529_COMMIT=914d46a
AQ_GOLDEN="$HNC_REPO_ROOT/test/golden/tc_manager_v529_cmds.txt"
AQ_TD="${HNC_TEST_DIR}-aq"

# mock 的 tc 输出: HNC 的 HTB 树已在(否则 set_limit 走自愈分支就返回了, 覆盖不到
# 设备 class / netem / SQM 这些路径)。设备 class 本身不在输出里 → 走新建。
AQ_TREE="$(printf 'qdisc htb 1: root refcnt 2 r2q 10 default 0x9999 direct_packets_stat 0\nclass htb 1:1 root rate 1000Mbit ceil 1000Mbit burst 200Kb cburst 200Kb')"

# 场景: $1 = 要跑的 tc_manager.sh; 输出 mock 记录(tc / ip / iptables 调用)
aq_tc_scenario() {
    mock_set_stdout tc "$AQ_TREE"
    rm -rf "$AQ_TD"; mkdir -p "$AQ_TD/bin" "$AQ_TD/run" "$AQ_TD/data" "$AQ_TD/logs"
    cp "$HNC_REPO_ROOT"/bin/*.sh "$AQ_TD/bin/" 2>/dev/null
    rm -f "$AQ_TD/bin/tc_state_snapshot.sh"   # 后台快照会让记录顺序不确定
    cp "$1" "$AQ_TD/bin/tc_manager.sh"
    for _c in "init wlan2" "set_limit wlan2 5 10 2 192.168.43.5" "set_delay wlan2 5 50 10 1 192.168.43.5" \
              "set_sqm wlan2 5 on 192.168.43.5" "set_limit wlan2 1 3 0 192.168.43.6" \
              "set_delay wlan2 1 0 0 0 192.168.43.6" "remove wlan2 5"; do
        # shellcheck disable=SC2086
        HNC_DIR="$AQ_TD" sh "$AQ_TD/bin/tc_manager.sh" $_c >/dev/null 2>&1
    done
    cat "$MOCK_LOG"
}

if [ "${UPDATE_TESTDATA:-0}" = "1" ]; then
    mock_setup
    git -C "$HNC_REPO_ROOT" show "$AQ_V529_COMMIT:bin/tc_manager.sh" > "$AQ_TD.v529.sh" \
        && aq_tc_scenario "$AQ_TD.v529.sh" > "$AQ_GOLDEN" && echo "  [UPDATE_TESTDATA] regenerated $AQ_GOLDEN"
    rm -f "$AQ_TD.v529.sh"
    mock_teardown
fi

test_start "app_qos: golden(v5.29 命令序列)不是空壳"
if [ -f "$AQ_GOLDEN" ] && [ "$(wc -l < "$AQ_GOLDEN")" -ge 100 ] \
   && grep -q '^tc|class add dev wlan2 parent 1:1 classid 1:5 htb' "$AQ_GOLDEN" \
   && grep -q '^tc|class change dev wlan2 parent 1:1 classid 1:5 htb rate 10000kbit' "$AQ_GOLDEN" \
   && grep -q '^tc|qdisc replace dev wlan2 parent 1:5 handle 1005: netem delay 25ms 10ms' "$AQ_GOLDEN" \
   && grep -q '^tc|qdisc replace dev wlan2 parent 1:5 handle 1005: cake' "$AQ_GOLDEN" \
   && grep -q '^tc|filter add dev wlan2 parent 1: pref 1 handle 0x800005 fw flowid 1:5' "$AQ_GOLDEN" \
   && grep -q '^tc|class add dev wlan2 parent 1:1 classid 1:100 htb' "$AQ_GOLDEN" \
   && grep -q '^tc|class del dev wlan2 classid 1:5' "$AQ_GOLDEN"; then
    test_pass
else
    test_fail "golden 缺关键命令或太短: $(wc -l < "$AQ_GOLDEN" 2>/dev/null) 行"
fi

test_start "app_qos: 关闭时 tc_manager 命令序列与 v5.29 逐条一致"
mock_setup
aq_tc_scenario "$HNC_REPO_ROOT/bin/tc_manager.sh" > "$AQ_TD.now"
if diff "$AQ_GOLDEN" "$AQ_TD.now" > "$AQ_TD.diff" 2>&1; then
    test_pass
else
    test_fail "与 v5.29 不一致:
$(head -20 "$AQ_TD.diff")"
fi
mock_teardown
rm -f "$AQ_TD.now" "$AQ_TD.diff"

# ── apply_app_qos.sh ───────────────────────────────────────────────────
aq_env() {
    rm -rf "$AQ_TD"; mkdir -p "$AQ_TD/bin" "$AQ_TD/run" "$AQ_TD/data" "$AQ_TD/logs"
    cp "$HNC_REPO_ROOT"/bin/*.sh "$AQ_TD/bin/" 2>/dev/null
    rm -f "$AQ_TD/bin/tc_state_snapshot.sh"
}
aq_apply() { HNC_DIR="$AQ_TD" sh "$AQ_TD/bin/apply_app_qos.sh" "$@" >/dev/null 2>&1; }
AQ_CLASS5='class htb 1:5 parent 1:1 leaf 1005: prio 0 rate 20Mbit ceil 20Mbit burst 1600b cburst 1600b'
AQ_PLAN='iface wlan2
dev 5 aa:bb:cc:00:00:05 192.168.43.5
ip 1 1.1.1.1
ip 3 3.3.3.3'

test_start "app_qos: 关闭(无计划 / 空计划, 无状态)→ 一条命令都不发"
aq_env; mock_setup
aq_apply
: > "$AQ_TD/run/app_qos.plan"
aq_apply
assert_eq "0" "$(wc -l < "$MOCK_LOG" | tr -d ' ')" "关闭时 mock 调用数" && test_pass
mock_teardown

test_start "app_qos: 开启 → 3 个子 class(50/35/15、ceil=父、prio 0/1/2)+ 过滤器 + iptables"
aq_env; mock_setup
mock_set_stdout tc "$AQ_CLASS5"
printf '%s\n' "$AQ_PLAN" > "$AQ_TD/run/app_qos.plan"
aq_apply
assert_mock_called "tc|class change dev wlan2 parent 1:5 classid 1:a015 htb rate 10000kbit ceil 20Mbit prio 0" && \
assert_mock_called "tc|class change dev wlan2 parent 1:5 classid 1:a016 htb rate 7000kbit ceil 20Mbit prio 1" && \
assert_mock_called "tc|class change dev wlan2 parent 1:5 classid 1:a017 htb rate 3000kbit ceil 20Mbit prio 2" && \
assert_mock_called "tc|qdisc replace dev wlan2 parent 1:a015 handle b015: fq_codel" && \
assert_mock_called "tc|filter add dev wlan2 parent 1:5 protocol all prio 1 handle 0x200000/0x600000 fw flowid 1:a015" && \
assert_mock_called "tc|filter add dev wlan2 parent 1:5 protocol all prio 1 handle 0x600000/0x600000 fw flowid 1:a017" && \
assert_mock_called "tc|filter add dev wlan2 parent 1:5 protocol all prio 9 u32 match u32 0 0 flowid 1:a016" && \
assert_mock_called "tc|filter add dev wlan2 parent 1: protocol all pref 50 handle 0x800005/0x9fffff fw flowid 1:5" && \
assert_mock_called "iptables|-t mangle -A HNC_APP_QOS -d 192.168.43.5 -m mark --mark 0x0/0x100000 -j HNC_APP_QOS_IP" && \
assert_mock_called "iptables|-t mangle -A HNC_APP_QOS_IP -s 1.1.1.1 -j MARK --set-xmark 0x200000/0x600000" && \
assert_mock_called "iptables|-t mangle -A HNC_APP_QOS_IP -s 3.3.3.3 -j MARK --set-xmark 0x600000/0x600000" && \
assert_mock_called "iptables|-t mangle -C POSTROUTING -j HNC_APP_QOS" && \
assert_mock_not_called "classid 1:5 " "设备 class 本身(总限速)不应被改" && \
assert_mock_not_called "MARK --set-mark" "只能用 set-xmark 改档位位, 不能整个覆盖 mark" && \
assert_eq "wlan2 5" "$(cat "$AQ_TD/run/app_qos.state")" "state" && test_pass
mock_teardown

test_start "app_qos: 子 class rate 之和 = 设备 rate(总限速不变)"
aq_env; mock_setup
mock_set_stdout tc 'class htb 1:7 parent 1:1 leaf 1007: prio 0 rate 3Mbit ceil 3Mbit burst 1600b cburst 1600b'
printf 'iface wlan2\ndev 7 aa:bb:cc:00:00:07\n' > "$AQ_TD/run/app_qos.plan"
aq_apply
_sum=$(grep -o 'classid 1:a01[def] htb rate [0-9]*kbit ceil 3Mbit' "$MOCK_LOG" | awk '{s += $5 + 0} END {print s}')
assert_eq "3000" "$_sum" "1500+1050+450" && assert_mock_not_called "HNC_APP_QOS -d" "不在线(没 IP)的设备不加 iptables 选择规则" && test_pass
mock_teardown

test_start "app_qos: mark_id=1 → 设备 class 1:100, 子 class 1:a005..a007"
aq_env; mock_setup
mock_set_stdout tc 'class htb 1:100 parent 1:1 leaf 1100: prio 0 rate 8Mbit ceil 10Mbit burst 1600b cburst 1600b'
printf 'iface wlan2\ndev 1 aa:bb:cc:00:00:01 192.168.43.1\n' > "$AQ_TD/run/app_qos.plan"
aq_apply
assert_mock_called "parent 1:100 classid 1:a005 htb rate 4000kbit ceil 10Mbit prio 0" && \
assert_mock_called "pref 50 handle 0x800001/0x9fffff fw flowid 1:100" && \
assert_eq "wlan2 100" "$(cat "$AQ_TD/run/app_qos.state")" "state" && test_pass
mock_teardown

test_start "app_qos: 计划没变且子 class 都在 → 不重下发"
aq_env; mock_setup
mock_set_stdout tc "$AQ_CLASS5"
printf '%s\n' "$AQ_PLAN" > "$AQ_TD/run/app_qos.plan"
aq_apply
: > "$MOCK_LOG"
mock_set_stdout tc "class htb 1:a015 parent 1:5 leaf b015: prio 0 rate 10Mbit ceil 20Mbit
class htb 1:a016 parent 1:5 leaf b016: prio 1 rate 7Mbit ceil 20Mbit
class htb 1:a017 parent 1:5 leaf b017: prio 2 rate 3Mbit ceil 20Mbit"
aq_apply
assert_mock_not_called "class change" && assert_mock_not_called "iptables" && \
    assert_eq "1" "$(wc -l < "$MOCK_LOG" | tr -d ' ')" "只查一次子 class" && test_pass
mock_teardown

test_start "app_qos: 关掉 → 拆子 class / 过滤器 / iptables, 再让 tc_manager 补叶子"
aq_env; mock_setup
mock_set_stdout tc "$AQ_CLASS5"
printf '%s\n' "$AQ_PLAN" > "$AQ_TD/run/app_qos.plan"
aq_apply
: > "$MOCK_LOG"
: > "$AQ_TD/run/app_qos.plan"
aq_apply
assert_mock_called "tc|filter del dev wlan2 parent 1:5" && \
assert_mock_called "tc|class del dev wlan2 classid 1:a015" && \
assert_mock_called "tc|class del dev wlan2 classid 1:a017" && \
assert_mock_called "tc|filter del dev wlan2 parent 1: pref 50 handle 0x800005 fw" && \
assert_mock_called "parent 1:5 handle 1005:" "tc_manager ensure_class 应补回设备叶子" && \
assert_mock_called "iptables|-t mangle -X HNC_APP_QOS" && \
assert_mock_not_called "class del dev wlan2 classid 1:5" "设备 class 本身保留" && \
[ ! -f "$AQ_TD/run/app_qos.state" ] && test_pass || test_fail "state 应删除"
mock_teardown

# ── tc_manager.sh 的叶子保护 ───────────────────────────────────────────
test_start "app_qos: 开着的设备 set_delay 不碰下行叶子(上行照常), set_limit 照改 rate"
aq_env; mock_setup
mock_set_stdout tc "$AQ_TREE"
echo "wlan2 5" > "$AQ_TD/run/app_qos.state"
HNC_DIR="$AQ_TD" sh "$AQ_TD/bin/tc_manager.sh" set_delay wlan2 5 50 0 0 192.168.43.5 >/dev/null 2>&1
HNC_DIR="$AQ_TD" sh "$AQ_TD/bin/tc_manager.sh" set_limit wlan2 5 10 0 192.168.43.5 >/dev/null 2>&1
assert_mock_not_called "dev wlan2 parent 1:5 handle 1005: netem" "app QoS 管着的下行 class 不应挂 netem" && \
assert_mock_called "dev ifb0 parent 1:5 handle 2005: netem delay 25ms" "上行(ifb0)不归 app QoS 管, 延迟照常" && \
assert_mock_not_called "qdisc replace dev wlan2 parent 1:5 " && \
assert_mock_called "classid 1:5 htb rate 10000kbit" "限速仍然改设备 class" && test_pass
mock_teardown

test_start "app_qos: remove 先拆子 class 再删设备 class"
aq_env; mock_setup
echo "wlan2 5" > "$AQ_TD/run/app_qos.state"
HNC_DIR="$AQ_TD" sh "$AQ_TD/bin/tc_manager.sh" remove wlan2 5 >/dev/null 2>&1
_l1=$(grep -n 'class del dev wlan2 classid 1:a015' "$MOCK_LOG" | head -1 | cut -d: -f1)
_l2=$(grep -n 'class del dev wlan2 classid 1:5$' "$MOCK_LOG" | head -1 | cut -d: -f1)
if [ -n "$_l1" ] && [ -n "$_l2" ] && [ "$_l1" -lt "$_l2" ] && [ ! -f "$AQ_TD/run/app_qos.state" ]; then
    test_pass
else
    test_fail "子 class 行=$_l1 设备 class 行=$_l2 state=$(cat "$AQ_TD/run/app_qos.state" 2>/dev/null)"
fi
mock_teardown

rm -rf "$AQ_TD"
