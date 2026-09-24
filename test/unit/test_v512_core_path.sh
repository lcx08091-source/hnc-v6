#!/system/bin/sh
# test/unit/test_v512_core_path.sh — v5.12 限速核心路径回归
# 覆盖: mark_id 分配 / 默认类保护 / v6 filter 同步 / 陈旧规则清理 / 接口缓存 等。
# 全部走 mock(test/lib.sh 的 PATH 拦截),不碰真实 tc/iptables。

ADR="$HNC_REPO_ROOT/bin/apply_device_rule.sh"

adr() {
    HNC_DIR="$HNC_TEST_DIR" HNC="$HNC_TEST_DIR" sh "$ADR" "$@"
}

# ═══ get_or_assign_mid: 只认本设备块内的 mark_id ═══════════════
test_start "alloc_mid: 设备条目无 mark_id 时不得借用下一台设备的 mid"
mock_setup
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:aa:aa:aa:aa:01":{"whitelist":true},"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","mark_id":5}},"blacklist":[],"whitelist":[]}
EOF
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:aa:aa:aa:aa:01":{"ip":"192.168.43.9","status":"allowed"}}
EOF
out=$(adr alloc_mid aa:aa:aa:aa:aa:01 2>/dev/null | tail -1)
assert_ne "5" "$out" "不能复用 bb:02 的 mark_id=5" && \
    assert_contains "$(cat "$HNC_TEST_DIR/data/rules.json")" '"mark_id"' "应写入新 mark_id" && test_pass
mock_teardown

test_start "alloc_mid: 已有 mark_id 的设备复用自己的 mid"
mock_setup
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:aa:aa:aa:aa:01":{"whitelist":true},"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","mark_id":5}},"blacklist":[],"whitelist":[]}
EOF
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","status":"allowed"}}
EOF
out=$(adr alloc_mid bb:bb:bb:bb:bb:02 2>/dev/null | tail -1)
assert_eq "5" "$out" "bb:02 应复用自己的 5" && test_pass
mock_teardown

# ═══ mark_id=1 不得落到 HTB 父类 1:1 ══════════════════════════
TCM="$HNC_REPO_ROOT/bin/tc_manager.sh"
tcm() {
    HNC_DIR="$HNC_TEST_DIR" sh "$TCM" "$@"
}
TC_TREE="qdisc htb 1: root refcnt 2 r2q 10 default 0x9999
class htb 1:1 root rate 1Gbit ceil 1Gbit
class htb 1:9999 parent 1:1 leaf 9999: prio 0 rate 1Gbit"

test_start "set_limit mark_id=1: 设备 class 用 1:100, 不碰父类 1:1"
mock_setup
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 1 10 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "classid 1:100 htb" "mid=1 应映射到 class 1:100" && \
    assert_mock_not_called "classid 1:1 htb" "绝不能改写父类 1:1" && \
    assert_mock_called "handle 0x800001 fw" "fwmark 仍是 0x800001" && \
    assert_mock_called "prio 101 u32" "u32 优先级仍按 mark_id=1 → 101" && test_pass
mock_teardown

test_start "set_limit mark_id=1 清限速: 不得把父类 1:1 复位成 1000mbit"
mock_setup
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 1 0 0 192.168.43.5 >/dev/null 2>&1
assert_mock_not_called "classid 1:1 htb" "清限速不能改父类 1:1" && test_pass
mock_teardown

# ═══ remove_device 不得误删 mark_id+1 设备的 u32 filter ═══════
test_start "remove mark_id=5: 只删 prio 105, 不碰 mark_id=6 的 prio 106"
mock_setup
tcm remove wlan2 5 >/dev/null 2>&1
assert_mock_called "parent 1: prio 105" "应删自己的 prio 105" && \
    assert_mock_not_called "prio 106" "不能删相邻设备 prio 106" && test_pass
mock_teardown

# ═══ apply_app_limits 不得删除默认类 1:9999(十六进制 0x9999)════
test_start "apply_app_limits: 清理应用段 class 时不碰默认类 1:9999"
mock_setup
echo "wlan2" > "$HNC_TEST_DIR/run/active_iface"
mock_set_stdout tc "class htb 1:1 root rate 1Gbit ceil 1Gbit
class htb 1:9999 parent 1:1 leaf 9999: prio 0 rate 1Gbit
class htb 1:9001 parent 1:1 prio 0 rate 5Mbit
class htb 1:5 parent 1:1 leaf 1005: prio 0 rate 10Mbit"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
assert_mock_called "class del dev wlan2 classid 1:9001" "应用段 class 应被清理" && \
    assert_mock_not_called "classid 1:9999" "默认类 1:9999 绝不能删" && \
    assert_mock_not_called "classid 1:5" "设备 class 不能删" && test_pass
mock_teardown

# ═══ v6_sync: 地址不变但 tc 上 filter 已丢 → 必须重建 ════════════
V6="$HNC_REPO_ROOT/bin/v6_sync.sh"
seed_v6_env() {
    echo "wlan2" > "$HNC_TEST_DIR/run/iface.cache"
    mkdir -p "$HNC_TEST_DIR/run/v6"
    mock_set_stdout ip "    inet 192.168.43.1/24 scope global wlan2
2408:1::5 dev wlan2 lladdr aa:bb:cc:dd:ee:05 REACHABLE"
}
IPT_MARKED="MARK       all  --  0.0.0.0/0            0.0.0.0/0            MAC aa:bb:cc:dd:ee:05 MARK set 0x800005"

test_start "v6_sync: 旧快照地址相同但 filter 不在 tc 上(热点重开/重启)→ 重建"
mock_setup
seed_v6_env
mock_set_stdout iptables "$IPT_MARKED"
echo "2408:1::5" > "$HNC_TEST_DIR/run/v6/aa:bb:cc:dd:ee:05"
HNC_DIR="$HNC_TEST_DIR" sh "$V6" sync >/dev/null 2>&1
assert_mock_called "filter add dev wlan2 parent 1: protocol ipv6 prio 205 u32 match ip6 dst 2408:1::5/128 flowid 1:5" \
    "v6 egress filter 必须重建" && test_pass
mock_teardown

test_start "v6_sync: 状态未变且 filter 仍在 → 不重复重建"
mock_setup
seed_v6_env
mock_set_stdout iptables "$IPT_MARKED"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n' "#hnc_v6 iface=wlan2 mark=5 ing=0" "2408:1::5" > "$HNC_TEST_DIR/run/v6/aa:bb:cc:dd:ee:05"
HNC_DIR="$HNC_TEST_DIR" sh "$V6" sync >/dev/null 2>&1
assert_mock_not_called "filter add" "稳态不应重建" && test_pass
mock_teardown

test_start "v6_sync: iptables 已无 mark 的孤儿快照 → 按快照里的 mark 删 filter"
mock_setup
seed_v6_env
printf '%s\n%s\n' "#hnc_v6 iface=wlan2 mark=5 ing=1" "2408:1::5" > "$HNC_TEST_DIR/run/v6/aa:bb:cc:dd:ee:05"
HNC_DIR="$HNC_TEST_DIR" sh "$V6" sync >/dev/null 2>&1
assert_mock_called "filter del dev wlan2 parent 1: prio 205 protocol ipv6" "孤儿 v6 filter 必须删" && \
    assert_mock_called "filter del dev ifb0 parent 1: prio 205 protocol ipv6" "ifb0 上的也要删" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/v6/aa:bb:cc:dd:ee:05" && test_pass
mock_teardown

# ═══ cleanup_stale_rules: 持 gate 时 unmark 不得自阻塞 + 离线设备也要 unmark ═══
test_start "cleanup_stale_rules: 陈旧离线设备的 MARK 规则被真正删除"
mock_setup
mock_set_exit iptables 1     # 让 ipt_del_all 一次即停(规则"已不存在")
mock_set_exit ip6tables 1
echo "wlan2" > "$HNC_TEST_DIR/run/iface.cache"
mock_set_stdout ip "    inet 192.168.43.1/24 scope global wlan2"
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"stale_rule_ttl_days":30,"devices":{"cc:cc:cc:cc:cc:07":{"mark_id":7,"down_mbps":5,"limit_enabled":true,"last_seen_persist":1000}},"blacklist":[],"whitelist":[]}
EOF
echo '{}' > "$HNC_TEST_DIR/data/devices.json"
HNC_DIR="$HNC_TEST_DIR" HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/cleanup_stale_rules.sh" >/dev/null 2>&1
assert_mock_called "mangle -D HNC_MARK -m mac --mac-source cc:cc:cc:cc:cc:07 -m mark --mark 0 -j MARK --set-mark 0x800007" \
    "陈旧设备的 MAC-only MARK 规则必须删除" && test_pass
mock_teardown

# ═══ ensure_ingress: 已有 mirred 时不得反复 del+重装 ════════════
test_start "ensure_ingress: 识别 iproute2 真实输出的 mirred, 不重装"
mock_setup
mock_set_stdout tc "filter parent ffff: protocol all pref 1 matchall chain 0
filter parent ffff: protocol all pref 1 matchall chain 0 handle 0x1
	action order 1: mirred (Egress Redirect to device ifb0) stolen"
tcm ensure_ingress wlan2 >/dev/null 2>&1
assert_mock_not_called "ingress pref 1" "mirred 已在, 不应 del pref 1" && \
    assert_mock_not_called "filter add" "mirred 已在, 不应重装" && test_pass
mock_teardown

# ═══ watchdog action full_init: 延迟 re-restore 不得拖住调用方的 stdout 管道 ═══
test_start "watchdog action full_init: 被 \$(...) 捕获时不因后台 sleep 15 阻塞"
mock_setup
echo "wlan2" > "$HNC_TEST_DIR/run/iface.cache"
mock_set_stdout ip "    inet 192.168.43.1/24 scope global wlan2"
echo '{"version":1,"devices":{},"blacklist":[],"whitelist":[]}' > "$HNC_TEST_DIR/data/rules.json"
t0=$(date +%s)
_out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/watchdog.sh" action full_init wlan2 192.168.43.1 2>&1)
t1=$(date +%s)
# 结束后把状态改掉,让残留的后台子 shell 醒来后什么都不做
echo "PENDING" > "$HNC_TEST_DIR/run/hnc_state"
el=$((t1 - t0))
if [ "$el" -lt 12 ]; then test_pass; else test_fail "full_init 捕获输出耗时 ${el}s(后台子 shell 持有管道)"; fi
mock_teardown

# ═══ device_detect iface: 缓存的接口已消失 → 重新探测 ═══════════
test_start "device_detect iface: 缓存接口已无 IPv4 时不返回旧值"
mock_setup
echo "wlan9" > "$HNC_TEST_DIR/run/iface.cache"
mock_set_stdout ip "9: wlan9: <BROADCAST,MULTICAST> mtu 1500 state DOWN"
mock_set_stdout iptables "   10   800 ACCEPT     all  --  wlan1  rmnet_data0  0.0.0.0/0            0.0.0.0/0"
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/device_detect.sh" iface 2>/dev/null)
assert_eq "wlan1" "$out" "应重新探测到 wlan1 而不是缓存里已失效的 wlan9" && test_pass
mock_teardown
