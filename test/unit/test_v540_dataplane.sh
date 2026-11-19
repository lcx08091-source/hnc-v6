#!/system/bin/sh
# test/unit/test_v540_dataplane.sh — HNC v5.40.0 T2 Android 13–16 真机数据面全场景核心单测
#
# 覆盖:
#   1. 32 位正交 skb->mark 位域编码/新旧双格式解码 + 低 16 位 netd [15:0] 零污染静态红线审计
#   2. iptables_manager.sh 双栈正交 xmark + CONNMARK 0xffff0000 + 陌生/随机 MAC 零误伤 + 幂等删除
#   3. apply_app_limits.sh 父子层级归位 parent 1:<cid> + ceil<=父ceil 钳制 + 1:9eXX 兜底不逃逸
#   4. 未开整机限速设备自动建 1:<cid> + 清空单应用限速后拆子类并自动补回设备默认叶子
#   5. 单应用限速 (prio 1, 0xfc000000) 与三档 fq_codel app_qos (prio 2/9, 0x03000000) 同设备共存与独立拆装
#   6. tc_manager.sh 对 app_limits/app_qos 内部节点的叶子保护 + remove 先拆子类再删父类
#   7. ifb0 mirred prio 2 解耦 + 旧 pref 1 mirred 平滑迁移 + hnc_clsact_sync.sh 双栈正交同步
#   8. 无 ifb0 时双栈 tc police (burst = max(rate_Bps/8, 65536) + mtu 65535 + fw 正交兜底)
#   9. 受限应用双栈 HNC_QUIC_APPLIM + 全局 HNC_QUIC (IPv4 icmp / IPv6 icmp6 REJECT)
#  10. hnc_offload_guard.sh T+0 主动慢路径压制 + orig_tether_offload_disabled (null/0/1) 三态无损备份还原

. "$HNC_REPO_ROOT/bin/hnc_constants.sh"

assert_mock_not_regex() {
    local regex="$1" msg="${2:-mock log should not match $regex}"
    if ! grep -qE -- "$regex" "$MOCK_LOG" 2>/dev/null; then
        return 0
    fi
    test_fail "$msg (matched: $regex)"
    return 1
}

# ═══ 1. hnc_constants.sh 32位正交位域与新旧双兼容解码 ═══════════════
test_start "v5.40 T2-1: hnc_constants 正交常量、hnc_dev_mark_hex 与 hnc_parse_mid_from_mark 新旧兼容"
assert_eq "0x00800000" "$HNC_MARK_BASE" "HNC_MARK_BASE" && \
assert_eq "0x00ff0000" "$HNC_MARK_MASK" "HNC_MARK_MASK" && \
assert_eq "16" "$HNC_MARK_SHIFT" "HNC_MARK_SHIFT" && \
assert_eq "0x03000000" "$HNC_QOS_MASK" "HNC_QOS_MASK" && \
assert_eq "0xfc000000" "$HNC_APPLIM_MASK" "HNC_APPLIM_MASK" && \
assert_eq "26" "$HNC_APPLIM_SHIFT" "HNC_APPLIM_SHIFT" && \
assert_eq "0xffff0000" "$HNC_CONNMARK_MASK" "HNC_CONNMARK_MASK" && \
assert_eq "0x00810000" "$(hnc_dev_mark_hex 1)" "mid=1 hex" && \
assert_eq "0x00850000" "$(hnc_dev_mark_hex 5)" "mid=5 hex" && \
assert_eq "0x00bb0000" "$(hnc_dev_mark_hex 59)" "mid=59 hex" && \
assert_eq "0x04000000" "$(hnc_applim_mark_hex 1)" "slot=1 hex" && \
assert_eq "0xfc000000" "$(hnc_applim_mark_hex 63)" "slot=63 hex" && \
assert_eq "1" "$(hnc_parse_mid_from_mark 0x00810000/0x00ff0000)" "decode new mid=1" && \
assert_eq "59" "$(hnc_parse_mid_from_mark 0xbb0000/0xff0000)" "decode short new mid=59" && \
assert_eq "5" "$(hnc_parse_mid_from_mark 0x05851234)" "decode composite mark preserving netd low16" && \
assert_eq "1" "$(hnc_parse_mid_from_mark 0x800001)" "decode legacy mid=1" && \
assert_eq "59" "$(hnc_parse_mid_from_mark 0x80003b/0xffffffff)" "decode legacy mid=59" && \
test_pass

test_start "v5.40 T2-1: 数据面核心脚本静态红线审计 (零无掩码 --set-mark、零污染低 16 位掩码、零高危节点)"
_bad=""
for _f in hnc_constants.sh iptables_manager.sh tc_manager.sh apply_device_rule.sh \
          v6_sync.sh hnc_clsact_sync.sh apply_app_limits.sh apply_app_qos.sh \
          hnc_offload_guard.sh quic_block_sync.sh cleanup_stale_rules.sh; do
    _fp="$HNC_REPO_ROOT/bin/$_f"
    if grep -v '^[[:space:]]*#' "$_fp" | grep -qE -- '--set-mark[[:space:]]+0x|--set-mark[[:space:]]+"?\$'; then
        _bad="$_bad $_f(--set-mark)"
    fi
    if grep -v '^[[:space:]]*#' "$_fp" | grep -qiE '/0xffffffff|/0xffffff([^0-9a-f]|$)|/0x9fffff|/0x600000'; then
        _bad="$_bad $_f(legacy_mask)"
    fi
    if grep -v '^[[:space:]]*#' "$_fp" | grep -qiE '/sys/kernel/debug/ppe|ipacm'; then
        _bad="$_bad $_f(unsafe_hw_node)"
    fi
done
assert_eq "" "$_bad" "发现违反正交掩码或硬件安全红线的脚本:$_bad" && test_pass

# ═══ 2. iptables_manager.sh 双栈 CONNMARK 0xffff0000 与陌生 MAC 保护 ══
test_start "v5.40 T2-1: iptables_manager init 使用 0xffff0000 掩码且陌生/随机 MAC 默认不限速不拉黑"
mock_setup
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/iptables_manager.sh" init >/dev/null 2>&1
assert_mock_called "HNC_RESTORE -m connmark ! --mark 0x0/0xffff0000 -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000" && \
assert_mock_called "HNC_SAVE -m mark ! --mark 0x0/0xffff0000 -j CONNMARK --save-mark --nfmask 0xffff0000 --ctmask 0xffff0000" && \
assert_mock_not_called "mangle -A HNC_MARK" "初始化不得给未知/随机 MAC 默认打限速标" && \
assert_mock_not_called "filter -A HNC_CTRL" "初始化不得默认拉黑任何 MAC" && \
test_pass
mock_teardown

# ═══ 3. 单应用限速父子层级归位 + ceil 钳制 + 1:9eXX 兜底不逃逸 ═════════
v540_seed_al() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
    echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
    echo "wlan2" > "$HNC_TEST_DIR/run/active_iface"
    cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","online":true}}
EOF
    mock_set_stdout ip "2408:8000::55 dev wlan2 lladdr aa:bb:cc:dd:ee:05 REACHABLE"
}

test_start "v5.40 T2-2/8: 单应用限速归属客户端 parent 1:5, 应用 ceil 钳制<=父 ceil, 自动建 1:9e05 兜底防逃逸"
mock_setup
v540_seed_al
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"down_mbps":5,"limit_enabled":true}}}
EOF
mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:5 parent 1:1 leaf 1005: prio 0 rate 5000Kbit ceil 5000Kbit"
printf 'aa:bb:cc:dd:ee:05 douyin 8\naa:bb:cc:dd:ee:05 bilibili 1\n' > "$HNC_TEST_DIR/data/app_limits.flat"
printf '203.0.113.10 douyin\n2408:8000::99 douyin\n198.51.100.20 bilibili\n' > "$HNC_TEST_DIR/run/ip_app_map.flat"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1

assert_mock_called "qdisc del dev wlan2 parent 1:5" "转为内部节点前先摘除 1:5 直接叶子" && \
assert_mock_called "class add dev wlan2 parent 1:5 classid 1:9001 htb rate 5000kbit ceil 5000kbit" "8Mbps 应用必须被钳制到父设备 ceil 5000kbit" && \
assert_mock_called "class add dev wlan2 parent 1:5 classid 1:9002 htb rate 1000kbit ceil 1000kbit" "1Mbps 应用挂在 parent 1:5 下" && \
assert_mock_not_called "parent 1:1 classid 1:9001" "绝不能挂在根 1:1 下突破设备总限速" && \
assert_mock_called "filter add dev wlan2 parent 1:5 protocol all prio 1 handle 0x04000000/0xfc000000 fw flowid 1:9001" && \
assert_mock_called "filter add dev wlan2 parent 1:5 protocol all prio 1 handle 0x08000000/0xfc000000 fw flowid 1:9002" && \
assert_mock_called "parent 1:5 classid 1:9e05 htb rate 1000kbit ceil 5000kbit" "剩余带宽不足时兜底子类保底 1000kbit 且 ceil=5000kbit" && \
assert_mock_called "qdisc replace dev wlan2 parent 1:9e05 handle 9e05: fq_codel" && \
assert_mock_called "filter add dev wlan2 parent 1:5 protocol all prio 9 u32 match u32 0 0 flowid 1:9e05" "兜底 u32 防逃逸至 1:9999" && \
assert_eq "wlan2 5" "$(cat "$HNC_TEST_DIR/run/app_limits.devs")" "记录活跃 app_limits 设备类" && \
test_pass
mock_teardown

# ═══ 4. 未开整机限速设备自动建 1:<cid> + 清空后补回默认叶子 ════════════
test_start "v5.40 T2-2: 未开整机限速设备自动建 1:<cid>(1000mbit), 清空单应用限速后自动补回默认叶子"
mock_setup
v540_seed_al
echo '{"version":1,"devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
echo "aa:bb:cc:dd:ee:05 douyin 4" > "$HNC_TEST_DIR/data/app_limits.flat"
echo "203.0.113.10 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
# aa:bb:cc:dd:ee:05 -> 0x05 % 99 + 1 = 6 -> class 1:6, dev_mark 0x00860000
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
assert_mock_called "class add dev wlan2 parent 1:1 classid 1:6 htb rate 1000000kbit ceil 1000000kbit" "自动建 1000mbit 父类 1:6" && \
assert_mock_called "filter add dev wlan2 parent 1: protocol all pref 1 handle 0x00860000/0x00ff0000 fw flowid 1:6" && \
assert_mock_called "parent 1:6 classid 1:9001 htb rate 4000kbit ceil 4000kbit" && \
assert_mock_called "parent 1:6 classid 1:9e06 htb rate 996000kbit ceil 1000000kbit" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:6 parent 1:1 prio 0 rate 1000Mbit ceil 1000Mbit
class htb 1:9001 parent 1:6 prio 0 rate 4000Kbit ceil 4000Kbit
class htb 1:9e06 parent 1:6 prio 2 rate 996000Kbit ceil 1000Mbit"
    : > "$HNC_TEST_DIR/data/app_limits.flat"
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
    assert_mock_called "filter del dev wlan2 parent 1:6 prio 1" && \
    assert_mock_called "class del dev wlan2 classid 1:9001" && \
    assert_mock_called "class del dev wlan2 classid 1:9e06" && \
    assert_mock_called "parent 1:6 handle 1006:" "清空后自动调用 tc_manager 为 1:6 补回默认叶子" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/app_limits.devs" && \
    test_pass
    mock_teardown
fi

# ═══ 5. 单应用限速 + 三档 fq_codel app_qos 同设备完美共存 ═════════════
test_start "v5.40 T2-8: 同设备开启 app_limits + app_qos 正交共存, 关闭 app_qos 不误删 prio 1 并补回 1:9e05"
mock_setup
v540_seed_al
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"down_mbps":20,"limit_enabled":true}}}
EOF
mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:5 parent 1:1 prio 0 rate 20Mbit ceil 20Mbit"
echo "aa:bb:cc:dd:ee:05 douyin 4" > "$HNC_TEST_DIR/data/app_limits.flat"
echo "203.0.113.10 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1

: > "$MOCK_LOG"
cat > "$HNC_TEST_DIR/run/app_qos.plan" <<'EOF'
iface wlan2
dev 5 aa:bb:cc:dd:ee:05 192.168.43.55
ip 1 1.1.1.1
ip 3 3.3.3.3
EOF
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_qos.sh" >/dev/null 2>&1
assert_mock_not_regex '^tc\|filter del dev wlan2 parent 1:5$' "不得盲删整个 parent 1:5 过滤器(保护 prio 1)" && \
assert_mock_not_called "parent 1:5 prio 1" "不得碰 prio 1 单应用限速过滤器" && \
assert_mock_called "class del dev wlan2 classid 1:9e05" "开启 app_qos 后移除冗余 1:9e05, 改走 1:a015..a017" && \
assert_mock_called "parent 1:5 protocol all prio 2 handle 0x01000000/0x03000000 fw flowid 1:a015" && \
assert_mock_called "parent 1:5 protocol all prio 2 handle 0x03000000/0x03000000 fw flowid 1:a017" && \
assert_mock_called "parent 1:5 protocol all prio 9 u32 match u32 0 0 flowid 1:a016" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    : > "$HNC_TEST_DIR/run/app_qos.plan"
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_qos.sh" >/dev/null 2>&1
    assert_mock_not_regex '^tc\|filter del dev wlan2 parent 1:5$' "关闭 app_qos 时不得盲删 prio 1" && \
    assert_mock_called "parent 1:5 prio 2" "精确拆除 prio 2 QoS 过滤器" && \
    assert_mock_called "class del dev wlan2 classid 1:a015" && \
    assert_mock_called "parent 1:5 classid 1:9e05 htb" "仍有 app_limits 时自动补回 1:9e05 默认兜底子类" && \
    assert_mock_called "parent 1:5 protocol all prio 9 u32 match u32 0 0 flowid 1:9e05" && \
    test_pass
    mock_teardown
fi

# ═══ 6. tc_manager 保护 app_limits 内部节点叶子 + remove 先拆子类再删父类 ══
test_start "v5.40 T2-2/8: tc_manager 对 app_limits 管理的 1:5 跳过下行叶子覆盖, remove 先拆子类再删 1:5"
mock_setup
echo "wlan2 5" > "$HNC_TEST_DIR/run/app_limits.devs"
printf 'DEV wlan2 5 5 192.168.43.55\nAPP wlan2 1:5 1:9001\n' > "$HNC_TEST_DIR/run/app_limits.tree"
mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:5 parent 1:1 prio 0 rate 10Mbit ceil 10Mbit"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" set_delay wlan2 5 60 0 0 192.168.43.55 >/dev/null 2>&1
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" set_limit wlan2 5 12 0 192.168.43.55 >/dev/null 2>&1
assert_mock_not_called "dev wlan2 parent 1:5 handle 1005:" "app_limits 内部节点 1:5 不得挂直接叶子" && \
assert_mock_called "classid 1:5 htb rate 12000kbit" "父设备自身 rate/ceil 正常更新" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" remove wlan2 5 >/dev/null 2>&1
    _l_sub=$(grep -n 'class del dev wlan2 classid 1:9001' "$MOCK_LOG" | head -1 | cut -d: -f1)
    _l_def=$(grep -n 'class del dev wlan2 classid 1:9e05' "$MOCK_LOG" | head -1 | cut -d: -f1)
    _l_par=$(grep -n 'class del dev wlan2 classid 1:5$' "$MOCK_LOG" | head -1 | cut -d: -f1)
    if [ -n "$_l_sub" ] && [ -n "$_l_def" ] && [ -n "$_l_par" ] && [ "$_l_sub" -lt "$_l_par" ] && [ "$_l_def" -lt "$_l_par" ]; then
        test_pass
    else
        test_fail "删除顺序错: 9001=$_l_sub 9e05=$_l_def 1:5=$_l_par"
    fi
    mock_teardown
fi

# ═══ 7. ifb0 mirred prio 2 平滑迁移 + hnc_clsact_sync 双栈正交同步 ══════
test_start "v5.40 T2-4: ensure_ingress 将旧 pref 1 mirred 迁至 pref 2, hnc_clsact_sync 输出双栈正交 0x00850000"
mock_setup
mkdir -p "$HNC_TEST_DIR/sysnet/wlan2"
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","online":true}}
EOF
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"clsact_bpf_mode":"on","devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"limit_enabled":true}}}
EOF
: > "$HNC_TEST_DIR/bin/hnc_clsact.o"
cat > "$HNC_TEST_DIR/bin/hnc_clsact_ctl" <<'EOF'
#!/bin/sh
echo "ctl|$*" >> "$MOCK_LOG"
case "$1" in
    check) echo '{"ok":false,"bpf_filter":false,"map":true}' ;;
    sync)  cat >> "$MOCK_LOG.clsact_sync" ;;
esac
exit 0
EOF
chmod +x "$HNC_TEST_DIR/bin/hnc_clsact_ctl"

# 状态感知 tc mock: 初始在 pref 1 占 mirred; 执行 filter del ... pref 1 后自动切到 pref 2, 且 filter add 输出空串表示成功
echo "pref1" > "$HNC_TEST_DIR/tc_mirred_state"
cat > "$MOCK_BIN_DIR/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$MOCK_LOG"
case "$*" in
    *"qdisc show"*)
        echo "qdisc clsact ffff: parent ffff:fff1"
        ;;
    *"filter del dev wlan2 ingress pref 1"*)
        echo "none" > "$HNC_DIR/tc_mirred_state"
        ;;
    *"filter add dev wlan2 ingress prio 2"*)
        echo "pref2" > "$HNC_DIR/tc_mirred_state"
        ;;
    *"filter show"*)
        st=$(cat "$HNC_DIR/tc_mirred_state" 2>/dev/null)
        if [ "$st" = "pref1" ]; then
            echo "filter parent ffff: protocol all pref 1 matchall chain 0 action order 1: mirred (Egress Redirect to device ifb0) stolen"
        elif [ "$st" = "pref2" ]; then
            echo "filter parent ffff: protocol all pref 2 matchall chain 0 action order 1: mirred (Egress Redirect to device ifb0) stolen"
        fi
        ;;
esac
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/tc"
mock_set_stdout ip "2408:8000::55 dev wlan2 lladdr aa:bb:cc:dd:ee:05 REACHABLE"

HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" ensure_ingress wlan2 >/dev/null 2>&1
sync_entries=$(cat "$MOCK_LOG.clsact_sync" 2>/dev/null)
assert_mock_called "tc|filter del dev wlan2 ingress pref 1" "应删旧 pref 1 mirred" && \
assert_mock_called "tc|filter add dev wlan2 ingress prio 2 protocol all matchall action mirred egress redirect dev ifb0" "迁至 prio 2" && \
assert_mock_called "ctl|install wlan2" "安装 pref 1 clsact" && \
assert_contains "$sync_entries" "aa:bb:cc:dd:ee:05 0x00850000" "MAC 正交编码" && \
assert_contains "$sync_entries" "192.168.43.55 0x00850000" "IPv4 正交编码" && \
assert_contains "$sync_entries" "2408:8000::55 0x00850000" "IPv6 邻居正交编码" && \
test_pass
mock_teardown

# ═══ 8. 无 ifb0 时双栈 tc police: burst >= 64KB (65536b) + mtu 65535 ═══
test_start "v5.40 T2-5: 无 ifb0 时 set_uplink_police 强制 burst>=65536b + mtu 65535 + IPv4/IPv6/fw 双栈全覆盖"
mock_setup
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","online":true}}
EOF
mock_set_stdout ip "2408:8000::55 dev wlan2 lladdr aa:bb:cc:dd:ee:05 REACHABLE"
# 低速率 2000kbit (250000 B/s / 8 = 31250 < 65536 -> 必须提升至 65536b!)
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" set_uplink_police wlan2 5 192.168.43.55 2000kbit >/dev/null 2>&1
assert_mock_called "protocol ip prio 305 u32 match ip src 192.168.43.55/32 police rate 2000kbit burst 65536b mtu 65535 drop" && \
assert_mock_called "protocol ipv6 prio 5305 u32 match ip6 src 2408:8000::55/128 police rate 2000kbit burst 65536b mtu 65535 drop" && \
assert_mock_called "protocol ip prio 6305 handle 0x00850000/0x00ff0000 fw police rate 2000kbit burst 65536b mtu 65535 drop" && \
assert_mock_called "protocol ipv6 prio 7305 handle 0x00850000/0x00ff0000 fw police rate 2000kbit burst 65536b mtu 65535 drop" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    # 高速率 80000kbit (10,000,000 B/s / 8 = 1250000b > 65536b)
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" set_uplink_police wlan2 5 192.168.43.55 80000kbit >/dev/null 2>&1
    assert_mock_called "police rate 80000kbit burst 1250000b mtu 65535 drop" && test_pass
    mock_teardown
fi

# ═══ 9. 受限应用双栈 QUIC 定向回落 TCP (HNC_QUIC_APPLIM) ════════════════
test_start "v5.40 T2-7: apply_app_limits 维护双栈 filter/HNC_QUIC_APPLIM (icmp-port-unreachable & icmp6-port-unreachable)"
mock_setup
v540_seed_al
# 模拟首次挂载: -C 返回 1 (尚未挂载), 其余命令返回 0
for _b in iptables ip6tables; do
    cat > "$MOCK_BIN_DIR/$_b" <<EOF
#!/bin/sh
echo "${_b}|\$*" >> "\$MOCK_LOG"
case "\$*" in
    *" -C "*) exit 1 ;;
esac
exit 0
EOF
    chmod +x "$MOCK_BIN_DIR/$_b"
done
echo '{"version":1,"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5}}}' > "$HNC_TEST_DIR/data/rules.json"
echo "aa:bb:cc:dd:ee:05 douyin 3" > "$HNC_TEST_DIR/data/app_limits.flat"
printf '203.0.113.10 douyin\n2408:8000::99 douyin\n' > "$HNC_TEST_DIR/run/ip_app_map.flat"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
assert_mock_called "iptables|-w 2 -t filter -A HNC_QUIC_APPLIM -i wlan2 -m mac --mac-source aa:bb:cc:dd:ee:05 -d 203.0.113.10 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable" && \
assert_mock_called "ip6tables|-w 2 -t filter -A HNC_QUIC_APPLIM -i wlan2 -m mac --mac-source aa:bb:cc:dd:ee:05 -d 2408:8000::99 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable" && \
assert_mock_called "iptables|-w 2 -t filter -I FORWARD 1 -j HNC_QUIC_APPLIM" && \
assert_mock_called "ip6tables|-w 2 -t filter -I FORWARD 1 -j HNC_QUIC_APPLIM" && \
test_pass
mock_teardown

# ═══ 10. hnc_offload_guard 三态 tether_offload_disabled 无损备份还原 ═════
test_start "v5.40 T2-6: hnc_offload_guard T+0 压制与 tether_offload_disabled (null/0/1) 三态无损备份还原"
mock_setup
mkdir -p "$HNC_TEST_DIR/sysnet/wlan2"
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
echo "CAPABLE" > "$HNC_TEST_DIR/check_state"
echo "aa:bb:cc:dd:ee:05 douyin 3" > "$HNC_TEST_DIR/data/app_limits.flat"
echo '{"clsact_bpf_mode":"auto","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"

cat > "$HNC_TEST_DIR/bin/hnc_ipc" <<'EOF'
#!/bin/sh
echo "ipc|$*" >> "$MOCK_LOG"
echo "OK:OK"
EOF
cat > "$MOCK_BIN_DIR/settings" <<'EOF'
#!/bin/sh
echo "settings|$*" >> "$MOCK_LOG"
case "$1 $2 $3" in
    "get global tether_offload_disabled") cat "$HNC_DIR/mock_setting_val" ;;
    "put global tether_offload_disabled") echo "$4" > "$HNC_DIR/mock_setting_val" ;;
    "delete global tether_offload_disabled") echo "null" > "$HNC_DIR/mock_setting_val" ;;
esac
exit 0
EOF
chmod +x "$HNC_TEST_DIR/bin/hnc_ipc" "$MOCK_BIN_DIR/settings"

run_og() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" \
    HNC_SETTINGS_BIN="$MOCK_BIN_DIR/settings" \
    HNC_GUARD_CHECK_CMD="cat $HNC_TEST_DIR/check_state" \
        sh "$HNC_REPO_ROOT/bin/hnc_offload_guard.sh" "$@" >/dev/null 2>&1
}

# 状态 1: 初始为 null -> 压制设为 1, 恢复时必须执行 settings delete 还原为 null
echo "null" > "$HNC_TEST_DIR/mock_setting_val"
run_og apply
saved_null=$(tr -d ' \r\n' < "$HNC_TEST_DIR/run/orig_tether_offload_disabled" 2>/dev/null)
run_og restore
after_null=$(tr -d ' \r\n' < "$HNC_TEST_DIR/mock_setting_val")

# 状态 2: 初始为 0 -> 压制设为 1, 恢复时必须写回 0
echo "0" > "$HNC_TEST_DIR/mock_setting_val"
run_og apply
saved_zero=$(tr -d ' \r\n' < "$HNC_TEST_DIR/run/orig_tether_offload_disabled" 2>/dev/null)
run_og restore
after_zero=$(tr -d ' \r\n' < "$HNC_TEST_DIR/mock_setting_val")

# 状态 3: 用户原本就设为 1 -> 恢复时绝不能误改回 0, 必须保持 1!
: > "$MOCK_LOG"
echo "1" > "$HNC_TEST_DIR/mock_setting_val"
run_og apply
run_og restore
after_one=$(tr -d ' \r\n' < "$HNC_TEST_DIR/mock_setting_val")

assert_eq "null" "$saved_null" "备份 null" && \
assert_eq "null" "$after_null" "还原 null (delete)" && \
assert_eq "0" "$saved_zero" "备份 0" && \
assert_eq "0" "$after_zero" "还原 0" && \
assert_eq "1" "$after_one" "原值为 1 时保持 1 不变" && \
assert_mock_not_called "settings|put global tether_offload_disabled 0" "原值 1 时绝不能 put 0" && \
test_pass
mock_teardown

# ═══ 11. Wave 4 [BLOCKER-03]: Per-Protocol 回退 pref 3 / pref 51 一致性与 remove 清理 ═══
test_start "v5.40 W4-B03: apply_app_limits 回退路径 IPv6 fw 使用 pref 3(先 del 后 add), apply_app_qos 使用 pref 51"
mock_setup
v540_seed_al
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"down_mbps":10,"limit_enabled":true}}}
EOF
cat > "$MOCK_BIN_DIR/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$MOCK_LOG"
case "$*" in
    *"filter add"*"parent 1: protocol all"*)
        exit 2
        ;;
    *"qdisc show"*)
        echo "qdisc htb 1: root refcnt 2 default 0x9999"
        ;;
    *"class show"*)
        echo "class htb 1:1 root rate 1000Mbit ceil 1000Mbit"
        echo "class htb 1:5 parent 1:1 prio 0 rate 10Mbit ceil 10Mbit"
        ;;
esac
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/tc"
echo "aa:bb:cc:dd:ee:05 douyin 3" > "$HNC_TEST_DIR/data/app_limits.flat"
echo "203.0.113.10 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
assert_mock_called "tc|filter del dev wlan2 parent 1: protocol ipv6 pref 3 handle 0x00850000/0x00ff0000 fw" && \
assert_mock_called "tc|filter add dev wlan2 parent 1: protocol ipv6 pref 3 handle 0x00850000/0x00ff0000 fw flowid 1:5" && \
assert_mock_not_called "parent 1: protocol ipv6 pref 1" "IPv6 根 fw 过滤器不得再挂 pref 1" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    rm -f "$HNC_TEST_DIR/data/app_limits.flat" "$HNC_TEST_DIR/run/app_limits.devs"
    cat > "$HNC_TEST_DIR/run/app_qos.plan" <<'EOF'
iface wlan2
dev 5 aa:bb:cc:dd:ee:05 192.168.43.55
ip 1 1.1.1.1
EOF
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_qos.sh" >/dev/null 2>&1
    assert_mock_called "tc|filter add dev wlan2 parent 1: protocol ip pref 50 handle 0x00850000/0x00ff0000 fw flowid 1:5" && \
    assert_mock_called "tc|filter del dev wlan2 parent 1: protocol ipv6 pref 51 handle 0x00850000/0x00ff0000 fw" && \
    assert_mock_called "tc|filter add dev wlan2 parent 1: protocol ipv6 pref 51 handle 0x00850000/0x00ff0000 fw flowid 1:5" && \
    test_pass
    mock_teardown
fi

# ═══ 12. Wave 4 [BLOCKER-04]: 显式 teardown 补叶子 + 状态缺失内核扫描反推补叶子 + ensure_class 退避重试 ═══
test_start "v5.40 W4-B04: apply_app_qos teardown 补回叶子、apply_app_limits 缺 tree 文件内核扫描反推补叶子、ensure_class 锁竞争重试"
mock_setup
v540_seed_al
mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:5 parent 1:1 prio 0 rate 20Mbit ceil 20Mbit"
echo "wlan2 5" > "$HNC_TEST_DIR/run/app_qos.state"
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_qos.sh" teardown wlan2 5 >/dev/null 2>&1
assert_mock_called "parent 1:5 handle 1005:" "显式 teardown 无 app_limits 时必须补回 1:5 默认叶子" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    # 模拟 run/app_limits.tree 状态文件丢失, 仅内核存在 1:9001 / 1:9e05 parent 1:5
    : > "$MOCK_LOG"
    rm -f "$HNC_TEST_DIR/run/app_limits.tree" "$HNC_TEST_DIR/run/app_limits.devs" "$HNC_TEST_DIR/run/app_qos.state"
    mock_set_stdout tc "qdisc htb 1: root refcnt 2 default 0x9999
class htb 1:1 root rate 1000Mbit ceil 1000Mbit
class htb 1:5 parent 1:1 prio 0 rate 20Mbit ceil 20Mbit
class htb 1:9001 parent 1:5 prio 0 rate 4000Kbit ceil 4000Kbit
class htb 1:9e05 parent 1:5 prio 2 rate 16000Kbit ceil 20Mbit"
    : > "$HNC_TEST_DIR/data/app_limits.flat"
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/apply_app_limits.sh" >/dev/null 2>&1
    assert_mock_called "class del dev wlan2 classid 1:9001" && \
    assert_mock_called "class del dev wlan2 classid 1:9e05" && \
    assert_mock_called "parent 1:5 handle 1005:" "状态文件缺失时必须从内核子类 parent 1:5 反推并补回默认叶子" || { mock_teardown; true; }
fi

if [ -n "$MOCK_BIN_DIR" ]; then
    # 模拟短暂持有 tc_action.lock (300ms 后释放), 验证 ensure_class 退避重试成功不报 exit 12
    : > "$MOCK_LOG"
    mkdir -p "$HNC_TEST_DIR/run/tc_action.lock"
    echo "$$ set_limit $(date +%s)" > "$HNC_TEST_DIR/run/tc_action.lock/owner"
    (
        usleep 300000 2>/dev/null || sleep 1
        rm -rf "$HNC_TEST_DIR/run/tc_action.lock" 2>/dev/null
    ) &
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" ensure_class wlan2 5 192.168.43.55 >/dev/null 2>&1
    _ec_rc=$?
    wait 2>/dev/null
    assert_eq "0" "$_ec_rc" "ensure_class 遇短暂锁竞争应重试成功而非 exit 12" && \
    assert_mock_called "parent 1:5 handle 1005:" && \
    test_pass
    mock_teardown
fi

# ═══ 13. Wave 4 [RISK-02/03/04]: offload_guard 死锁回收、cleanup_tc 5301..7400 清理与 gate_lock 重入安全 ═══
test_start "v5.40 W4-RISK: offload_guard.lock 死 PID 回收、cleanup_tc 清理 5301..7400 及 gate_lock 重入不误删父锁"
mock_setup
mkdir -p "$HNC_TEST_DIR/sysnet/wlan2" "$HNC_TEST_DIR/run/offload_guard.lock"
echo "99999999" > "$HNC_TEST_DIR/run/offload_guard.lock/pid"
echo "1000" > "$HNC_TEST_DIR/run/offload_guard.lock/ts"
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
echo '{"clsact_bpf_mode":"off","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
HNC_DIR="$HNC_TEST_DIR" HNC_SYS_NET="$HNC_TEST_DIR/sysnet" sh "$HNC_REPO_ROOT/bin/hnc_offload_guard.sh" apply >/dev/null 2>&1
assert_file_not_exists "$HNC_TEST_DIR/run/offload_guard.lock" "offload_guard 应回收死锁并在退出时释放锁目录" || { mock_teardown; true; }

if [ -n "$MOCK_BIN_DIR" ]; then
    : > "$MOCK_LOG"
    # 预置陈旧死锁(>25s)验证 tc_action_lock 抢占与 cleanup_tc 5301..7400 清理
    mkdir -p "$HNC_TEST_DIR/run/tc_action.lock"
    echo "99999999 set_limit 1000" > "$HNC_TEST_DIR/run/tc_action.lock/owner"
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/tc_manager.sh" cleanup wlan2 >/dev/null 2>&1
    assert_mock_called "filter del dev wlan2 parent ffff: prio 5305 protocol ipv6" && \
    assert_mock_called "filter del dev wlan2 parent ffff: prio 6305 protocol ip" && \
    assert_mock_called "filter del dev wlan2 parent ffff: prio 7305 protocol ipv6" || { mock_teardown; true; }
fi

if [ -n "$MOCK_BIN_DIR" ]; then
    # 验证 hnc_lock.sh gate_lock 同进程与子进程重入获取不死锁、内层 gate_unlock 不提前删父级锁
    _reent_res=$(
        export HNC_DIR="$HNC_TEST_DIR"
        export HNC_SKIP_PATH_HARDENING=1
        rm -rf "$HNC_TEST_DIR/run/lock"
        . "$HNC_REPO_ROOT/bin/hnc_lock.sh"
        gate_lock || { echo "outer_fail"; exit 1; }
        gate_lock || { echo "inner_same_proc_fail"; exit 1; }
        gate_unlock
        [ -d "$HNC_TEST_DIR/run/lock/gate" ] || { echo "inner_deleted_parent"; exit 1; }
        sh -c '. "$1"; gate_lock || exit 2; gate_unlock' _ "$HNC_REPO_ROOT/bin/hnc_lock.sh" || { echo "child_reent_fail"; exit 1; }
        [ -d "$HNC_TEST_DIR/run/lock/gate" ] || { echo "child_deleted_parent"; exit 1; }
        gate_unlock
        [ ! -d "$HNC_TEST_DIR/run/lock/gate" ] || { echo "outer_not_cleaned"; exit 1; }
        echo "reent_ok"
    )
    assert_eq "reent_ok" "$_reent_res" "gate_lock 同进程与跨子进程重入保护" && test_pass
    mock_teardown
fi
