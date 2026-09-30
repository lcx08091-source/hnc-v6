#!/system/bin/sh
# test/unit/test_v6_sync_grace.sh — v5.20 v6_sync: 地址宽限 / 每台上限 / 增量补装 / sync_macs / 锁
# 全部走 mock(test/lib.sh 的 PATH 拦截),不碰真实 tc/iptables/ip。

V6="$HNC_REPO_ROOT/bin/v6_sync.sh"
MAC5="aa:bb:cc:dd:ee:05"
IPT_MARKED5="MARK       all  --  0.0.0.0/0            0.0.0.0/0            MAC $MAC5 MARK set 0x800005"
HDR5="#hnc_v6 iface=wlan2 mark=5 ing=0"

# neigh_lines <addr>... → 模拟 `ip -6 neigh` 输出(外加 device_detect 需要的 inet 行)
neigh_lines() {
    out="    inet 192.168.43.1/24 scope global wlan2"
    for a in "$@"; do
        out="$out
$a dev wlan2 lladdr $MAC5 REACHABLE"
    done
    printf '%s' "$out"
}

seed() {
    echo "wlan2" > "$HNC_TEST_DIR/run/iface.cache"
    mkdir -p "$HNC_TEST_DIR/run/v6"
    mock_set_stdout iptables "$IPT_MARKED5"
}

v6() {
    HNC_DIR="$HNC_TEST_DIR" sh "$V6" "$@" >/dev/null 2>&1
}

snap5() { cat "$HNC_TEST_DIR/run/v6/$MAC5" 2>/dev/null; }

# ═══ 宽限期内: 地址暂时从邻居表消失, filter 保留, 不 flush ═══════════
test_start "v6_sync grace: 地址消失未满宽限 → 保留 filter, 不重建"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::5 1000" "2408:1::6 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1100 v6 sync
assert_mock_not_called "filter del dev wlan2" "宽限期内不能 flush" && \
    assert_mock_not_called "filter add" "宽限期内不应重建" && \
    assert_contains "$(snap5)" "2408:1::6 1000" "消失的地址保留原时间戳" && \
    assert_contains "$(snap5)" "2408:1::5 1100" "当前地址刷新时间戳" && test_pass
mock_teardown

# ═══ 超过宽限: 过期地址的 filter 被删除 ═══════════════════════════
test_start "v6_sync grace: 地址消失超过宽限 → 重建时去掉过期地址"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::5 1000" "2408:1::6 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1400 v6 sync
assert_mock_called "filter del dev wlan2 parent 1: prio 205 protocol ipv6" "过期后必须 flush 该设备 prio 段" && \
    assert_mock_called "match ip6 dst 2408:1::5/128 flowid 1:5" "当前地址重建" && \
    assert_mock_not_called "2408:1::6/128" "过期地址不能再装" && \
    assert_not_contains "$(snap5)" "2408:1::6" "快照去掉过期地址" && test_pass
mock_teardown

# ═══ 自定义宽限(HNC_V6_GRACE) ══════════════════════════════════════
test_start "v6_sync grace: HNC_V6_GRACE=60 时 100s 前的地址已过期"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::5 1000" "2408:1::6 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_GRACE=60 HNC_V6_NOW=1100 v6 sync
assert_mock_not_called "2408:1::6/128" "过期地址不能再装" && \
    assert_mock_called "filter del dev wlan2 parent 1: prio 205 protocol ipv6" "应重建" && test_pass
mock_teardown

# ═══ 临时地址轮换: 只新增 → 增量补装, 不 flush ═══════════════════
test_start "v6_sync incremental: 新增临时地址只补装新 filter, 不 flush"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5 2408:1::7)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n' "$HDR5" "2408:1::5 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1010 v6 sync_macs "$MAC5"
assert_mock_called "filter add dev wlan2 parent 1: protocol ipv6 prio 205 u32 match ip6 dst 2408:1::7/128 flowid 1:5" "新地址必须补装" && \
    assert_mock_not_called "2408:1::5/128" "旧地址不重复装" && \
    assert_mock_not_called "filter del" "增量路径不能 flush" && \
    assert_contains "$(snap5)" "2408:1::7 1010" "快照记下新地址" && test_pass
mock_teardown

test_start "v6_sync incremental: 有上行 class 时同时补装 ifb0 src filter"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5 2408:1::7)"
mock_set_stdout tc "class htb 1:5 parent 1:1 prio 0 rate 5Mbit
filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n' "#hnc_v6 iface=wlan2 mark=5 ing=1" "2408:1::5 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1010 v6 sync_macs "$MAC5"
assert_mock_called "filter add dev ifb0 parent 1: protocol ipv6 prio 205 u32 match ip6 src 2408:1::7/128 flowid 1:5" "上行 filter 必须补装" && \
    assert_mock_not_called "filter del" "增量路径不能 flush" && test_pass
mock_teardown

test_start "v6_sync incremental: 新增地址但 tc 上 filter 已丢 → 全量重建"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5 2408:1::7)"
printf '%s\n%s\n' "$HDR5" "2408:1::5 1000" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1010 v6 sync_macs "$MAC5"
assert_mock_called "filter del dev wlan2 parent 1: prio 205 protocol ipv6" "filter 丢了要 flush 重建" && \
    assert_mock_called "match ip6 dst 2408:1::5/128" "旧地址也重装" && \
    assert_mock_called "match ip6 dst 2408:1::7/128" "新地址装上" && test_pass
mock_teardown

# ═══ 每台上限: 按最近看到保留 16 个 ════════════════════════════════
test_start "v6_sync cap: 超过 16 个地址时丢弃最旧的"
mock_setup
seed
addrs=""
i=10
while [ $i -le 25 ]; do addrs="$addrs 2408:1::$i"; i=$((i+1)); done
# shellcheck disable=SC2086
mock_set_stdout ip "$(neigh_lines $addrs)"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::1 900" "2408:1::2 950" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=1000 v6 sync
n=$(grep -c "filter add dev wlan2" "$MOCK_LOG")
assert_eq "16" "$n" "egress filter 条数应被限制为 16" && \
    assert_mock_not_called "2408:1::1/128" "最旧的 ::1 被截掉" && \
    assert_mock_not_called "2408:1::2/128" "次旧的 ::2 被截掉" && \
    assert_mock_called "2408:1::25/128" "当前地址都在" && \
    assert_contains "$(cat "$HNC_TEST_DIR/logs/v6_sync.log")" "capping to newest 16" "应记日志" && test_pass
mock_teardown

test_start "v6_sync cap: HNC_V6_MAX_ADDRS=2 按最近看到保留"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::9)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::1 900" "2408:1::2 950" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_MAX_ADDRS=2 HNC_V6_NOW=1000 v6 sync
assert_mock_called "2408:1::9/128" "当前地址" && \
    assert_mock_called "2408:1::2/128" "较新的旧地址保留" && \
    assert_mock_not_called "2408:1::1/128" "最旧的被截掉" && test_pass
mock_teardown

# ═══ 旧快照格式(无时间戳)向后兼容 ══════════════════════════════
test_start "v6_sync compat: 旧格式快照(仅地址)按刚看到处理, 不误删"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
mock_set_stdout tc "filter parent 1: protocol ipv6 pref 205 u32 chain 0"
printf '%s\n%s\n%s\n' "$HDR5" "2408:1::5" "2408:1::6" > "$HNC_TEST_DIR/run/v6/$MAC5"
HNC_V6_NOW=5000 v6 sync
assert_mock_not_called "filter del" "旧格式地址在宽限内, 不应重建" && \
    assert_contains "$(snap5)" "2408:1::6 5000" "旧格式地址补上时间戳" && test_pass
mock_teardown

# ═══ sync_macs: 无规则且无快照的设备静默跳过 ═══════════════════
test_start "v6_sync sync_macs: 未限速且无快照的 MAC 不动 tc; 非法 MAC 忽略"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
HNC_V6_NOW=1000 v6 sync_macs aa:bb:cc:dd:ee:99 'bad;rm' "$MAC5"
assert_mock_not_called "prio 299" "无关设备不应有 tc 操作" && \
    assert_mock_called "match ip6 dst 2408:1::5/128 flowid 1:5" "有 mark 的设备照常同步" && \
    assert_contains "$(cat "$HNC_TEST_DIR/logs/v6_sync.log")" "bad mac" "非法 MAC 记日志" && \
    assert_not_contains "$(cat "$HNC_TEST_DIR/logs/v6_sync.log")" "Clear aa:bb:cc:dd:ee:99" "无快照不刷 clear 日志" && test_pass
mock_teardown

test_start "v6_sync sync_macs: 大写 MAC 规范成小写"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
HNC_V6_NOW=1000 v6 sync_macs AA:BB:CC:DD:EE:05
assert_mock_called "match ip6 dst 2408:1::5/128 flowid 1:5" "大写 MAC 也能匹配 mark" && \
    assert_file_exists "$HNC_TEST_DIR/run/v6/$MAC5" && test_pass
mock_teardown

# ═══ 锁: 持有者已死的 stale 锁被回收; 执行完释放 ═══════════════
test_start "v6_sync lock: stale 锁(pid 已死)被回收, 结束后锁释放"
mock_setup
seed
mock_set_stdout ip "$(neigh_lines 2408:1::5)"
mkdir -p "$HNC_TEST_DIR/run/v6_sync.lock"
echo 999999 > "$HNC_TEST_DIR/run/v6_sync.lock/pid"
HNC_V6_NOW=1000 v6 sync
rc=$?
assert_exit_zero "$rc" "stale 锁不应阻塞" && \
    assert_mock_called "match ip6 dst 2408:1::5/128" "应正常同步" && \
    assert_eq "no" "$([ -d "$HNC_TEST_DIR/run/v6_sync.lock" ] && echo yes || echo no)" "锁目录应被释放" && test_pass
mock_teardown
