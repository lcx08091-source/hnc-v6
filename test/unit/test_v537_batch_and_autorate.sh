#!/system/bin/sh
# test/unit/test_v537_batch_and_autorate.sh — 验证 --noflush 原子批处理、自动回退、客户端互访隔离与 global_shaper_tune 热调速

v537_make_env() {
    mock_setup
    export HNC_DIR="$HNC_TEST_DIR"
    echo "ACTIVE:wlan2" > "$HNC_DIR/run/hnc_state"
    echo "wlan2" > "$HNC_DIR/run/active_iface"
    cat > "$HNC_DIR/data/devices.json" <<'EOF'
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","online":true}}
EOF
    cat > "$HNC_DIR/data/rules.json" <<'EOF'
{"devices":{}}
EOF
}

test_start "v5.37: apply_app_limits uses single iptables-restore/ip6tables-restore --noflush batch"
v537_make_env
cat > "$MOCK_BIN_DIR/iptables-restore" <<'EOF'
#!/bin/sh
echo "iptables-restore|$*" >> "$MOCK_LOG"
cat >> "$MOCK_LOG.v4batch"
exit 0
EOF
cat > "$MOCK_BIN_DIR/ip6tables-restore" <<'EOF'
#!/bin/sh
echo "ip6tables-restore|$*" >> "$MOCK_LOG"
cat >> "$MOCK_LOG.v6batch"
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/iptables-restore" "$MOCK_BIN_DIR/ip6tables-restore"
echo "aa:bb:cc:dd:ee:01 bilibili 8" > "$HNC_DIR/data/app_limits.flat"
cat > "$HNC_DIR/run/ip_app_map.flat" <<'EOF'
203.0.113.10 bilibili
203.0.113.11 bilibili
2408:8000::10 bilibili
EOF
sh "$HNC_DIR/bin/apply_app_limits.sh"
assert_eq "1" "$(grep -c '^iptables-restore|.*--noflush' "$MOCK_LOG")" "single v4 --noflush commit" &&
assert_eq "1" "$(grep -c '^ip6tables-restore|.*--noflush' "$MOCK_LOG")" "single v6 --noflush commit" &&
assert_contains "$(cat "$MOCK_LOG.v4batch")" "-A HNC_AL_C1 -s 203.0.113.10 -j MARK --set-mark 0x900001" "v4 rule in batch" &&
assert_contains "$(cat "$MOCK_LOG.v6batch")" "-A HNC_AL_C1 -s 2408:8000::10 -j MARK --set-mark 0x900001" "v6 rule in batch" &&
test_pass
mock_teardown

test_start "v5.37: apply_app_limits falls back cleanly when iptables-restore --noflush fails"
v537_make_env
cat > "$MOCK_BIN_DIR/iptables-restore" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$MOCK_BIN_DIR/iptables-restore"
echo "aa:bb:cc:dd:ee:01 bilibili 5" > "$HNC_DIR/data/app_limits.flat"
echo "198.51.100.7 bilibili" > "$HNC_DIR/run/ip_app_map.flat"
sh "$HNC_DIR/bin/apply_app_limits.sh"
assert_contains "$(cat "$MOCK_LOG")" "-A HNC_AL_C1 -s 198.51.100.7 -j MARK --set-mark 0x900001" "per-rule fallback executed" &&
test_pass
mock_teardown

test_start "v5.37: apply_app_qos commits HNC_APP_QOS_IP via single --noflush batch"
v537_make_env
cat > "$MOCK_BIN_DIR/iptables-restore" <<'EOF'
#!/bin/sh
echo "iptables-restore|$*" >> "$MOCK_LOG"
cat >> "$MOCK_LOG.qos_v4"
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/iptables-restore"
cat > "$MOCK_BIN_DIR/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$MOCK_LOG"
case "$*" in
    "class show dev wlan2 classid 1:5"|"class show dev wlan2")
        echo "class htb 1:5 parent 1:1 rate 20Mbit ceil 20Mbit"
        ;;
esac
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/tc"
cat > "$HNC_DIR/run/app_qos.plan" <<'EOF'
iface wlan2
dev 5 aa:bb:cc:dd:ee:01 192.168.43.10
ip 1 203.0.113.88
ip 3 203.0.113.99
EOF
sh "$HNC_DIR/bin/apply_app_qos.sh"
assert_eq "1" "$(grep -c '^iptables-restore|.*--noflush' "$MOCK_LOG")" "single qos --noflush commit" &&
assert_contains "$(cat "$MOCK_LOG.qos_v4")" "-A HNC_APP_QOS_IP -s 203.0.113.88 -j MARK --set-xmark 0x200000/0x600000" "RT rule in batch" &&
test_pass
mock_teardown

test_start "v5.37: tc_manager global_shaper_tune hot-updates 1:1 ceil without resetting 1:9999 leaf"
v537_make_env
cat > "$MOCK_BIN_DIR/tc" <<'EOF'
#!/bin/sh
echo "tc|$*" >> "$MOCK_LOG"
case "$*" in
    "qdisc show dev wlan2"|"qdisc show dev ifb0") echo "qdisc htb 1: root refcnt 2" ;;
    "class show dev wlan2"|"class show dev ifb0") echo "class htb 1:1 root rate 100Mbit ceil 100Mbit" ;;
esac
exit 0
EOF
chmod +x "$MOCK_BIN_DIR/tc"
sh "$HNC_DIR/bin/tc_manager.sh" global_shaper_tune wlan2 68mbit 18mbit
assert_contains "$(cat "$MOCK_LOG")" "class change dev wlan2 parent 1: classid 1:1 htb rate 68mbit ceil 68mbit" "downlink hot-tuned" &&
assert_contains "$(cat "$MOCK_LOG")" "class change dev ifb0 parent 1: classid 1:1 htb rate 18mbit ceil 18mbit" "uplink hot-tuned" &&
assert_eq "0" "$(grep -c 'parent 1:9999' "$MOCK_LOG")" "1:9999 AQM leaf untouched" &&
test_pass
mock_teardown

test_start "v5.37: iptables_manager set_isolation installs dual-stack HNC_ISOLATE drop chain"
v537_make_env
sh "$HNC_DIR/bin/iptables_manager.sh" set_isolation wlan2 on
assert_contains "$(cat "$MOCK_LOG")" "-A HNC_ISOLATE -i wlan2 -o wlan2 -j DROP" "L3 client isolation DROP installed" &&
test_pass
mock_teardown
