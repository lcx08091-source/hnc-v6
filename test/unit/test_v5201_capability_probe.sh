#!/system/bin/sh
# test/unit/test_v5201_capability_probe.sh — v5.20.1
# 真机自检(RMX5010, 开机 3 分钟)报 "run/capabilities.json 不存在或损坏; 本次自检已重新探测"。
# 复现并锁定两个根因:
#   A. `dmesg | grep -c ... || echo 0`: 无匹配时输出 "0\n0" → JSON 数值位非法 → 整个文件解析失败
#      (自检重新探测后仍然 nil —— 与真机报告完全一致)。
#   B. v5.20 在写 capabilities.json 之前同步跑 qdisc_caps.sh probe(无总超时), 模块加载卡住
#      时基础能力文件迟迟不落盘。现在先写(qdisc_probe=pending), 再带总超时补写。

CAP="$HNC_REPO_ROOT/bin/capability_probe.sh"

cap_mock_setup() {
    CPM="$HNC_TEST_DIR/cpmock"
    mkdir -p "$CPM"
    # tc: 全部成功(find_bin 优先用 $HNC/bin/hnc_tc)
    cat > "$HNC_TEST_DIR/bin/hnc_tc" <<'EOF'
#!/bin/sh
[ "$1" = "-V" ] && { echo "tc utility, iproute2-mock"; exit 0; }
exit 0
EOF
    cat > "$CPM/ip" <<'EOF'
#!/bin/sh
exit 0
EOF
    # dmesg: 由 MOCK_DMESG_FILE 提供内容
    cat > "$CPM/dmesg" <<'EOF'
#!/bin/sh
cat "$MOCK_DMESG_FILE" 2>/dev/null
exit 0
EOF
    chmod +x "$HNC_TEST_DIR/bin/hnc_tc" "$CPM/ip" "$CPM/dmesg"
    : > "$CPM/dmesg.txt"
    export MOCK_DMESG_FILE="$CPM/dmesg.txt"
}
cap_run() {
    HNC="$HNC_TEST_DIR" HNC_TEST_MODE=1 HNC_SKIP_PATH_HARDENING=1 PATH="$CPM:$PATH" \
        sh "$CAP" "$@" >/dev/null 2>&1
}
cap_json() { cat "$HNC_TEST_DIR/run/capabilities.json" 2>/dev/null; }
# 假 qdisc_caps.sh: probe 时按 MOCK_QC_MODE 行为; 记录收到的 QDISC_CAPS_NO_LOAD
cap_fake_qdisc() {
    cat > "$HNC_TEST_DIR/bin/qdisc_caps.sh" <<'EOF'
#!/bin/sh
case "$1" in
    chosen) echo "" ; exit 0 ;;
esac
echo "noload=$QDISC_CAPS_NO_LOAD" >> "$HNC_DIR/run/fake_qc.log"
case "$MOCK_QC_MODE" in
    hang) exec sleep 30 ;;
    cake) echo cake ;;
    *) echo sfq ;;
esac
exit 0
EOF
}

test_start "capability_probe: dmesg 无 AVC 匹配 → capabilities.json 仍是合法 JSON(旧版 0\\n0 损坏)"
cap_mock_setup
printf 'random kernel line\nanother line\n' > "$CPM/dmesg.txt"
cap_run
j=$(cap_json)
assert_json_valid "$HNC_TEST_DIR/run/capabilities.json" "无匹配时 JSON 必须可解析" && \
    assert_contains "$j" '"selinux_avc_denied_recent": 0,' && test_pass
unset MOCK_DMESG_FILE

test_start "capability_probe: dmesg 有 2 条 HNC AVC → 计数 2 且 JSON 合法"
cap_mock_setup
printf 'avc: denied { read } for comm="hnc_dpid"\nfoo\navc:  denied { write } for comm="hotspotd"\n' > "$CPM/dmesg.txt"
cap_run
assert_json_valid "$HNC_TEST_DIR/run/capabilities.json" && \
    assert_contains "$(cap_json)" '"selinux_avc_denied_recent": 2,' && test_pass
unset MOCK_DMESG_FILE

test_start "capability_probe: tc -V 带 TAB/控制字符 → 仍是合法 JSON"
cap_mock_setup
cat > "$HNC_TEST_DIR/bin/hnc_tc" <<'EOF'
#!/bin/sh
[ "$1" = "-V" ] && { printf 'tc\tutility\001 "q" \\ x\n'; exit 0; }
exit 0
EOF
chmod +x "$HNC_TEST_DIR/bin/hnc_tc"
cap_run
assert_json_valid "$HNC_TEST_DIR/run/capabilities.json" && test_pass
unset MOCK_DMESG_FILE

test_start "capability_probe: qdisc_caps 卡住 → 先写基础能力(pending), 总超时后补写 timeout 并记标记"
cap_mock_setup
cap_fake_qdisc
export MOCK_QC_MODE=hang
t0=$(date +%s)
( CAP_QDISC_TIMEOUT=3 cap_run ) &
bgp=$!
# 探针卡在 qdisc 阶段时, capabilities.json 必须已经存在
seen_pending=0
i=0
while [ $i -lt 20 ]; do
    if grep -q '"qdisc_probe": "pending"' "$HNC_TEST_DIR/run/capabilities.json" 2>/dev/null; then
        seen_pending=1; break
    fi
    sleep 0.2 2>/dev/null || sleep 1
    i=$((i + 1))
done
wait $bgp
t1=$(date +%s)
el=$((t1 - t0))
j=$(cap_json)
assert_eq "1" "$seen_pending" "卡住期间应已写出 qdisc_probe=pending 的 capabilities.json" && \
    assert_json_valid "$HNC_TEST_DIR/run/capabilities.json" && \
    assert_contains "$j" '"qdisc_probe": "timeout"' && \
    assert_contains "$j" '"tc_htb": true' && \
    assert_eq "yes" "$([ "$el" -le 12 ] && echo yes || echo no)" "总超时应生效(耗时 ${el}s)" && \
    { [ ! -r /proc/sys/kernel/random/boot_id ] || assert_file_exists "$HNC_TEST_DIR/run/qdisc_caps_timeout" "超时标记"; } && \
    test_pass
unset MOCK_QC_MODE MOCK_DMESG_FILE

test_start "capability_probe: 本次开机已超时过 → 再跑时 QDISC_CAPS_NO_LOAD=1(不再碰模块)"
if [ ! -r /proc/sys/kernel/random/boot_id ]; then
    test_skip "no boot_id"
else
    cap_mock_setup
    cap_fake_qdisc
    export MOCK_QC_MODE=cake
    cat /proc/sys/kernel/random/boot_id > "$HNC_TEST_DIR/run/qdisc_caps_timeout"
    cap_run
    j=$(cap_json)
    assert_contains "$(cat "$HNC_TEST_DIR/run/fake_qc.log")" "noload=1" && \
        assert_contains "$j" '"qdisc_probe": "done"' && \
        assert_contains "$j" '"qdisc_lowlat_chosen": "cake"' && \
        assert_json_valid "$HNC_TEST_DIR/run/capabilities.json" && test_pass
    unset MOCK_QC_MODE MOCK_DMESG_FILE
fi

test_start "capability_probe: 正常路径 qdisc 探测完成 → qdisc_probe=done, 首次无标记时不传 NO_LOAD"
cap_mock_setup
cap_fake_qdisc
export MOCK_QC_MODE=sfq
cap_run
assert_contains "$(cat "$HNC_TEST_DIR/run/fake_qc.log")" "noload=" && \
    assert_not_contains "$(cat "$HNC_TEST_DIR/run/fake_qc.log")" "noload=1" && \
    assert_contains "$(cap_json)" '"qdisc_probe": "done"' && \
    assert_contains "$(cap_json)" '"qdisc_lowlat_chosen": "sfq"' && test_pass
unset MOCK_QC_MODE MOCK_DMESG_FILE
