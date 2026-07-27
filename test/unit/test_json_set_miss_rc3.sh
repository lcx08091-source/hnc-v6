#!/system/bin/sh
# test/unit/test_json_set_miss_rc3.sh — v5.9.3 BUG-008 回归测试
#
# 背景(归因反转):
#   bin/hnc_json 用 exit 3 表示"键不存在" —— 这是正常结果不是故障。
#   json_set.sh 的三个读桥接(top_get / device_get / name_get)老实现用
#   `if ! json_xxx_hnc_json ...` 一把兜住,把 rc=3 和 rc=1(锁超时)/
#   rc=2(文件缺失或 JSON 非法)/ rc=127(helper 不可用)同等当故障:
#   计进 run/json_legacy_fallback.count 并回退 legacy reader。
#   热路径上"键不存在"是常态(device_detect.sh 每轮对每台未命名设备问一次),
#   于是该计数变成只会猛涨的无意义大数,SLA 面板据此误报,
#   "计数长期为 0 才能退役 400 行 legacy writer"的条件也永远达不成。
#
# 本文件锁死的不变量:
#   1. rc=3 → 退出码 0、stdout 为空、count **不增加**、不回退 legacy
#   2. rc=2 / rc=127 等真故障 → count 仍然增加(这才是有效告警信号)
#
# 实现说明:用桩 hnc_json(json_set.sh 的 HNC_JSON 是可被环境变量覆盖的)
# 而不是真 helper,这样退出码是确定的,且不受宿主机有没有 /system/bin/sh、
# json_guard.sh 能不能直接 exec 之类的环境差异影响。

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"

# 桩脚本的 shebang:真机是 /system/bin/sh,Linux 沙箱是 /bin/sh。
if [ -x /system/bin/sh ]; then
    STUB_SHEBANG='#!/system/bin/sh'
else
    STUB_SHEBANG='#!/bin/sh'
fi

# 造一个按 $FAKE_HNC_JSON_RC 退出的假 hnc_json
make_stub() {
    mkdir -p "$HNC_TEST_DIR/bin"
    {
        echo "$STUB_SHEBANG"
        echo '# 测试桩:模拟 hnc_json 的退出码语义'
        echo 'exit ${FAKE_HNC_JSON_RC:-3}'
    } > "$HNC_TEST_DIR/bin/fake_hnc_json"
    chmod 755 "$HNC_TEST_DIR/bin/fake_hnc_json"
}

seed() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run"
    printf '%s' '{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}' \
        > "$HNC_TEST_DIR/data/rules.json"
    printf '%s' '{}' > "$HNC_TEST_DIR/data/device_names.json"
    rm -f "$HNC_TEST_DIR/run/json_legacy_fallback.count"
}

# 读 fallback 计数(文件不存在 = 0)
fb_count() {
    if [ -f "$HNC_TEST_DIR/run/json_legacy_fallback.count" ]; then
        cat "$HNC_TEST_DIR/run/json_legacy_fallback.count" 2>/dev/null
    else
        echo 0
    fi
}

# 用桩跑 json_set.sh
js_stub() {
    _rc=$1; shift
    HNC="$HNC_TEST_DIR" \
    HNC_JSON="$HNC_TEST_DIR/bin/fake_hnc_json" \
    FAKE_HNC_JSON_RC="$_rc" \
        sh "$JSON_SET" "$@"
}

# ═══ rc=3(键不存在)不得计数 ═══════════════════════════════════

test_start "BUG-008: top_get rc=3 (key missing) does not count as legacy fallback"
seed; make_stub
out=$(js_stub 3 top_get definitely_absent_key 2>/dev/null)
rc=$?
assert_eq "0" "$rc" "键不存在应按正常空答案返回 0" && \
    assert_eq "" "$out" "键不存在应输出空" && \
    assert_eq "0" "$(fb_count)" "rc=3 不得增加 json_legacy_fallback.count" && \
    test_pass

test_start "BUG-008: device_get rc=3 (device/key missing) does not count"
seed; make_stub
out=$(js_stub 3 device_get aa:bb:cc:dd:ee:ff mark_id 2>/dev/null)
rc=$?
assert_eq "0" "$rc" "设备/字段不存在应返回 0" && \
    assert_eq "" "$out" "应输出空" && \
    assert_eq "0" "$(fb_count)" "rc=3 不得增加 json_legacy_fallback.count" && \
    test_pass

test_start "BUG-008: name_get rc=3 (unnamed device) does not count"
seed; make_stub
out=$(js_stub 3 name_get aa:bb:cc:dd:ee:ff 2>/dev/null)
rc=$?
assert_eq "0" "$rc" "设备没有手工命名应返回 0" && \
    assert_eq "" "$out" "应输出空" && \
    assert_eq "0" "$(fb_count)" "rc=3 不得增加 json_legacy_fallback.count" && \
    test_pass

test_start "BUG-008: repeated misses keep the counter at 0"
seed; make_stub
i=0
while [ $i -lt 5 ]; do
    js_stub 3 top_get absent_key >/dev/null 2>&1
    js_stub 3 name_get aa:bb:cc:dd:ee:ff >/dev/null 2>&1
    i=$((i + 1))
done
assert_eq "0" "$(fb_count)" "10 次未命中后计数仍应为 0(这正是热路径的真实形态)" && \
    test_pass

# ═══ 真故障仍然要计数(反向断言,防止把分流写成"一律不计")═══════

test_start "BUG-008: top_get rc=2 (invalid/missing JSON) still counts as fallback"
seed; make_stub
js_stub 2 top_get whitelist_mode >/dev/null 2>&1
assert_eq "1" "$(fb_count)" "rc=2 是真故障,必须计数" && \
    test_pass

test_start "BUG-008: top_get rc=127 (helper unavailable) still counts as fallback"
seed; make_stub
js_stub 127 top_get whitelist_mode >/dev/null 2>&1
assert_eq "1" "$(fb_count)" "rc=127 是真故障,必须计数" && \
    test_pass

test_start "BUG-008: rc=2 fallback still returns the real value via legacy reader"
seed; make_stub
out=$(js_stub 2 top_get whitelist_mode 2>/dev/null)
assert_eq "false" "$out" "回退 legacy reader 后仍要读到真实值" && \
    test_pass
