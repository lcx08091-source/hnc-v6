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
#   2. v5.33: legacy reader 与回退计数整体删除 —— rc=2 / rc=127 等真故障原样作为
#      json_set.sh 的退出码、不输出、不写任何计数文件(v5.32 及以前回退 grep reader
#      并计数)。
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

# ═══ v5.33: 真故障原样报错, 不再回退 legacy reader ═══════════════

test_start "v5.33: top_get rc=2 (invalid/missing JSON) → exit 2, no legacy reader"
seed; make_stub
out=$(js_stub 2 top_get whitelist_mode 2>/dev/null)
rc=$?
assert_eq "2" "$rc" "rc=2 应原样返回" && \
    assert_eq "" "$out" "不得回退 grep reader 读出值(v5.32 会读出 false)" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/json_legacy_fallback.count" "回退计数已删" && \
    test_pass

test_start "v5.33: device_get / name_get rc=127 (helper unavailable) → exit 127"
seed; make_stub
js_stub 127 device_get aa:bb:cc:dd:ee:ff mark_id >/dev/null 2>&1
r1=$?
js_stub 127 name_get aa:bb:cc:dd:ee:ff >/dev/null 2>&1
r2=$?
assert_eq "127 127" "$r1 $r2" "rc=127 应原样返回" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/json_legacy_fallback.count" "回退计数已删" && \
    test_pass

test_start "v5.33: write commands fail when hnc_json fails (no legacy writer)"
seed; make_stub
before=$(cat "$HNC_TEST_DIR/data/rules.json")
js_stub 1 top whitelist_mode true >/dev/null 2>&1; r1=$?
js_stub 1 device aa:bb:cc:dd:ee:ff up_mbps 5 >/dev/null 2>&1; r2=$?
js_stub 1 bl_add aa:bb:cc:dd:ee:ff >/dev/null 2>&1; r3=$?
after=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_eq "1 1 1" "$r1 $r2 $r3" "hnc_json 失败 = 写失败" && \
    assert_eq "$before" "$after" "rules.json 不得被 legacy writer 改写" && \
    test_pass
