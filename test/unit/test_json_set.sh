#!/system/bin/sh
# test/unit/test_json_set.sh — json_set.sh 命令单元测试
# 覆盖: init_dirs / top / device / bl_add / bl_del / reset / cfg_set / cfg_get / name_set / name_get / top_get

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"

# helper: 在隔离环境跑 json_set,设 HNC=$HNC_TEST_DIR
js() {
    HNC="$HNC_TEST_DIR" sh "$JSON_SET" "$@"
}

# helper: 创建初始 rules.json
seed_rules() {
    mkdir -p "$HNC_TEST_DIR/data"
    if [ -n "$1" ]; then
        printf '%s' "$1" > "$HNC_TEST_DIR/data/rules.json"
    else
        printf '%s' '{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}' > "$HNC_TEST_DIR/data/rules.json"
    fi
}

# ═══ init_dirs ═══════════════════════════════════════════
test_start "init_dirs creates required directories"
js init_dirs >/dev/null 2>&1
assert_file_exists "$HNC_TEST_DIR/data/rules.json" && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "init_dirs is idempotent (run twice no error)"
js init_dirs >/dev/null 2>&1
js init_dirs >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "second init_dirs should succeed" && test_pass

# ═══ top (顶层字段更新) ═══════════════════════════════════
test_start "top updates existing field"
seed_rules
js top hotspot_auto true
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"hotspot_auto": true' && test_pass

test_start "top inserts new field if not exists"
seed_rules '{"version":1,"devices":{}}'
js top new_field 42
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"new_field": 42' && test_pass

test_start "top preserves other fields after update"
seed_rules '{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[]}'
js top whitelist_mode true
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"version":1' && \
    assert_contains "$content" '"whitelist_mode": true' && \
    assert_contains "$content" '"blacklist":[]' && test_pass

test_start "top handles string values with quotes"
seed_rules
js top hotspot_iface '"wlan2"'
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" 'wlan2' && test_pass

# ═══ device (设备字段更新) ═══════════════════════════════
test_start "device adds new device with single field"
seed_rules
js device aa:bb:cc:dd:ee:ff up_mbps 24
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" 'aa:bb:cc:dd:ee:ff' && \
    assert_contains "$content" '"up_mbps"' && \
    assert_contains "$content" '24' && test_pass

test_start "device updates existing field of existing device"
seed_rules
js device aa:bb:cc:dd:ee:ff up_mbps 10
js device aa:bb:cc:dd:ee:ff up_mbps 20
content=$(cat "$HNC_TEST_DIR/data/rules.json")
# 应该只有一个 up_mbps:20,不应该有 up_mbps:10
case "$content" in
    *'"up_mbps":10'*) test_fail "old value still present" ;;
    *'"up_mbps": 10'*) test_fail "old value still present" ;;
    *) assert_contains "$content" '20' && test_pass ;;
esac

test_start "device preserves other devices when updating one"
seed_rules
js device aa:bb:cc:dd:ee:01 up_mbps 10
js device aa:bb:cc:dd:ee:02 up_mbps 20
js device aa:bb:cc:dd:ee:01 down_mbps 5
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" 'ee:01' && \
    assert_contains "$content" 'ee:02' && \
    assert_contains "$content" '20' && \
    assert_contains "$content" '5' && test_pass

test_start "device handles ip string field"
seed_rules
js device aa:bb:cc:dd:ee:ff ip '"192.168.43.5"'
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '192.168.43.5' && test_pass

test_start "device boolean field stays unquoted"
seed_rules
js device aa:bb:cc:dd:ee:ff limit_enabled true
content=$(cat "$HNC_TEST_DIR/data/rules.json")
# limit_enabled 后面的值应该是 true (无引号),不应该是 "true" (字符串)
# 容忍冒号后有/无空格
assert_contains "$content" 'limit_enabled' && \
    assert_not_contains "$content" '"true"' && test_pass

# ═══ bl_add / bl_del ═════════════════════════════════════
test_start "bl_add adds mac to empty blacklist"
seed_rules
js bl_add aa:bb:cc:dd:ee:ff
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"blacklist":["aa:bb:cc:dd:ee:ff"]' && test_pass

test_start "bl_add does not duplicate existing mac"
seed_rules
js bl_add aa:bb:cc:dd:ee:ff
js bl_add aa:bb:cc:dd:ee:ff
content=$(cat "$HNC_TEST_DIR/data/rules.json")
# 数 mac 出现次数,应该 = 1
count=$(echo "$content" | grep -oE 'aa:bb:cc:dd:ee:ff' | wc -l)
assert_eq "1" "$count" "mac should appear once" && test_pass

test_start "bl_add appends to non-empty blacklist"
seed_rules
js bl_add aa:bb:cc:dd:ee:01
js bl_add aa:bb:cc:dd:ee:02
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" 'ee:01' && \
    assert_contains "$content" 'ee:02' && test_pass

test_start "bl_del removes mac from blacklist"
seed_rules
js bl_add aa:bb:cc:dd:ee:01
js bl_add aa:bb:cc:dd:ee:02
js bl_del aa:bb:cc:dd:ee:01
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_not_contains "$content" 'ee:01' && \
    assert_contains "$content" 'ee:02' && test_pass

test_start "bl_del on non-existent mac is no-op"
seed_rules
js bl_del aa:bb:cc:dd:ee:ff
rc=$?
assert_eq "0" "$rc" "should succeed silently" && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

# ═══ JSON 完整性: 任何写命令后 JSON 必须有效 ═════════════
test_start "JSON stays valid after 10 mixed operations"
seed_rules
for i in 1 2 3 4 5; do
    js device "aa:bb:cc:dd:ee:0$i" up_mbps "$((i * 10))" >/dev/null 2>&1
done
js bl_add aa:bb:cc:dd:ee:01 >/dev/null 2>&1
js top hotspot_auto true >/dev/null 2>&1
js bl_del aa:bb:cc:dd:ee:01 >/dev/null 2>&1
js top whitelist_mode true >/dev/null 2>&1
assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

# ═══ cfg_set / cfg_get (config.json) ════════════════════
test_start "cfg_set creates config.json on first call"
mkdir -p "$HNC_TEST_DIR/data"
js cfg_set theme dark
assert_file_exists "$HNC_TEST_DIR/data/config.json" && \
    assert_json_valid "$HNC_TEST_DIR/data/config.json" && test_pass

test_start "cfg_get returns value set by cfg_set"
js cfg_set theme dark
val=$(js cfg_get theme)
assert_eq "dark" "$val" "should return 'dark'" && test_pass

test_start "cfg_set updates existing key"
js cfg_set theme dark
js cfg_set theme light
val=$(js cfg_get theme)
assert_eq "light" "$val" "should return 'light'" && test_pass

test_start "cfg_get returns empty for missing key"
js cfg_set theme dark
val=$(js cfg_get nonexistent_key)
assert_eq "" "$val" "should return empty string" && test_pass

# ═══ name_set / name_get / name_del (device_names.json) ═
test_start "name_set creates device_names.json"
js name_set aa:bb:cc:dd:ee:ff "客厅平板"
assert_file_exists "$HNC_TEST_DIR/data/device_names.json" && \
    assert_json_valid "$HNC_TEST_DIR/data/device_names.json" && test_pass

test_start "name_get returns name set by name_set"
js name_set aa:bb:cc:dd:ee:ff "Living Room TV"
val=$(js name_get aa:bb:cc:dd:ee:ff)
assert_eq "Living Room TV" "$val" "name should match" && test_pass

test_start "name_set with chinese characters preserved"
js name_set aa:bb:cc:dd:ee:ff "客厅平板"
val=$(js name_get aa:bb:cc:dd:ee:ff)
assert_eq "客厅平板" "$val" "chinese should round-trip" && test_pass

test_start "name_del removes name"
js name_set aa:bb:cc:dd:ee:ff "TV"
js name_del aa:bb:cc:dd:ee:ff
val=$(js name_get aa:bb:cc:dd:ee:ff)
assert_eq "" "$val" "should be empty after del" && test_pass

# v3.4.11 P0-6 回归测试: hostname 含 " 不破坏 JSON
test_start "name_set with double quote does not corrupt JSON"
js name_set aa:bb:cc:dd:ee:ff 'Bob"s TV'
assert_json_valid "$HNC_TEST_DIR/data/device_names.json" && test_pass

# ═══ 锁机制 (P0-2 回归测试) ═══════════════════════════════
test_start "concurrent writes do not corrupt JSON"
seed_rules
# 启 5 个并发写
for i in 1 2 3 4 5; do
    js device "aa:bb:cc:dd:ee:0$i" up_mbps "$i" >/dev/null 2>&1 &
done
wait
assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

# ═══ top_get (rules.json 顶层字段读) ═════════════════════
test_start "top_get returns boolean field"
seed_rules '{"version":1,"hotspot_auto":true,"devices":{}}'
val=$(js top_get hotspot_auto)
assert_contains "$val" "true" && test_pass

test_start "top_get returns string field"
seed_rules '{"version":1,"hotspot_iface":"wlan2","devices":{}}'
val=$(js top_get hotspot_iface)
assert_contains "$val" "wlan2" && test_pass

# ═══ reset (清空所有规则) ════════════════════════════════
test_start "reset clears devices but keeps top fields"
seed_rules
js device aa:bb:cc:dd:ee:01 up_mbps 10
js device aa:bb:cc:dd:ee:02 up_mbps 20
js bl_add aa:bb:cc:dd:ee:01
js top hotspot_auto true
js reset
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_not_contains "$content" 'ee:01' && \
    assert_not_contains "$content" 'ee:02' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass


# ═══ hotfix18.0 JSON writer fuzz / regression tests ═════════════
test_start "top update preserves comma inside existing string"
seed_rules '{"version":1,"hotspot_ssid":"我家,客房","devices":{},"blacklist":[]}'
js top hotspot_ssid "新家,客房"
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"hotspot_ssid":"新家,客房"' && \
    assert_contains "$content" '"devices":{}' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "top update preserves right brace inside string"
seed_rules '{"version":1,"hotspot_ssid":"A}B,old","devices":{},"blacklist":[]}'
js top hotspot_ssid "A}B,new"
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"hotspot_ssid":"A}B,new"' && \
    assert_contains "$content" '"blacklist":[]' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "device update preserves comma and brace in string field"
seed_rules '{"version":1,"devices":{"aa:bb:cc:dd:ee:ff":{"note":"old,value}x","down_mbps":8}},"blacklist":[]}'
js device aa:bb:cc:dd:ee:ff note "new,value}x"
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"note":"new,value}x"' && \
    assert_contains "$content" '"down_mbps":8' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "device insert quotes IP-like strings"
seed_rules '{"version":1,"devices":{},"blacklist":[]}'
js device aa:bb:cc:dd:ee:ff ip 192.168.43.5
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"ip": "192.168.43.5"' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "device update preserves escaped quote in old string"
seed_rules '{"version":1,"devices":{"aa:bb:cc:dd:ee:ff":{"note":"Bob\"s,old","down_mbps":8}},"blacklist":[]}'
js device aa:bb:cc:dd:ee:ff note 'Bob"s,new'
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"note":"Bob\"s,new"' && \
    assert_contains "$content" '"down_mbps":8' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

# ═══ hotfix18.1 remaining JSON writer regression tests ══════════
test_start "bl_add/bl_del keep blacklist valid when other arrays contain brackets"
seed_rules '{"version":1,"devices":{},"blacklist":["aa:bb:cc:dd:ee:01"],"whitelist":["not]blacklist"]}'
js bl_add aa:bb:cc:dd:ee:02
js bl_del aa:bb:cc:dd:ee:01
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_not_contains "$content" 'ee:01' && \
    assert_contains "$content" 'ee:02' && \
    assert_contains "$content" 'not]blacklist' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "device_remove handles braces and commas inside device string values"
seed_rules '{"version":1,"devices":{"aa:bb:cc:dd:ee:01":{"note":"a,b}c","down_mbps":8},"aa:bb:cc:dd:ee:02":{"down_mbps":2}},"blacklist":[]}'
js device_remove aa:bb:cc:dd:ee:01
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_not_contains "$content" 'ee:01' && \
    assert_contains "$content" 'ee:02' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "device_patch preserves comma and brace in value"
seed_rules '{"version":1,"devices":{},"blacklist":[]}'
js device_patch aa:bb:cc:dd:ee:ff note 'a,b}c' ip 192.168.43.5
content=$(cat "$HNC_TEST_DIR/data/rules.json")
assert_contains "$content" '"note": "a,b}c"' && \
    assert_contains "$content" '"ip": "192.168.43.5"' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass

test_start "name_set/name_del handle comma brace quote and backslash"
js name_set aa:bb:cc:dd:ee:ff '客厅,电视}Bob"s\\TV'
assert_json_valid "$HNC_TEST_DIR/data/device_names.json" || test_fail "device_names invalid after name_set"
js name_del aa:bb:cc:dd:ee:ff
content=$(cat "$HNC_TEST_DIR/data/device_names.json")
assert_not_contains "$content" 'aa:bb:cc:dd:ee:ff' && \
    assert_json_valid "$HNC_TEST_DIR/data/device_names.json" && test_pass

test_start "tpl_set/tpl_del handle special template names"
js tpl_set '游戏,严格}Bob"s\\profile' 1 2 3 4 5
assert_json_valid "$HNC_TEST_DIR/data/templates.json" || test_fail "templates invalid after tpl_set"
js tpl_del '游戏,严格}Bob"s\\profile'
content=$(cat "$HNC_TEST_DIR/data/templates.json")
assert_not_contains "$content" 'down_mbps' && \
    assert_json_valid "$HNC_TEST_DIR/data/templates.json" && test_pass
