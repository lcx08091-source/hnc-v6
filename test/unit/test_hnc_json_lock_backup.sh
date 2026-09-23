#!/system/bin/sh
# test/unit/test_hnc_json_lock_backup.sh — v5.11 hnc_json 锁/备份回归
# 覆盖:
#   - add-array-unique 读-改-写整段持锁(旧实现读在锁外, 并发直调会丢条目)
#   - 写入后按文件名 prune 备份(旧实现从不清理, .json_backups 无限增长)
#   - 按文件名分别保留, rules.json 的高频写不会挤掉 device_names.json 的备份

HNC_JSON_BIN="$HNC_REPO_ROOT/bin/hnc_json"

test_start "hnc_json add-array-unique: concurrent direct callers do not lose entries"
mkdir -p "$HNC_TEST_DIR/run"
printf '%s\n' '{"version":1,"blacklist":[]}' > "$HNC_TEST_DIR/data/rules.json"
for i in 1 2 3 4 5 6; do
    HNC="$HNC_TEST_DIR" sh "$HNC_JSON_BIN" add-array-unique "$HNC_TEST_DIR/data/rules.json" blacklist "aa:bb:cc:dd:ee:0$i" >/dev/null 2>&1 &
done
wait
content=$(cat "$HNC_TEST_DIR/data/rules.json")
n=$(printf '%s' "$content" | grep -o 'aa:bb:cc:dd:ee:0' | wc -l | tr -d ' ')
assert_json_valid "$HNC_TEST_DIR/data/rules.json" && \
    assert_eq "6" "$n" "all 6 concurrent adds must survive (content: $content)" && test_pass

test_start "hnc_json prunes backups per file (HNC_JSON_BACKUP_KEEP)"
mkdir -p "$HNC_TEST_DIR/run"
printf '{}\n' > "$HNC_TEST_DIR/data/device_names.json"
printf '%s\n' '{"version":1,"devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
# 先给 device_names.json 留 2 份备份
for i in 1 2; do
    HNC="$HNC_TEST_DIR" HNC_JSON_BACKUP_KEEP=3 sh "$HNC_JSON_BIN" set-object-key \
        "$HNC_TEST_DIR/data/device_names.json" "aa:bb:cc:dd:ee:0$i" "n$i" str >/dev/null 2>&1
done
# rules.json 写 6 次, 只应保留 3 份, 且不能挤掉 device_names.json 的备份
for i in 1 2 3 4 5 6; do
    HNC="$HNC_TEST_DIR" HNC_JSON_BACKUP_KEEP=3 sh "$HNC_JSON_BIN" set-top \
        "$HNC_TEST_DIR/data/rules.json" "k$i" "$i" num >/dev/null 2>&1
done
BK="$HNC_TEST_DIR/data/.json_backups"
nr=$(ls "$BK"/rules.json.*.bak 2>/dev/null | wc -l | tr -d ' ')
nn=$(ls "$BK"/device_names.json.*.bak 2>/dev/null | wc -l | tr -d ' ')
assert_eq "3" "$nr" "rules.json backups should be pruned to 3" && \
    assert_eq "2" "$nn" "device_names.json backups must not be evicted by rules.json writes" && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && test_pass
