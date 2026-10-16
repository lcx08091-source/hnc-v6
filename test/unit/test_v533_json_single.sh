#!/system/bin/sh
# test/unit/test_v533_json_single.sh — v5.33 第 6 步: JSON 读写只留 hnc_json 一份。
#   - json_set.sh / json_set_batch.sh 的 legacy awk writer / grep reader 与回退计数删除,
#     hnc_json 失败 = 命令失败;
#   - hnc_json 新增 del-device / replace / 类型 auto(json_set.sh、json_set_batch.sh 的
#     两份类型推断合成一份); set-device 在没有 devices 对象时自建;
#   - run/json.lock 只有 hnc_json 一份实现(json_set.sh、json_doctor.sh 各自那份删掉,
#     hnc_json 的内层 hnc_json.lock 也删); json_doctor restore 走 hnc_json replace。
# 「改动前会失败」: v5.32 的 hnc_json 没有 del-device / replace / auto(用法错 rc 2);
# json_set_batch.sh 在 hnc_json 不在时退回逐字段串行写(成功); json_doctor 自己拷贝
# 并留 .pre-restore. 备份; json_set.sh / json_doctor.sh 自己拿 json.lock。

HJ="$HNC_REPO_ROOT/bin/hnc_json"

hj_seed() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run"
    # 注意: 不能写成 ${1:-{...}} —— 默认值里的第一个 } 会提前结束参数展开
    if [ -n "$1" ]; then
        printf '%s' "$1" > "$HNC_TEST_DIR/data/rules.json"
    else
        printf '%s' '{"version":1,"devices":{"aa:bb:cc:dd:ee:01":{"note":"a,b}c"},"aa:bb:cc:dd:ee:02":{"down_mbps":2}},"blacklist":[]}' \
            > "$HNC_TEST_DIR/data/rules.json"
    fi
}
hjr() { HNC="$HNC_TEST_DIR" sh "$HJ" "$@"; }

test_start "v5.33 hnc_json del-device: 删整条记录, 不存在的 MAC / 文件不报错"
hj_seed
hjr del-device "$HNC_TEST_DIR/data/rules.json" aa:bb:cc:dd:ee:01; r1=$?
c=$(cat "$HNC_TEST_DIR/data/rules.json")
hjr del-device "$HNC_TEST_DIR/data/rules.json" ff:ff:ff:ff:ff:ff; r2=$?
hjr del-device "$HNC_TEST_DIR/data/nope.json" aa:bb:cc:dd:ee:02; r3=$?
assert_eq "0 0 0" "$r1 $r2 $r3" "rc" && \
    assert_not_contains "$c" 'ee:01' && assert_contains "$c" 'ee:02' && \
    assert_json_valid "$HNC_TEST_DIR/data/rules.json" && \
    assert_file_not_exists "$HNC_TEST_DIR/data/nope.json" "不存在的文件不该被建出来" && test_pass

test_start "v5.33 hnc_json replace: 坏输入拒绝(rc 2, 原文件不动); 现有文件坏了也能替换并先备份"
hj_seed
before=$(cat "$HNC_TEST_DIR/data/rules.json")
printf '{"x":' | hjr replace "$HNC_TEST_DIR/data/rules.json" 2>/dev/null; r1=$?
after=$(cat "$HNC_TEST_DIR/data/rules.json")
printf '{"broken":' > "$HNC_TEST_DIR/data/rules.json"
printf '{"ok":1}' | hjr replace "$HNC_TEST_DIR/data/rules.json"; r2=$?
bak=$(ls "$HNC_TEST_DIR/data/.json_backups/" 2>/dev/null | grep -c '^rules\.json\..*\.bak$')
if [ "$bak" -lt 1 ]; then
    test_fail "replace 前没备份现有文件(bak=$bak, r1=$r1 r2=$r2)"
else
    assert_eq "2 0" "$r1 $r2" "rc" && assert_eq "$before" "$after" "坏输入不得改动原文件" && \
        assert_eq '{"ok":1}' "$(cat "$HNC_TEST_DIR/data/rules.json")" && \
        assert_file_not_exists "$HNC_TEST_DIR/run/json.lock" "锁应释放" && test_pass
fi

test_start "v5.33 hnc_json 类型 auto + 控制字符: 布尔 / null / 数字原样, IP 是字符串, \\001 丢弃 \\t 转义"
hj_seed '{"version":1}'
F="$HNC_TEST_DIR/data/rules.json"
hjr set-device "$F" aa:bb:cc:dd:ee:03 on true auto && \
hjr set-device "$F" aa:bb:cc:dd:ee:03 nil null auto && \
hjr set-device "$F" aa:bb:cc:dd:ee:03 n -2.5 auto && \
hjr set-device "$F" aa:bb:cc:dd:ee:03 ip 192.168.43.5 auto && \
hjr set-device "$F" aa:bb:cc:dd:ee:03 s "$(printf 'a\001b\tc')" auto
rc=$?
c=$(tr -d ' \n' < "$F")
assert_eq 0 "$rc" "set-device auto" && \
    assert_contains "$c" '"devices":{"aa:bb:cc:dd:ee:03":{' "没有 devices 对象时应自建" && \
    assert_contains "$c" '"on":true' && assert_contains "$c" '"nil":null' && assert_contains "$c" '"n":-2.5' && \
    assert_contains "$c" '"ip":"192.168.43.5"' && assert_contains "$c" '"s":"ab\tc"' && \
    assert_json_valid "$F" && test_pass

test_start "v5.33 json_set_batch: hnc_json 不在就失败(不再逐字段串行回退)"
hj_seed
before=$(cat "$HNC_TEST_DIR/data/rules.json")
HNC="$HNC_TEST_DIR" HNC_JSON=/nonexistent/hnc_json sh "$HNC_REPO_ROOT/bin/json_set_batch.sh" device aa:bb:cc:dd:ee:02 up_mbps 9 >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    test_fail "hnc_json 不在时批量写应失败(legacy 串行回退还在?)"
else
    assert_eq "$before" "$(cat "$HNC_TEST_DIR/data/rules.json")" "rules.json 不得被改" && test_pass
fi

test_start "v5.33 json_doctor restore: 走 hnc_json replace(恢复后合法, 坏文件经 hnc_json 备份, 无 pre-restore 副本)"
hj_seed
mkdir -p "$HNC_TEST_DIR/data/.json_backups"
printf '%s' '{"version":1,"devices":{},"blacklist":["aa:bb:cc:dd:ee:09"]}' > "$HNC_TEST_DIR/data/.json_backups/rules.json.20260101-000000.1.bak"
printf '{"broken":' > "$HNC_TEST_DIR/data/rules.json"
HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/json_doctor.sh" restore rules.json >/dev/null 2>&1
rc=$?
nbak=$(ls "$HNC_TEST_DIR/data/.json_backups/" | grep -c '^rules\.json\.[0-9].*\.bak$')
npre=$(ls "$HNC_TEST_DIR/data/.json_backups/" | grep -c 'pre-restore')
assert_eq 0 "$rc" "restore rc" && assert_json_valid "$HNC_TEST_DIR/data/rules.json" && \
    assert_contains "$(cat "$HNC_TEST_DIR/data/rules.json")" 'ee:09' && \
    assert_eq "2 0" "$nbak $npre" "原备份 + hnc_json 备份的坏文件, 没有 json_doctor 自己的 pre-restore 副本" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/json.lock" && test_pass

test_start "v5.33 json.lock 只有 hnc_json 一份实现; legacy 计数与脚本已删"
bad=""
# (json_doctor.sh 自己的 json_doctor.lock 只让 doctor 之间互斥, 不是 json.lock)
for f in json_set.sh json_set_batch.sh json_doctor.sh; do
    grep -v '^[[:space:]]*#' "$HNC_REPO_ROOT/bin/$f" | grep -q 'run/json\.lock\|JSON_LOCKDIR\|acquire_json_lock' && bad="$bad $f-locks"
done
grep -v '^[[:space:]]*#' "$HNC_REPO_ROOT/bin/json_set.sh" | grep -q 'mkdir "\$LOCKDIR"' && bad="$bad json_set-mkdir-lock"
grep -v '^[[:space:]]*#' "$HJ" | grep -q 'hnc_json\.lock\|OUTER_LOCK' && bad="$bad hnc_json-inner-lock"
grep -rh 'HNC_JSON_OUTER_LOCK_HELD' "$HNC_REPO_ROOT/bin" | grep -qv '^[[:space:]]*#' && bad="$bad outer-lock-env"
[ -e "$HNC_REPO_ROOT/bin/json_legacy_fallback_status.sh" ] && bad="$bad status-script"
grep -q 'json_legacy_fallback' "$HNC_REPO_ROOT/daemon/hnc_httpd/api_sla.go" "$HNC_REPO_ROOT/webroot/js/settings.js" && bad="$bad sla-field"
grep -v '^[[:space:]]*#' "$HNC_REPO_ROOT/bin/json_set.sh" | grep -q 'json_update_device_safe\|json_legacy_fallback_warn\|cfg_set)' && bad="$bad legacy-writer"
[ -z "$bad" ] && test_pass || test_fail "$bad"
