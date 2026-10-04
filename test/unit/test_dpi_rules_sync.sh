#!/system/bin/sh
# test/unit/test_dpi_rules_sync.sh — v5.27 T1 bin/dpi_rules_sync.sh
# 用临时目录模拟「模块目录 → 运行目录」的开机同步(= 一次重启)。

SYNC="$HNC_REPO_ROOT/bin/dpi_rules_sync.sh"

# 造一个模块: $1 = versionCode, 其余参数 = bucket 文件名
make_mod() {
    ver="$1"; shift
    rm -rf "$HNC_TEST_DIR/mod"
    mkdir -p "$HNC_TEST_DIR/mod/data/dpi_rules.d"
    printf 'id=hotspot_network_control\nversion=vX\nversionCode=%s\n' "$ver" > "$HNC_TEST_DIR/mod/module.prop"
    for b in "$@"; do
        printf '{"rules_version":"mod-%s","rules":[]}\n' "$b" > "$HNC_TEST_DIR/mod/data/dpi_rules.d/$b"
    done
}

# 运行一次同步(= 一次开机)
run_sync() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_TEST_MODE=1 \
        sh "$SYNC" "$HNC_TEST_DIR/mod/data/dpi_rules.d" "$HNC_TEST_DIR/etc/dpi_rules.d" "$HNC_TEST_DIR/mod/module.prop"
}

RT_REL="etc/dpi_rules.d"

# 在运行目录放「这台手机自己的」规则
seed_runtime() {
    mkdir -p "$HNC_TEST_DIR/$RT_REL"
    echo '{"user":1}' > "$HNC_TEST_DIR/$RT_REL/99-user-custom.json"
    echo '{"exp":1}' > "$HNC_TEST_DIR/$RT_REL/_auto_expanded.json"
    echo '{"pro":1}' > "$HNC_TEST_DIR/$RT_REL/_auto_promoted.json"
    echo '{"imp":1}' > "$HNC_TEST_DIR/$RT_REL/_imported.json"
    echo '{"online":1}' > "$HNC_TEST_DIR/$RT_REL/97-online-update.json"
    echo 'online-v7' > "$HNC_TEST_DIR/etc/dpi_rules_online.version"
}

t_keep_user_and_learned() {
    test_start "sync: 保留 99 / _auto_* / _imported, 模块 bucket 复制到位"
    make_mod 5270001 00-core.json 10-im.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    run_sync || { test_fail "第二次同步失败"; return; }
    for f in 99-user-custom.json _auto_expanded.json _auto_promoted.json _imported.json 00-core.json 10-im.json; do
        assert_file_exists "$HNC_TEST_DIR/$RT_REL/$f" "$f 应存在" || return
    done
    assert_eq '{"exp":1}' "$(cat "$HNC_TEST_DIR/$RT_REL/_auto_expanded.json")" "_auto_expanded 内容不变" || return
    assert_eq '{"user":1}' "$(cat "$HNC_TEST_DIR/$RT_REL/99-user-custom.json")" "99 内容不变" || return
    test_pass
}

t_same_version_keeps_97() {
    test_start "sync: 模块版本没变 → 保留 97 与在线版本号"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    run_sync || { test_fail "重启同步失败"; return; }
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/97-online-update.json" "97 应保留" || return
    assert_file_exists "$HNC_TEST_DIR/etc/dpi_rules_online.version" "在线版本号应保留" || return
    assert_eq "5270001" "$(cat "$HNC_TEST_DIR/etc/.rules_sync_module_version")" "记下模块版本" || return
    test_pass
}

t_upgrade_drops_97() {
    test_start "sync: 升级模块 → 删 97 与在线版本号, 学到的规则仍在"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    make_mod 5270002 00-core.json
    run_sync || { test_fail "升级同步失败"; return; }
    assert_file_not_exists "$HNC_TEST_DIR/$RT_REL/97-online-update.json" "97 应删除" || return
    assert_file_not_exists "$HNC_TEST_DIR/etc/dpi_rules_online.version" "在线版本号应删除" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/_auto_promoted.json" "_auto_promoted 仍在" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/99-user-custom.json" "99 仍在" || return
    assert_eq "5270002" "$(cat "$HNC_TEST_DIR/etc/.rules_sync_module_version")" "版本号更新" || return
    test_pass
}

t_removed_bucket_disappears() {
    test_start "sync: 模块删掉的旧 bucket 跟着消失, 模块内容覆盖旧内容"
    make_mod 5270001 00-core.json 33-old.json
    run_sync || { test_fail "首次同步失败"; return; }
    echo 'stale' > "$HNC_TEST_DIR/$RT_REL/00-core.json"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "第二次同步失败"; return; }
    assert_file_not_exists "$HNC_TEST_DIR/$RT_REL/33-old.json" "33-old 应消失" || return
    assert_contains "$(cat "$HNC_TEST_DIR/$RT_REL/00-core.json")" "mod-00-core" "00-core 以模块为准" || return
    test_pass
}

t_missing_module_dir() {
    test_start "sync: 模块目录不存在 → 什么都不动"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    rm -rf "$HNC_TEST_DIR/mod/data/dpi_rules.d"
    run_sync
    assert_eq "0" "$?" "缺目录应返回 0" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/00-core.json" "原 bucket 不动" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/97-online-update.json" "97 不动" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/_auto_expanded.json" "_auto_expanded 不动" || return
    test_pass
}

t_cp_failure_keeps_files() {
    test_start "sync: cp 失败 → 运行目录与保留文件原样不动"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    make_mod 5270002 00-core.json 11-new.json
    # root 下只读目录拦不住写, 改用 PATH 里放一个必失败的 cp 模拟
    mkdir -p "$HNC_TEST_DIR/failbin"
    printf '#!/bin/sh\nexit 1\n' > "$HNC_TEST_DIR/failbin/cp"
    chmod +x "$HNC_TEST_DIR/failbin/cp"
    PATH="$HNC_TEST_DIR/failbin:$PATH" run_sync
    rc=$?
    assert_ne "0" "$rc" "cp 失败应返回非 0" || return
    for f in 99-user-custom.json _auto_expanded.json _auto_promoted.json _imported.json 97-online-update.json 00-core.json; do
        assert_file_exists "$HNC_TEST_DIR/$RT_REL/$f" "$f 应仍在" || return
    done
    assert_file_not_exists "$HNC_TEST_DIR/$RT_REL/11-new.json" "未完成的同步不应生效" || return
    assert_file_exists "$HNC_TEST_DIR/etc/dpi_rules_online.version" "失败时不动在线版本号" || return
    assert_eq "5270001" "$(cat "$HNC_TEST_DIR/etc/.rules_sync_module_version")" "失败时不改记录的版本" || return
    left=$(ls -a "$HNC_TEST_DIR/etc" | grep -c 'dpi_rules_sync')
    assert_eq "0" "$left" "不留暂存目录" || return
    # 恢复后再同步一次能成功
    run_sync || { test_fail "恢复后同步失败"; return; }
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/11-new.json" "恢复后新 bucket 到位" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/_imported.json" "恢复后 _imported 仍在" || return
    test_pass
}

t_recover_interrupted_swap() {
    test_start "sync: 上次换目录被中断(运行目录不在, .old 在)→ 先挪回再同步"
    make_mod 5270001 00-core.json
    run_sync || { test_fail "首次同步失败"; return; }
    seed_runtime
    mv "$HNC_TEST_DIR/$RT_REL" "$HNC_TEST_DIR/etc/.dpi_rules_sync.old.12345"
    run_sync || { test_fail "同步失败"; return; }
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/_auto_expanded.json" "中断前的学到规则被找回" || return
    assert_file_exists "$HNC_TEST_DIR/$RT_REL/99-user-custom.json" "中断前的 99 被找回" || return
    test_pass
}

t_keep_user_and_learned
t_same_version_keeps_97
t_upgrade_drops_97
t_removed_bucket_disappears
t_missing_module_dir
t_cp_failure_keeps_files
t_recover_interrupted_swap
