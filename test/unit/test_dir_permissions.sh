#!/system/bin/sh
# test/unit/test_dir_permissions.sh — v5.9.3 BUG-009 回归测试
#
# 背景:
#   仓库里一处 `chmod 777` 都没有,真机上那一堆 0777 目录是
#   "`mkdir -p` 不带 mode + 引导脚本继承 magiskd/KSU 的 umask=0" 的必然结果。
#   0777 且无 sticky 位 → 任何能 traverse 进来的非 root 进程都能 unlink 掉
#   run/local_admin.secret 再写一个自己的,伪造 X-HNC-Local-Admin 拿到 root
#   级写 API(data/tokens.json 同理)。secret 文件本身早就是 0600 —— 问题
#   一直在目录上。
#
# 本文件锁死的不变量:
#   1. json_set.sh init_dirs 之后,顶层 / data / logs / run 必须是 700
#   2. bin / api / webroot 是 755(可执行与静态资源,里面没有凭据)
#   3. 无论调用方的 umask 多松(模拟 magiskd 的 umask 0),结果都不能是 0777
#
# 说明:post-fs-data.sh / service.sh 里的同款 chmod 无法在单测里跑
#   (它们硬编码 /data/local/hnc 且要 root),init_dirs 是唯一可被测试覆盖、
#   且逻辑与那两处一致的入口。

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"

# 取目录的八进制权限位;stat -c 在 Android/Linux 都支持
mode_of() {
    stat -c %a "$1" 2>/dev/null
}

# 以指定 umask 跑 init_dirs(模拟真机引导环境)
init_dirs_with_umask() {
    ( umask "$1"; HNC="$HNC_TEST_DIR" sh "$JSON_SET" init_dirs >/dev/null 2>&1 )
}

test_start "BUG-009: init_dirs locks top/data/logs/run to 700"
init_dirs_with_umask 022
assert_eq "700" "$(mode_of "$HNC_TEST_DIR")"        "HNC 顶层应为 700" && \
    assert_eq "700" "$(mode_of "$HNC_TEST_DIR/data")" "data/ 应为 700(tokens.json)" && \
    assert_eq "700" "$(mode_of "$HNC_TEST_DIR/logs")" "logs/ 应为 700" && \
    assert_eq "700" "$(mode_of "$HNC_TEST_DIR/run")"  "run/ 应为 700(local_admin.secret)" && \
    test_pass

test_start "BUG-009: init_dirs keeps bin/api/webroot at 755"
init_dirs_with_umask 022
assert_eq "755" "$(mode_of "$HNC_TEST_DIR/bin")"     "bin/ 应为 755" && \
    assert_eq "755" "$(mode_of "$HNC_TEST_DIR/api")"     "api/ 应为 755" && \
    assert_eq "755" "$(mode_of "$HNC_TEST_DIR/webroot")" "webroot/ 应为 755" && \
    test_pass

test_start "BUG-009: umask 0 (magiskd) must not leave any 0777 dir"
# 这是真机上产生 0777 的确切条件:magiskd 把 umask=0 传给 post-fs-data/service。
init_dirs_with_umask 000
bad=""
for d in "" /data /logs /run /bin /api /webroot; do
    m=$(mode_of "$HNC_TEST_DIR$d")
    [ "$m" = "777" ] && bad="$bad $HNC_TEST_DIR$d($m)"
done
assert_eq "" "$bad" "umask=0 下也不允许出现 0777 目录, 命中:$bad" && \
    test_pass

test_start "BUG-009: umask 0 still yields 700 on credential dirs"
init_dirs_with_umask 000
assert_eq "700" "$(mode_of "$HNC_TEST_DIR/run")"  "umask=0 下 run/ 仍应为 700" && \
    assert_eq "700" "$(mode_of "$HNC_TEST_DIR/data")" "umask=0 下 data/ 仍应为 700" && \
    test_pass

test_start "BUG-009: init_dirs is still idempotent after the chmod split"
init_dirs_with_umask 022
init_dirs_with_umask 022
rc=$?
assert_eq "0" "$rc" "重复 init_dirs 不应失败" && \
    assert_eq "700" "$(mode_of "$HNC_TEST_DIR/run")" "第二次跑完 run/ 仍是 700" && \
    test_pass

# ═══ 引导脚本侧:静态断言(无法在沙箱里真跑 /data/local/hnc)═════════

test_start "BUG-009: post-fs-data.sh sets umask and chmods credential dirs"
PFD="$HNC_REPO_ROOT/post-fs-data.sh"
c=$(cat "$PFD" 2>/dev/null)
assert_contains "$c" "umask 022" "post-fs-data.sh 应显式设 umask" && \
    assert_contains "$c" "chmod 700 \$HNC_DIR \$HNC_DIR/data \$HNC_DIR/logs \$HNC_DIR/run" \
        "post-fs-data.sh 应把顶层/data/logs/run 收到 700" && \
    assert_not_contains "$c" "umask 077" \
        "不得用 umask 077(cp -rf 不带 -p 会把脚本/二进制压到不可执行)" && \
    test_pass

test_start "BUG-009: service.sh sets umask and chmods credential dirs"
SVC="$HNC_REPO_ROOT/service.sh"
c=$(cat "$SVC" 2>/dev/null)
assert_contains "$c" "umask 022" "service.sh 应显式设 umask(WebUI 重启后端直接 fork 它)" && \
    assert_contains "$c" "chmod 700 \$HNC_DIR \$HNC_DIR/logs \$RUN" \
        "service.sh 应把顶层/logs/run 收到 700" && \
    test_pass
