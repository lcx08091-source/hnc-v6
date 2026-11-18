#!/system/bin/sh
# test/unit/test_v533_misc_single.sh — v5.33 第 7 步: 零散的「两份」只留一份。
#   - DPI 规则: 删 data/dpi_rules.json(dpi_rules.d/ 的逐字节派生副本)与读它的各条退路;
#   - clsact 旧键 clsact_bpf_enabled: post-fs-data 开机一次性迁成 clsact_bpf_mode 后删除;
#   - 模块 → 运行目录同步: bin/hnc_runtime_sync.sh 一份(post-fs-data.sh / service.sh 共用);
#   - prune_duplicate_hotspotd / pid 校验: bin/hnc_proc.sh 一份(service.sh / watchdog.sh 共用)。
# 「改动前会失败」: v5.32 有 data/dpi_rules.json 且 --export 在没有用户规则时导出整套
# 策展规则; post-fs-data 没有迁移块; 两个开机脚本各有一份 cp -rf 同步与 chmod 清单;
# service.sh / watchdog.sh 各定义一份 prune_duplicate_hotspotd, service.sh 还有 _verify_pid。

R="$HNC_REPO_ROOT"

# 去掉注释行再 grep(只看代码)
code_grep() { # $1 = 模式, 其余 = 文件
    _pat=$1; shift
    for _f in "$@"; do
        grep -v '^[[:space:]]*\(#\|//\)' "$_f" 2>/dev/null | grep -q -- "$_pat" && echo "$_f"
    done
}

test_start "v5.33 DPI 规则只有 dpi_rules.d/: 单文件删除, 没有代码再读 dpi_rules.json"
bad=""
[ -e "$R/data/dpi_rules.json" ] && bad="$bad data/dpi_rules.json-still-there"
[ -e "$R/tools/dpi_rules_split.py" ] && bad="$bad split-tool"
hits=$(code_grep 'etc/dpi_rules\.json\|data/dpi_rules\.json\|"dpi_rules\.json"' \
    "$R/service.sh" "$R/bin/dpi_rules_import.sh" "$R/bin/dpi_rules_update.sh" \
    $(ls "$R"/daemon/hnc_httpd/*.go "$R"/src/dpid/output/*.go | grep -v '_test\.go$'))
[ -n "$hits" ] && bad="$bad readers:$(echo $hits)"
n=$(ls "$R"/data/dpi_rules.d/*.json 2>/dev/null | wc -l)
[ "$n" -ge 10 ] || bad="$bad rules-dir-files=$n"
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 dpi_rules_import --export: 没有用户规则时导出空规则(不再导出整套策展规则)"
mkdir -p "$HNC_TEST_DIR/etc" "$HNC_TEST_DIR/run"
out=$(HNC_DIR="$HNC_TEST_DIR" MODDIR="$R" HNC_DPI_RULES_NO_REBIND=1 sh "$R/bin/dpi_rules_import.sh" --export 2>/dev/null)
HNC_DIR="$HNC_TEST_DIR" MODDIR="$R" HNC_DPI_RULES_NO_REBIND=1 sh "$R/bin/dpi_rules_import.sh" --install-default >/dev/null 2>&1
rc=$?
assert_eq '{"schema_version":"1.0","rules_version":"empty","rules":[]}' "$out" "export" && \
    assert_eq 1 "$rc" "--install-default 已删(当成不存在的源文件, 退 1)" && test_pass

# post-fs-data 的迁移块原文(从注释行到 fi), 在临时目录里跑
mig_run() { # $1 = rules.json 内容
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run"
    printf '%s' "$1" > "$HNC_TEST_DIR/data/rules.json"
    awk '/^# v5.33: 旧开关键 clsact_bpf_enabled/{f=1} f{print} f&&/^fi$/{exit}' "$R/post-fs-data.sh" \
        > "$HNC_TEST_DIR/mig.sh"
    HNC_DIR="$HNC_TEST_DIR" MODDIR="$R" sh -c '. "$1"' _ "$HNC_TEST_DIR/mig.sh"
    tr -d ' \n' < "$HNC_TEST_DIR/data/rules.json"
}
test_start "v5.33 clsact 旧键开机迁移: true → on / 已有 mode 保留 / 迁完删旧键 / 没旧键不动"
r1=$(mig_run '{"version":1,"clsact_bpf_enabled":true,"devices":{}}')
r2=$(mig_run '{"version":1,"clsact_bpf_enabled":true,"clsact_bpf_mode":"off"}')
r3=$(mig_run '{"version":1,"clsact_bpf_enabled":false}')
r4=$(mig_run '{"version":1,"devices":{}}')
bad=""
case "$r1" in *'"clsact_bpf_mode":"on"'*) ;; *) bad="$bad r1=$r1" ;; esac
case "$r2" in *'"clsact_bpf_mode":"off"'*) ;; *) bad="$bad r2=$r2" ;; esac
case "$r3" in *'"clsact_bpf_mode":"auto"'*) ;; *) bad="$bad r3=$r3" ;; esac
for r in "$r1" "$r2" "$r3"; do case "$r" in *clsact_bpf_enabled*) bad="$bad old-key-left" ;; esac; done
[ "$r4" = '{"version":1,"devices":{}}' ] || bad="$bad r4=$r4"
[ -s "$HNC_TEST_DIR/mig.sh" ] || bad="$bad no-migration-block"
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 hnc_runtime_sync.sh: 两个开机脚本共用; 拷 bin / webroot / 有变化的 httpd, 不建 api / test"
M="$HNC_TEST_DIR/mod"; H="$HNC_TEST_DIR/rt"
mkdir -p "$M/bin" "$M/webroot" "$M/daemon/hnc_httpd" "$M/test"
echo 'echo hi' > "$M/bin/a.sh"; echo 'x' > "$M/bin/hnc_dpid"; echo '<html>' > "$M/webroot/index.html"
echo 'httpd-v2' > "$M/daemon/hnc_httpd/hnc_httpd"; echo t > "$M/test/t.sh"
mkdir -p "$H/daemon/hnc_httpd"; echo 'httpd-v1' > "$H/daemon/hnc_httpd/hnc_httpd"
HNC_SKIP_PATH_HARDENING=1 sh "$R/bin/hnc_runtime_sync.sh" sync "$M" "$H" > "$HNC_TEST_DIR/sync.log" 2>&1
rc=$?
bad=""
[ "$rc" = 0 ] || bad="$bad rc=$rc"
[ -f "$H/bin/a.sh" ] && [ -x "$H/bin/hnc_dpid" ] && [ -f "$H/webroot/index.html" ] || bad="$bad not-copied"
[ "$(cat "$H/daemon/hnc_httpd/hnc_httpd" 2>/dev/null)" = httpd-v2 ] || bad="$bad httpd-not-refreshed"
[ -e "$H/api" ] || [ -e "$H/test" ] && bad="$bad api/test-created"
grep -q 'refreshed hnc_httpd' "$HNC_TEST_DIR/sync.log" || bad="$bad no-log"
for f in post-fs-data.sh service.sh; do
    grep -q 'hnc_runtime_sync.sh" sync' "$R/$f" || bad="$bad $f-not-calling"
    [ -n "$(code_grep 'cp -rf "$MODDIR"*/bin/\|cp -rf "\$MODDIR/bin/' "$R/$f")" ] && bad="$bad $f-own-copy"
    [ -n "$(code_grep 'hnc_tc_ingress mdns_resolve' "$R/$f")" ] && bad="$bad $f-own-chmod-list"
done
grep -q 'sync_runtime_from_moddir()' "$R/service.sh" && bad="$bad old-function"
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 prune_duplicate_hotspotd / pid 校验只在 hnc_proc.sh 一份"
bad=""
grep -q '^prune_duplicate_hotspotd()' "$R/bin/hnc_proc.sh" || bad="$bad not-in-hnc_proc"
for f in service.sh bin/watchdog.sh; do
    grep -q '^prune_duplicate_hotspotd()' "$R/$f" && bad="$bad $f-defines-own"
done
grep -q '^_verify_pid()' "$R/service.sh" && bad="$bad _verify_pid"
grep -q 'hnc_proc.sh' "$R/bin/watchdog.sh" || bad="$bad watchdog-not-sourcing"
# pidfile_live_pid: 假 /proc —— pid 对得上才输出, 被复用成别的进程 → 空
P="$HNC_TEST_DIR/proc"; mkdir -p "$P/4242" "$P/4343" "$HNC_TEST_DIR/run"
printf '/data/local/hnc/bin/hotspotd\000-d\000' > "$P/4242/cmdline"
printf '/system/bin/app_process\000' > "$P/4343/cmdline"
echo 4242 > "$HNC_TEST_DIR/run/a.pid"; echo 4343 > "$HNC_TEST_DIR/run/b.pid"
a=$(HNC_PROC_ROOT="$P" sh -c '. "$1"; pidfile_live_pid "$2" hotspotd' _ "$R/bin/hnc_proc.sh" "$HNC_TEST_DIR/run/a.pid")
b=$(HNC_PROC_ROOT="$P" sh -c '. "$1"; pidfile_live_pid "$2" hotspotd' _ "$R/bin/hnc_proc.sh" "$HNC_TEST_DIR/run/b.pid")
[ "$a" = 4242 ] && [ -z "$b" ] || bad="$bad live_pid:a=$a,b=$b"
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 httpd 应用分级直接用 dpid 的 output.AppTier(删照抄的副本)"
grep -q 'func appTier(category string) int { return output.AppTier(category) }' "$R/daemon/hnc_httpd/api_conn.go" \
    && ! grep -q '"third_party_telemetry"' "$R/daemon/hnc_httpd/api_conn.go" && test_pass || test_fail "api_conn.go 还有自己的分级表"
