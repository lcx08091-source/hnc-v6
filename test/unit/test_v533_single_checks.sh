#!/system/bin/sh
# test/unit/test_v533_single_checks.sh — v5.33 第 5 步: 看门狗的检查只留 Go 一份(M2),
# httpd 启动参数只留一套。
#   - watchdog.sh 不再提供 probe_hotspot / check_health / httpd_drift / get_iface 四个
#     action(判断在 src/dpid/cmd/hnc_watchdog/native.go; 未知 action 退 64);
#   - service.sh launch_httpd_safe 与 Go 看门狗 httpdDaemon 的 httpd 参数相同, 都不带
#     -bind(远程端口由 httpd 按 remote_enabled 自己开关, remote_listener.go);
#   - 迁移热点网卡时不再杀 httpd「重绑 IP」; run/httpd_bind_ip 没有读写者了。
# 「改动前会失败」: v5.32 的四个 action 都存在(退 0 / 1); service.sh 按 remote_enabled
# 带 -bind 0.0.0.0 而看门狗不带参数; do_migrate 杀 httpd 并删 httpd_bind_ip。

WD="$HNC_REPO_ROOT/bin/watchdog.sh"

test_start "v5.33 watchdog.sh: 四个检查 action 已删(退 64), 动手的 action 还在"
bad=""
for a in probe_hotspot check_health httpd_drift get_iface; do
    HNC_DIR="$HNC_TEST_DIR" sh "$WD" action "$a" >/dev/null 2>&1
    rc=$?
    [ "$rc" = 64 ] || bad="$bad $a=$rc"
done
for a in full_restore full_init migrate tc_uplink_healthy capability_probe is_doze prune_dup_hotspotd rotate_logs cleanup_stale_rules; do
    grep -q "^        $a)" "$WD" || bad="$bad missing:$a"
done
for f in probe_valid_hotspot check_health check_httpd_bind_drift httpd_guard_install httpd_guard_remove; do
    grep -q "^$f()" "$WD" && bad="$bad still-defined:$f"
done
grep -v '^[[:space:]]*#' "$WD" | grep -q '_HEALTH_TS=\|_HEALTH_RC=' && bad="$bad health-cache-vars"
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 httpd 启动参数: service.sh 与 Go 看门狗相同, 都不带 -bind"
svc_line=$(awk '/^launch_httpd_safe\(\) \{/{f=1} f&&/hnc_httpd"/{print; exit}' "$HNC_REPO_ROOT/service.sh")
go_args=$(awk '/^func httpdDaemon\(\)/{f=1} f&&/^}/{exit} f' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" | grep 'args:')
bad=""
case "$svc_line" in *'-hnc-dir "$HNC_DIR"'*) ;; *) bad="$bad svc=[$svc_line]" ;; esac
awk '/^launch_httpd_safe\(\) \{/{f=1} f&&/^}/{exit} f' "$HNC_REPO_ROOT/service.sh" | grep -v '^[[:space:]]*#' | grep -q -- '-bind\|get-top' && bad="$bad svc-still-reads-remote"
case "$go_args" in *'[]string{"-hnc-dir", hncDir}'*) ;; *) bad="$bad go=[$go_args]" ;; esac
[ -z "$bad" ] && test_pass || test_fail "$bad"

test_start "v5.33 迁移不再杀 httpd; run/httpd_bind_ip / httpd.wanted 没有读写者"
bad=""
awk '/^do_migrate\(\) \{/{f=1} f&&/^}/{exit} f' "$WD" | grep -q 'kill -9 "\$wpid"' && bad="$bad migrate-kills-httpd"
hits=$(grep -rln 'httpd_bind_ip\|httpd\.wanted' "$HNC_REPO_ROOT/bin" "$HNC_REPO_ROOT/service.sh" \
       "$HNC_REPO_ROOT/src/dpid" "$HNC_REPO_ROOT/daemon/hnc_httpd" 2>/dev/null \
       | grep -v '_test\.go$\|/hnc_watchdog$\|/hnc_httpd/hnc_httpd$' \
       | while read -r f; do grep -v '^[[:space:]]*\(#\|//\)' "$f" | grep -q 'httpd_bind_ip\|httpd\.wanted' && echo "$f"; done)
[ -n "$hits" ] && bad="$bad readers:$(echo $hits)"
grep -q 'httpd_bind_ip' "$HNC_REPO_ROOT/post-fs-data.sh" || bad="$bad post-fs-data-stale-rm"
[ -z "$bad" ] && test_pass || test_fail "$bad"
