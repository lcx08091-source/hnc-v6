#!/system/bin/sh
if ! command -v test_start >/dev/null 2>&1; then
    exec sh "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" "unit/$(basename "$0" .sh)"
fi
# v5.22+: webui_guard.sh —— WebUI 访问白名单落防火墙(INPUT 链 HNC_WEBUI, v4+v6)
# 用一个"有状态"的 iptables 桩(规则存在文本 DB 里, -C/-D/-X 语义与真 iptables 一致),
# 验证: 各模式规则内容、重复 apply 幂等(不叠加跳转/规则)、remove 拆干净、
# 配置损坏 fail-closed、非法条目不进规则、公共 Wi-Fi wlan0/eth+ 封堵与单芯片 AP 保护。

GSCRIPT="$HNC_REPO_ROOT/bin/webui_guard.sh"

gseed() {  # $1 = webui_access.json 内容(空 = 不建文件)
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
rm -f "$HNC_TEST_DIR/run/iface_detect.json" "$HNC_TEST_DIR/run/hnc_state" "$HNC_TEST_DIR/run/active_iface" \
      "$HNC_TEST_DIR/run/hotspot_iface" "$HNC_TEST_DIR/run/iface.cache" "$HNC_TEST_DIR/data/rules.json" "$HNC_TEST_DIR/no_reject"
[ -n "$1" ] && printf '%s\n' "$1" > "$HNC_TEST_DIR/data/webui_access.json"
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
# 用法: sh ipt_stub.sh <db> <iptables 参数...>
db=$1; shift
touch "$db"
echo "$*" >> "$db.calls"
op=$1; chain=$2; shift 2
case "$op" in
  -I) case "$1" in [0-9]*) shift ;; esac ;;
esac
spec="$*"
if [ -f "${db%/*}/no_reject" ]; then
  case "$op:$spec" in
    -A:*-j\ REJECT*|-I:*-j\ REJECT*) exit 1 ;;
  esac
fi
has_chain() { grep -qxF "CHAIN $1" "$db"; }
case "$op" in
  -N) has_chain "$chain" && exit 1; echo "CHAIN $chain" >> "$db" ;;
  -F) has_chain "$chain" || exit 1
      grep -vF "RULE $chain " "$db" > "$db.t"; mv "$db.t" "$db" ;;
  -X) has_chain "$chain" || exit 1
      grep -qE -- "-j $chain\$" "$db" && exit 1          # 仍被引用
      grep -qF "RULE $chain " "$db" && exit 1            # 非空
      grep -vxF "CHAIN $chain" "$db" > "$db.t"; mv "$db.t" "$db" ;;
  -A) [ "$chain" = INPUT ] || has_chain "$chain" || exit 1
      echo "RULE $chain $spec" >> "$db" ;;
  -I) { echo "RULE $chain $spec"; cat "$db"; } > "$db.t"; mv "$db.t" "$db" ;;
  -C) grep -qxF "RULE $chain $spec" "$db"; exit $? ;;
  -D) grep -qxF "RULE $chain $spec" "$db" || exit 1
      awk -v l="RULE $chain $spec" 'd==0 && $0==l {d=1; next} {print}' "$db" > "$db.t"; mv "$db.t" "$db" ;;
  -L|-S) exit 0 ;;
  *) exit 1 ;;
esac
exit 0
STUB
rm -f "$HNC_TEST_DIR/db4" "$HNC_TEST_DIR/db6" "$HNC_TEST_DIR"/db*.calls
}
grun() {
    HNC_IPT="sh $HNC_TEST_DIR/ipt_stub.sh $HNC_TEST_DIR/db4" \
    HNC_IP6T="sh $HNC_TEST_DIR/ipt_stub.sh $HNC_TEST_DIR/db6" \
    HNC_WEBUI_PORTS="8443 8080" HNC_DIR="$HNC_TEST_DIR" sh "$GSCRIPT" "$@" 2>/dev/null | tail -1
}
db4() { cat "$HNC_TEST_DIR/db4" 2>/dev/null; }
db6() { cat "$HNC_TEST_DIR/db6" 2>/dev/null; }
cnt() { printf '%s\n' "$1" | grep -cxF "$2"; }

test_start "webui_guard: no config → mode=all, lo + cellular REJECT + RETURN, jumps for each port (v4+v6)"
gseed ""
out=$(grun apply)
d4=$(db4); d6=$(db6)
[ "$out" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i lo -j RETURN")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i rmnet+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -j RETURN")" = 1 ] \
  && [ "$(cnt "$d4" "RULE INPUT -p tcp --dport 8443 -j HNC_WEBUI")" = 1 ] \
  && [ "$(cnt "$d4" "RULE INPUT -p tcp --dport 8080 -j HNC_WEBUI")" = 1 ] \
  && [ "$(cnt "$d6" "RULE INPUT -p tcp --dport 8443 -j HNC_WEBUI")" = 1 ] \
  && ! printf '%s\n' "$d4" | grep -q "HNC_WEBUI -p tcp -j REJECT" \
  && grep -q "^applied mode=all" "$HNC_TEST_DIR/run/webui_guard.state" \
  && test_pass || test_fail "out=$out db4=$d4"

test_start "webui_guard: allowlist → MAC rules both families, IPs per family, tail REJECT tcp-reset"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07","192.168.43.20","fd00::20"],"updated":1}'
out=$(grun apply)
d4=$(db4); d6=$(db6)
[ "$out" = "WEBUI_GUARD=applied mode=allowlist entries=3 v6=1" ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -m mac --mac-source aa:bb:cc:dd:ee:07 -j RETURN")" = 1 ] \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -m mac --mac-source aa:bb:cc:dd:ee:07 -j RETURN")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -s 192.168.43.20 -j RETURN")" = 1 ] \
  && ! printf '%s\n' "$d4" | grep -q "fd00::20" \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -s fd00::20 -j RETURN")" = 1 ] \
  && ! printf '%s\n' "$d6" | grep -q "192.168.43.20" \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -j RETURN")" = 0 ] \
  && test_pass || test_fail "out=$out db4=$d4 db6=$d6"

test_start "webui_guard: allowlist rule order — lo first, REJECT last (after all RETURNs)"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07"]}'
grun apply >/dev/null
chain=$(grep "^RULE HNC_WEBUI " "$HNC_TEST_DIR/db4")
first=$(printf '%s\n' "$chain" | head -1); last=$(printf '%s\n' "$chain" | tail -1)
[ "$first" = "RULE HNC_WEBUI -i lo -j RETURN" ] \
  && [ "$last" = "RULE HNC_WEBUI -p tcp -j REJECT --reject-with tcp-reset" ] \
  && test_pass || test_fail "first=$first last=$last"

test_start "webui_guard: apply ×3 is idempotent (same DB, one jump per port, no duplicate rules)"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07","192.168.43.20"]}'
grun apply >/dev/null; s1=$(db4); s1v6=$(db6)
grun apply >/dev/null; grun apply >/dev/null; s3=$(db4); s3v6=$(db6)
[ "$s1" = "$s3" ] && [ "$s1v6" = "$s3v6" ] \
  && [ "$(cnt "$s3" "RULE INPUT -p tcp --dport 8443 -j HNC_WEBUI")" = 1 ] \
  && [ "$(printf '%s\n' "$s3" | grep -c "mac-source aa:bb:cc:dd:ee:07")" = 1 ] \
  && test_pass || test_fail "first=[$s1] third=[$s3]"

test_start "webui_guard: mode switch allowlist → all replaces chain content (no stale REJECT)"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07"]}'
grun apply >/dev/null
printf '%s\n' '{"mode":"all","macs":["aa:bb:cc:dd:ee:07"]}' > "$HNC_TEST_DIR/data/webui_access.json"
out=$(grun apply); d4=$(db4)
[ "$out" = "WEBUI_GUARD=applied mode=all entries=1 v6=1" ] \
  && ! printf '%s\n' "$d4" | grep -q "mac-source" \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -p tcp -j REJECT --reject-with tcp-reset")" = 0 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -j RETURN")" = 1 ] \
  && test_pass || test_fail "out=$out db4=$d4"

test_start "webui_guard: local_only → only lo RETURN + cellular + tail REJECT"
gseed '{"mode":"local_only","macs":["aa:bb:cc:dd:ee:07"]}'
out=$(grun apply); d4=$(db4)
[ "$out" = "WEBUI_GUARD=applied mode=local_only entries=1 v6=1" ] \
  && ! printf '%s\n' "$d4" | grep -q "mac-source" \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && test_pass || test_fail "out=$out db4=$d4"

test_start "webui_guard: remove → no HNC_WEBUI chain, no INPUT jumps (v4+v6); remove twice is safe"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07","fd00::20"]}'
grun apply >/dev/null; grun apply >/dev/null
out=$(grun remove); out2=$(grun remove)
[ "$out" = "WEBUI_GUARD=removed" ] && [ "$out2" = "WEBUI_GUARD=removed" ] \
  && ! grep -q "HNC_WEBUI" "$HNC_TEST_DIR/db4" && ! grep -q "HNC_WEBUI" "$HNC_TEST_DIR/db6" \
  && grep -q "^removed" "$HNC_TEST_DIR/run/webui_guard.state" \
  && test_pass || test_fail "out=$out db4=$(db4)"

test_start "webui_guard: corrupt config / unknown mode → fail-closed local_only"
gseed '{"mode":"everyone","macs":[]}'
out=$(grun apply)
[ "$out" = "WEBUI_GUARD=applied mode=local_only entries=0 v6=1" ] && test_pass || test_fail "out=$out"

test_start "webui_guard: injection-looking entries never reach iptables argv"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07","-j ACCEPT","$(reboot)","1.2.3.4;id","10.0.0.0/8"]}'
out=$(grun apply)
calls=$(cat "$HNC_TEST_DIR/db4.calls" "$HNC_TEST_DIR/db6.calls" 2>/dev/null)
[ "$out" = "WEBUI_GUARD=applied mode=allowlist entries=1 v6=1" ] \
  && ! printf '%s\n' "$calls" | grep -qE 'reboot|ACCEPT|;id|/8' \
  && test_pass || test_fail "out=$out calls=$calls"

test_start "webui_guard: v4 failure → exit 1 + state failed"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07"]}'
out=$(HNC_IPT="false" HNC_IP6T="false" HNC_DIR="$HNC_TEST_DIR" sh "$GSCRIPT" apply 2>/dev/null | tail -1)
[ "$out" = "WEBUI_GUARD=failed v4" ] && grep -q "^failed" "$HNC_TEST_DIR/run/webui_guard.state" \
  && test_pass || test_fail "out=$out"

test_start "webui_guard: cleanup.sh and service.sh wire the guard (remove / apply-before-httpd)"
if grep -q 'webui_guard.sh" remove' "$HNC_REPO_ROOT/bin/cleanup.sh" \
   && awk '/webui_guard.sh" apply/{a=NR} /launch_httpd_safe\(\) \{/{l=NR} END{exit !(a && l && a<l)}' "$HNC_REPO_ROOT/service.sh"; then
    test_pass
else
    test_fail "cleanup.sh remove / service.sh apply-before-launch missing"
fi

test_start "webui_guard: blocks public Wi-Fi wlan0, eth+, Tensor/Samsung gti+, CLAT v4-+, and VPN utun+/sing_tun+ when AP is wlan2"
gseed ""
printf '%s\n' '{"iface":"wlan2","upstream":"wlan0"}' > "$HNC_TEST_DIR/run/iface_detect.json"
out=$(grun apply)
d4=$(db4); d6=$(db6)
[ "$out" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i eth+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i gti+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i v4-+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i utun+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i sing_tun+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && ! printf '%s\n' "$d4" | grep -q -- "-i wlan2 " \
  && test_pass || test_fail "out=$out db4=$d4"

test_start "webui_guard: single-chip AP on wlan0 is NOT blocked, while eth+ and dynamic upstream wlan1 ARE blocked"
gseed ""
printf '%s\n' '{"iface":"wlan0"}' > "$HNC_TEST_DIR/run/iface_detect.json"
out1=$(grun apply)
d4_single=$(db4)
printf '%s\n' '{"iface":"wlan2","upstream":"wlan1"}' > "$HNC_TEST_DIR/run/iface_detect.json"
out2=$(grun apply)
d4_dual=$(db4)
[ "$out1" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && ! printf '%s\n' "$d4_single" | grep -q -- "-i wlan0 " \
  && [ "$(cnt "$d4_single" "RULE HNC_WEBUI -i eth+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$out2" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && [ "$(cnt "$d4_dual" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4_dual" "RULE HNC_WEBUI -i wlan1 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && ! printf '%s\n' "$d4_dual" | grep -q -- "-i wlan2 " \
  && test_pass || test_fail "single=[$d4_single] dual=[$d4_dual]"

test_start "webui_guard: missing xt_REJECT gracefully falls back to -j DROP"
gseed '{"mode":"allowlist","macs":["aa:bb:cc:dd:ee:07"]}'
touch "$HNC_TEST_DIR/no_reject"
out=$(grun apply)
d4=$(db4)
[ "$out" = "WEBUI_GUARD=applied mode=allowlist entries=1 v6=1" ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i wlan0 -j DROP")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -j DROP")" = 1 ] \
  && test_pass || test_fail "out=$out db4=$d4"

test_start "webui_guard: single-chip wlan0 PENDING (hotspot off -> public Wi-Fi) blocks wlan0 despite stale hotspot_iface/rules.json, and unblocks on ACTIVE:wlan0"
gseed ""
echo "PENDING" > "$HNC_TEST_DIR/run/hnc_state"
echo "wlan0" > "$HNC_TEST_DIR/run/hotspot_iface"
echo "wlan0" > "$HNC_TEST_DIR/run/active_iface"
printf '%s\n' '{"hotspot_iface":"wlan0"}' > "$HNC_TEST_DIR/data/rules.json"
printf '%s\n' '{"iface":"wlan0","wlan0_ap":true}' > "$HNC_TEST_DIR/run/iface_detect.json"
out_pend=$(grun apply)
d4_pend=$(db4); d6_pend=$(db6)
echo "ACTIVE:wlan0" > "$HNC_TEST_DIR/run/hnc_state"
out_act=$(grun apply)
d4_act=$(db4)
rm -f "$HNC_TEST_DIR/run/hnc_state" "$HNC_TEST_DIR/run/iface_detect.json"
out_stale_rules=$(grun apply)
d4_stale_rules=$(db4)
[ "$out_pend" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && [ "$(cnt "$d4_pend" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d6_pend" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$out_act" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && ! printf '%s\n' "$d4_act" | grep -q -- "-i wlan0 " \
  && [ "$out_stale_rules" = "WEBUI_GUARD=applied mode=all entries=0 v6=1" ] \
  && [ "$(cnt "$d4_stale_rules" "RULE HNC_WEBUI -i wlan0 -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && test_pass || test_fail "pend=[$d4_pend] act=[$d4_act] stale=[$d4_stale_rules]"

test_start "webui_guard: allowlist pre-blocks UPSTREAM_TUN_IFACES (tun+/wg+/tailscale+/utun+/sing_tun+) before IP allow rules"
gseed '{"mode":"allowlist","macs":["192.168.43.20","fd00::20"]}'
out=$(grun apply)
d4=$(db4); d6=$(db6)
tun_ln=$(printf '%s\n' "$d4" | grep -nF "RULE HNC_WEBUI -i tun+ -p tcp -j REJECT --reject-with tcp-reset" | head -1 | cut -d: -f1)
ip_ln=$(printf '%s\n' "$d4" | grep -nF "RULE HNC_WEBUI -s 192.168.43.20 -j RETURN" | head -1 | cut -d: -f1)
[ "$out" = "WEBUI_GUARD=applied mode=allowlist entries=2 v6=1" ] \
  && [ -n "$tun_ln" ] && [ -n "$ip_ln" ] && [ "$tun_ln" -lt "$ip_ln" ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i wg+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d4" "RULE HNC_WEBUI -i tailscale+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -i utun+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && [ "$(cnt "$d6" "RULE HNC_WEBUI -i sing_tun+ -p tcp -j REJECT --reject-with tcp-reset")" = 1 ] \
  && test_pass || test_fail "out=$out tun_ln=$tun_ln ip_ln=$ip_ln db4=$d4"
