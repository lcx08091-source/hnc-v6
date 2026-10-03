#!/system/bin/sh
# DPI v2: dns_takeover.sh —— DNS 接管的 nat DNAT / INPUT 放行 / 拆除 / 计数

DSCRIPT="$HNC_REPO_ROOT/bin/dns_takeover.sh"

dseed() {
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
# 桩: 记录 "<族> 参数"; -D 永远失败(链上没挂过); fail.<族> 里的子串命中则失败;
# -nL HNC_DNSTK 看 has_chain.<族>; -nvxL 输出 list.<族>
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$FAM $*" >> "$IPT_LOG"
if [ -f "$STUB_DIR/fail.$FAM" ]; then
    while read -r pat; do
        [ -n "$pat" ] || continue
        case " $* " in *"$pat"*) exit 1 ;; esac
    done < "$STUB_DIR/fail.$FAM"
fi
case " $* " in
    *" -D "*) exit 1 ;;
    *" -nvxL "*) [ -f "$STUB_DIR/list.$FAM" ] && cat "$STUB_DIR/list.$FAM"; exit 0 ;;
    *" -nL HNC_DNSTK "*) [ -f "$STUB_DIR/has_chain.$FAM" ] && exit 0; exit 1 ;;
esac
exit 0
STUB
: > "$HNC_TEST_DIR/ipt.log"
}
drun() {
    STUB_DIR="$HNC_TEST_DIR" IPT_LOG="$HNC_TEST_DIR/ipt.log" \
    HNC_IPT="env FAM=4 sh $HNC_TEST_DIR/ipt_stub.sh" HNC_IP6T="env FAM=6 sh $HNC_TEST_DIR/ipt_stub.sh" \
    HNC_DIR="$HNC_TEST_DIR" sh "$DSCRIPT" "$@" 2>/dev/null | tail -1
}
L() { cat "$HNC_TEST_DIR/ipt.log"; }

test_start "dns_takeover: apply v4 → DNAT per gateway addr (udp+tcp), INPUT accept, PREROUTING linked last"
dseed
out=$(drun apply wlan2 15353 192.168.43.1 192.168.43.1,192.168.43.67)
Lg=$(L)
nlink=$(echo "$Lg" | grep -n -- "^4 -t nat -I PREROUTING 1 -j HNC_DNSTK$" | cut -d: -f1)
nlast=$(echo "$Lg" | grep -n -- "^4 -t nat -A HNC_DNSTK " | tail -1 | cut -d: -f1)
[ "$out" = "DNSTK=on iface=wlan2 port=15353 rules=4 v6=0" ] \
  && echo "$Lg" | grep -q -- "^4 -t nat -A HNC_DNSTK -i wlan2 -d 192.168.43.1 -p udp --dport 53 -j DNAT --to-destination 192.168.43.1:15353$" \
  && echo "$Lg" | grep -q -- "^4 -t nat -A HNC_DNSTK -i wlan2 -d 192.168.43.67 -p tcp --dport 53 -j DNAT --to-destination 192.168.43.1:15353$" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_DNSTK_IN -i wlan2 -p udp --dport 15353 -j ACCEPT$" \
  && echo "$Lg" | grep -q -- "^4 -t filter -I INPUT 1 -j HNC_DNSTK_IN$" \
  && [ -n "$nlink" ] && [ -n "$nlast" ] && [ "$nlast" -lt "$nlink" ] \
  && ! echo "$Lg" | grep -q -- "OUTPUT" \
  && ! echo "$Lg" | grep -q -- "^6 .* -A " && test_pass || test_fail "out=$out"

test_start "dns_takeover: only -i <hotspot> inbound + gateway -d (never the phone's own traffic / foreign resolvers)"
dseed
drun apply ap0 15353 10.0.0.1 10.0.0.1 >/dev/null
# 每条 DNAT 都必须带 -i ap0 与 -d 10.0.0.1, 且不能出现在 OUTPUT
n_all=$(grep -c -- "-A HNC_DNSTK .*DNAT" "$HNC_TEST_DIR/ipt.log")
n_ok=$(grep -c -- "-A HNC_DNSTK -i ap0 -d 10.0.0.1 -p .* --dport 53 -j DNAT" "$HNC_TEST_DIR/ipt.log")
[ "$n_all" = 2 ] && [ "$n_ok" = 2 ] && ! grep -q "OUTPUT" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "all=$n_all ok=$n_ok"

test_start "dns_takeover: idempotent — every apply tears down first, identical rule set"
dseed
drun apply wlan2 15353 192.168.43.1 192.168.43.1 >/dev/null
grep -- " -A \| -I " "$HNC_TEST_DIR/ipt.log" > "$HNC_TEST_DIR/r1"
: > "$HNC_TEST_DIR/ipt.log"
out=$(drun apply wlan2 15353 192.168.43.1 192.168.43.1)
grep -- " -A \| -I " "$HNC_TEST_DIR/ipt.log" > "$HNC_TEST_DIR/r2"
first_add=$(grep -n -- " -A \| -I \| -N " "$HNC_TEST_DIR/ipt.log" | head -1 | cut -d: -f1)
del=$(grep -n -- "^4 -t nat -D PREROUTING -j HNC_DNSTK$" "$HNC_TEST_DIR/ipt.log" | head -1 | cut -d: -f1)
xx=$(grep -n -- "^4 -t nat -X HNC_DNSTK$" "$HNC_TEST_DIR/ipt.log" | head -1 | cut -d: -f1)
[ "$out" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=0" ] && cmp -s "$HNC_TEST_DIR/r1" "$HNC_TEST_DIR/r2" \
  && [ -n "$del" ] && [ -n "$xx" ] && [ "$del" -lt "$first_add" ] && [ "$xx" -lt "$first_add" ] \
  && grep -q -- "^6 -t nat -D PREROUTING -j HNC_DNSTK$" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "^4 -t filter -D INPUT -j HNC_DNSTK_IN$" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out del=$del first=$first_add"

test_start "dns_takeover: remove → unlink + flush + delete (v4+v6), adds nothing, repeatable"
dseed
out=$(drun remove)
out2=$(drun remove)
Lg=$(L)
[ "$out" = "DNSTK=off" ] && [ "$out2" = "DNSTK=off" ] \
  && echo "$Lg" | grep -q -- "^4 -t nat -D PREROUTING -j HNC_DNSTK$" \
  && echo "$Lg" | grep -q -- "^4 -t nat -F HNC_DNSTK$" \
  && echo "$Lg" | grep -q -- "^4 -t nat -X HNC_DNSTK$" \
  && echo "$Lg" | grep -q -- "^4 -t filter -X HNC_DNSTK_IN$" \
  && echo "$Lg" | grep -q -- "^6 -t nat -X HNC_DNSTK$" \
  && ! echo "$Lg" | grep -q -- " -A \| -I \| -N " && test_pass || test_fail "out=$out"

test_start "dns_takeover: bad args / injection rejected, nothing touched"
dseed
o1=$(drun apply 'wlan2;reboot' 15353 192.168.43.1 192.168.43.1); r1=$?
o2=$(drun apply wlan2 53 192.168.43.1 192.168.43.1)
o3=$(drun apply wlan2 15353 '1.2.3.4;id' 192.168.43.1)
o4=$(drun apply wlan2 15353 192.168.43.300 192.168.43.1)
o5=$(drun bogus)
[ "$o1" = "DNSTK=error bad_args" ] && [ "$o2" = "DNSTK=error bad_args" ] && [ "$o3" = "DNSTK=error bad_args" ] \
  && [ "$o4" = "DNSTK=error bad_args" ] && [ -z "$o5" ] \
  && ! grep -q -- " -A \| -I \| -N \|reboot\|id" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "o1=$o1 o2=$o2 o3=$o3 o4=$o4"

test_start "dns_takeover: bad dst entries filtered, empty dst list falls back to listen addr"
dseed
out=$(drun apply wlan2 15353 192.168.43.1 '192.168.43.9,$(id),1.2.3,::1')
Lg=$(L)
o2=$(: > "$HNC_TEST_DIR/ipt.log"; drun apply wlan2 15353 192.168.43.1 '')
[ "$out" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=0" ] \
  && echo "$Lg" | grep -q -- "-d 192.168.43.9 -p udp" && ! echo "$Lg" | grep -q -- "1.2.3 \|id)\|-d ::1" \
  && [ "$o2" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=0" ] \
  && grep -q -- "-d 192.168.43.1 -p tcp --dport 53 -j DNAT" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out o2=$o2"

test_start "dns_takeover: DNAT unsupported → full rollback, PREROUTING never linked, exit 1"
dseed
echo "-j DNAT" > "$HNC_TEST_DIR/fail.4"
out=$(drun apply wlan2 15353 192.168.43.1 192.168.43.1)
Lg=$(L)
[ "$out" = "DNSTK=error apply_failed" ] && ! echo "$Lg" | grep -q -- "-I PREROUTING" \
  && [ "$(echo "$Lg" | grep -c -- "^4 -t nat -X HNC_DNSTK$")" -ge 2 ] \
  && grep -q "apply FAILED" "$HNC_TEST_DIR/logs/service.log" && test_pass || test_fail "out=$out"

test_start "dns_takeover: IPv6 with ip6tables nat → DNAT each v6 addr to [addr]:port"
dseed
out=$(drun apply wlan2 15353 192.168.43.1 192.168.43.1 '2408:1:2::1,fe80::1')
Lg=$(L)
[ "$out" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=4" ] \
  && echo "$Lg" | grep -q -- "^6 -t nat -A HNC_DNSTK -i wlan2 -d 2408:1:2::1 -p udp --dport 53 -j DNAT --to-destination \[2408:1:2::1\]:15353$" \
  && echo "$Lg" | grep -q -- "^6 -t filter -A HNC_DNSTK_IN -i wlan2 -p tcp --dport 15353 -j ACCEPT$" \
  && echo "$Lg" | grep -q -- "^6 -t nat -I PREROUTING 1 -j HNC_DNSTK$" && test_pass || test_fail "out=$out"

test_start "dns_takeover: IPv6 nat unavailable → v6=unsupported, v4 still on, v6 rolled back"
dseed
printf '%s\n' "-t nat -N HNC_DNSTK" > "$HNC_TEST_DIR/fail.6"
out=$(drun apply wlan2 15353 192.168.43.1 192.168.43.1 '2408:1:2::1')
Lg=$(L)
o2=$(rm -f "$HNC_TEST_DIR/fail.6"; echo "-j DNAT" > "$HNC_TEST_DIR/fail.6"; : > "$HNC_TEST_DIR/ipt.log"; drun apply wlan2 15353 192.168.43.1 192.168.43.1 '2408:1:2::1')
[ "$out" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=unsupported" ] \
  && echo "$Lg" | grep -q -- "^4 -t nat -I PREROUTING 1 -j HNC_DNSTK$" \
  && ! echo "$Lg" | grep -q -- "^6 .* -A " \
  && [ "$o2" = "DNSTK=on iface=wlan2 port=15353 rules=2 v6=unsupported" ] \
  && ! grep -q -- "^6 -t nat -I PREROUTING" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "^6 -t nat -X HNC_DNSTK$" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out o2=$o2"

test_start "dns_takeover: counters → present + DNAT pkts (v4/v6), absent chain → present=false"
dseed
out0=$(drun counters)
touch "$HNC_TEST_DIR/has_chain.4" "$HNC_TEST_DIR/has_chain.6"
cat > "$HNC_TEST_DIR/list.4" <<'EOF'
Chain HNC_DNSTK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      12      800 DNAT       udp  --  wlan2  *       0.0.0.0/0            192.168.43.1         udp dpt:53 to:192.168.43.1:15353
       3      180 DNAT       tcp  --  wlan2  *       0.0.0.0/0            192.168.43.1         tcp dpt:53 to:192.168.43.1:15353
EOF
cat > "$HNC_TEST_DIR/list.6" <<'EOF'
Chain HNC_DNSTK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       5      400 DNAT       udp      wlan2  *       ::/0                 2408:1:2::1          udp dpt:53 to:[2408:1:2::1]:15353
EOF
out=$(drun counters)
[ "$out0" = '{"present":false,"pkts":0,"v6_present":false,"pkts_v6":0}' ] \
  && [ "$out" = '{"present":true,"pkts":15,"v6_present":true,"pkts_v6":5}' ] && test_pass || test_fail "out0=$out0 out=$out"

test_start "dns_takeover: cleanup.sh and watchdog (httpd dead) call remove"
# v5.26 T1: shell ensure_httpd_running 已删, httpd 死亡时的 remove 由 Go 看门狗
# ensureDaemonRunning 执行(原 watchdog.sh 两处调用点合并为 Go 一处)。
grep -q 'dns_takeover.sh" remove' "$HNC_REPO_ROOT/bin/cleanup.sh" \
  && grep -q 'dns_takeover.sh", "remove' "$HNC_REPO_ROOT/src/dpid/cmd/hnc_watchdog/main.go" && test_pass || test_fail "remove hook missing"
