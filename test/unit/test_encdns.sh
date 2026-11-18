#!/system/bin/sh
# v5.21: encdns_sync.sh —— 加密 DNS 策略(off / dot / strict, 全局 + 按设备覆盖)

ESCRIPT="$HNC_REPO_ROOT/bin/encdns_sync.sh"

eseed() {
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
# 桩: 记录参数; -D 永远失败(链上没挂过); -nvxL 输出 $STUB_LIST_<chain> 文件内容
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$FAM $*" >> "$IPT_LOG"
case " $* " in
    *" -D "*) exit 1 ;;
    *" -nvxL "*)
        for a in "$@"; do ch=$a; done
        f="$STUB_DIR/list.$FAM.$ch"
        [ -f "$f" ] && cat "$f"
        exit 0 ;;
    *" -nL HNC_ENCDNS"*) [ -f "$STUB_DIR/has_chain" ] && exit 0; exit 1 ;;
esac
exit 0
STUB
cat > "$HNC_TEST_DIR/resolvers.txt" <<'LIST'
# test list
dns.google
cloudflare-dns.com   # trailing comment
8.8.8.8
45.90.28.0/24
2001:4860:4860::8888
bad;reboot
$(id).com
LIST
: > "$HNC_TEST_DIR/ipt.log"
}
erun() {
    STUB_DIR="$HNC_TEST_DIR" IPT_LOG="$HNC_TEST_DIR/ipt.log" \
    HNC_IPT="env FAM=4 sh $HNC_TEST_DIR/ipt_stub.sh" HNC_IP6T="env FAM=6 sh $HNC_TEST_DIR/ipt_stub.sh" \
    HNC_ENCDNS_LIST="$HNC_TEST_DIR/resolvers.txt" HNC_DIR="$HNC_TEST_DIR" sh "$ESCRIPT" "$@" 2>/dev/null | tail -1
}
econf() { printf '%s\n' "$1" > "$HNC_TEST_DIR/data/encdns.json"; }
L() { cat "$HNC_TEST_DIR/ipt.log"; }

test_start "encdns: no config → off, chains torn down (INPUT+FORWARD, v4+v6)"
eseed
out=$(HNC_ENCDNS_IFACE=wlan2 erun)
[ "$out" = "ENCDNS=off" ] \
  && grep -q -- "^4 -t filter -D INPUT -j HNC_ENCDNS" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "^6 -t filter -D FORWARD -j HNC_ENCDNS" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "^4 -t filter -X HNC_ENCDNS_STRICT" "$HNC_TEST_DIR/ipt.log" \
  && ! grep -q -- " -A " "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "encdns: global dot → 853 tcp-reset + udp reject (v4 icmp / v6 icmp6), jump only 853, linked INPUT+FORWARD"
eseed
econf '{"policy":"dot","devices":{}}'
out=$(HNC_ENCDNS_IFACE=wlan2 erun)
Lg=$(L)
[ "$out" = "ENCDNS=on global=dot devices=0 rules=4 string_layer=0" ] \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_DOT -p tcp --dport 853 -j REJECT --reject-with tcp-reset" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_DOT -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable" \
  && echo "$Lg" | grep -q -- "^6 -t filter -A HNC_ENCDNS_DOT -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS -i wlan2 -p tcp --dport 853 -j HNC_ENCDNS_DOT" \
  && ! echo "$Lg" | grep -q -- "-A HNC_ENCDNS -i wlan2 -p tcp --dport 443" \
  && echo "$Lg" | grep -q -- "^4 -t filter -I INPUT 1 -j HNC_ENCDNS" \
  && echo "$Lg" | grep -q -- "^6 -t filter -I FORWARD 1 -j HNC_ENCDNS" \
  && ! echo "$Lg" | grep -q -- "-m string" && test_pass || test_fail "out=$out"

test_start "encdns: global strict → resolver IPs per family, SNI + DNS qname rules, list sanitised"
eseed
econf '{"policy":"strict","devices":{}}'
out=$(HNC_ENCDNS_IFACE=wlan2 erun)
Lg=$(L)
# v4: 853×2 + 2 IP×2 + 2 host×3 = 12; v6: 853×2 + 1 IP×2 + 2 host×3 = 10
[ "$out" = "ENCDNS=on global=strict devices=0 rules=22 string_layer=1" ] \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_STRICT -j HNC_ENCDNS_DOT" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_STRICT -d 8.8.8.8 -p tcp --dport 443 -j REJECT --reject-with tcp-reset" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_STRICT -d 45.90.28.0/24 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable" \
  && echo "$Lg" | grep -q -- "^6 -t filter -A HNC_ENCDNS_STRICT -d 2001:4860:4860::8888 -p tcp --dport 443 -j REJECT" \
  && ! echo "$Lg" | grep -q -- "^6 .*-d 8.8.8.8" && ! echo "$Lg" | grep -q -- "^4 .*-d 2001:" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_STRICT -p udp --dport 53 -m string --algo bm --icase --hex-string |03|dns|06|google|00| -j DROP" \
  && echo "$Lg" | grep -q -- "^6 -t filter -A HNC_ENCDNS_STRICT -p tcp --dport 53 -m string --algo bm --icase --hex-string |0e|cloudflare-dns|03|com|00| -j DROP" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS_STRICT -p tcp --dport 443 -m string --algo bm --icase --hex-string |00000a|dns.google -j REJECT --reject-with tcp-reset" \
  && echo "$Lg" | grep -q -- "|000012|cloudflare-dns.com" \
  && echo "$Lg" | grep -q -- "^4 -t filter -A HNC_ENCDNS -i wlan2 -p udp --dport 443 -j HNC_ENCDNS_STRICT" \
  && ! echo "$Lg" | grep -q "reboot\|(id)" \
  && grep -q '"string_layer":true' "$HNC_TEST_DIR/run/encdns_caps.json" && test_pass || test_fail "out=$out"

test_start "encdns: per-device overrides first (with RETURN), 'off' device exempt, global after"
eseed
econf '{"policy":"dot","devices":{"AA:BB:CC:00:00:01":"strict","aa:bb:cc:00:00:02":"off","aa:bb:cc:00:00:03":"bogus"}}'
out=$(HNC_ENCDNS_IFACE=wlan2 erun)
f4=$(grep '^4 .* -A HNC_ENCDNS ' "$HNC_TEST_DIR/ipt.log")
n1=$(echo "$f4" | grep -n -- "--mac-source aa:bb:cc:00:00:01 -p tcp --dport 443 -j HNC_ENCDNS_STRICT" | head -1 | cut -d: -f1)
n2=$(echo "$f4" | grep -n -- "--mac-source aa:bb:cc:00:00:01 -j RETURN" | cut -d: -f1)
n3=$(echo "$f4" | grep -n -- "--mac-source aa:bb:cc:00:00:02 -j RETURN" | cut -d: -f1)
n4=$(echo "$f4" | grep -n -- "-i wlan2 -p tcp --dport 853 -j HNC_ENCDNS_DOT" | cut -d: -f1)
[ "$out" = "ENCDNS=on global=dot devices=2 rules=22 string_layer=1" ] \
  && [ -n "$n1" ] && [ -n "$n2" ] && [ -n "$n3" ] && [ -n "$n4" ] \
  && [ "$n1" -lt "$n2" ] && [ "$n2" -lt "$n3" ] && [ "$n3" -lt "$n4" ] \
  && ! echo "$f4" | grep -q -- "aa:bb:cc:00:00:02 -p" \
  && ! grep -q "00:00:03" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out n=$n1/$n2/$n3/$n4"

test_start "encdns: hotspot iface unknown → global pending, device overrides still applied"
eseed
econf '{"policy":"strict","devices":{"aa:bb:cc:00:00:01":"dot"}}'
out=$(erun)
[ "$out" = "ENCDNS=on global=pending devices=1 rules=22 string_layer=1" ] \
  && grep -q -- "-A HNC_ENCDNS -m mac --mac-source aa:bb:cc:00:00:01 -p tcp --dport 853 -j HNC_ENCDNS_DOT" "$HNC_TEST_DIR/ipt.log" \
  && ! grep -q -- "-A HNC_ENCDNS -i " "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "encdns: iface from run/hnc_state; injection in iface rejected"
eseed
econf '{"policy":"dot"}'
echo "ACTIVE:ap0" > "$HNC_TEST_DIR/run/hnc_state"
out=$(erun)
ok1=0; [ "$out" = "ENCDNS=on global=dot devices=0 rules=4 string_layer=0" ] && grep -q -- "-i ap0 -p tcp --dport 853" "$HNC_TEST_DIR/ipt.log" && ok1=1
: > "$HNC_TEST_DIR/ipt.log"
out2=$(HNC_ENCDNS_IFACE='wlan2;reboot' erun)
[ "$ok1" = 1 ] && [ "$out2" = "ENCDNS=on global=pending devices=0 rules=4 string_layer=0" ] \
  && ! grep -q reboot "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out out2=$out2"

test_start "encdns: idempotent — second run tears down then produces identical rule set"
eseed
econf '{"policy":"strict","devices":{"aa:bb:cc:00:00:01":"off"}}'
HNC_ENCDNS_IFACE=wlan2 erun >/dev/null
grep -- " -A \| -I " "$HNC_TEST_DIR/ipt.log" | grep -v EDPROBE > "$HNC_TEST_DIR/r1"
: > "$HNC_TEST_DIR/ipt.log"
HNC_ENCDNS_IFACE=wlan2 erun >/dev/null
grep -- " -A \| -I " "$HNC_TEST_DIR/ipt.log" > "$HNC_TEST_DIR/r2"
grep -q -- "-D FORWARD -j HNC_ENCDNS" "$HNC_TEST_DIR/ipt.log" && grep -q -- "-F HNC_ENCDNS_DOT" "$HNC_TEST_DIR/ipt.log" \
  && [ -s "$HNC_TEST_DIR/r1" ] && cmp -s "$HNC_TEST_DIR/r1" "$HNC_TEST_DIR/r2" \
  && ! grep -q HNC_EDPROBE "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "rule sets differ or re-probed"

test_start "encdns: no xt_string → strict keeps IP layer only, caps recorded false"
eseed
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$FAM $*" >> "$IPT_LOG"
case " $* " in *" -D "*|*" -m string "*) exit 1 ;; esac
exit 0
STUB
econf '{"policy":"strict"}'
out=$(HNC_ENCDNS_IFACE=wlan2 erun)
[ "$out" = "ENCDNS=on global=strict devices=0 rules=10 string_layer=0" ] \
  && grep -q '"string_layer":false' "$HNC_TEST_DIR/run/encdns_caps.json" \
  && ! grep -q -- "-A HNC_ENCDNS_STRICT .*-m string" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "-d 8.8.8.8 -p tcp --dport 443" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "encdns: --counters parses iptables -nvxL (v4+v6, blank opt column, jump rules ignored)"
eseed
cat > "$HNC_TEST_DIR/list.4.HNC_ENCDNS_DOT" <<'X'
Chain HNC_ENCDNS_DOT (2 references)
    pkts      bytes target     prot opt in     out     source               destination
      12      720 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:853 reject-with tcp-reset
       3      180 REJECT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:853 reject-with icmp-port-unreachable
X
cat > "$HNC_TEST_DIR/list.4.HNC_ENCDNS_STRICT" <<'X'
Chain HNC_ENCDNS_STRICT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     500    30000 HNC_ENCDNS_DOT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
       7      420 REJECT     tcp  --  *      *       0.0.0.0/0            8.8.8.8              tcp dpt:443 reject-with tcp-reset
       2      120 REJECT     udp  --  *      *       0.0.0.0/0            8.8.8.8              udp dpt:443 reject-with icmp-port-unreachable
       4      300 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53 STRING match  "|03646e7306676f6f676c6500|" ALGO name bm TO 65535 ICASE
       1      517 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 STRING match  "|00000a|dns.google" ALGO name bm TO 65535 ICASE reject-with tcp-reset
       0        0 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:4430 reject-with tcp-reset
X
cat > "$HNC_TEST_DIR/list.6.HNC_ENCDNS_DOT" <<'X'
Chain HNC_ENCDNS_DOT (2 references)
    pkts      bytes target     prot opt in     out     source               destination
       5      400 REJECT     tcp      *      *       ::/0                 ::/0                 tcp dpt:853 reject-with tcp-reset
X
cat > "$HNC_TEST_DIR/list.6.HNC_ENCDNS_STRICT" <<'X'
Chain HNC_ENCDNS_STRICT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       2      160 REJECT     tcp      *      *       ::/0                 2001:4860:4860::8888  tcp dpt:443 reject-with tcp-reset
X
touch "$HNC_TEST_DIR/has_chain"
out=$(erun --counters)
exp='{"chain":true,"v6":true,"dot":{"pkts":20,"bytes":1300},"doh_ip":{"pkts":11,"bytes":700},"doh_sni":{"pkts":1,"bytes":517},"doh_dns":{"pkts":4,"bytes":300},"total_pkts":36,"total_bytes":2817,"v4_pkts":29,"v6_pkts":7}'
[ "$out" = "$exp" ] && ! grep -q -- " -A \| -F \| -X " "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "encdns: --counters with no chains → zeros, chain=false (valid JSON)"
eseed
out=$(erun --counters)
printf '%s\n' "$out" > "$HNC_TEST_DIR/c.json"
case "$out" in
  '{"chain":false,"v6":true,"dot":{"pkts":0,"bytes":0}'*'"total_pkts":0,"total_bytes":0,"v4_pkts":0,"v6_pkts":0}')
    assert_json_valid "$HNC_TEST_DIR/c.json" && test_pass ;;
  *) test_fail "out=$out" ;;
esac

test_start "encdns: shipped data/encdns_resolvers.txt parses (hosts + v4 + v6, no junk)"
eseed
econf '{"policy":"strict"}'
out=$(STUB_DIR="$HNC_TEST_DIR" IPT_LOG="$HNC_TEST_DIR/ipt.log" \
    HNC_IPT="env FAM=4 sh $HNC_TEST_DIR/ipt_stub.sh" HNC_IP6T="env FAM=6 sh $HNC_TEST_DIR/ipt_stub.sh" \
    HNC_ENCDNS_LIST="$HNC_REPO_ROOT/data/encdns_resolvers.txt" HNC_ENCDNS_IFACE=wlan2 HNC_DIR="$HNC_TEST_DIR" sh "$ESCRIPT" 2>/dev/null | tail -1)
case "$out" in ENCDNS=on\ global=strict*) ;; *) out="BAD $out" ;; esac
grep -q -- "^4 .*-d 223.5.5.5 -p tcp --dport 443" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "^6 .*-d 2400:3200::1 -p tcp --dport 443" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "|03|doh|03|pub|00|" "$HNC_TEST_DIR/ipt.log" \
  && ! grep -q -- "^4 .*-d [0-9a-f]*:" "$HNC_TEST_DIR/ipt.log" \
  && [ "${out#BAD}" = "$out" ] && test_pass || test_fail "out=$out"
