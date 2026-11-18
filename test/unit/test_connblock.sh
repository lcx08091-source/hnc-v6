#!/system/bin/sh
# v5.16: connblock_sync.sh —— 按设备封锁域名/IP(REJECT, 只拦该 MAC)

CSCRIPT="$HNC_REPO_ROOT/bin/connblock_sync.sh"

cseed() {
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$*" >> "$IPT_LOG"
case " $* " in *" -D "*) exit 1 ;; esac
exit 0
STUB
: > "$HNC_TEST_DIR/ipt.log"
}
crun() { IPT_LOG="$HNC_TEST_DIR/ipt.log" HNC_IPT="sh $HNC_TEST_DIR/ipt_stub.sh" HNC_IP6T="sh $HNC_TEST_DIR/ipt_stub.sh" HNC_DIR="$HNC_TEST_DIR" sh "$CSCRIPT" "$@" 2>/dev/null | tail -1; }

test_start "connblock: empty flat → chain removed"
cseed
: > "$HNC_TEST_DIR/run/conn_blocks.flat"
out=$(crun)
[ "$out" = "CONN_BLOCK=off" ] && grep -q -- "-X HNC_CONNBLK" "$HNC_TEST_DIR/ipt.log" && ! grep -q REJECT "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "connblock: per-MAC REJECT rules, linked first in FORWARD"
cseed
printf 'aa:bb:cc:00:00:01 1.2.3.4\naa:bb:cc:00:00:01 5.6.7.8\n' > "$HNC_TEST_DIR/run/conn_blocks.flat"
out=$(crun)
[ "$out" = "CONN_BLOCK=on rules=2" ] \
  && grep -q -- "-A HNC_CONNBLK -m mac --mac-source aa:bb:cc:00:00:01 -d 1.2.3.4 -j REJECT" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "-I FORWARD 1 -j HNC_CONNBLK" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "connblock: malformed / injection lines are skipped"
cseed
printf 'aa:bb:cc:00:00:01 1.2.3.4;reboot\nnot-a-mac 1.2.3.4\naa:bb:cc:00:00:01 $(id)\naa:bb:cc:00:00:02 9.9.9.9\n' > "$HNC_TEST_DIR/run/conn_blocks.flat"
out=$(crun)
[ "$out" = "CONN_BLOCK=on rules=1" ] && ! grep -q "reboot\|(id)\|not-a-mac" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

# ── v5.18 DNS 层(xt_string qname 后缀匹配)──────────────────────────
test_start "connblock dns: qname wire-format suffix rules for udp+tcp 53, linked in INPUT+FORWARD"
cseed
printf 'aa:bb:cc:00:00:01 1.2.3.4\n' > "$HNC_TEST_DIR/run/conn_blocks.flat"
printf 'aa:bb:cc:00:00:01 google.com\n' > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
L="$HNC_TEST_DIR/ipt.log"
[ "$out" = "CONN_BLOCK=on rules=1 dns=1 dns_layer=1" ] \
  && grep -q -- "-A HNC_CONNBLK_DNS -m mac --mac-source aa:bb:cc:00:00:01 -p udp --dport 53 -m string --algo bm --icase --hex-string |06|google|03|com|00| -j DROP" "$L" \
  && grep -q -- "-A HNC_CONNBLK_DNS -m mac --mac-source aa:bb:cc:00:00:01 -p tcp --dport 53 -m string --algo bm --icase --hex-string |06|google|03|com|00| -j DROP" "$L" \
  && grep -q -- "-I INPUT 1 -j HNC_CONNBLK_DNS" "$L" && grep -q -- "-I FORWARD 1 -j HNC_CONNBLK_DNS" "$L" \
  && grep -q -- "-I FORWARD 1 -j HNC_CONNBLK$" "$L" \
  && grep -q '"dns_layer":true' "$HNC_TEST_DIR/run/connblock_caps.json" && test_pass || test_fail "out=$out"

test_start "connblock dns: DoT tcp/853 rejected once per device with domain blocks"
cseed
: > "$HNC_TEST_DIR/run/conn_blocks.flat"
printf 'aa:bb:cc:00:00:01 a.example.com\naa:bb:cc:00:00:01 b.example.org\naa:bb:cc:00:00:02 x-y.cn\n' > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
c1=$(grep -c -- "--mac-source aa:bb:cc:00:00:01 -p tcp --dport 853 -j REJECT --reject-with tcp-reset" "$HNC_TEST_DIR/ipt.log")
c2=$(grep -c -- "--mac-source aa:bb:cc:00:00:02 -p tcp --dport 853 -j REJECT" "$HNC_TEST_DIR/ipt.log")
[ "$out" = "CONN_BLOCK=on rules=0 dns=3 dns_layer=1" ] && [ "$c1" = 1 ] && [ "$c2" = 1 ] \
  && grep -q -- "|01|a|07|example|03|com|00|" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "|03|x-y|02|cn|00|" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out c1=$c1 c2=$c2"

test_start "connblock dns: malformed domains / macs skipped (no injection)"
cseed
: > "$HNC_TEST_DIR/run/conn_blocks.flat"
printf 'aa:bb:cc:00:00:01 bad;reboot.com\naa:bb:cc:00:00:01 ..com\nnot-a-mac ok.com\naa:bb:cc:00:00:01 $(id).com\naa:bb:cc:00:00:01 Good.COM\n' > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
[ "$out" = "CONN_BLOCK=on rules=0 dns=1 dns_layer=1" ] && ! grep -q "reboot\|(id)\|not-a-mac\||02|ok|" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "|04|good|03|com|00|" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "connblock dns: no xt_string → IP layer only, capability recorded unavailable"
cseed
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$*" >> "$IPT_LOG"
case " $* " in *" -D "*|*" -m string "*) exit 1 ;; esac
exit 0
STUB
printf 'aa:bb:cc:00:00:01 1.2.3.4\n' > "$HNC_TEST_DIR/run/conn_blocks.flat"
printf 'aa:bb:cc:00:00:01 google.com\n' > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
[ "$out" = "CONN_BLOCK=on rules=1 dns=0 dns_layer=0" ] \
  && grep -q '"dns_layer":false' "$HNC_TEST_DIR/run/connblock_caps.json" \
  && ! grep -q -- "-A HNC_CONNBLK_DNS" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "-d 1.2.3.4 -j REJECT" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "connblock dns: cached capability reused (no re-probe), teardown removes DNS chain from INPUT/FORWARD"
cseed
printf '{"dns_layer":true,"dns_layer_v6":false,"checked":%s}\n' "$(date +%s)" > "$HNC_TEST_DIR/run/connblock_caps.json"
: > "$HNC_TEST_DIR/run/conn_blocks.flat"
printf 'aa:bb:cc:00:00:01 google.com\n' > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
[ "$out" = "CONN_BLOCK=on rules=0 dns=1 dns_layer=1" ] && ! grep -q HNC_CBPROBE "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "-D INPUT -j HNC_CONNBLK_DNS" "$HNC_TEST_DIR/ipt.log" && grep -q -- "-X HNC_CONNBLK_DNS" "$HNC_TEST_DIR/ipt.log" \
  && test_pass || test_fail "out=$out"

test_start "connblock dns: both lists empty → off"
cseed
: > "$HNC_TEST_DIR/run/conn_blocks.flat"
: > "$HNC_TEST_DIR/run/conn_blocks.dns"
out=$(crun)
[ "$out" = "CONN_BLOCK=off" ] && grep -q -- "-X HNC_CONNBLK_DNS" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"
