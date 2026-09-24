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
