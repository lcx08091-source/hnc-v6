#!/system/bin/sh
# v5.14: quic_block_sync.sh —— 强制 QUIC 回落 TCP(UDP 443 → REJECT)

QSCRIPT="$HNC_REPO_ROOT/bin/quic_block_sync.sh"

qseed() {  # $1=quic_block
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
printf '{\n  "version": 1,\n  "quic_block": %s,\n  "devices": {}\n}\n' "$1" > "$HNC_TEST_DIR/data/rules.json"
# iptables 桩: 记录参数; -D 恒失败(否则删除循环不会停), 其余成功
cat > "$HNC_TEST_DIR/ipt_stub.sh" <<'STUB'
echo "$*" >> "$IPT_LOG"
case " $* " in *" -D "*) exit 1 ;; esac
exit 0
STUB
: > "$HNC_TEST_DIR/ipt.log"
}
qrun() { IPT_LOG="$HNC_TEST_DIR/ipt.log" HNC_IPT="sh $HNC_TEST_DIR/ipt_stub.sh" HNC_IP6T="sh $HNC_TEST_DIR/ipt_stub.sh" HNC_DIR="$HNC_TEST_DIR" sh "$QSCRIPT" "$@" 2>/dev/null | tail -1; }

test_start "quic_block: off → chain removed, no REJECT"
qseed false
out=$(qrun)
[ "$out" = "QUIC_BLOCK=off" ] && grep -q -- "-X HNC_QUIC" "$HNC_TEST_DIR/ipt.log" && ! grep -q REJECT "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "quic_block: on + ACTIVE iface → REJECT udp 443 on hotspot iface, linked first in FORWARD"
qseed true
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
out=$(qrun)
[ "$out" = "QUIC_BLOCK=on iface=wlan2" ] \
  && grep -q -- "-A HNC_QUIC -i wlan2 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable" "$HNC_TEST_DIR/ipt.log" \
  && grep -q -- "-I FORWARD 1 -j HNC_QUIC" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"

test_start "quic_block: HNC_WL_IFACE overrides state; multi-line rules.json"
qseed true
printf '{\n  "quic_block":\n    true\n}\n' > "$HNC_TEST_DIR/data/rules.json"
out=$(HNC_WL_IFACE=ap0 qrun)
[ "$out" = "QUIC_BLOCK=on iface=ap0" ] && test_pass || test_fail "out=$out"

test_start "quic_block: on but hotspot down → pending, nothing linked"
qseed true
rm -f "$HNC_TEST_DIR/run/hnc_state"
out=$(qrun)
[ "$out" = "QUIC_BLOCK=pending" ] && ! grep -q -- "-I FORWARD" "$HNC_TEST_DIR/ipt.log" && test_pass || test_fail "out=$out"
