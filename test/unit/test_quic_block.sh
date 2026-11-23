#!/system/bin/sh
# test/unit/test_quic_block.sh — 双栈 QUIC 回落开关单测 (IPv4 + IPv6)

QB="$HNC_REPO_ROOT/bin/quic_block_sync.sh"

qseed() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs" "$HNC_TEST_DIR/stub"
    : > "$HNC_TEST_DIR/ipt.log"
    : > "$HNC_TEST_DIR/ip6t.log"
    {
        printf '#!%s\n' "${HNC_TEST_SH:-/system/bin/sh}"
        cat <<'EOF'
echo "$*" >> "$HNC_DIR/ipt.log"
case "$*" in *"-D FORWARD -j HNC_QUIC")
    n=$(grep -cE -- '-D FORWARD -j HNC_QUIC$' "$HNC_DIR/ipt.log")
    [ "$n" -le 1 ] && exit 0 || exit 1 ;;
esac
exit 0
EOF
    } > "$HNC_TEST_DIR/stub/iptables"
    {
        printf '#!%s\n' "${HNC_TEST_SH:-/system/bin/sh}"
        cat <<'EOF'
echo "$*" >> "$HNC_DIR/ip6t.log"
case "$*" in *"-D FORWARD -j HNC_QUIC")
    n=$(grep -cE -- '-D FORWARD -j HNC_QUIC$' "$HNC_DIR/ip6t.log")
    [ "$n" -le 1 ] && exit 0 || exit 1 ;;
esac
exit 0
EOF
    } > "$HNC_TEST_DIR/stub/ip6tables"
    chmod +x "$HNC_TEST_DIR/stub/iptables" "$HNC_TEST_DIR/stub/ip6tables"
    [ -n "$1" ] && printf '%s\n' "$1" > "$HNC_TEST_DIR/data/rules.json"
    [ -n "$2" ] && printf '%s\n' "$2" > "$HNC_TEST_DIR/run/hnc_state"
}
qrun() {
    HNC_DIR="$HNC_TEST_DIR" HNC_IPT="$HNC_TEST_DIR/stub/iptables -w 2" HNC_IP6T="$HNC_TEST_DIR/stub/ip6tables -w 2" \
        PATH="$HNC_TEST_DIR/stub:$PATH" sh "$QB" "$@"
}

test_start "quic_block: off → dual-stack chains removed, no REJECT"
qseed '{"quic_block":false}' "ACTIVE:wlan2"
out=$(qrun)
[ "$out" = "QUIC_BLOCK=off" ] \
    && grep -q -- '-X HNC_QUIC' "$HNC_TEST_DIR/ipt.log" \
    && grep -q -- '-X HNC_QUIC' "$HNC_TEST_DIR/ip6t.log" \
    && ! grep -q 'REJECT' "$HNC_TEST_DIR/ipt.log" \
    && ! grep -q 'REJECT' "$HNC_TEST_DIR/ip6t.log" \
    && test_pass || test_fail "out=$out v4=$(cat "$HNC_TEST_DIR/ipt.log") v6=$(cat "$HNC_TEST_DIR/ip6t.log")"

test_start "quic_block: on + ACTIVE iface → dual-stack REJECT udp 443 (icmp & icmp6), linked first in FORWARD"
qseed '{"quic_block":true}' "ACTIVE:wlan2"
out=$(qrun)
[ "$out" = "QUIC_BLOCK=on iface=wlan2" ] \
    && grep -q -- '-A HNC_QUIC -i wlan2 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable' "$HNC_TEST_DIR/ipt.log" \
    && grep -q -- '-I FORWARD 1 -j HNC_QUIC' "$HNC_TEST_DIR/ipt.log" \
    && grep -q -- '-A HNC_QUIC -i wlan2 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable' "$HNC_TEST_DIR/ip6t.log" \
    && grep -q -- '-I FORWARD 1 -j HNC_QUIC' "$HNC_TEST_DIR/ip6t.log" \
    && test_pass || test_fail "out=$out v4=$(cat "$HNC_TEST_DIR/ipt.log") v6=$(cat "$HNC_TEST_DIR/ip6t.log")"

test_start "quic_block: HNC_WL_IFACE overrides state; multi-line rules.json"
qseed "$(printf '{\n  "quic_block": true\n}')" "IDLE"
out=$(HNC_WL_IFACE=ap0 HNC_DIR="$HNC_TEST_DIR" HNC_IPT="$HNC_TEST_DIR/stub/iptables -w 2" HNC_IP6T="$HNC_TEST_DIR/stub/ip6tables -w 2" PATH="$HNC_TEST_DIR/stub:$PATH" sh "$QB")
[ "$out" = "QUIC_BLOCK=on iface=ap0" ] \
    && grep -q -- '-i ap0 -p udp --dport 443 -j REJECT' "$HNC_TEST_DIR/ipt.log" \
    && grep -q -- '-i ap0 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable' "$HNC_TEST_DIR/ip6t.log" \
    && test_pass || test_fail "out=$out"

test_start "quic_block: on but hotspot down → pending, nothing linked"
qseed '{"quic_block":true}' "IDLE"
out=$(qrun)
[ "$out" = "QUIC_BLOCK=pending" ] && ! grep -q -- '-I FORWARD' "$HNC_TEST_DIR/ipt.log" \
    && ! grep -q -- '-I FORWARD' "$HNC_TEST_DIR/ip6t.log" \
    && test_pass || test_fail "out=$out"

test_start "quic_block: iptables_manager.sh cleanup unlinks FORWARD -> HNC_QUIC and removes dual-stack HNC_QUIC chains"
qseed '{"quic_block":true}' "ACTIVE:wlan2"
out=$(qrun)
: > "$HNC_TEST_DIR/ipt.log"
: > "$HNC_TEST_DIR/ip6t.log"
HNC_DIR="$HNC_TEST_DIR" HNC_IPT="$HNC_TEST_DIR/stub/iptables -w 2" HNC_IP6T="$HNC_TEST_DIR/stub/ip6tables -w 2" \
    PATH="$HNC_TEST_DIR/stub:$PATH" sh "$HNC_REPO_ROOT/bin/iptables_manager.sh" cleanup >/dev/null 2>&1
rc_cleanup=$?
[ "$out" = "QUIC_BLOCK=on iface=wlan2" ] \
    && [ "$rc_cleanup" -eq 0 ] \
    && grep -qE -- '-t filter -D FORWARD -j HNC_QUIC$' "$HNC_TEST_DIR/ipt.log" \
    && grep -qE -- '-t filter -F HNC_QUIC$' "$HNC_TEST_DIR/ipt.log" \
    && grep -qE -- '-t filter -X HNC_QUIC$' "$HNC_TEST_DIR/ipt.log" \
    && grep -qE -- '-t filter -D FORWARD -j HNC_QUIC$' "$HNC_TEST_DIR/ip6t.log" \
    && grep -qE -- '-t filter -F HNC_QUIC$' "$HNC_TEST_DIR/ip6t.log" \
    && grep -qE -- '-t filter -X HNC_QUIC$' "$HNC_TEST_DIR/ip6t.log" \
    && test_pass || test_fail "out=$out rc=$rc_cleanup v4=$(cat "$HNC_TEST_DIR/ipt.log") v6=$(cat "$HNC_TEST_DIR/ip6t.log")"
