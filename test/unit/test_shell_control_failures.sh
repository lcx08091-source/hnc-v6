#!/system/bin/sh
# Control-plane regressions use a temporary HNC_DIR and mocked network commands.

test_start "cleanup rules preserves a live IPC endpoint, pidfiles and JSON locks"
if ! command -v python3 >/dev/null 2>&1; then
    test_skip "python3 required for a real Unix socket probe"
else
    mock_setup
    mock_set_exit iptables 1
    mock_set_exit ip6tables 1
    mock_set_exit tc 1
    mock_set_exit ip 1
    printf '#!/bin/sh\necho wlan2\n' > "$HNC_TEST_DIR/bin/device_detect.sh"
    echo "$$" > "$HNC_TEST_DIR/run/httpd.pid"
    mkdir -p "$HNC_TEST_DIR/run/json.lock" "$HNC_TEST_DIR/run/hnc_json.lock"
    echo "$$" > "$HNC_TEST_DIR/run/json.lock/pid"
    echo "$$" > "$HNC_TEST_DIR/run/hnc_json.lock/pid"
    python3 - "$HNC_TEST_DIR/run/hotspotd.sock" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(1)
c, _ = s.accept()
c.recv(4); c.sendall(b"pong"); c.close(); s.close()
PY
    socket_pid=$!
    socket_wait=0
    while [ ! -S "$HNC_TEST_DIR/run/hotspotd.sock" ] && [ "$socket_wait" -lt 200 ]; do
        sleep 0.01
        socket_wait=$((socket_wait + 1))
    done
    HNC_DIR="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/cleanup.sh" rules >/dev/null 2>&1
    cleanup_rc=$?
    python3 - "$HNC_TEST_DIR/run/hotspotd.sock" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2); s.connect(sys.argv[1]); s.sendall(b"ping")
assert s.recv(4) == b"pong"
PY
    ipc_rc=$?
    kill "$socket_pid" 2>/dev/null || true
    wait "$socket_pid" 2>/dev/null || true
    assert_eq 0 "$cleanup_rc" && assert_eq 0 "$ipc_rc" "IPC must still accept connections" && \
        assert_eq "$$" "$(cat "$HNC_TEST_DIR/run/httpd.pid" 2>/dev/null)" && \
        assert_eq "$$" "$(cat "$HNC_TEST_DIR/run/json.lock/pid" 2>/dev/null)" && \
        assert_eq "$$" "$(cat "$HNC_TEST_DIR/run/hnc_json.lock/pid" 2>/dev/null)" && test_pass
    mock_teardown
fi

test_start "apply_device_rule does not borrow the next device's IP"
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:bb:cc:dd:ee:01":{"name":"IPv6 only"},"aa:bb:cc:dd:ee:02":{"ip":"192.168.43.99"}}
EOF
cat > "$HNC_TEST_DIR/bin/iptables_manager.sh" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$HNC_DIR/run/applied.args"
STUB
printf '#!/bin/sh\nexit 0\n' > "$HNC_TEST_DIR/bin/json_set.sh"
HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/apply_device_rule.sh" bl_add aa:bb:cc:dd:ee:01 >/dev/null 2>&1
rc=$?
args=$(cat "$HNC_TEST_DIR/run/applied.args" 2>/dev/null)
assert_eq 0 "$rc" && assert_eq "$(printf 'blacklist_add\n\naa:bb:cc:dd:ee:01')" "$args" \
    "missing IP must use MAC-only blocking instead of another client's IP" && test_pass

test_start "apply_device_rule resolves its own IP from formatted device JSON"
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{
  "aa:bb:cc:dd:ee:01": {"name":"A } B", "ip": "192.168.43.5"},
  "aa:bb:cc:dd:ee:02": {"ip":"192.168.43.99"}
}
EOF
cat > "$HNC_TEST_DIR/bin/iptables_manager.sh" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$HNC_DIR/run/applied.args"
STUB
printf '#!/bin/sh\nexit 0\n' > "$HNC_TEST_DIR/bin/json_set.sh"
HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/apply_device_rule.sh" bl_add aa:bb:cc:dd:ee:01 >/dev/null 2>&1
rc=$?
args=$(cat "$HNC_TEST_DIR/run/applied.args" 2>/dev/null)
assert_eq 0 "$rc" && assert_eq "$(printf 'blacklist_add\n192.168.43.5\naa:bb:cc:dd:ee:01')" "$args" && test_pass
