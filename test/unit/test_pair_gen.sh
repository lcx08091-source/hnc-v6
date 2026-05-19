#!/system/bin/sh
# test/unit/test_pair_gen.sh — bin/pair_gen.sh 单元测试(Patch 2.c)

PAIR_GEN="$HNC_REPO_ROOT/bin/pair_gen.sh"

pg() {
    HNC_DIR="$HNC_TEST_DIR" sh "$PAIR_GEN" "$@"
}

# fake httpd in running state
start_fake_httpd() {
    echo $$ > "$HNC_TEST_DIR/run/httpd.pid"
}

# ─── basic generate ───────────────────────────────────────────────

test_start "pair_gen: generate with no httpd returns error"
# 干净环境, 没写 httpd.pid
out=$(pg 2>&1)
rc=$?
assert_ne "0" "$rc" "should fail without httpd"
echo "$out" | grep -q '"ok":false' || test_fail "expected ok:false in output: $out"
echo "$out" | grep -q 'httpd not running' || test_fail "expected error message: $out"
test_pass

test_start "pair_gen: generate outputs valid JSON"
start_fake_httpd
out=$(pg)
rc=$?
assert_eq "0" "$rc" "should succeed"
echo "$out" | grep -q '"ok":true' || test_fail "expected ok:true: $out"
echo "$out" | grep -qE '"pin":"[0-9]{6}"' || test_fail "expected 6-digit pin: $out"
echo "$out" | grep -qE '"session_id":"[a-zA-Z0-9_-]+"' || test_fail "expected sid: $out"
echo "$out" | grep -qE '"expiry":[0-9]+' || test_fail "expected expiry: $out"
echo "$out" | grep -qE '"valid_sec":120' || test_fail "expected valid_sec=120: $out"
test_pass

test_start "pair_gen: writes pair_pending with 3 lines"
start_fake_httpd
pg > /dev/null
[ -f "$HNC_TEST_DIR/run/pair_pending" ] || test_fail "pair_pending not created"
lines=$(wc -l < "$HNC_TEST_DIR/run/pair_pending")
assert_eq "3" "$lines" "pair_pending should have 3 lines"
# line 1: 6-digit pin
pin=$(sed -n '1p' "$HNC_TEST_DIR/run/pair_pending")
case "$pin" in
    [0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) test_fail "bad pin format: $pin" ;;
esac
# line 2: sid
sid=$(sed -n '2p' "$HNC_TEST_DIR/run/pair_pending")
case "$sid" in
    [a-zA-Z0-9]*) ;;
    *) test_fail "sid must start with alnum: $sid" ;;
esac
[ ${#sid} -ge 8 ] && [ ${#sid} -le 64 ] || test_fail "bad sid length: $sid (${#sid})"
# line 3: expiry > now
expiry=$(sed -n '3p' "$HNC_TEST_DIR/run/pair_pending")
now=$(date +%s)
[ "$expiry" -gt "$now" ] || test_fail "expiry not in future: $expiry vs $now"
test_pass

test_start "pair_gen: pair_pending has 0600 perms"
start_fake_httpd
pg > /dev/null
perms=$(stat -c %a "$HNC_TEST_DIR/run/pair_pending" 2>/dev/null || stat -f %Lp "$HNC_TEST_DIR/run/pair_pending" 2>/dev/null)
assert_eq "600" "$perms" "pair_pending should be 0600"
test_pass

# ─── sid 分布(防参数注入) ─────────────────────────────────────────

test_start "pair_gen: 20 sids all start with alphanumeric"
start_fake_httpd
bad_count=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    out=$(pg)
    sid=$(echo "$out" | grep -oE '"session_id":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
    first=$(printf '%s' "$sid" | head -c 1)
    case "$first" in
        [a-zA-Z0-9]) ;;
        *) bad_count=$((bad_count + 1)) ;;
    esac
done
assert_eq "0" "$bad_count" "all 20 sids must start with alnum"
test_pass

# ─── PIN 分布 (宽松 — 10 次生成至少有 8 个不同值) ─────────────────

test_start "pair_gen: PIN has entropy (10 generations, 7+ unique)"
start_fake_httpd
pins=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    pin=$(pg | grep -oE '"pin":"[0-9]+"' | sed 's/.*"\([0-9]*\)"$/\1/')
    pins="$pins $pin"
done
uniq_count=$(echo "$pins" | tr ' ' '\n' | sort -u | grep -c .)
if [ "$uniq_count" -lt 7 ]; then
    test_fail "too few unique PINs: $uniq_count of 10 ($pins)"
fi
test_pass

# ─── cancel ────────────────────────────────────────────────────────

test_start "pair_gen: cancel removes pair_pending"
start_fake_httpd
pg > /dev/null
[ -f "$HNC_TEST_DIR/run/pair_pending" ] || test_fail "setup failed"
out=$(pg cancel)
echo "$out" | grep -q '"cancelled":true' || test_fail "expected cancelled:true: $out"
[ ! -f "$HNC_TEST_DIR/run/pair_pending" ] || test_fail "pair_pending not removed after cancel"
test_pass

test_start "pair_gen: cancel when nothing pending is ok"
start_fake_httpd
out=$(pg cancel)
rc=$?
assert_eq "0" "$rc" "cancel on empty should succeed"
echo "$out" | grep -q '"ok":true' || test_fail "expected ok:true"
test_pass

# ─── status ────────────────────────────────────────────────────────

test_start "pair_gen: status without pending returns active=false"
start_fake_httpd
out=$(pg status)
echo "$out" | grep -q '"active":false' || test_fail "expected active:false: $out"
# 不应该泄露 PIN
echo "$out" | grep -q '"pin"' && test_fail "status must not expose pin: $out"
test_pass

test_start "pair_gen: status with pending returns sid + remaining but no PIN"
start_fake_httpd
pg > /dev/null
out=$(pg status)
echo "$out" | grep -q '"active":true' || test_fail "expected active:true: $out"
echo "$out" | grep -qE '"session_id":"[a-zA-Z0-9_-]+"' || test_fail "expected sid: $out"
echo "$out" | grep -qE '"remaining_sec":[0-9]+' || test_fail "expected remaining_sec: $out"
# 关键: status 不泄露 PIN
echo "$out" | grep -q '"pin"' && test_fail "status leaked pin!: $out"
test_pass

test_start "pair_gen: status detects expired and cleans up"
start_fake_httpd
# 手工写一个已过期的 pair_pending
printf '123456\nsidabcde\n%d\n' "$(( $(date +%s) - 60 ))" > "$HNC_TEST_DIR/run/pair_pending"
out=$(pg status)
echo "$out" | grep -q '"active":false' || test_fail "expected active:false for expired: $out"
echo "$out" | grep -q '"was_expired":true' || test_fail "expected was_expired: $out"
[ ! -f "$HNC_TEST_DIR/run/pair_pending" ] || test_fail "expired pair_pending should be auto-removed"
test_pass

# ─── 原子性: generate 过程中不能看到半写文件 ──────────────────────
# 由于 tmp+rename, 观察者看到的永远是完整文件或没文件
test_start "pair_gen: generate uses atomic tmp+rename"
start_fake_httpd
pg > /dev/null
# 不该留下 tmp 文件
[ -f "$HNC_TEST_DIR/run/pair_pending.tmp" ] && test_fail "pair_pending.tmp leaked"
test_pass

# ─── stale httpd pid 检测 ─────────────────────────────────────────

test_start "pair_gen: detects stale pid file (process dead)"
# 写一个肯定不存在的 PID
echo "999999" > "$HNC_TEST_DIR/run/httpd.pid"
out=$(pg 2>&1)
rc=$?
assert_ne "0" "$rc" "should fail with stale pid"
echo "$out" | grep -q 'stale\|dead' || test_fail "expected dead/stale hint: $out"
test_pass

# ─── 清理 pair_success 老文件 ──────────────────────────────────────

test_start "pair_gen: cleans up pair_success files older than 60min"
start_fake_httpd
# 造一个 2 小时前的 success 文件
old="$HNC_TEST_DIR/run/pair_success.oldsid1234"
recent="$HNC_TEST_DIR/run/pair_success.newsid1234"
echo "x" > "$old"
echo "x" > "$recent"
# 把 old 的 mtime 设 2 小时前(120 分钟)
touch -t $(date -d '120 minutes ago' +%Y%m%d%H%M 2>/dev/null || \
    date -v-120M +%Y%m%d%H%M 2>/dev/null || \
    echo "202301010000") "$old" 2>/dev/null

pg > /dev/null
# old 应被清, recent 应保留
[ -f "$old" ] && test_fail "old pair_success not cleaned"
[ -f "$recent" ] || test_fail "recent pair_success wrongly cleaned"
test_pass
