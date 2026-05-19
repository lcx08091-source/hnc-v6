#!/system/bin/sh
# test/unit/test_tokens.sh — json_set.sh token_* 子命令单元测试(Patch 2.a)

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"
TOKENS_FILE="$HNC_TEST_DIR/data/remote_tokens.json"

js() {
    HNC="$HNC_TEST_DIR" sh "$JSON_SET" "$@"
}

# helper: 写入标准的两条 token 测试文件(revoked 都为 false)
seed_two_tokens() {
    cat > "$TOKENS_FILE" << 'EOF'
{
  "version": 1,
  "tokens": {
    "aB3xK7mQ9N": {
      "hash": "$2a$10$AAA",
      "created": 1700000000,
      "last_seen": 1700000100,
      "label": "Alice",
      "ip_hint": "192.168.43.10",
      "revoked": false
    },
    "pZ8nR4wE5Y": {
      "hash": "$2a$10$BBB",
      "created": 1700000200,
      "last_seen": 1700000300,
      "label": "Bob",
      "ip_hint": "192.168.43.20",
      "revoked": false
    }
  }
}
EOF
}

# ═══ token_revoke 基本 ═══════════════════════════════════════════

test_start "token_revoke sets specific token revoked=true"
seed_two_tokens
js token_revoke "aB3xK7mQ9N"
content=$(cat "$TOKENS_FILE")
# aB3xK7mQ9N 应该 revoked=true,pZ8nR4wE5Y 应该还是 false
# 用 awk 只抽 aB3xK7mQ9N 块看 revoked
alice_rev=$(awk '/aB3xK7mQ9N/,/\}/' "$TOKENS_FILE" | grep revoked)
bob_rev=$(awk '/pZ8nR4wE5Y/,/\}/' "$TOKENS_FILE" | grep revoked)
assert_contains "$alice_rev" "true" && \
    assert_contains "$bob_rev" "false" && test_pass

test_start "token_revoke for second token leaves first alone"
seed_two_tokens
js token_revoke "pZ8nR4wE5Y"
alice_rev=$(awk '/aB3xK7mQ9N/,/\}/' "$TOKENS_FILE" | grep revoked)
bob_rev=$(awk '/pZ8nR4wE5Y/,/\}/' "$TOKENS_FILE" | grep revoked)
assert_contains "$alice_rev" "false" && \
    assert_contains "$bob_rev" "true" && test_pass

test_start "token_revoke idempotent on non-existent TokenID"
seed_two_tokens
js token_revoke "NOSUCH"
rc=$?
content=$(cat "$TOKENS_FILE")
assert_eq "0" "$rc" "should succeed silently" && \
    assert_contains "$content" '"revoked": false' && test_pass

test_start "token_revoke idempotent on already-revoked"
seed_two_tokens
js token_revoke "aB3xK7mQ9N"
js token_revoke "aB3xK7mQ9N"    # 第二次
rc=$?
alice_rev=$(awk '/aB3xK7mQ9N/,/\}/' "$TOKENS_FILE" | grep revoked)
assert_eq "0" "$rc" "second revoke should still succeed" && \
    assert_contains "$alice_rev" "true" && test_pass

# ═══ token_revoke 格式校验 ════════════════════════════════════════

test_start "token_revoke rejects empty TokenID"
seed_two_tokens
js token_revoke "" 2>/dev/null
rc=$?
assert_eq "1" "$rc" "empty TokenID should fail" && test_pass

test_start "token_revoke rejects TokenID with path traversal"
seed_two_tokens
js token_revoke "../../etc/passwd" 2>/dev/null
rc=$?
assert_eq "1" "$rc" "path traversal should fail" && test_pass

test_start "token_revoke rejects TokenID with shell injection"
seed_two_tokens
js token_revoke "a; rm -rf /" 2>/dev/null
rc=$?
assert_eq "1" "$rc" "shell injection should fail" && test_pass

test_start "token_revoke rejects TokenID with quote"
seed_two_tokens
js token_revoke 'a"b' 2>/dev/null
rc=$?
assert_eq "1" "$rc" "quote should fail" && test_pass

test_start "token_revoke rejects TokenID with space"
seed_two_tokens
js token_revoke "a b" 2>/dev/null
rc=$?
assert_eq "1" "$rc" "space should fail" && test_pass

# ═══ token_revoke_all ═════════════════════════════════════════════

test_start "token_revoke_all flips all revoked:false to true"
seed_two_tokens
js token_revoke_all
content=$(cat "$TOKENS_FILE")
false_count=$(echo "$content" | grep -c '"revoked": false')
true_count=$(echo "$content" | grep -c '"revoked": true')
assert_eq "0" "$false_count" "no false should remain" && \
    assert_eq "2" "$true_count" "both should be true" && test_pass

test_start "token_revoke_all is idempotent"
seed_two_tokens
js token_revoke_all
js token_revoke_all
content=$(cat "$TOKENS_FILE")
true_count=$(echo "$content" | grep -c '"revoked": true')
assert_eq "2" "$true_count" "double revoke_all still 2 true" && test_pass

# ═══ 文件权限与原子性 ═════════════════════════════════════════════

test_start "token_revoke preserves 0600 permissions"
seed_two_tokens
chmod 600 "$TOKENS_FILE"
js token_revoke "aB3xK7mQ9N"
perm=$(stat -c '%a' "$TOKENS_FILE" 2>/dev/null || stat -f '%Lp' "$TOKENS_FILE" 2>/dev/null)
assert_eq "600" "$perm" "tokens.json should remain 0600" && test_pass

test_start "token_revoke_all on missing file creates empty template"
rm -f "$TOKENS_FILE"
js token_revoke_all
assert_file_exists "$TOKENS_FILE" && \
    assert_json_valid "$TOKENS_FILE" && test_pass

test_start "token_revoke creates file if missing (then revokes nothing)"
rm -f "$TOKENS_FILE"
js token_revoke "aB3xK7mQ9N"
rc=$?
assert_eq "0" "$rc" "should succeed on empty store" && \
    assert_file_exists "$TOKENS_FILE" && \
    assert_json_valid "$TOKENS_FILE" && test_pass

# ═══ token_prune marker 机制 ══════════════════════════════════════

test_start "token_prune creates httpd_prune_request marker"
rm -f "$HNC_TEST_DIR/run/httpd_prune_request"
js token_prune
assert_file_exists "$HNC_TEST_DIR/run/httpd_prune_request" && test_pass

test_start "token_prune is idempotent"
rm -f "$HNC_TEST_DIR/run/httpd_prune_request"
js token_prune
js token_prune    # 第二次
assert_file_exists "$HNC_TEST_DIR/run/httpd_prune_request" && test_pass

# ═══ JSON 结构完整性 ═══════════════════════════════════════════════

test_start "token_revoke preserves other fields unchanged"
seed_two_tokens
js token_revoke "aB3xK7mQ9N"
content=$(cat "$TOKENS_FILE")
# 校验 bob 的 label / hash / ip_hint 未被意外修改
assert_contains "$content" '"label": "Bob"' && \
    assert_contains "$content" '"hash": "$2a$10$BBB"' && \
    assert_contains "$content" '"ip_hint": "192.168.43.20"' && test_pass

test_start "token_revoke output is valid JSON"
seed_two_tokens
js token_revoke "aB3xK7mQ9N"
assert_json_valid "$TOKENS_FILE" && test_pass

test_start "token_revoke_all output is valid JSON"
seed_two_tokens
js token_revoke_all
assert_json_valid "$TOKENS_FILE" && test_pass

# ═══ 并发(简化版,真并发看 Go 测试) ═══════════════════════════════

test_start "token_revoke with lock does not corrupt during same-shell rapid calls"
seed_two_tokens
# 快速 10 次切换 revoke (同 TokenID),锁应该能保证每次都拿到一致状态
i=0
while [ $i -lt 10 ]; do
    js token_revoke "aB3xK7mQ9N" > /dev/null 2>&1
    i=$((i+1))
done
assert_json_valid "$TOKENS_FILE" && test_pass
