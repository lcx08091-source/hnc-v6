#!/system/bin/sh
# test/unit/test_tokens.sh — json_set.sh token_* 子命令单元测试
#
# v5.9.0 单写者化改写: token_revoke/_all 不再直改 remote_tokens.json,
# 而是追加撤销请求到 run/token_revoke.request(marker 桥),由 httpd
# (remote_tokens.json 唯一运行期写者)消费落盘。本测试断言:
#   1. CLI 接口/退出码不变(入参校验原样保留);
#   2. tokens.json 内容对 shell 侧不可变(md5 前后一致);
#   3. request 文件按行累积 TokenID / ALL;
#   4. 非法 TokenID 被拒且不产生排队行。

JSON_SET="$HNC_REPO_ROOT/bin/json_set.sh"
TOKENS_FILE="$HNC_TEST_DIR/data/remote_tokens.json"
REVOKE_REQ="$HNC_TEST_DIR/run/token_revoke.request"

js() {
    HNC="$HNC_TEST_DIR" sh "$JSON_SET" "$@"
}

file_md5() {
    md5sum "$1" 2>/dev/null | awk '{print $1}'
}

req_lines() {
    [ -f "$REVOKE_REQ" ] && wc -l < "$REVOKE_REQ" | tr -d ' ' || echo 0
}

# helper: 写入标准的两条 token 测试文件(revoked 都为 false)
seed_two_tokens() {
    rm -f "$REVOKE_REQ"
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

# ═══ token_revoke 基本(marker 语义) ══════════════════════════════

test_start "token_revoke queues TokenID and leaves tokens.json untouched"
seed_two_tokens
before=$(file_md5 "$TOKENS_FILE")
js token_revoke "aB3xK7mQ9N"
rc=$?
after=$(file_md5 "$TOKENS_FILE")
req=$(cat "$REVOKE_REQ" 2>/dev/null)
assert_eq "0" "$rc" "revoke should succeed" && \
    assert_eq "$before" "$after" "tokens.json must NOT be modified by shell" && \
    assert_contains "$req" "aB3xK7mQ9N" && test_pass

test_start "token_revoke appends one line per call (idempotent queueing)"
seed_two_tokens
js token_revoke "aB3xK7mQ9N" > /dev/null
js token_revoke "pZ8nR4wE5Y" > /dev/null
rc=$?
n=$(req_lines)
assert_eq "0" "$rc" && \
    assert_eq "2" "$n" "two calls → two queued lines" && test_pass

test_start "token_revoke on non-existent TokenID still queues (httpd side is idempotent)"
seed_two_tokens
js token_revoke "NOSUCHTOKEN1"
rc=$?
req=$(cat "$REVOKE_REQ" 2>/dev/null)
assert_eq "0" "$rc" "should succeed (httpd silently ignores unknown ids)" && \
    assert_contains "$req" "NOSUCHTOKEN1" && test_pass

# ═══ token_revoke 格式校验(与旧版一致,且不得排队) ═══════════════

test_start "token_revoke rejects empty TokenID"
seed_two_tokens
js token_revoke "" 2>/dev/null
rc=$?
n=$(req_lines)
assert_eq "1" "$rc" "empty TokenID should fail" && \
    assert_eq "0" "$n" "no line queued" && test_pass

test_start "token_revoke rejects TokenID with path traversal"
seed_two_tokens
js token_revoke "../../etc/passwd" 2>/dev/null
rc=$?
n=$(req_lines)
assert_eq "1" "$rc" "path traversal should fail" && \
    assert_eq "0" "$n" "no line queued" && test_pass

test_start "token_revoke rejects TokenID with shell injection"
seed_two_tokens
js token_revoke "a; rm -rf /" 2>/dev/null
rc=$?
n=$(req_lines)
assert_eq "1" "$rc" "shell injection should fail" && \
    assert_eq "0" "$n" "no line queued" && test_pass

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

test_start "token_revoke_all queues ALL and leaves tokens.json untouched"
seed_two_tokens
before=$(file_md5 "$TOKENS_FILE")
js token_revoke_all
rc=$?
after=$(file_md5 "$TOKENS_FILE")
req=$(cat "$REVOKE_REQ" 2>/dev/null)
assert_eq "0" "$rc" && \
    assert_eq "$before" "$after" "tokens.json must NOT be modified by shell" && \
    assert_contains "$req" "ALL" && test_pass

test_start "token_revoke_all works without tokens.json present"
rm -f "$TOKENS_FILE" "$REVOKE_REQ"
js token_revoke_all
rc=$?
req=$(cat "$REVOKE_REQ" 2>/dev/null)
# 单写者模型: shell 不再创建/初始化 tokens.json(那是 httpd 的事)
assert_eq "0" "$rc" && \
    assert_contains "$req" "ALL" && test_pass

# ═══ request 文件属性 ═════════════════════════════════════════════

test_start "token_revoke request file is 0600"
seed_two_tokens
js token_revoke "aB3xK7mQ9N" > /dev/null
perm=$(stat -c '%a' "$REVOKE_REQ" 2>/dev/null || stat -f '%Lp' "$REVOKE_REQ" 2>/dev/null)
assert_eq "600" "$perm" "request file should be 0600" && test_pass

test_start "token_revoke does not create or touch tokens.json when missing"
rm -f "$TOKENS_FILE" "$REVOKE_REQ"
js token_revoke "aB3xK7mQ9N"
rc=$?
exists=0; [ -f "$TOKENS_FILE" ] && exists=1
assert_eq "0" "$rc" "queueing works without tokens.json" && \
    assert_eq "0" "$exists" "shell must not create tokens.json (httpd owns it)" && test_pass

# ═══ token_prune marker 机制(不变) ═══════════════════════════════

test_start "token_prune creates httpd_prune_request marker"
rm -f "$HNC_TEST_DIR/run/httpd_prune_request"
js token_prune
assert_file_exists "$HNC_TEST_DIR/run/httpd_prune_request" && test_pass

test_start "token_prune is idempotent"
rm -f "$HNC_TEST_DIR/run/httpd_prune_request"
js token_prune
js token_prune    # 第二次
assert_file_exists "$HNC_TEST_DIR/run/httpd_prune_request" && test_pass

# ═══ 快速连发不损坏 ═══════════════════════════════════════════════

test_start "rapid token_revoke calls keep request file line-oriented and tokens.json intact"
seed_two_tokens
before=$(file_md5 "$TOKENS_FILE")
i=0
while [ $i -lt 10 ]; do
    js token_revoke "aB3xK7mQ9N" > /dev/null 2>&1
    i=$((i+1))
done
after=$(file_md5 "$TOKENS_FILE")
n=$(req_lines)
# grep -c 无匹配时打印 0 但退出码 1,不能接 || echo 0(会变成两行"0")
bad=$(grep -cv '^[A-Za-z0-9_-]\{1,\}$' "$REVOKE_REQ" 2>/dev/null)
[ -n "$bad" ] || bad=0
assert_eq "$before" "$after" "tokens.json untouched after 10 queued revokes" && \
    assert_eq "10" "$n" "10 calls → 10 lines" && \
    assert_eq "0" "$bad" "every line is a bare base64url token" && test_pass
