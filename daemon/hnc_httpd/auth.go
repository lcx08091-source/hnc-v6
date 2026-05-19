// auth.go - Patch 2.a 鉴权核心
//
// 架构(按 v4_0_design_v2.1 §3.2):
//   Cookie 格式: hnc_token=<TokenID>.<Secret>
//   TokenID: 8 字节 random base64url (约 11 字符,非保密,审计可记)
//   Secret:  24 字节 random base64url (约 32 字符,永不存磁盘 / 永不 log)
//   签发: bcrypt(Secret, cost=10) 存 tokens[TokenID].hash
//   验证: 解析 TokenID → O(1) 查 tokens → 1 次 bcrypt(Secret vs hash) → 恒定 100ms
//
// 安全属性(Gemini v2 审查 1.1 核心):
//   - TokenID 未命中 tokens map → 立即返回 false,不碰 bcrypt(关闭 CPU DoS 向量)
//   - Secret 恒定长度 bcrypt,耗时不随 token 总数扩展
//   - 审计日志记 TokenID 前缀不泄 Secret

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	tokenIDBytes      = 8  // base64url encode 后约 11 字符
	tokenSecretBytes  = 24 // base64url encode 后约 32 字符
	bcryptCost        = 10 // ~100ms on x86_64,arm64 可能 200-300ms
	collisionRetryMax = 3  // TokenID 冲突重试上限(实际 2^64 空间几乎永不冲突)
)

// ErrBadCookieFormat 表示 cookie 不是合法的 TokenID.Secret 格式
var ErrBadCookieFormat = errors.New("malformed cookie")

// IssueToken 生成一对新的 TokenID+Secret,bcrypt hash 存入 store。
// 返回的 cookieValue 是拼接后的字符串,可直接放进 Set-Cookie 的 Value。
// 明文 Secret **不**返回给调用者之外的任何地方,不入 log。
//
// v2.a hotfix (Gemini 2.1): 用 PutIfAbsent 单锁原子原语,消除 TOCTOU 竞态。
// 之前 "RLock check + 无锁随机 + Lock put" 模式在两个并发协程碰到相同 TokenID 时
// 会相互覆盖。虽然 2^64 空间碰撞现实不发生,代码模型上的缺陷通过重试循环消除。
func IssueToken(store *TokensStore, label, ipHint string) (cookieValue string, tokenID string, err error) {
	// 1. 先生成 Secret + bcrypt(慢操作,不持锁)
	secret, err := randomBase64URL(tokenSecretBytes)
	if err != nil {
		return "", "", fmt.Errorf("generate Secret: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("bcrypt: %w", err)
	}

	// 2. 生成 TokenID + PutIfAbsent 重试
	//    2^64 空间实际不会碰撞,但代码模型允许最多 3 次重试
	now := time.Now().Unix()
	tok := Token{
		Hash:     string(hash),
		Created:  now,
		LastSeen: now,
		Label:    label,
		IPHint:   ipHint,
		Revoked:  false,
	}
	for i := 0; i < collisionRetryMax; i++ {
		tokenID, err = randomBase64URL(tokenIDBytes)
		if err != nil {
			return "", "", fmt.Errorf("generate TokenID: %w", err)
		}
		err = store.PutIfAbsent(tokenID, tok)
		if err == nil {
			// 成功
			return tokenID + "." + secret, tokenID, nil
		}
		if !errors.Is(err, ErrTokenIDCollision) {
			// 非冲突错误(比如磁盘写失败),立即返回不重试
			return "", "", fmt.Errorf("store put: %w", err)
		}
		// 冲突,重试
	}
	return "", "", fmt.Errorf("TokenID collision after %d retries (should be impossible with 2^64 space)", collisionRetryMax)
}

// randomBase64URL 生成 n 字节随机数据,用 base64 URL-safe 编码(无 padding)
// 8 字节 → 11 字符, 24 字节 → 32 字符
func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// VerifyCookie 验证 cookie value 是否有效。
// 成功返回 (tokenID, token, nil)。失败返回 (_, _, err)。
// 可能的失败原因:
//   - cookie 格式错(不是 TokenID.Secret)
//   - TokenID 不存在 tokens 中(此时不做 bcrypt,防 DoS)
//   - token 已 revoked
//   - token 硬过期(last_seen > 60 天)
//   - Secret 错(bcrypt 不匹配)
//
// 调用者应先调 store.SyncIfChanged() 保证 tokens 是最新的。
func VerifyCookie(store *TokensStore, cookieValue string) (string, Token, error) {
	tokenID, secret, err := parseCookie(cookieValue)
	if err != nil {
		return "", Token{}, err
	}

	tok, ok := store.Get(tokenID)
	if !ok {
		// 关键: TokenID 不存在时立即返回,不碰 bcrypt
		// 这是防御 O(N) CPU DoS 的核心
		return "", Token{}, errors.New("unknown token")
	}

	if tok.Revoked {
		return "", Token{}, errors.New("token revoked")
	}

	// 硬过期
	if tok.LastSeen > 0 && time.Now().Unix()-tok.LastSeen > hardExpireSec {
		return "", Token{}, errors.New("token hard expired")
	}

	// 单次 bcrypt 比对(恒定 100ms)
	if err := bcrypt.CompareHashAndPassword([]byte(tok.Hash), []byte(secret)); err != nil {
		return "", Token{}, errors.New("secret mismatch")
	}

	return tokenID, tok, nil
}

// parseCookie 把 "TokenID.Secret" 拆开并做格式校验。
// 合法的 TokenID 和 Secret 都是 base64url 字符 [A-Za-z0-9_-]。
// 不允许空字符串、含 `.` 之外其他分隔符、长度异常。
//
// v2.a hotfix (Gemini 3.1): base64url RawURLEncoding 对固定字节数输入长度唯一:
//
//	8 字节 → 恰好 11 字符
//	24 字节 → 恰好 32 字符
//
// 改成严格等号,密码学代码的标准实践。
const (
	tokenIDLen = 11 // base64url(8 bytes) = 11 chars
	secretLen  = 32 // base64url(24 bytes) = 32 chars
)

func parseCookie(v string) (tokenID, secret string, err error) {
	// 1. 必须有且仅有 1 个 `.`
	i := strings.IndexByte(v, '.')
	if i < 0 || strings.IndexByte(v[i+1:], '.') >= 0 {
		return "", "", ErrBadCookieFormat
	}
	tokenID = v[:i]
	secret = v[i+1:]

	// 2. 严格长度校验
	if len(tokenID) != tokenIDLen {
		return "", "", ErrBadCookieFormat
	}
	if len(secret) != secretLen {
		return "", "", ErrBadCookieFormat
	}

	// 3. 字符集校验
	if !isBase64URLString(tokenID) || !isBase64URLString(secret) {
		return "", "", ErrBadCookieFormat
	}

	return tokenID, secret, nil
}

// isBase64URLString 检查字符串是否全部是 base64 URL-safe 字符集 [A-Za-z0-9_-]
func isBase64URLString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return len(s) > 0
}

// TokenIDLogPrefix 返回 TokenID 的前 8 字符用于日志。
// TokenID 本身不是秘密,但日志里只需要前缀做关联追踪即可。
func TokenIDLogPrefix(tokenID string) string {
	if len(tokenID) <= 8 {
		return tokenID
	}
	return tokenID[:8]
}
