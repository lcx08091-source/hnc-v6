package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureCert 确保 cert/key 文件存在;不存在则生成自签 P-256 ECDSA 证书
// 10 年有效期(家用设备,不期望短期轮换)
// SAN 包含 bindIP + localhost 方便本机调试
// 权限严格 0600,防止普通应用读到私钥
// rc3.1.14 修 P3 (review): 之前只看 cert/key 文件存在就 reuse, 不检查内容.
// 实际场景: 用户从 192.168.43.1 迁移到 10.41.82.1 (热点子网换了), 旧 cert
// 的 SAN 不再匹配, 浏览器 SAN mismatch 警告; 或者 cert 接近过期没人重生.
// 现在: 文件存在但 (过期 / 30 天内将过期 / bindIP 不在 SAN) → 重生.
func ensureCert(certPath, keyPath, bindIP string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// 文件都在, 但要校验内容是否还匹配
			if reason := certNeedsRegen(certPath, bindIP); reason == "" {
				log.Printf("using existing cert: %s", certPath)
				return nil
			} else {
				log.Printf("cert %s needs regen: %s", certPath, reason)
				// fall through 重生
			}
		}
	}

	log.Printf("generating self-signed cert: %s (10-year validity)", certPath)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("gen key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("gen serial: %w", err)
	}

	ip := net.ParseIP(bindIP)
	if ip == nil {
		return fmt.Errorf("invalid bind IP: %s", bindIP)
	}

	// rc3.1.34 修 #31: bindIP 是 0.0.0.0 时不写进 SAN. 浏览器永远不会用 0.0.0.0
	// 连接 (URL bar 不接受 unspecified 地址), SAN 里 0.0.0.0 完全无意义, 部分
	// TLS 库 (Java jks importer / 一些 mTLS 库) 看到 0.0.0.0 在 SAN 里会 warning
	// 或拒签. certNeedsRegen 已经对 0.0.0.0 短路 (line 148-150), 配套这里也跳过.
	// IP SAN 去重: 如果 bindIP 已经是 127.0.0.1 或 0.0.0.0, 不加 bindIP, 仅留 loopback
	ipSANs := []net.IP{}
	loopback := net.IPv4(127, 0, 0, 1)
	if v4 := ip.To4(); v4 != nil && !v4.IsUnspecified() && !ip.Equal(loopback) {
		ipSANs = append(ipSANs, ip)
	}
	ipSANs = append(ipSANs, loopback)

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HNC Remote Access (self-signed)"},
		NotBefore:             time.Now().Add(-5 * time.Minute), // 防时钟偏差
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           ipSANs,
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	// 保证父目录存在
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}

	// 证书: 0644 (公共部分)
	// rc3.1.34 修 #37: 跟 key 路径对齐, 用 tmp+rename 原子写. 之前直接 WriteFile,
	// 进程在写中间被杀 (OOM / cleanup) → 半个 cert 文件落盘 → 下次启动 pem.Decode
	// 失败 → certNeedsRegen 触发重生 (自愈). 但中间 N 秒窗口内任何尝试启动 httpd
	// 的进程会拿到坏 cert. tmp+rename 让 cert 要么完整要么不存在.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpCert := certPath + ".tmp"
	if err := os.WriteFile(tmpCert, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert tmp: %w", err)
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		_ = os.Remove(tmpCert)
		return fmt.Errorf("rename cert: %w", err)
	}

	// 私钥: 0600 (严格)
	// 先写 .tmp 再 rename,防中间状态被读到
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tmpKey := keyPath + ".tmp"
	if err := os.WriteFile(tmpKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key tmp: %w", err)
	}
	if err := os.Chmod(tmpKey, 0600); err != nil {
		_ = os.Remove(tmpKey)
		return fmt.Errorf("chmod key: %w", err)
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		_ = os.Remove(tmpKey)
		return fmt.Errorf("rename key: %w", err)
	}

	return nil
}

// certNeedsRegen 检查现有 cert 是否需要重生.
// 返回空串表示可继续用, 非空是 reason (打 log 用).
// rc3.1.14 修 P3 (review): bindIP 漂移 / 过期提前 30 天预警都触发重生.
func certNeedsRegen(certPath, bindIP string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "read failed: " + err.Error()
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "not a valid PEM certificate"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "parse failed: " + err.Error()
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return "expired at " + cert.NotAfter.Format(time.RFC3339)
	}
	// 30 天内将过期 → 提前重生 (10 年证书极少触发, 但接 LTS 节奏算合理)
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		return "expires within 30 days at " + cert.NotAfter.Format(time.RFC3339)
	}
	// bindIP 必须在 SAN 中
	wantIP := net.ParseIP(bindIP)
	if wantIP == nil {
		return "" // bindIP 解析失败由上层处理, 这里不阻塞 reuse
	}
	// rc3.1.14 修边界: 0.0.0.0 (IsUnspecified) bind 时不强求 SAN 匹配,
	// 否则每次启动都触发重生 (集成测试 T5 暴露). 0.0.0.0 监听所有接口,
	// 没有"该用哪个 IP"的明确答案, 沿用现有 cert 即可.
	if wantIP.To4() != nil && wantIP.To4().IsUnspecified() {
		return ""
	}
	for _, ip := range cert.IPAddresses {
		if ip.Equal(wantIP) {
			return "" // SAN 命中, 可继续用
		}
	}
	return "bindIP " + bindIP + " not in SAN " + ipsString(cert.IPAddresses)
}

func ipsString(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	if len(parts) == 0 {
		return "[]"
	}
	out := "["
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out + "]"
}
