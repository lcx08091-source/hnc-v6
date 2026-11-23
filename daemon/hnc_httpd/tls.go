package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

const (
	// tlsCertValidityDays Apple HT211025 强制 TLS 服务器证书有效期 <= 398 天;
	// 取 397 天(含 -5m 时钟偏差余量后总跨度约 397.003 天 < 398 天), 避免 iOS/macOS Safari 硬拒。
	tlsCertValidityDays = 397
	// tlsCertMaxAllowedSpan 存量旧版 10 年自签证书(> 825 天)升级后首次启动自动轮换重签。
	tlsCertMaxAllowedSpan = 825 * 24 * time.Hour
)

// ensureCert 确保 cert/key 文件存在;不存在则生成自签 P-256 ECDSA 证书
// 397 天有效期(符合 Apple Safari <= 398/825 天强制规范, 30 天内到期自动续签)
// SAN 包含 bindIP + 127.0.0.1 + ::1 + 本机私网/热点接口 IP + localhost
// 权限严格 0600,防止普通应用读到私钥
func ensureCert(certPath, keyPath, bindIP string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// 文件都在, 但要校验内容是否还匹配
			reason := certNeedsRegen(certPath, bindIP)
			// v5.11: 还要校验 cert/key 是否配对。下面生成时 cert 与 key 分两次
			// rename, 两次之间进程被杀 → 新 cert + 旧 key; certNeedsRegen 只看
			// cert(有效)会直接复用 → ListenAndServeTLS 报 "private key does
			// not match public key" → log.Fatalf, watchdog 重启后依旧, 远程
			// 访问永久不可用。配对失败即重生, 自愈。
			if reason == "" {
				if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
					reason = "cert/key pair invalid: " + err.Error()
				}
			}
			if reason == "" {
				log.Printf("using existing cert: %s", certPath)
				return nil
			}
			log.Printf("cert %s needs regen: %s", certPath, reason)
			// fall through 重生
		}
	}

	log.Printf("generating self-signed cert: %s (%d-day validity)", certPath, tlsCertValidityDays)

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

	ipSANs := collectCertIPSANs(ip)
	now := time.Now()

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HNC Remote Access (self-signed)"},
		NotBefore:             now.Add(-5 * time.Minute), // 防时钟偏差
		NotAfter:              now.AddDate(0, 0, tlsCertValidityDays),
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

	// 证书: 0644 (公共部分), tmp+rename 原子写, 失败清理 .tmp
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpCert := certPath + ".tmp"
	if err := os.WriteFile(tmpCert, certPEM, 0644); err != nil {
		_ = os.Remove(tmpCert)
		return fmt.Errorf("write cert tmp: %w", err)
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		_ = os.Remove(tmpCert)
		return fmt.Errorf("rename cert: %w", err)
	}

	// 私钥: 0600 (严格), 先写 .tmp 再 rename, 失败清理 .tmp 防半截私钥残留
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tmpKey := keyPath + ".tmp"
	if err := os.WriteFile(tmpKey, keyPEM, 0600); err != nil {
		_ = os.Remove(tmpKey)
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

// collectCertIPSANs 汇总证书 IP SAN: 显式 bindIP(非 0.0.0.0/::) + 127.0.0.1 + ::1 + 当前本机私网/热点接口 IP。
func collectCertIPSANs(bindIP net.IP) []net.IP {
	var out []net.IP
	add := func(cand net.IP) {
		if cand == nil || cand.IsUnspecified() || cand.IsMulticast() {
			return
		}
		if v4 := cand.To4(); v4 != nil {
			cand = v4
		} else if len(cand) == net.IPv6len {
			cand = append(net.IP(nil), cand...)
		} else {
			return
		}
		for _, existing := range out {
			if existing.Equal(cand) {
				return
			}
		}
		out = append(out, cand)
	}

	if bindIP != nil && !bindIP.IsUnspecified() && !bindIP.IsLoopback() {
		add(bindIP)
	}
	add(net.IPv4(127, 0, 0, 1))
	add(net.IPv6loopback)

	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isCellIface(ifi.Name) || isVPNIface(ifi.Name) {
			continue
		}
		isHotspotDown := isAPIfaceName(ifi.Name) ||
			hncAPMaybeIfaceRE.MatchString(ifi.Name) ||
			hncUSBTetherRE.MatchString(ifi.Name) ||
			hncBTTetherRE.MatchString(ifi.Name)
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if len(out) >= 36 {
				return out
			}
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if ip.IsPrivate() || (isHotspotDown && (ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast())) {
				add(ip)
			}
		}
	}
	return out
}

// certNeedsRegen 检查现有 cert 是否需要重生.
// 返回空串表示可继续用, 非空是 reason (打 log 用).
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
	// RC2: 存量 10 年旧证书(> 825 天)会被 iOS/macOS Safari 硬拒, 自动轮换为 397 天新证书
	if span := cert.NotAfter.Sub(cert.NotBefore); span > tlsCertMaxAllowedSpan {
		return fmt.Sprintf("validity span %dh exceeds 825-day Safari limit", int(span.Hours()))
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return "expired at " + cert.NotAfter.Format(time.RFC3339)
	}
	// 30 天内将过期 → 提前重生
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		return "expires within 30 days at " + cert.NotAfter.Format(time.RFC3339)
	}
	// bindIP 必须在 SAN 中
	wantIP := net.ParseIP(bindIP)
	if wantIP == nil {
		return "" // bindIP 解析失败由上层处理, 这里不阻塞 reuse
	}
	// 0.0.0.0 / :: (IsUnspecified) bind 时不强求固定单 IP SAN 匹配
	if wantIP.IsUnspecified() {
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
