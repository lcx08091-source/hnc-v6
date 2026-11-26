// fp_distill_splt.go — HNC v5.37.0: 导出编译态指纹包 run/dpi_fp_compiled.json 供 dpid 实时分类与 QoS 联动
package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

type compiledFPRuleOut struct {
	AppID      string  `json:"app_id"`
	AppName    string  `json:"app_name"`
	Category   string  `json:"category"`
	JA4        string  `json:"ja4,omitempty"`
	ALPN       string  `json:"alpn,omitempty"`
	Port       string  `json:"port,omitempty"`
	UDPSig     string  `json:"udp_sig,omitempty"`
	IPPrefix24 string  `json:"ip24,omitempty"`
	PrefixKey  string  `json:"prefix_key,omitempty"`
	ProtoSig64 uint64  `json:"proto_sig64,omitempty"`
	Conf       float64 `json:"conf"`
}

type compiledFPBundleOut struct {
	Version   int                          `json:"version"`
	ExactFP   map[string]compiledFPRuleOut `json:"exact_fp,omitempty"`
	ExactSPLT map[string]compiledFPRuleOut `json:"exact_splt,omitempty"`
	SoftSPLT  []compiledFPRuleOut          `json:"soft_splt,omitempty"`
}

func parseStoredFPKeyParts(key string) (ja4, alpn, port, qtp string, ok bool) {
	parts := strings.Split(key, "|")
	if len(parts) < 2 || parts[0] == "" {
		return "", "", "", "", false
	}
	ja4 = parts[0]
	alpn = parts[1]
	port = "443"
	if len(parts) >= 3 && parts[2] != "" {
		port = parts[2]
	}
	if len(parts) >= 4 {
		qtp = parts[3]
	}
	return ja4, alpn, port, qtp, true
}

func buildNoPortFPKey(ja4, alpn, qtp string) string {
	if qtp != "" {
		return ja4 + "|" + alpn + "|" + qtp
	}
	return ja4 + "|" + alpn
}

func exportCompiledFPForDPID(hncDir string, now time.Time) error {
	nowUnix := now.Unix()
	exactFP := make(map[string]compiledFPRuleOut)
	genericFullKeys := make(map[string]bool)
	genericNoPortKeys := make(map[string]bool)

	// 1. 聚合本机蒸馏合格的专属 JA4/ALPN/Port/QTP 指纹
	fpSt := fpFor(hncDir)
	fpSt.mu.Lock()
	fpSt.loadLocked()
	for key, e := range fpSt.m {
		if e == nil {
			continue
		}
		ja4, alpn, port, qtp, ok := parseStoredFPKeyParts(key)
		if !ok {
			continue
		}
		fullKey := fpKeyQ(ja4, alpn, port, qtp)
		noPortKey := buildNoPortFPKey(ja4, alpn, qtp)
		v := e.verdict(nowUnix)
		if v.Generic {
			genericFullKeys[fullKey] = true
			if port == "443" {
				genericNoPortKeys[noPortKey] = true
			}
			continue
		}
		if !v.Usable || v.Top == "" || v.Top == fpOtherApp {
			continue
		}
		if qtp == "" && fpSt.ja4GenericLocked(ja4, v.Top, nowUnix) {
			genericFullKeys[fullKey] = true
			if port == "443" {
				genericNoPortKeys[noPortKey] = true
			}
			continue
		}
		appName := v.TopName
		if appName == "" {
			appName = v.Top
		}
		rule := compiledFPRuleOut{
			AppID:    v.Top,
			AppName:  appName,
			Category: v.TopCat,
			JA4:      ja4,
			ALPN:     alpn,
			Port:     port,
			Conf:     v.Conf,
		}
		exactFP[fullKey] = rule
		// 仅标准 443 端口在非通用前提下同步写入无端口兼容键, 防止 other/80 非标端口规则污染标准 HTTPS
		if port == "443" && !genericNoPortKeys[noPortKey] {
			exactFP[noPortKey] = rule
		}
	}
	// 2. 合并导入规则包中的高纯度指纹(严格保留端口类并阻断已被本机判为通用的 JA4)
	for key, imp := range fpSt.importedLocked() {
		if imp.AppID == "" {
			continue
		}
		ja4, alpn, port, qtp, ok := parseStoredFPKeyParts(key)
		if !ok {
			continue
		}
		fullKey := fpKeyQ(ja4, alpn, port, qtp)
		if genericFullKeys[fullKey] {
			continue
		}
		if qtp == "" && fpSt.ja4GenericLocked(ja4, imp.AppID, nowUnix) {
			continue
		}
		appName := imp.App
		if appName == "" {
			appName = imp.AppID
		}
		rule := compiledFPRuleOut{
			AppID:    imp.AppID,
			AppName:  appName,
			Category: imp.Category,
			JA4:      ja4,
			ALPN:     alpn,
			Port:     port,
			Conf:     0.90,
		}
		if _, exists := exactFP[fullKey]; !exists {
			exactFP[fullKey] = rule
		}
		if port == "443" {
			noPortKey := buildNoPortFPKey(ja4, alpn, qtp)
			if !genericNoPortKeys[noPortKey] {
				if _, exists := exactFP[noPortKey]; !exists {
					exactFP[noPortKey] = rule
				}
			}
		}
	}
	fpSt.mu.Unlock()

	// 3. 覆盖用户手工指定的非通用 JA4 纠正规则(对齐 fp_learn.go:689 过滤 ja4Generic)
	rp := rpCollect(hncDir, now)
	for _, ur := range rp.userJA4 {
		if ur.JA4 == "" || ur.AppID == "" {
			continue
		}
		if generic, _ := fpSt.ja4Generic(ur.JA4, ur.AppID, now); generic {
			continue
		}
		appName := ur.App
		if appName == "" {
			appName = ur.AppID
		}
		exactFP[ur.JA4] = compiledFPRuleOut{
			AppID:    ur.AppID,
			AppName:  appName,
			Category: ur.Category,
			JA4:      ur.JA4,
			Conf:     1.0,
		}
	}

	bundle := compiledFPBundleOut{
		Version: 1,
		ExactFP: exactFP,
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(filepath.Join(hncDir, "run", "dpi_fp_compiled.json"), raw)
}
