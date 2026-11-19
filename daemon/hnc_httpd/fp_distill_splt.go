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

func exportCompiledFPForDPID(hncDir string, now time.Time) error {
	nowUnix := now.Unix()
	exactFP := make(map[string]compiledFPRuleOut)

	// 1. 聚合本机蒸馏合格的专属 JA4/ALPN/QTP 指纹
	fpSt := fpFor(hncDir)
	fpSt.mu.Lock()
	fpSt.loadLocked()
	for key, e := range fpSt.m {
		if e == nil {
			continue
		}
		v := e.verdict(nowUnix)
		if !v.Usable || v.Top == "" {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		ja4, alpn := parts[0], parts[1]
		qtp := ""
		if len(parts) >= 4 {
			qtp = parts[3]
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
			Conf:     v.Conf,
		}
		if qtp != "" {
			exactFP[ja4+"|"+alpn+"|"+qtp] = rule
		} else {
			exactFP[ja4+"|"+alpn] = rule
		}
	}
	// 2. 合并导入规则包中的高纯度指纹
	for key, imp := range fpSt.importedLocked() {
		parts := strings.Split(key, "|")
		if len(parts) < 2 || parts[0] == "" || imp.AppID == "" {
			continue
		}
		ja4, alpn := parts[0], parts[1]
		qtp := ""
		if len(parts) >= 4 {
			qtp = parts[3]
		}
		k := ja4 + "|" + alpn
		if qtp != "" {
			k = k + "|" + qtp
		}
		appName := imp.App
		if appName == "" {
			appName = imp.AppID
		}
		if _, exists := exactFP[k]; !exists {
			exactFP[k] = compiledFPRuleOut{
				AppID:    imp.AppID,
				AppName:  appName,
				Category: imp.Category,
				JA4:      ja4,
				ALPN:     alpn,
				Conf:     0.90,
			}
		}
	}
	fpSt.mu.Unlock()

	// 3. 最高优先级覆盖用户手工指定的 JA4 纠正规则
	rp := rpCollect(hncDir, now)
	for _, ur := range rp.userJA4 {
		if ur.JA4 == "" || ur.AppID == "" {
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
