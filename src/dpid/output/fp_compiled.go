// Package output - fp_compiled.go: HNC v5.37.0 编译态个人指纹与 SPLT 实时匹配桥接器
package output

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

var compiledForceReloadGen atomic.Uint64

func BumpCompiledFPGen() {
	compiledForceReloadGen.Add(1)
}

type CompiledSPLTRule struct {
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

type CompiledFPBundle struct {
	Version   int                         `json:"version"`
	ExactFP   map[string]CompiledSPLTRule `json:"exact_fp,omitempty"`
	ExactSPLT map[string]CompiledSPLTRule `json:"exact_splt,omitempty"`
	SoftSPLT  []CompiledSPLTRule          `json:"soft_splt,omitempty"`
}

type compiledFPCache struct {
	mu      sync.RWMutex
	path    string
	modUnix int64
	size    int64
	seenGen uint64
	bundle  CompiledFPBundle
}

var defaultCompiledFP = &compiledFPCache{
	path: "/data/local/hnc/run/dpi_fp_compiled.json",
}

func SetCompiledFPPath(runDir string) {
	if strings.TrimSpace(runDir) == "" {
		return
	}
	defaultCompiledFP.mu.Lock()
	defaultCompiledFP.path = filepath.Join(runDir, "dpi_fp_compiled.json")
	defaultCompiledFP.modUnix = 0
	defaultCompiledFP.mu.Unlock()
}

func (c *compiledFPCache) ensureLoaded() {
	gen := compiledForceReloadGen.Load()
	c.mu.RLock()
	path := c.path
	c.mu.RUnlock()
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	c.mu.RLock()
	unchanged := c.modUnix == st.ModTime().UnixNano() && c.size == st.Size() && c.seenGen == gen
	c.mu.RUnlock()
	if unchanged {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 {
		return
	}
	var next CompiledFPBundle
	if json.Unmarshal(b, &next) != nil {
		return
	}
	c.mu.Lock()
	c.bundle = next
	c.modUnix = st.ModTime().UnixNano()
	c.size = st.Size()
	c.seenGen = gen
	c.mu.Unlock()
}

func slash24Key(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String() + "/24"
	}
	return ""
}

func IsECHOuterHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "cloudflare-ech.com" || strings.HasPrefix(h, "ech.") || strings.Contains(h, "-ech.")
}

func MatchCompiledEncrypted(ja4, alpn, qtp, udpSig string, remoteIP net.IP, spltPrefix string, spltSig64 uint64) (CompiledSPLTRule, bool) {
	c := defaultCompiledFP
	c.ensureLoaded()
	c.mu.RLock()
	defer c.mu.RUnlock()

	if ja4 != "" && len(c.bundle.ExactFP) > 0 {
		if qtp != "" {
			if r, ok := c.bundle.ExactFP[ja4+"|"+alpn+"|"+qtp]; ok && r.AppID != "" {
				return r, true
			}
		}
		if r, ok := c.bundle.ExactFP[ja4+"|"+alpn]; ok && r.AppID != "" {
			return r, true
		}
		if r, ok := c.bundle.ExactFP[ja4]; ok && r.AppID != "" {
			return r, true
		}
	}

	ip24 := slash24Key(remoteIP)
	if spltPrefix != "" && len(c.bundle.ExactSPLT) > 0 {
		if ip24 != "" {
			if r, ok := c.bundle.ExactSPLT[spltPrefix+"|"+ip24]; ok && r.AppID != "" {
				return r, true
			}
		}
		if ja4 != "" {
			if r, ok := c.bundle.ExactSPLT[spltPrefix+"|"+ja4]; ok && r.AppID != "" {
				return r, true
			}
		}
	}

	if spltSig64 != 0 && len(c.bundle.SoftSPLT) > 0 {
		var best CompiledSPLTRule
		bestScore := 0.88
		for _, cand := range c.bundle.SoftSPLT {
			if cand.JA4 != "" && ja4 != "" && cand.JA4 != ja4 {
				continue
			}
			if cand.UDPSig != "" && udpSig != "" && cand.UDPSig != udpSig {
				continue
			}
			if cand.IPPrefix24 != "" && ip24 != "" && cand.IPPrefix24 != ip24 {
				continue
			}
			sim := SPLTSoftSimilarity(spltSig64, cand.ProtoSig64) * cand.Conf
			if sim > bestScore {
				bestScore = sim
				best = cand
			}
		}
		if best.AppID != "" {
			return best, true
		}
	}
	return CompiledSPLTRule{}, false
}
