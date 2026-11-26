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
	"time"
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
	// 64-bit atomics strictly at offset 0 for 32-bit ARMv7 alignment (arm32_align_gate_test.go).
	lastCheckUnix atomic.Int64
	seenGen       atomic.Uint64

	snap   atomic.Pointer[CompiledFPBundle]
	loadMu sync.Mutex
	mu     sync.RWMutex
	path   string
	modNs  int64
	size   int64
}

var defaultCompiledFP = &compiledFPCache{
	path: "/data/local/hnc/run/dpi_fp_compiled.json",
}

func SetCompiledFPPath(runDir string) {
	if strings.TrimSpace(runDir) == "" {
		return
	}
	defaultCompiledFP.loadMu.Lock()
	defaultCompiledFP.mu.Lock()
	defaultCompiledFP.path = filepath.Join(runDir, "dpi_fp_compiled.json")
	defaultCompiledFP.modNs = 0
	defaultCompiledFP.size = 0
	defaultCompiledFP.lastCheckUnix.Store(0)
	defaultCompiledFP.mu.Unlock()
	defaultCompiledFP.loadMu.Unlock()
}

func (c *compiledFPCache) ensureLoaded() {
	gen := compiledForceReloadGen.Load()
	now := time.Now().Unix()
	last := c.lastCheckUnix.Load()
	if c.seenGen.Load() == gen && now-last < 2 && last <= now {
		return
	}

	c.loadMu.Lock()
	defer c.loadMu.Unlock()

	last = c.lastCheckUnix.Load()
	if c.seenGen.Load() == gen && now-last < 2 && last <= now {
		return
	}

	c.mu.RLock()
	path := c.path
	prevModNs := c.modNs
	prevSize := c.size
	c.mu.RUnlock()

	st, err := os.Stat(path)
	if err != nil {
		c.seenGen.Store(gen)
		c.lastCheckUnix.Store(now)
		return
	}
	if prevModNs == st.ModTime().UnixNano() && prevSize == st.Size() && c.seenGen.Load() == gen && c.snap.Load() != nil {
		c.lastCheckUnix.Store(now)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 {
		c.seenGen.Store(gen)
		c.lastCheckUnix.Store(now)
		return
	}
	var next CompiledFPBundle
	if json.Unmarshal(b, &next) != nil {
		c.seenGen.Store(gen)
		c.lastCheckUnix.Store(now)
		return
	}
	c.snap.Store(&next)
	c.mu.Lock()
	c.modNs = st.ModTime().UnixNano()
	c.size = st.Size()
	c.mu.Unlock()
	c.seenGen.Store(gen)
	c.lastCheckUnix.Store(now)
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
	if h == "" {
		return true
	}
	switch h {
	case "cloudflare-ech.com", "crypto.cloudflare.com", "encryptedsni.com",
		"akamai-ech.com", "fastly-ech.com", "ech.cloudflare.com":
		return true
	}
	for _, suf := range []string{
		".cloudflare-ech.com", ".crypto.cloudflare.com", ".encryptedsni.com",
		".akamai-ech.com", ".fastly-ech.com",
	} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return strings.HasPrefix(h, "ech.") || strings.Contains(h, "-ech.")
}

func MatchCompiledEncrypted(ja4, alpn, qtp, udpSig string, remoteIP net.IP, spltPrefix string, spltSig64 uint64) (CompiledSPLTRule, bool) {
	c := defaultCompiledFP
	c.ensureLoaded()
	bundle := c.snap.Load()
	if bundle == nil {
		return CompiledSPLTRule{}, false
	}

	if ja4 != "" && len(bundle.ExactFP) > 0 {
		if qtp != "" {
			if r, ok := bundle.ExactFP[ja4+"|"+alpn+"|"+qtp]; ok && r.AppID != "" {
				return r, true
			}
			if alpn != "" {
				if r, ok := bundle.ExactFP[ja4+"||"+qtp]; ok && r.AppID != "" {
					return r, true
				}
			}
		}
		if r, ok := bundle.ExactFP[ja4+"|"+alpn]; ok && r.AppID != "" {
			return r, true
		}
		if alpn != "" {
			if r, ok := bundle.ExactFP[ja4+"|"]; ok && r.AppID != "" {
				return r, true
			}
		}
		if r, ok := bundle.ExactFP[ja4]; ok && r.AppID != "" {
			return r, true
		}
	}

	ip24 := slash24Key(remoteIP)
	if spltPrefix != "" && len(bundle.ExactSPLT) > 0 {
		if ip24 != "" {
			if r, ok := bundle.ExactSPLT[spltPrefix+"|"+ip24]; ok && r.AppID != "" {
				return r, true
			}
		}
		if ja4 != "" {
			if r, ok := bundle.ExactSPLT[spltPrefix+"|"+ja4]; ok && r.AppID != "" {
				return r, true
			}
		}
	}

	if spltSig64 != 0 && len(bundle.SoftSPLT) > 0 {
		var best CompiledSPLTRule
		bestScore := 0.88
		for _, cand := range bundle.SoftSPLT {
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
