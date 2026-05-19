// Package output - dfp.go: JA4 (DFP = DPI fingerprint) library.
//
// JA4 algorithm: see https://github.com/FoxIO-LLC/ja4
//
// Format: t<v><sni><n>_<ciphers12>_<exts12>
//   t  = TLS protocol (always 't' for TLS over TCP; 'q' for QUIC; rc29 only TLS/TCP)
//   v  = version: 13 for TLS 1.3, 12 for 1.2, 11 for 1.1, 10 for 1.0, 00 for older
//   sni = 'd' if SNI present, 'i' if no SNI (ip-only)
//   n  = 2-digit count of cipher suites (excluding GREASE)
//        + 2-digit count of extensions (excluding GREASE, ALPN, SNI)
//        + first ALPN (2 chars, or "00" if no ALPN)
//   ciphers12 = first 12 hex chars of sha256(sorted_ciphers_comma_separated)
//   exts12    = first 12 hex chars of sha256(sorted_exts_comma_separated + "_" + signature_algorithms)
//
// rc29 implements the JA4 (TLS ClientHello) variant only; JA4S/JA4H/JA4X/etc
// from the FoxIO suite are out of scope.

package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

const dfpRulesPath = "/data/local/hnc/etc/dpi_ja4_fingerprints.json"

// DFPFingerprint is one library entry.
type DFPFingerprint struct {
	JA4        string `json:"ja4"`
	Client     string `json:"client"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Source     string `json:"_source,omitempty"`
}

type dfpFile struct {
	SchemaVersion string           `json:"schema_version"`
	RulesVersion  string           `json:"rules_version"`
	Fingerprints  []DFPFingerprint `json:"fingerprints"`
}

type loadedDFP struct {
	version string
	byJA4   map[string]DFPFingerprint
}

var dfpCache = struct {
	sync.Mutex
	mtime int64
	size  int64
	val   loadedDFP
}{val: loadedDFP{version: "builtin-rc29", byJA4: map[string]DFPFingerprint{}}}

func currentDFPRuleVersion() string {
	d := loadDFPRules()
	if d.version == "" {
		return "builtin-rc29"
	}
	return d.version
}

func loadDFPRules() loadedDFP {
	st, err := os.Stat(dfpRulesPath)
	if err != nil {
		dfpCache.Lock()
		defer dfpCache.Unlock()
		dfpCache.mtime = 0
		dfpCache.size = 0
		dfpCache.val = loadedDFP{version: "builtin-rc29", byJA4: map[string]DFPFingerprint{}}
		return dfpCache.val
	}
	mtime := st.ModTime().UnixNano()
	size := st.Size()

	dfpCache.Lock()
	if dfpCache.mtime == mtime && dfpCache.size == size && dfpCache.val.byJA4 != nil {
		v := dfpCache.val
		dfpCache.Unlock()
		return v
	}
	dfpCache.Unlock()

	b, err := os.ReadFile(dfpRulesPath)
	if err != nil || len(b) == 0 || len(b) > 256*1024 {
		dfpCache.Lock()
		defer dfpCache.Unlock()
		dfpCache.val = loadedDFP{version: "builtin-rc29", byJA4: map[string]DFPFingerprint{}}
		dfpCache.mtime = mtime
		dfpCache.size = size
		return dfpCache.val
	}

	var f dfpFile
	if err := json.Unmarshal(b, &f); err != nil {
		dfpCache.Lock()
		defer dfpCache.Unlock()
		dfpCache.val = loadedDFP{version: "builtin-rc29+invalid", byJA4: map[string]DFPFingerprint{}}
		dfpCache.mtime = mtime
		dfpCache.size = size
		return dfpCache.val
	}

	m := make(map[string]DFPFingerprint, len(f.Fingerprints))
	for _, fp := range f.Fingerprints {
		k := strings.TrimSpace(fp.JA4)
		if k == "" {
			continue
		}
		m[k] = fp
		if len(m) >= 4096 {
			break
		}
	}
	version := strings.TrimSpace(f.RulesVersion)
	if version == "" {
		version = "external"
	}
	lr := loadedDFP{version: "external:" + version, byJA4: m}

	dfpCache.Lock()
	dfpCache.mtime = mtime
	dfpCache.size = size
	dfpCache.val = lr
	dfpCache.Unlock()
	return lr
}

// lookupDFP returns the library entry for a JA4 string and true if found.
func lookupDFP(ja4 string) (DFPFingerprint, bool) {
	d := loadDFPRules()
	fp, ok := d.byJA4[ja4]
	return fp, ok
}

// ─── JA4 computation ───────────────────────────────────────────────────

// JA4Inputs is the subset of ClientHello fields needed to compute JA4.
// Capture/parse.go populates this from the TLS ClientHello it already parses.
type JA4Inputs struct {
	TLSVersion uint16 // legacy_version OR negotiated via supported_versions extension
	HasSNI     bool
	Ciphers    []uint16 // raw cipher suites in ClientHello order
	Extensions []uint16 // raw extension types in ClientHello order
	ALPNs      []string // ALPN values in ClientHello order
	SigAlgs    []uint16 // signature_algorithms extension contents
}

// IsGREASE returns true if the given value is one of TLS GREASE markers
// (RFC 8701). GREASE values look like 0xNANA where N is hex 0..F.
func IsGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v & 0xff)
	return hi == lo && (hi&0x0f) == 0x0a
}

// ComputeJA4 produces the canonical JA4 fingerprint for a TLS ClientHello.
// Returns "" if inputs are clearly bogus (e.g. zero ciphers).
func ComputeJA4(in JA4Inputs) string {
	if len(in.Ciphers) == 0 {
		return ""
	}

	// 1) Filter GREASE.
	ciphers := filterGREASE(in.Ciphers)
	exts := filterGREASE(in.Extensions)

	// 2) Filter ALPN/SNI from the "n" counter inputs.
	extsForCount := make([]uint16, 0, len(exts))
	for _, e := range exts {
		// 0x0000 = SNI, 0x0010 = ALPN
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extsForCount = append(extsForCount, e)
	}

	// 3) Version byte. JA4 uses TLS 1.3 if supported_versions includes it,
	//    else legacy_version. capture/ja4.go feeds us the resolved value.
	verStr := versionDigits(in.TLSVersion)

	// 4) SNI flag.
	sniFlag := "i"
	if in.HasSNI {
		sniFlag = "d"
	}

	// 5) Two-digit cipher count, two-digit ext count.
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := len(extsForCount)
	if extCount > 99 {
		extCount = 99
	}

	// 6) First ALPN (first 2 chars, ASCII-printable).
	alpnPair := "00"
	if len(in.ALPNs) > 0 {
		a := in.ALPNs[0]
		if len(a) >= 2 {
			alpnPair = string([]byte{safeASCII(a[0]), safeASCII(a[len(a)-1])})
		} else if len(a) == 1 {
			alpnPair = string([]byte{safeASCII(a[0]), '0'})
		}
	}

	// 7) Ciphers hash: sorted lowercase comma-joined hex, sha256, take 12.
	cipherHashIn := joinHexSorted(ciphers)
	cipherHash12 := sha256Hex12(cipherHashIn)

	// 8) Extensions hash: sorted exts (excluding SNI/ALPN), then "_",
	//    then sig_algs in their ORIGINAL order (NOT sorted) comma-joined hex.
	extHashIn := joinHexSorted(extsForCount) + "_" + joinHex(in.SigAlgs)
	extHash12 := sha256Hex12(extHashIn)

	// 9) Assemble: t<ver><sni><n>_<chash>_<ehash>
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		verStr, sniFlag, cipherCount, extCount, alpnPair,
		cipherHash12, extHash12)
}

func versionDigits(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func safeASCII(b byte) byte {
	if b >= 32 && b <= 126 {
		return b
	}
	return '9'
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if IsGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func joinHex(in []uint16) string {
	if len(in) == 0 {
		return ""
	}
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, uint16Hex(v))
	}
	return strings.Join(parts, ",")
}

func joinHexSorted(in []uint16) string {
	if len(in) == 0 {
		return ""
	}
	cp := make([]uint16, len(in))
	copy(cp, in)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	parts := make([]string, 0, len(cp))
	for _, v := range cp {
		parts = append(parts, uint16Hex(v))
	}
	return strings.Join(parts, ",")
}

func uint16Hex(v uint16) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{
		hexChars[(v>>12)&0xf],
		hexChars[(v>>8)&0xf],
		hexChars[(v>>4)&0xf],
		hexChars[v&0xf],
	})
}

func sha256Hex12(s string) string {
	if s == "" {
		// FoxIO convention: empty input -> hash of "000000000000".
		// In practice tools render this as 12 zeroes.
		return "000000000000"
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}
