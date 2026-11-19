// json_v2_codec.go — HNC v6.0.0 · Vector: Go 1.27 encoding/json/v2 + jsontext 零缓冲复用编解码器与透明排障导出
//
// 设计原则:
//   1. 采用 Go 1.27 标准库 encoding/json/v2 与 encoding/json/jsontext, 配合 sync.Pool 复用
//      bytes.Buffer 与 *jsontext.Encoder, 消除高频 HTTP JSON 响应的临时切片分配与反射开销;
//   2. 显式启用 jsontext.AllowInvalidUTF8(true) 与 jsontext.AllowDuplicateNames(true), 防止异常
//      客户端主机名/SSID 含非 UTF-8 字节时导致序列化报错, 并通过 DefaultOptionsV2() 保持空切片 []
//      与空映射 {} 的前端友好语义(若遇遗留未标注类型自动无损回退 v1 编码器);
//   3. 落实反驳组「绝不变成二进制黑盒」铁律: 提供 GET /api/v6/diag_dump 输出带缩进的人类可读
//      全栈诊断 JSON, 同时校验持久配置文件的可读性。
package main

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	initPooledJSONBufCap = 8 << 10   // 8 KiB 初始缓冲
	maxPooledJSONBufCap  = 256 << 10 // 超过 256 KiB 的大缓冲不回池, 防峰值常驻
)

// jsonV2Metrics 64 位原子字段严格置于结构体开头(offset 0), 满足 32 位 ARMv7 原子对齐要求。
type jsonV2Metrics struct {
	encodeCalls    atomic.Uint64
	encodeFallback atomic.Uint64
	poolReuses     atomic.Uint64
	bytesEmitted   atomic.Uint64
}

var globalJSONv2Metrics jsonV2Metrics

type pooledJSONv2Encoder struct {
	buf    bytes.Buffer
	enc    *jsontext.Encoder
	reused bool
}

var jsonV2EncoderPool = sync.Pool{
	New: func() any {
		pw := &pooledJSONv2Encoder{}
		pw.buf.Grow(initPooledJSONBufCap)
		pw.enc = jsontext.NewEncoder(
			&pw.buf,
			jsontext.AllowInvalidUTF8(true),
			jsontext.AllowDuplicateNames(true),
		)
		return pw
	},
}

var jsonV2DecoderPool = sync.Pool{
	New: func() any {
		return jsontext.NewDecoder(
			bytes.NewReader(nil),
			jsontext.AllowInvalidUTF8(true),
			jsontext.AllowDuplicateNames(true),
		)
	},
}

func acquireJSONv2Encoder(multiline bool) *pooledJSONv2Encoder {
	pw := jsonV2EncoderPool.Get().(*pooledJSONv2Encoder)
	if pw.reused {
		globalJSONv2Metrics.poolReuses.Add(1)
	}
	pw.buf.Reset()
	if multiline {
		pw.enc.Reset(
			&pw.buf,
			jsontext.AllowInvalidUTF8(true),
			jsontext.AllowDuplicateNames(true),
			jsontext.WithIndent("  "),
		)
	} else {
		pw.enc.Reset(
			&pw.buf,
			jsontext.AllowInvalidUTF8(true),
			jsontext.AllowDuplicateNames(true),
		)
	}
	return pw
}

func releaseJSONv2Encoder(pw *pooledJSONv2Encoder) {
	if pw == nil || pw.buf.Cap() > maxPooledJSONBufCap {
		return
	}
	pw.buf.Reset()
	pw.reused = true
	jsonV2EncoderPool.Put(pw)
}

// encodeToPooledBuffer 使用 Go 1.27 json/v2 + jsontext 序列化到复用缓冲区;
// 若传入包含未指定格式的 time.Duration 等遗留 v1 类型, 自动回退至 v1 编码保证 100% 兼容。
func encodeToPooledBuffer(v any, multiline bool) (*pooledJSONv2Encoder, error) {
	globalJSONv2Metrics.encodeCalls.Add(1)
	pw := acquireJSONv2Encoder(multiline)
	var opts jsonv2.Options
	if multiline {
		opts = jsonv2.JoinOptions(jsonv2.DefaultOptionsV2(), jsonv2.Deterministic(true))
	} else {
		opts = jsonv2.DefaultOptionsV2()
	}
	if err := jsonv2.MarshalEncode(pw.enc, v, opts); err != nil {
		globalJSONv2Metrics.encodeFallback.Add(1)
		pw.buf.Reset()
		encV1 := jsonv1.NewEncoder(&pw.buf)
		if multiline {
			encV1.SetIndent("", "  ")
		}
		if errV1 := encV1.Encode(v); errV1 != nil {
			releaseJSONv2Encoder(pw)
			return nil, err
		}
	}
	return pw, nil
}

// MarshalJSONv2 使用池化 jsontext.Encoder 产出独立紧凑 JSON 字节切片(不含尾随换行)。
func MarshalJSONv2(v any) ([]byte, error) {
	pw, err := encodeToPooledBuffer(v, false)
	if err != nil {
		return nil, err
	}
	defer releaseJSONv2Encoder(pw)
	raw := bytes.TrimRight(pw.buf.Bytes(), "\n")
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// MarshalIndentJSONv2 使用池化 jsontext.Encoder 产出 2 空格缩进、键序确定的人类可读 JSON。
func MarshalIndentJSONv2(v any) ([]byte, error) {
	pw, err := encodeToPooledBuffer(v, true)
	if err != nil {
		return nil, err
	}
	defer releaseJSONv2Encoder(pw)
	raw := bytes.TrimRight(pw.buf.Bytes(), "\n")
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// UnmarshalJSONv2 使用池化 jsontext.Decoder 解析 JSON 字节切片(兼容大小写不敏感字段匹配)。
func UnmarshalJSONv2(data []byte, out any) error {
	dec := jsonV2DecoderPool.Get().(*jsontext.Decoder)
	dec.Reset(
		bytes.NewReader(data),
		jsontext.AllowInvalidUTF8(true),
		jsontext.AllowDuplicateNames(true),
	)
	defer func() {
		dec.Reset(bytes.NewReader(nil))
		jsonV2DecoderPool.Put(dec)
	}()
	return jsonv2.UnmarshalDecode(
		dec,
		out,
		jsonv2.DefaultOptionsV2(),
		jsonv2.MatchCaseInsensitiveNames(true),
	)
}

// WriteJSONv2 使用 Go 1.27 encoding/json/v2 + sync.Pool 缓冲池向 http.ResponseWriter 输出 JSON。
func WriteJSONv2(w http.ResponseWriter, status int, v any) {
	writeJSONv2Internal(w, status, v, false)
}

// WriteJSONv2Indented 输出格式化的人类可读 JSON(供 /api/v6/diag_dump 排障导出使用)。
func WriteJSONv2Indented(w http.ResponseWriter, status int, v any) {
	writeJSONv2Internal(w, status, v, true)
}

func writeJSONv2Internal(w http.ResponseWriter, status int, v any, multiline bool) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	pw, err := encodeToPooledBuffer(v, multiline)
	if err != nil {
		log.Printf("WriteJSONv2 encode error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"ok\":false,\"error\":\"json encode failed\"}\n"))
		return
	}
	defer releaseJSONv2Encoder(pw)

	b := pw.buf.Bytes()
	w.WriteHeader(status)
	n, werr := w.Write(b)
	if werr != nil {
		log.Printf("WriteJSONv2 write error: %v", werr)
	}
	if n > 0 {
		globalJSONv2Metrics.bytesEmitted.Add(uint64(n))
	}
}

// WritePrebuiltJSONv2 直接写出不可变快照预编码好的 JSON 字节(零序列化、零内存分配)。
func WritePrebuiltJSONv2(w http.ResponseWriter, status int, raw []byte) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	n, _ := w.Write(raw)
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		_, _ = w.Write([]byte{'\n'})
		n++
	}
	if n > 0 {
		globalJSONv2Metrics.bytesEmitted.Add(uint64(n))
	}
}

// ExtractJSONStringsStream 基于 jsontext.Decoder 状态机在截断流上零反射提取目标字段值。
func ExtractJSONStringsStream(r io.Reader, maxBytes int64, wantKeys map[string]bool) map[string]string {
	out := make(map[string]string)
	if r == nil || len(wantKeys) == 0 {
		return out
	}
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	lr := io.LimitReader(r, maxBytes)
	dec := jsonV2DecoderPool.Get().(*jsontext.Decoder)
	dec.Reset(
		lr,
		jsontext.AllowInvalidUTF8(true),
		jsontext.AllowDuplicateNames(true),
	)
	defer func() {
		dec.Reset(bytes.NewReader(nil))
		jsonV2DecoderPool.Put(dec)
	}()

	for {
		tok, err := dec.ReadToken()
		if err != nil {
			break
		}
		if tok.Kind() != '"' {
			continue
		}
		// 在 JSON 对象内部, StackIndex(depth) 长度为奇数代表刚读入的是成员 Key。
		depth := dec.StackDepth()
		if depth <= 0 {
			continue
		}
		kind, length := dec.StackIndex(depth)
		if kind != '{' || length%2 != 1 {
			continue
		}
		key := tok.String()
		if !wantKeys[key] {
			continue
		}
		valTok, verr := dec.ReadToken()
		if verr != nil {
			break
		}
		switch valTok.Kind() {
		case '"', '0', 't', 'f':
			if _, exists := out[key]; !exists {
				out[key] = valTok.String()
			}
		}
	}
	return out
}

// ─── GET /api/v6/diag_dump (人类可读排障快照, 绝不变成二进制黑盒) ─────────

type diagRuntimeStats struct {
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	NumCPU         int    `json:"num_cpu"`
	Goroutines     int    `json:"goroutines"`
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes uint64 `json:"heap_inuse_bytes"`
	SysBytes       uint64 `json:"sys_bytes"`
	NumGC          uint32 `json:"num_gc"`
}

type diagCodecStats struct {
	Engine         string `json:"engine"`
	EncodeCalls    uint64 `json:"encode_calls"`
	EncodeFallback uint64 `json:"encode_fallback"`
	PoolReuses     uint64 `json:"pool_reuses"`
	BytesEmitted   uint64 `json:"bytes_emitted"`
}

type diagFileHealth struct {
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	SizeBytes int64  `json:"size_bytes"`
	ValidJSON bool   `json:"valid_json"`
	ModUnix   int64  `json:"mod_unix,omitempty"`
}

type CoreDiagDump struct {
	OK               bool                      `json:"ok"`
	Schema           int                       `json:"schema"`
	GeneratedAt      int64                     `json:"generated_at"`
	GeneratedISO     string                    `json:"generated_iso"`
	Note             string                    `json:"note"`
	Version          string                    `json:"version"`
	VersionCode      string                    `json:"version_code"`
	CoreUptimeSec    int64                     `json:"core_uptime_sec"`
	VectorSyncHits   uint64                    `json:"vector_sync_hits"`
	Runtime          diagRuntimeStats          `json:"runtime"`
	JSONv2Codec      diagCodecStats            `json:"json_v2_codec"`
	PlaintextConfigs map[string]diagFileHealth `json:"plaintext_configs"`
	World            *WorldSnapshot            `json:"world"`
}

func inspectPlaintextJSONFiles(hncDir string) map[string]diagFileHealth {
	out := make(map[string]diagFileHealth, 5)
	if hncDir == "" {
		return out
	}
	rels := []string{
		"data/rules.json",
		"data/devices.json",
		"data/limit_policies.json",
		"data/device_names.json",
		"run/activity.json",
	}
	for _, rel := range rels {
		full := filepath.Join(hncDir, rel)
		st, err := os.Stat(full)
		if err != nil {
			out[rel] = diagFileHealth{Path: rel, Exists: false}
			continue
		}
		fh := diagFileHealth{
			Path:      rel,
			Exists:    true,
			SizeBytes: st.Size(),
			ModUnix:   st.ModTime().Unix(),
		}
		if st.Size() >= 0 && st.Size() <= 4<<20 {
			if b, rerr := os.ReadFile(full); rerr == nil {
				fh.ValidJSON = jsontext.Value(b).IsValid(
					jsontext.AllowInvalidUTF8(true),
					jsontext.AllowDuplicateNames(true),
				)
			}
		}
		out[rel] = fh
	}
	return out
}

// BuildCoreDiagDump 组装完整人类可读排障结构(纯只读, 零外部子进程)。
func (s *server) BuildCoreDiagDump() CoreDiagDump {
	now := time.Now()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	var hub *CoreHub
	var world *WorldSnapshot
	var hits uint64
	var hncDir string
	if s != nil {
		hncDir = s.hncDir
		hub = s.CoreHub()
		world = hub.Snapshot()
		hits = hub.VectorSyncHits()
	}

	return CoreDiagDump{
		OK:             true,
		Schema:         1,
		GeneratedAt:    now.Unix(),
		GeneratedISO:   now.Format(time.RFC3339),
		Note:           "HNC v6.0 Vector human-readable diagnostic dump (persistent configs remain plaintext JSON)",
		Version:        version,
		VersionCode:    versionCode,
		CoreUptimeSec:  coreUptimeSeconds(),
		VectorSyncHits: hits,
		Runtime: diagRuntimeStats{
			GOOS:           runtime.GOOS,
			GOARCH:         runtime.GOARCH,
			NumCPU:         runtime.NumCPU(),
			Goroutines:     runtime.NumGoroutine(),
			HeapAllocBytes: ms.HeapAlloc,
			HeapInuseBytes: ms.HeapInuse,
			SysBytes:       ms.Sys,
			NumGC:          ms.NumGC,
		},
		JSONv2Codec: diagCodecStats{
			Engine:         "encoding/json/v2+jsontext",
			EncodeCalls:    globalJSONv2Metrics.encodeCalls.Load(),
			EncodeFallback: globalJSONv2Metrics.encodeFallback.Load(),
			PoolReuses:     globalJSONv2Metrics.poolReuses.Load(),
			BytesEmitted:   globalJSONv2Metrics.bytesEmitted.Load(),
		},
		PlaintextConfigs: inspectPlaintextJSONFiles(hncDir),
		World:            world,
	}
}

// apiCoreDiagDump 处理 GET /api/v6/diag_dump, 输出带缩进的人类可读排障 JSON。
func (s *server) apiCoreDiagDump(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteJSONv2(w, http.StatusMethodNotAllowed, map[string]any{
			"ok":    false,
			"error": "method not allowed",
		})
		return
	}
	dump := s.BuildCoreDiagDump()
	WriteJSONv2Indented(w, http.StatusOK, &dump)
}
