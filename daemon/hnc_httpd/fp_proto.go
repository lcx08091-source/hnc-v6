// fp_proto.go — HNC v5.38.0: 极少样本 (1~3 条真值即可生效) 多模态原型匹配器 (IDF-Jaccard + 对数归一化 SPLT 余弦)
//
// 解决痛点:
//
//	旧 fp_learn.go 要求 support >= 50 且 purity >= 90%, 个人手机日常亮屏仅采集几百条样本时大量 App 只有 1~5 条冷启动记录,
//	长期处于 0 条可用指纹死锁状态; 而 flow_cls.go 分箱朴素贝叶斯在少样本下退化为平滑噪声且只能分大类。
//	本模块为每个应用构建轻量多模态原型(<400B/App):
//	  1) 离散上下文特征词 (TLSFP / JA4 / QTP / ASN / /24 子网) 采用全局逆应用频率 (IDF) 加权广义 Jaccard,
//	     自动压低 20 个应用共用的系统 WebView/通用栈权重, 放大专属栈与专属网段区分度;
//	  2) 连续行为序列采用对数压缩 L2 归一化 8 包有向 SPLT 质心余弦相似度, 区分共享同一 TTNet/Cronet 栈的短视频 vs 小说图文。
package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	protoSPLTDim   = 8
	protoMinScore  = 0.50
	protoMinMargin = 0.08
	protoMaxTokens = 32
)

type AppPrototype struct {
	AppID        string                `json:"app_id"`
	AppName      string                `json:"app_name"`
	Category     string                `json:"category,omitempty"`
	SampleCount  uint32                `json:"sample_count"`
	Tokens       map[string]float32    `json:"tokens"`
	SPLTCentroid [protoSPLTDim]float32 `json:"splt_centroid,omitempty"`
	UpdatedAt    int64                 `json:"updated_at"`
}

type protoStoreFile struct {
	Version   int                      `json:"version"`
	UpdatedAt int64                    `json:"updated_at"`
	TokenDF   map[string]uint32        `json:"token_df"`
	Apps      map[string]*AppPrototype `json:"apps"`
}

type PrototypeStore struct {
	mu      sync.RWMutex
	apps    map[string]*AppPrototype
	tokenDF map[string]uint32
}

func newPrototypeStore() *PrototypeStore {
	return &PrototypeStore{
		apps:    make(map[string]*AppPrototype, 64),
		tokenDF: make(map[string]uint32, 256),
	}
}

func protoStorePath(hncDir string) string {
	return filepath.Join(hncDir, "data", "dpi_fp_prototypes.json")
}

func loadPrototypeStore(hncDir string) *PrototypeStore {
	ps := newPrototypeStore()
	b, err := os.ReadFile(protoStorePath(hncDir))
	if err != nil {
		return ps
	}
	var f protoStoreFile
	if json.Unmarshal(b, &f) == nil {
		if f.Apps != nil {
			ps.apps = f.Apps
		}
		if f.TokenDF != nil {
			ps.tokenDF = f.TokenDF
		}
	}
	return ps
}

func (s *PrototypeStore) Save(hncDir string) error {
	s.mu.RLock()
	f := protoStoreFile{
		Version:   1,
		UpdatedAt: time.Now().Unix(),
		TokenDF:   s.tokenDF,
		Apps:      s.apps,
	}
	b, err := json.Marshal(f)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return discoverWriteAtomic(protoStorePath(hncDir), b)
}

func (s *PrototypeStore) AppCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.apps)
}

func (s *PrototypeStore) ObserveSample(appID, appName, cat string, tokens []string, rawSPLT [protoSPLTDim]int16, nowUnix int64) {
	if appID == "" || len(tokens) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.apps[appID]
	if !ok {
		p = &AppPrototype{
			AppID:    appID,
			AppName:  appName,
			Category: cat,
			Tokens:   make(map[string]float32, 12),
		}
		s.apps[appID] = p
	}
	if appName != "" {
		p.AppName = appName
	}
	if cat != "" {
		p.Category = cat
	}
	p.SampleCount++
	p.UpdatedAt = nowUnix
	denom := p.SampleCount
	if denom > 32 {
		denom = 32
	}
	alpha := float32(1.0 / float64(denom))

	seen := make(map[string]struct{}, len(tokens))
	for _, tk := range tokens {
		if tk == "" {
			continue
		}
		seen[tk] = struct{}{}
		if _, ex := p.Tokens[tk]; !ex && len(p.Tokens) < protoMaxTokens {
			s.tokenDF[tk]++
		}
	}
	for tk := range p.Tokens {
		obs := float32(0)
		if _, hit := seen[tk]; hit {
			obs = 1
		}
		p.Tokens[tk] = (1-alpha)*p.Tokens[tk] + alpha*obs
	}
	for tk := range seen {
		if _, ex := p.Tokens[tk]; !ex && len(p.Tokens) < protoMaxTokens {
			p.Tokens[tk] = alpha
		}
	}

	nv, hasSPLT := logNormSPLT8(rawSPLT)
	if hasSPLT {
		var sq float64
		for i := 0; i < protoSPLTDim; i++ {
			p.SPLTCentroid[i] = (1-alpha)*p.SPLTCentroid[i] + alpha*nv[i]
			sq += float64(p.SPLTCentroid[i] * p.SPLTCentroid[i])
		}
		inv := float32(1.0 / (math.Sqrt(sq) + 1e-7))
		for i := 0; i < protoSPLTDim; i++ {
			p.SPLTCentroid[i] *= inv
		}
	}
}

func (s *PrototypeStore) Match(queryTokens []string, rawSPLT [protoSPLTDim]int16) (appID, appName, cat string, conf float32, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nApps := float64(len(s.apps))
	if nApps == 0 || len(queryTokens) == 0 {
		return "", "", "", 0, false
	}
	qVec, qHasSPLT := logNormSPLT8(rawSPLT)
	qSet := make(map[string]struct{}, len(queryTokens))
	for _, t := range queryTokens {
		if t != "" {
			qSet[t] = struct{}{}
		}
	}

	var best *AppPrototype
	var bestScore, secondScore float32

	for _, p := range s.apps {
		var numSum, denSum float64
		for tk, freq := range p.Tokens {
			idf := math.Log(1.0+nApps/(1.0+float64(s.tokenDF[tk]))) + 0.25
			wa := idf * float64(freq)
			wq := 0.0
			if _, hit := qSet[tk]; hit {
				wq = idf
			}
			numSum += math.Min(wq, wa)
			denSum += math.Max(wq, wa)
		}
		for tk := range qSet {
			if _, inP := p.Tokens[tk]; !inP {
				idf := math.Log(1.0+nApps/(1.0+float64(s.tokenDF[tk]))) + 0.25
				denSum += idf
			}
		}
		jacc := float32(numSum / (denSum + 1e-7))

		var pHasSPLT bool
		for i := 0; i < protoSPLTDim; i++ {
			if p.SPLTCentroid[i] != 0 {
				pHasSPLT = true
				break
			}
		}
		var score float32
		if qHasSPLT && pHasSPLT {
			var dot float32
			for i := 0; i < protoSPLTDim; i++ {
				dot += qVec[i] * p.SPLTCentroid[i]
			}
			if dot < 0 {
				dot = 0
			}
			score = 0.65*jacc + 0.35*dot
		} else {
			score = jacc
		}
		sampleFactor := float32(float64(p.SampleCount) / (float64(p.SampleCount) + 0.15))
		score *= sampleFactor

		if score > bestScore {
			secondScore = bestScore
			bestScore = score
			best = p
		} else if score > secondScore {
			secondScore = score
		}
	}

	if best != nil && bestScore >= protoMinScore && (bestScore-secondScore) >= protoMinMargin {
		return best.AppID, best.AppName, best.Category, bestScore, true
	}
	return "", "", "", 0, false
}

func logNormSPLT8(raw [protoSPLTDim]int16) ([protoSPLTDim]float32, bool) {
	var out [protoSPLTDim]float32
	var sq float64
	nonZero := 0
	for i, v := range raw {
		if v == 0 {
			continue
		}
		nonZero++
		sign := 1.0
		if v < 0 {
			sign = -1.0
			v = -v
		}
		lv := sign * math.Log1p(float64(v))
		out[i] = float32(lv)
		sq += lv * lv
	}
	if nonZero == 0 {
		return out, false
	}
	inv := float32(1.0 / (math.Sqrt(sq) + 1e-7))
	for i := range out {
		out[i] *= inv
	}
	return out, true
}

// distillFewShotPrototypes 扫描最近 7 天本机真值 label_samples, 1~3 条样本即可生成 IDF-Jaccard + SPLT 原型库
func distillFewShotPrototypes(hncDir string, now time.Time) int {
	allSamples, _, _ := readDistillLabelSamples(hncDir, 7, startupCursor{}, now)
	if len(allSamples) == 0 {
		return loadPrototypeStore(hncDir).AppCount()
	}
	pmap := pkgAppMap(hncDir)
	rnames, hiddenRules := ruleMeta(hncDir)
	cat := loadAppCatalog(hncDir)
	conduitPkgs := buildConduitPkgSet(hncDir)
	resolver, _ := buildPkgAppResolver(allSamples, pmap, rnames, hiddenRules, conduitPkgs, cat, true)

	ps := newPrototypeStore()
	nowU := now.Unix()
	for _, sm := range allSamples {
		if distillBrowserWebViewPkgs[sm.Pkg] || conduitPkgs[sm.Pkg] {
			continue
		}
		rp, ok := resolver[sm.Pkg]
		if !ok || rp.ID == "" {
			continue
		}
		var toks []string
		if sm.JA4 != "" {
			toks = append(toks, "ja4:"+sm.JA4)
		}
		if sm.QTP != "" {
			toks = append(toks, "qtp:"+sm.QTP)
		}
		if sm.ALPN != "" {
			toks = append(toks, "alpn:"+sm.ALPN)
		}
		if len(toks) > 0 {
			ps.ObserveSample(rp.ID, rp.Name, rp.Category, toks, [protoSPLTDim]int16{}, nowU)
		}
	}
	if ps.AppCount() > 0 {
		_ = ps.Save(hncDir)
	}
	return ps.AppCount()
}
