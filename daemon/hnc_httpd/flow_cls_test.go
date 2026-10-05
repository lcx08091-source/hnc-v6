// flow_cls_test.go — v5.28 B3: 流量形状分类器(分箱朴素贝叶斯)。
package main

import (
	"math/rand"
	"sync"
	"testing"
	"time"
)

// fcSynthFlow 合成一条 flow: 用典型形状的 fsFeatures + fsFlow。
func fcSynthFlow(f fsFeatures, proto string, dport int) *fsFlow {
	return &fsFlow{proto: proto, dport: dport}
}

// fcVideoFeats 视频类形状: 下行大、上行小、稳、包偏大。
func fcVideoFeats() fsFeatures {
	return fsFeatures{
		n: 12, dur: 120, upBps: 50_000, dnBps: 2_500_000, bidir: 0.02,
		active: 0.95, cvDn: 0.3, cvTot: 0.3, peakDn: 4_000_000,
		psz: 1200, ppsUp: 40, ppsDn: 260, cvPps: 0.3,
	}
}

// fcGameFeats 游戏类形状: 双向小包、高频、UDP。
func fcGameFeats() fsFeatures {
	return fsFeatures{
		n: 20, dur: 60, upBps: 300_000, dnBps: 400_000, bidir: 0.43,
		active: 0.99, cvDn: 0.6, cvTot: 0.55, peakDn: 900_000,
		psz: 180, ppsUp: 1600, ppsDn: 2100, cvPps: 0.5,
	}
}

// fcBrowsingFeats 浏览类形状: 突发、不对称、中等包。
func fcBrowsingFeats() fsFeatures {
	return fsFeatures{
		n: 8, dur: 45, upBps: 120_000, dnBps: 700_000, bidir: 0.15,
		active: 0.5, cvDn: 0.9, cvTot: 0.85, peakDn: 2_000_000,
		psz: 800, ppsUp: 90, ppsDn: 200, cvPps: 0.9,
	}
}

func fcJitter(f fsFeatures, r *rand.Rand) fsFeatures {
	mul := 0.7 + r.Float64()*0.6
	f.dnBps *= mul
	f.upBps *= mul
	f.ppsUp *= mul
	f.ppsDn *= mul
	f.psz *= 0.8 + r.Float64()*0.4
	f.cvDn *= 0.7 + r.Float64()*0.6
	f.cvTot *= 0.7 + r.Float64()*0.6
	f.dur *= 0.5 + r.Float64()
	return f
}

// TestFcTrainSynthetic 可分数据训练 → 留出集准确率 > 90%。
func TestFcTrainSynthetic(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	var pool []fcSample
	for i := 0; i < 150; i++ {
		pool = append(pool,
			fcSample{vec: fcVecOf(fcJitter(fcVideoFeats(), r), fcSynthFlow(fcVideoFeats(), "tcp", 443)), cat: "视频", ts: 1000},
			fcSample{vec: fcVecOf(fcJitter(fcGameFeats(), r), fcSynthFlow(fcGameFeats(), "udp", 443)), cat: "游戏", ts: 1000},
			fcSample{vec: fcVecOf(fcJitter(fcBrowsingFeats(), r), fcSynthFlow(fcBrowsingFeats(), "tcp", 443)), cat: "浏览", ts: 1000},
		)
	}
	m := fcTrain(pool, 2000)
	if m == nil {
		t.Fatal("应能训练出模型")
	}
	right, total := 0, 0
	for i := 0; i < 50; i++ {
		for _, c := range []struct {
			cat  string
			f    fsFeatures
			prot string
		}{{"视频", fcVideoFeats(), "tcp"}, {"游戏", fcGameFeats(), "udp"}, {"浏览", fcBrowsingFeats(), "tcp"}} {
			got, conf, ok := fcPredict(m, fcVecOf(fcJitter(c.f, r), fcSynthFlow(c.f, c.prot, 443)))
			total++
			if ok && got == c.cat {
				right++
			} else {
				t.Logf("cat=%s got=%s conf=%.2f", c.cat, got, conf)
			}
		}
	}
	acc := float64(right) / float64(total)
	if acc < 0.9 {
		t.Fatalf("合成可分数据准确率 = %.2f, want > 0.90", acc)
	}
}

// TestFcVecOfBinsInRange 所有维度 bin 落在合法区间。
func TestFcVecOfBinsInRange(t *testing.T) {
	for _, f := range []fsFeatures{fcVideoFeats(), fcGameFeats(), fcBrowsingFeats(), {n: 1, dur: 0.01, dnBps: 1, upBps: 1, psz: 40, ppsUp: 1, ppsDn: 1}} {
		for _, fl := range []*fsFlow{
			fcSynthFlow(f, "tcp", 443), fcSynthFlow(f, "udp", 443),
			fcSynthFlow(f, "tcp", 8080), fcSynthFlow(f, "tcp", 22),
		} {
			v := fcVecOf(f, fl)
			for d, b := range v {
				sz := len(fcEdges[d]) + 1
				if b < 0 || b >= sz {
					t.Fatalf("维度 %d bin=%d 越界(边界 %d 档)", d, b, sz)
				}
			}
		}
	}
}

// TestFcPoolCap 样本池每类上限 2000, 按时间淘汰。
func TestFcPoolCap(t *testing.T) {
	old := fcPool
	fcPoolMu.Lock()
	fcPool = nil
	fcPoolMu.Unlock()
	defer func() {
		fcPoolMu.Lock()
		fcPool = old
		fcPoolMu.Unlock()
	}()
	vec := fcVecOf(fcVideoFeats(), fcSynthFlow(fcVideoFeats(), "tcp", 443))
	for i := 0; i < 2500; i++ {
		fcPoolAdd(fcSample{vec: vec, cat: "视频", ts: int64(100000 + i)})
	}
	fcPoolMu.Lock()
	n := len(fcPool)
	firstTS := fcPool[0].ts
	fcPoolMu.Unlock()
	if n != fcPoolPerCat {
		t.Fatalf("池大小 = %d, want %d", n, fcPoolPerCat)
	}
	if firstTS != 100500 { // 最老的 500 条被淘汰
		t.Fatalf("淘汰后最老样本 ts = %d, want 100500", firstTS)
	}
}

// TestFcModelRoundtrip 模型存取往返: 存盘 → 读回 → 预测一致。
func TestFcModelRoundtrip(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	var pool []fcSample
	for i := 0; i < 60; i++ {
		pool = append(pool,
			fcSample{vec: fcVecOf(fcJitter(fcVideoFeats(), r), fcSynthFlow(fcVideoFeats(), "tcp", 443)), cat: "视频", ts: 1000},
			fcSample{vec: fcVecOf(fcJitter(fcGameFeats(), r), fcSynthFlow(fcGameFeats(), "udp", 443)), cat: "游戏", ts: 1000},
		)
	}
	m := fcTrain(pool, 2000)
	dir := t.TempDir()
	if err := fcSaveModel(dir, m); err != nil {
		t.Fatalf("存模型: %v", err)
	}
	m2 := fcLoadModel(dir)
	if m2 == nil {
		t.Fatal("读回模型为 nil")
	}
	probe := fcVecOf(fcVideoFeats(), fcSynthFlow(fcVideoFeats(), "tcp", 443))
	c1, conf1, _ := fcPredict(m, probe)
	c2, conf2, _ := fcPredict(m2, probe)
	if c1 != c2 || conf1 != conf2 {
		t.Fatalf("往返后预测不一致: (%s,%.3f) vs (%s,%.3f)", c1, conf1, c2, conf2)
	}
}

// TestFcEvalTimeSplit 评估的时间切分: 训练集不含今天。
func TestFcEvalTimeSplit(t *testing.T) {
	old := fcPool
	fcPoolMu.Lock()
	fcPool = nil
	fcPoolMu.Unlock()
	defer func() {
		fcPoolMu.Lock()
		fcPool = old
		fcPoolMu.Unlock()
	}()
	tz := time.Local
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, tz)
	midnight := time.Date(2026, 10, 5, 0, 0, 0, 0, tz)
	// 昨天: 视频/游戏各 60 条
	r := rand.New(rand.NewSource(9))
	for i := 0; i < 60; i++ {
		fcPoolMu.Lock()
		fcPool = append(fcPool,
			fcSample{vec: fcVecOf(fcJitter(fcVideoFeats(), r), fcSynthFlow(fcVideoFeats(), "tcp", 443)), cat: "视频", ts: midnight.Add(-24 * time.Hour).Add(time.Duration(i) * time.Minute).Unix(), manual: "视频"},
			fcSample{vec: fcVecOf(fcJitter(fcGameFeats(), r), fcSynthFlow(fcGameFeats(), "udp", 443)), cat: "游戏", ts: midnight.Add(-24 * time.Hour).Add(time.Duration(i) * time.Minute).Unix(), manual: "游戏"},
		)
		fcPoolMu.Unlock()
	}
	// 今天: 考题 60 条(视频 30 / 游戏 30)
	for i := 0; i < 30; i++ {
		fcPoolMu.Lock()
		fcPool = append(fcPool,
			fcSample{vec: fcVecOf(fcJitter(fcVideoFeats(), r), fcSynthFlow(fcVideoFeats(), "tcp", 443)), cat: "视频", ts: midnight.Add(time.Duration(i) * time.Minute).Unix(), manual: "视频"},
			fcSample{vec: fcVecOf(fcJitter(fcGameFeats(), r), fcSynthFlow(fcGameFeats(), "udp", 443)), cat: "游戏", ts: midnight.Add(time.Duration(i) * time.Minute).Unix(), manual: "游戏"},
		)
		fcPoolMu.Unlock()
	}
	out := evalFlowCls(now)
	if out.Samples != 60 {
		t.Fatalf("考题数 = %d, want 60", out.Samples)
	}
	if out.ModelAcc < 0.9 {
		t.Fatalf("时间切分后模型准确率 = %.2f, want ≥ 0.9", out.ModelAcc)
	}
	// 手工规则列与标签一致(构造时 manual == cat)
	if out.ManualSamples != 60 || out.ManualAcc < 0.99 {
		t.Fatalf("手工列: n=%d acc=%.2f, want 60/≈1.0", out.ManualSamples, out.ManualAcc)
	}
}

// TestFcEvalInsufficient 样本不足 → 只给说明。
func TestFcEvalInsufficient(t *testing.T) {
	old := fcPool
	fcPoolMu.Lock()
	fcPool = nil
	fcPoolMu.Unlock()
	defer func() {
		fcPoolMu.Lock()
		fcPool = old
		fcPoolMu.Unlock()
	}()
	out := evalFlowCls(time.Now())
	if out.Note == "" {
		t.Fatal("样本不足应有说明")
	}
}

// TestFcPoolConcurrent 池并发安全(apiConnections 读 vs tick 写)。
func TestFcPoolConcurrent(t *testing.T) {
	old := fcPool
	fcPoolMu.Lock()
	fcPool = nil
	fcPoolMu.Unlock()
	defer func() {
		fcPoolMu.Lock()
		fcPool = old
		fcPoolMu.Unlock()
	}()
	var wg sync.WaitGroup
	vec := fcVecOf(fcGameFeats(), fcSynthFlow(fcGameFeats(), "udp", 443))
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				fcPoolAdd(fcSample{vec: vec, cat: "游戏", ts: int64(200000 + i)})
			}
		}()
	}
	wg.Wait()
	if n := func() int { fcPoolMu.Lock(); defer fcPoolMu.Unlock(); return len(fcPool) }(); n != 2000 {
		t.Fatalf("并发加入后池 = %d, want 2000(封顶)", n)
	}
}
