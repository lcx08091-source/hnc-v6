// Package output - flow.go: per-client flow persistence tracker.
//
// Why: the 20-min ground-truth pcap (2026-05-16) had a WeChat voice call
// running the entire time in the background, plus several foreground apps
// rotating in and out. The prior rule binary attributed background WeChat
// packets to whatever app happened to be in the foreground at the time,
// poisoning per-app statistics.
//
// Fix: classify a flow as "background" if it sustained activity for more
// than 80% of its 30-second observation buckets. Background flows are
// still classified (rule still hits), but the WebUI can choose to display
// them separately, and label aggregates know which packets came from a
// long-running flow vs a freshly-opened one.
//
// Implementation: a flowTracker holds at most maxFlowsPerClient flows.
// Each flow has a ring of 16 thirty-second buckets. A bucket is "active"
// if any packet landed in it. backgroundShare() returns the fraction of
// tracked flows whose persistence percentage is >= persistenceThreshold.

package output

import (
	"sort"
)

const (
	bucketSeconds        = 30
	bucketCount          = 16 // 8 minutes of history
	persistenceThreshold = 0.80
	flowMaxIdleSeconds   = 60 * 10 // 10min idle -> evict
)

type flowBucket struct {
	startUnix int64
	packets   uint32
	bytes     uint64
}

type flowEntry struct {
	key       string // "T|remoteIP:port" 或 "U|remoteIP:port" (proto|ip:port)
	firstSeen int64
	lastSeen  int64
	packets   uint64
	bytes     uint64

	buckets [bucketCount]flowBucket
	head    int // ring index of current bucket

	// pps tracking: ema of packets per second over the last bucket.
	lastBucketStart int64
	lastBucketPkts  uint32
	emaPPS          float64
}

type flowTracker struct {
	flows map[string]*flowEntry
}

func newFlowTracker() *flowTracker {
	return &flowTracker{flows: make(map[string]*flowEntry)}
}

// observe records a single packet on the named flow. Returns the latest
// per-second packet rate estimate for this flow (used by sub-category
// detectors like wechat voice_call), plus created=true when this call
// materialized a NEW flow entry (v5.9.7: Writer 用它做 O(1) 全局流计数)。
func (ft *flowTracker) observe(key string, nowUnix int64, bytes uint64) (float64, bool) {
	if ft.flows == nil {
		ft.flows = make(map[string]*flowEntry)
	}
	f := ft.flows[key]
	created := false
	if f == nil {
		if len(ft.flows) >= maxFlowsPerClient {
			ft.evictOldest(nowUnix)
		}
		f = &flowEntry{
			key:             key,
			firstSeen:       nowUnix,
			lastBucketStart: bucketStart(nowUnix),
		}
		f.buckets[0].startUnix = bucketStart(nowUnix)
		ft.flows[key] = f
		created = true
	}
	f.lastSeen = nowUnix
	f.packets++
	f.bytes += bytes

	// Roll bucket if we've passed bucketSeconds.
	bs := bucketStart(nowUnix)
	if bs != f.buckets[f.head].startUnix {
		// Close out previous bucket and compute pps for it.
		prevPkts := f.buckets[f.head].packets
		if bs > f.buckets[f.head].startUnix {
			// Linear EMA: new = 0.6 * sample + 0.4 * old.
			sample := float64(prevPkts) / float64(bucketSeconds)
			if f.emaPPS == 0 {
				f.emaPPS = sample
			} else {
				f.emaPPS = sample*0.6 + f.emaPPS*0.4
			}
		}
		// Advance head, possibly skipping multiple empty buckets if there
		// was a gap > bucketSeconds.
		stepsBack := int((bs - f.buckets[f.head].startUnix) / bucketSeconds)
		if stepsBack < 1 {
			stepsBack = 1
		}
		if stepsBack > bucketCount {
			stepsBack = bucketCount
		}
		for i := 0; i < stepsBack; i++ {
			f.head = (f.head + 1) % bucketCount
			f.buckets[f.head] = flowBucket{startUnix: bs - int64((stepsBack-1-i)*bucketSeconds)}
		}
		f.lastBucketStart = bs
	}
	f.buckets[f.head].packets++
	f.buckets[f.head].bytes += bytes
	return f.emaPPS, created
}

// bucketStart truncates a unix timestamp to the start of its 30s bucket.
func bucketStart(t int64) int64 {
	return t - (t % bucketSeconds)
}

// evictOldest 返回删除的流条数(v5.9.7: Writer 用它维护全局计数)。
func (ft *flowTracker) evictOldest(nowUnix int64) int {
	// v5.9.6 (回移自 5.9.91 分叉): 第一遍清掉全部 idle 流 (主判据) —— 旧实现
	// 只删一个就返回, cap 压力大时一次只腾一个坑; 清完仍满员再按活跃度
	// (bytes+packets 最低) 删最不活跃的 (次判据, 取代旧的"最旧")。
	removed := 0
	for k, f := range ft.flows {
		if nowUnix-f.lastSeen > flowMaxIdleSeconds {
			delete(ft.flows, k)
			removed++
		}
	}
	if len(ft.flows) >= maxFlowsPerClient {
		var worstKey string
		var worstScore uint64
		first := true
		for k, f := range ft.flows {
			score := f.bytes + f.packets // activity score
			if first || score < worstScore {
				worstKey, worstScore, first = k, score, false
			}
		}
		if worstKey != "" {
			delete(ft.flows, worstKey)
			removed++
		}
	}
	return removed
}

// globalEvict 全局超限时的驱逐(回移自 5.9.91 分叉): 先清 idle, 再按活跃度
// 从低到高删到全局预算以内。返回删除条数。
func (ft *flowTracker) globalEvict(nowUnix int64, budget int) int {
	removed := 0
	// 先清 idle
	for k, f := range ft.flows {
		if nowUnix-f.lastSeen > flowMaxIdleSeconds {
			delete(ft.flows, k)
			removed++
		}
	}
	for len(ft.flows) > budget {
		var worstKey string
		var worstScore uint64
		first := true
		for k, f := range ft.flows {
			score := f.bytes + f.packets
			if first || score < worstScore {
				worstKey, worstScore, first = k, score, false
			}
		}
		if worstKey == "" {
			break
		}
		delete(ft.flows, worstKey)
		removed++
	}
	return removed
}

// persistencePct returns the share of buckets within bucketCount window that
// have at least one packet. Range [0,1]. We require a flow to have been
// observed for at least 3 buckets (90s) before classifying as persistent.
func (f *flowEntry) persistencePct(nowUnix int64) float64 {
	age := nowUnix - f.firstSeen
	if age < bucketSeconds*3 {
		return 0
	}
	totalWindow := bucketCount
	if int(age/bucketSeconds) < totalWindow {
		totalWindow = int(age/bucketSeconds) + 1
	}
	if totalWindow <= 0 {
		return 0
	}
	active := 0
	for i := 0; i < totalWindow; i++ {
		idx := (f.head - i + bucketCount) % bucketCount
		if f.buckets[idx].packets > 0 {
			active++
		}
	}
	return float64(active) / float64(totalWindow)
}

// backgroundShare returns the fraction of currently-tracked flows whose
// persistence pct exceeds persistenceThreshold. Used by Flush to populate
// ClientProfile.BackgroundFlowsPct.
func (ft *flowTracker) backgroundShare(nowUnix int64) float64 {
	if len(ft.flows) == 0 {
		return 0
	}
	total := 0
	bg := 0
	for _, f := range ft.flows {
		// Only count flows old enough to be meaningful.
		if nowUnix-f.firstSeen < bucketSeconds*3 {
			continue
		}
		total++
		if f.persistencePct(nowUnix) >= persistenceThreshold {
			bg++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(bg) / float64(total)
}

// topFlowsByBytes is currently unused but kept for future WebUI views and
// to help debug the persistence detector. Returns flows sorted by byte
// count descending, capped at n.
func (ft *flowTracker) topFlowsByBytes(n int) []*flowEntry {
	out := make([]*flowEntry, 0, len(ft.flows))
	for _, f := range ft.flows {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bytes > out[j].bytes })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
