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
	key       string // remoteIP:port
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
// detectors like wechat voice_call).
func (ft *flowTracker) observe(key string, nowUnix int64, bytes uint64) float64 {
	if ft.flows == nil {
		ft.flows = make(map[string]*flowEntry)
	}
	f := ft.flows[key]
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
	return f.emaPPS
}

// bucketStart truncates a unix timestamp to the start of its 30s bucket.
func bucketStart(t int64) int64 {
	return t - (t % bucketSeconds)
}

func (ft *flowTracker) evictOldest(nowUnix int64) {
	var oldestKey string
	var oldest int64
	for k, f := range ft.flows {
		// Prefer evicting flows idle > flowMaxIdleSeconds.
		if nowUnix-f.lastSeen > flowMaxIdleSeconds {
			delete(ft.flows, k)
			return
		}
		if oldestKey == "" || f.lastSeen < oldest {
			oldestKey = k
			oldest = f.lastSeen
		}
	}
	if oldestKey != "" {
		delete(ft.flows, oldestKey)
	}
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
