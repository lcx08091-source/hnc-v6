// Package bytestats - dumpsys fallback.
//
// Parses `dumpsys netstats detail` output on devices where the eBPF
// path is unavailable. Slower (~200ms fork+exec+parse per sample) and
// the text format is internal-not-stable, but works on basically any
// rooted Android.
//
// Expected format (from real-device probe on Android 16 / ColorOS):
//
//   ident=[{type=0, ratType=...}] uid=10426 set=FOREGROUND tag=0x0
//       NetworkStatsHistory: bucketDuration=7200
//         st=1779444000 rb=8326 rp=55 tb=6977 tp=59 op=0
//         st=1779451200 rb=12000 rp=80 tb=8000 tp=70 op=0
//
// Strategy:
//   1. Run `dumpsys netstats detail`
//   2. Parse line-by-line: each `ident=...uid=N` marks a new section,
//      followed by 1+ NetworkStatsHistory bucket lines (st= rb= rp= tb= tp=).
//   3. Per uid, sum rb (rx_bytes) and tb (tx_bytes) across ALL buckets
//      and ALL ident/set/tag groups.
//   4. Return cumulative-since-boot counters.

package bytestats

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dumpsysCmd          = "dumpsys"
	dumpsysArg          = "netstats"
	dumpsysArgDetail    = "detail"
	dumpsysCmdTimeout   = 10 * time.Second
	dumpsysMinInterval  = 4 * time.Second // throttle: don't fork faster than this
)

// DumpsysSampler is the fallback ByteSampler. Stateless except for
// rate-limiting bookkeeping.
type DumpsysSampler struct {
	mu           sync.Mutex
	lastSampleAt time.Time
	lastResult   map[int]ByteCounts
}

// NewDumpsysSampler does a quick smoke test that `dumpsys netstats`
// runs and produces parseable output. If the command is missing,
// permissions are denied, or output is unparseable, returns an error.
func NewDumpsysSampler() (*DumpsysSampler, error) {
	s := &DumpsysSampler{}
	// Smoke test.
	result, err := s.runOnce()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("dumpsys netstats produced no uid stats — likely permission denied or unexpected format")
	}
	return s, nil
}

func (s *DumpsysSampler) Source() string { return "dumpsys" }

func (s *DumpsysSampler) Close() error { return nil }

// Sample runs dumpsys if enough time has passed since the last call,
// otherwise returns the cached result. This keeps the per-sample cost
// low when the caller polls faster than dumpsysMinInterval.
func (s *DumpsysSampler) Sample() (map[int]ByteCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastSampleAt.IsZero() && time.Since(s.lastSampleAt) < dumpsysMinInterval {
		return s.lastResult, nil
	}
	result, err := s.runOnce()
	if err != nil {
		return s.lastResult, err
	}
	s.lastSampleAt = time.Now()
	s.lastResult = result
	return result, nil
}

// uidRE matches the per-section header line:
//   ident=[{...}] uid=N set=FOREGROUND tag=0x0
var uidRE = regexp.MustCompile(`uid=(-?\d+)\s+set=`)

// bucketRE matches a single history bucket line:
//   st=1779444000 rb=8326 rp=55 tb=6977 tp=59 op=0
// We only need rb and tb. Numbers are unsigned 64-bit.
var bucketRE = regexp.MustCompile(`st=\d+\s+rb=(\d+)\s+rp=\d+\s+tb=(\d+)`)

// runOnce executes dumpsys netstats detail and parses the per-uid totals.
func (s *DumpsysSampler) runOnce() (map[int]ByteCounts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dumpsysCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, dumpsysCmd, dumpsysArg, dumpsysArgDetail)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dumpsys exec: %w", err)
	}

	totals := make(map[int]ByteCounts, 256)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	// Bump scanner buffer — dumpsys output has long ident= lines.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	currentUID := -1
	uidActive := false

	for scanner.Scan() {
		line := scanner.Text()

		// Section header line — switch current uid.
		if m := uidRE.FindStringSubmatch(line); m != nil {
			uid, err := strconv.Atoi(m[1])
			if err != nil {
				uidActive = false
				continue
			}
			// Filter out -1, -5 etc (Android special uids).
			if uid < 0 {
				uidActive = false
				continue
			}
			currentUID = uid
			uidActive = true
			continue
		}

		// Bucket data line — accumulate into current uid.
		if !uidActive {
			continue
		}
		if m := bucketRE.FindStringSubmatch(line); m != nil {
			rb, err1 := strconv.ParseUint(m[1], 10, 64)
			tb, err2 := strconv.ParseUint(m[2], 10, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			c := totals[currentUID]
			c.RxBytes += rb
			c.TxBytes += tb
			totals[currentUID] = c
		}
	}
	if err := scanner.Err(); err != nil {
		return totals, fmt.Errorf("dumpsys output scan: %w", err)
	}
	return totals, nil
}
