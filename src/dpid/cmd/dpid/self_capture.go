// v5.6.0-rc1 — self-iface AF_PACKET capture supervisor.
//
// This file is the third pillar of HNC's traffic awareness, alongside
// the AP capture (runCapture, watches the hotspot iface) and the /proc/net
// sampler (selfAttrib.RunSampler, uid → app attribution).
//
// Its job: open AF_PACKET capture handles on the device's *own* interfaces
// (rmnet0, wlan0, etc) and route the SNI events it extracts into selfAttrib,
// *not* into the main Writer — these flows belong to the device itself, not
// to a hotspot client.
//
// ── Lifecycle ──────────────────────────────────────────────────────────
// Reconciler loop ticks every selfRescanInterval (30s):
//
//   - flag file (`/data/local/hnc/run/self_capture.enabled`) absent
//     → cancel all live captures, push empty Interfaces[] to selfAttrib, idle
//
//   - flag file present
//     → DiscoverSelfCandidates(currentAP) lists eligible ifaces
//     → reconcile: spawn new captures, cancel vanished ones
//     → push current per-iface state (Started/Restarts/TLS/DNS counts)
//
// ── Per-iface capture ──────────────────────────────────────────────────
// capture.Open with the default BPF (TCP/443 + UDP/53 + UDP/443 — same as
// the AP capture; IsSelfBPFFilter() currently returns "" by design).
//
// On EventTLSClientHello: LookupUID(DstIP, DstPort) → RecordSNI(uid, sni, ts).
// On any error (open / run): log, exit; reconciler restarts on next tick.
//
// ── Why this isn't fused into runCapture ──────────────────────────────
// The AP capture has a different failure model — the AP iface is the
// raison d'être of HNC, so its disappearance is degraded mode (SetMode
// "blind") and we back off + retry forever. Self ifaces come and go
// freely (airplane mode, dual-SIM swap, USB tether plug/unplug); their
// disappearance is routine, not a failure. Keeping them in a separate
// supervisor lets each pillar fail in its own appropriate way.

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"hnc.io/dpid/capture"
	"hnc.io/dpid/output"
)

const (
	// selfRescanInterval bounds how quickly we notice new ifaces (rmnet0
	// appearing after airplane mode off) or vanished ifaces. 30s is a
	// compromise between snappiness and /sys/class/net scan cost.
	selfRescanInterval = 30 * time.Second
)

// liveCap is one active per-iface capture goroutine's bookkeeping.
type liveCap struct {
	iface     string
	cancel    context.CancelFunc
	done      chan struct{} // closed when the capture goroutine exits
	startedAt int64

	// Per-iface counters (atomic so the reconciler can read them under
	// only its own liveMu, not the capture goroutine's locks).
	packets   atomic.Uint64
	tlsEvents atomic.Uint64
	dnsEvents atomic.Uint64
	restarts  atomic.Int64

	// lastErr is the last open/run error, if any. Surfaced into
	// SelfIfaceState.LastError so the WebUI can show it without us
	// having to invent a separate log stream.
	lastErrMu sync.Mutex
	lastErr   string
}

func (lc *liveCap) setErr(s string) {
	lc.lastErrMu.Lock()
	defer lc.lastErrMu.Unlock()
	lc.lastErr = s
}

func (lc *liveCap) getErr() string {
	lc.lastErrMu.Lock()
	defer lc.lastErrMu.Unlock()
	return lc.lastErr
}

// runSelfCaptures is the reconciler loop. Started once from dpid main
// near the selfAttrib goroutine. Returns only when ctx is cancelled.
//
// On return, all live captures are cancelled and waited synchronously
// (via defer cancelAll), so dpid shutdown is deterministic.
func runSelfCaptures(ctx context.Context, cfg Config, selfAttrib *output.SelfAttribAggregator, getAPIface func() string) {
	flagPath := filepath.Join(cfg.RunDir, "self_capture.enabled")

	live := map[string]*liveCap{}
	var liveMu sync.Mutex

	// cancelOne stops and waits for one iface's capture. Caller holds liveMu.
	cancelOne := func(name string) {
		lc, ok := live[name]
		if !ok {
			return
		}
		lc.cancel()
		<-lc.done
		delete(live, name)
		log.Printf("self-capture[%s]: stopped", name)
	}

	// pushState publishes the live[] snapshot into selfAttrib so the next
	// dpi_state.json flush shows the right Interfaces[] block. Caller
	// holds liveMu so atomic reads are coherent with map state.
	pushState := func() {
		statuses := make([]output.SelfIfaceState, 0, len(live))
		for name, lc := range live {
			statuses = append(statuses, output.SelfIfaceState{
				Name:      name,
				StartedAt: lc.startedAt,
				Restarts:  lc.restarts.Load(),
				LastError: lc.getErr(),
				Packets:   lc.packets.Load(),
				TLSEvents: lc.tlsEvents.Load(),
				DNSEvents: lc.dnsEvents.Load(),
			})
		}
		selfAttrib.SetIfaceState(statuses)
	}

	// cancelAll is for shutdown (defer) and for the disabled-flag branch.
	cancelAll := func() {
		liveMu.Lock()
		defer liveMu.Unlock()
		names := make([]string, 0, len(live))
		for n := range live {
			names = append(names, n)
		}
		for _, n := range names {
			cancelOne(n)
		}
		pushState()
	}
	defer cancelAll()

	reconcile := func() {
		liveMu.Lock()
		defer liveMu.Unlock()

		// Flag re-read on every tick — no caching. Cheap stat call,
		// keeps the loop honest about user toggling via WebUI.
		if _, err := os.Stat(flagPath); err != nil {
			if len(live) > 0 {
				log.Printf("self-capture: flag file absent, cancelling %d capture(s)", len(live))
			}
			names := make([]string, 0, len(live))
			for n := range live {
				names = append(names, n)
			}
			for _, n := range names {
				cancelOne(n)
			}
			pushState()
			return
		}

		// Flag present — discover ifaces.
		ap := getAPIface()
		cands, err := capture.DiscoverSelfCandidates(ap)
		if err != nil {
			log.Printf("self-capture: DiscoverSelfCandidates: %v", err)
			return
		}
		wantSet := map[string]struct{}{}
		for _, c := range cands {
			wantSet[c.Name] = struct{}{}
		}

		// Stop captures whose iface vanished.
		toStop := []string{}
		for name := range live {
			if _, want := wantSet[name]; !want {
				toStop = append(toStop, name)
			}
		}
		for _, n := range toStop {
			cancelOne(n)
		}

		// Start captures for newly-discovered ifaces.
		for _, c := range cands {
			if _, exists := live[c.Name]; exists {
				continue
			}
			childCtx, childCancel := context.WithCancel(ctx)
			lc := &liveCap{
				iface:     c.Name,
				cancel:    childCancel,
				done:      make(chan struct{}),
				startedAt: time.Now().Unix(),
			}
			live[c.Name] = lc
			go runOneSelfCapture(childCtx, cfg, lc, selfAttrib)
			log.Printf("self-capture[%s]: started (oper=%s, wifi=%v, cell=%v, rx=%d)",
				c.Name, c.OperState, c.IsWiFi, c.IsCell, c.RxBytes)
		}

		pushState()
	}

	// Prime once so the first dpi_state.json flush already shows the
	// populated Interfaces[] (rather than empty until first 30s tick).
	reconcile()

	tk := time.NewTicker(selfRescanInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			reconcile()
		}
	}
}

// runOneSelfCapture opens a single capture handle and pumps events through
// the self-attribution path. close(lc.done) on exit is unconditional so
// cancelOne can wait deterministically.
//
// Failure modes:
//   - capture.Open fails (iface down between Discover and Open, no
//     permissions, etc) → log, set lc.lastErr, return.
//   - h.Run returns non-nil non-Canceled error (kernel drop, raw socket
//     EOF, etc) → log, set lc.lastErr, return.
// In all cases, the reconciler will see this iface still present in
// DiscoverSelfCandidates on the next tick and restart us — restarts
// counter bumps to make this visible in dpi_state.json.
func runOneSelfCapture(ctx context.Context, cfg Config, lc *liveCap, selfAttrib *output.SelfAttribAggregator) {
	defer close(lc.done)

	h, err := capture.Open(capture.Options{
		Iface:       lc.iface,
		Snaplen:     cfg.Snaplen,
		RcvBufBytes: cfg.RcvBufBytes,
	})
	if err != nil {
		lc.setErr("open: " + err.Error())
		log.Printf("self-capture[%s]: open failed: %v", lc.iface, err)
		return
	}
	defer h.Close()
	lc.setErr("") // clear stale error on successful open

	// v5.6.0-rc3: log linkType so the right parser dispatch is visible
	// at a glance (rmnet=519 RawIP, tun=65534 None, wlan0=1 Ether).
	// Pre-rc3 we silently used the Ethernet parser on all interfaces;
	// that produced zero events on cellular because rmnet has no L2
	// header. If you see linkType=519 here and still pkts=0 below, the
	// kernel isn't delivering — try `ip link show <iface>` for state.
	log.Printf("self-capture[%s]: capture handle open (linkType=%d)", lc.iface, h.LinkType())

	err = h.Run(ctx, func(ev capture.Event) {
		lc.packets.Add(1)
		switch ev.Kind {
		case capture.EventTLSClientHello:
			lc.tlsEvents.Add(1)
			if ev.TLS.SNI == "" {
				return
			}
			// In self traffic, our device is the TLS client, so the
			// ClientHello travels src→dst. DstIP/DstPort identifies the
			// remote endpoint we need to look up in /proc/net.
			//
			// LookupUID can return ok=false legitimately on startup
			// (pkg cache hasn't warmed yet) or for very short-lived
			// connections that established+SNI'd between two 5s
			// sampler ticks. Both are silent skips — the next
			// observation of the same conn will catch up.
			uid, _, ok := selfAttrib.LookupUID(ev.DstIP.String(), ev.DstPort)
			if !ok {
				return
			}
			// v5.6.0-rc2: ObserveSNI handles all three concerns in one call:
			// store the SNI in selfAttrib (for WebUI), classify against the
			// rule set (count hits for auto-expand evidence), and enqueue
			// unmatched ones for auto-expansion consideration. See
			// output/auto_expand.go.
			selfAttrib.ObserveSNI(uid, ev.TLS.SNI, ev.Time.Unix())
		case capture.EventDNS:
			lc.dnsEvents.Add(1)
			// DNS attribution intentionally not wired in v5.6 rc1.
			// Routing DNS QName into RecordSNI would conflate the
			// resolved name with the eventual TLS SNI; v5.7's candidate
			// accumulator will handle unmatched DNS separately with
			// proper provenance tracking.
		}
	})

	if err != nil && err != context.Canceled {
		lc.setErr("run: " + err.Error())
		log.Printf("self-capture[%s]: run ended with error: %v", lc.iface, err)
		lc.restarts.Add(1) // visible in SelfIfaceState.Restarts
	} else {
		log.Printf("self-capture[%s]: run ended cleanly", lc.iface)
	}
}
