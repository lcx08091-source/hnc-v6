// hnc_dpid: HNC DPI daemon, AppSense-lite rc1.2-fixed.
//
// rc19 adds L2 per-client DNS/SNI attribution:
// capability probe -> mode decision -> raw AF_PACKET socket -> DNS/TLS events -> per-client metadata -> dpi_state.json.
//
// It does NOT do: NFQUEUE, DNS hijacking, QUIC, HTTP parsing,
// conntrack correlation, automatic limit/mark, or offload modification.
// rc20 adds L3 read-only app/category labels from DNS/SNI suffix rules. rc20.1 supports external dpi_rules.json imports.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/capture"
	"hnc.io/dpid/output"
	"hnc.io/dpid/probe"
)

var version = "0.5.3-rc30.12.3-iface-retry"

const (
	defaultConfigPath = "/data/local/hnc/etc/dpi_config.json"
	defaultRunDir     = "/data/local/hnc/run"

	pidFileName   = "dpid.pid"
	lockFileName  = "dpid.lock"
	probeFileName = "dpid.probe.json"
	stateFileName = "dpi_state.json"
	crashFlagFile = "dpid.crashflag"

	maxCrashesWindow  = 60 * time.Second
	maxCrashesAllowed = 3

	debugEventsPerSec = 20
)

type Config struct {
	Iface          string `json:"iface,omitempty"`
	Snaplen        int    `json:"snaplen,omitempty"`
	RcvBufBytes    int    `json:"rcv_buf_bytes,omitempty"`
	LogLevel       string `json:"log_level,omitempty"`
	RunDir         string `json:"run_dir,omitempty"`
	DisableCapture bool   `json:"disable_capture,omitempty"`
}

func defaultConfig() Config {
	return Config{
		Snaplen:     1024,
		RcvBufBytes: 4 << 20,
		LogLevel:    "info",
		RunDir:      defaultRunDir,
	}
}

type Mode string

const (
	ModeOK        Mode = "ok"
	ModeBlind     Mode = "blind"
	ModeDisabled  Mode = "disabled"
	ModeCrashLoop Mode = "crash_loop"
)

func main() {
	cfgPath := flag.String("config", defaultConfigPath, "path to dpi_config.json")
	showVer := flag.Bool("version", false, "print version and exit")
	// rc29.1: -write-blind-state lets dpid_guard.sh hand off blind/waiting
	// state writing to dpid itself, so the JSON written matches dpid's schema
	// (2.0+) instead of the legacy schema-1 shell template. Used while iface
	// isn't ready, dpid binary is missing, etc.
	writeBlind := flag.String("write-blind-state", "",
		"write a single blind-mode dpi_state.json using this reason then exit (0 = full daemon)")
	blindIface := flag.String("blind-iface", "",
		"interface name to record in blind-state JSON (optional, used with -write-blind-state)")
	flag.Parse()

	if *showVer {
		fmt.Println("hnc_dpid", version)
		return
	}

	cfg := loadConfig(*cfgPath)
	if err := os.MkdirAll(cfg.RunDir, 0o750); err != nil {
		log.Fatalf("mkdir run_dir %s: %v", cfg.RunDir, err)
	}

	// rc29.1 blind-state writer mode: takes no lock, writes one file, exits.
	// Multiple guard invocations may race; that's fine because each rewrite
	// is atomic (Writer.Flush -> tmp + rename) and they're all equivalent
	// blind states. We don't try to acquire dpid.lock because the real
	// daemon may be running concurrently for unrelated reasons (e.g. in
	// disabled mode keeping state fresh).
	if *writeBlind != "" {
		statePath := filepath.Join(cfg.RunDir, stateFileName)
		sw := output.NewWriter(statePath, version)
		sw.SetMode(string(ModeBlind), *writeBlind, *blindIface, false, false)
		if err := sw.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "write-blind-state: %v\n", err)
			os.Exit(1)
		}
		return
	}

	lockFD, err := acquireLock(filepath.Join(cfg.RunDir, lockFileName))
	if err != nil {
		log.Fatalf("lock: %v", err)
	}
	defer releaseLock(lockFD)

	// Write PID early so crash_loop, blind, disabled, and ok modes all have a pid file.
	pidPath := filepath.Join(cfg.RunDir, pidFileName)
	if err := atomicWriteString(pidPath, strconv.Itoa(os.Getpid())+"\n"); err != nil {
		log.Printf("WARN: write pid: %v", err)
	}
	defer os.Remove(pidPath)

	statePath := filepath.Join(cfg.RunDir, stateFileName)
	sw := output.NewWriter(statePath, version)

	if reason := checkCrashLoop(cfg.RunDir); reason != "" {
		log.Printf("ERROR: %s", reason)
		sw.SetMode(string(ModeCrashLoop), reason, "", false, false)
		_ = sw.Flush()
		idleUntilSignal(sw)
		return
	}

	pr := probe.Run(probe.Options{IfaceOverride: cfg.Iface})
	if err := probe.WriteJSON(filepath.Join(cfg.RunDir, probeFileName), pr); err != nil {
		log.Printf("WARN: write probe: %v", err)
	}
	log.Printf("probe: af_packet=%v iface=%q src=%s offload_hint=%v conntrack=%v ipv6_capture=%v",
		pr.AFPacketAvailable, pr.APIface, pr.APIfaceSource, pr.OffloadHint, pr.ConntrackReadable, pr.IPv6Capture)

	// rc29 fix: tell capture about the hotspot's own IP nets so assignClient
	// can correctly identify which side of a flow is the client. Without
	// this, reverse-direction packets (server -> client) get the server
	// SrcIP assigned as the "client", flooding the clients map with bogus
	// per-server entries (rc29 initial release bug).
	if pr.APIface != "" {
		nets := capture.InterfaceNets(pr.APIface)
		capture.SetHotspotNets(nets)
		if len(nets) > 0 {
			names := make([]string, 0, len(nets))
			for _, n := range nets {
				names = append(names, n.String())
			}
			log.Printf("hotspot nets on %s: %s", pr.APIface, strings.Join(names, " "))
		} else {
			log.Printf("WARN: no IP addrs detected on %s; client/server direction inference disabled", pr.APIface)
		}
	}

	mode, blindReason := decideMode(cfg, pr)
	sw.SetMode(string(mode), blindReason, pr.APIface, pr.TLSReassembly, pr.OffloadHint)
	_ = sw.Flush()
	if blindReason != "" {
		log.Printf("startup mode: %s: %s", mode, blindReason)
	} else {
		log.Printf("startup mode: %s", mode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				log.Printf("received %v, shutting down", sig)
				cancel()
				return
			case syscall.SIGHUP:
				log.Printf("SIGHUP received (rules reload is rc2)")
			}
		}
	}()

	armCrashFlag(cfg.RunDir)

	// rc30.4: traffic history sampler. Runs at the top-level ctx so it
	// survives attempt restarts (interface migration, capture re-open).
	// First tick after dpid start only establishes a baseline — no row is
	// written. Subsequent ticks emit (mac, app, tx_delta, rx_delta) JSONL
	// rows to /data/local/hnc/run/stats.YYYYMMDD.jsonl for trend graphs.
	output.HistoryDir = cfg.RunDir
	historySampler := output.NewHistorySampler(sw)
	go func() {
		tk := time.NewTicker(output.HistorySampleEvery)
		defer tk.Stop()
		// Establish baseline immediately so the first row arrives at the
		// FIRST scheduled tick, not the second.
		historySampler.Tick(time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-tk.C:
				historySampler.Tick(t)
			}
		}
	}()

	// rc30.6: IP→app reverse map flusher. Writes /run/ip_app_map.json
	// every 30s for apply_app_limits.sh to consume. Holding the data only
	// in memory and dumping on a clock tick (vs. streaming on every
	// classification hit) keeps the file lock contention near zero.
	if sw.IPAppMap != nil {
		sw.IPAppMap.SetPath(filepath.Join(cfg.RunDir, "ip_app_map.json"))
		go func() {
			tk := time.NewTicker(30 * time.Second)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-tk.C:
					if err := sw.IPAppMap.Flush(t); err != nil {
						log.Printf("ip_app_map flush: %v", err)
					}
				}
			}
		}()
	}

	// v5.5: self-attribution sampler.
	//
	// Reads /proc/net/{tcp,tcp6,udp,udp6} every 5s, resolves each
	// socket's uid via `pm list packages -U` (cached 5min), publishes a
	// per-uid app aggregation into State.Self via Writer.SetSelf(), and
	// appends one observation per tick to self_attrib.YYYYMMDD.jsonl.
	//
	// Gated by the flag file /data/local/hnc/run/self_capture.enabled:
	// touch to enable, rm to disable. Re-read on every sampler tick so
	// changes take effect within 5s without restarting dpid.
	//
	// The aggregator is built unconditionally so SetSelf() can be called
	// from the goroutine on every tick — the WebUI then sees either a
	// populated `self` block (when enabled) or a stub block with
	// {enabled: false, reason: ...}.
	selfAttribFlag := filepath.Join(cfg.RunDir, "self_capture.enabled")
	selfAttrib := output.NewSelfAttribAggregator(cfg.RunDir)
	go func() {
		isEnabled := func() bool {
			_, err := os.Stat(selfAttribFlag)
			enabled := err == nil
			if enabled {
				selfAttrib.SetEnabled(true, "")
			} else {
				selfAttrib.SetEnabled(false, "self-capture flag file not present")
			}
			return enabled
		}
		// Also publish a periodic snapshot into the dpi_state, regardless
		// of enabled (so WebUI can see "feature exists but is off").
		go func() {
			tk := time.NewTicker(5 * time.Second)
			defer tk.Stop()
			isEnabled() // prime the flag once
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					isEnabled() // refresh enabled bit
					sw.SetSelf(selfAttrib.Snapshot())
				}
			}
		}()
		selfAttrib.RunSampler(ctx, isEnabled)
	}()

	switch mode {
	case ModeBlind, ModeDisabled:
		log.Printf("no capture in %s mode; idling for state writes", mode)
		idleWithFlush(ctx, sw)
	case ModeOK:
		if err := runCapture(ctx, cfg, pr, sw); err != nil {
			// Capture open/run failure is capability failure, not daemon crash.
			reason := "open/run capture failed: " + err.Error()
			log.Printf("ERROR: %s", reason)
			sw.SetMode(string(ModeBlind), reason, pr.APIface, pr.TLSReassembly, pr.OffloadHint)
			_ = sw.Flush()
			clearCrashFlag(cfg.RunDir)
			idleWithFlush(ctx, sw)
		}
	}

	_ = sw.Flush()
	clearCrashFlag(cfg.RunDir)
	log.Printf("hnc_dpid exited cleanly")
}

func runCapture(ctx context.Context, cfg Config, pr probe.Result, sw *output.Writer) error {
	iface := pr.APIface
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		attempt++
		h, err := capture.Open(capture.Options{Iface: iface, Snaplen: cfg.Snaplen, RcvBufBytes: cfg.RcvBufBytes})
		if err != nil {
			if isRecoverableCaptureError(err) {
				reason := "interface down/rebind retry: " + err.Error()
				log.Printf("WARN: %s", reason)
				sw.SetMode(string(ModeBlind), reason, iface, pr.TLSReassembly, pr.OffloadHint)
				_ = sw.Flush()
				if !sleepOrDone(ctx, 2*time.Second) {
					return nil
				}
				continue
			}
			return fmt.Errorf("open capture: %w", err)
		}

		attemptCtx, attemptCancel := context.WithCancel(ctx)
		log.Printf("capture started on %s (snaplen=%d, rcvbuf=%d, attempt=%d)", iface, cfg.Snaplen, cfg.RcvBufBytes, attempt)
		sw.SetMode(string(ModeOK), "", iface, pr.TLSReassembly, pr.OffloadHint)
		_ = sw.Flush()

		debug := cfg.LogLevel == "debug"
		var debugBudget atomic.Int64
		if debug {
			debugBudget.Store(int64(debugEventsPerSec))
			go func() {
				tk := time.NewTicker(time.Second)
				defer tk.Stop()
				for {
					select {
					case <-attemptCtx.Done():
						return
					case <-tk.C:
						debugBudget.Store(int64(debugEventsPerSec))
					}
				}
			}()
		}

		go func(local *capture.Handle) {
			tk := time.NewTicker(5 * time.Second)
			defer tk.Stop()
			for {
				select {
				case <-attemptCtx.Done():
					return
				case <-tk.C:
					s := local.Stats()
					sw.UpdateStats(output.Stats{
						Packets:        s.Packets,
						KernelDrops:    s.KernelDrops,
						DNSEvents:      s.DNSEvents,
						TLSEvents:      s.TLSEvents,
						FlowEvents:     s.FlowEvents,
						IgnoredPackets: s.IgnoredPackets,
						ParseErrors:    s.ParseErrors,
					})
					if err := sw.Flush(); err != nil {
						log.Printf("WARN: flush state: %v", err)
					}
				}
			}
		}(h)

		go func(local *capture.Handle) {
			tk := time.NewTicker(15 * time.Second)
			defer tk.Stop()
			for {
				select {
				case <-attemptCtx.Done():
					return
				case <-tk.C:
					s := local.Stats()
					log.Printf("stats: pkts=%d drops=%d dns=%d tls=%d flow=%d ignored=%d perr=%d",
						s.Packets, s.KernelDrops, s.DNSEvents, s.TLSEvents, s.FlowEvents, s.IgnoredPackets, s.ParseErrors)
				}
			}
		}(h)

		// rc29: conntrack telemetry, refreshed every 15s.
		go func() {
			tk := time.NewTicker(15 * time.Second)
			defer tk.Stop()
			// Refresh once immediately so the first dpi_state.json has values.
			r := output.ReadConntrack()
			sw.UpdateConntrack(r.Available, r.Readable, r.Path, r.Flows)
			for {
				select {
				case <-attemptCtx.Done():
					return
				case <-tk.C:
					r := output.ReadConntrack()
					sw.UpdateConntrack(r.Available, r.Readable, r.Path, r.Flows)
				}
			}
		}()

		err = h.Run(attemptCtx, func(ev capture.Event) {
			clientMAC := ev.ClientMAC.String()
			clientIP := ev.ClientIP.String()
			remoteIP := ev.RemoteIP.String()

			switch ev.Kind {
			case capture.EventDNS:
				sw.RecordDNS(clientMAC, clientIP, remoteIP, ev.DNS.QName, ev.Time)
			case capture.EventTLSClientHello:
				sw.RecordTLS(clientMAC, clientIP, remoteIP, ev.TLS.SNI, ev.TLS.JA4, ev.Time)
			case capture.EventFlow:
				// txFromClient: heuristic — when ClientIP == SrcIP, this packet
				// went client->remote (uplink). The assignClient() logic in
				// parse.go always sets ClientIP=SrcIP for non-DNS-response
				// packets, so for EventFlow this is always true. Bidirectional
				// byte counts will only be accurate once we also see the
				// remote->client direction; on hotspot we typically do.
				port := ev.DstPort
				txFromClient := ev.SrcIP.Equal(ev.ClientIP)
				if !txFromClient {
					port = ev.SrcPort
				}
				sw.RecordFlow(clientMAC, clientIP, remoteIP, ev.IsUDP, port, uint64(ev.Bytes), txFromClient, ev.Time)
			}

			if !debug {
				return
			}
			if debugBudget.Add(-1) < 0 {
				return
			}
			// NOTE: debug logs contain full qname/SNI. Formal release/debug bundles must sanitize qname/SNI.
			switch ev.Kind {
			case capture.EventDNS:
				log.Printf("DNS client=%s/%s remote=%s qname=%q qtype=%d resp=%v ttl=%d answers=%d",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.DNS.QName, ev.DNS.QType, ev.DNS.IsResponse, ev.DNS.TTL, len(ev.DNS.Answers))
			case capture.EventTLSClientHello:
				log.Printf("TLS-CH client=%s/%s remote=%s sni=%q alpn=%v ja4=%s",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.TLS.SNI, ev.TLS.ALPN, ev.TLS.JA4)
			case capture.EventFlow:
				log.Printf("FLOW client=%s/%s remote=%s udp=%v sport=%d dport=%d bytes=%d v6=%v",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.IsUDP, ev.SrcPort, ev.DstPort, ev.Bytes, ev.IsIPv6)
			}
		})
		attemptCancel()
		h.Close()
		if err == nil {
			return nil
		}
		if isRecoverableCaptureError(err) {
			reason := "interface down/rebind retry: " + err.Error()
			log.Printf("WARN: %s", reason)
			sw.SetMode(string(ModeBlind), reason, iface, pr.TLSReassembly, pr.OffloadHint)
			_ = sw.Flush()
			if !sleepOrDone(ctx, 2*time.Second) {
				return nil
			}
			continue
		}
		return err
	}
}

// rc30.12.3-iface-retry: 同步到 bin/hnc_dpid 实际二进制的修复版本.
// 之前源码只匹配 4 个 syscall errno, 但 Realme / ColorOS 16 / SukiSU 上 AF_PACKET
// 经常返回字符串错误 ("no such network interface" 等) 而不是 errno, 老逻辑漏判,
// dpid 直接退出, DPI 盲. 加字符串 fallback 后能正确识别 "接口暂时不在" 类错误,
// 进入 retry 循环等接口起来.
func isRecoverableCaptureError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENETRESET) ||
		errors.Is(err, syscall.ENXIO) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such network interface") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "network is down") ||
		strings.Contains(msg, "network is unreachable")
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func idleWithFlush(ctx context.Context, sw *output.Writer) {
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			_ = sw.Flush()
		}
	}
}

func idleUntilSignal(sw *output.Writer) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-sigCh:
			return
		case <-tk.C:
			_ = sw.Flush()
		}
	}
}

func decideMode(cfg Config, pr probe.Result) (Mode, string) {
	if cfg.DisableCapture {
		return ModeDisabled, "disable_capture=true"
	}
	if !pr.AFPacketAvailable {
		return ModeBlind, "AF_PACKET unavailable: " + pr.AFPacketError
	}
	if pr.APIface == "" {
		return ModeBlind, "no hotspot iface detected"
	}
	return ModeOK, ""
}

func loadConfig(path string) Config {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARN: read config %s: %v", path, err)
		}
		return cfg
	}
	var raw Config
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Printf("WARN: parse config %s: %v (using defaults)", path, err)
		return cfg
	}
	if raw.Iface != "" {
		cfg.Iface = raw.Iface
	}
	if raw.Snaplen > 0 {
		cfg.Snaplen = raw.Snaplen
	}
	if raw.RcvBufBytes > 0 {
		cfg.RcvBufBytes = raw.RcvBufBytes
	}
	if raw.LogLevel != "" {
		cfg.LogLevel = raw.LogLevel
	}
	if raw.RunDir != "" {
		cfg.RunDir = raw.RunDir
	}
	if raw.DisableCapture {
		cfg.DisableCapture = true
	}
	return cfg
}

func acquireLock(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0o644)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if err == syscall.EWOULDBLOCK {
			return -1, fmt.Errorf("another hnc_dpid is running (%s held)", path)
		}
		return -1, fmt.Errorf("flock %s: %w", path, err)
	}
	return fd, nil
}

func releaseLock(fd int) {
	if fd >= 0 {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}
}

func atomicWriteString(path, data string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func armCrashFlag(runDir string) {
	path := filepath.Join(runDir, crashFlagFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("WARN: arm crash flag: %v", err)
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%d\n", time.Now().Unix())
	_ = f.Sync()
}

func clearCrashFlag(runDir string) {
	_ = os.Remove(filepath.Join(runDir, crashFlagFile))
}

func checkCrashLoop(runDir string) string {
	path := filepath.Join(runDir, crashFlagFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	cutoff := time.Now().Add(-maxCrashesWindow).Unix()
	recent := 0
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '\n' {
			if i > start {
				if ts, err := strconv.ParseInt(string(b[start:i]), 10, 64); err == nil && ts >= cutoff {
					recent++
				}
			}
			start = i + 1
		}
	}
	if recent >= maxCrashesAllowed {
		return fmt.Sprintf("crash loop: %d starts in last %s", recent, maxCrashesWindow)
	}
	return ""
}
