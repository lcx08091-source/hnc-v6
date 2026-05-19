// hnc_dpid_supervisor — rc30.0
//
// Static Go replacement for bin/hnc_dpid_guard.sh.
//
// Why: the shell guard depended on /system/bin/sleep, head, printf, date, ip,
// cat, etc. In Android post-fs-data namespace transitions (KSU/SukiSU
// bind-mounting /system module overlays), these binaries are transiently
// ENOENT, putting the shell guard into a busy-loop death spiral. See
// dpid_guard.log evidence from rc29.0 through rc29.4.
//
// This binary is statically compiled (CGO_ENABLED=0), depends on no external
// tools, reads netlink via direct syscall, and forks dpid via os/exec which
// inherits a clean namespace via Go runtime, not shell.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ─── constants ────────────────────────────────────────────────────────────

const (
	hncDir          = "/data/local/hnc"
	runDir          = hncDir + "/run"
	logDir          = hncDir + "/logs"
	realBin         = hncDir + "/bin/hnc_dpid"
	configPath      = hncDir + "/etc/dpi_config.json"
	guardLog        = logDir + "/dpid_guard.log"
	dpidChildLog    = logDir + "/dpid.log"
	heartbeatFile   = runDir + "/dpid_guard.heartbeat"
	childPidFile    = runDir + "/dpid.child.pid"
	guardPidFile    = runDir + "/dpid_guard.pid"
	dpiStateFile    = runDir + "/dpi_state.json"
	hotspotHintFile = runDir + "/hotspot_iface"

	graceDur         = 5 * time.Second
	debounceDur      = 4 * time.Second
	heartbeatTick    = 2 * time.Second
	takeoverStaleSec = 60

	schemaVersion = "2.0"
	version       = "0.5.4-rc30.0-supervisor"
)

// netlink group constants (Linux RTNLGRP_*; not all exported by syscall)
const (
	rtnlgrpLink         = 0x1
	rtnlgrpIPv4IfAddr   = 0x5
	rtnlgrpIPv6IfAddr   = 0x9
	rtnlgrpIPv4Route    = 0x7
	rtnlgrpIPv6Route    = 0xb
)

// ─── globals ──────────────────────────────────────────────────────────────

var (
	logFile *os.File
	logMu   sync.Mutex

	netlinkCh = make(chan netlinkEvent, 64)
	stopCh    = make(chan struct{})
	stopOnce  sync.Once
)

type netlinkEvent struct {
	iface string
	kind  string // "link" | "addr"
	op    string // "new" | "del"
	raw   string // for logging
}

// ─── log + heartbeat ──────────────────────────────────────────────────────

func openLog() {
	_ = os.MkdirAll(logDir, 0o755)
	f, err := os.OpenFile(guardLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		logFile = f
	}
}

func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] [DPID-GUARD] %s\n", time.Now().Format("15:04:05"), msg)
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

func heartbeatLoop() {
	t := time.NewTicker(heartbeatTick)
	defer t.Stop()
	writeHeartbeat()
	for {
		select {
		case <-stopCh:
			return
		case <-t.C:
			writeHeartbeat()
		}
	}
}

func writeHeartbeat() {
	_ = os.WriteFile(heartbeatFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
}

// ─── single-instance lock ────────────────────────────────────────────────

func acquireLock() bool {
	if data, err := os.ReadFile(guardPidFile); err == nil {
		oldPid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if oldPid > 0 && processAlive(oldPid) {
			hb := readHeartbeatAge()
			if hb >= 0 && hb < takeoverStaleSec {
				logf("another supervisor already running pid=%d (heartbeat fresh, %ds)", oldPid, hb)
				return false
			}
			logf("supervisor pid=%d alive but heartbeat stale (age=%ds); taking over", oldPid, hb)
			_ = syscall.Kill(oldPid, syscall.SIGKILL)
			time.Sleep(300 * time.Millisecond)
		}
	}
	_ = os.MkdirAll(runDir, 0o755)
	return os.WriteFile(guardPidFile, []byte(strconv.Itoa(os.Getpid())), 0o644) == nil
}

func releaseLock() {
	if data, err := os.ReadFile(guardPidFile); err == nil {
		owner, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if owner == os.Getpid() {
			_ = os.Remove(guardPidFile)
		}
	}
}

func readHeartbeatAge() int64 {
	data, err := os.ReadFile(heartbeatFile)
	if err != nil {
		return -1
	}
	hb, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || hb <= 0 {
		return -1
	}
	return time.Now().Unix() - hb
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// ─── config + iface discovery ────────────────────────────────────────────

type Config struct {
	Iface          string `json:"iface"`
	DisableCapture bool   `json:"disable_capture"`
}

func readConfig() Config {
	var c Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c)
	return c
}

// getIface mirrors guard.sh's get_iface() priority:
//   1. config.iface (explicit override)
//   2. /data/local/hnc/run/hotspot_iface hint file (written by hotspotd)
//   3. built-in scan of likely AP-style iface names
//   4. default "wlan2"
func getIface() string {
	if c := readConfig(); c.Iface != "" {
		return c.Iface
	}
	if data, err := os.ReadFile(hotspotHintFile); err == nil {
		line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		if line != "" {
			return line
		}
	}
	for _, c := range []string{"wlan2", "ap0", "ap1", "swlan0", "wlan1", "rndis0"} {
		if _, err := os.Stat("/sys/class/net/" + c); err == nil {
			return c
		}
	}
	return "wlan2"
}

func ifaceExists(iface string) bool {
	if iface == "" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + iface)
	return err == nil
}

// ifaceReady: any of: operstate=up | IFF_UP flag | has IPv4 | has ARP clients | hotspot hint matches
func ifaceReady(iface string) bool {
	if !ifaceExists(iface) {
		return false
	}
	if ifaceUp(iface) {
		return true
	}
	if ifaceHasIPv4(iface) {
		return true
	}
	if ifaceHasArpClients(iface) {
		return true
	}
	if hotspotHintMatches(iface) {
		return true
	}
	return false
}

func ifaceUp(iface string) bool {
	if data, err := os.ReadFile("/sys/class/net/" + iface + "/operstate"); err == nil {
		op := strings.TrimSpace(string(data))
		if op == "up" {
			return true
		}
		// Android wlan2 often "unknown" while AF_PACKET works; check IFF_UP flag.
		if op == "unknown" {
			if fl, err := os.ReadFile("/sys/class/net/" + iface + "/flags"); err == nil {
				s := strings.TrimSpace(string(fl))
				s = strings.TrimPrefix(s, "0x")
				if v, err := strconv.ParseUint(s, 16, 64); err == nil && v&0x1 != 0 {
					return true
				}
			}
		}
	}
	return false
}

func ifaceHasIPv4(iface string) bool {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			return true
		}
	}
	return false
}

// ifaceHasArpClients reads /proc/net/arp and checks for non-zero MAC clients on iface.
func ifaceHasArpClients(iface string) bool {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if fields[5] == iface && fields[3] != "00:00:00:00:00:00" {
			return true
		}
	}
	return false
}

func hotspotHintMatches(iface string) bool {
	data, err := os.ReadFile(hotspotHintFile)
	if err != nil {
		return false
	}
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	return line != "" && line == iface
}

func ifaceReadyReason(iface string) string {
	op, _ := os.ReadFile("/sys/class/net/" + iface + "/operstate")
	carrier, _ := os.ReadFile("/sys/class/net/" + iface + "/carrier")
	ip4 := "no"
	if ifaceHasIPv4(iface) {
		ip4 = "yes"
	}
	arp := "no"
	if ifaceHasArpClients(iface) {
		arp = "yes"
	}
	hint, _ := os.ReadFile(hotspotHintFile)
	return fmt.Sprintf("operstate=%s carrier=%s ipv4=%s arp_clients=%s hint=%s",
		strings.TrimSpace(string(op)),
		strings.TrimSpace(string(carrier)),
		ip4, arp,
		strings.TrimSpace(string(hint)),
	)
}

// ─── waiting state JSON ──────────────────────────────────────────────────

type WaitingState struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   int64  `json:"generated_at"`
	Mode          string `json:"mode"`
	BlindReason   string `json:"blind_reason"`
	Interface     string `json:"interface"`
	Version       string `json:"version"`
}

func writeWaitingState(iface, reason string) {
	ws := WaitingState{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().Unix(),
		Mode:          "blind",
		BlindReason:   reason,
		Interface:     iface,
		Version:       version,
	}
	data, err := json.Marshal(&ws)
	if err != nil {
		return
	}
	tmp := dpiStateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, dpiStateFile)
}

// dpidReportsNetworkDown peeks dpi_state.json for the "network is down" hint
// produced by capture.go when the AF_PACKET socket lost its interface mid-flight.
func dpidReportsNetworkDown() bool {
	data, err := os.ReadFile(dpiStateFile)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "network is down")
}

// ─── netlink monitor ─────────────────────────────────────────────────────

// netlinkMonitor opens an AF_NETLINK socket on NETLINK_ROUTE, subscribes to
// link + ipv4/ipv6 address events, and emits filtered events to netlinkCh.
//
// Only events whose ifname matches the live hotspot iface from getIface()
// trigger emission, so wlan0 flapping or rndis events don't kick our wlan2
// dpid child. (This was the rc29.1/2 bug.)
func netlinkMonitor() {
	sock, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		logf("netlink socket: %v", err)
		return
	}
	defer syscall.Close(sock)

	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: 1<<(rtnlgrpLink-1) | 1<<(rtnlgrpIPv4IfAddr-1) | 1<<(rtnlgrpIPv6IfAddr-1),
	}
	if err := syscall.Bind(sock, addr); err != nil {
		logf("netlink bind: %v", err)
		return
	}
	logf("netlink monitor started")

	buf := make([]byte, 65536)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// Connection error or our socket got blown away. Brief backoff.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		hotspot := getIface()
		for i := range msgs {
			emitFromMsg(&msgs[i], hotspot)
		}
	}
}

// emitFromMsg parses one netlink message and emits to netlinkCh if its iface
// name matches the hotspot iface.
func emitFromMsg(m *syscall.NetlinkMessage, hotspot string) {
	var (
		name string
		kind string
		op   string
	)
	switch m.Header.Type {
	case syscall.RTM_NEWLINK:
		kind, op = "link", "new"
		name = ifNameFromLinkMsg(m)
	case syscall.RTM_DELLINK:
		kind, op = "link", "del"
		name = ifNameFromLinkMsg(m)
	case syscall.RTM_NEWADDR:
		kind, op = "addr", "new"
		name = ifNameFromAddrMsg(m)
	case syscall.RTM_DELADDR:
		kind, op = "addr", "del"
		name = ifNameFromAddrMsg(m)
	default:
		return
	}
	if name == "" || name != hotspot {
		return
	}
	select {
	case netlinkCh <- netlinkEvent{iface: name, kind: kind, op: op, raw: fmt.Sprintf("%s %s on %s", op, kind, name)}:
	default:
		// Channel full — events are coalesced anyway, drop.
	}
}

// ifNameFromLinkMsg extracts IFLA_IFNAME from a RTM_*LINK message.
func ifNameFromLinkMsg(m *syscall.NetlinkMessage) string {
	if len(m.Data) < syscall.SizeofIfInfomsg {
		return ""
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return ""
	}
	for _, a := range attrs {
		if a.Attr.Type == syscall.IFLA_IFNAME {
			return strings.TrimRight(string(a.Value), "\x00")
		}
	}
	return ""
}

// ifNameFromAddrMsg resolves ifindex from RTM_*ADDR's IfAddrmsg.Index to a name
// via net.InterfaceByIndex (which reads /sys/class/net).
func ifNameFromAddrMsg(m *syscall.NetlinkMessage) string {
	if len(m.Data) < syscall.SizeofIfAddrmsg {
		return ""
	}
	ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
	if ifam.Index == 0 {
		return ""
	}
	ifi, err := net.InterfaceByIndex(int(ifam.Index))
	if err != nil {
		return ""
	}
	return ifi.Name
}

// ─── child process management ────────────────────────────────────────────

// runChild forks hnc_dpid, redirects its stdout/stderr to dpid.log, and
// blocks until it exits or context conditions force a rebind.
//
// Returns true if we should immediately re-loop (rebind), false if we should
// shut down.
func runChild(iface string) bool {
	logf("launching hnc_dpid on iface=%s", iface)

	cmd := exec.Command(realBin, "-config", configPath)
	cmd.Env = os.Environ()
	// Open dpid.log fresh each launch so log rotation outside us still works.
	out, err := os.OpenFile(dpidChildLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		cmd.Stdout = out
		cmd.Stderr = out
		defer out.Close()
	} else {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	}
	// Put dpid into its own pgrp so killing it doesn't TERM us.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logf("failed to start hnc_dpid: %v", err)
		return true // try again
	}
	_ = os.WriteFile(childPidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	defer os.Remove(childPidFile)

	childStart := time.Now()
	lastRebind := time.Time{}

	// Goroutine: wait for child exit, signal via exitCh.
	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	periodicTicker := time.NewTicker(3 * time.Second)
	defer periodicTicker.Stop()

	killAndReap := func() {
		_ = cmd.Process.Kill()
		<-exitCh
	}

	for {
		select {
		case <-stopCh:
			killAndReap()
			return false

		case err := <-exitCh:
			if err != nil {
				logf("hnc_dpid exited: %v", err)
			} else {
				logf("hnc_dpid exited cleanly")
			}
			return true

		case ev := <-netlinkCh:
			age := time.Since(childStart)
			if age < graceDur {
				logf("ignore netlink event %s in startup grace (age=%v < %v)", ev.raw, age.Round(time.Millisecond), graceDur)
				continue
			}
			if !lastRebind.IsZero() && time.Since(lastRebind) < debounceDur {
				logf("debounce netlink event %s (last rebind %v ago)", ev.raw, time.Since(lastRebind).Round(time.Millisecond))
				continue
			}
			logf("netlink event %s for iface=%s, request immediate rebind", ev.raw, iface)
			lastRebind = time.Now()
			killAndReap()
			return true

		case <-periodicTicker.C:
			// Recheck iface health + dpid state.
			cur := getIface()
			if cur != iface {
				logf("hotspot iface changed mid-run: %s -> %s; rebind", iface, cur)
				killAndReap()
				return true
			}
			if !ifaceReady(iface) {
				logf("iface %s no longer ready; rebind (%s)", iface, ifaceReadyReason(iface))
				writeWaitingState(iface, "iface lost mid-run: "+ifaceReadyReason(iface))
				killAndReap()
				return true
			}
			if dpidReportsNetworkDown() {
				logf("dpi_state reports 'network is down'; restart immediately")
				killAndReap()
				return true
			}
		}
	}
}

// ─── main loop ───────────────────────────────────────────────────────────

func mainLoop() {
	fastDelays := []time.Duration{
		0, 100 * time.Millisecond, 200 * time.Millisecond,
		500 * time.Millisecond, 1 * time.Second,
		1500 * time.Millisecond, 2 * time.Second,
	}
	fastIdx := 0
	lastIface := ""

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		cfg := readConfig()
		iface := getIface()

		if !cfg.DisableCapture {
			if !ifaceExists(iface) {
				writeWaitingState(iface, "waiting for hotspot interface "+iface+" to appear")
				logf("iface %s missing; waiting", iface)
				if !sleepUntil(3 * time.Second) {
					return
				}
				continue
			}
			if !ifaceReady(iface) {
				writeWaitingState(iface, "waiting for "+iface+" to become usable: "+ifaceReadyReason(iface))
				d := 3 * time.Second
				if fastIdx < len(fastDelays) {
					d = fastDelays[fastIdx]
					fastIdx++
				}
				if !sleepUntil(d) {
					return
				}
				continue
			}
		}

		if iface != lastIface {
			logf("target iface changed: [%s] -> [%s]", lastIface, iface)
			lastIface = iface
		}
		fastIdx = 0

		// runChild blocks until exit/rebind/shutdown.
		if !runChild(iface) {
			return // shutdown requested
		}
		// Small damping after restart to avoid tight crash loops.
		if !sleepUntil(200 * time.Millisecond) {
			return
		}
	}
}

// sleepUntil sleeps d or returns early on stopCh. Returns false if stopCh fired.
func sleepUntil(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stopCh:
		return false
	case <-t.C:
		return true
	}
}

// ─── signal handling ─────────────────────────────────────────────────────

func handleSignals() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		sig := <-ch
		logf("received signal %v, shutting down", sig)
		stopOnce.Do(func() { close(stopCh) })
		// Give main loop a moment to clean up; force exit on second signal.
		go func() {
			<-ch
			logf("second signal, exiting forcefully")
			os.Exit(2)
		}()
	}()
}

// ─── entrypoint ──────────────────────────────────────────────────────────

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}

	openLog()
	logf("hnc_dpid_supervisor %s starting, pid=%d", version, os.Getpid())

	if !acquireLock() {
		os.Exit(0)
	}
	defer releaseLock()

	handleSignals()
	go heartbeatLoop()
	go netlinkMonitor()

	mainLoop()
	logf("supervisor exiting normally")
}
