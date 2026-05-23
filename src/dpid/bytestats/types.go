// Package bytestats provides per-uid network byte statistics, with
// pluggable backends to support a range of Android versions.
//
// Backends, in preference order:
//
//   1. eBPF: read /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map
//      directly via the bpf(2) syscall. Available on Android 12+ (most
//      devices shipped after 2021). Real-time, ~zero CPU cost.
//
//   2. dumpsys: parse `dumpsys netstats detail` output. Available on
//      any Android with a system_server (i.e. all of them). Slower
//      (~200ms per fork) and parsing is somewhat fragile, but works
//      as a universal fallback.
//
// detect.go chooses the best available backend at startup. If neither
// works, returns a NoneSampler that reports zeros — dpid keeps running
// fine, the UI just doesn't show byte data.
//
// Design notes:
//
//   - All backends report CUMULATIVE byte counters per uid (since
//     reboot, typically). Delta computation is done in self_attrib.go's
//     RecordBytes by diffing against the previous sample.
//
//   - We aggregate across (iface, set=FOREGROUND/DEFAULT, tag) — the
//     UI shows "this uid used X bytes period", not split by network
//     class or fg/bg state. Future refinement could expose this split,
//     but for v5.7.0 keep it simple.
//
//   - The Sample() call is meant to be ~5s ticks. Backends that need
//     more time (dumpsys) internally rate-limit if called faster.
package bytestats

// ByteCounts is the cumulative byte/packet counters for one uid since
// boot. All fields are uint64 because Android counters easily exceed
// 2 GB on long-running devices.
type ByteCounts struct {
	RxBytes   uint64
	RxPackets uint64
	TxBytes   uint64
	TxPackets uint64
}

// ByteSampler is the unified backend interface.
//
// Implementations:
//   - eBPFSampler (sampler_ebpf.go, linux only)
//   - DumpsysSampler (sampler_dumpsys.go)
//   - NoneSampler (detect.go, no-op fallback)
//
// Sample returns a snapshot of cumulative per-uid counters. The map
// key is uid (0 = root, 1000 = system, 10000+ = user apps). uid == -1
// or other special values are filtered out — only real uids appear.
//
// Source returns a stable identifier of which backend is active, used
// in dpi_state.json so the UI can show data freshness expectations.
// Values: "ebpf", "dumpsys", "none".
type ByteSampler interface {
	Sample() (map[int]ByteCounts, error)
	Source() string
	Close() error
}
