// Package bytestats - Multi-map netd_shared eBPF detail sampler.
//
// Reads the Android netd_shared BPF map suite via read-only bpf(2) syscalls:
//   - /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map
//     KeySize=4 (uint32 uid), ValueSize>=32 (rxPackets, rxBytes, txPackets, txBytes).
//     Monotonically increasing since boot, never wiped/rotated (<0.2ms full scan).
//   - /sys/fs/bpf/netd_shared/map_netd_stats_map_A & map_netd_stats_map_B
//     KeySize=16 ({UID, Tag, CounterSet, IfaceIndex}), ValueSize>=32.
//     Only Tag==0 entries are counted; CounterSet==0 is background (DEFAULT),
//     CounterSet==1 is foreground (FOREGROUND).
//   - /sys/fs/bpf/netd_shared/map_netd_uid_counterset_map
//     KeySize=4 (uint32 uid), ValueSize=1 (uint8: 1=foreground, 0=background).
//   - /sys/fs/bpf/netd_shared/map_netd_iface_index_name_map
//     KeySize=4 (uint32 ifindex), ValueSize=16 (char name[IFNAMSIZ]), used to
//     exclude loopback/tunnel/CLAT duplicate-accounting interfaces (lo, tun*, v4-*).
//
// Every map is opened with BPF_F_RDONLY (1<<3) first (falling back to 0 on
// older kernels) and strictly validated via BPF_OBJ_GET_INFO_BY_FD before any
// lookup/iteration buffer is passed to the kernel.

package bytestats

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	NetdAppUIDStatsMapPath    = "/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map"
	NetdStatsMapAPath         = "/sys/fs/bpf/netd_shared/map_netd_stats_map_A"
	NetdStatsMapBPath         = "/sys/fs/bpf/netd_shared/map_netd_stats_map_B"
	NetdUIDCounterSetMapPath  = "/sys/fs/bpf/netd_shared/map_netd_uid_counterset_map"
	NetdIfaceIndexNameMapPath = "/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map"
)

var (
	altAppUIDStatsMapPaths = []string{
		NetdAppUIDStatsMapPath,
		"/sys/fs/bpf/tethering/map_netd_app_uid_stats_map",
	}
	altStatsMapAPaths = []string{
		NetdStatsMapAPath,
		"/sys/fs/bpf/tethering/map_netd_stats_map_A",
	}
	altStatsMapBPaths = []string{
		NetdStatsMapBPath,
		"/sys/fs/bpf/tethering/map_netd_stats_map_B",
	}
	altUIDCounterSetMapPaths = []string{
		NetdUIDCounterSetMapPath,
		"/sys/fs/bpf/tethering/map_netd_uid_counterset_map",
	}
	altIfaceIndexNameMapPaths = []string{
		NetdIfaceIndexNameMapPath,
		"/sys/fs/bpf/tethering/map_netd_iface_index_name_map",
	}
)

// netdDetailStatsKey matches AOSP struct stats_key (16 bytes: 4 * uint32).
type netdDetailStatsKey struct {
	UID        uint32
	Tag        uint32
	CounterSet uint32
	IfaceIndex uint32
}

// netdDetailValueBuf holds 64-bit packet/byte counters aligned to 8 bytes.
// Sized to 64 bytes to safely accommodate 32/40/48/64B stats_value schemas.
type netdDetailValueBuf struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
	Extra     [4]uint64
}

// NetdUIDDetail holds per-UID counters and live foreground/background state
// collected in a single pass across netd_shared BPF maps.
type NetdUIDDetail struct {
	// Total cumulative counters from map_netd_app_uid_stats_map (monotonic since boot).
	Total ByteCounts

	// Unarchived live counters from map_netd_stats_map_A + map_netd_stats_map_B
	// (Tag==0, excluding lo/tun*/v4-* duplicate-accounting interfaces).
	BgAll    ByteCounts
	FgAll    ByteCounts
	BgMobile ByteCounts
	FgMobile ByteCounts
	BgWiFi   ByteCounts
	FgWiFi   ByteCounts

	// Foreground reflects real-time state from map_netd_uid_counterset_map (counterSet == 1).
	Foreground bool
}

// NetdDetailSnapshot is a point-in-time snapshot read from netd_shared BPF maps.
type NetdDetailSnapshot struct {
	ByUID             map[int]NetdUIDDetail
	ForegroundUIDs    map[int]bool
	IfaceNames        map[uint32]string
	HasStatsAB        bool
	HasCounterSetMap  bool
	HasIfaceNameMap   bool
	StatsABTotalBytes uint64
}

// NetdDetailSampler reads netd_shared BPF maps with reusable, heap-pinned,
// 8-byte aligned buffers safe on both 32-bit ARMv7 and 64-bit ARM64.
type NetdDetailSampler struct {
	// Placed strictly at offset 0 with atomic.Uint64 alignment marker so Go's
	// allocator guarantees 8-byte alignment on 32-bit armeabi-v7a.
	_   [0]atomic.Uint64
	val netdDetailValueBuf

	// Heap-resident key/value buffers passed to bpf(2) syscalls.
	statsKey, statsNext netdDetailStatsKey
	uidKey, uidNext     uint32
	csVal               [8]byte
	ifaceNameBuf        [32]byte

	appUIDFD     int
	statsAFD     int
	statsBFD     int
	counterSetFD int
	ifaceNameFD  int
}

// Compile-time offset & alignment assertions (zero runtime cost).
var (
	_ [0 - int(unsafe.Offsetof(NetdDetailSampler{}.val))]byte
	_ [8 - int(unsafe.Alignof(NetdDetailSampler{}))]byte
	_ [int(unsafe.Alignof(NetdDetailSampler{})) - 8]byte
)

func validDetailAppUIDSchema(keySz, valSz uint32) bool {
	return keySz == 4 && valSz >= 32 && valSz <= uint32(unsafe.Sizeof(netdDetailValueBuf{})) && valSz%8 == 0
}

func validDetailStatsABSchema(keySz, valSz uint32) bool {
	return keySz == uint32(unsafe.Sizeof(netdDetailStatsKey{})) &&
		valSz >= 32 && valSz <= uint32(unsafe.Sizeof(netdDetailValueBuf{})) && valSz%8 == 0
}

func validDetailCounterSetSchema(keySz, valSz uint32) bool {
	return keySz == 4 && (valSz == 1 || valSz == 4)
}

func validDetailIfaceNameSchema(keySz, valSz uint32) bool {
	return keySz == 4 && valSz >= 16 && valSz <= 32
}

func openValidatedNetdMap(candidates []string, checkSchema func(keySz, valSz uint32) bool) (int, error) {
	var lastErr error
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			continue
		}
		fd, err := bpfObjGetReadonlyCall(path)
		if err != nil {
			lastErr = fmt.Errorf("bpf(BPF_OBJ_GET, %s): %w", path, err)
			continue
		}
		info, err := bpfObjGetInfoCall(fd)
		if err != nil {
			_ = syscall.Close(fd)
			lastErr = fmt.Errorf("bpf(BPF_OBJ_GET_INFO_BY_FD, %s): %w", path, err)
			continue
		}
		if !checkSchema(info.KeySize, info.ValueSize) {
			_ = syscall.Close(fd)
			lastErr = fmt.Errorf("bpf schema mismatch at %s: key=%d value=%d", path, info.KeySize, info.ValueSize)
			continue
		}
		return fd, nil
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return -1, lastErr
}

// NewNetdDetailSampler opens map_netd_app_uid_stats_map (required) and best-effort
// companion maps (stats_map_A/B, uid_counterset_map, iface_index_name_map) in
// read-only mode, validating every map's KeySize and ValueSize via BPF_OBJ_GET_INFO_BY_FD.
func NewNetdDetailSampler() (*NetdDetailSampler, error) {
	appFD, err := openValidatedNetdMap(altAppUIDStatsMapPaths, validDetailAppUIDSchema)
	if err != nil {
		return nil, err
	}
	s := &NetdDetailSampler{
		appUIDFD:     appFD,
		statsAFD:     -1,
		statsBFD:     -1,
		counterSetFD: -1,
		ifaceNameFD:  -1,
	}
	if fd, err := openValidatedNetdMap(altStatsMapAPaths, validDetailStatsABSchema); err == nil {
		s.statsAFD = fd
	}
	if fd, err := openValidatedNetdMap(altStatsMapBPaths, validDetailStatsABSchema); err == nil {
		s.statsBFD = fd
	}
	if fd, err := openValidatedNetdMap(altUIDCounterSetMapPaths, validDetailCounterSetSchema); err == nil {
		s.counterSetFD = fd
	}
	if fd, err := openValidatedNetdMap(altIfaceIndexNameMapPaths, validDetailIfaceNameSchema); err == nil {
		s.ifaceNameFD = fd
	}
	return s, nil
}

// Close releases all open BPF map file descriptors held by the sampler.
func (s *NetdDetailSampler) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	closeOne := func(fd *int) {
		if *fd > 0 {
			if err := syscall.Close(*fd); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		*fd = -1
	}
	closeOne(&s.appUIDFD)
	closeOne(&s.statsAFD)
	closeOne(&s.statsBFD)
	closeOne(&s.counterSetFD)
	closeOne(&s.ifaceNameFD)
	return firstErr
}

// ShouldExcludeNetdIface returns true for loopback, VPN tunnels, CLAT464xlat,
// and virtual interfaces whose byte counters would double-count physical traffic.
func ShouldExcludeNetdIface(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if name == "lo" || name == "Meta" {
		return true
	}
	for _, pfx := range []string{
		"tun",
		"v4-",
		"tap",
		"ppp",
		"wg",
		"ipsec",
		"xfrm",
		"tailscale",
		"utun",
		"sing_tun",
		"dummy",
		"r_rmnet",
		"rmnet_ipa",
		"rmnet_mhi",
	} {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	return false
}

// ClassifyNetdIface classifies a physical Android network interface into
// "mobile", "wifi", or "other".
func ClassifyNetdIface(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || ShouldExcludeNetdIface(name) {
		return "other"
	}
	for _, pfx := range []string{
		"rmnet_data",
		"rmnet",
		"ccmni",
		"seth_",
		"sipa_eth",
		"gti",
		"wwan",
	} {
		if strings.HasPrefix(name, pfx) {
			return "mobile"
		}
	}
	if name == "wlan0" || strings.HasPrefix(name, "wlan") {
		return "wifi"
	}
	return "other"
}

func isRealAppOrSystemUID(uid uint32) bool {
	// Exclude kernel sentinel UIDs such as -1 (0xffffffff) and -5 (UID_TETHERING).
	return uid <= 100_000_000
}

func addByteCounts(dst *ByteCounts, val netdDetailValueBuf) {
	dst.RxPackets += val.RxPackets
	dst.RxBytes += val.RxBytes
	dst.TxPackets += val.TxPackets
	dst.TxBytes += val.TxBytes
}

func (s *NetdDetailSampler) readIfaceNameMap() map[uint32]string {
	out := make(map[uint32]string, 16)
	if s.ifaceNameFD <= 0 {
		return out
	}
	s.uidKey, s.uidNext = 0, 0
	first := true
	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(&s.uidKey)
		}
		err := bpfMapGetNextKeyCall(s.ifaceNameFD, keyPtr, unsafe.Pointer(&s.uidNext))
		if err == syscall.ENOENT || err != nil {
			break
		}
		s.ifaceNameBuf = [32]byte{}
		if err := bpfMapLookupElemCall(s.ifaceNameFD, unsafe.Pointer(&s.uidNext), unsafe.Pointer(&s.ifaceNameBuf[0])); err == nil {
			raw := s.ifaceNameBuf[:]
			if idx := bytes.IndexByte(raw, 0); idx >= 0 {
				raw = raw[:idx]
			}
			if name := strings.TrimSpace(string(raw)); name != "" {
				out[s.uidNext] = name
			}
		}
		s.uidKey = s.uidNext
		first = false
	}
	return out
}

func (s *NetdDetailSampler) readCounterSetMap() map[int]bool {
	out := make(map[int]bool, 32)
	if s.counterSetFD <= 0 {
		return out
	}
	s.uidKey, s.uidNext = 0, 0
	first := true
	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(&s.uidKey)
		}
		err := bpfMapGetNextKeyCall(s.counterSetFD, keyPtr, unsafe.Pointer(&s.uidNext))
		if err == syscall.ENOENT || err != nil {
			break
		}
		if isRealAppOrSystemUID(s.uidNext) {
			s.csVal = [8]byte{}
			if err := bpfMapLookupElemCall(s.counterSetFD, unsafe.Pointer(&s.uidNext), unsafe.Pointer(&s.csVal[0])); err == nil {
				if s.csVal[0] == 1 {
					out[int(s.uidNext)] = true
				}
			}
		}
		s.uidKey = s.uidNext
		first = false
	}
	return out
}

func (s *NetdDetailSampler) accumulateStatsMap(fd int, ifaceNames map[uint32]string, byUID map[int]NetdUIDDetail) uint64 {
	if fd <= 0 {
		return 0
	}
	var totalBytes uint64
	s.statsKey, s.statsNext = netdDetailStatsKey{}, netdDetailStatsKey{}
	first := true
	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(&s.statsKey)
		}
		err := bpfMapGetNextKeyCall(fd, keyPtr, unsafe.Pointer(&s.statsNext))
		if err == syscall.ENOENT || err != nil {
			break
		}
		k := s.statsNext
		// Only count Tag==0 (root UID bucket; non-zero tags duplicate Tag==0)
		// and CounterSet in {0 (DEFAULT/background), 1 (FOREGROUND)}.
		if k.Tag != 0 || k.CounterSet > 1 || !isRealAppOrSystemUID(k.UID) {
			s.statsKey = s.statsNext
			first = false
			continue
		}

		ifName, ok := ifaceNames[k.IfaceIndex]
		if !ok && k.IfaceIndex > 0 {
			ifName = lookupSysfsIfaceNameByIndex(k.IfaceIndex)
			ifaceNames[k.IfaceIndex] = ifName
		}
		if ShouldExcludeNetdIface(ifName) {
			s.statsKey = s.statsNext
			first = false
			continue
		}

		s.val = netdDetailValueBuf{}
		if err := bpfMapLookupElemCall(fd, unsafe.Pointer(&s.statsNext), unsafe.Pointer(&s.val)); err != nil {
			s.statsKey = s.statsNext
			first = false
			continue
		}
		val := s.val
		totalBytes += val.RxBytes + val.TxBytes

		uid := int(k.UID)
		det := byUID[uid]
		netKind := ClassifyNetdIface(ifName)
		if k.CounterSet == 1 {
			addByteCounts(&det.FgAll, val)
			switch netKind {
			case "mobile":
				addByteCounts(&det.FgMobile, val)
			case "wifi":
				addByteCounts(&det.FgWiFi, val)
			}
		} else {
			addByteCounts(&det.BgAll, val)
			switch netKind {
			case "mobile":
				addByteCounts(&det.BgMobile, val)
			case "wifi":
				addByteCounts(&det.BgWiFi, val)
			}
		}
		byUID[uid] = det

		s.statsKey = s.statsNext
		first = false
	}
	return totalBytes
}

// SampleDetail performs a single sub-millisecond read across all open netd BPF maps.
func (s *NetdDetailSampler) SampleDetail() (*NetdDetailSnapshot, error) {
	if s == nil || s.appUIDFD <= 0 {
		return nil, fmt.Errorf("netd detail sampler closed")
	}

	byUID := make(map[int]NetdUIDDetail, 256)

	// 1. Read monotonic per-UID totals from map_netd_app_uid_stats_map (KeySize=4).
	s.uidKey, s.uidNext = 0, 0
	first := true
	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(&s.uidKey)
		}
		err := bpfMapGetNextKeyCall(s.appUIDFD, keyPtr, unsafe.Pointer(&s.uidNext))
		if err == syscall.ENOENT {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY, app_uid_stats): %w", err)
		}
		if isRealAppOrSystemUID(s.uidNext) {
			s.val = netdDetailValueBuf{}
			if err := bpfMapLookupElemCall(s.appUIDFD, unsafe.Pointer(&s.uidNext), unsafe.Pointer(&s.val)); err == nil {
				uid := int(s.uidNext)
				det := byUID[uid]
				addByteCounts(&det.Total, s.val)
				byUID[uid] = det
			}
		}
		s.uidKey = s.uidNext
		first = false
	}

	// 2. Read interface index -> name map.
	ifaceNames := s.readIfaceNameMap()

	// 3. Read current foreground/background counterSet map.
	fgUIDs := s.readCounterSetMap()

	// 4. Read live unarchived foreground/background per-iface counters from stats_map_A/B.
	var abTotal uint64
	hasAB := s.statsAFD > 0 || s.statsBFD > 0
	if s.statsAFD > 0 {
		abTotal += s.accumulateStatsMap(s.statsAFD, ifaceNames, byUID)
	}
	if s.statsBFD > 0 {
		abTotal += s.accumulateStatsMap(s.statsBFD, ifaceNames, byUID)
	}

	// 5. Stamp real-time foreground state onto all observed UIDs.
	for uid := range fgUIDs {
		det := byUID[uid]
		det.Foreground = true
		byUID[uid] = det
	}

	return &NetdDetailSnapshot{
		ByUID:             byUID,
		ForegroundUIDs:    fgUIDs,
		IfaceNames:        ifaceNames,
		HasStatsAB:        hasAB,
		HasCounterSetMap:  s.counterSetFD > 0,
		HasIfaceNameMap:   s.ifaceNameFD > 0,
		StatsABTotalBytes: abTotal,
	}, nil
}

// ReadNetdForegroundUIDs opens map_netd_uid_counterset_map transiently in
// read-only mode, collects all UIDs currently in foreground (counterSet == 1),
// and closes the fd immediately (0 resident file descriptors).
func ReadNetdForegroundUIDs() (map[int]bool, bool) {
	fd, err := openValidatedNetdMap(altUIDCounterSetMapPaths, validDetailCounterSetSchema)
	if err != nil || fd <= 0 {
		return nil, false
	}
	tmp := &NetdDetailSampler{
		appUIDFD:     -1,
		statsAFD:     -1,
		statsBFD:     -1,
		counterSetFD: fd,
		ifaceNameFD:  -1,
	}
	defer tmp.Close()
	return tmp.readCounterSetMap(), true
}

func lookupSysfsIfaceNameByIndex(target uint32) string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	want := strconv.FormatUint(uint64(target), 10)
	for _, e := range entries {
		name := e.Name()
		raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifindex"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(raw)) == want {
			return name
		}
	}
	return ""
}
