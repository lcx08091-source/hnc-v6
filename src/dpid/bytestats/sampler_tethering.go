// Package bytestats - AOSP Mainline tethering stats BPF map backend.
//
// v6.0.0 Vector 修复:
//   - Android 14–16 Mainline Tethering APEX 模块演进后, 统计 BPF map 的
//     key_size 出现 16 / 20 / 24 字节变体, value_size 出现 32 / 40 / 48 字节变体;
//     旧版写死 16/32 导致 Android 16 (如 ColorOS 16 / Kernel 6.6) 上直接校验失败、
//     退化为每 5 秒拉起高开销的 `dumpsys netstats detail` 子进程。
//   - 缓冲区按最大兼容尺寸 24B Key / 48B Value 置于堆结构体上(严防内核 bpf(2) 越界写栈/堆),
//     并兼容 16/20/24 × 32/40/48 的合法 Mainline schema 组合; 非法尺寸或首轮 EINVAL
//     仍安全拒绝并回退。

package bytestats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type tetheringMapPair struct {
	pathA string
	pathB string
}

// tetheringMapPairs lists active/standby Mainline per-UID stats map pairs across Android 12–16.
// Deliberately excludes map_offload_tether_stats_map whose 4-byte key is upstream ifindex, NOT UID.
var tetheringMapPairs = []tetheringMapPair{
	{
		pathA: "/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_A",
		pathB: "/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_B",
	},
	{
		pathA: "/sys/fs/bpf/tethering/map_netd_stats_map_A",
		pathB: "/sys/fs/bpf/tethering/map_netd_stats_map_B",
	},
	{
		pathA: "/sys/fs/bpf/netd_shared/map_netd_stats_map_A",
		pathB: "/sys/fs/bpf/netd_shared/map_netd_stats_map_B",
	},
}

// TetheringStatsSampler reads AOSP Mainline per-UID stats from pinned A/B BPF maps.
type TetheringStatsSampler struct {
	// Placed at offset 0 with atomic.Uint64 8-byte alignment guarantee on 32-bit ARM.
	_   [0]atomic.Uint64
	val tetheringStatsValue

	// Heap-resident bpf(2) key/name buffers sized to max 24B key variant (v5.12 + v6.0.0).
	key, next    tetheringStatsKey
	ifaceKey     uint32
	ifaceNext    uint32
	ifaceNameBuf [32]byte

	fd          int
	fdB         int
	ifaceNameFD int
	keySize     uint32
	valueSize   uint32
	path        string
	pathB       string
	ifaceCache  map[uint32]string
}

// tetheringStatsKey accommodates 16, 20, or 24 byte Mainline Tethering/netd BPF keys:
// {UID, Tag, CounterSet, IfaceIndex} followed by optional trailing words.
type tetheringStatsKey struct {
	UID        uint32
	Tag        uint32
	CounterSet uint32
	IfaceIndex uint32
	Ext        [2]uint32 // total = 24 bytes (>= max supported keySize 24)
}

// tetheringStatsValue accommodates 32, 40, or 48 byte Mainline stats values.
// First 4×uint64 match AOSP stats_value (rxPackets, rxBytes, txPackets, txBytes);
// Extra0/Extra1 absorb optional error/timestamp counters on 40B and 48B maps.
type tetheringStatsValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
	Extra0    uint64
	Extra1    uint64
}

func validTetheringKeySize(sz uint32) bool {
	return sz == 16 || sz == 20 || sz == 24
}

func validTetheringValueSize(sz uint32) bool {
	return sz == 32 || sz == 40 || sz == 48
}

func isForbiddenTetheringMapBase(base string) bool {
	return strings.Contains(base, "limit") ||
		strings.Contains(base, "offload") ||
		strings.Contains(base, "app_uid") ||
		strings.Contains(base, "iface") ||
		strings.Contains(base, "counterset") ||
		strings.Contains(base, "cookie") ||
		strings.Contains(base, "uid_owner") ||
		strings.Contains(base, "uid_permission")
}

func openValidatedTetheringFD(path string) (int, *bpfMapInfo, error) {
	if path == "" {
		return -1, nil, os.ErrNotExist
	}
	if _, err := os.Stat(path); err != nil {
		return -1, nil, err
	}
	fd, err := bpfObjGetCall(path)
	if err != nil {
		return -1, nil, fmt.Errorf("bpf(BPF_OBJ_GET, %s): %w", path, err)
	}
	info, err := bpfObjGetInfoCall(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return -1, nil, fmt.Errorf("bpf(BPF_OBJ_GET_INFO_BY_FD, %s): %w", path, err)
	}
	if !validTetheringKeySize(info.KeySize) || !validTetheringValueSize(info.ValueSize) {
		_ = syscall.Close(fd)
		return -1, nil, fmt.Errorf(
			"tethering map schema mismatch at %s: key=%d (want 16/20/24) value=%d (want 32/40/48) — refusing to guess uid layout",
			path, info.KeySize, info.ValueSize)
	}
	return fd, info, nil
}

// discoverTetheringMapPairs returns candidate (A, B) map path pairs, excluding
// offload_tether_stats_map (4B upstream ifindex key) and quota/limit control maps.
func discoverTetheringMapPairs() []tetheringMapPair {
	out := make([]tetheringMapPair, 0, len(tetheringMapPairs)+2)
	seen := make(map[string]bool, 8)
	for _, pair := range tetheringMapPairs {
		seen[pair.pathA] = true
		seen[pair.pathB] = true
		out = append(out, pair)
	}
	for _, pat := range []string{
		"/sys/fs/bpf/tethering/*stats*",
		"/sys/fs/bpf/*tether*stats*",
	} {
		entries, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, cand := range entries {
			if seen[cand] {
				continue
			}
			base := strings.ToLower(filepath.Base(cand))
			if isForbiddenTetheringMapBase(base) {
				continue
			}
			sibling := ""
			if strings.HasSuffix(cand, "_A") {
				sibling = strings.TrimSuffix(cand, "_A") + "_B"
			} else if strings.HasSuffix(cand, "_B") {
				sibling = strings.TrimSuffix(cand, "_B") + "_A"
			}
			seen[cand] = true
			if sibling != "" {
				seen[sibling] = true
			}
			out = append(out, tetheringMapPair{pathA: cand, pathB: sibling})
		}
	}
	return out
}

// NewTetheringStatsSampler opens AOSP Mainline A/B stats BPF maps, validates
// keySize (16/20/24) and valueSize (32/40/48), and attaches iface_index_name_map if available.
func NewTetheringStatsSampler() (*TetheringStatsSampler, error) {
	var lastErr error
	for _, pair := range discoverTetheringMapPairs() {
		fdA, infoA, errA := openValidatedTetheringFD(pair.pathA)
		fdB, infoB, errB := openValidatedTetheringFD(pair.pathB)
		if fdA < 0 && fdB < 0 {
			if errA != nil && !os.IsNotExist(errA) {
				lastErr = errA
			} else if errB != nil && !os.IsNotExist(errB) {
				lastErr = errB
			}
			continue
		}
		s := &TetheringStatsSampler{
			fd:          -1,
			fdB:         -1,
			ifaceNameFD: -1,
			ifaceCache:  make(map[uint32]string, 16),
		}
		if fdA >= 0 {
			s.fd = fdA
			s.keySize = infoA.KeySize
			s.valueSize = infoA.ValueSize
			s.path = pair.pathA
			if fdB >= 0 {
				if infoB.KeySize == infoA.KeySize && infoB.ValueSize == infoA.ValueSize {
					s.fdB = fdB
					s.pathB = pair.pathB
				} else {
					_ = syscall.Close(fdB)
				}
			}
		} else {
			s.fd = fdB
			s.keySize = infoB.KeySize
			s.valueSize = infoB.ValueSize
			s.path = pair.pathB
		}
		if ifFD, err := openValidatedNetdMap(altIfaceIndexNameMapPaths, validDetailIfaceNameSchema); err == nil {
			s.ifaceNameFD = ifFD
		}
		return s, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tethering stats map not found")
	}
	return nil, lastErr
}

func (s *TetheringStatsSampler) Source() string { return "tethering_bpf" }

func (s *TetheringStatsSampler) Close() error {
	var firstErr error
	closeFD := func(fd *int) {
		if *fd > 0 {
			if err := syscall.Close(*fd); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		*fd = -1
	}
	closeFD(&s.fd)
	closeFD(&s.fdB)
	closeFD(&s.ifaceNameFD)
	return firstErr
}

func (s *TetheringStatsSampler) readIfaceNames() map[uint32]string {
	out := make(map[uint32]string, 16)
	if s.ifaceNameFD <= 0 {
		return out
	}
	s.ifaceKey, s.ifaceNext = 0, 0
	first := true
	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(&s.ifaceKey)
		}
		if err := bpfMapGetNextKeyCall(s.ifaceNameFD, keyPtr, unsafe.Pointer(&s.ifaceNext)); err != nil {
			break
		}
		s.ifaceNameBuf = [32]byte{}
		if err := bpfMapLookupElemCall(s.ifaceNameFD, unsafe.Pointer(&s.ifaceNext), unsafe.Pointer(&s.ifaceNameBuf[0])); err == nil {
			raw := s.ifaceNameBuf[:]
			if idx := bytes.IndexByte(raw, 0); idx >= 0 {
				raw = raw[:idx]
			}
			if name := strings.TrimSpace(string(raw)); name != "" {
				out[s.ifaceNext] = name
				if s.ifaceCache != nil {
					s.ifaceCache[s.ifaceNext] = name
				}
				putCachedNetdIfaceName(s.ifaceNext, name)
			}
		}
		s.ifaceKey = s.ifaceNext
		first = false
	}
	return out
}

func (s *TetheringStatsSampler) resolveIfaceName(ifindex uint32, ifaceNames map[uint32]string, missed map[uint32]bool) string {
	if ifindex == 0 {
		return ""
	}
	if name := ifaceNames[ifindex]; name != "" {
		return name
	}
	if s.ifaceCache != nil {
		if name := s.ifaceCache[ifindex]; name != "" {
			ifaceNames[ifindex] = name
			return name
		}
	}
	if name, ok := getCachedNetdIfaceName(ifindex); ok && name != "" {
		if s.ifaceCache != nil {
			s.ifaceCache[ifindex] = name
		}
		ifaceNames[ifindex] = name
		return name
	}
	if missed[ifindex] {
		return ""
	}
	if ifc, err := net.InterfaceByIndex(int(ifindex)); err == nil && ifc != nil {
		if name := strings.TrimSpace(ifc.Name); name != "" {
			ifaceNames[ifindex] = name
			if s.ifaceCache != nil {
				s.ifaceCache[ifindex] = name
			}
			putCachedNetdIfaceName(ifindex, name)
			return name
		}
	}
	if name := strings.TrimSpace(lookupSysfsIfaceNameByIndex(ifindex)); name != "" {
		ifaceNames[ifindex] = name
		if s.ifaceCache != nil {
			s.ifaceCache[ifindex] = name
		}
		putCachedNetdIfaceName(ifindex, name)
		return name
	}
	missed[ifindex] = true
	return ""
}

func (s *TetheringStatsSampler) accumulateFD(fd int, hasIfaceMap bool, ifaceNames map[uint32]string, missed map[uint32]bool, out map[int]ByteCounts) error {
	if fd <= 0 {
		return nil
	}
	key, next := &s.key, &s.next
	*key, *next = tetheringStatsKey{}, tetheringStatsKey{}
	first := true

	for {
		var keyPtr unsafe.Pointer
		if !first {
			keyPtr = unsafe.Pointer(key)
		}
		err := bpfMapGetNextKeyCall(fd, keyPtr, unsafe.Pointer(next))
		if err == syscall.ENOENT {
			break
		}
		if err != nil {
			return fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY): %w", err)
		}

		// Filter sentinel UIDs (-1 / -5), non-zero socket tags (which duplicate Tag==0),
		// and invalid CounterSet (>1; only 0=DEFAULT and 1=FOREGROUND are valid).
		if next.UID > 100_000_000 || next.Tag != 0 || next.CounterSet > 1 {
			*key = *next
			first = false
			continue
		}

		ifName := s.resolveIfaceName(next.IfaceIndex, ifaceNames, missed)
		if next.IfaceIndex > 0 && ifName == "" && hasIfaceMap {
			*key = *next
			first = false
			continue
		}
		if ShouldExcludeNetdIface(ifName) {
			*key = *next
			first = false
			continue
		}

		s.val = tetheringStatsValue{}
		err = bpfMapLookupElemCall(fd, unsafe.Pointer(next), unsafe.Pointer(&s.val))
		val := s.val
		if err != nil {
			*key = *next
			first = false
			continue
		}

		uid := int(next.UID)
		bc := out[uid]
		bc.RxBytes += val.RxBytes
		bc.RxPackets += val.RxPackets
		bc.TxBytes += val.TxBytes
		bc.TxPackets += val.TxPackets
		out[uid] = bc

		*key = *next
		first = false
	}
	return nil
}

// Sample iterates stats_map_A + stats_map_B (when both present) and aggregates per uid.
func (s *TetheringStatsSampler) Sample() (map[int]ByteCounts, error) {
	if s.fd <= 0 {
		return nil, fmt.Errorf("sampler closed")
	}
	out := make(map[int]ByteCounts, 64)
	hasIfaceMap := s.ifaceNameFD > 0
	ifaceNames := s.readIfaceNames()
	missed := make(map[uint32]bool, 4)

	if err := s.accumulateFD(s.fd, hasIfaceMap, ifaceNames, missed, out); err != nil {
		return out, err
	}
	if s.fdB > 0 {
		if err := s.accumulateFD(s.fdB, hasIfaceMap, ifaceNames, missed, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

// bpfMapInfo is the struct returned by BPF_OBJ_GET_INFO_BY_FD for maps.
type bpfMapInfo struct {
	_                 [0]atomic.Uint64
	Type              uint32
	ID                uint32
	KeySize           uint32
	ValueSize         uint32
	MaxEntries        uint32
	MapFlags          uint32
	Name              [16]byte
	IfIndex           uint32
	BtfVmlinuxValueID uint32
	NetnsDev          uint64
	NetnsIno          uint64
	BtfID             uint32
	BtfKeyTypeID      uint32
	BtfValueTypeID    uint32
}

var (
	_ [0 - int(unsafe.Offsetof(TetheringStatsSampler{}.val))]byte
	_ [8 - int(unsafe.Alignof(TetheringStatsSampler{}))]byte
	_ [int(unsafe.Alignof(TetheringStatsSampler{})) - 8]byte
	_ [8 - int(unsafe.Alignof(bpfMapInfo{}))]byte
	_ [int(unsafe.Alignof(bpfMapInfo{})) - 8]byte
)

// bpfObjGetInfoCall wraps BPF_OBJ_GET_INFO_BY_FD (cmd 15).
func bpfObjGetInfoCall(fd int) (*bpfMapInfo, error) {
	info := new(bpfMapInfo)
	attrBuf := struct {
		BPFFD   uint32
		InfoLen uint32
		InfoPtr uint64
	}{BPFFD: uint32(fd), InfoLen: uint32(unsafe.Sizeof(*info)), InfoPtr: uint64(uintptr(unsafe.Pointer(info)))}
	var buf bpfAttrBuf
	binary.NativeEndian.PutUint32(buf.pad[0:4], attrBuf.BPFFD)
	binary.NativeEndian.PutUint32(buf.pad[4:8], attrBuf.InfoLen)
	binary.NativeEndian.PutUint64(buf.pad[8:16], attrBuf.InfoPtr)

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&buf.pad[0])),
		unsafe.Sizeof(attrBuf),
	)
	runtime.KeepAlive(info)
	runtime.KeepAlive(&buf)
	if errno != 0 {
		return nil, errno
	}
	return info, nil
}
