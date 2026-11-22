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
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// tetheringMapCandidates lists pinned BPF stats maps across Android 12–16 Mainline.
var tetheringMapCandidates = []string{
	"/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_A",
	"/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_B",
	"/sys/fs/bpf/tethering/map_netd_app_uid_stats_map",
	"/sys/fs/bpf/tethering/map_netd_stats_map_A",
	"/sys/fs/bpf/tethering/map_netd_stats_map_B",
	"/sys/fs/bpf/tethering/map_offload_tether_stats_map",
}

// TetheringStatsSampler reads AOSP Mainline tethering stats from a pinned BPF map.
type TetheringStatsSampler struct {
	// Placed at offset 0 for 8-byte alignment of uint64 counters on 32-bit ARM.
	val tetheringStatsValue

	// Heap-resident bpf(2) key buffers sized to max 24B key variant (v5.12 + v6.0.0).
	key, next tetheringStatsKey

	fd        int
	keySize   uint32
	valueSize uint32
	path      string
}

// tetheringStatsKey accommodates 16, 20, or 24 byte Mainline Tethering BPF keys.
// First uint32 carries uid / client key; trailing words hold tag/counterSet/ifindex/etc.
type tetheringStatsKey struct {
	UID uint32
	Ext [5]uint32 // total = 24 bytes (>= max supported keySize 24)
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

// discoverTetheringMap finds the AOSP tethering stats BPF map path.
// Tries known Mainline paths first, then falls back to glob-based discovery
// (excluding limit/quota control maps whose schema is unrelated to byte stats).
func discoverTetheringMap() (string, error) {
	for _, p := range tetheringMapCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
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
			base := strings.ToLower(filepath.Base(cand))
			if strings.Contains(base, "limit") {
				continue
			}
			return cand, nil
		}
	}
	return "", fmt.Errorf("tethering stats map not found")
}

// NewTetheringStatsSampler opens the AOSP Mainline tethering stats BPF map and
// validates its keySize (16/20/24) and valueSize (32/40/48).
func NewTetheringStatsSampler() (*TetheringStatsSampler, error) {
	path, err := discoverTetheringMap()
	if err != nil {
		return nil, err
	}
	fd, err := bpfObjGetCall(path)
	if err != nil {
		return nil, fmt.Errorf("bpf(BPF_OBJ_GET, %s): %w", path, err)
	}

	info, err := bpfObjGetInfoCall(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bpf(BPF_OBJ_GET_INFO_BY_FD, %s): %w", path, err)
	}
	if !validTetheringKeySize(info.KeySize) || !validTetheringValueSize(info.ValueSize) {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf(
			"tethering map schema mismatch at %s: key=%d (want 16/20/24) value=%d (want 32/40/48) — refusing to guess uid layout",
			path, info.KeySize, info.ValueSize)
	}
	return &TetheringStatsSampler{
		fd:        fd,
		keySize:   info.KeySize,
		valueSize: info.ValueSize,
		path:      path,
	}, nil
}

func (s *TetheringStatsSampler) Source() string { return "tethering_bpf" }

func (s *TetheringStatsSampler) Close() error {
	if s.fd > 0 {
		err := syscall.Close(s.fd)
		s.fd = 0
		return err
	}
	return nil
}

// Sample iterates the tethering stats map and aggregates per uid.
func (s *TetheringStatsSampler) Sample() (map[int]ByteCounts, error) {
	if s.fd <= 0 {
		return nil, fmt.Errorf("sampler closed")
	}
	out := make(map[int]ByteCounts, 64)

	key, next := &s.key, &s.next
	*key, *next = tetheringStatsKey{}, tetheringStatsKey{}
	first := true

	for {
		var keyPtr unsafe.Pointer
		if first {
			keyPtr = nil // NULL key → start at first entry
		} else {
			keyPtr = unsafe.Pointer(key)
		}
		err := bpfMapGetNextKeyCall(s.fd, keyPtr, unsafe.Pointer(next))
		if err == syscall.ENOENT {
			break // end of map
		}
		if err != nil {
			// EINVAL on first iteration = kernel rejected key layout.
			return out, fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY): %w", err)
		}

		s.val = tetheringStatsValue{}
		err = bpfMapLookupElemCall(s.fd, unsafe.Pointer(next), unsafe.Pointer(&s.val))
		val := s.val
		if err != nil {
			*key = *next
			first = false
			continue
		}

		// Filter out special negative sentinel UIDs (-1 / -5 cast to uint32 > 100_000_000)
		// safely on both 32-bit ARM and 64-bit ARM64 before converting to int.
		if next.UID > 100_000_000 {
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

	return out, nil
}

// bpfMapInfo is the struct returned by BPF_OBJ_GET_INFO_BY_FD for maps.
type bpfMapInfo struct {
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

// bpfObjGetInfoCall wraps BPF_OBJ_GET_INFO_BY_FD (cmd 15).
func bpfObjGetInfoCall(fd int) (*bpfMapInfo, error) {
	info := new(bpfMapInfo)
	attrBuf := struct {
		BPFFD   uint32
		InfoLen uint32
		InfoPtr uint64
	}{BPFFD: uint32(fd), InfoLen: uint32(unsafe.Sizeof(*info)), InfoPtr: uint64(uintptr(unsafe.Pointer(info)))}
	var pad [128]byte
	binary.NativeEndian.PutUint32(pad[0:4], attrBuf.BPFFD)
	binary.NativeEndian.PutUint32(pad[4:8], attrBuf.InfoLen)
	binary.NativeEndian.PutUint64(pad[8:16], attrBuf.InfoPtr)

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&pad)),
		unsafe.Sizeof(attrBuf),
	)
	runtime.KeepAlive(info)
	runtime.KeepAlive(&pad)
	if errno != 0 {
		return nil, errno
	}
	return info, nil
}
