// Package bytestats - eBPF backend.
//
// Reads /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map via raw
// bpf(2) syscalls. Map is created by netd at boot on Android 12+, and
// keyed by (uid, tag, counterSet, ifaceIndex). We aggregate by uid.
//
// We deliberately don't pull in github.com/cilium/ebpf — for this
// narrow use case (open pinned map + iterate + lookup), the raw syscall
// version is ~80 lines of focused code without an extra dependency.
//
// Map schema (defined in AOSP system/netd/bpf_progs/bpf_net_helpers.h):
//
//	struct stats_key { uint32_t uid, tag, counterSet, ifaceIndex; }  // 16 B
//	struct stats_value { uint64_t rxPackets, rxBytes, txPackets, txBytes; }  // 32 B
//
// Permission model on Android:
//   - File at /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map
//   - Mode 0060 owned by root:net_bw_acct (group-only access)
//   - SELinux type fs_bpf_net_shared
//   - Root (CAP_DAC_OVERRIDE) bypasses DAC; SukiSU's `su:s0` domain
//     typically passes MAC. If either gate fails, BPF_OBJ_GET returns
//     EACCES and we fall back to dumpsys.
//
// Reference: https://source.android.com/docs/core/data/traffic-counters
//            (Android's official cookbook for reading this exact map)

package bytestats

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	bpfMapPath = "/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map"

	// bpf() syscall numbers per Linux ABI. arm64 = 280, amd64 = 321.
	// We only target arm64 (Android), so hardcode.
	sysBPF_arm64 = 280

	// bpf() commands.
	bpfMapLookupElem  = 1
	bpfMapGetNextKey  = 4
	bpfObjGet         = 7
)

// netdStatsKey is the key struct of the BPF map. Layout matches AOSP's
// definition byte-for-byte (4×uint32, native endianness).
type netdStatsKey struct {
	UID        uint32
	Tag        uint32
	CounterSet uint32
	IfaceIndex uint32
}

// netdStatsValue is the value struct (4×uint64).
type netdStatsValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
}

// EBPFSampler implements ByteSampler against the netd BPF map.
type EBPFSampler struct {
	fd int
}

// NewEBPFSampler opens the pinned BPF map. Returns an error if the map
// doesn't exist (older Android), if the kernel rejects bpf(2) entirely,
// or if SELinux/DAC blocks us. detect.go interprets all such errors as
// "fall back to dumpsys".
func NewEBPFSampler() (*EBPFSampler, error) {
	// Quick pre-check: does the file even exist? Saves us from issuing
	// a bpf() syscall just to get ENOENT.
	if _, err := os.Stat(bpfMapPath); err != nil {
		return nil, fmt.Errorf("bpf map not found: %w", err)
	}

	fd, err := bpfObjGetCall(bpfMapPath)
	if err != nil {
		return nil, fmt.Errorf("bpf(BPF_OBJ_GET, %s): %w", bpfMapPath, err)
	}
	return &EBPFSampler{fd: fd}, nil
}

func (s *EBPFSampler) Source() string { return "ebpf" }

func (s *EBPFSampler) Close() error {
	if s.fd > 0 {
		err := syscall.Close(s.fd)
		s.fd = 0
		return err
	}
	return nil
}

// Sample iterates the entire map and aggregates per uid. Each iteration
// does one BPF_MAP_GET_NEXT_KEY + one BPF_MAP_LOOKUP_ELEM. Map size is
// typically <2000 entries (one per active uid×iface×set combination),
// so the whole pass is sub-millisecond.
func (s *EBPFSampler) Sample() (map[int]ByteCounts, error) {
	if s.fd <= 0 {
		return nil, fmt.Errorf("sampler closed")
	}
	out := make(map[int]ByteCounts, 256)

	var key netdStatsKey
	var next netdStatsKey
	first := true

	for {
		var keyPtr unsafe.Pointer
		if first {
			keyPtr = nil // BPF_MAP_GET_NEXT_KEY with NULL = start at first
		} else {
			keyPtr = unsafe.Pointer(&key)
		}
		err := bpfMapGetNextKeyCall(s.fd, keyPtr, unsafe.Pointer(&next))
		if err == syscall.ENOENT {
			// End of map.
			break
		}
		if err != nil {
			return out, fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY): %w", err)
		}

		var val netdStatsValue
		err = bpfMapLookupElemCall(s.fd, unsafe.Pointer(&next), unsafe.Pointer(&val))
		if err != nil {
			// Could be that the entry was deleted between get_next_key
			// and lookup. Skip and continue.
			key = next
			first = false
			continue
		}

		uid := int(next.UID)
		// uid -5 (-1 cast to uint32 → 4294967291) is "unknown" / special.
		// Filter out non-real uids: -1, -5 (>4 billion when interpreted unsigned).
		if uid < 0 || uid > 100000000 {
			key = next
			first = false
			continue
		}

		bc := out[uid]
		bc.RxBytes += val.RxBytes
		bc.RxPackets += val.RxPackets
		bc.TxBytes += val.TxBytes
		bc.TxPackets += val.TxPackets
		out[uid] = bc

		key = next
		first = false
	}

	return out, nil
}

// ─── raw bpf(2) syscall wrappers ─────────────────────────────────────

// bpfAttrObjGet matches union bpf_attr { struct { ... } obj_get; } in
// Linux kernel uapi/linux/bpf.h. Size is fixed at 12 bytes (8+4 padded).
//
// Actually the kernel's bpf_attr union is the LARGEST member's size,
// but for this command we only need to set Pathname and Flags. To
// satisfy the kernel ABI check, we pad to the full union size by
// declaring a larger buffer.
type bpfAttrObjGet struct {
	Pathname  uint64 // user pointer to NUL-terminated path
	BPFFD     uint32
	FileFlags uint32
}

func bpfObjGetCall(path string) (int, error) {
	cpath := append([]byte(path), 0) // NUL-terminate
	attr := bpfAttrObjGet{
		Pathname: uint64(uintptr(unsafe.Pointer(&cpath[0]))),
	}
	// We need the syscall to see the full union size. Padding to 128 B
	// (current largest bpf_attr member as of Linux 6.x) is safe.
	var pad [128]byte
	binary.NativeEndian.PutUint64(pad[0:8], attr.Pathname)
	binary.NativeEndian.PutUint32(pad[8:12], attr.BPFFD)
	binary.NativeEndian.PutUint32(pad[12:16], attr.FileFlags)

	r1, _, errno := syscall.Syscall(
		sysBPF_arm64,
		bpfObjGet,
		uintptr(unsafe.Pointer(&pad[0])),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// bpfAttrMapElem matches the map_elem sub-union for LOOKUP/GET_NEXT_KEY.
type bpfAttrMapElem struct {
	MapFD uint32
	_pad  uint32
	Key   uint64 // pointer
	Value uint64 // pointer (for LOOKUP) or NextKey pointer (for GET_NEXT_KEY)
	Flags uint64
}

func bpfMapLookupElemCall(mapFD int, key, value unsafe.Pointer) error {
	attr := bpfAttrMapElem{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(key)),
		Value: uint64(uintptr(value)),
	}
	var pad [128]byte
	binary.NativeEndian.PutUint32(pad[0:4], attr.MapFD)
	binary.NativeEndian.PutUint64(pad[8:16], attr.Key)
	binary.NativeEndian.PutUint64(pad[16:24], attr.Value)
	binary.NativeEndian.PutUint64(pad[24:32], attr.Flags)

	_, _, errno := syscall.Syscall(
		sysBPF_arm64,
		bpfMapLookupElem,
		uintptr(unsafe.Pointer(&pad[0])),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func bpfMapGetNextKeyCall(mapFD int, key, nextKey unsafe.Pointer) error {
	var keyPtr uint64
	if key != nil {
		keyPtr = uint64(uintptr(key))
	}
	attr := bpfAttrMapElem{
		MapFD: uint32(mapFD),
		Key:   keyPtr,
		Value: uint64(uintptr(nextKey)), // overloaded: holds next_key pointer
	}
	var pad [128]byte
	binary.NativeEndian.PutUint32(pad[0:4], attr.MapFD)
	binary.NativeEndian.PutUint64(pad[8:16], attr.Key)
	binary.NativeEndian.PutUint64(pad[16:24], attr.Value)

	_, _, errno := syscall.Syscall(
		sysBPF_arm64,
		bpfMapGetNextKey,
		uintptr(unsafe.Pointer(&pad[0])),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
