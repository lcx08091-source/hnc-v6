// Package bytestats - eBPF backend.
//
// Reads /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map via raw
// bpf(2) syscalls. Map is created by netd/Connectivity Mainline at boot on
// Android 12+.
//
// Real-device verified schema on Android 12–16:
//   - map_netd_app_uid_stats_map:
//     KeySize = 4 (uint32_t uid only — NO tag/counterSet/ifaceIndex),
//     ValueSize >= 32 (struct stats_value { uint64_t rxPackets, rxBytes, txPackets, txBytes; }),
//     monotonically increasing since boot and never rotated/wiped (<0.2ms full scan).
//   - Per-(uid, tag, counterSet, ifaceIndex) 16-byte keys live in
//     map_netd_stats_map_A and map_netd_stats_map_B (see netd_detail_ebpf.go).
//
// We deliberately don't pull in github.com/cilium/ebpf — for this
// narrow use case (open pinned map + info check + iterate + lookup), the raw
// syscall version is compact and zero-dependency.
//
// Permission model on Android:
//   - File at /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map
//   - Mode 0060 owned by root:net_bw_acct (group-only access)
//   - SELinux type fs_bpf_net_shared / fs_bpf_tethering
//   - Opened with BPF_F_RDONLY (1<<3) first (falling back to 0 on older kernels).
//   - Root (CAP_DAC_OVERRIDE) bypasses DAC; Magisk/KernelSU/APatch root domain
//     passes MAC. If either gate fails, BPF_OBJ_GET returns EACCES and we fall
//     back to dumpsys.
//
// Reference: https://source.android.com/docs/core/data/traffic-counters

package bytestats

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	bpfMapPath          = "/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map"
	bpfTetherAppMapPath = "/sys/fs/bpf/tethering/map_netd_app_uid_stats_map"

	// bpf() syscall number: per-arch constant sysBPF in sysbpf_<arch>.go
	// (v5.22: arm64 = 280, arm EABI = 386, amd64 = 321, 386 = 357).

	// bpf() commands.
	bpfMapLookupElem  = 1
	bpfMapGetNextKey  = 4
	bpfObjGet         = 7
	bpfObjGetInfoByFD = 15 // v5.9.7: BPF map schema 校验用

	// bpfFileFlagRdonly is Linux UAPI BPF_F_RDONLY (1U << 3) for read-only map fds.
	bpfFileFlagRdonly uint32 = 1 << 3
)

var bpfAppUIDMapCandidates = []string{
	bpfMapPath,
	bpfTetherAppMapPath,
}

// netdStatsKey holds the heap key buffer passed to bpf(2).
// For map_netd_app_uid_stats_map (KeySize=4), the kernel reads/writes only UID;
// trailing words are kept for defensive heap buffer slack.
type netdStatsKey struct {
	UID uint32
	Ext [5]uint32
}

// netdStatsValue holds the heap value buffer (up to 64B to safely absorb
// 32/40/48/64-byte Mainline stats_value variants without kernel overwrite).
type netdStatsValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
	Extra     [4]uint64
}

// EBPFSampler implements ByteSampler against map_netd_app_uid_stats_map.
type EBPFSampler struct {
	// 严格置于偏移 0 处并附带 atomic.Uint64 对齐标记, 确保 32 位 armeabi-v7a
	// 下堆分配起始地址与 64 位计数字段均按 8 字节边界对齐, 防止未对齐 panic/SIGBUS。
	_   [0]atomic.Uint64
	val netdStatsValue

	// 传给 bpf(2) 的 key/next/val 缓冲区放在堆分配的 sampler 结构体里,
	// 避免栈扩容搬迁导致内核按旧地址越界读写。
	key, next netdStatsKey
	fd        int
	keySize   uint32
	valueSize uint32
}

func validAppUIDMapKeySize(sz uint32) bool {
	return sz == 4
}

func validStatsValueSize(sz uint32) bool {
	return sz >= 32 && sz <= uint32(unsafe.Sizeof(netdStatsValue{})) && sz%8 == 0
}

// NewEBPFSampler opens the pinned BPF map (preferring BPF_F_RDONLY across
// netd_shared and tethering Mainline paths) and verifies KeySize==4 and ValueSize.
func NewEBPFSampler() (*EBPFSampler, error) {
	var lastErr error
	for _, path := range bpfAppUIDMapCandidates {
		if _, err := os.Stat(path); err != nil {
			lastErr = fmt.Errorf("bpf map not found: %w", err)
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
		if !validAppUIDMapKeySize(info.KeySize) || !validStatsValueSize(info.ValueSize) {
			_ = syscall.Close(fd)
			lastErr = fmt.Errorf("app_uid_stats_map schema mismatch at %s: key=%d (want 4) value=%d (want 32..64)",
				path, info.KeySize, info.ValueSize)
			continue
		}
		return &EBPFSampler{
			fd:        fd,
			keySize:   info.KeySize,
			valueSize: info.ValueSize,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("bpf map not found")
	}
	return nil, lastErr
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

// Sample iterates map_netd_app_uid_stats_map and aggregates per uid.
// With KeySize=4 (1 entry per uid), a full pass typically completes in <0.2ms.
func (s *EBPFSampler) Sample() (map[int]ByteCounts, error) {
	if s.fd <= 0 {
		return nil, fmt.Errorf("sampler closed")
	}
	out := make(map[int]ByteCounts, 256)

	key, next := &s.key, &s.next // v5.12: 堆上缓冲区, 见结构体注释
	*key, *next = netdStatsKey{}, netdStatsKey{}
	first := true

	for {
		var keyPtr unsafe.Pointer
		if first {
			keyPtr = nil // BPF_MAP_GET_NEXT_KEY with NULL = start at first
		} else {
			keyPtr = unsafe.Pointer(key)
		}
		err := bpfMapGetNextKeyCall(s.fd, keyPtr, unsafe.Pointer(next))
		if err == syscall.ENOENT {
			// End of map.
			break
		}
		if err != nil {
			return out, fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY): %w", err)
		}

		s.val = netdStatsValue{}
		err = bpfMapLookupElemCall(s.fd, unsafe.Pointer(next), unsafe.Pointer(&s.val))
		val := s.val
		if err != nil {
			*key = *next
			first = false
			continue
		}

		// Filter out special negative sentinel UIDs (-1 / -5 cast to uint32 > 100_000_000)
		// before casting to int so 32-bit ARM and 64-bit ARM64 behave identically.
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

// ─── raw bpf(2) syscall wrappers ─────────────────────────────────────

// bpfAttrBuf 为 bpf(2) 系统调用提供严格 8 字节对齐的 union bpf_attr 原始缓冲区。
// 同时包含 [0]atomic.Uint64 与 [0]uint64, 确保在 32 位 ARM 与 64 位架构上均按 8 字节对齐。
type bpfAttrBuf struct {
	_   [0]atomic.Uint64
	_   [0]uint64
	pad [120]byte
}

// 编译期偏移与对齐断言(零运行时开销): 若 32 位/64 位下偏移偏离 0 或对齐不足 8 字节则直接拒绝编译。
var (
	_ [0 - int(unsafe.Offsetof(EBPFSampler{}.val))]byte
	_ [0 - int(unsafe.Offsetof(bpfAttrBuf{}.pad))]byte
	_ [8 - int(unsafe.Alignof(EBPFSampler{}))]byte
	_ [int(unsafe.Alignof(EBPFSampler{})) - 8]byte
	_ [8 - int(unsafe.Alignof(bpfAttrBuf{}))]byte
	_ [int(unsafe.Alignof(bpfAttrBuf{})) - 8]byte
)

// bpfAttrObjGet matches union bpf_attr { struct { ... } obj_get; } in
// Linux kernel uapi/linux/bpf.h.
type bpfAttrObjGet struct {
	Pathname  uint64 // user pointer to NUL-terminated path
	BPFFD     uint32
	FileFlags uint32
}

func bpfObjGetWithFlagsCall(path string, fileFlags uint32) (int, error) {
	cptr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	attr := bpfAttrObjGet{
		Pathname:  uint64(uintptr(unsafe.Pointer(cptr))),
		FileFlags: fileFlags,
	}
	var buf bpfAttrBuf
	binary.NativeEndian.PutUint64(buf.pad[0:8], attr.Pathname)
	binary.NativeEndian.PutUint32(buf.pad[8:12], attr.BPFFD)
	binary.NativeEndian.PutUint32(buf.pad[12:16], attr.FileFlags)

	r1, _, errno := syscall.Syscall(
		sysBPF,
		bpfObjGet,
		uintptr(unsafe.Pointer(&buf.pad[0])),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(cptr)
	runtime.KeepAlive(&buf)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// bpfObjGetReadonlyCall opens a pinned BPF map with BPF_F_RDONLY (1<<3) first,
// falling back to flags=0 if the kernel rejects file_flags.
func bpfObjGetReadonlyCall(path string) (int, error) {
	fd, err := bpfObjGetWithFlagsCall(path, bpfFileFlagRdonly)
	if err == nil {
		return fd, nil
	}
	if err == syscall.ENOENT || err == syscall.ENOTDIR {
		return -1, err
	}
	if fdRw, errRw := bpfObjGetWithFlagsCall(path, 0); errRw == nil {
		return fdRw, nil
	}
	return -1, err
}

func bpfObjGetCall(path string) (int, error) {
	return bpfObjGetReadonlyCall(path)
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
	var buf bpfAttrBuf
	binary.NativeEndian.PutUint32(buf.pad[0:4], attr.MapFD)
	binary.NativeEndian.PutUint64(buf.pad[8:16], attr.Key)
	binary.NativeEndian.PutUint64(buf.pad[16:24], attr.Value)
	binary.NativeEndian.PutUint64(buf.pad[24:32], attr.Flags)

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapLookupElem,
		uintptr(unsafe.Pointer(&buf.pad[0])),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	runtime.KeepAlive(&buf)
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
	var buf bpfAttrBuf
	binary.NativeEndian.PutUint32(buf.pad[0:4], attr.MapFD)
	binary.NativeEndian.PutUint64(buf.pad[8:16], attr.Key)
	binary.NativeEndian.PutUint64(buf.pad[16:24], attr.Value)

	_, _, errno := syscall.Syscall(
		sysBPF,
		bpfMapGetNextKey,
		uintptr(unsafe.Pointer(&buf.pad[0])),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(nextKey)
	runtime.KeepAlive(&buf)
	if errno != 0 {
		return errno
	}
	return nil
}
