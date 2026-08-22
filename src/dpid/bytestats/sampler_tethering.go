// Package bytestats - AOSP tethering stats BPF map backend.
//
// 回移自 5.9.91 分叉 + v5.9.7 护栏。分叉版假设 map key 前 4 字节是 uid,
// 但真实 AOSP Tethering map 的 key 布局随 Android 版本变化(已知变体之一是
// ifindex+MAC, 共 12 字节)—— 假设错误时会把热点转发字节静默记到假 uid
// (如系统 uid 5/1000), 污染 per-app 归因。护栏:
//  1. 构造时 BPF_OBJ_GET_INFO 校验实际 key_size/value_size(预期 16/32),
//     不符即构造失败 → detect.go 自动落 dumpsys;
//  2. Sample 首次 GET_NEXT_KEY EINVAL(内核拒读布局)同样视为不可用。
// 因此该 backend 在 schema 不符的设备上会安全自禁用, 绝不出脏数据。

package bytestats

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// tetheringMapCandidates are the well-known pinned map paths for AOSP
// tethering stats. The exact name depends on the BPF program variant
// loaded by the Tethering module, which varies across Android versions.
var tetheringMapCandidates = []string{
	"/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_A",
	"/sys/fs/bpf/tethering/map_tethering_stats_stats_value_map_B",
}

// TetheringStatsSampler reads AOSP tethering stats from a BPF map.
type TetheringStatsSampler struct {
	fd   int
	path string
}

// tetheringStatsKey is the map key. Layout is 16 bytes; the first 4
// bytes carry a uid or client identifier (uint32). The exact schema
// varies by Android version, but the value struct is stable.
type tetheringStatsKey struct {
	UID  uint32
	_pad [12]byte // remaining key bytes (iface/counter/etc., ignored for aggregation)
}

// tetheringStatsValue is the map value: 4×uint64 counters, same layout
// as netdStatsValue.
type tetheringStatsValue struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
}

// discoverTetheringMap finds the AOSP tethering stats BPF map path.
// Tries known paths first, then falls back to glob-based discovery.
func discoverTetheringMap() (string, error) {
	for _, p := range tetheringMapCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	entries, err := filepath.Glob("/sys/fs/bpf/tethering/*stats*")
	if err == nil && len(entries) > 0 {
		return entries[0], nil
	}
	entries, err = filepath.Glob("/sys/fs/bpf/*tether*stats*")
	if err == nil && len(entries) > 0 {
		return entries[0], nil
	}
	return "", fmt.Errorf("tethering stats map not found")
}

// NewTetheringStatsSampler opens the AOSP tethering stats BPF map.
// Returns an error if the map cannot be found or opened (permissions,
// kernel too old, etc.). detect.go treats all errors as "try next backend".
func NewTetheringStatsSampler() (*TetheringStatsSampler, error) {
	path, err := discoverTetheringMap()
	if err != nil {
		return nil, err
	}
	fd, err := bpfObjGetCall(path)
	if err != nil {
		return nil, fmt.Errorf("bpf(BPF_OBJ_GET, %s): %w", path, err)
	}

	// v5.9.7 护栏: 校验 map 实际 key/value 尺寸, 与我们的解析假设不符
	// 时拒绝构造 —— 宁可不用, 也不把 ifindex 当 uid 污染归因。
	info, err := bpfObjGetInfoCall(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bpf(BPF_OBJ_GET_INFO_BY_FD, %s): %w", path, err)
	}
	const (
		wantKeySize   = 16 // tetheringStatsKey
		wantValueSize = 32 // tetheringStatsValue
	)
	if info.KeySize != wantKeySize || info.ValueSize != wantValueSize {
		syscall.Close(fd)
		return nil, fmt.Errorf(
			"tethering map schema mismatch at %s: key=%d (want %d) value=%d (want %d) — refusing to guess uid layout",
			path, info.KeySize, wantKeySize, info.ValueSize, wantValueSize)
	}
	return &TetheringStatsSampler{fd: fd, path: path}, nil
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

	var key tetheringStatsKey
	var next tetheringStatsKey
	first := true

	for {
		var keyPtr unsafe.Pointer
		if first {
			keyPtr = nil // NULL key → start at first entry
		} else {
			keyPtr = unsafe.Pointer(&key)
		}
		err := bpfMapGetNextKeyCall(s.fd, keyPtr, unsafe.Pointer(&next))
		if err == syscall.ENOENT {
			break // end of map
		}
		if err != nil {
			// EINVAL 在首轮 = 内核拒读该 key 布局 —— 返回错误让上层
			// 放弃本后端, 而不是吐出空数据冒充成功。
			return out, fmt.Errorf("bpf(BPF_MAP_GET_NEXT_KEY): %w", err)
		}

		var val tetheringStatsValue
		err = bpfMapLookupElemCall(s.fd, unsafe.Pointer(&next), unsafe.Pointer(&val))
		if err != nil {
			key = next
			first = false
			continue
		}

		uid := int(next.UID)
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

// bpfObjGetInfoCall wraps BPF_OBJ_GET_INFO_BY_FD (cmd 15)。
// 与 bpfObjGetCall 同款 128B pad 直写 syscall 形态。
func bpfObjGetInfoCall(fd int) (*bpfMapInfo, error) {
	info := bpfMapInfo{}
	attrBuf := struct {
		BPFFD   uint32
		InfoLen uint32
		InfoPtr uint64
	}{BPFFD: uint32(fd), InfoLen: uint32(unsafe.Sizeof(info)), InfoPtr: uint64(uintptr(unsafe.Pointer(&info)))}
	var pad [128]byte
	binary.NativeEndian.PutUint32(pad[0:4], attrBuf.BPFFD)
	binary.NativeEndian.PutUint32(pad[4:8], attrBuf.InfoLen)
	binary.NativeEndian.PutUint64(pad[8:16], attrBuf.InfoPtr)

	_, _, errno := syscall.Syscall(
		sysBPF_arm64,
		bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&pad[0])),
		unsafe.Sizeof(attrBuf),
	)
	if errno != 0 {
		return nil, errno
	}
	return &info, nil
}
