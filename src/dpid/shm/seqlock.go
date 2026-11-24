// Package shm implements a 16KB page-aligned dual-slot seqcount_latch shared
// memory snapshot at /data/local/hnc/run/shm_vector.bin for HNC v6.1.0 Vector.
//
// Design invariants:
//   - Fixed 16384-byte binary layout (matches Android 16 16KB page alignment):
//     [0..64)       Top-level latch header (Magic "HNCVSHM1", Version=3, layout tags, active seq)
//     [64..8224)    Latch Slot 0 (64B slot header + 126*64B devices + 24B pad + 8B EndSeq)
//     [8224..16384) Latch Slot 1 (64B slot header + 126*64B devices + 24B pad + 8B EndSeq)
//   - Linux/Android uses syscall.Mmap(MAP_SHARED); non-Linux or mmap-unsupported
//     filesystems gracefully fall back to atomic pread/pwrite (os.File.ReadAt/WriteAt).
//   - All 64-bit fields reside strictly at offset % 8 == 0 boundaries for 32-bit ARMv7 safety,
//     and readers issue stack-local atomic RMW full memory barriers on ARM64/ARMv7.
package shm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	Magic         = "HNCVSHM1"
	legacyMagicV1 = "HNCV6SHM"

	SchemaVersion uint32 = 3
	Version       uint32 = SchemaVersion
	EndianTag     uint32 = 0x01020304

	FileSize = 16384

	HeaderSize     = 64
	SlotSize       = (FileSize - HeaderSize) / 2 // 8160 bytes per latch slot
	PayloadSize    = SlotSize
	SlotHeaderSize = 64
	DeviceSlotSize = 64
	MaxDevices     = 126
	slotEndSeqOff  = SlotSize - 8 // 8152 (8152 % 8 == 0)

	DefaultRunDir   = "/data/local/hnc/run"
	DefaultFileName = "shm_vector.bin"
)

// Per-device bit flags stored in DeviceSlot.Flags.
const (
	FlagOnline  uint32 = 1 << 0
	FlagIPv4    uint32 = 1 << 1
	FlagIPv6    uint32 = 1 << 2
	FlagLeakHit uint32 = 1 << 3
)

var (
	ErrBadMagic       = errors.New("shm: invalid magic header")
	ErrShortRegion    = errors.New("shm: short shared memory region")
	ErrBadSize        = ErrShortRegion
	ErrSchemaMismatch = errors.New("shm: schema version or layout mismatch")
	ErrClosed         = errors.New("shm: handle closed")
	ErrUninitialized  = errors.New("shm: snapshot not yet published")
	ErrFault          = errors.New("shm: mmap bus fault")
)

var hostLittleEndian = func() bool {
	var v uint16 = 1
	return *(*byte)(unsafe.Pointer(&v)) == 1
}()

func loadU64(buf []byte, off int, useAtomic bool) uint64 {
	if useAtomic && hostLittleEndian && off >= 0 && off+8 <= len(buf) {
		ptr := unsafe.Pointer(&buf[off])
		if uintptr(ptr)&7 == 0 {
			return atomic.LoadUint64((*uint64)(ptr))
		}
	}
	return binary.LittleEndian.Uint64(buf[off : off+8])
}

func storeU64(buf []byte, off int, val uint64, useAtomic bool) {
	if useAtomic && hostLittleEndian && off >= 0 && off+8 <= len(buf) {
		ptr := unsafe.Pointer(&buf[off])
		if uintptr(ptr)&7 == 0 {
			atomic.StoreUint64((*uint64)(ptr), val)
			return
		}
	}
	binary.LittleEndian.PutUint64(buf[off:off+8], val)
}

func loadU32(buf []byte, off int, useAtomic bool) uint32 {
	if useAtomic && hostLittleEndian && off >= 0 && off+4 <= len(buf) {
		ptr := unsafe.Pointer(&buf[off])
		if uintptr(ptr)&3 == 0 {
			return atomic.LoadUint32((*uint32)(ptr))
		}
	}
	return binary.LittleEndian.Uint32(buf[off : off+4])
}

func storeU32(buf []byte, off int, val uint32, useAtomic bool) {
	if useAtomic && hostLittleEndian && off >= 0 && off+4 <= len(buf) {
		ptr := unsafe.Pointer(&buf[off])
		if uintptr(ptr)&3 == 0 {
			atomic.StoreUint32((*uint32)(ptr), val)
			return
		}
	}
	binary.LittleEndian.PutUint32(buf[off:off+4], val)
}

func validateFileHeader(hdr []byte, useAtomic bool) error {
	if len(hdr) < HeaderSize {
		return fmt.Errorf("%w (%w): header len %d < %d", ErrShortRegion, ErrSchemaMismatch, len(hdr), HeaderSize)
	}
	if hdr[0] != Magic[0] || hdr[1] != Magic[1] || hdr[2] != Magic[2] || hdr[3] != Magic[3] ||
		hdr[4] != Magic[4] || hdr[5] != Magic[5] || hdr[6] != Magic[6] || hdr[7] != Magic[7] {
		if string(hdr[0:8]) == legacyMagicV1 {
			return fmt.Errorf("%w: legacy v1 magic %q", ErrSchemaMismatch, legacyMagicV1)
		}
		return ErrBadMagic
	}
	ver := loadU32(hdr, 8, useAtomic)
	activeSlot := loadU32(hdr, 12, useAtomic)
	devCount := loadU32(hdr, 44, useAtomic)
	hdrSize := binary.LittleEndian.Uint16(hdr[52:54])
	devSlotSize := binary.LittleEndian.Uint16(hdr[54:56])
	slotSize := loadU32(hdr, 56, useAtomic)
	endianTag := loadU32(hdr, 60, useAtomic)

	if ver != SchemaVersion ||
		hdrSize != HeaderSize ||
		devSlotSize != DeviceSlotSize ||
		slotSize != SlotSize ||
		endianTag != EndianTag ||
		activeSlot > 1 ||
		devCount > MaxDevices {
		return fmt.Errorf(
			"%w: ver=%d hdr=%d devSlot=%d slot=%d endian=0x%08x active=%d devs=%d",
			ErrSchemaMismatch, ver, hdrSize, devSlotSize, slotSize, endianTag, activeSlot, devCount,
		)
	}
	return nil
}

// FilePath resolves the canonical shm_vector.bin path for a given runDir.
func FilePath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, DefaultFileName)
}

// Header represents the top-level metadata of a Vector shared memory snapshot.
// All 64-bit fields sit at offset % 8 == 0 on both 64-bit and 32-bit architectures.
type Header struct {
	Magic          [8]byte
	Seq            uint64
	UpdatedMonoNs  int64
	UpdatedUnixNs  int64
	TotalLeaks     uint64
	Version        uint32
	SlotSize       uint32
	EndianTag      uint32
	ActiveSlot     uint32
	ActiveFlows    uint32
	HostFlows      uint32
	DeviceCount    uint32
	Flags          uint32
	HeaderSize     uint16
	DeviceSlotSize uint16
	_pad           uint32
}

// DeviceSlot is one fixed-layout downstream client record in the snapshot body.
// 64-bit byte counters sit at offset 0 and 8 so array strides stay 8-byte aligned on ARMv7.
type DeviceSlot struct {
	RxBytes     uint64
	TxBytes     uint64
	ActiveFlows uint32
	Flags       uint32
	MAC         [6]byte
	IPv4        [4]byte
	IPv6        [16]byte
	_pad        [6]byte
}

// MACString formats the 6-byte hardware address as lowercase colon-separated hex.
func (d DeviceSlot) MACString() string {
	const hexDigits = "0123456789abcdef"
	if d.MAC == ([6]byte{}) {
		return ""
	}
	var out [17]byte
	for i := 0; i < 6; i++ {
		out[i*3] = hexDigits[d.MAC[i]>>4]
		out[i*3+1] = hexDigits[d.MAC[i]&0x0f]
		if i < 5 {
			out[i*3+2] = ':'
		}
	}
	return string(out[:])
}

// IPv4String formats IPv4 if non-zero, otherwise returns "".
func (d DeviceSlot) IPv4String() string {
	if d.IPv4 == ([4]byte{}) {
		return ""
	}
	return net.IPv4(d.IPv4[0], d.IPv4[1], d.IPv4[2], d.IPv4[3]).String()
}

// IPv6String formats IPv6 if non-zero, otherwise returns "".
func (d DeviceSlot) IPv6String() string {
	if d.IPv6 == ([16]byte{}) {
		return ""
	}
	return net.IP(d.IPv6[:]).String()
}

// Snapshot holds a complete zero-allocation decoded view of shm_vector.bin.
type Snapshot struct {
	Header  Header
	Devices [MaxDevices]DeviceSlot
}

// ValidDevices returns the populated prefix of Devices bounded by MaxDevices.
func (s *Snapshot) ValidDevices() []DeviceSlot {
	n := int(s.Header.DeviceCount)
	if n < 0 {
		return s.Devices[:0]
	}
	if n > MaxDevices {
		n = MaxDevices
	}
	return s.Devices[:n]
}

// ParseMAC parses a colon- or hyphen-separated MAC string into 6 raw bytes.
func ParseMAC(s string) ([6]byte, bool) {
	var out [6]byte
	s = strings.TrimSpace(s)
	if len(s) != 17 {
		return out, false
	}
	sep := s[2]
	if sep != ':' && sep != '-' {
		return out, false
	}
	for i := 0; i < 6; i++ {
		if i > 0 && s[i*3-1] != sep {
			return [6]byte{}, false
		}
		hi, ok1 := fromHexChar(s[i*3])
		lo, ok2 := fromHexChar(s[i*3+1])
		if !ok1 || !ok2 {
			return [6]byte{}, false
		}
		out[i] = (hi << 4) | lo
	}
	if out == ([6]byte{}) || out == ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		return [6]byte{}, false
	}
	return out, true
}

// ParseIPAddr classifies an IP string into IPv4 or IPv6 slot bytes.
func ParseIPAddr(s string) (v4 [4]byte, v6 [16]byte, isV4, isV6 bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return v4, v6, false, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(v4[:], ip4)
		return v4, v6, true, false
	}
	if ip16 := ip.To16(); ip16 != nil {
		copy(v6[:], ip16)
		return v4, v6, false, true
	}
	return v4, v6, false, false
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func shouldTryMmap(forceFallback bool) bool {
	if forceFallback {
		return false
	}
	return runtime.GOOS == "linux" || runtime.GOOS == "android"
}

// Writer publishes periodic device & leak telemetry snapshots into the 16KB
// dual-slot seqcount_latch file.
type Writer struct {
	// Placed at offset 0 for 32-bit ARM 64-bit atomic alignment.
	barrier atomic.Uint64

	mu       sync.Mutex
	seq      uint64
	path     string
	file     *os.File
	mmap     []byte
	mmapped  bool
	closed   bool
	slotBuf  [SlotSize]byte
	hdrBuf   [HeaderSize]byte
	imageBuf [FileSize]byte
}

// OpenWriter opens or initializes runDir/shm_vector.bin (16384 bytes) for writing.
func OpenWriter(runDir string) (*Writer, error) {
	return OpenWriterPath(FilePath(runDir), false)
}

// OpenWriterPath opens a specific file path for writing; forceFallback disables
// syscall.Mmap to exercise the atomic pwrite fallback path in tests.
func OpenWriterPath(path string, forceFallback bool) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("shm mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("shm open writer %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("shm stat %s: %w", path, err)
	}
	reinit := info.Size() != FileSize
	if reinit {
		if info.Size() > FileSize {
			if err := f.Truncate(FileSize); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("shm truncate %s: %w", path, err)
			}
		}
		var zeros [FileSize]byte
		if n, werr := f.WriteAt(zeros[:], 0); werr != nil || n != FileSize {
			_ = f.Close()
			if werr == nil {
				werr = io.ErrShortWrite
			}
			return nil, fmt.Errorf("shm prealloc %s: %w", path, werr)
		}
	}

	w := &Writer{
		path: path,
		file: f,
	}

	// Preserve monotonic continuity only if existing file already had exact size
	// and a valid SchemaVersion=3 header; otherwise zero-fill all physical blocks first.
	if !reinit {
		var existingHdr [HeaderSize]byte
		if _, err := f.ReadAt(existingHdr[:], 0); err == nil && validateFileHeader(existingHdr[:], false) == nil {
			w.seq = binary.LittleEndian.Uint64(existingHdr[16:24])
		} else {
			var zeros [FileSize]byte
			if n, werr := f.WriteAt(zeros[:], 0); werr != nil || n != FileSize {
				_ = f.Close()
				if werr == nil {
					werr = io.ErrShortWrite
				}
				return nil, fmt.Errorf("shm prealloc %s: %w", path, werr)
			}
		}
	}

	if shouldTryMmap(forceFallback) {
		data, merr := syscall.Mmap(int(f.Fd()), 0, FileSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if merr == nil && len(data) == FileSize {
			w.mmap = data
			w.mmapped = true
		}
	}

	// Ensure schema v3 header is immediately valid even before first traffic tick.
	if w.seq == 0 {
		if err := w.Write(MonotonicNs(), 0, 0, nil); err != nil {
			_ = w.Close()
			return nil, err
		}
	}
	return w, nil
}

// IsMmapped reports whether Writer is backed by a live MAP_SHARED mapping.
func (w *Writer) IsMmapped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mmapped
}

// Path returns the backing file path.
func (w *Writer) Path() string { return w.path }

// Seq returns the most recently published latch sequence generation.
func (w *Writer) Seq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// Write publishes device slots + summary counters into the inactive latch slot
// and atomically flips the active slot index.
func (w *Writer) Write(updatedMonoNs int64, activeFlows uint32, totalLeaks uint64, devices []DeviceSlot) error {
	return w.WriteWithHostFlows(updatedMonoNs, activeFlows, 0, totalLeaks, 0, devices)
}

func (w *Writer) writeToMmapLocked(slotOff int, oddLatch, evenLatch, nextSeq uint64) (err error) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if rec := recover(); rec != nil {
			err = ErrFault
		}
	}()

	// Step 1: mark target inactive slot in-progress (odd BeginSeq) while readers
	// continue reading the opposite quiescent slot undisturbed.
	storeU64(w.mmap, slotOff, oddLatch, true)
	w.barrier.Add(1)

	// Step 2: copy body, publish atomic EndSeq, fence, then publish even BeginSeq.
	copy(w.mmap[slotOff+8:slotOff+slotEndSeqOff], w.slotBuf[8:slotEndSeqOff])
	storeU64(w.mmap, slotOff+slotEndSeqOff, evenLatch, true)
	w.barrier.Add(1)
	storeU64(w.mmap, slotOff, evenLatch, true)
	w.barrier.Add(1)

	// Step 3: publish top-level header using aligned stores so concurrent header
	// validation never observes byte-torn 32-bit/64-bit metadata.
	copy(w.mmap[0:8], w.hdrBuf[0:8])
	storeU32(w.mmap, 8, binary.LittleEndian.Uint32(w.hdrBuf[8:12]), true)
	storeU32(w.mmap, 12, binary.LittleEndian.Uint32(w.hdrBuf[12:16]), true)
	storeU64(w.mmap, 24, binary.LittleEndian.Uint64(w.hdrBuf[24:32]), true)
	storeU64(w.mmap, 32, binary.LittleEndian.Uint64(w.hdrBuf[32:40]), true)
	storeU32(w.mmap, 40, binary.LittleEndian.Uint32(w.hdrBuf[40:44]), true)
	storeU32(w.mmap, 44, binary.LittleEndian.Uint32(w.hdrBuf[44:48]), true)
	storeU32(w.mmap, 48, binary.LittleEndian.Uint32(w.hdrBuf[48:52]), true)
	copy(w.mmap[52:56], w.hdrBuf[52:56])
	storeU32(w.mmap, 56, binary.LittleEndian.Uint32(w.hdrBuf[56:60]), true)
	storeU32(w.mmap, 60, binary.LittleEndian.Uint32(w.hdrBuf[60:64]), true)
	w.barrier.Add(1)
	storeU64(w.mmap, 16, nextSeq, true)
	w.barrier.Add(1)
	return nil
}

// WriteWithFlags publishes a snapshot with optional header-level flags.
func (w *Writer) WriteWithFlags(updatedMonoNs int64, activeFlows uint32, totalLeaks uint64, flags uint32, devices []DeviceSlot) error {
	return w.WriteWithHostFlows(updatedMonoNs, activeFlows, 0, totalLeaks, flags, devices)
}

// WriteWithHostFlows publishes orthogonal downstream hotspotFlows (ActiveFlows)
// and local phone hostFlows (HostFlows) into the inactive 16KB latch slot.
func (w *Writer) WriteWithHostFlows(updatedMonoNs int64, hotspotFlows uint32, hostFlows uint32, totalLeaks uint64, flags uint32, devices []DeviceSlot) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.file == nil {
		return ErrClosed
	}
	if updatedMonoNs <= 0 {
		updatedMonoNs = MonotonicNs()
	}
	nowUnixNs := time.Now().UnixNano()
	devCount := len(devices)
	if devCount > MaxDevices {
		devCount = MaxDevices
	}

	nextSeq := w.seq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	slotIdx := int(nextSeq & 1)
	slotOff := HeaderSize + slotIdx*SlotSize
	oddLatch := (nextSeq << 1) | 1
	evenLatch := nextSeq << 1

	clear(w.slotBuf[:])
	binary.LittleEndian.PutUint64(w.slotBuf[0:8], evenLatch)
	binary.LittleEndian.PutUint64(w.slotBuf[8:16], uint64(updatedMonoNs))
	binary.LittleEndian.PutUint64(w.slotBuf[16:24], uint64(nowUnixNs))
	binary.LittleEndian.PutUint32(w.slotBuf[24:28], hotspotFlows)
	binary.LittleEndian.PutUint32(w.slotBuf[28:32], uint32(devCount))
	binary.LittleEndian.PutUint64(w.slotBuf[32:40], totalLeaks)
	binary.LittleEndian.PutUint32(w.slotBuf[40:44], flags)
	binary.LittleEndian.PutUint32(w.slotBuf[44:48], SchemaVersion)
	binary.LittleEndian.PutUint16(w.slotBuf[48:50], HeaderSize)
	binary.LittleEndian.PutUint16(w.slotBuf[50:52], DeviceSlotSize)
	binary.LittleEndian.PutUint32(w.slotBuf[52:56], SlotSize)
	binary.LittleEndian.PutUint32(w.slotBuf[56:60], EndianTag)
	binary.LittleEndian.PutUint32(w.slotBuf[60:64], hostFlows)

	for i := 0; i < devCount; i++ {
		d := devices[i]
		off := SlotHeaderSize + i*DeviceSlotSize
		copy(w.slotBuf[off:off+6], d.MAC[:])
		copy(w.slotBuf[off+8:off+12], d.IPv4[:])
		binary.LittleEndian.PutUint32(w.slotBuf[off+12:off+16], d.ActiveFlows)
		copy(w.slotBuf[off+16:off+32], d.IPv6[:])
		binary.LittleEndian.PutUint64(w.slotBuf[off+32:off+40], d.RxBytes)
		binary.LittleEndian.PutUint64(w.slotBuf[off+40:off+48], d.TxBytes)
		binary.LittleEndian.PutUint32(w.slotBuf[off+48:off+52], d.Flags)
	}
	binary.LittleEndian.PutUint64(w.slotBuf[slotEndSeqOff:SlotSize], evenLatch)

	clear(w.hdrBuf[:])
	copy(w.hdrBuf[0:8], Magic)
	binary.LittleEndian.PutUint32(w.hdrBuf[8:12], SchemaVersion)
	binary.LittleEndian.PutUint32(w.hdrBuf[12:16], uint32(slotIdx))
	binary.LittleEndian.PutUint64(w.hdrBuf[16:24], nextSeq)
	binary.LittleEndian.PutUint64(w.hdrBuf[24:32], uint64(updatedMonoNs))
	binary.LittleEndian.PutUint64(w.hdrBuf[32:40], uint64(nowUnixNs))
	binary.LittleEndian.PutUint32(w.hdrBuf[40:44], hotspotFlows)
	binary.LittleEndian.PutUint32(w.hdrBuf[44:48], uint32(devCount))
	binary.LittleEndian.PutUint32(w.hdrBuf[48:52], flags)
	binary.LittleEndian.PutUint16(w.hdrBuf[52:54], HeaderSize)
	binary.LittleEndian.PutUint16(w.hdrBuf[54:56], DeviceSlotSize)
	binary.LittleEndian.PutUint32(w.hdrBuf[56:60], SlotSize)
	binary.LittleEndian.PutUint32(w.hdrBuf[60:64], EndianTag)

	if w.mmapped && len(w.mmap) == FileSize {
		if err := w.writeToMmapLocked(slotOff, oddLatch, evenLatch, nextSeq); err != nil {
			return err
		}
	} else {
		// Fallback path: write inactive slot via pwrite first, then update top header
		// (or write full image on very first initialization).
		if w.seq == 0 {
			clear(w.imageBuf[:])
			copy(w.imageBuf[0:HeaderSize], w.hdrBuf[:])
			copy(w.imageBuf[slotOff:slotOff+SlotSize], w.slotBuf[:])
			if _, err := w.file.WriteAt(w.imageBuf[:], 0); err != nil {
				return fmt.Errorf("shm pwrite init: %w", err)
			}
		} else {
			if _, err := w.file.WriteAt(w.slotBuf[:], int64(slotOff)); err != nil {
				return fmt.Errorf("shm pwrite slot: %w", err)
			}
			if _, err := w.file.WriteAt(w.hdrBuf[:], 0); err != nil {
				return fmt.Errorf("shm pwrite header: %w", err)
			}
		}
	}

	w.seq = nextSeq
	return nil
}

// Close unmaps shared memory (if mapped) and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var firstErr error
	if w.mmapped && w.mmap != nil {
		if err := syscall.Munmap(w.mmap); err != nil && firstErr == nil {
			firstErr = err
		}
		w.mmap = nil
		w.mmapped = false
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		w.file = nil
	}
	return firstErr
}

// Reader provides concurrent zero-allocation reads of shm_vector.bin (<1us on mmap).
// Concurrent ReadInto calls share an RWMutex read lock while Close acquires the
// exclusive write lock before Munmap so active readers never touch unmapped pages.
type Reader struct {
	// Placed at offset 0 for 32-bit ARM 64-bit atomic alignment.
	barrier atomic.Uint64
	closed  atomic.Uint32

	mu            sync.RWMutex
	path          string
	file          *os.File
	mmap          []byte
	mmapped       bool
	forceFallback bool
}

func probeMmapHeader(buf []byte, dst *[HeaderSize]byte) (err error) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if rec := recover(); rec != nil {
			err = ErrFault
		}
	}()
	copy(dst[:], buf[0:HeaderSize])
	return nil
}

// OpenReader opens runDir/shm_vector.bin for read-only access.
func OpenReader(runDir string) (*Reader, error) {
	return OpenReaderPath(FilePath(runDir), false)
}

// OpenReaderPath opens a specific shm_vector.bin path for reading.
func OpenReaderPath(path string, forceFallback bool) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("shm open reader %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("shm reader stat %s: %w", path, err)
	}
	if info.Size() < FileSize {
		_ = f.Close()
		return nil, fmt.Errorf("%w (%w): got %d want %d", ErrShortRegion, ErrSchemaMismatch, info.Size(), FileSize)
	}
	if info.Size() > FileSize {
		_ = f.Close()
		return nil, fmt.Errorf("%w: got %d want %d", ErrSchemaMismatch, info.Size(), FileSize)
	}

	r := &Reader{
		path:          path,
		file:          f,
		forceFallback: forceFallback,
	}
	if shouldTryMmap(forceFallback) {
		data, merr := syscall.Mmap(int(f.Fd()), 0, FileSize, syscall.PROT_READ, syscall.MAP_SHARED)
		if merr == nil && len(data) == FileSize {
			r.mmap = data
			r.mmapped = true
		}
	}

	var probeHdr [HeaderSize]byte
	if r.mmapped {
		if err := probeMmapHeader(r.mmap, &probeHdr); err != nil {
			_ = r.Close()
			return nil, err
		}
	} else if n, err := f.ReadAt(probeHdr[:], 0); err != nil || n < HeaderSize {
		_ = r.Close()
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w (%w): short header read %d", ErrShortRegion, ErrSchemaMismatch, n)
		}
		return nil, err
	}
	if err := validateFileHeader(probeHdr[:], false); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

// IsMmapped reports whether Reader is backed by a read-only MAP_SHARED mapping.
func (r *Reader) IsMmapped() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mmapped
}

// Path returns the backing file path.
func (r *Reader) Path() string { return r.path }

// Read decodes a consistent Snapshot by value.
func (r *Reader) Read() (Snapshot, error) {
	var snap Snapshot
	if err := r.ReadInto(&snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// ReadInto populates dst with zero heap allocations using seqcount_latch
// dual-slot validation: if the primary slot is mid-transition, it seamlessly
// falls back to the alternate quiescent slot without mutating dst until a
// complete tear-free frame passes sequence & schema verification.
func (r *Reader) ReadInto(dst *Snapshot) error {
	if r == nil || dst == nil {
		return ErrClosed
	}
	if r.closed.Load() != 0 {
		return ErrClosed
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed.Load() != 0 {
		return ErrClosed
	}

	if r.mmapped && len(r.mmap) == FileSize {
		return r.readFromMmap(r.mmap, dst)
	}

	// Fallback mode: atomic pread of the 16KB image onto stack buffer (zero heap allocs).
	var raw [FileSize]byte
	if r.file == nil {
		return ErrClosed
	}
	n, err := r.file.ReadAt(raw[:], 0)
	if n < FileSize {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w (%w): got %d want %d", ErrShortRegion, ErrSchemaMismatch, n, FileSize)
		}
		return fmt.Errorf("shm pread: %w", err)
	}
	return r.readFromBuf(raw[:], dst, false)
}

func (r *Reader) readFromMmap(buf []byte, dst *Snapshot) (err error) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if rec := recover(); rec != nil {
			err = ErrFault
		}
	}()
	return r.readFromBuf(buf, dst, true)
}

func (r *Reader) readFromBuf(buf []byte, dst *Snapshot, useAtomic bool) error {
	if len(buf) < FileSize {
		return fmt.Errorf("%w (%w): got %d want %d", ErrShortRegion, ErrSchemaMismatch, len(buf), FileSize)
	}
	if len(buf) > FileSize {
		return fmt.Errorf("%w: got %d want %d", ErrSchemaMismatch, len(buf), FileSize)
	}
	if err := validateFileHeader(buf[0:HeaderSize], useAtomic); err != nil {
		return err
	}

	// Try up to 4 fast iterations across primary and alternate latch slots.
	for attempt := 0; attempt < 4; attempt++ {
		var fence atomic.Uint32
		fence.Add(1)
		hdrSeq := loadU64(buf, 16, useAtomic)
		if hdrSeq == 0 {
			if useAtomic {
				runtime.Gosched()
			}
			continue
		}
		primaryIdx := int(hdrSeq & 1)
		ok, err := r.tryDecodeSlot(buf, primaryIdx, dst, useAtomic)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		// seqcount_latch fallback: while writer mutates primaryIdx, primaryIdx^1
		// holds the previous complete quiescent snapshot.
		altIdx := primaryIdx ^ 1
		ok, err = r.tryDecodeSlot(buf, altIdx, dst, useAtomic)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if useAtomic {
			runtime.Gosched()
		}
	}
	return ErrUninitialized
}

func (r *Reader) tryDecodeSlot(buf []byte, slotIdx int, dst *Snapshot, useAtomic bool) (bool, error) {
	slotOff := HeaderSize + slotIdx*SlotSize
	slot := buf[slotOff : slotOff+SlotSize]

	seq1 := loadU64(buf, slotOff, useAtomic)
	// Uninitialized (0) or writer active on this slot (odd bit set).
	if seq1 == 0 || (seq1&1) != 0 {
		return false, nil
	}

	var fence atomic.Uint32
	fence.Add(1)

	devCount := binary.LittleEndian.Uint32(slot[28:32])
	slotVer := binary.LittleEndian.Uint32(slot[44:48])
	slotHdrSz := binary.LittleEndian.Uint16(slot[48:50])
	slotDevSz := binary.LittleEndian.Uint16(slot[50:52])
	slotPayloadSz := binary.LittleEndian.Uint32(slot[52:56])
	slotEndian := binary.LittleEndian.Uint32(slot[56:60])

	if slotVer != SchemaVersion ||
		slotHdrSz != HeaderSize ||
		slotDevSz != DeviceSlotSize ||
		slotPayloadSz != SlotSize ||
		slotEndian != EndianTag ||
		devCount > MaxDevices {
		// Issue RMW full fence before checking whether this mismatch is a sealed
		// schema violation vs. an in-flight writer tear on this slot.
		fence.Add(1)
		endSeq := loadU64(buf, slotOff+slotEndSeqOff, useAtomic)
		seq2 := loadU64(buf, slotOff, useAtomic)
		if seq1 == endSeq && seq1 == seq2 && (seq1&1) == 0 {
			return false, fmt.Errorf(
				"%w: slot=%d ver=%d hdr=%d devSlot=%d payload=%d endian=0x%08x devs=%d",
				ErrSchemaMismatch, slotIdx, slotVer, slotHdrSz, slotDevSz, slotPayloadSz, slotEndian, devCount,
			)
		}
		return false, nil
	}

	// Decode into a stack-local temporary Snapshot so a mid-read writer takeover
	// can never pollute the caller's destination buffer with a half-torn frame.
	var tmp Snapshot
	copy(tmp.Header.Magic[:], Magic)
	tmp.Header.Version = slotVer
	tmp.Header.HeaderSize = slotHdrSz
	tmp.Header.DeviceSlotSize = slotDevSz
	tmp.Header.SlotSize = slotPayloadSz
	tmp.Header.EndianTag = slotEndian
	tmp.Header.ActiveSlot = uint32(slotIdx)
	tmp.Header.Seq = seq1 >> 1
	tmp.Header.UpdatedMonoNs = int64(binary.LittleEndian.Uint64(slot[8:16]))
	tmp.Header.UpdatedUnixNs = int64(binary.LittleEndian.Uint64(slot[16:24]))
	tmp.Header.ActiveFlows = binary.LittleEndian.Uint32(slot[24:28])
	tmp.Header.HostFlows = loadU32(slot, 60, useAtomic)
	tmp.Header.DeviceCount = devCount
	tmp.Header.TotalLeaks = binary.LittleEndian.Uint64(slot[32:40])
	tmp.Header.Flags = binary.LittleEndian.Uint32(slot[40:44])

	n := int(devCount)
	for i := 0; i < n; i++ {
		off := SlotHeaderSize + i*DeviceSlotSize
		copy(tmp.Devices[i].MAC[:], slot[off:off+6])
		copy(tmp.Devices[i].IPv4[:], slot[off+8:off+12])
		tmp.Devices[i].ActiveFlows = binary.LittleEndian.Uint32(slot[off+12 : off+16])
		copy(tmp.Devices[i].IPv6[:], slot[off+16:off+32])
		tmp.Devices[i].RxBytes = binary.LittleEndian.Uint64(slot[off+32 : off+40])
		tmp.Devices[i].TxBytes = binary.LittleEndian.Uint64(slot[off+40 : off+48])
		tmp.Devices[i].Flags = binary.LittleEndian.Uint32(slot[off+48 : off+52])
	}

	// Bidirectional full memory barrier (atomic RMW on stack-local word) prevents
	// ARM64 weak-memory plain mmap loads above from sinking past seq2/endSeq loads below.
	fence.Add(1)
	endSeq := loadU64(buf, slotOff+slotEndSeqOff, useAtomic)
	seq2 := loadU64(buf, slotOff, useAtomic)
	if seq1 != endSeq || seq1 != seq2 || (seq2&1) != 0 {
		return false, nil
	}

	*dst = tmp
	return true, nil
}

// Close unmaps shared memory (if mapped) and closes the underlying file.
func (r *Reader) Close() error {
	if !r.closed.CompareAndSwap(0, 1) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	if r.mmapped && r.mmap != nil {
		if err := syscall.Munmap(r.mmap); err != nil && firstErr == nil {
			firstErr = err
		}
		r.mmap = nil
		r.mmapped = false
	}
	if r.file != nil {
		if err := r.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.file = nil
	}
	return firstErr
}
