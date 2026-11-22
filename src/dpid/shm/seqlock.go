// Package shm implements a 16KB page-aligned dual-slot seqcount_latch shared
// memory snapshot at /data/local/hnc/run/shm_vector.bin for HNC v6.0.0 Vector.
//
// Design invariants:
//   - Fixed 16384-byte binary layout (matches Android 16 16KB page alignment):
//     [0..64)      Top-level latch header (Magic "HNCV6SHM", active seq, summary)
//     [64..8224)   Latch Slot 0 (64B slot header + 64*64B devices + padding + 8B EndSeq)
//     [8224..16384) Latch Slot 1 (64B slot header + 64*64B devices + padding + 8B EndSeq)
//   - Linux/Android uses syscall.Mmap(MAP_SHARED); non-Linux or mmap-unsupported
//     filesystems gracefully fall back to atomic pread/pwrite (os.File.ReadAt/WriteAt).
//   - Uses encoding/binary.LittleEndian for payload fields and 8-byte-aligned
//     64-bit atomics on mmap latch sequence fields, placing struct-level 64-bit
//     atomic fields at offset 0 for 32-bit ARMv7 safety.
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	Magic           = "HNCV6SHM"
	Version  uint32 = 1
	FileSize        = 16384

	HeaderSize     = 64
	SlotSize       = (FileSize - HeaderSize) / 2 // 8160 bytes per latch slot
	SlotHeaderSize = 64
	DeviceSlotSize = 64
	MaxDevices     = 64
	slotEndSeqOff  = SlotSize - 8

	DefaultRunDir   = "/data/local/hnc/run"
	DefaultFileName = "shm_vector.bin"

	clockBoottime = 7 // Linux CLOCK_BOOTTIME (includes suspend/Doze time)
)

// Per-device bit flags stored in DeviceSlot.Flags.
const (
	FlagOnline  uint32 = 1 << 0
	FlagIPv4    uint32 = 1 << 1
	FlagIPv6    uint32 = 1 << 2
	FlagLeakHit uint32 = 1 << 3
)

var (
	ErrBadMagic      = errors.New("shm: invalid magic header")
	ErrBadSize       = errors.New("shm: unexpected shared memory file size")
	ErrClosed        = errors.New("shm: handle closed")
	ErrUninitialized = errors.New("shm: snapshot not yet published")
	ErrFault         = errors.New("shm: mmap bus fault")
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

var (
	monoStart  = time.Now()
	bootBaseNs = initBootBaseNs()
)

func initBootBaseNs() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 1_000_000_000
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 1_000_000_000
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || sec <= 0 {
		return 1_000_000_000
	}
	return int64(sec * float64(time.Second))
}

// MonotonicNs returns a monotonically non-decreasing timestamp in nanoseconds.
// On Linux/Android it queries CLOCK_BOOTTIME directly so cross-process readers
// stay immune to Doze/suspend drift and wall-clock jumps; non-Linux falls back
// to time.Since.
func MonotonicNs() int64 {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		var ts syscall.Timespec
		_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockBoottime, uintptr(unsafe.Pointer(&ts)), 0)
		if errno == 0 {
			ns := int64(ts.Sec)*int64(time.Second) + int64(ts.Nsec)
			if ns > 0 {
				return ns
			}
		}
	}
	d := time.Since(monoStart).Nanoseconds()
	if d < 0 {
		d = 0
	}
	return bootBaseNs + d
}

// FilePath resolves the canonical shm_vector.bin path for a given runDir.
func FilePath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, DefaultFileName)
}

// Header represents the top-level metadata of a Vector shared memory snapshot.
type Header struct {
	Magic         [8]byte
	Version       uint32
	ActiveSlot    uint32
	Seq           uint64
	UpdatedMonoNs int64
	UpdatedUnixNs int64
	ActiveFlows   uint32
	DeviceCount   uint32
	TotalLeaks    uint64
	Flags         uint32
}

// DeviceSlot is one fixed-layout downstream client record in the snapshot body.
type DeviceSlot struct {
	MAC         [6]byte
	IPv4        [4]byte
	IPv6        [16]byte
	RxBytes     uint64
	TxBytes     uint64
	ActiveFlows uint32
	Flags       uint32
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
	// and a valid magic header; otherwise zero-fill all physical blocks first.
	if !reinit {
		var existingHdr [HeaderSize]byte
		if _, err := f.ReadAt(existingHdr[:], 0); err == nil && string(existingHdr[0:8]) == Magic {
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

	// Ensure magic header is immediately valid even before first traffic tick.
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
	return w.WriteWithFlags(updatedMonoNs, activeFlows, totalLeaks, 0, devices)
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

	// Step 3: publish top-level header pointing ActiveSlot/Seq to the completed slot.
	copy(w.mmap[0:8], w.hdrBuf[0:8])
	copy(w.mmap[8:16], w.hdrBuf[8:16])
	copy(w.mmap[24:HeaderSize], w.hdrBuf[24:HeaderSize])
	w.barrier.Add(1)
	storeU64(w.mmap, 16, nextSeq, true)
	w.barrier.Add(1)
	return nil
}

// WriteWithFlags publishes a snapshot with optional header-level flags.
func (w *Writer) WriteWithFlags(updatedMonoNs int64, activeFlows uint32, totalLeaks uint64, flags uint32, devices []DeviceSlot) error {
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
	binary.LittleEndian.PutUint32(w.slotBuf[24:28], activeFlows)
	binary.LittleEndian.PutUint32(w.slotBuf[28:32], uint32(devCount))
	binary.LittleEndian.PutUint64(w.slotBuf[32:40], totalLeaks)
	binary.LittleEndian.PutUint32(w.slotBuf[40:44], flags)

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
	binary.LittleEndian.PutUint32(w.hdrBuf[8:12], Version)
	binary.LittleEndian.PutUint32(w.hdrBuf[12:16], uint32(slotIdx))
	binary.LittleEndian.PutUint64(w.hdrBuf[16:24], nextSeq)
	binary.LittleEndian.PutUint64(w.hdrBuf[24:32], uint64(updatedMonoNs))
	binary.LittleEndian.PutUint64(w.hdrBuf[32:40], uint64(nowUnixNs))
	binary.LittleEndian.PutUint32(w.hdrBuf[40:44], activeFlows)
	binary.LittleEndian.PutUint32(w.hdrBuf[44:48], uint32(devCount))
	binary.LittleEndian.PutUint64(w.hdrBuf[48:56], totalLeaks)
	binary.LittleEndian.PutUint32(w.hdrBuf[56:60], flags)

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

// Reader provides concurrent zero-allocation reads of shm_vector.bin (<1µs on mmap).
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

func probeMmapMagic(buf []byte, dst *[8]byte) (err error) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if rec := recover(); rec != nil {
			err = ErrFault
		}
	}()
	copy(dst[:], buf[0:8])
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
		return nil, fmt.Errorf("%w: got %d want %d", ErrBadSize, info.Size(), FileSize)
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

	var probeHdr [8]byte
	if r.mmapped {
		if err := probeMmapMagic(r.mmap, &probeHdr); err != nil {
			_ = r.Close()
			return nil, err
		}
	} else if _, err := f.ReadAt(probeHdr[:], 0); err != nil {
		_ = r.Close()
		return nil, err
	}
	if string(probeHdr[:]) != Magic {
		_ = r.Close()
		return nil, ErrBadMagic
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
// falls back to the alternate quiescent slot.
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
	if err != nil && n < FileSize {
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
		return ErrBadSize
	}
	if buf[0] != 'H' || buf[1] != 'N' || buf[2] != 'C' || buf[3] != 'V' ||
		buf[4] != '6' || buf[5] != 'S' || buf[6] != 'H' || buf[7] != 'M' {
		return ErrBadMagic
	}

	// Try up to 4 fast iterations across primary and alternate latch slots.
	for attempt := 0; attempt < 4; attempt++ {
		_ = r.barrier.Load()
		hdrSeq := loadU64(buf, 16, useAtomic)
		if hdrSeq == 0 {
			if useAtomic {
				runtime.Gosched()
			}
			continue
		}
		primaryIdx := int(hdrSeq & 1)
		if r.tryDecodeSlot(buf, primaryIdx, dst, useAtomic) {
			return nil
		}
		// seqcount_latch fallback: while writer mutates primaryIdx, primaryIdx^1
		// holds the previous complete quiescent snapshot.
		altIdx := primaryIdx ^ 1
		if r.tryDecodeSlot(buf, altIdx, dst, useAtomic) {
			return nil
		}
	}
	return ErrUninitialized
}

func (r *Reader) tryDecodeSlot(buf []byte, slotIdx int, dst *Snapshot, useAtomic bool) bool {
	slotOff := HeaderSize + slotIdx*SlotSize
	slot := buf[slotOff : slotOff+SlotSize]

	beginSeq := loadU64(buf, slotOff, useAtomic)
	// Uninitialized (0) or writer active on this slot (odd bit set).
	if beginSeq == 0 || (beginSeq&1) != 0 {
		return false
	}
	_ = r.barrier.Load()

	devCount := binary.LittleEndian.Uint32(slot[28:32])
	if devCount > MaxDevices {
		return false
	}

	copy(dst.Header.Magic[:], Magic)
	dst.Header.Version = binary.LittleEndian.Uint32(buf[8:12])
	dst.Header.ActiveSlot = uint32(slotIdx)
	dst.Header.Seq = beginSeq >> 1
	dst.Header.UpdatedMonoNs = int64(binary.LittleEndian.Uint64(slot[8:16]))
	dst.Header.UpdatedUnixNs = int64(binary.LittleEndian.Uint64(slot[16:24]))
	dst.Header.ActiveFlows = binary.LittleEndian.Uint32(slot[24:28])
	dst.Header.DeviceCount = devCount
	dst.Header.TotalLeaks = binary.LittleEndian.Uint64(slot[32:40])
	dst.Header.Flags = binary.LittleEndian.Uint32(slot[40:44])

	n := int(devCount)
	for i := 0; i < n; i++ {
		off := SlotHeaderSize + i*DeviceSlotSize
		copy(dst.Devices[i].MAC[:], slot[off:off+6])
		copy(dst.Devices[i].IPv4[:], slot[off+8:off+12])
		dst.Devices[i].ActiveFlows = binary.LittleEndian.Uint32(slot[off+12 : off+16])
		copy(dst.Devices[i].IPv6[:], slot[off+16:off+32])
		dst.Devices[i].RxBytes = binary.LittleEndian.Uint64(slot[off+32 : off+40])
		dst.Devices[i].TxBytes = binary.LittleEndian.Uint64(slot[off+40 : off+48])
		dst.Devices[i].Flags = binary.LittleEndian.Uint32(slot[off+48 : off+52])
	}
	for i := n; i < MaxDevices; i++ {
		dst.Devices[i] = DeviceSlot{}
	}

	_ = r.barrier.Load()
	endSeq := loadU64(buf, slotOff+slotEndSeqOff, useAtomic)
	beginVerify := loadU64(buf, slotOff, useAtomic)
	return endSeq == beginSeq && beginVerify == beginSeq
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
