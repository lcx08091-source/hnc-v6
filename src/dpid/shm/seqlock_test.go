package shm

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func sampleDevices() []DeviceSlot {
	mac1, _ := ParseMAC("3c:22:fb:11:22:33")
	v4a, _, _, _ := ParseIPAddr("192.168.43.20")
	_, v6a, _, _ := ParseIPAddr("2409:8a00:1:2::20")

	mac2, _ := ParseMAC("aa-bb-cc-dd-ee-02")
	v4b, _, _, _ := ParseIPAddr("192.168.43.88")

	return []DeviceSlot{
		{
			MAC:         mac1,
			IPv4:        v4a,
			IPv6:        v6a,
			RxBytes:     9876543210,
			TxBytes:     1234567890,
			ActiveFlows: 14,
			Flags:       FlagOnline | FlagIPv4 | FlagIPv6,
		},
		{
			MAC:         mac2,
			IPv4:        v4b,
			RxBytes:     4096,
			TxBytes:     8192,
			ActiveFlows: 2,
			Flags:       FlagOnline | FlagIPv4 | FlagLeakHit,
		},
	}
}

func assertStruct64BitAlignment(t *testing.T, rt reflect.Type, baseOff uintptr, prefix string) {
	t.Helper()
	u64Atom := reflect.TypeOf((*atomic.Uint64)(nil)).Elem()
	i64Atom := reflect.TypeOf((*atomic.Int64)(nil)).Elem()
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		absOff := baseOff + sf.Offset
		switch {
		case sf.Type.Kind() == reflect.Uint64 || sf.Type.Kind() == reflect.Int64 || sf.Type == u64Atom || sf.Type == i64Atom:
			if absOff%8 != 0 {
				t.Fatalf("%s.%s (%s) at offset=%d is not 8-byte aligned", prefix, sf.Name, sf.Type, absOff)
			}
		case sf.Type.Kind() == reflect.Struct:
			assertStruct64BitAlignment(t, sf.Type, absOff, prefix+"."+sf.Name)
		case sf.Type.Kind() == reflect.Array && sf.Type.Elem().Kind() == reflect.Struct && sf.Type.Len() > 0:
			elemType := sf.Type.Elem()
			for idx := 0; idx < sf.Type.Len() && idx < 4; idx++ {
				assertStruct64BitAlignment(t, elemType, absOff+uintptr(idx)*elemType.Size(), prefix+"."+sf.Name)
			}
		}
	}
}

func TestSeqLockWireLayoutInvariants(t *testing.T) {
	if SchemaVersion != 3 || Version != 3 {
		t.Fatalf("unexpected SchemaVersion=%d Version=%d, want 3", SchemaVersion, Version)
	}
	if FileSize != 16384 || HeaderSize != 64 || SlotSize != 8160 || DeviceSlotSize != 64 || MaxDevices != 126 {
		t.Fatalf("unexpected geometry: FileSize=%d HeaderSize=%d SlotSize=%d DeviceSlotSize=%d MaxDevices=%d",
			FileSize, HeaderSize, SlotSize, DeviceSlotSize, MaxDevices)
	}
	if SlotHeaderSize+MaxDevices*DeviceSlotSize > slotEndSeqOff {
		t.Fatalf("device table overflows slotEndSeqOff: %d > %d", SlotHeaderSize+MaxDevices*DeviceSlotSize, slotEndSeqOff)
	}

	// Verify 32-bit/64-bit Go struct 8-byte alignment for all 64-bit fields and array strides.
	if unsafe.Sizeof(Header{})%8 != 0 {
		t.Fatalf("Header sizeof=%d is not a multiple of 8 bytes", unsafe.Sizeof(Header{}))
	}
	if unsafe.Sizeof(DeviceSlot{})%8 != 0 {
		t.Fatalf("DeviceSlot sizeof=%d is not a multiple of 8 bytes", unsafe.Sizeof(DeviceSlot{}))
	}
	assertStruct64BitAlignment(t, reflect.TypeOf(Header{}), 0, "Header")
	assertStruct64BitAlignment(t, reflect.TypeOf(DeviceSlot{}), 0, "DeviceSlot")
	assertStruct64BitAlignment(t, reflect.TypeOf(Snapshot{}), 0, "Snapshot")
	assertStruct64BitAlignment(t, reflect.TypeOf((*Writer)(nil)).Elem(), 0, "Writer")
	assertStruct64BitAlignment(t, reflect.TypeOf((*Reader)(nil)).Elem(), 0, "Reader")

	// Verify every 64-bit wire offset in top header and both latch slots is % 8 == 0.
	hdr64Offsets := []int{16, 24, 32}
	for _, off := range hdr64Offsets {
		if off%8 != 0 {
			t.Fatalf("top header 64-bit offset %d not 8-byte aligned", off)
		}
	}
	for slotIdx := 0; slotIdx < 2; slotIdx++ {
		base := HeaderSize + slotIdx*SlotSize
		for _, rel := range []int{0, 8, 16, 32, slotEndSeqOff} {
			if (base+rel)%8 != 0 {
				t.Fatalf("slot %d 64-bit offset %d not 8-byte aligned", slotIdx, base+rel)
			}
		}
		if (base+60)%4 != 0 {
			t.Fatalf("slot %d HostFlows 32-bit offset %d not 4-byte aligned", slotIdx, base+60)
		}
		for i := 0; i < MaxDevices; i++ {
			devBase := base + SlotHeaderSize + i*DeviceSlotSize
			if (devBase+32)%8 != 0 || (devBase+40)%8 != 0 {
				t.Fatalf("slot %d device %d 64-bit counter offset not 8-byte aligned", slotIdx, i)
			}
		}
	}
}

func TestSeqLockMmapAndFallbackRoundTrip(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, DefaultFileName)

		w, err := OpenWriterPath(path, fallback)
		if err != nil {
			t.Fatalf("fallback=%v OpenWriterPath: %v", fallback, err)
		}
		defer w.Close()

		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if st.Size() != FileSize {
			t.Fatalf("file size=%d want %d", st.Size(), FileSize)
		}

		r, err := OpenReaderPath(path, fallback)
		if err != nil {
			t.Fatalf("fallback=%v OpenReaderPath: %v", fallback, err)
		}
		defer r.Close()

		// Initial empty snapshot written at OpenWriterPath must already be readable.
		var snap Snapshot
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("initial ReadInto: %v", err)
		}
		if string(snap.Header.Magic[:]) != Magic ||
			snap.Header.Version != 3 ||
			snap.Header.HeaderSize != HeaderSize ||
			snap.Header.DeviceSlotSize != DeviceSlotSize ||
			snap.Header.SlotSize != SlotSize ||
			snap.Header.EndianTag != EndianTag ||
			snap.Header.ActiveFlows != 0 ||
			snap.Header.HostFlows != 0 ||
			snap.Header.DeviceCount != 0 {
			t.Fatalf("unexpected initial header: %+v", snap.Header)
		}

		devs := sampleDevices()
		mono1 := MonotonicNs()
		if err := w.WriteWithHostFlows(mono1, 42, 230, 7, 0x5, devs); err != nil {
			t.Fatalf("WriteWithHostFlows #1: %v", err)
		}
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("ReadInto #1: %v", err)
		}
		if snap.Header.UpdatedMonoNs != mono1 || snap.Header.ActiveFlows != 42 || snap.Header.HostFlows != 230 || snap.Header.TotalLeaks != 7 || snap.Header.Flags != 0x5 {
			t.Fatalf("header mismatch: %+v", snap.Header)
		}
		got := snap.ValidDevices()
		if len(got) != 2 {
			t.Fatalf("device count=%d want 2", len(got))
		}
		if got[0].MACString() != "3c:22:fb:11:22:33" || got[0].IPv4String() != "192.168.43.20" || got[0].IPv6String() != "2409:8a00:1:2::20" {
			t.Fatalf("dev[0] mismatch: mac=%s v4=%s v6=%s", got[0].MACString(), got[0].IPv4String(), got[0].IPv6String())
		}
		if got[0].RxBytes != 9876543210 || got[0].TxBytes != 1234567890 || got[0].ActiveFlows != 14 {
			t.Fatalf("dev[0] counters mismatch: %+v", got[0])
		}
		if got[1].MACString() != "aa:bb:cc:dd:ee:02" || got[1].Flags&FlagLeakHit == 0 {
			t.Fatalf("dev[1] mismatch: %+v", got[1])
		}

		// Second write flips to opposite latch slot via WriteWithHostFlows (0 hotspot devices, 185 host flows).
		mono2 := MonotonicNs()
		if err := w.WriteWithHostFlows(mono2, 0, 185, 9, 0, nil); err != nil {
			t.Fatalf("WriteWithHostFlows #2: %v", err)
		}
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("ReadInto #2: %v", err)
		}
		if snap.Header.DeviceCount != 0 || snap.Header.ActiveFlows != 0 || snap.Header.HostFlows != 185 || snap.Header.TotalLeaks != 9 {
			t.Fatalf("header #2 mismatch: %+v", snap.Header)
		}
		if snap.Devices[0] != (DeviceSlot{}) || snap.Devices[1] != (DeviceSlot{}) {
			t.Fatalf("stale tail device slots not cleared: %+v %+v", snap.Devices[0], snap.Devices[1])
		}

		// Backward-compatible Write wrapper sets HostFlows=0.
		devs[0].RxBytes += 100000
		mono3 := MonotonicNs()
		if err := w.Write(mono3, 55, 11, devs[:1]); err != nil {
			t.Fatalf("Write #3: %v", err)
		}
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("ReadInto #3: %v", err)
		}
		if snap.Header.DeviceCount != 1 || snap.Header.ActiveFlows != 55 || snap.Header.HostFlows != 0 || snap.Header.TotalLeaks != 11 {
			t.Fatalf("header #3 mismatch: %+v", snap.Header)
		}
	}
}

func TestSeqLockLatchFallbackOnTornActiveSlot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)

	w, err := OpenWriterPath(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	devs := sampleDevices()
	// Write twice so both Slot 0 and Slot 1 contain valid historical snapshots.
	if err := w.Write(1000, 10, 1, devs[:1]); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(2000, 20, 2, devs); err != nil {
		t.Fatal(err)
	}

	// Simulate an in-progress writer on the active slot (odd BeginSeq).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hdrSeq := binary.LittleEndian.Uint64(raw[16:24])
	activeSlotOff := HeaderSize + int(hdrSeq&1)*SlotSize
	binary.LittleEndian.PutUint64(raw[activeSlotOff:activeSlotOff+8], (hdrSeq<<1)|1)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReaderPath(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	snap, err := r.Read()
	if err != nil {
		t.Fatalf("latch fallback failed: %v", err)
	}
	// Reader must seamlessly return the previous quiescent slot (UpdatedMonoNs=1000).
	if snap.Header.UpdatedMonoNs != 1000 || snap.Header.DeviceCount != 1 {
		t.Fatalf("expected quiescent fallback slot, got %+v", snap.Header)
	}
}

func TestSeqLockHotUpgradeSchemaMismatchAndTruncation(t *testing.T) {
	makeValidRaw := func(t *testing.T) []byte {
		t.Helper()
		p := filepath.Join(t.TempDir(), DefaultFileName)
		w, err := OpenWriterPath(p, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Write(123456, 8, 2, sampleDevices()); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("legacy_v1_magic_and_writer_auto_upgrade", func(t *testing.T) {
		raw := makeValidRaw(t)
		copy(raw[0:8], "HNCV6SHM")
		binary.LittleEndian.PutUint32(raw[8:12], 1)
		p := filepath.Join(t.TempDir(), DefaultFileName)
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReaderPath(p, false); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("expected ErrSchemaMismatch on legacy v1 magic, got %v", err)
		}

		// Opening Writer on legacy v1 file must wipe and upgrade it cleanly to v2.
		w, err := OpenWriterPath(p, false)
		if err != nil {
			t.Fatalf("OpenWriterPath upgrade failed: %v", err)
		}
		defer w.Close()

		r, err := OpenReaderPath(p, false)
		if err != nil {
			t.Fatalf("OpenReaderPath after writer upgrade failed: %v", err)
		}
		defer r.Close()
		snap, err := r.Read()
		if err != nil || snap.Header.Version != SchemaVersion {
			t.Fatalf("expected upgraded SchemaVersion=%d, snap=%+v err=%v", SchemaVersion, snap.Header, err)
		}
	})

	t.Run("version_1_with_current_magic", func(t *testing.T) {
		raw := makeValidRaw(t)
		binary.LittleEndian.PutUint32(raw[8:12], 1)
		p := filepath.Join(t.TempDir(), DefaultFileName)
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReaderPath(p, false); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("expected ErrSchemaMismatch for Version=1, got %v", err)
		}
	})

	t.Run("version_2_with_current_magic_and_writer_auto_upgrade", func(t *testing.T) {
		raw := makeValidRaw(t)
		binary.LittleEndian.PutUint32(raw[8:12], 2)
		for sIdx := 0; sIdx < 2; sIdx++ {
			sOff := HeaderSize + sIdx*SlotSize
			binary.LittleEndian.PutUint32(raw[sOff+44:sOff+48], 2)
		}
		p := filepath.Join(t.TempDir(), DefaultFileName)
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, fb := range []bool{false, true} {
			if _, err := OpenReaderPath(p, fb); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("fallback=%v: expected ErrSchemaMismatch for Version=2, got %v", fb, err)
			}
		}

		// Opening Writer on legacy v2 file must automatically wipe and rebuild to SchemaVersion=3.
		w, err := OpenWriterPath(p, false)
		if err != nil {
			t.Fatalf("OpenWriterPath v2->v3 auto-upgrade failed: %v", err)
		}
		defer w.Close()

		r, err := OpenReaderPath(p, false)
		if err != nil {
			t.Fatalf("OpenReaderPath after v2->v3 upgrade failed: %v", err)
		}
		defer r.Close()
		snap, err := r.Read()
		if err != nil || snap.Header.Version != 3 || snap.Header.DeviceCount != 0 {
			t.Fatalf("expected clean upgraded SchemaVersion=3 snapshot, got snap=%+v err=%v", snap.Header, err)
		}
	})

	t.Run("mismatched_header_slotsize_devicesize_endiantag_devcount", func(t *testing.T) {
		mutators := []struct {
			name string
			fn   func([]byte)
		}{
			{"bad_header_size", func(b []byte) { binary.LittleEndian.PutUint16(b[52:54], 32) }},
			{"bad_device_slot_size", func(b []byte) { binary.LittleEndian.PutUint16(b[54:56], 48) }},
			{"bad_top_slot_size", func(b []byte) { binary.LittleEndian.PutUint32(b[56:60], 4096) }},
			{"bad_endian_tag", func(b []byte) { binary.LittleEndian.PutUint32(b[60:64], 0x04030201) }},
			{"bad_top_dev_count", func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], MaxDevices+1) }},
		}
		for _, tc := range mutators {
			raw := makeValidRaw(t)
			tc.fn(raw)
			p := filepath.Join(t.TempDir(), DefaultFileName)
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenReaderPath(p, false); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("%s: expected ErrSchemaMismatch, got %v", tc.name, err)
			}
		}

		// Also verify slot-level schema mismatch detected during ReadInto when top header passes.
		raw := makeValidRaw(t)
		hdrSeq := binary.LittleEndian.Uint64(raw[16:24])
		activeSlotOff := HeaderSize + int(hdrSeq&1)*SlotSize
		binary.LittleEndian.PutUint32(raw[activeSlotOff+52:activeSlotOff+56], 4096) // wrong slot PayloadSize
		p := filepath.Join(t.TempDir(), DefaultFileName)
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := OpenReaderPath(p, true)
		if err != nil {
			t.Fatalf("OpenReaderPath: %v", err)
		}
		defer r.Close()
		var snap Snapshot
		if err := r.ReadInto(&snap); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("expected slot-level ErrSchemaMismatch, got %v", err)
		}
	})

	t.Run("truncated_and_oversized_and_bad_magic", func(t *testing.T) {
		raw := makeValidRaw(t)
		for _, sz := range []int{0, 16, 63, 4096, FileSize - 1} {
			p := filepath.Join(t.TempDir(), DefaultFileName)
			if err := os.WriteFile(p, raw[:sz], 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := OpenReaderPath(p, false)
			if !errors.Is(err, ErrShortRegion) || !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("size=%d: expected ErrShortRegion & ErrSchemaMismatch, got %v", sz, err)
			}
		}

		// Oversized file triggers ErrSchemaMismatch.
		pOver := filepath.Join(t.TempDir(), DefaultFileName)
		over := make([]byte, FileSize+64)
		copy(over, raw)
		if err := os.WriteFile(pOver, over, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReaderPath(pOver, false); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("oversized file: expected ErrSchemaMismatch, got %v", err)
		}

		// Runtime truncation on fallback pread path triggers ErrShortRegion & ErrSchemaMismatch.
		pRun := filepath.Join(t.TempDir(), DefaultFileName)
		if err := os.WriteFile(pRun, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := OpenReaderPath(pRun, true)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := os.Truncate(pRun, 512); err != nil {
			t.Fatal(err)
		}
		var snap Snapshot
		readErr := r.ReadInto(&snap)
		if !errors.Is(readErr, ErrShortRegion) || !errors.Is(readErr, ErrSchemaMismatch) {
			t.Fatalf("runtime truncated ReadInto: expected ErrShortRegion & ErrSchemaMismatch, got %v", readErr)
		}

		// Unknown garbage magic triggers ErrBadMagic.
		pBad := filepath.Join(t.TempDir(), DefaultFileName)
		bad := make([]byte, FileSize)
		copy(bad[0:8], "GARBAGE!")
		if err := os.WriteFile(pBad, bad, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReaderPath(pBad, false); !errors.Is(err, ErrBadMagic) {
			t.Fatalf("expected ErrBadMagic, got %v", err)
		}
	})
}

func TestSeqLockZeroDirtyFramePollutionAndMax126ConcurrentStress(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Verify destination Snapshot is untouched if both slots have mismatched BeginSeq/EndSeq.
	tDir := t.TempDir()
	tPath := filepath.Join(tDir, DefaultFileName)
	tw, err := OpenWriterPath(tPath, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Write(5000, 3, 1, sampleDevices())
	_ = tw.Write(6000, 4, 2, sampleDevices())
	_ = tw.Close()

	tornRaw, err := os.ReadFile(tPath)
	if err != nil {
		t.Fatal(err)
	}
	for sIdx := 0; sIdx < 2; sIdx++ {
		sOff := HeaderSize + sIdx*SlotSize
		// BeginSeq is even (8), payload mutated, but EndSeq differs (6) -> torn frame!
		binary.LittleEndian.PutUint64(tornRaw[sOff:sOff+8], 8)
		binary.LittleEndian.PutUint64(tornRaw[sOff+SlotHeaderSize+32:sOff+SlotHeaderSize+40], 0xbad0bad0bad0bad0)
		binary.LittleEndian.PutUint64(tornRaw[sOff+slotEndSeqOff:sOff+SlotSize], 6)
	}
	if err := os.WriteFile(tPath, tornRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := OpenReaderPath(tPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	var preserved Snapshot
	preserved.Header.Seq = 777
	preserved.Devices[0].RxBytes = 0x1122334455667788
	if err := tr.ReadInto(&preserved); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("expected ErrUninitialized when both slots torn, got %v", err)
	}
	if preserved.Header.Seq != 777 || preserved.Devices[0].RxBytes != 0x1122334455667788 {
		t.Fatalf("caller buffer polluted by torn frame: seq=%d rx=0x%x", preserved.Header.Seq, preserved.Devices[0].RxBytes)
	}

	// Test MaxDevices (126) cap.
	many := make([]DeviceSlot, 140)
	for i := range many {
		many[i] = DeviceSlot{
			MAC:         [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, byte(i + 1)},
			IPv4:        [4]byte{192, 168, 43, byte((i % 250) + 2)},
			RxBytes:     uint64(i+1) * 1024,
			TxBytes:     uint64(i+1) * 512,
			ActiveFlows: uint32(i + 1),
			Flags:       FlagOnline | FlagIPv4,
		}
	}
	if err := w.WriteWithHostFlows(MonotonicNs(), 150, 260, 3, 0, many); err != nil {
		t.Fatal(err)
	}

	var snap Snapshot
	if err := r.ReadInto(&snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.ValidDevices()) != MaxDevices || snap.Header.HostFlows != 260 {
		t.Fatalf("capped devices=%d want %d, hostFlows=%d want 260", len(snap.ValidDevices()), MaxDevices, snap.Header.HostFlows)
	}

	// Zero-allocation & sub-microsecond read check when mmapped.
	if r.IsMmapped() {
		allocs := testing.AllocsPerRun(200, func() {
			if err := r.ReadInto(&snap); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Fatalf("ReadInto allocs=%v want 0", allocs)
		}
		start := time.Now()
		const iters = 2000
		for i := 0; i < iters; i++ {
			if err := r.ReadInto(&snap); err != nil {
				t.Fatal(err)
			}
		}
		avgNs := time.Since(start).Nanoseconds() / iters
		t.Logf("mmap ReadInto avg=%d ns/op (%d devices)", avgNs, MaxDevices)
	}

	// Concurrent writer + 6 lock-free readers across full 126-device frames: verify zero torn counters.
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		batch := make([]DeviceSlot, MaxDevices)
		for step := uint64(1); !stop.Load(); step++ {
			cnt := int(step%MaxDevices) + 1
			flows := uint32((step % 97) + 1)
			hostFlows := flows*7 + 3
			leaks := uint64(flows) * 13
			for idx := 0; idx < cnt; idx++ {
				rx := step*1000 + uint64(idx)
				batch[idx] = DeviceSlot{
					MAC:         [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, byte(idx + 1)},
					RxBytes:     rx,
					TxBytes:     rx*3 + 7,
					ActiveFlows: uint32(idx + 1),
					Flags:       FlagOnline,
				}
			}
			_ = w.WriteWithHostFlows(MonotonicNs(), flows, hostFlows, leaks, 0, batch[:cnt])
			runtime.Gosched()
		}
	}()

	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local Snapshot
			for i := 0; i < 1500; i++ {
				if err := r.ReadInto(&local); err != nil {
					t.Errorf("concurrent ReadInto failed: %v", err)
					return
				}
				devs := local.ValidDevices()
				if len(devs) > 0 && devs[0].MAC[1] == 0xaa {
					if local.Header.TotalLeaks != uint64(local.Header.ActiveFlows)*13 ||
						local.Header.HostFlows != local.Header.ActiveFlows*7+3 {
						t.Errorf("torn header invariant: flows=%d hostFlows=%d leaks=%d",
							local.Header.ActiveFlows, local.Header.HostFlows, local.Header.TotalLeaks)
						return
					}
					baseStep := devs[0].RxBytes / 1000
					for idx, d := range devs {
						wantRx := baseStep*1000 + uint64(idx)
						wantTx := wantRx*3 + 7
						if d.RxBytes != wantRx || d.TxBytes != wantTx || d.MAC[5] != byte(idx+1) {
							t.Errorf("torn device[%d] frame: got rx=%d tx=%d mac5=%d want rx=%d tx=%d",
								idx, d.RxBytes, d.TxBytes, d.MAC[5], wantRx, wantTx)
							return
						}
					}
				}
			}
		}()
	}
	time.Sleep(35 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}

func TestClockBoottimeY2038Gettime64AndFallback(t *testing.T) {
	m1 := MonotonicNs()
	m2 := MonotonicNs()
	if m1 <= 0 || m2 < m1 {
		t.Fatalf("non-monotonic clock values: m1=%d m2=%d", m1, m2)
	}

	// Simulate 32-bit post-Y2038 timestamp (> 2^31-1 seconds = 2_500_000_000s).
	calledLegacy := false
	ns64, ok := queryBoottimeNsWith(
		true,
		func(ts *[2]int64) syscall.Errno {
			ts[0] = 2_500_000_000
			ts[1] = 123_456_789
			return 0
		},
		func(_ *syscall.Timespec) syscall.Errno {
			calledLegacy = true
			return 0
		},
	)
	if !ok || calledLegacy || ns64 != 2_500_000_000*int64(time.Second)+123_456_789 {
		t.Fatalf("unexpected 64-bit boottime result: ok=%v legacy=%v ns=%d", ok, calledLegacy, ns64)
	}

	// Fallback to SYS_CLOCK_GETTIME must trigger ONLY on ENOSYS.
	nsFallback, ok := queryBoottimeNsWith(
		true,
		func(_ *[2]int64) syscall.Errno { return syscall.ENOSYS },
		func(ts *syscall.Timespec) syscall.Errno {
			ts.Sec = 4200
			ts.Nsec = 500
			return 0
		},
	)
	if !ok || nsFallback != 4200*int64(time.Second)+500 {
		t.Fatalf("ENOSYS fallback failed: ok=%v ns=%d", ok, nsFallback)
	}

	// Non-ENOSYS error must NOT call legacy clock_gettime.
	calledLegacyOnEinval := false
	_, ok = queryBoottimeNsWith(
		true,
		func(_ *[2]int64) syscall.Errno { return syscall.EINVAL },
		func(_ *syscall.Timespec) syscall.Errno {
			calledLegacyOnEinval = true
			return 0
		},
	)
	if ok || calledLegacyOnEinval {
		t.Fatalf("expected non-ENOSYS error to skip legacy syscall: ok=%v called=%v", ok, calledLegacyOnEinval)
	}
}
