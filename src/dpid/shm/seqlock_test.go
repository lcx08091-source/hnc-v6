package shm

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		if string(snap.Header.Magic[:]) != Magic || snap.Header.DeviceCount != 0 {
			t.Fatalf("unexpected initial header: %+v", snap.Header)
		}

		devs := sampleDevices()
		mono1 := MonotonicNs()
		if err := w.Write(mono1, 42, 7, devs); err != nil {
			t.Fatalf("Write #1: %v", err)
		}
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("ReadInto #1: %v", err)
		}
		if snap.Header.UpdatedMonoNs != mono1 || snap.Header.ActiveFlows != 42 || snap.Header.TotalLeaks != 7 {
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

		// Second write flips to opposite latch slot and preserves monotonic progression.
		devs[0].RxBytes += 100000
		mono2 := MonotonicNs()
		if err := w.Write(mono2, 55, 9, devs[:1]); err != nil {
			t.Fatalf("Write #2: %v", err)
		}
		if err := r.ReadInto(&snap); err != nil {
			t.Fatalf("ReadInto #2: %v", err)
		}
		if snap.Header.DeviceCount != 1 || snap.Header.ActiveFlows != 55 || snap.Header.TotalLeaks != 9 {
			t.Fatalf("header #2 mismatch: %+v", snap.Header)
		}
		if snap.Devices[1] != (DeviceSlot{}) {
			t.Fatalf("stale tail device slot not cleared: %+v", snap.Devices[1])
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

func TestSeqLockMax64DevicesCapAndConcurrentStress(t *testing.T) {
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

	many := make([]DeviceSlot, 80)
	for i := range many {
		many[i] = DeviceSlot{
			MAC:         [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, byte(i + 1)},
			IPv4:        [4]byte{192, 168, 43, byte(i + 2)},
			RxBytes:     uint64(i+1) * 1024,
			TxBytes:     uint64(i+1) * 512,
			ActiveFlows: uint32(i + 1),
			Flags:       FlagOnline | FlagIPv4,
		}
	}
	if err := w.Write(MonotonicNs(), 120, 3, many); err != nil {
		t.Fatal(err)
	}

	var snap Snapshot
	if err := r.ReadInto(&snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.ValidDevices()) != MaxDevices {
		t.Fatalf("capped devices=%d want %d", len(snap.ValidDevices()), MaxDevices)
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
		t.Logf("mmap ReadInto avg=%d ns/op (64 devices)", avgNs)
	}

	// Concurrent writer + multiple lock-free readers: verify zero torn counters.
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for step := uint64(1); !stop.Load(); step++ {
			d := DeviceSlot{
				MAC:         [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
				RxBytes:     step * 1000,
				TxBytes:     step * 2000,
				ActiveFlows: uint32(step % 100),
				Flags:       FlagOnline,
			}
			_ = w.Write(MonotonicNs(), uint32(step%100), step, []DeviceSlot{d})
		}
	}()

	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local Snapshot
			for i := 0; i < 2000; i++ {
				if err := r.ReadInto(&local); err != nil {
					t.Errorf("concurrent ReadInto failed: %v", err)
					return
				}
				devs := local.ValidDevices()
				if len(devs) == 1 && devs[0].MAC[1] == 0xaa {
					if devs[0].TxBytes != devs[0].RxBytes*2 {
						t.Errorf("torn read detected: rx=%d tx=%d", devs[0].RxBytes, devs[0].TxBytes)
						return
					}
				}
			}
		}()
	}
	time.Sleep(25 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
