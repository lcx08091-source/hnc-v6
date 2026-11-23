package bytestats

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestSamplerEBPF64BitAlignment(t *testing.T) {
	if off := unsafe.Offsetof(EBPFSampler{}.val); off != 0 {
		t.Fatalf("EBPFSampler.val offset = %d, want 0", off)
	}
	if al := unsafe.Alignof(EBPFSampler{}); al != 8 {
		t.Fatalf("EBPFSampler align = %d, want 8", al)
	}
	if off := unsafe.Offsetof(TetheringStatsSampler{}.val); off != 0 {
		t.Fatalf("TetheringStatsSampler.val offset = %d, want 0", off)
	}
	if al := unsafe.Alignof(TetheringStatsSampler{}); al != 8 {
		t.Fatalf("TetheringStatsSampler align = %d, want 8", al)
	}
	if off := unsafe.Offsetof(bpfAttrBuf{}.pad); off != 0 {
		t.Fatalf("bpfAttrBuf.pad offset = %d, want 0", off)
	}
	if sz := unsafe.Sizeof(bpfAttrBuf{}.pad); sz != 120 {
		t.Fatalf("bpfAttrBuf.pad size = %d, want 120", sz)
	}
	if al := unsafe.Alignof(bpfAttrBuf{}); al != 8 {
		t.Fatalf("bpfAttrBuf align = %d, want 8", al)
	}

	// 验证堆分配实例在 32 位 armeabi-v7a 与 64 位 arm64 下运行时真实指针 8 字节对齐,
	// 并对 64 位字段执行真实原子读写确认不会触发 SIGBUS 或未对齐 panic。
	for i := 0; i < 32; i++ {
		_ = new(byte) // 制造堆偏移扰动
		es := new(EBPFSampler)
		if addr := uintptr(unsafe.Pointer(&es.val)); addr%8 != 0 {
			t.Fatalf("heap EBPFSampler.val address 0x%x not 8-byte aligned", addr)
		}
		atomic.StoreUint64(&es.val.RxPackets, 1)
		atomic.StoreUint64(&es.val.RxBytes, 2)
		atomic.StoreUint64(&es.val.TxPackets, 3)
		atomic.StoreUint64(&es.val.TxBytes, 4)
		if got := atomic.LoadUint64(&es.val.TxBytes); got != 4 {
			t.Fatalf("atomic load TxBytes = %d, want 4", got)
		}

		ts := new(TetheringStatsSampler)
		if addr := uintptr(unsafe.Pointer(&ts.val)); addr%8 != 0 {
			t.Fatalf("heap TetheringStatsSampler.val address 0x%x not 8-byte aligned", addr)
		}
		atomic.StoreUint64(&ts.val.Extra1, 9)
		if got := atomic.LoadUint64(&ts.val.Extra1); got != 9 {
			t.Fatalf("atomic load Extra1 = %d, want 9", got)
		}

		attr := new(bpfAttrBuf)
		if addr := uintptr(unsafe.Pointer(&attr.pad[0])); addr%8 != 0 {
			t.Fatalf("heap bpfAttrBuf.pad[0] address 0x%x not 8-byte aligned", addr)
		}
	}
}
