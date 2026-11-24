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
	if off := unsafe.Offsetof(NetdDetailSampler{}.val); off != 0 {
		t.Fatalf("NetdDetailSampler.val offset = %d, want 0", off)
	}
	if al := unsafe.Alignof(NetdDetailSampler{}); al != 8 {
		t.Fatalf("NetdDetailSampler align = %d, want 8", al)
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

		ns := new(NetdDetailSampler)
		if addr := uintptr(unsafe.Pointer(&ns.val)); addr%8 != 0 {
			t.Fatalf("heap NetdDetailSampler.val address 0x%x not 8-byte aligned", addr)
		}
		atomic.StoreUint64(&ns.val.RxPackets, 11)
		atomic.StoreUint64(&ns.val.RxBytes, 22)
		atomic.StoreUint64(&ns.val.TxPackets, 33)
		atomic.StoreUint64(&ns.val.TxBytes, 44)
		atomic.StoreUint64(&ns.val.Extra[3], 55)
		if got := atomic.LoadUint64(&ns.val.Extra[3]); got != 55 {
			t.Fatalf("atomic load NetdDetailSampler.val.Extra[3] = %d, want 55", got)
		}

		attr := new(bpfAttrBuf)
		if addr := uintptr(unsafe.Pointer(&attr.pad[0])); addr%8 != 0 {
			t.Fatalf("heap bpfAttrBuf.pad[0] address 0x%x not 8-byte aligned", addr)
		}
	}
}

func TestNetdDetailSchemaAndIfaceFilters(t *testing.T) {
	if !validDetailAppUIDSchema(4, 32) || !validDetailAppUIDSchema(4, 48) {
		t.Fatal("expected KeySize=4 ValueSize=32/48 to pass app_uid_stats_map schema check")
	}
	if validDetailAppUIDSchema(16, 32) || validDetailAppUIDSchema(4, 24) {
		t.Fatal("expected invalid app_uid_stats_map schema to be rejected")
	}
	if !validDetailStatsABSchema(16, 32) || !validDetailStatsABSchema(16, 40) {
		t.Fatal("expected KeySize=16 ValueSize=32/40 to pass stats_map_A/B schema check")
	}
	if validDetailStatsABSchema(4, 32) {
		t.Fatal("expected KeySize=4 to be rejected for stats_map_A/B")
	}
	if !validDetailCounterSetSchema(4, 1) || !validDetailCounterSetSchema(4, 4) {
		t.Fatal("expected KeySize=4 ValueSize=1/4 to pass uid_counterset_map schema check")
	}
	if !validDetailIfaceNameSchema(4, 16) {
		t.Fatal("expected KeySize=4 ValueSize=16 to pass iface_index_name_map schema check")
	}

	for _, ex := range []string{"lo", "tun0", "tun10", "v4-rmnet_data2", "v4-wlan0", "wg0", "utun2", "sing_tun0"} {
		if !ShouldExcludeNetdIface(ex) {
			t.Fatalf("ShouldExcludeNetdIface(%q) = false, want true", ex)
		}
	}
	for _, keep := range []string{"wlan0", "rmnet_data2", "ccmni0", "sipa_eth0", "eth0"} {
		if ShouldExcludeNetdIface(keep) {
			t.Fatalf("ShouldExcludeNetdIface(%q) = true, want false", keep)
		}
	}
	if got := ClassifyNetdIface("rmnet_data2"); got != "mobile" {
		t.Fatalf("ClassifyNetdIface(rmnet_data2) = %q, want mobile", got)
	}
	if got := ClassifyNetdIface("ccmni1"); got != "mobile" {
		t.Fatalf("ClassifyNetdIface(ccmni1) = %q, want mobile", got)
	}
	if got := ClassifyNetdIface("wlan0"); got != "wifi" {
		t.Fatalf("ClassifyNetdIface(wlan0) = %q, want wifi", got)
	}
}
