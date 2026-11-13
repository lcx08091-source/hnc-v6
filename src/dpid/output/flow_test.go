package output

import (
	"fmt"
	"testing"
	"time"
)

// v5.9.7: O(1) 全局流计数依赖 observe 的 created 标志与 evict 的删除回报,
// 这里锁定这两个语义(计数漂移会让 enforceGlobalFlowLimitLocked 判错)。

func TestObserveCreatedFlag(t *testing.T) {
	ft := newFlowTracker()
	now := int64(1700000000)
	if _, created, _ := ft.observe("T|1.1.1.1:443", now, 100); !created {
		t.Fatal("first observe must report created=true")
	}
	if _, created, _ := ft.observe("T|1.1.1.1:443", now+1, 100); created {
		t.Fatal("second observe on same flow must report created=false")
	}
	if _, created, _ := ft.observe("U|1.1.1.1:443", now+2, 100); !created {
		t.Fatal("different flow key (proto prefix) must report created=true")
	}
}

func TestEvictOldestReturnsRemovedCount(t *testing.T) {
	ft := newFlowTracker()
	now := int64(1700000000)
	// 填满 maxFlowsPerClient 条(全部活跃 → idle 清不掉, 走活跃度删除)
	for i := 0; i < maxFlowsPerClient; i++ {
		key := string(rune('a'+i%26)) + "|" + string(rune('0'+i/26)) + ":443"
		ft.observe(key, now, uint64(1000-i)) // 递减活跃度(三返回值可丢弃)
	}
	if len(ft.flows) != maxFlowsPerClient {
		t.Fatalf("setup: got %d flows", len(ft.flows))
	}
	// 新 key 触发 evictOldest: 删 1 条最不活跃 → 总数回到 cap;
	// observe 必须回报 evicted(计数器回扣, 防 totalActiveFlows 单向漂移)
	_, _, evicted := ft.observe("T|9.9.9.9:443", now, 1)
	if evicted != 1 {
		t.Fatalf("observe must report evicted count: got %d, want 1", evicted)
	}
	if len(ft.flows) != maxFlowsPerClient {
		t.Fatalf("after overflow: got %d flows, want %d", len(ft.flows), maxFlowsPerClient)
	}
	if _, ok := ft.flows["a|9:443"]; ok {
		t.Fatal("least-active flow should have been evicted")
	}
}

func TestGlobalEvictBudget(t *testing.T) {
	ft := newFlowTracker()
	now := int64(1700000000)
	for i := 0; i < 30; i++ {
		ft.observe(string(rune('a'+i/10))+"|x:44"+string(rune('0'+i%10)), now, uint64(i))
	}
	if removed := ft.globalEvict(now, 10); len(ft.flows) != 10 || removed == 0 {
		t.Fatalf("globalEvict: got %d flows (removed=%d), want 10", len(ft.flows), removed)
	}
	if removed := ft.globalEvict(now, 0); len(ft.flows) != 0 || removed != 10 {
		t.Fatalf("zero budget: got %d flows (removed=%d), want empty", len(ft.flows), removed)
	}
}

func TestWriterEnforcesGlobalFlowLimitAcrossClients(t *testing.T) {
	w := NewWriter("unused", "test")
	now := time.Unix(1700000010, 0)
	for client := 0; client < 10; client++ {
		mac := fmt.Sprintf("aa:bb:cc:dd:ee:%02x", client)
		ip := fmt.Sprintf("192.168.43.%d", client+2)
		w.RecordDNS(mac, ip, "192.168.43.1", "example.com", now)
		for flow := 0; flow < maxFlowsPerClient; flow++ {
			w.RecordFlow(mac, ip, fmt.Sprintf("203.0.113.%d", flow+1), false, 443, 100, true, now)
			if w.totalActiveFlows > maxGlobalFlows {
				t.Fatalf("global limit exceeded: %d > %d", w.totalActiveFlows, maxGlobalFlows)
			}
		}
	}
	actual := 0
	for _, c := range w.clients {
		if c.Flows != nil {
			actual += len(c.Flows.flows)
		}
	}
	if actual != w.totalActiveFlows || actual != maxGlobalFlows {
		t.Fatalf("actual=%d counter=%d limit=%d", actual, w.totalActiveFlows, maxGlobalFlows)
	}
}

func TestPersistenceAgesWithoutNewPackets(t *testing.T) {
	ft := newFlowTracker()
	now := int64(1700000010) // 30-second bucket boundary
	for i := 0; i < bucketCount; i++ {
		ft.observe("T|203.0.113.1:443", now+int64(i*bucketSeconds), 100)
	}
	f := ft.flows["T|203.0.113.1:443"]
	if got := f.persistencePct(now + 450); got != 1 {
		t.Fatalf("setup persistence=%g, want 1", got)
	}
	if got := f.persistencePct(now + 540); got != 13.0/16.0 {
		t.Fatalf("after three empty buckets=%g, want 13/16", got)
	}
	if got := f.persistencePct(now + 930); got != 0 {
		t.Fatalf("expired buckets counted: %g", got)
	}
	if got := ft.backgroundShare(now + 3600); got != 0 {
		t.Fatalf("idle flow still reported as background: %g", got)
	}
}
