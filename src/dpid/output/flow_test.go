package output

import "testing"

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
}
