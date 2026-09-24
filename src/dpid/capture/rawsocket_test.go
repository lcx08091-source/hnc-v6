package capture

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func dgramPair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	tv := syscall.Timeval{Usec: 100_000}
	_ = syscall.SetsockoptTimeval(fds[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return fds[0], fds[1]
}

// v5.12: 模拟 Rebind 换 fd —— Run 必须返回 ErrRebound, 旧 fd 不得在 Run 仍可能
// 使用它时被关闭, 由 Close() 统一回收。
func TestRun_ReturnsErrReboundAfterSwap(t *testing.T) {
	a, aPeer := dgramPair(t)
	b, bPeer := dgramPair(t)
	defer syscall.Close(aPeer)
	defer syscall.Close(bPeer)

	h := &Handle{fd: a, snap: 256, buf: make([]byte, 320)}
	done := make(chan error, 1)
	go func() { done <- h.Run(context.Background(), func(Event) {}) }()

	time.Sleep(50 * time.Millisecond)
	// 与 Rebind 的交换段一致。
	h.mu.Lock()
	h.retired = append(h.retired, h.fd)
	h.fd = b
	h.rebound = true
	h.mu.Unlock()

	select {
	case err := <-done:
		if !errors.Is(err, ErrRebound) {
			t.Fatalf("want ErrRebound, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run 未在换 fd 后返回")
	}
	// 旧 fd 此时仍应有效(未被提前关闭)。
	if _, err := syscall.GetsockoptInt(a, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil {
		t.Fatalf("旧 fd 被提前关闭: %v", err)
	}
	h.Close()
	if _, err := syscall.GetsockoptInt(a, syscall.SOL_SOCKET, syscall.SO_TYPE); err == nil {
		t.Fatal("Close 后旧 fd 应已关闭")
	}
	if _, err := syscall.GetsockoptInt(b, syscall.SOL_SOCKET, syscall.SO_TYPE); err == nil {
		t.Fatal("Close 后新 fd 应已关闭")
	}
}
