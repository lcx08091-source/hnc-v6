// api_events.go — v5.7.0-rc44 · Server-Sent Events 推送(仅远程 SPA)。
//
// 为什么只给远程:本机 WebUI 是 file:// + window.ksu.exec(curl),exec 是一次性
// "命令跑完才回调",撑不起 EventSource 这种长连接流式推送 → 本机继续走轮询。
// 远程 SPA 是真浏览器,EventSource 走 https 到本端口,可用。
//
// 机制:服务端每 ~1.5s stat devices.json,mtime 变化时推一个 "changed" 事件;远程
// SPA 收到后做一次它原有的刷新(loadDevices),从而停掉盲目 1Hz 轮询 —— 空闲(无
// 变化)时只发心跳、几乎零开销;有变化时近实时。SPA 在 SSE 失败/不支持时自动回退轮询。

package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

// v5.8.8 (audit): cap concurrent SSE connections. An authenticated (or
// cookie-stolen) client could otherwise open many EventSource streams, each
// holding a goroutine + a 1.5s ticker, to amplify CPU/memory. 64 is far above
// any legitimate use (a few remote tabs).
const (
	maxSSEConns          = 64
	sseTCPUserTimeoutOpt = 18    // Linux TCP_USER_TIMEOUT (<netinet/tcp.h>)
	sseTCPUserTimeoutMs  = 45000 // 45s: 断网半开无 ACK 时加速内核回收僵尸 SSE 连接
)

var sseConns atomic.Int64

type netConnUnwrapper interface {
	NetConn() net.Conn
}

type respWriterUnwrapper interface {
	Unwrap() http.ResponseWriter
}

// setSSETCPUserTimeout 对底层 *net.TCPConn(含 *tls.Conn 包装)经 SyscallConn 设置 TCP_USER_TIMEOUT。
func setSSETCPUserTimeout(conn net.Conn, timeoutMs int) error {
	if conn == nil || timeoutMs <= 0 {
		return nil
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return nil
	}
	for {
		u, ok := conn.(netConnUnwrapper)
		if !ok {
			break
		}
		inner := u.NetConn()
		if inner == nil || inner == conn {
			break
		}
		conn = inner
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok || tcpConn == nil {
		return nil
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, sseTCPUserTimeoutOpt, timeoutMs)
	}); err != nil {
		return err
	}
	return sockErr
}

func extractSysfdFromTCPValue(v reflect.Value) (int, bool) {
	for v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) {
		if v.IsNil() {
			return -1, false
		}
		if v.Kind() == reflect.Pointer && v.Type().String() == "*tls.Conn" {
			elem := v.Elem()
			if elem.Kind() == reflect.Struct {
				v = elem.FieldByName("conn")
				continue
			}
		}
		if v.Kind() == reflect.Pointer && v.Type().String() == "*net.TCPConn" {
			if v.CanInterface() {
				if tc, ok := v.Interface().(*net.TCPConn); ok {
					_ = setSSETCPUserTimeout(tc, sseTCPUserTimeoutMs)
					return -1, false
				}
			}
			elem := v.Elem()
			if elem.Kind() != reflect.Struct {
				return -1, false
			}
			fdField := elem.FieldByName("fd")
			if !fdField.IsValid() || fdField.Kind() != reflect.Pointer || fdField.IsNil() {
				return -1, false
			}
			pfdField := fdField.Elem().FieldByName("pfd")
			if !pfdField.IsValid() || pfdField.Kind() != reflect.Struct {
				return -1, false
			}
			sysfdField := pfdField.FieldByName("Sysfd")
			if !sysfdField.IsValid() || sysfdField.Kind() != reflect.Int {
				return -1, false
			}
			fd := int(sysfdField.Int())
			return fd, fd >= 0
		}
		v = v.Elem()
	}
	return -1, false
}

func applySSETCPUserTimeoutForResponse(w http.ResponseWriter, timeoutMs int) {
	if w == nil || timeoutMs <= 0 {
		return
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return
	}
	defer func() { _ = recover() }()

	cur := w
	for cur != nil {
		if ncu, ok := cur.(netConnUnwrapper); ok {
			_ = setSSETCPUserTimeout(ncu.NetConn(), timeoutMs)
			return
		}
		uw, ok := cur.(respWriterUnwrapper)
		if !ok {
			break
		}
		next := uw.Unwrap()
		if next == nil || next == cur {
			break
		}
		cur = next
	}
	if cur == nil {
		return
	}
	rv := reflect.ValueOf(cur)
	if !rv.IsValid() || rv.Kind() != reflect.Pointer || rv.IsNil() {
		return
	}
	st := rv.Elem()
	if st.Kind() != reflect.Struct {
		return
	}
	// HTTP/1.1: *http.response -> conn (*http.conn) -> rwc (net.Conn)
	if connField := st.FieldByName("conn"); connField.IsValid() && connField.Kind() == reflect.Pointer && !connField.IsNil() {
		if rwcField := connField.Elem().FieldByName("rwc"); rwcField.IsValid() {
			if fd, ok := extractSysfdFromTCPValue(rwcField); ok {
				_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, sseTCPUserTimeoutOpt, timeoutMs)
				return
			}
		}
	}
	// HTTP/2: *http.http2responseWriter -> rws -> conn -> conn (net.Conn)
	if rwsField := st.FieldByName("rws"); rwsField.IsValid() && rwsField.Kind() == reflect.Pointer && !rwsField.IsNil() {
		if scField := rwsField.Elem().FieldByName("conn"); scField.IsValid() && scField.Kind() == reflect.Pointer && !scField.IsNil() {
			if ncField := scField.Elem().FieldByName("conn"); ncField.IsValid() {
				if fd, ok := extractSysfdFromTCPValue(ncField); ok {
					_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, sseTCPUserTimeoutOpt, timeoutMs)
					return
				}
			}
		}
	}
}

func (s *server) apiEvents(w http.ResponseWriter, r *http.Request) {
	n := sseConns.Add(1)
	if n > maxSSEConns {
		sseConns.Add(-1)
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "too many SSE connections"})
		return
	}
	if n == 1 && !activityNow().WebUIActive {
		activityPoke()
	}
	defer func() {
		if sseConns.Add(-1) == 0 {
			activityPoke()
		}
	}()

	rc := http.NewResponseController(w)
	// SSE 是长连接:必须清掉 WriteTimeout(httpsSrv 配了 60s),否则 60s 被掐断。
	// v5.11: accessLogMiddleware 会把 w 包成 loggingResponseWriter, 它实现了
	// Unwrap(), ResponseController 才能直达底层 conn(此前缺 Unwrap → 恒 500)。
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sse unsupported"})
		return
	}
	applySSETCPUserTimeoutForResponse(w, sseTCPUserTimeoutMs)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // 防中间代理缓冲
	w.WriteHeader(http.StatusOK)

	ctx := r.Context()
	if ctx.Err() != nil {
		return
	}

	write := func(payload string) bool {
		if ctx.Err() != nil {
			return false
		}
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := io.WriteString(w, payload)
		if err == nil {
			err = rc.Flush()
		}
		_ = rc.SetWriteDeadline(time.Time{})
		return err == nil
	}
	// 连上立即发一次,让 SPA 马上拉一遍最新状态。
	if !write("event: changed\ndata: {\"reason\":\"connect\"}\n\n") {
		return
	}

	devicesPath := filepath.Join(s.hncDir, "data", "devices.json")
	lastMod := int64(-1)
	if fi, err := os.Stat(devicesPath); err == nil {
		lastMod = fi.ModTime().UnixNano()
	}

	// v5.22: 基准 1.5s; 热点未开时 5s(设备表几乎不变, power_sched.go sse_poll)
	pollEvery, _ := powerInterval("sse_poll", activityNow(), loopFlags{})
	poll := time.NewTicker(pollEvery)
	defer poll.Stop()
	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()
	simTick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			if !write(": hb\n\n") { // 注释行心跳,保活 + 探测断连
				return
			}
		case <-poll.C:
			if d, _ := powerInterval("sse_poll", activityNow(), loopFlags{}); d != pollEvery && d > 0 {
				pollEvery = d
				poll.Reset(d)
			}
			// 模拟环境: 模拟设备速率一直在变, 每 ~3s 推一次 changed(关闭时不进这里)
			if s.simActive() {
				if simTick++; simTick%2 == 0 && !write("event: changed\ndata: {\"reason\":\"sim\"}\n\n") {
					return
				}
			}
			fi, err := os.Stat(devicesPath)
			if err != nil {
				continue
			}
			m := fi.ModTime().UnixNano()
			if m != lastMod {
				lastMod = m
				if !write("event: changed\ndata: {\"reason\":\"devices\"}\n\n") {
					return
				}
			}
		}
	}
}
