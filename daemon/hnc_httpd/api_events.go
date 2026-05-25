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
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (s *server) apiEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	// SSE 是长连接:必须清掉 WriteTimeout(httpsSrv 配了 60s),否则 60s 被掐断。
	// middleware 不包裹 w,ResponseController 能直达底层 conn。
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sse unsupported"})
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // 防中间代理缓冲
	w.WriteHeader(http.StatusOK)

	write := func(payload string) bool {
		if _, err := io.WriteString(w, payload); err != nil {
			return false
		}
		return rc.Flush() == nil
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

	poll := time.NewTicker(1500 * time.Millisecond)
	defer poll.Stop()
	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			if !write(": hb\n\n") { // 注释行心跳,保活 + 探测断连
				return
			}
		case <-poll.C:
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
