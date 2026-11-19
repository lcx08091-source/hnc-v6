// inotify_watch.go — HNC v5.38.0: Linux inotify 零轮询唤醒器 (无 unsafe 对齐风险 / 32 位 ARM 安全)
package main

import (
	"context"
	"encoding/binary"
	"os"
	"syscall"
)

func startRunDirInotify(ctx context.Context, runDir string, notifyCh chan<- string) bool {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return false
	}
	const mask = syscall.IN_MOVED_TO | syscall.IN_CLOSE_WRITE | syscall.IN_CREATE | syscall.IN_DELETE
	if _, err := syscall.InotifyAddWatch(fd, runDir, mask); err != nil {
		_ = syscall.Close(fd)
		return false
	}
	f := os.NewFile(uintptr(fd), "dpid-run-inotify")
	go func() {
		done := make(chan struct{})
		defer close(done)
		defer f.Close()
		go func() {
			select {
			case <-ctx.Done():
				_ = f.Close()
			case <-done:
			}
		}()
		var buf [4096]byte
		for {
			n, err := f.Read(buf[:])
			if err != nil {
				return
			}
			off := 0
			for off+syscall.SizeofInotifyEvent <= n {
				// struct inotify_event: wd(int32,0..4), mask(uint32,4..8), cookie(uint32,8..12), len(uint32,12..16)
				evLen := binary.LittleEndian.Uint32(buf[off+12 : off+16])
				hdrEnd := off + syscall.SizeofInotifyEvent
				if evLen > uint32(n-hdrEnd) {
					break
				}
				endOff := hdrEnd + int(evLen)
				raw := buf[hdrEnd:endOff]
				end := 0
				for end < len(raw) && raw[end] != 0 {
					end++
				}
				name := string(raw[:end])
				switch name {
				case "self_studio.poke", "self_capture.enabled", "self_runtime.json", "dpi_rules.reload", "dpi_fp_compiled.json":
					select {
					case notifyCh <- name:
					default:
					}
				}
				off = endOff
			}
		}
	}()
	return true
}
