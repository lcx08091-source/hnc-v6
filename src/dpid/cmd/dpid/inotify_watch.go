// inotify_watch.go — HNC v5.37.0: Linux inotify 零轮询唤醒器 (替代 80ms os.Stat 空转轮询)
package main

import (
	"context"
	"os"
	"syscall"
	"unsafe"
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
		defer f.Close()
		go func() {
			<-ctx.Done()
			_ = f.Close()
		}()
		var buf [4096]byte
		for {
			n, err := f.Read(buf[:])
			if err != nil {
				return
			}
			off := 0
			for off+syscall.SizeofInotifyEvent <= n {
				ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
				raw := buf[off+syscall.SizeofInotifyEvent : off+syscall.SizeofInotifyEvent+int(ev.Len)]
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
				off += syscall.SizeofInotifyEvent + int(ev.Len)
			}
		}
	}()
	return true
}
