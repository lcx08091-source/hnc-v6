// detached_linux.go · rc3 N-15
// Linux/Android 下用 Setsid 让 detached 子进程成新 session leader.
// 这样即使父进程(httpd) 被 kill, 子进程也继续跑完.

//go:build linux || android

package main

import "syscall"

func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
