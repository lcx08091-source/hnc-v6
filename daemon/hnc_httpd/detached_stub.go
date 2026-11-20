// detached_stub.go · non-Linux/Android stub for detachedSysProcAttr.

//go:build !linux && !android

package main

import "syscall"

func detachedSysProcAttr() *syscall.SysProcAttr {
	return nil
}
