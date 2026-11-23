// detached_stub.go · non-Linux/Android stub for detachedSysProcAttr.

//go:build !linux && !android

package main

import (
	"os/exec"
	"syscall"
)

func detachedSysProcAttr() *syscall.SysProcAttr {
	return nil
}

func hardenCmdSysProc(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			killCmdProcessGroup(cmd)
			return nil
		}
	}
}

func killCmdProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
