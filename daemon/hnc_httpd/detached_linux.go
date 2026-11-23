// detached_linux.go · rc3 N-15
// Linux/Android 下用 Setsid 让 detached 子进程成新 session leader.
// 这样即使父进程(httpd) 被 kill, 子进程也继续跑完.

//go:build linux || android

package main

import (
	"os/exec"
	"syscall"
)

func detachedSysProcAttr() *syscall.SysProcAttr {
	// Setsid 创建新会话的同时自动使子进程成为新进程组组长(pgid == pid);
	// 注意 Linux 下不可同时置 Setpgid: true, 否则对 session leader 调 setpgid 会报 EPERM。
	return &syscall.SysProcAttr{Setsid: true}
}

// hardenCmdSysProc 为受控子进程启用独立进程组(Setpgid: true),
// 并在 Context 超时取消时向 -pid 进程组发送 SIGKILL 连根清理孙进程, 防止孤儿进程占住管道或全局锁。
func hardenCmdSysProc(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	} else if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
	}
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			killCmdProcessGroup(cmd)
			return nil
		}
	}
}

// killCmdProcessGroup 向子进程所属的整个进程组(-pid)发送 SIGKILL。
func killCmdProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
