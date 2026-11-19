//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

// sysPidfdSendSignal 为 Linux 5.1+ 全架构通用系统调用号 (arm64 / arm EABI / amd64 / 386 / riscv64 均为 424)。
const sysPidfdSendSignal uintptr = 424

// pidfdProcessAlive 基于 Go 1.26+ 标准库 os.Process.WithHandle 对子进程绑定的内核 pidfd 执行无锁存活探测,
// 彻底消除数字 PID 回绕复用导致的误判活, 且全程零 unsafe 依赖。
//
// 返回值:
//   - (true,  true)  : 内核 pidfd 确认该子进程实例仍在运行且非僵尸态 ('Z')
//   - (false, true)  : 内核 pidfd 或 Wait 状态确认该子进程实例已退出或处于僵尸态
//   - (false, false) : 当前内核或运行时不支持 pidfd (如 os.ErrNoHandle / ENOSYS), 调用方回退 /proc 判活
func pidfdProcessAlive(p *os.Process) (alive bool, supported bool) {
	if p == nil || p.Pid <= 0 {
		return false, false
	}

	var innerAlive bool
	var innerSupported bool

	err := p.WithHandle(func(handle uintptr) {
		_, _, errno := syscall.RawSyscall6(sysPidfdSendSignal, handle, 0, 0, 0, 0, 0)
		switch errno {
		case 0, syscall.EPERM:
			innerSupported = true
			innerAlive = !isZombie(p.Pid)
		case syscall.ESRCH:
			innerSupported = true
			innerAlive = false
		case syscall.ENOSYS:
			innerSupported = false
			innerAlive = false
		default:
			innerSupported = false
			innerAlive = false
		}
	})

	if err == nil {
		return innerAlive, innerSupported
	}
	if errors.Is(err, os.ErrProcessDone) {
		return false, true
	}
	if errors.Is(err, os.ErrNoHandle) {
		return false, false
	}
	return false, false
}

// pidfdAlive 为 pidfdProcessAlive 的同义辅助入口。
func pidfdAlive(p *os.Process) (alive bool, supported bool) {
	return pidfdProcessAlive(p)
}
