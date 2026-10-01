//go:build arm

package bytestats

// sysBPF 是 bpf(2) 在 32 位 ARM EABI 上的系统调用号。
// v5.22: 此前全包硬编码 280(arm64 号),在 armeabi-v7a 上 280 = waitid,
// 会把 bpf 命令错发给 waitid —— 必须按架构分开。
const sysBPF uintptr = 386
