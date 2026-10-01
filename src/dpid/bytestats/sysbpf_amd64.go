//go:build amd64

package bytestats

// sysBPF 是 bpf(2) 在 x86_64 上的系统调用号(仅 host 单测编译用)。
const sysBPF uintptr = 321
