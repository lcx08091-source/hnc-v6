//go:build !arm64 && !arm && !amd64 && !386

package bytestats

// sysBPF: 未知架构 —— 用一个必然不存在的调用号, 内核返回 ENOSYS,
// 采样器随之回落到 dumpsys 后端(与 BPF_OBJ_GET 失败同一路径)。
const sysBPF = ^uintptr(0)
