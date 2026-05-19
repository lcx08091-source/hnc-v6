// gofork_probe.go - Go 版 fork+exec 测试程序
// 编译: CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o gofork_probe gofork_probe.go
// 用途: 验证当前内核是否拦截 Go runtime 的 clone(CLONE_VM|CLONE_VFORK) 调用.
//      如果这个程序报 EPERM, 说明命中了 ColorOS 16 / SukiSU 类的 kernel hook.
//      此时模块应自动走 C launcher 路径绕过.

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	target := "/system/bin/id"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Printf("[go-probe] testing fork+exec %s\n", target)
	out, err := exec.Command(target).Output()
	if err != nil {
		fmt.Printf("[go-probe] FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[go-probe] OK: %s", out)
}
