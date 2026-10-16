// hnc_paths.go — 运行期数据文件的查找顺序(v5.33: 原来 DPI 规则 3 份、模块目录 5 份
// 各写各的, 合成这一份)。
package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// defaultModuleDir 模块的默认安装位置(run/service.path 不在时用)。
const defaultModuleDir = "/data/adb/modules/hotspot_network_control"

// moduleDir 模块目录: run/service.path(service.sh 开机写入)> 默认安装位置。
func moduleDir(hncDir string) string {
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "service.path")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return defaultModuleDir
}

// dataCandidates 一份随模块发布、开机同步到运行目录的数据(文件或目录)的查找顺序:
// <hnc>/etc/<rel>(运行副本, dpid / 脚本读的就是它)> <模块>/data/<rel>(出厂, 运行副本
// 还没同步时)> <hnc>/data/<rel>。
func dataCandidates(hncDir, rel string) []string {
	return []string{
		filepath.Join(hncDir, "etc", rel),
		filepath.Join(moduleDir(hncDir), "data", rel),
		filepath.Join(hncDir, "data", rel),
	}
}

// dpiRuleFiles 与 dpid 同源的 DPI 规则文件: 按 dataCandidates 顺序第一个有 *.json 的
// dpi_rules.d 目录, 文件名排序(00- … 99-, dpid 同样按这个顺序合并)。都没有 → nil。
// v5.33: 删掉了单文件 dpi_rules.json(规则目录的逐字节派生副本)的各种退路。
func dpiRuleFiles(hncDir string) []string {
	for _, dir := range dataCandidates(hncDir, "dpi_rules.d") {
		if fs, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(fs) > 0 {
			sort.Strings(fs)
			return fs
		}
	}
	return nil
}
