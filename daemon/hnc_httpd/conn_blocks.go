// conn_blocks.go — v5.16 按设备封锁域名 / IP(从「实时连接」里一键封锁)
//
//   data/conn_blocks.json: {"items":[{"mac","kind":"domain"|"ip","value","label","ts"}]}
//   run/conn_blocks.flat:  展开后的 "<mac> <ip>" 每行一条, 交给 bin/connblock_sync.sh
//
// 域名封锁按 dpid 的 DNS/SNI 反查表(dpi_ipname.json + nDPI ip_to_host.json)展开:
// 名字等于该域名或是它的子域名的 IP 全部拦掉。App 换 IP 时反查表会更新, 后台
// (AppUsageLoop 每 10 秒)重新展开, 结果变了才重跑脚本。
// 局限: 反查表里还没出现过的新 IP 在第一次连接时拦不住, 直到 DNS/SNI 被看到
// (通常就是那次连接本身, 几秒后生效)。

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type connBlock struct {
	MAC   string `json:"mac"`
	Kind  string `json:"kind"` // domain | ip
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	Ts    int64  `json:"ts"`
}

type connBlockFile struct {
	Items []connBlock `json:"items"`
}

const connBlockMaxItems = 200
const connBlockMaxIPsPerDomain = 200

var connBlockMu sync.Mutex // 串行化读改写 + 展开/同步

func connBlocksPath(hncDir string) string { return filepath.Join(hncDir, "data", "conn_blocks.json") }
func connBlocksFlat(hncDir string) string { return filepath.Join(hncDir, "run", "conn_blocks.flat") }

func readConnBlocks(hncDir string) connBlockFile {
	var f connBlockFile
	if b, err := os.ReadFile(connBlocksPath(hncDir)); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	return f
}

// expandConnBlocks 把封锁项展开成排好序的 "mac ip" 行
func (s *server) expandConnBlocks(f connBlockFile) []string {
	var names map[string]ipName
	set := map[string]bool{}
	for _, it := range f.Items {
		switch it.Kind {
		case "ip":
			if ip := net.ParseIP(it.Value); ip != nil {
				set[it.MAC+" "+ip.String()] = true
			}
		case "domain":
			if names == nil {
				names = s.loadIPNames()
			}
			d := strings.ToLower(it.Value)
			n := 0
			for ip, nm := range names {
				h := strings.ToLower(nm.Name)
				if h == d || strings.HasSuffix(h, "."+d) {
					set[it.MAC+" "+ip] = true
					if n++; n >= connBlockMaxIPsPerDomain {
						break
					}
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// connBlockSyncLocked 重新展开; 与现有 flat 不同(或 force)才写文件并跑脚本
func (s *server) connBlockSyncLocked(force bool) (string, error) {
	lines := s.expandConnBlocks(readConnBlocks(s.hncDir))
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	old, _ := os.ReadFile(connBlocksFlat(s.hncDir))
	if !force && string(old) == content {
		return "", nil
	}
	if err := discoverWriteAtomic(connBlocksFlat(s.hncDir), []byte(content)); err != nil {
		return "", err
	}
	rc, out := runBin(s.hncDir, "connblock_sync.sh")
	out = lastLine(strings.TrimSpace(out))
	if rc != 0 {
		return out, os.ErrInvalid
	}
	return out, nil
}

// connBlockRefresh 后台调用: 反查表变了就重新同步
func (s *server) connBlockRefresh() {
	connBlockMu.Lock()
	defer connBlockMu.Unlock()
	if len(readConnBlocks(s.hncDir).Items) == 0 {
		if st, err := os.Stat(connBlocksFlat(s.hncDir)); err != nil || st.Size() == 0 {
			return
		}
	}
	_, _ = s.connBlockSyncLocked(false)
}

var domainRe = suffixRe

func actionConnBlockAdd(s *server, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	kind := strings.TrimSpace(p["kind"])
	val := strings.ToLower(strings.TrimSpace(p["value"]))
	if !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	switch kind {
	case "ip":
		ip := net.ParseIP(val)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid ip"}
		}
		if isPrivateIP(val) {
			return actionResp{OK: false, Error: "bad params", Detail: "不能封锁局域网地址"}
		}
		val = ip.String()
	case "domain":
		val = strings.TrimPrefix(val, "*.")
		if !domainRe.MatchString(val) || len(val) > 253 {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid domain"}
		}
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "kind must be domain|ip"}
	}
	label := strings.TrimSpace(p["label"])
	if len([]rune(label)) > 40 {
		label = string([]rune(label)[:40])
	}
	connBlockMu.Lock()
	defer connBlockMu.Unlock()
	f := readConnBlocks(s.hncDir)
	for _, it := range f.Items {
		if it.MAC == mac && it.Kind == kind && it.Value == val {
			return actionResp{OK: true, Detail: "已经封锁过了"}
		}
	}
	if len(f.Items) >= connBlockMaxItems {
		return actionResp{OK: false, Error: "too many", Detail: "封锁项已达上限 200"}
	}
	f.Items = append(f.Items, connBlock{MAC: mac, Kind: kind, Value: val, Label: label, Ts: time.Now().Unix()})
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := discoverWriteAtomic(connBlocksPath(s.hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	out, err := s.connBlockSyncLocked(true)
	if err != nil {
		return actionResp{OK: false, Error: "sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

func actionConnBlockDel(s *server, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	kind := strings.TrimSpace(p["kind"])
	val := strings.ToLower(strings.TrimSpace(p["value"]))
	connBlockMu.Lock()
	defer connBlockMu.Unlock()
	f := readConnBlocks(s.hncDir)
	kept := f.Items[:0]
	found := false
	for _, it := range f.Items {
		if it.MAC == mac && it.Kind == kind && it.Value == val {
			found = true
			continue
		}
		kept = append(kept, it)
	}
	if !found {
		return actionResp{OK: false, Error: "not found"}
	}
	f.Items = kept
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := discoverWriteAtomic(connBlocksPath(s.hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	out, err := s.connBlockSyncLocked(true)
	if err != nil {
		return actionResp{OK: false, Error: "sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

// connBlocksFor 某台设备的封锁项(给 /api/connections 与设备卡用)
func connBlocksFor(hncDir, mac string) []connBlock {
	var out []connBlock
	for _, it := range readConnBlocks(hncDir).Items {
		if it.MAC == mac {
			out = append(out, it)
		}
	}
	return out
}
