// api_discover_shared.go — v5.30 T1c: 「新发现的应用」排除公共基础设施。
//
// dpid(src/dpid/output/shared_infra.go)已在聚类时把共享基础设施(名单 +
// 频度兜底)排除在成组 / 起名之外。这里是 httpd 一侧:
//   - 读同一份名单(output.ParseSharedInfra / Match, 同一份实现), 再加上
//     dpi_discover.json 顶层 shared_infra 与组的 shared 字段, 把组里的这些域名
//     剔出 suffixes / domains / members, 挂到 shared(前端标「公共服务」);
//     剔完没有自己域名的组不显示 —— 升级前就在列表里的
//     alibabadns.com / cdngslb.com 之类旧组, 不用用户手动忽略就消失;
//   - 起名证据收紧: 证书只有在 SAN / CN 覆盖探测的主机名、且该主机仍属于本组
//     时才当证据; 共享域不参与本机 App / 证书兄弟域 / 组名。
package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"hnc.io/dpid/output"
)

// sharedInfraLabel 前端显示的标签。
const sharedInfraLabel = "公共服务"

var sharedInfraCache struct {
	mu    sync.Mutex
	path  string
	mtime int64
	size  int64
	cur   *output.SharedInfra
}

// sharedInfraPaths 名单查找顺序: 运行目录(随规则同步)> 模块目录 > hncDir/data。
func sharedInfraPaths(hncDir string) []string {
	ps := []string{filepath.Join(hncDir, "etc", "dpi_rules.d", output.SharedInfraFileName)}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "service.path")); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			ps = append(ps, filepath.Join(p, "data", "dpi_rules.d", output.SharedInfraFileName))
		}
	}
	return append(ps, filepath.Join(hncDir, "data", "dpi_rules.d", output.SharedInfraFileName))
}

// loadSharedInfra 第一份存在的名单(按 path + mtime + size 缓存)。都没有 → nil。
func loadSharedInfra(hncDir string) *output.SharedInfra {
	for _, p := range sharedInfraPaths(hncDir) {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() > 256<<10 {
			continue
		}
		c := &sharedInfraCache
		c.mu.Lock()
		if c.path == p && c.mtime == st.ModTime().UnixNano() && c.size == st.Size() && c.cur != nil {
			si := c.cur
			c.mu.Unlock()
			return si
		}
		c.mu.Unlock()
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		si := output.ParseSharedInfra(b)
		c.mu.Lock()
		c.path, c.mtime, c.size, c.cur = p, st.ModTime().UnixNano(), st.Size(), si
		c.mu.Unlock()
		return si
	}
	return nil
}

// sharedJudge 一次 /api/discover 用的判定器: 名单 + dpid 判出的(顶层 + 组内)。
type sharedJudge struct {
	si    *output.SharedInfra
	extra map[string]string // 可注册域 → 原因(dpid 给的)
}

func (j sharedJudge) reason(host string) string {
	if j.si.Match(host) {
		return "list"
	}
	return j.extra[registrable(host)]
}

// sharedFromDiscover dpi_discover.json 顶层 shared_infra(dpid v5.30 起写)。
func sharedFromDiscover(root map[string]interface{}) map[string]string {
	out := map[string]string{}
	addSharedList(out, root["shared_infra"])
	return out
}

func addSharedList(dst map[string]string, v interface{}) {
	l, _ := v.([]interface{})
	for _, x := range l {
		m, _ := x.(map[string]interface{})
		if s := strings.ToLower(asString(m["suffix"])); s != "" {
			r := asString(m["reason"])
			if r == "" {
				r = "list"
			}
			dst[s] = r
		}
	}
}

// filterSharedGroup 剔掉组里的共享域。返回过滤后的组(新 map, 不改入参);
// 剔完没有自己的域名 → ok=false(不显示)。
func filterSharedGroup(g map[string]interface{}, j sharedJudge) (map[string]interface{}, bool) {
	local := sharedJudge{si: j.si, extra: map[string]string{}}
	for k, v := range j.extra {
		local.extra[k] = v
	}
	addSharedList(local.extra, g["shared"])

	type shEntry struct {
		Suffix string `json:"suffix"`
		Reason string `json:"reason"`
		Hits   int64  `json:"hits,omitempty"`
		Label  string `json:"label"`
	}
	shared := map[string]*shEntry{}
	addShared := func(suf, reason string, hits int64) {
		suf = strings.ToLower(suf)
		if e := shared[suf]; e != nil {
			if hits > e.Hits {
				e.Hits = hits
			}
			return
		}
		shared[suf] = &shEntry{Suffix: suf, Reason: reason, Hits: hits, Label: sharedInfraLabel}
	}
	if l, ok := g["shared"].([]interface{}); ok {
		for _, x := range l {
			m, _ := x.(map[string]interface{})
			if s := asString(m["suffix"]); s != "" {
				h, _ := toInt64(m["hits"])
				r := asString(m["reason"])
				if r == "" {
					r = "list"
				}
				addShared(s, r, h)
			}
		}
	}

	var keep []interface{}
	for _, s := range strList(g["suffixes"]) {
		if r := local.reason(s); r != "" {
			addShared(registrable(s), r, 0)
			continue
		}
		keep = append(keep, s)
	}
	if len(keep) == 0 {
		return nil, false
	}
	out := make(map[string]interface{}, len(g)+1)
	for k, v := range g {
		out[k] = v
	}
	out["suffixes"] = keep
	if ds, ok := g["domains"].([]interface{}); ok {
		var kd []interface{}
		for _, d := range ds {
			m, _ := d.(map[string]interface{})
			if n := asString(m["name"]); n != "" && local.reason(n) != "" {
				continue
			}
			kd = append(kd, d)
		}
		out["domains"] = kd
	}
	if ms, ok := g["members"].([]interface{}); ok {
		var km []interface{}
		for _, x := range ms {
			m, _ := x.(map[string]interface{})
			if s := asString(m["suffix"]); s != "" && local.reason(s) != "" {
				h, _ := toInt64(m["hits"])
				addShared(registrable(s), local.reason(s), h)
				continue
			}
			km = append(km, x)
		}
		out["members"] = km
	}
	if len(shared) > 0 {
		list := make([]*shEntry, 0, len(shared))
		for _, e := range shared {
			list = append(list, e)
		}
		sort.Slice(list, func(a, b int) bool {
			if list[a].Hits != list[b].Hits {
				return list[a].Hits > list[b].Hits
			}
			return list[a].Suffix < list[b].Suffix
		})
		out["shared"] = list
	} else {
		delete(out, "shared")
	}
	return out, true
}

// certCoversHost 证书的 SAN(或没有 SAN 时的 CN)是否覆盖 host。
// 通配 *.example.com 只覆盖一层(a.example.com, 不含 example.com / a.b.example.com)。
func certCoversHost(ci certInfo, host string) bool {
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	names := ci.SANs
	if len(names) == 0 && ci.CN != "" {
		names = []string{ci.CN}
	}
	for _, n := range names {
		n = strings.Trim(strings.ToLower(n), ".")
		if n == host {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			base := n[2:]
			if strings.HasSuffix(host, "."+base) && !strings.Contains(strings.TrimSuffix(host, "."+base), ".") {
				return true
			}
		}
	}
	return false
}

// certUsable 证书能不能当本组的起名证据: 探测的主机仍属于本组(组里的域名
// 被剔成「公共服务」后, 旧的探测结果不算), 且证书覆盖该主机名。
// 返回 "" = 可用, 否则是不用的原因(前端显示)。
func certUsable(ci certInfo, sufSet map[string]bool) string {
	if ci.Err != "" || ci.Host == "" {
		return "no-cert"
	}
	if !sufSet[registrable(ci.Host)] {
		return "证书是对 " + ci.Host + " 取的, 它已不属于这个组, 不作为依据"
	}
	if !certCoversHost(ci, ci.Host) {
		return "证书上的域名没有覆盖 " + ci.Host + "(多半是共享服务器的默认证书), 不作为依据"
	}
	return ""
}

// certHostInGroup 上次探测的主机是否仍属于(过滤后的)组。没探测成功的按「属于」
// 处理(失败重试节奏不变)。
func certHostInGroup(ci certInfo, g map[string]interface{}) bool {
	if ci.Host == "" {
		return true
	}
	r := registrable(ci.Host)
	for _, x := range strList(g["suffixes"]) {
		if strings.EqualFold(registrable(x), r) {
			return true
		}
	}
	return false
}
