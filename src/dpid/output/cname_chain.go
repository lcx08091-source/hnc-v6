// Package output - cname_chain.go: HNC v5.38.0 零样本 DNS CNAME 8 跳全链规则回溯器
//
// 解决痛点:
//   国内 App 经常使用陌生边缘调度域名(如 svc-gw.cn / edge-dispatch-xx.com) CNAME 指向集团专属 CDN
//   (如 *.dewucdn.com / *.byteimg.com / *.bilivideo.com), 最终尾跳再落到阿里云/网宿泛公共 CDN。
//   旧 ipname.go 只存链末端 final CNAME, 一旦尾跳是泛公共 CDN(如 kunlunca.com)就会丢失中间专属跳证据!
//   本模块在 DNS 应答解析阶段沿完整 8 跳链逐跳匹配规则库(自动豁免多租户公共基础设施后缀), 零样本 0ms 锁定真实应用。
package output

import "strings"

var genericMultiTenantCDNs = map[string]struct{}{
	"kunlunca.com":        {},
	"alikunlun.com":       {},
	"alikunlun.net":       {},
	"cdngslb.com":         {},
	"chinanetcenter.com":  {},
	"wscdns.com":          {},
	"wsglb0.com":          {},
	"cdn20.com":           {},
	"qtlcdn.com":          {},
	"ksyuncdn.com":        {},
	"ks-cdn.com":          {},
	"cdn.cloudflare.net":  {},
	"cloudfront.net":      {},
	"akamaiedge.net":      {},
	"akamaihd.net":        {},
	"edgekey.net":         {},
	"edgesuite.net":       {},
	"fastly.net":          {},
	"dnsv1.com":           {},
	"dnsv1.com.cn":        {},
	"smtcdns.net":         {},
	"cdntip.com":          {},
	"baishan-cloud.net":   {},
	"bsclink.cn":          {},
	"myhuaweicloud.com":   {},
	"hwcdn.net":           {},
	"cdnhwc1.com":         {},
	"cdnhwc2.com":         {},
	"cdnhwc3.com":         {},
	"kunlungr.com":        {},
	"kunlunar.com":        {},
	"kunluncan.com":       {},
	"eo-edge.com":         {},
	"eo-dnse2.com":        {},
	"tcdnvod.com":         {},
	"ovscdns.com":         {},
	"bdydns.com":          {},
	"volcgslb.com":        {},
}

func isGenericMultiTenantCDN(host string) bool {
	h := normalizeName(host)
	if h == "" {
		return false
	}
	for suf := range genericMultiTenantCDNs {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// BestClassifiedCNAMEHop 沿 [qname -> hop1 -> ... -> hop8] 查找第一个能命中专属应用规则的跳名。
// 若中间第 k 跳命中非泛 CDN 的专属规则(例如 dewucdn.com -> 得物), 返回该跳域名存入 IPNameEntry.CNAME,
// 即使尾跳继续指向 kunlunca.com 也不会丢失应用归因!
func BestClassifiedCNAMEHop(qname string, cn map[string]string, fallbackFinal string) string {
	cur := normalizeName(qname)
	if cur == "" {
		return fallbackFinal
	}
	if r, ok := classifyHost(cur); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
		return fallbackFinal
	}
	visited := map[string]bool{cur: true}
	for i := 0; i < ipNameMaxCNAMEHops; i++ {
		nx, ok := cn[cur]
		if !ok || visited[nx] {
			break
		}
		visited[nx] = true
		cur = nx
		if isGenericMultiTenantCDN(cur) {
			continue
		}
		if r, ok := classifyHost(cur); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
			return cur
		}
	}
	return fallbackFinal
}
