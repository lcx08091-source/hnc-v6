// netstats_parse.go — v5.21 解析 `dumpsys netstats` 输出(系统自己的流量统计, 设置里
// 「流量使用」就是它), 用于和 HNC 自采的 phone_usage 对账(stats_calibration.go)。
//
// AOSP NetworkStatsService.dump(Android 7 → 16 基本不变):
//
//	Active interfaces:
//	  iface=rmnet_data2 ident=[{type=MOBILE, ratType=COMBINED, subscriberId=460001..., metered=true, defaultNetwork=true, oemManaged=OEM_NONE, subId=1}]
//	Dev stats:
//	  Pending bytes: 1234
//	  Complete history:                          (--full; 否则 "History since boot:")
//	  ident=[{type=MOBILE, ...}] uid=-1 set=ALL tag=0x0
//	    NetworkStatsHistory: bucketDuration=3600
//	      st=1727654400 rb=123 rp=4 tb=56 tp=7 op=0
//	Xt stats:            (同上; 含 TetherOffload/BPF provider 补报的分流字节)
//	UID stats:           (--uid / detail 才有; uid=-5 即 UID_TETHERING 热点)
//	UID tag stats:       (--tag / detail)
//
// 各版本差异(都按「可选字段」处理):
//   - NetworkIdentity.toString: A9-11 "{type=MOBILE, subType=COMBINED, subscriberId=460001..., metered=true}";
//     A12+ subType→ratType, 加 oemManaged; A13+ Wi-Fi 多 wifiNetworkKey="SSID"(可含逗号);
//     A14+ 加 subId=N。subscriberId 在 dump 里被 scrub 成前 6 位 + "..."。
//   - type 通常是名字(MOBILE/WIFI/ETHERNET/BLUETOOTH), 个别 ROM 打数字(0/1/9/7)。
//   - NetworkStatsHistory 行: st 为秒; rb/rp/tb/tp/op 某些字段可能缺省。
//   - 头部行在 A13+ 的 IndentingPrintWriter 下仍在第 0 列; 为稳妥按 trim 后文本识别。
//
// 解析是流式的, keep 回调可以丢掉不关心的 key(UID stats 可能有上百个 uid)。

package main

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// nsIdent NetworkIdentity 的一个成员
type nsIdent struct {
	Type       string // MOBILE / WIFI / ETHERNET / BLUETOOTH / ...
	Subscriber string // scrub 后的 subscriberId(如 "460001..."), 去掉末尾 "..."; 空=无
	SubID      int    // -1 = dump 里没有
	Metered    int8   // -1 未知, 0 false, 1 true
	Roaming    bool
}

type nsBucket struct {
	St     int64 // 秒
	Rx, Tx uint64
}

// nsKey 一条 ident+uid+set+tag 及其历史桶
type nsKey struct {
	Section   string // dev / xt / uid / uidtag
	Full      bool   // 本段是 Complete history(否则 History since boot)
	Idents    []nsIdent
	UID       int
	Set       string
	Tag       string
	BucketSec int64
	Buckets   []nsBucket
}

// Primary 第一个 ident(NetworkIdentitySet 实际上几乎总是单个)
func (k *nsKey) Primary() nsIdent {
	if len(k.Idents) == 0 {
		return nsIdent{SubID: -1, Metered: -1}
	}
	return k.Idents[0]
}

type nsDump struct {
	Keys     []*nsKey
	Sections map[string]bool // 出现过的段(dev/xt/uid/uidtag)
	FullSec  map[string]bool // 段是 Complete history
	Lines    int
}

const (
	nsUIDAll       = -1 // UID_ALL(Dev/Xt 的 key)
	nsUIDTethering = -5 // UID_TETHERING
)

var (
	nsKeyRE     = regexp.MustCompile(`^ident=\[(.*)\]\s+uid=(-?\d+)\s+set=(\S+)\s+tag=(\S+)`)
	nsIdentRE   = regexp.MustCompile(`\{[^{}]*\}`)
	nsTypeRE    = regexp.MustCompile(`(?:^|\{|,\s*)type=([A-Za-z0-9_]+)`)
	nsSubscrRE  = regexp.MustCompile(`subscriberId=([^,}\s]+)`)
	nsSubIDRE   = regexp.MustCompile(`(?:^|\{|,\s*)subId=(-?\d+)`)
	nsMeteredRE = regexp.MustCompile(`(?:^|\{|,\s*)metered=(true|false)`)
	nsRoamingRE = regexp.MustCompile(`(?:^|\{|,\s*)roaming=(true|false)`)
	nsBucketRE  = regexp.MustCompile(`NetworkStatsHistory:\s*bucketDuration=(\d+)`)
	nsRbRE      = regexp.MustCompile(`\brb=(\d+)`)
	nsTbRE      = regexp.MustCompile(`\btb=(\d+)`)
	nsStRE      = regexp.MustCompile(`^st=(\d+)`)
)

// nsTypeName 数字 type → 名字(ConnectivityManager.TYPE_*)
func nsTypeName(s string) string {
	switch s {
	case "0":
		return "MOBILE"
	case "1":
		return "WIFI"
	case "7":
		return "BLUETOOTH"
	case "9":
		return "ETHERNET"
	}
	return strings.ToUpper(s)
}

func nsParseIdent(seg string) nsIdent {
	id := nsIdent{SubID: -1, Metered: -1}
	// wifiNetworkKey="..." 里的内容可能伪造出 type=/subId=, 先去掉引号内文本
	clean := seg
	for {
		i := strings.IndexByte(clean, '"')
		if i < 0 {
			break
		}
		j := strings.IndexByte(clean[i+1:], '"')
		if j < 0 {
			clean = clean[:i]
			break
		}
		clean = clean[:i] + clean[i+1+j+1:]
	}
	if m := nsTypeRE.FindStringSubmatch(clean); m != nil {
		id.Type = nsTypeName(m[1])
	}
	if m := nsSubscrRE.FindStringSubmatch(clean); m != nil {
		v := strings.TrimSuffix(m[1], "...")
		if v != "null" {
			id.Subscriber = v
		}
	}
	if m := nsSubIDRE.FindStringSubmatch(clean); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			id.SubID = n
		}
	}
	if m := nsMeteredRE.FindStringSubmatch(clean); m != nil {
		if m[1] == "true" {
			id.Metered = 1
		} else {
			id.Metered = 0
		}
	}
	if m := nsRoamingRE.FindStringSubmatch(clean); m != nil {
		id.Roaming = m[1] == "true"
	}
	return id
}

func nsParseIdentSet(s string) []nsIdent {
	segs := nsIdentRE.FindAllString(s, -1)
	if len(segs) == 0 && strings.TrimSpace(s) != "" {
		segs = []string{s}
	}
	out := make([]nsIdent, 0, len(segs))
	for _, seg := range segs {
		out = append(out, nsParseIdent(seg))
	}
	return out
}

// nsSectionOf 段标题 → 段名; ok=false 表示不是段标题
func nsSectionOf(trimmed string) (string, bool) {
	if !strings.HasSuffix(trimmed, ":") {
		return "", false
	}
	h := strings.ToLower(strings.TrimSuffix(trimmed, ":"))
	switch h {
	case "dev stats":
		return "dev", true
	case "xt stats":
		return "xt", true
	case "uid stats":
		return "uid", true
	case "uid tag stats", "uidtag stats":
		return "uidtag", true
	}
	return "", false
}

// parseNetstatsDump 流式解析。keep(section, uid) 返回 false 的 key 不保留桶(省内存)。
func parseNetstatsDump(r io.Reader, keep func(section string, uid int) bool) (*nsDump, error) {
	d := &nsDump{Sections: map[string]bool{}, FullSec: map[string]bool{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	section := ""
	full := false
	var cur *nsKey
	for sc.Scan() {
		d.Lines++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if sec, ok := nsSectionOf(line); ok {
			section, full, cur = sec, false, nil
			d.Sections[sec] = true
			continue
		}
		// 第 0 列的其他 "Xxx:" 标题(Active interfaces: / Stats Providers: ...)结束当前段
		if raw[0] != ' ' && raw[0] != '\t' && strings.HasSuffix(line, ":") &&
			line != "Complete history:" && line != "History since boot:" {
			section, cur = "", nil
			continue
		}
		if section == "" {
			continue
		}
		switch {
		case line == "Complete history:":
			full = true
			d.FullSec[section] = true
			cur = nil
		case line == "History since boot:":
			full = false
			cur = nil
		case strings.HasPrefix(line, "ident="):
			cur = nil
			m := nsKeyRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			uid, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			if keep != nil && !keep(section, uid) {
				continue
			}
			cur = &nsKey{Section: section, Full: full, Idents: nsParseIdentSet(m[1]),
				UID: uid, Set: m[3], Tag: m[4]}
			d.Keys = append(d.Keys, cur)
		case cur != nil && strings.HasPrefix(line, "NetworkStatsHistory:"):
			if m := nsBucketRE.FindStringSubmatch(line); m != nil {
				cur.BucketSec, _ = strconv.ParseInt(m[1], 10, 64)
			}
		case cur != nil && strings.HasPrefix(line, "st="):
			m := nsStRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			st, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				continue
			}
			// 个别旧版本 st 是毫秒
			if st > 100000000000 {
				st /= 1000
			}
			b := nsBucket{St: st}
			if x := nsRbRE.FindStringSubmatch(line); x != nil {
				b.Rx, _ = strconv.ParseUint(x[1], 10, 64)
			}
			if x := nsTbRE.FindStringSubmatch(line); x != nil {
				b.Tx, _ = strconv.ParseUint(x[1], 10, 64)
			}
			cur.Buckets = append(cur.Buckets, b)
		}
	}
	return d, sc.Err()
}

// nsCountable 求总量时要的 key: tag=0x0(非 tag 细分), set 不是 DBG_VPN_IN/OUT(调试重复计数)
func nsCountable(k *nsKey) bool {
	if k.Tag != "0x0" && k.Tag != "0" {
		return false
	}
	return !strings.HasPrefix(strings.ToUpper(k.Set), "DBG_VPN")
}

// nsWindowBytes 该 key 在 [from, to) 内的 rx/tx(秒)。桶与窗口部分重叠时按时长比例折算;
// 尚未结束的桶(end > now)只按 [st, now] 摊。
func nsWindowBytes(k *nsKey, from, to, now int64) (float64, float64) {
	dur := k.BucketSec
	if dur <= 0 {
		dur = 3600
	}
	var rx, tx float64
	for _, b := range k.Buckets {
		end := b.St + dur
		if end > now {
			end = now
		}
		if end <= b.St { // 未来桶/刚开的桶: 看起点是否在窗口内
			if b.St >= from && b.St < to {
				rx += float64(b.Rx)
				tx += float64(b.Tx)
			}
			continue
		}
		lo, hi := b.St, end
		if from > lo {
			lo = from
		}
		if to < hi {
			hi = to
		}
		if hi <= lo {
			continue
		}
		f := float64(hi-lo) / float64(end-b.St)
		rx += float64(b.Rx) * f
		tx += float64(b.Tx) * f
	}
	return rx, tx
}

// nsEarliest 各 key 最早的桶起点(0 = 无桶)
func nsEarliest(keys []*nsKey) int64 {
	var e int64
	for _, k := range keys {
		for _, b := range k.Buckets {
			if e == 0 || b.St < e {
				e = b.St
			}
		}
	}
	return e
}

// nsSelect 挑某段里满足条件的可计 key
func (d *nsDump) nsSelect(section string, uid int, typ string) []*nsKey {
	var out []*nsKey
	if d == nil {
		return nil
	}
	for _, k := range d.Keys {
		if k.Section != section || k.UID != uid || !nsCountable(k) {
			continue
		}
		if typ != "" && k.Primary().Type != typ {
			continue
		}
		out = append(out, k)
	}
	return out
}
