// Package output - flowlog.go: v6.x DPI v2 每连接 ClientHello 指纹导出(run/dpi_flows.json)。
//
// 为什么: httpd 的应用归属按 conntrack 连接做(api_conn.go / app_usage.go), 以前只能用
// 目的 IP 反查域名。没有域名的连接(App 写死 IP / HTTPDNS / ECH 外层 SNI)就是「未识别」。
// TLS / QUIC 的 ClientHello 指纹(JA4)往往能代表「哪个 App 的网络栈」, 但 httpd 拿不到包。
// 这里把 dpid 看到的每个 ClientHello 按五元组导出, httpd 用同一个五元组
// ("proto|client_ip|sport|dst_ip|dport", 与 ctEntry.key() 同格式)去连接表 join:
//   - 学习: SNI 命中规则的连接 → (JA4, ALPN, 端口类) 记给该应用(httpd fp_learn.go);
//   - 识别: 无域名连接查学到的指纹表。
//
// 有界: 环形缓冲最多 flowLogMax 条, 输出只含最近 flowLogMaxAge 秒内的; 同一五元组 +
// 同一 JA4 在 flowLogDedupSec 内重复出现(QUIC Initial 重传 / ClientHello 重组)只顺延
// ts, 不新增。每条带单调递增 seq, httpd 记游标只处理新条目; boot(进程启动时间)变了
// 说明 dpid 重启过, httpd 重置游标。
//
// 并发: 自带锁; main.go 的 capture 回调直接调用 Record, flushEvery 调 Flush(无变化不写)。
package output

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultFlowLogPath = "/data/local/hnc/run/dpi_flows.json"

	flowLogMax      = 1024 // 环形缓冲上限(条)
	flowLogMaxAge   = 600  // 秒: 只导出最近 10 分钟
	flowLogDedupSec = 120  // 同五元组 + 同 JA4 在此窗口内视为同一连接
)

// FlowRecord 一个 ClientHello(TLS 或 QUIC Initial)。
type FlowRecord struct {
	Seq   int64  `json:"seq"`
	Ts    int64  `json:"ts"`
	MAC   string `json:"mac,omitempty"`
	CIP   string `json:"cip"`
	Sport int    `json:"sport"`
	DIP   string `json:"dip"`
	Dport int    `json:"dport"`
	Proto string `json:"proto"` // tcp | udp(QUIC)
	JA4   string `json:"ja4"`
	ALPN  string `json:"alpn,omitempty"` // 客户端提供的第一个 ALPN
	SNI   string `json:"sni,omitempty"`
	// ECHOuter: SNI 是已知的 ECH 外层 public_name(不代表真实站点, 不能拿来学习/归类)
	ECHOuter bool `json:"ech_outer,omitempty"`
	// SNI 按规则库归类的结果(Record 时算; ECH 外层不算)
	App      string `json:"app,omitempty"`
	AppName  string `json:"app_name,omitempty"`
	Category string `json:"category,omitempty"`
}

type flowLogFile struct {
	Schema      int          `json:"schema"`
	Boot        int64        `json:"boot"`
	GeneratedAt int64        `json:"generated_at"`
	Seq         int64        `json:"seq"`
	Flows       []FlowRecord `json:"flows"`
}

// FlowLog 有界环形缓冲。
type FlowLog struct {
	mu    sync.Mutex
	path  string
	max   int
	ring  []FlowRecord
	next  int            // 下一个写入槽
	idx   map[string]int // 五元组 key → 槽位(槽被覆盖时删除)
	seq   int64
	boot  int64
	dirty bool
	// classify 可替换(单测); 默认按规则库后缀归类
	classify func(host string) (id, name, category string, ok bool)
}

func NewFlowLog() *FlowLog {
	return &FlowLog{
		path: DefaultFlowLogPath, max: flowLogMax, idx: make(map[string]int),
		boot: time.Now().Unix(),
		classify: func(host string) (string, string, string, bool) {
			r, ok := classifyHost(host)
			if !ok || r.ID == "" {
				return "", "", "", false
			}
			return r.ID, r.Name, r.Category, true
		},
	}
}

func (l *FlowLog) SetPath(p string) {
	l.mu.Lock()
	l.path = p
	l.mu.Unlock()
}

// FlowKey 与 httpd ctEntry.key() 同格式: proto|src|sport|dst|dport
func FlowKey(proto, cip string, sport int, dip string, dport int) string {
	return proto + "|" + cip + "|" + strconv.Itoa(sport) + "|" + dip + "|" + strconv.Itoa(dport)
}

// Record 记一个 ClientHello。ja4 为空(截断/gQUIC)不记 —— 没有指纹对学习和识别都没用。
func (l *FlowLog) Record(mac, cip string, sport int, dip string, dport int, udp bool, ja4 string, alpn []string, sni string, ts time.Time) {
	if ja4 == "" {
		return
	}
	cip, dip = canonIP(cip), canonIP(dip)
	if cip == "" || dip == "" || sport <= 0 || dport <= 0 {
		return
	}
	proto := "tcp"
	if udp {
		proto = "udp"
	}
	host := normalizeName(sni)
	rec := FlowRecord{Ts: ts.Unix(), MAC: mac, CIP: cip, Sport: sport, DIP: dip, Dport: dport, Proto: proto, JA4: ja4, SNI: host}
	if len(alpn) > 0 && len(alpn[0]) <= 32 {
		rec.ALPN = alpn[0]
	}
	if host != "" {
		if echPublicNames[host] {
			rec.ECHOuter = true
		} else if l.classify != nil {
			if id, name, cat, ok := l.classify(host); ok {
				rec.App, rec.AppName, rec.Category = id, name, cat
			}
		}
	}
	key := FlowKey(proto, cip, sport, dip, dport)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max <= 0 {
		l.max = flowLogMax
	}
	if i, ok := l.idx[key]; ok && i < len(l.ring) {
		old := &l.ring[i]
		if old.JA4 == ja4 && rec.Ts-old.Ts >= 0 && rec.Ts-old.Ts <= flowLogDedupSec {
			if rec.Ts > old.Ts {
				old.Ts = rec.Ts
			}
			return
		}
	}
	l.seq++
	rec.Seq = l.seq
	if len(l.ring) < l.max {
		l.ring = append(l.ring, rec)
		l.idx[key] = len(l.ring) - 1
		l.next = len(l.ring) % l.max
	} else {
		ov := &l.ring[l.next]
		ok := FlowKey(ov.Proto, ov.CIP, ov.Sport, ov.DIP, ov.Dport)
		if j, has := l.idx[ok]; has && j == l.next {
			delete(l.idx, ok)
		}
		l.ring[l.next] = rec
		l.idx[key] = l.next
		l.next = (l.next + 1) % l.max
	}
	l.dirty = true
}

// Len 当前缓冲条数(≤ flowLogMax)
func (l *FlowLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ring)
}

// Snapshot 按 seq 升序返回最近 flowLogMaxAge 秒内的条目(Flush / 单测用)。
func (l *FlowLog) Snapshot(now time.Time) []FlowRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(now.Unix())
}

func (l *FlowLog) snapshotLocked(now int64) []FlowRecord {
	out := make([]FlowRecord, 0, len(l.ring))
	n := len(l.ring)
	start := 0
	if n == l.max {
		start = l.next // 满了: next 指向最旧的
	}
	for k := 0; k < n; k++ {
		r := l.ring[(start+k)%n]
		if now-r.Ts > flowLogMaxAge {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Flush 有新条目时原子写 JSON。
func (l *FlowLog) Flush(now time.Time) error {
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return nil
	}
	out := flowLogFile{Schema: 1, Boot: l.boot, GeneratedAt: now.Unix(), Seq: l.seq, Flows: l.snapshotLocked(now.Unix())}
	path := l.path
	l.dirty = false
	l.mu.Unlock()
	b, err := json.Marshal(out)
	if err == nil {
		err = atomicWrite(path, b, 0o644)
	}
	if err != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
	}
	return err
}
