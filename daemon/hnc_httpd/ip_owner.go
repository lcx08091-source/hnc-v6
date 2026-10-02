// ip_owner.go — DPI v2: 离线 IP 归属库(目的 IP → 组织/生态)
//
// 数据: data/ip_owner.bin, 由 tools/build_ip_owner.py 从 iptoasn.com 的 ASN→网段数据
// 生成(只挑关心的组织的 ASN, 合并相邻网段)。格式见生成脚本文件头; 这里只读。
//   - v4: [start, end] uint32 闭区间, 按 start 升序互不重叠 → 二分 O(log n)
//   - v6: 地址高 64 位的闭区间(同上)
//   - 组织 kind: app(消费级应用运营方) / cloud / cdn / carrier
//
// 加载: 第一次查询时懒加载(之后每 ipOwnerRecheck 最多 stat 一次, 文件变了才重读);
// 文件 > ipOwnerMaxFile 或 CRC/结构不对 → 当作没有(查询全部 miss), 不影响其它功能。
// 内存 ≈ 文件大小(当前 ~260 KB: v4 1.4 万段 × 10 B + v6 6.6 千段 × 18 B)。
//
// 查找顺序(第一个存在的文件):
//   $HNC_IP_OWNER_PATH(测试) → $HNC_DIR/etc/ip_owner.bin(用户覆盖) → $HNC_DIR/data/ip_owner.bin
//   → <run/service.path>/data/ip_owner.bin(模块目录) → /data/adb/modules/hotspot_network_control/data/ip_owner.bin
//
// 用途:
//   - 归属(app_usage.go): 目的 IP 无反查名、规则/用户纠正/指纹/共现都没归上的字节,
//     若归属组织是 app 类 → 记到伪应用 "_org:<key>"(如「字节系(未细分)」, category "org");
//     cloud/cdn/carrier 类仍记「未识别」, 但 /api/dpi_unknown 的 IP 条目带 owner 标签。
//   - /api/connections 每行带 owner(非局域网目的且库里有)。

package main

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ipOwnerMagic   = "HNCIPOW1"
	ipOwnerMaxFile = 8 << 20
	ipOwnerRecheck = 5 * time.Minute

	ipOwnerKindApp     = 1
	ipOwnerKindCloud   = 2
	ipOwnerKindCDN     = 3
	ipOwnerKindCarrier = 4

	orgAppPrefix   = "_org:"
	orgAppCategory = "org"
)

type ipOwnerOrg struct {
	Key  string
	Name string
	Kind uint8
}

// KindName app / cloud / cdn / carrier
func (o ipOwnerOrg) KindName() string {
	switch o.Kind {
	case ipOwnerKindApp:
		return "app"
	case ipOwnerKindCloud:
		return "cloud"
	case ipOwnerKindCDN:
		return "cdn"
	case ipOwnerKindCarrier:
		return "carrier"
	}
	return "other"
}

// 伪应用显示名的简称(没列的用组织名): 「字节系(未细分)」
var orgShortNames = map[string]string{"bytedance": "字节", "alibaba": "阿里"}

// AppID / AppName 归属组织对应的伪应用(仅 kind=app 有意义)
func (o ipOwnerOrg) AppID() string { return orgAppPrefix + o.Key }
func (o ipOwnerOrg) AppName() string {
	n := orgShortNames[o.Key]
	if n == "" {
		n = o.Name
	}
	return n + "系(未细分)"
}

// JSON 形态(/api/connections 行、/api/dpi_unknown 条目)
func (o ipOwnerOrg) JSON() map[string]interface{} {
	return map[string]interface{}{"key": o.Key, "name": o.Name, "kind": o.KindName()}
}

func isOrgAppID(id string) bool { return strings.HasPrefix(id, orgAppPrefix) }

type ipOwnerDB struct {
	date      uint32
	orgs      []ipOwnerOrg
	v4s, v4e  []uint32
	v4o       []uint16
	v6s, v6e  []uint64
	v6o       []uint16
	fileBytes int
}

var errIPOwnerFormat = errors.New("ip_owner: bad format")

// parseIPOwner 解析并校验整份文件(CRC、计数、排序、组织下标)
func parseIPOwner(b []byte) (*ipOwnerDB, error) {
	if len(b) < len(ipOwnerMagic)+14+4 || string(b[:8]) != ipOwnerMagic {
		return nil, errIPOwnerFormat
	}
	body, sum := b[:len(b)-4], binary.LittleEndian.Uint32(b[len(b)-4:])
	if crc32.ChecksumIEEE(body) != sum {
		return nil, errors.New("ip_owner: crc mismatch")
	}
	p := 8
	db := &ipOwnerDB{fileBytes: len(b)}
	db.date = binary.LittleEndian.Uint32(body[p:])
	nOrg := int(binary.LittleEndian.Uint16(body[p+4:]))
	n4 := int(binary.LittleEndian.Uint32(body[p+6:]))
	n6 := int(binary.LittleEndian.Uint32(body[p+10:]))
	p += 14
	str := func() (string, bool) {
		if p >= len(body) {
			return "", false
		}
		l := int(body[p])
		p++
		if p+l > len(body) {
			return "", false
		}
		s := string(body[p : p+l])
		p += l
		return s, true
	}
	for i := 0; i < nOrg; i++ {
		if p >= len(body) {
			return nil, errIPOwnerFormat
		}
		kind := body[p]
		p++
		k, ok1 := str()
		n, ok2 := str()
		if !ok1 || !ok2 || k == "" {
			return nil, errIPOwnerFormat
		}
		db.orgs = append(db.orgs, ipOwnerOrg{Key: k, Name: n, Kind: kind})
	}
	if n4 < 0 || n6 < 0 || len(body)-p != n4*10+n6*18 {
		return nil, errIPOwnerFormat
	}
	db.v4s, db.v4e, db.v4o = make([]uint32, n4), make([]uint32, n4), make([]uint16, n4)
	for i := 0; i < n4; i++ {
		s, e, o := binary.LittleEndian.Uint32(body[p:]), binary.LittleEndian.Uint32(body[p+4:]), binary.LittleEndian.Uint16(body[p+8:])
		p += 10
		if e < s || int(o) >= nOrg || (i > 0 && s <= db.v4e[i-1]) {
			return nil, errIPOwnerFormat
		}
		db.v4s[i], db.v4e[i], db.v4o[i] = s, e, o
	}
	db.v6s, db.v6e, db.v6o = make([]uint64, n6), make([]uint64, n6), make([]uint16, n6)
	for i := 0; i < n6; i++ {
		s, e, o := binary.LittleEndian.Uint64(body[p:]), binary.LittleEndian.Uint64(body[p+8:]), binary.LittleEndian.Uint16(body[p+16:])
		p += 18
		if e < s || int(o) >= nOrg || (i > 0 && s <= db.v6e[i-1]) {
			return nil, errIPOwnerFormat
		}
		db.v6s[i], db.v6e[i], db.v6o[i] = s, e, o
	}
	return db, nil
}

// lookupIP O(log n)
func (db *ipOwnerDB) lookupIP(ip net.IP) (ipOwnerOrg, bool) {
	if db == nil || ip == nil {
		return ipOwnerOrg{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		x := binary.BigEndian.Uint32(v4)
		i := sort.Search(len(db.v4s), func(i int) bool { return db.v4s[i] > x }) - 1
		if i >= 0 && x <= db.v4e[i] {
			return db.orgs[db.v4o[i]], true
		}
		return ipOwnerOrg{}, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return ipOwnerOrg{}, false
	}
	x := binary.BigEndian.Uint64(v6[:8])
	i := sort.Search(len(db.v6s), func(i int) bool { return db.v6s[i] > x }) - 1
	if i >= 0 && x <= db.v6e[i] {
		return db.orgs[db.v6o[i]], true
	}
	return ipOwnerOrg{}, false
}

func (db *ipOwnerDB) lookup(ip string) (ipOwnerOrg, bool) {
	if db == nil || ip == "" {
		return ipOwnerOrg{}, false
	}
	return db.lookupIP(net.ParseIP(ip))
}

// ─── 懒加载 ───────────────────────────────────────────────────────────

var ipOwnerSrc struct {
	mu      sync.Mutex
	hncDir  string
	db      *ipOwnerDB
	path    string
	mtime   time.Time
	size    int64
	checked time.Time
	err     string
	fixed   bool // 测试注入: 不再从磁盘加载
}

// ipOwnerConfigure 设 HNC 目录(newServer 调; 无 I/O)
func ipOwnerConfigure(hncDir string) {
	ipOwnerSrc.mu.Lock()
	defer ipOwnerSrc.mu.Unlock()
	if ipOwnerSrc.hncDir != hncDir {
		ipOwnerSrc.hncDir = hncDir
		ipOwnerSrc.checked = time.Time{}
	}
}

// ipOwnerSetDB 测试注入(nil = 恢复从磁盘加载)
func ipOwnerSetDB(db *ipOwnerDB) {
	ipOwnerSrc.mu.Lock()
	defer ipOwnerSrc.mu.Unlock()
	ipOwnerSrc.db, ipOwnerSrc.fixed, ipOwnerSrc.checked = db, db != nil, time.Time{}
	ipOwnerSrc.path, ipOwnerSrc.size, ipOwnerSrc.mtime = "", 0, time.Time{}
}

func ipOwnerCandidates(hncDir string) []string {
	var out []string
	if p := os.Getenv("HNC_IP_OWNER_PATH"); p != "" {
		return []string{p}
	}
	if hncDir != "" {
		out = append(out, filepath.Join(hncDir, "etc", "ip_owner.bin"), filepath.Join(hncDir, "data", "ip_owner.bin"))
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "service.path")); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				out = append(out, filepath.Join(v, "data", "ip_owner.bin"))
			}
		}
	}
	return append(out, "/data/adb/modules/hotspot_network_control/data/ip_owner.bin")
}

// ipOwnerGet 当前库(可能为 nil)
func ipOwnerGet() *ipOwnerDB {
	ipOwnerSrc.mu.Lock()
	defer ipOwnerSrc.mu.Unlock()
	if ipOwnerSrc.fixed {
		return ipOwnerSrc.db
	}
	now := time.Now()
	if !ipOwnerSrc.checked.IsZero() && now.Sub(ipOwnerSrc.checked) < ipOwnerRecheck && now.After(ipOwnerSrc.checked) {
		return ipOwnerSrc.db
	}
	ipOwnerSrc.checked = now
	for _, p := range ipOwnerCandidates(ipOwnerSrc.hncDir) {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if p == ipOwnerSrc.path && st.Size() == ipOwnerSrc.size && st.ModTime().Equal(ipOwnerSrc.mtime) {
			return ipOwnerSrc.db // 没变
		}
		ipOwnerSrc.path, ipOwnerSrc.size, ipOwnerSrc.mtime = p, st.Size(), st.ModTime()
		if st.Size() > ipOwnerMaxFile {
			ipOwnerSrc.db, ipOwnerSrc.err = nil, "file too large"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			ipOwnerSrc.db, ipOwnerSrc.err = nil, err.Error()
			return nil
		}
		db, err := parseIPOwner(b)
		if err != nil {
			ipOwnerSrc.db, ipOwnerSrc.err = nil, err.Error()
			return nil
		}
		ipOwnerSrc.db, ipOwnerSrc.err = db, ""
		return db
	}
	ipOwnerSrc.db, ipOwnerSrc.path, ipOwnerSrc.err = nil, "", "not found"
	return nil
}

// ipOwnerLookup 目的 IP 的归属组织(库不可用/不在库里 → false)。局域网地址不查。
func ipOwnerLookup(ip string) (ipOwnerOrg, bool) {
	if ip == "" || isPrivateIP(ip) {
		return ipOwnerOrg{}, false
	}
	return ipOwnerGet().lookup(ip)
}

// orgAppForIP 无名目的 IP 的生态伪应用(只有 app 类组织才归)
func orgAppForIP(ip string) (ipApp, bool) {
	o, ok := ipOwnerLookup(ip)
	if !ok || o.Kind != ipOwnerKindApp {
		return ipApp{}, false
	}
	return ipApp{ID: o.AppID(), Name: o.AppName(), Category: orgAppCategory}, true
}
