package apkscan

// v5.15: 主机名识别 + 可注册域(eTLD+1)换算 + 基础设施过滤。
//
// 数据来源是 dex 常量池 / resources.arsc / assets 文本里的可打印 ASCII 串,
// 里面混着大量"长得像域名"的东西: Java 包名(com.tencent.mm.app)、文件名
// (R.java / icon.png / base_bind.cc)、压缩 JS 的属性访问(window.top /
// user.id)。这里用几条便宜的启发式把误报压下去, 不追求 100% 精确 ——
// 下游还有"≥N 个 App 共用即视为 SDK"的文档频率过滤兜底。

import "strings"

const (
	minHostLen = 4
	maxHostLen = 253
	maxLabel   = 63
)

// strongTLDs: 在代码里几乎不会以"标识符.xxx"形式出现的 TLD, 两段式
// (foo.com)即可接受。
var strongTLDs = setOf(
	"com", "net", "org", "cn", "edu", "gov", "hk", "tw",
)

// weakTLDs: 同时是常见英文单词/属性名/文件扩展名的 TLD(window.top、
// user.id、foo.cc、this.app ...)。只有处在 URL 上下文("//"或"@"之后)
// 或主机名至少三段(api.foo.top)时才接受。
var weakTLDs = setOf(
	"io", "co", "me", "tv", "cc", "app", "info", "xyz", "top", "vip", "tech",
	"cloud", "link", "site", "online", "club", "biz", "mobi", "pro", "live",
	"shop", "store", "fun", "ltd", "group", "games", "game", "news", "life",
	"world", "today", "space", "website", "work", "ink", "wang", "asia",
	"icu", "ai", "dev", "im", "jp", "kr", "uk", "de", "fr", "ru", "mo",
	"sg", "my", "in", "id", "au", "ca", "us", "eu", "th", "vn", "ph", "br",
	"nl", "it", "es", "ch", "se", "be", "at", "nz", "la", "ws", "to", "gg",
	"fm", "ly", "red", "mom", "run", "art", "plus", "video", "music",
)

// fileExts: 常被误当成 TLD 的文件扩展名。TLD 白名单本来就不含这些,
// 这里显式再拒一次, 防止以后往白名单里加东西时误放进来(测试断言两表不相交)。
var fileExts = setOf(
	"png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico", "so", "java",
	"class", "xml", "json", "js", "ts", "kt", "dex", "apk", "jar", "zip",
	"gz", "txt", "html", "htm", "css", "md", "properties", "arsc", "bin",
	"dat", "db", "log", "sh", "py", "pl", "rs", "cpp", "c", "h", "hpp",
	"mp3", "mp4", "ogg", "wav", "ttf", "otf", "woff", "proto", "yaml", "yml",
	"cfg", "conf", "ini", "pem", "crt", "key", "tmp", "bak", "lua", "wasm",
)

// multiSuffixes: 内置的多级公共后缀(只收热点场景常见的一小撮,
// 不引入完整 PSL)。命中时可注册域取三段。
var multiSuffixes = setOf(
	"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
	"com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
	"com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
	"com.mo", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
	"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
	"com.au", "net.au", "org.au", "edu.au", "gov.au",
	"co.kr", "or.kr", "ne.kr", "com.sg", "edu.sg", "com.my",
	"co.in", "co.id", "com.br", "co.nz", "co.th", "com.vn", "com.ph",
)

// reverseDNSHeads: Java/Kotlin 包名的常见首段。首段命中且 ≥3 段时视为
// 包名(com.tencent.mm.app / org.json.io)而不是主机名。
var reverseDNSHeads = setOf(
	"com", "org", "net", "android", "androidx", "java", "javax", "kotlin",
	"kotlinx", "dalvik", "sun", "io", "junit", "okhttp3", "retrofit2",
)

// infraDomains: 通用基础设施 / 标准 / 开发工具类可注册域。它们几乎出现在
// 每个 APK 里(XML 命名空间、许可证、依赖库主页), 对"这个域名属于哪个
// App"毫无区分度, 直接丢弃(不进 sdk_suffixes)。
var infraDomains = setOf(
	"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
	"googlesource.com", "android.com", "w3.org", "w3c.org", "apache.org",
	"xmlpull.org", "xmlsoap.org", "github.com", "githubusercontent.com",
	"github.io", "example.com", "example.org", "example.net", "json.org",
	"mozilla.org", "xml.org", "adobe.com", "microsoft.com", "apple.com",
	"java.com", "oracle.com", "sun.com", "kotlinlang.org", "jetbrains.com",
	"ietf.org", "iana.org", "unicode.org", "openssl.org", "gnu.org",
	"opensource.org", "creativecommons.org", "schema.org", "purl.org",
	"xmlns.com", "ecma-international.org", "khronos.org", "chromium.org",
	"webkit.org", "npmjs.com", "npmjs.org", "stackoverflow.com",
	"wikipedia.org", "jquery.com", "jsdelivr.net", "bootstrapcdn.com",
	"gradle.org", "maven.org", "sonatype.org", "slf4j.org", "bouncycastle.org",
	"squareup.com", "reactjs.org", "nodejs.org", "python.org", "golang.org",
	"amazonaws.com", "cloudflare.com", "localhost.com",
)

func setOf(xs ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

func inSet(m map[string]struct{}, b []byte) bool {
	_, ok := m[string(b)] // 编译器对 m[string(b)] 查找不分配
	return ok
}

// tokClass: 主机名 token 允许的字节。'_' 也算 token 字符(之后整串拒掉),
// 否则 "foo_bar.com" 会被截成 "bar.com" 这种假域名。
var tokClass = func() (t [256]bool) {
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	t['.'], t['-'], t['_'] = true, true, true
	return
}()

// tokenizer 是跨块边界的流式状态机: 连续的 token 字节累积成候选串,
// 遇到分隔字节就交给 emit。状态(未完成的 token、前两个字节)跨 feed
// 调用保留, 所以块边界切在域名中间也能完整识别。
type tokenizer struct {
	buf      [maxHostLen + 1]byte
	n        int
	inTok    bool
	overflow bool // token 超过 253 字节: 整串丢弃
	urlCtx   bool // token 前面紧挨着 "//" 或 "@"
	p1, p2   byte // 最近两个输入字节
	emit     func(tok []byte, urlCtx bool)
}

func (t *tokenizer) reset() {
	t.n, t.inTok, t.overflow, t.urlCtx, t.p1, t.p2 = 0, false, false, false, 0, 0
}

func (t *tokenizer) feed(b []byte) {
	for _, c := range b {
		t.feedByte(c)
	}
}

func (t *tokenizer) feedByte(c byte) {
	if tokClass[c] {
		if !t.inTok {
			t.inTok, t.n, t.overflow = true, 0, false
			t.urlCtx = t.p1 == '@' || (t.p1 == '/' && t.p2 == '/')
		}
		if t.n < len(t.buf) {
			t.buf[t.n] = c
			t.n++
		} else {
			t.overflow = true
		}
	} else if t.inTok {
		t.flush()
	}
	t.p2, t.p1 = t.p1, c
}

// flush 结束当前 token(文件结束时也要调用, 但不跨文件拼接)。
func (t *tokenizer) flush() {
	if t.inTok && !t.overflow && t.n >= minHostLen {
		t.emit(t.buf[:t.n], t.urlCtx)
	}
	t.inTok, t.n, t.overflow = false, 0, false
}

// hostOf 校验候选 token 是否像一个真实主机名, 是则返回去掉首尾 '.'/'-'
// 之后的主机名(tok 的子切片)。
func hostOf(tok []byte, urlCtx bool) ([]byte, bool) {
	for len(tok) > 0 && (tok[0] == '.' || tok[0] == '-') {
		tok = tok[1:]
	}
	for len(tok) > 0 && (tok[len(tok)-1] == '.' || tok[len(tok)-1] == '-') {
		tok = tok[:len(tok)-1]
	}
	if len(tok) < minHostLen || len(tok) > maxHostLen {
		return nil, false
	}
	// 逐段校验: 1~63 字节, 只允许小写字母/数字/'-', 首尾不能是 '-'。
	// 含大写一律拒: 代码里的 "R.java"/"Build.VERSION"/"Foo.Info" 都带大写,
	// 真实域名常量基本是小写。
	labels := 0
	start := 0
	firstEnd := -1
	for i := 0; i <= len(tok); i++ {
		if i < len(tok) && tok[i] != '.' {
			c := tok[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, false
			}
			continue
		}
		l := i - start
		if l == 0 || l > maxLabel || tok[start] == '-' || tok[i-1] == '-' {
			return nil, false
		}
		if firstEnd < 0 {
			firstEnd = i
		}
		labels++
		start = i + 1
	}
	if labels < 2 {
		return nil, false
	}
	tld := tok[lastDot(tok)+1:] // labels ≥ 2 保证有 '.'
	if inSet(fileExts, tld) {
		return nil, false
	}
	strong := inSet(strongTLDs, tld)
	if !strong && !inSet(weakTLDs, tld) {
		return nil, false
	}
	first := tok[:firstEnd]
	if labels >= 3 && inSet(reverseDNSHeads, first) {
		return nil, false // Java 包名
	}
	if !strong && !urlCtx && labels < 3 {
		return nil, false // window.top / user.id / foo.cc
	}
	if strong && !urlCtx && labels == 2 && len(first) == 1 {
		return nil, false // 压缩代码里的 e.com / a.net
	}
	if string(first) == "schemas" || string(first) == "schema" {
		return nil, false // schemas.android.com / schemas.xmlsoap.org ...
	}
	return tok, true
}

func lastDot(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '.' {
			return i
		}
	}
	return -1
}

// registrable 把主机名换算成可注册域(eTLD+1)。host 已经过 hostOf 校验。
// 返回 "" 表示主机名本身就是公共后缀(如 "com.cn")。
func registrable(host string) string {
	i := strings.LastIndexByte(host, '.')
	if i < 0 {
		return ""
	}
	j := strings.LastIndexByte(host[:i], '.')
	last2 := host[j+1:]
	if _, ok := multiSuffixes[last2]; ok {
		if j < 0 {
			return ""
		}
		k := strings.LastIndexByte(host[:j], '.')
		return host[k+1:]
	}
	return last2
}

// isInfra 报告可注册域是否属于通用基础设施表。
func isInfra(rd string) bool {
	_, ok := infraDomains[rd]
	return ok
}
