// v6_leakguard_guard.go — HNC v6.1 RC1:
// LeakGuard 三级公共基础设施与共享 CDN 防误杀守卫（hard_block / warn_confirm / also_ip 共享 CDN IP 剥离）。
//
// 分级策略:
//   1. hard_block (HTTP 409, 即使 force:true 也拒封):
//      - 系统 Captive Portal 连通性探测域、公共 DNS/DoH/DoT 域名及单 IP、系统 NTP 授时域（含全部子域）;
//      - 八大生态与公共 CDN 裸根域本身（如 apple.com, icloud.com, cdn-apple.com, google.com, gstatic.com,
//        googleapis.com, cloudflare.com, akamaized.net, cloudfront.net, aliyun.com, alicdn.com, taobao.com,
//        alipay.com, qq.com, weixin.qq.com, myqcloud.com, gtimg.com, qpic.cn, douyin.com, douyincdn.com,
//        douyinvod.com, byteimg.com, pstatp.com 等）。
//   2. warn_confirm (默认 HTTP 409 返回 guard_level:"warn_confirm" 与 vendor, 传 force:true 放行):
//      - 上述生态/公共 CDN 根域的子域, 或命中 shared_infra.txt / entity_db.json 的共享基础设施, 或单封共享 CDN IP;
//      - 显式豁免 doubleclick.net, pangle.io, umeng.com 等纯广告与第三方追踪域（直接放行封禁）。
//   3. 第 3 级 also_ip 剥离:
//      - 封禁独立广告域附带 also_ip 时, 若 also_ip 命中公共 CDN/云共享 IP, 只封域名自动跳过共享 IP 并返回 skipped_shared_ip:true。

package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"hnc.io/dpid/output"
)

const (
	leakGuardLevelAllow       = "allow"
	leakGuardLevelWarnConfirm = "warn_confirm"
	leakGuardLevelHardBlock   = "hard_block"
)

type leakBlockGuardDecision struct {
	Level    string `json:"guard_level"`
	Vendor   string `json:"vendor,omitempty"`
	Category string `json:"category,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type guardInfraMeta struct {
	Vendor   string
	Category string
}

// 第 1 级(A): 系统 Captive Portal、公共 DNS/DoH/DoT 与系统 NTP 域名（本身及所有子域一律 hard_block）。
var hardBlockSystemSuffixes = map[string]guardInfraMeta{
	// Captive Portal 连通性探测
	"connectivitycheck.gstatic.com":          {Vendor: "Google Android", Category: "captive_portal"},
	"connectivitycheck.android.com":          {Vendor: "Google Android", Category: "captive_portal"},
	"clients3.google.com":                    {Vendor: "Google Android", Category: "captive_portal"},
	"clients4.google.com":                    {Vendor: "Google Android", Category: "captive_portal"},
	"captive.apple.com":                      {Vendor: "Apple", Category: "captive_portal"},
	"captive.g.aaplimg.com":                  {Vendor: "Apple", Category: "captive_portal"},
	"connect.rom.miui.com":                   {Vendor: "Xiaomi", Category: "captive_portal"},
	"connectivitycheck.platform.hicloud.com": {Vendor: "Huawei", Category: "captive_portal"},
	"wifi.vivo.com.cn":                       {Vendor: "vivo", Category: "captive_portal"},
	"conn1.oppomobile.com":                   {Vendor: "OPPO", Category: "captive_portal"},
	"conn2.oppomobile.com":                   {Vendor: "OPPO", Category: "captive_portal"},
	"msftconnecttest.com":                    {Vendor: "Microsoft", Category: "captive_portal"},
	"msftncsi.com":                           {Vendor: "Microsoft", Category: "captive_portal"},
	"detectportal.firefox.com":               {Vendor: "Mozilla", Category: "captive_portal"},
	"nmcheck.gnome.org":                      {Vendor: "Linux NetworkManager", Category: "captive_portal"},
	"cp.cloudflare.com":                      {Vendor: "Cloudflare", Category: "captive_portal"},

	// 公共 DNS / DoH / DoT
	"dns.google":         {Vendor: "Google DNS", Category: "public_dns"},
	"dns.google.com":     {Vendor: "Google DNS", Category: "public_dns"},
	"cloudflare-dns.com": {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"one.one.one.one":    {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"quad9.net":          {Vendor: "Quad9 DNS", Category: "public_dns"},
	"dns.quad9.net":      {Vendor: "Quad9 DNS", Category: "public_dns"},
	"alibabadns.com":     {Vendor: "Alibaba DNS", Category: "public_dns"},
	"alidns.com":         {Vendor: "Alibaba DNS", Category: "public_dns"},
	"dns.alidns.com":     {Vendor: "Alibaba DNS", Category: "public_dns"},
	"dnspod.cn":          {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"dnspod.com":         {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"dnspod.net":         {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"doh.pub":            {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"dot.pub":            {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"dns.pub":            {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"114dns.com":         {Vendor: "114DNS", Category: "public_dns"},
	"onedns.net":         {Vendor: "OneDNS", Category: "public_dns"},
	"opendns.com":        {Vendor: "Cisco OpenDNS", Category: "public_dns"},

	// 系统 NTP 授时服务
	"ntp.org":             {Vendor: "NTP Pool", Category: "ntp"},
	"pool.ntp.org":        {Vendor: "NTP Pool", Category: "ntp"},
	"time.apple.com":      {Vendor: "Apple NTP", Category: "ntp"},
	"time.android.com":    {Vendor: "Google Android NTP", Category: "ntp"},
	"time.google.com":     {Vendor: "Google NTP", Category: "ntp"},
	"time.windows.com":    {Vendor: "Microsoft NTP", Category: "ntp"},
	"ntp.aliyun.com":      {Vendor: "Alibaba NTP", Category: "ntp"},
	"ntp.tencent.com":     {Vendor: "Tencent NTP", Category: "ntp"},
	"time.cloudflare.com": {Vendor: "Cloudflare NTP", Category: "ntp"},
	"ntp.ntsc.ac.cn":      {Vendor: "NTSC NTP", Category: "ntp"},
}

// 第 1 级(B): 公共 DNS 单 IP（封禁会导致设备 DNS 解析瘫痪, 一律 hard_block）。
var hardBlockPublicDNSIPs = map[string]guardInfraMeta{
	"8.8.8.8":              {Vendor: "Google DNS", Category: "public_dns"},
	"8.8.4.4":              {Vendor: "Google DNS", Category: "public_dns"},
	"1.1.1.1":              {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"1.0.0.1":              {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"9.9.9.9":              {Vendor: "Quad9 DNS", Category: "public_dns"},
	"149.112.112.112":      {Vendor: "Quad9 DNS", Category: "public_dns"},
	"223.5.5.5":            {Vendor: "Alibaba DNS", Category: "public_dns"},
	"223.6.6.6":            {Vendor: "Alibaba DNS", Category: "public_dns"},
	"119.29.29.29":         {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"119.28.28.28":         {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"182.254.116.116":      {Vendor: "Tencent DNSPod", Category: "public_dns"},
	"114.114.114.114":      {Vendor: "114DNS", Category: "public_dns"},
	"114.114.115.115":      {Vendor: "114DNS", Category: "public_dns"},
	"180.76.76.76":         {Vendor: "Baidu DNS", Category: "public_dns"},
	"2001:4860:4860::8888": {Vendor: "Google DNS", Category: "public_dns"},
	"2001:4860:4860::8844": {Vendor: "Google DNS", Category: "public_dns"},
	"2606:4700:4700::1111": {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"2606:4700:4700::1001": {Vendor: "Cloudflare DNS", Category: "public_dns"},
	"2400:3200::1":         {Vendor: "Alibaba DNS", Category: "public_dns"},
	"2400:3200:baba::1":    {Vendor: "Alibaba DNS", Category: "public_dns"},
	"2402:4e00::":          {Vendor: "Tencent DNSPod", Category: "public_dns"},
}

// 第 1 级(C) & 第 2 级基座: 八大生态与全球公共 CDN 核心根域。
// 规则: 精确等于以下裸根域本身时 -> hard_block; 为其子域时（非纯广告豁免域）-> warn_confirm。
var ecosystemAndCDNRootDomains = map[string]guardInfraMeta{
	// Apple
	"apple.com":          {Vendor: "Apple", Category: "ecosystem_root"},
	"apple-dns.net":      {Vendor: "Apple", Category: "shared_cdn"},
	"icloud.com":         {Vendor: "Apple", Category: "ecosystem_root"},
	"icloud-content.com": {Vendor: "Apple", Category: "shared_cdn"},
	"cdn-apple.com":      {Vendor: "Apple", Category: "shared_cdn"},
	"mzstatic.com":       {Vendor: "Apple", Category: "shared_cdn"},
	"aaplimg.com":        {Vendor: "Apple", Category: "shared_cdn"},

	// Google
	"google.com":            {Vendor: "Google", Category: "ecosystem_root"},
	"gstatic.com":           {Vendor: "Google", Category: "shared_cdn"},
	"googleapis.com":        {Vendor: "Google", Category: "ecosystem_root"},
	"googleusercontent.com": {Vendor: "Google", Category: "shared_cdn"},
	"googlevideo.com":       {Vendor: "Google", Category: "shared_cdn"},
	"1e100.net":             {Vendor: "Google", Category: "shared_cdn"},
	"gvt1.com":              {Vendor: "Google", Category: "shared_cdn"},
	"gvt2.com":              {Vendor: "Google", Category: "shared_cdn"},
	"android.com":           {Vendor: "Google", Category: "ecosystem_root"},

	// Cloudflare / Akamai / CloudFront / Fastly / Microsoft
	"cloudflare.com":      {Vendor: "Cloudflare", Category: "shared_cdn"},
	"cloudflare.net":      {Vendor: "Cloudflare", Category: "shared_cdn"},
	"akamaized.net":       {Vendor: "Akamai", Category: "shared_cdn"},
	"akamai.net":          {Vendor: "Akamai", Category: "shared_cdn"},
	"akamaiedge.net":      {Vendor: "Akamai", Category: "shared_cdn"},
	"akamaihd.net":        {Vendor: "Akamai", Category: "shared_cdn"},
	"edgekey.net":         {Vendor: "Akamai", Category: "shared_cdn"},
	"edgesuite.net":       {Vendor: "Akamai", Category: "shared_cdn"},
	"cloudfront.net":      {Vendor: "Amazon CloudFront", Category: "shared_cdn"},
	"amazonaws.com":       {Vendor: "Amazon AWS", Category: "cloud"},
	"fastly.net":          {Vendor: "Fastly", Category: "shared_cdn"},
	"fastlylb.net":        {Vendor: "Fastly", Category: "shared_cdn"},
	"microsoft.com":       {Vendor: "Microsoft", Category: "ecosystem_root"},
	"microsoftonline.com": {Vendor: "Microsoft", Category: "ecosystem_root"},
	"office.com":          {Vendor: "Microsoft", Category: "ecosystem_root"},
	"office365.com":       {Vendor: "Microsoft", Category: "ecosystem_root"},
	"msedge.net":          {Vendor: "Microsoft Edge CDN", Category: "shared_cdn"},
	"msecnd.net":          {Vendor: "Microsoft Azure", Category: "shared_cdn"},
	"azure.com":           {Vendor: "Microsoft Azure", Category: "cloud"},
	"windows.net":         {Vendor: "Microsoft Azure", Category: "cloud"},
	"azureedge.net":       {Vendor: "Microsoft Azure", Category: "shared_cdn"},
	"azurefd.net":         {Vendor: "Microsoft Azure", Category: "shared_cdn"},
	"trafficmanager.net":  {Vendor: "Microsoft Azure", Category: "cloud"},
	"live.com":            {Vendor: "Microsoft", Category: "ecosystem_root"},

	// Alibaba
	"alibaba.com":       {Vendor: "Alibaba", Category: "ecosystem_root"},
	"aliyun.com":        {Vendor: "Alibaba", Category: "ecosystem_root"},
	"alicdn.com":        {Vendor: "Alibaba", Category: "shared_cdn"},
	"aliyuncs.com":      {Vendor: "Alibaba", Category: "cloud"},
	"alikunlun.com":     {Vendor: "Alibaba", Category: "shared_cdn"},
	"alikunlun.net":     {Vendor: "Alibaba", Category: "shared_cdn"},
	"tbcdn.cn":          {Vendor: "Alibaba", Category: "shared_cdn"},
	"taobao.com":        {Vendor: "Alibaba", Category: "ecosystem_root"},
	"tmall.com":         {Vendor: "Alibaba", Category: "ecosystem_root"},
	"alipay.com":        {Vendor: "Alibaba", Category: "ecosystem_root"},
	"alipayobjects.com": {Vendor: "Alibaba", Category: "shared_cdn"},
	"alibabacloud.com":  {Vendor: "Alibaba", Category: "cloud"},

	// Tencent
	"tencent.com":       {Vendor: "Tencent", Category: "ecosystem_root"},
	"qq.com":            {Vendor: "Tencent", Category: "ecosystem_root"},
	"weixin.qq.com":     {Vendor: "Tencent WeChat", Category: "ecosystem_root"},
	"servicewechat.com": {Vendor: "Tencent WeChat", Category: "ecosystem_root"},
	"wechat.com":        {Vendor: "Tencent WeChat", Category: "ecosystem_root"},
	"wechatpay.cn":      {Vendor: "Tencent WeChat Pay", Category: "ecosystem_root"},
	"myqcloud.com":      {Vendor: "Tencent Cloud", Category: "shared_cdn"},
	"qcloud.com":        {Vendor: "Tencent Cloud", Category: "cloud"},
	"gtimg.com":         {Vendor: "Tencent", Category: "shared_cdn"},
	"gtimg.cn":          {Vendor: "Tencent", Category: "shared_cdn"},
	"qpic.cn":           {Vendor: "Tencent", Category: "shared_cdn"},
	"qlogo.cn":          {Vendor: "Tencent", Category: "shared_cdn"},
	"idqqimg.com":       {Vendor: "Tencent", Category: "shared_cdn"},
	"tencentcos.cn":     {Vendor: "Tencent Cloud", Category: "cloud"},
	"tencent-cloud.net": {Vendor: "Tencent Cloud", Category: "cloud"},

	// ByteDance
	"bytedance.com":         {Vendor: "ByteDance", Category: "ecosystem_root"},
	"bytednsdoc.com":        {Vendor: "ByteDance", Category: "shared_cdn"},
	"bytefcdn.com":          {Vendor: "ByteDance", Category: "shared_cdn"},
	"bytefcdn-oversea.com":  {Vendor: "ByteDance", Category: "shared_cdn"},
	"douyin.com":            {Vendor: "ByteDance", Category: "ecosystem_root"},
	"douyincdn.com":         {Vendor: "ByteDance", Category: "shared_cdn"},
	"douyinvod.com":         {Vendor: "ByteDance", Category: "shared_cdn"},
	"byteimg.com":           {Vendor: "ByteDance", Category: "shared_cdn"},
	"bytecdn.com":           {Vendor: "ByteDance", Category: "shared_cdn"},
	"bytecdn.cn":            {Vendor: "ByteDance", Category: "shared_cdn"},
	"pstatp.com":            {Vendor: "ByteDance", Category: "shared_cdn"},
	"snssdk.com":            {Vendor: "ByteDance", Category: "ecosystem_root"},
	"amemv.com":             {Vendor: "ByteDance", Category: "ecosystem_root"},
	"toutiao.com":           {Vendor: "ByteDance", Category: "ecosystem_root"},
	"volces.com":            {Vendor: "ByteDance Volcengine", Category: "cloud"},
	"volccdn.com":           {Vendor: "ByteDance Volcengine", Category: "shared_cdn"},
	"volcengine.com":        {Vendor: "ByteDance Volcengine", Category: "cloud"},

	// 国内主流终端与国民级基础设施裸根域
	"huawei.com":        {Vendor: "Huawei", Category: "ecosystem_root"},
	"huaweicloud.com":   {Vendor: "Huawei Cloud", Category: "cloud"},
	"hicloud.com":       {Vendor: "Huawei", Category: "ecosystem_root"},
	"myhuaweicloud.com": {Vendor: "Huawei Cloud", Category: "cloud"},
	"dbankcloud.com":    {Vendor: "Huawei", Category: "cloud"},
	"dbankcloud.cn":     {Vendor: "Huawei", Category: "cloud"},
	"dbankcdn.com":      {Vendor: "Huawei", Category: "shared_cdn"},
	"mi.com":            {Vendor: "Xiaomi", Category: "ecosystem_root"},
	"xiaomi.com":        {Vendor: "Xiaomi", Category: "ecosystem_root"},
	"miui.com":          {Vendor: "Xiaomi", Category: "ecosystem_root"},
	"baidu.com":         {Vendor: "Baidu", Category: "ecosystem_root"},
	"bdstatic.com":      {Vendor: "Baidu", Category: "shared_cdn"},
	"bcebos.com":        {Vendor: "Baidu Cloud", Category: "cloud"},
}

// 显式豁免的纯广告/第三方统计追踪域（即使出现在 shared_infra.txt 或 entity_db.json 中也允许一键直封）。
var exemptPureAdTrackerSuffixes = map[string]bool{
	"doubleclick.net":       true,
	"googleadservices.com":  true,
	"googlesyndication.com": true,
	"google-analytics.com":  true,
	"googletagmanager.com":  true,
	"app-measurement.com":   true,
	"pangle.io":             true,
	"umeng.com":             true,
	"umengcloud.com":        true,
	"umsns.com":             true,
	"cnzz.com":              true,
	"mmstat.com":            true,
	"talkingdata.com":       true,
	"tendcloud.com":         true,
	"growingio.com":         true,
	"sensorsdata.cn":        true,
	"sensorsdata.com":       true,
	"gridsumdissector.com":  true,
	"scorecardresearch.com": true,
	"mob.com":               true,
	"adjust.com":            true,
	"appsflyer.com":         true,
	"branch.io":             true,
	"applovin.com":          true,
	"vungle.com":            true,
	"mintegral.com":         true,
	"rayjump.com":           true,
	"miaozhen.com":          true,
	"admaster.com.cn":       true,
	"reyun.com":             true,
	"tuia.cn":               true,
	"tuiaimg.com":           true,
	"heytapmobi.com":        true,
	"gdt.qq.com":            true,
	"e.qq.com":              true,
	"pos.baidu.com":         true,
	"hm.baidu.com":          true,
	"cpro.baidu.com":        true,
	"tanx.com":              true,
}

type guardEntityRecord struct {
	Type   string `json:"type"`
	Entity string `json:"entity"`
}

var guardEntityDBCache struct {
	mu    sync.Mutex
	path  string
	mtime int64
	size  int64
	ents  map[string]guardEntityRecord
}

var guardFallbackSharedCache struct {
	mu    sync.Mutex
	path  string
	mtime int64
	size  int64
	cur   *output.SharedInfra
}

type sharedCDNCIDR struct {
	prefix netip.Prefix
	vendor string
}

var (
	builtinCDNCIDRsOnce sync.Once
	builtinCDNCIDRs     []sharedCDNCIDR
)

func getBuiltinCDNCIDRs() []sharedCDNCIDR {
	builtinCDNCIDRsOnce.Do(func() {
		raw := []struct {
			cidr   string
			vendor string
		}{
			// Cloudflare Anycast CDN
			{"103.21.244.0/22", "Cloudflare"},
			{"103.22.200.0/22", "Cloudflare"},
			{"103.31.4.0/22", "Cloudflare"},
			{"104.16.0.0/12", "Cloudflare"},
			{"108.162.192.0/18", "Cloudflare"},
			{"131.0.72.0/22", "Cloudflare"},
			{"141.101.64.0/18", "Cloudflare"},
			{"162.158.0.0/15", "Cloudflare"},
			{"172.64.0.0/13", "Cloudflare"},
			{"173.245.48.0/20", "Cloudflare"},
			{"188.114.96.0/20", "Cloudflare"},
			{"190.93.240.0/20", "Cloudflare"},
			{"197.234.240.0/22", "Cloudflare"},
			{"198.41.128.0/17", "Cloudflare"},
			{"2400:cb00::/32", "Cloudflare"},
			{"2606:4700::/32", "Cloudflare"},
			{"2803:f800::/32", "Cloudflare"},
			{"2405:b500::/32", "Cloudflare"},
			{"2405:8100::/32", "Cloudflare"},
			{"2a06:98c0::/29", "Cloudflare"},
			{"2c0f:f248::/32", "Cloudflare"},

			// Fastly CDN
			{"151.101.0.0/16", "Fastly"},
			{"199.232.0.0/16", "Fastly"},
			{"2a04:4e40::/32", "Fastly"},

			// Amazon CloudFront
			{"13.32.0.0/15", "Amazon CloudFront"},
			{"13.35.0.0/16", "Amazon CloudFront"},
			{"13.224.0.0/14", "Amazon CloudFront"},
			{"52.84.0.0/15", "Amazon CloudFront"},
			{"54.230.0.0/16", "Amazon CloudFront"},
			{"99.84.0.0/16", "Amazon CloudFront"},
			{"143.204.0.0/16", "Amazon CloudFront"},
			{"2600:9000::/28", "Amazon CloudFront"},

			// Akamai CDN
			{"23.0.0.0/12", "Akamai"},
			{"104.64.0.0/10", "Akamai"},
			{"184.24.0.0/13", "Akamai"},
			{"2600:1400::/24", "Akamai"},

			// Apple Global / iCloud / CDN
			{"17.0.0.0/8", "Apple"},
			{"2620:149::/32", "Apple"},
			{"2a01:b740::/32", "Apple"},

			// Google Global Cache / Frontend / Cloud SLB
			{"34.64.0.0/10", "Google"},
			{"35.190.0.0/17", "Google"},
			{"74.125.0.0/16", "Google"},
			{"142.250.0.0/15", "Google"},
			{"172.217.0.0/16", "Google"},
			{"216.58.192.0/19", "Google"},
			{"2001:4860::/32", "Google"},
			{"2404:6800::/32", "Google"},
			{"2607:f8b0::/32", "Google"},

			// Microsoft Azure / Front Door / Edge SLB
			{"13.107.0.0/16", "Microsoft"},
			{"20.0.0.0/11", "Microsoft Azure"},
			{"20.32.0.0/11", "Microsoft Azure"},
			{"20.64.0.0/10", "Microsoft Azure"},
			{"20.128.0.0/9", "Microsoft Azure"},
			{"40.64.0.0/10", "Microsoft Azure"},
			{"52.96.0.0/12", "Microsoft"},
			{"204.79.197.0/24", "Microsoft Edge CDN"},
			{"2603:1000::/24", "Microsoft Azure"},
			{"2620:1ec::/36", "Microsoft"},

			// Tencent / WeChat / QCloud SLB & Shared Gateway
			{"43.128.0.0/10", "Tencent Cloud"},
			{"49.51.0.0/16", "Tencent Cloud"},
			{"101.32.0.0/14", "Tencent"},
			{"106.52.0.0/14", "Tencent Cloud"},
			{"109.244.0.0/16", "Tencent"},
			{"111.230.0.0/15", "Tencent Cloud"},
			{"119.28.0.0/15", "Tencent Cloud"},
			{"129.204.0.0/16", "Tencent Cloud"},
			{"134.175.0.0/16", "Tencent Cloud"},
			{"150.109.0.0/16", "Tencent Cloud"},
			{"159.75.0.0/16", "Tencent Cloud"},
			{"175.24.0.0/14", "Tencent Cloud"},
			{"182.254.0.0/16", "Tencent"},
			{"183.3.224.0/20", "Tencent"},
			{"183.232.84.0/24", "Tencent"},
			{"203.205.128.0/17", "Tencent"},
			{"2402:4e00::/32", "Tencent"},

			// Alibaba / Aliyun SLB & CDN
			{"39.96.0.0/12", "Alibaba Cloud"},
			{"47.88.0.0/13", "Alibaba Cloud"},
			{"47.96.0.0/11", "Alibaba Cloud"},
			{"101.37.0.0/16", "Alibaba Cloud"},
			{"101.132.0.0/15", "Alibaba Cloud"},
			{"106.11.0.0/16", "Alibaba"},
			{"106.14.0.0/15", "Alibaba Cloud"},
			{"114.55.0.0/16", "Alibaba Cloud"},
			{"118.31.0.0/16", "Alibaba Cloud"},
			{"118.178.0.0/16", "Alibaba Cloud"},
			{"120.24.0.0/14", "Alibaba Cloud"},
			{"120.55.0.0/16", "Alibaba Cloud"},
			{"120.76.0.0/14", "Alibaba Cloud"},
			{"121.40.0.0/14", "Alibaba Cloud"},
			{"139.196.0.0/16", "Alibaba Cloud"},
			{"139.224.0.0/16", "Alibaba"},
			{"203.119.128.0/17", "Alibaba"},
			{"2400:3200::/32", "Alibaba"},
			{"2408:4000::/22", "Alibaba"},

			// ByteDance / Volcengine CDN & SLB
			{"101.126.0.0/16", "ByteDance"},
			{"110.249.192.0/19", "ByteDance"},
			{"111.225.144.0/21", "ByteDance"},
			{"180.184.0.0/16", "ByteDance Volcengine"},
			{"199.115.252.0/22", "ByteDance"},
			{"2406:d440::/32", "ByteDance"},

			// Huawei Cloud / DBankCloud CDN
			{"114.115.128.0/17", "Huawei Cloud"},
			{"114.116.0.0/16", "Huawei Cloud"},
			{"119.3.0.0/16", "Huawei Cloud"},
			{"121.36.0.0/15", "Huawei Cloud"},
			{"122.112.128.0/17", "Huawei Cloud"},
			{"124.70.0.0/15", "Huawei Cloud"},
			{"139.9.0.0/16", "Huawei Cloud"},
			{"139.159.128.0/17", "Huawei Cloud"},
			{"2407:c080::/32", "Huawei Cloud"},
		}
		for _, item := range raw {
			if p, err := netip.ParsePrefix(item.cidr); err == nil {
				builtinCDNCIDRs = append(builtinCDNCIDRs, sharedCDNCIDR{prefix: p, vendor: item.vendor})
			}
		}
	})
	return builtinCDNCIDRs
}

func entityDBPaths(hncDir string) []string {
	var out []string
	if hncDir != "" {
		out = append(out, dataCandidates(hncDir, "entity_db.json")...)
	}
	out = append(out, filepath.Join("..", "..", "data", "entity_db.json"))
	return out
}

func loadGuardEntityDB(hncDir string) map[string]guardEntityRecord {
	for _, p := range entityDBPaths(hncDir) {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() <= 0 || st.Size() > 512<<10 {
			continue
		}
		guardEntityDBCache.mu.Lock()
		if guardEntityDBCache.path == p && guardEntityDBCache.mtime == st.ModTime().UnixNano() &&
			guardEntityDBCache.size == st.Size() && guardEntityDBCache.ents != nil {
			ents := guardEntityDBCache.ents
			guardEntityDBCache.mu.Unlock()
			return ents
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			guardEntityDBCache.mu.Unlock()
			continue
		}
		var doc struct {
			Entities map[string]guardEntityRecord `json:"entities"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Entities) == 0 {
			guardEntityDBCache.mu.Unlock()
			continue
		}
		norm := make(map[string]guardEntityRecord, len(doc.Entities))
		for k, v := range doc.Entities {
			nk := strings.Trim(strings.ToLower(strings.TrimSpace(k)), ".")
			if nk != "" {
				norm[nk] = v
			}
		}
		guardEntityDBCache.path = p
		guardEntityDBCache.mtime = st.ModTime().UnixNano()
		guardEntityDBCache.size = st.Size()
		guardEntityDBCache.ents = norm
		guardEntityDBCache.mu.Unlock()
		return norm
	}
	return nil
}

func loadGuardSharedInfra(hncDir string) *output.SharedInfra {
	if hncDir != "" {
		if si := loadSharedInfra(hncDir); si != nil {
			return si
		}
	}
	fallback := filepath.Join("..", "..", "data", "dpi_rules.d", output.SharedInfraFileName)
	st, err := os.Stat(fallback)
	if err != nil || st.IsDir() || st.Size() <= 0 || st.Size() > 256<<10 {
		return nil
	}
	guardFallbackSharedCache.mu.Lock()
	defer guardFallbackSharedCache.mu.Unlock()
	if guardFallbackSharedCache.path == fallback && guardFallbackSharedCache.mtime == st.ModTime().UnixNano() &&
		guardFallbackSharedCache.size == st.Size() && guardFallbackSharedCache.cur != nil {
		return guardFallbackSharedCache.cur
	}
	b, rerr := os.ReadFile(fallback)
	if rerr != nil {
		return nil
	}
	si := output.ParseSharedInfra(b)
	guardFallbackSharedCache.path = fallback
	guardFallbackSharedCache.mtime = st.ModTime().UnixNano()
	guardFallbackSharedCache.size = st.Size()
	guardFallbackSharedCache.cur = si
	return si
}

func matchDomainSuffixMap[T any](host string, table map[string]T) (T, string, bool) {
	for h := host; ; {
		if v, ok := table[h]; ok {
			return v, h, true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 || dot+1 >= len(h) {
			break
		}
		h = h[dot+1:]
	}
	var zero T
	return zero, "", false
}

func isExemptAdTrackerDomain(host string) bool {
	_, _, ok := matchDomainSuffixMap(host, exemptPureAdTrackerSuffixes)
	return ok
}

func isSharedEntityType(tp string) bool {
	switch strings.ToLower(strings.TrimSpace(tp)) {
	case "cdn", "cloud", "hosting", "infra", "shared", "push", "sdk":
		return true
	default:
		return false
	}
}

// sharedEcosystemOrgKeys 离线 ip_owner.bin 中虽标记为 ipOwnerKindApp(1),
// 但底层实际承载多业务共享接入网关 / Anycast / 云负载均衡的巨头组织键名。
var sharedEcosystemOrgKeys = map[string]string{
	"tencent":      "Tencent",
	"tencentcloud": "Tencent Cloud",
	"alibaba":      "Alibaba",
	"aliyun":       "Alibaba Cloud",
	"bytedance":    "ByteDance",
	"byteplus":     "BytePlus",
	"huawei":       "Huawei",
	"huaweicloud":  "Huawei Cloud",
	"apple":        "Apple",
	"google":       "Google",
	"googlecloud":  "Google Cloud",
	"microsoft":    "Microsoft",
	"amazon":       "Amazon AWS",
	"baidu":        "Baidu",
	"xiaomi":       "Xiaomi",
	"oppo":         "OPPO/HeyTap",
	"cloudflare":   "Cloudflare",
	"akamai":       "Akamai",
	"fastly":       "Fastly",
	"wangsu":       "Wangsu CDN",
	"qiniu":        "Qiniu CDN",
	"kingsoft":     "Kingsoft Cloud",
	"ucloud":       "UCloud",
}

func matchSharedInfraKeywordVendor(host string) (string, bool) {
	switch {
	case strings.Contains(host, "tencent") || strings.Contains(host, "qq.com") || strings.Contains(host, "weixin") ||
		strings.Contains(host, "wechat") || strings.Contains(host, "myqcloud") || strings.Contains(host, "qcloud") ||
		strings.Contains(host, "gtimg") || strings.Contains(host, "qpic.cn") || strings.Contains(host, "dnsv") ||
		strings.Contains(host, "tcdn") || strings.Contains(host, "smtcdns"):
		return "Tencent", true
	case strings.Contains(host, "alibaba") || strings.Contains(host, "aliyun") || strings.Contains(host, "alicdn") ||
		strings.Contains(host, "taobao") || strings.Contains(host, "kunlun") || strings.Contains(host, "alipay") ||
		strings.Contains(host, "tbcdn"):
		return "Alibaba", true
	case strings.Contains(host, "bytedance") || strings.Contains(host, "bytefcdn") || strings.Contains(host, "bytecdn") ||
		strings.Contains(host, "byteimg") || strings.Contains(host, "volces") || strings.Contains(host, "volccdn") ||
		strings.Contains(host, "volcengine") || strings.Contains(host, "douyin") || strings.Contains(host, "huoshan") ||
		strings.Contains(host, "pstatp"):
		return "ByteDance", true
	case strings.Contains(host, "huawei") || strings.Contains(host, "dbankcloud") || strings.Contains(host, "dbankcdn") ||
		strings.Contains(host, "hicloud") || strings.Contains(host, "cdnhwc"):
		return "Huawei", true
	case strings.Contains(host, "icloud") || strings.Contains(host, "mzstatic") || strings.Contains(host, "cdn-apple") ||
		strings.Contains(host, "aaplimg") || strings.HasSuffix(host, ".apple.com") || host == "apple.com":
		return "Apple", true
	case strings.Contains(host, "gstatic") || strings.Contains(host, "googleapis") || strings.Contains(host, "1e100") ||
		strings.Contains(host, "googlevideo") || strings.Contains(host, "googleusercontent") ||
		strings.HasSuffix(host, ".google.com") || host == "google.com":
		return "Google", true
	case strings.Contains(host, "microsoft") || strings.Contains(host, "msedge") || strings.Contains(host, "msecnd") ||
		strings.Contains(host, "azure") || strings.HasSuffix(host, ".live.com") || host == "live.com" ||
		strings.HasSuffix(host, ".windows.net"):
		return "Microsoft", true
	case strings.Contains(host, "akamai") || strings.Contains(host, "edgekey") || strings.Contains(host, "edgesuite"):
		return "Akamai", true
	case strings.Contains(host, "cloudfront") || strings.Contains(host, "amazonaws"):
		return "Amazon", true
	case strings.Contains(host, "fastly"):
		return "Fastly", true
	case strings.Contains(host, "cloudflare"):
		return "Cloudflare", true
	case strings.Contains(host, "ksyun") || strings.Contains(host, "ks-cdn"):
		return "Kingsoft Cloud", true
	case strings.Contains(host, "wscdns") || strings.Contains(host, "wsglb") || strings.Contains(host, "chinanetcenter") || strings.Contains(host, "lxdns"):
		return "Wangsu CDN", true
	case strings.Contains(host, "bdydns") || strings.Contains(host, "bcebos") || strings.Contains(host, "bdstatic"):
		return "Baidu Cloud", true
	case strings.Contains(host, "getui") || strings.Contains(host, "igexin"):
		return "GeTui Push", true
	case strings.Contains(host, "jpush") || strings.Contains(host, "jiguang"):
		return "Jiguang Push", true
	default:
		return "", false
	}
}

func inferSharedInfraVendor(host string) string {
	if v, ok := matchSharedInfraKeywordVendor(host); ok {
		return v
	}
	return "Shared Infrastructure"
}

func detectSharedInfraDomain(hncDir, rawDomain string) (bool, string) {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(rawDomain)), ".")
	if host == "" {
		return false, ""
	}
	if meta, _, ok := matchDomainSuffixMap(host, hardBlockSystemSuffixes); ok {
		return true, meta.Vendor
	}
	if meta, _, ok := matchDomainSuffixMap(host, ecosystemAndCDNRootDomains); ok {
		return true, meta.Vendor
	}
	if v, ok := matchSharedInfraKeywordVendor(host); ok {
		return true, v
	}
	if ents := loadGuardEntityDB(hncDir); len(ents) > 0 {
		if rec, _, ok := matchDomainSuffixMap(host, ents); ok && isSharedEntityType(rec.Type) {
			vendor := rec.Entity
			if vendor == "" {
				vendor = inferSharedInfraVendor(host)
			}
			return true, vendor
		}
	}
	if si := loadGuardSharedInfra(hncDir); si != nil && si.Match(host) {
		return true, inferSharedInfraVendor(host)
	}
	return false, ""
}

func detectSharedInfraOwnerOrg(org ipOwnerOrg) (bool, string) {
	key := strings.ToLower(strings.TrimSpace(org.Key))
	if org.Kind == ipOwnerKindCDN || org.Kind == ipOwnerKindCloud || org.Kind == ipOwnerKindCarrier {
		vendor := org.Name
		if vendor == "" {
			vendor = sharedEcosystemOrgKeys[key]
		}
		if vendor == "" {
			vendor = org.Key
		}
		return true, vendor
	}
	if v, ok := sharedEcosystemOrgKeys[key]; ok {
		if org.Name != "" {
			return true, org.Name
		}
		return true, v
	}
	lowName := strings.ToLower(strings.TrimSpace(org.Name))
	if v, ok := matchSharedInfraKeywordVendor(lowName); ok {
		if org.Name != "" {
			return true, org.Name
		}
		return true, v
	}
	return false, ""
}

// detectSharedInfraTarget 综合判定 (domain, ipStr) 是否命中公共 DNS / 共享 CDN / 大厂共享网关或云基础设施。
// 命中时严禁将候选 IP 展开进 HNC_CONNBLK 防火墙链，仅允许精确 DNS/SNI 域名层阻断。
func detectSharedInfraTarget(s *server, domain, ipStr string) (bool, string) {
	var hncDir string
	if s != nil {
		hncDir = s.hncDir
	}
	if shared, vendor := detectSharedInfraDomain(hncDir, domain); shared {
		return true, vendor
	}

	trimmedIP := strings.TrimSpace(ipStr)
	if trimmedIP == "" {
		return false, ""
	}
	addr, err := netip.ParseAddr(trimmedIP)
	if err != nil {
		return false, ""
	}
	addr = addr.Unmap()
	canon := addr.String()

	if meta, ok := hardBlockPublicDNSIPs[canon]; ok {
		return true, meta.Vendor
	}

	if org, ok := ipOwnerLookup(canon); ok {
		if shared, vendor := detectSharedInfraOwnerOrg(org); shared {
			return true, vendor
		}
	}

	for _, entry := range getBuiltinCDNCIDRs() {
		if entry.prefix.Contains(addr) {
			return true, entry.vendor
		}
	}

	if s != nil && s.hncDir != "" {
		if names := s.loadIPNames(); len(names) > 0 {
			if nm, ok := names[canon]; ok && nm.Name != "" {
				if shared, vendor := detectSharedInfraDomain(s.hncDir, nm.Name); shared {
					return true, vendor
				}
			}
		}
	}
	return false, ""
}

// detectSharedInfraIP 判定公网单 IP 是否属于公共 DNS / 共享 CDN / 公共云基础设施。
// 注意: 函数签名被 v6_flow_scalpel.go 直接依赖, 严禁变更函数名、参数或返回值类型。
func detectSharedInfraIP(s *server, ipStr string) (bool, string) {
	return detectSharedInfraTarget(s, "", ipStr)
}

func evaluateLeakBlockDomainGuard(hncDir, normDomain string) leakBlockGuardDecision {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(normDomain)), ".")
	if host == "" {
		return leakBlockGuardDecision{Level: leakGuardLevelAllow}
	}

	// 1A. 系统 Captive Portal / 公共 DNS / NTP（本身及所有子域一律 hard_block）
	if meta, _, ok := matchDomainSuffixMap(host, hardBlockSystemSuffixes); ok {
		return leakBlockGuardDecision{
			Level:    leakGuardLevelHardBlock,
			Vendor:   meta.Vendor,
			Category: meta.Category,
			Detail:   "该域名属于系统网络连通性探测、公共 DNS 或授时核心基础设施（" + meta.Vendor + "），封禁将导致设备断网或系统异常，已硬性拒封",
		}
	}

	// 1B. 八大生态与公共 CDN 裸根域本身（Exact Match 裸根域本身 -> hard_block）
	if meta, ok := ecosystemAndCDNRootDomains[host]; ok {
		return leakBlockGuardDecision{
			Level:    leakGuardLevelHardBlock,
			Vendor:   meta.Vendor,
			Category: meta.Category,
			Detail:   "禁止直接封禁核心生态或公共 CDN 裸根域 " + host + "（" + meta.Vendor + "），否则将连带瘫痪全生态子业务",
		}
	}

	// 2A. 纯广告与第三方追踪域显式豁免（直接允许封禁，不触发 warn_confirm）
	if isExemptAdTrackerDomain(host) {
		return leakBlockGuardDecision{Level: leakGuardLevelAllow}
	}

	// 2B. 八大生态与公共 CDN 根域的子域 -> warn_confirm
	if meta, matchedRoot, ok := matchDomainSuffixMap(host, ecosystemAndCDNRootDomains); ok && host != matchedRoot {
		return leakBlockGuardDecision{
			Level:    leakGuardLevelWarnConfirm,
			Vendor:   meta.Vendor,
			Category: meta.Category,
			Detail:   "目标子域归属 " + meta.Vendor + " 共享基础设施（" + matchedRoot + "），封禁可能影响共用该节点的正常功能；如确认无误可携带 force:true 强制封禁",
		}
	}

	// 2C. entity_db.json 共享基础设施实体（排除 ads/analytics 纯追踪类）-> warn_confirm
	if ents := loadGuardEntityDB(hncDir); len(ents) > 0 {
		if rec, matchedApex, ok := matchDomainSuffixMap(host, ents); ok {
			if isSharedEntityType(rec.Type) {
				vendor := rec.Entity
				if vendor == "" {
					vendor = inferSharedInfraVendor(host)
				}
				return leakBlockGuardDecision{
					Level:    leakGuardLevelWarnConfirm,
					Vendor:   vendor,
					Category: rec.Type,
					Detail:   "目标域名属于共享基础设施 " + vendor + "（" + matchedApex + "），封禁可能误伤多个共用应用；如确认继续请传 force:true",
				}
			}
			// entity_db 中明确标为 ads / analytics / tracker 的非共享基础设施，直接放行封禁（不再被下方 shared_infra.txt 拦截）
			if rec.Type == "ads" || rec.Type == "analytics" || rec.Type == "tracker" {
				return leakBlockGuardDecision{Level: leakGuardLevelAllow}
			}
		}
	}

	// 2D. shared_infra.txt 共享 CDN / GSLB / 云存储名单 -> warn_confirm
	if si := loadGuardSharedInfra(hncDir); si != nil && si.Match(host) {
		vendor := inferSharedInfraVendor(host)
		return leakBlockGuardDecision{
			Level:    leakGuardLevelWarnConfirm,
			Vendor:   vendor,
			Category: "shared_infra",
			Detail:   "目标域名命中共享基础设施名单（" + vendor + "），封禁可能影响其他正常应用；如确认继续请传 force:true",
		}
	}

	return leakBlockGuardDecision{Level: leakGuardLevelAllow}
}

// evaluateLeakBlockGuard 对 POST /api/leakguard/block-domain (action=="block") 的目标做三级防误杀评估。
func evaluateLeakBlockGuard(s *server, kind, normVal string) leakBlockGuardDecision {
	var hncDir string
	if s != nil {
		hncDir = s.hncDir
	}
	if kind == "ip" {
		if addr, err := netip.ParseAddr(normVal); err == nil {
			canon := addr.Unmap().String()
			if meta, ok := hardBlockPublicDNSIPs[canon]; ok {
				return leakBlockGuardDecision{
					Level:    leakGuardLevelHardBlock,
					Vendor:   meta.Vendor,
					Category: meta.Category,
					Detail:   "禁止封禁公共 DNS 服务器 IP（" + meta.Vendor + "），否则将导致设备域名解析中断",
				}
			}
			if shared, vendor := detectSharedInfraIP(s, canon); shared {
				return leakBlockGuardDecision{
					Level:    leakGuardLevelWarnConfirm,
					Vendor:   vendor,
					Category: "shared_ip",
					Detail:   "目标 IP 属于 " + vendor + " 公共 CDN/云共享节点，按 IP 封禁可能连坐其他网站；如确认继续请传 force:true",
				}
			}
		}
		return leakBlockGuardDecision{Level: leakGuardLevelAllow}
	}
	return evaluateLeakBlockDomainGuard(hncDir, normVal)
}

// evaluateScopedLeakBlockGuard 对热点/本机/双域封禁目标执行统一的三级基础设施与共享 CDN 防误杀评估。
func evaluateScopedLeakBlockGuard(s *server, kind, normVal, _ string) leakBlockGuardDecision {
	return evaluateLeakBlockGuard(s, kind, normVal)
}
