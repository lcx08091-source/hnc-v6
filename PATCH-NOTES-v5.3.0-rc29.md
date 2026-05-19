# v5.3.0-rc29 — dpid 重写, schema 全功能兑现

**versionCode**: 530090 (rc28.1.1 = 530082)
**dpid 版本**: 0.5.0-rc29-l3-flow (rc28.1.1 = 0.4.0-rc23)
**Schema 版本**: 2.0 (rc28.1.x = 1.2)
**发布日期**: 2026-05-17

## 核心目标

rc28.1 / rc28.1.1 在规则库里加了 `ip_matchers` / `ipv6_matchers` / `priority` / `sub_categories` / `ground_truth` 字段, 但 **dpid 二进制根本没读它们**。rc29 终于让 dpid 真正使用这些 schema。

同时 rc28 二进制保留了几个其实**功能为空的**输出字段(JA4、conntrack、字节流、AP iface 评分),rc29 一并把它们做成真实可用的数据来源。

## 新增能力

### 1) 真实 IPv6 抓包
- BPF 程序扩展双协议路径,IPv4 + IPv6 同等待遇
- DNS / TLS handshake / 端口 53 / 端口 443 全部双栈支持
- 用户态 parse.go 加 IPv6 解析(含扩展头跳过)
- IPv6 流的 RemoteIP 现在正确出现在 `top_sni` / `top_hostnames` 关联里
- **对中国移动 5G + 抖音(几乎全 IPv6 流量)是必备**

### 2) 真实 JA4 指纹
- 实现 FoxIO 公开的 JA4 算法,从 TLS ClientHello 实时计算
- 支持 GREASE 过滤、TLS 1.3 版本协商扩展、ALPN/SNI 排除
- `top_ja4` 和 `top_fingerprints`(rc28 alias) 现在是真实数据
- 可选库:`/data/local/hnc/etc/dpi_ja4_fingerprints.json` 将已知 JA4 映射到应用名

### 3) 真实 conntrack 读取
- 每 15 秒读 `/proc/net/nf_conntrack` 或 `/proc/net/ip_conntrack`
- 自适应:文件不存在 → `conntrack_available: false`,SELinux 拒读 → `conntrack_readable: false`
- WebUI 看到的 `conntrack_flows` 不再恒为 0

### 4) 字节流统计
- 新事件类型 `EventFlow`,在 DNS/TLS 之外的 TCP/UDP 包上触发
- 每个 client 累加 `tx_bytes` / `rx_bytes` 计数器
- 全局 `total_tx_bytes` / `total_rx_bytes` 输出
- 注:由 BPF 仍只放行 DNS + TLS handshake 包,字节统计基于采样,非真实总流量

### 5) IP/IPv6 流分类
- 规则的 `ip_matchers` / `ipv6_matchers` 终于真正生效
- 服务器 IP 落在 CIDR 范围 + 协议/端口匹配 → 命中规则
- 比单纯靠 DNS/SNI 分类更鲁棒(很多 App 不查 DNS、不用 SNI)
- 双向 priority 系统:`specific` 优先,`fallback` 兜底
- 抖音 / bytedance_group 等不再相互污染

### 6) 子分类检测
- 规则可以定义 `sub_categories`,例如 wechat 下的 `voice_call`
- 行为检测:基于 `(CIDR, 端口, pps 阈值)` 触发
- 例:UDP 183.232.84.0/24:8000 持续 > 200 pps → 命中 `voice_call`
- `LabelCount.sub_category` 字段输出命中子分类

### 7) 后台流持续性检测
- 每个 client 独立的 flowTracker,16 个 30 秒桶 = 8 分钟历史
- 持续覆盖 > 80% 桶 → 标记为"后台流"
- 通过 `ClientProfile.background_flows_pct` 输出
- WebUI 可据此区分前台 App 行为 vs 后台 keep-alive
- **直接解决 2026-05-16 真机录包中 WeChat 后台通话污染前台 App 统计的问题**

### 8) 置信度
- 规则带 `ground_truth.verified: true` + 多次观察 → `confidence: high`
- 仅 verified 或者次数 > 20 → `confidence: medium`
- 其他 → `confidence: low`
- WebUI 可据此显示置信度徽章

## Schema 变更

`dpi_state.json` schema 版本从 1.2 → **2.0**

### 新增字段(21 个)

| 字段 | 位置 | 含义 |
|---|---|---|
| `flow_events` | stats / ClientProfile | EventFlow 计数 |
| `background_flows_pct` | ClientProfile | 后台流占比 0..1 |
| `sub_category` | LabelCount | 命中的子分类 key |
| `confidence` | LabelCount / FingerprintCount | high/medium/low |
| `priority` | rule | specific/fallback |
| `ip_matchers` / `ipv6_matchers` | rule | CIDR 列表 |
| `sub_categories` | rule | 子分类映射 |
| `ground_truth` | rule | 真机验证记录 |
| `verified` / `date` / `packets_observed` | ground_truth | verify 详情 |
| `cidr` / `proto` / `ports` / `ports_pattern` / `purpose` / `note` | ip_matcher | matcher 字段 |
| `evidence_packets` / `rate_pps_active` | ip_matcher | 证据计数 |
| `detect` | sub_categories.* | 检测表达式 |
| `_source` | top_ja4 | "library" 或 "observed" |

### 字段兼容性

**rc29 是 rc28.1.1 字段集的严格超集**:

```
rc28.1.1 字段: 90 个
rc29 字段:     111 个 (+21 新)
rc28.1.1 中 rc29 缺失:    0 个 ✓ (完全兼容)
```

WebUI / 上层脚本无需任何修改即可继续工作。

## 文件改动概要

```
dpid/output/rule.go         新     (606 行) 规则解析 + ip_matchers + sub_categories
dpid/output/classify.go     新     (142 行) 三类匹配 + priority + sub-category 检测
dpid/output/dfp.go          新     (308 行) JA4 算法 + 指纹库
dpid/output/conntrack.go    新     (112 行) /proc/net/nf_conntrack 解析
dpid/output/flow.go         新     (208 行) 30s 桶持续性跟踪器
dpid/output/state.go        重写  (837 行) Writer + schema 2.0
dpid/capture/parse.go       重写  (508 行) IPv4+IPv6 + EventFlow + JA4
dpid/capture/ja4.go         新     (150 行) ClientHello -> JA4 输入提取
dpid/capture/bpf.go         重写  (212 行) cBPF 双协议过滤,label-resolve 算法
dpid/capture/rawsocket.go   微改  (203 行) FlowEvents 计数器
dpid/cmd/dpid/main.go       微改  (505 行) EventFlow 分发 + conntrack ticker + JA4 透传
                            ─────
                            ≈ 1700 行新代码
```

## 真机测试需求

以下三项**只有你装上才能验证**:

1. **conntrack 是否可读**:Snapdragon 8 Elite + ColorOS 16 上,SELinux 可能拦截 `/proc/net/nf_conntrack`。装上之后看 `dpi_state.json` 的 `conntrack_readable` 是 true 还是 false。

2. **JA4 算法在国内 App 上的稳定性**:微信、抖音的 TLS ClientHello 可能含非标 GREASE 模式。装上之后 `top_ja4` 字段如果出现某个 JA4 字符串重复几十上百次说明算法稳定;如果每次都不一样说明有 bug。

3. **kernel_drops 是否暴增**:BPF 双协议放行,IPv6 上 TLS handshake 频繁。如果 `stats.kernel_drops` / `stats.packets` 比例显著高于 rc28.1.1,需要调大 `rcv_buf_bytes` 或者缩窄 BPF。

预期 rc29.1 / rc29.2 微迭代修复以上问题。

## 与 rc28.1.1 比较的二进制信息

```
              rc28.1.1                rc29
版本字符串    0.4.0-rc23              0.5.0-rc29-l3-flow
体积          2,949,282 字节          2,556,056 字节
SHA256        f2939e4c...             786ea107...   (md5 简记)
源码          rc20.1 基线             rc20.1 + 1700 行新代码
GO 版本       1.26.2                  1.22.2 (容器 toolchain)
编译标记      -ldflags="-s -w"        -trimpath -ldflags="-s -w"
JSON 字段     90                      111 (+21)
```

**体积变小**:rc28.1.1 是 Go 1.26 编译的(包含较多 runtime),rc29 用 Go 1.22 + trimpath 编译。
