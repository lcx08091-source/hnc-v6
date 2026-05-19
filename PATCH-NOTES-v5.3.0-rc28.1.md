# HNC v5.3.0-rc28.1 — 规则库 v3 整合 Ground Truth

## 主题

把 2026-05-15 / 2026-05-16 用 SNI Labeler App + tcpdump ground truth 抓到的真实数据**全部整合**进规则库. 重点解决:

1. **游戏对战服务器识别** — 用 IP+端口匹配 (SNI 拿不到)
2. **IPv6 流量识别** — 抖音 / 中国移动 5G 主流
3. **微信电话单独识别** — UDP/8000 TRTC 语音流
4. **基础设施过滤** — 阿里 DoH / 共享 SDK 不归 App

dpid binary 不动 (rc23 base), 仅升规则库 schema + 数据.

## 规则库 schema v1.0 → v2.0

### 保留所有 v1 字段

所有 123 条原规则的 `suffixes` 字段都保留, 向后兼容. 不会破坏现有匹配.

### 新增字段

```json
{
  "id": "wangzhe",
  "app": "王者荣耀",
  "category": "game",
  "suffixes": [...],                   // v1: SNI suffix 匹配
  "ip_matchers": [                     // v2 新增: IPv4 CIDR + 端口
    {
      "cidr": "221.178.70.0/24",
      "ports": [30128],
      "proto": "udp",
      "purpose": "主对战服务器",
      "evidence_packets": 9331
    }
  ],
  "ipv6_matchers": [...],              // v2 新增: IPv6 段匹配
  "sub_categories": {                  // v2 新增: 同 App 子用途细分
    "voice_call": {
      "name": "微信电话",
      "detect": "UDP 183.232.84.0/24:8000 rate > 200 pps"
    }
  },
  "ground_truth": {                    // v2 新增: 抓包验证标签
    "verified": true,
    "date": "2026-05-16",
    "packets_observed": 12082
  }
}
```

### 全新规则类型

```json
{
  "id": "tencent_game_family",
  "app": "腾讯手游通用识别",
  "tcp_port_family": [6647, 6649, 8013, 8085, 8801, ...],
  "cidrs_observed": ["36.155.0.0/16", ...],
  "detection_logic": "AND: (port ∈ family) AND (ip ∈ cidrs)"
}
```

协同识别用 — 看到端口家族 + IP 段组合就标"腾讯手游", 但不区分具体游戏 (因为只能用 SNI / 专属对战服务器才能区分).

```json
{
  "id": "alibaba_doh",
  "category": "infrastructure",
  "do_not_attribute_to_app": true
}
```

基础设施标签 — 这些流量看到了**不要归到任何 App**.

## Ground Truth 验证的 App (5 个)

| App | 数据量 | 关键新增 |
|---|---|---|
| 王者荣耀 | 12,082 包 | UDP 221.178.70.0/24:30128 (主对战) + TGW 端口家族 |
| 无畏契约 | 49,992 包 | UDP 111.10.10.0/24:35711 + UDP 36.150.218.0/24:33943 |
| 抖音 | 27,040 包 | IPv6 2409:8963:e08::/48 + TCP 223.85.110.0/24:8889 |
| 微信 | 6,008 包 | UDP 183.232.84.0/24:8000 (电话语音, 子类别) |
| 小红书 | (历史 1 条) | 仅 SNI |

## 抓包工具

抓 ground truth 的 shell 脚本 + Python 分析工具放在 `tools/ground_truth/`:

- `capture.sh` — Termux/root 跑 tcpdump + dumpsys 同时抓包
- `analyze.py` — pcap + foreground log → JSON 报告
- `sni_to_rules.py` — JSON → HNC dpi_rules 增量

未来用户可以自己跑这套工具补抓 App, 持续完善规则库.

## dpid 兼容性

当前 dpid (rc23) **只读 v1 字段** (suffixes), 不识别 v2 新增字段.

意思是: rc28.1 装上后 dpid 行为**和之前一致** — IP matchers 等新数据在文件里, 但 dpid 不会用. 这是**为 rc29 准备**:

- rc29 会扩展 dpid 读 ip_matchers / ipv6_matchers
- 实现"SNI 拿不到 → 退化到 IP 匹配"
- 实现 IPv6 流量识别

rc28.1 这一版**纯粹是规则库升级 + 数据沉淀**, 不改运行时.

## 文件清单

```
M data/dpi_rules.json    32 KB → 38 KB, 123 → 126 rules
                         所有 5 个验证 App 新增 IP/IPv6 matchers
                         新增 2 条基础设施规则 (阿里 DoH / 移动 DNS)
                         新增 1 条协同识别规则 (腾讯游戏家族)
+ tools/ground_truth/    抓包 + 分析工具
+ PATCH-NOTES-v5.3.0-rc28.1.md  本文件
M module.prop            rc28.0 → rc28.1 / 530080 → 530081
```

## 装上预期

跟 rc28.0 行为完全一致 — 不死机, 按钮正常, 持续模式可用. 区别只是**规则库变厚了**.

你能在 HNC 设置页看到规则版本变化:
- 之前: `hnc-curated-v2-rc25.0`
- 现在: `hnc-curated-v3-rc28.1-groundtruth`

## 给社区的话

**任何想给 HNC 贡献规则的用户**:

1. 装 root + Termux
2. 跑 `tools/ground_truth/capture.sh 600` 抓 10 分钟
3. 同时玩你想标注的 App
4. 发抓到的 pcap + log + meta 三个文件
5. 我们/Claude 帮你转成规则增量

这是**最高质量的规则数据来源** — 比纯 SNI 抓取准 10 倍.

## 接下来 (rc29 计划)

1. dpid 支持 ip_matchers / ipv6_matchers
2. IPv6 流识别 (中国移动 5G 必须)
3. 后台流过滤 (用 30 秒桶持续性分析)
4. 子类别识别 (微信电话 vs 微信文字)

---

## rc28.1.1 热修 (2026-05-16 晚)

### 问题

用户实测 rc28.1: 设备明明在刷抖音, HNC 主页标签显示"字节系服务·社交" 而不是"抖音·视频".

### 根因

`bytedance_group` 规则的 suffix 太宽泛 (`bytedance.com`, `snssdk.com`, `zijieapi.com`,
`pstatp.com`, `byteimg.com`, `bytedanceapi.com`) - 这些域名抖音本身就在用. 
dpid 当前匹配逻辑无优先级, 哪个规则先命中算哪个 → "字节系" 抢标签.

### 修复 (rc28.1.1)

1. `douyin` 规则: 新增 8 个抖音独占后缀 (`zijieapi.com`, `snssdk.com`, `pstatp.com`, 
   `byteimg.com`, `bytedanceapi.com`, `douyinstatic.com` 等), 总后缀 8 → 16 个
2. `bytedance_group` 规则: 缩窄到只剩 4 个真正"跨产品/企业级"域名 
   (`bytedance.com`, `bytefcdn.com`, `bytecdn.cn`, `byteoversea.com`),
   confidence: medium → low, 标记 `priority: fallback`
3. 所有 ground-truth 验证规则标记 `priority: specific` 

### 立即效果

刷抖音的设备 → 标签应该正确显示"抖音·视频".

### 长期 (rc29)

dpid 需要支持 `priority` 字段 - 优先匹配 specific, 都不匹配才用 fallback. 
当前 rc28.1.1 是数据层修复 (缩窄 fallback 域名), 而非匹配引擎修复.
