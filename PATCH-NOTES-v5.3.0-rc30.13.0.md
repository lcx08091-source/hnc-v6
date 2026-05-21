# PATCH-NOTES v5.3.0-rc30.13.0 — dpi_rules.d/ batch回填 (AHNC analysis-driven)

**Type**: rules-only patch · no binary changes
**Base**: v5.3.0-rc30.12.34
**Source**: AHNC export `ahnc-export-20260520-110221.zip` (Realme RMX5010, 6h hotspot capture, 4 clients)

## TL;DR

往 `data/dpi_rules.d/` 里加了 **9 个新文件 / 24 条 rule / 56 个 suffix**。
不动 dpid / httpd / launcher 任何二进制。flash 即生效。

针对这份 6h export 实测,SNI 命中率:

```
              unique SNI         按出现次数
  rc30.12      296/360  82.2%   1195/1470  81.3%
  rc30.13      345/360  95.8%   1444/1470  98.2%
  delta        +49      +13.6pp +249       +16.9pp
```

## 新增的 9 个文件

| 文件 | rules | 说明 |
|---|---|---|
| `02-doh-sni-extra.json` | 2 | 给现有 `alibaba_doh` / 新增 `tencent_doh_sni` 补 SNI 维度 (原规则只有 IP matcher, `dns.alidns.com` / `doh.pub` 走 SNI 路径漏判) |
| `35-microsoft-extra.json` | 2 | `microsoftonline.com` / `skype.com` / `xiaomixiaoai.com` 补全 |
| `36-bytedance-music.json` | 2 | 汽水音乐 (`qishui.com`) + 字节 HTTPDNS (`bdurl.net`) |
| `42-caiyun.json` | 1 | **彩云科技全家桶** — 合并 `caiyunapp.com` (天气) + `caiyuncdn.com` (CDN) + `colorfulclouds.net` (数据上报) + `cyapi.cn` (LingoCloud 翻译 API). LinkedIn / 官网文档确认同公司 |
| `44-cn-utility.json` | 5 | 酷安 / 搜狗输入法 / MT 管理器 (`mt2.cn`) / Via 浏览器 / 拼多多补充域 (`pinduoduo.net`, `pddpic.com`, `yangkeduo.com`) |
| `55-rom-coloros-extras.json` | 2 | OPPO/HeyTap 内部代号域: `heypiqi.com` (OPPO 电池云 v2, 走 Cloudflare) + `youlishipin.com` (OPPO 喜番视频). 现有 `oppo_heytap` 没覆盖到. 顺带 Realme `allawn*` 天气 (confidence: medium) |
| `72-mobile-baseline-telemetry.json` | 2 | **中国移动 CMCC DM 强制注册** (`fxltsbl.com`) — 所有入移动产品库 Android 终端必须支持的隐性遥测, 首次开机上报 IMEI. **Qualcomm GPS XTRA** (`qualcomm.cn` / `xtracloud.cn`) — 芯片级 GNSS assistance |
| `82-third-party-sdk.json` | 6 | Sentry / Segment / Datadog (含 6 个 region-specific `browser-intake-*-datadoghq.com` 域) / Sift Science 反欺诈 / 作业帮 SDK / `finzfin` 信贷 SDK (confidence: medium) |
| `84-code-hosting.json` | 2 | GitHub 全族 (`github.com`, `githubusercontent.com`, `github.io`, `githubassets.com`) + Gitee 全族 (`gitee.com`, `giteeusercontent.com`, `gitee.io`) |

合计 dpi_rules.d/: **23 → 32 文件 / 144 → 168 rules**

## 故意不规则化的 SNI

下面这些**不应**变成 rule, 应该进 `90-anomaly-heuristics.json` (TODO, 这版没做):

- `cdn-backup-pool-west.com` (10 次) — 无 DNS 查询 + AWS Singapore IP, 典型代理/VPN 伪 SNI
- `df6fa9ab.qtaeixd.com` (3 次) — 8 位随机 hex 前缀 + NXDOMAIN, DGA 风格代理 SNI

→ 建议 dpid 加 flow_risk 启发式: `sni_without_dns` + `dga_sni` 双命中 → 自动归
  `proxy_suspected` category. 留作 rc31 候选.

## 置信度

22/24 条 `confidence: high`, 2 条 `medium`:
- `finzfin_loan_sdk` — 推测为小额贷款 SDK 但公开归属不确切
- `realme_allawn_weather` — Realme 内部代号 `allawn`, 公开资料少

每条 rule 都带 `ground_truth.evidence_method` 字段, 记录触发 SNI + 归属证据 +
所引 export 文件. 将来重放历史 pcap 可交叉对照.

## attribution 修正

无 attribution_corrections 这次. 但在分析过程中发现**一个误归因**值得记一笔:

> `ms_telemetry_realme_baseline` 规则 (针对 Realme 国行系统基线写的微软遥测域)
> 在这份 export 里 168 次命中,全部来自一台**Windows PC** (MAC `60:ff:9e:...`),
> 而不是 Realme 手机本身. 现规则用 SNI 维度无法区分 "Realme 上传 MS 遥测" vs
> "Windows PC 上传 MS 遥测", 都会归到这个 rule.
>
> **修复方向**(留作 rc31): rule schema 加 `client_filter` 字段, 支持按
> `client_os_hint` (Windows / Android / iOS, 由 DHCP vendor class +
> TCP fingerprint 推断) 过滤. 或者把这条 rule 拆成两个 (Android 路径 + PC 路径).

## 测试

- ✅ JSON parse: 全部 32 个文件 valid
- ✅ rules_version 字段格式与现有规则一致
- ✅ schema_version: "2.0" 统一
- ✅ 在 export 上的回放测试: 81.3% → 98.2% 命中率
- ⚠️ 未在真机上 reload dpid 验证 (需要 Ling 装上 flash 一遍)

## 后续 (rc31 候选)

1. `90-anomaly-heuristics.json` — `sni_without_dns` + `dga_sni` 启发式
2. `client_filter` 字段 — 解决 PC vs 手机归因冲突
3. `confidence: medium` 的 2 条规则在真机观察后升 high 或降 low
