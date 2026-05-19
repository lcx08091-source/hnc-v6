# MIGRATION PROPOSAL: `data/dpi_rules.json` → `etc/dpi_rules.d/*.json`

<!-- rc30.12.30 (TASK-a) v2: GPT 三审报告 §四 P2.16 提案落地 -->
<!-- v2 修订: 锁定 5 个决策点 (§"决策锁定" 节) + 加入 webroot:5879 隐患 (§5.3 + §6) -->

**类型**: 设计提案 (Stage 1, 0 代码改动)
**基线**: HNC v5.3.0-rc30.12.30 / `data/dpi_rules.json` 144 条
**作者对接**: 新对话 Claude → Ling 审 → 通过后下一轮做真实拆分
**生效状态**: **本文档仅为提案**. dpid 加载器未改, `dpi_rules.d/` 未生成

---

## 决策锁定 (v2 修订)

提案初稿留了 5 个开放决策点, Ling 审后锁定如下. 进入 Stage 2 实施时直接按这些走, 不再争论:

| # | 决策 | 锁定 | 备注 |
|---|---|---|---|
| 1 | 文件数粒度 | **方案 A: 23 个 bucket + 1 个 99-user-custom 占位** | 单 bucket 0.6-16 KB, 加规则 diff 最小 (§2.3) |
| 2 | dedup 保护 (compileExternalRules 末尾按 id 去重, 后入覆盖) | **做** | ~10 行, 给 99-user-custom 留可靠覆盖语义 (§3.4 #1) |
| 3 | rules_version 字符串格式 | **`external-d:<v1>,<v2>,...` 拼接** | 已 grep 确认 webroot/Go 无硬解析, 见 §3.4 #3 |
| 4 | service.sh 同步方式 | **`rm -rf <dst> && cp -r <src> <dst>`** | mksh 兼容, rsync 在 Android sh 不一定有 (§3.4 #5) |
| 5 | Stage 4 (删 legacy `dpi_rules.json`) | **永不执行** | 70 KB 留作 dpi_rules.d/ 路径出预料外问题时的保险, 见 §5.4 |

v2 修订还加入了一个 grep 发现的隐患: **`webroot/index.html:5879` 的 KSU WebUI "导出当前规则" 功能硬编码 `cat dpi_rules.json`**, Stage 2/3 需要顺手改. 详见 §5.3 和 §6.

---

## TL;DR

把 70 KB 单文件 `data/dpi_rules.json` 拆成 23 个业务族子文件
`etc/dpi_rules.d/*.json` (外加 1 个占位 `99-user-custom.json`),
dpid 启动时 glob + 顺序 merge. 扫描 144 条规则的结论:

- **零跨规则 CIDR overlap** (11 个 v4 + 10 个 v6 cidr, 两两检查无重叠) → merge 顺序对 match 优先级无影响, 拆分零风险
- 拆分后 23 个 bucket 文件总字节数 64.8 KB (脚本 dry-run 实测), 比原文件 (68.3 KB) 略小 (省掉了顶层 `_comment_top`/`schema_changes_from_v1`/`merge_history` 的重复)
- 最大子文件 `20-tencent-game.json` 16.0 KB (13 条规则, 含 sub_categories 的腾讯游戏占大头), 最小 `52-rom-vivo.json` 0.6 KB
- 加单条新规则 (例如抓包扩 1 条) 的变更面从 "覆盖 70 KB" 降到 "覆盖 0.6-16 KB" 或 "新增 0.5 KB"
- dpid 加载器改动 ~80 行 Go (含 fallback 到 legacy 单文件), 不破坏 mtime cache 语义

---

## 1. 现状分析

### 1.1 文件元信息

```
data/dpi_rules.json  68 290 bytes  144 条规则
顶层字段: schema_version / rules_version / updated_at / _comment_top
         / schema_changes_from_v1 / rules / _comment_changes / merge_history
rules_version: hnc-curated-v3-rc30.12-2026-05-19-v6-valorant-mobile
```

### 1.2 Confidence 分布

| level | count | 含义 |
|---|---|---|
| very_high | 16 | 敢于"自动限速", 装机 100% 识别 |
| high | 97 | 高置信但可能撞名 |
| medium | 23 | 边缘案例 |
| low | 8 | 含糊 |
| **总计** | **144** | |

(跟 HANDOFF v2 §8 一致)

### 1.3 Category 分布

24 种 category, 前 5 大占 82 条 (57%):

```
game            23     (腾讯/网易/米哈游/海外大厂游戏)
system          20     (ROM 内置: 小米/OPPO/华为/三星/Apple/Microsoft)
social          15     (微信/QQ/微博/小红书/海外社交)
video           14     (抖音/快手/B 站/腾讯视频/YouTube/Netflix)
ads             10     (穿山甲/广点通/Adjust/AppsFlyer 等)
ai               9
office           6
sdk-tencent-game 6     (腾讯游戏通用 SDK 大族)
shopping         5
cloud            4
... (剩 14 种 category 各 1-4 条)
```

### 1.4 CIDR overlap 分析 (关键发现)

扫了 21 个 cidr (11 v4 + 10 v6), 两两交叉检查 `ipaddress.overlaps()`:

**结果: 零跨规则 overlap**.

含义:

1. 拆分后 merge 顺序不会改变任何 flow 的 match 结果 — 同一个 IP 包不会在两个不同 rule 的 cidr 范围内
2. 即使两个不同子文件里有相邻 cidr (例如 tencent_video 的 `223.85.x.x/24` 和 douyin 的 `223.85.110.0/24` 在同一 /16), 它们在 `/24` 粒度上是各自独立的, 不冲突
3. 数字本身不大 (144 条规则只产生 21 个 cidr) 说明 HNC 当前以 **DNS/SNI suffix 匹配为主, IP CIDR 匹配为辅**, 拆分对 DPI 主链路 (suffix trie) 完全无影响

这一发现把"拆分会不会引入隐式优先级 bug"的风险降到了零.

### 1.5 业务族归类 (拆分依据)

按 `id` 前缀 + `category` 综合归类, 144 条覆盖到 23 个业务族 (合并掉碎桶后):

| bucket | rules | 业务族描述 | 主要 id 样例 |
|---|---:|---|---|
| `00-core-meta` | 2 | HNC 自检元规则 / P2P 兜底 | vpn_capture_double_count_trap, p2p_unknown_attribution |
| `10-tencent-im` | 5 | 微信 / QQ / 企微 + 微信 PCDN 心跳 marker | wechat, qq_im, qq_extra, qywechat, wechat_pcdn_heartbeat |
| `20-tencent-game` | 13 | 腾讯游戏 SDK + 王者/和平精英/火影 OL/无畏契约源能行动 + 前台心跳 marker | tencent_game_sdk_common, tencent_wzry_exclusive, tencent_codev_valorant_mobile, ... |
| `21-tencent-other` | 6 | 腾讯视频 / 云 / 集团 / 广告 / Bugly / 广点通 | tencent_video, tencent_cloud, gdt, bugly, ... |
| `30-bytedance-kuaishou` | 13 | 字节系 (抖音/头条/西瓜/穿山甲/火山/豆包/TikTok) + 快手 | douyin, toutiao, pangle, volcengine, doubao, kuaishou, ... |
| `32-alibaba` | 10 | 阿里集团 (淘宝/阿里云/钉钉/高德/友盟/通义/饿了么/DoH) | alibaba_group, aliyun_cloud, dingding, amap, tongyi, ... |
| `33-baidu` | 4 | 百度集团 + 文心一言 | baidu_group, baidu_map, baidu_pan, wenxin |
| `34-mihoyo` | 3 | 米哈游 (原神 / 启动器) | mihoyo, mihoyo_extra, hoyoplay_launcher |
| `35-netease` | 5 | 网易集团 + 游戏 + 音乐 + LOL 手游 | netease_group, netease_game, netease_music, lolm |
| `40-media-cn` | 8 | 国内长视频 / 音乐 / Apple Music | bilibili, iqiyi, youku, mango_tv, qq_music, kugou, kuwo, apple_music |
| `41-social-shopping-cn` | 9 | 国内社交 / 电商 / 出行 + 飞书 | weibo, zhihu, xiaohongshu, jd, pinduoduo, meituan, didi, feishu, douban |
| `43-ai` | 6 | 海外 AI (含字节豆包归字节, 不在此) | anthropic, openai, copilot, gemini, kimi |
| `50-rom-xiaomi` | 3 | 小米/MIUI 设备 | xiaomi, xiaomi_update, xiaomi_device_indicator |
| `51-rom-coloros` | 6 | OPPO/ColorOS/Realme + GameSpace + 微软遥测基线 | oppo, oppo_heytap, coloros_realme_device_indicator, realme_gamespace_trigger, realme_preinstalled_third_party, ms_telemetry_realme_baseline |
| `52-rom-vivo` | 2 | vivo / OriginOS | vivo, vivo_system_extra |
| `53-rom-huawei` | 3 | 华为 / HarmonyOS | huawei, huawei_cloud, huawei_update |
| `54-rom-overseas` | 5 | Apple / Microsoft / Samsung 系统域 | apple, apple_update, microsoft_group, microsoft_update, samsung |
| `60-accelerator` | 2 | 加速器 / 下载 | xunyou_accelerator, xunlei |
| `61-game-overseas` | 11 | 海外游戏平台 | steam, epic, riot, garena, battlenet, playstation, xbox, minecraft, roblox, supercell, pubg_global |
| `62-overseas-app` | 16 | 海外社交 / 通讯 / 流媒体 | facebook, instagram, meta_group, twitter, youtube, telegram, whatsapp, discord, line, slack, teams, zoom, netflix, disneyplus, spotify, twitch |
| `70-network-infra` | 5 | CDN + DoH | akamai_cdn, cloudflare_cdn, cloudfront_cdn, fastly_cdn, china_mobile_doh |
| `80-ads-sdk` | 4 | 独立广告/分析 SDK | adjust, appsflyer, google_ads_firebase, sensorsdata |
| `81-overseas-misc` | 3 | 海外其他基础 | google, google_play, github |
| **总计** | **144** | | |

(若 Ling 觉得 23 个文件偏多, 可再合并到 ~15 个; 见 §2.3 trade-off)

### 1.6 子文件大小估计

每个子文件含 `schema_version` + `subset` + `rules_version` + `rules` 数组, 2 空格缩进.
脚本 `tools/dpi_rules_split.py --dry-run` 实测:

```
bucket                      count  size
20-tencent-game             13     16.0 KB   ← 最大, 含 sub_categories 详尽
30-bytedance-kuaishou       13      7.9 KB
62-overseas-app             16      4.0 KB
10-tencent-im                5      4.0 KB
51-rom-coloros               6      3.7 KB
32-alibaba                  10      2.9 KB
61-game-overseas            11      2.7 KB
... (其他都 < 2.5 KB) ...
00-core-meta                 2      1.9 KB
70-network-infra             5      1.4 KB
52-rom-vivo                  2      0.6 KB   ← 最小
合并后总和                 144     64.8 KB
```

**比原文件略小** (省掉 4 个顶层注释字段的复制).

---

## 2. 拆分方案

### 2.1 目录结构

```
etc/dpi_rules.d/
├── 00-core-meta.json
├── 10-tencent-im.json
├── 20-tencent-game.json
├── 21-tencent-other.json
├── 30-bytedance-kuaishou.json
├── 32-alibaba.json
├── 33-baidu.json
├── 34-mihoyo.json
├── 35-netease.json
├── 40-media-cn.json
├── 41-social-shopping-cn.json
├── 43-ai.json
├── 50-rom-xiaomi.json
├── 51-rom-coloros.json
├── 52-rom-vivo.json
├── 53-rom-huawei.json
├── 54-rom-overseas.json
├── 60-accelerator.json
├── 61-game-overseas.json
├── 62-overseas-app.json
├── 70-network-infra.json
├── 80-ads-sdk.json
├── 81-overseas-misc.json
└── 99-user-custom.json     # ★ 占位, 用户本地抓包加规则放这, .gitignored
```

前缀两位数 → `filepath.Glob` + `sort.Strings` 后等于业务优先级.
`99-user-custom.json` 放在最后, 后加载, 用户自定义可覆盖 curated.

### 2.2 单子文件 schema (跟 dpid 现有 `externalRuleFile` struct 兼容)

dpid 当前 `src/dpid/output/rule.go:148-167` 已经定义了 `externalRuleFile`:

```go
type externalRuleFile struct {
    SchemaVersion string         `json:"schema_version"`
    RulesVersion  string         `json:"rules_version"`
    Rules         []externalRule `json:"rules"`
}
```

子文件直接复用这个 schema, **无需改 struct**, 只加一个可选 `subset` 字段做自描述 (dpid 可忽略):

```json
{
  "schema_version": "3",
  "subset": "20-tencent-game",
  "rules_version": "hnc-curated-v3-rc30.12-2026-05-19-v6-valorant-mobile#20-tencent-game",
  "rules": [
    { "id": "tencent_wzry_exclusive", "app": "...", "category": "game", "confidence": "very_high", ... }
  ]
}
```

注意:
- 字段名严格按现有 schema 用 **`id` (不是 `app_id`)** 和 **`app` (不是 `app_name`)** — 拆分不能改字段名, 否则 dpid 加载器 (rule.go:154-167 `externalRule` struct) 解不出
- `rules_version` 加 `#bucket` 后缀, 让单子文件被替换时整体版本号有可追溯性
- `subset` 字段 dpid struct 没定义, json.Unmarshal 会忽略, 不影响兼容性

### 2.3 文件数 trade-off (v2: 已锁定方案 A)

| 方案 | 文件数 | 最大文件 | 优点 | 缺点 |
|---|---:|---|---|---|
| ★ **A: 细分 (锁定)** | 23 (+ 1 user-custom 占位) | 20-tencent-game 16 KB | 业务族最清晰, 改 1 条规则 diff 最小, 加新业务族零冲突 | 文件数偏多, IDE 跳转/grep 噪音 |
| B: 中等 | ~15 | 合并 21/35 进 20, 合并 33/34 进 32, 合并 70/80/81 → 20 KB 左右 | 平衡 | 桶内边界模糊 |
| C: 粗分 | ~8 | tencent / bytedance / alibaba / cn / rom / overseas / cdn / misc | git diff 简单 | 单文件回到 15-20 KB, 失去拆分意义 |

锁定 A 的理由: 主要痛点是"加一条新规则不要 diff 70 KB", A 把单 bucket 压到 0.6-16 KB, 效果最好. 23 个文件不算多 (webroot/ 已 30+). 后续如果觉得碎, 合并比拆分简单 (合并不需要改 dpid).

---

## 3. dpid Go 加载器改动设计

### 3.1 改动位置

`src/dpid/output/rule.go` (本地源) + `daemon/hnc_httpd/...` 没有 (这是 dpid 独有).

改动集中在两个常量 + 一个函数:

- **L21**: `const externalRulesPath = "/data/local/hnc/etc/dpi_rules.json"` → 保留作为 legacy fallback, **新增** `externalRulesDir = "/data/local/hnc/etc/dpi_rules.d"`
- **L220-281**: `loadL3Rules()` → 新增 dir 探测 + glob + 顺序 merge 分支

### 3.2 加载顺序 (优先级从高到低)

```
1. 检查 etc/dpi_rules.d/ 目录存在
   a. 存在 → glob *.json, sort.Strings 后顺序读, merge
   b. 任一子文件解析失败 → log + skip 这个子文件, 不中断整个加载
   c. 解析出 0 条规则 → 回退到 builtinRules (避免空规则集)
2. 目录不存在 → 回退到读 etc/dpi_rules.json (legacy 路径, 现有逻辑)
3. 都失败 → builtinRules (现有 fallback, 不变)
```

### 3.3 伪代码 (不要直接 commit, 设计稿)

```go
// loadL3Rules: rc30.12.X (TASK-a follow-up): 优先 dpi_rules.d/ glob 加载, 回退 dpi_rules.json.
func loadL3Rules() loadedRules {
    // ① 先看 dpi_rules.d/ 目录
    if lr, ok := loadL3RulesFromDir(); ok {
        return lr
    }
    // ② 回退到 legacy 单文件 (现有逻辑保留, 不动)
    return loadL3RulesLegacy()  // 把 L220-281 原 loadL3Rules 改名
}

// loadL3RulesFromDir: glob etc/dpi_rules.d/*.json 顺序 merge.
// 返回 (规则集, ok). ok=false 表示目录不存在 (走 legacy), 不是解析失败.
func loadL3RulesFromDir() (loadedRules, bool) {
    st, err := os.Stat(externalRulesDir)
    if err != nil || !st.IsDir() {
        return loadedRules{}, false
    }
    pattern := filepath.Join(externalRulesDir, "*.json")
    files, err := filepath.Glob(pattern)
    if err != nil || len(files) == 0 {
        return loadedRules{}, false
    }
    sort.Strings(files)  // 前缀数字控制 merge 顺序

    // 聚合 mtime+size 作为缓存 key (替代 legacy 单文件 mtime cache)
    var aggrMtime, aggrSize int64
    var versionParts []string
    var allRules []externalRule
    for _, f := range files {
        st, err := os.Stat(f)
        if err != nil {
            continue
        }
        // 取所有子文件 mtime 最大值 作为聚合版本
        if mt := st.ModTime().UnixNano(); mt > aggrMtime {
            aggrMtime = mt
        }
        aggrSize += st.Size()
        if st.Size() > 1024*1024 {
            // 单子文件超 1MB 跳过, 不能让一个坏文件吃光内存
            log.Printf("WARN dpi_rules.d: skip oversized %s (%d bytes)", f, st.Size())
            continue
        }
        b, err := os.ReadFile(f)
        if err != nil || len(b) == 0 {
            log.Printf("WARN dpi_rules.d: read %s err=%v", f, err)
            continue
        }
        var sub externalRuleFile
        if err := json.Unmarshal(b, &sub); err != nil {
            log.Printf("WARN dpi_rules.d: parse %s err=%v (skipping this subset)", f, err)
            continue  // ★ 关键: 一个坏子文件不让整个 dpid 起不来
        }
        if v := strings.TrimSpace(sub.RulesVersion); v != "" {
            versionParts = append(versionParts, v)
        }
        allRules = append(allRules, sub.Rules...)
    }

    // 缓存命中检查 (跟 legacy 一样用 mtime+size, 但聚合到所有子文件)
    ruleCache.Lock()
    if ruleCache.mtime == aggrMtime && ruleCache.size == aggrSize && len(ruleCache.val.rules) > 0 {
        v := ruleCache.val
        ruleCache.Unlock()
        return v, true
    }
    ruleCache.Unlock()

    if len(allRules) == 0 {
        // 子文件都存在但都没规则 → 视为 legacy fallback
        return loadedRules{}, false
    }

    compiled := compileExternalRules(allRules)
    if len(compiled) == 0 {
        return loadedRules{}, false
    }
    merged := make([]l3Rule, 0, len(compiled)+len(builtinRules))
    merged = append(merged, compiled...)              // external 先 (现有 priority 语义)
    merged = append(merged, builtinRules...)          // builtin 后
    version := "external-d:" + strings.Join(versionParts, ",")
    lr := loadedRules{version: version, rules: merged}

    ruleCache.Lock()
    ruleCache.mtime = aggrMtime
    ruleCache.size = aggrSize
    ruleCache.val = lr
    ruleCache.Unlock()
    return lr, true
}
```

### 3.4 关键设计点 (v2: 5 条已锁定)

1. **冲突解决 (锁定: 加 dedup 保护)**:
   - 当前 `compileExternalRules` 不去重, 多条同 id 会都进 merge slice → suffix trie / cidr 匹配阶段最先匹到哪条无确定保证
   - 分桶后业务族不重叠, 实际不会触发; 但加 dedup 保护给 `99-user-custom.json` 留可靠覆盖语义 (nginx conf.d 风格), 改动小, 无负面
   - 实施代码 (Stage 2 在 `compileExternalRules` 末尾加):
     ```go
     // rc30.12.X (TASK-a follow-up): 按 id 去重, 后入覆盖先入 (nginx conf.d 风格).
     // 给 99-user-custom.json 留可靠覆盖空间.
     seen := make(map[string]int)
     dedup := out[:0]
     for _, r := range out {
         if idx, ok := seen[r.ID]; ok {
             dedup[idx] = r  // 同 id, 后入覆盖
         } else {
             seen[r.ID] = len(dedup)
             dedup = append(dedup, r)
         }
     }
     out = dedup
     ```

2. **错误处理边界 (设计自带, 无开放选项)**:
   - 单子文件 JSON 解析失败 → `log.Printf("WARN ...") + continue`, 不抛
   - 整个目录都 0 条规则 → 返回 `ok=false`, 走 legacy fallback
   - 目录存在但 glob 0 个 .json → 同上, 走 legacy

3. **rules_version 字符串格式 (锁定: `external-d:<v1>,<v2>,...` 拼接)**:
   - v2 grep 实查结论: **webroot 和 Go 代码无 `^external:` 硬解析**, 可以放心改 prefix
     ```
     扫描结果:
       src/dpid/output/rule.go:265-273   只是 prepend, 无反向解析
       src/dpid/output/dfp.go:121-125    JA4 指纹独立文件, 不受影响
       webroot/index.html:3397           textarea placeholder 文案, 无逻辑
       webroot/index.html:7783           WebUI 写用户自定义 rules_version, 不读
       webroot/changelog.html            纯文案
       daemon/hnc_httpd/web/             无任何引用
     ```
   - 拼接格式: `external-d:<v1>,<v2>,...`, 例如:
     ```
     external-d:hnc-curated-v3-rc30.12-...#00-core-meta,hnc-curated-v3-rc30.12-...#10-tencent-im,...
     ```
   - 备选方案 B (`external-d:mtime-<unix>`) 和 C (`_VERSION` 文件) 已废弃 — 拼接虽然长但人类可读, WebUI 显示也能直接 show

4. **缓存 invalidation (设计自带, 无开放选项)**:
   - legacy 用 (单文件 mtime, size) 双 key
   - 新的用 (max(子文件 mtime), sum(子文件 size)) 双 key
   - 加新文件 → size 涨, 命中失败 → reload ✓
   - 删文件 → size 降, 命中失败 → reload ✓
   - 修改某文件 → mtime 涨, 命中失败 → reload ✓
   - **边界**: 同时 +A 删 B 且 sizeof(A)==sizeof(B) 且 mtime 没动 → cache 不刷. 这跟 legacy 的边界一致 (legacy 也是 mtime+size 双 key), 实际不会出问题, 因为修改总会动 mtime

5. **service.sh 部署同步 (锁定: `rm -rf + cp -r`, 不用 rsync)**:
   - 现在 service.sh 把 `data/dpi_rules.json` 同步到 `/data/local/hnc/etc/dpi_rules.json`
   - 拆分后需要同步整个目录. 锁定语法 (mksh 兼容):
     ```sh
     # rc30.12.X (TASK-a follow-up): 同步 dpi_rules.d 目录, 先清旧防 rename 残留.
     if [ -d "$MOD/data/dpi_rules.d" ]; then
         rm -rf "$H/etc/dpi_rules.d"
         cp -r "$MOD/data/dpi_rules.d" "$H/etc/dpi_rules.d"
     fi
     ```
   - 不用 rsync 的理由: Android `/system/bin/sh` (mksh + BusyBox) 上 rsync 不一定在, `cp -r` 是 POSIX 标配 100% 可用
   - 先 `rm -rf` 的理由: 防止 bucket 改名 (例如 `30-bytedance.json` → `30-bytedance-kuaishou.json`) 时旧文件残留导致同 id 规则双份加载

### 3.5 估算改动行数

```
src/dpid/output/rule.go:
  + const externalRulesDir            +1
  + func loadL3RulesFromDir           +60 (含错误处理)
  - 现有 loadL3Rules 改名 + 调一下     +5
service.sh:
  + 同步 dpi_rules.d 目录              +5-10 (mksh)
  --------
  总计                                ~80 行 (含注释和 log)
```

不涉及 builtinRules / compileExternalRules / classify 主路径, 改动可单 commit 回滚.

---

## 4. Migration 脚本

附 `tools/dpi_rules_split.py` (本 patch zip 一并提供).

### 4.1 用法

```bash
# 工程根目录跑
python3 tools/dpi_rules_split.py
# 默认 in: data/dpi_rules.json
# 默认 out: data/dpi_rules.d/<bucket>.json
# 加 --dry-run 只打印不写
```

### 4.2 幂等性

- 同一份输入 → 同一份输出 (按 `id` 字典序 + bucket 顺序确定排序)
- 重跑会覆盖现有 `dpi_rules.d/*.json` (脚本会先清空目录, 防止旧分桶残留)
- `99-user-custom.json` **不被脚本写**, 用户自定义保护
- 不修改输入 `dpi_rules.json`

### 4.3 校验

脚本跑完打印 (dry-run 实测):
```
=== summary ===
input:  data/dpi_rules.json (144 rules, 69 918 bytes)
output: data/dpi_rules.d/   (23 files, 66 333 bytes)
[CIDR] scanned 21 cidr entries from 144 rules
[OK] no cross-rule CIDR overlap (拆分后 merge 顺序对 match 无影响)
[OK] all 144 input rules assigned to exactly one bucket
```

如果统计对不上 (例如某条规则没匹到任何 bucket → 落到 `99-misc`), 脚本会 warn 并列出, 但仍写文件 (让 Ling 看见再修 bucket_of()).

### 4.4 红线

- 脚本是工具, **不在 commit 时直接生成 dpi_rules.d/ 进 git** (TASK-a 红线)
- 实际拆分要等 Stage 3 (见 §5) 决定时再跑
- 跑出来的子文件作为 git commit 提交时, 由 Ling 决定要不要同时 `git rm data/dpi_rules.json` (Stage 4 才删)

---

## 5. 向后兼容 & 部署节奏

三阶段实施 + 一个永不执行的预留阶段, 每阶段都可装机验证 + git revert 单 commit 回滚.

### 5.1 Stage 1 (本提案) — rc30.12.30+ 文档

- 提交 `MIGRATION-PROPOSAL-dpi-rules-d.md` + `tools/dpi_rules_split.py`
- 不改 dpid, 不改 service.sh, 不动 `data/dpi_rules.json`
- **不 bump module.prop / 不改 CHANGELOG** (按 HANDOFF §10 纯文档不 bump 规则)
- 风险: 0

### 5.2 Stage 2 — dpid 加载器双路径 (下一个 rc, 例如 rc30.12.31)

- 改 `src/dpid/output/rule.go` 加 `loadL3RulesFromDir` (§3.3) + dedup 保护 (§3.4 #1)
- 改 `service.sh` 同步 `data/dpi_rules.d/` 目录 (§3.4 #5 锁定的 `rm -rf + cp -r` 语法)
- 此时 `data/dpi_rules.d/` 还不存在 → dpid 永远走 legacy 路径 → 行为完全等价于当前
- 装机验证: 看 `dpid.log` 里的 version tag 还是 `external:hnc-curated-v3-...`, 没变就对
- bump 一档 rc, 因为 dpid 二进制变了
- 风险: 低 (legacy 路径完全保留, 新分支死代码状态)
- 回滚: revert 单 commit 即可

### 5.3 Stage 3 — 跑 migration 脚本生成子文件 + 修 webroot:5879 (rc30.12.32 或同档)

- 在工程目录跑 `python3 tools/dpi_rules_split.py`
- `git add data/dpi_rules.d/`
- **同时保留** `data/dpi_rules.json` (双源并存, 但 service.sh 现在同步两个路径)

**★ Stage 3 必须同时修复 `webroot/index.html:5879` (v2 grep 发现的隐患)**:

KSU WebUI "导出当前规则" 功能 (UI 上的"导出"按钮) 当前是这条 shell:
```js
// webroot/index.html:5879 (现状)
const script = 'H=/data/local/hnc; MOD=$(cat "$H/run/service.path" 2>/dev/null); [ -z "$MOD" ] && MOD=/data/adb/modules/hotspot_network_control; if [ -f "$H/etc/dpi_rules.json" ]; then cat "$H/etc/dpi_rules.json"; elif [ -f "$MOD/data/dpi_rules.json" ]; then cat "$MOD/data/dpi_rules.json"; else echo "{...empty...}"; fi';
```

切到 `dpi_rules.d/` 后这条会读到老文件或读不到, 必须改成优先合并子文件:
```js
// rc30.12.X (TASK-a follow-up): 优先合并 dpi_rules.d/, fallback 到 legacy 单文件.
// 用 jq 把多个子文件 rules 数组合并; jq 不在则降级单 cat.
const script = `
H=/data/local/hnc
MOD=$(cat "$H/run/service.path" 2>/dev/null)
[ -z "$MOD" ] && MOD=/data/adb/modules/hotspot_network_control
for BASE in "$H/etc" "$MOD/data"; do
    if [ -d "$BASE/dpi_rules.d" ] && [ -n "$(ls "$BASE/dpi_rules.d"/*.json 2>/dev/null)" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -s '{schema_version:.[0].schema_version,rules_version:"exported-merged",rules:[.[].rules[]]}' "$BASE"/dpi_rules.d/*.json
        else
            # jq 不在: cat 第一个子文件做 fallback (不完整但能给用户看格式)
            cat "$BASE"/dpi_rules.d/$(ls "$BASE"/dpi_rules.d/ | head -1)
        fi
        exit 0
    fi
    if [ -f "$BASE/dpi_rules.json" ]; then
        cat "$BASE/dpi_rules.json"
        exit 0
    fi
done
echo '{"schema_version":"1.0","rules_version":"empty","rules":[]}'
`;
```

如果 jq 在真机 Termux/BusyBox 不一定有 (Ling 你的环境自查一下), 可以让 fallback 改成 `cat` 所有子文件拼一个粗糙输出.

- 装机验证: `dpid.log` 的 version tag 现在变成 `external-d:hnc-curated-v3-...#00-core-meta,hnc-curated-v3-...#10-tencent-im,...`
- 验证 144 条规则识别行为不变: 抓个微信/抖音/王者包看 ground_truth 还能命中
- 验证 WebUI "导出当前规则"按钮拿到完整 144 条规则的 JSON
- bump 一档 rc
- 回滚: `rm -rf data/dpi_rules.d/`, dpid 自动 fallback 到 `data/dpi_rules.json`, 行为恢复. webroot 改动也可单独 revert.

### 5.4 Stage 4 — 删 legacy `dpi_rules.json` (v2 锁定: 永不执行)

- 原计划: 装机稳定运行 1-2 个 rc 后, `git rm data/dpi_rules.json`
- **v2 锁定: 不执行**. 理由:
  - 70 KB 单文件留着零成本, 是 dpi_rules.d/ 路径出预料外问题时的保险
  - 如果半年/一年后 dpi_rules.d/ 路径稳定无任何 incident, 再补一个独立的 Stage 4 patch 不迟, 不急于现在锁定
  - 永不执行的代价: dpi_rules.json 跟 dpi_rules.d/ 双源, Stage 3 之后所有 curated 规则改动需要在两边同步 — 不可接受
  - 修正方案: **Stage 3 之后, `dpi_rules.json` 由 `tools/dpi_rules_split.py` 生成同步**(不是手编), 即每次跑脚本时把 dpi_rules.d/ 的所有 rules 反向合并写回 dpi_rules.json. 让 dpi_rules.json 成为 dpi_rules.d/ 的派生产物 (只有出问题回滚时才用到)
  - 这个反向合并的实现可以加到 `dpi_rules_split.py` 里, Stage 3 实施时一并做

---

## 6. 风险评估

| 风险点 | 严重度 | 触发条件 | 缓解 |
|---|---|---|---|
| dpid 加载器解析错 → DPI 全瘫 | **高** | Stage 2 新代码引入 bug | Stage 2 走 dry path (目录不存在), 实际不切换; Stage 3 才真切. 装机验证 version tag |
| 单子文件 JSON 损坏 → 整批拆分丢规则 | 中 | 手工编辑 dpi_rules.d/ 时手误 | 加载器 per-file try/catch + log warn (§3.3), 一个坏文件只丢一桶, 其他正常 |
| bucket 分类逻辑错 → 规则路由到错的子文件 | 低 | migration 脚本 bucket 判定函数有 bug | 影响**仅**是文件组织, 所有 144 条规则 merge 后全部生效, classify 行为不变 (因为零 cidr overlap, 见 §1.4) |
| ★ `webroot/index.html:5879` 导出功能读不到新规则 | 中 | Stage 3 切到 dpi_rules.d/ 但忘改 KSU WebUI 的 cat 脚本 | v2 已识别 (§5.3). Stage 3 必须同步改 webroot:5879 那条 shell, 让它先 merge dpi_rules.d/, fallback cat 单文件 |
| `rules_version` 字段格式变化 → WebUI 解析错 | ~~中~~ → **0** | ~~webroot/index.html 对 `external:` 前缀有正则硬匹配~~ | **v2 grep 实查: 无任何硬解析**, Go 代码只 prepend 不反向解析, WebUI 只显示. 风险消除 (§3.4 #3) |
| service.sh 同步 dpi_rules.d/ 失败 | 中 | mksh 兼容性 (cp -r 是否 ok) | `cp -r` 是 POSIX 标配, mksh 必有. rc30.12.X+1 装机验证时 `ls -la /data/local/hnc/etc/dpi_rules.d/` 确认 |
| `99-user-custom.json` 用户加错字段名 | 低 | 用户自己写 JSON 用了 `app_id` 而不是 `id` | dpid 加载器现有逻辑会 silently drop (rule.go:294 `if id == "" \|\| cat == "" { continue }`); WebUI 加个 "已加载 N 条" 计数让用户自查 |
| dpid 启动慢 (打开 23 个文件而不是 1 个) | 极低 | 真机 fs IO 慢 | Android tmpfs 上 23 次 stat+open+read 总开销 < 5ms, 无感 |

### 不在本提案范围内的事

- **不改 `compileExternalRules` 行为** (字段解析逻辑保持不变)
- **不改 classify 主路径** (suffix trie / cidr 匹配不动)
- **不动 builtinRules** (fallback 内置规则集保留)
- **不动 webroot 显示逻辑** (WebUI 那边由 Ling 决定要不要换 version 显示格式)
- **不引入热 reload** (现在是 mtime cache lazy reload, 改成 inotify 是另一个任务)

---

## 验收 checklist (回答完即过)

1. **拆完之后 144 条规则去到哪几个文件了**: §1.5 表, 23 个 bucket 文件 + 1 个 99-user-custom.json 占位 (脚本不写)
2. **加新规则的工作流**:
   - 抓包扩规则 → 跑 `sni_to_rules.py` 生成 → 决定属于哪个业务族 → 编辑该 bucket 的 json (例如新加一条网易游戏 → 改 `35-netease.json`, diff 仅 1-2 行)
   - 用户本地自定义 → 写到 `99-user-custom.json` (不进 git)
3. **dpid 加载器需要改哪几行**: §3.5, 约 80 行集中在 `rule.go` 的新增 `loadL3RulesFromDir` 函数, 不改主路径
4. **装机出问题怎么回滚**:
   - Stage 2 出问题 → revert 单 commit
   - Stage 3 出问题 → `rm -rf data/dpi_rules.d/`, 自动 fallback 到 `dpi_rules.json`
   - Stage 4 永远不删 legacy 是最保险的选项
5. **migration 脚本一次运行产出哪些文件, 是否幂等**: §4. 产出 23 个 `data/dpi_rules.d/<bucket>.json` (不写 99-user-custom); 幂等 (按 id 字典序 + bucket 编号顺序排序)

---

## 附录: 提案不收纳的备选讨论

### A. 为什么不按 confidence 拆而按业务族?

按 confidence 拆 (very_high.json / high.json / medium.json / low.json):

- 优点: dpid 可以按 confidence 整体启用/禁用
- 缺点: 加新规则时, 抓包扩规则 (例如新加一个游戏) 要决定 "这条规则放哪个 confidence 文件"; confidence 是规则属性不是组织属性, 业务族才是组织维度
- 决策: 按业务族拆, confidence 仍然在每条规则的 `confidence` 字段里, dpid classify 可以单独按 confidence filter

### B. 为什么不引入 `_index.json` 元文件?

`dpi_rules.d/_index.json` 列出所有子文件 + 加载顺序:

- 优点: 显式控制顺序, 不依赖文件名前缀数字
- 缺点: 多一个文件, 同步状态难维护 (新加文件忘记登记 index)
- 决策: 文件名前缀数字 + `filepath.Glob+sort.Strings` 足够, 不引入

### C. 为什么不上 inotify?

- 当前 mtime cache 是 lazy reload, 每次 classify 入口都会 stat 检查
- inotify 在 Android Linux 上要起一个 watcher goroutine, 增加 dpid 进程复杂度
- 加新规则后用户重启 dpid 也只是 `pkill -HUP hnc_dpid` 一次, 不算痛点
- 决策: 不在本任务范围

---

**End of proposal**. Ling 看完点头 → 进 Stage 2 (改 dpid 加载器, 真代码改动).
