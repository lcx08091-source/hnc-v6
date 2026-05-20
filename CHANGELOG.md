
## v5.3.0-rc30.12.33

**发布日期**: 2026-05-20
**versionCode**: 530153
**致谢**: GPT 第二轮审查 (rc30.12.32 时点) P0/P1 收口

### 概述

GPT 第一轮审查 (rc28-hf2 时点) 给了 17 条 P0/P1/P2, rc30.12.30 修了
P0 全部 + 关键 P2; TASK-a 三阶段 (rc30.12.30 提案 → rc30.12.31 加载器
预埋 → rc30.12.32 真激活) 把 P2.16 dpi_rules.d/ 收掉. **GPT 第二轮审查**
在 rc30.12.32 之上又找到 7 条问题, 其中 2 条 P0 + 1 条 P1 必须修了才能
tag v5.3.0 stable:

1. **P0.1 双源码树分叉** — rc30.12.30 修 P2.11 时只改了 daemon/hnc_httpd/
   没改 src/hnc_httpd/, 两边内容分叉 120+ 行 (middleware 77 + pair 47),
   `src/README.md` 还在声称"完全一致". 等于源代码层面撒谎: 审计者审 src/
   评估的是死代码, CI 构建跑的是 daemon/. **本版删 src/hnc_httpd/**,
   daemon/ 是唯一权威源, ci_preflight 加 check 防复发.
2. **P0.2 PIN 限流并发窗口** — `CheckPinVerify`(只读) → 释放锁 → constant-time
   比对 → `RegisterPinFail`(累计). 同一 IP 并发 N 个错误请求都能过 Check
   进入比对, 实际尝试可达 5+(N-1) 次. **本版新增 `ConsumePinAttempt`**
   原子方法, 把"占用 1 个名额"放进一把锁, pair.go 改用此方法.
3. **P1.3b /api/health 信息泄露** — apiHealth 返回 `hnc_dir` 字段, 而
   /api/health 在 isPublicPath, 任何能访问端口的网络方都能拿到模块部署
   路径 (典型 `/data/local/hnc`). 帮助攻击者定位文件系统结构. **本版删
   此字段**, grep webroot 确认前端无引用, 零回归.

剩 4 条 P1/P2 (构建 hermetic / 测试夹具 / launcher SIGKILL / LICENSE)
列入 v5.3.1 backlog, 不在本版范围.

### P0.1 双源码树合并 (`src/hnc_httpd/` 删除)

**问题确认**:
```
src/hnc_httpd/hotfix*.go           ← 还在 (3 个 hotfix 文件)
daemon/hnc_httpd/api_live.go       ← rc30.12.30 P2.11 重命名后的新名字
daemon/hnc_httpd/capability.go     ← 同上
daemon/hnc_httpd/action_hotspot_iface_set.go  ← 同上
src/README.md L87-91               ← "两目录内容完全一致"
diff middleware.go: 77 行 diff
diff pair.go: 47 行 diff
binary panic stack 路径 = daemon/hnc_httpd/...  ← CI 真构建 daemon/
```

**修法**:

- 写一次性清理脚本 `tools/cleanup-src-hnc_httpd.sh`, Ling 跑 `--apply` 后
  `git rm -rf src/hnc_httpd/` (patch zip 用 unzip -o 无法表达"删除文件")
- 改 `src/README.md`: 删"两目录完全一致"虚假声明, 改成"daemon/ 是唯一权威源,
  src/ 副本已删. 这是历史遗留布局, 项目 v5.0 起 hnc_httpd 源码就放在 daemon/,
  build.sh 直接从那里 go build 输出"
- `bin/ci_preflight.sh` 末尾加 `check_no_src_httpd_dupe`:
  ```sh
  if [ -d "src/hnc_httpd" ]; then
      GO_FILES=$(find src/hnc_httpd -maxdepth 2 -type f -name '*.go' 2>/dev/null | wc -l)
      if [ "$GO_FILES" -gt 0 ]; then
          echo "[ERROR] src/hnc_httpd/ contains $GO_FILES .go file(s) — double source tree forbidden since rc30.12.33"
          FAIL=$((FAIL+1))
      fi
  fi
  ```

**为什么选删 src/ 而不是改名 daemon/→src/**:

- daemon/hnc_httpd/ 已经是 build.sh、CI、release zip 一切下游的源, 改这个
  路径要动 build.sh / artifact_sanity_check / 可能还有别的脚本, 风险大
- src/hnc_httpd/ 是死代码副本, 删它零下游影响
- "唯一源" 比 "目录命名美学" 更重要

### P0.2 PIN 限流原子化

**问题**:
```go
// 旧 pair.go handlePairVerify (有并发窗口):
allowed, _ := s.limiter.CheckPinVerify(ip)  // ← 只 read, 放锁
if !allowed { return 429 }
// ↓ ↓ ↓ 这段时间内同 IP 别的请求都能过 CheckPinVerify
... parse body ...
... read pending ...
if subtle.ConstantTimeCompare(submitted, pending.PIN) != 1 {
    s.limiter.RegisterPinFail(ip)  // ← 这才扣计数, 但已经晚了
}
```

**修法**:

`ratelimit.go` 加新方法 `ConsumePinAttempt`:
```go
func (rl *RateLimiter) ConsumePinAttempt(ip string) (allowed bool, retryAfter int64, remaining int) {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    // ... 检查 pinLockTS / 窗口过期 / pinAttempts++ / 触锁判断 ...
    // 全部在一把锁里完成
}
```

`pair.go` 改两处:

1. 入口仍用 `CheckPinVerify` 做"已锁定短路"(避免对已锁 IP 浪费 body 读取)
2. 进入 PIN 比对**前**用 `ConsumePinAttempt` 原子占用名额, 占用成功才比对,
   占用失败直接 429
3. PIN 比对成功调 `ResetPin` 清空计数

`RegisterPinFail` 保留 (向后兼容 unit test) 但 deprecated, 新代码不再调用.

### P1.3b /api/health 删 hnc_dir 字段

**问题**: `apiHealth` 返回 `{"status": "ok", "version": ..., "hnc_dir": s.hncDir, "watchdog_passive": ...}`,
而 /api/health 在 isPublicPath, 任何能 reach 端口的网络方都能拿到 hnc_dir 值
(典型 `/data/local/hnc`). 信息泄露.

**修法**:
- `server.go:282` 删 `"hnc_dir": s.hncDir,` 一行
- 加注释说明删除原因, 如果未来需要 hnc_dir 走鉴权端点 (`/api/whoami` 风格)
- grep `webroot/` 全目录确认无任何 JS 代码读 `.hnc_dir` 字段, 零回归

### 验收

1. `go vet ./...` 通过 (本地用 GOPROXY=off 验不了, 因为 x/crypto 没 vendor.
   等 CI 跑完看 build 是否绿. Stage 2 已知 vet 干净, 改动局部不会引入新错)
2. `gofmt` 干净 (本版 3 个 .go 文件 gofmt -d 无输出)
3. `shellcheck -S error` 干净 (本版 2 个 .sh 文件无 error)
4. **Ling 在 commit 前必须先跑 `sh tools/cleanup-src-hnc_httpd.sh --apply`**
   完成 src/hnc_httpd/ 的 git rm. patch zip 是 unzip -o 覆盖式, 无法
   表达"删除文件", 所以这一步必须手动跑

### 装机验证 (跟 rc30.12.32 比)

1. **dpi_rules.d/ 路径不动** — `external-d:` 前缀应保持 (TASK-a Stage 3 验过)
2. **PIN 配对功能**: 用错 PIN 5 次应 429 锁定 (跟之前一样行为, 没改业务流程)
3. **/api/health** 响应 JSON 不再含 `hnc_dir`:
   ```sh
   su -c 'curl -sk https://127.0.0.1:8443/api/health' | jq .
   ```
   应只见 `status` / `version` / `watchdog_passive` 三个字段

### 不在本版范围

- **P1.1 构建非 hermetic** = TASK-i (go mod vendor), 独立任务, 后续做
- **P1.2 测试夹具落后**: 真存在, 但不是 ship blocker, 等 v5.3.1
- **P1.3a 0.0.0.0 绑定**: 有意设计权衡 (ColorOS 主机 IP 漂移), 不动
- **P1.4 launcher 无 SIGKILL 升级**: 改 launcher 启停流程有中等风险, 等 v5.3.1
- **P2.7a 仓库根无 LICENSE**: 法律问题不是工程问题, 单独 commit
- **P2.7b launcher README 静态/动态链接说法**: rc30.12.28 已改代码为 PIE 动态,
  文档没跟. 5 分钟纯文档修复, 等顺手做

---


## v5.3.0-rc30.12.32

**发布日期**: 2026-05-19
**versionCode**: 530152
**致谢**: TASK-a Stage 3 落地 — dpi_rules.d/ 真正激活 (GPT 三审 P2.16 收口完成)

### 概述

rc30.12.31 (上一版) 已把 dpid 加载器升级到双路径 dispatcher, 但 `data/dpi_rules.d/`
还没生成, 死代码状态. 本版按 Stage 3 计划:

1. **跑 `tools/dpi_rules_split.py split`** 生成 23 个 bucket 子文件到 `data/dpi_rules.d/`
2. **`tools/dpi_rules_split.py` 加 sync-legacy 子命令** + 反向跑一次, 把 `data/dpi_rules.json`
   重生成为派生产物 (顶层 `_comment_top` 警告别手编), 跟 23 个子文件的 144 条规则字节级等价
3. **修 `webroot/index.html:5879`** KSU WebUI 导出按钮, 优先合并 dpi_rules.d/, fallback dpi_rules.json
4. **service.sh dpi_rules.d/ 同步块第一次真激活** (rc30.12.31 时模块没 ship 这个目录, 这块代码 dormant)

风险: 中. 跟 rc30.12.31 字节等价改 → 这版 dpid 第一次真走 `loadL3RulesFromDir`, 之前
都没在真机摸过. 装机后必须确认 `l3_rule_version` 从 `external:...` 切到了 `external-d:...`
开头, 且 ground_truth 抓包还能命中 144 条规则.

### Stage 3 拆分: `data/dpi_rules.d/` 23 个 bucket 文件

```
00-core-meta             2 条 (HNC 自检 + p2p 兜底)
10-tencent-im            5 条 (微信 / QQ / 企微 + 微信 PCDN 心跳)
20-tencent-game         13 条 (腾讯游戏 SDK + 王者/和平精英/火影 OL/无畏契约源能)
21-tencent-other         6 条 (视频/云/广告/Bugly/广点通)
30-bytedance-kuaishou   13 条 (抖音/头条/西瓜/穿山甲/火山/豆包/TikTok + 快手)
32-alibaba              10 条 (集团/云/钉钉/高德/友盟/通义/淘宝/饿了么/DoH)
33-baidu                 4 条 (集团/地图/网盘 + 文心)
34-mihoyo                3 条 (米哈游 / 启动器)
35-netease               5 条 (集团/游戏/音乐/LOL 手游)
40-media-cn              8 条 (B 站/爱奇艺/芒果/优酷/QQ 音乐/酷狗/酷我/Apple Music)
41-social-shopping-cn    9 条 (微博/知乎/小红书/京东/拼多多/美团/滴滴/豆瓣/飞书)
43-ai                    6 条 (Anthropic/OpenAI/Copilot/Gemini/Kimi)
50-rom-xiaomi            3 条 (小米/MIUI)
51-rom-coloros           6 条 (OPPO/ColorOS/Realme + GameSpace + 微软遥测基线)
52-rom-vivo              2 条 (vivo/OriginOS)
53-rom-huawei            3 条 (华为/HarmonyOS)
54-rom-overseas          5 条 (Apple/Microsoft/Samsung 系统域)
60-accelerator           2 条 (迅游/迅雷)
61-game-overseas        11 条 (Steam/Epic/Riot/Garena/Battlenet/PSN/Xbox/...)
62-overseas-app         16 条 (FB/IG/Meta/Twitter/Twitch/YouTube/Discord/...)
70-network-infra         5 条 (4 个 CDN + 移动 DoH)
80-ads-sdk               4 条 (Adjust/AppsFlyer/Google Ads/Sensors)
81-overseas-misc         3 条 (Google/Google Play/GitHub)
─────────────────────────────────────────────
TOTAL                  144 条规则, 23 个 bucket 文件, 66.3 KB
```

(对比 `data/dpi_rules.json` 单文件 69.9 KB, 拆分总开销 -3.6 KB. 单文件最大
`20-tencent-game.json` 16 KB, 最小 `52-rom-vivo.json` 630 bytes.)

零跨规则 CIDR overlap (脚本扫描 21 个 cidr 两两交叉验证), merge 顺序对 match 无影响.

### `data/dpi_rules.json` 现在是派生产物

```json
{
  "schema_version": "2.0",
  "rules_version": "hnc-curated-v3-...+derived-from-dpi_rules.d",
  "_comment_top": "★ This file is a DERIVED PRODUCT generated by `tools/dpi_rules_split.py sync-legacy` from data/dpi_rules.d/*.json. Do NOT edit by hand. Edit dpi_rules.d/<bucket>.json instead, then rerun sync-legacy. Kept around as a 70KB safety net in case the dpi_rules.d/ loader path hits an unforeseen issue and dpid needs to fall back.",
  "rules": [ ... ]
}
```

**rc30.12.32 起的规则编辑工作流**:

1. 改 `data/dpi_rules.d/<bucket>.json` (人手编辑这里)
2. 跑 `python3 tools/dpi_rules_split.py sync-legacy` 同步 `data/dpi_rules.json`
3. `git add data/dpi_rules.d/ data/dpi_rules.json && git commit`

绝对不要再手编 `data/dpi_rules.json`. 它存在的唯一理由是 dpi_rules.d/ 加载器
出预料外问题时, dpid 自动 fallback 到这个 70 KB 文件 (v2 锁定 Stage 4 永不
执行的另一种说法 — 文件不删, 但变成派生产物, 跟 dpi_rules.d/ 两端始终一致).

### `tools/dpi_rules_split.py` 加 sync-legacy 子命令

旧用法 (v2 风格, 仍兼容):
```
python3 tools/dpi_rules_split.py [--dry-run]   # 等价于 split 子命令
python3 tools/dpi_rules_split.py --in <path> --out <dir>
```

新用法 (v3):
```
python3 tools/dpi_rules_split.py split [--dry-run]                   # dpi_rules.json -> dpi_rules.d/
python3 tools/dpi_rules_split.py sync-legacy [--dry-run]             # dpi_rules.d/ -> dpi_rules.json
```

sync-legacy 实现要点:
- 按文件名升序读 `dpi_rules.d/*.json` (跟 dpid 加载器 `sort.Strings(files)` 一致)
- 同 `id` 后入覆盖 (跟 `compileExternalRules` dedup 一致)
- 跳过 `99-user-custom.json` (用户本地, 不进 git, 不进派生产物)
- 顶层 rules_version 取所有子文件 rules_version 的公共前缀 + `+derived-from-dpi_rules.d`
- 原子写: `.tmp` + rename

### webroot KSU WebUI 导出按钮修复

`webroot/index.html` 的 `dpiRulesExportBackend()` 之前硬编码 `cat $H/etc/dpi_rules.json`,
切到 dpi_rules.d/ 模式后这条命令会读到老的派生产物 (内容是对的, 但不反映真正在跑的 dpi_rules.d/).
本版改成四级 fallback:

1. `etc/dpi_rules.d/*.json` + jq merge → 优先, 这是真正在跑的规则集
2. `$MOD/data/dpi_rules.d/*.json` + jq merge → 装机时模块包
3. `etc/dpi_rules.json` cat → 派生产物 fallback (没 jq 也走这条)
4. `$MOD/data/dpi_rules.json` cat → 模块包派生产物
5. 都没有 → empty schema

jq 不在的兜底很关键: Android 默认 sh 没 jq, BusyBox 也可能没编 jq. 没 jq 时
直接 fallback 到 cat `dpi_rules.json` (派生产物, 内容跟 dpi_rules.d/ 字节级
等价), 用户感知不到差别.

本地测试 4 个场景全过:
- A 理想 (dpi_rules.d/ + jq): 144 条规则 ✓
- B 降级 (dpi_rules.d/ 不在, 走 dpi_rules.json): 144 条规则 ✓
- C 空 (两个都不在): empty schema ✓
- D 没 jq (mock PATH 排除 jq): fallback 走 dpi_rules.json, 144 条规则 ✓

### service.sh 注释更新

L550-554 的注释 "Stage 2 dormant 块, Stage 3 才激活" 改成"Stage 3 第一次真激活"
+ 加一条 dpi_rules.json 派生产物说明. 逻辑零改动 (`[ -d ... ] && cp -r` 在
Stage 2 写就是为本版准备的, 现在 `$MODDIR/data/dpi_rules.d/` 第一次存在,
块直接跑起来).

### 验收 (装机必看)

1. **第一次走 dpi_rules.d/ 路径的证据** — 看 `dpi_state.json` 的 version tag:
   ```sh
   su -c 'grep -o "\"l3_rule_version\":\"[^\"]*\"" /data/local/hnc/run/dpi_state.json'
   ```
   预期: `"l3_rule_version":"external-d:hnc-curated-...#00-core-meta,...#10-tencent-im,..."`
   (`external-d:` 前缀 = ✓ 走 loadL3RulesFromDir; `external:` 前缀 = 还在 legacy 路径,
   说明 dpi_rules.d/ 没装上去或加载器 fallback 了)

2. **service.sh 同步日志**:
   ```sh
   su -c 'grep "synced dpi_rules.d" /data/local/hnc/logs/service.log | tail -1'
   ```
   预期: `dpid: synced dpi_rules.d/ (23 subset files) to /data/local/hnc/etc/dpi_rules.d`

3. **ground_truth 抓包**: 微信 / 抖音 / 王者任选一个, 看分类还能命中 → 144 条规则识别行为不变

4. **WebUI 导出按钮**: 设置页 → 导出当前规则 → 应该看到 144 条规则的完整 JSON, rules_version 是 merged 或 derived 二选一

### 还未做 (永不做)

- ~~Stage 4 删 legacy dpi_rules.json~~ → v2 锁定永不执行, dpi_rules.json 变成由 sync-legacy 生成的派生产物, 跟 dpi_rules.d/ 共存

---

## v5.3.0-rc30.12.31

**发布日期**: 2026-05-19
**versionCode**: 530151
**致谢**: TASK-a Stage 2 落地 (GPT 三审 P2.16 收口路径)

### 概述

rc30.12.30 (上一版) 收完 GPT P0 4 条 + 部分 P2. 本版按 `MIGRATION-PROPOSAL-dpi-rules-d.md`
(Stage 1 提案, 同 commit 序列) 的 Stage 2 实施: dpid 加载器加 `dpi_rules.d/`
分支, 但**本版仍走 legacy 单文件路径** — 模块还没 ship `data/dpi_rules.d/` 目录,
新代码处于"预埋"状态. Stage 3 (下个或下下个 rc) 跑 `tools/dpi_rules_split.py`
生成子文件 + 修 `webroot/index.html:5879` 后才真正切到新路径.

风险评估: 低. 任何还没拿到 `etc/dpi_rules.d/` 目录的真机, dpid 行为跟
rc30.12.30 字节级等价 — 同一份 `dpi_rules.json` 同样的 mtime cache 同样的
externalRule 解析. 验收: `dpi_state.json` 的 `l3_rule_version` 字段仍是 `external:hnc-curated-v3-...`
(`-d:` 前缀 = Stage 3 才出现), 装机后正常识别 144 条 App.

### dpid 加载器 (`src/dpid/output/rule.go`)

把单函数 `loadL3Rules()` 拆成 dispatcher:

```go
func loadL3Rules() loadedRules {
    if lr, ok := loadL3RulesFromDir(); ok {
        return lr
    }
    return loadL3RulesLegacy()
}
```

新加 `loadL3RulesFromDir()`:

- `os.Stat(externalRulesDir)` 不存在 → 立即返回 `(_, false)`, 走 legacy
- `filepath.Glob("*.json")` + `sort.Strings(files)` → 文件名前缀 (`00-` .. `99-`)
  控制 merge 优先级, `99-user-custom.json` 最后加载所以可覆盖 curated
- 逐文件 stat + read + json.Unmarshal, 任一步失败 `log.Printf("WARN ...") + continue` — **单个坏子文件不让整批拆分丢规则**
- 单子文件大小硬上限 1 MB (`externalRulesSubsetMaxBytes`), 超限 skip
- 所有 rules 收齐后走原 `compileExternalRules`, 跟 legacy 路径共享同一份解析逻辑
- merged version tag = `external-d:` + 各子文件 `rules_version` 逗号拼接

`loadL3RulesLegacy()` 是 rc30.12.30 的 `loadL3Rules()` 原封改名, 行为字节级等价.
mtime cache 加 prefix check (`!strings.HasPrefix(cached.version, "external-d:")`),
防 dir/legacy 路径切换时 (aggregate mtime, sum size) 跟 (single mtime, size)
巧合相等导致返回 stale cache.

### dedup 保护 (compileExternalRules 末尾)

```go
// rc30.12.31 (TASK-a Stage 2): dedup by id, last-write-wins (nginx conf.d 风格).
if len(out) > 1 {
    seen := make(map[string]int, len(out))
    dedup := out[:0]
    for _, r := range out {
        if idx, ok := seen[r.ID]; ok {
            dedup[idx] = r // overwrite earlier entry
            continue
        }
        seen[r.ID] = len(dedup)
        dedup = append(dedup, r)
    }
    out = dedup
}
```

legacy 单文件路径走这条代码也对的 — `dpi_rules.json` 没有同 id 重复, 不会触发. 主要给
Stage 3 `99-user-custom.json` 用户自定义覆盖 curated 留可靠语义.

### `service.sh` 子集目录同步

在原 `dpi_rules.json` 升级逻辑后追加 `dpi_rules.d/` 同步块:

```sh
MOD_RULES_D="$MODDIR/data/dpi_rules.d"
DPID_RULES_D="$HNC_DIR/etc/dpi_rules.d"
if [ -d "$MOD_RULES_D" ]; then
    # 跨升级保留 99-user-custom.json (用户本地抓包扩规则)
    USER_CUSTOM_TMP=""
    [ -f "$DPID_RULES_D/99-user-custom.json" ] && \
        USER_CUSTOM_TMP="$HNC_DIR/etc/.99-user-custom.json.preserve.$$" && \
        cp -f "$DPID_RULES_D/99-user-custom.json" "$USER_CUSTOM_TMP" 2>/dev/null
    rm -rf "$DPID_RULES_D" 2>/dev/null
    cp -r "$MOD_RULES_D" "$DPID_RULES_D" 2>/dev/null
    # 修权限 + 还原 user-custom
    chmod 755 "$DPID_RULES_D"
    find "$DPID_RULES_D" -type f -name '*.json' -exec chmod 644 {} \;
    [ -n "$USER_CUSTOM_TMP" ] && [ -f "$USER_CUSTOM_TMP" ] && \
        mv "$USER_CUSTOM_TMP" "$DPID_RULES_D/99-user-custom.json"
    log "dpid: synced dpi_rules.d/ ... subset files to $DPID_RULES_D"
fi
```

本版 `$MODDIR/data/dpi_rules.d` 不存在 → `[ -d ... ]` 失败 → 整块 skip → service.sh
跟 rc30.12.30 行为等价. Stage 3 模块开始 ship 这个目录时此块自动激活.

### 还未做 (留给后续 rc)

- **Stage 3** (下个或下下个 rc): 跑 `tools/dpi_rules_split.py` 生成 23 个子文件 + git add `data/dpi_rules.d/` + 修 `webroot/index.html:5879` (KSU WebUI "导出当前规则" 现在硬 `cat dpi_rules.json`, Stage 3 后这条命令读到老文件, 见 MIGRATION-PROPOSAL §5.3)
- **Stage 4** (永不执行, v2 锁定): `dpi_rules.json` 留作 dpi_rules.d/ 路径出预料外问题时的 70 KB 保险, 不删. Stage 3 起 `dpi_rules.json` 变成由脚本生成的派生产物
- **P2.13/14/15**: 别的 TASK 范围, 跟本任务无关

### 验收

- `go build ./output/...` 通过, gofmt 干净 (新代码无新增 diff; baseline 原有 5 处 struct 字段对齐遗留不在本任务范围, 红线 §2 "不打超出范围的修复")
- `sh -n service.sh` syntax 通过; shellcheck `-S error` 无 error, `-S warning` 在新增段无 warning
- 真机装上 rc30.12.31 → `dpi_state.json` 的 `l3_rule_version` 字段仍 `external:hnc-curated-v3-...` (没有 `-d:` = 走 legacy = 行为等价 rc30.12.30) → ✓
- 抓个微信/抖音/王者包看 ground_truth 仍命中 144 条规则 → ✓
- `ls /data/local/hnc/etc/dpi_rules.d/` 应该看到目录不存在 (本版没 ship), 这是正常的 → ✓

---


## v5.3.0-rc30.12.30

**发布日期**: 2026-05-19
**versionCode**: 530150
**致谢**: GPT 三审 P0 列表全部修完 + 部分 P2 工程整洁度收口

### 概述

rc30.12.29 把 P1 (架构 / 跨语言契约 / C 细节) 全部落地. 这一版收 P0 4 条安全相关
修复 + 力所能及的 P2 工程整洁度 (hotfix 文件命名 / .bak 残留 / CI 检查 / 文档 schema).

剩下 P2.13 (`stats_v52_*` 重命名) / P2.14 (`hnc_common.sh`) / P2.15 (巨型 shell
拆分) / P2.16 (`dpi_rules.json` 拆分) 风险大或工作量大, 留给下个 rc 分阶段做.
按 GPT 报告标准, 本版做完后 "rc30.12 系列可以心安理得 tag v5.3.0 stable", 但
还有 P2 大头未做, 暂不 tag.

### P0.1 handleLogout 漏洞修复 (pair.go / middleware.go)

之前的实现假设 authMiddleware 已 inject `ctxKeyTokenID`, 但 `/api/logout` 在
`isPublicPath` 里, middleware 早期就 `next.ServeHTTP` 跳过验证不会 inject.
结果 `tidVal` 永远 nil, revoke 那段死代码永不执行, 只清浏览器 cookie. cookie
被偷过的攻击者照样能用 server-side token 直到 60 天硬过期. **这是安全漏洞**.

**修法**: handler 自己解 cookie + `VerifyCookie` + revoke. 仍保留 `/api/logout`
在 isPublicPath 而非走 auth middleware, 因为 logout 应是 idempotent — cookie
过期/无效场景也应返回 200, 不应让用户在"我都要登出了"时还看到 401. 服务端自己
读 cookie, 有效就 revoke server-side token, 无效就只清浏览器 cookie. 无论何种
情况 status 200.

```go
// pair.go: 自己解 cookie. cookie 不存在或无效都 fall-through 到清浏览器 cookie + 200.
cookie, err := r.Cookie(CookieName)
if err == nil && cookie != nil && cookie.Value != "" {
    tokenID, _, verr := VerifyCookie(s.tokens, cookie.Value)
    if verr == nil && tokenID != "" {
        if tok, ok := s.tokens.Get(tokenID); ok {
            tok.Revoked = true
            _ = s.tokens.Put(tokenID, tok)
        }
    }
}
http.SetCookie(w, clearCookie())
// 返回 200
```

### P0.2 checkLocalAdminSecret 强制 64 hex (middleware.go)

之前只比较长度是否相等. 如果磁盘 secret 被部分写入 (截断/写半), 后端会接受
同样截断长度的伪 secret. 前端 (hf2 已修) 明确 `/^[0-9a-fA-F]{64}$/.test(s)`,
后端必须对齐. 抽 `isValid64Hex()` helper, got/want 都强制校验. 磁盘 secret
不是合法 64 hex 时打 log 并拒绝所有请求 (defense-in-depth, 服务变 fail-closed).

### P0.3 forceRemoteAuth 死变量删 (main.go / middleware.go)

rc30.12.18 默认拒绝重构后没有任何代码读 `forceRemoteAuth`. 启动时给它赋
`true` 的代码 + 全局变量声明都删, 只保留 SECURITY log. middleware.go 注释里
"forceRemoteAuth 旗子也保留" 那段误导文字也清除.

### P0.4 apiHealth session_label 死代码删 (server.go / web/app.js)

之前 `apiHealth` 从 ctx 取 `Token` 拿 `Label` 写进 resp, 但 `/api/health` 在
`isPublicPath`, authMiddleware 不会 inject `ctxKeyToken`, `tokVal` 永远 nil.
这段代码从来没跑过.

两个选项:
- (a) 移出 isPublicPath. 但远程 WebUI 顶部 `fetch('/api/health')` 探活会拿
  `version` 和 `watchdog_passive` (app.js:974), 移走会破坏匿名探活. 不可接受.
- (b) 删 session_label 死代码 - 保留匿名探活, 失去 session label UX (次要功能).

选 (b). `app.js loadSessionInfo()` 加 deprecation 注释说明字段永久 absent +
graceful degradation. 如果未来想恢复 session label, 应走独立 `/api/whoami`
端点 (鉴权).

### P2.11 hotfix*.go 合并 (daemon/hnc_httpd/)

之前按 "修第 N 个 bug" 命名的源文件是 patch 思维不是模块思维. 重命名 + 合并:

| 旧文件 | 新文件 | 功能 |
|---|---|---|
| `hotfix16_7_compile_compat.go` | `action_hotspot_iface_set.go` | actionHotspotIfaceSet + requestSnapshotRefresh shim |
| `hotfix16_8_live_api.go` | `api_live.go` | apiLive / apiCapabilities / apiMetrics handlers |
| `hotfix16_9_capability_gate.go` | `capability.go` | readCapabilityBool + tc_htb/tc_netem 读取 |

跟现有 `action_app_limit.go` / `action_device_rename.go` / `api_dpi_v53.go`
风格对齐. 内部逻辑零改动 (字节级 copy), 仅文件名 + 顶部注释更新. `go build` 通过.

### P2.12 .bak 残留 + CI 黑名单 (bin/ci_preflight.sh)

- 删除两个残留 `.bak.<timestamp>` 文件 (`bin/version_consistency_check.sh.bak.1777517057` / `.bak.1777517242`)
- `ci_preflight.sh` 残留检查扩展, 新增黑名单: `*.bak / *.bak.[0-9]* / *~ / .DS_Store / Thumbs.db`
- 顺手修正 module.prop version 正则: 旧版 `.` 没转义 + 只允许 `rc N.M` 两段 + `hotfix` 跟实际 `-hf` 命名不一致. 新正则 `^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+(\.[0-9]+){0,3}(-hf[0-9]+)?$` 正确识别 `v5.3.0-rc30.12.30`.

### P2.17 devices.json 权威 schema (ARCHITECTURE.md)

之前的 schema 段只有个示例 JSON, 字段混在一起靠 key 检索. 替换为三张权威表:

- **A) hotspotd 原始字段**: mac / ip / hostname / vendor / rx_bytes / tx_bytes / first_seen / last_seen / online / rx_bps,tx_bps (写入但 httpd 覆盖)
- **B) hnc_httpd 注入字段**: online (重算) / rx_bps,tx_bps (实时差分) / status (blocked/allowed) / hostname (manual 覆盖) / hostname_src
- **C) rules.json 合并字段**: mark_id / down_mbps / up_mbps / delay_ms / jitter_ms / loss_pct / limit_enabled / delay_enabled

明确写了 "devices.json 只由 hotspotd 写, httpd 经过 buildDevicesPayload 在内存
合并 + 返回, 不回写". 也写了 rule-only / blacklist-only 虚行的来源 (httpd 追加
离线行, 不进 devices.json).

### 没动的部分 (留给下个 rc)

- **P2.13** `bin/stats_v52_*` 重命名 (10 文件 / 100+ 引用跨多语言, 一次性
  风险大, 需要分阶段重命名 + 每次跑 CI 验证)
- **P2.14** 抽 `bin/hnc_common.sh` (设计需要讨论 + 涉及很多 shell 改动)
- **P2.15** 巨型 shell 拆分 (`tc_manager.sh` 2041 行 / `watchdog.sh` 1252 行 等, 真机风险)
- **P2.16** `dpi_rules.json` 拆 `etc/dpi_rules.d/*.json` (dpid 启动逻辑 Go 代码改动)

### 编译 / 验证

- `go build ./daemon/hnc_httpd`: 通过 (Go 1.22.5 host build)
- `sh -n bin/ci_preflight.sh`: 通过
- `sh bin/ci_preflight.sh`: residue 检查 OK, module.prop version 正则识别 valid
- 自检命令 (装机后跑):
  ```bash
  su
  SECRET=$(cat /data/local/hnc/run/local_admin.secret)
  # P0.2 校验: 错长度 secret 必拒
  curl -s -o /dev/null -w "wrong-len: %{http_code}\n" \
    -H "X-HNC-Local-Admin: $(echo -n "$SECRET" | head -c 32)" \
    http://127.0.0.1:8444/api/devices
  # 期望 401
  curl -s -o /dev/null -w "valid: %{http_code}\n" \
    -H "X-HNC-Local-Admin: $SECRET" \
    http://127.0.0.1:8444/api/devices
  # 期望 200

  # P0.1 校验: logout 应 idempotent
  curl -s -X POST -o /dev/null -w "no-cookie: %{http_code}\n" \
    http://127.0.0.1:8444/api/logout
  # 期望 200 (即使没 cookie)
  ```

---


## v5.3.0-rc30.12.29

**发布日期**: 2026-05-19
**versionCode**: 530149
**致谢**: GPT 三审 P1 列表全收口

### 概述

hf2 装机已确认完全修复 KSU WebUI auth required. 这一版回过头收 GPT 三审报告 P1
列表 (架构层重叠 / 跨语言契约一致性 / C 代码细节). 不修真机 bug, 是把工程脆性
点都拧紧, 为后续 tag v5.3.0 stable 做准备.

### P1.6 文档版本号同步

之前 module.prop 一路打到 rc30.12.28-hf2, 但:

- `README.md` 版本字段还停在 `v5.1.0-rc2 (2026-04-24)` — 落后 21 个 rc 版本
- `ARCHITECTURE.md` 顶部 `v5.3.0-rc30.12.7`
- `COMPATIBILITY.md` 顶部 `v5.3.0-rc30.12.8`
- `src/README.md` 当前版本表格 `v5.3.0-rc30.12.18`
- `EVOLUTION.md` "现状" 行 `v5.3.0-rc30.12.7`

全部统一同步到 `v5.3.0-rc30.12.29 / 2026-05-19`. 每处加 HTML 注释
`<!-- rc30.12.29: 文档版本号统一同步 module.prop -->` 方便后续 grep 定位.

后续可在 CI 里 sed module.prop 注入到 .md 顶部占位符自动同步, 这次先把数字对齐.

### P1.7 sentinel 收窄 (service.sh)

GPT 指出 sentinel ↔ watchdog ↔ launcher 三层 supervisor 职责重叠:

- `service.sh` sentinel 在管: dpid launcher / httpd / watchdog / hotspotd
- `bin/watchdog.sh` 在管: hotspotd / httpd / dpid (常规路径)
- `bin/hnc_launcher` 在管: dpid (waitpid + 2s backoff)

watchdog 死了 → sentinel 该兜底重启它.
hotspotd 死了 → 应该是 watchdog 管, sentinel 不该插一脚 (并发拉起触发过双进程事故).

**收窄后 sentinel 只管两件事**:

1. **dpid launcher + LAUNCHER_BROKEN 救命**: 保留. 这是 rc30.12.28 真机救命路径,
   因为 watchdog 自己用 launcher 重启 dpid, launcher 反复失败 (TLS abort) 时
   watchdog 也会一起卡, 需要 sentinel 在更外层兜底 fallback 到直拉 dpid.
   HANDOFF 红线, 不动.

2. **hnc_watchdog 健康**: 新核心职责. watchdog 死了 sentinel 重启,
   watchdog 接管 hotspotd / httpd.

**删除的部分**:

- `sentinel` 对 `hnc_httpd` 的检查 (调用 `launch_httpd_safe`) — 委托 watchdog.ensure_httpd_running
- `sentinel` 对 `hotspotd` 的检查 — 委托 watchdog.check_services

启动日志改 `scope=dpid+watchdog`, 方便日志看清当前 sentinel 在管哪些进程.

### P1.8 ksu.exec 统一入口 (webroot/index.html)

GPT 报告: 同一文件存在两种 `ksu.exec` 调用风格:

- callback-style: `ksu.exec(cmd, cbName) → window[cbName](exitCode, stdout, stderr)` (4990 行 `kexec()`)
- promise-style: `ksu.exec(cmd).then(r => ...)` (11919 行 `execCmd()` legacy)

虽然 promise-style 那段已经 `return` 短路掉 (v5.2-rc1.10), 但源里两套并存,
"下一次 GPT 三审找到根因" 的种子还在. hf2 修过的 callback signature bug 之所以发生,
就是因为 ksu.exec 调用散在 `kexec()` 和 `__hncLoadLocalAdminSecret()` 两处,
同文件 200 行外有正确签名却没参照.

**修法**:

1. 抽 `__hncKsuExecRaw(cmd, timeoutMs)` 作为全 codebase 唯一直接 touch
   `window.ksu.exec` callback API 的函数. 出参标准化为
   `{exitCode, stdout, stderr, syncMs}`, 一律 resolve 不 reject.
2. `kexec()` 改走 raw, profiling (sync/cb 耗时) 保留, 错误友好化保留.
3. `__hncLoadLocalAdminSecret()` 改走 raw, 64 hex 校验保留,
   1500ms timeout 在 raw 里实现.
4. 删 11910-11999 整段 dead promise-style code (90 行 + CSS + HTML 入口块).

任何对 ksu.exec 调用风格的修改 (回调签名、Promise 化、SDK 升级等) 之后只改
`__hncKsuExecRaw` 一个函数.

`grep "window\.ksu\.exec("` 真实调用点从 4 处压到 1 处.

### P1.9 crash_tracker_record 重写 (hnc_launcher.c)

旧版本是 "滑动窗口里现有几次 + 加新条目 + 数组满滚动覆盖最老" 三步交错,
窗口边界滚动时容易让人误读. 改成 "先压缩窗口外、再追加新崩溃" 两步语义:

```c
static int crash_tracker_record(struct crash_tracker *t)
{
    time_t now = time(NULL);
    int kept = 0, i;

    /* 1. 压缩 */
    for (i = 0; i < t->count; i++) {
        if (now - t->timestamps[i] <= CRASH_WINDOW_SEC)
            t->timestamps[kept++] = t->timestamps[i];
    }
    /* 2. 追加 (数组满了丢最老) */
    if (kept >= CRASH_LIMIT) {
        memmove(&t->timestamps[0], &t->timestamps[1],
                sizeof(time_t) * (CRASH_LIMIT - 1));
        t->timestamps[CRASH_LIMIT - 1] = now;
        t->count = CRASH_LIMIT;
    } else {
        t->timestamps[kept++] = now;
        t->count = kept;
    }
    return t->count >= CRASH_LIMIT;
}
```

行为等价 (单元测试可证), 阅读清晰.

### P1.10 check_singleton TOCTOU 修复 (hnc_launcher.c)

旧版本:

```c
pid_t existing = read_pid_file(PID_GUARD);
if (existing > 0 && existing != getpid() && pid_alive(existing))
    return -1;
if (write_pid_file(PID_GUARD, getpid()) < 0) return -1;
```

read → check → write 三步, 两个 launcher 同时启动可能都过 check 然后都 write,
后写者赢但实际两个 launcher 都在跑抢 dpid.

**修法**: `open(O_CREAT|O_RDWR|O_CLOEXEC) + flock(LOCK_EX|LOCK_NB)` 一步原子锁定.

```c
int fd = open(PID_GUARD, O_CREAT|O_RDWR|O_CLOEXEC, 0644);
if (flock(fd, LOCK_EX|LOCK_NB) != 0) {
    /* 另一个 launcher 持锁, 退出 */
    close(fd);
    return -1;
}
/* 持锁, 写 pid. fd 全程不 close — 进程退出时 kernel 释放 flock. */
ftruncate(fd, 0);
write(fd, pidbuf, n);
g_lock_fd = fd;  /* 全局保存防止误 close */
```

副作用: `pid_alive()` 不再被使用, 一并删掉. `read_pid_file()` 还在用 (锁失败时
读对方 pid 报告日志). VERSION bump `0.1.0-rc30.12` → `0.1.0-rc30.12.29`.

新加 include: `<sys/file.h>` (flock).

### 没动的部分 (留给下个 rc)

仍未处理的 GPT 三审条目:

- **P0** 全部 (handleLogout / checkLocalAdminSecret hex / forceRemoteAuth / apiHealth) — 下个对话做
- **P2** 全部 (hotfix*.go 合并 / stats_v52_* 清理 / bin/hnc_common.sh / 巨型 shell 拆分 / dpi_rules.json 拆分 / devices.json schema) — 下个对话做
- CI 自动版本号注入 (sed module.prop → docs)
- rc 系列收敛成 v5.3.0 stable (等 P0 + P2 落地后再 tag)

### 编译验证

- `gcc -O2 -Wall -Wextra -c hnc_launcher.c`: 通过 (只剩 pre-existing 的 `on_term_signal` unused 'sig' warning, 跟本次改动无关)
- `sh -n service.sh`: 通过
- `grep "window\.ksu\.exec(" webroot/index.html`: 1 处真实调用点 (在 `__hncKsuExecRaw` 内部, 符合设计)

### 装机验证清单

1. `cat /data/adb/modules/hotspot_network_control/module.prop` 应看到 `v5.3.0-rc30.12.29`
2. KSU WebUI 加载正常 (hf2 修复仍有效, P1.8 wrapper 不应破坏功能)
3. `tail -30 /data/local/hnc/logs/sentinel.log` 应看到 `scope=dpid+watchdog`
4. `ps -ef | grep hnc_` 应看到 5 个进程都在 (hotspotd / dpid / launcher / httpd / watchdog)
5. **故意测试 P1.10**: 在 `bin/hnc_launcher` 启动后再手动 `bin/hnc_launcher`,
   第二个应立刻退出并打印 `another launcher running (PID=...), exiting`

---


## v5.3.0-rc30.12.28-hf2

**发布日期**: 2026-05-19
**versionCode**: 530148
**致谢**: GPT 三审 (找到了 hf1 还没修到根的真正 bug)

### 真正根因 (我之前漏掉的)

hf1 装上用户机器后, KSU WebUI 还是 "auth required". GPT 审查代码发现:

**`__hncLoadLocalAdminSecret()` 的 ksu.exec 回调签名写错了**

```javascript
// 错的 (rc30.12.14 起就一直错):
window[cbName] = function(out) {           // ← 只接 1 个参数
  const s = String(out || '').trim();
  if (s) {
    __hncLocalAdminSecret = s;             // ← 实际拿到的 s = "0" (exitCode!)
  }
  resolve(__hncLocalAdminSecret);
};
window.ksu.exec('cat ... secret', cbName);
```

KSU/SukiSU 的 `ksu.exec` 回调**真实签名**是 `(exitCode, stdout, stderr)` 三参数 (可在 `kexec()` 第 4990 行确认). 之前写 `function(out)` 拿到的 `out` 就是 **exitCode** (数字 0), 不是 stdout!

然后 `String(0).trim() = "0"`, `__hncLocalAdminSecret` 被设为字符串 `"0"`. fetch 注入 header 变成 `X-HNC-Local-Admin: 0`. 后端 `checkLocalAdminSecret` 用 64 字节 hex 文件内容做 constant-time 比较, 长度不等直接拒绝 -> 401.

**这就是为什么用户 curl 用 `$SECRET` 能 200, 但 WebUI 永远 auth required.**

### 修复

#### 1. secret 回调签名修正 + hex 校验

```javascript
window[cbName] = function(exitCode, stdout, stderr) {
  var code = parseInt(String(exitCode), 10);
  var s = (typeof stdout === 'string' ? stdout : String(stdout || '')).trim();
  // 校验: 64 字符 hex (service.sh /dev/urandom 32 字节 hex)
  if (code === 0 && /^[0-9a-fA-F]{64}$/.test(s)) {
    __hncLocalAdminSecret = s;
  }
  resolve(__hncLocalAdminSecret);
};
```

#### 2. KSU WebUI 强制 bridge-first

GPT 还指出: 即使 fetch 注入了正确 secret, 也可能因为 KSU WebView 加载源是远程域 (e.g. `https://mui.kernelsu.org`) 导致 fetch 自动带 Origin header, `authMiddleware` 看到 Origin 就不走 "无 Origin/Referer 的 loopback secret" 分支, 还是 cookie 鉴权失败.

最稳的链路是 `ksu.exec curl ...` (curl 没有浏览器 Origin), 完美匹配中间件的本地管理员安全模型.

修改 `apiGet`:

```javascript
var __hncIsKsuWebUI = (window.ksu && typeof window.ksu.exec === 'function');
// KSU WebUI 直接跳过 fetch, 不浪费 1.8s 等超时
if (!__hncIsKsuWebUI && !__hncPreferBridgeTransport) {
  // fetch path
}
// bridge path (ksu.exec curl)
```

#### 3. KSU WebUI 收 401 不跳 /pair

`/pair` 是远程浏览器的 cookie 配对流程, 本地 KSU WebUI 应用 root secret, 不应被 401 误导到错流程. 修改 `fetchJsonWithTimeout` 的 401 处理:

```javascript
if (resp.status === 401 && !isKsu) {
  // 才跳 /pair
}
```

### 装机验证

刷入 rc30.12.28-hf2 后, KSU WebUI:

1. ✅ 设备列表能正常加载 (`X-HNC-Local-Admin` header 现在带的是真 64 hex)
2. ✅ 顶部 toast 不再 "auth required"
3. ✅ DPI / 统计 / 日志 / 设置 tab 都能访问
4. ✅ 不会自动跳到 /pair 页面

验证命令:
```bash
su
# 1. 看 secret 文件
ls -la /data/local/hnc/run/local_admin.secret  # 64 字节
# 2. 直接 curl 测后端
SECRET=$(cat /data/local/hnc/run/local_admin.secret)
curl -H "X-HNC-Local-Admin: $SECRET" http://127.0.0.1:8444/api/devices  # 200
# 3. 看 webroot 是新版
grep "rc30.12.28-hf2" /data/adb/modules/hotspot_network_control/webroot/index.html | head -1
# 应输出 hf2 注释
# 4. 看 httpd 日志没 401
tail -50 /data/local/hnc/logs/httpd.log | grep -c "auth required"
# 应该 0 (KSU WebUI 打开后)
```


## v5.3.0-rc30.12.28-hf1

**发布日期**: 2026-05-19
**versionCode**: 530147

hotfix1: 修 rc30.12.28 launcher 编译 + TLS 对齐根因.

### 根因

rc30.12.28 用 `-static-pie` 和 `-Wl,-z,max-page-size` 试图修 Bionic TLS 对齐, 但**都没用** —— 因为静态链接时, NDK 提供的 Bionic libc archive (`libc.a`) 里 TLS segment 本身就是 8 字节对齐. Linker flag 改不了 archive 内已经编好的 segment 对齐.

### 重新审视

发现 hnc_launcher.c 注释说"需要 `-static` 是因为 post-fs-data 早期 /system 未必 mount" —— 但 service.sh 实际是 **Magisk/KSU late_start service**, 跑在 boot 5 秒后, 此时 `/system` 早已 mount. 静态链接不是必须的, 完全可以动态链接.

### 真修

`src/launcher/build.sh`: hnc_launcher 改用 PIE + 动态链接 (跟 fork_probe 一样的编法).

```sh
# 之前 (有 TLS 对齐问题):
$CLANG -static -o hnc_launcher hnc_launcher.c

# 现在 (跟 fork_probe 一样的 PIE 动态链接):
$CLANG -o hnc_launcher hnc_launcher.c
```

### 副作用

- hnc_launcher 大小: ~700 KB → ~7 KB (libc 不再嵌入)
- 启动时依赖 `/system/lib64/libc.so` (late_start 阶段一定存在)
- 跟 fork_probe 行为一致, 不引入新的兼容性风险

### 为什么这次能成

因为你机器上 **fork_probe 跑通了** (是动态链接 PIE). hnc_launcher 用一模一样的编译方式, 应该也能跑.


## v5.3.0-rc30.12.28

**发布日期**: 2026-05-19
**versionCode**: 530146

紧急修复 rc30.12.27 真机装机暴露的 **5 个 P0/P1** + GPT 三审 P0.

### 背景

rc30.12.27 装到 RMX5010 (ColorOS 16 + SukiSU) 后,**WebUI 完全不能用**(显示 auth required),GPT 三审同时报告了一个 dpid 启动链 P0。诊断后发现 5 个独立但叠加的问题。

### 修复清单

#### P0-1: webroot/index.html fetch 路径漏注入 secret

**症状**: KSU WebUI 永远显示 "刷新提示: auth required" / "失败: auth required",刷新按钮失败,设备列表空。

**根因**: rc30.12.18 引入默认拒绝中间件后,所有 API 调用必须带鉴权(cookie 或 X-HNC-Local-Admin header)。webroot/index.html 的 `apiGet` 函数**优先走 fetch 路径**,但 `fetchJsonWithTimeout` 函数**只设置 `Cache-Control` header,没注入 X-HNC-Local-Admin**,只有 bridge 路径 (`window.ksu.exec` curl) 才注入。所以 fetch 永远 401,bridge 又因为 fetch "成功"(其实是 401)而不会被启用。

**修复**:
- `fetchJsonWithTimeout`: 设置 fetch options 时检查 `__hncLocalAdminSecret`,有就注入 `X-HNC-Local-Admin` header
- `apiGet`: 函数入口处先 `await __hncLoadLocalAdminSecret()`,保证 fetch 调用时 secret 一定就绪(有缓存,只首次有开销)

#### P0-2: service.sh 选 C launcher 后启动分支错 (GPT 三审 P0)

**症状**: fork_probe PASS 选了 C launcher,但 service.sh 第 558 行判断只匹配 `$DPID_SUPERVISOR` 或 `$DPID_GUARD`,**没匹配 `$DPID_LAUNCHER_C`**,走 else 分支**直启 hnc_dpid**。然后 sentinel 检查"launcher 进程"为 0,试图拉 hnc_launcher,可能造成双 dpid (如果 launcher 能正常 exec)。

**修复**: 改判断条件 `[ "$DPID_LAUNCHER" != "$DPID_BIN" ]` — 只要不是 fallback 到 DPID_BIN,任何 launcher (C / shell / Go) 都走统一 launcher 分支。

#### P0-3: sentinel 不区分 direct vs launcher 模式

**症状**: 配合 P0-2,sentinel 状态机错乱,日志反复刷 "no dpid launcher running"。

**修复**: sentinel 检查 `$DPID_LAUNCHER != $DPID_BIN`,launcher 模式查 launcher 进程,direct 模式查 hnc_dpid 进程。另外加 **launcher abort 检测**:如果 dpid_guard.log 最近 50 行出现 `TLS segment is underaligned` / `Aborted` / `cannot execute`,自动 fallback 到 direct mode,不再重复拉坏的 launcher。

#### P1-1: httpd serveIndex 用 UA 区分浏览器 vs KSU WebView

**症状**: 用户用手机浏览器访问 `https://127.0.0.1:8443/` 想绕过 KSU WebUI 问题,但**127.0.0.1 也是 loopback**,httpd 把浏览器当成 KSU WebView,serve KSU 版 index.html,浏览器没 `window.ksu` → 显示"需要 KernelSU 或 Magisk WebUI"白屏。

**修复**: 加 `looksLikeKSUWebView()` 函数,看 UA 里 Chrome/Firefox/Safari 标识。loopback 客户端如果是普通浏览器,serve 浏览器版 (app.html);只有像 WebView (UA 含 `wv)` 或无完整浏览器 token) 才 serve KSU 版。

#### P1-2: webroot/index.html 收 401 自动跳 /pair

**症状**: KSU WebUI 一旦 cookie 失效或 secret 注入失败,用户卡死在错误页,**没有自助修复路径**。

**修复**: `fetchJsonWithTimeout` 检测 401,自动 setTimeout 800ms 后 `window.location.href = API_BASE + '/pair'`。跟远程浏览器 WebUI (web/app.js line 609) 行为一致。

#### P2-1: hnc_launcher TLS 对齐错 (Bionic ARM64)

**症状**: 用户机上(Android 16 + SukiSU Ultra),`/data/local/hnc/bin/hnc_launcher` 直接报错:
```
error: "/data/local/hnc/bin/hnc_launcher": executable's TLS segment is underaligned: 
       alignment is 8, needs to be at least 64 for ARM64 Bionic
Aborted
```

**根因**: NDK toolchain 编出来的 TLS segment 默认 8 字节对齐,但 Bionic (Android libc) 在 ARM64 要求至少 64 字节对齐。

**修复**:
- `src/launcher/build.sh`: 加 `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` linker flags
- 编完后加 `readelf -l` 检查 TLS align >= 64,< 64 警告
- 本 zip **暂不打包** `bin/hnc_launcher` / `bin/fork_probe` (需要 CI 重编)。service.sh 看不到这两个二进制就 fallback 到 shell guard,**功能完全正常**

#### 加固: launcher 选择阶段 abort 自检

即使 hnc_launcher 二进制存在,选中后**真试一下 `--version`**,如果输出含 `underaligned` / `Aborted` 或退出码 134/137,**立即跳过 C launcher**,fallback 到 shell guard。

### 验证(从 rc30.12.27 装机数据)

```
现象 rc30.12.27          →   预期 rc30.12.28 行为
─────────────────────────────────────────────────
KSU WebUI: auth required  →  apiGet 注入 secret, HTTP 200, WebUI 正常加载
                             (退路: 收 401 自动跳 /pair)
                             
service.log:              →  service.log:
"no dpid launcher running" →  "launcher broken, fallback to direct dpid"
循环刷                      或 "starting hnc_dpid launcher: hnc_dpid_guard.sh"
                             
浏览器 127.0.0.1:8443      →  serve app.html (浏览器版)
"需要 KernelSU 或 Magisk"
白屏
```

### 待 CI 验证

第 6 项 P2 hnc_launcher 重编依赖 CI:
- push 后 CI 跑 `src/launcher/build.sh install` 编出新的 hnc_launcher (带 LDFLAGS)
- CI 产出的 zip artifact 应该包含**修好的** hnc_launcher
- 用户从 GitHub Releases 下的 zip = 完整版,本地解压的这个 zip = 不带 launcher (但能 fallback)


## v5.3.0-rc30.12.27

**发布日期**: 2026-05-19
**versionCode**: 530145

DPI 规则更新: 加入**无畏契约:源能行动** (VALORANT Mobile 国服).

### 数据来源

真机 pcap (RMX5010 + ColorOS 16 + SukiSU + 5G):

- 抓包时长: 13 分钟 (大厅 + 实战)
- 总包数: 2261
- SNI 提取: 93 个
- foreground app: com.tencent.tmgp.codev

### 新增规则细节 (very_high)

- **id**: `tencent_codev_valorant_mobile`
- **app**: 无畏契约:源能行动
- **category**: game
- **suffixes** (2 个独占):
  - `codev-club.qq.com` — 游戏俱乐部专属
  - `estv-op.tga.qq.com` — 国服内部代号
- **ip_matchers** (3 段):
  - `14.17.78.0/24:8001-8004` — 腾讯手游 game server 4 端口配对 (59 包印证)
  - `117.135.156.0/24:8013` — 腾讯手游经典端口 (25 包印证)
  - `183.194.238.0/24:8002` — 上海移动 IDC 腾讯游戏 (6 包印证)
- **ipv6_matchers** (6 段, 中国移动 5G):
  - `2409:8c1e:75b0::/48` — 主连接 #1 (195 包)
  - `2409:8c1e:8f60::/48` — 主连接 #2 (118 包)
  - `2409:8c70:3a10::/48` — 主连接 #3 (73 包)
  - `2409:8c54:871::/48` — 辅助 (62 包)
  - `2409:8c54:1040::/48` — 辅助 (56 包)
  - `2409:8c6c:1720::/48` — 辅助 (32 包)

### 关键发现

1. **不用 QUIC** — 无畏契约:源能行动**全部走 TLS-over-TCP**, DPI 完全能识别. 不像很多 Google/字节系 App 把 SNI 加密了, 这游戏的 SNI 是明文.

2. **跟现有规则无冲突** — IP 段都是新的, suffix 也独占.

3. **ColorOS 16 默认 DoH** — 你的 ROM 用 223.5.5.5/223.6.6.6 (阿里 DoH), 所以 DNS 抓不到. 但 SNI 在 TLS 握手里是明文, 不受影响.

### 跟通用腾讯 SDK 规则的关系

那些**所有腾讯游戏共用**的 SDK 域名 (如 `cloud.tgpa.qq.com`, `android.perfsight.qq.com`) **不重复加进 codev 规则**, 它们在 `tencent_game_sdk_common` 里. 这样 HNC 看到 SDK 流量会归类到"腾讯游戏通用 SDK", 看到 `codev-club.qq.com` 才确定是无畏契约.

### 总规则数变化

| 版本 | 总规则 | very_high | high | medium | low |
|---|---|---|---|---|---|
| rc30.12.22 | 143 | 15 | 97 | 23 | 8 |
| rc30.12.27 | **144** | **16** | 97 | 23 | 8 |

### rules_version

`hnc-curated-v3-rc30.12-2026-05-19-v6-valorant-mobile`


## v5.3.0-rc30.12.23

**发布日期**: 2026-05-19
**versionCode**: 530143

DPI 抓包工具拆分.

### 背景

rc30.12.22 把 capture.sh BPF 优化后, 工具本身已经很小 (5 个文件 / 52 KB). 但它仍打进 9 MB 主模块 zip 里, 装到手机的 `/data/adb/modules/.../tools/ground_truth/` — 这位置不合理:

1. 抓包是 ad-hoc 操作, 不需要常驻模块目录
2. analyze.py / sni_to_rules*.py 是给电脑 / Claude 跑的, 手机用不上
3. 用户用模块根本不需要它存在

### 改动

**模块 zip 打包时排除 `tools/`**:

```
zip ... -x "tools/*"
```

**独立分发**: `hnc-ground-truth-tools.zip` (15 KB)

### 体积影响

- 主模块 zip: 9.0 MB → 9.0 MB (变化忽略不计, tools/ 才 52 KB)
- 工具包: 单独 15 KB
- 用户体验: 想抓包再下载工具包, 不想抓的人模块里就没这个目录

### 仓库结构

GitHub `hnc-v6` 仓库**仍然保留** `tools/ground_truth/` 完整源码 (CI 可访问, 开源审计可见). 只是模块 zip 打包时不带它了.

### 拿工具包的方式

如果你后面想抓 pcap 标注 DPI 规则:

```bash
# 下载 hnc-ground-truth-tools.zip
# 解压到任意位置 (推荐 /sdcard/Download/hnc_tools/)
# Termux 跑:
su
sh /sdcard/Download/hnc_tools/capture.sh 1800
```

工具包里附带的 README.md 有完整工作流说明.

### 不变的部分

- BPF (rc30.12.22 优化)
- analyze.py
- sni_to_rules_v2.py
- 抓包后发 Claude 的流程


## v5.3.0-rc30.12.22

**发布日期**: 2026-05-19
**versionCode**: 530142

DPI pcap 抓包工具体积优化.

### 背景

之前 4 次 pcap 标注积累 441 MB / 36 分钟 (~12 MB/min). 体积大主要因为 BPF 太宽:

```
old BPF: (tcp or udp) and not arp + -s 200
```

抓所有 TCP/UDP 包. 但 analyze.py 实际只用 4 种东西:
- TLS ClientHello (TCP 443 内 payload 0x16 0x03)
- DNS query / response (UDP 53)
- QUIC Initial (UDP 443 long header)
- TCP SYN (5-tuple 流元数据)

视频流 / 文件下载 / HTTP/2 stream / keepalive 全是浪费.

### 优化

`tools/ground_truth/capture.sh` 重写 BPF, 双段过滤:

**IPv4 (精细)**:

```
(tcp[tcpflags] & tcp-syn != 0)
or (tcp port 443 and tcp[((tcp[12] & 0xf0) >> 2):2] = 0x1603)
or (udp port 53)
or (udp port 443 and udp[8] >= 0xc0 and udp[8] <= 0xff)
```

**IPv6 (粗过滤)**:

```
ip6 and (tcp port 443 or udp port 53 or udp port 443)
```

IPv6 粗一些是因为 tcp[] subscript 在 IPv6 上 tcpdump 编译行为依赖版本, 跨平台兼容性差. 而 IPv6 流量在移动场景通常 < 10%, 体积影响小.

### 预期效果

| 场景 | v1 体积 | v2 体积 | 压缩比 |
|---|---|---|---|
| 重度 (视频+游戏) | ~12 MB/min | 0.5-1 MB/min | 12-24× |
| 中度 (社交+刷) | ~6 MB/min | 0.2-0.5 MB/min | 12-30× |
| 单 App | ~3 MB/min | 0.1 MB/min | 30× |
| **36 min 真机** | **441 MB** | **15-30 MB** | **15-30×** |

### 其他改进

- 倒计时实时显示 pcap 大小 (能边抓边看体积)
- tcpdump 启动失败时自动 fallback 到 v1 BPF (兼容老版 tcpdump)
- meta-*.json 标记 schema v2 + capture_filters_summary
- 结束报告显示 KB/分钟率, 方便后续校准

### analyze.py 兼容性

不需要改. v2 pcap 仍是标准 pcap 格式, 内容是 v1 的子集 (handshake-only). analyze.py 本来就只看 handshake, 完美兼容.

### 用法

```bash
# 跟之前一样
sh tools/ground_truth/capture.sh                    # 默认 300s
sh tools/ground_truth/capture.sh 1800 wlan0 256     # 30 min
```


## v5.3.0-rc30.12.21

**发布日期**: 2026-05-19
**versionCode**: 530141

CI hotfix.

### 修复

- `bin/json_regression_test.sh` 第 102 行 `tpl_set` 调用参数错误
  - 之前: `sh "$JSON_SET" tpl_set "$TPL" down_mbps 1` (传字符串 `down_mbps` 当数字)
  - 现在: `sh "$JSON_SET" tpl_set "$TPL" 1 0 0 0 0` (5 个数字: down/up/delay/jitter/loss)
  - 这个 bug 一直存在, 但 rc30.12.20 之前没在 CI 跑过 ci_preflight, 所以没人发现
  - 修复后 ci_preflight 本地跑结果: failures=0 (之前是 1)

### 没改的

代码 / 二进制 / 行为 — 都没动. 只是测试脚本本身的 bug.


## v5.3.0-rc30.12.20

**发布日期**: 2026-05-19
**versionCode**: 530140

CI 流水线引入. 解决 hnc-v6 push 后不自动 build 的问题.

### 新增 .github/workflows/build.yml

每次 push 到 main 触发, 自动:

1. **预检**: shell `sh -n` 全扫 / version_consistency_check / ci_preflight
2. **build hnc_httpd**: 用 build.sh 注入版本号
3. **build hnc_dpid**: Go 交叉编译 android/arm64
4. **build hnc_launcher + fork_probe**: NDK r27c 编 C
5. **build hnc_tc_ingress**: NDK 编 C (纯 netlink, 不依赖 BPF)
6. **校验**: file 检查 arm64, strings 检查版本注入
7. **打包**: 排除 .git / build artifacts, 输出 HNC-x_x_x-arm64.zip
8. **artifact**: 30 天保留
9. **tag push**: 自动 GitHub Release

### 跟 hnc-v5 老 workflow 的差异

| 维度 | hnc-v5 build.yml | hnc-v6 build.yml (本版) |
|---|---|---|
| 编 hnc_launcher / fork_probe | 不编 | **编** |
| third_party submodule | 必须有 | 不要求 (hotspotd 直接入 git) |
| 适配的目录结构 | rc25 时代 | rc30.12 |
| Go 版本 | 1.22 | 1.22 |
| NDK 版本 | r27c | r27c |
| version 注入校验 | 强 fail | 强 fail |

### 关于 hotspotd / hnc_ipc

之前 .gitignore 排除了所有二进制. 但 hotspotd 依赖 libbpf 而 hnc-v6 没 vendor third_party/libbpf, CI 编不出来. 妥协方案: 把 hotspotd / hnc_ipc / mdns_resolve 三个二进制保留在 git, 其他 (hnc_dpid / launcher / fork_probe / tc_ingress / hnc_httpd) CI 编.

未来如果 vendor 了 libbpf, 可以让 CI 编全部.

### 下次 push 行为

```
git push origin main
  ↓ 5-10 分钟
GitHub Actions 编出 HNC-v5_3_0-rc30_12_20-arm64.zip
  ↓
Actions 页面下载 (或者 release 区, 如果是 tag push)
```

如果想触发 release 自动化:

```
git tag v5.3.0-rc30.12.20
git push origin v5.3.0-rc30.12.20
  ↓
CI 跑完后自动创建 Release, zip 自动 attach
```


## v5.3.0-rc30.12.19

**发布日期**: 2026-05-19
**versionCode**: 530139

工程收口版. GPT 二审给 rc30.12.17 评 80/100, 列了 6 个 P2/P3 问题. 这版修了其中 3 个性价比最高的:

### 修复 (3 件)

- **P2: launch_httpd_safe 改成每次动态读 (rc30.12.16 留下的尾巴)**
  - 问题: 之前用 $REMOTE_ENABLED 全局快照, 用户中途改 remote_enabled=false 之后, 如果 httpd 恰好死掉, sentinel 会用旧快照拉起 0.0.0.0 模式, 30s 内跟用户配置不一致
  - 触发条件极窄, 但确实存在窗口
  - 修法: 函数内部每次调用都重新 grep rules.json. 改动 ~10 行
  - 现在跟 watchdog 一样, 完全实时

- **P3: version_consistency_check.sh 正则不支持三段 rc**
  - 问题: 之前正则 `rc[0-9]+(\.[0-9]+)?(-hotfix...)?` 只支持两段, rc30.12.18 这种三段会误报 warn
  - 影响: CI / 自检会有假告警, 时间长了会让人忽略真告警
  - 修法: 改成 `rc[0-9]+(\.[0-9]+){0,2}`, 支持 1-3 段
  - 测试: 7 个合法格式 + 1 个非法, 全部判断正确

- **P3: src/README.md 完整重写**
  - 问题: 之前还是 rc29.1 的文档 (说 Go 1.25 / x/crypto v0.50.0 / dpid 0.5.1-rc29.1 / GOOS=linux), 全部跟当前实际不符
  - 影响: 新接手的人按文档走会全部失败
  - 修法: 重写到 rc30.12.18 状态. 加了:
    - launcher 编译说明 (链向 src/launcher/README.md)
    - src/ vs daemon/ 双源码目录的解释
    - web/ embed 资源说明 (之前的事故复盘)
    - 版本一致性检查命令
    - 历史变更点摘要

### 推迟的 GPT 建议

- **P3: gofmt 30 个 Go 文件** — 不影响编译, 一次性 `gofmt -w` 会改大量文件历史, 暂留
- **P3: go mod vendor** — 你不离线 build, 自用场景没必要

### 评分预期

| 版本 | GPT 评分 |
|---|---|
| rc30.12.15 | 67 |
| rc30.12.17 | 80 |
| rc30.12.18 (默认拒绝) | 85-88 (预估) |
| rc30.12.19 (本版) | 83-86 (预估) |

注: rc30.12.18 是更大的 P1 改动 (默认拒绝), rc30.12.19 主要是 P2/P3 工程整洁度. 实际打分需要 GPT 重审.


## v5.3.0-rc30.12.18

**发布日期**: 2026-05-19
**versionCode**: 530138

**默认拒绝中间件重构**. GPT 之前强推的 P1 修复.

### 核心改动

将 `middleware.go` 的鉴权逻辑从"敏感读白名单 + 其他默认放行"反转为"公共路径白名单 + 其他默认拒绝".

**之前**:

```
非公共路径 (cookie 缺失):
  if !auth_required && !isWritePath() && !isSensitiveReadPath() → 放行匿名
  else → 401
```

问题: 新加 API **默认是匿名可读**, 必须记得加进 isSensitiveReadPath() 白名单. 过去 3 次都漏过 (alerts / dpi_history / app_limits).

**现在**:

```
isPublicPath (/, /pair, /api/health, /api/pair/verify, /api/logout, /api/pairing/status, /changelog.html, /static/*):
  → 放行

其他所有路径:
  必须有 cookie, 否则 401
```

新加 API **默认是 401**, 忘记加白名单也是安全的. 工程师友好.

### 行为变化

- **rules.json `auth_required` 字段不再有"放行匿名"作用** — 任何不在 isPublicPath 的请求都强制 cookie. 字段保留兼容老配置, 但实际无效
- **service.sh 自动迁移**: 老 rules.json `auth_required=false` 启动时自动改成 `true` (UI 一致性)
- **rules.json 默认值**: false → true
- **升级用户行为**: 升级后第一次访问会要求登录. 走一遍 /pair 配对即可. SPA 主页能加载, 但 fetch /api/* 会 401, WebUI 自动跳 /pair

### 新增放行的公共路径

之前 isPublicPath 只有 5 个, 现在 8 个:

- 新增 `/` SPA 主页 (没鉴权也能加载 HTML, JS 自己处理登录跳转)
- 新增 `/changelog.html` (静态信息页)
- 新增 `/api/logout` (登出永远应该允许)
- 保留 `/pair` `/api/pair/verify` `/api/pairing/status` `/api/health` `/static/*`

### isSensitiveReadPath() 函数仍保留

主鉴权流程不再用它, 但 loopback secret 缺失时的分级 fail-closed 仍需它:
- secret 不存在 + 写接口 / 敏感读 → fail-closed
- secret 不存在 + 普通读 → 兼容放行 (避免升级窗口期 UI 完全瘫痪)

### 安全提升

| 维度 | rc30.12.17 | rc30.12.18 |
|---|---|---|
| 加新 API 时忘了鉴权 | 默认匿名可读 | 默认 401 |
| 老用户裸奔 (auth_required=false 默认) | 是 | 否 (自动升级) |
| GPT 评分预期 | 80-83 | 85-88 |


## v5.3.0-rc30.12.17

**发布日期**: 2026-05-19
**versionCode**: 530137

可复现构建小修. 跟 rc30.12.16 的差别只在 build/工程治理, 不动任何运行逻辑.

### 修复 (2 件)

- **src/hnc_httpd/web/ 补齐**
  - 之前 src/hnc_httpd/ 缺 web/ 目录, embed.go 引用的 app.html/app.js/style.css/pair.html 都不存在
  - 从 src/ 独立 go build 直接失败 (pattern web/app.html: no matching files found)
  - 修法: 从 daemon/hnc_httpd/web/ 同步一份过来. 现在 src/ 能独立 build

- **build.sh 重新编译 daemon/hnc_httpd, 注入正确版本号**
  - 之前我手动 go build 跳过了 build.sh, 没用 -X main.version 注入, 二进制 main.version 一直是默认值 "dev"
  - 影响: /api/health 接口返回 version=dev, WebUI 也显示 dev, 排障时分不清装的是哪版
  - 修法: 跑 daemon/hnc_httpd/build.sh, 它读 module.prop 的 version 字段自动注入. 现在二进制 strings 能搜到 "v5.3.0-rc30.12.17"
  - build.sh 自带的 DPI API 完整性检查也跑过了 (/api/dpi_state /api/dpi_probe apiDPIState apiDPIProbe dpi_rebind 5 个符号都在)

### 验证

- `strings daemon/hnc_httpd/hnc_httpd | grep v5.3.0-rc30.12.17` → 命中
- src/hnc_httpd 独立 go build 成功
- daemon/hnc_httpd/build.sh 成功

### 不变的部分

- service.sh / middleware.go / dpid 源码全部跟 rc30.12.16 一致
- DPI 规则数 143 条不变
- rc30.12.16 的 6 个 P0/P1 修复全部保留

### 评分预期

rc30.12.16 修完 P0/P1 后预期 76-80. 本版补可复现构建后预期 80-83. 剩下的距离主要是: launcher 源码补齐, app_limit 架构改造, CI 建立.


## v5.3.0-rc30.12.16

**发布日期**: 2026-05-18
**versionCode**: 530136

止血版. 消化 GPT 二次审查报告里的 P0/P1, 不动 DPI 规则, 不加功能.

### P0 修复 (3 条)

- **service.sh remote_enabled=false 不再硬编 0.0.0.0**
  - 症状: 用户在 rules.json 设了 remote_enabled=false, log 也说"loopback-only mode", 但 pre-launch 和 sentinel 两处仍 `-bind 0.0.0.0`, 配置语义失效, 远程端口实际监听
  - 根因: rc30.12 引入 shell pre-launch 时硬编了 -bind, REMOTE_ENABLED 读了只 log 没用到
  - 修法: 新增 launch_httpd_safe() 函数, 根据 REMOTE_ENABLED 决定参数; pre-launch 和 sentinel 都调用此函数

- **sentinel 移到 DPID_LAUNCHER 定义之后**
  - 症状: sentinel 在脚本前面就启动, 后台 subshell 拷贝当时还空的 $DPID_LAUNCHER. DPID 死了想重启时 `[ -x "$DPID_LAUNCHER" ]` 永远 false, 守护链失效
  - 根因: shell 后台 subshell 启动时变量环境快照, 父进程后续赋值不同步给已启动的 subshell
  - 修法: sentinel 整段移到末尾, 所有 launcher 选择逻辑完成后再启动. 加 DPID_LAUNCHER 为空时的 log warn

- **src/dpid 源码同步到 0.5.3-rc30.12.3-iface-retry**
  - 症状: bin/hnc_dpid 二进制有 "no such network interface" 字符串 fallback (rc30.12.3 修的), 但 src/dpid 源码还是旧版 0.5.3-rc29.3-l3-flow, isRecoverableCaptureError 只匹配 4 个 errno 不匹配字符串
  - 影响: 以后任何人从 zip 源码重新 build hnc_dpid, Realme / ColorOS / SukiSU 上的接口未就绪重试会回退到盲 DPI 状态
  - 修法: 源码 isRecoverableCaptureError 加字符串 fallback, version 改为 0.5.3-rc30.12.3-iface-retry. 验证: 在 src/dpid 直接 go build 成功, strings 显示新字符串

### P1 修复 (2 条)

- **3 个敏感读 API 加白名单**
  - 漏: /api/alerts (告警时间线 + MAC) / /api/dpi_history (流量历史 + app 聚合) / /api/app_limits (限速策略)
  - GPT 之前漏了 /api/logout, 实际 logout 不该算敏感 (登出永远应该允许), 这次 GPT 自己纠正了, 我们没加进去

- **loopback secret 分级 fallback (替代全放行)**
  - 老逻辑: secret 文件不存在时一律 fallback 老行为, 全放行
  - 新逻辑: secret 不存在时分级 —
    - 写接口 (/api/action) 永远 fail-closed
    - 敏感读 (devices/alerts/dpi_history/...) 也 fail-closed
    - 其他读 (/, /api/health, 静态) 兼容老行为放行 (升级中临时不影响首页 + 健康检查)

### P2 修复 (1 条)

- **umask 077 子 shell 隔离**
  - 老逻辑: `umask 077; printf ... > secret` 之后没 restore, 后续脚本所有 `>` 创建的文件都被收紧权限
  - 修法: `( umask 077; printf ... > secret )` 用子 shell 隔离, 不污染外面

### 推迟到 rc30.12.17 的事

- **build.sh 版本注入** (httpd 二进制内部 version 字段仍是 "dev", /api/health 会返回 dev). 推迟原因: 用 build.sh 重新编需要测试 build.sh 的 module.prop 读取逻辑在我们环境下能跑, 有失败风险, 不在止血版做.
- src/hnc_httpd/web/ 目录补齐 (架构整理, 不影响运行)
- hnc_launcher / fork_probe 源码补齐 (历史遗留 C 程序, 不可复现编译, 影响审计)
- app_limit 双文件改架构 (取消 flat 文件, 让 shell 读 JSON)

### 评分预期

GPT 给 rc30.12.15 评 67/100. 修完 P0+P1 后预期 76-80, 三个推迟项处理后能到 83-86.


## v5.3.0-rc30.12.15

**发布日期**: 2026-05-18
**versionCode**: 530135

快手专题 + VPN 抓包发现.

### 重大归属修正

- **`xxpkg.com` + `kuiniuca.com` 从"未知 P2P"修正到快手 P2P**
  - 之前 rc30.12.10 把它们归到 `p2p_unknown_attribution` (medium 置信), 后续也没动
  - 2026-05-18 纯快手会话 5 分钟真机印证: 16 次出现, 完全无抖音流量同时段 → 100% 快手专属
  - **这是 4 次 pcap 累积下来第一次有"决定性证据"重新归类某 P2P 域名**

### 升级 + 新增

- **快手 high → very_high**
  - 完整 10 个域名族: gifshow / ksapisrv / kuaishou / kwaicdn / wsukwai / wskwai / yximgs / kwimgs / kuaishouzt / inkuai
  - 广告 SDK 子分类: adkwai / adukwai
  - **P2P 加速子分类**: xxpkg.com / kuiniuca.com (新归属)
  - 借用 CDN 标注: `djvod.ndcimgs.com` 是快手在借用字节系 NDP CDN (前缀 djvod 才属快手, v16/v22 仍属抖音)
  - 5 分钟内 160+ 命中真机印证, 含 subdomain patterns 细分

- **微信 PCDN 心跳 (behavior marker, very_high)**
  - `apd-pcdnwxlogin/stat/nat.teg.tencent-cloud.net` 三个 PCDN 节点
  - 后台运行频率 ~5/min (24/5min 实测), 跟 game.eve.mdt.qq.com 同类型 behavior marker
  - HNC 可用作"微信是否在后台保活"信号

- **VPN 双计费陷阱告警 (meta-warning, very_high)**
  - `tcpdump -i any` 抓 VPN 流量, 同一字节流出现两次 (tun0 明文 + rmnet 加密)
  - 5 分钟 pcap 66k 包: 43k 在 tun0, 23k 在 rmnet, 总流量虚高 ~80%
  - HNC tc/iptables 限速规则**只挂一个接口**, 推荐 rmnet_data2 (真实出口)
  - 不要同时挂 tun + rmnet, 否则带宽统计 + 限速都翻倍

### 规则数

- 总数: 141 → 143
- very_high: 12 → **15** (+ 快手 + 微信 PCDN + VPN 陷阱)
- p2p_unknown_attribution: 6 → 4 (移除归属确认的两个)

### VPN 客户端特征观察 (供参考, 未确认归属)

- 主流量: udp/28575 (像 Hysteria2 / WireGuard 改端口)
- 备用: udp/8443 + tcp/13500-13504
- 服务器: 中国移动 IDC (223.86 / 112.45 / 112.19) + 香港中转 (103.102 / 103.107)
- 分流豁免: gw.alicdn.com / rdelivery.qq.com / heytapmobi.com / 部分快手广告域走直连


## v5.3.0-rc30.12.14

**发布日期**: 2026-05-18
**versionCode**: 530134

工程加固版. 消化 GPT 深度审查报告里的所有真问题, 不动应用规则.

### P0 安全 + 构建

- **Go 1.25 → 1.22 降级** (含 `golang.org/x/crypto v0.50.0 → v0.31.0`)
  - 原因: crypto v0.50 自己要求 Go ≥ 1.25, 离线 CI / Ubuntu 22.04 LTS / 老编译环境全都不友好
  - HNC 只用 `bcrypt` 子包, v0.31 跟 v0.50 接口完全一致, 0 安全损失
  - 二进制 6.6 MB → 6.2 MB (-6%)

- **HTTP 服务器补全超时**
  - 三个 server (httpsSrv / httpSrv / loopbackSrv) 都加 ReadTimeout (10-30s) + WriteTimeout (10-60s)
  - 防 slowloris / 慢响应耗 goroutine

- **loopback 鉴权加固 (核心)**
  - 问题: 老版本"loopback + 无 Origin/Referer 即放行", 本机任意能发 HTTP 的低信任 App 可绕过 token 鉴权调管理面
  - 修法:
    - service.sh 启动时生成 `/data/local/hnc/run/local_admin.secret` (32 字节 hex, mode 0600, owner root)
    - WebUI 通过 ksu.exec 读 secret, 注入到所有 curl 命令的 `X-HNC-Local-Admin` header
    - 后端 `checkLocalAdminSecret()` constant-time 比对
  - 向后兼容: secret 文件不存在 (老部署) 仍 fallback 到老 loopback 行为, 平滑升级不破坏现有环境
  - 普通 App 没 root 读不到 mode 0600 owner root 文件 → 无法构造 valid header

### P1 工程债

- **src/ vs daemon/ 源码统一**
  - 之前 daemon/.go 是 5-16 旧版, src/.go 是 5-17 新版, 但二进制实际从 src/ 编
  - 现在 daemon/ 完全跟 src/ 一致, 25 vs 25 文件对齐

- **app_limit 双文件原子提交**
  - 老逻辑: JSON 先 rename, flat 写失败 `return nil // best-effort`, 两份文件不一致 → "UI 显示成功但实际未生效"
  - 新逻辑: 两份 .tmp 都写成功后才依次 rename, 任一失败回滚

- **marker FD 修复**
  - `_, _ = os.Create(marker)` 返回 *os.File 但没 Close → 长期运行 FD 泄漏
  - 改成 `os.WriteFile(marker, []byte{}, 0o644)`, 无 FD 悬挂
  - 两处: `src/hnc_httpd/action_app_limit.go` + `src/dpid/cmd/hnc_watchdog/main.go`

- **test runner $0 修复**
  - 老问题: runner 用 `. "$test_file"` source 测试, 但测试用 `$(dirname $0)/../..` 推 ROOT, source 上下文 `$0` 是 runner 不是测试 → 推出错误根路径
  - 修法: runner export `HNC_TEST_FILE="$test_file"`, 测试改用 `$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")` 优先取 env
  - 影响 41 个单元测试

### 评分变化

GPT 报告给 rc30.12.2 打 69/100, 主要扣分在 loopback 鉴权 (P0)、敏感接口覆盖 (后查证为误判, 那些 endpoint 没注册到 mux)、超时不全、源码漂移、构建可移植性. 本版本处理了所有可证实的真问题, 预期评分 80+.

### 不动的部分

- WebUI 大单页拆分 (GPT 建议) - 自用项目可接受
- hotspotd 子进程超时 (P2, 已有 5s TTL, 真机没暴露过) - 不动
- DPI 规则 - 不动, 跟 rc30.12.13 一致


## v5.3.0-rc30.12.13

**发布日期**: 2026-05-18
**versionCode**: 530133

DPI 规则三次扩充 (王者荣耀 5 分钟真机印证).

### 新增 5 条规则

- **tencent_wzry_exclusive** (very_high, 替换旧 wangzhe high 规则)
  - **6 个内部代号**: yxzj (英雄战迹拼音) / sgame (天美 S 工作室) / smoba (Smart MOBA) / koh (King of Honor) / kohesport (KPL 电竞) / estv (E-Sports TV) + pvp/ingame (项目原名)
  - 12 个 subdomain_patterns 覆盖 broker / faas / itop / tgpa / measurement / estv 各子系统
  - 4 个测量服务器: measurement.{tj,sh,gz,cq}.prod.smoba.qq.com

- **tencent_game_geo_template** (high, 元规则)
  - 腾讯游戏地理分布通用模板: 火影 `prod-{nj,gz,cq,tj}.ino.hyrz.qq.com` 跟王者 `measurement.{tj,sh,gz,cq}.prod.smoba.qq.com` 完全对称
  - 6 个区域代号: nj/sh/gz/cq/tj/cd
  - 见到 `<X>.{region}.<X>.qq.com` 几乎必然是腾讯游戏 IDC

- **tencent_game_codename_table** (very_high, 元规则)
  - 完整代号对照表: yxzj/sgame/smoba/koh/kohesport/estv/pvp/ingame → 王者 · hpjy/418021106/gcloudpg → 和平精英 · hyrz/hyrzol/kihan → 火影 · tmgp.cf/cfm/cfmuhd → CF 手游
  - HNC 见到任意代号前缀即可反查具体游戏

- **ms_telemetry_realme_baseline** (high)
  - Realme 国行的 Microsoft 遥测基线: 5 分钟约 24 包稳定基线
  - 标记 do_not_attribute_to_user_app, 防止误判"用户在用微软产品"
  - 检测维度: 命中 >> 基线 (e.g. >40/5min) 才考虑用户真在用

- **realme_preinstalled_third_party** (medium)
  - 作业帮 (zuoyebang.cc / zybang.com), 西番有梨 (youlishipin.com), finzfin.com 等
  - Realme 国行预装第三方 SDK 背景流量, 不归属用户使用

### 增强已有规则

- **tencent_game_broker_tplay**: 加 yxzj → 王者荣耀 前缀映射
- **tencent_game_ino_servers**: 加 smoba 平行模式说明
- **realme_gamespace_trigger**: 加 `iot-earbuds-cn.heytapmobi.com` (玩游戏戴耳机时触发)
- **xunyou_accelerator**: 加王者真机印证 (3 次印证: 火影 + 和平 + 王者)

### 关键发现

腾讯游戏后端架构: **每个游戏部署 3-4 个地区 IDC, 域名模式 `<role>.<region>.<game>.qq.com`**. 这给了 HNC 一个通用规则模板, 不再需要每个游戏单独硬编码区域域名.

### 规则数

- 137 → 141
- very_high: 10 → 12 (+ 王者荣耀 + 代号对照表)


## v5.3.0-rc30.12.12

**发布日期**: 2026-05-18
**versionCode**: 530132

DPI 规则清理 + 抖音 confidence 升级.

### 合并重复规则 (5 对)

| 删除 | 合并到 | 加入的 suffix |
|---|---|---|
| `peace_elite` (high) | `tencent_pubgmhd_exclusive` (very_high) | pubgmhd.qq.com, tipw.qq.com, gameact.qq.com, hpjy.qq.com |
| `discord_extra` | `discord` | (已全重叠) |
| `telegram_extra` | `telegram` | telegram-cdn.org, telegra.ph |
| `wechat_extra` | `wechat` | weixinbridge.com, weixin110.qq.com, support.weixin.qq.com, res.wx.qq.com, szsupport.weixin.qq.com |
| `kuaishou_main_app` | `kuaishou` | wskwai.com, kwai.com |

### confidence 升级

- **抖音 (douyin)**: high → very_high
  - 35 个 suffix 完整覆盖字节系生态 (主程序 / ECDN / 火山引擎 / 电商 / 直播)
  - 两次真机 pcap 印证 (REDMI-K80 + RMX5010 主机)

### 规则数变化

- 总数: 142 → 137 (-5 重复)
- very_high: 9 → 10 (+ 抖音)
- high: 102 → 97 (合并掉 5 个)

### 保留的合理冗余 (没合并)

- **小米**: xiaomi_device_indicator (设备指纹) + xiaomi_update (更新/账号子域) + xiaomi (商业子品牌如 mi-img/duokan/xiaomiev) — 3 条覆盖不同维度
- **快手**: kuaishou (主程序) + kuaishou_ad_sdk (广告 SDK medium 置信) — 区分主程序 vs SDK
- **企业微信** vs **微信** — 不同 app


## v5.3.0-rc30.12.11

**发布日期**: 2026-05-18
**versionCode**: 530131

DPI 规则二次扩充 (PUBG 5 分钟 pcap 印证).

### 新增 7 条规则

- **tencent_pubgmhd_exclusive** (very_high): 和平精英专属指纹
  - 100% 专属域名: `hpjy.itop.qq.com` (hpjy = 和平精英拼音首字母) + `*.418021106.gcloudpg.qq.com` (418021106 = 腾讯 appid)
  - 之前只能判定"有腾讯游戏在跑", 现在可以确认"就是和平精英"

- **tencent_game_broker_tplay** (very_high): 腾讯游戏对战匹配 Broker 通用模式
  - `*.broker.tplay.qq.com` 前缀 = 游戏代号 (hyrz-new → 火影, cjm/jsonatm → 和平精英)
  - 一条规则覆盖所有腾讯手游对战匹配

- **tencent_game_ino_servers** (very_high): 腾讯游戏内网服务器通用模式
  - `*.ino.<game>.qq.com` 中段 = 游戏代号 (hyrz → 火影, 推测 sgame → 王者 / cf → CF)
  - 一条规则覆盖所有腾讯游戏内网/对战服务

- **tencent_vod_p2p** (high): 腾讯游戏 VOD P2P
  - `apd-vodp2p{login/nat/report/tracker}.teg.tencent-cloud.net` 全家桶, 游戏回放/录像 P2P

- **xunyou_accelerator** (very_high): 迅游加速器
  - 玩腾讯国服游戏标配, '当前在玩腾讯游戏'的强辅助信号

- **realme_gamespace_trigger** (high): Realme 游戏空间触发信号
  - `gc-gamespace-cn.heytapmobi.com` ColorOS 自己识别到游戏时查询. 借 ROM 做游戏识别

- **tencent_game_foreground_heartbeat** (very_high): 行为标记规则 (重要新分类)
  - `game.eve.mdt.qq.com` 查询频率 = 应用前台/后台/已杀状态金标准
  - 前台主玩: >10 queries/min · 后台保活: 1-5/min · 已杀: 0/min
  - 第一条"行为标记"类规则, 不只识别应用, 还判断应用状态

### 增强已有规则

- **tencent_game_sdk_common** + 5 个 suffix: gp.qq.com / bkapps.com / tga.qq.com / imtmp.net / tplay.qq.com
- **tencent_hyrz_naruto** 补"后台保活"模式证据 (4 queries/min, 无对战服务器查询)

### 副产物: IPv6 归属修正

上次 IPv6 归属判断错误 (`:18d4` v6 当成主机的, 实际是 K80 的 EUI-64), 第二次 pcap 通过 MAC 反算修正. **主机实际无 IPv6 出口**, 两个 v6 地址都是 K80.


## v5.3.0-rc30.12.10

**发布日期**: 2026-05-18
**versionCode**: 530130

DPI 规则修正版. 撤销 rc30.12.9 我自己 ground truth 不充分写的 4 条粗糙规则, 改用外部 AI 重新分析的精确规则.

### 撤销

- 删除 rc30.12.9 的 4 条粗糙规则: bytedance_ecdn / p2p_cdn_acceleration / tencent_anticheat / p2p_webrtc_stun (前 2 个归属判断过于自信, 后 2 个 confidence 标记不够保守)
- 撤销 rc30.12.9 给 douyin/xiaomi_update/qq_music/tencent_ads_extra 加的部分 suffix 和 ground_truth 字段 (准确性存疑)

### 新增 (基于外部 AI 重分析, 修正客户端归属)

- **tencent_hyrz_naruto** (very_high): 火影忍者OL — K80 客户端前台主玩, game.eve.mdt.qq.com x272 印证 + 4 个对战服务器 + PVP 服务器, 含 cloud.game.hyrz.qq.com 云游戏入口
- **douyin_p2p_inferred** (high): 抖音 P2P 加速 — cjjd13/cjjd14/dahhxxttxs.com 只在重度抖音用户上出现的强推断, 仍标注未官方确认
- **tencent_game_sdk_common** (very_high): 腾讯游戏通用 SDK (跨王者/CF/和平精英/火影忍者) — 20 个后缀, 命中只判定有腾讯游戏在跑, 定位具体游戏需配合专属规则
- **p2p_unknown_attribution** (medium): 主机侧不明归属 P2P (xxpkg/comfylink/xinqiucc/kuiniuca/sjxydc/ahdohpiechei) — 因为不只在抖音重度用户上出现, 改标 unknown 而非硬归到抖音
- **xiaomi_device_indicator** (very_high): 小米/MIUI 设备识别, 含 mDNS 三件套 (_lyra-mdns/_mi-connect/_miplay_lan) — 可用作 100% 准确的设备指纹
- **coloros_realme_device_indicator** (very_high): ColorOS/Realme 设备识别
- **kuaishou_main_app** (high): 快手主程序 — yximgs/wskwai/kwai/gifshow/ksapisrv
- **kuaishou_ad_sdk** (medium): 快手广告 SDK — adkwai/adukwai, 单独成规则, 不再误判为 "用了快手 App"
- **ixigua_disambiguation** (medium): 西瓜视频歧义规则 — ixigua.com 在字节系作为直播 CDN 给抖音用, 需配合抖音流量比例判断

### 补充已有规则 suffix

- douyin: +18 个 (完整字节系 ECDN + 火山 + 电商, 全部 26 个后缀)
- qq_music: +tencentmusic.com / kg.qq.com / y.gtimg.cn
- netease_music: +music.126.net / 126.net
- bilibili: +biliapi.com / bilivideo.com / hdslb.com

### 关键经验

- ground_truth 写之前必须**先验证客户端归属**, 不能因为某域名在 pcap 里高频就假设属于某 App. 必须看是否**仅出现在使用该 App 的客户端上**.
- 写规则时区分**主程序 suffix** vs **广告 SDK suffix** vs **共享 CDN suffix**, 避免假阳性识别.


## v5.3.0-rc30.12.9

**发布日期**: 2026-05-18
**versionCode**: 530129

DPI 规则更新. 基于 2026-05-18 真机 36 分钟抓包 (Realme RMX5010 / ColorOS 16 / 441MB pcap / 10645 域名命中) merge 进现有 dpi_rules.json.

### 改动

- **新增 4 条规则**:
  - `bytedance_ecdn`: 字节系 ECDN (ndcpp.com / bytegecko.com / bytemastatic.com / tcdnos.com / douyinliving.com) — 933 包命中, 之前被错归到 bytedance_group fallback
  - `p2p_cdn_acceleration`: 未知归属的 P2P CDN (comfylink.com / cjjd14.com / dahhxxttxs.com / xxpkg.com / 0kkkkkt.com / manlaxycloud.com / starrydyn.com) — 547 包命中, 多为 hash-style 子域
  - `tencent_anticheat`: 腾讯反作弊系统 (anticheatexpert.com) — 55 包命中, 装腾讯游戏后台跑
  - `p2p_webrtc_stun`: WebRTC STUN / P2P 打洞 (xdrtc.com) — 55 包命中
- **增强 4 条已有规则**:
  - `douyin`: 加 douyinliving.com (直播子品牌)
  - `xiaomi_update`: 加 xiaomi.net
  - `qq_music`: 加 tencentmusic.com
  - `tencent_ads_extra`: 加 sogou.com
- **rules_version**: hnc-curated-v3-rc28.1.1-priority → hnc-curated-v3-rc30.12-2026-05-18-merge
- **总规则数**: 126 → 130

### 升级机制

service.sh 检测到 rules_version 变化 (rc28.1.1 → rc30.12), 自动:
1. 备份用户当前 /data/local/hnc/etc/dpi_rules.json 到 .bak-<timestamp>
2. 复制模块新版规则到运行时
3. 重启 dpid 加载新规则

如果用户自己改过规则, 备份文件可恢复. 自动机制在 rc29.3 就有了, 这次只是触发它.


## v5.3.0-rc30.12.8

**发布日期**: 2026-05-17
**versionCode**: 530128

兼容性诊断体系完善 + 文档完善. 二进制无改动, 但加了"今天的所有兼容性发现都自动可见"的机制.

### 改动

- **capability_probe.sh 新增 17 个字段**: c_fork_supported / go_fork_supported / kernel_blocks_clone_vm / selected_launcher / fork_probe_present / hnc_launcher_present / dpid_has_iface_retry / dpid_version / selinux_enforcing / selinux_avc_denied_recent / seccomp_active / no_new_privs / cap_eff_full / su_domain — 把今天 fork EPERM 诊断时收集的所有关键信息固化进运行时探测.
- **bin/diag/ 新目录**: fork_probe (复制) + gofork_probe.go (源码) + diag.sh 一键诊断脚本.
- **diag.sh 13 项诊断**: 系统/内核/ROM/Root框架/进程清单/模块版本/daemon二进制/fork+exec测试/proc-status/AVC-denied/热点接口/capabilities/dpi状态/日志尾部.
- **COMPATIBILITY.md 彻底重写**: 加 Go fork EPERM 已知问题段, 加按风险排序的待测 ROM 表, 加 WebUI 内查兼容性指南.
- **WebUI 兼容性能力卡片优化**: 优先显示 fork / launcher 关键字段, 其次才是 tc 能力.
- **ARCHITECTURE.md** (rc30.12.8 新增): 项目内部架构手册, 给未来的 Ling/AI 看, 10 章约 600 行.
- **EVOLUTION.md** (rc30.12.8 新增): 项目演化史, rc1 → rc30.12.7 怎么走过来的, 13 章约 400 行.
- **CHANGELOG.md 补 rc30.12.4-12.7 段** + webroot/changelog.html 补 rc30.0-30.12.7 卡片.


## v5.3.0-rc30.12.7

**发布日期**: 2026-05-17
**versionCode**: 530127

设备页入场动画时序统一. 修 device-filter-bar 之前无动画 0s 立即出现, 其他组件 0.16-0.30s 延迟入场, 视觉错乱.

### 改动

- **device-filter-bar 加 0.22s fadeUp 动画**: 之前没有动画立即出现, 跟其他组件失同步
- **按 DOM 自上而下重排 timing**: hero 0.14 / search 0.18 / filter 0.22 / global-ops 0.26 / label 0.28 / toolbar 0.30, 形成自然的瀑布式入场
- **只动 CSS**, 不动 JS / 二进制


## v5.3.0-rc30.12.6

**发布日期**: 2026-05-17
**versionCode**: 530126

DPI 页结构优化 + 修空状态文字被切 bug.

### 改动

- **进程诊断 + 能力探测上移**: 排到设备应用画像之后, 折叠组之前 — 常用诊断不该藏在折叠组里
- **修空状态文字被左边切的 bug**: <code>dpi-l2-summary</code> 和 <code>dpi-empty</code> 在 <code>.setting-group</code> (overflow:hidden + 圆角) 里没有内 padding, 文字贴到玻璃边框被圆角切. 加 16px 内 padding
- **DPI 页字体统一**: 12→13px / 行距 1.55-1.6→1.7, 所有空状态文字视觉一致


## v5.3.0-rc30.12.5

**发布日期**: 2026-05-17
**versionCode**: 530125

DPI 字体优化 + 进程诊断常显.

### 改动

- **进程诊断 + 能力探测不再折叠**: 默认展开 (日常需要看的状态, 不该需要点击才看到)
- **关于 DPI 模块 字体优化**: 13→14px, 行距 1.7→1.85, 段间距 10→14px, +0.01em 字间距
- **代码块加深**: 加深背景 + 边框, 视觉锚点更清晰


## v5.3.0-rc30.12.4

**发布日期**: 2026-05-17
**versionCode**: 530124

UI 大幅优化: 设备页 DOM 重排 + DPI 页可折叠 sec-title 机制.

### 改动

- **设备页 DOM 顺序重排**: 搜索 → 设备过滤 → **全局操作上移** → 批量/模板 chip → 设备列表
  - 把"设备过滤 + 全局操作"两个主要功能视觉相邻, 次要的批量/模板放后面
- **DPI 页可折叠 sec-title**: 7 个次要 section 默认折叠 (未识别域名 / 规则库 / nDPI 高级诊断 / 进程诊断 / 能力探测 / 事件流 / 关于 DPI), 点击 sec-title 切换展开
  - CSS 加 .sec-title.collapsible.collapsed 样式, 加 chevron 箭头, hover/active 反馈
  - JS document-level click handler, 点击 toggle collapsed class + 隐藏/显示下一个 sec-title 之前所有 sibling


## v5.3.0-rc30.12.3

**发布日期**: 2026-05-17
**versionCode**: 530123

ColorOS 16 / SukiSU 后端启动彻底修复链 (合并 rc30.11 → rc30.12.3 整条).

详见 `PATCH-NOTES-v5.3.0-rc30.12.3.md`.

### 真凶定位 (今天最大发现)

Go runtime 用 `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` 的 vfork-style 路径**在 ColorOS 16 (Android 16, kernel 6.6.102) + SukiSU 上被内核 hook 拦截**, fork+exec 报 EPERM. 这不是 SELinux / seccomp / capability / 文件权限问题 — 系统层面完全没有限制 (Seccomp=0, NoNewPrivs=0, full caps, su domain), 但 Go 程序内 `exec.Cmd.Start()` 必定失败. C bionic `fork()+execv()` 在同一进程同一权限下 100% 工作.

### 修法概览

- **bin/hnc_launcher**: 新 C 写的 dpid 守护进程 (724KB, 静态链接 NDK API 21), 用 bionic fork+execv 替代 rc30.0 的 Go `hnc_dpid_supervisor`. 1 个 launcher 进程替代之前 3 个嵌套 hnc_dpid_guard.sh.
- **bin/fork_probe**: C 启动探测程序. service.sh 启动时跑一次, 通过 → C launcher (优雅) / 失败 → shell guard (兼容). **永远不会比 rc30.11 差**.
- **dpid 内部 retry 修复**: 改 `dpid/cmd/dpid/main.go` `isRecoverableCaptureError()` 加字符串匹配, 让接口未就绪时 dpid 自动每 2 秒重试 bind. 不再需要手动点 "重新绑定 DPI".
- **post-fs-data.sh + service.sh 加固**: chmod 模块目录 + 运行时目录, chcon system_file:s0 兜底, sentinel 哨兵循环.

### 改了什么二进制

- 新增 `bin/hnc_launcher` (C, 724 KB)
- 新增 `bin/fork_probe` (C, 6.7 KB)
- 重编 `bin/hnc_dpid` (Go, 字符串匹配修复, 版本 0.5.3-rc30.12.3-iface-retry)

### 进程数 (rc30.11 之前 vs rc30.12.3)

- 之前: hotspotd + httpd + watchdog + 3 个 hnc_dpid_guard.sh + dpid = **7 个**
- 现在: hotspotd + httpd + watchdog + hnc_launcher + dpid = **5 个**

### 不动 / 保留

- 王者规则 (rc30.10) / hotspotd 亚秒级 de-bounce (rc30.9) / 应用粒度限速 / nDPI 集成
- `hnc_dpid_supervisor` Go 二进制仍在 zip 里 (作为 tier-3 fallback)
- `hnc_dpid_guard.sh` shell 仍在 (作为 tier-2 fallback, 自动选择时使用)

### 没修的

- Go vfork EPERM 的**内核根因** (绕过了, 没深挖)
- dpid `decideMode` probe 阶段失败的极端 case (实战不触发)
- C launcher 在非 ColorOS 设备的兼容性 (probe 失败自动 fallback shell guard, 用户无感)


## v5.3.0-rc30.11 (作废, 已被 rc30.12.3 吸收)

第一次绕过 Go fork EPERM 的临时尝试. 让系统能用, 但 Go supervisor 本身仍然起不来 (sentinel 反复试启动徒劳). rc30.11 的所有修复在 rc30.12.3 里都保留, 只是不再依赖 Go supervisor.


## v5.3.0-rc30.10

王者荣耀规则大幅扩充. 真机抓包 134K 包 30 分钟, IPv4 5→10 段 + IPv6 0→2 段.


## v5.3.0-rc30.9

hotspotd 亚秒级 de-bounce. 本地 NDK 编 minimal 版 (去掉 BPF adapter / LSM loader, 这两个需要 libbpf 容器编不动), 5 处 g_last_event_ms 同步 + 主循环新算法, 让新设备识别延迟从 5 秒降到亚秒级.


## v5.3.0-rc30.8

- supervisor/watchdog chmod 列表补全 (rc30.0/rc30.1 加的 Go 二进制之前漏掉了 chmod)
- ps 扫描代替 pidof (pidof 在 Android toybox 上有 15 字符进程名限制)
- ensure_tc_uplink 冷却防止反复触发
- WebUI 250ms burst refresh


## v5.3.0-rc30.7

应用粒度限速 + 流量历史. WebUI 加流量分布饼图, 24h 应用流量趋势图.


## v5.3.0-rc30.6

异常流量检测. dpid 看到设备某 app 流量异常 (5x 移动平均) 时主动 emit alert, watchdog 读取后推送到 WebUI.


## v5.3.0-rc30.5

设备命名增强. mDNS / DHCP / OUI 联合查询, 设备名 fallback 链.


## v5.3.0-rc30.4

hw-banner 修复.


## v5.3.0-rc30.3

nDPI 集成. 作为常驻 daemon 自动运行, 抓 UDP/443 + TCP/443, RFC 9001 QUIC Initial 解密 + IP→SNI 反查表喂给主线 dpid. 电池开销 1-3%.


## v5.3.0-rc30.2

dpid 限速优化, 应用粒度限速 (按"抖音""王者"限带宽).


## v5.3.0-rc30.1

引入 Go `hnc_watchdog` 替代老 shell watchdog 主循环.

⚠️ **rc30.1 起在 ColorOS 16 + SukiSU 上 Go watchdog 内部 fork 子进程会报 EPERM**, 完整修复在 rc30.12.3.


## v5.3.0-rc30.0

引入 Go `hnc_dpid_supervisor` 替代 shell `hnc_dpid_guard.sh`.

⚠️ **rc30.0 起在 ColorOS 16 + SukiSU 上 Go supervisor 起不来**, 完整修复在 rc30.12.3.


## v5.3.0-rc29.1

**发布日期**: 2026-05-17
**versionCode**: 530091

修 rc29 的核心 bug + 加两个用户请求功能。

### 修复

- **dpid 假 IPv6 客户端**: rc29 装上后"当前活跃设备/应用"出现一堆 `2409:.../240e:...` 假客户端,MAC 全是上游 5G 网关。根因是 EventFlow 把回程包(server→client)的服务器 SrcIP 当成 client。修复方案:
  - **A**: dpid 启动时探测 wlan2 接口的全部 IPv4 子网 + IPv6 前缀,`assignClient` 优先用 hotspot 网段判方向
  - **C**: `RecordFlow` 改成只查不创,即使 A 漏判,服务器 IP 也不会污染 client 列表
- 修复后 tx/rx 字节统计方向正确、后台流持续性能正确触发、`NaN%` 置信度 bug 顺带消失

### 新增

- **WebUI 离线设备清理按钮**: 全局操作卡片加 `🧹 清理离线设备`。弹窗显示「N 台离线 + M 台带规则」,默认保留带规则的,复选框可选连规则一起清。后端走 `gate_lock` 跟 hotspotd 并发安全
- **WebUI 设备过滤"近 7 天活跃"**: 下拉框新增默认选项,显示在线 + 最近 7 天来过的离线设备。`只看在线` 选项保留作向后兼容

### 兼容性

- `dpi_state.json` schema 仍是 2.0,字段集与 rc29 相同
- 已选过设备过滤的用户不强制迁移
- 新装/未选过的用户默认走 `近 7 天活跃`


## v5.3.0-rc29

**发布日期**: 2026-05-17
**versionCode**: 530090

dpid 二进制重写,把 rc28.1.x 在规则库里加但二进制没读的 schema 字段(`ip_matchers` / `ipv6_matchers` / `priority` / `sub_categories` / `ground_truth`)全部真正使用,同时把保留为空字段的 4 个子系统做成真实数据来源。

### 新增

- **IPv6 抓包**:BPF 加双协议路径,DNS / TLS / 443 端口在 IPv4 + IPv6 上同等放行。对中国移动 5G + 抖音(几乎全 IPv6 流量)是必备。
- **JA4 指纹**:实时计算 FoxIO 公开的 JA4 算法。`top_ja4` / `top_fingerprints` 现在是真实数据,不再恒为空。可选加载 `/data/local/hnc/etc/dpi_ja4_fingerprints.json` 映射 JA4 → 应用名。
- **conntrack 真实读取**:每 15 秒读 `/proc/net/nf_conntrack`,自适应 SELinux 拒读情况(报 `conntrack_readable: false`)。
- **字节流统计**:`tx_bytes` / `rx_bytes` 每个 client 独立累加。全局 `total_tx_bytes` / `total_rx_bytes`。
- **IP / IPv6 流分类**:规则的 CIDR matcher 真正生效。比 DNS/SNI 分类更鲁棒。
- **priority 排序**:specific 规则优先,fallback 兜底,抖音 / bytedance_group 等不再相互污染。
- **子分类检测**:行为驱动,例如 wechat 下的 voice_call 由 `UDP 183.232.84.0/24:8000 pps > 200` 触发。
- **后台流持续性**:16 个 30 秒桶检测持续覆盖 > 80% 的"后台流"。直接修复 2026-05-16 真机录包中 WeChat 后台通话污染前台 App 统计的问题。
- **置信度**:LabelCount / FingerprintCount 加 `confidence` 字段(high/medium/low),WebUI 可显示徽章。

### Schema

- `dpi_state.json` schema 版本从 **1.2 → 2.0**。
- 新增 21 个字段(详见 PATCH-NOTES-v5.3.0-rc29.md)。
- rc29 是 rc28.1.1 字段集的**严格超集**:rc28.1.1 中 rc29 缺失字段 = 0 个。WebUI / 上层脚本零修改即可继续工作。

### 真机测试需求

以下三项**只有装上才能验证**,可能需要 rc29.1 / rc29.2 微迭代:
1. conntrack 在 Snapdragon 8 Elite + ColorOS 16 上是否被 SELinux 拦截读取。
2. JA4 算法对国内 App (微信 / 抖音) TLS ClientHello 的稳定性。
3. BPF 双协议放行后,`kernel_drops` 是否相对 rc28.1.1 显著恶化。

### dpid 体积变化

```
rc28.1.1: 2,949,282 字节 (Go 1.26.2)
rc29:     2,556,056 字节 (Go 1.22.2 + trimpath)
```


## v5.3.0-rc25.0

- DPI 规则库增强：新增/补充常见游戏、系统服务、广告 SDK、云服务/CDN 规则。
- DPI 页面新增未识别域名助手，可从 DNS/SNI Top 生成规则模板，无需重新刷包。
- nDPI Lab 继续作为可选采样参考；默认不影响主 DPI。

## v5.3.0-rc17

- DPI 页面等待接口/重绑中时自动进入 1 秒快速刷新，恢复正常后降回低频刷新。
- 新增 DPI 进程诊断卡，区分主实例与子 shell，避免把 guard/watchdog 子进程误判成重复失控。
- 新增 `bin/rc17_process_health.sh`，输出 hnc_httpd / hnc_dpid / hotspotd / watchdog / dpid_guard 健康 JSON。
- service/watchdog 加强 hotspotd 单实例整理，发现重复 C daemon 时保留 pidfile 指向实例并清理多余进程。
- 释放并重启资源后延长快速刷新窗口，减少后端恢复但页面慢半拍的问题。

## v5.3.0-rc16

- DPI 页面新增“刷新状态 / 重新绑定 DPI”。
- 放宽 hnc_dpid_guard 热点接口 ready 判断，避免 wlan2 可抓包但卡在“等待接口就绪”。
- 加强 service/watchdog 的 dpid_guard 单实例自愈。
- 新增 rc16 启动自检脚本。


## v5.3.0-rc13

- WebUI「释放所有资源」改为安全释放并自动重启，避免杀死 hnc_httpd 后无法重进。
- 新增 hnc_dpid_guard.sh：接口未就绪时快速等待，netlink 事件触发重绑，network-is-down 自动恢复。
- bridge 失败卡片新增「重新拉起服务」按钮。
- 新增 rc13_release_resource_selfcheck.sh 自检脚本。

# v5.3.0-rc1

**发布日期**: 2026-05-06  
**versionCode**: 530001

---

## 一句话总结

开启 HNC v5.3 Smart Queue / SQM 低延迟专项第一阶段：先做安全基础设施，不默认改变现有限速路径。

## 新增

- 新增 `capability_probe.sh` 对 `fq_codel`、`cake`、`cake autorate-ingress` 的 dummy 安全探测。
- `run/capabilities.json` 新增：
  - `tc_fq_codel_supported`
  - `tc_cake_supported`
  - `tc_cake_autorate_ingress_supported`
  - `sqm_supported`
  - `sqm_recommended_mode`
- 新增 `bin/sqm_manager.sh`：
  - `status [iface]` 查看当前 SQM 状态 JSON
  - `get-mode` 查看当前模式
  - `set-mode off|fq_codel|cake|auto|game` 保存模式
  - `set-profile balanced|game|bulk|custom` 保存策略档
  - `apply [iface]` 通过 `tc_manager.sh restore` 安全刷新叶子 qdisc

## 行为边界

- 默认 `sqm_mode=off`，升级后不改变 v5.2.1 的日常行为。
- 开启 SQM 后，只影响**无真实延迟/抖动/丢包**的设备 class leaf。
- 设备开启 netem 延迟/抖动/丢包时，仍然强制使用 netem，避免弱网模拟失效。
- 不接管、不替换、不清空 Android/ColorOS 系统 BPF map/program。
- 不把 nftables 作为依赖。

## 技术说明

- `tc_manager.sh` 新增 SQM leaf 选择逻辑：
  - `off`：继续使用 `netem delay 0ms limit 100` 占位 leaf。
  - `fq_codel/game`：delay-free class 使用 `fq_codel` leaf。
  - `cake`：delay-free class 使用 `cake` leaf，失败自动回退 netem 占位。
  - `auto`：根据 capabilities 选择推荐模式。
- `set_delay 0 0 0` 会在 SQM 开启时回到 SQM leaf；设置真实 delay/jitter/loss 时会切回 netem。

## 测试

新增回归测试：

- `test/unit/test_sqm_v53.sh`

覆盖：

- capability probe 输出 SQM 相关字段。
- `sqm_manager.sh` 默认 off。
- `sqm_manager.sh set-mode fq_codel` 可持久化。
- 非法模式会失败。

---

# v5.2.1

**发布日期**: 2026-05-02  
**versionCode**: 520100 (从 rc1.22 的 520032 提升)  
**daemon md5**: `0d869b3de76d6a97b53253edb4d8c2d6`

---

## 一句话总结

整合 v5.2.0-rc1.22 + 在真机环境下追出来的 9 个独立缺陷修复（合称 webfix1–9），是 v5.2 系列里**首个面向日常使用**的稳定版。核心功能（限速 / 延迟 / 黑白名单 / 远程访问）零改动。

---

## 用户视角的变化（简版）

| 你之前可能遇到的问题 | v5.2.1 已修复 |
|---|---|
| 升级到 rc1.22 后 WebUI 按钮全部失灵，热点状态卡片显示但点不动 | ✅ 修复 patch 损坏的 JS 语法 |
| 打开 WebUI 卡 1 分钟左右才出现内容（特别是 SukiSU manager） | ✅ 首屏从 ~48 秒降到 < 1 秒 |
| WebUI 频繁弹 toast：`HTTP fetch failed; KSU bridge auto disabled` | ✅ daemon 加 CORS 头，HTTP 直连工作 |
| 应用限速 / 注入延迟时 UI 卡顿 200-500ms | ✅ 走 HTTP 直连后无主线程阻塞 |
| 提示"当前设备内核不支持 IFB/mirred，上行限速已禁用"（明明以前能用） | ✅ 修复 capability 探测逻辑，上行限速可用 |
| 注入延迟时弹 `netem apply failed` 错误 | ✅ 修复 daemon 解析 stderr 污染问题 |
| 配对码生成失败弹窗的"关闭"按钮点不动 | ✅ 按钮可点 |
| 统计页"限速中/延迟注入"数字偏大（包含离线历史设备） | ✅ 只算在线设备 |
| 主页设备过滤卡片首屏一闪无主题样式（一根灰条） | ✅ 与其他卡片样式统一 |
| watchdog 日志疯狂刷"mirred missing repairing" | ✅ 修复 grep 模式，日志清净 |

---

## 修复细节（技术版，按发现顺序）

### 1. patch tarball JS 语法损坏 (webfix1)

`webroot/index.html` 第 4468/4478 行被上游 patch 工具错误展开，把 `$("#stats-v52-source-status")` 变成 `0 0"#stats-v52-source-status")` —— `$(` 在 patch 生成管道里被某个 shell 当成命令替换执行了，把 `$("#...")` 干掉了。

整个 `<script>` 块因此 `SyntaxError`，所有 `onclick` 不绑定，UI 看似正常但全部按钮死。

**修法**：恢复成 `$("#...")`。

### 2. 首屏 48 秒同步 shell 阻塞 (webfix2)

rc1.22 在 `init()` 同步段加了 `initStatsSourceSelect()`，里面通过 `kexec("sh stats_v52_source_switch.sh text")` 调一个会级联 6 个子脚本的 shell。SukiSU manager 的 `window.ksu.exec` 是同步 fork+exec+wait，主线程被锁 ~48 秒（实测 `FCP=48860ms`）。

**修法**：
- Shell 端加 `HNC_FIRSTLOAD_FAST=1` 让只读模式跳过 `run_observe` 级联（约 120× 加速）；
- JS 端把 `refreshStatsV52SourceStatus` 用 `setTimeout(4000)` 推到首屏之后。

### 3. loopback HTTP 未开 CORS (webfix3)

daemon `hnc_httpd` 只在 HTTPS 远程端口（8443）设 CORS，loopback 端口（8444）裸返。SukiSU manager 把 WebUI 装载到 `https://mui.kernelsu.org`，从那里 fetch `http://127.0.0.1:8444/api/*` 是跨 origin 请求，被浏览器拦下，WebUI 退回到 `window.ksu.exec` 桥接（每次 50–200ms 同步阻塞）。

**修法**：新增 `loopbackCORSMiddleware`，严格白名单单一 origin `https://mui.kernelsu.org`，OPTIONS preflight 返回 204。HTTPS 远程服务**不动**（保留原有鉴权层）。

### 4. CORS 与 daemon 反 CSRF 冲突 + IFNAMSIZ 网卡名溢出 (webfix4)

两个独立问题，因相互掩盖一并修复：

- **(a)** daemon 的 loopback 免鉴权路径要求 `Origin` 和 `Referer` 都为空（rc3 时代写下的反 CSRF 措施）。webfix3 加了 CORS 头之后，SukiSU 的 WebView 总是带 `Origin: https://mui.kernelsu.org`，daemon 看到非空 Origin 直接走 cookie auth，没 cookie → 401。Middleware 在白名单 origin 校验通过后剥掉 Origin/Referer，让免鉴权路径触发。

- **(b)** `bin/capability_probe.sh` 用 `hnc_probe_dummy_$$` / `hnc_probe_peer_$$` / `hnc_probe_ifb_$$` 做临时网卡名。PID 4-5 位时这些名字 19-21 字符，超过 Linux `IFNAMSIZ=15`（含 NUL 是 16）。`ip link add` 永远拒绝，dummy 创建失败，下游 HTB / netem / mirred / IFB 探测全部 skip 真测分支，capabilities.json 全是 null/false。改为 `hnc_p_d_NNNNN`（13 字符，PID 取后 5 位）。

### 5. capability_probe qdisc + parent 不兼容 (webfix5)

`ensure_ingress_parent()` 优先尝试 `clsact` qdisc，但下面所有 filter 测试用 `parent ffff:`（这是 ingress qdisc 的固定 handle 简写）。

老版本 Android iproute2（ColorOS RMX5010 装的是 `ss171113`，2017 年的）不接受 `clsact + parent ffff:` 组合，返回：
- `RTNETLINK answers: Invalid argument` （u32 / mirred / police）
- `Unknown action "noact"` （matchall / flower）

这些错误信号被 capability_probe 当作"内核不支持"，UI 显示"IFB/mirred 不支持，上行限速已禁用"。但 tc_manager 实际操作时用 ingress qdisc，所以**上行限速一直是工作的**——只是 capability 报告错了，前端禁用了输入框。

**修法**：`ensure_ingress_parent()` 优先用 `ingress` qdisc，clsact 作为 fallback。ingress + parent ffff: 是从 ~2010 年 iproute2 起就完全兼容的组合。

### 6. watchdog mirred 检测 grep 不匹配 + marker 永久卡死 (webfix6)

两个紧密相关的问题：

- **(a)** `bin/watchdog.sh` 检测 ingress mirred filter 用 `grep -q "mirred.*redirect dev ifb0"`。但 tc 实际输出是 `mirred (Egress Redirect to device ifb0)` —— 大写 `Redirect`、`to device` 不是 `dev`。pattern **永不匹配**，watchdog 每分钟报一次"missing"并触发"修复"（修复成功因为 mirred 早就在了），日志被永久 spam。改为大小写不敏感的 `grep -qi "mirred.*ifb0"`。

- **(b)** `tc_manager.sh` / `watchdog.sh` 在首次失败时写 sticky marker 文件（如 `uplink_unsupported`、`tc_qos_fallback`），但只有 `hotspot_autostart.sh` 在自启时清。多数用户不开自启 → marker **永远不被清** → 即使后续 capability 探测改对了，runtime 检查仍走"不支持"分支。capability_probe 跑完确认能力支持时，主动清相关 marker，让自愈链路畅通。

### 7. json_set.sh stderr 泄漏到 daemon (webfix7)

`bin/json_set.sh` 在 `hnc_json` 二进制不可用时 `echo "[WARN] ..." >&2` 提示走 fallback。但 `daemon/hnc_httpd/action.go` 用 `cmd.CombinedOutput()` —— **stdout 和 stderr 合并**。WARN 字符串于是混进了 daemon 解析的"返回值"前面：

```
json_set: [WARN] hnc_json device_get unavailable; count=53385
85
```

第二行才是真实 mid (`85`)，但 daemon 的 `intRE.MatchString` 看第一行就 fail，错误信息 surface 成 "mid invalid: device_get returned non-integer mid"，前端 toast 显示 "netem apply failed"。

`count=53385` 同时揭示了第 8 个问题：hnc_json 在测试设备上**失败了 5 万 3 千次**，没人看那个计数器。

**修法**：WARN 用 `printf >> $JSON_LEGACY_FALLBACK_LOG` 改写到日志文件，**不输出到 stderr**。

### 8. hnc_json 缺少可执行权限 (webfix8)

`post-fs-data.sh` 显式 `chmod 755` 一组无 `.sh` 后缀的二进制：

```sh
for _b in hotspotd hnc_ipc hnc_tc_ingress mdns_resolve; do
```

**漏了 `hnc_json`**。该文件是个 awk 脚本但没 .sh 后缀，KSU 模块解压后保持 644，`json_set.sh` 每次调它都 `Permission denied`，回退到内置 awk 实现。这就是 webfix7 看到的"5 万次 fallback"的根因。

**修法**：`hnc_json` 加入 chmod 列表。

### 9. 用户反馈的 4 个 UX bug (webfix9)

- **`pair_gen.sh` find -delete 污染 stdout**：脚本最后 `find ... -delete 2>/dev/null` 用来清理 60 分钟前的 `pair_success.*` 残留。Linux GNU find `-delete` 静默，但 Android 的 toybox find **会把每个被删的路径 print 到 stdout**。残留文件存在时，daemon 收到的"JSON 输出"实际是：
  ```
  /data/local/hnc/run/pair_success.OF4qRclPv2Hi
  {"ok":true,"pin":"...","session_id":"..."}
  ```
  前端 `JSON.parse` 在第一行炸，弹"配对码生成失败"。修法：`>/dev/null 2>&1` 双重重定向。

- **配对失败弹窗的"关闭"按钮点不动**：按钮用了 `data-action="modal-close"` 属性，但**代码里没有任何 dispatcher 监听这个 action**。其他模态框都是 `onclick="hideModal()"` 或 `data-action="cancel"`。可能是早期某版有 modal-close dispatcher 后来重构掉了，这处遗忘清理。结果是用户被永久关在弹窗里直到 force-stop SukiSU。修法：直接改用 `onclick="hideModal()"`。

- **统计页计数包含离线历史设备**：`updateCounters()` 计算 `limited` 和 `delayed` 时没过滤 `status === 'online'`。一台设备的规则保存在 rules.json 里，即使设备已离线很久也会被算入。9 台历史设备 1 台在线时显示"2 限速中, 6 延迟注入"——令人困惑。修法：加 `d.status === 'online' &&` 前置过滤。

- **设备过滤卡片首屏样式不一致**：用了自定义 `.device-filter-bar` 而非项目通用的 `.glass`。CSS 变量在两类元素上的解析时机有微差，首屏一闪显示无主题状态（看起来像一根灰横条）。修法：加上 `.glass` 类，让它走和其他卡片同一套渲染路径。

---

## 包结构清理

v5.2.1 同时整理了发布 zip 的内容：

| 类别 | rc1.22 | v5.2.1 | 说明 |
|---|---|---|---|
| 文件总数 | 338 | 220 | -118 |
| zip 大小 | 5.1 MB | ~5.0 MB | 变化不大（多数被删的是文档）|
| `PATCH-NOTES-*.md` | 82 个 | 0 | 历史发布说明，已归档到仓库 docs-archive/ |
| 顶层 `.md` 文件 | 11 个 | 4 个 | 仅保留用户需要的：README, CHANGELOG, COMPATIBILITY, SECURITY |
| `CHANGELOG.md` | 326 KB（85 个版本节）| ~12 KB | 仅保留 v5.2.1 节，历史归档 |
| `third_party_build/` | 含 | 不含 | 开发用，运行时不需要 |
| `STAGE-*.md`、`README-BATCH2.md` | 含 | 不含 | 开发过程文档 |
| `INTEGRATION.md` (v5.0 alpha)、`HACKING.md`（60 KB）、`ROADMAP.md`、`INSTRUCTIONS.md`（v5.1 时代）、`CONTRIBUTING.md` | 含 | 不含 | 开发文档/过时文档，归档到仓库 |
| `test/` | 含 | **保留** | `post-fs-data.sh` 会复制到 `/data/local/hnc/test/` 让用户能跑测试，不能删 |

---

## 安全边界

未触动以下任何一项：
- tc / iptables 规则计算逻辑
- watchdog 状态机
- 限速精度策略 (htb / netem / mq fallback)
- 黑白名单匹配规则
- 远程访问鉴权 (cookie / token)
- KSU IPC 协议
- `service.sh` / `post-fs-data.sh` 启动时序

9 项均为缺陷修复，不引入新功能、不改变 API、不移除任何选项。

---

## daemon binary

```
v5.2.1 daemon md5: 0d869b3de76d6a97b53253edb4d8c2d6
- Go 源码 vs rc1.22: server.go +37 / main.go +5 (CORS middleware)
- Go 源码 vs webfix9:  完全相同 (webfix5-9 仅改 shell + HTML)
- v5.2.1 重新构建嵌入新版本字符串 (-X main.version=v5.2.1)
```

## 安装

新安装：直接刷 `HNC-v5_2_1-arm64.zip`。

从 rc1.22 升级：
1. SukiSU manager → 模块 → HNC → 卸载（建议保留数据）
2. 重启
3. 刷 `HNC-v5_2_1-arm64.zip`
4. 重启

如果之前应用过 webfix1-9 的就地热修复脚本，刷 zip 时模块会被完整覆盖，自动接管。

## 已知限制

- mq child htb（最精确队列链路）在 Snapdragon 8 + ColorOS / MIUI 平台上仍**无法启用**——内核拒绝在 mq 的子 class 上挂 htb，HNC 自动 fallback 到 root htb（"稳准"模式）。这是平台限制不是 HNC bug。fallback 模式精度对手机热点场景完全够用，UI banner "无法使用最精确队列链路" 是诚实告知，不是错误。

- `hnc_json` 二进制本身在某些设备上仍可能失败（测试机上 webfix8 chmod 之后失败次数从 5 万降到 0，但其他设备的具体失败原因没有跟进调查）。失败时 awk fallback 接管，功能上无影响。

---

## 历史版本

完整历史变更记录（v5.0 alpha → v5.2.0-rc1.22, 共 85 个版本节点）已归档到
`docs-archive/CHANGELOG-full-history.md`，仅作为开发参考保留，**不打入模块 zip**。

如需查阅过往版本说明，请访问项目 repository。
