# 工作文档:HNC v5.30.0-rc1「用户反馈的三个 bug + 迁移 M5 / M4(影子) + 应用感知 QoS 初版」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」和第 3 节「测试纪律」是硬约束。
> 背景:`docs/ROADMAP.md` §A(v5.30 行)与 §B(迁移清单 M4 / M5)、`docs/CODEMAP.md`、`docs/WORK-v5.29.md`、`CHANGELOG.md` 5.28.0-rc1 ~ 5.29.0-rc1(**特别是 5.29 的「审查修复」一节 —— 那里列的每一类错误本版都不许再犯**)。
> 基线:分支 `claude/environment-config-ydr2ow` 最新提交(= main,v5.29.0-rc1 + 审查修复 + 本文档)。

---

## 0. 这一版做什么(按优先级)

| 顺序 | 任务 | 一句话 |
|---|---|---|
| T1 | 三个用户反馈 bug | 「今日在线 1 小时」不准、设备名显示 `null`、「新发现的应用」把公共 CDN / DNS 当成应用 |
| T2 | 迁移 M5:dpid 守护链收缩 | 4 层互相盯 → 2 层(C launcher + Go 看门狗) |
| T3 | 迁移 M4 第一步:设备发现 Go 影子 | Go 版邻居 / DHCP 发现**只算只比对**,不替换 hotspotd |
| T4 | 应用感知 QoS 初版 | 按识别结果给队列分优先级,**默认关、逐台开** |
| T-last | 版本与文档 | |

做不完时按 T1 > T2 > T3 > T4 的顺序取舍,**T1 必须做完**。

---

## 1. 项目基本情况(必读)

沿用 `docs/WORK-v5.27.md` ~ `WORK-v5.29.md` 的 §1,这里只补本版相关的。

- **在线时长**:Go 看门狗 `src/dpid/cmd/hnc_watchdog/duties.go` 的 `sampleOnlineHours`:热点开着时**每 ~55 分钟**(`onlineHoursEvery = 3300s`)读一次 `data/devices.json`,把此刻在线(`last_seen` 在 90 秒内)的每台设备往 `run/online_hours.jsonl` 写一行 `{"t","day","mac"}`。httpd `daemon/hnc_httpd/dpi_stats_source.go` 的 `onlineHoursByMAC` **一行算 1 小时**。前端 `webroot/js/core.js` `onlineHoursOf(mac)` 显示「今日在线 N 小时」。→ **刚连上 5 分钟、正好赶上采样的设备会显示 1 小时**(用户截图实锤)。
- **设备名**:前端 `core.js` 设备对象 `name = d.hostname || d.name || d.vendor || mac`。主机名来源:hotspotd(C,`daemon/hotspotd/hostname_cache.c` / `mdns_worker.c` / DHCP)写进 `devices.json`,dpid `src/dpid/capture/devhint.go` `cleanHostname` 只去不可打印字符。**有些设备的 DHCP option 12 上报的就是字符串 `"null"`**,全链路没人过滤,`"null"` 是非空字符串 → 界面显示 `null`。
- **新发现的应用**:dpid `src/dpid/output/discover.go`(共现聚类,已有「枢纽节点不参与合并」)→ httpd `api_discover.go`(分组、证据、忽略列表;`genericCertOrg` 只过滤了证书组织名里的 Cloudflare / Akamai 等)→ `api_discover_suggest.go`(v5.28 B2 起名:apk_domains / 启动指纹 / 证书 / JA4 / 域名)。用户截图里被当成「应用」的:`alibabadns.com`(被起名「Apple 旗下应用 / 证书·Apple」)、`cdngslb.com`(被起名「网易云音乐」)、`qtlcdn.com`(「好游快爆」)、`ksyuncdn.com`、`lanniao.com`、`wechatpay.cn`、`tencentcos.cn`。这些是公共 DNS / CDN / 对象存储 / 支付 SDK,被很多应用共用。
- **dpid 守护链现状**(`docs/CODEMAP.md`「侦察员的保镖」):`run/dpid_launcher.choice` 选定三者之一 —— C `hnc_launcher`(`src/launcher/`)、Go `dpid_supervisor`(`src/dpid/cmd/dpid_supervisor/`)、shell `bin/hnc_dpid_guard.sh`;外面还有 `service.sh` 的哨兵循环(30 秒,shell)和 Go 看门狗 `hnc_watchdog` 各自也会判 dpid 死活。v5.26 T2 已做到「选定后其他守护不插手」,但代码都还在、开机时仍会探测三选一。ColorOS 上 Go 进程起子进程可能被拦(所以 C launcher 必须保留)。
- **hotspotd**(C,~6900 行):邻居表 / DHCP 租约 / mDNS 名字 / 在线状态 → `data/devices.json` + UNIX socket。v5.30 只做 Go 影子,不替换。
- **限速树**:`bin/tc_manager.sh` 建 htb(根 `1:`,每台设备一个 class,mark → class 由 iptables `HNC_MARK` 链打 connmark)。DPI 识别结果:dpid 输出每条连接的应用 / 类别(`output/` 包,`run/flow_cls*.json`、`/api/connections`)。

---

## 2. 边界(硬约束)

1. 隐私与安全红线照旧:不做中间人解密,不注入 / hook 任何设备,不新增采集内容。
2. 迁移要「行为一致 + 能回退」:T2 / T3 每项一个开关文件(见各任务),退回旧做法不需要重刷模块。
3. T4 **默认关闭**,只对用户逐台开启的设备生效;关闭时 tc / iptables 规则与 v5.29 **逐字节相同**(要有测试比对生成的命令)。
4. API 兼容、持久化格式只增不改(`online_hours.jsonl` 旧行必须继续能读);不加第三方依赖,不改两个 `go.mod` 的 `go` 版本,`CGO_ENABLED=0`。
5. `service.sh` / `post-fs-data.sh` 只改 T2 指明的地方;**插入代码前先确认插入点在函数定义之后、不在注释里**(v5.29 把整块代码插进了文件头注释,开机根本执行不到)。

---

## 3. 测试纪律(v5.29 审查里每条都出过事,违反任一条该任务按未完成处理)

1. **每个修复 / 新功能都要有「改动前会失败」的测试**,提交说明里写清怎么验证的(例如 `git stash` 掉实现后跑测试看到哪条失败)。
2. **不许写同义反复的测试**:测试里重写一遍被测逻辑再断言自己(v5.29 `TestClsactSchedGateCacheAndRepairs`);在测试模式下被测代码根本不会走到的分支(v5.29 owner 测试:测试模式从不真起进程,新旧代码都过)。
3. **要测接起来的样子**:新逻辑接进主循环 / 调用链的,至少一条测试驱动**真实的调用方**(v5.29:单测测 `natUse(ncHealth)`,主循环写的是 `natUse("health")`,退回机制从没生效)。用常量,不要在调用处手写字符串键。
4. **不许把「没输出 / 错误输出」锁进期望文件**:期望文件要配一条「必须包含关键事实」的底线断言(v5.29 回放期望文件只有一行 DNS,TLS 一条没解析出来)。
5. **测试要密封**:不读真实 `/data/local/hnc`、本机网卡、真实时钟;全部注入(v5.29 预算测试在开发机上读了真实目录,直接失败)。
6. **测试不许改仓库里的文件**(生成测试数据要用 `UPDATE_TESTDATA=1` 显式开启)。
7. 不靠 `time.Sleep` 等异步结果;要么同步等待完成信号,要么注入时钟。
8. **编辑器不许把 Tab 换成空格**;所有改动的 Go 文件 `gofmt -l` 为空。**不许在提交说明 / README 里写「全绿」「基线即不满足」之类没实际跑过的结论**,要贴命令输出。
9. 外部命令调用:脚本路径和参数**分开传**(v5.29 把 `"脚本 repair 网卡"` 拼成一个参数,修复从没执行过)。

---

## 4. 任务

### T0 · 记录基线
跑第 6 节全部自检命令,结果写进提交说明(空提交)。维护者环境基线:`test/run_all.sh` → `ALL PASS: 504/505 (1 skipped)`。

---

### T1 · 三个用户反馈 bug(必须做完)

**T1a 在线时长按分钟累计**
- 看门狗改为**每 5 分钟**采样一次在线设备(进程内读 `devices.json`,不起 sh;只在 ACTIVE 时做),在内存里按 `(day, mac)` 累加分钟;**每 ~55 分钟或跨日时**落一行 `{"t","day","mac","m":<分钟>}`(仍是一行一台设备,文件增长与现在同量级)。看门狗退出(收到 SIGTERM)时把未落盘的分钟写掉。
- httpd `onlineHoursByMAC` 改为累计分钟:**有 `m` 字段按 `m` 算,旧行没有 `m` 按 60 算**(兼容)。API 增加分钟字段(如 `online_min`),保留原小时字段(= 分钟 / 60 取整,不再「有一行就是 1 小时」)。
- 前端:< 60 分钟显示「今日在线 N 分钟」,≥ 60 显示「N.N 小时」;0 不显示。
- 测试:设备只在一次采样时在线 → 5 分钟而非 1 小时;旧格式行仍按 60 计;跨日拆分到两天;退出时落盘。

**T1b 垃圾主机名当作「没有名字」**
- 统一一张垃圾名表(大小写不敏感,去首尾空白):`null`、`(null)`、`nil`、`none`、`(none)`、`undefined`、`unknown`、`localhost`、`localhost.localdomain`、`*`、`-`、空串、纯数字 / 纯空白。
- 三处都要挡:hotspotd 写缓存前(`hostname_cache.c` `hnc_cache_update` / DHCP / mDNS 入口,C 侧加一个小函数)、dpid `cleanHostname`、httpd 输出设备列表前(存量 `devices.json` 里已经是 `"null"` 的也要挡掉)。前端 `name` 兜底链同样跳过垃圾名(防御)。
- 用户手动改的名字(`hostname_src == "manual"`)不过滤。
- 测试:Go 两处 + C 侧(仓库已有 C 单测方式的照用;没有就用 shell 测试编译 + 调用)+ 前端(`test/unit` 里已有前端逻辑测试方式的照用)。

**T1c「新发现的应用」排除公共基础设施**
1. **共享基础设施名单**:新文件 `etc/dpi/shared_infra.txt`(或放进现有规则目录,跟随规则库更新),每行一个注册域(eTLD+1),至少包含:公共 DNS(`alibabadns.com`、`dnspod.cn`、`dnspod.com`、`114dns.com`、`dns.google`、`cloudflare-dns.com`、`quad9.net`、`doh.pub`)、国内外 CDN / GSLB(`cdngslb.com`、`alicdn.com`、`alikunlun.com`、`kunlunca.com`、`qtlcdn.com`、`ksyuncdn.com`、`ks-cdn.com`、`lanniao.com`、`wscdns.com`、`chinanetcenter.com`、`cdnhwc*.com` 类按前缀写清楚规则、`akamaized.net`、`akamaiedge.net`、`cloudfront.net`、`fastly.net`、`cdn77.org`、`bdydns.com`、`bcebos.com`、`qcloudcdn.com`、`cdn.dnsv1.com`)、对象存储(`tencentcos.cn`、`myqcloud.com`、`aliyuncs.com`、`amazonaws.com`、`myhuaweicloud.com`)、支付 / 通用 SDK(`wechatpay.cn`、`alipay.com` 的 SDK 子域、`umeng.com`、`getui.com`、`jpush.cn`、`bugly.qq.com`)。写进测试的是名单**机制**,名单内容可以继续扩。
2. 名单里的域名:**不能单独成组、不能作为组名 / 起名依据**;可以作为别的组的附属证据显示,但标注「公共服务」。
3. **按设备频度兜底**(不靠名单也能挡):同一时间窗内被 ≥ 3 台不同设备、且与 ≥ 4 个互不相关的组共现的注册域,判为共享基础设施(阈值做成常量并在测试里覆盖边界)。
4. **起名证据收紧**:证书组织名只有在证书 SAN 覆盖该主机名时才能当证据;命中名单 / 频度判定的域名不参与 apk_domains / 证书 / 「本机 App」证据。用户截图里 `alibabadns.com → Apple`、`cdngslb.com → 网易云音乐`、`qtlcdn.com → 好游快爆` 三个都要写成回归用例。
5. 已经出现在列表里的这些组:升级后不再显示(不需要用户手动忽略)。

---

### T2 · 迁移 M5:dpid 守护链收缩(开关 `run/wd_m5.disabled`)

- 目标形态:**C `hnc_launcher` 负责拉起 / 重启 dpid,Go 看门狗负责盯 launcher**;`service.sh` 哨兵循环不再判 dpid / launcher(只保留它现在对 Go 看门狗的兜底和 v5.29 的回滚观察)。
- Go `dpid_supervisor` 与 `bin/hnc_dpid_guard.sh`:开关打开(默认)时不再被选用;**代码先保留**(开关关掉时恢复 v5.29 的三选一行为),下个大版本再删。
- 「launcher 坏了」的救命路径(sentinel 里检测 `TLS segment is underaligned` 等 → 直拉 dpid)要搬到 Go 看门狗,行为照抄,并有测试。
- 进程风暴防线(v5.8.8 / v5.28 A3):判活一律走 pidfile + `/proc/<pid>/cmdline`,不用 `ps`;任何「发现没活 → 拉起」都要有冷却,测试覆盖「ps 只显示短名」的场景。
- 测试:开关开 / 关两种形态下谁负责拉起;launcher 坏 → 直拉 dpid;连续拉起失败的冷却;`dpid_launcher.choice` 旧值兼容。
- 验收:真机常驻进程里不再有 `hnc_dpid_guard.sh` / `dpid_supervisor`;杀掉 dpid 30 秒内被 launcher 拉回;杀掉 launcher 被看门狗拉回。

---

### T3 · 迁移 M4 第一步:设备发现 Go 影子(开关 `run/wd_m4_shadow.disabled`)

- 新包 `src/dpid/neigh/`:netlink `RTM_GETNEIGH` dump + 订阅 `RTNLGRP_NEIGH`(纯 syscall,照 v5.29 `nlroute` 的风格,**解析函数可直接喂字节测试,并按 ifindex 过滤 —— 内核 dump 不替你筛**)。
- Go 看门狗里跑影子:每 5 分钟把 Go 看到的「在线设备集合(MAC / IP / 网卡)」与 hotspotd 的 `devices.json` 比对,不一致计数写进 `run/watchdog_actions.json` 的 `m4_mismatch`,自检「看门狗动作」行一并显示。**不写 `devices.json`、不替换 hotspotd 任何功能。**
- 名字解析(DHCP / mDNS)本版不搬。
- 测试:报文解析(多条、DONE、ERROR、截断不 panic、按 ifindex 过滤);比对逻辑(多 / 少 / IP 变化);开关。

---

### T4 · 应用感知 QoS 初版(默认关,逐台开)

- 设备设置里新增开关「按应用分优先级」(`rules.json` 设备项 `app_qos: true`,默认缺省 = 关)。
- 开启的设备:在它已有的 htb class 下面挂 **3 个子 class + prio**:实时(通话 / 游戏)> 前台交互(视频、浏览)> 后台(下载 / 更新 / 云同步)。分档依据 = dpid 已有的识别类别(只读现有输出,不改识别);认不出的连接进中间档。连接 → 子 class 用 connmark 的空闲位(先查清 `HNC_MARK` 现有位分配,写进文档),**不得改动已有 mark 位的含义**。
- 速率:子 class 共享父 class 的 ceil,rate 按 50 / 35 / 15 分配,不改变设备总限速。
- 关闭(默认)时生成的 tc / iptables 命令与 v5.29 完全一致 —— 用 `tc_manager.sh` 的现有测试桩比对命令序列。
- 先不做 QoE 闭环、不做自动调参。
- 测试:命令生成(开 / 关);类别 → 档位映射;未识别 → 中间档;设备总限速不变。
- 验收(维护者真机):开热点,一台打游戏一台下载,对比开 / 关时游戏延迟抖动。

---

### T-last · 版本与文档
1. `module.prop`:`version=v5.30.0-rc1`,`versionCode=5300001`。
2. `CHANGELOG.md` 加 `## [5.30.0-rc1] - <日期>`;`webroot/changelog.html` 加大白话一段。
3. `docs/ROADMAP.md`:§A v5.30 行标「rc1 ✅」;§B M5 标完成、M4 标「影子 ✅,替换待 v5.31」。
4. `docs/CODEMAP.md`:守护链、`neigh` 包、共享基础设施名单、QoS 子 class。
5. `docs/API.md` 加「## 28. v5.30 变更」:`online_min`、`app_qos`、`m4_mismatch`、开关文件清单(`run/wd_m5.disabled`、`run/wd_m4_shadow.disabled`)。

---

## 5. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 用 Go 替换 hotspotd、删 hotspotd 代码 | M4 第二步,v5.31,先看影子对照数据 |
| 删除 `dpid_supervisor` / `hnc_dpid_guard.sh` 源码 | 留一版做回退 |
| QoE 闭环、自动调参、场景模式 | 6.0 |
| 改 DPI 识别结果本身 / 规则库格式 | 本版只读识别结果 |
| SQLite、进程合并、新界面转正 | 6.0(§B M6–M9) |

---

## 6. 自检命令(每个任务完成后都跑,全部通过才提交)

```sh
for f in $(git diff --name-only HEAD~1 -- '*.go'); do [ -f "$f" ] && gofmt -l "$f"; done
(cd daemon/hnc_httpd && go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && go vet ./... && go test ./... && go test -race ./capture/ ./nlroute/ ./output/ ./cmd/hnc_watchdog/ \
  && for c in dpid hnc_watchdog dpid_supervisor dpid_replay; do CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null ./cmd/$c || exit 1; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd
python3 -m unittest discover -s tools -p 'test_*.py'; rm -rf tools/__pycache__
for f in $(git diff --name-only HEAD~1 -- '*.sh') service.sh post-fs-data.sh bin/watchdog.sh; do [ -f "$f" ] && sh -n "$f" || echo "SYNTAX $f"; done
sh bin/pitfall_lint.sh
sh test/run_all.sh
sh bin/version_consistency_check.sh
sh bin/ci_preflight.sh
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done
```
改了 C(hotspotd / launcher)的:按 `.github/workflows/build.yml` 里的编译命令本地交叉编译一遍(有 NDK 时),没有 NDK 就在提交说明写明「C 改动未本地编译」。

---

## 7. 验收清单

- [ ] T1a / T1b / T1c 各自的回归用例(含用户截图里的 7 个域名、`null` 主机名、5 分钟设备)在旧代码下失败、新代码下通过。
- [ ] T2:两种开关形态的拉起职责测试;救命路径测试;冷却测试。
- [ ] T3:neigh 报文解析与 ifindex 过滤测试;影子比对测试。
- [ ] T4:关闭时命令序列与 v5.29 一致的比对测试。
- [ ] 第 3 节测试纪律逐条自查,在提交说明里写「已自查」并列出每个任务「改动前会失败」的证据。
- [ ] 第 6 节全部通过,`run_all.sh` 不比 T0 基线差;所有改动 Go 文件 gofmt 干净。
- [ ] 版本号、CHANGELOG、changelog.html、ROADMAP、CODEMAP、API.md 已更新。

**维护者真机验收**:在线时长对一台刚连的设备显示分钟;`null` 名字消失;「新发现的应用」里不再有截图中的 CDN;常驻进程少 dpid_guard / supervisor;`m4_mismatch` 观察一天;QoS 开 / 关对比游戏延迟。

---

## 8. 提交方式

- 从 `claude/environment-config-ydr2ow` 最新提交新建分支 `ai/v5.30`,先记下 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,中文提交信息:`v5.30 T1: ...`。署名用你自己的模型名。
- 没有推送权限:`git format-patch $BASE..ai/v5.30 -o patches/`,README 写上 `$BASE` 和第 6 节命令的**实际输出**;有推送权限:推到 `ai/v5.30`,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 9. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
