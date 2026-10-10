# 工作文档:HNC v5.32.0-rc1「收尾 + 正式版候选」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」和第 3 节「测试纪律」是硬约束。
> 背景:`docs/ROADMAP.md`、`docs/WORK-v5.31.md`(§8「有问题」的定义)、`CHANGELOG.md` 5.30 / 5.31(**特别是 5.31.0-rc1 的「审查修复」一节 —— 那里列的每一类错误本版都不许再犯**)。
> 基线:分支 `claude/new-session-hoxhbz` 最新提交(v5.31.0-rc1 + 审查修复 + 本文档)。
> **维护者决定:本版不等真机验收结果。** 所以凡是要靠真机结论才能定的事(删旧守护代码、删 hotspotd 的发现代码、改设备发现的默认值)本版一律不做;本版只出 `v5.32.0-rc1`,正式版(去掉 `-rc`)等维护者真机回归之后由 Claude 改版本号发出。

---

## 0. 这一版做什么

不加新功能,把已知的账还清,并把「退回 C 版」这条退路练通。

| 顺序 | 任务 | 一句话 |
|---|---|---|
| T1 | 已知小 bug 收口 | 启动指纹起名不生效、设备合并丢 `app_qos`、扫描计数恒为 1、一处 gofmt |
| T2 | C 版退路的老问题 | hotspotd 重扫 ARP 时,换过 IP 的设备可能报回旧 IP |
| T3 | 退路演练 | 「默认值改回 C 版」这条路在模拟设备上跑通(本版不真的改默认值) |
| T4 | 省电小项(可选) | Go 写者空闲时降低醒来频率 |
| T5 | 文档 | README / ROADMAP / CODEMAP / API,正式版说明草稿 |
| T-last | 版本 | `v5.32.0-rc1` |

做不完时按 T1 > T2 > T3 > T5 > T4 取舍。

---

## 1. 现状(必读)

### 1.1 设备发现(v5.31)

- 默认由 Go 看门狗发现设备、写 `data/devices.json`(`src/dpid/cmd/hnc_watchdog/m4_owner.go`,表 `src/dpid/devscan`,名字 `src/dpid/devname`,邻居表 `src/dpid/neigh`);hotspotd 带 `--no-discovery` 只留硬件加速兜底。
- 开关 `data/m4_owner`(`go` / `c`);默认值是 `m4_owner.go` 里的常量 `m4OwnerDefault = "go"`。看门狗每轮用 hotspotd 的 `STATUS` 核对它到底在不在做发现,与开关不符就纠正(审查加的 `reconcileLocked`)。
- 「有问题就退回 C 版」的规则见 `docs/WORK-v5.31.md` §8:真机上出问题时,正式版把 `m4OwnerDefault` 改成 `c`。**这一步本版不做**,但 T3 要保证它改了就能用。

### 1.2 模拟设备(本版的主要验收手段)

不用手机:`test/sim/simnet.sh`(假热点 + 假设备 + 假 `dumpsys`)、`test/sim/run_m4_sim.sh`(C 模式对照)、`test/sim/run_m4_sim_v531.sh`(全字段影子 / Go 模式 / 看门狗真实的运行中切换)。用法见脚本头注释;`HNC_SIM=1 sh test/run_all.sh` 一起跑(要 root + 网络命名空间)。**你的环境跑不了就照写场景,提交说明写明,审查时 Claude 在云端容器跑。**

### 1.3 v5.31 审查里出过的错(本版不许再犯)

1. 异步结果做完了没人知道:后台解析出的名字只改了内存、没触发写盘。**异步回填要通知主循环。**
2. 改动了用户数据:为了比 MAC 把整个文件转小写,连用户起的名字一起变小写。**只在比较时折叠大小写,数据原样取。**
3. 判断进程活没活把僵尸当活着。**统一用 `processAlive` / `findLiveByName`(已不认僵尸),不要自己 `kill(pid, 0)`。**
4. 有意的重启撞上崩溃保护的冷却。**主动重启前用 `m4ResetCooldown`。**
5. 模式在每次写盘时查文件,中途改开关就出现两个写者。**模式在启动时定死。**
6. 停一个组件不等它的后台 goroutine,停了以后它还在写文件。**停的时候等它们结束。**
7. 测试读写真实的 `/data/local/hnc`、改仓库里的文件、模拟场景根本没经过被测代码(检查恒为真)。见第 3 节。

### 1.4 T1 / T2 涉及的代码

- **启动指纹起名**:`daemon/hnc_httpd/api_discover_suggest.go` 约 244 行 `strList(g["domains"])`。组的 `domains` 是对象数组(`[{"name": "…", …}]`,参照同文件 / `api_discover.go` 的 `firstHost`),`strList` 只认字符串数组,结果永远为空 —— 启动指纹从 v5.28 起一次都没参与起名。
- **设备合并**:`daemon/hnc_httpd/mac_merge_action.go` 的 `deviceMerge` 把旧 MAC 的设置迁到新 MAC,漏了 v5.30 新增的每设备字段 `app_qos`。
- **扫描计数**:`bin/device_detect.sh` 约 166 行 `awk '/"mac"/{n++}'` 按**行**数 —— `devices.json` 是一行,所以永远报 1 台。
- **gofmt**:`src/dpid/cmd/dpid_replay/replay_test.go` 末尾多一个空行(v5.29 遗留)。
- **C 版重扫报回旧 IP**:`daemon/hotspotd/hotspotd.c` 的 `scan_arp` 逐行读 `/proc/net/arp`,同一个 MAC 的每一行都覆盖 `d->ip` —— 最后一行赢。设备换 IP 后旧表项以 STALE 留在邻居表里几分钟,这期间的全量扫描(hotspotd 启动、`SIGUSR1` / `REFRESH`,即 WebUI 点「刷新」触发的 `device_detect.sh scan`)可能把它报回旧 IP。`/proc/net/arp` 不带时间,分不出新旧。复现:把 `test/sim/run_m4_sim_v531.sh` 场景 2 第 3 步里的 `$SIM poke pad` 去掉,hotspotd 那边就会报回 `.102`。Go 版已用 netlink dump 的 `NDA_CACHEINFO`(多久前确认可达)挑最近确认的 IP(`src/dpid/neigh` 的 `ConfirmedAgo`,`src/dpid/devscan` 的 `pickIP`)。

---

## 2. 边界(硬约束)

1. 隐私与安全红线照旧:不做中间人解密,不注入 / hook 任何设备,不新增采集内容。
2. **不改 `m4OwnerDefault` 的值**(仍是 `go`);**不删代码**(shell guard、Go supervisor、hotspotd 的发现代码都留着),除非是 T1 / T2 修 bug 本身要删的几行。
3. 不加新功能;方案 B(hotspotd 彻底退役、动硬件加速兜底)不碰。
4. hotspotd(C)只改 T2 涉及的发现路径(`scan_arp` 及其直接调用的函数);硬件加速兜底(`scheduler.c` / `upstream.c` / `offload/` / `OFFLOAD_*`)不动。
5. API 兼容、持久化格式只增不改;不加第三方依赖;不改两个 `go.mod` 的 `go` 版本;`CGO_ENABLED=0`。
6. `service.sh` / `post-fs-data.sh` 本版不需要改;要改先停下说明。

---

## 3. 测试纪律

原样沿用 `docs/WORK-v5.30.md` §3 的 9 条和 `docs/WORK-v5.31.md` §3 的第 10、11 条,再加两条(都来自 v5.31 审查):

12. **模拟设备场景必须真的经过被测代码。** v5.31 的「运行中切换」场景是脚本自己停起 hotspotd,完全没经过看门狗的切换代码,对「Go 写者已停写」的检查恒为真。每个新场景在提交说明里写一条「把实现去掉 / 还原后这个场景失败」的证据。
13. **测试不许改仓库里的文件、不许读写真实的 `/data/local/hnc`。** v5.31 的厂商表同步测试不同步时会重写库内数据文件(把问题「修好」了);看门狗测试曾读写真实路径。生成物写临时目录;路径变量在测试结束时恢复(参照 `m4TestEnv`、`withTempM4Owner`)。

---

## 4. 任务

### T0 · 记录基线
跑第 6 节全部自检(含 `HNC_SIM=1 sh test/run_all.sh`,跑不了就写明),结果写进提交说明(空提交)。维护者环境基线:`sh test/run_all.sh` → `ALL PASS: 541/544 (3 skipped)`;`HNC_SIM=1` → `543/544 (1 skipped)`。

### T1 · 已知小 bug 收口
1. **启动指纹起名**:从组的 `domains` 对象数组里正确取出域名(`name` 字段)。测试:构造一个与某个可用应用的特征 token 重合 ≥ 2 的组,旧代码下建议名里没有 `startup` 来源、新代码下有。顺手核对同文件里其它读 `g["domains"]` 的地方有没有同样问题。
2. **设备合并迁 `app_qos`**:随其它设置一起迁。测试:旧 MAC 开着 → 合并后新 MAC 也开着(旧代码下失败)。再逐个核对 v5.29 以后新增的每设备字段(看 `rules.json` 的设备对象都有哪些键)有没有同样漏迁,有就一起补、各配测试。
3. **扫描计数**:`device_detect.sh` 改成按 `"mac":"` 出现次数数(与 hotspotd `count_devices_in_file_at` 同口径)。测试:一行里 3 台设备的 `devices.json` → 报 3(旧代码报 1)。
4. **gofmt**:`gofmt -w src/dpid/cmd/dpid_replay/replay_test.go`。

### T2 · C 版重扫报回旧 IP
- 目标:hotspotd 在全量扫描(启动、`SIGUSR1` / `REFRESH`)时,同一个 MAC 有多条有效表项,选**内核最近确认可达**的那条;已知设备的 IP 只在新候选比当前 IP 更近确认时才改。netlink 事件路径的行为不变。
- 建议做法:全量扫描改用 netlink `RTM_GETNEIGH` dump(带 `NDA_CACHEINFO`,`struct nda_cacheinfo` 的 `ndm_confirmed` 是距今的 clock_t),解析可参照 `src/dpid/neigh/neigh.go`;读不了 netlink 时退回现在的 `/proc/net/arp`。其它做法也行,写清楚。
- 测试:
  - C 单测(照 `daemon/hotspotd/test/test_no_discovery.c` + `test/unit/test_v531_no_discovery_c.sh` 的样子接进 `run_all`):同一 MAC 两条候选、不同确认时间,两种顺序都挑新的;旧代码下失败。
  - 模拟设备:新场景(C 模式)—— 设备换 IP 后,不发包、直接 `SIGUSR1` 让 hotspotd 重扫,以及重启 hotspotd,各重复几次(旧行为看顺序,要多试),每次都得新 IP。脚本可以加进 `run_m4_sim_v531.sh` 或新建 `run_m4_sim_v532.sh`(新建的话照 `test_v531_sim_owner.sh` 接进 `run_all`)。
- C 改动至少本机 gcc 完整编译通过;有 NDK 时按 `.github/workflows/build.yml` 交叉编译,没有就在提交说明写明(审查时 Claude 用 NDK 编)。

### T3 · 退路演练(不改默认值)
- 目标:证明「正式版把 `m4OwnerDefault` 改成 `c`」这一步改了就能用 —— 包括从 v5.31 升级上来的手机(`run/m4_owner.current` 里还留着上次会话的 `go`,开机时 `device_detect.sh` 会按它以 `--no-discovery` 拉起 hotspotd)。
- 做法:让默认值在测试里可替换,但生产代码里仍只写在一处(例如保留常量,另加一个只在测试里覆盖的包级变量读它;怎么做写清楚)。
- 测试:
  - 单测:默认值换成 `c`、没有 `data/m4_owner` 文件时,owner 是 `c`、hotspotd 被纠正为做发现、Go 写者不起。
  - 模拟设备(在 `TestM4SimOwner` 旁边新增,用看门狗真实的切换管理器):没有 `data/m4_owner`、`run/m4_owner.current=go`、hotspotd 以 `--no-discovery` 跑 → 默认值换成 `c` 后一轮之内 hotspotd 恢复发现、写出全部设备;再把默认值换回 `go` → 切到 Go 版。写日志确认写者不交错(照 `TestM4SimOwner` 第 5 步)。

### T4 · 省电小项(可选,前面都做完再做)
- 现状:Go 写者的主循环固定每 200 ms 醒一次(热点开着时)。hotspotd 的做法是「有待写的变化时 200 ms,否则 5 秒」。
- 目标:有待写变化或有待解析的名字时 200 ms,否则 1 秒;`REFRESH` / `SIGUSR1`(touch `run/devices.refresh`)仍要在 1 秒内反映到 `devices.json`(`device_detect.sh scan` 的判断依赖它)。
- 测试:空闲时一段时间内主循环醒来次数的上限(注入计数,不靠 sleep 精确计时);`TestRefreshTriggersFullSync` 照样通过。

### T5 · 文档
- `README.md`:功能清单与当前一致;安装 / 升级 / 回退说明(v5.29 的自动回滚、`data/m4_owner`)。
- `docs/ROADMAP.md`:v5.32 行标 rc1 ✅;正式版之后的小版本:真机结论出来后决定删哪些旧代码(shell guard / Go supervisor / hotspotd 发现代码)、方案 B。
- `docs/CODEMAP.md` / `docs/API.md`:与代码一致。
- 正式版说明草稿:在 `CHANGELOG.md` 末尾写一段「5.x 正式版(草稿)」—— 相对上一个正式版(5.18 及以前)用户能感知到的全部变化、怎么退回;正式发版时由 Claude 挪到正式版小节。

### T-last · 版本
- `module.prop`:`version=v5.32.0-rc1`,`versionCode=5320001`。
- `CHANGELOG.md` 加 `## [5.32.0-rc1] - <日期>`;`webroot/changelog.html` 加大白话一段。

---

## 5. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 改 `m4OwnerDefault` 的值 | 要靠真机结论(WORK-v5.31 §8),本版没有 |
| 删 shell guard / Go supervisor / hotspotd 的发现代码 | 同上;留到正式版之后 |
| 方案 B(hotspotd 退役、动硬件加速兜底) | 出错表现是「限速悄悄不生效」,不进正式版 |
| 新功能(QoE 闭环、场景模式、上行 / IPv6 的应用 QoS …) | 收尾版不加 |
| 发正式版(去掉 `-rc`) | 维护者真机回归后由 Claude 做 |

---

## 6. 自检命令(每个任务完成后都跑,全部通过才提交)

沿用 `docs/WORK-v5.31.md` §6 的全部命令(含本机 gcc 编 hotspotd、`HNC_SIM=1 sh test/run_all.sh`)。改了 `bin/*.sh` 的跑 `sh -n` 与 `sh bin/pitfall_lint.sh`。

---

## 7. 验收清单

- [ ] T1 四条各有测试(第 4 条除外),在旧代码下失败。
- [ ] T2:C 单测 + 模拟设备场景,旧代码下失败;C 本机完整编译通过。
- [ ] T3:单测 + 模拟设备场景(真实切换管理器),写者不交错。
- [ ] T4(做了的话):空闲醒来次数测试;refresh 测试照过。
- [ ] 第 3 节逐条自查(含新加的 12、13 两条);第 6 节全部通过,`run_all.sh` 不比 T0 基线差;gofmt 干净(含 `replay_test.go`)。
- [ ] 版本号、CHANGELOG、changelog.html、README、ROADMAP、CODEMAP、API.md 已更新。

**维护者真机回归(正式版前,不是你的任务)**:全功能过一遍 —— 设备列表 / 改名 / 限速 / 封锁 / 延迟模拟 / 配额 / 分时段 / 应用限速 / 按应用分优先级 / DPI 统计 / 新发现的应用 / 自检 / 导出诊断包 / 升级与回滚;`data/m4_owner` 来回切。按 WORK-v5.31 §8 判断默认值用 Go 版还是 C 版。

---

## 8. 提交方式

- 从基线新建分支 `ai/v5.32`,先记下 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,中文提交信息:`v5.32 T1: ...`。署名用你自己的模型名。
- 没有推送权限:`git format-patch $BASE..ai/v5.32 -o patches/`,README 写上 `$BASE` 和第 6 节命令的**实际输出**;有推送权限:推到 `ai/v5.32`,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 9. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
- T2 的 netlink 做法在 C 里太重:可以先只做「已知设备全量扫描时不把 IP 改成更旧的」(需要别的判断新旧的依据,写清楚),并在提交说明里说明还剩什么。
