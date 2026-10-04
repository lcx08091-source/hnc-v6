# 工作文档:HNC v5.28.0-rc1「防线 + DPI 自学习」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」是硬约束。
> 背景:`docs/CODEMAP.md`(代码地图 + 权威实现表)、`docs/ROADMAP.md`(§A 计划表、§B 迁移清单)、`docs/WORK-v5.27.md` §1.2(DPI 数据流图,本文不再重复)、`CHANGELOG.md` 的 5.25.0-rc1 ~ 5.27.0-rc1。
> 基线:分支 `claude/environment-config-ydr2ow` 最新提交(v5.27.0-rc1 + 本文档)。

---

## 0. 这一版做什么

**A 部分 · 防线**(先做):把最近几次真机事故的教训变成**自动拦截**,而不是靠人眼发现。
- v5.27 真机:热点空转 1 小时 watchdog 约 530 CPU 秒 —— Go 看门狗每轮都调能力探测(已在 v5.27 用 shell 节流止血)。
- v5.26:`action tc_uplink_healthy` 一直 exit 127,Go 侧不看返回码,几个版本没人发现。
- v5.8.8 后的进程风暴、v5.25 的「看门狗未运行」误报:都是 shell 里靠 `ps` / `grep` 判断进程,Android toybox 输出格式不同。

**B 部分 · DPI 自学习**(影子运行):路线图原 v5.28 的内容。注意 **「共现聚类发现新应用」v5.15 已经做了**(`src/dpid/output/discover.go` + `daemon/hnc_httpd/api_discover.go`,设置 →「新发现的应用」),本版不重做,而是**给它量化准确率、自动起名**;另做**轻量分类器**和**交互节拍**。

---

## 1. 项目基本情况(必读)

沿用 `docs/WORK-v5.27.md` §1(两个 Go 模块、`go 1.22` / `1.25.0`、`CGO_ENABLED=0`、Android 坑、DPI 数据流、规则库、前端约定),此处只补本版相关的:

- **Go 看门狗**(`src/dpid/cmd/hnc_watchdog/`,真机实际运行):`main.go` 的 `mainLoop()` 每轮先 `hsSched.runIfDue`,再按状态 `handlePending` / `handleActive`,再做进程保活。热点开着(ACTIVE)且健康时 60 秒一轮,`handleActive` 每轮调用:`probe_hotspot`、`capability_probe`、`check_health`、`runV6Sync()`、(到点)`runStatsSample()`、`sampleOnlineHours`、`httpd_drift`、`tc_uplink_healthy`。每个 `runAction(name)` = fork 一次 `sh bin/watchdog.sh action <name>`(851 行脚本 + 动作内部的 tc / iptables 命令)。
- `runAction`(`main.go` 约 236 行)返回 `actionResult{exitCode, stdout, err}`,**调用方大多 `_ =` 丢掉**。
- `service.sh` 末尾的**哨兵循环**(约 1060 行起,每 30 秒):保 dpid launcher 与 hnc_watchdog。判断进程是否活着用的是 `process_by_name_alive`(约 168 行,`pidof` + `ps -ef | awk`)和 `list_watchdog_pids`。
- 功耗统计:httpd `power_stats.go`(`/api/power`,自检「功耗」行);自检进程段 `selfcheck.go` 的 `scSectionProcess`。
- **流形态**:`daemon/hnc_httpd/flow_shape.go`(按 conntrack 字节 / 包计数的时间形状手工判 9 类:video_stream / live_stream / download / upload / gaming / video_call / voice_call / browsing / background)。
- **未知应用发现**:dpid `output/discover.go`(同设备 5 秒窗口共现的未识别可注册域 → 并查集聚组,输出 `run/dpi_discover.json`);httpd `api_discover.go`(展示 + 证书线索 + `run/apk_domains.json` 本机安装包域名线索 + 用户确认写 99-user-custom)。

---

## 2. 边界(硬约束)

1. **隐私与安全红线**:不做 TLS 中间人解密,不向任何设备注入 / hook,不新增采集内容(只用现有元数据:SNI、JA4、QUIC 参数、conntrack 字节 / 包计数、时间)。
2. **B 部分全部影子运行**:分类器、交互节拍、自动起名**不得改变**任何连接的应用归属、按应用限速、应用限时、类别封锁、tc / iptables;只能新增字段、新增接口、进识别自评。「新发现的应用」仍需用户点确认才写规则。
3. **A 部分不改 tc / iptables / 限速规则的内容**;允许改的是「多久检查一次」和「怎么判断进程活着」,且每项改动都要在提交说明写清最坏情况下的影响(例如上行限速丢失最长多久才被发现)。
4. API 兼容:现有字段一个不能少、含义不能变(可以加字段)。持久化格式只增不改。
5. 省电:不新增常驻循环;重活(训练、离线评估)最多 30 分钟一次,且尊重 `run/activity.json` 的档位(热点未开时不做客户端相关的计算)。
6. 不改 CI、`customize.sh`;`service.sh` 只许改 A3 指明的哨兵相关函数;`post-fs-data.sh` 不改。不加第三方依赖,不改两个 `go.mod` 的 `go` 版本。
7. 不许通过删除或跳过测试让测试变绿。**每个修复 / 节流都要配一个「在改动前的代码上会失败」的测试**,并在提交说明里写明怎么验证过它会失败。shell 测试**必须测行为**,不许只 `grep` 源码里有没有某段文字(v5.26 有测试把 bug 本身锁进了 grep 断言)。
8. 第 4 节「不做」清单里的东西一律不碰。

---

## 3. 任务(按顺序做,每个任务一个提交)

### T0 · 记录基线
跑第 5 节全部自检命令,结果写进提交说明(空提交)。维护者环境基线:`test/run_all.sh` → `ALL PASS: 462/463 (1 skipped)`。

---

## A 部分 · 防线

### A1 · 看门狗调用预算(热点空转耗电的根治 + 回归测试)

**做法:**
1. **可测试化**:`runAction` 改成包级变量 `var runActionFn = runAction`(或等价方式),`handleActive` / `handlePending` / `runV6Sync` / `runStatsSample` / `runScript` 里的外部调用都经由可替换的函数;时间统一取 `nowFn()`(默认 `time.Now`)。不改变生产行为。
2. **能力探测的节流搬到 Go 侧**(v5.27 在 shell 里已有 6 小时节流,保留作双保险):`handleActive` 只在「本进程启动后还没探测过」「网卡变了」「距上次 ≥ 6 小时」时才调 `capability_probe`。
3. **健康时放宽两个附带检查**:`httpd_drift` 每 5 分钟一次、`tc_uplink_healthy` 每 3 分钟一次(原来每轮 60 秒)。规则不健康 / 刚恢复(`recoveryRounds > 0`)时照旧每轮。提交说明写清:上行 ingress 重定向丢失时最长约 3 分钟被发现(原 1 分钟)。
4. **预算测试** `src/dpid/cmd/hnc_watchdog/budget_test.go`:用假的 `runActionFn` 计数、假时钟,模拟以下场景各 60 分钟,断言每种动作的调用次数不超过预算表:

   | 场景 | 预算(次 / 小时) |
   |---|---|
   | ACTIVE、规则健康、无在线设备、亮屏 | `probe_hotspot` ≤ 60;`check_health` ≤ 60;`capability_probe` ≤ 1;`httpd_drift` ≤ 12;`tc_uplink_healthy` ≤ 20;`v6_sync.sh` ≤ 60;`stats_sample.sh` ≤ 4;`full_restore` = 0;`full_init` = 0;`is_doze` = 0;`prune_dup_hotspotd` ≤ 6;所有外部进程合计 ≤ 300 |
   | ACTIVE、网卡在第 30 分钟从 wlan2 变成 ap0 | `migrate` = 1;`capability_probe` ≤ 2 |
   | ACTIVE、`check_health` 一直返回 1(规则丢了) | `full_restore` 受 `restoreThrottle` 限制(按现有窗口规则算出上限并断言) |
   | PENDING(热点未开)、activity 显示 hotspot_off | 外部进程合计 ≤ 40(120 秒兜底探测 + 偶发) |

   预算表放在测试文件顶部常量里,注释写明每个数字的来源。**用 v5.27 之前的 Go 代码(每轮调 capability_probe)跑这个测试必须失败**——在提交说明里写出你怎么验证的。
5. `power_sched.go` 的 `watchdog_active` 说明文字同步(健康时附带检查的新节拍)。

### A2 · 动作失败不再被吞掉 + 每个动作的开销可见

**做法:**
1. `runAction` 统一记账(在 `runActionFn` 的默认实现里):每个动作名累计 `calls`、`fails`、`last_rc`、`last_fail_at`、`total_ms`、`max_ms`,按小时桶保留 24 小时。
   - **「失败」的定义**按动作区分,写成一张表:`check_health` 的 1 / 2、`is_doze` 的 1、`probe_hotspot` 在热点没开时的非 0 都是**正常结果**,不算失败;**任何动作的 126 / 127(找不到命令 / 函数)、超时(rc = -1)、64(未知动作)一律算失败**。
2. 每分钟(随现有落盘节奏,不新开循环)原子写 `run/watchdog_actions.json`:`{schema:1, generated_at, actions:{name:{calls_1h, fails_1h, last_rc, last_fail_at, avg_ms, max_ms}}}`。
3. httpd:
   - `/api/power` 增加 `watchdog_actions` 段(原样转出,文件不新鲜 > 3 分钟标 `stale:true`);
   - 自检「进程与资源」新增一行「看门狗动作」:有任何动作 1 小时内出现 126 / 127 / 超时 → **警告**并列出动作名;外部进程合计 > 400 次 / 小时 → **警告**「看门狗调用偏多」;否则正常,显示「N 次 / 小时 · 平均 x 毫秒」。
   - 前端:自检该行正常渲染即可;功耗详情里加一张小表(动作名、次 / 小时、平均耗时、失败数),按次数降序。
4. 测试:失败分类表(每个动作的正常码 / 失败码);小时桶滚动;文件格式;自检在「有 127」「调用过多」「全正常」三种输入下的输出;**用一个故意返回 127 的假动作,断言自检显示警告**(这正是 v5.26 那个 bug 的场景)。

### A3 · 哨兵不再用 `ps` 判断进程

**问题**:`service.sh` 哨兵用 `pidof` + `ps -ef | awk` 判断 watchdog / launcher 是否活着。v5.8.8 之后的进程风暴就是因为 ColorOS 的 `ps` 不显示完整路径,哨兵误判「watchdog 死了」每 30 秒多拉一个。`watchdogfix-v6.1` 修了匹配方式,但仍依赖 `ps` 的输出格式。

**做法:**
1. `service.sh` 里新增一个函数 `pid_matches <pid> <关键字>`:`/proc/<pid>/cmdline`(把 NUL 换成空格)里**某个参数恰好是关键字、或以 `/关键字` 结尾**才算(与 Go `findLiveByCmdlineSub` 同口径),纯 shell 内建 + `tr`,不用 `ps`。
2. `find_live_watchdog_pid`、`launcher_alive_count`、`dpid_alive`:**先查 pidfile**(`run/watchdog.pid`、`run/dpid_guard.pid`、`run/dpid.pid` 等现有文件)并用 `pid_matches` 校验;pidfile 失效时才退回现有 `pidof` / `ps` 逻辑(保留为兜底,不删)。
3. 读 `/proc` 的根目录可用环境变量覆盖(`HNC_PROC_ROOT`,默认 `/proc`),**只为测试**。
4. 测试 `test/unit/test_sentinel_proc.sh`:用临时目录造假 `/proc/<pid>/cmdline`,并把 `ps` mock 成「只显示短名字、没有完整路径、PPID 不是 1」(就是当年 ColorOS 的样子):
   - watchdog 活着(pidfile + cmdline 对得上)→ 判活,**不重复拉起**;
   - pidfile 指向的 pid 被复用成别的进程 → 判死;
   - pidfile 缺失 → 走兜底逻辑。
   这些函数要能被测试单独调用:把它们挪到一个可被 `.` 引入的小文件 `bin/hnc_proc.sh`,`service.sh` 引入它(照抄现有 `.` 引入写法与 PATH 加固)。

### A4 · 老坑自动检查(pitfall lint)

**做法:**
1. 新脚本 `bin/pitfall_lint.sh`(纯 shell,在仓库根目录跑,`bin/ci_preflight.sh` 里调用它,失败算 preflight 失败):
   - **P1 时区**:`src/dpid/cmd/*/main.go` 与 `daemon/hnc_httpd/main.go` 里凡是用到 `time.Now`(或按日期分文件)的 `main` 包,必须出现 `tzlocal.Location()`;
   - **P2 toybox grep**:`bin/*.sh`、`service.sh` 里不许出现 BRE 的 `\|`(要用 `grep -E 'a|b'`);
   - **P3 进程检测**:Go 代码(非测试)里不许新增 `exec.Command("pidof"` / `"ps"`;shell 里不许新增 `ps -ef | grep`;
   - **P4 告警写入**:`alert.Append` 之外不许直接 `OpenFile` 写 `alerts.jsonl`;
   - **P5 Tab**:检查已知含 Tab 语义的 sed 表达式(`json_escape` 里的 `s/<Tab>/ /g`)仍是真的 Tab。
2. **存量白名单**:现有代码里已经存在的命中(例如哨兵的兜底 `ps`)记到 `bin/pitfall_lint.allow`(一行一个 `文件:规则:原因`),**只拦新增的**。
3. 测试 `test/unit/test_pitfall_lint.sh`:在临时目录造违规文件,断言每条规则都能报出来;白名单生效;当前仓库跑一遍为 0 个新增违规。

---

## B 部分 · DPI 自学习(影子运行)

### B1 · 给「新发现的应用」量化准确率

**问题**:`discover.go` 的共现聚类(5 秒窗口、边权 ≥ 3、枢纽节点不合并)阈值是手调的,没人知道聚出来的组准不准。

**做法**:
1. 把 `discover.go` 的「建图 + 聚类」核心抽成可复用的纯函数(放在同一个包里,`Discoverer` 改为调用它,行为不变;用现有测试证明不变)。
2. httpd `dpi_eval.go` 新增 `discover` 段:把本机样本(`run/label_samples.*.jsonl`)当成一台设备的 SNI 序列,用同一个聚类函数跑一遍,**只看规则库认不出的域名**(与线上一致);真值 = 样本里的包名。指标:
   - **纯度**:每个组里占比最多的那个包名的比例(加权平均);
   - **完整度**:同一个包名的未知域名,被聚进同一个组的比例;
   - 组数、平均组大小、被判为「枢纽」丢掉的节点数。
3. 再用 3 组参数(当前值、更松、更紧)各跑一遍,结果并排给出,**只展示不自动改参数**(维护者看数据后再决定)。
4. 前端:识别自评加一块「新应用发现:纯度 x% · 完整度 y%(共 N 组)」。
5. 测试:合成样本(两个包各有一组专属域名 + 共享 SDK 域名)→ 纯度 / 完整度符合预期;枢纽节点被排除。

### B2 · 新发现的应用自动起名(建议,不自动确认)

**做法**:`api_discover.go` 给每个组算「建议名称 + 置信度 + 依据」,来源按可信度:
1. `run/apk_domains.json`(本机安装包里写死了这些域名)→ App 名;
2. T3(v5.27)启动指纹学到的应用,其特征 token 与组内域名重合 ≥ 2 个;
3. 证书组织名(现有证书线索);
4. 组内域名的可注册域本身(最弱)。
多个来源一致时置信度叠加;冲突时取最可信的并标「有分歧」。前端「新发现的应用」列表显示建议名与依据,**确认仍需用户点**,确认框里预填建议名。测试:各来源单独 / 叠加 / 冲突。

### B3 · 轻量分类器:按流量形状猜「应用类别」(影子运行)

**目标**:规则库认不出的连接,至少能猜出是「视频 / 游戏 / 通话 / 下载 / 浏览 / 音乐 / 社交」哪一类(AppScanner 思路的轻量版),并和现有手工规则 `flow_shape.go` 比一比谁准。

**做法**(新文件 `daemon/hnc_httpd/flow_cls.go`):
1. **训练样本(自监督)**:热点客户端上**规则库已认出应用**(非广告 / SDK / CDN 档)的连接,标签 = 该应用的类别(用规则库现有类别,合并成上述 7 个大类,映射表写在文件里);特征 = `flow_shape.go` 已经在算的窗口特征(上 / 下行速率、对称度、活跃占比、变异系数、峰值、平均包长、包速率)+ 协议 / 端口类 + ALPN + JA4 第一个字符(t / q)。**不用 SNI / 域名本身当特征**(否则模型只是在背规则)。
2. **模型**:多类逻辑回归(或分箱朴素贝叶斯),纯 Go 手写,不加依赖;特征标准化参数一起存;每 30 分钟用新样本增量训练一次(挂在 app_usage 每轮上做时间判断),样本池有上限(如每类 2000 条,按时间淘汰),模型存 `data/flow_cls.json`。
3. **预测**:只对「规则库认不出」的连接给出 `{cls_category, cls_conf}`,加到 `/api/connections` 每行(新字段)。**不改归属、不改显示的应用名**。
4. **评估**(`dpi_eval.go` 新增 `flow_cls` 段):按时间切分 —— 用今天之前的模型,在今天已认出应用的连接上预测类别(当它不知道答案),算准确率;同样的连接用 `flow_shape.go` 的手工判类映射到大类(video_stream → 视频、gaming → 游戏 …),两者并排对比。样本不足(每类 < 50)时只返回说明。
5. 前端:识别自评加一行「流量形状猜类别:准确 x%(手工规则 y%)」。
6. 测试:合成特征的可分数据 → 训练后准确率 > 90%;增量训练与样本池上限;模型文件往返;评估的时间切分不会用到「今天」的训练数据。

### B4 · 交互节拍:「人在用」还是「挂后台」(影子运行)

**做法**:在 `fg_model.go` 现有的每轮特征上,给每个(设备, 应用)算一个 `engagement`:
- `interactive`(人在操作):新建连接频繁 / 请求-响应突发多 / 上行零碎小包,且间隔不规则;
- `passive`(在看 / 在听,没在操作):下行持续、节奏规则、几乎没有新请求;
- `background`(后台):只有心跳级流量或大文件下载特征。
规则与阈值写在文件顶部常量里,注释说明依据。输出到 `/api/devices[].fg.engagement`(新字段)和前台时间线每段的占比统计。**本版没有真值**(本机前台真值只告诉「哪个 App 在前台」,不告诉「有没有在操作」),所以只做:单元测试锁行为 + 自评里显示三种状态的时长分布,供人工判断是否合理。

---

### T-last · 版本与文档
1. `module.prop`:`version=v5.28.0-rc1`,`versionCode=5280001`。
2. `CHANGELOG.md` 加 `## [5.28.0-rc1] - <日期>`:A 部分写清每道防线拦的是哪一次真实事故;B 部分写清「影子运行、能改变什么」。
3. `webroot/changelog.html` 加一段大白话。
4. `docs/ROADMAP.md` §A 的 v5.28 行标「rc1 ✅」;§B 迁移清单里 M1 标完成。
5. `docs/CODEMAP.md` 权威实现表加:看门狗动作记账 → `runActionFn`;进程判断(shell)→ `bin/hnc_proc.sh`;老坑检查 → `bin/pitfall_lint.sh`;流量形状分类器 → `flow_cls.go`。
6. `docs/API.md` 加「## 26. v5.28 变更」:`/api/power.watchdog_actions`、`run/watchdog_actions.json`、`/api/connections` 的 `cls_category` / `cls_conf`、`/api/devices[].fg.engagement`、`/api/dpi_eval` 的 `discover` / `flow_cls` 段、`/api/discover` 每组的建议名字段。

---

## 4. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 把 `check_health` / `probe_hotspot` 改成 Go 直接读内核(netlink) | 迁移清单 M2,放 v5.29(本版先把预算测试和记账做好,M2 才有对照) |
| 删除哨兵或 shell 守护脚本 | 迁移清单 M3 / M5,后续版本 |
| 用分类器结果改归属 / 限速 / 限时 | 先影子运行看准确率 |
| 自动调整 discover 聚类参数 | 先看 B1 的数据,由维护者决定 |
| 用户标注「我在用 / 没在用」做交互节拍真值 | 需要新的交互设计,以后再说 |
| SQLite、进程合并、新界面 | 6.0 / HNC X 方向 |

---

## 5. 自检命令(每个任务完成后都跑,全部通过才提交)

```sh
# Go
(cd daemon/hnc_httpd && gofmt -l $(git diff --name-only --diff-filter=AM HEAD~1 -- . | sed 's#daemon/hnc_httpd/##' | grep '\.go$') ; \
  go vet ./... && go test ./... \
  && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null . \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
(cd src/dpid && gofmt -l . ; go vet ./... && go test ./... && go test -race ./output/ ./cmd/hnc_watchdog/ \
  && for c in dpid hnc_watchdog dpid_supervisor; do CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /dev/null ./cmd/$c || exit 1; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go vet ./...)
rm -f daemon/hnc_httpd/hnc_httpd

# Python 工具
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/build_pkg_app_map.py --check
rm -rf tools/__pycache__

# shell
for f in $(git diff --name-only HEAD~1 -- '*.sh') service.sh bin/watchdog.sh; do [ -f "$f" ] && sh -n "$f" || echo "SYNTAX $f"; done
sh bin/pitfall_lint.sh          # A4 完成后
sh test/run_all.sh
sh bin/version_consistency_check.sh
sh bin/ci_preflight.sh

# 前端
for f in webroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done
```
注:`daemon/hnc_httpd` 里有几个旧文件在基线就不满足 gofmt,只要求你新增 / 修改的文件干净。

---

## 6. 验收清单

- [ ] A1:预算测试在 v5.27 之前的 Go 代码上失败、现在通过;健康时 `capability_probe` ≤ 1 次 / 小时,外部进程合计 ≤ 300 次 / 小时。
- [ ] A2:`run/watchdog_actions.json` 每分钟更新;故意返回 127 的动作会让自检报警;`/api/power` 有 `watchdog_actions`。
- [ ] A3:模拟「ps 只显示短名字」时哨兵不重复拉起 watchdog;pidfile 被复用时判死。
- [ ] A4:每条 lint 规则都有能触发它的测试;当前仓库 0 个新增违规。
- [ ] B1–B4:全部影子运行,没有改变任何归属 / 限速 / 限时;识别自评有 `discover`、`flow_cls`;`/api/devices[].fg.engagement` 有值。
- [ ] 每个修复 / 节流都有「改动前会失败」的测试,提交说明写了验证方法;shell 测试测的是行为,不是 grep 源码。
- [ ] 第 5 节全部命令通过,`run_all.sh` 不比 T0 基线差。
- [ ] 版本号、CHANGELOG、changelog.html、ROADMAP、CODEMAP、API.md 已更新。

---

## 7. 提交方式

- 从 `claude/environment-config-ydr2ow` 最新提交新建分支 `ai/v5.28`,先记下基线 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,提交信息中文:`v5.28 A1: 看门狗调用预算`。
- 提交署名用你自己的模型名(`git config user.name "<模型名>"`)。
- 没有推送权限的沙箱:`git format-patch $BASE..ai/v5.28 -o patches/` 导出,README 写上 `$BASE`。有推送权限的会话:推到 `ai/v5.28` 分支,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 8. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
- 依赖:A2 依赖 A1 的 `runActionFn`;B2 用到 v5.27 的启动指纹(没有学到时该来源为空,照常工作)。
- 时间不够时的优先级:**A1 > A2 > A3 > A4 > B1 > B3 > B2 > B4**。
