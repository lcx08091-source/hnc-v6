# HNC 代码审查 v2 报告(v5.9.1 随附)

> 方法:6 维度并行审查(Shell/Go-httpd/Go-dpid/C-hotspotd/前端/横切)→ 每条 P1/P2 发现由独立 agent 做对抗性交叉验证(以"反驳"为目标)→ 汇总去重。
> 共 31 个审查子任务;确认存活 21 项、P3 共 11 项、误报否决 2 项、降级 5 项。
> 状态:文中标注【已修】的项已随 v5.9.1 落地;其余按用户决策只记录、下轮排期。

# HNC v5.9.0 六维度审查汇总报告(对抗性交叉验证后)

**总量**:确认存活 21 项(其中 5 项经交叉验证降级)、低优先 P3 共 11 项、误报否决 2 项。
**重要状态说明**:审查进行期间,4 项最高危问题已在当前分支落地修复——SH-1/SH-3(commit `a6f8fac`)、HTTPD-1(commit `2240d66`)、流量图假页签(`webroot/index.html` 工作区改动,**尚未提交**)。⚠️ 按 CLAUDE.md 纪律,`module.prop` 仍是 v5.9.0、CHANGELOG 无 v5.9.1 条目、webroot 改动未 commit,**收尾时需补 v5.9.1 三件套 + `node --check` + 提交**。

---

## ① 高价值确认问题清单(按严重度排序)

### P1(3 项已修,2 项待办)

**P1-1【已修 a6f8fac】tc_action_lock 续租/释放不验属主**
- 位置:`bin/tc_manager.sh:2255`(SH-1)
- 问题:`tc_action_lock_renew` 只判目录存在即覆写 owner,`tc_action_unlock` 无条件 `rm -rf`。合法回收场景(持有者活着但 90s 未续租,tc 卡内核)下,旧持有者醒来会偷回新持有者的锁或删掉任意人的锁——重新制造 536611f 声称修掉的"两个 TC 写者并发"。
- 现状:已修复并验证(renew/unlock 校验 owner 第 1 字段 == `$$`,restore 检查 renew rc 失败即 return 12,watchdog 对 rc=12 特判不入熔断)。修复质量比原建议更完善。

**P1-2【已修 2240d66】consumeTokenRevokeRequests 无互斥,撤销请求可被整文件误删**
- 位置:`daemon/hnc_httpd/server.go:1121`(HTTPD-1)
- 问题:三个并发入口(启动/每请求 middleware/60s poll)无锁执行 stat→rename→apply→Remove,`os.Rename` 覆盖语义 + 按路径 Remove 交错时,新 rename 出的 `.working` 可未读先删——撤销行(含 `ALL`)静默永久丢失,token 继续有效。v5.9.0 单写者化新引入的安全性回归。
- 现状:已加 `revokeMu` 串行化(server.go:61)。

**P1-3【待办】每个已鉴权远程请求做一次完整 bcrypt(arm64 200-300ms)**
- 位置:`daemon/hnc_httpd/auth.go:129`(HTTPD-2)
- 影响:远程 SPA 场景 SSE 每次 changed 触发多请求各付一次 bcrypt,手机 SoC 上 UI 刷新被串行叠加 +400-600ms、发热耗电,多标签线性放大。对内存中已验证过的 secret 重复付费无安全收益。
- 修复:TokensStore 加已验证缓存(首次 bcrypt 成功后存 `{bcryptHash, secretSHA256}`,后续 `subtle.ConstantTimeCompare`,Revoked/过期检查顺序不变,hash 变更回退 bcrypt)。交叉验证确认方案无投毒面、撤销即时性不变。
- 工作量:约 50 行 Go + 测试,半天。

**P1-4【待办】APPS 页每 5s 全量 innerHTML 重建**
- 位置:`webroot/index.html:12896`(FE-1)
- 影响:每 5 秒重建最多 150 张 blur(16px) 玻璃卡并重放入场动画(周期性整列表闪烁);正确性问题:用户展开的系统应用列表每 5s 被强制收起(L12893 硬编码 `display:none`)、candidate 的 promote/拒绝按钮会在手指落下前被替换。设备页已有完整的签名比对 + 原位补丁纪律,APPS 页零沿用。
- 修复:签名短路(注意剔除 last_seen 等快变字段,且置于空态分支之后)+ 保存展开态 + 重渲染时 `animation:none`。
- 工作量:约 40 行,半天。

**P1-5【待办】DPI(最快 1s)/APPS(5s)/新鲜度(1s)定时器切后台不停,每 tick 都是 root fork**
- 位置:`webroot/index.html:6997`(FE-2)
- 影响:KSU WebView 下每次 apiGet = `ksu.exec(curl)` 真实 fork;dpid 挂掉时(unavail 恰是 1s 快轮询常态)用户按 Home 后每秒最多 3 次 root fork,持续耗电。项目已为设备页专门做 visibility 管理,不对称即缺陷。
- 修复:三个入口加 `if (document.hidden) return;` + visibilitychange 回前台按 active page 恢复;彻底方案落地上轮建议的 `managedInterval`。
- 工作量:最小改动 10 行内,1 小时。

### P2(维持原级,待办)

| # | 位置 | 问题与影响 | 修复 / 工作量 |
|---|---|---|---|
| SH-2 | `bin/hnc_lock.sh:175` | mac_lock 的 gate 等待分支从不回收陈旧 gate;主触发源是 httpd 10s 超时 SIGKILL apply_device_rule(gate 段内含 2 次可各阻塞 5s 的 json_set),trap 都接不住。陈旧 gate 后 WebUI clear/blacklist 每次白等 5s 退 11,其中 clear/bl_del 把 rc11 吞成 warn——**用户看到 ok 但 iptables 规则残留**(静默漂移);最坏窗口 ≤24h(watchdog 每日清理兜底)。另 L202 stale 检查 `-eq` 单轮可被 gate 分支吞掉 | gate 等待分支加节流回收 + `-eq` 改 `-ge`;同时收敛 gate 段内 json_set 或调大 httpd 对该脚本超时(trap 只是部分缓解)。~20 行,半天 |
| SH-3 | `bin/tc_manager.sh:2243` | 【已修 a6f8fac】陈旧回收 `rm -rf`+`mkdir` 非互斥,两个回收者可双持锁并发写 tc 树。已改 mv 原子抢占 + 坟场清理 | 已闭环 |
| C-1 | `daemon/hotspotd/scheduler.c:773` | EEMPTY 快速重试在 init/rebuild 路径漏调 `request_refresh`,worker 睡 60s——恰是注释自称"真机 100% 命中"的旗舰场景,v5.9.0 的"冷启 60s→5s"承诺在该路径未达标 | rebuild 块解锁后按 pending 快照补一次 request_refresh(与 notify L872 同构,无锁序风险)。~5 行,1 小时 |
| C-2 | `daemon/hotspotd/hnc_helpers.c:1251` | pipe 无 O_CLOEXEC,3 个并发 fork 线程互相泄漏写端,EOF 拖到 select 超时上限(500ms~3s 主循环毛刺,长运行数天必偶发);try_mdns_resolve 读循环甚至无超时,更脆弱 | `pipe2(O_CLOEXEC)` ×3 + `accept4(SOCK_CLOEXEC)`。~10 行,1 小时 |
| C-3 | `daemon/hotspotd/hotspotd.c:1392` | mac 兜底设备每次 re-resolve 必 fork dumpsys 且同轮 N 次输出完全相同;REFRESH + 10 台未命名设备 = 主循环单次阻塞 350ms~5s,netlink/IPC 全停(上轮 P1-4 方向的低成本增量) | 函数内静态 5s TTL 缓存(单主线程调用,无线程安全问题)。~20 行,2 小时 |
| DPID-1 | `src/dpid/output/self_attrib.go:798` | getPkgCache 持 a.mu 每 5min 锁内 exec 无超时的 pm;pm 挂死则 self-attrib/flywheel 整体永久冻结——与 v5.9.0 刚为 hotspotd 修掉的同型问题(持锁调无超时子进程) | pm 调用挪锁外 + CommandContext 10s 超时 + `cmd.WaitDelay` 防管道继承。~15 行,2 小时 |
| FE-3 | `webroot/index.html:7721` | DPI 页每 1-4s 全量重建 6 个子面板 DOM(数百节点/tick),数据没变也重建;`__lastDPIStateRaw` 已缓存却不用于短路 | 分段签名短路,但**须修正原方案**:'active' filter 依赖墙钟,不能纯签名短路(否则空闲设备永不掉出活跃视图),签名需含 l3_enabled/dfp 字段。~20 行,半天 |
| XC-1 | `.github/workflows/build.yml:102` | tag 直推发版路径零校验:dispatch 四重护栏一条不覆盖,人工推 tag v5.9.1 到 v5.9.0 的 commit 仍产出"Release v5.9.1 挂 v5_9_0.zip"——v5.8.9-portal 事故的口子只堵了一半 | elif 分支复用护栏 a+b(格式 + 等于 module.prop;c/d 照搬会恒败,勿搬)。~5 行,1 小时 |
| XC-2 | `.github/workflows/build.yml:396` | `ci_preflight --artifact` / artifact_sanity_check 完整存在且有单测,但 CI 打包后从不调用;漏包/错架构/嵌套 zip 这类发生过 9 次的事故形态在真正需要拦截的位置无门禁 | Package 后加一步 `sh bin/ci_preflight.sh --artifact "$OUT_ZIP"`;顺手实现上轮 0.3 的 build_info.json。1 小时 |
| XC-3 | `.github/workflows/build.yml:146` | 61 个 shell 单测(含本轮新增锁/tokens 用例)不进 CI;实跑确认 host 上 17 failed / 173 passed——v5.9.0 大量 shell 并发修复无任何 CI 回归保护。注:a6f8fac 已顺带减少 2 个基线失败 | 以 CI 环境实跑结果建 known_failures 基线,runner 只对新增失败 exit 1;逐步清零。1-2 天 |
| XC-4 | `bin/tc_manager.sh:2213` | 本轮最核心的三态锁零用例(而它 v5.9.0 后已实际出过 SH-1/SH-3 两个 P1,用例缺失有实证代价);CHANGELOG 声称的 run_cmd_timeout host 测试未提交;且 `tools/build.sh host sched_test` 当前**编不过**(v5.9.0 加依赖未同步 COMMON_SRCS)——"测试不进 CI 即腐烂"的现场标本 | 先修 tools/build.sh 链接;新增 test_tc_action_lock.sh(伪造 owner 文件三态断言);提交 run_cmd_timeout 测试;CI 加 host cc 步骤。1-2 天 |

### 经交叉验证降级(P2→M/P3,酌情排期)

- **SH-4** `tc_manager.sh:2118`:restore 主通道 set_all 失败不进最终 rc,watchdog 误记"修复成功"。**降级理由**:git 考古证实是 v5.7.0 起的存量而非 v5.9.0 回归,且修了也换不来重试(check_health 看不见 per-device 规则丢失);**原修复方案有害**——必须排除 rc=8/66/67(IFB 降级机型会恒 rc=1 误开熔断,恰是本机 realme 内核场景)。修订后再做。
- **SH-6** `watchdog.sh:1028`:直改 ifb0 绕锁(上轮已知 M8)。头号撞击场景被驳倒(init/restore 唯一调用方是 watchdog 自身单线程),"唯一绕锁写者"也不成立(apps_limits/cleanup 同样绕锁)。如做,注意锁 busy 不应计入 uplink_fail_count。
- **HTTPD-3** `tokens.go:137`:`>=` 双检导致 json_doctor `cp -p` 恢复永不被吸收 + 30s 被 Flush 反向覆盖,与代码注释的防御声明直接矛盾——但实际受损仅"进程存活期手动 restore 被静默打回"的小众场景;修复需配套 dirty 标志(否则空闲 Flush 仍抢先覆盖)。
- **DPID-2** `rule.go:281`:缓存命中路径仍每事件 ~35 次锁内 stat。量级被高估(cBPF 已在内核层过滤,稳态数十事件/秒),且属上轮路线图明确分期的已知遗留。方案 A(2s stat-TTL)~10 行,顺手可做。
- **FE-6** `index.html:9576`:switchPage 180ms 窗口连点抛 TypeError 属实,但"nav 与页面失同步"为假(高亮代码在抛点之后永远执行不到),实际后果仅吞一次点击后自愈。修复时注意 `old===next` 早退须放在 clearTimeout 之后。

### P3 摘要(11 项,合并列出)

- **hotspotd**:C-4 EEMPTY pending 三处成功路径不清零(空转烧 credit);C-5 null adapter 下 notify 白付 fork(开机批量恢复串行多付 0.4~10s,一行门卫可修);C-6 LSM status JSON 未转义 comm/fail_reason(prctl 可击穿 OFFLOAD_STATUS 整段 JSON,复用 hnc_json_escape)。
- **dpid**:DPID-3 缓存键对 rename 失明(文件名进键,~10 行);DPID-4 oversized WARN 逐事件刷屏 + 全灭时无负缓存(_auto_expanded.json 无上限,数月后可越 1MB);DPID-5 supervisor acquireLock 缺自 pid 保护(pid 回绕启动即 SIGKILL 自己,2 行短修 + 中期抽 daemonutil);DPID-6 classifyHost 每事件 ~1500 次重复归一化扫描(编译期后缀索引)。
- **httpd**:HTTPD-4 读放大(上轮已知 M5,拆锁后加快照缓存已无障碍,低风险高收益)。
- **frontend**:FE-5 非合成属性动画清单(alertPulse box-shadow 逐帧 repaint 在 blur 玻璃层上、指示器 width 过渡、transition:all ×3)。
- **crosscut**:XC-5 ls-remote 失败被当"tag 不存在"放行(改三分支 fail-closed);XC-6 文档漂移(CLAUDE.md 旧分支名/过时触发器描述、ARCHITECTURE.md 版本注入从未接线)。

---

## ② 被交叉验证否决的代表性误报(体现交叉审查价值)

1. **「撞锁即退 12 无重试,v5.9.0 长持锁拉长用户可见失败窗口」(shell)**——被**锁次序证据**直接否定:restore 全程同时持 gate 锁,而 set_limit 在到达 tc 锁之前就必须先抢同一把 gate,5s 失败于 gate 处、根本收不到 rc12,报告的"回滚 mark"链条不可达;新旧版本此场景用户可见行为完全相同,"回归"归因错误,且 v5.9.0 的 gate 传递实际**缩短**了 restore 时长。审查者只看了 tc 锁一层,没有追完整调用链的锁嵌套次序。
2. **「renderHistPie 单 app 100% 时整张饼图消失」(frontend)**——前端代码形态属实,但**端到端不可达**:数据唯一写者 dpid HistorySampler 明确 `if dTx==0 && dRx==0 { continue }`,每条落盘行 ≥1 字节,多条目时最大段 frac 严格 <1。审查者孤立读了 reader,未核写入端约束;其建议的修复②反会把真实的 0.05% 小段画没——**误报的修复本身会引入新 bug**,这正是交叉验证要拦的。

此外 5 项 P2 被降级的共同模式:影响链后半段夸大(SH-4 的"修了就有重试"、FE-6 的"导航失同步")或把存量债误标为 v5.9.0 回归——交叉验证把"该修"与"该现在修"分开了。

---

## ③ 流量图 bug 结论

**根因确诊:统计页 24h/7d/30d 是假页签。** 旧代码 `renderBars` 硬编码 `range:'today'`,页签点击只切换高亮、不改请求参数,故三个页签永远显示同一份今日数据。后端 `/api/stats` 本就支持 `today|week|month|all`(daily 数据保留 90 天),纯前端 bug。

**已在工作区修复**(`webroot/index.html`,带 v5.9.1 注释,**未提交**):引入 `statsRange` 状态,页签点击真正切 range 并重拉;流量明细表复用 `renderBars` 已取到的 buckets 不发第二次请求;顺带修了 shadow 源未开启时选中恒空图无解释的问题(据 `/api/config.stats_shadow_enabled` 禁用 option 并强制回退 legacy)。**收尾动作:`node --check` 校验后与版本三件套一并提交为 v5.9.1。**

---

## ④ 总体评价与优先级建议

**v5.9.0 改动质量:良好,方向全部正确,但两处新机制自带 P1 级实现缺口。** 分维度:hotspotd 最佳(probe/apply 拆分锁序正确、run_cmd_timeout 边界正确、LSM 清理无遗漏,仅剩 EEMPTY 唤醒漏一处);dpid 两项修复无回归;httpd 拆锁与单写者化前提(tmp+rename 原子发布)经核实成立,但 marker 消费协议漏了互斥(P1,已修);shell 三个声明目标达成,但新锁体系漏了属主追踪(P1,已修)。**模式教训**:两个 P1 都是"新并发协议设计对、实现漏了一个不变量",而 XC-4 证明这类逻辑当时零测试——三态锁上线即出两个 P1 是用例缺失的直接代价。前端呈两极:设备页纪律优秀,后加的 APPS/DPI 面板完全未沿用同一套纪律。

**剩余债务优先级建议**:

1. **立即(随 v5.9.1 收尾)**:提交流量图修复 + 版本三件套;XC-1/XC-2/C-1/C-2 四个 1 小时级小修可一并带上——发版护栏和 hotspotd 两处是纯增益零风险。
2. **短期(下个迭代)**:HTTPD-2 bcrypt 缓存(用户可感知的最大性能项)、FE-1/FE-2(可感知闪烁 + 后台耗电)、SH-2(静默状态漂移)、DPID-1(冻结风险,同型问题刚在 C 侧付过学费)、C-3、FE-3。
3. **基建(值得专门排期)**:XC-3 + XC-4 一起做——shell 测试进 CI + 三态锁/run_cmd_timeout 补用例 + 修 tools/build.sh。本轮两个 P1 回归证明这是当前回报率最高的投入,应优先于任何新功能。
4. **降级与 P3 项**:SH-4 按修订方案(排除 rc=8/66/67)择机做;DPID-2 方案 A、HTTPD-4 快照缓存、C-5/C-6 均为 ≤半天的顺手项,可捎带;SH-6/FE-6/HTTPD-3 与其余 P3 放入 backlog,不阻塞发版。
