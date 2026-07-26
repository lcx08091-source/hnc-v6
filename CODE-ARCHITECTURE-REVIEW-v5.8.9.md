# HNC 代码架构审查报告(v5.8.8 仓库 + v5.8.9-portal-0.1.4 发布包)

> 审查日期:2026-07-26
> 审查对象:仓库 `hnc-v6` 分支 `claude/code-architecture-review-ejb05l`(HEAD `0e6f45b`,module.prop v5.8.8)
> 对照物:发布刷机包 `HNCv5_8_9portal0_1_4arm64bugfix.zip`(module.prop v5.8.9-portal-0.1.4)
> 审查方式:5 路并行深度审查(Shell 核心层 / Go 守护层 / C 原生层 / 前端层 / 横切面),全部只读分析,交叉验证后汇总。本报告未修改任何运行时代码。

---

## 0. 项目概览与技术栈

| 维度 | 内容 |
|---|---|
| 业务场景 | Android root 模块:对个人热点的每台客户端做限速/延迟/黑白名单/流量统计/DPI 应用识别 |
| 技术栈 | C(hotspotd 设备发现、launcher、tc_netlink)+ Go(hnc_httpd WebUI 后端、hnc_dpid DPI、watchdog/supervisor)+ POSIX Shell(tc/iptables/JSON 编排,79 个脚本约 1.9 万行)+ 前端(单文件 SPA 13,246 行 + 远程 SPA app.js 1,285 行) |
| 架构模式 | 5 守护进程,进程间通过 JSON 文件解耦(devices.json / rules.json / dpi_state.json),Go 做 HTTP 壳、shell 做系统操作,三套 supervisor fallback 链(C launcher > shell guard > Go supervisor) |
| 规模 | 约 5.8 万行(C 9.9K + Go 20.8K + Shell 19.2K + HTML/JS 约 15K) |

**总体判断**:微观工程质量明显高于典型 root 模块——原子写、能力探测、熔断退避、事故复盘注释密度都是高水准;但宏观上已处在"补丁文化压倒架构"的临界点。最紧迫的不是代码问题而是**发布流程问题**(P0-1/P0-2):线上运行的代码在 git 里没有对应提交。其次是三大系统性债务:锁体系碎片化(6 套并立且有结构性缺陷)、JSON 解析/读写入口不收敛(C 3 套 + Shell 4 套解析器、多处绕锁写者)、热路径性能反模式(每包重读规则、持锁 fork、主循环阻塞)。

---

## 1. 高优先级问题(P0:流程红线;P1:结构性缺陷)

### P0-1:发布包与仓库源码实质脱钩——v5.8.9-portal 是绕过 CI 的手工构建

**问题描述**:
- 仓库 `module.prop` = v5.8.8;发布 zip = v5.8.9-portal-0.1.4(versionCode 589014)。
- zip 内 `BUILD-NOTES-portal-0.1.4.txt` 自述构建方式为"v5.8.8 base + v5.8.9 shell bugfix patch + portal 0.1.4 patch + watchdogfix-v6.2"手工叠加,并非 `.github/workflows/build.yml` 的 CI 产物。
- 源码缺口:zip 里的 `bin/portal_manager.sh`、`webroot/portal.{html,js,css}`、hnc_httpd portal API 在仓库工作树中**不存在**;"v5.8.9 shell bugfix patch" 与 "watchdogfix-v6.2" 连 patch 文件都不在仓库(仓库只有 v6.1)。
- 实测 diff:zip 与仓库在 `service.sh`、`bin/watchdog.sh`、`bin/json_set.sh`、`bin/tc_manager.sh`、`bin/hnc_lock.sh`、`webroot/index.html` 等核心文件全部不一致。
- 护栏失效链:`bin/version_consistency_check.sh:23` 与 `bin/ci_preflight.sh:68` 的版本正则都不接受 `-portal-` 后缀且不匹配只 warn 不 fail;CI 的 Source preflight 步骤 `continue-on-error: true`;v5.8.2 引入的二进制指纹护栏在 v5.8.3 被撤。本次发布恰好从所有缝隙中穿过。

**影响**:下一次从 main 触发 CI 构建会发布一个**倒退版本**(丢 portal、丢 v5.8.9 修复、丢 watchdogfix-v6.2)——这是 CHANGELOG 里出现过 9 次的"改了没进包/发布陈旧"事故的镜像版,只是方向相反。

**优化方案**:
1. 立即把三个 patch 内容落进仓库,合并出 v5.8.9-portal 的真实 commit + tag(portal 建议按 P0-2 推倒重做而非 git apply)。
2. 立规:**只有 CI 产物可发布**;手工热修包必须在 24h 内回灌仓库。
3. 护栏修复:两个检查器的版本正则统一为单一来源并把不匹配升为 fail;去掉 preflight 的 `continue-on-error`;zip 内嵌 `build_info.json`(commit sha + CI run id),`artifact_sanity_check.sh` 校验其存在。

**预期收益**:消除"线上代码无源可溯"这一当前唯一可能造成不可逆损害的风险;根除"假修复发布/倒退发布"这一反复发作的事故家族。

### P0-2:发布的 hnc_httpd 用源码已丢失的自制 bcrypt shim 替换 golang.org/x/crypto

**问题描述**:zip 内 `daemon/hnc_httpd/go.mod` 含 `replace golang.org/x/crypto => ./local_x_crypto`,但 `local_x_crypto/` 目录既不在 zip 也不在仓库;BUILD-NOTES 自认是沙箱下载不了依赖时的"local compatibility shim"。

**影响**:远程访问(8443)鉴权路径上的密码学组件被**不可审计、不可复现**的实现替换。若 shim 在 cost 处理、盐生成或时序比较上有弱化,远程 token 体系整体受损,且无人能 diff 出来。

**优化方案**:视 v5.8.9-portal 的 hnc_httpd 为不可信产物,用 CI + 真实 x/crypto 重编重发;`ci_preflight` 增加"禁止 replace 指向仓库外路径 + go.sum 完整性校验"。

**预期收益**:恢复鉴权组件的供应链可信度。

### P0-3:portal 0.1.4 提交失实,补丁本体损坏

**问题描述**:commit `0e6f45b` 名为 "Apply HNC portal 0.1.4",实际只添加了 `HNC-v6-watchdogfix-v6.1.patch`;工作树中 grep 不到任何 portal 代码。`patches/HNC-v5_8_8-portal-0_1_4.patch`(2,276 行)本体存在三处硬伤:
- app.html/app.js hunk 的中文全部损坏为 `?`(0x3F)且行尾为 CRLF——应用后 UI 按钮文案就是 "??";
- 同一份 portal.js 被逐字节复制进 `daemon/hnc_httpd/web/` 和 `webroot/` 两处(业务逻辑第 4 份副本尚未落地就先双份);
- admin 面板全部使用 inline `onclick="portalApprove(...)"` 拼接字符串参数——app.js 内(约 L1050)有大段注释解释当年正是因为设备名含引号会破坏 onclick 才迁到 `data-act` 委托,补丁把修过的 bug 模式原样带回。

**优化方案**:放弃 patch 搬运,portal 作为普通提交直接进分支(UTF-8 + LF);portal.js 只保留 `daemon/hnc_httpd/web/` 一份(portal 页面本来就由 hnc_httpd serve);按钮改用既有 click 委托:

```text
before: '<button onclick="portalApprove(' + portalJSArg(ip) + ')">放行</button>'
after:  '<button class="act-btn" data-act="portal-approve"
                 data-ip="' + esc(ip) + '" data-mac="' + esc(mac) + '">放行</button>'
```

CI 增加 `grep -P '\r$'` 与中文完整性检查。

**预期收益**:portal 功能脱离"薛定谔状态";避免乱码 UI、CRLF 混入与注入类回归进入正式版本。

---

### P1-1:锁体系六套并立,且已产生两个结构性缺陷

**问题描述**:shell 层同时存在 6 套锁:`json.lock`(2s 查 PID 强拆)、`hnc_json.lock`、gate+mac 双层(`hnc_lock.sh`)、`tc_action.lock`(25s 纯 age)、`daemon.spawn`(60s mtime;device_detect 又是 10s force-break)、`hnc_common.sh` pidfile 锁。语义、超时、回收条件全不一致,并直接导致:

**(a) 跨进程嵌套自阻塞**:`tc_manager.sh restore` 先取 gate 锁(`tc_manager.sh:2244-2252`),随后在 `restore_rules` 循环内(`tc_manager.sh:2107`)fork `iptables_manager.sh mark`,后者强制取 per-MAC 锁(`iptables_manager.sh:680`),而 `mac_lock` 的第一步是"gate 目录存在就一直等"(`hnc_lock.sh:154-160`)。gate 由父进程全程持有 → 子进程空转 50×100ms = 5 秒后 exit 11,且 `restore_rules` 不检查返回值。**结果:每台设备开机恢复至少多 5 秒,且 per-device 的 iptables MARK/CONNMARK 规则根本没装上**(此前 init 已 flush 过链),IPv6/fw-mark 路径静默失效。

**(b) 假陈旧强拆**:`tc_action_lock` 的 stale 判定只看 age ≥ 25s,无 `kill -0` 存活检查(`tc_manager.sh:2186-2197`;对比 `json_set.sh:110` 和 `hnc_lock.sh:133` 都做了)。而 restore 因 (a) 每设备至少 5s,5 台设备即稳超 25s → WebUI 并发操作会 `rm -rf` 掉活跃 restore 的锁并并发改 tc 树——恰是这把锁要防的场景。

**优化方案**:

```text
# (a) 方案 A · 收窄 gate 范围(推荐):
tc restore:  tc_action_lock
             → gate_lock; 解析 rules.json 生成恢复计划(纯读); gate_unlock
             → for mac: { iptables mark(可正常拿 mac_lock); set_all }

# (a) 方案 B · 锁传递(改动最小):
tc_manager:  gate_lock && export HNC_GATE_HELD=<owner token>
hnc_lock.sh: mac_lock() { [ "$HNC_GATE_HELD" = <token> ] && return 0; ... }

# (b):
owner_pid=$(awk '{print $1}' owner)
kill -0 "$owner_pid" && return 1        # 持有者活着永不强拆,只返回 BUSY
[ age -ge 25 ] && rm -rf lock           # 死了才按 age 回收
# restore 期间周期 touch owner 续租
```

中期:统一到 `hnc_lock.sh` 单库,`hnc_lock acquire <name> [--timeout N] [--lease N]`,固定"mkdir + pid + 续租 + kill -0 回收"一种范式,其余五套逐个替换。

**预期收益**:开机恢复时间从 5N 秒级降到秒级;消除限速规则静默缺装;消除并发强拆导致的 tc 树竞态。

### P1-2:共享 JSON 的写者/解析器不收敛(跨 C/Go/Shell 三语言)

**问题描述**(三个子问题):

**(a) 绕锁写者**:
- `service.sh:375-376` 用 `sed -i` 直改 rules.json 的 `auth_required`,不取 json.lock、不走 guarded_commit——与开机同期的 json_set.sh 写者是经典 lost-update;
- `remote_tokens.json` 双写者(Go httpd 直写 + `json_set.sh token_revoke`),无共享锁,`tokens.go:245-324` 用 mtime 探测 + 双向 merge + dirty 集合缝合,注释自认"真正的解决方案是引入 flock",该逻辑已历经 3 轮补丁、无测试、肉眼不可验证;
- `known_devices.json` 由 dpid 与 httpd **两个进程**写,包级 `ledgerMu` 跨进程无效;`alert.go:664` 的 alerts_seen.json 还是非原子 `os.WriteFile`。

**(b) C 层三套手写 JSON 解析器解析同一格式**:`hotspotd.c:555-574`(strstr/strchr 裸扫 blacklist,不识别转义)、`scheduler.c:211-359`(149 行 brace 状态机)、`hnc_helpers.c:111-175`(手工子串匹配 + **8KB 定长 buffer,device_names.json 超限静默截断**——与 rc39 P1-5"16KB 截断导致限速静默绕过"同型)。历史上 rc3.1.34 #65、hotfix10 C3、rc39 P1-5 均为这类解析器独立翻车。

**(c) Shell 层 4 套读取器**:`service.sh`/`watchdog.sh` 裸 grep、`tc_manager.sh json_top_string`、`json_set.sh top_get`、`hnc_common.sh hnc_json_get_top`,同一字段在不同脚本可能读出不同结果。另 `json_set.sh` 内同一套 awk 状态机(strend/valend/findkey)复制了 7 份。

**优化方案**:
1. `service.sh` 的 sed 改为 `json_set.sh top auth_required true`(2 行改动,立即可做);
2. tokens 单写者化——项目已有现成模式(`token_prune` 就是 shell touch marker、httpd 在 pruneLoop 执行):

```text
# before: shell 直改 remote_tokens.json;Go 端 saveAtomicLocked 读盘→双向 merge→dirty 缝合
# after:  shell: echo <id> >> run/token_revoke.request && touch marker
#         Go:    pruneLoop 发现 marker → tokens.Revoke(id) → 唯一写者原子写
#         saveAtomicLocked 删掉全部 merge/dirty 逻辑(约 80 行)
```

3. known_devices 的 MarkKnown 改经 dpid IPC/意图文件;
4. C 层提取 `hnc_json_scan.c`(约 200 行只读扫描器:`jscan_load`(动态读)/`jscan_find_key`(统一处理 escape/嵌套)/`jscan_iter_string`/`jscan_obj_get_*`),三处调用点统一,顺带修掉 8KB 截断;
5. Shell 层立规:rules.json 读写只允许 `json_set.sh`/`hnc_json` 入口;awk 状态机抽成 `bin/lib/json_sm.awk`;
6. CI 静态护栏:grep 禁止 Go/C 出现 rules.json 写路径、禁止脚本裸 grep rules.json。

**预期收益**:消除 lost-update 与"复活已撤销 token"窗口;根除"解析器各自翻车"事故家族;tokens.go 复杂度大幅下降且可测。

### P1-3:dpid DPI 分类热路径每个包事件重读+重解析全部规则文件,且在全局锁内

**问题描述**:`src/dpid/output/rule.go:267-338` 的 `loadL3RulesFromDir` 把"算聚合 mtime"和"ReadFile+Unmarshal"揉在同一个循环里,**缓存命中检查在循环之后**——缓存只能挡编译,挡不住 I/O。而 `classifyHost`/`classifyFlowIP`(`output/classify.go:26,67,92`)每次都调 `loadL3Rules()`,调用源头是 `RecordDNS/RecordTLS/RecordFlow`(`output/state.go:493-610`)= **每个 DNS/TLS/Flow 包事件一次**,且全程持有 `Writer.mu`。

**影响**:热点满负载时每秒几十上百事件 × N 个规则文件的 stat+read+parse 全部落在持锁临界区,拖慢整个捕获管线,真机上体现为耗电与 kernel drop 上升。

**优化方案**:

```go
// 修改前
for f in files { stat(f); read(f); unmarshal(f) }   // 全量 I/O
if cache.hit(aggrMtime, aggrSize) { return cache }  // 太迟
// 修改后
for f in files { aggr += stat(f) }                  // 只 stat
if cache.hit(aggrMtime, aggrSize) { return cache }  // 命中 → 零 read/parse
for f in files { read(f); unmarshal(f) }            // 仅 miss 时
```

进一步:后台 goroutine 每 30-60s 刷新,`atomic.Pointer[loadedRules]` 发布,classify 热路径完全无锁无 I/O。

**预期收益**:DPI 热路径 CPU/IO/GC 压力下降一个数量级;降耗电、降丢包。

### P1-4:hotspotd 单线程主循环被三处同步阻塞破防;scheduler 持锁 popen 可冻死全进程

**问题描述**:
- 主循环内:`update_traffic_stats()`(`hotspotd.c:440-506`)每次 write_json 前同步 fork `iptables_manager.sh stats_all`(注释自认几百毫秒);`process_pending_mdns()` 的 dumpsys 路径单次上限 500ms(`hotspotd.c:1418-1615`);`handle_client()` IPC 同步 recv 2s / send 5s(`hotspotd.c:1074-1184`),慢客户端可冻主循环 7 秒。注释自认"30 台设备同时上线总阻塞 15 秒仍不完美"。主循环阻塞 → netlink 缓冲溢出 ENOBUFS → 全量 rescan 风暴(v3.6 注释警告过的灾难路径)。历史上已为此打过 6+ 轮局部止血补丁。
- 更严重:offload worker 线程**持 `sched.lock` 调用无超时 `popen("ip route get ...")`**(`scheduler.c:544-546` → `upstream.c:51`),而主线程的 IPC 命令(`OFFLOAD_NOTIFY_LIMIT`/`OFFLOAD_STATUS`)会抢同一把锁 → `ip` 命令被 ROM 异常挂起时**整个 hotspotd(设备发现、JSON 写出、全部 IPC)永久冻死**。同文件 `try_ns_dhcp_resolve` 已示范了 fork+select+SIGKILL 的正确超时模式,upstream.c 未复用。

**优化方案**:

```text
# 主循环:把 mdns_worker 泛化为通用子进程任务 worker(队列已有现成实现)
main loop tick:
    drain(worker_results)              # dumpsys/mdns/iptables 结果统一非阻塞取回
    if dirty: write_json(cached_stats) # 只用 worker 缓存的 stats,不再 fork
    handle_client(cfd)                 # 超时降至 200ms 或移入 IPC 线程

# scheduler:探测挪到锁外 + 超时
worker:
    idx = upstream_detect_primary_with_timeout(500ms)  # 锁外;复用 try_ns_dhcp_resolve 骨架
    lock(sched.lock); 写回结果; unlock
```

**预期收益**:消除全进程冻死路径;设备上线感知回到亚秒级;根治而非再一轮止血。

### P1-5:hnc_httpd `/api/action` 持全局排他锁横跨 shell exec(最长 60s),期间全站读 API 冻结

**问题描述**:`action.go:211-219` 持 `s.stateMu.Lock()` 执行 `dispatchAction`,内部串行 fork 多个脚本(cleanup.sh 60s、hotspot 类 30s 超时);而 `/api/devices`、`/api/live` 都要 `stateMu.RLock()`(`server.go:331`、`api_live.go:54`),前端 1-2s 轮询。一次慢写 = 整个 UI 假死。且外部进程(hotspotd/watchdog)本来就绕过这把锁写文件,锁并不能给读者提供真正的一致性。

**优化方案**:写互斥换专用 `actionMu`(只串行化 action);读路径去锁,靠文件原子 rename 保证单文件一致性;长任务(hotspot_stop、cleanup)统一改 `runBinDetached`(hotspot_start 已是异步,同文件内两个 hotspot action 一异步一同步本身就不一致)。

**预期收益**:慢操作期间 UI 保持可读;消除远程多客户端排队假死。

### P1-6:self_attrib JSONL 无限增长,无任何 retention

**问题描述**:`src/dpid/output/self_attrib.go:674-683` 启用 self-capture 后每 5s append 一次全部连接行;全仓检索确认 `history.go trimOldFiles` 只清 `stats.*` 前缀,`log_rotate.sh` 不含 jsonl 清理——**旧日期文件永不删除**,轻松数十 MB/天写进 /data。`apiSelfAttrib` 还会把当天文件整个读进内存。

**优化方案**:照抄 history.go 模式,sampler 每日首 tick 调 `trimOldFiles("self_attrib.", 保留 7 天)`;`apiSelfAttrib` 改环形缓冲读尾部。

**预期收益**:消除吃满 /data 的定时雷(root 模块吃满 /data 可能影响整机)。

---

## 2. 中优先级问题

### M1:上帝文件/超大函数(全语言层普遍)

| 位置 | 规模 | 混杂职责 |
|---|---|---|
| `webroot/index.html` | 13,246 行单文件,主 IIFE 7,823 行、262 个函数、69 个闭包变量 + 29 个 window.* | CSS/HTML/JS、8 大业务域全内联 |
| `bin/tc_manager.sh` `restore_rules` | L1899-2142,约 244 行 | 内嵌 2 段 50 行 awk 解析器 + IP 漂移策略 + 能力降级 + 黑名单 + 全局整形 |
| `bin/tc_manager.sh` `init_tc` | 约 190 行 | 4 种 root qdisc 策略 + offload + ifb + 整形 |
| `bin/watchdog.sh` 主循环 | L1079-1265,约 187 行 | 状态机、退避、passive、v6 sync、stats、httpd 保活全内联;且与 Go `hnc_watchdog` action 分发双执行模型并存 |
| `daemon/hotspotd/hotspotd.c` `main()` | L1635-1989,355 行 | daemonize、crash handler、6 子系统 init、去抖算法、mdns drain、离线清理 |
| `daemon/hnc_httpd/` | 单 package 31 文件约 8K 行 | 文件按"补丁批次"(action_v5、hotfix shim)而非领域切分;30-case switch 分发散布 10 个文件 |
| `src/dpid/cmd/dpid/main.go` | 849 行手工编排约 10 个 goroutine,含嵌套匿名 goroutine | 拓扑只存在于 main 的阅读顺序里 |
| `service.sh` | 955-1044 行 | 工具链预置、同步、密钥、迁移、launcher 四级择优、内嵌 sentinel 常驻循环共 8 类职责 |

**优化方案**(择要):
- `restore_rules` 拆为 `rules_plan()`(独立 awk 文件,可单测)+ `resolve_ip()` + `restore_one()`,字段拆分用 `IFS='|' read` 替代 8 次 `echo|cut`;
- watchdog 主循环拆 `state_pending()/state_active()`;确认 Go 壳稳定后删 legacy 主循环;
- hotspotd.c 按已验证的 worker/helpers 惯例切出 `device_table.c`/`json_writer.c`/`ipc_server.c`/`resolve_chain.c`;
- hnc_httpd 引入声明式 action registry(见 M2);dpid main 抽 `runGroup(ctx, name, fn)`;
- `service.sh` 的 sentinel 循环独立成 `bin/sentinel.sh`;
- index.html 按其内部已有的 30+ 个 `═══` banner 边界拆 ES module,esbuild 构建期再内联回单文件(交付形态不变,CI 的 `node --check` 换成 bundle 即校验)。

**预期收益**:回归面可控、核心逻辑可单测、hotfix 不再只能往函数尾部追加分支。

### M2:hnc_httpd 路由/鉴权元数据分离,写防护双实现

**问题描述**:`isWritePath`/`isSensitiveReadPath`/`isPublicPath` 三个白名单与 handler 注册分离,已三次漏登记(`middleware.go:47-50` 注释自述);`requireMutation`(middleware.go:279)与 `handleAction` 内联检查(action.go:127-181)是同一套防护的两份实现,`apiExport` 还有第三份 method 检查。

**优化方案**:声明式 registry 单一事实源:

```go
var actions = map[string]actionDef{
  "rule_set":    {fn: actionRuleSet, write: true},
  "pair_revoke": {fn: actionPairRevoke, loopbackOnly: true},
}
// isPublicPath/isWritePath 从同一张表派生;requireMutation 由 registry 自动包裹
```

**预期收益**:结构性消除"忘记登记白名单"这一类已三次发生的 bug。

### M3:前端双端(即将三端)重复维护,已实际分叉

**问题描述**:本机 `webroot/index.html` 与远程 `daemon/hnc_httpd/web/app.js` 各维护一份设备卡渲染、限速换算、统计图、APPS 页、esc/fmtBytes(全仓 ≥4 份 esc);12 个 API 端点重叠。已产生真实行为分叉:
- 限速换算:index.html `fmtRate` 用 `Math.round(v*1000)` 无下限;app.js `uiToApiRate` 用 `Math.ceil` + 64kbit 下限(hotfix5 的修复只落了远程一边);
- OUI 分类:app.js 内联 641 条 OUI_DB;index.html 的 `loadOuiDb()` 是空 stub(`window.OUI_DB = {}`),本机分类实际失效。
portal.js 若按现补丁落地将成为第三份(且自带两处副本)。

**优化方案**:共享 core + 传输适配器,构建期分别打包:

```text
web/core/{rates,oui,device-card,format}.js   # 唯一一份业务逻辑
web/core/transport.js                         # makeTransport('ksu' | 'remote')
构建: webroot/index.html = core + local-shell(内联回单文件,交付不变)
      daemon/web/app.js  = core + remote-shell(go:embed 不变)
```

**预期收益**:消除"修一份漏一份"在前端的翻版;portal 落地即复用而非第三写。

### M4:watchdog 是唯一状态机,单点级联面过大

**问题描述**:watchdog.sh 同时负责 iface 状态机、tc/iptables init+restore、httpd 保活、hotspotd 照护、stats 采样调度、v6_sync、log_rotate、每日 cleanup。v5.8.x 的"流量统计一直不动"事故根因正是该耦合(init flush 了 HNC_STATS 链且无人重建)。watchdog 卡死 → 限速恢复/统计/httpd 保活全停。监督链已有 4 层(sentinel→watchdog→launcher→dpid),历史上因层间职责重叠出过多次双进程事故。

**优化方案**:把数据面(stats_sample、log_rotate、cleanup)拆出为独立低频定时器;watchdog 只保留 iface 状态机 + 进程照护;full_restore 各子步骤加独立超时;"谁监督谁"固化成一张表并在 `rc17_process_health.sh` 断言。

**预期收益**:单组件故障不再级联到统计与限速恢复;根除双 supervisor 类事故。

### M5:高频路径 fork 风暴(Shell)与每请求全量读盘(Go)

**问题描述**:
- `set_limit` 单次调用仅"读 QoS 模式"就 20+ 次 fork(`qos_mode_raw` 4 级管道被调 4 次,`tc_manager.sh:100-143`);`restore_rules` 每设备一次全文件 awk + 8 次 `echo|cut`,O(N²);watchdog 60s 稳态每轮 fork device_detect + 2×iptables + 无条件 v6_sync 子进程;device_detect fallback 每 IP fork 一次 iptables_manager(每次进程启动都重跑 IPv6 探测);
- Go 侧:`buildDevicesPayload` 每请求读 4 个 JSON(`server.go:326-368`),`/api/live` 1-2s 轮询走同一路;RateLoop 每 2s 再独立读一次;每个 SSE 连接各自 1.5s stat 一次;
- `action_v5.go` 一次 delay_set 串行 fork 6 个脚本,其中 `lookupRuleDeviceField` fork json_set.sh 只为读一个字段(同文件 Go 直读 devices.json 的代码就在旁边);回滚失败被静默丢弃(`action_v5.go:172-173`)。

**优化方案**:shell 进程内 memoize(`qos_ctx_load()` 入口一次读取,纯内建零 fork);`ensure_stats_batch` 批量子命令;Go 侧 `readJSON` 挂 mtime 缓存(注意 P1-3 教训:先 stat 后 read);SSE 改单一共享 watcher + 订阅者广播;delay_set 链合并为单个 shell 子命令一次 fork。

**预期收益**:WebUI 操作时延与整机功耗显著下降(Android 上 fork+exec 是最贵操作之一)。

### M6:devices.json"约定单写者"而非"锁保证单写者"

**问题描述**:hotspotd(C)、`device_detect.sh do_scan_shell`、`cleanup_offline_devices.sh` 三个写者,互斥完全依赖 pid 文件编排与注释约定。rename 保证"不损坏"但不保证"不丢更新":cleanup 与 hotspotd 全量刷新并发时,被删设备可被旧快照写回。

**优化方案**:cleanup 走 hotspotd 的 unix socket(hnc_ipc 已存在)发删除指令,devices.json 收敛为真单写者;shell fallback 写前检查 hotspotd.pid 活性。

### M7:C 层数据竞争与资源缺陷(量小但属 UB/静默失效)

- `scheduler.c:579-580` worker 锁外写 int64 计数,主线程无锁读(C11 UB,换编译器/LTO 可能撕裂);`hnc_lsm_loader.c:168` `rb_should_stop` 非 atomic。→ 改 `_Atomic` 即可;
- `hnc_lsm_loader.c` init 失败路径泄漏 `target_limit_map_fd`;ringbuf 线程创建失败仅 WARN 但状态照样置 ACTIVE——**guard 完全不工作却上报 active**。→ 统一 `goto fail` 清理,线程失败视为 init 失败或标记 degraded;
- `adapter_bpf.c:619-667` `disable_global` 对空 map 返回 OK,冷启动限速窗口靠 60s 轮询兜底。→ 返回可区分的 `OFFLOAD_EEMPTY`,调度器 5s 快速重试;
- `hotspotd.c:179-191` 设备表满时静默驱逐,可能驱逐仍在黑名单/限速中的设备。→ 驱逐置 dirty 且优先驱逐无规则设备。

### M8:watchdog 越层直改 tc/iptables,与 tc_manager 参数漂移

**问题描述**:`watchdog.sh:1026-1032` 自己重建 ifb0 树,与 `tc_manager.sh ensure_ifb_root_v1` 参数已漂移(`r2q 10` vs 无;`1Gbit` vs `1000mbit`),且不经 `tc_action_lock`,可与持锁中的 tc_manager 并发写;`watchdog.sh:1000` 硬编码 `iface="wlan2"` 机型假设;`httpd_guard_install` 绕开 iptables_manager 直接操作 iptables。

**优化方案**:watchdog 只做探测,修复一律委托 `tc_manager.sh ensure_ifb/ensure_ingress`;删除 wlan2 兜底。

### M9:常量/路径无单一来源

**问题描述**:`/data/local/hnc` 字面量分布在 118 个文件(shell 127 处、Go 48、C 22、webroot 49);8443/8444 在 4 个 Go 文件硬编码;MARK_BASE `0x800000` 多处字面量重复;C 层 limit_map 路径 4 处独立定义、downstream/VPN 接口名单各 2-3 份副本。`hnc_constants.sh` 名为共享常量实际只有 4 个值。

**优化方案**:不必大重构——CI 加 consistency 断言(grep 对比各语言常量点与 hnc_constants.sh 一致);C 层集中到 platform.h(`HNC_BPF_LIMIT_MAP_PATH`、`hnc_iface_is_downstream()`);新代码一律经各语言单一常量点。

### M10:JSON 抽象层三代并存,迁移停在半途

**问题描述**:`json_set.sh`(1,075 行 legacy)→ 桥接 → `hnc_json`(1,196 行 shell)→ 可选 `hnc_json_c`;锁状态靠环境变量 `HNC_JSON_OUTER_LOCK_HELD` 接力(被 su/env -i 清洗即退化为死锁或双锁);`device_patch` 每字段 fork 一次自身。

**优化方案**:以 `run/json_legacy_fallback.count` 遥测数据为准,长期为 0 则删除 legacy writer(约 400 行),json_set.sh 退化为薄兼容壳;锁传递改显式参数 `--no-outer-lock`。

---

## 3. 低优先级问题(择要)

1. **一次性/灰度脚本堆积且被护栏钉死**:bin/ 79 个文件中约 30 个属一次性(stats_v52_* 11-13 个、stats_shadow_* 4 个、rc*_selfcheck 5 个),且 `ci_preflight.sh`/`artifact_sanity_check.sh` 把它们列为必需文件——删除会导致 CI 报错,债务被制度化。→ 建 `bin/attic/`(不进 zip),同步瘦身检查器清单。
2. **module.prop description 塞 10.7KB changelog**:成为第 4 份 changelog 载体(与 CHANGELOG.md、changelog.html、PATCH-NOTES 并存),四处人工同步已出现不一致。→ description 收敛为一句话;changelog.html 由脚本从 CHANGELOG.md 生成。
3. **注释即变更史**:hotspotd.c 约 40% 行数是版本考古;tc_manager.sh usage 硬编码的版本号已与实际脱节。→ 历史留 CHANGELOG/git,代码注释只留"当前不变量"。
4. **重复实现清单(DRY)**:shell `log()` 21 份、`prune_duplicate_hotspotd` 两份逐行相同、`get_current_ip`≈`get_ip`、marker JSON 字面量 3 处;Go 手写 itoa 3 份、atomicWrite 4 份(其中 supervisor 版漏 fsync)、watchdog 与 supervisor 10+ 函数逐行克隆;前端 esc() ≥4 份。→ 分别收编进 `hnc_common.sh` / `internal/daemonutil` / `web/core`。
5. **测试近乎为零**:两个 Go module 合计 1 个测试文件;tokens merge、rateToMbpsStr、aggregate 等纯函数最适合先补表驱动测试;C 层测试靠 `#include "hotspotd.c"` 开洞。
6. **前端定时器生命周期不统一**:主轮询有完整 visibility 管理,但 `__candDotTimer`(25s 打 /api/dpi_state)、`__alertPollTimer`(60s)后台不停——KSU WebView 切后台仍周期 fork curl。→ 抽 `managedInterval(fn, ms, {pauseWhenHidden})` 统一接入。
7. **杂项**:mdns_resolve 放弃 txid 校验(同链路可伪造 hostname 展示);`hostname_src` 12 字节截断("cache-manual"→"cache-manua");devices.json.tmp.<pid> SIGKILL 残留无清理;watchdog `pollDirty` 每轮 select 新 spawn 30s 轮询 goroutine;`ndpiEnabledByConfig` 用 strings.Index 手搜 JSON;ndpi-lab.html/json-health.html 各自第 3/4 份 ksu.exec 封装绕开 `__hncKsuExecRaw` 单入口;localStorage 键名三种风格混用。

---

## 4. 设计准则违反汇总

| 准则 | 主要违反点 |
|---|---|
| 单一职责(SRP) | watchdog.sh(状态机+数据面+保活)、service.sh(8 类职责)、hotspotd.c main、index.html 单文件、hnc_httpd server 结构体 |
| 开闭原则(OCP) | action 新增需改 30-case switch + 3 个白名单;hotfix 只能往超大函数追加分支 |
| 接口隔离/依赖倒置 | Go↔shell 契约为裸字符串子串匹配(`strings.Contains(detail, "partial_tc_fail=uplink")`);watchdog 越层直改 tc |
| DRY | 见第 3 节第 4 条清单;三套 C JSON 解析器、四套 shell JSON 读取器、双端前端业务逻辑 |
| 最小惊讶 | 六套锁六种 stale 语义;同文件两个 hotspot action 一异步一同步;两个版本正则互相矛盾 |

---

## 5. 优化路线图(可执行,分四阶段)

### 阶段 0:止血(本周内,不动架构)

| # | 事项 | 工作量 | 对应问题 |
|---|---|---|---|
| 0.1 | 三个 patch 回灌仓库,产出 v5.8.9-portal 真实 commit;portal 按 P0-3 重做(UTF-8/LF、单份 portal.js、data-act 委托) | 0.5-1 天 | P0-1/P0-3 |
| 0.2 | CI 重编 hnc_httpd(真实 x/crypto),重发刷机包;ci_preflight 禁 replace 仓外路径 | 0.5 天 | P0-2 |
| 0.3 | 版本正则统一 + 升 fail;去 preflight continue-on-error;zip 嵌 build_info.json | 0.5 天 | P0-1 |
| 0.4 | `service.sh` sed 改 json_set.sh(2 行);`tc_action_lock` 加 kill -0(10 行);`restore_rules` 检查 mark 返回值 | 0.5 天 | P1-1b/P1-2a |
| 0.5 | self_attrib 加 7 天 trim(20 行) | 0.5 天 | P1-6 |
| 0.6 | dpid 规则缓存改"先 stat 后 read"两段式(30 行) | 0.5 天 | P1-3 |

### 阶段 1:结构性缺陷修复(1-2 个版本周期)

| # | 事项 | 对应问题 |
|---|---|---|
| 1.1 | gate/mac 嵌套自阻塞:先用锁传递方案 B 止血,随版本收窄 gate 范围(方案 A) | P1-1a |
| 1.2 | httpd 锁拆分:actionMu 串行写、读路径去锁;长任务统一 detached | P1-5 |
| 1.3 | scheduler 探测挪锁外 + 超时;hotspotd 主循环三处阻塞收进 worker 线程 | P1-4 |
| 1.4 | tokens 单写者化(marker 模式,删 merge/dirty 约 80 行);known_devices 经 IPC | P1-2a |
| 1.5 | C 层 `hnc_json_scan.c` 统一三套解析器(顺带修 8KB 截断) | P1-2b |
| 1.6 | `_Atomic` 修数据竞争;LSM init 失败路径 goto fail;disable_global 返回 EEMPTY | M7 |

### 阶段 2:偿债与收敛(2-3 个版本周期,建议冻结新特性一个版本)

| # | 事项 | 对应问题 |
|---|---|---|
| 2.1 | 锁统一:`hnc_lock acquire <name> --timeout --lease` 单库,替换其余五套 | P1-1/M5 |
| 2.2 | JSON 入口收敛:shell 只留 json_set/hnc_json 两入口→一入口;legacy writer 按遥测删除;CI 加绕锁写者护栏 | P1-2c/M10 |
| 2.3 | hnc_httpd action registry(白名单从表派生)+ 按领域重组文件 | M2 |
| 2.4 | watchdog 拆分:数据面外移、只留状态机+照护;删 legacy 主循环;越层 tc 操作委托 tc_manager | M4/M8 |
| 2.5 | fork 风暴治理:qos memoize、ensure_stats_batch、restore_rules 重构(rules_plan awk + IFS read) | M5/M1 |
| 2.6 | `bin/attic/` 归档灰度脚本;module.prop description 瘦身;changelog.html 脚本生成 | 低-1/2 |
| 2.7 | Go:抽 internal/daemonutil(watchdog/supervisor 去克隆);补 tokens/rates/aggregate 表驱动测试 | 低-4/5 |

### 阶段 3:长期架构演进(按需)

| # | 事项 | 对应问题 |
|---|---|---|
| 3.1 | 前端"共享 core + 双壳打包"(esbuild,交付仍是零依赖单文件);index.html 按 banner 边界拆模块 | M3/M1 |
| 3.2 | devices.json 真单写者化(cleanup 走 hnc_ipc);长期考虑 devices 查询走 IPC 而非文件快照 | M6/低-3 |
| 3.3 | Go↔shell 契约结构化:脚本末行输出单行 JSON `{"ok":bool,...}`,runBin 解析 | M-Go3 |
| 3.4 | hotspotd.c 按 worker/helpers 惯例拆文件;OUI 表独立为生成文件 | M1 |
| 3.5 | 常量一致性 CI 断言(HNC_DIR/端口/MARK_BASE 跨语言对比) | M9 |

### 路线图原则

1. **P0 三项先于一切**——发布流程失控是当前唯一可能造成不可逆损害的问题;
2. 每阶段结束跑真机回归(开机恢复计时、限速精度、watchdog 巡检一轮),用 `/api/sla` 面板的计数做前后对比;
3. 阶段 2 建议冻结新特性一个版本专门偿债——按当前 hotfix 叠加速率,再不偿债 tc_manager/watchdog 将不可维护;
4. 所有"删除"类动作(legacy writer、灰度脚本)以运行遥测(json_legacy_fallback.count 等)为准,先归档后删除。

---

## 6. 值得保留的好设计(避免重构误伤)

- 三套 supervisor fallback 链 + fork_probe 自动选择(对 Go fork EPERM 的工程化应对,ARCHITECTURE.md 有完整决策记录);
- launcher 与 tc_ingress 接近范本水平(flock 单实例、崩溃风暴冷却自愈、rtnetlink 幂等/seq 校验);
- RateLoop 单采样源、`RecordFlow` 拒绝隐式建 client、`PutIfAbsent` 消 TOCTOU、supervisor netlink+debounce;
- hnc_watchdog "Go 管进程、shell 管业务"的单一出口边界(可作为 httpd 整改参照);
- 前端传输层单入口(`__hncKsuExecRaw`)、事件委托、签名比对增量渲染、visibility 感知轮询、乐观 UI;
- 原子写(tmp+rename+ferror 检查)在 C/Go/Shell 三层的普遍纪律;诚实的事故复盘注释文化。

---

*本报告由 5 路并行深度审查交叉验证汇总;所有 file:line 引用以分支 `claude/code-architecture-review-ejb05l` HEAD `0e6f45b` 的工作树为准,发布包差异以 v5.8.9-portal-0.1.4 zip 为准。*
