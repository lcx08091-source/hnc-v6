# HNC 外部审查报告 · Bug 修复总结(v5.7.0-rc36 → rc40)

> 整理日期:2026-05-25  ·  分支 `claude/webui-fake-code-audit-RJjFZ`(均已 FF 合并 main)
> 背景:共收到 **4 份外部 AI 审查报告**(均基于 rc32)。逐条对照**当前源码**核查后,
> 把「确认为真且值得修」的问题分批修复;误报 / 已修 / by-design / 评估后暂缓的也记录在案。
> 含 Go / C / 前端改动的版本均需 CI 重编(`.github/workflows/build.yml` 只在 push main 时构建)。

---

## 0. 一页总览

| 编号 | 严重度 | 一句话 | 修在 | 主要文件 |
|---|---|---|---|---|
| GS-1 | P1 | 全局整形 ceil 在 init_tc 重建后静默丢失 | rc36 | `bin/tc_manager.sh` |
| GS-2 | P1 | global_shaper_set 三次写不检 rc → 半状态 | rc36 | `daemon/hnc_httpd/action_global_shaper.go` |
| LOCK-1 | P1 | hnc_json 与 json_set.sh 两套锁并发写同一文件 | rc36 | `bin/hnc_json` + `bin/json_set.sh` |
| TC-1 | P2 | init_tc HTB 失败仍 `return 0` 误导调用方 | rc36 | `bin/tc_manager.sh` |
| PKG-1 | P0/P2* | hnc_watchdog 未 strip 且 CI 从不重编(陈旧) | rc37 | `build.yml` + `.gitignore` |
| PKG-2 | P1 | 刷机 zip 全量打包源码/文档(~9MB 冗余) | rc37 | `build.yml` |
| DELAY-1 | P1 | delay_set/clear 多次 JSON 写非原子 | rc38 | `daemon/hnc_httpd/action_v5.go` |
| ESC-1 | P2 | hnc_json json/raw 值反斜杠被 awk -v 吃掉损坏 | rc38 | `bin/hnc_json` |
| SEC-1 | P2 | uninstall 备份 tokens.json 世界可读 | rc38 | `uninstall.sh` |
| M1 | — | dpid_supervisor netlink 防抖永不触发 | rc38 | `src/dpid/cmd/dpid_supervisor/main.go` |
| (lint) | P3 | 死代码 / 未用函数 / 未引号 / UI min 对齐 | rc38 | 多处 |
| P1-5 | P1 | scheduler.c 16KB 静态 buffer 截断 → 限速静默绕过 | rc39 | `daemon/hotspotd/scheduler.c` |
| P2-12 | P2 | 远程 actionKey 去重过粗,同设备连点被挡 | rc39 | `daemon/hnc_httpd/web/app.js` |
| P2-23 | P2 | dpid 调 `pm` 缺 LD_LIBRARY_PATH | rc39 | `src/dpid/output/self_attrib.go` |
| P2-28 | P2 | 出口探测只试 1.1.1.1,受限网络挂不上 NAT | rc39 | `bin/hotspot_autostart.sh` |
| P2-25 | P2 | alert 标记已读截断丢最新 → 回弹未读 | rc39 | `src/dpid/alert/alert.go` |
| P2-20 | P2 | dpid 健康运行时不清 crashflag → 误判 crash-loop | rc40 | `src/dpid/cmd/dpid/main.go` |
| P2-30 | P2 | crash-loop 空转无超时,拖死 launcher 自愈 | rc40 | `src/dpid/cmd/dpid/main.go` |
| P2-18 | P2 | dpid_guard 杀子进程仅等 0.2s,BPF 资源易残留 | rc40 | `bin/hnc_dpid_guard.sh` |

\* PKG-1:某报告列 P0,但对 root 模块"信息泄露"意义很小,实为体积 + 陈旧问题,按 P2 处理。

---

## 1. rc36 — 功能 / 正确性(审查 A)

### GS-1 · 全局整形 ceil 在 init_tc 重建后静默丢失(P1,本版功能闭环)
- **现象**:UI 显示「全局限速 100Mbit · 开」,实际 HTB 父类 `1:1` 的 ceil 是满速,所有流量不受限。
- **根因**:`init_tc` 用 `DEFAULT_RATE` 建 `1:1`,而全局整形 ceil 只在 `restore_rules` **末段**恢复。ROM 把根 qdisc 换成 mq/noqueue → `ensure_egress_htb_ready` → `init_tc` 重建 → ceil 退回满速,直到下次 restore 才纠回。
- **修复**:抽出 `apply_global_shaper_if_enabled <iface>`,在 `init_tc` 建好 HTB 树后 + `restore_rules` **共用同一逻辑**;树重建后立即把 ceil 压回 WAN 带宽。(`set_global_shaper` 内的 `ensure_egress_htb_ready` 在树已就绪时直接返回,不会递归。)

### GS-2 · global_shaper_set 三次写不检 rc(P1)
- **根因**:on 路径前两次写 `global_shaper_down/up`、off 路径写 `enabled` 都忽略了返回码 → 中途失败留下「enabled=true 但 down/up 是旧值」的半状态,下次 restore 用错误参数。
- **修复**:三次写全部检查 rc;down/up 任一失败显式落 `enabled=false` 防半状态后返回 error;off 写 enabled 检 rc。

### LOCK-1 · 两套 JSON 锁并发写 rules.json(P1)
- **根因**:`hnc_json` 用 `run/hnc_json.lock`,`json_set.sh` 用 `run/json.lock`;直接调 hnc_json 的写者(如 `json_set_batch.sh`)与走 json_set.sh 的写者并发时互不见锁,竞态可丢写。
- **关键**:报告建议「把 hnc_json 的 LOCKDIR 改成 json.lock 对齐」——**那会死锁**(json_set.sh 持 json.lock 后桥接 hnc_json,非重入 mkdir 锁自锁)。
- **修复**:hnc_json 写路径也抢同一把 `json.lock`(外层)+ 保留内层 `hnc_json.lock`;新增 `HNC_JSON_OUTER_LOCK_HELD=1` 环境变量,json_set.sh 桥接前导出,被桥接的 hnc_json 跳过外层锁避免死锁;`reclaim_stale_lock` 加 `ts>0` 守卫,避免误拆 json_set.sh 那把「只写 pid 不写 ts」的活锁。
- **验证**:交错 15×`json_set.sh top` + 15×`json_set_batch device` 并发 → 12s 全完成、**零丢写、终态合法、无死锁、无残留锁**。

### TC-1 · init_tc HTB 失败仍 return 0(P2)
- **根因**:root htb add 三次重试都失败后只装 ingress mirred 却 `return 0`,误导调用方以为成功。
- **修复**:ingress mirred 装好后 `return 1` 如实上报(`ensure_egress_htb_ready` 的后置树检查本就能纠正,这里让 CLI/调用方拿到准确状态)。

---

## 2. rc37 — 打包瘦身(审查 B,纯 CI/打包,无运行时代码改动)

### PKG-1 · hnc_watchdog 未 strip 且 CI 从不重编
- **根因**:`bin/hnc_watchdog` 是**提交进 git 的预编译二进制**,CI 无构建步骤 → 发布的是陈旧(改了源码也不重编)且未 strip(3.1M)的版本;service.sh 还优先用它。
- **修复**:① 加 CI 步骤从 `src/dpid/cmd/hnc_watchdog` 构建(`-trimpath -ldflags="-s -w"`,并断言已 strip);② 从 git 取消跟踪 + 加进 `.gitignore`,对齐 hnc_dpid/hnc_httpd 的「CI 产物不入库」约定。此后每次 CI 重编为最新 + 已 strip(2.6M)。
- 备注:某报告同时声称 dpid/httpd 也未 strip —— **误报**,CI 一直对这两个加了 `-s -w`,只有 watchdog 真没。

### PKG-2 · 刷机 zip 全量打包开发产物
- **根因**:`zip -rqX .` 仅排除了 `tools/ground_truth` → `src/`(8.7M)、`docs/`、`test/`、`third_party_*`、`daemon/**` 下 `.go/.c/.h` 源码、`PATCH-NOTES/设计类 .md` 全进了刷机包。
- **修复**:zip 增加排除以上目录/文件,运行时一概不依赖(已核 service/post-fs-data/bin 无引用,编译产物在 bin/)。刷机包减约 **9MB**;保留 README/CHANGELOG/SECURITY + 运行时目录。

---

## 3. rc38 — 轻量补丁 + 防未然(审查 C/D)

### DELAY-1 · 注入/清除延迟多次 JSON 写非原子(P1)
- **根因**:循环里逐字段 `json_set.sh device` 写 4 个字段,中途失败留半状态。
- **修复**:改用 `json_set_batch.sh device`(→ `hnc_json set-device-batch`:一次校验/备份/锁/提交,原子);hnc_json 缺失时该脚本自动退回逐字段串行(行为等价)。

### ESC-1 · hnc_json json/raw 值反斜杠被 awk -v 吃掉(P2)
- **根因**:`set-top`/`set-object-key` 对 `json`/`raw` 类型不转义反斜杠,但 awk -v 对任何值都吃一层 C 风格转义 → 合法 JSON 如 `{"p":"a\\b"}` 被写成 `{"p":"a\b"}`(静默损坏)。**已实测复现并验证修复**。
- **修复**:统一对所有类型 `sed 's/\\/\\\\/g'`,删除错误的 json|raw 特例 + 改正误导注释。

### SEC-1 · uninstall 备份 tokens.json 世界可读(P2 安全)
- **根因**:`tokens.json.last` 含远程访问 token,备份目录默认 755/文件 644 → 有 root 的其他模块可读。
- **修复**:备份目录 `chmod 700`、`tokens.json.last` `chmod 600`。

### M1 · dpid_supervisor netlink 防抖永不触发
- **根因**:`lastRebind` 是 `runChild` 的局部变量、每次调用归零,命中 netlink 事件赋值后立即 return → 下次又归零 → `IsZero()` 恒真 → 防抖永不生效(staticcheck SA4006)。
- **修复**:`lastRebind` 提到 `mainLoop` 栈、按指针传入 `runChild`,跨调用保活。
- 备注:某报告把它列为「最高 ROI」属误判——`hnc_dpid_supervisor` 是「最后兜底」启动器,CI 不构建、git 不跟踪 → 实际不发布不运行;本修为将来启用预防。

### lint / 加固(P3)
- 删 `bin/watchdog.sh` 死变量 `PROBE_INTERVAL_ACTIVE`、`bin/apply_device_rule.sh` 未用 `IFS_ORIG`、`action.go` 未用的 `rateToKbit/rateToMbps`;`post-fs-data.sh` 给 rm 路径加引号 + 开机同时清 `json.lock`;WebUI 全局整形输入 `min` 1→0.1(对齐后端 64kbit 下限)。

---

## 4. rc39 — 第 4 份报告 · G1 快赢

### P1-5 · scheduler.c 16KB 静态 buffer 截断(唯一新 P1)
- **根因**:`rebuild_from_rules` 用 `static char buf[16384]` + `fread`,rules.json >16KB(~80+ 限速设备)时只读前 16KB → devices 对象 `}` 被截 → brace-count 找不到结尾 → `return 0` → `limited_macs` 空 → BPF tether offload 不被 disable → **被限速设备流量走 BPF fast-path 全速绕过 HTB,UI 显示限速实际满速,完全 silent**。
- **修复**:`fseek`/`ftell` 取文件大小后 `malloc` 读全量(失败回退 65536),所有 return 路径 `free`。
- **边界**:仅当①设备多到 >16KB ②内核 BPF tether offload 实际生效 时触发(start-softap+手动 NAT 下大概率不走 offload)→ 低成本作保险。

### P2-12 · 远程 SPA actionKey 去重过粗
- **根因**:per-device 去重 key 是 `'dev:'+mac`,同设备先点限速(in-flight)再点封锁被误判 busy 拒掉。
- **修复**:key 改 `'dev:'+mac+':'+action`。

### P2-23 · dpid 调 `pm` 缺 LD_LIBRARY_PATH
- **根因**:nohup 启动 Env 不全时 `pm` 可能 linker error → uid→pkg 全空 / 系统应用过滤失效。
- **修复**:`loadSystemPkgs`/`loadPkgUIDs` 两处 exec 前 `cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/system/lib64:/system/lib")`。

### P2-28 · 出口探测只试 1.1.1.1
- **根因**:受限网络 1.1.1.1 不可达 → 出口探测失败 → NAT 不挂 → 客户端连上没网。
- **修复**:`detect_up_iface` 依次试 `1.1.1.1 / 223.5.5.5 / 114.114.114.114`,第一个探到 `dev` 即用。

### P2-25 · alert 标记已读截断丢最新
- **根因**:按 map 随机序建 list 再留最后 1000,刚标记的可能被截掉 → 刷新又变未读。
- **修复**:把本次 `ids` 放最前、再补其余、保留**前** 1000,确保最近确认必留(alert id 是 `kind_mac_bucket`,sort 给不出时序,故不用 sort)。

---

## 5. rc40 — 第 4 份报告 · G2 dpid 稳定性(弱网/iface 抖动)

### P2-20 · 健康运行时不清 crashflag
- **根因**:`clearCrashFlag` 只在采集 open 失败转 blind / 干净退出时调;长时间健康运行后被 SIGKILL(OOM/iface flap/硬杀)→ flag 残留 → 下次 `checkCrashLoop` 误判 → `ModeCrashLoop`。
- **修复**:同一采集 attempt 健康跑满 **5min** 后起 goroutine 调 `clearCrashFlag`(attemptCtx 在 rebind 时取消,故只在真撑过 5min 才清)。

### P2-30 · crash-loop 空转无超时拖死 launcher
- **根因**:`idleUntilSignal`(仅 ModeCrashLoop 用)永久阻塞 → launcher 的 `waitpid` 永不返回 → 它自己的 cooldown 自愈也卡住。
- **修复**:加 **30min** 超时分支退出,让 launcher 重启 dpid 重评估。crash 窗口 60s/3 次,30min 后旧时间戳早过期 → 瞬时抖动自愈;持续故障自降到 ~30min 一次而非紧打循环。

### P2-18 · dpid_guard 杀子进程过于激进
- **根因**:SIGTERM 后只等 0.2s 就 SIGKILL,不够 dpid 清 BPF map/ringbuf/flush → pinned BPF 资源可能泄漏。
- **修复**:轮询至多 ~2s(10×0.2s,提前退出)再 SIGKILL。

---

## 6. 评估后「不改」的项(误报 / by-design / 暂缓)

### 误报(代码已正确)
- **shell 注入**:Go 侧全 argv-form `exec.Command("sh", argv...)`,mac/iface/rate 先正则校验,无注入面。
- **auth_required=false 匿名放行**:rc30.12.18 已默认拒绝、fail-closed。
- **loopback = 本机任意 app 可写**:已有 `local_admin.secret`(0600 root-only)校验。
- **dpid/httpd 未 strip**:CI 一直加 `-s -w`(只 watchdog 真没,见 PKG-1)。
- **json_set_batch 没人用**:`apply_device_rule.sh` 在用。
- **WebUI 假数据**:rc22/23/31 已修。
- **P3-16 alert XSS**:本机 WebUI `renderAlertList` 标题/meta 已走 `esc()`;远程 SPA 不渲染 alert;系统通知 argv-form 纯文本 → **无 XSS 面**。

### by-design(有意为之)
- **global_shaper_off 残留 down/up**:WebUI 用它预填上次的值,`enabled=false` 已阻止 restore,不算 bug。

### 评估后暂缓 · G3 offload C(P2-15/16/17)
实读 `adapter_bpf.c`/`scheduler.c`/`hotspotd.c` 后发现报告**高估了严重度**:
- **P2-15**:真正的 `disable_global`/`restore_global`/`restore_upstream` 都直接遍历/写 BPF `limit_map`,不依赖本地 8 槽集合 → 溢出只让 `status()` 少报一项 = **纯显示瑕疵**,且需 >8 上游同时禁用(极罕见)。
- **P2-16**:`sleep(5)` 仅在一次采样里,worker 主等待已是 `cond_timedwait`(响应)→ 仅**关停最多慢 5s**。
- **P2-17**:worker **已有 60s 周期重探 + 切换 retrigger** → 最坏 60s 自愈,非永久失效;netlink 瞬时化是优化。
- 且整条 BPF tether offload 仅内核硬件 offload 生效才相关(start-softap+手动 NAT 下大概率不启用),本环境无法验证。
- **结论**:不值得为「status 一致 + 关停快 5s + 切换 60s→瞬时」去动一条用不到、又无法验证的复杂 C 路径。**留待将来真机确认 offload 生效后再议。**

### P3 其余(影响可忽略,不改)
- P3-8(ip6tables `-m mac` 无能力探测)= 真但设备特定,有 IP/CONNMARK 兜底。
- P3-9/11/12/13/15/17/18/19 = 微优化 / 设计接受 / 诊断精度,影响可忽略。

---

## 7. 验证手段(每版均跑)
- 静态:`sh -n`(改过的脚本)、`node --check`(WebUI 内联 JS / app.js)、`go vet ./...`、`go test ./output/`、`CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build`、`scheduler.c` 主机 `-fsyntax-only`、`sh bin/version_consistency_check.sh`。
- 专项:LOCK-1 并发压测(零丢写/无死锁)、ESC-1 反斜杠保真实测、P1-5 free/return 路径核对。
- **待真机**(刷 CI 包后):全局整形(开→重启/换网仍生效)、限速/延迟、瘦身包安装、受限网络下热点 NAT、多设备限速。

---

## 附:本会话更早的改动(rc14–rc35,非本批审查报告)
WebUI 假代码审计(rc14)→ 无挂载加固(rc15-17)→ police/netem 兜底(rc18)→ 每设备低延迟 + 删旧全局 SQM(rc19-21)→ 低延迟重试 + dpi_apps 折叠卡(rc22)→ 运行状态真数据(rc23)→ 开机自启热点(异步+降级+自建 NAT,rc24-28)→ 未匹配 SNI 卡诚实化 + 候选角标(rc29-30)→ 远程 WebUI 对齐(rc31)→ 全局带宽整形 opt-in(rc32)→ VPN 飞轮排除(引擎+扩清单,rc33-34)→ VPN 排除卡片徽标 + WebUI 管理 + Go 单测(rc35)。
