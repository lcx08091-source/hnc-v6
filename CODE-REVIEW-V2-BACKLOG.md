# HNC 审查 v2 — P2/P3 待办排期(v5.9.1 后)

> 来源:`CODE-REVIEW-V2-v5.9.1.md` 确认但当时未修的项,经二次实测核实(含 2 次 host 编译、1 次完整 shell 测试套件运行)后分档。
> 状态基准:HEAD `f897ddd`(v5.9.1)。v5.9.1 除 webroot/index.html + 版本三件套外未动任何文件,故 shell/C/Go 侧各项与审查时一致。
> **v5.9.2 已落地**:见文末"v5.9.2 实际纳入"。

---

## A 档 · 已纳入 v5.9.2 或强烈建议尽快做

| 项 | 位置 | 问题 | 修复 | 重编 | 收益/风险 |
|---|---|---|---|---|---|
| XC-1 | `.github/workflows/build.yml` Resolve release tag 的 elif | tag 直推发版零校验:人工推 v5.9.1 到 v5.9.0 的 commit 会产出"Release v5.9.1 挂 v5_9_0.zip"(v5.8.9-portal 事故的另一半口子) | elif 分支复用护栏 a(格式)+ b(=module.prop)。**c/d 不能照搬**:c 要求 refs/heads/main 而 tag push 下 GITHUB_REF 恒为 refs/tags/*(定义上不等);d 查 tag 是否已存在,而触发本 run 的 tag 必然已存在(恒 exit 1) | 否 | 高/零 |
| C-1 | `daemon/hotspotd/scheduler.c:774` | EEMPTY 快重试在 init-rebuild 路径漏 `hnc_scheduler_request_refresh()`,worker 要等满 60s 才重试 → v5.9.0"冷启 60s→5s"承诺在该路径未达标 | unlock 后加 1 行 request_refresh(worker 启动早于 rebuild、无丢唤醒、锁序安全,均已验证)。与 notify 路径同构 | hotspotd | 中/极低 |
| C-2 | `hnc_helpers.c:1268`、`hotspotd.c:1273/1424/1933` | 3 个 pipe 无 O_CLOEXEC + 1 个 accept 无 SOCK_CLOEXEC:并发 fork 线程互相泄漏写端,EOF 拖到 select 超时上限;try_mdns_resolve 读循环甚至无超时(唯一保护是子进程 -t 800),写端被继承时可永久挂起 | pipe2(O_CLOEXEC)×3 + accept4(SOCK_CLOEXEC);建议同刀给 try_mdns_resolve 读循环套 O_NONBLOCK+select(或直接复用 hnc_run_cmd_timeout)。API21 全可用 | hotspotd | 中/极低 |
| HTTPD-2 | `daemon/hnc_httpd/auth.go:129` | 每个已鉴权远程请求跑完整 bcrypt(arm64 ~100-300ms),SSE 场景多请求线性叠加 → 手机 UI 刷新 +400-600ms、发热耗电 | TokensStore 加 `verified map[string]{bcryptHash, secretSHA256}`,复用 s.mu(勿新加锁);命中用 subtle.ConstantTimeCompare;Revoked/过期检查在 bcrypt 之前不动(撤销即时性天然保持);Prune/reload 删孤儿 entry | httpd | **最高**/低 |
| FE-1 | `webroot/index.html:13181` appsRenderList | APPS 页每 5s 全量 innerHTML 重建:展开的系统应用列表被强制收起、candidate promote/拒绝按钮在手指落下前被替换、前 6 卡周期性重放入场动画 | 优先做**展开态保持 + animation:none**(必中);签名短路次之(注意 active_conns 高频变化削弱命中率、签名须置于空态分支后、candidate 单独签名);照抄设备页 tickPoll 的 skip-expanded/activeElement 纪律 | 否 | 高/低 |
| SH-2 | `bin/hnc_lock.sh:175/202` | 陈旧 gate 永不回收(mac_lock 的 gate 等待分支从不调 _try_reclaim_stale)+ L202 stale 检查 `-eq` 单轮可被 gate 分支吞掉。触发源:httpd runBin 10s 超时 SIGKILL apply_device_rule(gate 段含 2 次各 5s 的 json_set);该脚本**零 trap**。后果:陈旧 gate 后 WebUI clear/bl_del 每次白等 5s 退 11 且被吞成 warn → 用户看到 ok 但 iptables 规则残留(静默漂移,最坏窗口 ≤24h) | gate 等待分支加节流回收(`% 10`)、`-eq`→`-ge`;给 apply_device_rule.sh 加 `trap 'gate_unlock' EXIT INT TERM`(接不住 SIGKILL 但覆盖其余早退路径) | 否 | 高/低 |
| DPID-1 | `src/dpid/output/self_attrib.go:798` | getPkgCache 持 a.mu 调 `pm list packages -s` 无超时 → pm 挂死则 self-attrib/flywheel 整体永久冻结(与 v5.9.0 刚给 hotspotd 修掉的同型)。**范围已收窄**:loadPkgUIDs 已在锁外,只剩 loadSystemPkgs(L798) | loadSystemPkgs/loadFlywheelExcludePkgs 挪锁外;两处 exec 加 CommandContext(10s)+ cmd.WaitDelay(5s,Go1.22 支持) | dpid | 中/低 |

> A 档涉及 hotspotd/httpd/dpid 三个二进制,应一次 CI 全量重编 + 一轮真机验证。

## B 档 · 可搭 A 档车或紧随其后

- **C-3** `hotspotd.c:1392` try_ns_dhcp_resolve:mac 兜底设备每次 re-resolve 必 fork dumpsys,同一轮 scan_arp 内 N 台设备的 dumpsys 输出逐字节相同 → 10 台未命名设备 = 主循环单次阻塞 350ms~5s(netlink/IPC 全停)。方案:函数内 static 5s TTL 缓存原始输出(单线程调用已确认——mdns worker 注入的是 try_mdns_resolve 另一个函数;超时/失败不写缓存)。hotspotd 重编。
- **FE-3** `webroot/index.html:7809` renderDPI:每 1-4s 全量重建 6 个子面板。分段签名(见报告表),注意 renderDPIActiveSection 的 'active' filter 依赖墙钟(纯签名会让空闲设备永不掉出)→ 用 10s 桶并入签名;renderDPIRulesStatus/Clients 签名须含 l3_enabled/dfp_enabled。**顺手零成本**:`index.html:6845-6847` collectBuiltinDPIForCompare 有死代码(return 在缓存赋值前,`__cachedBuiltin` 恒 null,标注的缓存从未生效),2 行修复。纯前端。
- **XC-2** artifact 门禁进 CI:`bin/ci_preflight.sh --artifact` 已串联 `artifact_sanity_check.sh`,CI 打包后从不调用(9 次漏包/错架构事故形态在拦截位无门禁)。在 Compute SHA256 前加一步 `sh bin/ci_preflight.sh --artifact "$OUT_ZIP"`。**首次必须先在 PR 上验证**(22 个 warn 里确认无 fail),否则可能一次挡死发版。

## C 档 · 专门基建迭代(建议 v5.9.3)

- **XC-4** `daemon/hotspotd/tools/build.sh` 的 COMMON_SRCS 与实际依赖不同步 → sched_test/platform_probe/offload_ctl 三个工具 host 编不过(已实测:缺 lsm/hnc_lsm_stub.c、hnc_helpers.c、oui_override.c;补齐后 sched_test 全 PASS)。**build.sh 一行修复零风险,可提前搭 A 档车**;配套新增 test_tc_action_lock.sh(9 个三态+属主用例,CI 友好无 root/无 tc/无 sleep)需给 tc_manager.sh 加 `[ "$1" = "__source_only" ] && return 0` 守卫,约 1 天。
- **XC-3** shell 单测进 CI:host 实跑 16 failed/173 passed。**62% 失败(10 条)是 `#!/system/bin/sh` shebang 环境问题**(CI 加 `ln -sf /bin/dash /system/bin/sh` 一步消掉);另 runner 会吞 13 条 `exit 1` 但不写计数器的失败(需修 run_all.sh 检查 subshell rc);6 处硬编码 rc1.x 陈旧版本断言需先清;B 组 3 条 tc/netem 失败**冻进基线前必须先定性**(疑似真回归,别把 bug 合法化)。正确顺序:符号链接→修 runner 吞失败→清陈旧断言→才建 known_failures 基线。1-2 天。

## D 档 · 本轮不做(backlog)

- **SH-4** restore set_all 失败不进 rc(v5.7.0 存量非 v5.9.0 回归;原修复方案有害,须先排除 rc=8/66/67 否则 IFB 降级机型恒误开熔断)。
- **SH-6** watchdog 直改 ifb0 绕锁(头号撞击场景被驳:唯一调用方是 watchdog 自身单线程)。
- **HTTPD-3** tokens reload `>=` 双检使 json_doctor cp -p 恢复不被吸收(受损仅"进程存活期手动 restore 被静默打回"小众场景,修复需配 dirty 标志)。
- **FE-6** switchPage 180ms 连点 TypeError(后果仅吞一次点击后自愈;v5.9.1 的 `if(old)` 兜底已实际消除抛错)。
- **DPID-2~6**、**C-4/5/6**、**XC-5/6**:详见 CODE-REVIEW-V2-v5.9.1.md 的 P3 摘要。

## 交叉验证否决的误报(留档,勿重开)

1. "撞锁即退 12 无重试拉长用户可见失败窗口"——被锁序证据否决:restore 全程持 gate,set_limit 在到达 tc 锁前先抢同一 gate,5s 失败于 gate 处收不到 rc12;新旧行为一致,且 gate 传递实际缩短了 restore 时长。
2. "renderHistPie 单 app 100% 时整张饼图消失"——端到端不可达:dpid HistorySampler `if dTx==0 && dRx==0 continue`,多条目时最大 frac 严格 <1;且误报建议的修复②会把真实 0.05% 小段画没(误报的修复本身引入新 bug)。

---

## v5.9.2 实际纳入

<!-- 落地后补:预览版视觉合入(blur 收敛/暗色对比度/骨架屏/幽灵柱/触控外扩/动画 token)+ 本档 A 档选定项 -->
