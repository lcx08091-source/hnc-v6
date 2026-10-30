# v5.33.0-rc2 全量代码审查记录

> 开始:2026-10-19 · 基线提交 `44045d0`(v5.33.0-rc2)· 分支 `ccr-88cc290a-wgd5ww`
> 本轮**只记录、不改代码**(修复另开任务,修时再按 CLAUDE.md 走 bump 版本 / CHANGELOG / changelog.html)。
> 每发现一个 bug 立即追加到下方「Bug 列表」并提交推送,防止会话中断丢失。

## 中断恢复说明(给下一个会话)

1. 先读本文件。「进度」表里 ✅ = 已审完,🔶 = 审了一部分(备注写到哪了),⬜ = 未审。
2. 从第一个 🔶 / ⬜ 继续;Bug 编号接着最后一个往下编(`BUG-NNN`)。
3. 每审完一个模块就把状态改成 ✅ 并提交推送。

## 严重度定义

| 级别 | 含义 |
|---|---|
| **P0** 致命 | 安全漏洞(远程可利用)/ 数据丢失 / 热点断网 / 开机卡死或循环崩溃 |
| **P1** 严重 | 功能结果错误、用户可见的错误行为、常见路径崩溃 |
| **P2** 一般 | 边界条件、资源泄漏、并发竞态、少见路径出错 |
| **P3** 轻微 | 代码质量、日志 / 文档与代码不符、潜在隐患 |

## 进度

2026-10-19 起按用户要求改为 **12 个子 Agent 并行审查**:每个子审查员只写自己的记录文件 `docs/audit/NN-*.md`(Bug 编号带前缀 A1–A12),主会话后台每 3 分钟自动提交推送一次。各文件里的「已审文件」一节就是该模块的进度;文件末尾有「## 小结」= 该模块审完。

| # | 模块 | 记录文件 | 前缀 | 状态 |
|---|---|---|---|---|
| 0 | 自动化检查 | 本文件下方「自动化检查结果」 | — | ✅ |
| 1 | httpd 安全面(鉴权 / token / 中间件 / 配对 / 远程端口 / TLS / 限流) | `docs/audit/01-httpd-security.md` | A1 | 🔶 审查中 |
| 2 | httpd 动作(action*.go / 规则包 / 导出 / 合并) | `docs/audit/02-httpd-actions.md` | A2 | 🔶 审查中 |
| 3 | httpd 网络(DNS 接管 / 转发 / 报文解析 / 配额 / 连接 / 邻居) | `docs/audit/03-httpd-net.md` | A3 | 🔶 审查中 |
| 4 | httpd 识别(应用时长 / 前台模型 / 指纹 / 新应用发现) | `docs/audit/04-httpd-ident.md` | A4 | 🔶 审查中 |
| 5 | httpd 统计 / 功耗 / 自检 / 模拟 | `docs/audit/05-httpd-stats.md` | A5 | 🔶 审查中 |
| 6 | dpid 抓包解析(capture / cmd/dpid / bytestats / BPF) | `docs/audit/06-dpid-capture.md` | A6 | 🔶 审查中 |
| 7 | dpid output / alert / apkscan / appmeta | `docs/audit/07-dpid-output.md` | A7 | 🔶 审查中 |
| 8 | 看门狗 + devscan / neigh / nlroute / procfind / devname 等 | `docs/audit/08-watchdog.md` | A8 | 🔶 审查中 |
| 9 | C:hotspotd / launcher / clsact_ctl / tc_netlink / BPF | `docs/audit/09-c-daemons.md` | A9 | 🔶 审查中 |
| 10 | 开机脚本 + bin 核心(tc / iptables / hnc_json / 锁 / v6 / 回滚…) | `docs/audit/10-shell-core.md` | A10 | 🔶 审查中 |
| 11 | bin 其余脚本 | `docs/audit/11-shell-rest.md` | A11 | 🔶 审查中 |
| 12 | 前端 webroot + CI + tools | `docs/audit/12-frontend-ci.md` | A12 | 🔶 审查中 |

**中断后续审**:看哪个记录文件没有「## 小结」,按它「已审文件」之外的范围续审(范围见文件开头)。

## 自动化检查结果(2026-10-19,基线 44045d0)

- `go vet ./...`:httpd、dpid 两个模块都是 0 条。
- `go test -race -count=1 ./...`:httpd、dpid 全部通过,没有数据竞争报告。
- `golangci-lint`(staticcheck / ineffassign / unused / nilerr / gosec 等):httpd 510 条、dpid 136 条,绝大多数是 gosec 文件权限(0644/0755)、errcheck、De Morgan 风格建议这类噪音。值得人工核实的已分派给对应子审查员:
  - nilerr(err≠nil 却返回 nil):httpd `jsoncache.go:62`、`dns_wire.go:210`;dpid `alert/anomaly.go:80`、`capture/rawsocket.go:180,375`、`cmd/dpid/main.go:493`、`cmd/dpid_replay/main.go:137`、`devname/resolve.go:537`、`output/ip_app_map.go:204`
  - 无效赋值:`dns_wire.go:487`、`dpi_eval.go:373,375`、`api_discover.go:586`、`selfcheck.go:689`、`app_time.go:704`、`m4_owner.go:344`、`native.go:258`、`apkscan/scan.go:216`、`output/classify.go:76`
  - 未使用(疑似漏接):`middleware.go:283 isWritePath`、`server.go:1072 filterByMAC`、`compat_report.go:284 dispatchCompatReport`、`flow_cls.go:39 clsBigCats`、`capture/parse.go:700 parseTLSClientHello` 等

## Bug 列表

<!-- 新条目追加在最后。格式:
### BUG-NNN [P?] 一句话标题
- **位置**:`path:line`
- **现象 / 触发**:
- **原因**:
- **建议修复**:
-->

各模块的 Bug 见上表对应的 `docs/audit/NN-*.md`;全部审完后在这里汇总成总表(按严重度排序)。
