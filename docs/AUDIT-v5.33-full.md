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

| # | 模块 | 状态 | 备注 |
|---|---|---|---|
| 0 | 自动化检查(go vet / golangci-lint / go test / gcc -Wall / sh -n / node --check / run_all.sh) | ⬜ | |
| 1 | httpd 安全面:auth / tokens / middleware / security_headers / server / webui_access / pair / remote_listener / tls / ratelimit / writelimit | ⬜ | |
| 2 | httpd 动作:action*.go(参数校验 → 调脚本) | ⬜ | |
| 3 | httpd 其余 API / 后台逻辑 | ⬜ | |
| 4 | dpid 抓包解析(capture/*,处理不可信报文) | ⬜ | |
| 5 | dpid output / 其余包 | ⬜ | |
| 6 | 看门狗 hnc_watchdog | ⬜ | |
| 7 | C:hotspotd / launcher / clsact_ctl / tc_netlink | ⬜ | |
| 8 | 开机脚本:post-fs-data.sh / service.sh / customize.sh / uninstall.sh | ⬜ | |
| 9 | bin 核心:tc_manager / iptables_manager / apply_device_rule / hnc_json / json_set* / hnc_lock / hnc_common / hnc_iface / v6_sync / watchdog.sh / offload_guard / rollback | ⬜ | |
| 10 | bin 其余脚本 | ⬜ | |
| 11 | 前端 webroot(XSS / 逻辑) | ⬜ | |
| 12 | CI / 构建 / tools | ⬜ | |

## Bug 列表

<!-- 新条目追加在最后。格式:
### BUG-NNN [P?] 一句话标题
- **位置**:`path:line`
- **现象 / 触发**:
- **原因**:
- **建议修复**:
-->

（暂无）
