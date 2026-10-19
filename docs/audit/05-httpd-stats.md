# A5 审计记录：hnc_httpd 统计 / 功耗 / 自检 / 模拟数据

- 基线版本：v5.33.0-rc2
- 审查员前缀：A5
- 范围（daemon/hnc_httpd/）：phone_usage.go、phone_usage_sim.go、phone_usage_upstream.go、selfcheck.go、selfcheck_api.go、stats_calibration.go、stats_days.go、stats_health.go、power_activity.go、power_hooks.go、power_sched.go、power_stats.go、clock_guard.go、proc_health.go、sim.go、sim_merge.go
- 只记录、不改代码。严重度：P0 远程可利用/数据丢失/断网/开机卡死；P1 常见路径功能错误或崩溃；P2 边界、泄漏、竞态、少见路径；P3 轻微隐患、文档不符。

## 已审文件

## Bug

