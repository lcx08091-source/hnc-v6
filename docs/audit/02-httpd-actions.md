# A2 审计记录：hnc_httpd 动作处理（daemon/hnc_httpd/action*.go 等）

- 基线版本：v5.33.0-rc2
- 审查员：A2（子审查员）
- 范围：daemon/hnc_httpd/ 下 action.go、action_app_limit.go、action_app_qos.go、action_candidate.go、action_dev_sqm.go、action_device_rename.go、action_flywheel.go、action_global_shaper.go、action_hotspot_iface_set.go、action_qdisc.go、action_v5.go、action_v511.go、action_v512.go、rulepack.go、api_export.go、mac_merge_action.go、compat_report.go、capture_record.go、watchdog_actions.go、alert_config.go、offload_guard.go、rollback.go、app_limit_shared.go
- 重点：参数校验、exec/脚本参数注入、JSON 原子写与 run/json.lock 互斥、导入导出路径穿越与大小限制、错误码、并发。

## 已审文件

## Bug

