# A11 审查记录：bin/ 其余 shell 脚本

- 基线版本：v5.33.0-rc2（versionCode 5330002）
- 审查员前缀：A11
- 范围：bin/ 下除以下文件外的全部脚本（含 bin/diag/diag.sh）：
  tc_manager.sh、iptables_manager.sh、apply_device_rule.sh、hnc_json、json_set.sh、json_set_batch.sh、
  hnc_lock.sh、hnc_common.sh、hnc_constants.sh、hnc_iface.sh、v6_sync.sh、watchdog.sh、
  hnc_offload_guard.sh、hnc_rollback.sh、hnc_runtime_sync.sh、hnc_proc.sh、hnc_compat.sh、hnc_clsact_sync.sh
- 运行环境：Android /system/bin/sh（mksh）+ toybox

## 已审文件

## Bug

