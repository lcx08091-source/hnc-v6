# A2 审计记录：hnc_httpd 动作处理（daemon/hnc_httpd/action*.go 等）

- 基线版本：v5.33.0-rc2
- 审查员：A2（子审查员）
- 范围：daemon/hnc_httpd/ 下 action.go、action_app_limit.go、action_app_qos.go、action_candidate.go、action_dev_sqm.go、action_device_rename.go、action_flywheel.go、action_global_shaper.go、action_hotspot_iface_set.go、action_qdisc.go、action_v5.go、action_v511.go、action_v512.go、rulepack.go、api_export.go、mac_merge_action.go、compat_report.go、capture_record.go、watchdog_actions.go、alert_config.go、offload_guard.go、rollback.go、app_limit_shared.go
- 重点：参数校验、exec/脚本参数注入、JSON 原子写与 run/json.lock 互斥、导入导出路径穿越与大小限制、错误码、并发。

## 已审文件

- action.go（handleAction / dispatchAction / runBin / runExe / runBinDetached / clsact 系列；lint 778/827/933/1037：脚本名均为字面量、hncDir 来自启动配置、参数走 argv，未发现注入）
- action_v5.go
- action_app_limit.go
- action_app_qos.go
- action_candidate.go
- action_dev_sqm.go
- action_device_rename.go
- action_flywheel.go
- action_global_shaper.go
- action_hotspot_iface_set.go
- action_qdisc.go

## Bug

### A2-001 [P3][确认] cache_clear 删除的是不存在的路径，「清缓存」按钮恒为空操作
- **位置**：`daemon/hnc_httpd/action_v511.go:157-165`
- **触发 / 现象**：WebUI 维护页点「清缓存」（webroot/js/main.js:363 → `api.action('cache_clear')`），恒返回 `OK removed 0 file(s)`，前端提示「缓存已清理」，但真实的主机名缓存 `data/hostname_cache.json`（devname.Resolver / 看门狗 m4_owner.go:62 使用）原封不动，设备名错误缓存无法通过 UI 清掉。
- **原因**：
  ```go
  for _, f := range []string{"hostname_cache", "dev_class_cache"} {
      if err := os.Remove(filepath.Join(hncDir, "cache", f)); err == nil {
  ```
  全仓库没有任何写者产生 `$HNC/cache/hostname_cache` / `$HNC/cache/dev_class_cache`（grep 只有这一处引用），缓存早已迁到 `data/hostname_cache.json`。
- **建议修复**：改为删除 `data/hostname_cache.json`（并通知看门狗的 devname 写者丢弃内存副本，否则会被下一轮回写），或删掉该按钮；返回值在删 0 个文件时不要报“已清理”。

