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
- action_v511.go（含 /api/dpi_rules 导入、/api/rules_export、/api/run_status）
- action_v512.go
- rulepack.go

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

### A2-002 [P2][确认] 规则包导入没有总量上限：_imported.json 超过 dpid 的 1 MiB 子集上限后整文件被跳过，全部已导入规则静默失效；超过 2 MB 后下次导入还会清掉旧导入
- **位置**：`daemon/hnc_httpd/rulepack.go:756-765`、`rulepack.go:1013-1027`；对照 `src/dpid/output/rule.go:41`、`rule.go:310-314`
- **触发 / 现象**：单包上限只校验“本包 ≤ 5000 条后缀、请求体 ≤ 1.2 MB”，写出的 `_imported.json` 是 MarshalIndent 并累加历史导入。实测估算：5000 条规则各 1 个后缀（后缀约 24 字符、应用名约 6 字符）写出就有 1,014,001 字节，后缀或应用名再长一点（中文应用名每字 3 字节），或累计导入 3 个 1000×5 的包，就会超过 1,048,576 字节。dpid `loadL3RulesFromDir` 对任何超过 `externalRulesSubsetMaxBytes = 1024*1024` 的子集文件打 WARN 后 `continue`，整份 `_imported.json` 不再加载。此时导入报告仍是 `ok:true, added N`，`/api/dpi_rulepack` 摘要也照常显示已导入条数，但之前导入、本来能用的规则也一起失效。文件继续增长超过 2 MB 后，`importRulepack` 读旧文件时 `len(b) <= 2<<20` 不成立，`existing` 被当成空，下一次导入会把所有旧导入覆盖掉（数据丢失）。`fp_imported.json`（读上限 4 MB）也有同样的“读不进就当空，然后覆盖”问题。
- **原因**：
  ```go
  if b, err := os.ReadFile(impPath); err == nil && len(b) <= 2<<20 {   // 读不进 → existing 为空
  ...
  b, _ := json.MarshalIndent(doc, "", "  ")
  if err := writeFileAtomic(impPath, b); err != nil {                  // 写出不看大小
  ```
  dpid 侧：`if fst.Size() > externalRulesSubsetMaxBytes { log.Printf("WARN ... skip oversized"); continue }`
- **建议修复**：导入前用合并后的结果预估输出大小，超过 dpid 上限（建议留余量，并用紧凑 Marshal）时整包拒绝并给出明确提示；现有文件超限或解析失败时返回错误，不要当空覆盖。

### A2-003 [P2][确认] /api/export 时间范围检查可被 int64 溢出绕过，dayFileKeys 近乎无限循环并持续分配内存，httpd 卡死或被 OOM 杀
- **位置**：`daemon/hnc_httpd/api_export.go:105-116`、`api_export.go:260-262`（`addDailyJSONLToZip`）；循环体在 `stats_days.go:36-57`
- **触发 / 现象**：已鉴权客户端（远程配对 token，或本机 secret）发 `POST /api/export`，body 为 `{"from":-5000000000000000000,"to":5000000000000000000}`。`req.To-req.From` 溢出成 -8446744073709551616，`> maxRange` 不成立，检查被绕过。随后 `dayFileKeys` 从公元前约 1584 亿年按天循环到公元后约 1584 亿年，大约 1.16e14 次迭代，每次都往 `keys`/`seen` 里追加。实测 500 万次迭代就要约 2 秒，内存线性增长，最终 httpd 被 OOM 杀（期间 CPU 满载，exportMu 一直被占，其他导出请求返回 409）。scratchpad 复现：`A2/ovf/main.go`。
- **原因**：
  ```go
  if req.From > req.To { req.From, req.To = req.To, req.From }
  const maxRange = int64(24 * 3600)
  if req.To-req.From > maxRange {          // 减法溢出为负数，检查失效
  ...
  keys := dayFileKeys(time.Unix(from, 0), time.Unix(to, 0))
  ```
- **建议修复**：先把 from/to 夹到合理区间（例如 [0, now+1d]）再做差，或者用 `req.From < req.To-maxRange` 这类不会溢出的写法；`dayFileKeys` 自身也应限制最多迭代的天数。

### A2-004 [P3][确认] exports/ 目录没有保留上限，也没有删除接口，导出产物只增不减
- **位置**：`daemon/hnc_httpd/api_export.go:117-195`（另有 action_v511.go:170 诊断包、rulepack.go:632 规则包、compat_report.go:263、selfcheck_api.go:203、dpid capture/recorder.go:336 抓包都写到同一目录）
- **触发 / 现象**：每次 `/api/export` 都按秒命名生成一个新 zip（24h 窗口会打包当天最多约 32 MB 的 self_attrib 加上 stats），诊断包、抓包 pcap、自检报告也都落在 `exports/`。全仓库没有任何代码清理这个目录（bin/、service.sh、httpd 里 grep 不到），WebUI 也没有删除接口。长期使用会持续占用 /data；已鉴权客户端在写限流（60 次/分钟）内连续导出，几分钟内就能写入 GB 级数据。middleware.go:328-330 的注释承认“从不清理”，但只加了限流。
- **原因**：`os.Rename(tmp, full)` 之后没有任何按数量或总大小的轮转；`apiExportList` / `apiExportFile` 只读。
- **建议修复**：导出成功后按类型保留最近 N 个，或按总大小上限删除最旧的；同时提供 `export_delete` 动作。

### A2-005 [P2][确认] 设备合并的生产实现 realMergeOps.rule 不认识 app_qos_set：旧设备开着「按应用分优先级」时合并必失败并整体回滚
- **位置**：`daemon/hnc_httpd/mac_merge_action.go:70-98`（switch），调用点在 `mac_merge_action.go:480`、`:485`、`:528`、`:533`、`:848`
- **触发 / 现象**：旧 MAC 在 rules.json 里 `app_qos=true`，新 MAC 没开，在设备卡上执行 `device_merge`。阶段一 rules 步骤执行 `run("app_qos_set", …)`，`realMergeOps.rule` 落到 `default` 分支，返回 `{OK:false, Error:"unknown action"}`，整个合并回滚，前端看到“步骤 rules 失败, 已回滚: app_qos_set …: unknown action”。也就是说，开了按应用分优先级的随机 MAC 设备永远无法合并。v5.32 T1 本来要修的“合并会丢 app_qos”在生产环境变成了“合并必失败”。force 路径 `qosOffNew` 同样失败。双方都开着时，阶段二 `clearOld("app_qos_set", …)` 恒报警告“旧 MAC 清理未完成: app_qos_set: unknown action”。单测之所以没发现，是因为 `mac_merge_test.go:189` 的 fakeMergeOps 自己实现了 app_qos_set 分支。
- **原因**：
  ```go
  switch action {
  case "rule_set": ... case "device_whitelist_set": ... case "rules_device_remove": ...
  default:
      r = actionResp{OK: false, Error: "unknown action"}   // 缺 case "app_qos_set"
  ```
- **建议修复**：在 `realMergeOps.rule` 里加上 `case "app_qos_set": r = actionAppQosSet(h, p)`，并补一个走 realMergeOps 的测试（或让 fake 只模拟脚本层、复用真实 switch）。

### A2-006 [P3][确认] 合并后 mergeCtlUsage 只累加 MonthBytes、不累加 MonthRx/MonthTx，新 MAC 本计费月的上下行拆分失真（上行恒为 0）
- **位置**：`daemon/hnc_httpd/mac_merge_action.go:1024-1048`；读取端 `quota_global.go:97-104`
- **触发 / 现象**：旧 MAC 本月已有用量时执行合并。之后新 MAC 的 `MonthBytes = 旧 + 新`，`MonthRx + MonthTx` 却只有新 MAC 自己的部分，两者不再相等。`MonthUsageSplit` 遇到不等就走“升级过渡”分支，返回 `rx = MonthBytes, tx = 0`。此后每次 `usageAcc.add` 都同步累加三者，差值一直保留，整个计费月 `/api/usage_month` 对这台设备显示的上行都是 0、下行偏大。配额判定用的是 MonthBytes，不受影响。
- **原因**：
  ```go
  if u.MonthKey == o.MonthKey {
      u.MonthBytes += o.MonthBytes          // 漏了 u.MonthRx += o.MonthRx; u.MonthTx += o.MonthTx
  }
  ```
- **建议修复**：同周期合并时一并累加 `MonthRx`/`MonthTx`。

