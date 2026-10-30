# A7 审查记录：dpid output / alert / apkscan / appmeta

- 基线版本：v5.33.0-rc2
- 审查员前缀：A7
- 范围：
  - `src/dpid/output/` 下全部非测试文件（auto_expand、candidate、classify、cluster、conntrack、devid、dfp、discover、encdns、entity、evidence_ledger、flow、flowlog、flywheel_exclude、history、ip_app_map、ipname、ja4family、label_samples、qtp、rule、self_attrib、shared_infra、state）
  - `src/dpid/alert/`
  - `src/dpid/apkscan/`（解析 APK / 文件，属于不可信输入）
  - `src/dpid/appmeta/`
- 原则：只记真 bug，只记录不改代码。

## 已审文件

- `src/dpid/alert/alert.go`（含 lint 核实：无）
- `src/dpid/alert/anomaly.go`（lint「:80 err 不为 nil 却返回 nil」核实：`sumByMAC` 永远返回 nil，该分支是死代码，注释写明「当天文件不存在不算错」，属有意为之，不记 bug）
- `src/dpid/alert/export.go`
- `src/dpid/appmeta/appmeta.go`、`appmeta/pmlabels.go`、`appmeta/labels.go`
- `src/dpid/apkscan/hosts.go`、`apkscan/daemon.go`
- `src/dpid/apkscan/scan.go`（lint「:216 counts 赋值无效」核实：`counts = nil` 只是给 GC 的提示，下一轮循环就重新赋值，无害，不是 bug）
- `src/dpid/output/classify.go`（lint「:76 pri 赋值被浪费」核实：switch 每个分支都会重新赋值，纯风格，不是 bug；后缀匹配按 '.' 边界切尾串，`evilqq.com` 不会命中 `qq.com`）
- `src/dpid/output/conntrack.go`（lint「:135 parseConntrackLine 未使用」核实：注释写明留作以后按协议/状态分桶，主循环只数行数，没有漏接）
- `src/dpid/output/flow.go`（lint「:51 lastBucketPkts、:245 topFlowsByBytes 未使用」核实：只是没删的字段/调试函数；`background_flows_pct` 全仓没有消费方，持久度算法即使不准也无外部影响，不记）
- `src/dpid/output/ip_app_map.go`（lint「:204 写 .flat 失败返回 nil」核实：注释写明 best-effort，有意为之）

## Bug

### A7-001 [P3][确认] alerts.jsonl 没有任何滚动截断，文档却声称 alert.Append 负责截断
- **位置**：`src/dpid/alert/alert.go:265`（`Append`）；文档：`bin/pitfall_lint.sh:14-15`、`src/dpid/alert/alert.go:10-11`
- **触发 / 现象**：`run/alerts.jsonl` 由 httpd（配额、DNS 接管、配对爆破、合并 MAC、应用时长）和看门狗（陌生设备、异常流量）共同追加，全仓找不到任何截断/轮转代码（`grep alerts.jsonl` 只有写入与读取），`post-fs-data.sh` 也只清 `run/*.pid`。文件会永久增长；`ListRecent` 每次 `/api/alerts` 都 `make` 并读最后 4MB。同时 pitfall_lint P4 的说明写「alert.Append 之外不许直接写 alerts.jsonl（绕过锁与滚动截断）」，包注释写「trivial to truncate when older than 30 days」，与代码不符。
- **原因**：
  ```go
  f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
  ...
  _, err = f.Write(append(b, '\n'))   // 只追加，从不截断
  ```
- **建议修复**：在 `Append` 里（持 flock 时）按大小阈值（如 >1MB）保留尾部若干行后原子替换；或把文档改成实话。

### A7-002 [P2][疑似] apkscan 对 dex 条目没有总解压预算，重叠条目 zip 炸弹可让扫描 goroutine 连烧数天 CPU
- **位置**：`src/dpid/apkscan/scan.go:442`（`classify` 只按名字认 `classes*.dex`）、`scan.go:485-497`（逐条 `f.Open()` + `io.LimitReader(rc, maxEntryRead)`，`maxEntryRead = 512 << 20`）
- **触发 / 现象**：`/data/app` 下某个 APK 的中央目录里放 N 个名为 `classes2.dex`…`classesN.dex` 的条目，全部指向同一段 512KB 的 deflate 数据（解压后 512MB，Go 的 `archive/zip` 不检查条目重叠，也不校验本地头文件名与中央目录是否一致）。本地复现：77KB 的文件、200 个条目各解压 64MB，`Scan` 20 秒超时仍未结束；单个 512MB 条目在 x86 上耗时 4.6 秒。65535 个条目（文件约 4MB）≈ 65535×4.6s ≈ 84 小时，手机上更慢。扫描不结束就不会写缓存，dpid 每次重启 10 分钟后又从头开始烧。即使不用重叠，400MB 上限内放 800 个 512KB 的 dex 条目也要扫约 1 小时（之后才进缓存）。`MaxAPKBytes` 只限制压缩后大小，限制不了解压量。
- **原因**：
  ```go
  case strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") && !strings.Contains(name, "/"):
      return kindText            // dex 不看 UncompressedSize64，也不数条目个数
  ...
  err = s.scanStream(ctx, io.LimitReader(rc, maxEntryRead), kind == kindARSC, emit) // 每个条目各 512MB
  ```
- **还缺的证据**：没在真机上验证 PackageManager 会不会接受这种 APK（libziparchive 解压时会比对本地头文件名，但安装阶段走 v2/v3 签名时不逐条解压）。Go 侧行为已复现。
- **建议修复**：每个 APK 设解压总预算（如 256MB，用完即停并记入缓存）；记下已打开过的本地头偏移，重叠的条目直接跳过；dex 条目也检查 `UncompressedSize64` 和条目个数上限。

