# A4 审查记录：hnc_httpd 应用识别 / 前台判断 / 流量分类 / 新应用发现

- 基线版本：v5.33.0-rc2
- 审查员前缀：A4
- 范围（daemon/hnc_httpd/）：app_time.go、app_usage.go、fg_engagement.go、fg_hmm.go、fg_model.go、flow_cls.go、flow_shape.go、fp_learn.go、fp_user_rules.go、startup_fp.go、traffic_ident.go、self_fg_truth.go、dpi_eval.go、dpi_eval_discover.go、api_discover.go、api_discover_shared.go、api_discover_suggest.go、api_dpi_history.go、api_dpi_v53.go
- 只记录真 bug，不改代码。

## 已审文件

## Bug

### A4-001 [P2][确认] 流量形状分类器样本池无上限：生产路径绕过 fcPoolAdd，内存与重训耗时只增不减
- **位置**：`daemon/hnc_httpd/flow_cls.go:371`（对照 `flow_cls.go:178` 的 `fcPoolAdd`）
- **触发 / 现象**：热点客户端持续使用（每条已识别、≥3 轮采样且已结束的流都收一条样本），httpd 长期不重启。`fcPool` 永不淘汰：每条样本约 150 字节，日均上万条连接时每天约 1.5 MB、按周按月线性涨；每 30 分钟重训（`flow_cls.go:390`）和每次 `/api/dpi_eval`（`flow_cls.go:436`）都要把整个池复制一遍再全量训练，耗时随之线性增长。文件头写的「池按类上限 2000 条、按时间淘汰」实际不成立。
- **原因**：唯一实现上限淘汰的 `fcPoolAdd` 只在 `flow_cls_test.go` 里被调用；生产路径 `flowClsTick` 直接追加：
  ```go
  fcPool = append(fcPool, added...)   // flow_cls.go:371，没有按类上限，也没有按时间淘汰
  ```
  测试 `flow_cls_test.go:124/246` 只验证了 fcPoolAdd 这个没人调用的函数，把「有上限」锁成了期望，掩盖了生产路径无上限。
- **建议修复**：`flowClsTick` 改成逐条走 fcPoolAdd（或在追加后按类裁到 fcPoolPerCat）；测试改为驱动 flowClsTick 来验证上限。

### A4-002 [P3][确认] 流量形状分类器「平均包长」一维的分箱边界单位错了，该维恒落第 0 箱（特征失效）
- **位置**：`daemon/hnc_httpd/flow_cls.go:113`（边界）、`flow_cls.go:146`（取值）
- **触发 / 现象**：任何连接。平均包长 psz 最大也就 1500 字节左右（GRO 聚合也不超过 64 KB），`log10(psz+1)` 最大约 3.2（GRO 极端约 4.8），永远小于第一条边界 5.2，所以第 7 维对所有样本都是 0 箱，训练和预测里这一维完全不提供信息；文件头和 CHANGELOG 宣称的「包长」特征实际不存在。
- **原因**：边界按自然对数（e^5.2≈181、e^7.3≈1480）或别的尺度写的，取值却用 log10：
  ```go
  {5.2, 5.9, 6.6, 7.3},    // 7  log10(平均包长 字节) ~160/500/1600/4k/…
  ...
  lg := func(x float64) float64 { return math.Log10(x + 1) }
  v[7] = fcBinOf(lg(f.psz), fcEdges[7])
  ```
  注释里的 160/500/1600/4k 对应的 log10 值应是 2.2/2.7/3.2/3.6。测试夹具 psz=1200/180/800 也全落 0 箱，所以测试没发现。
- **建议修复**：边界改成 log10 尺度（如 {2.2, 2.7, 3.2, 3.6}），并同步把 fcJSONVersion 加 1，让旧模型文件作废。

### A4-003 [P3][确认] 流量形状分类器的持久化模型在重启 30 分钟后被「只用重启后样本」训出的小模型覆盖
- **位置**：`daemon/hnc_httpd/flow_cls.go:388-399`
- **触发 / 现象**：httpd 重启（升级、看门狗拉起、关机重开）。样本池只在内存里，重启后为空；首轮读回 `data/flow_cls.json` 用上，但 30 分钟后的第一次重训只用这 30 分钟收到的少量样本训练，直接替换内存模型并覆盖写回文件，之前积累的模型丢掉。如果这 30 分钟里只收到一个大类的样本，NCat 里只有一类，`fcPredict` 对所有未识别连接都输出这一类、置信度 1.0。CHANGELOG 写的是「30 分钟增量重训」，实际是用内存池全量重训。
- **原因**：
  ```go
  if !haveModel || now.Sub(fcLastTrain) >= fcRetrainEvery {
      snap := append([]fcSample(nil), fcPool...)   // 只含本进程启动以来的样本
      if m := fcTrain(snap, now.Unix()); m != nil { // 没有最少样本数 / 最少类数门槛
          fcLiveModel = m
          _ = fcSaveModel(hncDir, m)                // 覆盖已存模型
  ```
- **建议修复**：把样本池（带上限）和模型一起持久化、启动时读回；或者在已存模型的计数上做增量合并；再加一个最少样本数 / 最少类数门槛，不够就不替换。

