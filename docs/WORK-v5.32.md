# 工作文档:HNC v5.32.0「收尾 + 正式版」

> 交给接手开发的 AI 编程助手执行。**请完整读完再动手**,第 2 节「边界」和第 3 节「测试纪律」是硬约束。
> 背景:`docs/ROADMAP.md`、`docs/WORK-v5.31.md`(**特别是 §8「有问题」的定义 —— 本版的退路规则靠它**)、`CHANGELOG.md` 5.30 / 5.31 各 rc。
> 基线:v5.31.0-rc1 审查修复之后的最新提交。**本版先出 `v5.32.0-rc1`,维护者真机回归通过后再去掉 `-rc` 出正式版。**

---

## 0. 这一版做什么

不加新功能。把 v5.30 / v5.31 的账还清,收成一个能长期用的正式版。

| 顺序 | 任务 | 一句话 |
|---|---|---|
| T1 | 真机反馈修复 | 维护者在 v5.30 / v5.31 rc 上验出来的问题(开工前由维护者补进 §4 T1 的清单) |
| T2 | 退路规则落地 | v5.31 rc 有问题 → 设备发现默认值改回 C 版;没问题 → 保持 Go 版 |
| T3 | 已知小 bug 收口 | 下面列的 4 条 |
| T4 | 瘦身 | 删 shell guard / Go supervisor;方案 A 稳了再删 hotspotd 里停用的发现代码 |
| T5 | 文档 | README / ROADMAP / CODEMAP / API / 用户向说明 |
| T-last | 版本:先 rc,验完出正式版 | |

做不完时按 T2 > T1 > T3 > T5 > T4 取舍。**T4 宁可不做,也不能为了瘦身让正式版多一分风险。**

---

## 1. 现状(必读)

- **设备发现**:v5.31 起由 Go 看门狗做(方案 A),hotspotd 带 `--no-discovery` 只管硬件加速兜底;开关 `data/m4_owner`(`go` / `c`),默认值是 Go 里的一个常量(见 v5.31 T3)。C 版发现代码还在。
- **dpid 守护**:v5.30 起只用 C `hnc_launcher` + Go 看门狗(M5);`run/wd_m5.disabled` 能退回 v5.29 的三选一,退回路径要用到 `bin/hnc_dpid_guard.sh` 和 `src/dpid/cmd/dpid_supervisor/`。
- **模拟设备** `test/sim/`:不用手机验设备发现,`HNC_SIM=1 sh test/run_all.sh`。
- **已知小 bug**(T3 处理):
  1. 「新发现的应用」起名的启动指纹这条线索从 v5.28 起没生效:`daemon/hnc_httpd/api_discover_suggest.go` 约 244 行 `strList(g["domains"])` —— `g["domains"]` 是对象数组,`strList` 只认字符串数组,结果永远是空,启动指纹一次都没参与过起名。
  2. 设备合并(`daemon/hnc_httpd/mac_merge_action.go` `deviceMerge`)把旧 MAC 的设置迁到新 MAC 时漏了 v5.30 新增的 `app_qos`(「按应用分优先级」开关),合并后这个开关丢了。
  3. `src/dpid/cmd/dpid_replay/replay_test.go` 末尾多一个空行,`gofmt -l` 报它(v5.29 遗留)。
  4. 应用感知 QoS 只管下载方向、只管 IPv4 —— **不是 bug,是范围**,在 `changelog.html` / 设备卡说明里写清楚,不扩功能。

---

## 2. 边界(硬约束)

1. 隐私与安全红线照旧。
2. **不加新功能、不改行为**,除非是 T1 / T3 列出的修复。方案 B(hotspotd 彻底退役、动硬件加速兜底)**不进本版**。
3. API 兼容、持久化格式只增不改;不加第三方依赖;不改 `go.mod` 的 `go` 版本;`CGO_ENABLED=0`。
4. 删代码(T4)前先证明没有调用方:`grep` 结果、开机流程、看门狗、自检、打包清单(`bin/artifact_sanity_check.sh`、`.github/workflows/build.yml`)逐个核对,写进提交说明。
5. `service.sh` / `post-fs-data.sh` 只改 T4 指明的地方;插入 / 删除点不在注释里。

---

## 3. 测试纪律

原样沿用 `docs/WORK-v5.30.md` §3 的 9 条和 `docs/WORK-v5.31.md` §3 的第 10、11 条。

---

## 4. 任务

### T0 · 记录基线
跑第 6 节全部自检(含 `HNC_SIM=1 sh test/run_all.sh`),结果写进提交说明(空提交)。

### T1 · 真机反馈修复
维护者开工前把 v5.30 / v5.31 rc 真机验收发现的问题列在这里(每条:现象、复现步骤、日志 / 截图位置)。每条一个提交、配「改动前会失败」的测试;复现不了的写清楚试过什么,不硬改。

- (待维护者补充)

### T2 · 退路规则落地
- 维护者按 `docs/WORK-v5.31.md` §8 判断 v5.31 rc 有没有「问题」,结论写在这里:**(待维护者填写:有 / 没有,哪一条)**。
- **有问题**:把 `m4OwnerDefault` 改成 `c`,配一条测试(没有 `data/m4_owner` 时写者是 hotspotd、Go 写者不跑);changelog 写明「设备发现默认用回旧版,新版可在 …… 手动打开」。Go 版代码和开关保留。
- **没问题**:默认值保持 `go`,不改代码;changelog 写明「设备发现已换成新版,旧版可用 `data/m4_owner` 写 `c` 退回」。
- **不论哪种,正式版照常发,不为它推迟。**

### T3 · 已知小 bug 收口(§1 的 1–3,第 4 条只改文案)
- 启动指纹:让组内域名正确取出(对象数组里的域名字段),配测试:构造一个与某个可用应用特征 token 重合 ≥ 2 的组,旧代码下建议名里没有 `startup` 来源、新代码下有。
- 设备合并:`app_qos` 随其它设置一起迁,配测试(旧 MAC 开着 → 合并后新 MAC 也开着;旧代码下失败)。顺手核对 v5.29 以后新增的其它每设备字段有没有同样漏迁,有就一起补并各配测试。
- `gofmt -w src/dpid/cmd/dpid_replay/replay_test.go`。

### T4 · 瘦身
1. **删 shell guard / Go supervisor**(`bin/hnc_dpid_guard.sh`、`src/dpid/cmd/dpid_supervisor/`),**前提**:维护者确认 v5.30 / v5.31 真机上 M5 正常(杀 dpid 被 launcher 拉回、杀 launcher 被看门狗拉回)。删的同时去掉 `run/wd_m5.disabled` 的退回分支(没东西可退了),以及开机选择、看门狗、自检、清理脚本、打包清单、`build.yml` 里对它们的引用;测试同步改。前提不满足就整条不做。
2. **删 hotspotd 里停用的发现代码**,**前提**:T2 结论是「没问题」(Go 版保持默认)。不满足就不删。满足时也只删发现 / 名字解析 / `devices.json` 写入相关代码,硬件加速兜底与控制接口一行不动;`data/m4_owner=c` 的退路随之消失 —— 在 changelog 里写明,并把 `m4OwnerDefault` 与开关一起删掉。**拿不准就不删**,留到正式版之后的小版本。

### T5 · 文档
- `README.md`:功能清单与当前一致;安装 / 升级 / 回退说明(含 v5.29 的自动回滚、`data/m4_owner`)。
- `docs/ROADMAP.md`:v5.32 行标 ✅;正式版之后:方案 B(hotspotd 退役)放 6.0 或正式版后的小版本。
- `docs/CODEMAP.md` / `docs/API.md`:与代码一致(删掉的东西同步删)。
- `webroot/changelog.html`:正式版一段大白话总结「从 5.19 到 5.32 都改了什么、怎么退回」。

### T-last · 版本
- 先出 rc:`version=v5.32.0-rc1`,`versionCode=5320001`;后续 rc 依次 +1。
- 维护者真机回归通过后出正式版:`version=v5.32.0`,`versionCode=5320100`(**必须大于所有 rc 的 versionCode**,否则管理器不认为是升级)。`bin/version_consistency_check.sh` 通过。
- `CHANGELOG.md` 正式版一节:列出相对上一个正式版的全部用户可见变化(可以引用各 rc 小节)。

---

## 5. 不做(明确排除,别碰)

| 不做 | 原因 |
|---|---|
| 方案 B:hotspotd 彻底退役、硬件加速兜底搬进 Go | 出错表现是「限速悄悄不生效」,不适合放进最后一版;放 6.0 或正式版后的小版本 |
| 新功能(QoE 闭环、场景模式、上行 QoS、IPv6 QoS …) | 正式版只收尾 |
| 为了 T4 改动行为 | 瘦身只删死代码 |

---

## 6. 自检命令

沿用 `docs/WORK-v5.31.md` §6 的全部命令(含本机编 hotspotd 与 `HNC_SIM=1 sh test/run_all.sh`)。删了二进制 / 脚本的(T4),再跑一次 `sh bin/artifact_sanity_check.sh`(有产物时)和 `sh bin/ci_preflight.sh`,确认必需文件清单同步改了。

---

## 7. 验收清单

- [ ] T1 每条修复有测试、在旧代码下失败。
- [ ] T2 结论写进本文档,代码 / changelog 与结论一致,有测试锁住默认值。
- [ ] T3 三条修复各有测试;第 4 条文案已改。
- [ ] T4 做了的话:删除前的调用方核对写进提交说明;删后全部自检通过;做不了的写明原因。
- [ ] 第 6 节全部通过;gofmt 干净(含 `replay_test.go`)。
- [ ] 版本号(rc → 正式版)、CHANGELOG、changelog.html、README、ROADMAP、CODEMAP、API.md 已更新。

**维护者真机回归(正式版前)**:全功能过一遍 —— 设备列表 / 改名 / 限速 / 封锁 / 延迟模拟 / 配额 / 分时段 / 应用限速 / 按应用分优先级 / DPI 统计 / 新发现的应用 / 自检 / 导出诊断包 / 升级与回滚。

---

## 8. 提交方式

- 从基线新建分支 `ai/v5.32`,先记下 `BASE=$(git rev-parse HEAD)`。每个任务一个提交,中文提交信息:`v5.32 T1: ...`。署名用你自己的模型名。
- 没有推送权限:`git format-patch $BASE..ai/v5.32 -o patches/`,README 写上 `$BASE` 和第 6 节命令的**实际输出**;有推送权限:推到 `ai/v5.32`,**不要推 main**。
- 不要改 `CLAUDE.md`。

## 9. 做不完 / 遇到问题怎么办

- 代码和本文档对不上:以代码为准,在提交说明里写清怎么处理的。
- 必须越过第 2 节边界才能做:停下,该任务不提交,写清问题交回;其余任务照常。
- T4 的前提拿不准:不做,写明原因。
