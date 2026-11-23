# CLAUDE.md — 项目记忆与工程死定律 (v6.1 基线)

## 1. 沟通语言（用户长期偏好）
- 每次回复、代码注释说明、提交摘要与架构文档一律使用通俗直白的简体中文（全文零 Emoji）。技术名词、命令、API 路径与代码标识符保留英文；提及任何 `.sh` 脚本路径时统一带上 `./`、`./bin/` 或 `./test/` 前缀。

## 2. 真机基准与多机型现实约束
- **唯一已实机跑透的基准设备**：realme RMX5010 / ColorOS Android 16 / 内核 6.6 GKI / SukiSU（`magic_mount_rs`, `umount=false`）+ SuSFS。
- **已知真机特性**：
  1. ColorOS 16 / SukiSU 内核拦截 Go runtime `clone(CLONE_VFORK)` 返回 `EPERM`，守护子进程拉起必须经由 C 版 `hnc_launcher`（严禁退回纯 Go 直接守护 `fork/exec`）；控制面调用 Android 系统包装脚本（如 `content`、`settings`、`cmd`、`am`）时严禁清空 `BOOTCLASSPATH` / `SYSTEMSERVERCLASSPATH` 等 ART 运行环境变量，且能走原生 C++ Binder 服务（如 `dumpsys isub`、`dumpsys telephony.registry`）或 `/proc`、`/sys` 直读的绝不拉起 `app_process` Java 虚拟机。
  2. 运行期 `/system/bin` 可能被间歇卸载，系统命令调用必须优先走 Go 原生 Netlink/procfs 直读或 `./bin/hnc_env.sh` 的 `/data` 备份工具链垫片，并附带硬超时与进程组清理保护。
  3. 该内核缺省无 `sch_cake` / `sch_fq_codel`（低延迟自动降级），且开启系统级共享硬件加速时高通 BPF `tether_limit_map` / IPA 快路径可能截流。
- **跨机型谨慎原则**：天玑 MDDP/HNAT、三星 DIT、Google Tensor、展锐、MIUI/澎湃 OS `miui_net_*`、单网卡 `wlan0` AP 等路径未经全量真机实测，编写或修改兼容代码时必须检查节点读写权限失败与返回值，严禁假设 `sysfs`/`procfs` 节点一定存在或格式固定。

## 3. 全栈构建与二进制清单（6 大核心原生组件 + 辅助工具）
- 当前架构包含 **6 个核心原生组件**：`hnc_httpd` (`daemon/hnc_httpd`)、`hnc_dpid` (`src/dpid/cmd/dpid`)、`hnc_watchdog` (`src/dpid/cmd/hnc_watchdog`)、`hnc_launcher` (`src/launcher`，含 `fork_probe`)、`hotspotd` (`daemon/hotspotd`，含配套 `hnc_ipc` 与 `mdns_resolve`)、`hnc_clsact_ctl` (`daemon/clsact_ctl` + `daemon/tc_netlink/hnc_tc_ingress` + `src/dpid/bpf/hnc_clsact.bpf.c`)。
- 任何涉及 Go、C 或 eBPF 源码的改动，必须确保双架构（`arm64-v8a` 与 32 位 `armeabi-v7a`）均可零警告编译通过，并在 `.github/workflows/build.yml` CI 构建脚本中全量覆盖，严禁出现“改了源码但漏编二进制”的假发布。

## 4. 九条不可违背的工程死定律（违反任意一条视为构建失败）

### 死定律一：零假数据、零估算曲线、仿真环境物理隔离
- 生产路径（真机运行态）严禁出现任何硬编码假数据、模拟波形曲线、拍脑袋估算公式或假成功绿灯。
- 当底层内核计数器、`sysfs` 节点、射频指标（RSRP/SINR）或共享内存在当前机型不可读/未就绪时，后端必须返回明确的 `supported: false` / `available: false` 或具体 `reason_code`，前端必须如实展示「当前内核/机型不支持」或明确原因，严禁静默回退到假默认值。
- 仅供浏览器离线预览的“仿真假后端/Mock 数据”必须有严格的显式开关与运行时物理隔离，任何异常分支下都不得泄漏进真机 API 或 WebUI 渲染逻辑。

### 死定律二：跨组件数据契约与共享内存对齐铁律
- **单一写盘权**：`devices.json` 唯一合法运行期写者为 `hnc_watchdog` 内的 `m4_owner.go`，其他进程（如 `hnc_httpd`）仅允许只读或纯内存应急合并，严禁多进程并发写同一持久化文件。
- **共享内存安全 (`shm_vector.bin`)**：修改 `src/dpid/shm` 与 `daemon/hnc_httpd` 之间的 16KB 共享内存布局时，结构体头部必须包含固定 `Magic`、`SchemaVersion` 与 `PayloadSize` 校验；版本不匹配或截断时立即无感降级回 JSON 通道，严禁强读错位字节。所有 64 位字段（`uint64`/`int64`/原子计数）必须严格按 **8 字节边界对齐**，防止 32 位 `armeabi-v7a` 触发 `SIGBUS` 或未对齐 panic。
- **跨语言字段同名同义**：Go、C、Shell、前端 JS 之间传递的 JSON 字段名、时间时区（统一本地时区或显式 UTC 时间戳）与速率单位（明确区分 `bps`/`kbps`/`MB/s`，严禁比特与字节混算差 8 倍）必须端到端逐字核对。

### 死定律三：内核数据面正交与原子操作铁律
- 严禁侵占 Android `netd` 使用的低 16 位 `0x0000ffff` fwmark；设备与应用标记必须严格限定在规定的高位掩码区间，且 `mangle/POSTROUTING` 中的保存顺序不得被尾部规则清零。
- 严禁周期性无差别拆建未发生变更的 `tc` 队列或 `iptables/ip6tables` 链（防重置令牌桶与产生 RST 风暴）；任何防火墙与流控变更必须同时覆盖 **IPv4 与 IPv6 双栈**。
- 删除或清理根队列、防火墙链时必须校验 HNC 归属特征，严禁误删宿主 ROM 自带的系统规则，严禁在未确认真实热点接口就绪前向本机上游 `wlan0` 挂载限速。

### 死定律四：异构传感器与外部命令防呆铁律
- 读取电池温度、网卡速率等 `sysfs` 数值时，必须做量纲自适应归一化（如区分毫摄氏度 `42000`、十分之一度 `420` 与摄氏度 `42`）及上下界合法性校验（如温度超出合理物理区间 `[-20°C, 100°C]` 时直接熔断跳过，严禁误触发温控降速）。
- 任何拼接进 Shell、`tc`、`iptables` 的外部输入（MAC、IP、接口名、域名）必须经过严格白名单校验与长度截断；严禁在持有互斥锁期间执行可能阻塞的子进程调用。

### 死定律五：自动化战术舱互斥仲裁与保底铁律
- `ThermoCruise`（温控）、`5G Autorate`（自适应带宽）、`UpdateLeash`（突发收束）等自动调速模块不得各自无序叠加压速，必须设有全局最低保底带宽地板（Floor）与平滑恢复回差，且发生自动压速时必须在状态接口暴露明确归因，防止用户误判为限速故障。
- `LeakGuard` 自动或一键封禁时必须守住公共 CDN / 云网关共享 IP 边界，优先阻断精确域名/SNI，严禁因封禁单一埋点 IP 连坐断掉正常主流应用；`DNS serve-stale` 必须对 Captive Portal 探测流量放行，防止酒店/校园网认证页无法弹出。

### 死定律六：单一做法原则（加新必清旧）
- 同一职责在全仓只保留一套生产实现。重构替换旧机制时，必须在同一提交内清理废弃脚本、死分支、无效前端控件与冗余文件，严禁留存“写好未编译进包”的幽灵源码或死按钮。

### 死定律七：待机零唤醒、`tmpfs` 禁放胀大文件与长稳资源封顶铁律
- 热点未开启或在线客户端为 0 时，所有高频采样器（如 200ms 黑匣子、流控对账定时器、共享内存刷写）必须彻底停表休眠，严禁空转耗电；断流空闲期不得用空白帧覆盖冲刷已捕获的卡顿现场。
- `/data/local/hnc/run` 挂载在仅 `32MB` 的内存盘（`tmpfs`）上：**严禁向 `run/` 写入任何按天增长的历史统计、DPI 流水或本机自训练样本文件**（包括 `stats.*.jsonl`、`phone_usage.*.json`、`app_usage.*.json`、`self_attrib.*.jsonl`、`label_samples.*.jsonl`、`self_fg.*.jsonl`、`apk_domains.json` 等，一律存放在持久化 `data/` 子目录并设单文件与总容量硬上限）；所有原子写文件函数在 `Write` / `Sync` / `Close` / `Rename` 任一步失败（特别是 `ENOSPC`）时必须立即 `os.Remove(tmp)`，严禁遗留 `0` 字节 `.tmp.*` 孤儿文件。
- Netlink 订阅与文件监控必须具备溢出重同步与退出单次关闭保护，确保 30 天长稳零 fd / goroutine 泄漏。

### 死定律八：双卡物理卡槽真值与系统对账铁律
- **严禁混淆数据库自增 `subId` 与物理卡槽 `simSlotIndex`**：Android `telephony.db/siminfo` 中的 `_id`（`subId`）随历史换卡单调递增（如 `subId=9`），必须严格通过当前在位物理卡槽 `simSlotIndex`（`0` 对应卡1，`1` 对应卡2）映射，过滤掉已拔出历史卡（`simSlotIndex < 0`）、临时虚拟流量卡/国际漫游云卡（`isOpportunistic=1` 或超出硬件 `Active modem count` 的虚拟槽位）。
- **优先走原生 `dumpsys isub` + `telephony.registry` 权威链路**：识别当前上网数据卡优先读取 `activeDataSubId`（兼容双卡智能切换/通话临时切卡）-> `defaultDataSubId` -> `Logical SIM slot` 映射；若仍需调用 `content` / `settings` 等依赖 `app_process` 的命令，必须保留系统 `BOOTCLASSPATH` / `SYSTEMSERVERCLASSPATH` / `ANDROID_*` 环境变量，严禁使用空环境 `env -i` 导致静默空输出。
- **双卡机型严禁渲染幽灵「第 3 张卡」**：在双卡硬件（`modemCount <= 2`）上，SIM 卡片列表严格限定在真实物理卡槽（卡1、卡2）；开机瞬态未识别到卡槽的零星蜂窝字节，在确认唯一上网卡或系统 `NetworkStats` 卡槽归属后自动归并校正，确无法归属时仅作底部文字附注，严禁与卡1、卡2并列渲染出第 3 张「未知卡」卡片。

### 死定律九：架构文档与版本元数据同轮闭环铁律
- 每次改动涉及进程职责、IPC 通道、队列优先级或兼容边界时，必须**在同一轮修改中同步更新 `ARCHITECTURE.md`（务必保留头部 `{{VERSION}}` 与 `{{DATE}}` 打包注入占位符）与 `COMPATIBILITY.md`**，严禁留下过期文档误导后续维护。
- 每次发版必须同步更新：`module.prop`（`version` + `versionCode`，RC 测试版严守 `6009301~6009999` 走廊以保住正式版 `6010000`，且冻结 `update.json` 不打扰稳定版）-> `CHANGELOG.md` -> `webroot/changelog.html` -> 运行全套静态与构建门禁（`sh -n`、HTML 内联与独立 JS `node --check`、双架构 `go vet/test/build`、C11 `-Werror` 双架构编译、`sh ./bin/version_consistency_check.sh`、`sh ./bin/ci_preflight.sh`、`sh ./test/run_all.sh` 及全仓零 Emoji 检查）。
