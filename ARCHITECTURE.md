# HNC 内部架构手册

> 面向维护者与协作者的 HNC `v6.1` 全栈真实架构契约、进程边界与内核数据面手册

**版本**: {{VERSION}} <!-- ./bin/inject_version_to_docs.sh 打包阶段自动注入, 仓库内切勿手改实值 -->
**最后更新**: {{DATE}}

## 一、全栈架构总览（6 大核心原生组件 + 辅助工具）

HNC `v6.1`（Vector 架构）采用 **Go 1.27 控制与分析面 + C11 / eBPF 原生数据与守护面** 的高内聚混合架构。全栈彻底清退了早期 `v5.30` 之前的重复守护脚本与多写者状态竞争，同一职责在全仓严格保留唯一生产实现，所有原生组件均同时支持 `arm64-v8a`（Android 15/16 `16KB` 页大小对齐 `-Wl,-z,max-page-size=16384`）与 32 位 `armeabi-v7a` 双架构编译。

### 1.1 系统组件与数据流拓扑图

```text
+-----------------------------------------------------------------------------------+
| 客户端浏览器 / KernelSU WebUI / SukiSU / APatch / Magisk 本地免密与远程配对终端    |
+-----------------------------------------------------------------------------------+
                                        |  HTTP / HTTPS (:8443 / :8444) + SSE
                                        v
+-----------------------------------------------------------------------------------+
| 1. hnc_httpd (daemon/hnc_httpd -> daemon/hnc_httpd/hnc_httpd, Go 1.27)            |
|  - CoreHub 四舱壁防连坐隔离: dataplane / dpi_shm / android_bridge / storage        |
|  - WorldSnapshot 无锁原子快照环 (GET /api/vector_sync < 50ns 零锁读取)            |
|  - 战术舱: VectorExpress / UpdateLeash / ThermoCruise(双温源) / FlowScalpel       |
|  - 本机守护中心: 8s 租约 BPF 流量 / 单飞 batterystats 耗电 / L1 审计 / 四档防火墙 |
|  - RootShaperArbiter 根带宽统一仲裁 (1:1 总顶 + 5Mbps/2Mbps 保底地板 + 压速归因)  |
|  - DataplaneActor 常驻长连接 RTNetlink + 双栈 iptables/ip6tables --noflush 提交   |
|  - 单锁 DNS 解析接管 (弱网 serve-stale + Captive Portal 门户探测逃生放行)         |
|  - 双卡物理槽位引擎 (原生 dumpsys isub + telephony.registry + BOOTCLASSPATH 保护) |
+-----------------------------------------------------------------------------------+
       ^                      ^                         ^                     |
       | 16KB 无锁 mmap       | 只读加载                 | 本地控制 / 协同      | 原生 Netlink /
       | run/shm_vector.bin   | data/devices.json       | run/hotspotd.sock   | 原子管道下发
       | (v3 双域流正交拆分)  | (唯一写盘契约)           | + clsact 状态对账    v
+------------------+  +----------------------+  +--------------------+  +-----------+
| 2. hnc_dpid      |  | 3. hnc_watchdog      |  | 5. hotspotd        |  | 6. clsact |
| (src/dpid/cmd/   |  | (src/dpid/cmd/       |  | (daemon/hotspotd,  |  | hnc_clsact|
|  dpid, Go 1.27)  |  |  hnc_watchdog, Go)   |  |  含 hnc_ipc 与     |  | _ctl +    |
|                  |  |                      |  |  mdns_resolve, C11)|  | hnc_tc_   |
| - epoll AF_PACKET|  | - pidfd / pidfile    |  |                    |  | ingress + |
| - SNI/JA4/QUIC   |  |   守护巡检与自愈      |  | - 热点链路事件监听 |  | hnc_clsact|
| - 智能防抖前台轨  |  | - 四档省电停表状态机 |  | - 高通 BPF tether  |  | .bpf.c    |
| - LeakGuard+L2审 |  | - m4_owner.go 唯一   |  |   limit/downstream |  |           |
| - 双域 conntrack |  |   原子写 devices.json|  |   map 硬件卸载控制 |  | - 双栈着色|
| - eBPF 字节采样  |  +----------------------+  +--------------------+  | - PERCPU  |
+------------------+             |                                      |   槽位计数|
       ^                         | 监控与降级直盯                       +-----------+
       | Bionic fork()+execv()   v                                            |
+--------------------------------------------+                                |
| 4. hnc_launcher (src/launcher, 含          |                                |
|    fork_probe, C11 原生守护启动器)          |                                |
| - 绕过 ColorOS 16 / SukiSU CLONE_VFORK     |                                |
|   EPERM 拦截, 指数退避守护 hnc_dpid        |                                |
+--------------------------------------------+                                |
       |                                                                      |
       +----------------------------------+-----------------------------------+
                                          v
+-----------------------------------------------------------------------------------+
| Linux 5.10 ~ 6.6+ 内核双域数据面 (热点口 wlan2/ap0/ap_br_*/swlan0 + ifb0 + 本机)  |
| - skb->mark 正交高位位段 (低 16 位 0x0000ffff 完整保留给 Android netd)            |
| - Tier-A clsact eBPF + HTB | Tier-B Native Netlink HTB | Tier-C 原子批处理兜底    |
| - 热点转发子链 (FORWARD/mangle: HNC_SCALPEL / HNC_CONNBLK / HNC_V6_EXPRESS / LEASH)|
| - 本机守护子链 (OUTPUT: HNC_SELF_UID / HNC_SELF_DNS / HNC_SCALPEL_HOST + SOCK_DESTROY)|
+-----------------------------------------------------------------------------------+
```

### 1.2 六大核心原生组件与辅助工具清单

| 序号 | 组件名称 | 源码目录 | 运行时产物路径 | 语言与依赖 | 核心职责边界 |
|---|---|---|---|---|---|
| 1 | `hnc_httpd` | `daemon/hnc_httpd` | `daemon/hnc_httpd/hnc_httpd` | Go 1.27 | 控制面 HTTP/WebUI 网关、`CoreHub` 四舱壁、`RootShaperArbiter`、主动战术舱、本机守护中心（流量/耗电/隐私审计/四档防火墙/本机手术刀）、长连接 RTNetlink 数据面下发、DNS 接管与双卡引擎 |
| 2 | `hnc_dpid` | `src/dpid/cmd/dpid` | `bin/hnc_dpid` | Go 1.27 | 不解密深度包检测（SNI/JA4/QUIC/ECA-SPLT）、威布尔半马尔可夫前台识别、`LeakGuard` 与 L2 `self_capture` 明文深度审计（含 `CREDENTIAL` 与 ISO 7064 `ID_CARD`）、双域流拆分与 `shm_vector.bin` v3 写端 |
| 3 | `hnc_watchdog` | `src/dpid/cmd/hnc_watchdog` | `bin/hnc_watchdog` | Go 1.27 | 进程健康巡检（`pidfd` + pidfile）、省电状态机、网卡迁移规则恢复、`m4_owner.go` 唯一合法写盘 `data/devices.json` |
| 4 | `hnc_launcher` | `src/launcher` | `bin/hnc_launcher`、`bin/fork_probe` | C11 (Bionic) | 以无 `CLONE_VM` 的标准 `fork()+execv()` 绕过 ColorOS 16 / SukiSU `CLONE_VFORK EPERM` 限制，专职拉起并守护 `hnc_dpid` |
| 5 | `hotspotd` | `daemon/hotspotd` | `bin/hotspotd`、`bin/hnc_ipc`、`bin/mdns_resolve` | C11 + `libbpf v1.4.7` | 热点链路事件监听、`run/hotspotd.sock` 本地 IPC 通道、高通 BPF 卸载表项驱逐与硬件加速探测压制 |
| 6 | `hnc_clsact_ctl` | `daemon/clsact_ctl`、`daemon/tc_netlink`、`src/dpid/bpf` | `bin/hnc_clsact_ctl`、`bin/hnc_tc_ingress`、`bin/hnc_clsact.o` | C11 + eBPF | 裸系统调用 TC `clsact` eBPF 加载挂载、双栈 L2/L3 着色、`dev_stats_map` 统计、入站预提权、`hnc_tc_ingress` 挂载与内核策略对账 |
| 辅助 | `hnc_applabel.dex` 等 | `tools/applabel`、`bin/` | `bin/hnc_applabel.dex`、`./bin/self_firewall_sync.sh`、`./bin/hnc_json`、`./bin/hnc_env.sh` | Java DEX / POSIX sh | 按需提取本机应用本地化标签、本机双栈四档防火墙同步与六道防自锁校验、内核 `flock` 原子 JSON 配置读写与运行环境收敛 |

### 1.3 各原生组件关键实现细节

1. **`hnc_httpd`（控制面与双域网关中枢）**：
   - 启动时对 `run/httpd.lock` 加非阻塞 `flock` 排他锁，杜绝双实例抢占 `:8443` / `:8444` 端口。
   - 采用 Go 1.27 标准库高吞吐 JSON 引擎，聚合热点态势、设备列表（内存合并 `data/devices.json`、`data/rules.json`、`data/device_names.json` 与实时速率）、DPI 分析、射频信号诊断（`RSRP`/`SINR` 与四维空口归因）、五大主动护航战术舱以及「本机守护」中心全套接口（`/api/local_apps/traffic`、`/api/local_apps/power`、`/api/local_apps/privacy_audit`、本机防火墙与本机连接手术刀）。
   - 执行外部 Android 命令时严守环境变量铁律：优先直读 `/proc`、`/sys`、`/sys/fs/bpf/netd_shared` 或调用原生 C++ Binder 服务（`dumpsys isub`、`dumpsys telephony.registry`、`dumpsys tethering`、`dumpsys netstats`、`dumpsys batterystats`）；确需调用 `content`、`settings`、`cmd`、`am` 等依赖 `app_process` 的包装命令时，完整保留宿主 `BOOTCLASSPATH`、`SYSTEMSERVERCLASSPATH` 与 `ANDROID_*` 环境变量，严禁以空环境拉起导致静默失败。
2. **`hnc_dpid`（深度包检测与共享内存 v3 写端）**：
   - 基于 `AF_PACKET` 与纯 `epoll` 事件驱动捕获双栈流量，无需安装中间人根证书即可提取 DNS CNAME 链、TLS ClientHello SNI 与 JA4 指纹、抗后量子分片 QUIC Initial 与 QTP 传输参数、前 8 包方向与包长序列（SPLT），以及 120ms 门控时间因果突发传播。
   - 默认启用威布尔半马尔可夫「智能防抖」前台意图识别模型，支持长视频分段缓冲保持、语音/音乐伴随轨解耦与锁屏防后台推送篡位。
   - 内置 `LeakGuard` 与按需 L2 `self_capture` HTTP/DNS 明文深度载荷审计引擎，非阻塞检测未加密请求中的手机号、IMEI/OAID、精确经纬度、MAC、高危鉴权凭据（`CREDENTIAL`）及通过 ISO 7064 (MOD 11-2) 强校验的二代身份证号（`ID_CARD`）。
   - 在连接追踪与共享内存发布层将热点下游转发流（`hotspot_flows`）与宿主本机流（`host_flows`）正交隔离；接口未就绪时通过可恢复错误判定自动退避重试，避免永久滞留盲模式。
3. **`hnc_watchdog`（生命周期巡检与单一设备写盘者）**：
   - 通过 Linux `pidfd` 与 `run/*.pid` 心跳时间戳巡检各守护进程存活状态；监听热点启停与上下行接口切换，驱动数据面规则重放与自愈。
   - 内嵌 `m4_owner.go`（调用 `src/dpid/devscan` 与 `src/dpid/devname`）订阅 `RTNLGRP_NEIGH` 内核邻居事件（配 `500ms` 读取超时、`512KiB` 缓冲、`ENOBUFS` `1 Hz` 限流全量重同步与 `1s..30s` 指数退避重连），作为全系统唯一合法写盘者原子更新 `/data/local/hnc/data/devices.json`。
4. **`hnc_launcher` + `fork_probe`（C 原生启动器）**：
   - ColorOS 16 / SukiSU 等内核钩子会拦截 Go runtime 的 `clone(CLONE_VM | CLONE_VFORK)` 并返回 `EPERM`。`./service.sh` 启动期调用 `fork_probe` 实测 C `fork()+execv()` 可用性，默认选定 `hnc_launcher` 守护 `hnc_dpid`（写入 `run/dpid_launcher.choice`）；仅当极端环境 C 启动器异常时，由 `hnc_watchdog` 切换至 `direct` 模式直接接管。
5. **`hotspotd` + `hnc_ipc` + `mdns_resolve`（硬件卸载控制与辅助解析）**：
   - 监听热点链路状态变化，维护 `0600` 权限的 `run/hotspotd.sock` 本地控制套接字（供 `./bin/device_detect.sh` 或 `hnc_ipc` 查询状态、触发刷新与卸载切换），并在受控设备生效瞬间协同压制高通 BPF `tether_limit_map` 与 `tether_downstream4/6_map` 硬件快路径。
   - `mdns_resolve` 提供轻量级局域网多播主机名辅助解析。
6. **`hnc_clsact_ctl` + `hnc_tc_ingress` + `hnc_clsact.bpf.c`（内核 eBPF 与入站控制）**：
   - `hnc_clsact.bpf.c` 针对 Linux 5.10 ~ 6.6 Verifier 及 32 位 ARMv7 `NET_IP_ALIGN=2` 严格对齐硬化：支持双层 VLAN（802.1Q/QinQ）剥离、4 层有界 IPv6 扩展头遍历并豁免 ICMPv6 NDP/RA/MLDv2 报文、按 `mac_mark_map` / `ip_mark_map` 执行双栈双向着色、写入 `PERCPU` `dev_stats_map` 槽位字节计数、在进入 `ifb0` 前为实时游戏/语音小包预提权，并统一返回 `TC_ACT_UNSPEC (-1)` 使后续 `prio 2` 过滤器继续串联执行。

## 二、进程间契约与存储分层

### 2.1 `CoreHub` 四舱壁防连坐隔离中枢

`daemon/hnc_httpd/core_hub_v6.go` 将控制面内部任务严格隔离在四个独立舱壁（Bulkhead）内，任一慢操作或外部异常绝不波及 WebUI 读取与其他子系统：

| 舱壁标识 | 内部组件 | 职责范围 | 超时与熔断护栏 |
|---|---|---|---|
| `dataplane` | `DataplaneBulkhead` | RTNetlink 队列调速、双栈防火墙规则批量提交、流控对账 | 单写者串行有界队列 + `recover()` 异常隔离 + 单调时钟心跳 |
| `dpi_shm` | `DpiShmBulkhead` | 无锁读取 `run/shm_vector.bin` 共享内存与 `run/dpi_state.json` 回退缓存 | 页大小与头部强校验 + `SIGBUS` 保护 + 超期零报错回退 JSON |
| `android_bridge` | `AndroidBridgeBulkhead` | 调用 `dumpsys`、`cmd` 等系统桥接查询 | `ExecIsolatedAndroidCmd` 强制 `Setpgid: true` 2s 硬超时向 `-pgid` 发送 `SIGKILL` 连根清理孙进程；连续 2 次超时触发 45s 半开熔断 |
| `storage` | `StorageBulkhead` | 持久化配置读写、统计归档、备份导出与配置医生自检 | 互斥锁 + 同目录 `.tmp` `fsync + rename` 原子写 + 失败即删 `.tmp` |

前端主轮询端点 `GET /api/vector_sync` 直接通过 `atomic.Pointer[WorldSnapshot]` 无锁读取后台协程预编码的最新快照（耗时 `<50ns`），请求路径零互斥锁等待、零磁盘 I/O、零子进程派生。

### 2.2 `m4_owner.go` 单一写盘契约与内存合并层

- **唯一写盘者**：`/data/local/hnc/data/devices.json` 在运行期仅允许由 `hnc_watchdog` 内的 `m4_owner.go` 写入（扁平小写 MAC 到包含 `ip`、`mac`、`hostname`、`hostname_src`、`iface`、`rx_bytes`、`tx_bytes`、`status`、`last_seen` 9 个固定字段的对象映射）。主动刷新通过写入 `run/devices.refresh` 随机凭据并等待 `run/devices.refresh.ack` 回执完成握手。
- **只读应急合并**：`hnc_httpd` 绝不回写 `data/devices.json`。当 `ACTIVE` 态下文件超期或刷新回执超时时，`hnc_httpd` 以 2 秒冷却周期从内核 Netlink 邻居表只读提取在线条目，在内存深拷贝中叠加 `data/rules.json`、`data/device_names.json` 与实时速率后返回前端。

### 2.3 `run/shm_vector.bin` 16KB 双槽无锁共享内存契约（`SchemaVersion = 3`）

`src/dpid/shm` 与 `daemon/hnc_httpd` 通过 `/data/local/hnc/run/shm_vector.bin` 实现微秒级跨进程状态同步：

1. **固定 16384B 页对齐双槽布局**：总大小严格锁定 `16384` 字节（匹配 Android 15/16 `16KB` 内存页），划分为 `[0..64)` 顶层控制头、`[64..8224)` Latch Slot 0 与 `[8224..16384)` Latch Slot 1，采用 `seqcount_latch` 奇偶序列号双缓冲机制。
2. **头部强校验与双域流正交拆分（`SchemaVersion = 3`）**：顶层控制头包含固定魔数 `Magic=HNCVSHM1`、结构版本号 `SchemaVersion=3`、精确载荷尺寸 `PayloadSize`、`CLOCK_BOOTTIME` 跨休眠单调时钟戳以及序列号前后屏障（含 RMW 读屏障校验），彻底拦截半写帧与脏读。每个双槽 `64B` 槽头末尾偏移 `slot[60:64]` 新增 `uint32` `HostFlows` 字段，将热点下游终端转发流（`hotspot_flows`）与宿主手机本机流（`host_flows`）在物理采集与共享内存层彻底正交拆分，消除手机自身后台连接混入热点活跃连接数导致的虚高。
3. **32 位 ARMv7 8 字节对齐铁律**：共享内存帧及全仓 Go 结构体中所有 64 位字段（`uint64`、`int64`、`atomic.Uint64`、`atomic.Int64`）一律严格排布在 **8 字节整数倍偏移处**（结构体级 64 位原子字段统一置于 `offset 0`），防止 32 位 `armeabi-v7a` 平台触发 `SIGBUS` 或 `unaligned 64-bit atomic operation` 崩溃。
4. **热升级无感 JSON 回退**：模块热升级切换期若新旧进程间的 `Magic`、`SchemaVersion` 或 `PayloadSize` 不一致，或文件尚未生成、超出新鲜度窗口，读端立即无感回退至 `run/dpi_state.json`，绝不强解错位字节导致乱码或假离线。

### 2.4 `32MB tmpfs` 瞬态盘与持久化 `data/` 物理分离

1. **瞬态内存盘 `/data/local/hnc/run/`（`32MB tmpfs`）**：
   - 开机挂载为上限 `32MB` 的内存文件系统，保护手机 UFS 闪存免受高频状态刷写磨损。
   - **严禁放入任何随时间增长的历史流水或样本文件**，仅存放固定上限的瞬态文件：`shm_vector.bin`（16KB）、`dpi_state.json`、各守护进程 `*.pid`（`httpd.pid`、`dpid.pid`、`watchdog.pid`、`launcher.pid`、`hotspotd.pid`、`dpid_guard.pid`）、`hotspotd.sock`、`local_admin.secret`（`0600`）、`iface_detect.json`、`capabilities.json`、`root_env.json` 及运行期锁文件。
2. **持久化目录 `/data/local/hnc/data/`（硬配额轮转）**：
   - 核心配置：`rules.json`、`device_names.json`、`known_devices.json`、`remote_tokens.json`、`leakguard_config.json`、`vector_express.json`、`update_leash.json`、`thermo_cruise.json`、`rmac_policy.json`、`encdns.json`、`self_policy.json`、`self_firewall.json` 等。
   - 历史流量统计子目录 `data/stats/`：存放按日/跨月统计账单（`stats.*.jsonl`、`phone_usage.*.json`、`app_usage.*.json` 等）。
   - 本机真值自训练子目录 `data/self_studio/`：存放本机自训练工作台流水与蒸馏中间集（`self_attrib.*.jsonl`、`label_samples.*.jsonl`、`self_fg.*.jsonl`、`apk_domains.json` 等），实施单文件截断与目录总容量硬配额轮转。
   - **零孤儿临时文件铁律**：所有原子写操作统一采用同目录临时文件写入 + `fsync` + `close` + `rename`；任一环节失败（特别是磁盘满 `ENOSPC`）立即调用 `os.Remove` 清理临时文件，严禁遗留 `0` 字节 `.tmp.*` 孤儿文件。

## 三、内核数据面完整架构

### 3.1 正交高位 `skb->mark` 位段契约

Android 系统 `netd` 依赖 `skb->mark` 的低 16 位执行策略路由（`ip rule`）与网络权限校验。HNC 全栈（Go、C、eBPF、Shell）严格锁定在高 16 位 `[31:16]`（`CONNMARK` 掩码 `0xffff0000`）进行正交位域编解码：

| 位段掩码 | 位域区间 | 语义职责与正交约束 |
|---|---|---|
| `0x0000ffff` | `[15:0]` | **Android `netd` 专属保留区**（`netId` 与系统权限位），HNC 读写一律带高位掩码保护，100% 绝不触碰 |
| `0x00ff0000` | `[23:16]` | 应用类 / 正交分类标识段（与客户端正交高位基准编码协同，配合掩码精确匹配，不污染低 16 位） |
| `0x7f000000` | `[30:24]` | 设备与精细流控槽位段（承载受控槽位、三档动态 QoS 档位与单应用限速子类分流索引） |
| `0x80000000` | `[31]` | **免限盾最高位豁免标志**（置位流量直入免限快车道，跳过常规限速整形） |

**路由与标记持久化顺序护栏**：
- 在进入策略路由前由 `HNC_PREROUTE_GUARD` 保护策略路由位，`HNC_RESTORE` 挂载于 `mangle/FORWARD` 首部，避免下行包误触宿主 `unreachable` 路由规则；
- 在 `mangle/POSTROUTING` 中，`HNC_APP_LIMIT_DOWN`、`HNC_APP_QOS` 及战术舱标记链严格排在 `HNC_SAVE`（写入 `CONNMARK`）之前，尾部辅以 `HNC_EGRESS_FIX`（排除蜂窝上游 `rmnet+`）防止宿主 ROM 的 `bw_mangle_POSTROUTING` 清零高位标记。

### 3.2 三级自适应数据面（Tier-A -> Tier-B -> Tier-C）

`ProbeDataplaneTier` 在热点就绪时按内核真实能力自动探测并热切换最优执行层级：

1. **Tier-A（`tier1_ebpf_edt`：`clsact eBPF + Native Netlink HTB`）**：
   - 条件：硬件卸载已受控 + `hnc_clsact.o` 成功挂载至热点口 `clsact` + 内核调度器支持就绪。
   - 路径：数据包在 `clsact` `prio 1` 由 eBPF 完成 L2/L3 双栈着色、实时小包预提权与 `dev_stats_map` 纳秒级统计，返回 `TC_ACT_UNSPEC` 串联 `prio 2`（`ifb0` 镜像重定向或无 `ifb` 内核的双栈 `ingress police`），队列树由 `DataplaneActor` 常驻长连接 `AF_NETLINK` 零子进程维护。
2. **Tier-B（`tier2_native_netlink`：`Native Netlink HTB + iptables mangle`）**：
   - 条件：内核无 `clsact` BPF 环境，但原生 RTNetlink `HTB` 可用。
   - 路径：`DataplaneActor` 复用单一长连接 `AF_NETLINK` 套接字直接下发 `RTM_NEWQDISC` / `RTM_NEWTCLASS` / `RTM_NEWTFILTER`（内置精确 `tick_in_usec` 与 256 项 `RTAB/CTAB` 计算及 O(1) 增量摘要去重），叶子队列按五级自适应回退链（`fq_codel(5ms)` -> `fq_codel` -> `fq` -> `sfq` -> 按速率动态缩放 `pfifo(16..256)`）挂载，配合双栈 `mangle` 着色生效耗时 `<80ms`。
3. **Tier-C（`tier3_atomic_batch`：Shell / 批量管道应急兜底）**：
   - 条件：特殊定制内核对原生 Netlink 属性有非标限制时的兜底路径。
   - 路径：在内存中拼装完整批处理指令，经管道一次性喂给 `tc -force -batch -` 与 `./bin/tc_manager.sh` / `./bin/iptables_manager.sh`（统一持 `tc_action.lock` 互斥锁，单事务严格限制子进程次数）。

### 3.3 `RootShaperArbiter` 统一根带宽仲裁与 HTB 队列树

为防止多个自动化模块叠加压速导致热点“假断网”，控制面设立统一的 **`RootShaperArbiter`** 仲裁器管理下行热点口与上行 `ifb0` 的根类 `1:1` 带宽上限：

- **多源互斥与取严仲裁**：统一汇集用户手动全局整形、`5G Autorate` 空口缓冲膨胀自适应控制、`ThermoCruise` 电芯与壳温巡航以及 `VectorExpress` 背景池收束请求，消除多模块各自直改 `1:1` 造成的振荡与覆盖。
- **全局保底带宽地板（Floor）与显式归因**：任何自动压速路径均受硬性最低保底地板保护——**下行不低于 `5Mbps`，上行不低于 `2Mbps`**，并带施密特回差平滑恢复；一旦自动压速生效，`/api/vector_sync` 与诊断面板同步输出明确的触发模块与原因码（如温控降速或基站拥塞收口）。
- **核心 HTB 类别拓扑**：
   - `1:1`：全局根父类（由 `RootShaperArbiter` 统一仲裁总顶 `ceil`）；
   - `1:8010`（双栈过滤器 `prio 4` / `prio 5`）：**`VectorExpress` 低时延专道**（`prio 0`，浅驻留 `fq_codel target 2ms / interval 40ms`，避开 `prio 1` eBPF 着色、`prio 2` `mirred`/`police` 及第 16 号设备类 `1:10`）；
   - `1:<cid>`（`cid` 对应受控设备槽位）：每台受控终端独立 HTB 类，内部可进一步挂载 `1:9001+` 单应用限速子类与 `1:a0XX` 动态三档应用 QoS 队列；
   - `1:fffe`：`2.5Gbps` 局域网互传免限速直通类；
   - `1:9999`（含 `1:9990` 收束子通道）：**默认未分类流量与突发收束队列**（承载普通未限速流量及 `UpdateLeash` 超过 `200MB` 免死缓冲后的后台大包更新平滑收束流）。

### 3.4 双域双栈 `iptables-restore --noflush` / `ip6tables-restore --noflush` 原子下发

所有防火墙与流控着色变更一律同时覆盖 **IPv4 与 IPv6 双栈**，通过内存构造目标链完整快照并经 `iptables-restore -w 2 --noflush` 与 `ip6tables-restore -w 2 --noflush` 单次原子替换独立子链，严禁周期性清空未变更规则（防止打断活跃连接或重置计数）：

| 核心子链名称 | 挂载表与父链 | 功能契约与防误伤守卫 |
|---|---|---|
| `HNC_SCALPEL` | `filter / FORWARD` | 热点转发域 `FlowScalpel` 连接手术台链：下发精确五元组瞬时 `REJECT`（配合原生 `IPCTNL_MSG_CT_DELETE` 秒斩死流）或带 TTL 的精确冻结规则，内置本机网关、DNS 端口（53/853）与管理端口硬豁免防自锁 |
| `HNC_CONNBLK` / `HNC_CONNBLK_DNS` | `filter / FORWARD, INPUT` | 应用连接阻断与 `LeakGuard` 隐私封禁链：严守公共 CDN / 共享云底座防连坐边界，优先精确阻断目标域名/SNI，绝不因单一埋点共享 IP 误封主流正常应用 |
| `HNC_V6_EXPRESS` | `mangle / FORWARD, POSTROUTING` | `VectorExpress` 双栈低时延护航着色链（校验外网并发目的 IP 阈值 `<=48` 排除 BT/P2P 伪装后导流至 `1:8010`） |
| `HNC_V6_LEASH` | `mangle / FORWARD, POSTROUTING` | `UpdateLeash` 后台系统/商店巨量更新着色链（单向大流超出 `200MB` 缓冲池后平滑导流至收束队列） |
| `HNC_QUIC` / `HNC_QUIC_APPLIM` | `filter / FORWARD` | 排障兜底「强制 QUIC 回落 TCP」与受控单应用双栈 `UDP 443` 防逃逸阻断链，热点停用时幂等摘除不留残余 |
| `HNC_TUN_GUARD` / `HNC_ISOLATE` | `filter, mangle / FORWARD` | 自动感知本机 `tun+` / `wg+` 代理隧道智能礼让防环路、双栈 `TCPMSS --clamp-mss-to-pmtu` 钳制及客户端二层/三层互访隔离 |
| `HNC_SELF_UID` | `filter / OUTPUT` | 本机守护域 UID 四档安全防火墙链（放行 / 仅禁明文 HTTP / 禁移动数据 / 全局禁网），协同封禁 Android 13+ SDK Sandbox `uid+10000` 并经 `./bin/self_firewall_sync.sh` 六道防自锁门禁守卫 |
| `HNC_SELF_DNS` | `filter / OUTPUT` | 本机直连明文 DNS 封堵链：拦截受控本机应用绕过系统加密 DNS 直连外网 `:53` 端口的 UDP/TCP 明文解析请求并执行 `DROP` |
| `HNC_SCALPEL_HOST` | `filter / OUTPUT` | 本机连接手术刀专用链：配合内核 `SOCK_DESTROY` 即刻销毁本机目标 Socket，并对目标五元组下发精确秒断或带 TTL 的临时冻结规则 |

清理或关闭热点时，`./bin/cleanup.sh` 严格校验热点转发链与 `run/tc_root_owned_*` 归属标记，100% 不触碰宿主 ROM 原生系统规则，且绝不在未确认权威 AP 模式前向本机上游 `wlan0` 挂载限速；本机防火墙策略独立持久化，仅在用户调整或模块卸载（`./uninstall.sh`）时由 `./bin/self_firewall_sync.sh` 幂等收敛或完整摘除。

## 四、本机守护双域架构（Host & Hotspot Dual-Domain Guardian）

在守护下游热点终端的同时，HNC 构建正交独立的**手机本机守护中心**，覆盖本机应用实时流量、后台耗电归因、双层明文隐私审计与本机出站防火墙：

1. **按需 8s 短租约本机实时网速与前后台流量引擎（`GET /api/local_apps/traffic`）**：
   - 只读访问 Android `netd` 内核共享 BPF 映射 `/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map`（兼容回退 `stats_map_A` / `stats_map_B`）与 `map_netd_uid_counterset_map`（区分 `SET_DEFAULT` 后台与 `SET_FOREGROUND` 前台），结合 `dumpsys netstats --uid` 周期校准历史前后台蜂窝与 Wi-Fi 累计流量。
   - 高频速率差分循环严格采用前端视图驱动的 **8 秒短租约（Lease）按需激活机制**：仅当用户停留在「本机守护」相关面板时续租采样，退出页面逾 8 秒即自动停表休眠，日常后台零轮询开销。
2. **流式单飞缓存后台耗电与射频唤醒归因引擎（`GET /api/local_apps/power`）**：
   - 经 `AndroidBridgeBulkhead` 流式逐行解析 `dumpsys batterystats --charged`（避免将数十 MB 原始输出整体读入内存造成 GC 尖峰），内置 `singleflight` 并发请求合并与缓存窗口。
   - 精准提取各 UID 充电后累计耗电（Android 14+ 支持拆分后台/息屏独立 `mAh`）、Partial Wakelock 持锁时长、Alarm 定时唤醒次数以及蜂窝基带射频唤醒（Cellular Radio Wakeup）归因排行。
3. **L1 零抓包实时套接字审计 + L2 深度载荷隐私安检（`GET /api/local_apps/privacy_audit` & `self_capture`）**：
   - **L1 零抓包实时套接字审计**：无需开启网卡混杂抓包，直接关联本机活跃 Socket UID、目标端口（如 `:80`/`:8080` 明文端口、外网 `:53` 直连明文 DNS）与内置广告/追踪 SDK 域名指纹库，零额外功耗揭示本机应用后台明文联网与追踪连接态势。
   - **L2 按需 `self_capture` HTTP/DNS 深度载荷审计**：用户主动开启本机深度审计时，非阻塞扫描未加密 HTTP 请求头/体与明文 DNS 报文，在手机号、IMEI/OAID、精确经纬度与 MAC 基础上，新增高危登录鉴权凭据（`CREDENTIAL`）与经 **ISO 7064 (MOD 11-2) 校验位强核验**的 18 位身份证号（`ID_CARD`）防泄露检测。
4. **本机安全防火墙四档管控、`uid+10000` 沙盒协同与本机手术刀**：
   - `filter/OUTPUT` `HNC_SELF_UID` 提供单应用四档管控：**放行**、**仅禁明文 HTTP**（精确拦截非加密 HTTP 端口，倒逼回落 HTTPS 而不影响正常加密业务）、**禁移动数据**（蜂窝上游 `rmnet+`/`ccmni+` 等阻断、Wi-Fi 放行）与**全局禁网**。
   - **Android 13+ SDK Sandbox 协同封禁**：对常规宿主应用 UID（`appId` 位于 `10000..19999`），自动推导并同步封禁其伴生沙盒进程 UID（`uid + 10000`），封堵内嵌广告 SDK 借独立沙盒 UID 绕过宿主网络限制的通道。
   - **六道防自锁门禁**：硬豁免系统核心特权 `appId`（`uid % 100000 < 10000`，全面覆盖主用户与多用户/应用分身）、HNC 与当前 Root 管理器宿主包、仅限回环与本机局域网目标地址的 WebUI 管理会话端口（`:8443`/`:8444`，封堵外网同号端口绕过禁网）、回环接口 `lo`、局域网/热点网关控制报文及系统连通性基础链路，配合 `HNC_SELF_DNS`（`:53` `DROP`）与 `HNC_SCALPEL_HOST`（`INET_DIAG` `SOCK_DESTROY` 瞬断存量连接 + 五元组秒断/冻结）形成完整闭环。

## 五、控制面关键可靠性契约

1. **双卡物理卡槽真值与防「第 3 张幽灵卡」铁律**：
   - Android `telephony.db/siminfo` 的自增主键 `_id`（`subId`）随历史换卡不断增大，严禁将其直接当作卡槽号。
   - `daemon/hnc_httpd/sim.go`、`phone_usage_sim.go` 与 `signal_monitor.go` 统一走原生 `dumpsys isub` + `dumpsys telephony.registry` 权威链路，严格过滤 `INVALID_SUBSCRIPTION_ID`（`2147483647`）、`pid>=2` 软 SIM 槽及 `v4-` CLAT 接口前缀，按 `activeDataSubId` -> `defaultDataSubId` -> 在位物理卡槽 `simSlotIndex`（`0` 为卡 1，`1` 为卡 2）精确映射，自动剔除已拔出历史卡（`simSlotIndex < 0`）与虚拟云卡/副流量逻辑槽（`isOpportunistic=1` 或超出硬件 `Active modem count`）。
   - 双卡硬件（`modemCount <= 2`）严格最多渲染卡 1、卡 2 两张实体卡片；开机瞬态尚未归属卡槽的零星蜂窝字节自动按唯一上网卡或系统 `NetworkStats` 校正归并，无法归属时仅作底部文字说明。
2. **ThermoCruise 电池与机身壳温双源交叉校准及热点待机实时只读刷新**：
   - 同时直读 `/sys/class/power_supply/*/temp` 电芯温度与 `/sys/class/thermal/thermal_zone*` 机身表皮/壳温热区（匹配 `shell_*`、`skin*` 等传感器），自动识别毫摄氏度（如 `42000`）、十分之一摄氏度（如 `420`）与摄氏度（如 `42`）三种内核量纲；一旦读数越出合理物理区间 `[-20°C, 100°C]` 立即熔断剔除异常源。
   - **防低温伪装模块致盲**：当设备装有快充伪装模块（如将电池温度人为拉低 `-10°C`）导致电芯温度显著低于机身壳温时，双源交叉校准自动识别偏置并以真实机身壳温估算值接管温控判据；在热点待机或零客户端状态下，传感器看板支持无写盘、无流控副作用的实时只读刷新。
3. **DNS 接管单锁串行与 Captive Portal 门户逃生**：
   - `dns_takeover.go` 与 `dns_forwarder.go` 采用单一互斥锁串行控制转发规则，弱网偶发超时期间通过 `serve-stale` 保持已有解析不断网，上行切网瞬间清空陈旧缓存并重置上游健康探测窗口；对酒店/校园网 Captive Portal 联网探测域名（如 `connectivitycheck.gstatic.com`、`captive.apple.com`、`connect.rom.miui.com` 等）强制直通上游真实响应，严禁返回过期缓存阻断认证页弹出。
4. **待机零唤醒、看门狗身份核验与零假数据铁律**：
   - 后台探活路由（`/api/health`）与未鉴权公开路由严格排除在 `activityTouchMiddleware` 之外，杜绝看门狗周期探活误刷新 `webuiLastHit` 锁死活跃档位；热点关闭或在线客户端数为 `0` 时，`200ms` 卡顿黑匣子、战术舱巡检定时器、流控对账、Netlink 高频轮询与 `shm_vector.bin` 刷写全部停表休眠（断流空闲期不写空白帧，完整保留断流前 `60s` 真实卡顿现场）；`hnc_watchdog` 对守护进程执行判活或超时强杀前强制核验 `/proc/<pid>/cmdline`（回退 `comm`），根除 PID 复用误杀隐患。
   - 生产运行态严禁任何硬编码模拟曲线或假成功状态；底层计数器或传感器不支持时明确返回 `supported: false` / `available: false` 与具体 `reason_code`；前端离线预览仿真脚本 `tools/ui_mock/fake_api.js` 排除在刷机包之外并由打包门禁双重拦截。

## 六、目录结构契约

### 6.1 模块安装目录（只读挂载：`/data/adb/modules/hotspot_net_ctl/`）

安装期 `./customize.sh` 与启动期 `./post-fs-data.sh` 会自动检测并停用历史旧模块目录 `hotspot_network_control`，防止新旧模块双实例冲突：

```text
/data/adb/modules/hotspot_net_ctl/
├── module.prop                         # 模块版本与元数据 (id=hotspot_net_ctl)
├── customize.sh                        # 安装期 ABI 强校验 (./bin/hnc_arch.sh) 与黄金回滚快照准备
├── post-fs-data.sh                     # 权限收敛 (0700)、跨重启失效锁清理、同步运行文件至 /data/local/hnc
├── service.sh                          # 挂载 32MB tmpfs、环境探测、fork_probe 选路、本机防火墙恢复与守护进程拉起
├── action.sh                           # 模块管理器操作按钮入口 (免密打开本机 WebUI / 配对指引)
├── uninstall.sh                        # 卸载清理热点与本机双域规则及运行时残留
├── LICENSE                             # GPL-3.0-only (用户态) / GPL-2.0-or-3.0 (eBPF) 许可证
├── daemon/hnc_httpd/hnc_httpd          # Go 控制面主网关 ELF
├── bin/                                # 原生二进制 (hnc_dpid / hnc_watchdog / hnc_launcher / fork_probe /
│                                       # hotspotd / hnc_ipc / mdns_resolve / hnc_clsact_ctl / hnc_tc_ingress /
│                                       # hnc_clsact.o / hnc_applabel.dex / hnc_pkg_abi) 与运维脚本 (./bin/*.sh)
├── data/                               # 内置只读规则分包 (dpi_rules.d/*.json)、JA4 指纹库、OUI 与归属库
└── webroot/                            # WebUI 静态资源 (index.html / changelog.html / json-health.html / css / js)
```

### 6.2 运行时工作目录（读写隔离：`/data/local/hnc/`，权限 `0700`）

```text
/data/local/hnc/
├── daemon/hnc_httpd/hnc_httpd          # 运行期独立副本 (跨 Mount Namespace 稳定执行)
├── bin/                                # 运行期二进制、脚本 (含 ./bin/self_firewall_sync.sh) 与 /data 工具链垫片
├── webroot/                            # 热同步 WebUI 静态文件
├── etc/                                # 用户自定义配置 (跨版本刷机保留)
│   ├── dpi_config.json                 # hnc_dpid 抓包参数配置
│   └── dpi_rules.d/*.json              # 同步规则分包 + 99-user-custom.json 用户高优覆盖规则
├── data/                               # 持久化配置与受配额保护的历史数据 (UFS 闪存)
│   ├── devices.json                    # m4_owner.go 唯一原子写盘
│   ├── rules.json                      # 限速 / 黑白名单 / 全局整形主配置
│   ├── self_firewall.json              # 本机守护 UID 四档防火墙与直连 DNS 管控配置
│   ├── device_names.json               # 设备备注名映射
│   ├── stats/                          # 跨日/跨月 SIM 与设备流量账单 (硬上限轮转)
│   └── self_studio/                    # 本机真值自训练样本与中间集 (硬上限轮转)
├── run/                                # 32MB tmpfs 瞬态内存盘 (重启清空, 禁放历史累积大文件)
│   ├── shm_vector.bin                  # 16384B seqcount_latch 双槽共享内存 (v3, 含 HostFlows 双域流拆分)
│   ├── dpi_state.json                  # DPI 实时快照与共享内存回退源
│   ├── httpd.pid / dpid.pid / watchdog.pid / launcher.pid / hotspotd.pid / dpid_guard.pid
│   ├── hotspotd.sock                   # hotspotd 本地 UNIX 控制套接字 (0600)
│   ├── local_admin.secret              # 本机免密管理凭据 (0600)
│   └── capabilities.json / iface_detect.json / root_env.json / offload_guard.json
└── logs/                               # 轮转运行日志 (service.log / httpd.log / dpid.log / watchdog.log / tc.log)
```

## 七、构建与质量门禁闭环

每次代码、规则或文档变更进入 `.github/workflows/build.yml` 时，均须通过全套自动化门禁：

1. **标签强一致、静态语法与老坑门禁**：Tag 推送或手动发版强制校验标签与 `module.prop` 的 `version` 完全一致；全仓 Shell 脚本 `sh -n`、前端独立脚本与 HTML 内联 `<script>` `node --check`、`sh ./bin/version_consistency_check.sh`、`sh ./bin/pitfall_lint.sh`、`sh ./bin/ci_preflight.sh`（含全仓零 Emoji Unicode 扫描与 `arm64` ELF `16KB` 页对齐校验）。
2. **双架构编译与结构体/数组步长对齐测试**：`daemon/hnc_httpd` 与 `src/dpid` 的 `go vet ./...`、`go test ./...`、32 位 `GOOS=android GOARCH=arm GOARM=7` 编译与 64 位原子字段（含结构体切片/数组步长 `sizeof % 8 == 0`）对齐测试，以及 `sh ./test/run_all.sh` 全套单元测试。
3. **双架构全组件现编与成品包纯净度核验**：每次 CI 从源码全新编译 `arm64-v8a` 与 `armeabi-v7a` 全套 6 大核心组件及全部辅助二进制/DEX，打包前执行 `sh ./bin/inject_version_to_docs.sh` 注入版本占位符并用 `HNC_RELEASE_CHECK=1 sh ./bin/version_consistency_check.sh` 复核，最后对双架构刷机包分别运行 `sh ./bin/artifact_sanity_check.sh` 强制校验全套编译产物齐全、字节级路由标记、架构纯净度并拦截 `fake_api.js` / `tools/` 混入刷机包。
