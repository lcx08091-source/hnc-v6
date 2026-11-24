# HNC 兼容性矩阵与实测边界说明

**当前版本**: v6.1.0-rc.6
**最后更新**: 2026-11-24

本文件遵循「实测一分说一分，未实测绝不夸大承诺」的工程原则，将 HNC `v6.1.0-rc.6` 的平台兼容性严格划分为**基准真机实测验证**、**源码级防御护栏（待对应真机回报）**与**明确不支持或受宿主内核硬限制**三层证据边界。当任何底层能力在当前设备上不可用时，后端与 WebUI 均如实返回 `supported: false` / `available: false` 与具体原因码，绝不伪造成功状态。

## 一、已在基准真机完整实测验证（Tier 1 实证基线）

### 1.1 基准测试环境

| 维度 | 实测配置详情 |
|---|---|
| 机型与 SoC | realme GT 7 Pro (`RMX5010`) · 高通骁龙 8 至尊版 (`SM8750`) |
| 系统与内核 | ColorOS 16 (Android 16) · Linux `6.6.x` GKI (`arm64-v8a`, `16KB` 页对齐兼容) |
| Root 与挂载环境 | SukiSU Ultra (`magic_mount_rs`, `umount=false`) + SuSFS |
| 热点与蜂窝接口 | Wi-Fi 热点口 `wlan2`（及双频桥接态）· 蜂窝上游 `rmnet_dataN`（双物理 Nano-SIM 卡槽） |

### 1.2 已在该基准真机逐项跑透并闭环的兼容能力

1. **C 原生守护启动器绕过 `CLONE_VFORK EPERM` 与看门狗身份核验防误杀**：
   - ColorOS 16 + SukiSU 内核钩子会拦截 Go runtime 的 `clone(CLONE_VM | CLONE_VFORK)` 并固定返回 `EPERM`。
   - `./service.sh` 启动期通过 `bin/fork_probe` 自动实测，由 C11 编写的 `bin/hnc_launcher` 使用不带 `CLONE_VM` 的 Bionic `fork() + execv()` 稳定拉起并按指数退避守护 `hnc_dpid`；`hnc_watchdog` 巡检与重启前同步核验 `/proc/<pid>/cmdline`（回退 `comm`），彻底杜绝系统 PID 复用导致误杀系统进程。
2. **`/system/bin` 间歇卸载耐受与 `/data` 备份工具链垫片**：
   - 针对运行期挂载命名空间切换或间歇卸载，高频流控与邻居感知优先走纯 Go 原生 `AF_NETLINK` 直连与 `/proc`、`/sys` 直读；外部命令调用统一经 `./bin/hnc_env.sh` 的 `/data` 备份工具链垫片解析，并配 `Setpgid` 独立进程组 2 秒硬超时连根清理与连续超时熔断保护。
3. **缺省无 `sch_cake` / `sch_fq_codel` 内核的自动无感降级**：
   - 基准 GKI 6.6 内核未编译 `sch_cake` 与 `sch_fq_codel`。`./bin/capability_probe.sh` 与原生 RTNetlink 引擎实测探测后，自动按五级叶子队列回退链降级至可用调度器（直至按限速值动态缩放队列深度的 `pfifo(16..256)` 配合 `HTB` 令牌桶）；无 `ifb` 模块时上行限速自动切换至双栈 `clsact` / `ingress police`。
4. **高通热点硬件加速（`tether_limit_map` / IPA 快路径）截流检测与双路径修复**：
   - 开启系统级热点硬件加速时，Android `tether_limit_map` / `tether_downstream4_map` / `tether_downstream6_map` 与高通 IPA 快路径会旁路软件 `tc` 队列。
   - 已实测验证两套闭环方案：一是 `hotspotd` 与 `./bin/hnc_offload_guard.sh` 在设备纳入管控时 `T+0` 置位压制并动态驱逐加速表项，同时在 `/api/dataplane_verify` 中交叉对比真实转发流量与 HTB 命中字节计算截流比例；二是当固件锁死 IPA 硬旁路时，WebUI 自检卡片直接给出前往「系统设置 -> 连接与共享 -> 个人热点」关闭热点硬件加速的明确指引。
5. **原生 `dumpsys isub` 双卡物理槽位与信号监测统一对齐及 `BOOTCLASSPATH` 环境保护**：
   - 摒弃易将历史换卡自增 `subId`（如 `subId=9`）误判为新卡或渲染出「第 3 张未知卡」的旧逻辑，实测打通原生 C++ Binder 服务 `dumpsys isub` + `dumpsys telephony.registry` 权威链路，在流量账单与实时信号诊断双路径统一过滤 `INVALID_SUBSCRIPTION_ID`（`2147483647`）、`pid>=2` 软 SIM 与 `v4-` CLAT 转换口前缀，严格按在位物理卡槽 `simSlotIndex`（`0` 为卡 1，`1` 为卡 2）映射并识别 `activeDataSubId` 当前上网卡。
   - 所有需经 `app_process` 执行的系统命令（`content`、`settings`、`cmd`、`am`）均完整保留宿主 `BOOTCLASSPATH`、`SYSTEMSERVERCLASSPATH` 与 `ANDROID_*` 环境变量，根除空环境导致的静默空输出。
6. **`32MB tmpfs` 瞬态内存盘与持久化目录物理隔离**：
   - 实测验证 `/data/local/hnc/run` 挂载 `32MB tmpfs` 零闪存磨损运行，跨月 SIM 流量账单与本机真值自训练样本已全量迁入持久化 `/data/local/hnc/data/stats/` 与 `/data/local/hnc/data/self_studio/`，配齐硬配额轮转与原子写失败即删 `.tmp` 孤儿清理。
7. **ColorOS 16 / Kernel 6.6 GKI 本机 `netd_shared` BPF 只读流量感知与 Android 14+ 多维功耗归因**：
   - 实测以 `BPF_F_RDONLY` 只读方式打开 `/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map`（`4B` UID Key）与 `map_netd_uid_counterset_map`，实现按需 8 秒短租约的本机应用实时网速与前后台流量拆分；配合流式 `dumpsys batterystats --charged` 单飞解析，稳定提取 Android 16 多状态后台/息屏耗电（`mAh`）、Partial Wakelock 与射频唤醒排行。
8. **电池温度伪装模块（如 `fopbatt` `-10°C` 偏置）下的机身壳温防致盲校准**：
   - 针对刷入快充/性能模块（如 `fopbatt` 将 `/sys/class/power_supply/battery/temp` 人为偏置 `-10°C`）导致单电芯读数失真的场景，已实测通过 `/sys/class/thermal` 机身壳温传感器（`shell_*` / `skin*`）与电芯温度双源交叉校准识别偏置，自动切入真实机身壳温基准驱动 `ThermoCruise`，并在热点待机时保持零副作用只读实时刷新。
9. **Android 13~16 本机四档防火墙、多用户分身保护、SDK Sandbox（`uid + 10000`）协同与本机连接手术刀**：
   - 实测验证 `filter/OUTPUT` `HNC_SELF_UID` 四档策略（放行 / 仅禁明文 HTTP / 禁移动数据 / 全局禁网）、`HNC_SELF_DNS` 直连 `:53` 封堵及 `HNC_SCALPEL_HOST`（`SOCK_DESTROY` + 五元组秒断/冻结），通过 `./bin/self_firewall_sync.sh` 自动联动封禁 Android 13+ 伴生 `sdk_sandbox` UID（`uid + 10000`），将 `:8443`/`:8444` 管理端口豁免严格收紧至回环与本机局域网接口（阻断外网同号端口逃逸），并按 `appId = uid % 100000` 覆盖多用户与应用双开分身防自锁门禁。

## 二、已按 AOSP / 内核源码实现防御护栏、待对应机型实机反馈验证（Tier 2 防御适配）

以下芯片平台、跨代 Android 版本、定制 ROM 与特殊硬件拓扑已依据 AOSP 源码、内核公开接口与离线夹具单元测试编写了非破坏性防御护栏（所有 `sysfs` / `procfs` / `bpffs` / 命令调用均严格校验存在性与返回码，失败即安全退避），但**尚未在所有跨代机型上逐台跑完完整长稳测试，欢迎持有对应机型的用户反馈诊断日志**：

| 适配领域 | 目标平台 / 场景示例 | 已落地的代码防御护栏 | 待实机核验重点 |
|---|---|---|---|
| **`netd_shared` BPF Map Schema 跨代兼容** | Android 12 ~ 16 不同 GKI 分支与厂商定制内核 | 同时适配新一代 `map_netd_app_uid_stats_map`（`4B` `uint32 uid` Key）与旧版 Android 12 / 分支内核的 `map_netd_stats_map_A` / `map_netd_stats_map_B`（`16B` `{uid, tag, cntSet, ifaceIndex}` 复合 Key 聚合）；全程强制 `BPF_F_RDONLY` 只读打开，若无权限、未挂载 `bpffs` 或键值尺寸异构，自动无感降级至 `dumpsys netstats --uid` 并如实标注实时速率受限原因 | Android 12 / 13 早期非 GKI 定制内核中 `netd_shared` Map 路径命名与 SELinux 只读访问边界 |
| **`batterystats` 跨版本功耗拆分与回退** | Android 14 ~ 16 多状态模型 vs Android 9 ~ 13 传统模型 | 流式解析器在 Android 14+ 提取前台、后台与息屏分项 `mAh`；在仅输出合并总 `Estimated power use` 的 Android 9 ~ 13 上严格执行诚实回退，仅展示真实总 `mAh` 及精确 Wakelock / Alarm / 射频唤醒计数，绝不按流量比例伪造后台 `mAh` | 各厂商定制 ROM 对 `dumpsys batterystats --charged` 功耗字段的裁剪或格式扩展 |
| **电池低温伪装与异构壳温交叉校准** | 刷入 `fopbatt` 等 `-10°C` 电池温度偏置模块机型、双电芯串联机型 | `ThermoCruise` 自动归一化毫摄氏度、十分之一度与摄氏度三量纲并熔断越出 `[-20°C, 100°C]` 的离群读数；同步扫描 `shell_front`/`shell_frame`/`shell_back`/`skin*` 等机身壳温节点交叉比对，电芯被模块人为拉低时自动由壳温接管防致盲，无壳温节点机型安全回退电芯温度 | 不同品牌机型（小米 / vivo / 三星 / Pixel）机身表皮 `thermal_zone` `type` 命名覆盖度 |
| **Android 13+ SDK Sandbox UID 协同管控** | Android 13 ~ 16（含多用户 / 应用分身 `userId * 100000`）及 Android 9 ~ 12 回退 | 对常规应用 UID（`appId` 位于 `10000..19999`）自动推导同用户伴生沙盒 UID（`uid + 10000`，即 `appId` `20000..29999`）同步施加 `HNC_SELF_UID` 四档规则，封堵广告 SDK 借独立沙盒进程逃逸禁网；Android 12 及以下无该沙盒进程，规则保持幂等无副作用 | 多开分身环境下宿主 ROM 自定义双开用户区间（如 `999` 用户）与沙盒 UID 的映射一致性 |
| **联发科天玑硬件加速** | 天玑 8000 / 9000 系列 (`ccmniN` 上游、`ap0` 热点口) | `./bin/hnc_mtk_hwnat.sh` 与 `./bin/hnc_offload_guard.sh` 按需探测 `/proc/hnat`、`/sys/kernel/debug/hnat`、`mtk_ppe` 与 `mddp` 节点；仅在节点可写时压制并在恢复时写回原值，高通机型绝不触碰 | 不同厂商天玑内核下 `mddp` / `hnat` 开关节点的实际权限与命名差异 |
| **三星 / 谷歌 / 展锐平台** | Samsung Exynos (`DIT`, `swlan0`)、Google Pixel Tensor (`wlan1`/`ap0`/`gti*`)、紫光展锐 (`seth_lteN`/`sipa_ethN`) | `./bin/hnc_iface.sh` 与 `iface_patterns.go` 同步维护多芯片蜂窝口与 AP 接口匹配表；Exynos `DIT` 状态仅在对应节点存在时执行探测与压制 | Exynos `DIT` 旁路压制深度、Pixel 新一代 `gti*` 热点桥接计数及展锐网卡命名完整性 |
| **小米 MIUI / 澎湃 OS 规则共存** | 小米 / 红米 MIUI 14+、HyperOS 1/2 | 防火墙与 `tc` 操作严格限定在 `HNC_*` 独立子链与归属标记内，绝不清空系统 `miui_net_*` 规则；`hnc_watchdog` 巡检发现外部守护清理挂载钩子时自动幂等补挂 | `miui_netd` 在省电模式切换或网络重连时是否周期冲刷 `mangle` 高位 `CONNMARK` |
| **单芯片同名 `wlan0` 热点门控** | 部分老旧或入门单路 Wi-Fi 芯片机型（开热点自动断开 Wi-Fi，复用 `wlan0` 做 AP） | `./bin/hnc_iface.sh` 仅在 `dumpsys tethering` 或 `softap` 权威源明确报告且无默认路由时标记 `wlan0_ap: true`，守护层保留严格安全门控防止向正在充当本机上游 STA 的 `wlan0` 误挂限速 | 单接口 `wlan0` AP 机型在开关热点瞬间的状态切换时序与防自锁边界 |
| **多 Root 框架与跨端浏览器** | KernelSU / KernelSU-Next / APatch (`SuperKey`) / Magisk 26+ / 32 位 `armeabi-v7a` Magisk | `./bin/hnc_compat.sh` 自动识别四大 Root 框架与各自 `busybox`；`./action.sh` 与 `./bin/pair_gen.sh` 支持免输配对进入；CSS 补齐 Chromium 83–110 回退，TLS 证书有效期 `<=397` 天兼容 iOS Safari | 不同 APatch 版本 WebView 桥接差异及老旧 32 位 ARMv7 机型的内核 Netlink 特性裁剪情况 |

## 三、明确不支持或受宿主内核硬限制的场景（Tier 3 硬边界）

遇到以下宿主环境硬限制时，HNC 无法绕过物理与内核边界，界面与 API 将如实展示不支持原因：

1. **无 Root 权限设备（含纯 ADB / Shizuku 环境）**：
   - **不支持**。HNC 依赖 `CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_BPF` 与 `/data/adb/modules` 系统级挂载，未获取完整 Root 权限（KernelSU / SukiSU / APatch / Magisk）的设备无法运行。
2. **宿主内核彻底裁除 `CONFIG_NET_SCH_HTB`（`tc_htb: false`）**：
   - 当极少数深度精简内核连基础 `HTB` 队列调度器都未编译时，分级带宽限速、单应用限速、`VectorExpress` 与 `RootShaperArbiter` 全局整形均**无法生效**（返回 `supported: false`）。此时 HNC 仅保留在线设备发现、流量统计、DPI 应用识别以及基于 `iptables/ip6tables` 的设备拉黑与域名/连接阻断能力。
3. **宿主内核禁用 `AF_PACKET` 或硬拦截原始抓包套接字**：
   - 若内核未开启 `CONFIG_PACKET` 或被安全模块阻止打开抓包套接字，`hnc_dpid` 将如实报告 `mode: "blind"` 与具体 `blind_reason`。DPI 应用级识别与 `LeakGuard` 明文检测停用，但基于 IP/MAC 的设备发现与上下行总带宽限速不受影响。
4. **内核缺失部分可选子模块时的局部能力边界**：
   - 缺失 `CONFIG_IFB` 或 `act_mirred`：无法构建 `ifb0` 上行二级 HTB 树，自动回退为双栈 `ingress police` 单级上行限速（不支持上行多级子类借用带宽）。
   - 缺失 `clsact` 或 eBPF 加载受限：无法启用 Tier-A（`clsact eBPF`），自动运行于 Tier-B（原生 Netlink HTB）或 Tier-C（批量管道模式）。
   - 缺失 Netfilter `xt_string` 模块：`./bin/connblock_sync.sh` 首次探测后缓存状态，基于报文特征串的辅助连接阻断跳过，仅保留 IP/端口与 DNS 级阻断。
5. **非 Wi-Fi 共享方式（USB / 蓝牙 / 以太网共享）**：
   - USB 网络共享（`rndis0`/`usb0`/`ncm0`）、蓝牙共享（`bt-pan`）与以太网共享仅在状态栏与 `/api/live` 中作为连接态势展示，**设备限速、战术舱调度与阻断规则仅作用于 Wi-Fi 热点接口**。
6. **Android 10 及以下系统的命令行自动开热点**：
   - Android 10 及更早版本系统无 `cmd wifi start-softap` 接口，定时热点与开机自动开热点无法通过命令行拉起，需用户在系统设置中手动开启热点（开启后限速与识别功能正常）。
7. **架构包混刷拦截**：
   - 64 位设备必须刷入 `HNC-*-arm64.zip`，纯 32 位 ARMv7 系统必须刷入 `HNC-*-armv7.zip`。刷错架构包时 `./customize.sh` 会调用 `./bin/hnc_arch.sh` 当场提示并中止安装，防止写入无法执行的二进制文件。

## 四、如何查看本机兼容性与提交真机反馈

### 4.1 在 WebUI 内一键查看

打开 HNC 管理界面，进入 **「设置 -> 运行自检 / 兼容性能力」**：
- 可实时查看 `./bin/capability_probe.sh` 与守护进程实测得出的内核队列支持项（`HTB`、`fq_codel`、`ifb`、`clsact`、双栈 `iptables` 扩展等）、当前激活的数据面层级（Tier-A / Tier-B / Tier-C）、`fork_probe` 启动路径与硬件加速截流核验结果。

### 4.2 导出脱敏诊断包协助适配

若在未实测机型上遇到接口未识别、限速被硬件加速旁路或双卡显示异常，可在 WebUI 点击导出诊断包，或在终端以 Root 权限执行：

```sh
su -c 'sh /data/local/hnc/bin/diag/diag.sh' > /sdcard/hnc_diag.txt
```

该脚本会自动采集内核版本、SoC 与 Root 环境、`run/capabilities.json`、`run/iface_detect.json`、守护进程状态与关键日志尾部，并对设备 MAC、IP 等个人隐私信息做脱敏处理，便于快速定位跨机型兼容差异。
