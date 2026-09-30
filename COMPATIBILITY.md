# HNC 兼容性矩阵

**当前版本**: v5.3.0-rc30.12.30 <!-- rc30.12.30: 文档版本号统一同步 module.prop -->
**最后更新**: 2026-05-19

**图例**:
- ✅ 工作
- ⚠️ 工作但有限制(见备注)
- 🔧 需要 rc30.12.3+ 才能工作
- ❌ 不工作
- ❓ 未测试

---

## 一、确认工作

| ROM | 设备 | Android | 内核 | Root | 限速 | DPI | SQM | 关键备注 |
|---|---|---|---|---|---|---|---|---|
| **ColorOS 16** | realme GT 7 Pro (RMX5010) | 16 | 6.6.102-android15-9 | SukiSU Ultra | ✅ | 🔧 | ✅ | **主测设备**. **必须 rc30.12.3+** 才能用 — 早期版本 Go fork EPERM 必现, dpid 一直 blind. 详见第三节. |

---

## 二、待测 / 待报告

按"撞 Go fork EPERM 概率"从高到低排:

| ROM | 设备示例 | Android | 风险 | 备注 |
|---|---|---|---|---|
| **OxygenOS 15** | OnePlus 13 | 15 | 🟥 高 | 跟 ColorOS 共享内核, 大概率同样的 Go fork EPERM. 仍需 rc30.12.3+. |
| **MIUI 14+ / HyperOS 2** | 小米/红米 | 14-16 | 🟧 中 | 小米可能有不同 kernel hook, 需真机验证 |
| **ColorOS 14/15** | realme/OPPO 老机型 | 13-15 | 🟧 中 | 旧 ColorOS 不一定有 CLONE_VM hook |
| **OriginOS 5** | vivo/iQOO | 14-16 | 🟨 低 | vivo 历史上 root 兼容性更好 |
| **OneUI 7** | Samsung Galaxy | 15-16 | 🟨 低 | 三星生态相对独立, 未知 |
| **Pixel 原生 16** | Pixel 8/9 | 16 | 🟩 极低 | KernelSU 主测平台, Go fork 应该 OK (但仍建议 rc30.12+ 兜底) |
| **LineageOS 22** | 通用 | 15 | 🟩 极低 | AOSP 衍生, 大概率 Go fork OK |
| **APatch** | 通用 | 13-16 | ❓ | 不同 root 框架, 行为可能不同 |

---

## 三、已知重要问题:Go fork+exec EPERM(rc30.12 之前)

### 症状

在 ColorOS 16 + SukiSU 上, 模块装上后 WebUI 显示:

```
HTTP fetch failed; bridge auto disabled
hnc_httpd 未运行
DPI 状态: 盲模式·未抓包
```

日志显示:
```
[WDG-GO] hnc_dpid: launch failed: 
fork/exec /data/local/hnc/bin/hnc_dpid_supervisor: operation not permitted
```

### 根因

Go runtime 用 `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` 的 vfork-style 路径**被内核 hook 拦截**.

**不是 SELinux 问题**(无 AVC denied), **不是 seccomp**(Seccomp=0), **不是 capability 问题**(full caps). 系统层面没任何限制, 但 Go fork+exec 必报 EPERM.

C bionic `fork()+execv()` 不带 `CLONE_VM`, 完全工作.

### 修复

**rc30.12+** 引入两层修复:

1. **C launcher 替代 Go supervisor** (`bin/hnc_launcher`)
   - 用 bionic fork+execv 绕开 Go vfork 路径
   - 由 `bin/fork_probe` 启动时探测自动选择
   - 探测失败自动降级 shell guard

2. **dpid 内部 retry 修复** (rc30.12.3)
   - 接口未就绪时 dpid 自动每 2 秒重试 bind, 不再需要手动点"重新绑定"

### 影响版本

- rc30.0 - rc30.11: ❌ 在 ColorOS 16 + SukiSU 上整条后端起不来
- rc30.11: ⚠️ shell pre-launch 临时绕过, 系统能用但不优雅
- **rc30.12.3+**: ✅ **完整修复**, 装上即用

### 详细文档

- `PATCH-NOTES-v5.3.0-rc30.12.3.md` — 完整诊断链 + 修复
- `go-fork-eperm-coloros-sukisu-diagnosis.md` — 公开技术笔记
- `ARCHITECTURE.md` 第三章 — 在项目里的位置
- `EVOLUTION.md` 第七到第九章 — 这条修复链怎么走过来的

---

## 四、其他已知限制

| ROM 系 | 问题 | 缓解措施 |
|---|---|---|
| **ColorOS / OxygenOS** | `oplus_netd` 主动清外部 tc 规则 | HNC 自愈已覆盖, watchdog 检测到清除后自动重建 |
| **ColorOS 16 + Snapdragon 8 Elite** | Android BPF fast path (tether_limit_map) 截胡 tethered 流量, 部分绕开 tc 限速 | 当前未修, 但实战极少触发(只在系统级 tethering offload 开启时) |
| **MIUI 14+** | (待确认) `miui_net_*` 服务可能类似 oplus_netd | 需真机验证, 大概率自愈机制能应付 |
| **老旧 AOSP (Android < 13)** | 无 BPF tethering offload | 上行限速走兜底路径, 精度下降 |
| **iOS 客户端连接** | "私有 WiFi 地址"每次随机 MAC | 客户端关掉此功能; 或接受每次重新配规则 |

---

## 四·五、跨机型适配层(v5.20)

> 以下逻辑只在 RMX5010 / ColorOS 16 上真机验证过; 其他机型的行为来自 AOSP 源码与 fixture 单测, **需真机回报**。

### 热点接口探测 —— `bin/hnc_iface.sh`(唯一权威)

顺序: 用户偏好(rules.json `hotspot_iface`, 接口存在且有 IPv4 才生效)→ `dumpsys tethering`
(Android 8–10 为 `dumpsys connectivity tethering`)的 `TetheredState` → netd `tetherctrl_FORWARD`
→ `dumpsys wifi` 的 `mApInterfaceName` → AP 名扫描(`ap0` / `ap_br_*` / `swlan0` / `softap0`, 次选
`wlan1+` / `wigig0`; 须 UP、RFC1918 IPv4、**没有任何 default route**、不是上游)。非权威来源绝不返回 `wlan0`。
热点关着时只跑一次 `ip addr` + `ip route`, 不跑 dumpsys。结果写 `run/iface_detect.json`(字段见脚本头),
`device_detect.sh iface` / `hotspot_autostart.sh` / httpd `currentHotspotIface` 都读它。

| 机型(预期) | 热点口 | 蜂窝上游 |
|---|---|---|
| ColorOS / realme / OnePlus(高通) | `wlan2` | `rmnet_dataN` |
| Pixel(Tensor) | `wlan1` 或 `ap0` | `rmnetN` |
| Samsung One UI | `swlan0` | `rmnet_dataN`(高通)/ `rmnetN`(Exynos) |
| 联发科(天玑) | `ap0` | `ccmniN` |
| 展锐(Unisoc) | `wlan1` / `ap0`(待确认) | `seth_lteN` / `sipa_ethN` |
| Android 12+ 双频桥接热点 | `ap_br_wlanN` | — |

- **USB(`rndis0`/`usb0`/`ncm0`)/ 蓝牙(`bt-pan`)/ 以太网共享**: 只探测并在 `iface_detect.json`
  (`usb_tether` / `bt_tether` / `eth_tether`)与 `/api/live` 里上报; **限速、封锁、统计只作用于 Wi-Fi 热点口**,
  这些共享方式的客户端不在管控范围内。
- **`wlan0` 本身做 AP 的老机型**(单接口, 开热点时断开 Wi-Fi): 探测器能从 tethering / softap 权威来源
  认出(`wlan0_ap:true`), 但 watchdog 仍按历史事故保护拒绝在 `wlan0` 上挂规则 —— 此类机型目前不受管控。
- 蜂窝名字表 shell(`HNC_CELL_IFACE_ERE`)与 Go(`iface_patterns.go`)逐字一致, `go test` 校验。

### 开热点命令(定时热点 / 开机自启)—— `bin/hnc_compat.sh hnc_softap_probe`

先读 `cmd wifi help` / `cmd -l` / `svc wifi` 帮助文本, 再按可用性尝试:
`start-softap … -b any`(Android 12+)→ `start-softap`(Android 11)→ `cmd tethering tether wifi`(仅个别 ROM)
→ `svc wifi hotspot enable`(仅个别定制 ROM)。加密类型只试帮助里列出的。**Android 10 及以下没有
`start-softap`, 命令行无法开热点, 请从系统设置开**。`start-softap` 起的热点不带系统 NAT, HNC 自建 NAT。
探测与最近一次结果写 `run/softap_method.json`。

### root 方案 —— `bin/hnc_compat.sh root`(service.sh 启动时调用)

识别 KernelSU / SukiSU-Ultra / KernelSU-Next / APatch / Magisk, 选对应 busybox
(`/data/adb/ksu/bin/busybox` / `/data/adb/ap/bin/busybox` / `/data/adb/magisk/busybox`)作为
`/system/bin` 被卸时的 applet 兜底源, 写 `run/root_env.json`(含 SoC 厂商、SDK、PATH 审计)。
**Magisk 没有模块 WebUI**: 用手机浏览器打开 `run/webui_url`(`http://127.0.0.1:8444`), 用登录密码 / 配对码登录。
注意: `ip` / `iptables` / `tc` / `cmd` / `dumpsys` 是动态链接程序, 依赖 `/system/bin/linker64`, `/system/bin`
被卸期间任何副本都跑不起来(`root_env.json` 的 `path_dynamic_only` 列出缺失项), 只能等挂载恢复。

### 联发科 HWNAT(实验性)—— `bin/hnc_mtk_hwnat.sh`

仅在 offload 兜底为 **on 模式**时调用; 检测 `/sys/kernel/debug/hnat`、`/proc/hnat`、`/sys/module/*hnat*`、
`mtk_ppe`、MDDP; 有可写 `hook_toggle` 等开关才写 0, 撤销兜底 / 切回 auto 时写回原值。**高通平台绝不动作**。
状态见 `run/mtk_hwnat.json` 与 `run/offload_guard.json` 的 `hwnat` 字段。

### 老内核(4.x)降级

cake / fq_codel / IFB / mirred / netem 由 `capability_probe.sh` 探测后按能力跳过; `xt_string`(连接封锁)
在 `connblock_sync.sh` 首次探测并缓存; clsact BPF 无产物时静默; conntrack 事件订阅失败时 httpd 退纯轮询,
**只记一次日志**(v5.20 起, 此前每 60 秒一行)。

---

## 五、报告兼容性的方法

### 1. 装最新版

下载 `HNC-v5_3_0-rc30.12.8-arm64.zip` 或更新版本.

### 2. 跑诊断脚本

```sh
su -c '/data/local/hnc/bin/diag/diag.sh' > /sdcard/hnc_diag.txt
```

这个脚本会一键收集:
- 系统/内核版本
- Root 框架
- 进程清单
- 所有 daemon 二进制版本
- **fork+exec 兼容性测试** (C 和 Go 都测)
- /proc/self/status (Seccomp / NoNewPrivs / CapEff)
- AVC denied 历史
- 热点接口状态
- capabilities.json
- dpid 状态
- 关键日志尾部

报告**不包含任何个人数据**(IP / MAC / 设备名), 只有技术信息.

### 3. 提交报告

如果项目有 GitHub Issue, 开 issue 标题:
```
[Compatibility] <ROM 名> <Android 版本> <设备型号>
```
附上 `hnc_diag.txt` 全文.

如果是自用项目, 把 diag.txt 存档自己看就行.

---

## 六、WebUI 内查兼容性

装上后, 在 WebUI:

1. **设置页 → 兼容性能力** 卡片
   - 自动读 `run/capabilities.json`
   - 显示 51+ tc/iptables/内核能力字段
   - **rc30.12.8+ 新增** fork / launcher / SELinux 探测字段

2. 关键新字段 (rc30.12.8+):
   - `c_fork_supported`: C fork+execv 是否工作 (由 fork_probe 测)
   - `go_fork_supported`: Go fork+exec 是否工作
   - `kernel_blocks_clone_vm`: 是否推断内核拦截 CLONE_VM
   - `selected_launcher`: 当前用 c_launcher / shell_guard / go_supervisor 哪个
   - `dpid_has_iface_retry`: dpid 二进制是否含 rc30.12.3 字符串匹配修复
   - `selinux_avc_denied_recent`: 最近 AVC denied 计数
   - `seccomp_active` / `no_new_privs` / `cap_eff_full`: 进程安全机制状态

如果你发现 `kernel_blocks_clone_vm=true` 且 `selected_launcher=c_launcher`, **你的设备就是这套修复救场的设备**.

---

## 七、给模块开发者的兼容性建议

如果你想 fork 这套架构做自己的模块, 记住:

1. **不要假设 Go fork 能工作**. 即使在自己开发机能跑, 国产 ROM 上很可能挂.
2. **必须有 C/shell fallback**. 至少保留一条不依赖 Go runtime fork 的启动路径.
3. **用 fork_probe 做自动路径选择**. 这是核心抗风险设计.
4. **在 ColorOS / MIUI / OneUI 至少一台上真测**. AOSP/Pixel 上的成功不代表国产 ROM 也行.
5. **任何 Go std lib 的网络错误判断, 不要只看 syscall errno**. `net.InterfaceByName()` 返回字符串错误, `errors.Is(syscall.ENODEV)` 不工作.

---

*本矩阵会随真机测试结果更新. 如果你测了一台没列在这里的设备, 欢迎补充.*
