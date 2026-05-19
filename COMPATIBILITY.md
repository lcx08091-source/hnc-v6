# HNC 兼容性矩阵

**当前版本**: v5.3.0-rc30.12.8
**最后更新**: 2026-05-17

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
