# HNC 项目演化史

> 从 rc1 到 rc30.12.29,这个项目是怎么一步步走过来的

**起源**: 一个人想管自己的手机热点
**现状**: v5.3.0-rc30.12.29,5 进程 multi-language 架构 <!-- rc30.12.29: 文档版本号统一同步 module.prop -->
**作者**: Ling + Claude (Anthropic AI)
**时间跨度**: rc1 是早期,rc30.12.29 是 2026-05-19

---

## 0. 一句话项目史

> HNC 从"shell 写的热点限速脚本",**演化成**"集 DPI 流量识别 + 应用粒度限速 + 跨多语言守护的完整 Android 模块",**核心驱动力**是真机踩坑 → 加 fallback → 又踩坑 → 又加 fallback,**积累出**今天看似复杂但每层都有真实原因的架构。

---

## 一、起源:基础限速时代(rc1 - rc15)

### 痛点

手机开热点给电脑/平板/家人用,经常出现:
- 某台设备一开始下载就把整个热点速度吃光
- 想给孩子限制只用某些应用(微信可,抖音不行)
- 不知道连进来的设备是谁(MAC 地址看不懂)

Android 系统自带的"热点流量限制"只有"总流量上限"一个开关,远远不够。

### 解决方案

shell + iptables + tc 写的基础限速脚本:
- 每个设备一个 tc class,可独立限速
- iptables 规则做黑白名单
- 简单 web 服务器(早期是 Python http.server)展示状态

### 技术栈
- 100% shell
- `iptables` / `tc qdisc` / `tc class`
- 几百行脚本

### 这个阶段的特点
- **单文件**或几个文件 shell 项目
- **没有 daemon** 概念,全靠 cron / init.d 周期触发
- **简单可控**,但功能边界明显

---

## 二、第一次跃迁:hotspotd 引入(rc15 时期)

### 痛点

shell 周期触发的方式发现新设备至少要 5 秒,而且:
- 设备名只有 MAC 不友好
- 离线设备和在线设备区分不清楚
- shell 性能撑不起复杂逻辑

### 解决方案

写一个 C daemon `hotspotd`:
- **netlink RTGRP_NEIGH** 监听 ARP 表变化 — 亚秒级检测设备
- **mDNS 解析** — 拿设备真实名字("红米 K70" 而不是 `aa:bb:cc`)
- **DHCP snooping** — 从 hostapd 日志拿 hostname
- **OUI 数据库** — MAC → 厂商名映射(70k+ 条目)
- **流量统计** — 周期采样 tc 字节计数

### 技术跃迁
- 从 shell → C native daemon
- 从 polling → event-driven (netlink)
- 从无状态 → 有 pidfile / JSON 状态文件

### 这个阶段的痕迹
- `daemon/hotspotd/` 源码至今保留
- `data/oui.txt` 数据库至今使用

---

## 三、第二次跃迁:WebUI + Go httpd(rc15 - rc17)

### 痛点

Python http.server 太简陋:
- 写起来一堆 Python 模板字符串
- 性能不够(高并发会卡)
- 跟 daemon 间通信只能靠 shell 调用,慢

### 解决方案

写 Go 的 `hnc_httpd`:
- 单二进制 (静态链接, 没有 Python 依赖)
- 60+ REST API endpoints
- 内嵌 WebUI 静态文件 (HTML/CSS/JS)
- TLS / 配对码 / token 鉴权(远程访问)

### WebUI 重写

从简陋的 Python 模板 → 现代 SPA:
- 单文件 `index.html`(rc15 时几千行,rc30 时 1.1 万行)
- 玻璃拟态视觉风格(rc3.x 引入)
- 完整设备管理 + 限速 + DPI 分析界面
- 支持 KSU/Magisk WebUI 容器、独立浏览器、远程访问

### 技术跃迁
- 后端从 Python → Go
- 前端从模板 → SPA
- 通信从 shell exec → JSON 文件(daemon 写,httpd 读)

---

## 四、第三次跃迁:DPI 引入(rc17 - rc25)

### 痛点

光知道"某设备用了 200MB"不够,需要知道:
- 这 200MB 是抖音还是微信?
- 哪个应用一直在跑后台?
- 哪些 IP/域名是哪个应用的?

### 解决方案

写 Go 的 `hnc_dpid` (DPI = Deep Packet Inspection):
- **AF_PACKET 监听 wlan2** — 抓所有流量(不动 iptables/tc,只读)
- **DNS 包解析** — 抓 UDP/53 看域名查询
- **TLS ClientHello SNI 提取** — 即使 HTTPS 加密也能识别站点
- **规则库匹配** — 域名/IP → 应用名(本地 `dpi_rules.json`)
- **写 dpi_state.json** — 实时识别结果给 WebUI

### 多语言协作模式形成

- shell — 启动脚本、限速操作
- C — 设备识别 daemon(hotspotd)、限速工具(hnc_tc_ingress)
- Go — DPI daemon(hnc_dpid)、HTTP 后端(hnc_httpd)
- 前端 — HTML/CSS/JS

### 这个阶段的关键设计

**daemon 完全解耦**:
- hotspotd 不知道 dpid 存在
- dpid 不知道 httpd 存在
- 大家只通过 JSON 文件交换状态

**好处**: 单个 daemon crash 不影响其他
**代价**: 跨进程通信延迟 100-500ms(可接受)

---

## 五、第四次跃迁:nDPI 协作(rc25 - rc29)

### 痛点

主线 DPI 看不到:
- **QUIC 流量**(UDP/443,没有传统 TLS 握手)
- **HTTP/3 / Encrypted ClientHello**(完全加密的连接)
- 王者荣耀、抖音、B 站这些用 QUIC 的应用识别率低

### 解决方案

引入 nDPI(开源 DPI 库)做协作:
- 新增 `hnc_ndpi_probe` daemon(C,2.6MB)
- **抓 UDP/443 + TCP/443** 给 nDPI 处理
- **RFC 9001 QUIC Initial 解密** 提取 SNI
- **IP → 域名反查表** 喂给主线 dpid

### 这个阶段的复杂性

进程数从 3 涨到 4:
- hotspotd
- hnc_httpd
- hnc_dpid
- **hnc_ndpi_probe** ← 新增

watchdog 开始变得重要(进程多了需要统一守护)。

---

## 六、第五次跃迁:Go 化重构(rc30.0 - rc30.7)

### 痛点

shell guard(hnc_dpid_guard.sh) 用了很久,但:
- 启动慢(shell 解释执行)
- 3 个嵌套 sh 进程(看起来啰嗦)
- 在 post-fs-data 早期某些 ROM 上被 mount namespace 切换搞挂
- 日志非结构化,排查难

### 解决方案

**Go 化** — 写两个 Go daemon 替代 shell:

**rc30.0** — `hnc_dpid_supervisor`(Go,替代 `hnc_dpid_guard.sh`)
- 单进程
- 静态链接,启动快
- 结构化日志

**rc30.1** — `hnc_watchdog`(Go,替代老 shell watchdog)
- 整体进程守护
- 推送告警到 WebUI
- 自动恢复

### 表面上很好

在 Pixel + KernelSU 测试机上跑得飞起。架构变干净:
```
进程数: 4 个 daemon + 0 个 guard.sh
启动时间: 慢路径几秒 → 亚秒
日志: 结构化 JSON, 可分析
```

### 暗藏的危机

**没有在 ColorOS 16 + SukiSU 上测试**(因为开发机不是这个组合)。

---

## 七、危机爆发:rc30.10 的真机翻车(2026-05-17)

### 现象

Ling 把 rc30.10 装到自己手机(Realme RMX5010 / ColorOS 16 / SukiSU)上,**整条后端起不来**:
- WebUI 显示 "HTTP fetch failed; bridge auto disabled"
- 进程清单只有 `hotspotd`,其他全挂
- 日志:`fork/exec hnc_dpid_supervisor: operation not permitted`

### 第一轮诊断(走错路 2 小时)

排除了一堆错误猜想:
- 文件权限 → 排除
- SELinux context → 排除(无 AVC denied)
- chmod 时机 → 加了兜底,没解决
- seccomp filter → 排除(Seccomp=0)
- capabilities → 排除(full caps)

**全是猜,全错**。

### 第二轮诊断(找到真凶 1 小时)

关键洞察:**C 程序能 fork 就不是系统限制**。

写 `fork_probe.c`(C 写的 fork+execv 测试):
```
[1/3] calling fork()...   fork OK
[2/3] calling execv...    SUCCESS
[3/3] child exited 0
```

C bionic 100% 工作。Go runtime 必报 EPERM。

**真凶**:
- C bionic fork(): `clone(CLONE_CHILD_SETTID | SIGCHLD)` — 干净 clone
- Go runtime fork+exec: `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` — vfork 风格
- **ColorOS 16 内核或 SukiSU 拦截了带 CLONE_VM 的 clone 调用**(反内存共享攻击 / 反 root 探测)

---

## 八、紧急修复:rc30.11(临时绕过)

### 思路

既然 Go supervisor 起不来,**用 shell 把所有 daemon 都先拉起来**,Go supervisor 起不起来都不影响功能。

### 修法

- post-fs-data.sh 强化 chmod + chcon
- service.sh **shell pre-launch** 关键 daemon(httpd / dpid)
- 后台**哨兵循环**(30 秒巡检 4 个核心进程,死了重新拉起)

### 效果

系统**能用了**,但:
- Go supervisor 仍然起不来(sentinel 反复试启动徒劳)
- 看进程清单一堆 shell guard 的子进程,丑
- 没解决根本问题

**作废**(被 rc30.12.3 完整吸收后保留)。

---

## 九、根治:rc30.12 - 30.12.3(C launcher + dpid retry)

### rc30.12:C launcher 替代 Go supervisor

写 C 版 `hnc_launcher`(700 KB,静态链接 NDK API 21):
- 用 bionic `fork()+execv()` 绕开 Go vfork 路径
- 启动时探测接口 ready 再 fork dpid
- crash-loop 保护

**关键设计:fork_probe 兜底降级**

引入 `bin/fork_probe`,service.sh 启动时探测:
```sh
if fork_probe 通过 → 用 C launcher (优雅)
elif shell guard 存在 → 退回 shell (兼容)
else → 用 Go supervisor (最后兜底)
```

**永远不会比 rc30.11 差**。

### rc30.12.1 - 30.12.2:接口检测细化

发现 launcher 启动 dpid 太早,dpid 找不到接口进盲模式。

加接口就绪检测:
- `/sys/class/net/wlan2` 存在 → ✓
- `/proc/net/route` 有 wlan2 条目 → ✓

但 dpid 启动**仍然**进盲模式!

### rc30.12.3:发现 dpid 内部的 Go std lib 坑(根治)

跑去看 dpid Go 源码,在 `main.go` line 429 找到:

```go
func isRecoverableCaptureError(err error) bool {
    return errors.Is(err, syscall.ENETDOWN) || 
           errors.Is(err, syscall.ENODEV) ||      // 只看 syscall errno
           errors.Is(err, syscall.ENETRESET) || 
           errors.Is(err, syscall.ENXIO)
}
```

**真凶**: Go std lib 的 `net.InterfaceByName()` 在接口不存在时返回**字符串错误** `"route ip+net: no such network interface"`,**不是 syscall errno**。所以 `errors.Is(err, syscall.ENODEV)` → false → 判定不可恢复 → dpid 进 Blind 永不重试。

**修法 3 行**:加字符串匹配。

```go
msg := err.Error()
if strings.Contains(msg, "no such network interface") ||
   strings.Contains(msg, "no such device") {
    return true
}
```

dpid 重新交叉编译,版本号 `0.5.3-rc30.12.3-iface-retry`。

**效果**: 接口未就绪时 dpid 自动每 2 秒重试,接口 ready 后自动绑成功,**不再需要手动点重新绑定**。

---

## 十、收尾:rc30.12.4 - 30.12.7(UI 优化)

修完真凶后做 UI 优化:

- **rc30.12.4**: 设备页 DOM 重排(全局操作上移),DPI 页可折叠 sec-title(7 个次要 section 默认折叠)
- **rc30.12.5**: 进程诊断 + 能力探测改成默认展开,关于 DPI 模块字体优化(14px / 1.85 行距)
- **rc30.12.6**: 进程诊断 + 能力探测上移到设备应用画像之后,修空状态文字被左边切的 bug
- **rc30.12.7**: 设备页入场动画时序统一(device-filter-bar 之前 0s 立即出现,其他 0.2s 延迟,视觉错乱;改成按 DOM 自上而下 0.14-0.30s 入场)

---

## 十一、当前状态(rc30.12.7)

```
进程数: 5
  ✓ hotspotd       (C, 95KB)   - 设备识别
  ✓ hnc_httpd      (Go, 6.6MB) - HTTP + WebUI
  ✓ hnc_watchdog   (Go, 2.3MB) - 整体守护
  ✓ hnc_launcher   (C, 724KB)  - 守 dpid
  ✓ hnc_dpid       (Go, 2.9MB) - DPI 抓包

启动路径: fork_probe 自动选 C launcher (ColorOS 16) / shell guard (兼容)

WebUI: 5 个页面 (设备/统计/日志/DPI/设置), 完整动态色 + 折叠组

稳定性: 真机连续运行无人工干预, 重启自动恢复
```

---

## 十二、回顾:这条演化路径的几个教训

### 1. 真机踩坑驱动一切

每一次大跃迁(C 化 / Go 化 / C launcher)都是被**真实问题**逼出来的,而不是"我看 X 技术好,我也用一下"。

### 2. 不要因为优雅就重构

rc30.0 的 Go 化重构出发点是"shell 太啰嗦,Go 更现代",但**没有充分验证国产 ROM 兼容性**。结果在 ColorOS 16 上整条翻车,**反过来加了 C launcher**,架构反而更复杂了。

教训:**重构必须以"在所有真实部署环境上都能跑"为前提**,否则就是引入隐性 bug。

### 3. fallback 链条比"完美方案"更重要

rc30.12 引入 `fork_probe` 自动选路径,保留 3 个 fallback。**这是最重要的设计决策** — 因为它承诺"永远不会比之前差"。

后来证明这个设计真的救了命:Ling 真机 C launcher 工作,但万一未来在某台没测过的设备上不工作,会自动退回 shell guard,**用户无感**。

### 4. Go 在国产 ROM 上的兼容性是雷区

这次踩的坑(CLONE_VM 被内核 hook 拦)只是冰山一角。如果哪天再有 Go runtime 在国产 ROM 上的怪问题,**第一反应应该是"能不能用 C 绕过"**,而不是"怎么改 Go runtime"。

### 5. 多语言协作 + JSON 解耦是对的

shell + C + Go 协作,每个组件做自己擅长的:
- shell — 启动 / 限速 / 系统操作
- C — netlink / event-driven daemon / 包过滤
- Go — 业务逻辑 / HTTP / 复杂状态机

进程间用 JSON 文件解耦 — 简单,可调试,单点故障不连累。这个架构经得起 30 多次 rc 迭代,**值得继续保持**。

---

## 十三、未来方向(如果还要做的话)

按可能性排:

**P0 — 真有用**
- ✅ ARCHITECTURE.md(本文档,以及 EVOLUTION.md)
- 完整诊断脚本固化到 `bin/diag/`
- zip 减肥(去掉源码,只保留运行时)

**P1 — 中等价值**
- 修 dpid `decideMode` 早期 probe 阶段的洞(理论上还有 race condition)
- 健康自检脚本 `hnc_health.sh`
- 抓包工具固化(扩规则到其他游戏时省时间)

**P2 — 锦上添花**
- WebUI 重设计(其他 AI 风格融合)
- C launcher 在其他 Android 版本兼容性测试
- 国际化

**P3 — 暂时别做**
- Go watchdog 接管 launcher(收益太小)
- 开源整个项目(自用就够了)
- 写更多公开技术笔记(除非有真实需求)

---

## 后记

这份演化史最重要的价值不是"记录历史",而是**告诉未来的你 / AI**:

> 这个项目的复杂性不是过度设计,而是真实踩坑积累的。
> 每一层 fallback 都对应一次真实的翻车经验。
> 没有银弹,只有"在你的真实部署环境上,真的能跑"。

如果你 3 个月后回来想"砍掉 shell guard 让架构更干净",**先读这份文档第 7 章**。Go 化重构带来的危机,我们已经踩过一次了。

如果你想"用 Rust 重写所有 daemon 让性能更好",**先在 ColorOS 16 + SukiSU 上测一下 Rust runtime 是怎么 fork 的**。如果它也用 CLONE_VM,你会重演 rc30.0-30.11 这条悲剧之路。

**不要假设技术的优雅度等于实用度。**

---

*Ling × Claude, 2026-05-17*
*HNC v5.3.0-rc30.12.7*
