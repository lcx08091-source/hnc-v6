# HNC 代码地图(给项目负责人看的大白话版)

> 写于 v5.23.0-rc1。目的:不读每一行代码,也知道「东西在哪、怎么串起来、出了问题先看哪」。
> 行数为当时统计,只作量级参考。

## 1. 一句话

HNC 是一个装在手机里的 root 模块:**开机脚本把几个后台程序拉起来 → 它们盯着热点上的设备和流量 → 你在网页界面点按钮 → 后端调用内核工具(tc / iptables)去限速、封锁 → 再把结果和统计显示回界面**。

## 2. 手机上跑着的「人」(进程)

把 HNC 想成一个小公司,每个进程是一个员工:

| 员工 | 文件 | 语言 / 行数 | 干什么 |
|---|---|---|---|
| **前台接待**<br>`hnc_httpd` | `daemon/hnc_httpd/` | Go,约 3.7 万行(不含测试) | 网页界面的后端。收到你的点击 → 检查参数 → 调脚本执行 → 回结果;同时汇总设备、统计、识别结果给界面。端口 8443 / 8444 |
| **侦察员**<br>`hnc_dpid` | `src/dpid/` | Go,约 2.1 万行 | 抓热点上的网络包头(DNS、TLS 握手、QUIC 首包、HTTP),认出域名和指纹,写给 httpd 用。**只看握手、不看内容** |
| **门卫**<br>`hotspotd` | `daemon/hotspotd/` | C,约 1.2 万行 | 盯热点开关、谁连上来了(ARP / DHCP / mDNS 拿设备名)、定时任务调度 |
| **巡逻员**<br>`hnc_watchdog` | `src/dpid/cmd/hnc_watchdog/` | Go | 每 60 秒检查:进程还活着吗、tc 规则还在吗、配额 / 分时段到点了吗;坏了就修。`bin/watchdog.sh` 只保留被 `action` 调用的修复函数,主循环已是 Go 版(v5.26) |
| **侦察员的保镖(三选一)**<br>`hnc_dpid_guard` / `dpid_supervisor` / `hnc_launcher` | `bin/hnc_dpid_guard.sh` / `src/dpid/cmd/dpid_supervisor/` / `src/launcher/` | Shell / Go / C | 把 dpid 拉起来、挂了重启。由 `run/dpid_launcher.choice` 指定的「当前守护者」负责,选定后其他守护不再插手(v5.26 T2) |
| **执行队**<br>各种 `bin/*.sh` | `bin/` | Shell,约 2.3 万行 | 真正去改内核规则的:`tc_manager.sh`(限速 / 延迟队列)、`iptables_manager.sh`(打标记 / 封锁)、`apply_device_rule.sh`(一台设备的完整规则)、各种 `*_sync.sh` |

## 2.5 权威实现表(v5.26 起生效)

同一件事只认这一份实现,别处要么调用它、要么已删除:

| 功能 | 权威实现 | 说明 |
|---|---|---|
| 进程检测(pid → 是否 HNC 的进程) | `src/dpid/procfind`(共享包) | Self → pidfile(存活 + cmdline 校验)→ /proc 扫描;httpd 自检 / 功耗统计 / 运行状态 / 进程健康四处共用 |
| 热点网卡名 | `bin/hnc_iface.sh`(探测器)+ `src/dpid/ifacehint`(读取) | 结果写 `run/iface_detect.json`,10 分钟内新鲜则 dpid 侧全部信它 |
| 时钟是否可信 | `src/dpid/clockhwm`(共享包) | ≥2025(UTC)且不落后高水位 600 秒;shell 版 `hnc_clock.sh` 保留给脚本,镜像测试锁定常量一致 |
| 月用量 | `daemon/hnc_httpd` 的 `limitCtl` | 计费月,取防火墙累计与 DPI 合计的较大值;设备卡 / 配额 / 全局告警 / `/api/usage_month` 同源 |
| 告警写入(`run/alerts.jsonl`) | `src/dpid/alert` 的 `Append`(带 flock) | httpd 与看门狗两个进程并发追加安全 |
| 看门狗主循环 | `src/dpid/cmd/hnc_watchdog`(Go) | `bin/watchdog.sh` 只提供 `action` |
| dpid 守护 | `run/dpid_launcher.choice` 指定的那一个 | guard(shell)/ supervisor(Go)/ launcher(C)三选一机制保留,选定后不换手 |

---

## 3. 开机时发生什么

```
手机开机
 ├─ post-fs-data.sh   最早阶段:准备目录、拷二进制、设权限(漏设权限 = 功能静默失效,出过两次事故)
 └─ service.sh        系统起来后:
      ├─ 拉起 hotspotd(门卫)
      ├─ 按 run/dpid_launcher.choice 选定守护者,由它拉起 hnc_dpid(侦察员)
      ├─ 拉起 hnc_httpd(前台)
      └─ 拉起 hnc_watchdog(Go 版巡逻员),之后由它负责「谁挂了就拉起谁」
```

## 4. 三条最重要的链路

### 4.1 你点「应用限速」之后
```
网页 webroot/js/devices.js  (devAct → api.action('rule_set', …))
  → httpd  action.go  case "rule_set"
    → runBin("apply_device_rule.sh", "limit", mac, 下行, 上行)
      → iptables_manager.sh  给这台设备的包打上标记(mark)
      → tc_manager.sh        在热点网卡上建 HTB 限速队列,按标记分流
      → 写 data/rules.json   记住规则(重启后由 watchdog 恢复)
  ← httpd 返回成功 → 网页刷新这张设备卡
```

### 4.2 认出「这台设备在用抖音」
```
hnc_dpid  src/dpid/capture/  抓 DNS / TLS SNI / QUIC / HTTP Host + 算 JA4
  → src/dpid/output/          写 run/ 下的识别结果、流水
httpd 读进来:
  traffic_ident.go  域名 → 应用(规则库 data/dpi_rules.json + data/dpi_rules.d/)
  fp_learn.go       TLS 指纹学习 / fp_user_rules.go 你的纠正
  ip_owner.go       IP 属于哪家公司
  flow_shape.go     流量形态(看视频 / 游戏 / 通话…)
  fg_model.go       综合推断「正在用」
  → /api/devices、/api/connections → 网页显示
```

### 4.3 流量统计
```
watchdog / stats_sample.sh 定时采样计数 → stats_rollup.sh 汇总
httpd: app_usage.go(按应用)、phone_usage.go(本机 / 热点 / 分卡)、
       stats_calibration.go(和系统流量管理对账)、stats_health.go(统计是否健康)
```

## 5. 目录地图

```
hnc-v6/
├─ module.prop / customize.sh / post-fs-data.sh / service.sh / uninstall.sh   模块安装与开机入口
├─ daemon/
│   ├─ hnc_httpd/     ★ 后端主体(116 个 Go 文件)
│   ├─ hotspotd/      门卫(C)
│   ├─ clsact_ctl/    硬件加速兜底用的 BPF 控制工具(C)
│   └─ tc_netlink/    上行限速辅助(C)
├─ src/
│   ├─ dpid/          ★ 抓包识别(capture 抓包 / output 输出 / apkscan 扫本机 App / bytestats 流量计数 / alert 告警 …)
│   └─ launcher/      dpid 的守护启动器(C)
├─ bin/               ★ 执行脚本(tc / iptables / 同步 / 自检 / 诊断 / CI 检查)
├─ webroot/           ★ 网页界面
│   ├─ index.html     页面骨架
│   ├─ css/           base(通用) / apple(苹果风) / liquid(液态玻璃)
│   └─ js/            core(底层+数据) → fx(动画) → devices / apps / stats / settings(四个页面) → sheets(弹层) → main(点击分发)
├─ data/              出厂数据:应用规则库、IP 归属库、OUI 厂商库、JA4 种子指纹
├─ test/              shell 测试(test/run_all.sh,415 项)
├─ tools/             离线工具(生成 IP 归属库等)
├─ third_party*/      第三方库(不是我们写的)
├─ docs/              API 文档、路线图、本文件
└─ .github/workflows/build.yml   推 main 自动打包发版
```

## 6. 数据存在哪(手机上)

模块运行目录(`/data/local/hnc/` 一带):

| 目录 | 放什么 | 特点 |
|---|---|---|
| `data/` | 你的设置和规则:`rules.json`(限速等)、配额 / 分时段、纠正记录、指纹学习表、DNS 接管配置… | **要保留**,约 60 个 JSON / JSONL 文件各自读写 |
| `run/` | 运行时状态:进程 pid、实时识别结果、活动档位、前台时间线 | 重启可丢 |
| `logs/` | 各进程日志 | 自动轮转 |

## 7. 出了问题先看哪

| 现象 | 先看 |
|---|---|
| 网页打不开 / 白屏 | httpd 是否在跑(设置 → 诊断 → 运行状态);远程浏览器白屏可能是 CSP(`security_headers.go`) |
| 限速不生效 | 自检报告「限速能力」;硬件加速兜底(`hnc_offload_guard.sh`);`tc_manager.sh` 日志 |
| 识别不准 | 设置 → 应用识别 → 识别纠正与指纹学习;连接上看「依据」标签;dpid 是否在跑 |
| 统计对不上 | 设置 → 诊断 → 运行健康 → 统计健康;和系统流量对账 |
| 一切都怪 | 设置 → 诊断 → 导出诊断包,发给 AI / 开发者 |

## 8. 规模参考

业务代码约 10.3 万行(Go 5.85 万、Shell 2.33 万、C 1.45 万、前端 0.57 万),测试约 2.45 万行。
`daemon/hotspotd/lsm/vmlinux.h`(15.5 万行)是工具生成的内核类型头文件,不是手写代码。
