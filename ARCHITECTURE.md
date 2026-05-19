# HNC 内部架构手册

> 给未来的 Ling、Claude、或者任何接手这个项目的人

**版本**: v5.3.0-rc30.12.7
**最后更新**: 2026-05-17

---

## 这份文档解决什么问题

HNC 经过 30 多个 rc 迭代,现在的架构是**多层 fallback + 多语言协作**,看起来复杂。但每一层都有真实原因。这份文档讲清:

1. **5 个进程的职责分工**(为什么是这 5 个,不是更多/更少)
2. **数据流**(从设备连接热点到 WebUI 看到它的完整链路)
3. **3 套 fallback 的历史原因**(为什么 supervisor 有 C / shell / Go 三个版本)
4. **关键 JSON schema**(运行时状态文件)
5. **设备/环境特殊处理**(为什么 ColorOS 16 / SukiSU 需要单独路径)

---

## 一、整体架构图

```
┌──────────────────────────────────────────────────────────────┐
│  用户(手机浏览器 / KSU WebUI / Magisk MMRL)                  │
└──────────────────────────────────────────────────────────────┘
                           ↑↓ HTTP
┌──────────────────────────────────────────────────────────────┐
│  hnc_httpd  (Go, 6.6MB)                                       │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  - HTTP 服务器 (端口 8443/8444)                       │    │
│  │  - WebUI 静态文件 (embedded)                          │    │
│  │  - /api/* REST API                                    │    │
│  │  - 远程访问 / TLS / Token / Pairing                   │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
            ↑           ↑           ↑           ↑
            │ JSON 读   │ JSON 读   │ JSON 读   │ exec shell
            │           │           │           │
┌─────────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐
│  hotspotd   │ │   hnc_dpid    │ │ hnc_     │ │  action 类   │
│  (C, 95KB)  │ │  (Go, 2.9MB)  │ │ watchdog │ │   shell 脚本  │
│             │ │               │ │ (Go,2.3M)│ │              │
│ 设备识别     │ │ DPI 抓包      │ │ 整体守护  │ │ tc/iptables │
│ netlink     │ │ AF_PACKET     │ │ 进程     │ │ 限速/重启    │
│ mDNS/DHCP   │ │ DNS/TLS 解析  │ │ 健康     │ │              │
│ 流量统计     │ │ 应用识别      │ │ 状态     │ │              │
└─────────────┘ └──────────────┘ └──────────┘ └──────────────┘
       ↑              ↑
       │              │ fork() + execv()
       │              │
       │       ┌─────────────────┐
       │       │  hnc_launcher    │  ← C, 724KB, rc30.12 新增
       │       │  绕开 Go fork    │
       │       │  EPERM 问题      │
       │       └─────────────────┘
       │              ↑
       │              │ service.sh 启动
       │              │ (fork_probe 探测后决定用哪个)
       │
   ┌──────────┐
   │ wlan2    │
   │ /sys/class
   │ /net     │
   │ 内核接口  │
   └──────────┘
```

---

## 二、5 个核心进程

按启动顺序排:

### 1. `hotspotd` (C, 95KB)

**职责**: 设备识别 + 流量统计 + mDNS/DHCP 解析

**关键技术**:
- `netlink RTGRP_NEIGH` — 监听热点接口的 ARP 表变化,**亚秒级**检测新设备
- mDNS 解析 — 通过 ZeroConf 拿设备主机名
- DHCP snooping — 从 hostapd 日志拿 hostname
- OUI 数据库 — MAC 前缀 → 厂商名
- 写 pidfile + JSON 状态文件供 httpd 读

**特别说明**:
- 用 C 写,因为 netlink 是 Linux native API,Go 处理 netlink 不如 C 直观
- 主循环极简(单进程,无 goroutine 复杂度)
- 这个 daemon 是**第一个独立可工作的组件**(rc1 时代就有了),从未出过大问题

### 2. `hnc_dpid` (Go, 2.9MB)

**职责**: DPI 流量识别(应用粒度)

**关键技术**:
- `AF_PACKET` + cBPF — 抓 wlan2 上的 DNS (UDP/53) 和 TLS ClientHello (TCP/443)
- SNI 提取 + JA4 指纹 — 即使 ECH/Encrypted ClientHello 也能识别
- 内置规则库 + 用户可导入规则 — 域名/IP → 应用名映射
- nDPI 协作(rc30.3+) — 解密 QUIC Initial 提取 SNI,反查表喂给主线
- 写 `dpi_state.json` 供 WebUI 实时显示

**为什么用 Go**:
- 网络协议解析 Go 友好(net/http, encoding/binary, 强类型)
- 规则匹配 / JSON 解析 Go 写起来短
- 跨平台理论上方便(但这优势在 Android 反而成了今天的坑)

**特别说明**:
- **rc30.12.3 的字符串匹配 fix 必须保留** — 否则接口未就绪时 dpid 进 Blind 永不重试,只能手动点"重新绑定 DPI"
- 详见 `dpid/cmd/dpid/main.go` 的 `isRecoverableCaptureError()`

### 3. `hnc_httpd` (Go, 6.6MB)

**职责**: HTTP 后端 + WebUI 服务

**关键 API endpoints** (60+ 个):
- `GET /api/live` — 实时下/上行 + 在线设备数(WebUI 顶部 hero)
- `GET /api/devices` — 设备列表(带规则、流量、名字)
- `GET /api/dpi_state` — DPI 完整状态(WebUI DPI 页)
- `GET /api/stats` — 历史统计
- `POST /api/action` — 写操作(限速、加黑、清空等)
- `GET /api/health` — 各 daemon 健康
- `GET /api/capabilities` — 系统能力探测

**特别说明**:
- 二进制大(6.6MB)因为内嵌了 WebUI 静态文件
- TLS / 配对码 / token 鉴权全在这里
- **不直接做业务** — 只是 daemon 状态的"展示窗口" + shell 脚本的"触发器"

### 4. `hnc_watchdog` (Go, 2.3MB)

**职责**: 整体进程守护 + 故障恢复

**做什么**:
- 每 N 秒检查每个 daemon 的 pidfile 是否新鲜
- 进程死了 → 拉起来
- 上行接口变化(切 WiFi → 5G) → 重新跑 `ensure_tc_uplink.sh`
- 推送告警到 WebUI

**特别说明**:
- 自己**不 fork 子进程**(rc30.12 之前是,踩 Go fork EPERM 坑后改了)
- 改成**调用 shell 脚本**(watchdog.sh action mode),让 shell 去启动子进程

### 5. `hnc_launcher` (C, 724KB) — rc30.12 新增

**职责**: 守护 `hnc_dpid`(其他 daemon 由 watchdog 守护)

**为什么需要**:
- ColorOS 16 + SukiSU 拦截 Go runtime 的 `clone(CLONE_VM | CLONE_VFORK)` → Go 程序 fork 子进程必报 EPERM
- C bionic `fork()+execv()` 不带 CLONE_VM,100% 工作
- 所以**用 C 写 launcher,从 C 里 fork dpid**,而不是从 Go supervisor

**关键设计**:
- 启动时等接口 ready(`/sys/class/net/wlan2` 存在 + `/proc/net/route` 有路由)
- fork+execv() 启 dpid
- 监视 dpid 状态,死了重启(指数 backoff)
- 收 SIGTERM 时优雅退出

详见公开技术笔记 `go-fork-eperm-coloros-sukisu-diagnosis.md`。

---

## 三、3 套 fallback 的历史原因

**为什么有 supervisor 的 C / shell / Go 三个版本?**

这是 HNC 经过 3 次大重构后的产物,每一版都对应不同时期的痛点:

```
rc1 - rc25:  shell guard 路径 (传统)
              ↓
rc26 - rc29: Go supervisor 路径 (现代化)
              ↓
rc30.0-11:   Go 路径在 ColorOS 16 翻车
              ↓
rc30.12+:    C launcher 路径 (最终方案)
              ↓
              所有路径并存, fork_probe 自动选择
```

### v1: shell guard(`hnc_dpid_guard.sh`)

**rc1-rc25 时期**,纯 shell 实现:

```sh
# hnc_dpid_guard.sh (简化)
while true; do
    if ! pidof hnc_dpid >/dev/null; then
        /data/local/hnc/bin/hnc_dpid &
        echo $! > /data/local/hnc/run/hnc_dpid.pid
    fi
    sleep 5
done
```

**优点**:
- 任何 Android 设备都能跑(POSIX sh)
- 调试方便,直接看脚本
- 不依赖 NDK 编译产物

**缺点**:
- 启动慢(shell 解释执行)
- 3 个嵌套 sh 进程(guard + 包装 sh + dpid 本身)= 6MB 内存
- 在 post-fs-data 早期被 mount namespace 切换搞挂(rc29.x 翻过几次车)

### v2: Go supervisor(`hnc_dpid_supervisor`)

**rc30.0-rc30.11 时期**,Go 实现替代:

```go
// 简化逻辑
func main() {
    for {
        cmd := exec.Command("/data/local/hnc/bin/hnc_dpid")
        cmd.Start()  // ← ColorOS 16 在这里报 EPERM
        cmd.Wait()
        time.Sleep(2 * time.Second)
    }
}
```

**优点**:
- 单进程(1 个 supervisor 替代 3 个 sh)
- 启动快(静态链接 native)
- 日志结构化(json 输出)
- 跨 Android 版本理论兼容

**致命缺点**:
- **在 ColorOS 16 + SukiSU 上 `cmd.Start()` 必报 EPERM**(Go runtime fork+exec 用 CLONE_VM 被内核 hook 拦)
- rc30.0 起所有用此路径的设备都翻车
- 修不了(改 Go runtime 不现实)

### v3: C launcher(`hnc_launcher`)

**rc30.12+ 现行方案**,C 写守护进程:

```c
// 核心逻辑
while (running) {
    pid_t pid = fork();
    if (pid == 0) {
        execv("/data/local/hnc/bin/hnc_dpid", args);
    }
    waitpid(pid, &status, 0);
    sleep(2);
}
```

**优点**:
- 绕开 Go runtime vfork 问题(C fork 不带 CLONE_VM)
- 700KB,启动极快
- 在 ColorOS 16 + SukiSU 上**真的能跑**

**缺点**:
- 多了一个 C 源码要维护
- 需要 NDK 才能编(但反正你的项目已经在编 hotspotd 了)

### 自动选择(`fork_probe`)

**rc30.12 引入**, service.sh 启动时跑 `fork_probe` 探测:

```sh
if "$MODDIR/bin/fork_probe" /system/bin/true >/dev/null 2>&1; then
    # C fork 工作 → 用 C launcher (优雅路径)
    DPID_LAUNCHER="$MODDIR/bin/hnc_launcher"
elif [ -x "$MODDIR/bin/hnc_dpid_guard.sh" ]; then
    # C 不工作 → 退回 shell guard (兼容路径)
    DPID_LAUNCHER="$MODDIR/bin/hnc_dpid_guard.sh"
else
    # 最后兜底 → Go supervisor (在不踩 EPERM 的设备上工作)
    DPID_LAUNCHER="$MODDIR/bin/hnc_dpid_supervisor"
fi
```

**保留 3 个路径的意义**:
- 99% 设备走 C launcher(理论上 Android 5+ 都能跑)
- 1% 设备 C launcher 异常 → 自动降级 shell guard(rc1 时代验证过的稳定方案)
- 万一 shell guard 也异常 → 兜底 Go supervisor(老设备 / 老内核)

**永远不会比 rc30.11 差** — 是这个设计的核心承诺。

---

## 四、数据流(完整链路示例)

**场景**: 一台新手机连上热点,WebUI 上几秒后显示出来。

```
[t=0ms]   手机连热点 → 内核 ARP 表新增条目 → wlan2 接口
            ↓ netlink event (RTGRP_NEIGH)
            ↓
[t=10ms]  hotspotd 收到 netlink event
          - 查 mDNS (异步 worker, 100ms-1s)
          - 查 DHCP lease (从 hostapd log)
          - OUI 数据库查厂商
          ↓ 写 devices.json
          ↓
[t=200ms] hotspotd 完成设备识别, 写
          /data/local/hnc/run/devices.json
          - mac=aa:bb:cc, ip=192.168.43.x,
          - hostname=红米K70, vendor=Xiaomi
          ↓
[t=200ms] hnc_dpid 同时在抓包
          (AF_PACKET 监听 wlan2)
          - DNS 查询: example.com → IP
          - TLS ClientHello: SNI=douyin.com
          ↓ 写 dpi_state.json
          ↓
[t=300ms] hnc_dpid 完成识别, 写
          /data/local/hnc/data/dpi_state.json
          - client=aa:bb:cc → 抖音
          - bytes_rx=1234, bytes_tx=567
          ↓
[t=1000ms] WebUI 轮询 /api/devices + /api/dpi_state
           hnc_httpd 读两个 JSON, 合并返回
           ↓
[t=1100ms] WebUI 渲染设备卡片:
           "红米K70 · 192.168.43.5 · 抖音 · 1.2KB↓"
```

**关键点**:
- **进程间通过 JSON 文件解耦**,不用 socket/pipe(简单 + 可调试)
- hotspotd 和 dpid 完全并行,**不互相依赖**
- httpd 只是"读 JSON 然后返回 HTTP",**不参与业务**

---

## 五、关键 JSON schema(运行时状态文件)

所有运行时状态都在 `/data/local/hnc/run/` 和 `/data/local/hnc/data/`:

### `run/devices.json` (hotspotd 写, httpd 读)

```json
{
  "schema": 1,
  "hotspot_active": true,
  "hotspot_iface": "wlan2",
  "hotspot_ip": "192.168.43.1",
  "devices": [
    {
      "mac": "aa:bb:cc:11:22:33",
      "ip": "192.168.43.5",
      "hostname": "红米K70",
      "vendor": "Xiaomi",
      "online": true,
      "rx_bps": 12800000,
      "tx_bps": 450000,
      "first_seen": 1747507200,
      "last_seen": 1747510800
    }
  ]
}
```

### `data/dpi_state.json` (dpid 写, httpd 读)

```json
{
  "schema_version": "2.0",
  "iface": "wlan2",
  "mode": "ok",         // ok | blind | disabled
  "uptime_sec": 4523,
  "version": "0.5.3-rc30.12.3-iface-retry",
  "stats": { "pkts": 158234, "dns": 24891, "tls": 18432, "drops": 12 },
  "actives": [
    {
      "client_mac": "aa:bb:cc:11:22:33",
      "client_ip": "192.168.43.5",
      "app": "抖音",
      "category": "video",
      "confidence": 0.97,
      "rx_bps": 25600000, "tx_bps": 1200000,
      "recent_domains": ["douyin.com", "amemv.com"]
    }
  ],
  "rank": [ /* 应用排行 */ ],
  "history_24h": [ /* 24 小时趋势 */ ]
}
```

### `etc/dpi_rules.json` (用户/项目维护, dpid 读)

```json
{
  "rules_version": "my-rules-001",
  "rules": [
    {
      "id": "mihoyo",
      "priority": 25,
      "hostmark": [{ "app": "米哈游", "category": "game", "suffixes": ["mihoyo.com", "hoyoverse.com", "mhystatic.com"] }]
    }
  ]
}
```

### `etc/dpi_config.json` (用户配置)

```json
{
  "disable_capture": false,
  "iface": "wlan2",
  "rules_path": "/data/local/hnc/etc/dpi_rules.json"
}
```

### `run/*.pid` (各 daemon 的 pidfile)

```
/data/local/hnc/run/hotspotd.pid       (hotspotd 自己写)
/data/local/hnc/run/hnc_dpid.pid       (launcher 写)
/data/local/hnc/run/hnc_httpd.pid      (httpd 自己写)
/data/local/hnc/run/hnc_watchdog.pid   (watchdog 自己写)
/data/local/hnc/run/hnc_launcher.pid   (launcher 自己写, rc30.12+)
```

watchdog 每 N 秒检查这些文件的 mtime 是否新鲜(每个 daemon 自己每 5 秒 touch 一次自己的 pidfile),不新鲜说明卡死,触发重启。

---

## 六、设备/环境特殊处理

### ColorOS 16 / SukiSU 路径

**问题**: Go fork+exec 报 EPERM(详见公开笔记)

**处理**:
1. `fork_probe` 在启动时探测,失败则不用 Go supervisor
2. `hnc_launcher`(C)替代 Go supervisor
3. `hnc_watchdog` 不直接 fork 子进程,改成调 shell 脚本

### Snapdragon 8 Elite / kernel 6.6+

**问题**: Android 的 BPF fast path (tether_limit_map) 在新内核 截胡 tethered 流量,绕开 tc 限速

**处理**: 还没修(见 P1 TODO,但实战很少触发)

### MIUI / OneUI / HyperOS 等其他国产 ROM

**未测过**。fork_probe 兜底降级保证不会比之前差,但具体表现需要真机验证。

---

## 七、关键文件位置

### 模块目录(只读,KSU/Magisk 挂载)

```
/data/adb/modules/hotspot_network_control/
├── module.prop
├── post-fs-data.sh
├── service.sh
├── uninstall.sh
├── bin/          ← 二进制 (source of truth)
├── daemon/       ← 大二进制 (hnc_httpd / hotspotd ELF)
├── data/         ← 规则文件 (dpi_rules, oui)
├── bpf/          ← eBPF 字节码
├── webroot/      ← WebUI 静态文件
└── META-INF/     ← 模块元数据
```

### 运行时目录(读写, /data/local/)

```
/data/local/hnc/
├── bin/          ← service.sh sync 自模块目录
├── daemon/       ← 同上
├── webroot/      ← 同上
├── data/         ← 用户数据 (dpi_state, rules 副本)
├── etc/          ← 用户配置 (可编辑)
├── run/          ← pidfile + 实时状态 (devices.json)
├── logs/         ← 日志文件
└── tmp/          ← 临时文件
```

**为什么要 sync 一份到 /data/local**: KSU 挂载的模块目录有 mount namespace 限制,某些 daemon 跨 namespace 启动时找不到二进制。运行时拷贝一份到 /data/local/ 是稳定方案。

---

## 八、常见排查路径

### 问题:WebUI 显示"hnc_httpd 未运行 / bridge 失败"

```sh
# 1. 看进程清单
ps -ef | grep -E "hnc_|hotspotd" | grep -v grep

# 期望看到 5 个 (rc30.12+):
# hotspotd / hnc_httpd / hnc_watchdog / hnc_launcher / hnc_dpid

# 2. 看 service.sh 启动日志
tail -50 /data/local/hnc/logs/service.log

# 3. 看哪个 fallback 路径被选中
grep "launcher\|fork_probe\|guard" /data/local/hnc/logs/service.log | tail -5

# 4. 如果是 ColorOS / SukiSU 设备且看到 "fork/exec EPERM"
#    → 是 Go fork 问题, 应该被 fork_probe 自动绕开
#    → 如果没绕开, 检查 fork_probe 二进制是否存在 + 可执行
ls -la /data/local/hnc/bin/fork_probe
```

### 问题:DPI 一直显示"盲模式·未抓包"

```sh
# 1. 看 dpid 进程
ps -ef | grep hnc_dpid

# 2. 看 dpid 日志
tail -50 /data/local/hnc/logs/hnc_dpid.log

# 3. 看接口状态
cat /sys/class/net/wlan2/operstate
cat /proc/net/route | grep wlan2

# 4. 如果错误是 "no such network interface"
#    且 dpid 版本 < 0.5.3-rc30.12.3 → 升级到 rc30.12.3+
strings /data/local/hnc/bin/hnc_dpid | grep "rc30.12"

# 5. 手动重新绑定 (临时workaround)
#    WebUI DPI 页 → 重新绑定 DPI 按钮
```

### 问题:设备列表不显示新连接的设备

```sh
# 1. hotspotd 在不在
ps -ef | grep hotspotd

# 2. netlink 事件能不能收到
tail -50 /data/local/hnc/logs/hotspotd.log

# 期望看到:
# [HOTSPOTD] NEW: aa:bb:cc:dd:ee:ff (192.168.43.x) on wlan2

# 3. 看 devices.json 是否更新
ls -la /data/local/hnc/run/devices.json
cat /data/local/hnc/run/devices.json | python3 -m json.tool
```

---

## 九、对未来你 / AI 的几句话

1. **不要回滚 rc30.12.3 的 dpid 字符串匹配** — 看上去丑(`strings.Contains(msg, "no such network interface")`),但这是 Go std lib 的限制,**没有更优雅的方案**。

2. **不要试图用 Go 重写 launcher** — Go runtime fork EPERM 是绝症,在国产 ROM 上无解。C 200 行,够了。

3. **不要删 hnc_dpid_supervisor 或 hnc_dpid_guard.sh** — 它们是 fallback 链的最后两环。占几 MB 不要紧,删了万一其他设备装不上就尴尬了。

4. **改 dpid Go 代码必须重新交叉编译** — 别忘了 `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w"`。

5. **WebUI 改完不需要重装模块** — 直接 sync 到 /data/local/hnc/webroot/ 或者改完重启 hnc_httpd 就行(WebUI 是热加载的)。

6. **加新 daemon 时记得**:写自己的 pidfile,每 5 秒 touch 一次,在 watchdog 里登记。

7. **真机调试时最有用的三个命令**:
   - `tail -f /data/local/hnc/logs/service.log` — 启动诊断
   - `cat /data/local/hnc/data/dpi_state.json | python3 -m json.tool` — DPI 状态
   - `ps -ef | grep -E "hnc|hotspotd"` — 进程清单

---

## 十、相关文档

- `EVOLUTION.md` — 项目演化史(rc1 → rc30.12.7 是怎么走过来的)
- `CHANGELOG.md` — 完整版本变更记录
- `PATCH-NOTES-v5.3.0-rc30.12.3.md` — Go fork EPERM 完整诊断 + 修复链
- `go-fork-eperm-coloros-sukisu-diagnosis.md` — 公开技术笔记(可发布)

---

*本文写于 rc30.12.7 时期,趁记忆鲜活。如果你 3 个月后回来发现哪里不对,大概率是项目又演化了 — 以代码为准。*
