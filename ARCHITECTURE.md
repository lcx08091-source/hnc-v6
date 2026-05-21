# HNC 内部架构手册

> 给未来的 Ling、Claude、或者任何接手这个项目的人

**版本**: {{VERSION}} <!-- rc30.12.34: CI build.sh 自动注入, 不要手编 -->
**最后更新**: {{DATE}}

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

### `run/devices.json` (hotspotd 写)

<!-- rc30.12.30 (P2.17): 字段权威 schema, 替代之前的纯 JSON 示例 -->

**重要**: 这个文件由 `hotspotd` 单方面写, 不要从其他进程往里写. `hnc_httpd` 经过 `buildDevicesPayload()` 在内存里合并 `devices.json` + `data/rules.json` + `data/names.json` + 实时差分速率, 但**结果只通过 /api/devices 返回**, 不回写 devices.json. 这一节列三类字段来源, 因为之前 GPT 三审指出"混在一个 map 里靠 key 检索容易出错".

#### 顶层字段

| 字段 | 类型 | 写者 | 含义 |
|---|---|---|---|
| `schema` | int | hotspotd | 当前是 `1`, 升级时 bump |
| `hotspot_active` | bool | hotspotd | 热点接口存在 + 有 IP + 至少一台 client 见过 |
| `hotspot_iface` | string | hotspotd | 热点接口名 (`wlan2` / `ap0` / `softap0` 等) |
| `hotspot_ip` | string | hotspotd | 热点接口 IPv4 (通常 `192.168.43.1`) |
| `devices` | array | hotspotd | 当前可见 client 数组 (见下) |

#### `devices[]` 字段 — 按来源分三类

**A) hotspotd 原始字段** (devices.json 真实存的内容):

| 字段 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `mac` | string | ✅ | 客户端 MAC, 小写, 冒号分隔 (`aa:bb:cc:11:22:33`) |
| `ip` | string | ✅ | 当前 DHCP 分配的 IPv4 |
| `hostname` | string | 可空 | DHCP option 12 / ARP 探测出的设备名 |
| `vendor` | string | 可空 | OUI 查表得到的厂商 (`Xiaomi` / `Apple` / `Huawei` …) |
| `rx_bytes` | int64 | ✅ | hostapd/tc 累计接收字节 (单调递增) |
| `tx_bytes` | int64 | ✅ | 累计发送字节 |
| `first_seen` | int64 | ✅ | unix 秒, 首次 association |
| `last_seen` | int64 | ✅ | unix 秒, 最近 DHCP renewal / probe 响应 |
| `online` | bool | — | hotspotd 写入的近似值. **httpd 会覆盖** (基于 last_seen) |
| `rx_bps`/`tx_bps` | int64 | — | hotspotd 历史字段, **httpd 会覆盖** (实时差分) |

**B) hnc_httpd 在 buildDevicesPayload 时临时注入** (`/api/devices` 返回, 不进 devices.json):

| 字段 | 类型 | 注入条件 | 含义 |
|---|---|---|---|
| `online` | bool | 总是覆盖 | `last_seen > 0 && now - last_seen < 90` |
| `rx_bps` | int64 | 总是覆盖 | `(rx_bytes - prev_rx_bytes) / dt`, dt < 2s 时沿用缓存 |
| `tx_bps` | int64 | 总是覆盖 | 同上 |
| `status` | string | 总是注入 | `"blocked"` (在 rules.json blacklist) / `"allowed"` |
| `hostname` | string | manual rename 时 | rules/names.json 里的 manual rename, 优先级最高 |
| `hostname_src` | string | manual rename 时 | 固定 `"manual"`, 标记字段来源, UI 可显示标签 |

**C) hnc_httpd 从 `data/rules.json` 的 `device_rules.<mac>` 合并** (`/api/devices` 返回):

| 字段 | 类型 | 含义 |
|---|---|---|
| `mark_id` | int | iptables fwmark 值, tc class 用 |
| `down_mbps` | float | 下行限速 (Mbps), 0 = 不限 |
| `up_mbps` | float | 上行限速 (Mbps), 0 = 不限 |
| `delay_ms` | int | netem 延迟注入 (毫秒) |
| `jitter_ms` | int | netem 抖动 |
| `loss_pct` | float | netem 丢包率 (0-100) |
| `limit_enabled` | bool | 限速规则是否激活 |
| `delay_enabled` | bool | 延迟规则是否激活 |

#### Rule-only / blacklist-only 设备

`devices.json` 只列当前可见 client. 一台设备配了限速但目前断开, **不在 devices.json**.

`buildDevicesPayload` 末尾会扫描 `rules.json.device_rules` 和 `blacklist`, 把规则存在但 hotspotd 没看到的 MAC 也追加成离线行 (`online: false`, `ip: "-"`, `rx_bps/tx_bps: 0`), 让 UI 仍能显示已配置状态. 这些"虚行"**不写回 devices.json**, 只在 `/api/devices` 返回时存在.

#### 示例(httpd 合并后的 /api/devices 形态)

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
      "hostname": "我的红米",
      "hostname_src": "manual",
      "vendor": "Xiaomi",
      "online": true,
      "rx_bytes": 8421000000,
      "tx_bytes": 102400000,
      "rx_bps": 12800000,
      "tx_bps": 450000,
      "first_seen": 1747500000,
      "last_seen": 1747510800,
      "status": "allowed",
      "mark_id": 11,
      "down_mbps": 5.0,
      "up_mbps": 2.0,
      "limit_enabled": true
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

---

## 十一、v5.5+ 自身流量识别与规则闭环 (新章节)

> 写于 v5.5.0 时期。这一章描述 v5.5 已落地的内容,以及 v5.6 / v5.7 的规划路径。
> v5.5 之前 HNC 只识别热点客户端的流量;v5.5 起新增了对本机自身流量的可选追踪,
> 并把原 AHNC 卫星模块的能力整合进来。

### 11.1 整体分阶段路线

```
v5.5 ─┬─► /proc/net + uid→pkg 半自动采样 (本章 11.2)
      └─► "我的应用" + "导出" WebUI (整合在新 "应用" tab)

v5.6 ─┬─► self-iface (rmnet/wlan0) AF_PACKET capture
      ├─► SNI 抓取 + 跟 /proc/net 的 uid join → 自动填 top_snis/top_rules
      └─► 已知 app 子域自动扩展 (走法 1 · _auto_expanded.json)

v5.7 ─┬─► unmatched SNI 频率累积器 (candidates.jsonl)
      └─► WebUI "候选规则" 子页 (走法 2 · 一键 promote · HIGH/MED/LOW 三档)
```

### 11.2 v5.5 实现细节

**新进程? 无。** 所有逻辑都在 `hnc_dpid` 内,作为它的一个 goroutine 跑。
理由:`dpid` 本来就有 5 秒主循环和 JSON Writer,加一个 sampler 不需要新进程。

**新文件**:
- `src/dpid/output/self_attrib.go` (593 行) — `/proc/net/*` 解析 + uid→pkg 映射 + 历史 JSONL
- `src/dpid/capture/self_iface.go` (153 行) — 列出哪些接口算"自身接口"(供 v5.6 使用,v5.5 仅 WebUI 预览用)
- `daemon/hnc_httpd/api_self.go` (261 行) — 4 个 self 端点 (`/api/self`, `/toggle`, `/ifaces`, `/attrib`)
- `daemon/hnc_httpd/api_export.go` (421 行) — export 打包 (`/api/export`, `/api/exports`)
- `bin/ahnc_migration.sh` (108 行) — 一次性数据迁移

**State schema 扩展**:
`dpi_state.json` 的 `schema_version` 仍然是 `2.0`(兼容性优先),新增字段是 `state.self`,
为 nil 时 `omitempty` 不输出。当采样开启时形如:

```jsonc
{
  "self": {
    "enabled": true,
    "last_attrib_tick": 1716293400,
    "pkg_cache_size": 73,
    "apps_by_uid": {
      "10198": {
        "uid": 10198,
        "pkg": "com.tencent.mm",
        "active_conns": 28,
        "total_conns": 247,
        "first_seen": 1716293000,
        "last_seen": 1716293400,
        "top_snis": [],     // v5.5: 空; v5.6 接 self-iface capture 后才填
        "top_rules": []     // 同上
      }
    },
    "interfaces": []        // v5.6 才有
  }
}
```

**触发开关**:`/data/local/hnc/run/self_capture.enabled` 标志文件。
- 文件存在 → 采样器 5s 一次工作
- 文件不存在 → 采样器 idle (snapshot 仍上报但 enabled=false)
- WebUI 的 `POST /api/self/toggle` 就是 touch/rm 这个文件

**默认关闭** —— 装上 HNC v5.5 不会自动采你自己的流量。

### 11.3 v5.6 设计 (待实现)

#### 11.3.1 self-iface AF_PACKET

为什么需要:v5.5 已有 `/proc/net` 给出 `(uid, remote_ip, remote_port)`,但 SNI 没有。
要拿 SNI,必须 AF_PACKET 抓 TLS ClientHello。

实现思路 (基于 `capture/iface.go` 现有 AP 选 iface 的 `DiscoverAPCandidates` 模式):

```
main.go (dpid):
  现在:    一个 runCapture(ctx, cfg, pr, sw) on pr.APIface (wlan2)
  v5.6 改: 上面那个 + 启动一批 secondary captures on
           capture.DiscoverSelfCandidates(pr.APIface) 返回的接口

  每个 secondary capture:
    - 同样的 BPF (TCP/443 + UDP/53 + UDP/443)
    - 同样的 parser (TLS ClientHello → SNI)
    - SNI 事件不进 sw.RecordTLS (那会污染热点客户端聚合)
    - 而是进 selfAttrib.RecordSNI(uid, sni, now)
    - uid 通过 selfAttrib.LookupUID(remote_ip, remote_port) 查到
```

需注意的坑:
- ColorOS BPF fast path 可能截走 tethered 流量;但 self iface 流量 (本机自己) 应该不受影响,因为 BPF fast path 只针对 tether 链路
- 多 capture handle 的 SIGTERM 关停顺序 — child contexts 先 cancel
- rmnet 接口在飞行模式 / 双卡切换时会增删,需要每 30s 重扫一次 DiscoverSelfCandidates

#### 11.3.2 子域自动扩展 (走法 1)

**触发条件 (三重证据,缺一不可)**:

1. **apex 相同**:观测到的新 SNI 跟现有某规则中至少一个已 verified SNI 共享 effective TLD+1 (eTLD+1)
2. **uid 相同**:观测到这条新 SNI 的 uid,跟上面那个规则中高频命中的 uid 相同 (>= 10 次)
3. **apex 不在 blocklist**:`data/auto_expand_blocklist.json` 列了禁止自动扩展的 apex
   (CDN / 共享 API gateway / 跨公司基础设施)

**dpid 中的实现位点**:在 `applyRuleHitLocked` 之后、把命中写进 client 聚合之前,
对 *未* 命中的 SNI 做一次 `tryAutoExpand(sni, uid, now)` 检查。

**输出**:`data/dpi_rules.d/_auto_expanded.json` (单文件)。每条 entry 长这样:

```jsonc
{
  "id": "tencent_wechat_voice",            // <existing_rule_id>_<new_subdomain>
  "name": "微信 (自动扩展: 语音子域)",
  "category": "messaging",
  "sni_suffixes": ["voice.weixin.qq.com"],
  "_source": "auto_expanded",
  "_apex": "weixin.qq.com",
  "_parent_rule_id": "tencent_wechat",
  "_added_at": 1716293400,
  "_evidence": {
    "uid": 10198,
    "uid_pkg": "com.tencent.mm",
    "parent_hits_at_time_of_expand": 47,
    "hours_observed": 3
  }
}
```

**回滚**:`rm data/dpi_rules.d/_auto_expanded.json && killall hnc_dpid` 即可。
所有自动条目集中在一个文件,人工写的规则**永不被自动修改**。

**Blocklist 初版** (`data/auto_expand_blocklist.json`):

```jsonc
{
  "blocked_apex": [
    "cloudfront.net", "amazonaws.com",
    "akamai.net", "akamaiedge.net",
    "fastly.net", "cloudflare.com",
    "googleapis.com", "googleusercontent.com",
    "appsflyer.com", "adjust.com", "branch.io",
    "newrelic.com", "datadoghq.com",
    "trustarc.com", "onetrust.com"
  ],
  "_comment": "These apex domains are shared across many companies / generic SDK providers. Auto-expansion would misattribute traffic."
}
```

### 11.4 v5.7 设计 (待实现)

#### 11.4.1 candidate 累积器

任何 SNI 既没匹配已有规则、也不满足走法 1 的三重证据 → 进 candidate 累积。

`/data/local/hnc/run/candidates.jsonl` (按日 rotate):

```jsonc
{"t":1716293400, "sni":"api.adjust.com", "uid":10256, "pkg":"com.ss.android.ugc.aweme",
 "remote_ip":"54.230.x.x", "tier":"medium", "reason":"apex shared across known pkgs"}
```

dpid 端只做累积,不判断 tier 优先级 —— tier 由 httpd 在 WebUI 加载时算出来。

#### 11.4.2 WebUI 审批页

`#apps-sub-candidates` (新增子页)。3 档,每档 collapse 一组:

- **HIGH** (绿色,默认展开):新 apex 但 uid 跟现有规则一致 → 建议 promote 为该 app 的新规则
- **MEDIUM** (黄色,折叠):uid 在多个已知 app 间分布 → 显示候选 app,人工选
- **LOW** (灰色,折叠):频率 <5、uid 不在 pm 缓存里 → "再观察一周"

每条记录有按钮:
- **加入规则**:弹出表单 (rule_id / name / category / 选 app 归属),提交后写入 `dpi_rules.d/_user_promoted.json`
- **永不再问**:加入 `data/_blocklist_personal.json`,下次出现自动 hide
- **导出给 Claude**:把这条记录加进下一次 export zip 的 `pending_review.json`

### 11.5 关键不变量 (设计宪法)

无论 v5.6 / v5.7 怎么扩展,以下原则不能违反:

1. **人工规则永不被自动改**。`dpi_rules.d/00-core-meta.json` 到 `90-anomaly-heuristics.json` 这些文件,自动逻辑只读不写。
2. **自动产物有独立命名空间**。`_auto_expanded.json` 和 `_user_promoted.json` 用下划线前缀,永远在最后加载,优先级低于人工规则。
3. **采集默认 OFF**。每个新增的探测能力 (self-iface capture / candidate 累积 / 等等) 必须有独立开关 + 默认关闭。
4. **任何"自动"动作必须可一键回滚**。删除一个 JSON 文件 + 重启 dpid = 完全还原。
5. **WebUI 显示自动产物时永远带 badge** (`auto_expanded` / `promoted_from_candidate` 等),让用户看到这条规则是怎么来的。

### 11.6 跟 AHNC 卫星模块的关系

v5.5 之前,AHNC 是个独立 KSU 模块,跑自己的 tcpdump、写自己的 pcap、做自己的 uid 解析。
v5.5 把它的能力吸收进 HNC 主仓:

- **保留**:`/proc/net` + uid→pkg 思路、historical JSONL、给 Claude 的 export 工作流
- **废弃**:独立 tcpdump 进程 (HNC 主 capture 已经在 AF_PACKET 实时解);独立 daemon (合进 hnc_dpid);独立 WebUI (合进主 webroot)
- **迁移**:`/data/local/ahnc/self-conns.*.jsonl` 最近 7 天会被 `bin/ahnc_migration.sh` 自动搬到 `/data/local/hnc/run/self_attrib.*.jsonl`,其他 AHNC 数据 (pcap / 旧 export / mirror) 全丢弃

迁移完成后 AHNC 模块本体仍在 `/data/adb/modules/ahnc-capture/`,需手动从 KSU 管理器卸载。
迁移脚本会留 marker 文件 `/data/local/hnc/run/.ahnc_migration_done` 写明清理步骤。
