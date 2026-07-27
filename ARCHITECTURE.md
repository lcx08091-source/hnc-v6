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
          /data/local/hnc/data/devices.json      ← data/, 不是 run/
          - mac=aa:bb:cc, ip=192.168.43.x,
          - hostname=红米K70, hostname_src=oui   ← 厂商进 hostname, 没有 vendor 字段
          ↓
[t=200ms] hnc_dpid 同时在抓包
          (AF_PACKET 监听 wlan2)
          - DNS 查询: example.com → IP
          - TLS ClientHello: SNI=douyin.com
          ↓ 写 dpi_state.json
          ↓
[t=300ms] hnc_dpid 完成识别, 写
          /data/local/hnc/run/dpi_state.json     ← run/, 不是 data/
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

<!-- v5.9.3 (BUG-007 B): 本节全部逐项对着代码核过一遍。上一版把 devices.json
     写在 run/、把 dpi_state.json 写在 data/、stats 字段写成 pkts/dns/tls/drops,
     全是漂移 —— 而 bin/diag/diag.sh 就照着漂移的路径去读, 结果诊断包对 DPI
     恒定输出 "MISSING", 把好好的 dpid 报成挂了。文档漂移会变成可执行代码的
     bug, 所以本节的每一行都带 file:line 出处。 -->

**纪律(改代码时请一起改)**: 本节的路径与字段名**以实际代码为准**。任何一次
改动 `daemon/hotspotd/hotspotd.c` 的 `write_json()`、`src/dpid/output/state.go`
的结构体 tag、或 `daemon/hnc_httpd/server.go` 的 `buildDevicesPayload()`,都要
在同一个提交里同步本节。写文档时**不要凭印象**,`grep` 一遍再写 —— 下游有真代码
(诊断脚本、shell 解析、WebUI)按这里的描述去找文件和字段。

两个运行时目录的分工(不要凭直觉猜):

| 目录 | 放什么 | 典型内容 |
|---|---|---|
| `data/` | **可跨重启保留**的状态与用户数据 | `devices.json`、`rules.json`、`device_names.json`、`known_devices.json`、`remote_tokens.json`、`oui.txt` |
| `run/` | **进程生命周期内**的易失状态 | `dpi_state.json`、`*.pid`、`hotspotd.sock`、`ip_app_map.json`、`self_attrib.*.jsonl`、`local_admin.secret` |

### `data/devices.json` (hotspotd 写, httpd/dpid/shell 读)

**路径**: `/data/local/hnc/data/devices.json`
(`hotspotd.c:75` `#define DEVICES_JSON HNC_DIR "/data/devices.json"`)

**写者(两个,同一套 schema)**:

| 写者 | 位置 | 何时 |
|---|---|---|
| `hotspotd` (C) | `hotspotd.c:498-628` `write_json()` | 常态。netlink NEIGH 事件 / 周期扫描后 |
| `bin/device_detect.sh` | `:312` `do_scan_shell()` → `:478-479` | 兜底。`hotspotd_alive()`(`:55`)为假时 |

两者都是 **tmp + rename 原子写**,tmp 名带 PID 后缀(`hotspotd.c:79`
`DEVICES_TMP_FMT`;shell 侧 `${DEVICES_FILE}.tmp.$$`)—— 这是 v3.6.1 修的真实
事故:两个 scan 并发写同一个 tmp,字节交错产出"看着合法但字段错位"的 JSON。

**读者**: `hnc_httpd` 5 处 —— `server.go:343`(`buildDevicesPayload`)、
`server.go:589`(`RateLoop` 采速率)、`api_v5.go:174`(反查热点 iface)、
`api_events.go:64`(stat mtime 推 SSE 变更事件)、`action_v5.go:29`;
`hnc_dpid` 1 处 —— `src/dpid/alert/alert.go:54`(新设备告警对比);
shell 侧 `apply_device_rule.sh:24`、`apply_app_limits.sh:40`、
`cleanup_offline_devices.sh:24`、`cleanup_stale_rules.sh:11` 等直接 grep 解析。

#### 真实结构:**扁平 MAC → 对象 map**,没有任何外层包装

```json
{
  "aa:bb:cc:11:22:33": {
    "ip": "192.168.43.5",
    "mac": "aa:bb:cc:11:22:33",
    "hostname": "红米K70",
    "hostname_src": "mdns",
    "iface": "wlan2",
    "rx_bytes": 8421000000,
    "tx_bytes": 102400000,
    "status": "allowed",
    "last_seen": 1747510800
  }
}
```

**顶层没有** `schema` / `hotspot_active` / `hotspot_iface` / `hotspot_ip` /
`devices[]` 这些键 —— 旧文档写的那套外层包装从来不存在。热点自身状态由
`/api/live` 提供(`api_live.go:81-84`),不在这个文件里。

hotspotd 真正写出的字段**只有下面 9 个**(`hotspotd.c:590-605` 的 `fprintf`
格式串,一个不多一个不少;shell 兜底路径 `device_detect.sh:424` 逐字对齐):

| 字段 | 类型 | 含义 |
|---|---|---|
| `ip` | string | 当前 IPv4 |
| `mac` | string | 客户端 MAC,小写冒号分隔(同时也是 map 的 key) |
| `hostname` | string | mDNS / DHCP / OUI / 缓存推出的名字;推不出时是 MAC 尾段 |
| `hostname_src` | string | 名字来源:`mdns` / `dhcp` / `oui` / `cache-*` / `mac` / `pending` |
| `iface` | string | 观察到该设备的接口名 |
| `rx_bytes` | int64 | 累计字节(来自 `HNC_STATS` iptables 计数链) |
| `tx_bytes` | int64 | 同上 |
| `status` | string | `allowed` / `blocked`(hotspotd 读 rules.json 黑名单填);shell 兜底路径还会写 `stale` |
| `last_seen` | int64 | unix 秒 |

**没有** `vendor` 字段(OUI 查表的结果直接进 `hostname`,并把
`hostname_src` 置成 `oui`,见 `hnc_helpers.c:1172` 附近的 OUI 表);
**没有** `first_seen`;**没有** `online` / `rx_bps` / `tx_bps` —— 后三个是
httpd 在内存里算出来的,见下。

#### httpd 合并层:`/api/devices` 返回的对象 ≠ devices.json 里的对象

`buildDevicesPayload()`(`server.go:336-558`)读 3 个文件在内存里合并,
**结果只从 HTTP 返回,绝不回写 devices.json**:

| 来源 | 文件 | 叠加的字段 |
|---|---|---|
| hotspotd | `data/devices.json` | 上表 9 个原始字段 |
| 用户规则 | `data/rules.json` 的 `devices.<mac>` | `mark_id` `down_mbps` `up_mbps` `delay_ms` `jitter_ms` `loss_pct` `limit_enabled` `delay_enabled` `sqm_enabled`(`server.go:422-424`) |
| 手动改名 | `data/device_names.json` | 覆盖 `hostname`,并把 `hostname_src` 置 `manual`(`server.go:433-439`) |
| httpd 计算 | — | `status`(黑名单判定)、`online`(`last_seen` 在 90s 内)、`rx_bps`/`tx_bps`(`RateLoop` 2s 采样快照)、`dpi_apps`(来自 dpi_state.json 的 per-client top_apps) |

> 文件名是 `device_names.json`,**不是** `names.json`(`server.go:345`)。

**响应外层**是 `{ "devices": [...], "whitelist_mode": ..., "remote_enabled": ... }`
(`server.go:554-558`),数组按 IP 数值序排(`.10` 排在 `.2` 后面)。

#### Rule-only / blacklist-only / renamed-only 虚行

`devices.json` 只列当前可见 client。配了限速但已断开的设备**不在文件里**,
`buildDevicesPayload` 末尾会从 `rules.json.devices`、`blacklist`、
`device_names.json` 三处补出离线虚行(`server.go:469-531`):
`ip: "-"`、`online: false`、`rx_bps/tx_bps: 0`、`last_seen` 取
`rules.json` 的 `last_seen_persist`(取不到给 0)。虚行同样**不写回**文件。

### `run/hotspotd.sock` (IPC 命令通道,**不是** devices.json 的替代品)

**路径**: `/data/local/hnc/run/hotspotd.sock`(`hotspotd.c:74`),
`0600` + `chown root:root`(`hotspotd.c:1017-1021`)。

这是一个 **UNIX SOCK_STREAM 命令通道**,支持 `GET_DEVICES` / `REFRESH` /
`STATUS` / `QUIT`(`hotspotd.c:9`、`:1064` 起的请求分发)。它与
`data/devices.json` **并存**,不存在"改用 socket 所以 devices.json 没有了"
这回事:

- 状态的**权威落盘**始终是 `data/devices.json`,httpd 只读文件不连 socket;
- socket 是给 shell / 工具**主动问一次**用的:`bin/device_detect.sh:62`
  `socket_query()` 优先 `socat`,退 `nc -U`,**两个都没有时直接
  `cat "$DEVICES_FILE"`**(`:69`)—— 兜底路径本身就说明两者是同一份数据;
- `daemon/hotspotd/tools/hnc_ipc.c` 是这个 socket 的独立客户端(调试用)。

真机上看不到设备,先怀疑热点没开 / hotspotd 没起,不要怀疑"文件换成 socket 了"。

### `run/dpi_state.json` (dpid 写, httpd 读)

**路径**: `/data/local/hnc/run/dpi_state.json` —— `run/`,**不是** `data/`。
出处:`src/dpid/cmd/dpid/main.go:38`(`defaultRunDir = "/data/local/hnc/run"`)
+ `:43`(`stateFileName = "dpi_state.json"`)+ `:155` 拼路径。可以被
`etc/dpi_config.json` 的 `run_dir` 覆盖,但没人这么干。

**读者全部按 `run/` 读**:`api_dpi_v53.go:23`(整文件透传给 WebUI)、
`api_self.go:49`、`api_export.go:139`、`server.go:661`(join `dpi_apps`)、
`dpid_supervisor/main.go:47`、`src/bin/hnc_dpid_guard.sh:491`。

顶层字段来自 `src/dpid/output/state.go:244-298` 的 `State` 结构体:

```json
{
  "schema_version": "2.0",
  "generated_at": 1747510800,
  "version": "0.5.3-rc30.12.3-iface-retry",
  "mode": "ok",
  "blind_reason": "",
  "interface": "wlan2",
  "uptime_s": 4523,
  "tls_reassembly": true,
  "ipv6_capture": true,
  "offload_hint": false,
  "stats": {
    "packets": 158234,
    "kernel_drops": 12,
    "dns_events": 24891,
    "tls_events": 18432,
    "flow_events": 9021,
    "ignored_packets": 3,
    "parse_errors": 0
  },
  "clients": { "<client-key>": { "client_ip": "…", "client_mac": "…", "top_apps": [] } },
  "client_count": 2,
  "top_hostnames": [], "top_sni": [], "top_apps": [], "top_categories": [], "top_ja4": [],
  "l3_enabled": true, "l3_rule_version": "…",
  "ndpi_available": false,
  "conntrack_readable": true, "conntrack_flows": 128,
  "total_rx_bytes": 0, "total_tx_bytes": 0,
  "self": { "enabled": false }
}
```

**容易写错的四个点(旧文档四个全错)**:

| 旧文档 | 实际 | 出处 |
|---|---|---|
| `iface` | `interface` | `state.go:250` |
| `uptime_sec` | `uptime_s` | `state.go:254` |
| `stats.pkts` / `.dns` / `.tls` / `.drops` | `stats.packets` / `.dns_events` / `.tls_events` / `.kernel_drops` | `state.go:38-44` |
| 顶层 `actives` / `rank` / `history_24h` | **不存在**。per-client 数据在 `clients`,排行在 `top_apps` / `top_categories`,24h 趋势走 `/api/dpi_history`(另一套采样文件) | `state.go:244-298` |

`mode` 只有四个取值(`cmd/dpid/main.go:94-99`):

| 值 | 含义 |
|---|---|
| `ok` | `decideMode`(`main.go:637-648`)判定可抓包,且 AF_PACKET socket 打开成功 |
| `blind` | AF_PACKET 不可用 / 没探到热点接口;`blind_reason` 给原因 |
| `disabled` | 配置 `disable_capture=true` |
| `crash_loop` | 60s 内崩 ≥3 次,dpid 自保进 idle |

> **`mode: "ok"` 不等于"正在抓到包"**(BUG-003)。它只表示 socket 开成功了,
> 整个 attempt 生命周期内不复查流量。真机出现过 `mode=ok` 且
> `stats.packets` 恒为 0 持续 5 天。判断"DPI 到底有没有在干活"必须
> **同时**看 `stats.packets` 与 `uptime_s`;WebUI 从 v5.9.3 起在
> `webroot/index.html` 的徽标处做这个交叉校验。

### `etc/dpi_rules.json` / `etc/dpi_rules.d/*.json` (用户/项目维护, dpid 读)

加载顺序(`src/dpid/output/rule.go:33-40`,先命中先用):

1. `/data/local/hnc/etc/dpi_rules.d/*.json` —— rc30.12.31+,按文件名序 glob
   合并,同 id 后写覆盖(nginx `conf.d` 风格,`99-user-custom.json` 能盖掉
   项目内置规则);单个子集文件坏掉只 WARN 跳过,不影响整体加载
2. `/data/local/hnc/etc/dpi_rules.json` —— legacy 单文件
3. 编译进二进制的 `builtinRules` 兜底

文件结构(`rule.go:170-215` 的结构体 tag):

```json
{
  "schema_version": "1",
  "rules_version": "my-rules-001",
  "rules": [
    {
      "id": "mihoyo",
      "name": "米哈游",
      "app": "米哈游",
      "category": "game",
      "priority": "specific",
      "suffixes": ["mihoyo.com", "hoyoverse.com", "mhystatic.com"],
      "domains": [],
      "ip_matchers": [{ "cidr": "1.2.3.0/24", "proto": "udp", "ports": [7000] }]
    }
  ]
}
```

`priority` 是**字符串**,只认 `specific`(默认)/ `fallback`
(`rule.go:54-60`),不是数字;顶层键是 `rules`,没有 `hostmark` 这种东西。

### `etc/dpi_config.json` (用户配置)

dpid 只认下面 6 个键(`cmd/dpid/main.go:75-82` 的 `Config` 结构体),
多写的键会被静默忽略:

```json
{
  "iface": "wlan2",
  "snaplen": 1024,
  "rcv_buf_bytes": 4194304,
  "log_level": "info",
  "run_dir": "/data/local/hnc/run",
  "disable_capture": false
}
```

没有 `rules_path` 这个键 —— 规则路径是上面写死的三级探测顺序。

### `run/*.pid` (各 daemon 的 pidfile)

<!-- v5.9.3 (BUG-007 B): 逐个对着写者核过。旧文档写的 hnc_dpid.pid /
     hnc_httpd.pid / hnc_watchdog.pid / hnc_launcher.pid 四个文件名**都不存在**
     —— 真实文件名没有 hnc_ 前缀。照旧文档写监控脚本会永远 "pidfile missing"。 -->

```
/data/local/hnc/run/hotspotd.pid       (hotspotd 自己写, hotspotd.c:81/1182)
/data/local/hnc/run/dpid.pid           (hnc_launcher 写, src/launcher/hnc_launcher.c:64)
/data/local/hnc/run/dpid_guard.pid     (hnc_launcher / dpid_supervisor 写, hnc_launcher.c:65)
/data/local/hnc/run/dpid.child.pid     (dpid_supervisor 写, dpid_supervisor/main.go:45)
/data/local/hnc/run/httpd.pid          (httpd 自己写, hnc_httpd/main.go:89)
/data/local/hnc/run/watchdog.pid       (hnc_watchdog 自己写, hnc_watchdog/main.go:55)
/data/local/hnc/run/launcher.pid       (hnc_watchdog spawn launcher 时写, main.go:355 + :579)
/data/local/hnc/run/detect.pid         (device_detect.sh:507 自己写)
/data/local/hnc/run/ndpi_continuous.pid(ndpi_continuous.sh, 由 watchdog 监管)
```

watchdog 每 N 秒检查这些文件的 mtime 是否新鲜(每个 daemon 自己每 5 秒 touch 一次自己的 pidfile),不新鲜说明卡死,触发重启。Go watchdog 侧的对照表在
`src/dpid/cmd/hnc_watchdog/main.go:304-360`(`daemonSpec.pidFile`),**加/改 pidfile 名字要同时改那张表**,否则 watchdog 会永远认为该 daemon 没在跑。

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

<!-- v5.9.3 (BUG-007 B): 本节与第五节同一条纪律 —— 路径以代码为准, 改动同步。
     上一版把 devices.json 标在 run/、把 dpi_state 标在 data/, 正好是反的;
     bin/diag/diag.sh 就是照着这份描述去读 data/dpi_state.json, 于是诊断包
     对 DPI 恒报 MISSING。目录归属写错的代价是真的会让人误判故障。 -->

### 模块目录(只读,KSU/Magisk 挂载)

```
/data/adb/modules/hotspot_network_control/
├── module.prop
├── post-fs-data.sh          ← 建目录 + 从模块目录 sync 到 /data/local/hnc
├── service.sh               ← 拉起 5 个 daemon
├── uninstall.sh
├── bin/          ← 脚本 + 小二进制 (hotspotd / hnc_dpid / hnc_launcher / fork_probe / hnc_ipc …)
├── daemon/       ← hnc_httpd ELF (daemon/hnc_httpd/hnc_httpd)
├── api/          ← WebUI 用的 shell API 入口
├── data/         ← 项目维护的规则/数据 (dpi_rules.json, dpi_rules.d/, oui.txt, entity_db.json …)
├── bpf/          ← eBPF 字节码 (hnc_limit_map_guard.bpf.o)
├── webroot/      ← WebUI 静态文件 (index.html / changelog.html …)
├── test/         ← 真机可跑的单测
└── META-INF/     ← 模块元数据
```

### 运行时目录(读写, `/data/local/hnc/`)

```
/data/local/hnc/
├── bin/          ← post-fs-data.sh:63-70 从模块目录 cp
├── api/          ← 同上
├── webroot/      ← 同上
├── test/         ← 同上
├── daemon/hnc_httpd/hnc_httpd  ← post-fs-data.sh:80-88 单独 cp (只 cp 产物)
├── bpf/          ← post-fs-data.sh:98-105
├── data/    ← 持久状态 + 用户数据
│   ├── devices.json          ← hotspotd 写 (见第五节)
│   ├── rules.json            ← 限速/黑名单/白名单规则, json_set.sh 单写者
│   ├── device_names.json     ← 手动改名 (不是 names.json)
│   ├── known_devices.json    ← 新设备告警的"已知"集合
│   ├── remote_tokens.json    ← 远程访问凭据 (bcrypt), httpd 是唯一写者 (tokens.go:65)
│   ├── hostname_cache.json   ← hotspotd 名字缓存
│   └── oui.txt / entity_db.json / dpi_*.json  ← service.sh 从模块目录同步的只读数据
├── etc/     ← 用户可编辑配置 (刷机不覆盖, service.sh:705 起做软迁移)
│   ├── dpi_config.json
│   ├── dpi_rules.json        ← legacy 单文件
│   └── dpi_rules.d/*.json    ← 首选, 99-user-custom.json 可覆盖项目规则
├── run/     ← 易失状态 (重启即弃)
│   ├── dpi_state.json        ← dpid 写 (**在这里, 不在 data/**)
│   ├── *.pid                 ← 见上一节的真实文件名清单
│   ├── hotspotd.sock         ← IPC 命令通道
│   ├── ip_app_map.json / .flat
│   ├── self_attrib.YYYYMMDD.jsonl
│   ├── local_admin.secret    ← 本机免密凭据 (0600, 目录 700)
│   └── iface.cache / dpid.netlink.event / dpid.crashflag / json.lock …
└── logs/    ← service.log / dpid.log / httpd.log / hotspotd.log / detect.log /
              watchdog.log / tc.log / iptables.log … (log_rotate.sh 轮转)
```

> 没有 `tmp/` 目录 —— 临时文件一律是"目标文件同目录 + `.tmp.$$` 后缀"再 rename,
> 这样 rename 才是同一文件系统内的原子操作。

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

# 3. 看 devices.json 是否更新 (data/, 不是 run/)
ls -la /data/local/hnc/data/devices.json
cat /data/local/hnc/data/devices.json | python3 -m json.tool
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
   - `cat /data/local/hnc/run/dpi_state.json | python3 -m json.tool` — DPI 状态(**run/**)
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
