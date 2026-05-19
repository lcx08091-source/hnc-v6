# v5.3.0-rc29.1 — dpid 方向修复 + 离线设备清理

**versionCode**: 530091 (rc29 = 530090)
**dpid 版本**: 0.5.1-rc29.1-l3-flow
**hnc_httpd**: 重编 (加 `cleanup_offline_devices` action)
**发布日期**: 2026-05-17

## 修的核心 bug

### rc29 假 IPv6 客户端

rc29 装上后 `当前活跃设备/应用` 列表里出现一堆假"客户端",例如:

```
客户端 .2409:8963:e82:f25:a090:...    MAC 76:c1:ff:f2:af:e9
客户端 .2409:8c74:f100:1004:1::e6    MAC 76:c1:ff:f2:af:e9
客户端 .240e:974:1200:402:8000:...   MAC 76:c1:ff:f2:af:e9
```

**根因**: rc29 新加的 `EventFlow` 把回程包(server→client)的 SrcIP 当成了 client。结果每个外网服务器 IP 都被记成一个新"客户端",MAC 全是上游 5G 网关 `76:c1:ff:f2:af:e9`。

**修复方案 A + C**:

**A. hotspot 子网/前缀检测**
- dpid 启动时探测 wlan2 接口的全部 IPv4 子网 + IPv6 前缀
- `assignClient` 优先按 hotspot 网段判方向: 哪一端 IP 在 hotspot 范围内,哪一端就是 client
- IPv6 link-local (fe80::/10) 和 /128 host route 排除
- 启动日志输出 `hotspot nets on wlan2: 10.117.193.0/24 2409:.../64 ...`

**C. EventFlow 不创建新 client**
- `RecordFlow` 改用 `clientLookupLocked` (只查不创)
- 假阳性兜底: 即使 A 漏判,服务器 IP 也不会污染 client 列表
- DNS/TLS 事件不受影响,仍然可以创建新 client

修复后预期效果:
- ✅ `客户端 .52` 只剩 米10 一个真客户端
- ✅ 字节系服务正确归到米10 名下
- ✅ tx_bytes / rx_bytes 方向正确
- ✅ 后台流持续性检测对 WeChat 等正确触发
- ✅ `NaN%` 置信度 bug 一并消失 (分母正确)

## 新增功能

### 1) WebUI 离线设备清理按钮

"全局操作"卡片新增 `🧹 清理离线设备`:

- 弹 confirm 框,显示「将清理 N 台离线设备(其中 M 条有规则)」
- 默认只清 offline + 无规则
- 复选框可选「包含带规则的设备」(连规则一起清)
- 后端走 `gate_lock`,跟 hotspotd 并发安全
- 完成后 toast 显示 `已清理 N 台离线设备 (保留 M 台带规则)`

新脚本: `bin/cleanup_offline_devices.sh`
新 action: `POST /api/action` body `{action: "cleanup_offline_devices", params: {include_rules: "0|1"}}`
返回 JSON: `{ok, removed, kept_with_rules, skipped_online}`

### 2) WebUI 设备过滤 "近 7 天活跃" 选项

设备过滤下拉框新增 `近 7 天活跃` 作为新的默认值:

- 显示: 在线 OR last_seen 在 7 天内的离线设备
- 旧的 `只看在线` 选项保留 (用户偏好向后兼容)
- 新装/未选过的用户默认走 `近 7 天活跃` 模式
- 已选过其他选项的用户不强制迁移
- 提示文字: `在线 N · 近 7 天 M · 共 K 台` / `默认隐藏 7+ 天无流量设备`

阈值常量 `RECENT_DAYS = 7` 写死在 JS 顶部,后续如果要做成配置项 1 行改。

## 文件改动

```
dpid/capture/iface.go    +44 行  新增 InterfaceNets()
dpid/capture/parse.go    +50 行  SetHotspotNets() + assignClient 改方向逻辑 + Event.RemoteMAC
dpid/output/state.go     +25 行  clientLookupLocked() + RecordFlow 改用 lookup
dpid/cmd/dpid/main.go    +18 行  启动时探测+注入 hotspot 网段
                         ─────
                         ≈ 140 行修复

daemon/hnc_httpd/action.go      +2  行  case "cleanup_offline_devices"
daemon/hnc_httpd/action_v5.go   +20 行  actionCleanupOfflineDevices()

bin/cleanup_offline_devices.sh  新文件 (130 行)
webroot/index.html              ≈ 80 行  按钮/JS handler/过滤选项/默认值
                                ─────
                                ≈ 230 行新功能
```

## Schema 与 rc28.1.x 兼容性

- `dpi_state.json` schema 仍是 **2.0**
- 字段集与 rc29 相同 (没新增也没删减)
- WebUI / 上层脚本无需任何修改

## 真机测试需求

### 必看 (装上立刻能验证)

1. **`当前活跃设备/应用` 列表干净度**: 应该只剩米10 (10.117.193.52 / 8a:47:4c:9f:24:54),不再有 2409:.../240e:... 那些假客户端
2. **dpid 启动日志**: `logcat | grep "hotspot nets on"` 应该看到 wlan2 的所有 IPv4+IPv6 网段
3. **`清理离线设备` 按钮**: 全局操作卡片展开后能看到,点击有确认弹窗
4. **设备过滤下拉**: 默认显示 `近 7 天活跃`,选项里有 4 项

### 待观察 (可能需要 rc29.2)

1. **conntrack_readable**: 跟 rc29 一样,Snapdragon 8 Elite + ColorOS 16 可能 SELinux 拒读
2. **JA4 稳定性**: 微信/抖音的 JA4 字符串是否在重复出现
3. **kernel_drops 比例**: BPF 双协议放行后跟 rc28.1.1 比较

## 二进制信息

```
              rc29.0                  rc29.1
hnc_dpid      2,556,056 字节          2,556,056 字节  (体积同)
hnc_dpid md5  786ea107...             e52dc21c...
hnc_httpd     7,405,921 字节(原)     6,684,856 字节
hnc_httpd md5 -                       b835d95f...
```

hnc_httpd 体积变小 = 用了 Go 1.25.3 + trimpath + -s -w 重编 (原版 Go 版本未知, 估计带 debug info).
