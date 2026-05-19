# HNC v5.3.0-rc26.0 — DPI 截图风格 UI 的 5 个 bug 修复

## 主题

修 rc23 截图反馈的 UI 问题。rc24-25 期间 GPT 加了 nDPI Lab + 规则库扩展 + 未识别域名助手, **但这些 UI bug 一直没修**, 装上看到的还是 5/13 截图那个样子。这一版**只修 bug, 不加新功能**。

**dpid binary 不动** (still v0.4.0-rc23, md5 `f2939e4c849c572e08013213e4e17b17`)
**daemon 不动**
**rc25 的所有新功能保留** (nDPI Lab / 规则库 v2 / 域名助手)

## 修了什么

### Bug 1: "字..." 应用名截断
**截图症状**: 当前活跃应用卡中间列只能塞下 "字..."

**根因**: `.dpi-active-card` 用 3 列 grid `1fr 1.2fr 0.7fr`. 手机 ~390 dp 宽度下中间列只剩 ~155 dp, 减去 app icon (28) + 置信度 badge (~70) + gap, app 名只有 ~50 dp.

**修法**: 卡片从 **3 列改成 3 行**:
- Row 1: 头像 + 设备名 + 速率
- Row 2: app icon + app 名 + 置信度 badge
- Row 3: 最近域名 chips

每行有完整宽度, app 名字 `white-space: normal + word-break: break-word`, 允许换行不再 ellipsis.

### Bug 2: 识别总览也截断
**截图症状**: 条形图里只看到 "字节...", "微信..."

**根因**: `.dpi-rank-bar-name` 是 `position: absolute` 浮在 bar 内部, `max-width: calc(100% - 12px)` 限死了名字最多和 bar 一样宽. bar 本身又是按 count 占比, 不是按 name 长度.

**修法**: 重排为 2 行 — 第 1 行: rank num + icon + **名字 (独立行有全宽)** + 百分比; 第 2 行: 纯 bar. 名字不再压在 bar 上.

### Bug 3: 设备名变成 "172.23.1..."
**截图症状**: 头像下显示截断的 IP, 不是主页一致的设备名

**根因**: dpid 看到的 client_mac 在 `state.devices` 找不到对应条目 (你那台 USB tether 客户端可能不在主页设备列表里). 老代码 fallback 直接显示裸 IP, 又被 CSS 的 ellipsis 截断.

**修法**:
1. MAC 比对加 **格式归一化** — 去掉冒号/中划线/大小写差异 (`normMac` 函数)
2. 没匹配时退化到 **"客户端 .89"** 这种短标签 (IP 末段), 而不是裸 IP
3. emoji 用 📡 (网络上看到的) 而不是 ❓ (没归档但中性)
4. meta 行只在 displayName ≠ IP 时显示 IP, 避免重复

### Bug 4: "— Mbps" 速率不显示
**截图症状**: 右侧速率永远显示 "— Mbps"

**根因 (2 个)**:
1. dpid 自己算的 `rx_bps/tx_bps` 在你设备上是 0 (可能 conntrack accounting 没开)
2. **fallback 字段名写错了** — 我之前写的是 `matched.rxbps`, 但主页 `state.devices` 的实际字段是 `matched.rx` (bps 单位)

**修法**:
1. fallback 字段名修正: `matched.rx || matched.rxbps || matched.rx_bps` (兼容三种命名)
2. 真没数据时显示 "速率不可用 (等 conntrack)" 而不是模糊的 "— Mbps"

### Bug 5: 流量分布 legend 没显示应用名
**截图症状**: 环图右边只有 69% / 31%, 没有应用名

**根因**: legend 渲染时 `d.name` 为空(数据问题), 但代码没兜底.

**修法**: name 为空时退化到 category 中文 label (`dpiCategoryLabel(d.cat)`) 或 raw category 字符串, 最差也显示 "未分类". `<span>` 加 `title` 属性, hover 看完整名.

## 文件清单

```
M webroot/index.html               (~150 行: CSS 重排 + JS 设备匹配 + 速率字段 + legend 兜底)
M module.prop                       rc25.0 → rc26.0 / 530050 → 530060
+ PATCH-NOTES-v5.3.0-rc26.0.md      (本文件)
```

## 不动

- dpid binary 不变 (still v0.4.0-rc23)
- daemon hnc_httpd 不变
- 所有 rc24/25 加的 nDPI Lab 工具不变
- 所有 rc24/25 加的规则库扩展 v2 不变
- 所有 rc24/25 加的未识别域名助手不变
- 所有之前的 P0/P1 修复不变

## 验证

```
sh -n  → 全过 (主要 shell)
node --check  → 全过 (3 个 script block)
JSON  → 全过 (5 个 data 文件)
新 class 都存在 (dpi-ac-row-head, dpi-rank-head, dpi-rank-name 等)
```

## 装上预期

打开 DPI tab, 跟你 5/13 截图对比应该看到:

| 元素 | 截图 (rc23) | rc26 |
|---|---|---|
| 应用名 | 字... | **字节系服务·社交** (完整, 可能换行) |
| 识别总览 1 | 字节... 100% | **字节系服务·社交** (独立一行) + bar + 100% |
| 识别总览 2 | 微信... 44% | **微信** + bar + 44% |
| 设备名 | 172.23.1... | **客户端 .89** (IP 末段) |
| 头像 | ❓ 灰色 | 📡 (网络中性) |
| 速率 | — Mbps | **0.91 Mbps** (如主页有数据) / **速率不可用 (等 conntrack)** (诚实文案) |
| 环图 legend | 69% / 31% | **字节系服务 69%** / **微信 31%** |

## 真正的关键

**rc26 没修底层数据问题**:

- conntrack 字节统计**还是不工作** — 这是 dpid v0.4.0 在 ColorOS 16 上的问题, 要么 `nf_conntrack_acct` 没开, 要么 BPF tether offload 抢走了流量. 装上后如果 conntrack 仍空, **告诉我**, 我做 rc27 加诊断脚本 (`nf_conntrack_acct` 检测 + 开关说明)
- USB tether 客户端**主页探不到** — 这是 device_detect.sh 的 ARP 探测路径问题, 跟 DPI UI 无关

这两个我都没动, 只让 UI 在数据缺失时**显示得不那么糟糕**. 如果你想从根本上修, 告诉我哪个先做 (开 nf_conntrack_acct / 改 device_detect 找 USB tether).

## 接下来

装上 → 拍照 → 对比看修了多少
