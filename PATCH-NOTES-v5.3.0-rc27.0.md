# HNC v5.3.0-rc27.0 — 修 UI 死机 (rc26.0 引入的 audit-fix 退化)

## 主题

rc26.0 是 MiMo-V2.5-Pro + Hermes Agent 跑的 25+ 处 audit-fix/opt 优化版. 大部分质量提升是好的, 但**两处 audit-fix 引起 UI 在你设备上"打开就死机"**. 这一版**只回退/修正引起死机的部分**, 保留其他所有改进.

**dpid binary 不动** (still v0.4.0-rc23)
**daemon 不动**
**所有 rc24/25/26 新功能保留** (nDPI Lab / 规则库 v2 / 域名助手 / 截图风格 DPI UI / a11y / WCAG 对比度等 audit-fix)

## 修了什么

### Bug 1 (主因): `__sanitizeModalHTML` 剥光所有 `on*` 属性导致 modal 死锁

**根因**:

rc26-full 加的 audit-fix:

```js
function __sanitizeModalHTML(html) {
  ...
  doc.querySelectorAll('*').forEach(el => {
    for (const attr of Array.from(el.attributes)) {
      if (/^on/i.test(attr.name)) el.removeAttribute(attr.name);  // ← 太激进
    }
  });
  ...
}
```

代码库里有 **4 处 modal 内容用了内联 `onclick`**:

```js
// line 4498-4499 - 屏蔽确认
<button class="btn" onclick="window.__bl_confirm(false)">取消</button>
<button class="btn btn-danger" onclick="window.__bl_confirm(true)">仍要屏蔽</button>

// line 4263 - dbg 关闭按钮
<button onclick="hideDbgBar()">×</button>

// line 9540 - JSON 健康卡片
[data-hje-open].onclick = ...
```

经过 `__sanitizeModalHTML` 后这些 onclick **全被剥**, 按钮点不动 → modal 关不掉 → modal-backdrop 永久挡住主页 → 看起来"打开就死机".

**为什么是"打开"就发生**:
你装上 rc26.0 后, 系统可能因为某些条件 (首次 token 检查 / token 过期 / bridge 失败) 自动弹一个 modal — 这是用户没主动触发的 modal. 这个 modal 立刻被 sanitize 剥掉 onclick, 然后**无法关闭**, 整个 UI 看起来"死了". 主页其实在背后, 但被透明 backdrop 挡住.

**rc27.0 修法**: 

不剥 `on*` 属性. 改成只剥真正危险的两类:
1. `<script>` / `<iframe>` / `<object>` / `<embed>` 等容器元素
2. `<a href="javascript:..">` / `<img src="javascript:..">` 等 URL 协议注入

为什么这样安全:
- modal HTML 是代码里 template literal **写死**的, 不是用户输入. 不存在 XSS 风险
- 真正需要 escape 的是 `${userInput}` 插值点, 那是另一层 (各调用点应自己 escape)
- 这次审计如果想杜绝 XSS 应该是**在 ${...} 插值处 escape**, 不是粗暴 strip on*

### Bug 2: viewport `user-scalable=no` 被去掉

**根因**:

rc26-full 改了 viewport meta:
```
< user-scalable=no  (原)
> (去掉)             (audit-fix 改: 允许用户双指缩放, a11y)
```

**a11y 角度这个改动是对的** — 让弱视用户能放大. **但是**在某些 WebView 实现 (尤其 ColorOS 上的 SukiSU WebUI) 上, 移除 `user-scalable=no` 会触发:
- 输入框聚焦时 WebView 自动缩放
- 缩放后 layout 抖动
- 部分 viewport 内事件捕获错位

具体到你那台 RMX5010 + ColorOS 16, 移除 `user-scalable=no` 可能让首次 layout 反复重排, 极端情况下卡死.

**rc27.0 修法**: 加回 `user-scalable=no`. 这跟整个 HNC 的"工具型应用,固定布局"定位一致. 弱视场景可以靠系统级 WebView 字号设置代偿, 不需要双指缩放.

## 没修的 audit-fix (保留)

| 改动 | 保留原因 |
|---|---|
| reduced-motion 媒体查询禁用 bg 动画 | a11y, 不影响功能 |
| `--text-3` 对比度提升 (0.62→0.72) | WCAG, 让浅色模式更易读 |
| 删 backdrop-filter 冗余 | 性能, 无副作用 |
| z-index 1000→350 (dbgbar) | dbg 栏不挡 modal, 合理 |
| `[opt #1]` __lastDPIStateRaw 缓存 | 性能 |
| `[opt #2]` ndpiExtractAll 单遍 | 性能 |
| `[opt #15]` normMac 顶层提取 | DRY |
| `[opt #16]` ndpiLabRun 共享 | DRY |
| 死代码 `kexecJSON` 删除 | 清理 |
| 2 个新 unit test 脚本 | 回归保护 |
| 380px 媒体查询 (小屏 2 列计数卡) | 响应式 |
| 等等... | 共 23 处保留 |

## 文件清单

```
M webroot/index.html               (2 处修改: __sanitizeModalHTML 改安全过滤; viewport 加回 user-scalable=no)
M module.prop                       rc26.0 → rc27.0 / 530060 → 530070
+ PATCH-NOTES-v5.3.0-rc27.0.md      (本文件)
```

## 验证

- shell `sh -n` 全过
- JSON 全过 (5 个 data 文件)
- node --check 报警跟 rc26-full 完全一样 (ES2020 语法 node parse 不全, 不是 rc27 引入)
- module.prop 格式正确

## 装上预期

1. **打开 HNC 应该不再死机** — modal 按钮可以点了, sanitize 不再剥代码里写死的 onclick
2. **输入搜索框时不再被 WebView 自动放大** — viewport 加回 user-scalable=no
3. **rc26.0 的所有正面改动还在** — 对比度好了 / a11y 部分改进 / 性能优化 / 死代码清理 / DRY 优化

## 如果还死机

那就不是这两处, 我需要你帮我看:

1. 装上 rc27.0, 在 HNC 打开**前** 1 秒进 SukiSU/KSU WebUI 的 "DevTools" 或 "Inspect" (如果有)
2. 看 console 有没有 JS error
3. 看 Network 有没有某个 fetch hang
4. 拍照发我

或者更简单: 装上 rc27.0 后**长按 dbg 栏**(底部右下角小调试栏) 应该会展开显示最近的 error log, 拍那个发我.

## 这是个教训

Hermes Agent 跑出来的 audit-fix 大部分质量很好, 但**最后 1 公里**还是需要人工检查 — 特别是当改动跨越"代码-runtime"边界 (audit-fix 在 *代码静态* 角度对, 但在 *运行时实际效果* 上引起 regression).

下次 Hermes Agent 跑完后, 我建议在合并前**至少装机跑 5 分钟**, 任何"看起来跟之前不一样"的现象都拍照发我.
