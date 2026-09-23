# HNC WebUI · 液态玻璃设计预览

新版 WebUI 的视觉方案预览：苹果 Liquid Glass 风格的真折射玻璃。

- `index.html`：自包含预览页，内置**示例数据**，不连接后端；已去掉 DPI 识别、offload 检测、能力检测等检测类功能，只保留设备、应用、统计、设置四个核心页面。直接用 Chromium 内核的浏览器打开即可。
- `hyalite.js`：折射引擎，原样引入，未做修改。

## 致谢

液态玻璃的折射效果来自 **[Hyalite](https://github.com/VII-Cae/hyalite--liquid-glass)**（v0.5.0），作者 **VII-Cae（VII）**，MIT 协议，许可证原文见 `LICENSE-hyalite`。

Hyalite 按元素的尺寸和圆角算出一张透镜位移贴图，放进 SVG 滤镜，再通过 `backdrop-filter: url(#…)` 让元素背后的画面真正弯折：中心清透，边缘压暗，并带一道高光。Chromium / Android WebView 上渲染的是真折射；其他浏览器会退回 CSS 里写的 `blur()` 毛玻璃。

## 本页的参数

| 元素 | bevel | thickness | blur | 用途 |
|---|---|---|---|---|
| `.lg` 卡片 | 20 | 30 | 7 | 乳白磨砂卡片 |
| `.lg-dark` | 18 | 26 | 5 | 深色玻璃 |
| `.lg-pill` 胶囊按钮 | 14 | 18 | 4 | 按钮、搜索框、Toast |
| `.lg-nav` 底栏 | 18 | 26 | 6 | 悬浮导航胶囊 |
| `.lg-lens` 导航透镜 | 16 | 40 | 0.6 | 滑动时放大下方图标 |

## 截图时注意

无 GPU 的 headless Chromium（软件合成）画 SVG backdrop 滤镜时会整体错位，Hyalite 自己的 demo 也一样。截图时要带 `--use-gl=angle --use-angle=swiftshader --enable-unsafe-swiftshader` 走 GPU 合成路径，手机上不受影响。
