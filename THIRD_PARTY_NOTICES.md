# Third-Party Notices

本文件列出 HNC 模块中包含的、来自第三方的数据或代码及其许可。

## v2fly/domain-list-community

- 名称: domain-list-community
- 地址: https://github.com/v2fly/domain-list-community
- 使用的 commit: `2c892a618f4e23c549d28edd0f3f75407521b1aa`(2026-10-02)
- 使用方式: v5.27 起, `tools/import_v2fly.py` 按 `tools/v2fly_map.json` 把其中「一个清单 = 一个 App / 服务」
  的域名清单转换为 DPI 规则 `data/dpi_rules.d/46-v2fly-*.json`(并派生进 `data/dpi_rules.json`)。
  只取域名后缀; `keyword:` / `regexp:` 行与带 `@ads` 属性的行未使用; 与已有规则冲突的后缀已跳过。
- 许可: MIT License,全文如下(原样摘自该仓库 LICENSE 文件):

```
MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Hyalite(液态玻璃折射)

- 名称: hyalite — real refraction "liquid glass" for the web(v0.5.0)
- 地址: https://github.com/VII-Cae/hyalite--liquid-glass
- 作者: VII-Cae (VII)
- 使用方式: `webroot/hyalite.js` 原样随 WebUI 分发(v5.24 之前引入),液态玻璃风格下给底栏 / 透镜 / 顶栏按钮 /
  弹层 / 提示挂真折射(SVG 位移贴图 + `backdrop-filter: url()`,只在 Chromium 内核生效,其它退回 CSS 磨砂)。
  许可全文另见 `webroot/LICENSE-hyalite`;署名在 `webroot/index.html` 头注释与 `webroot/js/main.js`。
- 许可: MIT License,全文如下(原样摘自 `webroot/LICENSE-hyalite`):

```
MIT License

Copyright (c) 2026 VII-Cae (VII)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
