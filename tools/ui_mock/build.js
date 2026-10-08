#!/usr/bin/env node
/* HNC WebUI 界面预览 · build.js —— 把真实的 webroot 界面 + 假后端(fake_api.js)打成一个自包含的 HTML
 *
 * 用法: node tools/ui_mock/build.js <out.html>
 *
 * 按 webroot/index.html 里的顺序内联:
 *   css/base.css → css/apple.css → css/liquid.css(<style>)
 *   hyalite.js → js/core.js → [fake_api.js] → js/fx.js → … → js/main.js(内联 <script>)
 * 另外:
 *   - 首帧主题脚本之前插一段: localStorage 没有 hnc6.style 时默认「液态玻璃」(liquid)
 *   - <title> 改成「HNC 界面预览」
 *   - 内嵌 webroot/changelog.html 副本(设置 → 更新日志 用), 以及 module.prop 的版本号
 * 产物不引用任何外部 / 本地文件(没有 src= / href= 指向文件), 双击就能在浏览器里打开。
 * 只用 Node 内置模块; 不修改 webroot 里的任何文件。 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const WEB = path.join(ROOT, 'webroot');
const out = process.argv[2];
if (!out || out === '-h' || out === '--help') {
  console.error('用法: node tools/ui_mock/build.js <out.html>');
  process.exit(out ? 0 : 1);
}

const read = (p) => fs.readFileSync(p, 'utf8');
// 内联脚本里不能出现 "</script"(会提前结束 <script> 元素); "<!--" 也可能把解析器带进 script-data-escaped 状态
const safeJs = (s) => s.replace(/<\/(script)/gi, '<\\/$1').replace(/<!--/g, '<\\!--');
const safeCss = (s) => s.replace(/<\/(style)/gi, '<\\/$1');
const LS_ = new RegExp(String.fromCharCode(0x2028), 'g'), PS_ = new RegExp(String.fromCharCode(0x2029), 'g');   // 行分隔符在旧引擎的字符串字面量里不合法
const jsStr = (s) => JSON.stringify(s).replace(/<\//g, '<\\/').replace(/<!--/g, '<\\!--').replace(LS_, '\\u2028').replace(PS_, '\\u2029');

let html = read(path.join(WEB, 'index.html'));
const used = [];

// 1) <title>
html = html.replace(/<title>[\s\S]*?<\/title>/, '<title>HNC 界面预览</title>');

// 2) 样式表 → <style>
html = html.replace(/<link\s+rel="stylesheet"\s+href="([^"]+)"\s*\/?>/g, (m, href) => {
  const f = path.join(WEB, href);
  if (!fs.existsSync(f)) throw new Error('找不到样式表: ' + href);
  used.push(href);
  return '<style>/* ' + href + ' */\n' + safeCss(read(f)) + '\n</style>';
});

// 3) 首帧主题脚本之前: 默认液态玻璃风格
const firstInline = html.search(/<script>(?=\(function \(\) \{ try \{ var r = document\.documentElement)/);
if (firstInline < 0) throw new Error('index.html 里没找到首帧主题脚本(<script>(function () { try { var r = document.documentElement …)');
const styleDefault = '<!-- 界面预览: 没选过界面风格时默认「液态玻璃」 -->\n' +
  "<script>try { if (!localStorage.getItem('hnc6.style')) localStorage.setItem('hnc6.style', 'liquid'); } catch (_) {}</script>\n";
html = html.slice(0, firstInline) + styleDefault + html.slice(firstInline);

// 4) 外链脚本 → 内联; js/core.js 之后插入内嵌数据 + fake_api.js
let sawCore = false;
const meta = (() => {
  const o = { builtAt: new Date().toISOString() };
  try {
    const mp = read(path.join(ROOT, 'module.prop'));
    const v = /^version=(.*)$/m.exec(mp), c = /^versionCode=(.*)$/m.exec(mp);
    if (v) o.version = v[1].trim();
    if (c) o.versionCode = c[1].trim();
  } catch (_) {}
  return o;
})();
html = html.replace(/<script\s+src="([^"]+)"\s*><\/script>/g, (m, src) => {
  const f = path.join(WEB, src);
  if (!fs.existsSync(f)) throw new Error('找不到脚本: ' + src);
  used.push(src);
  let s = '<script>/* ' + src + ' */\n' + safeJs(read(f)) + '\n</script>';
  if (src === 'js/core.js') {
    sawCore = true;
    let cl = '';
    try { cl = read(path.join(WEB, 'changelog.html')); } catch (_) {}
    s += '\n<script>/* 界面预览: 内嵌数据(版本号 + changelog.html 副本) */\nwindow.__HNC_MOCK_META = ' + jsStr(meta) + ';\nwindow.__HNC_MOCK_CHANGELOG = ' + jsStr(cl) + ';\n</script>';
    s += '\n<script>/* tools/ui_mock/fake_api.js */\n' + safeJs(read(path.join(__dirname, 'fake_api.js'))) + '\n</script>';
  }
  return s;
});
if (!sawCore) throw new Error('index.html 里没找到 <script src="js/core.js">, fake_api.js 无处插入');

// 5) 头部加一行说明
html = html.replace(/<head>/, '<head>\n<!-- HNC 界面预览: 由 tools/ui_mock/build.js 生成于 ' + meta.builtAt + ' · 所有数据都是虚构的演示数据, 不连接任何后端 -->');

// 6) 自检: 不能再有引用文件的 <script src> / <link href> / <img src>
const leftover = [];
const re = /<(script|link|img|iframe|source)\b[^>]*\b(src|href)\s*=\s*"([^"]*)"/gi;
let mm;
// 只看 HTML 结构部分: 先把内联 <script>/<style> 的内容剔掉再扫
const skeleton = html.replace(/<script>[\s\S]*?<\/script>/g, '<script></script>').replace(/<style>[\s\S]*?<\/style>/g, '<style></style>');
while ((mm = re.exec(skeleton))) if (!/^(data:|#)/.test(mm[3])) leftover.push(mm[0]);
if (leftover.length) throw new Error('产物里还有外部引用: ' + leftover.join(' | '));

fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
fs.writeFileSync(out, html);
console.log('已生成 ' + path.resolve(out) + ' · ' + (Buffer.byteLength(html) / 1024).toFixed(0) + ' KB · 内联 ' + used.length + ' 个文件 + fake_api.js' + (meta.version ? ' · ' + meta.version : ''));
