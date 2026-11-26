#!/usr/bin/env node
/* HNC WebUI 界面预览 · build.js —— 把真实的 webroot 界面 + 假后端(fake_api.js)打成一个自包含的 HTML
 *
 * 用法: node tools/ui_mock/build.js [--variant=pure|prism|dew] [out.html]
 *
 * 按 webroot/index.html 里的顺序内联:
 *   css/base.css -> css/apple.css -> css/liquid.css(<style>)
 *   hyalite.js -> js/core.js -> [fake_api.js] -> js/fx.js -> ... -> js/main.js(内联 <script>)
 * 另外:
 *   - <html> 静态预置 data-style="apple" data-glass="liquid" data-lg-variant="<variant>"
 *   - 首帧主题脚本之前注入兼容 content:// 沙箱 WebView 的无异常预设脚本
 *   - <title> 按版本区分(pure / prism / dew)
 *   - 内嵌 webroot/changelog.html 副本(设置 -> 更新日志 用), 以及 module.prop 的版本号
 *   - 强制校验 hyalite.js 已内联且包含 Hyalite 引擎
 * 产物不引用任何外部 / 本地文件(没有 src= / href= 指向文件), 双击或在沙箱 WebView 中均可直接打开。
 * 只用 Node 内置模块; 不修改 webroot 里的任何文件。 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const WEB = path.join(ROOT, 'webroot');

const VALID_VARIANTS = { pure: 1, prism: 1, dew: 1 };
const VARIANT_TITLES = {
  pure: 'HNC · 版本1 原生无框纯透版',
  prism: 'HNC · 版本2 棱镜随景微色散版',
  dew: 'HNC · 版本3 凝脂水滴张力柔光版',
};

function normVariant(v) {
  const s = String(v || '').trim().toLowerCase();
  return VALID_VARIANTS[s] ? s : 'pure';
}

let rawVariant = '';
let outFile = '';
const cliArgs = process.argv.slice(2);
for (let i = 0; i < cliArgs.length; i++) {
  const a = cliArgs[i];
  if (a === '-h' || a === '--help') {
    console.error('用法: node tools/ui_mock/build.js [--variant=pure|prism|dew] [out.html]');
    process.exit(0);
  }
  if (a.indexOf('--variant=') === 0) {
    rawVariant = a.slice('--variant='.length);
  } else if (a === '--variant') {
    if (i + 1 < cliArgs.length && cliArgs[i + 1].indexOf('--') !== 0) {
      rawVariant = cliArgs[++i];
    } else {
      rawVariant = '';
    }
  } else if (a.indexOf('--') === 0) {
    // 忽略其它未知 -- 选项
  } else if (!outFile) {
    outFile = a;
  }
}
const variant = normVariant(rawVariant);
const out = outFile || path.join(ROOT, 'dist', 'hnc_webui_preview.html');

const read = (p) => fs.readFileSync(p, 'utf8');
// 内联脚本里不能出现 "</script"(会提前结束 <script> 元素); "<!--" 也可能把解析器带进 script-data-escaped 状态
const safeJs = (s) => s.replace(/<\/(script)/gi, '<\\/$1').replace(/<!--/g, '<\\!--');
const safeCss = (s) => s.replace(/<\/(style)/gi, '<\\/$1');
const LS_ = new RegExp(String.fromCharCode(0x2028), 'g'), PS_ = new RegExp(String.fromCharCode(0x2029), 'g');   // 行分隔符在旧引擎的字符串字面量里不合法
const jsStr = (s) => JSON.stringify(s).replace(/<\//g, '<\\/').replace(/<!--/g, '<\\!--').replace(LS_, '\\u2028').replace(PS_, '\\u2029');

let html = read(path.join(WEB, 'index.html'));
const used = [];

// 0) <html> 根节点静态预置属性(保证 content:// 首帧零闪烁直出对应液态玻璃版本)
let sawHtml = false;
html = html.replace(/<html\b([^>]*)>/i, (m, attrs) => {
  sawHtml = true;
  const cleaned = attrs.replace(/\s+data-(?:style|glass|lg-variant)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  return '<html' + cleaned + ' data-style="apple" data-glass="liquid" data-lg-variant="' + variant + '">';
});
if (!sawHtml) throw new Error('index.html 里没找到 <html> 根节点');

// 1) <title> 按版本附带清晰后缀
html = html.replace(/<title>[\s\S]*?<\/title>/, '<title>' + VARIANT_TITLES[variant] + '</title>');

// 2) 样式表 -> <style>
html = html.replace(/<link\s+rel="stylesheet"\s+href="([^"]+)"\s*\/?>/g, (m, href) => {
  const f = path.join(WEB, href);
  if (!fs.existsSync(f)) throw new Error('找不到样式表: ' + href);
  used.push(href);
  return '<style>/* ' + href + ' */\n' + safeCss(read(f)) + '\n</style>';
});

// 3) 首帧主题脚本之前: 注入兼容 content:// 的零报错全局预设与版本配置
let firstInline = html.search(/<script>\s*(?=\(function\s*\(\)\s*\{\s*try\s*\{\s*var\s+r\s*=\s*document\.documentElement)/);
if (firstInline < 0) {
  const inlineRe = /<script>([\s\S]*?)<\/script>/g;
  let im;
  while ((im = inlineRe.exec(html))) {
    if (im[1].indexOf('document.documentElement') >= 0 &&
        (im[1].indexOf('data-style') >= 0 || im[1].indexOf('data-theme') >= 0 || im[1].indexOf('hnc6.style') >= 0)) {
      firstInline = im.index;
      break;
    }
  }
}
if (firstInline < 0) throw new Error('index.html 里没找到首帧主题脚本(<script>(function () { try { var r = document.documentElement ...))');
const vJson = JSON.stringify(variant);
const styleDefault = '<!-- 界面预览: 首帧预设液态玻璃与版本(' + variant + '), 兼容 content:// 沙箱 WebView -->\n' +
  '<script>(function(){var p={"hnc6.style":"liquid","hnc6.glass_mode":"liquid","hnc6.lg_variant":' + vJson + '};' +
  'window.__HNC_PREVIEW_VARIANT__=' + vJson + ';window.__HNC_BOOT_PREFS__=p;' +
  'try{if(!localStorage.getItem("hnc6.style"))localStorage.setItem("hnc6.style","liquid");' +
  'if(!localStorage.getItem("hnc6.glass_mode"))localStorage.setItem("hnc6.glass_mode","liquid");' +
  'localStorage.setItem("hnc6.lg_variant",' + vJson + ');}catch(e){}})();</script>\n';
html = html.slice(0, firstInline) + styleDefault + html.slice(firstInline);

// 4) 外链脚本 -> 内联; js/core.js 之后插入内嵌数据 + fake_api.js
let sawCore = false;
const meta = (() => {
  const o = { builtAt: new Date().toISOString(), variant };
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
    try {
      cl = read(path.join(WEB, 'changelog.html'));
      if (cl.length > 36000) {
        var secs = cl.split(/(?=<div class="cl-section\b)/);
        cl = secs.slice(0, 13).join('') +
          '<div class="note" style="text-align:center;padding:12px 0">单文件交互预览仅内嵌近期 12 个版本记录 · 完整历史记录见模块包 webroot/changelog.html</div>';
      }
    } catch (_) {}
    s += '\n<script>/* 界面预览: 内嵌数据(版本号 + changelog.html 副本) */\nwindow.__HNC_MOCK_PREVIEW__ = true;\nwindow.__HNC_MOCK_META = ' + jsStr(meta) + ';\nwindow.__HNC_MOCK_CHANGELOG = ' + jsStr(cl) + ';\n</script>';
    s += '\n<script>/* tools/ui_mock/fake_api.js */\n' + safeJs(read(path.join(__dirname, 'fake_api.js'))) + '\n</script>';
  }
  return s;
});
if (!sawCore) throw new Error('index.html 里没找到 <script src="js/core.js">, fake_api.js 无处插入');

// 5) 头部加一行说明
html = html.replace(/<head>/, '<head>\n<!-- HNC 界面预览(' + variant + '): 由 tools/ui_mock/build.js 生成于 ' + meta.builtAt + ' · 所有数据都是虚构的演示数据, 不连接任何后端 -->');

// 6) 自检: 强制校验 hyalite.js 已内联, 且不能再有引用文件的 <script src> / <link href> / <img src>
const skeleton = html.replace(/<script>[\s\S]*?<\/script>/g, '<script></script>').replace(/<style>[\s\S]*?<\/style>/g, '<style></style>');
if (html.indexOf('<script src="hyalite.js"></script>') >= 0 || /<script\b[^>]*\bsrc\s*=\s*["'][^"']*hyalite\.js["'][^>]*>/i.test(skeleton)) {
  throw new Error('构建失败: hyalite.js 未内联(<script src="hyalite.js"></script> 仍残留)');
}
if (html.indexOf('Hyalite') < 0) {
  throw new Error('构建失败: 最终 HTML 未包含 Hyalite 物理折射引擎');
}
const leftover = [];
const re = /<(script|link|img|iframe|source)\b[^>]*\b(src|href)\s*=\s*"([^"]*)"/gi;
let mm;
while ((mm = re.exec(skeleton))) if (!/^(data:|#)/.test(mm[3])) leftover.push(mm[0]);
if (leftover.length) throw new Error('产物里还有外部引用: ' + leftover.join(' | '));

fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
fs.writeFileSync(out, html);
console.log('已生成 ' + path.resolve(out) + ' · variant=' + variant + ' · ' + (Buffer.byteLength(html) / 1024).toFixed(0) + ' KB · 内联 ' + used.length + ' 个文件 + fake_api.js' + (meta.version ? ' · ' + meta.version : ''));
