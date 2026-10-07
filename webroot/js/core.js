/* HNC WebUI · core.js —— 基础工具、图标、传输层(KSU 桥接 / 同源 fetch)、toast、全局状态 S、能力、数据加载

  脚本组织: 经典脚本(不是 ES module —— 部分 KSU WebView 用 file:// 加载, module 脚本会被拒),
  由 index.html 按 hyalite → core → fx → devices → apps → stats → settings → sheets → main 的顺序
  同步加载。各文件顶层的 var / function 共处同一个全局作用域, 与拆分前的单个 IIFE 等价。
  约束: 文件里"加载时立即执行"的代码(含它注册的回调最终会调用的函数)只能依赖本文件及之前文件
  定义的名字 —— 远程加载时两个 <script> 之间事件循环可能先跑 rAF/事件回调; 启动逻辑全在 main.js。 */
'use strict';

/* ═════════════════════ 基础工具 ═════════════════════ */
var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
function sum(a, f) { return a.reduce(function (s, x) { return s + (f ? f(x) : x); }, 0); }
function num(v, d) { var n = parseFloat(v); return isFinite(n) ? n : (d || 0); }
function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
function trim0(s) { return String(s).replace(/(\.\d*?[1-9])0+$/, '$1').replace(/\.0+$/, ''); }
function pad2(n) { return String(n).padStart(2, '0'); }
var LS = {
  get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (_) { return d; } },
  set: function (k, v) { try { localStorage.setItem(k, v); } catch (_) {} },
  del: function (k) { try { localStorage.removeItem(k); } catch (_) {} }
};
var SS = {
  get: function (k) { try { return sessionStorage.getItem(k); } catch (_) { return null; } },
  set: function (k, v) { try { sessionStorage.setItem(k, v); } catch (_) {} }
};
var wideMQ = matchMedia('(min-width: 900px)');
function wide() { return wideMQ.matches; }
var calm = matchMedia('(prefers-reduced-motion: reduce)').matches;

/* 单位: 后端限速一律 Mbps, 界面一律 MB/s(= Mbps / 8); 速率 rx_bps/tx_bps 是字节/秒 */
function mbpsToMBs(m) { m = num(m); return m > 0 ? trim0((m / 8).toFixed(2)) : ''; }
function mbsToMbps(v) { v = num(v); return v > 0 ? v * 8 : 0; }
function fmtRate(mbps) { return (mbps >= 1 && Math.abs(mbps - Math.round(mbps)) < 1e-9) ? Math.round(mbps) + 'mbit' : Math.max(1, Math.round(mbps * 1000)) + 'kbit'; }
function bps(b) { b = num(b); if (b >= 1048576) return { v: (b / 1048576).toFixed(2), u: 'MB/s' }; if (b >= 1024) return { v: String(Math.round(b / 1024)), u: 'KB/s' }; return { v: String(Math.round(b)), u: 'B/s' }; }
function bytes(b) { b = num(b); if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB'; if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB'; if (b >= 1024) return Math.round(b / 1024) + ' KB'; return Math.round(b) + ' B'; }
function gb(b) { return num(b) / 1073741824; }
function ago(ts) {
  ts = num(ts); if (!ts) return '—';
  var s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return s + ' 秒前'; if (s < 3600) return Math.round(s / 60) + ' 分钟前';
  if (s < 86400) return Math.round(s / 3600) + ' 小时前'; return Math.round(s / 86400) + ' 天前';
}
function hms(sec) { sec = Math.max(0, Math.round(num(sec))); var h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60); return h ? h + ' 时 ' + m + ' 分' : m + ' 分 ' + (sec % 60) + ' 秒'; }
function today() { var d = new Date(); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
function isMac(s) { return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(String(s || '')); }
function isRandomMac(m) { var c = parseInt(String(m || '').charAt(1), 16); return !isNaN(c) && (c & 2) === 2; }

/* ═════════════════════ 图标 ═════════════════════ */
var I = {
  dev:'<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  apps:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
  stats:'<line x1="6" y1="20" x2="6" y2="13"/><line x1="12" y1="20" x2="12" y2="5"/><line x1="18" y1="20" x2="18" y2="10"/>',
  gear:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  chev:'<polyline points="6 9 12 15 18 9"/>', right:'<polyline points="9 6 15 12 9 18"/>',
  search:'<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  bolt:'<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  home:'<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  refresh:'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  trash:'<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/>',
  power:'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/>',
  check:'<polyline points="20 6 9 17 4 12"/>', box:'<polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  star:'<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 1 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>',
  doc:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>',
  wifi:'<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1"/>',
  gauge:'<path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
  shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', globe:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  cpu:'<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
  heart:'<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>', tool:'<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
  flask:'<path d="M9 2h6M10 2v6L4 20a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 20L14 8V2"/>', info:'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  palette:'<circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.93 0 1.5-.75 1.5-1.66 0-.43-.18-.83-.44-1.12-.29-.29-.44-.65-.44-1.12a1.64 1.64 0 0 1 1.67-1.67h2c3.05 0 5.56-2.5 5.56-5.56C21.97 6.01 17.46 2 12 2z"/>',
  rocket:'<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/>',
  layers:'<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  down:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  lock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  x:'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  warn:'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  trend:'<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>',
  eye:'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  tunnel:'<path d="M3 21v-9a9 9 0 0 1 18 0v9"/><path d="M8 21v-8a4 4 0 0 1 8 0v8"/><line x1="1" y1="21" x2="23" y2="21"/>',
  merge:'<circle cx="6" cy="5" r="2.5"/><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="12" r="2.5"/><path d="M6 7.5v9"/><path d="M8.3 6.2C12 7 15 8.5 16 10"/>'
};
function ico(k, cls) { return '<svg class="' + (cls || '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + (I[k] || '') + '</svg>'; }
function gi(color, k) { return '<span class="gi ' + color + '">' + ico(k) + '</span>'; }
function toggle(on, attrs) { return '<button class="toggle" role="switch" aria-checked="' + !!on + '" ' + (attrs || '') + '></button>'; }
function seg(id, opts, cur, cls) {
  return '<div class="seg ' + (cls || 'glass') + '" data-seg="' + id + '"><i class="thumb"></i>' + opts.map(function (o) {
    return '<button type="button" data-v="' + esc(o[0]) + '" class="' + (String(o[0]) === String(cur) ? 'on' : '') + '">' + o[1] + '</button>'; }).join('') + '</div>';
}
function placeSegs(root) {
  $$('.seg', root || document).forEach(function (s) {
    var on = $('button.on', s), th = $('.thumb', s); if (!on || !on.offsetWidth) { if (th) th.style.width = '0px'; return; }
    var w = on.offsetWidth + 'px', tf = 'translateX(' + on.offsetLeft + 'px)';
    if (th.style.width === w && th.style.transform === tf) return;
    // 新渲染出来的分段控件第一次定位不走过渡 —— 此前每次重绘滑块都从最左边滑过来(一页十几个同时滑)
    var first = !th.style.transform || th.style.width === '0px';
    if (first) th.style.transition = 'none';
    th.style.width = w; th.style.transform = tf;
    if (first) { void th.offsetWidth; th.style.transition = ''; }
  });
}

/* ═════════════════════ 就地更新(morph) ═════════════════════
 * 把新 HTML 合并进现有 DOM, 而不是 innerHTML 整块替换: 节点按 key(data-dev / data-side / data-foldkey / id /
 * data-app / data-mkey)或「位置 + 标签」复用, 只改变化了的属性和文字。
 * 好处: 展开的折叠、滚动位置、焦点、正在输入的值、进行中的过渡都不被打断; 进度条/柱子/侧栏这类 CSS 入场
 * 动画不会因为后台刷新重放; 每次刷新替换的节点从几百上千降到个位数。
 *  - 输入框: 只有模板里的 value 变了(后端数据变了)才覆盖当前值, 且从不动正在聚焦的框 —— 用户正在填的值保留
 *  - data-keep: 异步填进来的内容(日志/趋势图/授权列表), 整个子树跳过
 *  - .pending(或其所在 .seg.pending): 请求进行中的乐观状态, 不被后台刷新改回去(避免开关来回闪)
 *  - 临时 class(busy / pending / jelly / run)保留 */
var MORPH_KEEP_CLS = ['busy', 'pending', 'jelly', 'run'];
function mkey(n) {
  if (n.nodeType !== 1) return '';
  var k = n.getAttribute('data-dev') || n.getAttribute('data-side') || n.getAttribute('data-foldkey') || n.id || n.getAttribute('data-app') || n.getAttribute('data-mkey');
  return k ? n.nodeName + ':' + k : '';
}
function morphAttrs(a, b) {
  var i, at, frozen = a.classList.contains('pending') || !!(a.parentNode && a.parentNode.classList && a.parentNode.classList.contains('pending'));
  for (i = a.attributes.length - 1; i >= 0; i--) {
    at = a.attributes[i].name;
    if (b.hasAttribute(at) || (at === 'style' && a.classList.contains('thumb'))) continue;
    if (frozen && (at === 'class' || at === 'aria-checked')) continue;
    a.removeAttribute(at);
  }
  for (i = 0; i < b.attributes.length; i++) {
    at = b.attributes[i];
    var cur = a.getAttribute(at.name); if (cur === at.value) continue;
    if (at.name === 'class') {
      if (frozen) continue;
      var keep = MORPH_KEEP_CLS.filter(function (c) { return a.classList.contains(c) && !b.classList.contains(c); });
      a.setAttribute('class', at.value + (keep.length ? ' ' + keep.join(' ') : ''));
      continue;
    }
    if (frozen && at.name === 'aria-checked') continue;
    if (at.name === 'style' && a.classList.contains('thumb')) continue;
    a.setAttribute(at.name, at.value);
    if (a.nodeName === 'INPUT' && at.name === 'value' && a !== document.activeElement) a.value = at.value;
  }
  if (a.nodeName === 'INPUT' && (a.type === 'checkbox' || a.type === 'radio')) { var ck = b.hasAttribute('checked'); if (a.defaultChecked !== ck) a.checked = ck; }
}
function morphNode(a, b) {
  if (a.nodeType !== 1) { if (a.nodeValue !== b.nodeValue) a.nodeValue = b.nodeValue; return a; }
  if (a.hasAttribute('data-keep')) return a;
  morphAttrs(a, b);
  if (a.nodeName !== 'TEXTAREA') morphKids(a, b);
  return a;
}
function morphKids(a, b) {
  var olds = Array.prototype.slice.call(a.childNodes), news = Array.prototype.slice.call(b.childNodes), keyed = {}, free = [], fi = 0;
  olds.forEach(function (n) { var k = mkey(n); if (k && !keyed[k]) keyed[k] = n; else free.push(n); });
  for (var i = 0; i < news.length; i++) {
    var nn = news[i], k = mkey(nn), m = null;
    if (k) { m = keyed[k] || null; if (m) delete keyed[k]; }
    else {
      // 按位置找第一个同类型的旧节点(往后最多看 3 个: 中间插入/删掉一两块时后面的仍能对上)
      for (var j = fi; j < free.length && j < fi + 3; j++) { var f = free[j]; if (f && f.nodeName === nn.nodeName && !mkey(f)) { m = f; free[j] = null; fi = j + 1; break; } }
    }
    var ref = a.childNodes[i] || null;
    if (m) { if (m !== ref) a.insertBefore(m, ref); morphNode(m, nn); }
    else a.insertBefore(nn, ref);
  }
  while (a.childNodes.length > news.length) a.removeChild(a.lastChild);
}
/* 用 html 更新 el 的内容(el 本身保留) */
function morph(el, html) {
  if (!el) return el;
  var t = document.createElement('div'); t.innerHTML = html; morphKids(el, t); return el;
}
/* 用 html(单个根元素)更新 el 本身; 标签不同则整个替换。返回更新后的元素 */
function morphOuter(el, html) {
  var t = document.createElement('div'); t.innerHTML = html;
  var nu = t.firstElementChild; if (!nu) return el;
  if (nu.nodeName !== el.nodeName) { el.replaceWith(nu); return nu; }
  return morphNode(el, nu);
}

/* ═════════════════════ 传输层 ═════════════════════
 * KSU 模式: window.ksu.exec(cmd, cbName) 回调 (exitCode, stdout, stderr)。
 *   - curl 追加 -w 取 HTTP 状态码: 旧版没取, 401/500 的错误体被当成功数据静默吞掉。
 *   - 本地密钥读失败不永久缓存(旧版第一次失败就一直不带密钥 → 全部 401)。
 * 浏览器模式: 同源 fetch + cookie; 401 → /pair 配对页。 */
var API_BASE = 'http://127.0.0.1:8444';
var HNC_DIR = '/data/local/hnc';
var MOD_DIR = '/data/adb/modules/hotspot_network_control';
var KSU = typeof window.ksu !== 'undefined' && window.ksu && typeof window.ksu.exec === 'function';
var rawCb = 0;
function execRaw(cmd, timeoutMs) {
  return new Promise(function (resolve) {
    if (!KSU) { resolve({ code: -1, out: '', err: 'no ksu bridge' }); return; }
    var name = '__hnc6_cb_' + (++rawCb), done = false;
    var tm = setTimeout(function () { if (done) return; done = true; try { delete window[name]; } catch (_) {} resolve({ code: -1, out: '', err: 'timeout' }); }, timeoutMs || 30000);
    window[name] = function (code, out, err) {
      if (done) return; done = true; clearTimeout(tm);
      try { delete window[name]; } catch (_) {}
      resolve({ code: parseInt(String(code), 10), out: typeof out === 'string' ? out : String(out || ''), err: typeof err === 'string' ? err : String(err || '') });
    };
    try { window.ksu.exec(cmd, name); }
    catch (e) { if (!done) { done = true; clearTimeout(tm); try { delete window[name]; } catch (_) {} resolve({ code: -1, out: '', err: String(e) }); } }
  });
}
function sq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
var secret = '', secretAt = 0, secretP = null;
function loadSecret(force) {
  if (!KSU) return Promise.resolve('');
  if (secret && !force) return Promise.resolve(secret);
  if (secretP) return secretP;
  if (!force && secretAt && Date.now() - secretAt < 3000) return Promise.resolve(secret);
  secretP = execRaw('cat ' + HNC_DIR + '/run/local_admin.secret 2>/dev/null', 1500).then(function (r) {
    var s = (r.out || '').trim(); secretAt = Date.now(); secretP = null;
    if (r.code === 0 && /^[0-9a-fA-F]{64}$/.test(s)) secret = s;
    return secret;
  });
  return secretP;
}
function HttpError(msg, status, body) { var e = new Error(msg); e.status = status; e.body = body; return e; }
function parseJSON(txt, status) {
  if (!txt) return {};
  try { return JSON.parse(txt); }
  catch (_) { throw HttpError(status >= 400 ? 'HTTP ' + status + ' · ' + String(txt).slice(0, 60) : '返回的不是 JSON: ' + String(txt).slice(0, 60), status); }
}
function curlCmd(method, path, body, sec, maxTime) {
  var c = 'curl -sS --connect-timeout 1 --max-time ' + (maxTime || 6) + " -w '\\n__HNC_HTTP__%{http_code}'";
  if (method === 'POST') c += ' -X POST -H ' + sq('Content-Type: application/json') + ' -H ' + sq('X-HNC-CSRF: 1') + ' --data ' + sq(JSON.stringify(body || {}));
  if (sec) c += ' -H ' + sq('X-HNC-Local-Admin: ' + sec);
  return c + ' -H ' + sq('Cache-Control: no-cache') + ' ' + sq(API_BASE + path);
}
function bridgeReq(method, path, body, opt, retried) {
  opt = opt || {};
  return loadSecret().then(function (sec) {
    return execRaw(curlCmd(method, path, body, sec, opt.maxTime), (opt.timeout || 9000) + 2000);
  }).then(function (r) {
    if (r.code !== 0) {
      var raw = r.err || '';
      if (r.code === 7 || /failed to connect|connection refused|port \d+ after/i.test(raw)) throw HttpError('后端未就绪 · hnc_httpd 没有在运行', 0);
      if (r.code === 28 || /timed out|timeout/i.test(raw)) throw HttpError('后端无响应 · 超时', 0);
      throw HttpError('桥接失败 exit=' + r.code + (raw ? ' ' + raw.slice(0, 80) : ''), 0);
    }
    var out = r.out, k = out.lastIndexOf('\n__HNC_HTTP__'), status = 200;
    if (k >= 0) { status = parseInt(out.slice(k + 13), 10) || 0; out = out.slice(0, k); }
    if (status === 401 && !retried) { secret = ''; return loadSecret(true).then(function () { return bridgeReq(method, path, body, opt, true); }); }
    var obj = parseJSON(out, status);
    if (status >= 400) throw HttpError(status === 401 ? '本地密钥校验失败 (401) · 可在设置里重启服务' : (obj.error || ('HTTP ' + status)) + (obj.detail ? ' · ' + obj.detail : ''), status, obj);
    return obj;
  });
}
function fetchReq(method, path, body, opt) {
  opt = opt || {};
  var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
  var tm = setTimeout(function () { try { ctrl && ctrl.abort(); } catch (_) {} }, opt.timeout || 9000);
  var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: { 'Cache-Control': 'no-cache' }, signal: ctrl ? ctrl.signal : undefined };
  if (method === 'POST') { init.headers['Content-Type'] = 'application/json'; init.headers['X-HNC-CSRF'] = '1'; init.body = JSON.stringify(body || {}); }
  return fetch(path, init).then(function (resp) {
    clearTimeout(tm);
    return resp.text().then(function (txt) {
      if (resp.status === 401) {
        if (location.pathname.indexOf('/pair') !== 0) setTimeout(function () { location.href = '/pair'; }, 600);
        throw HttpError('需要先配对这台设备', 401);
      }
      var obj = parseJSON(txt, resp.status);
      if (!resp.ok) throw HttpError((obj.error || ('HTTP ' + resp.status)) + (obj.detail ? ' · ' + obj.detail : ''), resp.status, obj);
      return obj;
    });
  }, function (e) { clearTimeout(tm); throw HttpError(e && e.name === 'AbortError' ? '请求超时' : '网络错误 · ' + (e && e.message || e), 0); });
}
function req(method, path, body, opt) { return KSU ? bridgeReq(method, path, body, opt) : fetchReq(method, path, body, opt); }
function qs(params) {
  if (!params) return '';
  var q = Object.keys(params).filter(function (k) { return params[k] !== undefined && params[k] !== null && params[k] !== ''; })
    .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); }).join('&');
  return q ? '?' + q : '';
}
var api = {
  get: function (path, params, opt) {
    return req('GET', path + qs(params), null, opt).then(function (o) {
      if (o && o.ok === false) { var e = HttpError(o.error || '接口返回失败', 200, o); e.detail = o.detail; throw e; }
      return o || {};
    });
  },
  getSafe: function (path, params, fallback) { return api.get(path, params).catch(function () { return fallback; }); },
  post: function (path, body, opt) { return req('POST', path, body, opt); },
  /* 写操作: 全局串行(与旧版一致, 避免 tc/json 竞态); params 的值必须全是字符串(后端 map[string]string) */
  _q: Promise.resolve(),
  action: function (name, params, opt) {
    var p = {}; params = params || {};
    Object.keys(params).forEach(function (k) { if (params[k] !== undefined && params[k] !== null) p[k] = String(params[k]); });
    var run = function () {
      return req('POST', '/api/action', { action: name, params: p }, Object.assign({ timeout: 12000, maxTime: 10 }, opt)).then(function (o) {
        if (!o || !o.ok) { var e = HttpError((o && o.error) || '操作失败', 200, o); e.detail = o && o.detail; throw e; }
        return o;
      });
    };
    var pr = api._q.catch(function () {}).then(run);
    api._q = pr.catch(function () {});
    return pr;
  }
};
function errText(e) { return (e && e.message) ? e.message + (e.detail && e.message.indexOf(e.detail) < 0 ? ' · ' + String(e.detail).slice(0, 120) : '') : String(e || '未知错误'); }
function detailJSON(r) { try { return typeof r.detail === 'string' ? JSON.parse(r.detail) : (r.detail || {}); } catch (_) { return {}; } }
/* 只在 KSU WebView 里能用的本机 shell(诊断/兜底类), 浏览器模式下这些入口隐藏 */
function shell(cmd, timeoutMs) {
  return execRaw(cmd, timeoutMs || 15000).then(function (r) {
    if (r.code !== 0) throw new Error((r.err || r.out || 'exit ' + r.code).slice(0, 160));
    return r.out;
  });
}

/* ═════════════════════ 交互组件: toast / 弹层 / 确认 ═════════════════════ */
var toastT;
function toast(m, kind) {
  var t = $('#toast'), ic = $('#toast-ic');
  $('#toast-t').textContent = m;
  ic.style.color = kind === 'err' ? 'var(--red)' : kind === 'warn' ? 'var(--orange)' : 'var(--green)';
  ic.innerHTML = kind === 'err' ? I.x : kind === 'warn' ? I.warn : I.check;
  t.classList.remove('show'); void t.offsetWidth; t.classList.add('show');
  clearTimeout(toastT); toastT = setTimeout(function () { t.classList.remove('show'); }, kind === 'err' ? 3600 : 2200);
}

/* ═════════════════════ 状态 ═════════════════════ */
var DEFAULT_TEMPLATES = [
  { name: '视频会议', down: 5, up: 2, delay: 0, jitter: 0, loss: 0 },
  { name: '轻度浏览', down: 2, up: 1, delay: 0, jitter: 0, loss: 0 },
  { name: '游戏限流', down: 10, up: 10, delay: 20, jitter: 5, loss: 0 },
  { name: '弱网测试', down: 1, up: 0.5, delay: 200, jitter: 50, loss: 3 },
  { name: '解除全部', down: 0, up: 0, delay: 0, jitter: 0, loss: 0 }
];
var S = {
  page: 'devices', connected: false, booted: false, bootErr: '',
  live: null, lastOk: 0, sig: '', hotspot: { active: null, iface: '', ip: '' },
  devices: [], devLoaded: false, cfg: {}, caps: {}, capsLoaded: false,
  offload: { active: false, detail: '' }, alerts: { unread: 0, list: [] },
  appLimits: [], templates: [], onlineMin: {}, spark: [],
  filter: LS.get('hnc_device_filter', 'recent'), q: '', batch: false, picked: {}, open: {}, sel: null, busy: {},
  refreshMode: LS.get('hnc.refresh-mode', 'balanced'),
  statsRange: 'today', aseg: 'stats', appsSub: 'my',
  theme: LS.get('hnc6.theme', 'auto'), motion: LS.get('hnc6.motion', '1') !== '0', style: ['apple', 'liquid'].indexOf(LS.get('hnc6.style', 'default')) >= 0 ? LS.get('hnc6.style', 'default') : 'default',
  dpi: null, probe: null, dpiHist: {}, dpiDays: 1, dpiFilter: 'all', dpiSpark: { packets: [], dns_events: [], tls_events: [], kernel_drops: [] },
  self: null, selfCfg: {}, logFile: 'combined'
};
if (['recent', 'online_only', 'all', 'offline_rules'].indexOf(S.filter) < 0) S.filter = 'recent';
/* 折叠状态记在本机(设置分组、「高级」「诊断」、设备卡里的「更多控制」和各小节); 设备卡本身展开与否、自检分组不记 */
var FOLD_LS = 'hnc6.folds';
function foldRemembered(k) { return !!k && !isMac(k) && !/^sc-/.test(k); }
(function () { try { var o = JSON.parse(LS.get(FOLD_LS, '{}')) || {}; Object.keys(o).forEach(function (k) { if (o[k] && foldRemembered(k)) S.open[k] = true; }); } catch (_) {} })();
function saveFolds(k) {
  if (!foldRemembered(k)) return;
  try {
    var o = JSON.parse(LS.get(FOLD_LS, '{}')) || {};
    if (S.open[k]) o[k] = 1; else delete o[k];
    var ks = Object.keys(o); if (ks.length > 300) ks.slice(0, ks.length - 300).forEach(function (x) { delete o[x]; });
    LS.set(FOLD_LS, JSON.stringify(o));
  } catch (_) {}
}
if (['realtime', 'balanced', 'powersave'].indexOf(S.refreshMode) < 0) S.refreshMode = 'balanced';

/* ═════════════════════ 能力 ═════════════════════ */
function cap(k) { return S.caps ? S.caps[k] : undefined; }
function htbOk() { return cap('tc_htb') !== false; }
function netemOk() { return htbOk() && cap('tc_netem') !== false; }
function upOk() { return htbOk() && cap('uplink_supported') !== false; }
function qosFallback() { return cap('qos_fallback_required') === true || /root_htb|htb_root/.test(String(cap('downlink_mode') || '')) || S.cfg.qos_fallback === true; }
var QD_T = { cake: 'CAKE', fq_codel: 'fq_codel', fq: 'fq', sfq: 'sfq', pfifo: 'pfifo' };
function qdChosen() { return S.qcaps && S.qcaps.chosen ? String(S.qcaps.chosen) : ''; }
function sqmLabel() { var c = qdChosen(); if (c) return QD_T[c] || c; return cap('tc_cake') === true ? 'CAKE' : cap('tc_fq_codel') === true ? 'fq_codel' : 'sfq'; }
/* 低延迟开关实际用哪个队列(qdisc_caps.sh 实测; 没有实测结果时按旧能力位猜) */
function qdiscNote() {
  var c = qdChosen();
  if (!c) return S.qcaps ? '内核没有测到可用的低延迟队列，效果有限' : '使用 ' + sqmLabel();
  if (c === 'cake' || c === 'fq_codel') return '使用 ' + QD_T[c];
  if (c === 'pfifo') return '内核无 cake / fq_codel / sfq，只有 pfifo，效果有限';
  return '内核无 cake/fq_codel，使用 ' + (QD_T[c] || c);
}
var IFM_T = { override: '手动指定', tethering: '系统共享服务', tetherctrl: 'tetherctrl 转发表', wifi_softap: 'WiFi 热点服务', scan: '接口扫描（兜底）', none: '未识别' };
function offloadRisk() { return (S.offload.detail === 'ACTIVE' || S.offload.detail === 'CAPABLE') && !(S.offload.guard && S.offload.guard.fallback_active); }

/* ═════════════════════ 数据加载 ═════════════════════ */
var TYPE_T = { phone: '手机', tablet: '平板', pc: '电脑', tv: '电视 / 投屏', iot: '智能设备', console: '游戏机', watch: '手表' };
var TYPE_I = { phone: '📱', tablet: '📲', pc: '💻', tv: '📺', iot: '💡', console: '🎮', watch: '⌚' };
/* dpid 被动识别(DHCP / mDNS / 域名指纹) → 「小米 · Android 14 · 手机」 */
function identText(id, max) {
  if (!id) return '';
  var a = [], os = id.os ? id.os + (id.os_ver ? ' ' + id.os_ver : '') : '';
  if (id.brand) a.push(id.brand);
  if (id.model && String(id.model).toLowerCase() !== String(id.brand || '').toLowerCase()) a.push(id.model);
  if (os && (!id.brand || String(os).indexOf(id.brand) < 0)) a.push(os);
  if (TYPE_T[id.type] && a.length < 3) a.push(TYPE_T[id.type]);
  return (max ? a.slice(0, max) : a).join(' · ');
}
function devIcon(d) {
  if (d.ident && TYPE_I[d.ident.type] && num(d.ident.confidence) >= 40) return TYPE_I[d.ident.type];
  var s = (d.name + ' ' + (d.vendor || '') + ' ' + (d.idText || '')).toLowerCase();
  if (/watch|band|手环|手表/.test(s)) return '⌚';
  if (/ipad|tablet|pad|平板|tab/.test(s)) return '📲';
  if (/tv|电视|box|盒子|projector|投影/.test(s)) return '📺';
  if (/switch|nintendo|playstation|ps[45]|xbox|steam/.test(s)) return '🎮';
  if (/mac|book|laptop|thinkpad|surface|desktop|pc|windows|dell|lenovo|asus|acer|hp-|legion/.test(s)) return '💻';
  if (/phone|iphone|android|xiaomi|redmi|oppo|vivo|huawei|honor|realme|oneplus|samsung|meizu|nubia|iqoo|pixel|mi-|手机/.test(s)) return '📱';
  return '📶';
}
/* v5.30 T1b: 垃圾主机名("null" 等)当作没有名字(后端已挡, 这里防御旧后端)。
 * 与 hotspotd / Go(hnc.io/dpid/hostname)同一张表(test/unit/test_v530_junk_table_sync.sh 核对)。 */
function isJunkName(s) {
  s = String(s == null ? '' : s).trim();
  if (!s || /^[0-9]+$/.test(s)) return true;
  return ['null', '(null)', 'nil', 'none', '(none)', 'undefined', 'unknown', 'localhost', 'localhost.localdomain', '*', '-'].indexOf(s.toLowerCase()) >= 0;
}
/* v5.30 T4: 按应用分优先级(rules.json devices[mac].app_qos; 旧后端没有这个字段 → 关) */
function appQosOf(d) { return d.app_qos === true || d.app_qos === 'true'; }
/* 设备显示名: 主机名 > name > 厂商 > MAC; 手动命名原样用, 其余跳过垃圾名 */
function devName(d, mac) {
  var hn = d.hostname_src === 'manual' ? d.hostname : (isJunkName(d.hostname) ? '' : d.hostname);
  return hn || (isJunkName(d.name) ? '' : d.name) || d.vendor || mac;
}
function mapDevice(d) {
  var mac = String(d.mac || '').toLowerCase();
  var active = S.hotspot.active !== false;
  var name = devName(d, mac);
  var o = {
    mac: mac, ip: d.ip || '', name: name, manual: d.hostname_src === 'manual', vendor: d.vendor || '', lastSeen: num(d.last_seen),
    blocked: d.status === 'blocked', online: active && d.online === true,
    down: num(d.down_mbps), up: num(d.up_mbps), limitOn: d.limit_enabled !== false && (num(d.down_mbps) > 0 || num(d.up_mbps) > 0),
    delay: num(d.delay_ms), jitter: num(d.jitter_ms), loss: num(d.loss_pct),
    sqm: d.sqm_enabled === true || d.sqm_enabled === 'true', wl: d.whitelist === true || d.whitelist === 'true', appQos: appQosOf(d),
    rx: 0, tx: 0, apps: Array.isArray(d.dpi_apps) ? d.dpi_apps : [], live: Array.isArray(d.live_apps) ? d.live_apps : [], call: d.live_call && d.live_call.label ? d.live_call : null,
    limitMode: d.limit_apply_mode || '', delayMode: d.delay_apply_mode || '', applyError: d.apply_error || '',
    mark: d.mark_id, iface: d.iface || '',
    ident: d.ident && typeof d.ident === 'object' ? d.ident : null, hnSrc: d.hostname_src || '',
    // 模拟设备 / 配额 / 分时段 / 实际生效 / 应用时长 / 类别封锁(旧后端没有这些字段时全部为空)
    sim: d.sim === true, quota: d.quota && typeof d.quota === 'object' ? d.quota : null,
    sched: d.schedule && typeof d.schedule === 'object' && Array.isArray(d.schedule.windows) ? d.schedule : null,
    eff: d.effective && typeof d.effective === 'object' ? d.effective : null,
    atl: Array.isArray(d.app_time_limits) ? d.app_time_limits : [], cblocks: Array.isArray(d.category_blocks) ? d.category_blocks : [],
    // 随机 MAC / 疑似同一设备建议 / 已被合并 / VPN·代理检测(旧后端没有这些字段 → 随机 MAC 按首字节本地管理位推断)
    rmac: typeof d.randomized_mac === 'boolean' ? d.randomized_mac : d.sim !== true && isRandomMac(mac),
    merge: d.merge_suggestion && typeof d.merge_suggestion === 'object' && isMac(d.merge_suggestion.old_mac) ? d.merge_suggestion : null,
    mergedInto: isMac(d.merged_into) ? String(d.merged_into).toLowerCase() : '',
    vpn: d.vpn && (d.vpn.level === 'likely' || d.vpn.level === 'certain') ? d.vpn : null,
    // DPI v2: 前台应用推断 / 此刻的流量形态(旧后端没有 → null)
    fg: d.fg && typeof d.fg === 'object' && d.fg.state ? d.fg : null,
    ttype: d.traffic_type && typeof d.traffic_type === 'object' && d.traffic_type.type ? d.traffic_type : null
  };
  o.idText = identText(o.ident); o.idShort = identText(o.ident, 2);
  if (o.online) { o.rx = num(d.rx_bps); o.tx = num(d.tx_bps); }
  o.hasDelay = o.delay > 0 || o.jitter > 0 || o.loss > 0;
  o.hasRule = o.limitOn || o.hasDelay || o.blocked || o.sqm || o.wl || !!o.quota || !!o.sched;
  o.icon = devIcon(o);
  return o;
}
function devBy(mac) { mac = String(mac || '').toLowerCase(); for (var i = 0; i < S.devices.length; i++) if (S.devices[i].mac === mac) return S.devices[i]; return null; }
function applyLive(l) {
  S.live = l; S.lastOk = Date.now(); S.connected = true;
  var act = l.hotspot_active; S.hotspot.active = typeof act === 'boolean' ? act : S.hotspot.active;
  S.hotspot.iface = l.hotspot_iface || l.iface || S.hotspot.iface; S.hotspot.ip = l.hotspot_ip || S.hotspot.ip;
  S.spark.push(num(l.rx_bps)); if (S.spark.length > 30) S.spark.shift();
}
function loadLive() { return api.get('/api/live', null, { timeout: 7000 }).then(function (l) { applyLive(l); return l; }); }
function loadDevices() { return api.get('/api/devices', null, { timeout: 8000 }).then(applyDevices); }
function applyDevices(r) {
  {
    if (typeof r.hotspot_active === 'boolean') S.hotspot.active = r.hotspot_active;
    if (r.hotspot_iface) S.hotspot.iface = r.hotspot_iface;
    if (r.hotspot_ip) S.hotspot.ip = r.hotspot_ip;
    S.devices = (r.devices || []).map(mapDevice).sort(function (a, b) {
      // 稳定排序: 在线在前、封锁在后、再按名字 —— 不按实时速率, 否则每次轮询卡片都会跳来跳去
      return (b.online - a.online) || (a.blocked - b.blocked) || (a.online ? 0 : b.lastSeen - a.lastSeen) || a.name.localeCompare(b.name, 'zh-CN') || a.mac.localeCompare(b.mac);
    });
    S.devLoaded = true;
    // 后端有没有限速策略引擎(配额 / 分时段) —— 旧后端的设备行里没有 effective 字段, 此时不显示这两块
    S.polSupport = (r.devices || []).some(function (x) { return x && typeof x.effective === 'object' && x.effective; });
    if (r.devices_sig) S.sig = r.devices_sig;
    return S.devices;
  }
}
/* 一次请求同时拿汇总和设备列表(本机桥接每个请求都要拉起一个 curl 进程) */
function loadLiveAndDevices() {
  return api.get('/api/live', { devices: 1 }, { timeout: 8000 }).then(function (l) {
    applyLive(l);
    if (Array.isArray(l.devices)) applyDevices(l); else return loadDevices().then(function () { return l; });
    return l;
  });
}
function loadConfig() { return api.get('/api/config').then(function (c) { S.cfg = c || {}; return S.cfg; }); }
function loadCaps() {
  return api.get('/api/capabilities').then(function (r) {
    S.caps = r.capabilities || (r.available === false ? {} : r) || {}; S.capsLoaded = true;
    S.qcaps = r.qdisc_caps && typeof r.qdisc_caps === 'object' ? r.qdisc_caps : null;   // 低延迟 qdisc 兜底链实测结果
    return S.caps;
  }).catch(function () { S.caps = {}; S.capsLoaded = true; return {}; });
}
function loadOffload() { return api.getSafe('/api/offload_status', null, null).then(function (o) { if (o) S.offload = { active: o.active === true, detail: o.detail || '', guard: o.offload_guard || null }; renderOffloadBanner(); }); }
function loadAlerts() {
  return api.getSafe('/api/alerts', null, null).then(function (a) {
    if (!a) return; S.alerts = { unread: num(a.unread), list: a.alerts || [] };
    var b = $('#bell-n'); b.hidden = !S.alerts.unread; b.textContent = S.alerts.unread > 99 ? '99+' : S.alerts.unread;
    if ($('#sheet').dataset.kind === 'alerts') renderAlertsSheet(true);
  });
}
function loadAppLimits() {
  return api.getSafe('/api/app_limits', null, { items: [] }).then(function (r) {
    S.appLimits = r.items || [];
    // 逃生口「包含共享 CDN IP」; 旧后端没有这个字段 → 设置里不显示开关
    S.appLimitSharedKnown = typeof r.include_shared_ips === 'boolean'; S.appLimitShared = r.include_shared_ips === true;
  });
}
/* v5.30 T1a: 在线时长按分钟(online_min); 旧后端只有 hours(一行算 1 小时)→ 换算成分钟兜底 */
function onlineMinMap(r) {
  if (!r) return null;
  if (r.online_min && typeof r.online_min === 'object') return r.online_min;
  if (!r.hours || typeof r.hours !== 'object') return null;
  var out = {};
  Object.keys(r.hours).forEach(function (mac) { var d = r.hours[mac] || {}; out[mac] = {}; Object.keys(d).forEach(function (k) { out[mac][k] = num(d[k]) * 60; }); });
  return out;
}
function loadOnlineHours() { return api.getSafe('/api/online_hours', { days: 7 }, null).then(function (r) { var m = onlineMinMap(r); if (m) S.onlineMin = m; paintOnlineHours(); }); }
function loadTemplates() {
  var local = []; try { local = JSON.parse(LS.get('hnc.templates', '[]')) || []; } catch (_) {}
  return api.getSafe('/api/templates', null, {}).then(function (r) {
    var list = [], seen = {};
    Object.keys(r || {}).forEach(function (n) {
      var t = r[n] || {}; seen[n] = 1;
      list.push({ name: n, down: num(t.down_mbps), up: num(t.up_mbps), delay: num(t.delay_ms), jitter: num(t.jitter_ms), loss: num(t.loss_pct) });
    });
    local.forEach(function (t) { if (t && t.name && !seen[t.name]) { seen[t.name] = 1; list.push(t); } });
    S.templates = list.length ? list : DEFAULT_TEMPLATES.slice();
  });
}
/* 每台设备本自然月流量(与月度配额告警同源); 开了配额时显示占比 */
S.usage = null;
function loadUsage() { return api.getSafe('/api/usage_month', null, null).then(function (r) { if (r && r.devices) S.usage = r; paintUsage(); }); }
function usageOf(mac) { var u = S.usage && S.usage.devices && S.usage.devices[mac]; return u ? num(u.rx) + num(u.tx) : 0; }
function paintUsage() {
  var q = S.alertCfg && S.alertCfg.monthly_quota, lim = q && q.enabled ? num(q.limit_bytes) : 0;
  S.devices.forEach(function (d) {
    var el = document.getElementById('mu-' + d.mac.replace(/:/g, '')); if (!el) return;
    var v = usageOf(d.mac);
    el.textContent = v ? ' · 本月 ' + bytes(v) + (lim ? '（配额 ' + Math.round(v / lim * 100) + '%）' : '') : '';
    var od = S.usage && num(S.usage.oldest_data), since = S.usage && num(S.usage.since);
    el.title = od && od - since > 2 * 86400 ? '本月数据从 ' + new Date(od * 1000).toLocaleDateString() + ' 起（更早的已被清理）' : '';
    el.style.color = lim && v >= lim ? 'var(--badge-red)' : lim && v >= lim * num(q.warn_at_pct, 80) / 100 ? 'var(--badge-warn)' : '';
  });
}
function onlineMinOf(mac) { var h = S.onlineMin[mac] || S.onlineMin[mac.toUpperCase()]; if (!h) return 0; var t = today(); return num(h[t.replace(/-/g, '')] != null ? h[t.replace(/-/g, '')] : h[t]); }
/* < 60 分钟显示「N 分钟」, ≥ 60 显示「N.N 小时」, 0 不显示 */
function onlineText(min) {
  min = Math.round(num(min)); if (min <= 0) return '';
  return ' · 今日在线 ' + (min < 60 ? min + ' 分钟' : trim0((min / 60).toFixed(1)) + ' 小时');
}
function paintOnlineHours() {
  paintUsage();
  S.devices.forEach(function (d) {
    var el = document.getElementById('oh-' + d.mac.replace(/:/g, '')); if (!el) return;
    el.textContent = onlineText(onlineMinOf(d.mac));
  });
}

