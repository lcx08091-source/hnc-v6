/* HNC WebUI · core.js —— 基础工具、图标、传输层(KSU 桥接 / 同源 fetch)、toast、全局状态 S、能力、数据加载

  脚本组织: 经典脚本(不是 ES module —— 部分 KSU WebView 用 file:// 加载, module 脚本会被拒),
  由 index.html 按 hyalite → core → fx → devices → apps → stats → settings → sheets → main 的顺序
  同步加载。各文件顶层的 var / function 共处同一个全局作用域, 与拆分前的单个 IIFE 等价。
  约束: 文件里"加载时立即执行"的代码(含它注册的回调最终会调用的函数)只能依赖本文件及之前文件
  定义的名字 —— 远程加载时两个 <script> 之间事件循环可能先跑 rAF/事件回调; 启动逻辑全在 main.js。 */
'use strict';

/* ═════════════════════ 老内核 WebView 兼容补丁与基础工具 ═════════════════════ */
if (!String.prototype.padStart) {
  String.prototype.padStart = function (len, fill) {
    var s = String(this), n = len >> 0, p = String(fill === undefined ? ' ' : fill);
    if (s.length >= n || !p) return s;
    n -= s.length;
    while (p.length < n) p += p;
    return p.slice(0, n) + s;
  };
}
if (typeof Element !== 'undefined') {
  if (!Element.prototype.matches) {
    Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector || function () { return false; };
  }
  if (!Element.prototype.closest) {
    Element.prototype.closest = function (s) {
      var el = this;
      while (el && el.nodeType === 1) { if (el.matches(s)) return el; el = el.parentElement || el.parentNode; }
      return null;
    };
  }
  if (!Element.prototype.replaceWith) {
    Element.prototype.replaceWith = function (nu) {
      if (this.parentNode && nu) this.parentNode.replaceChild(nu, this);
    };
  }
  if (!Element.prototype.remove) {
    Element.prototype.remove = function () {
      if (this.parentNode) this.parentNode.removeChild(this);
    };
  }
}
function evEl(e) { var t = e && e.target; return t && t.nodeType === 3 ? t.parentNode : t; }
function isUsbTetherIface(s) { return /(^|_)(rndis|ncm|usb)\d*$/i.test(String(s || '').trim()); }

var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
function sum(a, f) { return a.reduce(function (s, x) { return s + (f ? f(x) : x); }, 0); }
function num(v, d) { var n = parseFloat(v); return isFinite(n) ? n : (d || 0); }
function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
function trim0(s) { return String(s).replace(/(\.\d*?[1-9])0+$/, '$1').replace(/\.0+$/, ''); }
function pad2(n) { return String(n).padStart(2, '0'); }
var _memLS = { 'hnc6.style': 'liquid', 'hnc6.theme': 'light', 'hnc6.glass_tint': '38' };
if (typeof window !== 'undefined' && window.__HNC_BOOT_PREFS__ && typeof window.__HNC_BOOT_PREFS__ === 'object') {
  Object.keys(window.__HNC_BOOT_PREFS__).forEach(function (k) {
    if (window.__HNC_BOOT_PREFS__[k] != null) _memLS[k] = String(window.__HNC_BOOT_PREFS__[k]);
  });
}
var LS = {
  get: function (k, d) {
    try { var v = localStorage.getItem(k); if (v != null) return v; } catch (_) { if (Object.prototype.hasOwnProperty.call(_memLS, k)) return _memLS[k]; }
    return (typeof window !== 'undefined' && (window.__HNC_MOCK_META || window.__HNC_BOOT_PREFS__) && Object.prototype.hasOwnProperty.call(_memLS, k)) ? _memLS[k] : d;
  },
  set: function (k, v) { _memLS[k] = String(v); try { localStorage.setItem(k, v); } catch (_) {} },
  del: function (k) { delete _memLS[k]; try { localStorage.removeItem(k); } catch (_) {} }
};
function normLgVariant(v) {
  return (v === 'prism' || v === 'dew' || v === 'pure') ? v : 'pure';
}
var _memSS = {};
var SS = {
  get: function (k) { try { var v = sessionStorage.getItem(k); if (v != null) return v; } catch (_) {} return _memSS[k] || null; },
  set: function (k, v) { _memSS[k] = String(v); try { sessionStorage.setItem(k, v); } catch (_) {} }
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
function cleanVer(v, fb) {
  var s = String(v == null ? '' : v).trim();
  if (!s || /^(dev|0|unknown|none|null|undefined|-)$/i.test(s)) return fb == null ? '' : fb;
  return s;
}

/* ═════════════════════ v5.38.0 双层光学矢量图标系统 (24×24 · 1.85px · 零位图) ═════════════════════ */
var I = {
  dev:'<rect x="2.5" y="3.5" width="19" height="13" rx="2.6" fill="currentColor" fill-opacity=".16"/><rect x="2.5" y="3.5" width="19" height="13" rx="2.6"/><path d="M8.5 20.5h7"/><path d="M12 16.5v4"/>',
  apps:'<rect x="3.2" y="3.2" width="7.2" height="7.2" rx="2.1" fill="currentColor" fill-opacity=".18"/><rect x="13.6" y="3.2" width="7.2" height="7.2" rx="2.1"/><rect x="3.2" y="13.6" width="7.2" height="7.2" rx="2.1"/><rect x="13.6" y="13.6" width="7.2" height="7.2" rx="2.1" fill="currentColor" fill-opacity=".18"/><rect x="3.2" y="3.2" width="7.2" height="7.2" rx="2.1"/><rect x="13.6" y="13.6" width="7.2" height="7.2" rx="2.1"/>',
  stats:'<rect x="4" y="12.5" width="3.8" height="7.5" rx="1.2" fill="currentColor" fill-opacity=".18"/><rect x="10.1" y="5.5" width="3.8" height="14.5" rx="1.2" fill="currentColor" fill-opacity=".22"/><rect x="16.2" y="9.5" width="3.8" height="10.5" rx="1.2" fill="currentColor" fill-opacity=".18"/><rect x="4" y="12.5" width="3.8" height="7.5" rx="1.2"/><rect x="10.1" y="5.5" width="3.8" height="14.5" rx="1.2"/><rect x="16.2" y="9.5" width="3.8" height="10.5" rx="1.2"/>',
  gear:'<circle cx="12" cy="12" r="3.2" fill="currentColor" fill-opacity=".2"/><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  chev:'<path d="m6.5 9.5 5.5 5.5 5.5-5.5"/>', right:'<path d="m9.5 6.5 5.5 5.5-5.5 5.5"/>',
  search:'<circle cx="11" cy="11" r="7.5" fill="currentColor" fill-opacity=".14"/><circle cx="11" cy="11" r="7.5"/><path d="m20.5 20.5-4.2-4.2"/>',
  bolt:'<polygon points="13.2 2.4 4.2 13.6 11.8 13.6 10.8 21.6 19.8 10.4 12.2 10.4 13.2 2.4" fill="currentColor" fill-opacity=".18"/><polygon points="13.2 2.4 4.2 13.6 11.8 13.6 10.8 21.6 19.8 10.4 12.2 10.4 13.2 2.4"/>',
  home:'<path d="M3.5 9.5 12 3l8.5 6.5V20a1.8 1.8 0 0 1-1.8 1.8H5.3A1.8 1.8 0 0 1 3.5 20Z" fill="currentColor" fill-opacity=".14"/><path d="M3.5 9.5 12 3l8.5 6.5V20a1.8 1.8 0 0 1-1.8 1.8H5.3A1.8 1.8 0 0 1 3.5 20Z"/><path d="M9.5 21.8V13h5v8.8"/>',
  refresh:'<path d="M21 4.5v5.5h-5.5"/><path d="M3 19.5V14h5.5"/><path d="M4.2 9.2A8.5 8.5 0 0 1 18.6 6L21 10M3 14l2.4 4A8.5 8.5 0 0 0 19.8 14.8"/>',
  trash:'<path d="M4 6.5h16"/><path d="M18.2 6.5 17.3 19.6a2 2 0 0 1-2 1.9H8.7a2 2 0 0 1-2-1.9L5.8 6.5" fill="currentColor" fill-opacity=".14"/><path d="M18.2 6.5 17.3 19.6a2 2 0 0 1-2 1.9H8.7a2 2 0 0 1-2-1.9L5.8 6.5"/><path d="M9.2 6.5V4.2a1.2 1.2 0 0 1 1.2-1.2h3.2a1.2 1.2 0 0 1 1.2 1.2v2.3"/><path d="M10 11v6M14 11v6"/>',
  power:'<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".14"/><path d="M12 3v8"/><path d="M17.6 6.4a8 8 0 1 1-11.2 0"/>',
  check:'<path d="m20 6.5-10.5 11L4.5 12.5"/>',
  box:'<rect x="3.5" y="3.5" width="17" height="17" rx="3.2" fill="currentColor" fill-opacity=".14"/><rect x="3.5" y="3.5" width="17" height="17" rx="3.2"/><path d="m8.2 12.2 2.6 2.6 5.2-5.4"/>',
  star:'<polygon points="12 2.6 14.9 8.5 21.4 9.4 16.7 14 17.8 20.5 12 17.4 6.2 20.5 7.3 14 2.6 9.4 9.1 8.5 12 2.6" fill="currentColor" fill-opacity=".18"/><polygon points="12 2.6 14.9 8.5 21.4 9.4 16.7 14 17.8 20.5 12 17.4 6.2 20.5 7.3 14 2.6 9.4 9.1 8.5 12 2.6"/>',
  edit:'<path d="M12 20h8.5"/><path d="M16.2 3.8a2.1 2.1 0 0 1 3 3L7.5 18.5l-4 1 1-4Z" fill="currentColor" fill-opacity=".16"/><path d="M16.2 3.8a2.1 2.1 0 0 1 3 3L7.5 18.5l-4 1 1-4Z"/>',
  doc:'<path d="M14 2.5H6.5A2 2 0 0 0 4.5 4.5v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8Z" fill="currentColor" fill-opacity=".14"/><path d="M14 2.5H6.5A2 2 0 0 0 4.5 4.5v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8Z"/><path d="M14 2.5V8h5.5"/><path d="M8.5 13h7M8.5 16.8h4.8"/>',
  wifi:'<path d="M5 12.6a10.5 10.5 0 0 1 14 0"/><path d="M1.8 9a15.5 15.5 0 0 1 20.4 0"/><path d="M8.5 16.2a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19.6" r="1.2" fill="currentColor" stroke="none"/>',
  gauge:'<path d="M4.2 18.5a9 9 0 1 1 15.6 0Z" fill="currentColor" fill-opacity=".15"/><path d="M4.2 18.5a9 9 0 1 1 15.6 0"/><path d="m12 13.5 3.8-4"/><circle cx="12" cy="13.5" r="1.4" fill="currentColor" stroke="none"/>',
  shield:'<path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z" fill="currentColor" fill-opacity=".16"/><path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z"/>',
  globe:'<circle cx="12" cy="12" r="9.2" fill="currentColor" fill-opacity=".13"/><circle cx="12" cy="12" r="9.2"/><path d="M2.8 12h18.4"/><path d="M12 2.8a14.2 14.2 0 0 1 3.8 9.2 14.2 14.2 0 0 1-3.8 9.2 14.2 14.2 0 0 1-3.8-9.2A14.2 14.2 0 0 1 12 2.8Z"/>',
  cpu:'<rect x="5" y="5" width="14" height="14" rx="2.4" fill="currentColor" fill-opacity=".15"/><rect x="5" y="5" width="14" height="14" rx="2.4"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M19 9h3M19 15h3M2 9h3M2 15h3"/>',
  heart:'<path d="M21.5 12h-3.8l-2.6 8-5.8-16-2.7 8H2.5"/>',
  tool:'<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.5-3.5a5.8 5.8 0 0 1-7.6 7.6l-6.6 6.6a2.1 2.1 0 0 1-3-3l6.6-6.6a5.8 5.8 0 0 1 7.6-7.6Z" fill="currentColor" fill-opacity=".15"/><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.5-3.5a5.8 5.8 0 0 1-7.6 7.6l-6.6 6.6a2.1 2.1 0 0 1-3-3l6.6-6.6a5.8 5.8 0 0 1 7.6-7.6Z"/>',
  flask:'<path d="M9 2.5h6M10.2 2.5v5.6L4.4 19.6a1.4 1.4 0 0 0 1.25 2h12.7a1.4 1.4 0 0 0 1.25-2L13.8 8.1V2.5" fill="currentColor" fill-opacity=".14"/><path d="M9 2.5h6M10.2 2.5v5.6L4.4 19.6a1.4 1.4 0 0 0 1.25 2h12.7a1.4 1.4 0 0 0 1.25-2L13.8 8.1V2.5"/><path d="M7.2 14.5h9.6"/>',
  info:'<circle cx="12" cy="12" r="9.2" fill="currentColor" fill-opacity=".14"/><circle cx="12" cy="12" r="9.2"/><path d="M12 16v-4.2M12 8.2h.01"/>',
  palette:'<path d="M12 2.8a9.2 9.2 0 0 0 0 18.4c.9 0 1.5-.7 1.5-1.6 0-.4-.16-.8-.42-1.1-.28-.28-.43-.62-.43-1.1a1.6 1.6 0 0 1 1.6-1.6h1.9a5.3 5.3 0 0 0 5.3-5.3C21.45 6.4 17.2 2.8 12 2.8Z" fill="currentColor" fill-opacity=".15"/><path d="M12 2.8a9.2 9.2 0 0 0 0 18.4c.9 0 1.5-.7 1.5-1.6 0-.4-.16-.8-.42-1.1-.28-.28-.43-.62-.43-1.1a1.6 1.6 0 0 1 1.6-1.6h1.9a5.3 5.3 0 0 0 5.3-5.3C21.45 6.4 17.2 2.8 12 2.8Z"/><circle cx="13.5" cy="7" r="1.2" fill="currentColor" stroke="none"/><circle cx="17.2" cy="10.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="8.5" cy="8" r="1.2" fill="currentColor" stroke="none"/><circle cx="6.8" cy="12.5" r="1.2" fill="currentColor" stroke="none"/>',
  rocket:'<path d="M12 15.2 8.8 12a21 21 0 0 1 2-3.9A12.5 12.5 0 0 1 21.5 2.5c0 2.7-.8 7.3-5.8 10.7a21 21 0 0 1-3.7 2Z" fill="currentColor" fill-opacity=".16"/><path d="M12 15.2 8.8 12a21 21 0 0 1 2-3.9A12.5 12.5 0 0 1 21.5 2.5c0 2.7-.8 7.3-5.8 10.7a21 21 0 0 1-3.7 2Z"/><path d="M4.8 16.4c-1.4 1.2-1.9 4.8-1.9 4.8s3.6-.5 4.8-1.9a2.1 2.1 0 0 0-2.9-2.9Z"/>',
  layers:'<polygon points="12 2.8 2.8 7.5 12 12.2 21.2 7.5 12 2.8" fill="currentColor" fill-opacity=".18"/><polygon points="12 2.8 2.8 7.5 12 12.2 21.2 7.5 12 2.8"/><path d="m2.8 12.2 9.2 4.7 9.2-4.7"/><path d="m2.8 16.8 9.2 4.7 9.2-4.7"/>',
  down:'<path d="M20.5 15v3.8a1.8 1.8 0 0 1-1.8 1.8H5.3a1.8 1.8 0 0 1-1.8-1.8V15"/><path d="m7.2 10.2 4.8 4.8 4.8-4.8"/><path d="M12 15V3.2"/>',
  copy:'<rect x="8.8" y="8.8" width="12.2" height="12.2" rx="2.2" fill="currentColor" fill-opacity=".15"/><rect x="8.8" y="8.8" width="12.2" height="12.2" rx="2.2"/><path d="M5.2 15.2H4.2a1.8 1.8 0 0 1-1.8-1.8V4.6a1.8 1.8 0 0 1 1.8-1.8h8.8a1.8 1.8 0 0 1 1.8 1.8v1"/>',
  link:'<path d="M10 13a4.8 4.8 0 0 0 7.2.5l2.8-2.8a4.8 4.8 0 0 0-6.8-6.8l-1.6 1.6"/><path d="M14 11a4.8 4.8 0 0 0-7.2-.5L4 13.3a4.8 4.8 0 0 0 6.8 6.8l1.6-1.6"/>',
  lock:'<rect x="3.8" y="10.8" width="16.4" height="10.4" rx="2.4" fill="currentColor" fill-opacity=".16"/><rect x="3.8" y="10.8" width="16.4" height="10.4" rx="2.4"/><path d="M7.5 10.8V7.2a4.5 4.5 0 0 1 9 0v3.6"/>',
  x:'<path d="M18 6 6 18M6 6l12 12"/>',
  undo:'<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"/>',
  warn:'<path d="M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" fill="currentColor" fill-opacity=".16"/><path d="M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9.2v4M12 17h.01"/>',
  trend:'<path d="m22 6.5-8.8 8.8-4.6-4.6L2 17.3"/><path d="M16 6.5h6v6"/>',
  eye:'<path d="M1.8 12S5.5 5 12 5s10.2 7 10.2 7-3.7 7-10.2 7S1.8 12 1.8 12Z" fill="currentColor" fill-opacity=".14"/><path d="M1.8 12S5.5 5 12 5s10.2 7 10.2 7-3.7 7-10.2 7S1.8 12 1.8 12Z"/><circle cx="12" cy="12" r="2.8"/>',
  tunnel:'<path d="M3.2 20.5v-8.5a8.8 8.8 0 0 1 17.6 0v8.5" fill="currentColor" fill-opacity=".14"/><path d="M3.2 20.5v-8.5a8.8 8.8 0 0 1 17.6 0v8.5"/><path d="M8.2 20.5v-7.5a3.8 3.8 0 0 1 7.6 0v7.5"/><path d="M1.5 20.5h21"/>',
  merge:'<circle cx="6" cy="5.5" r="2.4" fill="currentColor" fill-opacity=".18"/><circle cx="6" cy="18.5" r="2.4" fill="currentColor" fill-opacity=".18"/><circle cx="18" cy="12" r="2.6" fill="currentColor" fill-opacity=".22"/><circle cx="6" cy="5.5" r="2.4"/><circle cx="6" cy="18.5" r="2.4"/><circle cx="18" cy="12" r="2.6"/><path d="M6 8v8M8.4 6.4c3.5.8 5.2 3.2 7 4.4"/>',
  screen:'<rect x="5.5" y="2.5" width="13" height="19" rx="2.8" fill="currentColor" fill-opacity=".15"/><rect x="5.5" y="2.5" width="13" height="19" rx="2.8"/><path d="M10.5 18.2h3"/>',
  rmac:'<path d="M16.2 3.5h4.3v4.3"/><path d="M4.2 19.8 20.5 3.5"/><path d="M20.5 16.2v4.3h-4.3"/><path d="m14.8 14.8 5.7 5.7"/><path d="m4.2 4.2 4.8 4.8"/>',
  isolate:'<circle cx="7" cy="12" r="2.8" fill="currentColor" fill-opacity=".18"/><circle cx="17" cy="12" r="2.8" fill="currentColor" fill-opacity=".18"/><circle cx="7" cy="12" r="2.8"/><circle cx="17" cy="12" r="2.8"/><path d="M12 4.5v15"/>',
  sim:'<path d="M7 2.8h6.8L18.5 7.5v12.2a1.8 1.8 0 0 1-1.8 1.8H7a1.8 1.8 0 0 1-1.8-1.8V4.6A1.8 1.8 0 0 1 7 2.8Z" fill="currentColor" fill-opacity=".16"/><path d="M7 2.8h6.8L18.5 7.5v12.2a1.8 1.8 0 0 1-1.8 1.8H7a1.8 1.8 0 0 1-1.8-1.8V4.6A1.8 1.8 0 0 1 7 2.8Z"/><rect x="8.5" y="11" width="7" height="6.5" rx="1.2"/>',
  rule_hub:'<circle cx="12" cy="12" r="8.8" fill="currentColor" fill-opacity=".14"/><circle cx="12" cy="12" r="8.8"/><polygon points="12 6.5 15.8 14.8 8.2 14.8" fill="currentColor" fill-opacity=".22"/><polygon points="12 6.5 15.8 14.8 8.2 14.8"/>',
  signal:'<rect x="3" y="15.5" width="3" height="5" rx="1" fill="currentColor"/><rect x="8" y="12" width="3" height="8.5" rx="1" fill="currentColor"/><rect x="13" y="8.2" width="3" height="12.3" rx="1" fill="currentColor"/><rect x="18" y="4.2" width="3" height="16.3" rx="1" fill="currentColor" fill-opacity=".35"/>',
  vector:'<polygon points="12 2.6 20.6 7.5 20.6 16.5 12 21.4 3.4 16.5 3.4 7.5" fill="currentColor" fill-opacity=".15"/><polygon points="12 2.6 20.6 7.5 20.6 16.5 12 21.4 3.4 16.5 3.4 7.5"/><circle cx="12" cy="12" r="2.8"/><path d="M12 2.6v6.6M20.6 16.5l-5.8-3.3M3.4 16.5l5.8-3.3"/>',
  scalpel:'<path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z" fill="currentColor" fill-opacity=".16"/><path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z"/><path d="M3.5 20.5h11"/><path d="m14.5 6.5 3 3"/>',
  leash:'<rect x="3" y="6.5" width="7.5" height="11" rx="3.6" fill="currentColor" fill-opacity=".15"/><rect x="13.5" y="6.5" width="7.5" height="11" rx="3.6" fill="currentColor" fill-opacity=".15"/><rect x="3" y="6.5" width="7.5" height="11" rx="3.6"/><rect x="13.5" y="6.5" width="7.5" height="11" rx="3.6"/><path d="M8.2 12h7.6"/>',
  thermo:'<path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z" fill="currentColor" fill-opacity=".16"/><path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z"/><circle cx="12" cy="17.5" r="1.5" fill="currentColor" stroke="none"/><path d="M16.8 6h2.2M16.8 9.5h1.6"/>'
};
function ico(k, cls) { return '<svg class="' + (cls || '') + '" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round">' + (I[k] || '') + '</svg>'; }

/* 底栏双态光学图标：默认轮廓态 (out) vs 液态透镜内实心镂空态 (fill) */
var HNC_TAB_SVGS = {
  dev: {
    out: '<rect x="2.6" y="3.8" width="18.8" height="12.6" rx="2.6"/><path d="M8.5 20.2h7"/><path d="M12 16.4v3.8"/>',
    fill: '<path fill="currentColor" stroke="none" fill-rule="evenodd" d="M5.2 3C3.65 3 2.4 4.25 2.4 5.8v8.4C2.4 15.75 3.65 17 5.2 17h5.85v2.3H8.4a.9.9 0 1 0 0 1.8h7.2a.9.9 0 1 0 0-1.8h-2.65V17h5.85c1.55 0 2.8-1.25 2.8-2.8V5.8C21.6 4.25 20.35 3 18.8 3H5.2Zm1.4 3.2a1 1 0 0 1 1-1h8.8a1 1 0 0 1 1 1v5.6a1 1 0 0 1-1 1H7.6a1 1 0 0 1-1-1V6.2Z"/>'
  },
  apps: {
    out: '<rect x="3.3" y="3.3" width="7.2" height="7.2" rx="2.1"/><rect x="13.5" y="3.3" width="7.2" height="7.2" rx="2.1"/><rect x="3.3" y="13.5" width="7.2" height="7.2" rx="2.1"/><rect x="13.5" y="13.5" width="7.2" height="7.2" rx="2.1"/>',
    fill: '<g fill="currentColor" stroke="none"><rect x="2.9" y="2.9" width="7.8" height="7.8" rx="2.4"/><rect x="13.3" y="2.9" width="7.8" height="7.8" rx="2.4"/><rect x="2.9" y="13.3" width="7.8" height="7.8" rx="2.4"/><rect x="13.3" y="13.3" width="7.8" height="7.8" rx="2.4" fill-opacity=".68"/></g>'
  },
  vector: {
    out: '<polygon points="12 2.8 20.4 7.6 20.4 16.4 12 21.2 3.6 16.4 3.6 7.6"/><circle cx="12" cy="12" r="2.6"/><path d="M12 2.8v6.6M20.4 16.4l-5.8-3.2M3.6 16.4l5.8-3.2"/>',
    fill: '<path fill="currentColor" stroke="none" fill-rule="evenodd" d="M11.15 2.3a1.7 1.7 0 0 1 1.7 0l7.4 4.28a1.7 1.7 0 0 1 .85 1.47v7.9a1.7 1.7 0 0 1-.85 1.47l-7.4 4.28a1.7 1.7 0 0 1-1.7 0l-7.4-4.28a1.7 1.7 0 0 1-.85-1.47v-7.9a1.7 1.7 0 0 1 .85-1.47l7.4-4.28ZM12 8.7a3.3 3.3 0 1 0 0 6.6 3.3 3.3 0 0 0 0-6.6Z"/>'
  },
  stats: {
    out: '<rect x="4" y="12.4" width="3.8" height="7.6" rx="1.2"/><rect x="10.1" y="5.2" width="3.8" height="14.8" rx="1.2"/><rect x="16.2" y="9.4" width="3.8" height="10.6" rx="1.2"/>',
    fill: '<g fill="currentColor" stroke="none"><rect x="3.6" y="12" width="4.4" height="8.4" rx="1.5"/><rect x="9.8" y="4.6" width="4.4" height="15.8" rx="1.5"/><rect x="16" y="8.8" width="4.4" height="11.6" rx="1.5"/></g>'
  },
  gear: {
    out: I.gear,
    fill: '<path fill="currentColor" stroke="none" fill-rule="evenodd" d="M10.4 2.2a1.8 1.8 0 0 1 3.2 0l.44 1.04a1.4 1.4 0 0 0 1.8.75l1.04-.44a1.8 1.8 0 0 1 2.26 2.26l-.44 1.04a1.4 1.4 0 0 0 .75 1.8l1.04.44a1.8 1.8 0 0 1 0 3.2l-1.04.44a1.4 1.4 0 0 0-.75 1.8l.44 1.04a1.8 1.8 0 0 1-2.26 2.26l-1.04-.44a1.4 1.4 0 0 0-1.8.75l-.44 1.04a1.8 1.8 0 0 1-3.2 0l-.44-1.04a1.4 1.4 0 0 0-1.8-.75l-1.04.44a1.8 1.8 0 0 1-2.26-2.26l.44-1.04a1.4 1.4 0 0 0-.75-1.8l-1.04-.44a1.8 1.8 0 0 1 0-3.2l1.04-.44a1.4 1.4 0 0 0 .75-1.8l-.44-1.04a1.8 1.8 0 0 1 2.26-2.26l1.04.44a1.4 1.4 0 0 0 1.8-.75l.44-1.04ZM12 8.7a3.3 3.3 0 1 0 0 6.6 3.3 3.3 0 0 0 0-6.6Z"/>'
  }
};
function tabSvg(k, filled) {
  var item = HNC_TAB_SVGS[k] || HNC_TAB_SVGS.dev;
  return '<svg class="tab-ic' + (filled ? ' is-fill' : '') + '" width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (filled ? item.fill : item.out) + '</svg>';
}

/* 实时 0..4 格 5G / Wi-Fi 信号阶梯矢量图标 */
function cellSvg(bars, mode) {
  var b = clamp(Math.round(num(bars, 0)), 0, 4);
  if (mode === 'wifi_sta') {
    var o1 = b >= 1 ? '1' : '.25', o2 = b >= 2 ? '1' : '.25', o3 = b >= 3 ? '1' : '.25';
    return '<svg class="sig-ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><path d="M2.2 8.8a15.2 15.2 0 0 1 19.6 0" stroke-opacity="' + o3 + '"/><path d="M5.6 12.8a10.2 10.2 0 0 1 12.8 0" stroke-opacity="' + o2 + '"/><path d="M9 16.8a5.2 5.2 0 0 1 6 0" stroke-opacity="' + o1 + '"/><circle cx="12" cy="20" r="1.4" fill="currentColor" stroke="none"/></svg>';
  }
  var hs = [[3, 15.5, 5], [8, 12, 8.5], [13, 8.2, 12.3], [18, 4.2, 16.3]];
  return '<svg class="sig-ic" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">' + hs.map(function (x, idx) {
    var on = idx < b;
    return '<rect x="' + x[0] + '" y="' + x[1] + '" width="3.2" height="' + x[2] + '" rx="1.1" fill="currentColor" fill-opacity="' + (on ? '1' : '.24') + '"/>';
  }).join('') + '</svg>';
}

/* 共享基础设施 CDN / SDK 智能识别字典(供应用规则中心与未识别域名补库共用) */
var INFRA_EXACT = {
  'kunlunca.com': ['cdn', '阿里云 CDN'], 'alikunlun.com': ['cdn', '阿里云 CDN'], 'alikunlun.net': ['cdn', '阿里云 CDN'],
  'alicdn.com': ['cdn', '阿里云公共 CDN'], 'tbcdn.cn': ['cdn', '阿里公共静态资源'], 'mmstat.com': ['sdk', '阿里统计 SDK'],
  'cdngslb.com': ['cdn', '网宿 GSLB'], 'chinanetcenter.com': ['cdn', '网宿科技 CDN'], 'wscdns.com': ['cdn', '网宿 CDN'], 'wsglb0.com': ['cdn', '网宿 GSLB'],
  'qtlcdn.com': ['cdn', '网宿海外 CDN'], 'ksyuncdn.com': ['cdn', '金山云 CDN'], 'ks-cdn.com': ['cdn', '金山云 CDN'],
  'dnsv1.com': ['cdn', '腾讯云 DNSPod/CDN'], 'dnsv1.com.cn': ['cdn', '腾讯云 CDN'], 'smtcdns.net': ['cdn', '腾讯云智能调度'], 'cdntip.com': ['cdn', '腾讯云边缘 CDN'],
  'myqcloud.com': ['cloud', '腾讯云对象存储'], 'gtimg.cn': ['cdn', '腾讯公共静态 CDN'],
  'volccdn.com': ['cdn', '火山引擎公共 CDN'], 'bytefcdn.com': ['cdn', '火山边缘融合 CDN'],
  'bdydns.com': ['cdn', '百度智能云 CDN'], 'jomodns.com': ['cdn', '京东云 CDN'], 'baishan-cloud.net': ['cdn', '白山云 CDN'],
  'myhuaweicloud.com': ['cloud', '华为云底座'], 'hwcdn.net': ['cdn', '华为云 CDN'],
  'cloudfront.net': ['cdn', 'AWS CloudFront'], 'akamaiedge.net': ['cdn', 'Akamai CDN'], 'akamaihd.net': ['cdn', 'Akamai HD'],
  'cdn.cloudflare.net': ['cdn', 'Cloudflare CDN'], 'fastly.net': ['cdn', 'Fastly CDN'],
  'umeng.com': ['sdk', '友盟统计 SDK'], 'umengcloud.com': ['sdk', '友盟推送 SDK'],
  'getui.com': ['sdk', '个推推送 SDK'], 'igexin.com': ['sdk', '个推长连接 SDK'], 'jpush.cn': ['sdk', '极光推送 SDK'],
  'pangolin-sdk-toutiao.com': ['sdk', '穿山甲广告 SDK'], 'pglstatp-toutiao.com': ['sdk', '穿山甲统计 SDK'],
  'gdt.qq.com': ['sdk', '优量汇广告 SDK'], 'bugly.qq.com': ['sdk', 'Bugly 崩溃上报 SDK'],
  'doubleclick.net': ['sdk', 'Google Ads SDK'], 'googlesyndication.com': ['sdk', 'Google 广告 SDK'], 'app-measurement.com': ['sdk', 'Firebase 统计 SDK']
};
function classifyInfraHost(host) {
  var h = String(host || '').toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!h) return null;
  for (var suf in INFRA_EXACT) {
    if (h === suf || h.slice(-(suf.length + 1)) === '.' + suf) {
      var inf = INFRA_EXACT[suf];
      return { kind: inf[0], label: inf[1], shared: true };
    }
  }
  var parts = h.split('.').filter(Boolean);
  var reg = parts.length <= 2 ? h : (/^(com|net|org|gov|edu)\.cn$|^co\.(uk|jp)$|^com\.(au|br|hk|tw)$/.test(parts.slice(-2).join('.')) ? parts.slice(-3).join('.') : parts.slice(-2).join('.'));
  if (/^kunlun[a-z0-9-]*\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '阿里昆仑 CDN 簇', shared: true };
  if (/^cdnhwc[a-z0-9-]*\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '华为云 CDN 簇', shared: true };
  if (/^(t?dnsv[0-9a-z-]*|smtcdns[0-9a-z-]*)\.(com|net|cn|com\.cn)$/.test(reg)) return { kind: 'cdn', label: '腾讯 GSLB/CDN 簇', shared: true };
  if (/(gslb|cdngslb|wsglb|ksyungslb|alikunlun|qiniudns|baishan-cloud|bsclink)/.test(h)) return { kind: 'cdn', label: '公共 GSLB/CDN 调度', shared: true };
  if (/(^|\.)(cdn[0-9]*|static-cdn|imgcdn|vodcdn)\./.test(h) || /-cdn\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '疑似公共 CDN 节点', shared: true };
  if (/^(sdk|ads?|adx|track|telemetry|beacon|metrics|stat|crash)\./.test(h)) return { kind: 'sdk', label: '疑似通用统计/广告 SDK', shared: true };
  return { kind: 'app', label: '可归因专属域名', shared: false };
}
function infraBadgeHtml(info) {
  if (!info) return '';
  var prefix = info.kind === 'cdn' ? '公共 CDN · ' : info.kind === 'sdk' ? '共享 SDK · ' : info.kind === 'cloud' ? '公共云网关 · ' : '';
  return '<span class="infra-tag ' + info.kind + '">' + esc(prefix + info.label) + '</span>';
}
function gi(color, k) { return '<span class="gi ' + color + '">' + ico(k) + '</span>'; }
function toggle(on, attrs) { return '<button class="toggle" role="switch" aria-checked="' + !!on + '" ' + (attrs || '') + '></button>'; }
function seg(id, opts, cur, cls) {
  return '<div class="seg ' + (cls || 'glass') + '" data-seg="' + id + '"><i class="thumb"></i>' + opts.map(function (o) {
    return '<button type="button" data-v="' + esc(o[0]) + '" class="' + (String(o[0]) === String(cur) ? 'on' : '') + '">' + o[1] + '</button>'; }).join('') + '</div>';
}
function placeSegs(root) {
  $$('.seg', root || document).forEach(function (s) {
    var on = $('button.on', s), th = $('.thumb', s); if (!on || !on.offsetWidth) { if (th) th.style.width = '0px'; return; }
    var nx = on.offsetLeft, nw = on.offsetWidth, w = nw + 'px', tf = 'translate3d(' + nx + 'px,0,0)';
    var prevX = th._lx;
    if (th.style.width === w && th.style.transform === tf) return;
    var first = prevX == null || !th.style.transform || th.style.width === '0px';
    th._lx = nx;
    if (first) {
      th.style.transition = 'none';
      th.style.width = w; th.style.transform = tf;
      void th.offsetWidth; th.style.transition = '';
      return;
    }
    var dx = nx - prevX, adx = Math.abs(dx);
    s.style.setProperty('--seg-dir', dx >= 0 ? '1' : '-1');
    th.style.width = w; th.style.transform = tf;
    if (adx > 6 && th.animate && typeof motionOn === 'function' && motionOn()) {
      var stretch = Math.min(1.12, 1 + adx / 420), squash = Math.max(0.91, 1 - (stretch - 1) * 0.55);
      var midX = prevX + dx * 0.52;
      try {
        th.animate([
          { transform: 'translate3d(' + prevX + 'px,0,0) scale(1,1)' },
          { transform: 'translate3d(' + midX.toFixed(1) + 'px,0,0) scale(' + stretch.toFixed(3) + ',' + squash.toFixed(3) + ')', offset: 0.42 },
          { transform: 'translate3d(' + (nx + (dx > 0 ? 1.5 : -1.5)).toFixed(1) + 'px,0,0) scale(0.985,1.015)', offset: 0.82 },
          { transform: tf + ' scale(1,1)' }
        ], { duration: 340, easing: 'cubic-bezier(.22,1,.36,1)' });
      } catch (_) {}
    }
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
function _dirtyBaseOf(el) {
  if (!el || !el.getAttribute) return '';
  var av = el.getAttribute('value');
  if (av != null) return av;
  if (el.nodeName === 'SELECT' && el.options && el.options.length) {
    for (var i = 0; i < el.options.length; i++) {
      if (el.options[i].defaultSelected) return el.options[i].value || '';
    }
    return el.options[0].value || '';
  }
  if (el.nodeName === 'TEXTAREA') return el.defaultValue || '';
  return '';
}
function markDirtyInput(el) {
  if (!el || el.nodeType !== 1) return;
  var tag = el.nodeName;
  if (tag !== 'INPUT' && tag !== 'SELECT' && tag !== 'TEXTAREA') return;
  if (tag === 'INPUT' && (el.type === 'file' || el.type === 'checkbox' || el.type === 'radio' || el.type === 'button' || el.type === 'submit' || el.type === 'reset')) return;
  if (el.getAttribute('data-dirty') !== '1') {
    el.setAttribute('data-dirty-base', _dirtyBaseOf(el));
    el.setAttribute('data-dirty', '1');
  }
}
function clearDirtyInputs(root) {
  if (arguments.length > 0 && !root) return;
  var scope = root || (typeof document !== 'undefined' ? document : null);
  if (!scope) return;
  if (scope.nodeType === 1 && scope.removeAttribute) {
    scope.removeAttribute('data-dirty');
    scope.removeAttribute('data-dirty-base');
  }
  if (scope.querySelectorAll) {
    var list = scope.querySelectorAll('[data-dirty], [data-dirty-base]');
    for (var i = 0; i < list.length; i++) {
      list[i].removeAttribute('data-dirty');
      list[i].removeAttribute('data-dirty-base');
    }
  }
}
if (typeof window !== 'undefined') {
  window.clearDirtyInputs = clearDirtyInputs;
  window.markDirtyInput = markDirtyInput;
}
if (typeof document !== 'undefined' && document.addEventListener) {
  var _onFormDirtyEvt = function (e) {
    var t = e && e.target;
    if (t && t.nodeType === 1) markDirtyInput(t);
  };
  document.addEventListener('input', _onFormDirtyEvt, true);
  document.addEventListener('change', _onFormDirtyEvt, true);
}
function mkey(n) {
  if (n.nodeType !== 1) return '';
  var k = n.getAttribute('data-dev') || n.getAttribute('data-side') || n.getAttribute('data-foldkey') || n.id || n.getAttribute('data-app') || n.getAttribute('data-mkey') || n.getAttribute('data-cnk') || n.getAttribute('data-dev-pane') || n.getAttribute('data-seg');
  return k ? n.nodeName + ':' + k : '';
}
function morphAttrs(a, b) {
  var i, at, frozen = a.classList.contains('pending') || a.classList.contains('busy') || !!(a.parentNode && a.parentNode.classList && (a.parentNode.classList.contains('pending') || a.parentNode.classList.contains('busy')));
  var activeEl = typeof document !== 'undefined' ? document.activeElement : null;
  var segDir = a.classList.contains('seg') ? a.style.getPropertyValue('--seg-dir') : '';
  var isTextInp = a.nodeName === 'INPUT' && a.type !== 'checkbox' && a.type !== 'radio' && a.type !== 'file';
  var hasBVal = isTextInp && b.hasAttribute('value');
  var bVal = hasBVal ? b.getAttribute('value') : '';
  var keepDirty = a.getAttribute('data-dirty') === '1';
  if (isTextInp && keepDirty) {
    var baseVal = a.getAttribute('data-dirty-base');
    if (baseVal == null) baseVal = '';
    if (bVal === a.value || bVal !== baseVal) {
      keepDirty = false;
      a.removeAttribute('data-dirty');
      a.removeAttribute('data-dirty-base');
    }
  }
  for (i = a.attributes.length - 1; i >= 0; i--) {
    at = a.attributes[i].name;
    if (b.hasAttribute(at) || (at === 'style' && (a.classList.contains('thumb') || !!segDir))) continue;
    if (keepDirty && (at === 'data-dirty' || at === 'data-dirty-base')) continue;
    if (frozen && (at === 'class' || at === 'aria-checked' || at === 'disabled' || at === 'aria-busy')) continue;
    a.removeAttribute(at);
  }
  for (i = 0; i < b.attributes.length; i++) {
    at = b.attributes[i];
    if (isTextInp && keepDirty && at.name === 'value') continue;
    var cur = a.getAttribute(at.name); if (cur === at.value) continue;
    if (at.name === 'class') {
      if (frozen) continue;
      var keep = MORPH_KEEP_CLS.filter(function (c) { return a.classList.contains(c) && !b.classList.contains(c); });
      a.setAttribute('class', at.value + (keep.length ? ' ' + keep.join(' ') : ''));
      continue;
    }
    if (frozen && (at.name === 'aria-checked' || at.name === 'disabled' || at.name === 'aria-busy')) continue;
    if (at.name === 'style' && a.classList.contains('thumb')) continue;
    a.setAttribute(at.name, at.value);
    if (isTextInp && at.name === 'value' && !keepDirty && a !== activeEl) a.value = at.value;
  }
  if (isTextInp && !keepDirty && hasBVal && a !== activeEl && a.value !== bVal) {
    a.value = bVal;
  }
  if (segDir && a.style.getPropertyValue('--seg-dir') !== segDir) {
    a.style.setProperty('--seg-dir', segDir);
  }
  if (a.nodeName === 'INPUT' && (a.type === 'checkbox' || a.type === 'radio')) {
    var ck = b.hasAttribute('checked');
    if (a.defaultChecked !== ck) { if (a !== activeEl) a.checked = ck; a.defaultChecked = ck; }
  }
  if (a.nodeName === 'OPTION') {
    var sel = b.hasAttribute('selected');
    if (a.defaultSelected !== sel) a.defaultSelected = sel;
  }
}
function morphNode(a, b) {
  if (a.nodeType !== 1) { if (a.nodeValue !== b.nodeValue) a.nodeValue = b.nodeValue; return a; }
  if (a.hasAttribute('data-keep')) return a;
  var activeEl = typeof document !== 'undefined' ? document.activeElement : null;
  var hasSelVal = a.nodeName === 'SELECT' && b.options && b.options.length > 0;
  var wantSel = hasSelVal ? b.value : '';
  var isDirtySel = hasSelVal && a.getAttribute('data-dirty') === '1';
  var selBase = isDirtySel ? (a.getAttribute('data-dirty-base') || '') : '';
  var prevSelVal = hasSelVal ? a.value : '';
  var prevSelIdx = hasSelVal ? a.selectedIndex : -1;
  morphAttrs(a, b);
  if (a.nodeName !== 'TEXTAREA') morphKids(a, b);
  else if (a.getAttribute('data-dirty') === '1') {
    var bTaVal = b.value || b.textContent || '';
    var taBase = a.getAttribute('data-dirty-base') || '';
    if (bTaVal === a.value || bTaVal !== taBase) {
      a.removeAttribute('data-dirty');
      a.removeAttribute('data-dirty-base');
      if (a !== activeEl && a.value !== bTaVal) a.value = bTaVal;
    }
  }
  if (hasSelVal) {
    if (isDirtySel) {
      if (wantSel === prevSelVal || wantSel !== selBase) {
        a.removeAttribute('data-dirty');
        a.removeAttribute('data-dirty-base');
        if (a !== activeEl && a.value !== wantSel) a.value = wantSel;
      } else if (a.value !== prevSelVal) {
        a.value = prevSelVal;
        if (a.value !== prevSelVal && prevSelIdx >= 0 && prevSelIdx < a.options.length) {
          a.selectedIndex = prevSelIdx;
        }
      }
    } else if (a !== activeEl && a.value !== wantSel) {
      a.value = wantSel;
    }
  }
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
var MOD_DIR = '/data/adb/modules/hotspot_net_ctl';
var KSU = typeof window.ksu !== 'undefined' && window.ksu && typeof window.ksu.exec === 'function';
var IS_LOCAL = KSU || /^(127\.0\.0\.1|localhost|\[?::1\]?)$/i.test((typeof location !== 'undefined' && location && location.hostname) || '');
var rawCb = 0;
function execRaw(cmd, timeoutMs) {
  return new Promise(function (resolve) {
    if (!KSU) { resolve({ code: -1, out: '', err: 'no ksu bridge' }); return; }
    var done = false;
    if (window.ksu.exec.length <= 1) {
      var tm1 = setTimeout(function () { if (done) return; done = true; resolve({ code: -1, out: '', err: 'timeout' }); }, timeoutMs || 30000);
      try {
        Promise.resolve(window.ksu.exec(cmd)).then(function (r) {
          if (done) return; done = true; clearTimeout(tm1);
          if (typeof r === 'string') { resolve({ code: 0, out: r, err: '' }); return; }
          if (r && typeof r === 'object') {
            var cRaw = r.errno !== undefined ? r.errno : (r.code !== undefined ? r.code : (r.exitCode !== undefined ? r.exitCode : 0));
            var cNum = parseInt(String(cRaw), 10);
            resolve({
              code: isNaN(cNum) ? 0 : cNum,
              out: typeof r.stdout === 'string' ? r.stdout : (typeof r.out === 'string' ? r.out : String(r.stdout != null ? r.stdout : '')),
              err: typeof r.stderr === 'string' ? r.stderr : (typeof r.err === 'string' ? r.err : String(r.stderr != null ? r.stderr : ''))
            });
            return;
          }
          resolve({ code: 0, out: r == null ? '' : String(r), err: '' });
        }, function (e) {
          if (done) return; done = true; clearTimeout(tm1);
          resolve({ code: -1, out: '', err: String((e && e.message) || e) });
        });
      } catch (e1) {
        if (!done) { done = true; clearTimeout(tm1); resolve({ code: -1, out: '', err: String(e1) }); }
      }
      return;
    }
    var name = '__hnc6_cb_' + (++rawCb);
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
function splitUtf16Safe(str, chunkSize) {
  var chunks = [], i = 0, len = str.length;
  while (i < len) {
    var end = Math.min(i + chunkSize, len);
    if (end < len) {
      var code = str.charCodeAt(end - 1);
      if (code >= 0xD800 && code <= 0xDBFF) end++;
    }
    chunks.push(str.slice(i, end));
    i = end;
  }
  return chunks;
}
function curlCmd(method, path, bodyStr, sec, maxTime, bodyFile) {
  var c = 'curl -g -sS --connect-timeout 1 --max-time ' + (maxTime || 6) + " -w '\\n__HNC_HTTP__%{http_code}'";
  if (method === 'POST') {
    c += ' -X POST -H ' + sq('Content-Type: application/json') + ' -H ' + sq('X-HNC-CSRF: 1');
    if (bodyFile) c += ' --data-binary @' + sq(bodyFile);
    else c += ' --data-raw ' + sq(bodyStr || '{}');
  }
  if (sec) c += ' -H ' + sq('X-HNC-Local-Admin: ' + sec);
  return c + ' -H ' + sq('Cache-Control: no-cache') + ' ' + sq(API_BASE + path);
}
function ksuBridge(method, path, body, sec, opt) {
  var bodyStr = method === 'POST' ? JSON.stringify(body || {}) : '';
  var tmo = (opt.timeout || 9000) + 2000;
  if (method !== 'POST' || bodyStr.length <= 65536) {
    return execRaw(curlCmd(method, path, bodyStr, sec, opt.maxTime, ''), tmo);
  }
  // 超过 64KB 请求体按 48KB 分片写入 /data/local/hnc/run/.webui_req.$$.tmp，绕过 Linux MAX_ARG_STRLEN (128KB) E2BIG 限制
  var parts = splitUtf16Safe(bodyStr, 49152);
  var tmpPath = '';
  var p = execRaw('umask 077 && mkdir -p /data/local/hnc/run && _f="/data/local/hnc/run/.webui_req.$$.tmp" && printf \'%s\' ' + sq(parts[0]) + ' > "$_f" && printf \'%s\' "$_f"', 8000).then(function (r0) {
    var fp = String(r0.out || '').trim();
    if (r0.code !== 0 || fp.indexOf('/data/local/hnc/run/.webui_req.') !== 0) {
      return { code: r0.code || -1, out: '', err: r0.err || 'failed to stage request chunk 0' };
    }
    tmpPath = fp;
    var chain = Promise.resolve({ code: 0 });
    for (var idx = 1; idx < parts.length; idx++) {
      (function (chunk) {
        chain = chain.then(function (prev) {
          if (prev.code !== 0) return prev;
          return execRaw("printf '%s' " + sq(chunk) + ' >> ' + sq(tmpPath), 8000);
        });
      })(parts[idx]);
    }
    return chain.then(function (lastW) {
      if (lastW.code !== 0) {
        return execRaw('rm -f ' + sq(tmpPath), 3000).then(function () { return lastW; });
      }
      var sendCmd = curlCmd(method, path, '', sec, Math.max(opt.maxTime || 6, 15), tmpPath) + '; _rc=$?; rm -f ' + sq(tmpPath) + '; exit $_rc';
      return execRaw(sendCmd, Math.max(tmo, 18000));
    });
  });
  return p.then(function (res) {
    if (res.code !== 0 && tmpPath) execRaw('rm -f ' + sq(tmpPath), 3000);
    return res;
  });
}
function bridgeReq(method, path, body, opt, retried) {
  opt = opt || {};
  return loadSecret().then(function (sec) {
    return ksuBridge(method, path, body, sec, opt);
  }).then(function (r) {
    if (r.code !== 0) {
      var raw = r.err || '';
      if (r.code === 7 || /failed to connect|connection refused|port \d+ after/i.test(raw)) throw HttpError('后端未就绪 · hnc_httpd 没有在运行', 0);
      if (r.code === 28 || /timed out|timeout/i.test(raw)) throw HttpError('后端无响应 · 超时', 0);
      throw HttpError('桥接失败 exit=' + r.code + (raw ? ' ' + raw.slice(0, 80) : ''), 0);
    }
    var out = r.out, k = out.lastIndexOf('\n__HNC_HTTP__'), status = 200;
    if (k >= 0) {
      status = parseInt(out.slice(k + 13), 10) || 0; out = out.slice(0, k);
      if (status === 0) throw HttpError('后端未就绪 · hnc_httpd 没有在运行', 0);
    }
    if (status === 401 && !retried) { secret = ''; return loadSecret(true).then(function () { return bridgeReq(method, path, body, opt, true); }); }
    var obj = parseJSON(out, status);
    if (status >= 400) throw HttpError(status === 401 ? '本地密钥校验失败 (401) · 可在设置里重启服务' : (obj.error || ('HTTP ' + status)) + (obj.detail ? ' · ' + obj.detail : ''), status, obj);
    return obj;
  });
}
function fetchReq(method, path, body, opt) {
  opt = opt || {};
  var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
  var tm, timedOut = false;
  var timeout = new Promise(function (resolve, reject) {
    tm = setTimeout(function () {
      timedOut = true;
      try { ctrl && ctrl.abort(); } catch (_) {}
      reject(HttpError('请求超时', 0));
    }, opt.timeout || 9000);
  });
  var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: { 'Cache-Control': 'no-cache' }, signal: ctrl ? ctrl.signal : undefined };
  // 超时覆盖响应正文; Promise.race 也让没有 AbortController 的旧 WebView 能释放请求队列。
  var response = Promise.resolve().then(function () {
    if (method === 'POST') { init.headers['Content-Type'] = 'application/json'; init.headers['X-HNC-CSRF'] = '1'; init.body = JSON.stringify(body || {}); }
    return fetch(path, init);
  }).then(function (resp) {
    return resp.text().then(function (txt) {
      if (timedOut) throw HttpError('请求超时', 0);
      if (resp.status === 401) {
        if (location.pathname.indexOf('/pair') !== 0) setTimeout(function () { location.href = '/pair'; }, 600);
        throw HttpError('需要先配对这台设备', 401);
      }
      var obj = parseJSON(txt, resp.status);
      if (!resp.ok) throw HttpError((obj.error || ('HTTP ' + resp.status)) + (obj.detail ? ' · ' + obj.detail : ''), resp.status, obj);
      return obj;
    });
  });
  return Promise.race([response, timeout]).then(function (obj) { clearTimeout(tm); return obj; }, function (e) {
    clearTimeout(tm);
    if (e && e.status !== undefined) throw e;
    throw HttpError(e && e.name === 'AbortError' ? '请求超时' : '网络错误 · ' + (e && e.message || e), 0);
  });
}
function req(method, path, body, opt) { return KSU ? bridgeReq(method, path, body, opt) : fetchReq(method, path, body, opt); }
function qs(params) {
  if (!params) return '';
  var q = Object.keys(params).filter(function (k) { return params[k] !== undefined && params[k] !== null && params[k] !== ''; })
    .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); }).join('&');
  return q ? '?' + q : '';
}
var api = {
  writeGen: 0,
  writeInFlight: 0,
  bumpWriteGen: function () { api.writeGen = (api.writeGen || 0) + 1; return api.writeGen; },
  get: function (path, params, opt) {
    return req('GET', path + qs(params), null, opt).then(function (o) {
      if (o && o.ok === false) { var e = HttpError(o.error || '接口返回失败', 200, o); e.detail = o.detail; throw e; }
      return o || {};
    });
  },
  getSafe: function (path, params, fallback) { return api.get(path, params).catch(function () { return fallback; }); },
  post: function (path, body, opt) {
    var skipFence = /^\/api\/(logout|export|rollback_ack)/.test(String(path || ''));
    if (!skipFence) { api.bumpWriteGen(); api.writeInFlight++; }
    return Promise.resolve().then(function () {
      return req('POST', path, body, opt);
    }).then(function (r) {
      if (!skipFence) { api.writeInFlight = Math.max(0, api.writeInFlight - 1); api.bumpWriteGen(); }
      return r;
    }, function (e) {
      if (!skipFence) { api.writeInFlight = Math.max(0, api.writeInFlight - 1); api.bumpWriteGen(); }
      throw e;
    });
  },
  /* 写操作: 全局串行(与旧版一致, 避免 tc/json 竞态); params 的值必须全是字符串(后端 map[string]string) */
  _q: Promise.resolve(),
  action: function (name, params, opt) {
    var p = {}; params = params || {};
    Object.keys(params).forEach(function (k) { if (params[k] !== undefined && params[k] !== null) p[k] = String(params[k]); });
    var slow = /^(debug_bundle|cleanup_all|dpi_rules_update|capture_record|selfcheck_run|selfcheck_export|compat_report|self_studio_start|self_studio_distill|self_studio_export|dpi_distill_now|flow_cls_retrain|dpi_rulepack_export|device_merge|device_unmerge|encdns_set|clsact_mode_set|dataplane_verify_run)$/.test(name);
    var skipFence = /^(debug_bundle|selfcheck_run|selfcheck_export|compat_report|capture_record|dpi_rulepack_export|self_studio_export|clsact_check)$/.test(name);
    var defOpt = slow ? { timeout: 35000, maxTime: 30 } : { timeout: 12000, maxTime: 10 };
    var run = function () {
      if (!skipFence) { api.bumpWriteGen(); api.writeInFlight++; }
      return Promise.resolve().then(function () {
        return req('POST', '/api/action', { action: name, params: p }, Object.assign({}, defOpt, opt));
      }).then(function (o) {
        if (!skipFence) { api.writeInFlight = Math.max(0, api.writeInFlight - 1); api.bumpWriteGen(); }
        if (!o || !o.ok) { var e = HttpError((o && o.error) || '操作失败', 200, o); e.detail = o && o.detail; throw e; }
        return o;
      }, function (e) {
        if (!skipFence) { api.writeInFlight = Math.max(0, api.writeInFlight - 1); api.bumpWriteGen(); }
        throw e;
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

/* ═════════════════════ 交互组件: toast / 5秒撤销胶囊(undoToast) / 弹层 / 确认 ═════════════════════ */
var toastT;
function toast(m, kind) {
  var t = $('#toast'), ic = $('#toast-ic');
  if (!t || !ic) return;
  $('#toast-t').textContent = m;
  ic.style.color = kind === 'err' ? 'var(--red)' : kind === 'warn' ? 'var(--orange)' : 'var(--green)';
  ic.innerHTML = kind === 'err' ? I.x : kind === 'warn' ? I.warn : I.check;
  t.classList.remove('show'); void t.offsetWidth; t.classList.add('show');
  clearTimeout(toastT); toastT = setTimeout(function () { t.classList.remove('show'); }, kind === 'err' ? 3600 : 2200);
}

var undoT = 0, undoHideT = 0, undoCur = null, undoRunning = false, undoBound = false;
function dismissUndo(immediate) {
  clearTimeout(undoT); undoT = 0;
  clearTimeout(undoHideT); undoHideT = 0;
  undoCur = null; undoRunning = false;
  var pill = typeof document !== 'undefined' ? document.getElementById('undo-pill') : null;
  if (!pill) return;
  var btn = document.getElementById('undo-btn');
  if (btn) btn.disabled = false;
  pill.classList.remove('show');
  var noMotion = immediate || (typeof motionOn === 'function' && !motionOn());
  if (noMotion) {
    pill.hidden = true;
  } else {
    undoHideT = setTimeout(function () {
      undoHideT = 0;
      if (!undoCur && pill) pill.hidden = true;
    }, 220);
  }
}
function bindUndoOnce() {
  if (undoBound || typeof document === 'undefined') return;
  var pill = document.getElementById('undo-pill');
  if (!pill) return;
  undoBound = true;
  var btn = document.getElementById('undo-btn');
  var xBtn = document.getElementById('undo-x');
  if (btn) btn.addEventListener('click', function () {
    if (undoRunning || !undoCur || typeof undoCur.fn !== 'function') return;
    undoRunning = true;
    btn.disabled = true;
    clearTimeout(undoT); undoT = 0;
    var cur = undoCur;
    if (typeof haptic === 'function') haptic(8);
    Promise.resolve().then(cur.fn).then(function (res) {
      var uMsg = cur.opt && cur.opt.undoMsg;
      dismissUndo(true);
      if (uMsg) toast(typeof uMsg === 'function' ? uMsg(res) : String(uMsg));
    }, function (e) {
      dismissUndo(true);
      toast(errText(e), 'err');
    });
  });
  if (xBtn) xBtn.addEventListener('click', function () { dismissUndo(false); });
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) dismissUndo(true);
  });
}
function undoToast(msg, undoFn, opt) {
  if (msg && typeof msg === 'object' && typeof undoFn !== 'function') {
    opt = msg; undoFn = opt.undo || opt.onUndo || opt.fn; msg = opt.msg || opt.text || '';
  }
  opt = opt || {};
  if (typeof undoFn !== 'function') { toast(msg, opt.kind); return; }
  var pill = typeof document !== 'undefined' ? document.getElementById('undo-pill') : null;
  var msgEl = typeof document !== 'undefined' ? document.getElementById('undo-msg') : null;
  if (!pill || !msgEl) { toast(msg, opt.kind); return; }
  bindUndoOnce();
  var topToast = document.getElementById('toast');
  if (topToast && topToast.classList.contains('show')) { clearTimeout(toastT); topToast.classList.remove('show'); }
  clearTimeout(undoT); undoT = 0;
  clearTimeout(undoHideT); undoHideT = 0;
  undoRunning = false;
  var btn = document.getElementById('undo-btn');
  if (btn) btn.disabled = false;
  var btnTxt = document.getElementById('undo-btn-t');
  if (btnTxt) btnTxt.textContent = String(opt.label || '撤销');
  msgEl.textContent = String(msg == null ? '' : msg);
  undoCur = { fn: undoFn, opt: opt };
  pill.hidden = false;
  pill.classList.remove('show');
  void pill.offsetWidth;
  pill.classList.add('show');
  var dur = clamp(Math.round(num(opt.duration || opt.timeout, 5000)), 1500, 15000);
  undoT = setTimeout(function () { dismissUndo(false); }, dur);
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
  statsRange: 'today', aseg: 'stats', appsSub: 'active', devTab: {}, puEditSlot: 0, signal: null,
  theme: LS.get('hnc6.theme', 'auto'), motion: LS.get('hnc6.motion', '1') !== '0', glassTint: clamp(Math.round(num(LS.get('hnc6.glass_tint', '50'), 50)), 0, 100), style: (function(){ var sv = LS.get('hnc6.style', 'default'); if (sv === 'apple') sv = 'cyber'; return ['cyber', 'liquid'].indexOf(sv) >= 0 ? sv : 'default'; })(),
  lgVariant: normLgVariant((typeof window !== 'undefined' && window.__HNC_PREVIEW_VARIANT__) || LS.get('hnc6.lg_variant', 'pure')),
  dpi: null, probe: null, dpiHist: {}, dpiDays: 1, dpiFilter: 'all', dpiSpark: { packets: [], dns_events: [], tls_events: [], kernel_drops: [] },
  self: null, selfCfg: {}, logFile: 'combined',
  vectorSyncState: 'unknown', vecDevSig: '', coreHealthy: true, coreUptimeSec: 0, bulkheads: null, v6: null
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
function upOk() { return htbOk() && (cap('uplink_supported') !== false || cap('uplink_police_supported') === true); }
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
function offloadGuardTakenOver(og) {
  var g = og || (S.offload && S.offload.guard) || (S.cfg && S.cfg.offload_guard) || null;
  return !!(g && (
    g.fallback_active === true ||
    g.clsact === 'installed' || g.clsact_attached === true ||
    g.slowpath === 'ok' || g.slowpath_active === true ||
    g.tether_offload_disabled === true || g.tether_limit_zeroed === true
  ));
}
function hasActiveControlPolicy(cfg) {
  var c = cfg || S.cfg || {};
  var og = (S.offload && S.offload.guard) || c.offload_guard || null;
  if (og && (og.policy_active === true || og.has_active_policy === true)) return true;
  if (c.global_shaper_enabled === true || (c.autorate && c.autorate.enabled === true) || c.quic_block === true || c.client_isolation_enabled === true || c.whitelist_mode === true || c.whitelist_enabled === true) return true;
  if (Array.isArray(c.blacklist) && c.blacklist.length > 0) return true;
  if ((S.appLimits || []).length > 0) return true;
  if ((S.devices || []).some(function (d) {
    return !d.sim && (d.limitOn || d.hasDelay || d.blocked || d.sqm || d.appQos || !!d.quota || !!d.sched || (d.atl && d.atl.length > 0) || (d.cblocks && d.cblocks.length > 0));
  })) return true;
  if (S.live && S.live.active_limiter_reason && S.live.active_limiter_reason !== 'none') return true;
  return false;
}
function offloadRisk() {
  return S.hotspot.active !== false &&
    hasActiveControlPolicy() &&
    (S.offload.detail === 'ACTIVE' || S.offload.detail === 'CAPABLE') &&
    !offloadGuardTakenOver();
}

/* ═════════════════════ 数据加载 ═════════════════════ */
/* HNC v5.36.0 Apple SF Symbols / Lucide Duotone Vector SVG System (Zero Bitmap · Zero Phone Emoji) */
var HNC_DEV_SVGS = {
  phone: '<rect x="6" y="2.5" width="12" height="19" rx="3" fill="currentColor" fill-opacity=".14"/><rect x="6" y="2.5" width="12" height="19" rx="3"/><path d="M10.5 5.5h3"/><path d="M10 18.5h4"/>',
  tablet: '<rect x="4" y="2.5" width="16" height="19" rx="2.8" fill="currentColor" fill-opacity=".14"/><rect x="4" y="2.5" width="16" height="19" rx="2.8"/><circle cx="12" cy="5.2" r=".75" fill="currentColor" stroke="none"/><path d="M9.5 18.5h5"/>',
  pc: '<path d="M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5V16H4V5.5Z" fill="currentColor" fill-opacity=".14"/><path d="M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5V16H4V5.5Z"/><path d="M2 16h20l-1.2 2.4a1.5 1.5 0 0 1-1.34.83H4.54a1.5 1.5 0 0 1-1.34-.83L2 16Z"/><path d="M10 16h4"/>',
  tv: '<rect x="2.5" y="4" width="19" height="12.5" rx="2.2" fill="currentColor" fill-opacity=".14"/><rect x="2.5" y="4" width="19" height="12.5" rx="2.2"/><path d="M8 20h8"/><path d="M12 16.5V20"/>',
  console: '<path d="M6.2 6h11.6a4.2 4.2 0 0 1 4.12 5.02l-.96 4.8a3.2 3.2 0 0 1-5.6 1.42L13.8 15.3h-3.6l-1.56 1.94a3.2 3.2 0 0 1-5.6-1.42l-.96-4.8A4.2 4.2 0 0 1 6.2 6Z" fill="currentColor" fill-opacity=".14"/><path d="M6.2 6h11.6a4.2 4.2 0 0 1 4.12 5.02l-.96 4.8a3.2 3.2 0 0 1-5.6 1.42L13.8 15.3h-3.6l-1.56 1.94a3.2 3.2 0 0 1-5.6-1.42l-.96-4.8A4.2 4.2 0 0 1 6.2 6Z"/><path d="M6.5 11h3M8 9.5v3"/><circle cx="15.5" cy="10" r=".85" fill="currentColor" stroke="none"/><circle cx="17.5" cy="12" r=".85" fill="currentColor" stroke="none"/>',
  iot: '<rect x="6" y="3" width="12" height="18" rx="5" fill="currentColor" fill-opacity=".14"/><rect x="6" y="3" width="12" height="18" rx="5"/><circle cx="12" cy="8.5" r="2"/><path d="M9.5 15.5a3.5 3.5 0 0 1 5 0"/><circle cx="12" cy="17.5" r=".75" fill="currentColor" stroke="none"/>',
  watch: '<rect x="6.5" y="6" width="11" height="12" rx="3.2" fill="currentColor" fill-opacity=".14"/><path d="M9 6 9.8 2.5h4.4L15 6"/><path d="m9 18 .8 3.5h4.4L15 18"/><rect x="6.5" y="6" width="11" height="12" rx="3.2"/><path d="M17.5 10v2"/><path d="M12 9.5V12l1.8 1.2"/>',
  router: '<rect x="3" y="13.5" width="18" height="6.5" rx="2.2" fill="currentColor" fill-opacity=".14"/><rect x="3" y="13.5" width="18" height="6.5" rx="2.2"/><path d="M7.5 13.5 6 6.5"/><path d="M16.5 13.5 18 6.5"/><path d="M9.5 8.5a3.8 3.8 0 0 1 5 0"/><circle cx="7.5" cy="16.8" r=".85" fill="currentColor" stroke="none"/><circle cx="11" cy="16.8" r=".85" fill="currentColor" stroke="none"/><path d="M15 16.8h2.5"/>'
};
function devSvg(k, cls) {
  var body = HNC_DEV_SVGS[k] || HNC_DEV_SVGS.router;
  return '<svg class="dev-svg' + (cls ? ' ' + cls : '') + '" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';
}

var HNC_BENTO_SVGS = {
  sqm: '<path d="M13.2 2.5 4.8 13.2h6.1l-.9 8.3 8.4-10.7h-6.1l.9-8.3Z" fill="currentColor" fill-opacity=".22"/><path d="M13.2 2.5 4.8 13.2h6.1l-.9 8.3 8.4-10.7h-6.1l.9-8.3Z"/>',
  appqos: '<polygon points="12 2.8 2.8 7.5 12 12.2 21.2 7.5 12 2.8" fill="currentColor" fill-opacity=".24"/><polygon points="12 2.8 2.8 7.5 12 12.2 21.2 7.5 12 2.8"/><path d="m2.8 12.2 9.2 4.7 9.2-4.7"/><path d="m2.8 16.8 9.2 4.7 9.2-4.7"/>',
  wl: '<path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z" fill="currentColor" fill-opacity=".20"/><path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z"/><path d="m8.8 12.1 2.2 2.2 4.4-4.6"/>',
  conns: '<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".18"/><circle cx="12" cy="12" r="9"/><path d="M12 12 18.2 5.8"/><path d="M16.2 12a4.2 4.2 0 1 1-4.2-4.2"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/>',
  leash: '<rect x="3" y="6.5" width="7.5" height="11" rx="3.6" fill="currentColor" fill-opacity=".20"/><rect x="13.5" y="6.5" width="7.5" height="11" rx="3.6" fill="currentColor" fill-opacity=".20"/><rect x="3" y="6.5" width="7.5" height="11" rx="3.6"/><rect x="13.5" y="6.5" width="7.5" height="11" rx="3.6"/><path d="M8.2 12h7.6"/>',
  thermo: '<path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z" fill="currentColor" fill-opacity=".22"/><path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z"/><circle cx="12" cy="17.5" r="1.5" fill="currentColor" stroke="none"/><path d="M16.8 6h2.2M16.8 9.5h1.6"/>'
};
function bentoSvg(k) {
  var body = HNC_BENTO_SVGS[k] || HNC_BENTO_SVGS.conns;
  return '<svg class="cc-svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';
}

var HNC_STUDIO_SVGS = {
  prism: '<polygon points="11.2 3.2 3.6 18.8 18.8 18.8" fill="var(--orb-c1,var(--blue))" fill-opacity=".16"/><polygon points="11.2 3.2 11.2 18.8 18.8 18.8" fill="var(--orb-c2,var(--purple))" fill-opacity=".20"/><path d="M1.8 12.2h4.7" stroke="var(--orb-c1,var(--blue))" stroke-width="1.85"/><path d="M15.1 9.8 20.8 6.8" stroke="var(--orb-c1,var(--blue))" stroke-width="1.65"/><path d="M16.3 12.6h4.9" stroke="var(--orb-c2,var(--purple))" stroke-width="1.65"/><path d="M17.3 15.4 21 17.4" stroke="var(--orb-c3,var(--green))" stroke-width="1.65"/><circle cx="21.3" cy="6.5" r="1.2" fill="var(--orb-c1,var(--blue))" stroke="none"/><circle cx="21.7" cy="12.6" r="1.2" fill="var(--orb-c2,var(--purple))" stroke="none"/><circle cx="21.4" cy="17.6" r="1.2" fill="var(--orb-c3,var(--green))" stroke="none"/><polygon points="11.2 3.2 3.6 18.8 18.8 18.8" stroke="var(--orb-c1,var(--blue))" stroke-width="1.75"/><path d="m6.5 12.2 8.6-2.4M6.5 12.2l9.8.4" stroke="var(--orb-c2,var(--purple))" stroke-width="1.3" stroke-opacity=".8"/>',
  discover: '<circle cx="12" cy="12" r="8.8" fill="var(--orb-c1,var(--blue))" fill-opacity=".13"/><polygon points="12 4.6 5.6 16.8 18.4 16.8" fill="var(--orb-c2,var(--purple))" fill-opacity=".18"/><polygon points="12 4.6 5.6 16.8 18.4 16.8" stroke="var(--orb-c1,var(--blue))" stroke-width="1.75"/><path d="M12 4.6v7.6m0 0-6.4 4.6m6.4-4.6 6.4 4.6" stroke="var(--orb-c2,var(--purple))" stroke-width="1.35" stroke-opacity=".82"/><circle cx="12" cy="12.2" r="1.6" fill="var(--orb-c1,var(--blue))" stroke="none"/><path d="m18.6 4.2.7 1.6 1.6.7-1.6.7-.7 1.6-.7-1.6-1.6-.7 1.6-.7.7-1.6Z" fill="var(--orb-c3,var(--green))" stroke="none"/>'
};
function studioSvg(k) {
  var body = HNC_STUDIO_SVGS[k] || HNC_STUDIO_SVGS.prism;
  return '<svg class="studio-svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';
}

var HNC_UI_SVGS = {
  mic: '<rect x="9" y="2.5" width="6" height="11" rx="3" fill="currentColor" fill-opacity=".18"/><rect x="9" y="2.5" width="6" height="11" rx="3"/><path d="M5.5 10.5a6.5 6.5 0 0 0 13 0M12 17v4m-3 0h6"/>',
  music: '<circle cx="8" cy="18" r="3" fill="currentColor" fill-opacity=".20"/><circle cx="18" cy="16" r="3" fill="currentColor" fill-opacity=".20"/><path d="M11 18V6l10-2v12"/><circle cx="8" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
  phone: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.12.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.58 2.81.7A2 2 0 0 1 22 16.92Z" fill="currentColor" fill-opacity=".18"/>',
  ban: '<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".14"/><circle cx="12" cy="12" r="9"/><path d="m5.7 5.7 12.6 12.6"/>',
  warn: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" fill="currentColor" fill-opacity=".16"/><path d="M12 9v4m0 4h.01"/>',
  check: '<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".16"/><path d="m8.4 12.4 2.3 2.3 4.9-5.1"/>',
  cross: '<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".15"/><path d="m9.3 9.3 5.4 5.4m0-5.4-5.4 5.4"/>',
  info: '<circle cx="12" cy="12" r="9" fill="currentColor" fill-opacity=".14"/><path d="M12 11v5m0-8h.01"/>',
  sparkles: '<path d="m12 3 1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3Z" fill="currentColor" fill-opacity=".20"/><path d="m19 15 .85 2 2 .85-2 .85-.85 2-.85-2-2-.85 2-.85.85-2ZM5.2 16.2l.65 1.5 1.5.65-1.5.65-.65 1.5-.65-1.5-1.5-.65 1.5-.65.65-1.5Z"/>',
  bolt: '<polygon points="13 2.5 3.8 13.5 11.8 13.5 10.8 21.5 20.2 10.5 12.2 10.5 13 2.5" fill="currentColor" fill-opacity=".20"/>',
  trend: '<path d="m3 17 6-6 4 4 8-8"/><path d="M15 7h6v6"/>',
  chart: '<rect x="3.5" y="12" width="4" height="8" rx="1" fill="currentColor" fill-opacity=".20"/><rect x="10" y="7.5" width="4" height="12.5" rx="1" fill="currentColor" fill-opacity=".20"/><rect x="16.5" y="4" width="4" height="16" rx="1" fill="currentColor" fill-opacity=".20"/><path d="M2.5 20h19"/>',
  traffic: '<path d="M4.2 18a9 9 0 1 1 15.6 0Z" fill="currentColor" fill-opacity=".15"/><path d="M4.2 18a9 9 0 1 1 15.6 0"/><path d="m12 13 3.8-3.8"/><circle cx="12" cy="13" r="1.4" fill="currentColor" stroke="none"/>',
  hourglass: '<path d="M6.5 3h11M6.5 21h11"/><path d="M7.5 3v3.8a4.5 4.5 0 0 0 2.1 3.8L12 12l-2.4 1.4a4.5 4.5 0 0 0-2.1 3.8V21h9v-3.8a4.5 4.5 0 0 0-2.1-3.8L12 12l2.4-1.4a4.5 4.5 0 0 0 2.1-3.8V3h-9Z" fill="currentColor" fill-opacity=".16"/>',
  merge: '<circle cx="6" cy="6" r="2.5" fill="currentColor" fill-opacity=".18"/><circle cx="6" cy="18" r="2.5" fill="currentColor" fill-opacity=".18"/><circle cx="18" cy="12" r="2.5" fill="currentColor" fill-opacity=".24"/><path d="M8.5 6.8c3.8.6 4.8 4.1 7 5.2m-7 5.2c3.8-.6 4.8-4.1 7-5.2"/>',
  isolate: '<circle cx="7" cy="12" r="2.6" fill="currentColor" fill-opacity=".18"/><circle cx="17" cy="12" r="2.6" fill="currentColor" fill-opacity=".18"/><circle cx="7" cy="12" r="2.6"/><circle cx="17" cy="12" r="2.6"/><path d="M12 4.5v15"/>'
};
function uiSvg(name, cls) {
  var body = HNC_UI_SVGS[name] || HNC_UI_SVGS.sparkles;
  return '<svg class="ui-ic' + (cls ? ' ' + cls : '') + '" data-ic="' + name + '" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';
}

var TYPE_T = { phone: '手机', tablet: '平板', pc: '电脑', tv: '电视 / 投屏', iot: '智能设备', console: '游戏机', watch: '手表' };
var TYPE_I = {
  phone: devSvg('phone'),
  tablet: devSvg('tablet'),
  pc: devSvg('pc'),
  tv: devSvg('tv'),
  iot: devSvg('iot'),
  console: devSvg('console'),
  watch: devSvg('watch')
};
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
  if (/watch|band|手环|手表/.test(s)) return devSvg('watch');
  if (/ipad|tablet|pad|平板|tab/.test(s)) return devSvg('tablet');
  if (/tv|电视|box|盒子|projector|投影/.test(s)) return devSvg('tv');
  if (/switch|nintendo|playstation|ps[45]|xbox|steam/.test(s)) return devSvg('console');
  if (/mac|book|laptop|thinkpad|surface|desktop|pc|windows|dell|lenovo|asus|acer|hp-|legion/.test(s)) return devSvg('pc');
  if (/phone|iphone|android|xiaomi|redmi|oppo|vivo|huawei|honor|realme|oneplus|samsung|meizu|nubia|iqoo|pixel|mi-|手机/.test(s)) return devSvg('phone');
  if (/miiot|aqara|yeelight|mijia|espressif|tuya|iot|smart|音箱|插座|灯|空调|扫地/.test(s)) return devSvg('iot');
  return devSvg('router');
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
  return String(hn || (isJunkName(d.name) ? '' : d.name) || d.vendor || mac || '');
}
function mapDevice(d) {
  var mac = String(d.mac || '').toLowerCase();
  var active = S.hotspot.active !== false;
  var name = devName(d, mac);
  var autoFrom = isMac(d.auto_inherited_from) ? String(d.auto_inherited_from).toLowerCase() : '';
  var mfList = Array.isArray(d.merged_from)
    ? d.merged_from.map(function (x) { return isMac(x) ? String(x).toLowerCase() : (x && isMac(x.old_mac) ? String(x.old_mac).toLowerCase() : ''); }).filter(Boolean)
    : (isMac(d.merged_from) ? [String(d.merged_from).toLowerCase()] : []);
  var mfPrimary = mfList[0] || autoFrom;
  var mfName = d.merged_from_name || (Array.isArray(d.merged_from) && d.merged_from[0] && d.merged_from[0].old_name) || d.auto_inherited_name || '';
  var o = {
    mac: mac, ip: d.ip || '', name: name, manual: d.hostname_src === 'manual', vendor: d.vendor || '', lastSeen: num(d.last_seen),
    blocked: d.status === 'blocked', online: (active || d.sim === true) && d.online === true,
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
    mergedFrom: mfPrimary,
    mergedFromList: mfList.length ? mfList : (mfPrimary ? [mfPrimary] : []),
    mergedFromName: String(mfName || ''),
    autoInhFrom: autoFrom,
    autoInhName: d.auto_inherited_name || '',
    autoInhScore: num(d.auto_inherited_score),
    rmacGuarded: false,
    rmacGuardMode: d.rmac_guard_mode || '',
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
  if (l && typeof l === 'object') {
    var bv = cleanVer(l.backend_version, '');
    if (bv) l.backend_version = bv; else delete l.backend_version;
    var bvc = cleanVer(l.backend_version_code, '');
    if (bvc) l.backend_version_code = bvc; else delete l.backend_version_code;
  }
  S.live = l; S.lastOk = Date.now(); S.connected = true;
  var act = l.hotspot_active; S.hotspot.active = typeof act === 'boolean' ? act : S.hotspot.active;
  S.hotspot.iface = l.hotspot_iface || l.iface || (S.hotspot.active === false ? '' : S.hotspot.iface);
  S.hotspot.ip = S.hotspot.active === false ? '' : (l.hotspot_ip || S.hotspot.ip);
  if (l && l.autorate && typeof l.autorate === 'object' && l.autorate.enabled !== false) {
    S.autorate = l.autorate;
    if (S.cfg) S.cfg.autorate = l.autorate;
  } else {
    S.autorate = null;
    if (S.cfg && S.cfg.autorate) {
      S.cfg.autorate = Object.assign({}, S.cfg.autorate, (l && l.autorate && typeof l.autorate === 'object') ? l.autorate : {}, { enabled: false, state: 'disabled', rtt_ms: 0, base_rtt_ms: 0, delta_rtt_ms: 0, cur_down_mbps: 0, cur_up_mbps: 0 });
    }
  }
  if (l && l.signal && typeof l.signal === 'object') {
    S.signal = l.signal;
    if (typeof ingestSignalSample === 'function') { try { ingestSignalSample(l.signal); } catch (_) {} }
    if (typeof paintSignalPill === 'function') paintSignalPill();
  }
  S.spark.push(num(l.rx_bps)); if (S.spark.length > 30) S.spark.shift();
  if (typeof renderOffloadBanner === 'function') renderOffloadBanner();
}
function loadLive(guardGen) {
  return api.get('/api/live', null, { timeout: 7000 }).then(function (l) {
    if (guardGen != null && (guardGen !== api.writeGen || api.writeInFlight > 0)) return S.live || l;
    applyLive(l);
    return l;
  });
}
function loadDevices(guardGen) {
  return api.get('/api/devices', null, { timeout: 8000 }).then(function (r) {
    if (guardGen != null && (guardGen !== api.writeGen || api.writeInFlight > 0)) return S.devices;
    return applyDevices(r);
  });
}
function applyDevices(r) {
  {
    if (typeof r.hotspot_active === 'boolean') S.hotspot.active = r.hotspot_active;
    if (S.hotspot.active === false) {
      S.hotspot.ip = '';
      if (!r.hotspot_iface) S.hotspot.iface = '';
    } else {
      if (r.hotspot_iface) S.hotspot.iface = r.hotspot_iface;
      if (r.hotspot_ip) S.hotspot.ip = r.hotspot_ip;
    }
    S.devices = (r.devices || []).map(mapDevice).sort(function (a, b) {
      // 稳定排序: 在线在前、封锁在后、再按名字 —— 不按实时速率, 否则每次轮询卡片都会跳来跳去
      return (b.online - a.online) || (a.blocked - b.blocked) || (a.online ? 0 : b.lastSeen - a.lastSeen) || a.name.localeCompare(b.name, 'zh-CN') || a.mac.localeCompare(b.mac);
    });
    S.devLoaded = true;
    // 后端有没有限速策略引擎(配额 / 分时段) —— 旧后端的设备行里没有 effective 字段, 此时不显示这两块
    S.polSupport = (r.devices || []).some(function (x) { return x && typeof x.effective === 'object' && x.effective; });
    if (r.devices_sig) S.sig = r.devices_sig;
    if (typeof renderOffloadBanner === 'function') renderOffloadBanner();
    return S.devices;
  }
}
/* 一次请求同时拿汇总和设备列表(本机桥接每个请求都要拉起一个 curl 进程) */
function loadLiveAndDevices(guardGen) {
  return api.get('/api/live', { devices: 1 }, { timeout: 8000 }).then(function (l) {
    if (guardGen != null && (guardGen !== api.writeGen || api.writeInFlight > 0)) return S.live || l;
    applyLive(l);
    if (Array.isArray(l.devices)) applyDevices(l); else return loadDevices(guardGen).then(function () { return l; });
    return l;
  });
}
function loadConfig(guardGen) {
  var reqGen = typeof guardGen === 'number' ? guardGen : api.writeGen;
  return api.get('/api/config').then(function (c) {
    if (reqGen != null && (reqGen !== api.writeGen || api.writeInFlight > 0)) return S.cfg;
    S.cfg = c || {};
    if (S.cfg.autorate && S.cfg.autorate.enabled === true) S.autorate = S.cfg.autorate;
    else S.autorate = null;
    if (typeof renderOffloadBanner === 'function') renderOffloadBanner();
    return S.cfg;
  });
}
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
function loadAppLimits(guardGen) {
  var reqGen = typeof guardGen === 'number' ? guardGen : api.writeGen;
  return api.getSafe('/api/app_limits', null, { items: [] }).then(function (r) {
    if (reqGen != null && (reqGen !== api.writeGen || api.writeInFlight > 0)) return S.appLimits;
    S.appLimits = (r && r.items) || [];
    // 逃生口「包含共享 CDN IP」; 旧后端没有这个字段 → 设置里不显示开关
    S.appLimitSharedKnown = !!(r && typeof r.include_shared_ips === 'boolean');
    S.appLimitShared = !!(r && r.include_shared_ips === true);
    if (typeof renderOffloadBanner === 'function') renderOffloadBanner();
    return S.appLimits;
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
  var q = S.alertCfg && S.alertCfg.enabled !== false && S.alertCfg.monthly_quota, lim = q && q.enabled ? num(q.limit_bytes) : 0;
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

/* === v5.38.0 Optical Duotone Vector SVG Icon System Active === */

/* ═════════════════════ v6.0.0 · Vector 聚合快路径 (/api/vector_sync) ═════════════════════
 * KSU 模式下单次调用同时喂饱顶栏健康度、四大隔离舱壁状态、实时速率与 v6 战术摘要;
 * 对轻量级 VectorDevice 列表做就地速率/在线态热补丁，不冲掉 /api/devices 的完整画像与配额字段;
 * 若旧后端返回 404/405/501 则无缝回退原有请求链，确保 100% 向后兼容。 */
var V6_SYNC_PATH = '/api/vector_sync';
function computeVecDevSig(arr) {
  if (!Array.isArray(arr)) return '';
  return arr.map(function (d) {
    return [String(d.mac || '').toLowerCase(), d.ip || '', d.online ? 1 : 0, d.status || '', d.limit_enabled ? 1 : 0, num(d.down_mbps), num(d.up_mbps), d.hostname || ''].join(':');
  }).join('|');
}
function patchVectorDevicesInPlace(arr) {
  if (!S.devLoaded || !Array.isArray(arr) || !Array.isArray(S.devices)) return false;
  var byMac = {};
  S.devices.forEach(function (d) { byMac[d.mac] = d; });
  for (var i = 0; i < arr.length; i++) {
    var vd = arr[i] || {}, mk = String(vd.mac || '').toLowerCase();
    if (!mk || !byMac[mk]) return false; // 发现新接入 MAC，需拉一次完整 /api/devices
  }
  var seen = {}, active = S.hotspot.active !== false;
  arr.forEach(function (vd) {
    var mk = String(vd.mac || '').toLowerCase(), d = byMac[mk];
    if (!d) return;
    seen[mk] = 1;
    d.ip = vd.ip || '';
    var isSim = d.sim === true || vd.sim === true;
    d.online = (active || isSim) && vd.online === true;
    d.blocked = vd.status === 'blocked';
    d.rx = d.online ? num(vd.rx_bps) : 0;
    d.tx = d.online ? num(vd.tx_bps) : 0;
  });
  S.devices.forEach(function (d) {
    if (!seen[d.mac] && !d.sim) { d.online = false; d.rx = 0; d.tx = 0; }
  });
  return true;
}
function applyVectorSyncPayload(r) {
  if (!r || typeof r !== 'object') return {};
  var got = { health: false, live: false, devices: false, cfg: false, caps: false, alerts: false, offload: false, appLimits: false, templates: false };
  if (typeof r.healthy === 'boolean') S.coreHealthy = r.healthy;
  if (r.core_uptime_sec != null) S.coreUptimeSec = num(r.core_uptime_sec);
  if (r.bulkheads && typeof r.bulkheads === 'object') S.bulkheads = r.bulkheads;

  var hObj = (r.health && typeof r.health === 'object') ? r.health : null;
  if (hObj || r.rollback || typeof r.healthy === 'boolean') {
    var hv = cleanVer((hObj && hObj.backend_version) || r.version || r.backend_version, '');
    S.lastHealth = hObj ? Object.assign({}, hObj, { backend_version: cleanVer(hObj.backend_version, hv) }) : { ok: r.healthy !== false, rollback: r.rollback, backend_version: hv };
    got.health = true;
  }
  var lvObj = (r.live && typeof r.live === 'object') ? r.live : ((r.rx_bps !== undefined || r.hotspot_active !== undefined) ? r : null);
  var rawDevArr = Array.isArray(r.devices) ? r.devices
    : (r.devices && typeof r.devices === 'object' && Array.isArray(r.devices.devices) ? r.devices.devices
    : (lvObj && Array.isArray(lvObj.devices) ? lvObj.devices : null));

  if (lvObj) {
    var verStr = cleanVer((hObj && hObj.backend_version) || r.version || r.backend_version, '');
    if (verStr && !cleanVer(lvObj.backend_version, '')) lvObj.backend_version = verStr;
    var verCode = cleanVer((hObj && (hObj.backend_version_code || hObj.version_code)) || r.version_code || r.backend_version_code, '');
    if (verCode && !cleanVer(lvObj.backend_version_code, '')) lvObj.backend_version_code = verCode;
    if (rawDevArr && !lvObj.devices_sig) {
      var vSig = computeVecDevSig(rawDevArr);
      if (S.vecDevSig && S.vecDevSig !== vSig) lvObj.devices_sig = 'vsync:' + vSig;
      S.vecDevSig = vSig;
    }
    applyLive(lvObj);
    got.live = true;
  }
  if (rawDevArr) {
    var hasFullMeta = rawDevArr.some(function (x) {
      return x && (x.ident !== undefined || x.effective !== undefined || x.dpi_apps !== undefined || x.sqm_enabled !== undefined || x.delay_ms !== undefined);
    });
    if (hasFullMeta) {
      applyDevices({
        devices: rawDevArr,
        devices_sig: r.devices_sig || (lvObj && lvObj.devices_sig) || '',
        hotspot_active: lvObj ? lvObj.hotspot_active : r.hotspot_active,
        hotspot_iface: lvObj ? (lvObj.hotspot_iface || lvObj.iface) : r.hotspot_iface,
        hotspot_ip: lvObj ? lvObj.hotspot_ip : r.hotspot_ip
      });
      got.devices = true;
    } else if (patchVectorDevicesInPlace(rawDevArr)) {
      got.devices = true;
    }
  }
  var cfgObj = r.config || r.cfg;
  if (cfgObj && typeof cfgObj === 'object') {
    S.cfg = cfgObj;
    if (S.cfg.autorate && S.cfg.autorate.enabled === true) S.autorate = S.cfg.autorate;
    else if (!got.live) S.autorate = null;
    got.cfg = true;
  }
  var capObj = r.capabilities || r.caps;
  if (capObj && typeof capObj === 'object') {
    S.caps = capObj.capabilities || (capObj.available === false ? {} : capObj) || {};
    S.capsLoaded = true;
    if (capObj.qdisc_caps && typeof capObj.qdisc_caps === 'object') S.qcaps = capObj.qdisc_caps;
    else if (r.qdisc_caps && typeof r.qdisc_caps === 'object') S.qcaps = r.qdisc_caps;
    got.caps = true;
  }
  if (r.alerts && typeof r.alerts === 'object') {
    S.alerts = { unread: num(r.alerts.unread), list: Array.isArray(r.alerts.alerts) ? r.alerts.alerts : (Array.isArray(r.alerts.list) ? r.alerts.list : []) };
    var bEl = $('#bell-n');
    if (bEl) { bEl.hidden = !S.alerts.unread; bEl.textContent = S.alerts.unread > 99 ? '99+' : S.alerts.unread; }
    got.alerts = true;
  }
  var offObj = r.offload_status || r.offload;
  if (offObj && typeof offObj === 'object') {
    S.offload = { active: offObj.active === true, detail: offObj.detail || '', guard: offObj.offload_guard || offObj.guard || null };
    if (typeof renderOffloadBanner === 'function') renderOffloadBanner();
    got.offload = true;
  }
  if (r.app_limits && typeof r.app_limits === 'object') {
    S.appLimits = Array.isArray(r.app_limits.items) ? r.app_limits.items : (Array.isArray(r.app_limits) ? r.app_limits : []);
    if (typeof r.app_limits.include_shared_ips === 'boolean') {
      S.appLimitSharedKnown = true;
      S.appLimitShared = r.app_limits.include_shared_ips === true;
    }
    got.appLimits = true;
  }
  if (r.templates && typeof r.templates === 'object') {
    var tList = [], tSeen = {};
    Object.keys(r.templates).forEach(function (n) {
      var t = r.templates[n] || {}; tSeen[n] = 1;
      tList.push({ name: n, down: num(t.down_mbps), up: num(t.up_mbps), delay: num(t.delay_ms), jitter: num(t.jitter_ms), loss: num(t.loss_pct) });
    });
    if (tList.length) S.templates = tList;
    got.templates = true;
  }
  if (typeof v6IngestVectorSync === 'function') {
    try { v6IngestVectorSync(r); } catch (_) {}
  }
  return got;
}

function loadVectorSync(params, guardGen) {
  if (S.vectorSyncState === 'unsupported') {
    var uErr = new Error('vector_sync unsupported');
    uErr.status = 404;
    uErr.isVectorSyncUnsupported = true;
    return Promise.reject(uErr);
  }
  return api.get(V6_SYNC_PATH, params || null, { timeout: 8000 }).then(function (r) {
    S.vectorSyncState = 'supported';
    if (guardGen != null && (guardGen !== api.writeGen || api.writeInFlight > 0)) {
      return { raw: r, got: {}, stale: true, live: S.live || r.live || r };
    }
    var got = applyVectorSyncPayload(r);
    return { raw: r, got: got, live: S.live || r.live || r };
  }, function (e) {
    if (e && (e.status === 404 || e.status === 405 || e.status === 501)) {
      S.vectorSyncState = 'unsupported';
      e.isVectorSyncUnsupported = true;
    }
    throw e;
  });
}

if (typeof window !== 'undefined' && typeof window.openV6Subtab !== 'function') {
  window.openV6Subtab = function (tab, opts) {
    window.__pendingV6Subtab = { tab: tab || 'escort', opts: opts || null };
    if (typeof go === 'function') go('vector');
  };
}

