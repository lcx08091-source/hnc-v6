/* HNC WebUI · fx.js —— 动效: 弹簧曲线、低端机自动降级(PERF)、可打断弹簧(Spring)与弹层背景缩放、动画开关(FX)、主题/风格应用(applyTheme)、液态玻璃(Hyalite)挂载、大标题滚动 */
'use strict';

/* ═════════════════════ 弹簧曲线(所有动画共用) ═════════════════════ */
function springCurve(zeta, omega, ms) {
  var wd = omega * Math.sqrt(1 - zeta * zeta), pts = [], n = 48;
  for (var i = 0; i <= n; i++) {
    var t = i / n * ms / 1000;
    pts.push(+(1 - Math.exp(-zeta * omega * t) * (Math.cos(wd * t) + zeta * omega / wd * Math.sin(wd * t))).toFixed(4));
  }
  pts[n] = 1;
  return 'linear(' + pts.join(',') + ')';
}
var EASE = { q:'cubic-bezier(.34,1.56,.64,1)', soft:'cubic-bezier(.32,.72,0,1)' };
(function () {
  var q = springCurve(.42, 15, 800), s = springCurve(.72, 16, 600);
  try {
    if (window.CSS && CSS.supports('transition-timing-function', q)) {
      EASE.q = q; EASE.soft = s;
      document.documentElement.style.setProperty('--q', q);
      document.documentElement.style.setProperty('--q-soft', s);
    }
  } catch (_) {}
})();
function motionOn() { return !calm && !document.documentElement.classList.contains('calm'); }
function anim(el, frames, opt) {
  if (!el || !el.animate || !motionOn()) return null;
  try { return el.animate(frames, Object.assign({ duration: 700, easing: EASE.q }, opt)); } catch (_) { return null; }
}
function stagger(root, max) {
  var kids = root ? root.children : [];
  if (typeof fxOn === 'function' && !fxOn('list')) return;
  if (document.documentElement.getAttribute('data-style') === 'apple') {   // 苹果风 —— 每行 30ms, 最多 8 行(低端机 4 行)
    var m = document.documentElement.classList.contains('lowfx') ? 4 : 8;
    for (var j = 0; j < kids.length && j < m; j++) anim(kids[j], [{ opacity: .25, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { delay: j * 24, duration: 420, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards' });
    return;
  }
  for (var i = 0; i < kids.length && i < (max || 14); i++) anim(kids[i], [{ opacity: .2, transform: 'translateY(16px) scale(.97)' }, { opacity: 1, transform: 'none' }], { delay: i * 32, duration: 560, fill: 'backwards' });
}
function tween(el, to, dec) {
  if (!el) return;
  // 「数字滚动」可关; 苹果风 400ms
  var numOn = typeof fxOn !== 'function' || fxOn('num'), ap = document.documentElement.getAttribute('data-style') === 'apple';
  var from = parseFloat(el.textContent) || 0, t0 = performance.now(), dur = motionOn() && numOn ? (ap ? 400 : 700) : 0;
  if (!dur || Math.abs(to - from) < Math.pow(10, -dec)) { el.textContent = Number(to).toFixed(dec); return; }
  (function step(t) {
    var k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 4);
    el.textContent = (from + (to - from) * e).toFixed(dec);
    if (k < 1) requestAnimationFrame(step);
  })(t0);
}

/* ═════════════════════ 低端机自动降级 ═════════════════════
   启动时测 40 帧; 运行中每段弹簧动画统计掉帧(>34ms 的帧占比 >35%), 连续两段掉帧就自动简化:
   关掉毛玻璃、背景缩放、共享元素展开, 列表浮现只做前 4 行。可在 设置 → 外观 里恢复。 */
// hnc6.lowfx: '1' 已简化 · '0' 用户选了完整(不再自动降级) · '' 自动
var PERF = { low: LS.get('hnc6.lowfx', '') === '1', auto: LS.get('hnc6.lowfx', '') === '', frames: 0, slow: 0, strikes: 0, probe: '' };
function lowFx() { return PERF.low; }
function perfFrame(dt) { PERF.frames++; if (dt > 34) PERF.slow++; }
function perfEnd() {
  if (PERF.frames >= 12) { if (PERF.slow / PERF.frames > .35) PERF.strikes++; else PERF.strikes = Math.max(0, PERF.strikes - 1); if (PERF.strikes >= 2 && !PERF.low && PERF.auto) setLowFx(true, true); }
  PERF.frames = PERF.slow = 0;
}
function setLowFx(on, auto) {
  PERF.low = !!on; if (!auto) PERF.auto = false; LS.set('hnc6.lowfx', on ? '1' : (PERF.auto ? '' : '0')); document.documentElement.classList.toggle('lowfx', !!on);
  if (typeof liquidGlass === 'function') liquidGlass();
  if (auto && on) setTimeout(function () { toast('检测到掉帧，已自动简化动画（可在 设置 → 外观 恢复）', 'warn'); }, 50);
}
document.documentElement.classList.toggle('lowfx', PERF.low);
(function probe() {
  if (PERF.low || !PERF.auto || !window.requestAnimationFrame) return;
  var n = 0, t0 = 0, slow = 0, last = 0;
  requestAnimationFrame(function f(t) {
    if (last) { if (t - last > 28) slow++; n++; } else t0 = t;
    last = t;
    if (n < 40) { requestAnimationFrame(f); return; }
    var avg = (t - t0) / n, weak = (navigator.hardwareConcurrency || 8) <= 4 && (navigator.deviceMemory || 8) <= 2;
    PERF.probe = Math.round(1000 / avg) + ' fps';
    if (avg > 26 || slow > 12 || weak) setLowFx(true, false);
  });
})();

/* ═════════════════════ 可打断的弹簧 + 苹果风弹层 ═════════════════════
   Spring: 半隐式欧拉积分(每帧 4 个子步), go() 中途改目标时保留当前速度 → 动画可随时打断、衔接连贯。
   苹果风弹层: 弹层 y 与背景缩放各一根弹簧; 跟手下拉时两者联动, 松手按手指速度回弹或关闭。 */
function Spring(p, onFrame, onRest) { this.k = p.k; this.c = p.c; this.x = 0; this.v = 0; this.to = 0; this.raf = 0; this.last = 0; this.onFrame = onFrame; this.onRest = onRest; this.eps = .5; }
Spring.prototype.set = function (x) { this.stop(); this.x = this.to = x; this.v = 0; this.onFrame(x); };
Spring.prototype.stop = function () { if (this.raf) cancelAnimationFrame(this.raf); this.raf = 0; this.last = 0; };
Spring.prototype.go = function (to, v, p) {
  this.to = to; if (v != null) this.v = v; if (p) { this.k = p.k; this.c = p.c; }
  if (!motionOn()) { this.x = to; this.v = 0; this.onFrame(to); this.stop(); if (this.onRest) this.onRest(); return; }
  if (!this.raf) { var me = this; this.raf = requestAnimationFrame(function f(t) { me.step(t); }); }
};
Spring.prototype.step = function (t) {
  var dt = this.last ? Math.min(.034, (t - this.last) / 1000) : 1 / 60, n = 4, h = dt / n, me = this;
  if (this.last) perfFrame(t - this.last);
  this.last = t;
  for (var i = 0; i < n; i++) { this.v += (-this.k * (this.x - this.to) - this.c * this.v) * h; this.x += this.v * h; }
  if (Math.abs(this.x - this.to) < this.eps && Math.abs(this.v) < this.eps * 10) {
    this.x = this.to; this.v = 0; this.onFrame(this.x); this.raf = 0; this.last = 0; perfEnd(); if (this.onRest) this.onRest(); return;
  }
  this.onFrame(this.x);
  this.raf = requestAnimationFrame(function f(t2) { me.step(t2); });
};
function springP() { return SPRING[FX.spring] || SPRING.light; }
function appleSheet() { return apple() && fxOn('sheet'); }
var SM = { open: false, closing: false, h: 600 };
var bgEls = function () { return [document.querySelector('.header'), document.getElementById('pages'), document.getElementById('tabbar')]; };
// 背景缩放: p=1 完全打开(缩到 0.94、变暗), p=0 复原。以视口中心为原点缩放 —— 顶栏/页面/底栏各自的
// transform-origin 换算到同一个视口中心(用 offsetLeft/Top: 不含 transform 的布局位置)
function bgOrigins() {
  var cx = innerWidth / 2, cy = innerHeight / 2;
  bgEls().forEach(function (el) { if (el) el.style.transformOrigin = (cx - el.offsetLeft) + 'px ' + (cy - el.offsetTop) + 'px'; });
}
var bgSpring = new Spring({ k: 300, c: 30 }, function (p) {
  p = Math.max(0, p);
  var sc = 1 - .06 * Math.min(1, p), on = p > .002, r = document.documentElement;
  bgEls().forEach(function (el) { if (el) el.style.scale = on ? sc.toFixed(4) : ''; });
  r.classList.toggle('bgscaled', on);
  r.style.setProperty('--bgp', Math.min(1, p).toFixed(3));
  $('#scrim').style.opacity = on ? Math.min(1, p).toFixed(3) : '';
}, null);
bgSpring.eps = .002;
var shSpring = new Spring({ k: 300, c: 30 }, function (y) { $('#sheet').style.transform = 'translate(-50%,' + y.toFixed(1) + 'px)'; }, function () {
  if (SM.closing) {
    var sh = $('#sheet'); SM.closing = false; sh.classList.remove('closing'); sh.style.transform = ''; sh.style.transition = '';
  }
});

/* ═════════════════════ 动画效果(可逐项选择) ═════════════════════
   title/haptic 不算"动画"(滚动驱动 / 震动), 不受「界面动画」总开关和系统「减少动态效果」影响;
   其余效果在总开关关闭或系统要求减少动态效果时一律停用。 */
var FX_LIST = [
  ['title', '大标题收起', '滚动时大标题收成顶栏居中小标题（苹果风）'],
  ['page', '页面切换', '切换标签时新页面原地轻快淡入'],
  ['sheet', '弹层背景缩放', '弹层弹出时背后页面缩小变暗，可跟手下拉（苹果风）'],
  ['morph', '共享元素展开', '弹层从你刚点的那一行 / 卡片里长出来（苹果风）'],
  ['press', '按压回弹', '按下缩小到 0.97，松手弹回'],
  ['list', '列表浮现', '进入页面时逐行错开浮现'],
  ['num', '数字滚动', '速率、流量等数字滚动过渡'],
  ['haptic', '触感反馈', '开关、长按、确认时轻震一下']
];
var FX_PRESETS = {
  calm: { title: true, page: true, sheet: true, morph: false, press: true, list: false, num: true, haptic: true, spring: 'light' },
  std: { title: true, page: true, sheet: true, morph: true, press: true, list: true, num: true, haptic: true, spring: 'light' },
  lively: { title: true, page: true, sheet: true, morph: true, press: true, list: true, num: true, haptic: true, spring: 'bouncy' }
};
var FX = (function () {
  var d = Object.assign({}, FX_PRESETS.std), o = null;
  try { o = JSON.parse(LS.get('hnc6.fx', '') || 'null'); } catch (_) {}
  if (o && typeof o === 'object') FX_LIST.forEach(function (x) { if (typeof o[x[0]] === 'boolean') d[x[0]] = o[x[0]]; });
  if (o && (o.spring === 'light' || o.spring === 'bouncy')) d.spring = o.spring;
  return d;
})();
function saveFx() { LS.set('hnc6.fx', JSON.stringify(FX)); }
function fxOn(k) { if (k === 'title' || k === 'haptic') return FX[k] !== false; return motionOn() && FX[k] !== false; }
function fxPreset() {
  if (!S.motion) return 'off';
  for (var n in FX_PRESETS) { var p = FX_PRESETS[n], same = p.spring === FX.spring; FX_LIST.forEach(function (x) { if (p[x[0]] !== FX[x[0]]) same = false; }); if (same) return n; }
  return 'custom';
}
function haptic(ms) { if (fxOn('haptic') && navigator.vibrate) try { navigator.vibrate(ms || 10); } catch (_) {} }
/* 弹簧参数 → CSS linear() 曲线。轻: stiffness 300 / damping 30; 弹: 200 / 20(质量 1) */
var SPRING = { light: { k: 300, c: 30 }, bouncy: { k: 200, c: 20 } };
function springKC(p) {
  var w = Math.sqrt(p.k), z = p.c / (2 * w), ms = clamp(Math.log(1000) / (z * w) * 1000, 300, 1200);
  return { curve: springCurve(z, w, ms), ms: Math.round(ms) };
}
var EASE0 = { q: EASE.q, soft: EASE.soft };
function applyMotion() {
  var r = document.documentElement, q = EASE0.q, soft = EASE0.soft;
  if (apple()) { q = springKC(SPRING[FX.spring] || SPRING.light).curve; soft = springKC(SPRING.light).curve; }
  try {
    if (!window.CSS || !CSS.supports('transition-timing-function', q)) return;
    EASE.q = q; EASE.soft = soft; r.style.setProperty('--q', q); r.style.setProperty('--q-soft', soft);
  } catch (_) {}
  r.classList.toggle('fx-nopress', !fxOn('press'));
  // 弹层开着时关掉了动画 / 切回默认风格: 背景立即复原, 弹层交回 CSS 控制
  if (SM.open && !appleSheet()) { SM.open = false; shSpring.stop(); bgSpring.set(0); var sh = document.getElementById('sheet'); sh.style.transform = ''; sh.style.transition = ''; }
}
function applyTheme() {
  var r = document.documentElement;
  if (S.theme === 'light' || S.theme === 'dark') r.setAttribute('data-theme', S.theme); else r.removeAttribute('data-theme');
  // 界面风格(默认 / 苹果风)。只切视觉与动效, 逻辑共用
  if (apple()) r.setAttribute('data-style', 'apple'); else r.removeAttribute('data-style');
  if (S.style === 'liquid') r.setAttribute('data-glass', 'liquid'); else r.removeAttribute('data-glass');
  if (typeof liquidGlass === 'function') liquidGlass();
  applyGlassTint();
  r.classList.toggle('calm', !S.motion);
  applyMotion();
}
/* 玻璃浓度(液态玻璃专用, 0 清透 … 50 标准 … 100 着色) → <html> 上的 --gx-up / --gx-dn(liquid.css 头注释);
   标准档两个都删掉 = 旧版数值。与 index.html 首帧脚本同一算法 */
function glassTintVars(v) { v = clamp(num(v, 50), 0, 100); return { up: v > 50 ? (v - 50) / 50 : 0, dn: v < 50 ? (50 - v) / 50 : 0 }; }
function applyGlassTint(v) {
  var r = document.documentElement, g = glassTintVars(v == null ? S.glassTint : v);
  if (g.up) r.style.setProperty('--gx-up', g.up.toFixed(3)); else r.style.removeProperty('--gx-up');
  if (g.dn) r.style.setProperty('--gx-dn', g.dn.toFixed(3)); else r.style.removeProperty('--gx-dn');
}
var GX_T = [[10, '清透'], [40, '偏清透'], [60, '标准'], [90, '偏着色'], [101, '着色']];
function glassTintLabel(v) { for (var i = 0; i < GX_T.length; i++) if (v < GX_T[i][0]) return GX_T[i][1]; return '着色'; }
function apple() { return S.style === 'apple' || S.style === 'liquid'; }
/* 液态玻璃: 功能层元素挂 Hyalite 真折射(按各自尺寸生成折射贴图); 其它风格 / 低端机 / 非 Chromium 摘掉, 退回 CSS 磨砂。
   v5.30: shade(边缘暗边)、rim(边缘反光)、edge(CSS 描边)各加一档 —— iOS 27 的「暗边 + 更亮高光」, 元素和背景分得更开 */
var LG_OPTS = {
  tabbar: { bevel: 20, thickness: 34, slope: .9, shape: 'squircle', blur: 2.2, dispersion: 1.8, shade: .3, rim: 1.8, edgeW: 2, edge: 1, light: -30, sat: 1.1, materialize: 420, settle: 120 },
  hbtn: { bevel: 20, thickness: 22, shape: 'squircle', blur: 1.2, dispersion: 1.6, shade: .32, rim: 1.9, edge: 1.05, light: -30, materialize: 420 },
  sheet: { bevel: 26, thickness: 42, slope: .9, shape: 'squircle', blur: 16, dispersion: 1.4, shade: .24, rim: 1.6, edge: 1, light: -30, sat: 1.1, settle: 160 },
  toast: { bevel: 16, thickness: 22, shape: 'squircle', blur: 10, dispersion: 1.2, shade: .24, rim: 1.5, edge: 1, light: -30 }
};
var lgOn = false;
function lgTargets() { return [['tabbar', $('#tabbar')], ['hbtn', $('#bell')], ['hbtn', $('#theme-btn')], ['sheet', $('#sheet')], ['toast', $('#toast')]]; }
function liquidGlass() {
  var want = S.style === 'liquid' && !!window.Hyalite && !(typeof PERF !== 'undefined' && PERF.low);
  if (want === lgOn || !window.Hyalite) return;
  lgOn = want;
  lgTargets().forEach(function (t) { if (!t[1]) return; try { if (want) Hyalite.attach(t[1], LG_OPTS[t[0]]); else Hyalite.detach(t[1]); } catch (_) {} });
}
/* 大标题滚动插值 —— --lt 大标题淡出缩小, --st 顶栏小标题浮现, --hp 顶栏毛玻璃出现 */
var NAV_T = { devices: '设备', apps: '应用', stats: '分析', settings: '设置' }, navRaf = 0;
function navSync() {
  var hdr = document.querySelector('.header'), ht = document.getElementById('htitle'); if (!hdr || !ht) return;
  ht.textContent = NAV_T[S.page] || '';
  var pg = document.getElementById('p-' + S.page), y = pg ? pg.scrollTop : 0, on = apple() && fxOn('title');
  document.documentElement.classList.toggle('fx-notitle', apple() && !fxOn('title'));
  var lt = on ? clamp(y / 44, 0, 1) : 1, st = on ? clamp((y - 28) / 14, 0, 1) : 1, hp = on ? clamp((y - 4) / 26, 0, 1) : 1;
  if (pg) pg.style.setProperty('--lt', lt.toFixed(3));
  hdr.style.setProperty('--st', st.toFixed(3)); hdr.style.setProperty('--hp', hp.toFixed(3));
  // --hs 液态玻璃顶栏变实底(liquid.css): 大标题收起后内容才算滚到顶栏下面; 没有大标题时滚一点就算
  var hs = clamp((y - (on ? 56 : 8)) / 20, 0, 1);
  hdr.style.setProperty('--hs', hs.toFixed(3)); hdr.classList.toggle('hs-on', hs > 0);
}
document.addEventListener('scroll', function (e) {
  if (!apple() || !e.target.classList || !e.target.classList.contains('page')) return;
  if (!navRaf) navRaf = requestAnimationFrame(function () { navRaf = 0; navSync(); });
}, true);
applyTheme();

