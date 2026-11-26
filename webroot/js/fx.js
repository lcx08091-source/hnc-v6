/* HNC WebUI · fx.js —— 动效与物理引擎: 四大视觉模式(Liquid / Frosted / Default / Cyber)专属 120fps 曲线与弹簧矩阵、低端机自动降级(PERF)、可打断弹簧(Spring)、动画开关(FX)、主题应用(applyTheme)、液态玻璃(Hyalite)挂载、大标题滚动 */
'use strict';

/* ═════════════════════ 弹簧曲线与四大视觉模式物理矩阵 ═════════════════════ */
function springCurve(zeta, omega, ms) {
  var wd = omega * Math.sqrt(1 - zeta * zeta), pts = [], n = 48;
  for (var i = 0; i <= n; i++) {
    var t = i / n * ms / 1000;
    pts.push(+(1 - Math.exp(-zeta * omega * t) * (Math.cos(wd * t) + zeta * omega / wd * Math.sin(wd * t))).toFixed(4));
  }
  pts[n] = 1;
  return 'linear(' + pts.join(',') + ')';
}
var _HAS_LINEAR = false;
try { _HAS_LINEAR = !!(window.CSS && CSS.supports && CSS.supports('transition-timing-function', 'linear(0, 1)')); } catch (_) {}
var _CY_EASE = _HAS_LINEAR ? 'linear(0, 0.78 38%, 0.96 72%, 1)' : 'cubic-bezier(.08,.94,.16,1)';

var EASE = { q: 'cubic-bezier(.22,1.26,.36,1)', soft: 'cubic-bezier(.20,.96,.32,1)' };

function motionTheme() {
  var r = document.documentElement;
  if (!r || !r.getAttribute) return 'default';
  var g = r.getAttribute('data-glass');
  if (g === 'liquid') return 'liquid';
  if (g === 'frosted') return 'frosted';
  if (r.getAttribute('data-style') === 'cyber') return 'cyber';
  return 'default';
}

function themePhys(mode) {
  var m = mode || motionTheme(), bouncy = typeof FX !== 'undefined' && FX.spring === 'bouncy';
  if (m === 'liquid') {
    return {
      mode: 'liquid',
      q: bouncy ? 'cubic-bezier(.22,1.34,.36,1)' : 'cubic-bezier(.22,1.26,.36,1)',
      soft: 'cubic-bezier(.20,.96,.32,1)',
      lens: { k: bouncy ? 480 : 550, c: bouncy ? 34 : 39.5, dk: 960, dc: 60, sk: 520, sc: 32, tapV: 1.18, dragS: 1.042, maxSp: .068, dragSp: .084, sqRatio: .46, wallBounce: .52, rigid: false },
      sheet: { k: bouncy ? 290 : 340, c: bouncy ? 27 : 32.5 },
      foldMs: 320,
      page: { dur: 250, step: 18, y: 9, scale: .992, op: .62, ease: 'cubic-bezier(.20,.96,.32,1)', scan: false },
      stagger: { max: 10, delay: 24, dur: 350, y: 11, scale: .988, op: .26, ease: 'cubic-bezier(.20,.96,.32,1)' },
      seg: { mode: 'liquid', dur: 320, ease: 'cubic-bezier(.22,1,.36,1)' },
      numDur: 380,
      numSteps: 0
    };
  }
  if (m === 'frosted') {
    return {
      mode: 'frosted',
      q: bouncy ? 'cubic-bezier(.24,1.06,.36,1)' : 'cubic-bezier(.25,1,.38,1)',
      soft: 'cubic-bezier(.25,.94,.35,1)',
      lens: { k: 680, c: 50, dk: 980, dc: 62, sk: 680, sc: 50, tapV: .42, dragS: 1.02, maxSp: .020, dragSp: .028, sqRatio: .35, wallBounce: 0, rigid: false },
      sheet: { k: 400, c: 39 },
      foldMs: 270,
      page: { dur: 215, step: 15, y: 6, scale: 1, op: .68, ease: 'cubic-bezier(.25,1,.38,1)', scan: false },
      stagger: { max: 8, delay: 20, dur: 280, y: 8, scale: 1, op: .32, ease: 'cubic-bezier(.25,1,.38,1)' },
      seg: { mode: 'frosted', dur: 250, ease: 'cubic-bezier(.25,1,.38,1)' },
      numDur: 300,
      numSteps: 0
    };
  }
  if (m === 'cyber') {
    return {
      mode: 'cyber',
      q: _CY_EASE,
      soft: 'cubic-bezier(.10,.92,.18,1)',
      lens: { k: 1480, c: 79, dk: 1680, dc: 84, sk: 1400, sc: 76, tapV: 0, dragS: 1, maxSp: 0, dragSp: 0, sqRatio: 0, wallBounce: 0, rigid: true },
      sheet: { k: 1120, c: 68.5 },
      foldMs: 135,
      page: { dur: 130, step: 8, y: 3.5, scale: 1, op: .78, ease: 'cubic-bezier(.08,.94,.16,1)', scan: true },
      stagger: { max: 12, delay: 12, dur: 130, y: 4, scale: 1, op: .45, ease: 'cubic-bezier(.08,.94,.16,1)' },
      seg: { mode: 'cyber', dur: 125, ease: 'cubic-bezier(.08,.94,.16,1)' },
      numDur: 135,
      numSteps: 4
    };
  }
  return {
    mode: 'default',
    q: 'cubic-bezier(.16,1,.3,1)',
    soft: 'cubic-bezier(.16,1,.3,1)',
    lens: { k: 960, c: 62, dk: 1160, dc: 68, sk: 980, sc: 63, tapV: -.38, dragS: .99, maxSp: 0, dragSp: 0, sqRatio: 0, wallBounce: 0, rigid: false },
    sheet: { k: 660, c: 51.5 },
    foldMs: 185,
    page: { dur: 175, step: 10, y: 4.5, scale: 1, op: .74, ease: 'cubic-bezier(.16,1,.3,1)', scan: false },
    stagger: { max: 10, delay: 15, dur: 180, y: 5, scale: 1, op: .38, ease: 'cubic-bezier(.16,1,.3,1)' },
    seg: { mode: 'default', dur: 175, ease: 'cubic-bezier(.16,1,.3,1)' },
    numDur: 180,
    numSteps: 0
  };
}

// 实时响应系统级「减少动态效果」切换，无需刷新页面即刻降级/恢复
try {
  var _rmMQ = matchMedia('(prefers-reduced-motion: reduce)');
  var _syncCalm = function (e) {
    calm = !!e.matches;
    if (typeof applyMotion === 'function') applyMotion();
  };
  if (_rmMQ.addEventListener) _rmMQ.addEventListener('change', _syncCalm);
  else if (_rmMQ.addListener) _rmMQ.addListener(_syncCalm);
} catch (_) {}

function motionOn() {
  return !calm && !document.documentElement.classList.contains('calm') && (typeof S === 'undefined' || S.motion !== false);
}
function anim(el, frames, opt) {
  if (!el || !el.animate || !motionOn()) return null;
  var tp = themePhys();
  try { return el.animate(frames, Object.assign({ duration: tp.page.dur, easing: tp.q }, opt)); } catch (_) { return null; }
}
function stagger(root, max) {
  var kids = root ? root.children : [];
  if (!motionOn() || (typeof fxOn === 'function' && !fxOn('list'))) return;
  var tp = themePhys(), sp = tp.stagger;
  var cap = document.documentElement.classList.contains('lowfx') ? 4 : Math.min(max || sp.max, sp.max);
  var startTf = 'translate3d(0,' + sp.y + 'px,0)' + (sp.scale !== 1 ? ' scale(' + sp.scale + ')' : '');
  for (var i = 0; i < kids.length && i < cap; i++) {
    var el = kids[i];
    if (el.hidden) continue;
    if (el._stAnim) { try { el._stAnim.cancel(); } catch (_) {} }
    el._stAnim = anim(el, [
      { opacity: sp.op, transform: startTf },
      { opacity: 1, transform: 'none' }
    ], { delay: i * sp.delay, duration: sp.dur, easing: sp.ease, fill: 'backwards' });
    if (tp.mode === 'cyber' && i < 4 && el.classList) {
      el.classList.remove('cy-lock-in');
      void el.offsetWidth;
      el.classList.add('cy-lock-in');
    }
  }
}
var _scrollBusyUntil = 0;
function tween(el, to, dec) {
  if (!el) return;
  var busyUntil = Math.max(_scrollBusyUntil, (typeof S !== 'undefined' && S && S.scrollBusyUntil) || 0);
  if (typeof performance !== 'undefined' && performance.now() < busyUntil) {
    if (el._twRaf) { cancelAnimationFrame(el._twRaf); el._twRaf = 0; }
    el._v = to;
    var fastTxt = to.toFixed(dec);
    if (el.textContent !== fastTxt) el.textContent = fastTxt;
    return;
  }
  if (el._twRaf) { cancelAnimationFrame(el._twRaf); el._twRaf = 0; }
  var numOn = typeof fxOn !== 'function' || fxOn('num');
  var tp = themePhys();
  var from = parseFloat(el.textContent) || 0, t0 = performance.now();
  var dur = motionOn() && numOn && !(typeof PERF !== 'undefined' && PERF.low) ? tp.numDur : 0;
  if (!dur || Math.abs(to - from) < Math.pow(10, -dec)) {
    el.textContent = Number(to).toFixed(dec);
    return;
  }
  if (tp.numSteps > 0) {
    // Cyber 战术终端阶梯跳变 + 冰蓝微闪指示
    if (el.classList) {
      el.classList.remove('cy-num-tick');
      void el.offsetWidth;
      el.classList.add('cy-num-tick');
      clearTimeout(el._cyTickT);
      el._cyTickT = setTimeout(function () { el.classList.remove('cy-num-tick'); }, 160);
    }
    var lastStep = -1;
    (function stepCy(t) {
      var k = Math.min(1, (t - t0) / dur);
      var qk = k >= 1 ? 1 : Math.floor(k * tp.numSteps) / tp.numSteps;
      if (qk !== lastStep) {
        lastStep = qk;
        var e = 1 - Math.pow(1 - qk, 2);
        el.textContent = (from + (to - from) * e).toFixed(dec);
      }
      if (k < 1) el._twRaf = requestAnimationFrame(stepCy);
      else { el._twRaf = 0; el.textContent = Number(to).toFixed(dec); }
    })(t0);
    return;
  }
  var pwr = tp.mode === 'liquid' ? 5 : tp.mode === 'frosted' ? 4 : 3;
  (function step(t) {
    var k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, pwr);
    el.textContent = (from + (to - from) * e).toFixed(dec);
    if (k < 1) el._twRaf = requestAnimationFrame(step);
    else el._twRaf = 0;
  })(t0);
}

/* 解析元素当前实时视觉 translateX（优先 DOMMatrix，回退 matrix3d / matrix 正则） */
function readTranslateX(el, fallback) {
  if (!el || typeof getComputedStyle !== 'function') return fallback;
  try {
    var raw = getComputedStyle(el).transform;
    if (!raw || raw === 'none') return fallback;
    var DM = typeof DOMMatrixReadOnly === 'function' ? DOMMatrixReadOnly
      : (typeof DOMMatrix === 'function' ? DOMMatrix
      : (typeof WebKitCSSMatrix === 'function' ? WebKitCSSMatrix : null));
    if (DM) {
      var dm = new DM(raw);
      if (isFinite(dm.m41)) return dm.m41;
    }
    var m3 = raw.match(/^matrix3d\((.+)\)$/);
    if (m3) {
      var x3 = parseFloat(m3[1].split(',')[12]);
      if (isFinite(x3)) return x3;
    }
    var m2 = raw.match(/^matrix\((.+)\)$/);
    if (m2) {
      var x2 = parseFloat(m2[1].split(',')[4]);
      if (isFinite(x2)) return x2;
    }
  } catch (_) {}
  return fallback;
}

/* ── 四模式分段控制器滑块物理覆写 (实时在途坐标起跳 + data-spring="1" 屏蔽 CSS transition 抢控制权) ── */
function placeSegs(root) {
  $$('.seg', root || document).forEach(function (s) {
    var on = $('button.on', s), th = $('.thumb', s);
    if (!on || !on.offsetWidth) { if (th) th.style.width = '0px'; return; }
    var nx = on.offsetLeft, nw = on.offsetWidth, w = nw + 'px', tf = 'translate3d(' + nx + 'px,0,0)';
    var prevX = th._lx;
    var first = prevX == null || !th.style.transform || th.style.width === '0px';
    if (!first && !th._segAnim && th.style.width === w && th.style.transform === tf) return;
    // 连点打断时在 cancel() 前读取当前实时合成帧 translateX，杜绝跳回旧终点 th._lx
    var startX = first ? nx : readTranslateX(th, prevX);
    var prevW = first ? nw : (th.offsetWidth || parseFloat(th.style.width) || nw);
    th._lx = nx;
    th.setAttribute('data-spring', '1');
    if (th._segAnim) { try { th._segAnim.cancel(); } catch (_) {} th._segAnim = null; }
    if (first || !motionOn()) {
      th.style.transition = 'none';
      th.style.width = w;
      th.style.transform = tf;
      return;
    }
    var dx = nx - startX, adx = Math.abs(dx), dw = Math.abs(nw - prevW), tp = themePhys();
    s.style.setProperty('--seg-dir', dx >= 0 ? '1' : '-1');
    th.style.transition = 'none';
    th.style.width = w;
    th.style.transform = tf;
    if (tp.mode === 'cyber') {
      s.classList.remove('cy-seg-lock');
      void s.offsetWidth;
      s.classList.add('cy-seg-lock');
      clearTimeout(s._cySegT);
      s._cySegT = setTimeout(function () { s.classList.remove('cy-seg-lock'); }, 150);
    }
    if ((adx <= 1.5 && dw <= 1.5) || (typeof PERF !== 'undefined' && PERF.low) || !th.animate) return;
    var startW = prevW + 'px';
    var frames;
    if (tp.mode === 'liquid' && adx > 4) {
      var stretch = Math.min(1.10, 1 + adx / 380), squash = Math.max(0.92, 1 - (stretch - 1) * 0.52);
      var midX = startX + dx * 0.50, overX = nx + (dx > 0 ? 1.2 : -1.2);
      frames = [
        { width: startW, transform: 'translate3d(' + startX.toFixed(2) + 'px,0,0) scale(1,1)' },
        { width: ((prevW + nw) * 0.5).toFixed(1) + 'px', transform: 'translate3d(' + midX.toFixed(1) + 'px,0,0) scale(' + stretch.toFixed(3) + ',' + squash.toFixed(3) + ')', offset: 0.40 },
        { width: w, transform: 'translate3d(' + overX.toFixed(1) + 'px,0,0) scale(0.986,1.014)', offset: 0.80 },
        { width: w, transform: tf + ' scale(1,1)' }
      ];
    } else if (tp.mode === 'frosted' && adx > 4) {
      var midF = startX + dx * 0.52;
      frames = [
        { width: startW, transform: 'translate3d(' + startX.toFixed(2) + 'px,0,0) scale(1,1)' },
        { width: ((prevW + nw) * 0.5).toFixed(1) + 'px', transform: 'translate3d(' + midF.toFixed(1) + 'px,0,0) scale(1.018,0.992)', offset: 0.45 },
        { width: w, transform: tf + ' scale(1,1)' }
      ];
    } else {
      frames = [
        { width: startW, transform: 'translate3d(' + startX.toFixed(2) + 'px,0,0)' },
        { width: w, transform: tf }
      ];
    }
    try {
      var segAnim = th.animate(frames, { duration: tp.seg.dur, easing: tp.seg.ease });
      th._segAnim = segAnim;
      var clearSegAnim = function () { if (th._segAnim === segAnim) th._segAnim = null; };
      segAnim.onfinish = clearSegAnim;
      segAnim.oncancel = clearSegAnim;
    } catch (_) {}
  });
  if (typeof lgOn !== 'undefined' && lgOn && typeof normLgVariant === 'function' && normLgVariant(S.lgVariant) === 'prism' && typeof rebindHyaliteTargets === 'function') {
    rebindHyaliteTargets(null, false);
  }
}

/* ── 无水平漂移、零 Backdrop-Root 破坏的四模式专属切页引擎 ── */
var _cyScanEl = null, _cyScanAnim = null;
function triggerCyberScan() {
  if (!motionOn() || (typeof PERF !== 'undefined' && PERF.low)) return;
  if (!_cyScanEl && document.body) {
    _cyScanEl = document.createElement('div');
    _cyScanEl.id = 'hnc-cy-scan';
    _cyScanEl.setAttribute('aria-hidden', 'true');
    document.body.appendChild(_cyScanEl);
  }
  if (!_cyScanEl || !_cyScanEl.animate) return;
  if (_cyScanAnim) { try { _cyScanAnim.cancel(); } catch (_) {} }
  try {
    _cyScanAnim = _cyScanEl.animate([
      { opacity: 0.92, transform: 'translate3d(0, 54px, 0) scaleY(1)' },
      { opacity: 0.55, transform: 'translate3d(0, 52vh, 0) scaleY(1.2)', offset: 0.58 },
      { opacity: 0, transform: 'translate3d(0, 92vh, 0) scaleY(0.6)' }
    ], { duration: 145, easing: 'cubic-bezier(.08,.88,.18,1)' });
  } catch (_) {}
}

function pageEnterTargets(pg) {
  if (!pg) return [];
  var out = [];
  var splitMain = pg.querySelector('.dev-split > .wrap');
  var host = splitMain || pg.querySelector(':scope > .wrap') || pg;
  var kids = host.children;
  for (var i = 0; i < kids.length && out.length < 6; i++) {
    var k = kids[i];
    if (k.hidden || k.style.display === 'contents') continue;
    out.push(k);
  }
  var side = pg.querySelector('#dev-side');
  if (side && !side.hidden) out.push(side);
  return out;
}

function runPageEnterFx(to) {
  if (typeof lgOn !== 'undefined' && lgOn && typeof normLgVariant === 'function' && normLgVariant(S.lgVariant) === 'prism' && typeof rebindHyaliteTargets === 'function') {
    rebindHyaliteTargets(null, false);
  }
  if (!to || !motionOn() || (typeof fxOn === 'function' && !fxOn('page')) || (typeof PERF !== 'undefined' && PERF.low)) return;
  // 严禁对 .page 施加 transform / filter / opacity<1，彻底守护子层 .glass 的 backdrop-filter 采样根与零水平溢出
  to.style.transform = '';
  to.style.opacity = '';
  var tp = themePhys(), p = tp.page;
  if (p.scan) triggerCyberScan();
  var items = pageEnterTargets(to);
  var startTf = 'translate3d(0,' + p.y + 'px,0)' + (p.scale !== 1 ? ' scale(' + p.scale + ')' : '');
  for (var i = 0; i < items.length; i++) {
    var el = items[i];
    if (el._pgAnim) { try { el._pgAnim.cancel(); } catch (_) {} el._pgAnim = null; }
    try {
      el._pgAnim = el.animate([
        { opacity: p.op, transform: startTf },
        { opacity: 1, transform: 'none' }
      ], { duration: p.dur, delay: i * p.step, easing: p.ease, fill: 'backwards' });
    } catch (_) {}
  }
}

/* ═════════════════════ 低端机自动降级 ═════════════════════
   启动时测 40 帧; 运行中每段弹簧动画统计掉帧(>45ms 的帧占比 >55%), 连续三段且在低核小内存设备上才简化:
   关掉毛玻璃、共享元素展开, 列表浮现只做前 4 行。可在 设置 → 外观 里恢复。 */
// v5.35.0: 自动清理旧版冷启动探针静默误写的 hnc6.lowfx='1'（仅保留用户主动点击「手动简化」设置的 hnc6.lowfx_manual='1'）
if (LS.get('hnc6.lowfx', '') === '1' && LS.get('hnc6.lowfx_manual', '') !== '1') LS.del('hnc6.lowfx');
var PERF = { low: LS.get('hnc6.lowfx', '') === '1' && LS.get('hnc6.lowfx_manual', '') === '1', auto: LS.get('hnc6.lowfx_manual', '') !== '1' && LS.get('hnc6.lowfx', '') !== '0', frames: 0, slow: 0, strikes: 0, probe: '' };
function lowFx() { return PERF.low; }
function perfFrame(dt) { PERF.frames++; if (dt > 45) PERF.slow++; }
function perfEnd() {
  if (PERF.frames >= 16) { if (PERF.slow / PERF.frames > .55) PERF.strikes++; else PERF.strikes = Math.max(0, PERF.strikes - 1); if (PERF.strikes >= 3 && !PERF.low && PERF.auto && (navigator.hardwareConcurrency || 8) <= 4 && (navigator.deviceMemory || 8) <= 2) setLowFx(true, true); }
  PERF.frames = PERF.slow = 0;
}
function setLowFx(on, auto) {
  PERF.low = !!on;
  if (!auto) { PERF.auto = false; LS.set('hnc6.lowfx_manual', on ? '1' : '0'); LS.set('hnc6.lowfx', on ? '1' : '0'); }
  document.documentElement.classList.toggle('lowfx', !!on);
  if (typeof liquidGlass === 'function') liquidGlass();
  if (typeof applyMotion === 'function') applyMotion();
  if (auto && on) setTimeout(function () { toast('检测到低配设备持续掉帧，已临时简化动画（可在 设置 → 外观 恢复）', 'warn'); }, 50);
}
document.documentElement.classList.toggle('lowfx', PERF.low);
setTimeout(function probe() {
  if (PERF.low || !PERF.auto || !window.requestAnimationFrame) return;
  var n = 0, t0 = 0, slow = 0, last = 0;
  requestAnimationFrame(function f(t) {
    if (last) { if (t - last > 42) slow++; n++; } else t0 = t;
    last = t;
    if (n < 40) { requestAnimationFrame(f); return; }
    var avg = (t - t0) / n, weak = (navigator.hardwareConcurrency || 8) <= 2 && (navigator.deviceMemory || 8) <= 2;
    PERF.probe = Math.round(1000 / avg) + ' fps';
    if (weak && avg > 40 && slow > 24) setLowFx(true, true);
  });
}, 1800);

/* ═════════════════════ 可打断半隐式欧拉弹簧 + 四主题弹层物理引擎 ═════════════════════
   Spring: 每帧 6 个辛欧拉子步(适配 60~120Hz 与高刚度 Cyber 弹簧 k=1480), go() 中途改目标保留速度 → 随时可打断。
   弹层 #sheet: 保持背景 1:1 不缩放(守护 backdrop-filter 120fps), 弹层 y 与 #scrim 遮罩透明度跟手联动, 松手继承手指速度甩出或回弹。 */
function Spring(p, onFrame, onRest) { this.k = p.k; this.c = p.c; this.x = 0; this.v = 0; this.to = 0; this.raf = 0; this.last = 0; this.onFrame = onFrame; this.onRest = onRest; this.eps = .4; }
Spring.prototype.set = function (x) { this.stop(); this.x = this.to = x; this.v = 0; this.onFrame(x); };
Spring.prototype.stop = function () {
  if (this.raf) cancelAnimationFrame(this.raf);
  this.raf = 0;
  this.last = 0;
  if (typeof PERF !== 'undefined' && PERF) { PERF.frames = 0; PERF.slow = 0; }
};
Spring.prototype.go = function (to, v, p) {
  this.to = to; if (v != null) this.v = v; if (p) { this.k = p.k; this.c = p.c; }
  if (!motionOn()) { this.x = to; this.v = 0; this.onFrame(to); this.stop(); if (this.onRest) this.onRest(); return; }
  if (!this.raf) { var me = this; this.raf = requestAnimationFrame(function f(t) { me.step(t); }); }
};
Spring.prototype.step = function (t) {
  var dt = this.last ? Math.min(.032, (t - this.last) / 1000) : 1 / 120, n = 6, h = dt / n, me = this;
  if (this.last) perfFrame(t - this.last);
  this.last = t;
  for (var i = 0; i < n; i++) { this.v += (-this.k * (this.x - this.to) - this.c * this.v) * h; this.x += this.v * h; }
  if (Math.abs(this.x - this.to) < this.eps && Math.abs(this.v) < this.eps * 10) {
    this.x = this.to; this.v = 0; this.onFrame(this.x); this.raf = 0; this.last = 0; perfEnd(); if (this.onRest) this.onRest(); return;
  }
  this.onFrame(this.x);
  this.raf = requestAnimationFrame(function f(t2) { me.step(t2); });
};
function springP() { return themePhys().sheet; }
function appleSheet() { return motionOn() && !lowFx(); }
var SM = { open: false, closing: false, h: 520 };
var shSpring = new Spring({ k: 340, c: 32.5 }, function (y) {
  var sh = $('#sheet');
  if (!sh) return;
  sh.style.transform = 'translate3d(-50%,' + y.toFixed(2) + 'px,0)';
  if (SM.open && !SM.closing) {
    var sc = $('#scrim');
    if (sc && y > 0) sc.style.opacity = String(clamp(1 - y / Math.max(240, SM.h * 0.95), 0, 1).toFixed(3));
    else if (sc) sc.style.opacity = '';
  }
}, function () {
  var sh = $('#sheet'), sc = $('#scrim');
  if (SM.closing) {
    SM.closing = false;
    if (sh) { sh.classList.remove('closing', 'is-spring', 'is-dragging'); sh.style.transform = ''; sh.style.opacity = ''; sh.style.transition = ''; }
    if (sc) sc.style.opacity = '';
  } else if (sh) {
    sh.classList.remove('is-spring');
    if (SM.open && Math.abs(shSpring.x) < .5) sh.style.transform = 'translate3d(-50%,0,0)';
    if (sc) sc.style.opacity = '';
  }
});

/* ═════════════════════ 动画效果(可逐项选择) ═════════════════════
   title/haptic 不算"动画"(滚动驱动 / 震动), 不受「界面动画」总开关和系统「减少动态效果」影响;
   其余效果在总开关关闭或系统要求减少动态效果时一律停用。 */
var FX_LIST = [
  ['title', '大标题收起', '滚动时大标题收成顶栏居中小标题（液态玻璃 / 毛玻璃）'],
  ['page', '页面切换', '切换标签时按当前主题动效语言原地浮现'],
  ['sheet', '弹层跟手物理', '弹层支持跟手下拉阻尼与速度继承丝滑收起'],
  ['morph', '共享元素展开', '弹层从点击位置平滑展开'],
  ['press', '按压回弹', '按主题材质呈现水滴微鼓、阻尼软压或战术锁定'],
  ['list', '列表浮现', '进入页面或筛选时逐行错开浮现'],
  ['num', '数字滚动', '速率、流量数字平滑过渡（赛博模式为阶梯跳变）'],
  ['haptic', '触感反馈', '开关、长按、确认时轻震一下']
];
var FX_PRESETS = {
  calm: { title: true, page: true, sheet: true, morph: false, press: true, list: false, num: true, haptic: true, spring: 'light' },
  std: { title: true, page: true, sheet: true, morph: false, press: true, list: false, num: true, haptic: true, spring: 'light' },
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
function canVib() { return !!(navigator.vibrate && (!navigator.userActivation || navigator.userActivation.hasBeenActive)); }
function haptic(ms) { if (fxOn('haptic') && canVib()) try { navigator.vibrate(ms || 10); } catch (_) {} }
/* 弹簧参数 → CSS linear() 曲线。轻: stiffness 300 / damping 30; 弹: 200 / 20(质量 1) */
var SPRING = { light: { k: 300, c: 30 }, bouncy: { k: 200, c: 20 } };
function springKC(p) {
  var w = Math.sqrt(p.k), z = p.c / (2 * w), ms = clamp(Math.log(1000) / (z * w) * 1000, 300, 1200);
  return { curve: springCurve(z, w, ms), ms: Math.round(ms) };
}
var EASE0 = { q: EASE.q, soft: EASE.soft };
function applyMotion() {
  var r = document.documentElement, tp = themePhys();
  EASE.q = tp.q; EASE.soft = tp.soft;
  r.style.setProperty('--q', tp.q);
  r.style.setProperty('--q-soft', tp.soft);
  r.classList.toggle('fx-nopress', !fxOn('press'));
  if (!motionOn()) {
    if (typeof resetScrollVel === 'function') resetScrollVel();
    if (typeof clearTabbarNavPop === 'function' && typeof document.getElementById === 'function') {
      clearTabbarNavPop(document.getElementById('tabbar'));
    }
  }
  // 弹层打开或收起途中若关闭动画 / 开启低配简化: 立即清理弹簧与内联属性，交回静态 CSS
  if ((SM.open || SM.closing) && !appleSheet()) {
    SM.open = false; SM.closing = false;
    shSpring.stop();
    var sh = document.getElementById('sheet'), sc = document.getElementById('scrim');
    if (sh) { sh.classList.remove('closing', 'is-spring', 'is-dragging'); sh.style.transform = ''; sh.style.opacity = ''; sh.style.transition = ''; }
    if (sc) sc.style.opacity = '';
  }
}
S.glassMode = LS.get('hnc6.glass_mode', 'liquid') === 'frosted' ? 'frosted' : 'liquid';
function currentGlassAttr() {
  if (S.style === 'liquid') return S.glassMode === 'frosted' ? 'frosted' : 'liquid';
  return '';
}
function resolveEffectiveTheme(mode) {
  if (mode === 'light' || mode === 'dark') return mode;
  var sysDark = false;
  try { sysDark = typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches; } catch (_) {}
  return sysDark ? 'dark' : 'light';
}
var LG_VARIANTS = [
  { id: 'pure',  name: '纯透无框', desc: '还原旧版无白框空气感，86% 纯透融景与极轻呼吸顶光' },
  { id: 'prism', name: '棱镜色散', desc: '主卡与底栏启用真实三通道 RGB 折射，边缘高光随树叶与天空实景动态色散' },
  { id: 'dew',   name: '凝脂水滴', desc: '水珠表面张力弯月面柔光与微凹水窝子格，温润饱满无硬线' }
];
function lgVariantLabel(v) {
  var id = typeof normLgVariant === 'function' ? normLgVariant(v) : ((v === 'prism' || v === 'dew' || v === 'pure') ? v : 'pure');
  for (var i = 0; i < LG_VARIANTS.length; i++) {
    if (LG_VARIANTS[i].id === id) return LG_VARIANTS[i].name;
  }
  return '纯透无框';
}
function lgVariantDesc(v) {
  var id = typeof normLgVariant === 'function' ? normLgVariant(v) : ((v === 'prism' || v === 'dew' || v === 'pure') ? v : 'pure');
  for (var i = 0; i < LG_VARIANTS.length; i++) {
    if (LG_VARIANTS[i].id === id) return LG_VARIANTS[i].desc;
  }
  return LG_VARIANTS[0].desc;
}
function applyTheme() {
  var r = document.documentElement, ga = currentGlassAttr();
  var tMode = (S.theme === 'light' || S.theme === 'dark') ? S.theme : 'auto';
  r.setAttribute('data-theme', resolveEffectiveTheme(tMode));
  r.setAttribute('data-theme-mode', tMode);
  r.setAttribute('data-lg-variant', typeof normLgVariant === 'function' ? normLgVariant(S.lgVariant) : 'pure');
  if (S.style === 'liquid') r.setAttribute('data-style', 'apple');
  else if (S.style === 'cyber') r.setAttribute('data-style', 'cyber');
  else r.removeAttribute('data-style');
  if (ga) r.setAttribute('data-glass', ga); else r.removeAttribute('data-glass');
  var hdr0 = typeof document.querySelector === 'function' ? document.querySelector('.header') : null;
  if (hdr0) hdr0._navKey = '';
  applyGlassTint();
  if (typeof liquidGlass === 'function') liquidGlass();
  r.classList.toggle('calm', !S.motion);
  applyMotion();
}
function setGlassMode(mode) {
  S.glassMode = mode === 'frosted' ? 'frosted' : 'liquid';
  LS.set('hnc6.glass_mode', S.glassMode);
  if (S.style !== 'liquid') { S.style = 'liquid'; LS.set('hnc6.style', 'liquid'); }
  applyTheme();
  if (typeof refreshHyaliteTargets === 'function') refreshHyaliteTargets();
}
/* 玻璃浓度(液态玻璃专用, 0 清透 … 50 标准 … 100 着色) → <html> 上的 --gx-up / --gx-dn(liquid.css 头注释);
   标准档两个都删掉 = 旧版数值。严守 v530_frontend.js 单测契约 */
function glassTintVars(v) { v = clamp(num(v, 50), 0, 100); return { up: v > 50 ? (v - 50) / 50 : 0, dn: v < 50 ? (50 - v) / 50 : 0 }; }
function applyGlassTint(v) {
  var r = document.documentElement, g = glassTintVars(v == null ? S.glassTint : v);
  if (g.up) r.style.setProperty('--gx-up', g.up.toFixed(3)); else r.style.removeProperty('--gx-up');
  if (g.dn) r.style.setProperty('--gx-dn', g.dn.toFixed(3)); else r.style.removeProperty('--gx-dn');
  if (typeof syncHyaliteTint === 'function') syncHyaliteTint(g);
}
var GX_T = [[10, '清透'], [40, '偏清透'], [60, '标准'], [90, '偏着色'], [101, '着色']];
function glassTintLabel(v) { for (var i = 0; i < GX_T.length; i++) if (v < GX_T[i][0]) return GX_T[i][1]; return '着色'; }
function apple() { return S.style === 'liquid'; }

/* 解决 Android content:// WebView（MT 管理器等非安全上下文）下 navigator.userAgentData 缺失导致 Hyalite.supported() 误判问题 */
function ensureHyaliteBlinkSupport() {
  if (typeof window === 'undefined' || !window.Hyalite || typeof Hyalite.force !== 'function') return false;
  try {
    if (typeof Hyalite.supported === 'function' && Hyalite.supported()) return true;
    var cssOk = typeof CSS !== 'undefined' && !!CSS.supports &&
      (CSS.supports('backdrop-filter', 'url(#hnc-p)') || CSS.supports('-webkit-backdrop-filter', 'url(#hnc-p)'));
    var ua = (typeof navigator !== 'undefined' && navigator && navigator.userAgent) || '';
    var blinkOk = (typeof window.chrome !== 'undefined' || /Chrome\/|Chromium\/|CriOS\/|EdgA\/|Edg\/|\bwv\b/.test(ua)) &&
      !/Firefox\/|FxiOS\//.test(ua);
    if (cssOk && blinkOk) {
      Hyalite.force(true);
      return true;
    }
  } catch (_) {}
  return typeof Hyalite.supported === 'function' ? !!Hyalite.supported() : false;
}

var LG_OPTS = {
  tabbar: { shape: 'squircle', bevel: 18, slope: 1.08, thickness: 28, blur: 4, sat: 1, rim: .42, edge: 0, dispersion: 0, settle: 160 }
};
var lgOn = false;
var _lgHandles = [];
var _lgTabHandle = null;

function hasWpActive() {
  if (typeof S !== 'undefined' && S && S.wpId && S.wpId !== 'none') return true;
  var r = typeof document !== 'undefined' ? document.documentElement : null;
  if (!r || !r.getAttribute) return false;
  return r.getAttribute('data-has-wp') === '1' || r.getAttribute('data-has-wallpaper') === '1' || !!(r.classList && r.classList.contains('has-wallpaper'));
}

function isHyaliteNodeDisconnected(el) {
  if (!el) return true;
  if ('isConnected' in el) return !el.isConnected;
  if (typeof document !== 'undefined' && document.body && typeof document.body.contains === 'function') {
    return !document.body.contains(el);
  }
  return false;
}

function _detachHyaliteItem(item) {
  if (!item) return;
  var el = item.el, handle = item.handle;
  if (handle && typeof handle.detach === 'function') {
    try { handle.detach(); } catch (_) {}
  }
  if (el && typeof window !== 'undefined' && window.Hyalite && typeof Hyalite.detach === 'function') {
    try { Hyalite.detach(el); } catch (_) {}
  }
  if (el) {
    el.__lgSig = '';
    if (el.style && typeof el.style.removeProperty === 'function') {
      el.style.removeProperty('--hyalite');
      el.style.removeProperty('--hyalite-edge');
    }
  }
}

function pruneDisconnectedHyalite() {
  if (!_lgHandles.length) return;
  var alive = [];
  for (var i = 0; i < _lgHandles.length; i++) {
    var item = _lgHandles[i];
    if (!item || isHyaliteNodeDisconnected(item.el)) {
      _detachHyaliteItem(item);
    } else {
      alive.push(item);
    }
  }
  _lgHandles = alive;
}

function detachAllHyaliteTargets() {
  for (var i = 0; i < _lgHandles.length; i++) {
    _detachHyaliteItem(_lgHandles[i]);
  }
  _lgHandles = [];
  _lgTabHandle = null;
  lgOn = false;
  var ln = typeof $ === 'function' ? $('#lens') : (typeof document !== 'undefined' && document.querySelector ? document.querySelector('#lens') : null);
  if (ln) {
    if (typeof window !== 'undefined' && window.Hyalite && typeof Hyalite.detach === 'function') {
      try { Hyalite.detach(ln); } catch (_) {}
    }
    if (ln.style && typeof ln.style.removeProperty === 'function') {
      ln.style.removeProperty('--hyalite');
      ln.style.removeProperty('--hyalite-edge');
    }
  }
}

function lgOptsFor(kind, g) {
  var variant = typeof normLgVariant === 'function' ? normLgVariant(S.lgVariant) : 'pure';
  var hasWp = hasWpActive();
  var dk = false;
  try { dk = document.documentElement.getAttribute('data-theme') === 'dark'; } catch (_) {}
  var o;
  if (kind === 'lens') {
    o = {
      shape: 'circle',
      bevel: 16,
      slope: 1.16,
      thickness: 30,
      blur: 0.8,
      sat: 1,
      rim: 0.34,
      edge: 0,
      dispersion: variant === 'prism' ? 2.3 : (variant === 'dew' ? 0.65 : 0.25),
      settle: 120
    };
  } else if (variant === 'prism') {
    if (kind === 'hero') {
      o = { shape: 'squircle', bevel: 24, slope: 1.15, thickness: 40, blur: hasWp ? 4.8 : 4.2, edgeBlur: 1.2, sat: 1, rim: .48, edge: 0, dispersion: 2.35, settle: 120 };
    } else if (kind === 'seg') {
      o = { shape: 'squircle', bevel: 16, slope: 1.12, thickness: 28, blur: hasWp ? 4.8 : 4.2, edgeBlur: 1.2, sat: 1, rim: .42, edge: 0, dispersion: 1.75, settle: 120 };
    } else {
      o = { shape: 'squircle', bevel: 22, slope: 1.14, thickness: 36, blur: hasWp ? 4.8 : 4.2, edgeBlur: 1.2, sat: 1, rim: .46, edge: 0, dispersion: 2.15, settle: 120 };
    }
  } else if (variant === 'dew') {
    o = { shape: 'lip', bevel: 24, slope: 1.06, thickness: 34, blur: hasWp ? 6.0 : 4.5, sat: 1, rim: .32, edge: 0, dispersion: .28, settle: 160 };
  } else {
    o = { shape: 'squircle', bevel: 18, slope: hasWp ? 1.0 : 1.08, thickness: 28, blur: hasWp ? 6.5 : 4, sat: 1, rim: hasWp ? .20 : .42, edge: 0, dispersion: 0, settle: 160 };
  }
  var gv = g || (typeof glassTintVars === 'function' ? glassTintVars(S.glassTint) : { up: 0, dn: 0 });
  if (kind !== 'lens' && gv && gv.up > 0) {
    o.blur = +(o.blur + gv.up * 3.0).toFixed(2);
  }
  if (dk) {
    o.rim = +(o.rim * 0.55).toFixed(2);
    o.edge = 0;
    o.theme = 'dark';
  } else {
    o.theme = 'light';
  }
  return o;
}

function lgTargets() {
  var variant = typeof normLgVariant === 'function' ? normLgVariant(S.lgVariant) : 'pure';
  var out = [], seen = [];
  function pushTarget(kind, el) {
    if (!el || el.hidden || isHyaliteNodeDisconnected(el) || seen.indexOf(el) >= 0) return false;
    seen.push(el);
    out.push([kind, el]);
    return true;
  }
  var tbBg = (typeof document !== 'undefined' && document.querySelector) ? document.querySelector('#tabbar > .tabbar-bg') : null;
  var rawTb = (typeof $ === 'function') ? $('#tabbar') : (typeof document !== 'undefined' && document.querySelector ? document.querySelector('#tabbar') : null);
  if (tbBg && rawTb && rawTb !== tbBg) {
    if (typeof window !== 'undefined' && window.Hyalite && typeof Hyalite.detach === 'function') {
      try { Hyalite.detach(rawTb); } catch (_) {}
    }
    if (rawTb.style && typeof rawTb.style.removeProperty === 'function') {
      rawTb.style.removeProperty('--hyalite');
      rawTb.style.removeProperty('--hyalite-edge');
    }
  }
  pushTarget('tabbar', tbBg || rawTb);
  var ln = (typeof document !== 'undefined' && document.querySelector) ? document.querySelector('#lens') : (typeof $ === 'function' ? $('#lens') : null);
  pushTarget('lens', ln);
  if (variant === 'prism' && typeof document !== 'undefined' && typeof document.querySelectorAll === 'function') {
    try {
      var heroes = document.querySelectorAll('.page.on .hero, .page.on .ahero, .page.on .pu, .page.on .dpihero');
      var hCount = 0;
      for (var i = 0; heroes && i < heroes.length && hCount < 2; i++) {
        if (pushTarget('hero', heroes[i])) hCount++;
      }
    } catch (_) {}
    try {
      var segs = document.querySelectorAll('.page.on > .wrap > .seg:not(.small)');
      if (!segs || !segs.length) {
        segs = document.querySelectorAll('.page.on > .dev-split > .wrap > .seg:not(.small)');
      }
      for (var j = 0; segs && j < segs.length; j++) {
        if (pushTarget('seg', segs[j])) break;
      }
    } catch (_) {}
  }
  return out;
}

function wrapHyaliteHandle(el, rawHandle) {
  if (rawHandle && typeof rawHandle.detach === 'function') return rawHandle;
  return {
    detach: function () {
      if (typeof window !== 'undefined' && window.Hyalite && typeof Hyalite.detach === 'function') {
        try { Hyalite.detach(el); } catch (_) {}
      }
    },
    refresh: function () {
      if (typeof window !== 'undefined' && window.Hyalite && typeof Hyalite.refresh === 'function') {
        try { Hyalite.refresh(el); } catch (_) {}
      }
    }
  };
}

function rebindHyaliteTargets(g, forceRefresh) {
  pruneDisconnectedHyalite();
  var isLow = !!(S.lowfx || (typeof PERF !== 'undefined' && PERF.low));
  if (typeof window === 'undefined' || !window.Hyalite || S.style !== 'liquid' || S.glassMode === 'frosted' || isLow) {
    detachAllHyaliteTargets();
    return;
  }
  var supported = ensureHyaliteBlinkSupport();
  lgOn = true;
  var targets = lgTargets();
  var nextPlan = [];
  for (var i = 0; i < targets.length; i++) {
    var kind = targets[i][0], el = targets[i][1];
    if (!el || isHyaliteNodeDisconnected(el)) continue;
    var opts = lgOptsFor(kind, g);
    nextPlan.push({ kind: kind, el: el, opts: opts, sig: kind + ':' + JSON.stringify(opts) });
  }
  var kept = [];
  for (var j = 0; j < _lgHandles.length; j++) {
    var prev = _lgHandles[j];
    var keep = false;
    if (prev && prev.el && !isHyaliteNodeDisconnected(prev.el)) {
      for (var m = 0; m < nextPlan.length; m++) {
        if (nextPlan[m].el === prev.el && nextPlan[m].sig === prev.sig) {
          keep = true;
          break;
        }
      }
    }
    if (keep) kept.push(prev);
    else _detachHyaliteItem(prev);
  }
  var nextHandles = [];
  var nextTabHandle = null;
  for (var k = 0; k < nextPlan.length; k++) {
    var plan = nextPlan[k], existing = null;
    for (var n = 0; n < kept.length; n++) {
      if (kept[n].el === plan.el) { existing = kept[n]; break; }
    }
    var lostFilter = !!(existing && supported && plan.el.offsetWidth >= 4 && plan.el.offsetHeight >= 4 &&
      plan.el.style && typeof plan.el.style.getPropertyValue === 'function' && !plan.el.style.getPropertyValue('--hyalite'));
    if (existing && !lostFilter) {
      if (forceRefresh) {
        try {
          if (existing.handle && typeof existing.handle.refresh === 'function') existing.handle.refresh();
          else if (typeof Hyalite.refresh === 'function') Hyalite.refresh(plan.el);
        } catch (_) {}
      }
      nextHandles.push(existing);
      if (plan.kind === 'tabbar') nextTabHandle = existing.handle || plan.el;
    } else {
      if (existing) _detachHyaliteItem(existing);
      try {
        var h = wrapHyaliteHandle(plan.el, Hyalite.attach(plan.el, plan.opts));
        plan.el.__lgSig = plan.sig;
        var entry = { kind: plan.kind, el: plan.el, handle: h, sig: plan.sig };
        nextHandles.push(entry);
        if (plan.kind === 'tabbar') nextTabHandle = h;
      } catch (_) {}
    }
  }
  _lgHandles = nextHandles;
  _lgTabHandle = nextTabHandle;
}
function refreshHyaliteTargets() { rebindHyaliteTargets(null, true); }
function syncHyaliteTint(g) { rebindHyaliteTargets(g, false); }
function initLiquidGlass() { rebindHyaliteTargets(null, false); }
function liquidGlass() { rebindHyaliteTargets(null, false); }

/* 大标题滚动插值 —— --lt 大标题淡出缩小, --st 顶栏小标题浮现, --hp 顶栏毛玻璃出现 (严守 v530_frontend.js nav_solid 单测契约) */
var NAV_T = { devices: '设备', apps: '应用', vector: '智能护航', stats: '分析', settings: '设置' }, navRaf = 0;
function navSync() {
  var hdr = document.querySelector('.header'), ht = document.getElementById('htitle'); if (!hdr || !ht) return;
  var curTitle = NAV_T[S.page] || '';
  if (ht.textContent !== curTitle) ht.textContent = curTitle;
  var pg = document.getElementById('p-' + S.page), y = pg ? pg.scrollTop : 0, isAp = apple(), tOn = fxOn('title'), on = isAp && tOn;
  document.documentElement.classList.toggle('fx-notitle', isAp && !tOn);
  var lt = on ? clamp((y - 2) / 24, 0, 1) : 1, st = on ? clamp((y - 30) / 14, 0, 1) : 1, hp = on ? clamp((y - 4) / 26, 0, 1) : 1;
  var hs = clamp((y - (on ? 56 : 8)) / 20, 0, 1), sp = clamp(y / 72, 0, 1);
  var ltS = lt.toFixed(3), stS = st.toFixed(3), hpS = hp.toFixed(3), hsS = hs.toFixed(3), spS = sp.toFixed(3);
  var nk = (S.page || '') + '|' + (on ? 1 : 0) + '|' + ltS + '|' + stS + '|' + hpS + '|' + hsS + '|' + spS;
  if (hdr._navKey === nk && (!pg || pg._ltVal === ltS)) return;
  hdr._navKey = nk;
  if (pg && pg._ltVal !== ltS) { pg._ltVal = ltS; pg.style.setProperty('--lt', ltS); }
  hdr.style.setProperty('--st', stS); hdr.style.setProperty('--hp', hpS);
  hdr.style.setProperty('--hs', hsS);
  hdr.style.setProperty('--scroll-p', spS);
  hdr.classList.toggle('hs-on', hs > 0);
}

/* ── 连续平滑滚速追踪（单 rAF 衰减，0.02 步长量化写入 --scroll-vy / --scroll-vy-abs，静止自动停表） ── */
var _svEl = null, _svLastY = 0, _svLastEv = 0, _svVy = 0, _svQuant = 0, _svRaf = 0, _svRafTs = 0;

function writeScrollVelVars(vyVal, absVal) {
  var r = typeof document !== 'undefined' ? document.documentElement : null;
  if (!r || !r.style || typeof r.style.setProperty !== 'function') return;
  r.style.setProperty('--scroll-vy', vyVal === 0 ? '0' : vyVal.toFixed(2));
  r.style.setProperty('--scroll-vy-abs', absVal === 0 ? '0' : absVal.toFixed(2));
}

function resetScrollVel() {
  var hadQuant = _svQuant !== 0;
  if (_svRaf && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(_svRaf);
  _svRaf = 0;
  _svRafTs = 0;
  _svVy = 0;
  _svQuant = 0;
  writeScrollVelVars(0, 0);
  if (hadQuant && typeof window !== 'undefined' && typeof window.scheduleWpSceneSync === 'function') {
    window.scheduleWpSceneSync();
  }
}

function stepScrollVel(ts) {
  var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : ts;
  var fdt = _svRafTs ? Math.min(0.05, Math.max(0.004, (ts - _svRafTs) / 1000)) : (1 / 60);
  _svRafTs = ts;
  var idleMs = now - _svLastEv;
  var decayRate = idleMs > 20 ? 14 : 3.5;
  _svVy *= Math.exp(-decayRate * fdt);
  if (Math.abs(_svVy) < 0.01 && idleMs > 32) {
    resetScrollVel();
    return;
  }
  var qAbs = Math.min(1, Math.round(Math.abs(_svVy) * 50) / 50);
  var qVy = qAbs === 0 ? 0 : (_svVy < 0 ? -qAbs : qAbs);
  if (qVy !== _svQuant) {
    _svQuant = qVy;
    writeScrollVelVars(qVy, qAbs);
  }
  _svRaf = requestAnimationFrame(stepScrollVel);
}

document.addEventListener('scroll', function (e) {
  var t = e.target;
  if (t && t.classList && t.classList.contains('page') && t.classList.contains('on')) {
    var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    _scrollBusyUntil = now + 170;
    if (typeof S !== 'undefined' && S) S.scrollBusyUntil = _scrollBusyUntil;
    var curY = t.scrollTop || 0;
    if (motionOn() && !lowFx() && typeof requestAnimationFrame === 'function') {
      if (_svEl !== t || now - _svLastEv > 180) {
        _svEl = t;
        _svLastY = curY;
        _svLastEv = now;
      } else {
        var dy = curY - _svLastY;
        var dt = Math.max(4, now - _svLastEv);
        _svLastY = curY;
        _svLastEv = now;
        var instVy = clamp((dy / dt) * (1000 / 1600), -1, 1);
        _svVy = clamp(_svVy * 0.48 + instVy * 0.52, -1, 1);
        if (!_svRaf) {
          _svRafTs = 0;
          _svRaf = requestAnimationFrame(stepScrollVel);
        }
      }
    } else if (_svQuant !== 0 || _svRaf) {
      resetScrollVel();
    }
    if (apple() && !navRaf) navRaf = requestAnimationFrame(function () { navRaf = 0; navSync(); });
  }
}, { capture: true, passive: true });

/* ── 清理 #tabbar 入场 navPop 动画残留，避免 animation-fill-mode:both 维持多余合成层阻断 #lens 采样 ── */
function clearTabbarNavPop(tb) {
  if (!tb || tb._navPopCleaned) return;
  tb._navPopCleaned = true;
  if (tb.style) {
    tb.style.animation = 'none';
    tb.style.webkitAnimation = 'none';
    if (typeof tb.style.removeProperty === 'function') {
      tb.style.removeProperty('opacity');
      tb.style.removeProperty('will-change');
    }
  }
}

(function initTabbarSettleAndLensSync() {
  if (typeof document === 'undefined') return;
  writeScrollVelVars(0, 0);
  var onTabbarAnimEnd = function (e) {
    var tgt = e && e.target;
    if (tgt && tgt.id === 'tabbar' && (!e.animationName || e.animationName === 'navPop')) {
      clearTabbarNavPop(tgt);
      if (lgOn) rebindHyaliteTargets(null, true);
    }
  };
  document.addEventListener('animationend', onTabbarAnimEnd, true);
  document.addEventListener('webkitAnimationEnd', onTabbarAnimEnd, true);
  var tbInit = document.getElementById ? document.getElementById('tabbar') : null;
  if (tbInit && !motionOn()) clearTabbarNavPop(tbInit);
  setTimeout(function () {
    var tb = document.getElementById ? document.getElementById('tabbar') : null;
    if (tb) clearTabbarNavPop(tb);
    if (lgOn) rebindHyaliteTargets(null, false);
  }, 1200);
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(function () {
      if (lgOn) rebindHyaliteTargets(null, false);
    });
  }
})();

if (typeof window !== 'undefined' && window.__HNC_MOCK_META && !S.sel) S.sel = '1e:52:a8:0c:77:3d';

applyTheme();
