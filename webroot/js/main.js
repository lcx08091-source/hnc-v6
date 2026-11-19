/* HNC WebUI · main.js —— 页面切换、底栏液态玻璃透镜、主题切换、事件委托、轮询、启动(最后加载) */
'use strict';

/* ═════════════════════ 页面切换(方向感知 + 弹簧) ═════════════════════ */
var ORDER = ['devices', 'apps', 'vector', 'stats', 'settings'];
var RENDER = {
  devices: renderDevices,
  apps: renderApps,
  vector: function (anim1) { if (typeof renderVectorPage === 'function') renderVectorPage(anim1); },
  stats: renderStats,
  settings: renderSettings
};
function onEnter(name) {
  if (name === 'devices') { paintHero(true); loadOnlineHours(); loadUsage(); if (typeof v6RefreshSummarySilent === 'function') v6RefreshSummarySilent(); }
  if (name === 'apps') loadApps().then(function () { if (S.page === 'apps') renderApps(false); });
  if (name === 'vector') { if (typeof onEnterVectorPage === 'function') onEnterVectorPage(); }
  if (name === 'stats') { afterAseg(); loadUsage().then(function () { var rk = $('#pu-dev-rank'); if (rk && typeof hsMonthRankHtml === 'function') rk.innerHTML = hsMonthRankHtml(); }); }
  if (name === 'settings') loadSettingsData().then(function () { if (S.page === 'settings') renderSettings(false); if (S.cfg.clsact_bpf_mode === 'on' && !S.clsact) clsactCheck(true); });
  schedulePoll(50);
}
var enterT = 0;
function markTabBtn(name) {
  $$('#tabs [data-tab]').forEach(function (el) {
    var on = el.getAttribute('data-tab') === name;
    el.classList.toggle('on', on);
    el.setAttribute('aria-selected', String(on));
    el.tabIndex = on ? 0 : -1;
  });
}
function go(name) {
  if (ORDER.indexOf(name) < 0) return;
  markTabBtn(name);
  if (name === S.page) { $('#p-' + name).scrollTo({ top: 0, behavior: motionOn() ? 'smooth' : 'auto' }); syncTab(name); return; }
  var from = $('#p-' + S.page), to = $('#p-' + name);
  S.page = name; closeDD(); syncTab(name); LS.set('hnc6.page', name); navSync();
  to.classList.add('on'); from.classList.remove('on');
  if (!to.firstElementChild) {
    RENDER[name](false);
  } else {
    placeSegs(to);
  }
  // v5.35 升级: 严禁对 .page 本身施加位移或半透明组隔离(彻底保护子层 .glass backdrop-filter 采样根与零水平漂移)
  if (typeof runPageEnterFx === 'function') runPageEnterFx(to);
  clearTimeout(enterT);
  enterT = setTimeout(function () { onEnter(name); }, 90);
}

/* ═════════════════════ 底栏: 微信 / iOS 26 液态玻璃滑动膨胀放大折射引擎 + 根治卡片展开乱滑 ═════════════════════ */
var TABS = [['devices', '设备', 'dev'], ['apps', '应用', 'apps'], ['vector', '矢量', 'vector'], ['stats', '分析', 'stats'], ['settings', '设置', 'gear']];
try { document.documentElement.style.setProperty('--tab-n', String(TABS.length)); } catch (_) {}
function buildTabItems(filled) {
  return TABS.map(function (t) {
    var ic = typeof tabSvg === 'function' ? tabSvg(t[2], filled) : ico(t[2]);
    var dotHtml = (t[0] === 'apps' ? '<span class="dot" hidden></span>' : (t[0] === 'vector' ? '<span class="dot v6-tab-dot" hidden></span>' : ''));
    return '<div class="tab" role="' + (filled ? 'presentation' : 'tab') + '" tabindex="-1" data-tab="' + t[0] + '">' + ic + t[1] + dotHtml + '</div>';
  }).join('');
}
$('#tabs').innerHTML = buildTabItems(false);
$('#lens-in').innerHTML = buildTabItems(true);
var bar = $('#tabbar'), lens = $('#lens'), lensIn = $('#lens-in'), tabsEl = $('#tabs');
var L = { x: 6, v: 0, tx: 6, s: 1, sv: 0, ts: 1, drag: false, down: false, hitIdx: 0, raf: 0, last: 0, gx: 0, moved: 0, fx0: 0, fx: 0, ft: 0, fv: 0, lockT: 0 };
function lensPhys() {
  return (typeof themePhys === 'function' ? themePhys() : { mode: 'default', lens: { k: 960, c: 62, dk: 1160, dc: 68, sk: 980, sc: 63, tapV: -.38, dragS: 1.08, maxSp: .12, dragSp: .16, sqRatio: .28, wallBounce: .18, rigid: false } }).lens;
}
function pulseCyberLens() {
  if (!lens || !motionOn() || (typeof motionTheme === 'function' && motionTheme() !== 'cyber')) return;
  lens.classList.remove('cy-lens-lock');
  void lens.offsetWidth;
  lens.classList.add('cy-lens-lock');
  clearTimeout(L.lockT);
  L.lockT = setTimeout(function () { lens.classList.remove('cy-lens-lock'); }, 150);
}
function tabGeom() {
  var br = bar.getBoundingClientRect(), tr = tabsEl.getBoundingClientRect();
  var padL = tr.width > 0 ? Math.max(0, tr.left - br.left) : 6;
  var totalW = tr.width > 0 ? tr.width : Math.max(160, bar.clientWidth - 12);
  var w = totalW / TABS.length;
  var minX = padL, maxX = padL + (TABS.length - 1) * w;
  return { padL: padL, w: w, totalW: totalW, minX: minX, maxX: maxX };
}
function slotW() { return tabGeom().w; }
function layoutLens() {
  var g = tabGeom();
  lens.style.width = g.w.toFixed(2) + 'px';
  if (lensIn) lensIn.style.width = g.totalW.toFixed(2) + 'px';
  var curIdx = Math.max(0, ORDER.indexOf(S.page));
  L.tx = g.padL + curIdx * g.w;
  if (!L.drag && !L.raf) { L.x = L.tx; paintLens(); }
}
function paintLens() {
  var g = tabGeom(), lp = lensPhys();
  var dragOver = lp.rigid ? 0 : 6;
  var px = L.drag ? clamp(L.x, g.minX - dragOver, g.maxX + dragOver) : clamp(L.x, g.minX, g.maxX);
  var relX = px - g.padL;
  // 动态挖空底层轮廓标签，让液态透镜内部的放大实心折射层独享视野，绝不重影
  tabsEl.style.setProperty('--ml', Math.max(0, relX + 2).toFixed(1) + 'px');
  tabsEl.style.setProperty('--mr', Math.min(g.totalW, relX + g.w - 2).toFixed(1) + 'px');

  var sxs = 1, sys = 1;
  if (!lp.rigid && motionOn() && !(typeof lowFx === 'function' && lowFx())) {
    var capSp = L.drag ? Math.max(.14, lp.dragSp) : Math.max(.08, lp.maxSp);
    var rawSp = capSp > 0 ? Math.min(Math.abs(L.v) / (L.drag ? 2400 : 2800), capSp) : 0;
    var pressInflateX = L.drag ? 1.14 : L.down ? 1.08 : 1.0;
    var pressInflateY = L.drag ? 1.26 : L.down ? 1.15 : 1.0;
    sxs = L.s * pressInflateX * (1 + rawSp * .65);
    sys = L.s * pressInflateY * (1 - rawSp * .22);
    var tilt = clamp(L.v / 1700, -1, 1);
    lens.style.setProperty('--lens-v', rawSp.toFixed(3));
    lens.style.setProperty('--lens-tilt', tilt.toFixed(3));
  } else {
    lens.style.setProperty('--lens-v', '0');
    lens.style.setProperty('--lens-tilt', '0');
  }
  lens.style.transform = 'translate3d(' + px.toFixed(2) + 'px,0,0) scale(' + sxs.toFixed(4) + ',' + sys.toFixed(4) + ')';
  if (lensIn) {
    // 反向平移以锁定世界坐标系下的 4 个标签位置，同时抵消外层椭圆非等比形变以保持字体不拉伸
    var invX = 1 / Math.max(.7, sxs), invY = 1 / Math.max(.7, sys);
    var mag = L.drag ? 1.13 : L.down ? 1.08 : 1.02;
    lensIn.style.transformOrigin = (relX + g.w * .5).toFixed(1) + 'px 50%';
    lensIn.style.transform = 'translate3d(' + (-relX).toFixed(2) + 'px,0,0) scale(' + (invX * mag).toFixed(4) + ',' + (invY * mag).toFixed(4) + ')';
  }
}
function stepLens(t) {
  var dt = L.last ? Math.min(.030, (t - L.last) / 1000) : 1 / 120; L.last = t;
  var lp = lensPhys(), k = L.drag ? lp.dk : lp.k, c = L.drag ? lp.dc : lp.c, n = 6, h = dt / n, g = tabGeom();
  for (var i = 0; i < n; i++) {
    L.v += (-k * (L.x - L.tx) - c * L.v) * h; L.x += L.v * h;
    if (lp.rigid) { L.s = 1; L.sv = 0; }
    else { L.sv += (-lp.sk * (L.s - L.ts) - lp.sc * L.sv) * h; L.s += L.sv * h; }
  }
  if (!L.drag) {
    if (L.x < g.minX) {
      if (lp.wallBounce && L.v < -45) L.sv -= Math.min(.45, Math.abs(L.v) / 1050) * lp.wallBounce;
      L.x = g.minX; if (L.v < 0) L.v = 0;
    } else if (L.x > g.maxX) {
      if (lp.wallBounce && L.v > 45) L.sv -= Math.min(.45, Math.abs(L.v) / 1050) * lp.wallBounce;
      L.x = g.maxX; if (L.v > 0) L.v = 0;
    }
  }
  paintLens();
  if (!L.down && !L.drag && Math.abs(L.x - L.tx) < .18 && Math.abs(L.v) < 2.2 && Math.abs(L.s - L.ts) < .0018 && Math.abs(L.sv) < .018) {
    L.x = L.tx; L.v = 0; L.s = L.ts; L.sv = 0; paintLens(); L.raf = 0; L.last = 0; return;
  }
  L.raf = requestAnimationFrame(stepLens);
}
function kick() { if (!motionOn()) { L.x = L.tx; L.s = L.ts; L.v = L.sv = 0; paintLens(); return; } if (!L.raf) { L.last = 0; L.raf = requestAnimationFrame(stepLens); } }
function idxAtX(x, g) { g = g || tabGeom(); return clamp(Math.round((x - g.padL) / g.w), 0, TABS.length - 1); }
function localLensX(e, g) { g = g || tabGeom(); var r = bar.getBoundingClientRect(); return e.clientX - r.left - g.w / 2; }
bar.addEventListener('pointerdown', function (e) {
  if (e.button != null && e.button !== 0) return;
  e.preventDefault();
  try { bar.setPointerCapture(e.pointerId); } catch (_) {}
  var g = tabGeom(), x = localLensX(e, g), hit = clamp(Math.floor((e.clientX - tabsEl.getBoundingClientRect().left) / g.w), 0, TABS.length - 1);
  L.down = true; L.drag = false; L.hitIdx = hit; L.moved = 0; L.fx0 = L.fx = x; L.ft = performance.now(); L.fv = 0;
  L.gx = Math.abs(x - L.x) < g.w * .55 ? L.x - x : 0;
  bar.classList.add('pressing');
  L.tx = g.padL + hit * g.w;
  markTabBtn(TABS[hit][0]);
  var lp = lensPhys();
  if (motionOn() && fxOn('press') && !(typeof lowFx === 'function' && lowFx())) {
    if (lp.rigid) pulseCyberLens();
    else { L.sv = 0.22; kick(); }
  } else paintLens();
});
bar.addEventListener('pointermove', function (e) {
  if (!L.down) return;
  var g = tabGeom(), fx = localLensX(e, g), lp = lensPhys();
  var now = performance.now(), dt = Math.max(1, now - L.ft);
  L.fv = L.fv * .4 + (fx - L.fx) / dt * 1000 * .6; L.fx = fx; L.ft = now;
  L.moved = Math.max(L.moved, Math.abs(fx - L.fx0));
  if (!L.drag) {
    if (L.moved < 6) return;
    L.drag = true; L.ts = 1.03; bar.classList.add('drag');
  }
  var dragPad = lp.rigid ? 0 : 6;
  var raw = clamp(fx + L.gx, g.minX - dragPad, g.maxX + dragPad);
  var prev = idxAtX(L.tx, g), cur = idxAtX(raw, g); L.tx = raw;
  if (cur !== prev) {
    markTabBtn(TABS[cur][0]);
    pulseCyberLens();
    if (typeof haptic === 'function') haptic(6);
  }
  kick();
});
function releaseLens(e) {
  if (!L.down) return;
  var wasDrag = L.drag;
  L.down = false; L.drag = false; bar.classList.remove('drag', 'pressing');
  var g = tabGeom(), i;
  if (!wasDrag || L.moved < 6) {
    i = e && e.clientX != null && e.type !== 'pointercancel'
      ? clamp(Math.floor((e.clientX - tabsEl.getBoundingClientRect().left) / g.w), 0, TABS.length - 1)
      : L.hitIdx;
  } else {
    var fv = performance.now() - L.ft < 120 ? L.fv : 0, af = Math.abs(fv);
    var fling = af > 700 ? (fv > 0 ? 1 : -1) * Math.min(g.w * .45, (af - 700) * .05) : 0;
    i = idxAtX(L.tx + fling, g);
  }
  var prevIdx = ORDER.indexOf(S.page);
  L.tx = g.padL + i * g.w; L.ts = 1;
  if (i !== prevIdx) pulseCyberLens();
  markTabBtn(TABS[i][0]);
  kick(); go(TABS[i][0]);
}
bar.addEventListener('pointerup', releaseLens);
bar.addEventListener('pointercancel', releaseLens);
function syncTab(name, instant) {
  var g = tabGeom(), idx = Math.max(0, ORDER.indexOf(name));
  markTabBtn(name); L.tx = g.padL + idx * g.w; L.ts = 1;
  if (instant) { L.x = L.tx; L.v = 0; L.s = 1; L.sv = 0; paintLens(); } else kick();
}
if (typeof ResizeObserver === 'function') {
  try { new ResizeObserver(function () { layoutLens(); if (typeof refreshHyaliteTargets === 'function') refreshHyaliteTargets(); }).observe(bar); } catch (_) {}
}
/* v5.38.0 根治乱滑: 展开设备卡(.dev)绝不因卡片总高超出底栏而强制大幅滚走页面，仅当卡片标题头本身被底栏遮挡时微调 */
function ensureAboveTabbar(el) {
  if (!el || !bar) return;
  if (el.classList && el.classList.contains('dev')) {
    var hdr = $('.dev-h', el);
    if (!hdr) return;
    var hr = hdr.getBoundingClientRect(), br0 = bar.getBoundingClientRect();
    if (hr.bottom > br0.top - 8) {
      var pg0 = $('#p-' + S.page);
      if (pg0) pg0.scrollBy({ top: Math.min(120, hr.bottom - br0.top + 28), behavior: motionOn() ? 'smooth' : 'auto' });
    }
    return;
  }
  var waitMs = !motionOn() ? 30 : (typeof themePhys === 'function' ? themePhys().foldMs : 220);
  setTimeout(function () {
    var pg = $('#p-' + S.page); if (!pg) return;
    var er = el.getBoundingClientRect(), br = bar.getBoundingClientRect();
    if (er.top < 96) return; // 卡片顶部已在视口上半区时绝不向下拽走标题!
    var overlap = er.bottom - (br.top - 16);
    if (overlap > 0) pg.scrollBy({ top: Math.min(overlap, 160), behavior: motionOn() ? 'smooth' : 'auto' });
  }, waitMs);
}

/* ═══ 顶栏热点手机本机 5G / Wi-Fi 信号实时胶囊与四象限诊断弹层 ═══ */
function paintSignalPill() {
  var btn = $('#sig-pill'); if (!btn) return;
  var sig = S.signal;
  if (!sig || !sig.available) { btn.hidden = true; return; }
  btn.hidden = false;
  var q = sig.quality || 'good';
  btn.className = 'sig-pill press q-' + q;
  var dbm = sig.mode === 'wifi_sta' ? sig.wifi_rssi_dbm : sig.rsrp_dbm;
  var ratTxt = sig.rat || (sig.mode === 'wifi_sta' ? 'Wi-Fi' : '5G');
  btn.innerHTML = cellSvg(sig.bars, sig.mode) + '<span>' + esc(ratTxt) + (dbm ? ' ' + dbm + '<span class="sig-unit">dBm</span>' : '') + '</span>';
}
function signalSheet() {
  var sig = S.signal || {};
  var ar = S.autorate || (S.cfg && S.cfg.autorate) || {};
  var isWifi = sig.mode === 'wifi_sta';
  var dbm = isWifi ? sig.wifi_rssi_dbm : sig.rsrp_dbm;
  var rtt = num(ar.rtt_ms), dRtt = num(ar.delta_rtt_ms);
  var quadTitle = '空口通畅 · 射频健康', quadDesc = '当前上游空口信号充足且队列时延平稳，热点客户端可跑满物理带宽。', quadCls = 'b-ok';
  if (sig.quality === 'weak' || sig.quality === 'critical') {
    quadTitle = '象限 II · 热点手机自身基站弱信号边缘';
    quadDesc = '手机当前 RSRP/SINR 处于弱场边缘（α_rf = ' + trim0(num(sig.rf_ceiling_factor, 1).toFixed(2)) + '），建议将手机移至窗边，并开启 5G Autorate 自动压低突发上限防断流。';
    quadCls = 'b-red';
  } else if (dRtt > 25) {
    quadTitle = '象限 III · 信号满格但基站空口晚高峰拥塞';
    quadDesc = '手机射频信号良好，但上游排队增量时延 +' + Math.round(dRtt) + 'ms，属于运营商基站调度拥塞；5G Autorate 已自动介入退避稳帧。';
    quadCls = 'b-warn';
  }
  var h = '<h3>热点手机实时信号与网络诊断</h3>' +
    '<div class="sub">零 Modem 唤醒读取 <span class="mono">dumpsys telephony.registry</span> · 联动 5G Autorate</div>' +
    '<div class="dbox" style="margin-bottom:10px">' +
      '<div class="row2"><span class="k">当前承载制式</span><span class="v"><span class="badge ' + quadCls + '">' + esc(sig.rat || '未知') + ' · ' + esc(sig.quality_cn || '') + '</span></span></div>' +
      (sig.carrier ? '<div class="row2"><span class="k">上网卡与出口</span><span class="v">' + esc('卡' + (sig.slot || 1) + ' · ' + sig.carrier) + (sig.upstream_iface ? ' (<span class="mono">' + esc(sig.upstream_iface) + '</span>)' : '') + '</span></div>' : '') +
      '<div class="row2"><span class="k">' + (isWifi ? 'Wi-Fi RSSI 信号强度' : '5G/LTE RSRP 接收功率') + '</span><span class="v mono">' + (dbm ? dbm + ' dBm' : '—') + (sig.band ? ' · 频段 ' + esc(sig.band) : '') + (sig.bandwidth_mhz ? ' (' + sig.bandwidth_mhz + 'MHz)' : '') + '</span></div>' +
      (!isWifi && sig.sinr_db != null ? '<div class="row2"><span class="k">SINR 信噪比 / RSRQ</span><span class="v mono">' + sig.sinr_db + ' dB / ' + (sig.rsrq_db || '—') + ' dB</span></div>' : '') +
      (isWifi && sig.wifi_link_mbps ? '<div class="row2"><span class="k">Wi-Fi 协商速率</span><span class="v mono">' + sig.wifi_link_mbps + ' Mbps</span></div>' : '') +
      '<div class="row2"><span class="k">Autorate 射频天花板系数 α_rf</span><span class="v mono">' + Math.round(num(sig.rf_ceiling_factor, 1) * 100) + '%</span></div>' +
      (rtt > 0 ? '<div class="row2"><span class="k">上游实测 RTT / 排队膨胀</span><span class="v mono">' + rtt.toFixed(1) + ' ms (Δ ' + dRtt.toFixed(1) + ' ms)</span></div>' : '') +
    '</div>' +
    '<div class="dsec">四象限瓶颈智能归因</div>' +
    '<div class="dbox"><div style="font-weight:700;margin-bottom:4px">' + quadTitle + '</div><div class="note">' + quadDesc + '</div></div>' +
    '<div class="btns" style="margin-top:12px"><button class="btn sec press" id="sig-refresh-btn">立即刷新信号</button><button class="btn pri press" data-close>完成</button></div>';
  sheet(h);
  var rb = $('#sig-refresh-btn');
  if (rb) rb.onclick = function () {
    busyWhile(rb, api.get('/api/signal', { refresh: 1 }).then(function (r) { S.signal = r; paintSignalPill(); signalSheet(); toast('实时信号已刷新'); }));
  };
}

/* ═════════════════════ 主题(圆形扩散 / 战术瞬切) ═════════════════════ */
function setStyle(v, x, y) {
  S.style = v === 'cyber' || v === 'liquid' ? v : 'default'; LS.set('hnc6.style', S.style);
  revealApply(function () { applyTheme(); if (typeof navSync === 'function') navSync(); }, x, y);
  $$('[data-style-pick]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-style-pick') === S.style); });
  setTimeout(function () { placeSegs(); layoutLens(); syncTab(S.page, true); }, 60);
}
function setTheme(t, x, y) {
  S.theme = t; LS.set('hnc6.theme', t);
  revealApply(applyTheme, x, y);
  $$('[data-theme-pick]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-theme-pick') === t); });
}
// 圆形扩散切换(主题 / 界面风格共用; Cyber 采用极速战术快切)
function revealApply(fn, x, y) {
  if (document.startViewTransition && motionOn() && !(typeof lowFx === 'function' && lowFx()) && x != null) {
    var r = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    var vt = document.startViewTransition(fn);
    var isCy = S.style === 'cyber';
    vt.ready.then(function () {
      document.documentElement.animate({ clipPath: ['circle(0px at ' + x + 'px ' + y + 'px)', 'circle(' + r + 'px at ' + x + 'px ' + y + 'px)'] },
        { duration: isCy ? 260 : 480, easing: isCy ? 'cubic-bezier(.08,.94,.16,1)' : 'cubic-bezier(.22,1,.36,1)', fill: 'forwards', pseudoElement: '::view-transition-new(root)' });
    }).catch(function () {});
    setTimeout(function () { try { vt.skipTransition(); } catch (_) {} }, 1000);
  } else fn();
}
function isDark() { var a = document.documentElement.getAttribute('data-theme'); return a === 'dark' || (!a && matchMedia('(prefers-color-scheme: dark)').matches); }
$('#theme-btn').addEventListener('click', function (e) { setTheme(isDark() ? 'light' : 'dark', e.clientX, e.clientY); });
$('#bell').addEventListener('click', openAlerts);
var v6NavBtnEl = $('#v6-nav-btn'); if (v6NavBtnEl) v6NavBtnEl.addEventListener('click', function () { if (S.page !== 'vector') go('vector'); else if (typeof v6ScrollToLeakGuard === 'function') v6ScrollToLeakGuard(); });
var sigPillEl = $('#sig-pill'); if (sigPillEl) sigPillEl.addEventListener('click', signalSheet);

/* ═════════════════════ 事件委托 ═════════════════════ */
function foldToggle(el, key) {
  if (!el) return;
  var on = !el.classList.contains('open'); el.classList.toggle('open', on); S.open[key] = on;
  if (on) {
    if (motionOn() && typeof motionTheme === 'function' && motionTheme() === 'cyber') {
      el.classList.remove('cy-fold-pulse');
      void el.offsetWidth;
      el.classList.add('cy-fold-pulse');
      clearTimeout(el._cyFoldT);
      el._cyFoldT = setTimeout(function () { el.classList.remove('cy-fold-pulse'); }, 180);
    }
    placeSegs(el); ensureAboveTabbar(el);
  }
  saveFolds(key);
  return on;
}
function ctxDev(a) { var box = a.closest('[data-dev]') || a.closest('[data-side]'); return box ? { box: box, d: devBy(box.getAttribute('data-dev') || box.getAttribute('data-side')) } : { box: null, d: null }; }
function selectedDevs() { return S.devices.filter(function (x) { return S.picked[x.mac]; }); }
function runBatch(act) {
  var sel = selectedDevs(); if (!sel.length) { toast('先勾选设备', 'warn'); return; }
  if (act === 'b-tpl') { tplSheet(sel); return; }
  var T = { 'b-clear': ['清除限速', function (d) { return api.action('rule_clear', { mac: d.mac }); }],
    'b-cdelay': ['清除延迟', function (d) { return api.action('delay_clear', { mac: d.mac }); }],
    'b-block': ['封锁', function (d) { return api.action('bl_add', { mac: d.mac }); }],
    'b-unblock': ['解除封锁', function (d) { return d.blocked ? api.action('bl_del', { mac: d.mac }) : Promise.resolve(); }] }[act];
  var gw = act === 'b-block' ? sel.filter(looksLikeGateway) : [];
  confirmSheet('批量' + T[0], '将对 ' + sel.length + ' 台设备执行「' + T[0] + '」' + (gw.length ? '<br><b style="color:var(--red)">其中 ' + gw.map(function (d) { return esc(d.name); }).join('、') + ' 看起来像网关，封锁可能让热点断网</b>' : ''), T[0], { safe: act === 'b-unblock' }).then(function (ok) {
    if (!ok) return;
    var okN = 0, chain = Promise.resolve();
    sel.forEach(function (d) { chain = chain.then(function () { return T[1](d).then(function () { okN++; }, function () {}); }); });
    chain.then(function () { toast(T[0] + ' ' + okN + '/' + sel.length + ' 台完成', okN === sel.length ? 'ok' : 'warn'); return globalRefresh(); });
  });
}
document.addEventListener('click', function (e) {
  var t = e.target, q;
  if (!t.closest('.dd')) closeDD();
  if ((q = t.closest('.seg button'))) {
    var sg = q.parentNode, k = sg.getAttribute('data-seg'), v = q.getAttribute('data-v');
    if (q.classList.contains('on') && k !== 'delay-pre') return;
    if (sg.classList.contains('pending')) return;   // 上一次切换还在提交
    var sgd = ctxDev(q).d; if (sgd && S.busy[sgd.mac] && k !== 'delay-pre' && k !== 'q-act') { toast('这台设备还有操作在进行', 'warn'); return; }
    $$('button', sg).forEach(function (b) { b.classList.toggle('on', b === q); });
    sg.classList.remove('jelly'); placeSegs(sg.parentNode);
    if (k === 'apps-sub') { S.appsSub = v; var bx = $('#apps-sub'); bx.innerHTML = appsSub(); placeSegs(bx); stagger(bx); if (v === 'rules') { if (typeof paintUnknown === 'function') paintUnknown(); if (S.open.fpl) loadFP(); if (S.open.rpack) loadRulepack(); } }
    else if (k === 'aseg') { S.aseg = v; var ab = $('#aseg-body'); ab.innerHTML = v === 'stats' ? statsBody() : dpiBody(); placeSegs(ab); stagger(ab); afterAseg(); }
    else if (k === 'range') { S.statsRange = v; refreshStats(); }
    else if (k === 'hist') { S.dpiDays = +v; paintDpiHist(); paintUnkTraffic(); Promise.all([loadDpiHist(S.dpiDays), loadAppUsage(S.dpiDays)]).then(paintDpiHist); loadDpiUnk(S.dpiDays).then(paintUnkTraffic); }
    else if (k === 'pu-period') { S.puPeriod = v; refreshPU(); }
    else if (k === 'dflt') { S.dpiFilter = v; paintClients(); }
    else if (k === 'fxp') { if (v === 'off') { S.motion = false; LS.set('hnc6.motion', '0'); } else { S.motion = true; LS.set('hnc6.motion', '1'); FX = Object.assign({}, FX_PRESETS[v]); saveFx(); } fxRefresh(); toast('动画效果：' + FXP_T[v]); }
    else if (k === 'guard-mode') { busyWhile(q, api.action('clsact_mode_set', { mode: v }, { timeout: 30000, maxTime: 28 })).then(function (r) { var g = detailJSON(r); S.cfg.clsact_bpf_mode = v; if (g && typeof g === 'object') S.cfg.offload_guard = g; S.clsact = null; toast('硬件加速兜底：' + q.textContent); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); if (S.page === 'settings') renderSettings(false); }); }
    else if (k === 'aqm-mode') { busyWhile(q, api.action('tc_leaf_aqm_set', { mode: v })).then(function () { S.aqmMode = v; LS.set('hnc6.aqm', v); toast('默认队列 AQM：' + q.textContent + ' · 之后新设 / 重设的限速生效'); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); if (S.page === 'settings') renderSettings(false); }); }
    else if (k === 'glass-mode') { if (typeof setGlassMode === 'function') setGlassMode(v); toast(v === 'frosted' ? '已切换：经典毛玻璃（均匀高斯柔雾）' : '已切换：iOS 27 液态玻璃（真光学边缘折射）'); }
    else if (k === 'fxspring') { FX.spring = v; saveFx(); fxRefresh(); }
    else if (k === 'connv') { S.connView = v; paintConnSheet(); }
    else if (k === 'webacc-mode') { S.webaccMode = v; }
    else if (k === 'dev-tab') { var d0 = ctxDev(q).d, b0 = ctxDev(q).box; if (d0 && b0) { S.devTab[d0.mac] = v; if (v === 'quota') atNeed(d0); $$('[data-dev-pane]', b0).forEach(function (pn) { pn.hidden = pn.getAttribute('data-dev-pane') !== v; }); placeSegs(b0); } }
    else if (k === 'studio-mode') {
      busyWhile(sg, api.action('self_studio_start', { mode: v, auto_stop_min: '15' }, { timeout: 22000, maxTime: 20 })).then(function () {
        var mTxt = { smart_screen: '已切换为「亮屏智能常驻」：亮屏无感采集，熄屏零耗电并自动蒸馏', lease_15m: '已开启「15 分钟集中快训」：到期自动蒸馏并退回常驻', off: '已关闭本机自训采集（0 后台唤醒）' }[v] || '已切换自训模式';
        toast(mTxt);
        return loadApps();
      }).then(function () { if (S.page === 'apps') renderApps(false); if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); }).catch(function (e2) { toast(errText(e2), 'err'); if (S.page === 'apps') renderApps(false); if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); });
    }
    else if (k === 'fgdays') { var fgd = devBy(S.fgMac); if (fgd) loadFgTl(fgd, +v); }
    else if (k === 'dns-bm') { busyWhile(sg, api.action('dns_takeover_set', { block_mode: v })).then(function () { toast('拦截方式：' + q.textContent); return loadDNS(); }).catch(function (e) { toast(errText(e), 'err'); loadDNS(); }); }
    else if (k === 'eval-days') { S.evalDays = +v; loadEval(S.evalDays); }
    else if (k === 'fg-engine') { busyWhile(sg, api.action('dpi_fg_engine', { engine: v })).then(function () { toast('前台识别引擎：' + q.textContent + ' · 时间线从此刻起按它记录'); return loadFgEngine(); }).catch(function (e) { toast(errText(e), 'err'); loadFgEngine(); }); }
    else if (k === 'set-lv') {
      S.setLv = v; LS.set('hnc6.set_lv', v);
      $$('#p-settings [data-lv-sec]').forEach(function (sec) {
        sec.hidden = (v !== 'all' && sec.getAttribute('data-lv-sec') !== v);
      });
    }
    else if (k === 'rmode') { S.refreshMode = v; LS.set('hnc.refresh-mode', v); toast('刷新模式：' + q.textContent); schedulePoll(50); }
    else if (k === 'qos-mode') setQos('mode', v, q);
    else if (k === 'qos-scale') setQos('scale', v, q);
    else if (k === 'encdns') { var encOk = false; busyWhile(q, api.action('encdns_set', { policy: v }, { timeout: 30000, maxTime: 28 }).then(function (r) { encOk = true; return loadEncdns().then(function () { return r; }); }, function (e) { toast(errText(e), 'err'); return loadEncdns(); })).then(function (r) { if (S.page === 'settings') renderSettings(false); if (encOk) toast('加密 DNS 拦截：' + (ENC_T[v] || v) + encdnsDetailTxt(r)); }); }
    else if (k === 'encdns-dev') { var ec = ctxDev(q); if (ec.d) { var ed = ec.d; devAct(ed.mac, function () { return api.action('encdns_set', { scope: 'device', mac: ed.mac, policy: v }, { timeout: 30000, maxTime: 28 }).then(function (r) { return loadEncdns().then(function () { return r; }); }); }, function (r) { return ed.name + ' · 加密 DNS：' + (ENC_T[v] || v) + encdnsDetailTxt(r); }, q); } }
    else if (k === 'pu-ns') { busyWhile(q, api.action('phone_usage_set', { use_netstats: v })).then(function () { toast('流量数据来源：' + q.textContent); if (S.puCfg) S.puCfg.use_netstats = v; S.pu = {}; return refreshPU(true); }).catch(function (e) { toast(errText(e), 'err'); }); }
    else if (k === 'delay-pre') { var cx = ctxDev(q); if (cx.box) { var di = $('[data-f="delay"]', cx.box); if (di) di.value = +v ? v : ''; if (!+v) { $('[data-f="jitter"]', cx.box).value = ''; $('[data-f="loss"]', cx.box).value = ''; } } }
    return;
  }
  if ((q = t.closest('.toggle'))) {
    // 提交中的开关不再响应(防重复提交 / 来回翻); 卡片有别的操作在跑时也先不翻, 免得界面和实际不一致
    if (q.disabled || q.classList.contains('pending')) return;
    var tc = ctxDev(q);
    if (tc.d && S.busy[tc.d.mac]) { toast('这台设备还有操作在进行', 'warn'); return; }
    var nv = q.getAttribute('aria-checked') !== 'true'; q.setAttribute('aria-checked', String(nv));
    q.classList.remove('liquid-pop', 'tog-on-fx', 'tog-off-fx');
    if (motionOn() && !(typeof lowFx === 'function' && lowFx())) {
      void q.offsetWidth;
      q.classList.add(nv ? 'tog-on-fx' : 'tog-off-fx');
      clearTimeout(q._togFxT);
      q._togFxT = setTimeout(function () { q.classList.remove('tog-on-fx', 'tog-off-fx'); }, 360);
    }
    var ta = q.getAttribute('data-act');
    if (q.hasAttribute('data-set')) { setToggleCfg(q.getAttribute('data-set'), q); return; }
    if (q.hasAttribute('data-selftog')) { selfToggle(q, q.getAttribute('data-selftog')); return; }
    if (q.hasAttribute('data-local')) return;   // 表单内开关, 点「保存」才提交
    if (ta === 'wl-mode') { setWhitelistMode(nv, q); return; }
    if (!tc.d) return;
    if (ta === 'sqm') devAct(tc.d.mac, function () { return api.action('rule_sqm', { mac: tc.d.mac, enabled: String(nv) }); }, nv ? '已开启低延迟模式' : '已关闭低延迟模式', q);
    if (ta === 'appqos') devAct(tc.d.mac, function () { return api.action('app_qos_set', { mac: tc.d.mac, enabled: String(nv) }); }, nv ? '已开启按应用分优先级（约 3 秒内生效）' : '已关闭按应用分优先级', q);
    if (ta === 'wl') devAct(tc.d.mac, function () { return api.action('device_whitelist_set', { mac: tc.d.mac, enabled: String(nv) }); }, nv ? tc.d.name + ' 已加入白名单' : tc.d.name + ' 已移出白名单', q);
    return;
  }
  if ((q = t.closest('[data-filter]'))) { S.filter = q.getAttribute('data-filter'); LS.set('hnc_device_filter', S.filter); closeDD(); listFreezeUntil = 0; renderDevList(false); renderDevices(false); return; }
  if ((q = t.closest('[data-style-pick]'))) { var rs = q.getBoundingClientRect(); setStyle(q.getAttribute('data-style-pick'), rs.left + rs.width / 2, rs.top + rs.height / 2); return; }
  if ((q = t.closest('[data-theme-pick]'))) { var r = q.getBoundingClientRect(); setTheme(q.getAttribute('data-theme-pick'), r.left + r.width / 2, r.top + r.height / 2); return; }
  if ((q = t.closest('[data-al]'))) { var row = q.closest('[data-alid]'); alertAction(q.getAttribute('data-al'), row.getAttribute('data-alid'), row.getAttribute('data-almac')); return; }
  if ((q = t.closest('[data-cand]'))) { candAct(q.getAttribute('data-cand'), q.closest('[data-apex]').getAttribute('data-apex')); return; }
  if ((q = t.closest('[data-excl]'))) { excludeApp(q.getAttribute('data-excl'), q.getAttribute('data-name')); return; }
  if ((q = t.closest('[data-exp-min]'))) { S.expMin = +q.getAttribute('data-exp-min'); $$('[data-exp-min]').forEach(function (b) { b.classList.toggle('on', b === q); }); $('#exp-from').value = dtLocal(Date.now() - S.expMin * 60000); $('#exp-to').value = dtLocal(Date.now()); return; }
  if ((q = t.closest('[data-dl]'))) { downloadExport(q.getAttribute('data-dl'), q.getAttribute('data-url')); return; }
  if ((q = t.closest('[data-cnk]'))) { var cm = S.connMac || (ctxDev(q).d || {}).mac; if (cm) connActSheet(cm, q.getAttribute('data-cnk')); return; }
  if ((q = t.closest('[data-cbdel]'))) { var kv2 = q.getAttribute('data-cbdel').split('|'), dm = S.connMac; if (!dm) return; api.action('conn_block_del', { mac: dm, kind: kv2[0], value: kv2.slice(1).join('|') }).then(function () { toast('已解除封锁'); return loadConns(dm); }).then(paintConnSheet).catch(function (e2) { toast(errText(e2), 'err'); }); return; }
  if ((q = t.closest('[data-unign]'))) { api.action('discover_unignore', { id: q.getAttribute('data-unign') }).then(function () { toast('已撤销忽略'); return loadDisc(); }).catch(function (e2) { toast(errText(e2), 'err'); }); return; }
  if ((q = t.closest('[data-urdel]'))) { var urid = q.getAttribute('data-urdel'), urn = q.getAttribute('data-name'); confirmSheet('删除规则「' + urn + '」？', '删除后这个应用又会变回「认不出」，可能重新出现在新发现列表里。', '删除').then(function (ok) { discSheet(); S.discManage = true; paintDiscSheet(); if (!ok) return; api.action('user_rule_del', { id: urid }).then(function () { toast('已删除'); return loadDisc(); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); return; }
  if ((q = t.closest('[data-disc]'))) { discOpenDetail(q.getAttribute('data-disc')); return; }
  if ((q = t.closest('[data-dcat]'))) { if (S.discForm) { S.discForm.cat = q.getAttribute('data-dcat'); $$('[data-dcat]').forEach(function (b) { b.classList.toggle('on', b === q); }); } return; }
  if ((q = t.closest('[data-dsuf]'))) { if (S.discForm) { var sx = q.getAttribute('data-dsuf'); S.discForm.sufs[sx] = !S.discForm.sufs[sx]; q.classList.toggle('on', S.discForm.sufs[sx]); } return; }
  if ((q = t.closest('[data-rule-tpl]'))) { ruleTemplate(q.getAttribute('data-rule-tpl')); return; }
  if ((q = t.closest('[data-mm-open]'))) { var mmp = q.getAttribute('data-mm-open').split('|'); mergeSheet(mmp[0], mmp[1]); return; }
  // 模拟环境 / 应用限时 / 类别封锁
  if ((q = t.closest('[data-sim-preset]'))) { var spk = q.getAttribute('data-sim-preset'); api.action('sim_preset', { preset: spk }).then(simAfter('已载入预设「' + ((SIM_P[spk] || [spk])[0]) + '」· 模拟环境已开启')).catch(function (e2) { toast(errText(e2), 'err'); }); return; }
  if ((q = t.closest('[data-sim-del]'))) { var sdm = q.getAttribute('data-sim-del'), sdn = q.getAttribute('data-name'); api.action('sim_device_del', { mac: sdm }).then(simAfter('已删除 ' + sdn)).catch(function (e2) { toast(errText(e2), 'err'); }); return; }
  if ((q = t.closest('[data-atl]'))) { var atd = ctxDev(q).d; if (atd) appTimeSheet(atd, q.getAttribute('data-atl'), q.getAttribute('data-name') || q.getAttribute('data-atl')); return; }
  if ((q = t.closest('[data-cblk]'))) {
    var cbd = ctxDev(q).d; if (!cbd) return;
    var cat = q.getAttribute('data-cblk'), cen = !q.classList.contains('on'), ccnt = q.querySelector('small');
    var go2 = function () { return devAct(cbd.mac, function () { return api.action('category_block_set', { mac: cbd.mac, category: cat, enabled: String(cen) }); }, (cen ? '已封锁「' : '已解除「') + catLabel(cat) + '」类应用').then(function () { return loadAppTime(cbd.mac, true); }); };
    if (cen) confirmSheet('封锁「' + catLabel(cat) + '」类应用？', esc(cbd.name) + ' 将无法使用这一类的' + (ccnt ? ' ' + esc(ccnt.textContent) + ' 个' : '') + '应用' + (cat === 'social' ? '。<br>「社交」包含字节系服务，同公司的其他应用也可能受影响' : '') + '。可以随时再点一次解除。', '封锁').then(function (ok) { if (ok) go2(); });
    else go2();
    return;
  }
  if ((q = t.closest('[data-fw-del]'))) { var pk = q.getAttribute('data-fw-del'); api.action('flywheel_exclude_set', { op: 'remove', pkg: pk }).then(function () { toast('已移除 ' + pk); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); return; }
  if ((q = t.closest('[data-fpdel]'))) { var fid = q.getAttribute('data-fpdel'), fall = fid === '__all'; confirmSheet(fall ? '撤销全部识别纠正？' : '撤销这条识别纠正？', '之后这类连接重新按规则库和自动学习来识别。', '撤销').then(function (ok) { if (ok) busyWhile(q, api.action('dpi_correct_del', fall ? { all: 'true' } : { id: fid })).then(function () { toast('已撤销'); return loadFP(); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); return; }
  if ((q = t.closest('[data-revoke]'))) { var tid = q.getAttribute('data-revoke'); confirmSheet('撤销「' + q.getAttribute('data-label') + '」的授权？', '这台设备需要重新配对才能远程访问。', '撤销').then(function (ok) { if (ok) api.action('pair_revoke', { token: tid }).then(function () { toast('已撤销'); loadTokens(); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); return; }
  if ((q = t.closest('[data-pu-pre]'))) { var sl = q.getAttribute('data-slot'), gv = q.getAttribute('data-pu-pre'), inpEl = $('#pu-in-plan-' + sl); if (inpEl) inpEl.value = gv === '0' ? '0' : gv; $$('[data-pu-pre][data-slot="' + sl + '"]').forEach(function (b) { b.classList.toggle('on', b === q); }); return; }
  var a = t.closest('[data-act]'); if (!a || a.disabled) return;
  var act = a.getAttribute('data-act'), cx2 = ctxDev(a), d = cx2.d, box = cx2.box;
  switch (act) {
    case 'dd': var dd = a.closest('.dd'), was = dd.classList.contains('open'); closeDD(); dd.classList.toggle('open', !was); break;
    case 'set-fold-toggle':
      var allCards = $$('#p-settings .scard[data-foldkey]');
      var visibleCards = allCards.filter(function (c) { var sec = c.closest('[data-lv-sec]'); return !sec || !sec.hidden; });
      var hasOpen = visibleCards.some(function (c) { return c.classList.contains('open'); });
      visibleCards.forEach(function (c, idx) {
        var k2 = c.getAttribute('data-foldkey'), shouldOpen = !hasOpen && (S.setLv !== 'all' || idx < 4);
        c.classList.toggle('open', shouldOpen); S.open[k2] = shouldOpen; saveFolds(k2);
        if (shouldOpen) placeSegs(c);
      });
      a.textContent = !hasOpen ? '全部收起' : '展开常用';
      break;
    case 'fold': var key = a.getAttribute('data-key'), selKey = (window.CSS && CSS.escape) ? CSS.escape(key) : String(key || '').replace(/["\\]/g, '\\$&'), fw = a.closest('[data-foldkey="' + selKey + '"]') || document.getElementById(key); var opened = foldToggle(fw, key);
      if (opened && (key === 'logs' || key === 'scard-diag') && S.open.logs) loadLog();
      if (opened && (key === 'tokens' || key === 'scard-rem') && S.open.tokens) loadTokens();
      if (opened && key === 'dnst') loadDNS(); if (opened && key === 'fpl') loadFP(); if (opened && key === 'pwr') loadPower(false);
      if (opened && key === 'deval') loadEval();
      if (opened && key === 'fgeng') loadFgEngine();
      if (opened && key === 'rpack') loadRulepack();
      if (opened && /^(at|cb)-/.test(key)) loadAppTime(key.slice(3));
      var ftBtn = $('#p-settings [data-act="set-fold-toggle"]');
      if (ftBtn) {
        var anyOp = $$('#p-settings .scard.open').length > 0;
        ftBtn.textContent = anyOp ? '全部收起' : '展开常用';
      }
      break;
    case 'toggle-dev':
      if (!d) break;
      if (S.batch) { if (S.picked[d.mac]) delete S.picked[d.mac]; else S.picked[d.mac] = 1; box.classList.toggle('picked', !!S.picked[d.mac]); var pn = $('#picked-n'); if (pn) pn.textContent = Object.keys(S.picked).length; anim(box, [{ transform: 'scale(.97)' }, { transform: 'none' }], { duration: 260, easing: 'ease-out' }); break; }
      if (wide()) {
        var same = S.sel === d.mac; S.sel = d.mac; $$('.dev.sel').forEach(function (x) { x.classList.remove('sel'); }); box.classList.add('sel');
        var sd = $('#dev-side'); if (same) morph(sd, devSide()); else sd.innerHTML = devSide();   // 换设备才播侧栏滑入; 点同一台只就地刷新
        placeSegs(sd); if (d.online) refreshConnMini(d.mac);
      }
      else {
        var fi = $('.fold-in', box); if (!S.open[d.mac]) { fi.innerHTML = devBody(d); }
        foldToggle(box, d.mac); a.setAttribute('aria-expanded', String(!!S.open[d.mac])); placeSegs(box);
        if (S.open[d.mac] && d.online) refreshConnMini(d.mac);
        if (!S.open[d.mac]) { (S.closingAt = S.closingAt || {})[d.mac] = Date.now(); freezeList(900); }   // 收起动画期间后台刷新不清空卡片内容   // 收起后等折叠动画走完, 再把顺序过时的列表平滑重排
      }
      break;
    case 'conns': if (d) connSheet(d); break;
    case 'ident-edit': if (d) identSheet(d); break;
    case 'fg-tl': if (d) fgTimelineSheet(d); break;
    case 'merge-yes': if (d && d.merge) doMerge(d.mac, d.merge.old_mac, d.merge.old_name || d.merge.old_mac, false); break;
    case 'merge-no': if (d && d.merge) dismissMerge(d.mac, d.merge.old_mac, d.merge.old_name || d.merge.old_mac); break;
    case 'fx-demo': fxDemo(a.getAttribute('data-demo')); break;
    case 'fx-perf': setLowFx(!PERF.low, false); PERF.strikes = 0; fxRefresh(); toast(PERF.low ? '已切到简化动画' : '已恢复完整动画'); break;
    case 'self-conns': selfConnSheet(); break;
    case 'apply-limit': var lv = [readNum(box, 'down'), readNum(box, 'up')]; devAct(d.mac, function () { return doLimit(d, mbsToMbps(lv[0]), mbsToMbps(lv[1])); }, lv[0] || lv[1] ? '已应用限速到 ' + d.name : '已清除 ' + d.name + ' 的限速', a); break;
    case 'clear-limit': devAct(d.mac, function () { return api.action('rule_clear', { mac: d.mac }); }, '已清除 ' + d.name + ' 的限速', a); break;
    case 'apply-delay': var dv = [readNum(box, 'delay'), readNum(box, 'jitter'), readNum(box, 'loss')]; devAct(d.mac, function () { return doDelay(d, dv[0], dv[1], dv[2]); }, dv[0] || dv[1] || dv[2] ? '已对 ' + d.name + ' 注入延迟' : '已清除延迟', a); break;
    case 'clear-delay': devAct(d.mac, function () { return api.action('delay_clear', { mac: d.mac }); }, '已清除 ' + d.name + ' 的延迟', a); break;
    case 'unblock': devAct(d.mac, function () { return api.action('bl_del', { mac: d.mac }); }, d.name + ' 已解除封锁', a); break;
    case 'rename': renameSheet(d.mac, d.manual || d.name !== d.mac ? d.name : ''); break;
    case 'copy-mac': copyText(d.mac).then(function (ok) { toast(ok ? '已复制 ' + d.mac : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'trend': busyWhile(a, loadTrend(d, box)); break;
    case 'applim-save': case 'applim-clear':
      var row2 = a.closest('[data-app]'), app = row2.getAttribute('data-app'), lim = act === 'applim-clear' ? 0 : mbsToMbps($('input', row2).value);
      // 应用限速表先刷新再重绘卡片: 此前卡片先按旧表画一遍, 再按新表画一遍(两次整卡重绘, 保存的值闪回旧值)
      devAct(d.mac, function () { return (lim > 0 ? api.action('app_limit_set', { mac: d.mac, app_id: app, down_mbps: trim0(lim.toFixed(3)) }) : api.action('app_limit_clear', { mac: d.mac, app_id: app })).then(function (r) { return loadAppLimits().then(function () { return r; }); }); }, lim > 0 ? '已限速 ' + app : app + ' 不再限速', a);
      break;
    case 'refresh': busyWhile(a, api.action('refresh', {}, { timeout: 15000, maxTime: 13 }).catch(function () {})).then(function () { return globalRefresh('已刷新 · ' + S.devices.filter(function (x) { return x.online; }).length + ' 台在线'); }); break;
    case 'clear-all': confirmSheet('清空所有规则', '移除全部限速、延迟、黑名单（设备列表保留）', '清空').then(function (ok) { if (ok) api.action('cleanup_rules', {}, { timeout: 30000, maxTime: 28 }).then(function () { return globalRefresh('已清空所有规则'); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'clean-offline': doCleanOffline(); break;
    case 'release': doRelease(); break;
    case 'batch': S.batch = !S.batch; S.picked = {}; renderDevices(false); break;
    case 'b-all': visibleDevs().forEach(function (x) { S.picked[x.mac] = 1; }); renderDevices(false); break;
    case 'b-none': S.picked = {}; renderDevices(false); break;
    case 'b-tpl': case 'b-clear': case 'b-cdelay': case 'b-block': case 'b-unblock': runBatch(act); break;
    case 'tpl':
      var tg = S.batch ? selectedDevs() : wide() && S.sel ? [devBy(S.sel)].filter(Boolean) : S.devices.filter(function (x) { return S.open[x.mac]; });
      tplSheet(tg, true); break;
    case 'quota-save':
      var qd = readNum(box, 'q-daily'), qm = readNum(box, 'q-month'), qt = mbsToMbps(readNum(box, 'q-thr')), qab = $('[data-seg="q-act"] button.on', box), qa = qab ? qab.getAttribute('data-v') : 'throttle';
      if (!(qd > 0) && !(qm > 0)) { toast('每日或每月至少填一个上限', 'warn'); break; }
      if (qd < 0 || qm < 0) { toast('上限不能是负数', 'err'); break; }
      devAct(d.mac, function () { var qp = { mac: d.mac, daily_gb: trim0(qd.toFixed(3)), monthly_gb: trim0(qm.toFixed(3)), action: qa }; if (qt > 0) qp.throttle_mbps = trim0(qt.toFixed(3)); return api.action('quota_set', qp); }, '已保存 ' + d.name + ' 的流量配额', a); break;
    case 'quota-clear': devAct(d.mac, function () { return api.action('quota_clear', { mac: d.mac }); }, '已删除流量配额', a); break;
    case 'sched-edit': schedSheet(d); break;
    case 'sched-clear': confirmSheet('清除分时段？', '删除 ' + esc(d.name) + ' 的全部时段，恢复手动限速。', '清除').then(function (ok) { if (ok) devAct(d.mac, function () { return api.action('schedule_clear', { mac: d.mac }); }, '已清除分时段'); }); break;
    case 'pu-save': puSave(); break;
    case 'sim-off': simSet(false).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'sim-add': simAddSheet(); break;
    case 'sim-clear': confirmSheet('清空模拟设备？', '删除全部模拟设备（不影响真实设备）。', '清空').then(function (ok) { if (ok) api.action('sim_clear', {}).then(simAfter('已清空模拟设备')).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'offload-dismiss': SS.set('hnc.hw-dismiss', S.offload.detail); renderOffloadBanner(); break;
    case 'bridge-retry': boot(true); break;
    case 'bridge-start': toast('正在拉起 HNC 服务…'); execRaw('nohup sh ' + MOD_DIR + '/service.sh >/dev/null 2>&1 &', 5000).then(function () { setTimeout(function () { boot(true); }, 6000); }); break;
    // 应用页
    case 'export-build': buildExport(a); break;
    case 'export-list': busyWhile(a, loadExports()); break;
    case 'self-purge': confirmSheet('清理自学习明细？', '删除 run/self_attrib.*.jsonl 明细（已学到的规则保留）。', '清理').then(function (ok) { if (ok) api.action('self_attrib_purge').then(function (r3) { toast('已清理 · ' + (r3.detail || '')); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    // 分析页
    case 'dpi-refresh': loadDpi(true); toast('已刷新'); break;
    case 'disc-open': case 'disc-back': case 'disc-manage': case 'disc-scan': case 'disc-probe': case 'disc-ignore': case 'disc-confirm': discAct(act); break;
    case 'dpi-rebind': busyWhile(a, api.action('dpi_rebind')).then(function () { toast('已请求 dpid 重新绑定'); setTimeout(function () { loadDpi(true); }, 2500); setTimeout(function () { loadDpi(true); }, 6000); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'rules-export': case 'rules-import': case 'rules-reset': case 'rules-update': rulesAct(act); break;
    // 设置页
    case 'log-refresh': S.logFile = $('#log-file').value; loadLog(); break;
    case 'log-copy': copyText(S.logText || '').then(function (ok) { toast(ok ? '日志已复制' : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'hs-save': busyWhile(a, hsSave()); break;
    case 'hs-start': busyWhile(a, hsStart()); break;
    case 'hs-stop': confirmSheet('关闭热点？', '已连接的设备会立即断开。', '关闭').then(function (ok) { if (ok) api.action('hotspot_stop').then(function () { toast('已发出关热点命令'); setTimeout(globalRefresh, 2500); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'iface-save': var ifv = $('#iface-pref').value.trim(); if (ifv && ifv !== 'auto' && !/^[A-Za-z0-9_.-]{1,15}$/.test(ifv)) { toast('接口名不合法', 'err'); break; }
      busyWhile(a, api.action('hotspot_iface_set', { iface: ifv === 'auto' ? '' : ifv })).then(function () { toast('热点接口偏好：' + (ifv || 'auto')); return loadConfig(); }).then(function () { renderSettings(false); globalRefresh(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'ud-save': busyWhile(a, api.action('alert_config_set', udParams(true))).then(function () { toast('新设备提醒已保存'); return reloadAlertCfg(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'aq-save': busyWhile(a, api.action('alert_config_set', { section: 'monthly_quota', enabled: 'true', limit_gb: String(num($('#aq-gb').value, 10)), warn_pct: String(clamp(Math.round(num($('#aq-pct').value, 80)), 1, 99)) })).then(function () { toast('月度配额已保存'); return api.getSafe('/api/alert_config', null, S.alertCfg); }).then(function (r3) { S.alertCfg = r3; renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'ar-save':
      var dMin = num($('#ar-dmin').value, 24), dMax = num($('#ar-dmax').value, 320), uMin = num($('#ar-umin').value, 8), uMax = num($('#ar-umax').value, 80), rDel = num($('#ar-delta').value, 25);
      if (dMax < dMin || uMax < uMin) { toast('峰值带宽不能低于保底带宽', 'err'); break; }
      busyWhile(a, api.action('autorate_set', { autorate_enabled: 'true', down_min_mbps: String(dMin), down_max_mbps: String(dMax), up_min_mbps: String(uMin), up_max_mbps: String(uMax), rtt_delta_ms: String(rDel) })).then(function () { toast('5G 自适应总带宽参数已保存并启用'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'pu-sim-edit':
      var targetSlot = Math.round(num(a.getAttribute('data-slot'), 0));
      S.puEditSlot = (S.puEditSlot === targetSlot) ? 0 : targetSlot;
      paintPU(); break;
    case 'pu-inline-save':
      var sSlot = Math.round(num(a.getAttribute('data-slot'), 1));
      var pIn = $('#pu-in-plan-' + sSlot), bdIn = $('#pu-in-bd-' + sSlot), ancIn = $('#pu-in-anc-' + sSlot);
      var pVal = pIn && pIn.value.trim() !== '' ? num(pIn.value, 0) : 0;
      var bdVal = clamp(Math.round(num(bdIn && bdIn.value, (S.puCfg && S.puCfg.billing_day) || 1)), 1, 28);
      var ancStr = ancIn ? ancIn.value.trim() : '';
      if (pVal < 0) { toast('套餐容量不能为负数', 'err'); break; }
      var puParams = { billing_day: String(bdVal) };
      puParams[sSlot === 1 ? 'plan_sim1_gb' : 'plan_sim2_gb'] = trim0(pVal.toFixed(2));
      puParams[sSlot === 1 ? 'anchor_sim1_gb' : 'anchor_sim2_gb'] = ancStr === '' ? '-1' : trim0(Math.max(0, num(ancStr)).toFixed(2));
      busyWhile(a, api.action('phone_usage_set', puParams)).then(function () {
        S.puEditSlot = 0; S.pu = {};
        var st0 = $('#pu-set'); if (st0) st0._filled = false;
        toast('已保存卡' + sSlot + (pVal > 0 ? ' 套餐 ' + pVal + ' GB' : '（不设套餐上限）'));
        return refreshPU(true);
      }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'go-rules-hub':
      S.appsSub = 'rules'; closeSheet(); go('apps'); renderApps(false); break;
    case 'go-dpi-studio':
      S.aseg = 'dpi'; closeSheet(); go('stats'); renderStats(false); break;
    case 'rmac-save':
      var rAuto = $('#rmac-auto') && $('#rmac-auto').getAttribute('aria-checked') === 'true';
      busyWhile(a, api.action('rmac_policy_set', {
        auto_inherit: String(rAuto),
        auto_inherit_score: String(clamp(Math.round(num($('#rmac-score').value, 85)), 65, 100)),
        ephemeral_gc_minutes: String(clamp(Math.round(num($('#rmac-gc').value, 30)), 5, 1440))
      })).then(function () { toast('随机 MAC 无感继承策略已保存'); return Promise.all([loadConfig(), loadDevices().catch(function () {})]); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'aa-save': busyWhile(a, api.action('alert_config_set', { section: 'anomaly_traffic', enabled: 'true', ratio: String(num($('#aa-ratio').value, 3)), min_mb: String(Math.round(num($('#aa-mb').value, 50))) })).then(function () { toast('异常检测已保存'); return api.getSafe('/api/alert_config', null, S.alertCfg); }).then(function (r3) { S.alertCfg = r3; renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'gs-apply': gsApply(a); break;
    case 'sched-save':
      var sT = $('[data-local="sched-time"]').getAttribute('aria-checked') === 'true', sC = $('[data-local="sched-charge"]').getAttribute('aria-checked') === 'true';
      var st = $('#hs-t-start').value, en = $('#hs-t-end').value;
      if (sT && !(/^\d\d:\d\d$/.test(st) && /^\d\d:\d\d$/.test(en))) { toast('请填好开始和结束时间', 'err'); break; }
      var sp = { time_enable: String(sT), charging_only: String(sC) }; if (/^\d\d:\d\d$/.test(st)) sp.start = st; if (/^\d\d:\d\d$/.test(en)) sp.end = en;
      busyWhile(a, api.action('hotspot_schedule_set', sp)).then(function () { toast(sT || sC ? '已保存 · 下一次检查（约 1 分钟内）开始生效' : '已关闭定时与充电规则'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'ttl-save':
      var td = Math.round(num($('#ttl-days').value, -1)); if (td < 0 || td > 3650) { toast('请填 0~3650 天', 'err'); break; }
      busyWhile(a, api.action('stale_ttl_set', { days: String(td) })).then(function () { toast(td ? '离线 ' + td + ' 天后自动清理规则' : '已关闭离线规则自动清理'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'fw-add': var pkg = $('#fw-pkg').value.trim(); if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(pkg)) { toast('包名格式不对', 'err'); break; }
      busyWhile(a, api.action('flywheel_exclude_set', { op: 'add', pkg: pkg })).then(function () { toast('已排除 ' + pkg + ' · 约 5 分钟内生效'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'webacc-save': (function () {
      var mode = S.webaccMode || ((S.cfg.webui_access || {}).mode) || 'all', mi = $('#webacc-macs');
      busyWhile(a, api.action('webui_access_set', { mode: mode, macs: mi ? mi.value.replace(/[\s，]+/g, ',').replace(/,+/g, ',').replace(/^,|,$/g, '') : '' })).then(function () {
        S.webaccMode = null; toast('WebUI 访问控制：' + ({ all: '全部', allowlist: '白名单', local_only: '仅本机' }[mode] || mode)); return loadConfig();
      }).then(function () { if (S.page === 'settings') renderSettings(false); }).catch(function (e) {
        toast(e && e.status === 409 ? '这样设置会把当前设备锁在外面：请把它加进白名单，或在本机 WebUI 里修改' : errText(e), 'err');
      });
    })(); break;
    case 'url-copy': copyText(remoteUrl()).then(function (ok) { toast(ok ? '已复制访问地址' : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'url-share': if (navigator.share) navigator.share({ title: 'HNC', url: remoteUrl() }).catch(function () {}); else copyText(remoteUrl()).then(function () { toast('已复制访问地址'); }); break;
    case 'pair-new': busyWhile(a, pairNew()); break;
    case 'svc-restart': confirmSheet('重启 HNC 服务？', '重跑 post-fs-data.sh + service.sh，期间规则会短暂重建。', '重启').then(function (ok) { if (ok) api.action('restart_service', {}, { timeout: 20000, maxTime: 18 }).then(function () { toast('正在重启…'); setTimeout(function () { location.reload(); }, 2500); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'cache-clear': busyWhile(a, api.action('cache_clear')).then(function (r3) { toast('缓存已清理' + (r3.detail ? ' · ' + r3.detail : '')); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'eval-enable': busyWhile(a, api.post('/api/self/toggle', { enabled: true }).then(function (r3) { if (r3 && r3.error) throw new Error(r3.error); return r3; })).then(function () { toast('本机流量归因已开启 · 5 秒后开始采集样本'); return loadEval(S.evalDays, true); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'eval-refresh': busyWhile(a, loadEval(S.evalDays, true)); break;
    case 'go-self-studio': S.aseg = 'dpi'; go('stats'); renderStats(false); break;
    case 'studio-recipe': S.studioRecipeOpen = !S.studioRecipeOpen; if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); else if (S.page === 'apps') renderApps(false); break;
    case 'studio-start': busyWhile(a, api.action('self_studio_start', { mode: 'full', auto_stop_min: '15' }, { timeout: 20000, maxTime: 18 })).then(function () { toast('已开启双路本机真值采集 · 15 分钟后自动停表并蒸馏'); return loadApps(); }).then(function () { if (S.page === 'apps') renderApps(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'studio-stop': busyWhile(a, api.action('self_studio_start', { mode: 'stop' }, { timeout: 25000, maxTime: 22 }).then(function () { return api.action('self_studio_distill', {}, { timeout: 25000, maxTime: 22 }); })).then(function (r3) { var d0 = detailJSON(r3) || {}; var fpN = num(d0.exclusive_fps, d0.usable_fp); toast('已停止采集并完成蒸馏' + (fpN ? ' · 专属指纹 ' + fpN + ' 个' : '')); return loadApps(); }).then(function () { if (S.page === 'apps') renderApps(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'studio-distill':
    case 'dpi-distill-now': busyWhile(a, api.action('self_studio_distill', {}, { timeout: 25000, maxTime: 22 })).then(function (r3) { var dj = detailJSON(r3); var d0 = (dj && dj.distill) || dj || {}; toast('本机真值蒸馏完成 · 专属指纹 ' + num(d0.exclusive_fps, d0.usable_fp) + ' 个 · 启动指纹 ' + num(d0.startup_usable, d0.usable_startup) + ' 个'); return Promise.all([loadApps(), S.page === 'settings' ? Promise.all([loadFP(), loadEval(S.evalDays, true), loadRulepack()]) : null]); }).then(function () { if (S.page === 'apps') renderApps(false); if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'studio-export': busyWhile(a, api.action('self_studio_export', { note: '本机真值自训练规则包' }, { timeout: 25000, maxTime: 22 })).then(function (r3) { var dj = detailJSON(r3), nm = String(dj.name || ''); if (nm && /^[A-Za-z0-9._-]+$/.test(nm)) { if (KSU) return shell('mkdir -p /sdcard/Download && cp ' + sq(HNC_DIR + '/exports/' + nm) + ' /sdcard/Download/ && echo ok').then(function () { toast('已蒸馏并存到 /sdcard/Download/' + nm); }); downloadExport(nm, '/api/exports/' + encodeURIComponent(nm)); toast('已蒸馏并导出 ' + nm); } else toast('规则包已生成'); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'startup-list': busyWhile(a, toggleStartupList()); break;
    case 'rpack-export': rulepackExport(a); break;
    case 'rpack-import': rulepackImport(a); break;
    case 'rpack-clear': confirmSheet('清除已导入的规则包？', '删除从别人那里导入的全部域名规则、指纹和启动指纹。这台手机自己学到的和你自己加的不受影响。', '清除').then(function (ok) { if (ok) busyWhile(a, api.action('dpi_rulepack_clear')).then(function () { toast('已清除导入的规则'); S.rpackRep = null; return loadRulepack(); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'eval-clear': confirmSheet('清除识别自评的样本？', '会删掉本机采集的标签样本、前台记录和自评结果，之后重新开始积累。不影响识别和限速。', '清除').then(function (ok) { if (ok) busyWhile(a, api.action('dpi_eval_clear')).then(function () { toast('已清除样本'); S.eval = null; return loadEval(S.evalDays, true); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'rules-json': busyWhile(a, exportRulesJson()); break;
    case 'json-health': location.href = 'json-health.html'; break;
    case 'debug-bundle': debugBundle(a); break;
    case 'sc-open': scSheet(); break;
    case 'sc-run': scRun(); break;
    case 'sc-export': scExport(a); break;
    case 'compat-report': compatExport(a); break;
    case 'rec-start': recStart(a); break;
    case 'rec-stop': recStop(a); break;
    case 'clsact-check': busyWhile(a, clsactCheck()); break;
    case 'clsact-repair': busyWhile(a, api.action('clsact_repair', {}, { timeout: 20000, maxTime: 18 })).then(function () { toast('已尝试修复'); return clsactCheck(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'changelog': showChangelog(); break;
    case 'pwr-refresh': loadPower(true).then(function () { toast('已刷新守护进程功耗采样'); }); break;
    case 'dns-log-open':
      api.get('/api/dns/log', { limit: 60 }).then(function (r) {
        var es = Array.isArray(r.entries) ? r.entries : [];
        var rows = es.length ? es.map(function (x) {
          return '<div class="row" style="padding:7px 0;min-height:0"><span class="tx"><div class="t mono">' + esc(x.qname || x.domain || '—') + '</div><div class="s">' + esc((x.mac || x.ip || '') + (x.qtype ? ' · ' + x.qtype : '') + (x.rcode ? ' · ' + x.rcode : '')) + '</div></span>' + val(x.blocked ? '已拦截' : (x.ms != null ? x.ms + 'ms' : '放行'), x.blocked ? 'warn' : 'ok') + '</div>';
        }).join('') : '<div class="note">暂无查询记录（确认热点设备正在通过网关发起明文 DNS 查询）</div>';
        sheet('<h3>最近 DNS 查询日志</h3><div class="sub">来自 /api/dns/log（最多显示最近 60 条）</div><div class="rows">' + rows + '</div><div class="btns" style="margin-top:12px"><button class="btn sec wide press" data-close>关闭</button></div>', { tall: true });
      }).catch(function (e) { toast('读取 DNS 日志失败：' + errText(e), 'err'); });
      break;
    case 'logout': confirmSheet('退出登录？', '这台设备需要重新配对才能访问。', '退出').then(function (ok) { if (ok) api.post('/api/logout', {}).catch(function () {}).then(function () { location.href = '/pair'; }); }); break;
  }
});
document.addEventListener('change', function (e) {
  if (e.target.id === 'log-file') { S.logFile = e.target.value; loadLog(); }
});
document.addEventListener('input', function (e) {
  if (e.target.id === 'q') { S.q = e.target.value; renderDevList(false); }
  else if (e.target.id === 'glass-tint') glassTintInput(e.target, false);
});
// 玻璃浓度滑块: 拖动时整页实时跟着变(不存); 松手才存。标准档(50)附近 ±3 吸附, 好拖回原样
var gxShown = null;
function glassTintInput(el, commit) {
  var v = clamp(Math.round(num(el.value, 50)), 0, 100);
  if (Math.abs(v - 50) <= 3) { v = 50; if (commit) el.value = '50'; }
  if (v === 50 && gxShown !== null && gxShown !== 50) haptic(6);   // 拖进标准档时轻震一下
  gxShown = v;
  applyGlassTint(v);
  var lb = $('#glass-tint-v'); if (lb) lb.textContent = glassTintLabel(v);
  if (commit && v !== S.glassTint) { S.glassTint = v; LS.set('hnc6.glass_tint', String(v)); }
}
document.addEventListener('change', function (e) { if (e.target.id === 'glass-tint') glassTintInput(e.target, true); });
document.addEventListener('keydown', function (e) {
  var el = e.target; if (e.key !== 'Enter' || !el.closest) return;
  var box = el.closest('[data-dev],[data-side]'); if (!box || el.tagName !== 'INPUT') return;
  var f = el.getAttribute('data-f'), ba = { down: 'apply-limit', up: 'apply-limit', delay: 'apply-delay', jitter: 'apply-delay', loss: 'apply-delay', 'q-daily': 'quota-save', 'q-month': 'quota-save', 'q-thr': 'quota-save' }[f];
  var btn = ba && $('[data-act="' + ba + '"]', box); if (btn) { e.preventDefault(); btn.click(); }
});
/* 柱子点选气泡 */
document.addEventListener('pointerdown', function (e) {
  var bars = $('#bars'); if (!bars) return;
  var col = e.target.closest('.bcol'), old = $('.btip', bars);
  if (old) old.remove(); bars.classList.remove('picking'); $$('.bcol.pk', bars).forEach(function (c) { c.classList.remove('pk'); });
  // 柱子只有几像素宽, 手指很难点中 —— 点在图表区域内任意位置都选离得最近的柱子
  if (!col && bars.contains(e.target)) {
    var best = null, bd = 1e9;
    $$('.bcol', bars).forEach(function (c) { var r = c.getBoundingClientRect(), dx = Math.abs(r.left + r.width / 2 - e.clientX); if (dx < bd) { bd = dx; best = c; } });
    if (best && bd < 40) col = best;
  }
  if (col && bars.contains(col)) barTip(col);
});
/* 长按封锁(0.8 秒) */
// 手指移动超过 10px(或页面开始滚动 → pointercancel)就取消。此前按住后滑走照样封锁;
//        且旧版在 document 上捕获所有 pointerleave, 鼠标划过任意子元素都会误取消。
// 触感反馈 —— 开关 / 分段 / 确认 / 长按开始
document.addEventListener('click', function (e) {
  var t = e.target; if (!t.closest) return;
  if (t.closest('.toggle')) haptic(10); else if (t.closest('#cf-ok')) haptic(15); else if (t.closest('.seg button, [data-style-pick], [data-theme-pick]')) haptic(6);
}, true);
document.addEventListener('pointerdown', function (e) { if (e.target.closest && e.target.closest('[data-act="hold"]')) haptic(8); }, true);
// 手指在设备列表里 → 这几秒内列表不重排(否则轮询刚好重排时, 点下去的位置已经换成另一台设备)
document.addEventListener('pointerdown', function (e) { if (e.target.closest && e.target.closest('#dev-list, #dev-side')) freezeList(2500); }, true);
var holdT = 0, holdP = null, swallowClick = false;
// 长按生效后, 这次手势结束时产生的 click 一律吞掉; 下一次按下即复位(不按时间算, 按多久都可靠)
document.addEventListener('click', function (e) { if (swallowClick) { swallowClick = false; e.stopPropagation(); e.preventDefault(); } }, true);
document.addEventListener('pointerdown', function () { swallowClick = false; }, true);
function holdCancel() { clearTimeout(holdT); holdT = 0; holdP = null; $$('.hold.run').forEach(function (b) { b.classList.remove('run'); }); }
document.addEventListener('pointerdown', function (e) {
  var hb = e.target.closest('[data-act="hold"]'); if (!hb || hb.disabled) return;
  var d = ctxDev(hb).d; if (!d) return;
  holdCancel(); hb.classList.add('run'); holdP = { id: e.pointerId, x: e.clientX, y: e.clientY };
  holdT = setTimeout(function () {
    holdT = 0; holdP = null; hb.classList.remove('run');
    // 长按触发后吞掉松手时的那次 click —— 封锁后卡片就地重绘, 同一位置变成「解除封锁」,
    // 手指多按一会儿再松开会点中它 → 刚封锁就被解封(网关确认弹窗时则会点到遮罩关掉弹窗)
    swallowClick = true;
    if (typeof canVib === 'function' && canVib()) try { navigator.vibrate(15); } catch (_) {}
    blockDevice(d);
  }, 800);
});
document.addEventListener('pointermove', function (e) {
  if (holdP && e.pointerId === holdP.id && Math.hypot(e.clientX - holdP.x, e.clientY - holdP.y) > 10) holdCancel();
}, true);
['pointerup', 'pointercancel'].forEach(function (ev) { document.addEventListener(ev, function (e) { if (holdP && e.pointerId === holdP.id) holdCancel(); }, true); });
document.addEventListener('scroll', function () { if (holdP) holdCancel(); }, true);

/* ═════════════════════ 轮询 ═════════════════════
 * 主循环 setTimeout 链; 页面不可见时停, 回前台立刻补一次。
 * 间隔与旧版一致: 有在线设备 1s / 空闲 1.5~5s / 热点关 3~15s; 设备签名变化后 5 秒内 250ms 快轮询。 */
var pollT = 0, pollBusy = false, burstUntil = 0, tickN = 0;
/* 远程浏览器用 /api/events 实时推送(设备接入/离开/规则变化), 空闲时轮询放缓到 15~30 秒 */
var es = null;
function startSSE() {
  if (KSU || typeof EventSource === 'undefined' || es || document.hidden) return;
  try {
    es = new EventSource('/api/events');
    es.onopen = function () { S.sse = true; };
    es.addEventListener('changed', function () { burstUntil = Date.now() + 3000; schedulePoll(0); });
    es.onerror = function () { S.sse = false; };   // 浏览器会自动重连
  } catch (_) { es = null; }
}
function stopSSE() { if (es) { try { es.close(); } catch (_) {} es = null; S.sse = false; } }
function pollDelay() {
  if (Date.now() < burstUntil) return 250;
  var l = S.live || {}, m = S.refreshMode, on = num(l.online);
  if (!S.connected) return 4000;
  if (S.sse && (S.page !== 'devices' || l.hotspot_active === false || !on)) return m === 'powersave' ? 30000 : 15000;
  if (S.page !== 'devices') return m === 'powersave' ? 15000 : 5000;
  if (l.hotspot_active === false) return m === 'powersave' ? 15000 : 3000;
  if (!on) return { realtime: 1500, balanced: 2000, powersave: 5000 }[m];
  return m === 'powersave' ? 3000 : 1000;
}
function schedulePoll(ms) { clearTimeout(pollT); if (document.hidden) return; pollT = setTimeout(pollOnce, ms == null ? pollDelay() : ms); }
function pollOnce() {
  if (pollBusy || document.hidden) { schedulePoll(); return; }
  // 初次启动失败或断线后必须重走完整初始化, 不能只恢复 live/devices。
  if (!S.booted || !S.connected) { boot(false); return; }
  pollBusy = true; tickN++;
  var prevSig = S.sig, prevShape = shapeOf(), wasOk = S.connected;
  // 设备页有在线设备时每轮都要刷新单台速率 → 直接用合并请求; 否则只拿汇总, 签名变了再补拉列表
  var wantDev = !S.devLoaded || (S.page === 'devices' && num((S.live || {}).online) > 0 && (S.refreshMode === 'realtime' || tickN % 2 === 0));
  var syncedDevs = false;
  var syncOrLive = (S.vectorSyncState === 'supported' && typeof loadVectorSync === 'function')
    ? loadVectorSync(null).then(function (sr) { syncedDevs = !!(sr.got && sr.got.devices); return sr.live; }, function (err) {
        if (err && err.isVectorSyncUnsupported) return wantDev ? loadLiveAndDevices().then(function (l0) { syncedDevs = true; return l0; }) : loadLive();
        throw err;
      })
    : (wantDev ? loadLiveAndDevices().then(function (l0) { syncedDevs = true; return l0; }) : loadLive());
  syncOrLive.then(function (l) {
    var sigChanged = l.devices_sig && l.devices_sig !== prevSig;
    if (sigChanged) burstUntil = Date.now() + 5000;
    var needDev = wantDev || sigChanged;
    var mustFetchFullDevs = !S.devLoaded || sigChanged || (needDev && !syncedDevs);
    return (mustFetchFullDevs ? loadDevices() : Promise.resolve()).then(function () {
      if (l.devices_sig) S.sig = l.devices_sig;
      if (!wasOk) { S.bootErr = ''; if (S.page === 'devices') renderDevices(false); }
      if (S.page === 'devices') {
        paintHero(false); drawSpark(); paintFresh();
        if (needDev) { if (shapeOf() !== prevShape) renderDevList(false); else patchRates(); }
      }
      if (S.page === 'settings') { var fr = $('#fresh-row .v'); if (fr) { fr.textContent = '刚刚'; fr.className = 'v ok'; } }
    });
  }).catch(function (e) {
    if (Date.now() - S.lastOk > 8000) { if (S.connected) { S.connected = false; S.bootErr = errText(e); if (S.page === 'devices') renderDevices(false); } }
    paintFresh();
  }).then(function () {
    pollBusy = false;
    if (typeof v6OnPollTick === 'function') v6OnPollTick(tickN);
    if (S.page === 'stats' && S.aseg === 'dpi' && tickN % 3 === 0) loadDpi(tickN % 12 === 0);
    // 设备页 —— 每 5 轮刷新各设备连接数; 展开着的在线设备卡每 3 轮刷新连接摘要(弹层开着时由弹层自己 2s 刷)
    if (S.page === 'devices' && num((S.live || {}).online) > 0) {
      if (tickN % 5 === 1) loadConnCounts();
      if (tickN % 3 === 0 && !S.connMac) S.devices.forEach(function (x) { if (x.online && (wide() ? S.sel === x.mac : S.open[x.mac])) refreshConnMini(x.mac); });
    }
    if (S.page === 'apps' && tickN % 5 === 0) loadApps().then(function () {
      if (S.page !== 'apps' || document.querySelector('#p-apps :focus')) return;
      var sc = $('#p-stats .studio-card') || $('#p-apps .studio-card');
      if (sc && typeof selfStudioCardHtml === 'function') { sc = morphOuter(sc, selfStudioCardHtml()); placeSegs(sc); }
      if (!document.querySelector('#p-apps .row-wrap.open')) {
        var b = $('#apps-sub'); if (b && S.appsSub !== 'export' && S.appsSub !== 'set') { b.innerHTML = appsSub(); placeSegs(b); }
      }
    });
    schedulePoll();
  });
}
setInterval(function () { if (S.page === 'devices') paintFresh(); }, 1000);
var slowT = [];
function startSlowPolls() {
  slowT.forEach(clearInterval);
  slowT = [setInterval(function () { if (!document.hidden) loadAlerts(); }, 60000),
    setInterval(function () { if (!document.hidden) loadOffload(); }, 60000),
    setInterval(function () { if (!document.hidden && S.page !== 'apps' && S.page !== 'stats') api.getSafe('/api/dpi_state', null, null).then(function (r) { if (r && r.available && r.state) { S.self = r.state.self || null; paintAppsDot(); } }); }, 25000),
    setInterval(function () { if (!document.hidden && S.page === 'devices') { loadOnlineHours(); loadUsage(); } }, 600000),
    setInterval(function () { if (!document.hidden && S.page === 'stats' && S.aseg === 'stats') { refreshStats(); refreshPU(true); } }, 300000)];
}
document.addEventListener('visibilitychange', function () { if (typeof v6OnVisibility === 'function') v6OnVisibility(document.hidden); if (document.hidden) { clearTimeout(pollT); stopSSE(); } else { burstUntil = Date.now() + 2000; schedulePoll(0); loadAlerts(); startSSE(); } });

/* ═════════════════════ 启动 ═════════════════════
 * 旧版 bug: health 失败后重试成功只恢复了设备轮询, 配置/能力/告警/offload 全停在默认值。
 * 这里 boot() 每次都走完整初始化。 */
var booting = null;
function boot(retry) {
  if (booting) return booting;
  S.booted = false;
  if (retry) { S.bootErr = ''; S.connected = false; if (S.page === 'devices') renderDevices(false); if (KSU) loadSecret(true); }
  var legacyBootChain = function () {
    return api.get('/api/health', null, { timeout: 6000 }).then(function (h) {
      // v5.29 T3: 升级回滚横幅(数据来自 /api/health 的 rollback 段)
      try { showRollbackBanner(h && h.rollback); } catch (e) {}
      return Promise.all([loadLive(), loadConfig().catch(function () {}), loadCaps(), loadTemplates(), loadAppLimits()]);
    }).then(function () {
      return loadDevices();
    });
  };
  var fastBootChain = function () {
    if (S.vectorSyncState === 'unsupported' || typeof loadVectorSync !== 'function') return legacyBootChain();
    return loadVectorSync({ boot: 1, devices: 1 }).then(function (sr) {
      var g = sr.got || {};
      try { if (S.lastHealth && S.lastHealth.rollback) showRollbackBanner(S.lastHealth.rollback); } catch (_) {}
      var rest = [];
      if (!g.live) rest.push(loadLive());
      if (!g.cfg) rest.push(loadConfig().catch(function () {}));
      if (!g.caps) rest.push(loadCaps());
      if (!g.templates) rest.push(loadTemplates());
      if (!g.appLimits) rest.push(loadAppLimits());
      return Promise.all(rest).then(function () {
        return g.devices ? S.devices : loadDevices();
      });
    }, function (err) {
      if (err && err.isVectorSyncUnsupported) return legacyBootChain();
      throw err;
    });
  };
  booting = fastBootChain().then(function () {
    S.booted = true; S.bootErr = '';
    $('#mode-pill').hidden = false; $('#mode-pill').textContent = KSU ? '本机' : '远程';
    RENDER[S.page](!retry); onEnter(S.page);
    setTimeout(function () {
      ORDER.forEach(function (pName, idx) {
        if (pName !== S.page) {
          setTimeout(function () {
            var pg = $('#p-' + pName);
            if (pg && !pg.firstElementChild) RENDER[pName](false);
          }, (idx + 1) * 90);
        }
      });
    }, 220);
    loadAlerts(); loadOffload();
    loadOnlineHours(); loadUsage(); startSlowPolls(); startSSE();
    if (typeof v6BootInit === 'function') v6BootInit();
    loadEncdns().then(function (e) { if (e) S.devices.forEach(function (x) { if (S.open[x.mac] || S.sel === x.mac) refreshCard(x.mac); }); });   // 设备卡的按设备加密 DNS
    api.getSafe('/api/alert_config', null, null).then(function (r) { if (r) { S.alertCfg = r; paintUsage(); } });
    if (retry) toast('已连接 HNC 后端');
  }).catch(function (e) {
    S.connected = false; S.bootErr = errText(e);
    if (S.page === 'devices') renderDevices(false); else toast('连不上 HNC 后端：' + S.bootErr, 'err');
    schedulePoll(4000);
  }).then(function () { booting = null; });
  return booting;
}

var saved = LS.get('hnc6.page', 'devices');
if (ORDER.indexOf(saved) >= 0) S.page = saved;
$$('.page').forEach(function (p) { p.classList.toggle('on', p.getAttribute('data-page') === S.page); });
RENDER[S.page](true);
layoutLens(); syncTab(S.page, true);
// v5.36.0: #lens 作为 #tabbar 内部水滴光晕胶囊不再嵌套挂载二次 Hyalite，根治底栏白蛋与白色折射摩尔纹
if (window.Hyalite && lens) { try { Hyalite.detach(lens); } catch (_) {} }
wideMQ.addEventListener('change', function () { RENDER[S.page](false); });
addEventListener('resize', function () { layoutLens(); syncTab(S.page, true); placeSegs(document); drawSpark(); });
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () { if (S.theme === 'auto') applyTheme(); });
boot(false);
window.__hnc6 = { S: S, go: go, api: api, boot: boot, L: L };   // 调试/截图用


// ── v5.29 T3: 升级回滚横幅 ──────────────────────────────────────────
// 数据: /api/health 的 rollback 段(rollback.go 转出; from = 启动失败的新版,
// to = 退回到的上一版)。rolled 且未 ack 时显示, 带「导出诊断包」与「知道了」
// (POST /api/rollback_ack 写 data/rollback.ack, 横幅消失)。
function rollbackBannerText(rb) {
  var bad = rb.from_name || rb.from, good = rb.to_name || rb.to;
  var t = '检测到 ' + (bad && bad !== 'unknown' ? 'v' + bad : '新版本') + ' 启动失败';
  if (rb.action === 'recorded_only') t += '(自动回滚已关闭,本次只记录)';
  else if (rb.action === 'no_snapshot') t += ',但没有上一版的快照,无法自动退回';
  else t += ',已自动退回 ' + (good && good !== 'unknown' ? 'v' + good : '上一版');
  return t + ';请把诊断包发给开发者';
}
function showRollbackBanner(rb) {
  if (!rb || !rb.rolled || rb.acknowledged) return;
  var old = document.getElementById('rollback-banner');
  if (old) old.remove();
  var bar = document.createElement('div');
  bar.id = 'rollback-banner';
  bar.style.cssText = 'position:sticky;top:0;z-index:900;background:#5a3a00;color:#ffd79a;' +
    'padding:10px 14px;font-size:13px;line-height:1.6;display:flex;gap:10px;align-items:center;flex-wrap:wrap';
  var txt = document.createElement('span');
  txt.style.flex = '1';
  txt.textContent = rollbackBannerText(rb);
  var btnCss = 'padding:4px 14px;border:0;border-radius:6px;background:#ffd79a;color:#3a2a00;cursor:pointer';
  var diagBtn = document.createElement('button');
  diagBtn.textContent = '导出诊断包';
  diagBtn.setAttribute('data-act', 'debug-bundle');   // 走全局点击分发(settings.js debugBundle)
  diagBtn.style.cssText = btnCss;
  var okBtn = document.createElement('button');
  okBtn.textContent = '知道了';
  okBtn.style.cssText = btnCss;
  okBtn.onclick = function () {
    api.post('/api/rollback_ack', {}).then(function () { bar.remove(); })
      .catch(function () { toast('确认失败,请重试'); });
  };
  bar.appendChild(txt); bar.appendChild(diagBtn); bar.appendChild(okBtn);
  var body = document.body || document.documentElement;
  body.insertBefore(bar, body.firstChild);
}

/* === v5.33.1 Enhancement Layer 1: Optical Spotlight & Control Center Bento Delegation === */
/* A restrained, pointer-following reflection, with no additional animation loop. */
(function(){
 /* Pointer-following radial-gradient disabled to avoid per-frame getBoundingClientRect style recalculation */
 /* The draggable original tab bar remains draggable; these semantics also make it keyboard-operable. */
 if (S.sel) refreshConnMini(S.sel);
 var host=document.getElementById('tabs');host.setAttribute('role','tablist');

  /* ═══ iOS 27 Interactive Liquid Capsule Sliders & Control Center Bento Tiles ═══ */
  function syncLccFromInput(box, field) {
    if (!box) return;
    var inp = box.querySelector('[data-f="' + field + '"]');
    var cap = box.querySelector('[data-lcc-track="' + field + '"]');
    var lbl = box.querySelector('[data-lcc-lbl="' + field + '"]');
    if (!inp || !cap || !lbl) return;
    var v = parseFloat(inp.value) || 0;
    var pct = v > 0 ? Math.min(100, Math.max(6, Math.round(Math.sqrt(v / 20) * 100))) : 0;
    var fill = cap.querySelector('.lcc-fill');
    if (fill) fill.style.width = pct + '%';
    cap.classList.toggle('active', v > 0);
    lbl.textContent = v > 0 ? v + ' MB/s' : '不限速';
    if (field === 'down') {
      $$('[data-lcc-preset]', box).forEach(function (b) {
        b.classList.toggle('on', parseFloat(b.getAttribute('data-lcc-preset')) === v);
      });
    }
  }

  // Dragging across .lcc-capsule directly manipulates rate with non-linear precision (0 ~ 20 MB/s)
  var lccDrag = null;
  function updateLccByClientX(clientX) {
    if (!lccDrag) return;
    var r = lccDrag.cap.getBoundingClientRect();
    var ratio = Math.max(0, Math.min(1, (clientX - r.left) / Math.max(1, r.width)));
    var val = 0;
    if (ratio > 0.05) {
      var raw = Math.pow((ratio - 0.04) / 0.96, 2) * 20;
      val = raw < 2 ? Math.round(raw * 10) / 10 : raw < 6 ? Math.round(raw * 2) / 2 : Math.round(raw);
      val = Math.max(0.1, Math.min(20, val));
    }
    var inp = lccDrag.box.querySelector('[data-f="' + lccDrag.field + '"]');
    if (inp && !inp.disabled) {
      inp.value = val > 0 ? String(val) : '';
      syncLccFromInput(lccDrag.box, lccDrag.field);
    }
  }
  // 1. 零重排 rAF 驱动光学流转高光 (--spot-x / --spot-y) 与 Liquid 微倾张力 / Cyber 战术定位脉冲
  var spotCtx = null;
  function writeSpotFrame() {
    if (!spotCtx) return;
    spotCtx.raf = 0;
    var r = spotCtx.rect, g = spotCtx.el;
    var nx = clamp((spotCtx.cx - r.left) / Math.max(1, r.width), 0, 1);
    var ny = clamp((spotCtx.cy - r.top) / Math.max(1, r.height), 0, 1);
    g.style.setProperty('--spot-x', (nx * 100).toFixed(1) + '%');
    g.style.setProperty('--spot-y', (ny * 100).toFixed(1) + '%');
    if (spotCtx.tilt) {
      var ry = ((nx - 0.5) * 2.4).toFixed(2) + 'deg';
      var rx = ((0.5 - ny) * 1.9).toFixed(2) + 'deg';
      g.style.setProperty('--tilt-rx', rx);
      g.style.setProperty('--tilt-ry', ry);
    }
  }
  function clearSpotCtx() {
    if (!spotCtx) return;
    if (spotCtx.raf) cancelAnimationFrame(spotCtx.raf);
    var g = spotCtx.el;
    g.classList.remove('is-spotting', 'is-gliding', 'is-tilting');
    g.style.removeProperty('--tilt-rx');
    g.style.removeProperty('--tilt-ry');
    spotCtx = null;
  }

  document.addEventListener('pointerdown', function (e) {
    var mode = typeof motionTheme === 'function' ? motionTheme() : 'default';
    if ((mode === 'liquid' || mode === 'cyber') && motionOn() && !(typeof lowFx === 'function' && lowFx())) {
      var g = e.target.closest && e.target.closest('.glass:not(.seg):not(.search)');
      if (g && !g.closest('#sheet')) {
        clearSpotCtx();
        var gr = g.getBoundingClientRect();
        if (mode === 'liquid') {
          var canTilt = fxOn('press') && !g.classList.contains('open') && gr.height < 260 && !e.target.closest('input,textarea,select,.toggle,.seg,[data-lcc-track]');
          g.classList.add('is-spotting');
          if (canTilt) g.classList.add('is-tilting');
          spotCtx = { el: g, rect: gr, pid: e.pointerId, cx: e.clientX, cy: e.clientY, x0: e.clientX, y0: e.clientY, tilt: canTilt, raf: 0 };
          writeSpotFrame();
        } else {
          var px = clamp((e.clientX - gr.left) / Math.max(1, gr.width) * 100, 0, 100).toFixed(1) + '%';
          var py = clamp((e.clientY - gr.top) / Math.max(1, gr.height) * 100, 0, 100).toFixed(1) + '%';
          g.style.setProperty('--spot-x', px);
          g.style.setProperty('--spot-y', py);
          g.classList.remove('cy-card-ping');
          void g.offsetWidth;
          g.classList.add('cy-card-ping');
          clearTimeout(g._cyPingT);
          g._cyPingT = setTimeout(function () { g.classList.remove('cy-card-ping'); }, 170);
        }
      }
    }
    // 2. Liquid Capsule Slider drag start
    var cap = e.target.closest && e.target.closest('[data-lcc-track]');
    if (!cap || cap.classList.contains('is-dis')) return;
    var box = cap.closest('[data-dev]') || cap.closest('[data-side]');
    var field = cap.getAttribute('data-lcc-track');
    var inp = box && box.querySelector('[data-f="' + field + '"]');
    if (!box || !inp || inp.disabled) return;
    try { cap.setPointerCapture(e.pointerId); } catch (_) {}
    cap.classList.add('dragging');
    lccDrag = { cap: cap, box: box, field: field, id: e.pointerId };
    updateLccByClientX(e.clientX);
  }, { passive: true });

  document.addEventListener('pointermove', function (e) {
    if (spotCtx && e.pointerId === spotCtx.pid) {
      spotCtx.cx = e.clientX;
      spotCtx.cy = e.clientY;
      if (!spotCtx.el.classList.contains('is-gliding') && Math.hypot(e.clientX - spotCtx.x0, e.clientY - spotCtx.y0) > 6) {
        spotCtx.el.classList.add('is-gliding');
      }
      if (!spotCtx.raf) spotCtx.raf = requestAnimationFrame(writeSpotFrame);
    }
    if (!lccDrag) return;
    updateLccByClientX(e.clientX);
  }, { passive: true });

  function endLccDrag() {
    clearSpotCtx();
    if (!lccDrag) return;
    lccDrag.cap.classList.remove('dragging');
    if (typeof haptic === 'function') haptic(8);
    lccDrag = null;
  }
  document.addEventListener('pointerup', endLccDrag);
  document.addEventListener('pointercancel', endLccDrag);
  document.addEventListener('scroll', clearSpotCtx, true);

  // Sync manual input typing back to liquid capsule bars
  document.addEventListener('input', function (e) {
    var f = e.target && e.target.getAttribute && e.target.getAttribute('data-f');
    if (f === 'down' || f === 'up') {
      var box = e.target.closest('[data-dev]') || e.target.closest('[data-side]');
      syncLccFromInput(box, f);
    }
  });

  // Wire preset pills & Control Center 3-tile Bento toggles
  document.addEventListener('click', function (e) {
    var pre = e.target.closest && e.target.closest('[data-lcc-preset]');
    if (pre) {
      var box = pre.closest('[data-dev]') || pre.closest('[data-side]');
      if (!box) return;
      var v = parseFloat(pre.getAttribute('data-lcc-preset')) || 0;
      var dnInp = box.querySelector('[data-f="down"]');
      var upInp = box.querySelector('[data-f="up"]');
      if (dnInp && !dnInp.disabled) { dnInp.value = v > 0 ? String(v) : ''; syncLccFromInput(box, 'down'); }
      if (upInp && !upInp.disabled) { upInp.value = v > 0 ? String(Math.max(0.2, +(v * 0.5).toFixed(1))) : ''; syncLccFromInput(box, 'up'); }
      if (typeof haptic === 'function') haptic(8);
      return;
    }
    var cc = e.target.closest && e.target.closest('[data-cc-tog]');
    if (cc && !cc.disabled) {
      var box2 = cc.closest('[data-dev]') || cc.closest('[data-side]');
      var mac2 = box2 && (box2.getAttribute('data-dev') || box2.getAttribute('data-side'));
      if (mac2 && S.busy[mac2]) { toast('这台设备还有操作在进行'); return; }
      var kind = cc.getAttribute('data-cc-tog');
      var realTog = box2 && box2.querySelector('.toggle[data-act="' + kind + '"]');
      if (realTog && !realTog.disabled) {
        realTog.click();
        var isNowOn = realTog.getAttribute('aria-checked') === 'true';
        cc.classList.toggle('on', isNowOn);
        if (kind === 'sqm') cc.classList.toggle('sqm-on', isNowOn);
        else if (kind === 'appqos') cc.classList.toggle('qos-on', isNowOn);
        else if (kind === 'wl') cc.classList.toggle('wl-on', isNowOn);
      }
    }
  });
 function tabState(){host.querySelectorAll('[data-tab]').forEach(function(el){var name=el.getAttribute('data-tab'),on=name===S.page;el.setAttribute('role','tab');el.setAttribute('aria-label',NAV_T[name]);el.setAttribute('aria-selected',String(on));el.setAttribute('aria-controls','p-'+name);el.tabIndex=on?0:-1;});}
 var originalSync=syncTab;syncTab=function(name,instant){originalSync(name,instant);tabState();};tabState();
 host.addEventListener('keydown',function(e){var el=e.target.closest('[data-tab]');if(!el)return;var n=ORDER.indexOf(el.getAttribute('data-tab'));if(e.key==='ArrowRight')n=(n+1)%4;else if(e.key==='ArrowLeft')n=(n+3)%4;else if(e.key==='Home')n=0;else if(e.key==='End')n=3;else if(e.key!=='Enter'&&e.key!==' ')return;e.preventDefault();go(ORDER[n]);host.querySelector('[data-tab="'+ORDER[n]+'"]').focus();});
})();

/* === v5.33.1 Enhancement Layer 2: Dual RX/TX Bezier Sparkline, Filter Pills & Live Settings Search === */
(function(){
  'use strict';
  if (typeof S === 'undefined') return;

  /* ── 新增状态字段：上行历史曲线、快捷胶囊筛选、液态阀门松手即生效、设置页搜索 ── */
  S.sparkTx = S.sparkTx || [];
  S.qpill = S.qpill || 'all';
  S.lccAutoApply = S.lccAutoApply !== false;
  S.setQ = S.setQ || '';

  // 初始化预置上行速率历史，与 S.spark (下行) 同步长度
  if (!S.sparkTx.length && Array.isArray(S.spark)) {
    S.sparkTx = S.spark.map(function(v, i){
      return Math.max(12000, Math.round(v * (0.09 + 0.03 * Math.sin(i / 2.2))));
    });
  }

  // 钩住 applyLive：每次轮询同时记录上行速率 tx_bps
  var _origApplyLive = window.applyLive;
  if (typeof _origApplyLive === 'function') {
    window.applyLive = function(l) {
      _origApplyLive(l);
      S.sparkTx.push(num(l && l.tx_bps));
      if (S.sparkTx.length > 30) S.sparkTx.shift();
    };
  }

  /* ── 1. 重构顶部座舱曲线：支持 RX(下行) + TX(上行) 双通道三次贝塞尔流光曲线 ── */
  window.drawSpark = function() {
    var el = $('#spark');
    if (!el) return;
    var rx = S.spark.length > 1 ? S.spark : [0, 0];
    var tx = S.sparkTx.length === rx.length ? S.sparkTx : rx.map(function(v, i){
      return S.sparkTx[i] != null ? S.sparkTx[i] : v * 0.1;
    });
    var W = Math.round(el.clientWidth) || 320, H = 52;
    var peakRx = Math.max.apply(null, rx), peakTx = Math.max.apply(null, tx);
    var mx = Math.max(peakRx, peakTx) * 1.16 || 1;
    var st = W / Math.max(1, rx.length - 1);

    function bezierPath(arr) {
      var pts = arr.map(function(v, i){ return [i * st, H - 4 - (v / mx) * (H - 10)]; });
      var d = 'M' + pts[0][0].toFixed(1) + ' ' + pts[0][1].toFixed(1);
      for (var i = 1; i < pts.length; i++) {
        var cx = (pts[i - 1][0] + pts[i][0]) / 2;
        d += ' C' + cx.toFixed(1) + ' ' + pts[i - 1][1].toFixed(1) + ',' +
                    cx.toFixed(1) + ' ' + pts[i][1].toFixed(1) + ',' +
                    pts[i][0].toFixed(1) + ' ' + pts[i][1].toFixed(1);
      }
      return { d: d, last: pts[pts.length - 1] };
    }

    var pr = bezierPath(rx), pt = bezierPath(tx);
    el.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    el.innerHTML =
      '<defs>' +
        '<linearGradient id="sgRx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--rx)" stop-opacity=".30"/><stop offset="1" stop-color="var(--rx)" stop-opacity="0"/></linearGradient>' +
        '<linearGradient id="sgTx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--tx)" stop-opacity=".24"/><stop offset="1" stop-color="var(--tx)" stop-opacity="0"/></linearGradient>' +
      '</defs>' +
      '<path d="' + pr.d + ' L' + W + ' ' + H + ' L0 ' + H + ' Z" fill="url(#sgRx)"/>' +
      '<path d="' + pt.d + ' L' + W + ' ' + H + ' L0 ' + H + ' Z" fill="url(#sgTx)"/>' +
      '<path d="' + pt.d + '" fill="none" stroke="var(--tx)" stroke-width="1.5" stroke-dasharray="3 2" opacity=".85"/>' +
      '<path d="' + pr.d + '" fill="none" stroke="var(--rx)" stroke-width="2.2" stroke-linejoin="round"/>' +
      '<circle cx="' + pr.last[0].toFixed(1) + '" cy="' + pr.last[1].toFixed(1) + '" r="3.5" fill="var(--rx)" stroke="var(--card-solid)" stroke-width="2"/>';

    // 注入或更新曲线上方的双通道图例与峰值 HUD
    var hud = $('#hero-spark-hud');
    var peakBps = bps(peakRx);
    var hudHtml = '<span class="leg"><span><i style="background:var(--rx)"></i>下行实时流</span><span><i style="background:var(--tx)"></i>上行实时流</span></span>' +
                  '<span class="num">近60秒峰值 <b style="color:var(--text-1)">' + peakBps.v + ' ' + peakBps.u + '</b></span>';
    if (!hud) {
      el.insertAdjacentHTML('beforebegin', '<div class="hero-spark-hud" id="hero-spark-hud">' + hudHtml + '</div>');
    } else {
      hud.innerHTML = hudHtml;
    }
  };

  /* ── 2. 增强 visibleDevs 与快捷筛选胶囊栏 (.quick-pills) ── */
  var _origVisibleDevs = window.visibleDevs;
  window.visibleDevs = function() {
    var list = _origVisibleDevs ? _origVisibleDevs() : S.devices;
    if (S.qpill === 'online') return list.filter(function(d){ return d.online; });
    if (S.qpill === 'shaped') return list.filter(function(d){ return d.limitOn || d.down > 0 || d.up > 0; });
    if (S.qpill === 'sqm')    return list.filter(function(d){ return d.sqm || d.appQos; });
    if (S.qpill === 'blocked')return list.filter(function(d){ return d.blocked; });
    if (S.qpill === 'rmac')   return list.filter(function(d){ return d.rmac; });
    return list;
  };

  function injectQuickPills() {
    var searchEl = $('#p-devices .search');
    if (!searchEl) return;
    var baseList = _origVisibleDevs ? _origVisibleDevs() : S.devices;
    var pills = [
      ['all', '全部', baseList.length],
      ['online', '在线', baseList.filter(function(d){ return d.online; }).length],
      ['shaped', '限速中', baseList.filter(function(d){ return d.limitOn || d.down > 0 || d.up > 0; }).length],
      ['sqm', '低延迟/分流', baseList.filter(function(d){ return d.sqm || d.appQos; }).length],
      ['blocked', '已封锁', baseList.filter(function(d){ return d.blocked; }).length],
      ['rmac', '随机MAC', baseList.filter(function(d){ return d.rmac; }).length]
    ];
    var html = pills.map(function(p){
      return '<button type="button" class="qpill press' + (S.qpill === p[0] ? ' on' : '') + '" data-qpill="' + p[0] + '">' +
               p[1] + '<b>' + p[2] + '</b></button>';
    }).join('');
    var bar = $('#qpill-bar');
    if (!bar) {
      searchEl.insertAdjacentHTML('afterend', '<div class="quick-pills" id="qpill-bar">' + html + '</div>');
    } else {
      bar.innerHTML = html;
    }
  }

  /* ── 3. 增强设备卡片：在线带宽负载条 + 4磁贴控制中心 + 液态阀门松手即生效 ── */
  var _origDevCard = window.devCard;
  window.devCard = function(d) {
    var html = _origDevCard(d);
    if (d.online) {
      var loadPct = Math.min(100, Math.max(6, Math.round((num(d.rx) + num(d.tx)) / (3.2 * 1048576) * 100)));
      html = html.replace('</span></button>', '<span class="dev-load-bar"><i style="width:' + loadPct + '%"></i></span></span></button>');
    }
    return html;
  };

  var _origPatchRates = window.patchRates;
  if (typeof _origPatchRates === 'function') {
    window.patchRates = function() {
      _origPatchRates();
      S.devices.forEach(function(d) {
        if (!d.online) return;
        var bar = document.querySelector('.dev[data-dev="' + d.mac + '"] .dev-load-bar > i');
        if (bar) {
          var loadPct = Math.min(100, Math.max(6, Math.round((num(d.rx) + num(d.tx)) / (3.2 * 1048576) * 100)));
          bar.style.width = loadPct + '%';
        }
      });
    };
  }

  var _origDevBody = window.devBody;
  window.devBody = function(d) {
    var html = _origDevBody(d);
    // 将 3 格控制中心升级为 4 格（新增第 4 格：实时连接流直达磁贴）
    var nConn = d.online && S.connCounts && S.connCounts[d.mac] && S.connCounts[d.mac].n;
    var connCount = nConn ? (nConn + ' 条') : (d.online ? '实时' : '离线');
    var tile4 = '<button type="button" class="cc-tile conn-tile press' + (d.online ? ' on conn-on' : '') + '" data-act="conns"' + (d.online ? '' : ' disabled') + '>' +
                  '<span class="cc-orb">' + bentoSvg('conns') + '</span>' +
                  '<span class="cc-txt"><b>实时连接流</b><small><span data-cc-conn="' + esc(d.mac) + '">' + connCount + '</span> · 点按嗅探</small></span>' +
                '</button>';
    html = html.replace('<div class="cc-bento-row">', '<div class="cc-bento-row bento-4">')
               .replace('</button></div><div class="ctrl lcc-ctrl', '</button>' + tile4 + '</div><div class="ctrl lcc-ctrl');
    return html;
  };

  var _origPaintConnCounts = window.paintConnCounts;
  if (typeof _origPaintConnCounts === 'function') {
    window.paintConnCounts = function() {
      _origPaintConnCounts();
      S.devices.forEach(function(d) {
        var nConn = d.online && S.connCounts && S.connCounts[d.mac] && S.connCounts[d.mac].n;
        if (!nConn) return;
        $$('[data-cc-conn="' + d.mac + '"]').forEach(function(el) { el.textContent = nConn + ' 条'; });
      });
    };
  }

  var _origRenderDevices = window.renderDevices;
  window.renderDevices = function(anim1) {
    _origRenderDevices(anim1);
    injectQuickPills();
    drawSpark();
  };

  var _origRenderDevList = window.renderDevList;
  window.renderDevList = function(animate) {
    _origRenderDevList(animate);
    injectQuickPills();
  };

  var _origRefreshCard = window.refreshCard;
  if (typeof _origRefreshCard === 'function') {
    window.refreshCard = function(mac) {
      _origRefreshCard(mac);
      injectQuickPills();
    };
  }

  /* ── 4. 增强应用页：顶部注入本机应用流量构成彩条 (.app-cat-card) ── */
  var _origAppsSub = window.appsSub;
  if (typeof _origAppsSub === 'function') {
    window.appsSub = function() {
      var html = _origAppsSub();
      if (S.appsSub === 'my') {
        var rows = appRows().filter(function(r){ return !r.a.is_system && r.bytes > 0; }).slice(0, 6);
        var tot = rows.reduce(function(s, r){ return s + r.bytes; }, 0);
        if (tot > 0) {
          var barHtml = '<div class="glass app-cat-card">' +
            '<div style="display:flex;justify-content:space-between;font-size:12px;font-weight:650"><span>本机主力应用流量占比</span><span class="num">Top ' + rows.length + ' · ' + bytes(tot) + '</span></div>' +
            '<div class="app-cat-bar">' + rows.map(function(r){
              return '<i style="width:' + (r.bytes / tot * 100).toFixed(1) + '%;background:' + appColor(r.a.pkg || r.name) + '"></i>';
            }).join('') + '</div>' +
            '<div class="app-cat-leg">' + rows.map(function(r){
              return '<span><i style="background:' + appColor(r.a.pkg || r.name) + '"></i>' + esc(r.name) + ' ' + Math.round(r.bytes / tot * 100) + '%</span>';
            }).join('') + '</div></div>';
          html = barHtml + html;
        }
      }
      return html;
    };
  }

  /* ── 5. 增强分析页 DPI 座舱：注入 SVG 环形识别覆盖率仪表盘 (.dpi-ring-svg) ── */
  var _origPaintDpi = window.paintDpi;
  if (typeof _origPaintDpi === 'function') {
    window.paintDpi = function() {
      _origPaintDpi();
      var top = $('#dpi-hero .dpihero .top');
      var st = S.dpi && S.dpi.available && S.dpi.state;
      var ur = st && st.unidentified_ratio;
      if (top && ur && ur.total_bytes && !$('#dpi-cov-ring')) {
        var cov = clamp(1 - num(ur.ratio), 0, 1), r = 19, c = 2 * Math.PI * r;
        var ringHtml = '<div class="dpi-ring-wrap" id="dpi-cov-ring">' +
          '<svg class="dpi-ring-svg" viewBox="0 0 46 46">' +
            '<circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--input)" stroke-width="4.5"/>' +
            '<circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--green)" stroke-width="4.5" stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + ((1 - cov) * c).toFixed(1) + '" stroke-linecap="round"/>' +
          '</svg>' +
          '<div style="text-align:right"><div class="num" style="font-size:17px;font-weight:800">' + Math.round(cov * 100) + '%</div><div class="note">识别覆盖率</div></div>' +
        '</div>';
        top.lastElementChild.insertAdjacentHTML('beforebegin', ringHtml);
      }
    };
  }

  /* ── 6. 增强设置页：顶部实时搜索过滤框 (#set-q)，跨 12 张折叠卡片秒搜 ── */
  function applySetSearch() {
    var q = (S.setQ || '').trim().toLowerCase();
    $$('#p-settings .scard').forEach(function(card) {
      var match = !q || card.textContent.toLowerCase().indexOf(q) >= 0;
      card.hidden = !match;
      if (q && match) {
        card.classList.add('open');
        placeSegs(card);
      }
    });
    $$('#p-settings [data-lv-sec]').forEach(function(sec) {
      if (q) sec.hidden = !$$('.scard:not([hidden])', sec).length;
      else sec.hidden = (S.setLv !== 'all' && sec.getAttribute('data-lv-sec') !== S.setLv);
    });
  }

  var _origRenderSettings = window.renderSettings;
  if (typeof _origRenderSettings === 'function') {
    window.renderSettings = function(anim1) {
      var wasFocused = document.activeElement && document.activeElement.id === 'set-q';
      var selStart = wasFocused ? document.activeElement.selectionStart : null;
      var selEnd = wasFocused ? document.activeElement.selectionEnd : null;
      _origRenderSettings(anim1);
      var bar = $('#p-settings .set-top-bar');
      if (bar && !$('#set-q')) {
        bar.insertAdjacentHTML('afterbegin',
          '<label class="glass search">' + ico('search') +
            '<input id="set-q" type="search" placeholder="搜索设置项（如：DNS、QUIC、配对、液态玻璃、自检）" value="' + esc(S.setQ) + '" autocomplete="off">' +
          '</label>'
        );
      }
      if (S.setQ && S.setQ.trim()) applySetSearch();
      if (wasFocused && $('#set-q')) {
        var inpEl = $('#set-q');
        inpEl.focus();
        try { if (selStart != null) inpEl.setSelectionRange(selStart, selEnd); } catch (_) {}
      }
    };
  }

  /* ── 7. 绑定新增交互事件（快捷胶囊、设置搜索、液态滑块松手自动下发限速） ── */
  document.addEventListener('click', function(e) {
    var qp = e.target.closest && e.target.closest('[data-qpill]');
    if (qp) {
      S.qpill = qp.getAttribute('data-qpill');
      renderDevList(false);
      return;
    }
    var setLvBtn = e.target.closest && e.target.closest('[data-seg="set-lv"] button');
    if (setLvBtn && S.setQ && S.setQ.trim()) {
      setTimeout(applySetSearch, 0);
    }
  });

  // 设置页实时搜索过滤
  document.addEventListener('input', function(e) {
    if (e.target && e.target.id === 'set-q') {
      S.setQ = e.target.value;
      applySetSearch();
    }
  });

  // 初次挂载立即刷新当前视图
  if (S.page === 'devices') renderDevices(false);
  else if (S.page === 'apps') renderApps(false);
  else if (S.page === 'stats') renderStats(false);
  else if (S.page === 'vector' && typeof renderVectorPage === 'function') renderVectorPage(false);
  else if (S.page === 'settings') renderSettings(false);
})();

/* === v5.33.1 Enhancement Layer 3: Custom Wallpaper Engine (Zero-Halo Micro-Capsule), Pure Digital Bandwidth & Auto Public CDN Badges === */
(function(){
  'use strict';
  if (typeof S === 'undefined') return;

  function softAnimateContainer(el) {
    if (!el || typeof motionOn !== 'function' || !motionOn()) return;
    el.classList.remove('fx-rise');
    void el.offsetWidth;
    el.classList.add('fx-rise');
  }

  /* ── 1. 自定义背景壁纸引擎（内置高折射 SVG 壁纸 + 本地图片压缩导入 + URL + 景深模糊/护眼遮罩） ── */
  function svgDataUri(svg) {
    return 'url("data:image/svg+xml;utf8,' + encodeURIComponent(svg) + '")';
  }

  var WP_PRESETS = {
    none: { label: '默认无图', thumb: 'linear-gradient(135deg,#e2ecfb,#cbd8ea)', uri: '' },
    aurora: {
      label: '深海极光',
      thumb: 'linear-gradient(135deg,#07192f,#0ea5e9 52%,#2dd4bf)',
      uri: svgDataUri('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><linearGradient id="g0" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#071326"/><stop offset="50%" stop-color="#0d2847"/><stop offset="100%" stop-color="#091d36"/></linearGradient><linearGradient id="g1" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#38bdf8" stop-opacity="0.75"/><stop offset="50%" stop-color="#2dd4bf" stop-opacity="0.65"/><stop offset="100%" stop-color="#818cf8" stop-opacity="0.7"/></linearGradient><linearGradient id="g2" x1="0" y1="1" x2="1" y2="0"><stop offset="0%" stop-color="#0284c7" stop-opacity="0.6"/><stop offset="100%" stop-color="#34d399" stop-opacity="0.55"/></linearGradient></defs><rect width="1200" height="800" fill="url(#g0)"/><circle cx="240" cy="180" r="280" fill="#0ea5e9" opacity="0.32"/><circle cx="980" cy="640" r="320" fill="#6366f1" opacity="0.28"/><path d="M-100 520 C 260 320, 520 680, 920 390 C 1080 280, 1200 360, 1320 260 L 1320 860 L -100 860 Z" fill="url(#g1)"/><path d="M-80 650 C 310 470, 660 740, 1300 460 L 1300 860 L -80 860 Z" fill="url(#g2)"/></svg>')
    },
    slate: {
      label: '蓝灰矩阵',
      thumb: 'linear-gradient(135deg,#0b1119,#1e3248 60%,#4a82b0)',
      uri: svgDataUri('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0a1018"/><stop offset="55%" stop-color="#142232"/><stop offset="100%" stop-color="#0d1724"/></linearGradient><pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"><path d="M 60 0 L 0 0 0 60" fill="none" stroke="#5ea4dc" stroke-opacity="0.14" stroke-width="1"/></pattern></defs><rect width="1200" height="800" fill="url(#bg)"/><rect width="1200" height="800" fill="url(#grid)"/><g stroke="#62a5dc" stroke-opacity="0.34" fill="none" stroke-width="2"><polygon points="180,140 360,90 460,250 280,320"/><polygon points="740,180 1020,120 1100,360 830,420"/><polygon points="320,520 640,410 760,670 420,730"/><line x1="360" y1="90" x2="740" y2="180"/><line x1="460" y1="250" x2="640" y2="410"/><line x1="830" y1="420" x2="640" y2="410"/></g><g fill="#5bc2b0" opacity="0.55"><circle cx="360" cy="90" r="6"/><circle cx="460" cy="250" r="6"/><circle cx="740" cy="180" r="6"/><circle cx="830" cy="420" r="6"/><circle cx="640" cy="410" r="7"/></g></svg>')
    },
    dusk: {
      label: '暮光层峦',
      thumb: 'linear-gradient(160deg,#3b82f6,#a855f7 52%,#fb7185)',
      uri: svgDataUri('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1d4ed8"/><stop offset="48%" stop-color="#7e22ce"/><stop offset="85%" stop-color="#f43f5e"/><stop offset="100%" stop-color="#fb923c"/></linearGradient></defs><rect width="1200" height="800" fill="url(#sky)"/><circle cx="860" cy="230" r="95" fill="#fde047" opacity="0.72"/><path d="M0 500 L220 360 L450 470 L710 310 L960 450 L1200 340 L1200 800 L0 800 Z" fill="#311042" opacity="0.55"/><path d="M0 590 L180 480 L430 580 L690 440 L940 570 L1200 470 L1200 800 L0 800 Z" fill="#1e1b4b" opacity="0.78"/><path d="M0 680 L290 590 L580 670 L890 580 L1200 650 L1200 800 L0 800 Z" fill="#0f172a"/></svg>')
    },
    prism: {
      label: '流光棱镜',
      thumb: 'linear-gradient(135deg,#bae6fd,#e9d5ff 50%,#fecdd3)',
      uri: svgDataUri('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><linearGradient id="p0" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#dbeafe"/><stop offset="50%" stop-color="#f3e8ff"/><stop offset="100%" stop-color="#ffe4e6"/></linearGradient><linearGradient id="p1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#38bdf8" stop-opacity="0.7"/><stop offset="100%" stop-color="#818cf8" stop-opacity="0.65"/></linearGradient><linearGradient id="p2" x1="1" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#f472b6" stop-opacity="0.65"/><stop offset="100%" stop-color="#fb923c" stop-opacity="0.55"/></linearGradient></defs><rect width="1200" height="800" fill="url(#p0)"/><circle cx="260" cy="240" r="240" fill="url(#p1)"/><circle cx="920" cy="260" r="260" fill="url(#p2)"/><circle cx="620" cy="600" r="290" fill="#2dd4bf" opacity="0.42"/><rect x="140" y="120" width="920" height="560" rx="64" fill="none" stroke="#ffffff" stroke-opacity="0.65" stroke-width="6"/></svg>')
    }
  };

  S.wpId = LS.get('hnc6.wp_id', 'none');
  S.wpCustom = LS.get('hnc6.wp_custom', '');
  S.wpBlur = num(LS.get('hnc6.wp_blur', '0'), 0);
  S.wpDim = num(LS.get('hnc6.wp_dim', '22'), 22);
  // v5.36.0: 默认启用无界原生透字排版 ('adaptive')，消除实心白底膏药胶囊；用 wp_text_v2 平滑升级旧缓存
  S.wpTextMode = LS.get('hnc6.wp_text_v2', '') === 'capsule' ? 'capsule' : 'adaptive';
  S.hideSharedUnk = LS.get('hnc6.hide_shared_unk', '0') === '1';

  var PRESET_TONES = {
    aurora: { tone: 'dark', top: 'dark', bot: 'dark' },
    slate:  { tone: 'dark', top: 'dark', bot: 'dark' },
    dusk:   { tone: 'dark', top: 'dark', bot: 'dark' },
    prism:  { tone: 'light', top: 'light', bot: 'light' }
  };

  if (typeof window !== 'undefined' && Array.isArray(window.__HNC_USER_WALLPAPERS)) {
    window.__HNC_USER_WALLPAPERS.forEach(function (uw) {
      if (!uw || !uw.id || !uw.src) return;
      WP_PRESETS[uw.id] = {
        label: uw.label || uw.id,
        thumb: 'url("' + uw.src + '") center/cover no-repeat',
        uri: 'url("' + uw.src + '")',
        rawSrc: uw.src
      };
      if (uw.tones) PRESET_TONES[uw.id] = uw.tones;
    });
    if (!LS.get('hnc6.wp_init_v537', '') && window.__HNC_USER_WALLPAPERS[0]) {
      S.wpId = window.__HNC_USER_WALLPAPERS[0].id;
      S.wpDim = 10;
      LS.set('hnc6.wp_id', S.wpId);
      LS.set('hnc6.wp_dim', '10');
      LS.set('hnc6.wp_init_v537', '1');
    }
  }

  function setWpToneAttrs(tones, persist) {
    var r = document.documentElement;
    var topT = (tones && tones.top) || 'dark';
    var midT = (tones && tones.tone) || 'light';
    var botT = (tones && tones.bot) || 'dark';
    r.setAttribute('data-wp-top', topT);
    r.setAttribute('data-wp-tone', midT);
    r.setAttribute('data-wp-bot', botT);
    if (persist) try { LS.set('hnc6.wp_tones', topT + ',' + midT + ',' + botT); } catch (_) {}
  }

  function detectWallpaperTone(rawSrc) {
    if (S.wpId !== 'custom' && PRESET_TONES[S.wpId] && !rawSrc) {
      setWpToneAttrs(PRESET_TONES[S.wpId], true);
      return;
    }
    if (S.wpId !== 'custom' && PRESET_TONES[S.wpId]) {
      setWpToneAttrs(PRESET_TONES[S.wpId], true);
    } else {
      var cached = String(LS.get('hnc6.wp_tones', '') || '').split(',');
      if (cached.length === 3) setWpToneAttrs({ top: cached[0], tone: cached[1], bot: cached[2] }, false);
      else setWpToneAttrs({ top: 'dark', tone: 'light', bot: 'dark' }, false);
    }
    if (!rawSrc) return;
    var im = new Image();
    im.crossOrigin = 'anonymous';
    im.onload = function() {
      try {
        var W = 24, H = 36, cv = document.createElement('canvas');
        cv.width = W; cv.height = H;
        var ctx = cv.getContext('2d');
        ctx.drawImage(im, 0, 0, W, H);
        var d = ctx.getImageData(0, 0, W, H).data;
        var sumMid = 0, nMid = 0, sumTop = 0, nTop = 0, sumBot = 0, nBot = 0;
        for (var y = 0; y < H; y++) {
          for (var x = 0; x < W; x++) {
            var idx = (y * W + x) * 4;
            var lum = 0.2126 * d[idx] + 0.7152 * d[idx + 1] + 0.0722 * d[idx + 2];
            if (y < 9) { sumTop += lum; nTop++; }
            else if (y < 27) { sumMid += lum; nMid++; }
            else { sumBot += lum; nBot++; }
          }
        }
        setWpToneAttrs({
          top: (nTop ? sumTop / nTop : 110) < 118 ? 'dark' : 'light',
          tone: (nMid ? sumMid / nMid : 128) < 108 ? 'dark' : 'light',
          bot: (nBot ? sumBot / nBot : 110) < 108 ? 'dark' : 'light'
        }, true);
      } catch (_) {}
    };
    im.src = rawSrc;
  }

  window.applyWallpaper = function() {
    var r = document.documentElement;
    var uri = '', rawSrc = '';
    if (S.wpId === 'custom' && S.wpCustom) {
      rawSrc = S.wpCustom;
      uri = 'url("' + S.wpCustom.replace(/"/g, '\"') + '")';
    } else if (WP_PRESETS[S.wpId] && WP_PRESETS[S.wpId].uri) {
      uri = WP_PRESETS[S.wpId].uri;
      rawSrc = WP_PRESETS[S.wpId].rawSrc || '';
    }
    if (uri) {
      r.setAttribute('data-has-wp', '1');
      r.setAttribute('data-has-wallpaper', '1');
      r.classList.add('has-wallpaper');
      r.setAttribute('data-wp-text', S.wpTextMode === 'capsule' ? 'capsule' : 'adaptive');
      r.style.setProperty('--wp-image', uri);
      r.style.setProperty('--wp-blur', clamp(num(S.wpBlur, 0), 0, 24) + 'px');
      r.style.setProperty('--wp-dim', (clamp(num(S.wpDim, 12), 0, 75) / 100).toFixed(2));
      detectWallpaperTone(rawSrc);
    } else {
      r.removeAttribute('data-has-wp');
      r.removeAttribute('data-has-wallpaper');
      r.classList.remove('has-wallpaper');
      r.removeAttribute('data-wp-text');
      r.removeAttribute('data-wp-tone');
      r.removeAttribute('data-wp-top');
      r.removeAttribute('data-wp-bot');
      r.style.removeProperty('--wp-image');
    }
    if (typeof refreshHyaliteTargets === 'function') refreshHyaliteTargets();
  };

  window.wpSettingsHtml = function() {
    var hasWp = (S.wpId === 'custom' && !!S.wpCustom) || (S.wpId !== 'none' && !!WP_PRESETS[S.wpId]);
    var preBtns = Object.keys(WP_PRESETS).map(function(k) {
      var p = WP_PRESETS[k];
      return '<button type="button" class="wp-pre press' + (S.wpId === k ? ' on' : '') + '" data-wp-pick="' + k + '">' +
        '<span class="wp-sw" style="background:' + p.thumb + '"></span>' +
        '<span>' + p.label + '</span></button>';
    }).join('');
    var customBadge = S.wpId === 'custom' && S.wpCustom ? ' · 已启用自定义图' : '';
    return '<div class="wp-panel" id="wp-panel">' +
      '<div class="note" style="margin-bottom:-2px">自定义背景壁纸' + customBadge + '（液态玻璃支持实时真光学边缘折射）</div>' +
      '<div class="wp-presets">' + preBtns + '</div>' +
      '<div class="wp-actions">' +
        '<input type="file" id="wp-file" accept="image/*" hidden>' +
        '<button type="button" class="btn sec press" data-act="wp-upload">本地选图</button>' +
        '<span class="box"><input id="wp-url-inp" type="url" placeholder="粘贴图片 https:// 直链…" value="' + (S.wpId === 'custom' && /^https?:\/\//.test(S.wpCustom) ? esc(S.wpCustom) : '') + '" style="font-size:12.5px"></span>' +
        '<button type="button" class="btn sec press" data-act="wp-url-apply">应用链接</button>' +
      '</div>' +
      '<div class="wp-sliders" id="wp-sliders"' + (hasWp ? '' : ' hidden') + '>' +
        '<div class="wp-mode-row"><span class="note" style="margin:0">标题与分组排版（无白边膏药感）</span>' +
          '<span class="wp-mode-pills">' +
            '<button type="button" class="wp-mpill press' + (S.wpTextMode !== 'capsule' ? ' on' : '') + '" data-wp-tmode="adaptive">原生透字</button>' +
            '<button type="button" class="wp-mpill press' + (S.wpTextMode === 'capsule' ? ' on' : '') + '" data-wp-tmode="capsule">轻纱托底</button>' +
          '</span></div>' +
        '<div class="note" style="margin-bottom:-2px">背景景深模糊 · <span id="wp-blur-v">' + Math.round(S.wpBlur) + ' px</span>（0 px 可最大化液态玻璃边缘折射细节）</div>' +
        '<div class="gx-row"><span>清晰</span><input type="range" class="gx-range" id="wp-blur" min="0" max="24" step="1" value="' + Math.round(S.wpBlur) + '" aria-label="背景景深模糊"><span>柔和</span></div>' +
        '<div class="note" style="margin-bottom:-2px">遮罩护眼浓度 · <span id="wp-dim-v">' + Math.round(S.wpDim) + '%</span>（花哨壁纸调高可保证文字锐利清晰）</div>' +
        '<div class="gx-row"><span>透亮</span><input type="range" class="gx-range" id="wp-dim" min="0" max="75" step="1" value="' + Math.round(S.wpDim) + '" aria-label="遮罩护眼浓度"><span>护眼</span></div>' +
      '</div>' +
    '</div>';
  };

  function syncWpUi() {
    var hasWp = (S.wpId === 'custom' && !!S.wpCustom) || (S.wpId !== 'none' && !!WP_PRESETS[S.wpId]);
    $$('[data-wp-pick]').forEach(function(b) {
      b.classList.toggle('on', b.getAttribute('data-wp-pick') === S.wpId);
    });
    var sl = $('#wp-sliders');
    if (sl) sl.hidden = !hasWp;
  }

  /* ── 2. 纯数字带宽输入实时换算与一键清空（零闪烁） ── */
  function syncBwInput(box, field) {
    if (!box) return;
    var inp = box.querySelector('[data-f="' + field + '"]');
    var eq = box.querySelector('[data-bw-eq="' + field + '"]');
    var clr = box.querySelector('[data-bw-clr="' + field + '"]');
    var card = inp && inp.closest('.bw-card');
    if (!inp) return;
    var raw = String(inp.value || '').trim();
    var v = parseFloat(raw) || 0;
    if (card) card.classList.toggle('has-val', v > 0);
    if (clr) clr.hidden = !raw.length;
    if (eq) eq.textContent = v > 0 ? '≈ ' + trim0((v * 8).toFixed(1)) + ' Mbps' : '当前不限速';
  }

  document.addEventListener('input', function(e) {
    var t = e.target;
    if (!t) return;
    var f = t.getAttribute && t.getAttribute('data-f');
    if (f === 'down' || f === 'up') {
      syncBwInput(t.closest('[data-dev]') || t.closest('[data-side]'), f);
      return;
    }
    if (t.id === 'wp-blur') {
      S.wpBlur = clamp(num(t.value, 0), 0, 24);
      LS.set('hnc6.wp_blur', String(S.wpBlur));
      var bv = $('#wp-blur-v'); if (bv) bv.textContent = Math.round(S.wpBlur) + ' px';
      applyWallpaper();
      return;
    }
    if (t.id === 'wp-dim') {
      S.wpDim = clamp(num(t.value, 22), 0, 75);
      LS.set('hnc6.wp_dim', String(S.wpDim));
      var dv = $('#wp-dim-v'); if (dv) dv.textContent = Math.round(S.wpDim) + '%';
      applyWallpaper();
      return;
    }
  });

  document.addEventListener('change', function(e) {
    var t = e.target;
    if (!t || t.id !== 'wp-file' || !t.files || !t.files[0]) return;
    var file = t.files[0];
    var reader = new FileReader();
    reader.onload = function(ev) {
      var img = new Image();
      img.onload = function() {
        var maxSide = 1600, w = img.width || 800, h = img.height || 600;
        if (w > maxSide || h > maxSide) {
          var scale = maxSide / Math.max(w, h);
          w = Math.round(w * scale);
          h = Math.round(h * scale);
        }
        var cv = document.createElement('canvas');
        cv.width = w; cv.height = h;
        var ctx = cv.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);
        var dataUrl = cv.toDataURL('image/jpeg', 0.84);
        S.wpCustom = dataUrl;
        S.wpId = 'custom';
        try { LS.set('hnc6.wp_custom', dataUrl); LS.set('hnc6.wp_id', 'custom'); } catch (_) {}
        applyWallpaper();
        syncWpUi();
        toast('已应用自定义本地壁纸');
      };
      img.onerror = function() { toast('图片格式无法解析', 'err'); };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
    t.value = '';
  });

  /* ── 3. 重构 DPI 分析页「活跃设备 (#dpi-clients)」与「设备画像 (#dpi-ident)」为精致紧凑 Bento ── */
  window.paintClients = function() {
    var el = $('#dpi-clients');
    if (!el) return;
    var st = S.dpi && S.dpi.available && S.dpi.state;
    var cl = st && st.clients ? Object.keys(st.clients).map(function(k){ return st.clients[k]; }) : [];
    var nowS = Date.now() / 1000;
    cl = cl.filter(function(c) {
      if (S.dpiFilter === 'active') return nowS - num(c.last_seen) < 120;
      if (S.dpiFilter === 'high') return (c.top_apps || []).some(function(a){ return a.confidence === 'high'; });
      return true;
    }).sort(function(a, b){ return num(b.last_seen) - num(a.last_seen); });

    if (!cl.length) {
      el.innerHTML = '<div class="empty">' + (st ? '没有符合条件的设备' : '等待 dpid 数据…') + '</div>';
      return;
    }
    el.innerHTML = cl.slice(0, 30).map(function(c) {
      var d = c.client_mac ? devBy(c.client_mac) : null;
      var ips = c.client_ips && c.client_ips.length ? c.client_ips : [c.client_ip];
      var iconHtml = d ? d.icon : ico('dev');
      return '<div class="dpi-client-card">' +
        '<span class="dpi-dev-av">' + iconHtml + '</span>' +
        '<div class="dpi-dev-main">' +
          '<div class="dpi-dev-head">' +
            '<span class="dpi-dev-nm">' + esc(d ? d.name : (c.last_hostname || c.client_mac || c.client_ip)) +
              (c.sim || (d && d.sim) ? ' <span class="badge b-sim">模拟</span>' : '') +
            '</span>' +
            '<span class="pill-count">' + ago(c.last_seen) + '</span>' +
          '</div>' +
          (d && d.idText ? '<div class="dpi-dev-id">' + esc(d.idText) + '</div>' : '') +
          '<div class="dpi-meta-pills">' +
            '<span class="dpi-mpill">' + esc(ips[0] || '—') + (ips.length > 1 ? ' +' + (ips.length - 1) : '') + '</span>' +
            '<span class="dpi-mpill">DNS ' + num(c.dns_events) + ' · TLS ' + num(c.tls_events) + '</span>' +
            (c.rx_bytes || c.tx_bytes ? '<span class="dpi-mpill">↓' + bytes(c.rx_bytes) + ' ↑' + bytes(c.tx_bytes) + '</span>' : '') +
            (c.last_sni ? '<span class="dpi-mpill sni">' + esc(c.last_sni) + '</span>' : '') +
          '</div>' +
          ((c.top_apps || []).length ? '<div class="apps" style="display:flex;gap:4px;flex-wrap:wrap;margin-top:2px">' +
            c.top_apps.slice(0, 6).map(function(a) {
              return '<span class="badge ' + (a.id === TUNNEL_ID ? 'b-gray' : a.confidence === 'high' ? 'b-acc' : a.confidence === 'low' ? 'b-gray' : 'b-pur') + '">' +
                appNmH(a.id, a.name) + (a.confidence === 'low' ? '?' : '') + '</span>';
            }).join('') + '</div>' : '') +
        '</div></div>';
    }).join('');
  };

  window.paintIdent = function() {
    var el = $('#dpi-ident');
    if (!el) return;
    var ds = S.devices.filter(function(d){ return d.ident; })
      .sort(function(a, b){ return (b.online - a.online) || num(b.ident.confidence) - num(a.ident.confidence); });
    if (!ds.length) {
      el.innerHTML = '<div class="empty">还没有识别结果 · 设备重新连接热点后会通过 DHCP / mDNS 自动识别</div>';
      return;
    }
    var tot = S.devices.filter(function(d){ return d.online; }).length;
    var got = ds.filter(function(d){ return d.online; }).length;
    el.innerHTML = '<div class="note" style="padding:11px 15px 4px">在线 ' + tot + ' 台，已识别 ' + got + ' 台</div>' +
      ds.slice(0, 30).map(function(d) {
        var conf = clamp(num(d.ident.confidence), 0, 100);
        return '<div class="dpi-client-card">' +
          '<span class="dpi-dev-av">' + d.icon + '</span>' +
          '<div class="dpi-dev-main">' +
            '<div class="dpi-dev-head">' +
              '<span class="dpi-dev-nm">' + esc(d.name) + (d.sim ? ' <span class="badge b-sim">模拟</span>' : '') + '</span>' +
              '<span class="dpi-conf-wrap"><span class="dpi-conf-track"><i style="width:' + conf + '%"></i></span><span class="pill-count">' + conf + '%</span></span>' +
            '</div>' +
            '<div class="dpi-dev-id">' + esc(d.idText || '—') + (d.online ? '' : ' · 离线') + '</div>' +
            (d.ident.evidence && d.ident.evidence.length ? '<div class="dpi-meta-pills">' +
              d.ident.evidence.slice(0, 3).map(function(ev) {
                return '<span class="dpi-mpill">' + esc((EV_SRC[ev.src] || ev.src) + ': ' + ev.detail) + '</span>';
              }).join('') + '</div>' : '') +
          '</div></div>';
      }).join('');
  };

  /* ── 4. 升级 DPI 环形覆盖率仪表盘生长动画 ── */
  var _v8PaintDpi = window.paintDpi;
  if (typeof _v8PaintDpi === 'function') {
    window.paintDpi = function() {
      _v8PaintDpi();
      var ringProg = $('#dpi-cov-ring circle:nth-child(2)');
      if (ringProg && !ringProg.dataset.animated && typeof motionOn === 'function' && motionOn()) {
        ringProg.dataset.animated = '1';
        var targetOff = ringProg.getAttribute('stroke-dashoffset');
        var dash = ringProg.getAttribute('stroke-dasharray');
        ringProg.style.strokeDashoffset = dash;
        ringProg.classList.add('dpi-ring-anim');
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            ringProg.style.strokeDashoffset = targetOff;
          });
        });
      }
    };
  }

  /* ── 5. 快捷胶囊、分段切换、带宽清空与壁纸交互委托 ── */
  document.addEventListener('click', function(e) {
    var clr = e.target.closest && e.target.closest('[data-bw-clr]');
    if (clr) {
      e.preventDefault();
      var fld = clr.getAttribute('data-bw-clr');
      var box = clr.closest('[data-dev]') || clr.closest('[data-side]');
      var inp = box && box.querySelector('[data-f="' + fld + '"]');
      if (inp && !inp.disabled) {
        inp.value = '';
        syncBwInput(box, fld);
        inp.focus();
      }
      return;
    }
    var wpPick = e.target.closest && e.target.closest('[data-wp-pick]');
    if (wpPick) {
      var wid = wpPick.getAttribute('data-wp-pick');
      S.wpId = wid;
      LS.set('hnc6.wp_id', wid);
      applyWallpaper();
      syncWpUi();
      toast(wid === 'none' ? '已恢复主题默认背景' : '已切换壁纸：「' + WP_PRESETS[wid].label + '」');
      return;
    }
    var wpUp = e.target.closest && e.target.closest('[data-act="wp-upload"]');
    if (wpUp) {
      var wf = $('#wp-file');
      if (wf) wf.click();
      return;
    }
    var wpUrlBtn = e.target.closest && e.target.closest('[data-act="wp-url-apply"]');
    if (wpUrlBtn) {
      var uInp = $('#wp-url-inp');
      var urlVal = uInp ? uInp.value.trim() : '';
      if (!urlVal) {
        S.wpId = 'none';
        LS.set('hnc6.wp_id', 'none');
        applyWallpaper();
        syncWpUi();
        toast('已清除壁纸链接');
        return;
      }
      if (!/^(https:\/\/|data:image\/)/i.test(urlVal)) {
        toast('请输入以 https:// 开头的图片直链', 'warn');
        return;
      }
      S.wpCustom = urlVal;
      S.wpId = 'custom';
      LS.set('hnc6.wp_custom', urlVal);
      LS.set('hnc6.wp_id', 'custom');
      applyWallpaper();
      syncWpUi();
      toast('已应用自定义网络壁纸');
      return;
    }
    var qp = e.target.closest && e.target.closest('[data-qpill]');
    if (qp && typeof stagger === 'function') {
      requestAnimationFrame(function() {
        var dl = $('#dev-list');
        if (dl) stagger(dl, 8);
      });
    }
    var cc = e.target.closest && e.target.closest('.cc-tile');
    var c0 = cc && cc.closest('.dev, .swap'), m0 = c0 && (c0.getAttribute('data-dev') || c0.getAttribute('data-side'));
    if (cc && !cc.disabled && !(m0 && S.busy[m0])) {
      cc.classList.remove('pulse');
      void cc.offsetWidth;
      cc.classList.add('pulse');
    }
    var segBtn = e.target.closest && e.target.closest('.seg button');
    if (segBtn) {
      var sg = segBtn.parentNode;
      var k = sg && sg.getAttribute('data-seg');
      if (k === 'dflt') requestAnimationFrame(function(){ softAnimateContainer($('#dpi-clients')); });
      else if (k === 'hist') requestAnimationFrame(function(){ softAnimateContainer($('#dpi-hist')); softAnimateContainer($('#dpi-unk2')); });
      else if (k === 'pu-period') requestAnimationFrame(function(){ softAnimateContainer($('#pu-body')); });
      else if (k === 'range') requestAnimationFrame(function(){ softAnimateContainer($('#bars')); softAnimateContainer($('#st-apps')); });
    }
  });

  /* ── 6. 多维特征自动识别公共 CDN / 云网关 / 第三方广告统计 SDK（免手动逐个排查） ── */
  var INFRA_EXACT = {
    'alicdn.com': ['cdn', '阿里 CDN'], 'alikunlun.com': ['cdn', '阿里昆仑 CDN'], 'alikunlun.net': ['cdn', '阿里昆仑 CDN'],
    'aliyuncs.com': ['cloud', '阿里云 OSS'], 'cdngslb.com': ['cdn', 'GSLB 调度'], 'qtlcdn.com': ['cdn', '速腾 CDN'],
    'ksyuncdn.com': ['cdn', '金山云 CDN'], 'ks-cdn.com': ['cdn', '金山云 CDN'], 'wscdns.com': ['cdn', '网宿 CDN'],
    'wsglb0.com': ['cdn', '网宿 GSLB'], 'cdn20.com': ['cdn', '网宿 CDN'], 'chinanetcenter.com': ['cdn', '网宿科技'],
    'hwcdn.net': ['cdn', '华为云 CDN'], 'myhuaweicloud.com': ['cloud', '华为云'], 'bdydns.com': ['cdn', '百度云 CDN'],
    'bcebos.com': ['cloud', '百度云 BOS'], 'bdstatic.com': ['cdn', '百度静态 CDN'], 'myqcloud.com': ['cloud', '腾讯云 COS'],
    'qcloudcdn.com': ['cdn', '腾讯云 CDN'], 'dnsv1.com': ['cdn', '腾讯 DNSPod 调度'], 'dnsv1.com.cn': ['cdn', '腾讯调度'],
    'smtcdns.net': ['cdn', '腾讯智能调度'], 'tcdnvod.com': ['cdn', '腾讯点播 CDN'], 'gtimg.com': ['cdn', '腾讯静态 CDN'],
    'qpic.cn': ['cdn', '腾讯图床 CDN'], 'akamaized.net': ['cdn', 'Akamai CDN'], 'akamaiedge.net': ['cdn', 'Akamai Edge'],
    'edgekey.net': ['cdn', 'Akamai CDN'], 'edgesuite.net': ['cdn', 'Akamai CDN'], 'cloudfront.net': ['cdn', 'AWS CloudFront'],
    'amazonaws.com': ['cloud', 'AWS 云基础设施'], 'fastly.net': ['cdn', 'Fastly CDN'], 'cloudflare.net': ['cdn', 'Cloudflare CDN'],
    'gstatic.com': ['cdn', 'Google 静态 CDN'], 'googleapis.com': ['cloud', 'Google API 网关'],
    'bytecdn.com': ['cdn', '字节 CDN'], 'byteimg.com': ['cdn', '字节图床 CDN'], 'pstatp.com': ['cdn', '字节静态 CDN'],
    'volces.com': ['cloud', '火山引擎云'], 'huoshan-gw.net': ['cloud', '火山/字节共享网关'],
    'tuiaimg.com': ['sdk', '推啊互动广告 SDK'], 'tuia.cn': ['sdk', '推啊广告 SDK'],
    'umeng.com': ['sdk', '友盟统计 SDK'], 'umengcloud.com': ['sdk', '友盟云 SDK'],
    'getui.com': ['sdk', '个推推送 SDK'], 'igexin.com': ['sdk', '个推 SDK'],
    'jpush.cn': ['sdk', '极光推送 SDK'], 'jiguang.cn': ['sdk', '极光 SDK'],
    'pangle.io': ['sdk', '穿山甲广告 SDK'], 'appsflyer.com': ['sdk', 'AppsFlyer 归因 SDK'],
    'adjust.com': ['sdk', 'Adjust 归因 SDK'], 'sentry.io': ['sdk', 'Sentry 监控 SDK'],
    'bugly.qq.com': ['sdk', '腾讯 Bugly SDK']
  };

  window.classifyInfraHost = function(host) {
    var h = String(host || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!h) return null;
    for (var suf in INFRA_EXACT) {
      if (h === suf || h.slice(-(suf.length + 1)) === '.' + suf) {
        var inf = INFRA_EXACT[suf];
        return { kind: inf[0], label: inf[1], shared: true };
      }
    }
    var reg = typeof guessSuffix === 'function' ? guessSuffix(h) : h;
    // 词法结构启发式：自动捕获未入库的阿里 kunlun*、华为 cdnhwc*、腾讯 *dnsv*、各类 *gslb* / *cdn* / sdk.* 节点
    if (/^kunlun[a-z0-9-]*\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '阿里昆仑 CDN 簇', shared: true };
    if (/^cdnhwc[a-z0-9-]*\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '华为云 CDN 簇', shared: true };
    if (/^(t?dnsv[0-9a-z-]*|smtcdns[0-9a-z-]*)\.(com|net|cn|com\.cn)$/.test(reg)) return { kind: 'cdn', label: '腾讯 GSLB/CDN 簇', shared: true };
    if (/(gslb|cdngslb|wsglb|ksyungslb|alikunlun|qiniudns|baishan-cloud|bsclink)/.test(h)) return { kind: 'cdn', label: '公共 GSLB/CDN 调度', shared: true };
    if (/(^|\.)(cdn[0-9]*|static-cdn|imgcdn|vodcdn)\./.test(h) || /-cdn\.(com|net|cn)$/.test(reg)) return { kind: 'cdn', label: '疑似公共 CDN 节点', shared: true };
    if (/^(sdk|ads?|adx|track|telemetry|beacon|metrics|stat|crash)\./.test(h)) return { kind: 'sdk', label: '疑似通用统计/广告 SDK', shared: true };
    return { kind: 'app', label: '可归因专属域名', shared: false };
  };

  function infraBadgeHtml(info) {
    if (!info) return '';
    var prefix = info.kind === 'cdn' ? '公共 CDN · ' : info.kind === 'sdk' ? '共享 SDK · ' : info.kind === 'cloud' ? '公共云网关 · ' : '';
    return '<span class="infra-tag ' + info.kind + '">' + esc(prefix + info.label) + '</span>';
  }

  document.addEventListener('click', function(e) {
    var tm = e.target.closest && e.target.closest('[data-wp-tmode]');
    if (tm) {
      S.wpTextMode = tm.getAttribute('data-wp-tmode') === 'capsule' ? 'capsule' : 'adaptive';
      LS.set('hnc6.wp_text_v2', S.wpTextMode);
      LS.set('hnc6.wp_text', S.wpTextMode);
      applyWallpaper();
      $$('[data-wp-tmode]').forEach(function(b){
        b.classList.toggle('on', b.getAttribute('data-wp-tmode') === S.wpTextMode);
      });
      toast(S.wpTextMode === 'capsule' ? '已切换：无边框轻纱微托底' : '已切换：原生无界透字排版');
      return;
    }
    var hs = e.target.closest && e.target.closest('[data-act="toggle-hide-shared"]');
    if (hs) {
      S.hideSharedUnk = !S.hideSharedUnk;
      LS.set('hnc6.hide_shared_unk', S.hideSharedUnk ? '1' : '0');
      paintUnknown();
      return;
    }
  });


  // 四模式实时速率数字过渡支持(Cyber 阶梯跳变 + 冰蓝闪烁 / Default 180ms 利落跳变 / Frosted & Liquid 柔滑过渡)
  if (typeof window.rollNum === 'function') {
    window.rollNum = function(el, str, unit) {
      if (!el) return;
      var sameUnit = (el.parentNode && el.parentNode.lastChild && el.parentNode.lastChild.textContent || '').trim() === unit;
      if (!fxOn('num') || !motionOn() || !sameUnit || !/^\d+(\.\d+)?$/.test(str) || el.textContent === str) {
        el.textContent = str;
        return;
      }
      tween(el, parseFloat(str), (str.split('.')[1] || '').length);
    };
  }

  // 初始化壁纸与主题同步，并重新渲染当前页面以立即呈现纯数字带宽面板
  if (typeof applyTheme === 'function') applyTheme();
  applyWallpaper();
  if (S.page === 'devices') renderDevices(false);
  else if (S.page === 'settings') renderSettings(false);
  else if (S.page === 'stats' && S.aseg === 'dpi') {
    paintClients();
    paintIdent();
  }
})();
