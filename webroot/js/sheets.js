/* HNC WebUI · sheets.js —— 弹层: 打开/关闭(四主题差异化可打断弹簧 + 共享元素展开)、亚像素跟手下拉与橡皮筋阻尼、确认框、告警列表 */
'use strict';

var sheetOnClose = null;

function sheetOpenFx(already) {
  var sh = $('#sheet'), sc = $('#scrim');
  if (!sh || !appleSheet()) return false;
  SM.closing = false;
  sh.classList.remove('closing', 'is-dragging');
  if (sc) sc.style.opacity = '';
  SM.h = Math.max(260, sh.offsetHeight || 520);
  SM.open = true;
  var mor = !already && fxOn('morph') && !lowFx() && morphFrom();
  if (mor) {
    sh.classList.remove('is-spring');
    shSpring.stop();
    shSpring.x = shSpring.to = 0;
    shSpring.v = 0;
    sh.style.transform = '';
    morphSheet(sh, mor);
    return true;
  }
  if (already && !shSpring.raf) {
    sh.classList.remove('is-spring');
    shSpring.set(0);
    sh.style.transform = '';
    return true;
  }
  sh.classList.add('is-spring');
  if (!already && (!shSpring.raf || shSpring.x > SM.h * 0.65)) {
    shSpring.set(Math.min(SM.h + 36, 420));
  }
  shSpring.go(0, 0, springP());
  return true;
}

function sheetCloseFx(v) {
  var sh = $('#sheet'), sc = $('#scrim');
  if (!sh || !SM.open || !appleSheet()) {
    SM.open = false; SM.closing = false;
    if (sh) { sh.classList.remove('closing', 'is-spring', 'is-dragging'); sh.style.transform = ''; sh.style.opacity = ''; sh.style.transition = ''; }
    if (sc) sc.style.opacity = '';
    return false;
  }
  SM.open = false;
  SM.closing = true;
  if (sc) sc.style.opacity = '';
  sh.classList.remove('is-dragging');
  sh.classList.add('closing', 'is-spring');
  shSpring.go((SM.h || sh.offsetHeight || 480) + 48, v || 0, springP());
  return true;
}

/* 共享元素展开: 记下刚点的那一行/卡片, 650ms 内打开的弹层从它的位置和大小"长"出来(裁剪 + 位移, 内容不变形) */
var lastTap = null;
document.addEventListener('pointerdown', function (e) {
  var t0 = evEl(e);
  var el = t0 && t0.closest && t0.closest('.chip, .btn, .cn, .dg, .row, .sni-row, .client, .dev-h, .cc-tile, [data-act], .dev, .glass');
  if (!el || (el.closest('#sheet') && !el.closest('.cn, .row, .dg, .btn'))) { lastTap = null; return; }
  var r = el.getBoundingClientRect();
  lastTap = { r: r, t: performance.now(), rad: parseFloat(getComputedStyle(el).borderRadius) || 14 };
}, true);

function morphFrom() { return lastTap && performance.now() - lastTap.t < 650 && lastTap.r.width > 20 ? lastTap : null; }
function morphSheet(sh, from) {
  var fr = sh.getBoundingClientRect(), s = from.r, dy = s.top - fr.top;
  var l = Math.max(0, s.left - fr.left), rgt = Math.max(0, fr.right - s.right), b = Math.max(0, fr.height - s.height);
  var endRad = getComputedStyle(sh).borderRadius || '24px 24px 0 0';
  var tp = typeof themePhys === 'function' ? themePhys() : { mode: 'default', q: EASE.q, page: { dur: 260 } };
  var dur = tp.mode === 'cyber' ? 160 : tp.mode === 'default' ? 220 : tp.mode === 'frosted' ? 320 : 380;
  var a = anim(sh, [
    { transform: 'translate3d(-50%,' + dy.toFixed(1) + 'px,0)', clipPath: 'inset(0 ' + rgt.toFixed(1) + 'px ' + b.toFixed(1) + 'px ' + l.toFixed(1) + 'px round ' + from.rad + 'px)' },
    { transform: 'translate3d(-50%,0,0)', clipPath: 'inset(0 0 0 0 round ' + endRad + ')' }
  ], { duration: dur, easing: tp.q });
  anim($('#sheet-body'), [{ opacity: 0 }, { opacity: 1 }], { duration: Math.round(dur * 0.58), delay: Math.round(dur * 0.16), easing: 'ease-out', fill: 'backwards' });
  lastTap = null;
  return a;
}

var _sheetPushedOverDrawer = false;
function sheet(html, opt) {
  opt = opt || {};
  var sh = $('#sheet'); sh.classList.toggle('tall', !!opt.tall); sh.dataset.kind = opt.kind || '';
  var already = sh.classList.contains('show') && !SM.closing;
  var prevClose = sheetOnClose; sheetOnClose = null;
  if (already && prevClose) { try { prevClose(); } catch (_) {} }
  $('#sheet-body').innerHTML = html; sheetOnClose = opt.onClose || null;
  $('#scrim').classList.add('show'); sh.classList.add('show'); sh.scrollTop = 0;
  var drEl = document.getElementById('v6-scalpel-drawer');
  if (!already && drEl && drEl.classList.contains('show') && !_sheetPushedOverDrawer) {
    try {
      if (window.history && typeof window.history.pushState === 'function') {
        window.history.pushState({ hncSheet: 1, hncScalpel: 1 }, '');
        _sheetPushedOverDrawer = true;
      }
    } catch (_) {}
  }
  placeSegs(sh);
  var usedSpring = sheetOpenFx(already);
  if (already && motionOn()) {
    var tp = typeof themePhys === 'function' ? themePhys() : { mode: 'default' };
    var dur = tp.mode === 'cyber' ? 130 : tp.mode === 'default' ? 170 : 230;
    anim($('#sheet-body'), [
      { opacity: 0, transform: tp.mode === 'liquid' || tp.mode === 'frosted' ? 'translate3d(0,6px,0)' : 'translate3d(0,3px,0)' },
      { opacity: 1, transform: 'none' }
    ], { duration: dur, easing: tp.soft || 'ease-out' });
  } else if (!usedSpring && !already && motionOn() && typeof themePhys === 'function' && themePhys().mode === 'cyber') {
    sh.classList.remove('cy-sheet-lock'); void sh.offsetWidth; sh.classList.add('cy-sheet-lock');
  }
  return sh;
}

/* 弹层收起动画还在跑时, 背后的页面先别重绘(否则卡片在半透明遮罩下跳一下)。 */
var sheetCloseAt = 0;
function sheetSettled(v) {
  var tp = typeof themePhys === 'function' ? themePhys() : { mode: 'default' };
  var holdMs = !motionOn() ? 0 : tp.mode === 'cyber' ? 160 : tp.mode === 'default' ? 210 : tp.mode === 'frosted' ? 320 : 380;
  var left = sheetCloseAt + holdMs - performance.now();
  if ($('#sheet').classList.contains('show') || left <= 0) return Promise.resolve(v);
  return new Promise(function (res) { setTimeout(function () { res(v); }, Math.min(420, left)); });
}

function closeSheet(v, fromPop) {
  if ($('#sheet').classList.contains('show')) sheetCloseAt = performance.now();
  if (_sheetPushedOverDrawer) {
    _sheetPushedOverDrawer = false;
    if (!fromPop) {
      try {
        if (window.history && window.history.state && window.history.state.hncSheet) {
          window.__hncSkipNextPop = (typeof window.__hncSkipNextPop === 'number' ? window.__hncSkipNextPop : (window.__hncSkipNextPop ? 1 : 0)) + 1;
          window.history.back();
          setTimeout(function () { if (window.__hncSkipNextPop) window.__hncSkipNextPop = false; }, 300);
        }
      } catch (_) {}
    }
  }
  $('#scrim').classList.remove('show');
  var sh = $('#sheet'); sh.classList.remove('show'); sh.dataset.kind = '';
  sheetCloseFx(typeof v === 'number' ? v : 0);
  var f = sheetOnClose; sheetOnClose = null; if (f) try { f(); } catch (_) {}
}
$('#scrim').addEventListener('click', function () { closeSheet(0); });

/* 弹层跟手下拉与拉手拖拽关闭 —— 亚像素 1:1 跟手 + 向上橡皮筋阻尼 + #scrim 联动渐隐 + 松手速度继承 */
(function () {
  var sh = $('#sheet'), sc = $('#scrim'), st = null;

  function rubberUp(negDy) {
    var mode = typeof motionTheme === 'function' ? motionTheme() : 'default';
    var a = Math.abs(negDy);
    if (mode === 'cyber') return -Math.min(4, a * 0.12);
    if (mode === 'default') return -Math.min(8, Math.pow(a, 0.62) * 0.9);
    return -Math.min(16, Math.pow(a, 0.68) * 1.35);
  }

  function applyDragY(dy) {
    var y = dy >= 0 ? dy : rubberUp(dy);
    if (st.js) {
      shSpring.x = shSpring.to = y;
      shSpring.v = 0;
    }
    sh.style.transform = 'translate3d(-50%,' + y.toFixed(2) + 'px,0)';
    if (sc && motionOn()) {
      var p = y > 0 ? clamp(1 - y / Math.max(240, (SM.h || 520) * 0.92), 0.08, 1) : 1;
      sc.style.opacity = p.toFixed(3);
    }
  }

  function beginDrag(y, onGrab, pid) {
    if (!sh.classList.contains('show') || SM.closing) return false;
    if (!onGrab && sh.scrollTop > 0) return false;
    SM.h = Math.max(260, sh.offsetHeight || 520);
    var useJs = appleSheet() && (typeof fxOn !== 'function' || fxOn('sheet'));
    if (useJs) { shSpring.stop(); SM.open = true; }
    st = {
      y0: y, ly: y, dy: 0, v: 0,
      t0: performance.now(), lt: performance.now(),
      onGrab: !!onGrab, active: !!onGrab, js: useJs, pid: pid
    };
    if (onGrab) sh.classList.add('is-dragging');
    return true;
  }

  function moveDrag(cy, ev) {
    if (!st) return;
    var now = performance.now(), dt = Math.max(1, now - st.lt);
    st.v = st.v * 0.32 + ((cy - st.ly) / dt * 1000) * 0.68;
    st.ly = cy; st.lt = now;
    st.dy = cy - st.y0;

    if (!st.active) {
      if (st.dy < -5 || sh.scrollTop > 0) {
        st = null;
        return;
      }
      if (st.dy < 5) return;
      st.active = true;
      sh.classList.add('is-dragging');
    }
    applyDragY(st.dy);
    if (ev && ev.cancelable) ev.preventDefault();
  }

  function endDrag() {
    if (!st) return;
    var wasActive = st.active, dy = st.dy, useJs = st.js;
    var v = performance.now() - st.lt < 100 ? st.v : 0;
    var elapsed = Math.max(1, performance.now() - st.t0);
    st = null;
    sh.classList.remove('is-dragging');
    if (!wasActive) return;

    var thresh = Math.min(96, Math.max(64, (SM.h || 520) * 0.22));
    var flick = (v > 560 && dy > 18) || (dy > 32 && dy / elapsed > 0.62);
    var shouldClose = dy > thresh || flick;

    if (useJs) {
      if (shouldClose) {
        if (typeof haptic === 'function') haptic(6);
        closeSheet(Math.max(v, 180));
      } else {
        sh.classList.add('is-spring');
        shSpring.go(0, v, springP());
      }
      return;
    }
    sh.style.transform = '';
    if (sc) sc.style.opacity = '';
    if (shouldClose) closeSheet(0);
  }

  // 触屏整卡顶部下拉关闭
  sh.addEventListener('touchstart', function (e) {
    if (e.touches.length !== 1) return;
    var te = evEl(e);
    if (te && te.closest && te.closest('input,textarea,select,.seg,.toggle')) return;
    var onGrab = !!(te && te.closest && te.closest('.grab'));
    beginDrag(e.touches[0].clientY, onGrab, null);
  }, { passive: true });
  sh.addEventListener('touchmove', function (e) {
    if (!st || e.touches.length !== 1) return;
    moveDrag(e.touches[0].clientY, e);
  }, { passive: false });
  sh.addEventListener('touchend', endDrag);
  sh.addEventListener('touchcancel', endDrag);

  // 桌面 / 触控笔按住顶部 .grab 拉手拖拽关闭
  sh.addEventListener('pointerdown', function (e) {
    if (e.pointerType === 'touch' || (e.button != null && e.button !== 0)) return;
    var pe = evEl(e);
    var grab = pe && pe.closest && pe.closest('.grab');
    if (!grab) return;
    e.preventDefault();
    try { grab.setPointerCapture(e.pointerId); } catch (_) {}
    beginDrag(e.clientY, true, e.pointerId);
  });
  sh.addEventListener('pointermove', function (e) {
    if (!st || st.pid == null || e.pointerId !== st.pid) return;
    moveDrag(e.clientY, e);
  });
  sh.addEventListener('pointerup', function (e) {
    if (st && st.pid != null && e.pointerId === st.pid) endDrag();
  });
  sh.addEventListener('pointercancel', function (e) {
    if (st && st.pid != null && e.pointerId === st.pid) endDrag();
  });
})();

$('#sheet').addEventListener('click', function (e) { var t = evEl(e); if (t && t.closest && t.closest('[data-close]')) closeSheet(0); });
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeSheet(0); closeDD(); } });
function confirmSheet(title, desc, okText, opt) {
  opt = opt || {};
  return new Promise(function (resolve) {
    var settled = false;
    sheet('<h3>' + esc(title) + '</h3><div class="sub">' + desc + '</div>' + (opt.extra || '') +
      '<div class="btns"><button class="btn sec press" data-close>取消</button><button class="btn ' + (opt.safe ? 'pri' : 'dan') + ' press" id="cf-ok">' + esc(okText || '确定') + '</button></div>',
      { onClose: function () { if (!settled) { settled = true; resolve(false); } } });
    $('#cf-ok').onclick = function () { var extra = opt.read ? opt.read() : true; settled = true; closeSheet(0); resolve(extra); };
  });
}
function copyText(t) {
  return new Promise(function (resolve) {
    try { if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).then(function () { resolve(true); }, fb); return; } } catch (_) {}
    fb();
    function fb() { try { var ta = document.createElement('textarea'); ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); var ok = document.execCommand('copy'); ta.remove(); resolve(ok); } catch (_) { resolve(false); } }
  });
}
function closeDD() { $$('.dd.open').forEach(function (d) { d.classList.remove('open'); }); }

/* ═════════════════════ 告警 ═════════════════════ */
var ALERT_KIND = { unknown_device: ['新设备接入', 'var(--orange)', devSvg('router', 'mini')], anomaly_traffic: ['流量异常', 'var(--red)', uiSvg('trend')], monthly_quota: ['月度配额', 'var(--purple)', uiSvg('chart')],
  device_quota: ['设备超出流量配额', 'var(--red)', uiSvg('traffic')], phone_quota: ['本机流量套餐', 'var(--orange)', devSvg('phone', 'mini')], app_time_warn: ['应用时长快用完', 'var(--orange)', uiSvg('hourglass')], app_time_exhausted: ['应用时长已用完', 'var(--red)', uiSvg('hourglass')],
  mac_merge_suggest: ['疑似同一设备换了 MAC', 'var(--orange)', uiSvg('merge')],
  mac_merge_auto: ['随机 MAC 无感自动继承', 'var(--green)', uiSvg('merge')],
  mac_merge_unmerge_auto: ['双胞胎同时在线 · 已自动拆分', 'var(--orange)', uiSvg('isolate')] };
function alertTitle(a) { return (ALERT_KIND[a.kind] || [a.kind || '告警'])[0]; }
function renderAlertsSheet(keep) {
  var list = (S.alerts.list || []).slice().sort(function (a, b) { return num(b.ts) - num(a.ts); });
  var html = '<h3>告警</h3><div class="sub">' + (list.length ? '未读 ' + S.alerts.unread + ' · 共 ' + list.length + ' 条' : '暂时没有告警') + '</div>' +
    (list.length ? '<div>' + list.slice(0, 60).map(function (a) {
      var k = ALERT_KIND[a.kind] || ['告警', 'var(--blue)'], d = a.mac ? devBy(a.mac) : null, nm = d ? d.name : (a.mac || '');
      var acts = '';
      if (a.kind === 'unknown_device' && a.mac) acts += '<button class="linkish" data-al="rename">起名</button><button class="linkish" data-al="known">认识它</button><button class="linkish danger" data-al="block">拉黑</button>';
      if (a.kind === 'mac_merge_suggest' && a.mac) acts += '<button class="linkish" data-al="merge">查看建议</button>';
      if (a.kind === 'mac_merge_auto' && a.mac) acts += '<button class="linkish" data-al="unmerge">拆分恢复</button>';
      if (!a.seen) acts += '<button class="linkish" data-al="seen">已读</button>';
      return '<div class="alrow' + (a.seen && !alertFresh[a.id] ? ' seen' : '') + '" data-alid="' + esc(a.id) + '" data-almac="' + esc(a.mac || '') + '"><i style="background:' + k[1] + '"></i><div style="min-width:0">' +
        '<div style="font-weight:700;font-size:14px">' + (k[2] ? '<span class="al-ic" style="color:' + k[1] + '">' + k[2] + '</span> ' : '') + esc(alertTitle(a)) + (nm ? ' · ' + esc(nm) : '') + '</div>' +
        '<div class="s">' + esc(a.detail || '') + (a.ip ? ' · ' + esc(a.ip) : '') + ' · ' + ago(a.ts) + '</div>' + (acts ? '<div class="acts">' + acts + '</div>' : '') + '</div></div>';
    }).join('') + '</div>' : '<div class="empty">' + uiSvg('check') + ' 一切正常</div>') +
    '<div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>关闭</button>' + (S.alerts.unread ? '<button class="btn pri press" id="al-all">全部已读</button>' : '') + '</div>';
  if (keep && $('#sheet').dataset.kind === 'alerts') { var y = $('#sheet').scrollTop; $('#sheet-body').innerHTML = html; $('#sheet').scrollTop = y; }
  else sheet(html, { kind: 'alerts', tall: true });
  var all = $('#al-all'); if (all) all.onclick = function () { api.action('alert_dismiss_all', {}).then(function () { toast('已全部标为已读'); return loadAlerts(); }).catch(function (e) { toast(errText(e), 'err'); }); };
}
var alertFresh = {};   // 打开面板时还未读的告警: 本次面板里保持高亮, 不因为自动标已读而立刻变灰
function openAlerts() {
  alertFresh = {}; S.alerts.list.forEach(function (a) { if (!a.seen) alertFresh[a.id] = 1; });
  renderAlertsSheet(false);
  loadAlerts().then(function () {
    setTimeout(function () {
      if ($('#sheet').dataset.kind !== 'alerts') return;
      var ids = S.alerts.list.filter(function (a) { return !a.seen; }).slice(0, 60).map(function (a) { return a.id; });
      if (ids.length) api.action('alert_mark_seen', { ids: ids.join(',') }).then(loadAlerts).catch(function () {});
    }, 800);
  });
}
function alertAction(kind, id, mac) {
  var d = devBy(mac) || { mac: mac, name: mac, ip: '' };
  var seen = function () { return api.action('alert_mark_seen', { ids: String(id) }).catch(function () {}); };
  var known = function () { return api.action('alert_mark_known', { mac: mac }).catch(function () {}); };
  if (kind === 'seen') return seen().then(loadAlerts);
  if (kind === 'merge') { var al = (S.alerts.list || []).filter(function (x) { return String(x.id) === String(id); })[0], ex = al && al.extra && typeof al.extra === 'object' ? al.extra : null; seen().then(loadAlerts); mergeSheet(mac, ex && ex.old_mac, ex); return; }
  if (kind === 'unmerge') {
    var alU = (S.alerts.list || []).filter(function (x) { return String(x.id) === String(id); })[0];
    var exU = alU && alU.extra && typeof alU.extra === 'object' ? alU.extra : null;
    seen().then(loadAlerts);
    if (typeof unmergeSheet === 'function') unmergeSheet(mac, (exU && (exU.old_mac || exU.from_mac)) || d.mergedFrom || '', (exU && exU.old_name) || d.mergedFromName || '');
    return;
  }
  if (kind === 'known') return Promise.all([known(), seen()]).then(function () { toast('已记为认识的设备'); return loadAlerts(); });
  if (kind === 'rename') { Promise.all([known(), seen()]).then(loadAlerts); renameSheet(mac, d.name === mac ? '' : d.name); return; }
  if (kind === 'block') {
    closeSheet(0);
    return blockDevice(d).then(function (ok) { if (ok) return Promise.all([seen(), known()]).then(loadAlerts); });
  }
}

/* v6 连接抽屉跟手下拉关闭与 Android 侧滑返回拦截 */
(function () {
  var dr = document.getElementById('v6-scalpel-drawer'), sc = document.getElementById('v6-scalpel-scrim'), ds = null;
  if (dr) {
    dr.addEventListener('pointerdown', function (e) {
      if (e.button != null && e.button !== 0) return;
      if (!dr.classList.contains('show')) return;
      var de = evEl(e);
      if (de && de.closest && de.closest('input, select, textarea, button, a')) return;
      var listEl = dr.querySelector('.v6-tuple-list');
      var onGrab = !!(de && de.closest && de.closest('.grab, .v6-drawer-head'));
      if (!onGrab && listEl && listEl.scrollTop > 2) return;
      ds = { id: e.pointerId, y0: e.clientY, dy: 0, drag: false, cap: false };
    });
    dr.addEventListener('pointermove', function (e) {
      if (!ds || e.pointerId !== ds.id) return;
      var dy = e.clientY - ds.y0;
      if (!ds.drag) {
        if (dy < 8) return;
        ds.drag = true;
        if (typeof dr.setPointerCapture === 'function') {
          try { dr.setPointerCapture(e.pointerId); ds.cap = true; } catch (_) {}
        }
        dr.style.transition = 'none';
        if (sc) sc.style.transition = 'none';
      }
      ds.dy = Math.max(0, dy);
      dr.style.transform = 'translate3d(-50%,' + ds.dy.toFixed(1) + 'px,0)';
      if (sc) sc.style.opacity = String(Math.max(0.15, 1 - ds.dy / 320));
    });
    var endDrag = function (e) {
      if (!ds || (e && e.pointerId != null && e.pointerId !== ds.id)) return;
      var wasDrag = ds.drag, dy = ds.dy, pid = ds.id, hadCap = ds.cap;
      ds = null;
      if (hadCap && typeof dr.releasePointerCapture === 'function') {
        try { if (!dr.hasPointerCapture || dr.hasPointerCapture(pid)) dr.releasePointerCapture(pid); } catch (_) {}
      }
      if (!wasDrag) return;
      dr.style.transition = '';
      dr.style.transform = '';
      if (sc) { sc.style.transition = ''; sc.style.opacity = ''; }
      if (dy > 68 && typeof closeScalpelDrawer === 'function') closeScalpelDrawer(false);
    };
    dr.addEventListener('pointerup', endDrag);
    dr.addEventListener('pointercancel', endDrag);
    dr.addEventListener('lostpointercapture', endDrag);
  }
  window.addEventListener('popstate', function () {
    if (window.__hncSkipNextPop) {
      if (typeof window.__hncSkipNextPop === 'number' && window.__hncSkipNextPop > 1) window.__hncSkipNextPop--;
      else window.__hncSkipNextPop = false;
      return;
    }
    var shEl = document.getElementById('sheet');
    if (shEl && shEl.classList.contains('show')) { closeSheet(0, true); return; }
    if (dr && dr.classList.contains('show') && typeof closeScalpelDrawer === 'function') closeScalpelDrawer(true);
  });
})();

/* ═════════════════════ v6.1.0-rc.1 一句话热点省电与健康体检单（按需拉取 · 平时 0 轮询） ═════════════════════ */
var QH_DEF_META = {
  hotspot_forward: { title: '热点连通与转发通路', icon: 'wifi', color: 'blue', target: 'scard-hs', targetLabel: '热点设置' },
  zero_wakeup_power: { title: '零唤醒待机与省电巡航', icon: 'bolt', color: 'green', target: 'pwr', targetLabel: '功耗自测' },
  shaping_offload: { title: '限速生效与防加速绕过', icon: 'shield', color: 'orange', target: 'scard-dpv', targetLabel: '限速检验' },
  tmpfs_config: { title: '内存空间与配置完整性', icon: 'cpu', color: 'purple', target: 'json-health', targetLabel: '配置健康' }
};
var QH_FIX_LABELS = {
  hotspot_start: '一键开启热点',
  restart_service: '一键重启恢复服务',
  self_studio_start: '关闭后台自训采样',
  dataplane_verify_run: '一键重下发修复限速',
  self_attrib_purge: '一键清理运行空间',
  json_doctor_repair: '一键修复损坏配置',
  refresh: '一键恢复网关转发',
  clsact_mode_set: '一键切为始终兜底',
  cache_clear: '一键释放运行空间'
};
function qhNormStatus(raw) {
  var s = String(raw || '').toLowerCase().trim();
  if (s === 'fail' || s === 'error' || s === 'bad' || s === 'critical') return 'fail';
  if (s === 'warn' || s === 'warning' || s === 'degraded' || s === 'bypass' || s === 'bypass_offload') return 'warn';
  if (s === 'unavailable' || s === 'unknown' || s === 'pending' || s === 'skipped' || s === 'n/a' || !s) return 'unavailable';
  if (s === 'info' || s === 'idle') return 'info';
  if (s === 'ok' || s === 'pass' || s === 'healthy' || s === 'good') return 'ok';
  return 'info';
}
function qhPickCards(r) {
  if (!r || typeof r !== 'object') return [];
  if (Array.isArray(r.cards)) return r.cards;
  if (Array.isArray(r.items)) return r.items;
  if (Array.isArray(r.checks)) return r.checks;
  if (Array.isArray(r.dimensions)) return r.dimensions;
  return [];
}
function qhParseActionSpec(specStr, extraParams) {
  var raw = String(specStr || '').trim();
  if (!raw) return null;
  var parts = raw.split(/\s+/).filter(Boolean);
  var act = parts[0] || '';
  if (!act || act.length > 48 || !/^[a-z][a-z0-9_]+$/.test(act)) return null;
  var p = {};
  if (extraParams && typeof extraParams === 'object') {
    Object.keys(extraParams).forEach(function (k) {
      if (extraParams[k] !== undefined && extraParams[k] !== null) p[k] = String(extraParams[k]);
    });
  }
  for (var i = 1; i < parts.length; i++) {
    var tok = parts[i], eqIdx = tok.indexOf('=');
    if (eqIdx > 0) p[tok.slice(0, eqIdx)] = tok.slice(eqIdx + 1);
    else if (act === 'self_studio_start' && !p.mode) p.mode = tok;
    else if (act === 'clsact_mode_set' && !p.mode) p.mode = tok;
  }
  if (act === 'self_studio_start' && !p.mode) p.mode = 'off';
  if (act === 'clsact_mode_set') {
    if (!p.mode || p.mode === 'always') p.mode = 'on';
  }
  if (act === 'dataplane_verify_run' && !p.resync) { p.resync = '1'; p.check_goroutineleak = '0'; }
  return { name: act, params: p };
}
function renderQuickHealthSheet(raw, keepScroll) {
  var sh = $('#sheet');
  var bodyHtml = '';
  if (!raw) {
    bodyHtml = '<h3>一句话省电与健康体检</h3>' +
      '<div class="sub">按需秒检热点转发、待机省电、限速生效与内存空间（平时 0 轮询）</div>' +
      '<div class="dbox" style="text-align:center;padding:24px 14px"><span class="spin" style="margin-right:8px;vertical-align:-2px"></span>正在读取实时健康状态…</div>' +
      '<div class="btns" style="margin-top:12px"><button type="button" class="btn sec wide press" data-close>关闭</button></div>';
  } else if (raw._err) {
    bodyHtml = '<h3>一句话省电与健康体检</h3>' +
      '<div class="sub">按需秒检热点转发、待机省电、限速生效与内存空间（平时 0 轮询）</div>' +
      '<div class="qh-hero is-warn">' +
        '<span class="qh-hero-ic">' + ico('warn') + '</span>' +
        '<div class="qh-hero-txt"><div class="qh-hero-t">暂未获取到实时体检结果</div><div class="qh-hero-s">' + esc(raw._err) + '</div></div>' +
      '</div>' +
      (S.refreshMode === 'realtime'
        ? '<div class="qh-card is-warn"><div class="qh-card-top"><span class="qh-card-l">' + gi('orange', 'bolt') + '<span>前台刷新模式耗电提示</span></span><span class="badge b-warn">可省电</span></div>' +
          '<div class="qh-card-sum">当前处于「实时刷新」高频模式</div><div class="qh-card-det">日常挂机使用建议切回「均衡刷新」，在保持流畅度的同时减少前台桥接唤醒。</div>' +
          '<div class="qh-card-acts"><button type="button" class="btn pri press" data-act="qh-set-balanced">一键切回均衡刷新</button></div></div>'
        : '') +
      '<div class="btns" style="margin-top:12px"><button type="button" class="btn sec press" data-act="qh-refresh">' + ico('refresh') + '<span>重试体检</span></button><button type="button" class="btn pri press" data-close>关闭</button></div>';
  } else {
    var cards = qhPickCards(raw);
    var hasExplicitOverall = Boolean(raw.overall || raw.status || raw.overall_status || raw.level || raw.grade);
    var worst = hasExplicitOverall ? qhNormStatus(raw.overall || raw.status || raw.overall_status || raw.level || raw.grade) : (cards.length ? 'ok' : 'unavailable');
    var rankOf = function (st) {
      return st === 'fail' ? 4 : (st === 'warn' ? 3 : (st === 'unavailable' ? 2 : (st === 'info' ? 1 : 0)));
    };
    if (!hasExplicitOverall && cards.length) {
      cards.forEach(function (c) {
        var cs = qhNormStatus(c && (c.status || c.level || c.state));
        if (rankOf(cs) > rankOf(worst)) worst = cs;
      });
    }
    var sumObj = raw.summary && typeof raw.summary === 'object' ? raw.summary : null;
    var defaultHeadline = worst === 'ok'
      ? '热点省电与限速状态一切健康，空闲自动零唤醒休眠'
      : (worst === 'fail'
        ? '发现影响上网或限速的异常项，可点击下方按钮一键修复'
        : (worst === 'warn'
          ? '热点运行正常，有部分省电或加速项可一键优化'
          : (worst === 'unavailable'
            ? '部分内核或系统状态暂不可读，已按中性提示如实展示'
            : '当前体检快照已就绪，可按提示查看各分项状态')));
    var headline = String(raw.headline || raw.one_liner || raw.summary_text || (typeof raw.summary === 'string' ? raw.summary : '') || (sumObj && (sumObj.headline || sumObj.text)) || defaultHeadline);
    var subline = String(raw.subline || raw.subtitle || raw.detail || (sumObj && sumObj.detail) || ('本机按需快照检测 · 平时后台 0 额外轮询' + (raw.checked_at ? ' · ' + ago(raw.checked_at) : '')));
    var heroCls = worst === 'fail' ? ' is-fail' : (worst === 'warn' ? ' is-warn' : '');
    var heroIc = worst === 'fail' ? 'warn' : (worst === 'warn' || worst === 'unavailable' || worst === 'info' ? 'info' : 'shield');
    var shownPowerBtn = false;

    var cardsHtml = cards.map(function (c, idx) {
      c = c || {};
      var cid = String(c.id || c.key || ('item_' + idx));
      var meta = QH_DEF_META[cid] || { title: '健康检查项', icon: 'check', color: 'blue', target: '', targetLabel: '查看详情' };
      var st = qhNormStatus(c.status || c.level || c.state);
      var isPowerCard = cid === 'zero_wakeup_power' || /省电|唤醒|功耗/.test(String(c.title || c.label || meta.title));
      if (isPowerCard && S.refreshMode === 'realtime' && st === 'ok') st = 'warn';
      var bdgCls = st === 'fail' ? 'b-red' : (st === 'warn' ? 'b-warn' : (st === 'unavailable' ? 'b-gray' : (st === 'info' ? 'b-acc' : 'b-ok')));
      var bdgTxt = String(c.status_label || c.badge || c.state_cn || (st === 'fail' ? '需修复' : st === 'warn' ? '可优化' : st === 'unavailable' ? '暂不可读' : st === 'info' ? '提示' : '健康'));
      var cTitle = String(c.title || c.label || c.name || meta.title);
      var cSum = String(c.verdict || c.summary || c.headline || c.value || c.text_cn || '');
      var cDet = String(c.detail || c.desc || c.message || c.reason || '');
      var fixRaw = String(c.fix_action || (c.fix && c.fix.action) || '').trim();
      var fixParams = (c.fix_params && typeof c.fix_params === 'object') ? c.fix_params : ((c.fix && typeof c.fix.params === 'object') ? c.fix.params : null);
      var spec = c.fix_kind === 'nav' ? null : qhParseActionSpec(fixRaw, fixParams);
      var fixLbl = String(c.fix_label || c.fix_text || (c.fix && c.fix.label) || (spec && QH_FIX_LABELS[spec.name]) || '一键修复');
      var jumpTo = String(c.jump_target || c.target || c.nav_target || meta.target || '');
      var jumpLbl = String((c.fix_kind === 'nav' && c.fix_label) ? c.fix_label : (c.jump_label || c.target_label || meta.targetLabel || '前往设置'));
      var acts = '';
      if (spec) {
        acts += '<button type="button" class="btn ' + (st === 'fail' ? 'dan' : 'pri') + ' press" data-qh-fix="' + esc(fixRaw) + '" data-qh-params="' + esc(fixParams ? JSON.stringify(fixParams) : '') + '">' + ico('tool') + '<span>' + esc(fixLbl) + '</span></button>';
      }
      if (isPowerCard && S.refreshMode === 'realtime') {
        shownPowerBtn = true;
        acts += '<button type="button" class="btn pri press" data-act="qh-set-balanced">' + ico('bolt') + '<span>一键切回均衡刷新</span></button>';
      }
      if (jumpTo) {
        acts += '<button type="button" class="btn sec press" data-qh-jump="' + esc(jumpTo) + '"><span>' + esc(jumpLbl) + '</span>' + ico('right') + '</button>';
      }
      var giCol = st === 'fail' ? 'red' : (st === 'warn' ? 'orange' : (st === 'unavailable' ? 'gray' : (st === 'ok' ? 'green' : meta.color)));
      var iconKey = st === 'unavailable' ? 'info' : meta.icon;
      return '<div class="qh-card' + (st === 'fail' ? ' is-fail' : st === 'warn' ? ' is-warn' : '') + '" data-qh-id="' + esc(cid) + '">' +
        '<div class="qh-card-top"><span class="qh-card-l">' + gi(giCol, iconKey) + '<span>' + esc(cTitle) + '</span></span><span class="badge ' + bdgCls + '">' + esc(bdgTxt) + '</span></div>' +
        (cSum ? '<div class="qh-card-sum">' + esc(cSum) + '</div>' : '') +
        (cDet ? '<div class="qh-card-det">' + esc(cDet) + '</div>' : '') +
        (isPowerCard && S.refreshMode === 'realtime' ? '<div class="qh-card-det" style="color:var(--badge-warn)">当前前台处于「实时刷新」档位，切回「均衡刷新」可进一步降低亮屏轮询开销。</div>' : '') +
        (acts ? '<div class="qh-card-acts">' + acts + '</div>' : '') +
      '</div>';
    }).join('');

    if (!shownPowerBtn && S.refreshMode === 'realtime') {
      cardsHtml += '<div class="qh-card is-warn" data-qh-id="realtime_mode_hint">' +
        '<div class="qh-card-top"><span class="qh-card-l">' + gi('orange', 'bolt') + '<span>前台轮询省电建议</span></span><span class="badge b-warn">可省电</span></div>' +
        '<div class="qh-card-sum">当前设备页为「实时刷新」高频档位</div>' +
        '<div class="qh-card-det">切回「均衡刷新」后按在线状态智能降频，日常看管更省电。</div>' +
        '<div class="qh-card-acts"><button type="button" class="btn pri press" data-act="qh-set-balanced">' + ico('bolt') + '<span>一键切回均衡刷新</span></button></div>' +
      '</div>';
    }

    bodyHtml = '<h3>一句话省电与健康体检</h3>' +
      '<div class="sub">按需秒检热点转发、待机省电、限速生效与内存空间（平时 0 轮询）</div>' +
      '<div class="qh-hero' + heroCls + '">' +
        '<span class="qh-hero-ic">' + ico(heroIc) + '</span>' +
        '<div class="qh-hero-txt"><div class="qh-hero-t">' + esc(headline) + '</div><div class="qh-hero-s">' + esc(subline) + '</div></div>' +
      '</div>' +
      '<div class="qh-list">' + (cardsHtml || '<div class="empty">暂无体检分项明细</div>') + '</div>' +
      '<div class="btns" style="margin-top:12px"><button type="button" class="btn sec press" data-act="qh-refresh">' + ico('refresh') + '<span>重新体检</span></button><button type="button" class="btn pri press" data-close>完成</button></div>';
  }

  if (keepScroll && sh && sh.classList.contains('show') && sh.dataset.kind === 'quick-health') {
    var topY = sh.scrollTop;
    $('#sheet-body').innerHTML = bodyHtml;
    sh.scrollTop = topY;
  } else {
    sheet(bodyHtml, { kind: 'quick-health', tall: true });
  }
}
function openQuickHealthSheet(forceRefresh) {
  var isOpen = $('#sheet') && $('#sheet').classList.contains('show') && $('#sheet').dataset.kind === 'quick-health';
  if (!forceRefresh && S.quickHealth && !S.quickHealth._err && isOpen) {
    renderQuickHealthSheet(S.quickHealth, true);
  } else if (!isOpen) {
    renderQuickHealthSheet(S.quickHealth && !forceRefresh ? S.quickHealth : null, false);
  }
  return api.get('/api/health_check', forceRefresh ? { refresh: 1 } : null, { timeout: 12000 }).then(function (r) {
    S.quickHealth = r || {};
    if ($('#sheet') && $('#sheet').classList.contains('show') && $('#sheet').dataset.kind === 'quick-health') {
      renderQuickHealthSheet(S.quickHealth, true);
    }
    if (S.page === 'settings' && typeof renderSettings === 'function') renderSettings(false);
    return S.quickHealth;
  }).catch(function (e) {
    var errObj = { _err: errText(e) };
    if ($('#sheet') && $('#sheet').classList.contains('show') && $('#sheet').dataset.kind === 'quick-health') {
      renderQuickHealthSheet(errObj, true);
    } else {
      toast('体检读取失败：' + errText(e), 'err');
    }
    return errObj;
  });
}
function execQuickHealthFix(fixActRaw, fixParamsObj, btnEl) {
  var parsedParams = fixParamsObj;
  if (typeof fixParamsObj === 'string' && fixParamsObj) {
    try { parsedParams = JSON.parse(fixParamsObj); } catch (_) { parsedParams = null; }
  }
  var spec = qhParseActionSpec(fixActRaw, parsedParams);
  if (!spec) { toast('不支持的修复动作', 'err'); return Promise.resolve(false); }
  var runChain = function () {
    return api.action(spec.name, spec.params).then(function (res) {
      if (spec.name === 'self_attrib_purge') {
        return api.action('cache_clear', {}).catch(function () {}).then(function () { return res; });
      }
      if (spec.name === 'cache_clear') {
        return api.action('self_attrib_purge', {}).catch(function () {}).then(function () { return res; });
      }
      return res;
    });
  };
  var p = btnEl && typeof busyWhile === 'function' ? busyWhile(btnEl, runChain()) : runChain();
  return p.then(function (res) {
    var okTxt = (QH_FIX_LABELS[spec.name] || '修复操作') + '已执行';
    if (res && res.detail && typeof res.detail === 'string' && res.detail.length < 60 && res.detail.charAt(0) !== '{') okTxt += ' · ' + res.detail;
    toast(okTxt);
    var waitMs = spec.name === 'restart_service' ? 2200 : (spec.name === 'hotspot_start' ? 1500 : 250);
    return new Promise(function (resolve) {
      setTimeout(function () {
        Promise.all([
          api.get('/api/health_check', { refresh: 1 }, { timeout: 12000 }).then(function (hr) {
            S.quickHealth = hr || {};
            if ($('#sheet') && $('#sheet').classList.contains('show') && $('#sheet').dataset.kind === 'quick-health') {
              renderQuickHealthSheet(S.quickHealth, true);
            }
          }).catch(function () {}),
          typeof loadLive === 'function' ? loadLive().catch(function () {}) : Promise.resolve(),
          typeof loadConfig === 'function' ? loadConfig().catch(function () {}) : Promise.resolve()
        ]).then(function () {
          if (S.page === 'settings' && typeof renderSettings === 'function') renderSettings(false);
          else if (S.page === 'devices' && typeof renderDevices === 'function') renderDevices(false);
          resolve(true);
        });
      }, waitMs);
    });
  }).catch(function (e) {
    toast(errText(e), 'err');
    return false;
  });
}
function jumpQuickHealthTarget(target, cardId) {
  var t = String(target || '').trim();
  var cid = String(cardId || '').trim();
  closeSheet(0);
  if (!t) return;
  if (t === 'json-health' || t === 'json_health') { location.href = 'json-health.html'; return; }
  if (t === 'devices') { if (typeof go === 'function') go('devices'); return; }
  if (t === 'vector') { if (typeof go === 'function') go('vector'); return; }
  if (t === 'stats') {
    var isPowerJump = cid === 'zero_wakeup_power' || (!cid && S && S.quickHealth && qhPickCards(S.quickHealth).some(function (x) {
      return x && x.id === 'zero_wakeup_power' && (x.nav_target === 'stats' || x.target === 'stats');
    }));
    if (isPowerJump) {
      S.setLv = 'all'; S.open['scard-maint'] = true; S.open.pwr = true;
      if (typeof go === 'function') go('settings');
      if (typeof renderSettings === 'function') renderSettings(false);
      if (typeof loadPower === 'function') loadPower(false);
    } else {
      if (typeof go === 'function') go('stats');
    }
    return;
  }
  if (t === 'settings') {
    S.setLv = 'all'; S.open['scard-diag'] = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
    return;
  }
  if (t === 'dpi-studio' || t === 'self_studio') {
    S.aseg = 'dpi';
    if (typeof go === 'function') go('stats');
    if (typeof renderStats === 'function') renderStats(false);
    return;
  }
  if (t === 'hotspot' || t === 'hotspot_forward' || t === 'scard-hs') {
    S.setLv = 'all'; S.open['scard-hs'] = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
    return;
  }
  if (t === 'power' || t === 'pwr' || t === 'zero_wakeup_power' || t === 'scard-maint' || t === 'tmpfs_config' || t === 'maint') {
    S.setLv = 'all'; S.open['scard-maint'] = true;
    if (t === 'power' || t === 'pwr' || t === 'zero_wakeup_power') S.open.pwr = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
    if (S.open.pwr && typeof loadPower === 'function') loadPower(false);
    return;
  }
  if (t === 'dpv' || t === 'shaping_offload' || t === 'scard-dpv' || t === 'offload') {
    S.setLv = 'all'; S.open['scard-dpv'] = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
    if (typeof dpvLoadSilent === 'function') dpvLoadSilent();
    return;
  }
  if (t === 'guard' || t === 'scard-guard') {
    S.setLv = 'all'; S.open['scard-guard'] = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
    return;
  }
  if (t.indexOf('scard-') === 0) {
    S.setLv = 'all'; S.open[t] = true;
    if (typeof go === 'function') go('settings');
    if (typeof renderSettings === 'function') renderSettings(false);
  }
}

