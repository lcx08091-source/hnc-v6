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
  var el = e.target.closest && e.target.closest('.chip, .btn, .cn, .dg, .row, .sni-row, .client, .dev-h, .cc-tile, [data-act], .dev, .glass');
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

function sheet(html, opt) {
  opt = opt || {};
  var sh = $('#sheet'); sh.classList.toggle('tall', !!opt.tall); sh.dataset.kind = opt.kind || '';
  var already = sh.classList.contains('show') && !SM.closing;
  var prevClose = sheetOnClose; sheetOnClose = null;
  if (already && prevClose) { try { prevClose(); } catch (_) {} }
  $('#sheet-body').innerHTML = html; sheetOnClose = opt.onClose || null;
  $('#scrim').classList.add('show'); sh.classList.add('show'); sh.scrollTop = 0;
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

function closeSheet(v) {
  if ($('#sheet').classList.contains('show')) sheetCloseAt = performance.now();
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
    if (e.target.closest('input,textarea,select,.seg,.toggle,[data-lcc-track]')) return;
    var onGrab = !!(e.target.closest && e.target.closest('.grab'));
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
    var grab = e.target.closest && e.target.closest('.grab');
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

$('#sheet').addEventListener('click', function (e) { if (e.target.closest('[data-close]')) closeSheet(0); });
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
  mac_merge_suggest: ['疑似同一设备换了 MAC', 'var(--orange)', uiSvg('merge')] };
function alertTitle(a) { return (ALERT_KIND[a.kind] || [a.kind || '告警'])[0]; }
function renderAlertsSheet(keep) {
  var list = (S.alerts.list || []).slice().sort(function (a, b) { return num(b.ts) - num(a.ts); });
  var html = '<h3>告警</h3><div class="sub">' + (list.length ? '未读 ' + S.alerts.unread + ' · 共 ' + list.length + ' 条' : '暂时没有告警') + '</div>' +
    (list.length ? '<div>' + list.slice(0, 60).map(function (a) {
      var k = ALERT_KIND[a.kind] || ['告警', 'var(--blue)'], d = a.mac ? devBy(a.mac) : null, nm = d ? d.name : (a.mac || '');
      var acts = '';
      if (a.kind === 'unknown_device' && a.mac) acts += '<button class="linkish" data-al="rename">起名</button><button class="linkish" data-al="known">认识它</button><button class="linkish danger" data-al="block">拉黑</button>';
      if (a.kind === 'mac_merge_suggest' && a.mac) acts += '<button class="linkish" data-al="merge">查看建议</button>';
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
      if (e.target.closest('input, select, textarea, button, a')) return;
      var listEl = dr.querySelector('.v6-tuple-list');
      var onGrab = !!e.target.closest('.grab, .v6-drawer-head');
      if (!onGrab && listEl && listEl.scrollTop > 2) return;
      ds = { id: e.pointerId, y0: e.clientY, dy: 0, drag: false };
    });
    dr.addEventListener('pointermove', function (e) {
      if (!ds || e.pointerId !== ds.id) return;
      var dy = e.clientY - ds.y0;
      if (!ds.drag) {
        if (dy < 8) return;
        ds.drag = true;
        dr.style.transition = 'none';
        if (sc) sc.style.transition = 'none';
      }
      ds.dy = Math.max(0, dy);
      dr.style.transform = 'translate3d(-50%,' + ds.dy.toFixed(1) + 'px,0)';
      if (sc) sc.style.opacity = String(Math.max(0.15, 1 - ds.dy / 320));
    });
    var endDrag = function (e) {
      if (!ds || (e && e.pointerId != null && e.pointerId !== ds.id)) return;
      var wasDrag = ds.drag, dy = ds.dy;
      ds = null;
      if (!wasDrag) return;
      dr.style.transition = '';
      dr.style.transform = '';
      if (sc) { sc.style.transition = ''; sc.style.opacity = ''; }
      if (dy > 68 && typeof closeScalpelDrawer === 'function') closeScalpelDrawer();
    };
    dr.addEventListener('pointerup', endDrag);
    dr.addEventListener('pointercancel', endDrag);
  }
  window.addEventListener('popstate', function () {
    var shEl = document.getElementById('sheet');
    if (shEl && shEl.classList.contains('show')) { closeSheet(0); return; }
    if (dr && dr.classList.contains('show') && typeof closeScalpelDrawer === 'function') closeScalpelDrawer(true);
  });
})();
