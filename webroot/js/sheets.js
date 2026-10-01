/* HNC WebUI · sheets.js —— 弹层: 打开/关闭(苹果风弹簧 + 共享元素展开)、跟手下拉、确认框、告警列表 */
'use strict';

var sheetOnClose = null;

function sheetOpenFx(already) {
  var sh = $('#sheet');
  if (!appleSheet()) return false;
  sh.style.transition = 'none'; SM.closing = false; sh.classList.remove('closing');
  SM.h = sh.offsetHeight || 600;
  if (!SM.open) bgOrigins();
  SM.open = true;
  var mor = !already && fxOn('morph') && !lowFx() && morphFrom();
  if (mor) { shSpring.set(0); morphSheet(sh, mor); }
  else if (already && !shSpring.raf) shSpring.set(0);
  else { if (!shSpring.raf && !already) shSpring.set(SM.h + 40); shSpring.go(0, null, springP()); }
  if (!lowFx()) bgSpring.go(1, null, springP()); else { bgSpring.set(0); $('#scrim').style.opacity = ''; }
  return true;
}
function sheetCloseFx(v) {
  var sh = $('#sheet');
  if (!SM.open || !appleSheet()) { SM.open = false; return false; }
  SM.open = false; SM.closing = true; sh.classList.add('closing');
  shSpring.go((SM.h || sh.offsetHeight) + 40, v || 0, springP());
  bgSpring.go(0, v ? -v / (SM.h || 600) : null, SPRING.light);
  return true;
}
/* 共享元素展开: 记下刚点的那一行/卡片, 600ms 内打开的弹层从它的位置和大小"长"出来(裁剪 + 位移, 内容不变形) */
var lastTap = null;
document.addEventListener('pointerdown', function (e) {
  // 取离手指最近的可点元素(按钮 / 行 / 卡片), 不要一路找到整个分组卡片
  var el = e.target.closest && e.target.closest('.chip, .btn, .cn, .dg, .row, .sni-row, .client, .dev-h, [data-act], .dev, .glass');
  if (!el || el.closest('#sheet') && !el.closest('.cn, .row, .dg, .btn')) { lastTap = null; return; }
  var r = el.getBoundingClientRect(); lastTap = { r: r, t: performance.now(), rad: parseFloat(getComputedStyle(el).borderRadius) || 12 };
}, true);
function morphFrom() { return lastTap && performance.now() - lastTap.t < 650 && lastTap.r.width > 20 ? lastTap : null; }
function morphSheet(sh, from) {
  var fr = sh.getBoundingClientRect(), s = from.r, dy = s.top - fr.top;
  var l = Math.max(0, s.left - fr.left), rgt = Math.max(0, fr.right - s.right), b = Math.max(0, fr.height - s.height);
  var a = anim(sh, [
    { transform: 'translate(-50%,' + dy.toFixed(1) + 'px)', clipPath: 'inset(0 ' + rgt.toFixed(1) + 'px ' + b.toFixed(1) + 'px ' + l.toFixed(1) + 'px round ' + from.rad + 'px)' },
    { transform: 'translate(-50%,0)', clipPath: 'inset(0 0 0 0 round 14px 14px 0 0)' }
  ], { duration: 450, easing: EASE.q });
  anim($('#sheet-body'), [{ opacity: 0 }, { opacity: 1 }], { duration: 260, delay: 90, easing: 'ease-out', fill: 'backwards' });
  lastTap = null;
  return a;
}
function sheet(html, opt) {
  opt = opt || {};
  var sh = $('#sheet'); sh.classList.toggle('tall', !!opt.tall); sh.dataset.kind = opt.kind || '';
  $('#sheet-body').innerHTML = html; sheetOnClose = opt.onClose || null;
  var already = sh.classList.contains('show') && !SM.closing;
  $('#scrim').classList.add('show'); sh.classList.add('show'); sh.scrollTop = 0;
  placeSegs(sh);
  if (!sheetOpenFx(already) && already) anim($('#sheet-body'), [{ opacity: 0 }, { opacity: 1 }], { duration: 220, easing: 'ease-out' });
  else if (already && apple()) anim($('#sheet-body'), [{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }], { duration: 260, easing: 'ease-out' });
  return sh;
}
function closeSheet(v) {
  $('#scrim').classList.remove('show'); var sh = $('#sheet'); sh.classList.remove('show'); sh.dataset.kind = '';
  sheetCloseFx(typeof v === 'number' ? v : 0);
  var f = sheetOnClose; sheetOnClose = null; if (f) try { f(); } catch (_) {}
}
$('#scrim').addEventListener('click', closeSheet);
/* 弹层下拉关闭 —— 在弹层已滚到顶部时往下拖, 超过 90px(或快速下甩)松手即关闭 */
(function () {
  var sh = $('#sheet'), st = null;
  sh.addEventListener('touchstart', function (e) {
    if (!sh.classList.contains('show') || sh.scrollTop > 0 || e.touches.length !== 1) return;
    if (e.target.closest('input,textarea,select,.seg,.toggle')) return;
    st = { y: e.touches[0].clientY, t: Date.now(), dy: 0, ly: e.touches[0].clientY, lt: performance.now(), v: 0, js: appleSheet() && SM.open };
    if (st.js) { shSpring.stop(); bgSpring.stop(); }
  }, { passive: true });
  sh.addEventListener('touchmove', function (e) {
    if (!st) return;
    var cy = e.touches[0].clientY, now = performance.now();
    st.v = st.v * .3 + (cy - st.ly) / Math.max(1, now - st.lt) * 1000 * .7; st.ly = cy; st.lt = now;   // 手指速度 px/s(平滑)
    st.dy = cy - st.y;
    if (st.dy <= 0 || sh.scrollTop > 0) { if (st.dy < -4) { var wasJs = st.js; st = null; if (wasJs) { shSpring.go(0, null, springP()); bgSpring.go(1, null, springP()); } else { sh.style.transform = ''; sh.style.transition = ''; } } return; }
    if (st.js) {   // 苹果风 —— 背景缩放 / 遮罩随拖动距离联动
      shSpring.set(st.dy); if (!lowFx()) bgSpring.set(Math.max(0, 1 - st.dy / (SM.h || 600)));
    } else {
      sh.style.transition = 'none';
      sh.style.transform = 'translate(-50%,' + Math.round(st.dy) + 'px)';
    }
    if (e.cancelable) e.preventDefault();
  }, { passive: false });
  function end() {
    if (!st) return;
    var fast = st.dy > 30 && st.dy / Math.max(1, Date.now() - st.t) > .6, far = st.dy > 90;
    if (st.js) {
      var v = performance.now() - st.lt < 90 ? st.v : 0, jsFast = v > 600 && st.dy > 20;
      st = null;
      if (far || fast || jsFast) closeSheet(Math.max(v, 0));
      else { shSpring.go(0, v, springP()); if (!lowFx()) bgSpring.go(1, -v / (SM.h || 600), springP()); }
      return;
    }
    st = null; sh.style.transition = ''; sh.style.transform = '';
    if (far || fast) closeSheet();
  }
  sh.addEventListener('touchend', end); sh.addEventListener('touchcancel', end);
})();
$('#sheet').addEventListener('click', function (e) { if (e.target.closest('[data-close]')) closeSheet(); });
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeSheet(); closeDD(); } });
function confirmSheet(title, desc, okText, opt) {
  opt = opt || {};
  return new Promise(function (resolve) {
    var settled = false;
    sheet('<h3>' + esc(title) + '</h3><div class="sub">' + desc + '</div>' + (opt.extra || '') +
      '<div class="btns"><button class="btn sec press" data-close>取消</button><button class="btn ' + (opt.safe ? 'pri' : 'dan') + ' press" id="cf-ok">' + esc(okText || '确定') + '</button></div>',
      { onClose: function () { if (!settled) { settled = true; resolve(false); } } });
    $('#cf-ok').onclick = function () { var extra = opt.read ? opt.read() : true; settled = true; closeSheet(); resolve(extra); };
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
var ALERT_KIND = { unknown_device: ['新设备接入', 'var(--orange)', '📶'], anomaly_traffic: ['流量异常', 'var(--red)', '📈'], monthly_quota: ['月度配额', 'var(--purple)', '📊'],
  device_quota: ['设备超出流量配额', 'var(--red)', '🚦'], phone_quota: ['本机流量套餐', 'var(--orange)', '📱'], app_time_warn: ['应用时长快用完', 'var(--orange)', '⏳'], app_time_exhausted: ['应用时长已用完', 'var(--red)', '⌛'],
  mac_merge_suggest: ['疑似同一设备换了 MAC', 'var(--orange)', '🔀'] };
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
        '<div style="font-weight:700;font-size:14px">' + (k[2] ? k[2] + ' ' : '') + esc(alertTitle(a)) + (nm ? ' · ' + esc(nm) : '') + '</div>' +
        '<div class="s">' + esc(a.detail || '') + (a.ip ? ' · ' + esc(a.ip) : '') + ' · ' + ago(a.ts) + '</div>' + (acts ? '<div class="acts">' + acts + '</div>' : '') + '</div></div>';
    }).join('') + '</div>' : '<div class="empty">一切正常 ✓</div>') +
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
    closeSheet();
    return blockDevice(d).then(function (ok) { if (ok) return Promise.all([seen(), known()]).then(loadAlerts); });
  }
}

