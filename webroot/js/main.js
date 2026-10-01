/* HNC WebUI · main.js —— 页面切换、底栏液态玻璃透镜、主题切换、事件委托、轮询、启动(最后加载) */
'use strict';

/* ═════════════════════ 页面切换(方向感知 + 弹簧) ═════════════════════ */
var ORDER = ['devices', 'apps', 'stats', 'settings'];
var RENDER = { devices: renderDevices, apps: renderApps, stats: renderStats, settings: renderSettings };
function onEnter(name) {
  if (name === 'devices') { paintHero(true); loadOnlineHours(); loadUsage(); }
  if (name === 'apps') loadApps().then(function () { if (S.page === 'apps') renderApps(false); });
  if (name === 'settings') loadSettingsData().then(function () { if (S.page === 'settings') renderSettings(false); if (S.cfg.clsact_bpf_mode === 'on' && !S.clsact) clsactCheck(true); });
  schedulePoll(50);
}
function go(name) {
  if (ORDER.indexOf(name) < 0) return;
  if (name === S.page) { $('#p-' + name).scrollTo({ top: 0, behavior: 'smooth' }); syncTab(name); return; }
  var from = $('#p-' + S.page), to = $('#p-' + name), dir = ORDER.indexOf(name) > ORDER.indexOf(S.page) ? 1 : -1;
  S.page = name; closeDD(); syncTab(name); LS.set('hnc6.page', name); navSync();
  // 标签切换不再用 View Transitions —— 它要先给整个页面区拍快照, 拍照期间渲染冻结(真机上就是
  // 一段空白), 快照层还在最上层, 会把底栏盖掉一半。iOS 的标签切换本来也不是"推入", 而是原地快速换内容。
  // 现在: 新页面立刻可见(不透明度从 .35 起, 不会出现整屏空白), 旧页面立刻隐藏(不再两页叠着渲染)。
  to.classList.add('on'); from.classList.remove('on');
  RENDER[name](true);
  if (fxOn('page') && motionOn()) {
    if (apple()) anim(to, [{ opacity: .35, transform: 'scale(.985)' }, { opacity: 1, transform: 'none' }], { duration: 260, easing: 'cubic-bezier(.2,.8,.2,1)' });
    else anim(to, [{ opacity: .3, transform: 'translateX(' + (dir * 28) + 'px) scale(.985)' }, { opacity: 1, transform: 'none' }], { duration: 420, easing: EASE.soft });
  }
  onEnter(name);
}

/* ═════════════════════ 底栏: 液态玻璃透镜 + 弹簧物理 ═════════════════════ */
var TABS = [['devices', '设备', 'dev'], ['apps', '应用', 'apps'], ['stats', '分析', 'stats'], ['settings', '设置', 'gear']];
var tabsHtml = TABS.map(function (t) { return '<div class="tab" data-tab="' + t[0] + '">' + ico(t[2]) + t[1] + (t[0] === 'apps' ? '<span class="dot" hidden></span>' : '') + '</div>'; }).join('');
$('#tabs').innerHTML = tabsHtml; $('#lens-in').innerHTML = tabsHtml;
var bar = $('#tabbar'), lens = $('#lens'), lensIn = $('#lens-in'), tabsEl = $('#tabs');
var L = { x: 0, v: 0, tx: 0, s: 1, sv: 0, ts: 1, drag: false, raf: 0, last: 0, gx: 0, moved: 0, fx0: 0, fx: 0, ft: 0, fv: 0 };
function slotW() { return tabsEl.clientWidth / TABS.length; }
function layoutLens() { var w = slotW(); lens.style.width = w + 'px'; lensIn.style.width = (w * TABS.length) + 'px'; }
function paintLens() {
  var w = slotW(), sp = Math.min(Math.abs(L.v) / 2600, .22);
  var sxs = L.s * (1 + sp), sys = L.s * (1 - sp * .55), mag = 1 + (L.s - 1) * .8, cx = L.x + w / 2;
  lens.style.transform = 'translateX(' + L.x.toFixed(2) + 'px) scale(' + sxs.toFixed(4) + ',' + sys.toFixed(4) + ')';
  lensIn.style.transformOrigin = cx.toFixed(1) + 'px 50%';
  lensIn.style.transform = 'translateX(' + (-L.x).toFixed(2) + 'px) scale(' + (mag / sxs).toFixed(4) + ',' + (mag / sys).toFixed(4) + ')';
  tabsEl.style.setProperty('--ml', (cx - w * sxs / 2 + 3).toFixed(1) + 'px');
  tabsEl.style.setProperty('--mr', (cx + w * sxs / 2 - 3).toFixed(1) + 'px');
}
function stepLens(t) {
  var dt = L.last ? Math.min(.032, (t - L.last) / 1000) : .016; L.last = t;
  var k = L.drag ? 900 : 360, c = L.drag ? 52 : 19, n = 4, h = dt / n;   // 拖动时紧跟手指; 松手后欠阻尼, 冲过头再弹回
  for (var i = 0; i < n; i++) {
    L.v += (-k * (L.x - L.tx) - c * L.v) * h; L.x += L.v * h;
    L.sv += (-560 * (L.s - L.ts) - 17 * L.sv) * h; L.s += L.sv * h;
  }
  // 松手后回弹不越过首尾标签超过 6px(此前切到最左/最右时透镜会冲出底栏约 30px), 撞边轻弹回
  if (!L.drag) {
    var mxL = (TABS.length - 1) * slotW();
    if (L.x < -6) { L.x = -6; if (L.v < 0) L.v = -L.v * .25; }
    else if (L.x > mxL + 6) { L.x = mxL + 6; if (L.v > 0) L.v = -L.v * .25; }
  }
  paintLens();
  if (!L.drag && Math.abs(L.x - L.tx) < .3 && Math.abs(L.v) < 4 && Math.abs(L.s - L.ts) < .002 && Math.abs(L.sv) < .02) { L.x = L.tx; L.v = 0; L.s = L.ts; L.sv = 0; paintLens(); L.raf = 0; L.last = 0; return; }
  L.raf = requestAnimationFrame(stepLens);
}
function kick() { if (!motionOn()) { L.x = L.tx; L.s = L.ts; L.v = L.sv = 0; paintLens(); return; } if (!L.raf) { L.last = 0; L.raf = requestAnimationFrame(stepLens); } }
function idxAt(x) { return clamp(Math.round(x / slotW()), 0, TABS.length - 1); }
function localX(e) { var r = bar.getBoundingClientRect(); return e.clientX - r.left - 6 - slotW() / 2; }
bar.addEventListener('pointerdown', function (e) {
  try { bar.setPointerCapture(e.pointerId); } catch (_) {}
  var x = localX(e), w = slotW();
  L.drag = true; L.moved = 0; L.fx0 = L.fx = x; L.ft = performance.now(); L.fv = 0;
  L.gx = Math.abs(x - L.x) < w * .5 ? L.x - x : 0;   // 按在透镜上 → 抓住它; 按在别处 → 透镜先弹过去
  L.tx = clamp(x + L.gx, 0, (TABS.length - 1) * w); L.ts = 1.18;
  bar.classList.add('drag'); kick();
});
bar.addEventListener('pointermove', function (e) {
  if (!L.drag) return;
  var w = slotW(), fx = localX(e), raw = fx + L.gx, max = (TABS.length - 1) * w;
  // 手指速度(指数平滑), 松手时的惯性用它 —— 不能用透镜自身的弹簧速度
  var now = performance.now(), dt = Math.max(1, now - L.ft);
  L.fv = L.fv * .4 + (fx - L.fx) / dt * 1000 * .6; L.fx = fx; L.ft = now;
  L.moved = Math.max(L.moved, Math.abs(fx - L.fx0));
  if (raw < 0) raw = -Math.pow(-raw, .7); else if (raw > max) raw = max + Math.pow(raw - max, .7);   // 边缘橡皮筋
  var prev = idxAt(L.tx); L.tx = raw;
  if (idxAt(raw) !== prev && navigator.vibrate) try { navigator.vibrate(6); } catch (_) {}
  kick();
});
function releaseLens(e) {
  if (!L.drag) return;
  L.drag = false; bar.classList.remove('drag');
  // 此前用透镜自身的弹簧速度算惯性 —— 轻点时透镜正以 1000~2200px/s 冲向目标,
  // 抬手瞬间被当成"甩"多滑一格: 在设备点应用跳到分析、在设置点应用跳到设备(点得越快越容易)。
  // 现在: 轻点(手指移动 <8px)直接去手指下面的标签; 拖动才用手指速度算惯性, 且最多多滑半格。
  var w = slotW(), i;
  if (L.moved < 8) i = idxAt(e && e.clientX != null && e.type !== 'pointercancel' ? localX(e) : L.fx);
  else {
    // 只有真正"甩"(手指 >700px/s 且刚动过)才加惯性; 正常速度拖到哪就停哪
    var fv = performance.now() - L.ft < 120 ? L.fv : 0, af = Math.abs(fv);
    var fling = af > 700 ? (fv > 0 ? 1 : -1) * Math.min(w * .5, (af - 700) * .06) : 0;
    i = idxAt(L.tx + fling);
  }
  L.tx = i * slotW(); L.ts = 1; L.sv -= 2.6;   // 松手瞬间"啵"地缩一下再弹回
  kick(); go(TABS[i][0]);
}
bar.addEventListener('pointerup', releaseLens);
bar.addEventListener('pointercancel', releaseLens);
function syncTab(name, instant) { L.tx = ORDER.indexOf(name) * slotW(); if (instant) { L.x = L.tx; paintLens(); } else kick(); }

/* ═════════════════════ 主题(圆形扩散) ═════════════════════ */
function setStyle(v, x, y) {
  S.style = v === 'apple' || v === 'liquid' ? v : 'default'; LS.set('hnc6.style', S.style);
  revealApply(function () { applyTheme(); if (typeof navSync === 'function') navSync(); }, x, y);
  $$('[data-style-pick]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-style-pick') === S.style); });
  setTimeout(function () { placeSegs(); layoutLens(); syncTab(S.page, true); }, 60);
}
function setTheme(t, x, y) {
  S.theme = t; LS.set('hnc6.theme', t);
  revealApply(applyTheme, x, y);
  $$('[data-theme-pick]').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-theme-pick') === t); });
}
// 圆形扩散切换(主题 / 界面风格共用)
function revealApply(fn, x, y) {
  if (document.startViewTransition && motionOn() && x != null) {
    var r = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    var vt = document.startViewTransition(fn);
    vt.ready.then(function () {
      document.documentElement.animate({ clipPath: ['circle(0px at ' + x + 'px ' + y + 'px)', 'circle(' + r + 'px at ' + x + 'px ' + y + 'px)'] },
        { duration: 600, easing: 'cubic-bezier(.4,0,.2,1)', fill: 'forwards', pseudoElement: '::view-transition-new(root)' });
    }).catch(function () {});
    setTimeout(function () { try { vt.skipTransition(); } catch (_) {} }, 1200);   // 保险: 个别 WebView 卡住时强制结束
  } else fn();
}
function isDark() { var a = document.documentElement.getAttribute('data-theme'); return a === 'dark' || (!a && matchMedia('(prefers-color-scheme: dark)').matches); }
$('#theme-btn').addEventListener('click', function (e) { setTheme(isDark() ? 'light' : 'dark', e.clientX, e.clientY); });
$('#bell').addEventListener('click', openAlerts);

/* ═════════════════════ 事件委托 ═════════════════════ */
function foldToggle(el, key) {
  if (!el) return;
  var on = !el.classList.contains('open'); el.classList.toggle('open', on); S.open[key] = on;
  if (on) { placeSegs(el); anim(el, [{ transform: 'scale(.985)' }, { transform: 'none' }], { duration: 650 }); }
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
    $$('button', sg).forEach(function (b) { b.classList.toggle('on', b === q); });
    sg.classList.remove('jelly'); void sg.offsetWidth; sg.classList.add('jelly'); placeSegs(sg.parentNode);
    if (k === 'apps-sub') { S.appsSub = v; var bx = $('#apps-sub'); bx.innerHTML = appsSub(); placeSegs(bx); stagger(bx); if (v === 'export') loadExports(); }
    else if (k === 'aseg') { S.aseg = v; var ab = $('#aseg-body'); ab.innerHTML = v === 'stats' ? statsBody() : dpiBody(); placeSegs(ab); stagger(ab); afterAseg(); }
    else if (k === 'range') { S.statsRange = v; refreshStats(); }
    else if (k === 'hist') { S.dpiDays = +v; paintDpiHist(); paintUnkTraffic(); Promise.all([loadDpiHist(S.dpiDays), loadAppUsage(S.dpiDays)]).then(paintDpiHist); loadDpiUnk(S.dpiDays).then(paintUnkTraffic); }
    else if (k === 'pu-period') { S.puPeriod = v; refreshPU(); }
    else if (k === 'dflt') { S.dpiFilter = v; paintClients(); }
    else if (k === 'fxp') { if (v === 'off') { S.motion = false; LS.set('hnc6.motion', '0'); } else { S.motion = true; LS.set('hnc6.motion', '1'); FX = Object.assign({}, FX_PRESETS[v]); saveFx(); } fxRefresh(); toast('动画效果：' + FXP_T[v]); }
    else if (k === 'guard-mode') { api.action('clsact_mode_set', { mode: v }, { timeout: 30000, maxTime: 28 }).then(function (r) { var g = detailJSON(r); S.cfg.clsact_bpf_mode = v; if (g && typeof g === 'object') S.cfg.offload_guard = g; S.clsact = null; toast('硬件加速兜底：' + q.textContent); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); if (S.page === 'settings') renderSettings(false); }); }
    else if (k === 'aqm-mode') { api.action('tc_leaf_aqm_set', { mode: v }).then(function () { S.aqmMode = v; LS.set('hnc6.aqm', v); toast('默认队列 AQM：' + q.textContent + ' · 之后新设 / 重设的限速生效'); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); if (S.page === 'settings') renderSettings(false); }); }
    else if (k === 'fxspring') { FX.spring = v; saveFx(); fxRefresh(); }
    else if (k === 'connv') { S.connView = v; paintConnSheet(); }
    else if (k === 'webacc-mode') { S.webaccMode = v; }
    else if (k === 'rmode') { S.refreshMode = v; LS.set('hnc.refresh-mode', v); toast('刷新模式：' + q.textContent); schedulePoll(50); }
    else if (k === 'qos-mode') setQos('mode', v);
    else if (k === 'qos-scale') setQos('scale', v);
    else if (k === 'encdns') { api.action('encdns_set', { policy: v }, { timeout: 30000, maxTime: 28 }).then(function (r) { toast('加密 DNS 拦截：' + (ENC_T[v] || v) + encdnsDetailTxt(r)); return loadEncdns(); }).catch(function (e) { toast(errText(e), 'err'); return loadEncdns(); }).then(function () { if (S.page === 'settings') renderSettings(false); }); }
    else if (k === 'encdns-dev') { var ec = ctxDev(q); if (ec.d) { var ed = ec.d; devAct(ed.mac, function () { return api.action('encdns_set', { scope: 'device', mac: ed.mac, policy: v }, { timeout: 30000, maxTime: 28 }).then(function (r) { return loadEncdns().then(function () { return r; }); }); }, function (r) { return ed.name + ' · 加密 DNS：' + (ENC_T[v] || v) + encdnsDetailTxt(r); }); } }
    else if (k === 'pu-ns') { api.action('phone_usage_set', { use_netstats: v }).then(function () { toast('流量数据来源：' + q.textContent); if (S.puCfg) S.puCfg.use_netstats = v; S.pu = {}; return refreshPU(true); }).catch(function (e) { toast(errText(e), 'err'); }); }
    else if (k === 'delay-pre') { var cx = ctxDev(q); if (cx.box) { var di = $('[data-f="delay"]', cx.box); if (di) di.value = +v ? v : ''; if (!+v) { $('[data-f="jitter"]', cx.box).value = ''; $('[data-f="loss"]', cx.box).value = ''; } } }
    return;
  }
  if ((q = t.closest('.toggle'))) {
    if (q.disabled) return;
    var nv = q.getAttribute('aria-checked') !== 'true'; q.setAttribute('aria-checked', String(nv));
    var ta = q.getAttribute('data-act');
    if (q.hasAttribute('data-set')) { setToggleCfg(q.getAttribute('data-set'), q); return; }
    if (q.hasAttribute('data-selftog')) { selfToggle(q, q.getAttribute('data-selftog')); return; }
    if (q.hasAttribute('data-local')) return;   // 表单内开关, 点「保存」才提交
    if (ta === 'wl-mode') { setWhitelistMode(nv, q); return; }
    var tc = ctxDev(q); if (!tc.d) return;
    if (ta === 'sqm') devAct(tc.d.mac, function () { return api.action('rule_sqm', { mac: tc.d.mac, enabled: String(nv) }); }, nv ? '已开启低延迟模式' : '已关闭低延迟模式');
    if (ta === 'wl') devAct(tc.d.mac, function () { return api.action('device_whitelist_set', { mac: tc.d.mac, enabled: String(nv) }); }, nv ? tc.d.name + ' 已加入白名单' : tc.d.name + ' 已移出白名单');
    return;
  }
  if ((q = t.closest('[data-filter]'))) { S.filter = q.getAttribute('data-filter'); LS.set('hnc_device_filter', S.filter); closeDD(); renderDevices(false); stagger($('#dev-list')); return; }
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
  if ((q = t.closest('[data-revoke]'))) { var tid = q.getAttribute('data-revoke'); confirmSheet('撤销「' + q.getAttribute('data-label') + '」的授权？', '这台设备需要重新配对才能远程访问。', '撤销').then(function (ok) { if (ok) api.action('pair_revoke', { token: tid }).then(function () { toast('已撤销'); loadTokens(); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); return; }
  var a = t.closest('[data-act]'); if (!a || a.disabled) return;
  var act = a.getAttribute('data-act'), cx2 = ctxDev(a), d = cx2.d, box = cx2.box;
  switch (act) {
    case 'dd': var dd = a.closest('.dd'), was = dd.classList.contains('open'); closeDD(); dd.classList.toggle('open', !was); break;
    case 'fold': var key = a.getAttribute('data-key'), fw = a.closest('[data-foldkey="' + key + '"]') || document.getElementById(key); var opened = foldToggle(fw, key);
      if (opened && key === 'logs') loadLog(); if (opened && key === 'tokens') loadTokens();
      if (opened && /^(at|cb)-/.test(key)) loadAppTime(key.slice(3)); break;
    case 'toggle-dev':
      if (!d) break;
      if (S.batch) { if (S.picked[d.mac]) delete S.picked[d.mac]; else S.picked[d.mac] = 1; box.classList.toggle('picked', !!S.picked[d.mac]); var pn = $('#picked-n'); if (pn) pn.textContent = Object.keys(S.picked).length; anim(box, [{ transform: 'scale(.96)' }, { transform: 'none' }], { duration: 550 }); break; }
      if (wide()) { S.sel = d.mac; $$('.dev.sel').forEach(function (x) { x.classList.remove('sel'); }); box.classList.add('sel'); var sd = $('#dev-side'); sd.innerHTML = devSide(); placeSegs(sd); anim(box, [{ transform: 'scale(.97)' }, { transform: 'none' }], { duration: 550 }); if (d.online) refreshConnMini(d.mac); }
      else { var fi = $('.fold-in', box); if (!S.open[d.mac]) { fi.innerHTML = devBody(d); } foldToggle(box, d.mac); a.setAttribute('aria-expanded', String(!!S.open[d.mac])); placeSegs(box); if (S.open[d.mac] && d.online) refreshConnMini(d.mac); }
      break;
    case 'conns': if (d) connSheet(d); break;
    case 'ident-edit': if (d) identSheet(d); break;
    case 'merge-yes': if (d && d.merge) doMerge(d.mac, d.merge.old_mac, d.merge.old_name || d.merge.old_mac, false); break;
    case 'merge-no': if (d && d.merge) dismissMerge(d.mac, d.merge.old_mac, d.merge.old_name || d.merge.old_mac); break;
    case 'fx-demo': fxDemo(a.getAttribute('data-demo')); break;
    case 'fx-perf': setLowFx(!PERF.low, false); PERF.strikes = 0; fxRefresh(); toast(PERF.low ? '已切到简化动画' : '已恢复完整动画'); break;
    case 'self-conns': selfConnSheet(); break;
    case 'apply-limit': devAct(d.mac, function () { return doLimit(d, mbsToMbps(readNum(box, 'down')), mbsToMbps(readNum(box, 'up'))); }, function () { return readNum(box, 'down') || readNum(box, 'up') ? '已应用限速到 ' + d.name : '已清除 ' + d.name + ' 的限速'; }); break;
    case 'clear-limit': devAct(d.mac, function () { return api.action('rule_clear', { mac: d.mac }); }, '已清除 ' + d.name + ' 的限速'); break;
    case 'apply-delay': devAct(d.mac, function () { return doDelay(d, readNum(box, 'delay'), readNum(box, 'jitter'), readNum(box, 'loss')); }, function () { return readNum(box, 'delay') || readNum(box, 'jitter') || readNum(box, 'loss') ? '已对 ' + d.name + ' 注入延迟' : '已清除延迟'; }); break;
    case 'clear-delay': devAct(d.mac, function () { return api.action('delay_clear', { mac: d.mac }); }, '已清除 ' + d.name + ' 的延迟'); break;
    case 'unblock': devAct(d.mac, function () { return api.action('bl_del', { mac: d.mac }); }, d.name + ' 已解除封锁'); break;
    case 'rename': renameSheet(d.mac, d.manual || d.name !== d.mac ? d.name : ''); break;
    case 'copy-mac': copyText(d.mac).then(function (ok) { toast(ok ? '已复制 ' + d.mac : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'trend': loadTrend(d, box); break;
    case 'applim-save': case 'applim-clear':
      var row2 = a.closest('[data-app]'), app = row2.getAttribute('data-app'), lim = act === 'applim-clear' ? 0 : mbsToMbps($('input', row2).value);
      devAct(d.mac, function () { return lim > 0 ? api.action('app_limit_set', { mac: d.mac, app_id: app, down_mbps: trim0(lim.toFixed(3)) }) : api.action('app_limit_clear', { mac: d.mac, app_id: app }); }, lim > 0 ? '已限速 ' + app : app + ' 不再限速').then(function () { return loadAppLimits(); }).then(function () { refreshCard(d.mac); });
      break;
    case 'refresh': api.action('refresh', {}, { timeout: 15000, maxTime: 13 }).catch(function () {}).then(function () { return globalRefresh('已刷新 · ' + S.devices.filter(function (x) { return x.online; }).length + ' 台在线'); }); break;
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
      devAct(d.mac, function () { var qp = { mac: d.mac, daily_gb: trim0(qd.toFixed(3)), monthly_gb: trim0(qm.toFixed(3)), action: qa }; if (qt > 0) qp.throttle_mbps = trim0(qt.toFixed(3)); return api.action('quota_set', qp); }, '已保存 ' + d.name + ' 的流量配额'); break;
    case 'quota-clear': devAct(d.mac, function () { return api.action('quota_clear', { mac: d.mac }); }, '已删除流量配额'); break;
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
    case 'export-list': loadExports(); break;
    case 'self-purge': confirmSheet('清理自学习明细？', '删除 run/self_attrib.*.jsonl 明细（已学到的规则保留）。', '清理').then(function (ok) { if (ok) api.action('self_attrib_purge').then(function (r3) { toast('已清理 · ' + (r3.detail || '')); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    // 分析页
    case 'dpi-refresh': loadDpi(true); toast('已刷新'); break;
    case 'disc-open': case 'disc-back': case 'disc-manage': case 'disc-scan': case 'disc-probe': case 'disc-ignore': case 'disc-confirm': discAct(act); break;
    case 'dpi-rebind': api.action('dpi_rebind').then(function () { toast('已请求 dpid 重新绑定'); setTimeout(function () { loadDpi(true); }, 2500); setTimeout(function () { loadDpi(true); }, 6000); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'rules-export': case 'rules-import': case 'rules-reset': case 'rules-update': rulesAct(act); break;
    // 设置页
    case 'log-refresh': S.logFile = $('#log-file').value; loadLog(); break;
    case 'log-copy': copyText(S.logText || '').then(function (ok) { toast(ok ? '日志已复制' : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'hs-save': hsSave(); break;
    case 'hs-start': hsStart(); break;
    case 'hs-stop': confirmSheet('关闭热点？', '已连接的设备会立即断开。', '关闭').then(function (ok) { if (ok) api.action('hotspot_stop').then(function () { toast('已发出关热点命令'); setTimeout(globalRefresh, 2500); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'iface-save': var ifv = $('#iface-pref').value.trim(); if (ifv && ifv !== 'auto' && !/^[A-Za-z0-9_.-]{1,15}$/.test(ifv)) { toast('接口名不合法', 'err'); break; }
      api.action('hotspot_iface_set', { iface: ifv === 'auto' ? '' : ifv }).then(function () { toast('热点接口偏好：' + (ifv || 'auto')); return loadConfig(); }).then(function () { renderSettings(false); globalRefresh(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'ud-save': api.action('alert_config_set', udParams(true)).then(function () { toast('新设备提醒已保存'); return reloadAlertCfg(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'aq-save': api.action('alert_config_set', { section: 'monthly_quota', enabled: 'true', limit_gb: String(num($('#aq-gb').value, 10)), warn_pct: String(Math.round(num($('#aq-pct').value, 80))) }).then(function () { toast('月度配额已保存'); return api.getSafe('/api/alert_config', null, S.alertCfg); }).then(function (r3) { S.alertCfg = r3; renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'aa-save': api.action('alert_config_set', { section: 'anomaly_traffic', enabled: 'true', ratio: String(num($('#aa-ratio').value, 3)), min_mb: String(Math.round(num($('#aa-mb').value, 50))) }).then(function () { toast('异常检测已保存'); return api.getSafe('/api/alert_config', null, S.alertCfg); }).then(function (r3) { S.alertCfg = r3; renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'gs-apply': gsApply(); break;
    case 'sched-save':
      var sT = $('[data-local="sched-time"]').getAttribute('aria-checked') === 'true', sC = $('[data-local="sched-charge"]').getAttribute('aria-checked') === 'true';
      var st = $('#hs-t-start').value, en = $('#hs-t-end').value;
      if (sT && !(/^\d\d:\d\d$/.test(st) && /^\d\d:\d\d$/.test(en))) { toast('请填好开始和结束时间', 'err'); break; }
      var sp = { time_enable: String(sT), charging_only: String(sC) }; if (/^\d\d:\d\d$/.test(st)) sp.start = st; if (/^\d\d:\d\d$/.test(en)) sp.end = en;
      api.action('hotspot_schedule_set', sp).then(function () { toast(sT || sC ? '已保存 · 下一次检查（约 1 分钟内）开始生效' : '已关闭定时与充电规则'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'ttl-save':
      var td = Math.round(num($('#ttl-days').value, -1)); if (td < 0 || td > 3650) { toast('请填 0~3650 天', 'err'); break; }
      api.action('stale_ttl_set', { days: String(td) }).then(function () { toast(td ? '离线 ' + td + ' 天后自动清理规则' : '已关闭离线规则自动清理'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'fw-add': var pkg = $('#fw-pkg').value.trim(); if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(pkg)) { toast('包名格式不对', 'err'); break; }
      api.action('flywheel_exclude_set', { op: 'add', pkg: pkg }).then(function () { toast('已排除 ' + pkg + ' · 约 5 分钟内生效'); return loadConfig(); }).then(function () { renderSettings(false); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'webacc-save': (function () {
      var mode = S.webaccMode || ((S.cfg.webui_access || {}).mode) || 'all', mi = $('#webacc-macs');
      api.action('webui_access_set', { mode: mode, macs: mi ? mi.value.replace(/[\s，]+/g, ',').replace(/,+/g, ',').replace(/^,|,$/g, '') : '' }).then(function () {
        S.webaccMode = null; toast('WebUI 访问控制：' + ({ all: '全部', allowlist: '白名单', local_only: '仅本机' }[mode] || mode)); return loadConfig();
      }).then(function () { if (S.page === 'settings') renderSettings(false); }).catch(function (e) {
        toast(e && e.status === 409 ? '这样设置会把当前设备锁在外面：请把它加进白名单，或在本机 WebUI 里修改' : errText(e), 'err');
      });
    })(); break;
    case 'url-copy': copyText(remoteUrl()).then(function (ok) { toast(ok ? '已复制访问地址' : '复制失败', ok ? 'ok' : 'err'); }); break;
    case 'url-share': if (navigator.share) navigator.share({ title: 'HNC', url: remoteUrl() }).catch(function () {}); else copyText(remoteUrl()).then(function () { toast('已复制访问地址'); }); break;
    case 'pair-new': pairNew(); break;
    case 'svc-restart': confirmSheet('重启 HNC 服务？', '重跑 post-fs-data.sh + service.sh，期间规则会短暂重建。', '重启').then(function (ok) { if (ok) api.action('restart_service', {}, { timeout: 20000, maxTime: 18 }).then(function () { toast('正在重启…'); setTimeout(function () { location.reload(); }, 2500); }).catch(function (e2) { toast(errText(e2), 'err'); }); }); break;
    case 'cache-clear': api.action('cache_clear').then(function (r3) { toast('缓存已清理' + (r3.detail ? ' · ' + r3.detail : '')); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'rules-json': exportRulesJson(); break;
    case 'json-health': location.href = 'json-health.html'; break;
    case 'debug-bundle': debugBundle(a); break;
    case 'sc-open': scSheet(); break;
    case 'sc-run': scRun(); break;
    case 'sc-export': scExport(a); break;
    case 'clsact-check': clsactCheck(); break;
    case 'clsact-repair': api.action('clsact_repair', {}, { timeout: 20000, maxTime: 18 }).then(function () { toast('已尝试修复'); return clsactCheck(); }).catch(function (e2) { toast(errText(e2), 'err'); }); break;
    case 'changelog': showChangelog(); break;
    case 'logout': confirmSheet('退出登录？', '这台设备需要重新配对才能访问。', '退出').then(function (ok) { if (ok) api.post('/api/logout', {}).catch(function () {}).then(function () { location.href = '/pair'; }); }); break;
  }
});
document.addEventListener('change', function (e) {
  if (e.target.id === 'log-file') { S.logFile = e.target.value; loadLog(); }
});
document.addEventListener('input', function (e) { if (e.target.id === 'q') { S.q = e.target.value; renderDevList(false); } });
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
    if (navigator.vibrate) try { navigator.vibrate(15); } catch (_) {}
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
  pollBusy = true; tickN++;
  var prevSig = S.sig, prevShape = shapeOf(), wasOk = S.connected;
  // 设备页有在线设备时每轮都要刷新单台速率 → 直接用合并请求; 否则只拿汇总, 签名变了再补拉列表
  var wantDev = !S.devLoaded || (S.page === 'devices' && num((S.live || {}).online) > 0 && (S.refreshMode === 'realtime' || tickN % 2 === 0));
  (wantDev ? loadLiveAndDevices() : loadLive()).then(function (l) {
    var sigChanged = l.devices_sig && l.devices_sig !== prevSig;
    if (sigChanged) burstUntil = Date.now() + 5000;
    var needDev = wantDev || sigChanged;
    return (needDev && !wantDev ? loadDevices() : Promise.resolve()).then(function () {
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
    if (S.page === 'stats' && S.aseg === 'dpi' && tickN % 3 === 0) loadDpi(tickN % 12 === 0);
    // 设备页 —— 每 5 轮刷新各设备连接数; 展开着的在线设备卡每 3 轮刷新连接摘要(弹层开着时由弹层自己 2s 刷)
    if (S.page === 'devices' && num((S.live || {}).online) > 0) {
      if (tickN % 5 === 1) loadConnCounts();
      if (tickN % 3 === 0 && !S.connMac) S.devices.forEach(function (x) { if (x.online && (wide() ? S.sel === x.mac : S.open[x.mac])) refreshConnMini(x.mac); });
    }
    if (S.page === 'apps' && tickN % 5 === 0) loadApps().then(function () { if (S.page === 'apps' && !document.querySelector('#p-apps .open, #p-apps :focus')) { var b = $('#apps-sub'); if (b && S.appsSub !== 'export' && S.appsSub !== 'set') { b.innerHTML = appsSub(); placeSegs(b); } } });
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
document.addEventListener('visibilitychange', function () { if (document.hidden) { clearTimeout(pollT); stopSSE(); } else { burstUntil = Date.now() + 2000; schedulePoll(0); loadAlerts(); startSSE(); } });

/* ═════════════════════ 启动 ═════════════════════
 * 旧版 bug: health 失败后重试成功只恢复了设备轮询, 配置/能力/告警/offload 全停在默认值。
 * 这里 boot() 每次都走完整初始化。 */
var booting = null;
function boot(retry) {
  if (booting) return booting;
  if (retry) { S.bootErr = ''; S.connected = false; if (S.page === 'devices') renderDevices(false); if (KSU) loadSecret(true); }
  booting = api.get('/api/health', null, { timeout: 6000 }).then(function () {
    return Promise.all([loadLive(), loadConfig().catch(function () {}), loadCaps(), loadTemplates(), loadAppLimits()]);
  }).then(function () {
    return loadDevices();
  }).then(function () {
    S.booted = true; S.bootErr = '';
    $('#mode-pill').hidden = false; $('#mode-pill').textContent = KSU ? '本机' : '远程';
    RENDER[S.page](!retry); onEnter(S.page);
    loadAlerts(); loadOffload(); loadOnlineHours(); loadUsage(); startSlowPolls(); startSSE();
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
// 透镜边缘的真折射 + 色散: Hyalite by VII-Cae (MIT), https://github.com/VII-Cae/hyalite--liquid-glass
if (window.Hyalite) { try { Hyalite.attach(lens, { bevel: 13, thickness: 24, blur: .3, dispersion: 2.6, shade: .28, rim: 1.7, edge: 0, sat: 1.15 }); } catch (_) {} }
wideMQ.addEventListener('change', function () { RENDER[S.page](false); });
addEventListener('resize', function () { layoutLens(); syncTab(S.page, true); placeSegs(document); drawSpark(); });
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () { if (S.theme === 'auto') applyTheme(); });
boot(false);
window.__hnc6 = { S: S, go: go, api: api, boot: boot, L: L };   // 调试/截图用
