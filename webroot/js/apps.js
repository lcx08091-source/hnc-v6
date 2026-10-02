/* HNC WebUI · apps.js —— 应用页: 本机应用流量归因 */
'use strict';

/* ═════════════════════ 应用页(本机应用流量归因) ═════════════════════ */
var APP_COLORS = ['#007AFF', '#FF2D55', '#34C759', '#FF9500', '#AF52DE', '#5856D6', '#00C7BE', '#FF3B30', '#32ADE6', '#A2845E'];
function appColor(s) { var h = 0; s = String(s || ''); for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return APP_COLORS[Math.abs(h) % APP_COLORS.length]; }
function appName(a, uid) { return (a.display_name && a.display_name.trim()) || (a.pkg ? a.pkg.split('.').slice(-1)[0] : 'uid ' + uid); }
function loadApps() {
  return Promise.all([
    api.get('/api/dpi_state', null, { timeout: 9000 }).then(function (r) { S.dpi = r; S.self = r && r.available && r.state ? (r.state.self || null) : null; }).catch(function (e) { S.dpiErr = errText(e); }),
    api.getSafe('/api/self', null, {}).then(function (r) { S.selfCfg = r || {}; }),
    api.getSafe('/api/self/ifaces', null, null).then(function (r) { S.selfIfaces = r; })
  ]).then(paintAppsDot);
}
function paintAppsDot() {
  var on = !!(S.self && num(S.self.candidate_high) > 0);
  $$('.tab[data-tab="apps"] .dot').forEach(function (d) { d.hidden = !on; });
}
function appRows() {
  var m = (S.self && S.self.apps_by_uid) || {};
  return Object.keys(m).map(function (u) { var a = m[u]; return { uid: u, a: a, name: appName(a, u), bytes: num(a.rx_bytes) + num(a.tx_bytes) }; })
    .sort(function (x, y) { return (num(y.a.active_conns) - num(x.a.active_conns)) || (y.bytes - x.bytes) || (num(y.a.last_seen) - num(x.a.last_seen)); });
}
function renderApps(anim1) {
  var self = S.self, rows = appRows(), active = rows.filter(function (r) { return num(r.a.active_conns) > 0; }).length;
  var tls = self ? sum(self.interfaces || [], function (i) { return num(i.tls_events); }) : 0;
  var st = !self ? ['未就绪', 'var(--text-3)'] : self.enabled ? ['运行中', 'var(--badge-ok)'] : ['已关闭', 'var(--badge-warn)'];
  var foot = !self ? (S.dpiErr ? esc(S.dpiErr) : 'dpid 暂未上报本机数据 · 检查日志 dpid.log') : self.enabled
    ? '采样 ' + (self.last_attrib_tick ? ago(self.last_attrib_tick) : '未开始') + ' · 应用名' + (self.app_label_source === 'pm_live' ? '系统解析 ' + num(self.live_label_count) + ' 个' : '内置字典') + (self.byte_sampler_source ? ' · 字节来源 ' + esc(self.byte_sampler_source) : '')
    : '采样器已停止 · ' + esc(self.reason || '去「设置」子页打开');
  var h = '<div class="wrap">' +
    '<div class="glass ahero"><div class="stats">' +
      '<div><div class="l">追踪状态</div><div class="v" style="color:' + st[1] + '">' + st[0] + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">活跃应用</div><div class="v num">' + active + (rows.length > active ? '<small style="font-size:12px;color:var(--text-3)"> / ' + rows.length + '</small>' : '') + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">连接数</div><div class="v num">' + sum(rows, function (r) { return num(r.a.active_conns); }) + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">TLS 抓取</div><div class="v num">' + tls + '</div></div></div>' +
      '<div class="foot2"><span class="breathe' + (self && self.enabled ? '' : ' off') + '"></span><span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + foot + '</span></div></div>' +
    seg('apps-sub', [['my', '我的应用'], ['cand', '候选' + (self && num(self.candidate_high) ? ' ·' + self.candidate_high : '')], ['export', '导出'], ['set', '设置']], S.appsSub) +
    '<div class="subview" id="apps-sub">' + appsSub() + '</div></div>';
  // 进页面后数据回来的那次重绘(以及开关后的刷新)就地 morph: 此前整页 innerHTML 替换, 把刚开始的浮现动画掐断重来
  var p = $('#p-apps'); if (!anim1 && p.firstElementChild) morph(p, h); else p.innerHTML = h; placeSegs(p);
  if (anim1) stagger($('.wrap', p));
  if (S.appsSub === 'export') loadExports();
}
function ifaceChips() {
  var d = S.selfIfaces; if (!d || !d.ifaces) return '';
  var out = [];
  if (d.ap_iface) out.push('<span class="chip" title="热点接口 · HNC 主路径已在抓">' + esc(d.ap_iface) + ' · 热点</span>');
  d.ifaces.filter(function (x) { return x.eligible; }).slice(0, 6).forEach(function (x) {
    var k = /^(rmnet|ccmni)/.test(x.name) ? ' · 移动网络' : /^wlan/.test(x.name) ? ' · WiFi' : /^eth/.test(x.name) ? ' · 以太网' : '';
    out.push('<span class="chip on" title="已抓取 ' + bytes(x.rx_bytes) + '">' + esc(x.name) + k + '</span>');
  });
  return out.length ? '<div class="chips">' + out.join('') + '</div>' : '';
}
/* 本机此刻的每条连接(哪个 App 连着哪里), 来自 dpid 的本机归因采样 */
function selfConnSheet() {
  sheet('<h3>本机连接明细</h3><div class="sub">这台手机自己此刻的连接 · 按 App 分组</div><div id="sc-body"><div class="note">加载中…</div></div><button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true });
  api.get('/api/self/attrib', { latest: 1, limit: 1 }, { timeout: 9000 }).then(function (r) {
    var el = $('#sc-body'); if (!el) return;
    var conns = r.conns || [], names = {}, by = {};
    var au = (S.self && S.self.apps_by_uid) || {};
    Object.keys(au).forEach(function (k) { var a = au[k]; if (a && a.pkg) names[a.pkg] = a.display_name || a.pkg; });
    conns.forEach(function (c) { var k = c.pkg || ('uid ' + c.uid); (by[k] = by[k] || []).push(c); });
    var keys = Object.keys(by).sort(function (a, b) { return by[b].length - by[a].length; });
    if (!keys.length) { el.innerHTML = '<div class="note" style="text-align:center;padding:16px 0">' + (r.note ? '本机流量追踪还没有数据（在「应用 → 设置」里打开）' : '此刻没有连接') + '</div>'; return; }
    el.innerHTML = '<div class="note" style="margin-bottom:6px">' + conns.length + ' 条连接 · ' + keys.length + ' 个 App' + (r.t ? ' · ' + ago(r.t) : '') + '</div>' + keys.map(function (k) {
      var list = by[k];
      return '<div class="dsec">' + esc(names[k] || k) + ' · ' + list.length + '</div><div class="dbox">' + list.slice(0, 12).map(function (c) {
        return '<div class="row2"><span class="k" style="color:var(--text-1);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(c.name || c.remote) + (c.app ? ' <span class="note">' + esc(c.app) + '</span>' : '') + '</span><span class="v mono" style="font-size:11px;font-weight:500">' + esc(String(c.proto || '').toUpperCase()) + (c.state ? ' ' + esc(c.state) : '') + '</span></div>';
      }).join('') + (list.length > 12 ? '<div class="note">还有 ' + (list.length - 12) + ' 条</div>' : '') + '</div>';
    }).join('');
  }).catch(function (e) { var el = $('#sc-body'); if (el) el.innerHTML = '<div class="note err">' + esc(errText(e)) + '</div>'; });
}
function appsSub() {
  var self = S.self;
  if (S.appsSub === 'my') {
    var rows = appRows();
    if (!rows.length) return ifaceChips() + '<div class="glass empty">' + (!self ? 'dpid 未上报本机数据' : !self.enabled ? '本机流量追踪已关闭 · 去「设置」子页打开（5 秒内生效）' : '采样器刚开启 · 等下一次采样…') + '</div>';
    var usr = rows.filter(function (r) { return !r.a.is_system; }), sys = rows.filter(function (r) { return r.a.is_system; });
    var mx = Math.max.apply(null, rows.map(function (r) { return r.bytes; })) || 1;
    var unm = self.unmatched_sni_samples || [];
    return ifaceChips() +
      (num(self.unmatched_snis_pending) ? '<div class="sec"><span>未匹配的 SNI <small>等待自动扩展规则</small></span><span class="r">' + self.unmatched_snis_pending + '</span></div><div class="glass sni">' +
        unm.slice(0, 8).map(function (s) { return '<div class="sni-row"><span class="dw"><span class="d">' + esc(s) + '</span></span></div>'; }).join('') + '</div>' : '') +
      '<div class="sec"><span>应用 <small>按活跃连接排序 · 点开看域名与规则</small></span><button class="linkish" data-act="self-conns">此刻连接明细</button></div>' +
      '<div class="glass rows">' + usr.slice(0, 60).map(function (r) { return appRow(r, mx); }).join('') + '</div>' +
      (sys.length ? '<div class="glass' + (S.open.sysapps ? ' open' : '') + '" data-foldkey="sysapps"><button class="card-h" data-act="fold" data-key="sysapps">' + gi('gray', 'cpu') + '<span class="tx"><div class="t">系统应用</div><div class="s">' + sys.length + ' 个 · 厂商/系统组件，默认收起</div></span>' + ico('chev', 'chev') + '</button>' +
        '<div class="fold"><div><div class="fold-in rows" style="border-top:1px solid var(--divider)">' + sys.slice(0, 100).map(function (r) { return appRow(r, mx); }).join('') + '</div></div></div></div>' : '');
  }
  if (S.appsSub === 'cand') {
    if (!self) return '<div class="glass empty">等待 dpid 上报…</div>';
    var cs = self.candidate_samples || [];
    var grp = function (title, list, acts) {
      if (!list.length) return '';
      return '<div class="sec"><span>' + title + '</span><span class="r">' + list.length + '</span></div><div class="glass sni">' + list.map(function (c) {
        return '<div class="sni-row" data-apex="' + esc(c.apex) + '"><span class="dw"><span class="d">' + esc(c.apex) + '</span><span class="c">' + esc(c.app || (c.uid ? 'uid ' + c.uid : '未知应用')) + ' · 命中 ' + num(c.hits) + ' 次 · ' + num(c.windows) + ' 个窗口 · ' + ({ high: '高', med: '中', low: '低', shared: '共享' }[c.tier] || c.tier) + '</span></span>' + acts(c) + '</div>';
      }).join('') + '</div>';
    };
    return '<div class="glass" style="padding:12px 14px"><div class="note">陌生主域名（走法 2）：dpid 会把「只被某一个应用访问」的新域名累积成候选。<b>晋级</b> = 写进规则库，以后流量归到这个应用；<b>拒绝</b> = 记为共享基础设施，不再归因。' +
        (self.auto_promote_on ? ' 当前已开启 HIGH 自动晋级。' : ' 当前是影子模式（只统计不写规则），可在「设置」里开启自动晋级。') + '</div></div>' +
      grp('已晋级', cs.filter(function (c) { return c.promoted; }), function () { return '<button class="btn sec press" data-cand="reject">撤销</button>'; }) +
      grp('待审', cs.filter(function (c) { return !c.promoted && c.tier !== 'shared'; }), function () { return '<span style="display:flex;gap:6px"><button class="btn sec press" data-cand="reject">拒绝</button><button class="btn pri press" data-cand="promote">晋级</button></span>'; }) +
      grp('共享基础设施', cs.filter(function (c) { return !c.promoted && c.tier === 'shared'; }), function () { return ''; }) +
      (cs.length ? '' : '<div class="glass empty">暂时没有候选 · 规则库已覆盖抓到的域名</div>');
  }
  if (S.appsSub === 'export') {
    return '<div class="glass" style="padding:14px;display:grid;gap:12px"><div class="field">快速选择时间范围<div class="chips">' + [[15, '最近 15 分'], [60, '最近 1 小时'], [180, '最近 3 小时'], [360, '最近 6 小时']].map(function (x) {
        return '<button class="chip press' + (x[0] === (S.expMin || 60) ? ' on' : '') + '" data-exp-min="' + x[0] + '">' + x[1] + '</button>'; }).join('') + '</div></div>' +
      '<div class="grid2"><label class="field">起始<span class="box"><input type="datetime-local" id="exp-from" value="' + dtLocal(Date.now() - (S.expMin || 60) * 60000) + '"></span></label><label class="field">结束<span class="box"><input type="datetime-local" id="exp-to" value="' + dtLocal(Date.now()) + '"></span></label></div>' +
      '<label class="field">备注（写给分析者的上下文，可选）<span class="box ta"><textarea id="exp-notes" maxlength="2000" placeholder="例如：刷短视频时偶尔卡顿，想看是哪个域名"></textarea></span></label>' +
      '<button class="btn pri wide press" data-act="export-build">' + ico('down') + '打包导出</button><div id="exp-result"></div></div>' +
      '<div class="sec"><span>最近的导出</span><button class="linkish" data-act="export-list">刷新</button></div><div class="glass rows" id="exp-list"><div class="empty">加载中…</div></div>';
  }
  var c = S.selfCfg || {};
  return '<div class="sec"><span>追踪开关</span></div><div class="glass rows">' +
    '<div class="row"><span class="tx"><div class="t">追踪本机应用流量</div><div class="s">按 uid 把本机连接归到应用（dpid 采样，5 秒内生效）。同时记录「应用 → 域名 / 指纹」样本，用来给识别打分；只存本机、保留 7 天、不上传</div></span>' + toggle(self && self.enabled, 'data-selftog="toggle" aria-label="追踪本机应用流量"') + '</div>' +
    '<div class="row"><span class="tx"><div class="t">已知应用子域自动加入规则</div><div class="s">走法 1：同一应用命中 ≥10 次的新子域自动扩进规则</div></span>' + toggle(c.auto_expand_enabled, 'data-selftog="auto_expand/toggle" aria-label="自动扩展规则"') + '</div>' +
    '<div class="row"><span class="tx"><div class="t">HIGH 候选自动晋级</div><div class="s">走法 2：高置信度的陌生主域名自动写进规则；关闭时只做影子统计</div></span>' + toggle(c.auto_promote_enabled, 'data-selftog="auto_promote/toggle" aria-label="HIGH 自动晋级"') + '</div></div>' +
    '<div class="glass rows"><button class="row" data-act="self-purge">' + gi('orange', 'trash') + '<span class="tx"><div class="t">清理自学习明细数据</div><div class="s">删除 self_attrib 明细（保留已学到的规则）</div></span><span class="hint-a warn">清理</span></button></div>';
}
function appRow(r, mx) {
  var a = r.a, key = 'app' + r.uid, nm = r.name;
  var snis = (a.top_snis || []).slice(0, 6), rules = (a.top_rules || []).slice(0, 4), hits = a.rule_hit_counts || {};
  var val = r.bytes ? bytes(r.bytes) : num(a.total_conns) + ' 次';
  return '<div class="row-wrap' + (S.open[key] ? ' open' : '') + '" data-foldkey="' + key + '"><button class="row-h" data-act="fold" data-key="' + key + '">' +
    '<span class="appi" style="background:linear-gradient(145deg,' + appColor(a.pkg || nm) + ',color-mix(in srgb,' + appColor(a.pkg || nm) + ' 60%,#000))">' + esc(nm.charAt(0).toUpperCase()) + '</span>' +
    '<span class="tx"><div class="dev-name" style="font-size:14.5px"><span class="nm">' + esc(nm) + '</span>' + (a.flywheel_excluded ? '<span class="badge b-gray">不学习</span>' : '') + '</div>' +
      (r.bytes ? '<div class="bar1"><i style="width:' + Math.max(2, r.bytes / mx * 100).toFixed(1) + '%"></i></div>' : '<div class="s">' + (a.last_seen ? '最近 ' + ago(a.last_seen) : '') + '</div>') + '</span>' +
    '<span style="text-align:right"><div class="num" style="font-size:13px;font-weight:700">' + val + '</div><div style="font-size:11px;color:var(--text-3)">' + num(a.active_conns) + ' 连接</div></span>' + ico('chev', 'chev') + '</button>' +
    '<div class="fold"><div><div class="fold-in set-body">' +
      '<div class="note mono">' + esc(a.pkg || '(包名未解析)') + ' · uid ' + esc(r.uid) + '</div>' +
      (snis.length ? '<div class="dev-apps">' + snis.map(function (s) { return '<span class="a mono">' + esc(s) + '</span>'; }).join('') + '</div>' : '') +
      (rules.length ? '<div class="dev-apps"><span class="lb">规则</span>' + rules.map(function (x) { var n = num(hits[x]); return '<span class="badge ' + (n >= 10 ? 'b-ok' : 'b-gray') + '">' + esc(x) + (n ? ' · ' + n : '') + '</span>'; }).join('') + '</div>' : '') +
      (a.flywheel_excluded ? '<div class="note">VPN / 代理类应用：它会代理其他应用的流量，不参与规则学习</div>'
        : a.pkg ? '<button class="btn sec press" data-excl="' + esc(a.pkg) + '" data-name="' + esc(nm) + '">排除 · 不学习此应用的规则</button>' : '') +
    '</div></div></div></div>';
}
function dtLocal(ms) { var d = new Date(ms); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
function loadExports() {
  return api.get('/api/exports').then(function (r) {
    var el = $('#exp-list'); if (!el) return;
    var l = r.exports || [];
    el.innerHTML = l.length ? l.slice(0, 20).map(function (x) {
      return '<button class="row" data-dl="' + esc(x.name) + '" data-url="' + esc(x.download_url || '') + '">' + gi('blue', 'down') + '<span class="tx"><div class="t mono" style="font-size:12.5px;word-break:break-all">' + esc(x.name) + '</div><div class="s">' + esc(x.modified || '') + ' · ' + bytes(x.size) + '</div></span><span class="hint-a">' + (KSU ? '存到下载' : '下载') + '</span></button>';
    }).join('') : '<div class="empty">还没有导出过</div>';
  }).catch(function (e) { var el = $('#exp-list'); if (el) el.innerHTML = '<div class="empty">' + esc(errText(e)) + '</div>'; });
}
function buildExport(btn) {
  var f = Date.parse($('#exp-from').value), t = Date.parse($('#exp-to').value), notes = $('#exp-notes').value.trim();
  if (!(f > 0) || !(t > 0) || t <= f) { toast('时间范围不对', 'err'); return; }
  btn.disabled = true; btn.lastChild.textContent = '正在打包…';
  api.post('/api/export', { from: Math.floor(f / 1000), to: Math.floor(t / 1000), notes: notes ? [notes] : [] }, { timeout: 90000, maxTime: 85 }).then(function (r) {
    if (r.status !== 'ok') throw new Error(r.error || '打包失败');
    var tr = (r.manifest && r.manifest.tracks) || {};
    $('#exp-result').innerHTML = '<div class="note" style="margin-top:4px">✓ ' + esc(r.name) + ' · ' + bytes(r.size_bytes) + '<br>' + Object.keys(tr).map(function (k) { return esc(k) + (tr[k].included ? ' ' + tr[k].file_count + ' 个文件' : ' 无'); }).join(' · ') + '</div>';
    toast('导出完成 · ' + bytes(r.size_bytes)); loadExports();
  }).catch(function (e) { toast(errText(e), 'err'); }).then(function () { btn.disabled = false; btn.lastChild.textContent = '打包导出'; });
}
function downloadExport(name, url) {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) { toast('文件名不合法', 'err'); return; }
  if (!KSU) { var a = document.createElement('a'); a.href = url || '/api/exports/' + encodeURIComponent(name); a.download = name; document.body.appendChild(a); a.click(); a.remove(); return; }
  shell('mkdir -p /sdcard/Download && cp ' + sq(HNC_DIR + '/exports/' + name) + ' /sdcard/Download/ && echo ok').then(function () { toast('已存到 /sdcard/Download/' + name); }, function (e) { toast(errText(e), 'err'); });
}
function selfToggle(el, path) {
  var on = el.getAttribute('aria-checked') === 'true';
  pend(el, true);
  api.post('/api/self/' + path, { enabled: on }).then(function (r) {
    if (r && r.error) throw new Error(r.error);
    toast((el.getAttribute('aria-label') || '') + (on ? ' 已开启' : ' 已关闭') + (path === 'toggle' && on ? ' · 5 秒内出现数据' : ''));
    if (path !== 'toggle') S.selfCfg[path.split('/')[0] + '_enabled'] = on;
    setTimeout(function () { loadApps().then(function () { if (S.page === 'apps') renderApps(false); }); }, path === 'toggle' ? 5500 : 800);
  }).catch(function (e) { el.setAttribute('aria-checked', String(!on)); toast(errText(e), 'err'); }).then(function () { pend(el, false); });
}
function candAct(kind, apex) {
  api.action(kind === 'promote' ? 'candidate_promote' : 'candidate_reject', { apex: apex }).then(function () {
    toast(kind === 'promote' ? apex + ' 已晋级为规则' : apex + ' 已标记为共享');
    return loadApps();
  }).then(function () { if (S.page === 'apps') { var b = $('#apps-sub'); if (b) b.innerHTML = appsSub(); } }).catch(function (e) { toast(errText(e), 'err'); });
}
function excludeApp(pkg, name) {
  confirmSheet('不学习「' + name + '」的规则？', 'VPN / 代理类应用会代理别的应用的流量，排除后它的域名不会被学成规则。约 5 分钟内生效，可在设置 → 飞轮排除名单里移除。', '排除', { safe: true }).then(function (ok) {
    if (!ok) return;
    api.action('flywheel_exclude_set', { op: 'add', pkg: pkg }).then(function () { toast('已排除 ' + name); return loadConfig(); }).catch(function (e) { toast(errText(e), 'err'); });
  });
}

