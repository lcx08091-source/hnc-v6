/* HNC WebUI · devices.js —— 设备页: 列表/卡片/筛选、配额·分时段·应用时长、设备识别与实时连接、设备操作、限速模板、全局操作 */
'use strict';

/* ═════════════════════ 设备页 ═════════════════════ */
var FILTERS = [['recent', '近 7 天活跃', '在线或 7 天内出现过'], ['online_only', '只看在线', '只显示当前连着热点的设备'], ['all', '显示全部', '包括很久没出现的历史设备'], ['offline_rules', '只看离线规则', '已离线但还留着限速/延迟/封锁规则的设备']];
function visibleDevs() {
  var q = S.q.trim().toLowerCase(), wk = Date.now() / 1000 - 7 * 86400;
  return S.devices.filter(function (d) {
    if (S.filter === 'online_only' && !d.online) return false;
    if (S.filter === 'recent' && !d.online && !(d.lastSeen > wk) && !d.hasRule) return false;
    if (S.filter === 'offline_rules' && !(!d.online && (d.limitOn || d.hasDelay || d.blocked))) return false;
    return !q || (d.name + ' ' + d.ip + ' ' + d.mac + ' ' + d.vendor + ' ' + d.idText).toLowerCase().indexOf(q) >= 0;
  });
}
function modeSuffix(kind, m) {
  if (!m) return '';
  if (kind === 'limit') return { down_only: ' · 仅下行', failed: ' · 失败', pending: ' · 待应用' }[m] || '';
  return { egress_only: ' · 仅下行', failed: ' · 失败', pending: ' · 待应用' }[m] || '';
}
function badges(d) {
  var b = '';
  if (d.sim) b += '<span class="badge b-sim" title="模拟环境里的虚构设备，操作不会碰 tc / iptables">模拟</span>';
  if (d.blocked) b += '<span class="badge b-red">已封锁</span>';
  else if (!d.online) b += '<span class="badge b-gray">离线</span>';
  if (d.limitOn) b += '<span class="badge ' + (d.limitMode === 'failed' ? 'b-red' : 'b-acc') + '">限速 ' + (mbpsToMBs(d.down) || '∞') + '/' + (mbpsToMBs(d.up) || '∞') + modeSuffix('limit', d.limitMode) + '</span>';
  if (d.hasDelay) b += '<span class="badge ' + (d.delayMode === 'failed' ? 'b-red' : 'b-pur') + '">延迟 ' + d.delay + 'ms' + (d.loss ? ' · 丢包 ' + d.loss + '%' : '') + modeSuffix('delay', d.delayMode) + '</span>';
  if (d.sqm) b += '<span class="badge b-ok">低延迟</span>';
  if (d.wl) b += '<span class="badge b-ok">白名单</span>';
  b += policyBadges(d);
  if (d.applyError) b += '<span class="badge b-red" title="' + esc(d.applyError) + '">应用出错</span>';
  if (d.vpn) b += vpnBadge(d.vpn);
  if (d.rmac) b += '<span class="badge b-gray" title="Android/iOS 隐私 Wi-Fi 的随机 MAC，无法识别厂商；换 MAC 后 HNC 会提示合并">随机 MAC</span>';
  if (d.mergedInto) b += '<span class="badge b-gray" title="这个旧 MAC 已合并到 ' + esc(d.mergedInto) + '">已合并</span>';
  return b;
}

/* ═══ 配额 / 分时段 / 实际生效 / 应用时长 / 类别封锁 ═══ */
var GB = 1073741824;
function fmtDur(sec) {
  sec = Math.max(0, Math.round(num(sec))); if (sec < 60) return sec ? '不到 1 分' : '0 分';
  var h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60);
  return h ? h + ' 小时' + (m ? ' ' + m + ' 分' : '') : m + ' 分';
}
var EFF_SRC = { manual: '手动设置', schedule: '分时段', quota: '流量配额', block: '黑名单' };
function effWhat(e) {
  if (!e) return '';
  if (e.blocked) return '断网';
  var dn = num(e.down_mbps), up = num(e.up_mbps);
  return dn > 0 || up > 0 ? '限速 ↓' + (mbpsToMBs(dn) || '∞') + ' / ↑' + (mbpsToMBs(up) || '∞') + ' MB/s' : '不限速';
}
function effLine(d) {
  var e = d.eff; if (!e) return '';
  var w = effWhat(e), src = EFF_SRC[e.reason] || e.reason || '';
  return '<div class="eff">当前生效：<b>' + esc(w) + '</b>' + (src && !(e.reason === 'manual' && w === '不限速') ? '<span class="src">· 来自' + esc(src) + '</span>' : '') + '</div>' +
    (e.apply_error ? '<div class="note err">自动策略落地失败：' + esc(e.apply_error) + '</div>' : '');
}
function quotaPct(q) {
  var a = num(q.daily_gb) > 0 ? num(q.used_today) / (num(q.daily_gb) * GB) : 0, b = num(q.monthly_gb) > 0 ? num(q.used_month) / (num(q.monthly_gb) * GB) : 0;
  return Math.max(a, b) * 100;
}
function policyBadges(d) {
  var b = '', q = d.quota, e = d.eff;
  if (q && q.state === 'exceeded') b += '<span class="badge b-red">超配额' + (q.applied ? ' · ' + (q.action === 'block' ? '断网' : '限速') : '') + '</span>';
  else if (q && q.state === 'warn') b += '<span class="badge b-warn">配额 ' + Math.round(quotaPct(q)) + '%</span>';
  if (e && e.reason === 'schedule') b += '<span class="badge b-acc">时段' + (e.blocked ? '断网' : '限速') + '</span>';
  var ex = d.atl.filter(function (x) { return x.exhausted; }).length;
  if (ex) b += '<span class="badge b-warn">' + ex + ' 个应用时长用完</span>';
  if (d.cblocks.length) b += '<span class="badge b-red">封锁 ' + d.cblocks.length + ' 类应用</span>';
  return b;
}
/* 设备卡内的折叠小节(复用全局 fold 机制: data-foldkey + data-act="fold") */
function dFold(key, color, title, summary, body) {
  return '<div class="ctrl dfold' + (S.open[key] ? ' open' : '') + '" data-foldkey="' + esc(key) + '"><button class="ctrl-t dfold-h" data-act="fold" data-key="' + esc(key) + '"><i style="background:' + color + '"></i><span class="dft">' + title + '</span><span class="dfs">' + summary + '</span>' + ico('chev', 'chev') + '</button>' +
    '<div class="fold"><div><div class="fold-in dfold-in">' + body + '</div></div></div></div>';
}
function qBar(label, used, limGB) {
  var lim = num(limGB) * GB, p = lim ? num(used) / lim * 100 : 0;
  return '<div class="qrow"><div class="h"><span class="k">' + label + '</span><span class="v">' + bytes(used) + ' / ' + trim0(num(limGB).toFixed(2)) + ' GB · ' + Math.round(p) + '%</span></div><div class="pbar' + (p >= 100 ? ' over' : p >= 80 ? ' warn' : '') + '"><i style="width:' + clamp(p, 0, 100).toFixed(1) + '%"></i></div></div>';
}
function quotaFold(d) {
  var q = d.quota, key = 'q-' + d.mac, act = q && q.action === 'block' ? 'block' : 'throttle';
  var sum2 = !q ? '未设置' : [num(q.daily_gb) ? '每日 ' + trim0(num(q.daily_gb).toFixed(2)) + ' GB' : '', num(q.monthly_gb) ? '每月 ' + trim0(num(q.monthly_gb).toFixed(2)) + ' GB' : ''].filter(Boolean).join(' · ') + (q.state === 'exceeded' ? ' · 已超' : q.state === 'warn' ? ' · 快用完' : '');
  var body = '';
  if (q) {
    if (num(q.daily_gb)) body += qBar('今日', q.used_today, q.daily_gb);
    if (num(q.monthly_gb)) body += qBar('本月' + (num(q.billing_day) > 1 ? '（' + num(q.billing_day) + ' 号起）' : ''), q.used_month, q.monthly_gb);
    if (q.state === 'exceeded') body += '<div class="note ' + (q.applied ? 'err' : 'warn') + '">' + (q.exceeded_period === 'monthly' ? '本月' : '今日') + '用量已超出配额' + (q.applied ? '，已自动' + (act === 'block' ? '断网' : '限速到 ' + (mbpsToMBs(q.throttle_mbps) || '?') + ' MB/s') + '，下个周期自动恢复' : '') + '</div>';
  }
  body += '<div class="grid2"><label class="field">每日上限<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="不限" data-f="q-daily" value="' + (q && num(q.daily_gb) ? trim0(num(q.daily_gb).toFixed(2)) : '') + '"><span class="u">GB</span></span></label>' +
    '<label class="field">每月上限<span class="box"><input type="number" inputmode="decimal" min="0" step="1" placeholder="不限" data-f="q-month" value="' + (q && num(q.monthly_gb) ? trim0(num(q.monthly_gb).toFixed(2)) : '') + '"><span class="u">GB</span></span></label></div>' +
    seg('q-act', [['throttle', '超额后限速'], ['block', '超额后断网']], act, 'small') +
    '<label class="field">超额后限速到<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="默认" data-f="q-thr" value="' + (q ? mbpsToMBs(q.throttle_mbps) : '') + '"><span class="u">MB/s</span></span></label>' +
    '<div class="note">今日用量每天 0 点清零；每月按计费日起算。超额后自动' + '限速或断网，到下个周期自动恢复。' + (d.sim ? '模拟设备只改模拟状态。' : '') + '</div>' +
    '<div class="btns">' + (q ? '<button class="btn sec press" data-act="quota-clear">删除配额</button>' : '') + '<button class="btn pri press" data-act="quota-save">保存配额</button></div>';
  return dFold(key, 'var(--orange)', '流量配额', esc(sum2), body);
}
var WD = [[1, '一'], [2, '二'], [3, '三'], [4, '四'], [5, '五'], [6, '六'], [0, '日']];
function daysText(days) {
  days = (days || []).map(Number);
  if (!days.length || days.length === 7) return '每天';
  var s = days.slice().sort().join(',');
  if (s === '1,2,3,4,5') return '工作日'; if (s === '0,6') return '周末';
  return '周' + WD.filter(function (w) { return days.indexOf(w[0]) >= 0; }).map(function (w) { return w[1]; }).join('');
}
function winDesc(w) { return w.block ? '断网' : (num(w.down_mbps) > 0 || num(w.up_mbps) > 0 ? '限速 ↓' + (mbpsToMBs(w.down_mbps) || '∞') + ' / ↑' + (mbpsToMBs(w.up_mbps) || '∞') + ' MB/s' : '不限速'); }
function schedFold(d) {
  var sc = d.sched, ws = sc ? sc.windows : [], ai = sc ? num(sc.active_window_index, -1) : -1, key = 's-' + d.mac;
  if (sc && sc.active_window_index == null) ai = -1;
  var body = ws.length ? '<div class="wlist">' + ws.map(function (w, i) {
    return '<div class="wline"><span class="w"><b>' + esc(daysText(w.days)) + ' ' + esc(w.start) + '–' + esc(w.end) + '</b> <span>' + esc(winDesc(w)) + '</span></span>' + (i === ai ? '<span class="badge b-ok">生效中</span>' : '') + '</div>';
  }).join('') + '</div>' : '<div class="note">按星期和时间段自动限速或断网，比如「工作日 22:00–07:00 断网」。时段内临时覆盖手动限速，结束后自动恢复。</div>';
  body += '<div class="btns">' + (ws.length ? '<button class="btn sec press" data-act="sched-clear">清除时段</button>' : '') + '<button class="btn pri press" data-act="sched-edit">' + (ws.length ? '编辑时段' : '添加时段') + '</button></div>';
  return dFold(key, 'var(--blue)', '分时段限速', ws.length ? ws.length + ' 个时段' + (ai >= 0 ? ' · 生效中' : '') : '未设置', body);
}
function schedSheet(d) {
  var ws = (d.sched && d.sched.windows || []).map(function (w) { return { days: (w.days || []).slice(), start: w.start, end: w.end, down: mbpsToMBs(w.down_mbps), up: mbpsToMBs(w.up_mbps), block: !!w.block }; });
  if (!ws.length) ws.push({ days: [1, 2, 3, 4, 5], start: '22:00', end: '07:00', down: '', up: '', block: true });
  sheet('<h3>分时段限速</h3><div class="sub">' + esc(d.name) + ' · 最多 16 个时段</div><div id="sw-list" style="display:grid;gap:10px"></div>' +
    '<button class="btn sec wide press" id="sw-add" style="margin-top:10px">＋ 添加时段</button>' +
    '<div class="note" style="margin-top:8px">不选星期 = 每天。跨午夜的时段（如 22:00–07:00）按开始那天算。限速单位 MB/s，留空 = 该方向不限。</div>' +
    '<div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>取消</button><button class="btn pri press" id="sw-save">保存</button></div>', { tall: true });
  function read() {
    $$('#sw-list .win').forEach(function (el, i) {
      var w = ws[i]; if (!w) return;
      w.days = $$('[data-wd].on', el).map(function (b) { return +b.getAttribute('data-wd'); });
      w.start = $('[data-k="start"]', el).value; w.end = $('[data-k="end"]', el).value;
      w.down = $('[data-k="down"]', el).value; w.up = $('[data-k="up"]', el).value; w.block = $('[data-k="block"]', el).checked;
    });
  }
  function paint() {
    $('#sw-list').innerHTML = ws.map(function (w, i) {
      return '<div class="win"><div class="top"><span>时段 ' + (i + 1) + '</span><button class="linkish danger" data-wdel="' + i + '">删除</button></div>' +
        '<div class="dchips">' + WD.map(function (x) { return '<button class="dchip cat' + (w.days.indexOf(x[0]) >= 0 ? ' on' : '') + '" data-wd="' + x[0] + '">' + x[1] + '</button>'; }).join('') + '</div>' +
        '<div class="grid2"><label class="field">开始<span class="box"><input type="time" data-k="start" value="' + esc(w.start) + '"></span></label><label class="field">结束<span class="box"><input type="time" data-k="end" value="' + esc(w.end) + '"></span></label></div>' +
        '<div class="grid2"><label class="field">下行<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="不限" data-k="down" value="' + esc(w.down) + '"><span class="u">MB/s</span></span></label><label class="field">上行<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="不限" data-k="up" value="' + esc(w.up) + '"><span class="u">MB/s</span></span></label></div>' +
        '<label class="cb"><input type="checkbox" data-k="block"' + (w.block ? ' checked' : '') + '> 这个时段直接断网</label></div>';
    }).join('');
  }
  paint();
  $('#sw-list').onclick = function (e) {
    var b = e.target.closest('[data-wd]'); if (b) { b.classList.toggle('on'); return; }
    var x = e.target.closest('[data-wdel]'); if (x) { read(); ws.splice(+x.getAttribute('data-wdel'), 1); paint(); }
  };
  $('#sw-add').onclick = function () { read(); if (ws.length >= 16) { toast('最多 16 个时段', 'warn'); return; } ws.push({ days: [], start: '08:00', end: '12:00', down: '', up: '', block: false }); paint(); };
  $('#sw-save').onclick = function () {
    read();
    var out = [], bad = '';
    ws.forEach(function (w, i) {
      if (bad) return;
      if (!/^\d\d:\d\d$/.test(w.start) || !/^\d\d:\d\d$/.test(w.end)) { bad = '时段 ' + (i + 1) + '：请填好开始和结束时间'; return; }
      if (w.start === w.end) { bad = '时段 ' + (i + 1) + '：开始和结束不能相同'; return; }
      var dn = mbsToMbps(w.down), up = mbsToMbps(w.up);
      if (!w.block && !(dn > 0) && !(up > 0)) { bad = '时段 ' + (i + 1) + '：填一个限速，或勾选断网'; return; }
      out.push({ days: w.days, start: w.start, end: w.end, down_mbps: w.block ? 0 : +trim0(dn.toFixed(3)), up_mbps: w.block ? 0 : +trim0(up.toFixed(3)), block: w.block });
    });
    if (bad) { toast(bad, 'err'); return; }
    closeSheet();
    if (!out.length) { devAct(d.mac, function () { return api.action('schedule_clear', { mac: d.mac }); }, '已清除分时段'); return; }
    devAct(d.mac, function () { return api.action('schedule_set', { mac: d.mac, windows: JSON.stringify(out) }); }, '已保存 ' + out.length + ' 个时段');
  };
}
/* 应用使用时长(活跃秒数, 后端按「有流量的分钟」累计) + 限时 + 按类别封锁 */
var CATB_T = { video: '视频', short_video: '短视频', game: '游戏', social: '社交', music: '音乐', shopping: '购物', news: '资讯', live: '直播', reading: '阅读' };
function catLabel(c) { return CATB_T[c] || CAT_T[c] || c || '其他'; }
S.appTime = {};
var atBusy = {};
function loadAppTime(mac, force) {
  var c = S.appTime[mac];
  if (atBusy[mac] || (c && !force && Date.now() - c.at < 60000)) return atBusy[mac] || Promise.resolve();
  atBusy[mac] = api.get('/api/app_time', { mac: mac, days: 1 }, { timeout: 10000 }).then(function (r) { S.appTime[mac] = { at: Date.now(), r: r }; })
    .catch(function (e) { S.appTime[mac] = { at: Date.now(), err: e && e.status === 404 ? '需要新版后端（/api/app_time）' : errText(e) }; })
    .then(function () { delete atBusy[mac]; paintAppTime(mac); });
  return atBusy[mac];
}
function paintAppTime(mac) {
  var d = devBy(mac); if (!d) return;
  $$('[data-dev="' + mac + '"] [data-at], [data-side="' + mac + '"] [data-at]').forEach(function (el) { el.innerHTML = appTimeInner(d); });
  $$('[data-dev="' + mac + '"] [data-cb], [data-side="' + mac + '"] [data-cb]').forEach(function (el) { el.innerHTML = catBlockInner(d); });
}
function atNeed(d) { if (!S.appTime[d.mac] && (S.open['at-' + d.mac] || S.open['cb-' + d.mac])) setTimeout(function () { loadAppTime(d.mac); }, 0); }
function appTimeInner(d) {
  var c = S.appTime[d.mac], lim = {}, h = '';
  d.atl.forEach(function (x) { lim[x.app_id] = x; });
  d.atl.forEach(function (x) {
    var p = num(x.minutes) ? num(x.used_sec) / (num(x.minutes) * 60) * 100 : 0;
    h += '<div class="atr"><span class="n">' + esc(x.name || x.app_id) + '<small>' + fmtDur(x.used_sec) + ' / ' + fmtDur(num(x.minutes) * 60) + '</small></span><button class="linkish" data-atl="' + esc(x.app_id) + '" data-name="' + esc(x.name || x.app_id) + '">修改</button>' +
      '<div class="pbar' + (x.exhausted ? ' over' : p >= 80 ? ' warn' : '') + '"><i style="width:' + clamp(p, 0, 100).toFixed(1) + '%"></i></div>' +
      (x.exhausted ? '<div class="note err">已用完 · 明天 0 点恢复' + (x.enforced === false ? '（' + (d.sim ? '模拟设备' : '当前') + '未实际拦截）' : '') + '</div>' : '') + '</div>';
  });
  if (!c) h += '<div class="note">加载中…</div>';
  else if (c.err) h += '<div class="note err">' + esc(c.err) + '</div>';
  else {
    var apps = (c.r.apps || []).filter(function (a) { return a.id && a.id.charAt(0) !== '_' && !lim[a.id]; });
    h += apps.slice(0, 12).map(function (a) {
      return '<div class="atr"><span class="n">' + esc(a.name || a.id) + '<small>' + (a.category ? esc(catLabel(a.category)) + ' · ' : '') + fmtDur(a.active_sec) + '</small></span><button class="linkish" data-atl="' + esc(a.id) + '" data-name="' + esc(a.name || a.id) + '">限时</button></div>';
    }).join('');
    if (!apps.length && !d.atl.length) h += '<div class="note">今天还没有这台设备的应用使用记录（需要 DPI 在运行）</div>';
    h += '<div class="note">今天共 ' + fmtDur(c.r.total_active_sec) + ' · 按「有流量的分钟」累计，后台挂着的应用也可能计入</div>';
  }
  return h;
}
function appTimeFold(d) {
  var ex = d.atl.filter(function (x) { return x.exhausted; }).length, c = S.appTime[d.mac];
  var sum2 = d.atl.length ? d.atl.length + ' 个限时' + (ex ? ' · ' + ex + ' 个已用完' : '') : c && c.r ? '今天 ' + fmtDur(c.r.total_active_sec) : '今日时长 · 限时';
  atNeed(d);
  return dFold('at-' + d.mac, 'var(--pink,#FF2D55)', '应用使用时长', esc(sum2), fgNowHtml(d) + '<div data-at>' + appTimeInner(d) + '</div>');
}
/* DPI v2 前台模型: 「正在用 / 后台」+ 前台时间线入口 */
var FG_ST = { active: '正在用', paused: '暂停中', idle: '空闲', stale: '数据过期', unknown: '未知' };
function fgNowHtml(d) {
  var f = d.fg; if (!f) return '';
  var main = f.state === 'active' && f.name ? esc(f.label || '正在用：' + f.name) + ' <small class="num">' + pct100(f.confidence) + '%</small>' : esc(FG_ST[f.state] || f.state);
  return '<div class="fgline"><b>' + main + '</b>' + ttTag(d) + (f.bg_label ? '<span class="note">' + esc(f.bg_label) + '</span>' : '') +
    '<button class="linkish" data-act="fg-tl" style="margin-left:auto">前台时间线</button></div>';
}
var FG_COL = ['#007AFF', '#FF2D55', '#34C759', '#FF9500', '#AF52DE', '#5AC8FA', '#FFCC00', '#8E8E93'];
function fgTimelineSheet(d, days) {
  days = days || 1;
  sheet('<h3>前台时间线 · ' + esc(d.name) + '</h3><div class="sub">根据流量形态推断「屏幕上正在用哪个应用」，后台下载 / 播放不算前台</div>' +
    '<div style="margin:10px 0 6px">' + seg('fgdays', [[1, '今天'], [3, '3 天'], [7, '7 天']], days, 'small') + '</div><div id="fgtl-body"><div class="note">加载中…</div></div>' +
    '<button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true });
  S.fgMac = d.mac; loadFgTl(d, days);
}
function loadFgTl(d, days) {
  var el0 = $('#fgtl-body'); if (el0 && el0.firstElementChild) el0.style.opacity = '.5';
  api.get('/api/fg_timeline', { mac: d.mac, days: days }, { timeout: 10000 }).then(function (r) {
    var el = $('#fgtl-body'); if (!el) return;
    var ss = Array.isArray(r.sessions) ? r.sessions : [], ba = Array.isArray(r.by_app) ? r.by_app : [], col = {};
    ba.forEach(function (x, i) { col[x.app_id] = FG_COL[i % FG_COL.length]; });
    var t1 = Date.now() / 1000, t0 = days === 1 ? new Date(new Date().setHours(0, 0, 0, 0)).getTime() / 1000 : t1 - days * 86400, span = Math.max(1, t1 - t0);
    var bar = '<div class="fgtl"><div class="bar">' + ss.map(function (x) {
      var a = Math.max(num(x.start), t0), b = Math.min(num(x.end) || t1, t1); if (b <= a) return '';
      return '<i title="' + esc((x.name || x.app_id) + ' · ' + fmtDur(b - a)) + '" style="left:' + ((a - t0) / span * 100).toFixed(2) + '%;width:' + Math.max(0.4, (b - a) / span * 100).toFixed(2) + '%;background:' + (col[x.app_id] || '#8E8E93') + '"></i>';
    }).join('') + '</div><div class="ax"><span>' + (days === 1 ? '0:00' : days + ' 天前') + '</span><span>现在</span></div></div>';
    var list = ba.length ? ba.map(function (x) {
      return '<div class="row2"><span class="k" style="color:var(--text-1)"><i style="display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;background:' + col[x.app_id] + '"></i>' + appNmH(x.app_id, x.name) + '</span><span class="v">前台 ' + fmtDur(num(x.fg_sec)) + (num(x.active_sec) ? ' · 有流量 ' + fmtDur(num(x.active_sec)) : '') + '</span></div>';
    }).join('') : '<div class="note">这段时间还没有前台记录（设备需要在线并产生流量）</div>';
    var cur = r.current || d.fg, why = cur && Array.isArray(cur.reasons) && cur.reasons.length ? '<div class="note">判断依据：' + esc(cur.reasons.slice(0, 4).join('；')) + '</div>' : '';
    if (S.fgMac !== d.mac) return; el.style.opacity = '';
    el.innerHTML = bar + '<div class="dbox" style="margin-top:10px">' + list + '</div>' + why +
      '<div class="note">「有流量」是按字节阈值算的使用时长（应用限时用这个口径）；「前台」会排除后台下载、后台播放等。</div>';
  }).catch(function (e) { var el = $('#fgtl-body'); if (el) el.innerHTML = '<div class="note err">' + esc(errText(e)) + '</div>'; });
}
function catBlockInner(d) {
  var c = S.appTime[d.mac], on = {}, cats = [];
  d.cblocks.forEach(function (b) { on[b.category] = b; });
  if (c && c.r && Array.isArray(c.r.categories)) cats = c.r.categories.map(function (x) { return { id: x.id, n: (x.apps || []).length, names: (x.apps || []).map(function (a) { return a.name || a.id; }) }; });
  d.cblocks.forEach(function (b) { if (!cats.some(function (x) { return x.id === b.category; })) cats.push({ id: b.category, n: num(b.app_count), names: [] }); });
  if (!cats.length) return c && c.err ? '<div class="note err">' + esc(c.err) + '</div>' : '<div class="note">' + (c ? '规则库里还没有可封锁的类别' : '加载中…') + '</div>';
  var blocked = cats.filter(function (x) { return on[x.id]; });
  return '<div class="dchips">' + cats.map(function (x) { return '<button class="dchip cat cblk' + (on[x.id] ? ' on' : '') + '" data-cblk="' + esc(x.id) + '" title="' + esc(x.names.slice(0, 12).join('、')) + '">' + esc(catLabel(x.id)) + (x.n ? '<small>' + x.n + '</small>' : '') + '</button>'; }).join('') + '</div>' +
    (blocked.length ? '<div class="note">已封锁：' + blocked.map(function (x) { return esc(catLabel(x.id)) + (x.names.length ? '（' + esc(x.names.slice(0, 6).join('、')) + (x.names.length > 6 ? ' 等' : '') + '）' : ''); }).join('；') +
      (d.cblocks.some(function (b) { return b.enforced === false; }) ? ' · ' + (d.sim ? '模拟设备' : '当前') + '未实际拦截' : '') + '</div>' : '') +
    '<div class="note">点一下封锁 / 解除这一类的全部应用（按域名拦截，只对这台设备生效）。注意「社交」包含字节系服务，封锁后同公司的其他应用也可能受影响。</div>';
}
function catBlockFold(d) {
  atNeed(d);
  return dFold('cb-' + d.mac, 'var(--red)', '按类别封锁', d.cblocks.length ? esc(d.cblocks.map(function (b) { return catLabel(b.category); }).join('、')) : '未封锁', '<div data-cb>' + catBlockInner(d) + '</div>');
}
function appTimeSheet(d, id, name) {
  var cur = d.atl.filter(function (x) { return x.app_id === id; })[0];
  sheet('<h3>限时 · ' + esc(name) + '</h3><div class="sub">' + esc(d.name) + ' · 每天可用多久，用完当天封锁，次日 0 点自动恢复</div>' +
    '<div class="dchips" id="atm-pre">' + [15, 30, 60, 90, 120, 180].map(function (m) { return '<button class="dchip cat' + (cur && num(cur.minutes) === m ? ' on' : '') + '" data-atm="' + m + '">' + fmtDur(m * 60) + '</button>'; }).join('') + '</div>' +
    '<label class="field" style="margin-top:12px">每天可用<span class="box"><input id="atm" type="number" inputmode="numeric" min="1" max="1440" placeholder="分钟" value="' + (cur ? num(cur.minutes) : '') + '"><span class="u">分钟</span></span></label>' +
    (cur ? '<div class="note" style="margin-top:8px">今天已用 ' + fmtDur(cur.used_sec) + (cur.exhausted ? ' · 已用完' : '') + '</div>' : '') +
    '<div class="btns" style="margin-top:12px">' + (cur ? '<button class="btn dan press" id="atm-del">取消限时</button>' : '<button class="btn sec press" data-close>取消</button>') + '<button class="btn pri press" id="atm-ok">保存</button></div>');
  $('#atm-pre').onclick = function (e) { var b = e.target.closest('[data-atm]'); if (!b) return; $('#atm').value = b.getAttribute('data-atm'); $$('#atm-pre [data-atm]').forEach(function (x) { x.classList.toggle('on', x === b); }); };
  var after = function () { return loadAppTime(d.mac, true); };
  $('#atm-ok').onclick = function () {
    var m = Math.round(num($('#atm').value)); if (!(m >= 1 && m <= 1440)) { toast('填 1~1440 分钟', 'err'); return; }
    closeSheet(); devAct(d.mac, function () { return api.action('app_time_limit_set', { mac: d.mac, app_id: id, minutes: m }); }, '「' + name + '」每天限 ' + fmtDur(m * 60)).then(after);
  };
  var del = $('#atm-del'); if (del) del.onclick = function () { closeSheet(); devAct(d.mac, function () { return api.action('app_time_limit_del', { mac: d.mac, app_id: id }); }, '「' + name + '」不再限时').then(after); };
}
function devBody(d) {
  var busy = S.busy[d.mac] ? ' disabled' : '';
  var dis = htbOk() ? '' : ' disabled', upDis = upOk() ? '' : ' disabled', dlDis = netemOk() ? '' : ' disabled';
  var h = '<div class="dev-body">';
  if (d.sim) h += '<div class="note warn" style="padding:0 2px">这是模拟设备 · 各项操作只改模拟状态，不会碰 tc / iptables</div>';
  h += vpnNote(d);
  if (d.mergedInto) { var mt = devBy(d.mergedInto); h += '<div class="note" style="padding:0 2px">这个旧 MAC 已合并到「' + esc(mt ? mt.name : d.mergedInto) + '」，它的设置和历史流量都算在新 MAC 上</div>'; }
  // 限速
  h += '<div class="ctrl"><div class="ctrl-t"><i></i>限速控制</div>' + effLine(d) +
    (htbOk() ? '' : '<div class="note err">当前内核 / tc 不支持 HTB，限速不可用</div>') +
    '<div class="grid2"><label class="field">下行<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="不限" value="' + mbpsToMBs(d.down) + '" data-f="down"' + dis + '><span class="u">MB/s</span></span></label>' +
    '<label class="field">上行' + (upOk() ? '' : ' · 不支持') + '<span class="box"><input type="number" inputmode="decimal" min="0" step="0.1" placeholder="不限" value="' + (upOk() ? mbpsToMBs(d.up) : '') + '" data-f="up"' + upDis + '><span class="u">MB/s</span></span></label></div>' +
    (upOk() && offloadRisk() ? '<div class="note warn">系统硬件 offload（' + esc(S.offload.detail) + '）可能绕过 tc，上行限速可能偏松</div>' : '') +
    '<div class="btns"><button class="btn sec press" data-act="clear-limit"' + busy + '>清除</button><button class="btn pri press" data-act="apply-limit"' + busy + dis + '>应用限速</button></div></div>';
  // 流量配额 / 分时段(折叠, 不把卡片撑得太长)
  if (S.polSupport || d.eff) h += quotaFold(d) + schedFold(d);
  // 不常用的控制收进「更多控制」: QoS 校准 / 延迟注入 / 低延迟·白名单 / 识别 / 加密 DNS / 7 天曲线
  var more = '';
  // QoS 校准(仅 root HTB fallback 时)
  if (qosFallback()) {
    var qm = S.cfg.tc_qos_mode || LS.get('hnc.qos-mode', 'compat'), qsc = String(S.cfg.tc_qos_scale || LS.get('hnc.qos-scale', '100'));
    more += '<div class="ctrl"><div class="ctrl-t"><i style="background:var(--orange)"></i>限速策略 · 已进入 root HTB 兼容链路</div>' +
      seg('qos-mode', [['precise', '精确'], ['compat', '兼容']], qm, 'small') + seg('qos-scale', [['100', '标准'], ['85', '稳准'], ['75', '严格']], qsc, 'small') +
      '<div class="note">精确模式减小 burst；校准越严格，实测越接近设定值，但可能略低于目标。</div></div>';
  }
  // 延迟
  more += '<div class="ctrl"><div class="ctrl-t"><i style="background:var(--purple)"></i>延迟注入</div>' +
    (netemOk() ? '' : '<div class="note err">当前内核 / tc 不支持 netem，延迟注入不可用</div>') +
    (d.sqm ? '<div class="note warn">已开启低延迟模式，与延迟注入互斥</div>' : '') +
    seg('delay-pre', [[0, '关闭'], [50, '50ms'], [100, '100ms'], [200, '200ms']], [0, 50, 100, 200].indexOf(d.delay) >= 0 ? d.delay : -1, 'small') +
    '<div class="grid2" style="grid-template-columns:1fr 1fr 1fr"><label class="field">延迟<span class="box"><input type="number" min="0" max="10000" placeholder="0" value="' + (d.delay || '') + '" data-f="delay"' + dlDis + '><span class="u">ms</span></span></label>' +
    '<label class="field">抖动<span class="box"><input type="number" min="0" max="5000" placeholder="0" value="' + (d.jitter || '') + '" data-f="jitter"' + dlDis + '><span class="u">ms</span></span></label>' +
    '<label class="field">丢包<span class="box"><input type="number" min="0" max="100" step="0.1" placeholder="0" value="' + (d.loss || '') + '" data-f="loss"' + dlDis + '><span class="u">%</span></span></label></div>' +
    '<div class="btns"><button class="btn sec press" data-act="clear-delay"' + busy + '>清除</button><button class="btn pri press" data-act="apply-delay"' + busy + (d.sqm ? ' disabled' : dlDis) + '>应用延迟</button></div></div>';
  // 低延迟 / 白名单
  more += '<div class="ctrl" style="gap:0;padding:4px 0">' +
    '<div class="row" style="padding:8px 0;min-height:0"><span class="tx"><div class="t">低延迟模式</div><div class="s">游戏/语音更稳 · <span data-qdisc>' + esc(qdiscNote()) + '</span>' + (d.hasDelay ? '（先清除延迟注入）' : '') + '</div></span>' + toggle(d.sqm, 'data-act="sqm" aria-label="低延迟模式"' + (d.hasDelay || !htbOk() ? ' disabled' : '')) + '</div>' +
    '<div class="row" style="padding:8px 0;min-height:0"><span class="tx"><div class="t">白名单</div><div class="s">开启白名单模式后，只有白名单设备能上网</div></span>' + toggle(d.wl, 'data-act="wl" aria-label="白名单"') + '</div></div>';
  // 实时连接(conntrack) —— 展开时拉一次, 「查看全部」打开实时刷新的弹层
  if (d.online) h += '<div class="ctrl"><div class="ctrl-t" style="justify-content:space-between"><span style="display:flex;gap:6px;align-items:center"><i style="background:var(--orange)"></i>实时连接</span><button class="linkish" data-act="conns">查看全部</button></div><div data-conn-mini>' + connMiniHtml(d.mac) + '</div></div>';
  // 设备识别
  more += identBlock(d);
  // 加密 DNS 按设备覆盖
  more += encdnsDevBlock(d);
  // 应用限速
  h += '<div class="ctrl"><div class="ctrl-t"><i style="background:var(--green)"></i>按应用限速</div><div data-applim>' + appLimitRows(d) + '</div></div>';
  // 应用使用时长 + 限时 / 按类别封锁
  h += appTimeFold(d) + catBlockFold(d);
  // 7 天曲线
  more += '<div class="ctrl"><div class="ctrl-t" style="justify-content:space-between"><span style="display:flex;gap:6px;align-items:center"><i style="background:var(--cyan)"></i>近 7 天 · 每小时流量</span><button class="linkish" data-act="trend">加载</button></div><div data-trend class="note">点「加载」查看这台设备 7 天内各时段的流量分布</div></div>';
  var on = [d.hasDelay ? '延迟 ' + (d.delay || 0) + 'ms' : '', d.sqm ? '低延迟' : '', d.wl ? '白名单' : ''].filter(Boolean);
  h += dFold('more-' + d.mac, 'var(--gray,#8E8E93)', '更多控制', esc(on.length ? on.join(' · ') : '延迟注入 · 低延迟 · 白名单 · 识别 · 趋势'), '<div class="more-in">' + more + '</div>');
  // 访问控制 + 其他
  h += (d.blocked ? '<button class="btn ok wide press" data-act="unblock"' + busy + '>✓ 解除封锁</button>'
    : '<button class="btn dan wide hold" data-act="hold"' + busy + '><i class="fill"></i><span>长按封锁设备</span></button>') +
    '<div class="btns"><button class="btn sec press" data-act="rename">' + ico('edit') + '重命名</button><button class="btn sec press" data-act="copy-mac">' + ico('copy') + '复制 MAC</button></div>' +
    '<dl class="kv" style="padding:0 4px"><dt>IP</dt><dd>' + esc(d.ip || '—') + '</dd><dt>MAC</dt><dd>' + esc(d.mac) + '</dd>' +
    (d.vendor ? '<dt>厂商</dt><dd>' + esc(d.vendor) + '</dd>' : '') + '<dt>最后出现</dt><dd>' + (d.online ? '在线' : ago(d.lastSeen)) + '</dd>' +
    (d.mark != null && d.mark !== '' ? '<dt>mark</dt><dd>0x' + (0x800000 + num(d.mark)).toString(16) + '</dd>' : '') + (d.applyError ? '<dt>错误</dt><dd style="color:var(--red)">' + esc(d.applyError) + '</dd>' : '') + '</dl>';
  return h + '</div>';
}
var HN_SRC = { dhcp: 'DHCP', dhcpv6: 'DHCPv6', mdns: 'mDNS', nbns: 'NetBIOS', manual: '手动命名', mac: 'MAC' };
var EV_SRC = { dhcp: 'DHCP', dhcpv6: 'DHCP6', mdns: 'mDNS', ssdp: 'SSDP', nbns: 'NBNS', dns: 'DNS', sni: 'TLS', ja4: 'JA4', oui: 'OUI', hostname: '主机名' };
function identBlock(d) {
  var id = d.ident;
  var rows = '';
  if (id) {
    var c = Math.max(0, Math.min(100, num(id.confidence)));
    if (TYPE_T[id.type]) rows += '<dt>类型</dt><dd>' + TYPE_I[id.type] + ' ' + TYPE_T[id.type] + '</dd>';
    if (id.os) rows += '<dt>系统</dt><dd>' + esc(id.os + (id.os_ver ? ' ' + id.os_ver : '')) + '</dd>';
    if (id.brand || id.model) rows += '<dt>品牌型号</dt><dd>' + esc([id.brand, id.model].filter(Boolean).join(' · ')) + '</dd>';
    if (id.hostname) rows += '<dt>上报名称</dt><dd class="mono">' + esc(id.hostname) + (id.hostname_src ? ' <span class="note">(' + esc(HN_SRC[id.hostname_src] || id.hostname_src) + ')</span>' : '') + '</dd>';
    if (id.services && id.services.length) rows += '<dt>服务</dt><dd class="mono" style="font-size:11.5px;font-weight:500">' + esc(id.services.slice(0, 6).join(' ')) + '</dd>';
    rows += '<dt>把握</dt><dd><span class="confbar"><i><b style="width:' + c + '%"></b></i><span class="num">' + c + '%</span></span></dd>';
  }
  if (!rows && !d.vendor) rows = '';
  var ev = id && Array.isArray(id.evidence) ? id.evidence : [];
  var body = rows ? '<dl class="idg">' + rows + '</dl>' : '<div class="note">' + (isRandomMac(d.mac) ? '这台设备用的是随机 MAC，厂商查不到。' : '') + '还没收集到识别信号 —— 设备重新连接热点（DHCP）或产生网络请求后会自动识别' + (S.dpi && S.dpi.available === false ? '（需要 DPI 在运行）' : '') + '</div>';
  if (ev.length) body += '<div class="evi">' + ev.slice(0, 6).map(function (e) { return '<span><em>' + esc(EV_SRC[e.src] || e.src || '?') + '</em><span style="min-width:0;overflow-wrap:anywhere">' + esc(e.detail || '') + '</span></span>'; }).join('') + '</div>';
  return '<div class="ctrl"><div class="ctrl-t" style="justify-content:space-between"><span style="display:flex;gap:6px;align-items:center"><i style="background:var(--indigo,#5856D6)"></i>设备识别' + (id && id.manual ? '<span class="note" style="font-weight:500;letter-spacing:0">· 已手动纠正</span>' : d.vendor ? '<span class="note" style="font-weight:500;letter-spacing:0">· OUI ' + esc(d.vendor) + '</span>' : '') + '</span><button class="linkish" data-act="ident-edit">纠正</button></div>' + body + '</div>';
}
/* 识别纠正 —— 自动识别错了可以手动改类型/系统/品牌型号 */
function identSheet(d) {
  var id = d.ident || {}, ty = id.type || '';
  sheet('<h3>纠正识别结果</h3><div class="sub">' + esc(d.name) + ' · 保存后以你填的为准（把握 100%）</div>' +
    '<div class="note" style="margin-bottom:6px">类型</div><div class="dchips" id="idt">' + Object.keys(TYPE_T).map(function (k) { return '<button class="dchip cat' + (ty === k ? ' on' : '') + '" data-idt="' + k + '">' + TYPE_I[k] + ' ' + TYPE_T[k] + '</button>'; }).join('') + '</div>' +
    '<div class="grid2" style="margin-top:12px"><label class="field">系统' + inp('idf-os', id.os || '', '', 'maxlength="40" placeholder="Android / iOS / Windows"') + '</label><label class="field">版本' + inp('idf-ver', id.os_ver || '', '', 'maxlength="40" placeholder="14"') + '</label></div>' +
    '<div class="grid2"><label class="field">品牌' + inp('idf-brand', id.brand || '', '', 'maxlength="40" placeholder="小米"') + '</label><label class="field">型号' + inp('idf-model', id.model || '', '', 'maxlength="40" placeholder="Xiaomi 14"') + '</label></div>' +
    '<div class="btns" style="margin-top:12px">' + (id.manual ? '<button class="btn sec press" id="idf-clear">恢复自动识别</button>' : '<button class="btn sec press" data-close>取消</button>') + '<button class="btn pri press" id="idf-save">保存</button></div>');
  var pick = ty;
  $('#idt').onclick = function (e) { var b = e.target.closest('[data-idt]'); if (!b) return; pick = pick === b.getAttribute('data-idt') ? '' : b.getAttribute('data-idt'); $$('#idt [data-idt]').forEach(function (x) { x.classList.toggle('on', x.getAttribute('data-idt') === pick); }); };
  var send = function (p, msg) { api.action('device_ident_set', p).then(function () { closeSheet(); toast(msg); return loadDevices(); }).then(function () { refreshCard(d.mac); }).catch(function (e) { toast(errText(e), 'err'); }); };
  $('#idf-save').onclick = function () { send({ mac: d.mac, type: pick, os: $('#idf-os').value.trim(), os_ver: $('#idf-ver').value.trim(), brand: $('#idf-brand').value.trim(), model: $('#idf-model').value.trim() }, '已保存识别结果'); };
  var cl = $('#idf-clear'); if (cl) cl.onclick = function () { send({ mac: d.mac, clear: 'true' }, '已恢复自动识别'); };
}
/* ── 实时连接 ── */
S.conn = {}; S.connCounts = {};
function connCountText(d) {
  var c = d.online && S.connCounts[d.mac];
  return c && num(c.n) ? ' · ' + num(c.n) + ' 条连接' : '';
}
function paintConnCounts() {
  S.devices.forEach(function (d) { var el = document.getElementById('ct-' + d.mac.replace(/:/g, '')); if (el) el.textContent = connCountText(d); });
}
function loadConnCounts() {
  return api.getSafe('/api/connections', null, null).then(function (r) { if (r && r.counts) { S.connCounts = r.counts; paintConnCounts(); } });
}
function loadConns(mac) {
  return api.get('/api/connections', { mac: mac }, { timeout: 8000 }).then(function (r) { S.conn[mac] = { at: Date.now(), r: r }; return r; })
    .catch(function (e) { S.conn[mac] = { at: Date.now(), err: errText(e) }; });
}
function connLabel(c) { return c.name || c.svc || c.dst; }
function connKey(c) { return c.proto + '|' + c.dst + '|' + c.dport + '|' + c.sport; }
/* 识别来源: user = 你纠正过 / fp = TLS 指纹学习推断(带置信度); 规则库 / 域名命中不标 */
function srcTag(c) {
  if (!c.app) return '';
  if (c.app_src === 'user') return '<span class="ap src">已纠正</span>';
  if (c.app_src === 'fp' || c.app_src === 'seed') return '<span class="ap src">指纹识别' + (c.app_conf ? ' ' + pct100(c.app_conf) + '%' : '') + '</span>';
  return '';
}
function connRow(c) {
  var act = num(c.down_bps) + num(c.up_bps) > 0, pc = c.local ? 'l' : c.proto === 'udp' ? 'u' : '';
  var sub = (c.v6 ? '[' + c.dst + ']' : c.dst) + ':' + c.dport + (c.svc && c.name ? ' · ' + c.svc : '') + (c.state && c.state !== 'ESTABLISHED' ? ' · ' + c.state : '') + (c.unreplied ? ' · 无应答' : '');
  return '<div class="cn press' + (act ? '' : ' idle') + '" data-cnk="' + esc(connKey(c)) + '" style="cursor:pointer"><span class="p ' + pc + '">' + esc(String(c.proto || '').toUpperCase().slice(0, 4)) + '</span>' +
    '<span class="m"><span class="n">' + esc(connLabel(c)) + '</span><span class="s">' + (c.app ? '<span class="ap">' + esc(c.app) + '</span>' : '') + srcTag(c) + (!c.app && c.owner && c.owner.name ? '<span class="ap own">' + esc(c.owner.name) + '</span>' : '') + (c.local ? '<span class="ap lan">局域网</span>' : '') + (c.blocked ? '<span class="ap" style="background:rgba(255,59,48,.14);color:var(--red)">已封锁</span>' : '') + esc(sub) + '</span></span>' +
    '<span class="r">' + (act ? '↓ ' + bpsTxt(c.down_bps) + '<br>↑ ' + bpsTxt(c.up_bps) : '<small>空闲</small>') + (num(c.down_bytes) + num(c.up_bytes) ? '<small>' + bytes(num(c.down_bytes) + num(c.up_bytes)) + '</small>' : '') + '</span></div>';
}
/* 点一条连接 → 封锁域名 / 封锁 IP / 给应用限速 / 复制 */
function connActSheet(mac, key) {
  var c0 = S.conn[mac], d = devBy(mac); if (!c0 || !c0.r || !d) return;
  var c = (c0.r.conns || []).filter(function (x) { return connKey(x) === key; })[0]; if (!c) return;
  var dom = c.name ? guessSuffix(c.name) : '', h = '';
  if (c.local) h += '<div class="note" style="text-align:center">这是局域网连接，不能封锁</div>';
  else {
    if (dom) h += '<button class="btn dan wide press" id="ca-dom" style="margin-bottom:8px">封锁 ' + esc(dom) + '（含子域名）</button>';
    h += '<button class="btn sec wide press" id="ca-ip" style="margin-bottom:8px">只封锁这个 IP · <span class="mono">' + esc(c.dst) + '</span></button>';
    if (c.app_id && !c.sdk) h += '<div class="dbox" style="margin-bottom:8px"><div class="row2"><span class="k">给「' + esc(c.app) + '」限速</span><span class="v"><span class="box" style="display:inline-flex;width:130px"><input id="ca-lim" type="number" min="0" step="0.1" placeholder="例如 1"><span class="u">MB/s</span></span></span></div><button class="btn pri wide press" id="ca-limit">保存限速</button></div>';
  }
  if (!c.local && !d.sim) h += '<button class="btn sec wide press" id="ca-fix" style="margin-bottom:8px">' + (c.app ? '识别不对？纠正为其他应用' : '这是哪个应用？告诉 HNC') + '</button>';
  h += '<button class="btn sec wide press" id="ca-copy">复制' + (c.name ? '域名' : ' IP') + '</button>';
  sheet('<h3>' + esc(c.name || c.dst) + '</h3><div class="sub">' + esc(d.name) + ' · ' + esc(String(c.proto).toUpperCase()) + ' ' + esc(c.dst) + ':' + c.dport + (c.app ? ' · ' + esc(c.app) : '') + '</div>' + h +
    '<div class="note" style="margin-top:10px">封锁只对这台设备生效，其他设备不受影响。域名按 DPI 看到的 DNS / TLS 自动跟踪 IP 变化。</div>' +
    '<button class="btn sec wide press" id="ca-back" style="margin-top:10px">返回</button>', { onClose: function () {} });
  var back = function () { connSheet(d); };
  var blk = function (kind, value, label) { api.action('conn_block_add', { mac: mac, kind: kind, value: value, label: label || '' }).then(function () { toast('已封锁 ' + value); back(); }).catch(function (e) { toast(errText(e), 'err'); }); };
  var bd = $('#ca-dom'); if (bd) bd.onclick = function () { blk('domain', dom, c.app || ''); };
  var bi = $('#ca-ip'); if (bi) bi.onclick = function () { blk('ip', c.dst, c.name || ''); };
  var bl = $('#ca-limit'); if (bl) bl.onclick = function () { var v = mbsToMbps($('#ca-lim').value); if (!(v > 0)) { toast('填一个大于 0 的速度', 'warn'); return; } api.action('app_limit_set', { mac: mac, app_id: c.app_id, down_mbps: trim0(v.toFixed(3)) }).then(function () { toast('已给「' + c.app + '」限速'); return loadAppLimits(); }).then(back).catch(function (e) { toast(errText(e), 'err'); }); };
  $('#ca-copy').onclick = function () { copyText(c.name || c.dst).then(function (ok) { toast(ok ? '已复制' : '复制失败', ok ? 'ok' : 'err'); }); };
  $('#ca-back').onclick = back;
  var fx = $('#ca-fix'); if (fx) fx.onclick = function () { dpiFixSheet(d, c, back); };
}
/* 纠正识别: 选一个应用 → dpi_correct(按域名 + IP + TLS 指纹记一条用户规则, 之后所有设备的同类连接都按这个算) */
function dpiFixSheet(d, c, back) {
  var cand = [], seen = {};
  var add = function (id, name) { if (!id || !name || id.charAt(0) === '_' || seen[id]) return; seen[id] = 1; cand.push([id, name]); };
  d.live.concat(d.apps).forEach(function (a) { add(a.id || a.app_id, a.name); });
  S.devices.forEach(function (x) { x.live.concat(x.apps).forEach(function (a) { add(a.id || a.app_id, a.name); }); });
  Object.keys(S.appUsage || {}).forEach(function (k) { var u = S.appUsage[k] && S.appUsage[k].d, m = u && u.apps; if (m && typeof m === 'object') Object.keys(m).forEach(function (id) { add(id, m[id] && m[id].name); }); });
  cand = cand.slice(0, 30);
  sheet('<h3>纠正识别</h3><div class="sub">' + esc(c.name || c.dst) + (c.app ? ' · 现在识别为「' + esc(c.app) + '」' : ' · 还没识别出来') + '</div>' +
    (cand.length ? '<div class="note" style="margin-bottom:6px">这条连接其实属于</div><div class="dchips" id="fix-pick">' + cand.map(function (x) { return '<button class="dchip cat" data-fix="' + esc(x[0]) + '">' + esc(x[1]) + '</button>'; }).join('') + '</div>' : '') +
    '<label class="field" style="margin-top:12px">或者填应用名' + inp('fix-name', '', '', 'maxlength="40" placeholder="例如 抖音"') + '</label>' +
    '<div class="note" style="margin-top:8px">会同时记住这个域名、这个 IP（7 天）和这类 TLS 指纹，之后所有设备的同类连接都按你选的算，统计和按应用限速一起变准。可在「设置 → 应用识别 → 识别纠正记录」里撤销。</div>' +
    '<div class="btns" style="margin-top:12px"><button class="btn sec press" id="fix-back">返回</button><button class="btn pri press" id="fix-ok">保存</button></div>');
  var pick = '';
  var pk = $('#fix-pick'); if (pk) pk.onclick = function (e) { var b = e.target.closest('[data-fix]'); if (!b) return; pick = pick === b.getAttribute('data-fix') ? '' : b.getAttribute('data-fix'); $$('#fix-pick [data-fix]').forEach(function (x) { x.classList.toggle('on', x.getAttribute('data-fix') === pick); }); };
  $('#fix-back').onclick = back;
  $('#fix-ok').onclick = function () {
    var nm = $('#fix-name').value.trim(), id = pick, name = '';
    if (!id && nm) { name = nm; id = 'user:' + nm.replace(/[^A-Za-z0-9_.-]/g, function (ch) { return ch.charCodeAt(0).toString(36); }).slice(0, 58); }
    if (!id) { toast('选一个应用或填应用名', 'warn'); return; }
    var p = { mac: d.mac, dst_ip: c.dst, dst_port: String(c.dport || ''), app_id: id };
    if (name) p.app_name = name; else { var hit = cand.filter(function (x) { return x[0] === id; })[0]; if (hit) p.app_name = hit[1]; }
    if (c.name) p.name = c.name; if (c.ja4) p.ja4 = c.ja4;
    busyWhile(this, api.action('dpi_correct', p)).then(function () { toast('已纠正为「' + (p.app_name || id) + '」· 新连接立即生效'); return loadConns(d.mac); }).then(back).catch(function (e) { toast(errText(e), 'err'); });
  };
}
function bpsTxt(v) { var b = bps(num(v)); return b.v + ' ' + b.u; }
function connNotes(r) {
  if (!r) return '';
  if (r.readable === false) return '<div class="note err">读不到内核连接表（' + esc(r.error || 'nf_conntrack') + '）</div>';
  if (r.acct === false && r.total) return '<div class="note warn">内核没开连接字节计数，已尝试打开（只对新连接生效），暂时看不到速率</div>';
  return '';
}
function connMiniHtml(mac) {
  var c = S.conn[mac];
  if (!c) return '<div class="note">加载中…</div>';
  if (c.err) return '<div class="note err">' + esc(c.err) + '</div>';
  var r = c.r || {}, list = r.conns || [];
  if (!list.length) return connNotes(r) + '<div class="note">当前没有连接</div>';
  var d0 = devBy(mac), cs = d0 ? catShare(d0) : '';
  return '<div class="cn-sum"><span>共 <b>' + num(r.total) + '</b> 条</span><span>↓↑ <b>' + bpsTxt(r.bps) + '</b></span>' + (r.groups && r.groups[0] ? '<span>最多 <b>' + esc(r.groups[0].label) + '</b></span>' : '') + '</div>' + (cs ? '<div class="note" style="margin:-4px 0 6px">' + esc(cs) + '</div>' : '') + connNotes(r) + list.slice(0, 4).map(connRow).join('');
}
function paintConnMini(mac) { $$('[data-dev="' + mac + '"] [data-conn-mini], [data-side="' + mac + '"] [data-conn-mini]').forEach(function (el) { el.innerHTML = connMiniHtml(mac); }); }
function refreshConnMini(mac) { return loadConns(mac).then(function () { paintConnMini(mac); }); }
var connT = null;
function connSheet(d) {
  S.connView = S.connView || 'all';
  sheet('<h3>实时连接 · ' + esc(d.name) + '</h3><div class="sub mono">' + (d.sim ? '<span class="badge b-sim" style="font-family:var(--font)">模拟</span> ' : '') + esc(d.ip || '') + ' · ' + d.mac + '</div>' +
    '<div style="margin:10px 0 6px">' + seg('connv', [['all', '全部'], ['active', '活跃'], ['group', '按应用']], S.connView, 'small') + '</div>' +
    '<div id="cn-body"><div class="note">加载中…</div></div><div class="note" style="margin-top:8px">数据来自内核连接表（conntrack），域名来自 DPI 抓到的 DNS / TLS，每 2 秒刷新</div>' +
    '<button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true, kind: 'conns', onClose: function () { clearInterval(connT); connT = null; S.connMac = null; } });
  S.connMac = d.mac;
  var tick = function () { if (document.hidden || S.connMac !== d.mac) return; loadConns(d.mac).then(function () { paintConnSheet(); paintConnMini(d.mac); }); };
  clearInterval(connT); connT = setInterval(tick, 2000); tick();
}
function paintConnSheet() {
  var el = $('#cn-body'); if (!el || !S.connMac) return;
  var c = S.conn[S.connMac]; if (!c) return;
  if (c.err) { el.innerHTML = '<div class="note err">' + esc(c.err) + '</div>'; return; }
  var r = c.r || {}, list = r.conns || [];
  var bl = r.blocks || [];
  // 应用时长用完 / 类别封锁 自动生成的封锁(source=app_time|category)不能在这里单独解除
  var blocks = bl.length ? '<div class="dbox" style="margin-bottom:8px">' + bl.map(function (b) {
    var auto = { app_time: '时长用完', category: '类别封锁' }[b.source];
    var right = auto ? '<span class="badge ' + (b.source === 'category' ? 'b-red' : 'b-warn') + '" title="' + esc(b.source === 'category' ? '在设备卡「按类别封锁」里解除' : '次日 0 点自动恢复，或在「应用使用时长」里修改限时') + '">' + auto + (b.source === 'category' && b.ref ? ' · ' + esc(catLabel(b.ref)) : '') + (num(b.until) ? ' · 至 ' + pad2(new Date(num(b.until) * 1000).getHours()) + ':' + pad2(new Date(num(b.until) * 1000).getMinutes()) : '') + '</span>'
      : '<button class="linkish" data-cbdel="' + esc(b.kind + '|' + b.value) + '">解除</button>';
    return '<div class="row2"><span class="k" style="color:var(--text-1)">🚫 ' + esc(b.label ? b.label + ' · ' : '') + '<span class="mono">' + esc(b.value) + '</span>' + (b.kind === 'domain' ? '<span class="note"> 及子域名</span>' : '') + '</span>' + right + '</div>'; }).join('') + '</div>' : '';
  var head = blocks + '<div class="cn-sum"><span>共 <b>' + num(r.total) + '</b> 条' + (num(r.total) > list.length ? '（显示前 ' + list.length + '）' : '') + '</span><span>↓↑ <b>' + bpsTxt(r.bps) + '</b></span><span>累计 <b>' + bytes(num(r.down_bytes) + num(r.up_bytes)) + '</b></span></div>' + connNotes(r);
  if (S.connView === 'group') {
    var gs = r.groups || [], mx = Math.max.apply(null, gs.map(function (g) { return num(g.bps) || num(g.bytes) / 1e6; }).concat([1]));
    el.innerHTML = head + (gs.length ? gs.map(function (g, i) { var v = num(g.bps) || num(g.bytes) / 1e6; return '<div class="hbar"><span class="n">' + esc(g.label) + '</span><span><i class="b" style="display:block;width:' + Math.max(2, v / mx * 100).toFixed(1) + '%;background:' + HIST_COLORS[i % 8] + ';animation:none"></i></span><span class="v">' + num(g.n) + ' 条 · ' + (num(g.bps) ? bpsTxt(g.bps) : bytes(g.bytes)) + '</span></div>'; }).join('') : '<div class="note">当前没有连接</div>');
    return;
  }
  if (S.connView === 'active') list = list.filter(function (x) { return num(x.down_bps) + num(x.up_bps) > 0; });
  el.innerHTML = head + (list.length ? list.map(connRow).join('') : '<div class="note">' + (S.connView === 'active' ? '这 2 秒内没有收发数据的连接' : '当前没有连接') + '</div>');
}
function appLimitRows(d) {
  var items = S.appLimits.filter(function (x) { return String(x.mac || '').toLowerCase() === d.mac; });
  var map = {}, rows = [];
  items.forEach(function (x) { map[x.app_id] = x; rows.push({ id: x.app_id, name: x.app_id, lim: num(x.down_mbps), it: x }); });
  d.live.concat(d.apps).slice(0, 8).forEach(function (a) {
    var id = a.id || a.app_id || a.name; if (!id || id.charAt(0) === '_') return;   // _tunnel 等伪应用不能按应用限速
    if (map[id]) { rows.forEach(function (r) { if (r.id === id) r.name = a.name || id; }); return; }
    map[id] = 1; rows.push({ id: id, name: a.name || id, lim: 0 });
  });
  if (!rows.length) return '<div class="note">还没识别到这台设备在用的应用（需要 DPI 在运行）</div>';
  return rows.map(function (r) {
    return '<div class="appq" data-app="' + esc(r.id) + '"><span class="n">' + esc(r.name) + '</span><span class="box"><input type="number" min="0" step="0.1" placeholder="不限" value="' + mbpsToMBs(r.lim) + '"><span class="u">MB/s</span></span>' +
      '<span style="display:flex;gap:10px"><button class="linkish" data-act="applim-save">保存</button>' + (r.lim ? '<button class="linkish danger" data-act="applim-clear">清除</button>' : '') + '</span>' + appLimNote(r.it) + '</div>';
  }).join('');
}
/* 应用限速按目的 IP 生效; 与其他应用共用的 CDN 地址默认跳过(否则会误伤) */
function appLimNote(x) {
  if (!x || !(num(x.down_mbps) > 0) || x.ip_stats_source === 'sim' || typeof x.ips_total !== 'number') return '';
  var t = num(x.ips_total), sk = num(x.ips_shared_skipped), l = num(x.ips_limited);
  if (!t) return '<div class="note appq-n">还没观察到这个应用的服务器地址，它联网后自动生效</div>';
  if (!l) return '<div class="note warn appq-n">这个应用的地址都与其他应用共用，限速暂未生效' + (sk ? '（跳过 ' + sk + ' 个共享 CDN 地址）' : '') + '</div>';
  return '<div class="note appq-n">已限速 ' + l + ' 个地址' + (sk ? ' · 跳过 ' + sk + ' 个共享 CDN 地址' : '') + (S.appLimitShared ? ' · 含共享地址' : '') + '</div>';
}
function devCard(d) {
  var r = bps(d.rx), t = bps(d.tx), open = !wide() && S.open[d.mac], closing = !open && !wide() && S.closingAt && Date.now() - (S.closingAt[d.mac] || 0) < 800;
  var meta = d.online ? (d.ip || '—') : d.blocked ? '已阻止联网' : '最后出现 ' + ago(d.lastSeen);
  return '<article class="glass dev' + (open ? ' open' : '') + (wide() && S.sel === d.mac ? ' sel' : '') + (S.picked[d.mac] ? ' picked' : '') + '" data-dev="' + d.mac + '">' +
    '<button class="dev-h" data-act="toggle-dev" aria-expanded="' + !!open + '"><span class="check">' + ico('check') + '</span>' +
      '<span class="av">' + d.icon + '<span class="dot ' + (d.blocked ? 'blocked' : d.online ? 'online' : 'offline') + '"></span></span>' +
      '<span class="dev-info"><span class="dev-name"><span class="nm">' + esc(d.name) + '</span>' + badges(d) + '</span>' +
        '<span class="dev-meta mono" style="display:block">' + esc(d.ip || '—') + ' · ' + d.mac + '</span>' +
        '<span class="dev-meta" style="display:block">' + esc(d.online ? (d.idShort || d.vendor || '在线') : (d.idShort ? d.idShort + ' · ' : '') + meta) + '<span id="ct-' + d.mac.replace(/:/g, '') + '">' + connCountText(d) + '</span><span id="oh-' + d.mac.replace(/:/g, '') + '"></span><span id="mu-' + d.mac.replace(/:/g, '') + '"></span></span>' +
        '<span class="dev-apps" data-apps' + (appsLine(d) ? '' : ' hidden') + '>' + appsLine(d) + '</span>' +
      '</span>' +
      (d.online ? '<span class="dev-rate num"><span class="d">↓ <b data-rx>' + r.v + '</b> ' + r.u + '</span><span class="u">↑ <b data-tx>' + t.v + '</b> ' + t.u + '</span>' + ico(wide() ? 'right' : 'chev', 'chev') + '</span>'
        : '<span class="dev-rate"><span class="off">' + (d.blocked ? '已阻止' : '离线') + '</span>' + ico(wide() ? 'right' : 'chev', 'chev') + '</span>') +
    '</button>' + mergeRowHtml(d) + (wide() ? '' : '<div class="fold"><div><div class="fold-in">' + (open || closing ? devBody(d) : '') + '</div></div></div>') +
  '</article>';
}
/* 「在用」= 此刻按实时速率排出来的应用(后端 conntrack 平滑); 没有实时数据时退回 DPI 的"最近识别" */
function callBadge(d) {
  if (!d.online || !d.call) return '';
  var m = Math.max(0, Math.floor((Date.now() / 1000 - num(d.call.since)) / 60));
  return '<span class="a call">📞 ' + esc(d.call.label) + (m ? ' ' + m + ' 分钟' : '') + '</span>';
}
var CAT_T = { video: '视频', social: '社交', social_voip: '通话', game: '游戏', shopping: '购物', music: '音乐', office: '办公', ai: 'AI', reading: '阅读', news: '资讯', travel: '出行', navigation: '地图', life_service: '生活', download: '下载', browser: '浏览', photo: '图片', finance: '金融', education: '教育', cloud: '云服务', system: '系统' };
/* 此刻流量按分类的占比(来自「在用」的实时速率) */
function catShare(d) {
  if (!d.live || !d.live.length) return '';
  var m = {}, tot = 0;
  d.live.forEach(function (a) { var c = CAT_T[a.category] || (String(a.category || '').indexOf('system') === 0 ? '系统' : '其他'); m[c] = (m[c] || 0) + num(a.bps); tot += num(a.bps); });
  if (!tot) return '';
  return '此刻：' + Object.keys(m).sort(function (a, b) { return m[b] - m[a]; }).slice(0, 3).map(function (k) { return k + ' ' + Math.round(m[k] / tot * 100) + '%'; }).join(' · ');
}
/* DPI v2: 前台应用推断(fg) + 此刻的流量形态(traffic_type) */
function pct100(v) { v = num(v); return Math.round(v <= 1 ? v * 100 : v); }
function fgActive(d) { var f = d.fg; return d.online && f && f.state === 'active' && f.name ? f : null; }
function ttTag(d) { var t = d.ttype; return d.online && t && t.label && t.type !== 'background' ? '<span class="tt">此刻在：' + esc(t.label) + '</span>' : ''; }
function appsLine(d) {
  var cb = callBadge(d), f = fgActive(d);
  if (f) return '<span class="lb">正在用</span><span class="a fg">' + appNmH(f.app_id, f.name) + ' <small class="num">' + pct100(f.confidence) + '%</small></span>' + ttTag(d) + cb +
    d.live.filter(function (a) { return (a.id || a.app_id) !== f.app_id; }).slice(0, 2).map(function (a) { return '<span class="a dim' + (a.system ? ' sys' : '') + '">' + appNmH(a.id, a.name) + '</span>'; }).join('');
  if (cb && !d.live.length) return '<span class="lb">正在</span>' + cb;
  if (d.online && d.live.length) return '<span class="lb">在用</span>' + cb + d.live.slice(0, 3).map(function (a) { return '<span class="a' + (a.system ? ' sys' : '') + '">' + appNmH(a.id, a.name) + ' <small class="num">' + bpsTxt(a.bps) + '</small></span>'; }).join('');
  if (d.apps.length) return '<span class="lb">最近</span>' + d.apps.slice(0, 4).map(function (a) { return '<span class="a dim">' + appNmH(a.id, a.name) + (a.confidence === 'low' ? '?' : '') + '</span>'; }).join('');
  return '';
}
function devSide() {
  var d = devBy(S.sel);
  if (!d) return '<div class="glass empty">点左侧的设备查看和调整规则</div>';
  return '<div class="glass swap" data-side="' + d.mac + '"><div class="side-head"><span class="av">' + d.icon + '<span class="dot ' + (d.blocked ? 'blocked' : d.online ? 'online' : 'offline') + '"></span></span><div style="min-width:0"><div class="t">' + esc(d.name) + '</div><div class="s mono">' + esc(d.ip || '—') + ' · ' + d.mac + '</div></div></div>' +
    '<div style="padding:10px 14px 12px" class="dev-name">' + (badges(d) || '<span class="badge b-ok">无规则</span>') + '</div>' + mergeRowHtml(d) + devBody(d) + '</div>';
}
/* 列表顺序冻结: 有卡片展开着 / 刚在列表里点过 / 刚做完操作的几秒内, 已在屏幕上的卡片保持原来的先后,
 * 新出现的排到后面。此前封锁一台设备、改个名字, 下一次轮询它就按「在线 / 封锁 / 名字」重排跳到别处,
 * 手指下面换成了另一张卡。解冻后再按自然顺序重排, 由 renderDevList 做 FLIP 平滑移动。 */
var listFreezeUntil = 0, resortT = 0;
function freezeList(ms) {
  listFreezeUntil = Math.max(listFreezeUntil, Date.now() + (ms || 4000));
  clearTimeout(resortT); resortT = setTimeout(resortIfNeeded, listFreezeUntil - Date.now() + 80);
}
function listFrozen() { return Date.now() < listFreezeUntil || (!wide() && S.devices.some(function (d) { return S.open[d.mac]; })); }
function screenOrder() { return $$('#dev-list > .dev').map(function (e) { return e.getAttribute('data-dev'); }); }
function displayOrder(list) {
  if (!listFrozen()) return list;
  var cur = screenOrder(); if (!cur.length) return list;
  var pos = {}; cur.forEach(function (m, i) { pos[m] = i; });
  var idx = {}; list.forEach(function (d, i) { idx[d.mac] = i; });
  return list.slice().sort(function (a, b) { return (a.mac in pos ? pos[a.mac] : 1e6 + idx[a.mac]) - (b.mac in pos ? pos[b.mac] : 1e6 + idx[b.mac]); });
}
/* 解冻后屏幕上的顺序和自然顺序不一样 → 重排一次(FLIP 动画) */
function resortIfNeeded() {
  if (S.page !== 'devices' || listFrozen() || !$('#dev-list')) return;
  var want = visibleDevs().map(function (d) { return d.mac; }).join('|');
  if (want !== screenOrder().join('|')) renderDevList(false);
}
function devListHtml() {
  if (!S.devLoaded) return '<div class="skel"></div><div class="skel"></div><div class="skel"></div>';
  var all = displayOrder(visibleDevs());
  if (all.length) return all.map(devCard).join('');
  var msg = S.hotspot.active === false ? '热点未开启 · 在线设备会显示在这里' : S.q ? '没有匹配的设备，换个关键词试试' : S.filter === 'offline_rules' ? '没有留着规则的离线设备' : '暂无设备 · 连接热点后会出现在这里';
  return '<div class="glass empty">' + msg + '</div>';
}
function freshText() {
  if (!S.connected) return { t: S.bootErr ? '未连接后端' : '正在连接 HNC 后端…', c: S.bootErr ? 'err' : '' };
  var age = Math.round((Date.now() - S.lastOk) / 1000);
  var mode = { realtime: '实时模式', balanced: '均衡模式', powersave: '省电模式' }[S.refreshMode];
  if (age > 8) return { t: '数据可能已过期 · ' + age + ' 秒前 · 正在重试', c: 'stale' };
  return { t: '已更新 · ' + (age <= 1 ? '刚刚' : age + ' 秒前') + ' · ' + mode, c: '' };
}
function paintFresh() { var el = $('#fresh'); if (!el) return; var f = freshText(); el.textContent = f.t; el.className = 'fresh ' + f.c; }
function bridgeBanner() {
  if (S.connected) return '';
  if (!S.bootErr) return '<div class="banner info" id="bridge-card"><span class="bi"><b>…</b></span><div><div class="bt">正在连接 HNC 后端</div><div class="bm">' + (KSU ? '通过 KernelSU 桥接调用本机 hnc_httpd' : '正在请求本机服务') + '</div></div></div>';
  return '<div class="banner err" id="bridge-card"><span class="bi"><b>!</b></span><div style="min-width:0"><div class="bt">连不上 HNC 后端</div><div class="bm">' + esc(S.bootErr) + '</div>' +
    '<div class="btns"><button class="btn sec press" data-act="bridge-retry">重试连接</button>' + (KSU ? '<button class="btn sec press" data-act="bridge-start">重新拉起服务</button>' : '') + '</div></div></div>';
}
/* 模拟环境开着时的细横幅(数据里混有虚构设备) */
function simOn() { return S.cfg.sim_enabled === true || S.devices.some(function (d) { return d.sim; }); }
function simBannerHtml() {
  if (!simOn()) return '';
  return '<div class="banner info thin" id="sim-banner"><span class="bi"><b>模</b></span><div style="min-width:0"><div class="bt">模拟环境已开启 · 数据含模拟设备</div></div><button class="btn sec press" data-act="sim-off">关闭模拟</button></div>';
}
function paintSimBanner() { var el = $('#sim-bn'); if (el) { var h = simBannerHtml(); if (el._h !== h) { el._h = h; el.innerHTML = h; } } }
function simSet(on) {
  return api.action('sim_set', { enabled: String(on) }).then(function (r) {
    S.cfg.sim_enabled = on; toast(r && r.detail ? String(r.detail).slice(0, 60) : on ? '模拟环境已开启' : '模拟环境已关闭');
    return Promise.all([loadSim(), globalRefresh()]);
  }).then(function () { paintSimBanner(); if (S.page === 'settings') renderSettings(false); });
}
function renderOffloadBanner() {
  var el = $('#offload-banner'); if (!el) return;
  var show = S.offload.active && S.offload.detail && S.offload.detail !== 'PENDING' && !(S.offload.guard && S.offload.guard.fallback_active) && SS.get('hnc.hw-dismiss') !== S.offload.detail;
  el.hidden = !show;
}
function renderDevices(anim1) {
  var l = S.live || {}, on = S.devices.filter(function (d) { return d.online; }).length;
  var fl = FILTERS.filter(function (f) { return f[0] === S.filter; })[0];
  var h = '<div class="wrap' + (wide() ? ' dev-split' : '') + '"><div class="wrap" style="margin:0;max-width:none">' + bridgeBanner() + '<div id="sim-bn" style="display:contents">' + simBannerHtml() + '</div>' +
    '<div class="banner warn" id="offload-banner" hidden><span class="bi"><b>!</b></span><div style="min-width:0"><div class="bt">检测到硬件 offload 正在转发流量</div><div class="bm">系统的 BPF tether offload 可能绕过 tc，导致限速偏松。若限速失灵，可在系统设置里关闭热点硬件加速，或重开一次热点。</div></div><button class="bx" data-act="offload-dismiss" aria-label="忽略">×</button></div>' +
    '<div class="glass hero"><div><div class="hero-l">下行</div><div class="hero-v num"><span id="h-dn">0.00</span><span class="u">MB/s</span></div></div><div class="hero-div"></div>' +
    '<div><div class="hero-l">上行</div><div class="hero-v num"><span id="h-up">0.00</span><span class="u">MB/s</span></div></div><div class="hero-div"></div>' +
    '<div class="right"><div class="hero-l"><span class="breathe' + (S.hotspot.active === false ? ' off' : '') + '" id="h-dot"></span><span id="h-state">' + (S.hotspot.active === false ? '热点关' : '在线') + '</span></div><div class="hero-v num"><span id="h-on">' + num(l.online, on) + '</span><span class="u">/ <span id="h-total">' + num(l.total, S.devices.length) + '</span><span class="dw"> 设备</span></span></div></div>' +
    '<svg class="spark" id="spark" aria-label="近 60 秒下行速率"></svg></div>' +
    '<div class="fresh" id="fresh"></div>' +
    '<label class="glass search">' + ico('search') + '<input id="q" type="search" placeholder="搜索设备 · IP · MAC · 名称" value="' + esc(S.q) + '" autocomplete="off"></label>' +
    '<div class="glass filter"><div class="tx"><div class="t">设备过滤</div><div class="s">' + esc(fl[2]) + '</div></div>' +
      '<div class="dd"><button class="dd-btn press" data-act="dd"><span>' + fl[1] + '</span>' + ico('chev') + '</button><div class="dd-menu">' +
      FILTERS.map(function (f) { return '<button data-filter="' + f[0] + '" class="' + (f[0] === S.filter ? 'on' : '') + '">' + f[1] + ico('check') + '</button>'; }).join('') + '</div></div></div>' +
    '<div class="glass gops' + (S.open.gops ? ' open' : '') + '" id="gops"><button class="card-h" data-act="fold" data-key="gops">' + gi('orange', 'bolt') +
      '<span class="tx"><div class="t">全局操作</div><div class="s">白名单 · 刷新 · 清空 · 清理 · 释放</div></span>' + ico('chev', 'chev') + '</button>' +
      '<div class="fold"><div><div class="fold-in rows">' +
        '<div class="row">' + gi('green', 'home') + '<span class="tx"><div class="t">白名单模式</div><div class="s">仅允许白名单内的设备联网（在设备卡里把设备加入白名单）</div></span>' + toggle(S.cfg.whitelist_mode === true, 'data-act="wl-mode" aria-label="白名单模式"') + '</div>' +
        '<button class="row" data-act="refresh">' + gi('blue', 'refresh') + '<span class="tx"><div class="t">刷新设备列表</div><div class="s">重新扫描热点连接设备</div></span><span class="hint-a">刷新</span></button>' +
        '<button class="row" data-act="clear-all">' + gi('orange', 'trash') + '<span class="tx"><div class="t">清空所有规则</div><div class="s">移除全部限速、延迟、黑名单</div></span><span class="hint-a warn">清空</span></button>' +
        '<button class="row" data-act="clean-offline">' + gi('orange', 'trash') + '<span class="tx"><div class="t">清理离线设备</div><div class="s">移除 devices.json 中所有离线设备</div></span><span class="hint-a warn">清理</span></button>' +
        '<button class="row" data-act="release">' + gi('red', 'power') + '<span class="tx"><div class="t">释放并重启资源</div><div class="s">危险操作：清 tc / iptables 后自动拉起后端</div></span><span class="hint-a danger">重启</span></button>' +
      '</div></div></div></div>' +
    '<div class="toolbar"><button class="chip press' + (S.batch ? ' on' : '') + '" data-act="batch">' + ico('box') + '批量</button><button class="chip press" data-act="tpl">' + ico('star') + '模板</button></div>' +
    (S.batch ? '<div class="glass batchbar swap"><div class="top"><span>已选 <b class="num" id="picked-n">' + Object.keys(S.picked).length + '</b> 台</span><button class="hint-a" data-act="b-all">全选</button><button class="hint-a" data-act="b-none">清空</button><button class="hint-a" data-act="batch">退出</button></div>' +
      '<div class="btns"><button class="btn sec press" data-act="b-tpl">应用模板</button><button class="btn sec press" data-act="b-clear">清除限速</button><button class="btn sec press" data-act="b-cdelay">清除延迟</button><button class="btn dan press" data-act="b-block">加黑</button><button class="btn ok press" data-act="b-unblock">解黑</button></div></div>' : '') +
    '<div class="sec"><span>设备列表</span><span class="r"><span id="list-on">' + on + '</span> 在线 · 共 ' + S.devices.length + '</span></div>' +
    '<div class="dev-list' + (S.batch ? ' batch' : '') + '" id="dev-list">' + devListHtml() + '</div></div>' +
    (wide() ? '<div class="dev-side" id="dev-side">' + devSide() + '</div>' : '') + '</div>';
  var p = $('#p-devices');
  // 已有内容时就地更新(批量模式切换 / 过滤 / 重连): 不丢滚动位置和展开状态, 不重放入场动画
  if (!anim1 && p.firstElementChild) morph(p, h); else p.innerHTML = h;
  placeSegs(p); paintHero(false); drawSpark(); paintFresh(); renderOffloadBanner(); paintOnlineHours();
  if (anim1) stagger($('.wrap .wrap', p));
}
/* 列表刷新: 就地 morph(卡片按 data-dev 复用) + FLIP —— 位置变了的卡片从旧位置平滑移过去, 新卡片淡入 */
function renderDevList(animate) {
  var list = $('#dev-list'); if (!list) return;
  var before = {}, flip = !animate && motionOn() && list.firstElementChild;
  if (flip) $$('#dev-list > .dev').forEach(function (c) { before[c.getAttribute('data-dev')] = c.getBoundingClientRect().top; });
  // 卡片元素复用 → 正在输入的框、焦点、光标位置天然保留(此前整表 innerHTML 要先快照再还原)
  morph(list, devListHtml()); placeSegs(list); paintOnlineHours(); paintSimBanner();
  var lo = $('#list-on'); if (lo) lo.textContent = S.devices.filter(function (d) { return d.online; }).length;
  if (wide()) { var sd = $('#dev-side'); if (sd) { morph(sd, devSide()); placeSegs(sd); } }
  if (animate) { stagger(list); return; }
  if (flip) $$('#dev-list > .dev').forEach(function (c) {
    var m = c.getAttribute('data-dev'), y0 = before[m];
    if (y0 == null) { anim(c, [{ opacity: 0 }, { opacity: 1 }], { duration: 220, easing: 'ease-out' }); return; }
    var dy = y0 - c.getBoundingClientRect().top;
    if (Math.abs(dy) > 2) anim(c, [{ transform: 'translateY(' + dy.toFixed(1) + 'px)' }, { transform: 'none' }], { duration: 320, easing: EASE.soft });
  });
}
function paintHero(tw) {
  var l = S.live || {}, dn = num(l.rx_bps) / 1048576, up = num(l.tx_bps) / 1048576;
  if (tw) { tween($('#h-dn'), dn, 2); tween($('#h-up'), up, 2); }
  else if ($('#h-dn')) { $('#h-dn').textContent = dn.toFixed(2); $('#h-up').textContent = up.toFixed(2); }
  if ($('#h-on')) { $('#h-on').textContent = num(l.online, 0); $('#h-total').textContent = num(l.total, S.devices.length); }
  var dot = $('#h-dot'); if (dot) { dot.classList.toggle('off', S.hotspot.active === false); $('#h-state').textContent = S.hotspot.active === false ? '热点关' : '在线'; }
}
function drawSpark() {
  var el = $('#spark'); if (!el) return;
  var s = S.spark.length > 1 ? S.spark : [0, 0], W = Math.round(el.clientWidth) || 300, H = 40, mx = Math.max.apply(null, s) * 1.15 || 1, st = W / (s.length - 1);
  var pts = s.map(function (v, i) { return [i * st, H - 3 - v / mx * (H - 8)]; });
  var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' '), last = pts[pts.length - 1];
  el.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  el.innerHTML = '<defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--rx)" stop-opacity=".25"/><stop offset="1" stop-color="var(--rx)" stop-opacity="0"/></linearGradient></defs>' +
    '<path d="' + line + ' L' + W + ' ' + H + ' L0 ' + H + ' Z" fill="url(#sg)"/><path d="' + line + '" fill="none" stroke="var(--rx)" stroke-width="2" stroke-linejoin="round"/>' +
    '<circle cx="' + last[0] + '" cy="' + last[1] + '" r="3.5" fill="var(--rx)" stroke="var(--card-solid)" stroke-width="2"/>';
}
/* 轮询里的就地刷新: 只改速率数字, 不重建卡片(展开中的卡片与正在输入的框不受影响) */
function patchRates() {
  S.devices.forEach(function (d) {
    var c = document.querySelector('.dev[data-dev="' + d.mac + '"]'); if (!c) return;
    var rx = $('[data-rx]', c), tx = $('[data-tx]', c);
    if (rx) { var a = bps(d.rx), b = bps(d.tx); rollNum(rx, a.v, a.u); rollNum(tx, b.v, b.u); rx.parentNode.lastChild.textContent = ' ' + a.u; tx.parentNode.lastChild.textContent = ' ' + b.u; }
    var al = $('[data-apps]', c); if (al) { var h = appsLine(d); if (al._h !== h) { al._h = h; al.innerHTML = h; al.hidden = !h; } }
  });
}
// 苹果风「数字滚动」—— 单位没变时从旧值滚到新值; 否则直接替换
function rollNum(el, str, unit) {
  var sameUnit = (el.parentNode.lastChild.textContent || '').trim() === unit;
  if (!apple() || !fxOn('num') || !sameUnit || !/^\d+(\.\d+)?$/.test(str)) { el.textContent = str; return; }
  tween(el, parseFloat(str), (str.split('.')[1] || '').length);
}
function shapeOf() { return S.devices.map(function (d) { return [d.mac, d.merge ? d.merge.old_mac + '/' + d.merge.score : '', d.vpn ? d.vpn.level : '', d.rmac ? 1 : 0, d.mergedInto, d.online ? 1 : 0, d.blocked ? 1 : 0, d.down, d.up, d.delay, d.jitter, d.loss, d.sqm ? 1 : 0, d.wl ? 1 : 0, d.name, d.limitMode, d.delayMode, d.applyError, d.sim ? 1 : 0,
  d.eff ? [d.eff.reason, d.eff.blocked ? 1 : 0, d.eff.down_mbps, d.eff.up_mbps, d.eff.apply_error || ''].join(',') : '', d.quota ? [d.quota.state, d.quota.applied ? 1 : 0, d.quota.daily_gb, d.quota.monthly_gb, d.quota.action].join(',') : '',
  d.sched ? d.sched.windows.length + ',' + d.sched.active_window_index : '', d.atl.map(function (x) { return x.app_id + (x.exhausted ? '!' : '') + x.minutes; }).join(','), d.cblocks.map(function (x) { return x.category; }).join(',')].join(':'); }).join('|'); }
function refreshCard(mac) {
  var d = devBy(mac); if (!d) return;
  var el = document.querySelector('.dev[data-dev="' + mac + '"]');
  if (el) { el = morphOuter(el, devCard(d)); placeSegs(el); paintOnlineHours(); }
  if (wide() && S.sel === mac) { var sd = $('#dev-side'); if (sd) { morph(sd, devSide()); placeSegs(sd); } }
}

/* ═════════════════════ 设备操作 ═════════════════════ */
function setBusy(mac, on) {
  if (on) S.busy[mac] = 1; else delete S.busy[mac];
  $$('[data-dev="' + mac + '"] .btn, [data-side="' + mac + '"] .btn').forEach(function (b) { if (b.dataset.act && b.dataset.act !== 'copy-mac' && b.dataset.act !== 'rename') b.disabled = !!on; });
  $$('.dev[data-dev="' + mac + '"], [data-side="' + mac + '"]').forEach(function (c) { if (on) c.setAttribute('aria-busy', 'true'); else c.removeAttribute('aria-busy'); });
}
/* 请求进行中的视觉状态: 按钮 → .busy(禁用 + 稍后出转圈, 防重复提交); 开关 / 分段 → .pending(保持乐观状态, 不被后台刷新改回) */
function pend(el, on) {
  if (!el || !el.classList) return;
  var t = el.matches('.seg button') ? el.parentNode : el, cls = t.classList.contains('toggle') || t.classList.contains('seg') ? 'pending' : 'busy';
  t.classList.toggle(cls, !!on);
  if (on) t.setAttribute('aria-busy', 'true'); else t.removeAttribute('aria-busy');
  if (cls === 'busy' && t.tagName === 'BUTTON') { if (on) { t._wasDis = t.disabled; t.disabled = true; } else if (!t._wasDis) t.disabled = false; }
}
/* 通用: 按钮在 promise 结束前保持忙碌状态 */
function busyWhile(el, p) { pend(el, true); return Promise.resolve(p).then(function (r) { pend(el, false); return r; }, function (e) { pend(el, false); throw e; }); }
/* 卡片级动作: 加锁 → 执行 → 拉一次设备 → (弹层收起后)就地更新这张卡 → 成功提示
 * 成功提示和界面变化同时出现; 失败立即提示并按后端真实状态回滚(开关只回滚一次, 不会来回闪)。
 * 期间列表顺序冻结, 卡片不会因为状态变化被重排到别处。 */
function devAct(mac, fn, okMsg, src) {
  if (S.busy[mac]) { toast('这台设备还有操作在进行', 'warn'); return Promise.resolve(false); }
  setBusy(mac, true); pend(src, true); freezeList(6000);
  var ok = false, msg = '';
  return Promise.resolve().then(fn).then(function (r) {
    ok = true; msg = okMsg ? (typeof okMsg === 'function' ? okMsg(r) : okMsg) : '';
  }, function (e) { toast(errText(e), 'err'); }).then(function () {
    return loadDevices().catch(function () {});
  }).then(sheetSettled).then(function () {
    setBusy(mac, false); pend(src, false);
    refreshCard(mac); updateStatsCounters(); freezeList(4000);
    if (ok && msg) toast(msg);
    return ok;
  });
}
function readNum(ctx, f) { var el = $('[data-f="' + f + '"]', ctx); return el ? num(el.value) : 0; }
function limitParams(d, downMbps, upMbps) {
  var p = { mac: d.mac };
  if (downMbps > 0) p.rate_down = fmtRate(downMbps);
  if (upMbps > 0 && upOk()) p.rate_up = fmtRate(upMbps);
  return p;
}
function doLimit(d, downMbps, upMbps) {
  if (!htbOk()) return Promise.reject(new Error('当前内核 / tc 不支持 HTB，限速不可用'));
  if (!(downMbps > 0) && !(upMbps > 0 && upOk())) return api.action('rule_clear', { mac: d.mac });
  return api.action('rule_set', limitParams(d, downMbps, upMbps));
}
function doDelay(d, delay, jitter, loss) {
  if (!(delay > 0) && !(jitter > 0) && !(loss > 0)) return api.action('delay_clear', { mac: d.mac });
  if (!netemOk()) return Promise.reject(new Error('当前内核 / tc 不支持 netem，延迟注入不可用'));
  if (d.sqm) return Promise.reject(new Error('先关闭低延迟模式再注入延迟'));
  return api.action('delay_set', { mac: d.mac, delay_ms: Math.round(delay), jitter_ms: Math.round(jitter), loss_pct: trim0(clamp(loss, 0, 100).toFixed(2)) });
}
/* 网关保护: 看起来像路由器/网关的设备, 封锁前多问一句(旧版告警面板里的「拉黑」绕过了这一步) */
function looksLikeGateway(d) { return /\.(1|254)$/.test(d.ip || '') || (d.iface && d.iface === 'wlan0'); }
function confirmBlock(d) {
  if (!looksLikeGateway(d)) return Promise.resolve(true);
  return confirmSheet('确认封锁 ' + d.name + '？', '这台设备的 IP（' + esc(d.ip || '—') + '）看起来像网关或上游路由器。封锁它可能让整个热点断网。', '仍然封锁');
}
function blockDevice(d) {
  return confirmBlock(d).then(function (ok) {
    if (!ok) return false;
    return devAct(d.mac, function () { return api.action('bl_add', { mac: d.mac }); }, d.name + ' 已封锁');
  });
}
function renameSheet(mac, name, after) {
  sheet('<h3>重命名设备</h3><div class="sub mono">' + esc(mac) + '</div>' +
    '<label class="field"><span class="box"><input id="rn" value="' + esc(name) + '" maxlength="32" placeholder="留空 = 恢复自动识别的名字" style="font-family:var(--font)"></span></label>' +
    '<div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>取消</button><button class="btn pri press" id="rn-ok">保存</button></div>');
  var inp = $('#rn'); setTimeout(function () { try { inp.focus(); inp.select(); } catch (_) {} }, 350);
  function save() {
    var v = inp.value.trim().slice(0, 32); closeSheet();
    devAct(mac, function () { return api.action('device_rename', { mac: mac, name: v }); }, v ? '已重命名为 ' + v : '已恢复自动名称').then(function () { if (after) after(); });
  }
  $('#rn-ok').onclick = save;
  inp.addEventListener('keydown', function (e) { if (e.key === 'Enter') save(); });
}
function loadTrend(d, box) {
  var el = $('[data-trend]', box); if (!el) return;
  el.className = ''; el.setAttribute('data-keep', ''); el.innerHTML = '<div class="note">加载中…</div>';   // data-keep: 后台刷新卡片时不把图表冲掉
  return api.get('/api/dpi_history', { days: 7, mac: d.mac }, { timeout: 12000 }).then(function (r) {
    var hrs = r.by_hour || [], tot = num(r.total_rx) + num(r.total_tx);
    if (!hrs.length || !tot) { el.innerHTML = '<div class="note">这台设备 7 天内没有 DPI 流量记录</div>'; return; }
    var mx = Math.max.apply(null, hrs.map(function (h) { return num(h.rx) + num(h.tx); })) || 1;
    el.innerHTML = '<div class="mini-bars">' + hrs.map(function (h, i) { var v = num(h.rx) + num(h.tx); return '<i title="' + i + ':00 · ' + bytes(v) + '" style="height:' + Math.max(1.5, v / mx * 100).toFixed(1) + '%;animation-delay:' + (i * 15) + 'ms"></i>'; }).join('') + '</div>' +
      '<div class="mini-axis"><span>0 时</span><span>6</span><span>12</span><span>18</span><span>23</span></div>' +
      '<div class="note" style="margin-top:6px">7 天合计 ↓ ' + bytes(r.total_rx) + ' · ↑ ' + bytes(r.total_tx) + '</div>';
  }).catch(function (e) { el.innerHTML = '<div class="note err">' + esc(errText(e)) + '</div>'; });
}

/* ═════════════════════ 模板(限速 + 延迟一起生效) ═════════════════════ */
function tplDesc(t) {
  var a = [];
  if (t.down || t.up) a.push('↓ ' + (mbpsToMBs(t.down) || '∞') + ' / ↑ ' + (mbpsToMBs(t.up) || '∞') + ' MB/s'); else a.push('不限速');
  if (t.delay || t.jitter || t.loss) a.push('延迟 ' + t.delay + 'ms' + (t.jitter ? ' ±' + t.jitter : '') + (t.loss ? ' · 丢包 ' + t.loss + '%' : '')); else a.push('无延迟');
  return a.join(' · ');
}
function applyTemplate(targets, t) {
  var ok = 0, fail = 0, skipped = 0, wantDelay = t.delay > 0 || t.jitter > 0 || t.loss > 0;
  toast('正在把「' + t.name + '」应用到 ' + targets.length + ' 台…');
  var chain = Promise.resolve();
  targets.forEach(function (d) {
    chain = chain.then(function () {
      setBusy(d.mac, true);
      return doLimit(d, t.down, t.up).then(function () {
        if (wantDelay) {
          if (!netemOk() || d.sqm) { skipped++; return; }
          return doDelay(d, t.delay, t.jitter, t.loss);
        }
        if (d.hasDelay) return api.action('delay_clear', { mac: d.mac });
      }).then(function () { ok++; }, function () { fail++; }).then(function () { setBusy(d.mac, false); });
    });
  });
  return chain.then(function () {
    toast('「' + t.name + '」已应用 ' + ok + '/' + targets.length + ' 台' + (fail ? ' · 失败 ' + fail : '') + (skipped ? ' · ' + skipped + ' 台跳过延迟（低延迟模式或不支持 netem）' : ''), fail ? 'warn' : 'ok');
    return loadDevices().catch(function () {});
  }).then(function () { if (S.page === 'devices') renderDevList(false); });
}
function tplSheet(targets, manage) {
  var rows = S.templates.map(function (t, i) {
    return '<div class="row" style="padding:10px 2px">' + gi(['green', 'blue', 'orange', 'purple', 'red', 'cyan'][i % 6], 'star') +
      '<button class="tx" data-tpl-i="' + i + '" style="text-align:left"><div class="t">' + esc(t.name) + '</div><div class="s">' + esc(tplDesc(t)) + '</div></button>' +
      '<button class="linkish" data-tpl-edit="' + i + '">编辑</button></div>';
  }).join('');
  sheet('<h3>' + (manage ? '限速模板' : '应用模板') + '</h3><div class="sub">' + (targets.length ? '点模板 → 应用到 ' + targets.length + ' 台设备（限速和延迟一起生效）' : '先在设备卡里展开一台设备，或进入批量模式勾选设备') + '</div>' +
    '<div class="rows">' + rows + '</div><div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>关闭</button><button class="btn pri press" id="tpl-new">' + ico('edit') + '新建模板</button></div>', { tall: true });
  $$('#sheet [data-tpl-i]').forEach(function (b) {
    b.onclick = function () {
      var t = S.templates[+b.getAttribute('data-tpl-i')];
      if (!targets.length) { toast('没有可应用的设备', 'warn'); return; }
      closeSheet(); applyTemplate(targets, t);
    };
  });
  $$('#sheet [data-tpl-edit]').forEach(function (b) { b.onclick = function () { tplEditor(S.templates[+b.getAttribute('data-tpl-edit')], targets); }; });
  $('#tpl-new').onclick = function () { tplEditor(null, targets); };
}
function tplEditor(t, targets) {
  var n = t || { name: '', down: 0, up: 0, delay: 0, jitter: 0, loss: 0 };
  function fld(lb, id, v, u, step) { return '<label class="field">' + lb + '<span class="box"><input id="' + id + '" type="number" min="0" step="' + (step || 1) + '" placeholder="0" value="' + (v || '') + '"><span class="u">' + u + '</span></span></label>'; }
  sheet('<h3>' + (t ? '编辑模板' : '新建模板') + '</h3><div class="sub">限速单位 MB/s，0 或留空 = 不限</div>' +
    '<div style="display:grid;gap:10px"><label class="field">名称<span class="box"><input id="te-name" maxlength="24" value="' + esc(n.name) + '" style="font-family:var(--font)"' + (t ? ' readonly' : '') + '></span></label>' +
    '<div class="grid2">' + fld('下行', 'te-down', mbpsToMBs(n.down), 'MB/s', 0.1) + fld('上行', 'te-up', mbpsToMBs(n.up), 'MB/s', 0.1) + '</div>' +
    '<div class="grid2" style="grid-template-columns:1fr 1fr 1fr">' + fld('延迟', 'te-delay', n.delay, 'ms') + fld('抖动', 'te-jitter', n.jitter, 'ms') + fld('丢包', 'te-loss', n.loss, '%', 0.1) + '</div></div>' +
    '<div class="btns" style="margin-top:14px">' + (t ? '<button class="btn dan press" id="te-del">删除</button>' : '<button class="btn sec press" id="te-back">返回</button>') + '<button class="btn pri press" id="te-save">保存</button></div>');
  if ($('#te-back')) $('#te-back').onclick = function () { tplSheet(targets); };
  $('#te-save').onclick = function () {
    var nt = { name: $('#te-name').value.trim(), down: mbsToMbps($('#te-down').value), up: mbsToMbps($('#te-up').value), delay: Math.round(num($('#te-delay').value)), jitter: Math.round(num($('#te-jitter').value)), loss: clamp(num($('#te-loss').value), 0, 100) };
    if (!nt.name || /[\\"\n\r\t]/.test(nt.name)) { toast('模板名不能为空，也不能含引号/反斜杠', 'err'); return; }
    saveTemplate(nt).then(function () { tplSheet(targets); });
  };
  if ($('#te-del')) $('#te-del').onclick = function () { deleteTemplate(n.name).then(function () { tplSheet(targets); }); };
}
function persistLocalTemplates() { LS.set('hnc.templates', JSON.stringify(S.templates)); }
function saveTemplate(nt) {
  var i = S.templates.findIndex(function (x) { return x.name === nt.name; });
  if (i >= 0) S.templates[i] = nt; else S.templates.push(nt);
  persistLocalTemplates();
  return api.action('template_set', { name: nt.name, down_mbps: trim0(nt.down.toFixed(3)), up_mbps: trim0(nt.up.toFixed(3)), delay_ms: nt.delay, jitter_ms: nt.jitter, loss_pct: trim0(nt.loss.toFixed(2)) })
    .then(function () { toast('模板「' + nt.name + '」已保存'); }, function (e) { toast('已存到本机，但后端保存失败：' + errText(e), 'warn'); });
}
function deleteTemplate(name) {
  S.templates = S.templates.filter(function (x) { return x.name !== name; });
  if (!S.templates.length) S.templates = DEFAULT_TEMPLATES.slice();
  persistLocalTemplates();
  return api.action('template_del', { name: name }).then(function () { toast('模板已删除'); }, function (e) { toast('本机已删除，后端删除失败：' + errText(e), 'warn'); });
}

/* ═════════════════════ 全局操作 ═════════════════════ */
function globalRefresh(msg) {
  return Promise.all([loadLive().catch(function () {}), loadDevices().catch(function () {})]).then(function () {
    if (S.page === 'devices') { renderDevList(false); paintHero(true); paintFresh(); }
    if (msg) toast(msg);
  });
}
function doCleanOffline() {
  var off = S.devices.filter(function (d) { return !d.online; }), withRule = off.filter(function (d) { return d.hasRule; }).length;
  if (!off.length) { toast('没有离线设备'); return; }
  confirmSheet('清理离线设备', '共 ' + off.length + ' 台离线设备' + (withRule ? '，其中 ' + withRule + ' 台还留着规则' : '') + '。清理只影响列表，不影响在线设备。', '清理', {
    extra: withRule ? '<label class="cb"><input type="checkbox" id="co-rules"> 连同带规则的设备一起清理</label>' : '',
    read: function () { var c = $('#co-rules'); return { rules: !!(c && c.checked) }; }
  }).then(function (r) {
    if (!r) return;
    api.action('cleanup_offline_devices', { include_rules: r.rules ? '1' : '0' }).then(function (o) {
      var dt = detailJSON(o);
      toast('已清理 ' + num(dt.removed) + ' 台' + (num(dt.kept_with_rules) ? ' · 保留 ' + dt.kept_with_rules + ' 台带规则的' : ''));
      return globalRefresh();
    }).catch(function (e) { toast(errText(e), 'err'); });
  });
}
function doRelease() {
  confirmSheet('释放并重启资源', '会清掉 tc / iptables 规则，随后自动拉起后端；期间热点可能短暂断流，约 10 秒。', '释放并重启').then(function (ok) {
    if (!ok) return;
    api.action('cleanup_all', {}, { timeout: 30000, maxTime: 28 }).then(function () {
      toast('已释放，10 秒后检查后端…');
      setTimeout(function () { api.get('/api/health').then(function () { toast('后端已恢复'); boot(true); }, function (e) { S.connected = false; S.bootErr = errText(e); renderDevices(false); }); }, 10000);
    }).catch(function (e) { toast(errText(e), 'err'); });
  });
}
function setQos(kind, v, el) {
  var p = kind === 'mode' ? { mode: v } : { scale: v };
  busyWhile(el, api.action('qos_set', p)).then(function () {
    if (kind === 'mode') { S.cfg.tc_qos_mode = v; LS.set('hnc.qos-mode', v); } else { S.cfg.tc_qos_scale = +v; LS.set('hnc.qos-scale', v); }
    toast(kind === 'mode' ? '限速策略：' + (v === 'precise' ? '精确' : '兼容') + ' · 下次应用规则时生效' : '校准：' + ({ 100: '标准', 85: '稳准', 75: '严格' }[v] || v + '%'));
  }).catch(function (e) { toast(errText(e), 'err'); });
}
function setWhitelistMode(on, el) {
  busyWhile(el, api.action('whitelist_set', { enabled: on ? 'true' : 'false' })).then(function (r) {
    S.cfg.whitelist_mode = on;
    var cnt = S.devices.filter(function (d) { return d.wl; }).length;
    toast(on ? '白名单模式已开启 · 放行 ' + cnt + ' 台' : '白名单模式已关闭', on && !cnt ? 'warn' : 'ok');
    if (on && !cnt) setTimeout(function () { toast('提醒：还没有设备在白名单里，热点内设备都将无法上网', 'warn'); }, 2300);
  }).catch(function (e) { if (el) el.setAttribute('aria-checked', String(!on)); toast(errText(e), 'err'); });
}

