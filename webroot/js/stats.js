/* HNC WebUI · stats.js —— 分析页: 本月流量对账、流量统计、本机/热点流量(按 SIM)、DPI、未知应用发现 */
'use strict';

/* ═══ 本月流量 —— 与系统 NetworkStats 对账 ═══ */
var CAL_R = { disabled: '未对账（仅 HNC）', pending: '对账中', cycle_changed: '计费周期刚切换' };
function calHtml(r) {
  var c = r.calibration; if (!c || typeof c !== 'object') return '';
  var chip;
  if (c.status === 'ok') chip = '<span class="badge b-ok">与系统统计一致' + (c.hnc_vs_netstats_pct != null && !c.low_volume ? ' · ' + calFmtPct(c.hnc_vs_netstats_pct) : '') + '</span>';
  else if (c.status === 'drift') chip = '<span class="badge b-warn">与系统偏差 ' + calFmtPct(c.hnc_vs_netstats_pct) + '</span>';
  else chip = '<span class="badge b-gray"' + (c.reason ? ' title="' + esc(c.reason) + '"' : '') + '>' + (CAL_R[c.reason] || '系统统计不可用') + '</span>';
  if (c.stale && c.status !== 'unavailable') chip += '<span class="badge b-gray">结果已过期</span>';
  var lines = Array.isArray(c.text_cn) ? c.text_cn : [], off = c.offload_gap_pct != null && num(c.offload_gap_pct) >= 10;
  return '<div class="pu-cal">' + chip + '<span class="pu-ns">数据来源：' + (r.primary_source === 'netstats' ? '系统统计（与系统设置一致）' : 'HNC 自采') + (num(c.checked_at) ? ' · ' + ago(c.checked_at) + '对账' : '') + '</span></div>' +
    (lines.length ? '<div class="note warn">' + lines.map(esc).join('<br>') + (off ? '<br>系统统计包含被硬件转发的热点流量，HNC 看不到这部分，热点和设备流量会偏小；可在 设置 → 硬件加速兜底 里让流量走常规路径' : '') + '</div>' : '') +
    (c.low_volume ? '<div class="note">本期蜂窝流量还太少，偏差仅供参考</div>' : '');
}
function calSimLine(r, sm) {
  if (sm.netstats_cycle_used == null) return '';
  var c = r.calibration || {}, ns = (c.netstats_cell_by_sim || []).filter(function (x) { return num(x.slot) === num(sm.slot); })[0];
  if (r.primary_source === 'netstats' && sm.hnc_cycle_used != null) return '<div class="pu-ns">系统统计（当前采用）· HNC 自采 ' + bytes(sm.hnc_cycle_used) + '</div>';
  return '<div class="pu-ns">系统统计 ' + bytes(sm.netstats_cycle_used) + (ns && ns.hnc_vs_netstats_pct != null ? ' · HNC ' + calFmtPct(ns.hnc_vs_netstats_pct) : '') + '</div>';
}

/* ═════════════════════ 分析页 · 流量统计(原版统计页) ═════════════════════ */
var RANGE_T = { today: '今日 24 小时', week: '近 7 天', month: '近 30 天' };
S.stats = { today: null, week: null, month: null };
/* 统计页只用全量真实统计(iptables 计数器, 每个字节都算); 按应用的真实流量由 /api/app_usage(连接表字节)提供。 */
function loadStats(range) {
  return api.get('/api/stats', { source: 'legacy', range: range }, { timeout: 12000 }).then(function (r) { S.stats[range] = r.buckets || []; return S.stats[range]; });
}
function counts() {
  return [[S.devices.filter(function (d) { return d.online; }).length, '在线设备'], [S.devices.filter(function (d) { return d.limitOn; }).length, '限速中'],
    [S.devices.filter(function (d) { return d.hasDelay; }).length, '延迟注入'], [S.devices.filter(function (d) { return d.blocked; }).length, '已封锁']];
}
function updateStatsCounters() { $$('#p-stats [data-cnt]').forEach(function (el, i) { var c = counts()[i]; if (c) tween(el, c[0], 0); }); }
function renderStats(anim1) {
  var h = '<div class="wrap">' + seg('aseg', [['stats', '流量统计'], ['dpi', 'DPI 分析']], S.aseg) + '<div id="aseg-body" class="subview">' + (S.aseg === 'stats' ? statsBody() : dpiBody()) + '</div></div>';
  var p = $('#p-stats'); if (!anim1 && p.firstElementChild) morph(p, h); else p.innerHTML = h; placeSegs(p);
  if (anim1) stagger($('.wrap', p));
  afterAseg();
}
/* ═══ 本机 / 热点流量(按 SIM 卡、计费周期) ═══ */
S.puPeriod = 'cycle'; S.pu = {};
var PU_C = { cell: 'var(--blue)', wifi: 'var(--cyan)', hotspot: 'var(--orange)', local: 'var(--green)' };
function loadPhoneUsage(period, force) {
  var c = S.pu[period];
  if (c && !force && Date.now() - c.at < 60000) return Promise.resolve(c);
  return api.get('/api/phone_usage', { period: period }, { timeout: 10000 }).then(function (r) { S.pu[period] = { at: Date.now(), r: r }; S.puCfg = r.config || S.puCfg; })
    .catch(function (e) { S.pu[period] = { at: Date.now(), err: e && e.status === 404 ? '当前后端还没有本机流量统计（需要新版 hnc_httpd）' : errText(e) }; })
    .then(function () { return S.pu[period]; });
}
function md(ts) { var d = new Date(num(ts) * 1000); return (d.getMonth() + 1) + '/' + d.getDate(); }
function puBodyHtml() {
  var c = S.pu[S.puPeriod];
  if (!c) return '<div class="note">加载中…</div>';
  if (c.err) return '<div class="note ' + (/新版/.test(c.err) ? '' : 'err') + '">' + esc(c.err) + '</div>';
  var r = c.r || {}, cfg = r.config || {}, warn = num(cfg.warn_percent, 80), t = r.totals || {}, g = function (k) { return num(t[k] && t[k].total); };
  var h = '<div class="pu-cyc">' + (r.cycle_start ? '计费周期 ' + md(r.cycle_start) + ' – ' + md(num(r.cycle_end) - 1) + ' · 每月 ' + num(r.billing_day || cfg.billing_day, 1) + ' 号起算' : '') + (S.puPeriod !== 'cycle' && r.since ? ' · 当前查看 ' + md(r.since) + ' 起' : '') + '</div>';
  h += calHtml(r);   // 与系统统计对账
  var sims = Array.isArray(r.by_sim) ? r.by_sim : [];
  h += sims.length ? '<div>' + sims.map(function (sm) {
    var lab = num(sm.slot) ? '卡' + num(sm.slot) + (sm.carrier ? ' · ' + sm.carrier : '') : '蜂窝（未知卡）', plan = num(sm.plan_bytes), used = num(sm.cycle_used), pct = sm.used_pct == null ? null : num(sm.used_pct);
    return '<div class="pu-sim"><div class="h"><span class="n">' + esc(lab) + (sm.is_default_data ? '<span class="badge b-acc">上网卡</span>' : '') + '</span><span class="v num">' + bytes(used) + (plan ? '<span style="color:var(--text-3);font-weight:500"> / ' + trim0(gb(plan).toFixed(1)) + ' GB</span>' : '') + '</span></div>' +
      (plan && pct != null ? '<div class="pbar' + (pct >= 100 ? ' over' : pct >= warn ? ' warn' : '') + '"><i style="width:' + clamp(pct, 0, 100).toFixed(1) + '%"></i></div><div class="note' + (pct >= 100 ? ' err' : pct >= warn ? ' warn' : '') + '">本期已用 ' + trim0(pct.toFixed(1)) + '%' + (pct >= 100 ? ' · 已超出套餐 ' + bytes(used - plan) : ' · 剩余 ' + bytes(plan - used)) + '</div>'
        : '<div class="note">本期已用 · ' + (num(sm.slot) ? '没设套餐，在下方「套餐与计费日」里填' : '没认出是哪张卡') + '</div>') + calSimLine(r, sm) +
      '<div class="note">' + (S.puPeriod === 'cycle' ? '' : '所选时段 ' + bytes(sm.total) + ' · ') + '其中热点 ' + bytes(sm.hotspot_total) + '</div></div>';
  }).join('') + '</div>' : '<div class="note">这段时间还没有蜂窝流量记录</div>';
  h += '<div class="pu-tiles">' + [['蜂窝', g('cellular'), PU_C.cell], ['Wi-Fi', g('wifi'), PU_C.wifi], ['热点', g('hotspot'), PU_C.hotspot]].map(function (x) {
    return '<div class="pu-tile"><div class="l"><i style="background:' + x[2] + '"></i>' + x[0] + '</div><div class="v num">' + bytes(x[1]) + '</div></div>'; }).join('') + '</div>';
  var lo = g('local'), hs = g('hotspot'), tot = lo + hs;
  if (tot > 0) {
    var via = r.hotspot_via || {}, vt = function (k) { return num(via[k] && via[k].total); };
    h += '<div><div class="split"><i style="width:' + (lo / tot * 100).toFixed(1) + '%;background:' + PU_C.local + '"></i><i style="width:' + (hs / tot * 100).toFixed(1) + '%;background:' + PU_C.hotspot + '"></i></div>' +
      '<div class="split-l"><span><i style="background:' + PU_C.local + '"></i>本机 ' + bytes(lo) + ' · ' + Math.round(lo / tot * 100) + '%</span><span><i style="background:' + PU_C.hotspot + '"></i>热点 ' + bytes(hs) + ' · ' + Math.round(hs / tot * 100) + '%</span></div>' +
      (vt('cell') || vt('wifi') ? '<div class="note" style="margin-top:4px">热点走的上游：蜂窝 ' + bytes(vt('cell')) + ' · Wi-Fi ' + bytes(vt('wifi')) + (vt('unknown') ? ' · 未知 ' + bytes(vt('unknown')) : '') + '</div>' : '') + '</div>';
  }
  // 每天(今天按小时)堆叠: 蜂窝本机 / Wi-Fi 本机 / 热点。上游量含热点, 热点按蜂窝:Wi-Fi 比例从两者里扣掉, 三段相加 = 上游总量
  var rows = S.puPeriod === 'today' && Array.isArray(r.by_hour) ? r.by_hour.map(function (x) { return { l: pad2(num(x.h)) + ':00', c: num(x.cell), w: num(x.wifi), hs: num(x.hotspot) }; })
    : (r.by_day || []).map(function (x) { return { l: String(x.date || '').slice(5), c: num(x.cell), w: num(x.wifi), hs: num(x.hotspot) }; });
  if (rows.length) {
    rows.forEach(function (x) { var up = x.c + x.w, hs2 = Math.min(x.hs, up), k = up ? x.c / up : 0; x.cl = Math.max(0, x.c - hs2 * k); x.wl = Math.max(0, x.w - hs2 * (1 - k)); x.hh = hs2; x.t = x.cl + x.wl + x.hh; });
    var mx = Math.max.apply(null, rows.map(function (x) { return x.t; }).concat([1])), every = Math.max(1, Math.ceil(rows.length / 5));
    h += '<div><div class="note" style="margin-bottom:6px">' + (S.puPeriod === 'today' ? '今天每小时' : '每天') + ' · 峰值 ' + bytes(mx) + '</div><div class="stk">' + rows.map(function (x) {
      var f = function (v, col) { return v > 0 ? '<i style="height:' + (v / mx * 100).toFixed(2) + '%;background:' + col + '"></i>' : ''; };
      return '<span class="c" title="' + esc(x.l) + ' · 蜂窝 ' + bytes(x.c) + ' · Wi-Fi ' + bytes(x.w) + '（均含热点）· 热点 ' + bytes(x.hs) + '">' + f(x.cl, PU_C.cell) + f(x.wl, PU_C.wifi) + f(x.hh, PU_C.hotspot) + '</span>';
    }).join('') + '</div><div class="stk-ax">' + rows.filter(function (x, i) { return i % every === 0; }).map(function (x) { return '<span>' + esc(x.l) + '</span>'; }).join('') + '</div>' +
      '<div class="split-l" style="justify-content:flex-start;gap:12px"><span><i style="background:' + PU_C.cell + '"></i>蜂窝（本机）</span><span><i style="background:' + PU_C.wifi + '"></i>Wi-Fi（本机）</span><span><i style="background:' + PU_C.hotspot + '"></i>热点</span></div></div>';
  }
  var src = r.sources || {};
  h += '<div class="note">本机 = 上游（蜂窝 + Wi-Fi）− 热点设备，是近似值；套餐百分比永远按计费周期算。' + (src.sim_detect && src.sim_detect !== 'ok' ? '没认出当前上网卡，蜂窝流量先记在「未知卡」下。' : '') + (src.error ? ' 采样出错：' + esc(src.error) : '') + '</div>';
  return h;
}
function puSetSummary() { var c = S.puCfg; if (!c) return ''; var a = ['每月 ' + num(c.billing_day, 1) + ' 号']; if (num(c.plan_sim1_gb)) a.push('卡1 ' + trim0(num(c.plan_sim1_gb).toFixed(1)) + ' GB'); if (num(c.plan_sim2_gb)) a.push('卡2 ' + trim0(num(c.plan_sim2_gb).toFixed(1)) + ' GB'); if (c.use_netstats === 'prefer') a.push('以系统为准'); else if (c.use_netstats === 'off') a.push('仅 HNC'); return a.join(' · '); }
function puSetHtml() {
  var c = S.puCfg || {};
  return '<div class="grid2"><label class="field">计费日' + inp('pu-bd', c.billing_day || 1, '号', 'type="number" min="1" max="28" inputmode="numeric"') + '</label><label class="field">用到多少提醒' + inp('pu-warn', c.warn_percent || 80, '%', 'type="number" min="1" max="100" inputmode="numeric"') + '</label></div>' +
    '<div class="grid2"><label class="field">卡1 套餐' + inp('pu-p1', num(c.plan_sim1_gb) ? trim0(num(c.plan_sim1_gb).toFixed(2)) : '', 'GB', 'type="number" min="0" step="1" inputmode="decimal" placeholder="没有填 0"') + '</label><label class="field">卡2 套餐' + inp('pu-p2', num(c.plan_sim2_gb) ? trim0(num(c.plan_sim2_gb).toFixed(2)) : '', 'GB', 'type="number" min="0" step="1" inputmode="decimal" placeholder="没有填 0"') + '</label></div>' +
    '<div class="note">计费日填运营商每月重置流量的那天（1~28）。套餐填 0 = 不设，超过提醒比例会在告警里通知。</div><button class="btn pri press" data-act="pu-save">保存</button>' +
    (c.use_netstats != null ? '<div class="note" style="margin:6px 0 -2px;font-weight:600;color:var(--text-2)">数据来源</div>' + seg('pu-ns', [['auto', '自动'], ['prefer', '以系统为准'], ['off', '仅 HNC']], ['auto', 'prefer', 'off'].indexOf(c.use_netstats) >= 0 ? c.use_netstats : 'auto', 'small') +
      '<div class="note">自动：显示 HNC 自采的数值，同时与系统「流量使用」对账；以系统为准：卡的本期用量、套餐百分比和提醒改用系统统计（和系统设置里一致）；仅 HNC：不读系统统计。</div>' : '');
}
function paintPU() {
  var b = $('#pu-body'); if (b) b.innerHTML = puBodyHtml();
  var ss = $('#pu-set-s'); if (ss) ss.textContent = puSetSummary();
  var st = $('#pu-set'); if (st && !st.contains(document.activeElement) && !st._filled && S.puCfg) { st.innerHTML = puSetHtml(); st._filled = true; }
}
function refreshPU(force) { paintPU(); return loadPhoneUsage(S.puPeriod, force).then(function () { if (S.page === 'stats' && S.aseg === 'stats') paintPU(); }); }
function puSave() {
  var bd = Math.round(num($('#pu-bd').value)), w = Math.round(num($('#pu-warn').value)), p1 = $('#pu-p1').value.trim(), p2 = $('#pu-p2').value.trim();
  if (!(bd >= 1 && bd <= 28)) { toast('计费日填 1~28', 'err'); return; }
  if (!(w >= 1 && w <= 100)) { toast('提醒比例填 1~100', 'err'); return; }
  var p = { billing_day: bd, warn_percent: w };
  if (p1 !== '') { if (!(num(p1, -1) >= 0)) { toast('卡1 套餐填 0 或正数', 'err'); return; } p.plan_sim1_gb = trim0(num(p1).toFixed(2)); }
  if (p2 !== '') { if (!(num(p2, -1) >= 0)) { toast('卡2 套餐填 0 或正数', 'err'); return; } p.plan_sim2_gb = trim0(num(p2).toFixed(2)); }
  api.action('phone_usage_set', p).then(function () { toast('已保存 · 计费日 ' + bd + ' 号'); S.pu = {}; var st = $('#pu-set'); if (st) st._filled = false; return refreshPU(true); }).catch(function (e) { toast(errText(e), 'err'); });
}
function afterAseg() {
  if (S.aseg === 'stats') { updateStatsCounters(); refreshStats(); refreshPU(); }
  else { paintDpi(); loadDpi(true); }
}
function statsBody() {
  return '<div class="counters">' + counts().map(function (c) { return '<div class="glass counter"><div class="n num" data-cnt>0</div><div class="l">' + c[1] + '</div></div>'; }).join('') + '</div>' +
    '<div class="sec"><span>本月流量 <small>本机 · 热点</small></span>' + seg('pu-period', [['cycle', '本期'], ['today', '今天'], ['7d', '7天'], ['30d', '30天']], S.puPeriod, 'small') + '</div>' +
    '<div class="glass pu"><div id="pu-body" style="display:grid;gap:12px">' + puBodyHtml() + '</div><div class="pu-set dfold' + (S.open.puset ? ' open' : '') + '" data-foldkey="puset"><button class="ctrl-t dfold-h" data-act="fold" data-key="puset"><i style="background:var(--green)"></i><span class="dft">套餐与计费日</span><span class="dfs" id="pu-set-s">' + esc(puSetSummary()) + '</span>' + ico('chev', 'chev') + '</button><div class="fold"><div><div class="fold-in dfold-in" id="pu-set">' + puSetHtml() + '</div></div></div></div></div>' +
    '<div class="note" style="margin:2px 4px 10px">下面是全量真实统计 · 来自内核计数器，热点设备的每个字节都算在内（包括没识别出应用的流量）</div>' +
    '<div class="grid2"><div class="glass stat"><div class="l">今日下行</div><div class="v num"><span id="day-rx">0.00</span><span class="u">GB</span></div><div class="tr" id="day-rx-tr">&nbsp;</div></div>' +
      '<div class="glass stat"><div class="l">今日上行</div><div class="v num"><span id="day-tx">0.00</span><span class="u">GB</span></div><div class="tr" id="day-tx-tr">&nbsp;</div></div></div>' +
    '<div class="glass chart"><div class="chart-h"><h3 id="chart-title">' + RANGE_T[S.statsRange] + '</h3>' + seg('range', [['today', '24h'], ['week', '7d'], ['month', '30d']], S.statsRange, 'small') + '</div>' +
      '<div class="bars" id="bars"></div><div class="axis" id="axis"></div>' +
      '<div class="legend"><span><i style="background:var(--rx)"></i>下行</span><span><i style="background:var(--tx)"></i>上行</span><span style="margin-left:auto;color:var(--text-3)">点柱子看数值</span></div></div>' +
    '<div class="sec"><span>按应用 <small id="st-apps-t">' + RANGE_T[S.statsRange] + ' · 真实流量</small></span></div><div class="glass" style="padding:12px 14px" id="st-apps"><div class="note">加载中…</div></div>' +
    '<div class="glass' + (S.open.detail ? ' open' : '') + '" id="detail"><button class="card-h" data-act="fold" data-key="detail"><span class="tx"><div class="t">流量明细</div><div class="s">只列有流量的时段 · 点开查看</div></span>' + ico('chev', 'chev') + '</button>' +
      '<div class="fold"><div><div class="fold-in tbl" id="tbl"></div></div></div></div>' +
    '<div class="sec"><span>TC 命令参考</span></div>' +
    '<pre class="glass tcref"><span class="c"># 下行限速 (热点接口 egress)</span>\n<span class="k">tc</span> qdisc add dev ' + esc(S.hotspot.iface || 'wlan2') + ' root handle <span class="h">1:</span> htb default 999\n<span class="k">tc</span> class add dev ' + esc(S.hotspot.iface || 'wlan2') + ' parent <span class="h">1:</span> classid <span class="h">1:14</span> \\\n  htb rate <span class="v">10mbit</span> ceil <span class="v">10mbit</span>\n\n<span class="c"># 上行限速 (ingress 经 IFB)</span>\n<span class="k">tc</span> qdisc add dev ' + esc(S.hotspot.iface || 'wlan2') + ' handle <span class="h">ffff:</span> ingress\n<span class="k">tc</span> filter add dev ' + esc(S.hotspot.iface || 'wlan2') + ' parent <span class="h">ffff:</span> protocol ip \\\n  u32 match u32 0 0 action mirred egress redirect dev ifb0\n\n<span class="c"># 延迟注入 (netem)</span>\n<span class="k">tc</span> qdisc add dev ' + esc(S.hotspot.iface || 'wlan2') + ' parent <span class="h">1:14</span> handle <span class="h">101:</span> \\\n  netem delay <span class="v">200ms 20ms</span> loss <span class="v">1%</span></pre>';
}
var RANGE_DAYS = { today: 1, week: 7, month: 30 };
S.appUsage = {};
function loadAppUsage(days, force) {
  var c = S.appUsage[days];
  if (c && !force && Date.now() - c.at < 60000) return Promise.resolve(c.d);
  return api.get('/api/app_usage', { days: days }, { timeout: 12000 }).then(function (r) { S.appUsage[days] = { at: Date.now(), d: r }; return r; })
    .catch(function (e) { S.appUsage[days] = { at: 0, d: null, err: errText(e) }; return null; });
}
/* 按应用的真实流量(横条): 未识别 / 局域网 / SDK·CDN 用灰色, 真应用彩色 */
function appUsageBars(r, max) {
  var apps = (r.by_app || []).map(function (a) { return { id: a.id, n: a.name || a.id, v: num(a.up) + num(a.down), t: num(a.active_sec), inf: num(a.inferred_bytes), gray: a.id === '_unknown' || a.id === '_local' || a.sdk }; });
  var tot = num(r.total_up) + num(r.total_down);
  if (!tot) return '';
  var top = apps.slice(0, max || 8), rest = sum(apps.slice(max || 8), function (a) { return a.v; }); if (rest > 0) top.push({ n: '其他', v: rest, gray: true });
  var mx = Math.max.apply(null, top.map(function (a) { return a.v; }).concat([1])), unk = apps.filter(function (a) { return a.n === '未识别'; })[0];
  return '<div class="note" style="margin-bottom:6px">合计 ↓ ' + bytes(r.total_down) + ' · ↑ ' + bytes(r.total_up) + (unk ? ' · 未识别占 ' + Math.round(unk.v / tot * 100) + '%' : '') + (num(r.inferred_bytes) > 0 ? ' · 其中 ' + bytes(r.inferred_bytes) + ' 为推测归属' : '') + '</div>' +
    top.map(function (a, i) { return '<div class="hbar"><span class="n"' + (a.id === TUNNEL_ID ? ' title="VPN/代理隧道：隧道里的应用看不到，按协议特征归到这里"' : '') + '>' + appNmH(a.id, a.n) + '</span><span><i class="b" style="display:block;width:' + Math.max(2, a.v / mx * 100).toFixed(1) + '%;background:' + (a.gray ? 'var(--text-4)' : HIST_COLORS[i % 8]) + ';animation-delay:' + i * 40 + 'ms"></i></span><span class="v">' + bytes(a.v) + ' · ' + (a.v / tot * 100).toFixed(0) + '%' + (a.t >= 60 && !a.gray && a.id !== TUNNEL_ID ? '<small>使用 ' + fmtDur(a.t) + '</small>' : '') + (a.inf > 0 ? '<small title="目的地址没有域名，按同一时刻建连的应用推测">含推测 ' + bytes(a.inf) + '</small>' : '') + '</span></div>'; }).join('');
}
function paintStatsApps() {
  var el = $('#st-apps'); if (!el) return;
  var t = $('#st-apps-t'); if (t) t.textContent = RANGE_T[S.statsRange] + ' · 真实流量';
  var c = S.appUsage[RANGE_DAYS[S.statsRange]];
  if (!c) { el.innerHTML = '<div class="note">加载中…</div>'; return; }
  var r = c.d;
  if (!r) { el.innerHTML = '<div class="note err">' + esc(c.err || '加载失败') + '</div>'; return; }
  if (r.readable === false) { el.innerHTML = '<div class="note warn">读不到内核连接表，按应用统计不可用（总量统计不受影响）</div>'; return; }
  var h = appUsageBars(r, 8);
  el.innerHTML = h || '<div class="note">' + (r.acct === false ? '内核连接字节计数还没打开，已尝试打开，新连接开始计入' : '这段时间还没有按应用的记录（v5.16 起开始累计）') + '</div>';
}
function refreshStats() {
  return Promise.all([loadStats('today'), S.statsRange === 'today' || S.statsRange === 'week' ? loadStats('week') : Promise.all([loadStats('week'), loadStats(S.statsRange)])])
    .then(function () { paintDay(); renderBars(); loadAppUsage(RANGE_DAYS[S.statsRange]).then(paintStatsApps); })
    .catch(function (e) { var b = $('#bars'); if (b) b.innerHTML = '<div class="empty" style="position:absolute;inset:0;display:grid;place-items:center">' + esc(errText(e)) + '</div>'; });
}
function paintDay() {
  var t = S.stats.today || [], w = S.stats.week || [];
  var rx = sum(t, function (b) { return num(b.rx); }), tx = sum(t, function (b) { return num(b.tx); });
  tween($('#day-rx'), gb(rx), 2); tween($('#day-tx'), gb(tx), 2);
  var d = new Date(Date.now() - 86400000), k1 = d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()), k2 = pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  var y = w.filter(function (b) { return b.label === k1 || b.label === k2 || b.label === k1.replace(/-/g, ''); })[0] || (w.length > 1 ? w[w.length - 2] : null);
  [['#day-rx-tr', rx, y && num(y.rx)], ['#day-tx-tr', tx, y && num(y.tx)]].forEach(function (x) {
    var el = $(x[0]); if (!el) return;
    if (!x[2]) { el.textContent = '昨日无数据'; el.className = 'tr'; el.style.color = 'var(--text-3)'; return; }
    var pct = Math.round((x[1] - x[2]) / x[2] * 100); el.style.color = '';
    el.className = 'tr' + (pct < 0 ? ' dn' : ''); el.textContent = (pct >= 0 ? '↑ ' : '↓ ') + Math.abs(pct) + '% 较昨日';
  });
}
function niceTop(v) { if (!(v > 0)) return 1; var p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p, st = [1, 2, 2.5, 5, 10]; for (var i = 0; i < st.length; i++) if (n <= st[i]) return st[i] * p; return 10 * p; }
function renderBars() {
  var bars = $('#bars'); if (!bars) return;
  var data = S.stats[S.statsRange] || [];
  $('#chart-title').textContent = RANGE_T[S.statsRange];
  var tots = data.map(function (b) { return num(b.rx) + num(b.tx); }), mx = Math.max.apply(null, tots.concat([0]));
  if (!data.length || !mx) {
    bars.innerHTML = '<div class="empty" style="position:absolute;inset:0;display:grid;place-items:center;padding-left:30px">暂无采样数据</div>';
    $('#axis').innerHTML = ''; var tb0 = $('#tbl'); if (tb0) tb0.innerHTML = '<div class="empty">暂无数据</div>'; return;
  }
  var top = niceTop(gb(mx)), grid = '';
  [0, .5, 1].forEach(function (k) { grid += '<div class="gridl" style="bottom:' + (k * 100) + '%"></div><div class="gridt" style="bottom:calc(' + (k * 100) + '% - 6px)">' + trim0((top * k).toFixed(2)) + (k === 1 ? 'G' : '') + '</div>'; });
  bars.innerHTML = grid + data.map(function (b, i) {
    var r = gb(b.rx) / top * 100, t = gb(b.tx) / top * 100;
    return '<div class="bcol" data-i="' + i + '"><div class="bar tx" style="--i:' + i + ';height:' + (b.tx > 0 ? Math.max(t, .8) : 0).toFixed(2) + '%"></div><div class="bar rx" style="--i:' + i + ';height:' + (b.rx > 0 ? Math.max(r, .8) : 0).toFixed(2) + '%"></div></div>';
  }).join('');
  var every = Math.ceil(data.length / 7);
  $('#axis').innerHTML = data.map(function (b, i) { return '<span>' + (i % every === 0 ? esc(String(b.label).replace(/^\d{4}-/, '')) : '') + '</span>'; }).join('');
  var tot = sum(tots);
  $('#tbl').innerHTML = '<table><thead><tr><th>' + (S.statsRange === 'today' ? '时段' : '日期') + '</th><th>下行</th><th>上行</th><th>合计</th><th>占比</th></tr></thead><tbody>' +
    data.map(function (b, i) { var s = tots[i]; if (!s) return ''; return '<tr><td class="lb">' + esc(b.label) + '</td><td>' + bytes(b.rx) + '</td><td>' + bytes(b.tx) + '</td><td>' + bytes(s) + '</td><td class="pct"><i style="width:' + (s / mx * 100).toFixed(0) + '%"></i><span>' + (s / tot * 100).toFixed(1) + '%</span></td></tr>'; }).join('') + '</tbody></table>';
}
function barTip(col) {
  var bars = $('#bars'), b = (S.stats[S.statsRange] || [])[+col.getAttribute('data-i')]; if (!b) return;
  bars.classList.add('picking'); col.classList.add('pk');
  var tip = document.createElement('div'); tip.className = 'btip';
  tip.innerHTML = esc(b.label) + '<br><i style="background:var(--rx)"></i>下行 ' + bytes(b.rx) + '<br><i style="background:var(--tx)"></i>上行 ' + bytes(b.tx) + '<br>合计 ' + bytes(num(b.rx) + num(b.tx));
  var br = bars.getBoundingClientRect(), cr = col.getBoundingClientRect();
  tip.style.left = Math.min(Math.max(cr.left - br.left + cr.width / 2, 70), br.width - 70) + 'px';
  bars.appendChild(tip);
}

/* ═════════════════════ 分析页 · DPI ═════════════════════ */
var MODE_T = { af_packet: 'AF_PACKET 抓包', conntrack: 'conntrack 旁路', waiting: '等待热点', rebinding: '重新绑定中', unavailable: '不可用', blind: '盲区（无法抓包）' };
function loadDpi(full) {
  var ps = [api.get('/api/dpi_state', null, { timeout: 9000 }).then(function (r) {
    S.dpi = r; S.dpiErr = '';
    if (r && r.available && r.state) {
      S.self = r.state.self || S.self;
      var st = r.state.stats || {};
      ['packets', 'dns_events', 'tls_events', 'kernel_drops'].forEach(function (k) { var a = S.dpiSpark[k]; a.push(num(st[k])); if (a.length > 30) a.shift(); });
    }
  }).catch(function (e) { S.dpiErr = errText(e); })];
  if (full) {
    ps.push(api.getSafe('/api/dpi_probe', null, null).then(function (r) { S.probe = r && r.probe; }));
    ps.push(loadDpiHist(S.dpiDays)); ps.push(loadAppUsage(S.dpiDays)); ps.push(loadDpiUnk(S.dpiDays));
    if (KSU || S.procHealthOk !== false) ps.push(loadProcHealth());
    ps.push(loadDisc());
  }
  return Promise.all(ps).then(function () { if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); paintAppsDot(); });
}
function loadDpiHist(days, force) {
  var c = S.dpiHist[days];
  if (c && !force && Date.now() - c.at < 300000) return Promise.resolve(c.d);
  return api.get('/api/dpi_history', { days: days }, { timeout: 12000 }).then(function (r) { S.dpiHist[days] = { at: Date.now(), d: r }; return r; }).catch(function (e) { S.dpiHist[days] = { at: 0, d: null, err: errText(e) }; });
}
function loadProcHealth() {
  return api.get('/api/proc_health', null, { timeout: 9000 }).then(function (r) { S.proc = r; S.procHealthOk = true; }).catch(function () { S.proc = null; S.procHealthOk = false; });
}
function dpiBody() {
  return '<div id="dpi-hero"></div><div class="glass" id="disc-entry" style="margin-top:12px">' + discEntryHtml() + '</div><div class="cols"><div>' +
      '<div class="sec"><span>流量历史 <small>热点设备 · 按应用</small></span>' + seg('hist', [[1, '今日'], [3, '3 天'], [7, '7 天']], S.dpiDays, 'small') + '</div><div class="glass" style="padding:12px 14px" id="dpi-hist"></div>' +
      '<div class="sec"><span>活跃设备 <small>应用画像</small></span>' + seg('dflt', [['all', '全部'], ['active', '活跃'], ['high', '高置信']], S.dpiFilter, 'small') + '</div><div class="glass" id="dpi-clients"></div>' +
      '<div class="sec"><span>设备画像 <small>DHCP / mDNS / 域名被动指纹</small></span></div><div class="glass" id="dpi-ident"></div>' +
    '</div><div>' +
      '<div class="sec"><span>总体状态</span><button class="linkish" data-act="dpi-refresh">刷新</button></div><div class="glass rows" id="dpi-status"></div>' +
      '<div class="sec"><span>能力探测</span></div><div class="glass rows" id="dpi-probe"></div>' +
      '<div class="sec"><span>未识别流量 <small>规则库没认出的去向 · 按流量排序</small></span></div><div class="glass" id="dpi-unk2"></div>' +
      '<div class="sec"><span>补库助手 <small id="dpi-unknown-t">没被规则认出来的域名 · 一键生成规则模板</small></span></div><div class="glass sni" id="dpi-unknown"></div>' +
      '<div class="sec"><span>DPI 规则库</span></div><div class="glass' + (S.open.rules ? ' open' : '') + '" id="rules"><button class="card-h" data-act="fold" data-key="rules">' + gi('blue', 'doc') + '<span class="tx"><div class="t">导出 / 导入 / 在线更新</div><div class="s">自定义规则 JSON，最大 512 KB</div></span>' + ico('chev', 'chev') + '</button>' +
        '<div class="fold"><div><div class="fold-in set-body"><textarea class="textarea" id="rules-text" spellcheck="false" placeholder="点「导出」读取当前规则库，或粘贴规则 JSON 后点「导入」"></textarea>' +
        '<div class="btns" style="flex-wrap:wrap"><button class="btn sec press" data-act="rules-export">导出</button><button class="btn pri press" data-act="rules-import">导入</button></div>' +
        '<div class="btns" style="flex-wrap:wrap"><button class="btn sec press" data-act="rules-update">检查在线更新</button><button class="btn dan press" data-act="rules-reset">恢复内置</button></div><div class="out" id="rules-out" hidden></div></div></div></div></div>' +
    '</div></div>';
}
function fmtN(n) { n = num(n); return n >= 1e6 ? (n / 1e6).toFixed(2) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'K' : String(Math.round(n)); }
function sparkSvg(a, color) {
  if (!a || a.length < 2) return '<svg class="spark-mini"></svg>';
  var d = a.map(function (v, i) { return i ? Math.max(0, v - a[i - 1]) : 0; }).slice(1), mx = Math.max.apply(null, d) || 1, W = 100, H = 26, st = W / Math.max(1, d.length - 1);
  return '<svg class="spark-mini" viewBox="0 0 100 26" preserveAspectRatio="none"><path d="' + d.map(function (v, i) { return (i ? 'L' : 'M') + (i * st).toFixed(1) + ' ' + (H - 2 - v / mx * (H - 5)).toFixed(1); }).join(' ') + '" fill="none" stroke="' + color + '" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>';
}
function stRow(t, v, cls, s) { return '<div class="row"><span class="tx"><div class="t" style="font-weight:600">' + t + '</div>' + (s ? '<div class="s">' + s + '</div>' : '') + '</span><span class="v ' + (cls || '') + '">' + v + '</span></div>'; }
function paintDpi() {
  var hero = $('#dpi-hero'); if (!hero) return;
  var r = S.dpi, st = r && r.available && r.state, s = (st && st.stats) || {};
  var health = st ? (st.health || 'ok') : 'down', ok = st && !/stall|crash|down|error/i.test(health) && st.mode !== 'unavailable';
  var badge = !r ? ['加载中', 'b-gray'] : !st ? ['不可用', 'b-red'] : ok ? ['运行中', 'b-ok'] : [health, 'b-warn'];
  hero.innerHTML = '<div class="glass dpihero"><div class="top"><div><div class="l">识别模式</div><div class="mode">' + esc(st ? (MODE_T[st.mode] || st.mode || '—') : (S.dpiErr || (r && r.error) || 'dpid 未运行')) + '</div></div>' +
    '<span class="badge ' + badge[1] + '" style="font-size:12px;padding:5px 10px">' + (badge[1] === 'b-ok' ? '<span class="breathe"></span>&nbsp;' : '') + esc(badge[0]) + '</span></div>' +
    (st ? '<div class="note" style="margin-top:6px">' + esc(st.interface || '—') + ' · 运行 ' + hms(st.uptime_s) + (st.stall_seconds ? ' · 停滞 ' + st.stall_seconds + ' 秒' : '') + (st.blind_reason ? ' · ' + esc(st.blind_reason) : '') + ' · 客户端 ' + num(st.client_count) + '</div>' : '') +
    '<div class="grid">' + [['packets', '已抓包', 'var(--blue)'], ['dns_events', 'DNS 事件', 'var(--cyan)'], ['tls_events', 'TLS 事件', 'var(--purple)'], ['kernel_drops', '内核丢包', 'var(--red)']].map(function (x) {
      return '<div><div class="n num">' + fmtN(s[x[0]]) + '</div><div class="l">' + x[1] + '</div>' + sparkSvg(S.dpiSpark[x[0]], x[2]) + '</div>'; }).join('') + '</div></div>';
  // 状态
  var ur = st && st.unidentified_ratio, p = S.proc;
  $('#dpi-status').innerHTML = !st ? stRow('dpid', esc(S.dpiErr || (r && r.error) || '未运行'), 'bad') :
    stRow('健康度', esc(health), ok ? 'ok' : 'warn') + stRow('规则库', esc(st.l3_rule_version || '—') + (st.dfp_enabled ? ' · DFP' : ''), '') +
    stRow('识别覆盖', ur && ur.total_bytes ? Math.round((1 - num(ur.ratio)) * 100) + '%' : '—', '', ur && ur.total_bytes ? '已识别 ' + bytes(ur.identified_bytes) + ' / ' + bytes(ur.total_bytes) : '按字节') +
    stRow('去重域名', num(st.unique_sni) + ' SNI · ' + num(st.unique_hostnames) + ' 主机名 · ' + num(st.unique_ja4) + ' 种指纹', '') +
    (st.evidence_summary && st.evidence_summary.total ? stRow('证据账本', num(st.evidence_summary.total) + ' 条', '', Object.keys(st.evidence_summary.by_source || {}).map(function (k) { return k + ' ' + st.evidence_summary.by_source[k]; }).join(' · ')) : '') +
    stRow('重新绑定', num(st.rebind_count) + ' 次', '', '<button class="linkish" data-act="dpi-rebind">立即重新绑定</button>') +
    (p ? stRow('进程健康', esc(p.status || '—'), /ok|healthy/i.test(p.status) ? 'ok' : 'warn', p.counts ? 'dpid ' + num(p.counts.hnc_dpid) + ' · httpd ' + num(p.counts.hnc_httpd) + ' · hotspotd ' + num(p.counts.hotspotd) + ' · watchdog ' + num(p.counts.watchdog_main) + ' · guard ' + num(p.counts.dpid_guard_main) : esc(p.detail || '')) : '');
  // 探测
  var pr = S.probe;
  $('#dpi-probe').innerHTML = !pr ? stRow('探针', '暂无数据', '') :
    stRow('AF_PACKET', pr.af_packet_available ? '✓ 可用' : '✗ ' + esc(pr.af_packet_error || '不可用'), pr.af_packet_available ? 'ok' : 'bad') +
    stRow('热点接口', esc(pr.ap_iface || '—'), '', pr.ap_iface_source ? '来源 ' + esc(pr.ap_iface_source) : '') +
    stRow('Conntrack', pr.conntrack_readable ? '✓ 可读' : '不可读', pr.conntrack_readable ? 'ok' : 'warn', esc(pr.conntrack_path || '')) +
    stRow('BPF Tether Offload', pr.offload_hint ? '可能接管' : '未接管', pr.offload_hint ? 'warn' : 'ok', esc(pr.offload_evidence || ''));
  paintDpiHist(); paintClients(); paintUnknown(); paintUnkTraffic(); paintIdent(); paintDiscEntry();
}
/* 未识别流量(按字节) —— 连接表里没被规则库认出来的域名 / IP */
S.dpiUnk = {};
function loadDpiUnk(days, force) {
  var c = S.dpiUnk[days];
  if (c && !force && Date.now() - c.at < 120000) return Promise.resolve(c);
  return api.get('/api/dpi_unknown', { days: days }, { timeout: 10000 }).then(function (r) { S.dpiUnk[days] = { at: Date.now(), r: r }; })
    .catch(function (e) { S.dpiUnk[days] = { at: Date.now(), err: e && e.status === 404 ? '当前后端还不支持（需要新版 hnc_httpd）' : errText(e) }; });
}
function paintUnkTraffic() {
  var el = $('#dpi-unk2'); if (!el) return;
  var c = S.dpiUnk[S.dpiDays];
  if (!c) { el.innerHTML = '<div class="empty">加载中…</div>'; return; }
  if (c.err) { el.innerHTML = '<div class="note" style="padding:12px 14px">' + esc(c.err) + '</div>'; return; }
  var r = c.r || {}, items = (r.items || []).slice(0, 20), tot = num(r.total_unknown_bytes), tb = num(r.tunnel_bytes), ib = num(r.inferred_bytes);
  // 已从「未识别」里分出去的两块 —— VPN/代理隧道、共现推断
  var split = tb > 0 || ib > 0 ? '<div class="note" style="padding:10px 14px 0">另有 ' + [tb > 0 ? '<b>' + bytes(tb) + '</b> 已归为 ' + ico('tunnel', 'tun-i') + 'VPN 隧道' : '', ib > 0 ? '<b>' + bytes(ib) + '</b> 为推测归属（按同一时刻建连的应用）' : ''].filter(Boolean).join('、') + '，不算在未识别里</div>' : '';
  if (!items.length) { el.innerHTML = split + '<div class="empty">' + (tot ? '有 ' + bytes(tot) + ' 未识别流量，但没记下去向' : '这段时间的流量都认出来了 🎉') + '</div>'; return; }
  el.innerHTML = split + '<div class="note" style="padding:10px 14px 0">' + ({ 1: '今日', 3: '近 3 天', 7: '近 7 天' }[S.dpiDays] || '') + '未识别共 ' + bytes(tot) + ' · 下面是最多的 ' + items.length + ' 个去向</div>' +
    items.map(function (u) {
      var ds = devNames(u.macs || []);
      return '<div class="client unk2"><div class="top"><span class="nm">' + esc(u.name_or_ip) + '</span><span class="pill-count">' + bytes(u.bytes) + '</span></div>' +
        '<div class="sub">' + (u.kind === 'ip' ? 'IP（没抓到域名）' : '域名') + (u.sample && u.sample !== u.name_or_ip ? ' · 例 <span class="mono">' + esc(u.sample) + '</span>' : '') + ' · ' + num(u.devices, ds.length) + ' 台设备' + (ds.length ? '：' + esc(ds.slice(0, 3).join('、')) + (ds.length > 3 ? ' 等' : '') : '') + '</div></div>';
    }).join('') +
    '<div class="note" style="padding:8px 14px 12px">可在 <button class="linkish" data-act="disc-open" style="font-size:inherit">新发现的应用</button> 里把它们加进规则库</div>';
}
var HIST_COLORS = ['#007AFF', '#AF52DE', '#34C759', '#FF9500', '#FF2D55', '#32ADE6', '#5856D6', '#8E8E93'];
function paintDpiHist() {
  var el = $('#dpi-hist'); if (!el) return;
  // 优先用连接表的真实按应用流量; 还没有累计数据时才退回 DPI 历史(只含握手包, 偏小)
  var au = S.appUsage[S.dpiDays], ar = au && au.d;
  if (ar && num(ar.total_up) + num(ar.total_down) > 0) {
    var hrs0 = ar.by_hour || [], hm0 = Math.max.apply(null, hrs0.map(function (h) { return num(h.up) + num(h.down); }).concat([1]));
    el.innerHTML = appUsageBars(ar, 7) + (S.dpiDays === 1 && hrs0.length ? '<div class="note" style="margin-top:10px">按小时分布</div><div class="mini-bars">' + hrs0.map(function (h, i) { var v = num(h.up) + num(h.down); return '<i title="' + i + ':00 · ' + bytes(v) + '" style="height:' + Math.max(1.5, v / hm0 * 100).toFixed(1) + '%;animation-delay:' + i * 15 + 'ms"></i>'; }).join('') + '</div><div class="mini-axis"><span>0</span><span>6</span><span>12</span><span>18</span><span>23</span></div>' : '') +
      '<div class="note" style="margin-top:8px">真实流量 · 来自内核连接表</div>';
    return;
  }
  var c = S.dpiHist[S.dpiDays];
  if (!c) { el.innerHTML = '<div class="note">加载中…</div>'; return; }
  var r = c.d; if (!r) { el.innerHTML = '<div class="note err">' + esc(c.err || '加载失败') + '</div>'; return; }
  var apps = (r.by_app || []).map(function (a) { return { id: a.app_id || a.id, n: a.name || a.app_id || '未知', v: num(a.rx) + num(a.tx) }; }).sort(function (a, b) { return b.v - a.v; });
  var tot = num(r.total_rx) + num(r.total_tx);
  if (!tot) { el.innerHTML = '<div class="note">这段时间没有 DPI 流量记录</div>'; return; }
  var top = apps.slice(0, 7), rest = sum(apps.slice(7), function (a) { return a.v; }); if (rest > 0) top.push({ n: '其他', v: rest });
  var mx = top.length ? top[0].v : 1;
  var hrs = r.by_hour || [], hm = Math.max.apply(null, hrs.map(function (h) { return num(h.rx) + num(h.tx); }).concat([1]));
  el.innerHTML = '<div class="note" style="margin-bottom:6px">合计 ↓ ' + bytes(r.total_rx) + ' · ↑ ' + bytes(r.total_tx) + ' · ' + num(r.sample_count) + ' 个采样</div>' +
    top.map(function (a, i) { return '<div class="hbar"><span class="n">' + appNmH(a.id, a.n) + '</span><span><i class="b" style="display:block;width:' + Math.max(2, a.v / mx * 100).toFixed(1) + '%;background:' + HIST_COLORS[i % 8] + ';animation-delay:' + i * 40 + 'ms"></i></span><span class="v">' + bytes(a.v) + ' · ' + (a.v / tot * 100).toFixed(0) + '%</span></div>'; }).join('') +
    (hrs.length ? '<div class="note" style="margin-top:10px">按小时分布</div><div class="mini-bars">' + hrs.map(function (h, i) { var v = num(h.rx) + num(h.tx); return '<i title="' + i + ':00 · ' + bytes(v) + '" style="height:' + Math.max(1.5, v / hm * 100).toFixed(1) + '%;animation-delay:' + i * 15 + 'ms"></i>'; }).join('') + '</div><div class="mini-axis"><span>0</span><span>6</span><span>12</span><span>18</span><span>23</span></div>' : '');
}
function paintClients() {
  var el = $('#dpi-clients'); if (!el) return;
  var st = S.dpi && S.dpi.available && S.dpi.state, cl = st && st.clients ? Object.keys(st.clients).map(function (k) { return st.clients[k]; }) : [];
  var now = Date.now() / 1000;
  cl = cl.filter(function (c) {
    if (S.dpiFilter === 'active') return now - num(c.last_seen) < 120;
    if (S.dpiFilter === 'high') return (c.top_apps || []).some(function (a) { return a.confidence === 'high'; });
    return true;
  }).sort(function (a, b) { return num(b.last_seen) - num(a.last_seen); });
  if (!cl.length) { el.innerHTML = '<div class="empty">' + (st ? '没有符合条件的设备' : '等待 dpid 数据…') + '</div>'; return; }
  el.innerHTML = cl.slice(0, 30).map(function (c) {
    var d = c.client_mac ? devBy(c.client_mac) : null, ips = c.client_ips && c.client_ips.length ? c.client_ips : [c.client_ip];
    return '<div class="client"><div class="top"><span class="nm">' + esc(d ? d.name : (c.last_hostname || c.client_mac || c.client_ip)) + (c.sim || (d && d.sim) ? ' <span class="badge b-sim">模拟</span>' : '') + '</span><span class="pill-count">' + ago(c.last_seen) + '</span></div>' +
      (d && d.idText ? '<div class="sub">' + d.icon + ' ' + esc(d.idText) + '</div>' : '') +
      '<div class="sub mono">' + esc(ips.slice(0, 2).join(' · ')) + (ips.length > 2 ? ' +' + (ips.length - 2) : '') + ' · DNS ' + num(c.dns_events) + ' · TLS ' + num(c.tls_events) + (c.rx_bytes || c.tx_bytes ? ' · ↓' + bytes(c.rx_bytes) + ' ↑' + bytes(c.tx_bytes) : '') + '</div>' +
      (c.last_sni ? '<div class="sub mono">最近 ' + esc(c.last_sni) + '</div>' : '') +
      ((c.top_apps || []).length ? '<div class="apps">' + c.top_apps.slice(0, 6).map(function (a) { return '<span class="badge ' + (a.id === TUNNEL_ID ? 'b-gray' : a.confidence === 'high' ? 'b-acc' : a.confidence === 'low' ? 'b-gray' : 'b-pur') + '">' + appNmH(a.id, a.name) + (a.confidence === 'low' ? '?' : '') + '</span>'; }).join('') + '</div>' : '') + '</div>';
  }).join('');
}
function guessSuffix(host) {
  host = String(host || '').toLowerCase().replace(/^\*\.?/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  var parts = host.split('.').filter(Boolean); if (parts.length <= 2) return host;
  var two = parts.slice(-2).join('.');
  return /^(com|net|org|gov|edu)\.cn$|^co\.(uk|jp)$|^com\.(au|br|hk|tw)$|^(ne|or)\.jp$/.test(two) ? parts.slice(-3).join('.') : two;
}
function domainHints() {
  var st = S.dpi && S.dpi.available && S.dpi.state, map = {}, list = [];
  if (!st) return null;
  Object.keys(st.clients || {}).forEach(function (k) {
    var c = st.clients[k] || {};
    [['DNS', c.top_hostnames], ['SNI', c.top_sni]].forEach(function (g) {
      (g[1] || []).forEach(function (x) {
        var h = String(x.name || '').trim().toLowerCase();
        if (!h || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return;
        if (!map[h]) { map[h] = { n: h, c: 0, k: {} }; list.push(map[h]); }
        map[h].c += num(x.count, 1); map[h].k[g[0]] = 1;
      });
    });
  });
  return list.sort(function (a, b) { return b.c - a.c; }).slice(0, 12);
}
/* dpid 新导出的 top_unknown(规则没命中的域名)优先; 旧 dpid 没有该字段时回落到"访问最多的域名" */
function unknownHints() {
  var st = S.dpi && S.dpi.available && S.dpi.state;
  if (!st || !Array.isArray(st.top_unknown) || !st.top_unknown.length) return null;
  return st.top_unknown.slice(0, 15).map(function (x) { return { n: String(x.name || '').toLowerCase(), c: num(x.count, 1), k: { '未识别': 1 } }; }).filter(function (x) { return x.n; });
}
/* ═══ 未知应用发现 ═══
   二级: 新发现的应用列表(弹层) → 三级: 某一组的判断依据 + 确认/忽略 */
S.disc = null; S.discSel = null; S.discForm = null;
var DCAT = [['video', '视频'], ['social', '社交'], ['game', '游戏'], ['shopping', '购物'], ['music', '音乐'], ['office', '办公'], ['ai', 'AI'], ['reading', '阅读'], ['news', '资讯'], ['travel', '出行'], ['navigation', '地图'], ['life_service', '生活'], ['finance', '金融'], ['education', '教育'], ['photo', '图片'], ['tool', '工具'], ['browser', '浏览器'], ['download', '下载'], ['unknown', '其他']];
var GCONF = { high: '把握大', medium: '把握中', low: '待确认' };
function loadDisc() { return api.getSafe('/api/discover', null, null).then(function (r) { if (r && r.ok) { S.disc = r; paintDiscEntry(); if (S.discOpen) paintDiscSheet(); } }); }
function discEntryHtml() {
  var r = S.disc, n = r && r.groups ? r.groups.length : 0;
  var named = r && r.groups ? r.groups.filter(function (g) { return g.guess && g.guess.src !== 'domain'; }).length : 0;
  return '<button class="disc-entry press" data-act="disc-open">' + gi('purple', 'search') + '<span class="tx"><div class="t">新发现的应用</div><div class="s">' +
    (!r ? '加载中…' : r.available === false ? '等 DPI 运行一段时间后，规则库认不出的应用会出现在这里' : n ? '规则库里没有的 ' + n + ' 个应用' + (named ? '，已认出 ' + named + ' 个是谁' : '') + ' · 点开确认' : '暂时没有 · 规则库都认得') +
    '</div></span>' + (n ? '<span class="n">' + n + '</span>' : '') + ico('right', 'chev') + '</button>';
}
function paintDiscEntry() { var el = $('#disc-entry'); if (el) el.innerHTML = discEntryHtml(); }
function discTags(g) {
  var t = '', gs = g.guess || {};
  if (g.apk && g.apk.length) t += '<span class="dtag apk">本机 App · ' + esc(g.apk[0].label || g.apk[0].pkg) + '</span>';
  if (g.company) t += '<span class="dtag cert">证书 · ' + esc(g.company) + '</span>';
  else if (g.cert && g.cert.org) t += '<span class="dtag cert">证书 · ' + esc(g.cert.org.slice(0, 18)) + '</span>';
  if (g.family_name) t += '<span class="dtag ja4">指纹 · ' + esc(g.family_name) + '</span>';
  if (!t) t = '<span class="dtag">仅域名</span>';
  return t + '<span class="dtag">' + (GCONF[gs.conf] || '待确认') + '</span>';
}
function devNames(macs) { return (macs || []).map(function (m) { var d = devBy(m); return d ? d.name : m; }); }
function discListHtml() {
  var r = S.disc;
  if (!r) return '<div class="note">加载中…</div>';
  var sc = r.apk_scan || {}, gs = r.groups || [];
  var head = '<div class="dbox" style="margin-bottom:6px"><div class="row2"><span class="k">本机安装包</span><span class="v">' + (sc.app_count ? '已扫描 ' + sc.app_count + ' 个 App · ' + ago(sc.generated_at) : '还没扫描') + (sc.requested ? ' · 排队中' : '') + '</span></div>' +
    '<div class="row2"><span class="k">服务器证书</span><span class="v">' + (r.cert_probe ? '自动获取中' : '已关闭') + '</span></div>' +
    '<div class="btns" style="margin:2px 0 0"><button class="btn sec press" data-act="disc-scan">' + ico('refresh') + '立即扫描本机 App</button></div></div>';
  if (!gs.length) return head + '<div class="note" style="text-align:center;padding:20px 0">' + (r.available === false ? 'dpid 还没产出发现结果（需要 DPI 运行一段时间）' : '暂时没有规则库认不出的应用 🎉') + '</div>';
  return head + gs.map(function (g) {
    var gs2 = g.guess || {};
    return '<button class="dg press" data-disc="' + esc(g.id) + '"><span class="h"><span class="nm">' + esc(gs2.name || (g.suffixes || [])[0] || g.id) + '</span><span class="pill-count">' + num(g.hits) + ' 次</span>' + ico('right', 'chev') + '</span>' +
      '<span class="d">' + esc((g.suffixes || []).slice(0, 4).join(' · ')) + ((g.suffixes || []).length > 4 ? ' +' + (g.suffixes.length - 4) : '') + '</span>' +
      '<span class="tags">' + discTags(g) + '<span class="dtag">' + (g.devices || []).length + ' 台设备</span></span></button>';
  }).join('') + discManageBtn(r);
}
function discManageBtn(r) {
  var ni = (r.ignored || []).length, nu = (r.user_rules || []).length;
  return ni || nu ? '<button class="btn sec wide press" data-act="disc-manage" style="margin-top:10px">管理 · 已加入规则库 ' + nu + ' 条 · 已忽略 ' + ni + ' 组</button>' : '';
}
/* 管理页 —— 撤销忽略 / 删除自己加的规则 */
function discManageHtml() {
  var r = S.disc || {}, ur = r.user_rules || [], ig = r.ignored || [], cat = {};
  DCAT.forEach(function (x) { cat[x[0]] = x[1]; });
  return '<button class="dback" data-act="disc-back">‹ 返回列表</button>' +
    '<div class="dsec">已加入规则库 · ' + ur.length + ' 条</div>' + (ur.length ? '<div class="dbox">' + ur.map(function (u) {
      return '<div class="row2"><span class="k" style="color:var(--text-1);font-weight:700">' + esc(u.app || u.id) + '<div class="note mono" style="font-weight:500">' + esc(cat[u.category] || u.category || '') + ' · ' + esc((u.suffixes || []).slice(0, 4).join(', ')) + ((u.suffixes || []).length > 4 ? ' …' : '') + '</div></span><button class="linkish danger" data-urdel="' + esc(u.id) + '" data-name="' + esc(u.app || u.id) + '">删除</button></div>'; }).join('') + '</div>' : '<div class="note">还没有</div>') +
    '<div class="dsec">已忽略 · ' + ig.length + ' 组</div>' + (ig.length ? '<div class="dbox">' + ig.map(function (g) {
      return '<div class="row2"><span class="k mono" style="color:var(--text-1)">' + esc((g.suffixes || []).join(' · ') || g.id) + (g.gone ? '<div class="note">已不再出现</div>' : '') + '</span><button class="linkish" data-unign="' + esc(g.id) + '">撤销</button></div>'; }).join('') + '</div>' : '<div class="note">还没有</div>');
}
function discSheet() {
  S.discOpen = true; S.discSel = null; S.discManage = false;
  sheet('<h3>新发现的应用</h3><div class="sub">规则库认不出的域名会自动聚成"同一个 App"，再从本机安装包、服务器证书、网络指纹里找出它是谁</div><div id="disc-body">' + discListHtml() + '</div>' +
    '<button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true, kind: 'disc', onClose: function () { S.discOpen = false; S.discSel = null; } });
  loadDisc();
}
function discGroup(id) { var gs = (S.disc && S.disc.groups) || []; for (var i = 0; i < gs.length; i++) if (gs[i].id === id) return gs[i]; return null; }
function paintDiscSheet() {
  var el = $('#disc-body'); if (!el) return;
  if (S.discManage) { el.innerHTML = discManageHtml(); return; }
  if (S.discSel) { var ni = $('#dc-name'); if (ni && document.activeElement === ni) return; if (ni && S.discForm) S.discForm.name = ni.value; var g = discGroup(S.discSel); if (g) { var st = $('#sheet').scrollTop; el.innerHTML = discDetailHtml(g); $('#sheet').scrollTop = st; return; } S.discSel = null; }
  el.innerHTML = discListHtml();
}
function discOpenDetail(id) {
  var g = discGroup(id); if (!g) return;
  S.discSel = id;
  var gs = g.guess || {};
  S.discForm = { name: gs.src === 'domain' ? '' : gs.name || '', cat: 'unknown', sufs: {} };
  (g.suffixes || []).forEach(function (x) { S.discForm.sufs[x] = true; });
  (g.cert_siblings || []).forEach(function (x) { if (!(x in S.discForm.sufs)) S.discForm.sufs[x] = false; });
  $('#disc-body').innerHTML = discDetailHtml(g); $('#sheet').scrollTop = 0;
}
function kv(k, v) { return '<div class="row2"><span class="k">' + k + '</span><span class="v">' + v + '</span></div>'; }
function discDetailHtml(g) {
  var gs = g.guess || {}, f = S.discForm || { name: '', cat: 'unknown', sufs: {} }, h = '<button class="dback" data-act="disc-back">‹ 返回列表</button>';
  h += '<div style="text-align:center;margin-bottom:6px"><div style="font-size:19px;font-weight:800">' + esc(gs.name || g.id) + '</div><div class="tags" style="display:flex;gap:4px;justify-content:center;flex-wrap:wrap;margin-top:6px">' + discTags(g) + '</div></div>';
  h += '<div class="dsec">判断依据</div>';
  // 本机安装包
  h += '<div class="dbox">' + (g.apk && g.apk.length ? g.apk.map(function (a, i) { return kv(i ? '也可能' : '本机 App', esc(a.label || a.pkg) + '<div class="note mono" style="font-weight:500">' + esc(a.pkg) + ' · 命中 ' + esc((a.suffixes || []).join(', ')) + '</div>'); }).join('') : kv('本机 App', '<span class="note">本机安装包里没找到这些域名</span>')) + '</div>';
  // 证书
  var c = g.cert;
  h += '<div class="dbox" style="margin-top:8px">' + (!c ? kv('服务器证书', '<span class="note">还没获取</span>') : c.err ? kv('服务器证书', '<span class="note">' + esc(c.err) + '</span>') :
    kv('证书主体', esc(c.org || '（证书没写组织名）') + (g.company ? '<div class="note">→ ' + esc(g.company) + '</div>' : '')) + kv('签发', esc(c.issuer || '—')) + (c.sans && c.sans.length ? kv('同证书域名', '<span class="mono" style="font-size:11.5px;font-weight:500">' + esc(c.sans.slice(0, 8).join(' ')) + (c.sans.length > 8 ? ' …' : '') + '</span>') : '')) +
    '<div class="btns" style="margin:2px 0 0"><button class="btn sec press" data-act="disc-probe">' + ico('refresh') + (c ? '重新获取证书' : '立即获取证书') + '</button></div></div>';
  // 指纹
  h += '<div class="dbox" style="margin-top:8px">' + kv('网络指纹', g.family_name ? esc(g.family_name) + ' 系网络库' + (g.family_conf ? '<span class="note"> · ' + Math.round(num(g.family_conf) * 100) + '%</span>' : '') : '<span class="note">没有匹配到已知家族</span>') +
    ((g.ja4 || []).length ? kv('JA4', '<span class="mono" style="font-size:11px;font-weight:500">' + esc(g.ja4.slice(0, 2).map(function (x) { return typeof x === 'string' ? x : x.ja4 + ' ×' + num(x.count); }).join(' ')) + '</span>') : '') + '</div>';
  // 观测
  h += '<div class="dsec">看到的域名 · ' + num(g.hits) + ' 次</div><div class="dbox">' + (g.domains || []).slice(0, 10).map(function (d) { return kv('<span class="mono" style="color:var(--text-1);font-size:12px">' + esc(d.name) + '</span>', '<span class="note">' + num(d.count) + ' 次</span>'); }).join('') +
    kv('出现在', esc(devNames(g.devices).join('、') || '—')) + (g.last_seen ? kv('最近', ago(g.last_seen)) : '') + '</div>';
  // 表单
  h += '<div class="dsec">确认后加入规则库</div>' +
    '<label class="field">应用名称<span class="box"><input id="dc-name" maxlength="40" placeholder="比如：小红书" value="' + esc(f.name) + '"></span></label>' +
    '<div class="note" style="margin:10px 0 6px">分类</div><div class="dchips">' + DCAT.map(function (x) { return '<button class="dchip cat' + (f.cat === x[0] ? ' on' : '') + '" data-dcat="' + x[0] + '">' + x[1] + '</button>'; }).join('') + '</div>' +
    '<div class="note" style="margin:10px 0 6px">要加入的域名（点选取消）' + ((g.cert_siblings || []).length ? ' · 虚线的是同证书里的兄弟域名' : '') + '</div><div class="dchips">' + Object.keys(f.sufs).map(function (x) { return '<button class="dchip' + (f.sufs[x] ? ' on' : '') + '" data-dsuf="' + esc(x) + '"' + ((g.suffixes || []).indexOf(x) < 0 ? ' style="border-style:dashed"' : '') + '>' + esc(x) + '</button>'; }).join('') + '</div>' +
    '<div class="btns" style="margin-top:14px"><button class="btn sec press" data-act="disc-ignore">忽略</button><button class="btn pri press" data-act="disc-confirm">确认加入规则库</button></div>';
  return h;
}
function discAct(act) {
  var id = S.discSel, g = id && discGroup(id);
  if (act === 'disc-open') return discSheet();
  if (act === 'disc-back') { S.discSel = null; S.discManage = false; $('#disc-body').innerHTML = discListHtml(); return; }
  if (act === 'disc-manage') { S.discSel = null; S.discManage = true; $('#disc-body').innerHTML = discManageHtml(); return; }
  if (act === 'disc-scan') return api.action('apk_scan').then(function (r) { toast(r.detail || '已请求扫描'); loadDisc(); }).catch(function (e) { toast(errText(e), 'err'); });
  if (!g) return;
  if (act === 'disc-probe') { toast('正在连接 ' + ((g.domains || [])[0] || {}).name + ' 读取证书…'); return api.action('discover_probe', { id: id }, { timeout: 20000, maxTime: 18 }).then(function () { toast('已获取证书'); }).catch(function (e) { toast(errText(e), 'warn'); }).then(loadDisc); }
  if (act === 'disc-ignore') return api.action('discover_ignore', { id: id }).then(function () { toast('已忽略'); S.discSel = null; S.disc.groups = S.disc.groups.filter(function (x) { return x.id !== id; }); paintDiscSheet(); paintDiscEntry(); loadDisc(); }).catch(function (e) { toast(errText(e), 'err'); });
  if (act === 'disc-confirm') {
    var name = ($('#dc-name').value || '').trim(), f = S.discForm, sufs = Object.keys(f.sufs).filter(function (x) { return f.sufs[x]; });
    if (!name) { toast('先填应用名称', 'warn'); $('#dc-name').focus(); return; }
    if (!sufs.length) { toast('至少保留一个域名', 'warn'); return; }
    return api.action('discover_confirm', { id: id, name: name, category: f.cat, suffixes: sufs.join(',') }).then(function (r) {
      toast('「' + name + '」已加入规则库'); S.discSel = null; S.disc.groups = S.disc.groups.filter(function (x) { return x.id !== id; }); paintDiscSheet(); paintDiscEntry(); loadDisc();
    }).catch(function (e) { toast(errText(e), 'err'); });
  }
}
function paintIdent() {
  var el = $('#dpi-ident'); if (!el) return;
  var ds = S.devices.filter(function (d) { return d.ident; }).sort(function (a, b) { return (b.online - a.online) || num(b.ident.confidence) - num(a.ident.confidence); });
  if (!ds.length) { el.innerHTML = '<div class="empty">还没有识别结果 · 设备重新连接热点后会通过 DHCP / mDNS 自动识别</div>'; return; }
  var tot = S.devices.filter(function (d) { return d.online; }).length, got = ds.filter(function (d) { return d.online; }).length;
  el.innerHTML = '<div class="note" style="padding:10px 14px 0">在线 ' + tot + ' 台，已识别 ' + got + ' 台</div>' + ds.slice(0, 30).map(function (d) {
    var c = num(d.ident.confidence);
    return '<div class="client"><div class="top"><span class="nm">' + d.icon + ' ' + esc(d.name) + (d.sim ? ' <span class="badge b-sim">模拟</span>' : '') + '</span><span class="pill-count">' + c + '%</span></div>' +
      '<div class="sub">' + esc(d.idText || '—') + (d.online ? '' : ' · 离线') + '</div>' +
      (d.ident.evidence && d.ident.evidence.length ? '<div class="sub mono">' + esc(d.ident.evidence.slice(0, 3).map(function (e) { return (EV_SRC[e.src] || e.src) + ' ' + e.detail; }).join(' · ')) + '</div>' : '') + '</div>';
  }).join('');
}
function paintUnknown() {
  var el = $('#dpi-unknown'); if (!el) return;
  var unk = unknownHints(), list = unk || domainHints();
  var tt = $('#dpi-unknown-t'); if (tt) tt.textContent = unk ? '没被规则认出来的域名 · 一键生成规则模板' : '设备访问最多的域名 · 一键生成规则模板';
  if (!list) { el.innerHTML = '<div class="empty">等待 dpid 数据…</div>'; return; }
  if (!list.length) { el.innerHTML = '<div class="empty">还没有抓到域名</div>'; return; }
  el.innerHTML = list.map(function (u) {
    return '<div class="sni-row"><span class="dw"><span class="d">' + esc(u.n) + '</span><span class="c">' + Object.keys(u.k).join('/') + ' · ' + u.c + ' 次 · 后缀 ' + esc(guessSuffix(u.n)) + '</span></span><button class="btn sec press" data-rule-tpl="' + esc(u.n) + '">生成规则</button></div>';
  }).join('');
}
function ruleTemplate(host) {
  var suf = guessSuffix(host), ta = $('#rules-text'); if (!ta || !suf) return;
  var rule = { id: ('user_' + suf.replace(/[^a-z0-9]+/g, '_')).replace(/_+$/, '').slice(0, 48), app: '待确认应用', category: 'unknown', confidence: 'user', suffixes: [suf] };
  var obj = null; try { obj = ta.value.trim() ? JSON.parse(ta.value) : null; } catch (_) { obj = null; }
  if (obj && Array.isArray(obj.rules)) {
    if (!obj.rules.some(function (r) { return (r.suffixes || []).indexOf(suf) >= 0; })) obj.rules.push(rule);
  } else obj = { schema_version: '1.0', rules_version: 'user-' + today(), rules: [rule] };
  ta.value = JSON.stringify(obj, null, 2);
  S.open.rules = true; var rb = $('#rules'); if (rb) rb.classList.add('open');
  toast('已加入规则模板（' + suf + '），改好 app / category 后点「导入」');
}
function rulesOut(t, cls) { var o = $('#rules-out'); if (!o) return; o.hidden = false; o.textContent = t; o.style.color = cls === 'err' ? 'var(--badge-red)' : ''; }
function rulesAct(act) {
  var ta = $('#rules-text');
  if (act === 'rules-export') {
    rulesOut('读取中…');
    return api.get('/api/dpi_rules', null, { timeout: 15000, maxTime: 13 }).then(function (r) { ta.value = typeof r.rules === 'string' ? r.rules : JSON.stringify(r.rules || r, null, 2); rulesOut('已读取 · 来源 ' + (r.source || '—') + ' · ' + (ta.value.length / 1024).toFixed(1) + ' KB'); }).catch(function (e) { rulesOut(errText(e), 'err'); });
  }
  if (act === 'rules-import') {
    var txt = ta.value.trim(); if (!txt) { toast('先粘贴规则 JSON', 'warn'); return; }
    try { JSON.parse(txt); } catch (e) { rulesOut('JSON 格式错误：' + e.message, 'err'); return; }
    if (txt.length > 512 * 1024) { rulesOut('超过 512 KB', 'err'); return; }
    return confirmSheet('导入规则库？', '会覆盖当前的自定义规则库（内置规则不受影响），dpid 随后自动重载。', '导入', { safe: true }).then(function (ok) {
      if (!ok) return;
      rulesOut('导入中…');
      api.post('/api/dpi_rules', { rules: txt }, { timeout: 30000, maxTime: 28 }).then(function (r) { if (r.ok === false) throw new Error(r.error || '导入失败'); rulesOut(r.detail || '✓ 已导入'); toast('规则库已导入'); }).catch(function (e) { rulesOut(errText(e), 'err'); });
    });
  }
  if (act === 'rules-reset') {
    return confirmSheet('恢复内置规则库？', '删除自定义规则，回到模块自带的规则库。', '恢复').then(function (ok) {
      if (!ok) return;
      api.action('dpi_rules_reset', {}, { timeout: 30000, maxTime: 28 }).then(function (r) { rulesOut(r.detail || '✓ 已恢复内置'); ta.value = ''; toast('已恢复内置规则库'); }).catch(function (e) { rulesOut(errText(e), 'err'); });
    });
  }
  if (act === 'rules-update') {
    rulesOut('正在检查…');
    return api.action('dpi_rules_update', { mode: 'check' }, { timeout: 40000, maxTime: 38 }).then(function (r) {
      var d = detailJSON(r);
      if (String(d.update_available) !== 'yes') { rulesOut('已是最新 · 当前 ' + (d.current || '—') + (d.remote ? ' · 远端 ' + d.remote : '')); return; }
      rulesOut('有新版本：' + (d.current || '—') + ' → ' + d.remote);
      return confirmSheet('更新规则库？', '当前 ' + esc(d.current || '—') + '，远端 ' + esc(d.remote) + '。', '更新', { safe: true }).then(function (ok) {
        if (!ok) return;
        rulesOut('正在下载安装…');
        return api.action('dpi_rules_update', { mode: 'install' }, { timeout: 90000, maxTime: 88 }).then(function (r2) { rulesOut(r2.detail || '✓ 已更新'); toast('规则库已更新'); });
      });
    }).catch(function (e) { rulesOut(errText(e), 'err'); });
  }
}

