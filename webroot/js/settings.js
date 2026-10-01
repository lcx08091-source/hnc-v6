/* HNC WebUI · settings.js —— 设置页: VPN 检测 / 随机 MAC 合并、加密 DNS、统计健康、全部设置条目、模拟环境、外观与动效、自检报告、更新日志 */
'use strict';

/* ═══ VPN / 代理检测 · 随机 MAC 合并建议 ═══ */
function pctTxt(v) { v = num(v); return Math.round((v <= 1 ? v * 100 : v)) + '%'; }
function vpnBadge(v) {
  var sure = v.level === 'certain', tip = (v.reason || (sure ? '协议特征' : '疑似隧道')) + ' · 近 ' + Math.round(num(v.window_sec, 300) / 60) + ' 分钟流量占 ' + pctTxt(v.share) + (v.dst ? ' · 对端 ' + v.dst : '');
  return '<span class="badge ' + (sure ? 'b-pur' : 'b-warn') + '" title="' + esc(tip) + '">' + ico('tunnel', 'tun-i') + (sure ? '在用 VPN/代理' : '可能在用 VPN/代理') + '</span>';
}
function vpnNote(d) {
  var v = d.vpn; if (!v) return '';
  return '<div class="note' + (v.level === 'certain' ? '' : ' warn') + '" style="padding:0 2px">' + ico('tunnel', 'tun-i') + (v.level === 'certain' ? '在用 VPN/代理' : '可能在用 VPN/代理') + '：近 ' + Math.round(num(v.window_sec, 300) / 60) + ' 分钟 ' + pctTxt(v.share) + ' 的流量（' + bytes(v.bytes) + '）走' + esc(v.reason || '隧道') + (v.dst ? '，对端 <span class="mono">' + esc(v.dst) + '</span>' : '') + '。隧道里是什么应用看不到，按应用限速 / 封锁对它无效</div>';
}
/* 应用名: 伪应用 _tunnel 显示成「VPN/代理隧道」+ 隧道图标; 返回 HTML */
var TUNNEL_ID = '_tunnel';
function appNmH(id, name) { return id === TUNNEL_ID ? ico('tunnel', 'tun-i') + 'VPN/代理隧道' : esc(name || id || '未知'); }
function mergeScoreTxt(m) { return '匹配 ' + num(m.score) + ' 分'; }
function mergeRowHtml(d) {
  var m = d.merge; if (!m) return '';
  var nm = m.old_name || m.old_mac, rs = Array.isArray(m.reasons) ? m.reasons : [];
  return '<div class="mrg" data-merge="' + esc(m.old_mac) + '"><div class="mrg-t">' + ico('merge') + '<span>可能是「' + esc(nm) + '」换了 MAC（<b>' + mergeScoreTxt(m) + '</b>）' + (num(m.old_last_seen) ? '<span class="note" style="font-weight:500;display:block">旧设备 ' + ago(m.old_last_seen) + '离线 · <span class="mono">' + esc(m.old_mac) + '</span></span>' : '') + '</span></div>' +
    (rs.length ? '<ul class="mrg-r">' + rs.slice(0, 6).map(function (r) { return '<li' + (/不同/.test(r) ? ' class="neg"' : '') + '>' + esc(r) + '</li>'; }).join('') + '</ul>' : '') +
    '<div class="note">合并后「' + esc(nm) + '」的名称、限速、配额、封锁和历史流量都转到这台设备</div>' +
    '<div class="btns"><button class="btn sec press" data-act="merge-no">不是</button><button class="btn pri press" data-act="merge-yes">合并</button></div></div>';
}
/* GET /api/mac_merge: 全部待确认建议 + 已合并的别名表(设置页 / 告警入口用; 设备卡直接用 /api/devices 的 merge_suggestion) */
S.mm = null;
function loadMacMerge() { return api.getSafe('/api/mac_merge', null, null).then(function (r) { S.mm = r && Array.isArray(r.suggestions) ? r : null; return S.mm; }); }
function mmFind(newMac, oldMac) {
  var s = null, d = devBy(newMac);
  (S.mm ? S.mm.suggestions : []).forEach(function (x) { if (!s && x.new_mac === newMac && (!oldMac || x.old_mac === oldMac)) s = x; });
  if (!s && d && d.merge && (!oldMac || d.merge.old_mac === oldMac)) s = Object.assign({ new_mac: newMac, new_name: d.name, randomized: d.rmac }, d.merge);
  return s;
}
function mergeSheet(newMac, oldMac, hint, fetched) {
  newMac = String(newMac || '').toLowerCase();
  var s = mmFind(newMac, oldMac);
  if (!s && !fetched) { loadMacMerge().then(function () { if (!hint || $('#sheet').dataset.kind === 'merge') mergeSheet(newMac, oldMac, hint, true); }); if (!hint) return; }
  if (!s && hint && isMac(hint.old_mac)) s = Object.assign({ new_mac: newMac, stale: true }, hint);
  if (!s) { sheet('<h3>疑似同一设备换了 MAC</h3><div class="empty">这条建议已经处理过了（已合并或已忽略）</div><button class="btn sec wide press" data-close>关闭</button>', { kind: 'merge' }); return; }
  var d = devBy(newMac), od = devBy(s.old_mac), nn = (d && d.name) || s.new_name || newMac, on = s.old_name || (od && od.name) || s.old_mac, sc = clamp(num(s.score), 0, 100), rs = Array.isArray(s.reasons) ? s.reasons : [];
  var oldSeen = num(s.old_last_seen) || (od && !od.online ? od.lastSeen : 0);
  sheet('<h3>疑似同一设备换了 MAC</h3><div class="sub">手机的「隐私 Wi-Fi 地址」会定期更换 MAC，HNC 会把它当成新设备。下面是判断两者是同一台的线索</div>' +
    '<div class="mm-cmp"><div><div class="k">旧设备</div><div class="n">' + esc(on) + '</div><div class="m">' + esc(s.old_mac) + '</div><div class="k">' + (oldSeen ? ago(oldSeen) + '离线' : '&nbsp;') + '</div></div>' + ico('right') +
    '<div><div class="k">新 MAC' + (s.randomized !== false && (!d || d.rmac) ? ' · 随机' : '') + '</div><div class="n">' + esc(nn) + '</div><div class="m">' + esc(newMac) + '</div><div class="k">' + (d && d.online ? '在线' : num(s.new_first_seen) ? ago(s.new_first_seen) + '出现' : '&nbsp;') + '</div></div></div>' +
    '<div class="qrow"><div class="h"><span class="k">匹配度</span><span class="v">' + sc + ' / 100</span></div><div class="pbar' + (sc >= 60 ? '' : ' warn') + '"><i style="width:' + sc + '%"></i></div></div>' +
    (rs.length ? '<ul class="mrg-r" style="margin:10px 0">' + rs.map(function (r) { return '<li' + (/不同/.test(r) ? ' class="neg"' : '') + '>' + esc(r) + '</li>'; }).join('') + '</ul>' : '') +
    '<div class="note" style="margin:6px 0 12px">合并 = 把旧 MAC 的名称、限速 / 延迟 / 黑白名单、配额与分时段、应用限速与时长、封锁项，以及历史流量都转到新 MAC 上；旧 MAC 的规则随后清掉。点「不是」以后不再对这一对提示。' + (s.stale ? '<br>（来自告警，建议可能已经过期）' : '') + '</div>' +
    '<div class="btns"><button class="btn sec press" id="mm-no">不是同一台</button><button class="btn pri press" id="mm-yes">合并</button></div>', { kind: 'merge' });
  $('#mm-yes').onclick = function () { doMerge(newMac, s.old_mac, on, false); };
  $('#mm-no').onclick = function () { dismissMerge(newMac, s.old_mac, on); };
}
function isConflict(e) { return !!e && (e.status === 409 || (e.body && e.body.error === 'conflict')); }
function mergeAfter() {
  return Promise.all([loadDevices().catch(function () {}), loadAppLimits().catch(function () {}), loadMacMerge(), S.encdns ? loadEncdns() : null]).then(function () {
    if (S.page === 'devices') renderDevList(false); else if (S.page === 'settings') renderSettings(false);
  });
}
function doMerge(to, from, oldName, force) {
  if (S.busy[to]) { toast('这台设备还有操作在进行', 'warn'); return Promise.resolve(false); }
  var p = { from_mac: from, to_mac: to }; if (force) p.force = 'true';
  setBusy(to, true); var b = $('#mm-yes'); if (b) b.disabled = true;
  return api.action('device_merge', p, { timeout: 30000, maxTime: 28 }).then(function (r) {
    if ($('#sheet').dataset.kind === 'merge') closeSheet();
    toast('已合并 · 「' + oldName + '」的名称和规则已转到新 MAC' + (/清理未完成/.test(r.detail || '') ? '（旧 MAC 有残留规则，可手动清）' : ''), /清理未完成/.test(r.detail || '') ? 'warn' : 'ok');
    return true;
  }, function (e) {
    if (isConflict(e)) { mergeConflict(to, from, oldName, e); return false; }
    toast(errText(e), 'err'); if (b) b.disabled = false; return false;
  }).then(function (ok) { setBusy(to, false); return mergeAfter().then(function () { return ok; }); });
}
/* 409: 新 MAC 已有不同的同类设置 —— 讲清楚会覆盖什么, 确认后 force=true(以旧设备设置为准) */
function mergeConflict(to, from, oldName, e) {
  var det = String((e.body && e.body.detail) || e.detail || ''), m = det.match(/设置[:：]\s*([^;；]+)/), what = m ? m[1].trim() : '';
  var d = devBy(to), nn = d ? d.name : to;
  return confirmSheet('两台设备的设置不一样', '新 MAC「' + esc(nn) + '」上已经有和「' + esc(oldName) + '」不同的设置' + (what ? '：<b>' + esc(what) + '</b>' : '') + '。<br><br>' +
    '继续合并会<b>以旧设备的设置为准</b>覆盖这些项（那是你之前花时间配好的）；旧设备没设置的项保留新 MAC 自己的，封锁项和类别封锁取两者并集。', '以旧设备设置为准合并', { safe: true }).then(function (ok) {
    if (ok) return doMerge(to, from, oldName, true);
    toast('已取消合并', 'warn'); return false;
  });
}
function dismissMerge(to, from, oldName) {
  return api.action('device_merge_dismiss', { from_mac: from, to_mac: to }).then(function () {
    if ($('#sheet').dataset.kind === 'merge') closeSheet();
    toast('好的，不再把它当成「' + oldName + '」');
  }, function (e) { toast(errText(e), 'err'); }).then(mergeAfter);
}
function mergeSettingsHtml() {
  var m = S.mm;
  if (!m) return sItem(['gray', 'merge'], '设备合并建议', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var sg = m.suggestions || [], al = m.aliases && typeof m.aliases === 'object' ? m.aliases : {}, ak = Object.keys(al).sort();
  var body = (sg.length ? sg.map(function (s) {
    var d = devBy(s.new_mac), nn = (d && d.name) || s.new_name || s.new_mac;
    return '<div class="mm-row"><span class="t">「' + esc(nn) + '」可能是「' + esc(s.old_name || s.old_mac) + '」</span><button class="linkish" data-mm-open="' + esc(s.new_mac + '|' + s.old_mac) + '">查看</button><span class="s">' + mergeScoreTxt(s) + (s.new_online ? ' · 新 MAC 在线' : '') + ((s.reasons || []).length ? ' · ' + esc(s.reasons.slice(0, 2).join(' · ')) : '') + '</span></div>';
  }).join('') : '<div class="note">暂时没有疑似换了 MAC 的设备</div>') +
    '<div class="mm-sub">已合并的旧 MAC（' + ak.length + '）</div>' + (ak.length ? ak.map(function (o) {
      var d = devBy(al[o]);
      return '<div class="mm-row"><span class="t mono" style="font-size:12px">' + esc(o) + ' → ' + esc(al[o]) + '</span><span></span><span class="s">现在是「' + esc(d ? d.name : al[o]) + '」· 旧 MAC 的历史流量算在新 MAC 上</span></div>';
    }).join('') : '<div class="note">还没有合并过</div>') +
    '<div class="note" style="margin-top:8px">手机的「隐私 Wi-Fi 地址」（随机 MAC）会不定期更换。HNC 按主机名、DHCP 指纹、TLS 指纹、常用应用和上下线时间打分，' + num(m.min_score, 40) + ' 分以上给出建议，' + num(m.alert_score, 60) + ' 分以上发提醒。</div>';
  return sFold('mmerge', ['orange', 'merge'], '设备合并建议', sg.length ? sg.length + ' 条待确认' + (ak.length ? ' · 已合并 ' + ak.length + ' 个旧 MAC' : '') : '随机 MAC 换地址后，把旧设备的名称和规则接过来' + (ak.length ? ' · 已合并 ' + ak.length + ' 个' : ''),
    body, sg.length ? '<span class="badge b-warn" style="font-size:12px;padding:3px 8px">' + sg.length + '</span>' : val('0'));
}
/* ═══ 加密 DNS 策略(GET /api/encdns + encdns_set) ═══ */
S.encdns = null;
var ENC_T = { off: '关闭', dot: '拦截 DoT', strict: '严格', inherit: '跟随全局' };
function loadEncdns() { return api.getSafe('/api/encdns', null, null).then(function (r) { S.encdns = r && typeof r.policy === 'string' ? r : null; return S.encdns; }); }
function encdnsDevPol(mac) { var e = S.encdns; return e && e.devices && e.devices[mac] ? e.devices[mac] : 'inherit'; }
function encdnsDevBlock(d) {
  var e = S.encdns; if (!e || d.sim) return '';
  var cur = encdnsDevPol(d.mac), g = ENC_T[e.policy] || e.policy || '关闭';
  return '<div class="ctrl"><div class="ctrl-t"><i style="background:var(--red)"></i>加密 DNS 拦截</div>' + seg('encdns-dev', [['inherit', '跟随全局'], ['off', '关闭'], ['dot', 'DoT'], ['strict', '严格']], cur, 'small') +
    '<div class="note">' + (cur === 'inherit' ? '跟随全局（' + esc(g) + '）' : cur === 'off' ? '这台设备不拦截（豁免全局设置）' : '单独设为「' + esc(ENC_T[cur] || cur) + '」') + '。如果它把「私人 DNS」设成了指定主机名，拦截会让它断网 —— 那就选「关闭」</div></div>';
}
function encdnsSettingsHtml() {
  var e = S.encdns;
  if (!e) return sItem(['gray', 'shield'], '加密 DNS 拦截', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var pol = ENC_T[e.policy] ? e.policy : 'off', c = e.counters, dp = e.dpid, nDev = Array.isArray(e.device_list) ? e.device_list.length : Object.keys(e.devices || {}).length;
  var slT = { available: '可用', unavailable: '内核不支持（严格档只按 IP 拦公共 DoH）', unknown: '未检测（首次开启严格档时检测）' }[e.string_layer] || '—';
  var pk = function (k) { return c && c[k] ? num(c[k].pkts) : 0; };
  var cnt = c ? '<div class="enc-cnt">' + [['dot', 'DoT / DoQ'], ['doh_ip', 'DoH · IP'], ['doh_sni', 'DoH · SNI'], ['doh_dns', 'DoH · 域名']].map(function (x) { return '<div><div class="n num">' + fmtN(pk(x[0])) + '</div><div class="l">' + x[1] + '</div></div>'; }).join('') + '</div>' +
      '<div class="note" style="margin-top:4px">已拦下的包数（含客户端重试）· 合计 ' + fmtN(c.total_pkts) + ' 包 · ' + bytes(c.total_bytes) + (num(c.v6_pkts) ? ' · 其中 IPv6 ' + fmtN(c.v6_pkts) : '') + ' · 规则重新同步时清零</div>'
    : '<div class="note" style="margin-top:6px">' + (e.counters_error ? '拦截计数读取失败：' + esc(e.counters_error) : pol === 'off' ? '开启后这里显示拦截计数' : '暂无拦截计数') + '</div>';
  var dpT = '';
  if (dp && typeof dp === 'object') {
    var rd = Array.isArray(dp.recent_doh) && dp.recent_doh.length ? dp.recent_doh[0] : null, rdd = rd && rd.client_mac ? devBy(rd.client_mac) : null;
    dpT = 'DPI 观察：明文 DNS ' + fmtN(dp.dns_seen) + ' 次 · DoT 尝试 ' + fmtN(dp.dot_attempts) + (num(dp.dot_flows) ? '（' + num(dp.dot_flows) + ' 条仍在连）' : '') + ' · 疑似 DoH ' + fmtN(dp.doh_suspect) +
      (rd ? ' · 最近 <span class="mono">' + esc(rd.name || '?') + '</span>' + (rdd ? '（' + esc(rdd.name) + '）' : '') + (num(rd.ts) ? ' ' + ago(rd.ts) : '') : '');
  }
  return '<div class="row" style="align-items:flex-start" id="encdns-row">' + gi('red', 'shield') + '<span class="tx"><div class="t">加密 DNS 拦截</div><div class="s">拦下 DoT / 公共 DoH，让设备回落明文 DNS：热点看得到每次解析，应用识别和域名封锁更准</div>' +
    '<div style="margin-top:8px">' + seg('encdns', [['off', '关闭'], ['dot', '拦截 DoT'], ['strict', '严格']], pol, 'small') + '</div>' +
    (e.tradeoff ? '<div class="note warn" style="margin-top:6px">' + esc(e.tradeoff) + '</div>' : '') +
    '<div class="note" style="margin-top:6px">名字层（SNI / 域名匹配）：' + slT + (nDev ? ' · ' + nDev + ' 台设备单独设置（在设备卡里改）' : ' · 可在设备卡里按设备单独设置') + '</div>' + cnt +
    (dpT ? '<div class="note" style="margin-top:4px">' + dpT + '</div>' : '') + '</span></div>';
}
function encdnsDetailTxt(r) { var d = String((r && r.detail) || ''); return /no change/.test(d) ? '（未变化）' : /global=pending/.test(d) ? ' · 热点开启后生效' : /string_layer=0/.test(d) ? ' · 内核不支持名字层，只按 IP 拦' : ''; }
/* ═══ 统计健康(GET /api/stats_health) ═══ */
S.sh = null;
function loadStatsHealth() { return api.getSafe('/api/stats_health', null, null).then(function (r) { S.sh = r && Array.isArray(r.issues) ? r : null; return S.sh; }); }
var SH_LV = { error: 'fail', warn: 'warn', info: 'info' }, OFFK_T = { hw: '硬件分流', bpf: '软件分流（BPF）', unknown: '分流', none: '' };
function calFmtPct(p) { p = num(p); return (p > 0 ? '+' : p < 0 ? '−' : '±') + Math.abs(p).toFixed(1) + '%'; }
function statsHealthHtml() {
  var r = S.sh;
  if (!r) return sItem(['gray', 'heart'], '统计健康', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var is = r.issues || [], nE = is.filter(function (x) { return x.level === 'error'; }).length, nW = is.filter(function (x) { return x.level === 'warn'; }).length;
  var lv = nE ? 'fail' : nW ? 'warn' : 'ok', gap = r.offload_gap_pct == null ? null : num(r.offload_gap_pct), age = r.last_stats_sample_age == null ? null : num(r.last_stats_sample_age, -1);
  var calS = { ok: '一致', drift: '有偏差', unavailable: '不可用' }[r.calibration_status] || r.calibration_status || '—';
  var rows = [
    ['精确模式', r.precise_mode ? '开' : '关' + (r.ct_poll_fallback ? ' · 10 秒轮询' : '')],
    ['连接销毁事件', r.ct_events_active ? Math.round(num(r.ct_destroy_events_per_min)) + ' 次/分' : '未订阅'],
    ['连接字节计数', r.ct_acct === 1 ? '已开启' : r.ct_acct === 0 ? '未开启' : '未知'],
    ['iptables 计数', r.iptables_stats_ok ? '正常' : r.iptables_stalled ? '停滞' : r.iptables_checked ? '异常' : '未检查'],
    ['设备流量采样', age == null || age < 0 ? '无记录' : age < 60 ? age + ' 秒前' : Math.round(age / 60) + ' 分钟前'],
    ['系统时钟', r.clock_sane === false ? '不可信' : '可信'],
    ['分流漏计', gap == null ? '—' : '≈ ' + Math.round(gap) + '%' + (OFFK_T[r.offload_kind] ? ' · ' + OFFK_T[r.offload_kind] : '')],
    ['分流兜底', r.offload_guard_active ? '生效中' : (r.offload_guard_mode || '—')],
    ['系统统计对账', r.netstats_mode === 'off' ? '已关闭' : calS + (r.hnc_vs_netstats_pct != null ? ' · ' + calFmtPct(r.hnc_vs_netstats_pct) : '')]
  ];
  var body = (is.length ? '<div class="sc-items">' + is.map(function (x) { var st = SH_LV[x.level] || 'info'; return '<div class="sc-it ' + st + '" data-shid="' + esc(x.id || '') + '"><span class="sc-i">' + SC_ST[st][0] + '</span><div style="min-width:0"><div class="s" style="margin:0;color:var(--text-2);font-size:13px">' + esc(x.text_cn || x.id) + '</div></div></div>'; }).join('') + '</div>' : '<div class="note">没有发现问题 ✓</div>') +
    '<dl class="kv sh-kv">' + rows.map(function (x) { return '<dt>' + x[0] + '</dt><dd>' + esc(x[1]) + '</dd>'; }).join('') + '</dl>' +
    '<div class="note" style="margin-top:6px">精确模式 = conntrack 连接销毁事件 + 字节计数都在线，按应用流量不漏短连接。' + (r.checked_at ? ' · ' + ago(r.checked_at) + '检测' : '') + '</div>';
  var sub = (r.precise_mode ? '精确模式' : '轮询模式') + (gap != null && gap >= 10 ? ' · 分流漏计 ≈ ' + Math.round(gap) + '%' : '') + ' · ' + (lv === 'ok' ? '各统计口径正常' : [nE ? nE + ' 个错误' : '', nW ? nW + ' 个警告' : ''].filter(Boolean).join(' · '));
  return sFold('sh', [lv === 'fail' ? 'red' : lv === 'warn' ? 'orange' : 'green', 'heart'], '统计健康', sub, body, val(lv === 'ok' ? '正常' : lv === 'fail' ? nE + ' 项错误' : nW + ' 项警告', lv === 'ok' ? 'ok' : lv === 'fail' ? 'bad' : 'warn'));
}

/* ═════════════════════ 设置页(原版全部条目, 就地展开) ═════════════════════ */
var LOG_FILES = ['combined', 'service', 'watchdog', 'hotspot', 'hotspotd', 'dpid', 'dpid_guard', 'httpd', 'tc', 'iptables', 'apply', 'detect', 'stats', 'audit'];
var OG_T = { NOMAP: '本机没有系统热点加速，无需兜底', IDLE: '加速存在但没在转发流量，无需兜底', CAPABLE: '支持加速，目前没在转发，继续观察', ACTIVE: '加速正在转发流量', NOHOTSPOT: '热点未开启', UNKNOWN: '未知', SKIPPED: '已关闭' };
var OFFLOAD_T = { ACTIVE: '正在接管转发', CAPABLE: '可接管（未激活）', IDLE: '空闲', NOMAP: '未发现 offload', PENDING: '检测中' };
S.alertCfg = null; S.sla = null; S.metrics = null; S.tokens = null; S.runStatus = null; S.clsact = null; S.ifaceInfo = null; S.logText = '';
function loadSettingsData() {
  return Promise.all([
    loadConfig().catch(function () {}),
    api.getSafe('/api/alert_config', null, null).then(function (r) { S.alertCfg = r; }),
    api.getSafe('/api/sla', null, null).then(function (r) { S.sla = r; }),
    api.getSafe('/api/metrics', null, null).then(function (r) { S.metrics = r; }),
    api.getSafe('/api/iface_info', null, null).then(function (r) { S.ifaceInfo = r; }),
    api.getSafe('/api/run_status', null, null).then(function (r) { S.runStatus = r; }),
    loadSim(),
    loadCaps(),
    loadSelfcheck(),
    loadAppLimits(),
    loadMacMerge(), loadEncdns(), loadStatsHealth()   // v5.21
  ]);
}
/* 模拟环境(调试) */
S.sim = null;
var SIM_T = { tv: ['电视', '📺'], phone: ['手机', '📱'], laptop: ['笔记本', '💻'], tablet: ['平板', '📲'], game: ['游戏机', '🎮'], iot: ['智能设备', '💡'], pc: ['电脑', '🖥️'] };
var SIM_P = { home: ['家庭', '晚上一家人：电视追剧 + 几台手机'], busy: ['繁忙', '下载 / 4K / 直播 / 会议，含限速和拉黑'], idle: ['空闲', '只有心跳流量，一台离线'] };
function loadSim() { return api.getSafe('/api/sim', null, null).then(function (r) { S.sim = r && (r.ok !== false) && Array.isArray(r.devices) ? r : null; if (S.sim) S.cfg.sim_enabled = S.sim.enabled === true; }); }
function simGroupHtml() {
  var sm = S.sim;
  if (!sm) return sItem(['gray', 'flask'], '模拟环境', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var devs = sm.devices || [], mx = num(sm.max, 32), presets = Array.isArray(sm.presets) && sm.presets.length ? sm.presets : ['home', 'busy', 'idle'];
  presets = ['home', 'busy', 'idle'].filter(function (x) { return presets.indexOf(x) >= 0; }).concat(presets.filter(function (x) { return !SIM_P[x]; }));
  var list = devs.length ? devs.map(function (x) {
    var t = SIM_T[x.type] || ['设备', '📶'], rx = bps(x.online === false ? 0 : num(x.cur_rx_bps, x.rx_bps)), tx = bps(x.online === false ? 0 : num(x.cur_tx_bps, x.tx_bps));
    return '<div class="simdev"><span style="font-size:20px;width:28px;text-align:center;flex:none">' + t[1] + '</span><span class="tx"><div class="t">' + esc(x.name || x.hostname || x.mac) + '</div><div class="s">' + t[0] + (x.online === false ? ' · 离线' : ' · ↓ ' + rx.v + ' ' + rx.u + ' ↑ ' + tx.v + ' ' + tx.u) + (x.app_name ? ' · ' + esc(x.app_name) : '') + (x.blocked ? ' · 已拉黑' : '') + '</div></span>' +
      '<button class="linkish danger" data-sim-del="' + esc(x.mac) + '" data-name="' + esc(x.name || x.mac) + '">删除</button></div>';
  }).join('') + '<button class="btn dan press" data-act="sim-clear">清空全部模拟设备</button>' : '<div class="note">还没有模拟设备 · 点上面的预设一键载入，或手动添加</div>';
  return sItem(['purple', 'flask'], '模拟环境', '用虚构设备和流量演示 / 调试界面；模拟设备的操作只改模拟状态，不碰 tc / iptables', toggle(sm.enabled === true, 'data-set="sim" aria-label="模拟环境"')) +
    '<div class="row">' + gi('orange', 'layers') + '<span class="tx"><div class="t">一键载入预设</div><div class="s">替换现有模拟设备并自动开启</div><div class="chips" style="margin-top:8px">' +
      presets.map(function (k) { return '<button class="chip press" data-sim-preset="' + esc(k) + '" title="' + esc((SIM_P[k] || [])[1] || '') + '">' + esc((SIM_P[k] || [k])[0]) + '</button>'; }).join('') + '</div></span></div>' +
    sBtn(['blue', 'dev'], '添加模拟设备', '名称 · 类型 · 速率 · 应用 · ' + devs.length + ' / ' + mx + ' 台', 'sim-add', '添加') +
    sFold('simlist', ['gray', 'dev'], '模拟设备列表', devs.length ? (sm.enabled ? '在线 ' + devs.filter(function (x) { return x.online !== false; }).length + ' 台 · 可逐台删除' : '模拟环境关闭中，设备页不显示') : '空', list, val(devs.length + ' 台'));
}
function simAddSheet() {
  var types = S.sim && Array.isArray(S.sim.types) && S.sim.types.length ? S.sim.types : Object.keys(SIM_T), pick = 'phone';
  sheet('<h3>添加模拟设备</h3><div class="sub">留空的项会随机生成；速率写成 3m / 512k / 字节数</div>' +
    '<label class="field">名称' + inp('sd-name', '', '', 'maxlength="32" placeholder="模拟-客厅电视" style="font-family:var(--font)"') + '</label>' +
    '<div class="note" style="margin:10px 0 6px">类型</div><div class="dchips" id="sd-type">' + types.map(function (k) { var t = SIM_T[k] || [k, '📶']; return '<button class="dchip cat' + (k === pick ? ' on' : '') + '" data-sdt="' + esc(k) + '">' + t[1] + ' ' + esc(t[0]) + '</button>'; }).join('') + '</div>' +
    '<div class="grid2" style="margin-top:12px"><label class="field">下行速率' + inp('sd-rx', '', 'B/s', 'maxlength="16" placeholder="3m" autocapitalize="off"') + '</label><label class="field">上行速率' + inp('sd-tx', '', 'B/s', 'maxlength="16" placeholder="200k" autocapitalize="off"') + '</label></div>' +
    '<label class="field" style="margin-top:10px">应用（规则库 id）' + inp('sd-app', '', '', 'maxlength="32" placeholder="douyin / bilibili / wechat，留空随机" autocapitalize="off" style="font-family:var(--mono)"') + '</label>' +
    '<div class="btns" style="margin-top:14px"><button class="btn sec press" data-close>取消</button><button class="btn pri press" id="sd-ok">添加</button></div>');
  $('#sd-type').onclick = function (e) { var b = e.target.closest('[data-sdt]'); if (!b) return; pick = b.getAttribute('data-sdt'); $$('#sd-type [data-sdt]').forEach(function (x) { x.classList.toggle('on', x === b); }); };
  $('#sd-ok').onclick = function () {
    var p = { type: pick }, re = /^\d+(\.\d+)?\s*[kmg]?$/i, rx = $('#sd-rx').value.trim(), tx = $('#sd-tx').value.trim(), nm = $('#sd-name').value.trim(), ap = $('#sd-app').value.trim().toLowerCase();
    if (rx && !re.test(rx)) { toast('下行速率格式：3m / 512k / 字节数', 'err'); return; }
    if (tx && !re.test(tx)) { toast('上行速率格式：3m / 512k / 字节数', 'err'); return; }
    if (nm) p.name = nm; if (rx) p.rx = rx.replace(/\s+/g, ''); if (tx) p.tx = tx.replace(/\s+/g, ''); if (ap) p.app = ap;
    api.action('sim_device_add', p).then(function (r) { var dj = detailJSON(r); closeSheet(); toast('已添加 ' + (dj.name || nm || '模拟设备') + (S.sim && !S.sim.enabled ? ' · 记得打开模拟环境' : '')); return Promise.all([loadSim(), globalRefresh()]); })
      .then(function () { paintSimBanner(); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); });
  };
}
function simAfter(msg) { return function () { if (msg) toast(msg); return Promise.all([loadSim(), loadConfig().catch(function () {})]).then(function () { return globalRefresh(); }).then(function () { paintSimBanner(); if (S.page === 'settings') renderSettings(false); }); }; }
function sItem(ic, t, s, right, attrs) { return '<div class="row"' + (attrs || '') + '>' + gi(ic[0], ic[1]) + '<span class="tx"><div class="t">' + t + '</div>' + (s ? '<div class="s">' + s + '</div>' : '') + '</span>' + (right || '') + '</div>'; }
function sBtn(ic, t, s, act, hint, cls) { return '<button class="row" data-act="' + act + '">' + gi(ic[0], ic[1]) + '<span class="tx"><div class="t">' + t + '</div>' + (s ? '<div class="s">' + s + '</div>' : '') + '</span>' + (hint ? '<span class="hint-a ' + (cls || '') + '">' + hint + '</span>' : ico('right', 'chev')) + '</button>'; }
function sFold(key, ic, t, s, body, ctrl) {
  return '<div class="row-wrap' + (S.open[key] ? ' open' : '') + '" data-foldkey="' + key + '"><div class="row-h" style="padding:12px 14px"><button data-act="fold" data-key="' + key + '" style="display:flex;align-items:center;gap:12px;flex:1;min-width:0;text-align:left">' + gi(ic[0], ic[1]) +
    '<span class="tx"><div class="t">' + t + '</div>' + (s ? '<div class="s">' + s + '</div>' : '') + '</span></button>' + (ctrl || '') +
    '<button data-act="fold" data-key="' + key + '" aria-label="展开" style="padding:6px">' + ico('chev', 'chev') + '</button></div><div class="fold"><div><div class="fold-in set-body">' + body + '</div></div></div></div>';
}
function val(v, cls) { return '<span class="v ' + (cls || '') + '">' + v + '</span>'; }
function inp(id, v, u, attrs) { return '<span class="box"><input id="' + id + '" value="' + esc(v == null ? '' : v) + '" ' + (attrs || 'type="number" min="0"') + '>' + (u ? '<span class="u">' + u + '</span>' : '') + '</span>'; }
function rateToMbps(r) { r = String(r || '').toLowerCase().trim(); var n = parseFloat(r); if (!(n > 0)) return ''; return trim0((/kbit/.test(r) ? n / 1000 : /gbit/.test(r) ? n * 1000 : n).toFixed(3)); }
function capsSummary() {
  var c = S.caps || {}, keys = ['tc_htb', 'tc_netem', 'uplink_supported', 'tc_cake', 'tc_fq_codel', 'ifb', 'sqm_supported'], ok = 0, n = 0;
  keys.forEach(function (k) { if (typeof c[k] === 'boolean') { n++; if (c[k]) ok++; } });
  return n ? ok + ' / ' + n + ' 可用' : '未知';
}
function schedDesc(c) {
  var a = [];
  if (c.hotspot_time_enable) a.push((c.hotspot_time_start || '?') + ' – ' + (c.hotspot_time_end || '?'));
  if (c.hotspot_charging_only) a.push('仅充电时');
  return a.length ? '已启用 · ' + a.join(' · ') : '按时段 / 充电状态自动开关热点 · 未启用';
}
function remoteUrl() { var i = S.ifaceInfo || {}, h = i.gateway || i.ip || S.hotspot.ip; return h ? 'https://' + h + ':8443' : ''; }
/* USB / 蓝牙共享只上报不管控 */
function tetherNote(l) {
  var u = Array.isArray(l.usb_tether) ? l.usb_tether : [], b = Array.isArray(l.bt_tether) ? l.bt_tether : [];
  if (!u.length && !b.length) return '';
  var what = [u.length ? 'USB 共享' : '', b.length ? '蓝牙共享' : ''].filter(Boolean).join(' + ');
  return '<div class="row">' + gi('orange', 'warn') + '<span class="tx"><div class="t">检测到' + what + '</div><div class="s">USB/蓝牙共享的设备不受 HNC 管控：限速、封锁、统计只作用于 WiFi 热点</div></span>' + val(esc(u.concat(b).join(' · ')), 'warn') + '</div>';
}
/* 设备限速叶子默认用 AQM(cake / fq_codel)还是 FIFO 占位; 后端不回显当前档位 → 记本地最后一次设置 */
function aqmRowHtml(c) {
  var q = S.qcaps, ch = qdChosen(), mode = c.tc_leaf_aqm || S.aqmMode || LS.get('hnc6.aqm', 'auto');
  if (['auto', 'on', 'off'].indexOf(mode) < 0) mode = 'auto';
  var elig = q ? q.default_leaf_aqm_eligible === true || ch === 'cake' || ch === 'fq_codel' : false;
  var eff = mode === 'on' || (mode === 'auto' && elig), av = q && Array.isArray(q.available) ? q.available : [];
  var desc = q ? (av.length ? '内核可用：' + av.map(function (x) { return QD_T[x] || x; }).join(' / ') : '内核没有测到可用的队列') + (ch ? ' · 选定 ' + (QD_T[ch] || ch) : '') + (mode === 'auto' && !elig ? ' · 自动模式只在有 cake / fq_codel 时开启' : '') : '尚未探测（重启 HNC 服务后生成）';
  return '<div class="row" style="align-items:flex-start" id="aqm-row">' + gi('cyan', 'layers') + '<span class="tx"><div class="t">默认队列 AQM</div><div class="s">限速设备的默认队列用 AQM 减少排队延迟 · 只影响之后新设 / 重设的限速</div>' +
    '<div style="margin-top:8px">' + seg('aqm-mode', [['auto', '自动'], ['on', '开'], ['off', '关']], mode, 'small') + '</div><div class="note" style="margin-top:6px">' + esc(desc) + '</div></span>' + val(eff ? '开 · ' + esc(ch ? QD_T[ch] || ch : sqmLabel()) : '关', eff ? 'ok' : '') + '</div>';
}
function renderSettings(anim1) {
  var c = S.cfg || {}, ac = S.alertCfg || {}, mq = ac.monthly_quota || {}, an = ac.anomaly_traffic || {}, ud = ac.unknown_device || {}, sla = S.sla || {}, rs = S.runStatus || {};
  var gsOn = c.global_shaper_enabled === true, hsAuto = c.hotspot_autostart === true, lv = S.live || {};
  var groups = [];
  var scR = scRep(), scW = scR ? (num((scR.summary || {}).fail) ? 'fail' : num((scR.summary || {}).warn) ? 'warn' : 'ok') : '';
  groups.push(['诊断', sBtn([scW === 'fail' ? 'red' : scW === 'warn' ? 'orange' : 'green', 'check'], '自检报告', SC.running ? '正在自检…' : scR ? scAgo(scR.generated_at) + '生成 · ' + scSumTxt(scR.summary) : '一键检查限速能力、防火墙、热点、IPv6、时间等，约 20 秒', 'sc-open', scR ? '查看' : '一键自检') + sFold('logs', ['gray', 'doc'], '运行日志', 'service · hotspotd · dpid · iptables/tc 等',
    '<div style="display:flex;gap:8px"><select class="selbox" id="log-file" style="flex:1">' + LOG_FILES.map(function (f) { return '<option' + (f === S.logFile ? ' selected' : '') + '>' + f + '</option>'; }).join('') + '</select><button class="btn sec press" data-act="log-refresh">' + ico('refresh') + '刷新</button><button class="btn sec press" data-act="log-copy">' + ico('copy') + '</button></div>' +
    '<div class="logv" id="logv"><div class="t">展开后自动加载</div></div>')]);
  groups.push(['热点', sFold('hs', ['blue', 'wifi'], '开机自动开热点', '开机后自动开 WiFi 热点；ColorOS 可能不放行命令行开热点',
      '<div class="grid2"><label class="field">SSID<span class="box"><input id="hs-ssid" maxlength="32" placeholder="留空 = 用系统热点设置" value="' + esc(c.hotspot_ssid || '') + '" style="font-family:var(--font)"></span></label>' +
      '<label class="field">密码<span class="box"><input id="hs-pass" type="password" maxlength="63" placeholder="留空 = 不改" autocomplete="new-password"></span></label></div>' +
      '<label class="field">开机后延迟<span class="box"><input id="hs-delay" type="number" min="0" max="3600" value="' + esc(c.hotspot_delay_sec == null ? '' : c.hotspot_delay_sec) + '" placeholder="0"><span class="u">秒</span></span></label>' +
      '<div class="btns"><button class="btn sec press" data-act="hs-start">' + ico('power') + '立即开启</button><button class="btn sec press" data-act="hs-stop">立即关闭</button><button class="btn pri press" data-act="hs-save">保存</button></div>',
      toggle(hsAuto, 'data-set="hs-auto" aria-label="开机自动开热点"')) +
    sFold('hsched', ['purple', 'bolt'], '定时与充电', schedDesc(c),
      '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">按时段开关热点</div><div class="s">进入时段自动开，离开时段自动关；跨午夜可填 22:00 → 07:00</div></span>' + toggle(c.hotspot_time_enable, 'data-local="sched-time" aria-label="按时段开关热点"') + '</div>' +
      '<div class="grid2"><label class="field">开始<span class="box"><input id="hs-t-start" type="time" value="' + esc(c.hotspot_time_start || '08:00') + '"></span></label><label class="field">结束<span class="box"><input id="hs-t-end" type="time" value="' + esc(c.hotspot_time_end || '23:00') + '"></span></label></div>' +
      '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">只在充电时开热点</div><div class="s">拔掉充电器后自动关热点，插上后自动开（同时受时段限制）</div></span>' + toggle(c.hotspot_charging_only, 'data-local="sched-charge" aria-label="只在充电时开热点"') + '</div>' +
      '<div class="note">只在状态切换的那一刻动作：时段外你手动开的热点不会被反复关掉。开机自启也遵守这里的规则。</div>' +
      '<button class="btn pri press" data-act="sched-save">保存</button>') +
    sItem(['blue', 'wifi'], '热点接口', '当前热点使用的接口（实时）' + (lv.iface_method ? ' · 识别方式：' + esc(IFM_T[lv.iface_method] || lv.iface_method) : ''), val(esc(S.hotspot.iface || '—') + (S.hotspot.active === false ? ' · 未开启' : ''))) + tetherNote(lv) +
    sFold('iface', ['cyan', 'wifi'], '热点接口偏好', '默认自动识别；ColorOS 常见 wlan2', '<div style="display:flex;gap:8px">' + inp('iface-pref', c.hotspot_iface || 'auto', '', 'maxlength="15" placeholder="auto" style="font-family:var(--mono)"') + '<button class="btn pri press" data-act="iface-save">保存</button></div><div class="note">填 auto 让 HNC 自动识别；手动填接口名（如 wlan2 / ap0）用于识别不准的机型。</div>', val(esc(c.hotspot_iface || 'auto'))) +
    sItem(['orange', 'rocket'], '硬件 offload', 'BPF tether 是否绕过 tc 限速', val((OFFLOAD_T[S.offload.detail] || S.offload.detail || '—') + (S.offload.guard && S.offload.guard.fallback_active ? ' · 已兜底' : ''), S.offload.detail === 'ACTIVE' && !(S.offload.guard && S.offload.guard.fallback_active) ? 'warn' : 'ok')) +
    sItem(['red', 'shield'], '网站封锁 · DNS 层', '封锁网站时顺带拦掉该设备对这个域名的 DNS 查询，第一次连接就拦住', val({ available: '可用', unavailable: '内核不支持（只按 IP 拦）', unknown: '首次封锁时检测' }[c.conn_block_dns_layer] || '—', c.conn_block_dns_layer === 'unavailable' ? 'warn' : 'ok'))]);
  groups.push(['设备', mergeSettingsHtml()]);   // 随机 MAC 合并
  // 告警总开关 + 新设备接入提醒(后端早就有, 旧新界面都没做设置)
  groups.push(['告警', sItem(['red', 'bolt'], '告警总开关', '关掉后所有提醒都不再产生（已有记录保留）', toggle(ac.enabled !== false, 'data-set="amaster" aria-label="告警总开关"')) +
    sFold('ud', ['blue', 'wifi'], '新设备接入提醒', '陌生设备连上热点时提醒；认识的设备可在告警里点「认识它」',
      '<div class="grid2"><label class="field">免打扰开始' + inp('ud-qs', ud.quiet_hour_start != null ? ud.quiet_hour_start : 23, '点', 'type="number" min="0" max="23"') + '</label><label class="field">免打扰结束' + inp('ud-qe', ud.quiet_hour_end != null ? ud.quiet_hour_end : 7, '点', 'type="number" min="0" max="23"') + '</label></div>' +
      '<label class="field">同一台设备最短提醒间隔' + inp('ud-iv', Math.round(num(ud.min_interval_sec, 1800) / 60), '分钟', 'type="number" min="1" max="1440"') + '</label>' +
      '<div class="note">免打扰时段内只记录、不弹通知；开始 = 结束 表示不设免打扰。</div><button class="btn pri press" data-act="ud-save">保存</button>',
      toggle(ud.enabled !== false, 'data-set="ud" aria-label="新设备接入提醒"')) +
    sFold('aq', ['orange', 'gauge'], '月度流量配额', '每台设备按自然月累计，超配额提醒',
      '<div class="grid2"><label class="field">配额' + inp('aq-gb', mq.limit_bytes ? trim0((mq.limit_bytes / 1073741824).toFixed(1)) : 10, 'GB/台/月', 'type="number" min="0.1" step="0.1"') + '</label><label class="field">预警' + inp('aq-pct', mq.warn_at_pct || 80, '%', 'type="number" min="1" max="100"') + '</label></div><button class="btn pri press" data-act="aq-save">保存</button>',
      toggle(mq.enabled, 'data-set="aq" aria-label="月度流量配额"')) +
    sFold('aa', ['red', 'heart'], '异常流量检测', '当前小时超过 7 日同时段均值 × 阈值时提醒',
      '<div class="grid2"><label class="field">倍数阈值' + inp('aa-ratio', an.ratio_threshold || 3, '倍', 'type="number" min="1.1" step="0.1"') + '</label><label class="field">最低量' + inp('aa-mb', an.min_bytes ? Math.round(an.min_bytes / 1048576) : 50, 'MB') + '</label></div><button class="btn pri press" data-act="aa-save">保存</button>',
      toggle(an.enabled, 'data-set="aa" aria-label="异常流量检测"'))]);
  groups.push(['全局带宽整形', sFold('gs', ['purple', 'layers'], '启用全局带宽整形', '给整个热点设 WAN 上限 + 智能队列，抗 bufferbloat',
    '<div class="grid2"><label class="field">下行上限' + inp('gs-down', rateToMbps(c.global_shaper_down), 'Mbps', 'type="number" min="0" step="0.1"') + '</label><label class="field">上行上限' + inp('gs-up', rateToMbps(c.global_shaper_up), 'Mbps', 'type="number" min="0" step="0.1"') + '</label></div>' +
    '<div class="note">填宽带/流量套餐实测速度的 85~90%。当前队列：' + sqmLabel() + (htbOk() ? '' : ' · <b>内核不支持 HTB，无法启用</b>') + '</div><button class="btn pri press" data-act="gs-apply">应用</button>',
    toggle(gsOn, 'data-set="gs" aria-label="全局带宽整形"' + (htbOk() ? '' : ' disabled'))) + aqmRowHtml(c)]);
  var fx = c.flywheel_exclude_user || [];
  groups.push(['飞轮排除名单', sFold('fw', ['cyan', 'shield'], '不参与规则学习的应用', 'VPN / 代理会代理别的应用流量，排除后不污染规则 · ' + fx.length + ' 个',
    '<div class="chips">' + (fx.length ? fx.map(function (p) { return '<span class="chip">' + esc(p) + '<button class="linkish danger" data-fw-del="' + esc(p) + '" aria-label="移除">×</button></span>'; }).join('') : '<span class="note">还没有手动排除的应用（内置名单已包含常见 VPN / 代理）</span>') + '</div>' +
    '<div style="display:flex;gap:8px">' + inp('fw-pkg', '', '', 'maxlength="128" placeholder="包名，如 com.github.metacubex.clash.meta" style="font-family:var(--mono)"') + '<button class="btn pri press" data-act="fw-add">添加</button></div><div class="note">约 5 分钟内生效；也可以在应用页的应用详情里一键排除。</div>')]);
  var m = S.metrics || {}, age = S.lastOk ? Math.round((Date.now() - S.lastOk) / 1000) : null;
  groups.push(['刷新与功耗', sFold('rmode', ['green', 'refresh'], '设备页刷新模式', '实时更跟手；省电会降低前台轮询频率', seg('rmode', [['realtime', '实时'], ['balanced', '均衡'], ['powersave', '省电']], S.refreshMode), val({ realtime: '实时', balanced: '均衡', powersave: '省电' }[S.refreshMode])) +
    sItem(['gray', 'info'], '数据新鲜度', '/api/live 最近一次成功返回', val(age == null ? '—' : age <= 2 ? '刚刚' : age + ' 秒前', age != null && age <= 8 ? 'ok' : 'warn'), ' id="fresh-row"') +
    sItem(['gray', 'cpu'], '控制面指标', m.instrumented === false ? '实时读取（未开启埋点）' : 'snapshot ' + (m.snapshot_age_ms != null ? m.snapshot_age_ms + 'ms' : '—') + ' · cache ' + num(m.json_cache_hits) + '/' + num(m.json_cache_misses) + ' · shell 兜底 ' + num(m.shell_fallback_count), val(S.metrics ? '正常' : '—', S.metrics ? 'ok' : '')) +
    sFold('caps', ['gray', 'flask'], '兼容性能力', 'tc / IFB / netem / 队列 / 启动器', '<dl class="kv">' + Object.keys(S.caps || {}).filter(function (k) { var v = S.caps[k]; return v !== null && typeof v !== 'object'; }).sort().map(function (k) { var v = S.caps[k]; return '<dt>' + esc(k) + '</dt><dd style="color:' + (v === true ? 'var(--badge-ok)' : v === false ? 'var(--badge-red)' : 'inherit') + '">' + esc(String(v)) + '</dd>'; }).join('') + '</dl>', val(capsSummary()))]);
  var rUrl = remoteUrl(), remOn = c.remote_enabled === true;
  groups.push(['远程访问', (KSU ? sItem(['blue', 'globe'], '启用远程访问服务', '开启后 :8443 监听，热点内其他设备可用浏览器访问（约 1 分钟生效）', toggle(remOn, 'data-set="remote" aria-label="远程访问服务"')) : sItem(['blue', 'globe'], '远程访问服务', '你正在通过远程访问使用 HNC；开关只能在本机 WebUI 里改', val('已开启', 'ok'))) +
    (remOn || !KSU ? '<div class="row">' + gi('gray', 'link') + '<span class="tx"><div class="t">访问地址</div><div class="s mono">' + esc(rUrl || '无法获取本机 IP · 请确认热点已开启') + '</div></span>' + (rUrl ? '<button class="linkish" data-act="url-copy">复制</button><button class="linkish" data-act="url-share">分享</button>' : '') + '</div>' : '') +
    sBtn(['orange', 'star'], '生成配对码', '远端新设备首次连接用 · 120 秒有效', 'pair-new', '生成') +
    (c.webui_access ? sFold('webacc', ['red', 'shield'], 'WebUI 访问控制', { all: '热点内所有设备都能打开登录页', allowlist: '只有名单里的设备能连接', local_only: '只有本机能打开' }[c.webui_access.mode || 'all'] || '',
      seg('webacc-mode', [['all', '全部'], ['allowlist', '白名单'], ['local_only', '仅本机']], S.webaccMode || c.webui_access.mode || 'all', 'small') +
      '<label class="field" style="margin-top:10px">白名单（MAC 或 IP，逗号分隔，最多 32 个）' + inp('webacc-macs', (c.webui_access.macs || []).join(', '), '', 'placeholder="aa:bb:cc:dd:ee:ff, 192.168.43.25"') + '</label>' +
      '<div class="note">在防火墙层直接断开不允许的设备；蜂窝网络上任何模式都连不上。本机和 KSU 里的 WebUI 永远可用。设置会把你自己锁在外面时会被拒绝。' + (c.webui_access.firewall ? '<br>防火墙状态：' + esc(c.webui_access.firewall) : '') + '</div>' +
      '<button class="btn pri wide press" data-act="webacc-save">保存</button>', val({ all: '全部', allowlist: '白名单', local_only: '仅本机' }[c.webui_access.mode || 'all'] || '—')) : '') +
    sFold('tokens', ['gray', 'dev'], '已授权设备', '管理能远程访问的设备' + (KSU ? '' : ' · 撤销只能在本机操作'), '<div id="tokens-list" class="note">展开后加载</div>')]);
  groups.push(['运行状态', (!S.runStatus ? sItem(['gray', 'cpu'], '运行状态', '后端暂未提供 /api/run_status', val('—')) :
    sItem(['green', 'cpu'], 'hotspotd 进程', rs.hotspotd_pid ? 'pid ' + rs.hotspotd_pid + (rs.hotspotd_rss_kb ? ' · ' + Math.round(rs.hotspotd_rss_kb / 1024) + ' MB' : '') : '未运行', val(rs.hotspotd === 'up' ? '运行中' : '未运行', rs.hotspotd === 'up' ? 'ok' : 'bad')) +
    sItem(['purple', 'layers'], 'tc 规则数', 'qdisc + class（热点接口 + IFB）', val(num(rs.tc_rules))) +
    sItem(['orange', 'shield'], 'iptables 规则', 'mangle 表里 HNC 的 MARK 规则', val(num(rs.ipt_rules))) +
    sItem(['blue', 'heart'], 'watchdog', '后台健康检查进程', val(num(rs.watchdog) > 0 ? '正常' : '未运行', num(rs.watchdog) > 0 ? 'ok' : 'bad'))) + scStatusRows()]);
  var nz = function (v) { return v == null ? '未统计' : String(v); }, slaCls = function (v) { return v == null ? '' : num(v) ? 'warn' : 'ok'; };
  groups.push(['运行健康', statsHealthHtml() + (!S.sla ? sItem(['gray', 'heart'], '运行健康', '暂无数据', val('—')) :
    sItem(['gray', 'refresh'], 'dpid 重启 / 近期崩溃', '累计重启 · 近期崩溃循环', val(nz(sla.dpid_restart_count) + ' / ' + nz(sla.dpid_crash_recent), num(sla.dpid_crash_recent) ? 'warn' : '')) +
    sItem(['gray', 'layers'], 'watchdog 全量重建', 'tc 树被整体重建的次数', val(nz(sla.watchdog_full_restore_count), slaCls(sla.watchdog_full_restore_count))) +
    sItem(['gray', 'tool'], 'tc 修复失败 / 上行失败', '自修复熔断 · 上行 IFB/police 失败', val(nz(sla.tc_repair_fail_count) + ' / ' + nz(sla.uplink_fail_count), sla.tc_repair_fail_count == null && sla.uplink_fail_count == null ? '' : num(sla.tc_repair_fail_count) + num(sla.uplink_fail_count) ? 'warn' : 'ok')) +
    sItem(['gray', 'doc'], 'JSON 退回 legacy', '应长期为 0', val(nz(sla.json_legacy_fallback_count), slaCls(sla.json_legacy_fallback_count))) +
    sItem(['gray', 'flask'], '能力降级标记', 'qos_fallback / uplink_unsupported', val([sla.qos_fallback_active ? 'QoS 兼容链路' : '', sla.uplink_unsupported ? '上行不支持' : ''].filter(Boolean).join(' · ') || '无', sla.qos_fallback_active || sla.uplink_unsupported ? 'warn' : 'ok')))]);
  groups.push(['维护', sBtn(['blue', 'refresh'], '重启 HNC 服务', '重跑 post-fs-data.sh + service.sh', 'svc-restart', '重启', 'danger') +
    sFold('ttl', ['orange', 'refresh'], '离线规则自动清理', num(c.stale_rule_ttl_days, 30) ? '设备离线超过 ' + num(c.stale_rule_ttl_days, 30) + ' 天后，自动删掉它的限速/延迟规则' : '已关闭 · 离线设备的规则永久保留',
      '<div style="display:flex;gap:8px"><span class="box" style="flex:1"><input id="ttl-days" type="number" min="0" max="3650" value="' + num(c.stale_rule_ttl_days, 30) + '"><span class="u">天</span></span><button class="btn pri press" data-act="ttl-save">保存</button></div><div class="note">填 0 = 永不自动清理。黑名单不受影响。</div>',
      val(num(c.stale_rule_ttl_days, 30) ? num(c.stale_rule_ttl_days, 30) + ' 天' : '关闭')) +
    sBtn(['orange', 'trash'], '清理缓存', 'hostname_cache · dev_class_cache', 'cache-clear', '清理', 'warn') +
    sBtn(['green', 'down'], '导出规则', '复制 rules.json（限速/延迟/黑名单/模板）', 'rules-json', '导出') +
    (KSU ? sBtn(['cyan', 'doc'], 'JSON 健康面板', 'rules / devices / tokens 的完整性与备份', 'json-health', '打开') : '') +
    sBtn(['purple', 'down'], '导出诊断包', '快照、配置、日志尾部和 tc/iptables/ip 状态', 'debug-bundle', '导出')]);
  // 应用识别 —— 强制 QUIC 回落 TCP
  groups.push(['应用识别', sItem(['purple', 'flask'], '强制 QUIC 回落 TCP', '拦下 UDP 443（HTTP/3），App 会立刻改走 TCP，看得到域名、识别和限速更准；首包可能慢几十毫秒。识别不准时再打开', toggle(c.quic_block === true, 'data-set="quic" aria-label="强制 QUIC 回落 TCP"')) +
    sItem(['blue', 'shield'], '自动获取服务器证书', '「新发现的应用」会主动连一次陌生域名读取证书上的公司名（只读证书，不发送数据）', toggle(c.discover_cert_probe !== false, 'data-set="certprobe" aria-label="自动获取服务器证书"')) +
    (S.appLimitSharedKnown ? sItem(['orange', 'warn'], '按应用限速包含共享 IP', '（可能误伤其他应用）CDN 地址常被多个应用共用；默认跳过这些地址，打开后也一起限速', toggle(S.appLimitShared, 'data-set="appshared" aria-label="按应用限速包含共享 IP"')) : '') +
    encdnsSettingsHtml() +
    sBtn(['purple', 'search'], '新发现的应用', '规则库认不出的应用 · 确认后加入规则库', 'disc-open', '查看')]);
  var cs = S.clsact;
  var gm = c.clsact_bpf_mode || (c.clsact_bpf_enabled === true ? 'on' : 'auto'), og = c.offload_guard || S.offload.guard || null;
  var ogS = gm === 'off' ? '已关闭：不做任何处理' : !og ? '等待第一次检测（约 1 分钟）' : og.fallback_active ? '兜底生效中：已让系统加速退回常规转发' + (og.since ? '（' + ago(og.since) + '起）' : '') : (OG_T[og.offload_state] || og.offload_state || '—');
  groups.push(['硬件加速兜底', sItem(['orange', 'rocket'], '防止系统热点加速绕过限速', '自动：检测到加速正在转发流量时，才让它退回常规路径，保证限速 / 封锁 / 统计都生效', '') +
    '<div class="row" style="padding-top:0">' + seg('guard-mode', [['auto', '自动'], ['on', '始终'], ['off', '关闭']], gm, 'small') + '</div>' +
    '<div class="row">' + gi(og && og.fallback_active ? 'green' : 'gray', 'layers') + '<span class="tx"><div class="t">当前状态</div><div class="s" id="guard-s">' + esc(ogS) + (og && og.detail && gm !== 'off' ? '<br>' + esc(og.detail) : '') + (og && og.last_check ? ' · ' + ago(og.last_check) + '检测' : '') + '</div></span></div>' +
    (gm === 'on' ? '<div class="row">' + gi('gray', 'flask') + '<span class="tx"><div class="t">clsact 打标（附带）</div><div class="s" id="clsact-s">' + (cs ? ['clsact', 'bpf_filter', 'map', 'watchdog'].map(function (k) { return k + (cs[k] ? ' ✓' : ' ✗'); }).join(' · ') : '点「检查」查看') + '</div></span><button class="linkish" data-act="clsact-check">检查</button>' + (cs && !(cs.clsact && cs.bpf_filter && cs.map && cs.watchdog) ? '<button class="linkish danger" data-act="clsact-repair">修复</button>' : '') + '</div>' : '')]);
  groups.push(['外观', sFold('look', ['purple', 'palette'], '主题与动画', ({ apple: '苹果风', liquid: '液态玻璃' }[S.style] || '默认风格') + ' · 浅色 / 深色 / 跟随系统 · 界面动画',
    '<div class="note" style="margin-bottom:-2px">界面风格</div><div class="style-pick">' + [['default', '默认', 'linear-gradient(135deg,#E7ECFF,#F3E9FF)', 'linear-gradient(90deg,#007AFF,#5856D6)', 'rgba(255,255,255,.85)'], ['apple', '苹果风', '#F2F2F7', '#007AFF', '#fff'], ['liquid', '液态玻璃', 'radial-gradient(60% 60% at 15% 10%,rgba(80,150,255,.35),transparent),radial-gradient(60% 60% at 90% 90%,rgba(255,120,190,.3),transparent),#FAFBFD', 'linear-gradient(180deg,#2B93FF,#0A74F5)', 'rgba(255,255,255,.6);box-shadow:inset 0 1px 0 #fff,0 2px 6px rgba(30,45,90,.12)']].map(function (t) {
      return '<button class="press' + (S.style === t[0] ? ' on' : '') + '" data-style-pick="' + t[0] + '"><span class="pv" style="background:' + t[2] + '"><i style="width:46%;background:' + t[3] + '"></i><i style="background:' + t[4] + '"></i><i style="width:80%;background:' + t[4] + '"></i></span>' + t[1] + '</button>'; }).join('') + '</div>' +
    '<a class="row" href="glass.html" style="padding:10px 0;min-height:0;text-decoration:none;color:inherit">' + gi('blue', 'palette') + '<span class="tx"><div class="t">预览全新界面 HNC Glass</div><div class="s">重新设计的液态玻璃界面 · 示例数据，不影响现在的设置</div></span>' + ico('right', 'chev') + '</a>' +
    '<div class="note" style="margin-bottom:-2px">颜色</div><div class="theme-pick">' + [['auto', '跟随系统', 'linear-gradient(135deg,#F5F5F7 50%,#1c1c1e 50%)'], ['light', '浅色', '#F5F5F7'], ['dark', '深色', '#1c1c1e']].map(function (t) {
      return '<button class="press' + (S.theme === t[0] ? ' on' : '') + '" data-theme-pick="' + t[0] + '"><span class="sw" style="background:' + t[2] + '"></span>' + t[1] + '</button>'; }).join('') + '</div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">界面动画</div><div class="s">弹簧切页、列表浮现、按压回弹</div></span>' + toggle(S.motion, 'data-set="motion" aria-label="界面动画"') + '</div>' + fxSettingsHtml())]);
  groups.push(['模拟环境（调试）', simGroupHtml()]);
  var l = S.live || {};
  groups.push(['关于', sItem(['blue', 'info'], '版本', 'HNC 后端 · versionCode ' + esc(l.backend_version_code || '—'), val(esc(l.backend_version || '—'))) +
    sBtn(['green', 'doc'], '更新日志', '查看完整变更记录', 'changelog', '查看') +
    (KSU ? '' : '<button class="row" data-act="logout">' + gi('red', 'lock') + '<span class="tx"><div class="t">退出登录</div><div class="s">清除这台设备的远程访问凭据</div></span><span class="hint-a danger">退出</span></button>')]);
  var html = groups.map(function (g) { return '<div><div class="sec" style="padding-bottom:8px"><span>' + g[0] + '</span></div><div class="glass rows">' + g[1] + '</div></div>'; });
  var half = 6;
  var h = '<div class="wrap">' + (wide() ? '<div class="cols"><div>' + html.slice(0, half).join('') + '</div><div>' + html.slice(half).join('') + '</div></div>' : html.join('')) +
    '<div class="foot">HNC · Hotspot Network Control' + (l.backend_version ? ' · ' + esc(l.backend_version) : '') + '</div></div>';
  var p = $('#p-settings'), y = p.scrollTop; p.innerHTML = h; placeSegs(p);
  if (anim1) { if (wide()) $$('.cols>div', p).forEach(function (x) { stagger(x); }); else stagger($('.wrap', p)); } else p.scrollTop = y;
  if (S.open.logs) loadLog();
  if (S.open.tokens) loadTokens();
}
function loadLog() {
  var el = $('#logv'); if (!el) return;
  api.get('/api/logs', { file: S.logFile === 'combined' ? 'combined' : S.logFile + '.log', tail: 300 }, { timeout: 10000 }).then(function (r) {
    S.logText = r.content || '';
    var lines = S.logText.split('\n').filter(Boolean).slice(-300);
    el.innerHTML = lines.length ? lines.map(function (ln) { var c = /\b(ERR|ERROR|FAIL|FATAL|panic)\b|失败|错误/i.test(ln) ? 'E' : /\bWARN|WARNING\b|警告/i.test(ln) ? 'W' : 'I'; return '<div class="' + c + '">' + esc(ln) + '</div>'; }).join('') : '<div class="t">(空)</div>';
    el.scrollTop = el.scrollHeight;
  }).catch(function (e) { el.innerHTML = '<div class="E">' + esc(errText(e)) + '</div>'; });
}
function loadTokens() {
  var el = $('#tokens-list'); if (!el) return;
  api.get('/api/tokens').then(function (r) {
    var t = r.tokens || [];
    el.className = '';
    el.innerHTML = t.length ? t.map(function (x) {
      return '<div class="row" style="padding:8px 0;min-height:0"><span class="tx"><div class="t">' + esc(x.label || '未命名设备') + '</div><div class="s mono">' + esc(x.ip_hint || '') + ' · ' + (x.last_seen ? new Date(x.last_seen * 1000).toLocaleString() : '从未使用') + ' · ' + esc(String(x.token_id || '').slice(0, 8)) + '</div></span>' +
        (KSU ? '<button class="hint-a danger" data-revoke="' + esc(x.token_id) + '" data-label="' + esc(x.label || '未命名设备') + '">撤销</button>' : '') + '</div>';
    }).join('') : '<div class="note">还没有已授权的设备</div>';
  }).catch(function (e) { el.className = 'note err'; el.textContent = errText(e); });
}
var pairT = 0;
function pairNew() {
  api.action('pair_new').then(function (r) {
    var d = detailJSON(r); if (!d.pin) throw new Error('没有拿到配对码');
    var left = num(d.valid_sec, 120), pin = String(d.pin), url = remoteUrl(), link = url ? url + '/pair?prefill=' + encodeURIComponent(pin) : '';
    sheet('<h3>配对码</h3><div class="sub">在新设备的浏览器里打开访问地址，输入这个配对码</div><div class="code num">' + esc(pin.slice(0, 3) + ' ' + pin.slice(3)) + '</div><div class="sub" id="pair-left"></div>' +
      (link ? '<div class="pair-link">' + esc(link) + '</div>' : '<div class="note warn" style="text-align:center;margin-bottom:12px">拿不到热点 IP，先开启热点和远程访问</div>') +
      '<div class="btns"><button class="btn sec press" id="pair-copy">复制配对码</button>' + (link ? '<button class="btn sec press" id="pair-link">复制链接</button>' : '') + '<button class="btn pri press" data-close>完成</button></div>', { onClose: function () { clearInterval(pairT); } });
    $('#pair-copy').onclick = function () { copyText(pin).then(function (ok) { toast(ok ? '已复制配对码' : '复制失败', ok ? 'ok' : 'err'); }); };
    if ($('#pair-link')) $('#pair-link').onclick = function () { copyText(link).then(function (ok) { toast(ok ? '已复制配对链接（打开后自动填好配对码）' : '复制失败', ok ? 'ok' : 'err'); }); };
    var tick = function () {
      var el = $('#pair-left'); if (!el) { clearInterval(pairT); return; }
      if (left <= 0) { el.textContent = '已过期，请重新生成'; el.style.color = 'var(--red)'; $('.code', $('#sheet')).style.opacity = '.35'; clearInterval(pairT); return; }
      el.textContent = Math.floor(left / 60) + ':' + pad2(left % 60) + ' 后失效'; left--;
    };
    clearInterval(pairT); tick(); pairT = setInterval(tick, 1000);
  }).catch(function (e) { toast('生成配对码失败：' + errText(e), 'err'); });
}
/* 设置 → 外观 → 动画效果 */
var FXP_T = { off: '关闭', calm: '克制', std: '标准', lively: '灵动', custom: '自定义' };
function fxSettingsHtml() {
  var pre = fxPreset();
  return '<div class="note" style="margin:8px 0 -2px">动画效果 · ' + FXP_T[pre] + (apple() ? '' : '（标注「苹果风」的效果在苹果风 / 液态玻璃下才有）') + '</div>' +
    seg('fxp', [['off', '关闭'], ['calm', '克制'], ['std', '标准'], ['lively', '灵动']], pre, 'small') +
    FX_LIST.map(function (x) {
      var dis = !S.motion && x[0] !== 'title' && x[0] !== 'haptic';
      return '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">' + x[1] + '</div><div class="s">' + x[2] + '</div></span>' + toggle(FX[x[0]], 'data-set="fx-' + x[0] + '" aria-label="' + x[1] + '"' + (dis ? ' disabled' : '')) + '</div>';
    }).join('') +
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">弹簧手感</div><div class="s">轻快：stiffness 300 / damping 30 · 有弹性：200 / 20</div></span>' + seg('fxspring', [['light', '轻快'], ['bouncy', '有弹性']], FX.spring, 'small') + '</div>' +
    '<div class="note" style="margin:6px 0 -2px">试一下</div><div class="chips">' + [['sheet', '弹层'], ['page', '切页'], ['list', '列表浮现'], ['num', '数字滚动']].map(function (b) { return '<button class="chip press" data-act="fx-demo" data-demo="' + b[0] + '">' + b[1] + '</button>'; }).join('') + '</div>' +
    '<div class="note">演示数字：<b class="num" id="fx-num" style="color:var(--text-1)">128.00</b> MB/s</div>' +
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">性能模式</div><div class="s">' + (PERF.low ? '已简化：去掉毛玻璃、背景缩放、共享元素展开，列表只浮现前 4 行' : '完整效果；连续掉帧时会自动简化') + (PERF.probe ? ' · 启动测得 ' + PERF.probe : '') + '</div></span><button class="linkish" data-act="fx-perf">' + (PERF.low ? '恢复完整' : '手动简化') + '</button></div>';
}
function fxRefresh() { applyTheme(); navSync(); if (S.page === 'settings') renderSettings(false); }
function fxDemo(k) {
  if (k === 'sheet') sheet('<h3>弹层演示</h3><div class="sub">从你点的按钮里长出来；按住往下拖可以关闭，背后的页面会跟着缩放</div>' +
    '<div class="dbox"><div class="row2"><span class="k">弹簧</span><span class="v">' + (FX.spring === 'bouncy' ? '有弹性 200 / 20' : '轻快 300 / 30') + '</span></div><div class="row2"><span class="k">性能模式</span><span class="v">' + (PERF.low ? '已简化' : '完整') + '</span></div></div>' +
    '<button class="btn pri wide press" data-close style="margin-top:14px">好的</button>');
  else if (k === 'page') { go('devices'); setTimeout(function () { go('settings'); }, 1100); }
  else if (k === 'list') { var w = $('#p-settings .wrap'); stagger(w, 14); }
  else if (k === 'num') { var el = $('#fx-num'); if (el) tween(el, Math.round(Math.random() * 90000) / 100, 2); }
}
function udParams(on) {
  var qs = Math.round(num($('#ud-qs') && $('#ud-qs').value, 23)), qe = Math.round(num($('#ud-qe') && $('#ud-qe').value, 7)), iv = Math.round(num($('#ud-iv') && $('#ud-iv').value, 30));
  qs = Math.min(23, Math.max(0, qs)); qe = Math.min(23, Math.max(0, qe)); iv = Math.min(1440, Math.max(1, iv));
  return { section: 'unknown_device', enabled: String(on), quiet_start: String(qs), quiet_end: String(qe), min_interval_sec: String(iv * 60) };
}
function reloadAlertCfg() { return api.getSafe('/api/alert_config', null, S.alertCfg).then(function (r) { S.alertCfg = r; if (S.page === 'settings') renderSettings(false); }); }
function setToggleCfg(kind, el) {
  var on = el.getAttribute('aria-checked') === 'true', rollback = function (e) { el.setAttribute('aria-checked', String(!on)); toast(errText(e), 'err'); };
  var done = function (msg) { return function (r) { toast(msg || ((el.getAttribute('aria-label') || '') + (on ? ' 已开启' : ' 已关闭'))); return loadConfig(); }; };
  if (kind.indexOf('fx-') === 0) { FX[kind.slice(3)] = on; saveFx(); fxRefresh(); return; }
  switch (kind) {
    case 'motion': S.motion = on; LS.set('hnc6.motion', on ? '1' : '0'); fxRefresh(); return;
    case 'hs-auto': api.action('hotspot_save', { autostart: on ? 'true' : 'false' }).then(done()).catch(rollback);
      var w = el.closest('[data-foldkey]'); if (on && w && !w.classList.contains('open')) foldToggle(w, 'hs'); return;
    case 'amaster': api.action('alert_config_set', { section: 'master', enabled: String(on) }).then(done()).then(reloadAlertCfg).catch(rollback); return;
    case 'ud': api.action('alert_config_set', udParams(on)).then(done()).then(reloadAlertCfg).catch(rollback); return;
    case 'aq': api.action('alert_config_set', { section: 'monthly_quota', enabled: String(on), limit_gb: String(num($('#aq-gb').value, 10)), warn_pct: String(Math.round(num($('#aq-pct').value, 80))) }).then(done()).catch(rollback); return;
    case 'aa': api.action('alert_config_set', { section: 'anomaly_traffic', enabled: String(on), ratio: String(num($('#aa-ratio').value, 3)), min_mb: String(Math.round(num($('#aa-mb').value, 50))) }).then(done()).catch(rollback); return;
    case 'gs':
      if (on) { var gw = el.closest('[data-foldkey]'); if (gw && !gw.classList.contains('open')) foldToggle(gw, 'gs'); el.setAttribute('aria-checked', 'false'); toast('填好上限后点「应用」启用'); return; }
      api.action('global_shaper_set', { enabled: 'false' }).then(done('全局带宽整形已关闭')).catch(rollback); return;
    case 'remote': api.action('remote_enabled_set', { enabled: String(on) }).then(function (r) { toast(on ? '远程访问已开启 · 约 1 分钟内可访问' : '远程访问已关闭 · 约 1 分钟内 :8443 关闭'); return loadConfig(); }).then(function () { if (S.page === 'settings') renderSettings(false); }).catch(rollback); return;
    case 'appshared': api.action('app_limit_shared_ips_set', { enabled: String(on) }).then(function () { S.appLimitShared = on; toast(on ? '已包含共享 IP · 同一 CDN 上的其他应用也可能被一起限速' : '已恢复：跳过与其他应用共用的地址'); return loadAppLimits(); }).catch(rollback); return;
    case 'certprobe': api.action('discover_cert_probe_set', { enabled: String(on) }).then(done()).catch(rollback); return;
    case 'sim': simSet(on).catch(rollback); return;
    case 'quic': api.action('quic_block_set', { enabled: String(on) }).then(function (r) { toast(on ? (/pending/.test(r && r.detail || '') ? '已开启 · 热点打开后生效' : '已开启 · QUIC 流量会回落到 TCP') : '已关闭 · 恢复 QUIC'); return loadConfig(); }).catch(rollback); return;
  }
}
function clsactCheck(quiet) {
  return api.action('clsact_check').then(function (r) { S.clsact = detailJSON(r); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { if (!quiet) toast(errText(e), 'err'); });
}
function hsStart() {
  api.action('hotspot_start').then(function () {
    toast('已发出开热点命令，等待系统响应…');
    var n = 0, t = setInterval(function () {
      n++;
      loadLive().then(function (l) {
        if (l.hotspot_active) { clearInterval(t); toast('热点已开启 · ' + (l.hotspot_iface || '')); globalRefresh(); }
        else if (n >= 12) { clearInterval(t); toast('约 24 秒还没开起来 · ColorOS 可能拦截了命令行开热点，详见日志 hotspot.log', 'warn'); }
      }).catch(function () { if (n >= 12) clearInterval(t); });
    }, 2000);
  }).catch(function (e) { toast(errText(e), 'err'); });
}
function hsSave() {
  var ssid = $('#hs-ssid').value.trim(), pass = $('#hs-pass').value, delay = $('#hs-delay').value.trim();
  if (pass && (pass.length < 8 || pass.length > 63)) { toast('密码需要 8~63 个字符', 'err'); return; }
  if (delay && !(num(delay) >= 0 && num(delay) <= 3600)) { toast('延迟需在 0~3600 秒', 'err'); return; }
  // 修旧版 bug: 旧版漏传 autostart, 每次保存都把「开机自启」关掉
  var p = { autostart: S.cfg.hotspot_autostart === true ? 'true' : 'false' };
  if (ssid) p.ssid = ssid; if (pass) p.password = pass; if (delay) p.delay_sec = String(Math.round(num(delay)));
  api.action('hotspot_save', p).then(function () { $('#hs-pass').value = ''; toast('热点配置已保存'); return loadConfig(); }).catch(function (e) { toast(errText(e), 'err'); });
}
function gsApply() {
  var d = num($('#gs-down').value), u = num($('#gs-up').value);
  if (!(d > 0) && !(u > 0)) { toast('至少填一个方向的上限', 'err'); return; }
  var p = { enabled: 'true' }; if (d > 0) p.rate_down = fmtRate(d); if (u > 0) p.rate_up = fmtRate(u);
  api.action('global_shaper_set', p).then(function (r) { toast('全局带宽整形已启用' + (r.detail ? ' · ' + String(r.detail).slice(0, 60) : '')); return loadConfig(); }).then(function () { if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); });
}
function exportRulesJson() {
  api.get('/api/rules_export', null, { timeout: 10000 }).then(function (r) {
    var txt = JSON.stringify(r.rules || r, null, 2);
    sheet('<h3>导出规则</h3><div class="sub">rules.json · ' + (txt.length / 1024).toFixed(1) + ' KB</div><textarea class="textarea" readonly id="rj">' + esc(txt) + '</textarea>' +
      '<div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>关闭</button>' + (KSU ? '<button class="btn sec press" id="rj-save">存到下载</button>' : '<button class="btn sec press" id="rj-dl">下载</button>') + '<button class="btn pri press" id="rj-copy">复制</button></div>', { tall: true });
    $('#rj-copy').onclick = function () { copyText(txt).then(function (ok) { toast(ok ? '已复制 rules.json' : '复制失败', ok ? 'ok' : 'err'); }); };
    var fn = 'hnc-rules-' + today() + '.json';
    if ($('#rj-dl')) $('#rj-dl').onclick = function () { var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], { type: 'application/json' })); a.download = fn; document.body.appendChild(a); a.click(); a.remove(); };
    if ($('#rj-save')) $('#rj-save').onclick = function () { shell('mkdir -p /sdcard/Download && cp ' + HNC_DIR + '/data/rules.json /sdcard/Download/' + fn + ' && echo ok').then(function () { toast('已存到 /sdcard/Download/' + fn); }, function (e) { toast(errText(e), 'err'); }); };
  }).catch(function (e) { toast(errText(e), 'err'); });
}
function debugBundle(btn) {
  btn.disabled = true; toast('正在生成诊断包（最长约 1 分钟）…');
  api.action('debug_bundle', {}, { timeout: 90000, maxTime: 88 }).then(function (r) {
    var d = detailJSON(r), name = d.name || String(r.detail || '').split('/').pop();
    if (KSU && /^[A-Za-z0-9._-]+$/.test(name)) return shell('mkdir -p /sdcard/Download && cp ' + sq(HNC_DIR + '/exports/' + name) + ' /sdcard/Download/ && echo ok').then(function () { toast('诊断包已存到 /sdcard/Download/' + name); });
    if (!KSU && name) { downloadExport(name, '/api/exports/' + encodeURIComponent(name)); toast('诊断包已生成 · ' + name); return; }
    toast('诊断包已生成');
  }).catch(function (e) { toast(errText(e), 'err'); }).then(function () { btn.disabled = false; });
}
/* ═════ 自检报告(GET /api/selfcheck · action selfcheck_run / selfcheck_export) ═════ */
var SC_ST = { ok: ['✓', '正常'], warn: ['!', '警告'], fail: ['✗', '失败'], info: ['·', '信息'] };
var SC_RANK = { fail: 3, warn: 2, ok: 1, info: 0 };
var SC_IC = { system: 'cpu', shaping: 'gauge', firewall: 'shield', offload: 'rocket', network: 'wifi', ipv6: 'layers', time: 'refresh', process: 'heart', ident: 'search' };
var SC = { running: false, t0: 0, timer: 0, waitT: 0, seenAt: 0, redact: LS.get('hnc6.sc-redact', '1') !== '0' };
function loadSelfcheck() {
  return api.getSafe('/api/selfcheck', null, null).then(function (r) {
    if (r && typeof r === 'object') { S.sc = r; if (r.running && !SC.running) scWaitIdle(); }
    return r;
  });
}
function scRep() { return S.sc && S.sc.available && Array.isArray(S.sc.sections) ? S.sc : null; }
function scSec(id) { var r = scRep(); if (!r) return null; for (var i = 0; i < r.sections.length; i++) if (r.sections[i].id === id) return r.sections[i]; return null; }
function scFind(sec, id) { var s = scSec(sec); if (!s) return null; var it = s.items || []; for (var i = 0; i < it.length; i++) if (it[i].id === id) return it[i]; return null; }
function scStat(st) { return SC_ST[st] ? st : 'info'; }
function scWorst(items) { var w = 'info'; (items || []).forEach(function (x) { var s = scStat(x.status); if (SC_RANK[s] > SC_RANK[w]) w = s; }); return w; }
function scCount(items) { var c = { ok: 0, warn: 0, fail: 0, info: 0 }; (items || []).forEach(function (x) { c[scStat(x.status)]++; }); return c; }
function scSumTxt(s) { s = s || {}; return '✓ ' + num(s.ok) + ' · ! ' + num(s.warn) + ' · ✗ ' + num(s.fail); }
function scAgo(ts) { return Date.now() / 1000 - num(ts) < 10 ? '刚刚' : ago(ts); }
function scDur(ms) { ms = num(ms); return ms >= 1000 ? (ms / 1000).toFixed(1) + ' 秒' : Math.round(ms) + ' 毫秒'; }
function scItemHtml(it) {
  var st = scStat(it.status);
  return '<div class="sc-it ' + st + '" data-scid="' + esc(it.id || '') + '"><span class="sc-i" aria-label="' + SC_ST[st][1] + '">' + SC_ST[st][0] + '</span><div style="min-width:0">' +
    '<div class="sc-l"><span class="t">' + esc(it.label || it.id || '') + '</span><span class="v">' + esc(it.value == null || it.value === '' ? '—' : it.value) + '</span></div>' +
    (it.detail ? '<div class="s">' + esc(it.detail) + '</div>' : '') + (it.fix ? '<div class="sc-fix"><b>建议</b>' + esc(it.fix) + '</div>' : '') + '</div></div>';
}
function scBody() {
  var r = scRep(), h = '', el = SC.running ? Math.floor((Date.now() - SC.t0) / 1000) : 0;
  h += SC.running ? '<button class="btn pri wide" data-act="sc-run" disabled><span class="spin"></span>正在自检… <span id="sc-el">' + el + '</span> 秒</button><div class="pbar" style="margin-top:8px"><i id="sc-pb" style="width:' + Math.min(95, el / 18 * 100).toFixed(0) + '%;animation:none;transition:width .5s linear"></i></div><div class="note" style="text-align:center;margin-top:6px">大约需要 20 秒，期间可以关掉这个窗口</div>'
    : '<button class="btn pri wide press" data-act="sc-run">' + ico('check') + (r ? '重新自检' : '一键自检') + '</button>';
  if (!r) return h + '<div class="note" style="text-align:center;margin-top:14px">' + (SC.running ? '' : '还没有自检记录。自检会检查机型与系统、限速能力、防火墙、硬件加速、热点、IPv6、时间、进程和识别引擎，只读不改任何设置。') + '</div>';
  var s = r.summary || {};
  h += '<div class="sc-meta">' + esc(scAgo(r.generated_at)) + '生成 · 耗时 ' + scDur(r.duration_ms) + (r.version ? ' · ' + esc(r.version) : '') + (r.redacted ? ' · 已打码' : '') + '</div>';
  h += '<div class="sc-chips">' + ['ok', 'warn', 'fail', 'info'].map(function (k) { return '<div class="sc-chip ' + k + (num(s[k]) ? ' has' : '') + '"><b class="num">' + SC_ST[k][0] + ' ' + num(s[k]) + '</b><span>' + SC_ST[k][1] + '</span></div>'; }).join('') + '</div>';
  if (SC.seenAt !== r.generated_at) {   // 新报告: 含警告 / 失败的分组自动展开, 其余收起
    SC.seenAt = r.generated_at;
    r.sections.forEach(function (sec) { var w = scWorst(sec.items); S.open['sc-' + sec.id] = w === 'warn' || w === 'fail'; });
  }
  h += '<div class="rows sc-secs">' + r.sections.map(function (sec) {
    var items = sec.items || [], w = scWorst(items), c = scCount(items);
    var sub = [c.fail ? c.fail + ' 失败' : '', c.warn ? c.warn + ' 警告' : '', c.ok ? c.ok + ' 正常' : '', c.info ? c.info + ' 信息' : ''].filter(Boolean).join(' · ') + (sec.elapsed_ms != null ? ' · 用时 ' + scDur(sec.elapsed_ms) : '');
    var badge = w === 'fail' ? '<span class="badge b-red">' + c.fail + ' 项失败</span>' : w === 'warn' ? '<span class="badge b-warn">' + c.warn + ' 项警告</span>' : '<span class="badge b-ok">正常</span>';
    return sFold('sc-' + sec.id, [w === 'fail' ? 'red' : w === 'warn' ? 'orange' : w === 'ok' ? 'green' : 'gray', SC_IC[sec.id] || 'flask'], esc(sec.title || sec.id), sub,
      '<div class="sc-items">' + (items.length ? items.map(scItemHtml).join('') : '<div class="note">（无检查项）</div>') + '</div>', badge);
  }).join('') + '</div>';
  h += '<div class="sc-exp"><span class="tx" style="flex:1;min-width:0"><div class="t" style="font-size:14px;font-weight:600">打码 MAC / IP</div><div class="note">导出给别人看时建议打开</div></span>' + toggle(SC.redact, 'id="sc-redact" data-local="sc-redact" aria-label="打码 MAC/IP"') + '</div>';
  h += '<div class="btns" style="margin-top:10px"><button class="btn sec press" data-close style="flex:1">关闭</button><button class="btn pri press" data-act="sc-export" style="flex:1.4">' + ico('down') + '导出报告</button></div>';
  return h;
}
function paintSc() {
  var b = $('#sc-body'); if (!b || $('#sheet').dataset.kind !== 'selfcheck') return;
  b.innerHTML = scBody(); placeSegs(b);
}
function scSheet() {
  sheet('<h3>自检报告</h3><div class="sub">检查这台手机能不能完整支持 HNC 的各项功能</div><div id="sc-body">' + scBody() + '</div>', { tall: true, kind: 'selfcheck', onClose: function () { if (S.page === 'settings') renderSettings(false); } });
  if (!SC.running) loadSelfcheck().then(paintSc);
}
function scTick() {
  clearInterval(SC.timer);
  SC.timer = setInterval(function () {
    if (!SC.running) { clearInterval(SC.timer); return; }
    var s = (Date.now() - SC.t0) / 1000, e = $('#sc-el'), p = $('#sc-pb');
    if (e) e.textContent = Math.floor(s); if (p) p.style.width = Math.min(95, s / 18 * 100).toFixed(0) + '%';
  }, 500);
}
function scDone() { SC.running = false; clearInterval(SC.timer); paintSc(); if (S.page === 'settings' && $('#sheet').dataset.kind !== 'selfcheck') renderSettings(false); }
function scBusy(e) { return e && (e.status === 409 || (e.body && e.body.error === 'busy') || /\bbusy\b/.test(String(e.message || ''))); }
/* 别处(另一个窗口 / 导出时顺带)正在跑: 每 2 秒看一次, 跑完就刷新 */
function scWaitIdle() {
  if (SC.running) return;
  SC.running = true; SC.t0 = Date.now(); paintSc(); scTick();
  var n = 0; clearInterval(SC.waitT);
  SC.waitT = setInterval(function () {
    n++;
    api.getSafe('/api/selfcheck', null, null).then(function (r) {
      if (r && !r.running) { clearInterval(SC.waitT); S.sc = r; scDone(); }
      else if (n >= 25) { clearInterval(SC.waitT); scDone(); }
    });
  }, 2000);
}
function scRun() {
  if (SC.running) return;
  SC.running = true; SC.t0 = Date.now(); paintSc(); scTick();
  api.action('selfcheck_run', {}, { timeout: 45000, maxTime: 43 }).then(function (r) {
    var rep = detailJSON(r);
    if (rep && Array.isArray(rep.sections)) { rep.available = true; rep.running = false; S.sc = rep; }
    var s = (rep && rep.summary) || {};
    toast('自检完成 · ' + scSumTxt(s), num(s.fail) ? 'err' : num(s.warn) ? 'warn' : 'ok');
    scDone();
  }).catch(function (e) {
    SC.running = false; clearInterval(SC.timer);
    if (scBusy(e)) { toast('自检正在进行，请稍候', 'warn'); scWaitIdle(); return; }
    toast('自检失败：' + errText(e), 'err'); paintSc();
  });
}
function scExport(btn) {
  var tg = $('#sc-redact'); if (tg) SC.redact = tg.getAttribute('aria-checked') === 'true';
  LS.set('hnc6.sc-redact', SC.redact ? '1' : '0');
  btn.disabled = true; toast('正在生成报告…');
  api.action('selfcheck_export', { redact: SC.redact ? '1' : '0' }, { timeout: 45000, maxTime: 43 }).then(function (r) {
    var d = detailJSON(r), name = String(d.name || ''), jn = String(d.json_name || ''), okN = /^[A-Za-z0-9._-]+$/;
    var tag = d.redacted ? '（已打码）' : '（未打码）';
    if (!okN.test(name)) { toast('报告已生成' + tag); return; }
    if (KSU) {
      var files = [name].concat(okN.test(jn) ? [jn] : []);
      return shell('mkdir -p /sdcard/Download && cp ' + files.map(function (f) { return sq(HNC_DIR + '/exports/' + f); }).join(' ') + ' /sdcard/Download/ && echo ok').then(function () { toast('报告已存到 /sdcard/Download/' + name + tag); });
    }
    downloadExport(name, '/api/exports/' + encodeURIComponent(name)); toast('报告已生成 · ' + name + tag);
  }).catch(function (e) { toast(scBusy(e) ? '自检正在进行，请稍候再导出' : errText(e), scBusy(e) ? 'warn' : 'err'); }).then(function () { btn.disabled = false; });
}
/* 设置页「运行状态」里的两行: 取自最近一次自检(没有单独的状态接口) */
function scStatusRows() {
  var r = scRep(), when = r ? '来自 ' + scAgo(r.generated_at) + '的自检' : '运行一次自检后显示';
  var cov = scFind('ipv6', 'v6_uncovered'), nb = scFind('ipv6', 'v6_neigh'), v6v = '—', v6c = '';
  if (cov) { var cs = scStat(cov.status); v6v = cs === 'ok' ? '全部覆盖' : cs === 'warn' ? cov.value + ' 个未覆盖' : String(cov.value || '').split(/[(（]/)[0]; v6c = cs === 'ok' ? 'ok' : cs === 'warn' || cs === 'fail' ? 'warn' : ''; }
  else if (nb) v6v = String(nb.value || '').split(/[,，]/)[0];
  var tsec = scSec('time'), tv = '—', tc = '';
  if (tsec) {
    var ck = scFind('time', 'clock'), at = scFind('time', 'auto_time'), tw = scWorst(tsec.items);
    tv = ck && ck.status === 'fail' ? '系统时间错误' : at && at.status === 'warn' ? '自动时间已关' : tw === 'warn' ? '有警告' : '正常';
    tc = tw === 'fail' ? 'bad' : tw === 'warn' ? 'warn' : 'ok';
  }
  return sItem(['cyan', 'layers'], 'IPv6 新地址跟踪', '设备换了新的 IPv6 临时地址后是否及时纳入限速 · ' + (nb && cov ? esc(nb.value) + ' · ' : '') + when, val(esc(v6v), v6c)) +
    sItem(['gray', 'refresh'], '系统时间', '按天统计、配额、定时规则都依赖系统时间 · ' + when, val(tv, tc));
}
var clCache = null;
function showChangelog() {
  sheet('<h3>更新日志</h3><div class="cl-body" id="cl-body"><div class="note" style="text-align:center">加载中…</div></div><button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true });
  (clCache ? Promise.resolve(clCache) : fetch('changelog.html', { cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })).then(function (txt) {
    clCache = txt;
    var doc = new DOMParser().parseFromString(txt, 'text/html');
    $$('script,iframe,object,embed,form,link,meta,style', doc).forEach(function (n) { n.remove(); });
    $$('*', doc.body).forEach(function (n) { Array.prototype.slice.call(n.attributes).forEach(function (a) { if (/^on/i.test(a.name) || (a.name === 'href' && /^\s*javascript:/i.test(a.value))) n.removeAttribute(a.name); }); });
    var b = $('#cl-body'); if (b) b.innerHTML = doc.body.innerHTML;
  }).catch(function (e) { var b = $('#cl-body'); if (b) b.innerHTML = '<div class="note err">读取 changelog.html 失败：' + esc(errText(e)) + '</div>'; });
}

