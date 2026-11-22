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
  var body = (is.length ? '<div class="sc-items">' + is.map(function (x) { var st = SH_LV[x.level] || 'info'; return '<div class="sc-it ' + st + '" data-shid="' + esc(x.id || '') + '"><span class="sc-i">' + SC_ST[st][0] + '</span><div style="min-width:0"><div class="s" style="margin:0;color:var(--text-2);font-size:13px">' + esc(x.text_cn || x.id) + '</div></div></div>'; }).join('') + '</div>' : '<div class="note">' + uiSvg('check') + ' 没有发现问题</div>') +
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
    loadMacMerge(), loadEncdns(), loadStatsHealth(), loadWhoami(), dpvLoadSilent()   // v5.40
  ]);
}
/* 模拟环境(调试) */
S.sim = null;
var SIM_T = { tv: ['电视', devSvg('tv', 'mini')], phone: ['手机', devSvg('phone', 'mini')], laptop: ['笔记本', devSvg('pc', 'mini')], tablet: ['平板', devSvg('tablet', 'mini')], game: ['游戏机', devSvg('console', 'mini')], iot: ['智能设备', devSvg('iot', 'mini')], pc: ['电脑', devSvg('pc', 'mini')] };
var SIM_P = { home: ['家庭', '晚上一家人：电视追剧 + 几台手机'], busy: ['繁忙', '下载 / 4K / 直播 / 会议，含限速和拉黑'], idle: ['空闲', '只有心跳流量，一台离线'] };
function loadSim() { return api.getSafe('/api/sim', null, null).then(function (r) { S.sim = r && (r.ok !== false) && Array.isArray(r.devices) ? r : null; if (S.sim) S.cfg.sim_enabled = S.sim.enabled === true; }); }
function simGroupHtml() {
  var sm = S.sim;
  if (!sm) return sItem(['gray', 'flask'], '模拟环境', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var devs = sm.devices || [], mx = num(sm.max, 32), presets = Array.isArray(sm.presets) && sm.presets.length ? sm.presets : ['home', 'busy', 'idle'];
  presets = ['home', 'busy', 'idle'].filter(function (x) { return presets.indexOf(x) >= 0; }).concat(presets.filter(function (x) { return !SIM_P[x]; }));
  var list = devs.length ? devs.map(function (x) {
    var t = SIM_T[x.type] || ['设备', devSvg('router', 'mini')], rx = bps(x.online === false ? 0 : num(x.cur_rx_bps, x.rx_bps)), tx = bps(x.online === false ? 0 : num(x.cur_tx_bps, x.tx_bps));
    return '<div class="simdev"><span class="simdev-ic">' + t[1] + '</span><span class="tx"><div class="t">' + esc(x.name || x.hostname || x.mac) + '</div><div class="s">' + t[0] + (x.online === false ? ' · 离线' : ' · ↓ ' + rx.v + ' ' + rx.u + ' ↑ ' + tx.v + ' ' + tx.u) + (x.app_name ? ' · ' + esc(x.app_name) : '') + (x.blocked ? ' · 已拉黑' : '') + '</div></span>' +
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
    '<div class="note" style="margin:10px 0 6px">类型</div><div class="dchips" id="sd-type">' + types.map(function (k) { var t = SIM_T[k] || [k, devSvg('router', 'mini')]; return '<button class="dchip cat' + (k === pick ? ' on' : '') + '" data-sdt="' + esc(k) + '">' + t[1] + ' ' + esc(t[0]) + '</button>'; }).join('') + '</div>' +
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
  var ek = esc(key);
  return '<div class="row-wrap' + (S.open[key] ? ' open' : '') + '" data-foldkey="' + ek + '"><div class="row-h" style="padding:12px 14px"><button data-act="fold" data-key="' + ek + '" style="display:flex;align-items:center;gap:12px;flex:1;min-width:0;text-align:left">' + gi(ic[0], ic[1]) +
    '<span class="tx"><div class="t">' + t + '</div>' + (s ? '<div class="s">' + s + '</div>' : '') + '</span></button>' + (ctrl || '') +
    '<button data-act="fold" data-key="' + ek + '" aria-label="展开" style="padding:6px">' + ico('chev', 'chev') + '</button></div><div class="fold"><div><div class="fold-in set-body">' + body + '</div></div></div></div>';
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
/* v5.38.0: 上游 5G 信号波动自适应总带宽 (CAKE/HTB Autorate) + 随机 MAC 全栈护栏 */
function autorateFoldHtml(c) {
  var ar = c.autorate || S.autorate || {};
  var on = ar.enabled === true;
  var stMap = { active: '动态巡航中', backoff: '拥塞退避压制中', sleeping: '空闲零唤醒休眠', disabled: '未启用' };
  var stTxt = stMap[ar.state] || (on ? '监控中' : '未启用');
  var rttTxt = on && num(ar.rtt_ms) > 0
    ? '当前上限 ↓' + num(ar.cur_down_mbps, 120) + ' / ↑' + num(ar.cur_up_mbps, 35) + ' Mbps · 蜂窝 RTT ' + num(ar.rtt_ms) + 'ms (基线 ' + num(ar.base_rtt_ms) + 'ms, Δ' + num(ar.delta_rtt_ms) + 'ms)'
    : (on ? '等待热点活跃流量触发探测（无流量时自动休眠 0 耗电）' : '实时探测 5G/蜂窝基站排队延迟(Bufferbloat)，信号变弱时自动收紧 HTB/CAKE 总上限，空闲时退回峰值');
  var body = '<div class="ar-pill"><span class="breathe' + (on && ar.state !== 'sleeping' ? '' : ' off') + '"></span><span><b>' + esc(stTxt) + '</b> · ' + esc(rttTxt) + '</span></div>' +
    '<div class="grid2"><label class="field">下行保底' + inp('ar-dmin', num(ar.down_min_mbps, 24), 'Mbps', 'type="number" min="1" max="2000" step="1"') + '</label>' +
    '<label class="field">下行峰值' + inp('ar-dmax', num(ar.down_max_mbps, 320), 'Mbps', 'type="number" min="2" max="2000" step="1"') + '</label></div>' +
    '<div class="grid2"><label class="field">上行保底' + inp('ar-umin', num(ar.up_min_mbps, 8), 'Mbps', 'type="number" min="1" max="1000" step="1"') + '</label>' +
    '<label class="field">上行峰值' + inp('ar-umax', num(ar.up_max_mbps, 80), 'Mbps', 'type="number" min="2" max="1000" step="1"') + '</label></div>' +
    '<label class="field">拥塞退避 RTT 膨胀阈值 (ΔRTT)' + inp('ar-delta', num(ar.rtt_delta_ms, 25), 'ms', 'type="number" min="8" max="200" step="1"') + '</label>' +
    '<div class="note">直绑上游 <span class="mono">rmnet_data* / ccmni*</span> 蜂窝口做轻量 TCP 握手测距：ΔRTT 超过阈值即刻乘性回退吸收基站排队抖动，无连接活跃时彻底挂起零耗电。</div>' +
    '<button class="btn pri press" data-act="ar-save"' + (htbOk() ? '' : ' disabled') + '>保存自适应带宽策略</button>';
  return sFold('autorate', ['blue', 'gauge'], '上游 5G 信号自适应总带宽', on ? stTxt + (num(ar.cur_down_mbps) ? ' · ↓' + num(ar.cur_down_mbps) + '/↑' + num(ar.cur_up_mbps) + 'M' : '') : '随 5G 基站信号波动动态伸缩热点总带宽上限',
    body, toggle(on, 'data-set="autorate" aria-label="5G 自适应总带宽"' + (htbOk() ? '' : ' disabled')));
}
function rmacPolicyHtml(c) {
  var rp = (c && c.rmac_policy) || {};
  var body = '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">高置信度老设备自动无感继承</div><div class="s">同一台手机换了随机 MAC 后，指纹匹配得分达标时自动迁移原有限速、配额与设备名；全新陌生设备正常放行，绝不默认限速或断网折腾</div></span>' +
      toggle(rp.auto_inherit !== false, 'id="rmac-auto" data-local="rmac-auto" aria-label="随机MAC自动无感继承"') + '</div>' +
    '<div class="grid2"><label class="field">无感继承置信阈值' + inp('rmac-score', num(rp.auto_inherit_score, 85), '分', 'type="number" min="65" max="100"') + '</label>' +
    '<label class="field">短命随机 MAC 离线回收' + inp('rmac-gc', num(rp.ephemeral_gc_minutes, 30), '分钟', 'type="number" min="5" max="1440"') + '</label></div>' +
    '<div class="note">离线超过回收时间且无手动规则的短命随机 MAC 会自动清理陈旧邻居表槽位，防止 <span class="mono">mark_id</span> 池耗尽。</div>' +
    '<button class="btn pri press" data-act="rmac-save">保存随机 MAC 策略</button>';
  var isoRow = sItem(['indigo', 'isolate'], '热点客户端互访隔离 (AP Isolation)', '在转发层阻断热点内客户端之间的互相扫描与私自投屏，不影响各自正常上网', toggle(rp.client_isolation === true || c.client_isolation_enabled === true, 'data-set="client-iso" aria-label="热点客户端互访隔离"'));
  return sFold('rmacpol', ['green', 'rmac'], '随机 MAC 无感继承与槽位回收', (rp.auto_inherit !== false ? '≥' + num(rp.auto_inherit_score, 85) + '分无感继承 · 新设备零阻断放行' : '手动合并 · 新设备零阻断放行'), body, val(rp.auto_inherit !== false ? '无感继承' : '手动', rp.auto_inherit !== false ? 'ok' : '')) + isoRow;
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
    sItem(['orange', 'rocket'], '硬件 offload', 'BPF tether 是否绕过 tc 限速', val(esc(OFFLOAD_T[S.offload.detail] || S.offload.detail || '—') + (S.offload.guard && S.offload.guard.fallback_active ? ' · 已兜底' : ''), S.offload.detail === 'ACTIVE' && !(S.offload.guard && S.offload.guard.fallback_active) ? 'warn' : 'ok')) +
    sItem(['red', 'shield'], '网站封锁 · DNS 层', '封锁网站时顺带拦掉该设备对这个域名的 DNS 查询，第一次连接就拦住', val({ available: '可用', unavailable: '内核不支持（只按 IP 拦）', unknown: '首次封锁时检测' }[c.conn_block_dns_layer] || '—', c.conn_block_dns_layer === 'unavailable' ? 'warn' : 'ok'))]);
  groups.push(['设备', rmacPolicyHtml(c) + mergeSettingsHtml()]);   // 随机 MAC 无感继承 + 防绕过护栏 + 合并建议
  // 告警总开关 + 新设备接入提醒(后端早就有, 旧新界面都没做设置)
  groups.push(['告警', sItem(['red', 'bolt'], '告警总开关', '关掉后所有提醒都不再产生（已有记录保留）', toggle(ac.enabled !== false, 'data-set="amaster" aria-label="告警总开关"')) +
    sFold('ud', ['blue', 'wifi'], '新设备接入提醒', '陌生设备连上热点时提醒；认识的设备可在告警里点「认识它」',
      '<div class="grid2"><label class="field">免打扰开始' + inp('ud-qs', ud.quiet_hour_start != null ? ud.quiet_hour_start : 23, '点', 'type="number" min="0" max="23"') + '</label><label class="field">免打扰结束' + inp('ud-qe', ud.quiet_hour_end != null ? ud.quiet_hour_end : 7, '点', 'type="number" min="0" max="23"') + '</label></div>' +
      '<label class="field">同一台设备最短提醒间隔' + inp('ud-iv', Math.round(num(ud.min_interval_sec, 1800) / 60), '分钟', 'type="number" min="1" max="1440"') + '</label>' +
      '<div class="note">免打扰时段内只记录、不弹通知；开始 = 结束 表示不设免打扰。</div><button class="btn pri press" data-act="ud-save">保存</button>',
      toggle(ud.enabled !== false, 'data-set="ud" aria-label="新设备接入提醒"')) +
    sFold('aq', ['orange', 'gauge'], '月度流量配额', '按计费日起算，与设备卡「本月」同一口径；单独设置了配额的设备按自己的配额提醒',
      '<div class="grid2"><label class="field">配额' + inp('aq-gb', mq.limit_bytes ? trim0((mq.limit_bytes / 1073741824).toFixed(1)) : 10, 'GB/台/月', 'type="number" min="0.1" step="0.1"') + '</label><label class="field">预警' + inp('aq-pct', Math.min(99, mq.warn_at_pct || 80), '%', 'type="number" min="1" max="99"') + '</label></div><button class="btn pri press" data-act="aq-save">保存</button>',
      toggle(mq.enabled, 'data-set="aq" aria-label="月度流量配额"')) +
    sFold('aa', ['red', 'heart'], '异常流量检测', '当前小时超过 7 日同时段均值 × 阈值时提醒',
      '<div class="grid2"><label class="field">倍数阈值' + inp('aa-ratio', an.ratio_threshold || 3, '倍', 'type="number" min="1.1" step="0.1"') + '</label><label class="field">最低量' + inp('aa-mb', an.min_bytes ? Math.round(an.min_bytes / 1048576) : 50, 'MB') + '</label></div><button class="btn pri press" data-act="aa-save">保存</button>',
      toggle(an.enabled, 'data-set="aa" aria-label="异常流量检测"'))]);
  groups.push(['全局带宽整形', autorateFoldHtml(c) + sFold('gs', ['purple', 'layers'], '固定总带宽整形（静态上限）', '适用于 Wi-Fi 中继或信号恒定场景；开启固定上限会自动停用 5G 自适应',
    '<div class="grid2"><label class="field">下行上限' + inp('gs-down', rateToMbps(c.global_shaper_down), 'Mbps', 'type="number" min="0" step="0.1"') + '</label><label class="field">上行上限' + inp('gs-up', rateToMbps(c.global_shaper_up), 'Mbps', 'type="number" min="0" step="0.1"') + '</label></div>' +
    '<div class="note">填宽带/流量套餐实测速度的 85~90%。当前队列：' + sqmLabel() + (htbOk() ? '' : ' · <b>内核不支持 HTB，无法启用</b>') + '</div><button class="btn pri press" data-act="gs-apply">应用</button>',
    toggle(gsOn && !(c.autorate && c.autorate.enabled), 'data-set="gs" aria-label="全局带宽整形"' + (htbOk() ? '' : ' disabled'))) + aqmRowHtml(c)]);
  var fx = c.flywheel_exclude_user || [];
  groups.push(['飞轮排除名单', sFold('fw', ['cyan', 'shield'], '不参与规则学习的应用', 'VPN / 代理会代理别的应用流量，排除后不污染规则 · ' + fx.length + ' 个',
    '<div class="chips">' + (fx.length ? fx.map(function (p) { return '<span class="chip">' + esc(p) + '<button class="linkish danger" data-fw-del="' + esc(p) + '" aria-label="移除">×</button></span>'; }).join('') : '<span class="note">还没有手动排除的应用（内置名单已包含常见 VPN / 代理）</span>') + '</div>' +
    '<div style="display:flex;gap:8px">' + inp('fw-pkg', '', '', 'data-fw-inp="1" maxlength="128" placeholder="包名，如 com.github.metacubex.clash.meta" style="font-family:var(--mono)"') + '<button class="btn pri press" data-act="fw-add">添加</button></div><div class="note">约 5 分钟内生效；也可以在应用页的应用详情里一键排除。</div>')]);
  var m = S.metrics || {}, age = S.lastOk ? Math.round((Date.now() - S.lastOk) / 1000) : null;
  groups.push(['刷新与功耗', sFold('rmode', ['green', 'refresh'], '设备页刷新模式', '实时更跟手；省电会降低前台轮询频率', seg('rmode', [['realtime', '实时'], ['balanced', '均衡'], ['powersave', '省电']], S.refreshMode), val({ realtime: '实时', balanced: '均衡', powersave: '省电' }[S.refreshMode])) +
    sItem(['gray', 'info'], '数据新鲜度', '/api/live 最近一次成功返回', val(age == null ? '—' : age <= 2 ? '刚刚' : age + ' 秒前', age != null && age <= 8 ? 'ok' : 'warn'), ' id="fresh-row"') +
    sItem(['gray', 'cpu'], '控制面指标', m.instrumented === false ? '实时读取（未开启埋点）' : 'snapshot ' + (m.snapshot_age_ms != null ? m.snapshot_age_ms + 'ms' : '—') + ' · cache ' + num(m.json_cache_hits) + '/' + num(m.json_cache_misses) + ' · shell 兜底 ' + num(m.shell_fallback_count), val(S.metrics ? '正常' : '—', S.metrics ? 'ok' : '')) +
    powerFold() +
    sFold('caps', ['gray', 'flask'], '兼容性能力', 'tc / IFB / netem / 队列 / 启动器', '<dl class="kv">' + Object.keys(S.caps || {}).filter(function (k) { var v = S.caps[k]; return v !== null && typeof v !== 'object'; }).sort().map(function (k) { var v = S.caps[k]; return '<dt>' + esc(k) + '</dt><dd style="color:' + (v === true ? 'var(--badge-ok)' : v === false ? 'var(--badge-red)' : 'inherit') + '">' + esc(String(v)) + '</dd>'; }).join('') + '</dl>', val(capsSummary()))]);
  var rUrl = remoteUrl(), remOn = c.remote_enabled === true;
  groups.push(['远程访问', (KSU ? sItem(['blue', 'globe'], '启用远程访问服务', '开启后 :8443 监听，热点内其他设备可用浏览器访问（约 1 分钟生效）', toggle(remOn, 'data-set="remote" aria-label="远程访问服务"')) : sItem(['blue', 'globe'], '远程访问服务', '你正在通过远程访问使用 HNC；开关只能在本机 WebUI 里改', val('已开启', 'ok'))) +
    (remOn || !KSU ? '<div class="row">' + gi('gray', 'link') + '<span class="tx"><div class="t">访问地址</div><div class="s mono">' + esc(rUrl || '无法获取本机 IP · 请确认热点已开启') + '</div></span>' + (rUrl ? '<button class="linkish" data-act="url-copy">复制</button><button class="linkish" data-act="url-share">分享</button>' : '') + '</div>' : '') +
    (KSU ? sItem(['purple', 'lock'], '远程 PIN 配对鉴权', '安全基线常驻保护 · 局域网浏览器首次访问必须验证 6 位配对码', val('强制开启', 'ok')) : '') +
    (KSU ? sBtn(['orange', 'star'], '生成配对码', '远端新设备首次连接用 · 120 秒有效', 'pair-new', '生成') : '') +
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
    sItem(['blue', 'heart'], '看门狗 watchdog', '规则巡检 / 进程保活 / 定时开关热点' + (rs.watchdog_pid ? ' · pid ' + rs.watchdog_pid : '') + (num(rs.watchdog_hb_age) > 120 ? ' · 心跳 ' + num(rs.watchdog_hb_age) + ' 秒未更新' : ''),
      val(num(rs.watchdog) > 0 ? (num(rs.watchdog_hb_age) > 120 ? '可能卡住' : '正常') : '未运行', num(rs.watchdog) > 0 && !(num(rs.watchdog_hb_age) > 120) ? 'ok' : 'bad'))) + scStatusRows()]);
  var nz = function (v) { return v == null ? '未统计' : String(v); }, slaCls = function (v) { return v == null ? '' : num(v) ? 'warn' : 'ok'; };
  groups.push(['运行健康', statsHealthHtml() + (!S.sla ? sItem(['gray', 'heart'], '运行健康', '暂无数据', val('—')) :
    sItem(['gray', 'refresh'], 'dpid 重启 / 近期崩溃', '累计重启 · 近期崩溃循环', val(nz(sla.dpid_restart_count) + ' / ' + nz(sla.dpid_crash_recent), num(sla.dpid_crash_recent) ? 'warn' : '')) +
    sItem(['gray', 'layers'], 'watchdog 全量重建', 'tc 树被整体重建的次数', val(nz(sla.watchdog_full_restore_count), slaCls(sla.watchdog_full_restore_count))) +
    sItem(['gray', 'tool'], 'tc 修复失败 / 上行失败', '自修复熔断 · 上行 IFB/police 失败', val(nz(sla.tc_repair_fail_count) + ' / ' + nz(sla.uplink_fail_count), sla.tc_repair_fail_count == null && sla.uplink_fail_count == null ? '' : num(sla.tc_repair_fail_count) + num(sla.uplink_fail_count) ? 'warn' : 'ok')) +
    sItem(['gray', 'flask'], '能力降级标记', 'qos_fallback / uplink_unsupported', val([sla.qos_fallback_active ? 'QoS 兼容链路' : '', sla.uplink_unsupported ? '上行不支持' : ''].filter(Boolean).join(' · ') || '无', sla.qos_fallback_active || sla.uplink_unsupported ? 'warn' : 'ok')))]);
  groups.push(['维护', sBtn(['blue', 'refresh'], '重启 HNC 服务', '重跑 post-fs-data.sh + service.sh', 'svc-restart', '重启', 'danger') +
    sFold('ttl', ['orange', 'refresh'], '离线规则自动清理', num(c.stale_rule_ttl_days, 30) ? '设备离线超过 ' + num(c.stale_rule_ttl_days, 30) + ' 天后，自动删掉它的限速/延迟规则' : '已关闭 · 离线设备的规则永久保留',
      '<div style="display:flex;gap:8px"><span class="box" style="flex:1"><input id="ttl-days" type="number" min="0" max="3650" value="' + num(c.stale_rule_ttl_days, 30) + '"><span class="u">天</span></span><button class="btn pri press" data-act="ttl-save">保存</button></div><div class="note">填 0 = 永不自动清理。黑名单不受影响。</div>',
      val(num(c.stale_rule_ttl_days, 30) ? num(c.stale_rule_ttl_days, 30) + ' 天' : '关闭')) +
    sBtn(['orange', 'trash'], '清理缓存', 'hostname_cache · dev_class_cache', 'cache-clear', '清理', 'warn') +
    sBtn(['green', 'down'], '导出规则', '复制 rules.json（限速/延迟/黑名单/模板）', 'rules-json', '导出') +
    sBtn(['cyan', 'doc'], 'JSON 健康面板', 'rules / devices / tokens 的完整性与备份', 'json-health', '打开') +
    sBtn(['purple', 'down'], '导出诊断包', '快照、配置、日志尾部和 tc/iptables/ip 状态', 'debug-bundle', '导出')]);
  // 应用识别 —— 强制 QUIC 回落 TCP
  groups.push(['应用识别', sItem(['purple', 'flask'], '强制 QUIC 回落 TCP', '拦下 UDP 443（HTTP/3），App 会改走 TCP；默认无需开启（v5.38 已支持 QUIC Initial 解密 + 几何特征 + 120ms 因果传播）', toggle(c.quic_block === true, 'data-set="quic" aria-label="强制 QUIC 回落 TCP"')) +
    sItem(['blue', 'shield'], '自动获取服务器证书', '「应用规则中心」对陌生域名探读一次公开 TLS 证书组织名辅助聚类', toggle(c.discover_cert_probe !== false, 'data-set="certprobe" aria-label="自动获取服务器证书"')) +
    (S.appLimitSharedKnown ? sItem(['orange', 'warn'], '按应用限速包含共享 IP', '默认跳过多应用共用 CDN IP 防误伤；打开后一并限速', toggle(S.appLimitShared, 'data-set="appshared" aria-label="按应用限速包含共享 IP"')) : '') +
    encdnsSettingsHtml() + dnsTakeoverFold() + fgEngineFold() +
    sBtn(['purple', 'rule_hub'], '应用规则中心', '新发现应用、候选晋级、识别纠正与规则包已统一整合至此', 'go-rules-hub', '前往') +
    sBtn(['cyan', 'flask'], 'DPI 与自训工作台', '亮屏常驻自训、少样本原型蒸馏与准确率自评已整合至分析页', 'go-dpi-studio', '前往')]);
  var cs = S.clsact;
  var gm = c.clsact_bpf_mode || 'auto', og = c.offload_guard || S.offload.guard || null;
  var ogS = gm === 'off' ? '已关闭：不做任何处理' : !og ? '等待第一次检测（约 1 分钟）' : og.fallback_active ? '兜底生效中：已让系统加速退回常规转发' + (og.since ? '（' + ago(og.since) + '起）' : '') : (OG_T[og.offload_state] || og.offload_state || '—');
  groups.push(['硬件加速兜底', sItem(['orange', 'rocket'], '防止系统热点加速绕过限速', '自动：检测到加速正在转发流量时，才让它退回常规路径，保证限速 / 封锁 / 统计都生效', '') +
    '<div class="row" style="padding-top:0">' + seg('guard-mode', [['auto', '自动'], ['on', '始终'], ['off', '关闭']], gm, 'small') + '</div>' +
    '<div class="row">' + gi(og && og.fallback_active ? 'green' : 'gray', 'layers') + '<span class="tx"><div class="t">当前状态</div><div class="s" id="guard-s">' + esc(ogS) + (og && og.detail && gm !== 'off' ? '<br>' + esc(og.detail) : '') + (og && og.last_check ? ' · ' + ago(og.last_check) + '检测' : '') + '</div></span></div>' +
    (gm === 'on' ? '<div class="row">' + gi('gray', 'flask') + '<span class="tx"><div class="t">clsact 打标（附带）</div><div class="s" id="clsact-s">' + (cs ? [['clsact', '队列挂点'], ['bpf_filter', '分流程序'], ['map', '状态表'], ['watchdog', '守护巡检']].map(function (it) { return it[1] + (cs[it[0]] ? ':正常' : ':异常'); }).join(' · ') : '点「检查」查看') + '</div></span><button class="linkish" data-act="clsact-check">检查</button>' + (cs && !(cs.clsact && cs.bpf_filter && cs.map && cs.watchdog) ? '<button class="linkish danger" data-act="clsact-repair">修复</button>' : '') + '</div>' : '')]);
  if (S.open.look === undefined) S.open.look = true;
  var curStyleKey = S.style === 'liquid' ? (S.glassMode === 'frosted' ? 'frosted' : 'liquid') : (S.style === 'cyber' ? 'cyber' : 'default');
  var curStyleName = { liquid: '液态玻璃 · 光学折射', frosted: '经典毛玻璃', cyber: '赛博机甲', default: '极简精密' }[curStyleKey] || '液态玻璃';
  var gxLbl = glassTintLabel(S.glassTint);
  groups.push(['外观', sFold('look', ['purple', 'palette'], '主题与动画', curStyleName + ' · 浅色 / 深色 / 跟随系统 · 120fps 动态引擎',
    '<div class="note" style="margin-bottom:2px">四大独立视觉架构（点按即时切换，均支持浅色 / 纯正 OLED 暗夜双态）</div>' +
    '<div class="style-pick style-pick-4">' + [
      ['liquid', '液态折射', '光学棱镜边缘 · 水滴透镜', 'pv-liquid'],
      ['frosted', '经典毛玻璃', '均匀柔雾缎面 · 零色散', 'pv-frosted'],
      ['default', '极简精密', '微米级实心边框 · 零模糊', 'pv-default'],
      ['cyber', '赛博机甲', '切角装甲遥测 · 等宽数显', 'pv-cyber']
    ].map(function (t) {
      return '<button type="button" class="style-card press' + (curStyleKey === t[0] ? ' on' : '') + '" data-style-pick="' + t[0] + '">' +
        '<span class="pv ' + t[3] + '"><span class="pv-top"><i class="pv-pill"></i><i class="pv-dot"></i></span><span class="pv-body"><i class="pv-bar"></i><i class="pv-sub"></i></span></span>' +
        '<span class="style-meta"><b>' + t[1] + '</b><small>' + t[2] + '</small></span>' +
      '</button>';
    }).join('') + '</div>' +
    // v6.1.0-rc.1 玻璃透光度五档离散胶囊(只在液态玻璃风格下显示, liquid.css .lg-only): 点按即切换并保存, 零滑条防展开手势误触
    '<div class="lg-only">' +
    '<div class="note" style="margin:2px 0 -2px">玻璃透光度微调 · <span id="glass-tint-v">' + gxLbl + '</span>' + (typeof PERF !== 'undefined' && PERF.low ? '（已手动简化特效）' : '') + '</div>' +
    '<div class="gx-pills-5" id="glass-tint" role="group" aria-label="玻璃浓度">' +
      [[0, '清透'], [25, '偏清透'], [50, '标准'], [75, '偏着色'], [100, '着色']].map(function (g) {
        var isOn = gxLbl === g[1];
        return '<button type="button" class="gx-btn press' + (isOn ? ' on' : '') + '" data-gx-tint="' + g[0] + '" aria-pressed="' + isOn + '">' + g[1] + '</button>';
      }).join('') +
    '</div></div>' +
    '<div class="note" style="margin-bottom:-2px">颜色</div><div class="theme-pick">' + [['auto', '跟随系统', 'linear-gradient(135deg,#F5F5F7 50%,#1c1c1e 50%)'], ['light', '浅色', '#F5F5F7'], ['dark', '深色', '#1c1c1e']].map(function (t) {
      return '<button class="press' + (S.theme === t[0] ? ' on' : '') + '" data-theme-pick="' + t[0] + '"><span class="sw" style="background:' + t[2] + '"></span>' + t[1] + '</button>'; }).join('') + '</div>' +
    (typeof wpSettingsHtml === 'function' ? wpSettingsHtml() : '') + '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">界面动画</div><div class="s">弹簧切页、列表浮现、按压回弹</div></span>' + toggle(S.motion, 'data-set="motion" aria-label="界面动画"') + '</div>' + fxSettingsHtml())]);
  groups.push(['模拟环境（调试）', simGroupHtml()]);
  var l = S.live || {};
  var wLabel = S.whoami && (S.whoami.session_label || S.whoami.label);
  var HNC_UI_VER = 'v6.1.0-rc.1', HNC_UI_VC = '6009301', HNC_UI_DATE = '2026-11-22';
  var bVer = cleanVer(l.backend_version, HNC_UI_VER);
  var bVc = cleanVer(l.backend_version_code, HNC_UI_VC);
  var bChan = /-alpha/i.test(bVer) ? 'ALPHA 内测通道' : /-beta/i.test(bVer) ? 'BETA 公测通道' : /-rc/i.test(bVer) ? 'RC 准正式通道' : 'STABLE 稳定通道';
  groups.push(['关于', sItem(['blue', 'info'], '版本', 'HNC 后端 · ' + bChan + ' · versionCode ' + esc(bVc), val(esc(bVer))) +
    sBtn(['green', 'doc'], '更新日志', '查看完整变更记录', 'changelog', '查看') +
    (KSU || (S.whoami && S.whoami.authenticated === false) ? '' : '<button class="row" data-act="logout">' + gi('red', 'lock') + '<span class="tx"><div class="t">退出登录' + (wLabel ? '（' + esc(wLabel) + '）' : '') + '</div><div class="s">清除这台设备的远程访问凭据</div></span><span class="hint-a danger">退出</span></button>')]);
  // 按级别分类 + 全部收拢为可折叠卡片(默认仅展开「热点」或全折叠，一屏清爽浏览)
  S.setLv = S.setLv || LS.get('hnc6.set_lv', 'all');
  var gMap = {}; groups.forEach(function (g) { gMap[g[0]] = g[1]; });
  var mmCnt = S.mm && Array.isArray(S.mm.suggestions) ? S.mm.suggestions.length : 0;
  var scard = function (key, ic, title, sub, badgeHtml, rowsHtml) {
    var isOpen = !!S.open[key];
    return '<div class="sgrp scard glass' + (isOpen ? ' open' : '') + '" data-foldkey="' + key + '" data-ic-color="' + ic[0] + '">' +
      '<button class="sgrp-h scard-h press" data-act="fold" data-key="' + key + '">' +
      gi(ic[0], ic[1]) +
      '<span class="tx"><b>' + title + '</b><small>' + sub + '</small></span>' +
      (badgeHtml || '') + ico('chev', 'chev') + '</button>' +
      '<div class="fold"><div><div class="fold-in"><div class="rows scard-rows">' + rowsHtml + '</div></div></div></div></div>';
  };
  var basicCards = [
    scard('scard-hs', ['blue', 'wifi'], '热点与接口设置',
      '接口 ' + esc(S.hotspot.iface || 'wlan2') + ' · ' + (hsAuto ? '开机自启已开' : '手动开启') + ' · 定时与接口偏好',
      '<span class="badge ' + (S.hotspot.active === false ? 'b-gray' : 'b-ok') + '">' + (S.hotspot.active === false ? '未开启' : '运行中') + '</span>',
      gMap['热点'] || ''),
    scard('scard-rem', ['indigo', 'globe'], '远程访问与设备授权',
      (remOn ? esc(rUrl || ':8443 监听中') : '远程管理已关闭') + ' · 配对码 · 访问白名单',
      '<span class="badge ' + (remOn ? 'b-ok' : 'b-gray') + '">' + (remOn ? '已开启' : '已关闭') + '</span>',
      gMap['远程访问'] || ''),
    scard('scard-look', ['purple', 'palette'], '外观、主题与动效',
      curStyleName + ' · ' + ({ auto: '跟随系统', light: '浅色', dark: '深色' }[S.theme] || '浅色') + ' · 自定义壁纸与视觉引擎',
      '<span class="badge b-acc">' + curStyleName.split(' · ')[0] + '</span>',
      gMap['外观'] || ''),
    scard('scard-alert', ['orange', 'bolt'], '告警与配额提醒',
      '新设备接入提醒 · 月度流量配额 · 异常流量检测',
      '<span class="badge ' + (ac.enabled !== false ? 'b-ok' : 'b-gray') + '">' + (ac.enabled !== false ? '已开启' : '已关闭') + '</span>',
      gMap['告警'] || '')
  ];
  var v6LgHits = num(window.V6 && V6.lg && V6.lg.total_hits);
  var v6TempS = (window.V6 && V6.thermo && V6.thermo.temp_c > 0) ? (V6.thermo.temp_c.toFixed(1) + '°C') : '正常';
  var advCards = [
    scard('scard-v6', ['blue', 'vector'], '智能护航与配置备份',
      '游戏通话优先 · 后台更新限速 · 温控保护（' + esc(v6TempS) + '）· 隐私安检（' + v6LgHits + ' 条）',
      (function(){ var _rv = cleanVer(l.backend_version, HNC_UI_VER); var _short = _rv.replace(/^(v\d+\.\d+)\.\d+-(alpha|beta|rc)\.?(\d+).*$/i, function(_, m, c, n){ return m + ' ' + (c.toLowerCase() === 'rc' ? 'RC' + n : c.charAt(0).toUpperCase() + n); }); return '<span class="badge b-acc" title="' + esc(_rv) + '">' + esc(_short) + '</span>'; })(),
      typeof v6SettingsBodyHtml === 'function' ? v6SettingsBodyHtml() : ''),
    scard('scard-dpi', ['purple', 'search'], '应用识别与 DNS 策略',
      'QUIC 回落 · 加密 DNS（' + (ENC_T[(S.encdns && S.encdns.policy) || 'off'] || '关闭') + '）· 指纹学习与规则包',
      '<span class="badge b-pur">DPI 识别</span>',
      gMap['应用识别'] || ''),
    scard('scard-qos', ['cyan', 'layers'], '5G 自适应整形与全局队列',
      ((c.autorate && c.autorate.enabled) ? '5G Autorate 动态巡航中' : gsOn ? '静态下行 ' + (rateToMbps(c.global_shaper_down) || '∞') + ' Mbps' : '未启用全局限速') + ' · 默认队列 AQM（' + sqmLabel() + '）',
      '<span class="badge ' + ((gsOn || (c.autorate && c.autorate.enabled)) ? 'b-ok' : 'b-gray') + '">' + ((c.autorate && c.autorate.enabled) ? '5G 自适应' : gsOn ? '静态整形' : '按设备') + '</span>',
      gMap['全局带宽整形'] || ''),
    scard('scard-guard', ['orange', 'rocket'], '硬件加速兜底',
      esc(ogS),
      '<span class="badge ' + (gm === 'off' ? 'b-gray' : 'b-ok') + '">' + ({ auto: '自动兜底', on: '始终开启', off: '已关闭' }[gm] || '自动') + '</span>',
      gMap['硬件加速兜底'] || ''),
    scard('scard-devm', ['green', 'merge'], '随机 MAC 继承、隔离与合并',
      '高置信无感继承（新设备不默认限速）· 客户端隔离 · VPN 排除（' + fx.length + ' 个）',
      mmCnt ? '<span class="badge b-warn">' + mmCnt + ' 条建议</span>' : '<span class="badge b-gray">正常</span>',
      (gMap['设备'] || '') + (gMap['飞轮排除名单'] || ''))
  ];
  var dpvNorm = typeof dpvNormalize === 'function' ? dpvNormalize(DPV_STATE.lastData, DPV_STATE.leakEnabled) : null;
  var dpvHasErr = !!(dpvNorm && dpvNorm.sampled_ok && dpvNorm.summary && dpvNorm.summary.bypass_or_missing_count > 0);
  if (dpvHasErr && S.open['scard-dpv'] === undefined) S.open['scard-dpv'] = true;
  var dpvSubTxt = !dpvNorm || !dpvNorm.sampled_ok
    ? '检验给设备设的限速是否真正管用，有无被手机系统加速绕过'
    : dpvHasErr
      ? ('发现 ' + dpvInt(dpvNorm.summary.bypass_or_missing_count) + ' 台设备限速可能被绕过 · 点开一键修复')
      : ('已设限速 ' + dpvInt(dpvNorm.summary.controlled_devices) + ' 台 · 正在生效 ' + dpvInt(dpvNorm.summary.hitting_count) + ' 台 · 未被硬件加速绕过');
  var dpvBadgeHtml = !dpvNorm || !dpvNorm.sampled_ok
    ? '<span class="badge b-gray" id="dpv-scard-badge">点开检验</span>'
    : dpvHasErr
      ? '<span class="badge b-warn" id="dpv-scard-badge">待修复</span>'
      : (dpvNorm.summary.hitting_count > 0
          ? '<span class="badge b-ok" id="dpv-scard-badge">真实生效</span>'
          : '<span class="badge b-acc" id="dpv-scard-badge">待命就绪</span>');
  var diagCards = [
    (function () {
      var qh = S.quickHealth && !S.quickHealth._err ? S.quickHealth : null;
      var qhSt = qh && typeof qhNormStatus === 'function' ? qhNormStatus(qh.overall || qh.status || qh.overall_status || qh.level) : '';
      var qhSub = qh && (qh.headline || qh.one_liner || qh.summary_text) ? String(qh.headline || qh.one_liner || qh.summary_text) : '热点转发 · 零唤醒省电 · 限速防绕过 · 内存空间四维秒检';
      var qhBdg = qhSt === 'fail' ? '<span class="badge b-red">需修复</span>' : qhSt === 'warn' ? '<span class="badge b-warn">可优化</span>' : qh ? '<span class="badge b-ok">健康</span>' : '<span class="badge b-ok">秒检</span>';
      return '<div class="sgrp scard glass" data-ic-color="green"><button type="button" class="sgrp-h scard-h press" data-act="quick-health">' +
        gi('green', 'shield') + '<span class="tx"><b>一句话省电与健康体检</b><small>' + esc(qhSub) + '</small></span>' +
        qhBdg + ico('right', 'chev') + '</button></div>';
    })(),
    scard('scard-dpv', [dpvHasErr ? 'orange' : 'green', 'shield'], '限速真实生效检验',
      esc(dpvSubTxt),
      dpvBadgeHtml,
      dpvRenderSettingsSlotHtml()),
    scard('scard-diag', [scW === 'fail' ? 'red' : scW === 'warn' ? 'orange' : 'green', 'check'], '自检报告与运行日志',
      (scR ? '自检 ' + scSumTxt(scR.summary) : '一键兼容性自检') + ' · 14 类系统与守护日志',
      scR ? '<span class="badge ' + (scW === 'fail' ? 'b-red' : scW === 'warn' ? 'b-warn' : 'b-ok') + '">' + esc(scSumTxt(scR.summary)) + '</span>' : '<span class="badge b-gray">可自检</span>',
      gMap['诊断'] || ''),
    scard('scard-stat', ['blue', 'heart'], '运行状态与统计健康',
      '守护进程 · tc ' + num(rs.tc_rules) + ' 条 / iptables ' + num(rs.ipt_rules) + ' 条 · 流量对账与 SLA',
      '<span class="badge ' + (rs.hotspotd === 'up' ? 'b-ok' : 'b-gray') + '">' + (rs.hotspotd === 'up' ? '运行正常' : '状态') + '</span>',
      (gMap['运行状态'] || '') + (gMap['运行健康'] || '')),
    scard('scard-maint', ['orange', 'tool'], '维护、备份与轮询功耗',
      '刷新模式（' + ({ realtime: '实时', balanced: '均衡', powersave: '省电' }[S.refreshMode]) + '）· 服务重启 · 导出规则与诊断包',
      '<span class="badge b-acc">' + ({ realtime: '实时', balanced: '均衡', powersave: '省电' }[S.refreshMode]) + '</span>',
      (gMap['刷新与功耗'] || '') + (gMap['维护'] || '')),
    scard('scard-about', ['gray', 'info'], '模拟环境与关于本模块',
      '调试模拟设备 · 后端版本 ' + esc(bVer) + ' · 完整更新日志',
      '<span class="badge b-gray">' + esc(bVer) + '</span>',
      (gMap['模拟环境（调试）'] || '') + (gMap['关于'] || ''))
  ];
  var cols = function (list) { if (!wide()) return '<div class="scard-stack">' + list.join('') + '</div>'; var hf = Math.ceil(list.length / 2); return '<div class="cols"><div>' + list.slice(0, hf).join('') + '</div><div>' + list.slice(hf).join('') + '</div></div>'; };
  var lvSec = function (id, title, sub, cards) {
    var hide = S.setLv !== 'all' && S.setLv !== id ? ' hidden' : '';
    return '<div class="set-lv-sec" data-lv-sec="' + id + '"' + hide + '>' +
      '<div class="sec set-lv-hd"><span>' + title + ' <small>' + sub + '</small></span><span class="r">' + cards.length + ' 项</span></div>' +
      cols(cards) + '</div>';
  };
  var anyOpen = ['scard-hs','scard-rem','scard-look','scard-alert','scard-v6','scard-dpi','scard-qos','scard-guard','scard-devm','scard-dpv','scard-diag','scard-stat','scard-maint','scard-about'].some(function (k) { return S.open[k]; });
  var h = '<div class="wrap">' +
    '<div class="set-top-bar">' + seg('set-lv', [['all', '全部 (' + (basicCards.length + advCards.length + diagCards.length) + ')'], ['basic', '常用 (' + basicCards.length + ')'], ['adv', '进阶 (' + advCards.length + ')'], ['diag', '诊断 (' + diagCards.length + ')']], S.setLv) +
    '<div class="set-top-meta"><span class="note">按级别分类折叠 · 点卡片展开对应设置</span><button class="linkish" data-act="set-fold-toggle">' + (anyOpen ? '全部收起' : '展开常用') + '</button></div></div>' +
    lvSec('basic', '一、基础常用', '热点 · 远程 · 外观 · 告警', basicCards) +
    lvSec('adv', '二、进阶与识别', 'DPI 识别 · 带宽队列 · 加速兜底 · 设备合并', advCards) +
    lvSec('diag', '三、诊断与系统', '自检日志 · 运行健康 · 维护备份 · 模拟与关于', diagCards) +
    '<div class="foot hnc-build-wm" id="hnc-build-wm">' + (/-alpha/i.test(bVer) ? '<span class="wm-chan">[ALPHA]</span>' : /-beta/i.test(bVer) ? '<span class="wm-chan">[BETA]</span>' : /-rc/i.test(bVer) ? '<span class="wm-chan">[RC]</span>' : '') + '<span>HNC · ' + esc(bVer) + ' · VC ' + esc(bVc) + ' · Build ' + HNC_UI_DATE + '</span></div></div>';
  var p = $('#p-settings');
  if (!anim1 && p.firstElementChild) morph(p, h); else p.innerHTML = h;
  placeSegs(p);
  if (S.open.logs) loadLog();
  if (S.open.tokens) loadTokens();
  if (S.open.dnst) { if (S.dns) paintDNS(); else loadDNS(); }
  if (S.open.fpl) { if (S.fpl) paintFP(); else loadFP(); }
  if (S.open.deval) { if (S.eval) paintEval(); else loadEval(); }
  if (S.open.fgeng) { if (S.fgcmp) paintFgEngine(); else loadFgEngine(); }
  if (S.open.rpack) { if (S.rpack) paintRulepack(); else loadRulepack(); }
}
/* ── DPI v2: DNS 接管(可选, 默认关) ── */
S.dns = null; S.fpl = null; S.power = null; S.whoami = null;
function loadWhoami() { return KSU ? Promise.resolve() : api.getSafe('/api/whoami', null, null).then(function (r) { S.whoami = r; }); }
function loadPower(ref) { return api.getSafe('/api/power', ref ? { refresh: '1' } : null, null).then(function (r) { S.power = r; paintPower(); }); }
function powerFold() {
  var p = S.power, tot = p && p.total ? p.total : null;
  var sub = tot ? ('合计 CPU ' + num(tot.cpu_pct_5m).toFixed(2) + '% · 唤醒 ' + Math.round(num(tot.wakeups_per_min)) + ' 次/分') : '5 大守护进程 CPU% / 唤醒频率 / 内存自测';
  return sFold('pwr', ['orange', 'cpu'], '守护进程功耗自测', '<span id="pwr-sum">' + esc(sub) + '</span>', '<div id="pwr-body"><div class="note">展开后加载 /api/power 实时采样</div></div>');
}
function paintPower() {
  var el = $('#pwr-body'), p = S.power; if (!el || !p) return;
  var sm = $('#pwr-sum'); if (sm && p.total) sm.textContent = '合计 CPU ' + num(p.total.cpu_pct_5m).toFixed(2) + '% · 唤醒 ' + Math.round(num(p.total.wakeups_per_min)) + ' 次/分';
  var ps = Array.isArray(p.processes) ? p.processes : [];
  var rows = ps.map(function (x) {
    return '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">' + esc(x.label || x.name) + '</div><div class="s mono">pid ' + (x.pid || '—') + ' · RSS ' + Math.round(num(x.rss_kb) / 1024) + ' MB · 唤醒 ' + Math.round(num(x.wakeups_per_min)) + '/min</div></span>' + val(num(x.cpu_pct_5m).toFixed(2) + '%', num(x.cpu_pct_5m) > 3 ? 'warn' : 'ok') + '</div>';
  }).join('');
  var tips = Array.isArray(p.tips) && p.tips.length ? '<div class="note">' + p.tips.map(esc).join('<br>') + '</div>' : '';
  el.innerHTML = (rows || '<div class="note">暂无采样样本（每 5 分钟自动采样一次）</div>') + tips + '<button class="btn sec wide press" style="margin-top:8px" data-act="pwr-refresh">立即刷新采样</button>';
}
function dnsSumTxt() {
  var r = S.dns; if (!r) return '默认关闭 · 让 HNC 代答热点设备的 DNS，识别更早、封锁更彻底';
  if (!r.enabled) return '未开启 · 让 HNC 代答热点设备的 DNS，识别更早、封锁更彻底';
  return r.active && r.healthy ? '运行中 · 今天 ' + num((r.stats || {}).queries) + ' 次查询' : '已开启 · 暂未生效（已自动放行直连）';
}
function dnsTakeoverFold() {
  return sFold('dnst', ['blue', 'shield'], 'DNS 接管（实验）', '<span id="dns-sum">' + esc(dnsSumTxt()) + '</span>', '<div id="dns-body"><div class="note">展开后加载</div></div>',
    toggle(!!(S.dns && S.dns.enabled), 'data-set="dnst" aria-label="DNS 接管"' + (S.dns ? '' : ' disabled')));
}
function loadDNS() {
  return api.get('/api/dns', null, { timeout: 8000 }).then(function (r) { S.dns = r; }).catch(function (e) { S.dns = { ok: false, err: errText(e) }; }).then(paintDNS);
}
var DNS_ST = { selftest: '自检没通过', upstream_errors: '上游 DNS 连续出错', dnat_path: '转发规则没生效', no_upstream: '找不到可用的上游 DNS' };
function paintDNS() {
  var el = $('#dns-body'), r = S.dns; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  var sm = $('#dns-sum'); if (sm) sm.textContent = dnsSumTxt();
  var tg = $('[data-set="dnst"]'); if (tg) { tg.removeAttribute('disabled'); if (!tg.closest('.pending')) tg.setAttribute('aria-checked', String(!!r.enabled)); }
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持 DNS 接管）</div>'; return; }
  var st = r.stats || {}, fo = r.failopen || {}, h = '';
  if (r.enabled) {
    h += '<dl class="kv"><dt>状态</dt><dd style="color:' + (r.active && r.healthy ? 'var(--badge-ok)' : 'var(--orange)') + '">' + (r.active && r.healthy ? '运行中' : '未生效 · ' + esc(DNS_ST[fo.reason] || fo.reason || r.last_error || r.state || '检测中')) + '</dd>' +
      '<dt>上游</dt><dd class="mono">' + esc(r.upstream || '自动') + (r.upstream_kind ? ' · ' + esc(r.upstream_kind) : '') + '</dd>' +
      '<dt>今天</dt><dd>' + num(st.queries) + ' 次 · 缓存 ' + num(st.cached) + ' · 拦截 ' + num(st.blocked) + '</dd>' +
      '<dt>耗时</dt><dd class="num">p50 ' + num(st.p50_ms) + 'ms · p95 ' + num(st.p95_ms) + 'ms</dd>' +
      (num(fo.count) ? '<dt>自动放行</dt><dd>' + num(fo.count) + ' 次' + (fo.last_ts ? ' · 最近 ' + ago(fo.last_ts) : '') + '</dd>' : '') + '</dl>';
    var td = Array.isArray(r.top_domains_today) ? r.top_domains_today.slice(0, 5) : [];
    if (td.length) h += '<div class="note">今天查询最多：' + td.map(function (x) { return esc(x.name) + ' ×' + num(x.count); }).join('、') + '</div>';
  }
  h += '<div class="note" style="margin:8px 0 -2px">被封锁的域名怎么回</div>' + seg('dns-bm', [['nxdomain', '域名不存在'], ['zero', '返回 0.0.0.0']], r.block_mode || 'nxdomain', 'small') +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">记录查询日志</div><div class="s">记下每台设备查了哪些域名（只存本机，约 2000 条滚动）</div></span>' + toggle(!!r.log_queries, 'data-set="dnslog" aria-label="记录查询日志"') + '</div>' +
    (r.log_queries ? '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">日志隐私脱敏</div><div class="s">开启后只记主域名、不记录完整子域与解析应答 IP</div></span>' + toggle(!!r.log_redact, 'data-set="dnsredact" aria-label="日志隐私脱敏"') + '</div><button class="btn sec wide press" style="margin:6px 0" data-act="dns-log-open">查看最近 DNS 查询明细</button>' : '') +
    '<div class="note">好处：设备一查域名 HNC 就知道它要用哪个应用，比等到 TLS 握手更早；按域名封锁在解析这一步就拦住。<br>风险：HNC 自己的 DNS 出问题时会在约 10 秒内自动放行直连（不会断网，但这段时间解析可能变慢）；设备自己开了加密 DNS（DoH / DoT / 私人 DNS）时接管不到；开启查询日志会留下访问记录。只对热点设备生效，不影响本机。</div>';
  el.innerHTML = h; placeSegs(el);
}
/* ── DPI v2: 识别纠正记录 + 指纹学习 ── */
function fpFold() {
  var n = S.fpl && Array.isArray(S.fpl.user_rules) ? S.fpl.user_rules.length : null;
  return sFold('fpl', ['green', 'flask'], '识别纠正与指纹学习', n == null ? '你纠正过的识别 · HNC 自动学会的 TLS 指纹' : n + ' 条纠正 · ' + num((S.fpl.stats || {}).usable) + ' 个可用指纹', '<div id="fp-body"><div class="note">展开后加载</div></div>');
}
function loadFP() {
  return api.get('/api/dpi_fp', null, { timeout: 8000 }).then(function (r) { S.fpl = r; }).catch(function (e) { S.fpl = { err: errText(e) }; }).then(paintFP);
}
var FPK_T = { domain: '域名', ip: 'IP', ja4: '指纹' };
function paintFP() {
  var el = $('#fp-body'), r = S.fpl; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '</div>'; return; }
  var ur = Array.isArray(r.user_rules) ? r.user_rules : [], ln = Array.isArray(r.learned) ? r.learned : [], st = r.stats || {};
  var h = '<div class="note" style="margin-bottom:-2px">你纠正过的（' + ur.length + '）</div>' + (ur.length ? '<div class="dbox">' + ur.map(function (x) {
    return '<div class="row2"><span class="k" style="color:var(--text-1);min-width:0;overflow-wrap:anywhere"><span class="badge b-acc">' + (FPK_T[x.kind] || esc(x.kind)) + '</span> <span class="mono">' + esc(x.kind === 'ja4' ? String(x.value).slice(0, 18) + '…' : x.value) + '</span> → ' + esc(x.app_name || x.app_id) + (x.expires ? ' <span class="note">· ' + Math.max(0, Math.ceil((num(x.expires) - Date.now() / 1000) / 86400)) + ' 天后过期</span>' : '') + '</span><button class="linkish danger" data-fpdel="' + esc(x.id) + '">撤销</button></div>';
  }).join('') + '</div>' + (ur.length > 1 ? '<button class="linkish danger" data-fpdel="__all" style="justify-self:start">全部撤销</button>' : '') : '<div class="note">还没有。在设备卡「实时连接 → 点一条连接 → 纠正识别」里添加。</div>');
  var use = ln.filter(function (x) { return x.usable; });
  h += '<div class="note" style="margin-bottom:-2px">自动学会的指纹（' + use.length + ' 个可用 / 共 ' + ln.length + ' 个观察中）</div>' +
    (use.length ? '<div class="dbox">' + use.slice(0, 12).map(function (x) {
      return '<div class="row2"><span class="k" style="color:var(--text-1)">' + esc(x.name || x.app_id) + ' <span class="note mono">' + esc(String(x.ja4).slice(0, 10)) + ' · ' + esc(x.port_class || '') + (x.qtp ? ' · ' + esc(String(x.qtp).replace(/^qtp1_/, '').slice(0, 8)) : '') + '</span></span><span class="v">' + pct100(x.purity) + '% · ' + num(x.devices) + ' 台</span></div>';
    }).join('') + '</div>' : '<div class="note">还在学习：同一个指纹在 ≥2 台设备上见过 20 次以上、且 90% 都属于同一个应用后才会用来识别。</div>') +
    '<div class="note">累计观察 ' + num(st.flows_seen) + ' 条连接 · 靠指纹认出 ' + num(st.flows_attributed_by_fp) + ' 条。指纹只在域名看不到（ECH / 直连 IP）时兜底，不会覆盖规则库。</div>';
  el.innerHTML = h;
  var sw = $('[data-foldkey="fpl"] .s'); if (sw) sw.textContent = ur.length + ' 条纠正 · ' + use.length + ' 个可用指纹';
}
/* ── v5.24 T5: 识别自评(只用这台手机自己的流量当标准答案) ── */
S.eval = null; S.evalDays = 1;
function evalSumTxt() {
  var r = S.eval; if (!r) return '用这台手机自己的流量当标准答案，看 HNC 认得准不准';
  if (!r.enabled) return '未开启本机流量归因 · 开启后才会采集样本并自评';
  if (!num(r.samples)) return '已开启 · 还没有样本，正常用手机一会儿再看';
  var m = (r.methods || {}).combined || {};
  return num(r.samples) + ' 条样本 · 综合覆盖 ' + pct100(m.coverage) + '% · 准确 ' + evalAcc(m);
}
function evalFold() {
  return sFold('deval', ['blue', 'gauge'], '识别自评', '<span id="eval-sum">' + esc(evalSumTxt()) + '</span>',
    '<div id="eval-body"><div class="note">展开后加载</div></div>');
}
var evalReqSeq = 0;
function loadEval(days, refresh) {
  var seq = ++evalReqSeq, d = days || S.evalDays || 1, q = { days: d };
  if (refresh) q.refresh = 1;   // 展开 / 切换范围用 10 分钟缓存, 只有「刷新」按钮才强制重算
  return api.get('/api/dpi_eval', q, { timeout: 12000 }).then(function (r) { if (seq === evalReqSeq) S.eval = r; })
    .catch(function (e) { if (seq === evalReqSeq) S.eval = { ok: false, err: errText(e) }; }).then(function () { if (seq === evalReqSeq) paintEval(); });
}
/* 准确率: 没有可判对错的样本(全是系统应用等无标准答案的)时显示「—」而不是 0% */
function evalAcc(m) { return m && m.accuracy_na ? '—' : m && m.judged === 0 ? '—' : pct100(m && m.accuracy) + '%'; }
var EVAL_M = [['rule', '规则库'], ['fp', '指纹'], ['owner', 'IP 归属']];

function lanSelfConsistencyHtml(r) {
  var lc = r && r.lan_self_consistency;
  if (!lc) return '';
  var okParity = lc.he_v4v6_parity == null || lc.he_v4v6_parity >= 0.9;
  var escCnt = num(lc.active_escape_alerts);
  return '<div class="dbox" style="margin:8px 0"><div class="note" style="margin:0 0 6px;font-weight:600;color:var(--text-1)">热点外部客户端无真值双栈自检（无需开启本机抓包）</div>' +
    '<div class="row2"><span class="k">DNS ↔ 握手跨模态冲突率（已豁免 ECH）</span><span class="v num">' + (lc.cm_conflict_rate != null ? (lc.cm_conflict_rate * 100).toFixed(1) + '%' : '0.0%') + '</span></div>' +
    '<div class="row2"><span class="k">Happy Eyeballs IPv4/IPv6 同源一致率</span><span class="v num" style="color:' + (okParity ? 'var(--badge-ok)' : 'var(--badge-warn)') + '">' + (lc.he_v4v6_parity != null ? (lc.he_v4v6_parity * 100).toFixed(1) + '%' : '100%') + '</span></div>' +
    '<div class="row2"><span class="k">实时 IPv6 应用限速逃逸告警</span><span class="v num" style="color:' + (escCnt > 0 ? 'var(--badge-red)' : 'var(--badge-ok)') + '">' + (escCnt > 0 ? escCnt + ' 台异常' : '0 逃逸（双栈闭合）') + '</span></div></div>';
}
function paintEval() {
  var el = $('#eval-body'), r = S.eval; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  var sm = $('#eval-sum'); if (sm) sm.textContent = evalSumTxt();
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持识别自评）</div>'; return; }
  if (!r.enabled) {
    el.innerHTML = '<div class="note">「识别自评」要用这台手机自己的流量当标准答案：HNC 一边看它连了哪些网站，一边记下每个连接是哪个 App 发的（靠系统给的 UID → 包名），再回头对比 HNC 自己认得准不准。</div>' +
      '<div class="note warn">现在本机流量归因没开，所以没有样本。</div>' +
      '<div class="btns"><button class="btn pri press" data-act="eval-enable">去开启</button></div>' +
      '<div class="note">只用这台手机自己的流量，样本保存 7 天，不上传。</div>' + lanSelfConsistencyHtml(r);
    return;
  }
  var m = r.methods || {}, comb = m.combined || {};
  var h = lanSelfConsistencyHtml(r) + '<div class="note" style="margin-bottom:-2px">本机真值评估时间范围</div>' + seg('eval-days', [[1, '24 小时'], [7, '7 天']], r.days || S.evalDays, 'small');
  if (!num(r.samples)) {
    h += '<div class="note">还没有样本。正常用手机（刷视频、聊微信）十来分钟，回来点刷新就有了。</div>' + evalFootHtml();
    el.innerHTML = h; placeSegs(el); return;
  }
  // 顶部四个数字
  h += '<div class="eval-nums">' +
    '<div class="en"><b class="num">' + num(r.samples) + '</b><span>样本</span></div>' +
    '<div class="en"><b class="num">' + pct100(comb.coverage) + '<i>%</i></b><span>覆盖率</span></div>' +
    '<div class="en"><b class="num">' + (evalAcc(comb) === '—' ? '—' : pct100(comb.accuracy) + '<i>%</i>') + '</b><span>准确率</span></div>' +
    '<div class="en"><b class="num">' + num(r.apps) + '</b><span>涉及应用</span></div></div>' +
    '<div class="note">覆盖率＝这些连接里 HNC 认出了应用的比例；准确率＝认出来的里面认对的比例。（综合＝用户纠正 &gt; 规则库 &gt; 指纹）</div>';
  // 各方法一行
  h += '<dl class="kv">';
  EVAL_M.forEach(function (x) {
    var mm = m[x[0]] || {};
    h += '<dt>' + x[1] + '</dt><dd class="num">覆盖 ' + pct100(mm.coverage) + '% · 准确 ' + evalAcc(mm) + ' <span class="note">(' + num(mm.predicted) + '/' + num(mm.samples) + (mm.judged != null && !mm.accuracy_na ? ' · 可判 ' + num(mm.judged) : '') + ')</span></dd>';
  });
  h += '</dl>';
  // v5.27 T2: QUIC 样本上「JA4 + 传输参数」与「仅 JA4」对比
  var qq = r.quic || {};
  if (num(qq.samples) > 0) {
    var qw = qq.fp_with_qtp || {}, qj = qq.fp_ja4_only || {};
    h += '<div class="note">QUIC 指纹（含传输参数）覆盖 ' + pct100(qw.coverage) + '% · 准确 ' + evalAcc(qw) + '（仅 JA4：覆盖 ' + pct100(qj.coverage) + '% · 准确 ' + evalAcc(qj) + '）· ' + num(qq.samples) + ' 条 QUIC 样本</div>';
  }
  // v5.27 T3: 启动指纹(影子运行: 只观察, 不改任何识别结果)
  var su = r.startup;
  if (su) {
    h += '<div class="note" style="margin-bottom:-2px">启动指纹（实验 · 只观察，不影响识别）</div><div class="note">学会 ' + num(su.apps_learned) + ' 个应用' +
      (num(su.days) >= 2 ? ' · 切换识别率 ' + pct100(su.switch_rate) + '% · 事件准确 ' + pct100(su.event_accuracy) + '%' + (num(su.switches) ? '（' + num(su.switch_hit) + '/' + num(su.switches) + ' 次切换）' : '') : ' · ' + esc(su.note || '')) +
      '</div><button class="linkish" data-act="startup-list" style="justify-self:start">' + (S.startupOpen ? '收起学会的应用' : '查看学会的应用') + '</button><div id="startup-list">' + (S.startupOpen ? startupListHtml() : '') + '</div>';
  }
  // v5.28 B1: 新应用发现(影子运行: 共现聚类准确率, 只统计不改动)
  var dv = r.discover;
  if (dv && num(dv.samples) > 0) {
    h += '<div class="note" style="margin-bottom:-2px">新应用发现（实验 · 只统计，不影响识别）</div><div class="note">纯度 ' + pct100(dv.purity) + '% · 完整度 ' + pct100(dv.completeness) + '%（共 ' + num(dv.groups) + ' 组' + (num(dv.hubs) ? ' · 枢纽域名 ' + num(dv.hubs) : '') + '）</div>';
    var dvs = Array.isArray(dv.variants) ? dv.variants : [];
    if (dvs.length > 1) {
      h += '<div class="note">参数对照：' + dvs.map(function (v) { return esc(v.label) + ' ' + pct100(v.purity) + '%/' + pct100(v.completeness) + '%（' + num(v.groups) + ' 组）'; }).join(' · ') + '</div>';
    }
  }
  // v5.28 B3: 流量形状猜类别(影子运行, 只标注不改变归属)
  var fc = r.flow_cls;
  if (fc && num(fc.samples) > 0) {
    h += '<div class="note">流量形状猜类别：模型 ' + pct100(fc.model_acc) + '% · 手工规则 ' + pct100(fc.manual_acc) + '%（' + num(fc.samples) + ' 条今日考题 · ' + num(fc.classes) + ' 类）</div>';
  }
  if (r.note) h += '<div class="note">' + esc(r.note) + '</div>';
  if (r.capped) h += '<div class="note warn">今天样本太多，超过单日上限后停止记录了（不影响已有统计）。</div>';
  // 最常认错 / 最常认不出
  var tw = Array.isArray(r.top_wrong) ? r.top_wrong.slice(0, 5) : [];
  if (tw.length) {
    h += '<div class="note" style="margin-bottom:-2px">最常认错</div><div class="dbox">' + tw.map(function (x) {
      return '<div class="row2"><span class="k" style="min-width:0;overflow-wrap:anywhere">' + esc(x.name || x.truth) + ' <span class="note">→ 认成 ' + esc(x.pred_name || x.pred) + '</span></span><span class="v num" style="white-space:nowrap">' + num(x.n) + ' 次</span></div>';
    }).join('') + '</div>';
  }
  var tu = Array.isArray(r.top_unknown) ? r.top_unknown.slice(0, 5) : [];
  if (tu.length) {
    h += '<div class="note" style="margin-bottom:-2px">最常认不出</div><div class="dbox">' + tu.map(function (x) {
      var snis = Array.isArray(x.snis) ? x.snis.slice(0, 3) : [];
      return '<div class="row2"><span class="k" style="min-width:0;overflow-wrap:anywhere">' + esc(x.name || x.truth) + (snis.length ? '<div class="note mono" style="white-space:normal;overflow-wrap:anywhere;font-size:11px">' + esc(snis.join(' · ')) + '</div>' : '') + '</span><span class="v num" style="white-space:nowrap">' + num(x.n) + ' 次</span></div>';
    }).join('') + '</div>';
  }
  // 前台记录
  var fg = r.fg_truth || {};
  var fgTxt = '24 小时切换 ' + num(fg.switches_24h) + ' 次' + (fg.last_pkg ? ' · 最近 ' + esc(fg.last_pkg) + (fg.last_ts ? '（' + ago(fg.last_ts) + '）' : '') : '');
  if (fg.source === 'none' || !num(fg.switches_24h)) {
    fgTxt = '还没有前台记录。亮屏用一会儿手机后会出现；如果一直没有，说明这台手机的系统取不到前台应用，v5.25 的前台评估可能不可用';
  } else {
    fgTxt += ' · 取数方式 ' + esc(fg.source);
  }
  h += '<div class="note" style="margin-bottom:-2px">前台记录（给以后的前台评估用）</div><div class="note">' + fgTxt + '</div>';
  h += evalFootHtml();
  el.innerHTML = h; placeSegs(el);
}
/* v5.27 T4: 前台识别引擎(经典 / HMM 实验)+ 过去 24 小时对比 */
S.fgcmp = null;
function fgEngineSumTxt() {
  var r = S.fgcmp; if (!r || r.err) return '经典（打分 + 滞回）· 新引擎（实验）更不容易来回跳';
  return (r.engine === 'hmm' ? '新（实验）' : '经典') + ' · 过去 24 小时两者一致 ' + num(r.agree_pct) + '%';
}
function fgEngineFold() {
  return sFold('fgeng', ['purple', 'gauge'], '前台识别引擎', '<span id="fgeng-sum">' + esc(fgEngineSumTxt()) + '</span>', '<div id="fgeng-body"><div class="note">展开后加载</div></div>');
}
function loadFgEngine() {
  return api.get('/api/fg_compare', { days: 1 }, { timeout: 8000 }).then(function (r) { S.fgcmp = r; }).catch(function (e) { S.fgcmp = { err: errText(e) }; }).then(paintFgEngine);
}
function paintFgEngine() {
  var el = $('#fgeng-body'), r = S.fgcmp; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  var sm = $('#fgeng-sum'); if (sm) sm.textContent = fgEngineSumTxt();
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持）</div>'; return; }
  var c = r.classic || {}, hm = r.hmm || {};
  el.innerHTML = seg('fg-engine', [['classic', '经典'], ['hmm', '新（实验）']], r.engine || 'classic', 'small') +
    (num(r.rounds) ? '<div class="note">过去 24 小时：经典 切换 ' + num(c.switches_per_hour) + ' 次/小时、短于 30 秒的 ' + num(c.short_segments) + ' 段；新 ' + num(hm.switches_per_hour) + ' 次/小时、' + num(hm.short_segments) + ' 段；两者一致 ' + num(r.agree_pct) + '%</div>'
      : '<div class="note">过去 24 小时还没有热点设备的流量，暂无对比。</div>') +
    '<div class="note">新引擎更不容易来回跳；切换后前台时间线从此刻起按新引擎记录。只影响「正在用什么」的显示和前台时间线，不影响识别、限速和限时。</div>';
  placeSegs(el);
}
/* v5.27 T6: 我的规则包(导出 / 导入 / 清除已导入) */
S.rpack = null; S.rpackRep = null;
function rulepackSumTxt() {
  var r = S.rpack; if (!r || r.err) return '把这台手机学到的和你自己加的识别规则打包备份 / 分享';
  var ex = r.exportable || {}, im = r.imported || {};
  return '可导出 ' + num(ex.domain_rules) + ' 条域名规则 · ' + num(ex.fingerprints) + ' 个指纹 · ' + num(ex.startup) + ' 个启动指纹' + (num(im.domain_rules) + num(im.fingerprints) + num(im.startup) ? ' · 已导入 ' + num(im.suffixes) + ' 个域名' : '');
}
function rulepackFold() {
  return sFold('rpack', ['green', 'down'], '我的规则包', '<span id="rpack-sum">' + esc(rulepackSumTxt()) + '</span>', '<div id="rpack-body"><div class="note">展开后加载</div></div>');
}
function loadRulepack() {
  return api.get('/api/dpi_rulepack', { summary: 1 }, { timeout: 10000 }).then(function (r) { S.rpack = r; }).catch(function (e) { S.rpack = { err: errText(e) }; }).then(paintRulepack);
}
var RPK_SKIP = { conflict: '和本机规则冲突', already_local: '本机已有', public_suffix: '公共后缀', shared_apex: '共享基础设施', bad_suffix: '域名不合法', bad_id: 'id 不合法', bad_category: '类别本机没有', bad_attach: '挂靠目标不合法', bad_ja4: '指纹不合法', bad_qtp: 'QUIC 参数指纹不合法', bad_port: '端口类不合法', bad_alpn: 'ALPN 不合法', bad_value: '数值不合法', bad_token: '启动 token 不合法', too_few_tokens: '启动 token 太少', bad_entry: '格式不对' };
function rulepackRepHtml(rep) {
  if (!rep) return '';
  if (rep.err) return '<div class="note err">' + esc(rep.err) + '</div>';
  var a = rep.added || {}, m = rep.merged || {}, u = rep.unchanged || {}, sk = rep.skipped || {};
  var skl = Object.keys(sk).filter(function (k) { return num(sk[k]); }).map(function (k) { return (RPK_SKIP[k] || k) + ' ' + num(sk[k]); });
  return '<div class="note">导入完成：新增 ' + num(a.suffixes) + ' 个域名（' + num(a.domain_rules) + ' 条规则）· ' + num(a.fingerprints) + ' 个指纹 · ' + num(a.startup) + ' 个启动指纹' +
    (num(m.suffixes) + num(m.fingerprints) + num(m.startup) ? '；合并 ' + num(m.suffixes) + ' 个域名 · ' + num(m.fingerprints) + ' 个指纹 · ' + num(m.startup) + ' 个启动指纹' : '') +
    (num(u.suffixes) + num(u.fingerprints) + num(u.startup) ? '；已有未变 ' + num(u.suffixes + u.fingerprints + u.startup) + ' 条' : '') + '</div>' +
    (skl.length ? '<div class="note warn">跳过：' + esc(skl.join('、')) + '</div>' : '') +
    (Array.isArray(rep.conflicts) && rep.conflicts.length ? '<div class="note mono" style="font-size:11px;overflow-wrap:anywhere">' + esc(rep.conflicts.slice(0, 5).join(' · ')) + '</div>' : '');
}
function paintRulepack() {
  var el = $('#rpack-body'), r = S.rpack; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  var sm = $('#rpack-sum'); if (sm) sm.textContent = rulepackSumTxt();
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持规则包）</div>'; return; }
  var src = r.sources || {}, ex = r.exportable || {}, im = r.imported || {}, uc = src.user_corrections || {};
  var pr = function (x) { return num((x || {}).rules); };
  var h = '<div class="note">可导出：域名规则 ' + num(ex.domain_rules) + ' 条（自动扩展 ' + pr(src.auto_expanded) + ' / 晋升 ' + pr(src.auto_promoted) + ' / 自定义 ' + pr(src.user_custom) + ' / 纠正 ' + num(uc.domain) + '）· 指纹 ' + num(ex.fingerprints) + ' 条 · 启动指纹 ' + num(ex.startup) + ' 个应用</div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="box" style="flex:1"><input id="rpack-note" maxlength="60" placeholder="备注（可空，例如「家里的手机」）"></span></div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">包含已导入的</div><div class="s">已导入 ' + num(im.suffixes) + ' 个域名 · ' + num(im.fingerprints) + ' 个指纹 · ' + num(im.startup) + ' 个启动指纹（别人给你的）</div></span>' + toggle(false, 'id="rpack-inc" data-local="rpack-inc" aria-label="包含已导入的"') + '</div>' +
    '<div class="btns"><button class="btn pri press" data-act="rpack-export">导出</button></div>' +
    '<div class="note" style="margin-bottom:-2px">导入</div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><input id="rpack-file" type="file" accept=".json,application/json" style="flex:1;min-width:0"></div>' +
    '<textarea id="rpack-text" rows="3" placeholder="或者把规则包 JSON 粘贴到这里" style="width:100%;box-sizing:border-box;font-size:12px"></textarea>' +
    '<div class="btns"><button class="btn sec press" data-act="rpack-import">导入</button>' +
    (num(im.domain_rules) + num(im.fingerprints) + num(im.startup) ? '<button class="btn sec danger press" data-act="rpack-clear">清除已导入</button>' : '') + '</div>' +
    '<div id="rpack-rep">' + rulepackRepHtml(S.rpackRep) + '</div>' +
    '<div class="note">只包含这台手机自己学到的和你自己加的规则，不含模块自带规则，也不含任何设备的 MAC / IP。导入的规则只用来给流量贴应用标签；和本机规则冲突的条目会被跳过。</div>';
  el.innerHTML = h;
}
function rulepackExport(btn) {
  var note = ($('#rpack-note') || {}).value || '', inc = $('#rpack-inc');
  var p = { note: note.trim() }; if (inc && inc.getAttribute('aria-checked') === 'true') p.include_imported = '1';
  btn.disabled = true;
  return api.action('dpi_rulepack_export', p, { timeout: 20000, maxTime: 18 }).then(function (r) {
    var d = detailJSON(r), name = String(d.name || '');
    if (!/^[A-Za-z0-9._-]+$/.test(name)) { toast('规则包已生成'); return; }
    if (KSU) return shell('mkdir -p /sdcard/Download && cp ' + sq(HNC_DIR + '/exports/' + name) + ' /sdcard/Download/ && echo ok').then(function () { toast('规则包已存到 /sdcard/Download/' + name); });
    downloadExport(name, '/api/exports/' + encodeURIComponent(name)); toast('规则包已生成 · ' + name);
  }).catch(function (e) { toast(errText(e), 'err'); }).then(function () { btn.disabled = false; });
}
function rulepackImport(btn) {
  var f = $('#rpack-file'), ta = $('#rpack-text');
  var readTxt = (f && f.files && f.files[0]) ? new Promise(function (ok, no) {
    var fr = new FileReader(); fr.onload = function () { ok(String(fr.result || '')); }; fr.onerror = function () { no(new Error('读取文件失败')); }; fr.readAsText(f.files[0]);
  }) : Promise.resolve(ta ? ta.value : '');
  btn.disabled = true;
  return readTxt.then(function (txt) {
    txt = String(txt || '').trim();
    if (!txt) throw new Error('先选择规则包文件，或把 JSON 粘贴进来');
    var o; try { o = JSON.parse(txt); } catch (e) { throw new Error('JSON 格式错误：' + e.message); }
    if (!o || o.format !== 'hnc-rulepack') throw new Error('这不是 HNC 规则包');
    if (txt.length > 1200 * 1024) throw new Error('规则包超过 1.2 MB');
    if (KSU && txt.length > 120 * 1024) throw new Error('规则包较大，本机界面传不过去，请在浏览器里打开远程管理页面导入');
    return api.post('/api/dpi_rulepack', { pack: txt }, { timeout: 30000, maxTime: 28 });
  }).then(function (rep) {
    if (rep && rep.ok === false) throw new Error(rep.error || '导入失败');
    S.rpackRep = rep; toast('规则包已导入'); return loadRulepack();
  }).catch(function (e) { S.rpackRep = { err: errText(e) }; var rp = $('#rpack-rep'); if (rp) rp.innerHTML = rulepackRepHtml(S.rpackRep); toast(errText(e), 'err'); })
    .then(function () { btn.disabled = false; });
}
/* v5.27 T3: 学会的启动指纹列表(/api/dpi_startup) */
S.startup = null; S.startupOpen = false;
function startupListHtml() {
  var r = S.startup; if (!r) return '<div class="note">加载中…</div>';
  if (r.err) return '<div class="note err">' + esc(r.err) + '</div>';
  var ln = (Array.isArray(r.learned) ? r.learned : []).filter(function (x) { return x.usable; });
  if (!ln.length) return '<div class="note">还没有学会的应用：同一个应用要冷启动 3 次以上、且每次都连到 2 个以上它特有的域名才算学会。</div>';
  return '<div class="dbox">' + ln.slice(0, 20).map(function (x) {
    return '<div class="row2"><span class="k" style="min-width:0;overflow-wrap:anywhere">' + esc(x.name || x.app_id) + '</span><span class="v num" style="white-space:nowrap">启动 ' + num(Math.round(num(x.starts))) + ' 次 · 特征 ' + num(x.feat) + ' 个</span></div>';
  }).join('') + '</div><div class="note">累计事件 ' + num((r.stats || {}).events_total) + ' 次（热点设备上认出的「打开了某应用」）</div>';
}
function toggleStartupList() {
  S.startupOpen = !S.startupOpen;
  var el = $('#startup-list'), b = $('[data-act="startup-list"]');
  if (b) b.textContent = S.startupOpen ? '收起学会的应用' : '查看学会的应用';
  if (!el) return Promise.resolve();
  if (!S.startupOpen) { el.innerHTML = ''; return Promise.resolve(); }
  el.innerHTML = startupListHtml();
  return api.get('/api/dpi_startup', null, { timeout: 8000 }).then(function (r) { S.startup = r; }).catch(function (e) { S.startup = { err: errText(e) }; })
    .then(function () { var e2 = $('#startup-list'); if (e2 && S.startupOpen) e2.innerHTML = startupListHtml(); });
}
function evalFootHtml() {
  return '<div class="note">只用这台手机自己的流量，样本保存 7 天，不上传。采够样本后可点「立即蒸馏」把本机真值秒级转化为热点指纹与流分类模型。</div>' +
    '<div class="btns" style="flex-wrap:wrap">' +
      '<button class="btn pri press" data-act="dpi-distill-now">立即蒸馏训练</button>' +
      '<button class="btn sec press" data-act="go-self-studio">自训工作台</button>' +
      '<button class="btn sec press" data-act="eval-refresh">刷新</button>' +
      '<button class="btn sec danger press" data-act="eval-clear">清除样本</button>' +
    '</div>';
}
function loadLog() {
  var el = $('#logv'); if (!el) return;
  api.get('/api/logs', { file: S.logFile === 'combined' ? 'combined' : S.logFile + '.log', tail: 300 }, { timeout: 10000 }).then(function (r) {
    S.logText = r.content || ''; el.setAttribute('data-keep', '');
    var lines = S.logText.split('\n').filter(Boolean).slice(-300);
    el.innerHTML = lines.length ? lines.map(function (ln) { var c = /\b(ERR|ERROR|FAIL|FATAL|panic)\b|失败|错误/i.test(ln) ? 'E' : /\bWARN|WARNING\b|警告/i.test(ln) ? 'W' : 'I'; return '<div class="' + c + '">' + esc(ln) + '</div>'; }).join('') : '<div class="t">(空)</div>';
    el.scrollTop = el.scrollHeight;
  }).catch(function (e) { el.innerHTML = '<div class="E">' + esc(errText(e)) + '</div>'; });
}
function loadTokens() {
  var el = $('#tokens-list'); if (!el) return;
  api.get('/api/tokens').then(function (r) {
    var t = r.tokens || [];
    el.className = ''; el.setAttribute('data-keep', '');
    el.innerHTML = t.length ? t.map(function (x) {
      return '<div class="row" style="padding:8px 0;min-height:0"><span class="tx"><div class="t">' + esc(x.label || '未命名设备') + '</div><div class="s mono">' + esc(x.ip_hint || '') + ' · ' + (x.last_seen ? new Date(x.last_seen * 1000).toLocaleString() : '从未使用') + ' · ' + esc(String(x.token_id || '').slice(0, 8)) + '</div></span>' +
        (KSU ? '<button class="hint-a danger" data-revoke="' + esc(x.token_id) + '" data-label="' + esc(x.label || '未命名设备') + '">撤销</button>' : '') + '</div>';
    }).join('') : '<div class="note">还没有已授权的设备</div>';
  }).catch(function (e) { el.className = 'note err'; el.textContent = errText(e); });
}
var pairT = 0;
function pairNew() {
  return api.action('pair_new').then(function (r) {
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
  var details = FX_LIST.map(function (x) {
      var dis = !S.motion && x[0] !== 'title' && x[0] !== 'haptic';
      return '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">' + x[1] + '</div><div class="s">' + x[2] + '</div></span>' + toggle(FX[x[0]], 'data-set="fx-' + x[0] + '" aria-label="' + x[1] + '"' + (dis ? ' disabled' : '')) + '</div>';
    }).join('') +
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">弹簧手感</div><div class="s">轻快：300 / 30 · 有弹性：200 / 20</div></span>' + seg('fxspring', [['light', '轻快'], ['bouncy', '有弹性']], FX.spring, 'small') + '</div>' +
    '<div class="note" style="margin:6px 0 -2px">效果演示</div><div class="chips">' + [['sheet', '弹层'], ['page', '切页'], ['list', '列表浮现'], ['num', '数字滚动']].map(function (b) { return '<button class="chip press" data-act="fx-demo" data-demo="' + b[0] + '">' + b[1] + '</button>'; }).join('') + '</div>' +
    '<div class="note">演示数字：<b class="num" id="fx-num" style="color:var(--text-1)">128.00</b> MB/s</div>';
  return '<div class="note" style="margin:8px 0 -2px">动画档位 · ' + FXP_T[pre] + '</div>' +
    seg('fxp', [['off', '关闭'], ['calm', '克制'], ['std', '标准'], ['lively', '灵动']], pre, 'small') +
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">性能模式</div><div class="s">' + (PERF.low ? '已开启简化渲染（最高帧率）' : '高帧率优化已启用') + (PERF.probe ? ' · ' + PERF.probe : '') + '</div></span><button class="linkish" data-act="fx-perf">' + (PERF.low ? '恢复完整' : '手动简化') + '</button></div>' +
    dFold('fx-more', 'var(--purple)', '展开 8 项动画细节与测试', FXP_T[pre], details);
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
  // 提交期间开关保持 .pending: 不接受再次点击(防重复提交), 后台重绘也不会把它改回旧状态; 失败只回滚一次
  var run = function (p) { return busyWhile(el, p.catch(rollback)); };
  if (kind.indexOf('fx-') === 0) { FX[kind.slice(3)] = on; saveFx(); fxRefresh(); return; }
  switch (kind) {
    case 'motion': S.motion = on; LS.set('hnc6.motion', on ? '1' : '0'); fxRefresh(); return;
    case 'hs-auto': run(api.action('hotspot_save', { autostart: on ? 'true' : 'false' }).then(done()));
      var w = el.closest('[data-foldkey]'); if (on && w && !w.classList.contains('open')) foldToggle(w, 'hs'); return;
    case 'amaster': run(api.action('alert_config_set', { section: 'master', enabled: String(on) }).then(done()).then(reloadAlertCfg)); return;
    case 'ud': run(api.action('alert_config_set', udParams(on)).then(done()).then(reloadAlertCfg)); return;
    case 'aq': run(api.action('alert_config_set', { section: 'monthly_quota', enabled: String(on), limit_gb: String(num($('#aq-gb').value, 10)), warn_pct: String(Math.round(num($('#aq-pct').value, 80))) }).then(done())); return;
    case 'aa': run(api.action('alert_config_set', { section: 'anomaly_traffic', enabled: String(on), ratio: String(num($('#aa-ratio').value, 3)), min_mb: String(Math.round(num($('#aa-mb').value, 50))) }).then(done())); return;
    case 'autorate':
      run(api.action('autorate_set', {
        autorate_enabled: String(on),
        down_min_mbps: String(num($('#ar-dmin') && $('#ar-dmin').value, 24)),
        down_max_mbps: String(num($('#ar-dmax') && $('#ar-dmax').value, 320)),
        up_min_mbps: String(num($('#ar-umin') && $('#ar-umin').value, 8)),
        up_max_mbps: String(num($('#ar-umax') && $('#ar-umax').value, 80)),
        rtt_delta_ms: String(num($('#ar-delta') && $('#ar-delta').value, 25))
      }).then(done(on ? '5G 自适应总带宽已开启' : '5G 自适应总带宽已关闭')).then(function () { if (S.page === 'settings') renderSettings(false); })); return;
    case 'client-iso':
      run(api.action('client_isolation_set', { enabled: String(on) }).then(done(on ? '热点客户端互访隔离已开启' : '热点客户端互访隔离已关闭')).then(function () { if (S.page === 'settings') renderSettings(false); })); return;
    case 'gs':
      if (on) { var gw = el.closest('[data-foldkey]'); if (gw && !gw.classList.contains('open')) foldToggle(gw, 'gs'); el.setAttribute('aria-checked', 'false'); toast('填好上限后点「应用」启用'); return; }
      run(api.action('global_shaper_set', { enabled: 'false' }).then(done('全局带宽整形已关闭'))); return;
    case 'remote': run(api.action('remote_enabled_set', { enabled: String(on) }).then(function (r) { toast(on ? '远程访问已开启 · 约 1 分钟内可访问' : '远程访问已关闭 · 约 1 分钟内 :8443 关闭'); return loadConfig(); })).then(function () { if (S.page === 'settings') renderSettings(false); }); return;
    case 'appshared': run(api.action('app_limit_shared_ips_set', { enabled: String(on) }).then(function () { S.appLimitShared = on; toast(on ? '已包含共享 IP · 同一 CDN 上的其他应用也可能被一起限速' : '已恢复：跳过与其他应用共用的地址'); return loadAppLimits(); })); return;
    case 'certprobe': run(api.action('discover_cert_probe_set', { enabled: String(on) }).then(done())); return;
    case 'sim': run(simSet(on)); return;
    case 'dnst':
      if (!on) { run(api.action('dns_takeover_set', { enabled: 'false' }).then(function () { toast('DNS 接管已关闭 · 设备恢复直连'); return loadDNS(); })); return; }
      el.setAttribute('aria-checked', 'false');
      confirmSheet('开启 DNS 接管？', '热点设备的 DNS 查询改由 HNC 代答，识别更早、按域名封锁更彻底。<br>HNC 的 DNS 出问题时约 10 秒内自动放行直连；设备开了私人 DNS / DoH 时接管不到。随时可以关闭。', '开启', { safe: true }).then(function (ok) {
        if (!ok) return; el.setAttribute('aria-checked', 'true');
        run(api.action('dns_takeover_set', { enabled: 'true' }).then(function () { toast('DNS 接管已开启 · 约 10 秒内生效'); return loadDNS(); }));
      }); return;
    case 'dnslog': run(api.action('dns_takeover_set', { log_queries: String(on) }).then(function () { toast(on ? '已开始记录查询日志' : '已停止记录查询日志'); return loadDNS(); })); return;
    case 'dnsredact': run(api.action('dns_takeover_set', { log_redact: String(on) }).then(function () { toast(on ? '已开启 DNS 日志脱敏' : '已关闭 DNS 日志脱敏'); return loadDNS(); })); return;
    case 'authreq': run(api.action('auth_required_set', { enabled: String(on) }).then(function () { if (S.cfg) { S.cfg.auth_required = on; S.cfg.remote_auth_required = on; } toast('已同步远程鉴权配置'); })); return;
    case 'quic': run(api.action('quic_block_set', { enabled: String(on) }).then(function (r) { toast(on ? (/pending/.test(r && r.detail || '') ? '已开启 · 热点打开后生效' : '已开启 · QUIC 流量会回落到 TCP') : '已关闭 · 恢复 QUIC'); return loadConfig(); })); return;
  }
}
function clsactCheck(quiet) {
  return api.action('clsact_check').then(function (r) { S.clsact = detailJSON(r); if (S.page === 'settings') renderSettings(false); }).catch(function (e) { if (!quiet) toast(errText(e), 'err'); });
}
function hsStart() {
  return api.action('hotspot_start').then(function () {
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
  return api.action('hotspot_save', p).then(function () { $('#hs-pass').value = ''; toast('热点配置已保存'); return loadConfig(); }).catch(function (e) { toast(errText(e), 'err'); });
}
function gsApply(btn) {
  var d = num($('#gs-down').value), u = num($('#gs-up').value);
  if (!(d > 0) && !(u > 0)) { toast('至少填一个方向的上限', 'err'); return; }
  var p = { enabled: 'true' }; if (d > 0) p.rate_down = fmtRate(d); if (u > 0) p.rate_up = fmtRate(u);
  busyWhile(btn, api.action('global_shaper_set', p)).then(function (r) { toast('全局带宽整形已启用' + (r.detail ? ' · ' + String(r.detail).slice(0, 60) : '')); return loadConfig(); }).then(function () { if (S.page === 'settings') renderSettings(false); }).catch(function (e) { toast(errText(e), 'err'); });
}
function exportRulesJson() {
  return api.get('/api/rules_export', null, { timeout: 10000 }).then(function (r) {
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
var SC_ST = { ok: [uiSvg('check'), '正常'], warn: [uiSvg('warn'), '警告'], fail: [uiSvg('cross'), '失败'], info: [uiSvg('info'), '信息'] };
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
function scSumTxt(s) { s = s || {}; return '正常 ' + num(s.ok) + ' · 警告 ' + num(s.warn) + ' · 失败 ' + num(s.fail); }
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
  var extraTools = '<div class="btns" style="margin-top:6px"><button class="btn sec press" data-act="compat-report" style="flex:1">' + ico('down') + '导出兼容性报告(脱敏)</button></div>' +
    '<div class="btns" style="margin-top:6px"><button class="btn sec press" data-act="rec-start" style="flex:2.2">' + ico('flask') + '录制握手流量 10 分钟</button><button class="btn sec press" data-act="rec-stop" style="flex:1">停止</button></div>' +
    '<div id="rec-hint" style="margin-top:4px;font-size:12px;opacity:.7">录制内容包含连接设备访问的域名,只存本机、请勿随意分享。录完自动出现在「导出」列表。</div>';
  if (!r) {
    return h + '<div class="note" style="text-align:center;margin:14px 0 10px">' + (SC.running ? '' : '还没有自检记录。自检会检查机型与系统、限速能力、防火墙、硬件加速、热点、IPv6、时间、进程和识别引擎，只读不改任何设置。') + '</div>' + extraTools;
  }
  var s = r.summary || {}, scVer = cleanVer(r.version, '');
  h += '<div class="sc-meta">' + esc(scAgo(r.generated_at)) + '生成 · 耗时 ' + scDur(r.duration_ms) + (scVer ? ' · ' + esc(scVer) : '') + (r.redacted ? ' · 已打码' : '') + '</div>';
  h += '<div class="sc-chips">' + ['ok', 'warn', 'fail', 'info'].map(function (k) { return '<div class="sc-chip ' + k + (num(s[k]) ? ' has' : '') + '"><b class="num">' + SC_ST[k][0] + ' ' + num(s[k]) + '</b><span>' + SC_ST[k][1] + '</span></div>'; }).join('') + '</div>';
  h += dpvRenderSelfCheckSummaryHtml();
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
  h += extraTools;
  return h;
}
function paintSc() {
  var b = $('#sc-body'); if (!b || $('#sheet').dataset.kind !== 'selfcheck') return;
  b.innerHTML = scBody(); placeSegs(b);
}
function scSheet() {
  sheet('<h3>自检报告</h3><div class="sub">检查这台手机能不能完整支持 HNC 的各项功能</div><div id="sc-body">' + scBody() + '</div>', { tall: true, kind: 'selfcheck', onClose: function () { if (REC.timer) { clearInterval(REC.timer); REC.timer = 0; } if (S.page === 'settings') renderSettings(false); } });
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
function loadRemoteChangelog() {
  if (clCache) return Promise.resolve(clCache);
  if (window.__HNC_REMOTE_CHANGELOG) return Promise.resolve(window.__HNC_REMOTE_CHANGELOG);
  if (window.__HNC_MOCK_CHANGELOG) return Promise.resolve(window.__HNC_MOCK_CHANGELOG);
  return new Promise(function (resolve) {
    var m = window.__HNC_MOCK_META || {};
    var fbVer = cleanVer(m.version, '') || cleanVer(S.live && S.live.backend_version, '') || 'v6.1.0-rc.1';
    var fallback = '<div class="cl-section" id="cl-history">' +
      '<div class="cl-title">' + uiSvg('sparkles') + ' ' + esc(fbVer) + ' · Vector 四舱壁零开销网关与三级自适应数据面</div>' +
      '<ul class="cl-list">' +
        '<li><b>按需远程加载</b>：已移除主文件内嵌的 378 KB 历史更新日志，改为由服务端按需注入 <code>changelog.html</code>，单文件体积直降 35%+。</li>' +
        '<li><b>iOS 27 光学液态玻璃</b>：新增状态驱动边缘导光、晶莹水滴开关拇指、分段滑块水银拉伸形变、顶栏滚动动态折射与深色黑曜石菲涅尔反射。</li>' +
        '<li><b>设置页四级卡片折叠</b>：支持「全部 / 常用 / 进阶 / 诊断」四级筛选与 14 张独立液态卡片折叠。</li>' +
      '</ul></div>';
    if (location.protocol === 'file:' || window.__HNC_MOCK_META) { resolve(fallback); return; }
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', 'changelog.html', true);
      xhr.timeout = 4000;
      xhr.onload = function () { resolve(xhr.status >= 200 && xhr.status < 300 && xhr.responseText ? xhr.responseText : fallback); };
      xhr.onerror = xhr.ontimeout = function () { resolve(fallback); };
      xhr.send();
    } catch (_) { resolve(fallback); }
  });
}
function showChangelog() {
  sheet('<h3>更新日志</h3><div class="cl-body" id="cl-body"><div class="note" style="text-align:center">正在按需加载更新日志…</div></div><button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true });
  loadRemoteChangelog().then(function (txt) {
    clCache = txt;
    var doc = new DOMParser().parseFromString(txt, 'text/html');
    $$('script,iframe,object,embed,form,link,meta,style', doc).forEach(function (n) { n.remove(); });
    $$('*', doc.body).forEach(function (n) {
      Array.prototype.slice.call(n.attributes).forEach(function (a) {
        var an = a.name.toLowerCase();
        if (/^on/.test(an)) { n.removeAttribute(a.name); return; }
        if (an === 'href' || an === 'xlink:href' || an === 'src' || an === 'action' || an === 'formaction') {
          var av = String(a.value || '').replace(/[\u0000-\u0020]+/g, '');
          if (/^(javascript|vbscript|data):/i.test(av)) n.removeAttribute(a.name);
        }
      });
    });
    var b = $('#cl-body'); if (b) b.innerHTML = doc.body.innerHTML;
  }).catch(function (e) { var b = $('#cl-body'); if (b) b.innerHTML = '<div class="note err">读取 changelog.html 失败：' + esc(errText(e)) + '</div>'; });
}


/* v5.29 T5: 兼容性报告(白名单收集, 不含 MAC/IP/SSID/设备名等) */
function compatExport(btn) {
  btn.disabled = true; toast('正在生成兼容性报告…');
  api.action('compat_report', {}, { timeout: 45000, maxTime: 43 }).then(function (r) {
    var d = detailJSON(r), name = String(d && d.name || '');
    if (!/^[A-Za-z0-9._-]+$/.test(name)) { toast('报告已生成'); return; }
    if (KSU) {
      return shell('mkdir -p /sdcard/Download && cp ' + sq(HNC_DIR + '/exports/' + name) + ' /sdcard/Download/ && echo ok')
        .then(function () { toast('报告已存到 /sdcard/Download/' + name); });
    }
    downloadExport(name, '/api/exports/' + encodeURIComponent(name));
    toast('报告已生成 · ' + name);
  }).catch(function (e) { toast(errText(e), 'err'); })
  .then(function () { btn.disabled = false; });
}

/* v5.29 T4: 流量录制(DPI 回归): capture_record / capture_record_stop + 状态轮询 */
// dpid 空闲时 10 秒才看一次请求文件: 点了开始后的 25 秒内「还没在录」算
// 正在启动, 继续轮询(rc1 点完立刻查一次, 查到没在录就停轮询并显示「未在录制」)
var REC = { timer: 0, pendingUntil: 0 };
function recStart(btn) {
  api.action('capture_record', { minutes: '10' }, { timeout: 12000 }).then(function () {
    toast('已请求录制(最长 10 分钟)'); REC.pendingUntil = Date.now() + 25000; recPoll();
    if (REC.timer) clearInterval(REC.timer);
    REC.timer = setInterval(recPoll, 5000);
  }).catch(function (e) { toast(errText(e), 'err'); });
}
function recPoll() {
  api.getSafe('/api/health', null, {}).then(function (h) {
    var r = h && h.capture_rec;
    var hint = document.getElementById('rec-hint');
    if (!r || !r.recording) {
      if (Date.now() < REC.pendingUntil) { if (hint) hint.textContent = '等待抓包进程开始录制…'; return; }
      if (REC.timer) { clearInterval(REC.timer); REC.timer = 0; }
      if (hint) hint.textContent = '未在录制。录制内容包含连接设备访问的域名,只存本机、请勿随意分享。';
      return;
    }
    REC.pendingUntil = 0;
    var left = Math.max(0, Math.round((r.minutes * 60 - (Date.now() / 1000 - (r.started_at || 0))) / 60));
    var mb = (r.bytes || 0) / 1048576;
    if (hint) hint.textContent = '录制中 · 剩余约 ' + left + ' 分钟 · 已 ' + mb.toFixed(1) + ' MB(上限 20 MB)';
    if (typeof S !== 'undefined' && S && S.page !== 'settings' && REC.timer) { clearInterval(REC.timer); REC.timer = 0; }
  });
}
function recStop() {
  REC.pendingUntil = 0;
  api.action('capture_record_stop', {}, { timeout: 12000 }).then(function () { toast('停止中,文件稍后出现在「导出」列表'); recPoll(); })
    .catch(function (e) { toast(errText(e), 'err'); });
}

/* ═════════════════════ v5.40.0 数据面真机命中核验面板 & Go 1.27 goroutineleak 按需诊断 ═════════════════════
 * 100% 双向兼容专线 3 dataplane_verify.go JSON 契约与动作返回格式 (actionResp.Detail JSON 字符串)
 * 全量 24×24 viewBox · stroke-width="1.85" 双层光学纯矢量 SVG · 零位图 · 零坏词安全兜底
 */
var DPV_API_PATH = '/api/dataplane_verify';
var DPV_RUN_ACT = 'dataplane_verify_run';
var DPV_APP_NAMES = {
  douyin: '抖音', kuaishou: '快手', wechat: '微信', honor_of_kings: '王者荣耀',
  genshin: '原神', peacekeeper: '和平精英', bilibili: 'B站 (哔哩哔哩)', iqiyi: '爱奇艺',
  tencent_video: '腾讯视频', xiaomi_store: '小米应用商店', tencent_meeting: '腾讯会议',
  feishu: '飞书', icloud: 'iCloud', nintendo_eshop: '任天堂 eShop',
  nintendo_online: 'Nintendo Switch Online', qqmusic: 'QQ音乐', xiaohongshu: '小红书',
  amap: '高德地图', taobao: '淘宝', weibo: '微博', netease_music: '网易云音乐',
  windows_update: 'Windows 更新', teams: 'Microsoft Teams', short_video: '短视频流媒体',
  moba_game: '实时竞技对战', cloud_sync: '云盘同步传输'
};
var DPV_STATE = {
  loading: false,
  resyncing: false,
  seq: 0,
  leakEnabled: false,
  leakUserToggled: false,
  lastData: null,
  sheetOpen: false
};

var DPV_ICONS = {
  dataplane:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M12 3L4.5 6.2v5.4c0 5.05 3.2 9.55 7.5 10.9 4.3-1.35 7.5-5.85 7.5-10.9V6.2L12 3z" fill="currentColor" fill-opacity=".16"/>' +
    '<path d="M12 3L4.5 6.2v5.4c0 5.05 3.2 9.55 7.5 10.9 4.3-1.35 7.5-5.85 7.5-10.9V6.2L12 3z"/>' +
    '<path d="M7.5 12.2h2.4l1.6-3.2 2.2 6 1.6-2.8h1.9"/>' +
    '</svg>',
  runVerify:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="8.5" fill="currentColor" fill-opacity=".16"/>' +
    '<circle cx="12" cy="12" r="8.5"/>' +
    '<path d="M12.8 7.5L9.2 12.4h3.1l-.9 4.1 3.8-5.1h-3.1l.7-3.9z"/>' +
    '</svg>',
  repair:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="8.5" fill="currentColor" fill-opacity=".16"/>' +
    '<path d="M19.2 12a7.2 7.2 0 0 1-12.3 5.1M4.8 12a7.2 7.2 0 0 1 12.3-5.1"/>' +
    '<path d="M14.4 6.9h3V3.9M9.6 17.1h-3v3"/>' +
    '</svg>',
  counters:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="3.5" y="4.5" width="17" height="15" rx="3" fill="currentColor" fill-opacity=".16"/>' +
    '<rect x="3.5" y="4.5" width="17" height="15" rx="3"/>' +
    '<path d="M7.5 15.5v-3M12 15.5V8.5M16.5 15.5v-5"/>' +
    '</svg>',
  fwmark:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="3.5" y="5.5" width="17" height="13" rx="2.5" fill="currentColor" fill-opacity=".16"/>' +
    '<rect x="3.5" y="5.5" width="17" height="13" rx="2.5"/>' +
    '<path d="M7.5 10h4M7.5 14h9M14.5 10h2"/>' +
    '</svg>',
  leakScan:
    '<svg class="dpv-ico" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="8.5" fill="currentColor" fill-opacity=".16"/>' +
    '<circle cx="12" cy="12" r="8.5"/>' +
    '<circle cx="12" cy="12" r="2.3"/>' +
    '<path d="M12 5.8v2.1M12 16.1v2.1M5.8 12h2.1M16.1 12h2.1"/>' +
    '</svg>'
};

function dpvHasBadToken(str) {
  if (typeof str !== 'string') return true;
  var t = str.trim();
  return (
    t === 'undefined' ||
    t === 'NaN' ||
    t === 'null' ||
    t === '[object Object]'
  );
}

function dpvStr(val, fallback) {
  var fb = typeof fallback === 'string' ? fallback : '';
  if (val === null || typeof val === 'undefined') return fb;
  if (typeof val === 'number') return isFinite(val) ? String(val) : fb;
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'string') {
    var t = val.trim();
    if (!t || dpvHasBadToken(t)) return fb;
    return val;
  }
  return fb;
}

function dpvEsc(val, fallback) {
  var raw = dpvStr(val, fallback);
  if (typeof esc === 'function') {
    var out = String(esc(raw));
    if (!dpvHasBadToken(out)) return out;
  }
  return raw.replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function dpvNum(val, defVal) {
  var d = typeof defVal === 'number' && isFinite(defVal) ? defVal : 0;
  if (val === null || typeof val === 'undefined' || val === '') return d;
  var n = Number(val);
  return typeof n === 'number' && isFinite(n) ? n : d;
}

function dpvInt(val) {
  var n = Math.max(0, Math.floor(dpvNum(val, 0)));
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function dpvBytes(val) {
  var b = Math.max(0, dpvNum(val, 0));
  if (typeof bytes === 'function') {
    var s = String(bytes(b));
    if (s && !dpvHasBadToken(s)) return s;
  }
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return Math.round(b / 1024) + ' KB';
  return Math.round(b) + ' B';
}

function dpvDeltaBytes(val) {
  var d = Math.max(0, dpvNum(val, 0));
  return '+' + dpvBytes(d);
}

function dpvRateMbps(mbps) {
  var m = dpvNum(mbps, 0);
  if (m <= 0) return '不限速';
  if (m >= 1) return (Math.abs(m - Math.round(m)) < 1e-6 ? Math.round(m) : Number(m.toFixed(1))) + ' Mbps';
  return Math.max(1, Math.round(m * 1000)) + ' Kbps';
}

function dpvObsRate(kbps) {
  var k = dpvNum(kbps, 0);
  if (k <= 0) return '';
  if (k >= 1000) return (k / 1000).toFixed(2) + ' Mbps';
  return Math.round(k) + ' Kbps';
}

/* v5.40.0 正交设备 mark 编码：0x00800000 | (mid << 16)，如 mid=1 -> 0x00810000，mid=5 -> 0x00850000 */
function dpvFormatMarkHex(mid) {
  var m = Math.floor(dpvNum(mid, 0));
  if (m <= 0) return '—';
  var v = ((0x00800000 | ((m & 0xff) << 16)) >>> 0).toString(16);
  while (v.length < 8) v = '0' + v;
  return '0x' + v;
}

function dpvFormatCheckedTime(tsSec, fallbackStr) {
  var t = Math.floor(dpvNum(tsSec, 0));
  if (t > 1000000000) {
    var d = new Date(t * 1000);
    var p = function (n) { return n < 10 ? '0' + n : String(n); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  return dpvStr(fallbackStr, '待首次采样');
}

function dpvVerdictMeta(verdict) {
  var v = dpvStr(verdict, 'idle');
  if (v === 'hit') return { key: 'hit', label: '队列真实命中', cls: 'dpv-status-hit' };
  if (v === 'bypass_offload' || v === 'bypass') return { key: 'bypass_offload', label: '疑似快径旁路', cls: 'dpv-status-bypass' };
  if (v === 'missing_class' || v === 'missing') return { key: 'missing_class', label: '内核队列缺失', cls: 'dpv-status-missing' };
  if (v === 'missing_rule') return { key: 'missing_rule', label: '掩码过滤器缺失', cls: 'dpv-status-missing' };
  return { key: 'idle', label: '链路就绪（空闲）', cls: 'dpv-status-idle' };
}

function dpvAppLabel(appId, rawName) {
  var nm = dpvStr(rawName, '');
  if (nm) return nm;
  var id = dpvStr(appId, '');
  if (!id) return '受控应用流';
  if (DPV_APP_NAMES[id]) return DPV_APP_NAMES[id] + ' (' + id + ')';
  return id;
}

/* 未采样 / 首次静默加载未返回时的诚实中性态（严禁伪装 BPF 已挂载或全绿健康） */
function dpvDefaultData(leakOn) {
  var ifc = (typeof S === 'object' && S && S.hotspot && S.hotspot.iface) ? S.hotspot.iface : '—';
  var hsOn = (typeof S === 'object' && S && S.hotspot && typeof S.hotspot.active === 'boolean') ? S.hotspot.active : false;
  return {
    ok: false,
    sampled_ok: false,
    checked_at: 0,
    checked_at_str: '待首次采样',
    iface: ifc || '—',
    hotspot_active: hsOn,
    engine_mode: 'pending',
    engine_label: '待采样核验',
    mark_layout: 'orthogonal_v540_0xffff0000',
    fwmark_mask: '0xffff0000',
    netd_low16_protected: true,
    ipv6_quic_controlled: false,
    bpf_maps: {
      mac_mark_entries: 0,
      ip_mark_entries: 0,
      tether_limit_zeroed: false,
      clsact_attached: false,
      ifb_redirect_prio2: false
    },
    offload_guard: {
      slowpath_active: false,
      tether_offload_disabled: false,
      hwnat: 'unknown'
    },
    summary: {
      controlled_devices: 0,
      hitting_count: 0,
      idle_count: 0,
      bypass_or_missing_count: 0,
      app_classes_total: 0,
      overall_status: 'unsampled',
      headline: '待采样核验：请点击立即核验读取内核计数，确认 HTB 队列与正交掩码真实命中状态'
    },
    devices: [],
    goroutineleak: {
      sampled: false,
      supported: true,
      trigger: '',
      total_goroutines: 0,
      leaked_count: 0,
      duration_ms: 0,
      status: 'idle',
      message: '默认零闲置开销（按需打开开关即可执行 Go 1.27 runtime/pprof goroutineleak 阻塞协程扫描）',
      preview_stacks: []
    }
  };
}

function dpvNormalize(raw, leakOn) {
  var base = dpvDefaultData(leakOn);
  if (!raw || typeof raw !== 'object') return base;
  var src = raw.data && typeof raw.data === 'object' && (raw.data.summary || raw.data.devices) ? raw.data : raw;
  if (src.sampled_ok === false) return base;
  var hasPayload = Boolean(
    src.ok === true ||
    src.sampled_ok === true ||
    src.checked_at > 0 ||
    (src.summary && typeof src.summary === 'object') ||
    Array.isArray(src.devices) ||
    (src.bpf_maps && typeof src.bpf_maps === 'object') ||
    (src.goroutineleak && typeof src.goroutineleak === 'object')
  );
  if (!hasPayload || src.ok === false) return base;

  var eng = src.engine && typeof src.engine === 'object' ? src.engine : {};
  var sum = src.summary && typeof src.summary === 'object' ? src.summary : {};
  var bpf = src.bpf_maps && typeof src.bpf_maps === 'object' ? src.bpf_maps : {};
  var off = src.offload_guard && typeof src.offload_guard === 'object' ? src.offload_guard : {};
  var glk = src.goroutineleak && typeof src.goroutineleak === 'object' ? src.goroutineleak : null;
  var devs = Array.isArray(src.devices) ? src.devices : [];

  var normDevs = [];
  var hitCnt = 0, idleCnt = 0, errCnt = 0, appTotal = 0;

  for (var i = 0; i < devs.length; i++) {
    var d = devs[i] || {};
    var mid = typeof d.mark_id !== 'undefined' ? Math.floor(dpvNum(d.mark_id, 0)) : Math.floor(dpvNum(d.cid, 0));
    var classId = dpvStr(d.class_id || d.htb_class, mid === 1 ? '1:100' : (mid > 0 ? '1:' + mid : '—'));
    var markHex = dpvStr(d.mark_hex || d.fwmark_hex, dpvFormatMarkHex(mid));

    var downLimitMbps = typeof d.down_limit_mbps !== 'undefined'
      ? dpvNum(d.down_limit_mbps, 0)
      : dpvNum(d.rate_down_kbps, 0) / 1000;
    var upLimitMbps = typeof d.up_limit_mbps !== 'undefined'
      ? dpvNum(d.up_limit_mbps, 0)
      : dpvNum(d.rate_up_kbps, 0) / 1000;

    var rawApps = Array.isArray(d.app_classes)
      ? d.app_classes
      : (Array.isArray(d.app_subclasses) ? d.app_subclasses : []);
    var normApps = [];
    for (var j = 0; j < rawApps.length; j++) {
      var a = rawApps[j] || {};
      var aClassId = dpvStr(a.class_id || a.classid, '1:' + (0x9001 + j).toString(16));
      var aParent = dpvStr(a.parent_class_id || a.parent, classId !== '—' ? classId : '1:1');
      var aDownMbps = typeof a.down_limit_mbps !== 'undefined'
        ? dpvNum(a.down_limit_mbps, 0)
        : dpvNum(a.ceil_kbps, 0) / 1000;
      var aSent = dpvNum(a.sent_bytes, 0);
      var aDelta = dpvNum(a.delta_bytes, 0);
      var aVerdict = dpvStr(a.verdict || a.status, (aDelta > 0 || aSent > 0) ? 'hit' : 'idle');
      normApps.push({
        app_id: dpvStr(a.app_id, 'app_' + (j + 1)),
        app_label: dpvAppLabel(a.app_id, a.app_name),
        class_id: aClassId,
        parent_class_id: aParent,
        down_limit_mbps: aDownMbps,
        class_present: a.class_present !== false,
        sent_bytes: aSent,
        delta_bytes: aDelta,
        drops: dpvNum(a.drops, 0),
        delta_drops: dpvNum(a.delta_drops, 0),
        overlimits: dpvNum(a.overlimits, 0),
        observed_kbps: dpvNum(a.observed_kbps, 0),
        verdict: aVerdict
      });
    }

    var rawVerdict = dpvStr(d.verdict || d.status, '');
    if (!rawVerdict) {
      rawVerdict = (dpvNum(d.down_delta_bytes, 0) + dpvNum(d.up_delta_bytes, 0) + dpvNum(d.down_sent_bytes, 0) > 0) ? 'hit' : 'idle';
    }
    var vMeta = dpvVerdictMeta(rawVerdict);
    if (vMeta.key === 'hit') hitCnt++;
    else if (vMeta.key === 'idle') idleCnt++;
    else errCnt++;
    appTotal += normApps.length;

    normDevs.push({
      mac: dpvStr(d.mac, '02:00:00:00:00:' + pad2(i + 1)),
      name: dpvStr(d.name, dpvStr(d.mac, '受控设备 #' + (i + 1))),
      ip: dpvStr(d.ip, '—'),
      online: d.online !== false,
      blacklisted: Boolean(d.blacklisted),
      mark_id: mid,
      mark_hex: markHex,
      class_id: classId,
      down_limit_mbps: downLimitMbps,
      up_limit_mbps: upLimitMbps,
      app_qos: Boolean(d.app_qos),
      app_limits_count: typeof d.app_limits_count !== 'undefined' ? dpvNum(d.app_limits_count, normApps.length) : normApps.length,
      down_sent_bytes: dpvNum(d.down_sent_bytes, 0),
      down_delta_bytes: dpvNum(d.down_delta_bytes, 0),
      down_drops: dpvNum(d.down_drops, 0),
      down_delta_drops: dpvNum(d.down_delta_drops, 0),
      down_overlimits: dpvNum(d.down_overlimits, 0),
      down_observed_kbps: dpvNum(d.down_observed_kbps, 0),
      up_sent_bytes: dpvNum(d.up_sent_bytes, 0),
      up_delta_bytes: dpvNum(d.up_delta_bytes, 0),
      up_drops: dpvNum(d.up_drops, 0),
      up_delta_drops: dpvNum(d.up_delta_drops, 0),
      up_overlimits: dpvNum(d.up_overlimits, 0),
      up_observed_kbps: dpvNum(d.up_observed_kbps, 0),
      verdict: vMeta.key,
      status_label: dpvStr(d.status_label || d.status_text, vMeta.label),
      status_cls: vMeta.cls,
      reason: dpvStr(d.reason, ''),
      fix: dpvStr(d.fix, ''),
      app_classes: normApps
    });
  }

  var engineMode = dpvStr(src.engine_mode || eng.mode, 'go_native_netlink');
  var engineLabel = dpvStr(
    eng.label,
    engineMode === 'shell_compat' ? 'tc -s 兼容解析引擎' : 'Go 1.27 原生 RTNetlink · Green Tea GC'
  );
  var low16Protected = typeof src.netd_low16_protected === 'boolean'
    ? src.netd_low16_protected
    : (eng.netd_low16_preserved !== false);
  var markLayout = dpvStr(src.mark_layout, low16Protected ? 'orthogonal_v540_0xffff0000' : 'legacy_low16_overlap');
  var fwmarkMask = markLayout.indexOf('0xffff0000') !== -1
    ? '0xffff0000'
    : dpvStr(eng.fwmark_mask, low16Protected ? '0xffff0000' : markLayout);
  var ipv6Quic = typeof src.ipv6_quic_controlled === 'boolean'
    ? src.ipv6_quic_controlled
    : (sum.quic_guard_dualstack !== false);

  var ctrlTotal = typeof sum.controlled_devices !== 'undefined'
    ? dpvNum(sum.controlled_devices, normDevs.length)
    : dpvNum(sum.controlled_total, normDevs.length);
  var hittingCount = typeof sum.hitting_count !== 'undefined'
    ? dpvNum(sum.hitting_count, hitCnt)
    : dpvNum(sum.hit_active, hitCnt);
  var idleCount = typeof sum.idle_count !== 'undefined'
    ? dpvNum(sum.idle_count, idleCnt)
    : dpvNum(sum.ready_idle, idleCnt);
  var bypassMissingCount = typeof sum.bypass_or_missing_count !== 'undefined'
    ? dpvNum(sum.bypass_or_missing_count, errCnt)
    : (typeof sum.bypass_suspected !== 'undefined' || typeof sum.missing_queue !== 'undefined'
        ? dpvNum(sum.bypass_suspected, 0) + dpvNum(sum.missing_queue, 0)
        : errCnt);

  var rawOverall = dpvStr(sum.overall_status || sum.health, '');
  if (rawOverall === 'healthy') rawOverall = 'ok';
  if (rawOverall === 'error') rawOverall = 'fail';
  if (rawOverall !== 'ok' && rawOverall !== 'idle' && rawOverall !== 'warn' && rawOverall !== 'fail') {
    rawOverall = bypassMissingCount > 0 ? 'warn' : (hittingCount > 0 ? 'ok' : 'idle');
  }

  var hsActive = typeof src.hotspot_active === 'boolean'
    ? src.hotspot_active
    : ((typeof S === 'object' && S && S.hotspot && typeof S.hotspot.active === 'boolean') ? S.hotspot.active : true);

  var defaultHeadline = !hsActive
    ? '当前未开启热点，开启热点后即可检验设备限速是否真实生效'
    : bypassMissingCount > 0
      ? '发现 ' + bypassMissingCount + ' 台设备的限速可能被手机硬件加速绕过，请点击下方「一键修复限速」'
      : hittingCount > 0
        ? '限速已真实生效：' + hittingCount + '/' + ctrlTotal + ' 台限速设备的上网流量正经过限速通道（其余 ' + idleCount + ' 台当前无流量待命）'
        : ctrlTotal > 0
          ? '全部 ' + ctrlTotal + ' 台设备的限速通道已准备就绪，设备开始上网下载后即可看到生效计数'
          : '热点运行正常，目前还没有给任何设备单独设置限速或封锁';

  var ipEntries = typeof bpf.ip_mark_entries !== 'undefined'
    ? dpvNum(bpf.ip_mark_entries, 0)
    : (dpvNum(bpf.ip_mark_v4_entries, 0) + dpvNum(bpf.ip_mark_v6_entries, 0));

  var leakSampled = glk
    ? (typeof glk.sampled === 'boolean' ? glk.sampled : (typeof glk.enabled === 'boolean' ? glk.enabled : true))
    : false;
  var leakSupported = glk ? glk.supported !== false : true;
  var leakLeaked = glk ? dpvNum(glk.leaked_count, 0) : 0;
  var leakStatus = glk
    ? dpvStr(glk.status, !leakSupported ? 'unsupported' : (leakLeaked > 0 ? 'leak_detected' : 'clean'))
    : 'idle';
  var leakObj = {
    sampled: leakSampled,
    supported: leakSupported,
    trigger: glk ? dpvStr(glk.trigger, '') : '',
    total_goroutines: glk ? dpvNum(glk.total_goroutines, 18) : 0,
    leaked_count: leakLeaked,
    duration_ms: glk
      ? (typeof glk.duration_ms !== 'undefined' ? dpvNum(glk.duration_ms, 0) : dpvNum(glk.checked_ms, 0))
      : 0,
    status: leakStatus,
    message: glk
      ? dpvStr(glk.message || glk.note, base.goroutineleak.message)
      : base.goroutineleak.message,
    preview_stacks: glk && Array.isArray(glk.preview_stacks)
      ? glk.preview_stacks
      : (glk && Array.isArray(glk.samples) ? glk.samples : [])
  };

  return {
    ok: true,
    sampled_ok: true,
    checked_at: dpvNum(src.checked_at, 0),
    checked_at_str: dpvFormatCheckedTime(src.checked_at, dpvStr(src.checked_at_str, '刚刚就绪')),
    iface: dpvStr(src.iface, base.iface !== '—' ? base.iface : 'wlan2'),
    hotspot_active: hsActive,
    engine_mode: engineMode,
    engine_label: engineLabel,
    mark_layout: markLayout,
    fwmark_mask: fwmarkMask,
    netd_low16_protected: low16Protected,
    ipv6_quic_controlled: ipv6Quic,
    bpf_maps: {
      mac_mark_entries: dpvNum(bpf.mac_mark_entries, 0),
      ip_mark_entries: ipEntries,
      tether_limit_zeroed: bpf.tether_limit_zeroed !== false,
      clsact_attached: typeof bpf.clsact_attached === 'boolean' ? bpf.clsact_attached : true,
      ifb_redirect_prio2: typeof bpf.ifb_redirect_prio2 === 'boolean' ? bpf.ifb_redirect_prio2 : (bpf.clsact_attached !== false)
    },
    offload_guard: {
      slowpath_active: typeof off.slowpath_active === 'boolean' ? off.slowpath_active : (off.tether_offload_disabled !== false),
      tether_offload_disabled: off.tether_offload_disabled !== false,
      hwnat: dpvStr(off.hwnat, 'none')
    },
    summary: {
      controlled_devices: ctrlTotal,
      hitting_count: hittingCount,
      idle_count: idleCount,
      bypass_or_missing_count: bypassMissingCount,
      app_classes_total: dpvNum(sum.app_classes_active, appTotal),
      overall_status: rawOverall,
      headline: dpvStr(sum.headline || sum.verdict, defaultHeadline)
    },
    devices: normDevs,
    goroutineleak: leakObj
  };
}

function dpvFetchVerifyStrict(leakOn) {
  var params = leakOn ? { goroutineleak: '1' } : null;
  if (typeof api === 'object' && api && typeof api.get === 'function') {
    return api.get(DPV_API_PATH, params).then(function (res) {
      if (!res || typeof res !== 'object' || res.ok === false) {
        throw new Error((res && res.error) || '数据面核验响应无效');
      }
      return dpvNormalize(res, leakOn);
    });
  }
  return Promise.reject(new Error('API 请求通道不可用'));
}

function dpvRunVerifyAction(leakOn, resync) {
  var payload = leakOn
    ? { check_goroutineleak: '1', goroutineleak: '1' }
    : { check_goroutineleak: '0' };
  if (resync) payload.resync = '1';
  if (typeof api === 'object' && api && typeof api.action === 'function') {
    return api.action(DPV_RUN_ACT, payload, { timeout: 25000, maxTime: 22 }).then(function (res) {
      if (res && typeof res === 'object') {
        if (res.summary || Array.isArray(res.devices)) {
          return dpvNormalize(res, leakOn);
        }
        var parsed = typeof detailJSON === 'function' ? detailJSON(res) : null;
        if (parsed && (parsed.summary || Array.isArray(parsed.devices))) {
          return dpvNormalize(parsed, leakOn);
        }
      }
      return dpvFetchVerifyStrict(leakOn);
    }).catch(function (actErr) {
      if (resync) {
        return dpvFetchVerifyStrict(leakOn).then(function (norm) {
          DPV_STATE.lastData = norm;
          throw actErr;
        }, function () {
          throw actErr;
        });
      }
      return dpvFetchVerifyStrict(leakOn);
    });
  }
  if (resync) {
    return Promise.reject(new Error('当前环境未提供重下发动作通道'));
  }
  return dpvFetchVerifyStrict(leakOn);
}

function dpvLoadSilent() {
  return dpvFetchVerifyStrict(DPV_STATE.leakEnabled).then(function (norm) {
    DPV_STATE.lastData = norm;
    dpvRefreshRenderedViews();
    return norm;
  }).catch(function () {
    if (!DPV_STATE.lastData) {
      DPV_STATE.lastData = dpvDefaultData(DPV_STATE.leakEnabled);
    }
    dpvRefreshRenderedViews();
    return DPV_STATE.lastData;
  });
}

function dpvDiagRowHtml() {
  var d = dpvNormalize(DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var s = d.summary;
  var maskSummary = d.netd_low16_protected
    ? '正交掩码 ' + dpvEsc(d.fwmark_mask)
    : '低 16 位 netd 掩码冲突 (' + dpvEsc(d.mark_layout) + ')';
  var sub = d.sampled_ok
    ? '受控 ' + dpvInt(s.controlled_devices) + ' 台 · 命中 ' + dpvInt(s.hitting_count) + ' 台 · ' + maskSummary
    : '待采样核验 · 请点击立即核验读取内核计数';
  var icoTone = !d.sampled_ok
    ? 'gray'
    : (s.bypass_or_missing_count > 0 || !d.netd_low16_protected ? 'orange' : 'blue');
  return '<button type="button" class="row" data-dpv-act="sheet" data-dpv-diag-row="1">' +
    gi(icoTone, 'gauge') +
    '<span class="tx"><div class="t">数据面命中逐设备计数器</div><div class="s">' + sub + '</div></span>' +
    '<span class="hint-a">查看明细</span></button>';
}

function dpvRenderCardHtml(data, isBusy) {
  var d = dpvNormalize(data || DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var sum = d.summary;
  var bpf = d.bpf_maps;
  var off = d.offload_guard;
  var sampled = Boolean(d.sampled_ok);
  var markLayout = d.mark_layout;
  var low16Protected = Boolean(d.netd_low16_protected);

  var offloadHealthy = sampled && (off.tether_offload_disabled || off.slowpath_active) &&
    off.hwnat !== 'detected_no_knob' && off.hwnat !== 'failed';
  var hwnatLabel = !sampled
    ? '系统加速接管状态：待检验'
    : (off.hwnat === 'none' || off.hwnat === 'disabled' || off.hwnat === 'suppressed'
        ? '系统硬件加速已受控（不绕过限速）'
        : '硬件加速状态：' + off.hwnat);

  var fwmarkBadgeCls = !sampled ? '' : (low16Protected ? 'dpv-chip-ok' : 'dpv-chip-warn');
  var fwmarkBadgeText = !sampled
    ? '系统网络标记隔离（待检验）'
    : (low16Protected
        ? '与系统路由互不冲突 (' + dpvEsc(d.fwmark_mask) + ')'
        : '存在标记冲突 (' + dpvEsc(markLayout) + ')');

  var hasAnomaly = sampled && sum.bypass_or_missing_count > 0;
  var repairBtnCls = hasAnomaly ? 'dpv-btn dpv-btn-warn press' : 'dpv-btn dpv-btn-secondary press';
  var runLabel = isBusy && !DPV_STATE.resyncing ? '正在检验限速通道…' : '立即重新检验';
  var repairLabel = isBusy && DPV_STATE.resyncing ? '正在修复限速规则…' : '一键修复限速';

  return (
    '<div class="dpv-inline-wrap" id="dpv-settings-card" aria-label="限速真实生效检验">' +
    '  <div class="dpv-plain-intro">' +
    '    部分手机开启自带热点硬件加速后，网页里显示的限速可能会被系统底层直接绕过（俗称“假限速”）。这里通过核对每台限速设备的真实过包流量，帮您确认限速 100% 生效。' +
    (sampled ? ' <span class="note">（热点接口 ' + dpvEsc(d.iface || 'wlan2') + ' · 检验时间 ' + dpvEsc(d.checked_at_str) + '）</span>' : '') +
    '  </div>' +
    '  <div class="dpv-kpi-grid">' +
    '    <div class="dpv-kpi-cell">' +
    '      <span class="dpv-kpi-num">' + (sampled ? dpvInt(sum.controlled_devices) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">已设限速设备</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (sampled ? 'is-hit' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (sampled ? dpvInt(sum.hitting_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">正在生效</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (sampled ? 'is-idle' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (sampled ? dpvInt(sum.idle_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">空闲待命</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (hasAnomaly ? 'is-alert' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (sampled ? dpvInt(sum.bypass_or_missing_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">绕过/失效异常</span>' +
    '    </div>' +
    '  </div>' +
    '  <p class="dpv-verdict-line">' + dpvEsc(sum.headline) + '</p>' +
    '  <div class="dpv-actions">' +
    '    <button type="button" class="dpv-btn dpv-btn-primary press" data-dpv-act="run"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.runVerify +
    '<span>' + runLabel + '</span>' +
    '    </button>' +
    '    <button type="button" class="' + repairBtnCls + '" data-dpv-act="repair"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.repair +
    '<span>' + repairLabel + '</span>' +
    '    </button>' +
    '    <button type="button" class="dpv-btn dpv-btn-secondary press" data-dpv-act="sheet">' +
    DPV_ICONS.counters +
    '<span>查看每台设备详情</span>' +
    '    </button>' +
    '  </div>' +
    '  <details class="v6-adv-fold dpv-tech-fold">' +
    '    <summary><span>底层内核队列与硬件加速技术指标</span><span class="v6-adv-r"><span>开发者详情</span></span></summary>' +
    '    <div class="v6-adv-body">' +
    '      <div class="dpv-tag-strip">' +
    '        <span class="dpv-chip ' + (sampled ? 'dpv-chip-primary' : '') + '">' + dpvEsc(d.engine_label) + '</span>' +
    '        <span class="dpv-chip ' + fwmarkBadgeCls + '">' + DPV_ICONS.fwmark + '<span>' + fwmarkBadgeText + '</span></span>' +
    '        <span class="dpv-chip ' + (!sampled ? '' : (offloadHealthy ? 'dpv-chip-ok' : 'dpv-chip-warn')) + '">' + dpvEsc(hwnatLabel) + '</span>' +
    '      </div>' +
    '      <div class="dpv-bpf-grid" role="list" aria-label="底层模块状态">' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">下行标记挂点 (clsact)</span>' +
    '          <span class="dpv-bpf-val ' + (!sampled ? 'is-muted' : (bpf.clsact_attached ? 'is-ok' : 'is-warn')) + '">' +
    (!sampled ? '待采样' : (bpf.clsact_attached ? '正常 · ' + dpvInt(bpf.mac_mark_entries) + ' 项' : '待挂载')) +
    '          </span>' +
    '        </div>' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">上行重定向队列 (ifb0)</span>' +
    '          <span class="dpv-bpf-val ' + (!sampled ? 'is-muted' : (bpf.ifb_redirect_prio2 ? 'is-ok' : 'is-warn')) + '">' +
    (!sampled ? '待采样' : (bpf.ifb_redirect_prio2 ? '就绪 · ' + dpvInt(bpf.ip_mark_entries) + ' 项' : dpvInt(bpf.ip_mark_entries) + ' 项')) +
    '          </span>' +
    '        </div>' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">防加速绕过开关 (tether_limit)</span>' +
    '          <span class="dpv-bpf-val ' + (!sampled ? 'is-muted' : (bpf.tether_limit_zeroed ? 'is-ok' : 'is-warn')) + '">' +
    (!sampled ? '待采样' : (bpf.tether_limit_zeroed ? '已压制防绕过' : '存在绕过风险')) +
    '          </span>' +
    '        </div>' +
    '      </div>' +
    '    </div>' +
    '  </details>' +
    '</div>'
  );
}

function dpvRenderSettingsSlotHtml() {
  return '<div id="dpv-settings-mount" data-dpv-mount="1">' + dpvRenderCardHtml(DPV_STATE.lastData, DPV_STATE.loading) + '</div>';
}

function dpvRenderDeviceItemHtml(dev, iface) {
  var subHtml = '';
  if (dev.app_classes && dev.app_classes.length > 0) {
    var rows = '';
    for (var i = 0; i < dev.app_classes.length; i++) {
      var sub = dev.app_classes[i];
      var dotCls = sub.verdict === 'missing_class' ? 'is-err' : (sub.verdict === 'hit' ? 'is-hit' : 'is-idle');
      var obsTxt = dpvObsRate(sub.observed_kbps);
      rows +=
        '<div class="dpv-subapp-row">' +
        '  <div class="dpv-subapp-main">' +
        '    <span class="dpv-subapp-dot ' + dotCls + '"></span>' +
        '    <span class="dpv-subapp-name">' + dpvEsc(sub.app_label) + '</span>' +
        '    <span class="dpv-mono-tag">' + dpvEsc(sub.class_id) + ' ← ' + dpvEsc(sub.parent_class_id) + '</span>' +
        (obsTxt ? '<span class="dpv-tier-tag">实测 ' + dpvEsc(obsTxt) + '</span>' : '') +
        '  </div>' +
        '  <div class="dpv-subapp-metrics">' +
        '    <span>限速 ' + dpvEsc(dpvRateMbps(sub.down_limit_mbps)) + '</span>' +
        '    <span>累计 ' + dpvEsc(dpvBytes(sub.sent_bytes)) + ' <em>(' + dpvEsc(dpvDeltaBytes(sub.delta_bytes)) + ')</em></span>' +
        '    <span>整形 ' + dpvInt(sub.overlimits) + ' / 丢包 ' + dpvInt(sub.drops) + '</span>' +
        '  </div>' +
        '</div>';
    }
    var parentNote = (dev.class_id && dev.class_id !== '—')
      ? '归位挂载于设备类 ' + dpvEsc(dev.class_id) + ' 下'
      : '挂载于根类 1:1 下';
    subHtml =
      '<div class="dpv-subapps">' +
      '  <div class="dpv-subapps-hd">单应用 HTB 子类命中明细（' + parentNote + '）</div>' +
      rows +
      '</div>';
  }

  var downObs = dpvObsRate(dev.down_observed_kbps);
  var upObs = dpvObsRate(dev.up_observed_kbps);

  return (
    '<article class="dpv-dev-card">' +
    '  <div class="dpv-dev-top">' +
    '    <div>' +
    '      <div class="dpv-dev-name">' + dpvEsc(dev.name) + (dev.online ? '' : ' · 离线') + '</div>' +
    '      <div class="dpv-dev-addr">' + dpvEsc(dev.mac) + ' · ' + dpvEsc(dev.ip) + '</div>' +
    '    </div>' +
    '    <span class="dpv-status-badge ' + dev.status_cls + '">' + dpvEsc(dev.status_label) + '</span>' +
    '  </div>' +
    '  <div class="dpv-dev-meta">' +
    (dev.class_id && dev.class_id !== '—' ? '<span class="dpv-mono-tag">HTB ' + dpvEsc(dev.class_id) + ' (mid=' + dpvInt(dev.mark_id) + ')</span>' : '') +
    (dev.mark_hex && dev.mark_hex !== '—' ? '<span class="dpv-mono-tag">Mark ' + dpvEsc(dev.mark_hex) + '</span>' : '') +
    '    <span class="dpv-mono-tag">限速 ↓' + dpvEsc(dpvRateMbps(dev.down_limit_mbps)) + ' / ↑' + dpvEsc(dpvRateMbps(dev.up_limit_mbps)) + '</span>' +
    (dev.app_qos ? '<span class="dpv-mono-tag is-quic">三档 fq_codel QoS</span>' : '') +
    (dev.blacklisted ? '<span class="dpv-mono-tag">双栈 MAC 黑名单</span>' : '') +
    '  </div>' +
    '  <div class="dpv-counter-pair">' +
    '    <div class="dpv-counter-box">' +
    '      <div class="dpv-counter-label">下行 HTB 队列 (' + dpvEsc(iface || 'wlan2') + ' egress' + (downObs ? ' · ' + dpvEsc(downObs) : '') + ')</div>' +
    '      <div class="dpv-counter-bytes">' +
    '        <strong>' + dpvEsc(dpvBytes(dev.down_sent_bytes)) + '</strong>' +
    '        <span class="dpv-delta">' + dpvEsc(dpvDeltaBytes(dev.down_delta_bytes)) + '</span>' +
    '      </div>' +
    '      <div class="dpv-counter-sub">overlimits ' + dpvInt(dev.down_overlimits) + ' · drops ' + dpvInt(dev.down_drops) + (dev.down_delta_drops > 0 ? ' (+' + dpvInt(dev.down_delta_drops) + ')' : '') + '</div>' +
    '    </div>' +
    '    <div class="dpv-counter-box">' +
    '      <div class="dpv-counter-label">上行 HTB 队列 (ifb0 / clsact' + (upObs ? ' · ' + dpvEsc(upObs) : '') + ')</div>' +
    '      <div class="dpv-counter-bytes">' +
    '        <strong>' + dpvEsc(dpvBytes(dev.up_sent_bytes)) + '</strong>' +
    '        <span class="dpv-delta">' + dpvEsc(dpvDeltaBytes(dev.up_delta_bytes)) + '</span>' +
    '      </div>' +
    '      <div class="dpv-counter-sub">overlimits ' + dpvInt(dev.up_overlimits) + ' · drops ' + dpvInt(dev.up_drops) + (dev.up_delta_drops > 0 ? ' (+' + dpvInt(dev.up_delta_drops) + ')' : '') + '</div>' +
    '    </div>' +
    '  </div>' +
    (dev.reason ? '<div class="dpv-dev-reason">' + dpvEsc(dev.reason) + '</div>' : '') +
    (dev.fix ? '<div class="dpv-dev-fix">修复建议：' + dpvEsc(dev.fix) + '</div>' : '') +
    subHtml +
    '</article>'
  );
}

function dpvIsLeakToggleOn(normData, explicitArg) {
  var glk = normData && normData.goroutineleak;
  if (normData && normData.sampled_ok && glk && glk.sampled) {
    if (glk.trigger === 'diag_flag_file' || !DPV_STATE.leakUserToggled) {
      return true;
    }
  }
  if (explicitArg && glk && glk.sampled) {
    return true;
  }
  return Boolean(DPV_STATE.leakEnabled);
}

function dpvRenderSheetContentHtml(data, isBusy) {
  var explicitArg = Boolean(data && data !== DPV_STATE.lastData);
  var d = dpvNormalize(data || DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var sampled = Boolean(d.sampled_ok);
  var bpf = d.bpf_maps;
  var sum = d.summary;
  var glk = d.goroutineleak;
  var leakOn = dpvIsLeakToggleOn(d, explicitArg);

  var devListHtml = '';
  if (!sampled) {
    devListHtml =
      '<div class="dpv-empty">' +
      '待采样核验：请点击上方「刷新实时增量」或「一键重下发修复」读取内核 RTNetlink HTB 类与正交 Fwmark 实时计数器。' +
      '</div>';
  } else if (d.devices.length === 0) {
    devListHtml =
      '<div class="dpv-empty">' +
      '当前暂无处于限速、应用感知 QoS 或黑名单策略下的受控客户端。为任意热点设备开启限速后，此处将实时展示内核 RTNetlink HTB 类与正交 Fwmark 命中计数器。' +
      '</div>';
  } else {
    for (var i = 0; i < d.devices.length; i++) {
      devListHtml += dpvRenderDeviceItemHtml(d.devices[i], d.iface);
    }
  }

  var leakErr = glk.status === 'error';
  var leakUnsupported = (glk.sampled && !glk.supported) || glk.status === 'unsupported';
  var leakBadgeCls = !leakOn
    ? 'dpv-pill-info'
    : (leakErr || leakUnsupported)
      ? 'dpv-pill-warn'
      : (glk.leaked_count > 0 || glk.status === 'leak_detected')
        ? 'dpv-pill-danger'
        : glk.sampled
          ? 'dpv-pill-ok'
          : 'dpv-pill-info';
  var leakBadgeTxt = !leakOn
    ? '按需待命'
    : leakErr
      ? '采样异常'
      : leakUnsupported
        ? '运行时不支持'
        : (glk.leaked_count > 0 || glk.status === 'leak_detected')
          ? '检出泄漏 ' + dpvInt(glk.leaked_count)
          : glk.sampled
            ? '0 协程泄漏'
            : '待采样';

  var stacksHtml = '';
  if (leakOn && glk.preview_stacks && glk.preview_stacks.length > 0) {
    stacksHtml = '<pre class="dpv-leak-stacks">' + dpvEsc(glk.preview_stacks.join('\n\n')) + '</pre>';
  }

  var leakDescText = (leakOn && glk.sampled)
    ? ((leakErr || leakUnsupported)
        ? '总协程 ' + dpvInt(glk.total_goroutines) + ' 个 · 耗时 ' + dpvInt(glk.duration_ms) + ' ms — ' + dpvEsc(glk.message)
        : '总协程 ' + dpvInt(glk.total_goroutines) + ' 个 · 泄漏 ' + dpvInt(glk.leaked_count) + ' 个 · 耗时 ' + dpvInt(glk.duration_ms) + ' ms — ' + dpvEsc(glk.message))
    : dpvEsc(glk.message);

  var pipeMaskLine = d.netd_low16_protected
    ? '设备标记 <code>0x00800000 | (mid &lt;&lt; 16)</code>（如 mid=1 → <code>0x00810000</code>，mid=5 → <code>0x00850000</code>），掩码 <code>' + dpvEsc(d.fwmark_mask) + '</code>，低 16 位 <code>0x0000ffff</code> 完整保留给 Android netd 策略路由'
    : '检测到低 16 位 netd 掩码冲突 (' + dpvEsc(d.mark_layout) + ')，建议点击「一键重下发修复」恢复 <code>0xffff0000</code> 正交掩码保护';

  var hasAnomaly = sampled && sum.bypass_or_missing_count > 0;
  var sheetRepairCls = 'dpv-btn dpv-btn-compact press' + (hasAnomaly ? ' dpv-btn-warn' : '');

  return (
    '<div class="dpv-sheet-body" id="dpv-sheet-root">' +
    '  <div class="dpv-pipe-banner">' +
    '    <div><strong>正交位域契约：</strong>' + pipeMaskLine + '</div>' +
    '    <div><strong>clsact / GRO 管道：</strong>eBPF 返回 <code>TC_ACT_UNSPEC (-1)</code>（prio 1 着色 → prio 2 ifb0/police 128KB 突发桶）· ' + (d.ipv6_quic_controlled ? '双栈 IPv4/IPv6 QUIC (UDP 443) 已闭环管控' : '按需启用双栈 QUIC 管控') + '</div>' +
    '    <div><strong>采集引擎状态：</strong>' + (sampled ? dpvEsc(d.engine_label) + ' · BPF mac_mark ' + dpvInt(bpf.mac_mark_entries) + ' 项 / ip_mark ' + dpvInt(bpf.ip_mark_entries) + ' 项' : '待采样核验 · 请点击刷新实时增量读取内核计数') + '</div>' +
    '  </div>' +
    '  <div class="dpv-leak-box">' +
    '    <div class="dpv-leak-row">' +
    '      <div class="dpv-leak-info">' +
    '        <div class="dpv-leak-title">' +
    DPV_ICONS.leakScan +
    '<span>Go 1.27 goroutineleak 按需诊断</span>' +
    '<span class="dpv-pill ' + leakBadgeCls + '">' + dpvEsc(leakBadgeTxt) + '</span>' +
    '        </div>' +
    '        <div class="dpv-leak-desc">' +
    leakDescText +
    '        </div>' +
    '      </div>' +
    '      <button type="button" role="switch" aria-checked="' + (leakOn ? 'true' : 'false') + '" class="dpv-switch ' + (leakOn ? 'is-on' : '') + '" data-dpv-act="toggle-leak" aria-label="切换 goroutineleak 按需诊断">' +
    '        <span class="dpv-switch-knob"></span>' +
    '      </button>' +
    '    </div>' +
    stacksHtml +
    '  </div>' +
    '  <div class="dpv-sheet-toolbar">' +
    '    <span class="dpv-sheet-count">受控客户端明细（' + (sampled ? '共 ' + dpvInt(d.devices.length) + ' 台 · 单应用子类 ' + dpvInt(sum.app_classes_total) + ' 个' : '待采样核验') + '）</span>' +
    '    <div class="dpv-sheet-actions">' +
    '      <button type="button" class="' + sheetRepairCls + '" data-dpv-act="repair"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.repair +
    '<span>' + (isBusy && DPV_STATE.resyncing ? '修复中…' : '一键重下发修复') + '</span>' +
    '      </button>' +
    '      <button type="button" class="dpv-btn dpv-btn-compact press" data-dpv-act="run"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.runVerify +
    '<span>' + (isBusy && !DPV_STATE.resyncing ? '采样中…' : '刷新实时增量') + '</span>' +
    '      </button>' +
    '    </div>' +
    '  </div>' +
    '  <div class="dpv-dev-list">' +
    devListHtml +
    '  </div>' +
    '</div>'
  );
}

function dpvRenderSelfCheckSummaryHtml(data) {
  var d = dpvNormalize(data || DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var sum = d.summary;
  var sampled = Boolean(d.sampled_ok);
  var maskTxt = d.netd_low16_protected
    ? '正交掩码 ' + dpvEsc(d.fwmark_mask)
    : '低 16 位 netd 掩码冲突 (' + dpvEsc(d.mark_layout) + ')';
  return (
    '<div class="dpv-selfcheck-bar" data-dpv-selfcheck="1">' +
    '  <div class="dpv-selfcheck-left">' +
    DPV_ICONS.dataplane +
    '    <div>' +
    '      <div class="dpv-selfcheck-title">' + (sampled
      ? '内核限速队列真机命中：' + dpvInt(sum.hitting_count) + ' / ' + dpvInt(sum.controlled_devices) + ' 台命中'
      : '内核限速队列真机命中：待采样核验') + '</div>' +
    '      <div class="dpv-selfcheck-sub">' + (sampled
      ? maskTxt + ' · ' + (d.bpf_maps.clsact_attached ? 'BPF mac/ip_mark 就绪' : 'BPF 待挂载') + ' · 原生 RTNetlink 采样'
      : '请点击核验明细读取内核实时计数器') + '</div>' +
    '    </div>' +
    '  </div>' +
    '  <button type="button" class="dpv-btn dpv-btn-compact press" data-dpv-act="sheet">核验明细</button>' +
    '</div>'
  );
}

function dpvRefreshRenderedViews() {
  if (typeof document === 'undefined') return;
  var mountEl = document.getElementById('dpv-settings-mount') || document.querySelector('[data-dpv-mount]');
  if (mountEl) {
    var openTech = !!mountEl.querySelector('.dpv-tech-fold[open]');
    mountEl.innerHTML = dpvRenderCardHtml(DPV_STATE.lastData, DPV_STATE.loading);
    if (openTech) {
      var tf = mountEl.querySelector('.dpv-tech-fold');
      if (tf) tf.open = true;
    }
    var scardEl = document.querySelector('.scard[data-foldkey="scard-dpv"]');
    if (scardEl && DPV_STATE.lastData && DPV_STATE.lastData.sampled_ok) {
      var dn = dpvNormalize(DPV_STATE.lastData, DPV_STATE.leakEnabled);
      var subEl = scardEl.querySelector('.scard-h small');
      var bdgEl = document.getElementById('dpv-scard-badge');
      var hasErr2 = dn.summary.bypass_or_missing_count > 0;
      if (subEl) {
        subEl.textContent = hasErr2
          ? ('发现 ' + dpvInt(dn.summary.bypass_or_missing_count) + ' 台设备限速可能被绕过 · 点开一键修复')
          : ('已设限速 ' + dpvInt(dn.summary.controlled_devices) + ' 台 · 正在生效 ' + dpvInt(dn.summary.hitting_count) + ' 台 · 未被硬件加速绕过');
      }
      if (bdgEl) {
        bdgEl.className = 'badge ' + (hasErr2 ? 'b-warn' : (dn.summary.hitting_count > 0 ? 'b-ok' : 'b-acc'));
        bdgEl.textContent = hasErr2 ? '待修复' : (dn.summary.hitting_count > 0 ? '真实生效' : '待命就绪');
      }
    }
  }
  var sheetRoot = document.getElementById('dpv-sheet-root');
  if (sheetRoot && sheetRoot.parentNode) {
    var html = dpvRenderSheetContentHtml(DPV_STATE.lastData, DPV_STATE.loading);
    if (typeof morphOuter === 'function') {
      morphOuter(sheetRoot, html);
    } else {
      sheetRoot.outerHTML = html;
    }
  }
  var diagRows = document.querySelectorAll('[data-dpv-diag-row]');
  for (var j = 0; j < diagRows.length; j++) {
    var rowHtml = dpvDiagRowHtml();
    if (typeof morphOuter === 'function') {
      morphOuter(diagRows[j], rowHtml);
    } else {
      diagRows[j].outerHTML = rowHtml;
    }
  }
  var scBars = document.querySelectorAll('[data-dpv-selfcheck]');
  for (var i = 0; i < scBars.length; i++) {
    var barHtml = dpvRenderSelfCheckSummaryHtml(DPV_STATE.lastData);
    if (typeof morphOuter === 'function') {
      morphOuter(scBars[i], barHtml);
    } else {
      scBars[i].outerHTML = barHtml;
    }
  }
}

function dpvOpenSheet() {
  var title = '内核限速命中逐设备计数器';
  var contentHtml = dpvRenderSheetContentHtml(DPV_STATE.lastData, DPV_STATE.loading);
  DPV_STATE.sheetOpen = true;
  if (typeof sheet === 'function' && typeof document !== 'undefined' && document.getElementById('sheet')) {
    sheet(
      '<h3>' + dpvEsc(title) + '</h3>' +
      '<div class="sub">实时读取内核 RTNetlink HTB 类字节增量、超限整形与正交 Fwmark 状态</div>' +
      contentHtml +
      '<button type="button" class="btn sec wide press" data-close style="margin-top:12px">关闭</button>',
      { tall: true, kind: 'dpv', onClose: function () { DPV_STATE.sheetOpen = false; } }
    );
    return;
  }
}

function dpvTriggerVerify(runAction, resync, isManualToggle) {
  var mySeq = ++DPV_STATE.seq;
  var doResync = Boolean(runAction && resync);
  DPV_STATE.loading = true;
  DPV_STATE.resyncing = doResync;
  dpvRefreshRenderedViews();

  var p = runAction
    ? dpvRunVerifyAction(DPV_STATE.leakEnabled, doResync)
    : dpvFetchVerifyStrict(DPV_STATE.leakEnabled);

  return p.then(function (norm) {
    if (mySeq === DPV_STATE.seq) {
      DPV_STATE.lastData = norm;
      DPV_STATE.loading = false;
      DPV_STATE.resyncing = false;
      dpvRefreshRenderedViews();
      if (runAction && typeof toast === 'function') {
        if (doResync) {
          toast(
            norm.summary.bypass_or_missing_count > 0
              ? '已执行重下发修复，仍有 ' + dpvInt(norm.summary.bypass_or_missing_count) + ' 台设备异常，请检查内核状态'
              : '一键重下发修复完成：' + dpvInt(norm.summary.hitting_count) + '/' + dpvInt(norm.summary.controlled_devices) + ' 台受控设备命中内核队列',
            norm.summary.bypass_or_missing_count > 0 ? 'warn' : 'ok'
          );
        } else {
          toast(
            '核验完成：' + dpvInt(norm.summary.hitting_count) + '/' + dpvInt(norm.summary.controlled_devices) + ' 台受控设备命中内核队列',
            norm.summary.bypass_or_missing_count > 0 ? 'warn' : 'ok'
          );
        }
      } else if (
        isManualToggle &&
        !DPV_STATE.leakEnabled &&
        norm.goroutineleak &&
        norm.goroutineleak.sampled &&
        norm.goroutineleak.trigger === 'diag_flag_file' &&
        typeof toast === 'function'
      ) {
        toast('诊断标志文件 diag_goroutineleak.enabled 生效中，移除该文件后可关闭常驻采样', 'warn');
      }
    }
    return norm;
  }).catch(function (err) {
    if (mySeq === DPV_STATE.seq) {
      DPV_STATE.loading = false;
      DPV_STATE.resyncing = false;
      if (!DPV_STATE.lastData) {
        DPV_STATE.lastData = dpvDefaultData(DPV_STATE.leakEnabled);
      }
      dpvRefreshRenderedViews();
      if ((runAction || isManualToggle) && typeof toast === 'function') {
        var msg = typeof errText === 'function' ? errText(err) : String((err && err.message) || err || '请求失败');
        toast(msg, 'err');
      }
    }
    return DPV_STATE.lastData || dpvDefaultData(DPV_STATE.leakEnabled);
  });
}

function dpvBindGlobalDelegate() {
  if (typeof document === 'undefined' || document.__dpvBound) return;
  document.__dpvBound = true;
  document.addEventListener('click', function (ev) {
    var t = ev.target;
    if (!t || typeof t.closest !== 'function') return;
    var btn = t.closest('[data-dpv-act]');
    if (!btn) return;
    var act = btn.getAttribute('data-dpv-act');
    if (act === 'run') {
      ev.preventDefault();
      dpvTriggerVerify(true, false);
    } else if (act === 'repair') {
      ev.preventDefault();
      dpvTriggerVerify(true, true);
    } else if (act === 'sheet') {
      ev.preventDefault();
      if (!DPV_STATE.lastData || !DPV_STATE.lastData.sampled_ok) {
        dpvTriggerVerify(false, false).then(function () { dpvOpenSheet(); });
      } else {
        dpvOpenSheet();
      }
    } else if (act === 'toggle-leak') {
      ev.preventDefault();
      var curOn = dpvIsLeakToggleOn(DPV_STATE.lastData, false);
      DPV_STATE.leakUserToggled = true;
      DPV_STATE.leakEnabled = !curOn;
      dpvTriggerVerify(false, false, true);
    }
  });
}

dpvBindGlobalDelegate();
if (typeof window !== 'undefined') {
  window.HNCDataPlaneVerify = {
    refresh: dpvTriggerVerify,
    repair: function () { return dpvTriggerVerify(true, true); },
    openVerifySheet: dpvOpenSheet,
    normalize: dpvNormalize,
    formatMarkHex: dpvFormatMarkHex,
    hasBadToken: dpvHasBadToken,
    renderCardHtml: dpvRenderCardHtml,
    renderSheetHtml: dpvRenderSheetContentHtml,
    renderSelfCheckSummaryHtml: dpvRenderSelfCheckSummaryHtml
  };
}
