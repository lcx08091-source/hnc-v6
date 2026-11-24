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
function mmBuildMergedList(m) {
  if (!m) return [];
  if (Array.isArray(m.merged_list) && m.merged_list.length) {
    return m.merged_list.map(function (x) {
      var nm = String((x && (x.new_mac || x.to_mac || x.mac)) || '').toLowerCase();
      var om = String((x && (x.old_mac || x.from_mac)) || '').toLowerCase();
      var d = nm ? devBy(nm) : null;
      return {
        new_mac: nm,
        old_mac: om,
        new_name: (d && d.name) || (x && x.new_name) || nm,
        old_name: (x && x.old_name) || (d && d.mergedFromName) || om,
        auto: !!(x && x.auto),
        score: num(x && x.score),
        ts: num(x && x.ts)
      };
    }).filter(function (x) { return isMac(x.new_mac) && isMac(x.old_mac); });
  }
  var al = m.aliases && typeof m.aliases === 'object' ? m.aliases : {};
  return Object.keys(al).sort().map(function (o) {
    var oldM = String(o || '').toLowerCase(), newM = String(al[o] || '').toLowerCase();
    var d = newM ? devBy(newM) : null, od = oldM ? devBy(oldM) : null;
    return {
      new_mac: newM,
      old_mac: oldM,
      new_name: (d && d.name) || newM,
      old_name: (d && d.mergedFrom === oldM && d.mergedFromName) || (od && od.name) || oldM,
      auto: !!(d && d.autoInhFrom === oldM),
      score: d && d.autoInhFrom === oldM ? num(d.autoInhScore) : 0,
      ts: 0
    };
  }).filter(function (x) { return isMac(x.new_mac) && isMac(x.old_mac); });
}
function mmFindMerged(newMac, oldMac) {
  newMac = String(newMac || '').toLowerCase();
  oldMac = String(oldMac || '').toLowerCase();
  var list = mmBuildMergedList(S.mm);
  for (var i = 0; i < list.length; i++) {
    if (newMac && list[i].new_mac === newMac && (!oldMac || list[i].old_mac === oldMac)) return list[i];
    if (!newMac && oldMac && list[i].old_mac === oldMac) return list[i];
  }
  var d = newMac ? devBy(newMac) : null;
  if (d && (oldMac || d.mergedFrom)) {
    var om = oldMac || d.mergedFrom;
    return {
      new_mac: d.mac,
      old_mac: om,
      new_name: d.name || d.mac,
      old_name: d.mergedFromName || om,
      auto: d.autoInhFrom === om,
      score: num(d.autoInhScore)
    };
  }
  return (isMac(newMac) && isMac(oldMac)) ? { new_mac: newMac, old_mac: oldMac, new_name: newMac, old_name: oldMac } : null;
}
function unmergeSheet(newMac, oldMac, oldName, fetched) {
  newMac = String(newMac || '').toLowerCase();
  oldMac = String(oldMac || '').toLowerCase();
  var rec = mmFindMerged(newMac, oldMac);
  if (!rec && !fetched) {
    loadMacMerge().then(function () { unmergeSheet(newMac, oldMac, oldName, true); });
    return;
  }
  if (!rec) {
    sheet('<h3>拆分恢复独立设备</h3><div class="empty">该设备当前没有可拆分的合并记录（可能已拆分恢复）</div><button class="btn sec wide press" data-close>关闭</button>', { kind: 'unmerge' });
    return;
  }
  var d = devBy(rec.new_mac);
  var nn = (d && d.name) || rec.new_name || rec.new_mac;
  var on = oldName || rec.old_name || rec.old_mac;
  sheet('<h3>拆分恢复独立设备</h3><div class="sub">两台同型号设备（双胞胎机型）被误判为换随机 MAC 合并时，可一键拆分恢复为两台独立设备</div>' +
    '<div class="mm-cmp"><div><div class="k">拆出独立设备</div><div class="n">' + esc(on) + '</div><div class="m">' + esc(rec.old_mac) + '</div><div class="k">' + (rec.auto ? '曾自动无感继承' : '曾手动合并') + '</div></div>' + ico('isolate') +
    '<div><div class="k">当前在线设备</div><div class="n">' + esc(nn) + '</div><div class="m">' + esc(rec.new_mac) + '</div><div class="k">' + (d && d.online ? '当前在线' : '已记录') + '</div></div></div>' +
    '<div class="note" style="margin:6px 0 12px">拆分后将解除两者的地址别名绑定，各自恢复独立的设备条目与流量统计，并自动写入<b>双胞胎互斥保护名单</b>，后台以后绝不再将这两台设备自动合并。</div>' +
    '<div class="btns"><button type="button" class="btn sec press" data-close>取消</button><button type="button" class="btn pri press" id="mm-unmerge-ok">确认拆分恢复</button></div>', { kind: 'unmerge' });
  $('#mm-unmerge-ok').onclick = function () { doUnmerge(rec.new_mac, rec.old_mac, on); };
}
function doUnmerge(to, from, oldName) {
  to = String(to || '').toLowerCase();
  from = String(from || '').toLowerCase();
  var lockKey = to || from;
  if (lockKey && S.busy[lockKey]) { toast('这台设备还有操作在进行', 'warn'); return Promise.resolve(false); }
  var p = {};
  if (to) { p.mac = to; p.to_mac = to; p.new_mac = to; }
  if (from) { p.from_mac = from; p.old_mac = from; if (!p.mac) p.mac = from; }
  if (lockKey) setBusy(lockKey, true);
  var b = $('#mm-unmerge-ok'); if (b) b.disabled = true;
  return api.action('device_unmerge', p, { timeout: 30000, maxTime: 28 }).then(function () {
    if ($('#sheet') && $('#sheet').dataset.kind === 'unmerge') closeSheet(0);
    toast('已拆分恢复独立设备' + (oldName ? ' · 「' + oldName + '」已独立并锁定双胞胎互斥' : ' · 已锁定双胞胎互斥不再误合并'));
    return true;
  }, function (e) {
    toast(errText(e), 'err');
    if (b) b.disabled = false;
    return false;
  }).then(function (ok) {
    if (lockKey) setBusy(lockKey, false);
    return mergeAfter().then(function () { return ok; });
  });
}
function mergeSettingsHtml() {
  var m = S.mm;
  if (!m) return sItem(['gray', 'merge'], '设备合并建议', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var sg = m.suggestions || [], mList = mmBuildMergedList(m), mutexCnt = Math.round(num(m.mutex_apart_count, 0));
  var body = (sg.length ? sg.map(function (s) {
    var d = devBy(s.new_mac), nn = (d && d.name) || s.new_name || s.new_mac;
    return '<div class="mm-row"><span class="t">「' + esc(nn) + '」可能是「' + esc(s.old_name || s.old_mac) + '」</span><button class="linkish" data-mm-open="' + esc(s.new_mac + '|' + s.old_mac) + '">查看</button><span class="s">' + mergeScoreTxt(s) + (s.new_online ? ' · 新 MAC 在线' : '') + ((s.reasons || []).length ? ' · ' + esc(s.reasons.slice(0, 2).join(' · ')) : '') + '</span></div>';
  }).join('') : '<div class="note">暂时没有疑似换了 MAC 的设备</div>') +
    '<div class="mm-sub">已合并的旧 MAC（' + mList.length + '）</div>' + (mList.length ? mList.map(function (it) {
      return '<div class="mm-row"><span class="t mono" style="font-size:12px">' + esc(it.old_mac) + ' → ' + esc(it.new_mac) + '</span><span></span><span class="s">原「' + esc(it.old_name || it.old_mac) + '」并入「' + esc(it.new_name || it.new_mac) + '」' + (it.auto ? '（自动无感继承）' : '') + ' · 旧 MAC 历史流量计入新 MAC</span>' +
        '<div style="grid-column:1/-1;margin-top:6px"><button type="button" class="btn sec press" data-mm-unmerge="' + esc(it.new_mac + '|' + it.old_mac + '|' + (it.old_name || '')) + '">' + ico('isolate') + '<span>拆分恢复独立设备</span></button></div></div>';
    }).join('') : '<div class="note">还没有合并过</div>') +
    (mutexCnt > 0 ? '<div class="note" style="margin-top:8px;color:var(--badge-ok)">双胞胎互斥锁定：已保护 ' + mutexCnt + ' 对同型号独立设备，同时在线或手动拆分后永不误合并。</div>' : '') +
    '<div class="note" style="margin-top:8px">手机的「隐私 Wi-Fi 地址」（随机 MAC）会不定期更换。HNC 按主机名、DHCP 指纹、TLS 指纹、常用应用和上下线时间打分，' + num(m.min_score, 40) + ' 分以上给出建议，' + num(m.alert_score, 60) + ' 分以上发提醒；两台设备若曾同时在线则自动建立双胞胎互斥锁。</div>';
  var sumParts = [];
  if (sg.length) sumParts.push(sg.length + ' 条待确认');
  else sumParts.push('随机 MAC 换地址后自动接续规则');
  if (mList.length) sumParts.push('已合并 ' + mList.length + ' 个');
  if (mutexCnt > 0) sumParts.push('双胞胎互斥 ' + mutexCnt + ' 对');
  return sFold('mmerge', ['orange', 'merge'], '设备合并与双胞胎拆分', sumParts.join(' · '),
    body, sg.length ? '<span class="badge b-warn" style="font-size:12px;padding:3px 8px">' + sg.length + '</span>' : val(String(mList.length)));
}
/* ═══ 加密 DNS 策略(GET /api/encdns + encdns_set) ═══ */
S.encdns = null;
var ENC_T = { off: '关闭', dot: '标准', strict: '严格', inherit: '跟随全局' };
function loadEncdns() { return api.getSafe('/api/encdns', null, null).then(function (r) { S.encdns = r && typeof r.policy === 'string' ? r : null; return S.encdns; }); }
function encdnsDevPol(mac) { var e = S.encdns; return e && e.devices && e.devices[mac] ? e.devices[mac] : 'inherit'; }
function encdnsDevBlock(d) {
  var e = S.encdns; if (!e || d.sim) return '';
  var cur = encdnsDevPol(d.mac), g = ENC_T[e.policy] || e.policy || '关闭';
  return '<div class="ctrl"><div class="ctrl-t"><i style="background:var(--red)"></i>加密 DNS 拦截</div>' + seg('encdns-dev', [['inherit', '跟随全局'], ['off', '关闭'], ['dot', '标准'], ['strict', '严格']], cur, 'small') +
    '<div class="note">' + (cur === 'inherit' ? '跟随全局（' + esc(g) + '）' : cur === 'off' ? '这台设备不拦截（豁免全局设置）' : '单独设为「' + esc(ENC_T[cur] || cur) + '」') + '。如果它手动指定了「私人 DNS」主机名导致无法上网，选「关闭」即可恢复</div></div>';
}
function encdnsSettingsHtml(c0) {
  var e = S.encdns;
  if (!e) return sItem(['gray', 'shield'], '加密 DNS 拦截', '当前后端不支持（需要新版 hnc_httpd）', val('—'));
  var pol = ENC_T[e.policy] ? e.policy : 'off', c = e.counters, dp = e.dpid, nDev = Array.isArray(e.device_list) ? e.device_list.length : Object.keys(e.devices || {}).length;
  var slT = { available: '支持', unavailable: '当前内核不支持（严格档仅按常见公共服务器 IP 拦截）', unknown: '未检测（首次开启严格档时自动检测）' }[e.string_layer] || '—';
  var pk = function (k) { return c && c[k] ? num(c[k].pkts) : 0; };
  var cnt = c ? '<div class="enc-cnt">' + [['dot', '私人 DNS'], ['doh_ip', '加密 DNS · IP'], ['doh_sni', '加密 DNS · 握手'], ['doh_dns', '加密 DNS · 域名']].map(function (x) { return '<div><div class="n num">' + fmtN(pk(x[0])) + '</div><div class="l">' + x[1] + '</div></div>'; }).join('') + '</div>' +
      '<div class="note" style="margin-top:4px">已拦下的数据包（含设备自动重试）· 合计 ' + fmtN(c.total_pkts) + ' 包 · ' + bytes(c.total_bytes) + (num(c.v6_pkts) ? ' · 其中 IPv6 ' + fmtN(c.v6_pkts) : '') + ' · 规则重新同步时清零</div>'
    : '<div class="note" style="margin-top:6px">' + (e.counters_error ? '拦截计数读取失败：' + esc(e.counters_error) : pol === 'off' ? '开启后这里显示实时拦截计数' : '暂无拦截计数') + '</div>';
  var dpT = '';
  if (dp && typeof dp === 'object') {
    var rd = Array.isArray(dp.recent_doh) && dp.recent_doh.length ? dp.recent_doh[0] : null, rdd = rd && rd.client_mac ? devBy(rd.client_mac) : null;
    dpT = '实时统计：普通 DNS ' + fmtN(dp.dns_seen) + ' 次 · 私人 DNS 尝试 ' + fmtN(dp.dot_attempts) + (num(dp.dot_flows) ? '（' + num(dp.dot_flows) + ' 条仍在连）' : '') + ' · 疑似内置加密 DNS ' + fmtN(dp.doh_suspect) +
      (rd ? ' · 最近 <span class="mono">' + esc(rd.name || '?') + '</span>' + (rdd ? '（' + esc(rdd.name) + '）' : '') + (num(rd.ts) ? ' ' + ago(rd.ts) : '') : '');
  }
  return '<div class="row" style="align-items:flex-start" id="encdns-row">' + gi('red', 'shield') + '<span class="tx"><div class="t">加密 DNS 拦截</div><div class="s">拦下加密域名解析请求，让接入设备自动回退普通 DNS，使应用识别与网站封锁更准确</div>' +
    '<div style="margin-top:8px">' + seg('encdns', [['off', '关闭'], ['dot', '标准'], ['strict', '严格']], pol, 'small') + '</div>' +
    '<div class="note" style="margin-top:6px"><b>标准</b>：只拦手机系统默认自动私人 DNS，最稳妥不易断网；<b>严格</b>：额外封堵浏览器和 App 内置公共加密 DNS，封锁更彻底。手动指定私人 DNS 的设备如无法上网，可在设备卡里单独选「关闭」。</div>' +
    (e.tradeoff ? '<div class="note warn" style="margin-top:6px">' + esc(e.tradeoff) + '</div>' : '') +
    '<div class="note" style="margin-top:6px">按域名精准识别能力：' + slT + (nDev ? ' · 已有 ' + nDev + ' 台设备单独设置（可在设备卡里修改）' : ' · 可在设备卡里按设备单独设置') + '</div>' + cnt +
    (dpT ? '<div class="note" style="margin-top:4px">' + dpT + '</div>' : '') + '</span></div>';
}
function encdnsDetailTxt(r) { var d = String((r && r.detail) || ''); return /no change/.test(d) ? '（未变化）' : /global=pending/.test(d) ? ' · 热点开启后生效' : /string_layer=0/.test(d) ? ' · 当前内核仅支持按 IP 拦截' : ''; }
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
  $('#sd-type').onclick = function (e) { var t = evEl(e), b = t && t.closest ? t.closest('[data-sdt]') : null; if (!b) return; pick = b.getAttribute('data-sdt'); $$('#sd-type [data-sdt]').forEach(function (x) { x.classList.toggle('on', x === b); }); };
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
var SET_VAULT = { lastSha: '', lastCount: 0, lastRestored: 0 };
function setDualFlowStats(lv, rs) {
  lv = lv || {}; rs = rs || {};
  var onCnt = S.hotspot.active === false ? 0 : S.devices.filter(function (d) { return d.online; }).length;
  var hsFlows = 0;
  if (S.hotspot.active !== false && onCnt > 0) {
    if (lv.hotspot_flows != null) hsFlows = Math.max(0, Math.round(num(lv.hotspot_flows, 0)));
    else if (rs.hotspot_flows != null) hsFlows = Math.max(0, Math.round(num(rs.hotspot_flows, 0)));
    else {
      Object.keys(S.connCounts || {}).forEach(function (m) {
        var d = devBy(m);
        if (d && d.online) hsFlows += Math.max(0, Math.round(num(S.connCounts[m] && S.connCounts[m].n, 0)));
      });
    }
  }
  var hostFlows = 0;
  if (lv.host_flows != null) hostFlows = Math.max(0, Math.round(num(lv.host_flows, 0)));
  else if (rs.host_flows != null) hostFlows = Math.max(0, Math.round(num(rs.host_flows, 0)));
  else if (S.self && S.self.apps_by_uid && typeof S.self.apps_by_uid === 'object') {
    Object.keys(S.self.apps_by_uid).forEach(function (u) {
      hostFlows += Math.max(0, Math.round(num(S.self.apps_by_uid[u] && S.self.apps_by_uid[u].active_conns, 0)));
    });
  }
  return { hs: hsFlows, host: hostFlows, text: '热点连接 ' + hsFlows + ' · 本机连接 ' + hostFlows };
}
function setDualTempStats(lv, rs) {
  var th = (lv && lv.thermo && typeof lv.thermo === 'object') ? lv.thermo
    : ((window.V6 && V6.thermo && typeof V6.thermo === 'object') ? V6.thermo
    : ((rs && rs.thermo && typeof rs.thermo === 'object') ? rs.thermo : null));
  var bat = th && th.battery && typeof th.battery === 'object' ? th.battery : null;
  var shellAvail = !!(th && (th.shell_temp_available === true || (bat && bat.shell_temp_available === true)));
  var shellC = num(th && (th.shell_temp_c != null ? th.shell_temp_c : (bat && bat.shell_temp_c)), 0);
  var batC = num(th && (th.battery_temp_c != null ? th.battery_temp_c : (bat && bat.temp_c)), 0);
  var effC = num(th && th.temp_c, shellAvail && shellC > 0 ? shellC : batC);
  var spoof = !!(th && (th.battery_spoof_suspected === true || (bat && bat.battery_spoof_suspected === true)));
  if (shellAvail && shellC > 0 && batC > 0) {
    return {
      hasTemp: true,
      shortText: effC.toFixed(1) + '°C',
      label: '机身 ' + shellC.toFixed(1) + '°C · 电池 ' + batC.toFixed(1) + '°C',
      sub: spoof ? '检测到电池锁温特征 · 已切换机身热区真实温度为准' : '机身热区与电池双传感器实时温度',
      cls: effC >= 45 ? 'bad' : (effC >= 42 ? 'warn' : 'ok')
    };
  }
  if (effC > 0 && effC < 95) {
    return {
      hasTemp: true,
      shortText: effC.toFixed(1) + '°C',
      label: effC.toFixed(1) + '°C',
      sub: '设备实时热区与电池温控采样',
      cls: effC >= 45 ? 'bad' : (effC >= 42 ? 'warn' : 'ok')
    };
  }
  return { hasTemp: false, shortText: '正常', label: '待采样', sub: '温控传感器按需低功耗采样', cls: '' };
}
function setVaultRowsHtml() {
  var vSha = SET_VAULT.lastSha || (window.V6 && V6.vault && V6.vault.last_sha256) || '';
  var vCnt = SET_VAULT.lastCount || (window.V6 && V6.vault && V6.vault.last_file_count) || 0;
  var vRes = SET_VAULT.lastRestored || (window.V6 && V6.vault && V6.vault.last_restored) || 0;
  var expSub = '一键打包设备备注、限速规则、本机防火墙与护航配置 JSON（自动剔除登录凭据）' +
    (vSha ? (' · 摘要 ' + esc(String(vSha).slice(0, 12)) + '…' + (vCnt ? ' (' + vCnt + ' 项)' : '')) : '');
  var impSub = '选择备份 JSON 快照或粘贴内容，校验 SHA256 后原子恢复整机配置' +
    (vRes ? (' · 最近已恢复 ' + vRes + ' 项') : '');
  return '<button type="button" class="row" data-set-vault="export">' + gi('blue', 'box') +
      '<span class="tx"><div class="t">配置保险箱 · 导出全量快照</div><div class="s">' + expSub + '</div></span><span class="hint-a">导出</span></button>' +
    '<button type="button" class="row" data-set-vault="import">' + gi('green', 'refresh') +
      '<span class="tx"><div class="t">配置保险箱 · 恢复整机配置</div><div class="s">' + impSub + '</div></span><span class="hint-a">恢复</span></button>' +
    '<input id="set-vault-file" type="file" accept=".json,application/json" hidden>';
}
function renderSettings(anim1) {
  var c = S.cfg || {}, ac = S.alertCfg || {}, mq = ac.monthly_quota || {}, an = ac.anomaly_traffic || {}, ud = ac.unknown_device || {}, sla = S.sla || {}, rs = S.runStatus || {};
  var gsOn = c.global_shaper_enabled === true, hsAuto = c.hotspot_autostart === true, lv = S.live || {};
  var flowSt = setDualFlowStats(lv, rs), tempSt = setDualTempStats(lv, rs);
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
  groups.push(['远程访问', (IS_LOCAL ? sItem(['blue', 'globe'], '启用远程访问服务', '开启后 :8443 监听，热点内其他设备可用浏览器访问（约 1 分钟生效）', toggle(remOn, 'data-set="remote" aria-label="远程访问服务"')) : sItem(['blue', 'globe'], '远程访问服务', '你正在通过远程访问使用 HNC；开关只能在本机 WebUI 里改', val('已开启', 'ok'))) +
    (remOn || !IS_LOCAL ? '<div class="row">' + gi('gray', 'link') + '<span class="tx"><div class="t">访问地址</div><div class="s mono">' + esc(rUrl || '无法获取本机 IP · 请确认热点已开启') + '</div></span>' + (rUrl ? '<button class="linkish" data-act="url-copy">复制</button><button class="linkish" data-act="url-share">分享</button>' : '') + '</div>' : '') +
    (IS_LOCAL ? sItem(['purple', 'lock'], '远程 PIN 配对鉴权', '安全基线常驻保护 · 局域网浏览器首次访问必须验证 6 位配对码', val('强制开启', 'ok')) : '') +
    (IS_LOCAL ? sBtn(['orange', 'star'], '生成配对码', '远端新设备首次连接用 · 120 秒有效', 'pair-new', '生成') : '') +
    (c.webui_access ? sFold('webacc', ['red', 'shield'], 'WebUI 访问控制', { all: '热点内所有设备都能打开登录页', allowlist: '只有名单里的设备能连接', local_only: '只有本机能打开' }[c.webui_access.mode || 'all'] || '',
      seg('webacc-mode', [['all', '全部'], ['allowlist', '白名单'], ['local_only', '仅本机']], S.webaccMode || c.webui_access.mode || 'all', 'small') +
      '<label class="field" style="margin-top:10px">白名单（MAC 或 IP，逗号分隔，最多 32 个）' + inp('webacc-macs', (c.webui_access.macs || []).join(', '), '', 'placeholder="aa:bb:cc:dd:ee:ff, 192.168.43.25"') + '</label>' +
      '<div class="note">在防火墙层直接断开不允许的设备；蜂窝网络上任何模式都连不上。本机和 KSU 里的 WebUI 永远可用。设置会把你自己锁在外面时会被拒绝。' + (c.webui_access.firewall ? '<br>防火墙状态：' + esc(c.webui_access.firewall) : '') + '</div>' +
      '<button class="btn pri wide press" data-act="webacc-save">保存</button>', val({ all: '全部', allowlist: '白名单', local_only: '仅本机' }[c.webui_access.mode || 'all'] || '—')) : '') +
    sFold('tokens', ['gray', 'dev'], '已授权设备', '管理能远程访问的设备' + (IS_LOCAL ? '' : ' · 撤销只能在本机操作'), '<div id="tokens-list" class="note">展开后加载</div>')]);
  groups.push(['运行状态',
    sItem(['cyan', 'link'], '活跃连接分流', '热点转发流与本机应用套接字正交分离（关热点不影响本机计数）', val(esc(flowSt.text), flowSt.hs > 0 || flowSt.host > 0 ? 'ok' : '')) +
    sItem(['orange', 'thermo'], '真实机身与电池温度', esc(tempSt.sub), val(esc(tempSt.label), tempSt.cls)) +
    (!S.runStatus ? sItem(['gray', 'cpu'], '守护进程运行态', '后端暂未提供 /api/run_status', val('—')) :
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
  groups.push(['维护', setVaultRowsHtml() +
    sBtn(['blue', 'refresh'], '重启 HNC 服务', '重新启动所有后台管控与识别服务（已设好的规则不会丢失，耗时约几秒）', 'svc-restart', '重启', 'danger') +
    sFold('ttl', ['orange', 'refresh'], '离线规则自动清理', num(c.stale_rule_ttl_days, 30) ? '设备离线超过 ' + num(c.stale_rule_ttl_days, 30) + ' 天后，自动删掉它的限速/延迟规则' : '已关闭 · 离线设备的规则永久保留',
      '<div style="display:flex;gap:8px"><span class="box" style="flex:1"><input id="ttl-days" type="number" min="0" max="3650" value="' + num(c.stale_rule_ttl_days, 30) + '"><span class="u">天</span></span><button class="btn pri press" data-act="ttl-save">保存</button></div><div class="note">填 0 = 永不自动清理。黑名单不受影响。</div>',
      val(num(c.stale_rule_ttl_days, 30) ? num(c.stale_rule_ttl_days, 30) + ' 天' : '关闭')) +
    sBtn(['orange', 'trash'], '清理缓存', 'hostname_cache · dev_class_cache', 'cache-clear', '清理', 'warn') +
    sBtn(['green', 'down'], '导出规则', '复制 rules.json（限速/延迟/黑名单/模板）', 'rules-json', '导出') +
    sBtn(['cyan', 'doc'], 'JSON 健康面板', 'rules / devices / tokens 的完整性与备份', 'json-health', '打开') +
    sBtn(['purple', 'down'], '导出诊断包', '快照、配置、日志尾部和 tc/iptables/ip 状态', 'debug-bundle', '导出')]);
  // 应用识别与 DNS 策略 —— 按协议主次排列，强制 QUIC 回落 TCP 置于开关区末尾兜底
  groups.push(['应用识别', encdnsSettingsHtml(c) + dnsTakeoverFold() + fgEngineFold() +
    sItem(['blue', 'shield'], '自动获取服务器证书', '遇到陌生域名时，读取网站公开安全证书里的所属公司名，辅助认出是哪款新应用', toggle(c.discover_cert_probe !== false, 'data-set="certprobe" aria-label="自动获取服务器证书"')) +
    (S.appLimitSharedKnown ? sItem(['orange', 'warn'], '按应用限速包含共享 IP', '默认跳过多款应用共用的云服务器 IP，防止限速甲应用时误伤乙应用；打开后一并限速', toggle(S.appLimitShared, 'data-set="appshared" aria-label="按应用限速包含共享 IP"')) : '') +
    sItem(['purple', 'flask'], '强制 QUIC 回落 TCP（兜底排障）', '平时无需开启（系统默认已能直接识别主流 HTTP/3 流量，单应用限速也会自动单独回退）。仅在开启「加密 DNS 严格拦截 / 域名封锁」仍有浏览器绕过、个别应用漏识别、本机挂代理开热点刷视频转圈，或多人刷短视频抢网压不住游戏延迟时再打开（注意：开启后会停用手机系统硬件转发加速，且 Hysteria2 / TUIC 等纯 QUIC 节点将无法连接）', toggle(c.quic_block === true, 'data-set="quic" aria-label="强制 QUIC 回落 TCP（兜底排障）"')) +
    sBtn(['purple', 'rule_hub'], '应用规则中心', '新发现应用、候选晋级、识别纠正与规则包已统一整合至此', 'go-rules-hub', '前往') +
    sBtn(['cyan', 'flask'], '应用识别学习与准确率自测', '利用本机日常联网自动学习新应用特征、查看识别准确率，已整合至「分析」页', 'go-dpi-studio', '前往')]);
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
    // 玻璃透光度五档离散胶囊(只在液态玻璃风格下显示, liquid.css .lg-only): 点按即切换并保存, 零滑条防展开手势误触
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
  var HNC_UI_VER = 'v6.1.0-rc.5', HNC_UI_VC = '6009305', HNC_UI_DATE = '2026-11-24';
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
  var v6TempS = tempSt.hasTemp ? tempSt.shortText : '正常';
  var advCards = [
    scard('scard-v6', ['blue', 'vector'], '智能护航与本机守护',
      '游戏通话优先 · 本机管控 · 温控保护（' + esc(v6TempS) + '）· 隐私安检（' + v6LgHits + ' 条）',
      (function(){ var _rv = cleanVer(l.backend_version, HNC_UI_VER); var _short = _rv.replace(/^(v\d+\.\d+)\.\d+-(alpha|beta|rc)\.?(\d+).*$/i, function(_, m, c, n){ return m + ' ' + (c.toLowerCase() === 'rc' ? 'RC' + n : c.charAt(0).toUpperCase() + n); }); return '<span class="badge b-acc" title="' + esc(_rv) + '">' + esc(_short) + '</span>'; })(),
      typeof v6SettingsBodyHtml === 'function' ? v6SettingsBodyHtml() : ''),
    scard('scard-dpi', ['purple', 'search'], '应用识别与 DNS 策略',
      (c.quic_block === true ? 'QUIC 回落已开 · ' : '') + '加密 DNS（' + (ENC_T[(S.encdns && S.encdns.policy) || 'off'] || '关闭') + '）· ' + (S.fgcmp && S.fgcmp.engine === 'classic' ? '前台灵敏实时' : '前台智能防抖') + ' · 应用识别学习',
      '<span class="badge b-pur">智能识别</span>',
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
  var dpvIsUnavail = !!(dpvNorm && dpvNorm.sampled_ok && dpvNorm.is_unavailable);
  var dpvIsBypass = !!(dpvNorm && dpvNorm.sampled_ok && dpvNorm.is_bypass);
  var dpvHasErr = !!(dpvNorm && dpvNorm.sampled_ok && !dpvIsUnavail && (dpvIsBypass || (dpvNorm.summary && dpvNorm.summary.bypass_or_missing_count > 0)));
  if (dpvHasErr && S.open['scard-dpv'] === undefined) S.open['scard-dpv'] = true;
  var dpvSubTxt = !dpvNorm || !dpvNorm.sampled_ok
    ? '检验给设备设的限速是否真正管用，有无被手机系统加速绕过'
    : dpvIsUnavail
      ? ('暂不可读 · ' + esc(dpvNorm.unavailable_reason || '未能读取内核队列状态'))
      : dpvIsBypass
        ? '检测到高通 tether_limit_map / 系统硬件加速绕过截流 · 点开一键兜底'
        : dpvHasErr
          ? ('发现 ' + dpvInt(dpvNorm.summary.bypass_or_missing_count) + ' 台设备限速可能被绕过 · 点开一键修复')
          : ('已设限速 ' + dpvInt(dpvNorm.summary.controlled_devices) + ' 台 · 正在生效 ' + dpvInt(dpvNorm.summary.hitting_count) + ' 台 · 未被硬件加速绕过');
  var dpvBadgeHtml = !dpvNorm || !dpvNorm.sampled_ok
    ? '<span class="badge b-gray" id="dpv-scard-badge">点开检验</span>'
    : dpvIsUnavail
      ? '<span class="badge b-gray" id="dpv-scard-badge">暂不可读</span>'
      : dpvIsBypass
        ? '<span class="badge b-warn" id="dpv-scard-badge">硬件截流</span>'
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
      esc(flowSt.text) + (tempSt.hasTemp ? ' · ' + esc(tempSt.label) : '') + ' · tc ' + num(rs.tc_rules) + ' / ipt ' + num(rs.ipt_rules),
      '<span class="badge ' + (rs.hotspotd === 'up' ? 'b-ok' : 'b-gray') + '">' + (rs.hotspotd === 'up' ? '运行正常' : '状态') + '</span>',
      (gMap['运行状态'] || '') + (gMap['运行健康'] || '')),
    scard('scard-maint', ['orange', 'tool'], '维护、配置保险箱与功耗',
      '配置保险箱（快照导出/恢复）· 刷新模式（' + ({ realtime: '实时', balanced: '均衡', powersave: '省电' }[S.refreshMode]) + '）· 诊断导出',
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
    lvSec('adv', '二、进阶与识别', '智能识别 · 带宽队列 · 加速兜底 · 设备合并', advCards) +
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
  var r = S.dns; if (!r) return '默认关闭 · 由本机代答热点设备的域名解析，应用识别更早、网站封锁更彻底';
  if (!r.enabled) return '未开启 · 由本机代答热点设备的域名解析，应用识别更早、网站封锁更彻底';
  return r.active && r.healthy ? '运行中 · 今天已解析 ' + num((r.stats || {}).queries) + ' 次' : '已开启 · 暂未生效（已自动放行直连）';
}
function dnsTakeoverFold() {
  return sFold('dnst', ['blue', 'shield'], 'DNS 解析接管', '<span id="dns-sum">' + esc(dnsSumTxt()) + '</span>', '<div id="dns-body"><div class="note">展开后加载</div></div>',
    toggle(!!(S.dns && S.dns.enabled), 'data-set="dnst" aria-label="DNS 解析接管"' + (S.dns ? '' : ' disabled')));
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
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持 DNS 解析接管）</div>'; return; }
  var st = r.stats || {}, fo = r.failopen || {}, h = '';
  if (r.enabled) {
    h += '<dl class="kv"><dt>状态</dt><dd style="color:' + (r.active && r.healthy ? 'var(--badge-ok)' : 'var(--orange)') + '">' + (r.active && r.healthy ? '运行中' : '未生效 · ' + esc(DNS_ST[fo.reason] || fo.reason || r.last_error || r.state || '检测中')) + '</dd>' +
      '<dt>上游</dt><dd class="mono">' + esc(r.upstream || '自动') + (r.upstream_kind ? ' · ' + esc(r.upstream_kind) : '') + '</dd>' +
      '<dt>今天</dt><dd>' + num(st.queries) + ' 次 · 缓存 ' + num(st.cached) + ' · 拦截 ' + num(st.blocked) + '</dd>' +
      '<dt>耗时</dt><dd class="num">平均约 ' + num(st.p50_ms) + 'ms · 慢查询 ' + num(st.p95_ms) + 'ms</dd>' +
      (num(fo.count) ? '<dt>自动放行</dt><dd>' + num(fo.count) + ' 次' + (fo.last_ts ? ' · 最近 ' + ago(fo.last_ts) : '') + '</dd>' : '') + '</dl>';
    var td = Array.isArray(r.top_domains_today) ? r.top_domains_today.slice(0, 5) : [];
    if (td.length) h += '<div class="note">今天查询最多：' + td.map(function (x) { return esc(x.name) + ' ×' + num(x.count); }).join('、') + '</div>';
  }
  h += '<div class="note" style="margin:8px 0 -2px">封锁域名的返回方式</div>' + seg('dns-bm', [['nxdomain', '提示域名不存在（推荐）'], ['zero', '返回空地址 0.0.0.0']], r.block_mode || 'nxdomain', 'small') +
    '<div class="note" style="margin-top:4px">默认选「提示域名不存在」可让应用立即停止转圈重试；个别老软件若反复报错可改选「返回空地址 0.0.0.0」。</div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">记录查询日志</div><div class="s">记下每台设备查了哪些域名（只存本机，约 2000 条滚动）</div></span>' + toggle(!!r.log_queries, 'data-set="dnslog" aria-label="记录查询日志"') + '</div>' +
    (r.log_queries ? '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">日志隐私脱敏</div><div class="s">开启后只记主域名、不记录完整子域与解析应答 IP</div></span>' + toggle(!!r.log_redact, 'data-set="dnsredact" aria-label="日志隐私脱敏"') + '</div><button class="btn sec wide press" style="margin:6px 0" data-act="dns-log-open">查看最近 DNS 查询明细</button>' : '') +
    '<div class="note">作用：设备刚查域名时系统就能提前认出应用，按域名封锁也能在第一步直接拦住。<br>安全兜底：万一本机解析服务异常，约 10 秒内会自动放行设备直连（不会断网）；设备若自己开启了私人 DNS 或内置加密 DNS 则不会被接管。只作用于接入热点的设备，不影响本机上网。</div>';
  el.innerHTML = h; placeSegs(el);
}
/* ── 识别纠正记录 + 指纹学习 ── */
function fpFold() {
  var n = S.fpl && Array.isArray(S.fpl.user_rules) ? S.fpl.user_rules.length : null;
  return sFold('fpl', ['green', 'flask'], '识别纠正与指纹学习', n == null ? '你纠正过的识别 · HNC 自动学会的加密特征' : n + ' 条纠正 · ' + num((S.fpl.stats || {}).usable) + ' 个可用特征', '<div id="fp-body"><div class="note">展开后加载</div></div>');
}
function loadFP() {
  return api.get('/api/dpi_fp', null, { timeout: 8000 }).then(function (r) { S.fpl = r; }).catch(function (e) { S.fpl = { err: errText(e) }; }).then(paintFP);
}
var FPK_T = { domain: '域名', ip: 'IP', ja4: '特征' };
function paintFP() {
  var el = $('#fp-body'), r = S.fpl; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '</div>'; return; }
  var ur = Array.isArray(r.user_rules) ? r.user_rules : [], ln = Array.isArray(r.learned) ? r.learned : [], st = r.stats || {};
  var h = '<div class="note" style="margin-bottom:-2px">你纠正过的（' + ur.length + '）</div>' + (ur.length ? '<div class="dbox">' + ur.map(function (x) {
    return '<div class="row2"><span class="k" style="color:var(--text-1);min-width:0;overflow-wrap:anywhere"><span class="badge b-acc">' + (FPK_T[x.kind] || esc(x.kind)) + '</span> <span class="mono">' + esc(x.kind === 'ja4' ? String(x.value).slice(0, 18) + '…' : x.value) + '</span> → ' + esc(x.app_name || x.app_id) + (x.expires ? ' <span class="note">· ' + Math.max(0, Math.ceil((num(x.expires) - Date.now() / 1000) / 86400)) + ' 天后过期</span>' : '') + '</span><button class="linkish danger" data-fpdel="' + esc(x.id) + '">撤销</button></div>';
  }).join('') + '</div>' + (ur.length > 1 ? '<button class="linkish danger" data-fpdel="__all" style="justify-self:start">全部撤销</button>' : '') : '<div class="note">还没有。在设备卡「实时连接 → 点一条连接 → 纠正识别」里添加。</div>');
  var use = ln.filter(function (x) { return x.usable; });
  h += '<div class="note" style="margin-bottom:-2px">自动学会的特征（' + use.length + ' 个可用 / 共 ' + ln.length + ' 个观察中）</div>' +
    (use.length ? '<div class="dbox">' + use.slice(0, 12).map(function (x) {
      return '<div class="row2"><span class="k" style="color:var(--text-1)">' + esc(x.name || x.app_id) + ' <span class="note mono">' + esc(String(x.ja4).slice(0, 10)) + ' · ' + esc(x.port_class || '') + (x.qtp ? ' · ' + esc(String(x.qtp).replace(/^qtp1_/, '').slice(0, 8)) : '') + '</span></span><span class="v">' + pct100(x.purity) + '% · ' + num(x.devices) + ' 台</span></div>';
    }).join('') + '</div>' : '<div class="note">还在学习：同一个连接特征在 ≥2 台设备上见过 20 次以上、且 90% 都属于同一个应用后才会启用。</div>') +
    '<div class="note">累计观察 ' + num(st.flows_seen) + ' 条连接 · 靠特征认出 ' + num(st.flows_attributed_by_fp) + ' 条。加密特征只在看不到域名（如直连 IP）时辅助兜底，不会覆盖规则库。</div>';
  el.innerHTML = h;
  var sw = $('[data-foldkey="fpl"] .s'); if (sw) sw.textContent = ur.length + ' 条纠正 · ' + use.length + ' 个可用特征';
}
/* ── 识别自评(只用这台手机自己的流量当标准答案) ── */
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
var EVAL_M = [['rule', '规则库'], ['fp', '加密特征'], ['owner', 'IP 归属']];

function lanSelfConsistencyHtml(r) {
  var lc = r && r.lan_self_consistency;
  if (!lc) return '';
  var okParity = lc.he_v4v6_parity == null || lc.he_v4v6_parity >= 0.9;
  var escCnt = num(lc.active_escape_alerts);
  return '<div class="dbox" style="margin:8px 0"><div class="note" style="margin:0 0 6px;font-weight:600;color:var(--text-1)">热点接入设备识别与双栈一致性自检（无需开启本机学习）</div>' +
    '<div class="row2"><span class="k">域名解析与加密握手不一致率（越低越准）</span><span class="v num">' + (lc.cm_conflict_rate != null ? (lc.cm_conflict_rate * 100).toFixed(1) + '%' : '0.0%') + '</span></div>' +
    '<div class="row2"><span class="k">IPv4 与 IPv6 双路连接识别一致率</span><span class="v num" style="color:' + (okParity ? 'var(--badge-ok)' : 'var(--badge-warn)') + '">' + (lc.he_v4v6_parity != null ? (lc.he_v4v6_parity * 100).toFixed(1) + '%' : '100%') + '</span></div>' +
    '<div class="row2"><span class="k">IPv6 应用限速绕过监测</span><span class="v num" style="color:' + (escCnt > 0 ? 'var(--badge-red)' : 'var(--badge-ok)') + '">' + (escCnt > 0 ? escCnt + ' 台异常' : '正常（未绕过限速）') + '</span></div></div>';
}
function paintEval() {
  var el = $('#eval-body'), r = S.eval; if (!el || !r) return;
  el.setAttribute('data-keep', '');
  var sm = $('#eval-sum'); if (sm) sm.textContent = evalSumTxt();
  if (r.err) { el.innerHTML = '<div class="note err">' + esc(r.err) + '（后端可能还不支持识别自评）</div>'; return; }
  if (!r.enabled) {
    el.innerHTML = '<div class="note">「识别自评」用这台手机自己的联网记录做标准答案：系统一边记录每次联网实际是哪个本机 App 发起的，一边检验识别规则有没有猜对。</div>' +
      '<div class="note warn">当前尚未开启本机联网学习，因此还没有对比样本。</div>' +
      '<div class="btns"><button class="btn pri press" data-act="eval-enable">去开启</button></div>' +
      '<div class="note">只用这台手机自己的流量，样本仅在本地保存 7 天，绝不上传。</div>' + lanSelfConsistencyHtml(r);
    return;
  }
  var m = r.methods || {}, comb = m.combined || {};
  var h = lanSelfConsistencyHtml(r) + '<div class="note" style="margin-bottom:-2px">自测统计时间范围</div>' + seg('eval-days', [[1, '24 小时'], [7, '7 天']], r.days || S.evalDays, 'small');
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
    '<div class="note">覆盖率＝这些连接里成功认出应用的比例；准确率＝认出来的结果里完全认对的比例。（综合优先级：手动纠正 &gt; 规则库 &gt; 加密特征）</div>';
  // 各方法一行
  h += '<dl class="kv">';
  EVAL_M.forEach(function (x) {
    var mm = m[x[0]] || {};
    h += '<dt>' + x[1] + '</dt><dd class="num">覆盖 ' + pct100(mm.coverage) + '% · 准确 ' + evalAcc(mm) + ' <span class="note">(' + num(mm.predicted) + '/' + num(mm.samples) + (mm.judged != null && !mm.accuracy_na ? ' · 可判 ' + num(mm.judged) : '') + ')</span></dd>';
  });
  h += '</dl>';
  // QUIC 样本特征对比
  var qq = r.quic || {};
  if (num(qq.samples) > 0) {
    var qw = qq.fp_with_qtp || {}, qj = qq.fp_ja4_only || {};
    h += '<div class="note">QUIC 加密流量特征覆盖 ' + pct100(qw.coverage) + '% · 准确 ' + evalAcc(qw) + '（基础特征：覆盖 ' + pct100(qj.coverage) + '% · 准确 ' + evalAcc(qj) + '）· 共 ' + num(qq.samples) + ' 条样本</div>';
  }
  // 应用打开瞬间特征学习
  var su = r.startup;
  if (su) {
    h += '<div class="note" style="margin-bottom:-2px">应用启动特征学习（后台静默观察，不影响现有识别）</div><div class="note">已掌握 ' + num(su.apps_learned) + ' 个应用' +
      (num(su.days) >= 2 ? ' · 切换识别率 ' + pct100(su.switch_rate) + '% · 准确率 ' + pct100(su.event_accuracy) + '%' + (num(su.switches) ? '（' + num(su.switch_hit) + '/' + num(su.switches) + ' 次切换）' : '') : ' · ' + esc(su.note || '')) +
      '</div><button class="linkish" data-act="startup-list" style="justify-self:start">' + (S.startupOpen ? '收起已掌握的应用' : '查看已掌握的应用') + '</button><div id="startup-list">' + (S.startupOpen ? startupListHtml() : '') + '</div>';
  }
  // 新应用自动发现准确度
  var dv = r.discover;
  if (dv && num(dv.samples) > 0) {
    h += '<div class="note" style="margin-bottom:-2px">新应用自动归类准确度（后台统计评估）</div><div class="note">归类准确度 ' + pct100(dv.purity) + '% · 归拢完整度 ' + pct100(dv.completeness) + '%（共 ' + num(dv.groups) + ' 组' + (num(dv.hubs) ? ' · 公共共用域名 ' + num(dv.hubs) + ' 个' : '') + '）</div>';
    var dvs = Array.isArray(dv.variants) ? dv.variants : [];
    if (dvs.length > 1) {
      h += '<div class="note">不同分档对比：' + dvs.map(function (v) { return esc(v.label) + ' ' + pct100(v.purity) + '%/' + pct100(v.completeness) + '%（' + num(v.groups) + ' 组）'; }).join(' · ') + '</div>';
    }
  }
  // 按流量特征猜应用类别
  var fc = r.flow_cls;
  if (fc && num(fc.samples) > 0) {
    h += '<div class="note">按流量特征猜应用类别：智能模型 ' + pct100(fc.model_acc) + '% · 固定规则 ' + pct100(fc.manual_acc) + '%（今日 ' + num(fc.samples) + ' 条样本 · ' + num(fc.classes) + ' 类）</div>';
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
  // 前台切换记录
  var fg = r.fg_truth || {};
  var fgTxt = '近 24 小时切换 ' + num(fg.switches_24h) + ' 次' + (fg.last_pkg ? ' · 最近 ' + esc(fg.last_pkg) + (fg.last_ts ? '（' + ago(fg.last_ts) + '）' : '') : '');
  if (fg.source === 'none' || !num(fg.switches_24h)) {
    fgTxt = '暂时还没有本机前台切换记录。正常亮屏使用一会儿手机后会自动生成；若一直没有，说明当前手机系统限制读取前台应用状态，不影响热点识别与限速';
  } else {
    fgTxt += ' · 来源 ' + esc(fg.source);
  }
  h += '<div class="note" style="margin-bottom:-2px">本机前台切换记录（辅助校验识别准确度）</div><div class="note">' + fgTxt + '</div>';
  h += evalFootHtml();
  el.innerHTML = h; placeSegs(el);
}
/* 前台应用判断模式(智能防抖 / 灵敏实时) + 近 24 小时对比 */
S.fgcmp = null;
function fgEngineSumTxt() {
  var r = S.fgcmp; if (!r || r.err) return '智能防抖（推荐） · 自动过滤后台消息与更新干扰，显示不乱跳';
  return (r.engine === 'classic' ? '当前：灵敏实时（经典）' : '当前：智能防抖（推荐）') + (num(r.rounds) ? ' · 近 24 小时两种模式一致率 ' + num(r.agree_pct) + '%' : '');
}
function fgEngineFold() {
  return sFold('fgeng', ['purple', 'gauge'], '前台应用判断模式', '<span id="fgeng-sum">' + esc(fgEngineSumTxt()) + '</span>', '<div id="fgeng-body"><div class="note">展开后加载</div></div>');
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
  el.innerHTML = seg('fg-engine', [['hmm', '智能防抖（推荐）'], ['classic', '灵敏实时（经典）']], r.engine || 'hmm', 'small') +
    '<div class="note" style="margin-top:6px"><b>智能防抖（默认推荐）</b>：结合应用类型与使用连贯性，自动过滤微信后台收消息、网盘同步、应用商店静默更新引起的偶发流量尖峰；看长视频分段缓冲、或边打语音边逛其他应用时也不会乱跳，设备卡「正在用」与前台时间线更干净准确。<br><b>灵敏实时（经典）</b>：只看最近十来秒谁流量猛就立刻切换显示，换应用瞬间反应更激进，适合紧盯设备瞬时联网动作的抓包排障，但容易被后台推送和预加载短暂抢走焦点。</div>' +
    (num(r.rounds) ? '<div class="note">近 24 小时实测对比：智能防抖每小时切换 ' + num(hm.switches_per_hour) + ' 次（不足半分钟的短暂闪跳 ' + num(hm.short_segments) + ' 次）；灵敏实时每小时切换 ' + num(c.switches_per_hour) + ' 次（短暂闪跳 ' + num(c.short_segments) + ' 次），两种模式在 ' + num(r.agree_pct) + '% 的时间判断一致。</div>'
      : '<div class="note">近 24 小时还没有热点设备的联网流量，暂无实测对比数据。</div>') +
    '<div class="note">这里只影响设备卡片「正在用什么」的显示和前台时间线，完全不影响总流量统计、按应用限速和每日使用时长限制。</div>';
  placeSegs(el);
}
/* 我的规则包(导出 / 导入 / 清除已导入) */
S.rpack = null; S.rpackRep = null;
function rulepackSumTxt() {
  var r = S.rpack; if (!r || r.err) return '把这台手机学到的和你自己加的识别规则打包备份 / 分享';
  var ex = r.exportable || {}, im = r.imported || {};
  return '可导出 ' + num(ex.domain_rules) + ' 条域名规则 · ' + num(ex.fingerprints) + ' 个特征 · ' + num(ex.startup) + ' 个启动特征' + (num(im.domain_rules) + num(im.fingerprints) + num(im.startup) ? ' · 已导入 ' + num(im.suffixes) + ' 个域名' : '');
}
function rulepackFold() {
  return sFold('rpack', ['green', 'down'], '我的规则包', '<span id="rpack-sum">' + esc(rulepackSumTxt()) + '</span>', '<div id="rpack-body"><div class="note">展开后加载</div></div>');
}
function loadRulepack() {
  return api.get('/api/dpi_rulepack', { summary: 1 }, { timeout: 10000 }).then(function (r) { S.rpack = r; }).catch(function (e) { S.rpack = { err: errText(e) }; }).then(paintRulepack);
}
var RPK_SKIP = { conflict: '和本机规则冲突', already_local: '本机已有', public_suffix: '公共后缀', shared_apex: '共享基础设施', bad_suffix: '域名不合法', bad_id: 'id 不合法', bad_category: '类别本机没有', bad_attach: '挂靠目标不合法', bad_ja4: '特征不合法', bad_qtp: 'QUIC 参数特征不合法', bad_port: '端口类不合法', bad_alpn: 'ALPN 不合法', bad_value: '数值不合法', bad_token: '启动特征不合法', too_few_tokens: '启动特征太少', bad_entry: '格式不对' };
function rulepackRepHtml(rep) {
  if (!rep) return '';
  if (rep.err) return '<div class="note err">' + esc(rep.err) + '</div>';
  var a = rep.added || {}, m = rep.merged || {}, u = rep.unchanged || {}, sk = rep.skipped || {};
  var skl = Object.keys(sk).filter(function (k) { return num(sk[k]); }).map(function (k) { return (RPK_SKIP[k] || k) + ' ' + num(sk[k]); });
  return '<div class="note">导入完成：新增 ' + num(a.suffixes) + ' 个域名（' + num(a.domain_rules) + ' 条规则）· ' + num(a.fingerprints) + ' 个特征 · ' + num(a.startup) + ' 个启动特征' +
    (num(m.suffixes) + num(m.fingerprints) + num(m.startup) ? '；合并 ' + num(m.suffixes) + ' 个域名 · ' + num(m.fingerprints) + ' 个特征 · ' + num(m.startup) + ' 个启动特征' : '') +
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
  var h = '<div class="note">可导出：域名规则 ' + num(ex.domain_rules) + ' 条（自动扩展 ' + pr(src.auto_expanded) + ' / 晋升 ' + pr(src.auto_promoted) + ' / 自定义 ' + pr(src.user_custom) + ' / 纠正 ' + num(uc.domain) + '）· 加密特征 ' + num(ex.fingerprints) + ' 条 · 启动特征 ' + num(ex.startup) + ' 个应用</div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="box" style="flex:1"><input id="rpack-note" maxlength="60" placeholder="备注（可空，例如「家里的手机」）"></span></div>' +
    '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t">包含已导入的</div><div class="s">已导入 ' + num(im.suffixes) + ' 个域名 · ' + num(im.fingerprints) + ' 个特征 · ' + num(im.startup) + ' 个启动特征（别人给你的）</div></span>' + toggle(false, 'id="rpack-inc" data-local="rpack-inc" aria-label="包含已导入的"') + '</div>' +
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
    return api.post('/api/dpi_rulepack', { pack: txt }, { timeout: 30000, maxTime: 28 });
  }).then(function (rep) {
    if (rep && rep.ok === false) throw new Error(rep.error || '导入失败');
    S.rpackRep = rep; toast('规则包已导入'); return loadRulepack();
  }).catch(function (e) { S.rpackRep = { err: errText(e) }; var rp = $('#rpack-rep'); if (rp) rp.innerHTML = rulepackRepHtml(S.rpackRep); toast(errText(e), 'err'); })
    .then(function () { btn.disabled = false; });
}
/* 已掌握的应用启动特征列表(/api/dpi_startup) */
S.startup = null; S.startupOpen = false;
function startupListHtml() {
  var r = S.startup; if (!r) return '<div class="note">加载中…</div>';
  if (r.err) return '<div class="note err">' + esc(r.err) + '</div>';
  var ln = (Array.isArray(r.learned) ? r.learned : []).filter(function (x) { return x.usable; });
  if (!ln.length) return '<div class="note">还没有掌握的应用：同一个应用正常冷启动 3 次以上、且每次都连到 2 个以上它专属的域名后会自动掌握。</div>';
  return '<div class="dbox">' + ln.slice(0, 20).map(function (x) {
    return '<div class="row2"><span class="k" style="min-width:0;overflow-wrap:anywhere">' + esc(x.name || x.app_id) + '</span><span class="v num" style="white-space:nowrap">启动 ' + num(Math.round(num(x.starts))) + ' 次 · 特征 ' + num(x.feat) + ' 个</span></div>';
  }).join('') + '</div><div class="note">累计识别事件 ' + num((r.stats || {}).events_total) + ' 次（热点设备上认出的「打开了某应用」）</div>';
}
function toggleStartupList() {
  S.startupOpen = !S.startupOpen;
  var el = $('#startup-list'), b = $('[data-act="startup-list"]');
  if (b) b.textContent = S.startupOpen ? '收起已掌握的应用' : '查看已掌握的应用';
  if (!el) return Promise.resolve();
  if (!S.startupOpen) { el.innerHTML = ''; return Promise.resolve(); }
  el.innerHTML = startupListHtml();
  return api.get('/api/dpi_startup', null, { timeout: 8000 }).then(function (r) { S.startup = r; }).catch(function (e) { S.startup = { err: errText(e) }; })
    .then(function () { var e2 = $('#startup-list'); if (e2 && S.startupOpen) e2.innerHTML = startupListHtml(); });
}
function evalFootHtml() {
  return '<div class="note">只用这台手机自己的联网记录做对比，数据仅存本机 7 天，绝不上传。积累足够记录后，点「立即更新学习模型」即可把新学到的应用特征同步给热点识别使用。</div>' +
    '<div class="btns" style="flex-wrap:wrap">' +
      '<button class="btn pri press" data-act="dpi-distill-now">立即更新学习模型</button>' +
      '<button class="btn sec press" data-act="go-self-studio">识别学习中心</button>' +
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
        (IS_LOCAL ? '<button class="hint-a danger" data-revoke="' + esc(x.token_id) + '" data-label="' + esc(x.label || '未命名设备') + '">撤销</button>' : '') + '</div>';
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
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">弹簧手感</div><div class="s">轻快：收放干脆利落 · 有弹性：轻微回弹更灵动</div></span>' + seg('fxspring', [['light', '轻快'], ['bouncy', '有弹性']], FX.spring, 'small') + '</div>' +
    '<div class="note" style="margin:6px 0 -2px">效果演示</div><div class="chips">' + [['sheet', '弹层'], ['page', '切页'], ['list', '列表浮现'], ['num', '数字滚动']].map(function (b) { return '<button class="chip press" data-act="fx-demo" data-demo="' + b[0] + '">' + b[1] + '</button>'; }).join('') + '</div>' +
    '<div class="note">演示数字：<b class="num" id="fx-num" style="color:var(--text-1)">128.00</b> MB/s</div>';
  return '<div class="note" style="margin:8px 0 -2px">动画档位 · ' + FXP_T[pre] + '</div>' +
    seg('fxp', [['off', '关闭'], ['calm', '克制'], ['std', '标准'], ['lively', '灵动']], pre, 'small') +
    '<div class="row" style="padding:6px 0;min-height:0"><span class="tx"><div class="t">性能模式</div><div class="s">' + (PERF.low ? '已开启简化渲染（最高帧率）' : '高帧率优化已启用') + (PERF.probe ? ' · ' + PERF.probe : '') + '</div></span><button class="linkish" data-act="fx-perf">' + (PERF.low ? '恢复完整' : '手动简化') + '</button></div>' +
    dFold('fx-more', 'var(--purple)', '展开 8 项动画细节与测试', FXP_T[pre], details);
}
function fxRefresh() { applyTheme(); navSync(); if (S.page === 'settings') renderSettings(false); }
function fxDemo(k) {
  if (k === 'sheet') sheet('<h3>弹层演示</h3><div class="sub">平滑弹出；按住顶部往下拖或点击空白处即可关闭</div>' +
    '<div class="dbox"><div class="row2"><span class="k">弹簧手感</span><span class="v">' + (FX.spring === 'bouncy' ? '有弹性（灵动回弹）' : '轻快（干脆利落）') + '</span></div><div class="row2"><span class="k">性能模式</span><span class="v">' + (PERF.low ? '已简化' : '完整') + '</span></div></div>' +
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
    case 'appshared': run(api.action('app_limit_shared_ips_set', { enabled: String(on) }).then(function () { S.appLimitShared = on; toast(on ? '已包含共享 IP · 共用同一云服务器的其他应用也可能一并被限速' : '已恢复默认：跳过与其他应用共用的服务器 IP，避免误伤'); return loadAppLimits(); })); return;
    case 'certprobe': run(api.action('discover_cert_probe_set', { enabled: String(on) }).then(done())); return;
    case 'sim': run(simSet(on)); return;
    case 'dnst':
      if (!on) { run(api.action('dns_takeover_set', { enabled: 'false' }).then(function () { toast('DNS 解析接管已关闭 · 设备恢复直连'); return loadDNS(); })); return; }
      el.setAttribute('aria-checked', 'false');
      confirmSheet('开启 DNS 解析接管？', '热点设备的域名查询改由本机代答，应用识别更早、按域名封锁更彻底。<br>若本机解析服务出现异常，约 10 秒内会自动放行设备直连；设备自己开启了私人 DNS 或内置加密 DNS 时不受影响。随时可以关闭。', '开启', { safe: true }).then(function (ok) {
        if (!ok) return; el.setAttribute('aria-checked', 'true');
        run(api.action('dns_takeover_set', { enabled: 'true' }).then(function () { toast('DNS 解析接管已开启 · 约 10 秒内生效'); return loadDNS(); }));
      }); return;
    case 'dnslog': run(api.action('dns_takeover_set', { log_queries: String(on) }).then(function () { toast(on ? '已开始记录查询日志' : '已停止记录查询日志'); return loadDNS(); })); return;
    case 'dnsredact': run(api.action('dns_takeover_set', { log_redact: String(on) }).then(function () { toast(on ? '已开启 DNS 日志脱敏' : '已关闭 DNS 日志脱敏'); return loadDNS(); })); return;
    case 'authreq': run(api.action('auth_required_set', { enabled: String(on) }).then(function () { if (S.cfg) { S.cfg.auth_required = on; S.cfg.remote_auth_required = on; } toast('已同步远程鉴权配置'); })); return;
    case 'quic': run(api.action('quic_block_set', { enabled: String(on) }).then(function (r) { toast(on ? (/pending/.test(r && r.detail || '') ? '已开启强制回落 TCP（热点打开后生效）' : '已开启强制回落 TCP · 设备将自动改走常规连接') : '已关闭强制回落 · 恢复默认连接方式'); return loadConfig(); }).then(function () { if (S.page === 'settings') renderSettings(false); })); return;
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
    if ($('#rj-dl')) $('#rj-dl').onclick = function () { var u = URL.createObjectURL(new Blob([txt], { type: 'application/json' })), a = document.createElement('a'); a.href = u; a.download = fn; document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 3000); };
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
    var fbVer = cleanVer(m.version, '') || cleanVer(S.live && S.live.backend_version, '') || 'v6.1.0-rc.5';
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

/* ═════════════════════ 限速真实生效检验面板 & 后台服务卡死自检（协程泄漏扫描） ═════════════════════
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
  guardSwitching: false,
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
  var v = dpvStr(verdict, 'idle').toLowerCase();
  if (v === 'hit') return { key: 'hit', label: '队列真实命中', cls: 'dpv-status-hit' };
  if (v === 'bypass') return { key: 'bypass', label: '硬件加速绕过截流', cls: 'dpv-status-bypass' };
  if (v === 'bypass_offload') return { key: 'bypass_offload', label: '疑似快径旁路', cls: 'dpv-status-bypass' };
  if (v === 'unavailable' || v === 'unknown') return { key: 'unavailable', label: '状态不可读', cls: 'dpv-status-idle' };
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

function dpvExtractGuidancePaths(src, sum, off) {
  var out = [];
  var rawArr = (Array.isArray(src.guidance_paths) ? src.guidance_paths : null) ||
    (Array.isArray(src.bypass_paths) ? src.bypass_paths : null) ||
    (Array.isArray(src.remediation_paths) ? src.remediation_paths : null) ||
    (Array.isArray(src.paths) ? src.paths : null) ||
    (sum && Array.isArray(sum.guidance_paths) ? sum.guidance_paths : null) ||
    (off && Array.isArray(off.guidance_paths) ? off.guidance_paths : null);
  if (rawArr) {
    rawArr.forEach(function (it) {
      if (!it) return;
      if (typeof it === 'string') {
        if (it.trim()) out.push(it.trim());
      } else if (typeof it === 'object') {
        var title = dpvStr(it.title || it.label || it.name, '');
        var desc = dpvStr(it.desc || it.detail || it.text || it.steps || it.guidance, '');
        if (title && desc) out.push(title + '：' + desc);
        else if (title || desc) out.push(title || desc);
      }
    });
  }
  var p1 = dpvStr(src.path_a || src.path_1 || src.system_toggle_guide || (off && off.system_toggle_guide), '');
  var p2 = dpvStr(src.path_b || src.path_2 || src.always_guard_guide || (off && off.always_guard_guide), '');
  if (p1 && out.indexOf(p1) < 0) out.push(p1);
  if (p2 && out.indexOf(p2) < 0) out.push(p2);
  return out;
}

/* 未采样 / 首次静默加载未返回时的诚实中性态（严禁伪装 BPF 已挂载或全绿健康） */
function dpvDefaultData(leakOn) {
  var ifc = (typeof S === 'object' && S && S.hotspot && S.hotspot.iface) ? S.hotspot.iface : '—';
  var hsOn = (typeof S === 'object' && S && S.hotspot && typeof S.hotspot.active === 'boolean') ? S.hotspot.active : false;
  return {
    ok: false,
    sampled_ok: false,
    verdict: 'unsampled',
    is_unavailable: false,
    unavailable_reason: '',
    reason_code: '',
    is_bypass: false,
    bypass_guidance: '',
    bypass_paths: [],
    checked_at: 0,
    checked_at_str: '待首次采样',
    iface: ifc || '—',
    hotspot_active: hsOn,
    engine_mode: 'pending',
    engine_label: '待采样核验',
    mark_layout: '',
    fwmark_mask: '—',
    netd_low16_known: false,
    netd_low16_protected: false,
    ipv6_quic_controlled: false,
    bpf_maps: {
      mac_mark_entries: 0,
      ip_mark_entries: 0,
      tether_limit_zeroed: false,
      clsact_attached: false,
      ifb_redirect_prio2: false
    },
    offload_guard: {
      mode: '',
      slowpath_active: false,
      tether_offload_disabled: false,
      hwnat: 'unknown'
    },
    summary: {
      controlled_devices: 0,
      hitting_count: 0,
      idle_count: 0,
      unavailable_count: 0,
      bypass_or_missing_count: 0,
      app_classes_total: 0,
      overall_status: 'unsampled',
      headline: '尚未开始检验：请点击下方「立即重新检验」，核对每台限速设备的流量是否真正经过限速通道'
    },
    devices: [],
    goroutineleak: {
      sampled: false,
      supported: false,
      trigger: '',
      total_goroutines: 0,
      leaked_count: 0,
      duration_ms: 0,
      status: 'idle',
      message: '平时不耗电（仅在怀疑后台控制服务卡顿或无响应时，打开右侧开关检查是否有后台任务卡住）',
      preview_stacks: []
    }
  };
}

function dpvNormalize(raw, leakOn) {
  var base = dpvDefaultData(leakOn);
  if (!raw || typeof raw !== 'object') return base;
  var src = raw.data && typeof raw.data === 'object' && (raw.data.summary || raw.data.devices || raw.data.verdict) ? raw.data : raw;
  if (src.sampled_ok === false) return base;
  var topVerdictRaw = dpvStr(src.verdict || (src.summary && src.summary.verdict), '').toLowerCase();
  var hasPayload = Boolean(
    src.ok === true ||
    src.sampled_ok === true ||
    topVerdictRaw === 'unavailable' ||
    topVerdictRaw === 'bypass' ||
    topVerdictRaw === 'bypass_offload' ||
    src.checked_at > 0 ||
    (src.summary && typeof src.summary === 'object') ||
    Array.isArray(src.devices) ||
    (src.bpf_maps && typeof src.bpf_maps === 'object') ||
    (src.goroutineleak && typeof src.goroutineleak === 'object')
  );
  if (!hasPayload) return base;
  if (src.ok === false && topVerdictRaw !== 'unavailable' && topVerdictRaw !== 'bypass' && !(src.summary && typeof src.summary === 'object')) {
    return base;
  }

  var eng = src.engine && typeof src.engine === 'object' ? src.engine : {};
  var sum = src.summary && typeof src.summary === 'object' ? src.summary : {};
  var bpf = src.bpf_maps && typeof src.bpf_maps === 'object' ? src.bpf_maps : {};
  var off = src.offload_guard && typeof src.offload_guard === 'object' ? src.offload_guard : {};
  var glk = src.goroutineleak && typeof src.goroutineleak === 'object' ? src.goroutineleak : null;
  var devs = Array.isArray(src.devices) ? src.devices : [];

  var normDevs = [];
  var hitCnt = 0, idleCnt = 0, unavailCnt = 0, errCnt = 0, bypassDevCnt = 0, appTotal = 0;
  var devBypassReasons = [];

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
      var aClassId = dpvStr(a.class_id || a.classid, '—');
      var aParent = dpvStr(a.parent_class_id || a.parent, classId !== '—' ? classId : '—');
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
        class_present: a.class_present === true,
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
    else if (vMeta.key === 'unavailable') unavailCnt++;
    else {
      errCnt++;
      if (vMeta.key === 'bypass' || vMeta.key === 'bypass_offload') {
        bypassDevCnt++;
        var bTxt = dpvStr(d.guidance_cn || d.guidance || d.reason, '');
        if (bTxt && devBypassReasons.indexOf(bTxt) < 0) devBypassReasons.push(bTxt);
      }
    }
    appTotal += normApps.length;

    normDevs.push({
      mac: dpvStr(d.mac, '—'),
      name: dpvStr(d.name, dpvStr(d.mac, '受控设备 #' + (i + 1))),
      ip: dpvStr(d.ip, '—'),
      online: d.online === true,
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
      reason: dpvStr(d.reason || d.reason_cn || d.detail, ''),
      fix: dpvStr(d.fix || d.guidance_cn || d.guidance, ''),
      guidance_paths: dpvExtractGuidancePaths(d, null, null),
      app_classes: normApps
    });
  }

  var engineMode = dpvStr(src.engine_mode || eng.mode, 'unknown');
  var engineLabel = dpvStr(
    eng.label,
    engineMode === 'shell_compat'
      ? 'tc -s 兼容解析引擎'
      : (engineMode === 'go_native_netlink' ? 'Go 原生 RTNetlink 统计引擎' : (engineMode === 'unknown' ? '引擎未上报' : engineMode))
  );
  var low16Known = typeof src.netd_low16_protected === 'boolean' || typeof eng.netd_low16_preserved === 'boolean';
  var low16Protected = typeof src.netd_low16_protected === 'boolean'
    ? src.netd_low16_protected
    : (eng.netd_low16_preserved === true);
  var markLayout = dpvStr(src.mark_layout, '');
  var fwmarkMask = markLayout.indexOf('0xffff0000') !== -1
    ? '0xffff0000'
    : dpvStr(eng.fwmark_mask, low16Protected ? '0xffff0000' : (markLayout || '—'));
  var ipv6Quic = typeof src.ipv6_quic_controlled === 'boolean'
    ? src.ipv6_quic_controlled
    : (sum.quic_guard_dualstack === true);

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

  var rawOverall = dpvStr(topVerdictRaw || sum.overall_status || sum.health, '').toLowerCase();
  if (rawOverall === 'healthy') rawOverall = 'ok';
  if (rawOverall === 'error') rawOverall = 'fail';
  if (rawOverall === 'bypass_offload') rawOverall = 'bypass';
  var isUnavailable = rawOverall === 'unavailable' || (ctrlTotal === 0 && unavailCnt > 0) || (src.available === false);
  var isBypass = rawOverall === 'bypass' || bypassDevCnt > 0 || src.bypass_detected === true || off.bypass_detected === true;
  if (isUnavailable) rawOverall = 'unavailable';
  else if (isBypass && rawOverall !== 'fail') rawOverall = 'bypass';
  else if (rawOverall !== 'ok' && rawOverall !== 'idle' && rawOverall !== 'warn' && rawOverall !== 'fail') {
    rawOverall = bypassMissingCount > 0 ? 'warn' : (hittingCount > 0 ? 'ok' : 'idle');
  }

  var hsActive = typeof src.hotspot_active === 'boolean'
    ? src.hotspot_active
    : ((typeof S === 'object' && S && S.hotspot && typeof S.hotspot.active === 'boolean') ? S.hotspot.active : false);

  var unavailReason = dpvStr(
    src.unavailable_reason || src.reason_cn || src.reason_zh || src.reason || src.detail || src.error || sum.reason || (isUnavailable ? sum.headline : ''),
    isUnavailable ? '当前内核接口、Netlink 权限或热点队列状态暂不可读' : ''
  );
  var reasonCode = dpvStr(src.reason_code || sum.reason_code, '');

  var bypassGuidance = dpvStr(
    src.bypass_guidance || src.dual_path_guidance || src.guidance_cn || src.guidance_zh || src.guidance || sum.guidance_cn || sum.guidance || off.guidance_cn || off.guidance || src.advice || (isBypass ? (src.fix || sum.fix) : ''),
    devBypassReasons.join('；')
  );
  var bypassPaths = dpvExtractGuidancePaths(src, sum, off);
  if (isBypass && !bypassPaths.length && !bypassGuidance) {
    bypassPaths = [
      '路径一（系统设置根治）：前往手机「设置 -> 连接与共享 -> 个人热点」，关闭「热点硬件加速 / WLAN 共享加速」，阻止高通 IPA / tether_limit_map 硬件快径绕过限速队列。',
      '路径二（HNC 始终兜底）：若系统界面无此开关或不便重开热点，点击下方「一键切为始终兜底」将硬件加速兜底切换为「始终」常驻压制模式。'
    ];
  }

  var defaultHeadline = isUnavailable
    ? ('数据面核验暂不可读：' + unavailReason)
    : !hsActive
      ? '当前未开启热点，开启热点后即可检验设备限速是否真实生效'
      : isBypass
        ? '检测到高通 tether_limit_map / 系统热点硬件加速绕过截流，限速流量未完整经过内核队列'
        : bypassMissingCount > 0
          ? '发现 ' + bypassMissingCount + ' 台设备的限速队列或规则异常，请点击下方「一键修复限速」'
          : hittingCount > 0
            ? '限速已真实生效：' + hittingCount + '/' + ctrlTotal + ' 台限速设备的上网流量正经过限速通道（其余 ' + idleCount + ' 台当前无流量待命）'
            : ctrlTotal > 0
              ? '全部 ' + ctrlTotal + ' 台设备的限速通道已准备就绪，设备开始上网下载后即可看到生效计数'
              : '热点运行正常，目前还没有给任何设备单独设置限速或封锁';

  var ipEntries = typeof bpf.ip_mark_entries !== 'undefined'
    ? dpvNum(bpf.ip_mark_entries, 0)
    : (dpvNum(bpf.ip_mark_v4_entries, 0) + dpvNum(bpf.ip_mark_v6_entries, 0));

  var leakSampled = glk
    ? Boolean(glk.sampled === true || glk.enabled === true)
    : false;
  var leakSupported = glk ? Boolean(glk.supported === true) : false;
  var leakLeaked = glk ? dpvNum(glk.leaked_count, 0) : 0;
  var leakStatus = glk
    ? dpvStr(glk.status, !leakSupported ? 'unsupported' : (leakLeaked > 0 ? 'leak_detected' : (leakSampled ? 'clean' : 'idle')))
    : 'idle';
  var leakObj = {
    sampled: leakSampled,
    supported: leakSupported,
    trigger: glk ? dpvStr(glk.trigger, '') : '',
    total_goroutines: glk ? dpvNum(glk.total_goroutines, 0) : 0,
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
    ok: src.ok !== false,
    sampled_ok: true,
    verdict: rawOverall,
    is_unavailable: isUnavailable,
    unavailable_reason: unavailReason,
    reason_code: reasonCode,
    is_bypass: isBypass,
    bypass_guidance: bypassGuidance,
    bypass_paths: bypassPaths,
    checked_at: dpvNum(src.checked_at, 0),
    checked_at_str: dpvFormatCheckedTime(src.checked_at, dpvStr(src.checked_at_str, '刚刚就绪')),
    iface: dpvStr(src.iface, base.iface !== '—' ? base.iface : '—'),
    hotspot_active: hsActive,
    engine_mode: engineMode,
    engine_label: engineLabel,
    mark_layout: markLayout,
    fwmark_mask: fwmarkMask,
    netd_low16_known: low16Known,
    netd_low16_protected: low16Protected,
    ipv6_quic_controlled: ipv6Quic,
    bpf_maps: {
      mac_mark_entries: dpvNum(bpf.mac_mark_entries, 0),
      ip_mark_entries: ipEntries,
      tether_limit_zeroed: bpf.tether_limit_zeroed === true,
      clsact_attached: bpf.clsact_attached === true,
      ifb_redirect_prio2: bpf.ifb_redirect_prio2 === true
    },
    offload_guard: {
      mode: dpvStr(off.mode || (typeof S === 'object' && S && S.cfg && S.cfg.clsact_bpf_mode), ''),
      slowpath_active: off.slowpath_active === true,
      tether_offload_disabled: off.tether_offload_disabled === true,
      hwnat: dpvStr(off.hwnat, 'unknown')
    },
    summary: {
      controlled_devices: ctrlTotal,
      hitting_count: hittingCount,
      idle_count: idleCount,
      unavailable_count: unavailCnt,
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
      if (!res || typeof res !== 'object') {
        throw new Error('数据面核验响应无效');
      }
      if (res.ok === false && !res.verdict && !res.summary) {
        throw new Error(res.error || '数据面核验响应无效');
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
        if (res.summary || Array.isArray(res.devices) || res.verdict) {
          return dpvNormalize(res, leakOn);
        }
        var parsed = typeof detailJSON === 'function' ? detailJSON(res) : null;
        if (parsed && (parsed.summary || Array.isArray(parsed.devices) || parsed.verdict)) {
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

function dpvRenderBypassOrUnavailBoxHtml(d, isBusy) {
  if (!d || !d.sampled_ok) return '';
  if (d.is_unavailable) {
    return '<div class="dbox" style="margin:8px 0;padding:12px 14px">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px">' +
        '<b>数据面状态暂不可读</b>' +
        '<span class="badge b-gray">不可读</span>' +
      '</div>' +
      '<div class="note" style="margin:0;color:var(--text-2)">' + dpvEsc(d.unavailable_reason || '未能读取内核 HTB / Netlink 队列状态') + '</div>' +
      (d.reason_code ? '<div class="note mono" style="margin-top:4px">原因码：' + dpvEsc(d.reason_code) + '</div>' : '') +
    '</div>';
  }
  if (!d.is_bypass) return '';
  var pathsHtml = (d.bypass_paths && d.bypass_paths.length)
    ? '<div style="display:grid;gap:6px;margin-top:6px">' + d.bypass_paths.map(function (p, idx) {
        return '<div class="note" style="margin:0;color:var(--text-1);line-height:1.5">' + (d.bypass_paths.length > 1 && !/^路径/.test(p) ? ('<b>路径 ' + (idx + 1) + '：</b>') : '') + dpvEsc(p) + '</div>';
      }).join('') + '</div>'
    : '';
  var guardMode = (d.offload_guard && d.offload_guard.mode) || (typeof S === 'object' && S && S.cfg && S.cfg.clsact_bpf_mode) || '';
  var guardAlwaysOn = guardMode === 'on' || guardMode === 'always';
  return '<div class="dbox" style="margin:8px 0;padding:12px 14px;border:1px solid rgba(255,149,0,.35);background:rgba(255,149,0,.08)">' +
    '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:4px">' +
      '<b style="color:var(--text-1)">高通 tether_limit_map / 系统热点硬件加速绕过截流告警</b>' +
      '<span class="badge b-warn">硬件快径截流</span>' +
    '</div>' +
    (d.bypass_guidance ? '<div class="note" style="margin:0;color:var(--text-1);line-height:1.5;white-space:pre-line">' + dpvEsc(d.bypass_guidance) + '</div>' : '') +
    pathsHtml +
    '<div class="dpv-actions" style="margin-top:10px">' +
      '<button type="button" class="dpv-btn dpv-btn-warn press" data-dpv-act="offload-guard-always"' + (isBusy ? ' disabled' : '') + '>' +
        DPV_ICONS.repair +
        '<span>' + (isBusy && DPV_STATE.guardSwitching ? '正在切换为始终兜底…' : (guardAlwaysOn ? '重新执行始终兜底压制' : '一键切为始终兜底')) + '</span>' +
      '</button>' +
    '</div>' +
  '</div>';
}

function dpvDiagRowHtml() {
  var d = dpvNormalize(DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var s = d.summary;
  var maskSummary = !d.netd_low16_known
    ? '路由标记待核验'
    : (d.netd_low16_protected
        ? '与系统路由互不冲突'
        : '存在系统网络标记冲突 (' + dpvEsc(d.mark_layout || '未保护') + ')');
  var sub = !d.sampled_ok
    ? '尚未检验 · 点击查看并核对每台设备的限速生效情况'
    : (d.is_unavailable
        ? ('暂不可读 · ' + dpvEsc(d.unavailable_reason))
        : (d.is_bypass
            ? '检测到系统热点硬件加速绕过截流 · 点开查看双路径指引或一键兜底'
            : ('已设限速 ' + dpvInt(s.controlled_devices) + ' 台 · 正在生效 ' + dpvInt(s.hitting_count) + ' 台 · ' + maskSummary)));
  var icoTone = !d.sampled_ok || d.is_unavailable
    ? 'gray'
    : (d.is_bypass || s.bypass_or_missing_count > 0 || (d.netd_low16_known && !d.netd_low16_protected) ? 'orange' : 'blue');
  return '<button type="button" class="row" data-dpv-act="sheet" data-dpv-diag-row="1">' +
    gi(icoTone, 'gauge') +
    '<span class="tx"><div class="t">每台设备限速生效明细</div><div class="s">' + sub + '</div></span>' +
    '<span class="hint-a">查看明细</span></button>';
}

function dpvRenderCardHtml(data, isBusy) {
  var d = dpvNormalize(data || DPV_STATE.lastData, DPV_STATE.leakEnabled);
  var sum = d.summary;
  var bpf = d.bpf_maps;
  var off = d.offload_guard;
  var sampled = Boolean(d.sampled_ok);
  var kpiReady = sampled && !d.is_unavailable;
  var markLayout = d.mark_layout;
  var low16Known = Boolean(d.netd_low16_known);
  var low16Protected = Boolean(d.netd_low16_protected);

  var hwnatLow = String(off.hwnat || '').toLowerCase();
  var hwnatSkipped = hwnatLow === 'skipped_qcom' || hwnatLow === 'skipped_not_mtk' || hwnatLow === 'n/a';
  var offloadHealthy = kpiReady && !d.is_bypass && (off.tether_offload_disabled || off.slowpath_active || hwnatSkipped) &&
    off.hwnat !== 'detected_no_knob' && off.hwnat !== 'failed';
  var hwnatLabel = !kpiReady
    ? '系统加速接管状态：' + (d.is_unavailable ? '不可读' : '待检验')
    : (d.is_bypass
        ? '系统硬件加速正在绕过限速'
        : (off.hwnat === 'none' || off.hwnat === 'disabled' || off.hwnat === 'suppressed'
            ? '系统硬件加速已受控（不绕过限速）'
            : hwnatSkipped
              ? '当前平台无需额外内核卸载干预'
              : '硬件加速状态：' + off.hwnat));

  var fwmarkBadgeCls = !kpiReady || !low16Known ? '' : (low16Protected ? 'dpv-chip-ok' : 'dpv-chip-warn');
  var fwmarkBadgeText = !kpiReady || !low16Known
    ? '系统网络标记隔离（' + (d.is_unavailable ? '不可读' : '待检验') + '）'
    : (low16Protected
        ? '与系统路由互不冲突 (' + dpvEsc(d.fwmark_mask) + ')'
        : '存在标记冲突 (' + dpvEsc(markLayout || '未保护') + ')');

  var hasAnomaly = kpiReady && (d.is_bypass || sum.bypass_or_missing_count > 0);
  var repairBtnCls = hasAnomaly ? 'dpv-btn dpv-btn-warn press' : 'dpv-btn dpv-btn-secondary press';
  var runLabel = isBusy && !DPV_STATE.resyncing && !DPV_STATE.guardSwitching ? '正在检验限速通道…' : '立即重新检验';
  var repairLabel = isBusy && DPV_STATE.resyncing ? '正在修复限速规则…' : '一键修复限速';

  return (
    '<div class="dpv-inline-wrap" id="dpv-settings-card" aria-label="限速真实生效检验">' +
    '  <div class="dpv-plain-intro">' +
    '    部分手机开启自带热点硬件加速后，网页里显示的限速可能会被系统底层直接绕过（俗称“假限速”）。这里通过核对每台限速设备的真实过包流量，帮您确认限速 100% 生效。' +
    (sampled ? ' <span class="note">（热点接口 ' + dpvEsc(d.iface && d.iface !== '—' ? d.iface : '未绑定接口') + ' · 检验时间 ' + dpvEsc(d.checked_at_str) + '）</span>' : '') +
    '  </div>' +
    '  <div class="dpv-kpi-grid">' +
    '    <div class="dpv-kpi-cell">' +
    '      <span class="dpv-kpi-num">' + (kpiReady ? dpvInt(sum.controlled_devices) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">已设限速设备</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (kpiReady ? 'is-hit' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (kpiReady ? dpvInt(sum.hitting_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">正在生效</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (kpiReady ? 'is-idle' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (kpiReady ? dpvInt(sum.idle_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">空闲待命</span>' +
    '    </div>' +
    '    <div class="dpv-kpi-cell ' + (hasAnomaly ? 'is-alert' : '') + '">' +
    '      <span class="dpv-kpi-num">' + (kpiReady ? dpvInt(sum.bypass_or_missing_count) : '—') + '</span>' +
    '      <span class="dpv-kpi-label">绕过/失效异常</span>' +
    '    </div>' +
    '  </div>' +
    '  <p class="dpv-verdict-line">' + dpvEsc(sum.headline) + '</p>' +
    dpvRenderBypassOrUnavailBoxHtml(d, isBusy) +
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
    '        <span class="dpv-chip ' + (kpiReady ? 'dpv-chip-primary' : '') + '">' + dpvEsc(d.engine_label) + '</span>' +
    '        <span class="dpv-chip ' + fwmarkBadgeCls + '">' + DPV_ICONS.fwmark + '<span>' + fwmarkBadgeText + '</span></span>' +
    '        <span class="dpv-chip ' + (!kpiReady ? '' : (offloadHealthy ? 'dpv-chip-ok' : 'dpv-chip-warn')) + '">' + dpvEsc(hwnatLabel) + '</span>' +
    '      </div>' +
    '      <div class="dpv-bpf-grid" role="list" aria-label="底层模块状态">' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">下行标记挂点 (clsact)</span>' +
    '          <span class="dpv-bpf-val ' + (!kpiReady ? 'is-muted' : (bpf.clsact_attached ? 'is-ok' : 'is-warn')) + '">' +
    (!kpiReady ? (d.is_unavailable ? '不可读' : '待采样') : (bpf.clsact_attached ? '正常 · ' + dpvInt(bpf.mac_mark_entries) + ' 项' : '未挂载')) +
    '          </span>' +
    '        </div>' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">上行重定向队列 (ifb0)</span>' +
    '          <span class="dpv-bpf-val ' + (!kpiReady ? 'is-muted' : (bpf.ifb_redirect_prio2 ? 'is-ok' : 'is-warn')) + '">' +
    (!kpiReady ? (d.is_unavailable ? '不可读' : '待采样') : (bpf.ifb_redirect_prio2 ? '就绪 · ' + dpvInt(bpf.ip_mark_entries) + ' 项' : dpvInt(bpf.ip_mark_entries) + ' 项')) +
    '          </span>' +
    '        </div>' +
    '        <div class="dpv-bpf-item" role="listitem">' +
    '          <span class="dpv-bpf-name">防加速绕过开关 (tether_limit)</span>' +
    '          <span class="dpv-bpf-val ' + (!kpiReady ? 'is-muted' : (bpf.tether_limit_zeroed ? 'is-ok' : 'is-warn')) + '">' +
    (!kpiReady ? (d.is_unavailable ? '不可读' : '待采样') : (bpf.tether_limit_zeroed ? '已压制防绕过' : '未清零（存在截流风险）')) +
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
    '      <div class="dpv-counter-label">下行 HTB 队列 (' + dpvEsc(iface && iface !== '—' ? iface : '未绑定接口') + ' egress' + (downObs ? ' · ' + dpvEsc(downObs) : '') + ')</div>' +
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
    (dev.guidance_paths && dev.guidance_paths.length ? '<div class="dpv-dev-fix">' + dev.guidance_paths.map(function (gp) { return '<div>' + dpvEsc(gp) + '</div>'; }).join('') + '</div>' : '') +
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
      '尚未读取数据：请点击上方「刷新实时数据」或「一键修复限速」，查看每台设备的限速通道实时流量。' +
      '</div>';
  } else if (d.is_unavailable) {
    devListHtml =
      '<div class="dpv-empty">' +
      '数据面核验暂不可读：' + dpvEsc(d.unavailable_reason || '未能读取内核 HTB / Netlink 队列状态') +
      (d.reason_code ? '（' + dpvEsc(d.reason_code) + '）' : '') +
      '</div>';
  } else if (d.devices.length === 0) {
    devListHtml =
      '<div class="dpv-empty">' +
      '目前还没有给任何热点设备设置限速、应用优先级或拉黑。给任意设备开启限速后，这里会实时展示它的限速生效流量与状态。' +
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
          ? '发现异常 ' + dpvInt(glk.leaked_count)
          : glk.sampled
            ? '运行流畅（无卡死）'
            : '待检测';

  var stacksHtml = '';
  if (leakOn && glk.preview_stacks && glk.preview_stacks.length > 0) {
    stacksHtml = '<pre class="dpv-leak-stacks">' + dpvEsc(glk.preview_stacks.join('\n\n')) + '</pre>';
  }

  var leakDescText = (leakOn && glk.sampled)
    ? ((leakErr || leakUnsupported)
        ? '后台任务共 ' + dpvInt(glk.total_goroutines) + ' 个 · 耗时 ' + dpvInt(glk.duration_ms) + ' ms — ' + dpvEsc(glk.message)
        : '后台任务共 ' + dpvInt(glk.total_goroutines) + ' 个 · 卡住泄漏 ' + dpvInt(glk.leaked_count) + ' 个 · 耗时 ' + dpvInt(glk.duration_ms) + ' ms — ' + dpvEsc(glk.message))
    : dpvEsc(glk.message);

  var plainSummaryLine = !sampled
    ? '点击下方「刷新实时数据」即可核对每台限速设备的流量是否真正经过限速通道。'
    : (d.is_unavailable
        ? ('暂不可读：' + dpvEsc(d.unavailable_reason || '未能读取内核队列状态'))
        : (d.is_bypass
            ? '检测到高通 tether_limit_map / 系统热点硬件加速正在绕过限速队列，请参考下方双路径指引处理'
            : (!d.netd_low16_known
                ? ('路由标记状态待上报 · 已登记设备地址 ' + dpvInt(bpf.mac_mark_entries) + ' 项 / IP ' + dpvInt(bpf.ip_mark_entries) + ' 项')
                : (d.netd_low16_protected
                    ? '系统网络路由与限速标记互不干扰 · ' + (d.ipv6_quic_controlled ? 'IPv4 / IPv6 双栈限速闭环正常' : '按需启用双栈 QUIC 管控') + ' · 已登记设备地址 ' + dpvInt(bpf.mac_mark_entries) + ' 项 / IP ' + dpvInt(bpf.ip_mark_entries) + ' 项'
                    : '检测到限速标记可能与手机系统网络冲突，建议点击下方「一键修复限速」自动恢复'))));

  var pipeMaskLine = !sampled || d.is_unavailable || !d.netd_low16_known
    ? '等待后端上报正交 fwmark 掩码状态'
    : (d.netd_low16_protected
        ? '设备标记 <code>0x00800000 | (mid &lt;&lt; 16)</code>（如 mid=1 → <code>0x00810000</code>，mid=5 → <code>0x00850000</code>），掩码 <code>' + dpvEsc(d.fwmark_mask) + '</code>，低 16 位 <code>0x0000ffff</code> 完整保留给 Android netd 策略路由'
        : '检测到低 16 位 netd 掩码冲突 (' + dpvEsc(d.mark_layout) + ')，建议点击「一键修复限速」恢复 <code>0xffff0000</code> 正交掩码保护');

  var hasAnomaly = sampled && !d.is_unavailable && (d.is_bypass || sum.bypass_or_missing_count > 0);
  var sheetRepairCls = 'dpv-btn dpv-btn-compact press' + (hasAnomaly ? ' dpv-btn-warn' : '');

  return (
    '<div class="dpv-sheet-body" id="dpv-sheet-root">' +
    '  <div class="dpv-pipe-banner">' +
    '    <div><strong>当前通道状态：</strong>' + plainSummaryLine + '</div>' +
    '    <details class="v6-adv-fold" style="margin-top:8px"><summary>底层技术参数（开发者）</summary>' +
    '      <div class="v6-adv-body" style="gap:4px;padding-top:6px">' +
    '        <div><strong>正交位域契约：</strong>' + pipeMaskLine + '</div>' +
    '        <div><strong>clsact / GRO 管道：</strong>eBPF 返回 <code>TC_ACT_UNSPEC (-1)</code>（prio 1 着色 → prio 2 ifb0/police 128KB 突发桶）· ' + (d.ipv6_quic_controlled ? '双栈 IPv4/IPv6 QUIC (UDP 443) 已闭环管控' : '按需启用双栈 QUIC 管控') + '</div>' +
    '        <div><strong>采集引擎状态：</strong>' + (sampled && !d.is_unavailable ? dpvEsc(d.engine_label) + ' · BPF mac_mark ' + dpvInt(bpf.mac_mark_entries) + ' 项 / ip_mark ' + dpvInt(bpf.ip_mark_entries) + ' 项' : (d.is_unavailable ? '暂不可读' : '尚未采样核验')) + '</div>' +
    '      </div>' +
    '    </details>' +
    '  </div>' +
    dpvRenderBypassOrUnavailBoxHtml(d, isBusy) +
    '  <div class="dpv-leak-box">' +
    '    <div class="dpv-leak-row">' +
    '      <div class="dpv-leak-info">' +
    '        <div class="dpv-leak-title">' +
    DPV_ICONS.leakScan +
    '<span>后台服务卡死自检（协程泄漏扫描）</span>' +
    '<span class="dpv-pill ' + leakBadgeCls + '">' + dpvEsc(leakBadgeTxt) + '</span>' +
    '        </div>' +
    '        <div class="dpv-leak-desc">' +
    leakDescText +
    '        </div>' +
    '      </div>' +
    '      <button type="button" role="switch" aria-checked="' + (leakOn ? 'true' : 'false') + '" class="dpv-switch ' + (leakOn ? 'is-on' : '') + '" data-dpv-act="toggle-leak" aria-label="切换后台服务卡死自检">' +
    '        <span class="dpv-switch-knob"></span>' +
    '      </button>' +
    '    </div>' +
    stacksHtml +
    '  </div>' +
    '  <div class="dpv-sheet-toolbar">' +
    '    <span class="dpv-sheet-count">已设限速设备明细（' + (!sampled ? '尚未检验' : (d.is_unavailable ? '状态不可读' : ('共 ' + dpvInt(d.devices.length) + ' 台 · 单应用规则 ' + dpvInt(sum.app_classes_total) + ' 个'))) + '）</span>' +
    '    <div class="dpv-sheet-actions">' +
    '      <button type="button" class="' + sheetRepairCls + '" data-dpv-act="repair"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.repair +
    '<span>' + (isBusy && DPV_STATE.resyncing ? '修复中…' : '一键修复限速') + '</span>' +
    '      </button>' +
    '      <button type="button" class="dpv-btn dpv-btn-compact press" data-dpv-act="run"' + (isBusy ? ' disabled' : '') + '>' +
    DPV_ICONS.runVerify +
    '<span>' + (isBusy && !DPV_STATE.resyncing && !DPV_STATE.guardSwitching ? '读取中…' : '刷新实时数据') + '</span>' +
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
  var maskTxt = !d.netd_low16_known
    ? '标记隔离待核验'
    : (d.netd_low16_protected
        ? '与系统路由互不冲突'
        : '存在系统网络标记冲突 (' + dpvEsc(d.mark_layout || '未保护') + ')');
  var titleTxt = !sampled
    ? '限速真实生效检验：待检验'
    : (d.is_unavailable
        ? '限速真实生效检验：暂不可读'
        : (d.is_bypass
            ? '限速真实生效检验：检测到系统加速绕过截流'
            : ('限速真实生效检验：' + dpvInt(sum.hitting_count) + ' / ' + dpvInt(sum.controlled_devices) + ' 台设备正在生效')));
  var subTxt = !sampled
    ? '点击右侧「核验明细」查看每台设备的限速过包情况'
    : (d.is_unavailable
        ? dpvEsc(d.unavailable_reason || '未能读取内核队列状态')
        : (d.is_bypass
            ? '高通 tether_limit_map / 热点硬件加速截流中 · 点击右侧查看双路径指引与一键兜底'
            : (maskTxt + ' · ' + (d.bpf_maps.clsact_attached ? '底层分流已就绪' : '底层分流待挂载'))));
  return (
    '<div class="dpv-selfcheck-bar" data-dpv-selfcheck="1">' +
    '  <div class="dpv-selfcheck-left">' +
    DPV_ICONS.dataplane +
    '    <div>' +
    '      <div class="dpv-selfcheck-title">' + titleTxt + '</div>' +
    '      <div class="dpv-selfcheck-sub">' + subTxt + '</div>' +
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
      var hasErr2 = !dn.is_unavailable && (dn.is_bypass || dn.summary.bypass_or_missing_count > 0);
      if (subEl) {
        subEl.textContent = dn.is_unavailable
          ? ('暂不可读 · ' + (dn.unavailable_reason || '未能读取内核队列状态'))
          : dn.is_bypass
            ? '检测到高通 tether_limit_map / 系统硬件加速绕过截流 · 点开一键兜底'
            : hasErr2
              ? ('发现 ' + dpvInt(dn.summary.bypass_or_missing_count) + ' 台设备限速可能被绕过 · 点开一键修复')
              : ('已设限速 ' + dpvInt(dn.summary.controlled_devices) + ' 台 · 正在生效 ' + dpvInt(dn.summary.hitting_count) + ' 台 · 未被硬件加速绕过');
      }
      if (bdgEl) {
        bdgEl.className = 'badge ' + (dn.is_unavailable ? 'b-gray' : (hasErr2 ? 'b-warn' : (dn.summary.hitting_count > 0 ? 'b-ok' : 'b-acc')));
        bdgEl.textContent = dn.is_unavailable ? '暂不可读' : (dn.is_bypass ? '硬件截流' : (hasErr2 ? '待修复' : (dn.summary.hitting_count > 0 ? '真实生效' : '待命就绪')));
      }
    }
  }
  var sheetRoot = document.getElementById('dpv-sheet-root');
  if (sheetRoot && sheetRoot.parentNode) {
    var openSheetAdv = !!sheetRoot.querySelector('.v6-adv-fold[open]');
    var html = dpvRenderSheetContentHtml(DPV_STATE.lastData, DPV_STATE.loading);
    if (typeof morphOuter === 'function') {
      morphOuter(sheetRoot, html);
    } else {
      sheetRoot.outerHTML = html;
    }
    if (openSheetAdv) {
      var newRoot = document.getElementById('dpv-sheet-root');
      var af = newRoot && newRoot.querySelector('.v6-adv-fold');
      if (af) af.open = true;
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
  var title = '每台设备限速生效明细';
  var contentHtml = dpvRenderSheetContentHtml(DPV_STATE.lastData, DPV_STATE.loading);
  DPV_STATE.sheetOpen = true;
  if (typeof sheet === 'function' && typeof document !== 'undefined' && document.getElementById('sheet')) {
    sheet(
      '<h3>' + dpvEsc(title) + '</h3>' +
      '<div class="sub">实时核对每台限速设备的上下行过包流量，确认限速规则真实生效、未被系统加速绕过</div>' +
      contentHtml +
      '<button type="button" class="btn sec wide press" data-close style="margin-top:12px">关闭</button>',
      { tall: true, kind: 'dpv', onClose: function () { DPV_STATE.sheetOpen = false; } }
    );
    return;
  }
}

function dpvSetOffloadGuardAlways() {
  if (DPV_STATE.loading) return Promise.resolve(DPV_STATE.lastData);
  var mySeq = ++DPV_STATE.seq;
  DPV_STATE.loading = true;
  DPV_STATE.resyncing = false;
  DPV_STATE.guardSwitching = true;
  dpvRefreshRenderedViews();

  return api.action('clsact_mode_set', { mode: 'on' }, { timeout: 30000, maxTime: 28 }).then(function (r) {
    var g = typeof detailJSON === 'function' ? detailJSON(r) : null;
    if (typeof S === 'object' && S && S.cfg) {
      S.cfg.clsact_bpf_mode = 'on';
      if (g && typeof g === 'object') S.cfg.offload_guard = g;
      S.clsact = null;
    }
    return Promise.all([
      typeof loadConfig === 'function' ? loadConfig().catch(function () {}) : Promise.resolve(),
      typeof loadOffload === 'function' ? loadOffload().catch(function () {}) : Promise.resolve(),
      dpvRunVerifyAction(DPV_STATE.leakEnabled, false)
    ]);
  }).then(function (arr) {
    var norm = arr && arr[2] ? arr[2] : dpvDefaultData(DPV_STATE.leakEnabled);
    if (mySeq === DPV_STATE.seq) {
      DPV_STATE.lastData = norm;
      DPV_STATE.loading = false;
      DPV_STATE.guardSwitching = false;
      dpvRefreshRenderedViews();
      if (typeof S === 'object' && S && S.page === 'settings' && typeof renderSettings === 'function') {
        renderSettings(false);
      }
      if (typeof toast === 'function') {
        toast(
          norm.is_bypass
            ? '已切换为始终兜底模式，若系统硬件快径仍截流请配合关闭系统热点加速开关'
            : '已切换硬件加速兜底为「始终」模式并重新核验限速状态',
          norm.is_bypass ? 'warn' : 'ok'
        );
      }
    }
    return norm;
  }).catch(function (err) {
    if (mySeq === DPV_STATE.seq) {
      DPV_STATE.loading = false;
      DPV_STATE.guardSwitching = false;
      dpvRefreshRenderedViews();
      if (typeof toast === 'function') {
        var msg = typeof errText === 'function' ? errText(err) : String((err && err.message) || err || '切换始终兜底失败');
        toast(msg, 'err');
      }
    }
    return DPV_STATE.lastData || dpvDefaultData(DPV_STATE.leakEnabled);
  });
}

function dpvTriggerVerify(runAction, resync, isManualToggle) {
  var mySeq = ++DPV_STATE.seq;
  var doResync = Boolean(runAction && resync);
  DPV_STATE.loading = true;
  DPV_STATE.resyncing = doResync;
  DPV_STATE.guardSwitching = false;
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
        if (norm.is_unavailable) {
          toast('数据面状态暂不可读：' + (norm.unavailable_reason || '请确认热点与内核状态'), 'warn');
        } else if (norm.is_bypass) {
          toast('检测到高通 tether_limit_map / 系统热点硬件加速绕过截流，请查看双路径指引或切为始终兜底', 'warn');
        } else if (doResync) {
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
    var t = typeof evEl === 'function' ? evEl(ev) : (ev && ev.target && ev.target.nodeType === 3 ? ev.target.parentNode : ev && ev.target);
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
    } else if (act === 'offload-guard-always') {
      ev.preventDefault();
      dpvSetOffloadGuardAlways();
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
    setOffloadGuardAlways: dpvSetOffloadGuardAlways,
    openVerifySheet: dpvOpenSheet,
    normalize: dpvNormalize,
    formatMarkHex: dpvFormatMarkHex,
    hasBadToken: dpvHasBadToken,
    renderCardHtml: dpvRenderCardHtml,
    renderSheetHtml: dpvRenderSheetContentHtml,
    renderSelfCheckSummaryHtml: dpvRenderSelfCheckSummaryHtml
  };
}

/* ═══ 配置保险箱 · 导出全量快照与原子恢复 (/api/backup) ═══ */
var SET_VAULT_BOUND = false;
function setVaultSyncMeta(sha, cnt, restored) {
  if (sha != null) SET_VAULT.lastSha = String(sha || '');
  if (cnt != null) SET_VAULT.lastCount = Math.max(0, Math.round(num(cnt, 0)));
  if (restored != null) SET_VAULT.lastRestored = Math.max(0, Math.round(num(restored, 0)));
  if (typeof window !== 'undefined' && window.V6 && window.V6.vault && typeof window.V6.vault === 'object') {
    if (sha != null) window.V6.vault.last_sha256 = SET_VAULT.lastSha;
    if (cnt != null) window.V6.vault.last_file_count = SET_VAULT.lastCount;
    if (restored != null) window.V6.vault.last_restored = SET_VAULT.lastRestored;
  }
}
function setVaultExport(btn) {
  var p = api.get('/api/backup', null, { timeout: 10000 }).then(function (res) {
    if (!res || typeof res !== 'object' || res.ok === false || !res.files) {
      throw new Error((res && res.error) || '备份导出载荷无效');
    }
    var verTag = String(res.module_version || 'v6.1.0-rc.5').replace(/[^a-zA-Z0-9._-]+/g, '-');
    var tsTag = Math.floor(Date.now() / 1000);
    var fn = 'hnc-backup-' + verTag + '-' + tsTag + '.json';
    var raw = JSON.stringify(res, null, 2);
    var sha = String(res.sha256 || '');
    var cnt = num(res.file_count, Object.keys(res.files || {}).length);
    setVaultSyncMeta(sha, cnt, null);
    if (S.page === 'settings') renderSettings(false);
    if (KSU && !window.__HNC_MOCK_META) {
      var base = (typeof API_BASE === 'string' && API_BASE) ? API_BASE : 'http://127.0.0.1:8765';
      return shell('mkdir -p /sdcard/Download && curl -fsSL ' + sq(base + '/api/backup?download=1') + ' -o ' + sq('/sdcard/Download/' + fn) + ' && echo ok').then(function () {
        toast('配置快照已存到 /sdcard/Download/' + fn + (sha ? ' · SHA256 ' + sha.slice(0, 8) + '…' : ''));
      }, function () {
        sheet('<h3>配置保险箱快照</h3><div class="sub">' + esc(fn) + (sha ? ' · SHA256 ' + esc(sha.slice(0, 12)) + '…' : '') + '</div>' +
          '<textarea class="textarea" readonly id="sv-exp-txt">' + esc(raw) + '</textarea>' +
          '<div class="btns" style="margin-top:12px"><button class="btn sec press" data-close>关闭</button><button class="btn pri press" id="sv-exp-copy">复制 JSON</button></div>', { tall: true });
        var cpBtn = $('#sv-exp-copy');
        if (cpBtn) cpBtn.onclick = function () { copyText(raw).then(function (ok) { toast(ok ? '已复制整机备份 JSON' : '复制失败', ok ? 'ok' : 'err'); }); };
      });
    }
    var downloaded = false;
    try {
      var blob = new Blob([raw], { type: 'application/json;charset=utf-8' });
      var u = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = u;
      a.download = fn;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(u); }, 3000);
      downloaded = true;
    } catch (_) {}
    if (downloaded) {
      toast('配置快照已导出 · ' + fn + (sha ? ' · SHA256 ' + sha.slice(0, 8) + '…' : ''));
    } else {
      copyText(raw).then(function (ok) {
        toast(ok ? '已复制备份快照到剪贴板 · ' + cnt + ' 项配置' : '浏览器不支持直接下载，请检查权限', ok ? 'ok' : 'warn');
      });
    }
  }).catch(function (e) {
    toast('导出配置快照失败：' + errText(e), 'err');
  });
  return btn ? busyWhile(btn, p) : p;
}
function setVaultParseBundle(txt) {
  var s = String(txt || '').trim();
  if (!s) throw new Error('请先选择备份 JSON 文件或粘贴快照内容');
  if (s.length > 4 * 1024 * 1024) throw new Error('备份文件超过 4 MB 上限');
  var parsed;
  try { parsed = JSON.parse(s); } catch (e) { throw new Error('备份 JSON 语法错误：' + e.message); }
  if (!parsed || typeof parsed !== 'object' || !parsed.files || typeof parsed.files !== 'object') {
    throw new Error('不是有效的 HNC 整机备份快照（缺少 files 清单）');
  }
  if (!parsed.sha256 || typeof parsed.sha256 !== 'string') {
    throw new Error('备份快照缺少 SHA256 完整性摘要');
  }
  return parsed;
}
function setVaultConfirmAndRestore(parsed, srcLabel) {
  var cnt = num(parsed.file_count, Object.keys(parsed.files || {}).length);
  var sha = String(parsed.sha256 || '');
  var ver = String(parsed.module_version || '未知版本');
  return confirmSheet(
    '原子恢复整机配置？',
    '即将校验并恢复备份快照' + (srcLabel ? '（<b>' + esc(srcLabel) + '</b>）' : '') + '：<br>' +
    '· 来源版本：<b>' + esc(ver) + '</b> · 共 <b>' + cnt + '</b> 项配置<br>' +
    '· SHA256：<span class="mono">' + esc(sha.slice(0, 16)) + '…</span><br><br>' +
    '后端将在完整校验单文件与总表 SHA256 及业务护栏后原子替换配置（当前远程登录会话与热点密码不会被清空）。',
    '校验并恢复',
    { safe: false }
  ).then(function (ok) {
    if (!ok) return false;
    return api.post('/api/backup', parsed, { timeout: 12000 }).then(function (res) {
      if (res && res.ok === false) throw new Error(res.error || '配置恢复失败');
      var restoredCnt = num(res && res.restored_count, cnt);
      setVaultSyncMeta(res && res.sha256 ? res.sha256 : sha, cnt, restoredCnt);
      toast('整机配置已原子恢复 · 共 ' + restoredCnt + ' 项生效');
      return Promise.all([
        typeof loadSettingsData === 'function' ? loadSettingsData().catch(function () {}) : null,
        typeof globalRefresh === 'function' ? Promise.resolve(globalRefresh()).catch(function () {}) : null
      ]).then(function () {
        if (S.page === 'settings') renderSettings(false);
        return true;
      });
    }).catch(function (e) {
      toast('恢复整机配置失败：' + errText(e), 'err');
      return false;
    });
  });
}
function setVaultOpenImportSheet() {
  sheet(
    '<h3>恢复整机配置</h3>' +
    '<div class="sub">选择之前导出的 <code>hnc-backup-*.json</code> 快照文件，或直接将备份 JSON 粘贴到下方。恢复前会自动校验 SHA256 完整性。</div>' +
    '<button type="button" class="btn sec wide press" id="sv-pick-btn" style="margin-bottom:10px">' + ico('doc') + '选择本地备份 JSON 文件</button>' +
    '<textarea class="textarea" id="sv-paste-txt" rows="6" placeholder="或直接在此粘贴整机备份 JSON 内容…"></textarea>' +
    '<div class="btns" style="margin-top:12px"><button type="button" class="btn sec press" data-close>取消</button><button type="button" class="btn pri press" id="sv-apply-btn">校验并恢复</button></div>',
    { kind: 'set-vault-import' }
  );
  var pickBtn = $('#sv-pick-btn'), applyBtn = $('#sv-apply-btn');
  if (pickBtn) {
    pickBtn.onclick = function () {
      var fi = $('#set-vault-file');
      if (fi) { fi.value = ''; fi.click(); }
    };
  }
  if (applyBtn) {
    applyBtn.onclick = function () {
      var ta = $('#sv-paste-txt');
      var parsed;
      try { parsed = setVaultParseBundle(ta ? ta.value : ''); }
      catch (e) { toast(errText(e), 'err'); return; }
      setVaultConfirmAndRestore(parsed, '粘贴的快照');
    };
  }
}
function setVaultBindGlobalDelegate() {
  if (SET_VAULT_BOUND || typeof document === 'undefined') return;
  SET_VAULT_BOUND = true;
  document.addEventListener('click', function (ev) {
    var t = ev.target && ev.target.closest ? ev.target.closest('[data-set-vault]') : null;
    if (!t) return;
    ev.preventDefault();
    var act = t.getAttribute('data-set-vault');
    if (act === 'export') setVaultExport(t);
    else if (act === 'import') setVaultOpenImportSheet();
  });
  document.addEventListener('change', function (ev) {
    var fi = ev.target;
    if (!fi || fi.id !== 'set-vault-file') return;
    var file = fi.files && fi.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      toast('备份文件超过 4 MB 上限', 'err');
      fi.value = '';
      return;
    }
    var fname = String(file.name || 'hnc-backup.json');
    var fr = new FileReader();
    fr.onload = function () {
      fi.value = '';
      var parsed;
      try { parsed = setVaultParseBundle(String(fr.result || '')); }
      catch (e) { toast(errText(e), 'err'); return; }
      setVaultConfirmAndRestore(parsed, fname);
    };
    fr.onerror = function () {
      fi.value = '';
      toast('读取备份文件失败', 'err');
    };
    fr.readAsText(file);
  });
}
setVaultBindGlobalDelegate();
