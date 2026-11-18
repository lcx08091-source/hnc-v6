/* HNC WebUI · apps.js —— v5.38.0 应用区重构: 「活跃应用」(热点+本机) + 「应用规则中心」(五合一规则收口)
 * 注: selfStudioCardHtml 保留在此文件供「分析 → DPI 与自训」直接调用(经典全局脚本同作用域)。 */
'use strict';

var APP_COLORS = ['#007AFF', '#FF2D55', '#34C759', '#FF9500', '#AF52DE', '#5856D6', '#00C7BE', '#FF3B30', '#32ADE6', '#A2845E'];
function appColor(s) { var h = 0; s = String(s || ''); for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return APP_COLORS[Math.abs(h) % APP_COLORS.length]; }
function appName(a, uid) { return (a.display_name && a.display_name.trim()) || (a.pkg ? a.pkg.split('.').slice(-1)[0] : 'uid ' + uid); }
S.studio = null; S.studioRecipeOpen = false;
if (S.appsSub !== 'active' && S.appsSub !== 'rules') S.appsSub = 'active';

function studioCurMode() {
  var st = S.studio || {}, cap = st.capture || {}, self = S.self || {};
  if (cap.mode === 'smart_screen' || cap.mode === 'lease_15m' || cap.mode === 'off') return cap.mode;
  if (num(cap.lease_rem_sec) > 0) return 'lease_15m';
  return (cap.enabled || self.enabled) ? 'smart_screen' : 'off';
}

function loadApps() {
  return Promise.all([
    api.get('/api/dpi_state', null, { timeout: 9000 }).then(function (r) { S.dpi = r; S.self = r && r.available && r.state ? (r.state.self || null) : null; }).catch(function (e) { S.dpiErr = errText(e); }),
    api.getSafe('/api/self/studio', null, null).then(function (r) {
      if (!r) return;
      S.studio = r;
      if (r.capture) {
        S.selfCfg = {
          enabled: r.capture.enabled !== false,
          auto_expand_enabled: r.capture.auto_expand_enabled !== false,
          auto_promote_enabled: r.capture.auto_promote_enabled !== false
        };
        if (Array.isArray(r.capture.active_ifaces) && r.capture.active_ifaces.length) {
          S.selfIfaces = {
            enabled: r.capture.enabled !== false,
            ap_iface: (S.hotspot && S.hotspot.iface) || 'wlan2',
            ifaces: r.capture.active_ifaces.map(function (x) { return { name: x.name, rx_bytes: num(x.rx_bytes), eligible: true }; })
          };
        }
      }
    }),
    typeof loadAppUsage === 'function' ? loadAppUsage(1) : Promise.resolve(),
    typeof loadDisc === 'function' ? loadDisc() : Promise.resolve()
  ]).then(function () {
    if (!S.studio) {
      return Promise.all([
        api.getSafe('/api/self', null, {}).then(function (r) { S.selfCfg = r || {}; }),
        api.getSafe('/api/self/ifaces', null, null).then(function (r) { S.selfIfaces = r; })
      ]);
    }
  }).then(paintAppsDot);
}

/* 本机真值常驻自训工作台 —— 已迁入「分析 → DPI 与自训」统一承载 */
function selfStudioCardHtml() {
  var st = S.studio || {}, self = S.self || {}, cap = st.capture || {}, cnt = st.counters || {}, lease = st.lease || {};
  var mode = studioCurMode();
  var remSec = num(cap.lease_rem_sec, lease.remaining_sec);
  var leaseOn = mode === 'lease_15m' && remSec > 0;
  var remMin = leaseOn ? Math.max(1, Math.ceil(remSec / 60)) : 0;
  var screenOn = cap.screen_on !== false;
  var capNow = cap.capturing_now != null ? !!cap.capturing_now : (mode !== 'off' && (mode === 'lease_15m' || screenOn));
  var smp = num(cnt.samples_written, st.samples_today);
  var appCnt = num(cnt.user_apps, st.samples_apps);
  var fpUse = num(cnt.usable_fps, st.usable_fp);
  var protoApps = num(st.prototype_apps, (st.last_distill && st.last_distill.prototype_apps) || appCnt);
  var domCnt = num(cnt.expanded_rules, st.auto_expanded_rules) + num(cnt.promoted_rules, st.auto_promoted_rules) + num(cnt.candidate_high, self.candidate_high);
  var suCnt = num(cnt.usable_startups, st.usable_startup);
  var ifList = [];
  if (Array.isArray(cap.active_ifaces) && cap.active_ifaces.length) {
    ifList = cap.active_ifaces.map(function (x) { return x.name; });
  } else if (S.selfIfaces && Array.isArray(S.selfIfaces.ifaces)) {
    ifList = S.selfIfaces.ifaces.filter(function (x) { return x.eligible; }).map(function (x) { return x.name; });
  }
  var ifTxt = ifList.length ? ifList.slice(0, 3).join(' + ') : 'wlan0 + rmnet_data*';
  var badge = leaseOn
    ? '<span class="badge b-ok studio-live-pill"><span class="breathe" style="width:6px;height:6px;margin-right:4px"></span>15m 集中快训 · 剩 ' + remMin + ' 分钟</span>'
    : mode === 'smart_screen'
      ? (capNow
          ? '<span class="badge b-ok studio-live-pill"><span class="breathe" style="width:6px;height:6px;margin-right:4px"></span>亮屏常驻采集中 · 熄屏自动蒸馏</span>'
          : '<span class="badge b-acc">熄屏静默休眠 · 0 轮询耗电</span>')
      : '<span class="badge b-gray">自训练已关闭 · 0 唤醒</span>';
  var recipe = S.studioRecipeOpen ? (
    '<div class="studio-recipe">' +
      '<div class="studio-step"><b>1</b><span><b>零样本即刻生效</b>：无任何本机样本时，8 跳 DNS CNAME 专属链回溯与 120ms 门控时间因果突发传播（<span class="mono">CausalBurstEngine</span>）自动覆盖并发无 SNI / ECH 流。</span></div>' +
      '<div class="studio-step"><b>2</b><span><b>1~3 条极少样本原型激活</b>：告别旧版 ≥50 条高门槛，IDF-Jaccard 离散栈特征 + 8 包归一化 SPLT 余弦质心（<span class="mono">PrototypeStore</span>）冷启动 1~2 次即可建立专属应用原型。</span></div>' +
      '<div class="studio-step"><b>3</b><span><b>亮屏常驻零耗电</b>：亮屏无感采集双路 <span class="mono">/proc/net</span> UID 真值，熄屏 25 秒自动增量蒸馏去瞬态 <span class="mono">TLSFP + QUICGeom</span> 指纹并热同步热点。</span></div>' +
    '</div>'
  ) : '';
  var c = S.selfCfg || {};
  return '<div class="glass studio-card' + (capNow ? ' is-recording' : '') + '" id="studio-card" data-mkey="studio-card">' +
    '<div class="studio-head">' +
      '<span class="studio-orb">' + studioSvg('prism') + '</span>' +
      '<div class="studio-title-wrap">' +
        '<div class="studio-title-row"><b>本机真值常驻自训工作台</b>' + badge + '</div>' +
        '<div class="studio-sub">亮屏无感采训 + 熄屏自动蒸馏 · K≥1 少样本 IDF-Jaccard/SPLT 原型与 TLSFP 稳定栈引擎</div>' +
      '</div>' +
    '</div>' +
    '<div class="studio-mode-bar">' +
      seg('studio-mode', [['smart_screen', '亮屏智能常驻'], ['lease_15m', '15m 集中快训'], ['off', '关闭']], mode, 'small') +
    '</div>' +
    '<div class="studio-metrics">' +
      '<div class="studio-m"><span class="l">累计真值样本</span><b class="num">' + smp + '</b><small>' + (appCnt ? appCnt + ' 个本机应用' : 'UID 精确对齐') + '</small></div>' +
      '<div class="studio-m"><span class="l">少样本应用原型</span><b class="num">' + (protoApps || fpUse) + '</b><small>专属栈 ' + fpUse + ' · K≥1 即生效</small></div>' +
      '<div class="studio-m"><span class="l">冷启动与扩展规则</span><b class="num">' + (suCnt + domCnt) + '</b><small>启动 ' + suCnt + ' · 域名 ' + domCnt + '</small></div>' +
      '<div class="studio-m"><span class="l">双路真值网卡</span><b class="mono" style="font-size:12.5px">' + esc(ifTxt) + '</b><small>inotify 零轮询唤醒</small></div>' +
    '</div>' +
    (st.last_distill && st.last_distill.ts ? '<div class="note" style="margin-top:4px">最近蒸馏：' + esc(ago(st.last_distill.ts)) + ' · 扫描 ' + num(st.last_distill.samples_read) + ' 条样本 · 专属指纹 ' + num(st.last_distill.exclusive_fps) + ' 个 · 少样本原型 ' + num(st.last_distill.prototype_apps, protoApps) + ' 个</div>' : '') +
    '<div class="studio-actions">' +
      '<button type="button" class="btn pri press" data-act="studio-distill">立即蒸馏并同步热点</button>' +
      '<button type="button" class="btn sec press" data-act="studio-export">导出规则包</button>' +
      '<button type="button" class="linkish studio-guide-btn" data-act="studio-recipe">' + (S.studioRecipeOpen ? '收起引擎说明' : '零/少样本引擎说明') + '</button>' +
    '</div>' +
    recipe +
    '<div style="border-top:1px solid var(--divider);margin-top:8px;padding-top:8px;display:grid;gap:6px">' +
      '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t" style="font-size:13px">已知应用新子域自动扩展</div><div class="s">同一应用命中 ≥10 次的新子域自动扩进本机规则</div></span>' + toggle(c.auto_expand_enabled !== false, 'data-selftog="auto_expand/toggle" aria-label="自动扩展规则"') + '</div>' +
      '<div class="row" style="padding:4px 0;min-height:0"><span class="tx"><div class="t" style="font-size:13px">高置信独占主域名自动晋级</div><div class="s">关闭时仅在「应用 → 应用规则中心」待你一键审核</div></span>' + toggle(c.auto_promote_enabled !== false, 'data-selftog="auto_promote/toggle" aria-label="HIGH 自动晋级"') + '</div>' +
    '</div>' +
  '</div>';
}

function rulesPendingCount() {
  var discN = S.disc && Array.isArray(S.disc.groups) ? S.disc.groups.length : 0;
  var candN = S.self ? num(S.self.candidate_high) : 0;
  return discN + candN;
}

function paintAppsDot() {
  var on = rulesPendingCount() > 0;
  $$('.tab[data-tab="apps"] .dot').forEach(function (d) { d.hidden = !on; });
}

function appRows() {
  var m = (S.self && S.self.apps_by_uid) || {};
  return Object.keys(m).map(function (u) { var a = m[u]; return { uid: u, a: a, name: appName(a, u), bytes: num(a.rx_bytes) + num(a.tx_bytes) }; })
    .sort(function (x, y) { return (num(y.a.active_conns) - num(x.a.active_conns)) || (y.bytes - x.bytes) || (num(y.a.last_seen) - num(x.a.last_seen)); });
}

function renderApps(anim1) {
  if (S.appsSub !== 'active' && S.appsSub !== 'rules') S.appsSub = 'active';
  var self = S.self, rows = appRows(), active = rows.filter(function (r) { return num(r.a.active_conns) > 0; }).length;
  var au = S.appUsage && S.appUsage[1] && S.appUsage[1].d;
  var hsAppCnt = au && Array.isArray(au.by_app) ? au.by_app.filter(function (a) { return a.id && a.id.charAt(0) !== '_'; }).length : 0;
  var pend = rulesPendingCount();
  var st = !self ? ['待连接', 'var(--text-3)'] : self.enabled ? ['采集中', 'var(--badge-ok)'] : ['休眠中', 'var(--accent)'];
  var foot = '热点今日识别 ' + hsAppCnt + ' 个应用 · 本机活跃 ' + active + ' 个应用 · 自训工作台已整合至「分析 → DPI 与自训」';

  var h = '<div class="wrap">' +
    '<div class="glass ahero"><div class="stats">' +
      '<div><div class="l">热点今日应用</div><div class="v num">' + hsAppCnt + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">本机活跃应用</div><div class="v num">' + active + (rows.length > active ? '<small style="font-size:12px;color:var(--text-3)"> / ' + rows.length + '</small>' : '') + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">待确认新规则</div><div class="v num" style="color:' + (pend ? 'var(--orange)' : 'var(--text-1)') + '">' + pend + '</div></div><div class="hero-div"></div>' +
      '<div><div class="l">本机归因</div><div class="v" style="color:' + st[1] + '">' + st[0] + '</div></div></div>' +
      '<div class="foot2"><span class="breathe' + (self && self.enabled ? '' : ' off') + '"></span><span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + foot + '</span></div></div>' +
    seg('apps-sub', [['active', '活跃应用'], ['rules', '应用规则中心' + (pend ? ' · ' + pend : '')]], S.appsSub) +
    '<div class="subview" id="apps-sub">' + appsSub() + '</div></div>';

  var p = $('#p-apps'); if (!anim1 && p.firstElementChild) morph(p, h); else p.innerHTML = h; placeSegs(p);
  if (anim1) stagger($('.wrap', p));
  if (S.appsSub === 'rules') {
    if (typeof paintUnknown === 'function') paintUnknown();
    if (S.open.fpl && typeof loadFP === 'function') loadFP();
    if (S.open.rpack && typeof loadRulepack === 'function') loadRulepack();
  }
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

function selfConnSheet() {
  sheet('<h3>本机连接明细</h3><div class="sub">这台手机自己此刻的连接 · 按 App 分组</div><div id="sc-body"><div class="note">加载中…</div></div><button class="btn sec wide press" data-close style="margin-top:12px">关闭</button>', { tall: true });
  api.get('/api/self/attrib', { latest: 1, limit: 1 }, { timeout: 9000 }).then(function (r) {
    var el = $('#sc-body'); if (!el) return;
    var conns = r.conns || [], names = {}, by = {};
    var au = (S.self && S.self.apps_by_uid) || {};
    Object.keys(au).forEach(function (k) { var a = au[k]; if (a && a.pkg) names[a.pkg] = a.display_name || a.pkg; });
    conns.forEach(function (c) { var k = c.pkg || ('uid ' + c.uid); (by[k] = by[k] || []).push(c); });
    var keys = Object.keys(by).sort(function (a, b) { return by[b].length - by[a].length; });
    if (!keys.length) { el.innerHTML = '<div class="note" style="text-align:center;padding:16px 0">' + (r.note ? '本机流量追踪还没有数据（可在「分析 → DPI 与自训」开启常驻采样）' : '此刻没有连接') + '</div>'; return; }
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
  // ── 子页 1: 活跃应用 (热点客户端今日应用排行 + 本机运行应用归因 + 代理排除) ──
  if (S.appsSub !== 'rules') {
    var au = S.appUsage && S.appUsage[1] && S.appUsage[1].d;
    var hsHtml = (au && typeof appUsageBars === 'function' && (num(au.total_up) + num(au.total_down) > 0))
      ? '<div class="sec"><span>热点客户端活跃应用 <small>今日全设备连接表真实字节</small></span><button class="linkish" data-act="go-dpi-studio">自训与覆盖率 ›</button></div>' +
        '<div class="glass" style="padding:12px 14px">' + appUsageBars(au, 6) + '</div>'
      : '';

    var rows = appRows();
    var usr = rows.filter(function (r) { return !r.a.is_system; }), sys = rows.filter(function (r) { return r.a.is_system; });
    var mx = Math.max.apply(null, rows.map(function (r) { return r.bytes; }).concat([1]));
    var fx = (S.cfg && S.cfg.flywheel_exclude_user) || [];

    var hostHtml = !rows.length
      ? '<div class="glass empty">' + (!self ? 'dpid 暂未上报本机数据' : !self.enabled ? '本机采样休眠中 · 亮屏后自动恢复，或前往 <button class="linkish" data-act="go-dpi-studio">DPI 与自训</button> 切换' : '采样器刚就绪 · 等待首批连接…') + '</div>'
      : '<div class="sec"><span>热点手机本机应用 <small>UID 级真实套接字归因 · 点开可排除代理</small></span><button class="linkish" data-act="self-conns">此刻连接明细</button></div>' +
        '<div class="glass rows">' + usr.slice(0, 50).map(function (r) { return appRow(r, mx); }).join('') + '</div>' +
        (sys.length ? '<div class="glass' + (S.open.sysapps ? ' open' : '') + '" data-foldkey="sysapps"><button class="card-h" data-act="fold" data-key="sysapps">' + gi('gray', 'cpu') + '<span class="tx"><div class="t">本机系统与组件应用</div><div class="s">' + sys.length + ' 个 · 默认收起不污染规则库</div></span>' + ico('chev', 'chev') + '</button>' +
          '<div class="fold"><div><div class="fold-in rows" style="border-top:1px solid var(--divider)">' + sys.slice(0, 80).map(function (r) { return appRow(r, mx); }).join('') + '</div></div></div></div>' : '');

    var exclHtml = '<div class="glass' + (S.open.fwexcl ? ' open' : '') + '" data-foldkey="fwexcl"><button class="card-h" data-act="fold" data-key="fwexcl">' + gi('cyan', 'shield') + '<span class="tx"><div class="t">VPN / 代理导管排除名单</div><div class="s">不参与自动规则与原型学习的包名 · 已自定义 ' + fx.length + ' 个</div></span>' + ico('chev', 'chev') + '</button>' +
      '<div class="fold"><div><div class="fold-in set-body">' +
        '<div class="chips">' + (fx.length ? fx.map(function (p) { return '<span class="chip">' + esc(p) + '<button class="linkish danger" data-fw-del="' + esc(p) + '" aria-label="移除">×</button></span>'; }).join('') : '<span class="note">内置已自动排除 Clash / Sing-box / V2Ray / WireGuard 等 30 款常见代理工具</span>') + '</div>' +
        '<div style="display:flex;gap:8px"><span class="box" style="flex:1"><input id="fw-pkg" maxlength="128" placeholder="输入代理包名，如 com.github.metacubex.clash.meta" style="font-family:var(--mono)"></span><button class="btn pri press" data-act="fw-add">添加</button></div>' +
      '</div></div></div></div>';

    return ifaceChips() + hsHtml + hostHtml + exclHtml;
  }

  // ── 子页 2: 应用规则中心 (合并原散落在 3 处的新发现应用 + 本机独占候选 + 未识别域名补库 + 人工纠正 + 规则包/JSON 库) ──
  var cs = (self && self.candidate_samples) || [];
  var unm = (self && self.unmatched_sni_samples) || [];
  var candGrp = function (title, list, acts) {
    if (!list.length) return '';
    return '<div class="dsec" style="margin:8px 2px 4px">' + title + ' · ' + list.length + '</div><div class="glass sni">' + list.map(function (c) {
      var inf = typeof classifyInfraHost === 'function' ? classifyInfraHost(c.apex) : null;
      return '<div class="sni-row" data-apex="' + esc(c.apex) + '"><span class="dw"><span class="d" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap"><span class="mono">' + esc(c.apex) + '</span>' + (inf ? infraBadgeHtml(inf) : '') + '</span><span class="c">' + esc(c.app || (c.uid ? 'uid ' + c.uid : '未知应用')) + ' · 命中 ' + num(c.hits) + ' 次 · ' + num(c.windows) + ' 窗口 · 置信' + ({ high: '高', med: '中', low: '低', shared: '共享' }[c.tier] || c.tier) + '</span></span>' + acts(c) + '</div>';
    }).join('') + '</div>';
  };

  return '<div class="sec"><span>1. 新发现的应用 <small>共现域名 + 本机 APK + 证书主体自动聚类</small></span><button class="linkish" data-act="disc-scan">扫描安装包</button></div>' +
    '<div class="glass" id="disc-entry">' + (typeof discEntryHtml === 'function' ? discEntryHtml() : '') + '</div>' +

    '<div class="sec"><span>2. 本机应用转换候选规则 <small>单应用独占主域名飞轮</small></span><span class="r">' + cs.length + '</span></div>' +
    (cs.length
      ? candGrp('待确认晋级', cs.filter(function (c) { return !c.promoted && c.tier !== 'shared'; }), function () { return '<span style="display:flex;gap:6px"><button class="btn sec press" data-cand="reject">共享豁免</button><button class="btn pri press" data-cand="promote">晋级规则</button></span>'; }) +
        candGrp('已晋级生效', cs.filter(function (c) { return c.promoted; }), function () { return '<button class="btn sec press" data-cand="reject">撤销</button>'; }) +
        candGrp('已识别公共基础设施（自动隔离）', cs.filter(function (c) { return !c.promoted && c.tier === 'shared'; }), function () { return '<span class="badge b-gray">不绑单应用</span>'; })
      : '<div class="glass empty">暂无待审本机候选域名 · 已覆盖当前活跃域名</div>') +

    (unm.length ? '<div class="sec"><span>本机未匹配 SNI 实时观察 <small>自动标注公共 CDN / SDK</small></span><span class="r">' + num(self.unmatched_snis_pending, unm.length) + '</span></div><div class="glass sni">' +
      unm.slice(0, 6).map(function (s) {
        var inf = typeof classifyInfraHost === 'function' ? classifyInfraHost(s) : null;
        return '<div class="sni-row' + (inf && inf.shared ? ' is-shared-infra' : '') + '"><span class="dw" style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;width:100%"><span class="d mono">' + esc(s) + '</span>' + (inf ? infraBadgeHtml(inf) : '') + '</span></div>';
      }).join('') + '</div>' : '') +

    '<div class="sec"><span>3. 热点未识别域名补库 <small id="dpi-unknown-t">自动过滤公共 CDN / SDK · 一键生成规则</small></span></div>' +
    '<div class="glass sni" id="dpi-unknown"></div>' +

    '<div class="sec"><span>4. 人工纠正、群智规则包与自定义 JSON 库</span></div>' +
    '<div class="glass rows">' +
      (typeof fpFold === 'function' ? fpFold() : '') +
      (typeof rulepackFold === 'function' ? rulepackFold() : '') +
    '</div>' +
    '<div class="glass' + (S.open.rules ? ' open' : '') + '" id="rules" data-foldkey="rules"><button class="card-h" data-act="fold" data-key="rules">' + gi('blue', 'doc') + '<span class="tx"><div class="t">自定义规则 JSON 编辑器</div><div class="s">导出 / 粘贴导入 / 检查在线规则库更新</div></span>' + ico('chev', 'chev') + '</button>' +
      '<div class="fold"><div><div class="fold-in set-body"><textarea class="textarea" id="rules-text" spellcheck="false" placeholder="点「导出」读取当前自定义规则 JSON，或由上方「生成规则」自动填入"></textarea>' +
      '<div class="btns" style="flex-wrap:wrap"><button class="btn sec press" data-act="rules-export">导出当前规则</button><button class="btn pri press" data-act="rules-import">保存并重载</button></div>' +
      '<div class="btns" style="flex-wrap:wrap"><button class="btn sec press" data-act="rules-update">检查在线更新</button><button class="btn dan press" data-act="rules-reset">恢复内置</button></div><div class="out" id="rules-out" hidden></div></div></div></div></div>';
}

function appRow(r, mx) {
  var a = r.a, key = 'app' + r.uid, nm = r.name;
  var snis = (a.top_snis || []).slice(0, 6), rules = (a.top_rules || []).slice(0, 4), hits = a.rule_hit_counts || {};
  var val = r.bytes ? bytes(r.bytes) : num(a.total_conns) + ' 次';
  return '<div class="row-wrap' + (S.open[key] ? ' open' : '') + '" data-foldkey="' + esc(key) + '"><button class="row-h" data-act="fold" data-key="' + esc(key) + '">' +
    '<span class="appi" style="background:linear-gradient(145deg,' + appColor(a.pkg || nm) + ',color-mix(in srgb,' + appColor(a.pkg || nm) + ' 60%,#000))">' + esc(nm.charAt(0).toUpperCase()) + '</span>' +
    '<span class="tx"><div class="dev-name" style="font-size:14.5px"><span class="nm">' + esc(nm) + '</span>' + (a.flywheel_excluded ? '<span class="badge b-gray">已排除代理</span>' : '') + '</div>' +
      (r.bytes ? '<div class="bar1"><i style="width:' + Math.max(2, r.bytes / mx * 100).toFixed(1) + '%"></i></div>' : '<div class="s">' + (a.last_seen ? '最近 ' + ago(a.last_seen) : '') + '</div>') + '</span>' +
    '<span style="text-align:right"><div class="num" style="font-size:13px;font-weight:700">' + val + '</div><div style="font-size:11px;color:var(--text-3)">' + num(a.active_conns) + ' 连接</div></span>' + ico('chev', 'chev') + '</button>' +
    '<div class="fold"><div><div class="fold-in set-body">' +
      '<div class="note mono">' + esc(a.pkg || '(包名未解析)') + ' · uid ' + esc(r.uid) + '</div>' +
      (snis.length ? '<div class="dev-apps">' + snis.map(function (s) { return '<span class="a mono">' + esc(s) + '</span>'; }).join('') + '</div>' : '') +
      (rules.length ? '<div class="dev-apps"><span class="lb">命中规则</span>' + rules.map(function (x) { var n = num(hits[x]); return '<span class="badge ' + (n >= 10 ? 'b-ok' : 'b-gray') + '">' + esc(x) + (n ? ' · ' + n : '') + '</span>'; }).join('') + '</div>' : '') +
      (a.flywheel_excluded ? '<div class="note">VPN / 代理导管类应用：已自动隔离，不参与本机域名与指纹蒸馏</div>'
        : a.pkg ? '<button class="btn sec press" data-excl="' + esc(a.pkg) + '" data-name="' + esc(nm) + '">排除 · 标记为代理不学习规则</button>' : '') +
    '</div></div></div></div>';
}

function dtLocal(ms) { var d = new Date(ms); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
function exportDiagBoxHtml() {
  return '<div class="glass' + (S.open.dpiexp ? ' open' : '') + '" data-foldkey="dpiexp"><button class="card-h" data-act="fold" data-key="dpiexp">' + gi('blue', 'down') + '<span class="tx"><div class="t">抓包样本与时间段诊断导出</div><div class="s">按时间窗打包 DPI 明细与规则快照，存至下载目录</div></span>' + ico('chev', 'chev') + '</button>' +
    '<div class="fold"><div><div class="fold-in set-body">' +
      '<div class="field">快速选择时间范围<div class="chips">' + [[15, '最近 15 分'], [60, '最近 1 小时'], [180, '最近 3 小时'], [360, '最近 6 小时']].map(function (x) {
        return '<button class="chip press' + (x[0] === (S.expMin || 60) ? ' on' : '') + '" data-exp-min="' + x[0] + '">' + x[1] + '</button>'; }).join('') + '</div></div>' +
      '<div class="grid2"><label class="field">起始<span class="box"><input type="datetime-local" id="exp-from" value="' + dtLocal(Date.now() - (S.expMin || 60) * 60000) + '"></span></label><label class="field">结束<span class="box"><input type="datetime-local" id="exp-to" value="' + dtLocal(Date.now()) + '"></span></label></div>' +
      '<label class="field">备注（可选）<span class="box ta"><textarea id="exp-notes" maxlength="2000" placeholder="例如：某游戏 UDP 未命中，附上时间段分析"></textarea></span></label>' +
      '<button class="btn pri wide press" data-act="export-build">' + ico('down') + '打包导出样本</button><div id="exp-result"></div>' +
      '<div class="sec" style="margin-top:6px"><span>最近的导出</span><button class="linkish" data-act="export-list">刷新</button></div><div class="rows" id="exp-list"><div class="note">点「刷新」加载列表</div></div>' +
    '</div></div></div></div>';
}
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
    $('#exp-result').innerHTML = '<div class="note" style="margin-top:4px">' + uiSvg('check') + ' ' + esc(r.name) + ' · ' + bytes(r.size_bytes) + '<br>' + Object.keys(tr).map(function (k) { return esc(k) + (tr[k].included ? ' ' + tr[k].file_count + ' 个文件' : ' 无'); }).join(' · ') + '</div>';
    toast('导出完成 · ' + bytes(r.size_bytes)); loadExports();
  }).catch(function (e) { toast(errText(e), 'err'); }).then(function () { btn.disabled = false; btn.lastChild.textContent = '打包导出样本'; });
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
    toast((el.getAttribute('aria-label') || '') + (on ? ' 已开启' : ' 已关闭'));
    if (path !== 'toggle') S.selfCfg[path.split('/')[0] + '_enabled'] = on;
    setTimeout(function () { loadApps().then(function () { if (S.page === 'apps') renderApps(false); if (S.page === 'stats' && S.aseg === 'dpi') paintDpi(); }); }, 800);
  }).catch(function (e) { el.setAttribute('aria-checked', String(!on)); toast(errText(e), 'err'); }).then(function () { pend(el, false); });
}
function candAct(kind, apex) {
  api.action(kind === 'promote' ? 'candidate_promote' : 'candidate_reject', { apex: apex }).then(function () {
    toast(kind === 'promote' ? apex + ' 已晋级为正式规则' : apex + ' 已标记为共享基础设施');
    return loadApps();
  }).then(function () { if (S.page === 'apps') renderApps(false); }).catch(function (e) { toast(errText(e), 'err'); });
}
function excludeApp(pkg, name) {
  confirmSheet('不学习「' + name + '」的规则？', 'VPN / 代理类应用会代发其他应用的流量，排除后它的域名不会被学成单应用规则。', '排除', { safe: true }).then(function (ok) {
    if (!ok) return;
    api.action('flywheel_exclude_set', { op: 'add', pkg: pkg }).then(function () { toast('已排除 ' + name); return loadConfig(); }).then(function () { if (S.page === 'apps') renderApps(false); }).catch(function (e) { toast(errText(e), 'err'); });
  });
}
