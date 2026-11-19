/* HNC WebUI · vector_v6.js —— HNC v6.0.0 · Vector 战术中枢与 LeakGuard 明文隐私安检面板
 * 职责范围:
 *   1. LeakGuard 明文隐私安检面板: 态势统计、系统通知/锁屏半脱敏开关、环形缓冲与去重冷却数字配置、
 *      高密度单行实时告警流(未打码完整 raw_value + 拉黑域名与IP/解封 + 秒斩连接 + XSS 安全原始 HTTP 报文取证折叠抽屉)、
 *      浏览器 SSE (/api/leakguard/stream) 与 KSU 模式平滑轮询回退。
 *   2. Vector v6 四大战术舱: Vector Express 零排队护航、UpdateLeash 更新拴绳、ThermoCruise 电芯温控巡航、
 *      FlowScalpel 五元组连接透视与单斩死流/秒斩+冻结15分钟手术台抽屉。
 *   3. /api/vector_sync 聚合快路径数据消费、四大隔离舱壁健康态势展示与跨页面联动。
 * 视觉与安全规范: 零表情字符 · 纯直接数字输入框 · 全量 HTML 转义防 XSS · 严格对齐后端 JSON 解码字段 · 自适应四大主题。
 */
'use strict';

var V6_API = {
  sync: '/api/vector_sync',
  lgEvents: '/api/leakguard/events',
  lgStream: '/api/leakguard/stream',
  lgClear: '/api/leakguard/clear',
  lgConfig: '/api/leakguard/config',
  lgBlockDomain: '/api/leakguard/block-domain',
  express: '/api/v6/express',
  updateLeash: '/api/v6/update_leash',
  thermo: '/api/v6/thermo',
  scalpelFlows: '/api/v6/scalpel/flows',
  scalpelCut: '/api/v6/scalpel/cut',
  blackbox: '/api/v6/blackbox',
  multiIface: '/api/v6/multi_iface',
  nativeSubtrees: '/api/v6/native_subtrees',
  backup: '/api/backup'
};

/* 严格 HTML 转义，防止恶意 HTTP Path / User-Agent / 原始报文切片触发 XSS */
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

/* 在已安全转义的原始 HTTP 报文中精确高亮命中的完整明文值 raw_value（零正则注入风险、严禁二次星号打码） */
function highlightRawSnippet(snippet, rawVal) {
  var src = String(snippet == null ? '' : snippet);
  var needle = String(rawVal == null ? '' : rawVal);
  if (!src) return '<span class="note">(当前告警未附带原始 HTTP 报文切片)</span>';
  if (!needle) return escapeHtml(src);
  var out = '', idx = 0, hit = -1;
  while ((hit = src.indexOf(needle, idx)) !== -1) {
    out += escapeHtml(src.slice(idx, hit)) + '<mark class="lgd-hl">' + escapeHtml(needle) + '</mark>';
    idx = hit + needle.length;
  }
  out += escapeHtml(src.slice(idx));
  return out;
}

/* 从原始 HTTP 报文切片中提取请求行 Path 与 User-Agent（当事件字段未单独携带时自动补齐） */
function extractHttpMetaFromSnippet(snippet) {
  var res = { method: '', path: '', ua: '' };
  var s = String(snippet || '');
  if (!s) return res;
  var lines = s.split(/\r?\n/);
  if (lines.length > 0) {
    var m0 = /^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i.exec(lines[0]);
    if (m0) {
      res.method = m0[1].toUpperCase();
      res.path = m0[2];
    }
  }
  for (var i = 1; i < lines.length; i++) {
    var um = /^\s*user-agent\s*:\s*(.+?)\s*$/i.exec(lines[i]);
    if (um) {
      res.ua = um[1];
      break;
    }
  }
  return res;
}

function v6ValidIp(ip) {
  var s = String(ip || '').trim();
  if (!s || s === '-' || s === '—') return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    return s.split('.').every(function (p) { var n = parseInt(p, 10); return n >= 0 && n <= 255; });
  }
  return s.indexOf(':') >= 0 && /^[0-9a-fA-F:.]+$/.test(s);
}

function v6ValidMac(m) {
  return /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(String(m || '').trim());
}

/* 纯内联矢量线条图标库（零位图 · 零表情字符） */
var V6_SVGS = {
  shieldAlert: '<path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z" fill="currentColor" fill-opacity=".15"/><path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z"/><path d="M12 8.2v4.4M12 16h.01"/>',
  express: '<polygon points="13.2 2.4 4.4 13.4 11.6 13.4 10.6 21.6 19.6 10.6 12.4 10.6 13.2 2.4" fill="currentColor" fill-opacity=".18"/><polygon points="13.2 2.4 4.4 13.4 11.6 13.4 10.6 21.6 19.6 10.6 12.4 10.6 13.2 2.4"/>',
  leash: '<rect x="2.8" y="6.8" width="7.6" height="10.4" rx="3.5" fill="currentColor" fill-opacity=".15"/><rect x="13.6" y="6.8" width="7.6" height="10.4" rx="3.5" fill="currentColor" fill-opacity=".15"/><rect x="2.8" y="6.8" width="7.6" height="10.4" rx="3.5"/><rect x="13.6" y="6.8" width="7.6" height="10.4" rx="3.5"/><path d="M8.2 12h7.6"/>',
  thermo: '<path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z" fill="currentColor" fill-opacity=".16"/><path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z"/><circle cx="12" cy="17.5" r="1.5" fill="currentColor" stroke="none"/><path d="M16.8 6h2.2M16.8 9.5h1.6"/>',
  scalpel: '<path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z" fill="currentColor" fill-opacity=".16"/><path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z"/><path d="M3.5 20.5h11"/><path d="m14.5 6.5 3 3"/>',
  cut: '<circle cx="6" cy="6" r="2.6"/><circle cx="6" cy="18" r="2.6"/><path d="M20 4 8.2 15.8M14.5 14.5 20 20M8.2 8.2 12 12"/>',
  freeze: '<path d="M12 2.5v19M4.8 6.8l14.4 10.4M19.2 6.8 4.8 17.2"/><circle cx="12" cy="12" r="2.2" fill="currentColor" fill-opacity=".2"/>',
  blackbox: '<rect x="3" y="4.5" width="18" height="15" rx="3" fill="currentColor" fill-opacity=".14"/><rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="M6.5 13h2.4l1.6-3.8 2.6 6.2 1.8-3.4h2.6"/>',
  vault: '<path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 16.5v-9Z" fill="currentColor" fill-opacity=".14"/><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 16.5v-9Z"/><circle cx="12" cy="12" r="2.6"/><path d="M12 9.4V7.8M12 16.2v-1.6M9.4 12H7.8M16.2 12h-1.6"/>'
};
function v6Svg(name, cls) {
  return '<svg class="' + (cls || '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (V6_SVGS[name] || V6_SVGS.express) + '</svg>';
}

/* 全局 v6 状态仓 */
var V6 = {
  view: LS.get('hnc6.v6_view', 'all'), // 'all' | 'leakguard' | 'cockpit'
  loaded: false,
  apiSupported: { lg: true, v6: true },
  lg: {
    total_hits: 0,
    affected_devices: 0,
    blocked_domains: 0,
    blocked_set: {},
    hit_ledger: {},
    notify_enabled: true,
    lockscreen_mask: true,
    capacity: 300,
    cooldown_sec: 300,
    events: [],
    openIds: {},
    typeFilter: 'ALL',
    q: '',
    sseActive: false,
    sseFailed: false
  },
  express: {
    enabled: true,
    auto_detect: true,
    state: 'idle_fullspeed',
    active: false,
    forced_macs: [],
    escorted_macs: [],
    escort_reasons: {},
    bg_ceil_pct: 100,
    configured_bg_ceil_pct: 85,
    cooldown_remaining_sec: 0,
    transitions: 0,
    qdisc: 'fq_codel'
  },
  leash: {
    enabled: true,
    grace_mb: 200,
    leash_kbps: 1500,
    sessions: [],
    active_sessions: 0,
    leashed_count: 0
  },
  thermo: {
    enabled: true,
    stage2_shaper_enabled: true,
    stage1_temp_c: 42,
    stage2_temp_c: 45,
    low_bat_pct: 20,
    temp_c: 0,
    capacity_pct: 0,
    bat_available: false,
    bat_status: '',
    is_charging: false,
    vector_express_active: false,
    stage2_exempt: false,
    exempt_reason: '',
    low_battery_cruise: false,
    cool_hold_remaining_sec: 0,
    raw_stage: 0,
    stage: 0,
    stage_label: 'STAGE-0'
  },
  scalpel: {
    open: false,
    mac: '',
    ip: '',
    devName: '',
    protoFilter: 'ALL',
    q: '',
    paused: false,
    loading: false,
    readable: true,
    flows: [],
    active_rules: [],
    totalFlows: 0,
    activeRulesCount: 0,
    cutTotal: 0,
    timer: 0,
    err: ''
  },
  blackbox: {
    granularity_ms: 200,
    total_ticks: 0,
    incident_count: 0,
    latest_jitter_ms: 0,
    incidents: []
  },
  multiIface: {
    primary_downstream: '',
    shape_targets: [],
    dual_band_or_mlo: false,
    usb_tether_active: false,
    lan_fastlane_class: '1:fffe',
    lan_fastlane_gbps: 2.5,
    tun0_vpn_active: false,
    tun0_loop_risk: false,
    low16_mark_safe: true
  },
  subtrees: {
    qos_mode: 'balanced_50_35_15',
    tier1_pct: 50,
    tier2_pct: 35,
    tier3_pct: 15,
    full_restores: 0
  },
  vault: {
    last_sha256: '',
    last_file_count: 0,
    last_restored: 0
  },
  sse: null,
  sseRetryT: 0
};
if (['all', 'leakguard', 'cockpit'].indexOf(V6.view) < 0) V6.view = 'all';

function fmtClockTs(ts) {
  if (!ts) return '--:--:--';
  var ms = ts > 1e12 ? ts : ts * 1000;
  var dt = new Date(ms);
  if (isNaN(dt.getTime())) return '--:--:--';
  return pad2(dt.getHours()) + ':' + pad2(dt.getMinutes()) + ':' + pad2(dt.getSeconds());
}

function leakTypeBadgeCode(tp) {
  var u = String(tp || 'PLAINTEXT').toUpperCase().replace(/[^A-Z0-9_-]/g, '_');
  if (u === 'COOKIE_TOKEN' || u === 'BEARER_TOKEN') return 'TOKEN';
  if (u === 'MAC') return 'MAC_ADDR';
  if (u === 'LATLNG' || u === 'LOCATION') return 'GPS';
  return u || 'PLAINTEXT';
}

function leakTypeBadgeCls(tp) {
  var u = leakTypeBadgeCode(tp);
  if (/PHONE|ID_CARD|IDCARD|AUTH|TOKEN|COOKIE|PASS|GPS|LOC|IMEI|IMSI/.test(u)) return 'b-bad';
  if (/DEVICE_ID|OAID|ANDROID_ID|IDFA|MAC|BSSID|SERIAL/.test(u)) return 'b-warn';
  return 'b-acc';
}

function leakTypeGroup(tp) {
  var u = leakTypeBadgeCode(tp);
  if (/PHONE|EMAIL|ID_CARD|IDCARD/.test(u)) return 'PHONE';
  if (/GPS|LOC|LAT|LON|WIFI_BSSID|BSSID/.test(u)) return 'GPS';
  if (/MAC/.test(u)) return 'MAC_ADDR';
  if (/TOKEN|AUTH|COOKIE|KEY|PASS/.test(u)) return 'TOKEN';
  if (/IMEI|IMSI|OAID|IDFA|ANDROID_ID|DEVICE/.test(u)) return 'DEVICE_ID';
  return 'OTHER';
}

function leakHitKey(mac, srcIp, dstHost, lType, rawVal) {
  return (mac || srcIp || '-') + '|' + String(dstHost || '').toLowerCase() + '|' + lType + '|' + rawVal;
}

/* ── LeakGuard 数据归一化（对齐 v6_leakguard_api.go LeakEvent） ── */
function v6NormLeakEvent(raw, idx, batchCounts) {
  raw = raw || {};
  var ts = num(raw.ts != null ? raw.ts : (raw.timestamp != null ? raw.timestamp : raw.created_at), 0);
  var mac = String(raw.mac || raw.client_mac || raw.src_mac || '').toLowerCase();
  var srcIp = String(raw.src_ip || raw.client_ip || raw.ip || '');
  var d = mac ? devBy(mac) : null;
  if (!d && srcIp && Array.isArray(S.devices)) {
    for (var i = 0; i < S.devices.length; i++) {
      if (S.devices[i].ip === srcIp) { d = S.devices[i]; if (!mac) mac = d.mac; break; }
    }
  }
  var dstHost = String(raw.dst_host || raw.host || raw.domain || raw.dst_ip || '—');
  var dstIp = String(raw.dst_ip || raw.server_ip || '');
  var lType = leakTypeBadgeCode(raw.leak_type || raw.type || raw.kind || 'PLAINTEXT');
  /* 严禁对 raw_value 做任何前端打码截断，100% 保留原始明文值 */
  var rawVal = raw.raw_value != null ? String(raw.raw_value) : (raw.value != null ? String(raw.value) : (raw.plaintext != null ? String(raw.plaintext) : ''));
  var snippet = String(raw.raw_snippet != null ? raw.raw_snippet : (raw.snippet || raw.raw_http || ''));
  var meta = extractHttpMetaFromSnippet(snippet);
  var method = String(raw.method || meta.method || 'GET').toUpperCase();
  var urlPath = String(raw.path || raw.url_path || raw.uri || meta.path || '/');
  var ua = String(raw.user_agent || raw.ua || meta.ua || '(报文未携带 User-Agent 头)');
  var id = String(raw.id || raw.event_id || (ts + '_' + srcIp + '_' + lType + '_' + dstHost + '_' + (idx || 0)));
  var isBlocked = raw.is_blocked === true || raw.blocked === true || !!V6.lg.blocked_set[dstHost.toLowerCase()];
  var hKey = leakHitKey(mac, srcIp, dstHost, lType, rawVal);
  var computedHits = Math.max(
    1,
    Math.round(num(raw.hit_count != null ? raw.hit_count : raw.hits, 0)),
    num(batchCounts && batchCounts[hKey], 0),
    num(V6.lg.hit_ledger[hKey], 0)
  );
  return {
    id: id,
    hKey: hKey,
    ts: ts,
    timeStr: raw.time_str || fmtClockTs(ts),
    mac: mac,
    devName: raw.device_name || (d ? d.name : '') || (srcIp || mac || '未知终端'),
    src_ip: srcIp || (d && d.ip) || '',
    src_port: num(raw.src_port != null ? raw.src_port : raw.sport, 0),
    dst_ip: dstIp,
    dst_port: num(raw.dst_port != null ? raw.dst_port : raw.dport, 80),
    proto: String(raw.proto || 'tcp').toLowerCase(),
    leak_type: lType,
    leak_label: String(raw.leak_label || ''),
    raw_value: rawVal,
    dst_host: dstHost,
    hit_count: computedHits,
    method: method,
    url_path: urlPath,
    user_agent: ua,
    raw_snippet: snippet,
    is_blocked: isBlocked
  };
}

function v6ApplyLeakGuardData(d) {
  if (!d || typeof d !== 'object') return;
  var cfg = (d.config && typeof d.config === 'object') ? d.config : d;
  var stats = (d.stats && typeof d.stats === 'object') ? d.stats : d;

  if (typeof cfg.notify_enabled === 'boolean') V6.lg.notify_enabled = cfg.notify_enabled;
  if (typeof cfg.lockscreen_mask === 'boolean') V6.lg.lockscreen_mask = cfg.lockscreen_mask;
  if (cfg.capacity != null || cfg.ring_capacity != null) {
    V6.lg.capacity = clamp(Math.round(num(cfg.capacity != null ? cfg.capacity : cfg.ring_capacity, 300)), 10, 2000);
  }
  if (cfg.cooldown_sec != null || cfg.dedup_cooldown_sec != null) {
    V6.lg.cooldown_sec = clamp(Math.round(num(cfg.cooldown_sec != null ? cfg.cooldown_sec : cfg.dedup_cooldown_sec, 300)), 0, 86400);
  }

  if (Array.isArray(d.events) || Array.isArray(d.items)) {
    var rawArr = d.events || d.items || [];
    var batchCounts = {};
    rawArr.forEach(function (it) {
      if (!it) return;
      var mac0 = String(it.mac || '').toLowerCase();
      var ip0 = String(it.src_ip || '');
      var hk = leakHitKey(mac0, ip0, it.dst_host, leakTypeBadgeCode(it.leak_type), String(it.raw_value != null ? it.raw_value : ''));
      batchCounts[hk] = (batchCounts[hk] || 0) + 1;
    });
    var list = rawArr.map(function (it, idx) {
      var ev = v6NormLeakEvent(it, idx, batchCounts);
      if (ev.is_blocked && ev.dst_host) V6.lg.blocked_set[ev.dst_host.toLowerCase()] = 1;
      return ev;
    });
    list.sort(function (a, b) { return b.ts - a.ts; });
    V6.lg.events = list.slice(0, V6.lg.capacity || 300);
  }

  if (stats.total_hits != null) {
    V6.lg.total_hits = Math.max(0, Math.round(num(stats.total_hits)));
  }
  if (stats.affected_devices != null) {
    V6.lg.affected_devices = Math.max(0, Math.round(num(stats.affected_devices)));
  } else if (V6.lg.events.length) {
    var devSeen = {};
    V6.lg.events.forEach(function (e) { var k = e.mac || e.src_ip; if (k) devSeen[k] = 1; });
    V6.lg.affected_devices = Object.keys(devSeen).length;
  }
  if (typeof stats.blocked_domains === 'number') {
    V6.lg.blocked_domains = Math.max(0, Math.round(stats.blocked_domains));
  }

  v6PaintHeaderBadges();
}

function v6PushStreamEvent(evObj) {
  if (!evObj || typeof evObj !== 'object') return;
  if (Array.isArray(evObj.events) || evObj.stats || evObj.config) {
    v6ApplyLeakGuardData(evObj);
    v6RefreshLeakGuardDom();
    return;
  }
  /* 过滤 SSE 握手帧 {"ok":true} 或无载荷心跳，绝不插入空白假行 */
  if (!evObj.leak_type && evObj.raw_value === undefined && !evObj.raw_snippet) return;

  var tmpEv = v6NormLeakEvent(evObj, Date.now() % 10000, null);
  V6.lg.hit_ledger[tmpEv.hKey] = num(V6.lg.hit_ledger[tmpEv.hKey], 0) + 1;
  tmpEv.hit_count = Math.max(tmpEv.hit_count, V6.lg.hit_ledger[tmpEv.hKey]);

  for (var i = V6.lg.events.length - 1; i >= 0; i--) {
    var cur = V6.lg.events[i];
    if (cur.id === tmpEv.id) {
      V6.lg.events.splice(i, 1);
    } else if (cur.hKey === tmpEv.hKey) {
      tmpEv.hit_count = Math.max(tmpEv.hit_count, num(cur.hit_count, 1) + 1);
      V6.lg.hit_ledger[tmpEv.hKey] = tmpEv.hit_count;
    }
  }
  V6.lg.events.unshift(tmpEv);
  if (V6.lg.events.length > (V6.lg.capacity || 300)) {
    V6.lg.events.length = V6.lg.capacity || 300;
  }
  V6.lg.total_hits = num(V6.lg.total_hits) + 1;
  var devSeen = {};
  V6.lg.events.forEach(function (x) { var k = x.mac || x.src_ip; if (k) devSeen[k] = 1; });
  V6.lg.affected_devices = Math.max(V6.lg.affected_devices, Object.keys(devSeen).length);
  v6PaintHeaderBadges();
  v6RefreshLeakGuardDom();
}

/* ── Vector Express 数据归一化（对齐 v6_vector_express.go） ── */
function v6ApplyExpressData(r) {
  if (!r || typeof r !== 'object') return;
  var cfg = (r.config && typeof r.config === 'object') ? r.config : r;
  if (typeof r.enabled === 'boolean') V6.express.enabled = r.enabled;
  else if (typeof cfg.enabled === 'boolean') V6.express.enabled = cfg.enabled;
  if (typeof r.auto_detect === 'boolean') V6.express.auto_detect = r.auto_detect;
  else if (typeof cfg.auto_detect === 'boolean') V6.express.auto_detect = cfg.auto_detect;
  if (r.state) V6.express.state = String(r.state);
  if (typeof r.active === 'boolean') V6.express.active = r.active;
  if (Array.isArray(r.forced_macs)) {
    V6.express.forced_macs = r.forced_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(v6ValidMac);
  } else if (Array.isArray(cfg.forced_macs)) {
    V6.express.forced_macs = cfg.forced_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(v6ValidMac);
  }
  if (Array.isArray(r.escorted_macs)) {
    V6.express.escorted_macs = r.escorted_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(Boolean);
  }
  if (r.escort_reasons && typeof r.escort_reasons === 'object') {
    V6.express.escort_reasons = r.escort_reasons;
  }
  if (r.bg_ceil_pct != null) V6.express.bg_ceil_pct = Math.round(num(r.bg_ceil_pct, 100));
  if (r.configured_bg_ceil_pct != null) V6.express.configured_bg_ceil_pct = Math.round(num(r.configured_bg_ceil_pct, 85));
  else if (cfg.bg_ceil_pct != null && r.bg_ceil_pct == null) V6.express.configured_bg_ceil_pct = Math.round(num(cfg.bg_ceil_pct, 85));
  if (r.cooldown_remaining_sec != null) V6.express.cooldown_remaining_sec = Math.max(0, Math.round(num(r.cooldown_remaining_sec)));
  if (r.transitions != null) V6.express.transitions = Math.max(0, Math.round(num(r.transitions)));
  if (r.dataplane && r.dataplane.qdisc) V6.express.qdisc = String(r.dataplane.qdisc);
}

/* ── UpdateLeash 数据归一化（对齐 v6_update_leash.go） ── */
function v6ApplyLeashData(r) {
  if (!r || typeof r !== 'object') return;
  var cfg = (r.config && typeof r.config === 'object') ? r.config : r;
  if (typeof r.enabled === 'boolean') V6.leash.enabled = r.enabled;
  else if (typeof cfg.enabled === 'boolean') V6.leash.enabled = cfg.enabled;
  if (r.grace_mb != null || cfg.grace_mb != null) {
    V6.leash.grace_mb = clamp(Math.round(num(r.grace_mb != null ? r.grace_mb : cfg.grace_mb, 200)), 10, 10240);
  }
  if (r.leash_kbps != null || cfg.leash_kbps != null) {
    V6.leash.leash_kbps = clamp(Math.round(num(r.leash_kbps != null ? r.leash_kbps : cfg.leash_kbps, 1500)), 128, 1000000);
  }
  if (r.leashed_count != null) V6.leash.leashed_count = Math.max(0, Math.round(num(r.leashed_count)));
  if (r.active_sessions != null) V6.leash.active_sessions = Math.max(0, Math.round(num(r.active_sessions)));

  var sess = Array.isArray(r.sessions) ? r.sessions : (Array.isArray(r.leashed_flows) ? r.leashed_flows : null);
  if (sess) {
    V6.leash.sessions = sess.map(function (s, idx) {
      var mac = String(s.mac || '').toLowerCase();
      var d = mac ? devBy(mac) : null;
      var downBytes = num(s.down_bytes, 0);
      var remBytes = num(s.grace_remaining_bytes, 0);
      var downBps = num(s.down_bps, 0);
      var st = String(s.state || (s.paused ? 'paused' : (s.bypass_once ? 'bypassed' : 'leashed')));
      return {
        session_key: String(s.session_key || s.id || (mac + '|' + (s.dst_host || s.dst_ip || idx))),
        mac: mac,
        devName: s.device_name || (d ? d.name : '') || s.src_ip || mac || '下游终端',
        src_ip: String(s.src_ip || (d && d.ip) || ''),
        dst_host: String(s.dst_host || s.dst_ip || '后台更新流'),
        dst_ip: String(s.dst_ip || ''),
        vendor_label: String(s.vendor_label || ''),
        down_mb: downBytes / 1048576,
        rem_mb: remBytes / 1048576,
        cur_kbps: downBps > 0 ? Math.round(downBps * 8 / 1000) : Math.round(num(s.applied_kbps, 0)),
        applied_kbps: Math.round(num(s.applied_kbps, V6.leash.leash_kbps)),
        state: st,
        bypass_once: s.bypass_once === true || st === 'bypassed',
        paused: s.paused === true || st === 'paused'
      };
    });
    V6.leash.active_sessions = V6.leash.sessions.length;
  }
}

/* ── ThermoCruise 数据归一化（对齐 v6_thermo_cruise.go） ── */
function v6ApplyThermoData(r) {
  if (!r || typeof r !== 'object') return;
  var cfg = (r.config && typeof r.config === 'object') ? r.config : r;
  var bat = (r.battery && typeof r.battery === 'object') ? r.battery : null;

  if (typeof r.enabled === 'boolean') V6.thermo.enabled = r.enabled;
  else if (typeof cfg.enabled === 'boolean') V6.thermo.enabled = cfg.enabled;

  if (typeof r.stage2_shaper_enabled === 'boolean') V6.thermo.stage2_shaper_enabled = r.stage2_shaper_enabled;
  else if (typeof cfg.stage2_shaper_enabled === 'boolean') V6.thermo.stage2_shaper_enabled = cfg.stage2_shaper_enabled;

  if (r.stage1_temp_c != null || cfg.stage1_temp_c != null) {
    V6.thermo.stage1_temp_c = clamp(num(r.stage1_temp_c != null ? r.stage1_temp_c : cfg.stage1_temp_c, 42), 30, 70);
  }
  if (r.stage2_temp_c != null || cfg.stage2_temp_c != null) {
    V6.thermo.stage2_temp_c = clamp(num(r.stage2_temp_c != null ? r.stage2_temp_c : cfg.stage2_temp_c, 45), 32, 75);
  }
  if (r.low_bat_pct != null || cfg.low_bat_pct != null) {
    V6.thermo.low_bat_pct = clamp(Math.round(num(r.low_bat_pct != null ? r.low_bat_pct : cfg.low_bat_pct, 20)), 1, 80);
  }

  if (bat) {
    V6.thermo.bat_available = bat.available === true;
    if (bat.temp_c != null) V6.thermo.temp_c = num(bat.temp_c);
    if (bat.capacity_pct != null) V6.thermo.capacity_pct = clamp(Math.round(num(bat.capacity_pct)), 0, 100);
    if (bat.status != null) V6.thermo.bat_status = String(bat.status);
    if (typeof bat.is_charging === 'boolean') V6.thermo.is_charging = bat.is_charging;
  } else {
    if (r.temp_c != null) V6.thermo.temp_c = num(r.temp_c);
    if (r.capacity_pct != null) V6.thermo.capacity_pct = clamp(Math.round(num(r.capacity_pct)), 0, 100);
    if (r.status != null) {
      V6.thermo.bat_status = String(r.status);
      V6.thermo.is_charging = /charging|full/i.test(V6.thermo.bat_status) && !/discharging/i.test(V6.thermo.bat_status);
    }
  }

  if (typeof r.vector_express_active === 'boolean') V6.thermo.vector_express_active = r.vector_express_active;
  if (typeof r.stage2_exempt === 'boolean') V6.thermo.stage2_exempt = r.stage2_exempt;
  if (r.exempt_reason != null) V6.thermo.exempt_reason = String(r.exempt_reason || '');
  if (typeof r.low_battery_cruise === 'boolean') V6.thermo.low_battery_cruise = r.low_battery_cruise;
  if (r.cool_hold_remaining_sec != null) V6.thermo.cool_hold_remaining_sec = Math.max(0, Math.round(num(r.cool_hold_remaining_sec)));

  var effStg = r.effective_stage != null ? Math.round(num(r.effective_stage)) : (r.raw_thermal_stage != null ? Math.round(num(r.raw_thermal_stage)) : null);
  if (r.raw_thermal_stage != null) V6.thermo.raw_stage = Math.round(num(r.raw_thermal_stage));
  if (effStg != null) {
    V6.thermo.stage = clamp(effStg, 0, 2);
  } else {
    var tc = V6.thermo.temp_c;
    V6.thermo.stage = !V6.thermo.enabled ? 0 : (tc >= V6.thermo.stage2_temp_c ? 2 : (tc >= V6.thermo.stage1_temp_c ? 1 : 0));
  }
  V6.thermo.stage_label = 'STAGE-' + V6.thermo.stage;
}

/* ── FlowScalpel 数据归一化（对齐 v6_flow_scalpel.go） ── */
function v6ApplyScalpelData(r) {
  if (!r || typeof r !== 'object') return;
  if (typeof r.readable === 'boolean') V6.scalpel.readable = r.readable;
  if (r.cut_total != null) V6.scalpel.cutTotal = Math.max(0, Math.round(num(r.cut_total)));
  if (Array.isArray(r.active_rules)) {
    V6.scalpel.active_rules = r.active_rules;
    V6.scalpel.activeRulesCount = r.active_rules.length;
  } else if (typeof r.active_rules === 'number') {
    V6.scalpel.activeRulesCount = Math.max(0, Math.round(r.active_rules));
  }

  var fl = Array.isArray(r.flows) ? r.flows : null;
  if (fl) {
    var nowSec = Date.now() / 1000;
    V6.scalpel.flows = fl.map(function (f, idx) {
      var mac = String(f.mac || '').toLowerCase();
      var srcIp = String(f.src_ip || '');
      var d = mac ? devBy(mac) : null;
      if (!d && srcIp && Array.isArray(S.devices)) {
        for (var i = 0; i < S.devices.length; i++) {
          if (S.devices[i].ip === srcIp) { d = S.devices[i]; if (!mac) mac = d.mac; break; }
        }
      }
      var rawProto = String(f.proto || 'tcp').toLowerCase();
      var sport = Math.round(num(f.sport != null ? f.sport : f.src_port, 0));
      var dport = Math.round(num(f.dport != null ? f.dport : f.dst_port, 0));
      var isQuic = rawProto === 'quic' || (rawProto === 'udp' && dport === 443);
      var frozenUntil = num(f.frozen_until, 0);
      return {
        id: String(f.flow_key || f.id || (rawProto + '|' + srcIp + ':' + sport + '|' + f.dst_ip + ':' + dport + '|' + idx)),
        proto: rawProto === 'udp' || rawProto === 'quic' ? 'udp' : 'tcp',
        protoBadge: isQuic ? 'QUIC' : (rawProto === 'udp' ? 'UDP' : 'TCP'),
        state: String(f.state || 'ESTABLISHED').toUpperCase(),
        frozen: frozenUntil > nowSec,
        frozen_until: frozenUntil,
        mac: mac,
        devName: f.device_name || (d ? d.name : '') || srcIp || '未知终端',
        src_ip: srcIp,
        sport: sport,
        dst_ip: String(f.dst_ip || ''),
        dport: dport,
        dst_host: String(f.domain || f.dst_host || ''),
        app_name: String(f.app_name || ''),
        traffic_type: String(f.traffic_type || ''),
        rx_bps: num(f.down_bps != null ? f.down_bps : f.rx_bps, 0),
        tx_bps: num(f.up_bps != null ? f.up_bps : f.tx_bps, 0),
        bytes: num(f.down_bytes, 0) + num(f.up_bytes, 0)
      };
    });
    V6.scalpel.totalFlows = Math.max(0, Math.round(num(r.total, V6.scalpel.flows.length)));
  }
}

/* 消费 /api/vector_sync 的无锁聚合快照（兼容顶层、extensions、modules 与 v6 子树） */
function v6IngestVectorSync(r) {
  if (!r || typeof r !== 'object') return;
  var ext = (r.extensions && typeof r.extensions === 'object') ? r.extensions : ((r.modules && typeof r.modules === 'object') ? r.modules : {});
  var v = (ext.v6 && typeof ext.v6 === 'object') ? ext.v6 : ((r.v6 && typeof r.v6 === 'object') ? r.v6 : ext);

  var lgSrc = r.leakguard || ext.leakguard || v.leakguard;
  var exSrc = r.express || ext.express || v.express;
  var ulSrc = r.update_leash || ext.update_leash || v.update_leash || v.leash;
  var thSrc = r.thermo || ext.thermo || v.thermo || v.thermo_cruise;
  var scSrc = r.scalpel || ext.scalpel || v.scalpel;

  if (lgSrc) v6ApplyLeakGuardData(lgSrc);
  if (exSrc) v6ApplyExpressData(exSrc);
  if (ulSrc) v6ApplyLeashData(ulSrc);
  if (thSrc) v6ApplyThermoData(thSrc);
  if (scSrc) v6ApplyScalpelData(scSrc);

  var pk = (ext.v6_pack && typeof ext.v6_pack === 'object') ? ext.v6_pack : ((r.v6_pack && typeof r.v6_pack === 'object') ? r.v6_pack : null);
  if (pk) v6ApplyScreenshotPackSummary(pk);

  V6.loaded = true;
  S.v6 = V6;
  v6PaintHeaderBadges();
  v6RefreshDevicesBannerDom();
  if (S.page === 'vector') {
    v6RefreshTopBulkheadsDom();
    v6RefreshCockpitDom();
  }
}

/* ── 独立 REST 拉取与 SSE 实时通道管理 ── */
function v6LoadLeakGuard() {
  return api.get(V6_API.lgEvents, null, { timeout: 8000 }).then(function (r) {
    V6.apiSupported.lg = true;
    v6ApplyLeakGuardData(r);
    V6.loaded = true;
    v6RefreshLeakGuardDom();
    v6RefreshDevicesBannerDom();
    return r;
  }).catch(function (e) {
    if (e && e.status === 404) V6.apiSupported.lg = false;
    return null;
  });
}

function v6LoadCockpitAll() {
  var scParams = { limit: 120 };
  if (v6ValidMac(V6.scalpel.mac)) scParams.mac = V6.scalpel.mac;
  if (v6ValidIp(V6.scalpel.ip)) scParams.ip = V6.scalpel.ip;
  return Promise.all([
    api.get(V6_API.express, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyExpressData(r); }).catch(function (e) { if (e && e.status === 404) V6.apiSupported.v6 = false; }),
    api.get(V6_API.updateLeash, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyLeashData(r); }).catch(function () {}),
    api.get(V6_API.thermo, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyThermoData(r); }).catch(function () {}),
    api.get(V6_API.scalpelFlows, scParams, { timeout: 7000 }).then(function (r) { v6ApplyScalpelData(r); }).catch(function () {}),
    api.get(V6_API.blackbox, { limit: 12, incidents_only: '1' }, { timeout: 7000 }).then(function (r) { v6ApplyBlackboxData(r); }).catch(function () {}),
    api.get(V6_API.multiIface, null, { timeout: 7000 }).then(function (r) { v6ApplyMultiIfaceData(r); }).catch(function () {})
  ]).then(function () {
    V6.loaded = true;
    S.v6 = V6;
    v6PaintHeaderBadges();
    v6RefreshDevicesBannerDom();
    if (S.page === 'vector') v6RefreshCockpitDom();
  });
}

function v6StartLeakGuardSSE() {
  if (KSU || typeof EventSource === 'undefined' || V6.sse || V6.lg.sseFailed || document.hidden || !V6.apiSupported.lg) return;
  try {
    var stream = new EventSource(V6_API.lgStream);
    V6.sse = stream;
    stream.onopen = function () {
      V6.lg.sseActive = true;
      v6UpdateStreamBadgeDom();
    };
    stream.addEventListener('ready', function () {
      V6.lg.sseActive = true;
      v6UpdateStreamBadgeDom();
    });
    var onPayload = function (ev) {
      if (!ev || !ev.data) return;
      try {
        var data = JSON.parse(ev.data);
        v6PushStreamEvent(data);
      } catch (_) {}
    };
    stream.onmessage = onPayload;
    stream.addEventListener('leak', onPayload);
    stream.addEventListener('snapshot', onPayload);
    stream.onerror = function () {
      V6.lg.sseActive = false;
      try { stream.close(); } catch (_) {}
      V6.sse = null;
      V6.lg.sseFailed = true;
      v6UpdateStreamBadgeDom();
      clearTimeout(V6.sseRetryT);
      V6.sseRetryT = setTimeout(function () {
        V6.lg.sseFailed = false;
        if (!document.hidden && S.page === 'vector') v6StartLeakGuardSSE();
      }, 20000);
    };
  } catch (_) {
    V6.sse = null;
    V6.lg.sseActive = false;
    V6.lg.sseFailed = true;
  }
}

function v6StopLeakGuardSSE() {
  clearTimeout(V6.sseRetryT);
  if (V6.sse) {
    try { V6.sse.close(); } catch (_) {}
    V6.sse = null;
  }
  V6.lg.sseActive = false;
}

/* ── 顶栏与跨页面徽章渲染 ── */
function v6PaintHeaderBadges() {
  var hits = num(V6.lg.total_hits);
  var b = $('#lgd-badge');
  if (b) {
    b.hidden = !(hits > 0);
    b.textContent = hits > 99 ? '99+' : String(hits);
  }
  $$('.v6-tab-dot').forEach(function (d) {
    d.hidden = !(hits > 0 || V6.thermo.stage >= 2);
  });
}

function v6IsDeviceEscorted(mac) {
  if (!mac || !V6.express.enabled) return false;
  var m = String(mac).toLowerCase();
  return V6.express.escorted_macs.indexOf(m) >= 0 || V6.express.forced_macs.indexOf(m) >= 0;
}

function v6DeviceBadgesHtml(d) {
  if (!d) return '';
  var out = '';
  if (v6IsDeviceEscorted(d.mac)) {
    var activeNow = V6.express.escorted_macs.indexOf(d.mac) >= 0;
    out += '<span class="v6-mono-badge b-ok" title="Vector Express 救护车零排队护航"><span class="v6-dot ok"></span>' + (activeNow ? 'EXPRESS' : 'VIP_PIN') + '</span>';
  }
  var hasLeash = V6.leash.enabled && V6.leash.sessions.some(function (s) {
    return ((s.mac && s.mac === d.mac) || (d.ip && s.src_ip === d.ip)) && s.state === 'leashed';
  });
  if (hasLeash) {
    out += '<span class="v6-mono-badge b-warn" title="UpdateLeash 后台大流量拴绳限速生效中"><span class="v6-dot warn"></span>LEASHED</span>';
  }
  return out;
}

function v6ExpressStateShort() {
  if (!V6.express.enabled) return ['OFF', ''];
  if (V6.express.state === 'active_escort' || V6.express.active) return ['ESCORT', 'b-ok'];
  if (V6.express.state === 'cooldown_hold') return ['HOLD', 'b-acc'];
  return ['READY', ''];
}

function v6DevicesStripHtml() {
  var lgHits = num(V6.lg.total_hits);
  var tempTxt = V6.thermo.temp_c > 0 ? V6.thermo.temp_c.toFixed(1) + ' °C' : '待采样';
  var stgCls = V6.thermo.stage >= 2 ? 'b-bad' : (V6.thermo.stage === 1 ? 'b-warn' : 'b-ok');
  var exSt = v6ExpressStateShort();
  var leashCnt = V6.leash.sessions.filter(function (s) { return s.state === 'leashed'; }).length || num(V6.leash.active_sessions);
  var bhBad = S.coreHealthy === false;
  return '<div class="glass v6-dev-banner press" data-v6-act="go-vector" role="button" tabindex="0" aria-label="打开 Vector v6 战术中枢与 LeakGuard 隐私安检">' +
    '<div class="v6-dev-banner-l">' +
      '<span class="v6-brand-tag">VECTOR v6.0</span>' +
      (bhBad ? '<span class="v6-mono-badge b-bad"><span class="v6-dot bad"></span>BULKHEAD DEGRADED</span>' : '') +
      '<span class="v6-mono-badge ' + exSt[1] + '"><span class="v6-dot ' + (exSt[1] === 'b-ok' ? 'ok' : (exSt[1] === 'b-acc' ? 'acc' : '')) + '"></span>EXPRESS ' + exSt[0] + '</span>' +
      '<span class="v6-mono-badge ' + (leashCnt > 0 ? 'b-warn' : '') + '">LEASH ' + leashCnt + '</span>' +
      '<span class="v6-mono-badge ' + stgCls + '">' + escapeHtml(V6.thermo.stage_label) + ' · ' + escapeHtml(tempTxt) + '</span>' +
      '<span class="v6-mono-badge ' + (lgHits > 0 ? 'b-bad' : 'b-ok') + '">LEAKGUARD ' + lgHits + '</span>' +
    '</div>' +
    '<span class="hint-a" style="font-size:12px">战术中枢 / 安检</span>' +
  '</div>';
}

function v6RefreshDevicesBannerDom() {
  var m = document.getElementById('v6-dev-strip-mount');
  if (m && S.page === 'devices') m.innerHTML = v6DevicesStripHtml();
}

function v6SettingsSlotHtml() {
  var lgHits = num(V6.lg.total_hits);
  var tempTxt = V6.thermo.temp_c > 0 ? V6.thermo.temp_c.toFixed(1) + ' °C' : '待采样';
  return '<section class="glass v6-card" style="margin-bottom:4px" aria-label="Vector v6 战术中枢与 LeakGuard 隐私安检入口">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb">' + ico('vector') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>Vector v6.0 战术舱与 LeakGuard 隐私安检</span><span class="v6-mono-badge b-acc">v6.0.0</span></div>' +
          '<div class="v6-card-s">集成 Vector Express 零排队、UpdateLeash 更新拴绳、ThermoCruise 温控巡航（' + escapeHtml(tempTxt) + '）、FlowScalpel 五元组手术台与 HTTP 明文泄露取证（已捕获 ' + lgHits + ' 次）</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="btns">' +
      '<button type="button" class="btn pri press" data-v6-act="go-vector">进入矢量战术中枢</button>' +
      '<button type="button" class="btn sec press" data-v6-act="open-scalpel" data-mac="" data-ip="" data-name="">开启全局五元组手术台</button>' +
    '</div>' +
  '</section>';
}

/* ── CoreHub 四大隔离舱壁状态微徽章 ── */
function v6BulkheadsBadgesHtml() {
  if (!S.bulkheads || typeof S.bulkheads !== 'object') {
    return S.vectorSyncState === 'supported'
      ? '<span class="v6-mono-badge b-ok"><span class="v6-dot ok"></span>VECTOR_SYNC OK</span>'
      : '<span class="v6-mono-badge b-acc"><span class="v6-dot acc"></span>REST_DIRECT</span>';
  }
  var keys = [
    ['dataplane', 'DP'],
    ['dpi_shm', 'DPI'],
    ['android_bridge', 'BRIDGE'],
    ['storage', 'IO']
  ];
  return keys.map(function (kv) {
    var b = S.bulkheads[kv[0]];
    if (!b) return '';
    var ok = b.healthy !== false && b.circuit_state !== 'open';
    var half = b.circuit_state === 'half_open';
    var cls = ok ? 'b-ok' : (half ? 'b-warn' : 'b-bad');
    var dot = ok ? 'ok' : (half ? 'warn' : 'bad');
    return '<span class="v6-mono-badge ' + cls + '" title="' + escapeHtml(kv[0] + ' · state=' + (b.circuit_state || 'closed') + (b.last_error ? ' · ' + b.last_error : '')) + '">' +
      '<span class="v6-dot ' + dot + '"></span>' + kv[1] + '</span>';
  }).join('');
}

function v6RefreshTopBulkheadsDom() {
  var el = document.getElementById('v6-bh-badges');
  if (el) el.innerHTML = v6BulkheadsBadgesHtml();
}

/* ═════════════════════ LeakGuard 明文隐私安检面板渲染 ═════════════════════ */
function v6StreamModeBadgeHtml() {
  var mode = (!KSU && V6.lg.sseActive) ? ['SSE_LIVE', 'b-ok', 'ok'] : (KSU ? ['KSU_POLL', 'b-acc', 'acc'] : ['HTTP_POLL', 'b-acc', 'acc']);
  return '<span class="v6-mono-badge ' + mode[1] + '" id="lgd-stream-mode"><span class="v6-dot ' + mode[2] + '"></span>' + mode[0] + '</span>';
}

function v6UpdateStreamBadgeDom() {
  var el = document.getElementById('lgd-stream-mode');
  if (el && el.parentNode) {
    var wrap = document.createElement('span');
    wrap.innerHTML = v6StreamModeBadgeHtml();
    if (wrap.firstElementChild) el.replaceWith(wrap.firstElementChild);
  }
}

function v6FilteredLeakEvents() {
  var tf = V6.lg.typeFilter || 'ALL';
  var q = String(V6.lg.q || '').trim().toLowerCase();
  return V6.lg.events.filter(function (ev) {
    if (tf !== 'ALL' && ev.leak_type !== tf && leakTypeGroup(ev.leak_type) !== tf) return false;
    if (!q) return true;
    var hay = (ev.devName + ' ' + ev.src_ip + ' ' + ev.mac + ' ' + ev.leak_type + ' ' + ev.raw_value + ' ' + ev.dst_host + ' ' + ev.url_path + ' ' + ev.user_agent).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6LeakEventRowHtml(ev) {
  var isOpen = !!V6.lg.openIds[ev.id];
  var devLabel = escapeHtml(ev.devName) + (ev.src_ip && ev.devName.indexOf(ev.src_ip) < 0 ? '<small>' + escapeHtml(ev.src_ip) + '</small>' : '');
  var bCls = leakTypeBadgeCls(ev.leak_type);
  return '<div class="lgd-item' + (isOpen ? ' is-open' : '') + (ev.is_blocked ? ' is-blocked' : '') + '" data-lgd-id="' + escapeHtml(ev.id) + '">' +
    '<div class="lgd-row" data-v6-act="lgd-toggle-row" data-id="' + escapeHtml(ev.id) + '">' +
      '<span class="lgd-ts num">' + escapeHtml(ev.timeStr) + '</span>' +
      '<span class="lgd-dev" title="' + escapeHtml(ev.devName + ' / ' + (ev.src_ip || ev.mac)) + '">' + devLabel + '</span>' +
      '<span class="lgd-type-cell"><span class="v6-mono-badge ' + bCls + '">' + escapeHtml(ev.leak_type) + '</span></span>' +
      '<span class="lgd-raw-val" title="未打码完整明文值: ' + escapeHtml(ev.raw_value) + '">' + escapeHtml(ev.raw_value || '(EMPTY)') + '</span>' +
      '<span class="lgd-host" title="' + escapeHtml(ev.dst_host + (ev.dst_ip ? ' (' + ev.dst_ip + ')' : '')) + '">' + escapeHtml(ev.dst_host) + (ev.is_blocked ? ' <span class="v6-mono-badge b-bad">BLOCKED</span>' : '') + '</span>' +
      '<span class="lgd-cnt num">x' + ev.hit_count + '</span>' +
      '<span class="lgd-acts">' +
        '<button type="button" class="lgd-act-btn ' + (ev.is_blocked ? 'ok' : 'warn') + ' press" data-v6-act="lgd-block-domain" data-id="' + escapeHtml(ev.id) + '">' + (ev.is_blocked ? '解封' : '拉黑域名+IP') + '</button>' +
        '<button type="button" class="lgd-act-btn dan press" data-v6-act="lgd-cut-conn" data-id="' + escapeHtml(ev.id) + '">秒斩连接</button>' +
        '<button type="button" class="lgd-act-btn press" data-v6-act="lgd-toggle-btn" data-id="' + escapeHtml(ev.id) + '">' + (isOpen ? '收起报文' : '展开报文') + '</button>' +
      '</span>' +
    '</div>' +
    '<div class="lgd-forensic"' + (isOpen ? '' : ' hidden') + '>' +
      '<dl class="lgd-forensic-meta">' +
        '<dt>ENDPOINT</dt><dd>' + escapeHtml(ev.proto.toUpperCase() + ' ' + (ev.src_ip || '—') + (ev.src_port ? ':' + ev.src_port : '') + ' -> ' + (ev.dst_ip || ev.dst_host) + ':' + ev.dst_port) + '</dd>' +
        '<dt>URL Path</dt><dd>' + escapeHtml(ev.method + ' ' + ev.url_path) + '</dd>' +
        '<dt>User-Agent</dt><dd>' + escapeHtml(ev.user_agent) + '</dd>' +
        '<dt>RAW VALUE</dt><dd>' + escapeHtml(ev.raw_value) + '</dd>' +
      '</dl>' +
      '<pre class="lgd-forensic-pre">' + highlightRawSnippet(ev.raw_snippet, ev.raw_value) + '</pre>' +
    '</div>' +
  '</div>';
}

function v6LeakStreamHtml() {
  var list = v6FilteredLeakEvents();
  if (!list.length) {
    return '<div class="empty" style="padding:22px 12px">' +
      (V6.lg.events.length
        ? '当前筛选条件下无匹配记录 · 共缓存 ' + V6.lg.events.length + ' 条告警'
        : '实时明文安检监听中 · 暂未捕获下游设备 HTTP 明文隐私外泄报文') +
    '</div>';
  }
  return list.map(v6LeakEventRowHtml).join('');
}

function v6RenderLeakGuardHtml() {
  var lg = V6.lg;
  var types = [
    ['ALL', 'ALL'],
    ['PHONE', 'PHONE'],
    ['DEVICE_ID', 'DEVICE_ID'],
    ['GPS', 'GPS'],
    ['MAC_ADDR', 'MAC_ADDR'],
    ['TOKEN', 'TOKEN']
  ];
  return '<section class="glass lgd-panel" id="v6-leakguard-card" aria-label="LeakGuard 明文隐私安检面板">' +
    '<div class="lgd-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb red">' + v6Svg('shieldAlert') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>LeakGuard · 明文隐私安检取证</span>' +
            v6StreamModeBadgeHtml() +
          '</div>' +
          '<div class="v6-card-s">零解密旁路嗅探下游 HTTP 明文敏感字段（手机号 / 设备指纹 / 经纬度 / MAC / 令牌），完整呈现原始载荷并支持双栈一键反制</div>' +
        '</div>' +
      '</div>' +
      '<div class="lgd-cfg-acts">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="lgd-refresh">' + ico('refresh') + '<span>刷新</span></button>' +
        '<button type="button" class="v6-mini-btn dan press" data-v6-act="lgd-clear">' + ico('trash') + '<span>清空记录</span></button>' +
      '</div>' +
    '</div>' +

    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi ' + (lg.total_hits > 0 ? 'is-bad' : 'is-ok') + '"><span>捕获泄露总次数 (total_hits)</span><b id="lgd-kpi-hits">' + num(lg.total_hits) + '</b></div>' +
      '<div class="v6-kpi ' + (lg.affected_devices > 0 ? 'is-warn' : '') + '"><span>涉及下游设备数 (affected_devices)</span><b id="lgd-kpi-devs">' + num(lg.affected_devices) + '<small>台</small></b></div>' +
      '<div class="v6-kpi is-acc"><span>已拦截追踪域名数 (blocked_domains)</span><b id="lgd-kpi-blk">' + num(lg.blocked_domains) + '<small>个</small></b></div>' +
    '</div>' +

    '<div class="lgd-ctrl-bar">' +
      '<div class="lgd-switches">' +
        '<div class="lgd-sw-row">' +
          '<span>状态栏系统通知开关<small>捕获高危明文隐私外泄时推送 Android 状态栏提醒 (notify_enabled)</small></span>' +
          toggle(lg.notify_enabled, 'id="lgd-sw-notify" data-v6-tog="lgd-notify" aria-label="状态栏系统通知开关"') +
        '</div>' +
        '<div class="lgd-sw-row">' +
          '<span>锁屏半脱敏保护开关<small>手机通知栏摘要中间位脱敏，WebUI 取证流始终保留 100% 完整原文 (lockscreen_mask)</small></span>' +
          toggle(lg.lockscreen_mask, 'id="lgd-sw-mask" data-v6-tog="lgd-mask" aria-label="锁屏半脱敏保护开关"') +
        '</div>' +
      '</div>' +
      '<div class="lgd-cfg-box">' +
        '<div class="v6-num-grid">' +
          '<label class="v6-num-field">环形缓冲容量上限' +
            '<span class="v6-num-box"><input id="lgd-ring-cap" type="number" inputmode="numeric" min="10" max="2000" step="10" value="' + num(lg.capacity, 300) + '"><span class="u">条</span></span>' +
          '</label>' +
          '<label class="v6-num-field">去重冷却秒数' +
            '<span class="v6-num-box"><input id="lgd-dedup-sec" type="number" inputmode="numeric" min="0" max="86400" step="10" value="' + num(lg.cooldown_sec, 300) + '"><span class="u">秒</span></span>' +
          '</label>' +
        '</div>' +
        '<div class="lgd-cfg-acts">' +
          '<button type="button" class="v6-mini-btn pri press" data-v6-act="lgd-save-cfg">保存安检配置</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="lgd-filter-bar">' +
      '<div class="lgd-type-chips">' +
        types.map(function (t) {
          return '<button type="button" class="lgd-tchip press' + (lg.typeFilter === t[0] ? ' on' : '') + '" data-v6-act="lgd-filter" data-type="' + t[0] + '">' + t[1] + '</button>';
        }).join('') +
      '</div>' +
      '<label class="lgd-search-mini">' + ico('search') +
        '<input id="lgd-q" type="search" placeholder="过滤明文值 / 域名 / 设备 IP" value="' + escapeHtml(lg.q) + '" autocomplete="off">' +
      '</label>' +
    '</div>' +

    '<div class="lgd-stream" id="lgd-stream-list">' + v6LeakStreamHtml() + '</div>' +
  '</section>';
}

function v6RefreshLeakGuardDom() {
  var hEl = document.getElementById('lgd-kpi-hits');
  var dEl = document.getElementById('lgd-kpi-devs');
  var bEl = document.getElementById('lgd-kpi-blk');
  if (hEl) hEl.textContent = String(num(V6.lg.total_hits));
  if (dEl) dEl.innerHTML = num(V6.lg.affected_devices) + '<small>台</small>';
  if (bEl) bEl.innerHTML = num(V6.lg.blocked_domains) + '<small>个</small>';
  var swN = document.getElementById('lgd-sw-notify');
  if (swN && !swN.classList.contains('pending')) swN.setAttribute('aria-checked', String(!!V6.lg.notify_enabled));
  var swM = document.getElementById('lgd-sw-mask');
  if (swM && !swM.classList.contains('pending')) swM.setAttribute('aria-checked', String(!!V6.lg.lockscreen_mask));
  var capIn = document.getElementById('lgd-ring-cap');
  if (capIn && document.activeElement !== capIn) capIn.value = String(num(V6.lg.capacity, 300));
  var cdIn = document.getElementById('lgd-dedup-sec');
  if (cdIn && document.activeElement !== cdIn) cdIn.value = String(num(V6.lg.cooldown_sec, 300));
  v6UpdateStreamBadgeDom();
  var stEl = document.getElementById('lgd-stream-list');
  if (stEl) stEl.innerHTML = v6LeakStreamHtml();
}

/* ═════════════════════ Vector v6 四大王牌战术舱渲染 ═════════════════════ */
function v6RenderExpressCardHtml() {
  var ex = V6.express;
  var stateBadge = !ex.enabled
    ? ['DISABLED', '', '']
    : (ex.state === 'active_escort' || ex.active
      ? ['TIER-0 ESCORT', 'b-ok', 'ok']
      : (ex.state === 'cooldown_hold' ? ['COOLDOWN ' + ex.cooldown_remaining_sec + 'S', 'b-acc', 'acc'] : ['IDLE FULLSPEED', '', '']));

  var onlineDevs = (S.devices || []).filter(function (d) { return d.online; });
  var vipPills = onlineDevs.length ? '<div class="v6-dev-pills">' + onlineDevs.slice(0, 10).map(function (d) {
    var isForced = ex.forced_macs.indexOf(d.mac) >= 0;
    var isAutoEscort = ex.escorted_macs.indexOf(d.mac) >= 0;
    var reason = ex.escort_reasons && ex.escort_reasons[d.mac] ? String(ex.escort_reasons[d.mac]) : '';
    var on = isForced || isAutoEscort;
    return '<button type="button" class="v6-dev-pill press' + (on ? ' on' : '') + '" data-v6-act="express-dev" data-mac="' + escapeHtml(d.mac) + '" title="' + escapeHtml(reason || (isForced ? '手动常驻护航' : '点按手动指定/取消常驻零排队护航')) + '">' +
      '<span class="v6-dot ' + (on ? 'ok' : '') + '"></span><span>' + escapeHtml(d.name) + (isForced ? ' · PIN' : (isAutoEscort ? ' · AUTO' : '')) + '</span></button>';
  }).join('') + '</div>' : '<div class="note">暂无在线热点设备 · 设备接入后可自动识别游戏/会议或一键锁定救护车护航</div>';

  return '<article class="glass v6-card" id="v6-card-express">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb green">' + v6Svg('express') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>Vector Express · 救护车零排队</span>' +
            '<span class="v6-mono-badge ' + stateBadge[1] + '">' + (stateBadge[2] ? '<span class="v6-dot ' + stateBadge[2] + '"></span>' : '') + stateBadge[0] + '</span>' +
          '</div>' +
          '<div class="v6-card-s">关键对战/音视频实时流直入 PRIO 0 高优队列 (' + escapeHtml(ex.qdisc || 'fq_codel') + ')，自动压低后台池上限防缓冲膨胀</div>' +
        '</div>' +
      '</div>' +
      toggle(ex.enabled, 'data-v6-tog="express" aria-label="Vector Express 救护车零排队开关"') +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi ' + (ex.escorted_macs.length > 0 ? 'is-ok' : '') + '"><span>当前护航设备</span><b>' + ex.escorted_macs.length + '<small>台</small></b></div>' +
      '<div class="v6-kpi ' + (ex.bg_ceil_pct < 100 ? 'is-acc' : '') + '"><span>后台池带宽上限</span><b>' + num(ex.bg_ceil_pct, 100) + '<small>%</small></b></div>' +
      '<div class="v6-kpi"><span>手动常驻锁定</span><b>' + ex.forced_macs.length + '<small>台</small></b></div>' +
    '</div>' +
    '<div class="v6-thermo-flags">' +
      '<button type="button" class="v6-dev-pill press' + (ex.auto_detect ? ' on' : '') + '" data-v6-act="express-auto">' +
        '<span class="v6-dot ' + (ex.auto_detect ? 'ok' : '') + '"></span><span>AUTO_DETECT · 自动识别游戏与实时通话</span>' +
      '</button>' +
    '</div>' +
    '<div><div class="note" style="margin-bottom:6px">点选在线设备锁定/解除手动零排队护航：</div>' + vipPills + '</div>' +
  '</article>';
}

function v6RenderUpdateLeashCardHtml() {
  var ul = V6.leash;
  var leashedNow = ul.sessions.filter(function (s) { return s.state === 'leashed'; }).length;
  var stateBadgeMap = {
    leashed: ['LEASHED', 'b-warn'],
    grace_fullspeed: ['GRACE', 'b-acc'],
    bypassed: ['BYPASSED', 'b-ok'],
    paused: ['PAUSED', 'b-bad']
  };
  var flowHtml = ul.sessions.length ? '<div class="v6-flow-list">' + ul.sessions.map(function (s) {
    var sb = stateBadgeMap[s.state] || ['ACTIVE', ''];
    var vendorPrefix = s.vendor_label ? (s.vendor_label + ' · ') : '';
    return '<div class="v6-flow-item">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t">' +
          '<span class="v6-mono-badge ' + sb[1] + '">' + sb[0] + '</span>' +
          '<span>' + escapeHtml(s.devName) + '</span>' +
          '<span class="mono" style="font-size:11.5px;color:var(--text-2)">' + escapeHtml(vendorPrefix + s.dst_host) + '</span>' +
        '</div>' +
        '<div class="v6-flow-s">' + escapeHtml((s.src_ip || '—') + ' -> ' + (s.dst_ip || s.dst_host)) +
          ' · 已跑 ' + s.down_mb.toFixed(1) + ' MB' +
          (s.state === 'grace_fullspeed' ? (' (余 ' + s.rem_mb.toFixed(0) + ' MB 免死额)') : (' · 限速 ' + (s.applied_kbps || ul.leash_kbps) + ' Kbps')) +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:5px;flex-wrap:wrap">' +
        (!s.bypass_once ? '<button type="button" class="v6-mini-btn ok press" data-v6-act="leash-release" data-skey="' + escapeHtml(s.session_key) + '" data-mac="' + escapeHtml(s.mac) + '" data-host="' + escapeHtml(s.dst_host) + '"><span>本次全速放行</span></button>' : '') +
        '<button type="button" class="v6-mini-btn ' + (s.paused ? 'pri' : 'warn') + ' press" data-v6-act="leash-pause-toggle" data-paused="' + (s.paused ? '1' : '0') + '" data-skey="' + escapeHtml(s.session_key) + '" data-mac="' + escapeHtml(s.mac) + '" data-host="' + escapeHtml(s.dst_host) + '"><span>' + (s.paused ? '恢复更新' : '暂停拉取') + '</span></button>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>' : '<div class="note">当前无被拴绳更新流 · 命中系统/商店更新源且单会话超出 ' + num(ul.grace_mb, 200) + ' MB 缓冲池后自动平滑收束至 ' + num(ul.leash_kbps, 1500) + ' Kbps</div>';

  return '<article class="glass v6-card" id="v6-card-leash">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb orange">' + v6Svg('leash') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>UpdateLeash · 后台更新拴绳</span>' +
            '<span class="v6-mono-badge ' + (ul.enabled ? (leashedNow > 0 ? 'b-warn' : 'b-ok') : '') + '">' + (ul.enabled ? ('LEASH ' + leashedNow + ' / ' + ul.sessions.length) : 'DISABLED') + '</span>' +
          '</div>' +
          '<div class="v6-card-s">前段突发全速放行保障常规补丁秒下，持续后台巨量系统/商店更新自动套上速率拴绳防刷爆套餐</div>' +
        '</div>' +
      '</div>' +
      toggle(ul.enabled, 'data-v6-tog="leash" aria-label="UpdateLeash 后台更新拴绳开关"') +
    '</div>' +
    '<div class="v6-num-grid">' +
      '<label class="v6-num-field">满速免死缓冲池 MB' +
        '<span class="v6-num-box"><input id="v6-ul-grace" type="number" inputmode="numeric" min="10" max="10240" step="10" value="' + num(ul.grace_mb, 200) + '"><span class="u">MB</span></span>' +
      '</label>' +
      '<label class="v6-num-field">拴绳限速 Kbps' +
        '<span class="v6-num-box"><input id="v6-ul-kbps" type="number" inputmode="numeric" min="128" max="1000000" step="50" value="' + num(ul.leash_kbps, 1500) + '"><span class="u">Kbps</span></span>' +
      '</label>' +
    '</div>' +
    '<div style="display:flex;justify-content:flex-end">' +
      '<button type="button" class="v6-mini-btn pri press" data-v6-act="leash-save">保存拴绳阈值</button>' +
    '</div>' +
    flowHtml +
  '</article>';
}

function v6RenderThermoCardHtml() {
  var th = V6.thermo;
  var stgCls = th.stage >= 2 ? 'b-bad' : (th.stage === 1 ? 'b-warn' : 'b-ok');
  var stgDot = th.stage >= 2 ? 'bad' : (th.stage === 1 ? 'warn' : 'ok');
  var tempStr = th.temp_c > 0 ? th.temp_c.toFixed(1) : '—';
  var batStr = th.capacity_pct > 0 ? String(th.capacity_pct) : '—';

  return '<article class="glass v6-card" id="v6-card-thermo">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb ' + (th.stage >= 2 ? 'red' : (th.stage === 1 ? 'orange' : 'purple')) + '">' + v6Svg('thermo') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>ThermoCruise · 电芯温控巡航</span>' +
            '<span class="v6-mono-badge ' + stgCls + '"><span class="v6-dot ' + stgDot + '"></span>' + escapeHtml(th.stage_label) + '</span>' +
          '</div>' +
          '<div class="v6-card-s">零 IPC 直读内核 sysfs 电芯温度与电量，阶梯式收束后台轮询与过热吞吐，3 °C 施密特回差防抖</div>' +
        '</div>' +
      '</div>' +
      toggle(th.enabled, 'data-v6-tog="thermo" aria-label="ThermoCruise 温控巡航开关"') +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi ' + (th.stage >= 2 ? 'is-bad' : (th.stage === 1 ? 'is-warn' : 'is-ok')) + '"><span>实时电芯温度</span><b>' + escapeHtml(tempStr) + '<small>°C</small></b></div>' +
      '<div class="v6-kpi ' + (th.low_battery_cruise ? 'is-warn' : '') + '"><span>当前剩余电量</span><b>' + escapeHtml(batStr) + '<small>%</small></b></div>' +
      '<div class="v6-kpi is-acc"><span>巡航控制档位</span><b>' + escapeHtml(th.stage_label) + '</b></div>' +
    '</div>' +
    '<div class="v6-thermo-flags">' +
      '<span class="v6-mono-badge ' + (th.is_charging ? 'b-ok' : '') + '" title="外接供电时二阶温控整形自动豁免"><span class="v6-dot ' + (th.is_charging ? 'ok' : '') + '"></span>CHARGING_EXEMPT · ' + (th.is_charging ? '充电豁免生效' : '未接电源') + '</span>' +
      '<span class="v6-mono-badge ' + (th.vector_express_active ? 'b-ok' : '') + '" title="Vector Express 护航期间二阶温控整形自动豁免不掉帧"><span class="v6-dot ' + (th.vector_express_active ? 'ok' : '') + '"></span>GAMING_EXEMPT · ' + (th.vector_express_active ? '护航豁免生效' : '待命') + '</span>' +
      '<button type="button" class="v6-dev-pill press' + (th.stage2_shaper_enabled ? ' on' : '') + '" data-v6-act="thermo-shaper" title="允许达到二阶温度且无豁免条件时温和收束总带宽">' +
        '<span class="v6-dot ' + (th.stage2_shaper_enabled ? 'acc' : '') + '"></span><span>STAGE2_SHAPER · 二阶降温限流</span>' +
      '</button>' +
    '</div>' +
    '<div class="v6-num-grid">' +
      '<label class="v6-num-field">一阶省电温度 °C' +
        '<span class="v6-num-box"><input id="v6-th-t1" type="number" inputmode="numeric" min="30" max="70" step="1" value="' + num(th.stage1_temp_c, 42) + '"><span class="u">°C</span></span>' +
      '</label>' +
      '<label class="v6-num-field">二阶护航温度 °C' +
        '<span class="v6-num-box"><input id="v6-th-t2" type="number" inputmode="numeric" min="32" max="75" step="1" value="' + num(th.stage2_temp_c, 45) + '"><span class="u">°C</span></span>' +
      '</label>' +
    '</div>' +
    '<div style="display:flex;justify-content:flex-end">' +
      '<button type="button" class="v6-mini-btn pri press" data-v6-act="thermo-save">保存温控阈值</button>' +
    '</div>' +
  '</article>';
}

function v6RenderScalpelCabinCardHtml() {
  var sc = V6.scalpel;
  var onlineDevs = (S.devices || []).filter(function (d) { return d.online; });
  var devBtns = onlineDevs.length ? '<div class="v6-dev-pills">' + onlineDevs.slice(0, 8).map(function (d) {
    return '<button type="button" class="v6-dev-pill press" data-v6-act="open-scalpel" data-mac="' + escapeHtml(d.mac) + '" data-ip="' + escapeHtml(d.ip || '') + '" data-name="' + escapeHtml(d.name) + '">' +
      v6Svg('scalpel') + '<span>' + escapeHtml(d.name) + '</span></button>';
  }).join('') + '</div>' : '<div class="note">点按下方「打开全局五元组手术台抽屉」可实时透视活跃 TCP / UDP / QUIC 五元组</div>';

  return '<article class="glass v6-card" id="v6-card-scalpel">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb">' + v6Svg('scalpel') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>FlowScalpel · 五元组连接手术台</span>' +
            '<span class="v6-mono-badge b-acc">5-TUPLE RST/DROP</span>' +
          '</div>' +
          '<div class="v6-card-s">精准定位异常吸血连接或顽固重连，免断网「单斩死流」销毁 conntrack 或「秒斩+冻结15分钟」</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi is-acc"><span>实时活跃五元组</span><b>' + num(sc.totalFlows, sc.flows.length) + '<small>条</small></b></div>' +
      '<div class="v6-kpi ' + (sc.activeRulesCount > 0 ? 'is-warn' : '') + '"><span>15分钟冻结规则</span><b>' + num(sc.activeRulesCount) + '<small>条</small></b></div>' +
      '<div class="v6-kpi"><span>累计精准斩流</span><b>' + num(sc.cutTotal) + '<small>次</small></b></div>' +
    '</div>' +
    '<div><div class="note" style="margin-bottom:6px">按设备直呼单机五元组手术台：</div>' + devBtns + '</div>' +
    '<button type="button" class="btn pri wide press" data-v6-act="open-scalpel" data-mac="" data-ip="" data-name="">' + v6Svg('scalpel') + '<span>打开全局五元组手术台抽屉</span></button>' +
  '</article>';
}

function v6ApplyBlackboxData(r) {
  if (!r || typeof r !== 'object') return;
  if (r.granularity_ms != null) V6.blackbox.granularity_ms = Math.round(num(r.granularity_ms, 200));
  if (r.total_ticks != null) V6.blackbox.total_ticks = Math.max(0, Math.round(num(r.total_ticks)));
  if (r.incident_count != null) V6.blackbox.incident_count = Math.max(0, Math.round(num(r.incident_count)));
  if (r.latest_jitter_ms != null) V6.blackbox.latest_jitter_ms = num(r.latest_jitter_ms, 0);
  if (Array.isArray(r.incidents)) V6.blackbox.incidents = r.incidents.slice(0, 8);
  else if (r.latest_incident && typeof r.latest_incident === 'object') V6.blackbox.incidents = [r.latest_incident];
}

function v6ApplyMultiIfaceData(r) {
  if (!r || typeof r !== 'object') return;
  if (r.primary_downstream != null) V6.multiIface.primary_downstream = String(r.primary_downstream || '');
  if (Array.isArray(r.shape_targets)) V6.multiIface.shape_targets = r.shape_targets.map(String);
  if (typeof r.dual_band_or_mlo === 'boolean') V6.multiIface.dual_band_or_mlo = r.dual_band_or_mlo;
  if (typeof r.usb_tether_active === 'boolean') V6.multiIface.usb_tether_active = r.usb_tether_active;
  var tg = (r.tun0_guard && typeof r.tun0_guard === 'object') ? r.tun0_guard : r;
  if (typeof tg.vpn_active === 'boolean') V6.multiIface.tun0_vpn_active = tg.vpn_active;
  else if (typeof r.tun0_vpn_active === 'boolean') V6.multiIface.tun0_vpn_active = r.tun0_vpn_active;
  if (typeof tg.loop_risk_detected === 'boolean') V6.multiIface.tun0_loop_risk = tg.loop_risk_detected;
  else if (typeof r.tun0_loop_risk === 'boolean') V6.multiIface.tun0_loop_risk = r.tun0_loop_risk;
  if (typeof tg.low16_mark_safe === 'boolean') V6.multiIface.low16_mark_safe = tg.low16_mark_safe;
  else if (typeof r.low16_mark_safe === 'boolean') V6.multiIface.low16_mark_safe = r.low16_mark_safe;
}

function v6ApplyScreenshotPackSummary(pk) {
  if (!pk || typeof pk !== 'object') return;
  if (pk.blackbox) v6ApplyBlackboxData(pk.blackbox);
  if (pk.multi_iface) v6ApplyMultiIfaceData(pk.multi_iface);
  if (pk.native_subtrees && typeof pk.native_subtrees === 'object') {
    var dq = pk.native_subtrees.dynamic_qos || {};
    if (dq.Mode || dq.mode) V6.subtrees.qos_mode = String(dq.Mode || dq.mode);
    if (dq.Tier1RealtimePct != null || dq.tier1_pct != null) V6.subtrees.tier1_pct = Math.round(num(dq.Tier1RealtimePct != null ? dq.Tier1RealtimePct : dq.tier1_pct, 50));
    if (dq.Tier2InteractivePct != null || dq.tier2_pct != null) V6.subtrees.tier2_pct = Math.round(num(dq.Tier2InteractivePct != null ? dq.Tier2InteractivePct : dq.tier2_pct, 35));
    if (dq.Tier3BulkPct != null || dq.tier3_pct != null) V6.subtrees.tier3_pct = Math.round(num(dq.Tier3BulkPct != null ? dq.Tier3BulkPct : dq.tier3_pct, 15));
    if (pk.native_subtrees.full_restores != null) V6.subtrees.full_restores = Math.round(num(pk.native_subtrees.full_restores));
  }
}

function v6RenderBlackboxCardHtml() {
  var bb = V6.blackbox;
  var mi = V6.multiIface;
  var st = V6.subtrees;
  var targets = mi.shape_targets.length ? mi.shape_targets.join(' + ') : (mi.primary_downstream || S.iface || '待探测');
  var incList = bb.incidents.length ? '<div class="v6-flow-list">' + bb.incidents.slice(0, 3).map(function (inc) {
    var tsTxt = fmtClockTs(inc.unix_ms || inc.ts || 0);
    var cause = String(inc.root_cause_zh || inc.root_cause || inc.summary || '检测到瞬时抖动尖峰');
    var culprit = String(inc.culprit_device || inc.culprit_mac || '');
    var rtt = num(inc.rtt_ms != null ? inc.rtt_ms : inc.jitter_ms, 0);
    return '<div class="v6-flow-item">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-warn">' + escapeHtml(tsTxt) + '</span><span>' + escapeHtml(cause) + '</span></div>' +
        '<div class="v6-flow-s">' + (culprit ? ('归因源: ' + escapeHtml(culprit) + ' · ') : '') + '尖峰 ' + rtt.toFixed(1) + ' ms</div>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>' : '<div class="note">200ms 环形飞行记录仪零闪存运行中 · 当前无异常延迟尖峰事件</div>';

  return '<article class="glass v6-card" id="v6-card-blackbox">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb purple">' + v6Svg('blackbox') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>JitterBlackbox · 200ms 卡顿黑匣子与多口并管</span>' +
            '<span class="v6-mono-badge ' + (bb.incident_count > 0 ? 'b-warn' : 'b-ok') + '">' + bb.granularity_ms + 'MS RING</span>' +
          '</div>' +
          '<div class="v6-card-s">每 200ms 采样信号/队列/大流归因抓出团战跳 Ping 元凶，同时监控 Wi-Fi 7 MLO / USB 共享并管、1:fffe 2.5Gbps 局域网直通与 tun0 防环路守卫</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi ' + (bb.latest_jitter_ms > 25 ? 'is-warn' : 'is-ok') + '"><span>实时采样抖动</span><b>' + bb.latest_jitter_ms.toFixed(1) + '<small>ms</small></b></div>' +
      '<div class="v6-kpi ' + (bb.incident_count > 0 ? 'is-warn' : '') + '"><span>捕获跳 Ping 事故</span><b>' + num(bb.incident_count) + '<small>起</small></b></div>' +
      '<div class="v6-kpi is-acc"><span>动态 QoS 配比</span><b>' + st.tier1_pct + '/' + st.tier2_pct + '/' + st.tier3_pct + '</b></div>' +
    '</div>' +
    '<div class="v6-thermo-flags">' +
      '<span class="v6-mono-badge b-ok"><span class="v6-dot ok"></span>IFACES · ' + escapeHtml(targets) + '</span>' +
      '<span class="v6-mono-badge b-acc">LAN 1:fffe · 2.5Gbps</span>' +
      '<span class="v6-mono-badge ' + (mi.tun0_loop_risk ? 'b-bad' : 'b-ok') + '">TUN0_GUARD · ' + (mi.tun0_loop_risk ? '环路告警' : (mi.tun0_vpn_active ? 'VPN 安全共存' : '净空')) + '</span>' +
      (mi.dual_band_or_mlo ? '<span class="v6-mono-badge b-ok">MLO/DUAL_AP</span>' : '') +
      (mi.usb_tether_active ? '<span class="v6-mono-badge b-ok">USB_TETHER</span>' : '') +
    '</div>' +
    incList +
    '<div style="display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="bb-sample">立即抓拍一帧</button>' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="subtrees-sync">同步原生 M8 子树</button>' +
      '<button type="button" class="v6-mini-btn dan press" data-v6-act="bb-clear">清空黑匣子</button>' +
    '</div>' +
  '</article>';
}

function v6RenderConfigVaultCardHtml() {
  var vt = V6.vault;
  var shaShort = vt.last_sha256 ? (vt.last_sha256.slice(0, 16) + '…') : 'SHA256 确定性校验就绪';
  return '<article class="glass v6-card" id="v6-card-vault">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb green">' + v6Svg('vault') + '</span>' +
        '<div>' +
          '<div class="v6-card-t">' +
            '<span>ConfigVault · 整机配置一键备份与原子恢复</span>' +
            '<span class="v6-mono-badge b-acc">SHA256 ATOMIC</span>' +
          '</div>' +
          '<div class="v6-card-s">一键打包规则、设备备注、应用限速与全部 v6 策略 JSON（自动剔除敏感会话令牌），换机或重刷模块后全量校验原子回滚恢复</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi is-ok"><span>支持备份配置集</span><b>16+<small>项</small></b></div>' +
      '<div class="v6-kpi"><span>最近导出文件数</span><b>' + num(vt.last_file_count) + '<small>个</small></b></div>' +
      '<div class="v6-kpi is-acc"><span>最近恢复文件数</span><b>' + num(vt.last_restored) + '<small>个</small></b></div>' +
    '</div>' +
    '<div class="note mono">完整性摘要：' + escapeHtml(shaShort) + '</div>' +
    '<input type="file" id="v6-backup-file" accept=".json,application/json" hidden>' +
    '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
      '<button type="button" class="btn pri press" data-v6-act="backup-export">导出整机备份 JSON</button>' +
      '<button type="button" class="btn sec press" data-v6-act="backup-import-pick">选择备份文件原子恢复</button>' +
    '</div>' +
  '</article>';
}

function v6RenderCockpitGridHtml() {
  return '<div class="v6-grid" id="v6-cockpit-grid">' +
    v6RenderExpressCardHtml() +
    v6RenderUpdateLeashCardHtml() +
    v6RenderThermoCardHtml() +
    v6RenderScalpelCabinCardHtml() +
    v6RenderBlackboxCardHtml() +
    v6RenderConfigVaultCardHtml() +
  '</div>';
}

function v6RefreshCockpitDom() {
  var g = document.getElementById('v6-cockpit-grid');
  if (!g) return;
  if (document.querySelector('#v6-cockpit-grid input:focus')) return;
  if (typeof morphOuter === 'function') morphOuter(g, v6RenderCockpitGridHtml());
  else g.outerHTML = v6RenderCockpitGridHtml();
}

/* ═════════════════════ Vector 主页面渲染 (#p-vector) ═════════════════════ */
function v6BuildPageHtml() {
  var vw = V6.view || 'all';
  var showLg = vw === 'all' || vw === 'leakguard';
  var showCp = vw === 'all' || vw === 'cockpit';
  return '<div class="wrap v6-shell">' +
    '<div class="glass v6-top-strip">' +
      '<div class="v6-top-title">' +
        '<span class="v6-brand-tag">HNC v6.0 · VECTOR</span>' +
        '<div>' +
          '<b>矢量战术中枢与明文隐私安检</b>' +
          '<small>' + (S.vectorSyncState === 'supported' ? '已启用 /api/vector_sync 无锁快照聚合快路径' : '自适应 REST / SSE 实时遥测') + '</small>' +
        '</div>' +
      '</div>' +
      '<div class="v6-top-right">' +
        '<div id="v6-bh-badges" style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">' + v6BulkheadsBadgesHtml() + '</div>' +
        seg('v6-view', [['all', '全览同屏'], ['leakguard', '隐私安检'], ['cockpit', '六大战术舱']], vw, 'small') +
      '</div>' +
    '</div>' +
    '<div id="v6-leakguard-wrap"' + (showLg ? '' : ' hidden') + '>' + v6RenderLeakGuardHtml() + '</div>' +
    '<div id="v6-cockpit-wrap"' + (showCp ? '' : ' hidden') + '>' + v6RenderCockpitGridHtml() + '</div>' +
  '</div>';
}

function renderVectorPage(anim1) {
  var pg = document.getElementById('p-vector');
  if (!pg) return;
  var html = v6BuildPageHtml();
  if (!anim1 && pg.firstElementChild) morph(pg, html);
  else pg.innerHTML = html;
  placeSegs(pg);
  if (anim1 && typeof stagger === 'function') stagger($('.v6-shell', pg));
}

function v6RefreshVectorDom() {
  if (S.page !== 'vector') return;
  v6RefreshTopBulkheadsDom();
  v6RefreshLeakGuardDom();
  v6RefreshCockpitDom();
}

function onEnterVectorPage() {
  v6LoadLeakGuard();
  v6LoadCockpitAll();
  v6StartLeakGuardSSE();
}

function v6ScrollToLeakGuard() {
  var el = document.getElementById('v6-leakguard-card');
  if (el && el.scrollIntoView) el.scrollIntoView({ behavior: motionOn() ? 'smooth' : 'auto', block: 'start' });
}

/* ═════════════════════ FlowScalpel 五元组手术台抽屉 ═════════════════════ */
function v6FilteredScalpelFlows() {
  var pf = V6.scalpel.protoFilter || 'ALL';
  var q = String(V6.scalpel.q || '').trim().toLowerCase();
  return V6.scalpel.flows.filter(function (f) {
    if (V6.scalpel.mac && f.mac && f.mac !== V6.scalpel.mac) return false;
    if (!V6.scalpel.mac && V6.scalpel.ip && f.src_ip && f.src_ip !== V6.scalpel.ip) return false;
    if (pf !== 'ALL' && f.protoBadge !== pf && f.proto.toUpperCase() !== pf) return false;
    if (!q) return true;
    var hay = (f.src_ip + ':' + f.sport + ' ' + f.dst_ip + ':' + f.dport + ' ' + f.dst_host + ' ' + f.app_name + ' ' + f.devName + ' ' + f.protoBadge).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6ScalpelListHtml() {
  if (V6.scalpel.loading && !V6.scalpel.flows.length) {
    return '<div class="empty">正在读取内核 conntrack 五元组流表…</div>';
  }
  if (V6.scalpel.err && !V6.scalpel.flows.length) {
    return '<div class="empty">' + escapeHtml(V6.scalpel.err) + '</div>';
  }
  var list = v6FilteredScalpelFlows();
  if (!list.length) {
    return '<div class="empty">当前筛选范围内没有活跃五元组连接</div>';
  }
  return list.slice(0, 150).map(function (f) {
    var pCls = f.protoBadge === 'QUIC' ? 'b-pur' : (f.protoBadge === 'UDP' ? 'b-warn' : 'b-acc');
    var dn = bps(f.rx_bps), up = bps(f.tx_bps);
    var hostTag = f.dst_host ? '<span class="v6-mono-badge">' + escapeHtml(f.dst_host) + '</span>' : '';
    var appTag = f.app_name ? '<span class="v6-mono-badge b-ok">' + escapeHtml(f.app_name) + '</span>' : '';
    var stTag = f.frozen ? '<span class="v6-mono-badge b-bad">FROZEN_15M</span>' : '<span class="v6-mono-badge">' + escapeHtml(f.state) + '</span>';
    var canCut = v6ValidIp(f.src_ip) && v6ValidIp(f.dst_ip) && f.sport >= 1 && f.dport >= 1;
    return '<div class="v6-tuple-row" data-fid="' + escapeHtml(f.id) + '">' +
      '<div class="v6-tuple-proto"><span class="v6-mono-badge ' + pCls + '">' + escapeHtml(f.protoBadge) + '</span></div>' +
      '<div class="v6-tuple-5">' +
        '<div class="ep" title="' + escapeHtml(f.src_ip + ':' + f.sport + ' -> ' + f.dst_ip + ':' + f.dport) + '">' +
          escapeHtml((f.src_ip || '—') + ':' + f.sport + ' -> ' + (f.dst_ip || '—') + ':' + f.dport) +
        '</div>' +
        '<div class="sub5">' +
          (!V6.scalpel.mac ? '<span>' + escapeHtml(f.devName) + '</span>' : '') +
          appTag + hostTag + stTag +
          (f.bytes > 0 ? '<span class="mono">' + escapeHtml(bytes(f.bytes)) + '</span>' : '') +
        '</div>' +
      '</div>' +
      '<div class="v6-tuple-rate num">' +
        '<div>RX ' + dn.v + ' ' + dn.u + '</div>' +
        '<div style="color:var(--text-3)">TX ' + up.v + ' ' + up.u + '</div>' +
      '</div>' +
      '<div class="v6-tuple-acts">' +
        '<button type="button" class="v6-mini-btn warn press" data-v6-act="scalpel-cut-once" data-fid="' + escapeHtml(f.id) + '"' + (canCut ? '' : ' disabled') + ' title="单斩此连接并立即清理内核 conntrack 状态">' +
          '<span>单斩死流</span>' +
        '</button>' +
        '<button type="button" class="v6-mini-btn dan press" data-v6-act="scalpel-cut-freeze" data-fid="' + escapeHtml(f.id) + '"' + (canCut ? '' : ' disabled') + ' title="秒斩连接并在 FORWARD 链精准冻结该四元组 15 分钟">' +
          '<span>秒斩+冻结15分钟</span>' +
        '</button>' +
      '</div>' +
    '</div>';
  }).join('');
}

function v6ScalpelDrawerBodyHtml() {
  var sc = V6.scalpel;
  var scopeTitle = sc.mac || sc.ip
    ? ('五元组手术台 · ' + escapeHtml(sc.devName || sc.ip || sc.mac))
    : 'FlowScalpel · 全局五元组连接手术台';
  var scopeSub = sc.mac || sc.ip
    ? ('锁定终端 ' + escapeHtml((sc.ip ? sc.ip + ' · ' : '') + (sc.mac || '')))
    : '实时透视全热点 TCP / UDP / QUIC 五元组流表 · 免断网单流手术切断与 15 分钟阻断冻结';
  var protos = ['ALL', 'TCP', 'UDP', 'QUIC'];

  return '<div class="v6-drawer-head">' +
      '<div style="min-width:0">' +
        '<div class="v6-card-t">' + v6Svg('scalpel', 'ui-ic') + '<span>' + scopeTitle + '</span>' +
          '<span class="v6-mono-badge b-acc" id="v6-sc-cnt">' + v6FilteredScalpelFlows().length + ' FLOWS</span>' +
          (sc.activeRulesCount > 0 ? '<span class="v6-mono-badge b-warn" id="v6-sc-rules">' + sc.activeRulesCount + ' FROZEN</span>' : '<span class="v6-mono-badge b-warn" id="v6-sc-rules" hidden>0 FROZEN</span>') +
        '</div>' +
        '<div class="v6-card-s mono">' + scopeSub + '</div>' +
      '</div>' +
      '<div style="display:flex;gap:6px;align-items:center;flex:none">' +
        ((sc.mac || sc.ip) ? '<button type="button" class="v6-mini-btn press" data-v6-act="scalpel-all-scope">看全网</button>' : '') +
        '<button type="button" class="v6-mini-btn ' + (sc.paused ? 'warn' : '') + ' press" data-v6-act="scalpel-pause">' + (sc.paused ? '已暂停' : '实时2s') + '</button>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="scalpel-close">关闭</button>' +
      '</div>' +
    '</div>' +
    '<div class="v6-drawer-tools">' +
      '<div class="lgd-type-chips">' +
        protos.map(function (p) {
          return '<button type="button" class="lgd-tchip press' + (sc.protoFilter === p ? ' on' : '') + '" data-v6-act="scalpel-proto" data-proto="' + p + '">' + p + '</button>';
        }).join('') +
      '</div>' +
      '<label class="lgd-search-mini">' + ico('search') +
        '<input id="v6-sc-q" type="search" placeholder="筛选 IP / 端口 / SNI / 应用" value="' + escapeHtml(sc.q) + '" autocomplete="off">' +
      '</label>' +
    '</div>' +
    '<div class="v6-tuple-list" id="v6-sc-list">' + v6ScalpelListHtml() + '</div>';
}

function v6FetchScalpelFlows() {
  var params = { limit: 200 };
  if (v6ValidMac(V6.scalpel.mac)) params.mac = V6.scalpel.mac;
  if (v6ValidIp(V6.scalpel.ip)) params.ip = V6.scalpel.ip;
  V6.scalpel.loading = true;
  return api.get(V6_API.scalpelFlows, params, { timeout: 7000 }).then(function (r) {
    V6.scalpel.err = '';
    V6.scalpel.loading = false;
    v6ApplyScalpelData(r);
    v6RefreshScalpelDrawerList();
    if (S.page === 'vector') v6RefreshCockpitDom();
  }).catch(function (e) {
    V6.scalpel.loading = false;
    if (V6.scalpel.mac && S.conn && S.conn[V6.scalpel.mac] && S.conn[V6.scalpel.mac].r && Array.isArray(S.conn[V6.scalpel.mac].r.conns)) {
      var d0 = devBy(V6.scalpel.mac);
      v6ApplyScalpelData({
        flows: S.conn[V6.scalpel.mac].r.conns.map(function (c) {
          return {
            proto: c.proto,
            src_ip: (d0 && d0.ip) || V6.scalpel.ip || '',
            sport: c.sport,
            dst_ip: c.dst,
            dport: c.dport,
            domain: c.name || c.svc || '',
            app_name: c.app || '',
            state: c.state || 'ESTABLISHED',
            down_bps: c.down_bps,
            up_bps: c.up_bps,
            down_bytes: c.down_bytes,
            up_bytes: c.up_bytes,
            mac: V6.scalpel.mac
          };
        })
      });
      V6.scalpel.err = '';
    } else {
      V6.scalpel.err = '读取五元组流表失败：' + errText(e);
    }
    v6RefreshScalpelDrawerList();
  });
}

function v6RefreshScalpelDrawerList() {
  if (!V6.scalpel.open) return;
  var listEl = document.getElementById('v6-sc-list');
  if (listEl) listEl.innerHTML = v6ScalpelListHtml();
  var cntEl = document.getElementById('v6-sc-cnt');
  if (cntEl) cntEl.textContent = v6FilteredScalpelFlows().length + ' FLOWS';
  var rEl = document.getElementById('v6-sc-rules');
  if (rEl) {
    rEl.hidden = !(V6.scalpel.activeRulesCount > 0);
    rEl.textContent = V6.scalpel.activeRulesCount + ' FROZEN';
  }
}

function openScalpelDrawer(mac, ip, name) {
  var dr = document.getElementById('v6-scalpel-drawer');
  var sc = document.getElementById('v6-scalpel-scrim');
  var bd = document.getElementById('v6-scalpel-body');
  if (!dr || !bd) return;
  if ($('#sheet') && $('#sheet').classList.contains('show')) closeSheet(0);
  V6.scalpel.open = true;
  var normMac = String(mac || '').toLowerCase();
  V6.scalpel.mac = v6ValidMac(normMac) ? normMac : '';
  V6.scalpel.ip = v6ValidIp(ip) ? String(ip).trim() : '';
  var d = V6.scalpel.mac ? devBy(V6.scalpel.mac) : null;
  V6.scalpel.devName = name || (d && d.name) || '';
  if (!V6.scalpel.ip && d && v6ValidIp(d.ip)) V6.scalpel.ip = d.ip;
  V6.scalpel.paused = false;
  bd.innerHTML = v6ScalpelDrawerBodyHtml();
  dr.hidden = false;
  void dr.offsetWidth;
  dr.classList.add('show');
  if (sc) sc.classList.add('show');
  v6FetchScalpelFlows();
  clearInterval(V6.scalpel.timer);
  V6.scalpel.timer = setInterval(function () {
    if (!V6.scalpel.open || V6.scalpel.paused || document.hidden) return;
    v6FetchScalpelFlows();
  }, 2000);
}

function closeScalpelDrawer() {
  V6.scalpel.open = false;
  clearInterval(V6.scalpel.timer);
  V6.scalpel.timer = 0;
  var dr = document.getElementById('v6-scalpel-drawer');
  var sc = document.getElementById('v6-scalpel-scrim');
  if (sc) sc.classList.remove('show');
  if (dr) {
    dr.classList.remove('show');
    setTimeout(function () { if (!V6.scalpel.open) dr.hidden = true; }, 260);
  }
}

/* ═════════════════════ 写操作处理器（100% 严格对齐后端 DisallowUnknownFields 结构体） ═════════════════════ */

/* POST /api/leakguard/config — 仅允许 { capacity, cooldown_sec, notify_enabled, lockscreen_mask } */
function v6SaveLeakGuardConfig(partial, triggerEl, okMsg) {
  var ringEl = document.getElementById('lgd-ring-cap');
  var cdEl = document.getElementById('lgd-dedup-sec');
  var capVal = clamp(Math.round(num(ringEl ? ringEl.value : V6.lg.capacity, 300)), 10, 2000);
  var cdVal = clamp(Math.round(num(cdEl ? cdEl.value : V6.lg.cooldown_sec, 300)), 0, 86400);
  var payload = {
    capacity: capVal,
    cooldown_sec: cdVal,
    notify_enabled: partial && typeof partial.notify_enabled === 'boolean' ? partial.notify_enabled : V6.lg.notify_enabled,
    lockscreen_mask: partial && typeof partial.lockscreen_mask === 'boolean' ? partial.lockscreen_mask : V6.lg.lockscreen_mask
  };
  V6.lg.capacity = capVal;
  V6.lg.cooldown_sec = cdVal;
  V6.lg.notify_enabled = payload.notify_enabled;
  V6.lg.lockscreen_mask = payload.lockscreen_mask;
  return busyWhile(triggerEl, api.post(V6_API.lgConfig, payload, { timeout: 8000 })).then(function (r) {
    if (r) v6ApplyLeakGuardData(r);
    v6RefreshLeakGuardDom();
    toast(okMsg || 'LeakGuard 安检配置已保存');
  }).catch(function (e) {
    toast(errText(e), 'err');
    v6LoadLeakGuard();
  });
}

/* POST /api/leakguard/clear */
function v6ClearLeakGuard(btn) {
  confirmSheet('清空 LeakGuard 取证记录？', '将清空内存环形缓冲区与事件快照中的全部明文隐私外泄告警（已生效的追踪域名/IP 封锁规则保留）。', '清空记录').then(function (ok) {
    if (!ok) return;
    busyWhile(btn, api.post(V6_API.lgClear, {}, { timeout: 8000 })).then(function () {
      V6.lg.events = [];
      V6.lg.hit_ledger = {};
      V6.lg.total_hits = 0;
      V6.lg.affected_devices = 0;
      V6.lg.openIds = {};
      v6PaintHeaderBadges();
      v6RefreshLeakGuardDom();
      v6RefreshDevicesBannerDom();
      toast('已清空 LeakGuard 历史告警记录');
    }).catch(function (e) { toast(errText(e), 'err'); });
  });
}

/* POST /api/leakguard/block-domain — 仅允许 { action, dst_host, mac }；同时覆盖域名与公网对端 IP */
function v6BlockLeakDomain(evId, btn) {
  var ev = V6.lg.events.filter(function (x) { return x.id === evId; })[0];
  if (!ev) return;
  var wantBlock = !ev.is_blocked;
  var act = wantBlock ? 'block' : 'unblock';
  var primaryHost = String(ev.dst_host && ev.dst_host !== '—' ? ev.dst_host : ev.dst_ip).trim();
  if (!primaryHost) { toast('该告警缺少可封禁的目标域名或公网 IP', 'warn'); return; }
  var macArg = v6ValidMac(ev.mac) ? ev.mac : '';
  var req1 = { action: act, dst_host: primaryHost, mac: macArg };

  busyWhile(btn, api.post(V6_API.lgBlockDomain, req1, { timeout: 9000 }).then(function (r1) {
    /* 若同时具备独立对端 IP，串联同步封禁/解封对端 IP 实现「拉黑域名+IP」双保险 */
    if (v6ValidIp(ev.dst_ip) && ev.dst_ip.toLowerCase() !== primaryHost.toLowerCase()) {
      return api.post(V6_API.lgBlockDomain, { action: act, dst_host: ev.dst_ip, mac: macArg }, { timeout: 7000 })
        .catch(function () { return r1; })
        .then(function () { return r1; });
    }
    return r1;
  })).then(function () {
    ev.is_blocked = wantBlock;
    var dk = primaryHost.toLowerCase();
    if (wantBlock) V6.lg.blocked_set[dk] = 1;
    else delete V6.lg.blocked_set[dk];
    V6.lg.events.forEach(function (x) {
      if (String(x.dst_host || '').toLowerCase() === dk || (ev.dst_ip && x.dst_ip === ev.dst_ip)) {
        x.is_blocked = wantBlock;
      }
    });
    v6LoadLeakGuard();
    toast(wantBlock ? ('已拉黑追踪域名与对端 IP：' + primaryHost) : ('已解除封锁：' + primaryHost));
  }).catch(function (e) { toast(errText(e), 'err'); });
}

/* POST /api/v6/scalpel/cut — 严格对齐 { mode, proto, src_ip, sport, dst_ip, dport } */
function v6BuildScalpelCutPayload(flowObj, modeStr) {
  var p = String(flowObj.proto || 'tcp').toLowerCase();
  var normProto = (p === 'udp' || p === 'quic') ? 'udp' : 'tcp';
  return {
    mode: modeStr === 'cut_freeze_15m' ? 'cut_freeze_15m' : 'cut_once',
    proto: normProto,
    src_ip: String(flowObj.src_ip || '').trim(),
    sport: clamp(Math.round(num(flowObj.sport != null ? flowObj.sport : flowObj.src_port, 0)), 1, 65535),
    dst_ip: String(flowObj.dst_ip || '').trim(),
    dport: clamp(Math.round(num(flowObj.dport != null ? flowObj.dport : flowObj.dst_port, 80)), 1, 65535)
  };
}

function v6CutFlow(flowObj, freeze15m, btn) {
  if (!flowObj) return;
  if (!v6ValidIp(flowObj.src_ip) || !v6ValidIp(flowObj.dst_ip) || !(num(flowObj.sport, flowObj.src_port) >= 1)) {
    toast('五元组端点信息不完整，请刷新流表后重试', 'warn');
    return;
  }
  var mode = freeze15m ? 'cut_freeze_15m' : 'cut_once';
  var payload = v6BuildScalpelCutPayload(flowObj, mode);
  busyWhile(btn, api.post(V6_API.scalpelCut, payload, { timeout: 8000 })).then(function () {
    toast(freeze15m
      ? ('已秒斩并冻结 15 分钟：' + (flowObj.dst_host || flowObj.dst_ip) + ':' + payload.dport)
      : ('已单斩死流：' + payload.dst_ip + ':' + payload.dport));
    if (V6.scalpel.open) v6FetchScalpelFlows();
    if (S.page === 'vector') v6LoadCockpitAll();
  }).catch(function (e) { toast(errText(e), 'err'); });
}

/* LeakGuard 告警行「秒斩连接」：自动匹配内核 conntrack 中该设备的活跃泄露连接并执行精准单流秒斩 */
function v6CutLeakEventConn(ev, btn) {
  if (!ev) return;
  if (v6ValidIp(ev.src_ip) && v6ValidIp(ev.dst_ip) && ev.src_port >= 1 && ev.src_port <= 65535) {
    v6CutFlow(ev, false, btn);
    return;
  }
  var qParams = { limit: 250 };
  if (v6ValidMac(ev.mac)) qParams.mac = ev.mac;
  if (v6ValidIp(ev.src_ip)) qParams.ip = ev.src_ip;

  busyWhile(btn, api.get(V6_API.scalpelFlows, qParams, { timeout: 7000 }).then(function (r) {
    var flows = Array.isArray(r && r.flows) ? r.flows : [];
    var hostLow = String(ev.dst_host || '').toLowerCase();
    var matched = flows.filter(function (f) {
      var sp = Math.round(num(f.sport, 0)), dp = Math.round(num(f.dport, 0));
      if (!v6ValidIp(f.src_ip) || !v6ValidIp(f.dst_ip) || sp < 1 || dp < 1) return false;
      if (ev.dst_ip && f.dst_ip === ev.dst_ip) return true;
      var dom = String(f.domain || '').toLowerCase();
      if (hostLow && hostLow !== '—' && (dom === hostLow || dom.slice(-(hostLow.length + 1)) === '.' + hostLow || f.dst_ip === hostLow)) return true;
      return ev.dst_port && dp === ev.dst_port && (!ev.dst_ip && (!hostLow || hostLow === '—'));
    });
    if (!matched.length) {
      return { cutN: 0 };
    }
    var chain = Promise.resolve(), cutN = 0;
    matched.slice(0, 6).forEach(function (mf) {
      chain = chain.then(function () {
        return api.post(V6_API.scalpelCut, v6BuildScalpelCutPayload(mf, 'cut_once'), { timeout: 6000 })
          .then(function () { cutN++; });
      });
    });
    return chain.then(function () { return { cutN: cutN }; });
  })).then(function (res) {
    if (res && res.cutN > 0) {
      toast('已秒斩 ' + res.cutN + ' 条活跃明文连接：' + (ev.dst_host || ev.dst_ip));
    } else {
      openScalpelDrawer(ev.mac, ev.src_ip, ev.devName);
      toast('该明文短连接已自然结束，已为您打开该设备的实时五元组手术台', 'warn');
    }
  }).catch(function (e) { toast(errText(e), 'err'); });
}

/* POST /api/v6/express — 仅允许 { enabled, auto_detect, forced_macs } */
function v6PostExpress(payload, el, msg) {
  return busyWhile(el, api.post(V6_API.express, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyExpressData(r || payload);
    v6RefreshCockpitDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (msg) toast(msg);
  }).catch(function (e) {
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

/* POST /api/v6/update_leash — 仅允许 { action, enabled, grace_mb, leash_kbps, session_key, mac, dst_host } */
function v6PostLeash(payload, el, msg) {
  return busyWhile(el, api.post(V6_API.updateLeash, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyLeashData(r || payload);
    v6RefreshCockpitDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (msg) toast(msg);
  }).catch(function (e) {
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

/* POST /api/v6/thermo — 仅允许 { enabled, stage2_shaper_enabled, stage1_temp_c, stage2_temp_c, low_bat_pct } */
function v6PostThermo(payload, el, msg) {
  return busyWhile(el, api.post(V6_API.thermo, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyThermoData(r || payload);
    v6RefreshCockpitDom();
    v6RefreshDevicesBannerDom();
    if (msg) toast(msg);
  }).catch(function (e) {
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

/* ═════════════════════ 全局事件委托与生命周期钩子 ═════════════════════ */
function v6BindEvents() {
  if (typeof document === 'undefined' || document.__v6Bound) return;
  document.__v6Bound = true;

  var scScrim = document.getElementById('v6-scalpel-scrim');
  if (scScrim) scScrim.addEventListener('click', closeScalpelDrawer);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && V6.scalpel.open) closeScalpelDrawer();
  });

  document.addEventListener('change', function (e) {
    var t = e.target;
    if (t && t.id === 'v6-backup-file' && t.files && t.files[0]) {
      var file = t.files[0];
      var reader = new FileReader();
      reader.onload = function () {
        var rawText = String(reader.result || '');
        t.value = '';
        var parsed = null;
        try { parsed = JSON.parse(rawText); } catch (_) {
          toast('备份文件不是合法的 JSON 格式', 'err');
          return;
        }
        confirmSheet('确认恢复整机配置？', '将校验 SHA256 摘要并原子覆盖规则、设备命名与全部 v6 策略（当前登录令牌不受影响）。', '立即恢复').then(function (ok) {
          if (!ok) return;
          api.post(V6_API.backup, parsed, { timeout: 12000 }).then(function (res) {
            V6.vault.last_restored = Math.round(num(res && res.restored_count, 0));
            if (res && res.sha256) V6.vault.last_sha256 = String(res.sha256);
            v6RefreshCockpitDom();
            toast('已原子恢复 ' + V6.vault.last_restored + ' 个配置文件');
          }).catch(function (err) { toast(errText(err), 'err'); });
        });
      };
      reader.readAsText(file);
    }
  });

  document.addEventListener('input', function (e) {
    var t = e.target;
    if (!t) return;
    if (t.id === 'lgd-q') {
      V6.lg.q = t.value;
      var st = document.getElementById('lgd-stream-list');
      if (st) st.innerHTML = v6LeakStreamHtml();
    } else if (t.id === 'v6-sc-q') {
      V6.scalpel.q = t.value;
      v6RefreshScalpelDrawerList();
    }
  });

  /* 捕获阶段处理 v6 专属开关与分段器，避免落入 main.js 默认设备开关分支 */
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || typeof t.closest !== 'function') return;

    var segBtn = t.closest('[data-seg="v6-view"] button');
    if (segBtn) {
      e.stopPropagation();
      var v = segBtn.getAttribute('data-v') || 'all';
      V6.view = v;
      LS.set('hnc6.v6_view', v);
      var sg = segBtn.parentNode;
      $$('button', sg).forEach(function (b) { b.classList.toggle('on', b === segBtn); });
      placeSegs(sg.parentNode);
      var lgW = document.getElementById('v6-leakguard-wrap');
      var cpW = document.getElementById('v6-cockpit-wrap');
      if (lgW) lgW.hidden = !(v === 'all' || v === 'leakguard');
      if (cpW) cpW.hidden = !(v === 'all' || v === 'cockpit');
      return;
    }

    var vTog = t.closest('[data-v6-tog]');
    if (vTog) {
      e.stopPropagation();
      e.preventDefault();
      if (vTog.disabled || vTog.classList.contains('pending')) return;
      var nextOn = vTog.getAttribute('aria-checked') !== 'true';
      vTog.setAttribute('aria-checked', String(nextOn));
      if (typeof haptic === 'function') haptic(10);
      var kind = vTog.getAttribute('data-v6-tog');
      if (kind === 'lgd-notify') {
        v6SaveLeakGuardConfig({ notify_enabled: nextOn }, vTog, nextOn ? '已开启状态栏系统通知' : '已关闭状态栏系统通知');
      } else if (kind === 'lgd-mask') {
        v6SaveLeakGuardConfig({ lockscreen_mask: nextOn }, vTog, nextOn ? '已开启锁屏半脱敏保护' : '已关闭锁屏半脱敏保护');
      } else if (kind === 'express') {
        V6.express.enabled = nextOn;
        v6PostExpress({ enabled: nextOn, auto_detect: V6.express.auto_detect, forced_macs: V6.express.forced_macs }, vTog, nextOn ? 'Vector Express 救护车零排队已开启' : 'Vector Express 已关闭');
      } else if (kind === 'leash') {
        V6.leash.enabled = nextOn;
        v6PostLeash({ action: 'config', enabled: nextOn, grace_mb: V6.leash.grace_mb, leash_kbps: V6.leash.leash_kbps }, vTog, nextOn ? 'UpdateLeash 后台更新拴绳已开启' : 'UpdateLeash 已关闭');
      } else if (kind === 'thermo') {
        V6.thermo.enabled = nextOn;
        v6PostThermo({ enabled: nextOn, stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled, stage1_temp_c: V6.thermo.stage1_temp_c, stage2_temp_c: V6.thermo.stage2_temp_c }, vTog, nextOn ? 'ThermoCruise 电芯温控巡航已开启' : 'ThermoCruise 已关闭');
      }
      return;
    }

    var actEl = t.closest('[data-v6-act]');
    if (!actEl) return;
    var act = actEl.getAttribute('data-v6-act');

    /* 在折叠告警行内部点击操作按钮时，不触发行的折叠切换 */
    if (act === 'lgd-toggle-row' && t.closest('.lgd-acts')) return;

    e.stopPropagation();

    switch (act) {
      case 'go-vector':
        if (typeof go === 'function') go('vector');
        break;
      case 'open-scalpel':
        openScalpelDrawer(actEl.getAttribute('data-mac') || '', actEl.getAttribute('data-ip') || '', actEl.getAttribute('data-name') || '');
        break;
      case 'scalpel-close':
        closeScalpelDrawer();
        break;
      case 'scalpel-all-scope':
        V6.scalpel.mac = '';
        V6.scalpel.ip = '';
        V6.scalpel.devName = '';
        var bd0 = document.getElementById('v6-scalpel-body');
        if (bd0) bd0.innerHTML = v6ScalpelDrawerBodyHtml();
        v6FetchScalpelFlows();
        break;
      case 'scalpel-pause':
        V6.scalpel.paused = !V6.scalpel.paused;
        actEl.textContent = V6.scalpel.paused ? '已暂停' : '实时2s';
        actEl.classList.toggle('warn', V6.scalpel.paused);
        if (!V6.scalpel.paused) v6FetchScalpelFlows();
        break;
      case 'scalpel-proto':
        V6.scalpel.protoFilter = actEl.getAttribute('data-proto') || 'ALL';
        $$('#v6-scalpel-body [data-v6-act="scalpel-proto"]').forEach(function (b) { b.classList.toggle('on', b === actEl); });
        v6RefreshScalpelDrawerList();
        break;
      case 'scalpel-cut-once':
      case 'scalpel-cut-freeze':
        var fid = actEl.getAttribute('data-fid');
        var fl = V6.scalpel.flows.filter(function (x) { return x.id === fid; })[0];
        v6CutFlow(fl, act === 'scalpel-cut-freeze', actEl);
        break;
      case 'lgd-refresh':
        busyWhile(actEl, v6LoadLeakGuard()).then(function () { toast('LeakGuard 取证流已刷新'); });
        break;
      case 'lgd-clear':
        v6ClearLeakGuard(actEl);
        break;
      case 'lgd-save-cfg':
        v6SaveLeakGuardConfig(null, actEl, '已保存环形缓冲容量与去重冷却配置');
        break;
      case 'lgd-filter':
        V6.lg.typeFilter = actEl.getAttribute('data-type') || 'ALL';
        $$('#v6-leakguard-card [data-v6-act="lgd-filter"]').forEach(function (b) { b.classList.toggle('on', b === actEl); });
        var stL = document.getElementById('lgd-stream-list');
        if (stL) stL.innerHTML = v6LeakStreamHtml();
        break;
      case 'lgd-toggle-row':
      case 'lgd-toggle-btn':
        var eid = actEl.getAttribute('data-id');
        if (!eid) break;
        if (V6.lg.openIds[eid]) delete V6.lg.openIds[eid];
        else V6.lg.openIds[eid] = 1;
        var itemEl = actEl.closest('.lgd-item');
        if (itemEl) {
          var openNow = !!V6.lg.openIds[eid];
          itemEl.classList.toggle('is-open', openNow);
          var fr = itemEl.querySelector('.lgd-forensic');
          if (fr) fr.hidden = !openNow;
          var tb = itemEl.querySelector('[data-v6-act="lgd-toggle-btn"]');
          if (tb) tb.textContent = openNow ? '收起报文' : '展开报文';
        }
        break;
      case 'lgd-block-domain':
        v6BlockLeakDomain(actEl.getAttribute('data-id'), actEl);
        break;
      case 'lgd-cut-conn':
        var ceid = actEl.getAttribute('data-id');
        var cev = V6.lg.events.filter(function (x) { return x.id === ceid; })[0];
        if (cev) v6CutLeakEventConn(cev, actEl);
        break;
      case 'express-auto':
        V6.express.auto_detect = !V6.express.auto_detect;
        v6PostExpress({
          enabled: V6.express.enabled,
          auto_detect: V6.express.auto_detect,
          forced_macs: V6.express.forced_macs
        }, actEl, V6.express.auto_detect ? '已开启游戏与实时通话自动护航检测' : '已切换为仅手动锁定设备护航');
        break;
      case 'express-dev':
        var emac = String(actEl.getAttribute('data-mac') || '').toLowerCase();
        if (!v6ValidMac(emac)) break;
        var nextMacs = V6.express.forced_macs.slice();
        var pos = nextMacs.indexOf(emac);
        if (pos >= 0) nextMacs.splice(pos, 1);
        else nextMacs.push(emac);
        V6.express.forced_macs = nextMacs;
        var nextEnabled = nextMacs.length > 0 ? true : V6.express.enabled;
        V6.express.enabled = nextEnabled;
        v6PostExpress({
          enabled: nextEnabled,
          auto_detect: V6.express.auto_detect,
          forced_macs: nextMacs
        }, actEl, pos < 0 ? '已锁定常驻零排队护航' : '已解除常驻零排队锁定');
        break;
      case 'leash-save':
        var gm = clamp(Math.round(num(($('#v6-ul-grace') || {}).value, 200)), 10, 10240);
        var kb = clamp(Math.round(num(($('#v6-ul-kbps') || {}).value, 1500)), 128, 1000000);
        V6.leash.grace_mb = gm;
        V6.leash.leash_kbps = kb;
        v6PostLeash({
          action: 'config',
          enabled: V6.leash.enabled,
          grace_mb: gm,
          leash_kbps: kb
        }, actEl, 'UpdateLeash 缓冲 ' + gm + 'MB / 限速 ' + kb + 'Kbps 已保存');
        break;
      case 'leash-release':
        var rMac = actEl.getAttribute('data-mac') || '';
        v6PostLeash({
          action: 'bypass_once',
          session_key: actEl.getAttribute('data-skey') || '',
          mac: v6ValidMac(rMac) ? rMac : '',
          dst_host: actEl.getAttribute('data-host') || ''
        }, actEl, '已对该更新会话执行本次全速放行');
        break;
      case 'leash-pause-toggle':
        var isPaused = actEl.getAttribute('data-paused') === '1';
        var pMac = actEl.getAttribute('data-mac') || '';
        v6PostLeash({
          action: isPaused ? 'resume_update' : 'pause_update',
          session_key: actEl.getAttribute('data-skey') || '',
          mac: v6ValidMac(pMac) ? pMac : '',
          dst_host: actEl.getAttribute('data-host') || ''
        }, actEl, isPaused ? '已恢复该更新会话下载' : '已暂停该后台更新流');
        break;
      case 'thermo-shaper':
        V6.thermo.stage2_shaper_enabled = !V6.thermo.stage2_shaper_enabled;
        v6PostThermo({
          enabled: V6.thermo.enabled,
          stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled,
          stage1_temp_c: V6.thermo.stage1_temp_c,
          stage2_temp_c: V6.thermo.stage2_temp_c
        }, actEl, V6.thermo.stage2_shaper_enabled ? '已启用二阶高温带宽收束' : '已关闭二阶高温带宽收束');
        break;
      case 'thermo-save':
        var t1 = clamp(Math.round(num(($('#v6-th-t1') || {}).value, 42)), 30, 70);
        var t2 = clamp(Math.round(num(($('#v6-th-t2') || {}).value, 45)), 32, 75);
        if (t2 < t1) {
          toast('二阶护航温度不能低于一阶省电温度', 'warn');
          break;
        }
        V6.thermo.stage1_temp_c = t1;
        V6.thermo.stage2_temp_c = t2;
        v6PostThermo({
          enabled: V6.thermo.enabled,
          stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled,
          stage1_temp_c: t1,
          stage2_temp_c: t2
        }, actEl, '温控巡航阈值已保存：' + t1 + ' °C / ' + t2 + ' °C');
        break;
      case 'bb-sample':
        busyWhile(actEl, api.post(V6_API.blackbox, { action: 'sample_now' }, { timeout: 6000 })).then(function () {
          return api.get(V6_API.blackbox, { limit: 12, incidents_only: '1' }, { timeout: 6000 });
        }).then(function (r) {
          v6ApplyBlackboxData(r);
          v6RefreshCockpitDom();
          toast('已完成 200ms 黑匣子即时采样');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'bb-clear':
        busyWhile(actEl, api.post(V6_API.blackbox, { action: 'clear' }, { timeout: 6000 })).then(function () {
          V6.blackbox.incidents = [];
          V6.blackbox.incident_count = 0;
          v6RefreshCockpitDom();
          toast('已清空 200ms 卡顿黑匣子历史记录');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'subtrees-sync':
        busyWhile(actEl, api.post(V6_API.nativeSubtrees, { action: 'full_restore' }, { timeout: 8000 })).then(function (r) {
          if (r && r.dynamic_qos) {
            v6ApplyScreenshotPackSummary({ native_subtrees: r });
          }
          v6RefreshCockpitDom();
          toast('已触发原生 Netlink M8 二级子树与动态 QoS 同步');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'backup-export':
        busyWhile(actEl, api.get(V6_API.backup, null, { timeout: 10000 })).then(function (bundle) {
          if (!bundle || typeof bundle !== 'object') { toast('导出空载荷', 'err'); return; }
          V6.vault.last_sha256 = String(bundle.sha256 || '');
          V6.vault.last_file_count = Math.round(num(bundle.file_count, 0));
          v6RefreshCockpitDom();
          var jsonStr = JSON.stringify(bundle, null, 2);
          var fname = 'hnc-backup-' + (bundle.module_version || 'v6.0.0') + '-' + Date.now() + '.json';
          try {
            var blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = fname;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
            toast('整机配置备份已导出 (' + V6.vault.last_file_count + ' 项)');
          } catch (_) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(jsonStr);
              toast('备份 JSON 已复制到剪贴板');
            }
          }
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'backup-import-pick':
        var fin = document.getElementById('v6-backup-file');
        if (fin) fin.click();
        break;
    }
  }, true);
}

/* 启动与轮询协同：KSU 模式下优先消费 /api/vector_sync 摘要，矢量页按需刷新明细；404 回退时低频安全轮询 */
function v6RefreshSummarySilent() {
  if (S.vectorSyncState === 'supported') return;
  if (V6.apiSupported.lg) v6LoadLeakGuard();
  if (V6.apiSupported.v6) v6LoadCockpitAll();
}

function v6BootInit() {
  if (S.vectorSyncState !== 'supported') {
    v6RefreshSummarySilent();
  }
  if (!KSU) v6StartLeakGuardSSE();
}

function v6OnPollTick(tickN) {
  if (S.page === 'vector') {
    if ((KSU || !V6.lg.sseActive) && tickN % 2 === 0 && V6.apiSupported.lg) v6LoadLeakGuard();
    if (tickN % 3 === 0 && V6.apiSupported.v6) v6LoadCockpitAll();
  } else if (S.vectorSyncState !== 'supported' && tickN % 10 === 0) {
    if (V6.apiSupported.lg) v6LoadLeakGuard();
  }
}

function v6OnVisibility(hidden) {
  if (hidden) {
    v6StopLeakGuardSSE();
  } else {
    if (!KSU && V6.apiSupported.lg) v6StartLeakGuardSSE();
    if (S.page === 'vector') { v6LoadLeakGuard(); v6LoadCockpitAll(); }
  }
}

v6BindEvents();
if (typeof window !== 'undefined') {
  window.HNCVectorV6 = {
    V6: V6,
    escapeHtml: escapeHtml,
    highlightRawSnippet: highlightRawSnippet,
    openScalpelDrawer: openScalpelDrawer,
    closeScalpelDrawer: closeScalpelDrawer,
    ingestSync: v6IngestVectorSync,
    renderVectorPage: renderVectorPage
  };
}
