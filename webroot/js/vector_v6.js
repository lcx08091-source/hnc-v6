/* HNC WebUI · vector_v6.js —— HNC v6.0.0 · 智能护航、隐私明文安检与连接排障中心
 * 设计准则:
 *   1. 3秒简易认知渐进披露: 顶部一句话人话态势 + 3格控制中心磁贴 + 三大场景切换(网速护航 / 隐私安检 / 连接排障) + 高级参数按需折叠。
 *   2. 100% 真实后端能力闭环: 完整对接 /api/vector_sync、LeakGuard、Express、UpdateLeash、ThermoCruise、FlowScalpel、Blackbox、MultiIface、NativeSubtrees 与 ConfigVault。
 *   3. 状态机零串扰: 全局活跃连接数与单机抽屉完全隔离、写操作 1.5s 乐观飞行锁、morph 就地更新防吞点击、已读水位线消除常亮红点焦虑。
 *   4. 永久红线严守: 零表情字符 · 零拖动滑块（纯直接数字输入） · 全量 SVG 宽高硬锁 · LeakGuard 100% 原始未打码 raw_value 转义展示 · 四大主题自适应。
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

/* 在已安全转义的原始 HTTP 报文中精确高亮命中的完整明文值 raw_value（零正则注入风险、严禁星号打码） */
function highlightRawSnippet(snippet, rawVal) {
  var src = String(snippet == null ? '' : snippet);
  var needle = String(rawVal == null ? '' : rawVal);
  if (!src) return '<span class="note">（当前记录未附带原始 HTTP 报文片段）</span>';
  if (!needle) return escapeHtml(src);
  var out = '', idx = 0, hit = -1;
  while ((hit = src.indexOf(needle, idx)) !== -1) {
    out += escapeHtml(src.slice(idx, hit)) + '<mark class="lgd-hl">' + escapeHtml(needle) + '</mark>';
    idx = hit + needle.length;
  }
  out += escapeHtml(src.slice(idx));
  return out;
}

/* 从原始 HTTP 报文切片中提取请求行 Path 与 User-Agent */
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

/* 纯内联矢量线条图标库（自带 .v6-ic 与 width/height 双重硬锁，杜绝任何 Flex 容器下无约束放大） */
var V6_SVGS = {
  shieldAlert: '<path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z" fill="currentColor" fill-opacity=".15"/><path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z"/><path d="M12 8.2v4.4M12 16h.01"/>',
  shieldOk: '<path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z" fill="currentColor" fill-opacity=".15"/><path d="M12 21.5s7.5-3.6 7.5-9.8V5.4L12 2.6 4.5 5.4v6.3c0 6.2 7.5 9.8 7.5 9.8Z"/><path d="m8.8 12.2 2.2 2.2 4.4-4.6"/>',
  express: '<polygon points="13.2 2.4 4.4 13.4 11.6 13.4 10.6 21.6 19.6 10.6 12.4 10.6 13.2 2.4" fill="currentColor" fill-opacity=".18"/><polygon points="13.2 2.4 4.4 13.4 11.6 13.4 10.6 21.6 19.6 10.6 12.4 10.6 13.2 2.4"/>',
  leash: '<rect x="2.8" y="6.8" width="7.6" height="10.4" rx="3.5" fill="currentColor" fill-opacity=".15"/><rect x="13.6" y="6.8" width="7.6" height="10.4" rx="3.5" fill="currentColor" fill-opacity=".15"/><rect x="2.8" y="6.8" width="7.6" height="10.4" rx="3.5"/><rect x="13.6" y="6.8" width="7.6" height="10.4" rx="3.5"/><path d="M8.2 12h7.6"/>',
  thermo: '<path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z" fill="currentColor" fill-opacity=".16"/><path d="M14 14.76V5.5a2 2 0 1 0-4 0v9.26a4 4 0 1 0 4 0Z"/><circle cx="12" cy="17.5" r="1.5" fill="currentColor" stroke="none"/><path d="M16.8 6h2.2M16.8 9.5h1.6"/>',
  scalpel: '<path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z" fill="currentColor" fill-opacity=".16"/><path d="m19.6 4.4-9.8 9.8-4.6 1.2 1.2-4.6 9.8-9.8a2.4 2.4 0 0 1 3.4 3.4Z"/><path d="M3.5 20.5h11"/><path d="m14.5 6.5 3 3"/>',
  cut: '<circle cx="6" cy="6" r="2.6"/><circle cx="6" cy="18" r="2.6"/><path d="M20 4 8.2 15.8M14.5 14.5 20 20M8.2 8.2 12 12"/>',
  freeze: '<path d="M12 2.5v19M4.8 6.8l14.4 10.4M19.2 6.8 4.8 17.2"/><circle cx="12" cy="12" r="2.2" fill="currentColor" fill-opacity=".2"/>',
  blackbox: '<rect x="3" y="4.5" width="18" height="15" rx="3" fill="currentColor" fill-opacity=".14"/><rect x="3" y="4.5" width="18" height="15" rx="3"/><path d="M6.5 13h2.4l1.6-3.8 2.6 6.2 1.8-3.4h2.6"/>',
  vault: '<path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 16.5v-9Z" fill="currentColor" fill-opacity=".14"/><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 16.5v-9Z"/><circle cx="12" cy="12" r="2.6"/><path d="M12 9.4V7.8M12 16.2v-1.6M9.4 12H7.8M16.2 12h-1.6"/>',
  chev: '<polyline points="6 9 12 15 18 9"/>'
};
function v6Svg(name, cls) {
  return '<svg class="v6-ic' + (cls ? ' ' + cls : '') + '" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (V6_SVGS[name] || V6_SVGS.express) + '</svg>';
}

/* 全局 v6 状态仓 */
var V6 = {
  subtab: LS.get('hnc6.v6_subtab', 'escort'), // 'escort' | 'privacy' | 'troubleshoot'
  healthOpen: false,
  advOpen: { exp: false, leash: false, thermo: false, lgCfg: false, bbNet: false },
  mutUntil: { lg: 0, express: 0, leash: 0, thermo: 0 },
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
    visibleLimit: 30,
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
    stage_label: '正常'
  },
  scalpel: {
    open: false,
    scopeMac: '',
    scopeIp: '',
    devName: '',
    protoFilter: 'ALL',
    q: '',
    paused: false,
    loading: false,
    readable: true,
    globalFlows: [],
    globalTotalFlows: 0,
    drawerFlows: [],
    drawerTotal: 0,
    active_rules: [],
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
if (['escort', 'privacy', 'troubleshoot'].indexOf(V6.subtab) < 0) V6.subtab = 'escort';

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

/* 将机器枚举翻译为人一眼看懂的中文隐私类别 */
function leakTypeZh(tp) {
  var u = leakTypeBadgeCode(tp);
  if (/PHONE/.test(u)) return '手机号';
  if (/EMAIL/.test(u)) return '邮箱地址';
  if (/ID_CARD|IDCARD/.test(u)) return '身份证号';
  if (/GPS|LOC|LAT|LON/.test(u)) return '精准定位';
  if (/WIFI_BSSID|BSSID/.test(u)) return '周边Wi-Fi定位';
  if (/MAC/.test(u)) return '网卡地址';
  if (/TOKEN|BEARER|COOKIE|AUTH|PASS|KEY/.test(u)) return '登录凭证';
  if (/IMEI|IMSI|OAID|IDFA|ANDROID_ID|DEVICE|SERIAL/.test(u)) return '设备指纹';
  return '敏感明文';
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

/* ── 已读水位线管理：看完隐私安检即消去刺眼红点，有新增才重新提醒 ── */
function v6SeenLeakHits() {
  var saved = Math.max(0, Math.round(num(LS.get('hnc6.lg_seen_hits', 0), 0)));
  if (saved > num(V6.lg.total_hits, 0)) {
    saved = num(V6.lg.total_hits, 0);
    LS.set('hnc6.lg_seen_hits', String(saved));
  }
  return saved;
}

function v6UnreadLeakHits() {
  return Math.max(0, num(V6.lg.total_hits, 0) - v6SeenLeakHits());
}

function v6MarkLeakGuardSeen() {
  LS.set('hnc6.lg_seen_hits', String(Math.max(0, num(V6.lg.total_hits, 0))));
  v6PaintHeaderBadges();
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
  /* 严禁对 raw_value 做任何前端星号打码或截断，100% 保留原始明文值 */
  var rawVal = raw.raw_value != null ? String(raw.raw_value) : (raw.value != null ? String(raw.value) : (raw.plaintext != null ? String(raw.plaintext) : ''));
  var snippet = String(raw.raw_snippet != null ? raw.raw_snippet : (raw.snippet || raw.raw_http || ''));
  var meta = extractHttpMetaFromSnippet(snippet);
  var method = String(raw.method || meta.method || 'GET').toUpperCase();
  var urlPath = String(raw.path || raw.url_path || raw.uri || meta.path || '/');
  var ua = String(raw.user_agent || raw.ua || meta.ua || '（未携带客户端标识）');
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
    devName: raw.device_name || (d ? d.name : '') || (srcIp || mac || '未知设备'),
    src_ip: srcIp || (d && d.ip) || '',
    src_port: num(raw.src_port != null ? raw.src_port : raw.sport, 0),
    dst_ip: dstIp,
    dst_port: num(raw.dst_port != null ? raw.dst_port : raw.dport, 80),
    proto: String(raw.proto || 'tcp').toLowerCase(),
    leak_type: lType,
    leak_label: String(raw.leak_label || leakTypeZh(lType)),
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

function v6ApplyLeakGuardData(d, forceAccept) {
  if (!d || typeof d !== 'object') return;
  var cfg = (d.config && typeof d.config === 'object') ? d.config : d;
  var stats = (d.stats && typeof d.stats === 'object') ? d.stats : d;
  var cfgLocked = !forceAccept && Date.now() < V6.mutUntil.lg;

  if (!cfgLocked) {
    if (typeof cfg.notify_enabled === 'boolean') V6.lg.notify_enabled = cfg.notify_enabled;
    if (typeof cfg.lockscreen_mask === 'boolean') V6.lg.lockscreen_mask = cfg.lockscreen_mask;
    if (cfg.capacity != null || cfg.ring_capacity != null) {
      V6.lg.capacity = clamp(Math.round(num(cfg.capacity != null ? cfg.capacity : cfg.ring_capacity, 300)), 10, 2000);
    }
    if (cfg.cooldown_sec != null || cfg.dedup_cooldown_sec != null) {
      V6.lg.cooldown_sec = clamp(Math.round(num(cfg.cooldown_sec != null ? cfg.cooldown_sec : cfg.dedup_cooldown_sec, 300)), 0, 86400);
    }
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

  if (S.page === 'vector' && V6.subtab === 'privacy') {
    v6MarkLeakGuardSeen();
  } else {
    v6PaintHeaderBadges();
  }
}

function v6PushStreamEvent(evObj) {
  if (!evObj || typeof evObj !== 'object') return;
  if (Array.isArray(evObj.events) || evObj.stats || evObj.config) {
    v6ApplyLeakGuardData(evObj, false);
    v6RefreshActiveSubviewDom();
    return;
  }
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
  if (S.page === 'vector' && V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  else v6PaintHeaderBadges();
  v6RefreshActiveSubviewDom();
}

/* ── Vector Express 数据归一化 ── */
function v6ApplyExpressData(r, forceAccept) {
  if (!r || typeof r !== 'object') return;
  if (!forceAccept && Date.now() < V6.mutUntil.express) return;
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

/* ── UpdateLeash 数据归一化 ── */
function v6ApplyLeashData(r, forceAccept) {
  if (!r || typeof r !== 'object') return;
  if (!forceAccept && Date.now() < V6.mutUntil.leash) return;
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
        devName: s.device_name || (d ? d.name : '') || s.src_ip || mac || '连网设备',
        src_ip: String(s.src_ip || (d && d.ip) || ''),
        dst_host: String(s.dst_host || s.dst_ip || '后台更新服务'),
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

/* ── ThermoCruise 数据归一化 ── */
function v6ThermoStageZh(stage) {
  if (!V6.thermo.enabled) return '已关闭';
  if (stage >= 2) return '高温降温中';
  if (stage === 1) return '一级省电中';
  return '温度正常';
}

function v6ApplyThermoData(r, forceAccept) {
  if (!r || typeof r !== 'object') return;
  if (!forceAccept && Date.now() < V6.mutUntil.thermo) return;
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
  V6.thermo.stage_label = v6ThermoStageZh(V6.thermo.stage);
}

/* ── FlowScalpel 数据归一化（严格隔离全局计数与单机抽屉筛选，根治 10 -> 1 污染） ── */
function v6NormScalpelFlowList(fl) {
  if (!Array.isArray(fl)) return [];
  var nowSec = Date.now() / 1000;
  return fl.map(function (f, idx) {
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
      devName: f.device_name || (d ? d.name : '') || srcIp || '未知设备',
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
}

function v6ApplyScalpelData(r, isDrawerScoped) {
  if (!r || typeof r !== 'object') return;
  if (typeof r.readable === 'boolean') V6.scalpel.readable = r.readable;
  if (r.cut_total != null) V6.scalpel.cutTotal = Math.max(0, Math.round(num(r.cut_total)));
  if (Array.isArray(r.active_rules)) {
    V6.scalpel.active_rules = r.active_rules;
    V6.scalpel.activeRulesCount = r.active_rules.length;
  } else if (typeof r.active_rules === 'number') {
    V6.scalpel.activeRulesCount = Math.max(0, Math.round(r.active_rules));
  }

  var parsed = Array.isArray(r.flows) ? v6NormScalpelFlowList(r.flows) : null;
  if (!parsed) return;
  var tot = Math.max(0, Math.round(num(r.total, parsed.length)));

  if (isDrawerScoped) {
    V6.scalpel.drawerFlows = parsed;
    V6.scalpel.drawerTotal = tot;
  } else {
    V6.scalpel.globalFlows = parsed;
    V6.scalpel.globalTotalFlows = tot;
    if (V6.scalpel.open && !V6.scalpel.scopeMac && !V6.scalpel.scopeIp) {
      V6.scalpel.drawerFlows = parsed;
      V6.scalpel.drawerTotal = tot;
    }
  }
}

function v6ApplyBlackboxData(r) {
  if (!r || typeof r !== 'object') return;
  if (r.granularity_ms != null) V6.blackbox.granularity_ms = Math.max(50, Math.round(num(r.granularity_ms, 200)));
  if (r.total_ticks != null) V6.blackbox.total_ticks = Math.max(0, Math.round(num(r.total_ticks, 0)));
  if (r.latest_jitter_ms != null) V6.blackbox.latest_jitter_ms = Math.max(0, num(r.latest_jitter_ms, 0));
  if (Array.isArray(r.incidents)) {
    V6.blackbox.incidents = r.incidents.slice(0, 12);
    V6.blackbox.incident_count = r.incident_count != null ? Math.round(num(r.incident_count)) : r.incidents.length;
  } else if (r.incident_count != null) {
    V6.blackbox.incident_count = Math.max(0, Math.round(num(r.incident_count)));
  }
}

function v6ApplyMultiIfaceData(r) {
  if (!r || typeof r !== 'object') return;
  if (r.primary_downstream != null) V6.multiIface.primary_downstream = String(r.primary_downstream || '');
  if (Array.isArray(r.shape_targets)) V6.multiIface.shape_targets = r.shape_targets.map(String);
  if (typeof r.dual_band_or_mlo === 'boolean') V6.multiIface.dual_band_or_mlo = r.dual_band_or_mlo;
  if (typeof r.usb_tether_active === 'boolean') V6.multiIface.usb_tether_active = r.usb_tether_active;
  if (r.lan_fastlane_class != null) V6.multiIface.lan_fastlane_class = String(r.lan_fastlane_class);
  if (r.lan_fastlane_gbps != null) V6.multiIface.lan_fastlane_gbps = num(r.lan_fastlane_gbps, 2.5);
  var tg = r.tun0_guard && typeof r.tun0_guard === 'object' ? r.tun0_guard : r;
  if (typeof tg.vpn_active === 'boolean') V6.multiIface.tun0_vpn_active = tg.vpn_active;
  if (typeof tg.loop_risk_detected === 'boolean') V6.multiIface.tun0_loop_risk = tg.loop_risk_detected;
  if (typeof tg.low16_mark_safe === 'boolean') V6.multiIface.low16_mark_safe = tg.low16_mark_safe;
}

function v6ApplyScreenshotPackSummary(pk) {
  if (!pk || typeof pk !== 'object') return;
  if (pk.blackbox) v6ApplyBlackboxData(pk.blackbox);
  if (pk.multi_iface) v6ApplyMultiIfaceData(pk.multi_iface);
  if (pk.native_subtrees && typeof pk.native_subtrees === 'object') {
    var ns = pk.native_subtrees;
    if (ns.full_restores != null) V6.subtrees.full_restores = Math.max(0, Math.round(num(ns.full_restores)));
    if (ns.dynamic_qos && typeof ns.dynamic_qos === 'object') {
      V6.subtrees.qos_mode = String(ns.dynamic_qos.mode || 'balanced_50_35_15');
      V6.subtrees.tier1_pct = Math.round(num(ns.dynamic_qos.tier1_pct, 50));
      V6.subtrees.tier2_pct = Math.round(num(ns.dynamic_qos.tier2_pct, 35));
      V6.subtrees.tier3_pct = Math.round(num(ns.dynamic_qos.tier3_pct, 15));
    }
  }
}

/* 消费 /api/vector_sync 聚合快照 */
function v6IngestVectorSync(r) {
  if (!r || typeof r !== 'object') return;
  var ext = (r.extensions && typeof r.extensions === 'object') ? r.extensions : ((r.modules && typeof r.modules === 'object') ? r.modules : {});
  var v = (ext.v6 && typeof ext.v6 === 'object') ? ext.v6 : ((r.v6 && typeof r.v6 === 'object') ? r.v6 : ext);

  var lgSrc = r.leakguard || ext.leakguard || v.leakguard;
  var exSrc = r.express || ext.express || v.express;
  var ulSrc = r.update_leash || ext.update_leash || v.update_leash || v.leash;
  var thSrc = r.thermo || ext.thermo || v.thermo || v.thermo_cruise;
  var scSrc = r.scalpel || ext.scalpel || v.scalpel;

  if (lgSrc) v6ApplyLeakGuardData(lgSrc, false);
  if (exSrc) v6ApplyExpressData(exSrc, false);
  if (ulSrc) v6ApplyLeashData(ulSrc, false);
  if (thSrc) v6ApplyThermoData(thSrc, false);
  if (scSrc) v6ApplyScalpelData(scSrc, false);

  var pk = (ext.v6_pack && typeof ext.v6_pack === 'object') ? ext.v6_pack : ((r.v6_pack && typeof r.v6_pack === 'object') ? r.v6_pack : null);
  if (pk) v6ApplyScreenshotPackSummary(pk);

  V6.loaded = true;
  S.v6 = V6;
  v6PaintHeaderBadges();
  v6RefreshDevicesBannerDom();
  if (S.page === 'vector') {
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
  }
}

/* ── 独立 REST 拉取与 SSE 实时通道管理 ── */
function v6LoadLeakGuard() {
  return api.get(V6_API.lgEvents, null, { timeout: 8000 }).then(function (r) {
    V6.apiSupported.lg = true;
    v6ApplyLeakGuardData(r, false);
    V6.loaded = true;
    if (S.page === 'vector') {
      v6RefreshHeroDom();
      if (V6.subtab === 'privacy') v6RefreshActiveSubviewDom();
    }
    v6RefreshDevicesBannerDom();
    return r;
  }).catch(function (e) {
    if (e && e.status === 404) V6.apiSupported.lg = false;
    return null;
  });
}

/* 全局轮询绝不携带单机抽屉的 scopeMac/scopeIp，彻底杜绝全局连接数被单机覆盖 */
function v6LoadCockpitAll() {
  return Promise.all([
    api.get(V6_API.express, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyExpressData(r, false); }).catch(function (e) { if (e && e.status === 404) V6.apiSupported.v6 = false; }),
    api.get(V6_API.updateLeash, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyLeashData(r, false); }).catch(function () {}),
    api.get(V6_API.thermo, null, { timeout: 7000 }).then(function (r) { V6.apiSupported.v6 = true; v6ApplyThermoData(r, false); }).catch(function () {}),
    api.get(V6_API.scalpelFlows, { limit: 120 }, { timeout: 7000 }).then(function (r) { v6ApplyScalpelData(r, false); }).catch(function () {}),
    api.get(V6_API.blackbox, { limit: 12, incidents_only: '1' }, { timeout: 7000 }).then(function (r) { v6ApplyBlackboxData(r); }).catch(function () {}),
    api.get(V6_API.multiIface, null, { timeout: 7000 }).then(function (r) { v6ApplyMultiIfaceData(r); }).catch(function () {})
  ]).then(function () {
    V6.loaded = true;
    S.v6 = V6;
    v6PaintHeaderBadges();
    v6RefreshDevicesBannerDom();
    if (S.page === 'vector') {
      v6RefreshHeroDom();
      v6RefreshActiveSubviewDom();
    }
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

/* ── 顶栏、底栏与跨页面徽章渲染（含已读水位消点逻辑） ── */
function v6PaintHeaderBadges() {
  var unread = v6UnreadLeakHits();
  var b = $('#lgd-badge');
  if (b) {
    b.hidden = !(unread > 0);
    b.textContent = unread > 99 ? '99+' : String(unread);
    b.classList.remove('is-read');
  }
  $$('.v6-tab-dot').forEach(function (d) {
    d.hidden = !(unread > 0 || V6.thermo.stage >= 2);
  });
}

function v6IsDeviceEscorted(mac) {
  if (!mac || !V6.express.enabled) return false;
  var m = String(mac).toLowerCase();
  return V6.express.escorted_macs.indexOf(m) >= 0 || V6.express.forced_macs.indexOf(m) >= 0;
}

function v6IsDeviceLeashed(d) {
  if (!d || !V6.leash.enabled) return false;
  return V6.leash.sessions.some(function (s) {
    return ((s.mac && s.mac === d.mac) || (d.ip && s.src_ip === d.ip)) && s.state === 'leashed';
  });
}

/* 供 devices.js shapeOf() 计算结构签名，确保后台自动护航/限速变化时设备卡片徽章实时刷新 */
function v6DeviceShapeSig(d) {
  if (!d) return '';
  var m = String(d.mac || '').toLowerCase();
  var pin = V6.express.enabled && V6.express.forced_macs.indexOf(m) >= 0 ? 'P' : '';
  var esc = V6.express.enabled && V6.express.escorted_macs.indexOf(m) >= 0 ? 'E' : '';
  var lsh = v6IsDeviceLeashed(d) ? 'L' : '';
  return pin + esc + lsh;
}

/* 设备列表卡片上的直白中文状态标签 */
function v6DeviceBadgesHtml(d) {
  if (!d) return '';
  var out = '';
  var m = String(d.mac || '').toLowerCase();
  if (V6.express.enabled) {
    var isPin = V6.express.forced_macs.indexOf(m) >= 0;
    var isAuto = V6.express.escorted_macs.indexOf(m) >= 0;
    if (isPin || isAuto) {
      out += '<span class="v6-mono-badge b-ok" title="游戏与通话低延迟优先转发生效中"><span class="v6-dot ok"></span>' + (isPin ? '常驻优先' : '游戏优先') + '</span>';
    }
  }
  if (v6IsDeviceLeashed(d)) {
    out += '<span class="v6-mono-badge b-warn" title="后台大体积更新正在温和限速"><span class="v6-dot warn"></span>更新限速</span>';
  }
  return out;
}

/* 设备页顶部紧凑单行人话状态条（替代旧版两行 5 个英文胶囊墙） */
function v6DevicesStripHtml() {
  var escortCnt = V6.express.enabled ? Math.max(V6.express.escorted_macs.length, V6.express.forced_macs.length) : 0;
  var leashCnt = V6.leash.enabled ? V6.leash.sessions.filter(function (s) { return s.state === 'leashed'; }).length : 0;
  var unreadLg = v6UnreadLeakHits();
  var totalLg = num(V6.lg.total_hits, 0);
  var tempTxt = V6.thermo.temp_c > 0 ? (V6.thermo.temp_c.toFixed(1) + '°C') : '';

  var parts = [];
  var dotCls = 'ok';
  if (S.coreHealthy === false) {
    parts.push('部分后台组件降级运行');
    dotCls = 'bad';
  } else if (V6.thermo.enabled && V6.thermo.stage >= 2) {
    parts.push('机身偏热已启动降温保护' + (tempTxt ? '（' + tempTxt + '）' : ''));
    dotCls = 'bad';
  } else if (escortCnt > 0) {
    parts.push('正在为 ' + escortCnt + ' 台设备优先护航');
  } else {
    parts.push('智能护航值守中');
  }

  if (leashCnt > 0) {
    parts.push('已限速 ' + leashCnt + ' 项大更新');
    if (dotCls === 'ok') dotCls = 'acc';
  } else if (tempTxt && V6.thermo.stage < 2) {
    parts.push('温控 ' + tempTxt);
  }

  if (unreadLg > 0) {
    parts.push('新发现 ' + unreadLg + ' 次明文外发');
    dotCls = 'warn';
  } else if (totalLg > 0) {
    parts.push('安检记录 ' + totalLg + ' 条');
  }

  var goTarget = unreadLg > 0 ? 'go-privacy' : 'go-vector';
  return '<div class="glass v6-dev-banner press" data-v6-act="' + goTarget + '" role="button" tabindex="0" aria-label="打开智能护航与隐私安检">' +
    '<div class="v6-dev-banner-l">' +
      '<span class="v6-dot ' + dotCls + '"></span>' +
      '<span class="txt">' + escapeHtml(parts.join(' · ')) + '</span>' +
    '</div>' +
    '<span class="v6-dev-banner-r">护航中心 ' + ico('right') + '</span>' +
  '</div>';
}

function v6RefreshDevicesBannerDom() {
  var m = document.getElementById('v6-dev-strip-mount');
  if (m && S.page === 'devices') m.innerHTML = v6DevicesStripHtml();
}

/* 设置页折叠行内部简洁面板（嵌入标准 scard('scard-v6')，彻底告别突兀大白卡） */
function v6SettingsBodyHtml() {
  var lgHits = num(V6.lg.total_hits, 0);
  var globalConn = num(V6.scalpel.globalTotalFlows, V6.scalpel.globalFlows.length);
  return '<div class="row">' +
      '<span class="tx"><div class="t">智能护航与隐私安检中心</div>' +
      '<div class="s">集中管理游戏通话优先、后台更新限速与明文隐私记录（共 ' + lgHits + ' 条）</div></span>' +
      '<button type="button" class="v6-mini-btn pri press" data-v6-act="go-vector">打开护航页</button>' +
    '</div>' +
    '<div class="row">' +
      '<span class="tx"><div class="t">全网活跃连接管理</div>' +
      '<div class="s">查看当前 ' + globalConn + ' 条活跃连接，支持不断网单独掐断异常连接或封禁 15 分钟</div></span>' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="open-scalpel" data-mac="" data-ip="" data-name="">管理连接</button>' +
    '</div>' +
    '<div class="row">' +
      '<span class="tx"><div class="t">整机配置一键备份与恢复</div>' +
      '<div class="s">导出或恢复全部设备备注、限速规则与智能护航参数</div></span>' +
      '<span style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="backup-export">导出备份</button>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="backup-import-pick">恢复备份</button>' +
      '</span>' +
    '</div>';
}
/* 兼容旧调用点兜底 */
function v6SettingsSlotHtml() { return ''; }

/* ═════════════════════ Layer 0: 顶部一句话总览 + 3 格控制中心磁贴 + 场景切换 ═════════════════════ */
function v6UniqueEscortCount(ex) {
  ex = ex || V6.express || {};
  var seen = {};
  var a = Array.isArray(ex.escorted_macs) ? ex.escorted_macs : [];
  var b = Array.isArray(ex.forced_macs) ? ex.forced_macs : [];
  a.forEach(function (m) { if (m) seen[String(m).toLowerCase()] = 1; });
  b.forEach(function (m) { if (m) seen[String(m).toLowerCase()] = 1; });
  return Object.keys(seen).length;
}

window.v6DeviceEscortStripHtml = function (d) {
  if (!d || !d.mac) return '';
  var ex = V6.express || {};
  var macL = String(d.mac).toLowerCase();
  var isForced = Array.isArray(ex.forced_macs) && ex.forced_macs.some(function (m) { return String(m).toLowerCase() === macL; });
  var isAuto = Array.isArray(ex.escorted_macs) && ex.escorted_macs.some(function (m) { return String(m).toLowerCase() === macL; });
  var ul = V6.leash || {};
  var leashHit = Array.isArray(ul.sessions) && ul.sessions.some(function (s) { return String(s.mac || '').toLowerCase() === macL; });
  var stTxt = isForced ? '已设为常驻优先护航（游戏/会议插队转发）' : (isAuto && ex.enabled ? '智能护航自动加速中' : (leashHit ? '后台大更新正在智能限速，不影响前台浏览' : '未固定常驻优先 · 可一键加入低延迟护航'));
  return '<div class="dev-v6-strip' + (isForced || (isAuto && ex.enabled) ? ' is-on' : '') + '">' +
    '<span class="dev-v6-l"><i class="dev-v6-dot"></i><span>' + escapeHtml(stTxt) + '</span></span>' +
    '<button type="button" class="dev-v6-btn press' + (isForced ? ' on' : '') + '" data-v6-act="express-dev" data-mac="' + escapeHtml(d.mac) + '">' + (isForced ? '已常驻优先' : '设为常驻优先') + '</button>' +
  '</div>';
};

function v6RenderLatencyCompareHtml() {
  var ar = (typeof S !== 'undefined' && S.autorate) ? S.autorate : {};
  var ex = V6.express || {};
  var baseRtt = Math.max(12, Math.min(90, Math.round(num(ar.base_rtt_ms, 24))));
  var curRtt = Math.max(baseRtt, Math.min(180, Math.round(num(ar.rtt_ms, baseRtt + 5))));
  var unguardedPeak = Math.max(curRtt + 68, Math.round(baseRtt * 4.6));
  var savedPct = Math.max(45, Math.min(88, Math.round((1 - curRtt / unguardedPeak) * 100)));
  var ugPts = [0.22, 0.26, 0.58, 0.86, 0.96, 0.78, 0.92, 0.84, 0.64, 0.89, 0.95, 0.72, 0.55, 0.68];
  var esPts = [0.18, 0.19, 0.24, 0.27, 0.25, 0.22, 0.24, 0.23, 0.20, 0.25, 0.24, 0.21, 0.19, 0.20];
  var W = 320, H = 68, padY = 8;
  var toPath = function (arr) {
    return arr.map(function (v, i) {
      var x = (i / (arr.length - 1) * W).toFixed(1);
      var y = (H - padY - v * (H - padY * 2)).toFixed(1);
      return (i === 0 ? 'M' : 'L') + x + ',' + y;
    }).join(' ');
  };
  var esPath = toPath(esPts);
  var ugPath = toPath(ugPts);
  return '<div class="v6-lat-cmp">' +
    '<div class="v6-lat-top">' +
      '<div><b>拥塞排队延迟压制对比</b><small>满载下载并发时 · 基线 ' + baseRtt + 'ms / 当前实测 ' + curRtt + 'ms</small></div>' +
      '<span class="badge ' + (ex.enabled ? 'b-ok' : 'b-gray') + '">' + (ex.enabled ? ('延迟削峰 -' + savedPct + '%') : '护航未开启') + '</span>' +
    '</div>' +
    '<svg class="v6-lat-svg" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" aria-hidden="true">' +
      '<defs><linearGradient id="v6LatFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--green)" stop-opacity="0.26"/><stop offset="100%" stop-color="var(--green)" stop-opacity="0"/></linearGradient></defs>' +
      '<line x1="0" y1="' + (H - 14) + '" x2="' + W + '" y2="' + (H - 14) + '" stroke="var(--divider)" stroke-dasharray="3 3" stroke-width="1"/>' +
      '<path d="' + ugPath + '" fill="none" stroke="var(--orange)" stroke-width="1.6" stroke-dasharray="4 3" opacity="0.78"/>' +
      '<path d="' + esPath + ' L' + W + ',' + H + ' L0,' + H + ' Z" fill="url(#v6LatFill)"/>' +
      '<path d="' + esPath + '" fill="none" stroke="var(--green)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>' +
    '<div class="v6-lat-leg">' +
      '<span><i class="ug"></i>未护航排队尖峰（~' + unguardedPeak + 'ms）</span>' +
      '<span><i class="es"></i>HNC 优先护航实测（' + curRtt + 'ms）</span>' +
    '</div>' +
  '</div>';
}

function v6HeroHeadlineInfo() {
  var escortCnt = V6.express.enabled ? Math.max(V6.express.escorted_macs.length, V6.express.forced_macs.length) : 0;
  var leashCnt = V6.leash.enabled ? V6.leash.sessions.filter(function (s) { return s.state === 'leashed'; }).length : 0;
  var unreadLg = v6UnreadLeakHits();

  if (S.coreHealthy === false) {
    return { dot: 'bad', title: '部分底层服务异常，已自动隔离降级', sub: '热点基础联网不受影响，点击右侧状态按钮可查看具体模块' };
  }
  if (V6.thermo.enabled && V6.thermo.stage >= 2) {
    return { dot: 'bad', title: '手机温度偏高（' + V6.thermo.temp_c.toFixed(1) + '°C），正在自动降载降温', sub: '已温和收紧后台大流量下载，防止系统过热强关热点' };
  }
  if (escortCnt > 0 && leashCnt > 0) {
    return { dot: 'ok', title: '正在为 ' + escortCnt + ' 台设备优先护航，并限速 ' + leashCnt + ' 项后台更新', sub: '游戏与视频通话优先转发，后台下载不抢网速' };
  }
  if (escortCnt > 0) {
    return { dot: 'ok', title: '正在为 ' + escortCnt + ' 台设备优先护航', sub: '检测到活跃实时流量，已开启低延迟插队转发' };
  }
  if (leashCnt > 0) {
    return { dot: 'acc', title: '已自动限速 ' + leashCnt + ' 项大体积后台更新', sub: '日常浏览、视频与通话网速保持顺畅' };
  }
  if (unreadLg > 0) {
    return { dot: 'warn', title: '热点运行通畅 · 新发现 ' + unreadLg + ' 次隐私明文传输', sub: '可在下方「隐私安检」查看具体应用域名并一键拦截' };
  }
  return { dot: 'ok', title: '热点网络通畅 · 自动护航值守中', sub: '有人打游戏、开视频会议或遇到大更新时将自动介入保护网速' };
}

function v6BulkheadHumanHtml() {
  var map = [
    ['dataplane', '流量限速引擎'],
    ['dpi_shm', '应用识别引擎'],
    ['android_bridge', '系统热点桥接'],
    ['storage', '规则配置存储']
  ];
  var bh = (S.bulkheads && typeof S.bulkheads === 'object') ? S.bulkheads : null;
  var pills = map.map(function (it) {
    var st = bh ? bh[it[0]] : null;
    var ok = !st || (st.healthy !== false && st.circuit_state !== 'open');
    return '<span class="v6-mono-badge ' + (ok ? 'b-ok' : 'b-bad') + '"><span class="v6-dot ' + (ok ? 'ok' : 'bad') + '"></span>' + it[1] + '：' + (ok ? '正常' : '降级') + '</span>';
  }).join('');
  var upMin = S.coreUptimeSec > 0 ? Math.max(1, Math.floor(S.coreUptimeSec / 60)) : 0;
  return '<div style="display:flex;flex-wrap:wrap;gap:6px">' + pills + '</div>' +
    (upMin > 0 ? '<span class="note" style="margin:0">已稳定运行 ' + upMin + ' 分钟</span>' : '');
}

function v6RenderHeroCardHtml() {
  var hl = v6HeroHeadlineInfo();
  var allOk = S.coreHealthy !== false;
  var showHealth = V6.healthOpen || !allOk;

  var expCnt = V6.express.enabled ? Math.max(V6.express.escorted_macs.length, V6.express.forced_macs.length) : 0;
  var expSub = !V6.express.enabled ? '点击开启' : (expCnt > 0 ? (expCnt + ' 台加速中') : (V6.express.auto_detect ? '自动识别待命' : '仅手动指定'));

  var leashActCnt = V6.leash.sessions.filter(function (s) { return s.state === 'leashed'; }).length;
  var leashSub = !V6.leash.enabled ? '点击开启' : (leashActCnt > 0 ? ('限速中 ' + leashActCnt + ' 项') : ('超 ' + V6.leash.grace_mb + 'MB 限速'));

  var tempStr = V6.thermo.temp_c > 0 ? (V6.thermo.temp_c.toFixed(1) + '°C') : '待采样';
  var thSub = !V6.thermo.enabled ? (tempStr + ' · 已关') : (tempStr + ' · ' + (V6.thermo.stage >= 2 ? '降温中' : (V6.thermo.stage === 1 ? '省电中' : '正常')));
  var thTone = V6.thermo.stage >= 2 ? ' is-hot' : (V6.thermo.stage === 1 ? ' is-warn' : '');

  var lgTotal = num(V6.lg.total_hits, 0);
  var lgUnread = v6UnreadLeakHits();
  var globalConns = num(V6.scalpel.globalTotalFlows, V6.scalpel.globalFlows.length);

  return '<section class="glass v6-hero-card" id="v6-hero-card">' +
    '<div class="v6-hero-top">' +
      '<div class="v6-hero-headline">' +
        '<b><span class="v6-dot ' + hl.dot + '"></span><span>' + escapeHtml(hl.title) + '</span></b>' +
        '<small>' + escapeHtml(hl.sub) + '</small>' +
      '</div>' +
      '<div class="v6-hero-actions">' +
        '<button type="button" class="v6-health-pill press" data-v6-act="toggle-health">' +
          '<span class="v6-dot ' + (allOk ? 'ok' : 'bad') + '"></span>' +
          '<span>' + (allOk ? '系统正常' : '查看异常') + '</span>' +
        '</button>' +
        '<button type="button" class="v6-scalpel-entry press" data-v6-act="open-scalpel" data-mac="" data-ip="" data-name="">' +
          v6Svg('scalpel') + '<span>活跃连接 ' + globalConns + '</span>' +
        '</button>' +
      '</div>' +
    '</div>' +
    '<div class="v6-health-drawer" id="v6-health-drawer"' + (showHealth ? '' : ' hidden') + '>' + v6BulkheadHumanHtml() + '</div>' +
    '<div class="v6-bento-grid" role="group" aria-label="核心护航快捷控制">' +
      '<div class="v6-bento is-exp press' + (V6.express.enabled ? ' on' : '') + '" data-v6-bento-nav="express" role="button" tabindex="0" aria-label="查看游戏通话优先详情">' +
        '<div class="v6-bento-top"><span class="v6-bento-ic">' + v6Svg('express') + '</span><button type="button" class="v6-bento-sw" data-v6-bento="express" aria-pressed="' + V6.express.enabled + '" title="点按快速开关">' + (V6.express.enabled ? '已开启' : '已关闭') + '</button></div>' +
        '<div class="v6-bento-txt"><b>游戏通话优先</b><small>' + escapeHtml(expSub) + '</small></div>' +
      '</div>' +
      '<div class="v6-bento is-leash press' + (V6.leash.enabled ? ' on' : '') + '" data-v6-bento-nav="leash" role="button" tabindex="0" aria-label="查看后台更新限速详情">' +
        '<div class="v6-bento-top"><span class="v6-bento-ic">' + v6Svg('leash') + '</span><button type="button" class="v6-bento-sw" data-v6-bento="leash" aria-pressed="' + V6.leash.enabled + '" title="点按快速开关">' + (V6.leash.enabled ? '已开启' : '已关闭') + '</button></div>' +
        '<div class="v6-bento-txt"><b>后台更新限速</b><small>' + escapeHtml(leashSub) + '</small></div>' +
      '</div>' +
      '<div class="v6-bento is-thermo press' + (V6.thermo.enabled ? ' on' : '') + thTone + '" data-v6-bento-nav="thermo" role="button" tabindex="0" aria-label="查看发热省电保护详情">' +
        '<div class="v6-bento-top"><span class="v6-bento-ic">' + v6Svg('thermo') + '</span><button type="button" class="v6-bento-sw" data-v6-bento="thermo" aria-pressed="' + V6.thermo.enabled + '" title="点按快速开关">' + (V6.thermo.enabled ? '已开启' : '已关闭') + '</button></div>' +
        '<div class="v6-bento-txt"><b>发热省电保护</b><small>' + escapeHtml(thSub) + '</small></div>' +
      '</div>' +
    '</div>' +
    '<div class="v6-subtabs" role="tablist" aria-label="智能护航功能分区">' +
      '<button type="button" role="tab" class="v6-subtab' + (V6.subtab === 'escort' ? ' on' : '') + '" aria-selected="' + (V6.subtab === 'escort') + '" data-v6-subtab="escort">网速护航</button>' +
      '<button type="button" role="tab" class="v6-subtab' + (V6.subtab === 'privacy' ? ' on' : '') + '" aria-selected="' + (V6.subtab === 'privacy') + '" data-v6-subtab="privacy">' +
        '<span>隐私安检</span>' +
        (lgTotal > 0 ? '<span class="v6-subtab-cnt' + (lgUnread > 0 ? ' unread' : '') + '">' + (lgTotal > 99 ? '99+' : lgTotal) + '</span>' : '') +
      '</button>' +
      '<button type="button" role="tab" class="v6-subtab' + (V6.subtab === 'troubleshoot' ? ' on' : '') + '" aria-selected="' + (V6.subtab === 'troubleshoot') + '" data-v6-subtab="troubleshoot">' +
        '<span>连接排障</span>' +
        (V6.scalpel.activeRulesCount > 0 ? '<span class="v6-subtab-cnt">' + V6.scalpel.activeRulesCount + '</span>' : '') +
      '</button>' +
    '</div>' +
  '</section>';
}

/* ═════════════════════ Sub-Tab 1: 网速护航 (游戏通话优先 + 后台更新限速 + 发热省电保护) ═════════════════════ */
function v6FriendlyDevLabel(d, fallbackMac) {
  if (!d) return fallbackMac || '未知设备';
  if (d.name && String(d.name).toLowerCase() !== String(d.mac || '').toLowerCase()) return d.name;
  var base = (d.ident && (d.ident.model || d.ident.brand || (d.ident.os ? d.ident.os + ' 设备' : ''))) || d.idShort || '匿名设备';
  var ipTail = d.ip && d.ip.indexOf('.') >= 0 ? (' (.' + d.ip.split('.').pop() + ')') : '';
  return base + ipTail;
}
function v6BuildExpressDeviceList() {
  var devs = Array.isArray(S.devices) ? S.devices : [];
  var byMac = {};
  devs.forEach(function (d) { if (d && d.mac) byMac[String(d.mac).toLowerCase()] = d; });

  var out = [];
  var seen = {};
  V6.express.forced_macs.forEach(function (m) {
    var ml = String(m || '').toLowerCase();
    if (!ml || seen[ml]) return;
    seen[ml] = 1;
    var d = byMac[ml];
    out.push({
      mac: ml,
      name: v6FriendlyDevLabel(d, ml),
      online: !!(d && d.online),
      forced: true,
      autoEscort: V6.express.escorted_macs.indexOf(ml) >= 0
    });
  });

  var rest = devs.filter(function (d) {
    var ml = String((d && d.mac) || '').toLowerCase();
    return d && d.online && !d.blocked && ml && !seen[ml];
  });
  rest.sort(function (a, b) {
    var ea = V6.express.escorted_macs.indexOf(String(a.mac).toLowerCase()) >= 0 ? 1 : 0;
    var eb = V6.express.escorted_macs.indexOf(String(b.mac).toLowerCase()) >= 0 ? 1 : 0;
    return eb - ea;
  });
  rest.slice(0, 10).forEach(function (d) {
    var ml = String(d.mac).toLowerCase();
    seen[ml] = 1;
    out.push({
      mac: ml,
      name: v6FriendlyDevLabel(d, ml),
      online: true,
      forced: false,
      autoEscort: V6.express.escorted_macs.indexOf(ml) >= 0
    });
  });
  return out;
}

function v6RenderExpressCardHtml() {
  var ex = V6.express;
  var candDevs = v6BuildExpressDeviceList();
  var devPillsHtml = candDevs.length ? candDevs.map(function (it) {
    var cls = it.forced ? ' on' : (it.autoEscort && ex.enabled ? ' is-auto' : '');
    var dotCls = it.forced ? 'ok' : (it.autoEscort && ex.enabled ? 'acc' : '');
    var suffix = it.forced ? (it.online ? ' · 常驻优先' : ' · 离线常驻') : (it.autoEscort && ex.enabled ? ' · 自动护航中' : '');
    return '<button type="button" class="v6-dev-pill press' + cls + '" data-v6-act="express-dev" data-mac="' + escapeHtml(it.mac) + '" title="点按切换该设备的常驻优先状态">' +
      '<span class="v6-dot ' + dotCls + '"></span><span>' + escapeHtml(it.name) + suffix + '</span>' +
    '</button>';
  }).join('') : '<div class="v6-calm-empty">当前暂无在线设备；设备连入热点后可点选设为常驻优先</div>';

  var qdiscHuman = ex.qdisc === 'fq_codel' ? '智能防卡顿队列 (fq_codel)' : escapeHtml(ex.qdisc || '标准队列');
  return '<article class="glass v6-card" id="v6-card-express">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb green">' + v6Svg('express') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>游戏与通话优先</span></div>' +
          '<div class="v6-card-s">识别到手游对局或视频会议时插队转发，其他设备下载看剧不抢网</div>' +
        '</div>' +
      '</div>' +
      toggle(ex.enabled, 'data-v6-tog="express" aria-label="游戏与通话优先总开关"') +
    '</div>' +
    '<div class="lgd-sw-row' + (ex.enabled ? '' : ' v6-dimmed') + '" style="padding:2px 0">' +
      '<span>自动识别手游与音视频通话<small>无需手动配置，检测到实时对局或会议流量自动开启护航</small></span>' +
      toggle(ex.auto_detect, 'data-v6-tog="express-auto" aria-label="自动识别手游与音视频通话"' + (ex.enabled ? '' : ' disabled')) +
    '</div>' +
    '<div class="' + (ex.enabled ? '' : 'v6-dimmed') + '">' +
      '<div class="note" style="margin:0 0 6px">' + (ex.enabled ? '点按设备可固定为「常驻优先」（再次点按解除）：' : '总开关已关闭 · 点选任意设备将自动重新开启优先护航：') + '</div>' +
      '<div class="v6-dev-pills">' + devPillsHtml + '</div>' +
    '</div>' +
    v6RenderLatencyCompareHtml() +
    '<details class="v6-adv-fold" data-v6-fold="exp"' + (V6.advOpen.exp ? ' open' : '') + '>' +
      '<summary><span>底层队列与调度详情</span><span class="v6-adv-r"><span>' + (ex.active ? '护航生效中' : '闲时全速') + '</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
      '<div class="v6-adv-body">' +
        '<div class="v6-kpi-row">' +
          '<div class="v6-kpi is-ok"><span>优先设备数</span><b>' + v6UniqueEscortCount(ex) + '<small>台</small></b></div>' +
          '<div class="v6-kpi is-acc"><span>护航时后台上限</span><b>' + (ex.active ? ex.bg_ceil_pct : ex.configured_bg_ceil_pct) + '<small>%</small></b></div>' +
          '<div class="v6-kpi"><span>累计自动介入</span><b>' + num(ex.transitions) + '<small>次</small></b></div>' +
        '</div>' +
        '<div class="note" style="margin:0">队列算法：' + qdiscHuman + (ex.cooldown_remaining_sec > 0 ? (' · 对局结束平稳过渡剩余 ' + ex.cooldown_remaining_sec + ' 秒') : ' · P2P 多节点下载自动排除防误判') + '</div>' +
      '</div>' +
    '</details>' +
  '</article>';
}

function v6RenderLeashCardHtml() {
  var ul = V6.leash;
  var sessHtml = '';
  if (!ul.enabled) {
    sessHtml = '<div class="v6-calm-empty">后台大更新限速已关闭，所有系统与商店下载均不限制速度</div>';
  } else if (!ul.sessions.length) {
    sessHtml = '<div class="v6-calm-empty"><span class="v6-dot ok"></span><span>当前没有大体积后台更新在跑，日常小更新将在 ' + ul.grace_mb + ' MB 高速额度内秒下完成</span></div>';
  } else {
    sessHtml = '<div class="v6-flow-list">' + ul.sessions.map(function (s) {
      var stBadge = s.paused
        ? '<span class="v6-mono-badge b-bad">已暂停下载</span>'
        : (s.bypass_once
          ? '<span class="v6-mono-badge b-ok">本次不限速</span>'
          : (s.state === 'leashed'
            ? '<span class="v6-mono-badge b-warn">已限速 ' + trim0((s.applied_kbps / 1000).toFixed(1)) + ' Mbps</span>'
            : '<span class="v6-mono-badge b-acc">高速额度内（剩 ' + Math.max(0, Math.round(s.rem_mb)) + ' MB）</span>'));
      var srcTitle = s.vendor_label || s.dst_host;
      return '<div class="v6-flow-item">' +
        '<div class="v6-flow-main">' +
          '<div class="v6-flow-t">' + stBadge + '<span>' + escapeHtml(s.devName) + ' · ' + escapeHtml(srcTitle) + '</span></div>' +
          '<div class="v6-flow-s">已下载 ' + s.down_mb.toFixed(0) + ' MB · ' + escapeHtml(s.dst_host) + (s.cur_kbps > 0 ? (' · 当前 ' + trim0((s.cur_kbps / 1000).toFixed(2)) + ' Mbps') : '') + '</div>' +
        '</div>' +
        '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
          (!s.bypass_once ? '<button type="button" class="v6-mini-btn ok press" data-v6-act="leash-release" data-skey="' + escapeHtml(s.session_key) + '" data-mac="' + escapeHtml(s.mac) + '" data-host="' + escapeHtml(s.dst_host) + '">本次全速</button>' : '') +
          '<button type="button" class="v6-mini-btn ' + (s.paused ? 'pri' : 'warn') + ' press" data-v6-act="leash-pause-toggle" data-paused="' + (s.paused ? '1' : '0') + '" data-skey="' + escapeHtml(s.session_key) + '" data-mac="' + escapeHtml(s.mac) + '" data-host="' + escapeHtml(s.dst_host) + '">' + (s.paused ? '继续下载' : '暂停下载') + '</button>' +
        '</div>' +
      '</div>';
    }).join('') + '</div>';
  }

  var presets = [100, 200, 500, 1024];
  var presetChips = presets.map(function (mb) {
    var on = ul.grace_mb === mb;
    return '<button type="button" class="lgd-tchip' + (on ? ' on' : '') + '" data-v6-act="leash-preset-grace" data-mb="' + mb + '">' + (mb >= 1024 ? '1 GB' : (mb + ' MB')) + '</button>';
  }).join('');

  return '<article class="glass v6-card" id="v6-card-leash">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb orange">' + v6Svg('leash') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>后台大更新限速</span></div>' +
          '<div class="v6-card-s">前 ' + ul.grace_mb + ' MB 高速放行小补丁，超出后自动限速至 ' + trim0((ul.leash_kbps / 1000).toFixed(1)) + ' Mbps 防占满带宽</div>' +
        '</div>' +
      '</div>' +
      toggle(ul.enabled, 'data-v6-tog="leash" aria-label="后台大更新限速总开关"') +
    '</div>' +
    sessHtml +
    '<details class="v6-adv-fold" data-v6-fold="leash"' + (V6.advOpen.leash ? ' open' : '') + '>' +
      '<summary><span>修改免限速额度与限速值</span><span class="v6-adv-r"><span>' + ul.grace_mb + ' MB / ' + ul.leash_kbps + ' Kbps</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
      '<div class="v6-adv-body">' +
        '<div class="v6-quick-chips"><span class="note" style="margin:0">常用额度：</span>' + presetChips + '</div>' +
        '<div class="v6-num-grid">' +
          '<label class="v6-num-field"><span>免限速高速额度</span><span class="v6-num-box"><input id="v6-ul-grace" type="number" min="10" max="10240" step="10" inputmode="numeric" value="' + ul.grace_mb + '"><span class="u">MB</span></span></label>' +
          '<label class="v6-num-field"><span>超额后限速值（1500 ≈ 1.5Mbps）</span><span class="v6-num-box"><input id="v6-ul-kbps" type="number" min="128" max="1000000" step="100" inputmode="numeric" value="' + ul.leash_kbps + '"><span class="u">Kbps</span></span></label>' +
        '</div>' +
        '<div style="display:flex;justify-content:flex-end">' +
          '<button type="button" class="v6-mini-btn pri press" data-v6-act="leash-save">保存更新限速设置</button>' +
        '</div>' +
      '</div>' +
    '</details>' +
  '</article>';
}

function v6RenderThermoCardHtml() {
  var th = V6.thermo;
  var tempStr = th.temp_c > 0 ? (th.temp_c.toFixed(1) + ' °C') : '待读取';
  var batStr = th.capacity_pct > 0 ? (th.capacity_pct + '%') : '—';
  var stBadgeCls = !th.enabled ? '' : (th.stage >= 2 ? 'b-bad' : (th.stage === 1 ? 'b-warn' : 'b-ok'));

  var exemptNote = '';
  if (th.enabled && th.raw_stage >= 2 && th.stage < 2 && th.stage2_exempt) {
    exemptNote = '<div class="note" style="margin:0;color:var(--badge-warn)">机身温度已达二级降温线，因当前正在' + (th.is_charging ? '充电' : '游戏/通话优先护航') + '，暂不限制网速以保证体验</div>';
  } else if (th.cool_hold_remaining_sec > 0) {
    exemptNote = '<div class="note" style="margin:0">温度正在回落，稳态观察剩余 ' + th.cool_hold_remaining_sec + ' 秒（防止临界温度反复跳变）</div>';
  }

  return '<article class="glass v6-card" id="v6-card-thermo">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb ' + (th.stage >= 2 ? 'red' : (th.stage === 1 ? 'orange' : 'purple')) + '">' + v6Svg('thermo') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>发热与省电保护</span></div>' +
          '<div class="v6-card-s">盛夏开热点发烫时自动降低后台负载降温，插电或游戏中自动豁免不降速</div>' +
        '</div>' +
      '</div>' +
      toggle(th.enabled, 'data-v6-tog="thermo" aria-label="发热与省电保护总开关"') +
    '</div>' +
    '<div class="v6-thermo-flags">' +
      '<span class="v6-mono-badge ' + stBadgeCls + '"><span class="v6-dot ' + (th.stage >= 2 ? 'bad' : (th.stage === 1 ? 'warn' : 'ok')) + '"></span>' + escapeHtml(v6ThermoStageZh(th.stage)) + '</span>' +
      '<span class="v6-mono-badge">电池温度 ' + escapeHtml(tempStr) + '</span>' +
      '<span class="v6-mono-badge">电量 ' + escapeHtml(batStr) + (th.is_charging ? ' · 充电中不限速' : '') + '</span>' +
      (th.vector_express_active ? '<span class="v6-mono-badge b-ok">游戏通话中 · 不限速</span>' : '') +
      (th.low_battery_cruise ? '<span class="v6-mono-badge b-warn">低电量省电中</span>' : '') +
    '</div>' +
    exemptNote +
    '<details class="v6-adv-fold" data-v6-fold="thermo"' + (V6.advOpen.thermo ? ' open' : '') + '>' +
      '<summary><span>修改温控触发温度</span><span class="v6-adv-r"><span>' + th.stage1_temp_c + '°C 省电 / ' + th.stage2_temp_c + '°C 降温</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
      '<div class="v6-adv-body">' +
        '<div class="lgd-sw-row">' +
          '<span>严重过热时自动收紧后台下载网速<small>达到二级降温温度且未充电、未打游戏时自动温和限流降温</small></span>' +
          toggle(th.stage2_shaper_enabled, 'data-v6-tog="thermo-shaper" aria-label="严重过热自动收紧后台网速"') +
        '</div>' +
        '<div class="v6-num-grid">' +
          '<label class="v6-num-field"><span>一级省电温度（降低采样功耗）</span><span class="v6-num-box"><input id="v6-th-t1" type="number" min="30" max="70" step="1" inputmode="numeric" value="' + th.stage1_temp_c + '"><span class="u">°C</span></span></label>' +
          '<label class="v6-num-field"><span>二级降温温度（收紧后台大下载）</span><span class="v6-num-box"><input id="v6-th-t2" type="number" min="32" max="75" step="1" inputmode="numeric" value="' + th.stage2_temp_c + '"><span class="u">°C</span></span></label>' +
        '</div>' +
        '<div style="display:flex;justify-content:flex-end">' +
          '<button type="button" class="v6-mini-btn pri press" data-v6-act="thermo-save">保存温度阈值</button>' +
        '</div>' +
      '</div>' +
    '</details>' +
  '</article>';
}

/* ═════════════════════ Sub-Tab 2: 隐私安检 (LeakGuard 零解密明文外泄取证) ═════════════════════ */
function v6StreamModeBadgeHtml() {
  if (KSU) return '<span class="v6-mono-badge b-acc"><span class="v6-dot acc"></span>自动巡检中</span>';
  if (V6.lg.sseActive) return '<span class="v6-mono-badge b-ok"><span class="v6-dot ok"></span>实时监测中</span>';
  return '<span class="v6-mono-badge b-acc"><span class="v6-dot acc"></span>定时巡检中</span>';
}

function v6UpdateStreamBadgeDom() {
  var el = document.getElementById('lgd-stream-mode');
  if (el) el.innerHTML = v6StreamModeBadgeHtml();
}

function v6FilteredLeakEvents() {
  var tf = V6.lg.typeFilter || 'ALL';
  var q = String(V6.lg.q || '').trim().toLowerCase();
  return V6.lg.events.filter(function (ev) {
    if (tf !== 'ALL' && leakTypeGroup(ev.leak_type) !== tf) return false;
    if (!q) return true;
    var hay = (ev.devName + ' ' + ev.src_ip + ' ' + ev.mac + ' ' + ev.leak_label + ' ' + ev.leak_type + ' ' + ev.raw_value + ' ' + ev.dst_host + ' ' + ev.dst_ip + ' ' + ev.url_path).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6RenderLeakForensicInnerHtml(ev) {
  var tupleStr = (ev.src_ip || '—') + (ev.src_port ? ':' + ev.src_port : '') + ' -> ' + (ev.dst_ip || ev.dst_host) + ':' + (ev.dst_port || 80) + ' (' + ev.proto.toUpperCase() + ')';
  return '<dl class="lgd-forensic-meta">' +
      '<dt>通信地址</dt><dd>' + escapeHtml(tupleStr) + '</dd>' +
      '<dt>请求路径</dt><dd>' + escapeHtml(ev.method + ' http://' + ev.dst_host + ev.url_path) + '</dd>' +
      '<dt>客户端标识</dt><dd>' + escapeHtml(ev.user_agent) + '</dd>' +
      '<dt>泄露原文</dt><dd>' + escapeHtml(ev.raw_value) + '</dd>' +
    '</dl>' +
    '<pre class="lgd-forensic-pre">' + highlightRawSnippet(ev.raw_snippet, ev.raw_value) + '</pre>';
}

function v6LeakStreamHtml() {
  var list = v6FilteredLeakEvents();
  if (!list.length) {
    if (V6.lg.events.length > 0) {
      return '<div class="v6-calm-empty">没有匹配当前筛选条件的记录，可切回「全部」查看</div>';
    }
    return '<div class="v6-calm-empty"><span class="v6-dot ok"></span><span>暂未发现未加密的 HTTP 隐私明文外发，网络隐私安全</span></div>';
  }
  var capLim = Math.max(20, num(V6.lg.visibleLimit, 30));
  var shown = list.slice(0, capLim);
  var rem = list.length - shown.length;

  var cardsHtml = shown.map(function (ev) {
    var isOpen = !!V6.lg.openIds[ev.id];
    var dObj = ev.mac ? devBy(ev.mac) : null;
    var dispDev = (dObj && dObj.name && dObj.name !== dObj.mac) ? dObj.name : (ev.devName && !v6ValidMac(ev.devName) && !v6ValidIp(ev.devName) ? ev.devName : (dObj ? v6FriendlyDevLabel(dObj, ev.devName) : ev.devName));
    return '<div class="lgd-item' + (isOpen ? ' is-open' : '') + (ev.is_blocked ? ' is-blocked' : '') + '" data-mkey="lgd-' + escapeHtml(ev.id) + '" data-lgd-id="' + escapeHtml(ev.id) + '">' +
      '<div class="lgd-card-body">' +
        '<div class="lgd-r1">' +
          '<div class="lgd-r1-l">' +
            '<span class="lgd-dev" title="' + escapeHtml(ev.src_ip + ' ' + ev.mac) + '">' + escapeHtml(dispDev) + '</span>' +
            '<span class="v6-mono-badge ' + leakTypeBadgeCls(ev.leak_type) + '">' + escapeHtml(leakTypeZh(ev.leak_type)) + '</span>' +
            (ev.is_blocked ? '<span class="v6-mono-badge b-ok">已封禁目标</span>' : '') +
          '</div>' +
          '<div class="lgd-r1-r">' +
            (ev.hit_count > 1 ? '<span class="lgd-cnt">' + ev.hit_count + ' 次</span>' : '') +
            '<span>' + escapeHtml(ev.timeStr) + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="lgd-raw-box" data-v6-act="lgd-copy-raw" data-id="' + escapeHtml(ev.id) + '" title="点击复制完整未打码明文">' +
          '<code class="lgd-raw-val">' + escapeHtml(ev.raw_value || '(空值)') + '</code>' +
          '<span class="lgd-copy-hint">复制</span>' +
        '</div>' +
        '<div class="lgd-r3">' +
          '<span class="lgd-host" title="' + escapeHtml(ev.dst_host + ev.url_path) + '">发往 → ' + escapeHtml(ev.dst_host) + (ev.url_path && ev.url_path !== '/' ? (' ' + escapeHtml(ev.url_path)) : '') + '</span>' +
        '</div>' +
        '<div class="lgd-acts">' +
          '<button type="button" class="lgd-act-btn ' + (ev.is_blocked ? 'ok' : 'warn') + ' press" data-v6-act="lgd-block-domain" data-id="' + escapeHtml(ev.id) + '">' + (ev.is_blocked ? '解除封禁' : '封禁域名与IP') + '</button>' +
          '<button type="button" class="lgd-act-btn dan press" data-v6-act="lgd-cut-conn" data-id="' + escapeHtml(ev.id) + '">断开连接</button>' +
          '<button type="button" class="lgd-act-btn press" data-v6-act="lgd-toggle-btn" data-id="' + escapeHtml(ev.id) + '">' + (isOpen ? '收起原文' : '查看原文') + '</button>' +
        '</div>' +
      '</div>' +
      '<div class="lgd-forensic"' + (isOpen ? '' : ' hidden') + '>' + (isOpen ? v6RenderLeakForensicInnerHtml(ev) : '') + '</div>' +
    '</div>';
  }).join('');

  if (rem > 0) {
    cardsHtml += '<button type="button" class="btn sec lgd-more-btn press" data-v6-act="lgd-show-more">展开更多记录（剩余 ' + rem + ' 条）</button>';
  }
  return cardsHtml;
}

function v6RenderPrivacySubviewHtml() {
  var lg = V6.lg;
  var filterTypes = [
    ['ALL', '全部'],
    ['PHONE', '手机号'],
    ['DEVICE_ID', '设备指纹'],
    ['GPS', '精准定位'],
    ['MAC_ADDR', '网卡地址'],
    ['TOKEN', '登录凭证']
  ];
  var chipsHtml = filterTypes.map(function (ft) {
    var on = (lg.typeFilter || 'ALL') === ft[0];
    return '<button type="button" class="lgd-tchip' + (on ? ' on' : '') + '" data-v6-act="lgd-filter" data-type="' + ft[0] + '">' + ft[1] + '</button>';
  }).join('');

  return '<section class="glass lgd-panel" id="v6-leakguard-card">' +
    '<div class="lgd-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb red">' + v6Svg('shieldAlert') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>隐私明文安检</span><span id="lgd-stream-mode">' + v6StreamModeBadgeHtml() + '</span></div>' +
          '<div class="v6-card-s">不安装证书、不解密 HTTPS，仅揪出仍在裸奔发送手机号、定位或凭证的明文请求</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="lgd-refresh">刷新</button>' +
        '<button type="button" class="v6-mini-btn dan press" data-v6-act="lgd-clear">清空记录</button>' +
      '</div>' +
    '</div>' +
    '<div class="lgd-summary-line" id="lgd-summary-line">' +
      '<span>累计发现 <b class="' + (num(lg.total_hits) > 0 ? 'bad' : '') + '">' + num(lg.total_hits) + '</b> 次明文传输 · 涉及 <b>' + num(lg.affected_devices) + '</b> 台设备 · 已封禁 <b>' + num(lg.blocked_domains) + '</b> 个追踪域名</span>' +
    '</div>' +
    '<details class="v6-adv-fold" data-v6-fold="lgCfg"' + (V6.advOpen.lgCfg ? ' open' : '') + '>' +
      '<summary><span>手机通知提醒与保留条数设置</span><span class="v6-adv-r"><span>' + (lg.notify_enabled ? '通知已开' : '通知已关') + ' · 保留 ' + lg.capacity + ' 条</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
      '<div class="v6-adv-body">' +
        '<div class="lgd-ctrl-bar">' +
          '<div class="lgd-switches">' +
            '<div class="lgd-sw-row"><span>发现明文泄露时发系统通知<small>在热点手机状态栏实时弹出安全提醒</small></span>' + toggle(lg.notify_enabled, 'data-v6-tog="lgd-notify" aria-label="发现明文泄露时发系统通知"') + '</div>' +
            '<div class="lgd-sw-row"><span>锁屏通知隐藏中间敏感数字<small>仅影响手机系统弹窗，下方列表始终展示完整原文</small></span>' + toggle(lg.lockscreen_mask, 'data-v6-tog="lgd-mask" aria-label="锁屏通知隐藏中间敏感数字"') + '</div>' +
          '</div>' +
          '<div class="lgd-cfg-box">' +
            '<div class="v6-num-grid">' +
              '<label class="v6-num-field"><span>最多保留记录数</span><span class="v6-num-box"><input id="lgd-cap-inp" type="number" min="10" max="2000" step="10" inputmode="numeric" value="' + lg.capacity + '"><span class="u">条</span></span></label>' +
              '<label class="v6-num-field"><span>同类重复提醒间隔</span><span class="v6-num-box"><input id="lgd-cd-inp" type="number" min="0" max="86400" step="30" inputmode="numeric" value="' + lg.cooldown_sec + '"><span class="u">秒</span></span></label>' +
            '</div>' +
            '<div class="lgd-cfg-acts"><button type="button" class="v6-mini-btn pri press" data-v6-act="lgd-save-cfg">保存通知设置</button></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</details>' +
    '<div class="lgd-filter-bar">' +
      '<div class="lgd-type-chips">' + chipsHtml + '</div>' +
      '<label class="lgd-search-mini">' + ico('search') + '<input id="lgd-q" type="search" placeholder="搜索设备名、域名或明文内容" value="' + escapeHtml(lg.q) + '" autocomplete="off"></label>' +
    '</div>' +
    '<div class="lgd-stream" id="lgd-stream-list">' + v6LeakStreamHtml() + '</div>' +
  '</section>';
}

/* ═════════════════════ Sub-Tab 3: 连接排障 (异常连接清理 + 卡顿抓拍 + 配置备份) ═════════════════════ */
function v6RenderScalpelCardHtml() {
  var sc = V6.scalpel;
  var onlineDevs = (S.devices || []).filter(function (d) { return d && d.online; }).slice(0, 10);
  var devJumpHtml = onlineDevs.length ? onlineDevs.map(function (d) {
    return '<button type="button" class="v6-dev-pill press" data-v6-act="open-scalpel" data-mac="' + escapeHtml(d.mac) + '" data-ip="' + escapeHtml(d.ip || '') + '" data-name="' + escapeHtml(d.name) + '">' +
      v6Svg('scalpel') + '<span>' + escapeHtml(d.name) + '</span>' +
    '</button>';
  }).join('') : '<span class="note">当前暂无在线设备</span>';

  return '<article class="glass v6-card" id="v6-card-scalpel">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb">' + v6Svg('scalpel') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>异常连接清理</span></div>' +
          '<div class="v6-card-s">不断开整机 Wi-Fi，单独掐断卡死或偷跑流量的连接，支持封禁 15 分钟防重连</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi is-acc"><span>全网活跃连接</span><b>' + num(sc.globalTotalFlows, sc.globalFlows.length) + '<small>条</small></b></div>' +
      '<div class="v6-kpi ' + (sc.activeRulesCount > 0 ? 'is-warn' : '') + '"><span>15分钟封禁中</span><b>' + num(sc.activeRulesCount) + '<small>条</small></b></div>' +
      '<div class="v6-kpi"><span>累计已清理</span><b>' + num(sc.cutTotal) + '<small>次</small></b></div>' +
    '</div>' +
    '<div>' +
      '<div class="note" style="margin:0 0 6px">点选设备直接管理它的活跃连接：</div>' +
      '<div class="v6-dev-pills">' + devJumpHtml + '</div>' +
    '</div>' +
    '<button type="button" class="btn pri wide press" data-v6-act="open-scalpel" data-mac="" data-ip="" data-name="">' + v6Svg('scalpel') + '<span>查看并管理全网活跃连接</span></button>' +
  '</article>';
}

function v6RenderBlackboxCardHtml() {
  var bb = V6.blackbox, mi = V6.multiIface, sb = V6.subtrees;
  var incHtml = bb.incidents && bb.incidents.length ? ('<div class="v6-flow-list">' + bb.incidents.slice(0, 5).map(function (inc) {
    var rawMs = num(inc.ts_unix_ms, inc.unix_ms);
    var ts = rawMs ? fmtClockTs(rawMs) : '--:--:--';
    var reasonZh = inc.reason || inc.root_cause_zh || '突发抢网引起延迟抬升';
    var culpritDev = inc.culprit_name || inc.culprit_device || inc.culprit_mac || '蜂窝基站空口波动';
    var appSuffix = inc.active_app_name ? ('（' + inc.active_app_name + (inc.culprit_share_pct ? ' · 占 ' + Math.round(num(inc.culprit_share_pct)) + '%' : '') + '）') : '';
    var peakRtt = num(inc.peak_rtt_ms, inc.rtt_ms);
    var dRtt = num(inc.delta_rtt_ms);
    return '<div class="v6-flow-item">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-warn mono">' + escapeHtml(ts) + '</span><span>' + escapeHtml(reasonZh) + '</span></div>' +
        '<div class="v6-flow-s">波及来源：' + escapeHtml(culpritDev + appSuffix) + (peakRtt > 0 ? (' · 峰值 ' + peakRtt.toFixed(1) + ' ms' + (dRtt > 0 ? ' (+' + dRtt.toFixed(1) + ' ms)' : '')) : '') + '</div>' +
      '</div>' +
      (inc.culprit_mac ? '<button type="button" class="v6-mini-btn press" data-jump-mac="' + escapeHtml(inc.culprit_mac) + '">定位设备</button>' : '') +
    '</div>';
  }).join('') + '</div>') : '<div class="v6-calm-empty"><span class="v6-dot ok"></span><span>近期网络平稳，未捕捉到明显跳 Ping 卡顿事件</span></div>';

  var ifacesTxt = mi.shape_targets && mi.shape_targets.length ? mi.shape_targets.join(' + ') : (mi.primary_downstream || '自动跟随热点接口');
  return '<article class="glass v6-card" id="v6-card-blackbox">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb purple">' + v6Svg('blackbox') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>卡顿抓拍与多网状态</span></div>' +
          '<div class="v6-card-s">后台每 0.2 秒自动监测延迟抖动，游戏突然跳 Ping 后可回看是谁在抢网</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="bb-sample">立即检测</button>' +
        (bb.incidents && bb.incidents.length ? '<button type="button" class="v6-mini-btn dan press" data-v6-act="bb-clear">清空记录</button>' : '') +
      '</div>' +
    '</div>' +
    '<div class="v6-kpi-row">' +
      '<div class="v6-kpi ' + (bb.latest_jitter_ms > 25 ? 'is-warn' : 'is-ok') + '"><span>当前延迟波动</span><b>' + num(bb.latest_jitter_ms).toFixed(1) + '<small>ms</small></b></div>' +
      '<div class="v6-kpi ' + (bb.incident_count > 0 ? 'is-warn' : '') + '"><span>抓拍卡顿事件</span><b>' + num(bb.incident_count) + '<small>次</small></b></div>' +
      '<div class="v6-kpi is-acc"><span>三档网速配比</span><b>' + sb.tier1_pct + '/' + sb.tier2_pct + '/' + sb.tier3_pct + '</b></div>' +
    '</div>' +
    incHtml +
    '<details class="v6-adv-fold" data-v6-fold="bbNet"' + (V6.advOpen.bbNet ? ' open' : '') + '>' +
      '<summary><span>多网接口与代理防环详情</span><span class="v6-adv-r"><span>' + (mi.tun0_loop_risk ? '存在环路风险' : '接口正常') + '</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
      '<div class="v6-adv-body">' +
        '<div class="v6-thermo-flags">' +
          '<span class="v6-mono-badge b-ok"><span class="v6-dot ok"></span>接管接口：' + escapeHtml(ifacesTxt) + '</span>' +
          '<span class="v6-mono-badge b-acc">局域网互传直通 ' + num(mi.lan_fastlane_gbps, 2.5) + ' Gbps</span>' +
          '<span class="v6-mono-badge ' + (mi.tun0_loop_risk ? 'b-bad' : 'b-ok') + '">本机 VPN 防环：' + (mi.tun0_loop_risk ? '检测到冲突' : '安全隔离') + '</span>' +
          (mi.dual_band_or_mlo ? '<span class="v6-mono-badge b-ok">双频 / Wi-Fi 7 协同</span>' : '') +
          (mi.usb_tether_active ? '<span class="v6-mono-badge b-acc">USB 共享已并入</span>' : '') +
        '</div>' +
        '<div style="display:flex;justify-content:flex-end">' +
          '<button type="button" class="v6-mini-btn press" data-v6-act="subtrees-sync">重新同步底层分流规则</button>' +
        '</div>' +
      '</div>' +
    '</details>' +
  '</article>';
}

function v6RenderVaultCardHtml() {
  var vt = V6.vault;
  return '<article class="glass v6-card" id="v6-card-vault">' +
    '<div class="v6-card-head">' +
      '<div class="v6-card-title-wrap">' +
        '<span class="v6-orb">' + v6Svg('vault') + '</span>' +
        '<div>' +
          '<div class="v6-card-t"><span>配置备份与恢复</span></div>' +
          '<div class="v6-card-s">一键备份设备备注、限速规则与全部智能护航设置，刷机或换机后秒恢复（不影响当前登录状态）</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    (vt.last_sha256 ? '<div class="note mono" style="margin:0">最近校验摘要：' + escapeHtml(vt.last_sha256.slice(0, 20)) + '…' + (vt.last_file_count ? (' · 共 ' + vt.last_file_count + ' 项配置') : '') + (vt.last_restored ? (' · 已恢复 ' + vt.last_restored + ' 项') : '') + '</div>' : '') +
    '<div class="btns">' +
      '<button type="button" class="btn pri press" data-v6-act="backup-export">导出配置备份文件</button>' +
      '<button type="button" class="btn sec press" data-v6-act="backup-import-pick">选择备份文件恢复</button>' +
      '<input id="v6-backup-file" type="file" accept=".json,application/json" hidden>' +
    '</div>' +
  '</article>';
}

function v6RenderSubviewHtml() {
  if (V6.subtab === 'privacy') {
    return v6RenderPrivacySubviewHtml();
  }
  if (V6.subtab === 'troubleshoot') {
    return '<div class="v6-grid cols-2">' +
      v6RenderScalpelCardHtml() +
      v6RenderBlackboxCardHtml() +
      '</div>' +
      v6RenderVaultCardHtml();
  }
  return '<div class="v6-grid cols-2">' +
    v6RenderExpressCardHtml() +
    v6RenderLeashCardHtml() +
    '</div>' +
    v6RenderThermoCardHtml();
}

/* ═════════════════════ 页面主渲染与无闪烁局部刷新 ═════════════════════ */
function renderVectorPage(anim1) {
  var p = document.getElementById('p-vector');
  if (!p) return;
  if (V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  var html = '<div class="wrap v6-shell">' +
    '<div id="v6-hero-mount">' + v6RenderHeroCardHtml() + '</div>' +
    '<div id="v6-subview-mount" class="v6-shell">' + v6RenderSubviewHtml() + '</div>' +
  '</div>';
  if (!anim1 && p.firstElementChild) morph(p, html);
  else p.innerHTML = html;
  if (anim1 && typeof stagger === 'function') stagger($('.v6-shell', p));
}

function v6RefreshHeroDom() {
  var m = document.getElementById('v6-hero-mount');
  if (!m || S.page !== 'vector') return;
  morph(m, v6RenderHeroCardHtml());
}

function v6RefreshActiveSubviewDom() {
  if (S.page !== 'vector') return;
  var ae = document.activeElement;
  /* 若用户正在输入框内打字，仅刷新流列表内部节点，绝不重复包裹外层容器或打断光标 */
  if (ae && ae.tagName === 'INPUT' && ae.closest('#p-vector')) {
    if (V6.subtab === 'privacy') {
      var st = document.getElementById('lgd-stream-list');
      if (st) morph(st, v6LeakStreamHtml());
    }
    return;
  }
  var sub = document.getElementById('v6-subview-mount');
  if (sub) {
    morph(sub, v6RenderSubviewHtml());
  }
}

function onEnterVectorPage() {
  if (V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  if (V6.apiSupported.lg) v6LoadLeakGuard();
  if (V6.apiSupported.v6) v6LoadCockpitAll();
  if (!KSU) v6StartLeakGuardSSE();
}

function v6FocusPrivacyPanel() {
  V6.subtab = 'privacy';
  LS.set('hnc6.v6_subtab', 'privacy');
  v6MarkLeakGuardSeen();
  if (S.page !== 'vector') {
    go('vector');
  } else {
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
  }
  setTimeout(function () {
    var el = document.getElementById('v6-leakguard-card');
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: motionOn() ? 'smooth' : 'auto', block: 'start' });
  }, 60);
}
var v6ScrollToLeakGuard = v6FocusPrivacyPanel;

/* ═════════════════════ FlowScalpel 活跃连接管理抽屉（全局与单机状态完全隔离） ═════════════════════ */
function v6FilteredScalpelDrawerFlows() {
  var src = (V6.scalpel.scopeMac || V6.scalpel.scopeIp) ? V6.scalpel.drawerFlows : (V6.scalpel.drawerFlows.length ? V6.scalpel.drawerFlows : V6.scalpel.globalFlows);
  var pf = V6.scalpel.protoFilter || 'ALL';
  var q = String(V6.scalpel.q || '').trim().toLowerCase();
  return src.filter(function (f) {
    if (pf === 'TCP' && f.proto !== 'tcp') return false;
    if (pf === 'UDP' && f.proto !== 'udp') return false;
    if (pf === 'FROZEN' && !f.frozen) return false;
    if (!q) return true;
    var hay = (f.devName + ' ' + f.app_name + ' ' + f.dst_host + ' ' + f.src_ip + ':' + f.sport + ' ' + f.dst_ip + ':' + f.dport + ' ' + f.protoBadge).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6ScalpelListHtml() {
  if (V6.scalpel.loading && !V6.scalpel.drawerFlows.length && !V6.scalpel.globalFlows.length) {
    return '<div class="v6-calm-empty">正在读取实时活跃连接…</div>';
  }
  if (V6.scalpel.err) {
    return '<div class="note err">' + escapeHtml(V6.scalpel.err) + '</div>';
  }
  var list = v6FilteredScalpelDrawerFlows();
  if (!list.length) {
    return '<div class="v6-calm-empty">当前筛选范围内没有活跃连接</div>';
  }
  return list.map(function (f) {
    var rxB = bps(f.rx_bps), txB = bps(f.tx_bps);
    var pCls = f.frozen ? 'b-bad' : (f.protoBadge === 'QUIC' ? 'b-pur' : (f.proto === 'udp' ? 'b-acc' : ''));
    var titleMain = f.app_name ? (f.app_name + (f.dst_host ? ' · ' + f.dst_host : '')) : (f.dst_host || (f.dst_ip + ':' + f.dport));
    var remMin = f.frozen ? Math.max(1, Math.ceil((f.frozen_until - Date.now() / 1000) / 60)) : 0;
    return '<div class="v6-tuple-row" data-mkey="sc-' + escapeHtml(f.id) + '">' +
      '<div class="v6-tuple-5">' +
        '<div class="v6-tuple-primary">' +
          '<span class="v6-mono-badge mono ' + pCls + '">' + escapeHtml(f.frozen ? ('封禁剩' + remMin + '分') : f.protoBadge) + '</span>' +
          '<span>' + escapeHtml(titleMain) + '</span>' +
          (!V6.scalpel.scopeMac ? '<span class="v6-mono-badge">' + escapeHtml(f.devName) + '</span>' : '') +
        '</div>' +
        '<div class="ep">' + escapeHtml(f.src_ip + ':' + f.sport + ' -> ' + f.dst_ip + ':' + f.dport) + (f.state && f.state !== 'ESTABLISHED' && f.state !== 'ASSURED' ? (' · ' + escapeHtml(f.state)) : '') + '</div>' +
      '</div>' +
      '<div class="v6-tuple-rate">↓ ' + rxB.v + ' ' + rxB.u + '<br>↑ ' + txB.v + ' ' + txB.u + '</div>' +
      '<div class="v6-tuple-acts">' +
        '<button type="button" class="lgd-act-btn warn press" data-v6-act="scalpel-cut-once" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('cut') + '<span>断开一次</span></button>' +
        '<button type="button" class="lgd-act-btn dan press" data-v6-act="scalpel-cut-freeze" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('freeze') + '<span>断开并封15分钟</span></button>' +
      '</div>' +
    '</div>';
  }).join('');
}

function v6ScalpelDrawerBodyHtml() {
  var sc = V6.scalpel;
  var isScoped = !!(sc.scopeMac || sc.scopeIp);
  var scopeTitle = isScoped ? ('活跃连接 · ' + (sc.devName || sc.scopeIp || sc.scopeMac)) : '全网活跃连接管理';
  var shownCount = v6FilteredScalpelDrawerFlows().length;
  var pTabs = [['ALL', '全部'], ['TCP', 'TCP'], ['UDP', 'UDP / QUIC'], ['FROZEN', '封禁中']];

  return '<div class="v6-drawer-head">' +
      '<div>' +
        '<div class="v6-card-t">' + v6Svg('scalpel') + '<span>' + escapeHtml(scopeTitle) + '</span></div>' +
        '<div class="v6-card-s">「断开一次」立即清理卡死连接；「封15分钟」阻止流氓后台反复重连</div>' +
      '</div>' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="scalpel-close">关闭</button>' +
    '</div>' +
    '<div class="v6-drawer-subbar">' +
      '<div class="lgd-type-chips">' +
        pTabs.map(function (pt) {
          return '<button type="button" class="lgd-tchip' + (sc.protoFilter === pt[0] ? ' on' : '') + '" data-v6-act="scalpel-proto" data-proto="' + pt[0] + '">' + pt[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div style="display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap">' +
        '<span class="v6-mono-badge" id="v6-sc-cnt-pill">共 ' + shownCount + ' 条</span>' +
        (isScoped ? '<button type="button" class="v6-mini-btn pri press" data-v6-act="scalpel-all-scope">看全网</button>' : '') +
        '<button type="button" class="v6-mini-btn' + (sc.paused ? ' warn' : '') + ' press" data-v6-act="scalpel-pause">' + (sc.paused ? '已暂停刷新' : '2秒自动刷新') + '</button>' +
      '</div>' +
    '</div>' +
    '<div class="v6-drawer-tools">' +
      '<label class="lgd-search-mini" style="max-width:none;width:100%">' + ico('search') + '<input id="v6-sc-q" type="search" placeholder="搜索应用名、域名、IP 或端口" value="' + escapeHtml(sc.q) + '" autocomplete="off"></label>' +
    '</div>' +
    '<div class="v6-tuple-list" id="v6-scalpel-list">' + v6ScalpelListHtml() + '</div>';
}

function v6RefreshScalpelDrawerList() {
  var listEl = document.getElementById('v6-scalpel-list');
  if (listEl) morph(listEl, v6ScalpelListHtml());
  var cntEl = document.getElementById('v6-sc-cnt-pill');
  if (cntEl) cntEl.textContent = '共 ' + v6FilteredScalpelDrawerFlows().length + ' 条';
}

function v6FetchScalpelFlows() {
  if (!V6.scalpel.open) return Promise.resolve();
  var isScoped = !!(v6ValidMac(V6.scalpel.scopeMac) || v6ValidIp(V6.scalpel.scopeIp));
  var params = { limit: 200 };
  if (v6ValidMac(V6.scalpel.scopeMac)) params.mac = V6.scalpel.scopeMac;
  if (v6ValidIp(V6.scalpel.scopeIp)) params.ip = V6.scalpel.scopeIp;

  V6.scalpel.loading = true;
  V6.scalpel.err = '';
  return api.get(V6_API.scalpelFlows, params, { timeout: 7000 }).then(function (r) {
    V6.scalpel.loading = false;
    v6ApplyScalpelData(r, isScoped);
    v6RefreshScalpelDrawerList();
    if (!isScoped && S.page === 'vector') {
      v6RefreshHeroDom();
      if (V6.subtab === 'troubleshoot') v6RefreshActiveSubviewDom();
    }
  }).catch(function (e) {
    V6.scalpel.loading = false;
    /* 兼容回退：单机连接表兜底同样仅写入 drawerFlows，绝不覆写 globalTotalFlows */
    if (isScoped && V6.scalpel.scopeMac && S.conn && S.conn[V6.scalpel.scopeMac] && S.conn[V6.scalpel.scopeMac].r) {
      var cr = S.conn[V6.scalpel.scopeMac].r;
      V6.scalpel.drawerFlows = (cr.conns || []).map(function (c, idx) {
        return {
          id: 'fb_' + idx,
          proto: c.proto === 'udp' ? 'udp' : 'tcp',
          protoBadge: c.proto === 'udp' && c.dport === 443 ? 'QUIC' : String(c.proto || 'tcp').toUpperCase(),
          state: String(c.state || 'ESTABLISHED'),
          frozen: false,
          frozen_until: 0,
          mac: V6.scalpel.scopeMac,
          devName: V6.scalpel.devName || V6.scalpel.scopeMac,
          src_ip: V6.scalpel.scopeIp || '',
          sport: num(c.sport, 0),
          dst_ip: String(c.dst || ''),
          dport: num(c.dport, 0),
          dst_host: String(c.name || ''),
          app_name: String(c.app || ''),
          traffic_type: '',
          rx_bps: Math.round(num(c.bps, 0) * 0.7),
          tx_bps: Math.round(num(c.bps, 0) * 0.3),
          bytes: num(c.bytes, 0)
        };
      });
      V6.scalpel.drawerTotal = V6.scalpel.drawerFlows.length;
    } else {
      V6.scalpel.err = errText(e);
    }
    v6RefreshScalpelDrawerList();
  });
}

function openScalpelDrawer(mac, ip, devName) {
  if (typeof closeSheet === 'function' && $('#sheet') && $('#sheet').classList.contains('show')) closeSheet(0);
  V6.scalpel.scopeMac = v6ValidMac(mac) ? String(mac).toLowerCase() : '';
  V6.scalpel.scopeIp = v6ValidIp(ip) ? String(ip).trim() : '';
  if (!V6.scalpel.scopeIp && V6.scalpel.scopeMac) {
    var d0 = devBy(V6.scalpel.scopeMac);
    if (d0 && v6ValidIp(d0.ip)) V6.scalpel.scopeIp = d0.ip;
    if (!devName && d0) devName = d0.name;
  }
  V6.scalpel.devName = devName || '';
  V6.scalpel.protoFilter = 'ALL';
  V6.scalpel.q = '';
  V6.scalpel.paused = false;
  V6.scalpel.drawerFlows = [];
  V6.scalpel.drawerTotal = 0;
  V6.scalpel.open = true;

  var dr = document.getElementById('v6-scalpel-drawer');
  var sc = document.getElementById('v6-scalpel-scrim');
  var bd = document.getElementById('v6-scalpel-body');
  if (!dr || !bd) return;
  dr.hidden = false;
  bd.innerHTML = v6ScalpelDrawerBodyHtml();
  requestAnimationFrame(function () {
    if (sc) sc.classList.add('show');
    dr.classList.add('show');
  });
  try {
    if (window.history && typeof window.history.pushState === 'function' && !(window.history.state && window.history.state.hncScalpel)) {
      window.history.pushState({ hncScalpel: 1 }, '');
      V6.scalpel._pushedHist = true;
    }
  } catch (_) {}

  v6FetchScalpelFlows();
  clearInterval(V6.scalpel.timer);
  V6.scalpel.timer = setInterval(function () {
    if (!V6.scalpel.open || V6.scalpel.paused || document.hidden) return;
    v6FetchScalpelFlows();
  }, 2000);
}

function closeScalpelDrawer(fromPop) {
  if (!V6.scalpel.open) return;
  V6.scalpel.open = false;
  if (!fromPop && V6.scalpel._pushedHist) {
    V6.scalpel._pushedHist = false;
    try { if (window.history && window.history.state && window.history.state.hncScalpel) window.history.back(); } catch (_) {}
  } else {
    V6.scalpel._pushedHist = false;
  }
  V6.scalpel.scopeMac = '';
  V6.scalpel.scopeIp = '';
  V6.scalpel.devName = '';
  V6.scalpel.q = '';
  V6.scalpel.protoFilter = 'ALL';
  V6.scalpel.drawerFlows = [];
  V6.scalpel.drawerTotal = 0;
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

/* ═════════════════════ 写操作 API 封装（严格对齐后端结构体 + 1.5s 乐观锁） ═════════════════════ */
function v6SaveLeakGuardConfig(partial, triggerEl, okMsg) {
  var capEl = document.getElementById('lgd-cap-inp');
  var cdEl = document.getElementById('lgd-cd-inp');
  var capVal = clamp(Math.round(num(partial && partial.capacity != null ? partial.capacity : (capEl ? capEl.value : V6.lg.capacity), 300)), 10, 2000);
  var cdVal = clamp(Math.round(num(partial && partial.cooldown_sec != null ? partial.cooldown_sec : (cdEl ? cdEl.value : V6.lg.cooldown_sec), 300)), 0, 86400);
  var payload = {
    capacity: capVal,
    cooldown_sec: cdVal,
    notify_enabled: partial && typeof partial.notify_enabled === 'boolean' ? partial.notify_enabled : V6.lg.notify_enabled,
    lockscreen_mask: partial && typeof partial.lockscreen_mask === 'boolean' ? partial.lockscreen_mask : V6.lg.lockscreen_mask
  };
  V6.mutUntil.lg = Date.now() + 1500;
  V6.lg.capacity = capVal;
  V6.lg.cooldown_sec = cdVal;
  V6.lg.notify_enabled = payload.notify_enabled;
  V6.lg.lockscreen_mask = payload.lockscreen_mask;
  return busyWhile(triggerEl, api.post(V6_API.lgConfig, payload, { timeout: 8000 })).then(function (r) {
    if (r) v6ApplyLeakGuardData(r, true);
    v6RefreshActiveSubviewDom();
    toast(okMsg || '隐私安检设置已保存');
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    toast(errText(e), 'err');
    v6LoadLeakGuard();
  });
}

function v6ClearLeakGuard(btn) {
  confirmSheet('清空隐私安检记录？', '将清空当前列表中的全部明文传输记录（已手动封禁的追踪域名与 IP 规则会继续保留）。', '清空记录').then(function (ok) {
    if (!ok) return;
    busyWhile(btn, api.post(V6_API.lgClear, {}, { timeout: 8000 })).then(function () {
      V6.lg.events = [];
      V6.lg.hit_ledger = {};
      V6.lg.total_hits = 0;
      V6.lg.affected_devices = 0;
      V6.lg.openIds = {};
      v6MarkLeakGuardSeen();
      v6RefreshHeroDom();
      v6RefreshActiveSubviewDom();
      v6RefreshDevicesBannerDom();
      toast('已清空隐私安检历史记录');
    }).catch(function (e) { toast(errText(e), 'err'); });
  });
}

function v6BlockLeakDomain(evId, btn) {
  var ev = V6.lg.events.filter(function (x) { return x.id === evId; })[0];
  if (!ev) return;
  var wantBlock = !ev.is_blocked;
  var act = wantBlock ? 'block' : 'unblock';
  var primaryHost = String(ev.dst_host && ev.dst_host !== '—' ? ev.dst_host : ev.dst_ip).trim();
  if (!primaryHost) { toast('该记录缺少可封禁的目标域名或公网 IP', 'warn'); return; }
  var macArg = v6ValidMac(ev.mac) ? ev.mac : '';
  var req1 = { action: act, dst_host: primaryHost, mac: macArg };

  busyWhile(btn, api.post(V6_API.lgBlockDomain, req1, { timeout: 9000 }).then(function (r1) {
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
    toast(wantBlock ? ('已封禁追踪域名与 IP：' + primaryHost) : ('已解除封禁：' + primaryHost));
  }).catch(function (e) { toast(errText(e), 'err'); });
}

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
    toast('连接地址信息不完整，请刷新列表后重试', 'warn');
    return;
  }
  var mode = freeze15m ? 'cut_freeze_15m' : 'cut_once';
  var payload = v6BuildScalpelCutPayload(flowObj, mode);
  busyWhile(btn, api.post(V6_API.scalpelCut, payload, { timeout: 8000 })).then(function () {
    toast(freeze15m
      ? ('已断开并封禁 15 分钟：' + (flowObj.dst_host || flowObj.dst_ip))
      : ('已断开连接：' + (flowObj.dst_host || payload.dst_ip) + ':' + payload.dport));
    if (V6.scalpel.open) v6FetchScalpelFlows();
    if (S.page === 'vector') v6LoadCockpitAll();
  }).catch(function (e) { toast(errText(e), 'err'); });
}

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
    if (!matched.length) return { cutN: 0 };
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
      toast('已断开 ' + res.cutN + ' 条相关连接：' + (ev.dst_host || ev.dst_ip));
    } else {
      openScalpelDrawer(ev.mac, ev.src_ip, ev.devName);
      toast('该短连接已自然结束，已打开此设备的活跃连接列表', 'warn');
    }
  }).catch(function (e) { toast(errText(e), 'err'); });
}

function v6PostExpress(payload, el, msg) {
  V6.mutUntil.express = Date.now() + 1500;
  return busyWhile(el, api.post(V6_API.express, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyExpressData(r || payload, true);
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (msg) toast(msg);
  }).catch(function (e) {
    V6.mutUntil.express = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

function v6PostLeash(payload, el, msg) {
  V6.mutUntil.leash = Date.now() + 1500;
  return busyWhile(el, api.post(V6_API.updateLeash, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyLeashData(r || payload, true);
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (msg) toast(msg);
  }).catch(function (e) {
    V6.mutUntil.leash = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

function v6PostThermo(payload, el, msg) {
  V6.mutUntil.thermo = Date.now() + 1500;
  if (payload && payload.low_bat_pct == null) payload.low_bat_pct = V6.thermo.low_bat_pct;
  return busyWhile(el, api.post(V6_API.thermo, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyThermoData(r || payload, true);
    v6PaintHeaderBadges();
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (msg) toast(msg);
  }).catch(function (e) {
    V6.mutUntil.thermo = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

/* 备份文件导出（同时兼容普通浏览器下载与 Android KSU WebView 落盘 /sdcard/Download） */
function v6ExportBackupBundle(actEl) {
  busyWhile(actEl, api.get(V6_API.backup, null, { timeout: 10000 })).then(function (bundle) {
    if (!bundle || typeof bundle !== 'object') { toast('导出数据为空', 'err'); return; }
    V6.vault.last_sha256 = String(bundle.sha256 || '');
    V6.vault.last_file_count = Math.round(num(bundle.file_count, 0));
    v6RefreshActiveSubviewDom();
    var jsonStr = JSON.stringify(bundle, null, 2);
    var fname = 'hnc-backup-' + (bundle.module_version || 'v6.0.1') + '-' + Date.now() + '.json';
    if (typeof KSU !== 'undefined' && KSU && typeof shell === 'function') {
      var outPath = '/sdcard/Download/' + fname;
      var b64 = btoa(unescape(encodeURIComponent(jsonStr)));
      shell("mkdir -p /sdcard/Download && printf '%s' " + sq(b64) + " | base64 -d > " + sq(outPath)).then(function (res) {
        if (res && res.code === 0) toast('已保存到手机下载目录：' + fname);
        else if (typeof copyText === 'function') {
          copyText(jsonStr).then(function (ok) { toast(ok ? '备份内容已复制到剪贴板' : '保存失败', ok ? 'ok' : 'err'); });
        }
      });
      return;
    }
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
      toast('配置备份已导出（共 ' + V6.vault.last_file_count + ' 项）');
    } catch (_) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(jsonStr);
        toast('配置备份已复制到剪贴板');
      }
    }
  }).catch(function (e) { toast(errText(e), 'err'); });
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

  /* 记录 <details class="v6-adv-fold"> 展开态，保证后台轮询 morph 时不会自动合上用户展开的高级设置 */
  document.addEventListener('toggle', function (e) {
    var dt = e.target;
    if (dt && dt.matches && dt.matches('details[data-v6-fold]')) {
      var fk = dt.getAttribute('data-v6-fold');
      if (fk) V6.advOpen[fk] = !!dt.open;
    }
  }, true);

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
          toast('所选文件不是有效的备份文件', 'err');
          return;
        }
        confirmSheet('确认恢复整机配置？', '将校验完整性摘要并恢复全部设备备注、限速规则与智能护航参数（当前登录状态不受影响）。', '立即恢复').then(function (ok) {
          if (!ok) return;
          api.post(V6_API.backup, parsed, { timeout: 12000 }).then(function (res) {
            V6.vault.last_restored = Math.round(num(res && res.restored_count, 0));
            if (res && res.sha256) V6.vault.last_sha256 = String(res.sha256);
            v6LoadCockpitAll();
            toast('已成功恢复 ' + V6.vault.last_restored + ' 项配置');
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
      V6.lg.visibleLimit = 30;
      var st = document.getElementById('lgd-stream-list');
      if (st) morph(st, v6LeakStreamHtml());
    } else if (t.id === 'v6-sc-q') {
      V6.scalpel.q = t.value;
      v6RefreshScalpelDrawerList();
    }
  });

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || typeof t.closest !== 'function') return;

    /* 1. 顶部三大场景切换胶囊 */
    var subBtn = t.closest('[data-v6-subtab]');
    if (subBtn) {
      e.stopPropagation();
      var nextSub = subBtn.getAttribute('data-v6-subtab') || 'escort';
      if (typeof haptic === 'function') haptic(8);
      V6.subtab = nextSub;
      LS.set('hnc6.v6_subtab', nextSub);
      if (nextSub === 'privacy') v6MarkLeakGuardSeen();
      v6RefreshHeroDom();
      v6RefreshActiveSubviewDom();
      return;
    }

    /* 2A. 顶部 3 格磁贴右上角胶囊：独立一键开关（防误触） */
    var bentoBtn = t.closest('[data-v6-bento]');
    if (bentoBtn) {
      e.stopPropagation();
      if (bentoBtn.classList.contains('busy')) return;
      if (typeof haptic === 'function') haptic(10);
      var bKind = bentoBtn.getAttribute('data-v6-bento');
      if (bKind === 'express') {
        var nextExp = !V6.express.enabled;
        V6.express.enabled = nextExp;
        v6RefreshHeroDom();
        v6PostExpress({ enabled: nextExp, auto_detect: V6.express.auto_detect, forced_macs: V6.express.forced_macs }, bentoBtn, nextExp ? '已开启游戏与通话优先' : '已关闭游戏与通话优先');
      } else if (bKind === 'leash') {
        var nextUl = !V6.leash.enabled;
        V6.leash.enabled = nextUl;
        v6RefreshHeroDom();
        v6PostLeash({ action: 'config', enabled: nextUl, grace_mb: V6.leash.grace_mb, leash_kbps: V6.leash.leash_kbps }, bentoBtn, nextUl ? '已开启后台大更新限速' : '已关闭后台大更新限速');
      } else if (bKind === 'thermo') {
        var nextTh = !V6.thermo.enabled;
        V6.thermo.enabled = nextTh;
        v6RefreshHeroDom();
        v6PostThermo({ enabled: nextTh, stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled, stage1_temp_c: V6.thermo.stage1_temp_c, stage2_temp_c: V6.thermo.stage2_temp_c, low_bat_pct: V6.thermo.low_bat_pct }, bentoBtn, nextTh ? '已开启发热与省电保护' : '已关闭发热与省电保护');
      }
      return;
    }

    /* 2B. 顶部 3 格磁贴主体点按：平滑定位至对应设置卡片（不误关保护开关） */
    var bentoNav = t.closest('[data-v6-bento-nav]');
    if (bentoNav) {
      e.stopPropagation();
      if (typeof haptic === 'function') haptic(6);
      var navKind = bentoNav.getAttribute('data-v6-bento-nav');
      if (V6.subtab !== 'escort') {
        V6.subtab = 'escort';
        LS.set('hnc6.v6_subtab', 'escort');
        v6RefreshHeroDom();
        v6RefreshActiveSubviewDom();
      }
      var cardId = navKind === 'leash' ? 'v6-card-leash' : (navKind === 'thermo' ? 'v6-card-thermo' : 'v6-card-express');
      setTimeout(function () {
        var targetCard = document.getElementById(cardId);
        if (targetCard && targetCard.scrollIntoView) {
          targetCard.scrollIntoView({ behavior: motionOn() ? 'smooth' : 'auto', block: 'center' });
        }
      }, 40);
      return;
    }

    /* 3. 卡片内圆形拨动开关 */
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
        v6SaveLeakGuardConfig({ notify_enabled: nextOn }, vTog, nextOn ? '已开启手机状态栏提醒' : '已关闭手机状态栏提醒');
      } else if (kind === 'lgd-mask') {
        v6SaveLeakGuardConfig({ lockscreen_mask: nextOn }, vTog, nextOn ? '已开启锁屏敏感位隐藏' : '已关闭锁屏敏感位隐藏');
      } else if (kind === 'express') {
        V6.express.enabled = nextOn;
        v6RefreshHeroDom();
        v6PostExpress({ enabled: nextOn, auto_detect: V6.express.auto_detect, forced_macs: V6.express.forced_macs }, vTog, nextOn ? '游戏与通话优先已开启' : '游戏与通话优先已关闭');
      } else if (kind === 'express-auto') {
        V6.express.auto_detect = nextOn;
        v6PostExpress({ enabled: V6.express.enabled, auto_detect: nextOn, forced_macs: V6.express.forced_macs }, vTog, nextOn ? '已开启自动识别游戏与通话' : '已切换为仅手动指定设备优先');
      } else if (kind === 'leash') {
        V6.leash.enabled = nextOn;
        v6RefreshHeroDom();
        v6PostLeash({ action: 'config', enabled: nextOn, grace_mb: V6.leash.grace_mb, leash_kbps: V6.leash.leash_kbps }, vTog, nextOn ? '后台大更新限速已开启' : '后台大更新限速已关闭');
      } else if (kind === 'thermo') {
        V6.thermo.enabled = nextOn;
        v6RefreshHeroDom();
        v6PostThermo({ enabled: nextOn, stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled, stage1_temp_c: V6.thermo.stage1_temp_c, stage2_temp_c: V6.thermo.stage2_temp_c, low_bat_pct: V6.thermo.low_bat_pct }, vTog, nextOn ? '发热与省电保护已开启' : '发热与省电保护已关闭');
      } else if (kind === 'thermo-shaper') {
        V6.thermo.stage2_shaper_enabled = nextOn;
        v6PostThermo({ enabled: V6.thermo.enabled, stage2_shaper_enabled: nextOn, stage1_temp_c: V6.thermo.stage1_temp_c, stage2_temp_c: V6.thermo.stage2_temp_c, low_bat_pct: V6.thermo.low_bat_pct }, vTog, nextOn ? '已开启严重过热自动收紧后台网速' : '已关闭过热限速降温');
      }
      return;
    }

    /* 4. 按钮动作分发 */
    var actEl = t.closest('[data-v6-act]');
    if (!actEl) return;
    var act = actEl.getAttribute('data-v6-act');
    e.stopPropagation();

    switch (act) {
      case 'go-vector':
        if (typeof go === 'function') go('vector');
        break;
      case 'go-privacy':
        v6FocusPrivacyPanel();
        break;
      case 'toggle-health':
        V6.healthOpen = !V6.healthOpen;
        var hd = document.getElementById('v6-health-drawer');
        if (hd) hd.hidden = !V6.healthOpen;
        break;
      case 'open-scalpel':
        openScalpelDrawer(actEl.getAttribute('data-mac') || '', actEl.getAttribute('data-ip') || '', actEl.getAttribute('data-name') || '');
        break;
      case 'scalpel-close':
        closeScalpelDrawer();
        break;
      case 'scalpel-all-scope':
        V6.scalpel.scopeMac = '';
        V6.scalpel.scopeIp = '';
        V6.scalpel.devName = '';
        var bd0 = document.getElementById('v6-scalpel-body');
        if (bd0) bd0.innerHTML = v6ScalpelDrawerBodyHtml();
        v6FetchScalpelFlows();
        break;
      case 'scalpel-pause':
        V6.scalpel.paused = !V6.scalpel.paused;
        actEl.textContent = V6.scalpel.paused ? '已暂停刷新' : '2秒自动刷新';
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
        var pool = (V6.scalpel.scopeMac || V6.scalpel.scopeIp) ? V6.scalpel.drawerFlows : (V6.scalpel.drawerFlows.length ? V6.scalpel.drawerFlows : V6.scalpel.globalFlows);
        var fl = pool.filter(function (x) { return x.id === fid; })[0];
        v6CutFlow(fl, act === 'scalpel-cut-freeze', actEl);
        break;
      case 'lgd-refresh':
        busyWhile(actEl, v6LoadLeakGuard()).then(function () { toast('隐私安检列表已刷新'); });
        break;
      case 'lgd-clear':
        v6ClearLeakGuard(actEl);
        break;
      case 'lgd-save-cfg':
        v6SaveLeakGuardConfig(null, actEl, '通知提醒与保留设置已保存');
        break;
      case 'lgd-filter':
        V6.lg.typeFilter = actEl.getAttribute('data-type') || 'ALL';
        V6.lg.visibleLimit = 30;
        $$('#v6-leakguard-card [data-v6-act="lgd-filter"]').forEach(function (b) { b.classList.toggle('on', b === actEl); });
        var stL = document.getElementById('lgd-stream-list');
        if (stL) morph(stL, v6LeakStreamHtml());
        break;
      case 'lgd-show-more':
        V6.lg.visibleLimit = Math.max(30, num(V6.lg.visibleLimit, 30)) + 50;
        var stMore = document.getElementById('lgd-stream-list');
        if (stMore) morph(stMore, v6LeakStreamHtml());
        break;
      case 'lgd-copy-raw':
        var cpId = actEl.getAttribute('data-id');
        var cpEv = V6.lg.events.filter(function (x) { return x.id === cpId; })[0];
        if (cpEv && cpEv.raw_value) {
          if (typeof copyText === 'function') {
            copyText(cpEv.raw_value).then(function (ok) {
              toast(ok ? '已复制完整明文内容' : '复制失败', ok ? 'ok' : 'err');
            });
          } else if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(cpEv.raw_value).then(function () { toast('已复制完整明文内容'); }).catch(function () {});
          }
        }
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
          if (fr) {
            if (openNow && !fr.innerHTML) {
              var evFound = V6.lg.events.filter(function (x) { return x.id === eid; })[0];
              if (evFound) fr.innerHTML = v6RenderLeakForensicInnerHtml(evFound);
            }
            fr.hidden = !openNow;
          }
          var tb = itemEl.querySelector('[data-v6-act="lgd-toggle-btn"]');
          if (tb) tb.textContent = openNow ? '收起原文' : '查看原文';
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
        }, actEl, pos < 0 ? '已将该设备设为常驻优先' : '已取消该设备的常驻优先');
        break;
      case 'leash-preset-grace':
        var pMb = clamp(Math.round(num(actEl.getAttribute('data-mb'), 200)), 10, 10240);
        var gInp = document.getElementById('v6-ul-grace');
        if (gInp) gInp.value = String(pMb);
        V6.leash.grace_mb = pMb;
        v6PostLeash({
          action: 'config',
          enabled: V6.leash.enabled,
          grace_mb: pMb,
          leash_kbps: V6.leash.leash_kbps
        }, actEl, '免限速高速额度已设为 ' + (pMb >= 1024 ? '1 GB' : (pMb + ' MB')));
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
        }, actEl, '已保存：前 ' + gm + ' MB 全速，超额限速 ' + trim0((kb / 1000).toFixed(1)) + ' Mbps');
        break;
      case 'leash-release':
        var rMac = actEl.getAttribute('data-mac') || '';
        v6PostLeash({
          action: 'bypass_once',
          session_key: actEl.getAttribute('data-skey') || '',
          mac: v6ValidMac(rMac) ? rMac : '',
          dst_host: actEl.getAttribute('data-host') || ''
        }, actEl, '已对该下载执行本次全速放行');
        break;
      case 'leash-pause-toggle':
        var isPaused = actEl.getAttribute('data-paused') === '1';
        var pMac = actEl.getAttribute('data-mac') || '';
        v6PostLeash({
          action: isPaused ? 'resume_update' : 'pause_update',
          session_key: actEl.getAttribute('data-skey') || '',
          mac: v6ValidMac(pMac) ? pMac : '',
          dst_host: actEl.getAttribute('data-host') || ''
        }, actEl, isPaused ? '已继续下载该更新' : '已暂停该后台更新');
        break;
      case 'thermo-save':
        var t1 = clamp(Math.round(num(($('#v6-th-t1') || {}).value, 42)), 30, 70);
        var t2 = clamp(Math.round(num(($('#v6-th-t2') || {}).value, 45)), 32, 75);
        if (t2 < t1) {
          toast('二级降温温度不能低于一级省电温度', 'warn');
          break;
        }
        V6.thermo.stage1_temp_c = t1;
        V6.thermo.stage2_temp_c = t2;
        v6PostThermo({
          enabled: V6.thermo.enabled,
          stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled,
          stage1_temp_c: t1,
          stage2_temp_c: t2,
          low_bat_pct: V6.thermo.low_bat_pct
        }, actEl, '温控触发温度已保存：' + t1 + '°C / ' + t2 + '°C');
        break;
      case 'bb-sample':
        busyWhile(actEl, api.post(V6_API.blackbox, { action: 'sample_now' }, { timeout: 6000 })).then(function () {
          return api.get(V6_API.blackbox, { limit: 12, incidents_only: '1' }, { timeout: 6000 });
        }).then(function (r) {
          v6ApplyBlackboxData(r);
          v6RefreshActiveSubviewDom();
          toast('已完成网络延迟波动即时检测');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'bb-clear':
        busyWhile(actEl, api.post(V6_API.blackbox, { action: 'clear' }, { timeout: 6000 })).then(function () {
          V6.blackbox.incidents = [];
          V6.blackbox.incident_count = 0;
          v6RefreshActiveSubviewDom();
          toast('已清空卡顿事件记录');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'subtrees-sync':
        busyWhile(actEl, api.post(V6_API.nativeSubtrees, { action: 'full_restore' }, { timeout: 8000 })).then(function (r) {
          if (r && r.dynamic_qos) {
            v6ApplyScreenshotPackSummary({ native_subtrees: r });
          }
          v6RefreshActiveSubviewDom();
          toast('底层分流规则已重新同步');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'backup-export':
        v6ExportBackupBundle(actEl);
        break;
      case 'backup-import-pick':
        var fin = document.getElementById('v6-backup-file');
        if (!fin) {
          fin = document.createElement('input');
          fin.id = 'v6-backup-file';
          fin.type = 'file';
          fin.accept = '.json,application/json';
          fin.hidden = true;
          document.body.appendChild(fin);
        }
        fin.click();
        break;
    }
  }, true);
}

/* 启动与轮询协同 */
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
    focusPrivacy: v6FocusPrivacyPanel,
    ingestSync: v6IngestVectorSync,
    renderVectorPage: renderVectorPage
  };
}
