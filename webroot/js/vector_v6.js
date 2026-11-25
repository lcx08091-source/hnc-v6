/* HNC WebUI · vector_v6.js —— HNC v6.1.0-rc.7 · 智能护航、本机守护、隐私安检与连接排障中心
 * 设计准则:
 *   1. 全站原语彻底收口: 统一复用 .hero.v6-hero、.cc-bento-row/.cc-tile、seg() 弹簧胶囊与 .sgrp.scard.glass.open 标准卡片，零孤岛私有大卡。
 *   2. 诚实三态与正交双连接: 严格区分热点待机/热点就绪无设备/热点活跃三态；热点连接数与本机连接数正交独立展示与检索。
 *   3. 本机守护全功能工作台: 完整对接 /api/local_apps/traffic、power、privacy_audit、firewall 与 self_firewall_* / self_dns_* 动作，严守零唤醒租约纪律。
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
  lgWhitelist: '/api/leakguard/whitelist',
  lgUndoBlock: '/api/leakguard/undo-block',
  express: '/api/v6/express',
  updateLeash: '/api/v6/update_leash',
  thermo: '/api/v6/thermo',
  scalpelFlows: '/api/v6/scalpel/flows',
  scalpelCut: '/api/v6/scalpel/cut',
  blackbox: '/api/v6/blackbox',
  multiIface: '/api/v6/multi_iface',
  nativeSubtrees: '/api/v6/native_subtrees',
  backup: '/api/backup',
  localTraffic: '/api/local_apps/traffic',
  localPower: '/api/local_apps/power',
  localPrivacy: '/api/local_apps/privacy_audit',
  localFirewall: '/api/local_apps/firewall',
  selfToggle: '/api/self/toggle'
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
  if (s.charAt(0) === '[' && s.charAt(s.length - 1) === ']') s = s.slice(1, -1);
  if (!s || s === '-' || s === '—') return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    return s.split('.').every(function (p) { var n = parseInt(p, 10); return n >= 0 && n <= 255; });
  }
  return s.indexOf(':') >= 0 && /^[0-9a-fA-F:.]+$/.test(s);
}

/* 提取纯 IPv4/IPv6 字面量（支持 [ipv6]:port / ipv4:port），若是域名或空则返回 '' */
function v6ExtractPureIp(hostRaw) {
  var s = String(hostRaw || '').trim();
  if (!s || s === '-' || s === '—') return '';
  if (s.charAt(0) === '[') {
    var rb = s.indexOf(']');
    if (rb > 1) {
      var inner6 = s.slice(1, rb);
      var rest6 = s.slice(rb + 1);
      if ((!rest6 || /^:\d{1,5}$/.test(rest6)) && v6ValidIp(inner6)) return inner6;
    }
    return '';
  }
  if (v6ValidIp(s)) return s;
  var m4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(s);
  if (m4 && v6ValidIp(m4[1])) return m4[1];
  return '';
}

/* 识别回环、私网、链路本地、CGNAT 及代理 Fake-IP (198.18.0.0/15, fc00::/7) */
function v6IsFakeOrPrivateIp(ipRaw) {
  var s = v6ExtractPureIp(ipRaw) || String(ipRaw || '').trim().replace(/^\[|\]$/g, '');
  s = s.toLowerCase();
  if (!v6ValidIp(s)) return false;
  if (s.indexOf('::ffff:') === 0) s = s.slice(7);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    var p = s.split('.').map(function (x) { return parseInt(x, 10); });
    if (p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    return false;
  }
  if (s === '::' || s === '::1') return true;
  if (/^(fc|fd)[0-9a-f]{0,2}:/.test(s)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(s)) return true;
  if (/^ff[0-9a-f]{0,2}:/.test(s)) return true;
  return false;
}

/* 统一格式化 host/IP 与端口，IPv6 自动包裹方括号为 [ipv6]:port */
function v6FmtHostPort(hostOrIp, port) {
  var h = String(hostOrIp == null ? '' : hostOrIp).trim();
  if (!h || h === '—') return port ? ('—:' + port) : '—';
  var hasBracket = h.charAt(0) === '[' && h.indexOf(']') > 0;
  var isV6 = !hasBracket && h.indexOf(':') >= 0;
  if (port != null && port !== '' && Number(port) > 0) {
    return (isV6 ? ('[' + h + ']') : h) + ':' + port;
  }
  return h;
}

/* 过滤后端占位的 uid: / isolated: 伪包名，防止传给防火墙校验报错或重复展示 */
function v6CleanHostRealPkg(pkg) {
  var s = String(pkg || '').trim();
  if (!s || /^(uid|isolated):/i.test(s)) return '';
  return s;
}

/* 本机事件应用名兜底：uid <= 0 统一展示为「本机未知连接」，杜绝刺眼的 UID 0 */
function v6HostEventAppLabel(appName, pkg, uid) {
  var nm = String(appName || '').trim();
  if (nm && !/^uid\s*[:#-]?\s*0$/i.test(nm) && !/^(uid|isolated):/i.test(nm)) return nm;
  var cp = v6CleanHostRealPkg(pkg);
  if (cp) return cp;
  var u = Math.round(num(uid, 0));
  return u > 0 ? ('UID ' + u) : '本机未知连接';
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
  subtab: LS.get('hnc6.v6_subtab', 'escort'), // 'escort' | 'host' | 'privacy' | 'troubleshoot'
  healthOpen: false,
  advOpen: { exp: false, leash: false, thermo: false, lgCfg: false, lgGuard: false, bbNet: false },
  mutUntil: { lg: 0, express: 0, leash: 0, thermo: 0, hostFw: 0, selfCap: 0 },
  loaded: false,
  apiSupported: { lg: true, v6: true },
  lg: {
    total_hits: 0,
    host_hits: 0,
    hotspot_hits: 0,
    hotspot_affected_devices: 0,
    affected_apps: 0,
    affected_devices: 0,
    hotspot_blocked_domains: 0,
    self_blocked_domains: 0,
    blocked_domains: 0,
    blocked_set: {},
    hit_ledger: {},
    notify_enabled: true,
    lockscreen_mask: true,
    capacity: 300,
    cooldown_sec: 300,
    whitelist: [],
    whitelist_count: 0,
    undo_stack: [],
    undo_count: 0,
    events: [],
    openIds: {},
    visibleLimit: 30,
    originFilter: 'ALL', // 'ALL' | 'host' | 'hotspot'
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
    qdisc: 'fq_codel',
    tier: ''
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
    battery_temp_c: 0,
    shell_temp_c: 0,
    shell_temp_available: false,
    shell_zone: '',
    battery_spoof_suspected: false,
    capacity_pct: 0,
    bat_available: null,
    sensor_checked: false,
    reason_code: '',
    reason_zh: '',
    bat_status: '',
    is_charging: false,
    vector_express_active: false,
    stage2_exempt: false,
    exempt_reason: '',
    low_battery_cruise: false,
    cool_hold_remaining_sec: 0,
    raw_stage: 0,
    stage: 0,
    stage_label: '待读取'
  },
  scalpel: {
    open: false,
    scopeDomain: 'all', // 'all' | 'hotspot' | 'host'
    scopeMac: '',
    scopeIp: '',
    devName: '',
    protoFilter: 'ALL',
    q: '',
    paused: false,
    loading: false,
    readable: true,
    hotspotFlows: 0,
    hostFlows: 0,
    hasSplitCounts: false,
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
  host: {
    mode: LS.get('hnc6.v6_host_mode', 'live'), // 'live' | 'traffic' | 'power' | 'firewall'
    includeSystem: LS.get('hnc6.v6_host_sys', '0') === '1',
    q: '',
    period: LS.get('hnc6.v6_host_period', 'today'), // 'boot' | 'today' | '7d' | '30d'
    net: LS.get('hnc6.v6_host_net', 'all'), // 'all' | 'mobile' | 'wifi'
    powerSort: LS.get('hnc6.v6_host_psort', 'bg_mah'), // 'bg_mah' | 'screen_off_mah' | 'wakelock_ms' | 'radio_ms' | 'cpu_bg_ms'
    pollTimer: 0,
    trafficLoading: false,
    powerLoading: false,
    privacyLoading: false,
    fwLoading: false,
    trafficLoadedAt: 0,
    powerLoadedAt: 0,
    privacyLoadedAt: 0,
    fwLoadedAt: 0,
    trafficErr: '',
    powerErr: '',
    privacyErr: '',
    traffic: {
      available: true,
      reason: '',
      rate_warming_up: false,
      bg_split_available: true,
      summary: {
        total_rx_bps: 0,
        total_tx_bps: 0,
        total_bps: 0,
        total_bytes: 0,
        bg_total_bytes: 0,
        fg_total_bytes: 0,
        bg_ratio_pct: 0,
        app_count: 0,
        active_conn_apps: 0
      },
      apps: []
    },
    power: {
      available: true,
      reason: '',
      cached: false,
      refresh_throttled: false,
      bg_mah_available: false,
      bg_mah_reason: '',
      screen_off_mah_available: false,
      device_summary: {
        battery_capacity_mah: 0,
        computed_drain_mah: 0,
        actual_discharge_mah: 0,
        screen_off_discharge_mah: 0,
        time_on_battery_ms: 0,
        screen_off_on_battery_ms: 0
      },
      apps: []
    },
    privacy: {
      available: true,
      reason: '',
      self_capture_enabled: false,
      self_capture_mode: '',
      summary: {
        cleartext_http_conns: 0,
        direct_dns_conns: 0,
        tracker_sdk_conns: 0,
        bg_active_conns: 0,
        risky_apps_count: 0
      },
      findings: []
    },
    firewall: {
      updated_at: 0,
      uid_rules: [],
      uid_map: {},
      blocked_domains: [],
      blocked_set: {},
      protected_packages: [
        'com.agy',
        'com.android.webview',
        'com.google.android.webview',
        'com.rifsxd.ksunext',
        'com.sukisu.ultra',
        'com.topjohnwu.magisk',
        'io.github.vvb2060.magisk',
        'me.bmax.apatch',
        'me.weishu.kernelsu'
      ],
      uid_rule_count: 0,
      blocked_domain_count: 0
    },
    appSheet: {
      open: false,
      uid: -1,
      pkg: '',
      appName: '',
      isSystem: false,
      flows: [],
      loading: false,
      err: '',
      timer: 0
    }
  },
  blackbox: {
    granularity_ms: 200,
    total_ticks: 0,
    incident_count: 0,
    latest_jitter_ms: 0,
    latest_rtt_ms: 0,
    rtt_probe_active: null,
    incidents: []
  },
  arbiter: {
    active: false,
    source: '',
    reason: '',
    down_mbps: 0,
    up_mbps: 0,
    sources: []
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
  _committed: {
    express: { enabled: true, auto_detect: true, forced_macs: [] },
    leash: { enabled: true, grace_mb: 200, leash_kbps: 1500 },
    thermo: { enabled: true, stage2_shaper_enabled: true, stage1_temp_c: 42, stage2_temp_c: 45, low_bat_pct: 20 }
  },
  sse: null,
  sseRetryT: 0
};
V6.appSheet = V6.host.appSheet;
if (['escort', 'host', 'privacy', 'troubleshoot'].indexOf(V6.subtab) < 0) V6.subtab = 'escort';
if (['live', 'traffic', 'power', 'firewall'].indexOf(V6.host.mode) < 0) V6.host.mode = 'live';
if (['boot', 'today', '7d', '30d'].indexOf(V6.host.period) < 0) V6.host.period = 'today';
if (['all', 'mobile', 'wifi'].indexOf(V6.host.net) < 0) V6.host.net = 'all';
if (['bg_mah', 'screen_off_mah', 'wakelock_ms', 'radio_ms', 'cpu_bg_ms'].indexOf(V6.host.powerSort) < 0) V6.host.powerSort = 'bg_mah';

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
  if (/CREDENTIAL/.test(u)) return '账号凭据';
  if (/GPS|LOC|LAT|LON/.test(u)) return '精准定位';
  if (/WIFI_BSSID|BSSID/.test(u)) return '周边Wi-Fi定位';
  if (/MAC/.test(u)) return '网卡地址';
  if (/TOKEN|BEARER|COOKIE|AUTH|PASS|KEY/.test(u)) return '登录凭据';
  if (/IMEI|IMSI|OAID|IDFA|ANDROID_ID|DEVICE|SERIAL/.test(u)) return '设备指纹';
  return '敏感明文';
}

function leakTypeBadgeCls(tp) {
  var u = leakTypeBadgeCode(tp);
  if (/PHONE|ID_CARD|IDCARD|CREDENTIAL|AUTH|TOKEN|COOKIE|PASS|GPS|LOC|IMEI|IMSI/.test(u)) return 'b-bad';
  if (/DEVICE_ID|OAID|ANDROID_ID|IDFA|MAC|BSSID|SERIAL/.test(u)) return 'b-warn';
  return 'b-acc';
}

function leakTypeGroup(tp) {
  var u = leakTypeBadgeCode(tp);
  if (/PHONE|EMAIL|ID_CARD|IDCARD/.test(u)) return 'PHONE';
  if (/GPS|LOC|LAT|LON|WIFI_BSSID|BSSID/.test(u)) return 'GPS';
  if (/MAC/.test(u)) return 'MAC_ADDR';
  if (/CREDENTIAL|TOKEN|AUTH|COOKIE|KEY|PASS/.test(u)) return 'TOKEN';
  if (/IMEI|IMSI|OAID|IDFA|ANDROID_ID|DEVICE/.test(u)) return 'DEVICE_ID';
  return 'OTHER';
}

function leakHitKey(origin, uid, mac, srcIp, dstHost, lType, rawVal) {
  var who = origin === 'host' ? ('uid:' + (uid || 0)) : (mac || srcIp || '-');
  return who + '|' + String(dstHost || '').toLowerCase() + '|' + lType + '|' + rawVal;
}

/* ── 三级公共基础设施域名守卫识别与归一化 ── */
var V6_HARD_PROTECTED_HOSTS = [
  'connectivitycheck.gstatic.com', 'clients3.google.com', 'captive.apple.com',
  'www.msftconnecttest.com', 'msftconnecttest.com', 'dns.msftncsi.com',
  'connect.rom.miui.com', 'connectivitycheck.platform.hicloud.com',
  'wifi.vivo.com.cn', 'conn1.oppomobile.com', 'time.android.com', 'time.apple.com'
];

function v6NormInfraGuard(rawGuard, fallbackLevel, fallbackLabel, dstHost) {
  var lvl = '', lbl = '';
  if (rawGuard && typeof rawGuard === 'object') {
    lvl = String(rawGuard.level || rawGuard.guard_level || '').toLowerCase().trim();
    lbl = String(rawGuard.label || rawGuard.provider || rawGuard.reason_zh || rawGuard.reason || '').trim();
  } else if (typeof rawGuard === 'string' && rawGuard.trim()) {
    lvl = rawGuard.toLowerCase().trim();
  }
  if (!lvl && fallbackLevel) lvl = String(fallbackLevel).toLowerCase().trim();
  if (!lbl && fallbackLabel) lbl = String(fallbackLabel).trim();

  var h = String(dstHost || '').toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!lvl && h && !v6ValidIp(h)) {
    for (var i = 0; i < V6_HARD_PROTECTED_HOSTS.length; i++) {
      var ph = V6_HARD_PROTECTED_HOSTS[i];
      if (h === ph || h.slice(-(ph.length + 1)) === '.' + ph) {
        lvl = 'hard_block';
        lbl = lbl || '系统联网探测核心域';
        break;
      }
    }
    if (!lvl && typeof classifyInfraHost === 'function') {
      var inf = classifyInfraHost(h);
      if (inf && inf.shared && (inf.kind === 'cdn' || inf.kind === 'cloud')) {
        lvl = 'warn_confirm';
        lbl = lbl || inf.label || '共享云底座 CDN';
      }
    }
  }
  if (lvl === 'hard' || lvl === 'forbid' || lvl === 'protected') lvl = 'hard_block';
  else if (lvl === 'warn' || lvl === 'confirm' || lvl === 'shared_cdn') lvl = 'warn_confirm';
  if (lvl !== 'hard_block' && lvl !== 'warn_confirm') return null;
  return {
    level: lvl,
    label: lbl || (lvl === 'hard_block' ? '系统核心公共域' : '共享公共底座')
  };
}

function v6NormWhitelistItem(it, idx) {
  if (typeof it === 'string') {
    var sh = it.trim().toLowerCase();
    return sh ? { id: sh, scope: 'host', dst_host: sh, leak_type: '', mac: '', uid: 0, pkg: '', app_name: '', device_name: '', note: '', label: '' } : null;
  }
  if (!it || typeof it !== 'object') return null;
  var host = String(it.dst_host || it.domain || it.host || it.value || '').trim().toLowerCase();
  var lTypeRaw = String(it.leak_type || it.type || '').trim();
  var lType = (!lTypeRaw || lTypeRaw === '*' || lTypeRaw.toUpperCase() === 'ALL') ? '' : leakTypeBadgeCode(lTypeRaw);
  var mac = String(it.mac || it.client_mac || '').trim().toLowerCase();
  var uid = it.uid != null ? Math.round(num(it.uid, 0)) : 0;
  var pkg = v6CleanHostRealPkg(it.pkg || it.package || '').toLowerCase();
  var appName = String(it.app_name || '').trim();
  var defaultScope = mac && host ? 'device_host_type' : ((uid > 0 || pkg) && host ? 'app_host_type' : (lType ? 'host_type' : 'host'));
  var scope = String(it.scope || it.kind || defaultScope).toLowerCase();
  if (scope === 'device_host') scope = 'device_host_type';
  if (scope === 'app_host') scope = 'app_host_type';
  var d = mac ? devBy(mac) : null;
  var noteTxt = String(it.note != null ? it.note : (it.label || ''));
  var comboKey = scope + '|' + host + '|' + lType + '|' + mac + '|' + (uid > 0 ? uid : '') + '|' + pkg;
  var id = String(it.id || it.rule_id || it.key || (comboKey + '|' + (idx || 0)));
  return {
    id: id,
    comboKey: comboKey,
    hasServerId: !!(it.id || it.rule_id || it.key),
    scope: scope,
    dst_host: host,
    leak_type: lType,
    mac: mac,
    uid: uid > 0 ? uid : 0,
    pkg: pkg,
    app_name: appName,
    device_name: String(it.device_name || (d && d.name) || ''),
    note: noteTxt,
    label: noteTxt
  };
}

function v6IsEventWhitelisted(ev, wlList) {
  if (!ev || !Array.isArray(wlList) || !wlList.length) return false;
  var evOrigin = ev.origin || 'hotspot';
  var evHost = String(ev.dst_host || '').toLowerCase();
  var evType = leakTypeBadgeCode(ev.leak_type);
  var evMac = String(ev.mac || '').toLowerCase();
  var evUid = Math.round(num(ev.uid, 0));
  var evPkg = v6CleanHostRealPkg(ev.pkg).toLowerCase();
  for (var i = 0; i < wlList.length; i++) {
    var w = wlList[i];
    if (!w) continue;
    var wScope = String(w.scope || '').toLowerCase();
    if (wScope === 'device_host') wScope = 'device_host_type';
    if (wScope === 'app_host') wScope = 'app_host_type';
    if (w.dst_host) {
      if (evHost !== w.dst_host && evHost.slice(-(w.dst_host.length + 1)) !== '.' + w.dst_host && ev.dst_ip !== w.dst_host) continue;
    }
    if (wScope === 'app_host_type' || (w.uid > 0) || w.pkg) {
      if (evOrigin !== 'host') continue;
      var wPkg = v6CleanHostRealPkg(w.pkg).toLowerCase();
      var wUid = Math.round(num(w.uid, 0));
      var pkgMatch = !!(wPkg && evPkg && wPkg === evPkg);
      var uidMatch = !!(wUid > 0 && evUid > 0 && wUid === evUid);
      if (!pkgMatch && !uidMatch) continue;
    } else if (wScope === 'device_host_type' || w.mac) {
      if (evOrigin === 'host' || !w.mac || w.mac !== evMac) continue;
    }
    if ((wScope === 'host_type' || wScope === 'device_host_type' || wScope === 'app_host_type' || w.leak_type) && w.leak_type && leakTypeBadgeCode(w.leak_type) !== evType) continue;
    return true;
  }
  return false;
}

function v6NormUndoBlockItem(it, idx) {
  if (!it || typeof it !== 'object') return null;
  var host = String(it.dst_host || it.host || it.domain || it.value || '').trim();
  if (!host) return null;
  var alsoIp = String(it.also_ip || it.dst_ip || it.ip || '').trim();
  var targetScope = String(it.target_scope || it.scope || '').toLowerCase();
  var uid = it.uid != null ? Math.round(num(it.uid, 0)) : 0;
  var macs = Array.isArray(it.macs) ? it.macs.map(function (m) { return String(m || '').trim().toLowerCase(); }).filter(Boolean) : [];
  var mac = String(it.mac || (macs.length === 1 ? macs[0] : '') || '').trim().toLowerCase();
  if (!macs.length && mac) macs = [mac];
  var devLabel = String(it.device_name || it.app_name || '');
  if (!devLabel && targetScope === 'host') {
    devLabel = uid > 0 ? ('本机应用 UID ' + uid) : '本机应用';
  } else if (!devLabel && targetScope === 'both') {
    devLabel = '本机与热点双端';
  } else if (!devLabel && macs.length) {
    var names = macs.map(function (m) {
      var d0 = devBy(m);
      return (d0 && d0.name) ? d0.name : m;
    });
    devLabel = names.length <= 2 ? names.join('、') : (names[0] + ' 等 ' + names.length + ' 台设备');
  }
  var ts = num(it.ts != null ? it.ts : it.created_at, 0);
  return {
    id: String(it.id || it.undo_id || (host + '|' + uid + '|' + ts + '|' + (idx || 0))),
    hasServerId: !!(it.id || it.undo_id),
    kind: String(it.kind || (v6ExtractPureIp(host) ? 'ip' : 'domain')),
    target_scope: targetScope,
    uid: uid > 0 ? uid : 0,
    dst_host: host,
    also_ip: (alsoIp && alsoIp.toLowerCase() !== host.toLowerCase()) ? alsoIp : '',
    mac: mac,
    macs: macs,
    device_name: devLabel,
    ts: ts,
    timeStr: ts ? fmtClockTs(ts) : ''
  };
}

/* ── 已读水位线管理：看完隐私安检即消去刺眼红点，有新增或白名单过滤后实时重算水位 ── */
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
  if (typeof S !== 'undefined' && S.page === 'vector') v6RefreshNavBadges();
}

function v6RecalcLeakWatermark() {
  var sumHits = 0, hostHits = 0, hsHits = 0, devSeen = {}, appSeen = {};
  V6.lg.events.forEach(function (e) {
    var h = Math.max(1, num(e.hit_count, 1));
    sumHits += h;
    if (e.origin === 'host') {
      hostHits += h;
      var cp0 = v6CleanHostRealPkg(e.pkg);
      var ak = cp0 ? ('pkg:' + cp0.toLowerCase()) : (e.uid > 0 ? ('uid:' + e.uid) : (e.app_name ? ('app:' + String(e.app_name).toLowerCase()) : 'host'));
      appSeen[ak] = 1;
    } else {
      hsHits += h;
      var dk = e.mac || e.src_ip;
      if (dk) devSeen[dk] = 1;
    }
  });
  V6.lg.total_hits = sumHits;
  V6.lg.host_hits = hostHits;
  V6.lg.hotspot_hits = hsHits;
  V6.lg.hotspot_affected_devices = Object.keys(devSeen).length;
  V6.lg.affected_apps = Object.keys(appSeen).length;
  V6.lg.affected_devices = V6.lg.hotspot_affected_devices + V6.lg.affected_apps;
  v6SeenLeakHits();
  if (S.page === 'vector' && V6.subtab === 'privacy') {
    v6MarkLeakGuardSeen();
  } else {
    v6PaintHeaderBadges();
    if (S.page === 'vector') v6RefreshNavBadges();
  }
}

/* ── LeakGuard 数据归一化（对齐 v6_leakguard_api.go LeakEvent: 支持本机 host 与热点 hotspot 双来源） ── */
function v6NormLeakEvent(raw, idx, batchCounts) {
  raw = raw || {};
  var ts = num(raw.ts != null ? raw.ts : (raw.timestamp != null ? raw.timestamp : raw.created_at), 0);
  var mac = String(raw.mac || raw.client_mac || raw.src_mac || '').toLowerCase();
  var srcIp = String(raw.src_ip || raw.client_ip || raw.ip || '');
  var uid = raw.uid != null ? Math.round(num(raw.uid, 0)) : 0;
  var rawPkgStr = String(raw.pkg || raw.package || '').trim();
  var pkg = v6CleanHostRealPkg(rawPkgStr);
  var appName = String(raw.app_name || '').trim();
  var originRaw = String(raw.origin || '').toLowerCase().trim();
  var origin = (originRaw === 'host' || (!originRaw && !mac && (uid > 0 || rawPkgStr))) ? 'host' : 'hotspot';

  var d = (origin === 'hotspot' && mac) ? devBy(mac) : null;
  if (origin === 'hotspot' && !d && srcIp && Array.isArray(S.devices)) {
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
  var id = String(raw.id || raw.event_id || (ts + '_' + origin + '_' + (uid || srcIp) + '_' + lType + '_' + dstHost + '_' + (idx || 0)));
  var hostLower = dstHost.toLowerCase();
  var dstPortNum = num(raw.dst_port != null ? raw.dst_port : raw.dport, 80);
  var protoStr = String(raw.proto || 'tcp').toLowerCase();
  var isBlocked = raw.is_blocked === true || raw.blocked === true ||
    (origin !== 'host' && !!V6.lg.blocked_set[hostLower]) ||
    (origin === 'host' && (
      v6IsHostDomainBlocked(dstHost) ||
      v6IsHostIpTargetBlocked(uid, dstHost) ||
      (dstIp ? v6IsHostIpTargetBlocked(uid, dstIp) : false) ||
      !!v6HostAppBlockingModeForEvent(uid, dstPortNum, protoStr)
    ));
  var infraGuard = v6NormInfraGuard(raw.infra_guard, raw.guard_level, raw.guard_label || raw.infra_label, dstHost);
  var hKey = leakHitKey(origin, uid, mac, srcIp, dstHost, lType, rawVal);
  var computedHits = Math.max(
    1,
    Math.round(num(raw.hit_count != null ? raw.hit_count : raw.hits, 0)),
    num(batchCounts && batchCounts[hKey], 0),
    num(V6.lg.hit_ledger[hKey], 0)
  );
  var devLabel = origin === 'host'
    ? v6HostEventAppLabel(appName, pkg, uid)
    : (raw.device_name || (d ? d.name : '') || (srcIp || mac || '未知设备'));
  var srcPort = Math.max(0, Math.round(num(raw.src_port != null ? raw.src_port : (raw.sport != null ? raw.sport : raw.client_port), 0)));

  return {
    id: id,
    hKey: hKey,
    ts: ts,
    timeStr: raw.time_str || fmtClockTs(ts),
    origin: origin,
    scope: origin,
    uid: uid,
    pkg: pkg,
    app_name: appName,
    mac: mac,
    devName: devLabel,
    src_ip: srcIp || (d && d.ip) || '',
    src_port: srcPort,
    sport: srcPort,
    dst_ip: dstIp,
    dst_port: dstPortNum,
    proto: protoStr,
    leak_type: lType,
    leak_label: String(raw.leak_label || leakTypeZh(lType)),
    raw_value: rawVal,
    dst_host: dstHost,
    hit_count: computedHits,
    method: method,
    url_path: urlPath,
    user_agent: ua,
    raw_snippet: snippet,
    is_blocked: isBlocked,
    infra_guard: infraGuard
  };
}

function v6ApplyLeakGuardData(d, forceAccept) {
  if (!d || typeof d !== 'object') return;
  var cfgLocked = !forceAccept && Date.now() < V6.mutUntil.lg;
  if (cfgLocked) return;

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

  var wlSrc = Array.isArray(d.ignore_rules) ? d.ignore_rules
    : (Array.isArray(d.whitelist) ? d.whitelist
    : (Array.isArray(d.ignored_rules) ? d.ignored_rules
    : (d.config && Array.isArray(d.config.ignore_rules) ? d.config.ignore_rules
    : (d.config && Array.isArray(d.config.whitelist) ? d.config.whitelist : null))));
  if (wlSrc) {
    V6.lg.whitelist = wlSrc.map(v6NormWhitelistItem).filter(Boolean);
    V6.lg.whitelist_count = V6.lg.whitelist.length;
  } else if (d.ignore_rules_cnt != null || stats.ignore_rules_cnt != null || d.whitelist_count != null || stats.whitelist_count != null) {
    var rawWlCnt = d.ignore_rules_cnt != null ? d.ignore_rules_cnt
      : (stats.ignore_rules_cnt != null ? stats.ignore_rules_cnt
      : (d.whitelist_count != null ? d.whitelist_count : stats.whitelist_count));
    V6.lg.whitelist_count = Math.max(0, Math.round(num(rawWlCnt, V6.lg.whitelist.length)));
  }

  var usSrc = Array.isArray(d.undo_stack) ? d.undo_stack : (Array.isArray(d.recent_blocks) ? d.recent_blocks : (d.config && Array.isArray(d.config.undo_stack) ? d.config.undo_stack : null));
  if (usSrc) {
    var normUs = usSrc.map(v6NormUndoBlockItem).filter(Boolean);
    if (normUs.length >= 2 && !(normUs[0].ts > normUs[normUs.length - 1].ts)) {
      normUs.reverse();
    }
    V6.lg.undo_stack = normUs.slice(0, 10);
    V6.lg.undo_stack.forEach(function (u) {
      if (u && (u.target_scope === 'host' || u.target_scope === 'both') && u.uid > 0 && u.kind === 'ip' && u.dst_host) {
        var uIp = v6ExtractPureIp(u.dst_host) || u.dst_host;
        V6.lg.blocked_set['uid:' + u.uid + '|' + String(uIp).toLowerCase()] = 1;
      }
    });
  }
  if (d.undo_count != null || stats.undo_count != null) {
    V6.lg.undo_count = Math.max(0, Math.round(num(d.undo_count != null ? d.undo_count : stats.undo_count, V6.lg.undo_stack.length)));
  } else if (usSrc) {
    V6.lg.undo_count = V6.lg.undo_stack.length;
  }

  if (Array.isArray(d.events) || Array.isArray(d.items)) {
    var rawArr = d.events || d.items || [];
    var batchCounts = {};
    rawArr.forEach(function (it) {
      if (!it) return;
      var mac0 = String(it.mac || '').toLowerCase();
      var ip0 = String(it.src_ip || '');
      var uid0 = it.uid != null ? Math.round(num(it.uid, 0)) : 0;
      var orig0 = (String(it.origin || '').toLowerCase() === 'host' || (!it.origin && !mac0 && (uid0 > 0 || it.pkg))) ? 'host' : 'hotspot';
      var hk = leakHitKey(orig0, uid0, mac0, ip0, it.dst_host, leakTypeBadgeCode(it.leak_type), String(it.raw_value != null ? it.raw_value : ''));
      batchCounts[hk] = (batchCounts[hk] || 0) + 1;
    });
    var list = rawArr.map(function (it, idx) {
      var ev = v6NormLeakEvent(it, idx, batchCounts);
      if (ev.is_blocked && ev.dst_host) {
        if (ev.origin !== 'host') {
          V6.lg.blocked_set[ev.dst_host.toLowerCase()] = 1;
        } else if (ev.uid > 0) {
          var evPureIp = v6ExtractPureIp(ev.dst_host);
          if (evPureIp && !v6HostAppBlockingModeForEvent(ev.uid, ev.dst_port, ev.proto)) {
            V6.lg.blocked_set['uid:' + ev.uid + '|' + evPureIp.toLowerCase()] = 1;
          }
        }
      }
      return ev;
    }).filter(function (ev) {
      return !v6IsEventWhitelisted(ev, V6.lg.whitelist);
    });
    list.sort(function (a, b) { return b.ts - a.ts; });
    V6.lg.events = list.slice(0, V6.lg.capacity || 300);
  }

  var rawTotalHits = d.total_hits != null ? d.total_hits : stats.total_hits;
  if (rawTotalHits != null) {
    V6.lg.total_hits = Math.max(0, Math.round(num(rawTotalHits)));
  }
  var rawHostHits = d.host_hits != null ? d.host_hits : stats.host_hits;
  if (rawHostHits != null) {
    V6.lg.host_hits = Math.max(0, Math.round(num(rawHostHits)));
  }
  var rawHotspotHits = d.hotspot_hits != null ? d.hotspot_hits : stats.hotspot_hits;
  if (rawHotspotHits != null) {
    V6.lg.hotspot_hits = Math.max(0, Math.round(num(rawHotspotHits)));
  }

  var rawAffectedDevs = d.affected_devices != null ? d.affected_devices : stats.affected_devices;
  var rawAffectedApps = d.affected_apps != null ? d.affected_apps : stats.affected_apps;
  if (rawAffectedDevs != null) {
    V6.lg.hotspot_affected_devices = Math.max(0, Math.round(num(rawAffectedDevs)));
  }
  if (rawAffectedApps != null) {
    V6.lg.affected_apps = Math.max(0, Math.round(num(rawAffectedApps)));
  }
  if (V6.lg.events.length && (rawAffectedDevs == null || rawAffectedApps == null)) {
    var devSeen = {}, appSeen = {};
    V6.lg.events.forEach(function (e) {
      if (e.origin === 'host') {
        var ak = e.pkg ? ('pkg:' + String(e.pkg).toLowerCase()) : (e.uid > 0 ? ('uid:' + e.uid) : (e.app_name ? ('app:' + String(e.app_name).toLowerCase()) : 'host'));
        appSeen[ak] = 1;
      } else {
        var dk = e.mac || e.src_ip;
        if (dk) devSeen[dk] = 1;
      }
    });
    if (rawAffectedDevs == null) V6.lg.hotspot_affected_devices = Math.max(V6.lg.hotspot_affected_devices, Object.keys(devSeen).length);
    if (rawAffectedApps == null) V6.lg.affected_apps = Math.max(V6.lg.affected_apps, Object.keys(appSeen).length);
  }
  if (rawAffectedDevs != null || rawAffectedApps != null || V6.lg.events.length) {
    V6.lg.affected_devices = V6.lg.hotspot_affected_devices + V6.lg.affected_apps;
  }

  var rawBlkDom = typeof d.blocked_domains === 'number' ? d.blocked_domains : stats.blocked_domains;
  var rawSelfBlkDom = typeof d.self_blocked_domains === 'number' ? d.self_blocked_domains : stats.self_blocked_domains;
  if (typeof rawBlkDom === 'number') {
    V6.lg.hotspot_blocked_domains = Math.max(0, Math.round(rawBlkDom));
  }
  if (typeof rawSelfBlkDom === 'number') {
    V6.lg.self_blocked_domains = Math.max(0, Math.round(rawSelfBlkDom));
  }
  if (typeof rawBlkDom === 'number' || typeof rawSelfBlkDom === 'number') {
    V6.lg.blocked_domains = V6.lg.hotspot_blocked_domains + V6.lg.self_blocked_domains;
  }

  if ((Array.isArray(d.events) || Array.isArray(d.items)) && V6.lg.events.length === 0) {
    LS.set('hnc6.lg_seen_hits', String(Math.max(0, num(V6.lg.total_hits, 0))));
  }
  v6SeenLeakHits();
  if (S.page === 'vector' && V6.subtab === 'privacy') {
    v6MarkLeakGuardSeen();
  } else {
    v6PaintHeaderBadges();
    if (S.page === 'vector') v6RefreshNavBadges();
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
  if (v6IsEventWhitelisted(tmpEv, V6.lg.whitelist)) return;
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
  if (tmpEv.origin === 'host') V6.lg.host_hits = num(V6.lg.host_hits) + 1;
  else V6.lg.hotspot_hits = num(V6.lg.hotspot_hits) + 1;
  var devSeen = {}, appSeen = {};
  V6.lg.events.forEach(function (x) {
    if (x.origin === 'host') {
      var ak = x.pkg ? ('pkg:' + String(x.pkg).toLowerCase()) : (x.uid > 0 ? ('uid:' + x.uid) : (x.app_name ? ('app:' + String(x.app_name).toLowerCase()) : 'host'));
      appSeen[ak] = 1;
    } else {
      var dk = x.mac || x.src_ip;
      if (dk) devSeen[dk] = 1;
    }
  });
  V6.lg.hotspot_affected_devices = Math.max(V6.lg.hotspot_affected_devices, Object.keys(devSeen).length);
  V6.lg.affected_apps = Math.max(V6.lg.affected_apps, Object.keys(appSeen).length);
  V6.lg.affected_devices = Math.max(V6.lg.affected_devices, V6.lg.hotspot_affected_devices + V6.lg.affected_apps);
  if (S.page === 'vector' && V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  else v6PaintHeaderBadges();
  if (S.page === 'vector') v6RefreshNavBadges();
  v6RefreshActiveSubviewDom();
}

function v6DataplaneTierZh(tier) {
  var s = String(tier || '').trim();
  if (!s) return '';
  if (/tier[_-]?a|ebpf/i.test(s)) return 'Tier-A eBPF';
  if (/tier[_-]?b|native|netlink/i.test(s)) return 'Tier-B 原生队列';
  if (/tier[_-]?c|compat|shell/i.test(s)) return 'Tier-C 兼容队列';
  return s;
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
  } else if ('forced_macs' in r && !r.forced_macs) {
    V6.express.forced_macs = [];
  } else if (Array.isArray(cfg.forced_macs)) {
    V6.express.forced_macs = cfg.forced_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(v6ValidMac);
  } else if (cfg !== r && 'forced_macs' in cfg && !cfg.forced_macs) {
    V6.express.forced_macs = [];
  }
  var hasRuntimeFields = !forceAccept || ('active' in r || 'state' in r || 'escorted_macs' in r || 'bg_ceil_pct' in r || 'transitions' in r);
  if (Array.isArray(r.escorted_macs)) {
    V6.express.escorted_macs = r.escorted_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(Boolean);
  } else if (r.escorted_macs === null || r.active === false || !V6.express.enabled || (hasRuntimeFields && !r.escorted_macs)) {
    V6.express.escorted_macs = [];
  }
  if (r.escort_reasons && typeof r.escort_reasons === 'object') {
    V6.express.escort_reasons = r.escort_reasons;
  } else if (r.escort_reasons === null || r.active === false || !V6.express.enabled || !V6.express.escorted_macs.length || (hasRuntimeFields && !r.escort_reasons)) {
    V6.express.escort_reasons = {};
  }
  if (r.bg_ceil_pct != null) V6.express.bg_ceil_pct = Math.round(num(r.bg_ceil_pct, 100));
  if (r.configured_bg_ceil_pct != null) V6.express.configured_bg_ceil_pct = Math.round(num(r.configured_bg_ceil_pct, 85));
  else if (cfg.bg_ceil_pct != null && r.bg_ceil_pct == null) V6.express.configured_bg_ceil_pct = Math.round(num(cfg.bg_ceil_pct, 85));
  if (r.cooldown_remaining_sec != null) V6.express.cooldown_remaining_sec = Math.max(0, Math.round(num(r.cooldown_remaining_sec)));
  if (r.transitions != null) V6.express.transitions = Math.max(0, Math.round(num(r.transitions)));
  if (r.dataplane && r.dataplane.qdisc) V6.express.qdisc = String(r.dataplane.qdisc);
  if (r.dataplane && (r.dataplane.tier || r.dataplane.active_tier)) V6.express.tier = String(r.dataplane.tier || r.dataplane.active_tier);
  else if (typeof r.dataplane_tier === 'string' && r.dataplane_tier) V6.express.tier = r.dataplane_tier;
  else if (r.dataplane_tier && (r.dataplane_tier.active_tier || r.dataplane_tier.tier)) V6.express.tier = String(r.dataplane_tier.active_tier || r.dataplane_tier.tier);
  V6._committed.express = {
    enabled: V6.express.enabled,
    auto_detect: V6.express.auto_detect,
    forced_macs: V6.express.forced_macs.slice()
  };
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
        cur_kbps: downBps > 0 ? Math.round(downBps * 8 / 1000) : 0,
        applied_kbps: Math.round(num(s.applied_kbps, V6.leash.leash_kbps)),
        state: st,
        bypass_once: s.bypass_once === true || st === 'bypassed',
        paused: s.paused === true || st === 'paused'
      };
    });
    V6.leash.active_sessions = V6.leash.sessions.length;
    if (r.leashed_count == null) {
      V6.leash.leashed_count = V6.leash.sessions.filter(function (x) { return x.state === 'leashed'; }).length;
    }
  } else if ((r.active_sessions != null && V6.leash.active_sessions === 0) || ('sessions' in r && !r.sessions) || !V6.leash.enabled) {
    V6.leash.sessions = [];
    if (!V6.leash.enabled || V6.leash.active_sessions === 0) V6.leash.leashed_count = 0;
  }
  V6._committed.leash = {
    enabled: V6.leash.enabled,
    grace_mb: V6.leash.grace_mb,
    leash_kbps: V6.leash.leash_kbps
  };
}

/* ── ThermoCruise 数据归一化（支持机身壳温 shell_temp_c + 电池温度双轨及温度锁定提示） ── */
function v6IsThermoSensorUnreadable(th) {
  th = th || V6.thermo || {};
  var rc = String(th.reason_code || '').toLowerCase();
  if (rc && /unreadable|unavailable|sensor|out_of_range|out_of_bounds|invalid_temp|fuse|trip|missing|nan/.test(rc)) return true;
  if (th.bat_available === false && !th.shell_temp_available) return true;
  return false;
}

function v6EffectiveTempC(th) {
  th = th || V6.thermo || {};
  if (th.shell_temp_available && th.shell_temp_c > 0 && th.shell_temp_c < 95) {
    return Math.max(th.shell_temp_c, th.temp_c || 0);
  }
  return num(th.temp_c, 0);
}

function v6ThermoStageZh(stage) {
  if (!V6.thermo.enabled) return '已关闭';
  if (v6IsThermoSensorUnreadable(V6.thermo)) return '温度传感器不可读（已安全跳过控温）';
  if (V6.thermo.bat_available === null && !(v6EffectiveTempC(V6.thermo) > 0)) return '待读取';
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

  V6.thermo.sensor_checked = true;
  var hasThermoSnap = !forceAccept || (bat != null || r.temp_c != null || r.stage != null || r.effective_stage != null || r.raw_thermal_stage != null || typeof r.bat_available === 'boolean' || 'reason_code' in r || 'reason_zh' in r || 'reason' in r);
  if (r.reason_code != null || (bat && bat.reason_code != null)) {
    V6.thermo.reason_code = String(r.reason_code != null ? r.reason_code : bat.reason_code).trim();
  } else if (hasThermoSnap) {
    V6.thermo.reason_code = '';
  }
  if (r.reason_zh != null || r.reason != null || (bat && (bat.reason_zh != null || bat.reason != null))) {
    V6.thermo.reason_zh = String(r.reason_zh || r.reason || (bat && (bat.reason_zh || bat.reason)) || '').trim();
  } else if (hasThermoSnap) {
    V6.thermo.reason_zh = '';
  }

  if (typeof r.bat_available === 'boolean') {
    V6.thermo.bat_available = r.bat_available;
  } else if (bat && typeof bat.available === 'boolean') {
    V6.thermo.bat_available = bat.available;
  } else if (r.temp_c != null && isFinite(Number(r.temp_c)) && Number(r.temp_c) > 0 && Number(r.temp_c) < 95) {
    V6.thermo.bat_available = true;
  }

  var inferCharging = function (stStr) {
    var s = String(stStr || '').trim();
    return /charging|full/i.test(s) && !/discharging|not[\s_-]*charging/i.test(s);
  };
  if (bat) {
    if (bat.temp_c != null) V6.thermo.temp_c = num(bat.temp_c);
    if (bat.battery_temp_c != null) V6.thermo.battery_temp_c = num(bat.battery_temp_c);
    if (bat.shell_temp_c != null) V6.thermo.shell_temp_c = num(bat.shell_temp_c);
    if (typeof bat.shell_temp_available === 'boolean') V6.thermo.shell_temp_available = bat.shell_temp_available;
    if (bat.shell_zone != null) V6.thermo.shell_zone = String(bat.shell_zone || '');
    if (typeof bat.battery_spoof_suspected === 'boolean') V6.thermo.battery_spoof_suspected = bat.battery_spoof_suspected;
    if (bat.capacity_pct != null) V6.thermo.capacity_pct = clamp(Math.round(num(bat.capacity_pct)), 0, 100);
    if (bat.status != null) V6.thermo.bat_status = String(bat.status);
    if (typeof bat.is_charging === 'boolean') V6.thermo.is_charging = bat.is_charging;
    else if (bat.status != null) V6.thermo.is_charging = inferCharging(V6.thermo.bat_status);
  }
  if (r.temp_c != null) V6.thermo.temp_c = num(r.temp_c);
  if (r.battery_temp_c != null) V6.thermo.battery_temp_c = num(r.battery_temp_c);
  if (r.shell_temp_c != null) V6.thermo.shell_temp_c = num(r.shell_temp_c);
  if (typeof r.shell_temp_available === 'boolean') V6.thermo.shell_temp_available = r.shell_temp_available;
  else if (V6.thermo.shell_temp_c > 0 && V6.thermo.shell_temp_c < 95) V6.thermo.shell_temp_available = true;
  if (r.shell_zone != null) V6.thermo.shell_zone = String(r.shell_zone || '');
  if (typeof r.battery_spoof_suspected === 'boolean') V6.thermo.battery_spoof_suspected = r.battery_spoof_suspected;
  if (!bat) {
    if (r.capacity_pct != null) V6.thermo.capacity_pct = clamp(Math.round(num(r.capacity_pct)), 0, 100);
    if (r.status != null || r.bat_status != null) {
      V6.thermo.bat_status = String(r.status != null ? r.status : r.bat_status);
    }
    if (typeof r.is_charging === 'boolean') {
      V6.thermo.is_charging = r.is_charging;
    } else if (r.status != null || r.bat_status != null) {
      V6.thermo.is_charging = inferCharging(V6.thermo.bat_status);
    }
  } else if (typeof r.is_charging === 'boolean' && typeof bat.is_charging !== 'boolean') {
    V6.thermo.is_charging = r.is_charging;
  }

  if (typeof r.vector_express_active === 'boolean') V6.thermo.vector_express_active = r.vector_express_active;
  if (typeof r.stage2_exempt === 'boolean') V6.thermo.stage2_exempt = r.stage2_exempt;
  else if (hasThermoSnap) V6.thermo.stage2_exempt = false;
  if (r.exempt_reason != null) V6.thermo.exempt_reason = String(r.exempt_reason || '');
  else if (hasThermoSnap) V6.thermo.exempt_reason = '';
  if (typeof r.low_battery_cruise === 'boolean') V6.thermo.low_battery_cruise = r.low_battery_cruise;
  if (r.cool_hold_remaining_sec != null) V6.thermo.cool_hold_remaining_sec = Math.max(0, Math.round(num(r.cool_hold_remaining_sec)));

  if (v6IsThermoSensorUnreadable(V6.thermo)) {
    V6.thermo.temp_c = 0;
    V6.thermo.raw_stage = 0;
    V6.thermo.stage = 0;
  } else {
    var effStg = r.effective_stage != null ? Math.round(num(r.effective_stage)) : (r.stage != null ? Math.round(num(r.stage)) : (r.raw_thermal_stage != null ? Math.round(num(r.raw_thermal_stage)) : null));
    if (r.raw_thermal_stage != null) V6.thermo.raw_stage = Math.round(num(r.raw_thermal_stage));
    if (effStg != null) {
      V6.thermo.stage = clamp(effStg, 0, 2);
    } else {
      var tc = v6EffectiveTempC(V6.thermo);
      V6.thermo.stage = !V6.thermo.enabled || !(tc > 0) ? 0 : (tc >= V6.thermo.stage2_temp_c ? 2 : (tc >= V6.thermo.stage1_temp_c ? 1 : 0));
    }
  }
  V6.thermo.stage_label = v6ThermoStageZh(V6.thermo.stage);
  V6._committed.thermo = {
    enabled: V6.thermo.enabled,
    stage2_shaper_enabled: V6.thermo.stage2_shaper_enabled,
    stage1_temp_c: V6.thermo.stage1_temp_c,
    stage2_temp_c: V6.thermo.stage2_temp_c,
    low_bat_pct: V6.thermo.low_bat_pct
  };
}

/* ── FlowScalpel 数据归一化（正交隔离热点连接与本机应用连接，严格隔离全局与单机抽屉） ── */
function v6IsHotspotActive() {
  return !(typeof S !== 'undefined' && S.hotspot && S.hotspot.active === false);
}

function v6OnlineClientCount() {
  if (!v6IsHotspotActive()) return 0;
  var devs = (typeof S !== 'undefined' && Array.isArray(S.devices)) ? S.devices : [];
  var byList = devs.filter(function (d) { return d && d.online; }).length;
  if (typeof S !== 'undefined' && S.devLoaded) return byList;
  return Math.max(0, Math.round(num(typeof S !== 'undefined' && S.live && S.live.online, byList)));
}

function v6HotspotFlowCount() {
  if (!v6IsHotspotActive() || v6OnlineClientCount() <= 0) return 0;
  if (V6.scalpel.hasSplitCounts) return Math.max(0, V6.scalpel.hotspotFlows);
  if (typeof S !== 'undefined' && S.live && S.live.hotspot_flows != null) {
    return Math.max(0, Math.round(num(S.live.hotspot_flows, 0)));
  }
  return 0;
}

function v6HostFlowCount() {
  if (typeof S !== 'undefined' && S.live && S.live.host_flows != null && !V6.scalpel.hasSplitCounts) {
    return Math.max(0, Math.round(num(S.live.host_flows, 0)));
  }
  if (V6.scalpel.hasSplitCounts) return Math.max(0, V6.scalpel.hostFlows);
  if (typeof S !== 'undefined' && S.live && S.live.host_flows != null) {
    return Math.max(0, Math.round(num(S.live.host_flows, 0)));
  }
  return Math.max(0, num(V6.scalpel.globalTotalFlows, 0));
}

function v6NormScalpelFlowList(fl) {
  if (!Array.isArray(fl)) return [];
  var nowSec = Date.now() / 1000;
  return fl.map(function (f, idx) {
    var mac = String(f.mac || '').toLowerCase();
    var srcIp = String(f.src_ip || '');
    var uid = f.uid != null ? Math.round(num(f.uid, -1)) : -1;
    var rawPkg = String(f.package || f.pkg || '');
    var pkg = v6CleanHostRealPkg(rawPkg);
    var hostAppName = String(f.host_app_name || '');
    var scopeRaw = String(f.scope || '').toLowerCase();
    var flowScope = (scopeRaw === 'host' || (!scopeRaw && !mac && (uid >= 0 || rawPkg || hostAppName))) ? 'host' : 'hotspot';

    var d = (flowScope === 'hotspot' && mac) ? devBy(mac) : null;
    if (flowScope === 'hotspot' && !d && srcIp && Array.isArray(S.devices)) {
      for (var i = 0; i < S.devices.length; i++) {
        if (S.devices[i].ip === srcIp) { d = S.devices[i]; if (!mac) mac = d.mac; break; }
      }
    }
    var rawProto = String(f.proto || 'tcp').toLowerCase();
    var sport = Math.round(num(f.sport != null ? f.sport : f.src_port, 0));
    var dport = Math.round(num(f.dport != null ? f.dport : f.dst_port, 0));
    var isQuic = rawProto === 'quic' || (rawProto === 'udp' && dport === 443);
    var frozenUntil = num(f.frozen_until, 0);
    var ownerLabel = flowScope === 'host'
      ? (uid === 0 && !hostAppName && !pkg ? 'Root / 内核系统' : v6HostEventAppLabel(hostAppName, pkg, uid))
      : (f.device_name || (d ? d.name : '') || srcIp || '未知设备');

    return {
      id: String(f.flow_key || f.id || (flowScope + '|' + rawProto + '|' + srcIp + ':' + sport + '|' + f.dst_ip + ':' + dport + '|' + idx)),
      scope: flowScope,
      uid: uid,
      pkg: pkg,
      host_app_name: hostAppName,
      is_system: f.is_system === true,
      cleartext_risk: String(f.cleartext_risk || ''),
      proto: rawProto === 'udp' || rawProto === 'quic' ? 'udp' : 'tcp',
      protoBadge: isQuic ? 'QUIC' : (rawProto === 'udp' ? 'UDP' : 'TCP'),
      state: String(f.state || 'ESTABLISHED').toUpperCase(),
      frozen: frozenUntil > nowSec,
      frozen_until: frozenUntil,
      mac: mac,
      devName: ownerLabel,
      src_ip: srcIp,
      sport: sport,
      dst_ip: String(f.dst_ip || ''),
      dport: dport,
      dst_host: String(f.domain || f.dst_host || ''),
      app_name: String(f.app_name || hostAppName || ''),
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
  if (!isDrawerScoped) {
    var rawHsCut = r.cut_total != null ? r.cut_total : r.total_cut_count;
    if (rawHsCut != null || r.host_cut_total != null || r.total_cuts != null) {
      var hsCut = Math.max(0, Math.round(num(rawHsCut, 0)));
      var hoCut = Math.max(0, Math.round(num(r.host_cut_total, 0)));
      V6.scalpel.cutTotal = r.total_cuts != null
        ? Math.max(0, Math.round(num(r.total_cuts, 0)))
        : (hsCut + hoCut);
    }
    if (Array.isArray(r.active_rules)) {
      var extraHostArr = Array.isArray(r.host_active_rules) ? r.host_active_rules : [];
      V6.scalpel.active_rules = extraHostArr.length ? r.active_rules.concat(extraHostArr) : r.active_rules;
      var hostRuleNum = typeof r.host_active_rules === 'number' ? Math.max(0, Math.round(r.host_active_rules)) : 0;
      var hasHostInArr = r.active_rules.some(function (x) { return x && x.scope === 'host'; });
      V6.scalpel.activeRulesCount = V6.scalpel.active_rules.length + (hasHostInArr ? 0 : hostRuleNum);
    } else if (typeof r.active_rules === 'number' || typeof r.host_active_rules === 'number') {
      V6.scalpel.activeRulesCount = Math.max(0, Math.round(num(r.active_rules, 0) + num(r.host_active_rules, 0)));
    }
  }
  if (!isDrawerScoped && (r.hotspot_flows != null || r.host_flows != null)) {
    V6.scalpel.hasSplitCounts = true;
    V6.scalpel.hotspotFlows = (!v6IsHotspotActive() || v6OnlineClientCount() <= 0) ? 0 : Math.max(0, Math.round(num(r.hotspot_flows, 0)));
    V6.scalpel.hostFlows = Math.max(0, Math.round(num(r.host_flows, 0)));
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
    if (V6.scalpel.open && !V6.scalpel.scopeMac && !V6.scalpel.scopeIp && V6.scalpel.scopeDomain === 'all') {
      V6.scalpel.drawerFlows = parsed;
      V6.scalpel.drawerTotal = tot;
    }
  }
}

function v6ApplyBlackboxData(r) {
  if (!r || typeof r !== 'object') return;
  var sumObj = (r.summary && typeof r.summary === 'object') ? r.summary : r;
  if (typeof r.rtt_probe_active === 'boolean') V6.blackbox.rtt_probe_active = r.rtt_probe_active;
  else if (typeof sumObj.rtt_probe_active === 'boolean') V6.blackbox.rtt_probe_active = sumObj.rtt_probe_active;
  if (r.granularity_ms != null) V6.blackbox.granularity_ms = Math.max(50, Math.round(num(r.granularity_ms, 200)));
  if (r.total_ticks != null) V6.blackbox.total_ticks = Math.max(0, Math.round(num(r.total_ticks, 0)));
  if (r.latest_jitter_ms != null) V6.blackbox.latest_jitter_ms = Math.max(0, num(r.latest_jitter_ms, 0));
  if (r.latest_rtt_ms != null) V6.blackbox.latest_rtt_ms = Math.max(0, num(r.latest_rtt_ms, 0));
  if (Array.isArray(r.incidents)) {
    V6.blackbox.incidents = r.incidents.slice(0, 12);
    V6.blackbox.incident_count = r.incident_count != null ? Math.round(num(r.incident_count)) : r.incidents.length;
  } else if (r.incident_count != null) {
    V6.blackbox.incident_count = Math.max(0, Math.round(num(r.incident_count)));
  }
}

var V6_ARBITER_SRC_ZH = {
  thermo_stage2: '温控二阶保护',
  thermo_recovery: '温控平滑恢复',
  thermo: '发热温控巡航',
  thermo_cruise: '发热温控巡航',
  thermal: '发热温控巡航',
  static_shaper: '全局静态限速',
  global_shaper: '全局静态限速',
  autorate: '5G 自适应总带宽',
  '5g_autorate': '5G 自适应总带宽',
  manual: '手动总带宽上限'
};

function v6ArbiterSrcZh(s) {
  var k = String(s || '').trim();
  if (!k) return '';
  var low = k.toLowerCase();
  return V6_ARBITER_SRC_ZH[low] || k;
}

function v6ApplyArbiterData(arb, liveObj) {
  var lv = liveObj || (typeof S !== 'undefined' && S.live) || {};
  var srcArr = [];
  var rawList = (arb && Array.isArray(arb.sources) ? arb.sources : null) ||
    (arb && Array.isArray(arb.throttle_sources) ? arb.throttle_sources : null) ||
    (Array.isArray(lv.throttle_sources) ? lv.throttle_sources : []);

  rawList.forEach(function (it) {
    if (!it) return;
    if (typeof it === 'string') {
      var st = it.trim();
      if (st) srcArr.push({ source: st, label: v6ArbiterSrcZh(st), reason: '', down_mbps: 0, active: true });
      return;
    }
    if (typeof it === 'object') {
      if (it.active === false) return;
      var sKey = String(it.source || it.id || it.name || '').trim();
      var dMbps = it.down_mbps != null ? num(it.down_mbps, 0) : (it.down_kbps != null ? num(it.down_kbps, 0) / 1000 : (it.ceil_kbps != null ? num(it.ceil_kbps, 0) / 1000 : 0));
      srcArr.push({
        source: sKey,
        label: String(it.label || v6ArbiterSrcZh(sKey) || '自动控速'),
        reason: String(it.reason_zh || it.reason || it.detail || '').trim(),
        down_mbps: dMbps > 0 ? dMbps : 0,
        active: true
      });
    }
  });

  var winSrc = String((arb && (arb.winning_source || arb.active_source || arb.winner || arb.source)) || (lv.winning_source || lv.active_limiter_source || '')).trim();
  var reasonStr = String(
    (arb && (arb.active_limiter_reason || arb.active_reason || arb.reason_zh || arb.reason || arb.summary)) ||
    lv.active_limiter_reason ||
    ''
  ).trim();
  var downMbps = 0, upMbps = 0;
  if (arb) {
    if (arb.effective_down_mbps != null || arb.ceil_mbps != null || arb.down_mbps != null) {
      downMbps = num(arb.effective_down_mbps != null ? arb.effective_down_mbps : (arb.ceil_mbps != null ? arb.ceil_mbps : arb.down_mbps), 0);
    } else if (arb.effective_down_kbps != null || arb.ceil_kbps != null || arb.down_kbps != null) {
      downMbps = num(arb.effective_down_kbps != null ? arb.effective_down_kbps : (arb.ceil_kbps != null ? arb.ceil_kbps : arb.down_kbps), 0) / 1000;
    }
    if (arb.effective_up_mbps != null || arb.up_mbps != null) {
      upMbps = num(arb.effective_up_mbps != null ? arb.effective_up_mbps : arb.up_mbps, 0);
    } else if (arb.effective_up_kbps != null || arb.up_kbps != null) {
      upMbps = num(arb.effective_up_kbps != null ? arb.effective_up_kbps : arb.up_kbps, 0) / 1000;
    }
  }

  var isAct = false;
  if (arb && typeof arb.active === 'boolean') isAct = arb.active;
  else if (arb && typeof arb.limiting === 'boolean') isAct = arb.limiting;
  else isAct = Boolean(reasonStr || srcArr.length > 0 || (winSrc && winSrc.toLowerCase() !== 'none' && winSrc.toLowerCase() !== 'idle'));

  if (!isAct && !reasonStr && !srcArr.length) {
    V6.arbiter = { active: false, source: '', reason: '', down_mbps: 0, up_mbps: 0, sources: [] };
    return;
  }

  if (!winSrc && srcArr.length) winSrc = srcArr[0].source || srcArr[0].label;
  if (!reasonStr && srcArr.length) {
    reasonStr = srcArr.map(function (x) {
      var seg = x.reason || x.label;
      if (x.down_mbps > 0 && seg.indexOf('Mbps') < 0) seg += '（上限 ' + trim0(x.down_mbps.toFixed(1)) + ' Mbps）';
      return seg;
    }).filter(Boolean).join('；');
  }

  V6.arbiter = {
    active: isAct,
    source: winSrc,
    reason: reasonStr,
    down_mbps: downMbps > 0 ? downMbps : 0,
    up_mbps: upMbps > 0 ? upMbps : 0,
    sources: srcArr
  };
}

function v6ActiveLimiterInfo() {
  var lv = (typeof S !== 'undefined' && S.live) || {};
  if (!V6._rawSyncArbiter || lv.active_limiter_reason != null || Array.isArray(lv.throttle_sources) || lv.arbiter) {
    v6ApplyArbiterData(V6._rawSyncArbiter || lv.arbiter || null, lv);
    if (V6._rawSyncArbiter && V6.arbiter.active) V6.arbiter._fromSync = true;
  }
  var ab = V6.arbiter || {};
  if (!ab.active && !ab.reason && !(ab.sources && ab.sources.length)) return null;
  return {
    active: true,
    sourceLabel: v6ArbiterSrcZh(ab.source) || (ab.sources && ab.sources[0] && ab.sources[0].label) || '自动总带宽仲裁',
    reason: ab.reason || v6ArbiterSrcZh(ab.source) || '总带宽自动压速保护生效中',
    down_mbps: ab.down_mbps || 0,
    up_mbps: ab.up_mbps || 0,
    sources: ab.sources || []
  };
}
window.v6ActiveLimiterInfo = v6ActiveLimiterInfo;

function v6ApplyMultiIfaceData(r) {
  if (!r || typeof r !== 'object') return;
  var src = (r.snapshot && typeof r.snapshot === 'object') ? r.snapshot : r;
  if (src.primary_downstream != null) V6.multiIface.primary_downstream = String(src.primary_downstream || '');
  if (Array.isArray(src.shape_targets)) V6.multiIface.shape_targets = src.shape_targets.map(String);
  if (typeof src.dual_band_or_mlo === 'boolean') V6.multiIface.dual_band_or_mlo = src.dual_band_or_mlo;
  if (typeof src.usb_tether_active === 'boolean') V6.multiIface.usb_tether_active = src.usb_tether_active;
  if (src.lan_fastlane_class != null) V6.multiIface.lan_fastlane_class = String(src.lan_fastlane_class);
  if (src.lan_fastlane_gbps != null) V6.multiIface.lan_fastlane_gbps = num(src.lan_fastlane_gbps, 2.5);
  var tg = (src.tun0_guard && typeof src.tun0_guard === 'object') ? src.tun0_guard : ((r.tun0_guard && typeof r.tun0_guard === 'object') ? r.tun0_guard : src);
  var vpnActive = typeof tg.vpn_active === 'boolean' ? tg.vpn_active : (typeof src.tun0_vpn_active === 'boolean' ? src.tun0_vpn_active : (typeof r.tun0_vpn_active === 'boolean' ? r.tun0_vpn_active : null));
  if (vpnActive !== null) V6.multiIface.tun0_vpn_active = vpnActive;
  var loopRisk = typeof tg.loop_risk_detected === 'boolean' ? tg.loop_risk_detected : (typeof src.tun0_loop_risk === 'boolean' ? src.tun0_loop_risk : (typeof r.tun0_loop_risk === 'boolean' ? r.tun0_loop_risk : null));
  if (loopRisk !== null) V6.multiIface.tun0_loop_risk = loopRisk;
  var low16Safe = typeof tg.low16_mark_safe === 'boolean' ? tg.low16_mark_safe : (typeof src.low16_mark_safe === 'boolean' ? src.low16_mark_safe : null);
  if (low16Safe !== null) V6.multiIface.low16_mark_safe = low16Safe;
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

/* 消费 /api/vector_sync 聚合快照（含零副作用 host_guardian 摘要） */
function v6ApplyHostSyncSummary(hg) {
  if (!hg || typeof hg !== 'object') return;
  if (Date.now() >= V6.mutUntil.hostFw) {
    if (hg.uid_rule_count != null) V6.host.firewall.uid_rule_count = Math.max(0, Math.round(num(hg.uid_rule_count, 0)));
    if (hg.blocked_domain_count != null) V6.host.firewall.blocked_domain_count = Math.max(0, Math.round(num(hg.blocked_domain_count, 0)));
  }
  if (Date.now() >= V6.mutUntil.selfCap) {
    if (typeof hg.self_capture_enabled === 'boolean') V6.host.privacy.self_capture_enabled = hg.self_capture_enabled;
    if (hg.self_capture_mode != null) V6.host.privacy.self_capture_mode = String(hg.self_capture_mode || '');
  }
}

function v6IngestVectorSync(r) {
  if (!r || typeof r !== 'object') return;
  var ext = (r.extensions && typeof r.extensions === 'object') ? r.extensions : ((r.modules && typeof r.modules === 'object') ? r.modules : {});
  var v = (ext.v6 && typeof ext.v6 === 'object') ? ext.v6 : ((r.v6 && typeof r.v6 === 'object') ? r.v6 : ext);

  var lgSrc = r.leakguard || ext.leakguard || v.leakguard;
  var exSrc = r.express || ext.express || v.express;
  var ulSrc = r.update_leash || r.leash || ext.update_leash || ext.leash || v.update_leash || v.leash;
  var thSrc = r.thermo || ext.thermo || v.thermo || v.thermo_cruise;
  var scSrc = r.scalpel || ext.scalpel || v.scalpel;
  var bbSrc = r.blackbox || ext.blackbox || v.blackbox;
  var arbSrc = ext.arbiter || r.arbiter || v.arbiter || null;
  var hgSrc = ext.host_guardian || r.host_guardian || v.host_guardian || null;
  var sfSrc = r.self_firewall || ext.self_firewall || v.self_firewall || null;

  if (lgSrc) v6ApplyLeakGuardData(lgSrc, false);
  if (exSrc) v6ApplyExpressData(exSrc, false);
  if (ulSrc) v6ApplyLeashData(ulSrc, false);
  if (thSrc) v6ApplyThermoData(thSrc, false);
  if (scSrc) v6ApplyScalpelData(scSrc, false);
  if (bbSrc) v6ApplyBlackboxData(bbSrc);
  if (hgSrc) v6ApplyHostSyncSummary(hgSrc);
  if (sfSrc && typeof sfSrc === 'object' && Date.now() >= V6.mutUntil.hostFw) {
    var rawSfUid = sfSrc.uid_rule_count != null ? sfSrc.uid_rule_count : sfSrc.enabled_apps;
    if (rawSfUid != null) {
      V6.host.firewall.uid_rule_count = Array.isArray(rawSfUid) ? rawSfUid.length : Math.max(0, Math.round(num(rawSfUid, 0)));
    }
    var rawSfDom = sfSrc.blocked_domain_count != null ? sfSrc.blocked_domain_count : sfSrc.blocked_domains;
    if (rawSfDom != null) {
      V6.host.firewall.blocked_domain_count = Array.isArray(rawSfDom) ? rawSfDom.length : Math.max(0, Math.round(num(rawSfDom, 0)));
    }
    var sfUpd = num(sfSrc.updated_at, 0);
    var needFwSync = !V6.host.fwLoadedAt
      ? (sfSrc.active === true || V6.host.firewall.uid_rule_count > 0 || V6.host.firewall.blocked_domain_count > 0)
      : (sfUpd > 0 && sfUpd !== V6.host.firewall.updated_at);
    if (needFwSync && !V6.host.fwLoading) {
      v6LoadHostFirewall(false);
    }
  }

  V6._rawSyncArbiter = arbSrc;
  v6ApplyArbiterData(arbSrc, r.live || S.live);
  if (arbSrc) V6.arbiter._fromSync = true;

  var pk = (ext.v6_pack && typeof ext.v6_pack === 'object') ? ext.v6_pack : ((r.v6_pack && typeof r.v6_pack === 'object') ? r.v6_pack : null);
  if (pk) v6ApplyScreenshotPackSummary(pk);
  var dpTierVal = (r.extensions && r.extensions.dataplane_tier && (r.extensions.dataplane_tier.active_tier || r.extensions.dataplane_tier.tier)) ||
    (ext && ext.dataplane_tier && (ext.dataplane_tier.active_tier || ext.dataplane_tier.tier)) ||
    (r.dataplane && (r.dataplane.active_tier || r.dataplane.tier)) ||
    (typeof r.dataplane_tier === 'string' ? r.dataplane_tier : (r.dataplane_tier && (r.dataplane_tier.active_tier || r.dataplane_tier.tier))) ||
    (r.bulkheads && r.bulkheads.dataplane && (r.bulkheads.dataplane.active_tier || r.bulkheads.dataplane.tier)) || '';
  if (dpTierVal) V6.express.tier = String(dpTierVal);

  V6.loaded = true;
  S.v6 = V6;
  v6PaintHeaderBadges();
  v6RefreshDevicesBannerDom();
  v6RefreshNavBadges();
  if (S.page === 'vector') {
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
  }
}

/* ── 独立 REST 拉取与 SSE 实时通道管理 ── */
function v6LoadLeakGuard(forceAccept) {
  var guardGen = (typeof api === 'object' && api) ? (api.writeGen || 0) : 0;
  return api.get(V6_API.lgEvents, null, { timeout: 8000 }).then(function (r) {
    if (typeof api === 'object' && api && (guardGen !== api.writeGen || api.writeInFlight > 0)) return r;
    V6.apiSupported.lg = true;
    v6ApplyLeakGuardData(r, !!forceAccept);
    V6.loaded = true;
    if (S.page === 'vector') {
      v6RefreshHeroDom();
      v6RefreshNavBadges();
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
  var guardGen = (typeof api === 'object' && api) ? (api.writeGen || 0) : 0;
  var isStale = function () {
    return typeof api === 'object' && api && (guardGen !== api.writeGen || api.writeInFlight > 0);
  };
  return Promise.all([
    api.get(V6_API.express, null, { timeout: 7000 }).then(function (r) { if (isStale()) return; V6.apiSupported.v6 = true; v6ApplyExpressData(r, false); }).catch(function (e) { if (e && e.status === 404) V6.apiSupported.v6 = false; }),
    api.get(V6_API.updateLeash, null, { timeout: 7000 }).then(function (r) { if (isStale()) return; V6.apiSupported.v6 = true; v6ApplyLeashData(r, false); }).catch(function () {}),
    api.get(V6_API.thermo, null, { timeout: 7000 }).then(function (r) { if (isStale()) return; V6.apiSupported.v6 = true; v6ApplyThermoData(r, false); }).catch(function () {}),
    api.get(V6_API.scalpelFlows, { scope: 'all', limit: 120 }, { timeout: 7000 }).then(function (r) { if (isStale()) return; v6ApplyScalpelData(r, false); }).catch(function () {}),
    api.get(V6_API.blackbox, { limit: 12, incidents_only: '1' }, { timeout: 7000 }).then(function (r) { if (isStale()) return; v6ApplyBlackboxData(r); }).catch(function () {}),
    api.get(V6_API.multiIface, null, { timeout: 7000 }).then(function (r) { if (isStale()) return; v6ApplyMultiIfaceData(r); }).catch(function () {})
  ]).then(function () {
    if (isStale()) return;
    V6.loaded = true;
    S.v6 = V6;
    v6PaintHeaderBadges();
    v6RefreshDevicesBannerDom();
    if (S.page === 'vector') {
      v6RefreshHeroDom();
      v6RefreshNavBadges();
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
        v6EnsureLeakStream();
      }, 20000);
    };
  } catch (_) {
    V6.sse = null;
    V6.lg.sseActive = false;
    V6.lg.sseFailed = true;
  }
}

function v6EnsureLeakStream() {
  if (!document.hidden && V6.apiSupported.lg) v6StartLeakGuardSSE();
}

function v6StopLeakGuardSSE() {
  clearTimeout(V6.sseRetryT);
  V6.sseRetryT = 0;
  if (V6.sse) {
    try { V6.sse.close(); } catch (_) {}
    V6.sse = null;
  }
  V6.lg.sseActive = false;
  V6.lg.sseFailed = false;
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
  var usb = (typeof isUsbTetherIface === 'function' ? isUsbTetherIface(d.iface) : /(^|_)(rndis|ncm|usb)\d*$/i.test(String(d.iface || '').trim())) ? 'U' : '';
  return pin + esc + lsh + usb;
}

/* 设备列表卡片上的直白中文状态标签 */
function v6DeviceBadgesHtml(d, skipUsb) {
  if (!d) return '';
  var out = '';
  var m = String(d.mac || '').toLowerCase();
  var isUsb = typeof isUsbTetherIface === 'function' ? isUsbTetherIface(d.iface) : /(^|_)(rndis|ncm|usb)\d*$/i.test(String(d.iface || '').trim());
  if (!skipUsb && isUsb) {
    out += '<span class="v6-mono-badge b-acc" title="通过 USB 数据线共享网络（' + escapeHtml(d.iface) + '）">USB 有线共享</span>';
  }
  if (V6.express.enabled) {
    var isPin = V6.express.forced_macs.indexOf(m) >= 0;
    var isAuto = V6.express.escorted_macs.indexOf(m) >= 0;
    if (d.online !== false && (isPin || isAuto)) {
      out += '<span class="v6-mono-badge b-ok" title="游戏与通话低延迟优先转发生效中"><span class="v6-dot ok"></span>' + (isPin ? '常驻优先' : '游戏优先') + '</span>';
    } else if (d.online === false && isPin) {
      out += '<span class="v6-mono-badge" title="已固定常驻优先，设备连入热点后自动生效"><span class="v6-dot idle"></span>常驻优先</span>';
    }
  }
  if (v6IsDeviceLeashed(d)) {
    out += '<span class="v6-mono-badge b-warn" title="后台大体积更新正在温和限速"><span class="v6-dot warn"></span>更新限速</span>';
  }
  return out;
}

function v6ActiveLeashedCount() {
  if (!v6IsHotspotActive() || v6OnlineClientCount() <= 0 || !V6.leash.enabled) return 0;
  if (V6.leash.active_sessions <= 0 && !V6.leash.sessions.length) return 0;
  if (V6.leash.sessions.length) {
    return V6.leash.sessions.filter(function (s) { return s.state === 'leashed'; }).length;
  }
  return Math.max(0, Math.round(num(V6.leash.leashed_count, 0)));
}

/* 设备页顶部紧凑单行人话状态条（诚实反映热点开关与本机守护状态） */
function v6DevicesStripHtml() {
  var hsActive = v6IsHotspotActive();
  var onlineCnt = v6OnlineClientCount();
  var escortCnt = (hsActive && onlineCnt > 0 && V6.express.enabled) ? v6UniqueEscortCount(V6.express) : 0;
  var leashCnt = v6ActiveLeashedCount();
  var unreadLg = v6UnreadLeakHits();
  var curLgCnt = Array.isArray(V6.lg.events) ? V6.lg.events.length : 0;
  var sensorUnreadable = v6IsThermoSensorUnreadable(V6.thermo);
  var effTemp = v6EffectiveTempC(V6.thermo);
  var tempTxt = (!sensorUnreadable && effTemp > 0) ? (effTemp.toFixed(1) + '°C') : '';
  var arbInfo = hsActive ? v6ActiveLimiterInfo() : null;

  var parts = [];
  var dotCls = 'ok';
  if (S.coreHealthy === false) {
    parts.push('部分后台组件降级运行');
    dotCls = 'bad';
  } else if (V6.thermo.enabled && !sensorUnreadable && V6.thermo.stage >= 2) {
    parts.push('机身偏热已启动降温保护' + (tempTxt ? '（' + tempTxt + '）' : ''));
    dotCls = 'bad';
  } else if (!hsActive) {
    parts.push('热点待机中 · 本机守护运行中');
    dotCls = 'acc';
  } else if (onlineCnt <= 0) {
    parts.push('热点已就绪 · 暂无接入设备');
  } else if (arbInfo && arbInfo.active) {
    parts.push('总带宽压速：' + arbInfo.sourceLabel);
    dotCls = 'warn';
  } else if (escortCnt > 0) {
    parts.push('正在为 ' + escortCnt + ' 台设备优先护航');
  } else {
    parts.push('智能护航值守中');
  }

  if (leashCnt > 0) {
    parts.push('已限幅 ' + leashCnt + ' 项大更新');
    if (dotCls === 'ok') dotCls = 'acc';
  } else if (tempTxt && V6.thermo.stage < 2) {
    parts.push('机身 ' + tempTxt);
  }

  if (unreadLg > 0) {
    parts.push('新发现 ' + unreadLg + ' 次明文外发');
    dotCls = 'warn';
  } else if (curLgCnt > 0) {
    parts.push('安检记录 ' + curLgCnt + ' 条');
  }

  var goTarget = unreadLg > 0 ? 'go-privacy' : (!hsActive ? 'go-host' : 'go-vector');
  var ctaLabel = !hsActive && unreadLg <= 0 ? '本机守护 ' : '护航中心 ';
  return '<div class="glass v6-dev-banner press" data-v6-act="' + goTarget + '" role="button" tabindex="0" aria-label="打开智能护航与本机守护">' +
    '<div class="v6-dev-banner-l">' +
      '<span class="v6-dot ' + dotCls + '"></span>' +
      '<span class="txt">' + escapeHtml(parts.join(' · ')) + '</span>' +
    '</div>' +
    '<span class="v6-dev-banner-r">' + ctaLabel + ico('right') + '</span>' +
  '</div>';
}

function v6RefreshDevicesBannerDom() {
  var m = document.getElementById('v6-dev-strip-mount');
  if (m && S.page === 'devices') m.innerHTML = v6DevicesStripHtml();
}

/* 设置页折叠行内部简洁面板（嵌入标准 scard('scard-v6')） */
function v6SettingsBodyHtml() {
  var lgHits = Array.isArray(V6.lg.events) && V6.lg.events.length ? V6.lg.events.length : 0;
  var hsConn = v6HotspotFlowCount();
  var hostConn = v6HostFlowCount();
  return '<div class="row">' +
      '<span class="tx"><div class="t">智能护航与本机守护中心</div>' +
      '<div class="s">集中管理网速护航、本机应用联网防火墙与隐私安检记录（当前 ' + lgHits + ' 条）</div></span>' +
      '<button type="button" class="v6-mini-btn pri press" data-v6-act="go-vector">打开护航页</button>' +
    '</div>' +
    '<div class="row">' +
      '<span class="tx"><div class="t">正交双域活跃连接清理</div>' +
      '<div class="s">热点连接 ' + hsConn + ' 条 · 本机连接 ' + hostConn + ' 条，支持不断网单独掐断或冻结 15 分钟</div></span>' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="open-scalpel" data-scope="all" data-mac="" data-ip="" data-name="">管理连接</button>' +
    '</div>' +
    '<div class="row">' +
      '<span class="tx"><div class="t">整机配置一键备份与恢复</div>' +
      '<div class="s">导出或恢复全部设备备注、本机防火墙规则与智能护航参数</div></span>' +
      '<span style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="backup-export">导出备份</button>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="backup-import-pick">恢复备份</button>' +
      '</span>' +
    '</div>';
}
/* 兼容旧调用点兜底 */
function v6SettingsSlotHtml() { return ''; }

/* ═════════════════════ Layer 0: 顶部诚实三态总览 + 正交双连接胶囊 + 3格磁贴 + 4分区弹簧胶囊 ═════════════════════ */
function v6UniqueEscortCount(ex) {
  ex = ex || V6.express || {};
  var seen = {};
  var a = Array.isArray(ex.escorted_macs) ? ex.escorted_macs : [];
  var checkDevOnline = typeof S !== 'undefined' && S.devLoaded && Array.isArray(S.devices);
  a.forEach(function (m) {
    if (!m) return;
    var ml = String(m).toLowerCase();
    if (checkDevOnline) {
      var d0 = typeof devBy === 'function' ? devBy(ml) : null;
      if (d0 && d0.online === false) return;
    }
    seen[ml] = 1;
  });
  return Object.keys(seen).length;
}

window.v6DeviceEscortStripHtml = function (d) {
  if (!d || !d.mac) return '';
  var ex = V6.express || {};
  var macL = String(d.mac).toLowerCase();
  var isForced = Array.isArray(ex.forced_macs) && ex.forced_macs.some(function (m) { return String(m).toLowerCase() === macL; });
  var isAuto = Array.isArray(ex.escorted_macs) && ex.escorted_macs.some(function (m) { return String(m).toLowerCase() === macL; });
  var isOnline = d.online !== false;
  var ul = V6.leash || {};
  var leashHit = Array.isArray(ul.sessions) && ul.sessions.some(function (s) { return String(s.mac || '').toLowerCase() === macL; });
  var stTxt = isForced
    ? (isOnline ? '已设为常驻优先护航（游戏/会议插队转发）' : '已设为常驻优先（设备离线，连入后自动加速）')
    : (isAuto && ex.enabled && isOnline ? '智能护航自动加速中' : (leashHit ? '后台大更新正在智能限幅，不影响前台浏览' : '未固定常驻优先 · 可一键加入低延迟护航'));
  return '<div class="dev-v6-strip' + ((isForced || (isAuto && ex.enabled)) && isOnline ? ' is-on' : '') + '">' +
    '<span class="dev-v6-l"><i class="dev-v6-dot"></i><span>' + escapeHtml(stTxt) + '</span></span>' +
    '<button type="button" class="dev-v6-btn press' + (isForced ? ' on' : '') + '" data-v6-act="express-dev" data-mac="' + escapeHtml(d.mac) + '">' + (isForced ? '已常驻优先' : '设为常驻优先') + '</button>' +
  '</div>';
};

function v6RenderLatencyCompareHtml() {
  var rawAr = (typeof S !== 'undefined' && S.autorate) ? S.autorate : null;
  var ar = (rawAr && rawAr.enabled === true) ? rawAr : {};
  var ex = V6.express || {};
  var bb = V6.blackbox || {};
  var hsActive = v6IsHotspotActive();
  var onlineCnt = v6OnlineClientCount();
  var baseRtt = num(ar.base_rtt_ms, 0);
  var curRtt = num(ar.rtt_ms, 0);
  var hasRealRtt = hsActive && baseRtt > 0 && curRtt > 0;
  var jitterMs = bb.rtt_probe_active === false ? 0 : num(bb.latest_jitter_ms, 0);
  var incCnt = Math.round(num(bb.incident_count, 0));

  if (!hsActive) {
    return '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot idle"></span><span>当前未开启热点，网速护航队列处于零唤醒待机；开启热点后自动接管转发优先级</span></span></div>';
  }
  if (onlineCnt <= 0 && !hasRealRtt) {
    return '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ' + (ex.enabled ? 'ok' : 'idle') + '"></span><span>热点已开启，等待设备接入后自动守护游戏通话低延迟</span></span></div>';
  }
  if (!hasRealRtt && !(jitterMs > 0) && !(incCnt > 0)) {
    return '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ' + (ex.enabled ? 'ok' : 'idle') + '"></span><span>当前网络通畅，暂无排队拥塞波动' + (ex.enabled ? '（优先护航待命中）' : '（开启后遇拥塞自动插队保护）') + '</span></span></div>';
  }
  if (hasRealRtt) {
    var delta = Math.max(0, Math.round(curRtt - baseRtt));
    var congested = delta >= 25;
    var badgeCls = congested ? 'b-warn' : 'b-ok';
    var badgeTxt = congested ? ('排队增量 +' + delta + 'ms') : (ex.enabled ? '延迟平稳' : '当前平稳');
    return '<div class="v6-lat-cmp">' +
      '<div class="v6-lat-top">' +
        '<div><b>实时延迟与拥塞观测</b><small>实测基线 ' + Math.round(baseRtt) + 'ms · 当前 ' + Math.round(curRtt) + 'ms' + (jitterMs > 0 ? (' · 抖动 ' + jitterMs.toFixed(1) + 'ms') : '') + '</small></div>' +
        '<span class="badge ' + badgeCls + '">' + badgeTxt + '</span>' +
      '</div>' +
    '</div>';
  }
  return '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ' + (incCnt > 0 ? 'warn' : 'ok') + '"></span><span>' + (incCnt > 0 ? ('近期已捕捉 ' + incCnt + ' 次短暂延迟波动' + (jitterMs > 0 ? (' · 最新抖动 ' + jitterMs.toFixed(1) + 'ms') : '')) : ('最新采样抖动 ' + jitterMs.toFixed(1) + 'ms · 当前网络整体平稳')) + '</span></span></div>';
}

function v6HeroHeadlineInfo() {
  var hsActive = v6IsHotspotActive();
  var onlineCnt = v6OnlineClientCount();
  var escortCnt = (hsActive && onlineCnt > 0 && V6.express.enabled) ? v6UniqueEscortCount(V6.express) : 0;
  var leashCnt = v6ActiveLeashedCount();
  var unreadLg = v6UnreadLeakHits();
  var effTemp = v6EffectiveTempC(V6.thermo);

  if (S.coreHealthy === false) {
    return { dot: 'bad', title: '部分底层服务异常，已自动隔离降级', sub: '基础联网不受影响，点击右侧状态按钮可查看具体模块' };
  }
  if (V6.thermo.enabled && !v6IsThermoSensorUnreadable(V6.thermo) && V6.thermo.stage >= 2) {
    return {
      dot: 'bad',
      title: '机身温度偏高（' + effTemp.toFixed(1) + '°C），正在自动降载降温',
      sub: hsActive ? '已温和收紧后台大流量下载，防止系统过热强关热点' : '热点待机中 · 本机温控巡航与后台守护持续运行'
    };
  }
  if (!hsActive) {
    if (unreadLg > 0) {
      return {
        dot: 'warn',
        title: '热点待机中 · 新发现 ' + unreadLg + ' 次明文外发',
        sub: '热点未开启；本机应用联网监测与隐私安检正在值守，可在下方查看拦截'
      };
    }
    return {
      dot: 'ok',
      title: '热点待机中 · 本机守护运行中',
      sub: '热点关闭时护航队列零额外耗电；本机应用联网、防火墙与明文安检正常值守'
    };
  }
  if (onlineCnt <= 0) {
    if (unreadLg > 0) {
      return {
        dot: 'warn',
        title: '热点已就绪 · 新发现 ' + unreadLg + ' 次明文外发',
        sub: '当前暂无设备连入热点；可在下方查看本机守护或隐私安检记录'
      };
    }
    return {
      dot: 'ok',
      title: '热点已就绪 · 暂无接入设备',
      sub: '智能护航静默待命，设备连入后将自动保护游戏通话并限制后台大更新'
    };
  }
  if (escortCnt > 0 && leashCnt > 0) {
    return { dot: 'ok', title: '正在为 ' + escortCnt + ' 台设备优先护航，并限幅 ' + leashCnt + ' 项后台更新', sub: '游戏与视频通话优先转发，后台下载不抢网速' };
  }
  if (escortCnt > 0) {
    return { dot: 'ok', title: '正在为 ' + escortCnt + ' 台设备优先护航', sub: '检测到活跃实时流量，已开启低延迟插队转发' };
  }
  if (leashCnt > 0) {
    return { dot: 'acc', title: '已自动限幅 ' + leashCnt + ' 项大体积后台更新', sub: '日常浏览、视频与通话网速保持顺畅' };
  }
  if (unreadLg > 0) {
    return { dot: 'warn', title: '热点守护 ' + onlineCnt + ' 台设备 · 新发现 ' + unreadLg + ' 次明文外发', sub: '可在下方「隐私安检」查看具体应用域名并一键拦截' };
  }
  return { dot: 'ok', title: '热点网络通畅 · 正在守护 ' + onlineCnt + ' 台设备', sub: '有人打游戏、开视频会议或遇到大更新时将自动介入保护网速' };
}

function v6BulkheadHumanHtml() {
  var dpTierTxt = v6DataplaneTierZh(V6.express && V6.express.tier);
  var map = [
    ['dataplane', '流量限速引擎' + (dpTierTxt ? '（' + dpTierTxt + '）' : '')],
    ['dpi_shm', '应用识别引擎'],
    ['android_bridge', '系统热点桥接'],
    ['storage', '规则配置存储']
  ];
  var bh = (S.bulkheads && typeof S.bulkheads === 'object') ? S.bulkheads : null;
  var pills = map.map(function (it) {
    var st = bh ? bh[it[0]] : null;
    var ok = !st || (st.healthy !== false && st.circuit_state !== 'open');
    return '<span class="v6-mono-badge ' + (ok ? 'b-ok' : 'b-bad') + '"><span class="v6-dot ' + (ok ? 'ok' : 'bad') + '"></span>' + escapeHtml(it[1]) + '：' + (ok ? '正常' : '降级') + '</span>';
  }).join('');
  var upMin = S.coreUptimeSec > 0 ? Math.max(1, Math.floor(S.coreUptimeSec / 60)) : 0;
  return '<div style="display:flex;flex-wrap:wrap;gap:6px">' + pills + '</div>' +
    (upMin > 0 ? '<span class="note" style="margin:0">已稳定运行 ' + upMin + ' 分钟</span>' : '');
}

function v6RenderArbiterBarHtml() {
  if (!v6IsHotspotActive()) return '';
  var arb = v6ActiveLimiterInfo();
  if (!arb || !arb.active) return '';
  var ceilParts = [];
  if (arb.down_mbps > 0) ceilParts.push('下行上限 ' + trim0(arb.down_mbps.toFixed(1)) + ' Mbps');
  if (arb.up_mbps > 0) ceilParts.push('上行上限 ' + trim0(arb.up_mbps.toFixed(1)) + ' Mbps');
  var srcExtra = (arb.sources && arb.sources.length > 1)
    ? (' · 参与仲裁：' + arb.sources.map(function (s) { return s.label; }).filter(Boolean).join(' / '))
    : '';
  return '<div class="v6-lat-cmp" data-mkey="v6-arbiter-bar">' +
    '<div class="v6-lat-top">' +
      '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">' +
        '<span class="v6-dot warn"></span>' +
        '<b>当前总带宽压速来源：' + escapeHtml(arb.sourceLabel) + '</b>' +
      '</div>' +
      (ceilParts.length ? '<span class="v6-mono-badge b-warn">' + escapeHtml(ceilParts.join(' · ')) + '</span>' : '<span class="v6-mono-badge b-warn">自动控速生效中</span>') +
    '</div>' +
    '<div class="note" style="margin:4px 0 0;color:var(--text-2)">' + escapeHtml(arb.reason + srcExtra) + '</div>' +
  '</div>';
}

function v6RenderHeroCardHtml() {
  var hl = v6HeroHeadlineInfo();
  var allOk = S.coreHealthy !== false;
  var showHealth = V6.healthOpen || !allOk;
  var hsActive = v6IsHotspotActive();
  var onlineCnt = v6OnlineClientCount();
  var hsConns = v6HotspotFlowCount();
  var hostConns = v6HostFlowCount();

  var expCnt = (hsActive && onlineCnt > 0 && V6.express.enabled) ? v6UniqueEscortCount(V6.express) : 0;
  var expSub = !V6.express.enabled
    ? '已关闭 · 点击开启'
    : (expCnt > 0 ? ('已开启 · ' + expCnt + ' 台加速') : (V6.express.auto_detect ? '已开启 · 自动识别' : '已开启 · 手动指定'));

  var leashActCnt = v6ActiveLeashedCount();
  var leashGraceStr = V6.leash.grace_mb >= 1024 ? (trim0((V6.leash.grace_mb / 1024).toFixed(1)) + 'G') : (V6.leash.grace_mb + 'M');
  var leashSub = !V6.leash.enabled
    ? '已关闭 · 点击开启'
    : (leashActCnt > 0 ? ('限幅中 ' + leashActCnt + ' 项') : ('已开启 · 超' + leashGraceStr + '限幅'));

  var sensorUnreadable = v6IsThermoSensorUnreadable(V6.thermo);
  var effTemp = v6EffectiveTempC(V6.thermo);
  var tempShort = sensorUnreadable ? '传感器异常' : (effTemp > 0 ? (effTemp.toFixed(1) + '°C') : '待采样');
  var batShort = V6.thermo.capacity_pct > 0 ? (V6.thermo.capacity_pct + '%') : '';
  var thSub = !V6.thermo.enabled
    ? ('已关闭 · ' + tempShort)
    : (sensorUnreadable
      ? '已安全跳过控温'
      : (V6.thermo.stage >= 2
        ? (tempShort + ' · 降温中')
        : (tempShort + (batShort ? (' · ' + batShort) : ' · 正常'))));
  var thStateCls = (!sensorUnreadable && V6.thermo.stage >= 2) ? 'th-hot' : ((!sensorUnreadable && V6.thermo.stage === 1) ? 'th-warn' : 'th-ok');
  var bSvg = typeof bentoSvg === 'function' ? bentoSvg : function (k) { return v6Svg(k === 'sqm' ? 'express' : k); };

  return '<div class="glass hero v6-hero" id="v6-hero-card">' +
    '<div class="v6-hero-top">' +
      '<div class="v6-hero-headline">' +
        '<div class="v6-hero-title"><span class="v6-dot ' + hl.dot + '"></span><span>' + escapeHtml(hl.title) + '</span></div>' +
        '<div class="v6-hero-sub">' + escapeHtml(hl.sub) + '</div>' +
      '</div>' +
      '<button type="button" class="v6-health-pill press" data-v6-act="toggle-health">' +
        '<span class="v6-dot ' + (allOk ? 'ok' : 'bad') + '"></span>' +
        '<span>' + (allOk ? '系统正常' : '查看异常') + '</span>' +
      '</button>' +
    '</div>' +
    '<div class="v6-health-drawer" id="v6-health-drawer"' + (showHealth ? '' : ' hidden') + '>' + v6BulkheadHumanHtml() + '</div>' +
    v6RenderArbiterBarHtml() +
    '<div class="v6-conn-pair" role="group" aria-label="正交双域活跃连接概览">' +
      '<button type="button" class="v6-conn-pill press" data-v6-act="open-scalpel" data-scope="hotspot" data-mac="" data-ip="" data-name="">' +
        '<span class="v6-conn-pill-l"><span class="v6-dot ' + (hsActive && onlineCnt > 0 ? 'ok' : 'idle') + '"></span><span>热点连接</span></span>' +
        '<span class="v6-conn-pill-r"><span>' + hsConns + '</span>' + ico('right') + '</span>' +
      '</button>' +
      '<button type="button" class="v6-conn-pill press" data-v6-act="open-scalpel" data-scope="host" data-mac="" data-ip="" data-name="">' +
        '<span class="v6-conn-pill-l"><span class="v6-dot acc"></span><span>本机连接</span></span>' +
        '<span class="v6-conn-pill-r"><span>' + hostConns + '</span>' + ico('right') + '</span>' +
      '</button>' +
    '</div>' +
    '<div class="cc-bento-row" role="group" aria-label="核心护航快捷控制">' +
      '<button type="button" class="cc-tile sqm-tile press' + (V6.express.enabled ? ' on sqm-on' : '') + '" data-v6-tile="express">' +
        '<span class="cc-orb">' + bSvg('sqm') + '</span>' +
        '<span class="cc-txt"><b>游戏通话优先</b><small>' + escapeHtml(expSub) + '</small></span>' +
      '</button>' +
      '<button type="button" class="cc-tile qos-tile press' + (V6.leash.enabled ? ' on qos-on' : '') + '" data-v6-tile="leash">' +
        '<span class="cc-orb">' + bSvg('leash') + '</span>' +
        '<span class="cc-txt"><b>后台更新限幅</b><small>' + escapeHtml(leashSub) + '</small></span>' +
      '</button>' +
      '<button type="button" class="cc-tile th-tile press' + (V6.thermo.enabled ? (' on ' + thStateCls) : '') + '" data-v6-tile="thermo">' +
        '<span class="cc-orb">' + bSvg('thermo') + '</span>' +
        '<span class="cc-txt"><b>机身温控</b><small>' + escapeHtml(thSub) + '</small></span>' +
      '</button>' +
    '</div>' +
  '</div>';
}

function v6BuildMainSegLabel(tabKey) {
  if (tabKey === 'escort') return '网速护航';
  if (tabKey === 'host') {
    var fwCnt = Math.max(0, num(V6.host.firewall.uid_rule_count, 0) + num(V6.host.firewall.blocked_domain_count, 0));
    return '本机守护' + (fwCnt > 0 ? ('<span class="v6-seg-cnt">' + (fwCnt > 99 ? '99+' : fwCnt) + '</span>') : '');
  }
  if (tabKey === 'privacy') {
    var lgUnread = v6UnreadLeakHits();
    if (lgUnread > 0) return '隐私安检<span class="v6-seg-cnt unread">' + (lgUnread > 99 ? '99+' : lgUnread) + '</span>';
    return '隐私安检';
  }
  var scCnt = Math.max(0, num(V6.scalpel.activeRulesCount, 0));
  return '连接排障' + (scCnt > 0 ? ('<span class="v6-seg-cnt">' + scCnt + '</span>') : '');
}

function v6RenderMainSegHtml() {
  return seg('v6-tab', [
    ['escort', v6BuildMainSegLabel('escort')],
    ['host', v6BuildMainSegLabel('host')],
    ['privacy', v6BuildMainSegLabel('privacy')],
    ['troubleshoot', v6BuildMainSegLabel('troubleshoot')]
  ], V6.subtab, 'glass');
}

/* 就地更新分段器按钮文字角标且不破坏 <i class="thumb"> 弹簧变换状态 */
function v6RefreshNavBadges() {
  var nav = document.getElementById('v6-nav-mount');
  if (!nav || S.page !== 'vector') return;
  var segEl = nav.querySelector('[data-seg="v6-tab"]');
  if (!segEl) return;
  ['escort', 'host', 'privacy', 'troubleshoot'].forEach(function (k) {
    var btn = segEl.querySelector('button[data-v="' + k + '"]');
    if (!btn) return;
    var nextHtml = v6BuildMainSegLabel(k);
    if (btn.innerHTML !== nextHtml) btn.innerHTML = nextHtml;
    btn.classList.toggle('on', V6.subtab === k);
  });
  if (typeof placeSegs === 'function') placeSegs(nav);
}

/* ═════════════════════ Sub-Tab 1: 网速护航 (全站标准 .sgrp.scard.glass 卡片) ═════════════════════ */
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

  if (v6IsHotspotActive()) {
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
  }
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
  }).join('') : '<div class="note" style="margin:0">当前暂无在线设备；设备连入热点后可点选固定为常驻优先</div>';

  var qdiscHuman = ex.qdisc === 'fq_codel' ? '智能防卡顿队列 (fq_codel)' : escapeHtml(ex.qdisc || '标准队列');
  var tierHuman = v6DataplaneTierZh(ex.tier);
  return '<div class="sgrp scard glass open" id="v6-card-express">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi('green', 'bolt') +
      '<span class="tx"><b>游戏与视频优先</b><small>识别到手游对局或音视频会议时插队转发，其他设备下载不抢网</small></span>' +
      toggle(ex.enabled, 'data-v6-tog="express" aria-label="游戏与视频优先总开关"') +
    '</div>' +
    '<div class="v6-scard-body">' +
      '<div class="lgd-sw-row' + (ex.enabled ? '' : ' v6-dimmed') + '">' +
        '<span>自动识别手游与音视频会议<small>无需手动配置，检测到实时互动流量自动介入护航</small></span>' +
        toggle(ex.auto_detect, 'data-v6-tog="express-auto" aria-label="自动识别手游与音视频会议"' + (ex.enabled ? '' : ' disabled')) +
      '</div>' +
      '<div class="' + (ex.enabled ? '' : 'v6-dimmed') + '">' +
        '<div class="note" style="margin:0 0 6px">' + (ex.enabled ? '点按设备可固定为「常驻优先」（再次点按解除）：' : '总开关已关闭 · 点选任意设备将自动重新开启优先护航：') + '</div>' +
        '<div class="v6-dev-pills">' + devPillsHtml + '</div>' +
      '</div>' +
      v6RenderLatencyCompareHtml() +
      '<details class="v6-adv-fold" data-v6-fold="exp"' + (V6.advOpen.exp ? ' open' : '') + '>' +
        '<summary><span>底层队列与调度详情</span><span class="v6-adv-r"><span>' + (ex.active ? '护航生效中' : '闲时全速') + (tierHuman ? ' · ' + escapeHtml(tierHuman) : '') + '</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
        '<div class="v6-adv-body">' +
          '<div class="v6-kpi-row">' +
            '<div class="v6-kpi is-ok"><span>优先设备数</span><b>' + v6UniqueEscortCount(ex) + '<small>台</small></b></div>' +
            '<div class="v6-kpi is-acc"><span>护航时后台上限</span><b>' + (ex.active ? ex.bg_ceil_pct : ex.configured_bg_ceil_pct) + '<small>%</small></b></div>' +
            '<div class="v6-kpi"><span>累计自动介入</span><b>' + num(ex.transitions) + '<small>次</small></b></div>' +
          '</div>' +
          '<div class="note" style="margin:0">' + (tierHuman ? ('数据面档位：' + escapeHtml(tierHuman) + ' · ') : '') + '队列算法：' + qdiscHuman + (ex.cooldown_remaining_sec > 0 ? (' · 对局结束平稳过渡剩余 ' + ex.cooldown_remaining_sec + ' 秒') : ' · P2P 多节点下载自动排除防误判') + '</div>' +
        '</div>' +
      '</details>' +
    '</div>' +
  '</div>';
}

function v6RenderLeashCardHtml() {
  var ul = V6.leash;
  var sessHtml = '';
  if (!ul.enabled) {
    sessHtml = '<div class="lgd-summary-line"><span>后台大下载限幅已关闭，所有系统与商店下载均不限制速度</span></div>';
  } else if (!v6IsHotspotActive() || !ul.sessions.length) {
    sessHtml = '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ok"></span><span>当前没有大体积后台更新在跑，日常小补丁将在 ' + ul.grace_mb + ' MB 高速额度内秒下完成</span></span></div>';
  } else {
    sessHtml = '<div class="v6-flow-list">' + ul.sessions.map(function (s) {
      var stBadge = s.paused
        ? '<span class="v6-mono-badge b-bad">已暂停下载</span>'
        : (s.bypass_once
          ? '<span class="v6-mono-badge b-ok">本次不限速</span>'
          : (s.state === 'leashed'
            ? '<span class="v6-mono-badge b-warn">已限幅 ' + trim0((s.applied_kbps / 1000).toFixed(1)) + ' Mbps</span>'
            : '<span class="v6-mono-badge b-acc">高速额度内（剩 ' + Math.max(0, Math.round(s.rem_mb)) + ' MB）</span>'));
      var srcTitle = s.vendor_label || s.dst_host;
      return '<div class="v6-flow-item">' +
        '<div class="v6-flow-main">' +
          '<div class="v6-flow-t">' + stBadge + '<span>' + escapeHtml(s.devName) + ' · ' + escapeHtml(srcTitle) + '</span></div>' +
          '<div class="v6-flow-s">已下载 ' + s.down_mb.toFixed(0) + ' MB · ' + escapeHtml(s.dst_host) + ' · 当前 ' + (s.cur_kbps > 0 ? (trim0((s.cur_kbps / 1000).toFixed(2)) + ' Mbps') : '0 Mbps') + '</div>' +
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

  return '<div class="sgrp scard glass open" id="v6-card-leash">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi('blue', 'leash') +
      '<span class="tx"><b>后台大下载自动限幅</b><small>前 ' + ul.grace_mb + ' MB 高速放行小补丁，超出后平滑限幅至 ' + trim0((ul.leash_kbps / 1000).toFixed(1)) + ' Mbps</small></span>' +
      toggle(ul.enabled, 'data-v6-tog="leash" aria-label="后台大下载自动限幅总开关"') +
    '</div>' +
    '<div class="v6-scard-body">' +
      sessHtml +
      '<details class="v6-adv-fold" data-v6-fold="leash"' + (V6.advOpen.leash ? ' open' : '') + '>' +
        '<summary><span>修改免限速额度与限幅速度</span><span class="v6-adv-r"><span>' + ul.grace_mb + ' MB / ' + ul.leash_kbps + ' Kbps</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
        '<div class="v6-adv-body">' +
          '<div class="v6-quick-chips"><span class="note" style="margin:0">常用额度：</span>' + presetChips + '</div>' +
          '<div class="v6-num-grid">' +
            '<label class="v6-num-field"><span>免限速高速额度</span><span class="v6-num-box"><input id="v6-ul-grace" type="number" min="10" max="10240" step="10" inputmode="numeric" value="' + ul.grace_mb + '"><span class="u">MB</span></span></label>' +
            '<label class="v6-num-field"><span>超额后限幅值（1500 ≈ 1.5Mbps）</span><span class="v6-num-box"><input id="v6-ul-kbps" type="number" min="128" max="1000000" step="100" inputmode="numeric" value="' + ul.leash_kbps + '"><span class="u">Kbps</span></span></label>' +
          '</div>' +
          '<div style="display:flex;justify-content:flex-end">' +
            '<button type="button" class="btn sm pri press" data-v6-act="leash-save">保存限幅设置</button>' +
          '</div>' +
        '</div>' +
      '</details>' +
    '</div>' +
  '</div>';
}

function v6RenderThermoCardHtml() {
  var th = V6.thermo;
  var sensorUnreadable = v6IsThermoSensorUnreadable(th);
  var effTemp = v6EffectiveTempC(th);
  var hasTemp = !sensorUnreadable && effTemp > 0;
  var batStr = th.capacity_pct > 0 ? (th.capacity_pct + '%') : '';
  var stBadgeCls = !th.enabled || sensorUnreadable || !hasTemp
    ? ''
    : (th.stage >= 2 ? 'b-bad' : (th.stage === 1 ? 'b-warn' : 'b-ok'));
  var stDotCls = !th.enabled || sensorUnreadable || !hasTemp
    ? 'idle'
    : (th.stage >= 2 ? 'bad' : (th.stage === 1 ? 'warn' : 'ok'));

  var tempBadges = '';
  if (!sensorUnreadable) {
    if (th.shell_temp_available && th.shell_temp_c > 0) {
      tempBadges += '<span class="v6-mono-badge b-acc">机身壳温 ' + th.shell_temp_c.toFixed(1) + '°C</span>';
      if (th.battery_temp_c > 0) {
        tempBadges += '<span class="v6-mono-badge">电池传感器 ' + th.battery_temp_c.toFixed(1) + '°C</span>';
      }
    } else if (hasTemp) {
      tempBadges += '<span class="v6-mono-badge">当前温度 ' + effTemp.toFixed(1) + '°C</span>';
    }
  }

  var extraNotes = '';
  if (sensorUnreadable) {
    var sensorHint = th.reason_zh || (th.reason_code ? ('诊断码：' + th.reason_code) : '内核温控节点未暴露或读数越界，已安全跳过温控降速保护');
    extraNotes += '<div class="note" style="margin:0;color:var(--text-3)">' + escapeHtml(sensorHint) + '</div>';
  } else {
    if (th.battery_spoof_suspected) {
      extraNotes += '<div class="note" style="margin:0;color:var(--text-2)">检测到电池温度读数偏低，已自动采用机身真实温度巡航</div>';
    }
    if (th.enabled && th.raw_stage >= 2 && th.stage < 2 && th.stage2_exempt) {
      extraNotes += '<div class="note" style="margin:0;color:var(--badge-warn)">机身温度已达二级降温线，因当前正在' + (th.is_charging ? '充电' : '游戏/通话优先护航') + '，暂不限制网速以保证体验</div>';
    } else if (th.cool_hold_remaining_sec > 0) {
      extraNotes += '<div class="note" style="margin:0">温度正在回落，稳态观察剩余 ' + th.cool_hold_remaining_sec + ' 秒（防止临界温度反复跳变）</div>';
    }
  }

  var giColor = (!sensorUnreadable && th.stage >= 2) ? 'red' : 'orange';
  return '<div class="sgrp scard glass open" id="v6-card-thermo">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi(giColor, 'thermo') +
      '<span class="tx"><b>高温与低电量自动保护</b><small>开热点机身发烫时自动降低后台负载降温，插电或游戏中自动豁免</small></span>' +
      toggle(th.enabled, 'data-v6-tog="thermo" aria-label="高温与低电量自动保护总开关"') +
    '</div>' +
    '<div class="v6-scard-body">' +
      '<div class="v6-thermo-flags">' +
        '<span class="v6-mono-badge ' + stBadgeCls + '"><span class="v6-dot ' + stDotCls + '"></span>' + escapeHtml(sensorUnreadable ? '温度传感器不可读（已安全跳过控温）' : v6ThermoStageZh(th.stage)) + '</span>' +
        tempBadges +
        (batStr ? '<span class="v6-mono-badge">电量 ' + escapeHtml(batStr) + (th.is_charging ? ' · 充电中不限速' : '') + '</span>' : '') +
        (th.vector_express_active ? '<span class="v6-mono-badge b-ok">游戏通话中 · 不限速</span>' : '') +
        (th.low_battery_cruise ? '<span class="v6-mono-badge b-warn">低电量省电中</span>' : '') +
      '</div>' +
      extraNotes +
      '<details class="v6-adv-fold" data-v6-fold="thermo"' + (V6.advOpen.thermo ? ' open' : '') + '>' +
        '<summary><span>修改温控触发阈值</span><span class="v6-adv-r"><span>' + th.stage1_temp_c + '°C 省电 / ' + th.stage2_temp_c + '°C 降温</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
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
            '<button type="button" class="btn sm pri press" data-v6-act="thermo-save">保存温度阈值</button>' +
          '</div>' +
        '</div>' +
      '</details>' +
    '</div>' +
  '</div>';
}

/* ═════════════════════ Sub-Tab 2: 本机守护 (Host Guardian 全功能工作台 · 严守零唤醒租约纪律) ═════════════════════ */
var V6_APP_AV_GRADS = [
  'linear-gradient(145deg,#0a84ff,#0066cc)',
  'linear-gradient(145deg,#34c759,#1f9d55)',
  'linear-gradient(145deg,#ff9f0a,#e07a00)',
  'linear-gradient(145deg,#af52de,#8938b8)',
  'linear-gradient(145deg,#00c7be,#00968f)',
  'linear-gradient(145deg,#ff453a,#d72b2b)'
];

function v6AppAvatarHtml(name, pkg, uid) {
  var raw = String(name || pkg || 'A').trim();
  var ch = raw.charAt(0).toUpperCase();
  if (/^com\.|^org\.|^net\.|^io\./i.test(raw)) {
    var segs = raw.split('.');
    var tail = segs[segs.length - 1] || raw;
    ch = tail.charAt(0).toUpperCase();
  }
  var seed = Math.abs(Math.round(num(uid, 0)) || raw.charCodeAt(0) || 0);
  var bg = V6_APP_AV_GRADS[seed % V6_APP_AV_GRADS.length];
  return '<span class="v6-app-ic" style="background:' + bg + '" aria-hidden="true">' + escapeHtml(ch || 'A') + '</span>';
}

function v6NormFwMode(mode) {
  var m = String(mode || 'allow').toLowerCase().trim();
  if (m === 'block_http' || m === 'cleartext' || m === 'block_cleartext') return 'block_cleartext';
  if (m === 'block_mobile' || m === 'cellular' || m === 'block_cellular') return 'block_cellular';
  if (m === 'block_all' || m === 'deny' || m === 'all') return 'block_all';
  return 'allow';
}

function v6FwModeBadgeHtml(mode) {
  var m = v6NormFwMode(mode);
  if (m === 'block_cleartext') return '<span class="v6-mono-badge b-acc">仅禁明文</span>';
  if (m === 'block_cellular') return '<span class="v6-mono-badge b-warn">禁移动网</span>';
  if (m === 'block_all') return '<span class="v6-mono-badge b-bad">全局禁网</span>';
  return '';
}

function v6FwModeZh(mode) {
  var m = v6NormFwMode(mode);
  if (m === 'block_cleartext') return '仅禁明文HTTP';
  if (m === 'block_cellular') return '禁移动数据';
  if (m === 'block_all') return '全局禁网';
  return '正常放行';
}

function v6LookupHostUidRule(uid) {
  var u = Math.round(num(uid, -1));
  if (u < 0 || !V6.host || !V6.host.firewall || !V6.host.firewall.uid_map) return null;
  var r = V6.host.firewall.uid_map[String(u)];
  if (r) return r;
  var appId = u % 100000;
  if (appId >= 20000 && appId <= 29999) {
    return V6.host.firewall.uid_map[String(u - 10000)] || null;
  }
  return null;
}

function v6HostUidMode(uid) {
  var r = v6LookupHostUidRule(uid);
  return r ? v6NormFwMode(r.mode) : 'allow';
}

function v6HostUidBlockTargets(uid) {
  var r = v6LookupHostUidRule(uid);
  return (r && Array.isArray(r.block_targets)) ? r.block_targets : [];
}

function v6IsHostDomainBlocked(hostRaw) {
  if (!V6.host || !V6.host.firewall || !V6.host.firewall.blocked_set) return false;
  var s = String(hostRaw || '').trim().toLowerCase();
  if (!s || s === '-' || s === '—') return false;
  if (v6ExtractPureIp(s)) return false;
  if (s.indexOf(':') >= 0) s = s.split(':')[0];
  s = s.replace(/^\.+|\.+$/g, '');
  if (!s) return false;
  var bSet = V6.host.firewall.blocked_set;
  var cur = s;
  while (cur) {
    if (bSet[cur]) return true;
    var dot = cur.indexOf('.');
    if (dot < 0 || dot + 1 >= cur.length) break;
    cur = cur.slice(dot + 1);
  }
  return false;
}

function v6IsHostIpTargetBlocked(uid, ipOrHostRaw) {
  var u = Math.round(num(uid, 0));
  if (u <= 0) return false;
  var rawLow = String(ipOrHostRaw || '').trim().toLowerCase();
  if (!rawLow || rawLow === '-' || rawLow === '—') return false;
  var pureIp = v6ExtractPureIp(rawLow).toLowerCase();
  if (V6.lg && V6.lg.blocked_set) {
    if (V6.lg.blocked_set['uid:' + u + '|' + rawLow]) return true;
    if (pureIp && V6.lg.blocked_set['uid:' + u + '|' + pureIp]) return true;
  }
  var targets = v6HostUidBlockTargets(u);
  for (var i = 0; i < targets.length; i++) {
    var tLow = String(targets[i] || '').trim().toLowerCase();
    if (!tLow) continue;
    if (tLow === rawLow) return true;
    if (pureIp && (tLow === pureIp || v6ExtractPureIp(tLow).toLowerCase() === pureIp)) return true;
  }
  return false;
}

function v6IsCleartextHttpPortProto(port, proto) {
  var lp = String(proto || '').trim().toLowerCase();
  if (lp && lp !== 'tcp' && lp !== 'http') return false;
  var p = Math.round(num(port, 0));
  return p === 0 || p === 80 || p === 8080 || p === 8000 || p === 8008 || p === 8888;
}

function v6HostAppBlockingModeForEvent(uid, port, proto) {
  var u = Math.round(num(uid, 0));
  if (u <= 0 || v6IsHostAppProtected(u, '')) return '';
  var m = v6HostUidMode(u);
  if (m === 'block_all') return 'block_all';
  if (m === 'block_cleartext' && v6IsCleartextHttpPortProto(port, proto)) return 'block_cleartext';
  return '';
}

function v6ClassifyHostLeakBlockState(ev) {
  if (!ev || ev.origin !== 'host') {
    return { targetBlocked: !!(ev && ev.is_blocked), appMode: '', appOnlyBlocked: false };
  }
  var evUid = Math.round(num(ev.uid, 0));
  var primaryHost = String(ev.dst_host && ev.dst_host !== '—' ? ev.dst_host : ev.dst_ip).trim();
  var pureIp = v6ExtractPureIp(primaryHost);
  var targetBlocked = pureIp
    ? v6IsHostIpTargetBlocked(evUid, primaryHost)
    : (v6IsHostDomainBlocked(primaryHost) || (ev.dst_ip ? v6IsHostIpTargetBlocked(evUid, ev.dst_ip) : false));
  var appMode = v6HostAppBlockingModeForEvent(evUid, ev.dst_port, ev.proto);
  return {
    targetBlocked: targetBlocked,
    appMode: appMode,
    appOnlyBlocked: !targetBlocked && !!appMode
  };
}

function v6SyncHostLeakEventsBlocked() {
  if (!V6.lg || !Array.isArray(V6.lg.events)) return;
  V6.lg.events.forEach(function (ev) {
    if (!ev || ev.origin !== 'host') return;
    var st = v6ClassifyHostLeakBlockState(ev);
    ev.is_blocked = !!(st.targetBlocked || st.appMode);
  });
}

function v6IsHostAppProtected(uid, pkg) {
  var u = Math.round(num(uid, 0));
  var appId = u >= 0 ? (u % 100000) : -1;
  if (u >= 0 && (appId < 10000 || appId >= 90000)) return true;
  var p = v6CleanHostRealPkg(pkg).toLowerCase();
  if (!p) return false;
  var list = V6.host.firewall.protected_packages || [];
  for (var i = 0; i < list.length; i++) {
    if (String(list[i] || '').toLowerCase() === p) return true;
  }
  return false;
}

function v6IsSheetShowing() {
  if (V6.appSheet && V6.appSheet.open) return true;
  if (V6.host.appSheet && V6.host.appSheet.open) return true;
  if (typeof document !== 'undefined') {
    var sh = document.getElementById('sheet');
    if (sh && sh.classList && sh.classList.contains('show')) return true;
  }
  return false;
}

function v6FmtDurMs(ms) {
  var sec = Math.max(0, Math.round(num(ms, 0) / 1000));
  if (sec <= 0) return '0 秒';
  if (sec < 60) return sec + ' 秒';
  var m = Math.floor(sec / 60), s = sec % 60;
  if (m < 60) return m + ' 分' + (s > 0 && m < 10 ? (' ' + s + ' 秒') : '');
  var h = Math.floor(m / 60), rm = m % 60;
  return h + ' 小时' + (rm > 0 ? (' ' + rm + ' 分') : '');
}

/* 零唤醒租约定时器：仅当停留在「护航 -> 本机守护」且页面可见时续租 2.5s 采样，离开即刻归零 */
function v6SyncHostPollTimer() {
  var shouldPoll = (typeof S !== 'undefined' && S.page === 'vector' && V6.subtab === 'host' && !document.hidden);
  if (!shouldPoll) {
    if (V6.host.pollTimer) {
      clearInterval(V6.host.pollTimer);
      V6.host.pollTimer = 0;
    }
    return;
  }
  if (!V6.host.pollTimer) {
    V6.host.pollTimer = setInterval(function () {
      if (typeof S === 'undefined' || S.page !== 'vector' || V6.subtab !== 'host' || document.hidden) {
        clearInterval(V6.host.pollTimer);
        V6.host.pollTimer = 0;
        return;
      }
      if (!V6.host.trafficLoading && (V6.host.mode === 'live' || V6.host.mode === 'traffic')) {
        v6LoadHostTraffic(false);
      }
    }, 2500);
  }
}

function v6LoadHostTraffic(manual) {
  if (V6.host.trafficLoading && !manual) return Promise.resolve();
  V6.host.trafficLoading = true;
  if (manual) V6.host.trafficErr = '';
  var sortKey = V6.host.mode === 'traffic' ? 'bg_bytes' : 'rate';
  var qParams = {
    period: V6.host.period || 'today',
    net: V6.host.net || 'all',
    sort: sortKey,
    include_system: V6.host.includeSystem ? '1' : '0',
    limit: 100
  };
  return api.get(V6_API.localTraffic, qParams, { timeout: 8000 }).then(function (r) {
    V6.host.trafficLoading = false;
    V6.host.trafficLoadedAt = Date.now();
    V6.host.trafficErr = '';
    if (r && typeof r === 'object') {
      V6.host.traffic.available = r.available !== false;
      V6.host.traffic.reason = String(r.reason || '');
      V6.host.traffic.rate_warming_up = r.rate_warming_up === true;
      V6.host.traffic.bg_split_available = r.bg_split_available !== false;
      if (r.summary && typeof r.summary === 'object') {
        V6.host.traffic.summary = Object.assign({}, V6.host.traffic.summary, r.summary);
      }
      if (Array.isArray(r.apps)) {
        V6.host.traffic.apps = r.apps;
      }
    }
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) {
        V6.host._deferTrafficPaint = true;
      } else {
        V6.host._deferTrafficPaint = false;
        v6RefreshActiveSubviewDom();
      }
    }
    return r;
  }).catch(function (e) {
    V6.host.trafficLoading = false;
    V6.host.trafficErr = errText(e);
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) {
        V6.host._deferTrafficPaint = true;
      } else {
        V6.host._deferTrafficPaint = false;
        v6RefreshActiveSubviewDom();
      }
    }
    return null;
  });
}

function v6LoadHostPower(forceRefresh) {
  if (V6.host.powerLoading && !forceRefresh) return Promise.resolve();
  V6.host.powerLoading = true;
  V6.host.powerErr = '';
  var qParams = {
    sort: V6.host.powerSort || 'bg_mah',
    include_system: V6.host.includeSystem ? '1' : '0'
  };
  if (forceRefresh) qParams.refresh = '1';
  return api.get(V6_API.localPower, qParams, { timeout: 12000 }).then(function (r) {
    V6.host.powerLoading = false;
    V6.host.powerLoadedAt = Date.now();
    if (r && typeof r === 'object') {
      V6.host.power.available = r.available !== false;
      V6.host.power.reason = String(r.reason || '');
      V6.host.power.cached = r.cached === true;
      V6.host.power.refresh_throttled = r.refresh_throttled === true;
      V6.host.power.bg_mah_available = r.bg_mah_available === true;
      V6.host.power.bg_mah_reason = String(r.bg_mah_reason || '');
      V6.host.power.screen_off_mah_available = r.screen_off_mah_available === true;
      if (r.device_summary && typeof r.device_summary === 'object') {
        V6.host.power.device_summary = Object.assign({}, V6.host.power.device_summary, r.device_summary);
      }
      if (Array.isArray(r.apps)) {
        V6.host.power.apps = r.apps;
      }
    }
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
      else v6RefreshActiveSubviewDom();
    }
    return r;
  }).catch(function (e) {
    V6.host.powerLoading = false;
    V6.host.powerErr = errText(e);
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
      else v6RefreshActiveSubviewDom();
    }
    return null;
  });
}

function v6LoadHostPrivacy(forceAccept) {
  if (V6.host.privacyLoading && !forceAccept) return Promise.resolve();
  V6.host.privacyLoading = true;
  V6.host.privacyErr = '';
  return api.get(V6_API.localPrivacy, { include_system: V6.host.includeSystem ? '1' : '0' }, { timeout: 8000 }).then(function (r) {
    V6.host.privacyLoading = false;
    V6.host.privacyLoadedAt = Date.now();
    if (r && typeof r === 'object') {
      V6.host.privacy.available = r.available !== false;
      V6.host.privacy.reason = String(r.reason || '');
      if (typeof r.self_capture_enabled === 'boolean' && (forceAccept || Date.now() >= V6.mutUntil.selfCap)) {
        V6.host.privacy.self_capture_enabled = r.self_capture_enabled;
      }
      if (r.self_capture_mode != null) V6.host.privacy.self_capture_mode = String(r.self_capture_mode || '');
      if (r.summary && typeof r.summary === 'object') {
        V6.host.privacy.summary = Object.assign({}, V6.host.privacy.summary, r.summary);
      }
      if (Array.isArray(r.findings)) {
        V6.host.privacy.findings = r.findings;
      }
    }
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
      else v6RefreshActiveSubviewDom();
    }
    return r;
  }).catch(function (e) {
    V6.host.privacyLoading = false;
    V6.host.privacyErr = errText(e);
    if (S.page === 'vector' && V6.subtab === 'host') {
      if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
      else v6RefreshActiveSubviewDom();
    }
    return null;
  });
}

function v6ApplyHostFirewallData(r) {
  if (!r || typeof r !== 'object') return;
  if (r.updated_at != null) V6.host.firewall.updated_at = num(r.updated_at, 0);
  if (Array.isArray(r.protected_packages) && r.protected_packages.length) {
    V6.host.firewall.protected_packages = r.protected_packages.map(String);
  }
  if (Array.isArray(r.uid_rules)) {
    if (V6.lg && V6.lg.blocked_set) {
      Object.keys(V6.lg.blocked_set).forEach(function (k) {
        if (k.indexOf('uid:') === 0) delete V6.lg.blocked_set[k];
      });
    }
    var uMap = {};
    V6.host.firewall.uid_rules = r.uid_rules.map(function (it) {
      var u = Math.round(num(it.uid, 0));
      var bTargets = Array.isArray(it.block_targets)
        ? it.block_targets.map(function (t) { return String(t || '').trim(); }).filter(Boolean)
        : [];
      var norm = {
        uid: u,
        sdk_sandbox_uid: Math.round(num(it.sdk_sandbox_uid, 0)),
        pkg: v6CleanHostRealPkg(it.pkg || it.package || ''),
        app_name: String(it.app_name || it.display_name || ''),
        mode: v6NormFwMode(it.mode),
        block_targets: bTargets,
        updated_at: num(it.updated_at, 0)
      };
      if (u > 0 && bTargets.length > 0 && V6.lg && V6.lg.blocked_set) {
        bTargets.forEach(function (tgt) {
          var tLow = tgt.toLowerCase();
          V6.lg.blocked_set['uid:' + u + '|' + tLow] = 1;
          var pIp = v6ExtractPureIp(tgt);
          if (pIp) V6.lg.blocked_set['uid:' + u + '|' + pIp.toLowerCase()] = 1;
        });
      }
      if (norm.mode !== 'allow' || norm.block_targets.length > 0) uMap[String(u)] = norm;
      return norm;
    }).filter(function (x) { return x.mode !== 'allow' || (x.block_targets && x.block_targets.length > 0); });
    V6.host.firewall.uid_map = uMap;
    V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
  } else if (r.uid_rule_count != null) {
    V6.host.firewall.uid_rule_count = Math.max(0, Math.round(num(r.uid_rule_count, 0)));
  }
  if (Array.isArray(r.blocked_domains)) {
    var bSet = {};
    V6.host.firewall.blocked_domains = r.blocked_domains.map(function (d) {
      var dom = typeof d === 'string' ? d.trim().toLowerCase() : String((d && (d.domain || d.host || d.value)) || '').trim().toLowerCase();
      if (dom) bSet[dom] = 1;
      return dom;
    }).filter(Boolean);
    V6.host.firewall.blocked_set = bSet;
    V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
  } else if (r.blocked_domain_count != null) {
    V6.host.firewall.blocked_domain_count = Math.max(0, Math.round(num(r.blocked_domain_count, 0)));
  }
  v6SyncHostLeakEventsBlocked();
}

function v6LoadHostFirewall(forceAccept) {
  if (V6.host.fwLoading && !forceAccept) return Promise.resolve();
  V6.host.fwLoading = true;
  return api.get(V6_API.localFirewall, null, { timeout: 7000 }).then(function (r) {
    V6.host.fwLoading = false;
    V6.host.fwLoadedAt = Date.now();
    if (forceAccept || Date.now() >= V6.mutUntil.hostFw) {
      v6ApplyHostFirewallData(r);
    }
    if (S.page === 'vector') {
      v6RefreshNavBadges();
      if (V6.subtab === 'host') {
        if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
        else v6RefreshActiveSubviewDom();
      } else if (V6.subtab === 'privacy') {
        v6RefreshActiveSubviewDom();
      }
    }
    if (V6.host.appSheet.open) v6PaintHostAppSheetFwButtons();
    return r;
  }).catch(function () {
    V6.host.fwLoading = false;
    return null;
  });
}

function v6EnsureHostModeLoaded(forceAll) {
  v6SyncHostPollTimer();
  v6LoadHostTraffic(!!forceAll);
  v6LoadHostFirewall(!!forceAll);
  if (forceAll || V6.host.mode === 'power' || !V6.host.powerLoadedAt) {
    v6LoadHostPower(!!forceAll);
  }
  if (forceAll || V6.host.mode === 'firewall' || !V6.host.privacyLoadedAt) {
    v6LoadHostPrivacy();
  }
}

/* ── UID 实时连接与四档防火墙抽屉 (Bottom Sheet) ── */
function v6PauseHostAppSheetTimer() {
  if (V6.host.appSheet.timer) {
    clearInterval(V6.host.appSheet.timer);
    V6.host.appSheet.timer = 0;
  }
}

function v6StartHostAppSheetTimer() {
  v6PauseHostAppSheetTimer();
  if (!V6.host.appSheet.open || document.hidden) return;
  V6.host.appSheet.timer = setInterval(function () {
    if (!V6.host.appSheet.open || document.hidden) {
      v6PauseHostAppSheetTimer();
      return;
    }
    v6FetchHostAppFlows();
  }, 2500);
}

function v6StopHostAppSheetTimer() {
  v6PauseHostAppSheetTimer();
  V6.host.appSheet.open = false;
  V6.host.appSheet.reqSeq = (V6.host.appSheet.reqSeq || 0) + 1;
  if (V6.host._deferTrafficPaint) {
    V6.host._deferTrafficPaint = false;
    var flushDeferred = function () {
      if (typeof S !== 'undefined' && S.page === 'vector' && V6.subtab === 'host' && !v6IsSheetShowing()) {
        v6RefreshActiveSubviewDom();
      }
    };
    if (typeof sheetSettled === 'function') sheetSettled().then(flushDeferred);
    else setTimeout(flushDeferred, 260);
  }
}

function v6HostAppFlowsInnerHtml() {
  var st = V6.host.appSheet;
  if (st.loading && !st.flows.length) {
    return '<div class="note">正在读取该应用的内核实时连接…</div>';
  }
  if (st.err) {
    return '<div class="note err">' + escapeHtml(st.err) + '</div>';
  }
  if (!st.flows.length) {
    return '<div class="lgd-summary-line"><span>当前该应用没有活跃网络套接字连接</span></div>';
  }
  return '<div class="v6-tuple-list" style="max-height:300px">' + st.flows.map(function (f) {
    var rxB = bps(f.rx_bps), txB = bps(f.tx_bps);
    var pCls = f.frozen ? 'b-bad' : (f.protoBadge === 'QUIC' ? 'b-pur' : (f.proto === 'udp' ? 'b-acc' : ''));
    var remMin = f.frozen ? Math.max(1, Math.ceil((f.frozen_until - Date.now() / 1000) / 60)) : 0;
    var riskBadge = f.cleartext_risk === 'http_cleartext'
      ? '<span class="v6-mono-badge b-bad">HTTP明文</span>'
      : (f.cleartext_risk === 'dns_direct' ? '<span class="v6-mono-badge b-warn">直连DNS</span>' : '');
    var titleMain = f.dst_host || v6FmtHostPort(f.dst_ip, f.dport);
    return '<div class="v6-tuple-row" data-mkey="huid-' + escapeHtml(f.id) + '">' +
      '<div class="v6-tuple-5">' +
        '<div class="v6-tuple-primary">' +
          '<span class="v6-mono-badge mono ' + pCls + '">' + escapeHtml(f.frozen ? ('封禁剩' + remMin + '分') : f.protoBadge) + '</span>' +
          riskBadge +
          '<span>' + escapeHtml(titleMain) + '</span>' +
        '</div>' +
        '<div class="ep">' + escapeHtml(v6FmtHostPort(f.src_ip, f.sport) + ' -> ' + v6FmtHostPort(f.dst_ip, f.dport)) + '</div>' +
      '</div>' +
      '<div class="v6-tuple-rate">↓ ' + rxB.v + ' ' + rxB.u + '<br>↑ ' + txB.v + ' ' + txB.u + '</div>' +
      '<div class="v6-tuple-acts">' +
        '<button type="button" class="lgd-act-btn warn press" data-v6-act="host-sheet-cut" data-freeze="0" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('cut') + '<span>秒断</span></button>' +
        '<button type="button" class="lgd-act-btn dan press" data-v6-act="host-sheet-cut" data-freeze="1" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('freeze') + '<span>冻结15分</span></button>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
}

function v6FetchHostAppFlows() {
  var st = V6.host.appSheet;
  if (!st.open || st.uid < 0 || document.hidden) return Promise.resolve();
  var reqUid = st.uid;
  var reqSeq = (st.reqSeq || 0) + 1;
  st.reqSeq = reqSeq;
  st.loading = true;
  return api.get(V6_API.scalpelFlows, { scope: 'host', uid: reqUid, limit: 100 }, { timeout: 6000 }).then(function (r) {
    if (!st.open || reqUid !== V6.host.appSheet.uid || reqSeq !== st.reqSeq) return;
    st.loading = false;
    st.err = '';
    st.flows = Array.isArray(r && r.flows) ? v6NormScalpelFlowList(r.flows) : [];
    var box = document.getElementById('v6-host-sheet-flows');
    if (box) morph(box, v6HostAppFlowsInnerHtml());
    var cnt = document.getElementById('v6-host-sheet-cnt');
    if (cnt) cnt.textContent = st.flows.length + ' 条连接';
  }).catch(function (e) {
    if (!st.open || reqUid !== V6.host.appSheet.uid || reqSeq !== st.reqSeq) return;
    st.loading = false;
    st.err = errText(e);
    var box = document.getElementById('v6-host-sheet-flows');
    if (box) box.innerHTML = v6HostAppFlowsInnerHtml();
    var cnt = document.getElementById('v6-host-sheet-cnt');
    if (cnt) cnt.textContent = '读取失败';
  });
}

function v6HostAppSheetIpTargetsInnerHtml(uid, pkg, appName) {
  var targets = v6HostUidBlockTargets(uid);
  if (!targets.length) return '';
  var cleanPkg = v6CleanHostRealPkg(pkg);
  var disp = v6HostEventAppLabel(appName, cleanPkg, uid);
  return '<div style="margin:12px 0 4px">' +
    '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px">' +
      '<b style="font-size:12.5px;color:var(--text-2)">该应用已封目标 IP（' + targets.length + ' 项）</b>' +
      (targets.length > 1 ? '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-uid-ip-clear" data-uid="' + uid + '" data-pkg="' + escapeHtml(cleanPkg) + '" data-name="' + escapeHtml(disp) + '">全部解封</button>' : '') +
    '</div>' +
    '<div class="v6-flow-list">' + targets.map(function (t) {
      return '<div class="v6-flow-item" data-mkey="hsip-' + uid + '-' + escapeHtml(t) + '">' +
        '<div class="v6-flow-main"><div class="v6-flow-t"><span class="v6-mono-badge b-bad">IP拦截</span><span class="mono">' + escapeHtml(t) + '</span></div></div>' +
        '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-ip-unblock" data-uid="' + uid + '" data-ip="' + escapeHtml(t) + '" data-pkg="' + escapeHtml(cleanPkg) + '" data-name="' + escapeHtml(disp) + '">解除封禁</button>' +
      '</div>';
    }).join('') + '</div>' +
  '</div>';
}

function v6PaintHostAppSheetFwButtons() {
  var st = V6.host.appSheet;
  if (!st.open) return;
  var curMode = v6HostUidMode(st.uid);
  $$('#v6-host-fw-picker [data-fw-mode]').forEach(function (b) {
    var m = b.getAttribute('data-fw-mode');
    b.classList.toggle('on', m === curMode);
  });
  var ipBox = document.getElementById('v6-host-sheet-ips');
  if (ipBox) {
    morph(ipBox, v6HostAppSheetIpTargetsInnerHtml(st.uid, st.pkg, st.appName));
  }
}

function v6OpenHostAppSheet(uid, pkg, appName, isSystem) {
  uid = Math.round(num(uid, -1));
  if (uid < 0 || typeof sheet !== 'function') return;
  pkg = v6CleanHostRealPkg(pkg);
  appName = v6HostEventAppLabel(appName, pkg, uid);
  v6PauseHostAppSheetTimer();

  var curMode = v6HostUidMode(uid);
  var isProt = v6IsHostAppProtected(uid, pkg);
  var disAttr = isProt ? ' disabled' : '';

  var html = '<h3>' + escapeHtml(appName) + '</h3>' +
    '<div class="sub mono">' + escapeHtml((pkg ? pkg + ' · ' : '') + 'UID ' + uid + (isSystem ? ' · 系统组件' : '')) + '</div>' +
    '<div style="margin:10px 0 6px;font-size:12.5px;font-weight:700;color:var(--text-2)">本机联网四档管控（内核 UID 级即时生效）</div>' +
    (isProt ? '<div class="note warn" style="margin:0 0 8px">该组件属于 Android 核心系统、隔离沙盒或 Root / WebView 保护白名单，已锁定防断网自锁，仅支持查看连接</div>' : '') +
    '<div class="v6-fw-grid' + (isProt ? ' v6-dimmed' : '') + '" id="v6-host-fw-picker">' +
      '<button type="button" class="v6-fw-btn m-allow press' + (curMode === 'allow' ? ' on' : '') + '" data-v6-act="host-fw-set" data-fw-mode="allow" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appName) + '"><b><span>正常放行</span></b><small>允许全部网络通信</small></button>' +
      '<button type="button" class="v6-fw-btn m-http press' + (curMode === 'block_cleartext' ? ' on' : '') + '" data-v6-act="host-fw-set" data-fw-mode="block_cleartext" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appName) + '"' + disAttr + '><b><span>仅禁明文HTTP</span></b><small>阻断80端口防裸奔，HTTPS正常</small></button>' +
      '<button type="button" class="v6-fw-btn m-mob press' + (curMode === 'block_cellular' ? ' on' : '') + '" data-v6-act="host-fw-set" data-fw-mode="block_cellular" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appName) + '"' + disAttr + '><b><span>禁移动数据</span></b><small>仅允许Wi-Fi联网，省流量</small></button>' +
      '<button type="button" class="v6-fw-btn m-all press' + (curMode === 'block_all' ? ' on' : '') + '" data-v6-act="host-fw-set" data-fw-mode="block_all" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appName) + '"' + disAttr + '><b><span>全局禁网</span></b><small>阻断前后台一切联网</small></button>' +
    '</div>' +
    '<div id="v6-host-sheet-ips">' + v6HostAppSheetIpTargetsInnerHtml(uid, pkg, appName) + '</div>' +
    '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin:14px 0 8px">' +
      '<b style="font-size:13px;color:var(--text-1)">当前活跃连接</b>' +
      '<span class="v6-mono-badge" id="v6-host-sheet-cnt">读取中…</span>' +
    '</div>' +
    '<div id="v6-host-sheet-flows"><div class="note">正在读取该应用的内核实时连接…</div></div>' +
    '<button type="button" class="btn sec wide press" data-close style="margin-top:12px">关闭</button>';

  /* 必须先调用 sheet() 让前一次已打开弹窗的 prevClose 执行完毕，再置 open=true 并拉取连接 */
  sheet(html, { tall: true, kind: 'v6-host-app', onClose: v6StopHostAppSheetTimer });
  V6.host.appSheet.open = true;
  V6.host.appSheet.uid = uid;
  V6.host.appSheet.pkg = pkg;
  V6.host.appSheet.appName = appName;
  V6.host.appSheet.isSystem = !!isSystem;
  V6.host.appSheet.flows = [];
  V6.host.appSheet.loading = true;
  V6.host.appSheet.err = '';
  v6FetchHostAppFlows();
  v6StartHostAppSheetTimer();
}

/* ── 本机防火墙与自抓包写操作封装 ── */
function v6SetHostUidFirewall(uid, rawMode, pkg, appName, triggerEl, fromUndo) {
  uid = Math.round(num(uid, -1));
  if (uid < 0) return Promise.resolve();
  pkg = v6CleanHostRealPkg(pkg);
  var wireMode = v6NormFwMode(rawMode);
  if (wireMode !== 'allow' && v6IsHostAppProtected(uid, pkg)) {
    toast('核心系统、隔离沙盒或管理器组件受安全保护，禁止拦截', 'warn');
    return Promise.resolve();
  }
  var prevRule = V6.host.firewall.uid_map[String(uid)] || null;
  var prevMode = prevRule ? v6NormFwMode(prevRule.mode) : v6HostUidMode(uid);
  var existingTargets = (prevRule && Array.isArray(prevRule.block_targets)) ? prevRule.block_targets.slice() : [];
  var hasBlockTargets = existingTargets.length > 0;
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.hostFw = Date.now() + 1500;

  if (wireMode === 'allow' && !hasBlockTargets) {
    delete V6.host.firewall.uid_map[String(uid)];
    V6.host.firewall.uid_rules = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== uid; });
  } else {
    var nextRule = {
      uid: uid,
      sdk_sandbox_uid: prevRule ? Math.round(num(prevRule.sdk_sandbox_uid, 0)) : 0,
      pkg: pkg || (prevRule && prevRule.pkg) || '',
      app_name: appName || (prevRule && prevRule.app_name) || '',
      mode: wireMode,
      block_targets: existingTargets,
      updated_at: Math.round(Date.now() / 1000)
    };
    V6.host.firewall.uid_map[String(uid)] = nextRule;
    var rest = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== uid; });
    rest.unshift(nextRule);
    V6.host.firewall.uid_rules = rest;
  }
  V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
  v6SyncHostLeakEventsBlocked();
  v6PaintHostAppSheetFwButtons();
  v6RefreshNavBadges();
  if (S.page === 'vector') {
    if (V6.subtab === 'host') {
      if (v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
      else v6RefreshActiveSubviewDom();
    } else if (V6.subtab === 'privacy') {
      v6RefreshActiveSubviewDom();
    }
  }

  var keepIpRule = wireMode === 'allow' && hasBlockTargets;
  var actName = (wireMode === 'allow' && !keepIpRule) ? 'self_firewall_remove' : 'self_firewall_set';
  var actParams = (wireMode === 'allow' && !keepIpRule)
    ? { uid: String(uid) }
    : { uid: String(uid), mode: wireMode, pkg: pkg, app_name: appName || '' };
  var dispApp = appName || pkg || ('UID ' + uid);

  return busyWhile(triggerEl, api.action(actName, actParams)).then(function () {
    v6LoadHostFirewall(true);
    if (V6.host.mode === 'firewall') v6LoadHostPrivacy();
    var okMsg = wireMode === 'allow'
      ? ('已恢复放行：' + dispApp + (keepIpRule ? ('（保留 ' + existingTargets.length + ' 项单 IP 封禁）') : ''))
      : ('已对「' + dispApp + '」设为' + v6FwModeZh(wireMode));
    if (!fromUndo && prevMode !== wireMode && typeof undoToast === 'function') {
      undoToast(okMsg, function () {
        return v6SetHostUidFirewall(uid, prevMode, pkg, appName, null, true);
      });
    } else {
      toast(okMsg);
    }
  }).catch(function (e) {
    V6.mutUntil.hostFw = 0;
    v6LoadHostFirewall(true);
    toast(errText(e), 'err');
  });
}

function v6UnblockHostUidIp(uid, targetRaw, pkg, appName, triggerEl, fromUndo) {
  uid = Math.round(num(uid, -1));
  var tgt = String(targetRaw || '').trim();
  if (uid <= 0 || !tgt) return Promise.resolve();
  var cleanPkg = v6CleanHostRealPkg(pkg);
  var dispApp = v6HostEventAppLabel(appName, cleanPkg, uid);
  var tgtLow = tgt.toLowerCase();
  var pureIp = v6ExtractPureIp(tgt);
  var pureLow = pureIp ? pureIp.toLowerCase() : '';
  var curRule = V6.host.firewall.uid_map[String(uid)] || null;
  var curMode = curRule ? v6NormFwMode(curRule.mode) : 'allow';
  var prevTargets = (curRule && Array.isArray(curRule.block_targets)) ? curRule.block_targets.slice() : [];
  var keptTargets = prevTargets.filter(function (x) {
    return String(x || '').trim().toLowerCase() !== tgtLow;
  });

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.hostFw = Date.now() + 1500;
  V6.mutUntil.lg = Date.now() + 1500;

  if (V6.lg && V6.lg.blocked_set) {
    delete V6.lg.blocked_set['uid:' + uid + '|' + tgtLow];
    if (pureLow && keptTargets.every(function (x) { return v6ExtractPureIp(x).toLowerCase() !== pureLow; })) {
      delete V6.lg.blocked_set['uid:' + uid + '|' + pureLow];
    }
  }
  if (curRule) {
    curRule.block_targets = keptTargets;
    if (curMode === 'allow' && keptTargets.length === 0) {
      delete V6.host.firewall.uid_map[String(uid)];
      V6.host.firewall.uid_rules = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== uid; });
    }
    V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
  }
  v6SyncHostLeakEventsBlocked();
  v6PaintHostAppSheetFwButtons();
  v6RefreshNavBadges();
  if (S.page === 'vector') {
    if (V6.subtab === 'host' && v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
    else v6RefreshActiveSubviewDom();
  }

  var reqPromise = v6ValidIp(tgt)
    ? api.post(V6_API.lgBlockDomain, {
        action: 'unblock',
        target_scope: 'host',
        uid: uid,
        dst_host: tgt,
        mac: '',
        pkg: cleanPkg,
        app_name: appName || '',
        force: false
      }, { timeout: 9000 })
    : api.action('self_firewall_set', {
        uid: String(uid),
        mode: curMode,
        pkg: cleanPkg,
        app_name: appName || '',
        block_targets: JSON.stringify(keptTargets)
      });

  return busyWhile(triggerEl, reqPromise).then(function () {
    v6LoadHostFirewall(true);
    v6LoadLeakGuard(true);
    var msg = '已解除「' + dispApp + '」目标 IP 封禁：' + tgt;
    if (!fromUndo && v6ValidIp(tgt) && typeof undoToast === 'function') {
      undoToast(msg, function () {
        return api.post(V6_API.lgBlockDomain, {
          action: 'block',
          target_scope: 'host',
          uid: uid,
          dst_host: tgt,
          mac: '',
          pkg: cleanPkg,
          app_name: appName || '',
          force: true
        }, { timeout: 9000 }).then(function () {
          v6LoadHostFirewall(true);
          v6LoadLeakGuard(true);
          toast('已恢复封禁「' + dispApp + '」目标 IP：' + tgt);
        }).catch(function (err) { toast(errText(err), 'err'); });
      });
    } else {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.hostFw = 0;
    V6.mutUntil.lg = 0;
    v6LoadHostFirewall(true);
    v6LoadLeakGuard(true);
    toast(errText(e), 'err');
  });
}

function v6ClearHostUidIps(uid, pkg, appName, triggerEl) {
  uid = Math.round(num(uid, -1));
  if (uid <= 0) return Promise.resolve();
  var cleanPkg = v6CleanHostRealPkg(pkg);
  var dispApp = v6HostEventAppLabel(appName, cleanPkg, uid);
  var curRule = V6.host.firewall.uid_map[String(uid)] || null;
  var curMode = curRule ? v6NormFwMode(curRule.mode) : 'allow';
  var prevTargets = (curRule && Array.isArray(curRule.block_targets)) ? curRule.block_targets.slice() : [];
  if (!prevTargets.length) return Promise.resolve();

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.hostFw = Date.now() + 1500;

  if (V6.lg && V6.lg.blocked_set) {
    Object.keys(V6.lg.blocked_set).forEach(function (k) {
      if (k.indexOf('uid:' + uid + '|') === 0) delete V6.lg.blocked_set[k];
    });
  }
  if (curMode === 'allow') {
    delete V6.host.firewall.uid_map[String(uid)];
    V6.host.firewall.uid_rules = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== uid; });
  } else if (curRule) {
    curRule.block_targets = [];
  }
  V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
  v6SyncHostLeakEventsBlocked();
  v6PaintHostAppSheetFwButtons();
  v6RefreshNavBadges();
  if (S.page === 'vector') {
    if (V6.subtab === 'host' && v6IsSheetShowing()) V6.host._deferTrafficPaint = true;
    else v6RefreshActiveSubviewDom();
  }

  var actPromise = curMode === 'allow'
    ? api.action('self_firewall_remove', { uid: String(uid) })
    : api.action('self_firewall_set', { uid: String(uid), mode: curMode, pkg: cleanPkg, app_name: appName || '', block_targets: '[]' });

  return busyWhile(triggerEl, actPromise).then(function () {
    v6LoadHostFirewall(true);
    v6LoadLeakGuard(true);
    toast('已清空「' + dispApp + '」全部 ' + prevTargets.length + ' 项单 IP 封禁');
  }).catch(function (e) {
    V6.mutUntil.hostFw = 0;
    v6LoadHostFirewall(true);
    toast(errText(e), 'err');
  });
}

function v6BlockHostDomain(domainRaw, triggerEl, opts) {
  opts = opts || {};
  var dom = String(domainRaw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!dom || dom.indexOf('.') < 0) {
    toast('请输入有效的目标域名', 'warn');
    return Promise.resolve();
  }
  var params = { domain: dom };
  if (opts.force) params.force = 'true';
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.hostFw = Date.now() + 1500;

  return busyWhile(triggerEl, api.action('self_dns_block', params)).then(function () {
    if (!V6.host.firewall.blocked_set[dom]) {
      V6.host.firewall.blocked_set[dom] = 1;
      V6.host.firewall.blocked_domains.unshift(dom);
      V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
    }
    v6SyncHostLeakEventsBlocked();
    var inp = document.getElementById('v6-host-dom-inp');
    if (inp) inp.value = '';
    v6RefreshNavBadges();
    v6LoadHostFirewall(true);
    if (V6.host.mode === 'firewall') v6LoadHostPrivacy();
    var msg = '已在本机拦截域名：' + dom;
    if (!opts.fromUndo && typeof undoToast === 'function') {
      undoToast(msg, function () { return v6UnblockHostDomain(dom, null, true); });
    } else {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.hostFw = 0;
    var errMsg = errText(e);
    if ((e && e.status === 409) || /guard_warn_confirm|共享|公共/i.test(errMsg)) {
      if (/hard_block|核心公共|禁止封禁/i.test(errMsg)) {
        toast('该域名属于系统联网检测核心域，禁止拦截以免断网', 'warn');
        return;
      }
      confirmSheet(
        '确认强制拦截共享底座域名？',
        '<b class="mono">' + escapeHtml(dom) + '</b> 涉及多款应用共用的公共 CDN 或云底座，拦截后可能影响同节点正常服务，确定继续吗？',
        '强制拦截'
      ).then(function (ok) {
        if (ok) v6BlockHostDomain(dom, triggerEl, { force: true, fromUndo: opts.fromUndo });
      });
      return;
    }
    toast(errMsg, 'err');
  });
}

function v6UnblockHostDomain(domainRaw, triggerEl, fromUndo) {
  var dom = String(domainRaw || '').trim().toLowerCase();
  if (!dom) return Promise.resolve();
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.hostFw = Date.now() + 1500;
  delete V6.host.firewall.blocked_set[dom];
  V6.host.firewall.blocked_domains = V6.host.firewall.blocked_domains.filter(function (x) { return x !== dom; });
  V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
  v6SyncHostLeakEventsBlocked();
  v6RefreshNavBadges();
  if (S.page === 'vector' && (V6.subtab === 'host' || V6.subtab === 'privacy')) v6RefreshActiveSubviewDom();

  return busyWhile(triggerEl, api.action('self_dns_unblock', { domain: dom })).then(function () {
    v6LoadHostFirewall(true);
    var msg = '已解除本机域名拦截：' + dom;
    if (!fromUndo && typeof undoToast === 'function') {
      undoToast(msg, function () { return v6BlockHostDomain(dom, null, { force: true, fromUndo: true }); });
    } else {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.hostFw = 0;
    v6LoadHostFirewall(true);
    toast(errText(e), 'err');
  });
}

function v6ClearHostFirewall(btn) {
  var tot = num(V6.host.firewall.uid_rule_count, 0) + num(V6.host.firewall.blocked_domain_count, 0);
  if (tot <= 0) { toast('当前没有生效中的本机管控规则'); return; }
  confirmSheet('清空全部本机管控规则？', '将立即解除全部 ' + tot + ' 条本机应用禁网规则与本机域名黑名单，恢复所有应用正常联网。', '全部清空').then(function (ok) {
    if (!ok) return;
    if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
    V6.mutUntil.hostFw = Date.now() + 1500;
    busyWhile(btn, api.action('self_firewall_clear', {})).then(function () {
      V6.host.firewall.uid_rules = [];
      V6.host.firewall.uid_map = {};
      V6.host.firewall.blocked_domains = [];
      V6.host.firewall.blocked_set = {};
      V6.host.firewall.uid_rule_count = 0;
      V6.host.firewall.blocked_domain_count = 0;
      if (V6.lg && V6.lg.blocked_set) {
        Object.keys(V6.lg.blocked_set).forEach(function (k) {
          if (k.indexOf('uid:') === 0) delete V6.lg.blocked_set[k];
        });
      }
      v6SyncHostLeakEventsBlocked();
      v6RefreshNavBadges();
      v6RefreshActiveSubviewDom();
      toast('已清空全部本机防火墙与域名规则');
    }).catch(function (e) {
      V6.mutUntil.hostFw = 0;
      v6LoadHostFirewall(true);
      toast(errText(e), 'err');
    });
  });
}

function v6ToggleSelfCapture(nextOn, togEl) {
  var isLease15mNow = function (modeStr) {
    var m = String(modeStr || V6.host.privacy.self_capture_mode || (typeof S !== 'undefined' && S.selfStudio && S.selfStudio.mode) || '').toLowerCase();
    return m === 'lease_15m';
  };
  if (nextOn && isLease15mNow()) {
    V6.host.privacy.self_capture_enabled = true;
    if (togEl) togEl.setAttribute('aria-checked', 'true');
    v6LoadHostPrivacy(false);
    toast('15分钟集中快训租约生效中，已保持深度明文审计开启');
    return Promise.resolve();
  }
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.selfCap = Date.now() + 6000;
  V6.host.privacy.self_capture_enabled = nextOn;

  var runToggleReq = function () {
    return api.post(V6_API.selfToggle, { enabled: !!nextOn }, { timeout: 7000 }).then(function (r) {
      V6.mutUntil.selfCap = Date.now() + 5500;
      if (r && typeof r.enabled === 'boolean') V6.host.privacy.self_capture_enabled = r.enabled;
      if (r && r.mode != null) V6.host.privacy.self_capture_mode = String(r.mode || '');
      else if (!nextOn) V6.host.privacy.self_capture_mode = 'off';
      v6LoadHostPrivacy(false);
      toast(nextOn ? '已开启本机深度明文抓包审计（5秒内生效）' : '已关闭本机深度抓包，恢复零开销巡检');
    });
  };

  var p = (nextOn && !V6.host.privacy.self_capture_mode)
    ? api.get(V6_API.localPrivacy, { include_system: '0' }, { timeout: 5000 }).catch(function () { return null; }).then(function (pr) {
        if (pr && pr.self_capture_mode != null) {
          V6.host.privacy.self_capture_mode = String(pr.self_capture_mode || '');
        }
        if (isLease15mNow(pr && pr.self_capture_mode)) {
          V6.mutUntil.selfCap = 0;
          V6.host.privacy.self_capture_enabled = true;
          v6LoadHostPrivacy(false);
          toast('15分钟集中快训租约生效中，已保持深度明文审计开启');
          return;
        }
        return runToggleReq();
      })
    : runToggleReq();

  return busyWhile(togEl, p).catch(function (e) {
    V6.mutUntil.selfCap = 0;
    V6.host.privacy.self_capture_enabled = !nextOn;
    if (togEl) togEl.setAttribute('aria-checked', String(!nextOn));
    toast(errText(e), 'err');
  });
}

/* ── 本机守护 4 子模式渲染器 ── */
function v6FilterHostApps(list) {
  var q = String(V6.host.q || '').trim().toLowerCase();
  if (!q) return list;
  return list.filter(function (a) {
    var doms = Array.isArray(a.top_domains) ? a.top_domains.join(' ') : '';
    var hay = ((a.app_name || '') + ' ' + (a.package || '') + ' ' + a.uid + ' ' + doms).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6RenderHostLiveListHtml() {
  var tf = V6.host.traffic;
  if (V6.host.trafficLoading && !V6.host.trafficLoadedAt) {
    return '<div class="empty">正在采样本机应用实时联网速率…</div>';
  }
  if (V6.host.trafficErr && !tf.apps.length) {
    return '<div class="v6-scard-body"><div class="note err">' + escapeHtml(V6.host.trafficErr) + '</div></div>';
  }
  if (!tf.available) {
    return '<div class="v6-scard-body"><div class="note">' + escapeHtml(tf.reason || '当前内核未暴露按 UID 流量统计接口') + '</div></div>';
  }
  var apps = v6FilterHostApps((tf.apps || []).slice());
  apps.sort(function (a, b) {
    return (num(b.total_bps, 0) - num(a.total_bps, 0)) || (num(b.active_conns, 0) - num(a.active_conns, 0)) || (num(b.bg_total_bytes, 0) - num(a.bg_total_bytes, 0));
  });
  if (!apps.length) {
    return '<div class="empty">' + (V6.host.q ? '没有匹配搜索词的本机应用' : '当前暂无产生流量的本机应用') + '</div>';
  }
  return '<div class="scard-rows">' + apps.slice(0, 60).map(function (a) {
    var uid = Math.round(num(a.uid, 0));
    var pkg = v6CleanHostRealPkg(a.package);
    var nm = v6HostEventAppLabel(a.app_name, pkg, uid);
    var isFg = a.current_state === 'fg' || a.current_state === 'foreground';
    var stateBadge = isFg
      ? '<span class="v6-mono-badge b-ok">前台</span>'
      : '<span class="v6-mono-badge b-warn">后台</span>';
    var fwBadge = v6FwModeBadgeHtml(v6HostUidMode(uid));
    var flags = Array.isArray(a.cleartext_flags) ? a.cleartext_flags : [];
    var riskHtml = '';
    if (flags.indexOf('http_cleartext') >= 0) riskHtml += '<span class="v6-mono-badge b-bad">HTTP明文</span>';
    if (flags.indexOf('dns_direct') >= 0) riskHtml += '<span class="v6-mono-badge b-warn">直连DNS</span>';
    var sysBadge = a.is_system ? '<span class="v6-mono-badge">系统</span>' : '';

    var rx = bps(a.rx_bps), tx = bps(a.tx_bps);
    var connsCnt = Math.round(num(a.active_conns, 0));
    var doms = Array.isArray(a.top_domains) && a.top_domains.length ? ('近期访问：' + a.top_domains.slice(0, 3).join('、')) : '';

    return '<div class="v6-app-row press" role="button" tabindex="0" data-mkey="hlive-' + uid + '" data-v6-act="host-app-open" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(nm) + '" data-sys="' + (a.is_system ? '1' : '0') + '">' +
      v6AppAvatarHtml(nm, pkg, uid) +
      '<div class="v6-app-main">' +
        '<div class="v6-app-t"><span class="nm">' + escapeHtml(nm) + '</span>' + stateBadge + fwBadge + riskHtml + sysBadge + '</div>' +
        '<div class="v6-app-s">' + escapeHtml((pkg ? pkg + ' · ' : '') + 'UID ' + uid + (connsCnt > 0 ? (' · ' + connsCnt + ' 条活跃连接') : '')) + '</div>' +
        (doms ? '<div class="v6-app-doms">' + escapeHtml(doms) + '</div>' : '') +
      '</div>' +
      '<div class="v6-app-metrics">' +
        '<span class="rx">↓ ' + rx.v + ' ' + rx.u + '</span>' +
        '<span class="tx">↑ ' + tx.v + ' ' + tx.u + '</span>' +
        '<small>累计 ' + bytes(a.total_bytes) + '</small>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
}

function v6RenderHostTrafficRankHtml() {
  var tf = V6.host.traffic;
  if (V6.host.trafficLoading && !V6.host.trafficLoadedAt) {
    return '<div class="empty">正在统计前后台累计流量排行…</div>';
  }
  var apps = v6FilterHostApps((tf.apps || []).slice());
  var splitOk = tf.bg_split_available !== false;
  apps.sort(function (a, b) {
    return splitOk
      ? ((num(b.bg_total_bytes, 0) - num(a.bg_total_bytes, 0)) || (num(b.total_bytes, 0) - num(a.total_bytes, 0)))
      : (num(b.total_bytes, 0) - num(a.total_bytes, 0));
  });
  apps = apps.filter(function (a) { return num(a.total_bytes, 0) > 0; });
  if (!apps.length) {
    return '<div class="empty">该统计周期内暂无本机应用流量记录</div>';
  }
  var maxTot = Math.max.apply(null, apps.map(function (a) { return num(a.total_bytes, 0); }).concat([1]));
  return '<div style="display:grid;gap:4px">' + apps.slice(0, 50).map(function (a) {
    var uid = Math.round(num(a.uid, 0));
    var pkg = v6CleanHostRealPkg(a.package);
    var nm = v6HostEventAppLabel(a.app_name, pkg, uid);
    var bgB = Math.max(0, num(a.bg_total_bytes, 0));
    var fgB = Math.max(0, num(a.fg_total_bytes, Math.max(0, num(a.total_bytes, 0) - bgB)));
    var totB = Math.max(1, bgB + fgB, num(a.total_bytes, 0));
    var bgW = splitOk ? Math.min(100, (bgB / maxTot) * 100) : 0;
    var fgW = splitOk ? Math.min(100 - bgW, (fgB / maxTot) * 100) : Math.min(100, (totB / maxTot) * 100);
    var bgPct = splitOk ? Math.round(clamp(num(a.bg_ratio_pct, (bgB / totB) * 100), 0, 100)) : 0;
    var fwBadge = v6FwModeBadgeHtml(v6HostUidMode(uid));

    return '<div class="hbar is-dual press" role="button" tabindex="0" data-mkey="htrf-' + uid + '" data-v6-act="host-app-open" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(nm) + '" data-sys="' + (a.is_system ? '1' : '0') + '">' +
      '<span class="n" style="min-width:0">' +
        '<span style="display:flex;align-items:center;gap:5px;flex-wrap:wrap"><b style="font-weight:700;color:var(--text-1)">' + escapeHtml(nm) + '</b>' + fwBadge + '</span>' +
        '<small style="display:block;font-size:10.5px;color:var(--text-3)">' + (splitOk ? ('后台占比 ' + bgPct + '%') : escapeHtml(pkg || ('UID ' + uid))) + '</small>' +
      '</span>' +
      '<div class="hbar-track" title="橙色：后台流量 · 蓝色：前台流量">' +
        (bgW > 0 ? '<i class="hbar-seg-bg" style="width:' + Math.max(1.8, bgW).toFixed(1) + '%"></i>' : '') +
        (fgW > 0 ? '<i class="hbar-seg-fg" style="width:' + Math.max(1.8, fgW).toFixed(1) + '%"></i>' : '') +
      '</div>' +
      '<span class="v" style="text-align:right">' +
        (splitOk
          ? ('<span style="color:var(--badge-warn)">后台 ' + bytes(bgB) + '</span><small style="display:block;color:var(--text-3)">前台 ' + bytes(fgB) + '</small>')
          : ('<span>总计 ' + bytes(totB) + '</span>')) +
      '</span>' +
    '</div>';
  }).join('') + '</div>';
}

function v6BgMahReasonZh(reasonRaw) {
  var r = String(reasonRaw || '').trim();
  if (!r) return '当前系统未单独拆分前后台毫安时，已自动按真实内核持锁与射频唤醒时长排序（零估算伪造）';
  if (/[\u4e00-\u9fa5]/.test(r)) return r;
  var low = r.toLowerCase();
  if (low === 'rom_uid_power_no_bg_split') {
    return '当前系统 ROM 仅输出应用总耗电、未拆分前后台毫安时，已自动按真实总耗电与内核持锁时长排序（零估算伪造）';
  }
  if (low === 'power_profile_uid_split_missing' || low === 'hardware_timers_only') {
    return '当前系统未开放按应用毫安时归因，已自动按真实内核持锁与射频唤醒时长排序（零估算伪造）';
  }
  if (low === 'batterystats_unavailable' || low === 'dumpsys_failed') {
    return '当前系统暂无法读取电池耗电明细，已按可用内核持锁与唤醒指标展示';
  }
  return '当前系统未单独拆分前后台毫安时，已自动按真实内核持锁与射频唤醒时长排序（零估算伪造）';
}

function v6RenderHostPowerListHtml() {
  var pw = V6.host.power;
  if (V6.host.powerLoading && !V6.host.powerLoadedAt) {
    return '<div class="empty">正在解析系统电池耗电与内核持锁归因…</div>';
  }
  if (V6.host.powerErr && !pw.apps.length) {
    return '<div class="v6-scard-body"><div class="note err">' + escapeHtml(V6.host.powerErr) + '</div></div>';
  }
  if (!pw.available) {
    return '<div class="v6-scard-body"><div class="note">' + escapeHtml(pw.reason || '当前系统未开放 batterystats 耗电统计') + '</div></div>';
  }
  var apps = v6FilterHostApps((pw.apps || []).slice());
  if (!apps.length) {
    return '<div class="empty">暂无可归因的后台耗电或持锁唤醒记录（拔掉充电器使用一段时间后数据更完整）</div>';
  }
  return '<div class="scard-rows">' + apps.slice(0, 50).map(function (a) {
    var uid = Math.round(num(a.uid, 0));
    var pkg = v6CleanHostRealPkg(a.package);
    var nm = v6HostEventAppLabel(a.app_name, pkg, uid);
    var fwBadge = v6FwModeBadgeHtml(v6HostUidMode(uid));
    var wlMs = Math.max(num(a.wakelock_bg_ms, 0), num(a.wakelock_partial_ms, 0));
    var radioMs = num(a.mobile_radio_active_ms, 0);
    var cpuBgMs = num(a.cpu_bg_ms, 0);
    var alarms = Math.round(num(a.wakeup_alarms_count, 0));
    var bgMah = Math.max(0, num(a.bg_mah, 0));
    var fgsMah = Math.max(0, num(a.fgs_mah, 0));
    var bgCombinedMah = bgMah + fgsMah;
    var topWl = (Array.isArray(a.top_wakelocks) && a.top_wakelocks[0] && a.top_wakelocks[0].name) ? a.top_wakelocks[0].name : '';
    var topAl = (!topWl && Array.isArray(a.top_wakeup_alarms) && a.top_wakeup_alarms[0] && a.top_wakeup_alarms[0].name) ? a.top_wakeup_alarms[0].name : '';

    var detailParts = [];
    if (fgsMah > 0) detailParts.push('前台服务 ' + fgsMah.toFixed(1) + ' mAh');
    if (wlMs > 0) detailParts.push('持锁 ' + v6FmtDurMs(wlMs));
    if (radioMs > 0) detailParts.push('射频 ' + v6FmtDurMs(radioMs));
    if (cpuBgMs > 0) detailParts.push('后台CPU ' + v6FmtDurMs(cpuBgMs));
    if (alarms > 0) detailParts.push('唤醒 ' + alarms + ' 次');
    if (!detailParts.length && num(a.total_mah, 0) > 0) detailParts.push('总耗电 ' + num(a.total_mah, 0).toFixed(1) + ' mAh');

    var rightMain = '';
    var rightSub = '';
    if (a.bg_mah_available && bgCombinedMah > 0) {
      rightMain = bgMah > 0
        ? ('<span style="color:var(--badge-warn)">后台 ' + bgCombinedMah.toFixed(1) + ' mAh</span>')
        : ('<span style="color:var(--badge-warn)">前台服务 ' + fgsMah.toFixed(1) + ' mAh</span>');
      rightSub = num(a.screen_off_mah, 0) > 0
        ? ('息屏 ' + num(a.screen_off_mah, 0).toFixed(1) + ' mAh')
        : ('总计 ' + num(a.total_mah, 0).toFixed(1) + ' mAh');
    } else if (num(a.total_mah, 0) > 0) {
      rightMain = '<span>总计 ' + num(a.total_mah, 0).toFixed(1) + ' mAh</span>';
      rightSub = wlMs > 0 ? ('持锁 ' + v6FmtDurMs(wlMs)) : (alarms > 0 ? ('唤醒 ' + alarms + ' 次') : '点击管控联网');
    } else {
      rightMain = '<span style="color:var(--badge-warn)">' + (wlMs > 0 ? ('持锁 ' + v6FmtDurMs(wlMs)) : (radioMs > 0 ? ('射频 ' + v6FmtDurMs(radioMs)) : ('唤醒 ' + alarms + ' 次'))) + '</span>';
      rightSub = cpuBgMs > 0 ? ('后台CPU ' + v6FmtDurMs(cpuBgMs)) : '点击管控联网';
    }

    return '<div class="v6-app-row press" role="button" tabindex="0" data-mkey="hpwr-' + uid + '" data-v6-act="host-app-open" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(nm) + '" data-sys="' + (a.is_system ? '1' : '0') + '">' +
      v6AppAvatarHtml(nm, pkg, uid) +
      '<div class="v6-app-main">' +
        '<div class="v6-app-t"><span class="nm">' + escapeHtml(nm) + '</span>' + fwBadge + (a.is_system ? '<span class="v6-mono-badge">系统</span>' : '') + '</div>' +
        '<div class="v6-app-s">' + escapeHtml(detailParts.join(' · ') || (pkg || ('UID ' + uid))) + '</div>' +
        ((topWl || topAl) ? '<div class="v6-app-doms">主要唤醒源：' + escapeHtml(topWl || topAl) + '</div>' : '') +
      '</div>' +
      '<div class="v6-app-metrics">' + rightMain + '<small>' + escapeHtml(rightSub) + '</small></div>' +
    '</div>';
  }).join('') + '</div>';
}

function v6RenderHostFirewallModeHtml() {
  var pv = V6.host.privacy;
  var fw = V6.host.firewall;
  var pvSum = pv.summary || {};
  var findings = Array.isArray(pv.findings) ? pv.findings : [];

  var findingsHtml = '';
  if (V6.host.privacyLoading && !V6.host.privacyLoadedAt) {
    findingsHtml = '<div class="note">正在扫描本机明文连接与直连 DNS 风险…</div>';
  } else if (!findings.length) {
    findingsHtml = '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ok"></span><span>当前未发现本机应用使用 80 明文端口、绕过代理直连 DNS 或已知追踪连接</span></span></div>';
  } else {
    findingsHtml = '<div class="v6-flow-list">' + findings.slice(0, 30).map(function (f, idx) {
      var uid = Math.round(num(f.uid, 0));
      var pkg = v6CleanHostRealPkg(f.package);
      var appNm = v6HostEventAppLabel(f.app_name || f.name, pkg, uid);
      var rType = String(f.risk_type || '');
      var isHttpClear = (rType === 'http_cleartext' || rType === 'cleartext_http');
      var isDnsDirect = (rType === 'dns_direct' || rType === 'direct_dns');
      var rBadge = isHttpClear
        ? '<span class="v6-mono-badge b-bad">HTTP明文</span>'
        : (isDnsDirect
          ? '<span class="v6-mono-badge b-warn">直连DNS</span>'
          : (rType === 'bg_silent_uplink'
            ? '<span class="v6-mono-badge b-acc">后台外发</span>'
            : '<span class="v6-mono-badge b-pur">' + escapeHtml(f.sdk_name || '追踪SDK') + '</span>'));
      var rIp = f.remote_ip || f.dst_ip || '';
      var rPort = f.remote_port != null ? f.remote_port : (f.dport != null ? f.dport : '');
      var targetStr = f.domain ? v6FmtHostPort(f.domain, rPort) : v6FmtHostPort(rIp, rPort);
      var isProt = v6IsHostAppProtected(uid, pkg);
      var curMode = v6HostUidMode(uid);
      var domBlocked = !!(f.domain && fw.blocked_set[String(f.domain).toLowerCase()]);
      var isBgState = (f.app_state === 'background' || f.app_state === 'bg' || f.current_state === 'background');

      return '<div class="v6-flow-item" data-mkey="hpvf-' + uid + '-' + idx + '">' +
        '<div class="v6-flow-main">' +
          '<div class="v6-flow-t">' + rBadge + '<span>' + escapeHtml(appNm) + '</span>' + (isBgState ? '<span class="v6-mono-badge">后台</span>' : '') + '</div>' +
          '<div class="v6-flow-s">' + escapeHtml(targetStr + (f.detail ? (' · ' + f.detail) : '')) + '</div>' +
        '</div>' +
        '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
          (!isProt && isHttpClear && curMode !== 'block_cleartext' && curMode !== 'block_all'
            ? '<button type="button" class="v6-mini-btn pri press" data-v6-act="host-fw-set" data-fw-mode="block_cleartext" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appNm) + '">仅禁明文</button>'
            : '') +
          (f.domain
            ? (domBlocked
              ? '<span class="v6-mono-badge b-ok">域名已拦截</span>'
              : '<button type="button" class="v6-mini-btn warn press" data-v6-act="host-dns-block" data-domain="' + escapeHtml(f.domain) + '">拦截域名</button>')
            : '') +
          '<button type="button" class="v6-mini-btn press" data-v6-act="host-app-open" data-uid="' + uid + '" data-pkg="' + escapeHtml(pkg) + '" data-name="' + escapeHtml(appNm) + '" data-sys="' + (f.is_system ? '1' : '0') + '">管控</button>' +
        '</div>' +
      '</div>';
    }).join('') + '</div>';
  }

  var ipTargetEntries = [];
  fw.uid_rules.forEach(function (r) {
    var rPkg = v6CleanHostRealPkg(r.pkg);
    var disp = v6HostEventAppLabel(r.app_name, rPkg, r.uid);
    var bts = Array.isArray(r.block_targets) ? r.block_targets : [];
    bts.forEach(function (t) {
      var ts = String(t || '').trim();
      if (ts) ipTargetEntries.push({ uid: r.uid, pkg: rPkg, disp: disp, target: ts });
    });
  });

  var uidRulesHtml = fw.uid_rules.length ? ('<div class="v6-flow-list">' + fw.uid_rules.map(function (r) {
    var rPkg = v6CleanHostRealPkg(r.pkg);
    var disp = v6HostEventAppLabel(r.app_name, rPkg, r.uid);
    var rMode = v6NormFwMode(r.mode);
    var bts = Array.isArray(r.block_targets) ? r.block_targets : [];
    var modeBadges = rMode !== 'allow'
      ? (v6FwModeBadgeHtml(rMode) + (bts.length ? ('<span class="v6-mono-badge b-warn">+' + bts.length + ' IP</span>') : ''))
      : ('<span class="v6-mono-badge b-warn">单IP封禁 (' + bts.length + ')</span>');
    var subMeta = (rPkg ? rPkg + ' · ' : '') + 'UID ' + r.uid +
      (r.sdk_sandbox_uid > 0 ? (' · 同步沙箱 ' + r.sdk_sandbox_uid) : '') +
      (bts.length ? (' · 已封 IP：' + bts.slice(0, 3).join('、') + (bts.length > 3 ? (' 等 ' + bts.length + ' 项') : '')) : '');
    var rightBtnHtml = rMode !== 'allow'
      ? '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-fw-set" data-fw-mode="allow" data-uid="' + r.uid + '" data-pkg="' + escapeHtml(rPkg) + '" data-name="' + escapeHtml(disp) + '">恢复放行</button>'
      : '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-uid-ip-clear" data-uid="' + r.uid + '" data-pkg="' + escapeHtml(rPkg) + '" data-name="' + escapeHtml(disp) + '">清空IP封禁</button>';
    return '<div class="v6-flow-item" data-mkey="hfwu-' + r.uid + '">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t">' + modeBadges + '<span>' + escapeHtml(disp) + '</span></div>' +
        '<div class="v6-flow-s">' + escapeHtml(subMeta) + '</div>' +
      '</div>' +
      '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="host-app-open" data-uid="' + r.uid + '" data-pkg="' + escapeHtml(rPkg) + '" data-name="' + escapeHtml(disp) + '" data-sys="0">改档位</button>' +
        rightBtnHtml +
      '</div>' +
    '</div>';
  }).join('') + '</div>') : '<div class="note" style="margin:0">暂无受限应用（在「实时联网 / 后台耗流 / 后台耗电」点任意应用即可一键设为仅禁明文、禁移动网或全局禁网）</div>';

  var ipRulesHtml = ipTargetEntries.length ? ('<div class="v6-flow-list">' + ipTargetEntries.map(function (it) {
    return '<div class="v6-flow-item" data-mkey="hfwip-' + it.uid + '-' + escapeHtml(it.target) + '">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-bad">应用级IP拦截</span><span class="mono">' + escapeHtml(it.target) + '</span></div>' +
        '<div class="v6-flow-s">' + escapeHtml('所属应用：' + it.disp + '（' + (it.pkg ? it.pkg + ' · ' : '') + 'UID ' + it.uid + '）') + '</div>' +
      '</div>' +
      '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-ip-unblock" data-uid="' + it.uid + '" data-ip="' + escapeHtml(it.target) + '" data-pkg="' + escapeHtml(it.pkg) + '" data-name="' + escapeHtml(it.disp) + '">解除封禁</button>' +
    '</div>';
  }).join('') + '</div>') : '<div class="note" style="margin:0">暂无按应用封禁的纯 IP 目标（可在「隐私安检」对直连公网 IP 的明文请求一键封禁）</div>';

  var domRulesHtml = fw.blocked_domains.length ? ('<div class="v6-flow-list">' + fw.blocked_domains.map(function (dom) {
    return '<div class="v6-flow-item" data-mkey="hfwd-' + escapeHtml(dom) + '">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-bad">本机拦截</span><span class="mono">' + escapeHtml(dom) + '</span></div>' +
      '</div>' +
      '<button type="button" class="v6-mini-btn ok press" data-v6-act="host-dns-unblock" data-domain="' + escapeHtml(dom) + '">解除拦截</button>' +
    '</div>';
  }).join('') + '</div>') : '<div class="note" style="margin:0">暂无本机域名黑名单</div>';

  var totRules = num(fw.uid_rule_count, 0) + num(fw.blocked_domain_count, 0);

  return '<div class="v6-shell">' +
    '<div class="sgrp scard glass open" id="v6-host-privacy-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('orange', 'eye') +
        '<span class="tx"><b>本机明文与追踪风险巡检</b><small>零抓包开销扫描本机 80 明文 HTTP、直连 DNS 与追踪连接</small></span>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="host-privacy-refresh">立即扫描</button>' +
      '</div>' +
      '<div class="v6-scard-body">' +
        '<div class="v6-ov-grid">' +
          '<div class="v6-ov-cell' + (num(pvSum.cleartext_http_conns) > 0 ? ' is-bad' : '') + '"><span>80端口明文连接</span><b>' + num(pvSum.cleartext_http_conns, 0) + '</b><small>未加密裸奔请求</small></div>' +
          '<div class="v6-ov-cell' + (num(pvSum.direct_dns_conns) > 0 ? ' is-warn' : '') + '"><span>直连 DNS (:53)</span><b>' + num(pvSum.direct_dns_conns, 0) + '</b><small>绕过本机DNS守卫</small></div>' +
          '<div class="v6-ov-cell' + (num(pvSum.tracker_sdk_conns) > 0 ? ' is-warn' : '') + '"><span>追踪/广告连接</span><b>' + num(pvSum.tracker_sdk_conns, 0) + '</b><small>已知统计与广告域</small></div>' +
          '<div class="v6-ov-cell"><span>涉及风险应用</span><b>' + num(pvSum.risky_apps_count, 0) + '</b><small>支持一键禁明文</small></div>' +
        '</div>' +
        '<div class="lgd-sw-row">' +
          '<span>开启本机深度明文载荷审计<small>平时关闭零额外耗电；开启后实时提取本机 HTTP 明文原文并汇入「隐私安检」</small></span>' +
          toggle(pv.self_capture_enabled, 'data-v6-tog="host-self-capture" aria-label="开启本机深度明文载荷审计"') +
        '</div>' +
        findingsHtml +
      '</div>' +
    '</div>' +
    '<div class="sgrp scard glass open" id="v6-host-fw-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('red', 'lock') +
        '<span class="tx"><b>已生效本机防火墙与域名黑名单</b><small>内核 OUTPUT 链 UID 精确阻断与 DNS 拦截，重启自动恢复</small></span>' +
        (totRules > 0 ? '<button type="button" class="v6-mini-btn dan press" data-v6-act="host-fw-clear">清空全部</button>' : '') +
      '</div>' +
      '<div class="v6-scard-body">' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
          '<label class="lgd-search-mini" style="max-width:none;flex:1 1 200px">' + ico('globe') + '<input id="v6-host-dom-inp" type="text" placeholder="输入要在本机屏蔽的域名，如 ad.example.com" autocomplete="off"></label>' +
          '<button type="button" class="btn sm pri press" data-v6-act="host-dns-add">添加本机拦截</button>' +
        '</div>' +
        '<div><div class="note" style="margin:0 0 6px;font-weight:700;color:var(--text-2)">应用联网限制（' + fw.uid_rules.length + ' 款）</div>' + uidRulesHtml + '</div>' +
        '<div><div class="note" style="margin:0 0 6px;font-weight:700;color:var(--text-2)">本机已封目标 IP（' + ipTargetEntries.length + ' 个）</div>' + ipRulesHtml + '</div>' +
        '<div><div class="note" style="margin:0 0 6px;font-weight:700;color:var(--text-2)">本机屏蔽域名（' + fw.blocked_domains.length + ' 个）</div>' + domRulesHtml + '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function v6RenderHostSubviewHtml() {
  var tf = V6.host.traffic;
  var ts = tf.summary || {};
  var pw = V6.host.power;
  var ds = pw.device_summary || {};
  var fw = V6.host.firewall;
  var rxB = bps(ts.total_rx_bps), txB = bps(ts.total_tx_bps);
  var bgSneakCnt = (tf.apps || []).filter(function (a) {
    return a.current_state !== 'fg' && a.current_state !== 'foreground' && (num(a.total_bps, 0) > 0 || num(a.active_conns, 0) > 0);
  }).length;
  var fwTotal = num(fw.uid_rule_count, 0) + num(fw.blocked_domain_count, 0);

  var drainMain = (pw.screen_off_mah_available && num(ds.screen_off_discharge_mah, 0) > 0)
    ? (Math.round(num(ds.screen_off_discharge_mah, 0)) + ' mAh')
    : (num(ds.actual_discharge_mah, 0) > 0 ? ('总放 ' + Math.round(num(ds.actual_discharge_mah, 0)) + ' mAh') : (V6.host.powerLoadedAt ? '0 mAh' : '按需读取'));
  var drainSub = num(ds.screen_off_on_battery_ms, 0) > 0
    ? ('息屏时长 ' + v6FmtDurMs(ds.screen_off_on_battery_ms))
    : '点后台耗电查看归因';

  var modeBodyHtml = '';
  if (V6.host.mode === 'firewall') {
    modeBodyHtml = v6RenderHostFirewallModeHtml();
  } else if (V6.host.mode === 'traffic') {
    modeBodyHtml = '<div class="sgrp scard glass open" id="v6-host-list-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('orange', 'stats') +
        '<span class="tx"><b>本机应用前后台流量排行</b><small>橙色为后台静默消耗，点按任意应用可一键限制移动网或禁网</small></span>' +
      '</div>' +
      '<div class="v6-scard-body">' +
        '<div class="v6-toolbar-row">' +
          seg('v6-host-period', [['boot', '自开机'], ['today', '今日'], ['7d', '近7天'], ['30d', '近30天']], V6.host.period, 'small') +
          seg('v6-host-net', [['all', '全部'], ['mobile', '移动网'], ['wifi', 'Wi-Fi']], V6.host.net, 'small') +
        '</div>' +
        (tf.bg_split_available === false ? '<div class="lgd-summary-line"><span>当前内核未单独拆分 UID 前后台历史字节，已按总流量真实排序</span></div>' : '') +
        '<label class="lgd-search-mini" style="max-width:none;width:100%">' + ico('search') + '<input id="v6-host-q" type="search" placeholder="搜索本机应用名或包名" value="' + escapeHtml(V6.host.q) + '" autocomplete="off"></label>' +
        '<div id="v6-host-dynamic-list">' + v6RenderHostTrafficRankHtml() + '</div>' +
      '</div>' +
    '</div>';
  } else if (V6.host.mode === 'power') {
    var pDims = [
      ['bg_mah', '后台耗电'],
      ['screen_off_mah', '息屏掉电'],
      ['wakelock_ms', '后台持锁'],
      ['radio_ms', '射频唤醒'],
      ['cpu_bg_ms', '后台CPU']
    ];
    modeBodyHtml = '<div class="sgrp scard glass open" id="v6-host-list-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('purple', 'power') +
        '<span class="tx"><b>后台耗电与持锁唤醒归因</b><small>直读系统 batterystats 真实持锁、射频激活与闹钟唤醒源</small></span>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="host-power-refresh">刷新统计</button>' +
      '</div>' +
      '<div class="v6-scard-body">' +
        '<div class="lgd-type-chips">' +
          pDims.map(function (pd) {
            return '<button type="button" class="lgd-tchip' + (V6.host.powerSort === pd[0] ? ' on' : '') + '" data-v6-act="host-psort" data-sort="' + pd[0] + '">' + pd[1] + '</button>';
          }).join('') +
        '</div>' +
        (V6.host.powerLoadedAt && !pw.bg_mah_available
          ? '<div class="lgd-summary-line"><span>' + escapeHtml(v6BgMahReasonZh(pw.bg_mah_reason)) + '</span></div>'
          : '') +
        '<label class="lgd-search-mini" style="max-width:none;width:100%">' + ico('search') + '<input id="v6-host-q" type="search" placeholder="搜索应用名、包名或唤醒锁名称" value="' + escapeHtml(V6.host.q) + '" autocomplete="off"></label>' +
      '</div>' +
      '<div id="v6-host-dynamic-list">' + v6RenderHostPowerListHtml() + '</div>' +
    '</div>';
  } else {
    modeBodyHtml = '<div class="sgrp scard glass open" id="v6-host-list-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('green', 'globe') +
        '<span class="tx"><b>本机应用实时联网监控</b><small>实时显示前后台网速、活跃连接与访问域名，点按应用开启四档管控</small></span>' +
      '</div>' +
      '<div class="v6-scard-body" style="padding-bottom:10px">' +
        '<label class="lgd-search-mini" style="max-width:none;width:100%">' + ico('search') + '<input id="v6-host-q" type="search" placeholder="搜索应用名、包名或正在访问的域名" value="' + escapeHtml(V6.host.q) + '" autocomplete="off"></label>' +
      '</div>' +
      '<div id="v6-host-dynamic-list">' + v6RenderHostLiveListHtml() + '</div>' +
    '</div>';
  }

  return '<div class="v6-shell">' +
    '<div class="sgrp scard glass open" id="v6-host-ov-card">' +
      '<div class="sgrp-h scard-h scard-head">' +
        gi('blue', 'screen') +
        '<span class="tx"><b>本机守护总览</b><small>仅在停留本页时按需采样，切走或息屏立即零唤醒静默</small></span>' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="host-refresh-all">刷新</button>' +
      '</div>' +
      '<div class="v6-scard-body">' +
        '<div class="v6-ov-grid">' +
          '<div class="v6-ov-cell is-ok"><span>本机实时网速</span><b>↓' + rxB.v + rxB.u + '</b><small>' + (tf.rate_warming_up ? '采样预热中 · ↑' : ('↑' + txB.v + txB.u + ' · 活跃 ' + num(ts.active_conn_apps, 0) + ' 款')) + '</small></div>' +
          '<div class="v6-ov-cell' + (bgSneakCnt > 0 ? ' is-warn' : '') + '"><span>后台活跃联网</span><b>' + bgSneakCnt + ' 款</b><small>后台流量占比 ' + Math.round(clamp(num(ts.bg_ratio_pct, 0), 0, 100)) + '%</small></div>' +
          '<div class="v6-ov-cell"><span>息屏待机掉电</span><b>' + escapeHtml(drainMain) + '</b><small>' + escapeHtml(drainSub) + '</small></div>' +
          '<div class="v6-ov-cell' + (fwTotal > 0 ? ' is-warn' : '') + '"><span>生效管控规则</span><b>' + fwTotal + ' 条</b><small>' + num(fw.uid_rule_count, 0) + ' 款应用 · ' + num(fw.blocked_domain_count, 0) + ' 个域名</small></div>' +
        '</div>' +
        '<div class="lgd-sw-row">' +
          '<span>包含系统底层组件<small>默认仅展示日常安装应用，开启后包含 Android 核心系统服务</small></span>' +
          toggle(V6.host.includeSystem, 'data-v6-tog="host-sys" aria-label="包含系统底层组件"') +
        '</div>' +
        seg('v6-host-mode', [
          ['live', '实时联网'],
          ['traffic', '后台耗流'],
          ['power', '后台耗电'],
          ['firewall', '明文与防火墙']
        ], V6.host.mode, 'small') +
      '</div>' +
    '</div>' +
    modeBodyHtml +
  '</div>';
}

/* ═════════════════════ Sub-Tab 3: 隐私安检 (LeakGuard 零解密明文外泄取证 · 支持本机+热点双来源) ═════════════════════ */
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
  var of = V6.lg.originFilter || 'ALL';
  var tf = V6.lg.typeFilter || 'ALL';
  var q = String(V6.lg.q || '').trim().toLowerCase();
  return V6.lg.events.filter(function (ev) {
    if (of !== 'ALL' && (ev.origin || 'hotspot') !== of) return false;
    if (tf !== 'ALL' && leakTypeGroup(ev.leak_type) !== tf) return false;
    if (!q) return true;
    var hay = (ev.devName + ' ' + (ev.pkg || '') + ' ' + ev.src_ip + ' ' + ev.mac + ' ' + ev.leak_label + ' ' + ev.leak_type + ' ' + ev.raw_value + ' ' + ev.dst_host + ' ' + ev.dst_ip + ' ' + ev.url_path).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6RenderLeakForensicInnerHtml(ev) {
  var srcEnd = ev.src_ip ? v6FmtHostPort(ev.src_ip, ev.src_port || '') : '—';
  var dstEnd = v6FmtHostPort(ev.dst_ip || ev.dst_host || '—', ev.dst_port || 80);
  var tupleStr = srcEnd + ' -> ' + dstEnd + ' (' + ev.proto.toUpperCase() + ')';
  var hostAppLbl = v6HostEventAppLabel(ev.app_name, ev.pkg, ev.uid);
  var realPkg = v6CleanHostRealPkg(ev.pkg);
  var srcOwner = ev.origin === 'host'
    ? ('本机应用 · ' + hostAppLbl + (realPkg && realPkg !== hostAppLbl ? ' (' + realPkg + ')' : '') + (ev.uid > 0 && hostAppLbl.indexOf('UID ') !== 0 ? ' [UID ' + ev.uid + ']' : ''))
    : ('热点设备 · ' + ev.devName + (ev.mac ? ' (' + ev.mac + ')' : ''));
  var urlHost = String(ev.dst_host || '');
  if (urlHost && urlHost.charAt(0) !== '[' && urlHost.indexOf(':') >= 0 && v6ValidIp(urlHost)) {
    urlHost = '[' + urlHost + ']';
  }
  return '<dl class="lgd-forensic-meta">' +
      '<dt>事件来源</dt><dd>' + escapeHtml(srcOwner) + '</dd>' +
      '<dt>通信地址</dt><dd>' + escapeHtml(tupleStr) + '</dd>' +
      '<dt>请求路径</dt><dd>' + escapeHtml(ev.method + ' http://' + urlHost + ev.url_path) + '</dd>' +
      '<dt>客户端标识</dt><dd>' + escapeHtml(ev.user_agent) + '</dd>' +
      '<dt>泄露原文</dt><dd>' + escapeHtml(ev.raw_value) + '</dd>' +
    '</dl>' +
    '<pre class="lgd-forensic-pre">' + highlightRawSnippet(ev.raw_snippet, ev.raw_value) + '</pre>';
}

function v6InfraGuardBadgeHtml(ig) {
  if (!ig || !ig.level) return '';
  if (ig.level === 'hard_block') {
    return '<span class="v6-mono-badge b-pur" title="系统联网检测或核心公共基础设施域名，禁止封禁以免断网">核心域保护 · ' + escapeHtml(ig.label) + '</span>';
  }
  if (ig.level === 'warn_confirm') {
    return '<span class="v6-mono-badge b-warn" title="多款应用共用的公共 CDN 或云底座，封禁前需确认连带影响">共享底座 · ' + escapeHtml(ig.label) + '</span>';
  }
  return '';
}

function v6LeakStreamHtml() {
  var list = v6FilteredLeakEvents();
  if (!list.length) {
    if (V6.lg.events.length > 0) {
      return '<div class="lgd-summary-line"><span>没有匹配当前筛选条件的记录，可切回「全部」查看</span></div>';
    }
    return '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ok"></span><span>暂未发现未加密的 HTTP 隐私明文外发，网络隐私安全</span></span></div>';
  }
  var capLim = Math.max(20, num(V6.lg.visibleLimit, 30));
  var shown = list.slice(0, capLim);
  var rem = list.length - shown.length;

  var cardsHtml = shown.map(function (ev) {
    var isOpen = !!V6.lg.openIds[ev.id];
    var isHostEv = ev.origin === 'host';
    var dObj = (!isHostEv && ev.mac) ? devBy(ev.mac) : null;
    var dispDev = isHostEv
      ? v6HostEventAppLabel(ev.app_name, ev.pkg, ev.uid)
      : ((dObj && dObj.name && dObj.name !== dObj.mac) ? dObj.name : (ev.devName && !v6ValidMac(ev.devName) && !v6ValidIp(ev.devName) ? ev.devName : (dObj ? v6FriendlyDevLabel(dObj, ev.devName) : ev.devName)));
    var originTag = isHostEv
      ? '<span class="v6-mono-badge b-acc">本机应用</span>'
      : '<span class="v6-mono-badge">热点设备</span>';
    var realPkg = v6CleanHostRealPkg(ev.pkg);
    var evUid = Math.round(num(ev.uid, 0));
    var devTitle = isHostEv
      ? [realPkg, evUid > 0 ? ('UID ' + evUid) : '本机未知连接'].filter(Boolean).join(' ')
      : [ev.src_ip, ev.mac].filter(Boolean).join(' ');

    var pureIp = v6ExtractPureIp(ev.dst_host);
    var appId = evUid > 0 ? (evUid % 100000) : -1;
    var isNormalHostApp = isHostEv && evUid > 0 && appId >= 10000 && appId < 90000 && !v6IsHostAppProtected(evUid, ev.pkg);
    var isFakeOrPriv = pureIp ? v6IsFakeOrPrivateIp(pureIp) : false;
    var hostBlkState = isHostEv ? v6ClassifyHostLeakBlockState(ev) : null;
    var appOnlyBlocked = !!(ev.is_blocked && hostBlkState && hostBlkState.appOnlyBlocked);
    var blkDimmed = false;
    var blkBtnTxt;
    var blkBtnActAttr = ' data-v6-act="lgd-block-domain" data-id="' + escapeHtml(ev.id) + '"';
    if (ev.is_blocked) {
      if (appOnlyBlocked) {
        blkBtnTxt = hostBlkState.appMode === 'block_all' ? '已全局禁网 · 管控' : '已禁明文 · 管控';
        blkBtnActAttr = ' data-v6-act="host-app-open" data-uid="' + evUid + '" data-pkg="' + escapeHtml(realPkg) + '" data-name="' + escapeHtml(dispDev) + '" data-sys="0"';
      } else {
        blkBtnTxt = '解除封禁';
      }
    } else if (pureIp) {
      if (isFakeOrPriv || (isHostEv && !isNormalHostApp)) {
        blkBtnTxt = '封禁此 IP';
        blkDimmed = true;
      } else if (isHostEv) {
        blkBtnTxt = '封禁该应用此 IP';
      } else {
        blkBtnTxt = '封禁热点此 IP';
      }
    } else {
      blkBtnTxt = isHostEv ? '拦截本机域名' : '封禁热点域名';
    }
    var blkBadgeLabel = appOnlyBlocked
      ? (hostBlkState.appMode === 'block_all' ? '应用已禁网' : '应用已禁明文')
      : '已封禁目标';
    var blkBtnCls = 'lgd-act-btn ' + (ev.is_blocked ? 'ok' : (blkDimmed ? 'is-dim' : 'warn')) + ' press';
    var blkBtnExtra = blkDimmed ? ' style="opacity:.52" aria-disabled="true" title="系统/代理内网流请用断开或应用防火墙"' : '';

    return '<div class="lgd-item' + (isOpen ? ' is-open' : '') + (ev.is_blocked ? ' is-blocked' : '') + '" data-mkey="lgd-' + escapeHtml(ev.id) + '" data-lgd-id="' + escapeHtml(ev.id) + '">' +
      '<div class="lgd-card-body">' +
        '<div class="lgd-r1">' +
          '<div class="lgd-r1-l">' +
            originTag +
            '<span class="lgd-dev" title="' + escapeHtml(devTitle) + '">' + escapeHtml(dispDev) + '</span>' +
            '<span class="v6-mono-badge ' + leakTypeBadgeCls(ev.leak_type) + '">' + escapeHtml(leakTypeZh(ev.leak_type)) + '</span>' +
            v6InfraGuardBadgeHtml(ev.infra_guard) +
            (ev.is_blocked ? '<span class="v6-mono-badge b-ok">' + blkBadgeLabel + '</span>' : '') +
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
          '<span class="lgd-host" title="' + escapeHtml(ev.dst_host + ev.url_path) + '">发往 -> ' + escapeHtml(ev.dst_host) + (ev.url_path && ev.url_path !== '/' ? (' ' + escapeHtml(ev.url_path)) : '') + '</span>' +
        '</div>' +
        '<div class="lgd-acts">' +
          '<button type="button" class="' + blkBtnCls + '"' + blkBtnExtra + blkBtnActAttr + '>' + blkBtnTxt + '</button>' +
          '<button type="button" class="lgd-act-btn press" data-v6-act="lgd-ignore-sheet" data-id="' + escapeHtml(ev.id) + '">忽略误报</button>' +
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

function v6WhitelistScopeLabel(w) {
  if (!w) return '域名忽略';
  if (w.scope === 'app_host_type' || w.scope === 'app_host' || w.uid > 0 || w.pkg) {
    var aName = v6HostEventAppLabel(w.app_name, w.pkg, w.uid);
    if (w.leak_type) {
      return '仅本机应用「' + aName + '」访问此目标的「' + leakTypeZh(w.leak_type) + '」豁免';
    }
    return '仅本机应用「' + aName + '」豁免';
  }
  if (w.scope === 'device_host_type' || w.scope === 'device_host' || w.mac) {
    var dName = w.device_name || (w.mac && devBy(w.mac) ? devBy(w.mac).name : '') || w.mac || '指定设备';
    if (w.leak_type) {
      return '仅设备「' + dName + '」访问此域名的「' + leakTypeZh(w.leak_type) + '」豁免';
    }
    return '仅设备「' + dName + '」豁免';
  }
  if (w.scope === 'host_type' || w.leak_type) {
    return '同类字段：' + leakTypeZh(w.leak_type || 'PLAINTEXT');
  }
  return '整域名全部明文豁免';
}

function v6RenderLeakGuardManagerBodyHtml() {
  var lg = V6.lg;
  var undoList = Array.isArray(lg.undo_stack) ? lg.undo_stack.slice(0, 10) : [];
  var wlList = Array.isArray(lg.whitelist) ? lg.whitelist : [];

  var undoHtml = undoList.length ? ('<div class="v6-flow-list">' + undoList.map(function (u) {
    var subParts = [];
    if (u.also_ip) subParts.push('连带 IP ' + u.also_ip);
    if (u.device_name) subParts.push('范围 ' + u.device_name);
    if (u.timeStr) subParts.push(u.timeStr);
    return '<div class="v6-flow-item">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-warn">已封禁</span><span class="mono">' + escapeHtml(u.dst_host) + '</span></div>' +
        (subParts.length ? '<div class="v6-flow-s">' + escapeHtml(subParts.join(' · ')) + '</div>' : '') +
      '</div>' +
      '<button type="button" class="v6-mini-btn ok press" data-v6-act="lgd-undo-block" data-uid="' + escapeHtml(u.hasServerId ? u.id : '') + '" data-app-uid="' + escapeHtml(u.uid > 0 ? String(u.uid) : '') + '" data-host="' + escapeHtml(u.dst_host) + '" data-tscope="' + escapeHtml(u.target_scope || '') + '">撤销封禁</button>' +
    '</div>';
  }).join('') + '</div>') : '<div class="note" style="margin:0">暂无最近封禁操作记录（封禁追踪域名或目标 IP 后最多保留最近 10 条供一键反悔恢复）</div>';

  var wlHtml = wlList.length ? ('<div class="v6-flow-list">' + wlList.map(function (w) {
    var scopeTxt = v6WhitelistScopeLabel(w);
    var noteTxt = w.note || w.label || '';
    var ns = w.scope === 'device_host' ? 'device_host_type' : (w.scope === 'app_host' ? 'app_host_type' : (w.scope || 'host'));
    var wid = w.id || w.comboKey || (ns + '|' + (w.dst_host || '') + '|' + (w.leak_type || '') + '|' + (w.mac || '') + '|' + (w.uid > 0 ? w.uid : '') + '|' + (w.pkg || ''));
    return '<div class="v6-flow-item" data-mkey="lgwl-' + escapeHtml(wid) + '">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t"><span class="v6-mono-badge b-acc">已忽略</span><span class="mono">' + escapeHtml(w.dst_host || '全局规则') + '</span></div>' +
        '<div class="v6-flow-s">' + escapeHtml(scopeTxt + (noteTxt ? ' · ' + noteTxt : '')) + '</div>' +
      '</div>' +
      '<button type="button" class="v6-mini-btn dan press" data-v6-act="lgd-wl-remove" data-wid="' + escapeHtml(wid) + '">移除</button>' +
    '</div>';
  }).join('') + '</div>') : '<div class="note" style="margin:0">暂无已忽略的白名单规则（可在下方任意记录点「忽略误报」按粒度添加）</div>';

  return '<div style="display:grid;gap:10px">' +
    '<div><div class="note" style="margin:0 0 6px;font-weight:700;color:var(--text-2)">最近封禁记录（最多 10 条）</div>' + undoHtml + '</div>' +
    '<div><div class="note" style="margin:0 0 6px;font-weight:700;color:var(--text-2)">已忽略误报白名单（共 ' + wlList.length + ' 项）</div>' + wlHtml + '</div>' +
  '</div>';
}

function v6LeakSummaryInnerHtml() {
  var lg = V6.lg;
  var curCnt = Array.isArray(lg.events) ? lg.events.length : 0;
  var wlCnt = Math.max(lg.whitelist ? lg.whitelist.length : 0, Math.round(num(lg.whitelist_count, 0)));
  var blkCnt = Math.max(0, Math.round(num(lg.blocked_domains, 0)));
  var hitExtra = (curCnt > 0 && num(lg.total_hits) > curCnt) ? ('（共触发 ' + num(lg.total_hits) + ' 次）') : '';
  return '<span>当前有效记录 <b class="' + (curCnt > 0 ? 'bad' : '') + '">' + curCnt + '</b> 条' + hitExtra +
    ' · 涉及 <b>' + (curCnt > 0 ? num(lg.affected_devices) : 0) + '</b> 个来源 · 已封禁 <b>' + blkCnt + '</b> 个追踪目标' +
    (wlCnt > 0 ? (' · 已忽略 <b>' + wlCnt + '</b> 项白名单') : '') + '</span>';
}

function v6RenderPrivacySubviewHtml() {
  var lg = V6.lg;
  var undoCnt = Math.max(0, Math.round(num(lg.undo_count, lg.undo_stack ? lg.undo_stack.length : 0)));
  var wlCnt = Math.max(lg.whitelist ? lg.whitelist.length : 0, Math.round(num(lg.whitelist_count, 0)));
  var originTypes = [
    ['ALL', '全部来源'],
    ['host', '本机应用'],
    ['hotspot', '热点设备']
  ];
  var filterTypes = [
    ['ALL', '全部类别'],
    ['PHONE', '手机/证件'],
    ['DEVICE_ID', '设备指纹'],
    ['GPS', '精准定位'],
    ['MAC_ADDR', '网卡地址'],
    ['TOKEN', '账号/凭据'],
    ['OTHER', '其他明文']
  ];
  var originChipsHtml = originTypes.map(function (ot) {
    var on = (lg.originFilter || 'ALL') === ot[0];
    return '<button type="button" class="lgd-tchip' + (on ? ' on' : '') + '" data-v6-act="lgd-origin-filter" data-origin="' + ot[0] + '">' + ot[1] + '</button>';
  }).join('');
  var chipsHtml = filterTypes.map(function (ft) {
    var on = (lg.typeFilter || 'ALL') === ft[0];
    return '<button type="button" class="lgd-tchip' + (on ? ' on' : '') + '" data-v6-act="lgd-filter" data-type="' + ft[0] + '">' + ft[1] + '</button>';
  }).join('');

  return '<div class="sgrp scard glass open" id="v6-leakguard-card">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi('red', 'eye') +
      '<span class="tx"><b>隐私明文安检 <span id="lgd-stream-mode">' + v6StreamModeBadgeHtml() + '</span></b><small>不安装证书、不解密 HTTPS，实时抓出本机与热点裸奔发送敏感信息的明文请求</small></span>' +
      '<div id="lgd-head-acts" style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        (undoCnt > 0 ? '<button type="button" class="v6-mini-btn warn press" data-v6-act="lgd-undo-block">撤销 (' + undoCnt + ')</button>' : '') +
        '<button type="button" class="v6-mini-btn press" data-v6-act="lgd-refresh">刷新</button>' +
        '<button type="button" class="v6-mini-btn dan press" data-v6-act="lgd-clear">清空</button>' +
      '</div>' +
    '</div>' +
    '<div class="v6-scard-body">' +
      '<div class="lgd-summary-line" id="lgd-summary-line">' +
        v6LeakSummaryInnerHtml() +
      '</div>' +
      '<details class="v6-adv-fold" data-v6-fold="lgCfg"' + (V6.advOpen.lgCfg ? ' open' : '') + '>' +
        '<summary><span>手机通知提醒与保留条数设置</span><span class="v6-adv-r"><span>' + (lg.notify_enabled ? '通知已开' : '通知已关') + ' · 保留 ' + lg.capacity + ' 条</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
        '<div class="v6-adv-body">' +
          '<div class="lgd-ctrl-bar">' +
            '<div class="lgd-switches">' +
              '<div class="lgd-sw-row"><span>发现明文泄露时发系统通知<small>在手机状态栏实时弹出安全提醒</small></span>' + toggle(lg.notify_enabled, 'data-v6-tog="lgd-notify" aria-label="发现明文泄露时发系统通知"') + '</div>' +
              '<div class="lgd-sw-row"><span>锁屏通知隐藏中间敏感数字<small>仅影响手机系统弹窗，下方列表始终展示完整原文</small></span>' + toggle(lg.lockscreen_mask, 'data-v6-tog="lgd-mask" aria-label="锁屏通知隐藏中间敏感数字"') + '</div>' +
            '</div>' +
            '<div class="lgd-cfg-box">' +
              '<div class="v6-num-grid">' +
                '<label class="v6-num-field"><span>最多保留记录数</span><span class="v6-num-box"><input id="lgd-cap-inp" type="number" min="10" max="2000" step="10" inputmode="numeric" value="' + lg.capacity + '"><span class="u">条</span></span></label>' +
                '<label class="v6-num-field"><span>同类重复提醒间隔</span><span class="v6-num-box"><input id="lgd-cd-inp" type="number" min="0" max="86400" step="30" inputmode="numeric" value="' + lg.cooldown_sec + '"><span class="u">秒</span></span></label>' +
              '</div>' +
              '<div class="lgd-cfg-acts"><button type="button" class="btn sm pri press" data-v6-act="lgd-save-cfg">保存通知设置</button></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</details>' +
      '<details class="v6-adv-fold" data-v6-fold="lgGuard"' + (V6.advOpen.lgGuard ? ' open' : '') + '>' +
        '<summary><span>误封恢复与忽略白名单管理</span><span class="v6-adv-r"><span id="lgd-guard-cnt">可撤销 ' + undoCnt + ' 条 · 白名单 ' + wlCnt + ' 项</span><span class="v6-adv-chev">' + v6Svg('chev') + '</span></span></summary>' +
        '<div class="v6-adv-body" id="lgd-guard-body">' + v6RenderLeakGuardManagerBodyHtml() + '</div>' +
      '</details>' +
      '<div class="lgd-type-chips">' + originChipsHtml + '</div>' +
      '<div class="lgd-filter-bar">' +
        '<div class="lgd-type-chips">' + chipsHtml + '</div>' +
        '<label class="lgd-search-mini">' + ico('search') + '<input id="lgd-q" type="search" placeholder="搜索应用名、设备名、域名或明文内容" value="' + escapeHtml(lg.q) + '" autocomplete="off"></label>' +
      '</div>' +
      '<div class="lgd-stream" id="lgd-stream-list">' + v6LeakStreamHtml() + '</div>' +
    '</div>' +
  '</div>';
}

/* ═════════════════════ Sub-Tab 4: 连接排障 (异常连接清理 + 卡顿抓拍归因 · 配置备份收口至设置页) ═════════════════════ */
function v6RenderScalpelCardHtml() {
  var sc = V6.scalpel;
  var hsActive = v6IsHotspotActive();
  var hsConns = v6HotspotFlowCount();
  var hostConns = v6HostFlowCount();
  var onlineDevs = hsActive ? (S.devices || []).filter(function (d) { return d && d.online; }).slice(0, 10) : [];
  var devJumpHtml = onlineDevs.length ? onlineDevs.map(function (d) {
    return '<button type="button" class="v6-dev-pill press" data-v6-act="open-scalpel" data-scope="hotspot" data-mac="' + escapeHtml(d.mac) + '" data-ip="' + escapeHtml(d.ip || '') + '" data-name="' + escapeHtml(d.name) + '">' +
      v6Svg('scalpel') + '<span>' + escapeHtml(d.name) + '</span>' +
    '</button>';
  }).join('') : '<span class="note">' + (hsActive ? '当前暂无在线热点设备' : '当前热点未开启（仍可清理本机应用活跃连接）') + '</span>';

  return '<div class="sgrp scard glass open" id="v6-card-scalpel">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi('blue', 'scalpel') +
      '<span class="tx"><b>异常连接手术刀</b><small>不断开整机网络，正交管理热点设备与本机应用连接，支持冻结 15 分钟</small></span>' +
    '</div>' +
    '<div class="v6-scard-body">' +
      '<div class="v6-kpi-row">' +
        '<div class="v6-kpi is-ok"><span>热点设备连接</span><b>' + hsConns + '<small>条</small></b></div>' +
        '<div class="v6-kpi is-acc"><span>本机应用连接</span><b>' + hostConns + '<small>条</small></b></div>' +
        '<div class="v6-kpi ' + (sc.activeRulesCount > 0 ? 'is-warn' : '') + '"><span>15分钟冻结中</span><b>' + num(sc.activeRulesCount) + '<small>条</small></b></div>' +
      '</div>' +
      '<div>' +
        '<div class="note" style="margin:0 0 6px">点选在线热点设备单独查看连接：</div>' +
        '<div class="v6-dev-pills">' + devJumpHtml + '</div>' +
      '</div>' +
      '<div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px">' +
        '<button type="button" class="btn sec press" data-v6-act="open-scalpel" data-scope="host" data-mac="" data-ip="" data-name="">管理本机连接 (' + hostConns + ')</button>' +
        '<button type="button" class="btn pri press" data-v6-act="open-scalpel" data-scope="all" data-mac="" data-ip="" data-name="">管理全网连接</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

/* ── 黑匣子四维人话归因字典与证据格式器 ── */
var V6_BB_DIMS = {
  uplink_saturated: { key: 'uplink_saturated', label: '手机上行占满', cls: 'b-warn' },
  cell_jitter:      { key: 'cell_jitter',      label: '基站信号抖动', cls: 'b-acc' },
  device_hog:       { key: 'device_hog',       label: '设备大流量抢网', cls: 'b-pur' },
  thermal_throttle: { key: 'thermal_throttle', label: '发热温控降速', cls: 'b-bad' }
};

function v6BlackboxDim(inc) {
  inc = inc || {};
  var rawDim = String(inc.dimension || inc.cause_dim || inc.root_cause || inc.cause || inc.category || '').toLowerCase().trim();
  if (V6_BB_DIMS[rawDim]) return V6_BB_DIMS[rawDim];
  var rLow = String(inc.reason || '').toLowerCase().trim();
  if (V6_BB_DIMS[rLow]) return V6_BB_DIMS[rLow];
  var zhText = String(inc.verdict_zh || '') + ' ' + String(inc.root_cause_zh || '') + ' ' + String(inc.culprit_device || '');
  if (num(inc.thermal_stage, 0) >= 2 || num(inc.temp_c, 0) >= 45 || /thermal|温控|过热|降温/.test(rLow + ' ' + zhText)) {
    return V6_BB_DIMS.thermal_throttle;
  }
  if (num(inc.uplink_util_pct, 0) >= 80 || num(inc.up_util_pct, 0) >= 80 || /uplink|上行占满|上行拥塞/.test(rLow + ' ' + zhText)) {
    return V6_BB_DIMS.uplink_saturated;
  }
  if (inc.culprit_is_hog === false || (!inc.culprit_mac && (rLow === 'rtt_spike' || /基站|空口|切站|信号|cell|nr|lte|pci/i.test(zhText)))) {
    return V6_BB_DIMS.cell_jitter;
  }
  return V6_BB_DIMS.device_hog;
}

function v6BlackboxVerdictZh(inc, dim) {
  inc = inc || {};
  if (inc.verdict_zh && String(inc.verdict_zh).trim()) return String(inc.verdict_zh).trim();
  if (inc.root_cause_zh && String(inc.root_cause_zh).trim()) return String(inc.root_cause_zh).trim();
  var r = String(inc.reason || '').trim();
  var rl = r.toLowerCase();
  if (rl === 'rtt_and_bw_spike') return '热点带宽瞬时跑满引发排队延迟抬升';
  if (rl === 'bw_saturated') return '热点总带宽瞬时占满，已触发平滑限流保护';
  if (rl === 'rtt_spike') return (dim && dim.key === 'cell_jitter') ? '手机蜂窝基站信号波动引起短暂跳 Ping' : '无线链路或上游网络出现短暂延迟抬升';
  if (rl === 'uplink_saturated') return '手机蜂窝上行带宽占满引起确认包排队';
  if (rl === 'cell_jitter') return '手机蜂窝基站切站或弱信号引起空口抖动';
  if (rl === 'device_hog') return '连接设备突发大流量下载抢占网速';
  if (rl === 'thermal_throttle') return '手机机身偏热触发温控保护降载';
  if (r && /[\u4e00-\u9fa5]/.test(r)) return r;
  if (dim && dim.key === 'thermal_throttle') return '手机温度偏高触发温控降载保护';
  if (dim && dim.key === 'uplink_saturated') return '手机蜂窝上行通道占满引起延迟抬升';
  if (dim && dim.key === 'cell_jitter') return '蜂窝基站空口抖动引起短暂延迟波动';
  return '突发流量拥塞引起延迟抬升';
}

function v6BlackboxEvidenceLine(inc, dim) {
  inc = inc || {};
  var peakRtt = num(inc.peak_rtt_ms, inc.rtt_ms);
  var dRtt = num(inc.delta_rtt_ms);
  var rttTail = peakRtt > 0
    ? ('峰值 ' + peakRtt.toFixed(1) + ' ms' + (dRtt > 0 ? ' (+' + dRtt.toFixed(1) + ' ms)' : ''))
    : (num(inc.jitter_ms) > 0 ? ('抖动 ' + num(inc.jitter_ms).toFixed(1) + ' ms') : '');
  var isNonHog = (inc.culprit_is_hog === false) ||
    (inc.culprit_is_hog === undefined && (dim.key === 'cell_jitter' || dim.key === 'thermal_throttle') && !v6ValidMac(inc.culprit_mac));

  if (isNonHog) {
    var evParts = [];
    var presetEv = String(inc.evidence_zh || inc.signal_evidence_zh || inc.env_evidence || '').trim();
    if (presetEv) {
      evParts.push(presetEv);
    } else {
      var sigObj = (inc.signal && typeof inc.signal === 'object') ? inc.signal : inc;
      var ratBand = [sigObj.display_rat || sigObj.rat || '', sigObj.band || ''].filter(Boolean).join(' ');
      if (ratBand) evParts.push(ratBand);
      if (sigObj.rsrp_dbm != null && num(sigObj.rsrp_dbm, 0) !== 0) evParts.push('信号 ' + Math.round(num(sigObj.rsrp_dbm)) + ' dBm');
      if (sigObj.sinr_db != null && isFinite(parseFloat(sigObj.sinr_db))) evParts.push('SINR ' + Math.round(num(sigObj.sinr_db)) + ' dB');
      var upPct = inc.uplink_util_pct != null ? num(inc.uplink_util_pct, -1) : num(inc.up_util_pct, -1);
      if (upPct > 0) evParts.push('上行占用 ' + Math.round(upPct) + '%');
      var tc = num(inc.temp_c != null ? inc.temp_c : (inc.thermal_temp_c != null ? inc.thermal_temp_c : 0), 0);
      if (tc > 0) evParts.push('机身 ' + tc.toFixed(1) + '°C');
      var rcZh = String(inc.root_cause_zh || '').trim();
      if (!evParts.length && rcZh && rcZh !== String(inc.verdict_zh || '').trim()) evParts.push(rcZh);
      if (!evParts.length && inc.culprit_device && !v6ValidMac(inc.culprit_device)) evParts.push(String(inc.culprit_device));
      if (!evParts.length) evParts.push(dim.key === 'thermal_throttle' ? '热点手机温控降载保护生效（非连接设备抢网）' : '上游蜂窝基站空口波动（非连接设备抢网）');
    }
    if (rttTail && presetEv.indexOf('ms') < 0) evParts.push(rttTail);
    return '现场证据：' + evParts.join(' · ');
  }

  var culpritDev = inc.culprit_name || inc.culprit_device || inc.culprit_mac || '连接设备突发流量';
  var appSuffix = inc.active_app_name
    ? ('（' + inc.active_app_name + (inc.culprit_share_pct ? ' · 占 ' + Math.round(num(inc.culprit_share_pct)) + '%' : '') + '）')
    : (inc.culprit_share_pct ? ('（占 ' + Math.round(num(inc.culprit_share_pct)) + '%）') : '');
  return '主要来源：' + culpritDev + appSuffix + (rttTail ? (' · ' + rttTail) : '');
}

function v6SecondaryDimsBadgesHtml(inc, primaryKey) {
  if (!inc || !Array.isArray(inc.secondary_dims) || !inc.secondary_dims.length) return '';
  return inc.secondary_dims.map(function (sd) {
    var k = String(sd || '').toLowerCase().trim();
    var m = V6_BB_DIMS[k];
    if (!m || m.key === primaryKey) return '';
    return '<span class="v6-mono-badge">' + escapeHtml('伴随：' + m.label) + '</span>';
  }).join('');
}

function v6RenderBlackboxCardHtml() {
  var bb = V6.blackbox, mi = V6.multiIface, sb = V6.subtrees;
  var hasInc = !!(bb.incidents && bb.incidents.length);

  var latestVerdictBoxHtml = '';
  if (hasInc) {
    var inc0 = bb.incidents[0];
    var dim0 = v6BlackboxDim(inc0);
    var rawMs0 = num(inc0.ts_unix_ms, inc0.unix_ms);
    var ts0 = rawMs0 ? fmtClockTs(rawMs0) : '--:--:--';
    var vZh0 = v6BlackboxVerdictZh(inc0, dim0);
    var ev0 = v6BlackboxEvidenceLine(inc0, dim0);
    var lbl0 = String(inc0.cause_label_zh || dim0.label);
    latestVerdictBoxHtml = '<div class="v6-lat-cmp" data-mkey="bb-latest-verdict">' +
      '<div class="v6-lat-top">' +
        '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">' +
          '<b>最近一次卡顿结论</b>' +
          '<span class="v6-mono-badge ' + dim0.cls + '">' + escapeHtml(lbl0) + '</span>' +
          v6SecondaryDimsBadgesHtml(inc0, dim0.key) +
        '</div>' +
        '<span class="v6-mono-badge mono">' + escapeHtml(ts0) + '</span>' +
      '</div>' +
      '<div style="font-size:13px;font-weight:650;color:var(--text-1);margin-top:5px;line-height:1.45">' + escapeHtml(vZh0) + '</div>' +
      '<div class="note" style="margin:3px 0 0">' + escapeHtml(ev0) + '</div>' +
    '</div>';
  }

  var incHtml = hasInc ? ('<div class="v6-flow-list">' + bb.incidents.slice(0, 5).map(function (inc) {
    var dim = v6BlackboxDim(inc);
    var rawMs = num(inc.ts_unix_ms, inc.unix_ms);
    var ts = rawMs ? fmtClockTs(rawMs) : '--:--:--';
    var verdictZh = v6BlackboxVerdictZh(inc, dim);
    var subEvidence = v6BlackboxEvidenceLine(inc, dim);
    var dimLbl = String(inc.cause_label_zh || dim.label);
    var canLocate = v6ValidMac(inc.culprit_mac) && (inc.culprit_is_hog === true || (inc.culprit_is_hog !== false && dim.key !== 'cell_jitter' && dim.key !== 'thermal_throttle'));
    return '<div class="v6-flow-item">' +
      '<div class="v6-flow-main">' +
        '<div class="v6-flow-t">' +
          '<span class="v6-mono-badge mono">' + escapeHtml(ts) + '</span>' +
          '<span class="v6-mono-badge ' + dim.cls + '">' + escapeHtml(dimLbl) + '</span>' +
          v6SecondaryDimsBadgesHtml(inc, dim.key) +
          '<span>' + escapeHtml(verdictZh) + '</span>' +
        '</div>' +
        '<div class="v6-flow-s">' + escapeHtml(subEvidence) + '</div>' +
      '</div>' +
      (canLocate ? '<button type="button" class="v6-mini-btn press" data-jump-mac="' + escapeHtml(inc.culprit_mac) + '">定位设备</button>' : '') +
    '</div>';
  }).join('') + '</div>') : '<div class="lgd-summary-line"><span style="display:inline-flex;align-items:center;gap:7px"><span class="v6-dot ok"></span><span>近期网络平稳，未捕捉到明显跳 Ping 卡顿事件</span></span></div>';

  var ifacesTxt = mi.shape_targets && mi.shape_targets.length ? mi.shape_targets.join(' + ') : (mi.primary_downstream || '自动跟随热点接口');
  var rttProbeOff = bb.rtt_probe_active === false ||
    (bb.rtt_probe_active == null && !(num(bb.latest_jitter_ms) > 0) && !(num(bb.latest_rtt_ms) > 0) && !(typeof S !== 'undefined' && S.autorate && S.autorate.enabled === true && num(S.autorate.rtt_ms) > 0));
  var rttKpiHtml = rttProbeOff
    ? '<div class="v6-kpi"><span>上游 RTT</span><b style="font-size:13px;color:var(--text-3);font-weight:650">未开启延迟探测</b></div>'
    : '<div class="v6-kpi ' + (bb.latest_jitter_ms > 25 ? 'is-warn' : 'is-ok') + '"><span>当前延迟波动</span><b>' + num(bb.latest_jitter_ms).toFixed(1) + '<small>ms</small></b></div>';

  return '<div class="sgrp scard glass open" id="v6-card-blackbox">' +
    '<div class="sgrp-h scard-h scard-head">' +
      gi('purple', 'heart') +
      '<span class="tx"><b>卡顿抓拍与多网状态</b><small>每 0.2 秒监测延迟抖动，精准区分设备抢网、上行占满、基站抖动与高温降速</small></span>' +
      '<div style="display:inline-flex;gap:6px;flex-wrap:wrap">' +
        '<button type="button" class="v6-mini-btn press" data-v6-act="bb-sample">检测</button>' +
        (hasInc ? '<button type="button" class="v6-mini-btn dan press" data-v6-act="bb-clear">清空</button>' : '') +
      '</div>' +
    '</div>' +
    '<div class="v6-scard-body">' +
      '<div class="v6-kpi-row">' +
        rttKpiHtml +
        '<div class="v6-kpi ' + (bb.incident_count > 0 ? 'is-warn' : '') + '"><span>抓拍卡顿事件</span><b>' + num(bb.incident_count) + '<small>次</small></b></div>' +
        '<div class="v6-kpi is-acc"><span>三档网速配比</span><b>' + sb.tier1_pct + '/' + sb.tier2_pct + '/' + sb.tier3_pct + '</b></div>' +
      '</div>' +
      latestVerdictBoxHtml +
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
    '</div>' +
  '</div>';
}

function v6RenderSubviewHtml() {
  if (V6.subtab === 'host') {
    return v6RenderHostSubviewHtml();
  }
  if (V6.subtab === 'privacy') {
    return v6RenderPrivacySubviewHtml();
  }
  if (V6.subtab === 'troubleshoot') {
    return '<div class="v6-grid cols-2">' +
      v6RenderScalpelCardHtml() +
      v6RenderBlackboxCardHtml() +
    '</div>';
  }
  return '<div class="v6-grid cols-2">' +
    v6RenderExpressCardHtml() +
    v6RenderLeashCardHtml() +
    '</div>' +
    v6RenderThermoCardHtml();
}

/* ═════════════════════ 页面主渲染、弹簧分段器切换与跨页面跳转契约 ═════════════════════ */
function renderVectorPage(anim1) {
  var p = document.getElementById('p-vector');
  if (!p) return;
  if (V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  var html = '<div class="wrap v6-shell">' +
    '<div id="v6-hero-mount">' + v6RenderHeroCardHtml() + '</div>' +
    '<div id="v6-nav-mount">' + v6RenderMainSegHtml() + '</div>' +
    '<div id="v6-subview-mount" class="v6-shell">' + v6RenderSubviewHtml() + '</div>' +
  '</div>';
  if (!anim1 && p.firstElementChild) morph(p, html);
  else p.innerHTML = html;
  if (typeof placeSegs === 'function') placeSegs(p);
  v6SyncHostPollTimer();
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
  /* 若用户正在输入框内打字，仅刷新流列表与白名单/摘要内部节点，绝不重绘外层容器或打断输入法光标 */
  if (ae && ae.tagName === 'INPUT' && ae.closest('#p-vector')) {
    if (V6.subtab === 'privacy') {
      var st = document.getElementById('lgd-stream-list');
      if (st) morph(st, v6LeakStreamHtml());
      var gb = document.getElementById('lgd-guard-body');
      if (gb) morph(gb, v6RenderLeakGuardManagerBodyHtml());
      var lg = V6.lg;
      var undoCnt = Math.max(0, Math.round(num(lg.undo_count, lg.undo_stack ? lg.undo_stack.length : 0)));
      var wlCnt = Math.max(lg.whitelist ? lg.whitelist.length : 0, Math.round(num(lg.whitelist_count, 0)));
      var gc = document.getElementById('lgd-guard-cnt');
      if (gc) gc.textContent = '可撤销 ' + undoCnt + ' 条 · 白名单 ' + wlCnt + ' 项';
      var sl = document.getElementById('lgd-summary-line');
      if (sl) {
        sl.innerHTML = v6LeakSummaryInnerHtml();
      }
      var ha = document.getElementById('lgd-head-acts');
      if (ha) {
        morph(ha, (undoCnt > 0 ? '<button type="button" class="v6-mini-btn warn press" data-v6-act="lgd-undo-block">撤销 (' + undoCnt + ')</button>' : '') +
          '<button type="button" class="v6-mini-btn press" data-v6-act="lgd-refresh">刷新</button>' +
          '<button type="button" class="v6-mini-btn dan press" data-v6-act="lgd-clear">清空</button>');
      }
    } else if (V6.subtab === 'host' && ae.id === 'v6-host-q') {
      var hl = document.getElementById('v6-host-dynamic-list');
      if (hl) {
        var nextInner = V6.host.mode === 'traffic'
          ? v6RenderHostTrafficRankHtml()
          : (V6.host.mode === 'power' ? v6RenderHostPowerListHtml() : v6RenderHostLiveListHtml());
        morph(hl, nextInner);
      }
    }
    return;
  }
  var sub = document.getElementById('v6-subview-mount');
  if (sub) {
    /* 备份内部 .seg 滑块坐标以防 morph 清空内联 transform 后丢失过渡基线 */
    var segSnaps = [];
    $$('.seg', sub).forEach(function (sg) {
      var th = $('.thumb', sg);
      if (th && th.style.transform) {
        segSnaps.push({ id: sg.getAttribute('data-seg'), w: th.style.width, tf: th.style.transform, lx: th._lx });
      }
    });
    morph(sub, v6RenderSubviewHtml());
    segSnaps.forEach(function (sn) {
      var sg2 = sub.querySelector('.seg[data-seg="' + sn.id + '"]');
      var th2 = sg2 && $('.thumb', sg2);
      if (th2) {
        th2.style.transition = 'none';
        th2.style.width = sn.w;
        th2.style.transform = sn.tf;
        th2._lx = sn.lx;
        void th2.offsetWidth;
        th2.style.transition = '';
      }
    });
    if (typeof placeSegs === 'function') placeSegs(sub);
  }
}

function onEnterVectorPage() {
  if (typeof window !== 'undefined' && window.__pendingV6Subtab) {
    var pend = window.__pendingV6Subtab;
    window.__pendingV6Subtab = null;
    openV6Subtab(pend.tab, pend.opts);
    return;
  }
  if (V6.subtab === 'privacy') v6MarkLeakGuardSeen();
  if (V6.apiSupported.lg) v6LoadLeakGuard();
  if (V6.apiSupported.v6) v6LoadCockpitAll();
  if (!KSU) v6StartLeakGuardSSE();
  if (V6.subtab === 'host') {
    v6EnsureHostModeLoaded(false);
  } else {
    v6SyncHostPollTimer();
  }
}

/* 跨页面统一跳转契约：供设备页、应用页、统计页一键跳入「本机守护」或任意子分区 */
function openV6Subtab(tab, opts) {
  var nextTab = ['escort', 'host', 'privacy', 'troubleshoot'].indexOf(tab) >= 0 ? tab : 'escort';
  var hm = typeof opts === 'string' ? opts : (opts && (opts.hostMode || opts.mode || opts.submode));
  if (hm && ['live', 'traffic', 'power', 'firewall'].indexOf(hm) >= 0) {
    V6.host.mode = hm;
    LS.set('hnc6.v6_host_mode', hm);
    if (!tab || tab === 'host') nextTab = 'host';
  }
  V6.subtab = nextTab;
  LS.set('hnc6.v6_subtab', nextTab);
  if (nextTab === 'privacy') v6MarkLeakGuardSeen();

  if (typeof S !== 'undefined' && S.page !== 'vector' && typeof go === 'function') {
    go('vector');
    v6RefreshHeroDom();
    v6RefreshNavBadges();
    v6RefreshActiveSubviewDom();
    if (nextTab === 'host') v6EnsureHostModeLoaded(false);
    else v6SyncHostPollTimer();
  } else {
    v6RefreshHeroDom();
    v6RefreshNavBadges();
    v6RefreshActiveSubviewDom();
    if (nextTab === 'host') v6EnsureHostModeLoaded(false);
    else v6SyncHostPollTimer();
  }
  if (opts && opts.openScalpel) {
    var scDom = ['all', 'hotspot', 'host'].indexOf(opts.openScalpel) >= 0 ? opts.openScalpel : 'all';
    setTimeout(function () { openScalpelDrawer('', '', '', scDom); }, 40);
  }
}
if (typeof window !== 'undefined') window.openV6Subtab = openV6Subtab;

function v6FocusPrivacyPanel() {
  openV6Subtab('privacy');
  setTimeout(function () {
    var el = document.getElementById('v6-leakguard-card');
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: motionOn() ? 'smooth' : 'auto', block: 'start' });
  }, 60);
}
var v6ScrollToLeakGuard = v6FocusPrivacyPanel;

/* ═════════════════════ FlowScalpel 正交双域连接清理抽屉（支持全部 / 热点设备 / 本机应用切换） ═════════════════════ */
function v6FilteredScalpelDrawerFlows() {
  var isDevScoped = !!(V6.scalpel.scopeMac || V6.scalpel.scopeIp);
  var hasDrawerArr = Array.isArray(V6.scalpel.drawerFlows);
  var src = (isDevScoped || V6.scalpel.scopeDomain !== 'all')
    ? (hasDrawerArr ? V6.scalpel.drawerFlows : [])
    : (hasDrawerArr && V6.scalpel.drawerFlows.length ? V6.scalpel.drawerFlows : V6.scalpel.globalFlows);
  var domScope = isDevScoped ? 'hotspot' : (V6.scalpel.scopeDomain || 'all');
  var pf = V6.scalpel.protoFilter || 'ALL';
  var q = String(V6.scalpel.q || '').trim().toLowerCase();
  return src.filter(function (f) {
    if (!isDevScoped && domScope !== 'all' && f.scope !== domScope) return false;
    if (pf === 'TCP' && f.proto !== 'tcp') return false;
    if (pf === 'UDP' && f.proto !== 'udp') return false;
    if (pf === 'FROZEN' && !f.frozen) return false;
    if (!q) return true;
    var srcEp = v6FmtHostPort(f.src_ip, f.sport);
    var dstEp = v6FmtHostPort(f.dst_ip, f.dport);
    var hay = (f.devName + ' ' + (f.pkg || '') + ' ' + f.app_name + ' ' + f.dst_host + ' ' + srcEp + ' ' + dstEp + ' ' + f.src_ip + ' ' + f.dst_ip + ' ' + f.protoBadge).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function v6ScalpelListHtml() {
  var dLen = Array.isArray(V6.scalpel.drawerFlows) ? V6.scalpel.drawerFlows.length : 0;
  var isSub = !!(V6.scalpel.scopeMac || V6.scalpel.scopeIp || V6.scalpel.scopeDomain !== 'all');
  if (V6.scalpel.loading && (isSub ? !dLen : (!dLen && !V6.scalpel.globalFlows.length))) {
    return '<div class="empty">正在读取实时活跃连接…</div>';
  }
  if (V6.scalpel.err) {
    return '<div class="note err">' + escapeHtml(V6.scalpel.err) + '</div>';
  }
  var list = v6FilteredScalpelDrawerFlows();
  if (!list.length) {
    return '<div class="empty">' + (V6.scalpel.scopeDomain === 'hotspot' && !v6IsHotspotActive() ? '当前热点未开启，热点连接为 0' : '当前筛选范围内没有活跃连接') + '</div>';
  }
  return list.map(function (f) {
    var rxB = bps(f.rx_bps), txB = bps(f.tx_bps);
    var pCls = f.frozen ? 'b-bad' : (f.protoBadge === 'QUIC' ? 'b-pur' : (f.proto === 'udp' ? 'b-acc' : ''));
    var dstEp = v6FmtHostPort(f.dst_ip, f.dport);
    var srcEp = v6FmtHostPort(f.src_ip, f.sport);
    var titleMain = f.app_name ? (f.app_name + (f.dst_host ? ' · ' + f.dst_host : '')) : (f.dst_host || dstEp);
    var remMin = f.frozen ? Math.max(1, Math.ceil((f.frozen_until - Date.now() / 1000) / 60)) : 0;
    var isHost = f.scope === 'host';
    var ownerBadge = !V6.scalpel.scopeMac
      ? ('<span class="v6-mono-badge ' + (isHost ? 'b-acc' : '') + '">' + escapeHtml((isHost ? '本机 · ' : '') + f.devName) + '</span>')
      : '';
    var riskBadge = f.cleartext_risk === 'http_cleartext'
      ? '<span class="v6-mono-badge b-bad">HTTP明文</span>'
      : (f.cleartext_risk === 'dns_direct' ? '<span class="v6-mono-badge b-warn">直连DNS</span>' : '');

    return '<div class="v6-tuple-row" data-mkey="sc-' + escapeHtml(f.id) + '">' +
      '<div class="v6-tuple-5">' +
        '<div class="v6-tuple-primary">' +
          '<span class="v6-mono-badge mono ' + pCls + '">' + escapeHtml(f.frozen ? ('冻结剩' + remMin + '分') : f.protoBadge) + '</span>' +
          riskBadge +
          '<span>' + escapeHtml(titleMain) + '</span>' +
          ownerBadge +
        '</div>' +
        '<div class="ep">' + escapeHtml(srcEp + ' -> ' + dstEp) + (f.state && f.state !== 'ESTABLISHED' && f.state !== 'ASSURED' ? (' · ' + escapeHtml(f.state)) : '') + '</div>' +
      '</div>' +
      '<div class="v6-tuple-rate">↓ ' + rxB.v + ' ' + rxB.u + '<br>↑ ' + txB.v + ' ' + txB.u + '</div>' +
      '<div class="v6-tuple-acts">' +
        '<button type="button" class="lgd-act-btn warn press" data-v6-act="scalpel-cut-once" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('cut') + '<span>断开一次</span></button>' +
        '<button type="button" class="lgd-act-btn dan press" data-v6-act="scalpel-cut-freeze" data-fid="' + escapeHtml(f.id) + '">' + v6Svg('freeze') + '<span>冻结15分</span></button>' +
      '</div>' +
    '</div>';
  }).join('');
}

function v6ResetScalpelScroll() {
  var listEl = document.getElementById('v6-scalpel-list') || document.querySelector('#v6-scalpel-drawer .v6-tuple-list');
  if (listEl) listEl.scrollTop = 0;
}

function v6ScalpelDrawerBodyHtml() {
  var sc = V6.scalpel;
  var isScoped = !!(sc.scopeMac || sc.scopeIp);
  var hsCnt = v6HotspotFlowCount();
  var hostCnt = v6HostFlowCount();
  var scopeTitle = isScoped
    ? ('活跃连接 · ' + (sc.devName || sc.scopeIp || sc.scopeMac))
    : (sc.scopeDomain === 'hotspot' ? '热点设备活跃连接' : (sc.scopeDomain === 'host' ? '本机应用活跃连接' : '全网活跃连接手术刀'));
  var shownCount = v6FilteredScalpelDrawerFlows().length;
  var pTabs = [['ALL', '全部'], ['TCP', 'TCP'], ['UDP', 'UDP / QUIC'], ['FROZEN', '冻结中']];

  return '<div class="v6-drawer-head">' +
      '<div style="min-width:0">' +
        '<div style="display:flex;align-items:center;gap:6px;font-size:15px;font-weight:750;color:var(--text-1)" id="v6-sc-title">' + v6Svg('scalpel') + '<span>' + escapeHtml(scopeTitle) + '</span></div>' +
        '<div style="font-size:11.5px;color:var(--text-3);margin-top:2px">「断开一次」秒清卡死套接字；「冻结15分」阻止后台顽固重连</div>' +
      '</div>' +
      '<button type="button" class="v6-mini-btn press" data-v6-act="scalpel-close">关闭</button>' +
    '</div>' +
    (!isScoped
      ? ('<div style="margin-bottom:8px" id="v6-sc-scope-mount">' + seg('v6-sc-scope', [
          ['all', '全部 (' + (hsCnt + hostCnt) + ')'],
          ['hotspot', '热点设备 (' + hsCnt + ')'],
          ['host', '本机应用 (' + hostCnt + ')']
        ], sc.scopeDomain || 'all', 'small') + '</div>')
      : '') +
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
      '<label class="lgd-search-mini" style="max-width:none;width:100%">' + ico('search') + '<input id="v6-sc-q" type="search" placeholder="搜索本机应用、设备名、域名、IP 或端口" value="' + escapeHtml(sc.q) + '" autocomplete="off"></label>' +
    '</div>' +
    '<div class="v6-tuple-list" id="v6-scalpel-list">' + v6ScalpelListHtml() + '</div>';
}

function v6RefreshScalpelDrawerList() {
  var listEl = document.getElementById('v6-scalpel-list');
  if (listEl) morph(listEl, v6ScalpelListHtml());
  var cntEl = document.getElementById('v6-sc-cnt-pill');
  if (cntEl) cntEl.textContent = '共 ' + v6FilteredScalpelDrawerFlows().length + ' 条';
  var scopeMount = document.getElementById('v6-sc-scope-mount');
  if (scopeMount) {
    var hsCnt = v6HotspotFlowCount(), hostCnt = v6HostFlowCount();
    var bAll = scopeMount.querySelector('button[data-v="all"]');
    var bHs = scopeMount.querySelector('button[data-v="hotspot"]');
    var bHo = scopeMount.querySelector('button[data-v="host"]');
    if (bAll) bAll.textContent = '全部 (' + (hsCnt + hostCnt) + ')';
    if (bHs) bHs.textContent = '热点设备 (' + hsCnt + ')';
    if (bHo) bHo.textContent = '本机应用 (' + hostCnt + ')';
    if (typeof placeSegs === 'function') placeSegs(scopeMount);
  }
}

function v6FetchScalpelFlows() {
  if (!V6.scalpel.open) return Promise.resolve();
  var isDevScoped = !!(v6ValidMac(V6.scalpel.scopeMac) || v6ValidIp(V6.scalpel.scopeIp));
  var domScope = isDevScoped ? 'hotspot' : (V6.scalpel.scopeDomain || 'all');
  var isScopedReq = isDevScoped || domScope !== 'all';
  var reqMac = V6.scalpel.scopeMac;
  var reqIp = V6.scalpel.scopeIp;
  var reqDevName = V6.scalpel.devName;
  var reqSeq = (V6.scalpel.reqSeq || 0) + 1;
  V6.scalpel.reqSeq = reqSeq;
  var params = { scope: domScope, limit: 200 };
  if (v6ValidMac(reqMac)) params.mac = reqMac;
  if (v6ValidIp(reqIp)) params.ip = reqIp;

  V6.scalpel.loading = true;
  V6.scalpel.err = '';
  return api.get(V6_API.scalpelFlows, params, { timeout: 7000 }).then(function (r) {
    if (!V6.scalpel.open || reqSeq !== V6.scalpel.reqSeq) return;
    V6.scalpel.loading = false;
    if (r && (r.hotspot_flows != null || r.host_flows != null)) {
      V6.scalpel.hasSplitCounts = true;
      V6.scalpel.hotspotFlows = (!v6IsHotspotActive() || v6OnlineClientCount() <= 0) ? 0 : Math.max(0, Math.round(num(r.hotspot_flows, 0)));
      V6.scalpel.hostFlows = Math.max(0, Math.round(num(r.host_flows, 0)));
    }
    v6ApplyScalpelData(r, isScopedReq);
    v6RefreshScalpelDrawerList();
    if (S.page === 'vector') {
      v6RefreshHeroDom();
      v6RefreshNavBadges();
      if (V6.subtab === 'troubleshoot') v6RefreshActiveSubviewDom();
    }
  }).catch(function (e) {
    if (!V6.scalpel.open || reqSeq !== V6.scalpel.reqSeq) return;
    V6.scalpel.loading = false;
    if (isDevScoped && reqMac && S.conn && S.conn[reqMac] && S.conn[reqMac].r) {
      var cr = S.conn[reqMac].r;
      V6.scalpel.drawerFlows = (cr.conns || []).map(function (c, idx) {
        var dstStr = String(c.dst || c.dst_ip || '').trim().replace(/^\[|\]$/g, '');
        var isDstV6 = dstStr.indexOf(':') >= 0;
        var rawSrc = String(c.src || c.src_ip || '').trim().replace(/^\[|\]$/g, '');
        var cleanReqIp = String(reqIp || '').trim().replace(/^\[|\]$/g, '');
        var fbSrcIp = '';
        if (v6ValidIp(rawSrc) && (!dstStr || (rawSrc.indexOf(':') >= 0) === isDstV6)) {
          fbSrcIp = rawSrc;
        } else if (v6ValidIp(cleanReqIp) && (!dstStr || (cleanReqIp.indexOf(':') >= 0) === isDstV6)) {
          fbSrcIp = cleanReqIp;
        }
        var rxBps = c.down_bps != null
          ? Math.max(0, Math.round(num(c.down_bps, 0)))
          : (c.rx_bps != null ? Math.max(0, Math.round(num(c.rx_bps, 0))) : Math.round(num(c.bps, 0) * 0.7));
        var txBps = c.up_bps != null
          ? Math.max(0, Math.round(num(c.up_bps, 0)))
          : (c.tx_bps != null ? Math.max(0, Math.round(num(c.tx_bps, 0))) : Math.round(num(c.bps, 0) * 0.3));
        var totBytes = (c.down_bytes != null || c.up_bytes != null)
          ? Math.max(0, num(c.down_bytes, 0) + num(c.up_bytes, 0))
          : Math.max(0, num(c.bytes, 0));
        return {
          id: 'fb_' + idx,
          scope: 'hotspot',
          uid: -1,
          pkg: '',
          host_app_name: '',
          is_system: false,
          cleartext_risk: '',
          proto: c.proto === 'udp' ? 'udp' : 'tcp',
          protoBadge: c.proto === 'udp' && c.dport === 443 ? 'QUIC' : String(c.proto || 'tcp').toUpperCase(),
          state: String(c.state || 'ESTABLISHED'),
          frozen: false,
          frozen_until: 0,
          mac: reqMac,
          devName: reqDevName || reqMac,
          src_ip: fbSrcIp,
          sport: num(c.sport, 0),
          dst_ip: dstStr,
          dport: num(c.dport, 0),
          dst_host: String(c.name || ''),
          app_name: String(c.app || ''),
          traffic_type: '',
          rx_bps: rxBps,
          tx_bps: txBps,
          bytes: totBytes
        };
      });
      V6.scalpel.drawerTotal = V6.scalpel.drawerFlows.length;
    } else {
      V6.scalpel.err = errText(e);
    }
    v6RefreshScalpelDrawerList();
  });
}

function openScalpelDrawer(mac, ip, devName, initialScope) {
  if (typeof closeSheet === 'function' && $('#sheet') && $('#sheet').classList.contains('show')) closeSheet(0);
  V6.scalpel.scopeMac = v6ValidMac(mac) ? String(mac).toLowerCase() : '';
  V6.scalpel.scopeIp = v6ValidIp(ip) ? String(ip).trim() : '';
  if (!V6.scalpel.scopeIp && V6.scalpel.scopeMac) {
    var d0 = devBy(V6.scalpel.scopeMac);
    if (d0 && v6ValidIp(d0.ip)) V6.scalpel.scopeIp = d0.ip;
    if (!devName && d0) devName = d0.name;
  }
  V6.scalpel.devName = devName || '';
  if (V6.scalpel.scopeMac || V6.scalpel.scopeIp) {
    V6.scalpel.scopeDomain = 'hotspot';
  } else if (initialScope && ['all', 'hotspot', 'host'].indexOf(initialScope) >= 0) {
    V6.scalpel.scopeDomain = initialScope;
  } else {
    V6.scalpel.scopeDomain = 'all';
  }
  V6.scalpel.protoFilter = 'ALL';
  V6.scalpel.q = '';
  V6.scalpel.paused = false;
  V6.scalpel.drawerFlows = null;
  V6.scalpel.drawerTotal = 0;
  V6.scalpel.open = true;

  var dr = document.getElementById('v6-scalpel-drawer');
  var sc = document.getElementById('v6-scalpel-scrim');
  var bd = document.getElementById('v6-scalpel-body');
  if (!dr || !bd) return;
  dr.hidden = false;
  bd.innerHTML = v6ScalpelDrawerBodyHtml();
  v6ResetScalpelScroll();
  if (typeof placeSegs === 'function') placeSegs(bd);
  void dr.offsetWidth;
  if (sc) sc.classList.add('show');
  dr.classList.add('show');
  requestAnimationFrame(function () {
    if (typeof placeSegs === 'function') placeSegs(bd);
  });
  if (typeof window.__hncSyncModalHistory === 'function') {
    V6.scalpel._pushedHist = false;
    window.__hncSyncModalHistory();
  } else {
    try {
      if (window.history && typeof window.history.pushState === 'function' && !(window.history.state && window.history.state.hncScalpel)) {
        window.history.pushState({ hncScalpel: 1 }, '');
        V6.scalpel._pushedHist = true;
      }
    } catch (_) {}
  }

  v6FetchScalpelFlows();
  v6StartScalpelTimer();
}

function v6StopScalpelTimer() {
  if (V6.scalpel.timer) {
    clearInterval(V6.scalpel.timer);
    V6.scalpel.timer = 0;
  }
}

function v6StartScalpelTimer() {
  v6StopScalpelTimer();
  if (!V6.scalpel.open || document.hidden) return;
  V6.scalpel.timer = setInterval(function () {
    if (!V6.scalpel.open || V6.scalpel.paused || document.hidden) return;
    v6FetchScalpelFlows();
  }, 2000);
}

function closeScalpelDrawer(fromPop) {
  if (!V6.scalpel.open) return;
  V6.scalpel.open = false;
  V6.scalpel.reqSeq = (V6.scalpel.reqSeq || 0) + 1;
  V6.scalpel.scopeDomain = 'all';
  V6.scalpel.scopeMac = '';
  V6.scalpel.scopeIp = '';
  V6.scalpel.devName = '';
  V6.scalpel.q = '';
  V6.scalpel.protoFilter = 'ALL';
  V6.scalpel.drawerFlows = null;
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
  if (typeof window.__hncSyncModalHistory === 'function') {
    V6.scalpel._pushedHist = false;
    window.__hncSyncModalHistory(!!fromPop);
  } else if (!fromPop && V6.scalpel._pushedHist) {
    V6.scalpel._pushedHist = false;
    try {
      if (window.history && window.history.state && window.history.state.hncScalpel) {
        window.__hncSkipNextPop = true;
        window.history.back();
        setTimeout(function () { window.__hncSkipNextPop = false; }, 300);
      }
    } catch (_) {
      window.__hncSkipNextPop = false;
    }
  } else {
    V6.scalpel._pushedHist = false;
  }
}

/* ═════════════════════ 写操作 API 封装（严格对齐后端结构体 + 1.5s 乐观锁 + 5s 撤销胶囊） ═════════════════════ */
function v6SaveLeakGuardConfig(partial, triggerEl, okMsg) {
  var capEl = document.getElementById('lgd-cap-inp');
  var cdEl = document.getElementById('lgd-cd-inp');
  var capVal = clamp(Math.round(num(partial && partial.capacity != null ? partial.capacity : (capEl ? capEl.value : V6.lg.capacity), 300)), 10, 2000);
  var cdVal = clamp(Math.round(num(partial && partial.cooldown_sec != null ? partial.cooldown_sec : (cdEl ? cdEl.value : V6.lg.cooldown_sec), 300)), 0, 86400);
  var savedWl = Array.isArray(V6.lg.whitelist) ? V6.lg.whitelist.slice() : [];
  var savedWlCnt = V6.lg.whitelist_count;
  var payload = {
    capacity: capVal,
    cooldown_sec: cdVal,
    notify_enabled: partial && typeof partial.notify_enabled === 'boolean' ? partial.notify_enabled : V6.lg.notify_enabled,
    lockscreen_mask: partial && typeof partial.lockscreen_mask === 'boolean' ? partial.lockscreen_mask : V6.lg.lockscreen_mask
  };
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.lg = Date.now() + 1500;
  V6.lg.capacity = capVal;
  V6.lg.cooldown_sec = cdVal;
  V6.lg.notify_enabled = payload.notify_enabled;
  V6.lg.lockscreen_mask = payload.lockscreen_mask;
  return busyWhile(triggerEl, api.post(V6_API.lgConfig, payload, { timeout: 8000 })).then(function (r) {
    if (r) v6ApplyLeakGuardData(r, true);
    var respHasWl = !!(r && (Array.isArray(r.ignore_rules) || Array.isArray(r.whitelist) || (r.config && (Array.isArray(r.config.ignore_rules) || Array.isArray(r.config.whitelist)))));
    if (!respHasWl && savedWl.length && !V6.lg.whitelist.length) {
      V6.lg.whitelist = savedWl;
      V6.lg.whitelist_count = Math.max(savedWl.length, savedWlCnt);
    }
    v6RefreshActiveSubviewDom();
    toast(okMsg || '隐私安检设置已保存');
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    toast(errText(e), 'err');
    v6LoadLeakGuard(true);
  });
}

function v6ClearLeakGuard(btn) {
  confirmSheet('清空隐私安检记录？', '将清空当前列表中的全部明文传输记录（已手动封禁的追踪域名、IP 规则与忽略白名单会继续保留）。', '清空记录').then(function (ok) {
    if (!ok) return;
    if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
    V6.mutUntil.lg = Date.now() + 1500;
    busyWhile(btn, api.post(V6_API.lgClear, {}, { timeout: 8000 })).then(function () {
      V6.lg.events = [];
      V6.lg.hit_ledger = {};
      V6.lg.total_hits = 0;
      V6.lg.host_hits = 0;
      V6.lg.hotspot_hits = 0;
      V6.lg.hotspot_affected_devices = 0;
      V6.lg.affected_apps = 0;
      V6.lg.affected_devices = 0;
      V6.lg.openIds = {};
      v6MarkLeakGuardSeen();
      v6RefreshHeroDom();
      v6RefreshNavBadges();
      v6RefreshActiveSubviewDom();
      v6RefreshDevicesBannerDom();
      toast('已清空隐私安检历史记录');
    }).catch(function (e) {
      V6.mutUntil.lg = 0;
      toast(errText(e), 'err');
    });
  });
}

function v6OpenLeakWhitelistSheet(ev) {
  if (!ev) return;
  var hostVal = String(ev.dst_host && ev.dst_host !== '—' ? ev.dst_host : ev.dst_ip).trim().toLowerCase();
  if (!hostVal) { toast('该记录缺少可忽略的目标域名或 IP', 'warn'); return; }
  var typeZh = leakTypeZh(ev.leak_type);
  var isHostEv = ev.origin === 'host';
  var evUid = Math.round(num(ev.uid, 0));
  var realPkg = v6CleanHostRealPkg(ev.pkg);
  var hasHostApp = isHostEv && (evUid > 0 || !!realPkg);
  var appLbl = hasHostApp ? v6HostEventAppLabel(ev.app_name, realPkg, evUid) : '';
  var dObj = (!isHostEv && ev.mac) ? devBy(ev.mac) : null;
  var dispDev = (dObj && dObj.name && dObj.name !== dObj.mac) ? dObj.name : (ev.devName || ev.mac || '当前设备');
  var hasMac = !isHostEv && v6ValidMac(ev.mac);
  var defaultScope = hasHostApp ? 'app_host_type' : 'host_type';

  var optRowStyle = 'display:flex;align-items:flex-start;gap:9px;padding:10px 12px;border-radius:12px;background:var(--input);border:1px solid var(--stroke);cursor:pointer;margin-bottom:8px';
  var html = '<h3>加入忽略误报白名单</h3>' +
    '<div class="sub">选择对 <b class="mono">' + escapeHtml(hostVal) + '</b> 的忽略粒度（随时可在「误封恢复与忽略白名单管理」中移除）：</div>' +
    '<div id="v6-wl-scope-box" style="margin:10px 0 4px">' +
      (hasHostApp ? (
        '<label style="' + optRowStyle + '">' +
          '<input type="radio" name="v6_wl_scope" value="app_host_type" checked style="margin-top:3px">' +
          '<span><b style="display:block;font-size:13px;color:var(--text-1)">仅忽略该应用访问此目标的「' + escapeHtml(typeZh) + '」提醒（推荐）</b>' +
          '<small style="display:block;font-size:11.5px;color:var(--text-3);margin-top:2px">仅对本机应用「' + escapeHtml(appLbl) + '」访问此目标的「' + escapeHtml(typeZh) + '」免提醒，手机上其他应用或其他敏感类别（如密码或凭据）仍正常检测</small></span>' +
        '</label>'
      ) : '') +
      '<label style="' + optRowStyle + '">' +
        '<input type="radio" name="v6_wl_scope" value="host_type"' + (!hasHostApp ? ' checked' : '') + ' style="margin-top:3px">' +
        '<span><b style="display:block;font-size:13px;color:var(--text-1)">仅忽略此目标的「' + escapeHtml(typeZh) + '」提醒' + (!hasHostApp ? '（推荐）' : '') + '</b>' +
        '<small style="display:block;font-size:11.5px;color:var(--text-3);margin-top:2px">若该目标后续明文传输其他敏感类别（如密码或凭据）仍会正常报警</small></span>' +
      '</label>' +
      '<label style="' + optRowStyle + '">' +
        '<input type="radio" name="v6_wl_scope" value="host" style="margin-top:3px">' +
        '<span><b style="display:block;font-size:13px;color:var(--text-1)">忽略此目标的全部明文提醒</b>' +
        '<small style="display:block;font-size:11.5px;color:var(--text-3);margin-top:2px">将该目标视为公开无害接口，不再对其产生任何明文安检告警</small></span>' +
      '</label>' +
      (hasMac ? (
        '<label style="' + optRowStyle + '">' +
          '<input type="radio" name="v6_wl_scope" value="device_host_type" style="margin-top:3px">' +
          '<span><b style="display:block;font-size:13px;color:var(--text-1)">仅忽略该设备访问此目标的此类提醒</b>' +
          '<small style="display:block;font-size:11.5px;color:var(--text-3);margin-top:2px">仅对设备「' + escapeHtml(dispDev) + '」访问此目标的「' + escapeHtml(typeZh) + '」免提醒，其他设备或其他敏感类别仍正常检测</small></span>' +
        '</label>'
      ) : '') +
    '</div>' +
    '<div class="btns">' +
      '<button type="button" class="btn sec press" data-close>取消</button>' +
      '<button type="button" class="btn pri press" id="v6-wl-submit">确认忽略</button>' +
    '</div>';

  if (typeof sheet !== 'function') return;
  sheet(html);
  var subBtn = document.getElementById('v6-wl-submit');
  if (!subBtn) return;
  subBtn.onclick = function () {
    var checked = document.querySelector('input[name="v6_wl_scope"]:checked');
    var scopeVal = checked ? checked.value : defaultScope;
    if (typeof closeSheet === 'function') closeSheet(0);
    v6AddLeakWhitelist(ev, hostVal, scopeVal, null);
  };
}

function v6AddLeakWhitelist(ev, hostVal, scopeVal, triggerEl) {
  if (scopeVal === 'device_host') scopeVal = 'device_host_type';
  if (scopeVal === 'app_host') scopeVal = 'app_host_type';
  var reqBody = {
    action: 'add',
    scope: scopeVal,
    dst_host: hostVal
  };
  if ((scopeVal === 'host_type' || scopeVal === 'device_host_type' || scopeVal === 'app_host_type') && ev && ev.leak_type) {
    reqBody.leak_type = ev.leak_type;
  }
  if (scopeVal === 'device_host_type' && ev && v6ValidMac(ev.mac)) {
    reqBody.mac = ev.mac;
  }
  if (scopeVal === 'app_host_type' && ev) {
    var evUid = Math.round(num(ev.uid, 0));
    var realPkg = v6CleanHostRealPkg(ev.pkg).toLowerCase();
    if (evUid > 0) reqBody.uid = evUid;
    if (realPkg) reqBody.pkg = realPkg;
  }

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.lg = Date.now() + 1500;

  var optItem = v6NormWhitelistItem({
    scope: scopeVal,
    dst_host: hostVal,
    leak_type: reqBody.leak_type || '',
    mac: reqBody.mac || '',
    uid: reqBody.uid || 0,
    pkg: reqBody.pkg || '',
    app_name: (ev && ev.app_name) || '',
    device_name: ev && ev.devName || ''
  }, V6.lg.whitelist.length);

  return busyWhile(triggerEl, api.post(V6_API.lgWhitelist, reqBody, { timeout: 8000 })).then(function (r) {
    var gotWl = !!(r && (Array.isArray(r.ignore_rules) || Array.isArray(r.whitelist) || (r.config && (Array.isArray(r.config.ignore_rules) || Array.isArray(r.config.whitelist)))));
    if (!gotWl && optItem) {
      V6.lg.whitelist.push(optItem);
      V6.lg.whitelist_count = V6.lg.whitelist.length;
    }
    if (r) v6ApplyLeakGuardData(r, true);
    V6.lg.events = V6.lg.events.filter(function (x) { return !v6IsEventWhitelisted(x, V6.lg.whitelist); });
    v6RecalcLeakWatermark();
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    v6LoadLeakGuard(true);
    toast('已加入忽略误报白名单：' + hostVal);
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    toast(errText(e), 'err');
    v6LoadLeakGuard(true);
  });
}

function v6RemoveLeakWhitelist(widOrIdx, triggerEl) {
  var list = Array.isArray(V6.lg.whitelist) ? V6.lg.whitelist : [];
  var wIdx = -1;
  if (typeof widOrIdx === 'number' && widOrIdx >= 0 && widOrIdx < list.length) {
    wIdx = widOrIdx;
  } else {
    var targetWid = String(widOrIdx == null ? '' : widOrIdx);
    for (var i = 0; i < list.length; i++) {
      var w = list[i];
      if (!w) continue;
      var ns = w.scope === 'device_host' ? 'device_host_type' : (w.scope === 'app_host' ? 'app_host_type' : (w.scope || 'host'));
      var wk = w.comboKey || (ns + '|' + (w.dst_host || '') + '|' + (w.leak_type || '') + '|' + (w.mac || '') + '|' + (w.uid > 0 ? w.uid : '') + '|' + (w.pkg || ''));
      if (w.id === targetWid || wk === targetWid) {
        wIdx = i;
        break;
      }
    }
  }
  var item = wIdx >= 0 ? list[wIdx] : null;
  if (!item) return;
  var normScope = item.scope === 'device_host' ? 'device_host_type' : (item.scope === 'app_host' ? 'app_host_type' : (item.scope || 'host'));
  var reqBody = {
    action: 'remove',
    scope: normScope,
    dst_host: item.dst_host || ''
  };
  if (item.hasServerId && item.id) reqBody.id = item.id;
  if (item.leak_type) reqBody.leak_type = item.leak_type;
  if (item.mac) reqBody.mac = item.mac;
  if (item.uid > 0) reqBody.uid = item.uid;
  if (item.pkg) reqBody.pkg = item.pkg;

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.lg = Date.now() + 1500;
  V6.lg.whitelist.splice(wIdx, 1);
  V6.lg.whitelist_count = V6.lg.whitelist.length;
  v6RefreshActiveSubviewDom();

  return busyWhile(triggerEl, api.post(V6_API.lgWhitelist, reqBody, { timeout: 8000 })).then(function (r) {
    if (r) v6ApplyLeakGuardData(r, true);
    v6RecalcLeakWatermark();
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    v6LoadLeakGuard(true);
    toast('已移除白名单规则：' + (item.dst_host || '指定规则'));
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    toast(errText(e), 'err');
    v6LoadLeakGuard(true);
  });
}

function v6UndoLeakBlock(undoId, fallbackHost, targetScope, triggerEl, fallbackAppUid) {
  var reqBody = {};
  if (undoId) reqBody.id = undoId;
  if (targetScope) reqBody.target_scope = targetScope;
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.lg = Date.now() + 1500;

  return busyWhile(triggerEl, api.post(V6_API.lgUndoBlock, reqBody, { timeout: 9000 })).then(function (r) {
    var undoneObj = (r && r.undone && typeof r.undone === 'object') ? r.undone : r;
    var undoneId = String((undoneObj && undoneObj.id) || undoId || '').trim();
    var restoredHost = String((undoneObj && (undoneObj.dst_host || undoneObj.host || undoneObj.domain)) || fallbackHost || '').trim();
    var restoredIp = String((undoneObj && (undoneObj.also_ip || undoneObj.dst_ip)) || '').trim();
    var effScope = String((undoneObj && undoneObj.target_scope) || targetScope || '').toLowerCase();
    var effUid = Math.round(num(undoneObj && undoneObj.uid != null ? undoneObj.uid : fallbackAppUid, 0));
    if (restoredHost) {
      var rk = restoredHost.toLowerCase();
      var rkPureIp = v6ExtractPureIp(rk).toLowerCase();
      if (effScope !== 'host') delete V6.lg.blocked_set[rk];
      if (effScope === 'host' && effUid > 0) {
        delete V6.lg.blocked_set['uid:' + effUid + '|' + rk];
        if (rkPureIp) delete V6.lg.blocked_set['uid:' + effUid + '|' + rkPureIp];
        var existRule = V6.host.firewall.uid_map[String(effUid)];
        if (existRule && Array.isArray(existRule.block_targets)) {
          existRule.block_targets = existRule.block_targets.filter(function (t) {
            var tLow = String(t || '').toLowerCase();
            return tLow !== rk && (!rkPureIp || v6ExtractPureIp(tLow).toLowerCase() !== rkPureIp);
          });
          if (v6NormFwMode(existRule.mode) === 'allow' && existRule.block_targets.length === 0) {
            delete V6.host.firewall.uid_map[String(effUid)];
            V6.host.firewall.uid_rules = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== effUid; });
            V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
          }
        }
      } else if (effScope === 'host' || effScope === 'both') {
        delete V6.host.firewall.blocked_set[rk];
        V6.host.firewall.blocked_domains = V6.host.firewall.blocked_domains.filter(function (x) { return x !== rk; });
        V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
      }
      V6.lg.events.forEach(function (x) {
        if (String(x.dst_host || '').toLowerCase() === rk || (restoredIp && x.dst_ip === restoredIp)) {
          if (x.origin === 'host') {
            var xSt = v6ClassifyHostLeakBlockState(x);
            x.is_blocked = !!(xSt.targetBlocked || xSt.appMode);
          } else if (!effScope || effScope === 'both' || (x.origin || 'hotspot') === effScope) {
            x.is_blocked = false;
          }
        }
      });
    }
    if (Array.isArray(V6.lg.undo_stack) && V6.lg.undo_stack.length) {
      var rmIdx = -1;
      for (var i = 0; i < V6.lg.undo_stack.length; i++) {
        var u = V6.lg.undo_stack[i];
        if ((undoneId && u.id === undoneId) || (!undoneId && restoredHost && String(u.dst_host || '').toLowerCase() === restoredHost.toLowerCase())) {
          rmIdx = i;
          break;
        }
      }
      if (rmIdx >= 0) V6.lg.undo_stack.splice(rmIdx, 1);
      else if (!undoId) V6.lg.undo_stack.shift();
    }
    if (r && r.remaining_undo != null) {
      V6.lg.undo_count = Math.max(0, Math.round(num(r.remaining_undo, V6.lg.undo_stack.length)));
    } else {
      V6.lg.undo_count = V6.lg.undo_stack.length;
    }
    if (r) v6ApplyLeakGuardData(r, true);
    if (effScope === 'host' || effScope === 'both') v6LoadHostFirewall(true);
    v6RefreshHeroDom();
    v6RefreshNavBadges();
    v6RefreshActiveSubviewDom();
    v6LoadLeakGuard(true);
    toast('已撤销封禁' + (restoredHost ? ('：' + restoredHost) : ''));
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    toast(errText(e), 'err');
    v6LoadLeakGuard(true);
  });
}

function v6BlockLeakDomain(evId, btn, opts) {
  opts = opts || {};
  var ev = V6.lg.events.filter(function (x) { return x.id === evId; })[0] || opts.evSnapshot;
  if (!ev) return;
  var evUid = Math.round(num(ev.uid, 0));
  var cleanPkg = v6CleanHostRealPkg(ev.pkg);
  if (!opts.targetAction && ev.is_blocked && ev.origin === 'host') {
    var hbs0 = v6ClassifyHostLeakBlockState(ev);
    if (hbs0.appOnlyBlocked) {
      v6OpenHostAppSheet(evUid, cleanPkg, v6HostEventAppLabel(ev.app_name, cleanPkg, evUid), false);
      return Promise.resolve();
    }
  }
  var wantBlock = opts.targetAction ? (opts.targetAction === 'block') : !ev.is_blocked;
  var act = wantBlock ? 'block' : 'unblock';
  var primaryHost = String(ev.dst_host && ev.dst_host !== '—' ? ev.dst_host : ev.dst_ip).trim();
  if (!primaryHost) { toast('该记录缺少可封禁的目标域名或公网 IP', 'warn'); return; }
  var targetScope = String(opts.targetScope || (ev.origin === 'host' ? 'host' : 'hotspot')).toLowerCase();
  var pureIp = v6ExtractPureIp(primaryHost);
  var appId = evUid > 0 ? (evUid % 100000) : -1;
  var isNormalHostApp = targetScope === 'host' && evUid > 0 && appId >= 10000 && appId < 90000 && !v6IsHostAppProtected(evUid, cleanPkg);

  if (pureIp) {
    if (wantBlock && (v6IsFakeOrPrivateIp(pureIp) || (targetScope === 'host' && !isNormalHostApp))) {
      toast('系统/代理内网流请用断开或应用防火墙', 'warn');
      return Promise.resolve();
    }
    if (targetScope === 'host') {
      if (!isNormalHostApp) {
        toast('系统/代理内网流请用断开或应用防火墙', 'warn');
        return Promise.resolve();
      }
      var hostIpPayload = {
        action: act,
        target_scope: 'host',
        uid: evUid,
        dst_host: pureIp,
        mac: '',
        pkg: cleanPkg,
        app_name: ev.app_name || '',
        force: !!opts.force
      };
      if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
      V6.mutUntil.lg = Date.now() + 1500;
      var evIpSnap = Object.assign({}, ev);

      return busyWhile(btn, api.post(V6_API.lgBlockDomain, hostIpPayload, { timeout: 9000 })).then(function (r) {
        var dkIp = primaryHost.toLowerCase();
        var pIpLow = pureIp.toLowerCase();
        if (wantBlock) {
          V6.lg.blocked_set['uid:' + evUid + '|' + pIpLow] = 1;
          V6.lg.blocked_set['uid:' + evUid + '|' + dkIp] = 1;
          var curR = V6.host.firewall.uid_map[String(evUid)];
          if (!curR) {
            curR = {
              uid: evUid,
              sdk_sandbox_uid: (appId >= 10000 && appId <= 19999) ? (evUid + 10000) : 0,
              pkg: cleanPkg,
              app_name: ev.app_name || '',
              mode: 'allow',
              block_targets: [pureIp],
              updated_at: Math.round(Date.now() / 1000)
            };
            V6.host.firewall.uid_map[String(evUid)] = curR;
            V6.host.firewall.uid_rules.unshift(curR);
            V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
          } else {
            if (!Array.isArray(curR.block_targets)) curR.block_targets = [];
            if (curR.block_targets.indexOf(pureIp) < 0) curR.block_targets.push(pureIp);
          }
        } else {
          delete V6.lg.blocked_set['uid:' + evUid + '|' + pIpLow];
          delete V6.lg.blocked_set['uid:' + evUid + '|' + dkIp];
          var curR2 = V6.host.firewall.uid_map[String(evUid)];
          if (curR2 && Array.isArray(curR2.block_targets)) {
            curR2.block_targets = curR2.block_targets.filter(function (t) {
              var tl = String(t || '').toLowerCase();
              return tl !== pIpLow && v6ExtractPureIp(tl).toLowerCase() !== pIpLow;
            });
            if (v6NormFwMode(curR2.mode) === 'allow' && curR2.block_targets.length === 0) {
              delete V6.host.firewall.uid_map[String(evUid)];
              V6.host.firewall.uid_rules = V6.host.firewall.uid_rules.filter(function (x) { return x.uid !== evUid; });
              V6.host.firewall.uid_rule_count = V6.host.firewall.uid_rules.length;
            }
          }
        }
        var stillAppBlockedIp = !wantBlock && !!v6HostAppBlockingModeForEvent(evUid, ev.dst_port, ev.proto);
        ev.is_blocked = wantBlock || stillAppBlockedIp;
        V6.lg.events.forEach(function (x) {
          if (x.origin === 'host' && Math.round(num(x.uid, 0)) === evUid) {
            var xHost = String(x.dst_host || '').toLowerCase();
            if (xHost === dkIp || v6ExtractPureIp(xHost).toLowerCase() === pIpLow) {
              var xSt = v6ClassifyHostLeakBlockState(x);
              x.is_blocked = !!(xSt.targetBlocked || xSt.appMode);
            }
          }
        });
        if (r) v6ApplyLeakGuardData(r, true);
        v6LoadHostFirewall(true);
        v6RefreshNavBadges();
        v6RefreshActiveSubviewDom();
        v6LoadLeakGuard(true);
        var appLbl = v6HostEventAppLabel(ev.app_name, cleanPkg, evUid);
        var ipMsg = wantBlock
          ? ('已封禁「' + appLbl + '」访问目标 IP：' + pureIp)
          : ('已解除「' + appLbl + '」目标 IP 封禁：' + pureIp + (stillAppBlockedIp ? '（该应用仍受应用防火墙限制）' : ''));
        if (!opts.fromUndo && typeof undoToast === 'function') {
          undoToast(ipMsg, function () {
            return v6BlockLeakDomain(evId, null, {
              fromUndo: true,
              targetAction: wantBlock ? 'unblock' : 'block',
              targetScope: 'host',
              force: true,
              evSnapshot: evIpSnap
            });
          });
        } else {
          toast(ipMsg);
        }
      }).catch(function (e) {
        V6.mutUntil.lg = 0;
        if (e && e.status === 409 && e.body) {
          var gLvlIp = String(e.body.guard_level || (e.body.infra_guard && e.body.infra_guard.level) || '').toLowerCase();
          var gRsnIp = String(e.body.detail || e.body.reason_zh || e.body.message || e.body.error || '涉及公共网络基础设施');
          if (gLvlIp === 'warn_confirm') {
            confirmSheet(
              '确认强制封禁共享节点 IP？',
              '<b>' + escapeHtml(pureIp) + '</b> 属于共享云底座或 CDN 节点（' + escapeHtml(gRsnIp) + '），仅对该应用封禁仍可能影响其正常加载内容，确定强制封禁吗？',
              '强制封禁'
            ).then(function (ok) {
              if (ok) {
                v6BlockLeakDomain(evId, btn, {
                  force: true,
                  fromUndo: opts.fromUndo,
                  targetAction: 'block',
                  targetScope: 'host',
                  evSnapshot: evIpSnap
                });
              }
            });
            return;
          }
          if (gLvlIp === 'hard_block') {
            toast('核心公共服务 IP 受保护：' + gRsnIp, 'warn');
            return;
          }
        }
        toast(errText(e), 'err');
      });
    }
  }

  var macArg = (targetScope !== 'host' && v6ValidMac(ev.mac)) ? ev.mac : '';
  var alsoIp = (targetScope !== 'host' && !pureIp && !opts.skipAlsoIp && v6ValidIp(ev.dst_ip) && ev.dst_ip.toLowerCase() !== primaryHost.toLowerCase()) ? ev.dst_ip : '';
  var reqPayload = {
    action: act,
    target_scope: targetScope,
    uid: targetScope === 'hotspot' ? 0 : (evUid > 0 ? evUid : 0),
    dst_host: pureIp || primaryHost,
    mac: macArg,
    pkg: targetScope === 'hotspot' ? '' : cleanPkg,
    app_name: targetScope === 'hotspot' ? '' : (ev.app_name || ''),
    force: !!opts.force
  };
  if (targetScope !== 'host' && !macArg) reqPayload.scope = 'global';
  if (alsoIp) reqPayload.also_ip = alsoIp;

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.lg = Date.now() + 1500;
  var evSnap = Object.assign({}, ev);

  return busyWhile(btn, api.post(V6_API.lgBlockDomain, reqPayload, { timeout: 9000 })).then(function (r) {
    var skippedSharedIp = !!(wantBlock && r && r.skipped_shared_ip === true);
    var effAlsoIp = skippedSharedIp ? '' : alsoIp;
    var dk = primaryHost.toLowerCase();
    if (wantBlock) {
      if (targetScope !== 'host') V6.lg.blocked_set[dk] = 1;
      if (targetScope === 'host' || targetScope === 'both') {
        if (!V6.host.firewall.blocked_set[dk]) {
          V6.host.firewall.blocked_set[dk] = 1;
          V6.host.firewall.blocked_domains.unshift(dk);
          V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
        }
      }
    } else {
      if (targetScope !== 'host') delete V6.lg.blocked_set[dk];
      if (targetScope === 'host' || targetScope === 'both') {
        delete V6.host.firewall.blocked_set[dk];
        V6.host.firewall.blocked_domains = V6.host.firewall.blocked_domains.filter(function (x) { return x !== dk; });
        V6.host.firewall.blocked_domain_count = V6.host.firewall.blocked_domains.length;
      }
    }
    var stillAppBlockedDom = (!wantBlock && ev.origin === 'host') ? !!v6HostAppBlockingModeForEvent(evUid, ev.dst_port, ev.proto) : false;
    ev.is_blocked = wantBlock || stillAppBlockedDom;
    V6.lg.events.forEach(function (x) {
      if (String(x.dst_host || '').toLowerCase() === dk || (effAlsoIp && x.dst_ip === effAlsoIp)) {
        if (targetScope === 'both' || (x.origin || 'hotspot') === targetScope) {
          if (x.origin === 'host') {
            var xSt = v6ClassifyHostLeakBlockState(x);
            x.is_blocked = !!(xSt.targetBlocked || xSt.appMode);
          } else {
            x.is_blocked = wantBlock;
          }
        }
      }
    });
    if (r) v6ApplyLeakGuardData(r, true);
    if (targetScope === 'host' || targetScope === 'both') v6LoadHostFirewall(true);
    v6RefreshNavBadges();
    v6RefreshActiveSubviewDom();
    v6LoadLeakGuard(true);
    var scopeZh = pureIp ? '热点目标 IP' : (targetScope === 'host' ? '本机域名' : (targetScope === 'both' ? '双端域名' : '热点域名'));
    var msgTxt;
    if (wantBlock && skippedSharedIp) {
      msgTxt = '已封禁' + scopeZh + '：' + primaryHost + '（共享 CDN IP 已自动跳过防误伤）';
    } else if (wantBlock) {
      msgTxt = '已封禁' + scopeZh + (effAlsoIp ? '与 IP' : '') + '：' + primaryHost;
    } else {
      msgTxt = '已解除封禁：' + primaryHost + (stillAppBlockedDom ? '（该应用仍受应用防火墙限制）' : '');
    }
    if (!opts.fromUndo && typeof undoToast === 'function') {
      undoToast(msgTxt, function () {
        return v6BlockLeakDomain(evId, null, {
          fromUndo: true,
          targetAction: wantBlock ? 'unblock' : 'block',
          targetScope: targetScope,
          force: true,
          skipAlsoIp: skippedSharedIp,
          evSnapshot: evSnap
        });
      });
    } else {
      toast(msgTxt);
    }
  }).catch(function (e) {
    V6.mutUntil.lg = 0;
    if (e && e.status === 409 && e.body) {
      var gLevel = String(e.body.guard_level || (e.body.infra_guard && e.body.infra_guard.level) || '').toLowerCase();
      var gReason = String(e.body.detail || e.body.reason_zh || e.body.message || e.body.error || '涉及公共网络基础设施');
      if (gLevel === 'warn_confirm') {
        confirmSheet(
          '确认强制封禁共享底座域名？',
          '<b>' + escapeHtml(primaryHost) + '</b> 属于多款应用共用的公共 CDN 或云底座（' + escapeHtml(gReason) + '）。<br><br>直接封禁可能导致使用同一节点的其他正常应用无法加载资源，确定仍要强制封禁吗？',
          '强制封禁'
        ).then(function (ok) {
          if (ok) {
            v6BlockLeakDomain(evId, btn, {
              force: true,
              fromUndo: opts.fromUndo,
              targetAction: 'block',
              targetScope: targetScope,
              evSnapshot: evSnap
            });
          }
        });
        return;
      }
      if (gLevel === 'hard_block') {
        confirmSheet(
          '核心公共域名受保护',
          '<b>' + escapeHtml(primaryHost) + '</b> 属于系统联网检测或核心基础公共服务（' + escapeHtml(gReason) + '），一旦封禁会导致设备误判无网络而断流，系统已阻止封禁。<br><br>如果确认该明文请求为正常公开参数，可将其转入忽略误报白名单。',
          '转入忽略误报',
          { safe: true }
        ).then(function (ok) {
          if (ok) v6OpenLeakWhitelistSheet(evSnap);
        });
        return;
      }
    }
    toast(errText(e), 'err');
  });
}

function v6BuildScalpelCutPayload(flowObj, modeStr) {
  var p = String(flowObj.proto || 'tcp').toLowerCase();
  var normProto = (p === 'udp' || p === 'quic') ? 'udp' : 'tcp';
  var fScope = (flowObj.scope === 'host' || flowObj.origin === 'host') ? 'host' : 'hotspot';
  var out = {
    mode: modeStr === 'cut_freeze_15m' ? 'cut_freeze_15m' : 'cut_once',
    scope: fScope,
    proto: normProto,
    src_ip: String(flowObj.src_ip || '').trim().replace(/^\[|\]$/g, ''),
    sport: clamp(Math.round(num(flowObj.sport != null ? flowObj.sport : flowObj.src_port, 0)), 1, 65535),
    dst_ip: String(flowObj.dst_ip || '').trim().replace(/^\[|\]$/g, ''),
    dport: clamp(Math.round(num(flowObj.dport != null ? flowObj.dport : flowObj.dst_port, 80)), 1, 65535)
  };
  var rawUid = flowObj.uid != null ? Math.round(num(flowObj.uid, -1)) : -1;
  if (fScope === 'host' && (rawUid > 0 || (rawUid === 0 && !flowObj.leak_type))) {
    out.uid = rawUid;
  } else if (v6ValidMac(flowObj.mac)) {
    out.mac = String(flowObj.mac).toLowerCase();
  }
  return out;
}

function v6CutFlow(flowObj, freeze15m, btn) {
  if (!flowObj) return;
  if (!v6ValidIp(flowObj.src_ip) || !v6ValidIp(flowObj.dst_ip) || !(num(flowObj.sport, flowObj.src_port) >= 1)) {
    toast('连接地址信息不完整，请刷新列表后重试', 'warn');
    return;
  }
  var mode = freeze15m ? 'cut_freeze_15m' : 'cut_once';
  var payload = v6BuildScalpelCutPayload(flowObj, mode);
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  busyWhile(btn, api.post(V6_API.scalpelCut, payload, { timeout: 8000 })).then(function () {
    toast(freeze15m
      ? ('已断开并冻结 15 分钟：' + (flowObj.dst_host || payload.dst_ip))
      : ('已秒断连接：' + v6FmtHostPort(flowObj.dst_host || payload.dst_ip, payload.dport)));
    if (V6.scalpel.open) v6FetchScalpelFlows();
    if (V6.host.appSheet.open) v6FetchHostAppFlows();
    if (S.page === 'vector') v6LoadCockpitAll();
  }).catch(function (e) { toast(errText(e), 'err'); });
}

function v6CutLeakEventConn(ev, btn) {
  if (!ev) return;
  var fastSport = Math.round(num(ev.src_port != null ? ev.src_port : ev.sport, 0));
  if (v6ValidIp(ev.src_ip) && v6ValidIp(ev.dst_ip) && fastSport >= 1 && fastSport <= 65535) {
    v6CutFlow(ev, false, btn);
    return;
  }
  var isHostEv = ev.origin === 'host';
  var evUid = Math.round(num(ev.uid, 0));
  var qParams = { scope: isHostEv ? 'host' : 'hotspot', limit: 250 };
  if (isHostEv && evUid > 0) qParams.uid = evUid;
  if (!isHostEv && v6ValidMac(ev.mac)) qParams.mac = ev.mac;
  if (!isHostEv && v6ValidIp(ev.src_ip)) qParams.ip = ev.src_ip;

  busyWhile(btn, api.get(V6_API.scalpelFlows, qParams, { timeout: 7000 }).then(function (r) {
    var flows = Array.isArray(r && r.flows) ? r.flows : [];
    var hostLow = String(ev.dst_host || '').toLowerCase();
    var matched = flows.filter(function (f) {
      var sp = Math.round(num(f.sport, 0)), dp = Math.round(num(f.dport, 0));
      if (!v6ValidIp(f.src_ip) || !v6ValidIp(f.dst_ip) || sp < 1 || dp < 1) return false;
      if (fastSport >= 1 && sp === fastSport && (!ev.src_ip || f.src_ip === ev.src_ip)) return true;
      if (ev.dst_ip && f.dst_ip === ev.dst_ip) return true;
      var dom = String(f.domain || '').toLowerCase();
      if (hostLow && hostLow !== '—' && (dom === hostLow || dom.slice(-(hostLow.length + 1)) === '.' + hostLow || f.dst_ip === hostLow)) return true;
      return ev.dst_port && dp === ev.dst_port && (!ev.dst_ip && (!hostLow || hostLow === '—'));
    });
    if (!matched.length) return { cutN: 0, skipProt: 0, failN: 0, lastErr: null };
    var chain = Promise.resolve(), cutN = 0, skipProt = 0, failN = 0, lastErr = null;
    matched.slice(0, 6).forEach(function (mf) {
      chain = chain.then(function () {
        return api.post(V6_API.scalpelCut, v6BuildScalpelCutPayload(mf, 'cut_once'), { timeout: 6000 })
          .then(function () { cutN++; })
          .catch(function (err) {
            if (err && err.status === 401) throw err;
            if (err && err.status === 409) skipProt++;
            else { failN++; lastErr = err; }
          });
      });
    });
    return chain.then(function () { return { cutN: cutN, skipProt: skipProt, failN: failN, lastErr: lastErr }; });
  })).then(function (res) {
    var appId = evUid > 0 ? (evUid % 100000) : -1;
    if (res && res.cutN > 0) {
      toast('已断开 ' + res.cutN + ' 条相关连接' + (res.skipProt > 0 ? ('（跳过 ' + res.skipProt + ' 条受保护连接）') : '') + '：' + (ev.dst_host || ev.dst_ip));
    } else if (res && res.skipProt > 0) {
      toast('匹配的 ' + res.skipProt + ' 条连接受系统保护，已跳过断开', 'warn');
    } else if (res && res.failN > 0 && res.lastErr) {
      toast(errText(res.lastErr), 'err');
    } else if (isHostEv && evUid <= 0) {
      toast('该本机未知连接已结束且未归属具体应用，暂无可断开的活跃连接', 'warn');
    } else if (isHostEv && appId >= 10000 && appId < 90000) {
      v6OpenHostAppSheet(evUid, ev.pkg, ev.app_name || ev.devName, false);
      toast('该短连接已自然结束，已打开此应用的联网管控面板', 'warn');
    } else {
      openScalpelDrawer(isHostEv ? '' : ev.mac, isHostEv ? '' : ev.src_ip, isHostEv ? '' : ev.devName, isHostEv ? 'host' : 'hotspot');
      toast('该短连接已自然结束，已打开实时活跃连接列表', 'warn');
    }
  }).catch(function (e) { toast(errText(e), 'err'); });
}

function v6PostExpress(payload, el, msg, opts) {
  var isFromUndo = !!(opts === true || (opts && opts.fromUndo));
  var macOp = (opts && typeof opts === 'object' && opts.macOp) ? opts.macOp : null;
  var prevMacs = (V6._committed.express.forced_macs || []).slice();
  if (!macOp && payload && Array.isArray(payload.forced_macs)) {
    var nextSet = payload.forced_macs.map(function (m) { return String(m || '').toLowerCase(); });
    var addedList = nextSet.filter(function (m) { return prevMacs.indexOf(m) < 0; });
    var removedList = prevMacs.filter(function (m) { return nextSet.indexOf(m) < 0; });
    if (addedList.length === 1 && removedList.length === 0) {
      macOp = { mac: addedList[0], added: true, autoTurnedOn: !!(typeof payload.enabled === 'boolean' && payload.enabled && !V6._committed.express.enabled) };
    } else if (removedList.length === 1 && addedList.length === 0) {
      macOp = { mac: removedList[0], added: false, autoTurnedOn: false };
    }
  }
  var undoScalar = {};
  var hasScalar = false;
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'enabled') && payload.enabled !== undefined && !(macOp && macOp.autoTurnedOn)) {
    undoScalar.enabled = V6._committed.express.enabled;
    hasScalar = true;
  }
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'auto_detect') && payload.auto_detect !== undefined) {
    undoScalar.auto_detect = V6._committed.express.auto_detect;
    hasScalar = true;
  }
  var fullMacsFallback = (!macOp && payload && Array.isArray(payload.forced_macs)) ? prevMacs.slice() : null;
  var canUndo = !!(macOp || fullMacsFallback || hasScalar);

  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.express = Date.now() + 1500;
  return busyWhile(el, api.post(V6_API.express, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyExpressData(r || payload, true);
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (!isFromUndo && msg && canUndo && typeof undoToast === 'function') {
      undoToast(msg, function () {
        var revPayload = {};
        if (macOp && macOp.mac) {
          var curMacs = (V6.express.forced_macs || []).slice();
          var idx = curMacs.indexOf(macOp.mac);
          if (macOp.added) {
            if (idx >= 0) curMacs.splice(idx, 1);
          } else if (idx < 0) {
            curMacs.push(macOp.mac);
          }
          revPayload.forced_macs = curMacs;
          V6.express.forced_macs = curMacs.slice();
          if (macOp.autoTurnedOn && curMacs.length === 0) {
            revPayload.enabled = false;
            V6.express.enabled = false;
          }
        } else if (fullMacsFallback) {
          revPayload.forced_macs = fullMacsFallback.slice();
          V6.express.forced_macs = fullMacsFallback.slice();
        }
        if (hasScalar) {
          if (Object.prototype.hasOwnProperty.call(undoScalar, 'enabled')) {
            revPayload.enabled = undoScalar.enabled;
            V6.express.enabled = undoScalar.enabled;
          }
          if (Object.prototype.hasOwnProperty.call(undoScalar, 'auto_detect')) {
            revPayload.auto_detect = undoScalar.auto_detect;
            V6.express.auto_detect = undoScalar.auto_detect;
          }
        }
        v6RefreshHeroDom();
        return v6PostExpress(revPayload, null, '已撤销优先护航变更', true);
      });
    } else if (msg) {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.express = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

function v6PostLeash(payload, el, msg, fromUndo) {
  var act = (payload && payload.action) || 'config';
  var undoPayload = null;
  if (act === 'config') {
    var cfgUndo = { action: 'config' };
    var hasCfgKey = false;
    ['enabled', 'grace_mb', 'leash_kbps'].forEach(function (k) {
      if (payload && Object.prototype.hasOwnProperty.call(payload, k) && payload[k] !== undefined) {
        cfgUndo[k] = V6._committed.leash[k];
        hasCfgKey = true;
      }
    });
    if (hasCfgKey) undoPayload = cfgUndo;
  } else if (act === 'pause_update' || act === 'resume_update') {
    undoPayload = {
      action: act === 'pause_update' ? 'resume_update' : 'pause_update',
      session_key: payload.session_key || '',
      mac: payload.mac || '',
      dst_host: payload.dst_host || ''
    };
  }
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.leash = Date.now() + 1500;
  return busyWhile(el, api.post(V6_API.updateLeash, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyLeashData(r || payload, true);
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (S.page === 'devices') renderDevList(false);
    if (!fromUndo && msg && undoPayload && typeof undoToast === 'function') {
      undoToast(msg, function () {
        if (undoPayload.action === 'config') {
          ['enabled', 'grace_mb', 'leash_kbps'].forEach(function (k) {
            if (Object.prototype.hasOwnProperty.call(undoPayload, k)) {
              V6.leash[k] = undoPayload[k];
            }
          });
          v6RefreshHeroDom();
        }
        return v6PostLeash(undoPayload, null, '已撤销后台更新限幅变更', true);
      });
    } else if (msg) {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.leash = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

function v6PostThermo(payload, el, msg, fromUndo) {
  var undoPayload = {};
  var hasKey = false;
  ['enabled', 'stage2_shaper_enabled', 'stage1_temp_c', 'stage2_temp_c', 'low_bat_pct'].forEach(function (k) {
    if (payload && Object.prototype.hasOwnProperty.call(payload, k) && payload[k] !== undefined) {
      undoPayload[k] = V6._committed.thermo[k];
      hasKey = true;
    }
  });
  if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
  V6.mutUntil.thermo = Date.now() + 1500;
  return busyWhile(el, api.post(V6_API.thermo, payload, { timeout: 8000 })).then(function (r) {
    v6ApplyThermoData(r || payload, true);
    v6PaintHeaderBadges();
    v6RefreshHeroDom();
    v6RefreshActiveSubviewDom();
    v6RefreshDevicesBannerDom();
    if (!fromUndo && msg && hasKey && typeof undoToast === 'function') {
      undoToast(msg, function () {
        ['enabled', 'stage2_shaper_enabled', 'stage1_temp_c', 'stage2_temp_c', 'low_bat_pct'].forEach(function (k) {
          if (Object.prototype.hasOwnProperty.call(undoPayload, k)) {
            V6.thermo[k] = undoPayload[k];
          }
        });
        v6RefreshHeroDom();
        return v6PostThermo(undoPayload, null, '已撤销温控保护变更', true);
      });
    } else if (msg) {
      toast(msg);
    }
  }).catch(function (e) {
    V6.mutUntil.thermo = 0;
    toast(errText(e), 'err');
    v6LoadCockpitAll();
  });
}

function v6CleanBackupVer(v) {
  var s = String(v == null ? '' : v).trim();
  if (!s || /^(dev|unknown|none|-|null|undefined)$/i.test(s)) return '';
  return s.replace(/[^a-zA-Z0-9._+-]/g, '_');
}

/* 备份文件导出（同时兼容普通浏览器下载与 Android KSU WebView 直写落盘 /sdcard/Download，绕过 128KB MAX_ARG_STRLEN） */
function v6ExportBackupBundle(actEl) {
  if (typeof KSU !== 'undefined' && KSU && typeof shell === 'function' && typeof loadSecret === 'function') {
    var ksuVer = v6CleanBackupVer(window.S && S.live && S.live.backend_version) ||
      v6CleanBackupVer(window.S && S.lastHealth && (S.lastHealth.backend_version || S.lastHealth.version)) ||
      'v6.1.0-rc.7';
    var ksuFname = 'hnc-backup-' + ksuVer + '-' + Date.now() + '.json';
    var outPath = '/sdcard/Download/' + ksuFname;
    var runCurlSave = function (forceSec) {
      return loadSecret(!!forceSec).then(function (sec) {
        var cmd = 'mkdir -p /sdcard/Download && curl -g -sS -f --connect-timeout 2 --max-time 15' +
          (sec ? ' -H ' + sq('X-HNC-Local-Admin: ' + sec) : '') +
          ' -H ' + sq('Cache-Control: no-cache') +
          ' ' + sq(API_BASE + V6_API.backup) +
          ' -o ' + sq(outPath) +
          ' && sed -n \'s/.*"sha256"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/sha=\\1/p; s/.*"file_count"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/cnt=\\1/p\' ' + sq(outPath);
        return shell(cmd);
      });
    };
    busyWhile(actEl, runCurlSave(false).catch(function () {
      return runCurlSave(true);
    }).then(function (metaOut) {
      var mSha = String(metaOut || '').match(/(?:^|\n)sha=([^\r\n]+)/);
      var mCnt = String(metaOut || '').match(/(?:^|\n)cnt=(\d+)/);
      if (mSha && mSha[1]) V6.vault.last_sha256 = mSha[1].trim();
      if (mCnt && mCnt[1]) V6.vault.last_file_count = Math.round(num(mCnt[1], 0));
      v6RefreshActiveSubviewDom();
      toast('已保存到手机下载目录：' + ksuFname);
    }).catch(function (err) {
      return api.get(V6_API.backup, null, { timeout: 10000 }).then(function (bundle) {
        if (!bundle || typeof bundle !== 'object') throw err;
        var rawJson = JSON.stringify(bundle, null, 2);
        if (typeof copyText === 'function') {
          return copyText(rawJson).then(function (ok) {
            toast(ok ? '写入下载目录失败，已复制备份内容到剪贴板' : '保存失败', ok ? 'warn' : 'err');
          });
        }
        toast('保存失败', 'err');
      }).catch(function (e2) { toast(errText(e2 || err), 'err'); });
    }));
    return;
  }
  busyWhile(actEl, api.get(V6_API.backup, null, { timeout: 10000 }).then(function (bundle) {
    if (!bundle || typeof bundle !== 'object') { toast('导出数据为空', 'err'); return; }
    V6.vault.last_sha256 = String(bundle.sha256 || '');
    V6.vault.last_file_count = Math.round(num(bundle.file_count, 0));
    v6RefreshActiveSubviewDom();
    var jsonStr = JSON.stringify(bundle, null, 2);
    var verTag = v6CleanBackupVer(bundle.module_version) ||
      v6CleanBackupVer(window.S && S.live && S.live.backend_version) ||
      v6CleanBackupVer(window.S && S.lastHealth && (S.lastHealth.backend_version || S.lastHealth.version)) ||
      'v6.1.0-rc.7';
    var fname = 'hnc-backup-' + verTag + '-' + Date.now() + '.json';
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
      if (typeof copyText === 'function') {
        copyText(jsonStr).then(function (ok) {
          toast(ok ? '配置备份已复制到剪贴板' : '复制备份失败', ok ? 'ok' : 'err');
        });
      }
    }
  })).catch(function (e) { toast(errText(e), 'err'); });
}
var v6ExportBackup = v6ExportBackupBundle;

/* ═════════════════════ 全局事件委托与生命周期钩子 ═════════════════════ */
function v6BindEvents() {
  if (typeof document === 'undefined' || document.__v6Bound) return;
  document.__v6Bound = true;

  var scScrim = document.getElementById('v6-scalpel-scrim');
  if (scScrim) scScrim.addEventListener('click', function () { closeScalpelDrawer(false); });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && V6.scalpel.open && !v6IsSheetShowing()) {
      closeScalpelDrawer(false);
      return;
    }
    if (e.key === 'Enter' && e.target && e.target.id === 'v6-host-dom-inp') {
      e.preventDefault();
      var inp = e.target;
      var val = inp.value;
      v6BlockHostDomain(val, inp).then(function (ok) {
        if (ok !== false) inp.value = '';
      });
    }
  }, true);

  /* 记录 <details class="v6-adv-fold"> 展开态，保证后台轮询 morph 时不会自动合上用户展开的高级设置，并在用户点击展开时调用 ensureAboveTabbar 防底栏遮挡 */
  document.addEventListener('toggle', function (e) {
    var dt = typeof evEl === 'function' ? evEl(e) : (e && e.target && e.target.nodeType === 3 ? e.target.parentNode : e && e.target);
    if (dt && dt.matches && dt.matches('details[data-v6-fold]')) {
      var fk = dt.getAttribute('data-v6-fold');
      var wasOpen = fk ? !!V6.advOpen[fk] : false;
      if (fk) V6.advOpen[fk] = !!dt.open;
      var tapped = !!(dt._v6UserTapAt && Date.now() - dt._v6UserTapAt < 800);
      if (dt._v6UserTapAt) dt._v6UserTapAt = 0;
      if (dt.open && (tapped || !wasOpen) && typeof ensureAboveTabbar === 'function') {
        ensureAboveTabbar(dt);
      }
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
          if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
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
    } else if (t.id === 'v6-host-q') {
      V6.host.q = t.value;
      var hl = document.getElementById('v6-host-dynamic-list');
      if (hl) {
        var nextInner = V6.host.mode === 'traffic'
          ? v6RenderHostTrafficRankHtml()
          : (V6.host.mode === 'power' ? v6RenderHostPowerListHtml() : v6RenderHostLiveListHtml());
        morph(hl, nextInner);
      }
    }
  });

  document.addEventListener('click', function (e) {
    var t = typeof evEl === 'function' ? evEl(e) : (e && e.target && e.target.nodeType === 3 ? e.target.parentNode : e && e.target);
    if (!t || typeof t.closest !== 'function') return;
    if (!t.closest('.dd') && typeof closeDD === 'function') closeDD();

    var foldSum = t.closest('details[data-v6-fold] > summary');
    if (foldSum && foldSum.parentNode) {
      foldSum.parentNode._v6UserTapAt = Date.now();
    }

    /* 0. 全站原生 .seg 弹簧分段器（v6-tab / v6-host-mode / v6-host-period / v6-host-net / v6-sc-scope） */
    var segBtn = t.closest('.seg button');
    if (segBtn && segBtn.parentNode) {
      var sg = segBtn.parentNode;
      var sk = sg.getAttribute('data-seg');
      var sv = segBtn.getAttribute('data-v');
      if (sk === 'v6-tab' || sk === 'v6-host-mode' || sk === 'v6-host-period' || sk === 'v6-host-net' || sk === 'v6-sc-scope') {
        e.stopPropagation();
        if (segBtn.classList.contains('on') || sg.classList.contains('pending')) return;
        if (typeof haptic === 'function') haptic(8);
        $$('button', sg).forEach(function (b) { b.classList.toggle('on', b === segBtn); });
        sg.classList.remove('jelly');
        if (typeof placeSegs === 'function') placeSegs(sg.parentNode);

        if (sk === 'v6-tab') {
          V6.subtab = sv || 'escort';
          LS.set('hnc6.v6_subtab', V6.subtab);
          if (V6.subtab === 'privacy') v6MarkLeakGuardSeen();
          v6RefreshHeroDom();
          v6RefreshNavBadges();
          v6RefreshActiveSubviewDom();
          if (V6.subtab === 'host') v6EnsureHostModeLoaded(false);
          else v6SyncHostPollTimer();
        } else if (sk === 'v6-host-mode') {
          V6.host.mode = sv || 'live';
          LS.set('hnc6.v6_host_mode', V6.host.mode);
          v6RefreshActiveSubviewDom();
          v6EnsureHostModeLoaded(false);
        } else if (sk === 'v6-host-period') {
          V6.host.period = sv || 'today';
          LS.set('hnc6.v6_host_period', V6.host.period);
          v6LoadHostTraffic(true);
        } else if (sk === 'v6-host-net') {
          V6.host.net = sv || 'all';
          LS.set('hnc6.v6_host_net', V6.host.net);
          v6LoadHostTraffic(true);
        } else if (sk === 'v6-sc-scope') {
          V6.scalpel.scopeDomain = sv || 'all';
          V6.scalpel.drawerFlows = null;
          V6.scalpel.drawerTotal = 0;
          v6RefreshScalpelDrawerList();
          v6ResetScalpelScroll();
          v6FetchScalpelFlows();
        }
        return;
      }
    }

    /* 1. 兼容旧式 data-v6-subtab 切换触发器 */
    var subBtn = t.closest('[data-v6-subtab]');
    if (subBtn) {
      e.stopPropagation();
      var nextSub = subBtn.getAttribute('data-v6-subtab') || 'escort';
      if (typeof haptic === 'function') haptic(8);
      openV6Subtab(nextSub);
      return;
    }

    /* 2. Hero 控制中心三联磁贴 (.cc-tile[data-v6-tile] 与兼容 [data-v6-bento]) */
    var tileBtn = t.closest('[data-v6-tile], [data-v6-bento]');
    if (tileBtn) {
      e.stopPropagation();
      if (tileBtn.classList.contains('busy')) return;
      if (typeof haptic === 'function') haptic(10);
      var bKind = tileBtn.getAttribute('data-v6-tile') || tileBtn.getAttribute('data-v6-bento');
      if (bKind === 'express') {
        var nextExp = !V6.express.enabled;
        V6.express.enabled = nextExp;
        v6RefreshHeroDom();
        if (V6.subtab === 'escort') v6RefreshActiveSubviewDom();
        v6PostExpress({ enabled: nextExp }, tileBtn, nextExp ? '已开启游戏与通话优先' : '已关闭游戏与通话优先');
      } else if (bKind === 'leash') {
        var nextUl = !V6.leash.enabled;
        V6.leash.enabled = nextUl;
        v6RefreshHeroDom();
        if (V6.subtab === 'escort') v6RefreshActiveSubviewDom();
        v6PostLeash({ action: 'config', enabled: nextUl }, tileBtn, nextUl ? '已开启后台大更新限幅' : '已关闭后台大更新限幅');
      } else if (bKind === 'thermo') {
        var nextTh = !V6.thermo.enabled;
        V6.thermo.enabled = nextTh;
        v6RefreshHeroDom();
        if (V6.subtab === 'escort') v6RefreshActiveSubviewDom();
        v6PostThermo({ enabled: nextTh }, tileBtn, nextTh ? '已开启机身温控保护' : '已关闭机身温控保护');
      }
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
        v6PostExpress({ enabled: nextOn }, vTog, nextOn ? '游戏与视频优先已开启' : '游戏与视频优先已关闭');
      } else if (kind === 'express-auto') {
        V6.express.auto_detect = nextOn;
        v6PostExpress({ auto_detect: nextOn }, vTog, nextOn ? '已开启自动识别游戏与通话' : '已切换为仅手动指定设备优先');
      } else if (kind === 'leash') {
        V6.leash.enabled = nextOn;
        v6RefreshHeroDom();
        v6PostLeash({ action: 'config', enabled: nextOn }, vTog, nextOn ? '后台大下载限幅已开启' : '后台大下载限幅已关闭');
      } else if (kind === 'thermo') {
        V6.thermo.enabled = nextOn;
        v6RefreshHeroDom();
        v6PostThermo({ enabled: nextOn }, vTog, nextOn ? '高温与低电量保护已开启' : '高温与低电量保护已关闭');
      } else if (kind === 'thermo-shaper') {
        V6.thermo.stage2_shaper_enabled = nextOn;
        v6PostThermo({ stage2_shaper_enabled: nextOn }, vTog, nextOn ? '已开启严重过热自动收紧后台网速' : '已关闭过热限速降温');
      } else if (kind === 'host-sys') {
        V6.host.includeSystem = nextOn;
        LS.set('hnc6.v6_host_sys', nextOn ? '1' : '0');
        v6EnsureHostModeLoaded(true);
      } else if (kind === 'host-self-capture') {
        v6ToggleSelfCapture(nextOn, vTog);
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
      case 'go-host':
        openV6Subtab('host', { mode: actEl.getAttribute('data-mode') || 'live' });
        break;
      case 'toggle-health':
        V6.healthOpen = !V6.healthOpen;
        var hd = document.getElementById('v6-health-drawer');
        if (hd) hd.hidden = !V6.healthOpen;
        break;
      case 'open-scalpel':
        openScalpelDrawer(
          actEl.getAttribute('data-mac') || '',
          actEl.getAttribute('data-ip') || '',
          actEl.getAttribute('data-name') || '',
          actEl.getAttribute('data-scope') || ''
        );
        break;
      case 'scalpel-close':
        closeScalpelDrawer();
        break;
      case 'scalpel-all-scope':
        V6.scalpel.scopeMac = '';
        V6.scalpel.scopeIp = '';
        V6.scalpel.devName = '';
        V6.scalpel.scopeDomain = 'all';
        V6.scalpel.drawerFlows = null;
        V6.scalpel.drawerTotal = 0;
        var bd0 = document.getElementById('v6-scalpel-body');
        if (bd0) {
          bd0.innerHTML = v6ScalpelDrawerBodyHtml();
          if (typeof placeSegs === 'function') placeSegs(bd0);
        }
        v6ResetScalpelScroll();
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
        v6ResetScalpelScroll();
        break;
      case 'scalpel-cut-once':
      case 'scalpel-cut-freeze':
        var fid = actEl.getAttribute('data-fid');
        var hasDrFlows = Array.isArray(V6.scalpel.drawerFlows) && V6.scalpel.drawerFlows.length > 0;
        var pool = (V6.scalpel.scopeMac || V6.scalpel.scopeIp || V6.scalpel.scopeDomain !== 'all' || hasDrFlows)
          ? (Array.isArray(V6.scalpel.drawerFlows) ? V6.scalpel.drawerFlows : [])
          : V6.scalpel.globalFlows;
        var fl = pool.filter(function (x) { return x.id === fid; })[0];
        v6CutFlow(fl, act === 'scalpel-cut-freeze', actEl);
        break;
      case 'host-refresh-all':
        busyWhile(actEl, Promise.all([
          v6LoadHostTraffic(true),
          v6LoadHostFirewall(true),
          v6LoadHostPower(true),
          v6LoadHostPrivacy(true)
        ])).then(function () { toast('本机守护数据已刷新'); });
        break;
      case 'host-power-refresh':
        busyWhile(actEl, v6LoadHostPower(true)).then(function () {
          toast(V6.host.power.refresh_throttled ? '距上次刷新不足15秒，已展示最新缓存' : '后台耗电统计已刷新');
        });
        break;
      case 'host-psort':
        V6.host.powerSort = actEl.getAttribute('data-sort') || 'bg_mah';
        LS.set('hnc6.v6_host_psort', V6.host.powerSort);
        $$('#v6-host-list-card [data-v6-act="host-psort"]').forEach(function (b) { b.classList.toggle('on', b === actEl); });
        v6LoadHostPower(false);
        break;
      case 'host-privacy-refresh':
        busyWhile(actEl, v6LoadHostPrivacy(true)).then(function () { toast('本机明文与追踪风险已重新扫描'); });
        break;
      case 'host-app-open':
        v6OpenHostAppSheet(
          num(actEl.getAttribute('data-uid'), -1),
          actEl.getAttribute('data-pkg') || '',
          actEl.getAttribute('data-name') || '',
          actEl.getAttribute('data-sys') === '1'
        );
        break;
      case 'host-fw-set':
        v6SetHostUidFirewall(
          num(actEl.getAttribute('data-uid'), -1),
          actEl.getAttribute('data-fw-mode') || 'allow',
          actEl.getAttribute('data-pkg') || '',
          actEl.getAttribute('data-name') || '',
          actEl,
          false
        );
        break;
      case 'host-fw-clear':
        v6ClearHostFirewall(actEl);
        break;
      case 'host-dns-block':
        v6BlockHostDomain(actEl.getAttribute('data-domain') || '', actEl);
        break;
      case 'host-dns-add':
        var dinp = document.getElementById('v6-host-dom-inp');
        var dval = dinp ? dinp.value : '';
        v6BlockHostDomain(dval, actEl).then(function (ok) {
          if (ok !== false && dinp) dinp.value = '';
        });
        break;
      case 'host-dns-unblock':
        v6UnblockHostDomain(actEl.getAttribute('data-domain') || '', actEl, false);
        break;
      case 'host-ip-unblock':
        v6UnblockHostUidIp(
          num(actEl.getAttribute('data-uid'), -1),
          actEl.getAttribute('data-ip') || '',
          actEl.getAttribute('data-pkg') || '',
          actEl.getAttribute('data-name') || '',
          actEl,
          false
        );
        break;
      case 'host-uid-ip-clear':
        v6ClearHostUidIps(
          num(actEl.getAttribute('data-uid'), -1),
          actEl.getAttribute('data-pkg') || '',
          actEl.getAttribute('data-name') || '',
          actEl
        );
        break;
      case 'host-sheet-cut':
        var hfid = actEl.getAttribute('data-fid');
        var hfl = (V6.host.appSheet.flows || []).filter(function (x) { return x.id === hfid; })[0];
        if (hfl) v6CutFlow(hfl, actEl.getAttribute('data-freeze') === '1', actEl);
        break;
      case 'lgd-refresh':
        busyWhile(actEl, v6LoadLeakGuard(true)).then(function () { toast('隐私安检列表已刷新'); });
        break;
      case 'lgd-clear':
        v6ClearLeakGuard(actEl);
        break;
      case 'lgd-save-cfg':
        v6SaveLeakGuardConfig(null, actEl, '通知提醒与保留设置已保存');
        break;
      case 'lgd-origin-filter':
        V6.lg.originFilter = actEl.getAttribute('data-origin') || 'ALL';
        V6.lg.visibleLimit = 30;
        $$('#v6-leakguard-card [data-v6-act="lgd-origin-filter"]').forEach(function (b) { b.classList.toggle('on', b === actEl); });
        var stOrig = document.getElementById('lgd-stream-list');
        if (stOrig) morph(stOrig, v6LeakStreamHtml());
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
      case 'lgd-ignore-sheet':
        var igId = actEl.getAttribute('data-id');
        var igEv = V6.lg.events.filter(function (x) { return x.id === igId; })[0];
        if (igEv) v6OpenLeakWhitelistSheet(igEv);
        break;
      case 'lgd-wl-remove':
        var widAttr = actEl.getAttribute('data-wid');
        if (widAttr != null && widAttr !== '') {
          v6RemoveLeakWhitelist(widAttr, actEl);
        } else {
          var wIdx = Math.round(num(actEl.getAttribute('data-widx'), -1));
          if (wIdx >= 0) v6RemoveLeakWhitelist(wIdx, actEl);
        }
        break;
      case 'lgd-undo-block':
        v6UndoLeakBlock(
          actEl.getAttribute('data-uid') || '',
          actEl.getAttribute('data-host') || '',
          actEl.getAttribute('data-tscope') || '',
          actEl,
          actEl.getAttribute('data-app-uid') || ''
        );
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
        var wasExpOn = !!V6.express.enabled;
        if (pos >= 0) nextMacs.splice(pos, 1);
        else nextMacs.push(emac);
        V6.express.forced_macs = nextMacs;
        var autoTurnedOn = !wasExpOn && pos < 0 && nextMacs.length > 0;
        var expPayload = { forced_macs: nextMacs };
        if (autoTurnedOn) {
          V6.express.enabled = true;
          expPayload.enabled = true;
        }
        v6PostExpress(
          expPayload,
          actEl,
          pos < 0 ? '已将该设备设为常驻优先' : '已取消该设备的常驻优先',
          { macOp: { mac: emac, added: pos < 0, autoTurnedOn: autoTurnedOn } }
        );
        break;
      case 'leash-preset-grace':
        var pMb = clamp(Math.round(num(actEl.getAttribute('data-mb'), 200)), 10, 10240);
        var gInp = document.getElementById('v6-ul-grace');
        if (gInp) gInp.value = String(pMb);
        V6.leash.grace_mb = pMb;
        v6PostLeash({
          action: 'config',
          grace_mb: pMb
        }, actEl, '免限速高速额度已设为 ' + (pMb >= 1024 ? '1 GB' : (pMb + ' MB')));
        break;
      case 'leash-save':
        var gm = clamp(Math.round(num(($('#v6-ul-grace') || {}).value, 200)), 10, 10240);
        var kb = clamp(Math.round(num(($('#v6-ul-kbps') || {}).value, 1500)), 128, 1000000);
        V6.leash.grace_mb = gm;
        V6.leash.leash_kbps = kb;
        v6PostLeash({
          action: 'config',
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
          stage1_temp_c: t1,
          stage2_temp_c: t2
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
        if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
        busyWhile(actEl, api.post(V6_API.blackbox, { action: 'clear' }, { timeout: 6000 })).then(function () {
          V6.blackbox.incidents = [];
          V6.blackbox.incident_count = 0;
          v6RefreshActiveSubviewDom();
          toast('已清空卡顿事件记录');
        }).catch(function (e) { toast(errText(e), 'err'); });
        break;
      case 'subtrees-sync':
        if (api && typeof api.bumpWriteGen === 'function') api.bumpWriteGen();
        busyWhile(actEl, api.post(V6_API.nativeSubtrees, { action: 'full_restore' }, { timeout: 8000 })).then(function (r) {
          var dqos = r && (r.dynamic_qos || (r.report && r.report.qos_ratios));
          if (dqos && typeof dqos === 'object') {
            var nsObj = Object.assign({}, r, { dynamic_qos: dqos });
            if (nsObj.full_restores == null && r.report && r.report.full_restores != null) nsObj.full_restores = r.report.full_restores;
            v6ApplyScreenshotPackSummary({ native_subtrees: nsObj });
          } else if (r && r.full_restores != null) {
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
  v6EnsureLeakStream();
}

function v6OnPollTick(tickN) {
  v6SyncHostPollTimer();
  if (S.page === 'vector') {
    if ((KSU || !V6.lg.sseActive) && tickN % 2 === 0 && V6.apiSupported.lg) v6LoadLeakGuard();
    if (tickN % 3 === 0 && V6.apiSupported.v6) v6LoadCockpitAll();
  } else if (S.vectorSyncState !== 'supported' && tickN % 10 === 0) {
    if (V6.apiSupported.lg) v6LoadLeakGuard();
  }
}

function v6OnVisibility(hidden) {
  v6SyncHostPollTimer();
  if (hidden) {
    v6StopLeakGuardSSE();
    v6StopScalpelTimer();
    v6PauseHostAppSheetTimer();
  } else {
    v6EnsureLeakStream();
    if (S.page === 'vector') {
      v6LoadLeakGuard();
      v6LoadCockpitAll();
      if (V6.subtab === 'host') v6EnsureHostModeLoaded(false);
    }
    if (V6.scalpel.open) {
      if (!V6.scalpel.paused) v6FetchScalpelFlows();
      v6StartScalpelTimer();
    }
    if (V6.host.appSheet.open) {
      v6FetchHostAppFlows();
      v6StartHostAppSheetTimer();
    }
  }
}

v6BindEvents();
if (typeof window !== 'undefined') {
  window.openV6Subtab = openV6Subtab;
  window.HNCVectorV6 = {
    V6: V6,
    escapeHtml: escapeHtml,
    highlightRawSnippet: highlightRawSnippet,
    openSubtab: openV6Subtab,
    openScalpelDrawer: openScalpelDrawer,
    closeScalpelDrawer: closeScalpelDrawer,
    focusPrivacy: v6FocusPrivacyPanel,
    ingestSync: v6IngestVectorSync,
    renderVectorPage: renderVectorPage
  };
}
