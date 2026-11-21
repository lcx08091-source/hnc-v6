/* HNC WebUI 界面预览 · fake_api.js —— 演示用的假后端(纯前端, 不联网)
 *
 * 由 tools/ui_mock/build.js 插在 js/core.js 之后(经典脚本, 不是 module; 与 webroot 各脚本共用一个全局作用域)。
 *  - 覆盖 core.js 的 req(): 所有 /api/* 请求都在内存里应答(随机 40~150ms 延迟)。没有模拟的接口一律
 *    HttpError('演示模式未提供此接口', 404), api.getSafe 会按默认值兜底。
 *  - 数据全部虚构: 设备名、MAC(本地管理地址)、IP、流量、告警都是编的, 与任何真实的人和设备无关。
 *    速率按随机游走变化, 页面看起来是"活"的; 改名 / 限速 / 开关这类写操作会改内存里的状态(刷新页面后复原)。
 *  - 拦下预览里用不了的东西: SSE(EventSource)、退出登录跳 /pair、下载导出文件、glass.html 原型链接;
 *    changelog.html 用 build.js 内嵌的副本(window.__HNC_MOCK_CHANGELOG)应答。
 *  - 顶栏 #mode-pill 固定显示「演示数据」(窄屏也显示), 免得被当成真实数据。
 */
(function () {
  'use strict';

  var META = window.__HNC_MOCK_META || {};
  var VER = META.version || 'v6.1.0-beta.1', VCODE = String(META.versionCode || '6009201');
  var GB = 1073741824, MB = 1048576, KB = 1024;
  var IFACE = 'wlan2', GW = '192.168.43.1';

  /* ═════════════ 小工具 ═════════════ */
  function now() { return Math.floor(Date.now() / 1000); }
  function rnd(a, b) { return a + Math.random() * (b - a); }
  function lim(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
  function hashStr(s) { var h = 2166136261; s = String(s); for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
  /* 确定性随机: 同一个 key 每次结果一样(统计图不会每次请求都变样) */
  function srand(key) {
    var a = hashStr(key);
    return function () { a = (a + 0x6D2B79F5) | 0; var t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }
  function p2(n) { return (n < 10 ? '0' : '') + n; }
  function dayAt(off) { var d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - off); return d; }
  function ymd(d) { return d.getFullYear() + p2(d.getMonth() + 1) + p2(d.getDate()); }
  function ymdDash(d) { return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()); }
  function mdDash(d) { return p2(d.getMonth() + 1) + '-' + p2(d.getDate()); }
  function midnight() { return Math.floor(dayAt(0).getTime() / 1000); }
  function round(v) { return Math.round(v); }
  function bool(v) { return v === true || /^(true|1|on|yes)$/i.test(String(v)); }
  function fakeIp(key) {
    var r = srand('ip:' + key), A = [36, 42, 58, 101, 106, 110, 111, 112, 113, 116, 117, 119, 120, 121, 122, 123, 124, 140, 175, 180, 182, 183, 202, 211, 218, 220, 221, 222, 223];
    return A[Math.floor(r() * A.length)] + '.' + (1 + Math.floor(r() * 254)) + '.' + Math.floor(r() * 255) + '.' + (1 + Math.floor(r() * 253));
  }
  function err(msg, status, extra) { return HttpError(msg, status || 400, Object.assign({ ok: false, error: msg }, extra || {})); }

  /* ═════════════ 应用目录(id → 名称 / 类别 / 常见域名) ═════════════ */
  var APP = {
    douyin: ['抖音', 'short_video', ['v26-dy.douyinvod.com', 'api5-normal-lq.amemv.com', 'p26-sign.douyinpic.com']],
    kuaishou: ['快手', 'short_video', ['txmov2.a.kwimgs.com', 'api.gifshow.com']],
    wechat: ['微信', 'social', ['szextshort.weixin.qq.com', 'mmsns.qpic.cn', 'wx.qlogo.cn']],
    honor_of_kings: ['王者荣耀', 'game', ['pvp.qq.com', 'gamesafe.qq.com']],
    genshin: ['原神', 'game', ['hk4e-sdk.mihoyo.com', 'autopatchcn.yuanshen.com']],
    peacekeeper: ['和平精英', 'game', ['gp.qq.com']],
    bilibili: ['B站', 'video', ['upos-sz-mirrorcos.bilivideo.com', 'api.bilibili.com', 'i0.hdslb.com']],
    iqiyi: ['爱奇艺', 'video', ['data.video.iqiyi.com', 'cache.m.iqiyi.com', 'msg.qy.net']],
    tencent_video: ['腾讯视频', 'video', ['vd6.l.qq.com']],
    xiaomi_store: ['小米应用商店', 'download', ['f5.market.xiaomi.com', 'file.market.mi-img.com']],
    tencent_meeting: ['腾讯会议', 'office', ['meeting.tencent.com', 'avc.meeting.qq.com']],
    feishu: ['飞书', 'office', ['internal-api-lark-api.feishu.cn', 'frontier.feishu.cn']],
    icloud: ['iCloud', 'cloud', ['p62-contacts.icloud.com', 'gateway.icloud.com']],
    nintendo_eshop: ['任天堂 eShop', 'download', ['atum.hac.lp1.d4c.nintendo.net', 'aqua.hac.lp1.d4c.nintendo.net']],
    nintendo_online: ['Nintendo Switch Online', 'game', ['dauth-lp1.ndas.srv.nintendo.net', 'g1.npln.srv.nintendo.net']],
    qqmusic: ['QQ音乐', 'music', ['isure.stream.qqmusic.qq.com', 'u.y.qq.com']],
    xiaohongshu: ['小红书', 'social', ['sns-video-qc.xhscdn.com', 'edith.xiaohongshu.com']],
    amap: ['高德地图', 'navigation', ['m5.amap.com', 'webrd01.is.autonavi.com']],
    taobao: ['淘宝', 'shopping', ['gw.alicdn.com', 'acs.m.taobao.com']],
    weibo: ['微博', 'social', ['api.weibo.cn']],
    netease_music: ['网易云音乐', 'music', ['interface.music.163.com']],
    windows_update: ['Windows 更新', 'system_update', ['tlu.dl.delivery.mp.microsoft.com', 'settings-win.data.microsoft.com']],
    teams: ['Microsoft Teams', 'office', ['teams.microsoft.com']],
    _tunnel: ['VPN/代理隧道', 'tunnel', []]
  };
  function appName(id) { return id === '_unknown' ? '未识别' : id === '_local' ? '局域网' : (APP[id] ? APP[id][0] : id); }
  function appCat(id) { return APP[id] ? APP[id][1] : 'unknown'; }

  /* ═════════════ 设备(全部虚构; MAC 用本地管理地址) ═════════════ */
  var T = now();
  var DEVS = [
    { mac: '0a:7f:3c:41:9e:21', ip: '192.168.43.23', hostname: '小米 14', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 1, randomized_mac: true, auto_inherited_from: '6e:19:b4:82:0c:55', auto_inherited_name: '小米 14', auto_inherited_score: 94,
      base: [1.1 * MB, 115 * KB], usage8: 5.2 * GB, onlineMin: [312, 288, 351, 240, 402, 198, 267],
      ident: { type: 'phone', os: 'Android', os_ver: '15', brand: '小米', model: 'Xiaomi 14', confidence: 93, hostname: 'Xiaomi-14', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'option 60 = android-dhcp-15' }, { src: 'hostname', detail: 'Xiaomi-14' }, { src: 'sni', detail: '*.miui.com · *.xiaomi.net' }, { src: 'ja4', detail: 'Android 15 系统 TLS 栈' }] },
      live: [['xiaomi_store', 0.72], ['honor_of_kings', 0.15], ['wechat', 0.09]], hist: ['honor_of_kings', 'wechat', 'douyin', 'genshin', 'xiaomi_store'],
      fg: { state: 'active', screen_state: 'active', app_id: 'honor_of_kings', name: '王者荣耀', confidence: 0.94, label: '正在用：王者荣耀', evidence_tags: ['DSCP实时标', '触控微突发'], companion: { app_id: 'wechat', name: '微信', mode: 'call', label: '语音开黑中', bps: 64000 }, dual_stack: { v6_pct: 82, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 1.4 }, bg_label: '后台：应用商店更新（CS1 降权已压制）',
        reasons: ['UDP 小包双向持续，每秒 30+ 个包', '包长稳定、间隔均匀（对战特征）', '握手 SNI 命中 *.pvp.qq.com'] },
      traffic_type: { type: 'game', label: '实时对战' }, app_qos: true },
    { mac: '1e:52:a8:0c:77:3d', ip: '192.168.43.45', hostname: 'iPad Air', hostname_src: 'manual', vendor: 'Apple', online: true, mark_id: 5,
      base: [2.0 * MB, 140 * KB], usage8: 8.3 * GB, onlineMin: [145, 210, 186, 95, 260, 300, 172],
      limit_enabled: true, down_mbps: 24, up_mbps: 8,
      ident: { type: 'tablet', os: 'iPadOS', os_ver: '18.6', brand: 'Apple', model: 'iPad Air', confidence: 88, hostname: 'iPad', hostname_src: 'mdns',
        services: ['_airplay._tcp', '_companion-link._tcp', '_rdlink._tcp'], evidence: [{ src: 'mdns', detail: '_companion-link._tcp · model=iPad13,16' }, { src: 'dhcp', detail: 'option 55 = 1,121,3,6,15,108,114,119,252' }, { src: 'oui', detail: 'Apple（随机 MAC 前缀已关闭）' }] },
      live: [['douyin', 0.78], ['bilibili', 0.12], ['wechat', 0.05]], hist: ['douyin', 'bilibili', 'wechat', 'xiaohongshu'],
      fg: { state: 'active', screen_state: 'active', app_id: 'douyin', name: '抖音', confidence: 0.93, label: '正在用：抖音', evidence_tags: ['秒级紧耦合', '触控微突发'], companion: { app_id: 'qqmusic', name: 'QQ音乐', mode: 'audio', label: '后台音频播放', bps: 192000 }, dual_stack: { v6_pct: 88, qos_cov: 'dual_stack_ok', escape_alert: false, limit_mbps: 24, actual_mbps: 16.2 }, reasons: ['DNS->QUIC 握手紧耦合 22ms + 重尾滑动突发 (CV=1.42)', '域名命中 *.douyinvod.com（IPv6 双栈限速已闭合）', 'ABR 虚拟播放缓冲信用保护中'] },
      traffic_type: { type: 'short_video', label: '刷短视频' },
      app_time_limits: [{ app_id: 'douyin', name: '抖音', category: 'short_video', minutes: 60, used_sec: 3120, used_min: 52, exhausted: false, enforced: true }],
      category_blocks: [{ category: 'game', app_count: 6, ts: T - 3 * 86400, enforced: true }],
      blocks: [{ kind: 'domain', value: 'yuanshen.com', label: '原神', source: 'category', ref: 'game' }, { kind: 'domain', value: 'pvp.qq.com', label: '王者荣耀', source: 'category', ref: 'game' }] },
    { mac: '3a:91:d4:6b:02:5f', ip: '192.168.43.31', hostname: 'MacBook Pro', hostname_src: 'manual', vendor: 'Apple', online: true, mark_id: 4,
      base: [420 * KB, 310 * KB], usage8: 3.7 * GB, onlineMin: [236, 410, 388, 0, 0, 455, 402],
      sqm_enabled: true, whitelist: true,
      ident: { type: 'pc', os: 'macOS', os_ver: '15.6', brand: 'Apple', model: 'MacBook Pro', confidence: 90, hostname: 'MacBook-Pro', hostname_src: 'mdns',
        services: ['_ssh._tcp', '_smb._tcp', '_companion-link._tcp'], evidence: [{ src: 'mdns', detail: 'model=Mac15,6' }, { src: 'dhcp', detail: 'macOS DHCP 指纹' }, { src: 'ja4', detail: 'Safari / macOS TLS 栈' }] },
      live: [['tencent_meeting', 0.82], ['feishu', 0.1], ['icloud', 0.05]], hist: ['tencent_meeting', 'feishu', 'wechat', 'icloud'],
      fg: { state: 'active', screen_state: 'active', app_id: 'tencent_meeting', name: '腾讯会议', confidence: 0.96, label: '正在用：腾讯会议', evidence_tags: ['DSCP实时标', 'STUN/SRTP'], dual_stack: { v6_pct: 76, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 5.8 }, reasons: ['上行携带 WebRTC EF(46)/AF41 原生实时 DSCP 标记', 'RFC 8489 STUN + SRTP 双向 50Hz 对称媒体流', '域名命中 *.meeting.qq.com'] },
      traffic_type: { type: 'call', label: '视频会议' }, live_call: { label: '腾讯会议', kind: 'video', since: T - 23 * 60 } },
    { mac: '5e:20:b7:3a:c4:18', ip: '192.168.43.52', hostname: '任天堂 Switch', hostname_src: 'manual', vendor: 'Nintendo', online: true, mark_id: 6,
      base: [1.8 * MB, 40 * KB], usage8: 7.1 * GB, onlineMin: [88, 120, 64, 302, 245, 0, 90],
      ident: { type: 'console', os: 'Horizon', brand: '任天堂', model: 'Switch OLED', confidence: 82, hostname: 'Nintendo-Switch', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'vendor class = Nintendo' }, { src: 'sni', detail: '*.d4c.nintendo.net' }] },
      live: [['nintendo_eshop', 0.93], ['nintendo_online', 0.05]], hist: ['nintendo_eshop', 'nintendo_online'],
      traffic_type: { type: 'download', label: '下载游戏更新' },
      schedule: { windows: [{ days: [1, 2, 3, 4, 5], start: '22:00', end: '07:00', down_mbps: 0, up_mbps: 0, block: true }, { days: [0, 6], start: '23:30', end: '08:00', down_mbps: 0, up_mbps: 0, block: true }] } },
    { mac: '6a:0e:55:b1:9c:42', ip: '192.168.43.67', hostname: '客厅电视', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 7,
      base: [2.3 * MB, 60 * KB], usage8: 12.8 * GB, onlineMin: [190, 245, 160, 330, 410, 380, 205],
      ident: { type: 'tv', os: 'Android TV', os_ver: '11', brand: '小米', model: 'Redmi 智能电视 X65', confidence: 86, hostname: 'MiTV-AXSU', hostname_src: 'dhcp',
        services: ['_googlecast._tcp', '_miio._udp'], evidence: [{ src: 'mdns', detail: '_googlecast._tcp' }, { src: 'ssdp', detail: 'urn:schemas-upnp-org:device:MediaRenderer:1' }] },
      live: [['iqiyi', 0.95], ['tencent_video', 0.02]], hist: ['iqiyi', 'tencent_video', 'bilibili'],
      fg: { state: 'active', screen_state: 'idle_audio', app_id: 'iqiyi', name: '爱奇艺', confidence: 0.91, label: '正在播：爱奇艺', evidence_tags: ['缓冲续播'], dual_stack: { v6_pct: 91, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 18.4 }, reasons: ['4K DASH/HLS 分片下行 18.4 Mbps（IPv6 占 91%）', '无高频触控点按，处于沉浸观看态'] },
      traffic_type: { type: 'video', label: '4K 视频' } },
    { mac: '7e:c4:19:20:5a:8b', ip: '192.168.43.71', hostname: '小爱音箱', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 8,
      base: [38 * KB, 6 * KB], usage8: 0.25 * GB, onlineMin: [1380, 1440, 1440, 1440, 1440, 1440, 1440], whitelist: true,
      ident: { type: 'iot', os: 'Linux', brand: '小米', model: '小爱音箱 Pro', confidence: 76, hostname: 'xiaomi-wifispeaker-l15a', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'xiaomi-wifispeaker-l15a' }, { src: 'mdns', detail: '_miio._udp' }] },
      live: [['qqmusic', 0.9]], hist: ['qqmusic'], traffic_type: { type: 'music', label: '在线音乐' } },
    { mac: '8a:3d:62:f0:11:c9', ip: '192.168.43.38', hostname: '华为 MatePad', hostname_src: 'manual', vendor: 'Huawei', online: false, last_seen: T - 3 * 3600 - 640, mark_id: 9,
      status: 'blocked', base: [0, 0], usage8: 1.3 * GB, onlineMin: [0, 85, 120, 60, 0, 140, 96],
      ident: { type: 'tablet', os: 'HarmonyOS', os_ver: '4.2', brand: '华为', model: 'MatePad 11.5', confidence: 84, hostname: 'HUAWEI_MatePad', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'HUAWEI_MatePad' }, { src: 'sni', detail: '*.dbankcloud.cn · *.hicloud.com' }] },
      live: [], hist: ['kuaishou', 'peacekeeper', 'wechat'] },
    { mac: 'a6:5b:0f:93:7e:24', ip: '192.168.43.84', hostname: 'ThinkPad', hostname_src: 'manual', vendor: 'Lenovo', online: true, mark_id: 10,
      base: [780 * KB, 160 * KB], usage8: 4.6 * GB, onlineMin: [410, 455, 0, 0, 380, 420, 396],
      ident: { type: 'pc', os: 'Windows', os_ver: '11', brand: '联想', model: 'ThinkPad X1 Carbon', confidence: 89, hostname: 'ThinkPad-X1', hostname_src: 'dhcp',
        services: ['_smb._tcp'], evidence: [{ src: 'dhcp', detail: 'MSFT 5.0' }, { src: 'nbns', detail: 'THINKPAD-X1' }, { src: 'sni', detail: '*.windowsupdate.com' }] },
      live: [['_tunnel', 0.62], ['windows_update', 0.22], ['teams', 0.08]], hist: ['_tunnel', 'windows_update', 'teams', 'wechat'],
      traffic_type: { type: 'tunnel', label: 'VPN 隧道' },
      vpn: { level: 'certain', reason: 'WireGuard（udp 51820）', share: 0.62, bytes: 48 * MB, dst: '203.0.113.18', window_sec: 300 },
      quota: { daily_gb: 5, monthly_gb: 60, action: 'throttle', throttle_mbps: 4, throttle_up_mbps: 2, used_today: 4.1 * GB, used_month: 4.6 * GB, billing_day: 1 },
      blocks: [{ kind: 'domain', value: 'steampowered.com', label: 'Steam' }] },
    { mac: 'd2:6e:4a:8c:15:f3', ip: '192.168.43.96', hostname: '', hostname_src: 'mac', vendor: '', online: true, randomized_mac: true, first_seen: T - 6 * 60, mark_id: 11,
      base: [210 * KB, 24 * KB], usage8: 0.05 * GB, onlineMin: [6, 0, 0, 0, 0, 0, 0],
      ident: { type: 'phone', os: 'Android', confidence: 35, evidence: [{ src: 'dhcp', detail: 'option 60 = android-dhcp-14' }] },
      live: [['xiaohongshu', 0.6], ['wechat', 0.2], ['amap', 0.12]], hist: ['xiaohongshu', 'wechat', 'amap'],
      merge_suggestion: { old_mac: 'ae:14:7c:2b:90:d5', old_name: 'Redmi K60', score: 68, old_last_seen: T - 9 * 86400 - 5400,
        reasons: ['DHCP 指纹相同（android-dhcp-14）', 'TLS 指纹相同（3 个）', '常用应用重合：微信、小红书、高德地图', '主机名不同（新 MAC 没上报主机名）'] } },
    { mac: 'ae:14:7c:2b:90:d5', ip: '192.168.43.60', hostname: 'Redmi-K60', hostname_src: 'dhcp', vendor: 'Xiaomi', online: false, last_seen: T - 9 * 86400 - 5400,
      base: [0, 0], usage8: 0, onlineMin: [0, 0, 0, 0, 0, 0, 0], ident: { type: 'phone', os: 'Android', os_ver: '14', brand: '小米', model: 'Redmi K60', confidence: 80 },
      live: [], hist: ['wechat', 'xiaohongshu', 'amap'] }
  ];
  DEVS.forEach(function (d) {
    ['down_mbps', 'up_mbps', 'delay_ms', 'jitter_ms', 'loss_pct'].forEach(function (k) { d[k] = d[k] || 0; });
    d.status = d.status || 'allowed'; d.k = [1, 1]; d.cur = [0, 0]; d.auto = [d.hostname, d.hostname_src];
    d.blocks = d.blocks || []; d.rx_bytes = d.usage8 * 0.12; d.tx_bytes = d.usage8 * 0.01;
    d.app_time_limits = d.app_time_limits || []; d.category_blocks = d.category_blocks || [];
    if (d.auto[1] === 'manual') d.auto = [d.ident && d.ident.hostname || '', d.ident && d.ident.hostname_src || 'dhcp'];
  });
  function dev(mac) { mac = String(mac || '').toLowerCase().replace(/-/g, ':'); for (var i = 0; i < DEVS.length; i++) if (DEVS[i].mac === mac) return DEVS[i]; return null; }
  function needDev(mac) { var d = dev(mac); if (!d) throw err('not found'); return d; }

  /* 分时段: 当前命中第几个窗口(跨午夜的窗口属于开始那天) */
  function schedIdx(d) {
    var s = d.schedule; if (!s || !s.windows) return -1;
    var t = new Date(), wd = t.getDay(), yd = (wd + 6) % 7, m = t.getHours() * 60 + t.getMinutes();
    var hm = function (x) { var a = String(x).split(':'); return (+a[0]) * 60 + (+a[1] || 0); };
    for (var i = 0; i < s.windows.length; i++) {
      var w = s.windows[i], ds = w.days && w.days.length ? w.days : [0, 1, 2, 3, 4, 5, 6], a = hm(w.start), b = hm(w.end);
      if (a === b) { if (ds.indexOf(wd) >= 0) return i; continue; }
      if (a < b) { if (ds.indexOf(wd) >= 0 && m >= a && m < b) return i; continue; }
      if ((ds.indexOf(wd) >= 0 && m >= a) || (ds.indexOf(yd) >= 0 && m < b)) return i;
    }
    return -1;
  }
  function effective(d) {
    if (d.status === 'blocked') return { down_mbps: 0, up_mbps: 0, blocked: true, reason: 'block' };
    var i = schedIdx(d);
    if (i >= 0) { var w = d.schedule.windows[i]; return { down_mbps: w.block ? 0 : w.down_mbps, up_mbps: w.block ? 0 : w.up_mbps, blocked: !!w.block, reason: 'schedule' }; }
    var q = d.quota;
    if (q && quotaState(q).state === 'exceeded') return { down_mbps: q.action === 'block' ? 0 : q.throttle_mbps, up_mbps: q.action === 'block' ? 0 : q.throttle_up_mbps, blocked: q.action === 'block', reason: 'quota' };
    var on = d.limit_enabled !== false && (d.down_mbps > 0 || d.up_mbps > 0);
    return { down_mbps: on ? d.down_mbps : 0, up_mbps: on ? d.up_mbps : 0, blocked: false, reason: 'manual' };
  }
  function quotaState(q) {
    var a = q.daily_gb > 0 ? q.used_today / (q.daily_gb * GB) : 0, b = q.monthly_gb > 0 ? q.used_month / (q.monthly_gb * GB) : 0;
    var p = Math.max(a, b);
    return { state: p >= 1 ? 'exceeded' : p >= 0.8 ? 'warn' : 'ok', period: p >= 1 ? (a >= 1 ? 'daily' : 'monthly') : '' };
  }

  /* 速率随机游走: 围绕基准值上下浮动, 偶尔冲高; 受限速 / 封锁 / 时段断网约束 */
  var lastStep = 0, LOAD = 1;   // LOAD: 全体共用的负载系数(慢变), 让顶部总速率和曲线有明显起伏
  function stepRates() {
    var t = Date.now(); if (t - lastStep < 650) return;
    var dt = lastStep ? Math.min(5, (t - lastStep) / 1000) : 1; lastStep = t;
    LOAD = lim(LOAD + (1 - LOAD) * 0.08 + (Math.random() - 0.5) * 0.22, 0.45, 1.5);
    DEVS.forEach(function (d) {
      for (var i = 0; i < 2; i++) {
        d.k[i] += (1 - d.k[i]) * 0.2 + (Math.random() - 0.5) * 0.45;
        if (Math.random() < 0.05) d.k[i] *= rnd(1.3, 1.9);
        d.k[i] = lim(d.k[i], 0.25, 2.3);
      }
      var e = effective(d), rx = d.base[0] * d.k[0] * LOAD, tx = d.base[1] * d.k[1] * LOAD;
      if (!d.online || e.blocked) rx = tx = 0;
      if (e.down_mbps > 0) rx = Math.min(rx, e.down_mbps * 125000 * rnd(0.9, 0.97));
      if (e.up_mbps > 0) tx = Math.min(tx, e.up_mbps * 125000 * rnd(0.9, 0.97));
      d.cur = [round(rx), round(tx)];
      d.rx_bytes += rx * dt; d.tx_bytes += tx * dt;
    });
  }
  function liveApps(d) {
    if (!d.online || !d.live.length) return [];
    var tot = d.cur[0] + d.cur[1];
    return d.live.map(function (x) {
      var c = appCat(x[0]);
      return { id: x[0], name: appName(x[0]), category: c, bps: round(tot * x[1] * rnd(0.88, 1.12)), share: x[1], system: /^system|cloud/.test(c) };
    }).filter(function (a) { return a.bps > 0; }).sort(function (a, b) { return b.bps - a.bps; });
  }
  function devRow(d) {
    var e = effective(d), t = now();
    var r = {
      mac: d.mac, ip: d.ip, hostname: d.hostname, hostname_src: d.hostname_src, vendor: d.vendor, iface: IFACE,
      status: d.status, online: d.online, last_seen: d.online ? t - 1 - (hashStr(d.mac) % 3) : d.last_seen,
      rx_bps: d.online ? d.cur[0] : 0, tx_bps: d.online ? d.cur[1] : 0, rx_bytes: round(d.rx_bytes), tx_bytes: round(d.tx_bytes),
      randomized_mac: !!d.randomized_mac, mark_id: d.mark_id,
      limit_enabled: d.limit_enabled !== false && (d.down_mbps > 0 || d.up_mbps > 0), down_mbps: d.down_mbps, up_mbps: d.up_mbps,
      delay_enabled: d.delay_ms > 0 || d.jitter_ms > 0 || d.loss_pct > 0, delay_ms: d.delay_ms, jitter_ms: d.jitter_ms, loss_pct: d.loss_pct,
      sqm_enabled: !!d.sqm_enabled, whitelist: !!d.whitelist, app_qos: !!d.app_qos,
      ident: d.ident || null, effective: e,
      quota: null, schedule: null,
      dpi_apps: d.hist.slice(0, 5).map(function (id, i) { return { id: id, name: appName(id), category: appCat(id), confidence: i < 3 ? 'high' : 'med', count: 40 - i * 7 }; }),
      live_apps: liveApps(d)
    };
    if (d.online && d.fg) r.fg = d.fg;
    if (d.online && d.traffic_type) r.traffic_type = d.traffic_type;
    if (d.online && d.live_call) r.live_call = d.live_call;
    if (d.vpn) r.vpn = d.vpn;
    if (d.merge_suggestion) r.merge_suggestion = d.merge_suggestion;
    if (d.quota) { var qs = quotaState(d.quota); r.quota = Object.assign({}, d.quota, { state: qs.state, exceeded_period: qs.period, applied: e.reason === 'quota', month_start: Math.floor(new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime() / 1000) }); }
    if (d.schedule) r.schedule = { windows: d.schedule.windows, active_window_index: schedIdx(d) };
    if (d.app_time_limits.length) r.app_time_limits = d.app_time_limits;
    if (d.category_blocks.length) r.category_blocks = d.category_blocks;
    return r;
  }
  function ipNum(ip) { var a = String(ip).split('.'); return a.length === 4 ? ((+a[0]) * 16777216 + (+a[1]) * 65536 + (+a[2]) * 256 + (+a[3])) : 0; }
  function devSig() {
    return hashStr(DEVS.map(function (d) {
      return [d.mac, d.ip, d.online, d.status, d.down_mbps, d.up_mbps, d.delay_ms, d.jitter_ms, d.loss_pct, d.sqm_enabled, d.whitelist, d.app_qos, d.hostname,
        JSON.stringify(d.quota || ''), JSON.stringify(d.schedule || ''), JSON.stringify(d.app_time_limits), JSON.stringify(d.category_blocks), d.merge_suggestion ? 1 : 0, schedIdx(d)].join('|');
    }).join('#')).toString(16) + 'c0ffee';
  }
  function devicesPayload() {
    stepRates();
    var rows = DEVS.slice().sort(function (a, b) { return ipNum(a.ip) - ipNum(b.ip); }).map(devRow);
    return { devices: rows, whitelist_mode: CFG.whitelist_mode, remote_enabled: CFG.remote_enabled, hotspot_active: true, hotspot_iface: IFACE, hotspot_ip: GW, devices_sig: devSig() };
  }
  function liveSummary() {
    stepRates();
    var on = 0, rx = 0, tx = 0;
    DEVS.forEach(function (d) { if (d.online) { on++; rx += d.cur[0]; tx += d.cur[1]; } });
    return { hotspot_active: true, iface: IFACE, hotspot_iface: IFACE, hotspot_ip: GW, iface_method: 'tethering', online: on, total: DEVS.length,
      rx_bps: rx, tx_bps: tx, devices_sig: devSig(), backend_version: VER, backend_version_code: VCODE, autorate: AUTORATE };
  }

  /* ═════════════ 配置 / 告警 / 模板 等全局状态 ═════════════ */
  var CFG = {
    auth_required: true, remote_auth_required: true, whitelist_mode: false, remote_enabled: true, hotspot_autostart: true, hotspot_ssid: 'HNC-Demo-5G', hotspot_delay_sec: 30,
    hotspot_time_enable: false, hotspot_time_start: '07:00', hotspot_time_end: '23:30', hotspot_charging_only: false, hotspot_iface: '',
    global_shaper_enabled: false, global_shaper_down: '', global_shaper_up: '', flywheel_exclude_user: ['com.example.proxyclient'],
    clsact_bpf_mode: 'auto', tc_leaf_aqm: 'auto', stale_rule_ttl_days: 30, quic_block: false, discover_cert_probe: true,
    conn_block_dns_layer: 'available', sim_enabled: false,
    offload_guard: { mode: 'auto', offload_state: 'IDLE', fallback_active: false, since: 0, detail: '加速通道存在，但当前没有转发热点流量', last_check: T - 42, slowpath: 'n/a', clsact: 'off', iface: IFACE },
    webui_access: { mode: 'all', macs: [], port: 8443, firewall: 'applied mode=all entries=0 v4=ok v6=ok' }
  };
  var ALERT_CFG = {
    enabled: true,
    unknown_device: { enabled: true, quiet_hour_start: 23, quiet_hour_end: 7, min_interval_sec: 1800 },
    anomaly_traffic: { enabled: true, ratio_threshold: 3, min_bytes: 50 * MB },
    monthly_quota: { enabled: true, limit_bytes: 15 * GB, warn_at_pct: 80 }
  };
  var ALERTS = [
    { id: 'unknown_device_d26e4a8c15f3_' + (T - T % 3600), ts: T - 6 * 60, kind: 'unknown_device', mac: 'd2:6e:4a:8c:15:f3', ip: '192.168.43.96', detail: '新设备接入：没有上报主机名 · 随机 MAC', extra: { hostname: '' }, seen: false },
    { id: 'app_time_warn_1e52a80c773d_douyin_' + ymd(dayAt(0)), ts: T - 14 * 60, kind: 'app_time_warn', mac: '1e:52:a8:0c:77:3d', detail: '「抖音」今天已用 52 分钟，上限 60 分钟', extra: { app_id: 'douyin', app_name: '抖音', minutes: 60, used_sec: 3120 }, seen: false },
    { id: 'anomaly_traffic_5e20b73ac418_' + (T - T % 3600 - 7200), ts: T - 2 * 3600 - 300, kind: 'anomaly_traffic', mac: '5e:20:b7:3a:c4:18', detail: '这一小时 3.2 GB，是近 7 天同时段平均的 4.6 倍（在下载游戏更新）', seen: true }
  ];
  var TPL = {
    '视频会议': { down_mbps: 40, up_mbps: 16, delay_ms: 0, jitter_ms: 0, loss_pct: 0 },
    '孩子模式': { down_mbps: 16, up_mbps: 4, delay_ms: 0, jitter_ms: 0, loss_pct: 0 },
    '游戏限流': { down_mbps: 80, up_mbps: 80, delay_ms: 20, jitter_ms: 5, loss_pct: 0 },
    '弱网测试': { down_mbps: 8, up_mbps: 4, delay_ms: 200, jitter_ms: 50, loss_pct: 3 }
  };
  var APP_LIMITS = [
    { mac: '6a:0e:55:b1:9c:42', app_id: 'iqiyi', down_mbps: 24, ips_total: 14, ips_shared_skipped: 2, ips_limited: 12 },
    { mac: '1e:52:a8:0c:77:3d', app_id: 'bilibili', down_mbps: 8, ips_total: 9, ips_shared_skipped: 3, ips_limited: 6 }
  ];
  var APP_LIMIT_SHARED = false;
  var ENC = { policy: 'dot', devices: {} };
  var MOCK_SIGNAL = { available: true, mode: 'cellular', rat: '5G SA', display_rat: '5G-A', is_5ga: true, slot: 1, sub_id: 1, carrier: '中国移动', carrier_short: '移动', mcc_mnc: '46000', sharing_mode: '2.6GHz+700MHz 移广双载波共享', upstream_iface: 'rmnet_data2', band: 'n41', bandwidth_mhz: 100, band_combo: 'n41+n28', total_bw_mhz: 130, ca_count: 2, arfcn: 504990, freq_mhz: 2600, band_trait: '5G-A 高低频黄金双载波聚合 n41+n28（总带宽 130MHz） · 兼顾 2.6GHz 极速大带宽与 700MHz 强穿墙稳上行', rsrp_dbm: -84, rsrq_db: -8, sinr_db: 21, rsrp_label: '极强', sinr_label: '极纯净', rsrq_label: '基站空闲', speed_potential_pct: 100, speed_potential_text: '可跑满套餐峰值', bars: 4, quality: 'excellent', quality_cn: '5G-A 极佳', rf_ceiling_factor: 1.0, diagnosis: 'ok', diagnosis_cn: '5G-A 多载波通道（n41+n28）信号纯净、基站空闲，热点可跑满高速带宽', updated_at: T };
  var PU_CFG = { billing_day: 1, warn_percent: 80, plan_sim1_gb: 100, plan_sim2_gb: 0, anchor_sim1_gb: 0, anchor_sim2_gb: 0, use_netstats: 'auto' };
  var SELF_ON = { toggle: true, auto_expand: true, auto_promote: false };
  var DNS = { enabled: false, block_mode: 'nxdomain', log_queries: false };
  var FG_ENGINE = 'classic';
  var SIM = { enabled: false, devices: [] };
  var REC_STATE = { recording: false, minutes: 10, started_at: 0 };
  var ALIASES = { 'ce:41:7a:09:3b:62': '0a:7f:3c:41:9e:21' };
  var MERGE_DONE = {};
  var FP_RULES = [
    { id: 'fp-u1', kind: 'domain', value: 'xhscdn.net', app_id: 'xiaohongshu', app_name: '小红书' },
    { id: 'fp-u2', kind: 'ip', value: '203.0.113.77', app_id: 'nintendo_online', app_name: 'Nintendo Switch Online', expires: T + 5 * 86400 }
  ];
  var EXPORTS = [
    { name: 'hnc-export-' + ymd(dayAt(1)) + '-213015.zip', size: 482133, modified: ymdDash(dayAt(1)) + 'T21:30:15+08:00' },
    { name: 'hnc-export-' + ymd(dayAt(4)) + '-090244.zip', size: 1268840, modified: ymdDash(dayAt(4)) + 'T09:02:44+08:00' }
  ];
  var TOKENS = [
    { token_id: '7f3a9c21d0e84b6f', label: '书房 MacBook · Safari', ip_hint: '192.168.43.31', last_seen: T - 320 },
    { token_id: 'c41e08b9a27d5f13', label: 'iPad Air · Safari', ip_hint: '192.168.43.45', last_seen: T - 2 * 86400 }
  ];
  var CANDS = [
    { apex: 'xhscdn.net', tier: 'high', uid: '10288', app: '小红书', hits: 46, windows: 7 },
    { apex: 'meituan.net', tier: 'med', uid: '10316', app: '美团', hits: 19, windows: 4 },
    { apex: 'zijieapi.com', tier: 'high', uid: '10234', app: '抖音', hits: 88, windows: 12, promoted: true },
    { apex: 'alicdn.com', tier: 'shared', hits: 212, windows: 31 }
  ];
  var DISC = {
    groups: [
      { id: 'g-dewu', hits: 138, suffixes: ['dewu.com', 'poizon.com', 'dewucdn.com'], devices: ['0a:7f:3c:41:9e:21', 'd2:6e:4a:8c:15:f3'], last_seen: T - 420,
        guess: { name: '得物', src: 'apk', conf: 'high' }, company: '上海识装信息科技有限公司',
        suggest: { name: '得物', conf: 'high', sources: [{ src: 'apk', name: '得物', basis: '本机安装包里含 dewu.com、poizon.com' }, { src: 'cert', name: '得物', basis: '证书组织：上海识装信息科技有限公司' }] },
        apk: [{ label: '得物', pkg: 'com.shizhuang.duapp', suffixes: ['dewu.com', 'poizon.com'] }],
        cert: { org: 'Shanghai Shizhuang Information Technology Co., Ltd.', issuer: 'GlobalSign RSA OV SSL CA 2018', sans: ['*.dewu.com', '*.poizon.com', 'dewu.com', 'poizon.com'] },
        family_name: 'OkHttp', family_conf: 0.82, ja4: [{ ja4: 't13d1516h2_8daaf6152771_02713d6af862', count: 41 }],
        domains: [{ name: 'app.dewu.com', count: 64 }, { name: 'cdn.poizon.com', count: 41 }, { name: 'h5static.dewucdn.com', count: 33 }],
        shared: [{ suffix: 'alicdn.com', label: '阿里云 CDN', reason: 'freq' }] },
      { id: 'g-fanqie', hits: 57, suffixes: ['fqnovel.com', 'snssdk-novel.com'], devices: ['1e:52:a8:0c:77:3d'], last_seen: T - 3600,
        guess: { name: '番茄小说', src: 'cert', conf: 'medium' },
        suggest: { name: '番茄小说', conf: 'medium', sources: [{ src: 'cert', name: '番茄小说', basis: '证书里同时签了 fqnovel.com' }, { src: 'ja4', name: '字节系应用', basis: '网络指纹属于字节系 Cronet 网络库' }] },
        cert: { org: 'Beijing Douyin Information Service Co., Ltd.', issuer: 'GeoTrust CN RSA CA G1', sans: ['*.fqnovel.com', '*.snssdk-novel.com'] },
        family_name: 'Cronet', family_conf: 0.74, ja4: ['t13d1517h2_5b57614c22b0_3d5424432f57'],
        domains: [{ name: 'api.fqnovel.com', count: 31 }, { name: 'p3-novel.snssdk-novel.com', count: 26 }] },
      { id: 'g-svcgw', hits: 23, suffixes: ['svc-gw.cn'], devices: ['a6:5b:0f:93:7e:24'], last_seen: T - 5400,
        guess: { name: 'svc-gw.cn', src: 'domain', conf: 'low' }, suggest: {},
        domains: [{ name: 'u3.svc-gw.cn', count: 23 }] }
    ],
    apk_scan: { app_count: 214, generated_at: T - 5 * 3600 }, cert_probe: true, ignored: [{ id: 'g-old1', suffixes: ['adtrack-xx.cn'], gone: true }],
    user_rules: [{ id: 'user_kuaikan', app: '快看漫画', category: 'reading', suffixes: ['kkmh.com', 'kuaikanmanhua.com'] }]
  };
  var SC_AT = T - 3 * 3600 - 1200;

  /* ═════════════ 流量统计(确定性: 按日期生成, 同一天每次一样) ═════════════ */
  var HW = [.22, .12, .08, .06, .05, .07, .14, .32, .5, .58, .62, .68, .8, .7, .62, .66, .78, .95, 1.25, 1.55, 1.75, 1.6, 1.15, .55];
  var HWS = HW.reduce(function (a, b) { return a + b; }, 0);
  function dayStat(off) {
    var d = dayAt(off), r = srand('hnc-day-' + ymd(d)), wk = d.getDay() === 0 || d.getDay() === 6;
    var full = { hs: (3.8 + r() * 2.8) * (wk ? 1.3 : 1) * GB, lc: (0.6 + r() * 0.8) * GB, lw: (0.12 + r() * 0.45) * GB };
    var c = new Date(), ch = c.getHours(), cf = (c.getMinutes() * 60 + c.getSeconds()) / 3600;
    var o = { d: d, hs: 0, lc: 0, lw: 0, h: [] };
    for (var h = 0; h < 24; h++) {
      var k = off > 0 || h < ch ? 1 : h === ch ? cf : 0, s = HW[h] / HWS * (0.8 + r() * 0.4) * k;
      var x = { hs: full.hs * s, lc: full.lc * s, lw: full.lw * s };
      o.h.push(x); o.hs += x.hs; o.lc += x.lc; o.lw += x.lw;
    }
    return o;
  }
  function statsRange(range) {
    if (range === 'today') return dayStat(0).h.map(function (x, i) { return { label: p2(i) + ':00', rx: round(x.hs * 0.93), tx: round(x.hs * 0.07) }; });
    var n = range === 'week' ? 7 : range === 'all' ? 90 : 30, out = [];
    for (var off = n - 1; off >= 0; off--) { var s = dayStat(off); out.push({ label: mdDash(s.d), rx: round(s.hs * 0.93), tx: round(s.hs * 0.07) }); }
    return out;
  }
  function sumDays(n, k) { var t = 0; for (var i = 0; i < n; i++) t += dayStat(i)[k || 'hs']; return t; }
  var SHARE = [['iqiyi', .19], ['douyin', .16], ['nintendo_eshop', .11], ['bilibili', .085], ['_unknown', .065], ['xiaomi_store', .055], ['genshin', .05],
    ['wechat', .045], ['_tunnel', .042], ['honor_of_kings', .035], ['tencent_meeting', .03], ['windows_update', .028], ['xiaohongshu', .024], ['tencent_video', .02],
    ['icloud', .012], ['_local', .011], ['qqmusic', .01], ['feishu', .008], ['amap', .006], ['taobao', .005], ['kuaishou', .004]];
  var ACT_H = { douyin: 2.4, iqiyi: 2.1, bilibili: 1.3, honor_of_kings: 1.1, genshin: 0.8, wechat: 3.2, tencent_meeting: 0.9, xiaohongshu: 0.7, qqmusic: 5.5,
    nintendo_eshop: 0.6, nintendo_online: 0.9, xiaomi_store: 0.3, amap: 0.2, tencent_video: 0.4, feishu: 1.6, taobao: 0.3, kuaishou: 0.4, teams: 1.2 };
  function dayFrac() { var c = new Date(); return Math.max(0.05, (c.getHours() * 3600 + c.getMinutes() * 60) / 86400); }
  function appUsage(days) {
    var tot = sumDays(days), r = srand('au' + days + ymd(dayAt(0))), act = days === 1 ? dayFrac() : days - 1 + dayFrac();
    var apps = SHARE.map(function (x) {
      var v = tot * x[1] * (0.85 + r() * 0.3), up = x[0] === 'tencent_meeting' || x[0] === '_tunnel' ? 0.35 : x[0] === 'icloud' ? 0.4 : 0.06;
      var o = { id: x[0], name: appName(x[0]), category: appCat(x[0]), up: round(v * up), down: round(v * (1 - up)) };
      if (ACT_H[x[0]]) o.active_sec = round(ACT_H[x[0]] * 3600 * act * (0.8 + r() * 0.4));
      if (x[0] === 'wechat' || x[0] === 'douyin') o.inferred_bytes = round(v * 0.04);
      return o;
    }).sort(function (a, b) { return (b.up + b.down) - (a.up + a.down); });
    var out = { ok: true, days: days, readable: true, acct: true, by_app: apps, total_up: 0, total_down: 0, inferred_bytes: 0 };
    apps.forEach(function (a) { out.total_up += a.up; out.total_down += a.down; out.inferred_bytes += a.inferred_bytes || 0; });
    if (days === 1) out.by_hour = dayStat(0).h.map(function (x, i) { return { h: i, up: round(x.hs * 0.07), down: round(x.hs * 0.93) }; });
    return out;
  }
  function dpiHistory(days, mac) {
    var share = 1, d = mac ? dev(mac) : null;
    if (d) share = Math.max(0.002, d.usage8 / (48 * GB));
    var by = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (var i = 0; i < days; i++) dayStat(i).h.forEach(function (x, h) { by[h] += x.hs * share * 0.86; });
    var tot = by.reduce(function (a, b) { return a + b; }, 0), r = srand('dh' + days + (mac || ''));
    var list = d ? d.hist.map(function (id, i) { return [id, [0.5, 0.25, 0.12, 0.08, 0.05][i] || 0.03]; }) : SHARE.filter(function (x) { return x[0].charAt(0) !== '_'; });
    return {
      ok: true, generated_at: now(), days_requested: days, window_start: ymdDash(dayAt(days - 1)), window_end: ymdDash(dayAt(0)), sample_count: 96 * days - 3,
      total_rx: round(tot * 0.93), total_tx: round(tot * 0.07),
      by_app: list.map(function (x) { var v = tot * x[1] * (0.85 + r() * 0.3); return { app_id: x[0], name: appName(x[0]), cat: appCat(x[0]), rx: round(v * 0.93), tx: round(v * 0.07) }; }),
      by_hour: by.map(function (v, h) { return { hour: h, rx: round(v * 0.93), tx: round(v * 0.07) }; })
    };
  }
  function dpiUnknown(days) {
    var tot = sumDays(days) * 0.065;
    var items = [['svc-gw.cn', 'domain', 'u3.svc-gw.cn', .21, ['a6:5b:0f:93:7e:24']], ['203.0.113.42', 'ip', '', .16, ['5e:20:b7:3a:c4:18']], ['dewucdn.com', 'domain', 'h5static.dewucdn.com', .12, ['0a:7f:3c:41:9e:21', 'd2:6e:4a:8c:15:f3']],
      ['fqnovel.com', 'domain', 'api.fqnovel.com', .09, ['1e:52:a8:0c:77:3d']], ['198.51.100.23', 'ip', '', .07, ['6a:0e:55:b1:9c:42']], ['tuiaimg.com', 'domain', 'yun.tuiaimg.com', .05, ['1e:52:a8:0c:77:3d', '0a:7f:3c:41:9e:21']],
      ['hixiaoyu.cn', 'domain', 'static.hixiaoyu.cn', .04, ['7e:c4:19:20:5a:8b']]];
    return { ok: true, days: days, cap_per_day: 300, total_unknown_bytes: round(tot), tunnel_bytes: round(sumDays(days) * 0.042), inferred_bytes: round(sumDays(days) * 0.009),
      items: items.map(function (x) { return { name_or_ip: x[0], kind: x[1], sample: x[2] || x[0], bytes: round(tot * x[3]), devices: x[4].length, macs: x[4] }; }) };
  }

  /* ═════════════ 本机 / 热点月流量 ═════════════ */
  function cycleStart() {
    var bd = PU_CFG.billing_day, t = new Date(), y = t.getFullYear(), m = t.getMonth();
    if (t.getDate() < bd) m -= 1;
    return new Date(y, m, bd);
  }
  function phoneUsage(period) {
    var cs = cycleStart(), ce = new Date(cs.getFullYear(), cs.getMonth() + 1, cs.getDate()), today0 = dayAt(0);
    var cycDays = Math.round((today0 - cs) / 86400000) + 1;
    var n = period === 'today' ? 1 : period === '7d' ? 7 : period === '30d' ? 30 : cycDays;
    var days = [], i, tot = { hs: 0, lc: 0, lw: 0 }, cyc = 0;
    for (i = n - 1; i >= 0; i--) { var s = dayStat(i); days.push(s); tot.hs += s.hs; tot.lc += s.lc; tot.lw += s.lw; }
    for (i = 0; i < cycDays; i++) { var s2 = dayStat(i); cyc += s2.hs + s2.lc; }
    var trio = function (v, up) { return { rx: round(v * (1 - up)), tx: round(v * up), total: round(v) }; };
    var cell = tot.hs + tot.lc, sim2c = 0.31 * GB * Math.min(1, cycDays / 3), plan1 = PU_CFG.plan_sim1_gb * GB, plan2 = PU_CFG.plan_sim2_gb * GB;
    var r = {
      period: period, since: Math.floor((period === 'cycle' || period === 'month' ? cs : dayAt(n - 1)).getTime() / 1000), until: now(),
      billing_day: PU_CFG.billing_day, cycle_start: Math.floor(cs.getTime() / 1000), cycle_end: Math.floor(ce.getTime() / 1000), config: clone(PU_CFG),
      totals: { cellular: trio(cell, 0.08), wifi: trio(tot.lw, 0.1), hotspot: trio(tot.hs, 0.07), local: trio(tot.lc + tot.lw, 0.1) },
      hotspot_via: { cell: trio(tot.hs, 0.07), wifi: trio(0, 0), unknown: trio(0, 0) },
      by_sim: [
        { slot: 1, carrier: '中国移动', carriers: ['中国移动'], total: round(cell), rx: round(cell * 0.92), tx: round(cell * 0.08), local_rx: round(tot.lc * 0.9), local_tx: round(tot.lc * 0.1),
          hotspot_total: round(tot.hs), cycle_used: round(cyc), netstats_cycle_used: round(cyc * 1.013), plan_bytes: plan1, used_pct: plan1 ? cyc / plan1 * 100 : null, is_default_data: true },
        { slot: 2, carrier: '中国联通', carriers: ['中国联通'], total: period === 'today' ? 0 : round(sim2c), rx: round(sim2c * 0.9), tx: round(sim2c * 0.1), local_rx: 0, local_tx: 0,
          hotspot_total: 0, cycle_used: round(sim2c), netstats_cycle_used: round(sim2c * 1.02), plan_bytes: plan2, used_pct: plan2 ? sim2c / plan2 * 100 : null, is_default_data: false }
      ],
      by_day: days.map(function (s) { return { date: ymdDash(s.d), cell: round(s.hs + s.lc), wifi: round(s.lw), hotspot: round(s.hs), local: round(s.lc + s.lw) }; }),
      default_sim: { slot: 1, carrier: '中国移动', sub_id: 1 },
      sources: { sim_detect: 'ok', sim_source: 'settings', hotspot_iface: IFACE, upstream: 'cell', counters: '/proc/net/dev', last_sample: now() - 37 },
      primary_source: PU_CFG.use_netstats === 'prefer' ? 'netstats' : 'hnc',
      calibration: PU_CFG.use_netstats === 'off' ? { status: 'unavailable', reason: 'disabled' } :
        { status: 'ok', hnc_vs_netstats_pct: -1.3, checked_at: now() - 1500, netstats_cell_by_sim: [{ slot: 1, hnc_vs_netstats_pct: -1.3 }, { slot: 2, hnc_vs_netstats_pct: -2 }], text_cn: [] }
    };
    if (period === 'today') r.by_hour = dayStat(0).h.map(function (x, h) { return { h: h, cell: round(x.hs + x.lc), wifi: round(x.lw), hotspot: round(x.hs), local: round(x.lc + x.lw) }; });
    return r;
  }

  /* ═════════════ 实时连接 ═════════════ */
  function devConns(d) {
    stepRates();
    var t = now(), list = [], tot = d.online ? d.cur[0] + d.cur[1] : 0, rxShare = tot ? d.cur[0] / tot : 0.9;
    var mk = function (o) { list.push(o); return o; };
    d.live.forEach(function (x) {
      var id = x[0], doms = APP[id] ? APP[id][2] : [], cat = appCat(id), udp = cat === 'game' || id === 'tencent_meeting';
      if (id === '_tunnel') {
        mk({ proto: 'udp', dst: '203.0.113.18', dport: 51820, sport: 51820, name: '', svc: 'WireGuard', app: 'VPN/代理隧道', app_id: '_tunnel', w: x[1], bytes: 380 * MB });
        return;
      }
      doms.forEach(function (dm, j) {
        var u = udp && j === 0;
        mk({ proto: u ? 'udp' : 'tcp', dst: fakeIp(dm), dport: u ? (id === 'tencent_meeting' ? 8000 : 10012) : 443, sport: 32000 + hashStr(d.mac + dm) % 28000, name: dm, svc: u ? '' : 'HTTPS',
          state: u ? '' : 'ESTABLISHED', app: appName(id), app_id: id, app_src: id === 'xiaohongshu' && j === 1 ? 'fp' : 'rule', app_conf: id === 'xiaohongshu' && j === 1 ? 0.86 : undefined,
          w: x[1] * (j === 0 ? 0.72 : 0.28 / Math.max(1, doms.length - 1)), bytes: (20 + hashStr(dm) % 400) * MB * (j === 0 ? 1 : 0.2) });
      });
    });
    d.hist.forEach(function (id) {
      if (d.live.some(function (x) { return x[0] === id; }) || !APP[id] || !APP[id][2].length) return;
      var dm = APP[id][2][0];
      mk({ proto: 'tcp', dst: fakeIp(dm), dport: 443, sport: 30000 + hashStr(d.mac + dm) % 30000, name: dm, svc: 'HTTPS', state: 'ESTABLISHED', app: appName(id), app_id: id, app_src: 'rule', w: 0, bytes: (2 + hashStr(dm) % 30) * MB });
    });
    mk({ proto: 'tcp', dst: fakeIp(d.mac + 'own'), dport: 443, sport: 41000 + hashStr(d.mac) % 9000, name: '', svc: 'HTTPS', state: 'ESTABLISHED', owner: { name: '阿里云' }, w: 0.02, bytes: 3.4 * MB });
    mk({ proto: 'udp', dst: GW, dport: 53, sport: 30000 + hashStr(d.mac + 'dns') % 20000, name: '', svc: 'DNS', local: true, w: 0.002, bytes: 180 * KB });
    d.blocks.forEach(function (b) {
      if (b.kind !== 'domain') return;
      mk({ proto: 'tcp', dst: fakeIp(b.value), dport: 443, sport: 50000 + hashStr(b.value) % 9000, name: 'api.' + b.value, svc: 'HTTPS', state: 'SYN_SENT', unreplied: true, blocked: true,
        app: b.label || '', app_id: '', w: 0, bytes: 0 });
    });
    var bps = 0, dn = 0, up = 0, groups = {};
    list.forEach(function (c) {
      var v = d.online ? tot * c.w * rnd(0.8, 1.2) : 0; delete c.w;
      c.down_bps = round(v * rxShare); c.up_bps = round(v * (1 - rxShare));
      c.down_bytes = round(c.bytes * 0.93); c.up_bytes = round(c.bytes * 0.07); delete c.bytes;
      if (c.app_conf === undefined) delete c.app_conf;
      bps += c.down_bps + c.up_bps; dn += c.down_bytes; up += c.up_bytes;
      var g = c.app || (c.local ? '局域网' : '未识别'); groups[g] = groups[g] || { label: g, n: 0, bytes: 0, bps: 0 };
      groups[g].n++; groups[g].bytes += c.down_bytes + c.up_bytes; groups[g].bps += c.down_bps + c.up_bps;
    });
    list.sort(function (a, b) { return (b.down_bps + b.up_bps) - (a.down_bps + a.up_bps) || (b.down_bytes - a.down_bytes); });
    return {
      ok: true, mac: d.mac, ts: t, readable: true, acct: true, total: list.length, conns: list, bps: bps, down_bytes: dn, up_bytes: up,
      groups: Object.keys(groups).map(function (k) { return groups[k]; }).sort(function (a, b) { return b.bps - a.bps || b.bytes - a.bytes; }),
      blocks: d.blocks
    };
  }
  function connCounts() {
    var c = {};
    DEVS.forEach(function (d) { if (d.online) { var r = devConns(d); c[d.mac] = { n: r.total + 3 + hashStr(d.mac) % 9, bps: r.bps }; } });
    return { ok: true, counts: c, readable: true, acct: true };
  }

  /* ═════════════ DPI 状态(dpid) + 本机应用归因 ═════════════ */
  var DPI_UP0 = 7 * 3600 + 23 * 60;
  function selfState() {
    var t = now(), up = (Date.now() - PAGE_T0) / 1000;
    var A = [
      ['10234', 'com.ss.android.ugc.aweme', '抖音', 6, 412, 1.24 * GB, ['v26-dy.douyinvod.com', 'api5-normal-lq.amemv.com', 'p26-sign.douyinpic.com'], ['douyin'], { douyin: 388 }],
      ['10198', 'com.tencent.mm', '微信', 9, 1286, 412 * MB, ['szextshort.weixin.qq.com', 'mmsns.qpic.cn', 'wx.qlogo.cn', 'dns.weixin.qq.com'], ['wechat'], { wechat: 1204 }],
      ['10311', 'tv.danmaku.bili', 'B站', 3, 201, 655 * MB, ['upos-sz-mirrorcos.bilivideo.com', 'api.bilibili.com'], ['bilibili'], { bilibili: 190 }],
      ['10287', 'com.autonavi.minimap', '高德地图', 2, 96, 38 * MB, ['m5.amap.com', 'webrd01.is.autonavi.com'], ['amap'], { amap: 91 }],
      ['10342', 'com.taobao.taobao', '淘宝', 0, 154, 96 * MB, ['acs.m.taobao.com', 'gw.alicdn.com'], ['taobao'], { taobao: 6 }],
      ['10405', 'com.tencent.tmgp.sgame', '王者荣耀', 1, 58, 210 * MB, ['pvp.qq.com', 'gamesafe.qq.com'], ['honor_of_kings'], { honor_of_kings: 52 }],
      ['10377', 'com.netease.cloudmusic', '网易云音乐', 1, 33, 74 * MB, ['interface.music.163.com'], ['netease_music'], { netease_music: 29 }],
      ['10420', 'com.example.proxyclient', '代理客户端', 1, 12, 156 * MB, [], [], {}, true],
      ['1000', 'android', 'Android 系统', 2, 640, 22 * MB, ['connectivitycheck.gstatic.com', 'time.android.com'], [], {}, false, true],
      ['10045', 'com.heytap.market', '软件商店', 0, 41, 180 * MB, ['api-cn.store.heytapmobi.com'], [], {}, false, true],
      ['10052', 'com.coloros.weather.service', '天气', 0, 19, 3 * MB, ['weather.heytapmobi.com'], [], {}, false, true]
    ];
    var apps = {};
    A.forEach(function (x, i) {
      apps[x[0]] = { uid: +x[0], pkg: x[1], display_name: x[2], active_conns: x[3], total_conns: x[4], rx_bytes: round(x[5] * 0.92), tx_bytes: round(x[5] * 0.08),
        first_seen: t - 6 * 3600, last_seen: x[3] ? t - 3 : t - 600 * (i + 1), top_snis: x[6], top_rules: x[7], rule_hit_counts: x[8], flywheel_excluded: !!x[9], is_system: !!x[10] };
    });
    return {
      enabled: SELF_ON.toggle, reason: SELF_ON.toggle ? '' : '用户关闭', last_attrib_tick: t - 4, app_label_source: 'pm_live', live_label_count: 186, byte_sampler_source: 'bpf_map',
      interfaces: [{ name: 'rmnet_data2', started_at: t - DPI_UP0, restarts: 0, packets: round(410000 + up * 120), tls_events: round(5120 + up * 0.6), dns_events: round(8300 + up * 0.9) },
        { name: 'wlan0', started_at: t - DPI_UP0, restarts: 1, packets: round(32000 + up * 8), tls_events: round(410 + up * 0.05), dns_events: round(820 + up * 0.1) }],
      apps_by_uid: SELF_ON.toggle ? apps : {}, unknown_conns: 4, pkg_cache_size: 214,
      unmatched_snis_pending: 3, unmatched_sni_samples: ['cfg.taptapdada.com', 'sdk.tuiaimg.com', 'api.huoshan-gw.net'],
      candidate_pending: CANDS.filter(function (c) { return !c.promoted && c.tier !== 'shared'; }).length,
      candidate_high: CANDS.filter(function (c) { return c.tier === 'high' && !c.promoted; }).length, candidate_samples: CANDS, auto_promote_on: SELF_ON.auto_promote
    };
  }
  var PAGE_T0 = Date.now();
  function dpiState() {
    stepRates();
    var t = now(), up = DPI_UP0 + (Date.now() - PAGE_T0) / 1000;
    var stats = { packets: round(up * 942 + 3100 * Math.sin(up / 37)), dns_events: round(up * 3.1 + 40 * Math.sin(up / 23)), tls_events: round(up * 2.2 + 30 * Math.sin(up / 29)),
      kernel_drops: round(up * 0.004 + 3 * Math.sin(up / 41) + 3), bytes: round(up * 9.5 * MB) };
    var clients = {};
    DEVS.forEach(function (d) {
      if (!d.online && t - d.last_seen > 86400) return;
      var top = d.hist.map(function (id, i) { return { id: id, name: appName(id), category: appCat(id), confidence: i < 2 ? 'high' : i < 4 ? 'med' : 'low', count: 60 - i * 9 }; });
      var doms = []; d.hist.forEach(function (id) { (APP[id] ? APP[id][2] : []).forEach(function (x) { doms.push(x); }); });
      var r = srand('cl' + d.mac);
      clients[d.mac] = {
        client_mac: d.mac, client_ip: d.ip, client_ips: [d.ip, '2408:8456:3c10:9a2:' + d.mac.slice(-5).replace(':', '') + ':1'], last_seen: d.online ? t - 2 : d.last_seen, last_hostname: d.hostname || '',
        dns_events: round(300 + r() * 2400), tls_events: round(200 + r() * 1800), rx_bytes: round(d.usage8 / 8 * 0.93), tx_bytes: round(d.usage8 / 8 * 0.07), last_sni: doms[0] || '',
        top_apps: top, top_hostnames: doms.slice(0, 6).map(function (x, i) { return { name: x, count: 120 - i * 15 }; }), top_sni: doms.slice(0, 4).map(function (x, i) { return { name: x, count: 80 - i * 12 }; })
      };
    });
    var idb = 0.89;
    return {
      available: true,
      state: {
        schema_version: 3, generated_at: t - 2, version: VER, mode: 'af_packet', interface: IFACE, tls_reassembly: true, ipv6_capture: true, offload_hint: false,
        uptime_s: round(up), stats: stats, clients: clients, client_count: Object.keys(clients).length, health: 'ok', rebind_count: 1,
        unique_hostnames: 2610 + round(up / 300), unique_sni: 1843 + round(up / 400), unique_ja4: 96, l3_enabled: true, l3_rule_version: '2026.10.02', dfp_enabled: true,
        conntrack_available: true, conntrack_readable: true, conntrack_path: '/proc/net/nf_conntrack', conntrack_flows: 412,
        unidentified_ratio: { total_bytes: round(sumDays(1)), identified_bytes: round(sumDays(1) * idb), ratio: 1 - idb },
        evidence_summary: { total: 48211 + round(up / 10), by_source: { sni: 31022, dns: 12840, ja4: 2210, ip_owner: 2139 } },
        top_unknown: [{ name: 'cfg.taptapdada.com', count: 41 }, { name: 'u3.svc-gw.cn', count: 23 }, { name: 'sdk.tuiaimg.com', count: 19 }, { name: 'static.hixiaoyu.cn', count: 12 }, { name: 'api.huoshan-gw.net', count: 9 }],
        self: selfState(), candidate_high: 1, auto_promote_on: SELF_ON.auto_promote,
        encdns: { dns_seen: 12840, dot_attempts: 37, dot_flows: 0, doh_suspect: 4, recent_doh: [{ client_mac: '3a:91:d4:6b:02:5f', name: 'dns.google', ts: t - 1900 }] }
      }
    };
  }

  /* ═════════════ 应用时长 / 前台时间线 ═════════════ */
  var CATS = [
    ['short_video', ['douyin', '抖音'], ['kuaishou', '快手'], ['weishi', '微视']],
    ['video', ['bilibili', 'B站'], ['iqiyi', '爱奇艺'], ['tencent_video', '腾讯视频'], ['youku', '优酷']],
    ['game', ['honor_of_kings', '王者荣耀'], ['genshin', '原神'], ['peacekeeper', '和平精英'], ['eggy_party', '蛋仔派对'], ['mc', '我的世界'], ['nintendo_online', 'Nintendo Switch Online']],
    ['social', ['wechat', '微信'], ['xiaohongshu', '小红书'], ['weibo', '微博'], ['qq', 'QQ']],
    ['live', ['douyu', '斗鱼'], ['huya', '虎牙']],
    ['shopping', ['taobao', '淘宝'], ['jd', '京东'], ['pdd', '拼多多']],
    ['music', ['qqmusic', 'QQ音乐'], ['netease_music', '网易云音乐']],
    ['reading', ['zhihu', '知乎'], ['fanqie', '番茄小说']]
  ];
  function appTime(mac, days) {
    var d = mac ? needDev(mac) : null, list = d ? d.hist.filter(function (id) { return id.charAt(0) !== '_' && ACT_H[id]; }) : Object.keys(ACT_H);
    var f = (days > 1 ? days - 1 : 0) + dayFrac(), r = srand('at' + (mac || '') + days);
    var apps = list.map(function (id, i) {
      var sec = round(ACT_H[id] * 3600 * f * (d ? [0.9, 0.4, 0.25, 0.15, 0.1][i] || 0.08 : 1) * (0.8 + r() * 0.4));
      if (d && id === 'douyin') { var tl = d.app_time_limits.filter(function (x) { return x.app_id === 'douyin'; })[0]; if (tl) sec = tl.used_sec; }
      return { id: id, name: appName(id), category: appCat(id), active_sec: sec, first_seen: midnight() + 7 * 3600, last_seen: now() - 60 };
    }).filter(function (a) { return a.active_sec > 0; }).sort(function (a, b) { return b.active_sec - a.active_sec; });
    var tot = apps.reduce(function (s, a) { return s + a.active_sec; }, 0);
    var out = { ok: true, days: days, mac: mac || '', since: ymd(dayAt(days - 1)), total_active_sec: tot, apps: apps, threshold_bytes: 8192, tick_sec: 10,
      by_hour: HW.map(function (w, h) { return { h: h, active_sec: round(tot * w / HWS) }; }),
      categories: CATS.map(function (c) { return { id: c[0], apps: c.slice(1).map(function (a) { return { id: a[0], name: a[1] }; }) }; }) };
    if (d) { out.app_time_limits = d.app_time_limits; out.category_blocks = d.category_blocks; }
    return out;
  }
  function fgTimeline(mac, days) {
    var d = needDev(mac), t = now(), t0 = days === 1 ? midnight() : t - days * 86400, r = srand('fg' + mac + days + ymd(dayAt(0)));
    var ids = d.hist.filter(function (id) { return id.charAt(0) !== '_'; }).slice(0, 4), sessions = [], by = {};
    if (!ids.length || !d.online && !d.last_seen) return { ok: true, sessions: [], by_app: [], current: null };
    var x = t0 + 7.5 * 3600 * (days === 1 ? 1 : 0.3), end = d.online ? t : d.last_seen;
    while (x < end - 300) {
      var id = ids[Math.floor(Math.pow(r(), 1.6) * ids.length)], len = 300 + r() * 2400, gap = 120 + r() * (days === 1 ? 2400 : 9000);
      var s = { app_id: id, name: appName(id), start: round(x), end: round(Math.min(end, x + len)) };
      sessions.push(s); by[id] = by[id] || { app_id: id, name: appName(id), fg_sec: 0, active_sec: 0 }; by[id].fg_sec += s.end - s.start; by[id].active_sec += round((s.end - s.start) * (1.05 + r() * 0.3));
      x += len + gap;
    }
    if (d.online && d.fg && d.fg.app_id) { var last = sessions[sessions.length - 1]; if (last) { last.app_id = d.fg.app_id; last.name = d.fg.name; last.end = 0; } }
    return { ok: true, mac: mac, days: days, engine: FG_ENGINE, sessions: sessions, by_app: Object.keys(by).map(function (k) { return by[k]; }).sort(function (a, b) { return b.fg_sec - a.fg_sec; }), current: d.fg || null };
  }

  /* ═════════════ 自检报告 ═════════════ */
  function selfcheck() {
    var S2 = [
      ['system', '机型与系统', [['model', '机型', 'ok', '示例机型 · Android 16'], ['kernel', '内核', 'ok', '6.6.56 GKI'], ['root', 'Root 方案', 'ok', 'KernelSU（Magic Mount）'], ['selinux', 'SELinux', 'info', 'Enforcing', '正常，HNC 规则已带 sepolicy']]],
      ['shaping', '限速能力', [['htb', 'HTB 限速', 'ok', '可用'], ['netem', '延迟注入 netem', 'ok', '可用'], ['ifb', '上行 IFB', 'ok', 'ifb0 可用'],
        ['aqm', '低延迟队列', 'warn', 'sfq', '内核没有 sch_cake / sch_fq_codel，低延迟模式退回 sfq，效果比 cake 弱一些', '可以继续用；换带 sch_cake 的内核后自动改用 CAKE']]],
      ['firewall', '防火墙', [['ipt', 'iptables mangle', 'ok', '31 条 HNC 规则'], ['ip6t', 'ip6tables', 'ok', '可用'], ['xt_string', '名字层（xt_string）', 'ok', '可用']]],
      ['offload', '硬件加速', [['tether_offload', '热点硬件加速', 'ok', 'IDLE', '加速存在但没在转发热点流量，限速不受影响'], ['guard', '兜底守护', 'ok', '自动 · 待命']]],
      ['network', '热点', [['iface', '热点接口', 'ok', IFACE + ' · 192.168.43.1/24'], ['dhcp', 'DHCP / 邻居表', 'ok', '9 个租约'], ['upstream', '上游', 'ok', 'rmnet_data2（蜂窝）']]],
      ['ipv6', 'IPv6', [['v6_neigh', 'IPv6 邻居', 'ok', '6 个地址, 4 台设备'], ['v6_uncovered', '未纳入限速的新地址', 'ok', '0']]],
      ['time', '时间', [['clock', '系统时间', 'ok', '正常'], ['auto_time', '自动同步时间', 'ok', '已开启']]],
      ['process', '进程', [['hotspotd', 'hotspotd', 'ok', '运行中'], ['dpid', 'hnc_dpid', 'ok', '运行中 · 7 小时'], ['watchdog', 'watchdog', 'ok', 'pidfd 心跳正常'], ['proc_goroutineleak', '协程泄漏检测 (Go 1.27)', 'ok', '0 泄漏 · 当前协程 18', 'Go 1.27 runtime/pprof goroutineleak GC 可达性核验耗时 2 ms']]],
      ['ident', '识别引擎', [['rules', '规则库', 'ok', '2026.10.02 · 3412 条'], ['capture', 'DPI 抓包', 'ok', 'AF_PACKET · ' + IFACE], ['fp', '指纹学习', 'info', '5 个可用指纹']]]
    ];
    var sum = { ok: 0, warn: 0, fail: 0, info: 0 };
    var sections = S2.map(function (s, i) {
      return { id: s[0], title: s[1], elapsed_ms: 300 + (i * 977) % 2600, items: s[2].map(function (x) { sum[x[2]]++; var o = { id: x[0], label: x[1], status: x[2], value: x[3] }; if (x[4]) o.detail = x[4]; if (x[5]) o.fix = x[5]; return o; }) };
    });
    return { available: true, running: false, generated_at: SC_AT, duration_ms: 18640, version: VER, redacted: false, summary: sum, sections: sections };
  }

  /* ═════════════ v5.40.0 数据面真机命中核验仿真 (100% 对齐 dataplane_verify.go JSON 契约) ═════════════ */
  var DPV_SNAP = { lastMs: Date.now() - 3200, runs: 1, resyncs: 0, byKey: {} };
  function dpvMarkHex(mid) {
    var m = +mid || 0;
    if (m <= 0) return '';
    var hex = (((0x00800000 | ((m & 0xff) << 16)) >>> 0)).toString(16);
    while (hex.length < 8) hex = '0' + hex;
    return '0x' + hex;
  }
  function dpvClassId(mid) {
    var m = +mid || 0;
    if (m <= 0) return '';
    return m === 1 ? '1:100' : ('1:' + m);
  }
  function dataplaneVerifyPayload(opts) {
    opts = opts || {};
    stepRates();
    var nowMs = Date.now();
    var isResync = !!opts.resync;
    if (opts.reset_baseline) {
      DPV_SNAP.byKey = {};
    }
    if (isResync) {
      DPV_SNAP.resyncs += 1;
    }
    var dtSec = Math.min(12, Math.max(0.45, (nowMs - DPV_SNAP.lastMs) / 1000));
    DPV_SNAP.lastMs = nowMs;
    if (opts.manual || isResync) DPV_SNAP.runs += 1;

    var appByMac = {};
    APP_LIMITS.forEach(function (al, gIdx) {
      var m = String(al.mac || '').toLowerCase();
      if (!m || !(al.down_mbps > 0)) return;
      appByMac[m] = appByMac[m] || [];
      appByMac[m].push({ globalIdx: gIdx, app_id: al.app_id, down_mbps: +al.down_mbps });
    });

    var sortedDevs = DEVS.slice().sort(function (a, b) { return a.mac < b.mac ? -1 : (a.mac > b.mac ? 1 : 0); });
    var devicesOut = [];
    var hitCnt = 0, idleCnt = 0, errCnt = 0, onlineMarked = 0;

    sortedDevs.forEach(function (d, idx) {
      var isBlacklisted = d.status === 'blocked';
      var hasRateLimit = d.limit_enabled !== false && (d.down_mbps > 0 || d.up_mbps > 0);
      var hasDelay = (d.delay_ms > 0 || d.jitter_ms > 0 || d.loss_pct > 0);
      var devApps = appByMac[d.mac] || [];
      var isControlled = isBlacklisted || hasRateLimit || !!d.app_qos || !!d.sqm_enabled || hasDelay || devApps.length > 0;
      if (!isControlled) return;

      var mid = (+d.mark_id > 0) ? Math.floor(+d.mark_id) : 0;
      var cid = mid > 0 ? dpvClassId(mid) : '';
      var mhex = mid > 0 ? dpvMarkHex(mid) : '';
      if (d.online && mid > 0) onlineMarked += 1;

      var activeFlow = d.online && !isBlacklisted;
      var snap = DPV_SNAP.byKey[d.mac];
      if (!snap) {
        var seed = idx + 1;
        snap = {
          downSent: activeFlow && mid > 0 ? (32845824 * seed) : 0,
          upSent: activeFlow && mid > 0 ? (6422528 * seed) : 0,
          downDrops: activeFlow && hasRateLimit && mid > 0 ? (12 * seed) : 0,
          upDrops: activeFlow && hasRateLimit && mid > 0 ? (2 * seed) : 0,
          downOver: activeFlow && (hasRateLimit || d.app_qos) && mid > 0 ? (860 * seed) : 0,
          upOver: activeFlow && hasRateLimit && mid > 0 ? (145 * seed) : 0,
          appSent: {},
          appDrops: {},
          appOver: {}
        };
        devApps.forEach(function (ap, j) {
          snap.appSent[ap.app_id] = activeFlow ? Math.floor(14680064 * (j + 1)) : 0;
          snap.appDrops[ap.app_id] = activeFlow ? (3 * (j + 1)) : 0;
          snap.appOver[ap.app_id] = activeFlow ? (310 * (j + 1)) : 0;
        });
        DPV_SNAP.byKey[d.mac] = snap;
      }

      var boost = isResync ? 2.1 : (opts.manual ? 1.65 : 1.0);
      var rxBps = activeFlow && mid > 0 ? Math.max(82000, d.cur[0] || 640000) : 0;
      var txBps = activeFlow && mid > 0 ? Math.max(18000, d.cur[1] || 96000) : 0;
      var downDelta = activeFlow && mid > 0 ? Math.max(49152, round(rxBps * dtSec * boost)) : 0;
      var upDelta = activeFlow && mid > 0 ? Math.max(12288, round(txBps * dtSec * boost)) : 0;
      var downDropDelta = activeFlow && hasRateLimit && mid > 0 && (opts.manual || isResync) ? 1 : 0;
      var upDropDelta = 0;

      snap.downSent += downDelta;
      snap.upSent += upDelta;
      snap.downDrops += downDropDelta;
      snap.upDrops += upDropDelta;
      if (activeFlow && mid > 0 && (hasRateLimit || d.app_qos)) {
        snap.downOver += Math.max(4, Math.floor(downDelta / 32768));
        snap.upOver += Math.max(1, Math.floor(upDelta / 32768));
      }

      var downObsKbps = activeFlow && mid > 0 ? Math.round((downDelta * 8) / (dtSec * 1000) * 100) / 100 : 0;
      var upObsKbps = activeFlow && mid > 0 ? Math.round((upDelta * 8) / (dtSec * 1000) * 100) / 100 : 0;

      var anyAppHit = false;
      var appSentSum = 0, appDeltaSum = 0, appDropsSum = 0, appOverSum = 0;
      var appClasses = devApps.map(function (ap) {
        var appCid = '1:' + (0x9001 + ap.globalIdx).toString(16);
        var baseFlowDelta = downDelta > 0 ? downDelta : (activeFlow ? Math.max(49152, round(480000 * dtSec * boost)) : 0);
        var aDelta = activeFlow ? Math.max(16384, round(baseFlowDelta * 0.58)) : 0;
        snap.appSent[ap.app_id] = (snap.appSent[ap.app_id] || 0) + aDelta;
        if (activeFlow) snap.appOver[ap.app_id] = (snap.appOver[ap.app_id] || 0) + Math.max(2, Math.floor(aDelta / 24576));
        var aKbps = activeFlow ? Math.round((aDelta * 8) / (dtSec * 1000) * 100) / 100 : 0;
        var aHit = (aDelta > 0 || snap.appSent[ap.app_id] > 0);
        if (aHit) anyAppHit = true;
        appSentSum += snap.appSent[ap.app_id];
        appDeltaSum += aDelta;
        appDropsSum += (snap.appDrops[ap.app_id] || 0);
        appOverSum += (snap.appOver[ap.app_id] || 0);
        return {
          app_id: ap.app_id,
          class_id: appCid,
          parent_class_id: cid || '1:1',
          down_limit_mbps: ap.down_mbps,
          class_present: true,
          sent_bytes: snap.appSent[ap.app_id],
          delta_bytes: aDelta,
          drops: snap.appDrops[ap.app_id] || 0,
          delta_drops: 0,
          overlimits: snap.appOver[ap.app_id] || 0,
          observed_kbps: aKbps,
          verdict: aHit ? 'hit' : 'idle'
        };
      });

      var outDownSent = snap.downSent, outDownDelta = downDelta, outDownDrops = snap.downDrops, outDownOver = snap.downOver;
      if (!hasRateLimit && !d.app_qos && appClasses.length > 0 && mid <= 0) {
        outDownSent = appSentSum;
        outDownDelta = appDeltaSum;
        outDownDrops = appDropsSum;
        outDownOver = appOverSum;
      }

      var verdict = 'idle', statusLabel = '链路就绪（空闲）', reason = '规则链路完整就绪，等待客户端产生流量';
      if (isBlacklisted) {
        verdict = 'hit';
        statusLabel = '黑名单阻断生效';
        reason = '双栈防火墙 HNC_CTRL MAC 阻断规则已就绪并拦截该设备转发流量';
      } else if (outDownDelta + upDelta > 0 || outDownSent + snap.upSent > 0 || anyAppHit) {
        verdict = 'hit';
        statusLabel = '队列真实命中';
        var totalMb = ((outDownSent + snap.upSent) / MB).toFixed(2);
        var shapeCnt = outDownOver + outDownDrops + snap.upOver + snap.upDrops;
        reason = '内核 HTB 限速队列已真实命中（累计转发 ' + totalMb + ' MB，超限整形/丢包 ' + shapeCnt + ' 次）';
      } else if (!d.online) {
        verdict = 'idle';
        statusLabel = '就绪（设备离线）';
        reason = '规则链路完整就绪，当前设备离线，重连产生流量后将自动命中队列';
      }

      if (verdict === 'hit') hitCnt += 1;
      else if (verdict === 'idle') idleCnt += 1;
      else errCnt += 1;

      var entry = {
        mac: d.mac,
        name: d.hostname || d.mac,
        ip: d.ip,
        online: !!d.online,
        mark_id: mid,
        mark_hex: mhex,
        class_id: cid,
        down_limit_mbps: hasRateLimit ? d.down_mbps : 0,
        up_limit_mbps: hasRateLimit ? d.up_mbps : 0,
        app_qos: !!d.app_qos,
        app_limits_count: devApps.length,
        down_sent_bytes: outDownSent,
        down_delta_bytes: outDownDelta,
        down_drops: outDownDrops,
        down_delta_drops: downDropDelta,
        down_overlimits: outDownOver,
        down_observed_kbps: downObsKbps,
        up_sent_bytes: snap.upSent,
        up_delta_bytes: upDelta,
        up_drops: snap.upDrops,
        up_delta_drops: upDropDelta,
        up_overlimits: snap.upOver,
        up_observed_kbps: upObsKbps,
        verdict: verdict,
        status_label: statusLabel,
        reason: reason,
        app_classes: appClasses
      };
      if (isBlacklisted) entry.blacklisted = true;
      devicesOut.push(entry);
    });

    var overall = errCnt > 0 ? 'warn' : (hitCnt > 0 ? 'ok' : 'idle');
    var headline = hitCnt > 0
      ? ('内核限速真实生效：' + hitCnt + '/' + devicesOut.length + ' 台受控设备已命中 HTB 队列（其余 ' + idleCnt + ' 台空闲就绪）')
      : ('全部 ' + devicesOut.length + ' 台受控设备内核队列与正交掩码链路已就绪，等待客户端产生流量');

    var out = {
      ok: true,
      checked_at: now(),
      iface: opts.iface || IFACE,
      hotspot_active: true,
      engine_mode: 'go_native_netlink',
      mark_layout: 'orthogonal_v540_0xffff0000',
      netd_low16_protected: true,
      ipv6_quic_controlled: true,
      bpf_maps: {
        mac_mark_entries: onlineMarked,
        ip_mark_entries: onlineMarked,
        tether_limit_zeroed: true,
        clsact_attached: true,
        ifb_redirect_prio2: true
      },
      offload_guard: {
        slowpath_active: true,
        tether_offload_disabled: true,
        hwnat: 'disabled'
      },
      summary: {
        controlled_devices: devicesOut.length,
        hitting_count: hitCnt,
        idle_count: idleCnt,
        bypass_or_missing_count: errCnt,
        overall_status: overall,
        headline: headline
      },
      devices: devicesOut
    };

    if (opts.goroutineleak) {
      var totalG = 18 + (DPV_SNAP.runs % 3);
      out.goroutineleak = {
        sampled: true,
        supported: true,
        trigger: opts.trigger || 'query_param',
        total_goroutines: totalG,
        leaked_count: 0,
        duration_ms: 2,
        status: 'clean',
        message: 'Go 1.27 goroutineleak GC 可达性核验通过：0 泄漏（总协程 ' + totalG + '，耗时 2 ms）'
      };
    }
    return out;
  }

  /* ═════════════ GET 路由 ═════════════ */
  function rulesJson() {
    var o = { whitelist_mode: CFG.whitelist_mode, remote_enabled: CFG.remote_enabled, blacklist: [], devices: {} };
    DEVS.forEach(function (d) {
      if (d.status === 'blocked') o.blacklist.push(d.mac);
      if (d.down_mbps || d.up_mbps || d.delay_ms || d.sqm_enabled || d.whitelist) o.devices[d.mac] = { mark_id: d.mark_id, limit_enabled: d.down_mbps > 0 || d.up_mbps > 0, down_mbps: d.down_mbps, up_mbps: d.up_mbps, delay_ms: d.delay_ms, jitter_ms: d.jitter_ms, loss_pct: d.loss_pct, sqm_enabled: !!d.sqm_enabled, whitelist: !!d.whitelist, ip: d.ip };
    });
    return o;
  }
  function logText() {
    var t = Date.now(), L = [], fmt = function (ms) { var d = new Date(ms); return ymdDash(d) + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()); };
    var M = ['[service] HNC ' + VER + ' 启动完成 · 热点接口 ' + IFACE, '[hotspotd] 新设备 d2:6e:4a:8c:15:f3 → 192.168.43.96（无主机名）', '[tc] class 1:15 rate 24mbit ceil 24mbit（iPad Air）',
      '[watchdog] 规则巡检通过 · tc 46 条 · iptables 31 条', '[dpid] 绑定 ' + IFACE + ' · AF_PACKET · 规则库 2026.10.02', '[apply] app_qos on 0a:7f:3c:41:9e:21 · 3 档优先级',
      '[stats] 采样 9 台设备 · 用时 41ms', '[detect] 低延迟队列: cake 不可用, fq_codel 不可用 → sfq', 'WARN [tc] sch_cake 不可用, 低延迟模式退回 sfq',
      '[hotspotd] 5e:20:b7:3a:c4:18 计数器 +312MB（下载中）', '[watchdog] 心跳 ok · 14s', '[dpid] 前台推断: 1e:52:a8:0c:77:3d → 抖音 0.91'];
    for (var i = 0; i < 48; i++) L.push(fmt(t - (48 - i) * 37000) + ' ' + M[(i * 7) % M.length]);
    return L.join('\n') + '\n';
  }
  var GET = {
    '/api/health': function () {
      var h = { status: 'ok', version: VER, watchdog_passive: false };
      if (REC_STATE.recording) {
        var elapsed = Math.max(1, now() - REC_STATE.started_at);
        if (elapsed >= REC_STATE.minutes * 60) REC_STATE.recording = false;
        else h.capture_rec = { recording: true, minutes: REC_STATE.minutes, started_at: REC_STATE.started_at, bytes: elapsed * 42 * KB };
      }
      return h;
    },
    '/api/signal': function () { MOCK_SIGNAL.updated_at = now(); return clone(MOCK_SIGNAL); },
    '/api/live': function (q) { var l = liveSummary(); l.signal = clone(MOCK_SIGNAL); if (q.devices) { var p = devicesPayload(); l.devices = p.devices; l.whitelist_mode = p.whitelist_mode; l.remote_enabled = p.remote_enabled; } return l; },
    '/api/devices': function () { return devicesPayload(); },
    '/api/config': function () { return Object.assign({}, CFG, { sim_enabled: SIM.enabled, autorate: AUTORATE, rmac_policy: RMAC_POL, client_isolation_enabled: RMAC_POL.client_isolation }); },
    '/api/capabilities': function () {
      return { available: true, capabilities: { tc_htb: true, tc_netem: true, uplink_supported: true, tc_cake: false, tc_fq_codel: false, ifb: true, ifb_supported: true, sqm_supported: true,
        sqm_recommended_mode: 'sfq', tc_ingress_supported: true, tc_clsact_supported: true, tc_u32_supported: true, tc_flower_supported: false, tc_matchall: true, tc_police_supported: true,
        tc_mirred: true, uplink_police_supported: true, downlink_mode: 'per_device_htb', uplink_mode: 'ifb_htb', delay_mode: 'netem_leaf', qos_fallback_required: false,
        tc_binary: 'bin/tc', tc_binary_source: 'module', tc_version: 'iproute2-6.1.0', c_fork_supported: true, selected_launcher: 'c_launcher', dpid_version: VER, generated_at: T - 7 * 3600 },
        qdisc_caps: { chosen: 'sfq', available: ['sfq', 'pfifo'], default_leaf_aqm_eligible: false } };
    },
    '/api/templates': function () { return TPL; },
    '/api/app_limits': function () { return { ok: true, items: APP_LIMITS, include_shared_ips: APP_LIMIT_SHARED }; },
    '/api/alerts': function () { return { ok: true, alerts: ALERTS.slice().sort(function (a, b) { return b.ts - a.ts; }), unread: ALERTS.filter(function (a) { return !a.seen; }).length, total: ALERTS.length }; },
    '/api/alert_config': function () { return ALERT_CFG; },
    '/api/offload_status': function () { return { active: false, detail: 'IDLE', offload_guard: CFG.offload_guard }; },
    '/api/online_hours': function (q) {
      var n = +q.days === 30 ? 30 : 7, om = {}, hrs = {};
      DEVS.forEach(function (d) {
        om[d.mac] = {}; hrs[d.mac] = {};
        for (var i = 0; i < n; i++) {
          var m = d.onlineMin[i % 7]; if (i === 0) m = d.online ? Math.min(m, Math.round(dayFrac() * 1440)) : m;
          if (m > 0) { om[d.mac][ymd(dayAt(i))] = m; if (m >= 60) hrs[d.mac][ymd(dayAt(i))] = Math.floor(m / 60); }
        }
      });
      return { days: n, online_min: om, hours: hrs };
    },
    '/api/usage_month': function () {
      var o = {}, cs = cycleStart(), f = dayFrac();
      DEVS.forEach(function (d) { if (d.usage8) o[d.mac] = { rx: round(d.usage8 * (0.97 + f * 0.03) * 0.93 + d.rx_bytes * 0.02), tx: round(d.usage8 * 0.07) }; });
      return { ok: true, since: Math.floor(cs.getTime() / 1000), oldest_data: Math.floor(cs.getTime() / 1000), devices: o };
    },
    '/api/encdns': function () {
      var dl = Object.keys(ENC.devices).map(function (m) { return { mac: m, policy: ENC.devices[m] }; });
      return { ok: true, policy: ENC.policy, devices: ENC.devices, device_list: dl, policies: ['off', 'dot', 'strict'], string_layer: 'available',
        counters: ENC.policy === 'off' ? null : { chain: true, v6: true, dot: { pkts: 214, bytes: 13096 }, doh_ip: { pkts: ENC.policy === 'strict' ? 61 : 0, bytes: 3904 }, doh_sni: { pkts: ENC.policy === 'strict' ? 7 : 0, bytes: 3619 },
          doh_dns: { pkts: ENC.policy === 'strict' ? 18 : 0, bytes: 1350 }, total_pkts: ENC.policy === 'strict' ? 300 : 214, total_bytes: 21969, v4_pkts: 190, v6_pkts: 24 },
        dpid: dpiState().state.encdns, tradeoff: '把「私人 DNS」设成指定主机名的设备在拦截后会整体无法解析（断网），遇到这种设备请在它的设备卡里单独选「关闭」。', updated_at: T - 86400 };
    },
    '/api/connections': function (q) { if (q.mac) { var d = needDev(q.mac); return devConns(d); } return connCounts(); },
    '/api/stats': function (q) { var rg = q.range || 'today'; if (['today', 'week', 'month', 'all'].indexOf(rg) < 0) throw err('invalid range'); return { range: rg, mac: '', source: q.source || 'legacy', buckets: statsRange(rg) }; },
    '/api/dpi_state': function () { seedDpiSpark(); return dpiState(); },
    '/api/dpi_probe': function () { return { available: true, probe: { af_packet_available: true, ap_iface: IFACE, ap_iface_source: 'tethering', conntrack_readable: true, conntrack_path: '/proc/net/nf_conntrack', offload_hint: false, offload_evidence: 'tether offload map 为空' } }; },
    '/api/dpi_history': function (q) { return dpiHistory(lim(+q.days || 1, 1, 7), q.mac); },
    '/api/app_usage': function (q) { return appUsage(lim(+q.days || 1, 1, 31)); },
    '/api/dpi_unknown': function (q) { return dpiUnknown(lim(+q.days || 1, 1, 31)); },
    '/api/proc_health': function () { return { status: 'ok', counts: { hnc_dpid: 1, hnc_httpd: 1, hotspotd: 1, watchdog_main: 1, dpid_guard_main: 1 }, detail: '' }; },
    '/api/discover': function () { return Object.assign({ ok: true, available: true }, DISC); },
    '/api/phone_usage': function (q) { var p = q.period || 'cycle'; if (['cycle', 'month', 'today', '7d', '30d'].indexOf(p) < 0) throw err('period must be cycle|month|today|7d|30d'); return phoneUsage(p); },
    '/api/app_time': function (q) { return appTime(q.mac, lim(+q.days || 1, 1, 31)); },
    '/api/fg_timeline': function (q) { return fgTimeline(q.mac, lim(+q.days || 1, 1, 7)); },
    '/api/self': function () { return { available: true, self: selfState(), auto_expand_enabled: SELF_ON.auto_expand, auto_promote_enabled: SELF_ON.auto_promote }; },
    '/api/self/ifaces': function () {
      return { enabled: SELF_ON.toggle, ap_iface: IFACE, flag_path: '/data/local/hnc/run/self_capture.enabled', ifaces: [
        { name: 'rmnet_data2', oper_state: 'up', rx_bytes: 38.2 * GB, eligible: true }, { name: 'wlan0', oper_state: 'up', rx_bytes: 2.4 * GB, eligible: true },
        { name: IFACE, oper_state: 'up', rx_bytes: 6.1 * GB, eligible: false, reason: 'hotspot' }, { name: 'lo', oper_state: 'unknown', rx_bytes: 12 * MB, eligible: false, reason: 'loopback' }] };
    },
    '/api/self/attrib': function () {
      var t = now(), C = [['com.ss.android.ugc.aweme', 10234, 'v26-dy.douyinvod.com', '抖音'], ['com.ss.android.ugc.aweme', 10234, 'api5-normal-lq.amemv.com', '抖音'], ['com.tencent.mm', 10198, 'szextshort.weixin.qq.com', '微信'],
        ['com.tencent.mm', 10198, 'mmsns.qpic.cn', '微信'], ['com.tencent.mm', 10198, 'dns.weixin.qq.com', '微信'], ['tv.danmaku.bili', 10311, 'api.bilibili.com', 'B站'], ['com.autonavi.minimap', 10287, 'm5.amap.com', '高德地图'],
        ['android', 1000, 'time.android.com', ''], ['com.example.proxyclient', 10420, '', '']];
      return { file: 'self_attrib.' + ymd(dayAt(0)) + '.jsonl', t: t - 4, conns: C.map(function (c, i) { return { pkg: c[0], uid: c[1], name: c[2], remote: fakeIp(c[2] + i) + ':443', app: c[3], proto: i === 7 ? 'udp' : 'tcp', state: i === 7 ? '' : 'ESTABLISHED' }; }) };
    },
    '/api/exports': function () { return { exports: EXPORTS.map(function (x) { return Object.assign({ download_url: '/api/exports/' + x.name }, x); }) }; },
    '/api/sla': function () { return { generated_at: now(), dpid_restart_count: 3, dpid_crash_recent: 0, dpid_guard_heartbeat_age_s: 2, watchdog_full_restore_count: 1, tc_repair_fail_count: 0, uplink_fail_count: 0, qos_fallback_active: false, uplink_unsupported: false }; },
    '/api/metrics': function () { return { instrumented: false, mode: 'live-read', backend_version: VER, compat: 'hotfix16.8-live-api' }; },
    '/api/autorate': function () { AUTORATE.updated_at = now(); return AUTORATE; },
    '/api/iface_info': function () { return { iface: IFACE, ip: GW, gateway: GW, network: '192.168.43.1/24' }; },
    '/api/run_status': function () { return { hotspotd: 'up', hotspotd_pid: 4127, hotspotd_rss_kb: 11840, tc_rules: 46, ipt_rules: 31, watchdog: 1, watchdog_pid: 4203, watchdog_kind: 'go', watchdog_hb_age: 14 }; },
    '/api/sim': function () { return { ok: true, enabled: SIM.enabled, count: SIM.devices.length, seed: 20261008, presets: ['busy', 'home', 'idle'], types: ['tv', 'phone', 'laptop', 'tablet', 'game', 'iot', 'pc'], mac_prefix: '02:5e:00:', max: 32, devices: SIM.devices }; },
    '/api/selfcheck': function () { return selfcheck(); },
    '/api/dataplane_verify': function (q) { return dataplaneVerifyPayload({ goroutineleak: bool(q.goroutineleak), reset_baseline: bool(q.reset_baseline), iface: q.iface, trigger: 'query_param', manual: false }); },
    '/api/mac_merge': function () {
      var sg = DEVS.filter(function (d) { return d.merge_suggestion; }).map(function (d) {
        return Object.assign({ new_mac: d.mac, new_name: d.hostname || d.mac, new_online: d.online, randomized: !!d.randomized_mac, new_first_seen: d.first_seen }, d.merge_suggestion);
      });
      return { ok: true, suggestions: sg, aliases: ALIASES, min_score: 40, alert_score: 60 };
    },
    '/api/stats_health': function () {
      return { issues: [], precise_mode: true, ct_events_active: true, ct_destroy_events_per_min: 186, ct_poll_fallback: false, ct_acct: 1, iptables_stats_ok: true, iptables_checked: true,
        last_stats_sample_age: 12, clock_sane: true, offload_gap_pct: 1.8, offload_kind: 'none', offload_guard_active: false, offload_guard_mode: 'auto',
        netstats_mode: PU_CFG.use_netstats, calibration_status: 'ok', hnc_vs_netstats_pct: -1.3, checked_at: now() - 95 };
    },
    '/api/logs': function () { return { ok: true, content: logText() }; },
    '/api/tokens': function () { return { tokens: TOKENS }; },
    '/api/dns': function () {
      var o = clone(DNS);
      if (DNS.enabled) Object.assign(o, { ok: true, active: true, healthy: true, state: 'active', iface: IFACE, port: 15353, upstream: GW + ':53', upstream_kind: 'tether', v6: { status: 'active', reason: '' }, ip_names: 128, stats: { queries: 18420, cached: 11230, blocked: 96, servfail: 2, p50_ms: 9, p95_ms: 41, cache_entries: 312 }, failopen: { count: 0 },
        top_domains_today: [{ name: 'v26-dy.douyinvod.com', count: 1820 }, { name: 'data.video.iqiyi.com', count: 1240 }, { name: 'szextshort.weixin.qq.com', count: 960 }] });
      return o;
    },
    '/api/dpi_fp': function () {
      return { user_rules: FP_RULES, stats: { usable: 5, flows_seen: 182340, flows_attributed_by_fp: 2311 }, learned: [
        { name: '抖音', app_id: 'douyin', ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1', port_class: 'tls443', usable: true, purity: 0.97, devices: 3 },
        { name: '微信', app_id: 'wechat', ja4: 't13d1715h2_5b57614c22b0_7121afd63204', port_class: 'tls443', usable: true, purity: 0.95, devices: 4 },
        { name: 'B站', app_id: 'bilibili', ja4: 'q13d0310h3_55b375c5d22e_cd85d2d88918', port_class: 'quic443', qtp: 'qtp1_7d3c19a0e4b2', usable: true, purity: 0.93, devices: 2 },
        { name: '王者荣耀', app_id: 'honor_of_kings', ja4: 't13d1312h2_a09f3c656075_14788d8d241b', port_class: 'tls443', usable: true, purity: 0.99, devices: 2 },
        { name: '爱奇艺', app_id: 'iqiyi', ja4: 't12d1209h2_d34a8e72043a_b39be8c56a14', port_class: 'tls443', usable: true, purity: 0.91, devices: 1 },
        { name: '小红书', app_id: 'xiaohongshu', ja4: 't13d1516h2_8daaf6152771_02713d6af862', port_class: 'tls443', usable: false, purity: 0.72, devices: 1 }] };
    },
    '/api/dpi_eval': function (q) {
      var dd = +q.days === 7 ? 7 : 1, k = dd === 7 ? 6.4 : 1;
      return { ok: true, enabled: SELF_ON.toggle, days: dd, samples: round(1842 * k), apps: dd === 7 ? 37 : 23,
        methods: { combined: { coverage: 0.91, accuracy: 0.96, judged: round(1400 * k), predicted: round(1676 * k), samples: round(1842 * k) }, rule: { coverage: 0.84, accuracy: 0.97, predicted: round(1547 * k), samples: round(1842 * k), judged: round(1300 * k) },
          fp: { coverage: 0.31, accuracy: 0.92, predicted: round(571 * k), samples: round(1842 * k), judged: round(480 * k) }, owner: { coverage: 0.22, accuracy: 0.81, predicted: round(405 * k), samples: round(1842 * k), judged: round(350 * k) } },
        quic: { samples: round(212 * k), fp_with_qtp: { coverage: 0.72, accuracy: 0.93 }, fp_ja4_only: { coverage: 0.58, accuracy: 0.88 } },
        startup: { apps_learned: 7, days: 5, switch_rate: 0.64, event_accuracy: 0.9, switches: 52, switch_hit: 33 },
        discover: { samples: 412, purity: 0.88, completeness: 0.71, groups: 26, hubs: 3 },
        flow_cls: { samples: 640, model_acc: 0.83, manual_acc: 0.71, classes: 7 },
        lan_self_consistency: { checked_ips: 386, paired_dual_stack: 124, cm_conflict_rate: 0.018, he_v4v6_parity: 0.976, active_escape_alerts: 0 },
        top_wrong: [{ name: '淘宝', truth: 'taobao', pred_name: '支付宝', pred: 'alipay', n: 14 }, { name: '高德地图', truth: 'amap', pred_name: '阿里系 SDK', pred: 'ali_sdk', n: 6 }],
        top_unknown: [{ name: '番茄小说', truth: 'fanqie', n: 31, snis: ['api.fqnovel.com', 'p3-novel.snssdk-novel.com'] }, { name: '得物', truth: 'dewu', n: 22, snis: ['app.dewu.com'] }],
        fg_truth: { source: 'usagestats', switches_24h: 146, last_pkg: 'com.tencent.mm', last_ts: now() - 120 } };
    },
    '/api/fg_compare': function () { return { ok: true, engine: FG_ENGINE, rounds: 2880, classic: { switches_per_hour: 7.4, short_segments: 19 }, hmm: { switches_per_hour: 4.1, short_segments: 6 }, agree_pct: 87 }; },
    '/api/dpi_rulepack': function () { return { ok: true, exportable: { domain_rules: 38, fingerprints: 12, startup: 7 }, imported: { domain_rules: 0, fingerprints: 0, startup: 0, suffixes: 0 },
      sources: { auto_expanded: { rules: 21 }, auto_promoted: { rules: 6 }, user_custom: { rules: 3 }, user_corrections: { domain: 8 } } }; },
    '/api/dpi_startup': function () { return { ok: true, stats: { events_total: 342 }, learned: [['抖音', 'douyin', 14, 5], ['微信', 'wechat', 22, 4], ['B站', 'bilibili', 9, 4], ['王者荣耀', 'honor_of_kings', 6, 3], ['高德地图', 'amap', 5, 3], ['小红书', 'xiaohongshu', 4, 3], ['淘宝', 'taobao', 3, 2]].map(function (x) { return { name: x[0], app_id: x[1], starts: x[2], feat: x[3], usable: true }; }) }; },
    '/api/whoami': function () { return { ok: true, authenticated: true, token_id: '7f3a9c21', session_label: '演示浏览器 · Safari', label: '演示浏览器 · Safari', ip_hint: '192.168.43.31', created: T - 86400, last_seen: now() }; },
    '/api/power': function () {
      return { ts: now(), sample_every_s: 300, samples: 12, level: 'active', level_label: '活跃',
        total: { cpu_pct_5m: 0.84, cpu_pct_1h: 0.62, cpu_sec_per_hour: 22.3, wakeups_per_min: 38 },
        processes: [
          { name: 'hnc_dpid', label: 'hnc_dpid', pid: 4120, alive: true, cpu_pct_5m: 0.41, rss_kb: 18432, wakeups_per_min: 19 },
          { name: 'hnc_httpd', label: 'hnc_httpd(含它拉起的脚本)', pid: 4118, alive: true, cpu_pct_5m: 0.23, rss_kb: 22528, wakeups_per_min: 9 },
          { name: 'watchdog', label: 'watchdog', pid: 4125, alive: true, cpu_pct_5m: 0.14, rss_kb: 11264, wakeups_per_min: 6 },
          { name: 'hotspotd', label: 'hotspotd', pid: 4112, alive: true, cpu_pct_5m: 0.06, rss_kb: 2480, wakeups_per_min: 4 }
        ], tips: ['当前总 CPU 占用 < 1%，处于极低功耗水平。'] };
    },
    '/api/dns/log': function () {
      var ms = Date.now();
      return { ok: true, log_queries: !!DNS.log_queries, entries: DNS.log_queries ? [
        { ts: ms - 4000, mac: DEVS[0].mac, ip: DEVS[0].ip, qname: 'pvp.qq.com', qtype: 'A', rcode: 'NOERROR', answers: ['183.3.226.35'], ms: 11, proto: 'udp', blocked: false },
        { ts: ms - 9000, mac: DEVS[1].mac, ip: DEVS[1].ip, qname: 'v26-dy.douyinvod.com', qtype: 'AAAA', rcode: 'NOERROR', answers: ['2408:871a:2100::12'], ms: 18, proto: 'udp', blocked: false },
        { ts: ms - 17000, mac: DEVS[1].mac, ip: DEVS[1].ip, qname: 'dns.google', qtype: 'AAAA', rcode: 'NXDOMAIN', ms: 1, proto: 'udp', blocked: true }
      ] : [] };
    },
    '/api/rules_export': function () { return { ok: true, rules: rulesJson() }; },
    '/api/dpi_rules': function () { return { ok: true, source: 'custom', rules: JSON.stringify({ schema_version: '1.0', rules_version: 'user-' + ymdDash(dayAt(2)), rules: [{ id: 'user_kuaikan', app: '快看漫画', category: 'reading', confidence: 'user', suffixes: ['kkmh.com', 'kuaikanmanhua.com'] }] }, null, 2) }; },
    '/api/self/studio': function () {
      var rem = STUDIO_LEASE.active ? Math.max(0, STUDIO_LEASE.until - now()) : 0;
      if (STUDIO_LEASE.active && rem <= 0) STUDIO_LEASE.active = false;
      return {
        ok: true,
        generated_at: now(),
        capture: {
          mode: STUDIO_MODE,
          enabled: STUDIO_MODE !== 'off',
          capturing_now: STUDIO_MODE !== 'off',
          screen_on: true,
          lease_active: STUDIO_MODE === 'lease_15m' && rem > 0,
          auto_expand_enabled: !!SELF_ON.auto_expand,
          auto_promote_enabled: !!SELF_ON.auto_promote,
          lease_rem_sec: rem,
          active_ifaces: [{ name: "wlan0", kind: "wifi", rx_bytes: 184 * MB, tls_events: 142, dns_events: 196 }, { name: "rmnet_data2", kind: "cellular", rx_bytes: 92 * MB, tls_events: 86, dns_events: 110 }],
          tls_events: 228,
          dns_events: 306
        },
        counters: {
          user_apps: STUDIO_STATS.apps,
          active_apps: 5,
          samples_written: STUDIO_STATS.samples,
          expanded_rules: 21,
          promoted_rules: 6,
          candidate_high: 2,
          usable_fps: STUDIO_STATS.usable_fp,
          usable_startups: STUDIO_STATS.usable_startup,
          nb_pool_samples: 248,
          nb_classes_ready: 6
        },
        rulepack: { domains: 40, fps: STUDIO_STATS.usable_fp, startups: STUDIO_STATS.usable_startup },
        last_distill: STUDIO_LAST_DISTILL
      };
    }
  };
  var STUDIO_MODE = 'smart_screen';
  var STUDIO_LEASE = { active: false, until: 0, saved: null };
  var STUDIO_LAST_DISTILL = { ts: T - 420, duration_ms: 42, samples_read: 386, exclusive_fps: 14, startup_usable: 7, nb_trained_samples: 264, nb_classes: 6, dpi_synced: true };
  var STUDIO_STATS = { samples: 418, apps: 15, learned_fp: 21, usable_fp: 14, usable_startup: 7 };
  var AUTORATE = { enabled: true, down_min_mbps: 24, down_max_mbps: 320, up_min_mbps: 8, up_max_mbps: 80, rtt_delta_ms: 25, state: 'active', hotspot_iface: IFACE, upstream_iface: 'rmnet_data2', cur_down_mbps: 186, cur_up_mbps: 52, actual_down_mbps: 31.4, actual_up_mbps: 4.8, load_down: 0.17, load_up: 0.09, base_rtt_ms: 24.5, rtt_ms: 31.2, delta_rtt_ms: 6.7, scale_events_up: 18, scale_events_down: 4, updated_at: T };
  var RMAC_POL = { auto_inherit: true, auto_inherit_score: 85, guard_mode: 'limit', guard_down_mbps: 16, guard_up_mbps: 8, client_isolation: false, ephemeral_gc_minutes: 30 };
  function pushExport(name, size) {
    var t = new Date();
    EXPORTS = EXPORTS.filter(function (x) { return x.name !== name; });
    EXPORTS.unshift({ name: name, size: size || 48620, modified: ymdDash(t) + 'T' + p2(t.getHours()) + ':' + p2(t.getMinutes()) + ':' + p2(t.getSeconds()) + '+08:00' });
  }

  /* ═════════════ POST /api/action ═════════════ */
  function parseRate(s) { s = String(s || '').toLowerCase(); var n = parseFloat(s); if (!(n > 0)) return 0; return /kbit/.test(s) ? n / 1000 : n; }
  function J(o) { return JSON.stringify(o); }
  function cfgSet(k) { return function (p) { CFG[k] = bool(p.enabled); return ''; }; }
  var ACT = {
    device_rename: function (p) { var d = needDev(p.mac), v = String(p.name || '').trim().slice(0, 32); if (v) { d.hostname = v; d.hostname_src = 'manual'; } else { d.hostname = d.auto[0]; d.hostname_src = d.auto[1]; } return v ? 'set ' + d.mac + ' -> "' + v + '"' : 'cleared name for ' + d.mac; },
    rule_set: function (p) { var d = needDev(p.mac); d.down_mbps = parseRate(p.rate_down); d.up_mbps = parseRate(p.rate_up); d.limit_enabled = true; return 'limit applied'; },
    template_apply: function (p) { return ACT.rule_set(p); },
    rule_clear: function (p) { var d = needDev(p.mac); d.down_mbps = d.up_mbps = 0; d.limit_enabled = false; return 'limit cleared'; },
    delay_set: function (p) { var d = needDev(p.mac); d.delay_ms = +p.delay_ms || 0; d.jitter_ms = +p.jitter_ms || 0; d.loss_pct = +p.loss_pct || 0; return 'delay injected'; },
    delay_clear: function (p) { var d = needDev(p.mac); d.delay_ms = d.jitter_ms = d.loss_pct = 0; return 'delay cleared'; },
    rule_sqm: function (p) { var d = needDev(p.mac); d.sqm_enabled = bool(p.enabled); return 'sqm=' + d.sqm_enabled + ' mac=' + d.mac; },
    app_qos_set: function (p) { var d = needDev(p.mac); d.app_qos = bool(p.enabled); return 'app_qos=' + d.app_qos; },
    device_whitelist_set: function (p) { var d = needDev(p.mac); d.whitelist = bool(p.enabled); return ''; },
    whitelist_set: function (p) { CFG.whitelist_mode = bool(p.enabled); return ''; },
    bl_add: function (p) { var d = needDev(p.mac); d.status = 'blocked'; return 'blacklisted'; },
    bl_del: function (p) { var d = needDev(p.mac); d.status = 'allowed'; return 'removed from blacklist'; },
    refresh: function () { return 'scan ok · ' + DEVS.filter(function (d) { return d.online; }).length + ' online'; },
    cleanup_rules: function () { DEVS.forEach(function (d) { d.down_mbps = d.up_mbps = d.delay_ms = d.jitter_ms = d.loss_pct = 0; d.limit_enabled = false; d.status = 'allowed'; d.blocks = []; }); if (typeof V6_LG_STATE === 'object') V6_LG_STATE.blocked_set = {}; if (typeof V6_EXP_STATE === 'object') V6_EXP_STATE.forced_macs = []; if (typeof V6_SC_STATE === 'object') V6_SC_STATE.frozen_rules = []; return ''; },
    cleanup_offline_devices: function (p) {
      var inc = bool(p.include_rules), rm = 0, kept = 0;
      DEVS = DEVS.filter(function (d) {
        if (d.online) return true;
        var rule = d.status === 'blocked' || d.down_mbps || d.up_mbps || d.delay_ms;
        if (rule && !inc) { kept++; return true; }
        rm++; return false;
      });
      return J({ ok: true, removed: rm, kept_with_rules: kept, skipped_online: DEVS.filter(function (d) { return d.online; }).length });
    },
    alert_mark_seen: function (p) { var ids = String(p.ids || '').split(','); ALERTS.forEach(function (a) { if (ids.indexOf(String(a.id)) >= 0) a.seen = true; }); return ''; },
    alert_dismiss_all: function () { ALERTS.forEach(function (a) { a.seen = true; }); return ''; },
    alert_mark_known: function () { return ''; },
    alert_config_set: function (p) {
      var s = p.section;
      if (s === 'master') ALERT_CFG.enabled = bool(p.enabled);
      else if (s === 'unknown_device') ALERT_CFG.unknown_device = { enabled: bool(p.enabled), quiet_hour_start: +p.quiet_start || 0, quiet_hour_end: +p.quiet_end || 0, min_interval_sec: +p.min_interval_sec || 1800 };
      else if (s === 'monthly_quota') ALERT_CFG.monthly_quota = { enabled: bool(p.enabled), limit_bytes: round((+p.limit_gb || 10) * GB), warn_at_pct: +p.warn_pct || 80 };
      else if (s === 'anomaly_traffic') ALERT_CFG.anomaly_traffic = { enabled: bool(p.enabled), ratio_threshold: +p.ratio || 3, min_bytes: round((+p.min_mb || 50) * MB) };
      return '';
    },
    app_limit_set: function (p) {
      var mac = String(p.mac).toLowerCase(), v = +p.down_mbps || 0, x = APP_LIMITS.filter(function (i) { return i.mac === mac && i.app_id === p.app_id; })[0];
      if (!v) { APP_LIMITS = APP_LIMITS.filter(function (i) { return i !== x; }); return 'cleared'; }
      if (x) x.down_mbps = v; else APP_LIMITS.push({ mac: mac, app_id: p.app_id, down_mbps: v, ips_total: 6, ips_shared_skipped: 1, ips_limited: 5 });
      return 'set ' + mac + '/' + p.app_id + ' = ' + v.toFixed(2) + ' Mbps';
    },
    app_limit_clear: function (p) { var mac = String(p.mac).toLowerCase(), n = APP_LIMITS.length; APP_LIMITS = APP_LIMITS.filter(function (i) { return !(i.mac === mac && (!p.app_id || i.app_id === p.app_id)); }); return 'cleared ' + (n - APP_LIMITS.length) + ' entry(s)'; },
    app_limit_shared_ips_set: function (p) { APP_LIMIT_SHARED = bool(p.enabled); return ''; },
    quota_set: function (p) {
      var d = needDev(p.mac), q = d.quota || { used_today: 0.6 * GB, used_month: d.usage8 || 1.2 * GB, billing_day: PU_CFG.billing_day };
      q.daily_gb = +p.daily_gb || 0; q.monthly_gb = +p.monthly_gb || 0; q.action = p.action === 'block' ? 'block' : 'throttle';
      q.throttle_mbps = +p.throttle_mbps || 1; q.throttle_up_mbps = q.throttle_mbps / 2; d.quota = q; return 'quota saved';
    },
    quota_clear: function (p) { var d = needDev(p.mac); var had = !!d.quota; d.quota = null; return had ? 'cleared' : 'nothing to clear'; },
    schedule_set: function (p) { var d = needDev(p.mac), w; try { w = JSON.parse(p.windows); } catch (_) { throw err('bad params'); } d.schedule = { windows: w }; return 'schedule saved'; },
    schedule_clear: function (p) { var d = needDev(p.mac); var had = !!d.schedule; d.schedule = null; return had ? 'cleared' : 'nothing to clear'; },
    app_time_limit_set: function (p) {
      var d = needDev(p.mac), m = +p.minutes || 0, x = d.app_time_limits.filter(function (i) { return i.app_id === p.app_id; })[0];
      if (!m) { d.app_time_limits = d.app_time_limits.filter(function (i) { return i !== x; }); return 'deleted'; }
      var used = x ? x.used_sec : round(rnd(0.2, 0.6) * m * 60);
      if (!x) { x = { app_id: p.app_id, name: appName(p.app_id), category: appCat(p.app_id), enforced: true }; d.app_time_limits.push(x); }
      x.minutes = m; x.used_sec = used; x.used_min = Math.floor(used / 60); x.exhausted = used >= m * 60; return 'saved';
    },
    app_time_limit_del: function (p) { var d = needDev(p.mac), n = d.app_time_limits.length; d.app_time_limits = d.app_time_limits.filter(function (i) { return i.app_id !== p.app_id; }); if (n === d.app_time_limits.length) throw err('not found'); return 'deleted'; },
    category_block_set: function (p) {
      var d = needDev(p.mac), on = bool(p.enabled), has = d.category_blocks.some(function (b) { return b.category === p.category; });
      if (on === has) return 'no change';
      if (on) { var c = CATS.filter(function (x) { return x[0] === p.category; })[0]; d.category_blocks.push({ category: p.category, app_count: c ? c.length - 1 : 3, ts: now(), enforced: true }); }
      else { d.category_blocks = d.category_blocks.filter(function (b) { return b.category !== p.category; }); d.blocks = d.blocks.filter(function (b) { return !(b.source === 'category' && b.ref === p.category); }); }
      return 'saved';
    },
    conn_block_add: function (p) { var d = needDev(p.mac); if (!d.blocks.some(function (b) { return b.kind === p.kind && b.value === p.value; })) d.blocks.push({ kind: p.kind, value: p.value, label: p.label || '' }); return 'blocked'; },
    conn_block_del: function (p) { var d = needDev(p.mac); d.blocks = d.blocks.filter(function (b) { return !(b.kind === p.kind && b.value === p.value); }); return 'removed'; },
    encdns_set: function (p) {
      if (p.mac || p.scope === 'device') { var d = needDev(p.mac); if (p.policy === 'inherit') delete ENC.devices[d.mac]; else ENC.devices[d.mac] = p.policy; }
      else { if (ENC.policy === p.policy) return 'no change'; ENC.policy = p.policy; }
      return ENC.policy === 'off' && !Object.keys(ENC.devices).length ? 'ENCDNS=off' : 'ENCDNS=on global=' + ENC.policy + ' devices=' + Object.keys(ENC.devices).length + ' rules=14 string_layer=1';
    },
    device_ident_set: function (p) {
      var d = needDev(p.mac);
      if (bool(p.clear)) { if (d.ident0) d.ident = d.ident0; return 'cleared'; }
      d.ident0 = d.ident0 || d.ident;
      d.ident = Object.assign({}, d.ident || {}, { type: p.type || '', os: p.os || '', os_ver: p.os_ver || '', brand: p.brand || '', model: p.model || '', confidence: 100, manual: true });
      return 'saved';
    },
    device_merge: function (p) {
      var to = needDev(p.to_mac), from = dev(p.from_mac);
      ALIASES[String(p.from_mac).toLowerCase()] = to.mac; MERGE_DONE[to.mac] = 1;
      if (from) { if (to.hostname_src !== 'manual') { to.hostname = from.hostname.replace(/-/g, ' '); to.hostname_src = 'manual'; } DEVS = DEVS.filter(function (d) { return d !== from; }); }
      delete to.merge_suggestion; to.randomized_mac = true; return 'merged';
    },
    device_merge_dismiss: function (p) { var d = needDev(p.to_mac); delete d.merge_suggestion; return 'dismissed'; },
    template_set: function (p) { TPL[p.name] = { down_mbps: +p.down_mbps || 0, up_mbps: +p.up_mbps || 0, delay_ms: +p.delay_ms || 0, jitter_ms: +p.jitter_ms || 0, loss_pct: +p.loss_pct || 0 }; return ''; },
    template_del: function (p) { delete TPL[p.name]; return ''; },
    hotspot_save: function (p) { if (p.ssid) CFG.hotspot_ssid = p.ssid; if (p.delay_sec) CFG.hotspot_delay_sec = +p.delay_sec; if (p.autostart) CFG.hotspot_autostart = bool(p.autostart); return 'config saved'; },
    hotspot_iface_set: function (p) { CFG.hotspot_iface = p.iface || ''; return p.iface ? 'preferred hotspot iface set to ' + p.iface : 'hotspot iface set to auto'; },
    hotspot_schedule_set: function (p) { CFG.hotspot_time_enable = bool(p.time_enable); CFG.hotspot_charging_only = bool(p.charging_only); if (p.start) CFG.hotspot_time_start = p.start; if (p.end) CFG.hotspot_time_end = p.end; return ''; },
    hotspot_start: function () { return '已触发启动，正在后台拉起热点（请稍候）'; },
    hotspot_stop: function () { return '演示模式：热点保持开启'; },
    stale_ttl_set: function (p) { CFG.stale_rule_ttl_days = +p.days || 0; return ''; },
    flywheel_exclude_set: function (p) { var l = CFG.flywheel_exclude_user; if (p.op === 'add') { if (l.indexOf(p.pkg) < 0) l.push(p.pkg); } else CFG.flywheel_exclude_user = l.filter(function (x) { return x !== p.pkg; }); return ''; },
    quic_block_set: cfgSet('quic_block'),
    discover_cert_probe_set: function (p) { CFG.discover_cert_probe = bool(p.enabled); DISC.cert_probe = CFG.discover_cert_probe; return ''; },
    remote_enabled_set: cfgSet('remote_enabled'),
    global_shaper_set: function (p) {
      CFG.global_shaper_enabled = bool(p.enabled);
      if (CFG.global_shaper_enabled) { CFG.global_shaper_down = p.rate_down || ''; CFG.global_shaper_up = p.rate_up || ''; return 'global shaper on down=' + (p.rate_down || '0') + ' up=' + (p.rate_up || '0'); }
      return 'global shaper off';
    },
    clsact_mode_set: function (p) { CFG.clsact_bpf_mode = p.mode; CFG.offload_guard.mode = p.mode; CFG.offload_guard.offload_state = p.mode === 'off' ? 'SKIPPED' : 'IDLE'; CFG.offload_guard.last_check = now(); return J(CFG.offload_guard); },
    clsact_check: function () { return J({ ok: true, clsact: true, bpf_filter: true, map: true, watchdog: true, iface: IFACE }); },
    tc_leaf_aqm_set: function (p) { CFG.tc_leaf_aqm = p.mode; return ''; },
    qos_set: function (p) { if (p.mode) CFG.tc_qos_mode = p.mode; if (p.scale) CFG.tc_qos_scale = +p.scale; return ''; },
    webui_access_set: function (p) { CFG.webui_access.mode = p.mode; if (p.macs != null) CFG.webui_access.macs = String(p.macs).split(',').filter(Boolean); return 'webui access mode=' + p.mode; },
    phone_usage_set: function (p) {
      ['billing_day', 'warn_percent', 'plan_sim1_gb', 'plan_sim2_gb'].forEach(function (k) { if (p[k] != null && p[k] !== '') PU_CFG[k] = +p[k]; });
      if (p.use_netstats) PU_CFG.use_netstats = p.use_netstats;
      return 'billing_day=' + PU_CFG.billing_day + ' sim1=' + PU_CFG.plan_sim1_gb + 'GB sim2=' + PU_CFG.plan_sim2_gb + 'GB warn=' + PU_CFG.warn_percent + '%';
    },
    dns_takeover_set: function (p) { if (p.enabled != null) DNS.enabled = bool(p.enabled); if (p.block_mode) DNS.block_mode = p.block_mode; if (p.log_queries != null) DNS.log_queries = bool(p.log_queries); if (p.log_redact != null) DNS.log_redact = bool(p.log_redact); return ''; },
    auth_required_set: function (p) { var v = bool(p.enabled); CFG.auth_required = v; CFG.remote_auth_required = v; return ''; },
    clsact_repair: function () { return J({ ok: true, clsact: true, bpf_filter: true, map: true, watchdog: true, iface: IFACE }); },
    capture_record: function (p) { var m = lim(+p.minutes || 10, 1, 30); REC_STATE = { recording: true, minutes: m, started_at: now() }; return J({ requested: true, recording: true, minutes: m }); },
    capture_record_stop: function () { REC_STATE.recording = false; var nm = 'rec-' + ymd(dayAt(0)) + '-120000.pcap'; pushExport(nm, 612480); return J({ recording: false, stopping: true, name: nm }); },
    dpi_eval_clear: function () { return 'cleared eval samples'; },
    dpi_rulepack_clear: function () { return 'cleared imported rulepack'; },
    sim_clear: function () { SIM.enabled = false; SIM.devices = []; DEVS = DEVS.filter(function (d) { return !/^02:5e:00:/i.test(d.mac); }); return 'cleared sim devices'; },
    sim_device_del: function (p) { var m = String(p.mac || '').toLowerCase(); SIM.devices = SIM.devices.filter(function (d) { return d.mac !== m; }); DEVS = DEVS.filter(function (d) { return d.mac.toLowerCase() !== m; }); return 'deleted ' + m; },
    sim_device_update: function (p) { var d = needDev(p.mac); if (p.name) d.hostname = p.name; return 'updated'; },
    dpi_correct_list: function () { return J({ rules: FP_RULES }); },
    dpi_fg_engine: function (p) { FG_ENGINE = p.engine === 'hmm' ? 'hmm' : 'classic'; return ''; },
    sim_set: function (p) { SIM.enabled = bool(p.enabled); return SIM.enabled ? '模拟环境已开启(' + SIM.devices.length + ' 台模拟设备)' : '模拟环境已关闭'; },
    sim_preset: function (p) { SIM.enabled = true; SIM.devices = [{ mac: '02:5e:00:11:22:33', ip: '192.168.43.210', name: '模拟-客厅电视', type: 'tv', online: true, cur_rx_bps: 3145728, cur_tx_bps: 92160 }]; return '已加载预设 ' + (p.preset || 'home'); },
    sim_device_add: function (p) { var mac = '02:5e:00:12:34:' + p2(10 + SIM.devices.length), nm = p.name || '模拟设备'; SIM.devices.push({ mac: mac, ip: '192.168.43.' + (215 + SIM.devices.length), name: nm, type: p.type || 'phone', online: true, cur_rx_bps: 524288, cur_tx_bps: 65536 }); return J({ mac: mac, name: nm, type: p.type || 'phone' }); },
    selfcheck_run: function () { SC_AT = now(); return J(selfcheck()); },
    dataplane_verify_run: function (p) {
      var isResync = p.resync === '1' || p.repair === '1' || bool(p.resync) || bool(p.repair);
      if (isResync) {
        CFG.offload_guard.offload_state = 'IDLE';
        CFG.offload_guard.fallback_active = true;
        CFG.offload_guard.last_check = now();
      }
      return J(dataplaneVerifyPayload({
        goroutineleak: bool(p.check_goroutineleak) || bool(p.goroutineleak),
        reset_baseline: bool(p.reset_baseline) || isResync,
        resync: isResync,
        iface: p.iface,
        trigger: 'action_param',
        manual: true
      }));
    },
    selfcheck_export: function (p) { var nm = 'hnc-selfcheck-' + ymd(dayAt(0)) + '-120000.txt', jn = 'hnc-selfcheck-' + ymd(dayAt(0)) + '-120000.json'; pushExport(nm, 18420); pushExport(jn, 34120); return J({ name: nm, json_name: jn, redacted: p.redact !== '0' }); },
    compat_report: function () { var nm = 'hnc-compat-' + ymd(dayAt(0)) + '.json'; pushExport(nm, 12840); return J({ name: nm, summary: { ok: 21, warn: 1, fail: 0 } }); },
    debug_bundle: function () { var nm = 'hnc-debug-' + ymd(dayAt(0)) + '-120000.tar.gz'; pushExport(nm, 428190); return J({ name: nm }); },
    dpi_rulepack_export: function () { var nm = 'hnc-rulepack-' + ymd(dayAt(0)) + '.json'; pushExport(nm, 26840); return J({ name: nm, counts: { domain_rules: 38, fingerprints: STUDIO_STATS.usable_fp, startup: STUDIO_STATS.usable_startup } }); },
    pair_new: function () { return J({ pin: String(100000 + Math.floor(Math.random() * 899999)), valid_sec: 120 }); },
    pair_revoke: function (p) { TOKENS = TOKENS.filter(function (x) { return x.token_id !== p.token; }); return ''; },
    candidate_promote: function (p) { CANDS.forEach(function (c) { if (c.apex === p.apex) c.promoted = true; }); return 'approved ' + p.apex; },
    candidate_reject: function (p) { CANDS.forEach(function (c) { if (c.apex === p.apex) { c.promoted = false; c.tier = 'shared'; } }); return 'blocklisted ' + p.apex; },
    self_attrib_purge: function () { return '已删除 3 个明细文件'; },
    cache_clear: function () { return '已清理 2 个缓存文件'; },
    apk_scan: function () { DISC.apk_scan.requested = true; return '已请求扫描，约 1 分钟内完成'; },
    discover_probe: function (p) { var g = DISC.groups.filter(function (x) { return x.id === p.id; })[0]; var ci = { host: (g && g.domains && g.domains[0] && g.domains[0].name) || 'svc-gw.cn', org: 'Example Cloud Tech Co., Ltd.', issuer: 'DigiCert Global G2 TLS RSA SHA256', sans: g ? g.suffixes : [], ts: now() }; if (g) g.cert = ci; return J(ci); },
    discover_ignore: function (p) { var g = DISC.groups.filter(function (x) { return x.id === p.id; })[0]; DISC.groups = DISC.groups.filter(function (x) { return x !== g; }); if (g) DISC.ignored.push({ id: g.id, suffixes: g.suffixes }); return ''; },
    discover_unignore: function (p) { DISC.ignored = DISC.ignored.filter(function (x) { return x.id !== p.id; }); return ''; },
    discover_confirm: function (p) { DISC.groups = DISC.groups.filter(function (x) { return x.id !== p.id; }); DISC.user_rules.push({ id: 'user_' + p.id, app: p.name, category: p.category, suffixes: String(p.suffixes || '').split(',') }); return ''; },
    user_rule_del: function (p) { DISC.user_rules = DISC.user_rules.filter(function (x) { return x.id !== p.id; }); return ''; },
    dpi_correct: function (p) { FP_RULES.push({ id: 'fp-u' + (FP_RULES.length + 1), kind: p.name ? 'domain' : 'ip', value: p.name || p.dst_ip, app_id: p.app_id, app_name: p.app_name || p.app_id }); return ''; },
    dpi_correct_del: function (p) { FP_RULES = bool(p.all) ? [] : FP_RULES.filter(function (x) { return x.id !== p.id; }); return ''; },
    dpi_rules_update: function () { return J({ update_available: 'no', current: '2026.10.02', remote: '2026.10.02' }); },
    dpi_rules_reset: function () { return '已恢复内置规则库（演示）'; },
    autorate_set: function (p) {
      if (p.autorate_enabled != null) AUTORATE.enabled = bool(p.autorate_enabled);
      else if (p.enabled != null) AUTORATE.enabled = bool(p.enabled);
      if (p.down_min_mbps) AUTORATE.down_min_mbps = +p.down_min_mbps;
      if (p.down_max_mbps) AUTORATE.down_max_mbps = +p.down_max_mbps;
      if (p.up_min_mbps) AUTORATE.up_min_mbps = +p.up_min_mbps;
      if (p.up_max_mbps) AUTORATE.up_max_mbps = +p.up_max_mbps;
      if (p.rtt_delta_ms) AUTORATE.rtt_delta_ms = +p.rtt_delta_ms;
      AUTORATE.state = AUTORATE.enabled ? 'active' : 'disabled';
      if (AUTORATE.enabled) {
        AUTORATE.cur_down_mbps = round((AUTORATE.down_min_mbps + AUTORATE.down_max_mbps) * 0.58);
        AUTORATE.cur_up_mbps = round((AUTORATE.up_min_mbps + AUTORATE.up_max_mbps) * 0.58);
        CFG.global_shaper_enabled = true;
      }
      return '5G autorate ' + (AUTORATE.enabled ? 'on' : 'off');
    },
    rmac_policy_set: function (p) {
      if (p.auto_inherit != null) RMAC_POL.auto_inherit = bool(p.auto_inherit);
      if (p.auto_inherit_score) RMAC_POL.auto_inherit_score = +p.auto_inherit_score;
      if (p.guard_mode) RMAC_POL.guard_mode = p.guard_mode;
      if (p.guard_down_mbps) RMAC_POL.guard_down_mbps = +p.guard_down_mbps;
      if (p.guard_up_mbps) RMAC_POL.guard_up_mbps = +p.guard_up_mbps;
      if (p.ephemeral_gc_minutes) RMAC_POL.ephemeral_gc_minutes = +p.ephemeral_gc_minutes;
      if (p.client_isolation != null) RMAC_POL.client_isolation = bool(p.client_isolation);
      return 'rmac policy saved';
    },
    rmac_trust: function (p) {
      var d = needDev(p.mac);
      d.rmac_guarded = false; d.rmac_guard_mode = ''; d.down_mbps = d.up_mbps = 0; d.limit_enabled = false; d.status = 'allowed';
      return 'trusted ' + d.mac;
    },
    client_isolation_set: function (p) {
      RMAC_POL.client_isolation = bool(p.enabled);
      return 'client isolation ' + (RMAC_POL.client_isolation ? 'on' : 'off');
    },
    self_studio_start: function (p) {
      var md = (p && p.mode) || 'smart_screen';
      if (md === 'stop' || md === 'off') {
        STUDIO_MODE = 'off'; STUDIO_LEASE.active = false; STUDIO_LEASE.until = 0; SELF_ON.toggle = false;
        return J({ mode: 'off', auto_stop_min: 0, lease_rem_sec: 0, dpid_synced: true });
      }
      if (md === 'smart_screen') {
        STUDIO_MODE = 'smart_screen'; STUDIO_LEASE.active = false; STUDIO_LEASE.until = 0;
        SELF_ON.toggle = true; SELF_ON.auto_expand = true; SELF_ON.auto_promote = true;
        return J({ mode: 'smart_screen', auto_stop_min: 0, lease_rem_sec: 0, dpid_synced: true });
      }
      STUDIO_MODE = 'lease_15m';
      SELF_ON.toggle = true; SELF_ON.auto_expand = md !== 'observe'; SELF_ON.auto_promote = md !== 'observe';
      var m = Math.max(1, +p.auto_stop_min || +p.minutes || 15), sec = m * 60;
      STUDIO_LEASE.active = true; STUDIO_LEASE.until = now() + sec;
      STUDIO_STATS.samples += 24;
      return J({ mode: 'lease_15m', auto_stop_min: m, lease_rem_sec: sec, dpid_synced: true });
    },
    self_studio_distill: function () {
      STUDIO_STATS.learned_fp += 2; STUDIO_STATS.usable_fp += 2; STUDIO_STATS.usable_startup += 1;
      STUDIO_LAST_DISTILL = { ts: now(), duration_ms: 48, samples_read: STUDIO_STATS.samples, exclusive_fps: STUDIO_STATS.usable_fp, startup_usable: STUDIO_STATS.usable_startup, nb_trained_samples: 248, nb_classes: 6, dpi_synced: true };
      return J(STUDIO_LAST_DISTILL);
    },
    dpi_distill_now: function () {
      STUDIO_STATS.usable_fp += 1;
      return J({ ok: true, distilled_at: now(), samples_scanned: STUDIO_STATS.samples, exclusive_count: STUDIO_STATS.usable_fp, startup_usable_count: STUDIO_STATS.usable_startup });
    },
    flow_cls_retrain: function () { return J({ samples: 248, classes: 6, retrained: true }); },
    self_studio_export: function () {
      STUDIO_STATS.usable_fp += 1;
      var nm = 'hnc-rulepack-' + ymd(dayAt(0)) + '.json'; pushExport(nm, 28410);
      return J({ name: nm, counts: { domain_rules: 40, fingerprints: STUDIO_STATS.usable_fp, startup: STUDIO_STATS.usable_startup }, distill_exclusive_fps: STUDIO_STATS.usable_fp, distill_startup_apps: STUDIO_STATS.usable_startup });
    },
    dpi_rebind: function () { return 'rebind requested'; },
    restart_service: function () { return 'restart scheduled'; },
    cleanup_all: function () { return 'safe release scheduled'; }
  };
  function doAction(body) {
    var name = body && body.action, p = (body && body.params) || {}, fn = ACT[name];
    if (!fn) return { ok: true, detail: '' };
    try { var det = fn(p); return det ? { ok: true, detail: det } : { ok: true }; }
    catch (e) { if (e && e.status != null) return { ok: false, error: e.message, detail: '' }; throw e; }
  }
  var POST = {
    '/api/action': doAction,
    '/api/export': function (b) {
      var t = new Date(), name = 'hnc-export-' + ymd(t) + '-' + p2(t.getHours()) + p2(t.getMinutes()) + p2(t.getSeconds()) + '.zip', size = 300000 + Math.floor(Math.random() * 500000);
      EXPORTS.unshift({ name: name, size: size, modified: ymdDash(t) + 'T' + p2(t.getHours()) + ':' + p2(t.getMinutes()) + ':' + p2(t.getSeconds()) + '+08:00' });
      var tr = { dpi_state: { included: true, file_count: 1 }, self_attrib: { included: true, file_count: 1 }, stats: { included: true, file_count: 2 }, ip_app_map: { included: true, file_count: 1 }, dpi_rules: { included: true, file_count: 3 } };
      return { status: 'ok', name: name, size_bytes: size, download_url: '/api/exports/' + name, manifest: { schema_version: '3', generated_at: now(), hnc_version: VER, tracks: tr, notes: (b && b.notes) || [] } };
    },
    '/api/self/toggle': function (b) { SELF_ON.toggle = !!(b && b.enabled); return { status: 'ok', enabled: SELF_ON.toggle }; },
    '/api/self/auto_expand/toggle': function (b) { SELF_ON.auto_expand = !!(b && b.enabled); return { status: 'ok', enabled: SELF_ON.auto_expand }; },
    '/api/self/auto_promote/toggle': function (b) { SELF_ON.auto_promote = !!(b && b.enabled); return { status: 'ok', enabled: SELF_ON.auto_promote }; },
    '/api/dpi_rules': function () { return { ok: true, detail: '已导入（演示：不会真的改规则库）' }; },
    '/api/dpi_rulepack': function () { return { ok: true, added: { suffixes: 4, domain_rules: 2, fingerprints: 1, startup: 0 }, merged: {}, unchanged: {}, skipped: {} }; },
    '/api/logout': function () { return { ok: true }; },
    '/api/rollback_ack': function () { return { ok: true }; }
  };


  /* ═════════════ HNC v6.0.0 · Vector 战术中枢与 LeakGuard 仿真层 ═════════════ */
  var V6_LG_STATE = {
    notify_enabled: true,
    lockscreen_mask: true,
    capacity: 300,
    cooldown_sec: 300,
    blocked_set: { 'adtrack-legacy.example.cn': 1 },
    events: [
      {
        id: 'lg_v6_01',
        ts: T - 18,
        mac: '0a:7f:3c:41:9e:21',
        device_name: '小米 14',
        src_ip: '192.168.43.23',
        src_port: 51428,
        dst_ip: '114.118.24.66',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'PHONE',
        raw_value: '13800138000',
        dst_host: 'sdk-report.example-ad.cn',
        hit_count: 3,
        method: 'POST',
        path: '/v2/collect?mobile=13800138000&channel=mi',
        user_agent: 'Dalvik/2.1.0 (Linux; U; Android 15; Xiaomi 14)',
        is_blocked: false,
        raw_snippet: 'POST /v2/collect?mobile=13800138000&channel=mi HTTP/1.1\r\nHost: sdk-report.example-ad.cn\r\nUser-Agent: Dalvik/2.1.0 (Linux; U; Android 15; Xiaomi 14)\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuid=demo_9021&phone=13800138000&net=wifi'
      },
      {
        id: 'lg_v6_02',
        ts: T - 47,
        mac: '3a:91:d4:6b:02:5f',
        device_name: 'MacBook Pro',
        src_ip: '192.168.43.31',
        src_port: 58310,
        dst_ip: '120.55.89.14',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'TOKEN',
        raw_value: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo_v6_token',
        dst_host: 'legacy-api.devtool-sync.net',
        hit_count: 1,
        method: 'GET',
        path: '/v1/workspace/ping',
        user_agent: 'curl/8.7.1',
        is_blocked: false,
        raw_snippet: 'GET /v1/workspace/ping HTTP/1.1\r\nHost: legacy-api.devtool-sync.net\r\nUser-Agent: curl/8.7.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo_v6_token\r\nAccept: */*'
      },
      {
        id: 'lg_v6_03',
        ts: T - 112,
        mac: 'd2:6e:4a:8c:15:f3',
        device_name: '192.168.43.96',
        src_ip: '192.168.43.96',
        src_port: 44912,
        dst_ip: '180.97.33.108',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'GPS',
        raw_value: '31.230416,121.473701',
        dst_host: 'weather-loc.iot-probe.cn',
        hit_count: 2,
        method: 'GET',
        path: '/loc/check?latlng=31.230416,121.473701&coord=gcj02',
        user_agent: 'okhttp/4.12.0',
        is_blocked: false,
        raw_snippet: 'GET /loc/check?latlng=31.230416,121.473701&coord=gcj02 HTTP/1.1\r\nHost: weather-loc.iot-probe.cn\r\nUser-Agent: okhttp/4.12.0\r\nConnection: keep-alive'
      },
      {
        id: 'lg_v6_04',
        ts: T - 265,
        mac: '6a:0e:55:b1:9c:42',
        device_name: '客厅电视',
        src_ip: '192.168.43.67',
        src_port: 39820,
        dst_ip: '106.11.43.88',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'DEVICE_ID',
        raw_value: 'oaid_8f4e2c19a0b741d39e5c0012a87b6d01',
        dst_host: 'adtrack-legacy.example.cn',
        hit_count: 6,
        method: 'GET',
        path: '/splash/impression?oaid=oaid_8f4e2c19a0b741d39e5c0012a87b6d01&res=3840x2160',
        user_agent: 'AndroidTV-AdSDK/3.4.2',
        is_blocked: true,
        raw_snippet: 'GET /splash/impression?oaid=oaid_8f4e2c19a0b741d39e5c0012a87b6d01&res=3840x2160 HTTP/1.1\r\nHost: adtrack-legacy.example.cn\r\nUser-Agent: AndroidTV-AdSDK/3.4.2'
      },
      {
        id: 'lg_v6_05',
        ts: T - 490,
        mac: '7e:c4:19:20:5a:8b',
        device_name: '小爱音箱',
        src_ip: '192.168.43.71',
        src_port: 47204,
        dst_ip: '42.62.94.19',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'MAC_ADDR',
        raw_value: '7e:c4:19:20:5a:8b',
        dst_host: 'ota-ping.smartspeaker-demo.cn',
        hit_count: 1,
        method: 'POST',
        path: '/device/heartbeat',
        user_agent: 'SmartSpeaker-HTTP/1.8',
        is_blocked: false,
        raw_snippet: 'POST /device/heartbeat HTTP/1.1\r\nHost: ota-ping.smartspeaker-demo.cn\r\nUser-Agent: SmartSpeaker-HTTP/1.8\r\nContent-Type: application/json\r\n\r\n{"mac":"7e:c4:19:20:5a:8b","fw":"2.14.8"}'
      }
    ]
  };

  function v6LeakGuardPayload() {
    var totalHits = 0, devMap = {};
    V6_LG_STATE.events.forEach(function (ev) {
      totalHits += (ev.hit_count || 1);
      if (ev.mac || ev.src_ip) devMap[ev.mac || ev.src_ip] = 1;
      ev.is_blocked = !!V6_LG_STATE.blocked_set[String(ev.dst_host || '').toLowerCase()] || !!V6_LG_STATE.blocked_set[String(ev.dst_ip || '').toLowerCase()];
    });
    var blkCnt = Object.keys(V6_LG_STATE.blocked_set).filter(function (k) { return !/^\d+\.\d+\.\d+\.\d+$/.test(k); }).length;
    return {
      ok: true,
      config: {
        notify_enabled: V6_LG_STATE.notify_enabled,
        lockscreen_mask: V6_LG_STATE.lockscreen_mask,
        capacity: V6_LG_STATE.capacity,
        cooldown_sec: V6_LG_STATE.cooldown_sec
      },
      stats: {
        total_hits: totalHits,
        affected_devices: Object.keys(devMap).length,
        blocked_domains: blkCnt
      },
      events: V6_LG_STATE.events
    };
  }

  var V6_EXP_STATE = {
    enabled: true,
    auto_detect: true,
    forced_macs: ['0a:7f:3c:41:9e:21'],
    configured_bg_ceil_pct: 85,
    transitions: 4,
    qdisc: 'fq_codel'
  };

  function v6ExpressPayload() {
    var escorted = [];
    var reasons = {};
    if (V6_EXP_STATE.enabled) {
      V6_EXP_STATE.forced_macs.forEach(function (m) {
        if (escorted.indexOf(m) < 0) escorted.push(m);
        reasons[m] = '手动常驻锁定零排队护航 (PRIO 0)';
      });
      if (V6_EXP_STATE.auto_detect) {
        var dGame = dev('0a:7f:3c:41:9e:21');
        if (dGame && dGame.online) {
          if (escorted.indexOf(dGame.mac) < 0) escorted.push(dGame.mac);
          reasons[dGame.mac] = '王者荣耀 UDP 高频对战微突发 + 常驻锁定';
        }
        var dCall = dev('3a:91:d4:6b:02:5f');
        if (dCall && dCall.online) {
          if (escorted.indexOf(dCall.mac) < 0) escorted.push(dCall.mac);
          reasons[dCall.mac] = '腾讯会议 WebRTC EF(46) 实时双向音视频流';
        }
      }
    }
    var active = V6_EXP_STATE.enabled && escorted.length > 0;
    return {
      ok: true,
      enabled: V6_EXP_STATE.enabled,
      auto_detect: V6_EXP_STATE.auto_detect,
      state: !V6_EXP_STATE.enabled ? 'disabled' : (active ? 'active_escort' : 'idle_fullspeed'),
      active: active,
      forced_macs: V6_EXP_STATE.forced_macs.slice(),
      escorted_macs: escorted,
      escort_reasons: reasons,
      bg_ceil_pct: active ? V6_EXP_STATE.configured_bg_ceil_pct : 100,
      configured_bg_ceil_pct: V6_EXP_STATE.configured_bg_ceil_pct,
      cooldown_remaining_sec: 0,
      transitions: V6_EXP_STATE.transitions,
      dataplane: { qdisc: V6_EXP_STATE.qdisc, tier: 'tier_b_native_htb' }
    };
  }

  var V6_UL_STATE = {
    enabled: true,
    grace_mb: 200,
    leash_kbps: 1500,
    leashed_count: 3,
    sessions: [
      {
        session_key: '5e:20:b7:3a:c4:18|atum.hac.lp1.d4c.nintendo.net',
        mac: '5e:20:b7:3a:c4:18',
        device_name: '任天堂 Switch',
        src_ip: '192.168.43.52',
        dst_host: 'atum.hac.lp1.d4c.nintendo.net',
        dst_ip: '104.111.42.88',
        vendor_label: 'Nintendo eShop',
        down_bytes: Math.round(648.4 * MB),
        grace_remaining_bytes: 0,
        down_bps: 184000,
        applied_kbps: 1500,
        state: 'leashed',
        bypass_once: false,
        paused: false
      },
      {
        session_key: 'a6:5b:0f:93:7e:24|tlu.dl.delivery.mp.microsoft.com',
        mac: 'a6:5b:0f:93:7e:24',
        device_name: 'ThinkPad',
        src_ip: '192.168.43.84',
        dst_host: 'tlu.dl.delivery.mp.microsoft.com',
        dst_ip: '13.107.4.52',
        vendor_label: 'Windows Update',
        down_bytes: Math.round(126.2 * MB),
        grace_remaining_bytes: Math.round(73.8 * MB),
        down_bps: 1420000,
        applied_kbps: 0,
        state: 'grace_fullspeed',
        bypass_once: false,
        paused: false
      }
    ]
  };

  function v6LeashPayload() {
    var graceBytes = V6_UL_STATE.grace_mb * MB;
    var computed = V6_UL_STATE.sessions.map(function (s) {
      var copy = clone(s);
      copy.grace_remaining_bytes = Math.max(0, graceBytes - copy.down_bytes);
      if (copy.paused) {
        copy.state = 'paused';
        copy.applied_kbps = 0;
      } else if (!V6_UL_STATE.enabled || copy.bypass_once) {
        copy.state = copy.bypass_once ? 'bypassed' : 'grace_fullspeed';
        copy.applied_kbps = 0;
      } else if (copy.down_bytes >= graceBytes) {
        copy.state = 'leashed';
        copy.applied_kbps = V6_UL_STATE.leash_kbps;
      } else {
        copy.state = 'grace_fullspeed';
        copy.applied_kbps = 0;
      }
      return copy;
    });
    var lCnt = computed.filter(function (s) { return s.state === 'leashed'; }).length;
    return {
      ok: true,
      enabled: V6_UL_STATE.enabled,
      grace_mb: V6_UL_STATE.grace_mb,
      leash_kbps: V6_UL_STATE.leash_kbps,
      leashed_count: lCnt,
      active_sessions: computed.length,
      sessions: computed
    };
  }

  var V6_TH_STATE = {
    enabled: true,
    stage2_shaper_enabled: true,
    stage1_temp_c: 42,
    stage2_temp_c: 45,
    low_bat_pct: 20,
    temp_c: 39.6,
    capacity_pct: 78,
    is_charging: false,
    bat_status: 'Discharging'
  };

  function v6ThermoPayload() {
    var exActive = v6ExpressPayload().active;
    var tc = round((V6_TH_STATE.temp_c + Math.sin(Date.now() / 45000) * 0.3) * 10) / 10;
    var rawStg = tc >= V6_TH_STATE.stage2_temp_c ? 2 : (tc >= V6_TH_STATE.stage1_temp_c ? 1 : 0);
    var exempt = V6_TH_STATE.is_charging || exActive;
    var effStg = !V6_TH_STATE.enabled ? 0 : (rawStg === 2 && exempt ? 1 : rawStg);
    return {
      ok: true,
      enabled: V6_TH_STATE.enabled,
      stage2_shaper_enabled: V6_TH_STATE.stage2_shaper_enabled,
      stage1_temp_c: V6_TH_STATE.stage1_temp_c,
      stage2_temp_c: V6_TH_STATE.stage2_temp_c,
      low_bat_pct: V6_TH_STATE.low_bat_pct,
      battery: {
        available: true,
        temp_c: tc,
        capacity_pct: V6_TH_STATE.capacity_pct,
        status: V6_TH_STATE.bat_status,
        is_charging: V6_TH_STATE.is_charging
      },
      vector_express_active: exActive,
      stage2_exempt: exempt,
      exempt_reason: V6_TH_STATE.is_charging ? 'charging_exempt' : (exActive ? 'gaming_escort_exempt' : ''),
      low_battery_cruise: V6_TH_STATE.capacity_pct <= V6_TH_STATE.low_bat_pct,
      cool_hold_remaining_sec: 0,
      raw_thermal_stage: rawStg,
      effective_stage: effStg
    };
  }

  var V6_SC_STATE = {
    cut_total: 4,
    killed_keys: {},
    frozen_rules: [
      { key: 'tcp|192.168.43.67|106.11.43.88|80', proto: 'tcp', src_ip: '192.168.43.67', dst_ip: '106.11.43.88', dport: 80, expires_at: T + 780 }
    ]
  };

  function v6BuildScalpelFlows(filterMac, filterIp) {
    stepRates();
    var nowSec = now();
    V6_SC_STATE.frozen_rules = V6_SC_STATE.frozen_rules.filter(function (r) { return r.expires_at > nowSec; });
    var frozenMap = {};
    V6_SC_STATE.frozen_rules.forEach(function (r) {
      frozenMap[r.proto + '|' + r.src_ip + '|' + r.dst_ip + '|' + r.dport] = r.expires_at;
    });

    var seedFlows = [
      { flow_key: 'sc_01', mac: '0a:7f:3c:41:9e:21', device_name: '小米 14', proto: 'udp', src_ip: '192.168.43.23', sport: 55120, dst_ip: '183.3.226.35', dport: 10012, domain: 'pvp.qq.com', app_name: '王者荣耀', state: 'ASSURED', down_bps: 148000, up_bps: 72000, down_bytes: 18 * MB, up_bytes: 7 * MB },
      { flow_key: 'sc_02', mac: '0a:7f:3c:41:9e:21', device_name: '小米 14', proto: 'tcp', src_ip: '192.168.43.23', sport: 51428, dst_ip: '114.118.24.66', dport: 80, domain: 'sdk-report.example-ad.cn', app_name: '广告遥测 SDK', state: 'ESTABLISHED', down_bps: 4200, up_bps: 1800, down_bytes: 64 * KB, up_bytes: 28 * KB },
      { flow_key: 'sc_03', mac: '3a:91:d4:6b:02:5f', device_name: 'MacBook Pro', proto: 'udp', src_ip: '192.168.43.31', sport: 60412, dst_ip: '119.147.82.44', dport: 3480, domain: 'avc.meeting.qq.com', app_name: '腾讯会议', state: 'ASSURED', down_bps: 680000, up_bps: 520000, down_bytes: 192 * MB, up_bytes: 148 * MB },
      { flow_key: 'sc_04', mac: '3a:91:d4:6b:02:5f', device_name: 'MacBook Pro', proto: 'tcp', src_ip: '192.168.43.31', sport: 58310, dst_ip: '120.55.89.14', dport: 80, domain: 'legacy-api.devtool-sync.net', app_name: '命令行工具', state: 'ESTABLISHED', down_bps: 2400, up_bps: 1200, down_bytes: 42 * KB, up_bytes: 19 * KB },
      { flow_key: 'sc_05', mac: '1e:52:a8:0c:77:3d', device_name: 'iPad Air', proto: 'quic', src_ip: '192.168.43.45', sport: 52890, dst_ip: '111.225.148.29', dport: 443, domain: 'v26-dy.douyinvod.com', app_name: '抖音', state: 'ASSURED', down_bps: 1940000, up_bps: 68000, down_bytes: 412 * MB, up_bytes: 14 * MB },
      { flow_key: 'sc_06', mac: '5e:20:b7:3a:c4:18', device_name: '任天堂 Switch', proto: 'tcp', src_ip: '192.168.43.52', sport: 49218, dst_ip: '104.111.42.88', dport: 443, domain: 'atum.hac.lp1.d4c.nintendo.net', app_name: '任天堂 eShop', state: 'ESTABLISHED', down_bps: 185000, up_bps: 9200, down_bytes: 648 * MB, up_bytes: 9 * MB },
      { flow_key: 'sc_07', mac: '6a:0e:55:b1:9c:42', device_name: '客厅电视', proto: 'quic', src_ip: '192.168.43.67', sport: 43106, dst_ip: '36.110.188.72', dport: 443, domain: 'data.video.iqiyi.com', app_name: '爱奇艺', state: 'ASSURED', down_bps: 2310000, up_bps: 42000, down_bytes: 1120 * MB, up_bytes: 21 * MB },
      { flow_key: 'sc_08', mac: '6a:0e:55:b1:9c:42', device_name: '客厅电视', proto: 'tcp', src_ip: '192.168.43.67', sport: 39820, dst_ip: '106.11.43.88', dport: 80, domain: 'adtrack-legacy.example.cn', app_name: '电视开屏 SDK', state: 'TIME_WAIT', down_bps: 0, up_bps: 0, down_bytes: 128 * KB, up_bytes: 24 * KB },
      { flow_key: 'sc_09', mac: 'a6:5b:0f:93:7e:24', device_name: 'ThinkPad', proto: 'udp', src_ip: '192.168.43.84', sport: 51820, dst_ip: '203.0.113.18', dport: 51820, domain: 'wg-gateway.corp-demo.net', app_name: 'VPN/代理隧道', state: 'ASSURED', down_bps: 540000, up_bps: 145000, down_bytes: 186 * MB, up_bytes: 52 * MB },
      { flow_key: 'sc_10', mac: 'd2:6e:4a:8c:15:f3', device_name: '192.168.43.96', proto: 'tcp', src_ip: '192.168.43.96', sport: 44912, dst_ip: '180.97.33.108', dport: 80, domain: 'weather-loc.iot-probe.cn', app_name: '天气定位组件', state: 'ESTABLISHED', down_bps: 1600, up_bps: 800, down_bytes: 18 * KB, up_bytes: 9 * KB }
    ];

    var fMac = String(filterMac || '').toLowerCase();
    var fIp = String(filterIp || '').trim();
    var out = [];
    seedFlows.forEach(function (f) {
      var pNorm = (f.proto === 'udp' || f.proto === 'quic') ? 'udp' : 'tcp';
      var k5 = pNorm + '|' + f.src_ip + ':' + f.sport + '|' + f.dst_ip + ':' + f.dport;
      if (V6_SC_STATE.killed_keys[k5]) return;
      if (f.domain && V6_LG_STATE.blocked_set[String(f.domain).toLowerCase()]) return;
      if (fMac && f.mac !== fMac) return;
      if (fIp && f.src_ip !== fIp) return;
      var k4 = pNorm + '|' + f.src_ip + '|' + f.dst_ip + '|' + f.dport;
      var copy = clone(f);
      if (frozenMap[k4]) {
        copy.frozen_until = frozenMap[k4];
        copy.down_bps = 0;
        copy.up_bps = 0;
        copy.state = 'FROZEN';
      } else {
        copy.down_bps = round(copy.down_bps * rnd(0.86, 1.16));
        copy.up_bps = round(copy.up_bps * rnd(0.86, 1.16));
      }
      out.push(copy);
    });
    return out;
  }

  function v6ScalpelPayload(q) {
    var flows = v6BuildScalpelFlows(q && q.mac, q && q.ip);
    return {
      ok: true,
      readable: true,
      total: flows.length,
      cut_total: V6_SC_STATE.cut_total,
      active_rules: V6_SC_STATE.frozen_rules,
      flows: flows
    };
  }

  var V6_BB_STATE = {
    granularity_ms: 200,
    total_ticks: 18420,
    latest_jitter_ms: 4.8,
    incidents: [
      {
        unix_ms: (T - 340) * 1000,
        rtt_ms: 46.2,
        jitter_ms: 28.4,
        culprit_device: '任天堂 Switch (192.168.43.52)',
        root_cause_zh: 'eShop 突发多线程并发拉取触发上行队列瞬时水位抬升，已由 UpdateLeash 压制收敛'
      },
      {
        unix_ms: (T - 1920) * 1000,
        rtt_ms: 39.5,
        jitter_ms: 21.0,
        culprit_device: '5G NR 空口切站 (rmnet_data2)',
        root_cause_zh: '上游基站 PCI 切换引起 180ms 短暂重传，5G Autorate 已平滑重锚定'
      }
    ]
  };

  function v6BlackboxPayload() {
    V6_BB_STATE.total_ticks += 3;
    V6_BB_STATE.latest_jitter_ms = round((4.2 + Math.abs(Math.sin(Date.now() / 9000)) * 3.6) * 10) / 10;
    return {
      ok: true,
      granularity_ms: V6_BB_STATE.granularity_ms,
      total_ticks: V6_BB_STATE.total_ticks,
      incident_count: V6_BB_STATE.incidents.length,
      latest_jitter_ms: V6_BB_STATE.latest_jitter_ms,
      incidents: V6_BB_STATE.incidents
    };
  }

  function v6MultiIfacePayload() {
    return {
      ok: true,
      primary_downstream: IFACE,
      shape_targets: [IFACE, 'ap_br_wlan2'],
      dual_band_or_mlo: true,
      usb_tether_active: false,
      lan_fastlane_class: '1:fffe',
      lan_fastlane_gbps: 2.5,
      tun0_guard: {
        vpn_active: false,
        loop_risk_detected: false,
        low16_mark_safe: true
      }
    };
  }

  var V6_SUBTREES_RESTORES = 2;
  function v6SubtreesPayload() {
    var exOn = v6ExpressPayload().active;
    return {
      ok: true,
      full_restores: V6_SUBTREES_RESTORES,
      dynamic_qos: exOn
        ? { mode: 'gaming_60_30_10', tier1_pct: 60, tier2_pct: 30, tier3_pct: 10 }
        : { mode: 'balanced_50_35_15', tier1_pct: 50, tier2_pct: 35, tier3_pct: 15 }
    };
  }

  var V6_VAULT_SHA = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

  GET['/api/vector_sync'] = function () {
    var lv = GET['/api/live']({});
    var dv = GET['/api/devices']();
    return {
      ok: true,
      version: VER,
      backend_version: VER,
      healthy: true,
      core_uptime_sec: 14820 + Math.floor((Date.now() - PAGE_T0) / 1000),
      bulkheads: {
        dataplane: { healthy: true, circuit_state: 'closed', fail_count: 0 },
        dpi_shm: { healthy: true, circuit_state: 'closed', fail_count: 0 },
        android_bridge: { healthy: true, circuit_state: 'closed', fail_count: 0 },
        storage: { healthy: true, circuit_state: 'closed', fail_count: 0 }
      },
      health: GET['/api/health'](),
      live: lv,
      devices: dv.devices,
      devices_sig: dv.devices_sig || '',
      config: GET['/api/config'](),
      capabilities: GET['/api/capabilities'](),
      alerts: GET['/api/alerts'](),
      offload_status: GET['/api/offload_status'](),
      app_limits: GET['/api/app_limits'](),
      templates: GET['/api/templates'](),
      leakguard: v6LeakGuardPayload(),
      express: v6ExpressPayload(),
      update_leash: v6LeashPayload(),
      thermo: v6ThermoPayload(),
      scalpel: v6ScalpelPayload({}),
      v6_pack: {
        blackbox: v6BlackboxPayload(),
        multi_iface: v6MultiIfacePayload(),
        native_subtrees: v6SubtreesPayload()
      }
    };
  };
  GET['/api/leakguard/events'] = function () { return v6LeakGuardPayload(); };
  GET['/api/v6/express'] = function () { return v6ExpressPayload(); };
  GET['/api/v6/update_leash'] = function () { return v6LeashPayload(); };
  GET['/api/v6/thermo'] = function () { return v6ThermoPayload(); };
  GET['/api/v6/scalpel/flows'] = function (q) { return v6ScalpelPayload(q || {}); };
  GET['/api/v6/blackbox'] = function () { return v6BlackboxPayload(); };
  GET['/api/v6/multi_iface'] = function () { return v6MultiIfacePayload(); };
  GET['/api/v6/native_subtrees'] = function () { return v6SubtreesPayload(); };
  GET['/api/v6/diag_dump'] = function () {
    return {
      ok: true,
      version: VER,
      generated_at: now(),
      bulkheads: GET['/api/vector_sync']().bulkheads,
      dataplane_tier: 'tier_b_native_htb',
      json_engine: 'go1.27_encoding_json_v2'
    };
  };
  GET['/api/backup'] = function () {
    return {
      schema: 'hnc.config.vault.v6',
      module_version: VER,
      exported_at: now(),
      file_count: 16,
      sha256: V6_VAULT_SHA,
      files: {
        'rules.json': rulesJson(),
        'vector_express.json': { enabled: V6_EXP_STATE.enabled, auto_detect: V6_EXP_STATE.auto_detect, forced_macs: V6_EXP_STATE.forced_macs },
        'update_leash.json': { enabled: V6_UL_STATE.enabled, grace_mb: V6_UL_STATE.grace_mb, leash_kbps: V6_UL_STATE.leash_kbps },
        'thermo_cruise.json': { enabled: V6_TH_STATE.enabled, stage1_temp_c: V6_TH_STATE.stage1_temp_c, stage2_temp_c: V6_TH_STATE.stage2_temp_c }
      }
    };
  };

  POST['/api/leakguard/config'] = function (b) {
    if (b && typeof b.notify_enabled === 'boolean') V6_LG_STATE.notify_enabled = b.notify_enabled;
    if (b && typeof b.lockscreen_mask === 'boolean') V6_LG_STATE.lockscreen_mask = b.lockscreen_mask;
    if (b && b.capacity != null) V6_LG_STATE.capacity = lim(round(+b.capacity || 300), 10, 2000);
    if (b && b.cooldown_sec != null) V6_LG_STATE.cooldown_sec = lim(round(+b.cooldown_sec || 300), 0, 86400);
    return v6LeakGuardPayload();
  };
  POST['/api/leakguard/clear'] = function () {
    V6_LG_STATE.events = [];
    return v6LeakGuardPayload();
  };
  POST['/api/leakguard/block-domain'] = function (b) {
    var host = String((b && b.dst_host) || '').trim().toLowerCase();
    if (!host) throw err('missing dst_host', 400);
    var unb = !!(b && b.action === 'unblock');
    if (unb) delete V6_LG_STATE.blocked_set[host];
    else V6_LG_STATE.blocked_set[host] = 1;
    var targetMac = String((b && b.mac) || '').toLowerCase();
    DEVS.forEach(function (d) {
      if (targetMac && d.mac !== targetMac) return;
      d.blocks = (d.blocks || []).filter(function (x) { return String(x.value || '').toLowerCase() !== host; });
      if (!unb) {
        d.blocks.push({ kind: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 'ip' : 'domain', value: host, label: '隐私安检拦截', source: 'manual' });
      }
    });
    return v6LeakGuardPayload();
  };
  POST['/api/v6/express'] = function (b) {
    if (b && typeof b.enabled === 'boolean') V6_EXP_STATE.enabled = b.enabled;
    if (b && typeof b.auto_detect === 'boolean') V6_EXP_STATE.auto_detect = b.auto_detect;
    if (b && Array.isArray(b.forced_macs)) {
      V6_EXP_STATE.forced_macs = b.forced_macs.map(function (m) { return String(m || '').toLowerCase(); }).filter(Boolean);
    }
    V6_EXP_STATE.transitions += 1;
    return v6ExpressPayload();
  };
  POST['/api/v6/update_leash'] = function (b) {
    var act = (b && b.action) || 'config';
    if (act === 'config') {
      if (b && typeof b.enabled === 'boolean') V6_UL_STATE.enabled = b.enabled;
      if (b && b.grace_mb != null) V6_UL_STATE.grace_mb = lim(round(+b.grace_mb || 200), 10, 10240);
      if (b && b.leash_kbps != null) V6_UL_STATE.leash_kbps = lim(round(+b.leash_kbps || 1500), 128, 1000000);
    } else {
      var sk = String((b && b.session_key) || '');
      V6_UL_STATE.sessions.forEach(function (s) {
        if (s.session_key === sk || (b.mac && s.mac === String(b.mac).toLowerCase() && (!b.dst_host || s.dst_host === b.dst_host))) {
          if (act === 'bypass_once') { s.bypass_once = true; s.paused = false; s.state = 'bypassed'; s.applied_kbps = 0; }
          else if (act === 'pause_update') { s.paused = true; s.state = 'paused'; s.down_bps = 0; }
          else if (act === 'resume_update') { s.paused = false; s.state = s.bypass_once ? 'bypassed' : 'leashed'; s.down_bps = 184000; }
        }
      });
    }
    return v6LeashPayload();
  };
  POST['/api/v6/thermo'] = function (b) {
    if (b && typeof b.enabled === 'boolean') V6_TH_STATE.enabled = b.enabled;
    if (b && typeof b.stage2_shaper_enabled === 'boolean') V6_TH_STATE.stage2_shaper_enabled = b.stage2_shaper_enabled;
    if (b && b.stage1_temp_c != null) V6_TH_STATE.stage1_temp_c = lim(+b.stage1_temp_c || 42, 30, 70);
    if (b && b.stage2_temp_c != null) V6_TH_STATE.stage2_temp_c = lim(+b.stage2_temp_c || 45, 32, 75);
    if (b && b.low_bat_pct != null) V6_TH_STATE.low_bat_pct = lim(round(+b.low_bat_pct || 20), 1, 80);
    return v6ThermoPayload();
  };
  POST['/api/v6/scalpel/cut'] = function (b) {
    var pNorm = (b && (b.proto === 'udp' || b.proto === 'quic')) ? 'udp' : 'tcp';
    var sip = String((b && b.src_ip) || '').trim();
    var dip = String((b && b.dst_ip) || '').trim();
    var sp = round(+(b && b.sport) || 0);
    var dp = round(+(b && b.dport) || 0);
    if (!sip || !dip || dp <= 0) throw err('invalid 5-tuple', 400);
    V6_SC_STATE.cut_total += 1;
    if (b && b.mode === 'cut_freeze_15m') {
      var k4 = pNorm + '|' + sip + '|' + dip + '|' + dp;
      V6_SC_STATE.frozen_rules = V6_SC_STATE.frozen_rules.filter(function (r) { return r.key !== k4; });
      V6_SC_STATE.frozen_rules.push({ key: k4, proto: pNorm, src_ip: sip, dst_ip: dip, dport: dp, expires_at: now() + 900 });
    } else if (sp > 0) {
      V6_SC_STATE.killed_keys[pNorm + '|' + sip + ':' + sp + '|' + dip + ':' + dp] = 1;
    }
    return { ok: true, mode: (b && b.mode) || 'cut_once', cut_total: V6_SC_STATE.cut_total, active_rules: V6_SC_STATE.frozen_rules.length };
  };
  POST['/api/v6/blackbox'] = function (b) {
    var act = (b && b.action) || 'sample_now';
    if (act === 'clear') {
      V6_BB_STATE.incidents = [];
    } else {
      V6_BB_STATE.total_ticks += 1;
      V6_BB_STATE.latest_jitter_ms = round(rnd(3.4, 7.8) * 10) / 10;
    }
    return v6BlackboxPayload();
  };
  POST['/api/v6/native_subtrees'] = function () {
    V6_SUBTREES_RESTORES += 1;
    return v6SubtreesPayload();
  };
  POST['/api/backup'] = function (b) {
    var cnt = (b && b.files && typeof b.files === 'object') ? Object.keys(b.files).length : (round(+(b && b.file_count) || 16));
    return { ok: true, restored_count: Math.max(1, cnt), sha256: (b && b.sha256) || V6_VAULT_SHA };
  };
  POST['/api/restore'] = POST['/api/backup'];

  /* ═════════════ 预置曲线历史 ═════════════
   * 顶部「近 60 秒下行」曲线和 DPI 计数小曲线都是前端按轮询结果一点点攒的, 刚打开时是一条直线;
   * 这里先按同样的随机游走补上前 29 个点(S 是 core.js 的全局状态), 首屏就有起伏 */
  (function seedHistory() {
    try {
      var hist = [];
      for (var i = 0; i < 29; i++) { lastStep = 0; stepRates(); var rx = 0; DEVS.forEach(function (d) { rx += d.cur[0]; }); hist.push(rx); }
      if (typeof S === 'object' && S && Array.isArray(S.spark) && !S.spark.length) S.spark = hist;
    } catch (_) {}
  })();
  /* DPI 计数小曲线: 等第一次进「分析 → DPI 分析」时再补(前端只在这个子页轮询时攒点, 间隔约 15 秒),
   * 补的最后一个点在「此刻 − 15 秒」, 和随后真实轮询的点衔接上 */
  var dpiSeeded = false;
  function seedDpiSpark() {
    try {
      if (dpiSeeded || typeof S !== 'object' || !S || S.page !== 'stats' || S.aseg !== 'dpi') return;
      var ds = S.dpiSpark; dpiSeeded = true;
      if (!ds || ds.packets.length) return;
      var up0 = DPI_UP0 + (Date.now() - PAGE_T0) / 1000;
      for (var j = 29; j >= 1; j--) {
        var u = up0 - j * 15, w = 0.35 * Math.sin(j / 2.3) + 0.2 * Math.sin(j * 1.7);
        ds.packets.push(round(u * 942 + 3100 * Math.sin(u / 37) + w * 2200));
        ds.dns_events.push(round(u * 3.1 + 40 * Math.sin(u / 23) + w * 9));
        ds.tls_events.push(round(u * 2.2 + 30 * Math.sin(u / 29) + w * 6));
        ds.kernel_drops.push(round(u * 0.004 + 3 * Math.sin(u / 41) + 3));
      }
    } catch (_) {}
  }

  /* ═════════════ 覆盖 core.js 的 req() ═════════════ */
  function route(method, path, body) {
    var i = path.indexOf('?'), p = i >= 0 ? path.slice(0, i) : path, q = {};
    if (i >= 0) new URLSearchParams(path.slice(i + 1)).forEach(function (v, k) { q[k] = v; });
    var tbl = method === 'POST' ? POST : GET, fn = tbl[p];
    if (!fn) throw HttpError('演示模式未提供此接口', 404, { error: 'not found in mock' });
    return method === 'POST' ? fn(body || {}, q) : fn(q);
  }
  window.req = function (method, path, body) {
    var wait = 40 + Math.random() * 110;
    if (body && body.action === 'selfcheck_run') wait = 1600;   // 真机自检要 ~20 秒, 演示里稍微等一下, 看得到进度条
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        try { resolve(clone(route(method, path, body))); }
        catch (e) {
          if (e && e.status != null) { reject(e); return; }
          if (window.console) console.error('[演示数据] ' + method + ' ' + path + ' 出错：', e);
          reject(HttpError('演示数据出错：' + (e && e.message || e), 500));
        }
      }, wait);
    });
  };

  /* ═════════════ 拦下预览里用不了的东西 ═════════════ */
  // SSE: 不建连接(演示数据本来就在内存里, 轮询足够)
  function FakeEventSource(url) {
    var self = this;
    this.url = url;
    this.readyState = 0;
    this.onopen = this.onerror = this.onmessage = null;
    this._ls = {};
    setTimeout(function () {
      if (self.readyState === 2) return;
      self.readyState = 1;
      if (typeof self.onopen === 'function') self.onopen({ type: 'open' });
      (self._ls.ready || []).forEach(function (fn) { try { fn({ type: 'ready', data: '{"ok":true}' }); } catch (_) {} });
    }, 35);
  }
  FakeEventSource.prototype.addEventListener = function (tp, fn) {
    if (!this._ls[tp]) this._ls[tp] = [];
    this._ls[tp].push(fn);
  };
  FakeEventSource.prototype.removeEventListener = function (tp, fn) {
    if (!this._ls[tp]) return;
    this._ls[tp] = this._ls[tp].filter(function (x) { return x !== fn; });
  };
  FakeEventSource.prototype.close = function () { this.readyState = 2; };
  window.EventSource = FakeEventSource;
  // fetch: 只应答 changelog.html(内嵌副本), 其它一律不联网
  var realFetch = window.fetch;
  window.fetch = function (url) {
    var u = String(url && url.url || url || '');
    if (/(^|\/)changelog\.html(\?|$)/.test(u)) {
      var html = window.__HNC_MOCK_CHANGELOG || '<h2>更新日志</h2><p>预览版没有内嵌更新日志。</p>';
      return Promise.resolve({ ok: true, status: 200, text: function () { return Promise.resolve(html); }, json: function () { return Promise.reject(new Error('not json')); } });
    }
    void realFetch;
    return Promise.reject(new TypeError('演示模式不联网：' + u));
  };
  // 点击拦截(捕获阶段, 早于 main.js 的委托)
  window.addEventListener('click', function (e) {
    var t = e.target; if (!t || !t.closest) return;
    var a = t.closest('a[href]');
    if (a) {
      var h = a.getAttribute('href') || '';
      if (/(^|\/)glass\.html/.test(h)) { e.preventDefault(); e.stopPropagation(); toast('预览版里不包含 HNC Glass 原型', 'warn'); return; }
      if (/^\/|^json-health|^[a-z0-9_-]+\.html/i.test(h)) { e.preventDefault(); e.stopPropagation(); toast('演示模式：不会真的下载 / 跳转（' + (a.getAttribute('download') || h).slice(0, 40) + '）', 'warn'); return; }
    }
    var b = t.closest('[data-act="logout"], [data-act="json-health"]');
    if (b) { e.preventDefault(); e.stopPropagation(); toast(b.getAttribute('data-act') === 'logout' ? '演示模式：没有登录状态，不用退出' : '演示模式：预览里没有 JSON 健康面板', 'warn'); }
  }, true);

  /* ═════════════ 「演示数据」标记 ═════════════ */
  var st = document.createElement('style');
  st.textContent = '#mode-pill.sample{display:inline-block!important;color:var(--orange,#FF9500);background:color-mix(in srgb,var(--orange,#FF9500) 14%,transparent);' +
    'box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--orange,#FF9500) 35%,transparent);position:relative;z-index:1;transition:opacity .15s ease}' +
    '[data-style="apple"] .header #mode-pill.sample{opacity:calc(1 - var(--st,0))}' +
    '.header.hs-on #mode-pill.sample{opacity:0!important;pointer-events:none!important}' +
    '@media (max-width:600px){.header{padding-left:60px!important}}';
  (document.head || document.documentElement).appendChild(st);
  function demoPill() {
    var p = document.getElementById('mode-pill'); if (!p) return;
    var fix = function () {
      if (p.textContent !== '演示数据') p.textContent = '演示数据';
      if (p.hidden) p.hidden = false;
      if (!p.title) p.title = '界面预览：所有设备、流量和告警都是虚构的演示数据，不连接任何真实后端';
    };
    fix();
    new MutationObserver(fix).observe(p, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ['hidden'] });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', demoPill); else demoPill();
})();
