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

  if (typeof window === 'undefined' || window.__HNC_MOCK_PREVIEW__ !== true) {
    return;
  }

  var META = window.__HNC_MOCK_META || {};
  var VER = (META.version && !/^(dev|unknown)$/i.test(String(META.version).trim())) ? META.version : 'v6.1.0-rc.8', VCODE = String(META.versionCode || '6009308');
  var GB = 1073741824, MB = 1048576, KB = 1024;
  var IFACE = 'wlan2', GW = '192.168.43.1', MOCK_HS_ACTIVE = true;

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
    douyin: ['抖音', 'video', ['v26-dy.douyinvod.com', 'api5-normal-lq.amemv.com', 'p26-sign.douyinpic.com']],
    kuaishou: ['快手', 'video', ['txmov2.a.kwimgs.com', 'api.gifshow.com']],
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
    windows_update: ['Windows 更新', 'system-update', ['tlu.dl.delivery.mp.microsoft.com', 'settings-win.data.microsoft.com']],
    teams: ['Microsoft Teams', 'office', ['teams.microsoft.com']],
    _tunnel: ['VPN/代理隧道', 'tunnel', []]
  };
  function appName(id) { return id === '_unknown' ? '未识别' : id === '_local' ? '局域网' : (APP[id] ? APP[id][0] : id); }
  function appCat(id) { return APP[id] ? APP[id][1] : 'unknown'; }

  /* ═════════════ 设备(全部虚构; MAC 用本地管理地址) ═════════════ */
  var T = now();
  var DEVS = [
    { mac: '0a:7f:3c:41:9e:21', ip: '192.168.43.23', hostname: '小米 14', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 1, randomized_mac: true, auto_inherited_from: 'ce:41:7a:09:3b:62', auto_inherited_name: '小米 14', auto_inherited_score: 94,
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
      fg: { state: 'active', screen_state: 'active', app_id: 'douyin', name: '抖音', confidence: 0.93, label: '正在用：抖音', evidence_tags: ['即时连接', '触控划屏'], companion: { app_id: 'qqmusic', name: 'QQ音乐', mode: 'audio', label: '后台音频播放', bps: 192000 }, dual_stack: { v6_pct: 88, qos_cov: 'dual_stack_ok', escape_alert: false, limit_mbps: 24, actual_mbps: 16.2 }, reasons: ['域名解析后 22ms 立即连接，流量呈连续上划刷视频特征', '域名命中 *.douyinvod.com（IPv4/IPv6 双栈限速均已生效）', '播放缓冲充足，视频流畅播放保护中'] },
      traffic_type: { type: 'short_video', label: '刷短视频' },
      app_time_limits: [{ app_id: 'douyin', name: '抖音', category: 'video', minutes: 60, used_sec: 3120, used_min: 52, exhausted: false, enforced: true }],
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
      schedule: { windows: [{ days: [1, 2, 3, 4, 5], start: '02:00', end: '06:00', down_mbps: 12, up_mbps: 4, block: false }, { days: [0, 6], start: '02:30', end: '06:30', down_mbps: 12, up_mbps: 4, block: false }] } },
    { mac: '6a:0e:55:b1:9c:42', ip: '192.168.43.67', hostname: '客厅电视', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 7,
      base: [2.3 * MB, 60 * KB], usage8: 12.8 * GB, onlineMin: [190, 245, 160, 330, 410, 380, 205],
      ident: { type: 'tv', os: 'Android TV', os_ver: '11', brand: '小米', model: 'Redmi 智能电视 X65', confidence: 86, hostname: 'MiTV-AXSU', hostname_src: 'dhcp',
        services: ['_googlecast._tcp', '_miio._udp'], evidence: [{ src: 'mdns', detail: '_googlecast._tcp' }, { src: 'ssdp', detail: 'urn:schemas-upnp-org:device:MediaRenderer:1' }] },
      live: [['iqiyi', 0.95], ['tencent_video', 0.02]], hist: ['iqiyi', 'tencent_video', 'bilibili'],
      fg: { state: 'active', screen_state: 'idle_audio', app_id: 'iqiyi', name: '爱奇艺', confidence: 0.91, label: '正在播：爱奇艺', evidence_tags: ['缓冲续播'], dual_stack: { v6_pct: 91, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 18.4 }, reasons: ['4K DASH/HLS 分片下行 18.4 Mbps（IPv6 占 91%）', '无高频触控点按，处于沉浸观看态'] },
      traffic_type: { type: 'video', label: '4K 视频' } },
    { mac: '7e:c4:19:20:5a:8b', ip: '192.168.43.71', hostname: '小爱音箱', hostname_src: 'manual', vendor: 'Xiaomi', online: true, mark_id: 8,
      base: [48 * KB, 8 * KB], usage8: 0.25 * GB, onlineMin: [1380, 1440, 1440, 1440, 1440, 1440, 1440], whitelist: true,
      ident: { type: 'iot', os: 'Linux', brand: '小米', model: '小爱音箱 Pro', confidence: 76, hostname: 'xiaomi-wifispeaker-l15a', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'xiaomi-wifispeaker-l15a' }, { src: 'mdns', detail: '_miio._udp' }] },
      live: [['qqmusic', 0.85], ['netease_music', 0.12]], hist: ['qqmusic', 'netease_music'], traffic_type: { type: 'music', label: '在线音乐' } },
    { mac: '8a:3d:62:f0:11:c9', ip: '192.168.43.38', hostname: '华为 MatePad', hostname_src: 'manual', vendor: 'Huawei', online: true, mark_id: 9,
      status: 'allowed', base: [640 * KB, 52 * KB], usage8: 1.3 * GB, onlineMin: [112, 85, 120, 60, 95, 140, 96],
      ident: { type: 'tablet', os: 'HarmonyOS', os_ver: '4.2', brand: '华为', model: 'MatePad 11.5', confidence: 84, hostname: 'HUAWEI_MatePad', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'HUAWEI_MatePad' }, { src: 'sni', detail: '*.dbankcloud.cn · *.hicloud.com' }] },
      live: [['kuaishou', 0.74], ['wechat', 0.18]], hist: ['kuaishou', 'peacekeeper', 'wechat'],
      fg: { state: 'active', screen_state: 'active', app_id: 'kuaishou', name: '快手', confidence: 0.90, label: '正在用：快手', evidence_tags: ['短视频流', 'QUIC连接'], dual_stack: { v6_pct: 84, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 5.1 }, reasons: ['HTTPS/QUIC 分片连续拉流，命中 *.kwimgs.com', '上划切换特征明显'] },
      traffic_type: { type: 'short_video', label: '刷短视频' } },
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
      merge_suggestion: { old_mac: 'ae:14:7c:2b:90:d5', old_name: 'Redmi K60', score: 68, old_last_seen: T - 120,
        reasons: ['DHCP 指纹相同（android-dhcp-14）', 'TLS 指纹相同（3 个）', '常用应用重合：微信、小红书、高德地图', '主机名不同（新 MAC 没上报主机名）'] } },
    { mac: 'ae:14:7c:2b:90:d5', ip: '192.168.43.60', hostname: 'Redmi-K60', hostname_src: 'dhcp', vendor: 'Xiaomi', online: true, mark_id: 13,
      base: [340 * KB, 42 * KB], usage8: 1.8 * GB, onlineMin: [128, 165, 92, 140, 110, 180, 135],
      ident: { type: 'phone', os: 'Android', os_ver: '14', brand: '小米', model: 'Redmi K60', confidence: 80, hostname: 'Redmi-K60', hostname_src: 'dhcp',
        evidence: [{ src: 'dhcp', detail: 'option 60 = android-dhcp-14' }, { src: 'hostname', detail: 'Redmi-K60' }, { src: 'sni', detail: '*.bilivideo.com · *.xiaohongshu.com' }] },
      live: [['bilibili', 0.65], ['wechat', 0.22], ['amap', 0.08]], hist: ['bilibili', 'wechat', 'xiaohongshu', 'amap'],
      fg: { state: 'active', screen_state: 'active', app_id: 'bilibili', name: 'B站', confidence: 0.89, label: '正在用：B站', evidence_tags: ['弹幕长连', '视频分片'], dual_stack: { v6_pct: 79, qos_cov: 'dual_stack_ok', escape_alert: false, actual_mbps: 2.7 }, reasons: ['SNI 命中 upos-sz-mirrorcos.bilivideo.com 与 api.bilibili.com'] },
      traffic_type: { type: 'video', label: '在线视频' } }
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
  function isDevActive(d) {
    return !!(d && d.online && (MOCK_HS_ACTIVE || (SIM && SIM.enabled && d.sim)));
  }
  function visibleDevs() {
    var simOn = !!(SIM && SIM.enabled);
    return DEVS.filter(function (d) { return simOn || !d.sim; });
  }
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
      if (!isDevActive(d) || e.blocked) rx = tx = 0;
      if (e.down_mbps > 0) rx = Math.min(rx, e.down_mbps * 125000 * rnd(0.9, 0.97));
      if (e.up_mbps > 0) tx = Math.min(tx, e.up_mbps * 125000 * rnd(0.9, 0.97));
      d.cur = [round(rx), round(tx)];
      d.rx_bytes += rx * dt; d.tx_bytes += tx * dt;
      if (d.sim && SIM && Array.isArray(SIM.devices)) {
        for (var si = 0; si < SIM.devices.length; si++) {
          if (SIM.devices[si].mac === d.mac) {
            SIM.devices[si].cur_rx_bps = d.cur[0];
            SIM.devices[si].cur_tx_bps = d.cur[1];
            SIM.devices[si].online = true;
          }
        }
      }
    });
  }
  function liveApps(d) {
    if (!isDevActive(d) || !d.live.length) return [];
    var tot = d.cur[0] + d.cur[1];
    return d.live.map(function (x) {
      var c = appCat(x[0]);
      return { id: x[0], name: appName(x[0]), category: c, bps: round(tot * x[1] * rnd(0.88, 1.12)), share: x[1], system: /^system|cloud/.test(c) };
    }).filter(function (a) { return a.bps > 0; }).sort(function (a, b) { return b.bps - a.bps; });
  }
  function devRow(d) {
    var e = effective(d), t = now(), isOn = isDevActive(d);
    var r = {
      mac: d.mac, ip: d.ip, hostname: d.hostname, hostname_src: d.hostname_src, vendor: d.vendor, iface: d.sim ? 'sim' : IFACE,
      sim: !!d.sim, status: d.status, online: isOn, last_seen: isOn ? t - 1 - (hashStr(d.mac) % 3) : (d.last_seen || t - 60),
      rx_bps: isOn ? d.cur[0] : 0, tx_bps: isOn ? d.cur[1] : 0, rx_bytes: round(d.rx_bytes), tx_bytes: round(d.tx_bytes),
      randomized_mac: !!d.randomized_mac, mark_id: d.mark_id,
      limit_enabled: d.limit_enabled !== false && (d.down_mbps > 0 || d.up_mbps > 0), down_mbps: d.down_mbps, up_mbps: d.up_mbps,
      delay_enabled: d.delay_ms > 0 || d.jitter_ms > 0 || d.loss_pct > 0, delay_ms: d.delay_ms, jitter_ms: d.jitter_ms, loss_pct: d.loss_pct,
      sqm_enabled: !!d.sqm_enabled, whitelist: !!d.whitelist, app_qos: !!d.app_qos,
      ident: d.ident || null, effective: e,
      quota: null, schedule: null,
      dpi_apps: d.hist.slice(0, 5).map(function (id, i) { return { id: id, name: appName(id), category: appCat(id), confidence: i < 3 ? 'high' : 'med', count: 40 - i * 7 }; }),
      live_apps: liveApps(d)
    };
    if (d.sim_type) r.sim_type = d.sim_type;
    if (isOn && d.fg) r.fg = d.fg;
    if (isOn && d.traffic_type) r.traffic_type = d.traffic_type;
    if (isOn && d.live_call) r.live_call = d.live_call;
    if (d.vpn) r.vpn = d.vpn;
    if (d.merge_suggestion) r.merge_suggestion = d.merge_suggestion;
    if (d.auto_inherited_from) {
      r.auto_inherited_from = d.auto_inherited_from;
      r.auto_inherited_name = d.auto_inherited_name || '';
      r.auto_inherited_score = d.auto_inherited_score || 0;
    }
    var mFromList = Object.keys(ALIASES).filter(function (om) { return ALIASES[om] === d.mac; });
    if (mFromList.length) {
      r.merged_from = mFromList[0];
      r.merged_from_list = mFromList;
      var mArch = MERGE_ARCHIVES[mFromList[0]];
      r.merged_from_name = (mArch && mArch.from_name) || d.auto_inherited_name || mFromList[0];
    }
    if (d.quota) { var qs = quotaState(d.quota); r.quota = Object.assign({}, d.quota, { state: qs.state, exceeded_period: qs.period, applied: e.reason === 'quota', month_start: Math.floor(new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime() / 1000) }); }
    if (d.schedule) r.schedule = { windows: d.schedule.windows, active_window_index: schedIdx(d) };
    if (d.app_time_limits.length) r.app_time_limits = d.app_time_limits;
    if (d.category_blocks.length) r.category_blocks = d.category_blocks;
    return r;
  }
  function ipNum(ip) { var a = String(ip).split('.'); return a.length === 4 ? ((+a[0]) * 16777216 + (+a[1]) * 65536 + (+a[2]) * 256 + (+a[3])) : 0; }
  function devSig() {
    var simOn = !!(SIM && SIM.enabled);
    return hashStr((MOCK_HS_ACTIVE ? '1#' : '0#') + (simOn ? 'S#' : '_') + visibleDevs().map(function (d) {
      return [d.mac, d.ip, isDevActive(d), d.status, d.down_mbps, d.up_mbps, d.delay_ms, d.jitter_ms, d.loss_pct, d.sqm_enabled, d.whitelist, d.app_qos, d.hostname,
        JSON.stringify(d.quota || ''), JSON.stringify(d.schedule || ''), JSON.stringify(d.app_time_limits), JSON.stringify(d.category_blocks), d.merge_suggestion ? 1 : 0, schedIdx(d)].join('|');
    }).join('#') + '@' + JSON.stringify(ALIASES)).toString(16) + 'c0ffee';
  }
  function devicesPayload() {
    stepRates();
    var simOn = !!(SIM && SIM.enabled);
    var rows = visibleDevs().sort(function (a, b) { return ipNum(a.ip) - ipNum(b.ip); }).map(devRow);
    return { devices: rows, whitelist_mode: CFG.whitelist_mode, remote_enabled: CFG.remote_enabled, sim: simOn, sim_active: simOn, hotspot_active: MOCK_HS_ACTIVE, hotspot_iface: MOCK_HS_ACTIVE ? IFACE : (simOn ? 'sim' : ''), hotspot_ip: MOCK_HS_ACTIVE ? GW : '', devices_sig: devSig() };
  }
  function liveSummary() {
    stepRates();
    var simOn = !!(SIM && SIM.enabled);
    var list = visibleDevs(), on = 0, rx = 0, tx = 0;
    list.forEach(function (d) { if (isDevActive(d)) { on++; rx += d.cur[0]; tx += d.cur[1]; } });
    var hsFlows = typeof v6MockComputeHotspotFlows === 'function' ? v6MockComputeHotspotFlows() : (on > 0 ? 18 : 0);
    var hostFlows = typeof v6MockComputeHostFlows === 'function' ? v6MockComputeHostFlows() : 25;
    return { hotspot_active: MOCK_HS_ACTIVE, sim: simOn, sim_active: simOn, iface: MOCK_HS_ACTIVE ? IFACE : (simOn ? 'sim' : ''), hotspot_iface: MOCK_HS_ACTIVE ? IFACE : (simOn ? 'sim' : ''), hotspot_ip: MOCK_HS_ACTIVE ? GW : '', iface_method: 'tethering', online: on, total: list.length,
      rx_bps: rx, tx_bps: tx, hotspot_flows: hsFlows, host_flows: hostFlows, devices_sig: devSig(), backend_version: VER, backend_version_code: VCODE, autorate: AUTORATE };
  }

  /* ═════════════ 配置 / 告警 / 模板 等全局状态 ═════════════ */
  var CFG = {
    auth_required: true, remote_auth_required: true, whitelist_mode: false, remote_enabled: true, hotspot_autostart: true, hotspot_ssid: 'HNC-Demo-5G', hotspot_delay_sec: 30,
    hotspot_time_enable: false, hotspot_time_start: '07:00', hotspot_time_end: '23:30', hotspot_charging_only: false, hotspot_iface: '',
    global_shaper_enabled: false, global_shaper_down: '', global_shaper_up: '', flywheel_exclude_user: ['com.example.proxyclient'],
    clsact_bpf_mode: 'auto', tc_leaf_aqm: 'auto', stale_rule_ttl_days: 30, quic_block: false, discover_cert_probe: true,
    conn_block_dns_layer: 'available', sim_enabled: false,
    offload_guard: { mode: 'auto', offload_state: 'IDLE', fallback_active: true, since: T - 3600, detail: '受控限速策略活跃，eBPF 二层加速与慢路径整形已协同生效', last_check: T - 18, slowpath: 'active', clsact: 'on', iface: IFACE },
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
  var MOCK_SIGNAL = {
    available: true, mode: 'cellular', rat: '5G SA', display_rat: '5G-A', is_5ga: true,
    dual_sim: true, max_slots: 2,
    slot: 2, sub_id: 2, carrier: '中国移动', custom_name: '中国移不动', carrier_short: '移动', mcc_mnc: '46000',
    sharing_mode: '2.6GHz+700MHz 移广双载波共享', upstream_iface: 'rmnet_data2',
    band: 'n41', bandwidth_mhz: 100, band_combo: 'n41+n28', total_bw_mhz: 130, ca_count: 2,
    arfcn: 504990, freq_mhz: 2600,
    band_trait: '5G SA / 5G-A 独立组网双载波聚合 n41+n28（总带宽 130MHz） · 兼顾 2.6GHz 极速大带宽与 700MHz 强穿墙稳上行',
    rsrp_dbm: -84, rsrq_db: -8, sinr_db: 21, has_sinr: true, has_rsrq: true,
    rssi_dbm: -56, pci: 384, has_pci: true,
    lte_pci: 0, has_lte_pci: false, lte_rsrp_dbm: 0, lte_rsrq_db: 0, lte_sinr_db: 0, has_lte_sinr: false,
    rsrp_label: '极强', sinr_label: '极纯净', rsrq_label: '基站空闲',
    speed_potential_pct: 100, speed_potential_text: '可跑满套餐峰值',
    bars: 4, quality: 'excellent', quality_cn: '5G-A 极佳', rf_ceiling_factor: 1.0,
    diagnosis: 'ok', diagnosis_cn: '双卡 5G SA 独立组网在线，主卡 5G-A 多载波通道（n41+n28）信号纯净、基站空闲，热点可跑满高速带宽',
    carriers: [
      { is_primary: true, net_type: 'NR', band: 'n41', bw_mhz: 100, arfcn: 504990, freq_mhz: 2600, pci: 384, has_pci: true },
      { is_primary: false, net_type: 'NR', band: 'n28', bw_mhz: 30, arfcn: 145600, freq_mhz: 700, pci: 192, has_pci: true }
    ],
    sim_slots: [
      { slot: 1, sub_id: 1, carrier: '中国联通', carrier_short: '联通', rat: '5G SA', display_rat: '5G SA', is_5ga: false, band: 'n78', bandwidth_mhz: 100, rsrp_dbm: -88, sinr_db: 19, bars: 4, is_default_data: false, standby_sa: true },
      { slot: 2, sub_id: 2, carrier: '中国移动', custom_name: '中国移不动', carrier_short: '移动', rat: '5G SA', display_rat: '5G-A', is_5ga: true, band: 'n41', band_combo: 'n41+n28', total_bw_mhz: 130, rsrp_dbm: -84, sinr_db: 21, bars: 4, is_default_data: true, standby_sa: true }
    ],
    handover_count: 1, jitter_db: 4, min_dbm: -87, max_dbm: -83, avg_dbm: -85,
    interference_pct: 14, interference_level: 'clean', interference_label: '信道纯净低噪',
    interference_sources: [],
    history: [],
    updated_at: T
  };
  function _recalcMockSignalMeta() {
    var h = MOCK_SIGNAL.history;
    if (!h.length) return;
    var mn = h[0].rsrp_dbm, mx = h[0].rsrp_dbm, sm = 0, ho = 0;
    for (var i = 0; i < h.length; i++) {
      var v = h[i].rsrp_dbm;
      if (v < mn) mn = v;
      if (v > mx) mx = v;
      sm += v;
      if (i > 0 && h[i].pci !== h[i - 1].pci) ho++;
    }
    var cur = h[h.length - 1];
    MOCK_SIGNAL.rsrp_dbm = cur.rsrp_dbm;
    MOCK_SIGNAL.sinr_db = cur.sinr_db;
    MOCK_SIGNAL.has_sinr = true;
    MOCK_SIGNAL.rsrq_db = cur.rsrq_db;
    MOCK_SIGNAL.pci = cur.pci;
    MOCK_SIGNAL.rssi_dbm = cur.rsrp_dbm + 28;
    MOCK_SIGNAL.min_dbm = mn;
    MOCK_SIGNAL.max_dbm = mx;
    MOCK_SIGNAL.avg_dbm = round(sm / h.length);
    MOCK_SIGNAL.jitter_db = Math.max(1, mx - mn);
    MOCK_SIGNAL.handover_count = ho;
    MOCK_SIGNAL.rsrp_label = cur.rsrp_dbm >= -85 ? '极强' : (cur.rsrp_dbm >= -95 ? '良好' : '一般');
    MOCK_SIGNAL.sinr_label = cur.sinr_db >= 20 ? '极纯净' : (cur.sinr_db >= 13 ? '纯净' : '轻度干扰');
    var pEm = lim(round((23 - cur.sinr_db) * 3.4), 6, 92);
    var pLoad = lim(round((-7 - cur.rsrq_db) * 7.2), 8, 92);
    var pFade = lim(round(MOCK_SIGNAL.jitter_db * 4.5 + ho * 12), 6, 92);
    var pBh = lim(round(Math.max(0, cur.rtt_ms - 18) * 2.2), 6, 92);
    var lvlOf = function (p) { return p >= 75 ? 'severe' : (p >= 50 ? 'moderate' : (p >= 25 ? 'mild' : 'clean')); };
    MOCK_SIGNAL.interference_sources = [
      { id: 'co_channel', name: '同频与邻区电磁干扰', available: true, pct: pEm, level: lvlOf(pEm), value: 'SINR ' + cur.sinr_db + ' dB', summary: cur.sinr_db >= 13 ? '同频邻区底噪干净，256QAM 高阶调制稳定' : '存在邻区同频重叠干扰，建议移近窗边' },
      { id: 'air_load', name: '基站空口信道负载', available: true, pct: pLoad, level: lvlOf(pLoad), value: 'RSRQ ' + cur.rsrq_db + ' dB', summary: 'n41+n28 双载波资源块充裕，下行调度响应及时' },
      { id: 'multipath_handover', name: '多径衰落与乒乓切换', available: true, pct: pFade, level: lvlOf(pFade), value: 'Δ' + MOCK_SIGNAL.jitter_db + ' dB' + (ho > 0 ? ' · ' + ho + '次切换' : ''), summary: ho > 0 ? '近期完成 1 次更优扇区切换，当前驻留 PCI ' + cur.pci + ' 稳定' : '驻留主服务小区锁频稳定，无乒乓切换' },
      { id: 'backhaul_jitter', name: '回程排队延迟抖动', available: true, pct: pBh, level: lvlOf(pBh), value: 'RTT ' + cur.rtt_ms.toFixed(1) + ' ms', summary: '上游 rmnet_data2 回程延迟平稳，零缓冲区膨胀' }
    ];
    MOCK_SIGNAL.interference_pct = round(pEm * 0.38 + pLoad * 0.26 + pFade * 0.20 + pBh * 0.16);
    MOCK_SIGNAL.interference_level = lvlOf(MOCK_SIGNAL.interference_pct);
    MOCK_SIGNAL.interference_label = MOCK_SIGNAL.interference_pct >= 75 ? '强干扰易跳Ping' : (MOCK_SIGNAL.interference_pct >= 50 ? '中度射频干扰' : (MOCK_SIGNAL.interference_pct >= 25 ? '轻度环境干扰' : '信道纯净低噪'));
    MOCK_SIGNAL.updated_at = cur.ts;
  }
  (function seedMockSignalHistory() {
    var r = srand('sig-seed-rc2');
    var baseR = -85, baseS = 20;
    for (var i = 23; i >= 0; i--) {
      baseR = lim(round(baseR + (r() - 0.48) * 2.2), -88, -82);
      baseS = lim(round(baseS + (r() - 0.48) * 2.4), 16, 23);
      var pciVal = i > 17 ? 381 : 384;
      MOCK_SIGNAL.history.push({
        ts: T - i * 3,
        rsrp_dbm: baseR,
        sinr_db: baseS,
        has_sinr: true,
        rsrq_db: -8 - Math.floor(r() * 2),
        pci: pciVal,
        has_pci: true,
        band: 'n41',
        rtt_ms: +(20.2 + r() * 4.2).toFixed(1)
      });
    }
    _recalcMockSignalMeta();
  })();
  var _lastSigStepMs = Date.now();
  function stepMockSignal(force) {
    var nowMs = Date.now();
    if (!force && nowMs - _lastSigStepMs < 1800) return;
    _lastSigStepMs = nowMs;
    var h = MOCK_SIGNAL.history;
    var prev = h.length ? h[h.length - 1] : { ts: now() - 3, rsrp_dbm: -84, sinr_db: 21, rsrq_db: -8, pci: 384, rtt_ms: 21.5 };
    var nextTs = Math.max(now(), prev.ts + 1);
    var nextRsrp = lim(round(prev.rsrp_dbm + rnd(-1.4, 1.4) + (-84 - prev.rsrp_dbm) * 0.25), -89, -81);
    var nextSinr = lim(round(prev.sinr_db + rnd(-1.6, 1.6) + (20.5 - prev.sinr_db) * 0.25), 15, 24);
    var nextRsrq = lim(round(prev.rsrq_db + rnd(-0.8, 0.8) + (-8.2 - prev.rsrq_db) * 0.3), -11, -7);
    var nextRtt = +(lim(prev.rtt_ms + rnd(-1.2, 1.2) + (21.5 - prev.rtt_ms) * 0.25, 18.5, 27.5)).toFixed(1);
    h.push({
      ts: nextTs,
      rsrp_dbm: nextRsrp,
      sinr_db: nextSinr,
      has_sinr: true,
      rsrq_db: nextRsrq,
      pci: 384,
      has_pci: true,
      band: 'n41',
      rtt_ms: nextRtt
    });
    if (h.length > 60) h.splice(0, h.length - 60);
    _recalcMockSignalMeta();
  }
  var PU_CFG = { billing_day: 1, warn_percent: 80, plan_sim1_gb: 30, plan_sim2_gb: 100, anchor_sim1_gb: 0, anchor_sim2_gb: 0, use_netstats: 'auto' };
  var SELF_ON = { toggle: true, auto_expand: true, auto_promote: false };
  var DNS = { enabled: false, block_mode: 'nxdomain', log_queries: false };
  var FG_ENGINE = 'hmm';
  var SIM = { enabled: false, devices: [] };
  var REC_STATE = { recording: false, minutes: 10, started_at: 0 };
  var ALIASES = { 'ce:41:7a:09:3b:62': '0a:7f:3c:41:9e:21' };
  var MERGE_ARCHIVES = {
    'ce:41:7a:09:3b:62': {
      from_mac: 'ce:41:7a:09:3b:62',
      to_mac: '0a:7f:3c:41:9e:21',
      from_name: '小米 14 (第二台/旧MAC)',
      to_name: '小米 14',
      merged_at: T - 3600,
      has_archive: true,
      auto_inherit: true,
      score: 94,
      snap: {
        mac: 'ce:41:7a:09:3b:62', ip: '192.168.43.88', hostname: 'Xiaomi-14-B', hostname_src: 'dhcp',
        vendor: 'Xiaomi', online: false, last_seen: T - 3600, mark_id: 12, randomized_mac: true,
        status: 'allowed', down_mbps: 0, up_mbps: 0, delay_ms: 0, jitter_ms: 0, loss_pct: 0,
        k: [1, 1], cur: [0, 0], auto: ['Xiaomi-14-B', 'dhcp'], blocks: [],
        base: [0, 0], usage8: 0.42 * GB, rx_bytes: 0.05 * GB, tx_bytes: 0.004 * GB,
        onlineMin: [42, 0, 0, 0, 0, 0, 0], app_time_limits: [], category_blocks: [],
        ident: { type: 'phone', os: 'Android', os_ver: '15', brand: '小米', model: 'Xiaomi 14', confidence: 88 },
        live: [], hist: ['wechat', 'douyin']
      }
    }
  };
  var MUTEX_APART_COUNT = 1;
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
    var cell = tot.hs + tot.lc, sim1c = 0.36 * GB * Math.min(1, cycDays / 3), sim1t = period === 'today' ? round(24 * MB * dayFrac()) : round(sim1c), plan1 = PU_CFG.plan_sim1_gb * GB, plan2 = PU_CFG.plan_sim2_gb * GB;
    var unattrBytes = round(14.6 * MB);
    var r = {
      period: period, since: Math.floor((period === 'cycle' || period === 'month' ? cs : dayAt(n - 1)).getTime() / 1000), until: now(),
      billing_day: PU_CFG.billing_day, cycle_start: Math.floor(cs.getTime() / 1000), cycle_end: Math.floor(ce.getTime() / 1000), config: clone(PU_CFG),
      max_slots: 2,
      unattributed_cycle_bytes: unattrBytes,
      totals: { cellular: trio(cell + sim1t, 0.08), wifi: trio(tot.lw, 0.1), hotspot: trio(tot.hs, 0.07), local: trio(tot.lc + tot.lw, 0.1) },
      hotspot_via: { cell: trio(tot.hs, 0.07), wifi: trio(0, 0), unknown: trio(0, 0) },
      by_sim: [
        { slot: 1, sub_id: 1, carrier: '中国联通', carriers: ['中国联通'], rat: '5G SA', display_rat: '5G SA', band: 'n78', total: sim1t, rx: round(sim1t * 0.9), tx: round(sim1t * 0.1), local_rx: round(sim1t * 0.9), local_tx: round(sim1t * 0.1),
          hotspot_total: 0, cycle_used: round(sim1c), netstats_cycle_used: round(sim1c * 1.018), plan_bytes: plan1, used_pct: plan1 ? sim1c / plan1 * 100 : null, is_default_data: false },
        { slot: 2, sub_id: 2, carrier: '中国移动', custom_name: '中国移不动', carriers: ['中国移动'], rat: '5G SA', display_rat: '5G-A', is_5ga: true, band: 'n41+n28', total: round(cell), rx: round(cell * 0.92), tx: round(cell * 0.08), local_rx: round(tot.lc * 0.9), local_tx: round(tot.lc * 0.1),
          hotspot_total: round(tot.hs), cycle_used: round(cyc), netstats_cycle_used: round(cyc * 1.013), plan_bytes: plan2, used_pct: plan2 ? cyc / plan2 * 100 : null, is_default_data: true }
      ],
      by_day: days.map(function (s) { return { date: ymdDash(s.d), cell: round(s.hs + s.lc), wifi: round(s.lw), hotspot: round(s.hs), local: round(s.lc + s.lw) }; }),
      default_sim: { slot: 2, carrier: '中国移动', custom_name: '中国移不动', sub_id: 2, rat: '5G SA', display_rat: '5G-A', is_5ga: true },
      sources: { sim_detect: 'ok', sim_source: 'isub', max_slots: 2, hotspot_iface: IFACE, upstream: 'cell', counters: '/proc/net/dev', last_sample: now() - 37 },
      primary_source: PU_CFG.use_netstats === 'prefer' ? 'netstats' : 'hnc',
      calibration: PU_CFG.use_netstats === 'off' ? { status: 'unavailable', reason: 'disabled' } :
        { status: 'ok', hnc_vs_netstats_pct: -1.3, checked_at: now() - 1500, netstats_cell_by_sim: [{ slot: 1, hnc_vs_netstats_pct: -1.8 }, { slot: 2, hnc_vs_netstats_pct: -1.3 }], text_cn: [] }
    };
    if (period === 'today') r.by_hour = dayStat(0).h.map(function (x, h) { return { h: h, cell: round(x.hs + x.lc), wifi: round(x.lw), hotspot: round(x.hs), local: round(x.lc + x.lw) }; });
    return r;
  }

  /* ═════════════ 实时连接 ═════════════ */
  function devConns(d) {
    stepRates();
    var isOn = isDevActive(d);
    var t = now(), list = [], tot = isOn ? d.cur[0] + d.cur[1] : 0, rxShare = tot ? d.cur[0] / tot : 0.9;
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
      var v = isOn ? tot * c.w * rnd(0.8, 1.2) : 0; delete c.w;
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
    visibleDevs().forEach(function (d) {
      if (isDevActive(d)) {
        var r = devConns(d);
        c[d.mac] = { n: r.total, bps: r.bps };
      }
    });
    return { ok: true, counts: c, readable: true, acct: true };
  }

  /* ═════════════ DPI 状态(dpid) + 本机应用归因 ═════════════ */
  var DPI_UP0 = 7 * 3600 + 23 * 60;
  function selfState() {
    var t = now(), up = (Date.now() - PAGE_T0) / 1000;
    var A = [
      ['10234', 'com.ss.android.ugc.aweme', '抖音', 3, 412, 1.24 * GB, ['v26-dy.douyinvod.com', 'api5-normal-lq.amemv.com', 'p26-sign.douyinpic.com'], ['douyin'], { douyin: 388 }],
      ['10198', 'com.tencent.mm', '微信', 3, 1286, 412 * MB, ['szextshort.weixin.qq.com', 'mmsns.qpic.cn', 'wx.qlogo.cn', 'dns.weixin.qq.com'], ['wechat'], { wechat: 1204 }],
      ['10311', 'tv.danmaku.bili', 'B站', 3, 201, 655 * MB, ['upos-sz-mirrorcos.bilivideo.com', 'api.bilibili.com'], ['bilibili'], { bilibili: 190 }],
      ['10287', 'com.autonavi.minimap', '高德地图', 2, 96, 38 * MB, ['m5.amap.com', 'webrd01.is.autonavi.com'], ['amap'], { amap: 91 }],
      ['10342', 'com.taobao.taobao', '淘宝', 1, 154, 96 * MB, ['acs.m.taobao.com', 'gw.alicdn.com'], ['taobao'], { taobao: 6 }],
      ['10405', 'com.tencent.tmgp.sgame', '王者荣耀', 1, 58, 210 * MB, ['pvp.qq.com', 'gamesafe.qq.com'], ['honor_of_kings'], { honor_of_kings: 52 }],
      ['10377', 'com.netease.cloudmusic', '网易云音乐', 1, 33, 74 * MB, ['interface.music.163.com'], ['netease_music'], { netease_music: 29 }],
      ['10420', 'com.example.proxyclient', '代理客户端', 1, 12, 156 * MB, [], [], {}, true],
      ['1000', 'android', 'Android 系统', 2, 640, 22 * MB, ['connectivitycheck.gstatic.com', 'time.android.com'], [], {}, false, true],
      ['10045', 'com.heytap.market', '软件商店', 2, 41, 180 * MB, ['api-cn.store.heytapmobi.com'], [], {}, false, true],
      ['10052', 'com.coloros.weather.service', '天气', 1, 19, 3 * MB, ['weather.heytapmobi.com'], [], {}, false, true]
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
    visibleDevs().forEach(function (d) {
      var isOn = isDevActive(d);
      if (!isOn && t - (d.last_seen || 0) > 86400) return;
      var top = d.hist.map(function (id, i) { return { id: id, name: appName(id), category: appCat(id), confidence: i < 2 ? 'high' : i < 4 ? 'med' : 'low', count: 60 - i * 9 }; });
      var doms = []; d.hist.forEach(function (id) { (APP[id] ? APP[id][2] : []).forEach(function (x) { doms.push(x); }); });
      var r = srand('cl' + d.mac);
      clients[d.mac] = {
        client_mac: d.mac, client_ip: d.ip, client_ips: [d.ip, '2408:8456:3c10:9a2:' + d.mac.slice(-5).replace(':', '') + ':1'], last_seen: isOn ? t - 2 : (d.last_seen || t - 60), last_hostname: d.hostname || '',
        sim: !!d.sim,
        dns_events: round(300 + r() * 2400), tls_events: round(200 + r() * 1800), rx_bytes: round((d.usage8 || 0.5 * GB) / 8 * 0.93), tx_bytes: round((d.usage8 || 0.5 * GB) / 8 * 0.07), last_sni: doms[0] || '',
        top_apps: top, top_hostnames: doms.slice(0, 6).map(function (x, i) { return { name: x, count: 120 - i * 15 }; }), top_sni: doms.slice(0, 4).map(function (x, i) { return { name: x, count: 80 - i * 12 }; })
      };
    });
    var idb = 0.89;
    var MOCK_L3_SUBS = [
      'hnc-curated-v6.1.0-rc.8-dedup#00-core-meta',
      'hnc-curated-v6.1.0-rc.8#01-short-video', 'hnc-curated-v6.1.0-rc.8#02-video-live', 'hnc-curated-v6.1.0-rc.8#03-social-im',
      'hnc-curated-v6.1.0-rc.8#04-games-cn', 'hnc-curated-v6.1.0-rc.8#05-games-global', 'hnc-curated-v6.1.0-rc.8#06-shopping-life',
      'hnc-curated-v6.1.0-rc.8#07-music-audio', 'hnc-curated-v6.1.0-rc.8#08-reading-news', 'hnc-curated-v6.1.0-rc.8#09-office-edu',
      'hnc-curated-v6.1.0-rc.8#10-cloud-drive', 'hnc-curated-v6.1.0-rc.8#11-finance-bank', 'hnc-curated-v6.1.0-rc.8#12-travel-map',
      'hnc-curated-v6.1.0-rc.8#13-ai-tools', 'hnc-curated-v6.1.0-rc.8#14-dev-tech', 'hnc-curated-v6.1.0-rc.8#15-app-stores',
      'hnc-curated-v6.1.0-rc.8#16-oem-vendors', 'hnc-curated-v6.1.0-rc.8#17-iot-smart', 'hnc-curated-v6.1.0-rc.8#18-tv-ott',
      'hnc-curated-v6.1.0-rc.8#19-carrier-isp', 'hnc-curated-v6.1.0-rc.8#20-gov-public', 'hnc-curated-v6.1.0-rc.8#21-auto-ev',
      'hnc-curated-v6.1.0-rc.8#22-health-sport', 'hnc-curated-v6.1.0-rc.8#23-food-retail', 'hnc-curated-v6.1.0-rc.8#24-social-global',
      'hnc-curated-v6.1.0-rc.8#25-stream-global', 'hnc-curated-v6.1.0-rc.8#26-browser-search', 'hnc-curated-v6.1.0-rc.8#27-mail-collab',
      'hnc-curated-v6.1.0-rc.8#28-security-dns', 'hnc-curated-v6.1.0-rc.8#29-ad-telemetry', 'hnc-curated-v6.1.0-rc.8#30-cdn-infra',
      'v2fly-2c892a618f4e#46-v2fly-a', 'hnc-curated-v6.1.0-rc.8#47-v2fly-b',
      'hnc-curated-v6.1.0-rc.8#95-system-updates', 'hnc-curated-v6.1.0-rc.8#96-system-updates-v6'
    ];
    return {
      available: true,
      state: {
        schema_version: '2.0', generated_at: t - 2, version: VER, mode: 'af_packet', interface: MOCK_HS_ACTIVE ? IFACE : ((SIM && SIM.enabled) ? 'sim' : ''), tls_reassembly: true, ipv6_capture: true, offload_hint: false,
        uptime_s: round(up), stats: stats, clients: clients, client_count: Object.keys(clients).length, health: 'ok', rebind_count: 1,
        unique_hostnames: 2610 + round(up / 300), unique_sni: 1843 + round(up / 400), unique_ja4: 96, l3_enabled: true, l3_rule_version: 'external-d:' + MOCK_L3_SUBS.join(','), dfp_enabled: true, dfp_rule_version: 'hnc-dfp-v6.1.0-rc.8',
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
    ['video', ['douyin', '抖音'], ['kuaishou', '快手'], ['weishi', '微视'], ['bilibili', 'B站'], ['iqiyi', '爱奇艺'], ['tencent_video', '腾讯视频'], ['youku', '优酷'], ['douyu', '斗鱼'], ['huya', '虎牙']],
    ['game', ['honor_of_kings', '王者荣耀'], ['genshin', '原神'], ['peacekeeper', '和平精英'], ['eggy_party', '蛋仔派对'], ['mc', '我的世界'], ['nintendo_online', 'Nintendo Switch Online']],
    ['social', ['wechat', '微信'], ['xiaohongshu', '小红书'], ['weibo', '微博'], ['qq', 'QQ']],
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
    var d = needDev(mac), t = now(), t0 = days === 1 ? midnight() : t - days * 86400, r = srand('fg' + mac + days + ymd(dayAt(0))), isOn = isDevActive(d);
    var ids = d.hist.filter(function (id) { return id.charAt(0) !== '_'; }).slice(0, 4), sessions = [], by = {};
    if (!ids.length || !isOn && !d.last_seen) return { ok: true, sessions: [], by_app: [], current: null };
    var x = t0 + 7.5 * 3600 * (days === 1 ? 1 : 0.3), end = isOn ? t : d.last_seen;
    while (x < end - 300) {
      var id = ids[Math.floor(Math.pow(r(), 1.6) * ids.length)], len = 300 + r() * 2400, gap = 120 + r() * (days === 1 ? 2400 : 9000);
      var s = { app_id: id, name: appName(id), start: round(x), end: round(Math.min(end, x + len)) };
      sessions.push(s); by[id] = by[id] || { app_id: id, name: appName(id), fg_sec: 0, active_sec: 0 }; by[id].fg_sec += s.end - s.start; by[id].active_sec += round((s.end - s.start) * (1.05 + r() * 0.3));
      x += len + gap;
    }
    if (isOn && d.fg && d.fg.app_id) { var last = sessions[sessions.length - 1]; if (last) { last.app_id = d.fg.app_id; last.name = d.fg.name; last.end = 0; } }
    return { ok: true, mac: mac, days: days, engine: FG_ENGINE, sessions: sessions, by_app: Object.keys(by).map(function (k) { return by[k]; }).sort(function (a, b) { return b.fg_sec - a.fg_sec; }), current: d.fg || null };
  }

  /* ═════════════ 自检报告 ═════════════ */
  function selfcheck() {
    var leaseCnt = visibleDevs().length;
    var S2 = [
      ['system', '机型与系统', [['model', '机型', 'ok', '示例机型 · Android 16'], ['kernel', '内核', 'ok', '6.6.56 GKI'], ['root', 'Root 方案', 'ok', 'KernelSU（Magic Mount）'], ['selinux', 'SELinux', 'info', 'Enforcing', '正常，HNC 规则已带 sepolicy']]],
      ['shaping', '限速能力', [['htb', 'HTB 限速', 'ok', '可用'], ['netem', '延迟注入 netem', 'ok', '可用'], ['ifb', '上行 IFB', 'ok', 'ifb0 可用'],
        ['aqm', '低延迟队列', 'ok', 'fq_codel', '内核原生支持 sch_fq_codel 智能公平队列，低延迟防缓冲膨胀已生效']]],
      ['firewall', '防火墙', [['ipt', 'iptables mangle', 'ok', '31 条 HNC 规则'], ['ip6t', 'ip6tables', 'ok', '可用'], ['xt_string', '名字层（xt_string）', 'ok', '可用']]],
      ['offload', '硬件加速', [['tether_offload', '热点硬件加速', 'ok', 'IDLE', '受控策略活跃，eBPF 二层加速与慢路径整形已协同生效'], ['guard', '兜底守护', 'ok', '自动 · eBPF 二层协同生效']]],
      ['network', '热点', [['iface', '热点接口', 'ok', IFACE + ' · 192.168.43.1/24'], ['dhcp', 'DHCP / 邻居表', 'ok', leaseCnt + ' 个租约'], ['upstream', '上游', 'ok', 'rmnet_data2（5G SA 蜂窝）']]],
      ['ipv6', 'IPv6', [['v6_neigh', 'IPv6 邻居', 'ok', '8 个地址, 6 台设备'], ['v6_uncovered', '未纳入限速的新地址', 'ok', '0']]],
      ['time', '时间', [['clock', '系统时间', 'ok', '正常'], ['auto_time', '自动同步时间', 'ok', '已开启']]],
      ['process', '进程', [['hotspotd', 'hotspotd', 'ok', '运行中'], ['dpid', 'hnc_dpid', 'ok', '运行中 · 7 小时'], ['watchdog', 'watchdog', 'ok', '心跳守护正常'], ['proc_goroutineleak', '后台任务泄漏检查', 'ok', '无残留 · 运行任务 18 个', '后台常驻任务健康巡检通过，无卡死或残留任务（耗时 2 ms）']]],
      ['ident', '识别引擎', [['rules', '规则库', 'ok', VER + ' · 3486 条'], ['capture', 'DPI 抓包', 'ok', 'AF_PACKET · ' + IFACE], ['fp', '指纹学习', 'info', '5 个可用指纹']]]
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

      var verdict = 'idle', statusLabel = '规则就绪（空闲）', reason = '限速规则已准备就绪，等待设备产生流量';
      if (isBlacklisted) {
        verdict = 'hit';
        statusLabel = '黑名单阻断生效';
        reason = '双栈防火墙设备阻断规则已生效，正在拦截该设备转发流量';
      } else if (outDownDelta + upDelta > 0 || outDownSent + snap.upSent > 0 || anyAppHit) {
        verdict = 'hit';
        statusLabel = '限速真实生效';
        var totalMb = ((outDownSent + snap.upSent) / MB).toFixed(2);
        var shapeCnt = outDownOver + outDownDrops + snap.upOver + snap.upDrops;
        reason = '限速规则已真实命中该设备流量（累计转发 ' + totalMb + ' MB，超速压制 ' + shapeCnt + ' 次）';
      } else if (!d.online) {
        verdict = 'idle';
        statusLabel = '就绪（设备离线）';
        reason = '限速规则已准备就绪，当前设备离线，重连上网后自动生效';
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
      ? ('限速规则真实生效：' + hitCnt + '/' + devicesOut.length + ' 台受控设备正在按规则限速（其余 ' + idleCnt + ' 台空闲待命）')
      : ('全部 ' + devicesOut.length + ' 台受控设备的限速规则已准备就绪，等待设备上网产生流量');

    var hsOrSim = MOCK_HS_ACTIVE || !!(SIM && SIM.enabled);
    var clsOn = hsOrSim && CFG.clsact_bpf_mode !== 'off';
    var out = {
      ok: true,
      checked_at: now(),
      iface: opts.iface || (MOCK_HS_ACTIVE ? IFACE : ((SIM && SIM.enabled) ? 'sim' : IFACE)),
      hotspot_active: hsOrSim,
      engine_mode: 'go_native_netlink',
      dataplane_tier: typeof v6DataplaneTierStatusPayload === 'function' ? v6DataplaneTierStatusPayload() : { active_tier: 'tier2_native_netlink' },
      mark_layout: 'orthogonal_v540_0xffff0000',
      netd_low16_protected: true,
      ipv6_quic_controlled: !!CFG.quic_block,
      bpf_maps: {
        mac_mark_entries: onlineMarked,
        ip_mark_entries: onlineMarked,
        tether_limit_zeroed: clsOn,
        clsact_attached: clsOn,
        ifb_redirect_prio2: clsOn
      },
      offload_guard: {
        slowpath_active: clsOn,
        tether_offload_disabled: clsOn,
        hwnat: clsOn ? 'disabled' : 'idle'
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
        message: '后台常驻任务健康检查通过：0 个异常残留（当前运行任务 ' + totalG + ' 个，耗时 2 ms）'
      };
    }
    return out;
  }

  /* ═════════════ GET 路由 ═════════════ */
  function rulesJson() {
    var o = { whitelist_mode: CFG.whitelist_mode, remote_enabled: CFG.remote_enabled, quic_block: CFG.quic_block, blacklist: [], devices: {} };
    DEVS.forEach(function (d) {
      if (d.sim) return;
      if (d.status === 'blocked') o.blacklist.push(d.mac);
      if (d.down_mbps || d.up_mbps || d.delay_ms || d.sqm_enabled || d.whitelist) o.devices[d.mac] = { mark_id: d.mark_id, limit_enabled: d.down_mbps > 0 || d.up_mbps > 0, down_mbps: d.down_mbps, up_mbps: d.up_mbps, delay_ms: d.delay_ms, jitter_ms: d.jitter_ms, loss_pct: d.loss_pct, sqm_enabled: !!d.sqm_enabled, whitelist: !!d.whitelist, ip: d.ip };
    });
    return o;
  }
  function logText() {
    var t = Date.now(), L = [], fmt = function (ms) { var d = new Date(ms); return ymdDash(d) + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()); };
    var M = ['[service] HNC ' + VER + ' 启动完成 · 热点接口 ' + IFACE, '[hotspotd] 新设备 d2:6e:4a:8c:15:f3 → 192.168.43.96（无主机名）', '[tc] class 1:5 rate 24mbit ceil 24mbit（iPad Air）',
      '[watchdog] 规则巡检通过 · tc 46 条 · iptables 31 条', '[dpid] 绑定 ' + IFACE + ' · AF_PACKET · 规则库 ' + VER, '[apply] app_qos on 0a:7f:3c:41:9e:21 · 3 档优先级',
      '[stats] 采样 10 台设备 · 用时 38ms', '[detect] 低延迟队列: sch_fq_codel 可用 → 默认启用 fq_codel', '[tc] leaf qdisc fq_codel quantum 1514 target 5ms（零缓冲膨胀）',
      '[hotspotd] 5e:20:b7:3a:c4:18 计数器 +312MB（下载中）', '[watchdog] 心跳 ok · 14s', '[dpid] 前台推断: 1e:52:a8:0c:77:3d → 抖音 0.93'];
    for (var i = 0; i < 48; i++) L.push(fmt(t - (48 - i) * 37000) + ' ' + M[(i * 7) % M.length]);
    return L.join('\n') + '\n';
  }
  function quickHealthCheckPayload() {
    var checkedAt = now();
    var onCnt = visibleDevs().filter(isDevActive).length;
    var limCnt = visibleDevs().filter(function (d) { return d.down_mbps > 0 || d.up_mbps > 0 || d.status === 'blocked'; }).length;
    return {
      ok: true,
      checked_at: checkedAt,
      duration_ms: 3,
      version: VER,
      version_code: VCODE,
      dpid_version: VER,
      watchdog_version: VER,
      overall: 'ok',
      headline: '热点省电与限速状态一切健康，空闲自动零唤醒休眠',
      subline: '本机按需快照检测 · 耗时 3 ms · 平时后台 0 额外轮询',
      items: [
        {
          id: 'hotspot_forward',
          title: '热点与转发通畅度',
          status: 'ok',
          badge: '转发顺畅',
          verdict: '热点接口 ' + IFACE + '（' + GW + '）转发已开启，当前 ' + onCnt + ' 台设备在线',
          detail: '内核 IPv4/IPv6 转发正常，看门狗主动守护中，无被动保护降级',
          fix_kind: 'none',
          fix_label: '',
          fix_action: '',
          fix_params: {},
          nav_target: '',
          metrics: { iface: IFACE, gateway: GW, ip_forward: 1, online_devices: onCnt }
        },
        {
          id: 'zero_wakeup_power',
          title: '待机零唤醒省电状态',
          status: 'ok',
          badge: '极低功耗',
          verdict: '后台总 CPU 占用 0.62%（约 22.3 秒/小时），无设备时自动进入零唤醒深睡',
          detail: '看门狗自适应退避巡检正常，无异常高频唤醒循环',
          fix_kind: 'none',
          fix_label: '',
          fix_action: '',
          fix_params: {},
          nav_target: '',
          metrics: { cpu_pct_1h: 0.62, cpu_sec_per_hour: 22.3, level: 'active' }
        },
        {
          id: 'shaping_offload',
          title: '限速与加速规则一致性',
          status: 'ok',
          badge: '规则一致',
          verdict: '当前 ' + limCnt + ' 台受控策略全部在内核生效，硬件加速旁路已受控无漏流',
          detail: '原生 Netlink 队列树对账一致，最近 0 次修复失败',
          fix_kind: 'none',
          fix_label: '',
          fix_action: '',
          fix_params: {},
          nav_target: '',
          metrics: { controlled_devices: limCnt, tc_repair_fail_count: 0, offload_active: false }
        },
        {
          id: 'tmpfs_config',
          title: '内存盘与配置文件健康度',
          status: 'ok',
          badge: '零擦写健康',
          verdict: '32M 内存盘余量充足（已用 2.4 / 32 MB），核心配置文件全部完好',
          detail: '已校验 8 个核心配置文件无损坏，高频运行态驻留内存保护手机闪存',
          fix_kind: 'none',
          fix_label: '',
          fix_action: '',
          fix_params: {},
          nav_target: '',
          metrics: { is_tmpfs: true, used_mb: 2.4, total_mb: 32, checked_files: 8, bad_files: 0 }
        }
      ]
    };
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
    '/api/health_check': function () { return quickHealthCheckPayload(); },
    '/api/json_health': function () {
      return {
        ok: true,
        backend_version: VER,
        backend_version_code: VCODE,
        timestamp: now(),
        overall: 'ok',
        json_doctor_rc: '0',
        json_doctor_message: 'all managed json files valid',
        files: {
          'rules.json': 'ok',
          'device_names.json': 'ok',
          'templates.json': 'ok',
          'remote_tokens.json': 'ok',
          'devices.json': 'ok'
        },
        backup_count: 5,
        latest_backup: 'rules.json.bak',
        last_bundle: '',
        has_tc_state: true,
        tc_state: { present: true, ts: now() - 42, age_s: 42, max_age_s: 900, fresh: true, note: '快照新鲜(42s 前刷新)' },
        has_capabilities: true
      };
    },
    '/api/signal': function (q) { stepMockSignal(bool(q && q.refresh)); return clone(MOCK_SIGNAL); },
    '/api/live': function (q) {
      stepMockSignal(false);
      var l = liveSummary();
      l.signal = clone(MOCK_SIGNAL);
      if (typeof v6ThermoPayload === 'function') l.thermo = v6ThermoPayload();
      if (typeof v6SelfFirewallSummary === 'function') l.self_firewall = v6SelfFirewallSummary();
      if (typeof v6HostGuardianSummary === 'function') l.host_guardian = v6HostGuardianSummary();
      if (typeof v6ArbiterPayload === 'function') {
        var arb = v6ArbiterPayload();
        l.arbiter = arb;
        l.active_limiter_source = arb.active_source;
        l.active_limiter_reason = arb.active_limiter_reason;
        l.throttle_sources = arb.sources;
      }
      if (q.devices) { var p = devicesPayload(); l.devices = p.devices; l.whitelist_mode = p.whitelist_mode; l.remote_enabled = p.remote_enabled; }
      return l;
    },
    '/api/devices': function () { return devicesPayload(); },
    '/api/config': function () { return Object.assign({}, CFG, { sim_enabled: SIM.enabled, autorate: AUTORATE, rmac_policy: RMAC_POL, client_isolation_enabled: RMAC_POL.client_isolation }); },
    '/api/capabilities': function () {
      return { available: true, capabilities: { tc_htb: true, tc_netem: true, uplink_supported: true, tc_cake: false, tc_fq_codel: true, ifb: true, ifb_supported: true, sqm_supported: true,
        sqm_recommended_mode: 'fq_codel', tc_ingress_supported: true, tc_clsact_supported: true, tc_u32_supported: true, tc_flower_supported: false, tc_matchall: true, tc_police_supported: true,
        tc_mirred: true, uplink_police_supported: true, downlink_mode: 'per_device_htb', uplink_mode: 'ifb_htb', delay_mode: 'netem_leaf', qos_fallback_required: false,
        tc_binary: 'bin/tc', tc_binary_source: 'module', tc_version: 'iproute2-6.1.0', c_fork_supported: true, selected_launcher: 'c_launcher', dpid_version: VER, generated_at: T - 7 * 3600 },
        qdisc_caps: { chosen: 'fq_codel', available: ['fq_codel', 'sfq', 'pfifo'], default_leaf_aqm_eligible: true } };
    },
    '/api/templates': function () { return TPL; },
    '/api/app_limits': function () { return { ok: true, items: APP_LIMITS, include_shared_ips: APP_LIMIT_SHARED }; },
    '/api/alerts': function () { return { ok: true, alerts: ALERTS.slice().sort(function (a, b) { return b.ts - a.ts; }), unread: ALERTS.filter(function (a) { return !a.seen; }).length, total: ALERTS.length }; },
    '/api/alert_config': function () { return ALERT_CFG; },
    '/api/offload_status': function () { return { active: false, detail: CFG.offload_guard.offload_state, offload_guard: CFG.offload_guard }; },
    '/api/online_hours': function (q) {
      var n = +q.days === 30 ? 30 : 7, om = {}, hrs = {};
      visibleDevs().forEach(function (d) {
        om[d.mac] = {}; hrs[d.mac] = {};
        for (var i = 0; i < n; i++) {
          var m = d.onlineMin[i % 7]; if (i === 0) m = isDevActive(d) ? Math.min(m, Math.round(dayFrac() * 1440)) : m;
          if (m > 0) { om[d.mac][ymd(dayAt(i))] = m; if (m >= 60) hrs[d.mac][ymd(dayAt(i))] = Math.floor(m / 60); }
        }
      });
      return { days: n, online_min: om, hours: hrs };
    },
    '/api/usage_month': function () {
      var o = {}, cs = cycleStart(), f = dayFrac();
      visibleDevs().forEach(function (d) { if (d.usage8) o[d.mac] = { rx: round(d.usage8 * (0.97 + f * 0.03) * 0.93 + d.rx_bytes * 0.02), tx: round(d.usage8 * 0.07) }; });
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
    '/api/dpi_probe': function () { return { available: true, probe: { af_packet_available: true, ap_iface: MOCK_HS_ACTIVE ? IFACE : ((SIM && SIM.enabled) ? 'sim' : ''), ap_iface_source: 'tethering', conntrack_readable: true, conntrack_path: '/proc/net/nf_conntrack', offload_hint: false, offload_evidence: 'eBPF 二层加速与慢路径整形已协同生效' } }; },
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
    '/api/iface_info': function () { return { iface: MOCK_HS_ACTIVE ? IFACE : '', ip: MOCK_HS_ACTIVE ? GW : '', gateway: MOCK_HS_ACTIVE ? GW : '', network: '192.168.43.1/24' }; },
    '/api/run_status': function () {
      var hsF = typeof v6MockComputeHotspotFlows === 'function' ? v6MockComputeHotspotFlows() : (MOCK_HS_ACTIVE ? 18 : 0);
      var hoF = typeof v6MockComputeHostFlows === 'function' ? v6MockComputeHostFlows() : 25;
      return { hotspotd: 'up', hotspotd_pid: 4127, hotspotd_rss_kb: 11840, tc_rules: MOCK_HS_ACTIVE ? 46 : 0, ipt_rules: 31, watchdog: 1, watchdog_pid: 4203, watchdog_kind: 'go', watchdog_hb_age: 14, hotspot_flows: hsF, host_flows: hoF, thermo: typeof v6ThermoPayload === 'function' ? v6ThermoPayload() : null };
    },
    '/api/sim': function () { return { ok: true, enabled: SIM.enabled, count: SIM.devices.length, seed: 20261008, presets: ['busy', 'home', 'idle'], types: ['tv', 'phone', 'laptop', 'tablet', 'game', 'iot', 'pc'], mac_prefix: '02:5e:00:', max: 32, devices: SIM.devices }; },
    '/api/selfcheck': function () { return selfcheck(); },
    '/api/dataplane_verify': function (q) { return dataplaneVerifyPayload({ goroutineleak: bool(q.goroutineleak), reset_baseline: bool(q.reset_baseline), iface: q.iface, trigger: 'query_param', manual: false }); },
    '/api/mac_merge': function () {
      var sg = DEVS.filter(function (d) { return d.merge_suggestion; }).map(function (d) {
        return Object.assign({ new_mac: d.mac, new_name: d.hostname || d.mac, new_online: d.online, randomized: !!d.randomized_mac, new_first_seen: d.first_seen }, d.merge_suggestion);
      });
      var mergedList = Object.keys(ALIASES).map(function (oldMac) {
        var toMac = ALIASES[oldMac];
        var toDev = dev(toMac);
        var oldDev = dev(oldMac);
        var arch = MERGE_ARCHIVES[oldMac] || null;
        var a = arch || { merged_at: T - 1800 };
        var fromName = a.from_name || (oldDev && oldDev.hostname) || oldMac;
        var toName = (toDev && toDev.hostname) || a.to_name || toMac;
        return {
          from_mac: oldMac,
          to_mac: toMac,
          old_mac: oldMac,
          new_mac: toMac,
          from_name: fromName,
          to_name: toName,
          old_name: fromName,
          new_name: toName,
          merged_at: a.merged_at,
          ts: a.merged_at,
          has_archive: !!arch,
          auto_inherit: Boolean(a.auto_inherit),
          auto: Boolean(a.auto_inherit),
          score: a.score || 91,
          old_online: !!(oldDev && oldDev.online),
          new_online: !!(toDev && toDev.online)
        };
      });
      return {
        ok: true,
        suggestions: sg,
        aliases: ALIASES,
        merged_list: mergedList,
        mutex_apart_count: MUTEX_APART_COUNT,
        min_score: 40,
        alert_score: 60
      };
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
    '/api/fg_compare': function (q) { return { ok: true, engine: FG_ENGINE, days: Number(q && q.days) || 1, rounds: 2880, agree_rounds: 2506, device_hours: 8.0, classic: { switches: 59, switches_per_hour: 7.4, short_segments: 19, short_per_hour: 2.4 }, hmm: { switches: 33, switches_per_hour: 4.1, short_segments: 6, short_per_hour: 0.75 }, agree_pct: 87 }; },
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
  function parseSimRateBytes(s, defVal) {
    if (s == null || String(s).trim() === '') return defVal;
    var raw = String(s).trim().toLowerCase();
    var m = /^(\d+(?:\.\d+)?)\s*([kmg])?$/.exec(raw);
    if (!m) return defVal;
    var n = parseFloat(m[1]);
    var u = m[2] || '';
    if (u === 'g') return round(n * GB);
    if (u === 'm') return round(n * MB);
    if (u === 'k') return round(n * KB);
    return round(n);
  }
  function syncSimToDevs() {
    if (!SIM || !SIM.enabled) {
      DEVS = DEVS.filter(function (d) { return !d.sim; });
      return;
    }
    var validMacs = {};
    (SIM.devices || []).forEach(function (sd) { validMacs[String(sd.mac || '').toLowerCase()] = sd; });
    DEVS = DEVS.filter(function (d) { return !d.sim || !!validMacs[d.mac.toLowerCase()]; });
    (SIM.devices || []).forEach(function (sd, i) {
      var m = String(sd.mac || '').toLowerCase();
      sd.online = true;
      var ex = dev(m);
      var appId = (sd.app_id && APP[sd.app_id]) ? sd.app_id : 'douyin';
      var rx0 = sd.cur_rx_bps > 0 ? sd.cur_rx_bps : 524288;
      var tx0 = sd.cur_tx_bps > 0 ? sd.cur_tx_bps : 65536;
      if (ex) {
        ex.sim = true;
        ex.online = true;
        if (sd.ip) ex.ip = sd.ip;
        if (sd.name && ex.hostname_src !== 'manual') ex.hostname = sd.name;
        return;
      }
      var tp = sd.type || 'phone';
      var idType = tp === 'laptop' ? 'pc' : (tp === 'game' ? 'console' : tp);
      var osName = { tv: 'Android TV', laptop: 'macOS', tablet: 'iPadOS', game: 'Horizon', iot: 'Linux', pc: 'Windows' }[tp] || 'Android';
      var dnLim = +sd.down_mbps || 0, upLim = +sd.up_mbps || 0;
      DEVS.push({
        mac: m, ip: sd.ip || ('192.168.43.' + (210 + i)), hostname: sd.name || m, hostname_src: 'manual',
        vendor: 'Simulated', sim: true, sim_type: tp, online: true, last_seen: now() - 1, mark_id: 40 + i, randomized_mac: false,
        status: sd.blocked ? 'blocked' : 'allowed',
        down_mbps: dnLim, up_mbps: upLim, limit_enabled: dnLim > 0 || upLim > 0,
        delay_ms: 0, jitter_ms: 0, loss_pct: 0, sqm_enabled: false, whitelist: false, app_qos: false,
        k: [1, 1], cur: [rx0, tx0], base: [rx0, tx0], auto: [sd.name || m, 'manual'], blocks: [],
        usage8: 0.8 * GB, rx_bytes: 96 * MB, tx_bytes: 8 * MB,
        onlineMin: [90, 120, 80, 110, 95, 130, 85], app_time_limits: [], category_blocks: [],
        ident: { type: idType, os: osName, brand: '模拟终端', model: sd.name || 'SimDevice', confidence: 92, hostname: sd.name || m, hostname_src: 'dhcp' },
        live: [[appId, 0.86], appId === 'wechat' ? ['douyin', 0.14] : ['wechat', 0.14]],
        hist: appId === 'wechat' ? ['wechat', 'douyin'] : [appId, 'wechat'],
        fg: { state: 'active', screen_state: 'active', app_id: appId, name: appName(appId), confidence: 0.91, label: '正在用：' + appName(appId), evidence_tags: ['模拟流量'] },
        traffic_type: { type: appCat(appId), label: appName(appId) }
      });
    });
  }
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
    whitelist_set: function (p) {
      var on = bool(p.enabled);
      if (on && !DEVS.some(function (d) { return !d.sim && !!d.whitelist; })) {
        throw err('empty whitelist', 400, {
          detail: '请至少先将 1 台真实设备加入白名单后再开启全局白名单模式（模拟设备不计入真实放行白名单，直接开启会导致全部真机断网）'
        });
      }
      CFG.whitelist_mode = on;
      return '';
    },
    bl_add: function (p) { var d = needDev(p.mac); d.status = 'blocked'; return 'blacklisted'; },
    bl_del: function (p) { var d = needDev(p.mac); d.status = 'allowed'; return 'removed from blacklist'; },
    refresh: function () { return 'scan ok · ' + DEVS.filter(function (d) { return d.online; }).length + ' online'; },
    cleanup_rules: function () { DEVS.forEach(function (d) { d.down_mbps = d.up_mbps = d.delay_ms = d.jitter_ms = d.loss_pct = 0; d.limit_enabled = false; d.status = 'allowed'; d.blocks = []; }); if (typeof V6_LG_STATE === 'object') { V6_LG_STATE.blocked_set = {}; V6_LG_STATE.undo_stack = []; } if (typeof V6_EXP_STATE === 'object') V6_EXP_STATE.forced_macs = []; if (typeof V6_SC_STATE === 'object') V6_SC_STATE.frozen_rules = []; return ''; },
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
    alert_clear: function (p) {
      var kind = p && p.kind ? String(p.kind).trim() : '';
      var before = ALERTS.length;
      if (kind) ALERTS = ALERTS.filter(function (a) { return a.kind !== kind; });
      else ALERTS = [];
      return J({ ok: true, cleared: before - ALERTS.length, remaining: ALERTS.length });
    },
    alerts_clear: function (p) { return ACT.alert_clear(p); },
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
      var to = needDev(p.to_mac), from = dev(p.from_mac), oldMac = String(p.from_mac || '').toLowerCase();
      ALIASES[oldMac] = to.mac; MERGE_DONE[to.mac] = 1;
      if (from) {
        MERGE_ARCHIVES[oldMac] = {
          from_mac: oldMac,
          to_mac: to.mac,
          from_name: from.hostname || oldMac,
          to_name: to.hostname || to.mac,
          merged_at: now(),
          has_archive: true,
          auto_inherit: false,
          snap: clone(from)
        };
        if (to.hostname_src !== 'manual') { to.hostname = from.hostname.replace(/-/g, ' '); to.hostname_src = 'manual'; }
        DEVS = DEVS.filter(function (d) { return d !== from; });
      }
      delete to.merge_suggestion; to.randomized_mac = true; return 'merged';
    },
    device_unmerge: function (p) {
      var reqFrom = String((p && (p.from_mac || p.old_mac)) || '').toLowerCase();
      var reqTo = String((p && (p.to_mac || p.new_mac || p.mac)) || '').toLowerCase();
      var oldMac = '';
      if (reqFrom && ALIASES[reqFrom]) {
        oldMac = reqFrom;
      } else if (reqTo) {
        Object.keys(ALIASES).forEach(function (k) { if (!oldMac && ALIASES[k] === reqTo) oldMac = k; });
      }
      var toMac = oldMac ? ALIASES[oldMac] : reqTo;
      var toDev = toMac ? dev(toMac) : null;
      if (!oldMac && toDev && toDev.auto_inherited_from) {
        oldMac = String(toDev.auto_inherited_from).toLowerCase();
      }
      if (!oldMac && !toDev) throw err('merge record not found', 404);
      if (oldMac) delete ALIASES[oldMac];
      if (toMac) delete MERGE_DONE[toMac];
      if (toDev) {
        delete toDev.auto_inherited_from;
        delete toDev.auto_inherited_name;
        delete toDev.auto_inherited_score;
      }
      var arch = oldMac ? MERGE_ARCHIVES[oldMac] : null;
      if (arch && arch.snap && !dev(oldMac)) {
        var restored = clone(arch.snap);
        restored.online = true;
        if (!restored.base || (!restored.base[0] && !restored.base[1])) restored.base = [180 * KB, 22 * KB];
        if (!restored.live || !restored.live.length) restored.live = [['wechat', 0.7], ['douyin', 0.3]];
        DEVS.push(restored);
      } else if (oldMac && !dev(oldMac)) {
        DEVS.push({
          mac: oldMac, ip: '192.168.43.189', hostname: (arch && arch.from_name) || oldMac, hostname_src: 'dhcp',
          vendor: (toDev && toDev.vendor) || '', online: true, last_seen: now() - 2, mark_id: 14, randomized_mac: true,
          status: 'allowed', down_mbps: 0, up_mbps: 0, delay_ms: 0, jitter_ms: 0, loss_pct: 0,
          k: [1, 1], cur: [180 * KB, 22 * KB], auto: [oldMac, 'dhcp'], blocks: [],
          base: [180 * KB, 22 * KB], usage8: 0.35 * GB, rx_bytes: 42 * MB, tx_bytes: 5 * MB,
          onlineMin: [35, 0, 0, 0, 0, 0, 0], app_time_limits: [], category_blocks: [],
          ident: toDev && toDev.ident ? clone(toDev.ident) : null, live: [['wechat', 0.7], ['douyin', 0.3]], hist: ['wechat', 'douyin']
        });
      }
      if (oldMac) delete MERGE_ARCHIVES[oldMac];
      MUTEX_APART_COUNT += 1;
      return J({ ok: true, from_mac: oldMac, to_mac: toMac || '', restored_archive: !!arch, mutex_apart: true });
    },
    device_merge_dismiss: function (p) { var d = needDev(p.to_mac); delete d.merge_suggestion; return 'dismissed'; },
    template_set: function (p) { TPL[p.name] = { down_mbps: +p.down_mbps || 0, up_mbps: +p.up_mbps || 0, delay_ms: +p.delay_ms || 0, jitter_ms: +p.jitter_ms || 0, loss_pct: +p.loss_pct || 0 }; return ''; },
    template_del: function (p) { delete TPL[p.name]; return ''; },
    hotspot_save: function (p) { if (p.ssid) CFG.hotspot_ssid = p.ssid; if (p.delay_sec) CFG.hotspot_delay_sec = +p.delay_sec; if (p.autostart) CFG.hotspot_autostart = bool(p.autostart); return 'config saved'; },
    hotspot_iface_set: function (p) { CFG.hotspot_iface = p.iface || ''; return p.iface ? 'preferred hotspot iface set to ' + p.iface : 'hotspot iface set to auto'; },
    hotspot_schedule_set: function (p) { CFG.hotspot_time_enable = bool(p.time_enable); CFG.hotspot_charging_only = bool(p.charging_only); if (p.start) CFG.hotspot_time_start = p.start; if (p.end) CFG.hotspot_time_end = p.end; return ''; },
    hotspot_start: function () {
      MOCK_HS_ACTIVE = true;
      var md = CFG.clsact_bpf_mode || 'auto';
      CFG.offload_guard.offload_state = md === 'off' ? 'SKIPPED' : 'IDLE';
      CFG.offload_guard.fallback_active = md !== 'off';
      CFG.offload_guard.clsact = md === 'off' ? 'off' : 'on';
      CFG.offload_guard.slowpath = md === 'off' ? 'n/a' : 'active';
      CFG.offload_guard.last_check = now();
      return '热点已拉起（' + IFACE + '），本机与热点双栈守护同步就绪';
    },
    hotspot_stop: function () {
      MOCK_HS_ACTIVE = false;
      CFG.offload_guard.offload_state = 'NOHOTSPOT';
      CFG.offload_guard.fallback_active = false;
      CFG.offload_guard.clsact = 'off';
      CFG.offload_guard.slowpath = 'n/a';
      CFG.offload_guard.last_check = now();
      return '热点已关闭，本机守护继续独立运行';
    },
    stale_ttl_set: function (p) { CFG.stale_rule_ttl_days = +p.days || 0; return ''; },
    flywheel_exclude_set: function (p) { var l = CFG.flywheel_exclude_user; if (p.op === 'add') { if (l.indexOf(p.pkg) < 0) l.push(p.pkg); } else CFG.flywheel_exclude_user = l.filter(function (x) { return x !== p.pkg; }); return ''; },
    quic_block_set: function (p) { CFG.quic_block = bool(p && p.enabled); return 'QUIC_BLOCK=' + (CFG.quic_block ? 'on iface=wlan2' : 'off'); },
    discover_cert_probe_set: function (p) { CFG.discover_cert_probe = bool(p.enabled); DISC.cert_probe = CFG.discover_cert_probe; return ''; },
    remote_enabled_set: cfgSet('remote_enabled'),
    global_shaper_set: function (p) {
      if (p && p.autorate_enabled != null && String(p.autorate_enabled).trim() !== '') {
        if (bool(p.autorate_enabled)) return ACT.autorate_set(p);
        AUTORATE.enabled = false;
        AUTORATE.state = 'disabled';
      }
      CFG.global_shaper_enabled = bool(p && p.enabled);
      if (CFG.global_shaper_enabled) {
        AUTORATE.enabled = false;
        AUTORATE.state = 'disabled';
        CFG.global_shaper_down = p.rate_down || '';
        CFG.global_shaper_up = p.rate_up || '';
        return 'global shaper on down=' + (p.rate_down || '0') + ' up=' + (p.rate_up || '0');
      }
      return 'global shaper off';
    },
    clsact_mode_set: function (p) {
      var md = String((p && p.mode) || 'auto').toLowerCase();
      if (md === 'always') md = 'on';
      CFG.clsact_bpf_mode = md;
      CFG.offload_guard.mode = md;
      CFG.offload_guard.offload_state = !MOCK_HS_ACTIVE ? 'NOHOTSPOT' : (md === 'off' ? 'SKIPPED' : 'IDLE');
      CFG.offload_guard.fallback_active = MOCK_HS_ACTIVE && md !== 'off';
      CFG.offload_guard.clsact = (MOCK_HS_ACTIVE && md !== 'off') ? 'on' : 'off';
      CFG.offload_guard.slowpath = (MOCK_HS_ACTIVE && md !== 'off') ? 'active' : 'n/a';
      CFG.offload_guard.last_check = now();
      return J(CFG.offload_guard);
    },
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
    sim_clear: function () { SIM.enabled = false; CFG.sim_enabled = false; SIM.devices = []; syncSimToDevs(); return 'cleared sim devices'; },
    sim_device_del: function (p) { var m = String(p.mac || '').toLowerCase(); SIM.devices = SIM.devices.filter(function (d) { return d.mac !== m; }); DEVS = DEVS.filter(function (d) { return d.mac.toLowerCase() !== m; }); return 'deleted ' + m; },
    sim_device_update: function (p) {
      var d = needDev(p.mac);
      if (p.name) {
        d.hostname = p.name;
        d.hostname_src = 'manual';
        SIM.devices.forEach(function (sd) { if (sd.mac === d.mac) sd.name = p.name; });
      }
      return 'updated';
    },
    dpi_correct_list: function () { return J({ rules: FP_RULES }); },
    dpi_fg_engine: function (p) { FG_ENGINE = (p && p.engine === 'classic') ? 'classic' : 'hmm'; return 'fg_engine=' + FG_ENGINE; },
    sim_set: function (p) {
      SIM.enabled = bool(p.enabled);
      CFG.sim_enabled = SIM.enabled;
      syncSimToDevs();
      return SIM.enabled ? '模拟环境已开启(' + SIM.devices.length + ' 台模拟设备)' : '模拟环境已关闭';
    },
    sim_preset: function (p) {
      var pk = String((p && p.preset) || 'home').toLowerCase();
      SIM.enabled = true;
      CFG.sim_enabled = true;
      if (pk === 'busy') {
        SIM.devices = [
          { mac: '02:5e:00:11:22:31', ip: '192.168.43.211', name: '模拟-4K客厅电视', type: 'tv', app_id: 'iqiyi', app_name: '爱奇艺', online: true, cur_rx_bps: 3145728, cur_tx_bps: 92160 },
          { mac: '02:5e:00:11:22:32', ip: '192.168.43.212', name: '模拟-电竞手机', type: 'phone', app_id: 'honor_of_kings', app_name: '王者荣耀', online: true, cur_rx_bps: 286720, cur_tx_bps: 143360 },
          { mac: '02:5e:00:11:22:33', ip: '192.168.43.213', name: '模拟-会议笔记本', type: 'laptop', app_id: 'tencent_meeting', app_name: '腾讯会议', online: true, cur_rx_bps: 786432, cur_tx_bps: 524288 },
          { mac: '02:5e:00:11:22:34', ip: '192.168.43.214', name: '模拟-游戏主机下载', type: 'game', app_id: 'nintendo_eshop', app_name: '任天堂 eShop', online: true, cur_rx_bps: 2621440, cur_tx_bps: 65536, down_mbps: 20, up_mbps: 5 }
        ];
      } else if (pk === 'idle') {
        SIM.devices = [
          { mac: '02:5e:00:11:22:41', ip: '192.168.43.211', name: '模拟-待机手机', type: 'phone', app_id: 'wechat', app_name: '微信', online: true, cur_rx_bps: 18432, cur_tx_bps: 6144 },
          { mac: '02:5e:00:11:22:42', ip: '192.168.43.212', name: '模拟-智能音箱', type: 'iot', app_id: 'qqmusic', app_name: 'QQ音乐', online: true, cur_rx_bps: 32768, cur_tx_bps: 4096 }
        ];
      } else {
        SIM.devices = [
          { mac: '02:5e:00:11:22:33', ip: '192.168.43.210', name: '模拟-客厅电视', type: 'tv', app_id: 'iqiyi', app_name: '爱奇艺', online: true, cur_rx_bps: 2621440, cur_tx_bps: 81920 },
          { mac: '02:5e:00:11:22:35', ip: '192.168.43.211', name: '模拟-家人手机', type: 'phone', app_id: 'douyin', app_name: '抖音', online: true, cur_rx_bps: 1310720, cur_tx_bps: 73728 },
          { mac: '02:5e:00:11:22:36', ip: '192.168.43.212', name: '模拟-书房平板', type: 'tablet', app_id: 'bilibili', app_name: 'B站', online: true, cur_rx_bps: 917504, cur_tx_bps: 49152 }
        ];
      }
      syncSimToDevs();
      return '已加载预设 ' + pk;
    },
    sim_device_add: function (p) {
      var idx = SIM.devices.length;
      var mac = '02:5e:00:12:34:' + p2(10 + (idx % 80));
      while (SIM.devices.some(function (x) { return x.mac === mac; })) { idx++; mac = '02:5e:00:12:34:' + p2(10 + (idx % 80)); }
      var tp = String((p && p.type) || 'phone').toLowerCase();
      var nm = String((p && p.name) || '').trim() || ('模拟-' + ({ tv: '电视', phone: '手机', laptop: '笔记本', tablet: '平板', game: '游戏机', iot: '智能设备', pc: '电脑' }[tp] || '设备') + (SIM.devices.length + 1));
      var appId = String((p && p.app) || '').trim().toLowerCase();
      if (!appId || !APP[appId]) appId = { tv: 'iqiyi', phone: 'douyin', laptop: 'tencent_meeting', tablet: 'bilibili', game: 'honor_of_kings', iot: 'qqmusic', pc: 'feishu' }[tp] || 'douyin';
      var rxB = parseSimRateBytes(p && p.rx, 640 * KB);
      var txB = parseSimRateBytes(p && p.tx, 72 * KB);
      var hostOctet = 215 + (SIM.devices.length % 35);
      var ipStr = (p && p.ip && /^192\.168\.43\.\d+$/.test(p.ip)) ? p.ip : ('192.168.43.' + hostOctet);
      SIM.devices.push({ mac: mac, ip: ipStr, name: nm, type: tp, app_id: appId, app_name: appName(appId), online: true, cur_rx_bps: rxB, cur_tx_bps: txB });
      syncSimToDevs();
      return J({ mac: mac, ip: ipStr, name: nm, type: tp });
    },
    selfcheck_run: function () { SC_AT = now(); return J(selfcheck()); },
    dataplane_verify_run: function (p) {
      var isResync = p.resync === '1' || p.repair === '1' || bool(p.resync) || bool(p.repair);
      if (isResync) {
        CFG.offload_guard.offload_state = 'IDLE';
        CFG.offload_guard.fallback_active = true;
        CFG.offload_guard.clsact = 'on';
        CFG.offload_guard.slowpath = 'active';
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
    compat_report: function () { var nm = 'hnc-compat-' + ymd(dayAt(0)) + '.json'; pushExport(nm, 12840); return J({ name: nm, summary: { ok: 22, warn: 0, fail: 0 } }); },
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
    dpi_rules_update: function () { return J({ update_available: 'no', current: 'builtin', remote: VER }); },
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
    cleanup_all: function () { return 'safe release scheduled'; },
    json_doctor_repair: function () { return '已校验并修复全部核心 JSON 配置文件（0 个异常残留）'; },
    self_firewall_set: function (p) { return J(v6ApplySelfFirewallMutation(Object.assign({ action: 'self_firewall_set' }, p || {}))); },
    self_firewall_remove: function (p) { return J(v6ApplySelfFirewallMutation(Object.assign({ action: 'self_firewall_remove' }, p || {}))); },
    self_firewall_clear: function (p) { return J(v6ApplySelfFirewallMutation(Object.assign({ action: 'self_firewall_clear' }, p || {}))); },
    self_dns_block: function (p) { return J(v6ApplySelfFirewallMutation(Object.assign({ action: 'self_dns_block' }, p || {}))); },
    self_dns_unblock: function (p) { return J(v6ApplySelfFirewallMutation(Object.assign({ action: 'self_dns_unblock' }, p || {}))); }
  };
  function doAction(body) {
    var name = body && body.action, p = (body && body.params) || {}, fn = name ? ACT[name] : null;
    if (!fn) throw err('unknown action', 400, { detail: String(name || '') });
    var det = fn(p);
    return det ? { ok: true, detail: det } : { ok: true };
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


  /* ═════════════ HNC v6.1.0-rc.8 · 本机+热点双栈守护、防火墙与 LeakGuard 仿真层 ═════════════ */
  function v6MockInfraGuard(host) {
    var h = String(host || '').trim().toLowerCase();
    if (!h) return null;
    if (/(connectivitycheck\.gstatic\.com|captive\.apple\.com|connect\.rom\.miui\.com|msftconnecttest\.com|dns\.alidns\.com|doh\.pub)$/.test(h)) {
      return { level: 'hard_block', label: '系统联网探测核心域' };
    }
    if (/(alicdn\.com|aliyuncs\.com|myqcloud\.com|cdnhwc1\.com|cloudfront\.net|bytecdn\.cn|kwimgs\.com|hdslb\.com)$/.test(h)) {
      return { level: 'warn_confirm', label: '共享公共云 CDN' };
    }
    return null;
  }

  function v6MockSharedCdnIpVendor(ip, hostGuard) {
    var s = String(ip || '').trim().toLowerCase();
    if (!s) return '';
    if (/^(104\.(1[6-9]|2[0-9]|3[01])\.|172\.(6[4-9]|7[01])\.|162\.15[89]\.|108\.162\.)/.test(s)) return 'Cloudflare';
    if (/^(151\.101\.|199\.232\.)/.test(s)) return 'Fastly';
    if (/^(13\.(32|33|35|22[4-7])\.|52\.8[45]\.|54\.230\.|99\.84\.|143\.204\.)/.test(s)) return 'Amazon CloudFront';
    if (/^(23\.(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-5][0-5])\.|104\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|184\.(2[4-9]|3[01])\.)/.test(s)) return 'Akamai';
    if (/^17\./.test(s)) return 'Apple';
    if (hostGuard && hostGuard.level === 'warn_confirm') return hostGuard.label || 'Shared CDN';
    return '';
  }

  var V6_PROTECTED_PKGS = [
    'com.agy',
    'com.android.webview',
    'com.google.android.webview',
    'com.rifsxd.ksunext',
    'com.sukisu.ultra',
    'com.topjohnwu.magisk',
    'io.github.vvb2060.magisk',
    'me.bmax.apatch',
    'me.weishu.kernelsu'
  ];

  var V6_HOST_APPS_CATALOG = [
    {
      uid: 10234, pkg: 'com.ss.android.ugc.aweme', app_name: '抖音', is_system: false,
      state: 'foreground', rx_bps: 1480000, tx_bps: 64000,
      bg_rx: 298 * MB, bg_tx: 22 * MB, fg_rx: 1840 * MB, fg_tx: 96 * MB, wifi_share: 0.72,
      active_conns: 3, top_domains: ['v26-dy.douyinvod.com', 'api5-normal-lq.amemv.com', 'p26-sign.douyinpic.com'],
      cleartext_flags: [],
      power: { total_mah: 312.4, fg_mah: 248.6, bg_mah: 52.8, fgs_mah: 11.0, cached_mah: 4.2, screen_off_mah: 31.4,
        wl_ms: 486000, wl_bg_ms: 342000, wl_cnt: 46, top_wl: [{ name: 'AwemePushWakeLock', duration_ms: 214000, count: 29 }, { name: 'TTNetBgSync', duration_ms: 128000, count: 17 }],
        radio_ms: 740000, radio_cnt: 38, wifi_ms: 1920000, wifi_scan: 4, cpu_tot_ms: 910000, cpu_fg_ms: 730000, cpu_bg_ms: 180000,
        alarms: 34, top_alarms: [{ name: 'com.ss.android.message.HEARTBEAT', count: 22 }, { name: 'com.bytedance.push.KEEP_ALIVE', count: 12 }], jobs_ms: 96000, jobs_cnt: 14 }
    },
    {
      uid: 10198, pkg: 'com.tencent.mm', app_name: '微信', is_system: false,
      state: 'foreground', rx_bps: 92000, tx_bps: 38000,
      bg_rx: 386 * MB, bg_tx: 94 * MB, fg_rx: 612 * MB, fg_tx: 148 * MB, wifi_share: 0.65,
      active_conns: 3, top_domains: ['szextshort.weixin.qq.com', 'mmsns.qpic.cn', 'wx.qlogo.cn'],
      cleartext_flags: [],
      power: { total_mah: 286.2, fg_mah: 164.0, bg_mah: 98.4, fgs_mah: 23.8, cached_mah: 6.1, screen_off_mah: 64.2,
        wl_ms: 924000, wl_bg_ms: 782000, wl_cnt: 118, top_wl: [{ name: 'MicroMsg.MMWakerLock', duration_ms: 540000, count: 84 }, { name: 'Mars.CoreWakeLock', duration_ms: 242000, count: 34 }],
        radio_ms: 1280000, radio_cnt: 96, wifi_ms: 2460000, wifi_scan: 9, cpu_tot_ms: 840000, cpu_fg_ms: 490000, cpu_bg_ms: 350000,
        alarms: 88, top_alarms: [{ name: 'com.tencent.mm.ALARM_ACTION', count: 61 }, { name: 'com.tencent.mm.push.SYNC', count: 27 }], jobs_ms: 142000, jobs_cnt: 19 }
    },
    {
      uid: 10318, pkg: 'com.kuaishou.nebula', app_name: '快手极速版', is_system: false,
      state: 'background', rx_bps: 184000, tx_bps: 26000,
      bg_rx: 684 * MB, bg_tx: 58 * MB, fg_rx: 192 * MB, fg_tx: 18 * MB, wifi_share: 0.58,
      active_conns: 3, top_domains: ['txmov2.a.kwimgs.com', 'log-sdk.ad-nebula-demo.cn', 'api.gifshow.com'],
      cleartext_flags: ['http_cleartext', 'tracker_sdk'],
      power: { total_mah: 194.8, fg_mah: 56.2, bg_mah: 126.6, fgs_mah: 12.0, cached_mah: 3.4, screen_off_mah: 78.5,
        wl_ms: 1140000, wl_bg_ms: 1060000, wl_cnt: 92, top_wl: [{ name: 'KwaiBgPreloadLock', duration_ms: 760000, count: 58 }, { name: 'NebulaAdReportLock', duration_ms: 300000, count: 34 }],
        radio_ms: 1520000, radio_cnt: 74, wifi_ms: 1380000, wifi_scan: 12, cpu_tot_ms: 620000, cpu_fg_ms: 170000, cpu_bg_ms: 450000,
        alarms: 67, top_alarms: [{ name: 'com.kuaishou.nebula.PRELOAD_VIDEO', count: 43 }, { name: 'com.kwai.ad.TRACK_REPORT', count: 24 }], jobs_ms: 310000, jobs_cnt: 31 }
    },
    {
      uid: 10356, pkg: 'com.cloudalbum.sync', app_name: '相册云盘备份', is_system: false,
      state: 'background', rx_bps: 14000, tx_bps: 420000,
      bg_rx: 84 * MB, bg_tx: 1120 * MB, fg_rx: 42 * MB, fg_tx: 34 * MB, wifi_share: 0.44,
      active_conns: 2, top_domains: ['up-z2.qiniup.com', 'ocr-legacy.album-verify.cn'],
      cleartext_flags: ['http_cleartext', 'bg_silent_uplink'],
      power: { total_mah: 148.5, fg_mah: 18.0, bg_mah: 114.5, fgs_mah: 16.0, cached_mah: 1.8, screen_off_mah: 82.0,
        wl_ms: 1380000, wl_bg_ms: 1340000, wl_cnt: 41, top_wl: [{ name: 'AlbumOriginalUploadWakeLock', duration_ms: 1090000, count: 26 }, { name: 'ExifIndexJobLock', duration_ms: 250000, count: 15 }],
        radio_ms: 1690000, radio_cnt: 52, wifi_ms: 1640000, wifi_scan: 2, cpu_tot_ms: 530000, cpu_fg_ms: 50000, cpu_bg_ms: 480000,
        alarms: 29, top_alarms: [{ name: 'com.cloudalbum.sync.NIGHT_UPLOAD', count: 29 }], jobs_ms: 680000, jobs_cnt: 22 }
    },
    {
      uid: 10294, pkg: 'com.weather.fastcalendar', app_name: '极速天气日历', is_system: false,
      state: 'background', rx_bps: 18500, tx_bps: 9400,
      bg_rx: 246 * MB, bg_tx: 64 * MB, fg_rx: 11 * MB, fg_tx: 3 * MB, wifi_share: 0.48,
      active_conns: 3, top_domains: ['api-plain.fastcalendar-sdk.cn', 'sdk.mob-analytics-tracker.cn'],
      cleartext_flags: ['http_cleartext', 'dns_direct', 'tracker_sdk'],
      power: { total_mah: 96.4, fg_mah: 6.2, bg_mah: 84.2, fgs_mah: 6.0, cached_mah: 1.2, screen_off_mah: 58.6,
        wl_ms: 820000, wl_bg_ms: 805000, wl_cnt: 134, top_wl: [{ name: 'FastCalLocPollLock', duration_ms: 560000, count: 92 }, { name: 'AdSdkBeaconWakeLock', duration_ms: 245000, count: 42 }],
        radio_ms: 1120000, radio_cnt: 108, wifi_ms: 640000, wifi_scan: 28, cpu_tot_ms: 340000, cpu_fg_ms: 22000, cpu_bg_ms: 318000,
        alarms: 112, top_alarms: [{ name: 'com.weather.fastcalendar.LOC_TICK', count: 76 }, { name: 'cn.mob.sdk.BEACON_WAKE', count: 36 }], jobs_ms: 240000, jobs_cnt: 45 }
    },
    {
      uid: 10311, pkg: 'tv.danmaku.bili', app_name: '哔哩哔哩', is_system: false,
      state: 'background', rx_bps: 36000, tx_bps: 4200,
      bg_rx: 168 * MB, bg_tx: 14 * MB, fg_rx: 920 * MB, fg_tx: 38 * MB, wifi_share: 0.81,
      active_conns: 3, top_domains: ['upos-sz-mirrorcos.bilivideo.com', 'api.bilibili.com', 'i0.hdslb.com'],
      cleartext_flags: [],
      power: { total_mah: 142.0, fg_mah: 112.4, bg_mah: 24.6, fgs_mah: 5.0, cached_mah: 2.5, screen_off_mah: 11.2,
        wl_ms: 210000, wl_bg_ms: 145000, wl_cnt: 19, top_wl: [{ name: 'IjkMediaPlayerWakeLock', duration_ms: 145000, count: 19 }],
        radio_ms: 320000, radio_cnt: 16, wifi_ms: 1180000, wifi_scan: 1, cpu_tot_ms: 480000, cpu_fg_ms: 410000, cpu_bg_ms: 70000,
        alarms: 14, top_alarms: [{ name: 'tv.danmaku.bili.PUSH_HEARTBEAT', count: 14 }], jobs_ms: 42000, jobs_cnt: 6 }
    },
    {
      uid: 10287, pkg: 'com.autonavi.minimap', app_name: '高德地图', is_system: false,
      state: 'background', rx_bps: 8200, tx_bps: 3100,
      bg_rx: 52 * MB, bg_tx: 16 * MB, fg_rx: 134 * MB, fg_tx: 22 * MB, wifi_share: 0.35,
      active_conns: 2, top_domains: ['m5.amap.com', 'webrd01.is.autonavi.com'],
      cleartext_flags: [],
      power: { total_mah: 88.6, fg_mah: 54.0, bg_mah: 28.6, fgs_mah: 6.0, cached_mah: 1.4, screen_off_mah: 14.8,
        wl_ms: 290000, wl_bg_ms: 180000, wl_cnt: 27, top_wl: [{ name: 'AMapLocationWakeLock', duration_ms: 180000, count: 27 }],
        radio_ms: 490000, radio_cnt: 24, wifi_ms: 420000, wifi_scan: 19, cpu_tot_ms: 270000, cpu_fg_ms: 190000, cpu_bg_ms: 80000,
        alarms: 18, top_alarms: [{ name: 'com.amap.api.location.APS_ALARM', count: 18 }], jobs_ms: 38000, jobs_cnt: 8 }
    },
    {
      uid: 10388, pkg: 'mark.via', app_name: 'Via 浏览器', is_system: false,
      state: 'background', rx_bps: 2400, tx_bps: 680,
      bg_rx: 6 * MB, bg_tx: 1 * MB, fg_rx: 118 * MB, fg_tx: 9 * MB, wifi_share: 0.76,
      active_conns: 2, top_domains: ['developer.mozilla.org', 'cdnjs.cloudflare.com'],
      cleartext_flags: [],
      power: { total_mah: 24.2, fg_mah: 21.8, bg_mah: 2.4, fgs_mah: 0, cached_mah: 0.8, screen_off_mah: 0.6,
        wl_ms: 18000, wl_bg_ms: 4000, wl_cnt: 3, top_wl: [],
        radio_ms: 64000, radio_cnt: 5, wifi_ms: 260000, wifi_scan: 0, cpu_tot_ms: 92000, cpu_fg_ms: 86000, cpu_bg_ms: 6000,
        alarms: 0, top_alarms: [], jobs_ms: 0, jobs_cnt: 0 }
    },
    {
      uid: 10045, pkg: 'com.heytap.market', app_name: '软件商店', is_system: true,
      state: 'background', rx_bps: 4200, tx_bps: 1100,
      bg_rx: 312 * MB, bg_tx: 11 * MB, fg_rx: 28 * MB, fg_tx: 3 * MB, wifi_share: 0.92,
      active_conns: 2, top_domains: ['api-cn.store.heytapmobi.com', 'dl-cn.heytapimage.com'],
      cleartext_flags: [],
      power: { total_mah: 34.6, fg_mah: 4.2, bg_mah: 30.4, fgs_mah: 0, cached_mah: 1.1, screen_off_mah: 19.2,
        wl_ms: 240000, wl_bg_ms: 230000, wl_cnt: 14, top_wl: [{ name: 'MarketAutoUpdateJob', duration_ms: 230000, count: 14 }],
        radio_ms: 110000, radio_cnt: 8, wifi_ms: 520000, wifi_scan: 0, cpu_tot_ms: 145000, cpu_fg_ms: 15000, cpu_bg_ms: 130000,
        alarms: 9, top_alarms: [{ name: 'com.heytap.market.DAILY_CHECK', count: 9 }], jobs_ms: 210000, jobs_cnt: 9 }
    },
    {
      uid: 1000, pkg: 'android', app_name: 'Android 系统', is_system: true,
      state: 'foreground', rx_bps: 1600, tx_bps: 900,
      bg_rx: 24 * MB, bg_tx: 8 * MB, fg_rx: 12 * MB, fg_tx: 4 * MB, wifi_share: 0.70,
      active_conns: 2, top_domains: ['connectivitycheck.gstatic.com', 'time.android.com'],
      cleartext_flags: [],
      power: { total_mah: 62.0, fg_mah: 18.0, bg_mah: 44.0, fgs_mah: 0, cached_mah: 0, screen_off_mah: 24.5,
        wl_ms: 410000, wl_bg_ms: 360000, wl_cnt: 64, top_wl: [{ name: 'NetworkStats', duration_ms: 190000, count: 40 }, { name: 'AnyMotionDetector', duration_ms: 170000, count: 24 }],
        radio_ms: 220000, radio_cnt: 19, wifi_ms: 680000, wifi_scan: 6, cpu_tot_ms: 380000, cpu_fg_ms: 90000, cpu_bg_ms: 290000,
        alarms: 31, top_alarms: [{ name: 'android.content.syncmanager.SYNC_ALARM', count: 31 }], jobs_ms: 85000, jobs_cnt: 16 }
    }
  ];

  var V6_SELF_FW = {
    updated_at: T - 120,
    apply_commits: 3,
    guard_rejects: 0,
    uid_rules: {
      '10356': {
        uid: 10356,
        sdk_sandbox_uid: 20356,
        pkg: 'com.cloudalbum.sync',
        app_name: '相册云盘备份',
        mode: 'block_cellular',
        block_targets: [],
        updated_at: T - 320
      }
    },
    blocked_domains: {
      'ad-beacon.legacy-push-demo.cn': 1
    }
  };

  function v6FindHostAppMeta(uid, fallbackPkg, fallbackName) {
    for (var i = 0; i < V6_HOST_APPS_CATALOG.length; i++) {
      if (V6_HOST_APPS_CATALOG[i].uid === uid) return V6_HOST_APPS_CATALOG[i];
    }
    return { uid: uid, pkg: fallbackPkg || ('uid:' + uid), app_name: fallbackName || fallbackPkg || ('UID ' + uid), is_system: uid < 10000 };
  }

  function v6SelfFirewallSnapshot() {
    var rules = Object.keys(V6_SELF_FW.uid_rules).map(function (k) {
      var r = clone(V6_SELF_FW.uid_rules[k]);
      r.block_targets = Array.isArray(r.block_targets) ? r.block_targets.slice() : [];
      return r;
    }).filter(function (r) {
      return r.mode !== 'allow' || r.block_targets.length > 0;
    }).sort(function (a, b) { return a.uid - b.uid; });
    var doms = Object.keys(V6_SELF_FW.blocked_domains).sort();
    return {
      ok: true,
      updated_at: V6_SELF_FW.updated_at,
      uid_rules: rules,
      blocked_domains: doms,
      protected_packages: V6_PROTECTED_PKGS.slice(),
      uid_rule_count: rules.length,
      blocked_domain_count: doms.length,
      sync_dirty: false
    };
  }

  function v6SelfFirewallSummary() {
    var rules = Object.keys(V6_SELF_FW.uid_rules).map(function (k) { return V6_SELF_FW.uid_rules[k]; }).filter(function (r) {
      return r && (r.mode !== 'allow' || (Array.isArray(r.block_targets) && r.block_targets.length > 0));
    });
    var domCnt = Object.keys(V6_SELF_FW.blocked_domains).length;
    var ctCnt = 0, cellCnt = 0, allCnt = 0, ipOnlyCnt = 0;
    rules.forEach(function (r) {
      if (r.mode === 'block_cleartext') ctCnt++;
      else if (r.mode === 'block_cellular') cellCnt++;
      else if (r.mode === 'block_all') allCnt++;
      else if (r.mode === 'allow' && Array.isArray(r.block_targets) && r.block_targets.length > 0) ipOnlyCnt++;
    });
    return {
      active: rules.length > 0 || domCnt > 0,
      uid_rule_count: rules.length,
      blocked_domain_count: domCnt,
      block_cleartext_apps: ctCnt,
      block_cellular_apps: cellCnt,
      block_all_apps: allCnt,
      ip_target_only_apps: ipOnlyCnt,
      apply_commits: V6_SELF_FW.apply_commits,
      guard_rejects: V6_SELF_FW.guard_rejects,
      sync_dirty: false,
      updated_at: V6_SELF_FW.updated_at
    };
  }

  function v6ApplySelfFirewallMutation(req) {
    req = req || {};
    var act = String(req.action || '').trim().toLowerCase();
    if (!act) {
      if (req.uid != null && req.uid !== '') act = 'self_firewall_set';
      else if (req.domain || req.dst_host) act = 'self_dns_block';
    }
    if (act === 'set' || act === 'self_firewall_set') {
      var uid = round(+(req.uid != null ? req.uid : -1));
      if (!(uid >= 0)) throw err('bad params', 400, { reason_code: 'bad params', detail: 'uid is required' });
      var appId = uid % 100000;
      if (uid < 10000 || appId < 10000 || appId >= 90000 || uid > 99999999) {
        V6_SELF_FW.guard_rejects += 1;
        throw err('protected_uid', 400, { reason_code: 'protected_uid', detail: '系统核心或隔离沙箱 UID 受防自锁红线保护，禁止封禁' });
      }
      var rawPkg = String(req.pkg || req.package || '').trim();
      if (/^(uid:|isolated:)/i.test(rawPkg)) rawPkg = '';
      var meta = v6FindHostAppMeta(uid, rawPkg, String(req.app_name || '').trim());
      var pkgName = rawPkg || (/^(uid:|isolated:)/i.test(meta.pkg) ? '' : String(meta.pkg || '').trim());
      if (pkgName && V6_PROTECTED_PKGS.indexOf(pkgName.toLowerCase()) >= 0) {
        V6_SELF_FW.guard_rejects += 1;
        throw err('protected_package', 400, { reason_code: 'protected_package', detail: '受保护的管理器 / 系统 WebView 包名禁止封禁：' + pkgName });
      }
      var mode = String(req.mode || 'allow').trim().toLowerCase();
      var targets = [];
      if (Array.isArray(req.block_targets)) targets = req.block_targets.map(String).filter(Boolean);
      else if (typeof req.block_targets === 'string') {
        var trimmedTgt = req.block_targets.trim();
        if (trimmedTgt.charAt(0) === '[') {
          try {
            var parsedArr = JSON.parse(trimmedTgt);
            if (Array.isArray(parsedArr)) targets = parsedArr.map(String).filter(Boolean);
          } catch (_) {}
        } else if (trimmedTgt) {
          targets = trimmedTgt.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
      } else if (V6_SELF_FW.uid_rules[String(uid)] && Array.isArray(V6_SELF_FW.uid_rules[String(uid)].block_targets) && req.block_targets === undefined) {
        targets = V6_SELF_FW.uid_rules[String(uid)].block_targets.slice();
      }
      var sbUid = (appId >= 10000 && appId <= 19999) ? (uid + 10000) : 0;
      if (mode === 'allow' || mode === 'off' || mode === 'none') {
        if (targets.length > 0) {
          V6_SELF_FW.uid_rules[String(uid)] = {
            uid: uid,
            sdk_sandbox_uid: sbUid,
            pkg: pkgName,
            app_name: String(req.app_name || meta.app_name || pkgName || ('UID ' + uid)),
            mode: 'allow',
            block_targets: targets,
            updated_at: now()
          };
        } else {
          delete V6_SELF_FW.uid_rules[String(uid)];
        }
      } else if (mode === 'block_cleartext' || mode === 'block_cellular' || mode === 'block_all') {
        V6_SELF_FW.uid_rules[String(uid)] = {
          uid: uid,
          sdk_sandbox_uid: sbUid,
          pkg: pkgName,
          app_name: String(req.app_name || meta.app_name || pkgName || ('UID ' + uid)),
          mode: mode,
          block_targets: targets,
          updated_at: now()
        };
      } else {
        throw err('bad params', 400, { reason_code: 'bad params', detail: 'invalid mode: ' + mode });
      }
      V6_SELF_FW.updated_at = now();
      V6_SELF_FW.apply_commits += 1;
      return v6SelfFirewallSnapshot();
    }
    if (act === 'remove' || act === 'self_firewall_remove') {
      var rUid = round(+(req.uid != null ? req.uid : -1));
      var rAppId = rUid >= 0 ? (rUid % 100000) : -1;
      if (rUid < 10000 || rAppId < 10000 || rAppId >= 90000) throw err('protected_uid', 400, { reason_code: 'protected_uid', detail: 'valid app uid is required' });
      delete V6_SELF_FW.uid_rules[String(rUid)];
      V6_SELF_FW.updated_at = now();
      V6_SELF_FW.apply_commits += 1;
      return v6SelfFirewallSnapshot();
    }
    if (act === 'clear' || act === 'self_firewall_clear') {
      var sc = String(req.scope || 'all').trim().toLowerCase();
      if (sc === 'uid' || sc === 'uid_rules') V6_SELF_FW.uid_rules = {};
      else if (sc === 'dns' || sc === 'domains') V6_SELF_FW.blocked_domains = {};
      else { V6_SELF_FW.uid_rules = {}; V6_SELF_FW.blocked_domains = {}; }
      V6_SELF_FW.updated_at = now();
      V6_SELF_FW.apply_commits += 1;
      return v6SelfFirewallSnapshot();
    }
    if (act === 'dns_block' || act === 'self_dns_block') {
      var dom = String(req.domain || req.dst_host || '').trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
      if (!dom || /^\d+\.\d+\.\d+\.\d+$/.test(dom) || dom.indexOf(':') >= 0) {
        throw err('bad params', 400, { reason_code: 'bad params', detail: 'HNC_SELF_DNS requires a valid domain name' });
      }
      var ig = v6MockInfraGuard(dom);
      if (ig && ig.level === 'hard_block') {
        V6_SELF_FW.guard_rejects += 1;
        throw err('guard_hard_block', 409, {
          guard_level: 'hard_block',
          requires_confirm: false,
          vendor: ig.label,
          domain: dom,
          detail: '系统联网探测与公共 DNS 核心域禁止拦截：' + dom
        });
      }
      if (ig && ig.level === 'warn_confirm' && !bool(req.force)) {
        V6_SELF_FW.guard_rejects += 1;
        throw err('guard_warn_confirm', 409, {
          guard_level: 'warn_confirm',
          requires_confirm: true,
          vendor: ig.label,
          domain: dom,
          detail: '该域名属于「' + ig.label + '」共享底座，拦截可能连带影响多款本机应用，确认后可强制下发。'
        });
      }
      V6_SELF_FW.blocked_domains[dom] = 1;
      V6_SELF_FW.updated_at = now();
      V6_SELF_FW.apply_commits += 1;
      return v6SelfFirewallSnapshot();
    }
    if (act === 'dns_unblock' || act === 'self_dns_unblock') {
      var udom = String(req.domain || req.dst_host || '').trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
      if (!udom) throw err('bad params', 400, { reason_code: 'bad params', detail: 'domain is required' });
      delete V6_SELF_FW.blocked_domains[udom];
      V6_SELF_FW.updated_at = now();
      V6_SELF_FW.apply_commits += 1;
      return v6SelfFirewallSnapshot();
    }
    throw err('bad params', 400, { detail: 'action must be self_firewall_set|self_firewall_remove|self_firewall_clear|self_dns_block|self_dns_unblock' });
  }

  function v6MockIsSelfDomainBlocked(dom) {
    var h = String(dom || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!h || /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.indexOf(':') >= 0) return false;
    var keys = Object.keys(V6_SELF_FW.blocked_domains);
    for (var i = 0; i < keys.length; i++) {
      var b = keys[i];
      if (h === b || h.slice(-(b.length + 1)) === '.' + b) return true;
    }
    return false;
  }

  function v6MockIsSelfIpBlocked(ip, uid) {
    var s = String(ip || '').trim().toLowerCase();
    if (s.charAt(0) === '[' && s.indexOf(']') > 1) s = s.slice(1, s.indexOf(']'));
    else if (s.indexOf(':') > 0 && s.indexOf(':') === s.lastIndexOf(':')) s = s.slice(0, s.indexOf(':'));
    if (!s || !(uid > 0)) return false;
    var u = round(+uid);
    var appId = u % 100000;
    var rule = V6_SELF_FW.uid_rules[String(u)] || ((appId >= 20000 && appId <= 29999) ? V6_SELF_FW.uid_rules[String(u - 10000)] : null);
    if (rule && Array.isArray(rule.block_targets)) {
      for (var i = 0; i < rule.block_targets.length; i++) {
        var t = String(rule.block_targets[i] || '').trim().toLowerCase();
        var tIp = t;
        if (tIp.charAt(0) === '[' && tIp.indexOf(']') > 1) tIp = tIp.slice(1, tIp.indexOf(']'));
        else if (tIp.indexOf(':') > 0 && tIp.indexOf(':') === tIp.lastIndexOf(':')) tIp = tIp.slice(0, tIp.indexOf(':'));
        if (t === s || tIp === s) return true;
      }
    }
    return false;
  }

  function v6MockComputeHotspotFlows() {
    if (typeof v6BuildScalpelFlows === 'function') return v6BuildScalpelFlows({ scope: 'hotspot' }).length;
    return MOCK_HS_ACTIVE ? 21 : 0;
  }

  function v6MockComputeHostFlows() {
    if (typeof v6BuildScalpelFlows === 'function') return v6BuildScalpelFlows({ scope: 'host' }).length;
    var total = 0;
    V6_HOST_APPS_CATALOG.forEach(function (a) {
      var rule = V6_SELF_FW.uid_rules[String(a.uid)];
      if (rule && rule.mode === 'block_all') return;
      total += a.active_conns;
    });
    return total;
  }

  function v6LocalAppsTrafficPayload(q) {
    q = q || {};
    var period = String(q.period || 'boot').trim().toLowerCase();
    if (['boot', 'today', '24h', '7d', '30d', 'cycle', 'month'].indexOf(period) < 0) period = 'boot';
    var netF = String(q.net || 'all').trim().toLowerCase();
    if (netF === 'cellular' || netF === 'mobile') netF = 'cell';
    if (['all', 'wifi', 'cell'].indexOf(netF) < 0) netF = 'all';
    var sortRaw = String(q.sort || 'rate').trim().toLowerCase();
    var sortBy = sortRaw;
    if (sortRaw === 'live' || sortRaw === 'bps') sortBy = 'rate';
    else if (sortRaw === 'bg') sortBy = 'bg_bytes';
    else if (sortRaw === 'total') sortBy = 'total_bytes';
    var includeSystem = bool(q.include_system);
    var pMul = period === 'today' ? 0.62 : (period === '24h' ? 0.78 : (period === '7d' ? 4.3 : (period === '30d' || period === 'cycle' || period === 'month' ? 14.6 : 1.0)));

    var rows = [];
    var sumRxBps = 0, sumTxBps = 0, sumTotB = 0, sumBgB = 0, sumFgB = 0, activeConnApps = 0;
    V6_HOST_APPS_CATALOG.forEach(function (a) {
      if (!includeSystem && a.is_system) return;
      var rule = V6_SELF_FW.uid_rules[String(a.uid)] || null;
      var fwMode = rule ? rule.mode : 'allow';
      var netShare = netF === 'wifi' ? a.wifi_share : (netF === 'cell' ? (1 - a.wifi_share) : 1.0);
      var isBlockedNow = fwMode === 'block_all' || (fwMode === 'block_cellular' && netF === 'cell');
      var jitter = 0.88 + ((hashStr(a.pkg + Math.floor(Date.now() / 2000)) % 25) / 100);
      var rxBps = isBlockedNow ? 0 : round(a.rx_bps * jitter * (netF === 'all' ? 1 : netShare));
      var txBps = isBlockedNow ? 0 : round(a.tx_bps * jitter * (netF === 'all' ? 1 : netShare));
      var bgRx = round(a.bg_rx * pMul * netShare);
      var bgTx = round(a.bg_tx * pMul * netShare);
      var fgRx = round(a.fg_rx * pMul * netShare);
      var fgTx = round(a.fg_tx * pMul * netShare);
      var bgTot = bgRx + bgTx;
      var fgTot = fgRx + fgTx;
      var totB = bgTot + fgTot;
      var bgPct = totB > 0 ? round((bgTot * 1000) / totB) / 10 : 0;
      var liveConns = typeof v6BuildScalpelFlows === 'function' ? v6BuildScalpelFlows({ scope: 'host', uid: a.uid }).length : a.active_conns;
      var conns = isBlockedNow ? 0 : liveConns;
      if (conns === 0) { rxBps = 0; txBps = 0; }
      var flags = (a.cleartext_flags || []).filter(function (fl) {
        if (fwMode === 'block_all') return false;
        if (fwMode === 'block_cleartext' && fl === 'http_cleartext') return false;
        return true;
      });
      var row = {
        uid: a.uid,
        package: a.pkg,
        pkg: a.pkg,
        app_name: a.app_name,
        name: a.app_name,
        is_system: a.is_system,
        current_state: a.state,
        rx_bps: rxBps,
        tx_bps: txBps,
        total_bps: rxBps + txBps,
        bg_rx_bytes: bgRx,
        bg_tx_bytes: bgTx,
        bg_total_bytes: bgTot,
        fg_rx_bytes: fgRx,
        fg_tx_bytes: fgTx,
        fg_total_bytes: fgTot,
        total_bytes: totB,
        bg_ratio_pct: bgPct,
        active_conns: conns,
        top_domains: a.top_domains.filter(function (dm) { return !v6MockIsSelfDomainBlocked(dm); }),
        cleartext_flags: flags,
        firewall_mode: fwMode
      };
      rows.push(row);
      sumRxBps += rxBps;
      sumTxBps += txBps;
      sumTotB += totB;
      sumBgB += bgTot;
      sumFgB += fgTot;
      if (conns > 0) activeConnApps++;
    });

    rows.sort(function (a, b) {
      if (sortBy === 'bg_bytes') return (b.bg_total_bytes - a.bg_total_bytes) || (b.total_bytes - a.total_bytes);
      if (sortRaw === 'bg_ratio') return (b.bg_ratio_pct - a.bg_ratio_pct) || (b.bg_total_bytes - a.bg_total_bytes);
      if (sortRaw === 'conns') return (b.active_conns - a.active_conns) || (b.total_bps - a.total_bps);
      if (sortBy === 'total_bytes') return (b.total_bytes - a.total_bytes) || (b.total_bps - a.total_bps);
      return (b.total_bps - a.total_bps) || (b.total_bytes - a.total_bytes);
    });

    var overallBgPct = sumTotB > 0 ? round((sumBgB * 1000) / sumTotB) / 10 : 0;
    return {
      ok: true,
      available: true,
      generated_at: now(),
      period: period,
      net: netF,
      sort: sortBy,
      include_system: includeSystem,
      rate_source: 'ebpf_uid_map',
      history_source: period === 'boot' ? 'netstats_ebpf_hybrid' : 'netstats_full',
      rate_warming_up: false,
      bg_split_available: true,
      lease_ttl_ms: 8000,
      summary: {
        total_rx_bps: sumRxBps,
        total_tx_bps: sumTxBps,
        total_bps: sumRxBps + sumTxBps,
        total_bytes: sumTotB,
        bg_total_bytes: sumBgB,
        fg_total_bytes: sumFgB,
        bg_ratio_pct: overallBgPct,
        app_count: rows.length,
        active_conn_apps: activeConnApps
      },
      apps: rows
    };
  }

  function v6LocalAppsPowerPayload(q) {
    q = q || {};
    var sortRaw = String(q.sort || 'bg_mah').trim().toLowerCase();
    var sortBy = sortRaw;
    if (sortRaw === 'wakelock_bg_ms') sortBy = 'wakelock_ms';
    else if (sortRaw === 'mobile_radio_active_ms') sortBy = 'radio_ms';
    else if (sortRaw === 'wakeup_alarms_count') sortBy = 'alarms';
    if (['bg_mah', 'screen_off_mah', 'total_mah', 'wakelock_ms', 'radio_ms', 'cpu_bg_ms', 'alarms'].indexOf(sortBy) < 0) sortBy = 'bg_mah';
    var includeSystem = bool(q.include_system);

    var rows = [];
    V6_HOST_APPS_CATALOG.forEach(function (a) {
      if (!includeSystem && a.is_system) return;
      var pw = a.power;
      var fwRule = V6_SELF_FW.uid_rules[String(a.uid)];
      rows.push({
        uid: a.uid,
        package: a.pkg,
        pkg: a.pkg,
        app_name: a.app_name,
        name: a.app_name,
        is_system: a.is_system,
        firewall_mode: fwRule ? fwRule.mode : 'allow',
        total_mah: pw.total_mah,
        fg_mah: pw.fg_mah,
        bg_mah: pw.bg_mah,
        fgs_mah: pw.fgs_mah,
        cached_mah: pw.cached_mah,
        screen_off_mah: pw.screen_off_mah,
        bg_mah_available: true,
        bg_components_mah: {
          cpu: round(pw.bg_mah * 38) / 100,
          mobile_radio: round(pw.bg_mah * 44) / 100,
          wifi: round(pw.bg_mah * 18) / 100
        },
        wakelock_partial_ms: pw.wl_ms,
        wakelock_bg_ms: pw.wl_bg_ms,
        wakelock_count: pw.wl_cnt,
        top_wakelocks: clone(pw.top_wl),
        mobile_radio_active_ms: pw.radio_ms,
        mobile_radio_wakeup_count: pw.radio_cnt,
        wifi_running_ms: pw.wifi_ms,
        wifi_bg_scan_count: pw.wifi_scan,
        cpu_total_ms: pw.cpu_tot_ms,
        cpu_fg_ms: pw.cpu_fg_ms,
        cpu_bg_ms: pw.cpu_bg_ms,
        wakeup_alarms_count: pw.alarms,
        top_wakeup_alarms: clone(pw.top_alarms),
        bg_jobs_ms: pw.jobs_ms,
        bg_jobs_count: pw.jobs_cnt
      });
    });

    rows.sort(function (a, b) {
      if (sortBy === 'screen_off_mah') return (b.screen_off_mah - a.screen_off_mah) || (b.total_mah - a.total_mah);
      if (sortBy === 'total_mah') return (b.total_mah - a.total_mah) || (b.bg_mah - a.bg_mah);
      if (sortBy === 'wakelock_ms') return (b.wakelock_bg_ms - a.wakelock_bg_ms) || (b.wakelock_partial_ms - a.wakelock_partial_ms);
      if (sortBy === 'radio_ms') return (b.mobile_radio_active_ms - a.mobile_radio_active_ms) || (b.bg_mah - a.bg_mah);
      if (sortBy === 'cpu_bg_ms') return (b.cpu_bg_ms - a.cpu_bg_ms) || (b.cpu_total_ms - a.cpu_total_ms);
      if (sortBy === 'alarms') return (b.wakeup_alarms_count - a.wakeup_alarms_count) || (b.bg_mah - a.bg_mah);
      return (b.bg_mah - a.bg_mah) || (b.total_mah - a.total_mah);
    });

    return {
      ok: true,
      available: true,
      generated_at: now() - 8,
      cached: false,
      refresh_throttled: false,
      sort: sortBy,
      include_system: includeSystem,
      power_model_format: 'a14_multi_state',
      bg_mah_available: true,
      screen_off_mah_available: true,
      app_count: rows.length,
      device_summary: {
        battery_capacity_mah: 5000,
        computed_drain_mah: 1184.5,
        actual_discharge_mah: 1240.0,
        total_discharge_mah: 1240.0,
        screen_off_discharge_mah: 186.4,
        screen_on_discharge_mah: 1053.6,
        time_on_battery_ms: 34200000,
        screen_off_on_battery_ms: 21600000,
        deep_doze_pct: 84.2
      },
      apps: rows
    };
  }

  function v6LocalAppsPrivacyAuditPayload(q) {
    q = q || {};
    var includeSystem = bool(q.include_system);
    var seedFindings = [
      {
        risk_type: 'http_cleartext',
        severity: 'high',
        uid: 10294,
        package: 'com.weather.fastcalendar',
        app_name: '极速天气日历',
        is_system: false,
        app_state: 'background',
        proto: 'tcp',
        remote_ip: '112.80.144.28',
        remote_port: 80,
        domain: 'api-plain.fastcalendar-sdk.cn',
        owner_org: '国内第三方云节点',
        up_bytes: 48 * KB,
        down_bytes: 164 * KB,
        up_bps: 1420,
        detail: '明文 HTTP 未加密传输至 api-plain.fastcalendar-sdk.cn (112.80.144.28):80'
      },
      {
        risk_type: 'dns_direct',
        severity: 'high',
        uid: 10294,
        package: 'com.weather.fastcalendar',
        app_name: '极速天气日历',
        is_system: false,
        app_state: 'background',
        proto: 'udp',
        remote_ip: '114.114.114.114',
        remote_port: 53,
        domain: '',
        owner_org: '114DNS',
        up_bytes: 14 * KB,
        down_bytes: 29 * KB,
        up_bps: 320,
        detail: '绕过系统 netd DNS 代理直连外部明文 DNS 114.114.114.114:53'
      },
      {
        risk_type: 'http_cleartext',
        severity: 'high',
        uid: 10318,
        package: 'com.kuaishou.nebula',
        app_name: '快手极速版',
        is_system: false,
        app_state: 'background',
        proto: 'tcp',
        remote_ip: '116.196.72.51',
        remote_port: 80,
        domain: 'log-sdk.ad-nebula-demo.cn',
        owner_org: '广告归因云服务',
        up_bytes: 92 * KB,
        down_bytes: 28 * KB,
        up_bps: 1860,
        detail: '明文 HTTP 未加密传输至 log-sdk.ad-nebula-demo.cn (116.196.72.51):80'
      },
      {
        risk_type: 'tracker_sdk',
        severity: 'medium',
        uid: 10318,
        package: 'com.kuaishou.nebula',
        app_name: '快手极速版',
        is_system: false,
        app_state: 'background',
        proto: 'tcp',
        remote_ip: '116.196.72.51',
        remote_port: 443,
        domain: 'sdk.mob-analytics-tracker.cn',
        owner_org: '移动广告监测 SDK',
        sdk_name: 'MobAnalytics 行为追踪 SDK',
        up_bytes: 210 * KB,
        down_bytes: 64 * KB,
        up_bps: 940,
        detail: '连接第三方追踪/广告 SDK [MobAnalytics 行为追踪 SDK] (sdk.mob-analytics-tracker.cn)'
      },
      {
        risk_type: 'bg_silent_uplink',
        severity: 'medium',
        uid: 10356,
        package: 'com.cloudalbum.sync',
        app_name: '相册云盘备份',
        is_system: false,
        app_state: 'background',
        proto: 'tcp',
        remote_ip: '123.56.91.40',
        remote_port: 443,
        domain: 'up-z2.qiniup.com',
        owner_org: '对象存储云节点',
        up_bytes: 184 * MB,
        down_bytes: 3 * MB,
        up_bps: 386000,
        detail: '应用处于后台静默状态持续向 up-z2.qiniup.com:443 外发数据'
      }
    ];

    var summary = {
      cleartext_http_conns: 0,
      direct_dns_conns: 0,
      tracker_sdk_conns: 0,
      bg_active_conns: 0,
      risky_apps_count: 0
    };
    var riskySet = {};
    var findings = [];
    seedFindings.forEach(function (f) {
      if (!includeSystem && f.is_system) return;
      var rule = V6_SELF_FW.uid_rules[String(f.uid)];
      var fwMode = rule ? rule.mode : 'allow';
      if (fwMode === 'block_all') return;
      if (fwMode === 'block_cleartext' && f.risk_type === 'http_cleartext') return;
      if (f.domain && v6MockIsSelfDomainBlocked(f.domain)) return;
      if (f.remote_ip && v6MockIsSelfIpBlocked(f.remote_ip, f.uid)) return;
      var copy = clone(f);
      copy.firewall_mode = fwMode;
      findings.push(copy);
      riskySet[String(copy.uid)] = 1;
      if (copy.risk_type === 'http_cleartext') summary.cleartext_http_conns++;
      else if (copy.risk_type === 'dns_direct') summary.direct_dns_conns++;
      else if (copy.risk_type === 'tracker_sdk') summary.tracker_sdk_conns++;
      else if (copy.risk_type === 'bg_silent_uplink') summary.bg_active_conns++;
    });
    summary.risky_apps_count = Object.keys(riskySet).length;
    return {
      ok: true,
      available: true,
      generated_at: now(),
      self_capture_enabled: !!SELF_ON.toggle,
      self_capture_mode: STUDIO_MODE || 'smart_screen',
      summary: summary,
      findings: findings
    };
  }

  function v6HostGuardianSummary() {
    var tr = v6LocalAppsTrafficPayload({ period: 'boot', net: 'all', include_system: false });
    var pa = v6LocalAppsPrivacyAuditPayload({ include_system: false });
    return {
      lease_active: true,
      rate_warming_up: false,
      self_capture_enabled: !!SELF_ON.toggle,
      self_capture_mode: STUDIO_MODE || 'smart_screen',
      tracked_apps: tr.apps.length,
      total_rx_bps: tr.summary.total_rx_bps,
      total_tx_bps: tr.summary.total_tx_bps,
      power_cached: true,
      privacy_cached: true,
      risky_apps_count: pa.summary.risky_apps_count
    };
  }

  var V6_LG_STATE = {
    notify_enabled: true,
    lockscreen_mask: true,
    capacity: 300,
    cooldown_sec: 300,
    blocked_set: { 'adtrack-legacy.example.cn': 1, '106.11.43.88': 1 },
    ignore_rules: [
      { id: 'ig_seed_1', scope: 'host_type', dst_host: 'weather-sdk.demo-cdn.cn', leak_type: 'GPS', mac: '', note: '天气组件定位更新', created_at: T - 600 }
    ],
    undo_stack: [
      { id: 'ub_seed_1', dst_host: 'adtrack-legacy.example.cn', kind: 'domain', target_scope: 'hotspot', also_ip: '106.11.43.88', macs: ['6a:0e:55:b1:9c:42'], created_at: T - 260 }
    ],
    events: [
      {
        id: 'lg_host_01',
        origin: 'host',
        ts: T - 12,
        uid: 10294,
        package: 'com.weather.fastcalendar',
        app_name: '极速天气日历',
        mac: '',
        device_name: '本机 · 极速天气日历',
        src_ip: '10.68.14.92',
        src_port: 46812,
        dst_ip: '112.80.144.28',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'TOKEN',
        raw_value: 'tk_live_98a1c7f204e6b319d502cc81',
        dst_host: 'api-plain.fastcalendar-sdk.cn',
        hit_count: 2,
        method: 'POST',
        path: '/v1/sync/profile',
        user_agent: 'okhttp/4.11.0',
        is_blocked: false,
        raw_snippet: 'POST /v1/sync/profile HTTP/1.1\r\nHost: api-plain.fastcalendar-sdk.cn\r\nUser-Agent: okhttp/4.11.0\r\nX-Auth-Token: tk_live_98a1c7f204e6b319d502cc81\r\nContent-Type: application/json\r\n\r\n{"city":"310000","token":"tk_live_98a1c7f204e6b319d502cc81"}'
      },
      {
        id: 'lg_v6_01',
        origin: 'hotspot',
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
        id: 'lg_host_02',
        origin: 'host',
        ts: T - 35,
        uid: 10318,
        package: 'com.kuaishou.nebula',
        app_name: '快手极速版',
        mac: '',
        device_name: '本机 · 快手极速版',
        src_ip: '10.68.14.92',
        src_port: 49104,
        dst_ip: '116.196.72.51',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'DEVICE_ID',
        raw_value: 'android_id_77c3e9104b28f605',
        dst_host: 'log-sdk.ad-nebula-demo.cn',
        hit_count: 4,
        method: 'GET',
        path: '/ad/report?aid=android_id_77c3e9104b28f605&net=5g',
        user_agent: 'Dalvik/2.1.0 (Linux; Android 15)',
        is_blocked: false,
        raw_snippet: 'GET /ad/report?aid=android_id_77c3e9104b28f605&net=5g HTTP/1.1\r\nHost: log-sdk.ad-nebula-demo.cn\r\nUser-Agent: Dalvik/2.1.0 (Linux; Android 15)'
      },
      {
        id: 'lg_v6_02',
        origin: 'hotspot',
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
        id: 'lg_host_03',
        origin: 'host',
        ts: T - 89,
        uid: 10356,
        package: 'com.cloudalbum.sync',
        app_name: '相册云盘备份',
        mac: '',
        device_name: '本机 · 相册云盘备份',
        src_ip: '10.68.14.92',
        src_port: 43922,
        dst_ip: '123.56.91.40',
        dst_port: 80,
        proto: 'tcp',
        leak_type: 'ID_CARD',
        raw_value: '11010119900307451X',
        dst_host: 'ocr-legacy.album-verify.cn',
        hit_count: 1,
        method: 'POST',
        path: '/ocr/cert_check',
        user_agent: 'AlbumSync/4.2.0',
        is_blocked: false,
        raw_snippet: 'POST /ocr/cert_check HTTP/1.1\r\nHost: ocr-legacy.album-verify.cn\r\nUser-Agent: AlbumSync/4.2.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid_no=11010119900307451X&scene=realname_backup'
      },
      {
        id: 'lg_v6_03',
        origin: 'hotspot',
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
        dst_host: 'oss-cn-shanghai.aliyuncs.com',
        infra_guard: { level: 'warn_confirm', label: '阿里云 OSS 公共底座' },
        hit_count: 2,
        method: 'GET',
        path: '/loc/check?latlng=31.230416,121.473701&coord=gcj02',
        user_agent: 'okhttp/4.12.0',
        is_blocked: false,
        raw_snippet: 'GET /loc/check?latlng=31.230416,121.473701&coord=gcj02 HTTP/1.1\r\nHost: oss-cn-shanghai.aliyuncs.com\r\nUser-Agent: okhttp/4.12.0\r\nConnection: keep-alive'
      },
      {
        id: 'lg_v6_04',
        origin: 'hotspot',
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
        origin: 'hotspot',
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
        dst_host: 'connect.rom.miui.com',
        infra_guard: { level: 'hard_block', label: '系统联网探测核心域' },
        hit_count: 1,
        method: 'POST',
        path: '/generate_204?mac=7e:c4:19:20:5a:8b',
        user_agent: 'SmartSpeaker-HTTP/1.8',
        is_blocked: false,
        raw_snippet: 'POST /generate_204?mac=7e:c4:19:20:5a:8b HTTP/1.1\r\nHost: connect.rom.miui.com\r\nUser-Agent: SmartSpeaker-HTTP/1.8\r\nContent-Type: application/json\r\n\r\n{"mac":"7e:c4:19:20:5a:8b","fw":"2.14.8"}'
      }
    ]
  };

  function v6MockEventWhitelisted(ev) {
    var host = String((ev && ev.dst_host) || '').toLowerCase();
    var tp = String((ev && ev.leak_type) || '').toUpperCase();
    var mac = String((ev && ev.mac) || '').toLowerCase();
    return (V6_LG_STATE.ignore_rules || []).some(function (w) {
      if (!w) return false;
      var wh = String(w.dst_host || '').toLowerCase();
      if (wh && host !== wh && host.slice(-(wh.length + 1)) !== '.' + wh && ev.dst_ip !== wh) return false;
      if (w.leak_type && String(w.leak_type).toUpperCase() !== tp) return false;
      if (w.mac && String(w.mac).toLowerCase() !== mac) return false;
      return true;
    });
  }

  function v6LeakGuardPayload(q) {
    var scope = String((q && q.scope) || 'all').trim().toLowerCase();
    if (scope !== 'hotspot' && scope !== 'host') scope = 'all';
    var totalHits = 0, hsHits = 0, hostHits = 0, devMap = {}, appMap = {};
    var allVisible = V6_LG_STATE.events.filter(function (ev) { return !v6MockEventWhitelisted(ev); });
    allVisible.forEach(function (ev) {
      var hits = ev.hit_count || 1;
      var org = ev.origin === 'host' ? 'host' : 'hotspot';
      totalHits += hits;
      if (org === 'host') {
        hostHits += hits;
        if (ev.uid || ev.package) appMap[String(ev.uid || ev.package)] = 1;
      } else {
        hsHits += hits;
        if (ev.mac || ev.src_ip) devMap[ev.mac || ev.src_ip] = 1;
      }
      if (!ev.infra_guard) {
        var ig = v6MockInfraGuard(ev.dst_host);
        if (ig) ev.infra_guard = ig;
      }
      var dlow = String(ev.dst_host || '').toLowerCase();
      var iplow = String(ev.dst_ip || '').toLowerCase();
      var evUidNum = ev.uid ? round(+ev.uid) : 0;
      var evAppId = evUidNum % 100000;
      var uidRule = evUidNum ? (V6_SELF_FW.uid_rules[String(evUidNum)] || ((evAppId >= 20000 && evAppId <= 29999) ? V6_SELF_FW.uid_rules[String(evUidNum - 10000)] : null)) : null;
      var isClearHttp = (!ev.proto || ev.proto === 'tcp' || ev.proto === 'http') && (!ev.dst_port || [80, 8080, 8000, 8008, 8888].indexOf(+ev.dst_port) >= 0);
      ev.is_blocked = org === 'host'
        ? (v6MockIsSelfDomainBlocked(dlow) || v6MockIsSelfIpBlocked(dlow, evUidNum) || (iplow ? v6MockIsSelfIpBlocked(iplow, evUidNum) : false) || !!(uidRule && (uidRule.mode === 'block_all' || (uidRule.mode === 'block_cleartext' && isClearHttp))))
        : (!!V6_LG_STATE.blocked_set[dlow] || !!V6_LG_STATE.blocked_set[iplow]);
    });
    var filteredEvents = scope === 'all' ? allVisible : allVisible.filter(function (ev) {
      return (ev.origin === 'host' ? 'host' : 'hotspot') === scope;
    });
    var blkCnt = Object.keys(V6_LG_STATE.blocked_set).filter(function (k) { return !/^\d+\.\d+\.\d+\.\d+$/.test(k) && k.indexOf(':') < 0; }).length;
    var selfBlkCnt = Object.keys(V6_SELF_FW.blocked_domains).length;
    var affectedDevs = Object.keys(devMap).length;
    var affectedApps = Object.keys(appMap).length;
    var igCnt = V6_LG_STATE.ignore_rules.length;
    var undoCnt = V6_LG_STATE.undo_stack.length;
    return {
      ok: true,
      scope: scope,
      total_hits: totalHits,
      hotspot_hits: hsHits,
      host_hits: hostHits,
      affected_devices: affectedDevs,
      affected_apps: affectedApps,
      blocked_domains: blkCnt,
      self_blocked_domains: selfBlkCnt,
      ignore_rules_cnt: igCnt,
      config: {
        notify_enabled: V6_LG_STATE.notify_enabled,
        lockscreen_mask: V6_LG_STATE.lockscreen_mask,
        capacity: V6_LG_STATE.capacity,
        cooldown_sec: V6_LG_STATE.cooldown_sec
      },
      stats: {
        total_hits: totalHits,
        hotspot_hits: hsHits,
        host_hits: hostHits,
        affected_devices: affectedDevs,
        affected_apps: affectedApps,
        blocked_domains: blkCnt,
        self_blocked_domains: selfBlkCnt,
        ignore_rules_cnt: igCnt,
        undo_count: undoCnt
      },
      ignore_rules: V6_LG_STATE.ignore_rules.slice(),
      undo_stack: V6_LG_STATE.undo_stack.slice(),
      undo_count: undoCnt,
      events: filteredEvents
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
    var hsOrSim = MOCK_HS_ACTIVE || !!(SIM && SIM.enabled);
    if (V6_EXP_STATE.enabled && hsOrSim) {
      V6_EXP_STATE.forced_macs.forEach(function (m) {
        var dm = dev(m);
        if (dm && !isDevActive(dm)) return;
        if (escorted.indexOf(m) < 0) escorted.push(m);
        reasons[m] = '手动常驻锁定零排队护航 (PRIO 0)';
      });
      if (V6_EXP_STATE.auto_detect) {
        var dGame = dev('0a:7f:3c:41:9e:21');
        if (dGame && isDevActive(dGame)) {
          if (escorted.indexOf(dGame.mac) < 0) escorted.push(dGame.mac);
          reasons[dGame.mac] = '王者荣耀 UDP 高频对战微突发 + 常驻锁定';
        }
        var dCall = dev('3a:91:d4:6b:02:5f');
        if (dCall && isDevActive(dCall)) {
          if (escorted.indexOf(dCall.mac) < 0) escorted.push(dCall.mac);
          reasons[dCall.mac] = '腾讯会议 WebRTC EF(46) 实时双向音视频流';
        }
      }
    }
    var active = V6_EXP_STATE.enabled && hsOrSim && escorted.length > 0;
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
      dataplane_tier: 'tier2_native_netlink',
      dataplane: { qdisc: V6_EXP_STATE.qdisc, tier: 'tier2_native_netlink', active_tier: 'tier2_native_netlink' }
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
    var computed = !MOCK_HS_ACTIVE ? [] : V6_UL_STATE.sessions.map(function (s) {
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
    shell_temp_c: 31.2,
    battery_temp_c: 30.8,
    shell_temp_available: true,
    battery_spoof_suspected: false,
    capacity_pct: 82,
    is_charging: false,
    bat_status: 'Discharging'
  };

  function v6ThermoPayload() {
    var exActive = v6ExpressPayload().active;
    var wave = Math.sin(Date.now() / 45000) * 0.2;
    var shellTc = round((V6_TH_STATE.shell_temp_c + wave) * 10) / 10;
    var batTc = round((V6_TH_STATE.battery_temp_c + wave * 0.8) * 10) / 10;
    var effTc = V6_TH_STATE.shell_temp_available ? shellTc : batTc;
    var rawStg = effTc >= V6_TH_STATE.stage2_temp_c ? 2 : (effTc >= V6_TH_STATE.stage1_temp_c ? 1 : 0);
    var exempt = V6_TH_STATE.is_charging || exActive;
    var effStg = !V6_TH_STATE.enabled ? 0 : (rawStg === 2 && exempt ? 1 : rawStg);
    return {
      ok: true,
      enabled: V6_TH_STATE.enabled,
      stage2_shaper_enabled: V6_TH_STATE.stage2_shaper_enabled,
      stage1_temp_c: V6_TH_STATE.stage1_temp_c,
      stage2_temp_c: V6_TH_STATE.stage2_temp_c,
      low_bat_pct: V6_TH_STATE.low_bat_pct,
      temp_c: effTc,
      battery_temp_c: batTc,
      shell_temp_c: shellTc,
      shell_temp_available: V6_TH_STATE.shell_temp_available,
      battery_spoof_suspected: V6_TH_STATE.battery_spoof_suspected,
      capacity_pct: V6_TH_STATE.capacity_pct,
      status: V6_TH_STATE.bat_status,
      is_charging: !!V6_TH_STATE.is_charging,
      battery: {
        available: true,
        temp_c: batTc,
        battery_temp_c: batTc,
        shell_temp_c: shellTc,
        shell_temp_available: V6_TH_STATE.shell_temp_available,
        battery_spoof_suspected: V6_TH_STATE.battery_spoof_suspected,
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
      { key: 'tcp|192.168.43.67|106.11.43.88|80', proto: 'tcp', src_ip: '192.168.43.67', dst_ip: '106.11.43.88', dport: 80, scope: 'hotspot', expires_at: T + 780 }
    ]
  };

  function v6BuildScalpelFlows(q) {
    q = q || {};
    stepRates();
    var nowSec = now();
    V6_SC_STATE.frozen_rules = V6_SC_STATE.frozen_rules.filter(function (r) { return r.expires_at > nowSec; });
    var frozenMap = {};
    V6_SC_STATE.frozen_rules.forEach(function (r) {
      frozenMap[r.proto + '|' + r.src_ip + '|' + r.dst_ip + '|' + r.dport] = r.expires_at;
    });

    var hsFlows = !MOCK_HS_ACTIVE ? [] : [
      { flow_key: 'sc_01', scope: 'hotspot', mac: '0a:7f:3c:41:9e:21', device_name: '小米 14', proto: 'udp', src_ip: '192.168.43.23', sport: 55120, dst_ip: '183.3.226.35', dport: 10012, domain: 'pvp.qq.com', app_name: '王者荣耀', state: 'ASSURED', down_bps: 148000, up_bps: 72000, down_bytes: 18 * MB, up_bytes: 7 * MB, cleartext_risk: '' },
      { flow_key: 'sc_02', scope: 'hotspot', mac: '0a:7f:3c:41:9e:21', device_name: '小米 14', proto: 'tcp', src_ip: '192.168.43.23', sport: 51428, dst_ip: '114.118.24.66', dport: 80, domain: 'sdk-report.example-ad.cn', app_name: '广告遥测 SDK', state: 'ESTABLISHED', down_bps: 4200, up_bps: 1800, down_bytes: 64 * KB, up_bytes: 28 * KB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_03', scope: 'hotspot', mac: '3a:91:d4:6b:02:5f', device_name: 'MacBook Pro', proto: 'udp', src_ip: '192.168.43.31', sport: 60412, dst_ip: '119.147.82.44', dport: 3480, domain: 'avc.meeting.qq.com', app_name: '腾讯会议', state: 'ASSURED', down_bps: 420000, up_bps: 310000, down_bytes: 192 * MB, up_bytes: 148 * MB, cleartext_risk: '' },
      { flow_key: 'sc_04', scope: 'hotspot', mac: '3a:91:d4:6b:02:5f', device_name: 'MacBook Pro', proto: 'tcp', src_ip: '192.168.43.31', sport: 58310, dst_ip: '120.55.89.14', dport: 80, domain: 'legacy-api.devtool-sync.net', app_name: '命令行工具', state: 'ESTABLISHED', down_bps: 2400, up_bps: 1200, down_bytes: 42 * KB, up_bytes: 19 * KB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_05', scope: 'hotspot', mac: '1e:52:a8:0c:77:3d', device_name: 'iPad Air', proto: 'quic', src_ip: '192.168.43.45', sport: 52890, dst_ip: '111.225.148.29', dport: 443, domain: 'v26-dy.douyinvod.com', app_name: '抖音', state: 'ASSURED', down_bps: 1940000, up_bps: 68000, down_bytes: 412 * MB, up_bytes: 14 * MB, cleartext_risk: '' },
      { flow_key: 'sc_06', scope: 'hotspot', mac: '5e:20:b7:3a:c4:18', device_name: '任天堂 Switch', proto: 'tcp', src_ip: '192.168.43.52', sport: 49218, dst_ip: '104.111.42.88', dport: 443, domain: 'atum.hac.lp1.d4c.nintendo.net', app_name: '任天堂 eShop', state: 'ESTABLISHED', down_bps: 185000, up_bps: 9200, down_bytes: 648 * MB, up_bytes: 9 * MB, cleartext_risk: '' },
      { flow_key: 'sc_07', scope: 'hotspot', mac: '6a:0e:55:b1:9c:42', device_name: '客厅电视', proto: 'quic', src_ip: '192.168.43.67', sport: 43106, dst_ip: '36.110.188.72', dport: 443, domain: 'data.video.iqiyi.com', app_name: '爱奇艺', state: 'ASSURED', down_bps: 2310000, up_bps: 42000, down_bytes: 1120 * MB, up_bytes: 21 * MB, cleartext_risk: '' },
      { flow_key: 'sc_08', scope: 'hotspot', mac: '6a:0e:55:b1:9c:42', device_name: '客厅电视', proto: 'tcp', src_ip: '192.168.43.67', sport: 39820, dst_ip: '106.11.43.88', dport: 80, domain: 'adtrack-legacy.example.cn', app_name: '电视开屏 SDK', state: 'TIME_WAIT', down_bps: 0, up_bps: 0, down_bytes: 128 * KB, up_bytes: 24 * KB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_08a', scope: 'hotspot', mac: '7e:c4:19:20:5a:8b', device_name: '小爱音箱', proto: 'tcp', src_ip: '192.168.43.71', sport: 46120, dst_ip: '183.3.226.92', dport: 443, domain: 'isure.stream.qqmusic.qq.com', app_name: 'QQ音乐', state: 'ESTABLISHED', down_bps: 42000, up_bps: 6400, down_bytes: 96 * MB, up_bytes: 4 * MB, cleartext_risk: '' },
      { flow_key: 'sc_08b', scope: 'hotspot', mac: '7e:c4:19:20:5a:8b', device_name: '小爱音箱', proto: 'tcp', src_ip: '192.168.43.71', sport: 47204, dst_ip: '42.62.94.19', dport: 80, domain: 'connect.rom.miui.com', app_name: '系统连通检测', state: 'ESTABLISHED', down_bps: 1200, up_bps: 520, down_bytes: 640 * KB, up_bytes: 190 * KB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_08c', scope: 'hotspot', mac: '8a:3d:62:f0:11:c9', device_name: '华为 MatePad', proto: 'quic', src_ip: '192.168.43.38', sport: 53410, dst_ip: '121.29.44.86', dport: 443, domain: 'txmov2.a.kwimgs.com', app_name: '快手', state: 'ASSURED', down_bps: 590000, up_bps: 44000, down_bytes: 312 * MB, up_bytes: 18 * MB, cleartext_risk: '' },
      { flow_key: 'sc_08d', scope: 'hotspot', mac: '8a:3d:62:f0:11:c9', device_name: '华为 MatePad', proto: 'tcp', src_ip: '192.168.43.38', sport: 53488, dst_ip: '183.47.102.19', dport: 443, domain: 'szextshort.weixin.qq.com', app_name: '微信', state: 'ESTABLISHED', down_bps: 48000, up_bps: 8200, down_bytes: 28 * MB, up_bytes: 6 * MB, cleartext_risk: '' },
      { flow_key: 'sc_09', scope: 'hotspot', mac: 'a6:5b:0f:93:7e:24', device_name: 'ThinkPad', proto: 'udp', src_ip: '192.168.43.84', sport: 51820, dst_ip: '203.0.113.18', dport: 51820, domain: 'wg-gateway.corp-demo.net', app_name: 'VPN/代理隧道', state: 'ASSURED', down_bps: 540000, up_bps: 145000, down_bytes: 186 * MB, up_bytes: 52 * MB, cleartext_risk: '' },
      { flow_key: 'sc_10', scope: 'hotspot', mac: 'd2:6e:4a:8c:15:f3', device_name: '192.168.43.96', proto: 'tcp', src_ip: '192.168.43.96', sport: 44912, dst_ip: '180.97.33.108', dport: 80, domain: 'weather-loc.iot-probe.cn', app_name: '天气定位组件', state: 'ESTABLISHED', down_bps: 1600, up_bps: 800, down_bytes: 18 * KB, up_bytes: 9 * KB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_11', scope: 'hotspot', mac: 'ae:14:7c:2b:90:d5', device_name: 'Redmi-K60', proto: 'quic', src_ip: '192.168.43.60', sport: 49812, dst_ip: '119.28.64.118', dport: 443, domain: 'upos-sz-mirrorcos.bilivideo.com', app_name: 'B站', state: 'ASSURED', down_bps: 310000, up_bps: 34000, down_bytes: 245 * MB, up_bytes: 14 * MB, cleartext_risk: '' },
      { flow_key: 'sc_12', scope: 'hotspot', mac: 'ae:14:7c:2b:90:d5', device_name: 'Redmi-K60', proto: 'tcp', src_ip: '192.168.43.60', sport: 49860, dst_ip: '183.47.102.19', dport: 443, domain: 'szextshort.weixin.qq.com', app_name: '微信', state: 'ESTABLISHED', down_bps: 28000, up_bps: 7400, down_bytes: 19 * MB, up_bytes: 4 * MB, cleartext_risk: '' }
    ];

    visibleDevs().forEach(function (sd) {
      if (!isDevActive(sd)) return;
      var dc = devConns(sd).conns || [];
      var usedKey = {};
      var curCnt = 0;
      hsFlows.forEach(function (f) {
        if (f.mac !== sd.mac) return;
        if (f.flow_key === 'sc_08') return; // pre-seeded LeakGuard blocked flow
        curCnt++;
        if (f.domain) usedKey['d:' + String(f.domain).toLowerCase()] = 1;
        if (f.dst_ip) usedKey['i:' + String(f.dst_ip).toLowerCase()] = 1;
      });
      var need = dc.length - curCnt;
      if (need <= 0) return;
      var cands = [];
      dc.forEach(function (c) {
        var kd = c.name ? ('d:' + String(c.name).toLowerCase()) : '';
        var ki = c.dst ? ('i:' + String(c.dst).toLowerCase()) : '';
        if ((kd && usedKey[kd]) || (ki && usedKey[ki])) return;
        cands.push(c);
      });
      if (cands.length < need) {
        dc.forEach(function (c) {
          if (cands.indexOf(c) < 0 && cands.length < need) cands.push(c);
        });
      }
      var macSlug = sd.mac.replace(/:/g, '');
      for (var j = 0; j < need && j < cands.length; j++) {
        var c = cands[j];
        var sp = (c.sport || (42000 + j * 17)) + j;
        hsFlows.push({
          flow_key: 'sc_dyn_' + macSlug + '_' + j,
          scope: 'hotspot',
          mac: sd.mac,
          device_name: sd.hostname || sd.ip || sd.mac,
          proto: c.proto || 'tcp',
          src_ip: sd.ip,
          sport: sp,
          dst_ip: c.dst || GW,
          dport: c.dport || 443,
          domain: c.name || '',
          app_name: c.app || (c.local ? '局域网 DNS' : ((c.owner && c.owner.name) || '连接会话')),
          state: c.state || (c.proto === 'udp' ? 'ASSURED' : 'ESTABLISHED'),
          down_bps: c.down_bps || 0,
          up_bps: c.up_bps || 0,
          down_bytes: c.down_bytes || 0,
          up_bytes: c.up_bytes || 0,
          cleartext_risk: (c.dport === 80 || c.dport === 8080) ? 'http_cleartext' : ''
        });
      }
    });

    var hostFlows = [
      /* 10234: 抖音 (3 条) */
      { flow_key: 'sc_h01', scope: 'host', uid: 10234, package: 'com.ss.android.ugc.aweme', pkg: 'com.ss.android.ugc.aweme', host_app_name: '抖音', mac: '', device_name: '本机 · 抖音', proto: 'quic', src_ip: '10.68.14.92', sport: 48210, dst_ip: '111.225.148.62', dport: 443, domain: 'v26-dy.douyinvod.com', app_name: '抖音', state: 'ASSURED', down_bps: 1380000, up_bps: 46000, down_bytes: 680 * MB, up_bytes: 28 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h01b', scope: 'host', uid: 10234, package: 'com.ss.android.ugc.aweme', pkg: 'com.ss.android.ugc.aweme', host_app_name: '抖音', mac: '', device_name: '本机 · 抖音', proto: 'tcp', src_ip: '10.68.14.92', sport: 48244, dst_ip: '111.225.148.91', dport: 443, domain: 'api5-normal-lq.amemv.com', app_name: '抖音', state: 'ESTABLISHED', down_bps: 76000, up_bps: 14000, down_bytes: 94 * MB, up_bytes: 12 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h01c', scope: 'host', uid: 10234, package: 'com.ss.android.ugc.aweme', pkg: 'com.ss.android.ugc.aweme', host_app_name: '抖音', mac: '', device_name: '本机 · 抖音', proto: 'tcp', src_ip: '10.68.14.92', sport: 48279, dst_ip: '36.155.132.47', dport: 443, domain: 'p26-sign.douyinpic.com', app_name: '抖音', state: 'ESTABLISHED', down_bps: 24000, up_bps: 4000, down_bytes: 42 * MB, up_bytes: 3 * MB, cleartext_risk: '' },
      /* 10198: 微信 (3 条) */
      { flow_key: 'sc_h02', scope: 'host', uid: 10198, package: 'com.tencent.mm', pkg: 'com.tencent.mm', host_app_name: '微信', mac: '', device_name: '本机 · 微信', proto: 'tcp', src_ip: '10.68.14.92', sport: 41908, dst_ip: '183.47.102.19', dport: 443, domain: 'szextshort.weixin.qq.com', app_name: '微信', state: 'ESTABLISHED', down_bps: 64000, up_bps: 28000, down_bytes: 210 * MB, up_bytes: 64 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h02b', scope: 'host', uid: 10198, package: 'com.tencent.mm', pkg: 'com.tencent.mm', host_app_name: '微信', mac: '', device_name: '本机 · 微信', proto: 'tcp', src_ip: '10.68.14.92', sport: 41952, dst_ip: '113.96.232.104', dport: 443, domain: 'mmsns.qpic.cn', app_name: '微信', state: 'ESTABLISHED', down_bps: 22000, up_bps: 6800, down_bytes: 124 * MB, up_bytes: 18 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h02c', scope: 'host', uid: 10198, package: 'com.tencent.mm', pkg: 'com.tencent.mm', host_app_name: '微信', mac: '', device_name: '本机 · 微信', proto: 'tcp', src_ip: '10.68.14.92', sport: 41986, dst_ip: '157.255.192.38', dport: 443, domain: 'wx.qlogo.cn', app_name: '微信', state: 'ESTABLISHED', down_bps: 6000, up_bps: 3200, down_bytes: 36 * MB, up_bytes: 5 * MB, cleartext_risk: '' },
      /* 10294: 极速天气日历 (3 条) */
      { flow_key: 'sc_h03', scope: 'host', uid: 10294, package: 'com.weather.fastcalendar', pkg: 'com.weather.fastcalendar', host_app_name: '极速天气日历', mac: '', device_name: '本机 · 极速天气日历', proto: 'tcp', src_ip: '10.68.14.92', sport: 46812, dst_ip: '112.80.144.28', dport: 80, domain: 'api-plain.fastcalendar-sdk.cn', app_name: '极速天气日历', state: 'ESTABLISHED', down_bps: 12400, up_bps: 6200, down_bytes: 18 * MB, up_bytes: 4 * MB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_h04', scope: 'host', uid: 10294, package: 'com.weather.fastcalendar', pkg: 'com.weather.fastcalendar', host_app_name: '极速天气日历', mac: '', device_name: '本机 · 极速天气日历', proto: 'udp', src_ip: '10.68.14.92', sport: 53914, dst_ip: '114.114.114.114', dport: 53, domain: '', app_name: '极速天气日历 (直连DNS)', state: 'UNREPLIED', down_bps: 900, up_bps: 420, down_bytes: 120 * KB, up_bytes: 64 * KB, cleartext_risk: 'dns_direct' },
      { flow_key: 'sc_h04b', scope: 'host', uid: 10294, package: 'com.weather.fastcalendar', pkg: 'com.weather.fastcalendar', host_app_name: '极速天气日历', mac: '', device_name: '本机 · 极速天气日历', proto: 'tcp', src_ip: '10.68.14.92', sport: 46890, dst_ip: '116.196.72.58', dport: 443, domain: 'sdk.mob-analytics-tracker.cn', app_name: '极速天气日历', state: 'ESTABLISHED', down_bps: 5200, up_bps: 2780, down_bytes: 9 * MB, up_bytes: 3 * MB, cleartext_risk: '' },
      /* 10318: 快手极速版 (3 条) */
      { flow_key: 'sc_h05', scope: 'host', uid: 10318, package: 'com.kuaishou.nebula', pkg: 'com.kuaishou.nebula', host_app_name: '快手极速版', mac: '', device_name: '本机 · 快手极速版', proto: 'tcp', src_ip: '10.68.14.92', sport: 49104, dst_ip: '116.196.72.51', dport: 80, domain: 'log-sdk.ad-nebula-demo.cn', app_name: '快手极速版', state: 'ESTABLISHED', down_bps: 28000, up_bps: 9600, down_bytes: 46 * MB, up_bytes: 11 * MB, cleartext_risk: 'http_cleartext' },
      { flow_key: 'sc_h05b', scope: 'host', uid: 10318, package: 'com.kuaishou.nebula', pkg: 'com.kuaishou.nebula', host_app_name: '快手极速版', mac: '', device_name: '本机 · 快手极速版', proto: 'quic', src_ip: '10.68.14.92', sport: 49142, dst_ip: '121.29.44.86', dport: 443, domain: 'txmov2.a.kwimgs.com', app_name: '快手极速版', state: 'ASSURED', down_bps: 148000, up_bps: 14200, down_bytes: 512 * MB, up_bytes: 32 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h05c', scope: 'host', uid: 10318, package: 'com.kuaishou.nebula', pkg: 'com.kuaishou.nebula', host_app_name: '快手极速版', mac: '', device_name: '本机 · 快手极速版', proto: 'tcp', src_ip: '10.68.14.92', sport: 49188, dst_ip: '121.29.44.99', dport: 443, domain: 'api.gifshow.com', app_name: '快手极速版', state: 'ESTABLISHED', down_bps: 8000, up_bps: 2200, down_bytes: 38 * MB, up_bytes: 9 * MB, cleartext_risk: '' },
      /* 10356: 相册云盘备份 (2 条) */
      { flow_key: 'sc_h06', scope: 'host', uid: 10356, package: 'com.cloudalbum.sync', pkg: 'com.cloudalbum.sync', host_app_name: '相册云盘备份', mac: '', device_name: '本机 · 相册云盘备份', proto: 'tcp', src_ip: '10.68.14.92', sport: 43980, dst_ip: '123.56.91.40', dport: 443, domain: 'up-z2.qiniup.com', app_name: '相册云盘备份', state: 'ESTABLISHED', down_bps: 12000, up_bps: 392000, down_bytes: 24 * MB, up_bytes: 840 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h06b', scope: 'host', uid: 10356, package: 'com.cloudalbum.sync', pkg: 'com.cloudalbum.sync', host_app_name: '相册云盘备份', mac: '', device_name: '本机 · 相册云盘备份', proto: 'tcp', src_ip: '10.68.14.92', sport: 43922, dst_ip: '123.56.91.48', dport: 80, domain: 'ocr-legacy.album-verify.cn', app_name: '相册云盘备份', state: 'ESTABLISHED', down_bps: 2000, up_bps: 28000, down_bytes: 4 * MB, up_bytes: 62 * MB, cleartext_risk: 'http_cleartext' },
      /* 10311: 哔哩哔哩 (4 条，含纯 IP P2P 节点) */
      { flow_key: 'sc_h07', scope: 'host', uid: 10311, package: 'tv.danmaku.bili', pkg: 'tv.danmaku.bili', host_app_name: '哔哩哔哩', mac: '', device_name: '本机 · 哔哩哔哩', proto: 'quic', src_ip: '10.68.14.92', sport: 45120, dst_ip: '119.28.64.118', dport: 443, domain: 'upos-sz-mirrorcos.bilivideo.com', app_name: '哔哩哔哩', state: 'ASSURED', down_bps: 29400, up_bps: 2800, down_bytes: 540 * MB, up_bytes: 18 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h07b', scope: 'host', uid: 10311, package: 'tv.danmaku.bili', pkg: 'tv.danmaku.bili', host_app_name: '哔哩哔哩', mac: '', device_name: '本机 · 哔哩哔哩', proto: 'tcp', src_ip: '10.68.14.92', sport: 45166, dst_ip: '120.92.113.45', dport: 443, domain: 'api.bilibili.com', app_name: '哔哩哔哩', state: 'ESTABLISHED', down_bps: 5200, up_bps: 1100, down_bytes: 62 * MB, up_bytes: 9 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h07c', scope: 'host', uid: 10311, package: 'tv.danmaku.bili', pkg: 'tv.danmaku.bili', host_app_name: '哔哩哔哩', mac: '', device_name: '本机 · 哔哩哔哩', proto: 'tcp', src_ip: '10.68.14.92', sport: 45198, dst_ip: '112.84.133.76', dport: 443, domain: 'i0.hdslb.com', app_name: '哔哩哔哩', state: 'ESTABLISHED', down_bps: 1400, up_bps: 300, down_bytes: 28 * MB, up_bytes: 2 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h07d', scope: 'host', uid: 10311, package: 'tv.danmaku.bili', pkg: 'tv.danmaku.bili', host_app_name: '哔哩哔哩', mac: '', device_name: '本机 · 哔哩哔哩', proto: 'tcp', src_ip: '10.68.14.92', sport: 45214, dst_ip: '59.82.43.77', dport: 443, domain: '', app_name: '哔哩哔哩 (P2P 节点)', state: 'ESTABLISHED', down_bps: 8400, up_bps: 1600, down_bytes: 48 * MB, up_bytes: 6 * MB, cleartext_risk: '' },
      /* 10287: 高德地图 (2 条) */
      { flow_key: 'sc_h08', scope: 'host', uid: 10287, package: 'com.autonavi.minimap', pkg: 'com.autonavi.minimap', host_app_name: '高德地图', mac: '', device_name: '本机 · 高德地图', proto: 'tcp', src_ip: '10.68.14.92', sport: 42610, dst_ip: '106.11.249.31', dport: 443, domain: 'm5.amap.com', app_name: '高德地图', state: 'ESTABLISHED', down_bps: 5800, up_bps: 2200, down_bytes: 78 * MB, up_bytes: 14 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h08b', scope: 'host', uid: 10287, package: 'com.autonavi.minimap', pkg: 'com.autonavi.minimap', host_app_name: '高德地图', mac: '', device_name: '本机 · 高德地图', proto: 'tcp', src_ip: '10.68.14.92', sport: 42648, dst_ip: '140.205.172.94', dport: 443, domain: 'webrd01.is.autonavi.com', app_name: '高德地图', state: 'ESTABLISHED', down_bps: 2400, up_bps: 900, down_bytes: 56 * MB, up_bytes: 8 * MB, cleartext_risk: '' },
      /* 10388: Via 浏览器 (2 条) */
      { flow_key: 'sc_h09', scope: 'host', uid: 10388, package: 'mark.via', pkg: 'mark.via', host_app_name: 'Via 浏览器', mac: '', device_name: '本机 · Via 浏览器', proto: 'quic', src_ip: '10.68.14.92', sport: 50312, dst_ip: '104.18.26.120', dport: 443, domain: 'developer.mozilla.org', app_name: 'Via 浏览器', state: 'ASSURED', down_bps: 1800, up_bps: 480, down_bytes: 64 * MB, up_bytes: 5 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h09b', scope: 'host', uid: 10388, package: 'mark.via', pkg: 'mark.via', host_app_name: 'Via 浏览器', mac: '', device_name: '本机 · Via 浏览器', proto: 'tcp', src_ip: '10.68.14.92', sport: 50344, dst_ip: '104.17.24.14', dport: 443, domain: 'cdnjs.cloudflare.com', app_name: 'Via 浏览器', state: 'ESTABLISHED', down_bps: 600, up_bps: 200, down_bytes: 32 * MB, up_bytes: 2 * MB, cleartext_risk: '' },
      /* 10045: 软件商店 (2 条) */
      { flow_key: 'sc_h10', scope: 'host', uid: 10045, is_system: true, package: 'com.heytap.market', pkg: 'com.heytap.market', host_app_name: '软件商店', mac: '', device_name: '本机 · 软件商店', proto: 'tcp', src_ip: '10.68.14.92', sport: 38910, dst_ip: '106.38.229.61', dport: 443, domain: 'api-cn.store.heytapmobi.com', app_name: '软件商店', state: 'ESTABLISHED', down_bps: 3100, up_bps: 820, down_bytes: 196 * MB, up_bytes: 8 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h10b', scope: 'host', uid: 10045, is_system: true, package: 'com.heytap.market', pkg: 'com.heytap.market', host_app_name: '软件商店', mac: '', device_name: '本机 · 软件商店', proto: 'tcp', src_ip: '10.68.14.92', sport: 38954, dst_ip: '117.161.74.29', dport: 443, domain: 'dl-cn.heytapimage.com', app_name: '软件商店', state: 'ESTABLISHED', down_bps: 1100, up_bps: 280, down_bytes: 116 * MB, up_bytes: 3 * MB, cleartext_risk: '' },
      /* 1000: Android 系统 (2 条) */
      { flow_key: 'sc_h11', scope: 'host', uid: 1000, is_system: true, package: 'android', pkg: 'android', host_app_name: 'Android 系统', mac: '', device_name: '本机 · Android 系统', proto: 'tcp', src_ip: '10.68.14.92', sport: 37412, dst_ip: '203.208.40.66', dport: 443, domain: 'connectivitycheck.gstatic.com', app_name: 'Android 系统', state: 'ESTABLISHED', down_bps: 1100, up_bps: 580, down_bytes: 14 * MB, up_bytes: 5 * MB, cleartext_risk: '' },
      { flow_key: 'sc_h11b', scope: 'host', uid: 1000, is_system: true, package: 'android', pkg: 'android', host_app_name: 'Android 系统', mac: '', device_name: '本机 · Android 系统', proto: 'udp', src_ip: '10.68.14.92', sport: 37488, dst_ip: '216.239.35.4', dport: 123, domain: 'time.android.com', app_name: 'Android 系统 (NTP)', state: 'ASSURED', down_bps: 500, up_bps: 320, down_bytes: 2 * MB, up_bytes: 1 * MB, cleartext_risk: '' }
    ];

    var fScope = String(q.scope || 'all').trim().toLowerCase();
    if (fScope !== 'hotspot' && fScope !== 'host') fScope = 'all';
    var fMac = String(q.mac || '').toLowerCase();
    var fIp = String(q.ip || '').trim();
    var fUid = (q.uid != null && q.uid !== '') ? round(+q.uid) : -1;

    var seedFlows = fScope === 'hotspot' ? hsFlows : (fScope === 'host' ? hostFlows : hsFlows.concat(hostFlows));
    var out = [];
    seedFlows.forEach(function (f) {
      var pNorm = (f.proto === 'udp' || f.proto === 'quic') ? 'udp' : 'tcp';
      var k5 = pNorm + '|' + f.src_ip + ':' + f.sport + '|' + f.dst_ip + ':' + f.dport;
      if (V6_SC_STATE.killed_keys[k5]) return;
      if (f.scope === 'hotspot' && f.domain && V6_LG_STATE.blocked_set[String(f.domain).toLowerCase()]) return;
      if (f.scope === 'hotspot' && f.dst_ip && V6_LG_STATE.blocked_set[String(f.dst_ip).toLowerCase()]) return;
      if (f.scope === 'host') {
        if (f.domain && v6MockIsSelfDomainBlocked(f.domain)) return;
        if (f.dst_ip && v6MockIsSelfIpBlocked(f.dst_ip, f.uid)) return;
        if (f.uid) {
          var fwR = V6_SELF_FW.uid_rules[String(f.uid)];
          if (fwR && fwR.mode === 'block_all') return;
          if (fwR && fwR.mode === 'block_cleartext' && (f.dport === 80 || f.dport === 8080 || f.dport === 8000)) return;
        }
      }
      if (fMac && f.mac !== fMac) return;
      if (fIp && f.src_ip !== fIp) return;
      if (fUid >= 0 && f.uid !== fUid) return;
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
    q = q || {};
    var flows = v6BuildScalpelFlows(q);
    var isScoped = (q.scope && String(q.scope).toLowerCase() !== 'all') || q.mac || q.ip || (q.uid != null && q.uid !== '');
    var countSrc = isScoped ? v6BuildScalpelFlows({ scope: 'all' }) : flows;
    var hsCnt = 0, hostCnt = 0;
    countSrc.forEach(function (f) { if (f.scope === 'host') hostCnt++; else hsCnt++; });
    var hsRules = V6_SC_STATE.frozen_rules.filter(function (r) { return r.scope !== 'host'; });
    var hostRulesCnt = V6_SC_STATE.frozen_rules.filter(function (r) { return r.scope === 'host'; }).length;
    return {
      ok: true,
      readable: true,
      scope: String(q.scope || 'all').toLowerCase(),
      total: flows.length,
      hotspot_flows: hsCnt,
      host_flows: hostCnt,
      hotspot_total: hsCnt,
      host_total: hostCnt,
      cut_total: V6_SC_STATE.cut_total,
      active_rules: hsRules,
      host_active_rules: hostRulesCnt,
      flows: flows
    };
  }

  var V6_BB_STATE = {
    granularity_ms: 200,
    total_ticks: 18420,
    latest_jitter_ms: 4.8,
    incidents: [
      {
        incident_id: 4,
        ts_unix_ms: (T - 190) * 1000,
        reason: 'rtt_and_bw_spike',
        cause_dim: 'device_hog',
        cause_label_zh: '设备大流量抢网',
        verdict_zh: '任天堂 Switch（任天堂 eShop）突发大流量下载，挤占热点带宽引起卡顿',
        root_cause_zh: '任天堂 Switch（任天堂 eShop）瞬时占用了 78% 的热点流量，已由后台限速平滑压制',
        peak_rtt_ms: 46.2,
        delta_rtt_ms: 21.7,
        jitter_ms: 28.4,
        bandwidth_util_pct: 91.5,
        down_util_pct: 91.5,
        up_util_pct: 18.2,
        culprit_is_hog: true,
        culprit_mac: '5e:20:b7:3a:c4:18',
        culprit_ip: '192.168.43.52',
        culprit_name: '任天堂 Switch',
        culprit_share_pct: 78,
        active_app_id: 'nintendo_eshop',
        active_app_name: '任天堂 eShop'
      },
      {
        incident_id: 3,
        ts_unix_ms: (T - 840) * 1000,
        reason: 'rtt_spike',
        cause_dim: 'cell_jitter',
        cause_label_zh: '基站信号抖动',
        verdict_zh: '上游移动网络基站空口瞬时抖动，并非热点内设备抢网',
        root_cause_zh: '热点下挂设备流量正常平稳（无抢网行为），本次跳 Ping 来自 5G SA n78 基站切站重传',
        rat: '5G SA',
        display_rat: '5G SA',
        band: 'n78',
        rsrp_dbm: -106,
        sinr_db: 3,
        peak_rtt_ms: 58.6,
        delta_rtt_ms: 34.1,
        jitter_ms: 24.2,
        bandwidth_util_pct: 22.0,
        down_util_pct: 22.0,
        up_util_pct: 9.4,
        culprit_is_hog: false,
        culprit_mac: '',
        culprit_name: ''
      },
      {
        incident_id: 2,
        ts_unix_ms: (T - 1920) * 1000,
        reason: 'bw_saturated',
        cause_dim: 'uplink_saturated',
        cause_label_zh: '手机上行占满',
        secondary_dims: ['device_hog'],
        verdict_zh: 'MacBook Pro（飞书）正在大量上传数据，占满上行通道引起跳 Ping',
        root_cause_zh: 'MacBook Pro（飞书）突发大流量上传挤满上行带宽，导致其他设备确认包排队延迟飙升',
        peak_rtt_ms: 63.4,
        delta_rtt_ms: 38.9,
        jitter_ms: 26.8,
        bandwidth_util_pct: 64.0,
        down_util_pct: 31.2,
        up_util_pct: 94.6,
        culprit_is_hog: true,
        culprit_mac: '3a:91:d4:6b:02:5f',
        culprit_ip: '192.168.43.31',
        culprit_name: 'MacBook Pro',
        culprit_share_pct: 84,
        active_app_id: 'feishu',
        active_app_name: '飞书'
      },
      {
        incident_id: 1,
        ts_unix_ms: (T - 3480) * 1000,
        reason: 'rtt_spike',
        cause_dim: 'thermal_throttle',
        cause_label_zh: '发热温控降速',
        verdict_zh: '手机发热（45.6°C）触发温控保护降速，引起延迟波动',
        root_cause_zh: '本次波动源于手机机身高温触发散热降速保护，热点下挂设备流量平稳，并非设备抢网',
        temp_c: 45.6,
        thermal_stage: 2,
        peak_rtt_ms: 49.0,
        delta_rtt_ms: 24.5,
        jitter_ms: 19.6,
        bandwidth_util_pct: 38.0,
        down_util_pct: 38.0,
        up_util_pct: 14.0,
        culprit_is_hog: false,
        culprit_mac: '',
        culprit_name: ''
      }
    ]
  };

  function v6BlackboxPayload() {
    V6_BB_STATE.total_ticks += 3;
    V6_BB_STATE.latest_jitter_ms = round((4.2 + Math.abs(Math.sin(Date.now() / 9000)) * 3.6) * 10) / 10;
    var rttActive = !!(AUTORATE && AUTORATE.enabled);
    var latestRtt = rttActive ? round((21.5 + Math.sin(Date.now() / 11000) * 2.4) * 10) / 10 : 0;
    return {
      ok: true,
      rtt_probe_active: true,
      latest_rtt_ms: rttActive ? latestRtt : 21.8,
      granularity_ms: V6_BB_STATE.granularity_ms,
      total_ticks: V6_BB_STATE.total_ticks,
      incident_count: V6_BB_STATE.incidents.length,
      latest_jitter_ms: V6_BB_STATE.latest_jitter_ms,
      incidents: V6_BB_STATE.incidents
    };
  }

  function v6ArbiterPayload() {
    var th = v6ThermoPayload();
    var sources = [];
    if (th.enabled && th.stage2_shaper_enabled && th.effective_stage >= 2) {
      sources.push({
        source: 'thermo_cruise',
        label: '发热温控巡航',
        down_mbps: 40,
        up_mbps: 15,
        reason_zh: '机身 ' + th.temp_c.toFixed(1) + '°C 温控巡航保护（压速至 40 Mbps 降温）',
        active: true
      });
    }
    if (AUTORATE.enabled && AUTORATE.state !== 'disabled') {
      sources.push({
        source: '5g_autorate',
        label: '5G 自适应总带宽',
        down_mbps: AUTORATE.cur_down_mbps,
        up_mbps: AUTORATE.cur_up_mbps,
        reason_zh: '5G 基站防抖巡航（当前上限 ↓' + AUTORATE.cur_down_mbps + ' / ↑' + AUTORATE.cur_up_mbps + ' Mbps，ΔRTT ' + AUTORATE.delta_rtt_ms + ' ms）',
        active: true
      });
    }
    if (CFG.global_shaper_enabled && !AUTORATE.enabled) {
      var gsDn = parseRate(CFG.global_shaper_down);
      var gsUp = parseRate(CFG.global_shaper_up);
      if (gsDn > 0 || gsUp > 0) {
        sources.push({
          source: 'global_shaper',
          label: '热点总网速上限',
          down_mbps: gsDn,
          up_mbps: gsUp,
          reason_zh: '手动全局带宽上限（↓' + (gsDn || '不限') + ' / ↑' + (gsUp || '不限') + ' Mbps）',
          active: true
        });
      }
    }
    sources.sort(function (a, b) { return (a.down_mbps || 999999) - (b.down_mbps || 999999); });
    var win = sources[0] || null;
    return {
      active: !!win,
      active_source: win ? win.source : 'none',
      winning_source: win ? win.source : 'none',
      effective_down_mbps: win ? win.down_mbps : 0,
      effective_up_mbps: win ? win.up_mbps : 0,
      active_limiter_reason: win ? win.reason_zh : '',
      sources: sources,
      throttle_sources: sources
    };
  }

  function v6MultiIfacePayload() {
    return {
      ok: true,
      primary_downstream: MOCK_HS_ACTIVE ? IFACE : '',
      shape_targets: MOCK_HS_ACTIVE ? [IFACE, 'ap_br_wlan2'] : [],
      dual_band_or_mlo: MOCK_HS_ACTIVE,
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

  function v6DataplaneTierStatusPayload() {
    var exPay = v6ExpressPayload();
    var clsOn = (MOCK_HS_ACTIVE || !!(SIM && SIM.enabled)) && CFG.clsact_bpf_mode !== 'off';
    return {
      active_tier: 'tier2_native_netlink',
      saved_forks: 1842,
      last_netlink_usec: 142,
      netlink_ops_total: 618,
      dedup_hits: 1420,
      tier3_batch_commits: 0,
      fallbacks: 0,
      offload_controlled: clsOn,
      clsact_bpf_ready: clsOn,
      sch_fq_available: true,
      rtnetlink_ready: true,
      express_active: !!exPay.active,
      express_bg_ceil_kbps: exPay.active ? round((AUTORATE.enabled ? AUTORATE.cur_down_mbps : 300) * 1000 * (V6_EXP_STATE.configured_bg_ceil_pct / 100)) : 0,
      update_leash_kbps: V6_UL_STATE.enabled ? V6_UL_STATE.leash_kbps : 0,
      global_down_kbps: AUTORATE.enabled ? AUTORATE.cur_down_mbps * 1000 : round(parseRate(CFG.global_shaper_down) * 1000),
      global_up_kbps: AUTORATE.enabled ? AUTORATE.cur_up_mbps * 1000 : round(parseRate(CFG.global_shaper_up) * 1000),
      probed_iface: MOCK_HS_ACTIVE ? IFACE : ((SIM && SIM.enabled) ? 'sim' : ''),
      updated_at: now()
    };
  }

  var V6_VAULT_SHA = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

  GET['/api/vector_sync'] = function () {
    var lv = GET['/api/live']({});
    var dv = GET['/api/devices']();
    var arb = v6ArbiterPayload();
    var hgSum = v6HostGuardianSummary();
    var sfSum = v6SelfFirewallSummary();
    var lgPay = v6LeakGuardPayload({ scope: 'all' });
    var exPay = v6ExpressPayload();
    var ulPay = v6LeashPayload();
    var thPay = v6ThermoPayload();
    var scPay = v6ScalpelPayload({});
    var dpTier = v6DataplaneTierStatusPayload();
    var v6Mod = {
      leakguard: lgPay,
      express: exPay,
      update_leash: ulPay,
      thermo: thPay,
      scalpel: scPay,
      self_firewall: sfSum
    };
    var packPay = {
      blackbox: v6BlackboxPayload(),
      multi_iface: v6MultiIfacePayload(),
      native_subtrees: v6SubtreesPayload(),
      host_guardian: hgSum,
      self_firewall: sfSum,
      arbiter: arb
    };
    return {
      ok: true,
      version: VER,
      version_code: VCODE,
      backend_version: VER,
      healthy: true,
      core_uptime_sec: 14820 + Math.floor((Date.now() - PAGE_T0) / 1000),
      dataplane_tier: dpTier.active_tier,
      dataplane: {
        tier: dpTier.active_tier,
        active_tier: dpTier.active_tier,
        qdisc: V6_EXP_STATE.qdisc
      },
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
      leakguard: lgPay,
      express: exPay,
      update_leash: ulPay,
      thermo: thPay,
      scalpel: scPay,
      host_guardian: hgSum,
      self_firewall: sfSum,
      arbiter: arb,
      v6: v6Mod,
      extensions: {
        v6: v6Mod,
        v6_pack: packPay,
        dataplane_tier: dpTier,
        arbiter: arb,
        host_guardian: hgSum,
        self_firewall: sfSum
      },
      v6_pack: packPay
    };
  };
  GET['/api/leakguard/events'] = function (q) { return v6LeakGuardPayload(q || {}); };
  GET['/api/leakguard/whitelist'] = function () {
    return { ok: true, ignore_rules: V6_LG_STATE.ignore_rules.slice(), ignore_rules_cnt: V6_LG_STATE.ignore_rules.length };
  };
  GET['/api/local_apps/traffic'] = function (q) { return v6LocalAppsTrafficPayload(q || {}); };
  GET['/api/v6/local_apps/traffic'] = GET['/api/local_apps/traffic'];
  GET['/api/local_apps/power'] = function (q) { return v6LocalAppsPowerPayload(q || {}); };
  GET['/api/v6/local_apps/power'] = GET['/api/local_apps/power'];
  GET['/api/local_apps/privacy_audit'] = function (q) { return v6LocalAppsPrivacyAuditPayload(q || {}); };
  GET['/api/v6/local_apps/privacy_audit'] = GET['/api/local_apps/privacy_audit'];
  GET['/api/local_apps/firewall'] = function () { return v6SelfFirewallSnapshot(); };
  GET['/api/v6/local_apps/firewall'] = GET['/api/local_apps/firewall'];
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
      dataplane_tier: 'tier2_native_netlink',
      json_engine: 'go1.27_encoding_json_v2'
    };
  };
  GET['/api/backup'] = function () {
    var fwSnap = v6SelfFirewallSnapshot();
    return {
      schema_version: 'hnc.backup.v6',
      module_version: VER,
      module_version_code: VCODE,
      exported_at: now(),
      file_count: 17,
      sha256: V6_VAULT_SHA,
      files: {
        'rules.json': rulesJson(),
        'vector_express.json': { enabled: V6_EXP_STATE.enabled, auto_detect: V6_EXP_STATE.auto_detect, forced_macs: V6_EXP_STATE.forced_macs },
        'update_leash.json': { enabled: V6_UL_STATE.enabled, grace_mb: V6_UL_STATE.grace_mb, leash_kbps: V6_UL_STATE.leash_kbps },
        'thermo_cruise.json': { enabled: V6_TH_STATE.enabled, stage1_temp_c: V6_TH_STATE.stage1_temp_c, stage2_temp_c: V6_TH_STATE.stage2_temp_c },
        'self_firewall.json': { version: 1, updated_at: fwSnap.updated_at, uid_rules: fwSnap.uid_rules, blocked_domains: fwSnap.blocked_domains }
      }
    };
  };

  function v6SyncDeviceBlocksForTarget(val, targetMac, add, labelTxt) {
    var norm = String(val || '').trim().toLowerCase();
    if (!norm) return;
    DEVS.forEach(function (d) {
      if (targetMac && d.mac !== targetMac) return;
      d.blocks = (d.blocks || []).filter(function (x) { return String(x.value || '').toLowerCase() !== norm; });
      if (add) {
        d.blocks.push({ kind: /^\d+\.\d+\.\d+\.\d+$/.test(norm) || norm.indexOf(':') >= 0 ? 'ip' : 'domain', value: norm, label: labelTxt || '隐私安检拦截', source: 'manual' });
      }
    });
  }

  function v6AssertAllowedKeys(obj, allowed) {
    if (!obj || typeof obj !== 'object') return;
    Object.keys(obj).forEach(function (k) {
      if (allowed.indexOf(k) < 0) throw err('json: unknown field "' + k + '"', 400);
    });
  }

  POST['/api/local_apps/firewall'] = function (b) { return v6ApplySelfFirewallMutation(b || {}); };
  POST['/api/v6/local_apps/firewall'] = POST['/api/local_apps/firewall'];

  POST['/api/leakguard/config'] = function (b) {
    v6AssertAllowedKeys(b, ['capacity', 'cooldown_sec', 'notify_enabled', 'lockscreen_mask']);
    if (b && typeof b.notify_enabled === 'boolean') V6_LG_STATE.notify_enabled = b.notify_enabled;
    if (b && typeof b.lockscreen_mask === 'boolean') V6_LG_STATE.lockscreen_mask = b.lockscreen_mask;
    if (b && b.capacity != null) V6_LG_STATE.capacity = lim(round(+b.capacity || 300), 10, 2000);
    if (b && b.cooldown_sec != null) V6_LG_STATE.cooldown_sec = lim(round(+b.cooldown_sec || 300), 0, 86400);
    return {
      ok: true,
      config: {
        notify_enabled: V6_LG_STATE.notify_enabled,
        lockscreen_mask: V6_LG_STATE.lockscreen_mask,
        capacity: V6_LG_STATE.capacity,
        cooldown_sec: V6_LG_STATE.cooldown_sec
      }
    };
  };
  POST['/api/leakguard/clear'] = function () {
    V6_LG_STATE.events = [];
    ALERTS = ALERTS.filter(function (a) { return a.kind !== 'leakguard'; });
    return { ok: true };
  };
  POST['/api/leakguard/whitelist'] = function (b) {
    v6AssertAllowedKeys(b, ['action', 'id', 'scope', 'dst_host', 'dst_ip', 'leak_type', 'mac', 'note', 'origin', 'uid', 'package', 'pkg']);
    var act = String((b && b.action) || 'add').toLowerCase();
    if (act === 'clear') {
      var rmAll = V6_LG_STATE.ignore_rules.length;
      V6_LG_STATE.ignore_rules = [];
      return { ok: true, action: 'clear', removed: rmAll, ignore_rules: [] };
    }
    var host = String((b && (b.dst_host || b.dst_ip)) || '').trim().toLowerCase();
    var lType = String((b && b.leak_type) || '').trim().toUpperCase();
    var mac = String((b && b.mac) || '').trim().toLowerCase();
    var scope = String((b && b.scope) || (mac && lType ? 'device_host_type' : (lType ? 'host_type' : 'host'))).toLowerCase();
    if (act === 'remove' || act === 'del' || act === 'delete') {
      var rid = String((b && b.id) || '').trim();
      var beforeLen = V6_LG_STATE.ignore_rules.length;
      V6_LG_STATE.ignore_rules = V6_LG_STATE.ignore_rules.filter(function (w) {
        if (!w) return false;
        if (rid && w.id === rid) return false;
        if (!rid && String(w.dst_host || '').toLowerCase() === host && String(w.scope || '') === scope && String(w.leak_type || '').toUpperCase() === lType && String(w.mac || '').toLowerCase() === mac) return false;
        return true;
      });
      return { ok: true, action: 'remove', removed: beforeLen - V6_LG_STATE.ignore_rules.length, ignore_rules: V6_LG_STATE.ignore_rules.slice() };
    }
    if (scope !== 'host_type' && scope !== 'host' && scope !== 'device_host_type' && scope !== 'app_host_type') {
      throw err('scope must be host_type|host|device_host_type|app_host_type', 400);
    }
    if (!host) throw err('missing dst_host', 400);
    if ((scope === 'host_type' || scope === 'device_host_type' || scope === 'app_host_type') && !lType) {
      throw err('valid leak_type is required for scope=' + scope, 400);
    }
    if (scope === 'device_host_type' && !mac) {
      throw err('valid device mac is required for scope=device_host_type', 400);
    }
    var item = {
      id: 'ig_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      scope: scope,
      dst_host: host,
      leak_type: (scope === 'host_type' || scope === 'device_host_type' || scope === 'app_host_type') ? lType : '',
      mac: scope === 'device_host_type' ? mac : '',
      uid: b && b.uid ? round(+b.uid) : 0,
      package: String((b && (b.package || b.pkg)) || ''),
      note: String((b && b.note) || ''),
      created_at: now()
    };
    V6_LG_STATE.ignore_rules = V6_LG_STATE.ignore_rules.filter(function (w) {
      return !(w.dst_host === item.dst_host && w.scope === item.scope && w.leak_type === item.leak_type && w.mac === item.mac && (w.uid || 0) === (item.uid || 0));
    });
    V6_LG_STATE.ignore_rules.push(item);
    return { ok: true, action: 'add', rule: item, ignore_rules: V6_LG_STATE.ignore_rules.slice() };
  };
  POST['/api/leakguard/block-domain'] = function (b) {
    v6AssertAllowedKeys(b, ['action', 'scope', 'target_scope', 'dst_host', 'mac', 'uid', 'pkg', 'app_name', 'force', 'also_ip']);
    var actRaw = String((b && b.action) || 'block').trim().toLowerCase();
    if (actRaw !== 'block' && actRaw !== 'unblock') throw err('bad params', 400, { detail: 'action must be block|unblock' });
    var unb = actRaw === 'unblock';
    var rawHost = String((b && b.dst_host) || '').trim();
    if (!rawHost) throw err('bad params', 400, { detail: 'invalid dst_host (domain or public IP required)' });
    var host = rawHost;
    if (host.charAt(0) === '[') {
      var rbIdx = host.indexOf(']');
      if (rbIdx > 1) host = host.slice(1, rbIdx);
    } else if (host.indexOf(':') > 0 && host.indexOf(':') === host.lastIndexOf(':')) {
      var spIdx = host.indexOf(':');
      if (/^\d{1,5}$/.test(host.slice(spIdx + 1))) host = host.slice(0, spIdx);
    }
    host = host.replace(/^\*\./, '').replace(/\.+$/, '').toLowerCase();
    if (!host) throw err('bad params', 400, { detail: 'invalid dst_host (domain or public IP required)' });
    var isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.indexOf(':') >= 0;
    if (isIp && (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|198\.1[89]\.|169\.254\.|0\.|255\.255\.255\.255$)/.test(host) || /^::1$|^fe80:|^fc|^fd/i.test(host))) {
      throw err('bad params', 400, { detail: 'private, loopback or Fake-IP cannot be blocked' });
    }
    var kind = isIp ? 'ip' : 'domain';
    var alsoIp = String((b && b.also_ip) || '').trim().toLowerCase();
    if (alsoIp === host) alsoIp = '';
    var rawMac = String((b && b.mac) || '').trim().toLowerCase();
    var targetMac = (rawMac === 'all' || rawMac === '*') ? '' : rawMac;
    var reqScope = String((b && b.scope) || '').trim().toLowerCase();
    var targetScope = String((b && b.target_scope) || 'hotspot').trim().toLowerCase();
    if (targetScope !== 'hotspot' && targetScope !== 'host' && targetScope !== 'both') {
      throw err('bad params', 400, { detail: 'target_scope must be hotspot|host|both' });
    }
    if (reqScope && reqScope !== 'device' && reqScope !== 'global') {
      throw err('bad params', 400, { detail: 'scope must be device|global' });
    }
    if (targetScope === 'hotspot' && reqScope !== 'global' && !targetMac) {
      throw err('bad params', 400, {
        reason_code: 'missing_mac',
        detail: '非全局封禁必须指定有效的目标设备 mac（如需全热点封禁请显式传 scope:"global"，或仅封本机传 target_scope:"host"）'
      });
    }
    var reqUid = (b && b.uid != null) ? round(+b.uid) : 0;
    var reqPkg = String((b && b.pkg) || '').trim();
    if (/^uid:/i.test(reqPkg)) {
      if (!reqUid) reqUid = round(+reqPkg.slice(4)) || 0;
      reqPkg = '';
    } else if (/^isolated:/i.test(reqPkg)) {
      reqPkg = '';
    }
    var reqAppName = String((b && b.app_name) || '').trim();

    var doHotspot = targetScope === 'hotspot' || targetScope === 'both';
    var doHost = targetScope === 'host' || targetScope === 'both';

    if (doHost && isIp) {
      if (targetScope === 'host' && !(reqUid > 0)) {
        throw err('bad params', 400, {
          reason_code: 'missing_uid',
          detail: '本机公网 IP 封禁必须指定有效的目标应用 uid'
        });
      }
      if (reqUid > 0) {
        var reqAppId = reqUid % 100000;
        if (reqUid < 10000 || reqAppId < 10000 || reqAppId >= 90000 || reqUid > 99999999) {
          throw err('protected_uid', 400, {
            reason_code: 'protected_uid',
            detail: '禁止对系统/隔离进程 UID=' + reqUid + ' 执行本机公网 IP 封禁'
          });
        }
        var uMeta = v6FindHostAppMeta(reqUid, reqPkg, reqAppName);
        var chkPkg = (reqPkg || (/^(uid:|isolated:)/i.test(uMeta.pkg) ? '' : String(uMeta.pkg || ''))).toLowerCase();
        if (chkPkg && V6_PROTECTED_PKGS.indexOf(chkPkg) >= 0) {
          throw err('protected_package', 400, {
            reason_code: 'protected_package',
            detail: '禁止封禁受保护的核心管理器/WebView/宿主应用 (' + chkPkg + ')'
          });
        }
      }
    }

    var evHit = V6_LG_STATE.events.filter(function (x) {
      return String(x.dst_host || '').toLowerCase() === host || String(x.dst_ip || '').toLowerCase() === host;
    })[0];
    var targetMacs = doHotspot ? (targetMac ? [targetMac] : visibleDevs().map(function (d) { return d.mac; })) : [];
    var skippedSharedIp = false;
    var skippedVendor = '';
    var blockedAlsoIp = '';
    var undoId = '';
    var hostUndoUid = 0;

    if (!unb) {
      var isPublicDnsIp = isIp && /^(8\.8\.(8\.8|4\.4)|1\.(1\.1\.1|0\.0\.1)|223\.(5\.5\.5|6\.6\.6)|119\.29\.29\.29|114\.114\.114\.114|9\.9\.9\.9|208\.67\.(222\.222|220\.220))$/.test(host);
      var ig = (evHit && evHit.infra_guard) || v6MockInfraGuard(host);
      if (isPublicDnsIp || (ig && ig.level === 'hard_block')) {
        var hbVendor = isPublicDnsIp ? 'Public DNS' : (ig.label || 'Core Infrastructure');
        var hbDetail = isPublicDnsIp
          ? ('禁止封禁公共 DNS 服务器 IP（' + hbVendor + '），否则将导致域名解析中断')
          : '该目标属于系统联网探测或核心公共服务，封禁会导致联网异常，建议改用「忽略误报」。';
        throw err('guard_hard_block', 409, {
          guard_level: 'hard_block',
          requires_confirm: false,
          target_scope: targetScope,
          vendor: hbVendor,
          provider: hbVendor,
          dst_host: host,
          detail: hbDetail,
          reason_zh: hbDetail
        });
      }
      var sharedIpVendor = isIp ? v6MockSharedCdnIpVendor(host, ig) : '';
      if (isIp && sharedIpVendor && (targetScope === 'host' || (targetScope === 'both' && reqUid > 0))) {
        V6_SELF_FW.guard_rejects += 1;
        var hbHostIpDetail = '禁止将 ' + sharedIpVendor + ' 公共 CDN/云共享 IP 写入本机应用防火墙 block_targets，避免误封同节点正常服务';
        throw err('guard_hard_block', 409, {
          guard_level: 'hard_block',
          requires_confirm: false,
          target_scope: targetScope,
          vendor: sharedIpVendor,
          provider: sharedIpVendor,
          category: 'shared_ip',
          dst_host: host,
          detail: hbHostIpDetail,
          reason_zh: hbHostIpDetail
        });
      }
      if (((ig && ig.level === 'warn_confirm') || sharedIpVendor) && !(b && b.force)) {
        var vLbl = (ig && ig.label) || sharedIpVendor || '公共云共享节点';
        var wcDetail = '该目标属于「' + vLbl + '」多应用共用节点，封禁后可能连带影响使用同一加速节点的其他正常应用。';
        throw err('guard_warn_confirm', 409, {
          guard_level: 'warn_confirm',
          requires_confirm: true,
          target_scope: targetScope,
          vendor: vLbl,
          provider: vLbl,
          dst_host: host,
          detail: wcDetail,
          reason_zh: wcDetail
        });
      }
      if (doHotspot && alsoIp && kind === 'domain') {
        skippedVendor = v6MockSharedCdnIpVendor(alsoIp, ig);
        if (skippedVendor) {
          skippedSharedIp = true;
        } else {
          blockedAlsoIp = alsoIp;
        }
      }
      if (doHotspot) {
        V6_LG_STATE.blocked_set[host] = 1;
        if (blockedAlsoIp) V6_LG_STATE.blocked_set[blockedAlsoIp] = 1;
        v6SyncDeviceBlocksForTarget(host, targetMac, true, 'LeakGuard 反制');
        if (blockedAlsoIp) v6SyncDeviceBlocksForTarget(blockedAlsoIp, targetMac, true, 'LeakGuard 关联 IP');
      }
      if (doHost) {
        if (!isIp) {
          V6_SELF_FW.blocked_domains[host] = 1;
          V6_SELF_FW.updated_at = now();
          V6_SELF_FW.apply_commits += 1;
        } else if (reqUid > 0) {
          var metaAdd = v6FindHostAppMeta(reqUid, reqPkg, reqAppName);
          var curRule = V6_SELF_FW.uid_rules[String(reqUid)];
          var curMode = (curRule && curRule.mode) ? curRule.mode : 'allow';
          var nextBt = (curRule && Array.isArray(curRule.block_targets)) ? curRule.block_targets.slice() : [];
          if (nextBt.indexOf(host) < 0) {
            nextBt.push(host);
            nextBt.sort();
          }
          var cleanResPkg = reqPkg || (curRule && curRule.pkg) || (/^(uid:|isolated:)/i.test(metaAdd.pkg) ? '' : String(metaAdd.pkg || ''));
          var cleanResName = reqAppName || (curRule && curRule.app_name) || metaAdd.app_name || cleanResPkg || ('UID ' + reqUid);
          var sbAdd = (reqUid % 100000 >= 10000 && reqUid % 100000 <= 19999) ? (reqUid + 10000) : 0;
          V6_SELF_FW.uid_rules[String(reqUid)] = {
            uid: reqUid,
            sdk_sandbox_uid: sbAdd,
            pkg: cleanResPkg,
            app_name: cleanResName,
            mode: curMode,
            block_targets: nextBt,
            updated_at: now()
          };
          hostUndoUid = reqUid;
          V6_SELF_FW.updated_at = now();
          V6_SELF_FW.apply_commits += 1;
        }
      }
      var effUndoScope = (targetScope === 'both' && kind !== 'domain' && hostUndoUid === 0) ? 'hotspot' : targetScope;
      undoId = 'ub_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
      V6_LG_STATE.undo_stack = V6_LG_STATE.undo_stack.filter(function (u) {
        var us = String(u.target_scope || u.origin || 'hotspot').toLowerCase();
        return !(String(u.dst_host || '').toLowerCase() === host && us === effUndoScope && (u.uid || 0) === hostUndoUid);
      });
      var undoEntry = {
        id: undoId,
        dst_host: host,
        kind: kind,
        target_scope: effUndoScope,
        origin: effUndoScope === 'host' ? 'host' : 'hotspot',
        also_ip: blockedAlsoIp || '',
        macs: doHotspot ? targetMacs.slice() : [],
        created_at: now()
      };
      if (hostUndoUid > 0) undoEntry.uid = hostUndoUid;
      V6_LG_STATE.undo_stack.push(undoEntry);
      while (V6_LG_STATE.undo_stack.length > 10) V6_LG_STATE.undo_stack.shift();
    } else {
      if (doHotspot) {
        delete V6_LG_STATE.blocked_set[host];
        if (alsoIp) delete V6_LG_STATE.blocked_set[alsoIp];
        v6SyncDeviceBlocksForTarget(host, targetMac, false);
        if (alsoIp) v6SyncDeviceBlocksForTarget(alsoIp, targetMac, false);
      }
      if (doHost) {
        if (!isIp) {
          delete V6_SELF_FW.blocked_domains[host];
          V6_SELF_FW.updated_at = now();
          V6_SELF_FW.apply_commits += 1;
        } else if (reqUid > 0 && V6_SELF_FW.uid_rules[String(reqUid)]) {
          var existingRule = V6_SELF_FW.uid_rules[String(reqUid)];
          var keptBt = (existingRule.block_targets || []).filter(function (t) { return String(t || '').toLowerCase() !== host; });
          if ((!existingRule.mode || existingRule.mode === 'allow') && keptBt.length === 0) {
            delete V6_SELF_FW.uid_rules[String(reqUid)];
          } else {
            existingRule.block_targets = keptBt;
            existingRule.updated_at = now();
          }
          V6_SELF_FW.updated_at = now();
          V6_SELF_FW.apply_commits += 1;
        }
      }
      var nextStack = [];
      V6_LG_STATE.undo_stack.forEach(function (u) {
        if (String(u.dst_host || '').toLowerCase() !== host) { nextStack.push(u); return; }
        var us = String(u.target_scope || u.origin || 'hotspot').toLowerCase();
        var hasHs = us === 'hotspot' || us === 'both';
        var hasHo = us === 'host' || us === 'both';
        if (doHost && hasHo) {
          if (u.kind !== 'ip' || reqUid <= 0 || !u.uid || u.uid === reqUid) {
            hasHo = false;
          }
        }
        if (doHotspot && hasHs) {
          hasHs = false;
        }
        if (hasHs && hasHo) {
          var copyBoth = clone(u);
          copyBoth.target_scope = 'both';
          nextStack.push(copyBoth);
        } else if (hasHs) {
          var copyHs = clone(u);
          copyHs.target_scope = 'hotspot';
          copyHs.origin = 'hotspot';
          delete copyHs.uid;
          nextStack.push(copyHs);
        } else if (hasHo) {
          var copyHo = clone(u);
          copyHo.target_scope = 'host';
          copyHo.origin = 'host';
          copyHo.macs = [];
          copyHo.also_ip = '';
          nextStack.push(copyHo);
        }
      });
      V6_LG_STATE.undo_stack = nextStack;
    }
    var selfBlockedNow = !isIp
      ? v6MockIsSelfDomainBlocked(host)
      : (reqUid > 0 ? (v6MockIsSelfIpBlocked(host, reqUid) || !!(V6_SELF_FW.uid_rules[String(reqUid)] && (V6_SELF_FW.uid_rules[String(reqUid)].mode === 'block_all' || V6_SELF_FW.uid_rules[String(reqUid)].mode === 'block_cleartext'))) : false);
    var resp = {
      ok: true,
      action: unb ? 'unblock' : 'block',
      target_scope: targetScope,
      kind: kind,
      origin: targetScope === 'host' ? 'host' : 'hotspot',
      dst_host: host,
      is_blocked: !unb,
      self_blocked: selfBlockedNow,
      macs: doHotspot ? targetMacs : [],
      applied_cnt: (doHotspot ? targetMacs.length : 0) + (doHost && (!isIp || reqUid > 0) ? 1 : 0),
      skipped_shared_ip: skippedSharedIp,
      undo_count: V6_LG_STATE.undo_stack.length
    };
    if (reqUid > 0) resp.uid = reqUid;
    if (undoId) resp.undo_id = undoId;
    if (skippedSharedIp) {
      resp.skipped_ip = alsoIp;
      resp.skipped_ip_vendor = skippedVendor;
    }
    if (blockedAlsoIp) resp.blocked_also_ip = blockedAlsoIp;
    return resp;
  };
  POST['/api/leakguard/undo-block'] = function (b) {
    v6AssertAllowedKeys(b, ['id', 'target_scope']);
    var reqTs = String((b && b.target_scope) || '').trim().toLowerCase();
    if (reqTs && reqTs !== 'hotspot' && reqTs !== 'host' && reqTs !== 'both') {
      throw err('bad params', 400, { detail: 'target_scope must be hotspot|host|both' });
    }
    if (!V6_LG_STATE.undo_stack.length) throw err('empty_undo_stack', 400, { detail: '当前没有可撤销的封禁记录' });
    var targetId = String((b && b.id) || '').trim();
    var idx = -1;
    for (var i = V6_LG_STATE.undo_stack.length - 1; i >= 0; i--) {
      var cur = V6_LG_STATE.undo_stack[i];
      if (targetId && cur.id !== targetId) continue;
      var es = String(cur.target_scope || cur.origin || 'hotspot').toLowerCase();
      var okScope = (!reqTs || reqTs === 'both') ||
        (reqTs === 'host' && (es === 'host' || es === 'both')) ||
        (reqTs === 'hotspot' && (es === 'hotspot' || es === 'both'));
      if (okScope) { idx = i; break; }
    }
    if (idx < 0) throw err('undo_not_found', 400, { detail: '指定的封禁撤销记录不存在' });

    var entry = clone(V6_LG_STATE.undo_stack[idx]);
    var entryUid = entry.uid ? round(+entry.uid) : 0;
    var origScope = String(entry.target_scope || entry.origin || 'hotspot').toLowerCase();
    var undoHotspot = origScope === 'hotspot' || origScope === 'both';
    var undoHost = origScope === 'host' || origScope === 'both';
    var executedScope = origScope;

    if (reqTs === 'host' && origScope === 'both') {
      undoHotspot = false;
      undoHost = true;
      executedScope = 'host';
      V6_LG_STATE.undo_stack[idx].target_scope = 'hotspot';
      V6_LG_STATE.undo_stack[idx].origin = 'hotspot';
      delete V6_LG_STATE.undo_stack[idx].uid;
    } else if (reqTs === 'hotspot' && origScope === 'both') {
      undoHotspot = true;
      undoHost = false;
      executedScope = 'hotspot';
      V6_LG_STATE.undo_stack[idx].target_scope = 'host';
      V6_LG_STATE.undo_stack[idx].origin = 'host';
      V6_LG_STATE.undo_stack[idx].macs = [];
      V6_LG_STATE.undo_stack[idx].also_ip = '';
    } else {
      V6_LG_STATE.undo_stack.splice(idx, 1);
    }

    var ph = String(entry.dst_host || '').toLowerCase();
    var pip = String(entry.also_ip || '').toLowerCase();
    var eKind = entry.kind || (/^\d+\.\d+\.\d+\.\d+$/.test(ph) || ph.indexOf(':') >= 0 ? 'ip' : 'domain');
    var macsToUnblock = (undoHotspot && Array.isArray(entry.macs)) ? entry.macs.slice() : [];
    var applied = 0;

    if (undoHotspot && ph) {
      delete V6_LG_STATE.blocked_set[ph];
      if (pip) delete V6_LG_STATE.blocked_set[pip];
      if (macsToUnblock.length) {
        macsToUnblock.forEach(function (m) {
          v6SyncDeviceBlocksForTarget(ph, m, false);
          if (pip) v6SyncDeviceBlocksForTarget(pip, m, false);
        });
        applied += macsToUnblock.length;
      } else {
        v6SyncDeviceBlocksForTarget(ph, '', false);
        if (pip) v6SyncDeviceBlocksForTarget(pip, '', false);
      }
    }
    if (undoHost && ph) {
      if (eKind === 'ip' && entryUid > 0) {
        var stillHasHostIp = V6_LG_STATE.undo_stack.some(function (u) {
          var us = String(u.target_scope || u.origin || 'hotspot').toLowerCase();
          return (u.kind || 'ip') === 'ip' && (u.uid || 0) === entryUid && String(u.dst_host || '').toLowerCase() === ph && (us === 'host' || us === 'both');
        });
        if (!stillHasHostIp && V6_SELF_FW.uid_rules[String(entryUid)]) {
          var uRule = V6_SELF_FW.uid_rules[String(entryUid)];
          var remBt = (uRule.block_targets || []).filter(function (t) { return String(t || '').toLowerCase() !== ph; });
          if ((!uRule.mode || uRule.mode === 'allow') && remBt.length === 0) {
            delete V6_SELF_FW.uid_rules[String(entryUid)];
          } else {
            uRule.block_targets = remBt;
            uRule.updated_at = now();
          }
          V6_SELF_FW.updated_at = now();
        }
        applied += 1;
      } else if (eKind !== 'ip') {
        var stillHasHostDom = V6_LG_STATE.undo_stack.some(function (u) {
          var us = String(u.target_scope || u.origin || 'hotspot').toLowerCase();
          return (u.kind || 'domain') === 'domain' && String(u.dst_host || '').toLowerCase() === ph && (us === 'host' || us === 'both');
        });
        if (!stillHasHostDom) {
          delete V6_SELF_FW.blocked_domains[ph];
          V6_SELF_FW.updated_at = now();
        }
        applied += 1;
      }
    }

    entry.target_scope = executedScope;
    if (entryUid > 0) entry.uid = entryUid;
    var selfBlkAfterUndo = eKind === 'ip'
      ? (entryUid > 0 ? (v6MockIsSelfIpBlocked(ph, entryUid) || !!(V6_SELF_FW.uid_rules[String(entryUid)] && (V6_SELF_FW.uid_rules[String(entryUid)].mode === 'block_all' || V6_SELF_FW.uid_rules[String(entryUid)].mode === 'block_cleartext'))) : false)
      : v6MockIsSelfDomainBlocked(ph);
    return {
      ok: true,
      undo_id: entry.id,
      target_scope: executedScope,
      self_blocked: selfBlkAfterUndo,
      undone: entry,
      dst_host: entry.dst_host || '',
      kind: eKind,
      uid: entryUid,
      also_ip: undoHotspot ? (entry.also_ip || '') : '',
      macs: macsToUnblock,
      applied_cnt: applied,
      remaining_undo: V6_LG_STATE.undo_stack.length
    };
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
      V6_SC_STATE.frozen_rules.push({ key: k4, proto: pNorm, src_ip: sip, dst_ip: dip, dport: dp, scope: (b && b.scope) || 'hotspot', uid: b && b.uid ? round(+b.uid) : 0, expires_at: now() + 900 });
    } else if (sp > 0) {
      V6_SC_STATE.killed_keys[pNorm + '|' + sip + ':' + sp + '|' + dip + ':' + dp] = 1;
    }
    var hsActCnt = V6_SC_STATE.frozen_rules.filter(function (r) { return r.scope !== 'host'; }).length;
    var hostActCnt = V6_SC_STATE.frozen_rules.filter(function (r) { return r.scope === 'host'; }).length;
    return { ok: true, mode: (b && b.mode) || 'cut_once', scope: (b && b.scope) || 'hotspot', cut_total: V6_SC_STATE.cut_total, active_rules: hsActCnt, host_active_rules: hostActCnt };
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
    if (b && b.schema_version && !/^(hnc\.backup\.v6(\.0|\.1)?|6\.0|6\.1)$/.test(String(b.schema_version).trim())) {
      throw err('unsupported backup schema_version', 400);
    }
    var files = (b && b.files && typeof b.files === 'object') ? b.files : null;
    if (files) {
      var sfRaw = files['self_firewall.json'] != null ? files['self_firewall.json'] : files['v6_self_firewall.json'];
      if (typeof sfRaw === 'string') {
        try { sfRaw = JSON.parse(sfRaw); } catch (_) { sfRaw = null; }
      }
      if (sfRaw && typeof sfRaw === 'object') {
        if (Array.isArray(sfRaw.uid_rules)) {
          var nextRules = {};
          sfRaw.uid_rules.forEach(function (r) {
            if (r && r.uid >= 10000 && r.mode && (r.mode !== 'allow' || (Array.isArray(r.block_targets) && r.block_targets.length > 0))) {
              var cpR = clone(r);
              cpR.block_targets = Array.isArray(cpR.block_targets) ? cpR.block_targets.slice() : [];
              nextRules[String(r.uid)] = cpR;
            }
          });
          V6_SELF_FW.uid_rules = nextRules;
        }
        if (Array.isArray(sfRaw.blocked_domains)) {
          var nextDoms = {};
          sfRaw.blocked_domains.forEach(function (d) {
            var dn = String(d || '').trim().toLowerCase();
            if (dn) nextDoms[dn] = 1;
          });
          V6_SELF_FW.blocked_domains = nextDoms;
        } else if (sfRaw.blocked_domains && typeof sfRaw.blocked_domains === 'object') {
          var nextDomsObj = {};
          Object.keys(sfRaw.blocked_domains).forEach(function (d) {
            if (sfRaw.blocked_domains[d]) nextDomsObj[String(d).trim().toLowerCase()] = 1;
          });
          V6_SELF_FW.blocked_domains = nextDomsObj;
        }
        V6_SELF_FW.updated_at = now();
      }
    }
    var cnt = files ? Object.keys(files).length : (round(+(b && b.file_count) || 17));
    return { ok: true, restored_count: Math.max(1, cnt), dataplane_reloaded: true, sha256: (b && b.sha256) || V6_VAULT_SHA };
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
