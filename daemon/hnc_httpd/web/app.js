// HNC 远程 dashboard · Patch 1 MVP
// 只读:拉 /api/devices 和 /api/stats,渲染设备卡片 + SVG 堆叠柱状图

(function() {
'use strict';

// HNC Patch 4.a · OUI DB for device class identification (641 entries, ~11KB)
// 算法: MAC 第 2 hex 字符 ∈ {2,6,a,e} → Privacy (locally-administered)
//       否则 OUI 前 6 字符 lookup 这个表
var OUI_DB = {"000393":"Apple","0003A0":"Apple","0003A1":"Apple","000A27":"Apple","000A95":"Apple","000D93":"Apple","000DCB":"Apple","000F23":"Apple","0010FA":"Apple","001124":"Apple","001451":"Apple","0014A8":"Apple","0016CB":"Apple","0017F2":"Apple","0019E3":"Apple","001B63":"Apple","001CB3":"Apple","001D4F":"Apple","001E52":"Apple","001EC2":"Apple","001F5B":"Apple","001FF3":"Apple","002241":"Apple","002312":"Apple","002332":"Apple","00236C":"Apple","002436":"Apple","0024A8":"Apple","002500":"Apple","00254B":"Apple","0025BC":"Apple","00264A":"Apple","0026B0":"Apple","0026BB":"Apple","003065":"Apple","0050E4":"Apple","0056CD":"Apple","006171":"Apple","006D52":"Apple","0084FF":"Apple","009027":"Apple","0099F3":"Apple","00A040":"Apple","00B362":"Apple","00C610":"Apple","00CDFE":"Apple","00DB70":"Apple","00F4B9":"Apple","00F76F":"Apple","04489A":"Apple","0469F8":"Apple","0489F0":"Apple","04A1B0":"Apple","04D3CF":"Apple","04DB56":"Apple","04E536":"Apple","04F13E":"Apple","04F7E4":"Apple","081196":"Apple","083E5D":"Apple","085BD6":"Apple","08664B":"Apple","0870BE":"Apple","0874A4":"Apple","0888A8":"Apple","089D84":"Apple","08A4D8":"Apple","0C1539":"Apple","0C30D5":"Apple","0C3E9F":"Apple","0C4DE9":"Apple","0C5101":"Apple","0C5106":"Apple","0C5113":"Apple","0C5115":"Apple","0C5135":"Apple","0C5142":"Apple","0C771A":"Apple","0CBC9F":"Apple","0CD746":"Apple","1040F3":"Apple","10417F":"Apple","105E29":"Apple","109ADD":"Apple","10DDB1":"Apple","14109F":"Apple","14205E":"Apple","142D27":"Apple","1499E2":"Apple","1840E5":"Apple","18AF61":"Apple","18AF8F":"Apple","18E7F4":"Apple","18EE69":"Apple","18F1D8":"Apple","18F643":"Apple","1C1AC0":"Apple","1C36BB":"Apple","1C5CF2":"Apple","1C9148":"Apple","1C9E46":"Apple","1CABA7":"Apple","1CE62B":"Apple","2002AF":"Apple","2078F0":"Apple","207D74":"Apple","20A2E4":"Apple","20AB37":"Apple","20C9D0":"Apple","24A074":"Apple","24A2E1":"Apple","24F094":"Apple","24F677":"Apple","2827BF":"Apple","283737":"Apple","285AEB":"Apple","286AB8":"Apple","286ABA":"Apple","28CFDA":"Apple","28CFE9":"Apple","28E02C":"Apple","28E14C":"Apple","28E7CF":"Apple","28ED6A":"Apple","28F076":"Apple","28FF3C":"Apple","2C1F23":"Apple","2C200B":"Apple","2C3361":"Apple","2C5491":"Apple","2CB43A":"Apple","2CBE08":"Apple","2CF0A2":"Apple","2CF0EE":"Apple","30636B":"Apple","3090AB":"Apple","30F7C5":"Apple","34159E":"Apple","3451C9":"Apple","342387":"Android","3463BE":"Apple","34A395":"Apple","34AB37":"Apple","34C059":"Apple","34E2FD":"Apple","3801D1":"Apple","380B40":"Apple","38484C":"Apple","386077":"Apple","38B54D":"Apple","38C986":"Apple","38CADA":"Apple","3C0754":"Apple","3C15C2":"Apple","3C2EFF":"Apple","3C2EF9":"Apple","3CAB8E":"Apple","3CD0F8":"Apple","3CE072":"Apple","40331A":"Apple","40A6D9":"Apple","40B395":"Apple","40CBC0":"Apple","40D32D":"Apple","4098AD":"Apple","4860BC":"Apple","48437C":"Apple","4894F1":"Apple","48A91C":"Apple","48BF6B":"Apple","48D705":"Apple","48E9F1":"Apple","4C3275":"Apple","4C57CA":"Apple","4C7C5F":"Apple","4C8D79":"Apple","4CB199":"Apple","50EAD6":"Apple","542696":"Windows","545C00":"Apple","54AE27":"Apple","54E43A":"Apple","58404E":"Apple","5855CA":"Apple","58B035":"Apple","5C5948":"Apple","5C8D4E":"Apple","5C8FE0":"Apple","5C95AE":"Apple","5C969D":"Apple","5C97F3":"Apple","5CADCF":"Apple","5CF5DA":"Apple","5CF7E6":"Apple","5CF938":"Apple","6030D4":"Apple","60334B":"Apple","606944":"Apple","60B3C3":"Apple","60C547":"Apple","60D9C7":"Apple","60FACD":"Apple","60FB42":"Apple","60FEC5":"Apple","64200C":"Apple","64A3CB":"Apple","64B0A6":"Apple","64B9E8":"Apple","68644B":"Apple","689C70":"Apple","68967B":"Apple","68A86D":"Apple","68AB1E":"Apple","68AE20":"Apple","68D93C":"Apple","68DBCA":"Apple","68FB7E":"Apple","6C19C0":"Apple","6C3E6D":"Apple","6C4008":"Apple","6C709F":"Apple","6C72E7":"Apple","6C8DC1":"Apple","6C94F8":"Apple","6CC26B":"Apple","6CE85C":"Apple","70112F":"Apple","7014A6":"Apple","705681":"Apple","70CD60":"Apple","70DEE2":"Apple","70ECE4":"Apple","70EF00":"Apple","74E1B6":"Apple","74E2F5":"Apple","786C1C":"Apple","787E61":"Android","7867D7":"Apple","788C77":"Apple","78A3E4":"Apple","78CA39":"Apple","78FD94":"Apple","7C0BC6":"Apple","7C11BE":"Apple","7C6D62":"Apple","7C6DF8":"Apple","7CC3A1":"Apple","7CC537":"Apple","7CD1C3":"Apple","7CF05F":"Apple","7CFADF":"Apple","80007A":"Apple","80006E":"Apple","80B03D":"Apple","8030DC":"Apple","80929F":"Apple","80BE05":"Apple","80E650":"Apple","80EA96":"Apple","84381F":"Apple","848505":"Apple","8489AD":"Apple","848E0C":"Apple","84A134":"Apple","84A87E":"Apple","84B153":"Apple","84FCFE":"Apple","885395":"Apple","886B6E":"Apple","88663A":"Apple","88E87F":"Apple","88E9FE":"Apple","8C006D":"Apple","8C2937":"Apple","8C5877":"Apple","8C7B9D":"Apple","8C7C92":"Apple","8C8590":"Apple","8C8EF2":"Apple","8CFABA":"Apple","9027E4":"Apple","904CE5":"Apple","9060F1":"Apple","907240":"Apple","908D6C":"Apple","90840D":"Apple","90B0ED":"Apple","90B21F":"Apple","90B931":"Apple","90C1C6":"Apple","90DD5D":"Apple","90FD61":"Apple","949426":"Apple","94E96A":"Apple","94F6D6":"Apple","9802D8":"Apple","9803D8":"Apple","9810E8":"Apple","98460A":"Apple","985AEB":"Apple","98B8E3":"Apple","98D6BB":"Apple","98E0D9":"Apple","98F0AB":"Apple","98FE94":"Apple","9C04EB":"Apple","9C20BD":"Apple","9C207B":"Apple","9C293F":"Apple","9C35EB":"Apple","9C4FDA":"Apple","9C84BF":"Apple","9C8BA0":"Apple","9CE33F":"Apple","9CE65E":"Apple","9CF387":"Apple","9CF48E":"Apple","9CFC01":"Apple","A01828":"Apple","A04EA7":"Apple","A0999B":"Apple","A0EDCD":"Apple","A4B197":"Apple","A4C361":"Apple","A4D18C":"Apple","A4D1D2":"Apple","A4F1E8":"Apple","A82066":"Apple","A8667F":"Apple","A86BAD":"Apple","A88E24":"Apple","A8968A":"Apple","A8BBCF":"Apple","A8FAD8":"Apple","AC1F74":"Apple","AC293A":"Apple","AC3C0B":"Apple","AC61EA":"Apple","AC7F3E":"Apple","AC87A3":"Apple","ACBC32":"Apple","ACCF5C":"Apple","ACFDEC":"Apple","B065BD":"Apple","B0481A":"Apple","B09FBA":"Apple","B418D1":"Apple","B44BD2":"Apple","B4F0AB":"Apple","B817C2":"Apple","B844D9":"Apple","B853AC":"Apple","B8782E":"Apple","B88D12":"Apple","B8C75D":"Apple","B8E856":"Apple","B8F6B1":"Apple","B8FF61":"Apple","BC3BAF":"Apple","BC4CC4":"Apple","BC52B7":"Apple","BC54FC":"Apple","BC926B":"Apple","BCA920":"Apple","BCEC5D":"Apple","BCFEC2":"Apple","C01ADA":"Apple","C06394":"Apple","C08359":"Apple","C0847A":"Apple","C0CECD":"Apple","C0F2FB":"Apple","C42AD0":"Apple","C4618B":"Apple","C46699":"Apple","C82A14":"Apple","C869CD":"Apple","C88550":"Apple","C8B5B7":"Apple","C8BCC8":"Apple","C8E0EB":"Apple","C8F650":"Apple","CC088D":"Apple","CC25EF":"Apple","CC29F5":"Apple","CC785F":"Apple","CCC760":"Apple","D02598":"Apple","D023DB":"Apple","D04F7E":"Apple","D0817A":"Apple","D0A637":"Apple","D0E140":"Apple","D49A20":"Apple","D4619D":"Apple","D4909C":"Apple","D4F46F":"Apple","D81D72":"Apple","D81C79":"Apple","D83062":"Apple","D88F76":"Apple","D89695":"Apple","D89E3F":"Apple","D8A25E":"Apple","D8BB2C":"Apple","D8CF9C":"Apple","D8D1CB":"Apple","DC2B2A":"Apple","DC2B61":"Apple","DC415F":"Apple","DC56E7":"Apple","DC86D8":"Apple","DC9B9C":"Apple","DCA4CA":"Apple","DCA904":"Apple","E0ACCB":"Apple","E0B52D":"Apple","E0B55F":"Apple","E0C767":"Apple","E0F5C6":"Apple","E0F847":"Apple","E425E7":"Apple","E48B7F":"Apple","E498D6":"Apple","E49A79":"Apple","E49ADC":"Apple","E4C63D":"Apple","E4CE8F":"Apple","E80688":"Apple","E8040B":"Apple","E8802E":"Apple","E88D28":"Apple","E8B2AC":"Apple","EC3586":"Apple","EC852F":"Apple","ECADB8":"Apple","F0B479":"Apple","F0C1F1":"Apple","F0CBA1":"Apple","F0DBE2":"Apple","F0DBF8":"Apple","F0DCE2":"Apple","F0F61C":"Apple","F40F24":"Apple","F41BA1":"Apple","F4F15A":"Apple","F4F951":"Apple","F81EDF":"Apple","F82793":"Apple","F86214":"Apple","F89976":"Apple","F8E94E":"Apple","F8FFC2":"Apple","FC253F":"Apple","FCE998":"Apple","FCFC48":"Apple","000DE5":"Android","000F73":"Android","001247":"Android","001632":"Android","00166B":"Android","00166C":"Android","0017C9":"Android","0017D5":"Android","001A8A":"Android","001AB1":"Android","001E7D":"Android","0021D1":"Android","00237A":"Android","0024E9":"Android","002566":"Android","00265D":"Android","0026E2":"Android","0411DC":"Android","1095C7":"Android","14F65A":"Android","185936":"Android","2082C0":"Android","286C07":"Android","38A4ED":"Android","3C45A8":"Android","4080E1":"Android","4CCC34":"Android","50A4D0":"Android","58D56E":"Android","640980":"Android","64B473":"Android","68DFDD":"Android","74EAC8":"Android","7451BA":"Android","7C1DD9":"Android","8417F0":"Android","98FAE3":"Android","A086C6":"Android","ACC1EE":"Android","ACF7F3":"Android","B0E235":"Android","B8275B":"Android","C46AB7":"Android","F0B429":"Android","00259E":"Android","002568":"Android","080038":"Android","0C37DC":"Android","0C7849":"Android","0C96BF":"Android","20F17C":"Android","283152":"Android","2C5BB8":"Android","3010E4":"Android","38BC01":"Android","4039A6":"Android","4CB16C":"Android","544A05":"Android","5C7D5E":"Android","6C92BF":"Android","7012F2":"Android","788DF7":"Android","803593":"Android","84A8E4":"Android","A0A33B":"Android","182012":"Android","1CCAE3":"Android","2CCC44":"Android","444795":"Android","60E394":"Android","70824B":"Android","A47B85":"Android","A89CED":"Android","B43A28":"Android","B4527E":"Android","B82368":"Android","DC0B34":"Android","F44E05":"Android","00B6E1":"Android","082E5F":"Android","30AE7B":"Android","404E36":"Android","500474":"Android","5814A4":"Android","58D9D5":"Android","B047BF":"Android","C09F05":"Android","3010B3":"Android","588694":"Android","6466B3":"Android","6C402C":"Android","9485C6":"Android","A4DA22":"Android","B05B99":"Android","B077AC":"Android","B85765":"Android","DA75CF":"Android","F4F5D8":"Android","F8F005":"Android","00125A":"Windows","0017FA":"Windows","001DD8":"Windows","00501A":"Windows","0050F2":"Windows","28E14F":"Windows","30B189":"Windows","347E5C":"Windows","4C0BBE":"Windows","58820A":"Windows","60450E":"Windows","6C0B84":"Windows","7048F7":"Windows","8C04BA":"Windows","984FEE":"Windows","A4AE12":"Windows","A85C2C":"Windows","DC32D1":"Windows","000423":"Windows","0011D8":"Windows","0013E8":"Windows","001500":"Windows","0016EA":"Windows","001A6B":"Windows","001CC0":"Windows","001E64":"Windows","001F3A":"Windows","002590":"Windows","0026C7":"Windows","00DBDF":"Windows","04D9F5":"Windows","085B0E":"Windows","0C8BFD":"Windows","0CD292":"Windows","1078D2":"Windows","1809F4":"Windows","1C1B0D":"Windows","2486F4":"Windows","24FD52":"Windows","3052CB":"Windows","3868DD":"Windows","3C2C30":"Windows","40A3CC":"Windows","50EB71":"Windows","60F262":"Windows","A0AFBD":"Windows","A0C589":"Windows","A0C9A0":"Windows","B025AA":"Windows","C0B6F9":"Windows","DCA632":"IoT","E8B1FC":"Windows","F0DEF1":"Windows","00E04C":"Windows","0024C5":"Windows","525400":"Linux","B827EB":"IoT","E45F01":"IoT","2CCF67":"IoT","4C3FD0":"IoT","44233F":"IoT","50EC50":"IoT","5CE5DD":"IoT","84F3EB":"IoT","A02088":"IoT","B8F009":"IoT","EC64C9":"IoT","000625":"Network","0019E0":"Network","14CC20":"Network","1C61B4":"Network","3C84A6":"Network","50FA84":"Network","68FF7B":"Network","70A741":"Network","98DAC4":"Network","B0487A":"Network","F4F26D":"Network","00226B":"Network","0030F1":"Network","0050BD":"Network","000FF8":"Network","00146C":"Network","0015F2":"Network","2C56DC":"Network","708BCD":"Network"};

var DEVICE_EMOJI = {
  Apple: '\u{1F34E}', Android: '\u{1F916}', Windows: '\u{1FA9F}',
  Linux: '\u{1F427}', IoT: '\u{1F4A1}', Network: '\u{1F4E1}',
  Privacy: '\u{1F3AD}', Other: '\u{2753}', Unknown: '\u{2753}'
};

function deviceClass(mac) {
  if (!mac || typeof mac !== 'string') return 'Unknown';
  var m = mac.toLowerCase();
  // bit 1 of first byte = locally-administered (Privacy MAC)
  // hex 第二位 2/6/a/e 的二进制 LSB+1 = 1 (二进制 0010/0110/1010/1110)
  var c2 = m.charAt(1);
  if (c2==='2'||c2==='6'||c2==='a'||c2==='e') return 'Privacy';
  // OUI lookup (前 6 字符无冒号大写)
  var oui = m.replace(/:/g,'').slice(0,6).toUpperCase();
  return OUI_DB[oui] || 'Other';
}

function deviceEmoji(mac) {
  return DEVICE_EMOJI[deviceClass(mac)] || '\u{2753}';
}


var statsRange = 'today';
var statsData = { buckets: [] };
var devicesData = [];
var deviceFilterMode = localStorage.getItem('hnc_remote_device_filter') || 'online_only';
var remoteRefreshMode = localStorage.getItem('hnc_remote_refresh_mode') || 'balanced';
var remoteSnapshotAgeMs = 0;
var remoteSnapshotStale = false;
var hotspotActive = false;
var remoteCapabilities = null;
var remoteUplinkSupported = null;
var remoteLiveApiUnavailable = false;
var remoteCapabilitiesApiUnavailable = false;

// UI sync/perf hotfix: avoid overlapping polls and stale slow responses.
// Mobile browsers may take >5s on bad links; without this, old /api/devices
// responses can overwrite newer state and repeated DOM rebuilds cause jank.
var devicesReqSeq = 0;
var devicesInFlight = false;
var devicesLastSig = '';
var devicesLastMacSig = '';
var statsReqSeq = 0;
var statsInFlight = false;

function $(id) { return document.getElementById(id); }

// 远程面板未配对 / 登录过期 → 跳配对页。
// 后端把 "/" 作为公共 SPA 入口放行,但数据接口需要 hnc_token cookie,缺失即 401;
// SPA 必须据此自动跳到 /pair(见 hnc_httpd middleware.go 注释)。之前只有写路径
// (/api/action) 这么做,读/轮询路径把 401 当普通错误显示,导致未配对用户卡在
// "加载失败: HTTP 401" 永远到不了配对页。守卫防止多个并发 401 重复跳转 / 循环。
var __pairRedirecting = false;
function redirectToPair() {
  if (__pairRedirecting) return;
  __pairRedirecting = true;
  try { setStatus(false, '未配对 · 正在跳转配对页…'); } catch (_) {}
  setTimeout(function(){ try { window.location.href = '/pair'; } catch (_) {} }, 600);
}

// hotfix4: bounded async transport. fetch() can stay pending for a long time
// on unstable mobile links, keeping in-flight flags true and making the UI look
// frozen. AbortController is available on modern Android WebView; fallback keeps
// compatibility on older engines.
function fetchWithTimeout(url, opts, timeoutMs) {
  opts = opts || {};
  timeoutMs = timeoutMs || 10000;
  // 任一 API 拿到 401 (未配对/过期) → 统一跳配对页. 在中心助手里做, 所有读写
  // 端点都覆盖, 调用方各自的 r.ok / status 处理不受影响.
  function checkAuth(r) { if (r && r.status === 401) redirectToPair(); return r; }
  if (typeof AbortController === 'undefined') {
    return fetch(url, opts).then(checkAuth);
  }
  var ctrl = new AbortController();
  var t = setTimeout(function(){ try { ctrl.abort(); } catch (_) {} }, timeoutMs);
  var nextOpts = {};
  Object.keys(opts).forEach(function(k){ nextOpts[k] = opts[k]; });
  nextOpts.signal = ctrl.signal;
  return fetch(url, nextOpts).then(function(r){
    clearTimeout(t);
    return checkAuth(r);
  }, function(e){
    clearTimeout(t);
    throw e;
  });
}

// ── tab 切换 ─────────────────────────────────────────────
window.switchTab = function(name) {
  document.querySelectorAll('.tab').forEach(function(t){
    t.classList.toggle('on', t.dataset.tab === name);
  });
  document.querySelectorAll('.tab-content').forEach(function(c){
    c.style.display = c.id === 'tab-'+name ? '' : 'none';
  });
  if (name === 'stats') loadStats();
  if (name === 'self') loadSelf();
  if (name === 'export') loadExports();
};

// ── 设备列表 ─────────────────────────────────────────────
function deviceListSignature(list) {
  try { return JSON.stringify(list || []); } catch (_) { return String(Date.now()); }
}
function deviceMacSignature(list) {
  return (list || []).map(function(d){ return d && d.mac || ''; }).sort().join('|');
}
function fetchLiveState() {
  if (remoteLiveApiUnavailable) return Promise.resolve(null);
  return fetchWithTimeout('/api/live', { cache: 'no-store', credentials: 'same-origin' }, 5000)
    .then(function(r){ if (!r.ok) { if (r.status === 404) remoteLiveApiUnavailable = true; throw new Error('HTTP '+r.status); } return r.json(); })
    .catch(function(){ return null; });
}

function applyRemoteCapabilities(cap) {
  if (!cap || typeof cap !== 'object') return;
  remoteCapabilities = cap;
  if (typeof cap.uplink_supported === 'boolean') remoteUplinkSupported = !!cap.uplink_supported;
}
function fetchRemoteCapabilities() {
  if (remoteCapabilitiesApiUnavailable) return Promise.resolve(null);
  return fetchWithTimeout('/api/capabilities', { cache: 'no-store', credentials: 'same-origin' }, 5000)
    .then(function(r){ if (!r.ok) { if (r.status === 404) remoteCapabilitiesApiUnavailable = true; throw new Error('HTTP '+r.status); } return r.json(); })
    .then(function(d){
      if (d && d.available === false) return null;
      var cap = d && (d.capabilities || d);
      applyRemoteCapabilities(cap);
      return cap;
    })
    .catch(function(){ return null; });
}
// rc31: 三态能力读取(true / false / null=未知)。本机 WebUI 用 capBool 门控每设备
// 低延迟,远端这里对齐:tc_htb=false 时禁用开关(后端也会拒,前端先拦避免无谓往返)。
function remoteCapBool(key) {
  var c = remoteCapabilities;
  if (!c || typeof c !== 'object') return null;
  var v = c[key];
  return (typeof v === 'boolean') ? v : null;
}

function fetchHotspotLiveState(data) {
  if (data && typeof data.hotspot_active === 'boolean') {
    return Promise.resolve({ active: !!data.hotspot_active, iface: data.hotspot_iface || '', ip: data.hotspot_ip || '' });
  }
  return fetchWithTimeout('/api/iface_info', { cache: 'no-store', credentials: 'same-origin' }, 4000)
    .then(function(r){ return r.ok ? r.json() : {}; })
    .then(function(info){ return { active: !!(info && info.ip && info.iface && info.iface !== 'wlan0'), iface: info && info.iface || '', ip: info && (info.gateway || info.ip) || '' }; })
    .catch(function(){ return { active: false, iface: '', ip: '' }; });
}

function loadDevices(opts) {
  opts = opts || {};
  if (devicesInFlight && !opts.force) return Promise.resolve(false);
  devicesInFlight = true;
  var seq = ++devicesReqSeq;
  return fetchWithTimeout('/api/devices', { cache: 'no-store', credentials: 'same-origin' }, 9000)
    .then(function(r){
      if (r.status === 503) {
        // httpd 启动了但 data 还没准备好(典型场景: devices.json 不存在)
        // 这种错误不同于 network 失败,要明确提示
        return r.json().then(function(j){
          throw new Error('HTTP 503 · ' + (j.error || 'data unavailable'));
        }).catch(function(){ throw new Error('HTTP 503 · server reported data unavailable'); });
      }
      if (!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(data){
      return fetchHotspotLiveState(data).then(function(hs){ return { data: data, hs: hs }; });
    })
    .then(function(pair){
      if (seq !== devicesReqSeq) return false; // stale slow response
      var data = pair.data || {};
      if (data.devices_sig) remoteLastDevicesSig = String(data.devices_sig);
      hotspotActive = !!(pair.hs && pair.hs.active);
      var next = (data && data.devices) || [];
      if (!hotspotActive) {
        next = next.map(function(d){ var x = Object.assign({}, d); x.online = false; x.rx_bps = 0; x.tx_bps = 0; return x; });
      }
      var sig = deviceListSignature(next) + '|hotspot=' + (hotspotActive ? 1 : 0);
      var macSig = deviceMacSignature(next);
      devicesData = next;
      if (opts.force || sig !== devicesLastSig) {
        renderDevices();
        devicesLastSig = sig;
      }
      setStatus(true);
      if (opts.force || macSig !== devicesLastMacSig) {
        populateDevSelect();
        devicesLastMacSig = macSig;
      }
      return true;
    })
    .catch(function(e){
      if (seq !== devicesReqSeq) return false;
      setStatus(false, e.message);
      var hint = '';
      if (/503/.test(e.message)) {
        hint = '<br><span style="color:var(--t2);font-size:11px">'+
               '提示: httpd 已连通但读不到 devices.json。'+
               '可能 HNC 还在启动,或 $HNC_DIR 路径配置错。'+
               '检查手机端 /data/local/hnc/logs/httpd.log</span>';
      }
      $('devices-list').innerHTML = '<div class="empty">加载失败: '+esc(e.message)+hint+'</div>';
      return false;
    })
    .then(function(v){
      if (seq === devicesReqSeq) devicesInFlight = false;
      return v;
    }, function(e){
      if (seq === devicesReqSeq) devicesInFlight = false;
      throw e;
    });
}

function setStatus(ok, msg) {
  var b = $('status-badge');
  if (!b) return;
  if (ok) { b.className = 'badge ok'; b.textContent = '已连接'; }
  else { b.className = 'badge err'; b.textContent = '连接失败 · '+(msg||''); }
}

function deviceHasRule(d) {
  if (!d) return false;
  return !!(d.limit_enabled || d.delay_enabled ||
    (Number(d.down_mbps) || 0) > 0 ||
    (Number(d.up_mbps) || 0) > 0 ||
    (Number(d.delay_ms) || 0) > 0 ||
    (Number(d.jitter_ms) || 0) > 0 ||
    (Number(d.loss_pct) || 0) > 0 ||
    d.status === 'blocked');
}

function devicePassFilter(d) {
  if (deviceFilterMode === 'all') return true;
  if (deviceFilterMode === 'offline_rules') return !d.online && deviceHasRule(d);
  return !!d.online;
}

function syncDeviceFilterUI() {
  var sel = $('device-filter-mode');
  if (sel) sel.value = deviceFilterMode;
  var note = $('device-filter-note');
  if (note) {
    var total = devicesData.length;
    var online = devicesData.filter(function(d){ return d.online; }).length;
    var rules = devicesData.filter(function(d){ return !d.online && deviceHasRule(d); }).length;
    if (deviceFilterMode === 'all') note.textContent = online + ' 在线 · 共 ' + total + ' 台';
    else if (deviceFilterMode === 'offline_rules') note.textContent = '离线规则 ' + rules + ' 条';
    else if (!hotspotActive) note.textContent = rules > 0 ? ('热点未开启 · ' + rules + ' 条离线规则') : '热点未开启';
    else note.textContent = rules > 0 ? ('已隐藏 ' + Math.max(0, total - online) + ' 台离线设备 · ' + rules + ' 条有规则') : '默认隐藏离线历史设备';
  }
}

function renderDevices() {
  var list = $('devices-list');
  var meta = $('devices-meta');
  syncDeviceFilterUI();
  if (devicesData.length === 0) {
    list.innerHTML = '<div class="empty">当前没有连接的设备</div>';
    meta.textContent = '';
    return;
  }
  var online = 0;
  var shown = 0;
  var html = '';
  devicesData.forEach(function(d){
    if (d.online) online++;
    if (!devicePassFilter(d)) return;
    shown++;
    html += renderCard(d);
  });
  if (!shown) {
    html = !hotspotActive
      ? '<div class="empty">热点未开启<br><span style="font-size:12px;color:var(--text-3)">在线设备已归零,可切换为“显示全部”查看离线历史规则</span></div>'
      : '<div class="empty">当前过滤条件下没有设备<br><span style="font-size:12px;color:var(--text-3)">可切换为“显示全部”查看离线历史规则</span></div>';
  }
  list.innerHTML = html;
  meta.textContent = online+' 在线 · 共 '+devicesData.length+' 台';
}

function applyModeText(kind, mode) {
  if (kind === 'delay') {
    if (mode === 'full') return '已生效';
    if (mode === 'egress_only') return '仅下行';
    if (mode === 'failed') return '失败';
    if (mode === 'pending') return '待应用';
  }
  if (kind === 'limit') {
    if (mode === 'full') return '';
    if (mode === 'down_only') return '上行不支持';
    if (mode === 'failed') return '失败';
    if (mode === 'pending') return '待应用';
  }
  return '';
}
function renderCard(d) {
  var name = d.hostname || (d.mac ? d.mac.replace(/:/g,'').slice(-8).toUpperCase() : '?');
  // Patch 4.a: 设备类型 emoji 前缀
  var emoji = d.mac ? deviceEmoji(d.mac) : '\u2753';
  var displayName = emoji + ' ' + name;
  var blk = d.status === 'blocked';
  var limited = d.limit_enabled && (d.down_mbps > 0 || d.up_mbps > 0);
  var sqmOn = (d.sqm_enabled === true || d.sqm_enabled === 'true');
  var badges = '';
  if (blk) badges += '<span class="b red">封锁</span>';
  else if (d.online) badges += '<span class="b green">在线</span>';
  else badges += '<span class="b gray">离线</span>';
  if (limited) {
    var lm = applyModeText('limit', d.limit_apply_mode || '');
    var lc = d.limit_apply_mode === 'down_only' ? 'orange' : (d.limit_apply_mode === 'failed' ? 'red' : 'blue');
    badges += '<span class="b '+lc+'">↓'+fmtMBps(d.down_mbps)+' ↑'+fmtMBps(d.up_mbps)+' MB/s'+(lm ? ' · '+lm : '')+'</span>';
  }
  if (d.delay_enabled && (d.delay_ms > 0 || d.jitter_ms > 0 || d.loss_pct > 0)) {
    var p = [];
    if (d.delay_ms > 0) p.push(d.delay_ms+'ms');
    if (d.jitter_ms > 0) p.push('±'+d.jitter_ms);
    if (d.loss_pct > 0) p.push(d.loss_pct+'%');
    var dm = applyModeText('delay', d.delay_apply_mode || '');
    if (dm) p.push(dm);
    var dc = d.delay_apply_mode === 'failed' ? 'red' : 'orange';
    badges += '<span class="b '+dc+'">'+p.join(' ')+'</span>';
  }
  if (sqmOn) badges += '<span class="b blue">低延迟</span>';

  // v4.0 Patch 3.b: 远端写操作按钮栏
  // 用 data-* 属性存 mac/name, 全局 click 监听分发(loadDevices 初始化时绑).
  // 之前的 onclick="showLimitModal('"+mac+"')" 嵌入 esc'd name 时,
  // 含单引号的 name(如 "Alice's iPhone")会被 HTML 属性解析还原成 '
  // 破 onclick 里的 JS 字符串, 导致点击无响应. data-* 靠 getAttribute
  // 读原始字符串,不受 HTML 解析还原影响.
  var actions = '';
  if (d.mac) {
    var a = ' data-mac="'+esc(d.mac)+'" data-name="'+esc(name)+'"';
    var delayOn = d.delay_enabled && (d.delay_ms > 0 || d.jitter_ms > 0 || d.loss_pct > 0);
    actions = '<div class="card-actions">';
    actions += '<button class="act-btn small" data-act="limit"'+a+'>🚦 限速</button>';
    if (limited) {
      actions += '<button class="act-btn small ghost" data-act="clear"'+a+'>解除限速</button>';
    }
    // rc3.1.10: 延迟注入 UI (后端 delay_set/delay_clear 一直就在, 只是远端 UI 缺)
    actions += '<button class="act-btn small warn" data-act="delay"'+a+'>⏱️ 延迟</button>';
    if (delayOn) {
      actions += '<button class="act-btn small ghost" data-act="delay-clear"'+a+'>清延迟</button>';
    }
    // rc31: 每设备低延迟(智能队列)。与延迟注入互斥(本机 UI 同);tc_htb=false 时禁用。
    var htbNo = remoteCapBool('tc_htb') === false;
    if (sqmOn) {
      actions += '<button class="act-btn small ghost" data-act="sqm-off"'+a+'>低延迟·关</button>';
    } else {
      var sqmDis = htbNo || delayOn;
      var sqmTip = htbNo ? '内核不支持 HTB,低延迟不可用' : (delayOn ? '已注入延迟时不能同时开低延迟(两者互斥)' : '给该设备智能队列(CAKE/fq_codel/sfq),跑满时更跟手·配合限速最佳');
      actions += '<button class="act-btn small"'+a+' data-act="sqm"'+(sqmDis?' disabled':'')+' title="'+esc(sqmTip)+'">🚀 低延迟</button>';
    }
    if (blk) {
      actions += '<button class="act-btn small success" data-act="unblock"'+a+'>✅ 移黑</button>';
    } else {
      actions += '<button class="act-btn small danger" data-act="block"'+a+'>⛔ 加黑</button>';
    }
    actions += '</div>';
  }

  // rc31: 设备在用 app(dpid 经 /api/devices 的 dpi_apps 上报)。与本机 WebUI 折叠卡一致,
  // 直接展示在卡片上,不藏二级页。confidence=low 标 "?",hover 看分类/命中次数。
  var dpiApps = Array.isArray(d.dpi_apps) ? d.dpi_apps : [];
  var dpiLine = '';
  if (dpiApps.length) {
    dpiLine = '<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px;align-items:center">'+
      '<span style="font-size:11px;color:var(--text-3);opacity:.85">在用</span>'+
      dpiApps.slice(0, 4).map(function(ap){
        var q = (ap.confidence === 'low') ? '?' : '';
        var t = esc((ap.category ? ap.category + ' · ' : '') + '命中 ' + (ap.count || 0) + ' 次');
        return '<span title="'+t+'" style="font-size:11px;background:rgba(0,122,255,.10);color:var(--sys-blue,#0a84ff);border-radius:5px;padding:1px 7px">'+esc(ap.name)+q+'</span>';
      }).join('')+'</div>';
  }

  return '<div class="card'+(blk?' blocked':'')+'">'+
    '<div class="card-head">'+
      '<div class="dev-name">'+esc(displayName)+'</div>'+
      '<div class="dev-badges">'+badges+'</div>'+
    '</div>'+
    '<div class="card-body">'+
      '<div class="field"><span class="k">IP</span><span class="v">'+esc(d.ip || '-')+'</span></div>'+
      '<div class="field"><span class="k">MAC</span><span class="v">'+esc(d.mac || '-')+'</span></div>'+
      '<div class="field"><span class="k">下行累计</span><span class="v">'+fmtB(d.rx_bytes)+'</span></div>'+
      '<div class="field"><span class="k">上行累计</span><span class="v">'+fmtB(d.tx_bytes)+'</span></div>'+
      dpiLine +
    '</div>'+
    actions +
  '</div>';
}

// ── 流量统计 ─────────────────────────────────────────────
function loadStats(opts) {
  opts = opts || {};
  if (statsInFlight && !opts.force) return Promise.resolve(false);
  statsInFlight = true;
  var seq = ++statsReqSeq;
  var mac = ($('stats-dev')||{}).value || '';
  var url = '/api/stats?range=' + statsRange + (mac ? '&mac='+encodeURIComponent(mac) : '');
  return fetchWithTimeout(url, { cache: 'no-store', credentials: 'same-origin' }, 9000)
    .then(function(r){ if (!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
    .then(function(data){
      if (seq !== statsReqSeq) return false;
      statsData = data || { buckets: [] };
      renderStatsChart();
      return true;
    })
    .catch(function(e){
      if (seq !== statsReqSeq) return false;
      statsData = { buckets: [] };
      renderStatsChart();
      return false;
    })
    .then(function(v){
      if (seq === statsReqSeq) statsInFlight = false;
      return v;
    }, function(e){
      if (seq === statsReqSeq) statsInFlight = false;
      throw e;
    });
}

function populateDevSelect() {
  var sel = $('stats-dev');
  if (!sel) return;
  var prev = sel.value;
  var html = '<option value="">全部设备</option>';
  devicesData.forEach(function(d){
    var nm = d.hostname || d.mac;
    var lbl = nm === d.mac ? d.mac.slice(-8).toUpperCase() : nm + ' · ' + (d.mac||'').slice(-5);
    html += '<option value="'+esc(d.mac)+'">'+esc(lbl)+'</option>';
  });
  sel.innerHTML = html;
  if (prev) sel.value = prev;
}

window.setRange = function(r) {
  statsRange = r;
  document.querySelectorAll('#stats-range button').forEach(function(b){
    b.classList.toggle('on', b.dataset.range === r);
  });
  loadStats();
};

window.renderStatsChart = function() {
  var svg = $('chart-svg');
  var buckets = (statsData && statsData.buckets) || [];
  var totalRx = 0, totalTx = 0;
  buckets.forEach(function(b){ totalRx += b.rx||0; totalTx += b.tx||0; });
  $('total-rx').textContent = fmtB(totalRx);
  $('total-tx').textContent = fmtB(totalTx);

  var hasData = buckets.some(function(b){return (b.rx||0)>0 || (b.tx||0)>0;});
  if (!hasData) {
    svg.innerHTML = '<text class="no-data" x="200" y="90">暂无数据</text>' +
      '<text class="no-data" x="200" y="108" style="font-size:9px">需等待 5 分钟采样 / 数据已轮转</text>';
    return;
  }

  var W = 400, H = 180, pad = {l:32, r:8, t:8, b:18};
  var cw = W - pad.l - pad.r;
  var ch = H - pad.t - pad.b;

  var maxV = 0;
  buckets.forEach(function(b){
    var s = (b.rx||0) + (b.tx||0);
    if (s > maxV) maxV = s;
  });
  if (maxV === 0) maxV = 1;
  maxV = niceMax(maxV);

  var n = buckets.length;
  var gap = Math.max(1, Math.floor(cw / n * 0.2));
  var bw = Math.max(1, (cw / n) - gap);

  var parts = [];
  var yTicks = 4;
  parts.push('<g class="grid">');
  for (var i = 0; i <= yTicks; i++) {
    var y = pad.t + ch - (ch * i / yTicks);
    parts.push('<line x1="'+pad.l+'" y1="'+y.toFixed(1)+'" x2="'+(W-pad.r)+'" y2="'+y.toFixed(1)+'"/>');
  }
  parts.push('</g>');

  parts.push('<g class="axis">');
  for (var j = 0; j <= yTicks; j++) {
    var yy = pad.t + ch - (ch * j / yTicks);
    var v = maxV * j / yTicks;
    parts.push('<text x="'+(pad.l-3)+'" y="'+(yy+3).toFixed(1)+'" text-anchor="end">'+fmtBShort(v)+'</text>');
  }
  parts.push('</g>');

  parts.push('<g class="axis">');
  for (var k = 0; k < n; k++) {
    var b = buckets[k];
    var x = pad.l + k * (bw + gap) + gap/2;
    var rxH = ((b.rx||0) / maxV) * ch;
    var txH = ((b.tx||0) / maxV) * ch;
    var yRx = pad.t + ch - rxH;
    var yTx = yRx - txH;
    var tip = esc(b.label + '\\n下行 ' + fmtB(b.rx||0) + '\\n上行 ' + fmtB(b.tx||0));
    parts.push('<g class="bar-group" onmousemove="showTip(event,\''+tip+'\')" onmouseleave="hideTip()" ontouchstart="showTip(event,\''+tip+'\')">');
    if ((b.rx||0) > 0) parts.push('<rect class="bar-rx" x="'+x.toFixed(1)+'" y="'+yRx.toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+rxH.toFixed(1)+'" rx="1"/>');
    if ((b.tx||0) > 0) parts.push('<rect class="bar-tx" x="'+x.toFixed(1)+'" y="'+yTx.toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+txH.toFixed(1)+'" rx="1"/>');
    parts.push('</g>');

    var every = Math.max(1, Math.ceil(n / 8));
    if (k % every === 0 || k === n-1) {
      var xc = x + bw/2;
      parts.push('<text x="'+xc.toFixed(1)+'" y="'+(H-6)+'" text-anchor="middle">'+esc(b.label)+'</text>');
    }
  }
  parts.push('</g>');
  svg.innerHTML = parts.join('');
};

function niceMax(v) {
  if (v <= 0) return 1;
  var exp = Math.floor(Math.log10(v));
  var base = Math.pow(10, exp);
  var d = v / base;
  var nice;
  if (d <= 1) nice = 1;
  else if (d <= 2) nice = 2;
  else if (d <= 2.5) nice = 2.5;
  else if (d <= 5) nice = 5;
  else nice = 10;
  return nice * base;
}

function fmtBShort(b) {
  b = Number(b) || 0;
  if (b < 1024) return Math.round(b)+'B';
  if (b < 1048576) return Math.round(b/1024)+'K';
  if (b < 1073741824) return Math.round(b/1048576)+'M';
  return (b/1073741824).toFixed(1)+'G';
}

function fmtB(b) {
  b = Number(b) || 0;
  if (b < 1024) return b+' B';
  if (b < 1048576) return (b/1024).toFixed(1)+' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}

function fmtMBps(mbps) {
  var v = (Number(mbps) || 0) / 8;
  if (v === 0) return '0';
  if (v < 1) return v.toFixed(2).replace(/\.?0+$/,'');
  return v.toFixed(1).replace(/\.?0+$/,'');
}

function esc(s) {
  return String(s || '').replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

window.showTip = function(ev, text) {
  var tip = $('tip');
  if (!tip) return;
  tip.innerHTML = String(text).replace(/\\n/g, '<br>');
  tip.classList.add('show');
  var x = ev.clientX || (ev.touches && ev.touches[0] && ev.touches[0].clientX) || 0;
  var y = ev.clientY || (ev.touches && ev.touches[0] && ev.touches[0].clientY) || 0;
  var w = tip.offsetWidth || 100;
  var vw = window.innerWidth || 400;
  if (x + w + 10 > vw) x = vw - w - 10;
  tip.style.left = (x+10)+'px';
  tip.style.top = (y-40)+'px';
};
window.hideTip = function() {
  var tip = $('tip');
  if (tip) tip.classList.remove('show');
};

// ── v4.0 Patch 3.b: 远端写操作 ────────────────────────────
// 所有写操作走 POST /api/action, 带 X-HNC-CSRF: 1 header
var actionInFlight = {};
function actionKey(action, params) {
  params = params || {};
  return params.mac ? ('dev:' + String(params.mac)) : ('global:' + String(action || ''));
}
async function callAction(action, params) {
  params = params || {};
  var key = actionKey(action, params);
  if (actionInFlight[key]) {
    return {status: 409, ok: false, error: 'busy', detail: 'same action is already running'};
  }
  actionInFlight[key] = true;
  try {
    var resp = await fetchWithTimeout('/api/action', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-HNC-CSRF': '1'
      },
      body: JSON.stringify({action: action, params: params})
    }, 15000);
    var data = {};
    try { data = await resp.json(); } catch(_) {}
    return {status: resp.status, ok: data.ok === true, error: data.error || '', detail: data.detail || ''};
  } catch (e) {
    var msg = String(e && e.message || e);
    if (e && e.name === 'AbortError') msg = 'request timeout';
    // The server-side shell action may still finish after a client timeout. Refresh
    // shortly so the UI converges instead of staying stale.
    setTimeout(function(){ loadDevices({force:true}); }, 1200);
    return {status: 0, ok: false, error: 'network', detail: msg};
  } finally {
    delete actionInFlight[key];
  }
}

// toast 显示短反馈
// kind: 'ok' (绿) / 'err' (红) / 'info' (蓝)
function showToast(text, kind) {
  var el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.className = 'toast show ' + (kind || 'info');
  el.textContent = text;
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(function(){
    el.classList.remove('show');
  }, 2800);
}

// 统一处理 action 返回,给用户 toast 反馈
function handleActionResult(r, successMsg) {
  if (r.ok) {
    showToast('✓ ' + (successMsg || r.detail || '已生效'), 'ok');
    // 触发一次强制刷新,同时丢弃任何旧的轮询响应,避免旧数据覆盖刚写入的状态。
    if (typeof requestRemoteForceRefresh === 'function') requestRemoteForceRefresh();
    else setTimeout(function(){ loadDevices({force:true}); }, 500);
    return true;
  }
  var msg = r.error || '操作失败';
  if (r.detail) msg += ': ' + r.detail;
  if (r.status === 429) {
    msg = '⛔ 操作过于频繁,请稍后再试';
  } else if (r.status === 401) {
    msg = '登录已过期,请重新配对';
    redirectToPair();
  } else if (r.error === 'protected mac') {
    msg = '⚠️ 无法对该设备操作: ' + (r.detail || 'protected');
  }
  showToast(msg, 'err');
  return false;
}

// 限速 modal
window.showLimitModal = function(mac, name) {
  var modal = document.getElementById('limit-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'limit-modal';
    modal.className = 'act-modal';
    modal.innerHTML =
      '<div class="act-modal-bg" onclick="closeLimitModal()"></div>' +
      '<div class="act-modal-card">' +
        '<div class="act-modal-title">🚦 设置限速</div>' +
        '<div class="act-modal-sub" id="lm-target">—</div>' +
        '<label class="act-label">下行 (下载) 速率</label>' +
        '<div class="act-rate-row">' +
          '<input id="lm-down" type="number" inputmode="decimal" step="0.1" placeholder="不限速留空" min="0.008">' +
          '<select id="lm-down-unit">' +
            '<option value="KBps">KB/s</option>' +
            '<option value="MBps" selected>MB/s</option>' +
          '</select>' +
        '</div>' +
        '<label class="act-label">上行 (上传) 速率</label>' +
        '<div class="act-rate-row">' +
          '<input id="lm-up" type="number" inputmode="decimal" step="0.1" placeholder="不限速留空" min="0.008">' +
          '<select id="lm-up-unit">' +
            '<option value="KBps">KB/s</option>' +
            '<option value="MBps" selected>MB/s</option>' +
          '</select>' +
        '</div>' +
        '<div class="act-hint" id="lm-hint">单位与本机 WebUI 一致(1 MB/s = 8 Mbit/s),范围 8 KB/s ~ 1280 MB/s。留空表示该方向不限速,至少填一项。</div>' +
        '<div class="act-modal-actions">' +
          '<button class="act-btn ghost" onclick="closeLimitModal()">取消</button>' +
          '<button class="act-btn primary" id="lm-apply">应用</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(modal);
  }
  document.getElementById('lm-target').textContent = name + ' · ' + mac;
  document.getElementById('lm-down').value = '';
  document.getElementById('lm-up').value = '';
  var upDisabled = remoteUplinkSupported === false;
  var upInput = document.getElementById('lm-up');
  var upUnit = document.getElementById('lm-up-unit');
  if (upInput) { upInput.disabled = upDisabled; upInput.placeholder = upDisabled ? '不支持' : ''; }
  if (upUnit) upUnit.disabled = upDisabled;
  var hint = document.getElementById('lm-hint');
  if (hint) {
    hint.innerHTML = upDisabled
      ? '当前设备内核不支持 IFB/mirred，上行限速已禁用；下行限速仍可用。'
      : '单位与本机 WebUI 一致(1 MB/s = 8 Mbit/s),范围 8 KB/s ~ 1280 MB/s。留空表示该方向不限速,至少填一项。<br><span style="color:var(--orange,#fa8c16)">⚠️ 上行限速可能受内核/硬件卸载影响。</span>';
  }
  modal.style.display = 'flex';

  // v4.0 Patch 3.b.2: UI 用户输入 MB/s 或 KB/s, 后端 API 仍只认 mbit/kbit
  // 这里前端做换算: 1 MB/s = 8 mbit/s = 8000 kbit/s, 1 KB/s = 8 kbit/s
  // 转后向上取整保留整数 kbit (后端 minRate 64 kbit, 8 KB/s 正好 64 kbit)
  function uiToApiRate(val, unit) {
    var v = parseFloat(val);
    if (!v || v <= 0) return '';
    var kbit;
    if (unit === 'MBps') kbit = Math.ceil(v * 8000);
    else if (unit === 'KBps') kbit = Math.ceil(v * 8);
    else return '';
    if (kbit < 64) kbit = 64;  // 后端最小 64kbit
    // hotfix5: tc / Go 后端按十进制 1000 kbit = 1 mbit。
    // 旧代码用 1024 并 Math.round, 会把 0.2 MB/s(1600kbit) 误发成 2mbit。
    // 只有整 1000kbit 时才压缩成 mbit, 其他保持 kbit 精度。
    if (kbit % 1000 === 0) return (kbit / 1000) + 'mbit';
    return kbit + 'kbit';
  }

  document.getElementById('lm-apply').onclick = async function() {
    var dn = document.getElementById('lm-down').value.trim();
    var up = remoteUplinkSupported === false ? '' : document.getElementById('lm-up').value.trim();
    var dnu = document.getElementById('lm-down-unit').value;
    var upu = document.getElementById('lm-up-unit').value;
    if (!dn && !up) {
      showToast('请至少填一项速率', 'err');
      return;
    }
    var params = {mac: mac};
    if (dn) params.rate_down = uiToApiRate(dn, dnu);
    if (up) params.rate_up = uiToApiRate(up, upu);
    var btn = document.getElementById('lm-apply');
    btn.disabled = true; btn.textContent = '应用中...';
    var r = await callAction('rule_set', params);
    btn.disabled = false; btn.textContent = '应用';
    // 成功提示: 上行限速时单独提醒可能不生效
    var msg = '限速已设置';
    if (r.ok && remoteUplinkSupported === false) msg = '已设置 (仅下行，上行不支持)';
    else if (r.ok && up) msg = '已设置 (上行可能受硬件卸载影响)';
    if (handleActionResult(r, msg)) closeLimitModal();
  };
};

window.closeLimitModal = function() {
  var m = document.getElementById('limit-modal');
  if (m) m.style.display = 'none';
};

// 解除限速 (confirm → API)
window.actionClearRate = async function(mac, name) {
  if (!confirm('解除 "' + name + '" 的限速?')) return;
  var r = await callAction('rule_clear', {mac: mac});
  handleActionResult(r, '限速已解除');
};

// 加黑
window.actionBlockDevice = async function(mac, name) {
  if (!confirm('加入黑名单 "' + name + '" ? 该设备将被断网。')) return;
  var r = await callAction('bl_add', {mac: mac});
  handleActionResult(r, '已加入黑名单');
};

// 移黑
window.actionUnblockDevice = async function(mac, name) {
  if (!confirm('将 "' + name + '" 移出黑名单?')) return;
  var r = await callAction('bl_del', {mac: mac});
  handleActionResult(r, '已移出黑名单');
};

// ── rc3.1.10: 延迟注入 modal (netem · delay/jitter/loss) ──────
// 后端 action_v5.go:actionDelaySet
//   params: mac, delay_ms (0-5000), jitter_ms (0-5000), loss_pct (0-100, 支持小数)
// 未分配 mark_id 时后端会自动先跑 limit 0 0 分配, 用户无需预先设限速.
window.showDelayModal = function(mac, name) {
  var modal = document.getElementById('delay-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'delay-modal';
    modal.className = 'act-modal';
    modal.innerHTML =
      '<div class="act-modal-bg" onclick="closeDelayModal()"></div>' +
      '<div class="act-modal-card">' +
        '<div class="act-modal-title">⏱️ 注入网络延迟</div>' +
        '<div class="act-modal-sub" id="dm-target">—</div>' +
        '<div class="act-delay-grid">' +
          '<div>' +
            '<label>延迟 (ms)</label>' +
            '<input id="dm-delay" type="number" inputmode="numeric" min="0" max="5000" step="10" placeholder="0">' +
          '</div>' +
          '<div>' +
            '<label>抖动 (ms)</label>' +
            '<input id="dm-jitter" type="number" inputmode="numeric" min="0" max="5000" step="5" placeholder="0">' +
          '</div>' +
          '<div>' +
            '<label>丢包 (%)</label>' +
            '<input id="dm-loss" type="number" inputmode="decimal" min="0" max="100" step="0.5" placeholder="0">' +
          '</div>' +
        '</div>' +
        '<div class="act-hint">延迟/抖动范围 0~5000 ms, 丢包 0~100%。三项至少填一项非 0 才生效;全 0 等同于清除注入。<br><span class="warn-hint">⚠️ 使用 tc netem 模拟网络劣化, 下行方向有效。</span></div>' +
        '<div class="act-modal-actions">' +
          '<button class="act-btn ghost" onclick="closeDelayModal()">取消</button>' +
          '<button class="act-btn primary" id="dm-apply">应用</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(modal);
  }
  document.getElementById('dm-target').textContent = name + ' · ' + mac;
  // 预填当前规则值 (让用户看到目前状态, 直接修改)
  var cur = devicesData.find(function(x){ return x.mac === mac; }) || {};
  document.getElementById('dm-delay').value  = cur.delay_ms  > 0 ? cur.delay_ms  : '';
  document.getElementById('dm-jitter').value = cur.jitter_ms > 0 ? cur.jitter_ms : '';
  document.getElementById('dm-loss').value   = cur.loss_pct  > 0 ? cur.loss_pct  : '';
  modal.style.display = 'flex';

  document.getElementById('dm-apply').onclick = async function() {
    var dv = parseInt(document.getElementById('dm-delay').value  || '0', 10);
    var jv = parseInt(document.getElementById('dm-jitter').value || '0', 10);
    var lv = parseFloat(document.getElementById('dm-loss').value || '0');
    if (isNaN(dv) || dv < 0 || dv > 5000) { showToast('延迟需 0-5000 ms', 'err'); return; }
    if (isNaN(jv) || jv < 0 || jv > 5000) { showToast('抖动需 0-5000 ms', 'err'); return; }
    if (isNaN(lv) || lv < 0 || lv > 100)  { showToast('丢包需 0-100 %', 'err'); return; }
    if (dv === 0 && jv === 0 && lv === 0) {
      showToast('请至少填一项非 0, 或用"清延迟"按钮', 'err');
      return;
    }
    if (jv > dv && dv > 0) {
      if (!confirm('抖动(' + jv + ')大于基础延迟(' + dv + ')可能导致乱序, 继续?')) return;
    }
    var params = {mac: mac, delay_ms: String(dv), jitter_ms: String(jv), loss_pct: String(lv)};
    var btn = document.getElementById('dm-apply');
    btn.disabled = true; btn.textContent = '应用中...';
    var r = await callAction('delay_set', params);
    btn.disabled = false; btn.textContent = '应用';
    if (handleActionResult(r, '延迟已注入')) closeDelayModal();
  };
};

window.closeDelayModal = function() {
  var m = document.getElementById('delay-modal');
  if (m) m.style.display = 'none';
};

// 清除延迟 (confirm → API)
window.actionClearDelay = async function(mac, name) {
  if (!confirm('清除 "' + name + '" 的延迟注入?')) return;
  var r = await callAction('delay_clear', {mac: mac});
  handleActionResult(r, '延迟已清除');
};

// rc31: 每设备低延迟开关 (后端 rule_sqm → actionDeviceSQMSet)。
// enabled=true 把该设备 class 叶子换成 CAKE/fq_codel/sfq (AQM, 压队列延迟);
// false 换回 netem 占位。与本机 WebUI 的 toggle-sqm 等价, 状态由 sqm_enabled 持久化。
window.actionToggleSqm = async function(mac, name, enable) {
  var r = await callAction('rule_sqm', {mac: mac, enabled: enable ? 'true' : 'false'});
  handleActionResult(r, enable ? '已开启低延迟(智能队列)' : '已关闭低延迟');
};


// ── 启动 ─────────────────────────────────────────────────
var filterSel = $('device-filter-mode');
if (filterSel) {
  filterSel.value = deviceFilterMode;
  filterSel.addEventListener('change', function(){
    deviceFilterMode = filterSel.value || 'online_only';
    localStorage.setItem('hnc_remote_device_filter', deviceFilterMode);
    renderDevices();
  });
}
var refreshSel = $('remote-refresh-mode');
if (refreshSel) {
  refreshSel.value = getRemoteRefreshMode();
  refreshSel.addEventListener('change', function(){
    remoteRefreshMode = refreshSel.value || 'balanced';
    localStorage.setItem('hnc_remote_refresh_mode', remoteRefreshMode);
    updateRemoteFreshness(null);
    requestRemoteForceRefresh();
  });
}
var remotePollTimer = null;
var remotePollBusy = false;
var remotePollVisible = !document.hidden;
var remoteLastDevicesSig = '';
var remotePendingForce = false;

function getRemoteRefreshMode() {
  return (remoteRefreshMode === 'realtime' || remoteRefreshMode === 'powersave') ? remoteRefreshMode : 'balanced';
}
function remotePollDelay(live) {
  var mode = getRemoteRefreshMode();
  var online = live && typeof live.online === 'number' ? live.online : 0;
  if (mode === 'realtime') {
    if (!live || live.hotspot_active === false) return 3000;
    if (online <= 0) return 3000;
    return 1500;
  }
  if (mode === 'powersave') {
    if (!live || live.hotspot_active === false) return 15000;
    if (online <= 0) return 8000;
    return 5000;
  }
  if (!live || live.hotspot_active === false) return 9000;
  if (online <= 0) return 5000;
  return 2000;
}
function updateRemoteFreshness(live) {
  if (live && typeof live.snapshot_age_ms === 'number') remoteSnapshotAgeMs = live.snapshot_age_ms;
  if (live) remoteSnapshotStale = !!(live.snapshot_stale || live.refresh_requested);
  var age = Math.max(0, Number(remoteSnapshotAgeMs || 0));
  var sec = age >= 1000 ? (age / 1000).toFixed(age < 10000 ? 1 : 0) + ' 秒前' : '刚刚';
  var modeLabel = ({realtime:'实时', balanced:'均衡', powersave:'省电'})[getRemoteRefreshMode()] || '均衡';
  var stale = remoteSnapshotStale || age > 5000;
  var el = $('remote-freshness-line');
  if (el) {
    el.textContent = stale ? ('数据可能已过期 · ' + sec + ' · 正在刷新') : ('已更新 · ' + sec + ' · ' + modeLabel + '模式');
    el.classList.toggle('stale', stale);
  }
}
function clearRemotePollTimer() {
  if (remotePollTimer) { clearTimeout(remotePollTimer); remotePollTimer = null; }
}
function scheduleRemotePoll(delay) {
  clearRemotePollTimer();
  if (!remotePollVisible || document.hidden) return;
  remotePollTimer = setTimeout(function(){ remotePollOnce('timer'); }, delay || 5000);
}
function applyRemoteLive(live) {
  if (!live || typeof live !== 'object') return;
  updateRemoteFreshness(live);
  if (typeof live.hotspot_active === 'boolean') hotspotActive = !!live.hotspot_active;
  if (hotspotActive === false) {
    devicesData = devicesData.map(function(d){ var x = Object.assign({}, d); x.online = false; x.rx_bps = 0; x.tx_bps = 0; return x; });
    renderDevices();
  }
}
function remotePollOnce(reason) {
  reason = reason || 'timer';
  if (remotePollBusy) {
    if (reason === 'force') remotePendingForce = true;
    return Promise.resolve(false);
  }
  if (!remotePollVisible || document.hidden) {
    if (reason === 'force') remotePendingForce = true;
    return Promise.resolve(false);
  }
  remotePollBusy = true;
  return fetchLiveState().then(function(live){
    applyRemoteLive(live);
    var sig = live && live.devices_sig ? String(live.devices_sig) : '';
    var needFull = reason === 'force' || !remoteLastDevicesSig || (sig && sig !== remoteLastDevicesSig);
    var p = needFull ? loadDevices({force:true}).then(function(){ remoteLastDevicesSig = sig || remoteLastDevicesSig; }) : Promise.resolve(false);
    var statsTab = document.getElementById('tab-stats');
    if (statsTab && statsTab.style.display !== 'none') loadStats();
    return p.then(function(){ return live; });
  }).catch(function(){
    return null;
  }).then(function(live){
    remotePollBusy = false;
    if (remotePendingForce && remotePollVisible && !document.hidden) {
      remotePendingForce = false;
      clearRemotePollTimer();
      setTimeout(function(){ remotePollOnce('force'); }, 0);
    } else {
      scheduleRemotePoll(remotePollDelay(live));
    }
  });
}
function requestRemoteForceRefresh() {
  remoteLastDevicesSig = '';
  remotePendingForce = true;
  if (!remotePollBusy) return remotePollOnce('force');
  return Promise.resolve(false);
}
window.requestRemoteForceRefresh = requestRemoteForceRefresh;
function startRemotePolling() {
  remotePollVisible = !document.hidden;
  if (!remotePollVisible) return;
  clearRemotePollTimer();
  remotePollOnce('force');
}
function stopRemotePolling() { clearRemotePollTimer(); }

document.addEventListener('visibilitychange', function(){
  remotePollVisible = !document.hidden;
  if (remotePollVisible) startRemotePolling(); else stopRemotePolling();
});
window.addEventListener('focus', function(){ remotePollVisible = true; startRemotePolling(); });
window.addEventListener('pageshow', function(){ remotePollVisible = true; startRemotePolling(); });
window.addEventListener('blur', function(){ remotePollVisible = !document.hidden; if (!remotePollVisible) stopRemotePolling(); });
window.addEventListener('pagehide', function(){ remotePollVisible = false; stopRemotePolling(); });
fetchRemoteCapabilities().finally(function(){ startRemotePolling(); });

// v4.0 Patch 3.b: 卡片 action 按钮走 event delegation
// 所有写操作按钮用 data-act/data-mac/data-name 属性, 这里统一 dispatch
document.addEventListener('click', function(ev) {
  var btn = ev.target;
  if (!btn || !btn.getAttribute) return;
  var act = btn.getAttribute('data-act');
  if (!act) return;
  var mac = btn.getAttribute('data-mac');
  var name = btn.getAttribute('data-name');
  if (!mac) return;
  switch (act) {
    case 'limit':       window.showLimitModal(mac, name); break;
    case 'clear':       window.actionClearRate(mac, name); break;
    case 'delay':       window.showDelayModal(mac, name); break;
    case 'delay-clear': window.actionClearDelay(mac, name); break;
    case 'sqm':         window.actionToggleSqm(mac, name, true); break;
    case 'sqm-off':     window.actionToggleSqm(mac, name, false); break;
    case 'block':       window.actionBlockDevice(mac, name); break;
    case 'unblock':     window.actionUnblockDevice(mac, name); break;
  }
});

// 拉 version 和 watchdog 健康状态
fetch('/api/health').then(function(r){return r.json();}).then(function(d){
  if (d && d.version) $('version-info').textContent = 'hnc_httpd ' + d.version;
  // v4.0.0-patch1.3: watchdog passive mode 警告
  if (d && d.watchdog_passive) {
    var banner = document.createElement('div');
    banner.style.cssText = 'background:rgba(250,140,22,.15);color:var(--orange);padding:10px 16px;font-size:12px;border-bottom:1px solid rgba(250,140,22,.3);line-height:1.5';
    banner.innerHTML = '⚠️ <b>守护进程已挂起</b>:watchdog 检测到 iptables/tc 规则异常反复失败,已进入 passive 模式,<b>限速规则可能失效</b>。请检查手机端 <code>/data/local/hnc/logs/watchdog.log</code>。';
    document.body.insertBefore(banner, document.body.firstChild);
  }
}).catch(function(){});

// ── v4.0 Patch 2.d: 当前身份 + logout ─────────────────────
// /api/health 返回的身份信息(仅已鉴权请求返回)
//
// rc30.12.30 (P0.4): session_label 字段已从 apiHealth 移除 (是死代码,
// /api/health 在 isPublicPath, middleware 不 inject token, label 永远是空).
// 函数保留, badge 在 session_label 缺失时不显示 (graceful degradation).
// 如果未来恢复, 应走独立 /api/whoami 端点.
function loadSessionInfo() {
  fetch('/api/health', { credentials: 'same-origin' })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d && d.session_label) {
        var b = $('session-badge');
        if (b) {
          b.textContent = d.session_label;
          b.style.display = '';
        }
        var btn = $('logout-btn');
        if (btn) btn.style.display = '';
        var am = $('auth-mode');
        if (am) am.textContent = '已鉴权';
      }
    }).catch(function(){});
}
loadSessionInfo();

window.doLogout = function() {
  if (!confirm('登出并撤销本设备授权?\n\n下次访问需要重新配对。')) return;
  fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
    .then(function(){ window.location.href = '/pair'; })
    .catch(function(e){ alert('登出失败: ' + (e.message || e)); });
};

// ── v5.5: 我的应用 + 导出 ──────────────────────────────
function loadSelf() {
  fetchWithTimeout('/api/dpi_state', { cache: 'no-store', credentials: 'same-origin' }, 8000)
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (!d || !d.available || !d.state) {
        $('self-apps-list').innerHTML = '<div class="loading">dpi_state 暂未就绪</div>';
        return;
      }
      var self = d.state.self;
      var toggle = document.getElementById('self-toggle-input');
      if (self) {
        if (toggle) toggle.checked = !!self.enabled;
        $('self-meta').textContent = self.enabled
          ? '运行中 · 采样 ' + (self.last_attrib_tick ? new Date(self.last_attrib_tick*1000).toLocaleTimeString() : '未开始')
          : '已关闭';
      } else {
        if (toggle) toggle.checked = false;
        $('self-meta').textContent = '已关闭(dpid 未上报 self 块)';
      }
      // Iface preview
      fetchWithTimeout('/api/self/ifaces', { cache: 'no-store', credentials: 'same-origin' }, 6000)
        .then(function(r){ return r.json(); })
        .then(function(ifd){
          var html = [];
          if (ifd.ap_iface) html.push('热点接口: <code>' + esc(ifd.ap_iface) + '</code>');
          html.push('候选自身接口: ');
          (ifd.ifaces || []).slice(0, 10).forEach(function(it){
            var cls = it.eligible ? 'iface-eligible' : 'iface-skip';
            var title = it.reason || (it.eligible ? 'eligible' : '');
            html.push('<span class="' + cls + '" title="' + esc(title) + '">' + esc(it.name) + '</span>');
          });
          $('self-ifaces-row').innerHTML = html.join(' ');
        }).catch(function(){});
      // Apps list
      var apps = (self && self.apps_by_uid) || {};
      var rows = Object.keys(apps).map(function(uid){
        var a = apps[uid];
        return { uid: parseInt(uid, 10), app: a };
      }).sort(function(a, b){
        return (b.app.last_seen || 0) - (a.app.last_seen || 0);
      });
      if (rows.length === 0) {
        $('self-apps-list').innerHTML = '<div class="loading">' +
          ((self && self.enabled) ? '已开启,正在等待第一次采样...' : '关闭中(打开后约 5 秒出现数据)') +
          '</div>';
        return;
      }
      $('self-apps-list').innerHTML = rows.map(function(r){
        var a = r.app;
        var snis = (a.top_snis || []).slice(0, 5);
        var rules = (a.top_rules || []).slice(0, 4);
        return '<div class="self-app-card">' +
          '<div class="self-app-head">' +
            '<b>' + esc(a.pkg || '(uid ' + a.uid + ', pm 未解析)') + '</b>' +
            '<span class="meta">uid ' + a.uid + ' · 活跃连接 ' + (a.active_conns || 0) + ' · 累计 ' + (a.total_conns || 0) + '</span>' +
          '</div>' +
          (snis.length > 0 ? '<div class="self-app-snis">SNI: ' + snis.map(esc).join(', ') + '</div>' : '') +
          (rules.length > 0 ? '<div class="self-app-rules">规则: ' + rules.map(esc).join(', ') + '</div>' : '') +
          '<div class="self-app-time meta">最后见: ' + (a.last_seen ? new Date(a.last_seen*1000).toLocaleTimeString() : '--') + '</div>' +
        '</div>';
      }).join('');
    })
    .catch(function(e){
      $('self-apps-list').innerHTML = '<div class="loading">加载失败: ' + esc(e.message || e) + '</div>';
    });
}

window.toggleSelf = function(enabled) {
  fetchWithTimeout('/api/self/toggle', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: enabled })
  }, 12000).then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.error) {
        showToast('切换失败: ' + d.error, 'err');
        document.getElementById('self-toggle-input').checked = !enabled;
      } else {
        showToast(enabled ? '已开启 · 等待 5 秒后出现数据' : '已关闭', 'ok');
        setTimeout(loadSelf, 6000);
      }
    })
    .catch(function(e){
      showToast('网络错误: ' + (e.message || e), 'err');
      document.getElementById('self-toggle-input').checked = !enabled;
    });
};

function loadExports() {
  fetchWithTimeout('/api/exports', { cache: 'no-store', credentials: 'same-origin' }, 8000)
    .then(function(r){ return r.json(); })
    .then(function(d){
      var list = (d && d.exports) || [];
      if (list.length === 0) {
        $('exports-list').innerHTML = '<div class="loading">(还没打包过 export)</div>';
        return;
      }
      $('exports-list').innerHTML = list.map(function(x){
        return '<div class="export-row">' +
          '<code>' + esc(x.name) + '</code> · ' + fmtB(x.size) + ' · ' + esc(x.modified) + ' ' +
          '<a href="' + esc(x.download_url) + '" download>下载</a>' +
        '</div>';
      }).join('');
    })
    .catch(function(e){
      $('exports-list').innerHTML = '<div class="loading">加载失败: ' + esc(e.message || e) + '</div>';
    });
}

window.setExportRange = function(mins) {
  var now = Math.floor(Date.now() / 1000);
  function fmt(unix) {
    var d = new Date(unix*1000);
    var pad = function(n){ return String(n).padStart(2, '0'); };
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
           'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  $('export-from').value = fmt(now - mins*60);
  $('export-to').value = fmt(now);
};

window.buildExport = function() {
  var fromUnix = 0, toUnix = 0;
  var fv = $('export-from').value, tv = $('export-to').value;
  if (fv) fromUnix = Math.floor(new Date(fv).getTime() / 1000);
  if (tv) toUnix = Math.floor(new Date(tv).getTime() / 1000);
  var notes = ($('export-notes').value || '').trim();
  var resBox = $('export-result');
  resBox.innerHTML = '<div class="loading">打包中...</div>';
  fetchWithTimeout('/api/export', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: fromUnix || undefined,
      to: toUnix || undefined,
      notes: notes ? [notes] : undefined
    })
  }, 30000).then(function(r){ return r.json(); })
    .then(function(d){
      if (!d || d.status !== 'ok') {
        resBox.innerHTML = '<div class="err-banner">打包失败: ' + esc(JSON.stringify(d)) + '</div>';
        return;
      }
      var tr = (d.manifest && d.manifest.tracks) || {};
      var trkLines = [];
      Object.keys(tr).forEach(function(k){
        var v = tr[k];
        if (v && v.included) {
          trkLines.push(k + ': ' + (v.file_count || 1) + ' 个文件 / ' + fmtB(v.bytes_total || 0));
        }
      });
      resBox.innerHTML =
        '<div class="export-result-ok">' +
          '<b>已打包</b> · <code>' + esc(d.name) + '</code> · ' + fmtB(d.size_bytes || 0) +
          '<div class="meta">' + trkLines.map(esc).join('<br>') + '</div>' +
          '<a class="download-btn" href="' + esc(d.download_url) + '" download>下载 zip</a>' +
        '</div>';
      loadExports();
    })
    .catch(function(e){
      resBox.innerHTML = '<div class="err-banner">网络错误: ' + esc(e.message || e) + '</div>';
    });
};

})();
