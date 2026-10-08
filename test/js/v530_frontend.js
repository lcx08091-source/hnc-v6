// test/js/v530_frontend.js — v5.30 前端逻辑用例(由 test/unit/test_v530_frontend.sh 逐个调用)。
// 用法: node v530_frontend.js <仓库根> <用例名>; 通过 exit 0, 失败打印原因 exit 1。
'use strict';
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { load } = require('./extract_fns.js');

const root = process.argv[2];
const which = process.argv[3];
const core = path.join(root, 'webroot/js/core.js');
const fxjs = path.join(root, 'webroot/js/fx.js');
const mainjs = path.join(root, 'webroot/js/main.js');
const liquidcss = path.join(root, 'webroot/css/liquid.css');
// fx.js 顶层的 var GX_T(档位名表) —— 取仓库里的真值, 不在测试里另写一份
function gxTable() { const m = /^var GX_T = (.*);$/m.exec(fs.readFileSync(fxjs, 'utf8')); if (!m) { console.log('fx.js 里没有 GX_T'); process.exit(1); } return vm.runInNewContext(m[1]); }
function fakeRoot(props) { return { style: { setProperty: (k, v) => { props[k] = v; }, removeProperty: (k) => { delete props[k]; } } }; }

function eq(a, b, msg) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    console.log(msg + ': got ' + JSON.stringify(a) + ', want ' + JSON.stringify(b));
    process.exit(1);
  }
}

const cases = {
  // T1a: < 60 分钟显示分钟, ≥ 60 显示 N.N 小时, 0 不显示
  online_text() {
    const c = load(core, ['num', 'trim0', 'onlineText']);
    eq(c.onlineText(0), '', '0 分钟');
    eq(c.onlineText(5), ' · 今日在线 5 分钟', '5 分钟');
    eq(c.onlineText(59), ' · 今日在线 59 分钟', '59 分钟');
    eq(c.onlineText(60), ' · 今日在线 1 小时', '60 分钟');
    eq(c.onlineText(95), ' · 今日在线 1.6 小时', '95 分钟');
    eq(c.onlineText(1440), ' · 今日在线 24 小时', '1440 分钟');
  },
  // T1a: 新后端 online_min 优先; 旧后端只有 hours → ×60
  online_min_map() {
    const c = load(core, ['num', 'onlineMinMap']);
    eq(c.onlineMinMap({ hours: { m: { '20261007': 1 } }, online_min: { m: { '20261007': 5 } } }), { m: { '20261007': 5 } }, 'online_min 优先');
    eq(c.onlineMinMap({ hours: { m: { '20261007': 2 } } }), { m: { '20261007': 120 } }, '旧后端 hours×60');
    eq(c.onlineMinMap(null), null, 'null');
  },
  // T1a: 接线 —— paintOnlineHours 用 onlineMinOf + onlineText 写到设备卡片
  online_paint() {
    const els = {};
    const g = {
      S: { devices: [{ mac: 'aa:bb:cc:dd:ee:01' }, { mac: 'aa:bb:cc:dd:ee:02' }], onlineMin: { 'aa:bb:cc:dd:ee:01': { '20261007': 5 }, 'aa:bb:cc:dd:ee:02': { '20261007': 75 } } },
      document: { getElementById: (id) => (els[id] = els[id] || { textContent: 'x' }) },
      today: () => '2026-10-07',
      paintUsage: () => {},
    };
    const c = load(core, ['num', 'trim0', 'onlineText', 'onlineMinOf', 'paintOnlineHours'], g);
    c.paintOnlineHours();
    eq(els['oh-aabbccddee01'].textContent, ' · 今日在线 5 分钟', '5 分钟设备');
    eq(els['oh-aabbccddee02'].textContent, ' · 今日在线 1.3 小时', '75 分钟设备');
  },
  // T1b: 垃圾名表(与 C / Go 同一组用例)
  junk_name() {
    const c = load(core, ['isJunkName']);
    for (const s of ['null', 'NULL', ' Null ', '(null)', 'nil', 'none', '(none)', 'undefined', 'unknown', 'UNKNOWN',
      'localhost', 'localhost.localdomain', '*', '-', '', '   ', '\t', '0', '12345', null, undefined]) {
      eq(c.isJunkName(s), true, 'junk ' + JSON.stringify(s));
    }
    for (const s of ['Mi-10', 'nullify', 'iPhone', 'localhost2', '123abc', 'a', 'Johns-MacBook', '客厅电视', '-x', 'none-pc']) {
      eq(c.isJunkName(s), false, 'good ' + JSON.stringify(s));
    }
  },
  // T1b: 接线 —— mapDevice 用的 devName 跳过垃圾名, 手动命名不动
  dev_name() {
    const c = load(core, ['isJunkName', 'devName']);
    const mac = 'aa:bb:cc:dd:ee:01';
    eq(c.devName({ hostname: 'null', hostname_src: 'dhcp', vendor: 'Xiaomi' }, mac), 'Xiaomi', 'null → 厂商');
    eq(c.devName({ hostname: 'null' }, mac), mac, 'null 无厂商 → MAC');
    eq(c.devName({ hostname: 'undefined', name: 'Pad' }, mac), 'Pad', '垃圾名 → name');
    eq(c.devName({ hostname: 'null', hostname_src: 'manual' }, mac), 'null', '手动命名不过滤');
    eq(c.devName({ hostname: 'Mi-10', vendor: 'Xiaomi' }, mac), 'Mi-10', '真名照用');
  },
  // T1c: 组详情里的「公共服务」块
  disc_shared() {
    const st = path.join(root, 'webroot/js/stats.js');
    const c = load(st, ['kv', 'discSharedHtml'], { esc: (x) => String(x) });
    eq(c.discSharedHtml({}), '', '没有 shared 不显示');
    const h = c.discSharedHtml({ shared: [{ suffix: 'qtlcdn.com', reason: 'list', label: '公共服务' }, { suffix: 'bridge-cdn.com', reason: 'freq', label: '公共服务' }] });
    for (const want of ['qtlcdn.com', 'bridge-cdn.com', '公共服务', '多台设备、多个应用都在用', '不作为起名依据']) {
      if (h.indexOf(want) < 0) { console.log('缺少 ' + want + ': ' + h); process.exit(1); }
    }
  },
  // T4: app_qos 回读(布尔 / 字符串; 旧后端没有 → 关)
  app_qos_of() {
    const c = load(core, ['appQosOf']);
    eq([c.appQosOf({ app_qos: true }), c.appQosOf({ app_qos: 'true' }), c.appQosOf({}), c.appQosOf({ app_qos: false })], [true, true, false, false], 'appQosOf');
  },
  // UI: 玻璃浓度 0–100 → --gx-up / --gx-dn(50 = 标准 = 两个都 0)
  glass_tint_vars() {
    const k = load(core, ['num', 'clamp']);
    const c = load(fxjs, ['glassTintVars'], { num: k.num, clamp: k.clamp });
    eq(c.glassTintVars(50), { up: 0, dn: 0 }, '标准');
    eq(c.glassTintVars(100), { up: 1, dn: 0 }, '着色');
    eq(c.glassTintVars(0), { up: 0, dn: 1 }, '清透');
    eq(c.glassTintVars(75), { up: 0.5, dn: 0 }, '75');
    eq(c.glassTintVars(-20), { up: 0, dn: 1 }, '下限');
    eq(c.glassTintVars(300), { up: 1, dn: 0 }, '上限');
    eq(c.glassTintVars('x'), { up: 0, dn: 0 }, '坏值 → 标准');
  },
  // UI: applyGlassTint 写 / 删 <html> 上的两个变量(标准档全删 = 旧版数值)
  glass_tint_apply() {
    const k = load(core, ['num', 'clamp']);
    const props = {};
    const c = load(fxjs, ['glassTintVars', 'applyGlassTint'], { num: k.num, clamp: k.clamp, document: { documentElement: fakeRoot(props) }, S: { glassTint: 80 } });
    c.applyGlassTint();
    eq(props, { '--gx-up': '0.600' }, 'S.glassTint = 80');
    c.applyGlassTint(20);
    eq(props, { '--gx-dn': '0.600' }, '20: 清透方向, 删掉 up');
    c.applyGlassTint(50);
    eq(props, {}, '标准: 两个都删');
  },
  // UI: 档位名(界限取 fx.js 的 GX_T)
  glass_tint_label() {
    const c = load(fxjs, ['glassTintLabel'], { GX_T: gxTable() });
    eq([0, 9, 10, 39, 40, 50, 59, 60, 89, 90, 100].map((v) => c.glassTintLabel(v)),
      ['清透', '清透', '偏清透', '偏清透', '标准', '标准', '标准', '偏着色', '偏着色', '着色', '着色'], '档位');
  },
  // UI: 接线 —— 滑块拖动实时生效不存, 松手才存; 标准档 ±3 吸附, 拖进标准档轻震
  glass_tint_input() {
    const k = load(core, ['num', 'clamp']);
    const props = {}, ls = {}, lb = { textContent: '' }, S = { glassTint: 50 };
    let buzz = 0;
    const f = load(fxjs, ['glassTintVars', 'applyGlassTint', 'glassTintLabel'], { num: k.num, clamp: k.clamp, document: { documentElement: fakeRoot(props) }, S, GX_T: gxTable() });
    const m = load(mainjs, ['glassTintInput'], {
      num: k.num, clamp: k.clamp, S, LS: { set: (a, b) => { ls[a] = b; } }, $: (q) => (q === '#glass-tint-v' ? lb : null),
      haptic: () => { buzz++; }, gxShown: null, applyGlassTint: f.applyGlassTint, glassTintLabel: f.glassTintLabel,
    });
    const el = { value: '52' };
    m.glassTintInput(el, false);
    eq([props, lb.textContent, ls, el.value, buzz], [{}, '标准', {}, '52', 0], '52 拖动: 吸到标准, 不存');
    el.value = '90';
    m.glassTintInput(el, false);
    eq([props, ls, S.glassTint], [{ '--gx-up': '0.800' }, {}, 50], '90 拖动: 实时生效, 不存');
    m.glassTintInput(el, true);
    eq([ls, S.glassTint, lb.textContent], [{ 'hnc6.glass_tint': '90' }, 90, '着色'], '90 松手: 存');
    el.value = '48';
    m.glassTintInput(el, true);
    eq([props, ls, S.glassTint, el.value, buzz], [{}, { 'hnc6.glass_tint': '50' }, 50, '50', 1], '48 松手: 吸回标准并存, 轻震一次');
  },
  // UI: liquid.css 的填充按 --gx-up / --gx-dn 插值; 两个都 0 时等于旧版数值; 两端不越界; 降低透明度 → 着色
  liquid_tint_css() {
    const css = fs.readFileSync(liquidcss, 'utf8');
    const re = /--(card|card-2|lg-fill|lg-fill-2|lg-tint):rgba\((\d+,\d+,\d+),calc\(([.\d]+) \+ var\(--gx-up,0\)\*([.\d]+) - var\(--gx-dn,0\)\*([.\d]+)\)\)/g;
    const got = [];
    let m;
    while ((m = re.exec(css))) got.push([m[1], m[2], +m[3], +m[4], +m[5]]);
    const old = [['card', '255,255,255', 0.62], ['card-2', '255,255,255', 0.74], ['lg-fill', '255,255,255', 0.26], ['lg-fill-2', '255,255,255', 0.5], ['lg-tint', '255,255,255', 0.34]];
    const oldDark = [['card', '44,44,52', 0.5], ['card-2', '56,56,64', 0.56], ['lg-fill', '40,40,48', 0.3], ['lg-fill-2', '60,60,70', 0.46], ['lg-tint', '255,255,255', 0.12]];
    eq(got.map((g) => [g[0], g[1], g[2]]), old.concat(oldDark, oldDark), '标准档 = 旧版数值(浅色 + 两处深色)');
    for (const g of got) {
      if (!(g[2] + g[3] <= 0.95 && g[3] > 0 && g[2] - g[4] >= 0.05 && g[4] > 0)) { console.log('越界: ' + JSON.stringify(g)); process.exit(1); }
    }
    if (!/@media \(prefers-reduced-transparency: reduce\)\{ :root\[data-glass="liquid"\]\{--gx-up:1!important;--gx-dn:0!important\} \}/.test(css)) { console.log('缺少降低透明度规则'); process.exit(1); }
  },
  // UI: 顶栏实底 —— 大标题收起(56px)后 20px 内渐变到实底; 关了大标题动效则滚 8px 起
  nav_solid() {
    const k = load(core, ['clamp']);
    const hp = {}, cls = {}, pg = { scrollTop: 0, style: { setProperty() {} } };
    const hdr = { style: { setProperty: (a, b) => { hp[a] = b; } }, classList: { toggle: (c, on) => { cls[c] = !!on; } } };
    let titleOn = true;
    const doc = { querySelector: (q) => (q === '.header' ? hdr : null), getElementById: (id) => (id === 'htitle' ? { textContent: '' } : id === 'p-devices' ? pg : null), documentElement: { classList: { toggle() {} } } };
    const c = load(fxjs, ['navSync'], { document: doc, S: { page: 'devices' }, NAV_T: { devices: '设备' }, apple: () => true, fxOn: () => titleOn, clamp: k.clamp });
    const at = (y) => { pg.scrollTop = y; c.navSync(); return [hp['--hs'], cls['hs-on']]; };
    eq([at(0), at(56), at(66), at(200)], [['0.000', false], ['0.000', false], ['0.500', true], ['1.000', true]], '大标题开');
    titleOn = false;
    eq([at(8), at(18), at(40)], [['0.000', false], ['0.500', true], ['1.000', true]], '大标题关');
  },
};

if (!cases[which]) { console.log('unknown case ' + which); process.exit(2); }
cases[which]();
