// test/js/v530_frontend.js — v5.30 前端逻辑用例(由 test/unit/test_v530_frontend.sh 逐个调用)。
// 用法: node v530_frontend.js <仓库根> <用例名>; 通过 exit 0, 失败打印原因 exit 1。
'use strict';
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { load } = require('./extract_fns.js');

const root = process.argv[2] || path.resolve(__dirname, '../..');
const which = process.argv[3] || '__all__';
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
  // UI: 玻璃浓度档位点选 —— setGlassTint 立即更新 CSS 变量、文案并写入本地存储
  glass_tint_pick() {
    const k = load(core, ['num', 'clamp']);
    const props = {}, attrs = {}, ls = {}, lb = { textContent: '' }, S = { glassTint: 50 };
    let buzz = 0;
    const mkBtn = (v) => ({
      dataset: { gxPick: String(v), glassTint: String(v), val: String(v) },
      getAttribute: (n) => (n === 'data-gx-pick' || n === 'data-glass-tint' || n === 'data-val' ? String(v) : null),
      setAttribute() {},
      removeAttribute() {},
      classList: { toggle() {}, add() {}, remove() {} },
    });
    const btns = [0, 25, 50, 75, 100].map(mkBtn);
    const rootEl = {
      style: { setProperty: (a, b) => { props[a] = b; }, removeProperty: (a) => { delete props[a]; } },
      setAttribute: (a, b) => { attrs[a] = String(b); },
      removeAttribute: (a) => { delete attrs[a]; },
      classList: { toggle() {}, add() {}, remove() {} },
    };
    const doc = {
      documentElement: rootEl,
      getElementById: (id) => (id === 'glass-tint-v' ? lb : null),
      querySelector: (q) => (q === '#glass-tint-v' ? lb : null),
      querySelectorAll: () => btns,
    };
    const f = load(fxjs, ['glassTintVars', 'applyGlassTint', 'glassTintLabel'], { num: k.num, clamp: k.clamp, document: doc, S, GX_T: gxTable() });
    const srcFile = [mainjs, fxjs, path.join(root, 'webroot/js/settings.js')].find((p) => /(^|\n)function setGlassTint\s*\(/.test(fs.readFileSync(p, 'utf8'))) || mainjs;
    const m = load(srcFile, ['setGlassTint'], {
      num: k.num, clamp: k.clamp, S, document: doc,
      LS: { set: (a, b) => { ls[a] = String(b); }, get: (a, d) => (a in ls ? ls[a] : d) },
      $: (q) => (q === '#glass-tint-v' ? lb : null),
      $$: () => btns,
      haptic: () => { buzz++; },
      applyGlassTint: f.applyGlassTint, glassTintLabel: f.glassTintLabel,
      setTimeout: (fn) => { fn(); return 1; }, clearTimeout: () => {},
    });
    m.setGlassTint(90);
    eq([props, S.glassTint, ls['hnc6.glass_tint'], lb.textContent], [{ '--gx-up': '0.800' }, 90, '90', '着色'], '点选 90 着色档');
    m.setGlassTint(20);
    eq([props, S.glassTint, ls['hnc6.glass_tint'], lb.textContent], [{ '--gx-dn': '0.600' }, 20, '20', '偏清透'], '点选 20 偏清透档');
    m.setGlassTint(50);
    eq([props, S.glassTint, ls['hnc6.glass_tint'], lb.textContent], [{}, 50, '50', '标准'], '点选 50 标准档清空变量');
    m.setGlassTint(150);
    eq([S.glassTint, ls['hnc6.glass_tint']], [100, '100'], '上限钳制 100');
    m.setGlassTint(-20);
    eq([S.glassTint, ls['hnc6.glass_tint']], [0, '0'], '下限钳制 0');
  },
  // UI: 壁纸模糊与遮罩步进/档位 —— syncWpNumericVars / setWpBlur / setWpDim
  wp_blur_dim_step() {
    const k = load(core, ['num', 'clamp']);
    const props = {}, attrs = {}, ls = {};
    const blurLb = { textContent: '' }, dimLb = { textContent: '' };
    const S = { wpBlur: 0, wpDim: 12 };
    const rootEl = {
      style: { setProperty: (a, b) => { props[a] = b; }, removeProperty: (a) => { delete props[a]; } },
      setAttribute: (a, b) => { attrs[a] = String(b); },
      removeAttribute: (a) => { delete attrs[a]; },
      classList: { toggle() {}, add() {}, remove() {} },
    };
    const qEl = (q) => (q === '#wp-blur-v' || q === 'wp-blur-v' ? blurLb : q === '#wp-dim-v' || q === 'wp-dim-v' ? dimLb : null);
    const doc = {
      documentElement: rootEl,
      getElementById: qEl,
      querySelector: qEl,
      querySelectorAll: () => [],
    };
    let sceneRebuilt = 0, sceneSynced = 0;
    const globals = {
      num: k.num, clamp: k.clamp, S, document: doc,
      LS: { set: (a, b) => { ls[a] = String(b); }, get: (a, d) => (a in ls ? ls[a] : d) },
      $: qEl, $$: () => [], haptic: () => {},
      rebuildEffectiveWpScene: () => { sceneRebuilt++; },
      scheduleWpSceneSync: () => { sceneSynced++; },
      setTimeout: (fn) => { fn(); return 1; }, clearTimeout: () => {},
    };
    const m = load(mainjs, ['syncWpNumericVars', 'setWpBlur', 'setWpDim'], globals);
    m.syncWpNumericVars();
    eq([props['--wp-blur'], props['--wp-dim'], 'data-wp-blurred' in attrs], ['0px', '0.12', false], '初始 0px 不标 data-wp-blurred');
    m.setWpBlur(12);
    eq([S.wpBlur, props['--wp-blur'], attrs['data-wp-blurred'], blurLb.textContent, ls['hnc6.wp_blur']], [12, '12px', '1', '12 px', '12'], '设置模糊 12px');
    m.setWpBlur(99);
    eq([S.wpBlur, props['--wp-blur'], ls['hnc6.wp_blur']], [24, '24px', '24'], '模糊上限钳制 24px');
    m.setWpBlur(-5);
    eq([S.wpBlur, props['--wp-blur'], 'data-wp-blurred' in attrs, ls['hnc6.wp_blur']], [0, '0px', false, '0'], '模糊归零移除 data-wp-blurred');
    m.setWpDim(35);
    eq([S.wpDim, props['--wp-dim'], dimLb.textContent, ls['hnc6.wp_dim'], sceneRebuilt > 0, sceneSynced > 0], [35, '0.35', '35%', '35', true, true], '设置遮罩 35% 并联动实景采样重算');
    m.setWpDim(120);
    eq([S.wpDim, props['--wp-dim'], ls['hnc6.wp_dim']], [75, '0.75', '75'], '遮罩上限钳制 75%');
    m.setWpDim(-8);
    eq([S.wpDim, props['--wp-dim'], ls['hnc6.wp_dim']], [0, '0.00', '0'], '遮罩下限钳制 0%');
  },
  // UI: 前端零拖动滑条 —— webroot 运行时代码零 <input type=range>、零旧滑条类名、零 glassTintInput
  webroot_zero_range() {
    const webDir = path.join(root, 'webroot');
    const walk = (dir) => {
      const out = [];
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const fp = path.join(dir, ent.name);
        if (ent.isDirectory()) out.push(...walk(fp));
        else if (/\.(html|css|js)$/.test(ent.name) && ent.name !== 'changelog.html') out.push(fp);
      }
      return out;
    };
    const legacyRangeCls = 'gx-' + 'range';
    const hits = [];
    for (const fp of walk(webDir)) {
      const rel = path.relative(root, fp);
      const txt = fs.readFileSync(fp, 'utf8');
      if (/<input[^>]*\btype\s*=\s*["']?range\b/i.test(txt)) hits.push(rel + ':<input type=range>');
      if (txt.indexOf(legacyRangeCls) >= 0) hits.push(rel + ':' + legacyRangeCls);
      if (/\bfunction\s+glassTintInput\b/.test(txt)) hits.push(rel + ':glassTintInput');
    }
    eq(hits, [], 'webroot 应零拖动滑条残留');
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
  // UI: 液态玻璃三版本辅助函数 —— normLgVariant / LG_VARIANTS / lgVariantLabel / lgVariantDesc
  lg_variants() {
    const files = [core, fxjs, mainjs, path.join(root, 'webroot/js/settings.js')].filter((p) => fs.existsSync(p));
    const stmtEnd = (src, idx) => {
      let depth = 0, quote = '', esc = false, lc = false, bc = false;
      for (let i = idx; i < src.length; i++) {
        const ch = src[i], nx = src[i + 1];
        if (lc) { if (ch === '\n') lc = false; continue; }
        if (bc) { if (ch === '*' && nx === '/') { bc = false; i++; } continue; }
        if (quote) {
          if (esc) { esc = false; continue; }
          if (ch === '\\') { esc = true; continue; }
          if (ch === quote) quote = '';
          continue;
        }
        if (ch === '/' && nx === '/') { lc = true; i++; continue; }
        if (ch === '/' && nx === '*') { bc = true; i++; continue; }
        if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') { if (depth > 0) depth--; }
        else if (ch === ';' && depth === 0) return i + 1;
      }
      return src.length;
    };
    const ctx = {};
    const vmCtx = vm.createContext(ctx);
    for (const fp of files) {
      const src = fs.readFileSync(fp, 'utf8');
      const declRe = /(?:^|\n)[ \t]*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=/g;
      let m;
      while ((m = declRe.exec(src))) {
        const name = m[1];
        if (/^(?:LG_|_LG|lgVariant|normLgVariant|KEY_LG|DEF_LG)/i.test(name)) {
          const st = m.index + (src[m.index] === '\n' ? 1 : 0);
          const ed = stmtEnd(src, m.index + m[0].length);
          const code = src.slice(st, ed).replace(/^[ \t]*(?:let|const)\b/, 'var');
          vm.runInContext(code, vmCtx);
        }
      }
    }
    for (const fp of files) {
      const src = fs.readFileSync(fp, 'utf8');
      const fnRe = /(?:^|\n)[ \t]*function\s+([A-Za-z_$][\w$]*)\s*\(/g;
      const matched = [];
      let fm;
      while ((fm = fnRe.exec(src))) {
        const fn = fm[1];
        if (/(?:lgVariant|LgVariant|^_?lg[A-Z_])/.test(fn) && !/^(?:setLgVariant|applyLgVariant|initLgVariant|syncLgVariant)$/.test(fn)) {
          matched.push(fn);
        }
      }
      if (matched.length) Object.assign(ctx, load(fp, matched, ctx));
    }
    if (typeof ctx.normLgVariant !== 'function') { console.log('缺少 normLgVariant'); process.exit(1); }
    if (typeof ctx.lgVariantLabel !== 'function') { console.log('缺少 lgVariantLabel'); process.exit(1); }
    eq(ctx.normLgVariant('pure'), 'pure', 'normLgVariant pure');
    eq(ctx.normLgVariant('prism'), 'prism', 'normLgVariant prism');
    eq(ctx.normLgVariant('dew'), 'dew', 'normLgVariant dew');
    eq(ctx.normLgVariant('xxx'), 'pure', 'normLgVariant 非法值 xxx -> pure');
    eq(ctx.normLgVariant(''), 'pure', 'normLgVariant 空串 -> pure');
    eq(ctx.normLgVariant(null), 'pure', 'normLgVariant null -> pure');
    eq(ctx.normLgVariant(undefined), 'pure', 'normLgVariant undefined -> pure');
    eq(ctx.lgVariantLabel('pure'), '纯透无框', 'lgVariantLabel pure');
    eq(ctx.lgVariantLabel('prism'), '棱镜色散', 'lgVariantLabel prism');
    eq(ctx.lgVariantLabel('dew'), '凝脂水滴', 'lgVariantLabel dew');
    eq(ctx.lgVariantLabel('xxx'), '纯透无框', 'lgVariantLabel 非法值 xxx -> 纯透无框');
    eq(ctx.lgVariantLabel(null), '纯透无框', 'lgVariantLabel null -> 纯透无框');
    if (typeof ctx.lgVariantDesc === 'function') {
      for (const v of ['pure', 'prism', 'dew']) {
        const d = ctx.lgVariantDesc(v);
        if (typeof d !== 'string' || !d.trim()) { console.log('lgVariantDesc(' + v + ') 为空'); process.exit(1); }
      }
      eq(ctx.lgVariantDesc('xxx'), ctx.lgVariantDesc('pure'), 'lgVariantDesc 非法值回退 pure');
    }
    if (ctx.LG_VARIANTS !== undefined) {
      const ids = Array.isArray(ctx.LG_VARIANTS)
        ? ctx.LG_VARIANTS.map((x) => (typeof x === 'string' ? x : (x.id || x.key || x.val || x.v || x.name)))
        : Object.keys(ctx.LG_VARIANTS);
      eq(ids, ['pure', 'prism', 'dew'], 'LG_VARIANTS 三版本顺序');
    }
  },
};

if (which === '__all__') { Object.keys(cases).forEach(k => cases[k]()); process.exit(0); }
if (!cases[which]) { console.log('unknown case ' + which); process.exit(2); }
cases[which]();
