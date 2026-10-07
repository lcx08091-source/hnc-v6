// test/js/v530_frontend.js — v5.30 前端逻辑用例(由 test/unit/test_v530_frontend.sh 逐个调用)。
// 用法: node v530_frontend.js <仓库根> <用例名>; 通过 exit 0, 失败打印原因 exit 1。
'use strict';
const path = require('path');
const { load } = require('./extract_fns.js');

const root = process.argv[2];
const which = process.argv[3];
const core = path.join(root, 'webroot/js/core.js');

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
};

if (!cases[which]) { console.log('unknown case ' + which); process.exit(2); }
cases[which]();
