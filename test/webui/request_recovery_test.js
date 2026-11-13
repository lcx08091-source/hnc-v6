'use strict';

// Execute the production classic-script functions with transport/DOM boundaries mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const core = fs.readFileSync(path.join(root, 'webroot/js/core.js'), 'utf8');
const main = fs.readFileSync(path.join(root, 'webroot/js/main.js'), 'utf8');
const watchdog = setTimeout(() => {
  console.error('FAIL: WebUI request/bootstrap promise did not settle');
  process.exit(1);
}, 3000);

function transport(fetch, controller) {
  const timers = new Set();
  const context = {
    fetch, AbortController: controller, KSU: false,
    location: { pathname: '/', href: '' },
    setTimeout(fn, ms) {
      const timer = setTimeout(() => { timers.delete(timer); fn(); }, ms);
      timers.add(timer); return timer;
    },
    clearTimeout(timer) { timers.delete(timer); clearTimeout(timer); }
  };
  vm.createContext(context);
  vm.runInContext(core.slice(core.indexOf('function HttpError('), core.indexOf('function errText(')), context);
  return { context, timers };
}

const json = value => ({ status: 200, ok: true, text: () => Promise.resolve(JSON.stringify(value)) });
const pendingBody = () => ({ status: 200, ok: true, text: () => new Promise(() => {}) });

async function requestTests() {
  for (const controller of [AbortController, undefined]) {
    const { context, timers } = transport(() => Promise.resolve(pendingBody()), controller);
    await assert.rejects(context.fetchReq('GET', '/api/live', null, { timeout: 25 }), /请求超时/);
    assert.equal(timers.size, 0, 'body timeout releases its timer even without AbortController');
  }
  {
    const { context, timers } = transport(() => new Promise(() => {}), undefined);
    await assert.rejects(context.fetchReq('GET', '/api/live', null, { timeout: 25 }), /请求超时/);
    assert.equal(timers.size, 0, 'header timeout releases request');
  }
  {
    let requests = 0;
    const { context, timers } = transport(() => Promise.resolve(++requests === 1 ? pendingBody() : json({ ok: true })), AbortController);
    const first = context.api.action('first', {}, { timeout: 25 });
    const second = context.api.action('second', {}, { timeout: 1000 });
    await assert.rejects(first, /请求超时/);
    assert.equal((await second).ok, true, 'next queued action runs after stalled response times out');
    assert.equal(requests, 2);
    assert.equal(timers.size, 0, 'successful response clears its deadline');
  }
  {
    let finishBody;
    const { context } = transport(() => Promise.resolve({ status: 401, ok: false, text: () => new Promise(resolve => { finishBody = resolve; }) }), undefined);
    await assert.rejects(context.fetchReq('GET', '/api/live', null, { timeout: 25 }), /请求超时/);
    finishBody('{}');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(context.location.href, '', 'late response after timeout does not schedule a pairing redirect');
  }
  {
    const { context, timers } = transport(() => Promise.resolve({ status: 200, ok: true, text: () => Promise.reject(new Error('body lost')) }), AbortController);
    await assert.rejects(context.fetchReq('GET', '/api/live', null, { timeout: 1000 }), /body lost/);
    assert.equal(timers.size, 0, 'body read rejection clears timer');
  }
}

async function bootstrapTests() {
  const counts = {};
  const count = name => { counts[name] = (counts[name] || 0) + 1; };
  let unavailable = true;
  const state = { page: 'devices', booted: false, connected: false, devices: [], devLoaded: true, open: {}, live: {}, lastOk: 0 };
  const context = {
    S: state, KSU: false, pollBusy: false, tickN: 0, document: { hidden: false },
    api: {
      get() { count('health'); return unavailable ? Promise.reject(new Error('starting')) : Promise.resolve({}); },
      getSafe() { return Promise.resolve(null); }
    },
    $() { return {}; },
    RENDER: { devices() { count('render'); } },
    renderDevices() {}, errText: e => e.message, showRollbackBanner() {}, toast() {},
    schedulePoll() { count('scheduled'); }, paintUsage() {}, refreshCard() {},
    paintHero() {}, drawSpark() {}, paintFresh() {}, shapeOf() { return ''; }, num: v => Number(v) || 0,
    loadLive() { count('live'); state.connected = true; return Promise.resolve({}); },
    loadEncdns() { return Promise.resolve(null); }
  };
  ['loadConfig', 'loadCaps', 'loadTemplates', 'loadAppLimits', 'loadDevices', 'loadAlerts', 'loadOffload', 'loadOnlineHours', 'loadUsage', 'startSlowPolls', 'startSSE'].forEach(name => {
    context[name] = () => { count(name); return Promise.resolve({}); };
  });
  vm.createContext(context);
  vm.runInContext(main.slice(main.indexOf('function onEnter('), main.indexOf('\nfunction go(')), context);
  vm.runInContext(main.slice(main.indexOf('var booting = null;'), main.indexOf('\nvar saved =')), context);
  vm.runInContext(main.slice(main.indexOf('function pollOnce()'), main.indexOf('\nsetInterval(function () { if (S.page')), context);
  await context.boot(false);
  assert.equal(state.booted, false);
  assert.equal(state.connected, false);
  assert.equal(counts.scheduled, 1, 'failed startup schedules retry');
  unavailable = false;
  context.pollOnce();
  await context.booting;
  assert.equal(state.booted, true);
  assert.equal(state.connected, true);
  ['loadConfig', 'loadCaps', 'loadTemplates', 'loadAppLimits', 'loadDevices', 'startSlowPolls', 'startSSE'].forEach(name => {
    assert.equal(counts[name], 1, `${name} initialized on automatic recovery`);
  });
  assert.equal(counts.scheduled, 2, 'successful automatic boot schedules the normal poll through onEnter');
  context.pollOnce();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(counts.live, 2, 'normal live polling continues after automatic boot');
  assert.equal(context.pollBusy, false);
  assert.equal(counts.scheduled, 3, 'completed normal poll schedules its successor');
  state.connected = false;
  context.pollOnce();
  await context.booting;
  assert.equal(counts.loadConfig, 2, 'later reconnect also refreshes configuration');
  assert.equal(counts.startSSE, 2);
}

async function interfaceOwnershipTests() {
  const state = { hotspot: { iface: 'wlan2', ip: '192.168.43.1' }, spark: [] };
  let preference = 'auto';
  const context = {
    S: state, Date, num: v => Number(v) || 0,
    api: { get: () => Promise.resolve({ hotspot_iface: preference }) }
  };
  vm.createContext(context);
  vm.runInContext(core.slice(core.indexOf('function applyLive('), core.indexOf('\nfunction loadLive(')), context);
  vm.runInContext(core.slice(core.indexOf('function loadConfig('), core.indexOf('\nfunction loadCaps(')), context);
  for (preference of ['auto', 'wlan3', '']) {
    await context.loadConfig();
    assert.equal(state.cfg.hotspot_iface, preference, 'configuration retains the user preference');
    assert.equal(state.hotspot.iface, 'wlan2', 'loading preferences never replaces the runtime interface');
  }
  context.applyLive({ hotspot_iface: 'ap0', hotspot_active: true });
  assert.equal(state.hotspot.iface, 'ap0', 'live status updates the runtime interface');
  assert.equal(state.cfg.hotspot_iface, '', 'live status never replaces the saved preference');
}

(async () => {
  await requestTests();
  await bootstrapTests();
  await interfaceOwnershipTests();
  console.log('PASS: WebUI response deadlines, queued actions and complete automatic recovery');
})().then(() => { clearTimeout(watchdog); }, error => {
  clearTimeout(watchdog);
  console.error(error); process.exitCode = 1;
});
