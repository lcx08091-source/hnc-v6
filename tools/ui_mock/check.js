#!/usr/bin/env node
/* HNC WebUI 界面预览 · check.js —— 用 Playwright(Chromium)把 build.js 的产物整体走一遍并截图
 *
 * 用法: node tools/ui_mock/check.js <preview.html> <截图目录>
 *
 * 手机视口 390×844、deviceScaleFactor 2, 浅色 / 深色各跑一遍:
 *   等启动 → 设备页(逐屏滚动截图)→ 展开一台设备卡 → 实时连接弹层 → 告警弹层
 *   → 应用页(4 个子页)→ 分析页(流量统计 + DPI 分析)→ 设置页(展开「外观」+ 自检报告弹层)
 * 期间收集 console error / pageerror / 非本地请求, 并检查页面上有没有「加载失败」「演示模式未提供此接口」
 * 「undefined」「NaN」之类说明假数据没对上的文字。有任何一项就以非 0 退出。
 * Playwright 找不到时会去 /opt/node<版本>/lib/node_modules 下找; 浏览器默认用 PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers。 */
'use strict';
const fs = require('fs');
const path = require('path');

const page0 = process.argv[2], shots = process.argv[3];
if (!page0 || !shots) { console.error('用法: node tools/ui_mock/check.js <preview.html> <截图目录>'); process.exit(2); }
const pageFile = path.resolve(page0);
if (!fs.existsSync(pageFile)) { console.error('找不到 ' + pageFile + '（先跑 build.js）'); process.exit(2); }
fs.mkdirSync(shots, { recursive: true });
if (!process.env.PLAYWRIGHT_BROWSERS_PATH && fs.existsSync('/opt/pw-browsers')) process.env.PLAYWRIGHT_BROWSERS_PATH = '/opt/pw-browsers';

function loadPlaywright() {
  const tries = ['playwright'];
  try { fs.readdirSync('/opt').filter((d) => /^node/.test(d)).forEach((d) => tries.push(path.join('/opt', d, 'lib/node_modules/playwright'))); } catch (_) {}
  try { tries.push(path.join(require('child_process').execSync('npm root -g', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(), 'playwright')); } catch (_) {}
  for (const t of tries) { try { return require(t); } catch (_) {} }
  throw new Error('找不到 playwright 模块（试过: ' + tries.join(', ') + '）');
}
function chromiumPath() {
  const base = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
  try {
    for (const d of fs.readdirSync(base).filter((x) => /^chromium-\d+$/.test(x)).sort().reverse()) {
      const p = path.join(base, d, 'chrome-linux', 'chrome'); if (fs.existsSync(p)) return p;
    }
  } catch (_) {}
  return undefined;
}

// 页面上出现这些字样 = 假数据没对上 / 前端拿到了错误
const BAD_TEXT = ['演示模式未提供此接口', '演示数据出错', '加载失败', '当前后端不支持', '当前后端还', '需要新版', '后端可能还不支持', '读取 changelog.html 失败', '连不上 HNC 后端', '未连接后端', 'undefined', 'NaN', '[object Object]'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const { chromium } = loadPlaywright();
  let browser;
  try { browser = await chromium.launch(); }
  catch (e) {
    const exe = chromiumPath();
    if (!exe) throw e;
    browser = await chromium.launch({ executablePath: exe });
  }
  const problems = [];
  const shotList = [];
  const fileUrl = 'file://' + pageFile;

  for (const scheme of ['light', 'dark']) {
    // reducedMotion: 无头 Chromium 没有 GPU, 大块毛玻璃每帧要渲染近 1 秒, 弹簧动画会慢到卡住流程;
    // 走界面自带的「减少动态效果」模式, 动画直接到终点, 截图也更稳定(视觉样式不变)
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: scheme, reducedMotion: 'reduce', isMobile: true, hasTouch: true, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' });
    // 截图稳定: 关掉自动降级探测(无头浏览器帧率不准, 否则会把液态玻璃自动简化掉)
    await ctx.addInitScript(() => { try { if (localStorage.getItem('hnc6.lowfx') == null) localStorage.setItem('hnc6.lowfx', '0'); } catch (_) {} });
    const page = await ctx.newPage();
    const tag = (m) => '[' + scheme + '] ' + m;
    page.on('pageerror', (e) => problems.push(tag('pageerror: ' + (e && e.stack || e))));
    page.on('console', (m) => { if (m.type() === 'error') problems.push(tag('console.error: ' + m.text())); });
    page.on('request', (r) => { const u = r.url(); if (u !== fileUrl && !/^(data|blob):/.test(u)) problems.push(tag('外部请求: ' + u)); });

    let n = 0;
    const shot = async (name) => {
      const f = path.join(shots, scheme + '-' + String(++n).padStart(2, '0') + '-' + name + '.png');
      await page.screenshot({ path: f }); shotList.push(f);
    };
    const settle = (ms) => sleep(ms || 900);
    const checkText = async (where) => {
      const txt = await page.evaluate(() => {
        const p = document.querySelector('.page.on'), sh = document.getElementById('sheet');
        return (p ? p.innerText : '') + '\n' + (sh && sh.classList.contains('show') ? sh.innerText : '') + '\n' + (document.querySelector('.header') || {}).innerText;
      });
      BAD_TEXT.forEach((b) => { const i = txt.indexOf(b); if (i >= 0) problems.push(tag(where + ' 页面出现「' + b + '」: …' + txt.slice(Math.max(0, i - 40), i + 40).replace(/\s+/g, ' ') + '…')); });
    };
    // 当前页逐屏往下滚动截图(页面在 .page 元素里滚动, 不是 window)
    const scrollShots = async (name, max) => {
      await page.evaluate(() => { const p = document.querySelector('.page.on'); if (p) p.scrollTop = 0; });
      await settle(400); await shot(name + '-1');
      for (let i = 2; i <= (max || 6); i++) {
        const moved = await page.evaluate(() => { const p = document.querySelector('.page.on'); if (!p) return false; const y = p.scrollTop; p.scrollTop = y + p.clientHeight * 0.85; return p.scrollTop > y + 4; });
        if (!moved) break;
        await settle(500); await shot(name + '-' + i);
      }
      await checkText(name);
    };
    const tab = async (name) => {
      const b = await page.locator('#tabs .tab[data-tab="' + name + '"]').boundingBox();
      if (!b) throw new Error('找不到底栏标签 ' + name);
      await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
      await page.waitForFunction((n) => document.querySelector('#p-' + n + '.on') && document.querySelector('#p-' + n).children.length > 0, name, { timeout: 8000 });
      await settle(1300);
    };
    // 关弹层后等收起动画走完(苹果风弹层是弹簧动画, 收起途中还盖在底栏上)
    const closeSheet = async () => {
      await page.keyboard.press('Escape');
      await page.waitForFunction(() => {
        const s = document.getElementById('sheet'), sc = document.getElementById('scrim');
        return s && !s.classList.contains('show') && !s.classList.contains('closing') && getComputedStyle(s).visibility === 'hidden' && +getComputedStyle(sc).opacity < 0.05;
      }, null, { timeout: 10000 }).catch(() => {});
      await settle(400);
    };
    // 顶栏 / 弹层在弹簧动画里时 Playwright 会一直判定「不稳定」—— 先正常点, 超时再强制点
    const click = async (sel, wait) => {
      const l = page.locator(sel).first();
      try { await l.scrollIntoViewIfNeeded({ timeout: 3000 }); await l.click({ timeout: 3000 }); }
      catch (_) { await l.click({ timeout: 5000, force: true }); }
      await settle(wait);
    };

    try {
      await page.goto(fileUrl);
      // 启动: 演示标记 + 设备列表画出来 + 速率已经有数
      await page.waitForFunction(() => {
        const p = document.getElementById('mode-pill');
        return p && p.textContent === '演示数据' && document.querySelectorAll('#dev-list .dev').length >= 5 && parseFloat((document.getElementById('h-dn') || {}).textContent) > 0;
      }, null, { timeout: 15000 });
      await settle(1800);

      // ── 设备 ──
      await scrollShots('devices', 5);
      await page.evaluate(() => { const p = document.querySelector('.page.on'); if (p) p.scrollTop = 0; });
      await settle(300);
      // 展开一台规则最多的在线设备(演示数据里的 iPad Air: 限速 + 应用限时 + 类别封锁 + 按应用限速); 找不到就展开第一台
      const card = (await page.locator('#dev-list .dev[data-dev="1e:52:a8:0c:77:3d"]').count()) ? '#dev-list .dev[data-dev="1e:52:a8:0c:77:3d"]' : '#dev-list .dev';
      await click(card + ' .dev-h', 1500);
      await page.waitForFunction(() => { const d = document.querySelector('#dev-list .dev.open [data-conn-mini]'); return d && /条/.test(d.textContent); }, null, { timeout: 8000 });
      // 卡片里的「应用使用时长」「按类别封锁」「更多控制」也展开
      for (const k of ['at-', 'cb-', 'more-']) {
        const sel = '#dev-list .dev.open [data-act="fold"][data-key^="' + k + '"]';
        if (await page.locator(sel).count()) await click(sel, 700);
      }
      await page.waitForFunction(() => { const a = document.querySelector('#dev-list .dev.open [data-at]'); return !a || !/加载中/.test(a.textContent); }, null, { timeout: 8000 }).catch(() => {});
      await page.evaluate(() => { const d = document.querySelector('#dev-list .dev.open'); const p = document.querySelector('.page.on'); if (d && p) p.scrollTop += d.getBoundingClientRect().top - 70; });
      await settle(600); await shot('device-card-1');
      for (let i = 2; i <= 7; i++) {
        const more = await page.evaluate(() => { const d = document.querySelector('#dev-list .dev.open'), p = document.querySelector('.page.on'); if (!d || d.getBoundingClientRect().bottom < p.clientHeight * 0.9) return false; p.scrollTop += p.clientHeight * 0.8; return true; });
        if (!more) break;
        await settle(500); await shot('device-card-' + i);
      }
      await checkText('device-card');
      await click('#dev-list .dev.open [data-act="conns"]', 1600);   // 实时连接弹层
      await page.waitForFunction(() => /条/.test((document.getElementById('cn-body') || {}).textContent || ''), null, { timeout: 8000 });
      await shot('device-conns'); await checkText('device-conns'); await closeSheet();
      await page.evaluate(() => { const p = document.querySelector('.page.on'); if (p) p.scrollTop = 0; });
      await settle(300);
      await click('#bell', 1200);   // 告警
      await shot('alerts'); await checkText('alerts'); await closeSheet();

      // ── 应用 ──
      await tab('apps');
      await scrollShots('apps-my', 4);
      for (const sub of ['cand', 'export', 'set']) {
        await page.evaluate(() => { const p = document.querySelector('.page.on'); if (p) p.scrollTop = 0; });
        await click('[data-seg="apps-sub"] button[data-v="' + sub + '"]', 1100);
        await scrollShots('apps-' + sub, 2);
      }

      // ── 分析 ──
      await tab('stats');
      await settle(800);
      await scrollShots('stats', 6);
      await page.evaluate(() => { const p = document.querySelector('.page.on'); if (p) p.scrollTop = 0; });
      await click('[data-seg="aseg"] button[data-v="dpi"]', 1800);
      await scrollShots('stats-dpi', 6);

      // ── 设置 ──
      await tab('settings');
      await settle(600);
      await scrollShots('settings', 6);
      await click('[data-act="fold"][data-key="look"]', 1000);   // 外观
      await page.evaluate(() => { const f = document.querySelector('[data-foldkey="look"]'), p = document.querySelector('.page.on'); if (f && p) p.scrollTop += f.getBoundingClientRect().top - 80; });
      await settle(700); await shot('settings-look-1');
      await page.evaluate(() => { const p = document.querySelector('.page.on'); p.scrollTop += p.clientHeight * 0.8; }); await settle(500); await shot('settings-look-2');
      await checkText('settings-look');
      await click('.sgrp[data-foldkey="grp-diag"] > .sgrp-h', 1000);   // 诊断分组 → 自检报告
      await click('[data-act="sc-open"]', 1500);
      await shot('selfcheck'); await checkText('selfcheck'); await closeSheet();

      // 回到设备页再看一眼(轮询仍在跑、没有报错)
      await tab('devices');
      await settle(2500);
      await shot('devices-again'); await checkText('devices-again');
    } catch (e) {
      problems.push(tag('流程中断: ' + (e && e.message || e)));
      try { await shot('failure'); } catch (_) {}
    }
    await ctx.close();
  }
  await browser.close();

  console.log('截图 ' + shotList.length + ' 张 → ' + path.resolve(shots));
  if (problems.length) {
    console.error('发现 ' + problems.length + ' 个问题:');
    problems.forEach((p) => console.error(' - ' + p));
    process.exit(1);
  }
  console.log('通过: 没有 console error / pageerror / 外部请求, 页面上没有错误字样');
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
