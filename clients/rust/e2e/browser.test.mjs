// Real-browser end-to-end test: drives the actual PWA in system Chrome against a
// live directory + queue + two client instances, entirely through the UI.
//
// Covers: passwordless signup (name + email), compose + send via the "New
// message" flow, delivery, the received-message UI (thread list, names learned
// from the signed record, rendered bubbles), replying via the message-action
// menu, adding a contact by email, and the Web Push subscription wiring.
//
// Run:  cd clients/rust/e2e && npm test        (needs: cargo build, google-chrome)
//
// Interactions use JS-triggered clicks (element.click()) and value-setting, not
// Puppeteer's synthetic mouse — a synthetic click that opens an overlay crashes
// *headless* Chrome (a headless-only quirk; the app is fine in a normal browser).

import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const BIN = (n) => path.join(ROOT, 'target/debug', n);
const CHROME = '/usr/bin/google-chrome';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const procs = [];
const tmps = [];
function cleanup() {
  for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
}
function tmpdir(tag) { const d = fs.mkdtempSync(path.join(os.tmpdir(), `myc-e2e-${tag}-`)); tmps.push(d); return d; }
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
function serviceConfig(name, config) { const file = path.join(ROOT, 'target', name + '-' + config.addr.split(':').pop() + '.json'); fs.writeFileSync(file, JSON.stringify(config)); return file; }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }
function spawnBin(name, args) { const p = spawn(BIN(name), args, { stdio: 'ignore' }); procs.push(p); return p; }

let failed = false;
const step = (m) => console.error('•', m);
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

// --- UI helpers: JS-based, no synthetic input devices ---
async function click(page, sel) {
  await page.waitForSelector(sel, { timeout: 10000 });
  await page.evaluate((s) => document.querySelector(s).click(), sel);
}
async function fill(page, sel, text) {
  await page.waitForSelector(sel, { timeout: 10000 });
  await page.evaluate((s, t) => {
    const el = document.querySelector(s);
    el.value = t;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }, sel, text);
}
async function textAppears(page, selector, needle, ms = 25000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await page
      .evaluate((s, t) => Array.from(document.querySelectorAll(s)).some((e) => e.textContent.includes(t)), selector, needle)
      .catch(() => false);
    if (ok) return true;
    await sleep(400);
  }
  throw new Error(`text "${needle}" never appeared in ${selector}`);
}

function sendFrom(page, email, text) {
  return page.evaluate(async (e, t) => {
    const r = await fetch('/api/threads/' + encodeURIComponent(e), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: t }) });
    return r.status;
  }, email, text);
}
const clearNotifs = (page) => page.evaluate(() => { window.__notifications = []; });
const notifCount = (page) => page.evaluate(() => (window.__notifications || []).length);
async function waitNotif(page, needle, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const hit = await page.evaluate((t) => (window.__notifications || []).some((n) => (n.body + ' ' + n.title).includes(t)), needle).catch(() => false);
    if (hit) return true;
    await sleep(400);
  }
  return false;
}

// Runs in the page before any app code: mock the Notification API so we can see
// what the app *would* pop, and pin visibility to 'visible' so the "are you
// looking at this thread?" check is deterministic (headless backgrounds pages).
function installNotificationMock() {
  window.__notifications = [];
  class MockNotification {
    constructor(title, opts) { window.__notifications.push({ title, body: (opts && opts.body) || '' }); }
    close() {}
  }
  MockNotification.permission = 'granted';
  MockNotification.requestPermission = () => Promise.resolve('granted');
  window.Notification = MockNotification;
  Object.defineProperty(document, 'hidden', { get: () => false, configurable: true });
  Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
}

async function signup(browser, base, name, email) {
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.error(`  [${name} pageerror] ${e.message}`));
  page.on('dialog', (d) => { console.error(`  [${name} DIALOG] ${d.type()}: ${d.message()}`); d.dismiss().catch(() => {}); });
  await page.evaluateOnNewDocument(installNotificationMock);
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await fill(page, '#name', name);
  await fill(page, '#email', email);
  await click(page, '#go');
  await page.waitForSelector('#verify', { timeout: 10000 }); // dev-mode code prefilled
  await click(page, '#verify');
  await page.waitForSelector('nav.tabs', { timeout: 10000 });
  return page;
}

async function main() {
  for (const b of ['mycellium-server', 'mycellium-queue', 'mycellium-client']) {
    if (!fs.existsSync(BIN(b))) throw new Error(`missing ${BIN(b)} — run: cargo build`);
  }
  const [dP, qP, caP, cbP] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const dir = `http://127.0.0.1:${dP}`, q = `http://127.0.0.1:${qP}`, aUrl = `http://127.0.0.1:${caP}`, bUrl = `http://127.0.0.1:${cbP}`;

  spawnBin('mycellium-server', ['--config', serviceConfig('directory', { addr: `127.0.0.1:${dP}`, dev_auth: true })]);
  spawnBin('mycellium-queue', ['--config', serviceConfig('queue', { addr: `127.0.0.1:${qP}` })]);
  await Promise.all([waitHttp(dir + '/health'), waitHttp(q + '/health')]);
  spawnBin('mycellium-client', ['--port', String(caP), '--directory', dir, '--queue', q, '--data-dir', tmpdir('a')]);
  spawnBin('mycellium-client', ['--port', String(cbP), '--directory', dir, '--queue', q, '--data-dir', tmpdir('b')]);
  await Promise.all([waitHttp(aUrl), waitHttp(bUrl)]);

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: true,
    args: [
      '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
      // Keep both pages polling — headless throttles timers in background tabs.
      '--disable-background-timer-throttling', '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding',
    ],
  });

  step('passwordless signup (name + email)');
  const mary = await signup(browser, aUrl, 'Mary', 'mary@example.com');
  const john = await signup(browser, bUrl, 'John', 'john@example.com');
  check(true, 'both reached the app — no password, no seed phrase');

  step('mary composes a message to john@example.com via the New-message flow');
  await click(mary, '#newChat');
  await fill(mary, '#pval', 'john@example.com');
  await click(mary, '#ok');
  await fill(mary, '#msg', 'hello from a real browser');
  await click(mary, '#send');
  await textAppears(mary, '.bubble', 'hello from a real browser', 8000);
  check(true, 'message composed and shown in the conversation');

  step("john's UI receives it (polling → thread list → conversation)");
  await textAppears(john, '.item .title', 'Mary', 25000);      // name learned from the signed record
  await textAppears(john, '.item .snippet', 'hello from a real browser', 25000);
  await click(john, '.item');
  await textAppears(john, '.bubble', 'hello from a real browser', 10000);
  check(true, 'john sees the thread from "Mary" and the message renders');

  step('john replies via the message-action menu');
  await click(john, '.bubble[data-id]');       // opens the action modal
  await click(john, '#reply');                  // sets reply mode
  await fill(john, '#msg', 'got it, thanks');
  await click(john, '#send');
  await textAppears(john, '.bubble', 'got it, thanks', 8000);
  // Mary: verify receipt via her thread list.
  await click(mary, '#back');
  await textAppears(mary, '.item .snippet', 'got it, thanks', 25000);
  check(true, "reply sent from john's UI and shows in mary's thread list");

  step('mary adds a contact by email');
  await click(mary, '[data-tab="contacts"]');
  await click(mary, '#addContact');
  await fill(mary, '#cemail', 'john@example.com');
  await fill(mary, '#cnick', 'Johnny');
  await click(mary, '#add');
  await textAppears(mary, '.item .title', 'Johnny', 15000);
  check(true, 'contact "Johnny" added by email and listed');

  step('desktop notification fires for a message you are NOT viewing');
  await click(john, '#back');           // leave the conversation → on the thread list
  await sleep(2000);                     // let a tick seed "seen" state
  await clearNotifs(john);
  await sendFrom(mary, 'john@example.com', 'ping while away');
  check(await waitNotif(john, 'ping while away', 20000), 'notification raised with the message text');

  step('NO notification while actively viewing that conversation');
  await click(john, '.item');           // open Mary's thread → now "viewing"
  await textAppears(john, '.bubble', 'ping while away', 10000);
  await clearNotifs(john);
  await sendFrom(mary, 'john@example.com', 'while you watch');
  await textAppears(john, '.bubble', 'while you watch', 20000); // it arrives + renders
  await sleep(2000);
  check((await notifCount(john)) === 0, 'no notification raised while the thread is open');

  step('web push subscription wiring');
  const sub = await mary.evaluate(async () => {
    if (!('serviceWorker' in navigator)) return { sw: false };
    const reg = await navigator.serviceWorker.ready;
    const s = await reg.pushManager.getSubscription().catch(() => null);
    const key = await (await fetch('/api/push/key')).json();
    return { sw: !!reg.active, hasKey: !!key.key, subscribed: !!s };
  });
  check(sub.sw, 'service worker active');
  check(sub.hasKey, 'queue exposes a VAPID key via /api/push/key');
  console.error(sub.subscribed
    ? '  ✓ browser push subscription created'
    : '  ~ push subscription not created headless (no reachable push service) — wiring verified, delivery needs a real device');

  await browser.close();
}

main()
  .then(() => { cleanup(); console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { cleanup(); console.error('\nERROR:', e.message); process.exit(1); });
