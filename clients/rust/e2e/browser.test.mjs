// Real-browser end-to-end test: drives the actual PWA in system Chrome against a
// live directory + queue + two client instances. Verifies passwordless signup
// (name + email), message delivery, the received-message UI (thread list, names
// learned from the signed record, rendered bubbles), and the Web Push
// *subscription* wiring.
//
// Run:  cd clients/rust/e2e && npm test        (needs: cargo build, google-chrome)
//
// Note: sends are issued via a same-origin fetch from the page rather than the
// "New message" modal — opening a modal disconnects *headless* Chrome (a headless
// quirk; modals work in a normal browser). The receive/render path is still
// driven fully through the UI.

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
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }
function spawnBin(name, args) { const p = spawn(BIN(name), args, { stdio: 'ignore' }); procs.push(p); return p; }

let failed = false;
const step = (m) => console.error('•', m);
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

async function signup(browser, base, name, email) {
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.error(`  [${name} pageerror] ${e.message}`));
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#name', { timeout: 10000 });
  await page.type('#name', name);
  await page.type('#email', email);
  await page.click('#go');
  await page.waitForSelector('#verify', { timeout: 10000 }); // dev-mode code is prefilled
  await page.click('#verify');
  await page.waitForSelector('nav.tabs', { timeout: 10000 });
  return page;
}

async function textAppears(page, selector, needle, ms = 20000) {
  await page.waitForFunction(
    (sel, txt) => Array.from(document.querySelectorAll(sel)).some((e) => e.textContent.includes(txt)),
    { timeout: ms }, selector, needle,
  );
}

async function main() {
  for (const b of ['mycellium-server', 'mycellium-queue', 'mycellium-client']) {
    if (!fs.existsSync(BIN(b))) throw new Error(`missing ${BIN(b)} — run: cargo build`);
  }
  const [dP, qP, caP, cbP] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const dir = `http://127.0.0.1:${dP}`, q = `http://127.0.0.1:${qP}`, aUrl = `http://127.0.0.1:${caP}`, bUrl = `http://127.0.0.1:${cbP}`;

  spawnBin('mycellium-server', ['--addr', `127.0.0.1:${dP}`]);
  spawnBin('mycellium-queue', ['--addr', `127.0.0.1:${qP}`]);
  await Promise.all([waitHttp(dir + '/health'), waitHttp(q + '/health')]);
  spawnBin('mycellium-client', ['--port', String(caP), '--directory', dir, '--queue', q, '--data-dir', tmpdir('a')]);
  spawnBin('mycellium-client', ['--port', String(cbP), '--directory', dir, '--queue', q, '--data-dir', tmpdir('b')]);
  await Promise.all([waitHttp(aUrl), waitHttp(bUrl)]);

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });

  step('passwordless signup (name + email) for two accounts');
  const mary = await signup(browser, aUrl, 'Mary', 'mary@example.com');
  const john = await signup(browser, bUrl, 'John', 'john@example.com');
  check(true, 'both reached the app with no password or seed phrase');

  step('mary messages john by email');
  const status = await mary.evaluate(async () => {
    const r = await fetch('/api/threads/' + encodeURIComponent('john@example.com'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: 'hello from a real browser' }),
    });
    return r.status;
  });
  check(status === 200, `send accepted (HTTP ${status}) — email path resolved to the hashed id`);

  step("john's UI receives and renders it (polling → thread list → conversation)");
  await textAppears(john, '.item .title', 'Mary', 25000);        // name learned from the signed record
  await textAppears(john, '.item .snippet', 'hello from a real browser', 25000);
  check(true, 'thread appears from "Mary" with the message preview');
  await john.click('.item');
  await textAppears(john, '.bubble', 'hello from a real browser', 10000);
  check(true, 'message renders inside the conversation');

  step('web push subscription wiring');
  const sub = await mary.evaluate(async () => {
    if (!('serviceWorker' in navigator)) return { sw: false };
    const reg = await navigator.serviceWorker.ready;
    const s = await reg.pushManager.getSubscription().catch(() => null);
    const key = await (await fetch('/api/push/key')).json();
    return { sw: !!reg.active, hasKey: !!key.key, subscribed: !!s };
  });
  check(sub.sw, 'service worker is active');
  check(sub.hasKey, 'queue exposes a VAPID key via /api/push/key');
  console.error(sub.subscribed
    ? '  ✓ browser push subscription created'
    : '  ~ push subscription not created in headless (no reachable push service) — wiring verified, delivery needs a real device');

  await browser.close();
}

main()
  .then(() => { cleanup(); console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { cleanup(); console.error('\nERROR:', e.message); process.exit(1); });
