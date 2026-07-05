// Stage-4 test: the real PWA, end to end, no local binary. Two isolated browser
// contexts (Alice, Bob) each open the static PWA, register through the UI against
// a real directory + queue, and Alice messages Bob — whose UI receives it via its
// own polling. This is the "open a link and message someone" experience the whole
// WASM effort was for.
//
// Run:  node clients/rust/e2e/pwa.test.mjs   (build: clients/web/build.sh + cargo build)

import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

// The directory fails closed without SMTP unless dev auth is explicit (#47).
process.env.MYCELLIUM_DEV_AUTH = '1';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const WEB = path.join(ROOT, 'clients/web');
const BIN = (n) => path.join(ROOT, 'target/debug', n);
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json', '.svg': 'image/svg+xml' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const procs = [];
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

// Drive the UI with JS-triggered clicks (synthetic mouse clicks crash headless
// Chrome when they open overlays — a headless quirk).
async function setVal(page, sel, val) { await page.waitForSelector(sel, { timeout: 15000 }); await page.evaluate((s, v) => { document.querySelector(s).value = v; }, sel, val); }
async function jsClick(page, sel) { await page.waitForSelector(sel, { timeout: 15000 }); await page.evaluate((s) => document.querySelector(s).click(), sel); }
async function hasText(page, sel, txt, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await page.evaluate((s, t) => Array.from(document.querySelectorAll(s)).some((e) => e.textContent.includes(t)), sel, txt).catch(() => false);
    if (ok) return true;
    await sleep(300);
  }
  return false;
}

// Mock the Notification API (record what the app would pop) + pin visibility.
function installNotifMock() {
  window.__notifs = [];
  class N { constructor(title, opts) { window.__notifs.push({ title, body: (opts && opts.body) || '' }); } close() {} }
  N.permission = 'granted';
  N.requestPermission = () => Promise.resolve('granted');
  window.Notification = N;
  Object.defineProperty(document, 'hidden', { get: () => false, configurable: true });
  Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
}
async function hasNotif(page, needle, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const hit = await page.evaluate((t) => (window.__notifs || []).some((n) => (n.body + ' ' + n.title).includes(t)), needle).catch(() => false);
    if (hit) return true;
    await sleep(300);
  }
  return false;
}

async function registerUI(ctx, url, username, name) {
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.error(`  [${username} pageerror] ${e.message}`));
  page.on('dialog', (d) => d.dismiss().catch(() => {}));
  await page.evaluateOnNewDocument(installNotifMock);
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await setVal(page, '#u', username);
  await setVal(page, '#n', name);
  await jsClick(page, '#go');
  await page.waitForSelector('header .who', { timeout: 20000 }); // reached the app screen
  return page;
}

async function main() {
  if (!fs.existsSync(path.join(WEB, 'pkg', 'mycellium_wasm.js'))) throw new Error('run clients/web/build.sh first');
  for (const b of ['mycellium-server', 'mycellium-queue']) if (!fs.existsSync(BIN(b))) throw new Error('run: cargo build');

  const [dirPort, qPort, webPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const dirUrl = `http://127.0.0.1:${dirPort}`, qUrl = `http://127.0.0.1:${qPort}`;
  procs.push(spawn(BIN('mycellium-server'), ['--addr', `127.0.0.1:${dirPort}`], { stdio: 'ignore' }));
  procs.push(spawn(BIN('mycellium-queue'), ['--addr', `127.0.0.1:${qPort}`], { stdio: 'ignore' }));
  await Promise.all([waitHttp(dirUrl + '/health'), waitHttp(qUrl + '/health')]);

  const web = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]);
    const file = path.join(WEB, rel === '/' ? 'index.html' : rel);
    if (!file.startsWith(WEB) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => web.listen(webPort, '127.0.0.1', r));
  const appUrl = `http://127.0.0.1:${webPort}/index.html?dir=${encodeURIComponent(dirUrl)}&queue=${encodeURIComponent(qUrl)}`;

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
      '--disable-background-timer-throttling', '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding'],
  });
  try {
    // Isolated storage per user (distinct IndexedDB → distinct identity).
    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();

    console.error('• Bob and Alice each register through the PWA UI (real directory)');
    const bob = await registerUI(ctxB, appUrl, 'bob', 'Bob');
    const alice = await registerUI(ctxA, appUrl, 'alice', 'Alice');
    check(true, 'both reached the messenger screen — no local binary, just a link');

    console.error('• Alice starts a chat with bob and sends a message');
    await jsClick(alice, '#new');
    await jsClick(alice, '#dm');        // FAB menu → "Message someone"
    await setVal(alice, '#peer', 'bob');
    await jsClick(alice, '#ok');
    await setVal(alice, '#msg', 'hello bob — sent from the browser PWA 🍄');
    await jsClick(alice, '#send');
    check(await hasText(alice, '.bubble', 'hello bob', 8000), "message shows in Alice's thread");

    console.error("• Bob's PWA receives it via its own polling");
    check(await hasText(bob, '.item .snippet', 'hello bob', 20000), "conversation from alice appears in Bob's list");
    check(await hasText(bob, '.item .title', 'Alice'), "Bob's list shows Alice's display name (not the raw username)");
    check(await hasText(alice, '.backbar', 'Bob'), "Alice's thread header shows Bob's display name");
    check(await hasNotif(bob, 'hello bob'), "Bob's PWA raised a desktop notification");
    await jsClick(bob, '.item');
    check(await hasText(bob, '.bubble', 'hello bob — sent from the browser PWA 🍄', 10000), 'Bob opens the thread and sees the decrypted message');

    console.error('• Bob replies to the message (rich message)');
    await jsClick(bob, '.bubble[data-id]'); // tap → action menu
    await jsClick(bob, '#reply');
    check(await hasText(bob, '.replybar', 'Replying', 5000), 'reply banner appears');
    await setVal(bob, '#msg', 'sounds good to me');
    await jsClick(bob, '#send');
    check(await hasText(bob, '.bubble', 'sounds good to me', 8000), "reply shows in Bob's thread");
    check(await hasText(alice, '.bubble', 'sounds good to me', 20000), 'Alice receives the reply (rendered with the ↪ marker)');

    console.error('• Bob reacts to a message');
    await jsClick(bob, '.bubble[data-id]'); // tap → action menu
    await jsClick(bob, '#react');           // 👍
    check(await hasText(alice, '.bubble', '👍', 20000), 'Alice receives the reaction');

    console.error('• Alice sends an image attachment, Bob renders it');
    const tinyPng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    await alice.evaluate((dir, q, png) => window.mycellium.rpc('send_file', [dir, 'alice', 'Alice', q, 'bob', 'pixel.png', 'image/png', png]), dirUrl, qUrl, tinyPng);
    const gotImg = await (async () => {
      const end = Date.now() + 20000;
      while (Date.now() < end) {
        if (await bob.evaluate(() => !!document.querySelector('img.attach[src^="data:image"]')).catch(() => false)) return true;
        await sleep(300);
      }
      return false;
    })();
    check(gotImg, "Bob's PWA received and rendered the image");

    console.error('• Alice creates a group and messages it; Bob joins + receives');
    await jsClick(alice, '#back');      // back to the chat list
    await jsClick(alice, '#new');       // FAB menu
    await jsClick(alice, '#grp');       // New group
    await setVal(alice, '#gname', 'Team Mycelium');
    await setVal(alice, '#gmembers', 'bob');
    await jsClick(alice, '#gok');       // create → opens the group
    await setVal(alice, '#msg', 'welcome to the group');
    await jsClick(alice, '#send');
    check(await hasText(alice, '.bubble', 'welcome to the group', 8000), "Alice's group message shows");
    await jsClick(bob, '#back');        // Bob to his list
    check(await hasText(bob, '.item .title', 'Team Mycelium', 25000), "the group appears in Bob's list (joined from the invite)");
    await jsClick(bob, '.item[data-group]');
    check(await hasText(bob, '.bubble', 'welcome to the group', 10000), 'Bob opens the group and sees the decrypted message');

    console.error('• Alice adds a member to the group via the UI');
    await jsClick(alice, '#gmenu');
    await jsClick(alice, '#gadd');
    await setVal(alice, '#amu', 'carol');
    await jsClick(alice, '#amok');
    await jsClick(alice, '#back');
    check(await hasText(alice, '.item .snippet', '3 member', 8000), 'group roster grew to 3 after adding a member');

    console.error('• Alice edits her display name in settings');
    await jsClick(alice, '#settings');
    check(await hasText(alice, 'b', 'alice'), 'settings shows the username');
    await setVal(alice, '#sname', 'Alice Cooper');
    await jsClick(alice, '#ssave');
    check(await hasText(alice, 'header .who', 'Alice Cooper', 8000), 'display name updated in the header');

    console.error('• Alice pairs a second device (seedless offer → approve)');
    // Device B: a fresh browser context joins the account and shows a pairing offer.
    const ctxAB = await browser.createBrowserContext();
    const aliceB = await ctxAB.newPage();
    aliceB.on('dialog', (d) => d.dismiss().catch(() => {}));
    await aliceB.goto(appUrl, { waitUntil: 'domcontentloaded' });
    await aliceB.waitForFunction(() => window.mycellium?.rpc !== undefined, { timeout: 15000, polling: 100 });
    await jsClick(aliceB, '#joininstead');
    await aliceB.waitForSelector('#offer', { timeout: 10000 });
    const offer = await aliceB.evaluate(() => document.getElementById('offer')?.value || '');
    check(offer.length > 40, 'device B produced a pairing offer');
    check(await aliceB.evaluate(() => !!document.querySelector('svg')), 'QR code rendered');
    // Device A approves the offer (seals its account key to it).
    await jsClick(alice, '#settings');
    await jsClick(alice, '#linkdev');
    await alice.waitForSelector('#offer', { timeout: 10000 });
    await alice.evaluate((o) => { document.getElementById('offer').value = o; }, offer);
    await jsClick(alice, '#approve');
    // Device B polls, adopts the account, and signs in as Alice — no seed involved.
    check(await hasText(aliceB, 'header .who', 'Alice', 20000), 'device B signed in as Alice via pairing');
    await jsClick(alice, '#back'); await jsClick(alice, '#back'); // return Alice to the chat list

    console.error('• Web Push wiring (key + subscribe path; live delivery needs a real device)');
    const pushKey = await bob.evaluate(async (q) => { try { return await window.mycellium.rpc('push_key', [q]); } catch (e) { return 'ERR:' + e; } }, qUrl);
    check(typeof pushKey === 'string' && pushKey.length > 20 && !pushKey.startsWith('ERR'), `queue serves the Session a VAPID key (${String(pushKey).slice(0, 14)}…)`);

    console.error('• offline indicator when the servers are unreachable');
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } // take the servers down (must be the last check)
    check(await hasText(alice, '.offline', 'offline', 15000), "Alice's PWA shows 'offline' when its queue is unreachable");
  } finally {
    await browser.close();
    web.close();
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
