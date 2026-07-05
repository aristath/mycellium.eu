// Multi-device: a second in-browser device adopts an account via the **seedless
// pairing** flow (new device offers, existing device approves, no seed anywhere),
// and a message to the account then fans out to BOTH devices.

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
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const procs = [];
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

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

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${webPort}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.Session !== undefined, { timeout: 15000, polling: 100 });

    console.error('• device B pairs into Alice (seedless); a message reaches both devices');
    const r = await page.evaluate((dir, q) => {
      try {
        const S = window.mycellium.Session;
        const a = new S(), b = new S(), carol = new S();
        a.register(dir, q, 'alice', 'Alice');
        carol.register(dir, q, 'carol', 'Carol');

        // Seedless pairing: B (a fresh device) makes a one-time offer, A approves
        // it (sealing the account key to it), B polls and adopts the account.
        const offer = b.pair_offer(q);
        a.pair_approve(offer, 'alice', dir);
        let cfg = null;
        for (let i = 0; i < 5 && !cfg; i++) {
          const res = b.pair_poll(q);
          if (res) cfg = JSON.parse(res);
        }

        carol.send(dir, 'carol', 'Carol', q, 'alice', 'hi alice on all devices');
        a.sync(q); b.sync(q);

        // Device A re-registers (e.g. renames itself). This must NOT drop device B
        // from the record — a later message must still reach both devices.
        a.register(dir, q, 'alice', 'Alice Renamed');
        carol.send(dir, 'carol', 'Carol', q, 'alice', 'still on both after rename');
        a.sync(q); b.sync(q);

        return {
          paired: !!cfg && cfg.handle === 'alice',
          offerLen: offer.length,
          walletA: a.wallet(), walletB: b.wallet(),
          threadA: JSON.parse(a.thread('carol')).map((m) => m.text),
          threadB: JSON.parse(b.thread('carol')).map((m) => m.text),
        };
      } catch (e) { return { error: String(e) }; }
    }, dirUrl, qUrl);

    check(!r.error, `no error (${r.error || 'ok'})`);
    check(r.offerLen > 40, 'pairing offer generated');
    check(r.paired, 'device B adopted the account via pairing');
    check(r.walletA === r.walletB, 'both devices share the account wallet (adopted, no seed)');
    check(r.threadA.includes('hi alice on all devices'), "device A received the message");
    check(r.threadB.includes('hi alice on all devices'), "device B received the message (multi-device fan-out)");
    check(r.threadB.includes('still on both after rename'), "device B still reachable after A re-registered (no device drop)");
  } finally {
    await browser.close();
    web.close();
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
