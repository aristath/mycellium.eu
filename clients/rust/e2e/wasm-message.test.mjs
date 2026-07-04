// Stage-3b (networked): a complete message delivered browser → servers →
// browser. Two in-browser WASM Sessions register with a real directory + queue,
// one sends a message to the other by handle, the other syncs its queue and
// decrypts it. The entire client — identity, record publish, X3DH seal, queue
// deposit/collect, decrypt, history — runs in the browser; the servers only
// move opaque sealed blobs.
//
// Run:  node clients/rust/e2e/wasm-message.test.mjs  (build: clients/web/build.sh + cargo build)

import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

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
  const dirUrl = `http://127.0.0.1:${dirPort}`;
  const qUrl = `http://127.0.0.1:${qPort}`;
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
    executablePath: '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${webPort}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.Session !== undefined, { timeout: 15000 });

    console.error('• two browser identities register, one messages the other through real servers');
    const r = await page.evaluate((dir, q) => {
      try {
        const S = window.mycellium.Session;
        const alice = new S();
        const bob = new S();
        alice.register(dir, q, 'alice', 'Alice');
        bob.register(dir, q, 'bob', 'Bob');
        const delivered = alice.send(dir, 'alice', 'Alice', q, 'bob', 'hello bob, from alice 🍄');
        const received = bob.sync(q);
        return {
          delivered, received,
          bobThread: JSON.parse(bob.thread('alice')),
          aliceThread: JSON.parse(alice.thread('bob')),
        };
      } catch (e) { return { error: String(e) }; }
    }, dirUrl, qUrl);

    check(!r.error, `no error (${r.error || 'ok'})`);
    check(r.delivered === 1, `sender delivered to 1 device (got ${r.delivered})`);
    check(r.received === 1, `recipient synced 1 new message (got ${r.received})`);
    check(r.bobThread?.length === 1 && r.bobThread[0].text === 'hello bob, from alice 🍄', 'recipient decrypted the exact plaintext');
    check(r.bobThread?.[0]?.from_me === false, 'recipient sees it as incoming');
    check(r.aliceThread?.length === 1 && r.aliceThread[0].from_me === true, "sender kept its own copy in history");
  } finally {
    await browser.close();
    web.close();
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
