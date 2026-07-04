// Group messaging in the browser: two WASM Sessions register with a real
// directory + queue; one creates a group (distributing its sender key as sealed
// invites), sends a group message (encrypted with the group sender key), and the
// other syncs — processing the invite, then decrypting the message. All group
// crypto (sender keys + the group ratchet) runs in the browser.
//
// Run:  node clients/rust/e2e/wasm-group.test.mjs   (build: clients/web/build.sh + cargo build)

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
    executablePath: '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${webPort}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.Session !== undefined, { timeout: 15000 });

    console.error('• group create, bidirectional messaging (the sender-key mesh), and add-member');
    const r = await page.evaluate((dir, q) => {
      try {
        const S = window.mycellium.Session;
        const alice = new S(), bob = new S(), carol = new S();
        alice.register(dir, q, 'alice', 'Alice');
        bob.register(dir, q, 'bob', 'Bob');
        carol.register(dir, q, 'carol', 'Carol');
        const settle = (who) => { for (let i = 0; i < 3; i++) who.forEach((s) => s.sync(q)); };

        const gid = alice.group_create(dir, 'alice', 'Alice', q, 'Team Mycelium', JSON.stringify(['bob']));
        alice.group_send(dir, 'alice', 'Alice', q, gid, 'hello team! 🍄');
        settle([bob, alice]); // bob joins + reciprocates its key; alice learns bob's key

        // Mesh check: Bob sends, Alice (a different member) must decrypt.
        bob.group_send(dir, 'bob', 'Bob', q, gid, 'hi from bob');
        settle([alice]);

        // Add Carol, let the roster + keys propagate, then message the group.
        alice.group_add(dir, 'alice', 'Alice', q, gid, 'carol');
        settle([carol, bob, alice]);
        alice.group_send(dir, 'alice', 'Alice', q, gid, 'welcome carol');
        settle([carol]);

        return {
          gid,
          bobGroups: JSON.parse(bob.groups()),
          bobThread: JSON.parse(bob.group_thread(gid)),
          aliceThread: JSON.parse(alice.group_thread(gid)),
          carolGroups: JSON.parse(carol.groups()),
          carolThread: JSON.parse(carol.group_thread(gid)),
        };
      } catch (e) { return { error: String(e) }; }
    }, dirUrl, qUrl);

    const texts = (t) => (t || []).map((m) => m.text);
    check(!r.error, `no error (${r.error || 'ok'})`);
    check(typeof r.gid === 'string' && r.gid.length > 0, `group created (id ${r.gid})`);
    check(r.bobGroups?.some((g) => g.name === 'Team Mycelium'), 'Bob joined the group from the invite');
    check(texts(r.bobThread).includes('hello team! 🍄'), "Bob decrypted Alice's group message");
    check(texts(r.aliceThread).includes('hi from bob'), "Alice decrypted Bob's message (sender-key mesh works both ways)");
    check(r.carolGroups?.some((g) => g.name === 'Team Mycelium'), 'Carol was added and joined the group');
    check(texts(r.carolThread).includes('welcome carol'), 'Carol decrypted a message sent after she joined');
  } finally {
    await browser.close();
    web.close();
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
