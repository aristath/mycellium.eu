// HTTP body-size limits: an oversized body sent with **chunked** transfer
// encoding (no Content-Length, so the server can't fast-path on the header) must
// be rejected with 413, not truncated to the cap and processed. Node's http
// client uses chunked encoding whenever you write a body without a length.
//
// Run:  node clients/rust/e2e/http-limits.test.mjs   (build: cargo build)

import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const BIN = (n) => path.join(ROOT, 'target/debug', n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const procs = [];
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
function serviceConfig(name, config) { const file = path.join(ROOT, 'target', name + '-' + config.addr.split(':').pop() + '.json'); fs.writeFileSync(file, JSON.stringify(config)); return file; }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }

let failed = false;
const check = (c, m) => { console.error((c ? '  ✓ ' : '  ✗ ') + m); if (!c) failed = true; };

// A chunked request (Node sends Transfer-Encoding: chunked when no length is set).
function chunked(port, method, pathname, body) {
  return new Promise((res, rej) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method, headers: { 'Content-Type': 'application/json' } }, (r) => { r.resume(); res(r.statusCode); });
    req.on('error', rej);
    req.write(body);
    req.end();
  });
}

async function main() {
  for (const b of ['mycellium-server', 'mycellium-queue']) if (!fs.existsSync(BIN(b))) throw new Error('run: cargo build');
  const [dirPort, qPort] = await Promise.all([freePort(), freePort()]);
  procs.push(spawn(BIN('mycellium-server'), ['--config', serviceConfig('directory', { addr: `127.0.0.1:${dirPort}`, dev_auth: true })], { stdio: 'ignore' }));
  procs.push(spawn(BIN('mycellium-queue'), ['--config', serviceConfig('queue', { addr: `127.0.0.1:${qPort}` })], { stdio: 'ignore' }));
  await Promise.all([waitHttp(`http://127.0.0.1:${dirPort}/health`), waitHttp(`http://127.0.0.1:${qPort}/health`)]);

  const big = Buffer.alloc(300 * 1024, 0x61); // > directory cap (256 KiB)
  const huge = Buffer.alloc(1100 * 1024, 0x61); // > queue cap (1 MiB)

  console.error('• oversized chunked bodies are rejected (not truncated)');
  check((await chunked(dirPort, 'PUT', '/records/x', big)) === 413, 'directory rejects an oversized chunked body with 413');
  check((await chunked(qPort, 'POST', '/login/challenge', huge)) === 413, 'queue rejects an oversized chunked body with 413');

  console.error('• a small chunked body is not size-rejected (routes normally)');
  const s = await chunked(dirPort, 'POST', '/login/challenge', Buffer.from('{}'));
  check(s !== 413, `a small chunked body is accepted for size (status ${s})`);
}

main()
  .then(() => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
