// The Mycellium engine runs here, off the UI thread, so its synchronous network
// (XHR) and crypto never freeze the page. The UI talks to it by RPC: it posts
// {id, op, args}; we run session[op](...args) and post back {id, ok, result}.
// This worker also owns durability (IndexedDB), persisting after any mutation.
import init, * as W from './pkg/mycellium_wasm.js';

const DB = 'mycellium';
const idb = () => new Promise((res, rej) => {
  const r = indexedDB.open(DB, 1);
  r.onupgradeneeded = () => r.result.createObjectStore('state');
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const idbGet = async (key) => {
  const db = await idb();
  return new Promise((res) => { const g = db.transaction('state', 'readonly').objectStore('state').get(key); g.onsuccess = () => res(g.result ?? null); g.onerror = () => res(null); });
};
const idbPut = async (key, val) => {
  const db = await idb();
  return new Promise((res) => { const tx = db.transaction('state', 'readwrite'); tx.objectStore('state').put(val, key); tx.oncomplete = res; tx.onerror = res; });
};

// The snapshot holds the account seed, so it is encrypted at rest with an
// AES-GCM key that is generated once and stored **non-extractable** in
// IndexedDB — the browser keeps the raw key bytes, never JS, so a script can't
// read the seed straight out of the snapshot and it isn't plaintext on disk.
// (Residual limit: a determined attacker with the whole browser profile — see
// docs/SECURITY.md — still needs OS-level disk encryption underneath.)
let keyPromise = null;
const wrapKey = () => {
  if (!keyPromise) keyPromise = (async () => {
    const existing = await idbGet('wrapkey');
    if (existing) return existing;
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await idbPut('wrapkey', key);
    return key;
  })();
  return keyPromise;
};

const load = async () => {
  const snap = await idbGet('snapshot');
  if (!snap) return null;
  // Legacy plaintext snapshot (pre-encryption): use it, then the next save
  // rewrites it encrypted.
  if (snap instanceof ArrayBuffer || snap instanceof Uint8Array) return new Uint8Array(snap);
  if (snap && snap.iv && snap.ct) {
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: snap.iv }, await wrapKey(), snap.ct);
      return new Uint8Array(plain);
    } catch { return null; }
  }
  return null;
};

const save = async (bytes) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await wrapKey(), bytes);
  await idbPut('snapshot', { iv, ct });
};

// Allowlist of engine ops reachable over RPC — a stray postMessage (or injected
// script) can't call arbitrary Session methods, only these. READS don't mutate
// (no persist afterwards); WRITES do. `export`/`import` are intentionally absent:
// nothing calls them over RPC (save() uses session.export() directly), and they
// dump/replace the whole store (seed included), so they stay off the wire.
const READS = new Set(['peers', 'groups', 'thread', 'group_thread', 'wallet', 'file', 'name_of', 'get', 'push_key', 'link_payload', 'qr_svg', 'version']);
const WRITES = new Set(['register', 'send', 'reply', 'react', 'delete_message', 'send_file', 'sync', 'group_create', 'group_send', 'group_add', 'group_leave', 'link_device', 'push_subscribe', 'put', 'del', 'add_message']);

let session = null;
const ready = (async () => {
  try {
    await init();
    const snap = await load();
    session = snap ? W.Session.restore(new Uint8Array(snap)) : new W.Session();
    if (!snap) await save(session.export());
  } catch (e) {
    // Surface a clear reason (WASM load or IndexedDB failure) rather than letting
    // every RPC reject cryptically.
    throw new Error('engine failed to start: ' + ((e && e.message) || e));
  }
})();

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    await ready;
    if (!READS.has(op) && !WRITES.has(op)) {
      self.postMessage({ id, ok: false, err: `unknown op: ${op}` });
      return;
    }
    const result = session[op](...(args || []));
    if (WRITES.has(op)) await save(session.export());
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, err: String((err && err.message) || err) });
  }
};
