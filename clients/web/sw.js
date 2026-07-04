// Minimal app-shell cache so Mycellium opens offline. Network-first for the
// WASM/JS bundle (so updates land), cache fallback when offline.
const CACHE = 'mycellium-shell-v2';
const SHELL = ['./', './index.html', './manifest.json', './icon.svg',
  './pkg/mycellium_wasm.js', './pkg/mycellium_wasm_bg.wasm'];

self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))); self.clients.claim(); });
// Contentless wake from the queue → show a generic notification (the message
// itself is fetched + decrypted in-app; the server never sees it).
self.addEventListener('push', (e) => {
  e.waitUntil(self.registration.showNotification('Mycellium', { body: 'New message', tag: 'mycellium-push', icon: './icon.svg' }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window' }).then((cs) => (cs[0] ? cs[0].focus() : self.clients.openWindow('./'))));
});

// Absolute URLs of the shell assets (+ the generated pkg/ dir), so the fetch
// handler only ever touches the app shell — never the API or other requests.
const SHELL_SET = new Set(SHELL.map((p) => new URL(p, self.registration.scope).href));
const PKG_PREFIX = new URL('./pkg/', self.registration.scope).href;

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  // Never intercept cross-origin traffic (the directory/queue API lives on other
  // origins) — let the browser handle it directly, uncached.
  if (url.origin !== self.location.origin) return;

  // App loads: network-first, falling back to the cached shell when offline.
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(() => caches.match('./index.html')));
    return;
  }

  // Shell assets (index/manifest/icon + pkg/*): network-first so updates land,
  // caching only same-origin basic responses; cache fallback when offline.
  if (SHELL_SET.has(url.href) || url.href.startsWith(PKG_PREFIX)) {
    e.respondWith(
      fetch(e.request)
        .then((r) => {
          if (r.ok && r.type === 'basic') {
            const cp = r.clone();
            caches.open(CACHE).then((c) => c.put(e.request, cp)).catch(() => {});
          }
          return r;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Any other same-origin GET: straight to the network, no caching, and no
  // index.html fallback (so a stray asset request never gets served the app HTML).
});
