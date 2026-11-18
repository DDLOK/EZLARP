// EZLARP offline support. Network first (so a new version always wins when online),
// falling back to the last copy when offline. Files you scan are never stored here.
const CACHE = 'ezlarp-shell-v3';
const SHELL = ['/', '/style.css', '/app.js', '/ui.js', '/inspect.js', '/jview.js', '/scan.js', '/compare.js', '/cil.js', '/x86.js', '/native.js',
  '/vendor/jszip.min.js', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/favicon-32.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const same = url.origin === self.location.origin;
  const cdn = url.hostname === 'cdnjs.cloudflare.com';
  // skip the link downloader, big decompiler jars and the Java runtime
  if ((!same && !cdn) || url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/') || url.pathname.endsWith('.jar')) return;
  e.respondWith(fetch(req).then(res => {
    if (res.ok && (res.type === 'basic' || res.type === 'cors')) {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(req.mode === 'navigate' ? '/' : req, copy)).catch(() => {});
    }
    return res;
  }).catch(() => caches.match(req.mode === 'navigate' ? '/' : req, { ignoreSearch: req.mode === 'navigate' }).then(r => r || Response.error())));
});
