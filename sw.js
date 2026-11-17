/* Service Worker: App-Dateien offline verfügbar machen. CVE-APIs werden nicht gecacht. */
const CACHE = 'otrisk-v6';
const ASSETS = ['./', 'index.html', 'anleitung.html', 'rechtliches.html', 'css/styles.css', 'js/risk.js', 'js/mitigations.js', 'js/api.js', 'js/local.js', 'js/cyclonedx.js', 'js/demo.js', 'js/app.js', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-180.png', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith('otrisk-v') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || e.request.method !== 'GET') return;
  if (url.pathname.includes('/api/')) return; // lokaler Helfer: nie cachen
  // Network first, damit Updates sofort ankommen; offline aus dem Cache
  e.respondWith(
    fetch(e.request, { cache: 'no-cache' }).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); return r; })
      .catch(() => caches.match(e.request).then(r => r || caches.match('index.html')))
  );
});
