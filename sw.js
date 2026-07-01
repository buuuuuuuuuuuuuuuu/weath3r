/* WEATH3R service worker — v7.2
   - offline shell + last-data cache
   - immediate activation, then notifies open clients of updates
   ← bump CACHE on every deploy (matches APP_VERSION) */
const CACHE = "weath3r-v8.1";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png"
];

// Install: pre-cache the app shell, then take over immediately.
self.addEventListener("install", e=>{
  e.waitUntil(
    caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting())
  );
});

// Activate: drop old caches, claim clients, then tell every open window
// that a new version is live so it can offer a refresh.
self.addEventListener("activate", e=>{
  e.waitUntil(
    caches.keys()
      .then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
      .then(()=>self.clients.matchAll({ type:"window" }))
      .then(clients=>clients.forEach(c=>c.postMessage({ type:"SW_UPDATED" })))
  );
});

// Fetch strategy:
//   - same-origin (app shell): cache-first, fall back to network (and runtime-
//     cache successful GETs); offline navigations fall back to index.html.
//   - cross-origin (Open-Meteo / Bright Sky APIs): network-only; the app keeps
//     its own localStorage data cache.
self.addEventListener("fetch", e=>{
  const url=new URL(e.request.url);
  const sameOrigin = url.origin===self.location.origin;

  if(sameOrigin){
    e.respondWith(
      caches.match(e.request).then(hit=> hit || fetch(e.request).then(res=>{
        if(e.request.method==="GET" && res.ok){
          const copy=res.clone();
          caches.open(CACHE).then(c=>c.put(e.request, copy));
        }
        return res;
      }).catch(()=>caches.match("./index.html")))
    );
  }
  // cross-origin: let the network handle it; no caching of API calls
});
