/* WEATH3R service worker — offline shell + last-data cache */
const CACHE = "weath3r-v2";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png"
];

// Install: pre-cache the app shell
self.addEventListener("install", e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()));
});

// Activate: clean up old caches
self.addEventListener("activate", e=>{
  e.waitUntil(
    caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
  );
});

// Fetch strategy:
//  - App shell (same-origin): cache-first, fall back to network.
//  - API calls (open-meteo etc.): network-first, fall back to nothing
//    (the app has its own localStorage data cache for weather).
self.addEventListener("fetch", e=>{
  const url=new URL(e.request.url);
  const sameOrigin = url.origin===self.location.origin;

  if(sameOrigin){
    e.respondWith(
      caches.match(e.request).then(hit=> hit || fetch(e.request).then(res=>{
        // runtime-cache successful same-origin GETs
        if(e.request.method==="GET" && res.ok){
          const copy=res.clone();
          caches.open(CACHE).then(c=>c.put(e.request, copy));
        }
        return res;
      }).catch(()=>caches.match("./index.html")))
    );
  }
  // cross-origin (API): let the network handle it; app caches data itself
});
