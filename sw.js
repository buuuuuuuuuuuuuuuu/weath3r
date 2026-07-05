/* WEATH3R service worker — v7.2
   - offline shell + last-data cache
   - immediate activation, then notifies open clients of updates
   ← bump CACHE on every deploy (matches APP_VERSION) */
const CACHE = "weath3r-v16.2";
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

// Incoming Web Push message (sent by the weath3r-push Cloudflare Worker) →
// show a native notification. Falls back gracefully if the payload isn't JSON.
self.addEventListener("push", e=>{
  let data = { title:"WEATH3R", body:"Regen könnte bald eintreffen." };
  try{ if(e.data) data = e.data.json(); }catch(err){
    try{ if(e.data) data.body = e.data.text(); }catch(err2){}
  }
  const title = data.title || "WEATH3R";
  const options = {
    body: data.body || "",
    icon: "./icon-192.png",
    badge: "./icon-192.png",
    tag: data.tag || "weath3r-rain-alert",
    renotify: true,
    data: { url: "./" },
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

// Tapping the notification focuses an already-open tab, or opens a new one.
self.addEventListener("notificationclick", e=>{
  e.notification.close();
  const targetUrl = (e.notification.data && e.notification.data.url) || "./";
  e.waitUntil(
    self.clients.matchAll({ type:"window", includeUncontrolled:true }).then(list=>{
      for(const c of list){ if("focus" in c) return c.focus(); }
      if(self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});
