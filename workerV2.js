/* WEATH3R Push-Notification Worker — v2
   - fetch(): nimmt Push-Anmeldungen von der App entgegen (POST /subscribe)
   - scheduled(): läuft per Cron alle ~10-15 Min, prüft für jede Anmeldung das
     DWD-Radar (Bright Sky) und verschickt bei Bedarf eine Push-Nachricht.

   ── Änderungen v2 (Audit-Fixes) ────────────────────────────────────────────
   A  Regen-Erkennung scannt jetzt ALLE Radar-Frames von jetzt bis +90 Min und
      meldet den ERSTEN nassen Frame (vorher: nur der eine Frame bei ~70 Min —
      kurze Schauer dazwischen wurden komplett verpasst). Die Vorlaufzeit in
      der Nachricht ist jetzt dynamisch ("Regen in ~35 Minuten").
   B  /subscribe upsertet jetzt per ON CONFLICT und ERHÄLT dabei
      last_notified_at (vorher: INSERT OR REPLACE setzte den Status zurück →
      Doppel-Benachrichtigung möglich, sobald die App den Standort neu synct).
      ⚠ EINMALIG in der D1-Konsole ausführen, falls noch nicht vorhanden:
        CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_endpoint
          ON subscriptions(endpoint);
   C  VAPID_SUBJECT ist jetzt eine echte, erreichbare Adresse (Pflicht bei
      Apple; vorher stand dort der Platzhalter example.com).
   D  Endpoints werden validiert: nur https und nur bekannte Push-Dienste
      (Apple/Google/Mozilla/Microsoft) — sonst könnte man den Worker Daten an
      beliebige fremde Server schicken lassen.
   E  Abo-Obergrenze (MAX_SUBSCRIPTIONS): schützt die D1-Datenbank gegen
      zufälliges Bot-Spam, völlig ausreichend für den privaten Nutzerkreis.
   F  location_name wird serverseitig auf 80 Zeichen gekappt und lat/lon
      werden als Zahlen im gültigen Bereich validiert (ein überlanger Name
      hätte das 4-KB-Limit des verschlüsselten Payloads sprengen können).
   ──────────────────────────────────────────────────────────────────────────
*/

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const WET_MMH = 0.3;            // ab dieser Intensität gilt eine Zelle als "nass" (mm/h)
const LEAD_MAX_MINUTES = 90;    // so weit in die Zukunft wird nach Regen gesucht (Fix A)
const MAX_SUBSCRIPTIONS = 50;   // Obergrenze für Abos (Fix E) — großzügig für ~10 Freunde
const MAX_NAME_LEN = 80;        // Kappung für location_name (Fix F)
// Fix C: echte Kontaktadresse (RFC 8292 erlaubt mailto: oder https:)
const VAPID_SUBJECT = "https://reinhard-buschmann.github.io/weath3r/";
// Fix D: nur echte Push-Dienste als Ziel zulassen
const ALLOWED_PUSH_HOSTS = [
  "push.apple.com",              // Safari/iOS (web.push.apple.com)
  "fcm.googleapis.com",          // Chrome/Android
  "push.services.mozilla.com",   // Firefox (updates.push.services.mozilla.com)
  "notify.windows.com",          // Edge (*.notify.windows.com)
];

// ---------- kleine Helfer ----------
const te = new TextEncoder();

function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function concatBufs(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
async function hmac(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, dataBytes));
}
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}
// Fix D: Endpoint-Validierung
function endpointAllowed(endpoint) {
  let u;
  try { u = new URL(endpoint); } catch (e) { return false; }
  if (u.protocol !== "https:") return false;
  const h = u.hostname;
  return ALLOWED_PUSH_HOSTS.some(host => h === host || h.endsWith("." + host));
}

// ---------- VAPID: signierte Authorization-Header pro Nachricht ----------
async function importVapidKeys(publicKeyB64url, privateKeyB64url) {
  const pubBytes = b64urlDecode(publicKeyB64url);
  const x = pubBytes.slice(1, 33), y = pubBytes.slice(33, 65);
  const jwkPublic = { kty: "EC", crv: "P-256", x: b64urlEncode(x), y: b64urlEncode(y), ext: true };
  const jwkPrivate = { ...jwkPublic, d: privateKeyB64url };
  const privateKey = await crypto.subtle.importKey("jwk", jwkPrivate, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return { privateKey };
}
async function buildVapidAuthHeader(privateKey, publicKeyB64url, endpoint) {
  const audience = new URL(endpoint).origin;
  const header = { typ: "JWT", alg: "ES256" };
  const claims = { aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT };
  const signingInput = b64urlEncode(te.encode(JSON.stringify(header))) + "." + b64urlEncode(te.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, te.encode(signingInput));
  const jwt = signingInput + "." + b64urlEncode(sig);
  return `vapid t=${jwt}, k=${publicKeyB64url}`;
}

// ---------- RFC 8291: Nachricht Ende-zu-Ende verschlüsseln ----------
async function encryptPayload(plaintextObj, subscriberP256dhB64url, subscriberAuthB64url) {
  const plaintext = te.encode(JSON.stringify(plaintextObj));
  const uaPublicBytes = b64urlDecode(subscriberP256dhB64url);
  const authSecret = b64urlDecode(subscriberAuthB64url);

  const asKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", asKeyPair.publicKey));

  const uaX = uaPublicBytes.slice(1, 33), uaY = uaPublicBytes.slice(33, 65);
  const uaPublicKey = await crypto.subtle.importKey("jwk",
    { kty: "EC", crv: "P-256", x: b64urlEncode(uaX), y: b64urlEncode(uaY), ext: true },
    { name: "ECDH", namedCurve: "P-256" }, true, []);

  const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: uaPublicKey }, asKeyPair.privateKey, 256);
  const ecdhSecret = new Uint8Array(sharedBits);

  const prkKey = await hmac(authSecret, ecdhSecret);
  const keyInfo = concatBufs(te.encode("WebPush: info"), new Uint8Array([0]), uaPublicBytes, asPublicRaw);
  const ikm = (await hmac(prkKey, concatBufs(keyInfo, new Uint8Array([1])))).slice(0, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);

  const cekInfo = concatBufs(te.encode("Content-Encoding: aes128gcm"), new Uint8Array([0]));
  const cek = (await hmac(prk, concatBufs(cekInfo, new Uint8Array([1])))).slice(0, 16);

  const nonceInfo = concatBufs(te.encode("Content-Encoding: nonce"), new Uint8Array([0]));
  const nonce = (await hmac(prk, concatBufs(nonceInfo, new Uint8Array([1])))).slice(0, 12);

  const paddedPlaintext = concatBufs(plaintext, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, paddedPlaintext));

  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4096, false);
  const header = concatBufs(salt, recordSize, new Uint8Array([asPublicRaw.length]), asPublicRaw);
  return concatBufs(header, ciphertext);
}

// ---------- eine Push-Nachricht an einen Abonnenten schicken ----------
async function sendPush(env, sub, payloadObj) {
  const { privateKey } = await importVapidKeys(env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
  const body = await encryptPayload(payloadObj, sub.p256dh, sub.auth);
  const authHeader = await buildVapidAuthHeader(privateKey, env.VAPID_PUBLIC_KEY, sub.endpoint);

  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Encoding": "aes128gcm",
      "TTL": "3600",
      "Authorization": authHeader,
    },
    body,
  });
  return res;
}

// ---------- Fix A: Bright Sky Radar — ERSTEN nassen Frame im Fenster finden ----------
async function checkRainAt(lat, lon) {
  const now = new Date();
  const endDate = new Date(now.getTime() + LEAD_MAX_MINUTES * 60000);
  const u = new URL("https://api.brightsky.dev/radar");
  u.searchParams.set("lat", lat);
  u.searchParams.set("lon", lon);
  u.searchParams.set("distance", "5000"); // klein halten, wir brauchen nur den einen Punkt
  u.searchParams.set("format", "plain");
  u.searchParams.set("date", now.toISOString());
  u.searchParams.set("last_date", endDate.toISOString());

  const res = await fetch(u.toString());
  if (!res.ok) throw new Error("Bright Sky radar " + res.status);
  const json = await res.json();
  if (!json || !Array.isArray(json.radar) || !json.radar.length) return null;

  const pos = json.latlon_position || { x: 0, y: 0 };
  const px = Math.max(0, Math.round(pos.x)), py = Math.max(0, Math.round(pos.y));

  // Frames chronologisch scannen — der erste nasse Frame bestimmt die Warnung.
  const frames = json.radar.slice().sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  for (const frame of frames) {
    const leadMin = Math.round((new Date(frame.timestamp).getTime() - now.getTime()) / 60000);
    if (leadMin < 0) continue; // Vergangenheits-Frames überspringen
    let raw = 0;
    try {
      const row = frame.precipitation_5[py] || frame.precipitation_5[0];
      raw = row[px] != null ? row[px] : row[0];
    } catch (e) { raw = 0; }
    const mmh = ((raw || 0) / 100) * 12;
    if (mmh >= WET_MMH) {
      return { wet: true, mmh, frameTime: frame.timestamp, leadMin };
    }
  }
  return { wet: false };
}

// ---------- HTTP: Abo-Endpunkt für die App ----------
async function handleFetch(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }
  const url = new URL(request.url);

  if (request.method === "POST" && url.pathname === "/subscribe") {
    let data;
    try { data = await request.json(); } catch (e) {
      return jsonResponse({ error: "invalid JSON" }, 400);
    }
    const { endpoint, keys } = data || {};
    const lat = Number(data && data.lat), lon = Number(data && data.lon);
    if (!endpoint || !keys || !keys.p256dh || !keys.auth ||
        !Number.isFinite(lat) || !Number.isFinite(lon) ||
        Math.abs(lat) > 90 || Math.abs(lon) > 180) {           // Fix F: Koordinaten validieren
      return jsonResponse({ error: "missing or invalid fields" }, 400);
    }
    if (!endpointAllowed(endpoint)) {                          // Fix D
      return jsonResponse({ error: "endpoint not allowed" }, 400);
    }
    // Fix F: Namen kappen, bevor er in DB und Payload landet
    const locationName = (typeof data.location_name === "string")
      ? data.location_name.slice(0, MAX_NAME_LEN) : null;

    // Fix E: Obergrenze — nur für NEUE Endpoints prüfen (Updates zählen nicht)
    const existing = await env.DB.prepare(
      `SELECT 1 AS x FROM subscriptions WHERE endpoint = ?`
    ).bind(endpoint).first();
    if (!existing) {
      const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM subscriptions`).first();
      if (row && row.n >= MAX_SUBSCRIPTIONS) {
        return jsonResponse({ error: "subscription limit reached" }, 429);
      }
    }

    // Fix B: Upsert, der den Benachrichtigungs-Status ERHÄLT.
    // (Benötigt einen UNIQUE-Index auf endpoint — siehe Kopfkommentar.)
    await env.DB.prepare(
      `INSERT INTO subscriptions (endpoint, p256dh, auth, lat, lon, location_name, last_notified_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, datetime('now'))
       ON CONFLICT(endpoint) DO UPDATE SET
         p256dh = excluded.p256dh,
         auth = excluded.auth,
         lat = excluded.lat,
         lon = excluded.lon,
         location_name = excluded.location_name`
    ).bind(endpoint, keys.p256dh, keys.auth, lat, lon, locationName).run();

    return jsonResponse({ ok: true });
  }

  if (request.method === "POST" && url.pathname === "/unsubscribe") {
    let data;
    try { data = await request.json(); } catch (e) { data = {}; }
    if (data.endpoint) {
      await env.DB.prepare(`DELETE FROM subscriptions WHERE endpoint = ?`).bind(data.endpoint).run();
    }
    return jsonResponse({ ok: true });
  }

  if (request.method === "GET" && url.pathname === "/") {
    return new Response("weath3r-push is running", { headers: CORS_HEADERS });
  }

  return new Response("Not found", { status: 404, headers: CORS_HEADERS });
}

// ---------- Cron: alle Abos durchgehen und ggf. benachrichtigen ----------
async function handleScheduled(env) {
  const { results } = await env.DB.prepare(`SELECT * FROM subscriptions`).all();
  if (!results || !results.length) return;

  for (const sub of results) {
    try {
      const check = await checkRainAt(sub.lat, sub.lon);
      if (!check) continue;

      if (check.wet && !sub.last_notified_at) {
        // steigende Flanke: neue Regen-Warnung auslösen
        // Fix A: dynamische Vorlaufzeit statt fixer "~70 Minuten"
        const lead5 = Math.max(5, Math.round(check.leadMin / 5) * 5);
        const when = new Date(check.frameTime).toLocaleTimeString("de-DE",
          { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Berlin" });
        const payload = {
          title: check.leadMin <= 10 ? "Regen zieht jetzt auf" : `Regen in ~${lead5} Minuten`,
          body: (sub.location_name || "Dein Standort") + ": Regen wird gegen " + when + " erwartet.",
          tag: "rain-alert",
        };
        const res = await sendPush(env, sub, payload);
        if (res.status === 404 || res.status === 410) {
          // Abo ist nicht mehr gültig (z.B. abgemeldet) -> aufräumen
          // (v2: Löschung per endpoint statt id — robust gegen Schema-Varianten)
          await env.DB.prepare(`DELETE FROM subscriptions WHERE endpoint = ?`).bind(sub.endpoint).run();
        } else {
          await env.DB.prepare(`UPDATE subscriptions SET last_notified_at = datetime('now') WHERE endpoint = ?`).bind(sub.endpoint).run();
        }
      } else if (!check.wet && sub.last_notified_at) {
        // fallende Flanke: bereit für die nächste Warnung
        await env.DB.prepare(`UPDATE subscriptions SET last_notified_at = NULL WHERE endpoint = ?`).bind(sub.endpoint).run();
      }
    } catch (e) {
      // ein einzelner fehlgeschlagener Abonnent darf die anderen nicht blockieren
      console.error("subscription check failed", sub.endpoint, e.message);
    }
  }
}

export default {
  async fetch(request, env) { return handleFetch(request, env); },
  async scheduled(event, env, ctx) { ctx.waitUntil(handleScheduled(env)); },
};
