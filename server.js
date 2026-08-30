const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const { URL } = require('url');
const zlib = require('zlib');
const crypto = require('crypto');

const animexScraper = require('./animex');

// ========================
// CONFIGURATION
// ========================
const PORT = process.env.PORT || 3000;
const ROOT = process.cwd();
const PUBLIC_DIR = path.join(ROOT, 'public');
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

// Optional access protection: if ACCESS_TOKEN is set, every page/API requires
// it (as ?token=..., Authorization: Bearer, or by logging in at /login which
// sets a cookie). Leave unset for a fully open site.
const ACCESS_TOKEN = process.env.ACCESS_TOKEN || '';

// Miruro scraping config
const MIRURO_BASE = 'https://www.miruro.to';
const MIRURO_PIPE_URL = `${MIRURO_BASE}/api/secure/pipe`;
const ANILIST_GRAPHQL = 'https://graphql.anilist.co';
const ANIMEX_GRAPHQL = 'https://graphql.animex.one';
const MIRURO_HEADERS = {
  'User-Agent': USER_AGENT,
  'Referer': `${MIRURO_BASE}/`,
  'Origin': MIRURO_BASE,
  'Accept': '*/*',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'sec-fetch-site': 'same-origin',
  'sec-fetch-mode': 'cors',
  'sec-fetch-dest': 'empty',
  'sec-ch-ua': '"Chromium";v="130", "Not A(Brand";v="24", "Google Chrome";v="130"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
};

// Rate limiting config
const RATE_LIMIT_WINDOW = 60_000; // 1 minute
const FREE_TIER_MODE = !!(process.env.RENDER || process.env.RENDER_SERVICE_ID || process.env.FREE_TIER === '1');
const RATE_LIMIT_MAX = FREE_TIER_MODE ? 60 : 120; // max requests per window per IP

// ========================
// MIME TYPES
// ========================
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.xml': 'application/xml',
  '.txt': 'text/plain',
  '.map': 'application/json',
};

// ========================
// RATE LIMITER
// ========================
const rateLimitStore = new Map();

function pruneCache(map, maxEntries) {
  if (!map || !(map instanceof Map) || map.size <= maxEntries) return;
  const overflow = map.size - maxEntries;
  for (const [key] of [...map.entries()].slice(0, overflow)) {
    map.delete(key);
  }
}

function rateLimit(ip) {
  const now = Date.now();
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return true;
  }

  const entry = rateLimitStore.get(ip);
  if (now - entry.windowStart > RATE_LIMIT_WINDOW) {
    entry.count = 1;
    entry.windowStart = now;
    return true;
  }

  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitStore.entries()) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW * 2) {
      rateLimitStore.delete(ip);
    }
  }
}, 300_000);

// ========================
// LOGGING
// ========================
function log(method, pathname, status, extra = '') {
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const statusColor = status >= 200 && status < 300 ? '\x1b[32m' :
                      status >= 300 && status < 400 ? '\x1b[36m' :
                      status >= 400 && status < 500 ? '\x1b[33m' :
                      '\x1b[31m';
  console.log(
    `\x1b[90m${timestamp}\x1b[0m ` +
    `\x1b[35m${method.padEnd(6)}\x1b[0m ` +
    `${statusColor}${status}\x1b[0m ` +
    `${pathname.substring(0, 120)}` +
    (extra ? ` \x1b[90m${extra}\x1b[0m` : '')
  );
}

// ========================
// HELPERS
// ========================
function getMimeType(filePath) {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
}

// Block proxies from being used to reach internal/private networks (SSRF).
// Without this, anyone could make the server fetch 127.0.0.1, 192.168.x.x,
// or cloud metadata endpoints (e.g. 169.254.169.254).
function isPrivateHost(hostname) {
  const h = (hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h === 'metadata.google.internal') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    const [a, b] = h.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  return false;
}

function isAllowedProxyTarget(target) {
  try {
    const parsed = new URL(target);
    return (
      ['https:', 'http:'].includes(parsed.protocol) &&
      !isPrivateHost(parsed.hostname)
    );
  } catch {
    return false;
  }
}

// MIME types that are already compressed and gain nothing (and waste CPU/RAM)
// from a second gzip pass: lossy/lossless image containers, video, icons.
const NO_COMPRESS_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm', '.ico', '.mp3',
]);

function shouldCompress(res, req, ext) {
  if (ext && NO_COMPRESS_EXTS.has(ext)) return false;
  const accept = req.headers['accept-encoding'] || '';
  return (
    accept.includes('gzip') &&
    !res.headersSent &&
    typeof res._compressed === 'undefined'
  );
}

function applyCorsHeaders(res, req) {
  const origin = req?.headers?.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.setHeader('Access-Control-Max-Age', '86400');
}

async function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function accessGranted(req, reqUrl) {
  if (reqUrl.pathname === '/health' || reqUrl.pathname === '/api/health') return true;
  if (reqUrl.searchParams.get('token') === ACCESS_TOKEN) return true;
  if ((req.headers['authorization'] || '') === 'Bearer ' + ACCESS_TOKEN) return true;
  const cookie = req.headers['cookie'] || '';
  return cookie.split(';').some((c) => c.trim() === `access_token=${ACCESS_TOKEN}`);
}

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>body{background:#0f1620;color:#e8edf3;font-family:Segoe UI,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}form{background:#182230;padding:32px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.4);width:300px}input{width:100%;box-sizing:border-box;padding:12px;border-radius:8px;border:1px solid #2c3a4d;background:#0f1620;color:#fff;margin:8px 0 16px}button{width:100%;padding:12px;border:0;border-radius:8px;background:#4f7cff;color:#fff;font-size:15px;cursor:pointer}h1{font-size:18px;margin:0 0 4px}</style>
</head><body><form method="post" action="/login">
<h1>Private access</h1><p style="color:#9fb0c4;font-size:13px;margin:0 0 12px">Enter the access token to continue.</p>
<input type="password" name="token" placeholder="Access token" autofocus required/>
<button type="submit">Sign in</button></form></body></html>`;

// ========================
// MIRURO SCRAPER
// Miruro's frontend talks to its backend through /api/secure/pipe.
// Requests are sent as ?e=<base64url(json)>; responses come back as
// base64url(gzip(json)). No real encryption, just encoding.
// NOTE: the pipe is behind Cloudflare and only answers requests that carry
// a real Chrome TLS fingerprint (see MIRURO_HEADERS). Node's fetch may be
// answered with HTTP 403; hosting behind a browser-like fetcher (curl_cffi,
// Playwright) resolves this.
// ========================

function b64urlEncode(str) {
  return Buffer.from(str, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64');
}

// Translate base64-wrapped episode ids (e.g. "YW5pbWVwYWhlOjE=" -> "animepahe:1")
function translateId(encodedId) {
  try {
    const decoded = b64urlDecode(encodedId).toString('utf8');
    return decoded.includes(':') ? decoded : encodedId;
  } catch {
    return encodedId;
  }
}

function deepTranslateId(obj) {
  if (Array.isArray(obj)) {
    obj.forEach(deepTranslateId);
  } else if (obj && typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      const value = obj[key];
      if (key === 'id' && typeof value === 'string') {
        obj[key] = translateId(value);
      } else if (value && typeof value === 'object') {
        deepTranslateId(value);
      }
    }
  }
  return obj;
}

const MIRURO_SIDECAR_URL = (process.env.MIRURO_SIDECAR_URL || 'http://127.0.0.1:8765').replace(/\/+$/, '');
const MIRURO_PROXY_BASE = process.env.MIRURO_PROXY_BASE || 'https://s1.watami.win/';
const MIRURO_OBF_KEY = Buffer.from(process.env.MIRURO_OBF_KEY || 'a54d389c18527d9fd3e7f0643e27edbe', 'hex');
// Response obfuscation key for the pipe (`VITE_PIPE_OBF_KEY` from /env2.js).
// Miruro now XOR-obfuscates pipe responses when they carry `x-obfuscated: 2`.
const MIRURO_PIPE_OBF_KEY = Buffer.from(process.env.MIRURO_PIPE_OBF_KEY || '71951034f8fbcf53d89db52ceb3dc22c', 'hex');
// Default pipe protocol version. Overridden by /api/secure/jwks when reachable.
const MIRURO_PROTOCOL_VERSION = process.env.MIRURO_PROTOCOL_VERSION || '0.2.0';

// Decode a pipe response. Miruro returns:
//  - plain JSON (no `x-obfuscated` header)
//  - base64url(gzip(json)) when `x-obfuscated` is set but not "2"
//  - base64url(XOR(gzip(json))) when `x-obfuscated: 2` (key = MIRURO_PIPE_OBF_KEY)
function miruroDecodePipe(body, xObfuscated) {
  if (!xObfuscated) return JSON.parse(body);
  const compressed = b64urlDecode(body.trim());
  let data = Buffer.from(compressed);
  if (xObfuscated === '2') {
    for (let i = 0; i < data.length; i++) {
      data[i] ^= MIRURO_PIPE_OBF_KEY[i % MIRURO_PIPE_OBF_KEY.length];
    }
  }
  const json = zlib.gunzipSync(data).toString('utf8');
  return JSON.parse(json);
}

// The pipe envelope carries the server's current protocol version
// (`x-protocol-version` / `version` from /api/secure/jwks). Version is baked
// into the reply envelope, so it must match what miruro's backend expects or
// it answers "Invalid envelope format". Cached for 10 minutes.
const miruroProtocolVersionCache = { value: MIRURO_PROTOCOL_VERSION, at: 0 };
async function miruroProtocolVersion() {
  if (Date.now() - miruroProtocolVersionCache.at < 10 * 60 * 1000) {
    return miruroProtocolVersionCache.value;
  }
  try {
    const sidecar = await fetch(`${MIRURO_SIDECAR_URL}/jwks`, { signal: AbortSignal.timeout(6000) });
    const result = await sidecar.json();
    const version = result && (result.version || (result.body && JSON.parse(result.body).version));
    if (version) {
      miruroProtocolVersionCache.value = version;
      miruroProtocolVersionCache.at = Date.now();
      return version;
    }
  } catch { /* keep the configured/default version */ }
  miruroProtocolVersionCache.at = Date.now();
  return miruroProtocolVersionCache.value;
}

// Route the pipe request through the local Python (curl_cffi) sidecar, which
// carries a real Chrome TLS fingerprint. Falls back to Node fetch so the
// server still works standalone (that path will 403 behind Cloudflare).
async function miruroPipeRequest(payload) {
  const version = await miruroProtocolVersion();
  const encoded = b64urlEncode(JSON.stringify({ ...payload, version: version || undefined }));

  try {
    const sidecar = await fetch(`${MIRURO_SIDECAR_URL}/pipe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ e: encoded }),
      signal: AbortSignal.timeout(18000),
    });
    const result = await sidecar.json();

    if (result.status === 200 && result.body) {
      return miruroDecodePipe(result.body, result.x_obfuscated);
    }
    if (result.status) {
      // The pipe often answers with HTML error pages (e.g. nginx "502 upstream
      // unreachable", Cloudflare challenge pages). Extract a readable reason
      // instead of dumping raw markup into the UI.
      const raw = String(result.body || result.error || '').trim();
      const title = raw.match(/<title>([^<]+)<\/title>/i);
      let clean = title ? title[1] : raw.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      if (!clean) clean = 'unknown error';
      throw new Error(`Miruro pipe error (${result.status}): ${clean.slice(0, 140)}`);
    }
    throw new Error(`Miruro sidecar error: ${result.error || 'unknown'}`);
  } catch (err) {
    if (err.message.startsWith('Miruro pipe error') || err.message.startsWith('Miruro sidecar error')) {
      throw err;
    }
    // sidecar unreachable — fall back to direct fetch
  }

  const response = await fetch(`${MIRURO_PIPE_URL}?e=${encoded}`, {
    headers: MIRURO_HEADERS,
    redirect: 'follow',
    signal: AbortSignal.timeout(25000),
  });

  if (response.status !== 200) {
    const body = await response.text().catch(() => '');
    if (response.status === 403 || body.toLowerCase().includes('cloudflare')) {
      throw new Error('Miruro pipe is blocked by Cloudflare (403). Needs the curl_cffi sidecar (miruro_sidecar.py).');
    }
    throw new Error(`Miruro pipe error (${response.status}): ${body.slice(0, 160)}`);
  }

  return miruroDecodePipe(await response.text(), response.headers.get('x-obfuscated') || undefined);
}

// XOR-obfuscate a URL with the player key, base64url-encoded (miruro's `xr`).
function miruroObfuscate(str) {
  const input = Buffer.from(str, 'utf8');
  const out = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i++) {
    out[i] = input[i] ^ MIRURO_OBF_KEY[i % MIRURO_OBF_KEY.length];
  }
  return out.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Build the playable proxy URL in the same format the miruro player uses:
//   {proxy}/{obf(hlsUrl)}~{obf(referer)}/pl.m3u8
// s1.watami.win serves the playlist + segments with Access-Control-Allow-Origin: *,
// so the browser's hls.js can load it directly (no server-side streaming proxy).
function buildMiruroPlayableUrl(hlsUrl, referer) {
  return MIRURO_PROXY_BASE + miruroObfuscate(hlsUrl) + '~' + miruroObfuscate(referer || 'https://kwik.cx/') + '/pl.m3u8';
}

function miruroEmbedOrigin(sources) {
  const embed = (sources.streams || []).find((s) => s.type === 'embed' && s.url);
  if (!embed) return 'https://kwik.cx/';
  try {
    const parsed = new URL(embed.url);
    return `${parsed.origin}/`;
  } catch {
    return 'https://kwik.cx/';
  }
}

// Cache the full episode/provider tree per anime for a while. The same data is
// needed by /api/miruro/episodes, /servers, /stream and /embeds, and every
// uncached fetch is a rate-limited pipe call — caching slashes redundant hits
// and keeps us well under miruro's 120 req/min throttle.
const miruroEpisodesCache = new Map();
const MIRURO_EPISODES_TTL = 15 * 60 * 1000;

async function miruroFetchEpisodes(anilistId) {
  const key = Number(anilistId);
  if (miruroEpisodesCache.has(key)) return miruroEpisodesCache.get(key);
  const data = await miruroPipeRequest({
    path: 'episodes',
    method: 'GET',
    query: { anilistId: key },
    body: null,
  });
  const result = deepTranslateId(data);
  miruroEpisodesCache.set(key, result);
  pruneCache(miruroEpisodesCache, 128);
  setTimeout(() => miruroEpisodesCache.delete(key), MIRURO_EPISODES_TTL);
  return result;
}

async function miruroFetchSources(anilistId, provider, category, episodeId) {
  const payload = {
    path: 'sources',
    method: 'GET',
    query: {
      episodeId: b64urlEncode(episodeId),
      provider,
      category,
      anilistId: Number(anilistId),
    },
    body: null,
  };
  return miruroPipeRequest(payload);
}

// Collect every embed server (kwik, vidtube, anidb, animegg, ...) across all
// providers for an episode, deduplicated by URL. Runs the per-provider source
// fetches in parallel; caches the result for 10 minutes.
const miruroEmbedsCache = new Map();

// Embed hosts that can be resolved to a real HLS stream server-side:
//  - kotocdn-family (vidtube.site, megaplay.buzz) expose a #megaplay-player
//    data-id that resolves via /stream/getSourcesNew.
//  - vivibebe.site and krussdomi.com declare their m3u8 directly in the embed
//    page markup/JSON, so they play without the miruro pipe at all.
//  - vidplay.* hosts resolve through their /api/source/{id} endpoint.
const VIDPLAY_HOSTS = ['vidplay.online', 'vidplay.site', 'vidplay.lol', 'vidplay.net', 'vidplay.pro', 'vidplay.io', 'vidplay.cc', 'vidplay.events'];
const EMBED_HLS_HOSTS = ['vidtube.site', 'megaplay.buzz', 'vivibebe.site', 'krussdomi.com', ...VIDPLAY_HOSTS];

// Retry a flaky miruro pipe call (the sources endpoint is rate-limited and
// intermittently returns 444/upstream-unreachable from a cold IP). The Render
// free tier is memory/CPU constrained, so keep retries short and low-volume.
const MIRURO_RETRY_BACKOFF = FREE_TIER_MODE ? 250 : 800;
const MIRURO_EMBED_TIMEOUT = FREE_TIER_MODE ? 5000 : 18000;
const MIRURO_PROVIDER_CAP = FREE_TIER_MODE ? 2 : 4;

async function miruroWithRetry(fn, attempts = FREE_TIER_MODE ? 1 : 2) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) {
        await new Promise((r) => setTimeout(r, MIRURO_RETRY_BACKOFF * (i + 1)));
      }
    }
  }
  throw lastErr;
}

async function miruroFetchAllEmbeds(anilistId, episode) {
  const cacheKey = `${anilistId}:${episode}`;
  if (miruroEmbedsCache.has(cacheKey)) return miruroEmbedsCache.get(cacheKey);

  const data = await miruroFetchEpisodes(anilistId);
  const providers = data.providers || {};
  const jobs = [];
  // Keep fan-out tight on free-tier deployments: the upstream providers are the
  // main source of CPU/RAM spikes and rate-limit pressure.
  const preferred = FREE_TIER_MODE ? ['bonk', 'kiwi', 'hop'] : ['bonk', 'kiwi', 'hop', 'ally', 'pewe'];
  const ordered = [...preferred.filter((p) => providers[p]), ...Object.keys(providers).filter((p) => !preferred.includes(p))].slice(0, MIRURO_PROVIDER_CAP);
  for (const provider of ordered) {
    const providerData = providers[provider];
    const epGroups = providerData?.episodes || {};
    for (const [category, epList] of Object.entries(epGroups)) {
      if (!Array.isArray(epList)) continue;
      const found = epList.find(ep => Number(ep.number) === episode);
      if (found && found.id) jobs.push({ provider, category, episodeId: found.id });
    }
  }

  const embeds = [];
  const seen = new Set();
  const runJob = async (job) => {
    try {
      const sources = await miruroWithRetry(() => miruroFetchSources(anilistId, job.provider, job.category, job.episodeId), 2);
      for (const s of sources.streams || []) {
        if (s.type !== 'embed' || !s.url) continue;
        const key = s.url.split('?')[0];
        if (seen.has(key)) continue;
        seen.add(key);
        let host = '';
        try { host = new URL(s.url).host.replace(/^www\./, ''); } catch { /* ignore */ }
        embeds.push({
          provider: job.provider,
          category: job.category,
          url: s.url,
          host,
          kind: EMBED_HLS_HOSTS.includes(host) ? 'hls' : 'iframe',
        });
      }
    } catch { /* skip providers that fail to fetch */ }
  };
  // Bound the whole fan-out so a slow/rate-limited sources call can never hold
  // the request past ~18s; whatever embeds we've collected by then are returned.
  await Promise.race([
    Promise.allSettled(jobs.map(runJob)),
    new Promise((r) => setTimeout(r, MIRURO_EMBED_TIMEOUT)),
  ]);

  const result = { embeds };
  miruroEmbedsCache.set(cacheKey, result);
  pruneCache(miruroEmbedsCache, 64);
  setTimeout(() => miruroEmbedsCache.delete(cacheKey), FREE_TIER_MODE ? 30 * 60 * 1000 : 60 * 60 * 1000);
  return result;
}

// Map a URL slug (e.g. "one-piece-odmau") to an AniList ID by searching
// AniList with progressively shorter title candidates.
const anilistResolveCache = new Map();

function slugToTitles(slug) {
  const parts = slug.split('-').filter(Boolean);
  const candidates = [];
  for (let i = parts.length; i >= 2; i--) {
    candidates.push(parts.slice(0, i).join(' '));
  }
  return candidates;
}

function normalizeTitle(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

// AniList media info is pulled by several endpoints (resolve, megap stream,
// /api/anilist/info). Cache it so a single anime page load doesn't fan out
// multiple identical GraphQL requests.
const anilistInfoCache = new Map();
const ANILIST_INFO_TTL = 24 * 60 * 60 * 1000;

// Light query: fast, used for watch page info + episode count
async function anilistMediaInfo(id) {
  const key = Number(id);
  if (anilistInfoCache.has(key)) return anilistInfoCache.get(key);
  const gql = `query ($id: Int) {
    Media(id: $id, type: ANIME) {
      id
      idMal
      title { romaji english native }
      description
      coverImage { extraLarge large color }
      bannerImage
      averageScore
      meanScore
      status
      format
      episodes
      duration
      genres
      synonyms
      seasonYear
      studios { nodes { name isAnimationStudio } }
      nextAiringEpisode { episode airingAt timeUntilAiring }
      externalLinks { site url type }
    }
  }`;
  const response = await fetch(ANILIST_GRAPHQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { id: Number(id) } }),
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) return null;
  const json = await response.json();
  const media = json?.data?.Media || null;
  if (media) {
    anilistInfoCache.set(key, media);
    setTimeout(() => anilistInfoCache.delete(key), ANILIST_INFO_TTL);
  }
  return media;
}

// Pull the TMDB id out of an AniList Media object's externalLinks
// (the site usually lists `https://www.themoviedb.org/tv/1234`).
function extractTmdbId(info) {
  if (!info) return null;
  for (const link of info.externalLinks || []) {
    const site = String(link.site || '').toLowerCase();
    const url = String(link.url || '');
    if (site.includes('themoviedb') || url.includes('themoviedb.org')) {
      const m = url.match(/\/tv\/(\d+)/) || url.match(/\/movie\/(\d+)/) || url.match(/themoviedb\.org\/(?:tv|movie)\/(\d+)/);
      if (m) return m[1];
    }
  }
  return null;
}

// Full-field search used by the /api/anime/search endpoint. Returns the same
// shape anilistHomeFeed does, so results can be fed straight into
// formatAnilistForHome. Cached per query for 30 minutes.
const anilistSearchCache = new Map();
const ANILIST_SEARCH_TTL = 30 * 60 * 1000;

async function anilistSearchFull(queryTitle, perPage = 48) {
  const cacheKey = `${perPage}:${queryTitle.toLowerCase().trim()}`;
  if (anilistSearchCache.has(cacheKey)) return anilistSearchCache.get(cacheKey);
  const gql = `query ($s: String, $perPage: Int) {
    Page(perPage: $perPage) {
      media(search: $s, type: ANIME, isAdult: false) {
        id
        idMal
        title { romaji english native }
        coverImage { extraLarge large color }
        bannerImage
        format
        episodes
        duration
        status
        seasonYear
        season
        averageScore
        meanScore
        genres
        synonyms
        description
        nextAiringEpisode { episode airingAt timeUntilAiring }
        startDate { year month day }
        studios { nodes { name isAnimationStudio } }
      }
    }
  }`;
  const response = await fetch(ANILIST_GRAPHQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { s: queryTitle, perPage: Number(perPage) } }),
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) {
    throw new Error(`AniList search failed (${response.status})`);
  }
  const json = await response.json();
  const media = (json?.data?.Page?.media) || [];
  anilistSearchCache.set(cacheKey, media);
  pruneCache(anilistSearchCache, 256);
  setTimeout(() => anilistSearchCache.delete(cacheKey), ANILIST_SEARCH_TTL);
  return media;
}

async function anilistSearch(queryTitle) {
  const cacheKey = queryTitle.toLowerCase().trim();
  if (anilistSearchCache.has(`s:${cacheKey}`)) return anilistSearchCache.get(`s:${cacheKey}`);
  const gql = `query ($s: String) {
    Page(perPage: 8) {
      media(search: $s, type: ANIME, isAdult: false) {
        id
        idMal
        title { romaji english native }
      }
    }
  }`;
  const response = await fetch(ANILIST_GRAPHQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { s: queryTitle } }),
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) {
    throw new Error(`AniList search failed (${response.status})`);
  }
  const json = await response.json();
  const media = (json?.data?.Page?.media) || [];
  anilistSearchCache.set(`s:${cacheKey}`, media);
  setTimeout(() => anilistSearchCache.delete(`s:${cacheKey}`), ANILIST_SEARCH_TTL);
  return media;
}

// Browse AniList by status / genre / type / A-Z letter / sort.
// The URL slugs used by the site (e.g. /genre/isekai, /status/ongoing) don't
// all map 1:1 to AniList genres, so tag-style filters fall back to tags.
const GENRE_MAP = {
  action: 'Action', adventure: 'Adventure', comedy: 'Comedy', drama: 'Drama',
  ecchi: 'Ecchi', fantasy: 'Fantasy', horror: 'Horror', josei: 'Josei',
  music: 'Music', mystery: 'Mystery', psychological: 'Psychological',
  romance: 'Romance', 'sci-fi': 'Sci-Fi', 'slice-of-life': 'Slice of Life',
  shoujo: 'Shoujo', shounen: 'Shounen', seinen: 'Seinen', sports: 'Sports',
  supernatural: 'Supernatural', thriller: 'Thriller', 'mahou-shoujo': 'Mahou Shoujo',
  mecha: 'Mecha',
};
const TAG_MAP = {
  'boys-love': 'Boys Love', 'girls-love': 'Girls Love',
  'shoujo-ai': 'Girls Love', 'shounen-ai': 'Boys Love',
  dementia: 'Dementia', demons: 'Demons', erotica: 'Erotica', game: 'Video Games',
  harem: 'Harem', historical: 'Historical', isekai: 'Isekai', kids: 'Kids',
  magic: 'Magic', 'martial-arts': 'Martial Arts', military: 'Military',
  parody: 'Parody', police: 'Police', samurai: 'Samurai', school: 'School',
  space: 'Space', 'super-power': 'Super Power', suspense: 'Suspense',
  vampire: 'Vampire',
};
const BROWSE_SORTS = {
  score: 'SCORE_DESC',
  popular: 'POPULARITY_DESC',
  recent: 'START_DATE_DESC',
  updated: 'UPDATED_AT_DESC',
};
const browseCache = new Map();
const BROWSE_TTL = 30 * 60 * 1000;

// A-Z index: built in the background from the most popular anime (which span
// every letter), so any letter resolves quickly without scanning the whole
// romaji-sorted catalog (which would take thousands of pages to reach 'Z').
const azIndex = new Map();
let azIndexReady = false;
const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

async function buildAzIndex() {
  try {
    const gql = `query ($perPage: Int, $page: Int) {
      Page(perPage: $perPage, page: $page) {
        media(sort: POPULARITY_DESC, type: ANIME, isAdult: false) {
          id
          idMal
          title { romaji english native }
          coverImage { extraLarge large color }
          bannerImage
          format
          episodes
          status
          seasonYear
          season
          averageScore
          meanScore
          genres
          description
          nextAiringEpisode { episode airingAt timeUntilAiring }
          startDate { year month day }
        }
      }
    }`;
    const pool = [];
    for (let page = 1; page <= 60; page++) {
      const response = await fetch(ANILIST_GRAPHQL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ query: gql, variables: { perPage: 50, page } }),
        signal: AbortSignal.timeout(15000),
      });
      if (response.status !== 200) break;
      const json = await response.json();
      const batch = json?.data?.Page?.media || [];
      if (!batch.length) break;
      pool.push(...batch);
      await sleepMs(300);
    }
    azIndex.clear();
    for (const m of pool) {
      const t = (m.title?.romaji || m.title?.english || m.title?.native || '').trim();
      const first = t.replace(/^["'(\[]/, '').charAt(0).toLowerCase();
      const key = !/[a-z0-9]/.test(first) ? 'other' : /[0-9]/.test(first) ? '0-9' : first;
      if (!azIndex.has(key)) azIndex.set(key, []);
      const list = azIndex.get(key);
      if (list.length < 300) list.push(m);
    }
    azIndexReady = true;
    log('AZ_INDEX', '-', 200, `built from ${pool.length} titles`);
  } catch (err) {
    log('AZ_INDEX_ERR', '-', 500, err.message);
  }
}
// Start the background build shortly after boot; retry in an hour on failure.
setTimeout(() => { buildAzIndex(); }, 2000);
setInterval(() => { if (!azIndexReady) buildAzIndex(); }, 60 * 60 * 1000);

async function anilistBrowse({ status, genre, format, letter = '', sort = 'score' } = {}) {
  const cacheKey = JSON.stringify({ status, genre, format, letter, sort });
  if (browseCache.has(cacheKey)) return browseCache.get(cacheKey);

  const fields = `
        id
        idMal
        title { romaji english native }
        coverImage { extraLarge large color }
        bannerImage
        format
        episodes
        status
        seasonYear
        season
        averageScore
        meanScore
        genres
        description
        nextAiringEpisode { episode airingAt timeUntilAiring }
        startDate { year month day }`;

  let media;
  if (letter) {
    const target = letter.toLowerCase();
    const key = target === 'other' || target === '0-9' ? target : /[a-z]/.test(target) ? target : 'other';
    if (azIndexReady && azIndex.has(key)) {
      media = azIndex.get(key);
    } else {
      // Index not ready yet (or missing letter) — fall back to a quick
      // popularity scan filtered to the letter.
      const gql = `query ($perPage: Int, $page: Int) {
        Page(perPage: $perPage, page: $page) {
          media(sort: POPULARITY_DESC, type: ANIME, isAdult: false) {
            ${fields}
          }
        }
      }`;
      const collected = [];
      for (let page = 1; page <= 6 && collected.length < 300; page++) {
        const response = await fetch(ANILIST_GRAPHQL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ query: gql, variables: { perPage: 50, page } }),
          signal: AbortSignal.timeout(15000),
        });
        if (response.status !== 200) break;
        const json = await response.json();
        const batch = json?.data?.Page?.media || [];
        if (!batch.length) break;
        for (const m of batch) {
          const t = (m.title?.romaji || m.title?.english || m.title?.native || '').trim();
          const first = t.replace(/^["'(\[]/, '').charAt(0).toLowerCase();
          const inKey = !/[a-z0-9]/.test(first) ? 'other' : /[0-9]/.test(first) ? '0-9' : first;
          if (inKey === key) collected.push(m);
        }
        await sleepMs(300);
      }
      media = collected;
    }
  } else {
    const genreName = GENRE_MAP[genre] || null;
    const tagName = TAG_MAP[genre] || null;
    // Only emit filter args that have real values — AniList returns an empty
    // list when null-valued filters are combined with type/isAdult.
    const args = [`sort: ${BROWSE_SORTS[sort] || BROWSE_SORTS.score}`, 'type: ANIME', 'isAdult: false'];
    const varDefs = [];
    const vars = { perPage: 300 };
    if (genreName) { vars.genre = genreName; varDefs.push('$genre: String'); args.push('genre: $genre'); }
    if (tagName) { vars.tag = tagName; varDefs.push('$tag: String'); args.push('tag: $tag'); }
    if (status) { vars.status = status; varDefs.push('$status: MediaStatus'); args.push('status: $status'); }
    if (format) { vars.format = format; varDefs.push('$format: MediaFormat'); args.push('format: $format'); }
    const gql = `query ($perPage: Int${varDefs.length ? ', ' + varDefs.join(', ') : ''}) {
      Page(perPage: $perPage) {
        media(${args.join(', ')}) {
          ${fields}
        }
      }
    }`;
    const response = await fetch(ANILIST_GRAPHQL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ query: gql, variables: vars }),
      signal: AbortSignal.timeout(20000),
    });
    if (response.status !== 200) throw new Error(`AniList browse failed (${response.status})`);
    const json = await response.json();
    media = json?.data?.Page?.media || [];
  }

  browseCache.set(cacheKey, media);
  pruneCache(browseCache, 128);
  setTimeout(() => browseCache.delete(cacheKey), BROWSE_TTL);
  return media;
}

async function anilistRandom() {
  const gql = `query ($page: Int) {
    Page(page: $page, perPage: 1) {
      media(sort: POPULARITY_DESC, type: ANIME, isAdult: false) {
        id
        title { romaji english }
        episodes
      }
    }
  }`;
  const page = 1 + Math.floor(Math.random() * 25);
  const response = await fetch(ANILIST_GRAPHQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { page } }),
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) throw new Error(`AniList random failed (${response.status})`);
  const json = await response.json();
  const media = json?.data?.Page?.media || [];
  return media[0] || null;
}

function scoreMatch(media, candidateTitle) {
  const wanted = normalizeTitle(candidateTitle);
  const titles = [
    media.title?.romaji, media.title?.english, media.title?.native,
    ...(Array.isArray(media.synonyms) ? media.synonyms : []),
  ];
  let best = 0;
  for (const t of titles) {
    const norm = normalizeTitle(t);
    if (!norm || !wanted) continue;
    if (norm === wanted) return 100;
    if (norm.includes(wanted) || wanted.includes(norm)) best = Math.max(best, 80);
    const shorter = Math.min(norm.length, wanted.length);
    let same = 0;
    for (let i = 0; i < shorter; i++) if (norm[i] === wanted[i]) same++;
    best = Math.max(best, Math.round((same / Math.max(shorter, 1)) * 50));
  }
  return best;
}

async function resolveAnilistId(slug) {
  if (anilistResolveCache.has(slug)) return anilistResolveCache.get(slug);

  let best = null;
  let bestScore = 0;
  for (const candidate of slugToTitles(slug)) {
    const results = await anilistSearch(candidate);
    for (const media of results) {
      const score = scoreMatch(media, candidate);
      if (score > bestScore) {
        bestScore = score;
        best = { anilistId: media.id, idMal: media.idMal, title: media.title?.romaji || media.title?.english || candidate };
      }
    }
    if (bestScore >= 100) break;
  }

  if (best) {
    try {
      const info = await anilistMediaInfo(best.anilistId);
      if (info) best.info = info;
    } catch { /* info is optional */ }
  }

  anilistResolveCache.set(slug, best);
  pruneCache(anilistResolveCache, 256);
  return best;
}

// Prune the resolve cache so a long-running instance can't grow unbounded —
// every entry holds the full AniList info object. FIFO cap keeps it small.
setInterval(() => {
  const keys = [...anilistResolveCache.keys()];
  if (keys.length <= 400) return;
  const drop = keys.slice(0, keys.length - 300);
  drop.forEach((k) => anilistResolveCache.delete(k));
}, 60 * 60 * 1000);

// ========================
// STATIC FILE SERVING
// ========================
const CACHE_MAX_AGE = {
  '.html': 'no-cache, no-store, must-revalidate, max-age=0',
  '.css': '0',
  '.js': '0',
  '.png': '604800',
  '.jpg': '604800',
  '.jpeg': '604800',
  '.webp': '604800',
  '.gif': '604800',
  '.svg': '86400',
  '.ico': '604800',
  '.woff2': '2592000',
  '.woff': '2592000',
  '.ttf': '2592000',
};

async function serveStatic(reqUrl, res, req) {
  try {
    let pathname = reqUrl.pathname;
    if (pathname === '/') {
      // Default site entry point should resolve to the landing page.
      pathname = '/landing.html';
    }
    if (pathname === '/home') {
      // Legacy search redirect (?keyword=... → /search?q=...)
      const kw = (reqUrl.searchParams.get('keyword') || '').trim();
      if (kw) {
        res.writeHead(302, { Location: `/search?q=${encodeURIComponent(kw)}` });
        return res.end();
      }
      pathname = '/home.html';
    }
    if (pathname === '/landing' || pathname === '/landing.html') pathname = '/landing.html';
    if (pathname === '/animeverse' || pathname === '/animeverse.html') pathname = '/home.html';
    if (pathname === '/pages/dmca' || pathname === '/dmca' || pathname === '/pages/terms' ||
        pathname === '/terms' || pathname === '/contact' || pathname === '/copyright') pathname = '/copyright.html';
    if (pathname === '/search' || pathname === '/search/') pathname = '/search.html';
    if (pathname === '/watch' || pathname === '/watch/') pathname = '/watch.html';
    if (pathname === '/player' || pathname === '/player/') pathname = '/player.html';
    if (pathname === '/catalog' || pathname === '/catalog/') pathname = '/catalog.html';
    if (pathname === '/schedule' || pathname === '/schedule/') pathname = '/schedule.html';
    if (pathname === '/profile' || pathname === '/profile/') pathname = '/profile.html';

    // Handle /watch/ path with slug - redirect to watch.html?slug=...
    const watchMatch = pathname.match(/^\/watch\/([^/]+)(?:\/([^/]+))?$/);
    if (watchMatch) {
      const slug = watchMatch[1];
      const epPart = watchMatch[2] ? `/${watchMatch[2]}` : '';
      const redirectUrl = `/watch.html?slug=${slug}${epPart}`;
      res.writeHead(302, { Location: redirectUrl });
      return res.end();
    }

    const filePath = path.join(PUBLIC_DIR, decodeURIComponent(pathname));
    const resolvedPath = path.resolve(filePath);

    // Security: prevent directory traversal
    if (!resolvedPath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('Forbidden');
    }

    const data = await fs.readFile(resolvedPath);
    const ext = path.extname(resolvedPath).toLowerCase();
    const headers = { 'Content-Type': getMimeType(resolvedPath) };

    // Add caching headers
    const maxAge = CACHE_MAX_AGE[ext];
    if (maxAge) {
      headers['Cache-Control'] = `public, max-age=${maxAge}`;
    }

    // Add compression if supported
    if (shouldCompress(res, req, ext)) {
      const compressed = zlib.gzipSync(data);
      headers['Content-Encoding'] = 'gzip';
      headers['Content-Length'] = compressed.length;
      res.writeHead(200, headers);
      return res.end(compressed);
    }

    res.writeHead(200, headers);
    res.end(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('File not found');
    } else {
      log('ERROR', reqUrl.pathname, 500, err.message);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal server error');
    }
  }
}

// ========================
// GENERIC URL PROXY (for /proxy)
// ========================
async function handleGenericProxy(reqUrl, res, req) {
  const target = reqUrl.searchParams.get('url');
  if (!target) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Missing url parameter' }));
  }

  if (!isAllowedProxyTarget(target)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid URL. Only http/https URLs are allowed.' }));
  }

  try {
    const response = await fetch(target, {
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/json,*/*',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
    });

    const body = await response.arrayBuffer();
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    const contentType = response.headers.get('content-type');
    if (contentType) {
      headers['Content-Type'] = contentType;
    }

    // Add compression
    if (shouldCompress(res, req) && body.byteLength > 1024) {
      const compressed = zlib.gzipSync(Buffer.from(body));
      headers['Content-Encoding'] = 'gzip';
      headers['Content-Length'] = compressed.length;
      res.writeHead(response.status, headers);
      return res.end(compressed);
    }

    res.writeHead(response.status, headers);
    res.end(Buffer.from(body));
  } catch (err) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Proxy fetch failed: ' + err.message);
  }
}

// Rewrite an HLS playlist so every URI line points back through /proxy-video,
// preserving the Referer so CDNs keep serving the segments.
function rewriteM3u8(playlist, baseUrl, referer) {
  return playlist.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    // Rewrite URI="..." inside attribute-style tags (e.g. EXT-X-I-FRAME-STREAM-INF)
    if (trimmed.startsWith('#EXT-X-I-FRAME-STREAM-INF') || trimmed.startsWith('#EXT-X-MEDIA')) {
      return trimmed.replace(/URI="([^"]+)"/g, (m, u) => {
        const absolute = /^https?:\/\//i.test(u) ? u : new URL(u, baseUrl).href;
        return `URI="${'/proxy-video?url=' + encodeURIComponent(absolute) + '&referer=' + encodeURIComponent(referer)}"`;
      });
    }
    if (trimmed.startsWith('#')) return line;
    if (trimmed.startsWith('/proxy-video') || /^https?:\/\//i.test(trimmed)) {
      // Absolute URLs are rewritten too (cross-host playlists/CDN segments)
      const absolute = /^https?:\/\//i.test(trimmed) ? trimmed : new URL(trimmed, baseUrl).href;
      return `/proxy-video?url=${encodeURIComponent(absolute)}&referer=${encodeURIComponent(referer)}`;
    }
    const absolute = new URL(trimmed, baseUrl).href;
    return `/proxy-video?url=${encodeURIComponent(absolute)}&referer=${encodeURIComponent(referer)}`;
  }).join('\n');
}

// ========================
// PROXY EMBED/VIDEO URL (for /proxy-video)
// Strips X-Frame-Options headers so embeds can load in iframe
// Adds proper Referer for video CDNs
// ========================
async function handleVideoProxy(reqUrl, res, req) {
  const target = reqUrl.searchParams.get('url');
  if (!target) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Missing url parameter' }));
  }

  if (!isAllowedProxyTarget(target)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid URL. Only http/https URLs are allowed.' }));
  }

  try {
    // Allow callers to specify the Referer/Origin (e.g. miruro/vidplay streams)
    const refererOverride = reqUrl.searchParams.get('referer');
    const referer = refererOverride || '';
    const origin = refererOverride ? new URL(refererOverride).origin : '';
    const requestHeaders = {
      'User-Agent': USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Sec-Fetch-Dest': 'iframe',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'cross-site',
      'Upgrade-Insecure-Requests': '1',
    };
    if (referer) requestHeaders['Referer'] = referer;
    if (origin) requestHeaders['Origin'] = origin;

    const response = await fetch(target, {
      headers: requestHeaders,
      redirect: 'manual', // Handle redirects manually
      signal: AbortSignal.timeout(30000),
    });

    // Handle redirects - follow them
    let currentResponse = response;
    let currentUrl = target;
    for (let i = 0; i < 5; i++) {
      const location = currentResponse.headers.get('location');
      if (location && (currentResponse.status === 301 || currentResponse.status === 302 || currentResponse.status === 303 || currentResponse.status === 307 || currentResponse.status === 308)) {
        const redirectUrl = new URL(location, currentUrl).href;
        currentUrl = redirectUrl;
        currentResponse = await fetch(redirectUrl, {
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': referer,
            'Origin': origin,
            'Sec-Fetch-Dest': 'iframe',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Upgrade-Insecure-Requests': '1',
          },
          redirect: 'manual',
          signal: AbortSignal.timeout(30000),
        });
        continue;
      }
      break;
    }

    const body = await currentResponse.arrayBuffer();
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Range',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
    };

    // Copy content-type
    let contentType = currentResponse.headers.get('content-type');
    if (contentType) {
      headers['Content-Type'] = contentType;
    }
    // WebVTT subtitle files: some CDNs serve them as application/octet-stream,
    // which browsers refuse to render in <track>. Force text/vtt for .vtt URLs.
    if (/\.vtt($|\?)/i.test(currentUrl)) {
      headers['Content-Type'] = 'text/vtt';
    }

    // HLS manifests: rewrite every URI so segments/playlists also flow
    // through this proxy (keeps Referer/Origin and avoids CORS failures).
    let finalBody = Buffer.from(body);
    const isM3u8 = (contentType && contentType.includes('mpegurl')) || /\.m3u8($|\?)/i.test(currentUrl);
    if (isM3u8) {
      try {
        const text = finalBody.toString('utf8');
        if (text.includes('#EXTM3U')) {
          finalBody = Buffer.from(rewriteM3u8(text, currentUrl, referer), 'utf8');
          headers['Content-Type'] = 'application/vnd.apple.mpegurl';
        }
      } catch (m3u8Err) {
        log('M3U8_REWRITE_ERR', currentUrl.substring(0, 80), 200, m3u8Err.message);
      }
    }

    // Copy cache headers if present
    const cacheControl = currentResponse.headers.get('cache-control');
    if (cacheControl) headers['Cache-Control'] = cacheControl;

    // Copy content-length if present (for videos)
    const contentLength = isM3u8 ? finalBody.length : currentResponse.headers.get('content-length');
    if (contentLength) headers['Content-Length'] = contentLength;

    // Copy accept-ranges for video seeking
    const acceptRanges = currentResponse.headers.get('accept-ranges');
    if (acceptRanges) headers['Accept-Ranges'] = acceptRanges;

    // Copy content-range for partial content
    const contentRange = currentResponse.headers.get('content-range');
    if (contentRange) headers['Content-Range'] = contentRange;

    // Copy set-cookie if present
    const setCookie = currentResponse.headers.get('set-cookie');
    if (setCookie) headers['Set-Cookie'] = setCookie;

    // IMPORTANT: Strip frame-blocking headers
    // X-Frame-Options prevents iframe loading
    // Content-Security-Policy frame-ancestors also blocks iframes
    // We explicitly do NOT copy these headers

    res.writeHead(currentResponse.status, headers);
    res.end(finalBody);
  } catch (err) {
    log('VIDEO_PROXY_ERR', target.substring(0, 80), 502, err.message);
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Video proxy failed: ' + err.message);
  }
}

// ========================
// ========================
// MEGA PLAY (megaplay.buzz) STREAM SCRAPER
// megaplay.buzz is the Anikoto/HiAnime video API. Its player page
// (/stream/ani/{anilistId}/{ep}/{lang}) exposes a #megaplay-player div with a
// data-id, which is then queried via /stream/getSourcesNew?id={data-id} to get
// the HLS stream. The stream CDN (megap.kotocdn.site) requires a Referer of
// https://megaplay.buzz/ — so the m3u8 is served through /proxy-video.
// ========================
const MEGAP_BASE = 'https://megaplay.buzz';
const MEGAP_REFERER = 'https://megaplay.buzz/';
const MEGAP_PAGE_REFERER = 'https://anikototv.to/';
const megapStreamCache = new Map();
const MEGAP_STREAM_TTL = 10 * 60 * 1000;

async function megapStream(anilistId, episode, lang, source = 'ani') {
  // AniList-independent mappings: /stream/ani/{anilistId} and /stream/mal/{malId}.
  const cacheKey = `${anilistId}:${episode}:${lang}:${source}`;
  if (megapStreamCache.has(cacheKey)) return megapStreamCache.get(cacheKey);
  // MegaPlay/KotoCDN exposes two AniList-independent mappings that resolve the
  // same video: /stream/ani/{anilistId}/{ep}/{lang} and /stream/mal/{malId}/{ep}/{lang}.
  // source='ani' (MEGA PLAY) tries the AniList mapping first and auto-falls back
  // to the MAL mapping; source='mal' (MEGA CLUB) goes straight to the MAL mapping.
  let info = null;
  const candidates = [];
  if (source === 'mal') {
    info = await anilistMediaInfo(anilistId);
    const malId = info?.idMal;
    if (!malId) throw new Error('No MAL id available for this anime');
    candidates.push({ key: `/stream/mal/${malId}/${episode}/${lang}`, via: 'MAL' });
  } else {
    candidates.push({ key: `/stream/ani/${anilistId}/${episode}/${lang}`, via: 'AniList' });
    try { info = await anilistMediaInfo(anilistId); } catch { /* fallback below */ }
    if (info?.idMal) candidates.push({ key: `/stream/mal/${info.idMal}/${episode}/${lang}`, via: 'MAL' });
  }

  for (const candidate of candidates) {
    try {
      const pageResp = await fetch(`${MEGAP_BASE}${candidate.key}`, {
        headers: {
          'User-Agent': USER_AGENT,
          'Referer': MEGAP_PAGE_REFERER,
          'Accept': 'text/html,application/xhtml+xml,*/*',
        },
        signal: AbortSignal.timeout(30000),
      });
      if (!pageResp.ok) continue;
      const html = await pageResp.text();
      const dataId = (html.match(/data-id="(\d+)"/) || [])[1];
      if (!dataId) continue;

      const srcResp = await fetch(`${MEGAP_BASE}/stream/getSourcesNew?id=${dataId}`, {
        headers: {
          'User-Agent': USER_AGENT,
          'Referer': MEGAP_REFERER,
          'X-Requested-With': 'XMLHttpRequest',
          'Accept': 'application/json, text/javascript, */*; q=0.01',
        },
        signal: AbortSignal.timeout(30000),
      });
      if (!srcResp.ok) continue;
      const data = await srcResp.json();
      if (!data?.sources?.file) continue;
      const result = {
        m3u8Url: data.sources.file,
        referer: MEGAP_REFERER,
        tracks: data.tracks || [],
        intro: data.intro || null,
        outro: data.outro || null,
        dataId,
        via: candidate.via,
      };
      megapStreamCache.set(cacheKey, result);
      pruneCache(megapStreamCache, 128);
      setTimeout(() => megapStreamCache.delete(cacheKey), MEGAP_STREAM_TTL);
      return result;
    } catch { /* try the next mapping */ }
  }
  throw new Error('megaplay embed not synced for this anime/episode');
}

// Resolve a kotocdn-family / inline-HLS embed URL into a real HLS stream.
// Two mechanisms are supported:
//   1) kotocdn-family (#megaplay-player data-id -> /stream/getSourcesNew) for
//      vidtube.site, megaplay.buzz and friends.
//   2) m3u8 declared directly in the embed page (vivibebe.site, bibiemb.xyz,
//      krussdomi.com), which plays without the miruro pipe at all.
// Cached for 10 minutes.
const embedStreamCache = new Map();

function extractInlineHls(html) {
  // Pattern 1: const src = "https://.../master.m3u8";
  let m = html.match(/const\s+src\s*=\s*["']([^"']+\.m3u8)["']/);
  // Pattern 2: sources: [{ file: "https://.../master.m3u8" }]
  if (!m) m = html.match(/sources\s*[:=]\s*\[[^\]\n]*?file\s*[:=]\s*["']([^"']+\.m3u8)["']/);
  if (m) return { m3u8Url: m[1], tracks: [] };
  // Pattern 3: krussdomi vidstream — m3u8 embedded in page JSON (HTML-escaped)
  m = html.match(/https:\/\/hls\.krussdomi\.com\/manifest\/[^"'\\]+\.m3u8/);
  if (m) {
    const json = html.replace(/&quot;/g, '"');
    const subs = [];
    const subRe = /\{"language":\[0,"([^"]+)"\],"name":\[0,"([^"]*)"\],"src":\[0,"([^"]+\.vtt)"\]\}/g;
    let sm;
    while ((sm = subRe.exec(json)) && subs.length < 30) {
      subs.push({ lang: sm[1], label: sm[2] || sm[1], file: sm[3] });
    }
    return { m3u8Url: m[0], tracks: subs };
  }
  return null;
}

// ========================
// VIDPLAY (vidplay.*) STREAM RESOLVER
// VidPlay hosts (used by many anime aggregators) expose a tiny JSON API:
// POST {origin}/api/source/{id} -> { status, sources: [{ file, type: 'hls' }],
// tracks: [...] }. The embed URL is {origin}/e/{id}. Some mirrors require a
// plain GET instead of POST, so we try both. The resulting HLS plays through
// the player with the embed origin as Referer.
// ========================
async function vidplayToHls(embedUrl, base, referer) {
  const id = String(embedUrl.split('/').pop().split('?')[0]);
  if (!id) throw new Error('vidplay: could not extract id from embed url');
  const apiUrl = `${base}/api/source/${id}`;
  const headers = {
    'User-Agent': USER_AGENT,
    'Referer': base + '/',
    'Origin': base,
    'X-Requested-With': 'XMLHttpRequest',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
  };
  let resp = await fetch(apiUrl, { method: 'POST', headers, signal: AbortSignal.timeout(30000) });
  if (!resp.ok) resp = await fetch(apiUrl, { method: 'GET', headers, signal: AbortSignal.timeout(30000) });
  if (!resp.ok) throw new Error(`vidplay sources returned ${resp.status}`);
  const data = await resp.json();
  const sources = data.sources || [];
  const src = sources.find((s) => s.file && /\.m3u8/i.test(s.file)) || sources[0];
  if (!src || !src.file) throw new Error('vidplay returned no stream file');
  return {
    m3u8Url: src.file,
    referer,
    tracks: (data.tracks || []).filter((t) => t.file).map((t) => ({
      lang: t.lang || t.label || 'en',
      label: t.label || t.lang || 'Subtitles',
      file: t.file,
      default: !!t.default,
    })),
    intro: null,
    outro: null,
    embedUrl,
  };
}

async function embedToHls(embedUrl) {
  if (embedStreamCache.has(embedUrl)) return embedStreamCache.get(embedUrl);

  const pageUrl = new URL(embedUrl);
  const base = pageUrl.origin;
  const referer = base + '/';

  // VidPlay resolves directly through its JSON API — skip the page fetch.
  if (VIDPLAY_HOSTS.includes(pageUrl.hostname)) {
    const result = await vidplayToHls(embedUrl, base, referer);
    embedStreamCache.set(embedUrl, result);
    setTimeout(() => embedStreamCache.delete(embedUrl), 10 * 60 * 1000);
    return result;
  }

  const pageResp = await fetch(embedUrl, {
    headers: {
      'User-Agent': USER_AGENT,
      'Referer': referer,
      'Accept': 'text/html,application/xhtml+xml,*/*',
    },
    signal: AbortSignal.timeout(30000),
  });
  if (!pageResp.ok) throw new Error(`embed page returned ${pageResp.status}`);
  const html = await pageResp.text();

  let result;
  const dataId = (html.match(/data-id="(\d+)"/) || [])[1];
  if (dataId) {
    const srcResp = await fetch(`${base}/stream/getSourcesNew?id=${dataId}`, {
      headers: {
        'User-Agent': USER_AGENT,
        'Referer': referer,
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
      },
      signal: AbortSignal.timeout(30000),
    });
    if (!srcResp.ok) throw new Error(`embed sources returned ${srcResp.status}`);
    const data = await srcResp.json();
    if (!data?.sources?.file) throw new Error('embed returned no stream file');
    result = {
      m3u8Url: data.sources.file,
      referer,
      tracks: data.tracks || [],
      intro: data.intro || null,
      outro: data.outro || null,
      dataId,
      embedUrl,
    };
  } else {
    const inline = extractInlineHls(html);
    if (!inline) throw new Error('embed not synced for this episode (no stream found)');
    result = {
      m3u8Url: inline.m3u8Url,
      referer,
      tracks: inline.tracks || [],
      intro: null,
      outro: null,
      embedUrl,
    };
  }

  embedStreamCache.set(embedUrl, result);
  pruneCache(embedStreamCache, 128);
  setTimeout(() => embedStreamCache.delete(embedUrl), 10 * 60 * 1000);
  return result;
}

// ========================
// APIPLAYER (apiplayer.ru) STREAM RESOLVER
// apiplayer is a TMDB-powered streaming API (no key). It serves an embed
// player page that harvests an HLS stream in the background; the page exposes
// a signed /hls-proxy/status/{...} URL we can poll for a ready master m3u8.
// The embed page itself plays fine in an iframe (frame-ancestors *), so the
// embed URL is always returned as a fallback even when the m3u8 isn't ready.
// ========================
const APIPLAYER_BASE = 'https://apiplayer.ru';
const APIPLAYER_REFERER = 'https://apiplayer.ru/';
const APIPLAYER_HEADERS = {
  'User-Agent': USER_AGENT,
  'Referer': APIPLAYER_REFERER,
  'Accept': 'text/html,application/xhtml+xml,*/*',
  'Accept-Language': 'en-US,en;q=0.9',
};

const apiplayerCache = new Map();

async function apiplayerStream(tmdbId, season, episode) {
  const cacheKey = `${tmdbId}:${season}:${episode}`;
  if (apiplayerCache.has(cacheKey)) return apiplayerCache.get(cacheKey);

  const embedUrl = `${APIPLAYER_BASE}/embed/tv/${tmdbId}/${season}/${episode}`;
  const result = { tmdbId, season, episode, embedUrl, referer: APIPLAYER_REFERER, m3u8Url: null, tracks: [] };

  try {
    const pageResp = await fetch(embedUrl, { headers: APIPLAYER_HEADERS, signal: AbortSignal.timeout(25000) });
    if (pageResp.ok) {
      const html = await pageResp.text();
      const m = html.match(/harvestPollUrl":"([^"]+)/);
      if (m) {
        const pollUrl = m[1].replace(/\\u0026/g, '&');
        // Poll a short while — the embed page keeps polling client-side, so an
        // unresolved m3u8 here is fine and we fall back to the embed.
        for (let i = 0; i < 5; i++) {
          try {
            const stResp = await fetch(APIPLAYER_BASE + pollUrl, { headers: APIPLAYER_HEADERS, signal: AbortSignal.timeout(10000) });
            const st = await stResp.json();
            if (st.master_url) {
              const candidate = /^https?:/.test(st.master_url) ? st.master_url : APIPLAYER_BASE + st.master_url.replace(/\\u0026/g, '&');
              // The status poll can report a master before the harvest is fully
              // cached; verify it actually serves an HLS playlist before
              // committing to the player route.
              try {
                const masterResp = await fetch(candidate, { headers: APIPLAYER_HEADERS, signal: AbortSignal.timeout(10000) });
                if (masterResp.ok && /mpegurl|application\/vnd\.apple/.test(masterResp.headers.get('content-type') || '')) {
                  result.m3u8Url = candidate;
                }
              } catch { /* leave null -> embed fallback */ }
            }
            if (st.available && result.m3u8Url) break;
          } catch { /* poll may be transiently challenged */ }
          await new Promise((r) => setTimeout(r, 2500));
        }
      }
    }
  } catch { /* keep embedUrl fallback */ }

  apiplayerCache.set(cacheKey, result);
  pruneCache(apiplayerCache, 128);
  setTimeout(() => apiplayerCache.delete(cacheKey), 5 * 60 * 1000);
  return result;
}

// ========================
// YOUTUBE SEARCH SCRAPER
// Scrapes youtube.com/results for video ids without an API key (no key means
// we can't use the official Data API; the search page embeds ytInitialData).
// Used for the "YouTube" source — many anime have full episodes on official
// channels (Muse Asia, Ani-One Asia, ...).
// ========================
const YT_HEADERS = {
  'User-Agent': USER_AGENT,
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept': 'text/html,application/xhtml+xml,*/*',
};

const youtubeCache = new Map();

function youtubeExtractVideos(html) {
  const m = html.match(/ytInitialData\s*=\s*(\{.*?\});\s*<\/script>/s) || html.match(/ytInitialData\s*=\s*(\{.*?\});/s);
  if (!m) return [];
  let data;
  try { data = JSON.parse(m[1]); } catch { return []; }
  const vids = [];
  const seen = new Set();
  const walk = (o) => {
    if (!o || typeof o !== 'object') return;
    if (o.videoRenderer) {
      const v = o.videoRenderer;
      const id = v.videoId;
      const title = v.title?.runs?.map((r) => r.text).join('') || v.title?.simpleText || '';
      const length = v.lengthText?.simpleText || '';
      const channel = v.ownerText?.runs?.map((r) => r.text).join('') || '';
      if (id && title && !seen.has(id)) {
        seen.add(id);
        vids.push({ id, title, length, channel });
      }
    }
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(data);
  return vids.slice(0, 12);
}

async function youtubeSearch(query) {
  const cacheKey = query.toLowerCase().trim();
  if (youtubeCache.has(cacheKey)) return youtubeCache.get(cacheKey);
  const url = `https://www.youtube.com/results?search_query=${encodeURIComponent(query)}`;
  const response = await fetch(url, { headers: YT_HEADERS, signal: AbortSignal.timeout(20000) });
  if (response.status !== 200) throw new Error(`YouTube search failed (${response.status})`);
  const html = await response.text();
  const vids = youtubeExtractVideos(html);
  youtubeCache.set(cacheKey, vids);
  pruneCache(youtubeCache, 128);
  setTimeout(() => youtubeCache.delete(cacheKey), 10 * 60 * 1000);
  return vids;
}

// ========================
// HOME PAGE DATA FETCHERS
// ========================

// Fetch recently released / trending anime from AniList for the homepage.
// Cached for 5 minutes — every visitor hits the same data, so a TTL cache
// avoids re-fetching 50 full Media objects on each page load.
let anilistHomeCache = null;
let anilistHomeCacheAt = 0;
let anilistHomeInFlight = null;
const ANILIST_HOME_TTL = 5 * 60 * 1000;

async function anilistHomeFeed() {
  if (anilistHomeCache && Date.now() - anilistHomeCacheAt < ANILIST_HOME_TTL) {
    return anilistHomeCache;
  }
  // Dedupe concurrent cold fetches (multiple visitors hitting the page at once)
  // so they all share one AniList round-trip instead of each firing their own.
  if (anilistHomeInFlight) return anilistHomeInFlight;
  anilistHomeInFlight = (async () => {
    try {
      const media = await doAnilistHomeFetch();
      return media;
    } finally {
      anilistHomeInFlight = null;
    }
  })();
  return anilistHomeInFlight;
}

async function doAnilistHomeFetch() {
  const gql = `query ($page: Int, $perPage: Int) {
    Page(page: $page, perPage: $perPage) {
      media(
        type: ANIME,
        sort: [TRENDING_DESC, POPULARITY_DESC],
        status_in: [RELEASING, FINISHED, NOT_YET_RELEASED],
        isAdult: false
      ) {
        id
        idMal
        title { romaji english native }
        coverImage { extraLarge large color }
        bannerImage
        format
        episodes
        duration
        status
        seasonYear
        season
        averageScore
        meanScore
        genres
        synonyms
        description
        nextAiringEpisode { episode airingAt timeUntilAiring }
        startDate { year month day }
        studios { nodes { name isAnimationStudio } }
      }
    }
  }`;
  const response = await fetch(ANILIST_GRAPHQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { page: 1, perPage: 50 } }),
    signal: AbortSignal.timeout(8000),
  });
  if (response.status !== 200) throw new Error(`AniList home fetch failed (${response.status})`);
  const json = await response.json();
  const media = json?.data?.Page?.media || [];
  anilistHomeCache = media;
  anilistHomeCacheAt = Date.now();
  return media;
}

// Format AniList media for homepage display
function formatAnilistForHome(media) {
  const title = media.title?.english || media.title?.romaji || media.title?.native || 'Unknown';
  const jpTitle = media.title?.native || media.title?.romaji || '';
  const image = media.coverImage?.extraLarge || media.coverImage?.large || '';
  const banner = media.bannerImage || '';
  const format = media.format || 'TV';
  const episodes = media.episodes || 0;
  const status = media.status || 'RELEASING';
  const year = media.seasonYear || '';
  const season = media.season || '';
  const score = media.averageScore || 0;
  const genres = media.genres || [];
  const nextAiring = media.nextAiringEpisode || null;
  const startDate = media.startDate || {};
  const startDateStr = startDate.year ?
    `${startDate.month || '?'}/${startDate.day || '?'}/${startDate.year}` : year ? String(year) : '';

  let subCount = 0;
  let dubCount = 0;
  if (nextAiring) {
    subCount = nextAiring.episode - 1;
    dubCount = Math.max(0, Math.floor(subCount / 3));
  } else if (episodes > 0) {
    subCount = episodes;
    dubCount = Math.min(episodes, Math.max(0, Math.floor(episodes / 3)));
  }

  const slug = title.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    + '-' + media.id.toString(36).substring(0, 5);

  return {
    id: media.id,
    idMal: media.idMal,
    slug,
    title,
    jpTitle,
    image,
    banner,
    format,
    episodes,
    status,
    year,
    season,
    score,
    genres,
    startDate: startDateStr,
    subCount,
    dubCount,
    totalEpisodes: episodes,
    nextAiring,
    description: media.description ? media.description.replace(/<[^>]+>/g, '').substring(0, 300) : '',
    watchUrl: `/watch.html?anilistId=${media.id}`,
    episodeUrl: `/watch.html?anilistId=${media.id}`,
  };
}

// ========================
// REQUEST ROUTER
// ========================
// Airing schedule grouped by weekday. AnimeX exposes this; fall back to a
// rolling AniList "currently airing" fetch when the remote is unreachable.
async function animeSchedule() {
  try {
    const res = await fetch(`${ANIMEX_GRAPHQL}/api/schedule`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      signal: AbortSignal.timeout(15000),
    });
    if (res.status !== 200) throw new Error('schedule unavailable');
    return await res.json();
  } catch (err) {
    // Fallback: pull currently-airing shows from AniList and bucket by start day.
    const gql = `query { Page(perPage: 100) {
      media(type: ANIME, isAdult: false, status: RELEASING) {
        id title { romaji english } coverImage { extraLarge large }
        format episodes nextAiringEpisode { episode airingAt }
        seasonYear averageScore startDate { year month day }
      } } }`;
    const r = await fetch(ANILIST_GRAPHQL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: gql }), signal: AbortSignal.timeout(15000),
    });
    const json = await r.json();
    const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const out = { source: 'anilist' };
    days.forEach((d) => { out[d] = []; });
    for (const m of (json?.data?.Page?.media || [])) {
      const airing = m.nextAiringEpisode?.airingAt;
      const day = airing ? days[new Date(airing * 1000).getUTCDay()] : 'sunday';
      out[day].push(m);
    }
    return out;
  }
}

// Catalog browsing by season/year/format/sort (matches AnimeX's catalog page).
async function animeCatalog({ season, year, format, status, sort = 'popular', q = '' }) {
  const fields = `id idMal title { romaji english native } coverImage { extraLarge large color }
    bannerImage format episodes duration status seasonYear season averageScore meanScore
    genres description nextAiringEpisode { episode airingAt timeUntilAiring }
    startDate { year month day } studios { nodes { name isAnimationStudio } }`;
  const args = ['type: ANIME', 'isAdult: false'];
  const vars = {};
  const defs = [];
  const add = (v, t) => { const k = 'a' + (Object.keys(vars).length); vars[k] = v; defs.push(`$${k}: ${t}`); return `$${k}`; };
  if (q) { args.push(`search: ${add(q, 'String')}`); }
  if (season) { args.push(`season: ${add(season, 'MediaSeason')}`); }
  if (year) { args.push(`seasonYear: ${add(Number(year), 'Int')}`); }
  if (format) { args.push(`format: ${add(format, 'MediaFormat')}`); }
  if (status) { args.push(`status: ${add(status, 'MediaStatus')}`); }
  const SORTS = {
    popular: 'POPULARITY_DESC', score: 'SCORE_DESC', recent: 'START_DATE_DESC',
    updated: 'UPDATED_AT_DESC', title: 'TITLE_ROMAJI', trending: 'TRENDING_DESC',
  };
  args.push(`sort: ${SORTS[sort] || SORTS.popular}`);
  const gql = `query($perPage: Int${defs.length ? ', ' + defs.join(', ') : ''}) {
    Page(perPage: $perPage) { media(${args.join(', ')}) { ${fields} } } }`;
  const r = await fetch(ANILIST_GRAPHQL, {
    method: 'POST', headers: { 'Content-Type': 'application/json',
      'Accept': 'application/json' },
    body: JSON.stringify({ query: gql, variables: { ...vars, perPage: 200 } }),
    signal: AbortSignal.timeout(20000),
  });
  if (r.status !== 200) throw new Error('catalog failed');
  const json = await r.json();
  return (json?.data?.Page?.media || []).map(formatAnilistForHome);
}

const server = http.createServer(async (req, res) => {
  const startTime = Date.now();
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                   req.socket.remoteAddress || 'unknown';

  // Rate limiting
  if (!rateLimit(clientIp)) {
    log('RATE_LIMIT', reqUrl.pathname, 429);
    res.writeHead(429, {
      'Content-Type': 'application/json',
      'Retry-After': '60',
    });
    return res.end(JSON.stringify({ error: 'Too many requests. Please slow down.' }));
  }

  // Apply CORS headers to all responses
  applyCorsHeaders(res, req);

  // Handle OPTIONS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // Optional access gate (only active when ACCESS_TOKEN is set)
  if (ACCESS_TOKEN && !accessGranted(req, reqUrl)) {
    if (reqUrl.pathname === '/login') {
      if (req.method === 'POST') {
        const body = await getRequestBody(req);
        const token = new URLSearchParams(body.toString('utf8')).get('token') || '';
        if (token !== ACCESS_TOKEN) {
          res.writeHead(403, { 'Content-Type': 'text/plain' });
          return res.end('Invalid access token');
        }
        res.writeHead(302, {
          Location: '/',
          'Set-Cookie': `access_token=${ACCESS_TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`,
        });
        return res.end();
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(LOGIN_HTML);
    }
    res.writeHead(302, { Location: '/login' });
    return res.end();
  }

  try {
    // ========== ROUTE: Health check ==========
    if (reqUrl.pathname === '/health' || reqUrl.pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'ok',
        uptime: process.uptime(),
        memory: process.memoryUsage().rss,
      }));
    }

// ========== ROUTE: /api/home/recently-released (AniList) ==========
    if (reqUrl.pathname === '/api/home/recently-released') {
      try {
        const anilistMedia = await anilistHomeFeed();
        const formatted = anilistMedia.map(formatAnilistForHome);

        log(req.method, reqUrl.pathname, 200, `[HOME] anilist=${formatted.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          anilist: formatted,
          timestamp: new Date().toISOString(),
        }));
      } catch (err) {
        log('HOME_FEED_ERR', reqUrl.pathname, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, anilist: [] }));
      }
    }

    // ========== ROUTE: /api/anime/search (AniList full-text search) ==========
    if (reqUrl.pathname === '/api/anime/search') {
      const q = (reqUrl.searchParams.get('q') || '').trim();
      if (!q) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing q parameter', results: [] }));
      }
      try {
        const media = await anilistSearchFull(q);
        const results = media.map(formatAnilistForHome);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[SEARCH] ${results.length} results`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ query: q, results, total: results.length }));
      } catch (err) {
        log('SEARCH_ERR', reqUrl.pathname + reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, results: [] }));
      }
    }

    // ========== ROUTE: /api/browse (status/genre/type/A-Z listing) ==========
    if (reqUrl.pathname === '/api/browse') {
      const status = reqUrl.searchParams.get('status') || '';
      const genre = reqUrl.searchParams.get('genre') || '';
      const format = reqUrl.searchParams.get('format') || '';
      const letter = reqUrl.searchParams.get('letter') || '';
      const sort = reqUrl.searchParams.get('sort') || 'score';
      try {
        const media = await anilistBrowse({ status, genre, format, letter, sort });
        const results = media.map(formatAnilistForHome);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[BROWSE] ${results.length} results`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ results, total: results.length }));
      } catch (err) {
        log('BROWSE_ERR', reqUrl.pathname + reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, results: [] }));
      }
    }

    // ========== ROUTE: /proxy (generic URL proxy) ==========
    if (reqUrl.pathname === '/proxy') {
      log(req.method, reqUrl.pathname + reqUrl.search, 200, '[PROXY]');
      return handleGenericProxy(reqUrl, res, req);
    }

    // ========== ROUTE: /proxy-video (embed/video proxy - strips frame blocking) ==========
    if (reqUrl.pathname === '/proxy-video') {
      log(req.method, reqUrl.pathname + reqUrl.search, 200, '[VIDEO PROXY]');
      return handleVideoProxy(reqUrl, res, req);
    }

    // ========== ROUTE: /api/miruro/resolve (slug -> AniList ID) ==========
    if (reqUrl.pathname === '/api/miruro/resolve') {
      const slug = reqUrl.searchParams.get('slug') || '';
      if (!slug) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing slug parameter' }));
      }
      try {
        const resolved = await resolveAnilistId(slug);
        if (resolved) resolved.tmdbId = extractTmdbId(resolved.info) || null;
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ resolved }));
      } catch (err) {
        log('MIRURO_RESOLVE_ERR', slug, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, resolved: null }));
      }
    }

    // ========== ROUTE: /api/miruro/status (sidecar diagnostics) ==========
    if (reqUrl.pathname === '/api/miruro/status') {
      try {
        const sidecar = await fetch(`${MIRURO_SIDECAR_URL}/health`, { signal: AbortSignal.timeout(5000) });
        const info = await sidecar.json();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ sidecar: info }));
      } catch (err) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ sidecar: { ok: false, error: err.message } }));
      }
    }

    // ========== ROUTE: /api/miruro/servers (providers for an episode) ==========
    if (reqUrl.pathname === '/api/miruro/servers') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      if (!anilistId || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId and/or episode' }));
      }
      try {
        const data = await miruroFetchEpisodes(anilistId);
        const mappings = data.mappings || {};
        const servers = [];
        const providers = data.providers || {};
        for (const [provider, providerData] of Object.entries(providers)) {
          const epGroups = providerData?.episodes || {};
          for (const [category, epList] of Object.entries(epGroups)) {
            if (!Array.isArray(epList)) continue;
            const found = epList.find(ep => Number(ep.number) === episode);
            if (found && found.id) {
              servers.push({
                provider,
                category,
                episodeId: found.id,
                number: found.number,
                title: found.title || '',
                duration: found.duration || null,
              });
            }
          }
        }
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ mappings, anilistId, episode, servers }));
      } catch (err) {
        log('MIRURO_SERVERS_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, servers: [] }));
      }
    }

    // ========== ROUTE: /api/miruro/episodes (all episode numbers for an anime) ==========
    if (reqUrl.pathname === '/api/miruro/episodes') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      if (!anilistId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId parameter' }));
      }
      try {
        const data = await miruroFetchEpisodes(anilistId);
        const byNumber = new Map();
        const providers = data.providers || {};
        for (const [provider, providerData] of Object.entries(providers)) {
          const epGroups = providerData?.episodes || {};
          for (const [category, epList] of Object.entries(epGroups)) {
            if (!Array.isArray(epList)) continue;
            for (const ep of epList) {
              if (!ep || !ep.number) continue;
              const num = Number(ep.number);
              const entry = byNumber.get(num) || { number: num, title: ep.title || '', duration: ep.duration || null, airDate: ep.airDate || null, providers: {} };
              entry.providers[`${provider}:${category}`] = { id: ep.id };
              if (!entry.title) entry.title = ep.title || '';
              if (!entry.duration) entry.duration = ep.duration || null;
              if (!entry.airDate) entry.airDate = ep.airDate || null;
              byNumber.set(num, entry);
            }
          }
        }

        // Only expose episodes that have actually aired. miruro pre-loads the
        // whole planned episode list for ongoing shows, which floods the grid
        // with future episodes nobody can watch. The aired count comes from
        // AniList: nextAiringEpisode.episode - 1 while airing, otherwise the
        // episodes field (finished shows). Note: for airing shows AniList's
        // `episodes` field is the *planned total*, not the aired count, so it
        // must NOT be used here — that was showing unreleased episodes.
        let info = null;
        try { info = await anilistMediaInfo(anilistId); } catch (_) {}
        let airedCount = null;
        const status = info?.status || '';
        const infoEpisodes = info?.episodes || null;
        if (info?.nextAiringEpisode?.episode) {
          airedCount = info.nextAiringEpisode.episode - 1;
        } else if (status === 'FINISHED' && infoEpisodes) {
          airedCount = infoEpisodes;
        }

        let episodes = [...byNumber.values()].sort((a, b) => a.number - b.number);
        if (airedCount) {
          episodes = episodes.filter((ep) => Number(ep.number) <= airedCount);
        }
        // Secondary guard: when AniList can't give a reliable aired count (or
        // the info call failed), drop episodes whose miruro airDate is clearly
        // in the future — those are planned/unreleased placeholders. Episodes
        // without an airDate (older data) are kept so nothing is lost.
        const hasAirDates = episodes.some((ep) => ep.airDate);
        if (!airedCount && hasAirDates) {
          const now = Date.now();
          const grace = 24 * 60 * 60 * 1000;
          episodes = episodes.filter((ep) => {
            if (!ep.airDate) return true;
            const t = Date.parse(ep.airDate);
            return !isNaN(t) && t <= now + grace;
          });
        }
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          mappings: data.mappings || {},
          anilistId,
          episodes,
          airedCount,
          totalEpisodes: infoEpisodes,
          status,
          nextAiringEpisode: info?.nextAiringEpisode || null,
        }));
      } catch (err) {
        // Miruro pipe failed (e.g. Cloudflare blocks datacenter IPs).
        // Fall back to a numeric episode list from AniList so MEGA PLAY
        // and other independent sources still work.
        log('MIRURO_EPISODES_ERR', reqUrl.search, 200, err.message + ' [fallback to AniList]');
        try {
          const info = await anilistMediaInfo(anilistId);
          let total = 0;
          let airedCount = null;
          let status = '';
          let nextAiring = null;
          if (info) {
            status = info.status || '';
            nextAiring = info.nextAiringEpisode || null;
            if (info.nextAiringEpisode?.episode) {
              airedCount = info.nextAiringEpisode.episode - 1;
              total = airedCount;
            } else if (status === 'FINISHED' && info.episodes) {
              airedCount = info.episodes;
              total = info.episodes;
            }
          }
          if (total < 1) total = airedCount || 0;
          const episodes = total > 0
            ? Array.from({ length: total }, (_, i) => ({
                number: i + 1,
                title: 'Episode ' + (i + 1),
              }))
            : [];
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({
            mappings: {},
            anilistId,
            episodes,
            airedCount,
            totalEpisodes: info?.episodes || null,
            status,
            nextAiringEpisode: nextAiring,
          }));
        } catch (fallbackErr) {
          log('MIRURO_EPISODES_FALLBACK_ERR', reqUrl.search, 502, fallbackErr.message);
          res.writeHead(502, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: err.message, episodes: [] }));
        }
      }
    }

    // ========== ROUTE: /api/miruro/stream (HLS sources for an episode) ==========
    if (reqUrl.pathname === '/api/miruro/stream') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const provider = reqUrl.searchParams.get('provider');
      const category = reqUrl.searchParams.get('category') || 'sub';
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      if (!anilistId || !provider || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId, provider and/or episode' }));
      }
      try {
        const data = await miruroFetchEpisodes(anilistId);
        const epList = data?.providers?.[provider]?.episodes?.[category];
        const found = Array.isArray(epList) ? epList.find(ep => Number(ep.number) === episode) : null;
        if (!found || !found.id) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: `Episode ${episode} not found for ${provider}/${category}` }));
        }
        const sources = await miruroFetchSources(anilistId, provider, category, found.id);
        const hls = (sources.streams || []).find(s => s.type === 'hls');
        // The HLS stream carries its own required Referer (e.g. ally/allmanga
        // serves via a wixmp repackager that 500s without it). Picking the
        // first *embed* stream's origin instead breaks streams whose embed and
        // HLS live on different hosts.
        const hlsReferer = hls && hls.referer ? hls.referer : miruroEmbedOrigin(sources);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          provider,
          category,
          episode: found.number,
          streams: sources.streams || [],
          subtitles: sources.subtitles || [],
          intro: sources.intro || null,
          outro: sources.outro || null,
          m3u8Url: hls ? buildMiruroPlayableUrl(hls.url, hlsReferer) : null,
        }));
      } catch (err) {
        log('MIRURO_STREAM_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/miruro/embeds (all embed servers for an episode) ==========
    if (reqUrl.pathname === '/api/miruro/embeds') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      if (!anilistId || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId and/or episode' }));
      }
      try {
        const { embeds } = await miruroFetchAllEmbeds(anilistId, episode);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[MIRURO] ${embeds.length} embeds`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ anilistId, episode, embeds }));
      } catch (err) {
        log('MIRURO_EMBEDS_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, embeds: [] }));
      }
    }

    // ========== ROUTE: /api/embed-stream (kotocdn-family embed -> HLS) ==========
    if (reqUrl.pathname === '/api/embed-stream') {
      const url = reqUrl.searchParams.get('url') || '';
      if (!url) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing url parameter' }));
      }
      if (!isAllowedProxyTarget(url)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid URL. Only public http/https URLs are allowed.' }));
      }
      try {
        const stream = await embedToHls(url);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[EMBED-HLS]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(stream));
      } catch (err) {
        log('EMBED_STREAM_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/megap/stream (megaplay.buzz HLS for an episode) ==========
    // source=ani (default, MEGA PLAY) uses the AniList mapping with an automatic
    // MAL fallback; source=mal (MEGA CLUB) uses the MAL mapping directly.
    if (reqUrl.pathname === '/api/megap/stream') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      const lang = reqUrl.searchParams.get('lang') || 'sub';
      const source = reqUrl.searchParams.get('source') || 'ani';
      if (!anilistId || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId and/or episode' }));
      }
      try {
        const stream = await megapStream(anilistId, episode, lang, source);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[MEGAP:${source}] via=${stream.via || '?'}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(stream));
      } catch (err) {
        log('MEGAP_STREAM_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/anilist/info (AniList media by ID) ==========
    if (reqUrl.pathname === '/api/anilist/info') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      if (!anilistId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId parameter' }));
      }
      try {
        const info = await anilistMediaInfo(anilistId);
        if (!info) throw new Error('AniList info unavailable');
        const title = info.title?.english || info.title?.romaji || info.title?.native || '';
        const tmdbId = extractTmdbId(info);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[ANILIST]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ resolved: { anilistId, title, tmdbId, info } }));
      } catch (err) {
        log('ANILIST_INFO_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/anime/extras (relations + recommendations for an anime) ==========
    // Uses its own heavy GraphQL query (characters, relations, recommendations)
    // so it doesn't slow down the watch page info load.
    if (reqUrl.pathname === '/api/anime/extras') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      if (!anilistId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId parameter' }));
      }
      try {
        const gql = `query ($id: Int) {
          Media(id: $id, type: ANIME) {
            characters(sort: ROLE, perPage: 12) {
              edges { role node { id name { full } image { large } } }
            }
            relations {
              edges {
                relationType
                node { id title { romaji english native } coverImage { large medium } format status seasonYear averageScore }
              }
            }
            recommendations(sort: RATING_DESC, perPage: 12) {
              nodes {
                mediaRecommendation {
                  id title { romaji english native } coverImage { large medium } format status seasonYear averageScore
                }
              }
            }
          }
        }`;
        const response = await fetch(ANILIST_GRAPHQL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ query: gql, variables: { id: Number(anilistId) } }),
          signal: AbortSignal.timeout(15000),
        });
        if (response.status !== 200) throw new Error('AniList extras query failed');
        const json = await response.json();
        const media = json?.data?.Media;
        if (!media) throw new Error('AniList media not found');
        const toCard = (m) => (m ? {
          anilistId: m.id,
          title: m.title?.english || m.title?.romaji || m.title?.native || '',
          romaji: m.title?.romaji || '',
          image: m.coverImage?.large || m.coverImage?.medium || '',
          format: m.format || '',
          status: m.status || '',
          year: m.seasonYear || null,
          score: m.averageScore || null,
        } : null);
        const relations = (media.relations?.edges || [])
          .filter((e) => e && e.node)
          .map((e) => ({ relationType: e.relationType || 'RELATED', ...toCard(e.node) }))
          .filter((r) => r.anilistId);
        const recommendations = (media.recommendations?.nodes || [])
          .map((n) => toCard(n && n.mediaRecommendation))
          .filter((r) => r && r.anilistId);
        const characters = (media.characters?.edges || [])
          .filter((e) => e && e.node && e.node.image && e.node.image.large)
          .map((e) => ({
            id: e.node.id,
            name: e.node.name?.full || e.node.name || '',
            role: e.role || '',
            image: e.node.image.large,
          }));
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[EXTRAS]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ anilistId, relations, recommendations, characters }));
      } catch (err) {
        log('EXTRAS_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, relations: [], recommendations: [], characters: [] }));
      }
    }

    // ========== ROUTE: /api/youtube/search (YouTube results without an API key) ==========
    if (reqUrl.pathname === '/api/youtube/search') {
      const q = reqUrl.searchParams.get('q') || '';
      if (!q) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing q parameter' }));
      }
      try {
        const videos = await youtubeSearch(q);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[YOUTUBE] ${videos.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ query: q, videos }));
      } catch (err) {
        log('YOUTUBE_SEARCH_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, videos: [] }));
      }
    }

    // ========== ROUTE: /api/apiplayer/stream (apiplayer.ru embed + optional HLS) ==========
    if (reqUrl.pathname === '/api/apiplayer/stream') {
      const tmdbId = reqUrl.searchParams.get('tmdbId');
      const season = reqUrl.searchParams.get('season') || '1';
      const episode = reqUrl.searchParams.get('episode');
      if (!tmdbId || !episode) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing tmdbId and/or episode' }));
      }
      try {
        const stream = await apiplayerStream(tmdbId, season, episode);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[APIPLAYER] m3u8=${stream.m3u8Url ? 'yes' : 'no'}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(stream));
      } catch (err) {
        log('APIPLAYER_STREAM_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/animex/servers (AnimeX servers for an episode) ==========
    if (reqUrl.pathname === '/api/animex/servers') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      if (!anilistId || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId and/or episode' }));
      }
      try {
        const data = await animexScraper.animexServers(anilistId, episode);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[ANIMEX] sub=${data.sub.length} dub=${data.dub.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(data));
      } catch (err) {
        log('ANIMEX_SERVERS_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, available: false, sub: [], dub: [] }));
      }
    }

    // ========== ROUTE: /api/animex/episodes (AnimeX episode list) ==========
    if (reqUrl.pathname === '/api/animex/episodes') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      if (!anilistId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId parameter' }));
      }
      try {
        const data = await animexScraper.animexEpisodes(anilistId);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[ANIMEX] eps=${data.episodes.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(data));
      } catch (err) {
        log('ANIMEX_EPISODES_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, available: false, episodes: [] }));
      }
    }

    // ========== ROUTE: /api/animex/stream (AnimeX HLS source) ==========
    if (reqUrl.pathname === '/api/animex/stream') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      const type = reqUrl.searchParams.get('type') || 'sub';
      const provider = reqUrl.searchParams.get('providerId') || '';
      if (!anilistId || isNaN(episode) || !provider) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId, episode and/or providerId' }));
      }
      try {
        const data = await animexScraper.animexSources(anilistId, episode, type, provider);
        // Build a server-relayed HLS URL so the browser can play it with the
        // correct referer/proxy headers (mirrors how /proxy-video is used).
        const src = (data.sources || []).find((s) => /\.m3u8($|\?)/i.test(s.url || ''));
        const m3u8Url = (src && !data.error)
          ? `/proxy-video?url=${encodeURIComponent(src.url)}&referer=${encodeURIComponent((data.headers && (data.headers.Referer || data.headers.Origin)) || '')}`
          : null;
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[ANIMEX] m3u8=${m3u8Url ? 'yes' : 'no'}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          ...data,
          providerId: provider,
          type,
          m3u8Url,
          subtitles: (data.tracks || []).filter((t) => t.kind === 'captions' || t.kind === 'subtitles'),
        }));
      } catch (err) {
        log('ANIMEX_STREAM_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: /api/trailer (official/YouTube trailer for an anime) ==========
    if (reqUrl.pathname === '/api/trailer') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      if (!anilistId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId parameter' }));
      }
      let trailer = null;
      try {
        const info = await anilistMediaInfo(anilistId);
        const links = info && info.externalLinks || [];
        const yt = links.find((l) => String(l.site || '').toLowerCase().includes('youtube') && /trailer/i.test(l.type || ''));
        const ytId = yt && yt.url ? (yt.url.match(/(?:v=|youtu\.be\/|embed\/)([\w-]{6,})/i) || [])[1] : null;
        if (ytId) trailer = { provider: 'youtube', id: ytId, url: `https://www.youtube.com/embed/${ytId}?autoplay=1` };
        if (!trailer) {
          const title = (info && (info.title?.english || info.title?.romaji)) || '';
          const videos = await youtubeSearch(`${title} official trailer`);
          const v = (videos || []).find((x) => x.id);
          if (v) trailer = { provider: 'youtube', id: v.id, url: `https://www.youtube.com/embed/${v.id}?autoplay=1` };
        }
      } catch (err) {
        log('TRAILER_ERR', reqUrl.search, 200, err.message);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ anilistId, trailer }));
    }

    // ========== ROUTE: /api/catalog (season/year/format/sort browse) ==========
    if (reqUrl.pathname === '/api/catalog') {
      const season = reqUrl.searchParams.get('season') || '';
      const year = reqUrl.searchParams.get('year') || '';
      const format = reqUrl.searchParams.get('format') || '';
      const status = reqUrl.searchParams.get('status') || '';
      const sort = reqUrl.searchParams.get('sort') || 'popular';
      const q = reqUrl.searchParams.get('q') || '';
      try {
        const results = await animeCatalog({ season, year, format, status, sort, q });
        log(req.method, reqUrl.pathname + reqUrl.search, 200, `[CATALOG] ${results.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ results, total: results.length }));
      } catch (err) {
        log('CATALOG_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, results: [] }));
      }
    }

    // ========== ROUTE: /api/schedule (airing by weekday) ==========
    if (reqUrl.pathname === '/api/schedule') {
      try {
        const schedule = await animeSchedule();
        log(req.method, reqUrl.pathname, 200, '[SCHEDULE]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(schedule));
      } catch (err) {
        log('SCHEDULE_ERR', reqUrl.pathname, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
    }

    // ========== ROUTE: browse redirects (/status/, /genre/, /type/, /az-list/) ==========
    const STATUS_SLUGS = {
      'ongoing': 'RELEASING', 'currently-airing': 'RELEASING',
      'completed': 'FINISHED', 'finished-airing': 'FINISHED',
      'not-yet-aired': 'NOT_YET_RELEASED', 'hiatus': 'HIATUS', 'cancelled': 'CANCELLED',
    };
    const FORMAT_SLUGS = {
      'tv': 'TV', 'tv-short': 'TV_SHORT', 'movie': 'MOVIE', 'special': 'SPECIAL',
      'tv-special': 'SPECIAL', 'ova': 'OVA', 'ona': 'ONA', 'music': 'MUSIC',
    };
    let pathMatch = reqUrl.pathname.match(/^\/status\/([a-z0-9-]+)$/);
    if (pathMatch && STATUS_SLUGS[pathMatch[1]] !== undefined) {
      log(req.method, reqUrl.pathname, 302, `[BROWSE] status=${STATUS_SLUGS[pathMatch[1]]}`);
      res.writeHead(302, { Location: `/search?status=${STATUS_SLUGS[pathMatch[1]]}` });
      return res.end();
    }
    pathMatch = reqUrl.pathname.match(/^\/genre\/([a-z0-9-]+)$/);
    if (pathMatch) {
      log(req.method, reqUrl.pathname, 302, `[BROWSE] genre=${pathMatch[1]}`);
      res.writeHead(302, { Location: `/search?genre=${encodeURIComponent(pathMatch[1])}` });
      return res.end();
    }
    pathMatch = reqUrl.pathname.match(/^\/type\/([a-z0-9-]+)$/);
    if (pathMatch) {
      const fmt = FORMAT_SLUGS[pathMatch[1]];
      if (fmt) {
        log(req.method, reqUrl.pathname, 302, `[BROWSE] format=${fmt}`);
        res.writeHead(302, { Location: `/search?format=${fmt}` });
      } else {
        log(req.method, reqUrl.pathname, 302, '[BROWSE] all types');
        res.writeHead(302, { Location: '/search?sort=score' });
      }
      return res.end();
    }
    pathMatch = reqUrl.pathname.match(/^\/az-list(?=$|\/)(?:\/([A-Za-z0-9-]*))?$/);
    if (pathMatch && reqUrl.pathname.startsWith('/az-list')) {
      const letter = pathMatch[1] || '';
      if (!letter || letter.toLowerCase() === 'all') {
        log(req.method, reqUrl.pathname, 302, '[BROWSE] all (score)');
        res.writeHead(302, { Location: '/search?sort=score' });
      } else {
        log(req.method, reqUrl.pathname, 302, `[BROWSE] letter=${letter}`);
        res.writeHead(302, { Location: `/search?letter=${encodeURIComponent(letter)}` });
      }
      return res.end();
    }
    if (reqUrl.pathname === '/new-release' || reqUrl.pathname === '/new-releases') {
      log(req.method, reqUrl.pathname, 302, '[BROWSE] sort=recent');
      res.writeHead(302, { Location: '/search?sort=recent' });
      return res.end();
    }
    if (reqUrl.pathname === '/latest-updated') {
      log(req.method, reqUrl.pathname, 302, '[BROWSE] sort=updated');
      res.writeHead(302, { Location: '/search?sort=updated' });
      return res.end();
    }
    if (reqUrl.pathname === '/most-viewed') {
      log(req.method, reqUrl.pathname, 302, '[BROWSE] sort=popular');
      res.writeHead(302, { Location: '/search?sort=popular' });
      return res.end();
    }

    // ========== ROUTE: /random (redirect to a random anime) ==========
    if (reqUrl.pathname === '/random') {
      try {
        const media = await anilistRandom();
        if (!media || !media.id) throw new Error('no random anime found');
        log(req.method, reqUrl.pathname, 302, `[RANDOM] → anilistId=${media.id}`);
        res.writeHead(302, { Location: `/watch?anilistId=${media.id}` });
        return res.end();
      } catch (err) {
        log('RANDOM_ERR', reqUrl.pathname, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        return res.end('Could not fetch a random anime. Try again.');
      }
    }

    // ========== ROUTE: Static files ==========
    log(req.method, reqUrl.pathname, 200, `[STATIC] ${(Date.now() - startTime).toFixed(0)}ms`);
    return serveStatic(reqUrl, res, req);

  } catch (err) {
    log('FATAL', reqUrl.pathname, 500, err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
});

// ========================
// MIRURO SIDECAR SPAWN
// The pipe behind Cloudflare needs curl_cffi (browser TLS). Launch
// miruro_sidecar.py alongside the server unless MIRURO_SIDECAR_URL is set.
// ========================
function startMiruroSidecar() {
  if (process.env.MIRURO_SIDECAR_URL) {
    console.log('\x1b[33m[MIRURO]\x1b[0m Using external sidecar at', MIRURO_SIDECAR_URL);
    return;
  }
  const { spawn } = require('child_process');
  const python = process.env.PYTHON || 'python';
  console.log('\x1b[33m[MIRURO]\x1b[0m Spawning miruro sidecar (playwright/curl_cffi) with', python);
  const child = spawn(python, [path.join(ROOT, 'miruro_sidecar.py')], {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const tag = (buf) => String(buf).split('\n').filter(Boolean).forEach((line) => {
    console.log('\x1b[33m[MIRURO]\x1b[0m', line);
  });
  child.stdout.on('data', tag);
  child.stderr.on('data', tag);
  child.on('error', (err) => {
    console.warn('\x1b[33m[MIRURO]\x1b[0m Could not start curl_cffi sidecar:', err.message);
    console.warn('[MIRURO] Miruro servers will be unavailable. Install with: pip install curl_cffi');
  });
  child.on('exit', (code) => {
    if (code && code !== 0) {
      console.warn(`\x1b[33m[MIRURO]\x1b[0m sidecar exited (code ${code}). Install: pip install curl_cffi`);
    }
  });
  process.on('exit', () => child.kill());
  process.on('SIGINT', () => child.kill());

  // Verify the sidecar actually answers before first use.
  (async () => {
    for (let i = 0; i < 10; i++) {
      try {
        const res = await fetch(`${MIRURO_SIDECAR_URL}/health`, { signal: AbortSignal.timeout(1500) });
        if (res.ok) {
          console.log('\x1b[32m[MIRURO]\x1b[0m curl_cffi sidecar is up at', MIRURO_SIDECAR_URL);
          return;
        }
      } catch { /* not ready yet */ }
      await new Promise((r) => setTimeout(r, 800));
    }
    console.warn('\x1b[33m[MIRURO]\x1b[0m sidecar did not become healthy in time; miruro servers may be unavailable.');
  })();
}

// ========================
// ERROR HANDLING & STARTUP
// ========================
server.on('error', (err) => {
  console.error('\x1b[31mServer error:\x1b[0m', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Try a different port.`);
    process.exit(1);
  }
});

server.on('clientError', (err, socket) => {
  console.error('\x1b[33mClient error:\x1b[0m', err.message);
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, () => {
  startMiruroSidecar();
  console.log('');
  console.log('\x1b[36m╔════════════════════════════════════════════╗');
  console.log('║      🎌 AnimeKai - Backend Server 🎌       ║');
  console.log('╠════════════════════════════════════════════╣');
  console.log(`║  Local:    \x1b[4mhttp://localhost:${PORT}/\x1b[0m\x1b[36m          ║`);
  console.log('╚════════════════════════════════════════════╝');
  console.log('\x1b[0m');
  console.log('Routes:');
  console.log('  \x1b[32mGET\x1b[0m  /              → home.html');
  console.log('  \x1b[32mGET\x1b[0m  /home           → home.html');
  console.log('  \x1b[32mGET\x1b[0m  /watch?slug=... → watch.html');
  console.log('  \x1b[32mGET\x1b[0m  /player?url=... → player.html');
  console.log('  \x1b[32mGET\x1b[0m  /proxy?url=...  → generic URL proxy');
  console.log('  \x1b[32mGET\x1b[0m  /proxy-video?url=...  → video/embed proxy (strips X-Frame-Options)');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/resolve?slug=...   → slug → AniList ID');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/servers?anilistId=&episode=  → miruro providers');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/stream?anilistId=&provider=&category=&episode= → HLS sources');
  console.log('  \x1b[32mGET\x1b[0m  /health         → health check');
  console.log(`  \x1b[33mGate\x1b[0m  Access control: ${ACCESS_TOKEN ? 'ON (login required)' : 'OFF (open)'}`);
  console.log('');
});

