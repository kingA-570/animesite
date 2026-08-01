const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const { URL } = require('url');
const zlib = require('zlib');

// ========================
// CONFIGURATION
// ========================
const PORT = process.env.PORT || 3000;
const ROOT = process.cwd();
const TARGET_BASE = 'https://anikaitv.to';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

// Optional access protection: if ACCESS_TOKEN is set, every page/API requires
// it (as ?token=..., Authorization: Bearer, or by logging in at /login which
// sets a cookie). Leave unset for a fully open site.
const ACCESS_TOKEN = process.env.ACCESS_TOKEN || '';

// Miruro scraping config
const MIRURO_BASE = 'https://www.miruro.to';
const MIRURO_PIPE_URL = `${MIRURO_BASE}/api/secure/pipe`;
const ANILIST_GRAPHQL = 'https://graphql.anilist.co';
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
const RATE_LIMIT_MAX = 120; // max requests per window per IP

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

function shouldCompress(res, req) {
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

function miruroDecodePipe(body) {
  const compressed = b64urlDecode(body.trim());
  const json = zlib.gunzipSync(compressed).toString('utf8');
  return JSON.parse(json);
}

// Route the pipe request through the local Python (curl_cffi) sidecar, which
// carries a real Chrome TLS fingerprint. Falls back to Node fetch so the
// server still works standalone (that path will 403 behind Cloudflare).
async function miruroPipeRequest(payload) {
  const encoded = b64urlEncode(JSON.stringify(payload));

  try {
    const sidecar = await fetch(`${MIRURO_SIDECAR_URL}/pipe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ e: encoded }),
      signal: AbortSignal.timeout(40000),
    });
    const result = await sidecar.json();

    if (result.status === 200 && result.body) {
      return miruroDecodePipe(result.body);
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

  return miruroDecodePipe(await response.text());
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

async function miruroFetchEpisodes(anilistId) {
  const data = await miruroPipeRequest({
    path: 'episodes',
    method: 'GET',
    query: { anilistId: Number(anilistId) },
    body: null,
    version: '0.1.0',
  });
  return deepTranslateId(data);
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
    version: '0.1.0',
  };
  return miruroPipeRequest(payload);
}

// Collect every embed server (kwik, vidtube, anidb, animegg, ...) across all
// providers for an episode, deduplicated by URL. Runs the per-provider source
// fetches in parallel; caches the result for 10 minutes.
const miruroEmbedsCache = new Map();

// kotocdn-family hosts share the MegaPlay embed mechanism (#megaplay-player
// data-id + /stream/getSourcesNew) and can be resolved to a real HLS stream.
const KOTOCDN_EMBED_HOSTS = ['vidtube.site', 'megaplay.buzz'];

async function miruroFetchAllEmbeds(anilistId, episode) {
  const cacheKey = `${anilistId}:${episode}`;
  if (miruroEmbedsCache.has(cacheKey)) return miruroEmbedsCache.get(cacheKey);

  const data = await miruroFetchEpisodes(anilistId);
  const providers = data.providers || {};
  const jobs = [];
  for (const [provider, providerData] of Object.entries(providers)) {
    const epGroups = providerData?.episodes || {};
    for (const [category, epList] of Object.entries(epGroups)) {
      if (!Array.isArray(epList)) continue;
      const found = epList.find(ep => Number(ep.number) === episode);
      if (found && found.id) jobs.push({ provider, category, episodeId: found.id });
    }
  }

  const embeds = [];
  const seen = new Set();
  await Promise.allSettled(jobs.map(async (job) => {
    try {
      const sources = await miruroFetchSources(anilistId, job.provider, job.category, job.episodeId);
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
          kind: KOTOCDN_EMBED_HOSTS.includes(host) ? 'hls' : 'iframe',
        });
      }
    } catch { /* skip providers that fail to fetch */ }
  }));

  const result = { embeds };
  miruroEmbedsCache.set(cacheKey, result);
  setTimeout(() => miruroEmbedsCache.delete(cacheKey), 10 * 60 * 1000);
  return result;
}

// Map an anikaitv slug (e.g. "one-piece-odmau") to an AniList ID by
// searching AniList with progressively shorter title candidates.
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

async function anilistMediaInfo(id) {
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
  return json?.data?.Media || null;
}

async function anilistSearch(queryTitle) {
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
  return (json?.data?.Page?.media) || [];
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
  return best;
}

// ========================
// STATIC FILE SERVING
// ========================
const CACHE_MAX_AGE = {
  '.html': 'no-cache, no-store, must-revalidate, max-age=0',
  '.css': '86400',
  '.js': '86400',
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
    if (pathname === '/' || pathname === '/home') pathname = '/home.html';
    if (pathname === '/animeverse' || pathname === '/animeverse.html') pathname = '/home.html';
    if (pathname === '/watch' || pathname === '/watch/') pathname = '/watch.html';
    if (pathname === '/player' || pathname === '/player/') pathname = '/player.html';

    // Handle /watch/ path with slug - redirect to watch.html?slug=...
    const watchMatch = pathname.match(/^\/watch\/([^/]+)(?:\/([^/]+))?$/);
    if (watchMatch) {
      const slug = watchMatch[1];
      const epPart = watchMatch[2] ? `/${watchMatch[2]}` : '';
      const redirectUrl = `/watch.html?slug=${slug}${epPart}`;
      res.writeHead(302, { Location: redirectUrl });
      return res.end();
    }

    const filePath = path.join(ROOT, decodeURIComponent(pathname));
    const resolvedPath = path.resolve(filePath);

    // Security: prevent directory traversal
    if (!resolvedPath.startsWith(ROOT)) {
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
    if (shouldCompress(res, req)) {
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
// REVERSE PROXY TO ANIKAITV.TO
// ========================
async function proxyToAnikai(reqUrl, res, req, bodyBuffer) {
  // Build the target URL
  const targetPath = reqUrl.pathname + (reqUrl.search || '');
  const targetUrl = `${TARGET_BASE}${targetPath}`;

  // Build headers for proxied request
  const headers = {
    'User-Agent': USER_AGENT,
    'Accept': req.headers['accept'] || '*/*',
    'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'Referer': `${TARGET_BASE}/`,
    'Origin': TARGET_BASE,
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
  };

  // AnimeKai's ajax endpoints reject requests without X-Requested-With
  // (they answer 500 "Invalid Request"). Send it for every ajax call.
  if (reqUrl.pathname.startsWith('/ajax/')) {
    headers['X-Requested-With'] = 'XMLHttpRequest';
  }

  // Forward cookies if present
  if (req.headers['cookie']) {
    headers['Cookie'] = req.headers['cookie'];
  }

  // Forward content-type for POST/PUT requests
  if (bodyBuffer && bodyBuffer.length > 0) {
    headers['Content-Type'] = req.headers['content-type'] || 'application/x-www-form-urlencoded';
    headers['Content-Length'] = bodyBuffer.length;
    headers['X-Requested-With'] = 'XMLHttpRequest';
  }

  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: headers,
      body: bodyBuffer && bodyBuffer.length > 0 ? bodyBuffer : undefined,
      redirect: 'manual', // Handle redirects manually
      signal: AbortSignal.timeout(30000), // 30s timeout
    });

    // Get response data
    const body = await response.arrayBuffer();

    // Build response headers
    const proxyOrigin = req.headers['origin'];
    const resHeaders = {
      'Access-Control-Allow-Origin': proxyOrigin || '*',
    };
    if (proxyOrigin) {
      resHeaders['Vary'] = 'Origin';
      resHeaders['Access-Control-Allow-Credentials'] = 'true';
    }
    resHeaders['Access-Control-Expose-Headers'] = 'Set-Cookie';

    // Forward important response headers
    const forwardHeaders = [
      'content-type', 'content-length', 'set-cookie', 'cache-control',
      'x-robots-tag', 'x-frame-options', 'content-security-policy',
    ];
    for (const h of forwardHeaders) {
      const val = response.headers.get(h);
      if (val) {
        // Combine multiple Set-Cookie headers
        if (h === 'set-cookie') {
          resHeaders['Set-Cookie'] = val;
        } else {
          resHeaders[h] = val;
        }
      }
    }

    // Handle redirects
    const location = response.headers.get('location');
    if (location && (response.status === 301 || response.status === 302 || response.status === 307 || response.status === 308)) {
      // Rewrite redirect URL if it points to anikaitv.to
      let redirectUrl = location;
      if (redirectUrl.startsWith(TARGET_BASE)) {
        redirectUrl = redirectUrl.replace(TARGET_BASE, '');
      }
      resHeaders['Location'] = redirectUrl;
    }

    // Add compression if applicable
    if (shouldCompress(res, req) && body.byteLength > 1024) {
      const compressed = zlib.gzipSync(Buffer.from(body));
      resHeaders['Content-Encoding'] = 'gzip';
      resHeaders['Content-Length'] = compressed.length;
      delete resHeaders['content-length'];

      res.writeHead(response.status, resHeaders);
      return res.end(compressed);
    }

    res.writeHead(response.status, resHeaders);
    res.end(Buffer.from(body));
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      log('TIMEOUT', targetPath, 504);
      res.writeHead(504, { 'Content-Type': 'text/plain' });
      return res.end('Upstream server timed out');
    }

    log('PROXY_ERR', targetPath, 502, err.message);
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Proxy error: ' + err.message);
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
        'Referer': 'https://anikaitv.to/',
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
    // Allow callers to specify the Referer/Origin (e.g. miruro streams)
    const refererOverride = reqUrl.searchParams.get('referer');
    let referer = refererOverride || 'https://anikaitv.to/';
    let origin = refererOverride ? new URL(refererOverride).origin : 'https://anikaitv.to';

    const response = await fetch(target, {
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

async function megapStream(anilistId, episode, lang) {
  const pageResp = await fetch(`${MEGAP_BASE}/stream/ani/${anilistId}/${episode}/${lang}`, {
    headers: {
      'User-Agent': USER_AGENT,
      'Referer': MEGAP_PAGE_REFERER,
      'Accept': 'text/html,application/xhtml+xml,*/*',
    },
    signal: AbortSignal.timeout(30000),
  });
  if (!pageResp.ok) throw new Error(`megaplay page returned ${pageResp.status}`);
  const html = await pageResp.text();
  const dataId = (html.match(/data-id="(\d+)"/) || [])[1];
  if (!dataId) throw new Error('megaplay embed not synced for this anime/episode');

  const srcResp = await fetch(`${MEGAP_BASE}/stream/getSourcesNew?id=${dataId}`, {
    headers: {
      'User-Agent': USER_AGENT,
      'Referer': MEGAP_REFERER,
      'X-Requested-With': 'XMLHttpRequest',
      'Accept': 'application/json, text/javascript, */*; q=0.01',
    },
    signal: AbortSignal.timeout(30000),
  });
  if (!srcResp.ok) throw new Error(`megaplay sources returned ${srcResp.status}`);
  const data = await srcResp.json();
  if (!data?.sources?.file) throw new Error('megaplay returned no stream file');
  return {
    m3u8Url: data.sources.file,
    referer: MEGAP_REFERER,
    tracks: data.tracks || [],
    intro: data.intro || null,
    outro: data.outro || null,
    dataId,
  };
}

// Resolve a kotocdn-family embed URL (vidtube.site, megaplay.buzz, ...) into a
// real HLS stream: fetch the embed page -> data-id -> getSourcesNew. Cached.
const embedStreamCache = new Map();

async function embedToHls(embedUrl) {
  if (embedStreamCache.has(embedUrl)) return embedStreamCache.get(embedUrl);

  const pageUrl = new URL(embedUrl);
  const base = pageUrl.origin;
  const referer = base + '/';
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
  const dataId = (html.match(/data-id="(\d+)"/) || [])[1];
  if (!dataId) throw new Error('embed not synced for this episode (no data-id)');

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

  const result = {
    m3u8Url: data.sources.file,
    referer,
    tracks: data.tracks || [],
    intro: data.intro || null,
    outro: data.outro || null,
    dataId,
    embedUrl,
  };
  embedStreamCache.set(embedUrl, result);
  setTimeout(() => embedStreamCache.delete(embedUrl), 10 * 60 * 1000);
  return result;
}

// ========================
// HOME PAGE DATA FETCHERS
// ========================

// Fetch recently released / trending anime from AniList for the homepage
async function anilistHomeFeed() {
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
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) throw new Error(`AniList home fetch failed (${response.status})`);
  const json = await response.json();
  return json?.data?.Page?.media || [];
}

// Also try to fetch the anikaitv.to home page widgets directly
async function anikaiHomeWidget(widgetName, page = 1) {
  try {
    const response = await fetch(`${TARGET_BASE}/ajax/home/widget/${widgetName}?page=${page}`, {
      headers: {
        'User-Agent': USER_AGENT,
        'Referer': `${TARGET_BASE}/`,
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
      },
      signal: AbortSignal.timeout(15000),
    });
    if (response.status !== 200) return null;
    return await response.json();
  } catch {
    return null;
  }
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

// ========== ROUTE: /api/home/recently-released (AniList + anikaitv.to fallback) ==========
    if (reqUrl.pathname === '/api/home/recently-released') {
      try {
        // Try anikaitv.to first for each widget
        const [updated, releases, added, completed] = await Promise.allSettled([
          anikaiHomeWidget('updated-all', 1),
          anikaiHomeWidget('latest-releases', 1),
          anikaiHomeWidget('recently-added', 1),
          anikaiHomeWidget('newly-completed', 1),
        ]);

        const anikaiData = {
          updated: updated.status === 'fulfilled' && updated.value ? updated.value : null,
          releases: releases.status === 'fulfilled' && releases.value ? releases.value : null,
          added: added.status === 'fulfilled' && added.value ? added.value : null,
          completed: completed.status === 'fulfilled' && completed.value ? completed.value : null,
        };

        // Also fetch from AniList as a fallback / enrichment
        let anilistMedia = [];
        try {
          anilistMedia = await anilistHomeFeed();
        } catch { /* anilist optional */ }

        const formatted = anilistMedia.map(formatAnilistForHome);

        log(req.method, reqUrl.pathname, 200, `[HOME] anikaitv=${anikaiData.updated ? 'ok' : 'fail'} anilist=${formatted.length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          anikai: anikaiData,
          anilist: formatted,
          timestamp: new Date().toISOString(),
        }));
      } catch (err) {
        log('HOME_FEED_ERR', reqUrl.pathname, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, anikai: {}, anilist: [] }));
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
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ resolved }));
      } catch (err) {
        log('MIRURO_RESOLVE_ERR', slug, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, resolved: null }));
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
              const entry = byNumber.get(num) || { number: num, title: ep.title || '', duration: ep.duration || null, providers: {} };
              entry.providers[`${provider}:${category}`] = { id: ep.id };
              if (!entry.title) entry.title = ep.title || '';
              if (!entry.duration) entry.duration = ep.duration || null;
              byNumber.set(num, entry);
            }
          }
        }
        const episodes = [...byNumber.values()].sort((a, b) => a.number - b.number);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MIRURO]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ mappings: data.mappings || {}, anilistId, episodes }));
      } catch (err) {
        log('MIRURO_EPISODES_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message, episodes: [] }));
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
    if (reqUrl.pathname === '/api/megap/stream') {
      const anilistId = reqUrl.searchParams.get('anilistId');
      const episode = parseInt(reqUrl.searchParams.get('episode') || '', 10);
      const lang = reqUrl.searchParams.get('lang') || 'sub';
      if (!anilistId || isNaN(episode)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing anilistId and/or episode' }));
      }
      try {
        const stream = await megapStream(anilistId, episode, lang);
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[MEGAP]');
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
        log(req.method, reqUrl.pathname + reqUrl.search, 200, '[ANILIST]');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ resolved: { anilistId, title, info } }));
      } catch (err) {
        log('ANILIST_INFO_ERR', reqUrl.search, 502, err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
      }
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

    // ========== ROUTE: Proxy API calls to anikaitv.to ==========
    const proxyPaths = ['/ajax/', '/auth/', '/social-auth/'];
    const shouldProxy = proxyPaths.some(p => reqUrl.pathname.startsWith(p));

    if (shouldProxy) {
      let bodyBuffer = null;
      if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
        bodyBuffer = await getRequestBody(req);
      }

      log(req.method, reqUrl.pathname + reqUrl.search, 200, `[PROXY→${TARGET_BASE}]`);
      return proxyToAnikai(reqUrl, res, req, bodyBuffer);
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
  if (process.env.MIRURO_SIDECAR_URL) return;
  const { spawn } = require('child_process');
  const python = process.env.PYTHON || 'python';
  const child = spawn(python, [path.join(ROOT, 'miruro_sidecar.py')], {
    stdio: 'ignore',
    windowsHide: true,
  });
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
  console.log(`║  Proxying: \x1b[4m${TARGET_BASE}\x1b[0m\x1b[36m           ║`);
  console.log('╚════════════════════════════════════════════╝');
  console.log('\x1b[0m');
  console.log('Routes:');
  console.log('  \x1b[32mGET\x1b[0m  /              → home.html');
  console.log('  \x1b[32mGET\x1b[0m  /home           → home.html');
  console.log('  \x1b[32mGET\x1b[0m  /watch?slug=... → watch.html');
  console.log('  \x1b[32mGET\x1b[0m  /player?url=... → player.html');
  console.log('  \x1b[33mANY\x1b[0m  /ajax/*         → proxied to anikaitv.to');
  console.log('  \x1b[33mANY\x1b[0m  /auth/*         → proxied to anikaitv.to');
  console.log('  \x1b[33mANY\x1b[0m  /social-auth/*  → proxied to anikaitv.to');
  console.log('  \x1b[32mGET\x1b[0m  /proxy?url=...  → generic URL proxy');
  console.log('  \x1b[32mGET\x1b[0m  /proxy-video?url=...  → video/embed proxy (strips X-Frame-Options)');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/resolve?slug=...   → anikaitv slug → AniList ID');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/servers?anilistId=&episode=  → miruro providers');
  console.log('  \x1b[32mGET\x1b[0m  /api/miruro/stream?anilistId=&provider=&category=&episode= → HLS sources');
  console.log('  \x1b[32mGET\x1b[0m  /health         → health check');
  console.log('');
});

