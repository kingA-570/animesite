// AnimeX.one backend scraper.
//
// AnimeX.one is a publicly-accessible anime backend (SvelteKit frontend with a
// self-hosted API split across subdomains). It exposes unauthenticated REST
// endpoints that return ready-to-play m3u8 URLs and a slug<->anilistId mapping.
//
// Sub hosting (all reachable directly with a plain browser User-Agent):
//   pp.animex.one        - streaming/data REST (episodes, servers, sources)
//   graphql.animex.one   - GraphQL catalog + /api/recent + /api/schedule
//
// We use this as an OPTIONAL extra provider alongside Miruro/MegaPlay. Every
// call is cached so a page load doesn't fan out repeatedly.

const ANIMEX_PP = 'https://pp.animex.one';
const ANIMEX_GRAPHQL = 'https://graphql.animex.one';

const ANIMEX_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Accept': 'application/json',
  'Accept-Language': 'en-US,en;q=0.9',
};

async function animexFetch(url, timeout = 15000) {
  const res = await fetch(url, {
    headers: ANIMEX_HEADERS,
    redirect: 'follow',
    signal: AbortSignal.timeout(timeout),
  });
  if (res.status !== 200) {
    throw new Error(`AnimeX error (${res.status})`);
  }
  return res.json();
}

// ---------- slug <-> anilistId ----------
// A small LRU-style cache mapping anilistId -> animex slug. Populated from
// /api/recent pages (each item carries both). A slug is enough to call the
// episodes/servers/sources endpoints.
const slugCache = new Map();
let slugCacheScanned = false;

async function ensureSlugCache() {
  if (slugCacheScanned) return;
  try {
    for (let page = 1; page <= 4; page++) {
      const data = await animexFetch(`${ANIMEX_GRAPHQL}/api/recent?page=${page}`, 12000);
      const results = data && data.results;
      if (!Array.isArray(results)) break;
      for (const it of results) {
        if (it.id && it.anilistId) slugCache.set(Number(it.anilistId), it.id);
      }
      if (!data.hasNextPage || results.length === 0) break;
    }
    slugCacheScanned = true;
  } catch (err) {
    // non-fatal
  }
}

async function animexSlugForAnilist(anilistId) {
  const cached = slugCache.get(Number(anilistId));
  if (cached) return cached;
  await ensureSlugCache();
  return slugCache.get(Number(anilistId)) || null;
}

async function animexSetSlug(anilistId, slug) {
  if (anilistId && slug) slugCache.set(Number(anilistId), slug);
}

// ---------- episodes ----------
const episodesCache = new Map();
const ANIMEX_EPISODES_TTL = 20 * 60 * 1000;

async function animexEpisodes(anilistId) {
  const slug = await animexSlugForAnilist(anilistId);
  if (!slug) return { available: false, error: 'not-in-catalog', episodes: [] };
  const cacheKey = Number(anilistId);
  if (episodesCache.has(cacheKey)) return episodesCache.get(cacheKey);
  try {
    const data = await animexFetch(`${ANIMEX_PP}/rest/api/episodes?id=${encodeURIComponent(slug)}`, 18000);
    const res = {
      available: true,
      slug,
      episodes: Array.isArray(data) ? data : (data.episodes || []),
    };
    episodesCache.set(cacheKey, res);
    setTimeout(() => episodesCache.delete(cacheKey), ANIMEX_EPISODES_TTL);
    return res;
  } catch (err) {
    return { available: false, error: err.message, slug, episodes: [] };
  }
}

// ---------- servers ----------
const serversCache = new Map();
const ANIMEX_SERVERS_TTL = 20 * 60 * 1000;

async function animexServers(anilistId, episode) {
  const slug = await animexSlugForAnilist(anilistId);
  if (!slug) return { available: false, error: 'not-in-catalog', sub: [], dub: [] };
  const cacheKey = `${Number(anilistId)}:${Number(episode)}`;
  if (serversCache.has(cacheKey)) return serversCache.get(cacheKey);
  try {
    const data = await animexFetch(`${ANIMEX_PP}/rest/api/servers?id=${encodeURIComponent(slug)}&epNum=${Number(episode)}`, 15000);
    const sub = (data.subProviders || []).map((p) => ({ id: p.id, tip: p.tip, default: !!p.default }));
    const dub = (data.dubProviders || []).map((p) => ({ id: p.id, tip: p.tip, default: !!p.default }));
    const res = { available: true, slug, sub, dub };
    serversCache.set(cacheKey, res);
    setTimeout(() => serversCache.delete(cacheKey), ANIMEX_SERVERS_TTL);
    return res;
  } catch (err) {
    return { available: false, error: err.message, slug, sub: [], dub: [] };
  }
}

// ---------- sources ----------
const sourcesCache = new Map();
const ANIMEX_SOURCES_TTL = 25 * 60 * 1000;

async function animexSources(anilistId, episode, type, providerId) {
  const slug = await animexSlugForAnilist(anilistId);
  if (!slug) return { available: false, error: 'not-in-catalog' };
  const cacheKey = `${Number(anilistId)}:${Number(episode)}:${type}:${providerId}`;
  if (sourcesCache.has(cacheKey)) return sourcesCache.get(cacheKey);
  try {
    const data = await animexFetch(
      `${ANIMEX_PP}/rest/api/sources?id=${encodeURIComponent(slug)}&epNum=${Number(episode)}&type=${encodeURIComponent(type)}&providerId=${encodeURIComponent(providerId)}`,
      18000
    );
    const res = {
      available: true,
      sources: Array.isArray(data.sources) ? data.sources : [],
      tracks: data.tracks || null,
      audio: data.audio || null,
      chapters: data.chapters || [],
      headers: data.headers || {},
    };
    sourcesCache.set(cacheKey, res);
    setTimeout(() => sourcesCache.delete(cacheKey), ANIMEX_SOURCES_TTL);
    return res;
  } catch (err) {
    return { available: false, error: err.message };
  }
}

module.exports = {
  animexEpisodes,
  animexServers,
  animexSources,
  animexSlugForAnilist,
  animexSetSlug,
};
