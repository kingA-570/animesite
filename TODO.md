# Backend Server Update

## Miruro Integration (added)

- [x] **`/api/miruro/resolve?slug=`** — maps an anikaitv slug → AniList ID (searches AniList GraphQL with progressively shorter title candidates + fuzzy scoring). Cached in memory.
- [x] **`/api/miruro/servers?anilistId=&episode=`** — hits miruro's `secure/pipe`, decodes episode ids, returns every provider/category that has the requested episode.
- [x] **`/api/miruro/stream?anilistId=&provider=&category=&episode=`** — resolves the HLS `streams[0].url` + subtitles + skip timestamps.
- [x] **Pipe protocol** implemented in `server.js`: `GET /api/secure/pipe?e=<base64url(json)>` → `base64url(gzip(json))`. No real encryption.
- [x] **`/proxy-video?referer=`** — new optional param; HLS manifests are rewritten so segments/playlists all flow through the proxy with the correct Referer (verified against test-streams.mux.dev).
- [x] **watch.html** — "MIRURO" section in the Servers panel with `provider · sub/dub` buttons per episode.

### ✅ Cloudflare blocker RESOLVED
- [x] **`miruro_sidecar.py`** — local HTTP sidecar (127.0.0.1:8765) that proxies the miruro pipe via `curl_cffi` (Chrome TLS impersonation), defeating the 403. Auto-spawned by `server.js`; falls back to direct `fetch` if absent.
- [x] **Stream proxy cracked** — `vault-*.uwucdn.top` CDN is also Cloudflare-gated, but the miruro player proxies it through `s1.watami.win` (or `s1.piltover.li`) using an obfuscated URL: `{proxy}/{XOR-b64(hlsUrl)}~{XOR-b64(refererOrigin)}/pl.m3u8`. Key is `a54d389c18527d9fd3e7f0643e27edbe`. `buildMiruroPlayableUrl()` in `server.js` replicates it.
- [x] **Playback verified** — `watami` serves playlist + AES-128 key + segments with `Access-Control-Allow-Origin: *`, so `player.html`'s hls.js loads the obfuscated URL **directly** (no server-side streaming proxy). Verified: 200 playlist (151 segs), 200 segment, and live playback via headless Chromium (currentTime advanced).
- [x] `/api/miruro/stream` now returns `m3u8Url` (the playable watami URL). `watch.html` selects it directly.

### Auto-fallback when anikaitv is down
- [x] `/api/miruro/episodes?anilistId=` — full episode list (all numbers, merged across providers).
- [x] `watch.html` — when the anikaitv episode list fails/returns empty, it auto-falls back to miruro episodes, auto-selects the requested episode (parsed from `/ep-N`), and auto-plays the first miruro source that has an HLS stream (tries each source in order).
- [x] Verified live: one-piece ep 40 → 1190 episode buttons, `ally:sub` auto-picked, playback confirmed (currentTime advances).

### Interactive player gestures (miruro-style) — player.html
- [x] **Tap-to-seek**: tap left third → back 10s, right third → forward 10s (with animated seek indicator showing target time). Works with mouse + touch.
- [x] **Hold & drag to scrub**: press-and-hold (or drag) on the video drags/scrolls the playhead across the episode in real time with a position indicator.
- [x] **Middle tap** toggles play/pause with a center flash animation; native browser click-toggle suppressed to avoid double toggling.
- [x] All verified via Playwright: tap ±10s, mouse drag (3s→603s), real CDP touch drag, play/pause toggle.

### MegaPlay (megaplay.buzz) integration — anikaitv-family native source
- [x] **Endpoints mapped**: megaplay.buzz player page `/stream/ani/{anilistId}/{ep}/{lang}` (works with any Referer present; `ani`/`mal`/`s-2` all map to the same file id). `#megaplay-player` div exposes `data-id`; `GET /stream/getSourcesNew?id={dataId}` returns `{sources.file (HLS), tracks, intro/outro}`.
- [x] **`/api/megap/stream?anilistId=&episode=&lang=`** — server.js endpoint: fetches embed page → extracts `data-id` → `getSourcesNew` → returns `m3u8Url`, `referer`, tracks, skip timestamps.
- [x] **Referer rule solved**: stream CDN `megap.kotocdn.site` returns 403 unless `Referer: https://megaplay.buzz/` — so the HLS is served through `/proxy-video?url=...&referer=https://megaplay.buzz/`, which rewrites manifests and proxies segments. Verified full chain: master → variant → segment all 200.
- [x] **watch.html**: "MEGA PLAY" section with Sub/Dub buttons (rendered for any episode once anilistId is known); plays via player.html with the proxied URL. `retryLastServer()` handles retry across megap/miruro/anikaitv.
- [x] **player.html HLS bug fixed**: some Chromium builds report `"maybe"` for `canPlayType('application/vnd.apple.mpegurl')` but can't actually play it, so the player was taking the broken native-HLS path. Now it always prefers hls.js when MSE is available (native only as last resort).
- [x] **`rewriteM3u8`**: now also rewrites `URI="..."` inside `#EXT-X-I-FRAME-STREAM-INF` / `#EXT-X-MEDIA` lines (previously left dangling → 404 iframes requests).
- [x] Verified end-to-end via headless Chromium: `/watch/one-piece-odmau/ep-40` → 1190 ep buttons → MegaPlay Sub → video plays (duration 1477s, currentTime advancing).

### Prerequisite
`pip install curl_cffi` must be present in the Python used to run `miruro_sidecar.py` (env `PYTHON` overrides the interpreter; `MIRURO_SIDECAR_URL` points at an external sidecar; `MIRURO_PROXY_BASE` swaps the proxy prefix).

## anikaitv-style watch page + miruro features (added)

### Info sidebar (AniList)
- [x] `/api/miruro/resolve` now also returns `resolved.info` — full AniList Media object (poster `coverImage`, title, description, genres, format, status, episodes, duration, seasonYear, averageScore) via a new `anilistMediaInfo(id)` GraphQL query.
- [x] **watch.html info sidebar** (right of the player, anikaitv `w-side-section` style): poster, title, score, meta badges (format/episodes/duration/year/status), genre chips, synopsis. Populated from the resolve response; falls back gracefully.

### Controls bar (anikaitv `#controls` style)
- [x] **watch.html** gains a controls bar under the player: prev/next episode buttons, current episode name + type, and toggles — **Auto Play**, **Auto Next**, **Auto Skip** (persisted to localStorage), a **skip-time dropdown** (60/90/120/150s), **Light mode** (brightness filter on the player), and **Expand** (fullscreen).
- [x] Settings persist via `localStorage` (`ak_autoPlay` / `ak_autoNext` / `ak_autoSkip` / `ak_skipTime`).
- [x] **player.html**: `?autoplay=0` disables auto-start; `?step=N` sets the seek step for the ±/forward/rewind controls; both are tunable at runtime through the `player-settings` postMessage (`{ autoSkip, step, autoplay }`).
- [x] **player.html skip buttons**: animated "Skip Intro" / "Skip Outro" buttons appear while the video is in a skip window (from `?skipIntro=start-end` / `?skipOutro=start-end`); **Auto Skip** (via `?autoSkip=1` or the `player-settings` message) seeks past the window automatically. Per-provider votes from aniskip are used to pick the intro/outro windows.
- [x] **player.html auto-next**: posts `{ type: 'video-ended' }` to the parent on `ended`. watch.html listens (origin + frame-source checked) and, when **Auto Next** is on, loads the next episode and **resumes the same source type** (MegaPlay lang, miruro provider/category, or embed host).

### Miruro embed servers (fixed "why aren't embed servers showing?")
- [x] `/api/miruro/embeds?anilistId=&episode=` — new server.js endpoint. Collects every `type: "embed"` stream across all providers for an episode (parallel source fetches, deduped by URL, 10-min cache).
- [x] **watch.html** renders a "MIRURO EMBED" section listing each unique embed host as a clickable server button (known-good hosts first, e.g. animegg/vivibebe/otakuhg/otakuvid/bibiemb; known-broken last: kwik/anidb/vidtube/playmogo).
- [x] Embed servers play in the player iframe through `/proxy-video` (strips frame-blocking headers). Verified working hosts: `www.animegg.org`, `vivibebe.site`, `otakuhg.site`, `otakuvid.online`, `bibiemb.xyz`. `kwik.cx` blocks headless with a security page; `anidb.app`/`vidtube.site`/`playmogo.com` fail to serve video.
- [x] Skip windows are wired for HLS sources: MegaPlay uses its `intro/outro`, miruro uses aniskip `op`/`ed` (highest-votes entries, incl. `mixed-op`/`mixed-ed`).

### Verification (headless Chromium, 32/32 checks)
- [x] 1190 episode buttons; info sidebar populated (poster/title/meta/synopsis).
- [x] Controls bar present; skip-time dropdown persists (`localStorage ak_skipTime=90`); light toggle adds `light-on` class.
- [x] MEGA PLAY (2), MIRURO (13), MIRURO EMBED (11 hosts incl. animegg) sections all render.
- [x] Clicking the animegg embed plays it via `/proxy-video` iframe with active state.
- [x] MegaPlay Sub → `player.html` with `autoplay`, `step`, `skipIntro=0-111`, `skipOutro=1373-1447` params; HLS video actually playing.
- [x] `player-settings` message accepted; `video-ended` from the player iframe advances episode 40→41 and resumes MegaPlay.
- [x] Note: rapid repeated test runs can hit the 120 req/min rate limiter (429); wait a minute between runs.

### anikaitv-style player skin + quality/speed controls (player.html)
- [x] **player.html rewritten** to a Vidstream/anikaitv-style skin: full-bleed poster backdrop (`?poster=`) with gradient, big center play button, custom seek bar (buffer fill, progress fill, draggable thumb, buffered-range hover), bottom gradient controls + top bar with back button and episode title.
- [x] **Settings menu** — gear button opens a menu with **Playback Speed** (0.25x–2x) and **Quality** (Auto + per-level picker from `hls.levels`, re-rendered on `LEVEL_SWITCHED`; selection sets `hls.currentLevel`).
- [x] **Menu bugs fixed**: menu-item clicks now `stopPropagation()` (clicked item is detached by re-render before the document "click-outside" handler ran, self-closing the menu), and the 600ms "return to main" timer is cancelled on every `renderMenu` (stale timer was reverting the menu mid-navigation).
- [x] **watch.html** passes `?poster=` (anilist banner/cover via `applyInfo`) and full episode title to the player.
- [x] Verified headless (11/11): poster param + poster div, big-play, custom seek bar, settings menu opens, speed submenu (7 speeds) applies `playbackRate=1.5`, quality submenu lists levels (Auto/1080p for megap single-level stream) and applies selection.
- [x] Controls-bar toggle labels in watch.html fixed: removed Bootstrap `custom-control-label` classes that were breaking the button CSS (plain label + right-aligned toggle switch).

### Player UI polish (anikaitv/miruro parity)
- [x] **No more black shadow over the video**: removed the always-on `:hover` visibility rules and the heavy `rgba(0,0,0,0.92)` bottom gradient. Controls (both bars) now appear only on mouse activity and **auto-hide after 2.5s idle** (`showControls` manages `#controls` + `#controls-top` together, `hideControls` clears the timer). Poster + top gradients lightened.
- [x] **Quality menu sorted 1080p-first** (descending by height, then Auto last), mirroring miruro's order; active option shows a ✓ checkmark, accent switched to anikaitv's `#b5a8ff`.
- [x] **Settings menu** restyled Vidstack-style: translucent `rgba(14,14,20,.92)` + `backdrop-filter: blur(14px)`, `#ffffff1a` border, rounded items.
- [x] **watch.html controls bar** restyled: each `.ctrl` is a pill (`#1a1f35` bg + border), toggle switches moved to the **right** of the label (`row-reverse`), icons fixed-width & centered, skip dropdown embedded cleanly.
- [x] Verified headless: toggle switch sits right of label, pills styled, controls show on mousemove → auto-hide after idle → re-show on hover, quality list `1080p | Auto`, speed applies.

### vidtube.site embed servers now play (kotocdn-family embed → HLS)
- [x] vidtube.site (and megaplay.buzz) embeds share the MegaPlay mechanism (`#megaplay-player` `data-id` + `/stream/getSourcesNew`). New server.js helper `embedToHls(embedUrl)` resolves any kotocdn-family embed URL into a real HLS stream (10-min cache); new route **`/api/embed-stream?url=`**.
- [x] `/api/miruro/embeds` now tags each embed with `kind: 'hls' | 'iframe'` so the frontend knows which embeds resolve to a playable stream.
- [x] watch.html: kotocdn embeds are sorted to the top of the MIRURO EMBED list and play through **player.html** with `/proxy-video?url=&referer=` (HLS + skip windows) instead of a raw iframe; iframe fallback if resolution fails. HLS embeds show a purple `HLS` badge. vidtube.site removed from the known-broken list (verified HLS on `vidtub.kotocdn.site`, Referer `https://vidtube.site/`, CORS `*`).

### Subtitle options for MEGA PLAY / HLS servers
- [x] megap HLS manifests carry **no** embedded `#EXT-X-MEDIA` subtitles — subs come only from the external `tracks` (VTT) returned by `getSourcesNew`; miruro sources return no subtitle files.
- [x] **player.html**: new `?subs=` param (JSON `[{label, lang, file, default}]`). Tracks are added as `<track>` elements before HLS load; the flagged-default track shows automatically. New **CC button** (toggles subtitles, `c` shortcut, active state) + **Subtitles submenu** in Settings (Off + each track, ✓ active).
- [x] **watch.html**: `selectMegapServer` and the kotocdn `embedStream` path now pass the stream's `tracks` to the player, with each VTT proxied through `/proxy-video?url=&referer=` (kotocdn 403s without Referer).
- [x] **server.js**: `/proxy-video` now forces `Content-Type: text/vtt` for `.vtt` URLs (CDN sends `application/octet-stream`, which browsers refuse in `<track>`).
- [x] Verified headless (8/8): `subs=` param present, track element created + auto-shown (default), CC toggles showing↔hidden, Settings → Subtitles menu lists Off/English, selecting Off hides, proxied VTT returns `200 | text/vtt | WEBVTT`.

## Status: ✅ COMPLETE

## Completed Steps

### Backend (`server.js`) - Complete Rewrite

- [x] **Proxy/API**: Full reverse proxy for all `/ajax/`, `/auth/`, `/social-auth/` paths → `https://anikaitv.to`
  - Handles GET, POST, PUT, PATCH, DELETE methods
  - POST body forwarding for login/register/search forms
  - Cookie forwarding to maintain sessions
  - Proper redirect handling (301/302/307/308)
  - Timeout protection (30s upstream timeout)

- [x] **Generic URL Proxy**: Enhanced `/proxy?url=...` endpoint
  - Allows any http/https URL (not just anikaitv.to)
  - Compression support
  - Better error handling and timeout

- [x] **Video/Embed Proxy**: NEW `/proxy-video?url=...` endpoint
  - Strips `X-Frame-Options` and `Content-Security-Policy` frame-ancestors headers
  - Follows redirects (up to 5 hops)
  - Passes proper Referer/Origin headers for video CDNs
  - Preserves content-type, content-length, accept-ranges for video seeking
  - CORS headers for cross-origin video loading

- [x] **Static File Serving**: Improved static file handler
  - Caching headers (html: no-cache, css/js: 1 day, images: 1 week, fonts: 30 days)
  - Gzip compression for text-based assets
  - Route rewrites: `/` → `home.html`, `/home` → `home.html`
  - Watch URL handling: `/watch/slug/ep-1` → redirects to `watch.html?slug=slug/ep-1`

- [x] **Rate Limiting**: Added per-IP rate limiting (120 req/min)
  - Memory store with automatic cleanup every 5 minutes
  - Returns 429 with Retry-After header when exceeded

- [x] **CORS**: Applied to all responses
  - Full CORS support with credentials
  - Proper OPTIONS preflight handling
  - Exposes Set-Cookie header

- [x] **Logging**: Colorful console logging
  - Timestamp, HTTP method, status code, path
  - Color-coded by status code family
  - Proxy destinations and timing info

- [x] **Health Check**: `/health` or `/api/health` endpoint
  - Returns status, uptime, and memory usage

- [x] **Error Handling**: Server-level error handlers
  - Port-in-use detection
  - Client error handling (bad requests)
  - Detailed error logging

### Frontend (`watch.html`) - Updated

- [x] **Uses direct `/ajax/*` proxy paths** instead of double-proxying through `/proxy?url=`
  - Episode list: `/ajax/episode/list/{slug}`
  - Server list: `/ajax/server/list?servers={ids}`
  - Server URL: `/ajax/server?get={linkId}`
  - Improves performance by avoiding unnecessary proxy hop

- [x] **FIXED `fetchWithProxy` to handle relative paths correctly**
  - Previously, relative `/ajax/*` paths were wrapped in `/proxy?url=/ajax/...` which failed
  - Now passes relative paths through as-is to use server.js's built-in `/ajax/*` proxy
  - Only wraps external (non-anikaitv.to) URLs in `/proxy?url=`

- [x] **FIXED JSON-wrapped HTML response handling**
  - Added `extractHtmlFromResponse()` function to detect and unwrap JSON `{"result": "<html>..."}` responses
  - anikaitv.to AJAX endpoints return JSON wrapping HTML content
  - Both `loadEpisodes()` and `loadServers()` now properly extract HTML before DOM parsing

- [x] **Embed/video URLs proxied through `/proxy-video`**
  - Strips frame-blocking headers so embeds load in iframe
  - Works with vidplay, megacloud, gogoanime, and other embed providers
  - Also proxies direct video URLs for proper CORS/Referer

- [x] **Removed dependency on public CORS proxies**
  - No more `https://api.allorigins.win/` or unreliable public proxies
  - All traffic flows through the local backend server

- [x] **Better embed URL detection**
  - Expanded patterns: embed, player.php, player.html, megacloud, gogoanime, east, west, server
  - Regex pattern for path-based embeds

## How to Run

```bash
node server.js
```

Server starts at `http://localhost:3000/`

