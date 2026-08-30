# animesite

A lightweight anime streaming web app with a Node.js backend, static frontend pages, and multiple anime source integrations.

## Features

- Browse anime by trending, popularity, season, genre, status, and A-Z
- Search anime titles
- View anime details, characters, related shows, and recommendations
- Support for multiple stream/source providers
- Built-in proxy routes for embeds and HLS playback
- Optional access token protection
- Rate limiting and basic security protections

## Tech Stack

- **Backend:** Node.js (CommonJS)
- **Frontend:** Static HTML/CSS/JavaScript
- **Anime data:** AniList GraphQL API
- **Streaming integrations:** Miruro, AnimeX, MegaPlay, VidPlay, YouTube
- **Deployment:** Docker / Render support

## Project Structure

- `server.js` — main HTTP server, API routes, static file serving, and proxy logic
- `animex.js` — AnimeX provider integration and caching helpers
- `miruro_sidecar.py` — Python sidecar used for Miruro requests when needed
- `public/` — frontend pages and assets
- `Dockerfile` — container build configuration
- `docker-compose.yml` — local container orchestration
- `render.yaml` — Render deployment configuration

## Getting Started

### Prerequisites

- Node.js 18+
- npm
- Python 3 if you want to use the Miruro sidecar

### Install

```bash
npm install
```

### Run locally

```bash
npm start
```

The app will start on port `3000` by default.

## Environment Variables

- `PORT` — server port
- `ACCESS_TOKEN` — optional token required for access
- `MIRURO_SIDECAR_URL` — custom sidecar URL if you do not want to spawn the local Python process
- `MIRURO_SIDECAR_PORT` — port used by the Python sidecar
- `PYTHON` — Python executable used to launch the sidecar
- `FREE_TIER` — enables more conservative rate limits and timeouts

## Available Routes

- `/` — landing page
- `/home` — home page
- `/watch?slug=...` — watch page
- `/player?url=...` — player page
- `/proxy?url=...` — generic proxy
- `/proxy-video?url=...` — video/embed proxy
- `/api/home/recently-released`
- `/api/anime/search?q=...`
- `/api/browse`
- `/api/catalog`
- `/api/schedule`
- `/api/miruro/*`
- `/api/animex/*`
- `/api/megap/stream`
- `/api/apiplayer/stream`
- `/api/youtube/search`
- `/health`

## Notes

This project appears to be a fork/custom anime site backend. If you want, I can also tailor the README to include:

- screenshots
- deployment instructions for Render
- API documentation
- a more polished project description/name

