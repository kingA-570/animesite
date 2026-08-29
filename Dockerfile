FROM node:22-bookworm-slim

# Python + curl_cffi for the miruro sidecar (browser TLS fingerprint)
# --only-binary prevents curl_cffi from trying to compile from source
# (that would require a Rust toolchain and fail the build).
# --break-system-packages: Debian's Python is PEP-668 "externally managed".
# Playwright/Chromium lets the sidecar pass Cloudflare's JS challenge from
# Render's datacenter IP (curl_cffi alone only works from residential IPs).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --break-system-packages --no-cache-dir --upgrade pip \
 && python3 -m pip install --break-system-packages --no-cache-dir --only-binary=:all: curl_cffi \
 && python3 -m pip install --break-system-packages --no-cache-dir playwright

# Chromium install is split out so a failure can never fail the deploy.
# We prefer the lean headless shell (`--only-shell`) which is ~40% smaller
# and stays under Render's free-tier 512MB disk/RAM; it's all Chromium's
# headless mode needs. Each step degrades gracefully:
#   deps fail  -> browser may still run (falls back at runtime if not)
#   shell fail -> try the full chromium download
#   that fails -> sidecar falls back to curl_cffi at runtime
RUN (python3 -m playwright install-deps chromium \
     || echo "WARNING: playwright deps failed; trying without deps") \
 && (python3 -m playwright install chromium --only-shell \
     || python3 -m playwright install chromium \
     || echo "WARNING: playwright chromium install failed; sidecar will fall back to curl_cffi")

WORKDIR /app

# No npm dependencies needed - server.js uses only Node built-ins
COPY package.json server.js db.js animex.js miruro_sidecar.py ./
COPY public/ ./public/

ENV PORT=3000 \
    PYTHON=python3 \
    NODE_ENV=production \
    # Keep the V8 heap bounded so the server shares the 512MB free-tier RAM
    # with the Python/Chromium sidecar instead of trying to grab it all.
    # --experimental-sqlite is required for node:sqlite (DatabaseSync) on Node 22
    NODE_OPTIONS="--max-old-space-size=192 --max-semi-space-size=16 --experimental-sqlite"
# Uncomment to require a token before anyone can use the site:
# ENV ACCESS_TOKEN=change-me-to-a-strong-random-string

EXPOSE 3000
CMD ["node", "server.js"]
