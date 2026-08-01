FROM node:20-bookworm-slim

# Python + curl_cffi for the miruro sidecar (browser TLS fingerprint)
# --only-binary prevents curl_cffi from trying to compile from source
# (that would require a Rust toolchain and fail the build).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir --upgrade pip \
 && python3 -m pip install --no-cache-dir --only-binary=:all: curl_cffi

WORKDIR /app

# No npm dependencies needed - server.js uses only Node built-ins
COPY package.json server.js miruro_sidecar.py ./
COPY home.html watch.html player.html animeverse.html ./
COPY style.css themes.css theme.js main.js ./
COPY logo.png HOMEPAGE.PNG TITLEBAR.PNG 12.mp4 ./

ENV PORT=3000 \
    PYTHON=python3 \
    NODE_ENV=production
# Uncomment to require a token before anyone can use the site:
# ENV ACCESS_TOKEN=change-me-to-a-strong-random-string

EXPOSE 3000
CMD ["node", "server.js"]
