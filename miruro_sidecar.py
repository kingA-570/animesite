import json
import os
import queue
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit


def process_memory_mb():
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, os.getpid())
            if not h:
                return -1.0
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb)
            ctypes.windll.kernel32.CloseHandle(h)
            if ok:
                return round(counters.WorkingSetSize / (1024 * 1024), 1)
            return -1.0
        with open(f"/proc/{os.getpid()}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return -1.0

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

try:
    from curl_cffi import requests
    HAS_CURL = True
except Exception:
    requests = None
    HAS_CURL = False

PORT = int(os.environ.get("MIRURO_SIDECAR_PORT", "8765"))
PIPE_URL = os.environ.get("MIRURO_PIPE_URL", "https://www.miruro.to/api/secure/pipe")
JWKS_URL = os.environ.get("MIRURO_JWKS_URL", "https://www.miruro.to/api/secure/jwks")

# A persistent headless Chromium grows memory over time (cached frames, V8
# heaps) which quickly exhausts Render's free-tier RAM. Recycle the browser
# after N requests or M seconds so memory stays flat.
MAX_REQUESTS_PER_BROWSER = int(os.environ.get("MIRURO_BROWSER_MAX_REQUESTS", "40"))
MAX_BROWSER_LIFETIME = int(os.environ.get("MIRURO_BROWSER_MAX_LIFETIME", "480"))
# Bound the job queue so a stuck page.evaluate can never grow the queue forever.
MAX_QUEUE_SIZE = int(os.environ.get("MIRURO_BROWSER_MAX_QUEUE", "16"))
# After this many consecutive browser errors, give up on the browser and fall
# back to curl_cffi instead of erroring every request.
BROWSER_MAX_CONSECUTIVE_ERRORS = int(os.environ.get("MIRURO_BROWSER_MAX_ERRORS", "3"))

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

# Flags that keep Chromium lean on a 512MB container. The most important are
# --disable-dev-shm-usage (no shared-memory tmpfs) and the V8 heap cap.
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--mute-audio",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-component-extensions-with-background-pages",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-hang-monitor",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=Translate,BackForwardCache",
    "--js-flags=--max-old-space-size=160",
]

HEADERS = {
    "User-Agent": USER_AGENT,
    "Referer": "https://www.miruro.to/",
    "Origin": "https://www.miruro.to",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "sec-ch-ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

ORIGIN = f"{urlsplit(PIPE_URL).scheme}://{urlsplit(PIPE_URL).netloc}"

_browser_state = {"warmed": False, "last_warm": 0, "error": None, "started": False, "init_done": False, "browser_failed": False, "consecutive_errors": 0}
_job_q = queue.Queue()
_RESP_OK = None

_FETCH_JS = """async ({ url }) => {
    const r = await fetch(url, { redirect: 'follow' });
    const text = await r.text();
    const hdrs = {};
    r.headers.forEach((v, k) => { hdrs[k] = v; });
    return { status: r.status, body: text, headers: hdrs };
}"""


def _warm(page, ctx):
    try:
        page.goto(ORIGIN + "/", wait_until="domcontentloaded", timeout=60000)
    except Exception:
        pass
    for _ in range(25):
        names = [c["name"] for c in ctx.cookies()]
        if "cf_clearance" in names:
            return True
        page.wait_for_timeout(2000)
    return False


def _fetch_on_page(page, ctx, url):
    if time.time() - _browser_state["last_warm"] > 12 * 60:
        _browser_state["warmed"] = False
    if not _browser_state["warmed"]:
        ok = _warm(page, ctx)
        _browser_state["warmed"] = ok
        _browser_state["last_warm"] = time.time()
        _browser_state["error"] = None if ok else "Cloudflare challenge did not clear"
        if not ok:
            raise RuntimeError(_browser_state["error"])
    result = page.evaluate(_FETCH_JS, {"url": url})
    if result.get("status") == 403:
        # token expired or a fresh challenge was issued — re-solve once
        _browser_state["warmed"] = False
        if _warm(page, ctx):
            _browser_state["warmed"] = True
            _browser_state["last_warm"] = time.time()
            result = page.evaluate(_FETCH_JS, {"url": url})
    return result


def _run_browser_cycle():
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True, args=BROWSER_ARGS)
    ctx = browser.new_context(user_agent=USER_AGENT, locale="en-US")
    page = ctx.new_page()
    return pw, browser, ctx, page


def _close_browser_cycle(pw, browser, ctx, page):
    try:
        page.close()
        ctx.close()
        browser.close()
        pw.stop()
    except Exception:
        pass


def _browser_worker():
    # A long-lived browser is the biggest memory hog on Render's free tier, so
    # the whole launch/warm/serve loop runs as a cycle that gets recycled.
    while True:
        try:
            pw, browser, ctx, page = _run_browser_cycle()
        except Exception as exc:
            _browser_state["browser_failed"] = True
            _browser_state["init_done"] = True
            _browser_state["error"] = f"browser launch failed: {exc}"
            print(f"[miruro_sidecar] {_browser_state['error']}; falling back to curl_cffi", flush=True)
            return
        _browser_state["started"] = True
        _browser_state["init_done"] = True
        _browser_state["consecutive_errors"] = 0
        cycle_start = time.time()
        cycle_requests = 0
        try:
            # Warm the Cloudflare challenge up front so the first request is fast.
            _browser_state["warmed"] = _warm(page, ctx)
            _browser_state["last_warm"] = time.time()
            _browser_state["error"] = None if _browser_state["warmed"] else "Cloudflare challenge did not clear"
            if not _browser_state["warmed"]:
                print("[miruro_sidecar] WARNING initial Cloudflare warmup failed", flush=True)
            else:
                print("[miruro_sidecar] Cloudflare challenge cleared (cf_clearance set)", flush=True)
        except Exception as exc:
            _browser_state["warmed"] = False
            _browser_state["error"] = f"warmup crashed: {exc}"
            print(f"[miruro_sidecar] WARNING {_browser_state['error']}", flush=True)

        while True:
            # Recycle the browser once it has served enough requests or lived
            # too long — closes the renderer processes and frees their memory.
            if cycle_requests >= MAX_REQUESTS_PER_BROWSER or (time.time() - cycle_start) > MAX_BROWSER_LIFETIME:
                break
            try:
                job = _job_q.get(timeout=1)
            except queue.Empty:
                continue
            if job is None:
                _close_browser_cycle(pw, browser, ctx, page)
                return
            url, ev, holder = job
            try:
                cycle_requests += 1
                holder["result"] = _fetch_on_page(page, ctx, url)
                _browser_state["consecutive_errors"] = 0
            except Exception as exc:
                _browser_state["consecutive_errors"] += 1
                holder["error"] = str(exc)
                if _browser_state["consecutive_errors"] >= BROWSER_MAX_CONSECUTIVE_ERRORS:
                    # Browser is in a bad state (crashed/OOM) — stop using it and
                    # let curl_cffi take over rather than erroring every request.
                    _browser_state["browser_failed"] = True
                    _browser_state["error"] = f"browser failed after {BROWSER_MAX_CONSECUTIVE_ERRORS} errors: {exc}"
                    print(f"[miruro_sidecar] {_browser_state['error']}; falling back to curl_cffi", flush=True)
            finally:
                ev.set()

        _browser_state["warmed"] = False
        _browser_state["last_warm"] = 0
        print("[miruro_sidecar] recycling browser to free memory", flush=True)
        _close_browser_cycle(pw, browser, ctx, page)


def _start_browser_worker():
    if not HAS_PLAYWRIGHT or _browser_state["started"]:
        return
    t = threading.Thread(target=_browser_worker, daemon=True)
    t.start()


def browser_fetch(url):
    if _browser_state["browser_failed"]:
        raise RuntimeError(_browser_state["error"] or "browser unavailable")
    # Wait briefly for Chromium to finish launching on cold start.
    for _ in range(20):
        if _browser_state["init_done"]:
            break
        time.sleep(0.5)
    if _browser_state["browser_failed"]:
        raise RuntimeError(_browser_state["error"] or "browser unavailable")
    if not _browser_state["init_done"]:
        raise RuntimeError("browser did not finish starting")
    if _job_q.qsize() >= MAX_QUEUE_SIZE:
        raise RuntimeError("sidecar busy (job queue full)")
    ev = threading.Event()
    holder = {}
    _job_q.put((url, ev, holder))
    if not ev.wait(timeout=120):
        raise RuntimeError("browser request timed out")
    if "error" in holder:
        raise RuntimeError(holder["error"])
    return holder["result"]


def curl_fetch(url):
    if not HAS_CURL:
        raise RuntimeError("curl_cffi not installed")
    resp = requests.get(url, headers=HEADERS, impersonate="chrome136", timeout=30)
    return {
        "status": resp.status_code,
        "body": resp.text if resp.status_code == 200 else resp.text[:300],
        "headers": {"x-obfuscated": resp.headers.get("x-obfuscated") or ""},
    }


def transport_available():
    return HAS_PLAYWRIGHT and not _browser_state["browser_failed"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {
                "ok": True,
                "transport": "browser" if transport_available() else "curl_cffi",
                "browser_error": _browser_state["error"],
                "started": _browser_state["started"],
                "init_done": _browser_state["init_done"],
                "queue": _job_q.qsize(),
                "rss_mb": round(process_memory_mb(), 1),
            })
            return
        if self.path == "/jwks":
            self._handle_jwks()
            return
        self._json(404, {"error": "not found"})

    def _handle_jwks(self):
        try:
            if transport_available():
                res = browser_fetch(JWKS_URL)
            else:
                res = curl_fetch(JWKS_URL)
            version = ""
            if res.get("status") == 200:
                try:
                    version = json.loads(res.get("body") or "{}").get("version", "")
                except Exception:
                    pass
            self._json(200, {
                "status": res.get("status"),
                "body": res.get("body"),
                "version": version,
                "browser_error": _browser_state["error"],
            })
        except Exception as exc:
            self._json(200, {"status": 0, "error": str(exc)})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path != "/pipe":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            e = payload.get("e", "")
            if not e:
                self._json(400, {"error": "missing e"})
                return
            url = f"{PIPE_URL}?e={e}"
            if transport_available():
                res = browser_fetch(url)
            else:
                res = curl_fetch(url)
            self._json(200, {
                "status": res.get("status"),
                "body": res.get("body") or "",
                "x_obfuscated": res.get("headers", {}).get("x-obfuscated") or "",
            })
        except Exception as exc:
            self._json(200, {"status": 0, "error": str(exc)})


def main():
    _start_browser_worker()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(
        f"miruro_sidecar listening on 127.0.0.1:{PORT} "
        f"(transport={'browser(playwright)' if transport_available() else 'curl_cffi'}, "
        f"recycle every {MAX_REQUESTS_PER_BROWSER} reqs / {MAX_BROWSER_LIFETIME}s)",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
