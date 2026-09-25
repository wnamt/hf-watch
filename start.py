#!/usr/bin/env python3
"""
HF·WATCH — start.py
Serves hf-watch.html + proxies DX cluster data.
Usage:  python start.py
Open:   http://localhost:8080/hf-watch.html
"""

import os, sys, ssl, json, time, hashlib, sqlite3, threading, urllib.request, urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PORT = 8080

# ── Visitor stats database ────────────────────────────────────────────────────
# Point DB_PATH at a Render Persistent Disk mount path for cross-deploy
# persistence, e.g. '/data/hfwatch-stats.db'. Defaults to the app directory,
# which persists across restarts but resets on redeploys.
DB_PATH = os.environ.get('HFW_STATS_DB', os.path.join(os.getcwd(), 'hfwatch-stats.db'))

# Historical total from before HFW_STATS_DB pointed at persistent storage —
# added on top of the live DB count so the counter doesn't look like it
# collapsed. Safe to leave in place permanently: once DB_PATH is durable this
# is just a fixed baseline the real count keeps growing from.
STATS_SEED = int(os.environ.get('HFW_STATS_SEED', '7200'))

def _db():
    """Open a DB connection with WAL mode for safe concurrent access."""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def init_db():
    with _db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS visits (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash  TEXT    NOT NULL,
            ts       INTEGER NOT NULL,
            country  TEXT
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts)')
        # Migrate DBs created before the country column existed.
        cols = [r[1] for r in db.execute('PRAGMA table_info(visits)')]
        if 'country' not in cols:
            db.execute('ALTER TABLE visits ADD COLUMN country TEXT')

        db.execute('''CREATE TABLE IF NOT EXISTS proxy_calls (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT    NOT NULL,
            ok       INTEGER NOT NULL,
            ts       INTEGER NOT NULL
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_ts ON proxy_calls(ts)')

        db.execute('''CREATE TABLE IF NOT EXISTS feature_events (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            event    TEXT    NOT NULL,
            detail   TEXT,
            ts       INTEGER NOT NULL
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_feature_ts ON feature_events(ts)')
        db.commit()
    safe_print(f'  DB    stats → {DB_PATH}')

# ── GeoIP (best-effort, country-level only) ───────────────────────────────────
# Cached by ip_hash (not the raw IP) so a returning visitor costs one lookup
# per day, not one per page load. The raw IP only ever exists in memory for
# the duration of the outbound lookup request — it's never written to disk.
_geoip_cache = {}   # ip_hash -> (country_code_or_None, looked_up_at)
_GEOIP_TTL   = 86400

def _is_private_ip(ip: str) -> bool:
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        return True
    return ip.startswith(('10.', '192.168.', '169.254.')) or \
           any(ip.startswith(f'172.{n}.') for n in range(16, 32))

def geoip_lookup(ip: str, ip_hash: str):
    """Return a 2-letter country code for ip, or None if it can't be resolved."""
    if _is_private_ip(ip):
        return None
    cached = _geoip_cache.get(ip_hash)
    if cached and time.time() - cached[1] < _GEOIP_TTL:
        return cached[0]
    cc = None
    try:
        req = urllib.request.Request(
            f'http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=countryCode',
            headers={'User-Agent': 'HF-WATCH/2.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as r:
            cc = json.loads(r.read()).get('countryCode') or None
    except Exception as e:
        safe_print(f'  GeoIP ✗  {e}')
    _geoip_cache[ip_hash] = (cc, time.time())
    return cc

def record_visit(ip: str):
    """Log a page load. IP is one-way hashed — never stored in plain text.
    The country lookup is resolved in a background thread and back-filled
    afterward, so a slow or unreachable geoip service never delays the
    response — record_visit itself only ever does one fast local insert."""
    ip_hash = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:20]
    ts      = int(time.time())
    try:
        with _db() as db:
            cur = db.execute('INSERT INTO visits (ip_hash, ts, country) VALUES (?,?,NULL)', (ip_hash, ts))
            db.commit()
            row_id = cur.lastrowid
    except Exception as e:
        safe_print(f'  DB ✗  record_visit: {e}')
        return
    threading.Thread(target=_backfill_visit_country, args=(ip, ip_hash, row_id), daemon=True).start()

def _backfill_visit_country(ip: str, ip_hash: str, row_id: int):
    country = geoip_lookup(ip, ip_hash)
    if not country:
        return
    try:
        with _db() as db:
            db.execute('UPDATE visits SET country=? WHERE id=?', (country, row_id))
            db.commit()
    except Exception as e:
        safe_print(f'  DB ✗  _backfill_visit_country: {e}')

def record_proxy_call(endpoint: str, ok: bool):
    """Track each upstream fetch (DX cluster, HamQSL, OWM, QRZ) so failures
    of an external source show up instead of silently degrading the display."""
    try:
        with _db() as db:
            db.execute('INSERT INTO proxy_calls (endpoint, ok, ts) VALUES (?,?,?)',
                       (endpoint, 1 if ok else 0, int(time.time())))
            db.commit()
    except Exception as e:
        safe_print(f'  DB ✗  record_proxy_call: {e}')

def record_feature_event(event: str, detail: str = ''):
    """Log a client-reported UI interaction (map view opened, band filter
    toggled, callsign looked up, ...) — see POST /track."""
    try:
        with _db() as db:
            db.execute('INSERT INTO feature_events (event, detail, ts) VALUES (?,?,?)',
                       ((event or '')[:40], (detail or '')[:80], int(time.time())))
            db.commit()
    except Exception as e:
        safe_print(f'  DB ✗  record_feature_event: {e}')

def get_stats() -> dict:
    """Return active unique visitors (last hour) and total all-time page loads."""
    now      = int(time.time())
    hour_ago = now - 3600
    try:
        with _db() as db:
            active = db.execute(
                'SELECT COUNT(DISTINCT ip_hash) FROM visits WHERE ts >= ?', (hour_ago,)
            ).fetchone()[0]
            total = db.execute('SELECT COUNT(*) FROM visits').fetchone()[0] + STATS_SEED
        return {'active': active, 'total': total}
    except Exception as e:
        safe_print(f'  DB ✗  get_stats: {e}')
        return {'active': 0, 'total': 0, 'error': str(e)}

def get_analytics() -> dict:
    """Fuller breakdown for the Settings → Analytics panel: 30-day traffic
    trend, all-time hour-of-day distribution, upstream proxy health, top
    client-reported feature events, and top visitor countries."""
    since30 = int(time.time()) - 30*86400
    try:
        with _db() as db:
            daily_rows = db.execute(
                "SELECT date(ts,'unixepoch') d, COUNT(*) c FROM visits WHERE ts>=? GROUP BY d ORDER BY d",
                (since30,)
            ).fetchall()

            hourly = [0]*24
            for h, c in db.execute(
                "SELECT CAST(strftime('%H',ts,'unixepoch') AS INTEGER) h, COUNT(*) c FROM visits GROUP BY h"
            ).fetchall():
                if h is not None:
                    hourly[int(h)] = c

            proxies = {}
            for endpoint, ok, cnt, last_ts in db.execute(
                'SELECT endpoint, ok, COUNT(*), MAX(ts) FROM proxy_calls GROUP BY endpoint, ok'
            ).fetchall():
                p = proxies.setdefault(endpoint, {'ok': 0, 'fail': 0, 'last_ok': None, 'last_fail': None})
                if ok: p['ok'] = cnt;   p['last_ok']   = last_ts
                else:  p['fail'] = cnt; p['last_fail'] = last_ts

            features = db.execute(
                "SELECT event, COALESCE(detail,'') d, COUNT(*) c FROM feature_events "
                'GROUP BY event, d ORDER BY c DESC LIMIT 15'
            ).fetchall()

            countries = db.execute(
                "SELECT country, COUNT(DISTINCT ip_hash) c FROM visits "
                "WHERE country IS NOT NULL AND country<>'' GROUP BY country ORDER BY c DESC LIMIT 10"
            ).fetchall()

        return {
            'daily':     [{'date': d, 'count': c} for d, c in daily_rows],
            'hourly':    hourly,
            'proxies':   proxies,
            'features':  [{'event': e, 'detail': d, 'count': c} for e, d, c in features],
            'countries': [{'country': cc, 'count': c} for cc, c in countries],
        }
    except Exception as e:
        safe_print(f'  DB ✗  get_analytics: {e}')
        return {'error': str(e)}

ssl_ctx = ssl.create_default_context()

def safe_print(msg):
    """Print with ASCII fallback so Windows console never crashes."""
    try:
        print(msg)
    except Exception:
        print(msg.encode('ascii', errors='replace').decode('ascii'))

def fetch_url(url, timeout=12):
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 HF-WATCH/2.0',
        'Accept': 'application/json, text/plain, */*',
    })
    ctx = ssl_ctx if url.startswith('https') else None
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read()

def parse_spots(data: bytes) -> list:
    try:
        obj = json.loads(data)
    except Exception as e:
        safe_print(f'  DX ✗  JSON parse failed: {e}')
        return []

    spots_raw = obj.get('s', {})
    ci        = obj.get('ci', {})

    if not isinstance(spots_raw, dict) or not spots_raw:
        return []

    spots = []
    for spot_id, arr in spots_raw.items():
        try:
            if not isinstance(arr, list) or len(arr) < 3:
                continue
            dx      = str(arr[0]).strip()
            freq    = str(arr[1])
            de      = str(arr[2]).strip()
            comment = str(arr[3]).strip() if len(arr) > 3 else ''
            time_   = str(arr[4]).strip() if len(arr) > 4 else ''

            if not de or not dx:
                continue

            spot = {
                'de': de, 'dx': dx, 'freq': freq,
                'band': '', 'comment': comment,
                'mode': '', 'time': time_,
            }

            de_info = ci.get(de, [])
            dx_info = ci.get(dx, [])
            if len(de_info) >= 8:
                try:
                    spot['de_lat'] = float(de_info[6])
                    spot['de_lon'] = float(de_info[7])
                except (ValueError, TypeError):
                    pass
            if len(dx_info) >= 8:
                try:
                    spot['dx_lat'] = float(dx_info[6])
                    spot['dx_lon'] = float(dx_info[7])
                except (ValueError, TypeError):
                    pass

            spots.append(spot)
        except Exception:
            continue

    return spots

class Handler(SimpleHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors(); self.end_headers()

    def _real_ip(self):
        """Prefer X-Forwarded-For (set by Render's proxy) over the raw socket
        address, which behind any reverse proxy is just the proxy itself —
        not the visitor. Falls back to the socket address for local runs."""
        xff = self.headers.get('X-Forwarded-For', '')
        return xff.split(',')[0].strip() if xff else self.client_address[0]

    def do_GET(self):
        if self.path.startswith('/spots'):
            self._serve_dx()
        elif self.path.startswith('/owm/'):
            self._proxy_owm()
        elif self.path == '/hamqsl':
            self._proxy_hamqsl()
        elif self.path == '/stats':
            self._serve_stats()
        elif self.path == '/analytics':
            self._serve_analytics()
        else:
            # Record a visit whenever the main app page is loaded
            clean = self.path.split('?')[0].rstrip('/')
            if clean in ('', '/hf-watch.html', '/index.html'):
                record_visit(self._real_ip())
            super().do_GET()

    def do_POST(self):
        if self.path == '/qrz-log':
            self._proxy_qrz_log()
        elif self.path == '/track':
            self._track_event()
        else:
            self.send_response(405)
            self.end_headers()

    def _serve_stats(self):
        self._json_response(get_stats())

    def _serve_analytics(self):
        self._json_response(get_analytics())

    def _track_event(self):
        """Client-reported UI interaction — see track() in index.html."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length)) if length else {}
            event  = str(body.get('event', '')).strip()
            if event:
                record_feature_event(event, str(body.get('detail', '')))
        except Exception:
            pass
        self._json_response({'ok': True})

    def _proxy_qrz_log(self):
        """
        Proxy POST requests to the QRZ Logbook API.
        Client sends JSON {key, options} → we POST to QRZ → return parsed response.
        """
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length))
            key    = body.get('key', '').strip()
            opts   = body.get('options', 'MAX:250,AFTERLOGID:0')

            if not key:
                self._json_response({'error': 'No API key provided'})
                return

            post_data = urllib.parse.urlencode({
                'KEY':    key,
                'ACTION': 'FETCH',
                'OPTION': opts,
            }).encode('utf-8')

            req = urllib.request.Request(
                'https://logbook.qrz.com/api',
                data=post_data,
                method='POST',
                headers={
                    'User-Agent':   f'HF-WATCH/{PORT} (hf-watch)',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            )
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=20) as r:
                raw = r.read().decode('utf-8')

            # QRZ returns URL-encoded name=value pairs
            parsed = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
            result = parsed.get('RESULT', '').upper()

            if result == 'OK':
                record_proxy_call('qrz', True)
                self._json_response({
                    'result': 'OK',
                    'adif':   parsed.get('ADIF', ''),
                    'count':  parsed.get('COUNT', '0'),
                    'logids': parsed.get('LOGIDS', ''),
                })
            else:
                msg = parsed.get('REASON') or parsed.get('ERROR') or raw[:200]
                safe_print(f'  QRZ ✗  {msg}')
                record_proxy_call('qrz', False)
                self._json_response({'error': msg, 'result': result})

        except Exception as e:
            safe_print(f'  QRZ !! {type(e).__name__}: {e}')
            record_proxy_call('qrz', False)
            self._json_response({'error': f'{type(e).__name__}: {e}'})

    def _json_response(self, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(200)
        self._cors()
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _proxy_hamqsl(self):
        """Proxy HamQSL solar XML — their server doesn't send CORS headers."""
        try:
            req = urllib.request.Request(
                'https://www.hamqsl.com/solarxml.php',
                headers={'User-Agent': 'HF-WATCH/2.0', 'Accept': 'text/xml, */*'}
            )
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=12) as r:
                data = r.read()
                ct = r.headers.get('Content-Type', 'text/xml')
            record_proxy_call('hamqsl', True)
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'public, max-age=300')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            safe_print(f'  HamQSL proxy error: {e}')
            record_proxy_call('hamqsl', False)
            self.send_response(502)
            self.end_headers()

    def _proxy_owm(self):
        # /owm/{layer}/{z}/{x}/{y}.png?appid={key}
        # Proxies OWM tile requests to bypass browser CORS restrictions
        try:
            req = urllib.request.Request(
                f'https://tile.openweathermap.org/map{self.path[4:]}',
                headers={'User-Agent': 'HF-WATCH/2.0'}
            )
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as r:
                data = r.read()
                ct = r.headers.get('Content-Type', 'image/png')
            record_proxy_call('owm', True)
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'public, max-age=600')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            safe_print(f'  OWM tile error: {e}')
            record_proxy_call('owm', False)
            self.send_response(502)
            self.end_headers()

    def _serve_dx(self):
        result = {'error': 'No data'}

        try:
            url = 'http://www.dxwatch.com/dxsd1/s.php?c=100'
            status, headers, data = fetch_url(url)
            spots = parse_spots(data)
            if spots:
                safe_print(f'  DX ✓  {len(spots)} spots')
                result = spots
                record_proxy_call('dx', True)
            else:
                result = {'error': f'0 spots parsed from {len(data)}b'}
                record_proxy_call('dx', False)
        except Exception as e:
            safe_print(f'  DX ✗  {type(e).__name__}: {e}')
            result = {'error': f'{type(e).__name__}: {e}'}
            record_proxy_call('dx', False)

        # Serialize — strip NaN coords and retry if needed
        try:
            body = json.dumps(result, ensure_ascii=True, allow_nan=False).encode('utf-8')
        except (ValueError, TypeError):
            if isinstance(result, list):
                for spot in result:
                    for k in ('de_lat', 'de_lon', 'dx_lat', 'dx_lon'):
                        spot.pop(k, None)
            body = json.dumps(result, ensure_ascii=True).encode('utf-8')

        # Always send response
        try:
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except Exception as e:
            safe_print(f'  DX    response write error: {e}')

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin',  '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')

    def log_message(self, fmt, *args):
        path = str(args[0]) if args else ''
        code = str(args[1]) if len(args) > 1 else ''
        skip = ('.css','.js','.png','.ico','.woff','.map','leaflet','favicon')
        if not any(s in path for s in skip):
            safe_print(f'  {code}  {path}')

if __name__ == '__main__':
    safe_print(f'''
  +----------------------------------------------+
  |           HF.WATCH  --  start.py             |
  +----------------------------------------------+
  |  Serving from:                               |
  |  {os.getcwd():<44s}|
  |                                              |
  |  Open -> http://localhost:{PORT}/hf-watch.html  |
  |  Press  Ctrl+C  to stop                      |
  +----------------------------------------------+
''')
    try:
        init_db()
        ThreadingHTTPServer(('', PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        safe_print('\n  Stopped.')
        sys.exit(0)
