#!/usr/bin/env python3
"""Local test server: serves public/ and emulates CheerpJ's cheerpjRunMain with a real JVM.

POST /__jvm {main, cp, args, files:{"/str/x": b64}} -> {code, stdout, out:{"/files/...": b64}}
Virtual paths: /app/* -> public/*, /str/* and /files/* -> a temp dir.
"""
import base64, http.server, json, os, re, shutil, subprocess, sys, tempfile

ACCOUNT = {'mode': 'off', 'used': 0}
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'public'))
VFS = tempfile.mkdtemp(prefix='ezlarp-vfs-')

def real(p):
    if p.startswith('/app/'):
        return os.path.join(ROOT, p[5:])
    if p.startswith('/str/') or p.startswith('/files/'):
        return os.path.join(VFS, p.lstrip('/'))
    return p

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def log_message(self, *a):
        pass

    # stand-in for the account functions (functions/api/me.js, scan/consume.js, auth/*).
    # Tests switch the mode with POST /__test/account?mode=off|limit|user|vpn (default off = no limits).
    def send_json(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def account(self):
        import time
        from urllib.parse import urlparse, parse_qs
        path = urlparse(self.path).path
        mode = ACCOUNT['mode']
        if path == '/__test/account':
            ACCOUNT['mode'] = parse_qs(urlparse(self.path).query).get('mode', ['off'])[0]
            ACCOUNT['used'] = 0
            return self.send_json(200, ACCOUNT) or True
        if mode == 'vpn' and (path.startswith('/api/') or path.startswith('/auth/')):
            if path.startswith('/auth/'):
                self.send_response(302); self.send_header('Location', '/?login=vpn'); self.end_headers(); return True
            return self.send_json(403, {'reason': 'vpn', 'error': 'VPNs and proxies are not allowed.'}) or True
        if path == '/api/me':
            if mode == 'user':
                return self.send_json(200, {'user': {'id': '123456789012345678', 'name': 'tester', 'avatar': None}, 'login': True, 'limit': None, 'left': None, 'windowHours': 24}) or True
            if mode == 'limit':
                return self.send_json(200, {'user': None, 'login': True, 'limit': 2, 'left': max(0, 2 - ACCOUNT['used']), 'reset': int(time.time()) + 86400, 'windowHours': 24}) or True
            return self.send_json(200, {'user': None, 'login': False, 'limit': None, 'left': None}) or True
        if path == '/api/scan/consume':
            if mode == 'limit':
                if ACCOUNT['used'] >= 2:
                    return self.send_json(429, {'ok': False, 'reason': 'limit', 'left': 0, 'limit': 2, 'reset': int(time.time()) + 86400}) or True
                ACCOUNT['used'] += 1
                return self.send_json(200, {'ok': True, 'left': 2 - ACCOUNT['used'], 'limit': 2}) or True
            return self.send_json(200, {'ok': True, 'left': None, 'limit': None}) or True
        if path == '/auth/login':
            ACCOUNT['mode'] = 'user'
            self.send_response(302); self.send_header('Location', '/?login=ok'); self.end_headers(); return True
        if path == '/auth/logout':
            ACCOUNT['mode'] = 'limit'; ACCOUNT['used'] = 0
            return self.send_json(200, {'ok': True}) or True
        return False

    def do_GET(self):
        if self.account():
            return
        # stand-in for functions/api/fetch.js: Discord links serve files from public/samples/
        if self.path.startswith('/api/fetch'):
            from urllib.parse import urlparse, parse_qs, quote
            url = parse_qs(urlparse(self.path).query).get('url', [''])[0]
            name = url.split('?')[0].rstrip('/').split('/')[-1]
            fp = os.path.join(ROOT, 'samples', name)
            if url.startswith('https://cdn.discordapp.com/') and os.path.isfile(fp):
                body = open(fp, 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('x-filename', quote(name))
            else:
                body = json.dumps({'error': 'test server: unsupported link'}).encode()
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def do_POST(self):
        if self.account():
            return
        if self.path != '/__jvm':
            self.send_error(404); return
        req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        for vp, b in req['files'].items():
            rp = real(vp); os.makedirs(os.path.dirname(rp), exist_ok=True)
            open(rp, 'wb').write(base64.b64decode(b))
        cp = ':'.join(real(x) for x in req['cp'].split(':'))
        args = [re.sub(r'(/(?:str|files|app)/[^\s=:]+)', lambda m: real(m.group(1)), a) for a in req['args']]
        p = subprocess.run(['java', '-Xss16m', '-cp', cp, req['main'], *args], capture_output=True, text=True)
        out = {}
        for a in req['args']:
            for vp in re.findall(r'/files/[^\s=:]+', a):
                if os.path.exists(real(vp)):
                    out[vp] = base64.b64encode(open(real(vp), 'rb').read()).decode()
        body = json.dumps({'code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr[-4000:], 'out': out}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
try:
    http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
finally:
    shutil.rmtree(VFS, ignore_errors=True)
