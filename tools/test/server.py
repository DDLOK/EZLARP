#!/usr/bin/env python3
"""Local test server: serves public/ and emulates CheerpJ's cheerpjRunMain with a real JVM.

POST /__jvm {main, cp, args, files:{"/str/x": b64}} -> {code, stdout, out:{"/files/...": b64}}
Virtual paths: /app/* -> public/*, /str/* and /files/* -> a temp dir.
"""
import base64, http.server, json, os, re, shutil, subprocess, sys, tempfile

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

    def do_GET(self):
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
