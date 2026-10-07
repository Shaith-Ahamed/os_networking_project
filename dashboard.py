"""Web dashboard for the firewall server: live stats, users, rules and an event feed.

Everything needs the admin password. POST /api/login exchanges it for a short-lived
bearer token that the page sends in an Authorization header (so other websites can't
trigger actions through the browser). Uses only the standard library.
"""
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')
TOKEN_TTL = 3600  # seconds a login stays valid
MAX_BODY = 10_000


def start_dashboard(server, host, port):
    """Start the dashboard in a background thread and return the HTTP server object."""
    tokens = {}  # token -> expiry (monotonic)
    tokens_lock = threading.Lock()

    def token_valid(token):
        now = time.monotonic()
        with tokens_lock:
            for t in [t for t, exp in tokens.items() if exp < now]:
                del tokens[t]
            return token in tokens

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # keep the console clean
            pass

        def send_body(self, status, body, content_type):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, payload):
            self.send_body(status, json.dumps(payload).encode('utf-8'), 'application/json')

        def authorized(self):
            header = self.headers.get('Authorization', '')
            return header.startswith('Bearer ') and token_valid(header[7:])

        def read_json(self):
            try:
                length = int(self.headers.get('Content-Length', 0))
                if not 0 < length <= MAX_BODY:
                    return None
                data = json.loads(self.rfile.read(length))
                return data if isinstance(data, dict) else None
            except (ValueError, OSError):
                return None

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == '/':
                try:
                    with open(HTML_PATH, 'rb') as f:
                        html = f.read()
                except OSError:
                    return self.send_json(500, {'error': 'dashboard.html not found'})
                return self.send_body(200, html, 'text/html; charset=utf-8')
            if url.path not in ('/api/state', '/api/events'):
                return self.send_json(404, {'error': 'not found'})
            if not self.authorized():
                return self.send_json(401, {'error': 'login required'})
            if url.path == '/api/state':
                return self.send_json(200, server.state())
            try:
                since = int(parse_qs(url.query).get('since', ['0'])[0])
            except ValueError:
                since = 0
            self.send_json(200, {'events': server.events.since(since)})

        def do_POST(self):
            url = urlparse(self.path)
            body = self.read_json()
            if body is None:
                return self.send_json(400, {'error': 'invalid JSON body'})
            if url.path == '/api/login':
                return self.login(body)
            if url.path == '/api/action':
                if not self.authorized():
                    return self.send_json(401, {'error': 'login required'})
                return self.action(body)
            self.send_json(404, {'error': 'not found'})

        def login(self, body):
            ip = self.client_address[0]
            if server.admin_hash is None:
                return self.send_json(503, {'error': 'No admin password is configured on the server.'})
            if server.rules.ip_is_blocked(ip):
                return self.send_json(403, {'error': 'Your IP is temporarily banned.'})
            password = body.get('password')
            if isinstance(password, str) and server.check_admin_password(password):
                token = secrets.token_hex(24)
                with tokens_lock:
                    tokens[token] = time.monotonic() + TOKEN_TTL
                return self.send_json(200, {'token': token})
            with server.lock:
                server.stats['admin_failures'] += 1
            server.record_violation(ip, 'admin_auth')  # too many wrong passwords => auto-ban
            self.send_json(401, {'error': 'Wrong password.'})

        def action(self, body):
            command, args, text = body.get('command'), body.get('args', []), body.get('text', '')
            if not isinstance(command, str) or not isinstance(text, str) \
                    or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                return self.send_json(400, {'error': 'invalid action'})
            ok, lines = server.run_admin(command, args, text, _dashboard_actor(self.client_address[0]))
            self.send_json(200, {'ok': ok, 'lines': [line.replace('[Admin] ', '', 1) for line in lines]})

    httpd = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class _DashboardActor:
    """Same shape as firewall_server.Actor (label + info); not imported to avoid a circular import."""
    def __init__(self, ip):
        self.label = f"dashboard@{ip}"
        self.info = None


def _dashboard_actor(ip):
    return _DashboardActor(ip)
