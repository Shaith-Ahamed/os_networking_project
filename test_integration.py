"""End-to-end tests: start a real server in a temp folder and talk to it over sockets.

Run:  python -m unittest test_integration -v
Needs only Python. TLS tests are skipped if `openssl` is not installed, and the tests
that use a second loopback address (127.0.0.2) are skipped if it can't be bound.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from netio import SafeSocket

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = 'Test-Pass-123'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def have_second_loopback():
    try:
        with socket.socket() as s:
            s.bind(('127.0.0.2', 0))
        return True
    except OSError:
        return False


class Client:
    """A chat client that collects every line the server sends."""

    def __init__(self, port, name, ctx=None, source='127.0.0.1', connect=True):
        raw = socket.socket()
        raw.bind((source, 0))
        raw.connect(('127.0.0.1', port))
        self.sock = SafeSocket(ctx.wrap_socket(raw, server_hostname='localhost')) if ctx else raw
        self.lines, self.buf = [], b''
        threading.Thread(target=self._read, daemon=True).start()
        if name:
            self.send(f'/username {name}')

    def _read(self):
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    return
                self.buf += data
                while b'\n' in self.buf:
                    line, self.buf = self.buf.split(b'\n', 1)
                    self.lines.append(line.decode())
        except OSError:
            pass

    def send(self, text):
        self.sock.sendall((text + '\n').encode())

    def got(self, text, timeout=3.0):
        """Wait until some received line contains `text`."""
        end = time.time() + timeout
        while time.time() < end:
            if any(text in line for line in self.lines):
                return True
            time.sleep(0.05)
        return False

    def never_got(self, text, wait=0.6):
        time.sleep(wait)
        return not any(text in line for line in self.lines)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class ServerCase(unittest.TestCase):
    """Starts one server per test class (own temp folder, ports and config)."""
    server_args = ['--rate-messages', '1000']  # tests send many messages quickly
    tls = False

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.port, cls.dash = free_port(), free_port()
        with open(os.path.join(cls.dir, 'rules.json'), 'w') as f:
            json.dump({'blocked_keywords': [], 'blocked_ips': []}, f)
        args = [sys.executable, os.path.join(HERE, 'firewall_server.py'), '--port', str(cls.port),
                '--dashboard-port', str(cls.dash), '--config', os.path.join(cls.dir, 'rules.json'),
                '--log-file', os.path.join(cls.dir, 'server.log')] + cls.server_args
        cls.extra_setup(args)
        env = dict(os.environ, FIREWALL_ADMIN_PASSWORD=PASSWORD)
        cls.proc = subprocess.Popen(args, cwd=cls.dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):  # wait until it accepts connections
            try:
                socket.create_connection(('127.0.0.1', cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.proc.kill()
            raise RuntimeError('server did not start')
        cls.ctx = None

    @classmethod
    def extra_setup(cls, args):
        pass

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def setUp(self):
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()

    def client(self, name, **kw):
        c = Client(self.port, name, ctx=self.ctx, **kw)
        self.clients.append(c)
        return c

    def admin(self, name):
        c = self.client(name)
        self.assertTrue(c.got(f'Welcome, {name}'))
        c.send(f'/admin {PASSWORD}')
        self.assertTrue(c.got('Authenticated'))
        return c

    def http(self, method, path, body=None, token=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.dash}{path}', method=method,
                                     data=None if body is None else json.dumps(body).encode())
        if token:
            req.add_header('Authorization', 'Bearer ' + token)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b'null'), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read()), e.headers


class ChatAndAdminTests(ServerCase):
    def test_usernames_are_validated_and_unique(self):
        a = self.client('alice')
        self.assertTrue(a.got('Welcome, alice'))
        self.assertTrue(self.client('ALICE').got('already in use'))
        self.assertTrue(self.client('bad name!').got('Invalid username'))
        self.assertTrue(self.client('Server').got('reserved'))

    def test_chat_private_messages_and_commands(self):
        a, b = self.client('chat_a'), self.client('chat_b')
        self.assertTrue(b.got('Welcome') and a.got('chat_b joined'))
        b.send('hello there')
        self.assertTrue(a.got('chat_b: hello there'))  # shown by username, no IP
        self.assertTrue(b.never_got('hello there'))    # no echo to the sender
        b.send('/msg chat_a psst')
        self.assertTrue(a.got('[PM from chat_b] psst') and b.got('[PM to chat_a] psst'))
        b.send('/msg nobody hi')
        self.assertTrue(b.got("User 'nobody' not found"))
        a.send('/users')
        self.assertTrue(a.got('chat_a') and a.got('chat_b'))
        a.send('/wat')
        self.assertTrue(a.got('Unknown command'))

    def test_admin_login_required_and_wrong_password_rejected(self):
        a = self.client('login_a')
        self.assertTrue(a.got('Welcome'))
        a.send('/admin list')
        self.assertTrue(a.got('Not authenticated'))
        a.send('/admin wrong-password')
        self.assertTrue(a.got('Authentication failed'))

    def test_keyword_rules_block_warn_redact(self):
        a, b = self.admin('kw_admin'), self.client('kw_user')
        self.assertTrue(b.got('Welcome'))
        a.send('/admin addkw ass')  # default: whole word, block
        self.assertTrue(a.got("'ass' added (word, block)"))
        b.send('what a class act')
        self.assertTrue(a.got('kw_user: what a class act'))  # not a whole-word match
        b.send('you ass')
        self.assertTrue(b.got('blocked'))
        a.send('/admin addkw hush word redact')
        self.assertTrue(a.got("'hush' added"))
        b.send('keep it hush ok')
        self.assertTrue(a.got('kw_user: keep it **** ok'))
        a.send('/admin addkw hmm word warn')
        self.assertTrue(a.got("'hmm' added"))
        b.send('hmm fine')
        self.assertTrue(b.got('Warning') and a.got('kw_user: hmm fine'))
        a.send('/admin addkw ( regex')
        self.assertTrue(a.got('invalid regex'))

    def test_mute_broadcast_and_kick(self):
        a, b = self.admin('mod_admin'), self.client('mod_user')
        self.assertTrue(b.got('Welcome'))
        a.send('/admin mute mod_user')
        self.assertTrue(b.got('muted'))
        b.send('can you hear me')
        self.assertTrue(b.got('You are muted'))
        self.assertTrue(a.never_got('can you hear me'))
        a.send('/admin unmute mod_user')
        a.send('/admin broadcast maintenance soon')
        self.assertTrue(b.got('[Server] maintenance soon'))
        a.send('/admin kick mod_user')
        self.assertTrue(a.got("Kicked 'mod_user'") and a.got('mod_user left the chat'))
        a.send('/admin kick mod_user')
        self.assertTrue(a.got('not found'))

    @unittest.skipUnless(have_second_loopback(), 'needs 127.0.0.2')
    def test_cidr_and_temporary_ip_blocks(self):
        a = self.admin('ip_admin')
        a.send('/admin blockip 127.0.0.0/30 1h')  # covers 127.0.0.1 too, but spares the issuing admin
        self.assertTrue(a.got('blocked for 1h'))
        refused = Client(self.port, None, source='127.0.0.2')
        self.clients.append(refused)
        self.assertTrue(refused.got('blocked'))
        a.send('/admin unblockip 127.0.0.0/30')
        self.assertTrue(a.got('unblocked'))
        a.send('/admin blockip 1.2.3.4 5x')
        self.assertTrue(a.got('invalid duration'))
        a.send('/admin blockip 999.1.1.1')
        self.assertTrue(a.got('not a valid IP'))

    def test_dashboard_api(self):
        self.assertEqual(self.http('GET', '/api/state')[0], 401)
        self.assertEqual(self.http('POST', '/api/login', {'password': 'wrong'})[0], 401)
        status, data, _ = self.http('POST', '/api/login', {'password': PASSWORD})
        self.assertEqual(status, 200)
        token = data['token']
        a = self.client('dash_user')
        self.assertTrue(a.got('Welcome'))
        status, state, _ = self.http('GET', '/api/state', token=token)
        self.assertTrue(any(u['username'] == 'dash_user' for u in state['users']))
        status, result, _ = self.http('POST', '/api/action',
                                      {'command': 'broadcast', 'text': 'hello from the web'}, token)
        self.assertTrue(result['ok'] and a.got('[Server] hello from the web'))
        status, result, _ = self.http('POST', '/api/action',
                                      {'command': 'addkw', 'args': ['two words', 'substring', 'block']}, token)
        self.assertTrue(result['ok'])
        self.assertEqual(self.http('GET', '/api/events?since=0', token=token)[0], 200)
        with urllib.request.urlopen(f'http://127.0.0.1:{self.dash}/') as r:
            self.assertIn(b'Firewall Dashboard', r.read())
            self.assertEqual(r.headers['X-Frame-Options'], 'DENY')

    def test_real_client_script(self):
        proc = subprocess.Popen([sys.executable, '-u', os.path.join(HERE, 'client.py'), '127.0.0.1', 'script_user',
                                 '--port', str(self.port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        watchdog = threading.Timer(20, proc.kill)
        watchdog.start()
        try:
            self.assertIn('Welcome, script_user', ''.join(proc.stdout.readline() for _ in range(2)))
            proc.stdin.write('/users\n')
            proc.stdin.flush()
            self.assertIn('Online', proc.stdout.readline())
            proc.stdin.write('exit\n')
            proc.stdin.flush()
            proc.wait(timeout=10)
        finally:
            watchdog.cancel()
            proc.kill()


class RateLimitTests(ServerCase):
    server_args = []  # default limit: 5 messages per 10 seconds

    def test_flooding_is_limited(self):
        a, b = self.client('rate_a'), self.client('rate_b')
        self.assertTrue(b.got('Welcome') and a.got('rate_b joined'))
        for i in range(8):
            b.send(f'm{i}')
        self.assertTrue(b.got('Rate limit exceeded'))
        time.sleep(0.5)
        self.assertEqual(sum(1 for l in a.lines if l.startswith('rate_b: m')), 5)


class AutoBanTests(ServerCase):
    server_args = []

    def test_wrong_admin_passwords_ban_the_ip(self):
        a = self.client('guesser')
        self.assertTrue(a.got('Welcome'))
        for i in range(5):
            a.send(f'/admin guess{i}')
        self.assertTrue(a.got('banned'))
        late = Client(self.port, None)
        self.clients.append(late)
        self.assertTrue(late.got('blocked'))
        self.assertEqual(self.http('POST', '/api/login', {'password': PASSWORD})[0], 403)


@unittest.skipUnless(have_second_loopback(), 'needs 127.0.0.2')
class AllowlistTests(ServerCase):
    def test_allowlist_mode(self):
        a = self.admin('allow_admin')
        a.send('/admin allowlist on')
        self.assertTrue(a.got('allowlist is empty'))
        a.send('/admin allowip 10.0.0.0/8')
        a.send('/admin allowlist on')
        self.assertTrue(a.got('lock yourself out'))
        a.send('/admin allowip 127.0.0.1')
        a.send('/admin allowlist on')
        self.assertTrue(a.got('now ON'))
        other = Client(self.port, None, source='127.0.0.2')
        self.clients.append(other)
        self.assertTrue(other.got('not allowed'))
        self.assertTrue(self.client('allowed_user').got('Welcome'))  # 127.0.0.1 is on the list
        a.send('/admin allowlist off')
        self.assertTrue(a.got('now OFF'))
        zed = Client(self.port, 'zed', source='127.0.0.2')
        self.clients.append(zed)
        self.assertTrue(zed.got('Welcome, zed'))


@unittest.skipUnless(shutil.which('openssl'), 'openssl not installed')
class TlsTests(ServerCase):
    @classmethod
    def extra_setup(cls, args):
        cert, key = os.path.join(cls.dir, 'cert.pem'), os.path.join(cls.dir, 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
                        '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                       check=True, capture_output=True)
        args += ['--tls-cert', cert, '--tls-key', key]
        cls.cert = cert

    def setUp(self):
        super().setUp()
        self.ctx = ssl.create_default_context(cafile=self.cert)

    def test_encrypted_chat_between_two_clients(self):
        a, b = self.client('tls_a'), self.client('tls_b')
        self.assertTrue(a.got('Welcome') and b.got('Welcome'))
        b.send('secret hello')
        self.assertTrue(a.got('tls_b: secret hello'))

    def test_untrusted_certificate_is_rejected_by_client(self):
        with self.assertRaises(ssl.SSLError):
            Client(self.port, 'eve', ctx=ssl.create_default_context())

    def test_plaintext_client_gets_no_access(self):
        plain = Client(self.port, 'plain')  # bypasses the class-wide TLS context
        self.clients.append(plain)
        self.assertTrue(plain.never_got('Welcome', wait=1.0))


if __name__ == '__main__':
    unittest.main()
