import argparse
import getpass
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
from collections import Counter, deque

import firewall_core as core
from dashboard import start_dashboard
from netio import LineReader, SafeSocket

CONFIG_FILE = 'firewall_config.json'
LOG_FILE = 'firewall_server.log'
PASSWORD_FILE = 'admin_password.hash'  # created by: python firewall_server.py --set-password
PASSWORD_ENV = 'FIREWALL_ADMIN_PASSWORD'  # optional override, handy for demos and tests
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345
MAX_LINE = 4096  # longest allowed message (bytes) before the client is dropped
AUTH_TIMEOUT = 30  # seconds a new connection has to finish the TLS handshake and send its username
RATE_LIMIT_MESSAGES = 5  # max messages (including commands) per client...
RATE_LIMIT_WINDOW = 10   # ...within this many seconds

# Auto-ban: kind -> (violations, within this many seconds). Reaching it bans the IP.
AUTOBAN = {
    'rate_limit': (10, 60),
    'blocked_message': (10, 60),
    'admin_auth': (5, 300),  # wrong admin passwords (chat and dashboard)
}
AUTOBAN_DURATION = 600  # seconds

USERNAME_WHITELIST = []  # Add usernames to restrict access, or leave empty for open access
USERNAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,20}$')


class EventLog(logging.Handler):
    """Keeps the most recent log records in memory for the web dashboard."""

    def __init__(self, capacity=300):
        super().__init__()
        self.events = deque(maxlen=capacity)
        self.next_id = 1

    def emit(self, record):  # logging holds self.lock around emit
        self.events.append({
            'id': self.next_id,
            'time': time.strftime('%H:%M:%S', time.localtime(record.created)),
            'level': record.levelname,
            'text': record.getMessage(),
        })
        self.next_id += 1

    def since(self, last_id):
        self.acquire()
        try:
            return [e for e in self.events if e['id'] > last_id]
        finally:
            self.release()


class ClientInfo:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.send_lock = threading.Lock()  # keeps concurrent writes to one socket from interleaving
        self.username = None  # set once authenticated
        self.is_admin = False
        self.connected_at = time.time()


class Actor:
    """Who is running an admin command: a chat client (info set) or the web dashboard."""
    def __init__(self, label, info=None):
        self.label = label
        self.info = info


HELP_LINES = [
    "[Admin] Commands:",
    "[Admin]   addkw <pattern> [word|substring|regex] [block|warn|redact]  (default: word block)",
    "[Admin]   rmkw <pattern>",
    "[Admin]   blockip <ip|cidr> [duration, e.g. 10m]   unblockip <ip|cidr>",
    "[Admin]   allowip <ip|cidr>   unallowip <ip|cidr>   allowlist on|off|status",
    "[Admin]   kick <user>   mute <user>   unmute <user>   broadcast <text>",
    "[Admin]   list   help",
]


class ChatServer:
    def __init__(self, rules, admin_hash, events, tls_context=None):
        self.rules = rules
        self.admin_hash = admin_hash  # None => admin access disabled
        self.events = events
        self.tls = tls_context
        self.lock = threading.RLock()  # guards clients, muted, violations and the counters
        self.clients = {}  # conn -> ClientInfo (includes connections still authenticating)
        self.muted = set()  # lowercase usernames
        self.violations = {}  # (ip, kind) -> deque of timestamps
        self.stats = Counter()
        self.blocked_by_ip = Counter()
        self.started = time.time()
        self.admin_commands = {
            'addkw': self._cmd_addkw, 'rmkw': self._cmd_rmkw,
            'blockip': self._cmd_blockip, 'unblockip': self._cmd_unblockip,
            'allowip': self._cmd_allowip, 'unallowip': self._cmd_unallowip,
            'allowlist': self._cmd_allowlist,
            'kick': self._cmd_kick, 'mute': self._cmd_mute, 'unmute': self._cmd_unmute,
            'broadcast': self._cmd_broadcast, 'list': self._cmd_list, 'help': self._cmd_help,
        }

    # ------------------------------------------------------------ sending / clients

    def send(self, info, text):
        payload = (text + '\n').encode('utf-8')
        with info.send_lock:
            info.conn.sendall(payload)

    def safe_send(self, info, text):
        try:
            self.send(info, text)
            return True
        except OSError:
            return False

    def authenticated(self):
        with self.lock:
            return [c for c in self.clients.values() if c.username]

    def broadcast(self, text, exclude=None):
        for client in self.authenticated():
            if client is not exclude:
                self.safe_send(client, text)  # a dead client's own thread cleans it up

    def is_registered(self, info):
        with self.lock:
            return info.conn in self.clients

    def remove_client(self, info):
        with self.lock:
            was_present = self.clients.pop(info.conn, None) is not None
        try:
            info.conn.close()
        except OSError:
            pass
        if was_present and info.username:
            self.broadcast(f"[Server] {info.username} left the chat.")

    def find_user(self, name):
        for client in self.authenticated():
            if client.username.lower() == name.lower():
                return client
        return None

    def disconnect_matching(self, rule, keep=None, notice="[Firewall]: Your IP has been blocked."):
        """Disconnect every client whose IP matches rule (an IP or CIDR), except `keep`."""
        with self.lock:
            targets = [c for c in self.clients.values()
                       if c is not keep and core.ip_in_rule(c.addr[0], rule)]
        for client in targets:
            self.safe_send(client, notice)
            self.remove_client(client)
        return len(targets)

    # ------------------------------------------------------------ violations / auto-ban

    def record_violation(self, ip, kind):
        limit, window = AUTOBAN[kind]
        now = time.monotonic()
        with self.lock:
            queue = self.violations.setdefault((ip, kind), deque())
            queue.append(now)
            while queue and now - queue[0] > window:
                queue.popleft()
            triggered = len(queue) >= limit
            if triggered:
                queue.clear()
        if triggered:
            self.rules.add_ip_block(ip, AUTOBAN_DURATION)
            with self.lock:
                self.stats['autobans'] += 1
            logging.warning(f"Auto-banned {ip} for {AUTOBAN_DURATION}s ({kind})")
            self.disconnect_matching(ip, notice=f"[Firewall]: Your IP was banned for {AUTOBAN_DURATION // 60} minutes ({kind.replace('_', ' ')}).")

    def check_admin_password(self, password):
        return self.admin_hash is not None and core.verify_password(password, self.admin_hash)

    # ------------------------------------------------------------ connection lifecycle

    def serve_connection(self, conn, addr):
        try:
            conn.settimeout(AUTH_TIMEOUT)
            if self.tls:
                conn = self.tls.wrap_socket(conn, server_side=True)  # handshake happens here
        except (ssl.SSLError, OSError) as e:
            logging.warning(f"TLS handshake with {addr} failed: {e}")
            conn.close()
            return
        conn = SafeSocket(conn)  # lets this thread read while others write (needed for TLS)
        info = ClientInfo(conn, addr)
        with self.lock:
            self.clients[conn] = info
            self.stats['connections'] += 1
        try:
            self.session(info)
        except Exception as e:
            logging.error(f"Unexpected error handling client {addr}: {e}")
        finally:
            self.remove_client(info)

    def register_username(self, info, username):
        """Claim a username for this connection. Returns an error string, or None on success."""
        if not USERNAME_RE.match(username):
            return "Invalid username (1-20 letters, digits, '_' or '-')."
        if username.lower() == 'server':
            return "Username is reserved."
        if USERNAME_WHITELIST and username not in USERNAME_WHITELIST:
            return "Username not allowed."
        with self.lock:  # check and claim atomically so two clients can't grab the same name
            if any(c is not info and c.username and c.username.lower() == username.lower()
                   for c in self.clients.values()):
                return "Username already in use."
            info.username = username
        return None

    def session(self, info):
        conn, addr = info.conn, info.addr
        print(f"[+] Connected by {addr}")
        logging.info(f"Connected by {addr}")
        reader = LineReader(conn, MAX_LINE)
        try:
            message = reader.read_line()
        except (OSError, ValueError) as e:
            logging.warning(f"No username from {addr}: {e}")
            return
        if message is None:
            return
        if not message.startswith('/username '):
            self.safe_send(info, "[Firewall] Username required. Please reconnect.")
            return
        username = message.split(' ', 1)[1].strip()
        error = self.register_username(info, username)
        if error:
            self.safe_send(info, f"[Firewall] {error}")
            logging.warning(f"Connection from {addr} rejected: {error} ('{username}')")
            return
        conn.settimeout(None)
        self.safe_send(info, f"[Firewall] Welcome, {username}!")
        logging.info(f"{addr} authenticated as '{username}'")
        self.broadcast(f"[Server] {username} joined the chat.", exclude=info)

        recent = deque()  # timestamps of this client's recent messages
        while True:
            try:
                message = reader.read_line()
                if message is None:
                    break
                self.handle_message(info, message, recent)
            except OSError as e:
                if self.is_registered(info):  # not closed on purpose by kick/ban
                    logging.error(f"Error handling client {addr}: {e}")
                break
            except ValueError as e:
                logging.error(f"Error handling client {addr}: {e}")
                break
        print(f"[-] Disconnected {addr}")
        logging.info(f"Disconnected {addr} ({username})")

    # ------------------------------------------------------------ messages

    def handle_message(self, info, message, recent):
        if not message.strip():
            return
        ip = info.addr[0]
        # Console echo, but never print admin lines: they may contain the admin password
        shown = '/admin <hidden>' if message.startswith('/admin') else message
        print(f"[Received from {info.username}@{info.addr}]: {shown}")

        # Rate limiting: sliding window over the last RATE_LIMIT_WINDOW seconds
        now = time.monotonic()
        while recent and now - recent[0] > RATE_LIMIT_WINDOW:
            recent.popleft()
        if len(recent) >= RATE_LIMIT_MESSAGES:
            with self.lock:
                self.stats['rate_limited'] += 1
            logging.warning(f"Rate limit exceeded by {info.username}@{info.addr}")
            self.send(info, f"[Firewall]: Rate limit exceeded ({RATE_LIMIT_MESSAGES} messages per {RATE_LIMIT_WINDOW}s). Slow down.")
            self.record_violation(ip, 'rate_limit')
            return
        recent.append(now)

        if message.startswith('/admin'):
            self.handle_admin_line(info, message)
        elif message.startswith('/msg '):
            self.handle_private(info, message)
        elif message == '/users':
            names = sorted(c.username for c in self.authenticated())
            self.send(info, f"[Server] Online ({len(names)}): {', '.join(names)}")
        elif message.startswith('/'):
            self.send(info, "[Server] Unknown command. Available: /users, /msg <user> <text>, exit")
        else:
            self.handle_chat(info, message)

    def screen(self, info, message, what):
        """Run a message through the firewall. Returns the Verdict if allowed, else None."""
        ip = info.addr[0]
        allowed, _ = self.rules.connection_allowed(ip)
        verdict = self.rules.check_message(message) if allowed else None
        if verdict is None or not verdict.allowed:
            with self.lock:
                self.stats['messages_blocked'] += 1
                self.blocked_by_ip[ip] += 1
            logging.warning(f"Blocked {what} from {info.username}@{info.addr}: {message}")
            self.send(info, "[Firewall]: Your message was blocked or your IP is blocked.")
            self.record_violation(ip, 'blocked_message')
            return None
        with self.lock:
            self.stats['messages_allowed'] += 1
            if verdict.redacted:
                self.stats['messages_redacted'] += 1
            if verdict.warnings:
                self.stats['messages_warned'] += 1
        if verdict.warnings:
            self.send(info, f"[Firewall] Warning: your message contains flagged terms ({', '.join(verdict.warnings)}).")
        return verdict

    def is_muted(self, username):
        with self.lock:
            return username.lower() in self.muted

    def handle_chat(self, info, message):
        if self.is_muted(info.username):
            self.send(info, "[Server] You are muted by an admin.")
            return
        verdict = self.screen(info, message, 'message')
        if verdict is None:
            return
        logging.info(f"Allowed message from {info.username}@{info.addr}: {verdict.text}")
        self.broadcast(f"{info.username}: {verdict.text}", exclude=info)

    def handle_private(self, info, message):
        parts = message.split(None, 2)
        if len(parts) < 3:
            self.send(info, "[Server] Usage: /msg <user> <text>")
            return
        target = self.find_user(parts[1])
        if target is None:
            self.send(info, f"[Server] User '{parts[1]}' not found.")
            return
        if target is info:
            self.send(info, "[Server] You can't message yourself.")
            return
        if self.is_muted(info.username):
            self.send(info, "[Server] You are muted by an admin.")
            return
        verdict = self.screen(info, parts[2], 'private message')
        if verdict is None:
            return
        logging.info(f"Private message from {info.username} to {target.username}")
        self.safe_send(target, f"[PM from {info.username}] {verdict.text}")
        self.send(info, f"[PM to {target.username}] {verdict.text}")

    # ------------------------------------------------------------ admin

    def handle_admin_line(self, info, message):
        parts = message.split()
        if len(parts) < 2:
            self.send(info, "[Admin] Use /admin <password> to log in, then /admin help.")
            return
        command = parts[1].lower()
        if not info.is_admin:
            if command in self.admin_commands:
                self.send(info, "[Admin] Not authenticated. Use /admin <password> first.")
                return
            if self.admin_hash is None:
                self.send(info, "[Admin] Admin access is disabled: no admin password is configured on the server.")
                return
            if self.check_admin_password(parts[1]):
                info.is_admin = True
                self.send(info, "[Admin] Authenticated. You can now send admin commands (try /admin help).")
                logging.info(f"{info.addr} ({info.username}) authenticated as admin.")
            else:
                with self.lock:
                    self.stats['admin_failures'] += 1
                logging.warning(f"Failed admin login from {info.username}@{info.addr}")
                self.send(info, "[Admin] Authentication failed.")
                self.record_violation(info.addr[0], 'admin_auth')
            return
        args = parts[2:]
        text = message.split(None, 2)[2] if len(parts) > 2 else ''
        _, lines = self.run_admin(command, args, text, Actor(f"{info.username}@{info.addr[0]}", info))
        for line in lines:
            self.send(info, line)

    def run_admin(self, command, args, text, actor):
        """Run one admin command (from chat or the dashboard). Returns (ok, [reply lines])."""
        handler = self.admin_commands.get(command)
        if handler is None:
            return False, [f"[Admin] Unknown command '{command}'. Try /admin help."]
        try:
            return handler(args, text, actor)
        except ValueError as e:
            return False, [f"[Admin] {e}"]

    def _cmd_addkw(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: addkw <pattern> [word|substring|regex] [block|warn|redact]"]
        kind, action = 'word', 'block'
        for option in (o.lower() for o in args[1:]):
            if option in core.KEYWORD_KINDS:
                kind = option
            elif option in core.KEYWORD_ACTIONS:
                action = option
            else:
                return False, [f"[Admin] Unknown option '{option}'."]
        status = self.rules.add_keyword(args[0], kind, action)
        logging.info(f"Admin {actor.label} {status} keyword '{args[0]}' ({kind}, {action})")
        return True, [f"[Admin] Keyword '{args[0]}' {status} ({kind}, {action})."]

    def _cmd_rmkw(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: rmkw <pattern>"]
        if self.rules.remove_keyword(args[0]):
            logging.info(f"Admin {actor.label} removed keyword: {args[0]}")
            return True, [f"[Admin] Keyword '{args[0]}' removed from block list."]
        return False, [f"[Admin] Keyword '{args[0]}' not found."]

    def _cmd_blockip(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: blockip <ip or CIDR> [duration, e.g. 10m]"]
        rule = args[0]
        if not core.valid_ip_rule(rule):
            return False, [f"[Admin] '{rule}' is not a valid IP or CIDR range."]
        duration = core.parse_duration(args[1]) if len(args) > 1 else None
        status = self.rules.add_ip_block(rule, duration)
        kicked = self.disconnect_matching(rule, keep=actor.info)
        suffix = f" for {args[1]}" if duration else ""
        logging.info(f"Admin {actor.label} blocked IP: {rule}{suffix} ({status})")
        lines = [f"[Admin] IP '{rule}' blocked{suffix}." if status != 'exists'
                 else f"[Admin] IP '{rule}' is already blocked permanently."]
        if kicked:
            lines.append(f"[Admin] Disconnected {kicked} matching client(s).")
        return True, lines

    def _cmd_unblockip(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: unblockip <ip or CIDR>"]
        if self.rules.remove_ip_block(args[0]):
            logging.info(f"Admin {actor.label} unblocked IP: {args[0]}")
            return True, [f"[Admin] IP '{args[0]}' unblocked."]
        return False, [f"[Admin] IP '{args[0]}' not found in block list."]

    def _cmd_allowip(self, args, text, actor):
        if not args or not core.valid_ip_rule(args[0]):
            return False, ["[Admin] Usage: allowip <ip or CIDR>"]
        if self.rules.add_allowed(args[0]):
            logging.info(f"Admin {actor.label} added to allowlist: {args[0]}")
            return True, [f"[Admin] '{args[0]}' added to the allowlist."]
        return False, [f"[Admin] '{args[0]}' is already on the allowlist."]

    def _cmd_unallowip(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: unallowip <ip or CIDR>"]
        if self.rules.remove_allowed(args[0]):
            logging.info(f"Admin {actor.label} removed from allowlist: {args[0]}")
            return True, [f"[Admin] '{args[0]}' removed from the allowlist."]
        return False, [f"[Admin] '{args[0]}' not on the allowlist."]

    def _cmd_allowlist(self, args, text, actor):
        mode = args[0].lower() if args else 'status'
        if mode == 'status':
            snap = self.rules.snapshot()
            state = 'ON' if snap['allowlist_enabled'] else 'OFF'
            return True, [f"[Admin] Allowlist mode is {state}: {', '.join(snap['allowed_ips']) or '(empty)'}"]
        if mode == 'off':
            self.rules.set_allowlist(False)
            logging.info(f"Admin {actor.label} turned allowlist mode OFF")
            return True, ["[Admin] Allowlist mode is now OFF."]
        if mode == 'on':
            if not self.rules.snapshot()['allowed_ips']:
                return False, ["[Admin] The allowlist is empty; add an entry with allowip first (everyone would be locked out)."]
            if actor.info and not self.rules.allowed_covers(actor.info.addr[0]):
                return False, ["[Admin] Your own IP is not on the allowlist; add it first or you would lock yourself out."]
            self.rules.set_allowlist(True)
            logging.info(f"Admin {actor.label} turned allowlist mode ON")
            return True, ["[Admin] Allowlist mode is now ON: only listed IPs can connect."]
        return False, ["[Admin] Usage: allowlist on|off|status"]

    def _cmd_kick(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: kick <username>"]
        target = self.find_user(args[0])
        if target is None:
            return False, [f"[Admin] User '{args[0]}' not found."]
        self.safe_send(target, "[Admin] You have been kicked from the server.")
        self.remove_client(target)
        with self.lock:
            self.stats['kicks'] += 1
        logging.info(f"Admin {actor.label} kicked user: {target.username}")
        return True, [f"[Admin] Kicked '{target.username}'."]

    def _cmd_mute(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: mute <username>"]
        with self.lock:
            self.muted.add(args[0].lower())
        target = self.find_user(args[0])
        if target:
            self.safe_send(target, "[Server] You have been muted by an admin.")
        logging.info(f"Admin {actor.label} muted user: {args[0]}")
        return True, [f"[Admin] '{args[0]}' muted."]

    def _cmd_unmute(self, args, text, actor):
        if not args:
            return False, ["[Admin] Usage: unmute <username>"]
        with self.lock:
            was_muted = args[0].lower() in self.muted
            self.muted.discard(args[0].lower())
        if not was_muted:
            return False, [f"[Admin] '{args[0]}' is not muted."]
        target = self.find_user(args[0])
        if target:
            self.safe_send(target, "[Server] You have been unmuted.")
        logging.info(f"Admin {actor.label} unmuted user: {args[0]}")
        return True, [f"[Admin] '{args[0]}' unmuted."]

    def _cmd_broadcast(self, args, text, actor):
        if not text.strip():
            return False, ["[Admin] Usage: broadcast <text>"]
        logging.info(f"Admin {actor.label} broadcast: {text}")
        self.broadcast(f"[Server] {text}")
        return True, ["[Admin] Broadcast sent."]

    def _cmd_list(self, args, text, actor):
        snap = self.rules.snapshot()
        keywords = ', '.join(f"{k['pattern']} ({k['kind']}/{k['action']})" for k in snap['keywords']) or '(none)'
        blocks = ', '.join(b['rule'] + ('' if b['expires_in'] is None else f" ({b['expires_in']}s left)")
                           for b in snap['blocked_ips']) or '(none)'
        with self.lock:
            users = ', '.join(f"{c.username}@{c.addr[0]}:{c.addr[1]}" + (' [muted]' if c.username.lower() in self.muted else '')
                              for c in self.clients.values() if c.username) or '(none)'
        state = 'ON' if snap['allowlist_enabled'] else 'OFF'
        return True, [
            f"[Admin] Keyword rules: {keywords}",
            f"[Admin] Blocked IPs: {blocks}",
            f"[Admin] Allowlist ({state}): {', '.join(snap['allowed_ips']) or '(empty)'}",
            f"[Admin] Connected users: {users}",
        ]

    def _cmd_help(self, args, text, actor):
        return True, list(HELP_LINES)

    # ------------------------------------------------------------ reporting (dashboard)

    def state(self):
        with self.lock:
            users = [{
                'username': c.username, 'ip': c.addr[0], 'port': c.addr[1],
                'is_admin': c.is_admin, 'muted': c.username.lower() in self.muted,
                'connected_for': int(time.time() - c.connected_at),
            } for c in self.clients.values() if c.username]
            keys = ('connections', 'connections_refused', 'messages_allowed', 'messages_blocked',
                    'messages_redacted', 'messages_warned', 'rate_limited', 'admin_failures',
                    'autobans', 'kicks')
            stats = {k: self.stats[k] for k in keys}
            top_blocked = [{'ip': ip, 'count': n} for ip, n in self.blocked_by_ip.most_common(10)]
            muted = sorted(self.muted)
        return {
            'uptime': int(time.time() - self.started),
            'tls': self.tls is not None,
            'stats': stats,
            'users': users,
            'muted': muted,
            'top_blocked_ips': top_blocked,
            'rules': self.rules.snapshot(),
            'limits': {'rate_messages': RATE_LIMIT_MESSAGES, 'rate_window': RATE_LIMIT_WINDOW,
                       'autoban_seconds': AUTOBAN_DURATION},
        }

    # ------------------------------------------------------------ accept loop

    def serve_forever(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            s.settimeout(1.0)  # so Ctrl+C is noticed (blocking accept ignores it on Windows)
            print(f"[Server] Listening on {host}:{port}{' (TLS)' if self.tls else ''}")
            logging.info(f"Server started on {host}:{port}{' with TLS' if self.tls else ''}")
            try:
                while True:
                    try:
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue
                    allowed, reason = self.rules.connection_allowed(addr[0])
                    if not allowed:
                        print(f"[Firewall] Refused connection from {addr[0]} ({reason})")
                        logging.warning(f"Refused connection from {addr[0]} ({reason})")
                        with self.lock:
                            self.stats['connections_refused'] += 1
                            self.blocked_by_ip[addr[0]] += 1
                        if not self.tls:  # can't send plaintext to a TLS client
                            try:
                                conn.sendall(f"[Firewall]: Your IP is {'blocked' if reason == 'blocked' else 'not allowed'}.\n".encode('utf-8'))
                            except OSError:
                                pass
                        conn.close()
                        continue
                    threading.Thread(target=self.serve_connection, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("\n[Server] Shutting down...")
                logging.info("Server shutting down")
                self.broadcast("[Server] The server is shutting down.")
                with self.lock:
                    infos = list(self.clients.values())
                for info in infos:
                    self.remove_client(info)


def build_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def load_admin_hash():
    """Admin password hash: env var (hashed in memory) first, then the password file."""
    env_password = os.environ.get(PASSWORD_ENV)
    if env_password:
        return core.hash_password(env_password)
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as f:
            return f.read().strip() or None
    return None


def set_password():
    password = getpass.getpass("New admin password (min 8 characters): ")
    if len(password) < 8:
        sys.exit("Password too short.")
    if getpass.getpass("Repeat password: ") != password:
        sys.exit("Passwords do not match.")
    with open(PASSWORD_FILE, 'w') as f:
        f.write(core.hash_password(password))
    print(f"Admin password saved (salted hash) to {PASSWORD_FILE}.")


def main():
    global RATE_LIMIT_MESSAGES, RATE_LIMIT_WINDOW
    parser = argparse.ArgumentParser(description="Chat server with a built-in firewall and web dashboard.")
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--config', default=CONFIG_FILE, help="firewall rules file")
    parser.add_argument('--log-file', default=LOG_FILE)
    parser.add_argument('--tls-cert', help="PEM certificate; with --tls-key enables TLS")
    parser.add_argument('--tls-key', help="PEM private key")
    parser.add_argument('--dashboard-host', default='127.0.0.1',
                        help="interface for the web dashboard (default: localhost only)")
    parser.add_argument('--dashboard-port', type=int, default=8080)
    parser.add_argument('--no-dashboard', action='store_true')
    parser.add_argument('--rate-messages', type=int, default=RATE_LIMIT_MESSAGES,
                        help="max messages per client per rate window (default %(default)s)")
    parser.add_argument('--rate-window', type=int, default=RATE_LIMIT_WINDOW,
                        help="rate window in seconds (default %(default)s)")
    parser.add_argument('--set-password', action='store_true', help="set the admin password and exit")
    args = parser.parse_args()
    RATE_LIMIT_MESSAGES, RATE_LIMIT_WINDOW = args.rate_messages, args.rate_window

    if args.set_password:
        set_password()
        return
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be given together")

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    events = EventLog()
    logging.getLogger().addHandler(events)

    rules = core.Rules(args.config)
    rules.load()
    admin_hash = load_admin_hash()
    if admin_hash is None:
        print(f"[!] No admin password configured: admin commands are disabled.\n"
              f"    Run 'python firewall_server.py --set-password' (or set {PASSWORD_ENV}).")
        logging.warning("No admin password configured; admin access disabled")
    tls = build_tls_context(args.tls_cert, args.tls_key) if args.tls_cert else None

    server = ChatServer(rules, admin_hash, events, tls)
    if not args.no_dashboard:
        start_dashboard(server, args.dashboard_host, args.dashboard_port)
        print(f"[Dashboard] http://{args.dashboard_host}:{args.dashboard_port}/")
    server.serve_forever(args.host, args.port)


if __name__ == "__main__":
    main()
