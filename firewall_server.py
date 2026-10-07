import socket
import threading
import json
import os
import logging
import time
from collections import deque


CONFIG_FILE = 'firewall_config.json'
LOG_FILE = 'firewall_server.log'
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345
MAX_LINE = 4096  # longest allowed message (bytes) before the client is dropped
RATE_LIMIT_MESSAGES = 5  # max messages (including commands) per client...
RATE_LIMIT_WINDOW = 10   # ...within this many seconds

clients = {}  # conn -> per-connection send lock
client_info = {}  # conn -> (username, addr), set once the client authenticates
BLOCKED_KEYWORDS = []
BLOCKED_IPS = []

# Guards clients, BLOCKED_KEYWORDS, BLOCKED_IPS and config file writes
state_lock = threading.RLock()


# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


ADMIN_PASSWORD = 'admin123'  # Change this for production
USERNAME_WHITELIST = []  # Add usernames to restrict access, or leave empty for open access

def load_config():
    global BLOCKED_KEYWORDS, BLOCKED_IPS
    with state_lock:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                BLOCKED_KEYWORDS = [w.lower() for w in config.get('blocked_keywords', [])]
                BLOCKED_IPS = config.get('blocked_ips', [])
        else:
            BLOCKED_KEYWORDS = []
            BLOCKED_IPS = []

def save_config():
    with state_lock:
        config = {
            'blocked_keywords': BLOCKED_KEYWORDS,
            'blocked_ips': BLOCKED_IPS
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

def send_line(conn, text):
    """Send one newline-terminated message; writes to one socket never interleave."""
    with state_lock:
        send_lock = clients.get(conn)
    payload = (text + '\n').encode('utf-8')
    if send_lock is None:
        conn.sendall(payload)
    else:
        with send_lock:
            conn.sendall(payload)

class LineReader:
    """Reassembles the TCP byte stream into newline-delimited messages."""
    def __init__(self, conn):
        self.conn = conn
        self.buf = b''

    def read_line(self):
        """Return the next message, or None if the connection closed."""
        while b'\n' not in self.buf:
            if len(self.buf) > MAX_LINE:
                raise ValueError("message too long")
            data = self.conn.recv(1024)
            if not data:
                return None
            self.buf += data
        line, self.buf = self.buf.split(b'\n', 1)
        if len(line) > MAX_LINE:
            raise ValueError("message too long")
        return line.decode('utf-8', errors='replace').strip('\r')

def remove_client(conn):
    with state_lock:
        clients.pop(conn, None)
        client_info.pop(conn, None)
    try:
        conn.close()
    except OSError:
        pass

def firewall_filter(message, addr):
    """Return True if message is allowed, False if blocked."""
    ip = addr[0]
    lowered = message.lower()
    with state_lock:
        if ip in BLOCKED_IPS:
            return False
        for word in BLOCKED_KEYWORDS:
            if word in lowered:
                return False
    return True

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    logging.info(f"Connected by {addr}")
    is_admin = False
    username = None
    reader = LineReader(conn)
    recent = deque()  # timestamps of this client's recent messages
    # Require username authentication
    try:
        message = reader.read_line()
        if message is None:
            remove_client(conn)
            return
        if message.startswith('/username '):
            username = message.split(' ', 1)[1].strip()
            if USERNAME_WHITELIST and username not in USERNAME_WHITELIST:
                send_line(conn, "[Firewall] Username not allowed.")
                remove_client(conn)
                logging.warning(f"Connection from {addr} rejected: username '{username}' not allowed.")
                return
            with state_lock:
                client_info[conn] = (username, addr)
            send_line(conn, f"[Firewall] Welcome, {username}!")
            logging.info(f"{addr} authenticated as '{username}'")
        else:
            send_line(conn, "[Firewall] Username required. Please reconnect.")
            remove_client(conn)
            return
    except Exception as e:
        logging.error(f"Error during username authentication from {addr}: {e}")
        remove_client(conn)
        return

    while True:
        try:
            message = reader.read_line()
            if message is None:
                break
            print(f"[Received from {username}@{addr}]: {message}")
            # Rate limiting: sliding window over the last RATE_LIMIT_WINDOW seconds
            now = time.monotonic()
            while recent and now - recent[0] > RATE_LIMIT_WINDOW:
                recent.popleft()
            if len(recent) >= RATE_LIMIT_MESSAGES:
                logging.warning(f"Rate limit exceeded by {username}@{addr}")
                send_line(conn, f"[Firewall]: Rate limit exceeded ({RATE_LIMIT_MESSAGES} messages per {RATE_LIMIT_WINDOW}s). Slow down.")
                continue
            recent.append(now)
            # Admin authentication and commands
            if message.startswith('/admin'):
                parts = message.strip().split()
                if len(parts) >= 2 and parts[1] == ADMIN_PASSWORD:
                    is_admin = True
                    send_line(conn, "[Admin] Authenticated. You can now send admin commands.")
                    logging.info(f"{addr} ({username}) authenticated as admin.")
                elif is_admin:
                    # Admin commands: /admin addkw <word>, /admin rmkw <word>, /admin blockip <ip>, /admin unblockip <ip>
                    if len(parts) >= 3 and parts[1] == 'addkw':
                        word = parts[2].lower()
                        with state_lock:
                            added = word not in BLOCKED_KEYWORDS
                            if added:
                                BLOCKED_KEYWORDS.append(word)
                                save_config()
                        if added:
                            send_line(conn, f"[Admin] Keyword '{word}' added to block list.")
                            logging.info(f"Admin {addr} ({username}) added blocked keyword: {word}")
                        else:
                            send_line(conn, f"[Admin] Keyword '{word}' already blocked.")
                    elif len(parts) >= 3 and parts[1] == 'rmkw':
                        word = parts[2].lower()
                        with state_lock:
                            removed = word in BLOCKED_KEYWORDS
                            if removed:
                                BLOCKED_KEYWORDS.remove(word)
                                save_config()
                        if removed:
                            send_line(conn, f"[Admin] Keyword '{word}' removed from block list.")
                            logging.info(f"Admin {addr} ({username}) removed blocked keyword: {word}")
                        else:
                            send_line(conn, f"[Admin] Keyword '{word}' not found.")
                    elif len(parts) >= 3 and parts[1] == 'blockip':
                        ip = parts[2]
                        with state_lock:
                            added = ip not in BLOCKED_IPS
                            if added:
                                BLOCKED_IPS.append(ip)
                                save_config()
                        if added:
                            send_line(conn, f"[Admin] IP '{ip}' blocked.")
                            logging.info(f"Admin {addr} ({username}) blocked IP: {ip}")
                        else:
                            send_line(conn, f"[Admin] IP '{ip}' already blocked.")
                    elif len(parts) >= 3 and parts[1] == 'unblockip':
                        ip = parts[2]
                        with state_lock:
                            removed = ip in BLOCKED_IPS
                            if removed:
                                BLOCKED_IPS.remove(ip)
                                save_config()
                        if removed:
                            send_line(conn, f"[Admin] IP '{ip}' unblocked.")
                            logging.info(f"Admin {addr} ({username}) unblocked IP: {ip}")
                        else:
                            send_line(conn, f"[Admin] IP '{ip}' not found in block list.")
                    elif len(parts) >= 2 and parts[1] == 'list':
                        with state_lock:
                            keywords = ', '.join(BLOCKED_KEYWORDS) or '(none)'
                            ips = ', '.join(BLOCKED_IPS) or '(none)'
                            users = ', '.join(f"{u}@{a[0]}:{a[1]}" for u, a in client_info.values()) or '(none)'
                        send_line(conn, f"[Admin] Blocked keywords: {keywords}")
                        send_line(conn, f"[Admin] Blocked IPs: {ips}")
                        send_line(conn, f"[Admin] Connected users: {users}")
                    elif len(parts) >= 3 and parts[1] == 'kick':
                        target = parts[2]
                        with state_lock:
                            targets = [c for c, (u, _) in client_info.items() if u == target]
                        for target_conn in targets:
                            try:
                                send_line(target_conn, "[Admin] You have been kicked from the server.")
                            except OSError:
                                pass
                            remove_client(target_conn)
                        if targets:
                            send_line(conn, f"[Admin] Kicked {len(targets)} connection(s) for user '{target}'.")
                            logging.info(f"Admin {addr} ({username}) kicked user: {target}")
                        else:
                            send_line(conn, f"[Admin] User '{target}' not found.")
                    else:
                        send_line(conn, "[Admin] Unknown command or missing argument.")
                else:
                    send_line(conn, "[Admin] Authentication failed or not authenticated. Use /admin <password> to authenticate.")
                continue
            # End admin commands
            if firewall_filter(message, addr):
                logging.info(f"Allowed message from {username}@{addr}: {message}")
                # Broadcast to all other clients
                with state_lock:
                    others = [c for c in clients if c != conn]
                for client in others:
                    try:
                        send_line(client, f"{username}@{addr}: {message}")
                    except OSError:
                        pass  # that client's own thread will clean it up
            else:
                logging.warning(f"Blocked message from {username}@{addr}: {message}")
                send_line(conn, "[Firewall]: Your message was blocked or your IP is blocked.")
        except Exception as e:
            with state_lock:
                kicked = conn not in clients  # socket was closed by /admin kick
            if not kicked:
                logging.error(f"Error handling client {addr}: {e}")
            break
    print(f"[-] Disconnected {addr}")
    logging.info(f"Disconnected {addr} ({username})")
    remove_client(conn)

def main():
    load_config()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        logging.info(f"Server started on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with state_lock:
                ip_blocked = addr[0] in BLOCKED_IPS
            if ip_blocked:
                print(f"[Firewall] Blocked connection attempt from {addr[0]}")
                logging.warning(f"Blocked connection attempt from {addr[0]}")
                send_line(conn, "[Firewall]: Your IP is blocked.")
                conn.close()
                continue
            with state_lock:
                clients[conn] = threading.Lock()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()
