import socket
import threading
import json
import os
import logging


CONFIG_FILE = 'firewall_config.json'
LOG_FILE = 'firewall_server.log'
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345

clients = []
BLOCKED_KEYWORDS = []
BLOCKED_IPS = []


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
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            BLOCKED_KEYWORDS = config.get('blocked_keywords', [])
            BLOCKED_IPS = config.get('blocked_ips', [])
    else:
        BLOCKED_KEYWORDS = []
        BLOCKED_IPS = []

def save_config():
    config = {
        'blocked_keywords': BLOCKED_KEYWORDS,
        'blocked_ips': BLOCKED_IPS
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def firewall_filter(message, addr):
    """Return True if message is allowed, False if blocked."""
    ip = addr[0]
    if ip in BLOCKED_IPS:
        return False
    for word in BLOCKED_KEYWORDS:
        if word in message.lower():
            return False
    return True

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    logging.info(f"Connected by {addr}")
    is_admin = False
    username = None
    # Require username authentication
    try:
        data = conn.recv(1024)
        if not data:
            conn.sendall(b"[Firewall] Username required.")
            conn.close()
            return
        message = data.decode('utf-8')
        if message.startswith('/username '):
            username = message.split(' ', 1)[1].strip()
            if USERNAME_WHITELIST and username not in USERNAME_WHITELIST:
                conn.sendall(b"[Firewall] Username not allowed.")
                conn.close()
                logging.warning(f"Connection from {addr} rejected: username '{username}' not allowed.")
                return
            conn.sendall(f"[Firewall] Welcome, {username}!".encode('utf-8'))
            logging.info(f"{addr} authenticated as '{username}'")
        else:
            conn.sendall(b"[Firewall] Username required. Please reconnect.")
            conn.close()
            return
    except Exception as e:
        logging.error(f"Error during username authentication from {addr}: {e}")
        conn.close()
        return

    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode('utf-8')
            print(f"[Received from {username}@{addr}]: {message}")
            # Admin authentication and commands
            if message.startswith('/admin'):
                parts = message.strip().split()
                if len(parts) >= 2 and parts[1] == ADMIN_PASSWORD:
                    is_admin = True
                    conn.sendall(b"[Admin] Authenticated. You can now send admin commands.")
                    logging.info(f"{addr} ({username}) authenticated as admin.")
                elif is_admin:
                    # Admin commands: /admin addkw <word>, /admin rmkw <word>, /admin blockip <ip>, /admin unblockip <ip>
                    if len(parts) >= 3 and parts[1] == 'addkw':
                        word = parts[2]
                        if word not in BLOCKED_KEYWORDS:
                            BLOCKED_KEYWORDS.append(word)
                            save_config()
                            conn.sendall(f"[Admin] Keyword '{word}' added to block list.".encode('utf-8'))
                            logging.info(f"Admin {addr} ({username}) added blocked keyword: {word}")
                        else:
                            conn.sendall(f"[Admin] Keyword '{word}' already blocked.".encode('utf-8'))
                    elif len(parts) >= 3 and parts[1] == 'rmkw':
                        word = parts[2]
                        if word in BLOCKED_KEYWORDS:
                            BLOCKED_KEYWORDS.remove(word)
                            save_config()
                            conn.sendall(f"[Admin] Keyword '{word}' removed from block list.".encode('utf-8'))
                            logging.info(f"Admin {addr} ({username}) removed blocked keyword: {word}")
                        else:
                            conn.sendall(f"[Admin] Keyword '{word}' not found.".encode('utf-8'))
                    elif len(parts) >= 3 and parts[1] == 'blockip':
                        ip = parts[2]
                        if ip not in BLOCKED_IPS:
                            BLOCKED_IPS.append(ip)
                            save_config()
                            conn.sendall(f"[Admin] IP '{ip}' blocked.".encode('utf-8'))
                            logging.info(f"Admin {addr} ({username}) blocked IP: {ip}")
                        else:
                            conn.sendall(f"[Admin] IP '{ip}' already blocked.".encode('utf-8'))
                    elif len(parts) >= 3 and parts[1] == 'unblockip':
                        ip = parts[2]
                        if ip in BLOCKED_IPS:
                            BLOCKED_IPS.remove(ip)
                            save_config()
                            conn.sendall(f"[Admin] IP '{ip}' unblocked.".encode('utf-8'))
                            logging.info(f"Admin {addr} ({username}) unblocked IP: {ip}")
                        else:
                            conn.sendall(f"[Admin] IP '{ip}' not found in block list.".encode('utf-8'))
                    else:
                        conn.sendall(b"[Admin] Unknown command or missing argument.")
                else:
                    conn.sendall(b"[Admin] Authentication failed or not authenticated. Use /admin <password> to authenticate.")
                continue
            # End admin commands
            if firewall_filter(message, addr):
                logging.info(f"Allowed message from {username}@{addr}: {message}")
                # Broadcast to all other clients
                for client in clients:
                    if client != conn:
                        client.sendall(f"{username}@{addr}: {message}".encode('utf-8'))
            else:
                logging.warning(f"Blocked message from {username}@{addr}: {message}")
                conn.sendall(b"[Firewall]: Your message was blocked or your IP is blocked.")
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
            break
    print(f"[-] Disconnected {addr}")
    logging.info(f"Disconnected {addr} ({username})")
    clients.remove(conn)
    conn.close()

def main():
    load_config()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        logging.info(f"Server started on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            if addr[0] in BLOCKED_IPS:
                print(f"[Firewall] Blocked connection attempt from {addr[0]}")
                logging.warning(f"Blocked connection attempt from {addr[0]}")
                conn.sendall(b"[Firewall]: Your IP is blocked.")
                conn.close()
                continue
            clients.append(conn)
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()
