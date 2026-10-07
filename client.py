import argparse
import socket
import ssl
import sys
import threading

from netio import LineReader, SafeSocket


def receive_messages(reader):
    while True:
        try:
            line = reader.read_line()
            if line is None:
                print("[Disconnected from server]")
                break
            print(line)
        except OSError:
            break

def parse_args():
    parser = argparse.ArgumentParser(description="Chat client for the firewall server.")
    parser.add_argument('host', nargs='?', help="server IP (asked for if omitted)")
    parser.add_argument('username', nargs='?', help="your username (asked for if omitted)")
    parser.add_argument('--port', type=int, default=12345)
    parser.add_argument('--tls', action='store_true', help="connect over TLS")
    parser.add_argument('--cafile', help="trust this server certificate (PEM); implies --tls")
    parser.add_argument('--insecure', action='store_true',
                        help="TLS without verifying the server certificate (testing only)")
    args = parser.parse_args()
    args.host = args.host or input("Enter server IP (default 127.0.0.1): ") or "127.0.0.1"
    args.username = args.username or input("Enter your username: ")
    return args

def connect(args):
    sock = socket.create_connection((args.host, args.port), timeout=10)
    if args.tls or args.cafile or args.insecure:
        context = ssl.create_default_context(cafile=args.cafile)
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=args.host)
    sock.settimeout(None)
    return SafeSocket(sock)

def main():
    args = parse_args()
    try:
        s = connect(args)
    except (OSError, ssl.SSLError) as e:
        print(f"[Error connecting to server]: {e}")
        sys.exit(1)
    with s:
        print(f"[Connected to {args.host}:{args.port}]")
        reader = LineReader(s)
        # Send username to server
        s.sendall(f"/username {args.username}\n".encode('utf-8'))
        response = reader.read_line()
        if response is None:
            print("[Disconnected from server]")
            return
        print(response)
        if not response.startswith('[Firewall] Welcome'):
            return  # username rejected (invalid, not allowed, or already in use)
        threading.Thread(target=receive_messages, args=(reader,), daemon=True).start()
        while True:
            try:
                msg = input()
            except EOFError:
                break
            if msg.lower() == 'exit':
                break
            try:
                s.sendall((msg + '\n').encode('utf-8'))
            except OSError:
                print("[Disconnected from server]")
                break

if __name__ == "__main__":
    main()
