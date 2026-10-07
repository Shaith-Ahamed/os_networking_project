import socket
import threading
import sys


HOST = input("Enter server IP (default 127.0.0.1): ") or "127.0.0.1"
PORT = 12345
USERNAME = input("Enter your username: ")

class LineReader:
    """Reassembles the TCP byte stream into newline-delimited messages."""
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    def read_line(self):
        """Return the next message, or None if the connection closed."""
        while b'\n' not in self.buf:
            data = self.sock.recv(1024)
            if not data:
                return None
            self.buf += data
        line, self.buf = self.buf.split(b'\n', 1)
        return line.decode('utf-8', errors='replace').strip('\r')

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

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[Error connecting to server]: {e}")
            sys.exit(1)
        print(f"[Connected to {HOST}:{PORT}]")
        reader = LineReader(s)
        # Send username to server
        s.sendall(f"/username {USERNAME}\n".encode('utf-8'))
        response = reader.read_line()
        if response is None:
            print("[Disconnected from server]")
            return
        print(response)
        if response.startswith('[Firewall] Username not allowed') or response.startswith('[Firewall] Username required'):
            return
        threading.Thread(target=receive_messages, args=(reader,), daemon=True).start()
        while True:
            msg = input()
            if msg.lower() == 'exit':
                break
            s.sendall((msg + '\n').encode('utf-8'))

if __name__ == "__main__":
    main()
