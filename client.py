import socket
import threading
import sys


HOST = input("Enter server IP (default 127.0.0.1): ") or "127.0.0.1"
PORT = 12345
USERNAME = input("Enter your username: ")

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("[Disconnected from server]")
                break
            print(data.decode('utf-8'))
        except:
            break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[Error connecting to server]: {e}")
            sys.exit(1)
        print(f"[Connected to {HOST}:{PORT}]")
        # Send username to server
        s.sendall(f"/username {USERNAME}".encode('utf-8'))
        response = s.recv(1024).decode('utf-8')
        print(response)
        if response.startswith('[Firewall] Username not allowed') or response.startswith('[Firewall] Username required'):
            return
        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()
        while True:
            msg = input()
            if msg.lower() == 'exit':
                break
            s.sendall(msg.encode('utf-8'))

if __name__ == "__main__":
    main()
