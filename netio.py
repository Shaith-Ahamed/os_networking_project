"""Socket helpers shared by the client and the server."""
import select
import socket
import ssl
import threading
import time

POLL = 0.25         # how long a TLS read holds the socket before letting writers in
SEND_TIMEOUT = 30   # seconds a TLS write may take before the peer is considered stuck


class SafeSocket:
    """A socket that several threads can use: one reading while others write.

    An SSL object is not safe for a concurrent read and write, which is exactly what a
    chat needs (a thread blocked reading while other threads send). For TLS sockets the
    reader waits for data *without* holding the lock, and each actual read/write is
    serialized by the lock. Plain TCP sockets are passed straight through.
    """

    def __init__(self, sock):
        self.sock = sock
        self.tls = isinstance(sock, ssl.SSLSocket)
        self.timeout = sock.gettimeout()  # overall read timeout (None = wait forever)
        self._lock = threading.Lock()

    def settimeout(self, timeout):
        self.timeout = timeout
        if not self.tls:
            self.sock.settimeout(timeout)

    def sendall(self, data):
        if not self.tls:
            return self.sock.sendall(data)
        with self._lock:
            self.sock.settimeout(SEND_TIMEOUT)
            self.sock.sendall(data)

    def recv(self, size):
        if not self.tls:
            return self.sock.recv(size)
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        while True:
            try:
                if not self.sock.pending():
                    select.select([self.sock], [], [], POLL)  # idle wait, lock not held
            except ValueError:  # select on a socket another thread just closed
                raise OSError("socket closed")
            with self._lock:
                self.sock.settimeout(POLL)
                try:
                    return self.sock.recv(size)
                except (socket.timeout, ssl.SSLWantReadError):
                    pass  # nothing complete yet; let a writer in, then try again
            if deadline is not None and time.monotonic() > deadline:
                raise socket.timeout("timed out")

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class LineReader:
    """Reassembles the TCP byte stream into newline-delimited messages."""

    def __init__(self, conn, max_line=None):
        self.conn = conn
        self.max_line = max_line
        self.buf = b''

    def read_line(self):
        """Return the next message, or None if the connection closed."""
        while b'\n' not in self.buf:
            if self.max_line and len(self.buf) > self.max_line:
                raise ValueError("message too long")
            data = self.conn.recv(1024)
            if not data:
                return None
            self.buf += data
        line, self.buf = self.buf.split(b'\n', 1)
        if self.max_line and len(line) > self.max_line:
            raise ValueError("message too long")
        return line.decode('utf-8', errors='replace').strip('\r')
