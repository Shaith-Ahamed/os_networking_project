# Basic Firewall Network Programming Project

## Overview
A real-time chat application with a built-in firewall. Multiple clients chat through a central server, which filters messages and connections using configurable rules. Admins can change the rules live, from the chat or from a web dashboard. Python standard library only.

---

## Features
- **Real-time chat** between multiple clients, with private messages (`/msg`), `/users`, and join/leave notices
- **Keyword rules** — whole-word, substring or regex, each with an action: **block**, **warn** or **redact** (`****`)
- **IP blocking** — single IPs or CIDR ranges, permanent or temporary (`10m`, `2h`, ...)
- **Allowlist mode** — only listed IPs/ranges may connect
- **Rate limiting** and **auto-ban** — flooding, repeated blocked messages and wrong admin passwords get an IP banned for 10 minutes
- **Unique, validated usernames** (optional whitelist)
- **Admin tools** — kick, mute, broadcast, live rule changes
- **Web dashboard** — live stats, users, rules and event feed, with the same admin actions
- **Optional TLS** encryption
- **Salted password hash** for the admin password (never stored in the source)
- **Logging** to `firewall_server.log`

---

## Files
| File | Purpose |
|---|---|
| `firewall_server.py` | The chat server |
| `client.py` | The chat client |
| `firewall_core.py` | Rules engine (keywords, IP blocks, allowlist, password hashing) |
| `netio.py` | Socket helpers shared by client and server (thread-safe TLS, line framing) |
| `dashboard.py`, `dashboard.html` | Web dashboard |
| `firewall_config.json` | Saved rules |
| `test_firewall_core.py` | Unit tests for the rules engine |
| `test_integration.py` | End-to-end tests against a real server |
| `admin_password.hash` | Created by `--set-password` (git-ignored) |

---

## Getting started

**You need:** Python 3.8 or newer (check with `python --version`; on Linux/macOS you may need `python3`). Nothing to install with pip.

```bash
git clone <repo-url>
cd os_networking_project
```

### 1. Set the admin password (once)
```bash
python firewall_server.py --set-password
```
It is stored as a salted hash in `admin_password.hash` (git-ignored, so every user sets their own). Until a password is set, admin commands and the dashboard login are disabled. For a quick demo you can set the `FIREWALL_ADMIN_PASSWORD` environment variable instead:
- Windows PowerShell: `$env:FIREWALL_ADMIN_PASSWORD = "my-demo-password"`
- Linux/macOS: `export FIREWALL_ADMIN_PASSWORD="my-demo-password"`

### 2. Start the server
```bash
python firewall_server.py
```
You should see `[Server] Listening on 0.0.0.0:12345` and `[Dashboard] http://127.0.0.1:8080/`.

### 3. Start one or more clients (each in its own terminal)
```bash
python client.py 127.0.0.1 alice
python client.py 127.0.0.1 bob
```
Arguments are optional; the client asks for the server IP and username if you leave them out. Type a message and press Enter; the other clients see it.

### 4. Open the dashboard
Go to <http://127.0.0.1:8080/> and log in with the admin password.

### Using it from several computers
Run the server on one machine and find its IP (`ipconfig` on Windows, `ip a` on Linux). Other machines run `python client.py <server-ip> <username>`. Allow TCP port `12345` through the server's firewall (Windows Defender prompts for this the first time). The dashboard stays on that machine's `localhost` unless you change `--dashboard-host`.

### Server options
`--host`, `--port` (default 12345), `--config`, `--log-file`, `--rate-messages`, `--rate-window`, `--dashboard-host`, `--dashboard-port` (default 8080), `--no-dashboard`, `--tls-cert` / `--tls-key`. Run `python firewall_server.py --help` for details.

---

## Testing that everything works

### Automated (recommended)
```bash
python -m unittest test_firewall_core test_integration -v
```
About 30 tests, around 10 seconds. `test_integration` starts its own server in a temporary folder on free ports (it won't touch your config, log or password), so it's safe to run while your own server is running. It covers usernames, chat and private messages, keyword block/warn/redact, mute/kick/broadcast, CIDR and temporary IP bans, rate limiting, auto-ban, allowlist mode, the dashboard API, the real `client.py`, and TLS. Two groups are skipped automatically when unavailable: TLS tests need `openssl`, and allowlist/IP-ban tests need the `127.0.0.2` loopback address (not available by default on macOS). Expected result: `OK`.

### Manual walkthrough (about 3 minutes)
With the server running and two clients (`alice`, `bob`) connected:

1. **Chat:** type `hello` in alice; bob sees `alice: hello`.
2. **Private message:** in alice, `/msg bob psst`; only bob sees it.
3. **Admin login:** in alice, `/admin <your password>` then `/admin help`.
4. **Keyword rules:** `/admin addkw ass` then have bob send `nice class` (delivered) and `you ass` (blocked). Try `/admin addkw secret word redact` and have bob send `the secret is out` (alice sees `the ****** is out`).
5. **Kick/mute:** `/admin mute bob`, then bob's messages are refused; `/admin unmute bob`; `/admin kick bob`.
6. **IP blocking:** `/admin blockip 10.0.0.0/8 10m` then `/admin list` shows it with the time left; `/admin unblockip 10.0.0.0/8`.
7. **Rate limit:** paste 8 lines quickly into a client; the last ones get `Rate limit exceeded`.
8. **Dashboard:** log in at <http://127.0.0.1:8080/>; users, counters and the event feed update every 2 seconds. Add a keyword, broadcast a message, or kick a user from the page and watch the clients react.
9. **Auto-ban (do this last):** keep the dashboard open and logged in. In a client send `/admin wrong1` ... `/admin wrong5`. The fifth bans your IP for 10 minutes and disconnects you. The banned IP also can't *log in* to the dashboard or connect, but a dashboard session that is already open keeps working, so press *Unblock* next to your IP under *Blocked IPs*. (If you lose the session, wait 10 minutes, or stop the server, remove the entry from `firewall_config.json` and start it again.)

### Troubleshooting
| Problem | Fix |
|---|---|
| `Admin access is disabled` | No password set yet: run `python firewall_server.py --set-password` |
| `Address already in use` | Another server is still running, or use `--port` / `--dashboard-port` |
| Client can't connect from another PC | Use the server's real IP (not `127.0.0.1`) and allow port 12345 in its firewall |
| `Your IP is blocked` after testing | You (or an auto-ban) blocked your own IP. Edit/delete the entry in `firewall_config.json` and restart, or unblock from an allowed IP |
| `certificate verify failed` | The client needs `--cafile cert.pem`, and the cert's `subjectAltName` must contain the address you connect to |
| Old client says nothing / garbled | Client and server must be the same version (messages are newline-delimited) |
| `python` not found | Use `python3` (Linux/macOS) or install Python from python.org |

---

## Chat commands
| Command | |
|---|---|
| `/users` | Who is online |
| `/msg <user> <text>` | Private message |
| `exit` | Leave |

## Admin commands
Log in with `/admin <password>`, then:

| Command | |
|---|---|
| `/admin addkw <pattern> [word\|substring\|regex] [block\|warn\|redact]` | Add or update a keyword rule (default: whole word, block) |
| `/admin rmkw <pattern>` | Remove a keyword rule |
| `/admin blockip <ip or CIDR> [duration]` | Block an IP or range, e.g. `192.168.1.0/24` or `10.0.0.5 30m`. Connected clients that match are disconnected |
| `/admin unblockip <ip or CIDR>` | Remove a block |
| `/admin allowip` / `unallowip <ip or CIDR>` | Edit the allowlist |
| `/admin allowlist on\|off\|status` | Turn allowlist mode on/off (refuses if it would lock you out) |
| `/admin kick <user>` | Disconnect a user |
| `/admin mute <user>` / `unmute <user>` | Stop/allow a user from sending messages |
| `/admin broadcast <text>` | Message everyone as `[Server]` |
| `/admin list` | Show rules, bans and users |
| `/admin help` | Command summary |

Durations: `30s`, `10m`, `2h`, `1d`. Keyword matching is case-insensitive. Old configs with plain keyword strings still load (they are treated as substring/block rules).

---

## Rate limiting and auto-ban
- Each client may send 5 messages (commands count too) per 10 seconds; extra messages are dropped with a warning.
- An IP is banned for 10 minutes after: 10 rate-limit hits in 60 s, 10 blocked messages in 60 s, or 5 wrong admin passwords in 5 min (chat or dashboard).
- Bans are by IP, so users behind one shared address (NAT) share a ban. Admins can lift a ban with `unblockip` or from the dashboard.

---

## Web dashboard
Open `http://127.0.0.1:8080/` and log in with the admin password. It shows live counters, connected users (kick/mute), keyword rules, blocked IPs and the allowlist (add/remove), a broadcast box and a live event feed.

By default it listens on **localhost only**. It uses plain HTTP, so don't expose it with `--dashboard-host 0.0.0.0` on an untrusted network; use an SSH tunnel or a reverse proxy with HTTPS instead.

---

## TLS (encrypted chat)
```bash
# Self-signed certificate for testing
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

python firewall_server.py --tls-cert cert.pem --tls-key key.pem
python client.py 127.0.0.1 alice --cafile cert.pem      # verifies the server
python client.py 127.0.0.1 alice --insecure             # no verification (testing only)
```
Clients must use `--tls` (or `--cafile`) when the server uses TLS. For a server reached by another address or name, put that IP/name in the certificate's `subjectAltName`.

---

## Configuration
- **Rules** live in `firewall_config.json` (edited by the admin commands and the dashboard; you can also edit it while the server is stopped).
- **Username whitelist**: `USERNAME_WHITELIST` in `firewall_server.py` (empty = open). Usernames are 1-20 letters, digits, `_` or `-`; names are unique (case-insensitive) and `Server` is reserved.
- **Rate limit / auto-ban thresholds**: constants at the top of `firewall_server.py`.

---

## Requirements
Python 3.8+ (developed on 3.10). No external dependencies. `openssl` is only needed to create a test certificate.

## Notes
- A regex keyword rule is run against every message; keep patterns simple.
- The client and server must be updated together: messages are newline-delimited.
- All server activity is logged in `firewall_server.log`, including message text.

## License
This project is for educational purposes.
