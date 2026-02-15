# Basic Firewall Network Programming Project

## Overview
This project is a real-time network communication application with a built-in basic firewall. It allows multiple clients to chat via a server, which filters messages and connections based on configurable firewall rules. The server supports admin commands for live rule updates, user authentication, and detailed logging.

---

## Features
- **Real-time chat** between multiple clients via a central server
- **Firewall filtering**: Block messages by keywords or IP addresses
- **Configurable rules**: Edit `firewall_config.json` or use admin commands
- **Admin commands**: Add/remove keywords, block/unblock IPs in real time
- **Username authentication**: Only allowed users can connect (optional whitelist)
- **Logging**: All events are logged to `firewall_server.log`

---

## Files
- `firewall_server.py` — The server with firewall and admin logic
- `client.py` — The client for connecting and chatting
- `firewall_config.json` — Stores blocked keywords and IPs
- `firewall_server.log` — Server log file (created at runtime)

---

## How to Run

### 1. Start the Server
```bash
python firewall_server.py
```

### 2. Start a Client
```bash
python client.py
```
- Enter the server IP and your username when prompted.

---

## Admin Commands (in client)
Authenticate as admin:
```
/admin admin123
```
(Replace `admin123` with your admin password.)

Then use:
- `/admin addkw <word>` — Block a keyword
- `/admin rmkw <word>` — Remove a blocked keyword
- `/admin blockip <ip>` — Block an IP address
- `/admin unblockip <ip>` — Unblock an IP address

---

## Configuration
- **Blocked keywords/IPs**: Edit `firewall_config.json` or use admin commands
- **Username whitelist**: Set `USERNAME_WHITELIST` in `firewall_server.py` (leave empty for open access)
- **Admin password**: Change `ADMIN_PASSWORD` in `firewall_server.py`

---

## Example Usage
1. Start the server on one machine.
2. Start clients on other machines, connect using the server's IP.
3. Chat in real time. Blocked messages/IPs are filtered by the server.
4. Admin can update firewall rules live.

---

## Requirements
- Python 3.x
- No external dependencies (uses only Python standard library)

---

## Notes
- For production, change the admin password and set a username whitelist.
- All server activity is logged in `firewall_server.log`.

---

## License
This project is for educational purposes.
#

