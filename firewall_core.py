"""Firewall rules engine: keyword rules, IP blocks (with expiry), allowlist, password hashing.

Thread-safe and free of any socket code so it can be unit tested on its own.
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time

KEYWORD_KINDS = ('word', 'substring', 'regex')
KEYWORD_ACTIONS = ('block', 'warn', 'redact')


# ---------------------------------------------------------------- passwords

def hash_password(password, iterations=200_000):
    """Return 'pbkdf2_sha256$iterations$salt$hash' (salted, slow to brute force)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split('$')
        if scheme != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                     bytes.fromhex(salt_hex), int(iterations))
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


# ---------------------------------------------------------------- helpers

_DURATION = re.compile(r'^(\d+)([smhd])$')
_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}


def parse_duration(text):
    """'30s', '10m', '2h', '1d' -> seconds. Raises ValueError on anything else."""
    match = _DURATION.match(text.strip().lower())
    if not match or int(match.group(1)) == 0:
        raise ValueError(f"invalid duration '{text}' (use e.g. 30s, 10m, 2h, 1d)")
    return int(match.group(1)) * _UNITS[match.group(2)]


def valid_ip_rule(rule):
    """True if rule is a single IP (1.2.3.4) or a CIDR range (192.168.1.0/24)."""
    try:
        ipaddress.ip_network(rule, strict=False)
        return True
    except ValueError:
        return False


def ip_in_rule(ip, rule):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        return False


class KeywordRule:
    """A keyword/pattern with a match type and an action. Matching is case-insensitive."""

    def __init__(self, pattern, kind='word', action='block'):
        if kind not in KEYWORD_KINDS:
            raise ValueError(f"kind must be one of {', '.join(KEYWORD_KINDS)}")
        if action not in KEYWORD_ACTIONS:
            raise ValueError(f"action must be one of {', '.join(KEYWORD_ACTIONS)}")
        if not pattern:
            raise ValueError("pattern is empty")
        self.pattern, self.kind, self.action = pattern, kind, action
        if kind == 'word':
            # whole word: not preceded/followed by a word character ("ass" won't match "class")
            source = r'(?<!\w)' + re.escape(pattern) + r'(?!\w)'
        elif kind == 'substring':
            source = re.escape(pattern)
        else:
            source = pattern
        try:
            self.regex = re.compile(source, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}")
        if self.regex.search(''):
            raise ValueError("pattern matches empty text")

    def to_dict(self):
        return {'pattern': self.pattern, 'kind': self.kind, 'action': self.action}


class Verdict:
    def __init__(self, allowed=True, text='', matched=None, warnings=None, redacted=False):
        self.allowed = allowed
        self.text = text
        self.matched = matched or []     # patterns that caused a block
        self.warnings = warnings or []   # patterns with action 'warn' that were hit
        self.redacted = redacted


class IpEntry:
    def __init__(self, rule, expires=None):
        self.rule = rule
        self.network = ipaddress.ip_network(rule, strict=False)
        self.expires = expires  # epoch seconds, or None for permanent

    def expired(self, now):
        return self.expires is not None and now >= self.expires


# ---------------------------------------------------------------- rules

class Rules:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._keywords = []
        self._ip_blocks = []   # list of IpEntry
        self._allowed = []     # list of IpEntry (never expire)
        self.allowlist_enabled = False

    # --- persistence

    def load(self):
        with self._lock:
            data = {}
            if os.path.exists(self.path):
                with open(self.path, 'r') as f:
                    data = json.load(f)
            self._keywords, self._ip_blocks, self._allowed = [], [], []
            for item in data.get('blocked_keywords', []):
                if isinstance(item, str):  # legacy format: plain substring, block
                    item = {'pattern': item, 'kind': 'substring', 'action': 'block'}
                try:
                    self._keywords.append(KeywordRule(item['pattern'], item.get('kind', 'word'),
                                                      item.get('action', 'block')))
                except (KeyError, TypeError, ValueError) as e:
                    logging.warning(f"Ignoring invalid keyword rule {item!r} in config: {e}")
            now = time.time()
            for item in data.get('blocked_ips', []):
                rule, expires = (item, None) if isinstance(item, str) else (item.get('rule'), item.get('expires'))
                if not isinstance(rule, str) or not valid_ip_rule(rule):
                    logging.warning(f"Ignoring invalid blocked IP rule in config: {item!r}")
                elif expires is None or expires > now:
                    self._ip_blocks.append(IpEntry(rule, expires))
            for rule in data.get('allowed_ips', []):
                if isinstance(rule, str) and valid_ip_rule(rule):
                    self._allowed.append(IpEntry(rule))
                else:
                    logging.warning(f"Ignoring invalid allowed IP rule in config: {rule!r}")
            self.allowlist_enabled = bool(data.get('allowlist_enabled', False))

    def save(self):
        with self._lock:
            now = time.time()
            blocked = [b.rule if b.expires is None else {'rule': b.rule, 'expires': b.expires}
                       for b in self._ip_blocks if not b.expired(now)]
            data = {
                'blocked_keywords': [k.to_dict() for k in self._keywords],
                'blocked_ips': blocked,
                'allowlist_enabled': self.allowlist_enabled,
                'allowed_ips': [a.rule for a in self._allowed],
            }
            tmp = self.path + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.path)  # never leave a half-written config

    # --- keywords

    def add_keyword(self, pattern, kind='word', action='block'):
        """Returns 'added' or 'updated'. Raises ValueError for a bad rule."""
        rule = KeywordRule(pattern, kind, action)
        with self._lock:
            for i, existing in enumerate(self._keywords):
                if existing.pattern.lower() == pattern.lower():
                    self._keywords[i] = rule
                    self.save()
                    return 'updated'
            self._keywords.append(rule)
            self.save()
            return 'added'

    def remove_keyword(self, pattern):
        with self._lock:
            before = len(self._keywords)
            self._keywords = [k for k in self._keywords if k.pattern.lower() != pattern.lower()]
            removed = len(self._keywords) < before
            if removed:
                self.save()
            return removed

    def check_message(self, text):
        """Apply keyword rules: any 'block' hit blocks; 'redact' masks; 'warn' only reports."""
        with self._lock:
            keywords = list(self._keywords)
        blocked = [k.pattern for k in keywords if k.action == 'block' and k.regex.search(text)]
        if blocked:
            return Verdict(False, text, matched=blocked)
        warnings, redacted = [], False
        for k in keywords:
            if k.action == 'redact':
                text, count = k.regex.subn(lambda m: '*' * len(m.group()), text)
                redacted = redacted or count > 0
            elif k.action == 'warn' and k.regex.search(text):
                warnings.append(k.pattern)
        return Verdict(True, text, warnings=warnings, redacted=redacted)

    # --- IP blocks / allowlist

    @staticmethod
    def _find(entries, rule):
        network = ipaddress.ip_network(rule, strict=False)
        for entry in entries:
            if entry.network == network:  # 10.0.0.5 and 10.0.0.5/32 are the same rule
                return entry
        return None

    def add_ip_block(self, rule, duration=None):
        """Block an IP/CIDR, optionally for `duration` seconds.
        Returns 'added', 'updated' or 'exists' (a permanent block is never downgraded)."""
        expires = time.time() + duration if duration else None
        with self._lock:
            self._purge(time.time())
            existing = self._find(self._ip_blocks, rule)
            if existing:
                if existing.expires is None and expires is not None:
                    return 'exists'
                existing.expires = expires
                self.save()
                return 'updated'
            self._ip_blocks.append(IpEntry(rule, expires))
            self.save()
            return 'added'

    def remove_ip_block(self, rule):
        with self._lock:
            existing = self._find(self._ip_blocks, rule)
            if existing:
                self._ip_blocks.remove(existing)
                self.save()
            return existing is not None

    def add_allowed(self, rule):
        with self._lock:
            if self._find(self._allowed, rule):
                return False
            self._allowed.append(IpEntry(rule))
            self.save()
            return True

    def remove_allowed(self, rule):
        with self._lock:
            existing = self._find(self._allowed, rule)
            if existing:
                self._allowed.remove(existing)
                self.save()
            return existing is not None

    def set_allowlist(self, enabled):
        with self._lock:
            self.allowlist_enabled = enabled
            self.save()

    def allowed_covers(self, ip):
        address = ipaddress.ip_address(ip)
        with self._lock:
            return any(address in a.network for a in self._allowed)

    def _purge(self, now):  # caller holds the lock
        self._ip_blocks = [b for b in self._ip_blocks if not b.expired(now)]

    def ip_is_blocked(self, ip):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self._lock:
            self._purge(time.time())
            return any(address in b.network for b in self._ip_blocks)

    def connection_allowed(self, ip):
        """(True, '') or (False, reason)."""
        if self.ip_is_blocked(ip):
            return False, 'blocked'
        if self.allowlist_enabled and not self.allowed_covers(ip):
            return False, 'not on allowlist'
        return True, ''

    # --- reporting

    def snapshot(self):
        now = time.time()
        with self._lock:
            self._purge(now)
            return {
                'keywords': [k.to_dict() for k in self._keywords],
                'blocked_ips': [{'rule': b.rule,
                                 'expires_in': None if b.expires is None else max(0, int(b.expires - now))}
                                for b in self._ip_blocks],
                'allowlist_enabled': self.allowlist_enabled,
                'allowed_ips': [a.rule for a in self._allowed],
            }
