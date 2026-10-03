"""
Web app sign-in security: two-factor codes (TOTP), server-side sessions, and reporting to the
security log / IP block list kept by the mail service.

State lives in DATA_DIR/security.json (the viewer_data volume), shared by all gunicorn workers.
The two-factor secret is encrypted with a key derived from SECRET_KEY.

Sessions: every sign-in gets a random id stored here. A browser cookie is only accepted while its
id is still listed, so "Sign out" / "Sign out everywhere" really end a session (a copied cookie
stops working), and the Security page can list and end individual sessions.
"""

import base64
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

logger = logging.getLogger("bearermail.viewer.security")

TOTP_PERIOD = 30
TOTP_DIGITS = 6
RECOVERY_CODE_COUNT = 10
LAST_SEEN_WRITE_SECONDS = 300


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) - compatible with Google Authenticator, Aegis, 1Password, Bitwarden, ...
# ---------------------------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at if at is not None else time.time()) // TOTP_PERIOD))


def totp_match(secret_b32: str, code: str, at: float | None = None, window: int = 1) -> int | None:
    """Returns the matching time step (to prevent reuse), or None."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    step = int((at if at is not None else time.time()) // TOTP_PERIOD)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, step + delta), code):
            return step + delta
    return None


def otpauth_uri(secret_b32: str, account: str, issuer: str = "BearerMail") -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


def qr_svg(data: str) -> str:
    """QR code as inline SVG (no images are fetched from anywhere)."""
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:  # pragma: no cover
        return ""
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    raw = img.to_string()
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return text[text.find("<svg"):] if "<svg" in text else text


def _hash_code(code: str) -> str:
    return hashlib.sha256(("bearermail-recovery:" + code.replace("-", "").lower()).encode()).hexdigest()


def new_recovery_codes() -> tuple[list, list]:
    """Returns (codes to show once, hashes to store)."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [_hash_code(c) for c in codes]


# ---------------------------------------------------------------------------
# Encrypted storage
# ---------------------------------------------------------------------------

class SecurityStore:
    def __init__(self, data_dir: str, secret_key: str, session_hours: int):
        self.path = os.path.join(data_dir, "security.json")
        self.lock_path = os.path.join(data_dir, "security.lock")
        self.session_seconds = max(1, session_hours) * 3600
        self._fernet = self._make_fernet(secret_key)
        self._cache = None
        self._cache_mtime = 0.0
        self._local_lock = threading.Lock()

    @staticmethod
    def _make_fernet(secret_key: str):
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(hashlib.sha256(("bearermail-viewer:" + secret_key).encode()).digest())
        return Fernet(key)

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str | None:
        from cryptography.fernet import InvalidToken
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except (InvalidToken, ValueError):
            return None

    @contextmanager
    def _file_lock(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self._local_lock, open(self.lock_path, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _read_file(self) -> dict:
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def read(self) -> dict:
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return {}
        if self._cache is None or mtime != self._cache_mtime:
            self._cache = self._read_file()
            self._cache_mtime = mtime
        return self._cache

    @contextmanager
    def edit(self):
        """Read-modify-write under an exclusive lock (safe with several gunicorn workers)."""
        with self._file_lock():
            data = self._read_file()
            yield data
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            self._cache = None

    # -- sessions --
    # A sign-in stays valid as long as it is used: it ends after ``ttl`` seconds WITHOUT activity
    # (each person's "Stay signed in" length, or SESSION_HOURS), not at a fixed time after signing in.
    def _expired(self, info: dict, now: float) -> bool:
        ttl = info.get("ttl") or self.session_seconds
        return now - max(info.get("last_seen", 0), info.get("created", 0)) > ttl

    def create_session(self, ip: str, user_agent: str, method: str, user: str = "", ttl: int | None = None) -> str:
        sid = secrets.token_urlsafe(24)
        now = time.time()
        with self.edit() as data:
            sessions = data.setdefault("sessions", {})
            for key in [k for k, v in sessions.items() if self._expired(v, now)]:
                sessions.pop(key, None)
            sessions[sid] = {"created": now, "last_seen": now, "ip": ip[:64], "ua": (user_agent or "")[:200], "method": method,
                             "user": (user or "")[:320], "ttl": int(ttl or self.session_seconds)}
        return sid

    def session_valid(self, sid: str) -> bool:
        if not sid:
            return False
        info = self.read().get("sessions", {}).get(sid)
        return bool(info) and not self._expired(info, time.time())

    def set_session_ttl(self, sid: str, ttl: int):
        info = self.read().get("sessions", {}).get(sid)
        if not info or info.get("ttl") == int(ttl):
            return
        with self.edit() as data:
            entry = data.get("sessions", {}).get(sid)
            if entry:
                entry["ttl"] = int(ttl)

    def touch_session(self, sid: str, ip: str):
        info = self.read().get("sessions", {}).get(sid)
        if not info or time.time() - info.get("last_seen", 0) < LAST_SEEN_WRITE_SECONDS:
            return
        with self.edit() as data:
            entry = data.get("sessions", {}).get(sid)
            if entry:
                entry["last_seen"] = time.time()
                entry["ip"] = ip[:64]

    def end_session(self, sid: str) -> bool:
        with self.edit() as data:
            return data.setdefault("sessions", {}).pop(sid, None) is not None

    def end_other_sessions(self, keep_sid: str, user: str | None = None) -> int:
        """End every session except keep_sid; with user, only that person's sessions."""
        with self.edit() as data:
            sessions = data.setdefault("sessions", {})
            gone = [k for k, v in sessions.items() if k != keep_sid and (user is None or v.get("user", "") == user)]
            for k in gone:
                sessions.pop(k, None)
            return len(gone)

    def list_sessions(self, user: str | None = None) -> list:
        now = time.time()
        out = []
        for sid, info in self.read().get("sessions", {}).items():
            if self._expired(info, now):
                continue
            if user is not None and info.get("user", "") != user:
                continue
            out.append({"id": sid, **info})
        return sorted(out, key=lambda s: -s.get("last_seen", 0))

    # -- two-factor --
    def totp_enabled(self) -> bool:
        return bool(self.read().get("totp", {}).get("enabled"))

    def totp_secret(self) -> str | None:
        enc = self.read().get("totp", {}).get("secret_enc")
        return self.decrypt(enc) if enc else None

    def verify_second_factor(self, code: str) -> str | None:
        """Checks a 6-digit code or a recovery code. Returns 'totp', 'recovery' or None."""
        code = (code or "").strip()
        digits = "".join(ch for ch in code if ch.isdigit())
        if len(digits) == TOTP_DIGITS and len(code.replace(" ", "")) == TOTP_DIGITS:
            secret = self.totp_secret()
            if not secret:
                return None
            step = totp_match(secret, digits)
            if step is None:
                return None
            with self.edit() as data:
                totp = data.setdefault("totp", {})
                if step <= int(totp.get("last_step", -1)):
                    return None  # the same code cannot be used twice
                totp["last_step"] = step
            return "totp"
        wanted = _hash_code(code)
        with self.edit() as data:
            hashes = data.setdefault("totp", {}).get("recovery", [])
            for h in hashes:
                if hmac.compare_digest(h, wanted):
                    hashes.remove(h)
                    return "recovery"
        return None

    def enable_totp(self, secret: str) -> list:
        codes, hashes = new_recovery_codes()
        with self.edit() as data:
            data["totp"] = {"enabled": True, "secret_enc": self.encrypt(secret), "recovery": hashes,
                            "enabled_at": time.time(), "last_step": -1}
        return codes

    def disable_totp(self):
        with self.edit() as data:
            data["totp"] = {"enabled": False}

    def regenerate_recovery_codes(self) -> list:
        codes, hashes = new_recovery_codes()
        with self.edit() as data:
            data.setdefault("totp", {})["recovery"] = hashes
        return codes

    def recovery_codes_left(self) -> int:
        return len(self.read().get("totp", {}).get("recovery", []))


# ---------------------------------------------------------------------------
# Reporting to the mail service (security log + block list)
# ---------------------------------------------------------------------------

class SecurityReporter:
    def __init__(self, base_url: str, api_key: str, http_session):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.http = http_session
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="seclog")
        self._block = {"ts": 0.0, "nets": []}
        self._block_lock = threading.Lock()

    def report(self, kind: str, ip: str = "", user: str = "", detail: str = "", aggregate: bool | None = None):
        if not self.api_key or not self.base_url:
            return
        body = {"source": "web", "kind": kind, "ip": ip, "user": user, "detail": detail[:300]}
        if aggregate is not None:
            body["aggregate"] = aggregate

        def _send():
            try:
                self.http.post(f"{self.base_url}/admin/security/events", json=body,
                               headers={"Authorization": f"Bearer {self.api_key}"}, timeout=5)
            except Exception as exc:  # pragma: no cover
                logger.debug("security event not sent: %s", exc)

        self.pool.submit(_send)

    def blocked(self, ip: str) -> bool:
        import ipaddress
        now = time.time()
        if now - self._block["ts"] > 30:
            with self._block_lock:
                if now - self._block["ts"] > 30:
                    nets = self._block["nets"]
                    try:
                        resp = self.http.get(f"{self.base_url}/admin/security/blocklist",
                                             headers={"Authorization": f"Bearer {self.api_key}"}, timeout=3)
                        if resp.status_code == 200:
                            nets = []
                            for entry in resp.json().get("blocklist", []):
                                exp = entry.get("expires_at")
                                if exp and exp < time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()):
                                    continue
                                try:
                                    nets.append(ipaddress.ip_network(entry["ip"], strict=False))
                                except (ValueError, KeyError):
                                    continue
                    except Exception:
                        pass  # keep the last known list if the mail service is briefly unavailable
                    self._block = {"ts": time.time(), "nets": nets}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self._block["nets"])
