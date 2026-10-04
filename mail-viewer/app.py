import base64
import binascii
import hmac
import ipaddress
import os
import secrets
import re
import socket
import time
from collections import defaultdict
from functools import wraps
from html import unescape

import requests
import bleach
from bleach.css_sanitizer import CSSSanitizer
from urllib.parse import urlparse, urljoin, quote
from flask import Flask, g, render_template, jsonify, request, session, redirect, url_for, Response, stream_with_context

import email_privacy
import security as sec

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "mail-viewer-secret-key-change-me")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"
app.config.update(
    # The cookie may live up to a year; the server decides when a sign-in ends (see _session_ttl).
    PERMANENT_SESSION_LIFETIME=366 * 24 * 3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)

if app.secret_key == "mail-viewer-secret-key-change-me":
    import warnings
    warnings.warn("⚠️ SECRET_KEY is using default value! Set it via environment variable in production!")

# Access password for the web UI
ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "")

# Mail service API configuration
DUCKMAIL_BASE_URL = os.getenv("DUCKMAIL_BASE_URL", "http://mail-service:8080")  # the mail-service container in docker-compose
DUCKMAIL_API_KEY = os.getenv("DUCKMAIL_API_KEY", "")
IMAP_MAIL_BASE_URL = os.getenv("IMAP_MAIL_BASE_URL", "http://imap-mail:3939")
BRIDGE_TOKEN = os.getenv("BRIDGE_TOKEN", "") or DUCKMAIL_API_KEY

MAX_IMAGE_PROXY_BYTES = int(os.getenv("MAX_IMAGE_PROXY_BYTES", str(5 * 1024 * 1024)))

# Outgoing attachment limits (raw bytes, before base64)
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", str(5 * 1024 * 1024)))
MAX_ATTACHMENT_TOTAL_BYTES = int(os.getenv("MAX_ATTACHMENT_TOTAL_BYTES", str(10 * 1024 * 1024)))
MAX_ATTACHMENT_COUNT = int(os.getenv("MAX_ATTACHMENT_COUNT", "10"))
# base64 inflates by ~4/3; leave headroom for the body
app.config["MAX_CONTENT_LENGTH"] = int(
    os.getenv("MAX_CONTENT_LENGTH", str(MAX_ATTACHMENT_TOTAL_BYTES * 4 // 3 + 2 * 1024 * 1024))
)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


AUTO_CREATE_ACCOUNTS = _env_flag("AUTO_CREATE_ACCOUNTS", default=not IS_PRODUCTION)
LOGIN_RATE_LIMIT_WINDOW = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW", "300"))
LOGIN_RATE_LIMIT_MAX = int(os.getenv("LOGIN_RATE_LIMIT_MAX", "10"))
SENSITIVE_RATE_LIMIT_WINDOW = int(os.getenv("SENSITIVE_RATE_LIMIT_WINDOW", "60"))
SENSITIVE_RATE_LIMIT_MAX = int(os.getenv("SENSITIVE_RATE_LIMIT_MAX", "20"))
_rate_limit_store: dict[str, list[float]] = defaultdict(list)

_EMAIL_ALLOWED_TAGS = [
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em", "font",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol",
    "p", "pre", "span", "strong", "table", "tbody", "td", "th", "thead",
    "tr", "u", "ul",
]
_EMAIL_ALLOWED_ATTRIBUTES = {
    # class/id are inert attributes (no URLs, no scripts);
    # with <style> allowed, selectors need them to match anything
    "*": ["align", "valign", "class", "id"],
    "a": ["href", "title", "target", "rel", "style"],
    "div": ["style"],
    "font": ["color", "size", "face"],
    "img": ["src", "alt", "title", "width", "height", "style"],
    "p": ["style"],
    "span": ["style"],
    "table": ["border", "cellpadding", "cellspacing", "width", "style"],
    "tbody": ["style"],
    "thead": ["style"],
    "tr": ["style"],
    "td": ["colspan", "rowspan", "width", "height", "style"],
    "th": ["colspan", "rowspan", "width", "height", "style"],
}
_EMAIL_ALLOWED_CSS_PROPERTIES = [
    "background", "background-color", "border", "border-bottom", "border-collapse",
    "border-left", "border-radius", "border-right", "border-spacing", "border-top",
    "clear", "color", "display", "float", "font", "font-family", "font-size",
    "font-style", "font-weight", "height", "letter-spacing", "line-height",
    "list-style", "margin", "margin-bottom", "margin-left", "margin-right",
    "margin-top", "max-height", "max-width", "min-height", "min-width", "opacity",
    "overflow", "padding", "padding-bottom", "padding-left", "padding-right",
    "padding-top", "text-align", "text-decoration", "text-transform",
    "vertical-align", "visibility", "white-space", "width", "word-break",
]
_EMAIL_CSS_SANITIZER = CSSSanitizer(allowed_css_properties=_EMAIL_ALLOWED_CSS_PROPERTIES)


def _require_production_value(name: str, value: str, disallowed: set[str] | None = None):
    if not IS_PRODUCTION:
        return
    disallowed = disallowed or set()
    normalized = (value or "").strip()
    if not normalized or normalized in disallowed:
        raise RuntimeError(f"{name} must be configured for production")


_require_production_value("SECRET_KEY", app.secret_key, {"mail-viewer-secret-key-change-me"})
_require_production_value("ACCESS_PASSWORD", ACCESS_PASSWORD)
_require_production_value("DUCKMAIL_API_KEY", DUCKMAIL_API_KEY)
_require_production_value("DUCKMAIL_BASE_URL", DUCKMAIL_BASE_URL)
_require_production_value("IMAP_MAIL_BASE_URL", IMAP_MAIL_BASE_URL)
# These checks apply in every environment: a public default secret, or no login password, would leave the app open.
if os.getenv("ALLOW_INSECURE_DEFAULTS", "0") != "1":
    if app.secret_key == "mail-viewer-secret-key-change-me":
        raise RuntimeError("SECRET_KEY is the public default. Set a long random SECRET_KEY (run ./setup.sh).")
    if not ACCESS_PASSWORD:
        raise RuntimeError("ACCESS_PASSWORD is empty, which would leave the web app without a login. Set it (run ./setup.sh).")


# Number of reverse proxies in front of this app (Nginx Proxy Manager, Caddy, a Cloudflare Tunnel...).
# X-Forwarded-For is only believable for the entries those proxies added, so the client address is read
# from the RIGHT end of the list. With 0 the header is ignored and the socket address is used.
TRUSTED_PROXY_COUNT = max(0, int(os.getenv("TRUSTED_PROXY_COUNT", "1")))


def _seg(value) -> str:
    """A value made safe to use as ONE path segment of a backend URL (no slashes, no dot-segments, no query)."""
    text = str(value if value is not None else "")
    if text in ("", ".", ".."):
        return "invalid"
    return quote(text, safe="")


def _client_ip() -> str:
    if TRUSTED_PROXY_COUNT:
        parts = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        if len(parts) >= TRUSTED_PROXY_COUNT:
            return parts[-TRUSTED_PROXY_COUNT][:64]
    return request.remote_addr or "unknown"


def _check_viewer_rate_limit(scope: str, window_seconds: int, max_attempts: int) -> bool:
    if max_attempts <= 0:
        return False
    now = time.time()
    if len(_rate_limit_store) > 5000:
        for k in [k for k, v in _rate_limit_store.items() if not v or now - v[-1] > 3600]:
            _rate_limit_store.pop(k, None)
    key = f"{scope}:{_client_ip()}"
    bucket = [t for t in _rate_limit_store[key] if now - t < window_seconds]
    if len(bucket) >= max_attempts:
        _rate_limit_store[key] = bucket
        return True
    bucket.append(now)
    _rate_limit_store[key] = bucket
    return False


def _rate_limited_json(message: str = "Too many requests, please try again shortly"):
    return jsonify({"success": False, "message": message}), 429


def login_required(f):
    """Login-required decorator. A cookie only counts while its server-side session still exists
    and (in multi-account mode) the account is still active."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ACCESS_PASSWORD and not _session_ok():
            session.clear()
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Only admins (single-password mode, an admin mailbox, or the emergency admin) may use this."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if ACCESS_PASSWORD and (not user or user["role"] != "admin"):
            return jsonify({"success": False, "message": "Only an admin can do that"}), 403
        return f(*args, **kwargs)
    return login_required(decorated_function)


SESSION_DAY_CHOICES = (1, 3, 7, 14, 30, 90, 180, 365)


def _session_ttl(user: dict | None) -> int:
    """How long a sign-in lasts without activity: the person's own setting, else SESSION_HOURS."""
    days = (user or {}).get("session_days")
    if isinstance(days, int) and days in SESSION_DAY_CHOICES:
        return days * 86400
    return SESSION_HOURS * 3600


def _session_ok() -> bool:
    if not session.get("authenticated"):
        return False
    sid = session.get("sid", "")
    if not security_store.session_valid(sid):
        return False
    user = current_user()
    if user is None:
        return False
    try:
        if not session.get("stealth"):
            security_store.set_session_ttl(sid, _session_ttl(user))  # follows changes to "Stay signed in"
        security_store.touch_session(sid, _client_ip())
    except OSError:
        pass
    return True

# HTTP session with retries
http_session = requests.Session()
adapter = requests.adapters.HTTPAdapter(max_retries=3)
http_session.mount("http://", adapter)
http_session.mount("https://", adapter)

DATA_DIR = os.getenv("DATA_DIR", "/data")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "168"))
security_store = sec.SecurityStore(DATA_DIR, app.secret_key, SESSION_HOURS)
# Internal calls for the security log, block list and privacy settings use their own HTTP session
# (short timeouts, no retries) so they never slow down or interfere with mail requests.
internal_http = requests.Session()
security_reporter = sec.SecurityReporter(DUCKMAIL_BASE_URL, DUCKMAIL_API_KEY, internal_http)


# ---------------------------------------------------------------- accounts (single / multi-account mode)
# Single mode: ACCESS_PASSWORD opens the web app with full rights (as before).
# Multi mode: people sign in with their own mailbox address + mailbox password (+ their own 2FA). Admin
# mailboxes see everything; other users only their own mailbox and its aliases, with the rights the
# admin gave them. ACCESS_PASSWORD then only works as an emergency admin login, and only when
# ALLOW_EMERGENCY_ADMIN=1 is set in .env (sign in with the email "admin").
ALLOW_EMERGENCY_ADMIN = _env_flag("ALLOW_EMERGENCY_ADMIN", default=False)
ADMIN_PERMISSIONS = {"send": True, "smtp_providers": "all", "own_smtp": True, "aliases": True, "max_aliases": 10000,
                     "external_accounts": True, "change_password": True}
_mode_cache = {"ts": 0.0, "mode": None}
_user_cache: dict = {}
_USER_CACHE_SECONDS = 10


def _svc(method: str, path: str, timeout: float = 10, **kwargs):
    """Call the mail service's admin API with the internal key."""
    return internal_http.request(method, f"{DUCKMAIL_BASE_URL.rstrip('/')}{path}",
                                 headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"}, timeout=timeout, **kwargs)


def auth_mode(force: bool = False) -> str:
    """'single' or 'multi'. The last known answer is also kept on disk, so a web app that starts while
    the mail service is down never falls back to the shared password when personal accounts are on."""
    now = time.time()
    if force or _mode_cache["mode"] is None or now - _mode_cache["ts"] > _USER_CACHE_SECONDS:
        mode = None
        try:
            resp = _svc("GET", "/admin/auth/mode")
            if resp.status_code == 200:
                mode = "multi" if resp.json().get("mode") == "multi" else "single"
        except Exception:
            pass
        if mode is None:
            mode = _mode_cache["mode"] or security_store.read().get("auth_mode", "single")
        elif security_store.read().get("auth_mode", "single") != mode:
            try:
                with security_store.edit() as data:
                    data["auth_mode"] = mode
            except OSError:
                pass
        _mode_cache.update(mode=mode, ts=now)
    return _mode_cache["mode"]


def _load_user(address: str, force: bool = False) -> dict | None:
    now = time.time()
    cached = _user_cache.get(address)
    if cached and not force and now - cached[0] < _USER_CACHE_SECONDS:
        return cached[1]
    profile = None
    try:
        resp = _svc("GET", f"/admin/users/{_seg(address)}")
        if resp.status_code == 200:
            profile = resp.json()
        elif resp.status_code != 404 and cached:
            profile = cached[1]
    except Exception:
        profile = cached[1] if cached else None
    if len(_user_cache) > 2000:
        _user_cache.clear()
    _user_cache[address] = (now, profile)
    return profile


def current_user() -> dict | None:
    """Who is signed in, with their role and rights. None when the session no longer counts."""
    if "bm_user" in g:
        return g.bm_user
    user = None
    if session.get("authenticated"):
        kind = session.get("kind", "single")
        mode = auth_mode()
        stealth = session.get("stealth")
        if stealth and not _impersonator_ok(stealth, mode):
            g.bm_user = None
            return None
        if kind == "user" and mode == "multi":
            profile = _load_user(session.get("user", ""))
            if profile and profile.get("is_active", True):
                user = {"kind": "user", "address": profile["address"], "role": profile.get("role", "user"),
                        "permissions": profile.get("permissions", {}), "addresses": [a.lower() for a in profile.get("addresses", [])],
                        "display_name": profile.get("display_name", ""), "two_factor": profile.get("two_factor", False),
                        "domains": [d.lower() for d in profile.get("domains", [])],
                        "session_days": profile.get("session_days")}
                if stealth:
                    user["stealth"] = True
                    user["impersonator"] = stealth.get("user") or "emergency admin"
        elif kind == "single" and mode == "single":
            user = {"kind": "single", "address": None, "role": "admin", "permissions": ADMIN_PERMISSIONS, "addresses": None}
        elif kind == "emergency" and mode == "multi" and ALLOW_EMERGENCY_ADMIN:
            user = {"kind": "emergency", "address": None, "role": "admin", "permissions": ADMIN_PERMISSIONS, "addresses": None}
    g.bm_user = user
    return user


def _impersonator_ok(stealth: dict, mode: str) -> bool:
    """A stealth view only lasts while the admin who opened it is still an active admin."""
    if mode != "multi":
        return False
    if stealth.get("kind") == "emergency":
        return ALLOW_EMERGENCY_ADMIN
    profile = _load_user(stealth.get("user", ""))
    return bool(profile and profile.get("is_active", True) and profile.get("role") == "admin")


def _may_use_address(address: str) -> bool:
    """Single-password mode: everything. Personal accounts: only your own mailbox and its aliases, admins
    included (an admin opens someone else's mailbox only through stealth sign-in, which is logged)."""
    user = current_user()
    if not user:
        return not ACCESS_PASSWORD
    if user["kind"] == "single":
        return True
    return (address or "").strip().lower() in (user.get("addresses") or [])


def _public_user() -> dict:
    user = current_user() or {"kind": "single", "role": "admin", "address": None, "permissions": ADMIN_PERMISSIONS}
    return {"mode": auth_mode(), "kind": user["kind"], "role": user["role"], "address": user.get("address"),
            "addresses": user.get("addresses"), "permissions": user.get("permissions", {}),
            "display_name": user.get("display_name", ""), "two_factor": user.get("two_factor", False),
            "emergency_admin": ALLOW_EMERGENCY_ADMIN, "stealth": bool(user.get("stealth")),
            "impersonator": user.get("impersonator", "")}
TWO_FACTOR_WINDOW_SECONDS = 300


def _normalize_remote_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("//"):
        return f"https:{url}"
    return url


def _is_public_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    has_public_ip = False
    for _, _, _, _, sockaddr in addr_infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if any([
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        ]):
            return False
        has_public_ip = True
    return has_public_ip


def _is_proxyable_image_url(url: str) -> bool:
    parsed = urlparse(_normalize_remote_url(url))
    return parsed.scheme in {"http", "https"} and _is_public_hostname(parsed.hostname or "")


# bleach strip=True removes disallowed tags but keeps their text,
# so <script>/<title> source would show up as body text.
# These elements' content must never appear in the body: drop them whole before bleach.
# <style> is handled separately: contents pass an allow-list and are re-attached (see _extract_stylesheets).
_RAW_TEXT_ELEMENT_RE = re.compile(
    r"<(script|title)\b[^>]*>.*?</\1\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)
# Unclosed tag: everything after it is raw text of that element; drop it
_UNCLOSED_RAW_TEXT_ELEMENT_RE = re.compile(
    r"<(style|script)\b[^>]*>(?:(?!</\1\s*>).)*$",
    flags=re.IGNORECASE | re.DOTALL,
)
_STYLE_ELEMENT_RE = re.compile(
    r"<style\b[^>]*>(.*?)</style\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)

_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", flags=re.DOTALL)
# url() lets CSS make outbound requests (tracking, fonts): always blocked; the rest are script surfaces
_CSS_FORBIDDEN_RE = re.compile(
    r"url\s*\(|image-set\s*\(|expression\s*\(|javascript\s*:|vbscript\s*:|behavior\s*:|-moz-binding",
    flags=re.IGNORECASE,
)
# Only these conditional rules are allowed; @import / @font-face / @charset pull external resources
_CSS_ALLOWED_AT_RULES = {"media", "supports"}
_CSS_AT_RULE_NAME_RE = re.compile(r"@([a-zA-Z-]+)")
_MAX_STYLESHEET_BYTES = 200 * 1024


def _drop_raw_text_elements(html: str) -> str:
    previous = None
    # Nested or spliced tags need repeated cleaning until nothing matches
    while previous != html:
        previous = html
        html = _RAW_TEXT_ELEMENT_RE.sub("", html)
    return _UNCLOSED_RAW_TEXT_ELEMENT_RE.sub("", html)


def _sanitize_css_declarations(body: str) -> str:
    kept = []
    for declaration in body.split(";"):
        prop, sep, value = declaration.partition(":")
        if not sep:
            continue
        prop = prop.strip().lower()
        value = value.strip()
        if not prop or not value:
            continue
        if prop not in _EMAIL_ALLOWED_CSS_PROPERTIES:
            continue
        if _CSS_FORBIDDEN_RE.search(value) or "<" in value:
            continue
        kept.append(f"{prop}:{value}")
    return ";".join(kept)


def _sanitize_stylesheet(css: str, depth: int = 0) -> str:
    """Rewrite CSS in <style> against an allow-list: keep selectors and @media, drop external links and unknown properties."""
    if depth > 4:
        return ""
    css = _CSS_COMMENT_RE.sub("", css)
    rules = []
    prelude = []
    index = 0
    length = len(css)
    while index < length:
        char = css[index]
        if char == "{":
            level = 1
            cursor = index + 1
            while cursor < length and level:
                if css[cursor] == "{":
                    level += 1
                elif css[cursor] == "}":
                    level -= 1
                cursor += 1
            block = css[index + 1:cursor - 1]
            selector = "".join(prelude).strip()
            prelude = []
            index = cursor
            # A "<" in a selector means someone is assembling </style> to escape rawtext: drop it
            if not selector or "<" in selector:
                continue
            if selector.startswith("@"):
                match = _CSS_AT_RULE_NAME_RE.match(selector)
                if not match or match.group(1).lower() not in _CSS_ALLOWED_AT_RULES:
                    continue
                if _CSS_FORBIDDEN_RE.search(selector):
                    continue
                inner = _sanitize_stylesheet(block, depth + 1)
                if inner:
                    rules.append(f"{selector}{{{inner}}}")
            else:
                if _CSS_FORBIDDEN_RE.search(selector):
                    continue
                declarations = _sanitize_css_declarations(block)
                if declarations:
                    rules.append(f"{selector}{{{declarations}}}")
        elif char == ";":
            # Block-less at-rules (@import/@charset/@namespace) and stray semicolons are dropped
            prelude = []
            index += 1
        else:
            prelude.append(char)
            index += 1
    return "".join(rules)


def _extract_stylesheets(html: str) -> tuple[str, str]:
    """Extract and sanitize all <style> blocks; returns (html without style, cleaned CSS)."""
    collected = []

    def _collect(match):
        collected.append(match.group(1))
        return ""

    html = _STYLE_ELEMENT_RE.sub(_collect, html)
    if not collected:
        return html, ""
    raw = "\n".join(collected)[:_MAX_STYLESHEET_BYTES]
    return html, _sanitize_stylesheet(raw)


def _sanitize_email_html(html: str) -> str:
    html = (html or "").strip()
    if not html:
        return ""
    # Extract stylesheets first: <style> may live in <head>
    html, stylesheet = _extract_stylesheets(html)
    body_match = re.search(r"<body[^>]*>(.*)</body>", html, flags=re.IGNORECASE | re.DOTALL)
    if body_match:
        html = body_match.group(1)
    html = _drop_raw_text_elements(html)
    cleaned = bleach.clean(
        html,
        tags=_EMAIL_ALLOWED_TAGS,
        attributes=_EMAIL_ALLOWED_ATTRIBUTES,
        protocols={"http", "https", "mailto", "cid", "data"},
        strip=True,
        css_sanitizer=_EMAIL_CSS_SANITIZER,
    ).strip()
    if stylesheet:
        cleaned = f"<style>{stylesheet}</style>{cleaned}"
    return cleaned


def _prepare_html_for_render(html: str) -> str:
    return _prepare_html_with_report(html)[0]


def _prepare_html_with_report(html: str) -> tuple[str, dict]:
    """Sanitize, then hold back remote images, mark trackers and check links (see email_privacy.py)."""
    cleaned = _sanitize_email_html(html)

    def _proxy(src):
        if not _is_proxyable_image_url(src):
            return ""  # private/unresolvable addresses are never fetched
        return url_for("image_proxy", url=src)

    privacy = _privacy_settings()
    return email_privacy.protect_html(cleaned, proxy_url=_proxy, strip_params=privacy.get("strip_link_tracking", True))


_privacy_cache = {"ts": 0.0, "value": {}}


def _privacy_settings() -> dict:
    """Privacy options from the Security page (cached for 30 s)."""
    now = time.time()
    if now - _privacy_cache["ts"] > 30:
        value = _privacy_cache["value"]
        if DUCKMAIL_API_KEY:
            try:
                resp = internal_http.get(f"{DUCKMAIL_BASE_URL.rstrip('/')}/admin/security/settings",
                                        headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"}, timeout=3)
                if resp.status_code == 200:
                    value = resp.json().get("privacy", {}) or {}
            except Exception:
                pass
        _privacy_cache.update(ts=now, value=value)
    return _privacy_cache["value"]


def _rewrite_imap_html(html: str) -> str:
    rewritten = html.replace("'/api/", "'/imap/api/").replace('"/api/', '"/imap/api/')
    rewritten = rewritten.replace("fetch(url, opts)", "fetch(url, opts)")
    return rewritten


def _proxy_imap_response(subpath: str = ""):
    base = IMAP_MAIL_BASE_URL.rstrip("/")
    clean = subpath.lstrip("/")
    if "://" in clean or "\\" in clean or any(seg == ".." for seg in clean.split("/")):
        return jsonify({"success": False, "message": "Not found"}), 404
    target = f"{base}/{clean}"
    if urlparse(target).netloc != urlparse(base).netloc:
        return jsonify({"success": False, "message": "Not found"}), 404
    headers = {}
    if BRIDGE_TOKEN:
        headers["X-Bridge-Token"] = BRIDGE_TOKEN  # the bridge refuses requests that did not come through this login-protected app
    # Each person only sees the external accounts they added (admins share one space).
    user = current_user()
    headers["X-Bridge-User"] = user["address"] if user and user.get("kind") == "user" and user["role"] != "admin" else "__admin__"
    for key, value in request.headers.items():
        key_lower = key.lower()
        if key_lower in {"host", "content-length", "cookie"}:
            continue
        if key_lower in {"accept", "content-type", "x-requested-with"}:
            headers[key] = value
    body = None if request.method in {"GET", "HEAD"} else request.get_data()
    resp = http_session.request(
        method=request.method,
        url=target,
        params=request.args,
        data=body,
        headers=headers,
        timeout=60,
        allow_redirects=False,
    )
    content_type = resp.headers.get("Content-Type", "")
    payload = resp.content
    if "text/html" in content_type:
        payload = _rewrite_imap_html(resp.text).encode(resp.encoding or "utf-8")
    proxied = Response(payload, status=resp.status_code, content_type=content_type or None)
    for header in ["Content-Disposition", "Cache-Control", "Location"]:
        if header in resp.headers:
            value = resp.headers[header]
            if header == "Location" and value.startswith("/"):
                value = "/imap" + value
            proxied.headers[header] = value
    return proxied


def _rewrite_html_images(html: str) -> str:
    if not html or "<img" not in html.lower():
        return html

    def _replace(match):
        prefix, src, suffix = match.groups()
        normalized = _normalize_remote_url(src)
        if not _is_proxyable_image_url(normalized):
            return match.group(0)
        proxied = url_for("image_proxy", url=normalized)
        return f"{prefix}{proxied}{suffix}"

    return re.sub(r'(<img\b[^>]*?\bsrc=["\'])([^"\']+)(["\'])', _replace, html, flags=re.IGNORECASE)


def _get_mail_token(email: str, password: str = "") -> tuple:
    """Get a mail-service token; returns (token, error_response)"""
    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        # The web UI sits behind ACCESS_PASSWORD and holds the admin API key, so it asks the mail
        # service for a token for the mailbox (or the mailbox behind an alias) directly.
        if DUCKMAIL_API_KEY:
            admin_resp = http_session.post(
                f"{base_url}/admin/token",
                json={"address": email},
                headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"},
                timeout=30,
            )
            if admin_resp.status_code == 200:
                return admin_resp.json().get("token"), None
        token_resp = http_session.post(
            f"{base_url}/token",
            json={"address": email, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        if token_resp.status_code != 200:
            return None, ("Sign-in failed", token_resp.status_code)
        token = token_resp.json().get("token")
        return token, None
    except Exception as e:
        app.logger.error(f"Could not get mail token: {e}", exc_info=True)
        return None, ("Could not reach the mail service", 500)


def _extract_api_error(resp, fallback: str = "Operation failed") -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            detail = data.get("detail") or data.get("message") or data.get("hydra:description") or fallback
            return detail if isinstance(detail, str) else fallback
    except Exception:
        pass
    return fallback


# Words that say "this email carries a one-time code". Without one of them nearby we don't
# guess, so order numbers, prices and zip codes in ordinary mail are left alone.
_CODE_KEYWORDS = re.compile(
    r"(verification|verify|confirmation|confirm|security|login|log-in|log in|sign-in|sign in|signin|"
    r"access|authentication|auth|one[- ]time|single[- ]use|otp|2fa|two[- ]factor|mfa|multi[- ]factor|"
    r"passcode|pass code|pin|code|token|c[oó]digo|kod|code de)\b",
    re.I,
)
# Digit codes of 4-8 (optionally split as "123 456" / "123-456"), or 4-8 letter+digit codes like "K7Q2PX".
_CODE_CANDIDATE = re.compile(
    r"(?<![\w$€£¥#+/.:-])"
    r"(\d{3,4}[ -]\d{3,4}|\d{4,8}|(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{4,8})"
    r"(?![\w%/:]|[.,]\d)"
)
_NOT_A_CODE_BEFORE = re.compile(
    r"\b(order|invoice|ticket|case|account|acct|ref|reference|tracking|phone|tel|call|fax|zip|"
    r"suite|ste|apt|unit|box|no\.?|number|id)\W{0,3}$",
    re.I,
)


def _html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", html or "")
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    return unescape(html)


def _extract_code(*parts: str) -> str | None:
    """Find a one-time / 2FA / verification code (4-8 characters) in the given text.

    Only returns something when the text reads like a code email (a keyword such as
    "verification code", "OTP", "2FA", "passcode" or "PIN") and the code sits close to it.
    Years, prices, phone numbers, times, dates and order numbers are skipped.
    """
    text = re.sub(r"\s+", " ", " ".join(p for p in parts if p))[:20000]
    keywords = [m.start() for m in _CODE_KEYWORDS.finditer(text)]
    if not keywords:
        return None
    best, best_score = None, None
    for m in _CODE_CANDIDATE.finditer(text):
        raw = m.group(1)
        code = re.sub(r"[ -]", "", raw)
        if not 4 <= len(code) <= 8:
            continue
        if code.isdigit():
            if len(code) == 4 and 1900 <= int(code) <= 2099:
                continue  # a year
            if len(set(code)) == 1 and len(code) < 6:
                continue  # 0000 / 1111 placeholders
        elif code.isalpha() or code.lower() in {"utf8", "mp3", "mp4", "h264"}:
            continue
        else:
            # Letter+digit codes must be written as one uppercase token (not "COVID19"-ish words).
            if sum(c.isdigit() for c in code) < 2:
                continue
        before = text[max(0, m.start() - 20):m.start()]
        if _NOT_A_CODE_BEFORE.search(before) and not re.search(r"(code|pin|otp|passcode)\W{0,3}$", before, re.I):
            continue
        if re.search(r"\b[A-Z]{2},? $", before) and len(code) == 5 and code.isdigit():
            continue  # US state + zip code in a footer
        if re.search(r"\d[ -]$", before):
            continue  # part of a phone number / longer digit run
        # Distance to the nearest keyword; a code after its keyword ("Your code is 123456") wins ties.
        dist = min(
            (m.start() - k) if k <= m.start() else (k - m.end()) * 1.5 for k in keywords
        )
        if dist > 160:
            continue
        score = dist - (20 if code.isdigit() else 0) - (10 if len(code) == 6 else 0)
        if best_score is None or score < best_score:
            best, best_score = code, score
    return best


def _format_attachments(detail: dict) -> list:
    attachments = detail.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []
    if not attachments and detail.get("hasAttachments"):
        attachments = [{"index": 0, "filename": "attachment", "size": 0}]
    normalized = []
    for index, item in enumerate(attachments):
        if isinstance(item, dict):
            normalized.append({
                "index": item.get("index", index),
                "id": item.get("id") or item.get("attachment_id") or item.get("contentId") or "",
                "filename": item.get("filename") or item.get("name") or f"attachment_{index}",
                "size": item.get("size") or 0,
                "contentType": item.get("contentType") or item.get("content_type") or "",
            })
        else:
            normalized.append({"index": index, "id": "", "filename": str(item), "size": 0, "contentType": ""})
    # Attach the mail service's scan (risky types, macros, files that contact the internet when opened).
    scan = detail.get("scan") if isinstance(detail.get("scan"), dict) else {}
    by_id = {s.get("id"): s for s in scan.get("attachments", []) if isinstance(s, dict) and s.get("id")}
    for item in normalized:
        found = by_id.get(item["id"])
        if found:
            item["risk"] = found.get("risk", "info")
            item["reasons"] = [r for r in found.get("reasons", []) if isinstance(r, str)][:6]
            item["phonesHome"] = bool(found.get("phones_home"))
    return normalized


def _find_attachment_download_url(base_url: str, message_id: str, attachment_id: str, headers: dict):
    quoted_id = quote(attachment_id, safe="")
    candidate_paths = [
        f"/messages/{_seg(message_id)}/attachments/{quoted_id}",
        f"/messages/{_seg(message_id)}/attachment/{quoted_id}",
        f"/messages/{_seg(message_id)}/attachments?index={quoted_id}",
    ]

    for path in candidate_paths:
        url = f"{base_url}{path}"
        try:
            resp = http_session.get(url, headers=headers, stream=True, timeout=30)
        except Exception:
            continue
        if resp.status_code == 200:
            return url, resp
        resp.close()
    return None, None


def _find_message_source_url(base_url: str, message_id: str, headers: dict):
    """Probe the upstream raw-message (.eml) endpoint; paths differ between implementations."""
    quoted_id = quote(message_id, safe="")
    candidate_paths = [
        f"/messages/{quoted_id}/download",
        f"/messages/{quoted_id}/source",
        f"/sources/{quoted_id}",
    ]

    for path in candidate_paths:
        url = f"{base_url}{path}"
        try:
            resp = http_session.get(url, headers=headers, stream=True, timeout=30)
        except Exception:
            continue
        if resp.status_code == 200:
            return url, resp
        resp.close()
    return None, None


@app.errorhandler(413)
def _payload_too_large(_e):
    """Return JSON when the request body exceeds MAX_CONTENT_LENGTH so the frontend can always parse JSON."""
    return jsonify({"success": False, "message": "Request too large. Please reduce the attachment size"}), 413


# ---------------------------------------------------------------- branding (custom logos)
LOGO_MAX_BYTES = int(os.getenv("LOGO_MAX_BYTES", str(512 * 1024)))
_LOGO_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif", "image/svg+xml": "svg"}
# Four places a logo can be shown: the signed-in header and the login page, each for light and dark themes.
LOGO_SLOTS = ("app_light", "app_dark", "login_light", "login_dark")


def _slot_paths(slot: str):
    return os.path.join(DATA_DIR, f"logo_{slot}.bin"), os.path.join(DATA_DIR, f"logo_{slot}.type")


def _read_state(path: str, tpath: str):
    try:
        st = os.stat(path)
        with open(tpath) as fh:
            mime = fh.read().strip()
        if mime in _LOGO_TYPES:
            return mime, int(st.st_mtime)
    except OSError:
        pass
    return None, 0


def _slot_files(slot: str):
    """Paths for a slot. A logo uploaded by an earlier version (logo.bin) counts as the app/light logo."""
    path, tpath = _slot_paths(slot)
    if slot == "app_light" and not os.path.exists(path):
        legacy = (os.path.join(DATA_DIR, "logo.bin"), os.path.join(DATA_DIR, "logo.type"))
        if os.path.exists(legacy[0]):
            return legacy
    return path, tpath


def _slot_state(slot: str):
    return _read_state(*_slot_files(slot))


def _resolve_logo(context: str, mode: str):
    """Best logo for (login|app, light|dark): the exact slot, then the same theme mode in the other place,
    then the other theme mode. Returns a slot name or None."""
    other_ctx = "login" if context == "app" else "app"
    other_mode = "dark" if mode == "light" else "light"
    for c, m in ((context, mode), (other_ctx, mode), (context, other_mode), (other_ctx, other_mode)):
        slot = f"{c}_{m}"
        if _slot_state(slot)[0]:
            return slot
    return None


def _brand_urls(context: str):
    out = {}
    for mode in ("light", "dark"):
        slot = _resolve_logo(context, mode)
        out[mode] = f"/branding/logo/{slot}?v={_slot_state(slot)[1]}" if slot else None
    return out


@app.context_processor
def _inject_branding():
    app_urls, login_urls = _brand_urls("app"), _brand_urls("login")
    return {
        "brand_app": app_urls, "brand_login": login_urls,
        "has_logo": bool(app_urls["light"] or app_urls["dark"]),
        "has_login_logo": bool(login_urls["light"] or login_urls["dark"]),
    }


@app.route("/branding/logo/<slot>")
def branding_logo(slot):
    """Public on purpose: the login page shows logos before sign-in."""
    if slot not in LOGO_SLOTS:
        return ("", 404)
    path, tpath = _slot_files(slot)
    mime, _v = _read_state(path, tpath)
    if not mime:
        return ("", 404)
    with open(path, "rb") as fh:
        data = fh.read()
    resp = Response(data, mimetype=mime)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/branding/logo")
def branding_logo_legacy():
    return branding_logo("app_light")


@app.route("/api/branding/logo", methods=["POST"])
@admin_required
def branding_logo_upload_legacy():
    return branding_logo_upload("app_light")


@app.route("/api/branding/logo", methods=["DELETE"])
@admin_required
def branding_logo_delete_legacy():
    return branding_logo_delete("app_light")


@app.route("/api/branding", methods=["GET"])
@login_required
def branding_status():
    return jsonify({"success": True, "slots": {slot: bool(_slot_state(slot)[0]) for slot in LOGO_SLOTS}})


def _sniff_logo_type(data: bytes) -> str | None:
    """Work out the image type from the bytes themselves; the browser-supplied type is never trusted."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    head = data[:2048].lstrip().lower()
    if b"<svg" in data[:4096].lower() and (head.startswith(b"<?xml") or head.startswith(b"<svg") or head.startswith(b"<!--") or head.startswith(b"<!doctype")):
        return "image/svg+xml"
    return None


_SVG_FORBIDDEN = re.compile(rb"<\s*script|<\s*foreignobject|<\s*iframe|<\s*embed|<\s*object|\son[a-z]+\s*=|javascript:|data:text/html|<\s*!entity", re.I)


@app.route("/api/branding/logo/<slot>", methods=["POST"])
@admin_required
def branding_logo_upload(slot):
    if slot not in LOGO_SLOTS:
        return jsonify({"success": False, "message": "Unknown logo slot."}), 404
    f = request.files.get("logo")
    if not f:
        return jsonify({"success": False, "message": "Choose an image file first."}), 400
    data = f.read(LOGO_MAX_BYTES + 1)
    if len(data) > LOGO_MAX_BYTES:
        return jsonify({"success": False, "message": f"Logo is too large (max {LOGO_MAX_BYTES // 1024} KB)."}), 413
    mime = _sniff_logo_type(data)
    if not mime:
        return jsonify({"success": False, "message": "Use a PNG, JPG, WebP, GIF or SVG image."}), 400
    if mime == "image/svg+xml" and _SVG_FORBIDDEN.search(data):
        return jsonify({"success": False, "message": "That SVG contains scripts or embedded content. Export a plain SVG or use PNG."}), 400
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        path, tpath = _slot_paths(slot)
        with open(path, "wb") as fh:
            fh.write(data)
        with open(tpath, "w") as fh:
            fh.write(mime)
        if slot == "app_light":  # the new upload replaces any logo from an earlier version
            for legacy in ("logo.bin", "logo.type"):
                try:
                    os.remove(os.path.join(DATA_DIR, legacy))
                except OSError:
                    pass
    except OSError:
        return jsonify({"success": False, "message": "Could not save the logo (is the data volume writable?)."}), 500
    return jsonify({"success": True, "version": _slot_state(slot)[1]})


@app.route("/api/branding/logo/<slot>", methods=["DELETE"])
@admin_required
def branding_logo_delete(slot):
    if slot not in LOGO_SLOTS:
        return jsonify({"success": False, "message": "Unknown logo slot."}), 404
    paths = list(_slot_paths(slot))
    if slot == "app_light":
        paths += [os.path.join(DATA_DIR, "logo.bin"), os.path.join(DATA_DIR, "logo.type")]
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass
    return jsonify({"success": True})


def _user_agent_label() -> str:
    ua = request.headers.get("User-Agent", "")[:300]
    browser = next((name for key, name in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                                           ("Safari/", "Safari")) if key in ua), "Browser")
    system = next((name for key, name in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                          ("Windows", "Windows"), ("Mac OS", "macOS"), ("Linux", "Linux")) if key in ua), "")
    return f"{browser} on {system}" if system else browser


def _start_session(method: str, kind: str = "single", user: str = ""):
    session.clear()  # fresh session on login
    session["authenticated"] = True
    session["kind"] = kind
    if user:
        session["user"] = user
    profile = _load_user(user, force=True) if user and kind == "user" else None
    session["sid"] = security_store.create_session(_client_ip(), _user_agent_label(), method, user=user or ("emergency admin" if kind == "emergency" else ""),
                                                   ttl=_session_ttl(profile))
    session.permanent = True
    security_reporter.report("login_ok", ip=_client_ip(), user=user, detail=_user_agent_label(), aggregate=False)
    if user:
        try:
            _svc("POST", f"/admin/users/{_seg(user)}/signed-in")
        except Exception:
            pass


def _login_template(error=None, status=200, step=None, email=""):
    return render_template("login.html", error=error, step=step, mode=auth_mode(force=True), email=email), status


@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Sign in. Single mode: the shared password. Multi mode: email + mailbox password.
    With two-factor on, a correct password leads to the code step (/login/verify)."""
    if not ACCESS_PASSWORD:
        app.logger.warning("ACCESS_PASSWORD is empty; viewer login is disabled")
        return redirect(url_for("index"))
    if request.method != "POST":
        return _login_template()

    if _check_viewer_rate_limit("login", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        security_reporter.report("rate_limited", ip=_client_ip(), detail="password step")
        return _login_template("Too many login attempts, please try again later", 429)
    password = request.form.get("password", "")
    mode = auth_mode(force=True)
    email = request.form.get("email", "").strip().lower()[:320]

    if mode == "multi" and email != "admin":
        try:
            resp = _svc("POST", "/admin/users/login", json={"address": email, "password": password})
        except Exception:
            return _login_template("The mail service is not reachable, please try again", 503, email=email)
        if resp.status_code != 200:
            security_reporter.report("login_failed", ip=_client_ip(), user=email, detail=_user_agent_label())
            message = "This account is disabled" if resp.status_code == 403 else "Wrong email or password"
            return _login_template(message, 401, email=email)
        profile = resp.json()
        if profile.get("two_factor"):
            session.clear()
            session["pw_ok_at"] = time.time()
            session["pending_user"] = profile["address"]
            return _login_template(step="code")
        _start_session("password", kind="user", user=profile["address"])
        return redirect(url_for("index"))

    # Single mode, or the emergency admin in multi mode (email "admin" + ACCESS_PASSWORD).
    if mode == "multi" and not ALLOW_EMERGENCY_ADMIN:
        security_reporter.report("login_failed", ip=_client_ip(), user="admin", detail="emergency admin is turned off")
        return _login_template("Wrong email or password", 401, email=email)
    # Compare as bytes: comparing str containing non-ASCII characters raises TypeError.
    if hmac.compare_digest(password.encode("utf-8"), ACCESS_PASSWORD.encode("utf-8")):
        kind = "emergency" if mode == "multi" else "single"
        if security_store.totp_enabled():
            session.clear()
            session["pw_ok_at"] = time.time()
            session["pending_kind"] = kind
            return _login_template(step="code")
        _start_session("password" if kind == "single" else "emergency password", kind=kind)
        return redirect(url_for("index"))
    app.logger.warning("Failed login from %s", _client_ip())
    security_reporter.report("login_failed", ip=_client_ip(), user="admin" if mode == "multi" else "", detail=_user_agent_label())
    return _login_template("Wrong password" if mode == "single" else "Wrong email or password", 401, email=email)


@app.route("/login/verify", methods=["POST"])
def login_verify():
    """Second step: the 6-digit code from the authenticator app, or a recovery code."""
    if not ACCESS_PASSWORD:
        return redirect(url_for("index"))
    started = session.get("pw_ok_at")
    if not started or time.time() - float(started) > TWO_FACTOR_WINDOW_SECONDS:
        session.clear()
        return _login_template("That took too long. Enter your password again.", 401)
    if _check_viewer_rate_limit("login2fa", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        session.clear()
        security_reporter.report("rate_limited", ip=_client_ip(), detail="two-factor step")
        return _login_template("Too many attempts, please try again later", 429)
    code = request.form.get("code", "")
    pending_user = session.get("pending_user")
    if pending_user:
        try:
            resp = _svc("POST", f"/admin/users/{_seg(pending_user)}/2fa/verify", json={"code": code})
            method = resp.json().get("method") if resp.status_code == 200 else None
        except Exception:
            method = None
        if not method:
            security_reporter.report("login_2fa_failed", ip=_client_ip(), user=pending_user, detail=_user_agent_label())
            return _login_template("That code is not right. Use the current code from your app.", 401, step="code")
        _start_session("password + " + ("authenticator app" if method == "totp" else "recovery code"), kind="user", user=pending_user)
    else:
        kind = session.get("pending_kind", "single")
        method = security_store.verify_second_factor(code)
        if not method:
            security_reporter.report("login_2fa_failed", ip=_client_ip(), detail=_user_agent_label())
            return _login_template("That code is not right. Use the current code from your app.", 401, step="code")
        _start_session("password + " + ("authenticator app" if method == "totp" else "recovery code"), kind=kind)
    if method == "recovery":
        security_reporter.report("recovery_code_used", ip=_client_ip(), user=pending_user or "", aggregate=False)
    return redirect(url_for("index"))


# ---- Public sign-up with an invite code ----

@app.route("/signup", methods=["GET"])
def signup_page():
    """Public sign-up page. Invite code needed unless the admin opened sign-up (Setup > Users > Invites)."""
    code = (request.args.get("code") or "")[:32]
    domains = []
    try:
        resp = _svc("GET", "/domains", timeout=5)
        if resp.status_code == 200:
            domains = [d.get("domain") for d in resp.json().get("hydra:member", []) if d.get("domain")]
    except Exception:
        app.logger.warning("Could not load domains for the signup page", exc_info=True)
    mode = "invite"
    try:
        resp = _svc("GET", "/signup/mode", timeout=5)
        if resp.status_code == 200:
            mode = resp.json().get("mode", "invite")
    except Exception:
        app.logger.warning("Could not load signup mode; defaulting to invite-only", exc_info=True)
    if mode not in ("invite", "open", "closed"):
        mode = "invite"
    return render_template("signup.html", code=code, domains=domains, mode=mode)


@app.route("/api/signup", methods=["POST"])
def api_signup():
    """Public sign-up API: forwards to mail-service POST /signup (no API key; the invite code is the credential)."""
    if _check_viewer_rate_limit("signup", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        return _rate_limited_json("Too many sign-up attempts, please try again later")
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 415
    body = request.get_json(silent=True) or {}
    payload = {
        "code": str(body.get("code") or "")[:64],
        "address": str(body.get("address") or "")[:320].strip().lower(),
        "password": str(body.get("password") or "")[:1024],
    }
    try:
        resp = http_session.request(
            "POST", f"{DUCKMAIL_BASE_URL.rstrip('/')}/signup", json=payload, timeout=30
        )
    except Exception:
        app.logger.error("Signup proxy failed", exc_info=True)
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 400:
        detail = data.get("detail") if isinstance(data, dict) else None
        return jsonify({"success": False, "message": detail or "Sign-up failed"}), resp.status_code
    return jsonify({"success": True, "address": data.get("address")}), 201


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Only POST signs out, so another website cannot log you out with a link or an image.
    if request.method == "POST":
        sid = session.get("sid", "")
        if sid:
            security_store.end_session(sid)
            security_reporter.report("logout", ip=_client_ip(), user=session.get("user", ""), detail=_user_agent_label(), aggregate=False)
        session.clear()
        return redirect(url_for("login_page"))
    return redirect(url_for("index"))


@app.before_request
def _refuse_blocked_addresses():
    """Addresses on the block list (Setup > Security) get nothing, not even the login page."""
    if request.endpoint == "static":
        return None
    ip = _client_ip()
    if ip and security_reporter.blocked(ip):
        security_reporter.report("blocked", ip=ip)
        return Response("Access denied.", status=403, mimetype="text/plain")
    return None


_MAILBOX_PATHS = ("/api/inbox/", "/api/trash/", "/api/sent/")


@app.before_request
def _only_your_own_mailboxes():
    """Multi-account mode: a user may only open, search, change or send from their own mailbox and its
    aliases. Checked here once for every mail request, so no single endpoint can forget it."""
    path = request.path
    if not (path.startswith(_MAILBOX_PATHS) or path == "/api/send"):
        return None
    user = current_user()
    if not user or user["kind"] == "single":
        return None  # not signed in is handled by login_required; the single shared password opens everything
    if path == "/api/send":
        data = request.get_json(silent=True) or {}
        address = data.get("from_email", "") if isinstance(data, dict) else ""
        if not user["permissions"].get("send"):
            return jsonify({"success": False, "message": "Your admin has not allowed sending mail"}), 403
    elif request.method == "GET":
        address = request.args.get("email", "")
    else:
        data = request.get_json(silent=True) or {}
        address = data.get("email", "") if isinstance(data, dict) else ""
    if not isinstance(address, str) or not _may_use_address(address):
        return jsonify({"success": False, "message": "That is not one of your addresses", "messages": []}), 403
    return None


# A stealth view is read-only: the admin can look, but nothing changes that the person could notice
# (no sending, no deleting, nothing marked read, no password / two-factor / key changes).
_STEALTH_READ_POSTS = {"/api/inbox/query", "/api/inbox/detail", "/api/inbox/search", "/api/inbox/tabs", "/api/trash/query",
                       "/api/sent/query", "/api/sent/detail", "/api/stealth/end"}


@app.before_request
def _stealth_is_read_only():
    if not session.get("stealth"):
        return None
    path = request.path
    if path.startswith("/imap"):
        return jsonify({"success": False, "message": "External accounts are not shown in a stealth view"}), 403
    if request.method in ("GET", "HEAD") or path in _STEALTH_READ_POSTS or not path.startswith("/api/"):
        return None
    return jsonify({"success": False, "message": "Stealth view is read-only. Return to your own account to make changes."}), 403


# The page, the email frames and every script come from this server only. Remote pictures in
# emails can only arrive through /api/image-proxy, so nothing in a message can contact another
# server directly. 'unsafe-inline' is still needed because the page uses inline handlers.
_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "media-src 'self'",
    "frame-src 'self'",
    "child-src 'self'",
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
])


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")  # the external-accounts page is embedded from this same site
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=15552000")
    if request.path.startswith("/api/") or request.path in ("/", "/login", "/login/verify"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
@login_required
def index():
    return render_template("index.html", bm_user=_public_user())


@app.route("/imap")
@login_required
def imap_root():
    return redirect("/imap/")


@app.route("/imap/", defaults={"subpath": ""}, methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
@app.route("/imap/<path:subpath>", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
@login_required
def imap_proxy(subpath: str):
    user = current_user()
    if user and not user["permissions"].get("external_accounts"):
        return jsonify({"success": False, "message": "Your admin has not allowed external accounts"}), 403
    return _proxy_imap_response(subpath)


@app.route("/api/image-proxy")
@login_required
def image_proxy():
    """Proxy remote images server-side so client network limits don't break email images."""
    source_url = _normalize_remote_url(request.args.get("url", ""))
    if not _is_proxyable_image_url(source_url):
        return jsonify({"success": False, "message": "Invalid image address"}), 400

    headers = {"User-Agent": "Mozilla/5.0 mail-viewer-image-proxy", "Accept": "image/*,*/*;q=0.8"}
    current = source_url
    resp = None
    try:
        for _hop in range(4):
            resp = http_session.get(current, timeout=30, stream=True, allow_redirects=False, headers=headers)
            if resp.status_code in (301, 302, 303, 307, 308):
                target = _normalize_remote_url(urljoin(current, resp.headers.get("Location", "")))
                resp.close()
                resp = None
                if not _is_proxyable_image_url(target):  # every hop must still be a public address
                    return jsonify({"success": False, "message": "Image failed to load"}), 502
                current = target
                continue
            break
    except requests.RequestException as e:
        app.logger.error(f"Image proxy request failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Image failed to load"}), 502

    if resp is None or not resp.ok:
        if resp is not None:
            resp.close()
        return jsonify({"success": False, "message": "Image failed to load"}), 502

    content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if not content_type.startswith("image/"):
        resp.close()
        return jsonify({"success": False, "message": "The remote resource is not an image"}), 415

    content_length = resp.headers.get("Content-Length")
    if content_length and int(content_length) > MAX_IMAGE_PROXY_BYTES:
        resp.close()
        return jsonify({"success": False, "message": "Image too large"}), 413

    chunks = []
    total = 0
    try:
        for chunk in resp.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_IMAGE_PROXY_BYTES:
                return jsonify({"success": False, "message": "Image too large"}), 413
            chunks.append(chunk)
    finally:
        resp.close()

    proxied_resp = Response(b"".join(chunks), mimetype=content_type)
    proxied_resp.headers["Cache-Control"] = "public, max-age=3600"
    return proxied_resp


@app.route("/api/inbox/query", methods=["POST"])
@login_required
def inbox_query():
    """Generic inbox query (auto-creates the mailbox when enabled)"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    offset = int(data.get("offset", 0))
    limit = int(data.get("limit", 30))
    tab = str(data.get("tab") or "")[:40]

    if not email:
        return jsonify({"success": False, "message": "Enter an email address", "messages": []})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        # Try to get a token for this mailbox / alias
        token, _err = _get_mail_token(email, password)

        # Not a mailbox or alias: auto-create (catch-all style) depending on configuration
        if not token:
            if not AUTO_CREATE_ACCOUNTS or (current_user() or {}).get("role") != "admin":
                return jsonify({"success": False, "message": "No mailbox or alias with that address. Create one under Setup.", "messages": []})
            if _check_viewer_rate_limit("auto_create_account", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
                return _rate_limited_json()
            if not DUCKMAIL_API_KEY:
                return jsonify({"success": False, "message": "Mailbox not found and no API key configured, cannot auto-create", "messages": []})

            create_headers = {
                "Authorization": f"Bearer {DUCKMAIL_API_KEY}",
                "Content-Type": "application/json",
            }
            create_resp = http_session.post(
                f"{base_url}/accounts",
                json={"address": email, "password": password or secrets.token_urlsafe(24)},
                headers=create_headers,
                timeout=30
            )

            if create_resp.status_code not in [200, 201]:
                error_msg = "Could not create the mailbox"
                try:
                    error_data = create_resp.json()
                    if "violations" in error_data:
                        error_msg = error_data["violations"][0].get("message", error_msg)
                    elif "hydra:description" in error_data:
                        error_msg = error_data["hydra:description"]
                except Exception:
                    pass
                return jsonify({"success": False, "message": error_msg, "messages": []})

            # Sign in again after creation
            token, _err = _get_mail_token(email, password)
            if not token:
                return jsonify({"success": False, "message": "Sign-in failed", "messages": []})

        # Fetch the message list (paginated)
        mail_resp = http_session.get(
            f"{base_url}/messages",
            params={"offset": offset, "limit": limit, **({"tab": tab} if tab else {})},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )

        if mail_resp.status_code != 200:
            return jsonify({"success": False, "message": "Could not load messages", "messages": []})

        resp_data = mail_resp.json()
        messages = resp_data.get("hydra:member", []) if isinstance(resp_data, dict) else resp_data
        total = resp_data.get("hydra:totalItems", len(messages)) if isinstance(resp_data, dict) else len(messages)

        # Extract a verification code for each message
        for msg in messages:
            msg["extracted_code"] = _extract_code(msg.get("subject", ""), msg.get("intro", ""))

        return jsonify({
            "success": True,
            "messages": messages,
            "total": total,
            "offset": offset,
            "limit": limit,
        })

    except Exception as e:
        app.logger.error(f"Inbox query failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again", "messages": []})


# ---- Domain management API (proxied to mail-service /admin/domains) ----

@app.route("/api/domains", methods=["GET"])
@login_required
def list_domains():
    """List domains"""
    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        resp = http_session.get(
            f"{base_url}/domains",
            timeout=30,
        )
        if resp.status_code != 200:
            return jsonify({"success": False, "message": f"Could not load domains: {resp.status_code}"}), resp.status_code
        payload = resp.json()
        domains = payload.get("hydra:member", []) if isinstance(payload, dict) else []
        user = current_user()
        if user and user["role"] != "admin":
            mine = {a.split("@", 1)[1] for a in user.get("addresses") or [] if "@" in a} | set(user.get("domains") or [])
            domains = [d for d in domains if d.get("domain") in mine]
        normalized = [
            {
                "domain": item.get("domain", ""),
                "is_active": item.get("isActive", True),
            }
            for item in domains
        ]
        return jsonify({"success": True, "domains": normalized})
    except Exception as e:
        app.logger.error(f"Could not list domains: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Could not load domains"}), 502


@app.route("/api/domains", methods=["POST"])
@admin_required
def add_domain():
    """Add a new domain"""
    data = request.json or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"success": False, "message": "Domain is required"})
    if _check_viewer_rate_limit("domain_admin", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    if not DUCKMAIL_API_KEY:
        return jsonify({"success": False, "message": "No API key configured, cannot manage domains"}), 503

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        resp = http_session.post(
            f"{base_url}/admin/domains",
            json={"domain": domain},
            headers={
                "Authorization": f"Bearer {DUCKMAIL_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        if resp.status_code in (200, 201):
            return jsonify({"success": True, **resp.json()})
        else:
            detail = resp.json().get("detail", "Could not add") if resp.headers.get("content-type", "").startswith("application/json") else "Could not add"
            return jsonify({"success": False, "message": detail}), resp.status_code
    except Exception as e:
        app.logger.error(f"Could not add domain: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Could not add domain"}), 502


@app.route("/api/domains/<domain>", methods=["DELETE"])
@admin_required
def delete_domain(domain):
    """Delete (deactivate) a domain"""
    if _check_viewer_rate_limit("domain_admin", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    if not DUCKMAIL_API_KEY:
        return jsonify({"success": False, "message": "No API key configured, cannot manage domains"}), 503

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        resp = http_session.delete(
            f"{base_url}/admin/domains/{_seg(domain)}",
            headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"},
            timeout=30,
        )
        if resp.status_code == 200:
            return jsonify({"success": True, **resp.json()})
        else:
            detail = resp.json().get("detail", "Could not delete") if resp.headers.get("content-type", "").startswith("application/json") else "Could not delete"
            return jsonify({"success": False, "message": detail}), resp.status_code
    except Exception as e:
        app.logger.error(f"Could not delete domain: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Could not delete domain"}), 502


@app.route("/api/inbox/detail", methods=["POST"])
@login_required
def inbox_detail():
    """Generic inbox message detail"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    message_id = data.get("message_id", "").strip()

    if not email or not message_id:
        return jsonify({"success": False, "message": "Missing required parameters"})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0]})

        detail_resp = http_session.get(
            f"{base_url}/messages/{_seg(message_id)}",
            headers={"Authorization": f"Bearer {token}"},
            params={"peek": 1} if session.get("stealth") else None,
            timeout=30
        )

        if detail_resp.status_code != 200:
            return jsonify({"success": False, "message": "Could not load message detail"})

        detail = detail_resp.json()
        if isinstance(detail, dict):
            # Search the raw body before sanitising: plain part first, then the HTML's visible text
            raw_html = detail.get("html", "")
            detail["html"], detail["privacy"] = _prepare_html_with_report(detail.get("html", ""))
            detail["attachments"] = _format_attachments(detail)
            # The detail has the full body, so the code search covers more than the list's subject + intro
            subject, intro = detail.get("subject", ""), detail.get("intro", "")
            detail["extracted_code"] = _extract_code(subject, intro, detail.get("text", "")) or (
                _extract_code(subject, _html_to_text(raw_html)) if raw_html else None
            )
        return jsonify({"success": True, "detail": detail})

    except Exception as e:
        app.logger.error(f"Could not load message detail: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})


@app.route("/api/inbox/attachment/<message_id>/<attachment_id>")
@login_required
def inbox_attachment(message_id, attachment_id):
    """Proxy-download an inbox attachment."""
    email = request.args.get("email", "").strip()
    password = ""  # never taken from the URL (it would end up in logs)
    if not email:
        return jsonify({"success": False, "message": "Missing mailbox parameter"}), 400

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    token, err = _get_mail_token(email, password)
    if err:
        return jsonify({"success": False, "message": err[0]}), err[1]

    headers = {"Authorization": f"Bearer {token}"}
    url, download_resp = _find_attachment_download_url(base_url, message_id, attachment_id, headers)
    if not download_resp:
        return jsonify({"success": False, "message": "Attachment download is unavailable"}), 404

    try:
        filename = request.args.get("filename", "attachment")
        content_type = download_resp.headers.get("Content-Type", "application/octet-stream")
        proxied = Response(stream_with_context(download_resp.iter_content(65536)), content_type=content_type)
        proxied.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
        if "Content-Length" in download_resp.headers:
            proxied.headers["Content-Length"] = download_resp.headers["Content-Length"]
        return proxied
    except Exception as e:
        app.logger.error(f"Attachment download failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Attachment download failed"}), 502


@app.route("/api/inbox/source/<message_id>")
@login_required
def inbox_source(message_id):
    """Proxy-download the raw message (.eml); 404 if upstream lacks it."""
    email = request.args.get("email", "").strip()
    password = ""  # never taken from the URL (it would end up in logs)
    if not email:
        return jsonify({"success": False, "message": "Missing mailbox parameter"}), 400

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    token, err = _get_mail_token(email, password)
    if err:
        return jsonify({"success": False, "message": err[0]}), err[1]

    headers = {"Authorization": f"Bearer {token}"}
    url, source_resp = _find_message_source_url(base_url, message_id, headers)
    if not source_resp:
        return jsonify({"success": False, "message": "Raw message download is unavailable"}), 404

    try:
        filename = request.args.get("filename", "").strip() or f"{message_id}.eml"
        if not filename.lower().endswith(".eml"):
            filename += ".eml"

        # Some implementations wrap the raw message in JSON; others return raw bytes
        content_type = (source_resp.headers.get("Content-Type") or "").lower()
        if "json" in content_type:
            payload = source_resp.json()
            source_resp.close()
            raw = ""
            if isinstance(payload, dict):
                for key in ("data", "raw", "source", "eml"):
                    value = payload.get(key)
                    if isinstance(value, str) and value:
                        raw = value
                        break
            elif isinstance(payload, str):
                raw = payload
            if not raw:
                return jsonify({"success": False, "message": "Raw message download is unavailable"}), 404
            proxied = Response(raw, content_type="message/rfc822")
        else:
            proxied = Response(
                stream_with_context(source_resp.iter_content(65536)),
                content_type="message/rfc822",
            )
            if "Content-Length" in source_resp.headers:
                proxied.headers["Content-Length"] = source_resp.headers["Content-Length"]

        proxied.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
        return proxied
    except Exception as e:
        app.logger.error(f"Raw message download failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Raw message download failed"}), 502


# ---- Batch actions API ----

@app.route("/api/inbox/batch", methods=["POST"])
@login_required
def inbox_batch():
    """Batch message actions"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    action = data.get("action", "").strip()
    message_ids = data.get("message_ids", [])

    if not email or not action or (not message_ids and action != "empty_trash"):
        return jsonify({"success": False, "message": "Missing required parameters"})
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0]})

        batch_resp = http_session.post(
            f"{base_url}/messages/batch",
            json={"action": action, "message_ids": message_ids},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )

        if batch_resp.status_code == 200:
            return jsonify({"success": True, **batch_resp.json()})
        else:
            detail = "Operation failed"
            try:
                detail = batch_resp.json().get("detail", detail)
            except Exception:
                pass
            return jsonify({"success": False, "message": detail})

    except Exception as e:
        app.logger.error(f"Batch action failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})


# ---- Inbox tabs (Primary / Favorites / Security / Promotions / ...) ----

def _tabs_call(path: str, method: str = "GET", body: dict | None = None):
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    if not email:
        return jsonify({"success": False, "message": "Missing mailbox"})
    token, err = _get_mail_token(email, str(data.get("password", "")).strip())
    if err or not token:
        return jsonify({"success": False, "message": (err or ["Sign-in failed"])[0]})
    try:
        resp = http_session.request(method, f"{DUCKMAIL_BASE_URL.rstrip('/')}{path}", json=body,
                                    headers={"Authorization": f"Bearer {token}"}, timeout=30)
        payload = resp.json()
    except Exception as e:
        app.logger.error(f"Tabs request failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})
    if resp.status_code != 200:
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return jsonify({"success": False, "message": detail if isinstance(detail, str) else "Operation failed"})
    return jsonify({"success": True, **payload})


@app.route("/api/inbox/tabs", methods=["POST"])
@login_required
def inbox_tabs():
    """Tab list with totals / unread counts, rules and the flood warning."""
    return _tabs_call("/messages/tabs")


@app.route("/api/inbox/tabs/move", methods=["POST"])
@login_required
def inbox_tabs_move():
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    data = request.get_json(silent=True) or {}
    body = {k: data.get(k) for k in ("message_ids", "tab", "rule", "match", "senders") if k in data}
    return _tabs_call("/messages/tabs/move", "POST", body)


@app.route("/api/inbox/tabs/settings", methods=["POST"])
@login_required
def inbox_tabs_settings():
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    data = request.get_json(silent=True) or {}
    keys = ("enabled", "hidden", "order", "add_tab", "rename_tab", "remove_tab", "remove_rule")
    return _tabs_call("/messages/tabs/settings", "POST", {k: data[k] for k in keys if k in data})


# ---- Search messages API ----

@app.route("/api/inbox/search", methods=["POST"])
@login_required
def inbox_search():
    """Search messages"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    query = data.get("query", "").strip()

    if not email or not query:
        return jsonify({"success": False, "message": "Missing required parameters", "messages": []})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0], "messages": []})

        search_resp = http_session.get(
            f"{base_url}/messages/search",
            params={"q": query},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if search_resp.status_code != 200:
            return jsonify({"success": False, "message": "Search failed", "messages": []})

        messages = search_resp.json()
        if isinstance(messages, dict):
            messages = messages.get("hydra:member", [])

        for msg in messages:
            msg["extracted_code"] = _extract_code(msg.get("subject", ""), msg.get("intro", ""))

        return jsonify({"success": True, "messages": messages})

    except Exception as e:
        app.logger.error(f"Search failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again", "messages": []})


# ---- Delete API ----

@app.route("/api/inbox/delete", methods=["POST"])
@login_required
def inbox_delete():
    """Delete messages (soft delete)"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    message_id = data.get("message_id", "").strip()

    if not email or not message_id:
        return jsonify({"success": False, "message": "Missing required parameters"})
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0]})

        del_resp = http_session.delete(
            f"{base_url}/messages/{_seg(message_id)}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )

        if del_resp.status_code == 200:
            return jsonify({"success": True, "message": "Message deleted"})
        else:
            return jsonify({"success": False, "message": f"Could not delete (HTTP {del_resp.status_code})"})

    except Exception as e:
        app.logger.error(f"Delete failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})


# ---- Trash / restore / permanent delete API ----

@app.route("/api/trash/query", methods=["POST"])
@login_required
def trash_query():
    """List trashed messages."""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    offset = int(data.get("offset", 0))
    limit = int(data.get("limit", 30))

    if not email:
        return jsonify({"success": False, "message": "Missing mailbox address", "messages": []})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0], "messages": []})

        headers = {"Authorization": f"Bearer {token}"}
        trash_resp = http_session.get(
            f"{base_url}/messages/trash",
            params={"offset": offset, "limit": limit},
            headers=headers,
            timeout=30,
        )
        if trash_resp.status_code == 404:
            trash_resp = http_session.get(
                f"{base_url}/trash",
                params={"offset": offset, "limit": limit},
                headers=headers,
                timeout=30,
            )
        if trash_resp.status_code != 200:
            return jsonify({"success": False, "message": "Trash is unavailable", "messages": []})

        resp_data = trash_resp.json()
        messages = resp_data.get("hydra:member", []) if isinstance(resp_data, dict) else resp_data
        total = resp_data.get("hydra:totalItems", len(messages)) if isinstance(resp_data, dict) else len(messages)
        return jsonify({"success": True, "messages": messages, "total": total, "offset": offset, "limit": limit})

    except Exception as e:
        app.logger.error(f"Trash query failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again", "messages": []})


@app.route("/api/inbox/restore", methods=["POST"])
@login_required
def inbox_restore():
    """Restore a message from trash."""
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    return _message_action(["restore"], "Message restored")


@app.route("/api/inbox/permanent-delete", methods=["POST"])
@login_required
def inbox_permanent_delete():
    """Permanently delete a message."""
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    return _message_action(["permanent-delete", "permanent_delete", "purge"], "Message permanently deleted")


def _message_action(actions: list[str], ok_message: str):
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    message_id = data.get("message_id", "").strip()

    if not email or not message_id:
        return jsonify({"success": False, "message": "Missing required parameters"})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0]})

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        last_resp = None
        for action in actions:
            endpoints = []
            if action in {"permanent-delete", "permanent_delete", "purge"}:
                endpoints.append(("delete", f"{base_url}/messages/{_seg(message_id)}/permanent", None))
            endpoints.extend([
                ("post", f"{base_url}/messages/{_seg(message_id)}/{action}", None),
                ("patch", f"{base_url}/messages/{_seg(message_id)}", {"action": action}),
                ("post", f"{base_url}/messages/batch", {"action": action, "message_ids": [message_id]}),
            ])
            for method, url, payload in endpoints:
                resp = http_session.request(method, url, json=payload, headers=headers, timeout=30)
                last_resp = resp
                if resp.status_code in (200, 204):
                    payload = resp.json() if resp.content else {}
                    return jsonify({"success": True, "message": ok_message, **payload})
                if resp.status_code not in (404, 405, 422):
                    detail = _extract_api_error(resp, ok_message)
                    return jsonify({"success": False, "message": detail}), resp.status_code

        detail = _extract_api_error(last_resp, "The backend does not provide this action") if last_resp else "The backend does not provide this action"
        return jsonify({"success": False, "message": detail})

    except Exception as e:
        app.logger.error(f"Message action failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})


# ---- Sent messages API ----

@app.route("/api/sent/detail", methods=["POST"])
@login_required
def sent_detail():
    """Sent message detail."""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    message_id = data.get("message_id", "").strip()

    if not email or not message_id:
        return jsonify({"success": False, "message": "Missing required parameters"})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0]})

        detail_resp = http_session.get(
            f"{base_url}/sent/{_seg(message_id)}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if detail_resp.status_code != 200:
            detail = _extract_api_error(detail_resp, "Could not load sent message")
            return jsonify({"success": False, "message": detail})

        detail = detail_resp.json()
        if isinstance(detail, dict):
            # Search the raw body before sanitising: plain part first, then the HTML's visible text
            raw_html = detail.get("html", "")
            detail["html"], detail["privacy"] = _prepare_html_with_report(detail.get("html", ""))
        return jsonify({"success": True, "detail": detail})

    except Exception as e:
        app.logger.error(f"Could not load sent message: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again"})


@app.route("/api/sent/query", methods=["POST"])
@login_required
def sent_query():
    """List sent messages"""
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not email:
        return jsonify({"success": False, "message": "Missing mailbox address", "messages": []})

    base_url = DUCKMAIL_BASE_URL.rstrip("/")

    try:
        token, err = _get_mail_token(email, password)
        if err:
            return jsonify({"success": False, "message": err[0], "messages": []})

        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 30))
        sent_resp = http_session.get(
            f"{base_url}/sent",
            params={"offset": offset, "limit": limit},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if sent_resp.status_code != 200:
            return jsonify({"success": False, "message": "Could not load sent messages", "messages": []})

        resp_data = sent_resp.json()
        if isinstance(resp_data, dict):
            messages = resp_data.get("hydra:member", [])
            total = resp_data.get("hydra:totalItems", len(messages))
        else:
            messages = resp_data
            total = len(messages)
        if total == len(messages) and len(messages) > limit:
            messages = messages[offset:offset + limit]
        for msg in messages:
            if isinstance(msg, dict):
                msg["html"] = _prepare_html_for_render(msg.get("html", ""))

        return jsonify({"success": True, "messages": messages, "total": total, "offset": offset, "limit": limit})

    except Exception as e:
        app.logger.error(f"Could not list sent messages: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Internal error, please try again", "messages": []})


@app.route("/api/sent/batch", methods=["POST"])
@login_required
def sent_batch():
    """Delete messages from Sent (the copies BearerMail keeps; delivered mail is not recalled)."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    ids = data.get("message_ids") or []
    if not email or not isinstance(ids, list) or not ids:
        return jsonify({"success": False, "message": "Missing required parameters"})
    if _check_viewer_rate_limit("mail_mutation", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    token, err = _get_mail_token(email, "")
    if err:
        return jsonify({"success": False, "message": err[0]})
    try:
        resp = http_session.post(f"{DUCKMAIL_BASE_URL.rstrip('/')}/sent/batch", json={"action": "delete", "message_ids": ids},
                                 headers={"Authorization": f"Bearer {token}"}, timeout=30)
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"})
    if resp.status_code != 200:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Delete failed")})
    return jsonify({"success": True, **resp.json()})


# ---- Send API (through the configured SMTP provider) ----

def _normalize_attachments(raw) -> tuple[list, str]:
    """Validate base64 attachments from the frontend; returns (attachment list, error message)."""
    if not raw:
        return [], ""
    if not isinstance(raw, list):
        return [], "Invalid attachment format"
    if len(raw) > MAX_ATTACHMENT_COUNT:
        return [], f"At most {MAX_ATTACHMENT_COUNT} attachments allowed"

    normalized = []
    total = 0
    for item in raw:
        if not isinstance(item, dict):
            return [], "Invalid attachment format"
        filename = str(item.get("filename") or "").strip()
        content = item.get("content")
        if not filename or not isinstance(content, str) or not content:
            return [], "Attachment is missing a file name or content"
        # Keep only the base file name so path separators never reach Content-Disposition
        filename = os.path.basename(filename.replace("\\", "/"))[:200]
        if not filename:
            return [], "Invalid attachment file name"
        try:
            decoded = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            return [], f"Attachment {filename} is not valid base64"
        if len(decoded) > MAX_ATTACHMENT_BYTES:
            return [], f"Attachment {filename} exceeds the {MAX_ATTACHMENT_BYTES // 1024 // 1024}MB per-file limit"
        total += len(decoded)
        if total > MAX_ATTACHMENT_TOTAL_BYTES:
            return [], f"Attachments exceed the {MAX_ATTACHMENT_TOTAL_BYTES // 1024 // 1024}MB total limit"
        entry = {"filename": filename, "content": content}
        content_type = str(item.get("contentType") or "").strip()
        if content_type:
            entry["content_type"] = content_type[:100]
        normalized.append(entry)

    return normalized, ""


@app.route("/api/send", methods=["POST"])
@login_required
def send_email():
    """Send a message through the mail service (which relays via your SMTP provider)."""
    if _check_viewer_rate_limit("send_email", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    if not DUCKMAIL_API_KEY:
        return jsonify({"success": False, "message": "No API key configured, cannot send"}), 503

    data = request.json or {}
    from_email = data.get("from_email", "").strip()
    to = data.get("to", "").strip()
    subject = data.get("subject", "").strip()
    html = data.get("html", "").strip()
    text = data.get("text", "").strip()
    attachments, attachment_error = _normalize_attachments(data.get("attachments"))
    if attachment_error:
        return jsonify({"success": False, "message": attachment_error})

    if not from_email:
        return jsonify({"success": False, "message": "Enter a sender address"})
    if not to:
        return jsonify({"success": False, "message": "Enter a recipient address"})
    if not subject:
        return jsonify({"success": False, "message": "Enter a subject"})
    if not html and not text:
        return jsonify({"success": False, "message": "Enter a message body"})

    payload = {
        "from_email": from_email.lower(),
        "from_name": data.get("from_name", "").strip(),
        "to": [addr.strip() for addr in to.split(",") if addr.strip()],
        "subject": subject,
        "text": text,
        "html": _sanitize_email_html(html) if html else "",
        "reply_to": data.get("reply_to", "").strip(),
        "in_reply_to": data.get("in_reply_to", "").strip(),
        "attachments": attachments,
    }
    if isinstance(data.get("drive_files"), list) and data["drive_files"]:
        payload["drive_files"] = [str(x) for x in data["drive_files"][:20] if re.fullmatch(r"[0-9a-f]{24}", str(x))]
    if data.get("event_id") and re.fullmatch(r"[0-9a-f]{24}", str(data["event_id"])):
        payload["event_id"] = str(data["event_id"])
    user = current_user()
    if user and user.get("kind") == "user":
        payload["as_user"] = user["address"]  # the mail service enforces the sender and SMTP rules

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        resp = http_session.post(
            f"{base_url}/admin/send",
            json=payload,
            headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"},
            timeout=90,
        )
    except Exception as e:
        app.logger.error(f"Send failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Could not reach the mail service"})

    if resp.status_code == 200:
        return jsonify({"success": True, "message": "Message sent", "email_id": resp.json().get("message_id", "")})
    return jsonify({"success": False, "message": _extract_api_error(resp, "Send failed")})


# ---- Setup API: authenticated proxy to the mail service admin endpoints ----

_ADMIN_PROXY_ALLOWED = re.compile(
    r"^(accounts(/[^/]+)?|aliases(/[^/]+)?|smtp-providers(/[^/]+(/test)?)?|smtp-presets|connect-info"
    r"|domains|domains/[^/]+|domains/[^/]+/dns|domains/[^/]+/dns/check"
    r"|security/(events|summary|settings|test-alert|imap-sessions|imap-sessions/[0-9a-f]{24}/kick"
    r"|blocklist|blocklist/[0-9a-fA-F.:]+(/[0-9]{1,3})?)"
    r"|relay-keys|relay-keys/revoke-all|relay-keys/[0-9a-f]{24}(/revoke)?"
    r"|users/[^/]+/app-passwords|users/[^/]+/app-passwords/[0-9a-f]{24}/revoke"
    r"|invites|invites/[^/]+"
    r"|dmarc/summary|dmarc/reports|dmarc/import"
    r"|ddns|ddns/check|domains/[^/]+/cloudflare"
    r"|signup/mode)$"
)


@app.route("/api/admin/<path:subpath>", methods=["GET", "POST", "PATCH", "DELETE"])
@admin_required
def admin_proxy(subpath):
    """Forward Setup-page calls to mail-service /admin/*, adding the API key server-side."""
    if not DUCKMAIL_API_KEY:
        return jsonify({"success": False, "message": "No API key configured"}), 503
    if not _ADMIN_PROXY_ALLOWED.fullmatch(subpath) or any(seg in (".", "..") for seg in subpath.split("/")):
        return jsonify({"success": False, "message": "Not found"}), 404
    body = None
    if request.method in ("POST", "PATCH"):
        if not request.is_json:
            return jsonify({"success": False, "message": "JSON body required"}), 415
        body = request.get_json(silent=True) or {}
        if subpath == "security/blocklist" and isinstance(body, dict):
            body["protect"] = [_client_ip()]  # never lock yourself out
        if (subpath.startswith("relay-keys") or "/app-passwords" in subpath) and isinstance(body, dict):
            body["by"] = (current_user() or {}).get("address") or "admin"  # who created / revoked a key
    if request.method != "GET" and _check_viewer_rate_limit(
        "admin_proxy", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX * 3
    ):
        return _rate_limited_json()

    base_url = DUCKMAIL_BASE_URL.rstrip("/")
    try:
        resp = http_session.request(
            request.method,
            f"{base_url}/admin/{quote(subpath, safe='/@')}",
            params=request.args or None,
            json=body,
            headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"},
            timeout=90,
        )
    except Exception as e:
        app.logger.error(f"Admin proxy failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502

    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if resp.status_code >= 400:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Request failed")}), resp.status_code
    if subpath == "security/settings":
        _privacy_cache["ts"] = 0.0
    return jsonify({"success": True, **(payload if isinstance(payload, dict) else {"data": payload})})


# ---- Security page: sign-in protection (two-factor, sessions) and external account status ----

def _require_recent_password(data: dict) -> tuple | None:
    """Sensitive changes need the web app password again (so an open, unattended browser is not enough)."""
    password = data.get("password", "") if isinstance(data.get("password"), str) else ""
    if _check_viewer_rate_limit("security_confirm", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        return jsonify({"success": False, "message": "Too many attempts, please wait a few minutes"}), 429
    if not ACCESS_PASSWORD or not hmac.compare_digest(password.encode("utf-8"), ACCESS_PASSWORD.encode("utf-8")):
        return jsonify({"success": False, "message": "The web app password is not right"}), 403
    return None


@app.route("/api/security/overview", methods=["GET"])
@admin_required
def security_overview():
    current = session.get("sid", "")
    sessions = []
    for s in security_store.list_sessions():
        sessions.append({
            "id": s["id"], "current": s["id"] == current, "ip": s.get("ip", ""), "device": s.get("ua", ""),
            "method": s.get("method", ""), "user": s.get("user", ""),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.get("created", 0))),
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.get("last_seen", 0))),
        })
    return jsonify({
        "success": True,
        "your_ip": _client_ip(),
        "two_factor": {"enabled": security_store.totp_enabled(), "recovery_codes_left": security_store.recovery_codes_left()},
        "sessions": sessions,
        "session_hours": SESSION_HOURS,
    })


@app.route("/api/security/sessions/<sid>", methods=["DELETE"])
@admin_required
def security_end_session(sid):
    if sid == session.get("sid"):
        return jsonify({"success": False, "message": "Use Sign out to end the session you are using"}), 400
    if not security_store.end_session(sid):
        return jsonify({"success": False, "message": "That session has already ended"}), 404
    security_reporter.report("sessions_revoked", ip=_client_ip(), detail="1 session", aggregate=False)
    return jsonify({"success": True})


@app.route("/api/security/sessions/revoke-others", methods=["POST"])
@admin_required
def security_end_other_sessions():
    count = security_store.end_other_sessions(session.get("sid", ""))
    security_reporter.report("sessions_revoked", ip=_client_ip(), detail=f"{count} other sessions", aggregate=False)
    return jsonify({"success": True, "ended": count})


@app.route("/api/security/2fa/setup", methods=["POST"])
@admin_required
def security_2fa_setup():
    if security_store.totp_enabled():
        return jsonify({"success": False, "message": "Two-factor sign-in is already on"}), 409
    secret = sec.new_totp_secret()
    session["totp_pending"] = security_store.encrypt(secret)
    label = urlparse(request.host_url).hostname or "BearerMail"
    uri = sec.otpauth_uri(secret, label)
    return jsonify({"success": True, "secret": secret, "uri": uri, "qr_svg": sec.qr_svg(uri)})


@app.route("/api/security/2fa/enable", methods=["POST"])
@admin_required
def security_2fa_enable():
    data = request.get_json(silent=True) or {}
    denied = _require_recent_password(data)
    if denied:
        return denied
    pending = session.get("totp_pending")
    secret = security_store.decrypt(pending) if pending else None
    if not secret:
        return jsonify({"success": False, "message": "Start the setup again"}), 400
    if sec.totp_match(secret, str(data.get("code", ""))) is None:
        return jsonify({"success": False, "message": "That code is not right. Check the time on your phone and try the current code."}), 400
    codes = security_store.enable_totp(secret)
    session.pop("totp_pending", None)
    security_reporter.report("2fa_enabled", ip=_client_ip(), aggregate=False)
    return jsonify({"success": True, "recovery_codes": codes})


@app.route("/api/security/2fa/disable", methods=["POST"])
@admin_required
def security_2fa_disable():
    data = request.get_json(silent=True) or {}
    denied = _require_recent_password(data)
    if denied:
        return denied
    if security_store.totp_enabled() and not security_store.verify_second_factor(str(data.get("code", ""))):
        return jsonify({"success": False, "message": "Enter a current code from your app (or a recovery code)"}), 400
    security_store.disable_totp()
    security_reporter.report("2fa_disabled", ip=_client_ip(), aggregate=False)
    return jsonify({"success": True})


@app.route("/api/security/2fa/recovery-codes", methods=["POST"])
@admin_required
def security_2fa_recovery_codes():
    data = request.get_json(silent=True) or {}
    denied = _require_recent_password(data)
    if denied:
        return denied
    if not security_store.totp_enabled():
        return jsonify({"success": False, "message": "Turn on two-factor sign-in first"}), 400
    return jsonify({"success": True, "recovery_codes": security_store.regenerate_recovery_codes()})


@app.route("/api/security/external-accounts", methods=["GET"])
@admin_required
def security_external_accounts():
    """Connection health of the Gmail/Outlook/... accounts added under External accounts."""
    headers = {"X-Bridge-Token": BRIDGE_TOKEN} if BRIDGE_TOKEN else {}
    try:
        resp = internal_http.get(f"{IMAP_MAIL_BASE_URL.rstrip('/')}/api/status", headers=headers, timeout=5)
        payload = resp.json() if resp.status_code == 200 else {}
    except Exception:
        return jsonify({"success": False, "message": "The external accounts service is not reachable", "accounts": []})
    return jsonify({"success": True, "accounts": payload.get("accounts", []), "persistence": payload.get("persistence", "")})


# ---- "My account": what a signed-in user may manage for themselves (multi-account mode) ----

def _me_or_403():
    user = current_user()
    if not user or user.get("kind") != "user":
        return None, (jsonify({"success": False, "message": "Only for personal accounts (multi-account mode)"}), 400)
    return user, None


def _svc_json(method: str, path: str, body=None, ok_message: str = ""):
    try:
        resp = _svc(method, path, json=body) if body is not None else _svc(method, path)
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if resp.status_code >= 400:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Request failed")}), resp.status_code
    if isinstance(payload, dict):
        return jsonify({"success": True, **({"message": ok_message} if ok_message else {}), **payload})
    return jsonify({"success": True, "data": payload})


def _confirm_own_password(user: dict, data: dict):
    """Sensitive changes ask for the mailbox password again."""
    if _check_viewer_rate_limit("security_confirm", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        return jsonify({"success": False, "message": "Too many attempts, please wait a few minutes"}), 429
    password = data.get("password") if isinstance(data.get("password"), str) else ""
    try:
        resp = _svc("POST", "/admin/users/login", json={"address": user["address"], "password": password})
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code != 200:
        return jsonify({"success": False, "message": "Your password is not right"}), 403
    return None


@app.route("/api/me", methods=["GET"])
@login_required
def me():
    info = _public_user()
    if info["kind"] == "user":
        profile = _load_user(info["address"], force=True) or {}
        info.update(recovery_codes_left=profile.get("recovery_codes_left", 0), last_login=profile.get("last_login"))
    return jsonify({"success": True, **info})


@app.route("/api/me/password", methods=["POST"])
@login_required
def me_password():
    user, err = _me_or_403()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    if _check_viewer_rate_limit("security_confirm", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX):
        return _rate_limited_json()
    result = _svc_json("POST", f"/admin/users/{_seg(user['address'])}/password",
                       {"current": data.get("current", ""), "new": data.get("new", "")})
    if result.status_code == 200:
        # Everywhere else this account was signed in must sign in with the new password.
        security_store.end_other_sessions(session.get("sid", ""), user=user["address"])
    return result


@app.route("/api/me/sessions", methods=["GET"])
@login_required
def me_sessions():
    user, err = _me_or_403()
    if err:
        return err
    current = session.get("sid", "")
    out = [{"id": s["id"], "current": s["id"] == current, "ip": s.get("ip", ""), "device": s.get("ua", ""),
            "method": s.get("method", ""),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.get("created", 0))),
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.get("last_seen", 0)))}
           for s in security_store.list_sessions(user=user["address"])]
    return jsonify({"success": True, "sessions": out, "session_hours": SESSION_HOURS, "your_ip": _client_ip()})


@app.route("/api/me/sessions/<sid>", methods=["DELETE"])
@login_required
def me_end_session(sid):
    user, err = _me_or_403()
    if err:
        return err
    if sid == session.get("sid") or not any(s["id"] == sid for s in security_store.list_sessions(user=user["address"])):
        return jsonify({"success": False, "message": "That session cannot be ended here"}), 404
    security_store.end_session(sid)
    return jsonify({"success": True})


@app.route("/api/me/sessions/revoke-others", methods=["POST"])
@login_required
def me_end_other_sessions():
    user, err = _me_or_403()
    if err:
        return err
    count = security_store.end_other_sessions(session.get("sid", ""), user=user["address"])
    security_reporter.report("sessions_revoked", ip=_client_ip(), user=user["address"], detail=f"{count} other sessions", aggregate=False)
    return jsonify({"success": True, "ended": count})


@app.route("/api/me/2fa/<action>", methods=["POST"])
@login_required
def me_two_factor(action):
    user, err = _me_or_403()
    if err:
        return err
    if action not in ("setup", "enable", "disable", "recovery-codes"):
        return jsonify({"success": False, "message": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    base = f"/admin/users/{_seg(user['address'])}/2fa"
    if action == "setup":
        try:
            resp = _svc("POST", f"{base}/setup")
        except Exception:
            return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
        if resp.status_code != 200:
            return jsonify({"success": False, "message": _extract_api_error(resp, "Could not start the setup")}), resp.status_code
        secret = resp.json()["secret"]
        uri = sec.otpauth_uri(secret, user["address"])
        return jsonify({"success": True, "secret": secret, "uri": uri, "qr_svg": sec.qr_svg(uri)})
    denied = _confirm_own_password(user, data)
    if denied:
        return denied
    if action == "enable":
        result = _svc_json("POST", f"{base}/enable", {"code": data.get("code", "")})
        if result.status_code == 200:
            security_reporter.report("2fa_enabled", ip=_client_ip(), user=user["address"], aggregate=False)
        return result
    if action == "disable":
        check = _svc("POST", f"{base}/verify", json={"code": data.get("code", "")})
        if check.status_code != 200:
            return jsonify({"success": False, "message": "Enter a current code from your app (or a recovery code)"}), 400
        security_reporter.report("2fa_disabled", ip=_client_ip(), user=user["address"], aggregate=False)
        return _svc_json("POST", f"{base}/disable", {})
    return _svc_json("POST", f"{base}/recovery-codes", {})


@app.route("/api/me/aliases", methods=["GET", "POST"])
@app.route("/api/me/aliases/<alias>", methods=["PATCH", "DELETE"])
@login_required
def me_aliases(alias=None):
    user, err = _me_or_403()
    if err:
        return err
    base = f"/admin/users/{_seg(user['address'])}/aliases"
    if request.method == "GET":
        return _svc_json("GET", base)
    if request.method != "GET" and _check_viewer_rate_limit("admin_proxy", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX * 3):
        return _rate_limited_json()
    _user_cache.pop(user["address"], None)  # the list of addresses this person may open changes
    if request.method == "POST":
        return _svc_json("POST", base, request.get_json(silent=True) or {})
    if request.method == "PATCH":
        return _svc_json("PATCH", f"{base}/{_seg(alias)}", request.get_json(silent=True) or {})
    return _svc_json("DELETE", f"{base}/{_seg(alias)}")


@app.route("/api/me/smtp-providers", methods=["GET", "POST"])
@app.route("/api/me/smtp-providers/<provider_id>", methods=["PATCH", "DELETE"])
@app.route("/api/me/smtp-providers/<provider_id>/test", methods=["POST"])
@login_required
def me_smtp(provider_id=None):
    user, err = _me_or_403()
    if err:
        return err
    base = f"/admin/users/{_seg(user['address'])}/smtp-providers"
    if request.method == "GET":
        return _svc_json("GET", base)
    if _check_viewer_rate_limit("admin_proxy", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX * 3):
        return _rate_limited_json()
    body = request.get_json(silent=True) or {}
    if request.path.endswith("/test"):
        return _svc_json("POST", f"{base}/{_seg(provider_id)}/test", body)
    if request.method == "POST":
        return _svc_json("POST", base, body)
    if request.method == "PATCH":
        return _svc_json("PATCH", f"{base}/{_seg(provider_id)}", body)
    return _svc_json("DELETE", f"{base}/{_seg(provider_id)}")


@app.route("/api/me/smtp-presets", methods=["GET"])
@login_required
def me_smtp_presets():
    return _svc_json("GET", "/admin/smtp-presets")


@app.route("/api/me/connect-info", methods=["GET"])
@login_required
def me_connect_info():
    user = current_user()
    try:
        own_domain = (user.get("address") or "").split("@")[-1] if user and user.get("address") else ""
        resp = _svc("GET", "/admin/connect-info", params={"domain": own_domain} if own_domain else None)
        info = resp.json() if resp.status_code == 200 else {}
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if user and user["role"] != "admin":
        info["mailboxes"] = [user["address"]]
        try:
            usable = _svc("GET", f"/admin/users/{_seg(user['address'])}/smtp-providers").json().get("usable", [])
        except Exception:
            usable = []
        # Users never see the provider's server or account; they send with their own SMTP key instead.
        info["provider_names"] = [u["name"] for u in usable if not u.get("own")]
        info["smtp_providers"] = []
    return jsonify({"success": True, **info})


# ---- Users (admin): multi-account mode switch and per-user rights ----

@app.route("/api/users", methods=["GET"])
@admin_required
def users_list():
    resp = _svc_json("GET", "/admin/users")
    if isinstance(resp, tuple):  # an error answer
        return resp
    if resp.status_code == 200 and resp.is_json:
        data = resp.get_json()
        data["session_hours"] = SESSION_HOURS  # the "Default" in Stay signed in
        return jsonify(data)
    return resp


@app.route("/api/users/<address>", methods=["PATCH"])
@admin_required
def users_update(address):
    result = _svc_json("PATCH", f"/admin/users/{_seg(address)}", request.get_json(silent=True) or {})
    _user_cache.pop(address.strip().lower(), None)
    if not isinstance(result, tuple) and result.status_code == 200:
        body = request.get_json(silent=True) or {}
        if body.get("is_active") is False:
            security_store.end_other_sessions("", user=address.strip().lower())
    return result


@app.route("/api/users/mode", methods=["POST"])
@admin_required
def users_mode():
    data = request.get_json(silent=True) or {}
    user = current_user() or {}
    if data.get("mode") == "multi" and user.get("kind") == "single":
        # Switching needs the shared password once more, and the admin mailbox's password after it.
        if not hmac.compare_digest(str(data.get("confirm", "")).encode("utf-8"), ACCESS_PASSWORD.encode("utf-8")):
            return jsonify({"success": False, "message": "Enter the current web app password (ACCESS_PASSWORD) to confirm"}), 403
    result = _svc_json("POST", "/admin/auth/mode", {k: data.get(k) for k in ("mode", "admin", "password")})
    if result.status_code == 200:
        auth_mode(force=True)
        _user_cache.clear()
        security_store.end_other_sessions("")  # everyone signs in again under the new mode
        session.clear()
        security_reporter.report("mode_changed", ip=_client_ip(), detail=f"sign-in mode set to {data.get('mode')}", aggregate=False)
    return result


# ---- Stealth sign-in: an admin looks into someone's mailbox without appearing anywhere they can see ----

@app.route("/api/users/<address>/stealth", methods=["POST"])
@admin_required
def users_stealth(address):
    user = current_user() or {}
    if auth_mode() != "multi":
        return jsonify({"success": False, "message": "Stealth sign-in is for personal-accounts mode"}), 400
    if session.get("stealth"):
        return jsonify({"success": False, "message": "Return to your own account first"}), 409
    target = (address or "").strip().lower()
    if target == (user.get("address") or ""):
        return jsonify({"success": False, "message": "That is your own mailbox"}), 400
    profile = _load_user(target, force=True)
    if not profile:
        return jsonify({"success": False, "message": "No mailbox with that address"}), 404
    if profile.get("role") == "admin":
        return jsonify({"success": False, "message": "Admins cannot open other admins' mailboxes"}), 403
    if _check_viewer_rate_limit("stealth", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX):
        return _rate_limited_json()
    # No new session, no "last sign-in" update, no alert to the person: only the admins' security log shows it.
    session["stealth"] = {"kind": user.get("kind"), "user": user.get("address") or "", "since": time.time()}
    session["kind"] = "user"
    session["user"] = profile["address"]
    g.pop("bm_user", None)
    security_reporter.report("stealth_start", ip=_client_ip(), user=user.get("address") or "emergency admin",
                             detail=f"opened {profile['address']}", aggregate=False)
    return jsonify({"success": True, "address": profile["address"]})


@app.route("/api/stealth/end", methods=["POST"])
@login_required
def stealth_end():
    stealth = session.get("stealth")
    if not stealth:
        return jsonify({"success": True})
    viewed = session.get("user", "")
    session.pop("stealth", None)
    if stealth.get("kind") == "emergency":
        session["kind"] = "emergency"
        session.pop("user", None)
    else:
        session["kind"] = "user"
        session["user"] = stealth.get("user", "")
    g.pop("bm_user", None)
    security_reporter.report("stealth_end", ip=_client_ip(), user=stealth.get("user") or "emergency admin",
                             detail=f"left {viewed}", aggregate=False)
    return jsonify({"success": True})


# ---- SMTP keys: a user's own keys (admins manage everyone's under Setup > APIs) ----

@app.route("/api/me/relay-keys", methods=["GET", "POST"])
@app.route("/api/me/relay-keys/<key_id>/revoke", methods=["POST"])
@login_required
def me_relay_keys(key_id=None):
    user = current_user()
    if not user or not user.get("address"):
        return jsonify({"success": False, "message": "Only for mailbox accounts"}), 400
    base = f"/admin/users/{_seg(user['address'])}/relay-keys"
    if request.method == "GET":
        return _svc_json("GET", base)
    if _check_viewer_rate_limit("admin_proxy", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX * 3):
        return _rate_limited_json()
    if key_id:
        if not re.fullmatch(r"[0-9a-f]{24}", key_id):
            return jsonify({"success": False, "message": "Not found"}), 404
        return _svc_json("POST", f"{base}/{key_id}/revoke", {})
    body = request.get_json(silent=True) or {}
    return _svc_json("POST", base, {k: body.get(k) for k in ("label", "provider_id")})


# ---- App passwords (Gmail style) for mail apps: email + generated code instead of the real password ----

@app.route("/api/me/app-passwords", methods=["GET", "POST"])
@app.route("/api/me/app-passwords/<key_id>/revoke", methods=["POST"])
@login_required
def me_app_passwords(key_id=None):
    user = current_user()
    if not user or not user.get("address"):
        return jsonify({"success": False, "message": "Only for mailbox accounts"}), 400
    base = f"/admin/users/{_seg(user['address'])}/app-passwords"
    if request.method == "GET":
        return _svc_json("GET", base)
    if _check_viewer_rate_limit("admin_proxy", SENSITIVE_RATE_LIMIT_WINDOW, SENSITIVE_RATE_LIMIT_MAX * 3):
        return _rate_limited_json()
    if key_id:
        if not re.fullmatch(r"[0-9a-f]{24}", key_id):
            return jsonify({"success": False, "message": "Not found"}), 404
        return _svc_json("POST", f"{base}/{key_id}/revoke", {"by": user["address"]})
    body = request.get_json(silent=True) or {}
    return _svc_json("POST", base, {"label": body.get("label", ""), "by": user["address"]})


@app.route("/api/me/app-passwords-only", methods=["POST"])
@login_required
def me_app_passwords_only():
    user, err = _me_or_403()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    only = bool(data.get("only"))
    if not only:
        # Letting mail apps use the real password again is a weakening: ask for it once more.
        denied = _confirm_own_password(user, data)
        if denied:
            return denied
    return _svc_json("POST", f"/admin/users/{_seg(user['address'])}/app-passwords-only", {"only": only})


@app.route("/api/users/app-passwords-required", methods=["POST"])
@admin_required
def users_app_passwords_required():
    data = request.get_json(silent=True) or {}
    result = _svc_json("POST", "/admin/auth/app-passwords-required", {"required": bool(data.get("required"))})
    if result.status_code == 200:
        security_reporter.report("settings_changed", ip=_client_ip(), detail=f"app passwords required: {bool(data.get('required'))}", aggregate=False)
    return result


# ---- HTTP sending API for scripts and apps: POST /api/v1/send with an SMTP key ----

def _api_key_from_request() -> tuple[str, str]:
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() == "basic":
        try:
            value = base64.b64decode(value).decode("utf-8")
        except Exception:
            return "", ""
    elif scheme.lower() != "bearer":
        return "", ""
    username, _, password = value.partition(":")
    return username.strip(), password.strip()


@app.route("/api/v1/send", methods=["POST"])
def api_v1_send():
    """Send with an SMTP key instead of a web sign-in. Authorization: Bearer <username>:<password>
    (or HTTP Basic). JSON body: from, to, cc, bcc, subject, text, html, reply_to, from_name, attachments."""
    if _check_viewer_rate_limit("api_v1_send", 60, 120):
        return jsonify({"success": False, "message": "Too many requests"}), 429
    username, password = _api_key_from_request()
    if not username or not password:
        return jsonify({"success": False, "message": "Send your SMTP key as 'Authorization: Bearer USERNAME:PASSWORD'"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Send a JSON body"}), 400
    attachments, attachment_error = _normalize_attachments(data.get("attachments"))
    if attachment_error:
        return jsonify({"success": False, "message": attachment_error}), 400
    payload = {k: data.get(k) for k in ("to", "cc", "bcc", "subject", "text", "reply_to", "from_name")}
    payload.update(username=username, password=password, from_email=data.get("from") or data.get("from_email"),
                   html=_sanitize_email_html(data["html"]) if isinstance(data.get("html"), str) and data["html"] else "",
                   attachments=attachments, client_ip=_client_ip())
    try:
        resp = _svc("POST", "/admin/relay/send", json=payload, timeout=90)  # the provider may be slow
    except Exception:
        return jsonify({"success": False, "message": "The mail service is not reachable"}), 502
    if resp.status_code == 200:
        body = resp.json()
        return jsonify({"success": True, "message_id": body.get("message_id", "")})
    return jsonify({"success": False, "message": _extract_api_error(resp, "Send failed")}), resp.status_code


# ---- Drive, storage, calendar and share links ----
# In personal-accounts mode everyone works in their own mailbox's Drive and Calendar. With the single shared
# password, the page says which mailbox (the one that is open), like the mail views do.

DRIVE_MAX_FILE_MB = max(1, int(os.getenv("DRIVE_MAX_FILE_MB", "10240")))
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().split(",")[0].strip().rstrip("/")
_SAFE_INLINE = {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain"}


def _drive_address() -> str:
    """The mailbox whose Drive / Calendar this request is about, or '' when not allowed."""
    user = current_user()
    if user and user.get("kind") == "user":
        return user["address"]
    data = request.get_json(silent=True) if request.is_json else None
    address = (request.args.get("email") or (data or {}).get("email") or "").strip().lower()
    return address if address and _may_use_address(address) else ""


def _no_mailbox():
    return jsonify({"success": False, "message": "Open a mailbox first (Drive and Calendar belong to a mailbox)"}), 400


def _public_base() -> str:
    if PUBLIC_URL and "127.0.0.1" not in PUBLIC_URL and "localhost" not in PUBLIC_URL:
        return PUBLIC_URL
    if TRUSTED_PROXY_COUNT:
        proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
        host = request.headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        if host and re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
            return f"{proto if proto in ('http', 'https') else 'https'}://{host}"
        if proto in ("http", "https"):
            return f"{proto}://{request.host}"
    return request.host_url.rstrip("/")


def _with_link(payload: dict) -> dict:
    """Links use the web address of the domain they were made for (Setup > Domains), else PUBLIC_URL."""
    if isinstance(payload, dict) and payload.get("code"):
        payload["url"] = f"{(payload.get('web_host') or _public_base()).rstrip('/')}/s/{payload['code']}"
    return payload


def _svc_stream(path: str, params=None):
    return internal_http.get(f"{DUCKMAIL_BASE_URL.rstrip('/')}{path}", params=params, stream=True, timeout=(10, 300),
                             headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}"})


def _relay_download(resp, inline: bool = False):
    """Pass a file from the mail service to the browser without holding it in memory."""
    if resp.status_code != 200:
        try:
            message = resp.json().get("detail", "Not found")
        except Exception:
            message = "Not found"
        resp.close()
        return jsonify({"success": False, "message": message}), resp.status_code
    ctype = resp.headers.get("Content-Type", "application/octet-stream")
    disposition = resp.headers.get("Content-Disposition", "attachment")
    if inline and ctype.split(";")[0].strip().lower() in _SAFE_INLINE:
        disposition = disposition.replace("attachment", "inline", 1)
    else:
        disposition = disposition.replace("inline", "attachment", 1)
    headers = {"Content-Disposition": disposition, "Cache-Control": "private, no-store"}
    if resp.headers.get("Content-Length"):
        headers["Content-Length"] = resp.headers["Content-Length"]
    # Uploaded files never run as part of this site, even if someone uploads a web page.
    headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox"
    return Response(stream_with_context(resp.iter_content(64 * 1024)), status=200, mimetype=ctype.split(";")[0], headers=headers)


@app.route("/api/storage", methods=["GET"])
@login_required
def storage_info():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    return _svc_json("GET", f"/admin/storage/{_seg(address)}")


@app.route("/api/drive", methods=["GET"])
@login_required
def drive_list():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    try:
        resp = _svc("GET", f"/admin/drive/{_seg(address)}", params={"folder": request.args.get("folder", "/")})
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code != 200:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Could not load Drive")}), resp.status_code
    return jsonify({"success": True, **resp.json()})


@app.route("/api/drive/all", methods=["GET"])
@login_required
def drive_all():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    try:
        resp = _svc("GET", f"/admin/drive/{_seg(address)}/all", params={"q": request.args.get("q", "")})
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    return jsonify({"success": resp.status_code == 200, **(resp.json() if resp.status_code == 200 else {"message": _extract_api_error(resp)})}), resp.status_code


@app.route("/api/drive/folders", methods=["POST", "DELETE"])
@app.route("/api/drive/folders/rename", methods=["POST"])
@login_required
def drive_folders():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    base = f"/admin/drive/{_seg(address)}/folders"
    if request.method == "DELETE":
        try:
            resp = _svc("DELETE", base, params={"path": request.args.get("path", ""), "recursive": request.args.get("recursive", "0")})
        except Exception:
            return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
        if resp.status_code != 200:
            return jsonify({"success": False, "message": _extract_api_error(resp, "Could not delete the folder")}), resp.status_code
        return jsonify({"success": True, **resp.json()})
    body = request.get_json(silent=True) or {}
    if request.path.endswith("/rename"):
        return _svc_json("POST", base + "/rename", {"path": body.get("path"), "name": body.get("name")})
    return _svc_json("POST", base, {"folder": body.get("folder"), "name": body.get("name")})


@app.route("/api/drive/upload", methods=["POST"])
@login_required
def drive_upload():
    """The file is the raw request body (the page sends it straight from the file picker), streamed on."""
    address = _drive_address()
    if not address:
        return _no_mailbox()
    request.max_content_length = DRIVE_MAX_FILE_MB * 1024 * 1024 + 1024
    length = request.content_length or 0
    if length > DRIVE_MAX_FILE_MB * 1024 * 1024:
        return jsonify({"success": False, "message": f"Files can be at most {DRIVE_MAX_FILE_MB} MB"}), 413
    if _check_viewer_rate_limit("drive_upload", 60, 120):
        return _rate_limited_json()
    stream = request.stream

    def body():
        while True:
            piece = stream.read(256 * 1024)
            if not piece:
                break
            yield piece

    params = {"name": request.args.get("name", "file"), "folder": request.args.get("folder", "/"),
              "content_type": (request.headers.get("X-File-Type") or "application/octet-stream")[:100]}
    # Sent on in chunks (Transfer-Encoding: chunked); the expected size goes along for the early quota check.
    headers = {"Authorization": f"Bearer {DUCKMAIL_API_KEY}", "Content-Type": "application/octet-stream"}
    params["size"] = str(length)
    try:
        resp = internal_http.post(f"{DUCKMAIL_BASE_URL.rstrip('/')}/admin/drive/{_seg(address)}/files", params=params,
                                  data=body(), headers=headers, timeout=(10, 600))
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code != 201:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Upload failed")}), resp.status_code
    return jsonify({"success": True, "file": resp.json()})


# Big files go up in parts (16 MB each by default), so no single request comes near Cloudflare's 100 MB limit.
DRIVE_UPLOAD_PART_MB = min(64, max(1, int(os.getenv("DRIVE_UPLOAD_PART_MB", "16"))))


@app.route("/api/drive/uploads", methods=["POST"])
@login_required
def drive_upload_start():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    body = request.get_json(silent=True) or {}
    return _svc_json("POST", f"/admin/drive/{_seg(address)}/uploads",
                     {k: body.get(k) for k in ("name", "folder", "size", "content_type")})


@app.route("/api/drive/uploads/<upload_id>", methods=["PUT", "DELETE"])
@login_required
def drive_upload_part(upload_id):
    address = _drive_address()
    if not address:
        return _no_mailbox()
    path = f"/admin/drive/{_seg(address)}/uploads/{_seg(upload_id)}"
    if request.method == "DELETE":
        return _svc_json("DELETE", path)
    if _check_viewer_rate_limit("drive_upload_part", 60, 900):
        return _rate_limited_json()
    limit = DRIVE_UPLOAD_PART_MB * 1024 * 1024
    request.max_content_length = limit + 1024
    if (request.content_length or 0) > limit:
        return jsonify({"success": False, "message": f"A part can be at most {DRIVE_UPLOAD_PART_MB} MB"}), 413
    data = request.get_data(cache=False)
    try:
        resp = internal_http.put(f"{DUCKMAIL_BASE_URL.rstrip('/')}{path}", params={"part": request.args.get("part", "0")},
                                 data=data, timeout=(10, 300),
                                 headers={"Authorization": f"Bearer {DUCKMAIL_API_KEY}", "Content-Type": "application/octet-stream"})
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code != 200:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Upload failed")}), resp.status_code
    return jsonify({"success": True, **resp.json()})


@app.route("/api/drive/uploads/<upload_id>/finish", methods=["POST"])
@login_required
def drive_upload_finish(upload_id):
    address = _drive_address()
    if not address:
        return _no_mailbox()
    return _svc_json("POST", f"/admin/drive/{_seg(address)}/uploads/{_seg(upload_id)}/finish", {})


@app.route("/api/drive/files/<file_id>", methods=["PATCH", "DELETE"])
@app.route("/api/drive/files/<file_id>/content", methods=["GET"])
@login_required
def drive_file(file_id):
    address = _drive_address()
    if not address:
        return _no_mailbox()
    if not re.fullmatch(r"[0-9a-f]{24}", file_id):
        return jsonify({"success": False, "message": "Not found"}), 404
    base = f"/admin/drive/{_seg(address)}/files/{file_id}"
    if request.method == "GET":
        try:
            return _relay_download(_svc_stream(base + "/content"), inline=request.args.get("inline") == "1")
        except Exception:
            return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if request.method == "DELETE":
        return _svc_json("DELETE", base)
    body = request.get_json(silent=True) or {}
    return _svc_json("PATCH", base, {k: body[k] for k in ("name", "folder") if k in body})


@app.route("/api/drive/from-message", methods=["POST"])
@app.route("/api/drive/from-attachment", methods=["POST"])
@login_required
def drive_save_from_mail():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    body = request.get_json(silent=True) or {}
    if not _may_use_address(str(body.get("email") or address)):
        return jsonify({"success": False, "message": "That is not one of your addresses"}), 403
    keys = ("message_id", "format", "folder", "sent", "attachment_id")
    path = "from-message" if request.path.endswith("from-message") else "from-attachment"
    try:
        resp = _svc("POST", f"/admin/drive/{_seg(address)}/{path}", json={k: body.get(k) for k in keys if k in body}, timeout=120)
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code != 201:
        return jsonify({"success": False, "message": _extract_api_error(resp, "Could not save to Drive")}), resp.status_code
    return jsonify({"success": True, "file": resp.json()})


@app.route("/api/drive/share-hosts", methods=["GET"])
@login_required
def drive_share_hosts():
    address = _drive_address()
    if not address:
        return _no_mailbox()
    return _svc_json("GET", f"/admin/drive/{_seg(address)}/share-hosts")


@app.route("/api/drive/shares", methods=["GET", "POST"])
@app.route("/api/drive/shares/<code>", methods=["DELETE"])
@login_required
def drive_shares(code=None):
    address = _drive_address()
    if not address:
        return _no_mailbox()
    base = f"/admin/drive/{_seg(address)}/shares"
    try:
        if request.method == "GET":
            resp = _svc("GET", base)
            if resp.status_code == 200:
                data = resp.json()
                data["shares"] = [_with_link(s) for s in data.get("shares", [])]
                return jsonify({"success": True, **data})
        elif request.method == "DELETE":
            if not re.fullmatch(r"[A-Za-z0-9]{6,16}", code or ""):
                return jsonify({"success": False, "message": "Not found"}), 404
            resp = _svc("DELETE", f"{base}/{code}")
            if resp.status_code == 200:
                return jsonify({"success": True})
        else:
            body = request.get_json(silent=True) or {}
            resp = _svc("POST", base, json={k: body.get(k) for k in ("kind", "target_id", "password", "expires_days", "domain")})
            if resp.status_code == 201:
                return jsonify({"success": True, **_with_link(resp.json())})
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    return jsonify({"success": False, "message": _extract_api_error(resp, "Request failed")}), resp.status_code


@app.route("/api/calendar", methods=["GET", "POST"])
@app.route("/api/calendar/from-message", methods=["POST"])
@app.route("/api/calendar/<event_id>", methods=["PATCH", "DELETE"])
@app.route("/api/calendar/<event_id>/ics", methods=["GET"])
@login_required
def calendar_api(event_id=None):
    address = _drive_address()
    if not address:
        return _no_mailbox()
    base = f"/admin/calendar/{_seg(address)}"
    if event_id and not re.fullmatch(r"[0-9a-f]{24}", event_id):
        return jsonify({"success": False, "message": "Not found"}), 404
    body = request.get_json(silent=True) or {}
    body.pop("email", None)
    try:
        if request.path.endswith("/ics"):
            return _relay_download(_svc_stream(f"{base}/{event_id}/ics"))
        if request.method == "GET":
            resp = _svc("GET", base, params={"start": request.args.get("start", ""), "end": request.args.get("end", "")})
        elif request.path.endswith("/from-message"):
            resp = _svc("POST", base + "/from-message", json={"message_id": body.get("message_id")})
        elif request.method == "POST":
            resp = _svc("POST", base, json=body)
        elif request.method == "PATCH":
            resp = _svc("PATCH", f"{base}/{event_id}", json=body)
        else:
            resp = _svc("DELETE", f"{base}/{event_id}")
    except Exception:
        return jsonify({"success": False, "message": "Could not reach the mail service"}), 502
    if resp.status_code not in (200, 201):
        return jsonify({"success": False, "message": _extract_api_error(resp, "Calendar request failed")}), resp.status_code
    data = resp.json()
    return jsonify({"success": True, **(data if isinstance(data, dict) else {"data": data})}), resp.status_code


# ---- Public share pages: /s/<code> (no sign-in; optional link password) ----

def _share_template(info=None, error=None, status=200, need_password=False):
    return render_template("share.html", info=info, error=error, need_password=need_password), status


def _share_info(code: str):
    if not re.fullmatch(r"[A-Za-z0-9]{6,16}", code or ""):
        return None, ("This link does not exist.", 404)
    try:
        resp = _svc("GET", f"/admin/shares/{code}")
    except Exception:
        return None, ("The server is busy, please try again.", 503)
    if resp.status_code != 200:
        return None, (_extract_api_error(resp, "This link does not exist."), resp.status_code if resp.status_code in (404, 410) else 404)
    return resp.json(), None


def _share_unlocked(code: str, info: dict) -> bool:
    return not info.get("has_password") or code in session.get("shares_ok", [])


@app.route("/s/<code>", methods=["GET", "POST"])
def share_page(code):
    info, err = _share_info(code)
    if err:
        return _share_template(error=err[0], status=err[1])
    if request.method == "POST":
        if _check_viewer_rate_limit("share_password", LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX * 2):
            return _share_template(info, error="Too many tries, please wait a few minutes.", status=429, need_password=True)
        try:
            ok = _svc("POST", f"/admin/shares/{code}/check", json={"password": request.form.get("password", "")}).status_code == 200
        except Exception:
            ok = False
        if not ok:
            return _share_template(info, error="That password is not right.", status=403, need_password=True)
        unlocked = [c for c in session.get("shares_ok", []) if c != code][-20:] + [code]
        session["shares_ok"] = unlocked
        return redirect(url_for("share_page", code=code))
    if not _share_unlocked(code, info):
        return _share_template(info, need_password=True)
    try:
        _svc("POST", f"/admin/shares/{code}/viewed")
    except Exception:
        pass
    return _share_template(info)


@app.route("/s/<code>/download")
def share_download(code):
    info, err = _share_info(code)
    if err:
        return _share_template(error=err[0], status=err[1])
    if not _share_unlocked(code, info):
        return redirect(url_for("share_page", code=code))
    try:
        return _relay_download(_svc_stream(f"/admin/shares/{code}/content"))
    except Exception:
        return _share_template(error="The server is busy, please try again.", status=503)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
