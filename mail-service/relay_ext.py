"""
BearerMail SMTP keys (Setup > APIs).

The admin's SMTP providers (Mailjet, Brevo, SES, ...) have one secret each. Handing that secret to every
user would mean replacing it everywhere the moment one person abuses it. Instead each user gets their
own BearerMail key:

    mail app  --(user's key)-->  BearerMail submission port 587 / 465  --(real secret)-->  Mailjet
    script    --(user's key)-->  POST /api/v1/send on the web app     --(real secret)-->  Mailjet

The real provider secret never leaves the server. A key:

* belongs to one mailbox, and can only send from that mailbox and the aliases that deliver into it
  (checked on the envelope sender AND on the From header, so it cannot be used to spoof anyone else);
* goes through the providers that mailbox is allowed to use (optionally pinned to one of them);
* has an hourly limit;
* can be revoked at any moment, which stops only that key. Nobody else has to change anything.

Only a hash of the key's password is stored; the password is shown once when the key is created.
"""

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import smtplib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import formatdate, getaddresses, make_msgid

from bson import ObjectId
from fastapi import APIRouter, Body, Depends, HTTPException, Request

import bearer_ext as ext
import security_ext
import users_ext

logger = logging.getLogger("bearermail.relay")

RELAY_HOURLY_LIMIT = max(1, int(os.getenv("RELAY_HOURLY_LIMIT", "100")))
RELAY_MAX_RCPTS = max(1, int(os.getenv("RELAY_MAX_RCPTS", "50")))
RELAY_MAX_MESSAGE_BYTES = max(1024, int(os.getenv("RELAY_MAX_MESSAGE_BYTES", str(15 * 1024 * 1024))))
SUBMISSION_PORT = int(os.getenv("SUBMISSION_PORT", "587"))
SUBMISSIONS_PORT = int(os.getenv("SUBMISSIONS_PORT", "465"))
SUBMISSION_ENABLED = os.getenv("SUBMISSION_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
SELF_SERVICE_MAX_KEYS = 5
ADMIN_MAX_KEYS = 20
_AUTH_FAIL_WINDOW = 900
_AUTH_FAIL_MAX = 10

_cfg = {"get_db": None, "require_api_key": None, "hostname": ""}
_state = {"submission": {"enabled": False, "ports": [], "reason": "not started"}}


def configure(get_db, require_api_key, hostname: str = ""):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key
    _cfg["hostname"] = hostname


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


router = APIRouter(dependencies=[Depends(_auth)])


def _now():
    return datetime.now(timezone.utc)


def init_indexes():
    db = _db()
    db.relay_keys.create_index("username", unique=True)
    db.relay_keys.create_index("owner")


class RelayRefused(Exception):
    """The message is refused for good (5xx)."""


class RelayTemporary(Exception):
    """Try again later (4xx)."""


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def _hash(secret: str) -> str:
    return hashlib.sha256(("bearermail-relay:" + secret).encode()).hexdigest()


APP_PASSWORD_LETTERS = "abcdefghjkmnpqrstuvwxyz"
MAX_APP_PASSWORDS = 20


def normalize_app_password(value: str) -> str:
    """App passwords are shown as 'abcd efgh jkmn pqrs'; spaces and capitals do not matter when typing them."""
    return "".join((value or "").split()).lower()


def new_app_password() -> str:
    raw = "".join(secrets.choice(APP_PASSWORD_LETTERS) for _ in range(16))
    return " ".join(raw[i:i + 4] for i in range(0, 16, 4))


def app_passwords_required() -> bool:
    return bool((_db().settings.find_one({"_id": "auth"}) or {}).get("app_passwords_required"))


def _provider_names() -> dict:
    return {str(p["_id"]): p.get("name", "") for p in _db().smtp_providers.find({}, {"name": 1})}


def _public(k: dict, names: dict | None = None) -> dict:
    names = names if names is not None else _provider_names()
    pid = k.get("provider_id")
    return {
        "id": str(k["_id"]),
        "kind": k.get("kind", "smtp_key"),
        "owner": k["owner"],
        "label": k.get("label", ""),
        "username": k["username"],
        "hint": k.get("hint", ""),
        "provider_id": pid,
        "provider": names.get(pid, "(removed)") if pid else "",
        "hourly_limit": k.get("hourly_limit") or RELAY_HOURLY_LIMIT,
        "created_at": ext._iso(k.get("created_at")),
        "created_by": k.get("created_by", ""),
        "last_used_at": ext._iso(k.get("last_used_at")),
        "last_ip": k.get("last_ip", ""),
        "sent_count": k.get("sent_count", 0),
        "revoked": bool(k.get("revoked_at")),
        "revoked_at": ext._iso(k.get("revoked_at")),
        "revoked_by": k.get("revoked_by", ""),
    }


_NOT_KEYS = ("app_password", "mailbox_password")  # listed separately from SMTP keys


def _key(key_id: str) -> dict:
    try:
        k = _db().relay_keys.find_one({"_id": ObjectId(key_id)})
    except Exception:
        k = None
    if not k:
        raise HTTPException(status_code=404, detail="Key not found")
    return k


def submission_info() -> dict:
    host = _cfg["hostname"] or ""
    ports = _state["submission"]["ports"]
    return {
        "host": host,
        "enabled": _state["submission"]["enabled"],
        "ports": ports,
        "starttls_port": SUBMISSION_PORT if SUBMISSION_PORT in ports else None,
        "tls_port": SUBMISSIONS_PORT if SUBMISSIONS_PORT in ports else None,
        "reason": _state["submission"]["reason"],
        "hourly_limit": RELAY_HOURLY_LIMIT,
        "max_recipients": RELAY_MAX_RCPTS,
    }


def _create(owner: str, body: dict, created_by: str, limit: int) -> dict:
    db = _db()
    acc = users_ext._account(owner)
    if db.relay_keys.count_documents({"owner": acc["address"], "revoked_at": None, "kind": {"$nin": list(_NOT_KEYS)}}) >= limit:
        raise HTTPException(status_code=409, detail=f"This mailbox already has {limit} active keys. Revoke one first.")
    label = str(body.get("label") or "").strip()[:60] or "Mail app"
    provider_id = body.get("provider_id") or None
    if provider_id:
        if str(provider_id) not in {str(p["_id"]) for p in users_ext.allowed_providers(acc)}:
            raise HTTPException(status_code=422, detail="That SMTP provider is not available to this mailbox")
        provider_id = str(provider_id)
    hourly = body.get("hourly_limit")
    if hourly not in (None, ""):
        if not isinstance(hourly, int) or not 1 <= hourly <= 100000:
            raise HTTPException(status_code=422, detail="The hourly limit must be a number from 1 to 100000")
    else:
        hourly = None
    username = "bm-" + secrets.token_hex(6)
    password = "bmk_" + secrets.token_urlsafe(24)
    doc = {"owner": acc["address"], "label": label, "username": username, "secret_hash": _hash(password),
           "hint": password[-4:], "provider_id": provider_id, "hourly_limit": hourly, "created_at": _now(),
           "created_by": created_by, "last_used_at": None, "last_ip": "", "sent_count": 0, "revoked_at": None}
    doc["_id"] = db.relay_keys.insert_one(doc).inserted_id
    security_ext.record("relay", "key_created", user=acc["address"], detail=f"{username} ({label}) by {created_by}", aggregate=False)
    return {"key": _public(doc), "username": username, "password": password, "submission": submission_info()}


def _revoke(k: dict, by: str) -> dict:
    if not k.get("revoked_at"):
        _db().relay_keys.update_one({"_id": k["_id"]}, {"$set": {"revoked_at": _now(), "revoked_by": by}})
        security_ext.record("relay", "key_revoked", user=k["owner"], detail=f"{k['username']} ({k.get('label', '')}) by {by}", aggregate=False)
    return _public(_db().relay_keys.find_one({"_id": k["_id"]}))


# ---- admin: every key ----

@router.get("/admin/relay-keys")
def list_keys(owner: str = ""):
    q = {"owner": ext._clean_address(owner)} if owner else {}
    names = _provider_names()
    keys = [_public(k, names) for k in _db().relay_keys.find(q).sort("created_at", -1)]
    shared = [{"id": str(p["_id"]), "name": p.get("name", "")} for p in _db().smtp_providers.find({"owner": None}).sort("created_at", 1)]
    return {"keys": keys, "providers": shared, "submission": submission_info()}


@router.post("/admin/relay-keys", status_code=201)
def admin_create_key(body: dict = Body(...)):
    by = ext._clean_address(body.get("by")) or "admin"
    return _create(body.get("owner") or "", body, f"admin {by}" if by != "admin" else "admin", ADMIN_MAX_KEYS)


@router.patch("/admin/relay-keys/{key_id}")
def admin_update_key(key_id: str, body: dict = Body(...)):
    k = _key(key_id)
    updates = {}
    if "label" in body:
        updates["label"] = str(body.get("label") or "").strip()[:60] or k.get("label", "")
    if "hourly_limit" in body:
        v = body["hourly_limit"]
        if v not in (None, "") and (not isinstance(v, int) or not 1 <= v <= 100000):
            raise HTTPException(status_code=422, detail="The hourly limit must be a number from 1 to 100000")
        updates["hourly_limit"] = v or None
    if "provider_id" in body:
        pid = body.get("provider_id") or None
        if pid:
            acc = users_ext._account(k["owner"])
            if str(pid) not in {str(p["_id"]) for p in users_ext.allowed_providers(acc)}:
                raise HTTPException(status_code=422, detail="That SMTP provider is not available to this mailbox")
            pid = str(pid)
        updates["provider_id"] = pid
    if updates:
        _db().relay_keys.update_one({"_id": k["_id"]}, {"$set": updates})
    return _public(_db().relay_keys.find_one({"_id": k["_id"]}))


@router.post("/admin/relay-keys/{key_id}/revoke")
def admin_revoke_key(key_id: str, body: dict = Body(default={})):
    return _revoke(_key(key_id), ext._clean_address((body or {}).get("by")) or "admin")


@router.post("/admin/relay-keys/revoke-all")
def admin_revoke_all(body: dict = Body(...)):
    owner = ext._clean_address(body.get("owner"))
    if not owner:
        raise HTTPException(status_code=422, detail="Which mailbox?")
    by = ext._clean_address(body.get("by")) or "admin"
    n = 0
    for k in _db().relay_keys.find({"owner": owner, "revoked_at": None}):
        _revoke(k, by)
        n += 1
    return {"revoked": n}


@router.delete("/admin/relay-keys/{key_id}")
def admin_delete_key(key_id: str):
    k = _key(key_id)
    _db().relay_keys.delete_one({"_id": k["_id"]})
    security_ext.record("relay", "key_deleted", user=k["owner"], detail=k["username"], aggregate=False)
    return {"ok": True}


# ---- a user's own keys (self-service, when the admin allows it) ----

@router.get("/admin/users/{address}/relay-keys")
def user_keys(address: str):
    acc = users_ext._account(address)
    perms = users_ext.permissions_of(acc)
    names = _provider_names()
    keys = [_public(k, names) for k in _db().relay_keys.find({"owner": acc["address"], "kind": {"$nin": list(_NOT_KEYS)}}).sort("created_at", -1)]
    usable = [{"id": str(p["_id"]), "name": p.get("name", "")} for p in users_ext.allowed_providers(acc)] if perms["send"] else []
    active = sum(1 for k in keys if not k["revoked"])
    return {"keys": keys, "providers": usable, "can_create": perms["send"] and perms["smtp_keys"] and active < SELF_SERVICE_MAX_KEYS,
            "can_send": perms["send"], "self_service": perms["smtp_keys"], "max_keys": SELF_SERVICE_MAX_KEYS,
            "submission": submission_info()}


@router.post("/admin/users/{address}/relay-keys", status_code=201)
def user_create_key(address: str, body: dict = Body(...)):
    acc = users_ext._account(address)
    perms = users_ext.permissions_of(acc)
    if not perms["send"]:
        raise HTTPException(status_code=403, detail="Your admin has not allowed sending mail")
    if not perms["smtp_keys"]:
        raise HTTPException(status_code=403, detail="Your admin creates SMTP keys for you. Ask them for one.")
    body = {k: body.get(k) for k in ("label", "provider_id")}
    return _create(acc["address"], body, "self", SELF_SERVICE_MAX_KEYS)


@router.post("/admin/users/{address}/relay-keys/{key_id}/revoke")
def user_revoke_key(address: str, key_id: str):
    acc = users_ext._account(address)
    k = _key(key_id)
    if k["owner"] != acc["address"] or k.get("kind") in _NOT_KEYS:
        raise HTTPException(status_code=404, detail="Key not found")
    return _revoke(k, acc["address"])


# ---------------------------------------------------------------------------
# Checking a key and sending with it
# ---------------------------------------------------------------------------

_fail_lock = threading.Lock()
_auth_failures: dict = defaultdict(deque)
_sent_lock = threading.Lock()
_sent_times: dict = defaultdict(deque)


def _too_many_failures(ip: str) -> bool:
    now = time.time()
    with _fail_lock:
        q = _auth_failures[ip]
        while q and now - q[0] > _AUTH_FAIL_WINDOW:
            q.popleft()
        return len(q) >= _AUTH_FAIL_MAX


def _note_failure(ip: str):
    with _fail_lock:
        _auth_failures[ip].append(time.time())
        if len(_auth_failures) > 5000:
            _auth_failures.clear()


def authenticate(username: str, password: str, ip: str = "", via: str = "smtp") -> tuple[dict, dict]:
    """(key, mailbox) for a valid, unrevoked key whose mailbox may send. Raises RelayRefused otherwise."""
    if ip and _too_many_failures(ip):
        security_ext.record("relay", "auth_throttled", ip=ip, detail=via, aggregate=True)
        raise RelayTemporary("Too many failed sign-ins from your address. Try again later.")
    username = (username or "").strip().lower()[:320]
    if "@" in username:
        # Gmail-style: your email address + one of your app passwords
        wanted = _hash(normalize_app_password(password))
        k = _db().relay_keys.find_one({"owner": username, "kind": "app_password", "secret_hash": wanted})
        if not k:
            # Or the real mailbox password, unless app passwords are required. Raises when wrong.
            k = _mailbox_key(mailbox_password_login(username, password or "", ip=ip, via=via))
            wanted = k["secret_hash"]
    else:
        k = _db().relay_keys.find_one({"username": username, "kind": {"$nin": ["app_password", "mailbox_password"]}}) if username else None
        wanted = _hash(password or "")
    if not k or not hmac.compare_digest(k.get("secret_hash", ""), wanted):
        if ip:
            _note_failure(ip)
        security_ext.record("relay", "auth_failed", ip=ip, user=(k or {}).get("owner", ""), detail=f"{via}: user {username or '-'}", aggregate=True)
        raise RelayRefused("Wrong SMTP username or password")
    if k.get("revoked_at"):
        security_ext.record("relay", "revoked_key_used", ip=ip, user=k["owner"], detail=f"{via}: {username}", aggregate=True)
        raise RelayRefused({"app_password": "This app password was revoked. Make a new one under My account.",
                            "mailbox_password": "Sending with the mailbox password is turned off for this account. Use an app password."}
                           .get(k.get("kind"), "This key was revoked. Ask your admin for a new one."))
    acc = _db().accounts.find_one({"address": k["owner"]})
    if not acc or acc.get("is_active", True) is False:
        raise RelayRefused("The mailbox for this key is disabled")
    if not users_ext.permissions_of(acc)["send"]:
        raise RelayRefused("Your admin has not allowed sending mail")
    return k, acc


def check_sender(acc: dict, address: str) -> tuple:
    """(alias, domain_doc) when `address` is the key owner's mailbox or one of its aliases."""
    address = ext._clean_address(address)
    if not address or not ext.ADDRESS_RE.match(address):
        raise RelayRefused("The sender address is missing or not valid")
    try:
        owner, alias, dom = ext._resolve_sender(address)
    except HTTPException as exc:
        raise RelayRefused(str(exc.detail))
    if owner != acc["address"]:
        raise RelayRefused(f"This key can only send from {acc['address']} and its aliases")
    return alias, dom


def _choose_provider(k: dict, acc: dict, alias, dom) -> dict:
    if k.get("provider_id"):
        for p in users_ext.allowed_providers(acc):
            if str(p["_id"]) == k["provider_id"]:
                return p
        raise RelayRefused("The SMTP provider this key was set up for is no longer available. Ask your admin.")
    try:
        return users_ext.pick_provider_for(acc, alias, dom)
    except HTTPException as exc:
        raise RelayRefused(str(exc.detail))


def _take_rate(k: dict, count: int = 1):
    limit = k.get("hourly_limit") or RELAY_HOURLY_LIMIT
    now = time.time()
    with _sent_lock:
        q = _sent_times[str(k["_id"])]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) + count > limit:
            raise RelayTemporary(f"Hourly sending limit reached ({limit} messages per hour for this key)")
        for _ in range(count):
            q.append(now)


def _texts(msg) -> tuple[str, str]:
    text = html = ""
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            text = part.get_content() if isinstance(part.get_content(), str) else ""
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            html = part.get_content() if isinstance(part.get_content(), str) else ""
    except Exception:
        pass
    return text[:200000], html[:500000]


def deliver(k: dict, acc: dict, mail_from: str, rcpts: list, data: bytes, ip: str = "", via: str = "smtp") -> dict:
    """Send a complete message with a key. Checks the sender (envelope and From header), limits and provider,
    then relays through the real provider. Blocking: call it from a worker thread in async code."""
    if not rcpts:
        raise RelayRefused("No recipients")
    if len(rcpts) > RELAY_MAX_RCPTS:
        raise RelayRefused(f"At most {RELAY_MAX_RCPTS} recipients per message")
    for r in rcpts:
        if not ext.ADDRESS_RE.match((r or "").lower()):
            raise RelayRefused(f"'{r}' is not a valid email address")
    if len(data) > RELAY_MAX_MESSAGE_BYTES:
        raise RelayRefused("The message is too large")
    # A revoked key or a blocked user stops at once, even halfway through a mail-app session.
    fresh = _db().relay_keys.find_one({"_id": k["_id"]})
    if not fresh or fresh.get("revoked_at"):
        raise RelayRefused("This key was revoked. Ask your admin for a new one.")
    acc = _db().accounts.find_one({"address": acc["address"]}) or acc
    if acc.get("is_active", True) is False or not users_ext.permissions_of(acc)["send"]:
        raise RelayRefused("Your admin has not allowed sending mail")

    alias, dom = check_sender(acc, mail_from)
    msg = BytesParser(policy=policy.SMTP).parsebytes(data)
    from_headers = [a for _n, a in getaddresses(msg.get_all("From", []) or []) if a]
    if not from_headers:
        raise RelayRefused("The message has no From address")
    for addr in from_headers:
        check_sender(acc, addr)
    changed = False
    if msg.get_all("Bcc"):
        del msg["Bcc"]
        changed = True
    if not msg.get("Message-ID"):
        msg["Message-ID"] = make_msgid(domain=mail_from.split("@", 1)[1])
        changed = True
    if not msg.get("Date"):
        msg["Date"] = formatdate(localtime=False)
        changed = True
    if changed:
        data = msg.as_bytes()

    provider = _choose_provider(fresh, acc, alias, dom)
    _take_rate(fresh)
    if provider.get("sign_dkim"):
        data = ext._dkim_sign(data, ext.ensure_dkim(dom["domain"]))
    try:
        conn = ext._open_smtp(provider)
        try:
            conn.sendmail(mail_from, rcpts, data)
        finally:
            try:
                conn.quit()
            except Exception:
                pass
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
        security_ext.record("relay", "provider_refused", ip=ip, user=acc["address"], detail=f"{provider.get('name')}: {ext._smtp_error_text(exc)}"[:300], aggregate=True)
        raise RelayRefused(ext._smtp_error_text(exc))
    except Exception as exc:
        logger.error("Relay via %s failed: %s", provider.get("name"), exc)
        security_ext.record("relay", "provider_failed", ip=ip, user=acc["address"], detail=f"{provider.get('name')}: {ext._smtp_error_text(exc)}"[:300], aggregate=True)
        raise RelayTemporary("The outgoing mail provider is not reachable right now. Try again later.")

    subject = str(msg.get("Subject", ""))[:500]
    text, html = _texts(msg)
    message_id = str(msg.get("Message-ID", ""))
    db = _db()
    db.sent_messages.insert_one({
        "from_address": mail_from, "owner": acc["address"], "to": list(rcpts), "subject": subject,
        "text": text, "html": html, "resend_id": message_id, "provider": provider.get("name", ""),
        "via": f"key {fresh['username']}", "created_at": _now(),
    })
    db.relay_keys.update_one({"_id": fresh["_id"]}, {"$set": {"last_used_at": _now(), "last_ip": ip[:64]}, "$inc": {"sent_count": 1}})
    security_ext.record("relay", "sent", ip=ip, user=acc["address"],
                        detail=f"{via} key {fresh['username']} via {provider.get('name')} to {len(rcpts)} recipient(s)", aggregate=True)
    return {"message_id": message_id, "provider": provider.get("name", "")}


# ---------------------------------------------------------------------------
# App passwords: like Gmail's. Username = your email, password = a generated 16-letter code.
# One app password works for reading mail (IMAP, port 993) and sending (ports 587/465), so a mail app
# never needs the real mailbox password. Revoke one and only that app stops.
# ---------------------------------------------------------------------------

def _app_passwords_info(acc: dict) -> dict:
    names = _provider_names()
    items = [_public(k, names) for k in _db().relay_keys.find({"owner": acc["address"], "kind": "app_password"}).sort("created_at", -1)]
    return {"app_passwords": items, "only": bool(acc.get("app_passwords_only")), "required": app_passwords_required(),
            "max": MAX_APP_PASSWORDS, "submission": submission_info()}


@router.get("/admin/users/{address}/app-passwords")
def user_app_passwords(address: str):
    return _app_passwords_info(users_ext._account(address))


@router.post("/admin/users/{address}/app-passwords", status_code=201)
def user_create_app_password(address: str, body: dict = Body(default={})):
    acc = users_ext._account(address)
    db = _db()
    if db.relay_keys.count_documents({"owner": acc["address"], "kind": "app_password", "revoked_at": None}) >= MAX_APP_PASSWORDS:
        raise HTTPException(status_code=409, detail=f"You have {MAX_APP_PASSWORDS} app passwords. Revoke one you no longer use first.")
    label = str((body or {}).get("label") or "").strip()[:60] or "Mail app"
    by = ext._clean_address((body or {}).get("by")) or acc["address"]
    password = new_app_password()
    doc = {"owner": acc["address"], "kind": "app_password", "label": label, "username": "ap-" + secrets.token_hex(8),
           "secret_hash": _hash(normalize_app_password(password)), "hint": password[-4:], "provider_id": None,
           "hourly_limit": None, "created_at": _now(), "created_by": "self" if by == acc["address"] else f"admin {by}",
           "last_used_at": None, "last_ip": "", "sent_count": 0, "revoked_at": None}
    doc["_id"] = db.relay_keys.insert_one(doc).inserted_id
    security_ext.record("relay", "app_password_created", user=acc["address"], detail=f"{label} by {by}", aggregate=False)
    return {"app_password": _public(doc), "password": password, "username": acc["address"], "submission": submission_info()}


@router.post("/admin/users/{address}/app-passwords/{key_id}/revoke")
def user_revoke_app_password(address: str, key_id: str, body: dict = Body(default={})):
    acc = users_ext._account(address)
    k = _key(key_id)
    if k["owner"] != acc["address"] or k.get("kind") != "app_password":
        raise HTTPException(status_code=404, detail="App password not found")
    return _revoke(k, ext._clean_address((body or {}).get("by")) or acc["address"])


@router.post("/admin/users/{address}/app-passwords-only")
def user_app_passwords_only(address: str, body: dict = Body(...)):
    """When on, mail apps (IMAP 993, SMTP 587/465) only accept app passwords, never the real mailbox password.
    The web app still uses the real password (plus two-factor)."""
    acc = users_ext._account(address)
    only = bool(body.get("only"))
    _db().accounts.update_one({"_id": acc["_id"]}, {"$set": {"app_passwords_only": only}})
    return _app_passwords_info(_db().accounts.find_one({"_id": acc["_id"]}))


@router.post("/admin/auth/app-passwords-required")
def set_app_passwords_required(body: dict = Body(...)):
    required = bool(body.get("required"))
    _db().settings.update_one({"_id": "auth"}, {"$set": {"app_passwords_required": required}}, upsert=True)
    return {"required": required}


def _mailbox_key(acc: dict) -> dict:
    """Sending with the real mailbox password is tracked (and can be revoked) like a key of its own."""
    db = _db()
    db.relay_keys.update_one(
        {"owner": acc["address"], "kind": "mailbox_password"},
        {"$setOnInsert": {"owner": acc["address"], "kind": "mailbox_password", "label": "Mailbox password (mail apps)",
                          "username": "mb-" + secrets.token_hex(8), "secret_hash": "-", "hint": "", "provider_id": None,
                          "hourly_limit": None, "created_at": _now(), "created_by": "automatic", "last_used_at": None,
                          "last_ip": "", "sent_count": 0, "revoked_at": None}},
        upsert=True)
    return db.relay_keys.find_one({"owner": acc["address"], "kind": "mailbox_password"})


def mailbox_password_login(address: str, password: str, ip: str = "", via: str = "smtp") -> dict:
    """Mail apps may also sign in to 587/465 with the email + real mailbox password, unless app passwords
    are required (for this person or everyone). Returns the account or raises RelayRefused."""
    import bcrypt
    acc = _db().accounts.find_one({"address": address})
    if not acc or not password or not bcrypt.checkpw(password.encode()[:1024], acc.get("password_hash", "").encode()):
        if ip:
            _note_failure(ip)
        security_ext.record("relay", "auth_failed", ip=ip, user=address if acc else "", detail=f"{via}: user {address}", aggregate=True)
        raise RelayRefused("Wrong username or password")
    if acc.get("app_passwords_only") or app_passwords_required():
        security_ext.record("relay", "real_password_refused", ip=ip, user=address, detail=via, aggregate=True)
        raise RelayRefused("Use an app password (My account > App passwords), not your mailbox password")
    return acc


# ---- HTTP API (the web app forwards POST /api/v1/send here) ----

@router.post("/admin/relay/send")
def http_send(body: dict = Body(...)):
    ip = str(body.get("client_ip") or "")[:64]
    try:
        k, acc = authenticate(str(body.get("username") or ""), str(body.get("password") or ""), ip=ip, via="api")
        from_email = ext._clean_address(body.get("from_email") or body.get("from"))
        check_sender(acc, from_email)
        to, cc, bcc = ext._addr_list(body.get("to")), ext._addr_list(body.get("cc")), ext._addr_list(body.get("bcc"))
        subject = str(body.get("subject") or "").strip()
        text, html = str(body.get("text") or ""), str(body.get("html") or "")
        if not to:
            raise RelayRefused("Add at least one recipient in 'to'")
        if not subject:
            raise RelayRefused("Add a subject")
        if not text and not html:
            raise RelayRefused("The message body is empty (send 'text' and/or 'html')")
        alias = _db().aliases.find_one({"address": from_email}) or {}
        from_name = str(body.get("from_name") or alias.get("from_name") or "").strip()
        try:
            msg = ext._build_message(from_email, from_name, to, cc, subject, text, html,
                                     str(body.get("reply_to") or "").strip(), "", body.get("attachments"))
        except ValueError as exc:
            raise RelayRefused(f"Invalid header value: {exc}")
        result = deliver(k, acc, from_email, to + cc + bcc, msg.as_bytes(), ip=ip, via="api")
        return {"success": True, **result}
    except RelayRefused as exc:
        raise HTTPException(status_code=401 if "username or password" in str(exc) else 403, detail=str(exc))
    except RelayTemporary as exc:
        raise HTTPException(status_code=429 if "limit" in str(exc).lower() or "Too many" in str(exc) else 503, detail=str(exc))


# ---------------------------------------------------------------------------
# Submission server (ports 587 STARTTLS and 465 SSL/TLS), for mail apps
# ---------------------------------------------------------------------------

def _peer_ip(session) -> str:
    peer = getattr(session, "peer", None)
    return str(peer[0]) if isinstance(peer, (tuple, list)) and peer else ""


def make_authenticator(port: int):
    from aiosmtpd.smtp import AuthResult, LoginPassword

    def authenticator(server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        ip = _peer_ip(session)
        try:
            login = auth_data.login.decode("utf-8", "replace")
            password = auth_data.password.decode("utf-8", "replace")
            k, acc = authenticate(login, password, ip=ip, via=f"port {port}")
        except RelayTemporary as exc:
            return AuthResult(success=False, handled=False, message=f"454 4.7.0 {exc}")
        except RelayRefused as exc:
            return AuthResult(success=False, handled=False, message=f"535 5.7.8 {exc}")
        security_ext.record("relay", "login_ok", ip=ip, user=acc["address"], detail=f"port {port}, key {k['username']}", aggregate=True)
        return AuthResult(success=True, auth_data={"key_id": str(k["_id"]), "owner": acc["address"]})

    return authenticator


class SubmissionHandler:
    def __init__(self, port: int):
        self.port = port

    @staticmethod
    def _who(session):
        data = getattr(session, "auth_data", None)
        return data if isinstance(data, dict) else None

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        who = self._who(session)
        if not who:
            return "530 5.7.0 Authentication required"
        acc = _db().accounts.find_one({"address": who["owner"]})
        try:
            if not acc:
                raise RelayRefused("The mailbox for this key no longer exists")
            check_sender(acc, address)
        except RelayRefused as exc:
            security_ext.record("relay", "sender_refused", ip=_peer_ip(session), user=who["owner"], detail=f"MAIL FROM {address}"[:200], aggregate=True)
            return f"550 5.7.1 {exc}"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if len(envelope.rcpt_tos) >= RELAY_MAX_RCPTS:
            return f"452 4.5.3 At most {RELAY_MAX_RCPTS} recipients per message"
        if not ext.ADDRESS_RE.match((address or "").lower()):
            return "553 5.1.3 Not a valid address"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        who = self._who(session)
        if not who:
            return "530 5.7.0 Authentication required"
        ip = _peer_ip(session)
        try:
            k = _db().relay_keys.find_one({"_id": ObjectId(who["key_id"])})
            acc = _db().accounts.find_one({"address": who["owner"]})
            if not k or not acc:
                raise RelayRefused("This key no longer exists")
            data = envelope.original_content or envelope.content
            if isinstance(data, str):
                data = data.encode("utf-8", "replace")
            await asyncio.wait_for(asyncio.to_thread(deliver, k, acc, envelope.mail_from, list(envelope.rcpt_tos), data,
                                                     ip, f"port {self.port}"), timeout=120)
        except RelayRefused as exc:
            return f"550 5.7.1 {exc}"
        except RelayTemporary as exc:
            return f"451 4.7.1 {exc}"
        except asyncio.TimeoutError:
            return "451 4.4.2 The outgoing mail provider did not answer in time. Try again later."
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Submission failed: %s", exc, exc_info=True)
            return "451 4.3.0 Temporary error, try again later"
        return "250 2.0.0 Message sent"


def start_submission_servers(tls_cert: str, tls_key: str, hostname: str, is_blocked=None):
    """Start ports 587 (STARTTLS) and 465 (SSL/TLS). Both need the TLS certificate: without it, passwords
    would cross the internet unencrypted, so the servers stay off and Setup > APIs says why."""
    if not SUBMISSION_ENABLED:
        _state["submission"] = {"enabled": False, "ports": [], "reason": "turned off (SUBMISSION_ENABLED=0)"}
        return
    if not tls_cert or not tls_key or not os.path.exists(tls_cert) or not os.path.exists(tls_key):
        _state["submission"] = {"enabled": False, "ports": [],
                                "reason": "no TLS certificate found (mount your certificate like the IMAP server does)"}
        logger.warning("Submission ports 587/465 not started: no TLS certificate at %s", tls_cert or "(not set)")
        return
    import ssl

    from aiosmtpd.controller import Controller
    from aiosmtpd.smtp import SMTP

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(tls_cert, tls_key)
    except Exception as exc:
        _state["submission"] = {"enabled": False, "ports": [], "reason": f"the TLS certificate could not be loaded ({exc})"}
        logger.error("Submission ports not started: %s", exc)
        return

    class SubmissionSMTP(SMTP):
        def connection_made(self, transport):
            upgrade = self._original_transport is not None
            super().connection_made(transport)
            if upgrade:
                return
            ip = _peer_ip(self.session)
            if ip and is_blocked and is_blocked(ip):
                security_ext.record("relay", "blocked", ip=ip)
                transport.close()
                return
            if ip and not ip.startswith(("127.", "::1")):  # not the server's own start-up check
                security_ext.record("relay", "connect", ip=ip)

    class SubmissionController(Controller):
        def factory(self):
            return SubmissionSMTP(self.handler, **self.SMTP_kwargs)

    started = []
    for port, implicit in ((SUBMISSION_PORT, False), (SUBMISSIONS_PORT, True)):
        if not port:
            continue
        kwargs = dict(hostname="0.0.0.0", port=port, server_hostname=hostname, data_size_limit=RELAY_MAX_MESSAGE_BYTES,
                      authenticator=make_authenticator(port), auth_required=True)
        if implicit:
            # The whole connection is TLS from the first byte, so AUTH is safe without STARTTLS.
            kwargs.update(ssl_context=ctx, auth_require_tls=False)
        else:
            kwargs.update(tls_context=ctx, require_starttls=True, auth_require_tls=True)
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)  # "AUTH without TLS": port 465 is TLS already
                SubmissionController(SubmissionHandler(port), **kwargs).start()
            started.append(port)
        except Exception as exc:
            logger.error("Could not start submission port %s: %s", port, exc)
    _state["submission"] = {"enabled": bool(started), "ports": started,
                            "reason": "" if started else "the ports could not be opened (see the mail-service log)"}
    if started:
        logger.info("Submission for SMTP keys on ports %s", started)
