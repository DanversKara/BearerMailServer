"""
BearerMail multi-account mode.

Single mode (default, as before): one ACCESS_PASSWORD opens the web app with full rights.

Multi mode: every person signs in to the web app with their own mailbox address, that mailbox's
password (the same one their mail apps use) and optionally their own two-factor code. One or more
mailboxes are admins (full rights, the Setup screens). Everyone else only sees their own mailbox and
the aliases that deliver into it, and can only do what the admin allowed:

  send                 send mail at all
  smtp_providers       which shared SMTP providers they may send through: "all" or a list of ids
  own_smtp             add their own SMTP provider (private to them)
  aliases, max_aliases create disposable aliases for their own mailbox
  external_accounts    add their own Gmail/Outlook/... accounts under External accounts
  change_password      change their own mailbox password
  smtp_keys            create their own SMTP keys (Setup > APIs) for mail apps and scripts
  share_links          make public share links for Drive files and calendar events
  domains              extra domains they may use for aliases and share links (their mailbox's domain always)

The web app (mail-viewer) enforces what a signed-in user can reach; this module is the source of truth
for roles, permissions and per-user two-factor secrets. All endpoints need the admin API key.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timezone

import bcrypt
from bson import ObjectId
from fastapi import APIRouter, Body, Depends, HTTPException, Request

import bearer_ext as ext

_cfg = {"get_db": None, "require_api_key": None}


def configure(get_db, require_api_key):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


router = APIRouter(dependencies=[Depends(_auth)])

ROLES = ("admin", "user")
DEFAULT_PERMISSIONS = {
    "send": True,
    "smtp_providers": "all",
    "own_smtp": False,
    "aliases": True,
    "max_aliases": 20,
    "external_accounts": False,
    "change_password": True,
    "smtp_keys": True,
    "share_links": True,
    "domains": [],
}
ADMIN_PERMISSIONS = {**DEFAULT_PERMISSIONS, "own_smtp": True, "external_accounts": True, "max_aliases": 10000, "domains": "all"}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
    return dt


# ---------------------------------------------------------------------------
# Mode
# ---------------------------------------------------------------------------

def get_mode() -> str:
    doc = _db().settings.find_one({"_id": "auth"}) or {}
    return "multi" if doc.get("mode") == "multi" else "single"


def role_of(acc: dict) -> str:
    return acc.get("role") if acc.get("role") in ROLES else "user"


def permissions_of(acc: dict) -> dict:
    if role_of(acc) == "admin":
        return dict(ADMIN_PERMISSIONS)
    stored = acc.get("permissions") or {}
    out = {}
    for key, default in DEFAULT_PERMISSIONS.items():
        value = stored.get(key, default)
        if key == "smtp_providers":
            value = value if value == "all" or isinstance(value, list) else default
        elif key == "domains":
            value = [str(v) for v in value] if isinstance(value, list) else []
        elif key == "max_aliases":
            value = int(value) if isinstance(value, int) and value >= 0 else default
        else:
            value = bool(value)
        out[key] = value
    return out


def _clean_permissions(body: dict, current: dict) -> dict:
    out = dict(current)
    for key, default in DEFAULT_PERMISSIONS.items():
        if key not in body:
            continue
        value = body[key]
        if key == "smtp_providers":
            if value != "all":
                if not isinstance(value, list):
                    raise HTTPException(status_code=422, detail="smtp_providers must be 'all' or a list")
                shared = {str(p["_id"]) for p in _db().smtp_providers.find({"owner": None}, {"_id": 1})}
                value = [str(v) for v in value if str(v) in shared]
        elif key == "domains":
            if not isinstance(value, list):
                raise HTTPException(status_code=422, detail="domains must be a list")
            known = {d["domain"] for d in _db().domains.find({}, {"domain": 1})}
            value = sorted({str(v).strip().lower() for v in value if str(v).strip().lower() in known})
        elif key == "max_aliases":
            if not isinstance(value, int) or not 0 <= value <= 10000:
                raise HTTPException(status_code=422, detail="max_aliases must be a number from 0 to 10000")
        elif not isinstance(value, bool):
            raise HTTPException(status_code=422, detail=f"{key} must be true or false")
        out[key] = value
    return out


def _account(address: str) -> dict:
    acc = _db().accounts.find_one({"address": ext._clean_address(address)})
    if not acc:
        raise HTTPException(status_code=404, detail="No mailbox with that address")
    return acc


def allowed_domains(acc: dict) -> list:
    """Active domains this account may use for aliases and share links: its own mailbox's domain, plus the ones the
    admin granted. Admins: every active domain."""
    active = [d["domain"] for d in _db().domains.find({"is_active": True}, {"domain": 1}).sort("domain", 1)]
    perms = permissions_of(acc)
    if perms.get("domains") == "all":
        return active
    wanted = {acc["address"].split("@", 1)[1]} | set(perms.get("domains") or [])
    return [d for d in active if d in wanted]


def _addresses_for(address: str) -> list:
    aliases = [a["address"] for a in _db().aliases.find({"deliver_to": address}, {"address": 1}).sort("address", 1)]
    return [address] + aliases


def public_user(acc: dict, with_addresses: bool = False) -> dict:
    totp = acc.get("totp") or {}
    out = {
        "address": acc["address"],
        "display_name": acc.get("display_name", ""),
        "role": role_of(acc),
        "permissions": permissions_of(acc),
        "is_active": acc.get("is_active", True) is not False,
        "two_factor": bool(totp.get("enabled")),
        "app_passwords_only": bool(acc.get("app_passwords_only")),
        "quota_mb": acc.get("quota_mb") if isinstance(acc.get("quota_mb"), int) else None,
        "recovery_codes_left": len(totp.get("recovery", [])) if totp.get("enabled") else 0,
        "last_login": _iso(acc.get("last_login")),
        "created_at": _iso(acc.get("created_at")),
    }
    if with_addresses:
        out["addresses"] = _addresses_for(acc["address"])
        out["domains"] = allowed_domains(acc)
    return out


@router.get("/admin/auth/mode")
def read_mode():
    db = _db()
    auth = db.settings.find_one({"_id": "auth"}) or {}
    return {"mode": get_mode(), "admins": [a["address"] for a in db.accounts.find({"role": "admin"}, {"address": 1})],
            "app_passwords_required": bool(auth.get("app_passwords_required"))}


@router.post("/admin/auth/mode")
def set_mode(body: dict = Body(...)):
    """Switch between single-password and multi-account sign-in."""
    db = _db()
    mode = body.get("mode")
    if mode == "single":
        db.settings.update_one({"_id": "auth"}, {"$set": {"mode": "single", "changed_at": _now()}}, upsert=True)
        return {"mode": "single"}
    if mode != "multi":
        raise HTTPException(status_code=422, detail="mode must be 'single' or 'multi'")
    admin = ext._clean_address(body.get("admin"))
    acc = db.accounts.find_one({"address": admin, "is_active": {"$ne": False}})
    if not acc:
        raise HTTPException(status_code=422, detail="Choose an active mailbox to be the admin")
    updates = {"role": "admin", "updated_at": _now()}
    password = body.get("password")
    if password not in (None, ""):
        if not isinstance(password, str) or len(password) < 10:
            raise HTTPException(status_code=422, detail="The admin password must be at least 10 characters")
        updates["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.accounts.update_one({"_id": acc["_id"]}, {"$set": updates})
    db.settings.update_one({"_id": "auth"}, {"$set": {"mode": "multi", "changed_at": _now()}}, upsert=True)
    return {"mode": "multi", "admin": admin}


# ---------------------------------------------------------------------------
# Users (admin view)
# ---------------------------------------------------------------------------

@router.get("/admin/users")
def list_users():
    db = _db()
    out = []
    for acc in db.accounts.find({}).sort("address", 1):
        entry = public_user(acc)
        entry["aliases"] = db.aliases.count_documents({"deliver_to": acc["address"]})
        entry["own_smtp_providers"] = db.smtp_providers.count_documents({"owner": acc["address"]})
        out.append(entry)
    shared = [{"id": str(p["_id"]), "name": p.get("name", "")} for p in db.smtp_providers.find({"owner": None}).sort("created_at", 1)]
    auth = db.settings.find_one({"_id": "auth"}) or {}
    import drive_ext
    return {"users": out, "mode": get_mode(), "defaults": DEFAULT_PERMISSIONS, "shared_smtp_providers": shared,
            "default_quota_mb": drive_ext.DEFAULT_QUOTA_MB,
            "app_passwords_required": bool(auth.get("app_passwords_required"))}


@router.patch("/admin/users/{address}")
def update_user(address: str, body: dict = Body(...)):
    db = _db()
    acc = _account(address)
    updates = {"updated_at": _now()}
    if "role" in body:
        if body["role"] not in ROLES:
            raise HTTPException(status_code=422, detail="role must be 'admin' or 'user'")
        if role_of(acc) == "admin" and body["role"] != "admin" and get_mode() == "multi":
            if db.accounts.count_documents({"role": "admin", "is_active": {"$ne": False}}) <= 1:
                raise HTTPException(status_code=409, detail="This is the only admin. Make someone else admin first.")
        updates["role"] = body["role"]
    if isinstance(body.get("permissions"), dict):
        updates["permissions"] = _clean_permissions(body["permissions"], permissions_of({**acc, "role": "user"}))
    if "display_name" in body:
        updates["display_name"] = str(body.get("display_name") or "").strip()[:80]
    if "is_active" in body:
        if not body["is_active"] and role_of(acc) == "admin" and get_mode() == "multi" and \
                db.accounts.count_documents({"role": "admin", "is_active": {"$ne": False}}) <= 1:
            raise HTTPException(status_code=409, detail="You cannot disable the only admin")
        updates["is_active"] = bool(body["is_active"])
    if "quota_mb" in body:
        q = body["quota_mb"]
        if q is None or q == "":
            updates.pop("quota_mb", None)
            db.accounts.update_one({"_id": acc["_id"]}, {"$unset": {"quota_mb": ""}})
        elif not isinstance(q, int) or not 0 <= q <= 10_000_000:
            raise HTTPException(status_code=422, detail="The quota must be a number of MB (0 = unlimited)")
        else:
            updates["quota_mb"] = q
    if "app_passwords_only" in body:
        updates["app_passwords_only"] = bool(body["app_passwords_only"])
    if body.get("reset_two_factor"):
        updates["totp"] = {"enabled": False}
    db.accounts.update_one({"_id": acc["_id"]}, {"$set": updates})
    return public_user(db.accounts.find_one({"_id": acc["_id"]}))


# ---------------------------------------------------------------------------
# Sign-in (used by the web app)
# ---------------------------------------------------------------------------

_DUMMY_HASH = bcrypt.hashpw(b"timing-equaliser", bcrypt.gensalt()).decode()


@router.post("/admin/users/login")
def check_login(body: dict = Body(...)):
    address = ext._clean_address(body.get("address"))
    password = body.get("password") if isinstance(body.get("password"), str) else ""
    acc = _db().accounts.find_one({"address": address}) if address else None
    if not acc or not password:
        bcrypt.checkpw(b"x", _DUMMY_HASH.encode())
        raise HTTPException(status_code=401, detail="Wrong email or password")
    if not bcrypt.checkpw(password.encode()[:1024], acc["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Wrong email or password")
    if acc.get("is_active", True) is False:
        raise HTTPException(status_code=403, detail="This account is disabled")
    return public_user(acc, with_addresses=True)


@router.post("/admin/users/{address}/signed-in")
def mark_signed_in(address: str):
    _db().accounts.update_one({"address": ext._clean_address(address)}, {"$set": {"last_login": _now()}})
    return {"ok": True}


@router.get("/admin/users/{address}")
def get_user(address: str):
    acc = _account(address)
    user = public_user(acc, with_addresses=True)
    user["mode"] = get_mode()
    return user


@router.post("/admin/users/{address}/password")
def change_own_password(address: str, body: dict = Body(...)):
    """Self-service: needs the current password (unless reset by an admin, which uses /admin/accounts)."""
    acc = _account(address)
    if not permissions_of(acc)["change_password"]:
        raise HTTPException(status_code=403, detail="Your admin has not allowed changing the password here")
    current = body.get("current") if isinstance(body.get("current"), str) else ""
    new = body.get("new") if isinstance(body.get("new"), str) else ""
    if not bcrypt.checkpw(current.encode()[:1024], acc["password_hash"].encode()):
        raise HTTPException(status_code=403, detail="Your current password is not right")
    if len(new) < 10:
        raise HTTPException(status_code=422, detail="Choose a new password of at least 10 characters")
    if new == current:
        raise HTTPException(status_code=422, detail="The new password is the same as the old one")
    _db().accounts.update_one({"_id": acc["_id"]}, {"$set": {
        "password_hash": bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode(), "updated_at": _now()}})
    return {"ok": True, "message": "Password changed. Update it in Thunderbird and on your phone too."}


# ---------------------------------------------------------------------------
# Per-user two-factor (TOTP)
# ---------------------------------------------------------------------------

def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


def _totp_step(secret: str, code: str, at: float | None = None) -> int | None:
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    step = int((at if at is not None else time.time()) // 30)
    for delta in (-1, 0, 1):
        if hmac.compare_digest(_hotp(secret, step + delta), code):
            return step + delta
    return None


def _hash_code(code: str) -> str:
    return hashlib.sha256(("bearermail-recovery:" + code.replace("-", "").strip().lower()).encode()).hexdigest()


def _new_codes() -> tuple[list, list]:
    codes = []
    for _ in range(10):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [_hash_code(c) for c in codes]


@router.post("/admin/users/{address}/2fa/setup")
def totp_setup(address: str):
    acc = _account(address)
    if (acc.get("totp") or {}).get("enabled"):
        raise HTTPException(status_code=409, detail="Two-factor sign-in is already on")
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    _db().accounts.update_one({"_id": acc["_id"]}, {"$set": {"totp_pending_enc": ext.encrypt_secret(secret)}})
    return {"secret": secret}


@router.post("/admin/users/{address}/2fa/enable")
def totp_enable(address: str, body: dict = Body(...)):
    acc = _account(address)
    pending = acc.get("totp_pending_enc")
    if not pending:
        raise HTTPException(status_code=400, detail="Start the setup again")
    secret = ext.decrypt_secret(pending)
    step = _totp_step(secret, body.get("code", ""))
    if step is None:
        raise HTTPException(status_code=400, detail="That code is not right. Check the time on your phone and try the current code.")
    codes, hashes = _new_codes()
    _db().accounts.update_one({"_id": acc["_id"]}, {
        "$set": {"totp": {"enabled": True, "secret_enc": ext.encrypt_secret(secret), "recovery": hashes, "last_step": step}},
        "$unset": {"totp_pending_enc": ""}})
    return {"recovery_codes": codes}


@router.post("/admin/users/{address}/2fa/verify")
def totp_verify(address: str, body: dict = Body(...)):
    """Checks a 6-digit code or a recovery code. A code can only be used once."""
    acc = _account(address)
    totp = acc.get("totp") or {}
    if not totp.get("enabled"):
        return {"ok": True, "method": "none"}
    code = str(body.get("code", "")).strip()
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) == 6 and len(code.replace(" ", "")) == 6:
        step = _totp_step(ext.decrypt_secret(totp["secret_enc"]), digits)
        if step is not None:
            res = _db().accounts.update_one(
                {"_id": acc["_id"], "$or": [{"totp.last_step": {"$lt": step}}, {"totp.last_step": {"$exists": False}}]},
                {"$set": {"totp.last_step": step}})
            if res.modified_count:
                return {"ok": True, "method": "totp"}
        raise HTTPException(status_code=401, detail="That code is not right")
    wanted = _hash_code(code)
    for h in totp.get("recovery", []):
        if hmac.compare_digest(h, wanted):
            _db().accounts.update_one({"_id": acc["_id"]}, {"$pull": {"totp.recovery": h}})
            return {"ok": True, "method": "recovery", "left": len(totp["recovery"]) - 1}
    raise HTTPException(status_code=401, detail="That code is not right")


@router.post("/admin/users/{address}/2fa/disable")
def totp_disable(address: str):
    acc = _account(address)
    _db().accounts.update_one({"_id": acc["_id"]}, {"$set": {"totp": {"enabled": False}}, "$unset": {"totp_pending_enc": ""}})
    return {"ok": True}


@router.post("/admin/users/{address}/2fa/recovery-codes")
def totp_new_codes(address: str):
    acc = _account(address)
    if not (acc.get("totp") or {}).get("enabled"):
        raise HTTPException(status_code=400, detail="Turn on two-factor sign-in first")
    codes, hashes = _new_codes()
    _db().accounts.update_one({"_id": acc["_id"]}, {"$set": {"totp.recovery": hashes}})
    return {"recovery_codes": codes}


# ---------------------------------------------------------------------------
# A user's own aliases
# ---------------------------------------------------------------------------

def _own_alias(address: str, alias: str) -> dict:
    doc = _db().aliases.find_one({"address": ext._clean_address(alias)})
    if not doc or doc.get("deliver_to") != address:
        raise HTTPException(status_code=404, detail="Alias not found")
    return doc


@router.get("/admin/users/{address}/aliases")
def user_aliases(address: str):
    acc = _account(address)
    db = _db()
    items = [ext._format_alias(a, db.messages.count_documents({"to_addresses": a["address"]}))
             for a in db.aliases.find({"deliver_to": acc["address"]}).sort("created_at", -1)]
    domain = acc["address"].split("@", 1)[1]
    perms = permissions_of(acc)
    return {"aliases": items, "domain": domain, "domains": allowed_domains(acc) or [domain],
            "can_create": perms["aliases"] and len(items) < perms["max_aliases"],
            "max_aliases": perms["max_aliases"]}


@router.post("/admin/users/{address}/aliases", status_code=201)
def user_create_alias(address: str, body: dict = Body(...)):
    acc = _account(address)
    perms = permissions_of(acc)
    if not perms["aliases"]:
        raise HTTPException(status_code=403, detail="Your admin has not allowed creating aliases")
    if _db().aliases.count_documents({"deliver_to": acc["address"]}) >= perms["max_aliases"]:
        raise HTTPException(status_code=403, detail=f"You can have at most {perms['max_aliases']} aliases")
    domain = acc["address"].split("@", 1)[1]
    if body.get("domain"):
        domain = ext._clean_address(body.get("domain"))
        if domain not in allowed_domains(acc):
            raise HTTPException(status_code=403, detail="Your admin has not given you that domain")
    local = ext._clean_address(body.get("local"))
    payload = {
        "deliver_to": acc["address"],
        "random": bool(body.get("random")) or not local,
        "prefix": ext._clean_address(body.get("prefix")),
        "domain": domain,
        "address": f"{local}@{domain}" if local else "",
        "label": body.get("label", ""),
        "from_name": body.get("from_name", ""),
        "send_via": _allowed_provider_id(acc, body.get("send_via")),
    }
    return ext.create_alias(payload)


@router.patch("/admin/users/{address}/aliases/{alias}")
def user_update_alias(address: str, alias: str, body: dict = Body(...)):
    acc = _account(address)
    _own_alias(acc["address"], alias)
    allowed = {k: body[k] for k in ("label", "from_name", "enabled") if k in body}
    if "send_via" in body:
        allowed["send_via"] = _allowed_provider_id(acc, body["send_via"])
    return ext.update_alias(ext._clean_address(alias), allowed)


@router.delete("/admin/users/{address}/aliases/{alias}")
def user_delete_alias(address: str, alias: str):
    acc = _account(address)
    _own_alias(acc["address"], alias)
    return ext.delete_alias(ext._clean_address(alias))


# ---------------------------------------------------------------------------
# SMTP: which providers a user may send through, and their own providers
# ---------------------------------------------------------------------------

def allowed_providers(acc: dict) -> list:
    """Provider documents this account may send through (own first, then permitted shared ones)."""
    db = _db()
    perms = permissions_of(acc)
    out = []
    if perms["own_smtp"]:
        out += list(db.smtp_providers.find({"owner": acc["address"]}).sort("created_at", 1))
    shared = list(db.smtp_providers.find({"owner": None}).sort("created_at", 1))
    if perms["smtp_providers"] == "all":
        out += shared
    else:
        wanted = set(perms["smtp_providers"])
        out += [p for p in shared if str(p["_id"]) in wanted]
    return out


def _allowed_provider_id(acc: dict, value):
    if not value:
        return None
    ids = {str(p["_id"]) for p in allowed_providers(acc)}
    if str(value) not in ids:
        raise HTTPException(status_code=403, detail="You are not allowed to use that SMTP provider")
    return str(value)


def pick_provider_for(acc: dict, alias: dict | None, domain_doc: dict) -> dict:
    """The provider to send with on behalf of a non-admin user, or 403."""
    perms = permissions_of(acc)
    if not perms["send"]:
        raise HTTPException(status_code=403, detail="Your admin has not allowed sending mail")
    allowed = allowed_providers(acc)
    if not allowed:
        raise HTTPException(status_code=403, detail="No SMTP provider is available to you. Ask your admin.")
    by_id = {str(p["_id"]): p for p in allowed}
    for pid in ((alias or {}).get("send_via"), domain_doc.get("send_via")):
        if pid and pid in by_id:
            return by_id[pid]
    own = [p for p in allowed if p.get("owner") == acc["address"]]
    if own:
        return own[0]
    default = next((p for p in allowed if p.get("is_default")), None)
    return default or allowed[0]


@router.get("/admin/users/{address}/smtp-providers")
def user_providers(address: str):
    acc = _account(address)
    perms = permissions_of(acc)
    own = [ext._provider_public(p) for p in _db().smtp_providers.find({"owner": acc["address"]}).sort("created_at", 1)]
    usable = [{"id": str(p["_id"]), "name": p.get("name", ""), "own": p.get("owner") == acc["address"]}
              for p in allowed_providers(acc)]
    return {"own": own, "usable": usable, "can_add": perms["own_smtp"], "can_send": perms["send"]}


def _own_provider(acc: dict, provider_id: str) -> dict:
    try:
        p = _db().smtp_providers.find_one({"_id": ObjectId(provider_id), "owner": acc["address"]})
    except Exception:
        p = None
    if not p:
        raise HTTPException(status_code=404, detail="SMTP provider not found")
    return p


@router.post("/admin/users/{address}/smtp-providers", status_code=201)
def user_create_provider(address: str, body: dict = Body(...)):
    acc = _account(address)
    if not permissions_of(acc)["own_smtp"]:
        raise HTTPException(status_code=403, detail="Your admin has not allowed adding your own SMTP provider")
    db = _db()
    if db.smtp_providers.count_documents({"owner": acc["address"]}) >= 5:
        raise HTTPException(status_code=409, detail="You can add up to 5 providers")
    fields = ext._provider_fields(body)
    fields["password_enc"] = ext.encrypt_secret(body["password"]) if body.get("password") else ""
    fields.update(created_at=_now(), owner=acc["address"], is_default=False)
    fields.setdefault("sign_dkim", False)
    res = db.smtp_providers.insert_one(fields)
    return ext._provider_public(db.smtp_providers.find_one({"_id": res.inserted_id}))


@router.patch("/admin/users/{address}/smtp-providers/{provider_id}")
def user_update_provider(address: str, provider_id: str, body: dict = Body(...)):
    acc = _account(address)
    p = _own_provider(acc, provider_id)
    fields = ext._provider_fields(body, partial=True)
    if not body.get("password") and any(k in fields and fields[k] != p.get(k) for k in ("host", "port", "username")):
        raise HTTPException(status_code=422, detail="Re-enter the password when you change the server, port or username")
    if body.get("password"):
        fields["password_enc"] = ext.encrypt_secret(body["password"])
    if fields:
        _db().smtp_providers.update_one({"_id": p["_id"]}, {"$set": fields})
    return ext._provider_public(_db().smtp_providers.find_one({"_id": p["_id"]}))


@router.delete("/admin/users/{address}/smtp-providers/{provider_id}")
def user_delete_provider(address: str, provider_id: str):
    acc = _account(address)
    p = _own_provider(acc, provider_id)
    pid = str(p["_id"])
    _db().smtp_providers.delete_one({"_id": p["_id"]})
    _db().aliases.update_many({"send_via": pid}, {"$set": {"send_via": None}})
    return {"message": "Provider deleted"}


@router.post("/admin/users/{address}/smtp-providers/{provider_id}/test")
def user_test_provider(address: str, provider_id: str, body: dict = Body(default={})):
    acc = _account(address)
    p = _own_provider(acc, provider_id)
    return ext.run_provider_test(p, {**(body or {}), "from_email": acc["address"]})
