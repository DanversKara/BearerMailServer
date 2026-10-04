"""
BearerMail invite codes and public sign-up.

Admins create invite codes (single- or multi-use, optional expiry). Anyone with a
code can sign up at POST /signup (no API key): the code is validated and a mailbox
account is created exactly like POST /accounts does.

Mongo collection: db.invites
    {
        "code": "ABCDEFGHJKLMNPQR",   # normalized: uppercase, no dashes
        "created_at": datetime,
        "created_by": "api",
        "expires_at": datetime | None,
        "max_uses": int,
        "uses": int,
        "used_by": [addresses],
        "note": str,
        "revoked": bool,
    }
"""

import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, Body, Depends, HTTPException, Request

_cfg = {"get_db": None, "require_api_key": None, "check_rate_limit": None,
        "get_active_domains": None}


def configure(get_db, require_api_key, check_rate_limit=None, get_active_domains=None):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key
    _cfg["check_rate_limit"] = check_rate_limit
    _cfg["get_active_domains"] = get_active_domains


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


def init_indexes():
    _db().invites.create_index("code", unique=True)


router = APIRouter(dependencies=[Depends(_auth)])
public_router = APIRouter()

# Unambiguous alphabet (no 0/O, 1/I/l) so codes read fine over the phone.
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LEN = 16
# Local parts that must never become a mailbox through public sign-up.
_RESERVED_LOCALPARTS = {
    "admin", "administrator", "postmaster", "abuse", "mailer-daemon",
    "noreply", "no-reply", "support", "info", "contact", "help",
    "security", "webmaster", "hostmaster", "root",
}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
    return dt


def _new_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))


def format_code(code: str) -> str:
    """Human-friendly display: XXXX-XXXX-XXXX-XXXX."""
    code = normalize_code(code)
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def normalize_code(code) -> str:
    """Accept pasted codes with dashes/spaces/lowercase; store without dashes."""
    return "".join(ch for ch in str(code or "").upper() if ch in _CODE_ALPHABET)


def _active_domains() -> list:
    if _cfg["get_active_domains"]:
        return list(_cfg["get_active_domains"]())
    return [d["domain"] for d in _db().domains.find({"is_active": True}, {"domain": 1})]


def _public_invite(doc: dict) -> dict:
    now = _now()
    expires_at = doc.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            expires_at = None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    uses = int(doc.get("uses") or 0)
    max_uses = int(doc.get("max_uses") or 1)
    if doc.get("revoked"):
        status = "revoked"
    elif expires_at is not None and expires_at <= now:
        status = "expired"
    elif uses >= max_uses:
        status = "used up"
    else:
        status = "active"
    return {
        "code": format_code(doc["code"]),
        "note": doc.get("note") or "",
        "max_uses": max_uses,
        "uses": uses,
        "uses_left": max(0, max_uses - uses),
        "expires_at": _iso(expires_at),
        "status": status,
        "created_at": _iso(doc.get("created_at")),
        "used_by": list(doc.get("used_by") or []),
    }


def _get_invite_or_404(code: str) -> dict:
    normalized = normalize_code(code)
    if not normalized:
        raise HTTPException(status_code=404, detail="Invite code not found")
    doc = _db().invites.find_one({"code": normalized})
    if not doc:
        raise HTTPException(status_code=404, detail="Invite code not found")
    return doc


def _check_redeemable(doc: dict) -> None:
    """Raise 410 if the invite cannot be used right now."""
    if doc.get("revoked"):
        raise HTTPException(status_code=410, detail="This invite has been revoked")
    expires_at = doc.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            expires_at = None
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= _now():
            raise HTTPException(status_code=410, detail="This invite has expired")
    if int(doc.get("uses") or 0) >= int(doc.get("max_uses") or 1):
        raise HTTPException(status_code=410, detail="This invite has already been used")


# ---------------------------------------------------------------------------
# Sign-up mode: who may use POST /signup
#   invite  - an invite code is required (default)
#   open    - anyone may sign up, no code needed
#   closed  - the sign-up page and endpoint refuse everyone
# ---------------------------------------------------------------------------

SIGNUP_MODES = ("invite", "open", "closed")


def get_signup_mode() -> str:
    doc = _db().settings.find_one({"_id": "signup"}) or {}
    mode = doc.get("mode", "invite")
    return mode if mode in SIGNUP_MODES else "invite"


@router.get("/admin/signup/mode")
def read_signup_mode():
    return {"mode": get_signup_mode()}


@router.post("/admin/signup/mode")
def set_signup_mode(body: dict = Body(...)):
    mode = str(body.get("mode") or "")
    if mode not in SIGNUP_MODES:
        raise HTTPException(status_code=422, detail="mode must be one of: invite, open, closed")
    _db().settings.update_one({"_id": "signup"}, {"$set": {"mode": mode}}, upsert=True)
    return {"mode": mode}


@public_router.get("/signup/mode")
def public_signup_mode():
    """What the sign-up page shows: no auth needed."""
    return {"mode": get_signup_mode()}


# ---------------------------------------------------------------------------
# Admin: create / list / revoke
# ---------------------------------------------------------------------------

@router.post("/admin/invites", status_code=201)
def create_invite(body: dict = Body(...)):
    """Create an invite code. Body: {max_uses=1, expires_in_days=7 (null = never), note=""}."""
    db = _db()
    try:
        max_uses = int(body.get("max_uses", 1))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="max_uses must be a number")
    if not 1 <= max_uses <= 10000:
        raise HTTPException(status_code=422, detail="max_uses must be between 1 and 10000")
    expires_in_days = body.get("expires_in_days", 7)
    expires_at = None
    if expires_in_days is not None:
        try:
            days = float(expires_in_days)
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="expires_in_days must be a number or null")
        if days < 0 or days > 3650:
            raise HTTPException(status_code=422, detail="expires_in_days must be between 0 and 3650")
        expires_at = _now() + timedelta(days=days)
    note = str(body.get("note") or "")[:200]

    for _ in range(5):  # code collision is ~impossible, but retry anyway
        code = _new_code()
        try:
            db.invites.insert_one({
                "code": code,
                "created_at": _now(),
                "created_by": "api",
                "expires_at": expires_at,
                "max_uses": max_uses,
                "uses": 0,
                "used_by": [],
                "note": note,
                "revoked": False,
            })
            break
        except Exception as exc:
            if "duplicate" not in str(exc).lower():
                raise
    else:
        raise HTTPException(status_code=500, detail="Could not generate a unique invite code")

    doc = db.invites.find_one({"code": code})
    return _public_invite(doc)


@router.get("/admin/invites")
def list_invites():
    docs = list(_db().invites.find().sort("created_at", -1).limit(500))
    return {"invites": [_public_invite(d) for d in docs]}


@router.delete("/admin/invites/{code}")
def revoke_invite(code: str):
    doc = _get_invite_or_404(code)
    _db().invites.update_one({"_id": doc["_id"]}, {"$set": {"revoked": True}})
    return {"ok": True, "code": format_code(doc["code"])}


# ---------------------------------------------------------------------------
# Public: redeem an invite to create a mailbox
# ---------------------------------------------------------------------------

@public_router.post("/signup", status_code=201)
async def signup(request: Request):
    """Create a mailbox account. Needs an invite code unless the admin opened sign-up."""
    if _cfg["check_rate_limit"]:
        _cfg["check_rate_limit"](request.client.host if request.client else "unknown")
    try:
        data = await request.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}

    mode = get_signup_mode()
    if mode == "closed":
        raise HTTPException(status_code=403, detail="Sign-ups are disabled")

    code = normalize_code(data.get("code"))
    address = str(data.get("address") or "").strip().lower()
    password = str(data.get("password") or "")

    if not address or not password:
        raise HTTPException(status_code=422, detail="Email address and password are required")
    if len(password) < 10:
        raise HTTPException(status_code=422, detail="Choose a password of at least 10 characters")
    if "@" not in address or address.startswith("@") or address.endswith("@"):
        raise HTTPException(status_code=422, detail="Enter a valid email address")

    db = _db()
    invite = None
    if mode == "invite":
        if not code:
            raise HTTPException(status_code=422, detail="An invite code is required")
        invite = db.invites.find_one({"code": code})
        if not invite:
            raise HTTPException(status_code=404, detail="Invite code not found")
        _check_redeemable(invite)

    domain = address.split("@", 1)[1]
    if domain not in _active_domains():
        raise HTTPException(status_code=422, detail=f"Domain '{domain}' is not available")
    localpart = address.split("@", 1)[0]
    if localpart in _RESERVED_LOCALPARTS:
        raise HTTPException(status_code=422, detail="That address is reserved")
    if db.accounts.find_one({"address": address}) or db.aliases.find_one({"address": address}):
        raise HTTPException(status_code=422, detail="This address is already used")

    # Claim one use atomically so a multi-tab double-submit cannot overshoot max_uses.
    # (Open sign-up skips invites entirely.)
    if invite is not None:
        claimed = db.invites.find_one_and_update(
            {"_id": invite["_id"], "revoked": {"$ne": True},
             "$expr": {"$lt": ["$uses", "$max_uses"]}},
            {"$inc": {"uses": 1}, "$push": {"used_by": address}},
        )
        if not claimed:
            raise HTTPException(status_code=410, detail="This invite has already been used")

    now = _now()
    password_hash = bcrypt.hashpw(password.encode()[:1024], bcrypt.gensalt()).decode()
    try:
        result = db.accounts.insert_one({
            "address": address,
            "password_hash": password_hash,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        })
    except Exception:
        if invite is not None:
            # Roll the claimed use back: the address insert failed (e.g. raced another signup).
            db.invites.update_one({"_id": invite["_id"]},
                                  {"$inc": {"uses": -1}, "$pull": {"used_by": address}})
        raise HTTPException(status_code=422, detail="This address is already used")

    return {
        "id": str(result.inserted_id),
        "address": address,
        "isActive": True,
        "createdAt": now.isoformat(),
    }
