"""
BearerMail mail service - DuckMail API compatible
SMTP receiver (aiosmtpd, port 25) + REST API (FastAPI, port 8080)
"""

import asyncio
import ipaddress
import os
import re
import time
import hmac
import logging
import threading
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import quote

import jwt
import bcrypt
import uvicorn
from bson import ObjectId
from pymongo import MongoClient, DESCENDING
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP

import bearer_ext
import calendar_ext
import ddns_ext
import dmarc_ext
import drive_ext
import mail_auth
import relay_ext
import security_ext
import tabs_ext
import users_ext

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MONGO_URL = os.getenv("MONGO_URL", "mongodb://mongodb:27017")
DB_NAME = os.getenv("DB_NAME", "mailserver")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-in-production")
API_KEY = os.getenv("API_KEY", "")
SMTP_HOSTNAME = os.getenv("SMTP_HOSTNAME", "mail.example.com")
SERVER_IP = os.getenv("SERVER_IP", "").strip()
IMAP_HOSTNAME = os.getenv("IMAP_HOSTNAME", "").strip()
SECRETS_KEY = os.getenv("SECRETS_KEY", "").strip()
# Public self-service sign-up is off by default: creating mailboxes needs the API key.
ALLOW_PUBLIC_REGISTRATION = os.getenv("ALLOW_PUBLIC_REGISTRATION", "0").strip().lower() in {"1", "true", "yes", "on"}
_RESERVED_LOCALPARTS = {"postmaster", "abuse", "hostmaster", "webmaster", "root", "mailer-daemon", "noc", "security"}
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
# Domains from the environment are only seed data; the real list lives in MongoDB
# Example values copied from .env.example must never become real domains.
_PLACEHOLDER_DOMAINS = {"yourdomain.com", "example.com", "example.org", "mail.yourdomain.com", "your-domain.com"}
_SEED_DOMAINS = [d.strip().lower() for d in os.getenv("DOMAINS", "").split(",") if d.strip()]
_IGNORED_PLACEHOLDERS = [d for d in _SEED_DOMAINS if d in _PLACEHOLDER_DOMAINS]
_SEED_DOMAINS = [d for d in _SEED_DOMAINS if d not in _PLACEHOLDER_DOMAINS]
API_PORT = int(os.getenv("API_PORT", "8080"))
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_TLS_CERT = os.getenv("SMTP_TLS_CERT", "")  # path to TLS certificate (PEM)
SMTP_TLS_KEY = os.getenv("SMTP_TLS_KEY", "")    # path to TLS private key (PEM)
# Ports 587/465 (SMTP keys) always need TLS; by default they use the same certificate as the IMAP server
# (IMAP_TLS_CERT/KEY from .env, e.g. /certs/live/<host>/fullchain.pem when setup.sh got a Let's Encrypt certificate).
SUBMISSION_TLS_CERT = (os.getenv("SUBMISSION_TLS_CERT", "").strip() or SMTP_TLS_CERT
                       or os.getenv("IMAP_TLS_CERT", "").strip() or "/certs/fullchain.pem")
SUBMISSION_TLS_KEY = (os.getenv("SUBMISSION_TLS_KEY", "").strip() or SMTP_TLS_KEY
                      or os.getenv("IMAP_TLS_KEY", "").strip() or "/certs/privkey.pem")


def _parse_message_ttl_days(value: str) -> int | None:
    normalized = value.strip().lower()
    if normalized in {"0", "none", "never", "infinite", "forever", "off", "disabled"}:
        return None
    try:
        days = int(normalized)
    except ValueError as exc:
        raise RuntimeError(
            "MESSAGE_TTL_DAYS must be a positive integer, or 0/forever to disable cleanup"
        ) from exc
    return days if days > 0 else None


MESSAGE_TTL_DAYS = _parse_message_ttl_days(os.getenv("MESSAGE_TTL_DAYS", "0"))


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


IS_PRODUCTION = ENVIRONMENT == "production"
ENABLE_API_DOCS = _env_flag("ENABLE_API_DOCS", default=not IS_PRODUCTION)
EXPOSE_HEALTH_DETAILS = _env_flag("EXPOSE_HEALTH_DETAILS", default=not IS_PRODUCTION)
_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if not _CORS_ORIGINS and not IS_PRODUCTION:
    _CORS_ORIGINS = ["*"]


def _require_production_value(name: str, value: str, disallowed: set[str] | None = None):
    if not IS_PRODUCTION:
        return
    disallowed = disallowed or set()
    normalized = (value or "").strip()
    if not normalized or normalized in disallowed:
        raise RuntimeError(f"{name} must be configured for production")

# ---------------------------------------------------------------------------
# Rate Limiting (simple in-memory limiter)
# ---------------------------------------------------------------------------

_rate_limit_store: dict = defaultdict(list)
_RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
_RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "60"))  # max requests per IP per window
_SMTP_RCPT_RATE_WINDOW = int(os.getenv("SMTP_RCPT_RATE_WINDOW", "60"))
_SMTP_RCPT_RATE_MAX = int(os.getenv("SMTP_RCPT_RATE_MAX", "100"))
_SMTP_DATA_RATE_WINDOW = int(os.getenv("SMTP_DATA_RATE_WINDOW", "60"))
_SMTP_DATA_RATE_MAX = int(os.getenv("SMTP_DATA_RATE_MAX", "20"))
_SMTP_MAX_RCPTS_PER_MESSAGE = int(os.getenv("SMTP_MAX_RCPTS_PER_MESSAGE", "20"))
# Largest incoming email. Stored as one MongoDB document (16 MB cap), and attachments shrink by ~25 % when
# decoded from base64, so 20 MB raw stays safely under it while fitting ordinary photos and PDFs.
_SMTP_MAX_MESSAGE_BYTES = min(int(os.getenv("SMTP_MAX_MESSAGE_BYTES", str(20 * 1024 * 1024))), 20 * 1024 * 1024)
_SMTP_MAX_ADDRESS_LENGTH = int(os.getenv("SMTP_MAX_ADDRESS_LENGTH", "320"))
_SMTP_BLACKLIST_IPS = {item.strip() for item in os.getenv("SMTP_BLACKLIST_IPS", "").split(",") if item.strip()}
_SMTP_BLACKLIST_SENDERS = {item.strip().lower() for item in os.getenv("SMTP_BLACKLIST_SENDERS", "").split(",") if item.strip()}
_SMTP_GREYLIST_ENABLED = _env_flag("SMTP_GREYLIST_ENABLED", default=False)
_SMTP_GREYLIST_DELAY_SECONDS = int(os.getenv("SMTP_GREYLIST_DELAY_SECONDS", "60"))
_SMTP_GREYLIST_TTL_SECONDS = int(os.getenv("SMTP_GREYLIST_TTL_SECONDS", "3600"))
# Sender checks (SPF / DKIM / DMARC) on incoming mail. On by default; the result is shown in the web app.
_CHECK_SENDER_AUTH = os.getenv("CHECK_SENDER_AUTH", "1").strip().lower() in {"1", "true", "yes", "on"}
# Refuse mail that fails DMARC when the sender's domain asks for that (p=reject). Off by default: warn only.
_SMTP_ENFORCE_DMARC_REJECT = os.getenv("SMTP_ENFORCE_DMARC_REJECT", "0").strip().lower() in {"1", "true", "yes", "on"}
_smtp_rcpt_rate_store: dict = defaultdict(list)
_smtp_data_rate_store: dict = defaultdict(list)
_smtp_greylist_store: dict = {}
_smtp_limit_lock = threading.Lock()

_require_production_value("JWT_SECRET", JWT_SECRET, {"change-this-in-production"})
if JWT_SECRET == "change-this-in-production" and os.getenv("ALLOW_INSECURE_DEFAULTS", "0") != "1":
    raise RuntimeError("JWT_SECRET is the public default. Set a long random JWT_SECRET (run ./setup.sh).")
_require_production_value("API_KEY", API_KEY)
if IS_PRODUCTION and not _CORS_ORIGINS:
    raise RuntimeError("CORS_ORIGINS must be configured for production")


def _is_internal_client(client_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(client_ip)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _check_rate_limit(client_ip: str):
    """Simple in-memory rate limit; skips container/internal sources so the shared proxy IP is not punished"""
    if _RATE_LIMIT_MAX <= 0 or _is_internal_client(client_ip):
        return
    now = time.time()
    _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < _RATE_LIMIT_WINDOW]
    if len(_rate_limit_store[client_ip]) >= _RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests, please try again later")
    _rate_limit_store[client_ip].append(now)


def _get_smtp_client_ip(session) -> str:
    peer = getattr(session, "peer", None)
    if isinstance(peer, (tuple, list)) and peer:
        return str(peer[0])
    return ""


def _prune_rate_bucket(store: dict, key: str, window_seconds: int, now: float | None = None) -> list:
    now = now or time.time()
    store[key] = [t for t in store[key] if now - t < window_seconds]
    return store[key]


def _check_smtp_rcpt_limit(client_ip: str, current_rcpt_count: int) -> str | None:
    if not client_ip or _is_internal_client(client_ip):
        return None
    if _SMTP_MAX_RCPTS_PER_MESSAGE > 0 and current_rcpt_count >= _SMTP_MAX_RCPTS_PER_MESSAGE:
        return "452 4.5.3 Too many recipients"
    if _SMTP_RCPT_RATE_MAX <= 0:
        return None
    now = time.time()
    with _smtp_limit_lock:
        bucket = _prune_rate_bucket(_smtp_rcpt_rate_store, client_ip, _SMTP_RCPT_RATE_WINDOW, now)
        if len(bucket) >= _SMTP_RCPT_RATE_MAX:
            return "421 4.7.0 Too many recipient commands, try again later"
        bucket.append(now)
    return None


def _check_smtp_data_limit(client_ip: str) -> str | None:
    if not client_ip or _is_internal_client(client_ip) or _SMTP_DATA_RATE_MAX <= 0:
        return None
    now = time.time()
    with _smtp_limit_lock:
        bucket = _prune_rate_bucket(_smtp_data_rate_store, client_ip, _SMTP_DATA_RATE_WINDOW, now)
        if len(bucket) >= _SMTP_DATA_RATE_MAX:
            return "421 4.7.0 Too many messages, try again later"
        bucket.append(now)
    return None


def _is_blacklisted_sender(address: str) -> bool:
    sender = (address or "").strip().lower()
    if not sender:
        return False
    if sender in _SMTP_BLACKLIST_SENDERS:
        return True
    domain = sender.split("@", 1)[1] if "@" in sender else sender
    return domain in _SMTP_BLACKLIST_SENDERS


def _check_smtp_blacklist(client_ip: str, mail_from: str) -> str | None:
    if client_ip and client_ip in _SMTP_BLACKLIST_IPS:
        return "554 5.7.1 Client blocked"
    if _is_blacklisted_sender(mail_from):
        return "554 5.7.1 Sender blocked"
    return None


def _check_smtp_greylist(client_ip: str, mail_from: str, rcpt_to: str) -> str | None:
    if not _SMTP_GREYLIST_ENABLED or not client_ip or _is_internal_client(client_ip):
        return None
    sender = (mail_from or "").strip().lower()
    recipient = (rcpt_to or "").strip().lower()
    if not sender or not recipient:
        return None
    now = time.time()
    key = (client_ip, sender, recipient)
    with _smtp_limit_lock:
        expired_keys = [k for k, meta in _smtp_greylist_store.items() if now - meta["first_seen"] > _SMTP_GREYLIST_TTL_SECONDS]
        for expired in expired_keys:
            _smtp_greylist_store.pop(expired, None)
        meta = _smtp_greylist_store.get(key)
        if meta is None:
            _smtp_greylist_store[key] = {"first_seen": now}
            return "451 4.7.1 Greylisted, please retry later"
        if now - meta["first_seen"] < _SMTP_GREYLIST_DELAY_SECONDS:
            return "451 4.7.1 Greylisted, please retry later"
    return None

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("mail-service")

# ---------------------------------------------------------------------------
# MongoDB (pymongo, thread-safe)
# ---------------------------------------------------------------------------

mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
db = mongo_client[DB_NAME]


def init_db():
    """Create indexes and import seed domains"""
    if JWT_SECRET == "change-this-in-production":
        logger.warning("⚠️ JWT_SECRET is using default value! Change it in production!")
    db.accounts.create_index("address", unique=True)
    db.messages.create_index("to_addresses")
    db.messages.create_index([("created_at", DESCENDING)])
    ttl_index = db.messages.index_information().get("ttl_cleanup")
    if MESSAGE_TTL_DAYS is None:
        if ttl_index:
            db.messages.drop_index("ttl_cleanup")
    else:
        expire_after_seconds = MESSAGE_TTL_DAYS * 86400
        if ttl_index and ttl_index.get("expireAfterSeconds") != expire_after_seconds:
            db.messages.drop_index("ttl_cleanup")
        db.messages.create_index(
            "created_at", expireAfterSeconds=expire_after_seconds, name="ttl_cleanup"
        )
    # sent messages collection indexes
    db.sent_messages.create_index("from_address")
    db.sent_messages.create_index([("created_at", DESCENDING)])
    # domains collection index
    db.domains.create_index("domain", unique=True)
    # Import domains from the environment as seed data (idempotent)
    for d in _SEED_DOMAINS:
        db.domains.update_one(
            {"domain": d},
            {"$setOnInsert": {
                "domain": d,
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
            }},
            upsert=True,
        )
    bearer_ext.init_indexes()
    security_ext.init_indexes()
    relay_ext.init_indexes()
    drive_ext.init_indexes()
    dmarc_ext.init_indexes()
    calendar_ext.init_indexes()
    ttl_label = "disabled" if MESSAGE_TTL_DAYS is None else f"{MESSAGE_TTL_DAYS} days"
    logger.info(f"MongoDB indexes created, message TTL = {ttl_label}")
    logger.info(f"Seed domains imported: {_SEED_DOMAINS}")
    if _IGNORED_PLACEHOLDERS:
        logger.warning(f"DOMAINS contains placeholder value(s) {_IGNORED_PLACEHOLDERS}; ignored. Set your real domain in .env or add it on the Setup screen.")
    if SMTP_HOSTNAME.lower() in _PLACEHOLDER_DOMAINS or SMTP_HOSTNAME.lower().endswith((".yourdomain.com", ".example.com")):
        logger.warning(f"SMTP_HOSTNAME is still a placeholder ({SMTP_HOSTNAME}). Set it to your real mail hostname in .env.")


# ---------------------------------------------------------------------------
# Dynamic Domain Management (cached)
# ---------------------------------------------------------------------------

_domains_cache: list = []
_domains_cache_ts: float = 0
_domains_cache_lock = threading.Lock()
_DOMAINS_CACHE_TTL = 30  # cache for 30 seconds


def get_active_domains() -> list:
    """Get the active domain list from MongoDB (in-memory cache to avoid frequent queries)"""
    global _domains_cache, _domains_cache_ts
    now = time.time()
    if now - _domains_cache_ts < _DOMAINS_CACHE_TTL and _domains_cache:
        return _domains_cache
    with _domains_cache_lock:
        # double-check
        if now - _domains_cache_ts < _DOMAINS_CACHE_TTL and _domains_cache:
            return _domains_cache
        try:
            docs = db.domains.find({"is_active": True})
            _domains_cache = [doc["domain"] for doc in docs]
            _domains_cache_ts = time.time()
        except Exception as e:
            logger.error(f"Failed to load domains from DB: {e}")
            # fall back to seed domains
            if not _domains_cache:
                _domains_cache = list(_SEED_DOMAINS)
    return _domains_cache


def _invalidate_domains_cache():
    """Clear the domain cache so the next call re-reads from the DB"""
    global _domains_cache_ts
    _domains_cache_ts = 0


# ---------------------------------------------------------------------------
# JWT Helpers
# ---------------------------------------------------------------------------

def create_token(account_id: str, address: str, alias: str | None = None) -> str:
    payload = {
        "account_id": account_id,
        "address": address,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    if alias:
        payload["alias"] = alias
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _addr_match(account: dict):
    """Mongo match for the account's inbox; narrowed to one alias when the token carries one."""
    address = account["address"]
    alias = account.get("alias")
    return {"$all": [address, alias]} if alias else address


async def get_current_account(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    claims = decode_token(auth[7:])
    # A token stops working as soon as its mailbox is deleted or disabled.
    if not db.accounts.find_one({"address": claims.get("address"), "is_active": {"$ne": False}}, {"_id": 1}):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return claims


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    init_db()
    start_smtp_server()
    relay_ext.start_submission_servers(SUBMISSION_TLS_CERT, SUBMISSION_TLS_KEY, IMAP_HOSTNAME or SMTP_HOSTNAME,
                                       is_blocked=security_ext.is_blocked)
    ddns_task = asyncio.create_task(ddns_ext.loop())
    logger.info(f"API server ready on port {API_PORT}")
    yield
    ddns_task.cancel()


app = FastAPI(
    title="Self-Hosted Mail API",
    docs_url="/api-docs" if ENABLE_API_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- Health Check ----

@app.get("/health")
async def health():
    payload = {"status": "ok"}
    if EXPOSE_HEALTH_DETAILS:
        payload["domains"] = get_active_domains()
    return payload


# ---- Domains ----

@app.get("/domains")
async def list_domains(request: Request):
    """List available domains"""
    active_domains = get_active_domains()
    domain_list = [
        {
            "@id": f"/domains/{d}",
            "@type": "Domain",
            "domain": d,
            "isActive": True,
            "isPrivate": False,
        }
        for d in active_domains
    ]
    return {"hydra:member": domain_list}


async def _json_body(request: Request) -> dict:
    """Parse a JSON object body; anything else is a 422, never a crash."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Body must be a JSON object")
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Body must be a JSON object")
    return data


def _text(value, default: str = "") -> str:
    """Only real strings are accepted from request bodies. Objects such as {"$gt": ""} become the default,
    so they can never reach a database query."""
    return value if isinstance(value, str) else default


# ---- Accounts ----

@app.post("/accounts")
async def create_account(request: Request):
    """Create a mailbox account (DuckMail API compatible). Needs the API key unless ALLOW_PUBLIC_REGISTRATION=1."""
    if not ALLOW_PUBLIC_REGISTRATION:
        _require_api_key(request)
    _check_rate_limit(request.client.host)
    data = await _json_body(request)
    address = _text(data.get("address")).strip().lower()
    password = _text(data.get("password"))

    if not address or not password:
        raise HTTPException(
            status_code=422,
            detail={"hydra:description": "Address and password are required"},
        )

    if "@" not in address:
        raise HTTPException(
            status_code=422,
            detail={"hydra:description": "Invalid email address format"},
        )

    domain = address.split("@", 1)[1]
    if domain not in get_active_domains():
        raise HTTPException(
            status_code=422,
            detail={"hydra:description": f"Domain '{domain}' is not available"},
        )

    if db.aliases.find_one({"address": address}) or (
        ALLOW_PUBLIC_REGISTRATION and address.split("@", 1)[0] in _RESERVED_LOCALPARTS
    ):
        raise HTTPException(
            status_code=422,
            detail={"hydra:description": "This address is already used."},
        )

    # check whether it already exists
    if db.accounts.find_one({"address": address}):
        raise HTTPException(
            status_code=422,
            detail={
                "hydra:description": "This address is already used.",
                "violations": [{"message": "This address is already used."}],
            },
        )

    now = datetime.now(timezone.utc)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    result = db.accounts.insert_one(
        {
            "address": address,
            "password_hash": password_hash,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }
    )

    logger.info(f"Account created: {address}")
    return JSONResponse(
        status_code=201,
        content={
            "id": str(result.inserted_id),
            "address": address,
            "isActive": True,
            "isSilenced": False,
            "createdAt": now.isoformat(),
            "updatedAt": now.isoformat(),
        },
    )


# ---- Token (Login) ----

@app.post("/token")
async def login(request: Request):
    """Sign in and get a JWT token (DuckMail API compatible)"""
    _check_rate_limit(request.client.host)
    data = await _json_body(request)
    address = _text(data.get("address")).strip().lower()
    password = _text(data.get("password"))

    account = db.accounts.find_one({"address": address, "is_active": {"$ne": False}})
    if not account:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not bcrypt.checkpw(password.encode(), account["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(str(account["_id"]), account["address"])
    return {"token": token}


# ---- Admin: Domain Management (API key auth) ----

def _require_api_key(request: Request):
    """Verify the API key (for admin endpoints)"""
    auth = request.headers.get("Authorization", "")
    key = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer ") else ""
    if not key:
        key = request.headers.get("X-API-Key", "").strip()
    if not API_KEY or not hmac.compare_digest(key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


bearer_ext.configure(
    get_db=lambda: db,
    require_api_key=_require_api_key,
    invalidate_domains=lambda: _invalidate_domains_cache(),
    create_token=create_token,
    smtp_hostname=SMTP_HOSTNAME,
    secret=SECRETS_KEY or JWT_SECRET,
    server_ip=SERVER_IP,
    imap_hostname=IMAP_HOSTNAME,
)
security_ext.configure(get_db=lambda: db, require_api_key=_require_api_key, send_mail=bearer_ext.send_system_mail)
users_ext.configure(get_db=lambda: db, require_api_key=_require_api_key)
relay_ext.configure(get_db=lambda: db, require_api_key=_require_api_key, hostname=IMAP_HOSTNAME or SMTP_HOSTNAME)
drive_ext.configure(get_db=lambda: db, require_api_key=_require_api_key)
dmarc_ext.configure(get_db=lambda: db, require_api_key=_require_api_key, server_ip=SERVER_IP)
calendar_ext.configure(get_db=lambda: db, require_api_key=_require_api_key, hostname=SMTP_HOSTNAME)
ddns_ext.configure(get_db=lambda: db, require_api_key=_require_api_key, env_server_ip=SERVER_IP,
                   record_event=security_ext.record, encrypt=bearer_ext.encrypt_secret, decrypt=bearer_ext.decrypt_secret,
                   build_dns_records=bearer_ext.build_dns_records, mail_host_for=bearer_ext.mail_host_for)
tabs_ext.configure(get_db=lambda: db, get_account=get_current_account, addr_match=_addr_match,
                   record_event=security_ext.record)


@app.get("/admin/domains")
async def admin_list_domains(request: Request):
    """List all domains (including inactive)"""
    _require_api_key(request)
    docs = list(db.domains.find({}, {"_id": 0, "dkim_private_enc": 0}))
    for doc in docs:
        if "created_at" in doc and isinstance(doc["created_at"], datetime):
            doc["created_at"] = doc["created_at"].isoformat()
    return {"domains": docs}


@app.post("/admin/domains")
async def admin_add_domain(request: Request):
    """Add a new domain"""
    _require_api_key(request)
    data = await _json_body(request)
    domain = _text(data.get("domain")).strip().lower()

    if not domain:
        raise HTTPException(status_code=422, detail="Domain is required")

    # basic domain format check
    if "." not in domain or len(domain) < 3:
        raise HTTPException(status_code=422, detail="Invalid domain format")

    existing = db.domains.find_one({"domain": domain})
    if existing:
        # if it exists but is inactive, reactivate it
        if not existing.get("is_active", True):
            db.domains.update_one({"domain": domain}, {"$set": {"is_active": True}})
            _invalidate_domains_cache()
            return {"message": f"Domain '{domain}' reactivated", "domain": domain}
        raise HTTPException(status_code=409, detail=f"Domain '{domain}' already exists")

    db.domains.insert_one({
        "domain": domain,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    })
    _invalidate_domains_cache()
    logger.info(f"Domain added: {domain}")
    return JSONResponse(status_code=201, content={"message": f"Domain '{domain}' added", "domain": domain})


@app.delete("/admin/domains/{domain}")
async def admin_delete_domain(domain: str, request: Request):
    """Delete (deactivate) a domain"""
    _require_api_key(request)
    domain = domain.strip().lower()

    result = db.domains.update_one(
        {"domain": domain},
        {"$set": {"is_active": False}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")

    _invalidate_domains_cache()
    logger.info(f"Domain deactivated: {domain}")
    return {"message": f"Domain '{domain}' deactivated", "domain": domain}


app.include_router(bearer_ext.router)
app.include_router(security_ext.router)
app.include_router(users_ext.router)
app.include_router(relay_ext.router)
app.include_router(drive_ext.router)
app.include_router(dmarc_ext.router)
app.include_router(calendar_ext.router)
app.include_router(tabs_ext.router)
app.include_router(ddns_ext.router)


# ---- Messages ----

def _dt_to_iso_utc(dt) -> str:
    """Convert a datetime to an ISO string with a UTC marker (naive datetimes from MongoDB are UTC)"""
    if isinstance(dt, datetime):
        s = dt.isoformat()
        # naive datetimes from pymongo carry no tzinfo but are UTC, so add 'Z'
        if dt.tzinfo is None:
            s += "Z"
        return s
    return str(dt) if dt else ""


def _format_attachment_meta(message_id: str, attachment: dict) -> dict:
    """Format attachment metadata; the content itself never appears in list/detail responses."""
    attachment_id = attachment.get("id", "")
    filename = attachment.get("filename", "")
    content_type = attachment.get("content_type", "application/octet-stream")
    size = attachment.get("size", 0)
    return {
        "id": attachment_id,
        "filename": filename,
        "contentType": content_type,
        "content_type": content_type,
        "size": size,
        "downloadUrl": f"/messages/{message_id}/attachments/{attachment_id}",
    }


def _format_message(msg: dict, include_body: bool = False) -> dict:
    """Format a message in DuckMail-compatible form"""
    msg_id = str(msg["_id"])
    created = msg["created_at"]
    updated = msg.get("updated_at", created)
    attachments = msg.get("attachments", [])

    result = {
        "@context": "/contexts/Message",
        "@id": f"/messages/{msg_id}",
        "@type": "Message",
        "id": msg_id,
        "msgid": msg_id,
        "from": msg.get("from", {}),
        "to": msg.get("to", []),
        "subject": msg.get("subject", ""),
        "intro": msg.get("intro", ""),
        "hasAttachments": msg.get("has_attachments", bool(attachments)),
        "seen": msg.get("seen", False),
        "isDeleted": msg.get("is_deleted", False),
        "size": msg.get("size", 0),
        "createdAt": _dt_to_iso_utc(created),
        "updatedAt": _dt_to_iso_utc(updated),
        # Sender check result for the list: "pass", "warn", "fail" or "" (checked before this version).
        "authVerdict": mail_auth.auth_verdict(msg.get("auth")),
        "riskyAttachments": int((msg.get("scan") or {}).get("risky_attachments", 0)),
    }

    if include_body:
        result["text"] = msg.get("text", "")
        result["html"] = msg.get("html", "")
        result["attachments"] = [_format_attachment_meta(msg_id, a) for a in attachments]
        result["auth"] = msg.get("auth") or None
        result["scan"] = msg.get("scan") or None
        result["replyTo"] = msg.get("reply_to", "")

    return result


@app.get("/messages")
async def list_messages(
    account=Depends(get_current_account),
    offset: int = 0,
    limit: int = 30,
    tab: str = "",
):
    """List the inbox (Bearer token auth), paginated; ``tab`` narrows it to one inbox tab."""
    address = account["address"]
    limit = max(1, min(limit, 100))  # 1..100
    offset = max(offset, 0)

    query_filter = {"to_addresses": _addr_match(account), "is_deleted": {"$ne": True}}
    if tab:
        tabs_ext.backfill(account)  # mail from before tabs existed gets sorted before it is filtered
        query_filter.update(tabs_ext.tab_filter(address, tab))
    total = db.messages.count_documents(query_filter)

    cursor = (
        db.messages.find(query_filter)
        .sort("created_at", DESCENDING)
        .skip(offset)
        .limit(limit)
    )
    messages = [{**_format_message(msg), "tab": tabs_ext.effective_tab(msg, address)} for msg in cursor]
    return {
        "hydra:member": messages,
        "hydra:totalItems": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/messages/search")
async def search_messages(
    q: str = "",
    account=Depends(get_current_account),
):
    """Search messages (fuzzy match on sender, subject, summary)"""
    address = account["address"]
    if not q.strip():
        return {"hydra:member": []}

    escaped_q = re.escape(q)
    query_filter = {
        "to_addresses": _addr_match(account),
        "is_deleted": {"$ne": True},
        "$or": [
            {"subject": {"$regex": escaped_q, "$options": "i"}},
            {"intro": {"$regex": escaped_q, "$options": "i"}},
            {"text": {"$regex": escaped_q, "$options": "i"}},
            {"html": {"$regex": escaped_q, "$options": "i"}},
            {"from.address": {"$regex": escaped_q, "$options": "i"}},
            {"from.name": {"$regex": escaped_q, "$options": "i"}},
        ],
    }
    cursor = (
        db.messages.find(query_filter)
        .sort("created_at", DESCENDING)
        .limit(50)
    )
    messages = [_format_message(msg) for msg in cursor]
    return {"hydra:member": messages}


@app.get("/messages/trash")
async def list_trash_messages(
    account=Depends(get_current_account),
    offset: int = 0,
    limit: int = 30,
):
    """List the trash (soft-deleted messages), paginated"""
    address = account["address"]
    limit = max(1, min(limit, 100))
    offset = max(offset, 0)

    query_filter = {"to_addresses": _addr_match(account), "is_deleted": True}
    total = db.messages.count_documents(query_filter)
    cursor = (
        db.messages.find(query_filter)
        .sort("updated_at", DESCENDING)
        .skip(offset)
        .limit(limit)
    )
    messages = [_format_message(msg) for msg in cursor]
    return {
        "hydra:member": messages,
        "hydra:totalItems": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/messages/{message_id}")
async def get_message(message_id: str, peek: int = 0, account=Depends(get_current_account)):
    """Get message detail. peek=1 leaves it unread (an admin's stealth view must not change anything)."""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Message not found")

    msg = db.messages.find_one({"_id": oid, "to_addresses": _addr_match(account)})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    # mark as read
    if not msg.get("seen") and not peek:
        db.messages.update_one({"_id": oid}, {"$set": {"seen": True, "updated_at": datetime.now(timezone.utc)}})

    # Mail stored before attachment scanning existed is scanned the first time it is opened.
    scan = msg.get("scan")
    if msg.get("attachments") and (not scan or scan.get("version", 0) < mail_auth.SCAN_VERSION):
        try:
            scan = mail_auth.scan_message(None, msg.get("attachments", []))
            if (msg.get("scan") or {}).get("read_receipt_to"):
                scan["read_receipt_to"] = msg["scan"]["read_receipt_to"]
            db.messages.update_one({"_id": oid}, {"$set": {"scan": scan}})
            msg["scan"] = scan
        except Exception as exc:
            logger.warning(f"Attachment scan failed for {message_id}: {exc}")

    return {**_format_message(msg, include_body=True), "tab": tabs_ext.effective_tab(msg, address)}


@app.get("/messages/{message_id}/attachments/{attachment_id}")
async def download_attachment(message_id: str, attachment_id: str, account=Depends(get_current_account)):
    """Download a message attachment"""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Message not found")

    msg = db.messages.find_one({"_id": oid, "to_addresses": _addr_match(account)})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    attachment = None
    for item in msg.get("attachments", []):
        if item.get("id") == attachment_id:
            attachment = item
            break
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")

    filename = attachment.get("filename") or "attachment"
    content_type = attachment.get("content_type", "application/octet-stream")
    content = attachment.get("content", b"")
    if isinstance(content, str):
        content = content.encode("utf-8")
    quoted_filename = quote(filename)
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quoted_filename}"},
    )


@app.post("/messages/{message_id}/restore")
async def restore_message(message_id: str, account=Depends(get_current_account)):
    """Restore a message from trash"""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Message not found")

    result = db.messages.update_one(
        {"_id": oid, "to_addresses": _addr_match(account), "is_deleted": True},
        {"$set": {"is_deleted": False, "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")

    logger.info(f"Message restored: {message_id} by {address}")
    return {"message": "Restored", "id": message_id}


@app.delete("/messages/{message_id}/permanent")
async def permanent_delete_message(message_id: str, account=Depends(get_current_account)):
    """Permanently delete a message from trash"""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Message not found")

    result = db.messages.delete_one({"_id": oid, "to_addresses": _addr_match(account), "is_deleted": True})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")

    logger.info(f"Message permanently deleted: {message_id} by {address}")
    return {"message": "Permanently deleted", "id": message_id}


@app.delete("/messages/{message_id}")
async def delete_message(message_id: str, account=Depends(get_current_account)):
    """Soft-delete a message (sets is_deleted)"""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Message not found")

    result = db.messages.update_one(
        {"_id": oid, "to_addresses": _addr_match(account)},
        {"$set": {"is_deleted": True, "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")

    logger.info(f"Message deleted: {message_id} by {address}")
    return {"message": "Deleted", "id": message_id}


@app.post("/messages/batch")
async def batch_action(request: Request, account=Depends(get_current_account)):
    """Batch actions (delete / mark read)"""
    address = account["address"]
    data = await _json_body(request)
    action = _text(data.get("action"))
    message_ids = data.get("message_ids", data.get("ids", []))
    now = datetime.now(timezone.utc)

    if action == "empty_trash":
        result = db.messages.delete_many({"to_addresses": _addr_match(account), "is_deleted": True})
        logger.info(f"Empty trash: {result.deleted_count} messages by {address}")
        return {"message": f"Permanently deleted {result.deleted_count} messages", "count": result.deleted_count}

    if not message_ids or not isinstance(message_ids, list):
        raise HTTPException(status_code=422, detail="message_ids is required")

    oids = []
    for mid in message_ids:
        if not isinstance(mid, str):
            continue
        try:
            oids.append(ObjectId(mid))
        except Exception:
            pass

    if not oids:
        raise HTTPException(status_code=422, detail="No valid message IDs")

    query_filter = {"_id": {"$in": oids}, "to_addresses": _addr_match(account)}

    if action == "delete":
        result = db.messages.update_many(query_filter, {"$set": {"is_deleted": True, "updated_at": now}})
        logger.info(f"Batch delete: {result.modified_count} messages by {address}")
        return {"message": f"Deleted {result.modified_count} messages", "count": result.modified_count}
    elif action in ("mark_read", "mark_unread"):
        seen = action == "mark_read"
        result = db.messages.update_many(query_filter, {"$set": {"seen": seen, "updated_at": now}})
        logger.info(f"Batch {action}: {result.modified_count} messages by {address}")
        return {"message": f"Marked {result.modified_count} as {'read' if seen else 'unread'}", "count": result.modified_count}
    elif action == "restore":
        result = db.messages.update_many({**query_filter, "is_deleted": True}, {"$set": {"is_deleted": False, "updated_at": now}})
        logger.info(f"Batch restore: {result.modified_count} messages by {address}")
        return {"message": f"Restored {result.modified_count} messages", "count": result.modified_count}
    elif action in {"permanent_delete", "delete_permanent"}:
        result = db.messages.delete_many({**query_filter, "is_deleted": True})
        logger.info(f"Batch permanent_delete: {result.deleted_count} messages by {address}")
        return {"message": f"Permanently deleted {result.deleted_count} messages", "count": result.deleted_count}
    else:
        raise HTTPException(status_code=422, detail=f"Unknown action: {action}")


# ---- Sent Messages (sent records) ----

@app.post("/admin/sent")
async def store_sent_message(request: Request):
    """Store a sent-message record (API key auth)"""
    _require_api_key(request)
    data = await _json_body(request)

    from_address = _text(data.get("from_address")).strip().lower()
    raw_to = data.get("to")
    to = [t for t in (raw_to if isinstance(raw_to, list) else [raw_to]) if isinstance(t, str) and t]
    subject = _text(data.get("subject"))
    text = _text(data.get("text"))
    html = _text(data.get("html"))
    resend_id = _text(data.get("resend_id"))

    if not from_address or not to:
        raise HTTPException(status_code=422, detail="from_address and to are required")

    now = datetime.now(timezone.utc)
    doc = {
        "from_address": from_address,
        "to": to if isinstance(to, list) else [to],
        "subject": subject,
        "text": text,
        "html": html,
        "resend_id": resend_id,
        "created_at": now,
    }
    result = db.sent_messages.insert_one(doc)
    logger.info(f"Sent message stored: {from_address} -> {to} | {subject[:50]}")
    return JSONResponse(status_code=201, content={
        "id": str(result.inserted_id),
        "message": "Stored",
    })


def _format_sent_message(doc: dict, include_body: bool = True) -> dict:
    result = {
        "id": str(doc["_id"]),
        "from_address": doc.get("from_address", ""),
        "to": doc.get("to", []),
        "subject": doc.get("subject", ""),
        "resend_id": doc.get("resend_id", ""),
        "createdAt": _dt_to_iso_utc(doc.get("created_at")),
    }
    if include_body:
        result["text"] = doc.get("text", "")
        result["html"] = doc.get("html", "")
    return result


def _sent_filter(account) -> dict:
    """Sent mail this token may see: an alias token only its own, a mailbox token everything it sent."""
    if account.get("alias"):
        return {"from_address": account["alias"]}
    address = account["address"]
    return {"$or": [{"from_address": address}, {"owner": address}]}


@app.post("/sent/batch")
async def sent_batch(request: Request, account=Depends(get_current_account)):
    """Delete sent-mail records (the copies kept in Sent; the mail itself was already delivered)."""
    data = await _json_body(request)
    if _text(data.get("action")) != "delete":
        raise HTTPException(status_code=422, detail="Unknown action")
    ids = data.get("message_ids", [])
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=422, detail="message_ids is required")
    oids = []
    for mid in ids:
        try:
            oids.append(ObjectId(mid))
        except Exception:
            pass
    result = db.sent_messages.delete_many({"_id": {"$in": oids}, **_sent_filter(account)})
    return {"message": f"Deleted {result.deleted_count} sent messages", "count": result.deleted_count}


@app.get("/sent")
async def list_sent_messages(
    account=Depends(get_current_account),
    offset: int = 0,
    limit: int = 100,
):
    """List sent messages (Bearer token auth), paginated"""
    limit = max(1, min(limit, 100))
    offset = max(offset, 0)
    query_filter = _sent_filter(account)
    total = db.sent_messages.count_documents(query_filter)
    cursor = (
        db.sent_messages.find(query_filter)
        .sort("created_at", DESCENDING)
        .skip(offset)
        .limit(limit)
    )
    messages = [_format_sent_message(doc) for doc in cursor]
    return {
        "hydra:member": messages,
        "hydra:totalItems": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/sent/{message_id}")
async def get_sent_message(message_id: str, account=Depends(get_current_account)):
    """Get sent message detail"""
    address = account["address"]

    try:
        oid = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Sent message not found")

    doc = db.sent_messages.find_one({"_id": oid, "$or": [{"from_address": address}, {"owner": address}]})
    if not doc:
        raise HTTPException(status_code=404, detail="Sent message not found")

    return _format_sent_message(doc)


def _part_text(part):
    """Decode a message part to str, always.

    Two failure modes are handled here because both used to abort handle_DATA
    and lose the whole message:

      * part.get_content() can return bytes instead of str. That single
        difference made
            re.sub(r"\\s+", " ", (text_body or ""))
        raise "cannot use a string pattern on a bytes-like object".
      * It can raise LookupError for a charset this build does not know.

    Returns "" instead of raising, so one odd part can never take down
    delivery of the entire message.
    """
    try:
        value = part.get_content()
    except Exception:
        return ""
    if isinstance(value, bytes):
        charset = None
        try:
            charset = part.get_content_charset()
        except Exception:
            charset = None
        for candidate in (charset, "utf-8"):
            if not candidate:
                continue
            try:
                return value.decode(candidate, errors="replace")
            except (LookupError, TypeError):
                continue
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    return str(value)


# ---------------------------------------------------------------------------
# SMTP Server (aiosmtpd)
# ---------------------------------------------------------------------------

class MailHandler:
    """SMTP receive handler"""

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        session.rcpt_count = 0
        session.mail_from = address
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Validate the recipient domain (domain list is read dynamically from MongoDB)"""
        addr = (address or "").strip().lower()
        client_ip = _get_smtp_client_ip(session)
        current_rcpt_count = int(getattr(session, "rcpt_count", 0))
        mail_from = getattr(envelope, "mail_from", "") or getattr(session, "mail_from", "")
        if not addr or "@" not in addr:
            return "501 5.1.3 Bad recipient address syntax"
        if len(addr) > _SMTP_MAX_ADDRESS_LENGTH:
            return "552 5.3.4 Recipient address too long"
        if addr in envelope.rcpt_tos:
            return "452 4.5.3 Duplicate recipient"
        blocked = _check_smtp_blacklist(client_ip, mail_from)
        if blocked:
            security_ext.record("smtp", "rejected_sender", ip=client_ip, detail=f"from {mail_from}"[:200])
            return blocked
        greylist = _check_smtp_greylist(client_ip, mail_from, addr)
        if greylist:
            security_ext.record("smtp", "greylisted", ip=client_ip, detail=f"from {mail_from}"[:200])
            return greylist
        limit_error = _check_smtp_rcpt_limit(client_ip, current_rcpt_count)
        if limit_error:
            security_ext.record("smtp", "rate_limited", ip=client_ip, detail=limit_error)
            return limit_error
        domain = addr.split("@", 1)[1] if "@" in addr else ""
        if domain not in get_active_domains():
            security_ext.record("smtp", "relay_attempt", ip=client_ip, detail=f"{mail_from} -> {addr}"[:200])
            return f"550 Domain {domain} not accepted here"
        if bearer_ext.is_disabled_alias(addr):
            return "550 5.1.1 Mailbox unavailable"
        # A mailbox the admin gave a mailbox limit refuses new mail once full (the sender gets a "mailbox full" bounce).
        try:
            for target in dict.fromkeys([addr, *bearer_ext.expand_recipient(addr)]):
                acc = db.accounts.find_one({"address": target, "mail_quota_mb": {"$gt": 0}})
                if acc and drive_ext.mail_full(acc):
                    security_ext.record("smtp", "mailbox_full", ip=client_ip, detail=f"{mail_from} -> {addr}"[:200])
                    return "552 5.2.2 Mailbox full"
        except Exception as exc:
            logger.warning(f"Mailbox limit check skipped: {exc}")
        envelope.rcpt_tos.append(addr)
        session.rcpt_count = current_rcpt_count + 1
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        """Receive and store a message"""
        try:
            client_ip = _get_smtp_client_ip(session)
            limit_error = _check_smtp_data_limit(client_ip)
            if limit_error:
                security_ext.record("smtp", "rate_limited", ip=client_ip, detail=limit_error)
                return limit_error
            raw = envelope.content
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if len(raw) > _SMTP_MAX_MESSAGE_BYTES:
                security_ext.record("smtp", "message_rejected", ip=client_ip, detail="too large")
                return "552 5.3.4 Message too large"
            if not envelope.rcpt_tos:
                return "554 5.5.1 No valid recipients"

            # parse the message
            parser = BytesParser(policy=policy.default)
            msg = parser.parsebytes(raw)

            # Sender checks: SPF / DKIM / DMARC (DNS lookups run off the event loop, with a time limit)
            auth = None
            if _CHECK_SENDER_AUTH:
                helo = getattr(session, "host_name", "") or ""
                envelope_from = getattr(envelope, "mail_from", "") or ""
                try:
                    auth = await asyncio.wait_for(
                        asyncio.to_thread(mail_auth.evaluate_sender, raw, msg, client_ip, helo, envelope_from),
                        timeout=25,
                    )
                except Exception as exc:
                    logger.warning(f"Sender checks skipped: {exc!r}")
                    auth = {"spf": "temperror", "dkim": "none", "dmarc": "temperror",
                            "header_from_domain": mail_auth._domain_of(mail_auth.header_from_address(msg))}
                if (_SMTP_ENFORCE_DMARC_REJECT and auth.get("dmarc") == "fail"
                        and auth.get("dmarc_policy") == "reject"):
                    security_ext.record("smtp", "forged_sender", ip=client_ip,
                                        detail=f"refused: From {mail_auth.header_from_address(msg)} failed DMARC (p=reject)")
                    return "550 5.7.1 Message rejected: it failed the DMARC policy of the sender's domain"

            # extract the sender
            from_header = msg.get("From", "")
            from_name, from_email = "", ""
            if "<" in from_header:
                parts = from_header.rsplit("<", 1)
                from_name = parts[0].strip().strip('"').strip()
                from_email = parts[1].strip(">").strip().lower()
            else:
                from_email = from_header.strip().lower()

            # extract recipients
            to_list = [{"address": a.lower(), "name": ""} for a in envelope.rcpt_tos]
            # Route aliases / catch-all into the mailbox that should receive them
            to_addresses = []
            for rcpt in envelope.rcpt_tos:
                rcpt = rcpt.lower()
                for target in [rcpt, *bearer_ext.expand_recipient(rcpt)]:
                    if target not in to_addresses:
                        to_addresses.append(target)

            # extract body and attachments
            text_body = ""
            html_body = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    if part.is_multipart():
                        continue
                    ct = part.get_content_type()
                    cd = part.get("Content-Disposition", "")
                    filename = part.get_filename()
                    is_attachment = "attachment" in cd.lower() or bool(filename)
                    if is_attachment:
                        payload = part.get_payload(decode=True) or b""
                        attachment_id = str(ObjectId())
                        attachments.append({
                            "id": attachment_id,
                            "filename": filename or f"attachment-{len(attachments) + 1}",
                            "content_type": ct or "application/octet-stream",
                            "size": len(payload),
                            "content": payload,
                        })
                        continue
                    if ct == "text/plain" and not text_body:
                        decoded = _part_text(part)
                        if decoded:
                            text_body = decoded
                    elif ct == "text/html" and not html_body:
                        decoded = _part_text(part)
                        if decoded:
                            html_body = decoded
            elif msg.get_content_maintype() != "text" or msg.get_content_type() == "text/xml" or msg.get_filename():
                # A message that is only a file (DMARC reports from Google/Microsoft are just a .zip or .gz):
                # keep it as an attachment instead of showing the raw bytes as text.
                import mimetypes
                ct = msg.get_content_type()
                payload = msg.get_payload(decode=True) or b""
                filename = msg.get_filename() or ("attachment" + (mimetypes.guess_extension(ct) or ".bin"))
                attachments.append({
                    "id": str(ObjectId()),
                    "filename": filename,
                    "content_type": ct or "application/octet-stream",
                    "size": len(payload),
                    "content": payload,
                })
            else:
                ct = msg.get_content_type()
                content = _part_text(msg)
                if ct == "text/html":
                    html_body = content
                else:
                    text_body = content

            has_attachments = bool(attachments)
            subject = msg.get("Subject", "")
            # take a summary from the plain text
            intro = re.sub(r"\s+", " ", (text_body or "")).strip()[:200]
            if not any([subject.strip(), text_body.strip(), html_body.strip()]):
                security_ext.record("smtp", "message_rejected", ip=client_ip, detail="empty message")
                return "554 5.6.0 Empty message rejected"

            try:
                scan = mail_auth.scan_message(msg, attachments)
            except Exception as exc:
                logger.warning(f"Attachment scan failed: {exc}")
                scan = None

            # DMARC reports (the daily summaries from Gmail, Microsoft...) go to the admins' Security page
            # instead of someone's inbox, unless the admin chose to keep copies.
            is_report, keep_copy = dmarc_ext.capture(attachments, auth, from_email)
            if is_report and not keep_copy:
                logger.info(f"DMARC report from {from_email} filed under Security")
                security_ext.record("smtp", "message_received", ip=client_ip, detail=f"DMARC report from {from_email}"[:200])
                session.rcpt_count = 0
                return "250 Message accepted for delivery"

            now = datetime.now(timezone.utc)
            doc = {
                "to_addresses": to_addresses,
                "from": {"address": from_email, "name": from_name},
                "to": to_list,
                "subject": subject,
                "intro": intro,
                "text": text_body,
                "html": html_body,
                "has_attachments": has_attachments,
                "attachments": attachments,
                "seen": False,
                "is_deleted": False,
                "size": len(raw),
                "created_at": now,
                "updated_at": now,
                "reply_to": mail_auth.reply_to_address(msg),
            }
            if auth:
                doc["auth"] = auth
            if scan:
                doc["scan"] = scan
            # Inbox tabs: the automatic sort, plus any "always put this sender in..." rules of the recipients
            try:
                doc["category"] = tabs_ext.classify(msg, from_email, subject, text_body, html_body,
                                                    mail_auth.auth_verdict(auth))
                doc["cat_v"] = tabs_ext.CAT_VERSION
                doc["tab_overrides"] = tabs_ext.overrides_for(to_addresses, from_email)
            except Exception as exc:
                logger.warning(f"Tab sorting skipped: {exc}")

            db.messages.insert_one(doc)
            logger.info(
                f"Email stored: {from_email} -> {to_addresses} | {subject[:50]}"
            )
            security_ext.record("smtp", "message_received", ip=client_ip, detail=f"from {from_email}"[:200])
            if mail_auth.auth_verdict(auth) == "fail":
                security_ext.record(
                    "smtp", "forged_sender", ip=client_ip,
                    detail=(f"From {from_email} (spf={auth.get('spf')}, dkim={auth.get('dkim')}, "
                            f"dmarc={auth.get('dmarc')}) subject: {subject[:60]}"),
                )
            session.rcpt_count = 0
            return "250 Message accepted for delivery"

        except Exception as e:
            logger.error(f"Failed to store email: {e}", exc_info=True)
            session.rcpt_count = 0
            return "451 Requested action aborted: error in processing"


class LoggingSMTP(SMTP):
    """aiosmtpd server that reports connections to the security log and drops blocked addresses."""

    def connection_made(self, transport):
        starttls_upgrade = self._original_transport is not None
        super().connection_made(transport)
        if starttls_upgrade:
            return
        client_ip = _get_smtp_client_ip(self.session)
        if client_ip and security_ext.is_blocked(client_ip):
            security_ext.record("smtp", "blocked", ip=client_ip)
            transport.close()
            return
        if client_ip and not _is_internal_client(client_ip):
            security_ext.record("smtp", "connect", ip=client_ip)

    async def smtp_AUTH(self, arg):
        client_ip = _get_smtp_client_ip(self.session)
        mechanism = (arg or "").split(" ", 1)[0][:20]
        security_ext.record("smtp", "auth_attempt", ip=client_ip, detail=f"AUTH {mechanism}".strip())
        await self.push("502 5.5.1 Authentication is not available on this server")


class LoggingController(Controller):
    def factory(self):
        return LoggingSMTP(self.handler, **self.SMTP_kwargs)


def _build_tls_context():
    """Build SSLContext for STARTTLS if cert/key are configured."""
    if not SMTP_TLS_CERT or not SMTP_TLS_KEY:
        return None
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(SMTP_TLS_CERT, SMTP_TLS_KEY)
    logger.info(f"TLS context loaded: cert={SMTP_TLS_CERT}")
    return ctx


def start_smtp_server():
    """Start the SMTP server (background daemon thread), supports STARTTLS"""
    handler = MailHandler()
    tls_ctx = _build_tls_context()

    kwargs = dict(
        hostname="0.0.0.0",
        port=SMTP_PORT,
        server_hostname=SMTP_HOSTNAME,
        data_size_limit=_SMTP_MAX_MESSAGE_BYTES,  # refuse oversized mail while receiving, not after buffering
    )
    if tls_ctx:
        kwargs["tls_context"] = tls_ctx
        kwargs["require_starttls"] = False  # offer but don't require

    controller = LoggingController(handler, **kwargs)
    controller.start()
    tls_status = "STARTTLS enabled" if tls_ctx else "no TLS"
    logger.info(f"SMTP server started on port {SMTP_PORT} ({tls_status})")
    logger.info(f"Accepting mail for domains: {get_active_domains()} (dynamic from DB)")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, log_level="info")
