"""
BearerMail extensions for the mail service.

Adds, on top of the receive-only core in app.py:

* Mailbox management  (create / list / reset password / delete)
* Disposable aliases  (catch-all addresses that deliver into a main mailbox)
* Per-domain catch-all routing
* DNS record generation + live DNS check (MX / A / SPF / DKIM / DMARC)
* Third-party SMTP providers (Mailjet, SendGrid, Brevo, ...) and outbound sending
* "Connect a mail app" (IMAP) settings

Everything under /admin/* is protected by the API key, exactly like the
existing admin endpoints.
"""

import base64
import hashlib
import logging
import re
import secrets
import smtplib
import socket
import ssl
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from types import SimpleNamespace

import bcrypt
from bson import ObjectId
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Body, Depends, HTTPException, Request

logger = logging.getLogger("bearermail.ext")

_cfg = SimpleNamespace(
    get_db=None,
    require_api_key=None,
    invalidate_domains=None,
    create_token=None,
    smtp_hostname="mail.example.com",
    secret="change-this-in-production",
    server_ip="",
    imap_hostname="",
    imap_port=993,
    dkim_selector="bearer",
)

ADDRESS_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")


def configure(**kwargs):
    """Called once from app.py with the pieces of the core app we depend on."""
    for key, value in kwargs.items():
        setattr(_cfg, key, value)


def _db():
    return _cfg.get_db()


def _auth(request: Request):
    _cfg.require_api_key(request)


router = APIRouter(dependencies=[Depends(_auth)])


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
    return dt


# ---------------------------------------------------------------------------
# Secret storage (SMTP passwords, DKIM private keys)
# ---------------------------------------------------------------------------

def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(_cfg.secret.encode()).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        raise HTTPException(
            status_code=500,
            detail="Stored secret could not be decrypted. Was SECRETS_KEY / JWT_SECRET changed? "
                   "Re-enter the SMTP password.",
        )


def init_indexes():
    db = _db()
    db.aliases.create_index("address", unique=True)
    db.aliases.create_index("deliver_to")
    db.sent_messages.create_index("owner")


# ---------------------------------------------------------------------------
# Routing helpers used by the SMTP receiver in app.py
# ---------------------------------------------------------------------------

def is_disabled_alias(address: str) -> bool:
    alias = _db().aliases.find_one({"address": address}, {"enabled": 1})
    return bool(alias) and alias.get("enabled", True) is False


def expand_recipient(address: str) -> list:
    """Extra mailbox addresses a message for `address` must also be delivered to."""
    db = _db()
    alias = db.aliases.find_one({"address": address})
    if alias:
        return [alias["deliver_to"]] if alias.get("enabled", True) and alias.get("deliver_to") else []
    if db.accounts.find_one({"address": address}, {"_id": 1}):
        return []
    domain = address.split("@", 1)[1] if "@" in address else ""
    dom = db.domains.find_one({"domain": domain}, {"catch_all_to": 1})
    if dom and dom.get("catch_all_to"):
        return [dom["catch_all_to"]]
    return []


# ---------------------------------------------------------------------------
# Small validation helpers
# ---------------------------------------------------------------------------

def _clean_address(value) -> str:
    """Only strings count; an object like {"$gt": ""} becomes an empty address instead of reaching a query."""
    return value.strip().lower() if isinstance(value, str) else ""


def _need_address(value, field="address") -> str:
    addr = _clean_address(value)
    if not ADDRESS_RE.match(addr):
        raise HTTPException(status_code=422, detail=f"'{field}' must be a valid email address")
    return addr


def _active_domain(domain: str):
    doc = _db().domains.find_one({"domain": domain, "is_active": True})
    if not doc:
        raise HTTPException(status_code=422, detail=f"Domain '{domain}' is not an active domain. Add it first.")
    return doc


def _need_account(address: str) -> dict:
    acc = _db().accounts.find_one({"address": address})
    if not acc:
        raise HTTPException(status_code=422, detail=f"Mailbox '{address}' does not exist. Create it first.")
    return acc


# ---------------------------------------------------------------------------
# Mailboxes
# ---------------------------------------------------------------------------

@router.get("/admin/accounts")
def list_accounts():
    db = _db()
    out = []
    for acc in db.accounts.find({}).sort("address", 1):
        addr = acc["address"]
        out.append({
            "address": addr,
            "is_active": acc.get("is_active", True),
            "created_at": _iso(acc.get("created_at")),
            "aliases": db.aliases.count_documents({"deliver_to": addr}),
            "messages": db.messages.count_documents({"to_addresses": addr, "is_deleted": {"$ne": True}}),
        })
    return {"accounts": out}


@router.post("/admin/accounts", status_code=201)
def create_mailbox(body: dict = Body(...)):
    db = _db()
    address = _need_address(body.get("address"))
    password = body.get("password") if isinstance(body.get("password"), str) else ""
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    domain = address.split("@", 1)[1]
    _active_domain(domain)
    if db.aliases.find_one({"address": address}):
        raise HTTPException(status_code=409, detail="That address is already used by an alias")
    if db.accounts.find_one({"address": address}):
        raise HTTPException(status_code=409, detail="This mailbox already exists")
    if db.aliases.find_one({"address": address}):
        raise HTTPException(status_code=409, detail="This address is already used by an alias")
    now = _now()
    db.accounts.insert_one({
        "address": address,
        "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        "is_active": True,
        "created_at": now,
        "updated_at": now,
    })
    return {"address": address, "message": "Mailbox created"}


@router.patch("/admin/accounts/{address}")
def update_mailbox(address: str, body: dict = Body(...)):
    db = _db()
    address = _clean_address(address)
    _need_account(address)
    updates = {"updated_at": _now()}
    if body.get("password") not in (None, ""):
        if not isinstance(body["password"], str) or len(body["password"]) < 8:
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
        updates["password_hash"] = bcrypt.hashpw(body["password"].encode(), bcrypt.gensalt()).decode()
    if "is_active" in body:
        updates["is_active"] = bool(body["is_active"])
    db.accounts.update_one({"address": address}, {"$set": updates})
    return {"address": address, "message": "Mailbox updated"}


@router.delete("/admin/accounts/{address}")
def delete_mailbox(address: str):
    db = _db()
    address = _clean_address(address)
    _need_account(address)
    db.accounts.delete_one({"address": address})
    removed = db.aliases.delete_many({"deliver_to": address}).deleted_count
    db.domains.update_many({"catch_all_to": address}, {"$set": {"catch_all_to": None}})
    return {"address": address, "message": f"Mailbox deleted ({removed} alias(es) removed)"}


@router.post("/admin/token")
def issue_token(body: dict = Body(...)):
    """Token for a mailbox (or for the mailbox behind an alias). Used by the web UI."""
    db = _db()
    address = _clean_address(body.get("address"))
    acc = db.accounts.find_one({"address": address, "is_active": True})
    if acc:
        return {"token": _cfg.create_token(str(acc["_id"]), acc["address"]), "kind": "mailbox",
                "mailbox": acc["address"], "alias": None}
    alias = db.aliases.find_one({"address": address})
    if alias:
        acc = db.accounts.find_one({"address": alias.get("deliver_to"), "is_active": True})
        if acc:
            return {"token": _cfg.create_token(str(acc["_id"]), acc["address"], alias=address),
                    "kind": "alias", "mailbox": acc["address"], "alias": address}
    raise HTTPException(status_code=404, detail="No mailbox or alias with that address")


# ---------------------------------------------------------------------------
# Aliases (disposable addresses)
# ---------------------------------------------------------------------------

def _random_local(prefix: str = "") -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    tail = "".join(secrets.choice(alphabet) for _ in range(8 if not prefix else 5))
    return f"{prefix}-{tail}" if prefix else "x" + tail


def _format_alias(a: dict, received=None) -> dict:
    return {
        "address": a["address"],
        "domain": a.get("domain", a["address"].split("@", 1)[1]),
        "label": a.get("label", ""),
        "deliver_to": a.get("deliver_to", ""),
        "from_name": a.get("from_name", ""),
        "send_via": a.get("send_via") or None,
        "enabled": a.get("enabled", True),
        "created_at": _iso(a.get("created_at")),
        "received": received,
    }


@router.get("/admin/aliases")
def list_aliases(domain: str = "", q: str = ""):
    db = _db()
    flt = {}
    if domain:
        flt["domain"] = domain.strip().lower()
    if q:
        flt["$or"] = [{"address": {"$regex": re.escape(q.lower())}},
                      {"label": {"$regex": re.escape(q), "$options": "i"}}]
    items = []
    for a in db.aliases.find(flt).sort("created_at", -1).limit(500):
        items.append(_format_alias(a, db.messages.count_documents({"to_addresses": a["address"]})))
    return {"aliases": items}


@router.post("/admin/aliases", status_code=201)
def create_alias(body: dict = Body(...)):
    db = _db()
    deliver_to = _clean_address(body.get("deliver_to"))
    if not deliver_to:
        raise HTTPException(status_code=422, detail="Choose the mailbox that should receive this alias' mail")
    _need_account(deliver_to)

    address = _clean_address(body.get("address"))
    if body.get("random") or not address:
        domain = _clean_address(body.get("domain"))
        if not domain:
            raise HTTPException(status_code=422, detail="Choose a domain")
        prefix = re.sub(r"[^a-z0-9._+\-]", "", _clean_address(body.get("prefix")))
        for _ in range(10):
            address = f"{_random_local(prefix)}@{domain}"
            if not db.aliases.find_one({"address": address}) and not db.accounts.find_one({"address": address}):
                break
    address = _need_address(address)
    domain = address.split("@", 1)[1]
    _active_domain(domain)
    if db.accounts.find_one({"address": address}):
        raise HTTPException(status_code=409, detail="This address is already a mailbox")
    if db.aliases.find_one({"address": address}):
        raise HTTPException(status_code=409, detail="This alias already exists")

    send_via = _valid_provider_id(body.get("send_via"))
    doc = {
        "address": address,
        "domain": domain,
        "label": (body.get("label") or "").strip()[:120],
        "deliver_to": deliver_to,
        "from_name": (body.get("from_name") or "").strip()[:120],
        "send_via": send_via,
        "enabled": True,
        "created_at": _now(),
    }
    db.aliases.insert_one(doc)
    return _format_alias(doc, 0)


@router.patch("/admin/aliases/{address}")
def update_alias(address: str, body: dict = Body(...)):
    db = _db()
    address = _clean_address(address)
    if not db.aliases.find_one({"address": address}):
        raise HTTPException(status_code=404, detail="Alias not found")
    updates = {}
    if "label" in body:
        updates["label"] = (body["label"] or "").strip()[:120]
    if "from_name" in body:
        updates["from_name"] = (body["from_name"] or "").strip()[:120]
    if "enabled" in body:
        updates["enabled"] = bool(body["enabled"])
    if "deliver_to" in body:
        target = _clean_address(body["deliver_to"])
        _need_account(target)
        updates["deliver_to"] = target
    if "send_via" in body:
        updates["send_via"] = _valid_provider_id(body["send_via"])
    if updates:
        db.aliases.update_one({"address": address}, {"$set": updates})
    return _format_alias(db.aliases.find_one({"address": address}))


@router.delete("/admin/aliases/{address}")
def delete_alias(address: str):
    address = _clean_address(address)
    res = _db().aliases.delete_one({"address": address})
    if not res.deleted_count:
        raise HTTPException(status_code=404, detail="Alias not found")
    return {"message": "Alias deleted", "address": address}


# ---------------------------------------------------------------------------
# Domain settings (catch-all target, default provider, provider DNS notes)
# ---------------------------------------------------------------------------

def clean_web_host(value) -> str | None:
    """'mail.example.com' or 'https://mail.example.com/' -> 'https://mail.example.com'. Empty -> None."""
    v = str(value or "").strip().rstrip("/")
    if not v:
        return None
    if "://" not in v:
        v = "https://" + v
    m = re.fullmatch(r"(https?)://([a-z0-9.\-]+\.[a-z]{2,})(:\d{1,5})?", v.lower())
    if not m:
        raise HTTPException(status_code=422, detail="Enter a web address like https://mail.example.com (no path)")
    return v.lower()


@router.patch("/admin/domains/{domain}")
def update_domain(domain: str, body: dict = Body(...)):
    db = _db()
    domain = domain.strip().lower()
    if not db.domains.find_one({"domain": domain}):
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")
    updates = {}
    if "catch_all_to" in body:
        target = _clean_address(body["catch_all_to"])
        if target:
            _need_account(target)
        updates["catch_all_to"] = target or None
    if "send_via" in body:
        updates["send_via"] = _valid_provider_id(body["send_via"])
    if "web_host" in body:
        updates["web_host"] = clean_web_host(body.get("web_host"))
    if "mail_host" in body:
        mh = str(body.get("mail_host") or "").strip().lower().rstrip(".")
        if mh and not re.fullmatch(r"[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+", mh):
            raise HTTPException(status_code=422, detail="Enter a hostname like mail.example.com")
        updates["mail_host"] = mh or None
    if "extra_dns_records" in body:
        records = []
        for r in (body["extra_dns_records"] or [])[:50]:
            rtype = str(r.get("type", "")).upper().strip()
            if rtype not in {"TXT", "CNAME", "MX", "A"}:
                raise HTTPException(status_code=422, detail=f"Unsupported record type '{rtype}'")
            name = str(r.get("name", "")).strip()
            value = str(r.get("value", "")).strip()
            if not name or not value:
                raise HTTPException(status_code=422, detail="Each provider record needs a host and a value")
            records.append({"type": rtype, "name": name[:255], "value": value[:2000],
                            "note": str(r.get("note", ""))[:200]})
        updates["extra_dns_records"] = records
    if updates:
        db.domains.update_one({"domain": domain}, {"$set": updates})
    doc = db.domains.find_one({"domain": domain}, {"_id": 0, "dkim_private_enc": 0})
    doc["created_at"] = _iso(doc.get("created_at"))
    return doc


# ---------------------------------------------------------------------------
# DNS records + live check
# ---------------------------------------------------------------------------

def _server_ip() -> str:
    # The dynamic-IP checker (ddns_ext) keeps the live address in settings; SERVER_IP from .env is the start value.
    try:
        live = _db().settings.find_one({"_id": "ddns"}, {"ip": 1, "enabled": 1}) or {}
        if live.get("enabled") and live.get("ip"):
            return live["ip"]
    except Exception:
        pass
    if _cfg.server_ip:
        return _cfg.server_ip
    try:
        return socket.gethostbyname(_cfg.smtp_hostname)
    except OSError:
        return ""


def ensure_dkim(domain: str) -> dict:
    """Create the DKIM key pair for a domain on first use."""
    db = _db()
    doc = db.domains.find_one({"domain": domain})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")
    if doc.get("dkim_private_enc") and doc.get("dkim_public"):
        return doc
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    db.domains.update_one({"domain": domain}, {"$set": {
        "dkim_selector": _cfg.dkim_selector,
        "dkim_private_enc": encrypt_secret(private_pem),
        "dkim_public": base64.b64encode(public_der).decode(),
    }})
    return db.domains.find_one({"domain": domain})


def _provider_spf_includes(domain_doc: dict) -> list:
    db = _db()
    includes = []
    ids = set()
    if domain_doc.get("send_via"):
        ids.add(domain_doc["send_via"])
    for a in db.aliases.find({"domain": domain_doc["domain"], "send_via": {"$ne": None}}, {"send_via": 1}):
        ids.add(a["send_via"])
    default = db.smtp_providers.find_one({"is_default": True})
    if default:
        ids.add(str(default["_id"]))
    for pid in ids:
        try:
            p = db.smtp_providers.find_one({"_id": ObjectId(pid)})
        except Exception:
            p = None
        if p and p.get("spf_include") and p["spf_include"] not in includes:
            includes.append(p["spf_include"])
    return includes


def mail_host_for(domain: str) -> str:
    """The mail server name a domain's MX points to: its own (Setup > Domains) or SMTP_HOSTNAME from .env."""
    d = _db().domains.find_one({"domain": domain}, {"mail_host": 1}) if domain else None
    return (d or {}).get("mail_host") or _cfg.smtp_hostname


def _host_warning(host: str) -> str:
    """Warn when the mail server name belongs to a domain that is no longer active here (e.g. after moving domains)."""
    active = [d["domain"] for d in _db().domains.find({"is_active": True}, {"domain": 1})]
    if any(host == d or host.endswith("." + d) for d in active):
        return ""
    return (f"The mail server name {host} is not on any of your active domains. That is fine while its DNS still points "
            "here; if you gave that domain up, set a mail server name for this domain below (and get a TLS certificate for it), "
            "or change SMTP_HOSTNAME / IMAP_HOSTNAME in .env.")


def build_dns_records(domain: str) -> dict:
    doc = ensure_dkim(domain)
    host = mail_host_for(domain)
    ip = _server_ip()
    includes = _provider_spf_includes(doc)

    spf_parts = ["v=spf1"]
    if ip:
        spf_parts.append(f"ip4:{ip}")
    spf_parts += [f"include:{i}" for i in includes]
    spf_parts.append("~all")

    selector = doc.get("dkim_selector", _cfg.dkim_selector)
    dkim_value = f"v=DKIM1; k=rsa; p={doc['dkim_public']}"

    records = [
        {"id": "a", "type": "A", "name": host.split(".")[0] if host.endswith("." + domain) else host,
         "fqdn": host, "value": ip or "YOUR_SERVER_IP", "priority": None, "required": True,
         "purpose": "Points your mail hostname at this server",
         "note": "Create this once for your mail hostname. If the hostname lives on a different domain, add it there."},
        {"id": "mx", "type": "MX", "name": "@", "fqdn": domain, "value": host, "priority": 10, "required": True,
         "purpose": "Tells the internet to deliver mail for this domain to this server", "note": ""},
        {"id": "spf", "type": "TXT", "name": "@", "fqdn": domain, "value": " ".join(spf_parts),
         "priority": None, "required": True,
         "purpose": "SPF: which servers may send mail for this domain",
         "note": "Includes your server IP and any SMTP provider you have linked. Only one SPF record per domain is allowed."},
        {"id": "dkim", "type": "TXT", "name": f"{selector}._domainkey", "fqdn": f"{selector}._domainkey.{domain}",
         "value": dkim_value, "priority": None, "required": True,
         "purpose": "DKIM: public key used to verify signed outgoing mail",
         "note": "Long value. Most DNS panels split it into 255-character chunks automatically."},
        {"id": "dmarc", "type": "TXT", "name": "_dmarc", "fqdn": f"_dmarc.{domain}",
         "value": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}", "priority": None, "required": True,
         "purpose": "DMARC: what receivers should do with mail that fails SPF/DKIM",
         "note": "Starts in monitor mode (p=none). Switch to p=quarantine once everything passes."},
    ]
    return {
        "domain": domain,
        "mail_host": host,
        "mail_host_default": _cfg.smtp_hostname,
        "mail_host_warning": _host_warning(host),
        "server_ip": ip,
        "records": records,
        "provider_records": doc.get("extra_dns_records", []),
    }


@router.get("/admin/domains/{domain}/dns")
def get_dns_records(domain: str):
    return build_dns_records(domain.strip().lower())


def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = 6
    r.timeout = 3
    return r


def _lookup(name: str, rtype: str) -> list:
    import dns.exception
    import dns.resolver
    try:
        answers = _resolver().resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        raise RuntimeError(str(exc) or exc.__class__.__name__)
    out = []
    for r in answers:
        if rtype == "TXT":
            out.append("".join(s.decode("utf-8", "replace") for s in r.strings))
        elif rtype == "MX":
            out.append(f"{r.preference} {str(r.exchange).rstrip('.').lower()}")
        else:
            out.append(str(r).rstrip("."))
    return out


def _check_record(rec: dict, ip: str) -> dict:
    result = {"id": rec["id"], "status": "missing", "found": []}
    try:
        if rec["id"] == "a":
            found = _lookup(rec["fqdn"], "A")
            result["found"] = found
            if found:
                result["status"] = "ok" if (not ip or ip in found) else "mismatch"
        elif rec["id"] == "mx":
            found = _lookup(rec["fqdn"], "MX")
            result["found"] = found
            if found:
                hosts = [f.split(" ", 1)[1] for f in found]
                result["status"] = "ok" if rec["value"].lower().rstrip(".") in hosts else "mismatch"
        elif rec["id"] == "spf":
            found = [t for t in _lookup(rec["fqdn"], "TXT") if t.lower().startswith("v=spf1")]
            result["found"] = found
            if found:
                want = [p for p in rec["value"].split() if p.startswith(("ip4:", "include:"))]
                ok = all(p in found[0].split() for p in want)
                result["status"] = "ok" if ok and len(found) == 1 else "mismatch"
        elif rec["id"] == "dkim":
            found = [t for t in _lookup(rec["fqdn"], "TXT") if "v=dkim1" in t.lower()]
            result["found"] = [f[:80] + ("…" if len(f) > 80 else "") for f in found]
            if found:
                want = rec["value"].split("p=", 1)[1].strip()
                have = found[0].replace(" ", "").split("p=", 1)[-1].split(";")[0]
                result["status"] = "ok" if have == want else "mismatch"
        elif rec["id"] == "dmarc":
            found = [t for t in _lookup(rec["fqdn"], "TXT") if t.lower().startswith("v=dmarc1")]
            result["found"] = found
            result["status"] = "ok" if found else "missing"
    except RuntimeError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    return result


@router.post("/admin/domains/{domain}/dns/check")
def check_dns(domain: str):
    data = build_dns_records(domain.strip().lower())
    results = [_check_record(r, data["server_ip"]) for r in data["records"]]
    return {"domain": data["domain"], "results": results,
            "all_ok": all(r["status"] == "ok" for r in results)}


# ---------------------------------------------------------------------------
# SMTP providers
# ---------------------------------------------------------------------------

PRESETS = [
    {"id": "mailjet", "name": "Mailjet", "host": "in-v3.mailjet.com", "port": 587, "security": "starttls",
     "username_label": "API Key", "password_label": "Secret Key", "spf_include": "spf.mailjet.com",
     "help": "Mailjet > Account settings > SMTP and SEND API settings. Username is your API key, password is your secret key. "
             "Add your sending domain under Sender domains & addresses and copy the DKIM/SPF records it shows."},
    {"id": "sendgrid", "name": "SendGrid", "host": "smtp.sendgrid.net", "port": 587, "security": "starttls",
     "username_label": "Username (literally: apikey)", "password_label": "API key", "spf_include": "sendgrid.net",
     "help": "Username is the word apikey; password is an API key with Mail Send permission. Authenticate your domain in Sender Authentication."},
    {"id": "brevo", "name": "Brevo (Sendinblue)", "host": "smtp-relay.brevo.com", "port": 587, "security": "starttls",
     "username_label": "SMTP login", "password_label": "SMTP key", "spf_include": "spf.brevo.com",
     "help": "Brevo > SMTP & API > SMTP. Use the login shown there and a generated SMTP key."},
    {"id": "mailgun", "name": "Mailgun", "host": "smtp.mailgun.org", "port": 587, "security": "starttls",
     "username_label": "SMTP username (postmaster@your-domain)", "password_label": "SMTP password", "spf_include": "mailgun.org",
     "help": "Mailgun > Sending > Domains > your domain > SMTP credentials."},
    {"id": "ses", "name": "Amazon SES", "host": "email-smtp.us-east-1.amazonaws.com", "port": 587, "security": "starttls",
     "username_label": "SMTP username", "password_label": "SMTP password", "spf_include": "amazonses.com",
     "help": "Use SMTP credentials (not your AWS login). Change the region in the host name if yours is not us-east-1."},
    {"id": "postmark", "name": "Postmark", "host": "smtp.postmarkapp.com", "port": 587, "security": "starttls",
     "username_label": "Server API token", "password_label": "Server API token", "spf_include": "spf.mtasv.net",
     "help": "Postmark uses the Server API token as both username and password."},
    {"id": "smtp2go", "name": "SMTP2GO", "host": "mail.smtp2go.com", "port": 587, "security": "starttls",
     "username_label": "SMTP username", "password_label": "SMTP password", "spf_include": "spf.smtp2go.com",
     "help": "SMTP2GO > Settings > SMTP Users."},
    {"id": "resend", "name": "Resend", "host": "smtp.resend.com", "port": 465, "security": "ssl",
     "username_label": "Username (literally: resend)", "password_label": "API key", "spf_include": "",
     "help": "Username is the word resend; password is your API key. Resend gives you its own SPF/DKIM records for your domain."},
    {"id": "gmail", "name": "Gmail / Google Workspace", "host": "smtp.gmail.com", "port": 587, "security": "starttls",
     "username_label": "Gmail address", "password_label": "App password", "spf_include": "_spf.google.com",
     "help": "Requires 2-step verification and an App Password. Gmail rewrites the From address unless it is a verified alias."},
    {"id": "custom", "name": "Other / custom SMTP", "host": "", "port": 587, "security": "starttls",
     "username_label": "Username", "password_label": "Password", "spf_include": "",
     "help": "Any SMTP relay. 587 usually means STARTTLS, 465 means SSL/TLS."},
]


@router.get("/admin/smtp-presets")
def smtp_presets():
    return {"presets": PRESETS}


def _provider_public(p: dict) -> dict:
    return {
        "id": str(p["_id"]),
        "name": p.get("name", ""),
        "preset": p.get("preset", "custom"),
        "host": p.get("host", ""),
        "port": p.get("port", 587),
        "security": p.get("security", "starttls"),
        "username": p.get("username", ""),
        "has_password": bool(p.get("password_enc")),
        "is_default": bool(p.get("is_default")),
        "sign_dkim": bool(p.get("sign_dkim")),
        "spf_include": p.get("spf_include", ""),
        "owner": p.get("owner") or None,
        "created_at": _iso(p.get("created_at")),
    }


def _valid_provider_id(value):
    if not value:
        return None
    try:
        oid = ObjectId(str(value))
    except Exception:
        raise HTTPException(status_code=422, detail="Unknown SMTP provider")
    if not _db().smtp_providers.find_one({"_id": oid}, {"_id": 1}):
        raise HTTPException(status_code=422, detail="Unknown SMTP provider")
    return str(oid)


# Providers with an "owner" belong to one user (multi-account mode) and are never used for anyone else's
# mail. The admin screens and the automatic choice of provider only ever see shared ones (owner: None).
SHARED = {"owner": None}


def _provider_fields(body: dict, partial: bool = False) -> dict:
    out = {}

    def take(key, required=False):
        if key in body:
            out[key] = str(body[key]).strip()
        elif required and not partial:
            raise HTTPException(status_code=422, detail=f"'{key}' is required")

    take("name", required=True)
    take("preset")
    take("host", required=True)
    take("username")
    take("spf_include")
    if "port" in body or not partial:
        try:
            out["port"] = int(body.get("port", 587))
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="Port must be a number")
        if not 1 <= out["port"] <= 65535:
            raise HTTPException(status_code=422, detail="Port must be between 1 and 65535")
    if "security" in body or not partial:
        out["security"] = body.get("security", "starttls")
        if out["security"] not in ("starttls", "ssl", "none"):
            raise HTTPException(status_code=422, detail="Security must be starttls, ssl or none")
    if "sign_dkim" in body:
        out["sign_dkim"] = bool(body["sign_dkim"])
    if not partial and not out.get("name"):
        raise HTTPException(status_code=422, detail="Give the provider a name")
    if "host" in out and not re.match(r"^[A-Za-z0-9.\-]+$", out["host"]):
        raise HTTPException(status_code=422, detail="Host name looks invalid")
    return out


@router.get("/admin/smtp-providers")
def list_providers():
    return {"providers": [_provider_public(p) for p in _db().smtp_providers.find(SHARED).sort("created_at", 1)]}


@router.post("/admin/smtp-providers", status_code=201)
def create_provider(body: dict = Body(...)):
    db = _db()
    fields = _provider_fields(body)
    fields["password_enc"] = encrypt_secret(body["password"]) if body.get("password") else ""
    fields["created_at"] = _now()
    fields["is_default"] = bool(body.get("is_default")) or db.smtp_providers.count_documents(SHARED) == 0
    fields.setdefault("sign_dkim", False)
    fields["owner"] = None
    if fields["is_default"]:
        db.smtp_providers.update_many(SHARED, {"$set": {"is_default": False}})
    res = db.smtp_providers.insert_one(fields)
    return _provider_public(db.smtp_providers.find_one({"_id": res.inserted_id}))


def _get_provider(provider_id: str) -> dict:
    try:
        p = _db().smtp_providers.find_one({"_id": ObjectId(provider_id), **SHARED})
    except Exception:
        p = None
    if not p:
        raise HTTPException(status_code=404, detail="SMTP provider not found")
    return p


@router.patch("/admin/smtp-providers/{provider_id}")
def update_provider(provider_id: str, body: dict = Body(...)):
    db = _db()
    p = _get_provider(provider_id)
    fields = _provider_fields(body, partial=True)
    # Pointing a saved login at a different server or user must not silently reuse the stored password.
    if not body.get("password") and any(k in fields and fields[k] != p.get(k) for k in ("host", "port", "username")):
        raise HTTPException(status_code=422, detail="Re-enter the password when you change the server, port or username")
    if body.get("password"):
        fields["password_enc"] = encrypt_secret(body["password"])
    if body.get("is_default"):
        db.smtp_providers.update_many(SHARED, {"$set": {"is_default": False}})
        fields["is_default"] = True
    if fields:
        db.smtp_providers.update_one({"_id": p["_id"]}, {"$set": fields})
    return _provider_public(db.smtp_providers.find_one({"_id": p["_id"]}))


@router.delete("/admin/smtp-providers/{provider_id}")
def delete_provider(provider_id: str):
    db = _db()
    p = _get_provider(provider_id)
    pid = str(p["_id"])
    db.smtp_providers.delete_one({"_id": p["_id"]})
    db.aliases.update_many({"send_via": pid}, {"$set": {"send_via": None}})
    db.domains.update_many({"send_via": pid}, {"$set": {"send_via": None}})
    if p.get("is_default"):
        other = db.smtp_providers.find_one(SHARED)
        if other:
            db.smtp_providers.update_one({"_id": other["_id"]}, {"$set": {"is_default": True}})
    return {"message": "Provider deleted"}


def _smtp_error_text(exc: Exception) -> str:
    def _txt(v):
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)

    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "Authentication failed. Check the username/password (or API key and secret) for this provider."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "The provider refused the recipient address."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return ("The provider refused the sender address. Verify this sender or domain in the provider's dashboard "
                f"(SMTP said: {exc.smtp_code} {_txt(exc.smtp_error)}).")
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"SMTP error {exc.smtp_code}: {_txt(exc.smtp_error)}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out. Check the host and port, and that your server allows outbound SMTP."
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc}. Try the other security mode (STARTTLS for 587, SSL/TLS for 465)."
    if isinstance(exc, OSError):
        return f"Could not connect: {exc}"
    return f"{exc.__class__.__name__}: {exc}"


def _open_smtp(p: dict):
    host, port, security = p["host"], int(p.get("port", 587)), p.get("security", "starttls")
    ctx = ssl.create_default_context()
    if security == "ssl":
        conn = smtplib.SMTP_SSL(host, port, timeout=25, context=ctx)
        conn.ehlo()
    else:
        conn = smtplib.SMTP(host, port, timeout=25)
        conn.ehlo()
        if security == "starttls":
            conn.starttls(context=ctx)
            conn.ehlo()
    if p.get("username"):
        conn.login(p["username"], decrypt_secret(p["password_enc"]) if p.get("password_enc") else "")
    return conn


def _build_message(from_email, from_name, to, cc, subject, text, html, reply_to, in_reply_to,
                   attachments) -> EmailMessage:
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=from_email.split("@", 1)[1])
    if reply_to:
        msg["Reply-To"] = reply_to
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    if html:
        plain = text or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip() or " "
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
    else:
        msg.set_content(text or " ")
    for att in attachments or []:
        if isinstance(att.get("raw"), (bytes, bytearray)):  # Drive files and calendar invitations
            raw = bytes(att["raw"])
        else:
            try:
                raw = base64.b64decode(att.get("content", ""), validate=False)
            except Exception:
                raise HTTPException(status_code=422, detail="An attachment could not be decoded")
        ctype = att.get("content_type") or "application/octet-stream"
        maintype, _, subtype = ctype.partition("/")
        extra = {"params": {"method": att["method"]}} if att.get("method") else {}
        msg.add_attachment(raw, maintype=maintype or "application", subtype=subtype or "octet-stream",
                           filename=att.get("filename") or "attachment", **extra)
    return msg


def _dkim_sign(data: bytes, domain_doc: dict) -> bytes:
    if not domain_doc.get("dkim_private_enc"):
        return data
    try:
        import dkim
        private = decrypt_secret(domain_doc["dkim_private_enc"]).encode()
        sig = dkim.sign(data, domain_doc.get("dkim_selector", _cfg.dkim_selector).encode(),
                        domain_doc["domain"].encode(), private,
                        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
        return sig + data
    except Exception as exc:  # signing is best-effort
        logger.warning("DKIM signing failed: %s", exc)
        return data


@router.post("/admin/smtp-providers/{provider_id}/test")
def test_provider(provider_id: str, body: dict = Body(default={})):
    return run_provider_test(_get_provider(provider_id), body)


def run_provider_test(p: dict, body: dict) -> dict:
    try:
        conn = _open_smtp(p)
    except Exception as exc:
        return {"success": False, "message": _smtp_error_text(exc)}
    try:
        to = _clean_address(body.get("to"))
        from_email = _clean_address(body.get("from_email"))
        if to:
            if not ADDRESS_RE.match(from_email):
                return {"success": False, "message": "Enter a valid 'from' address for the test email"}
            msg = _build_message(from_email, "BearerMail", [to], [], "BearerMail SMTP test",
                                 "This is a test message from BearerMail. Your SMTP provider is working.",
                                 "", "", "", [])
            conn.sendmail(from_email, [to], msg.as_bytes())
            return {"success": True, "message": f"Connected, signed in and sent a test email to {to}."}
        return {"success": True, "message": "Connected and signed in successfully."}
    except Exception as exc:
        return {"success": False, "message": _smtp_error_text(exc)}
    finally:
        try:
            conn.quit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def _resolve_sender(from_email: str):
    """Return (owner_mailbox, alias_doc_or_None, domain_doc). Raises if the address may not be used."""
    db = _db()
    domain = from_email.split("@", 1)[1]
    dom = db.domains.find_one({"domain": domain, "is_active": True})
    if not dom:
        raise HTTPException(status_code=422, detail=f"'{domain}' is not one of your active domains")
    if db.accounts.find_one({"address": from_email}, {"_id": 1}):
        return from_email, None, dom
    alias = db.aliases.find_one({"address": from_email})
    if alias:
        if not alias.get("enabled", True):
            raise HTTPException(status_code=422, detail="This alias is disabled")
        return alias["deliver_to"], alias, dom
    if dom.get("catch_all_to"):
        return dom["catch_all_to"], None, dom
    raise HTTPException(status_code=422,
                        detail=f"{from_email} is not a mailbox or alias. Create it under Aliases first.")


def _pick_provider(alias, dom) -> dict:
    db = _db()
    for pid in ((alias or {}).get("send_via"), dom.get("send_via")):
        if pid:
            try:
                p = db.smtp_providers.find_one({"_id": ObjectId(pid)})
            except Exception:
                p = None
            # A private provider is only used for its owner's own alias
            if p and (not p.get("owner") or p.get("owner") == (alias or {}).get("deliver_to")):
                return p
    p = db.smtp_providers.find_one({"is_default": True, **SHARED}) or db.smtp_providers.find_one(SHARED)
    if not p:
        raise HTTPException(status_code=400, detail="No SMTP provider is set up yet. Add one under Setup > SMTP Providers.")
    return p


def _addr_list(value) -> list:
    if isinstance(value, str):
        value = value.split(",")
    return [a.strip() for a in (value or []) if a and a.strip()]


@router.post("/admin/send")
def send_mail(body: dict = Body(...)):
    db = _db()
    from_email = _need_address(body.get("from_email"), "from_email")
    to = _addr_list(body.get("to"))
    cc = _addr_list(body.get("cc"))
    bcc = _addr_list(body.get("bcc"))
    subject = (body.get("subject") or "").strip()
    text = body.get("text") or ""
    html = body.get("html") or ""
    if not to:
        raise HTTPException(status_code=422, detail="Add at least one recipient")
    for a in to + cc + bcc:
        if not ADDRESS_RE.match(a.lower()):
            raise HTTPException(status_code=422, detail=f"'{a}' is not a valid email address")
    if not subject:
        raise HTTPException(status_code=422, detail="Add a subject")
    if not text and not html:
        raise HTTPException(status_code=422, detail="The message body is empty")

    owner, alias, dom = _resolve_sender(from_email)
    as_user = _clean_address(body.get("as_user"))
    if as_user:
        # Multi-account mode: a non-admin may only send as their own mailbox or its aliases,
        # through a provider their admin allowed.
        import users_ext
        acting = db.accounts.find_one({"address": as_user, "is_active": {"$ne": False}})
        if not acting:
            raise HTTPException(status_code=403, detail="Your account is not active")
        if users_ext.role_of(acting) != "admin":
            if owner != as_user:
                raise HTTPException(status_code=403, detail="You can only send from your own address or your aliases")
            provider = users_ext.pick_provider_for(acting, alias, dom)
        else:
            provider = _pick_provider(alias, dom)
    else:
        provider = _pick_provider(alias, dom)
    from_name = (body.get("from_name") or (alias or {}).get("from_name") or "").strip()

    attachments = list(body.get("attachments") or [])
    if body.get("drive_files") or body.get("event_id"):
        import calendar_ext
        import drive_ext
        if not isinstance(body.get("drive_files") or [], list):
            raise HTTPException(status_code=422, detail="drive_files must be a list")
        # Only the sender's own Drive files and events (owner = the mailbox behind the From address)
        attachments += drive_ext.attachments_for_send(owner, body.get("drive_files") or [])
        if body.get("event_id"):
            attachments.append(calendar_ext.invite_attachment(owner, str(body["event_id"]), from_email, to + cc + bcc))

    try:
        msg = _build_message(from_email, from_name, to, cc, subject, text, html,
                             (body.get("reply_to") or "").strip(), (body.get("in_reply_to") or "").strip(),
                             attachments)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid header value: {exc}")

    data = msg.as_bytes()
    if provider.get("sign_dkim"):
        data = _dkim_sign(data, ensure_dkim(dom["domain"]))

    try:
        conn = _open_smtp(provider)
        try:
            conn.sendmail(from_email, to + cc + bcc, data)
        finally:
            try:
                conn.quit()
            except Exception:
                pass
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Send via %s failed: %s", provider.get("name"), exc)
        raise HTTPException(status_code=502, detail=_smtp_error_text(exc))

    message_id = str(msg["Message-ID"])
    db.sent_messages.insert_one({
        "from_address": from_email,
        "owner": owner,
        "to": to + cc,
        "subject": subject,
        "text": text,
        "html": html,
        "resend_id": message_id,
        "provider": provider.get("name", ""),
        "created_at": _now(),
    })
    return {"success": True, "message_id": message_id, "provider": provider.get("name", "")}


def send_system_mail(from_email: str, to: str, subject: str, text: str):
    """Send a plain-text notice (security alerts) through the configured SMTP provider.
    Not stored in Sent. Raises HTTPException / Exception on failure."""
    from_email = _need_address(from_email, "from_email")
    to_list = _addr_list(to)
    if not to_list or not all(ADDRESS_RE.match(a.lower()) for a in to_list):
        raise HTTPException(status_code=422, detail="The alert recipient is not a valid email address")
    _owner, alias, dom = _resolve_sender(from_email)
    provider = _pick_provider(alias, dom)
    msg = _build_message(from_email, "BearerMail", to_list, [], subject, text, "", "", "", None)
    data = msg.as_bytes()
    if provider.get("sign_dkim"):
        data = _dkim_sign(data, ensure_dkim(dom["domain"]))
    conn = _open_smtp(provider)
    try:
        conn.sendmail(from_email, to_list, data)
    finally:
        try:
            conn.quit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# "Connect a mail app" info
# ---------------------------------------------------------------------------

@router.get("/admin/connect-info")
def connect_info(domain: str = ""):
    db = _db()
    host = _cfg.imap_hostname or _cfg.smtp_hostname
    own = db.domains.find_one({"domain": domain.strip().lower()}, {"mail_host": 1}) if domain else None
    if own and own.get("mail_host"):
        host = own["mail_host"]  # this domain's own mail server name (its TLS certificate must cover it)
    providers = [
        {"name": p.get("name"), "host": p.get("host"), "port": p.get("port"),
         "security": p.get("security"), "username": p.get("username"), "is_default": bool(p.get("is_default"))}
        for p in db.smtp_providers.find(SHARED).sort("created_at", 1)
    ]
    return {
        "imap": {"host": host, "port": _cfg.imap_port, "security": "SSL/TLS", "auth": "Normal password",
                 "username": "Your full mailbox address, e.g. you@yourdomain.com",
                 "password": "The password you set for that mailbox"},
        "smtp_providers": providers,
        "mailboxes": [a["address"] for a in db.accounts.find({}, {"address": 1}).sort("address", 1)],
        "submission": _submission_info(),
    }


def _submission_info() -> dict:
    import relay_ext  # imported here: relay_ext itself imports this module
    return relay_ext.submission_info()
