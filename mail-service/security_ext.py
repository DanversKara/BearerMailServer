"""
BearerMail security log, IP blocklist and alerts.

Every part of BearerMail reports what happens on its port here:

* port 25  (mail-service, SMTP)  connections, relay attempts, login attempts, rejected mail
* port 993 (imap-server)          connections, logins from mail apps, failed logins, throttled addresses
* web app  (mail-viewer)          sign-ins, failed passwords, two-factor, sessions
* external accounts (IMAP bridge) Gmail/Outlook connections and failures

Noisy events (a scanner hitting port 25 every few seconds) are grouped per address per hour
with a count, so the log stays small. Everything expires after SECURITY_LOG_DAYS (default 30).

All endpoints here need the admin API key, like the rest of /admin/*.
"""

import ipaddress
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pymongo import DESCENDING

logger = logging.getLogger("bearermail.security")

SECURITY_LOG_DAYS = max(1, int(os.getenv("SECURITY_LOG_DAYS", "30")))

_cfg = {"get_db": None, "require_api_key": None, "send_mail": None}


def configure(get_db, require_api_key, send_mail=None):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key
    _cfg["send_mail"] = send_mail


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


router = APIRouter(dependencies=[Depends(_auth)])


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
    return dt


# Human-readable meaning of every event kind; the web app shows these.
EVENT_KINDS = {
    "smtp": {
        "connect": ("info", "Connected to port 25"),
        "message_received": ("info", "Delivered a message"),
        "relay_attempt": ("warn", "Tried to send mail to a domain that is not yours (relay attempt)"),
        "auth_attempt": ("warn", "Tried to log in on port 25 (BearerMail has no SMTP login, so this is a password-guessing bot)"),
        "blocked": ("warn", "Refused: address is on your block list"),
        "rejected_sender": ("warn", "Refused: sender or address blacklisted in .env"),
        "greylisted": ("info", "Asked to retry later (greylisting)"),
        "rate_limited": ("warn", "Refused: too many messages or recipients"),
        "message_rejected": ("warn", "Message refused (too large, empty or malformed)"),
        "forged_sender": ("alert", "Message failed sender checks (the From address is probably fake)"),
        "unknown_recipient": ("info", "Mail for an address that does not exist"),
    },
    "imap": {
        "connect": ("info", "Connected to port 993"),
        "login_ok": ("info", "Mail app signed in"),
        "login_failed": ("warn", "Wrong mailbox password"),
        "throttled": ("alert", "Too many wrong passwords, address blocked for a while"),
        "too_many_connections": ("warn", "Too many connections from one address"),
        "tls_error": ("info", "Connection without valid TLS (usually a scanner)"),
        "blocked": ("warn", "Refused: address is on your block list"),
        "session_closed": ("info", "Mail app disconnected"),
        "session_kicked": ("warn", "Mail app session ended from the Security page"),
    },
    "web": {
        "login_ok": ("info", "Signed in to the web app"),
        "login_failed": ("warn", "Wrong web app password"),
        "login_2fa_failed": ("alert", "Correct password but wrong two-factor code"),
        "rate_limited": ("alert", "Too many sign-in attempts"),
        "logout": ("info", "Signed out"),
        "sessions_revoked": ("warn", "Other sessions signed out"),
        "2fa_enabled": ("info", "Two-factor sign-in turned on"),
        "2fa_disabled": ("warn", "Two-factor sign-in turned off"),
        "recovery_code_used": ("warn", "Signed in with a recovery code"),
        "blocked": ("warn", "Refused: address is on your block list"),
        "mode_changed": ("warn", "Sign-in mode changed (single password / personal accounts)"),
        "stealth_start": ("warn", "Admin opened someone's mailbox with stealth sign-in"),
        "stealth_end": ("info", "Admin returned from stealth sign-in"),
        "settings_changed": ("warn", "Sign-in settings changed"),
    },
    "relay": {
        "connect": ("info", "Connected to the sending port (587/465)"),
        "login_ok": ("info", "Mail app or script signed in with an SMTP key"),
        "auth_failed": ("warn", "Wrong SMTP key username or password"),
        "auth_throttled": ("alert", "Too many wrong SMTP keys, address refused for a while"),
        "revoked_key_used": ("warn", "Someone tried a revoked SMTP key"),
        "sent": ("info", "Sent a message with an SMTP key"),
        "sender_refused": ("warn", "Tried to send from an address the key does not own"),
        "provider_refused": ("warn", "The SMTP provider refused a message"),
        "provider_failed": ("warn", "The SMTP provider could not be reached"),
        "blocked": ("warn", "Refused: address is on your block list"),
        "key_created": ("info", "SMTP key created"),
        "key_revoked": ("warn", "SMTP key revoked"),
        "key_deleted": ("info", "SMTP key deleted"),
        "app_password_created": ("info", "App password created"),
        "real_password_refused": ("warn", "Mail app used the mailbox password, but app passwords are required"),
    },
    "bridge": {
        "account_connected": ("info", "External account connected"),
        "account_failed": ("warn", "External account could not connect"),
        "account_added": ("info", "External account added"),
        "account_removed": ("info", "External account removed"),
    },
    "system": {
        "ip_blocked": ("warn", "Address added to block list"),
        "ip_unblocked": ("info", "Address removed from block list"),
        "settings_changed": ("info", "Security settings changed"),
        "alert_sent": ("info", "Alert email sent"),
        "alert_failed": ("warn", "Alert email could not be sent"),
        "dmarc_failures": ("warn", "A DMARC report shows mail as your domain that failed the checks"),
    },
}

PORTS = {"smtp": 25, "imap": 993, "relay": "587/465", "web": "web", "bridge": "outbound", "system": None}
_LEVELS = ("info", "warn", "alert")


def init_indexes():
    db = _db()
    ev = db.security_events
    ev.create_index([("last", DESCENDING)])
    ev.create_index([("source", 1), ("kind", 1), ("last", DESCENDING)])
    ev.create_index([("ip", 1), ("last", DESCENDING)])
    ev.create_index("agg_key", unique=True, sparse=True)
    ttl_seconds = SECURITY_LOG_DAYS * 86400
    info = ev.index_information().get("security_ttl")
    if info and info.get("expireAfterSeconds") != ttl_seconds:
        ev.drop_index("security_ttl")
    ev.create_index("expires", expireAfterSeconds=0, name="security_ttl")
    db.ip_blocklist.create_index("ip", unique=True)
    db.security_known_ips.create_index([("scope", 1), ("user", 1), ("ip", 1)], unique=True)
    db.imap_sessions.create_index("last_seen")


# ---------------------------------------------------------------------------
# Recording events
# ---------------------------------------------------------------------------

def _clean(value, limit=200) -> str:
    return value[:limit] if isinstance(value, str) else ("" if value is None else str(value)[:limit])


def record(source: str, kind: str, ip: str = "", user: str = "", detail: str = "",
           level: str | None = None, aggregate: bool | None = None, port=None):
    """Store one event. Never raises: logging must not break mail delivery or logins."""
    try:
        source = _clean(source, 20).lower()
        kind = _clean(kind, 40).lower()
        default_level, _label = EVENT_KINDS.get(source, {}).get(kind, ("info", kind))
        level = level if level in _LEVELS else default_level
        ip, user, detail = _clean(ip, 64), _clean(user, 320).lower(), _clean(detail, 300)
        now = _now()
        expires = now + timedelta(days=SECURITY_LOG_DAYS)
        if aggregate is None:
            aggregate = kind in {"connect", "login_failed", "tls_error", "relay_attempt", "auth_attempt",
                                 "greylisted", "rate_limited", "blocked", "unknown_recipient",
                                 "message_received", "too_many_connections", "session_closed"}
        doc = {"source": source, "kind": kind, "level": level, "ip": ip, "user": user,
               "port": port if port is not None else PORTS.get(source), "detail": detail}
        db = _db()
        if aggregate:
            hour = now.strftime("%Y%m%d%H")
            key = f"{source}|{kind}|{ip}|{user}|{hour}"
            db.security_events.update_one(
                {"agg_key": key},
                {"$inc": {"count": 1},
                 "$set": {"last": now, "expires": expires, "detail": detail, "level": level},
                 "$setOnInsert": {k: v for k, v in doc.items() if k not in ("detail", "level")} | {"first": now, "agg_key": key}},
                upsert=True,
            )
        else:
            db.security_events.insert_one(doc | {"count": 1, "first": now, "last": now, "expires": expires})
        _after_event(source, kind, ip, user, detail)
    except Exception as exc:  # pragma: no cover - logging is best effort
        logger.warning("could not record security event %s/%s: %s", source, kind, exc)


def _format_event(e: dict) -> dict:
    source, kind = e.get("source", ""), e.get("kind", "")
    label = EVENT_KINDS.get(source, {}).get(kind, (None, kind))[1]
    return {
        "id": str(e.get("_id", "")), "source": source, "kind": kind, "label": label,
        "level": e.get("level", "info"), "ip": e.get("ip", ""), "user": e.get("user", ""),
        "port": e.get("port"), "detail": e.get("detail", ""), "count": e.get("count", 1),
        "first": _iso(e.get("first")), "last": _iso(e.get("last")),
    }


# ---------------------------------------------------------------------------
# Alerts (email)
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    "alerts": {
        "enabled": False,
        "to": "",
        "from": "",
        "new_web_login": True,
        "new_imap_login": True,
        "brute_force": True,
        "forged_sender": False,
    },
    "dmarc": {
        "keep_in_inbox": False,
    },
    "privacy": {
        "block_remote_images": True,
        "trusted_senders": [],
        "confirm_suspicious_links": True,
        "strip_link_tracking": True,
    },
}


def get_settings() -> dict:
    doc = _db().settings.find_one({"_id": "security"}) or {}
    out = {}
    for section, defaults in DEFAULT_SETTINGS.items():
        stored = doc.get(section) or {}
        out[section] = {k: stored.get(k, v) for k, v in defaults.items()}
    return out


_alert_lock = threading.Lock()
_alert_recent: dict = {}


def _alert_once(key: str, every_seconds: int) -> bool:
    now = time.time()
    with _alert_lock:
        if len(_alert_recent) > 5000:
            _alert_recent.clear()
        last = _alert_recent.get(key, 0)
        if now - last < every_seconds:
            return False
        _alert_recent[key] = now
        return True


def _is_new_ip(scope: str, user: str, ip: str) -> bool:
    if not ip:
        return False
    res = _db().security_known_ips.update_one(
        {"scope": scope, "user": user, "ip": ip},
        {"$set": {"last": _now()}, "$setOnInsert": {"first": _now()}},
        upsert=True,
    )
    return res.upserted_id is not None


def _after_event(source, kind, ip, user, detail):
    subject = body = None
    alerts = None
    if (source, kind) in {("web", "login_ok"), ("imap", "login_ok")}:
        scope = "web" if source == "web" else "imap"
        first_ever = _db().security_known_ips.count_documents({"scope": scope, "user": user}, limit=1) == 0
        is_new = _is_new_ip(scope, user, ip)
        if not is_new or first_ever:
            return
        alerts = get_settings()["alerts"]
        if source == "web" and alerts["new_web_login"]:
            subject = "BearerMail: new sign-in to the web app"
            body = (f"Someone signed in to your BearerMail web app from an address that has not signed in before.\n\n"
                    f"Address: {ip}\nDetails: {detail or '-'}\nTime: {_now():%Y-%m-%d %H:%M UTC}\n\n"
                    "If this was not you, open Setup > Security, sign out all sessions, change ACCESS_PASSWORD "
                    "and turn on two-factor sign-in.")
        elif source == "imap" and alerts["new_imap_login"]:
            subject = f"BearerMail: {user} signed in from a new address"
            body = (f"A mail app signed in to {user} over IMAP from an address that has not been used before.\n\n"
                    f"Address: {ip}\nApp: {detail or 'unknown'}\nTime: {_now():%Y-%m-%d %H:%M UTC}\n\n"
                    "If this was not you, reset this mailbox's password under Setup > Mailboxes.")
    elif (source, kind) in {("imap", "throttled"), ("web", "rate_limited"), ("web", "login_2fa_failed")}:
        alerts = get_settings()["alerts"]
        if alerts["brute_force"] and _alert_once(f"bf|{source}|{ip}", 6 * 3600):
            port = "the web app" if source == "web" else "port 993 (IMAP)"
            subject = f"BearerMail: password guessing from {ip}"
            body = (f"{ip} made repeated failed sign-in attempts on {port}.\n{detail}\n\n"
                    "BearerMail slowed it down automatically. To shut it out completely, open Setup > Security "
                    "and press Block next to the address.")
    elif (source, kind) == ("smtp", "forged_sender"):
        alerts = get_settings()["alerts"]
        if alerts["forged_sender"] and _alert_once(f"fs|{detail[:80]}", 3600):
            subject = "BearerMail: email with a fake sender received"
            body = f"A message arrived that failed the sender checks (SPF/DKIM/DMARC).\n{detail}\n\nIt is marked with a red warning in the web app."
    if subject and alerts and alerts.get("enabled") and alerts.get("to") and alerts.get("from"):
        threading.Thread(target=_send_alert, args=(alerts, subject, body), daemon=True).start()


def _send_alert(alerts, subject, body):
    sender = _cfg.get("send_mail")
    if not sender:
        return
    try:
        sender(alerts["from"], alerts["to"], subject, body)
        record("system", "alert_sent", detail=subject)
    except Exception as exc:
        logger.warning("alert email failed: %s", exc)
        record("system", "alert_failed", detail=f"{subject}: {str(exc)[:150]}")


# ---------------------------------------------------------------------------
# Block list
# ---------------------------------------------------------------------------

_block_cache = {"ts": 0.0, "nets": []}
_BLOCK_CACHE_SECONDS = 20


def parse_network(value: str):
    value = (value or "").strip()
    if not value:
        raise ValueError("Enter an IP address or range")
    return ipaddress.ip_network(value, strict=False)


# Your own network, Docker's network and loopback: blocking these would cut BearerMail off from itself.
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "::/128")]


def blocked_networks() -> list:
    now = time.time()
    if now - _block_cache["ts"] > _BLOCK_CACHE_SECONDS:
        nets = []
        try:
            for doc in _db().ip_blocklist.find({}, {"ip": 1, "expires_at": 1}):
                exp = doc.get("expires_at")
                if exp and exp.replace(tzinfo=exp.tzinfo or timezone.utc) < _now():
                    continue
                try:
                    nets.append(parse_network(doc["ip"]))
                except ValueError:
                    continue
        except Exception as exc:  # pragma: no cover
            logger.warning("could not load block list: %s", exc)
            nets = _block_cache["nets"]
        _block_cache.update(ts=now, nets=nets)
    return _block_cache["nets"]


def invalidate_block_cache():
    _block_cache["ts"] = 0.0


def is_blocked(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in blocked_networks())


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@router.post("/admin/security/events")
def post_event(body: dict = Body(...)):
    source = body.get("source") if isinstance(body.get("source"), str) else ""
    kind = body.get("kind") if isinstance(body.get("kind"), str) else ""
    if source not in EVENT_KINDS or not kind:
        raise HTTPException(status_code=422, detail="Unknown event source or kind")
    record(source, kind, ip=body.get("ip", ""), user=body.get("user", ""), detail=body.get("detail", ""),
           level=body.get("level") if body.get("level") in _LEVELS else None,
           aggregate=body.get("aggregate") if isinstance(body.get("aggregate"), bool) else None)
    return {"ok": True}


def _since(hours) -> datetime:
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        hours = 24
    return _now() - timedelta(hours=max(0.1, min(hours, SECURITY_LOG_DAYS * 24)))


@router.get("/admin/security/events")
def list_events(source: str = "", kind: str = "", ip: str = "", level: str = "", user: str = "",
                hours: float = 24, limit: int = 200, skip: int = 0):
    query = {"last": {"$gte": _since(hours)}}
    for field, value in (("source", source), ("kind", kind), ("ip", ip), ("user", user.lower())):
        if value:
            query[field] = value
    if level in _LEVELS:
        query["level"] = {"$in": list(_LEVELS[_LEVELS.index(level):])}
    limit = max(1, min(int(limit), 1000))
    cursor = _db().security_events.find(query).sort("last", DESCENDING).skip(max(0, int(skip))).limit(limit)
    return {"events": [_format_event(e) for e in cursor], "retention_days": SECURITY_LOG_DAYS,
            "kinds": {s: {k: v[1] for k, v in ks.items()} for s, ks in EVENT_KINDS.items()}}


@router.get("/admin/security/summary")
def summary(hours: float = 24):
    since = _since(hours)
    events = list(_db().security_events.find({"last": {"$gte": since}},
                                             {"source": 1, "kind": 1, "ip": 1, "count": 1, "level": 1, "user": 1}))
    by_source: dict = {}
    by_ip: dict = {}
    for e in events:
        src, kind, count = e.get("source", ""), e.get("kind", ""), int(e.get("count", 1))
        s = by_source.setdefault(src, {"total": 0, "kinds": {}, "ips": set()})
        s["total"] += count
        s["kinds"][kind] = s["kinds"].get(kind, 0) + count
        if e.get("ip"):
            s["ips"].add(e["ip"])
        if e.get("ip") and e.get("level") in ("warn", "alert"):
            entry = by_ip.setdefault(e["ip"], {"ip": e["ip"], "count": 0, "sources": set(), "kinds": set(), "users": set()})
            entry["count"] += count
            entry["sources"].add(src)
            entry["kinds"].add(kind)
            if e.get("user"):
                entry["users"].add(e["user"])
    blocked = {d["ip"] for d in _db().ip_blocklist.find({}, {"ip": 1})}
    top = sorted(by_ip.values(), key=lambda x: -x["count"])[:15]
    return {
        "hours": hours,
        "sources": {k: {"total": v["total"], "kinds": v["kinds"], "unique_ips": len(v["ips"]), "port": PORTS.get(k)}
                    for k, v in by_source.items()},
        "suspicious_ips": [{"ip": t["ip"], "count": t["count"], "sources": sorted(t["sources"]), "kinds": sorted(t["kinds"]),
                            "users": sorted(t["users"])[:5], "blocked": t["ip"] in blocked} for t in top],
    }


@router.get("/admin/security/imap-sessions")
def imap_sessions():
    cutoff = _now() - timedelta(minutes=5)
    out = []
    for s in _db().imap_sessions.find({"last_seen": {"$gte": cutoff}}).sort("login_at", DESCENDING).limit(200):
        out.append({"id": str(s.get("_id")), "user": s.get("user", ""), "ip": s.get("ip", ""),
                    "client": s.get("client", ""), "folder": s.get("folder", ""),
                    "login_at": _iso(s.get("login_at")), "last_seen": _iso(s.get("last_seen")),
                    "idle": bool(s.get("idle"))})
    return {"sessions": out}


@router.post("/admin/security/imap-sessions/{session_id}/kick")
def kick_imap_session(session_id: str):
    res = _db().imap_sessions.update_one({"_id": session_id}, {"$set": {"kick": True}})
    if not res.matched_count:
        raise HTTPException(status_code=404, detail="That session has already ended")
    return {"ok": True, "message": "The mail app will be disconnected within 30 seconds"}


@router.get("/admin/security/blocklist")
def get_blocklist():
    out = []
    for d in _db().ip_blocklist.find({}).sort("created_at", DESCENDING):
        out.append({"ip": d["ip"], "reason": d.get("reason", ""), "created_at": _iso(d.get("created_at")),
                    "expires_at": _iso(d.get("expires_at"))})
    return {"blocklist": out}


@router.post("/admin/security/blocklist")
def add_block(body: dict = Body(...)):
    raw = body.get("ip") if isinstance(body.get("ip"), str) else ""
    try:
        net = parse_network(raw)
    except ValueError:
        raise HTTPException(status_code=422, detail="That is not a valid IP address or range (e.g. 203.0.113.7 or 203.0.113.0/24)")
    too_large = net.num_addresses > 2 ** 16 if net.version == 4 else net.prefixlen < 48
    if too_large:
        raise HTTPException(status_code=422, detail="That range is too large to block safely")
    protect = [p for p in (body.get("protect") or []) if isinstance(p, str)]
    for p in protect:
        try:
            if ipaddress.ip_address(p) in net:
                raise HTTPException(status_code=409, detail=f"This would block your own current address ({p}). Not blocked.")
        except ValueError:
            continue
    if any(net.version == local.version and net.overlaps(local) for local in _LOCAL_NETS):
        raise HTTPException(status_code=422, detail="Private and local addresses (your own network and Docker) cannot be blocked")
    hours = body.get("hours")
    expires = _now() + timedelta(hours=float(hours)) if isinstance(hours, (int, float)) and hours > 0 else None
    ip_text = str(net) if net.num_addresses > 1 else str(net.network_address)
    _db().ip_blocklist.update_one(
        {"ip": ip_text},
        {"$set": {"reason": _clean(body.get("reason", ""), 200), "expires_at": expires},
         "$setOnInsert": {"created_at": _now()}},
        upsert=True,
    )
    invalidate_block_cache()
    record("system", "ip_blocked", ip=ip_text, detail=_clean(body.get("reason", ""), 200))
    return {"ok": True, "ip": ip_text}


@router.delete("/admin/security/blocklist/{ip:path}")
def remove_block(ip: str):
    res = _db().ip_blocklist.delete_one({"ip": ip})
    if not res.deleted_count:
        raise HTTPException(status_code=404, detail="Not on the block list")
    invalidate_block_cache()
    record("system", "ip_unblocked", ip=ip)
    return {"ok": True}


@router.get("/admin/security/settings")
def read_settings():
    return get_settings()


@router.patch("/admin/security/settings")
def update_settings(body: dict = Body(...)):
    current = get_settings()
    changes = {}
    for section, defaults in DEFAULT_SETTINGS.items():
        incoming = body.get(section)
        if not isinstance(incoming, dict):
            continue
        for key, default in defaults.items():
            if key not in incoming:
                continue
            value = incoming[key]
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    raise HTTPException(status_code=422, detail=f"{section}.{key} must be true or false")
            elif isinstance(default, list):
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise HTTPException(status_code=422, detail=f"{section}.{key} must be a list")
                value = sorted({v.strip().lower()[:320] for v in value if v.strip()})[:500]
            else:
                value = value.strip()[:320] if isinstance(value, str) else ""
            current[section][key] = value
            changes[f"{section}.{key}"] = True
    _db().settings.update_one({"_id": "security"}, {"$set": current}, upsert=True)
    if changes:
        record("system", "settings_changed", detail=", ".join(sorted(changes))[:300])
    return current


@router.post("/admin/security/test-alert")
def test_alert():
    alerts = get_settings()["alerts"]
    if not alerts.get("to") or not alerts.get("from"):
        raise HTTPException(status_code=422, detail="Set the 'send alerts to' and 'send from' addresses first")
    sender = _cfg.get("send_mail")
    if not sender:
        raise HTTPException(status_code=503, detail="Sending is not available")
    try:
        sender(alerts["from"], alerts["to"], "BearerMail: test alert",
               "This is a test of BearerMail security alerts. If you can read this, alerts work.")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)[:200])
    return {"ok": True, "message": f"Test alert sent to {alerts['to']}"}
