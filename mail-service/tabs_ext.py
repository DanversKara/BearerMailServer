"""Inbox tabs: Primary, Favorites, Security, Promotions, Social, Updates, Forums, Work, School + your own.

Every message gets an automatic ``category`` when it arrives (from its headers, sender and subject).
Each mailbox can override that per message or with a rule for a sender / whole domain; those choices are
stored in ``tab_overrides`` ([{"a": mailbox, "t": tab}]) because one stored message can be delivered to
several mailboxes, and each person sorts their own mail.

The Security tab exists so a flood of junk can't bury "your password was changed" / "new sign-in" /
"SIM changed" mail. A burst of incoming mail is also reported as a flood warning.
"""
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
_cfg = {}

CAT_VERSION = 1
FLOOD_THRESHOLD = int(os.getenv("MAIL_FLOOD_THRESHOLD", "30") or 30)  # emails in one hour
MAX_CUSTOM_TABS = 20
MAX_RULES = 500

BUILTIN_TABS = [
    ("primary", "Primary", "bi-inbox"),
    ("favorites", "Favorites", "bi-star"),
    ("security", "Security", "bi-shield-lock"),
    ("promotions", "Promotions", "bi-tag"),
    ("social", "Social", "bi-people"),
    ("updates", "Updates", "bi-info-circle"),
    ("forums", "Forums", "bi-chat-square-text"),
    ("work", "Work", "bi-briefcase"),
    ("school", "School", "bi-mortarboard"),
]
BUILTIN_IDS = [t[0] for t in BUILTIN_TABS]
# Tabs whose mail is decided automatically; the rest only fill up by your choices.
AUTO_TABS = {"security", "promotions", "social", "updates", "forums", "school"}


def configure(get_db, get_account, addr_match, record_event=None):
    _cfg["get_db"] = get_db
    _cfg["addr_match"] = addr_match
    _cfg["get_account"] = get_account
    _cfg["record"] = record_event


def _db():
    return _cfg["get_db"]()


async def _account(request: Request):
    return await _cfg["get_account"](request)


# ---------------------------------------------------------------------------
# Automatic sorting
# ---------------------------------------------------------------------------

_SECURITY = re.compile(
    r"password|passcode|pass code|\bpin\b (?:changed|reset)|"
    r"(?:new|recent|unusual|suspicious|unrecognized|unknown) (?:sign[- ]?in|log[- ]?in|login|device|activity|access)|"
    r"sign[- ]?in (?:attempt|alert|from|detected|notification)|log[- ]?in (?:attempt|alert|from|detected|notification)|"
    r"login (?:attempt|alert|from|detected|notification)|signed in|logged in|"
    r"security (?:alert|notice|notification|warning|code|update|check|key)|"
    r"verification code|security code|confirmation code|access code|login code|sign[- ]?in code|"
    r"one[- ]time (?:code|password|passcode|pin)|\botp\b|\b2fa\b|two[- ](?:factor|step)|multi[- ]factor|\bmfa\b|"
    r"authenticat|unauthori[sz]ed|compromised|"
    r"verify (?:your |this |a )?(?:new )?(?:device|identity|sign[- ]?in|log[- ]?in|login|browser)|confirm (?:it'?s|it was) you|"
    r"was this you|is this you|"
    r"account (?:locked|suspended|disabled|recovery|compromised|access|changes?|was changed|has been changed|update[ds]?)|"
    r"recovery (?:email|phone|code|key)|"
    r"\bsim\b|esim|port[- ]?out|number (?:transfer|port)|"
    r"(?:phone|mobile) number (?:was |has been )?(?:changed|updated|added|removed)|"
    r"email address (?:was |has been )?(?:changed|updated)|"
    r"(?:changed|updated|added|removed|reset) (?:your|the) (?:email|phone|password|number)|"
    r"new (?:phone|device) (?:added|order|activated)|device (?:added|activated|upgrade)",
    re.I,
)
# Subscription-bombing mail ("confirm your subscription") is exactly what a flood looks like; never Security.
_NOT_SECURITY = re.compile(r"subscri|newsletter|mailing list|verify your email|confirm your email|welcome to", re.I)

_PROMO = re.compile(
    r"\d+\s?% off|\bsale\b|\bdeals?\b|save (?:\$|up to|\d)|free shipping|coupon|promo|discount|\boffer|"
    r"limited[- ]time|last chance|shop now|new arrivals?|clearance|black friday|cyber monday|exclusive|"
    r"\bbogo\b|flash sale|ends (?:tonight|today|soon|sunday|midnight)|don'?t miss|\$\d+ off|% off|"
    r"buy (?:one|now|\d)|special (?:price|offer)|lowest price|gift (?:guide|ideas)|members? only",
    re.I,
)
_UPDATES = re.compile(
    r"\border\b|receipt|invoice|statement|\bbill\b|payment|paid|refund|shipped|shipping|delivered|delivery|"
    r"tracking|package|confirm(?:ed|ation)|reservation|booking|itinerary|appointment|reminder|renew|"
    r"subscription|your (?:account|plan|trip|ticket|request)|notification|report|digest|welcome|"
    r"newsletter|weekly|monthly|summary|update|verify your email|confirm your email",
    re.I,
)

_SOCIAL_DOMAINS = (
    "facebook.com", "facebookmail.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "tiktok.com", "pinterest.com", "snapchat.com", "discord.com", "discordapp.com", "nextdoor.com",
    "meetup.com", "tumblr.com", "threads.net", "bsky.app", "messenger.com", "whatsapp.com",
    "telegram.org", "youtube.com", "twitch.tv", "strava.com", "goodreads.com", "hinge.co",
    "tinder.com", "bumble.com", "match.com", "vk.com", "wechat.com", "line.me", "flickr.com",
)
_FORUM_DOMAINS = (
    "googlegroups.com", "groups.io", "discoursemail.com", "discourse.org", "redditmail.com", "reddit.com",
    "stackexchange.com", "stackoverflow.email", "lists.sourceforge.net", "freelists.org", "mailman",
)
_SCHOOL_DOMAIN = re.compile(r"\.(?:edu|k12\.[a-z]{2}\.us|sch\.[a-z]{2}|ac\.[a-z]{2}|edu\.[a-z]{2})$", re.I)
_SCHOOL_SENDERS = ("instructure.com", "canvaslms.com", "blackboard.com", "schoology.com", "powerschool.com",
                   "classroom.google.com", "parentsquare.com", "remind.com", "brightspace.com", "moodle")
_NOREPLY = re.compile(r"no[-_.]?reply|do[-_.]?not[-_.]?reply|notifications?@|alerts?@|info@|news@|marketing@|"
                      r"hello@|team@|updates?@|mailer", re.I)


def _domain_matches(domain: str, suffixes) -> bool:
    domain = (domain or "").lower()
    return any(domain == s or domain.endswith("." + s) or (("." not in s) and s in domain) for s in suffixes)


def _strip_html(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", html or "")
    return re.sub(r"(?s)<[^>]+>", " ", html)


def classify(msg=None, from_email: str = "", subject: str = "", text: str = "", html: str = "",
             verdict: str = "") -> str:
    """Pick the automatic tab for one email. ``msg`` is the parsed email (headers); None for old mail."""
    def header(name):
        try:
            return str(msg.get(name, "") or "") if msg is not None else ""
        except Exception:
            return ""

    from_email = (from_email or "").lower()
    domain = from_email.rsplit("@", 1)[-1] if "@" in from_email else ""
    subject = subject or ""
    body = re.sub(r"\s+", " ", text or _strip_html(html))[:3000]
    list_unsub = bool(header("List-Unsubscribe"))
    list_id = header("List-Id")
    list_post = header("List-Post")
    bulk = header("Precedence").lower() in ("bulk", "list", "junk") or bool(header("X-Campaign") or header("X-Mailchimp-Campaign")
                                                                          or header("X-MC-User") or header("X-CampaignID"))
    automated = bool(header("Auto-Submitted") and header("Auto-Submitted").lower() != "no") or bool(_NOREPLY.search(from_email))

    # Security first: account alerts must never end up buried among promotions.
    # A forged sender (failed SPF/DKIM/DMARC) is not trusted with this tab; it stays in Primary with its warning.
    if verdict != "fail" and not _NOT_SECURITY.search(subject):
        if _SECURITY.search(subject) or (not list_unsub and _SECURITY.search(body[:600])):
            return "security"
    if _domain_matches(domain, _SOCIAL_DOMAINS):
        return "social"
    if list_post or _domain_matches(domain, _FORUM_DOMAINS) or (list_id and not list_unsub and not bulk):
        return "forums"
    if _SCHOOL_DOMAIN.search(domain) or _domain_matches(domain, _SCHOOL_SENDERS):
        return "school"
    mass = list_unsub or bulk or automated
    if _PROMO.search(subject) and (mass or len(_PROMO.findall(body)) >= 2):
        return "promotions"
    if mass and len(_PROMO.findall(body)) >= 3:
        return "promotions"
    if _UPDATES.search(subject) and (mass or automated):
        return "updates"
    if mass:
        return "updates"
    return "primary"


# ---------------------------------------------------------------------------
# Per-mailbox settings and rules
# ---------------------------------------------------------------------------

def _settings(address: str) -> dict:
    doc = _db().mail_tabs.find_one({"_id": address}) or {}
    return {
        "enabled": doc.get("enabled", True),
        "custom": doc.get("custom", []),
        "hidden": doc.get("hidden", []),
        "rules": doc.get("rules", []),
        "order": doc.get("order", []),
    }


def _all_tab_ids(settings: dict) -> list:
    return BUILTIN_IDS + [c["id"] for c in settings["custom"]]


def _rule_match(match: str, from_email: str) -> bool:
    from_email = (from_email or "").lower()
    if match.startswith("@"):
        domain = from_email.rsplit("@", 1)[-1]
        return domain == match[1:] or domain.endswith("." + match[1:])
    return from_email == match


def _rule_for(rules: list, from_email: str):
    # An exact address beats a whole-domain rule.
    exact = [r for r in rules if not r["match"].startswith("@") and _rule_match(r["match"], from_email)]
    if exact:
        return exact[0]["tab"]
    dom = [r for r in rules if r["match"].startswith("@") and _rule_match(r["match"], from_email)]
    return dom[0]["tab"] if dom else None


def overrides_for(to_addresses: list, from_email: str) -> list:
    """At delivery: the mailboxes (among the recipients) whose rules pick a tab for this sender."""
    out = []
    try:
        for doc in _db().mail_tabs.find({"_id": {"$in": list(to_addresses)}, "rules.0": {"$exists": True}}):
            tab = _rule_for(doc.get("rules", []), from_email)
            if tab:
                out.append({"a": doc["_id"], "t": tab})
    except Exception:
        pass
    return out


def effective_tab(msg: dict, address: str, settings: dict | None = None) -> str:
    for o in msg.get("tab_overrides") or []:
        if o.get("a") == address:
            tab = o.get("t")
            break
    else:
        tab = msg.get("category") or "primary"
    if settings is not None:
        if tab not in _all_tab_ids(settings) or tab in settings["hidden"]:
            return "primary"
    return tab


def tab_filter(address: str, tab: str) -> dict:
    """Mongo condition for the messages of one tab (add it to the mailbox's usual filter)."""
    settings = _settings(address)
    if not settings["enabled"] or not tab or tab == "all":
        return {}
    known = _all_tab_ids(settings)
    if tab not in known:
        tab = "primary"
    if tab == "primary":
        # Primary also holds everything whose tab is switched off or no longer exists.
        falls_back = [t for t in known if t in settings["hidden"]]
        mine = {"a": address, "t": {"$nin": [t for t in known if t != "primary" and t not in settings["hidden"]]}}
        return {"$or": [
            {"tab_overrides": {"$elemMatch": mine}},
            {"tab_overrides": {"$not": {"$elemMatch": {"a": address}}},
             "category": {"$in": [None, "primary", *falls_back, *[c for c in AUTO_TABS if c not in known]]}},
        ]}
    return {"$or": [
        {"tab_overrides": {"$elemMatch": {"a": address, "t": tab}}},
        {"tab_overrides": {"$not": {"$elemMatch": {"a": address}}}, "category": tab},
    ]}


def _set_tab(address: str, query: dict, tab: str) -> int:
    db = _db()
    db.messages.update_many(query, {"$pull": {"tab_overrides": {"a": address}}})
    return db.messages.update_many(query, {"$push": {"tab_overrides": {"a": address, "t": tab}}}).modified_count


def _mailbox_query(account: dict) -> dict:
    return {"to_addresses": _cfg["addr_match"](account)}


def backfill(account: dict, limit: int = 50000):
    """Sort mail stored before tabs existed (no headers were kept, so this uses sender + subject + body).
    Runs once per mailbox in practice; later calls find nothing left to do."""
    import mail_auth  # noqa: PLC0415

    db = _db()
    base = _mailbox_query(account)
    pending = {}  # category -> ids; one update per category keeps this fast on big mailboxes

    def flush():
        for cat, ids in pending.items():
            db.messages.update_many({"_id": {"$in": ids}}, {"$set": {"category": cat, "cat_v": CAT_VERSION}})
        pending.clear()

    count = 0
    cursor = db.messages.find({**base, "cat_v": {"$exists": False}},
                              {"from": 1, "subject": 1, "text": 1, "html": 1, "auth": 1}).limit(limit)
    for m in cursor:
        try:
            verdict = mail_auth.auth_verdict(m.get("auth"))
        except Exception:
            verdict = ""
        cat = classify(None, (m.get("from") or {}).get("address", ""), m.get("subject", ""),
                       (m.get("text") or "")[:5000], (m.get("html") or "")[:20000], verdict)
        pending.setdefault(cat, []).append(m["_id"])
        count += 1
        if count % 1000 == 0:
            flush()
    flush()


_flood_reported = {}


def _flood(account: dict) -> dict | None:
    db = _db()
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    q = {**_mailbox_query(account), "is_deleted": {"$ne": True}, "created_at": {"$gte": since}}
    count = db.messages.count_documents(q)
    if count < FLOOD_THRESHOLD:
        return None
    senders = {(m.get("from") or {}).get("address", "") for m in db.messages.find(q, {"from.address": 1}).limit(2000)}
    address = account["address"]
    security_count = db.messages.count_documents({**q, **tab_filter(address, "security")})
    last = _flood_reported.get(address)
    if _cfg.get("record") and (not last or datetime.now(timezone.utc) - last > timedelta(hours=1)):
        _flood_reported[address] = datetime.now(timezone.utc)
        _cfg["record"]("smtp", "mail_flood", user=address,
                       detail=f"{count} emails in the last hour from {len(senders)} senders")
    return {"count": count, "senders": len(senders), "security": security_count}


# ---------------------------------------------------------------------------
# Endpoints (mailbox token auth, like /messages)
# ---------------------------------------------------------------------------

def _tabs_payload(account: dict) -> dict:
    address = account["address"]
    settings = _settings(address)
    backfill(account)
    counts = {}
    for m in _db().messages.find({**_mailbox_query(account), "is_deleted": {"$ne": True}},
                                 {"category": 1, "tab_overrides": 1, "seen": 1}):
        tab = effective_tab(m, address, settings)
        c = counts.setdefault(tab, [0, 0])
        c[0] += 1
        if not m.get("seen"):
            c[1] += 1
    tabs = []
    for tid, name, icon in BUILTIN_TABS:
        tabs.append({"id": tid, "name": name, "icon": icon, "builtin": True, "auto": tid in AUTO_TABS,
                     "hidden": tid in settings["hidden"], "total": counts.get(tid, [0, 0])[0],
                     "unread": counts.get(tid, [0, 0])[1]})
    for c in settings["custom"]:
        tabs.append({"id": c["id"], "name": c["name"], "icon": c.get("icon") or "bi-folder", "builtin": False,
                     "auto": False, "hidden": c["id"] in settings["hidden"],
                     "total": counts.get(c["id"], [0, 0])[0], "unread": counts.get(c["id"], [0, 0])[1]})
    # Your own order (dragged in the web app); tabs not in it keep their usual place after the ordered ones.
    rank = {tid: i for i, tid in enumerate(settings["order"])}
    tabs = [t for _, t in sorted(enumerate(tabs), key=lambda it: (rank.get(it[1]["id"], len(rank) + it[0]), it[0]))]
    return {"enabled": settings["enabled"], "tabs": tabs, "rules": settings["rules"],
            "flood": _flood(account), "threshold": FLOOD_THRESHOLD}


@router.get("/messages/tabs")
async def get_tabs(request: Request):
    account = await _account(request)
    return _tabs_payload(account)


def _clean_name(value) -> str:
    name = re.sub(r"\s+", " ", str(value or "")).strip()[:30]
    if not name:
        raise HTTPException(status_code=422, detail="Give the tab a name")
    return name


def _clean_match(value) -> str:
    value = str(value or "").strip().lower()
    if not re.fullmatch(r"(?:[^@\s]+@|@)[a-z0-9.-]+\.[a-z]{2,}", value):
        raise HTTPException(status_code=422, detail="A rule needs an email address or @domain")
    return value


@router.post("/messages/tabs/settings")
async def update_tabs(request: Request):
    account = await _account(request)
    address = account["address"]
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Invalid request")
    db = _db()
    settings = _settings(address)
    update = {}
    if "enabled" in data:
        update["enabled"] = bool(data["enabled"])
    if "order" in data and isinstance(data["order"], list):
        known = set(_all_tab_ids(settings))
        update["order"] = list(dict.fromkeys(str(t) for t in data["order"] if str(t) in known))
    if "hidden" in data and isinstance(data["hidden"], list):
        known = set(_all_tab_ids(settings)) - {"primary"}
        update["hidden"] = [t for t in data["hidden"] if t in known]
    custom = list(settings["custom"])
    rules = list(settings["rules"])
    if data.get("add_tab"):
        name = _clean_name(data["add_tab"])
        existing = {c["name"].lower(): c for c in custom} | {n.lower(): {"id": i} for i, n, _ in BUILTIN_TABS}
        if name.lower() in existing:
            return {**_tabs_payload(account), "tab_id": existing[name.lower()]["id"]}
        if len(custom) >= MAX_CUSTOM_TABS:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_CUSTOM_TABS} tabs of your own")
        new_id = "c_" + secrets.token_hex(4)
        custom.append({"id": new_id, "name": name, "icon": "bi-folder"})
        update["custom"] = custom
        data["_new_id"] = new_id
    if data.get("rename_tab") and isinstance(data["rename_tab"], dict):
        tid = data["rename_tab"].get("id")
        for c in custom:
            if c["id"] == tid:
                c["name"] = _clean_name(data["rename_tab"].get("name"))
        update["custom"] = custom
    if data.get("remove_tab"):
        tid = str(data["remove_tab"])
        if tid in BUILTIN_IDS:
            raise HTTPException(status_code=422, detail="Built-in tabs can be hidden, not removed")
        custom = [c for c in custom if c["id"] != tid]
        rules = [r for r in rules if r["tab"] != tid]
        update["custom"] = custom
        update["rules"] = rules
        # Its mail goes back to where it would be sorted automatically.
        db.messages.update_many({**_mailbox_query(account)}, {"$pull": {"tab_overrides": {"a": address, "t": tid}}})
    if data.get("remove_rule"):
        match = str(data["remove_rule"]).lower()
        update["rules"] = [r for r in rules if r["match"] != match]
    if update:
        db.mail_tabs.update_one({"_id": address}, {"$set": update}, upsert=True)
    out = _tabs_payload(account)
    if data.get("_new_id"):
        out["tab_id"] = data["_new_id"]
    return out


@router.post("/messages/tabs/move")
async def move_to_tab(request: Request):
    """Put messages in a tab; optionally remember it for everything from the sender (or their domain)."""
    from bson import ObjectId  # noqa: PLC0415

    account = await _account(request)
    address = account["address"]
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Invalid request")
    settings = _settings(address)
    tab = str(data.get("tab") or "")
    if tab not in _all_tab_ids(settings):
        raise HTTPException(status_code=422, detail="Unknown tab")
    oids = []
    for mid in data.get("message_ids") or []:
        try:
            oids.append(ObjectId(str(mid)))
        except Exception:
            pass
    base = _mailbox_query(account)
    moved = _set_tab(address, {**base, "_id": {"$in": oids}}, tab) if oids else 0

    rule = data.get("rule") or ""
    matches = []
    if rule in ("sender", "domain"):
        senders = {(m.get("from") or {}).get("address", "").lower()
                   for m in _db().messages.find({**base, "_id": {"$in": oids}}, {"from.address": 1})}
        for s in data.get("senders") or []:
            senders.add(str(s).lower())
        for s in senders:
            if "@" not in s:
                continue
            matches.append(s if rule == "sender" else "@" + s.rsplit("@", 1)[1])
    elif data.get("match"):
        matches.append(_clean_match(data["match"]))
    if matches:
        rules = [r for r in settings["rules"] if r["match"] not in matches]
        now = datetime.now(timezone.utc)
        for m in dict.fromkeys(matches):
            rules.append({"match": _clean_match(m), "tab": tab, "created_at": now})
        if len(rules) > MAX_RULES:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_RULES} sorting rules")
        _db().mail_tabs.update_one({"_id": address}, {"$set": {"rules": rules}}, upsert=True)
        # Also sort the mail already here from those senders.
        for m in dict.fromkeys(matches):
            if m.startswith("@"):
                sender_q = {"from.address": {"$regex": r"(@|\.)" + re.escape(m[1:]) + r"$", "$options": "i"}}
            else:
                sender_q = {"from.address": m}
            moved += _set_tab(address, {**base, **sender_q}, tab)
    return {**_tabs_payload(account), "moved": moved, "new_rules": matches}
