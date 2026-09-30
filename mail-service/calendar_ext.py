"""
BearerMail Calendar.

Each mailbox has its own events. Events can be added by hand, imported from an email (the .ics invite
attached to it, or pre-filled from the subject), attached to an outgoing email as an invitation
(an .ics file every calendar app understands), exported as .ics, and shared with a short link
(drive_ext handles the links). Times are stored in UTC; the web app shows them in the viewer's time zone.
"""

import re
import secrets
from datetime import date, datetime, timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import Response

import bearer_ext as ext
import drive_ext

_cfg = {"get_db": None, "require_api_key": None, "hostname": ""}


def configure(get_db, require_api_key, hostname: str = ""):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key
    _cfg["hostname"] = hostname or "bearermail.local"


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


router = APIRouter(dependencies=[Depends(_auth)])
COLORS = ("blue", "green", "red", "orange", "purple", "teal", "gray")


def _now():
    return datetime.now(timezone.utc)


def init_indexes():
    _db().events.create_index([("owner", 1), ("start", 1)])


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_when(value, all_day: bool = False) -> datetime:
    """ISO date ("2026-10-02") or date-time ("2026-10-02T15:00:00Z", with or without an offset) to UTC."""
    if isinstance(value, datetime):
        return _utc(value)
    text = str(value or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="Enter a start time")
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            d = date.fromisoformat(text)
            return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"'{text[:40]}' is not a date or time")
    if all_day:
        return datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc)
    return _utc(dt)


def _event(owner: str, event_id: str) -> dict:
    try:
        e = _db().events.find_one({"_id": ObjectId(event_id), "owner": owner})
    except Exception:
        e = None
    if not e:
        raise HTTPException(status_code=404, detail="Event not found")
    return e


def public_event(e: dict) -> dict:
    if not e:
        return {}
    return {"id": str(e["_id"]), "title": e.get("title", ""), "start": ext._iso(e.get("start")), "end": ext._iso(e.get("end")),
            "all_day": bool(e.get("all_day")), "location": e.get("location", ""), "description": e.get("description", ""),
            "attendees": e.get("attendees", []), "color": e.get("color", "blue"), "uid": e.get("uid", ""),
            "source": (e.get("source") or {}).get("kind", "manual"), "organizer": e.get("organizer", "")}


def _fields(body: dict, partial: bool = False, current: dict | None = None) -> dict:
    out = {}
    if not partial or "title" in body:
        title = str(body.get("title") or "").strip()[:200]
        if not title:
            raise HTTPException(status_code=422, detail="Give the event a title")
        out["title"] = title
    all_day = bool(body.get("all_day", (current or {}).get("all_day", False)))
    if not partial or "all_day" in body:
        out["all_day"] = all_day
    if not partial or "start" in body:
        out["start"] = parse_when(body.get("start"), all_day)
    if not partial or "end" in body or "start" in body:
        start = out.get("start") or (current or {}).get("start")
        if body.get("end"):
            end = parse_when(body.get("end"), all_day)
        else:
            end = start + (timedelta(days=1) if all_day else timedelta(hours=1))
        if all_day and end <= start:
            end = start + timedelta(days=1)
        if end < start:
            raise HTTPException(status_code=422, detail="The event ends before it starts")
        out["end"] = end
    for key, limit in (("location", 300), ("description", 5000)):
        if not partial or key in body:
            out[key] = str(body.get(key) or "").strip()[:limit]
    if not partial or "attendees" in body:
        raw = body.get("attendees") or []
        if isinstance(raw, str):
            raw = re.split(r"[,;\s]+", raw)
        people = []
        for a in raw:
            a = ext._clean_address(a)
            if a and ext.ADDRESS_RE.match(a) and a not in people:
                people.append(a)
        out["attendees"] = people[:100]
    if not partial or "color" in body:
        out["color"] = body.get("color") if body.get("color") in COLORS else "blue"
    return out


@router.get("/admin/calendar/{address}")
def list_events(address: str, start: str = "", end: str = ""):
    owner = drive_ext.owner_of(address)["address"]
    q = {"owner": owner}
    if start and end:
        s, e = parse_when(start), parse_when(end)
        q.update({"start": {"$lt": e}, "end": {"$gt": s}})
    events = [public_event(e) for e in _db().events.find(q).sort("start", 1).limit(2000)]
    return {"events": events}


@router.post("/admin/calendar/{address}", status_code=201)
def create_event(address: str, body: dict = Body(...)):
    owner = drive_ext.owner_of(address)["address"]
    doc = _fields(body)
    doc.update(owner=owner, uid=f"{secrets.token_hex(12)}@{_cfg['hostname']}", created_at=_now(), updated_at=_now(),
               organizer=owner, source={"kind": body.get("source_kind") or "manual", "message_id": body.get("message_id")})
    doc["_id"] = _db().events.insert_one(doc).inserted_id
    return public_event(doc)


@router.get("/admin/calendar/{address}/{event_id}")
def get_event(address: str, event_id: str):
    return public_event(_event(drive_ext.owner_of(address)["address"], event_id))


@router.patch("/admin/calendar/{address}/{event_id}")
def update_event(address: str, event_id: str, body: dict = Body(...)):
    owner = drive_ext.owner_of(address)["address"]
    e = _event(owner, event_id)
    changes = _fields(body, partial=True, current=e)
    changes["updated_at"] = _now()
    changes["sequence"] = int(e.get("sequence", 0)) + 1
    _db().events.update_one({"_id": e["_id"]}, {"$set": changes})
    return public_event(_db().events.find_one({"_id": e["_id"]}))


@router.delete("/admin/calendar/{address}/{event_id}")
def delete_event(address: str, event_id: str):
    owner = drive_ext.owner_of(address)["address"]
    e = _event(owner, event_id)
    _db().events.delete_one({"_id": e["_id"]})
    _db().shares.update_many({"kind": "event", "target_id": event_id}, {"$set": {"revoked": True}})
    return {"ok": True}


# ---------------------------------------------------------------------------
# .ics (iCalendar) in and out
# ---------------------------------------------------------------------------

def event_ics(e: dict, method: str = "PUBLISH", organizer: str = "", attendees: list | None = None) -> bytes:
    from icalendar import Calendar, Event, vCalAddress, vText
    cal = Calendar()
    cal.add("prodid", "-//BearerMail//Calendar//EN")
    cal.add("version", "2.0")
    cal.add("method", method)
    ev = Event()
    ev.add("uid", e.get("uid") or f"{e['_id']}@{_cfg['hostname']}")
    ev.add("dtstamp", _now())
    ev.add("summary", e.get("title", ""))
    start, end = _utc(e["start"]), _utc(e["end"])
    if e.get("all_day"):
        ev.add("dtstart", start.date())
        ev.add("dtend", end.date())
    else:
        ev.add("dtstart", start)
        ev.add("dtend", end)
    if e.get("location"):
        ev.add("location", e["location"])
    if e.get("description"):
        ev.add("description", e["description"])
    ev.add("sequence", int(e.get("sequence", 0)))
    org = organizer or e.get("organizer")
    if org:
        o = vCalAddress(f"mailto:{org}")
        o.params["cn"] = vText(org)
        ev["organizer"] = o
    for a in attendees if attendees is not None else e.get("attendees", []):
        att = vCalAddress(f"mailto:{a}")
        att.params["role"] = vText("REQ-PARTICIPANT")
        att.params["rsvp"] = vText("TRUE")
        ev.add("attendee", att, encode=0)
    cal.add_component(ev)
    return cal.to_ical()


@router.get("/admin/calendar/{address}/{event_id}/ics")
def download_ics(address: str, event_id: str):
    e = _event(drive_ext.owner_of(address)["address"], event_id)
    return Response(event_ics(e), media_type="text/calendar; charset=utf-8",
                    headers={"Content-Disposition": drive_ext._disposition(drive_ext._safe_filename(e.get("title")) + ".ics")})


def _to_utc_value(v) -> tuple[datetime, bool]:
    v = getattr(v, "dt", v)
    if isinstance(v, datetime):
        return _utc(v), False
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc), True
    raise ValueError("no date")


def parse_ics(data: bytes) -> list:
    """Events inside an .ics file, as dicts ready for _fields()."""
    from icalendar import Calendar
    out = []
    try:
        cal = Calendar.from_ical(data)
    except Exception:
        return out
    for comp in cal.walk("VEVENT"):
        try:
            start, all_day = _to_utc_value(comp.get("dtstart"))
        except Exception:
            continue
        try:
            end, _ = _to_utc_value(comp.get("dtend")) if comp.get("dtend") else (None, None)
        except Exception:
            end = None
        if end is None and comp.get("duration"):
            end = start + comp.get("duration").dt
        attendees = []
        raw = comp.get("attendee") or []
        for a in raw if isinstance(raw, list) else [raw]:
            attendees.append(str(a).replace("mailto:", "").replace("MAILTO:", ""))
        out.append({"title": str(comp.get("summary") or "Event"), "start": start, "end": end or "", "all_day": all_day,
                    "location": str(comp.get("location") or ""), "description": str(comp.get("description") or ""),
                    "attendees": attendees, "uid": str(comp.get("uid") or ""),
                    "organizer": str(comp.get("organizer") or "").replace("mailto:", "").replace("MAILTO:", "")})
    return out


@router.post("/admin/calendar/{address}/from-message")
def from_message(address: str, body: dict = Body(...)):
    """Import the invitations (.ics) attached to an email. Without one, suggest an event from the subject."""
    acc = drive_ext.owner_of(address)
    doc = drive_ext._message_for(acc, str(body.get("message_id") or ""))
    created = []
    for att in doc.get("attachments") or []:
        name = (att.get("filename") or "").lower()
        ctype = (att.get("content_type") or "").lower()
        content = att.get("content")
        if not isinstance(content, (bytes, bytearray)) or not (ctype.startswith("text/calendar") or name.endswith(".ics")):
            continue
        for item in parse_ics(bytes(content)):
            uid = item.pop("uid", "")
            organizer = item.pop("organizer", "")
            existing = _db().events.find_one({"owner": acc["address"], "uid": uid}) if uid else None
            fields = _fields({**item, "end": item.get("end") or None})
            fields.update(updated_at=_now(), organizer=organizer, source={"kind": "email", "message_id": str(body.get("message_id"))})
            if existing:
                _db().events.update_one({"_id": existing["_id"]}, {"$set": fields})
                created.append(public_event(_db().events.find_one({"_id": existing["_id"]})))
            else:
                fields.update(owner=acc["address"], uid=uid or f"{secrets.token_hex(12)}@{_cfg['hostname']}", created_at=_now())
                fields["_id"] = _db().events.insert_one(fields).inserted_id
                created.append(public_event(fields))
    if created:
        return {"imported": created}
    s = drive_ext.message_summary(doc)
    return {"imported": [], "suggestion": {"title": s["subject"][:200], "description": (f"From {s['from']}\n\n" + s["body"])[:2000],
                                           "attendees": [doc.get("from", {}).get("address", "")]}}


def invite_attachment(owner: str, event_id: str, organizer: str, attendees: list) -> dict:
    """An invitation to attach to an outgoing email (METHOD:REQUEST, so calendar apps offer Accept/Decline)."""
    e = _event(owner, event_id)
    people = [a for a in dict.fromkeys(list(e.get("attendees", [])) + list(attendees)) if a]
    _db().events.update_one({"_id": e["_id"]}, {"$set": {"attendees": people, "organizer": organizer}})
    e.update(attendees=people, organizer=organizer)
    return {"filename": "invite.ics", "content_type": "text/calendar", "raw": event_ics(e, "REQUEST", organizer, people),
            "method": "REQUEST"}
