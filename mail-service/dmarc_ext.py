"""
BearerMail DMARC reports (Setup > Security > DMARC reports).

The DMARC record of a domain (rua=mailto:...) asks Gmail, Microsoft, Yahoo... to send a daily summary of
the mail they received "from" that domain: which servers sent it and whether it passed SPF/DKIM. These
reports arrive as an email with a .zip / .gz / .xml attachment and mean nothing to a person reading mail.

BearerMail recognises them while receiving mail, reads them, and files them for the admins instead of the
inbox (a copy can be kept in the inbox if wanted). The Security page then shows, per sending server,
how much mail it sent as your domains and whether it passed, and points out servers that fail
(someone faking your address, or a service you forgot to set up).

Only reports about your own domains are kept. Reports whose sender cannot be verified (SPF/DKIM/DMARC)
are still read, but marked "unverified".
"""

import gzip
import io
import ipaddress
import logging
import zipfile
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, Request
from pymongo import DESCENDING

logger = logging.getLogger("bearermail.dmarc")

MAX_XML_BYTES = 20 * 1024 * 1024  # a report is a few KB; this stops zip bombs
_cfg = {"get_db": None, "require_api_key": None, "server_ip": ""}


def configure(get_db, require_api_key, server_ip: str = ""):
    _cfg["get_db"] = get_db
    _cfg["require_api_key"] = require_api_key
    _cfg["server_ip"] = server_ip or ""


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


router = APIRouter(dependencies=[Depends(_auth)])


def init_indexes():
    db = _db()
    db.dmarc_reports.create_index([("org_name", 1), ("report_id", 1)], unique=True)
    db.dmarc_reports.create_index([("end", DESCENDING)])


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
    return dt


# ---------------------------------------------------------------------------
# Reading a report
# ---------------------------------------------------------------------------

def _xml_from_attachment(filename: str, content_type: str, data: bytes) -> bytes | None:
    """The XML inside a report attachment (.zip, .gz or plain .xml), or None."""
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    try:
        is_gzip = data[:2] == b"\x1f\x8b" or name.endswith(".gz") or "gzip" in ctype
        if not is_gzip and (data[:2] == b"PK" or name.endswith(".zip") or "zip" in ctype):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if info.filename.lower().endswith(".xml") and info.file_size <= MAX_XML_BYTES:
                        with z.open(info) as fh:
                            return fh.read(MAX_XML_BYTES + 1)[:MAX_XML_BYTES]
            return None
        if is_gzip:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
                out = fh.read(MAX_XML_BYTES + 1)
            return out if len(out) <= MAX_XML_BYTES else None
        if name.endswith(".xml") or "xml" in ctype:
            return data[:MAX_XML_BYTES]
    except Exception as exc:
        logger.info("Not a readable report attachment (%s): %s", filename, exc)
    return None


def _text(node, path: str, default: str = "") -> str:
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else default


def parse_report(xml: bytes) -> dict | None:
    """A DMARC aggregate report (RFC 7489 appendix C) as a dict, or None when it is not one."""
    from defusedxml import ElementTree as ET  # refuses entity tricks in untrusted XML
    try:
        root = ET.fromstring(xml)
    except Exception:
        return None
    # Some reporters add an XML namespace; drop it so the paths below work for everyone.
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    if root.tag != "feedback":
        return None
    meta, policy = root.find("report_metadata"), root.find("policy_published")
    try:
        begin = datetime.fromtimestamp(int(_text(meta, "date_range/begin", "0")), timezone.utc)
        end = datetime.fromtimestamp(int(_text(meta, "date_range/end", "0")), timezone.utc)
    except (ValueError, OverflowError):
        return None
    records = []
    for rec in root.findall("record")[:5000]:
        row = rec.find("row")
        try:
            count = int(_text(row, "count", "0"))
        except ValueError:
            count = 0
        auth = rec.find("auth_results")
        records.append({
            "source_ip": _text(row, "source_ip"),
            "count": max(0, count),
            "disposition": _text(row, "policy_evaluated/disposition", "none"),
            "dkim": _text(row, "policy_evaluated/dkim", "fail"),
            "spf": _text(row, "policy_evaluated/spf", "fail"),
            "header_from": _text(rec, "identifiers/header_from").lower(),
            "envelope_from": _text(rec, "identifiers/envelope_from").lower(),
            "auth_dkim": [{"domain": _text(d, "domain").lower(), "result": _text(d, "result"), "selector": _text(d, "selector")}
                          for d in (auth.findall("dkim") if auth is not None else [])][:10],
            "auth_spf": [{"domain": _text(s, "domain").lower(), "result": _text(s, "result")}
                         for s in (auth.findall("spf") if auth is not None else [])][:10],
        })
    return {
        "org_name": _text(meta, "org_name", "unknown")[:200],
        "email": _text(meta, "email")[:320],
        "report_id": _text(meta, "report_id", "")[:200],
        "begin": begin, "end": end,
        "domain": _text(policy, "domain").lower(),
        "policy": {k: _text(policy, k) for k in ("adkim", "aspf", "p", "sp", "pct")},
        "records": records,
        "total": sum(r["count"] for r in records),
    }


def reports_in_attachments(attachments: list) -> list:
    out = []
    for att in attachments or []:
        content = att.get("content")
        if not isinstance(content, (bytes, bytearray)):
            continue
        xml = _xml_from_attachment(att.get("filename", ""), att.get("content_type", ""), bytes(content))
        if xml:
            report = parse_report(xml)
            if report:
                out.append(report)
    return out


def _our_domains() -> set:
    return {d["domain"] for d in _db().domains.find({}, {"domain": 1})}


def save_report(report: dict, verified: bool, source: str = "") -> bool:
    """File one report. Only reports about our own domains are kept. Returns True when it was stored/updated."""
    domain = report.get("domain", "")
    ours = _our_domains()
    if domain not in ours and not any(domain.endswith("." + d) for d in ours):
        logger.info("Ignored a DMARC report for %s (not one of our domains)", domain)
        return False
    if not report.get("report_id"):
        report["report_id"] = f"{report['org_name']}-{int(report['begin'].timestamp())}-{domain}"
    doc = {**report, "verified": bool(verified), "received_at": _now(), "source": source[:100]}
    _db().dmarc_reports.update_one({"org_name": report["org_name"], "report_id": report["report_id"]}, {"$set": doc}, upsert=True)
    failing = [r for r in report["records"] if r["dkim"] != "pass" and r["spf"] != "pass" and r["count"]]
    if failing:
        import security_ext
        security_ext.record("system", "dmarc_failures", detail=(
            f"{report['org_name']}: {sum(r['count'] for r in failing)} message(s) as {domain} failed, from "
            + ", ".join(sorted({r['source_ip'] for r in failing})[:5]))[:300])
    return True


def capture(attachments: list, auth: dict | None, from_address: str) -> tuple[bool, bool]:
    """Called for every incoming message. (is_report, keep_in_inbox)."""
    try:
        reports = reports_in_attachments(attachments)
    except Exception as exc:  # never let a report break mail delivery
        logger.warning("DMARC report could not be read: %s", exc)
        return False, True
    if not reports:
        return False, True
    import mail_auth
    import security_ext
    verified = mail_auth.auth_verdict(auth) == "pass"
    stored = [save_report(r, verified, source=from_address) for r in reports]
    keep = bool(security_ext.get_settings().get("dmarc", {}).get("keep_in_inbox", False))
    return any(stored), (keep or not any(stored))


# ---------------------------------------------------------------------------
# Summary for the Security page
# ---------------------------------------------------------------------------

_KNOWN = [  # reverse-DNS endings of common senders, to name the rows
    ("mailjet.com", "Mailjet"), ("sendgrid.net", "SendGrid"), ("brevo.com", "Brevo"), ("sendinblue.com", "Brevo"),
    ("mailgun.net", "Mailgun"), ("amazonses.com", "Amazon SES"), ("google.com", "Google"), ("outlook.com", "Microsoft"),
    ("protection.outlook.com", "Microsoft 365"), ("postmarkapp.com", "Postmark"), ("mandrillapp.com", "Mailchimp"),
    ("mcsv.net", "Mailchimp"), ("zoho.com", "Zoho"), ("sparkpostmail.com", "SparkPost"),
]
_ptr_cache: dict = {}


def _name_of(ip: str) -> tuple[str, str]:
    """(reverse DNS name, friendly name) for an address. Cached; short timeouts."""
    if ip in _ptr_cache:
        return _ptr_cache[ip]
    host = ""
    try:
        import dns.resolver
        import dns.reversename
        r = dns.resolver.Resolver()
        r.lifetime = 2.0
        host = str(r.resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".").lower()
    except Exception:
        host = ""
    friendly = next((n for suffix, n in _KNOWN if host.endswith(suffix)), "")
    if ip and ip == _cfg["server_ip"]:
        friendly = "This server"
    if len(_ptr_cache) > 5000:
        _ptr_cache.clear()
    _ptr_cache[ip] = (host, friendly)
    return host, friendly


def _ok(r: dict) -> bool:
    return r.get("dkim") == "pass" or r.get("spf") == "pass"


@router.get("/admin/dmarc/summary")
def summary(days: int = 30, domain: str = "", lookup: int = 1):
    days = max(1, min(days, 365))
    since = _now() - timedelta(days=days)
    q = {"end": {"$gte": since}}
    if domain:
        q["domain"] = domain.lower()
    sources: dict = {}
    reporters: dict = {}
    domains: dict = {}
    total = passed = 0
    reports = list(_db().dmarc_reports.find(q).sort("end", DESCENDING).limit(5000))
    for rep in reports:
        reporters[rep["org_name"]] = reporters.get(rep["org_name"], 0) + rep.get("total", 0)
        d = domains.setdefault(rep["domain"], {"domain": rep["domain"], "policy": rep.get("policy", {}), "total": 0, "passed": 0, "last": rep["end"]})
        for r in rep.get("records", []):
            ip = r.get("source_ip", "")
            s = sources.setdefault(ip, {"ip": ip, "total": 0, "passed": 0, "failed": 0, "dkim_pass": 0, "spf_pass": 0,
                                        "reporters": set(), "header_from": set(), "last": rep["end"], "unverified_only": True})
            n = r.get("count", 0)
            s["total"] += n
            s["reporters"].add(rep["org_name"])
            s["header_from"].add(r.get("header_from") or rep["domain"])
            s["last"] = max(s["last"], rep["end"])
            s["unverified_only"] = s["unverified_only"] and not rep.get("verified")
            if r.get("dkim") == "pass":
                s["dkim_pass"] += n
            if r.get("spf") == "pass":
                s["spf_pass"] += n
            if _ok(r):
                s["passed"] += n
                d["passed"] += n
                passed += n
            else:
                s["failed"] += n
            d["total"] += n
            total += n
    rows = []
    for s in sorted(sources.values(), key=lambda x: (-x["failed"], -x["total"])):
        host, friendly = _name_of(s["ip"]) if lookup else ("", "")
        try:
            private = ipaddress.ip_address(s["ip"]).is_private
        except ValueError:
            private = False
        status = "ok" if s["failed"] == 0 else ("partly" if s["passed"] else "failing")
        rows.append({**s, "reporters": sorted(s["reporters"]), "header_from": sorted(s["header_from"]), "last": _iso(s["last"]),
                     "host": host, "name": friendly, "private": private, "status": status})
    dom_rows = []
    for d in domains.values():
        p = (d["policy"] or {}).get("p", "")
        advice = ""
        if d["total"] and d["passed"] == d["total"] and p == "none":
            advice = "All mail passed. You can make the policy stricter: p=quarantine (fakes go to spam)."
        elif d["total"] and d["passed"] < d["total"]:
            advice = "Some mail failed. Check the red rows below before making the policy stricter."
        dom_rows.append({**d, "last": _iso(d["last"]), "advice": advice})
    return {"days": days, "total": total, "passed": passed, "failed": total - passed, "reports": len(reports),
            "reporters": [{"name": k, "messages": v} for k, v in sorted(reporters.items(), key=lambda x: -x[1])],
            "domains": sorted(dom_rows, key=lambda x: x["domain"]), "sources": rows}


@router.get("/admin/dmarc/reports")
def list_reports(limit: int = 50):
    out = []
    for r in _db().dmarc_reports.find({}).sort("end", DESCENDING).limit(max(1, min(limit, 500))):
        out.append({"id": str(r["_id"]), "org_name": r["org_name"], "email": r.get("email", ""), "report_id": r["report_id"],
                    "domain": r["domain"], "begin": _iso(r["begin"]), "end": _iso(r["end"]), "total": r.get("total", 0),
                    "failed": sum(x["count"] for x in r.get("records", []) if not _ok(x)), "policy": r.get("policy", {}),
                    "verified": r.get("verified", False), "records": r.get("records", [])})
    return {"reports": out}


@router.post("/admin/dmarc/import")
def import_from_mailboxes(body: dict = Body(default={})):
    """Find reports that were delivered to mailboxes before (or while keeping copies) and file them.
    Unless 'keep' is set, the report emails are moved to Trash afterwards."""
    import mail_auth
    keep = bool((body or {}).get("keep"))
    db = _db()
    found = moved = 0
    q = {"is_deleted": {"$ne": True}, "has_attachments": True,
         "attachments.filename": {"$regex": r"\.(zip|gz|xml)$", "$options": "i"}}
    for msg in db.messages.find(q).limit(5000):
        reports = reports_in_attachments(msg.get("attachments", []))
        if not reports:
            continue
        verified = mail_auth.auth_verdict(msg.get("auth")) == "pass"
        if any([save_report(r, verified, source=(msg.get("from") or {}).get("address", "")) for r in reports]):
            found += len(reports)
            if not keep:
                db.messages.update_one({"_id": msg["_id"]}, {"$set": {"is_deleted": True, "updated_at": _now()}})
                moved += 1
    return {"imported": found, "moved_to_trash": moved}


@router.delete("/admin/dmarc/reports")
def clear_reports(older_than_days: int = 0):
    q = {}
    if older_than_days > 0:
        q = {"end": {"$lt": _now() - timedelta(days=older_than_days)}}
    return {"deleted": _db().dmarc_reports.delete_many(q).deleted_count}
