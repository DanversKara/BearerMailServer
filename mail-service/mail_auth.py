"""
Checks run on every incoming message, before it is stored.

1. Sender verification (SPF, DKIM, DMARC): did this message really come from the
   domain in its From line? The result is stored with the message and shown as a
   warning in the web app, so a fake "PayPal" email stands out. By default nothing
   is rejected; set SMTP_ENFORCE_DMARC_REJECT=1 to refuse mail whose domain
   publishes p=reject and that fails the check.

2. Open-tracking and attachment scan: read-receipt requests, attachments that can
   contact another server when opened (so the sender learns you opened them), and
   risky attachment types (programs, macro documents, disguised files).

Every check is best effort. A DNS timeout or a malformed part never blocks delivery;
the result simply says "temperror" or is left out.
"""

import ipaddress
import logging
import re
import zipfile
from email.utils import getaddresses, parseaddr
from io import BytesIO

logger = logging.getLogger("bearermail.auth")

# ---------------------------------------------------------------------------
# Organisational domain (for DMARC "relaxed" alignment)
# ---------------------------------------------------------------------------

# Public suffixes that have two labels. Covers the common ones; anything else falls back to
# "last two labels", which is correct for .com/.net/.org and most country domains.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
    "co.in", "net.in", "org.in", "co.za", "org.za", "com.mx", "org.mx", "com.ar",
    "com.tr", "co.il", "com.ua", "com.pl", "co.id", "or.id", "com.ph", "com.vn",
    "com.pk", "com.eg", "com.sa", "com.co", "com.pe", "com.ve", "co.th", "in.th",
}


def org_domain(domain: str) -> str:
    labels = [p for p in (domain or "").lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _aligned(a: str, b: str, strict: bool) -> bool:
    a, b = (a or "").lower().strip("."), (b or "").lower().strip(".")
    if not a or not b:
        return False
    return a == b if strict else org_domain(a) == org_domain(b)


def _domain_of(address: str) -> str:
    address = (address or "").strip().strip("<>")
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def header_from_address(msg) -> str:
    """The address in the From: header (the one people see)."""
    try:
        value = str(msg.get("From", "") or "")
    except Exception:
        return ""
    return parseaddr(value)[1].lower()


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _txt_records(name: str, timeout: float = 4.0) -> list:
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout / 2
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        raise RuntimeError(str(exc) or exc.__class__.__name__)
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in answers]


def _dns_txt_for_dkim(name, timeout=5):
    """dnsfunc for dkimpy that uses dnspython with a short timeout."""
    try:
        records = _txt_records(name.decode() if isinstance(name, bytes) else name, timeout)
    except RuntimeError:
        return None
    return records[0].encode() if records else None


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def lookup_dmarc(domain: str) -> tuple[dict | None, str]:
    """Returns (tags, the domain the record was found on). Falls back to the organisational domain."""
    for candidate in dict.fromkeys([domain, org_domain(domain)]):
        if not candidate:
            continue
        for rec in _txt_records(f"_dmarc.{candidate}"):
            if rec.lower().startswith("v=dmarc1"):
                return parse_dmarc(rec), candidate
    return None, ""


# ---------------------------------------------------------------------------
# SPF / DKIM / DMARC
# ---------------------------------------------------------------------------

def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return True


def check_spf(client_ip: str, mail_from: str, helo: str) -> dict:
    if not client_ip or _is_local(client_ip):
        return {"result": "none", "domain": _domain_of(mail_from) or helo or "", "reason": "local connection"}
    sender = mail_from or (f"postmaster@{helo}" if helo else "")
    if not sender:
        return {"result": "none", "domain": "", "reason": "no sender"}
    try:
        import spf
        result, explanation = spf.check2(i=client_ip, s=sender, h=helo or "unknown", timeout=8, querytime=8)
    except Exception as exc:  # pragma: no cover - library/DNS failure
        return {"result": "temperror", "domain": _domain_of(sender), "reason": str(exc)[:200]}
    return {"result": result, "domain": _domain_of(sender), "reason": (explanation or "")[:200]}


def check_dkim(raw: bytes, max_signatures: int = 5) -> dict:
    try:
        import dkim
    except Exception:  # pragma: no cover
        return {"result": "none", "domains": [], "passed": []}
    try:
        verifier = dkim.DKIM(raw, timeout=5)
        count = sum(1 for name, _ in verifier.headers if name.lower() == b"dkim-signature")
    except Exception:
        return {"result": "none", "domains": [], "passed": []}
    if not count:
        return {"result": "none", "domains": [], "passed": []}
    domains, passed = [], []
    for idx in range(min(count, max_signatures)):
        try:
            ok = verifier.verify(idx=idx, dnsfunc=_dns_txt_for_dkim)
        except Exception:
            ok = False
        domain = (getattr(verifier, "domain", b"") or b"").decode("ascii", "replace").lower()
        if domain:
            domains.append(domain)
            if ok:
                passed.append(domain)
    return {"result": "pass" if passed else "fail", "domains": domains, "passed": passed}


def check_dmarc(from_domain: str, spf: dict, dkim_result: dict) -> dict:
    if not from_domain:
        return {"result": "none", "policy": "", "reason": "no From address"}
    try:
        tags, found_on = lookup_dmarc(from_domain)
    except RuntimeError as exc:
        return {"result": "temperror", "policy": "", "reason": str(exc)[:200]}
    if tags is None:
        return {"result": "none", "policy": "", "reason": "the sender's domain publishes no DMARC policy"}
    strict_spf = tags.get("aspf", "r").lower() == "s"
    strict_dkim = tags.get("adkim", "r").lower() == "s"
    policy = tags.get("p", "none").lower()
    if found_on and found_on != from_domain and tags.get("sp"):
        policy = tags.get("sp", policy).lower()
    spf_ok = spf.get("result") == "pass" and _aligned(spf.get("domain", ""), from_domain, strict_spf)
    dkim_ok = any(_aligned(d, from_domain, strict_dkim) for d in dkim_result.get("passed", []))
    if spf_ok or dkim_ok:
        return {"result": "pass", "policy": policy, "reason": "aligned " + ("DKIM" if dkim_ok else "SPF")}
    return {"result": "fail", "policy": policy,
            "reason": "neither SPF nor DKIM proves the message came from " + from_domain}


def evaluate_sender(raw: bytes, msg, client_ip: str, helo: str, mail_from: str) -> dict:
    """Run SPF, DKIM and DMARC. Always returns a dict; never raises."""
    from_addr = header_from_address(msg)
    from_domain = _domain_of(from_addr)
    if not client_ip or _is_local(client_ip):
        # Handed over from this server's own network (tests, local scripts): nothing to verify against.
        return {"skipped": True, "spf": "none", "dkim": "none", "dmarc": "none", "header_from_domain": from_domain,
                "client_ip": client_ip or "", "helo": (helo or "")[:255]}
    try:
        spf = check_spf(client_ip, mail_from, helo)
    except Exception as exc:  # pragma: no cover
        spf = {"result": "temperror", "domain": "", "reason": str(exc)[:200]}
    try:
        dkim_result = check_dkim(raw)
    except Exception:  # pragma: no cover
        dkim_result = {"result": "none", "domains": [], "passed": []}
    try:
        dmarc = check_dmarc(from_domain, spf, dkim_result)
    except Exception as exc:  # pragma: no cover
        dmarc = {"result": "temperror", "policy": "", "reason": str(exc)[:200]}
    return {
        "spf": spf.get("result", "none"),
        "spf_domain": spf.get("domain", ""),
        "dkim": dkim_result.get("result", "none"),
        "dkim_domains": dkim_result.get("passed", []) or dkim_result.get("domains", []),
        "dmarc": dmarc.get("result", "none"),
        "dmarc_policy": dmarc.get("policy", ""),
        "dmarc_reason": dmarc.get("reason", ""),
        "header_from_domain": from_domain,
        "client_ip": client_ip,
        "helo": (helo or "")[:255],
    }


def auth_verdict(auth: dict | None) -> str:
    """'fail' (likely forged), 'warn' (unverified), 'pass' (verified) or '' (not checked)."""
    if not auth or auth.get("skipped"):
        return ""
    if auth.get("dmarc") == "fail":
        return "fail"
    if auth.get("spf") == "fail" and auth.get("dkim") != "pass":
        return "fail"
    if auth.get("dmarc") == "pass" or auth.get("dkim") == "pass" or auth.get("spf") == "pass":
        return "pass"
    return "warn"


def authentication_results_header(hostname: str, auth: dict) -> str:
    """RFC 8601 style summary (used in the IMAP copy so mail apps can show it)."""
    parts = [hostname or "bearermail"]
    parts.append(f"spf={auth.get('spf', 'none')} smtp.mailfrom={auth.get('spf_domain') or 'unknown'}")
    dkim_domains = auth.get("dkim_domains") or []
    parts.append(f"dkim={auth.get('dkim', 'none')}" + (f" header.d={dkim_domains[0]}" if dkim_domains else ""))
    parts.append(f"dmarc={auth.get('dmarc', 'none')} header.from={auth.get('header_from_domain') or 'unknown'}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Open tracking: read receipts
# ---------------------------------------------------------------------------

_RECEIPT_HEADERS = ("Disposition-Notification-To", "Return-Receipt-To", "X-Confirm-Reading-To", "Read-Receipt-To")


def read_receipt_request(msg) -> str:
    """The address a read receipt was requested to, or ''. BearerMail never sends receipts itself."""
    for name in _RECEIPT_HEADERS:
        try:
            value = msg.get(name)
        except Exception:
            value = None
        if value:
            addresses = [a for _, a in getaddresses([str(value)]) if a]
            return (addresses[0] if addresses else str(value))[:320]
    return ""


def reply_to_address(msg) -> str:
    try:
        value = msg.get("Reply-To")
    except Exception:
        value = None
    if not value:
        return ""
    return parseaddr(str(value))[1].lower()[:320]


# ---------------------------------------------------------------------------
# Attachment scan
# ---------------------------------------------------------------------------

SCAN_VERSION = 1
_MAX_SCAN_BYTES = 8 * 1024 * 1024

_EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msix", "msp", "appx", "appxbundle", "dll", "cpl",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ws", "ps1", "psm1", "hta", "jar", "lnk", "reg", "inf",
    "scf", "url", "application", "gadget", "chm", "vb", "vbscript", "sct", "xll", "apk", "app", "command",
    "sh", "run", "bin", "elf", "deb", "rpm", "dmg", "pkg",
}
_DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
_MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
_OLD_OFFICE_EXT = {"doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "rtf"}
_OOXML_EXT = {"docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx", "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "vsdx", "odt", "ods", "odp"}
_WEB_EXT = {"html", "htm", "xhtml", "shtml", "mht", "mhtml", "svg", "svgz", "xml"}
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "arj", "ace", "lzh", "z"}
_DOC_LOOKALIKE_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "zip", "rtf", "csv"}

_REMOTE_URL_RE = re.compile(rb"https?://[^\s\"'<>)]{4,}", re.I)
_HTML_REMOTE_RE = re.compile(rb"(?:src|href|action|background|xlink:href)\s*=\s*[\"']?\s*(?:https?:)?//", re.I)
_TRACKER_HINT_RE = re.compile(rb"(?:pixel|track|beacon|open|/o/|/wf/)", re.I)


def _ext(filename: str) -> str:
    name = (filename or "").lower().strip().rstrip(".")
    return name.rsplit(".", 1)[1] if "." in name else ""


def _second_ext(filename: str) -> str:
    parts = (filename or "").lower().strip().split(".")
    return parts[-2] if len(parts) >= 3 else ""


def _sniff(data: bytes) -> str:
    head = data[:16]
    if head.startswith(b"MZ"):
        return "windows-program"
    if head.startswith(b"\x7fELF"):
        return "linux-program"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "mac-program"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if data[32769:32774] == b"CD001":
        return "iso"
    stripped = data[:512].lstrip().lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml")) or b"<script" in stripped:
        return "markup"
    return ""


def _scan_pdf(data: bytes, found: dict):
    body = data[:_MAX_SCAN_BYTES]
    has_js = b"/JavaScript" in body or re.search(rb"/JS\s*[(<\[]", body) is not None
    if has_js:
        found["reasons"].append("contains JavaScript that runs when the PDF is opened")
        found["risk"] = "high"
        found["phones_home"] = True
    if b"/Launch" in body:
        found["reasons"].append("can try to start another program (/Launch)")
        found["risk"] = "high"
    if b"/SubmitForm" in body:
        found["reasons"].append("has a form that sends data to a website")
        found["phones_home"] = True
    if b"/OpenAction" in body and (b"/URI" in body or b"/GoToR" in body):
        found["reasons"].append("opens a web address automatically when opened")
        found["phones_home"] = True
    elif b"/URI" in body:
        found["info"].append("contains web links")
    if b"/EmbeddedFile" in body:
        found["reasons"].append("has other files hidden inside it")
        found["risk"] = found["risk"] if found["risk"] == "high" else "medium"


def _scan_ooxml(data: bytes, found: dict):
    try:
        archive = zipfile.ZipFile(BytesIO(data[:_MAX_SCAN_BYTES]))
        names = archive.namelist()
    except Exception:
        return
    lowered = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lowered):
        found["reasons"].append("contains macros (programs that can run when the document is opened)")
        found["risk"] = "high"
    for name in names:
        if not name.lower().endswith(".rels"):
            continue
        try:
            content = archive.read(name)[:200_000]
        except Exception:
            continue
        if b'TargetMode="External"' not in content and b"TargetMode='External'" not in content:
            continue
        if b"attachedTemplate" in content or b"oleObject" in content or b"frame" in content.lower():
            found["reasons"].append("loads a template or object from the internet when opened (a known attack trick)")
            found["risk"] = "high"
            found["phones_home"] = True
        elif _REMOTE_URL_RE.search(content):
            found["reasons"].append("loads a picture or file from the internet when opened, which tells the sender you opened it")
            found["phones_home"] = True
            if found["risk"] == "info":
                found["risk"] = "medium"


def _scan_ole(data: bytes, found: dict):
    body = data[:_MAX_SCAN_BYTES]
    if b"_VBA_PROJECT" in body or "VBA".encode("utf-16-le") in body or b"Macros" in body:
        found["reasons"].append("contains macros (programs that can run when the document is opened)")
        found["risk"] = "high"
    if _REMOTE_URL_RE.search(body) and (b"INCLUDEPICTURE" in body or b"HYPERLINK" in body):
        found["reasons"].append("links to a picture on the internet that loads when opened")
        found["phones_home"] = True


def _scan_markup(data: bytes, found: dict):
    body = data[:2 * 1024 * 1024]
    if b"<script" in body.lower():
        found["reasons"].append("web page with scripts, opens in your browser outside BearerMail's protection")
        found["risk"] = "high"
    if b"<form" in body.lower() and (b"password" in body.lower() or b"type=\"password\"" in body.lower()):
        found["reasons"].append("asks for a password (typical of phishing pages sent as attachments)")
        found["risk"] = "high"
    if _HTML_REMOTE_RE.search(body):
        found["reasons"].append("loads content from the internet when opened, which tells the sender you opened it")
        found["phones_home"] = True
    if found["risk"] == "info":
        found["risk"] = "medium"
        found["reasons"].append("web page attachment: opening it outside the mail app skips the protection BearerMail applies")


def _scan_zip(data: bytes, found: dict):
    try:
        archive = zipfile.ZipFile(BytesIO(data[:_MAX_SCAN_BYTES]))
        infos = archive.infolist()[:500]
    except Exception:
        return
    if any(info.flag_bits & 0x1 for info in infos):
        found["reasons"].append("password-protected archive, so it cannot be scanned (often used to sneak malware past filters)")
        found["risk"] = "high" if found["risk"] == "high" else "medium"
    risky_inside = [i.filename for i in infos if _ext(i.filename) in _EXECUTABLE_EXT | _DISK_IMAGE_EXT | _MACRO_EXT]
    if risky_inside:
        shown = ", ".join(sorted({n.rsplit("/", 1)[-1] for n in risky_inside})[:3])
        found["reasons"].append(f"contains programs or macro files ({shown})")
        found["risk"] = "high"


def scan_attachment(filename: str, content_type: str, data: bytes) -> dict:
    """Assess one attachment. risk is 'high', 'medium' or 'info'."""
    data = data or b""
    ext = _ext(filename)
    found = {"filename": (filename or "")[:200], "risk": "info", "reasons": [], "info": [], "phones_home": False}
    kind = _sniff(data)

    if ext in _EXECUTABLE_EXT:
        found["reasons"].append(f".{ext} files are programs or scripts that run on your computer")
        found["risk"] = "high"
    if ext in _DISK_IMAGE_EXT:
        found["reasons"].append(f".{ext} disk images are used to slip programs past security warnings")
        found["risk"] = "high"
    if ext in _MACRO_EXT:
        found["reasons"].append(f".{ext} documents can contain macros")
        found["risk"] = "high"
    second = _second_ext(filename)
    if second in _DOC_LOOKALIKE_EXT and (ext in _EXECUTABLE_EXT or kind in ("windows-program", "script")):
        found["reasons"].append(f"disguised: the name ends in .{second}.{ext} to look like a .{second} file")
        found["risk"] = "high"
    if kind in ("windows-program", "linux-program", "mac-program") and ext not in _EXECUTABLE_EXT:
        found["reasons"].append(f"the file is really a program, even though it is named .{ext or 'no extension'}")
        found["risk"] = "high"
    if re.search(r"[‪-‮⁦-⁩]", filename or ""):
        found["reasons"].append("the file name contains hidden characters that reverse text (used to disguise programs)")
        found["risk"] = "high"

    try:
        if kind == "pdf" or ext == "pdf":
            _scan_pdf(data, found)
        elif kind == "zip" and ext in _OOXML_EXT:
            _scan_ooxml(data, found)
        elif kind == "ole" or ext in _OLD_OFFICE_EXT:
            _scan_ole(data, found)
        elif ext in _WEB_EXT or kind == "markup":
            _scan_markup(data, found)
        elif kind == "zip" or ext in _ARCHIVE_EXT:
            if kind == "zip":
                _scan_zip(data, found)
            elif ext in ("rar", "7z", "cab", "arj", "ace"):
                found["info"].append("archive type that BearerMail cannot look inside")
    except Exception as exc:  # pragma: no cover - never let one attachment break delivery
        logger.debug("attachment scan failed for %s: %s", filename, exc)

    found["reasons"] = found["reasons"][:6]
    found["info"] = found["info"][:3]
    return found


def scan_message(msg, attachments: list) -> dict:
    """Scan result stored with each message."""
    results = []
    for att in attachments or []:
        content = att.get("content", b"")
        if isinstance(content, str):
            content = content.encode("utf-8", "replace")
        entry = scan_attachment(att.get("filename", ""), att.get("content_type", ""), content)
        entry["id"] = att.get("id", "")
        results.append(entry)
    receipt = read_receipt_request(msg) if msg is not None else ""
    return {
        "version": SCAN_VERSION,
        "read_receipt_to": receipt,
        "attachments": results,
        "risky_attachments": sum(1 for r in results if r["risk"] == "high"),
        "attachments_phone_home": sum(1 for r in results if r["phones_home"]),
    }
