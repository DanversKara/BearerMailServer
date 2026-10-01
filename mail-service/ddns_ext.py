"""Dynamic IP + Cloudflare DNS.

Home internet connections change their public IP now and then. This module:
- checks the server's public IPv4 every few minutes (Cloudflare's /cdn-cgi/trace, with ipify as a second opinion);
- when it changes, rewrites every A record that pointed at the old IP and the ``ip4:`` part of SPF records,
  in every Cloudflare zone that holds one of your domains (or your mail server name);
- makes the app itself use the new IP right away (Setup > Domains > DNS, DNS check, DMARC page), so nothing
  needs a restart and SERVER_IP in .env is only the starting value;
- can also push a domain's whole recommended record set (A, MX, SPF, DKIM, DMARC) to Cloudflare from the
  DNS page, after showing exactly what it will change.

The Cloudflare API token is stored encrypted (same key as SMTP provider passwords). It needs
Zone > Zone > Read and Zone > DNS > Edit for your zones.
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

logger = logging.getLogger("bearermail.ddns")
router = APIRouter()
_cfg = {}

CF_API = os.getenv("CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4").rstrip("/")
IP_SOURCES = [u.strip() for u in os.getenv(
    "DDNS_IP_SOURCES", "https://1.1.1.1/cdn-cgi/trace,https://api.ipify.org").split(",") if u.strip()]
MIN_INTERVAL = 2
DEFAULTS = {"enabled": False, "auto_update": True, "interval_min": 5, "ip": "", "previous_ips": [],
            "last_check": None, "last_change": None, "last_error": "", "last_result": None}


def configure(get_db, require_api_key, env_server_ip: str = "", record_event=None,
              encrypt=None, decrypt=None, build_dns_records=None, mail_host_for=None):
    _cfg.update(get_db=get_db, require_api_key=require_api_key, env_ip=env_server_ip or "",
                record=record_event, encrypt=encrypt, decrypt=decrypt,
                build_dns_records=build_dns_records, mail_host_for=mail_host_for)


def _db():
    return _cfg["get_db"]()


def _auth(request: Request):
    _cfg["require_api_key"](request)


def _record(kind, detail, level=None):
    if _cfg.get("record"):
        _cfg["record"]("system", kind, detail=detail[:400], level=level)


def _settings() -> dict:
    doc = _db().settings.find_one({"_id": "ddns"}) or {}
    return {**DEFAULTS, **{k: v for k, v in doc.items() if k != "_id"}}


def _save(**fields):
    _db().settings.update_one({"_id": "ddns"}, {"$set": fields}, upsert=True)


def current_ip() -> str:
    """The IP the app should show for this server: the last detected one, else SERVER_IP from .env."""
    try:
        s = _db().settings.find_one({"_id": "ddns"}, {"ip": 1, "enabled": 1}) or {}
        if s.get("enabled") and s.get("ip"):
            return s["ip"]
    except Exception:
        pass
    return _cfg.get("env_ip", "")


def known_ips() -> set:
    """Current and earlier addresses of this server (DMARC reports from before a change still say 'this server')."""
    s = _settings()
    return {ip for ip in [current_ip(), _cfg.get("env_ip", ""), *s.get("previous_ips", [])] if ip}


# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def _fetch(url: str, timeout: int = 8) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "BearerMail-DDNS"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https URLs from config
        return r.read(2048).decode("utf-8", "replace")


def _parse_ip(text: str) -> str:
    m = re.search(r"^ip=(\S+)$", text, re.M)  # Cloudflare trace format
    candidate = (m.group(1) if m else text).strip()
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return str(ip) if ip.version == 4 and ip.is_global else ""


def detect_public_ip() -> str:
    """Ask up to two sources. If two answer and disagree, don't trust either (no DNS change on a hunch)."""
    answers, errors = [], []
    for url in IP_SOURCES:
        try:
            ip = _parse_ip(_fetch(url))
            if ip:
                answers.append(ip)
            else:
                errors.append(f"{url}: no IPv4 address in the answer")
        except Exception as exc:
            errors.append(f"{url}: {exc}")
        if len(answers) == 2:
            break
    if not answers:
        raise RuntimeError("Could not find this server's public IP (" + "; ".join(errors)[:300] + ")")
    if len(set(answers)) > 1:
        raise RuntimeError(f"IP lookups disagree ({', '.join(answers)}); not changing anything")
    return answers[0]


# ---------------------------------------------------------------------------
# Cloudflare API
# ---------------------------------------------------------------------------

class CloudflareError(RuntimeError):
    pass


def _cf(method: str, path: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{CF_API}{path}", data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "BearerMail-DDNS"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            payload = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except Exception:
            payload = {}
        msgs = "; ".join(e.get("message", "") for e in payload.get("errors", []) if isinstance(e, dict))
        raise CloudflareError(f"Cloudflare said {exc.code}: {msgs or exc.reason}") from None
    except urllib.error.URLError as exc:
        raise CloudflareError(f"Could not reach Cloudflare: {exc.reason}") from None
    if not payload.get("success", False):
        msgs = "; ".join(e.get("message", "") for e in payload.get("errors", []) if isinstance(e, dict))
        raise CloudflareError(msgs or "Cloudflare refused the request")
    return payload


def _token() -> str:
    doc = _db().settings.find_one({"_id": "ddns"}, {"token_enc": 1}) or {}
    if not doc.get("token_enc"):
        raise HTTPException(status_code=422, detail="Add a Cloudflare API token first")
    return _cfg["decrypt"](doc["token_enc"])


def _zone_for(name: str, token: str, cache: dict) -> dict | None:
    """The Cloudflare zone holding ``name`` (tries mail.example.com, then example.com ...)."""
    labels = name.lower().strip(".").split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in cache:
            if cache[candidate]:
                return cache[candidate]
            continue
        res = _cf("GET", f"/zones?name={candidate}&per_page=5", token).get("result") or []
        cache[candidate] = {"id": res[0]["id"], "name": res[0]["name"]} if res else None
        if cache[candidate]:
            return cache[candidate]
    return None


def _records(zone_id: str, token: str, rtype: str) -> list:
    out, page = [], 1
    while True:
        payload = _cf("GET", f"/zones/{zone_id}/dns_records?type={rtype}&per_page=500&page={page}", token)
        out += payload.get("result") or []
        info = payload.get("result_info") or {}
        if page >= int(info.get("total_pages") or 1):
            return out
        page += 1


def _names_to_cover() -> list:
    db = _db()
    names = []
    for d in db.domains.find({"is_active": True}, {"domain": 1}):
        names.append(d["domain"])
        if _cfg.get("mail_host_for"):
            names.append(_cfg["mail_host_for"](d["domain"]))
    return list(dict.fromkeys(n for n in names if n))


def _swap_spf(content: str, old_ips: set, new_ip: str) -> str:
    out = content
    for old in old_ips:
        if old and old != new_ip:
            out = re.sub(r"(?<=ip4:)" + re.escape(old) + r"(?![\d.])", new_ip, out)
    # Two old IPs could both have become the new one: keep a single ip4:new
    parts, seen = [], set()
    for p in out.split(" "):
        key = p.strip('"').lower()
        if key.startswith("ip4:") and key in seen:
            continue
        seen.add(key)
        parts.append(p)
    return " ".join(parts)


def plan_ip_change(old_ips: set, new_ip: str, token: str) -> dict:
    """Every A record pointing at an old IP, and every SPF with ip4:<old>, in the zones of your domains."""
    zones, cache, missing = {}, {}, []
    for name in _names_to_cover():
        z = _zone_for(name, token, cache)
        if z:
            zones[z["id"]] = z["name"]
        else:
            missing.append(name)
    # Whatever the mail server name points at now is this server's old address too
    # (covers an IP that changed while the server was off).
    mail_hosts = {(_cfg["mail_host_for"](d["domain"]) if _cfg.get("mail_host_for") else "").lower()
                  for d in _db().domains.find({"is_active": True}, {"domain": 1})} - {""}
    a_cache = {zid: _records(zid, token, "A") for zid in zones}
    for recs in a_cache.values():
        old_ips |= {r["content"] for r in recs if r.get("name", "").lower() in mail_hosts}
    old_ips = {ip for ip in old_ips if ip and ip != new_ip}
    changes = []
    for zid, zname in zones.items():
        for r in a_cache[zid]:
            if r.get("content") in old_ips:
                changes.append({"zone_id": zid, "zone": zname, "id": r["id"], "type": "A", "name": r["name"],
                                "old": r["content"], "new": new_ip, "proxied": r.get("proxied", False)})
        for r in _records(zid, token, "TXT"):
            content = r.get("content", "")
            if "v=spf1" in content.lower():
                new = _swap_spf(content, old_ips, new_ip)
                if new != content:
                    changes.append({"zone_id": zid, "zone": zname, "id": r["id"], "type": "TXT", "name": r["name"],
                                    "old": content, "new": new})
    return {"changes": changes, "zones": sorted(set(zones.values())), "not_on_cloudflare": sorted(set(missing)),
            "old_ips": sorted(old_ips), "new_ip": new_ip}


def apply_changes(changes: list, token: str) -> list:
    results = []
    for c in changes:
        try:
            if c.get("action") == "create":
                body = {"type": c["type"], "name": c["name"], "content": c["new"], "ttl": 1}
                if c["type"] == "MX":
                    body["priority"] = c.get("priority", 10)
                if c["type"] == "A":
                    body["proxied"] = False
                _cf("POST", f"/zones/{c['zone_id']}/dns_records", token, body)
            else:
                _cf("PATCH", f"/zones/{c['zone_id']}/dns_records/{c['id']}", token, {"content": c["new"]})
            results.append({**c, "ok": True})
        except CloudflareError as exc:
            results.append({**c, "ok": False, "error": str(exc)})
    return results


def run_check(force_apply: bool = False, dry_run: bool = False) -> dict:
    """One round: detect the IP; if it changed (or force), update Cloudflare. Returns what happened."""
    s = _settings()
    now = datetime.now(timezone.utc)
    try:
        ip = detect_public_ip()
    except RuntimeError as exc:
        _save(last_check=now, last_error=str(exc))
        return {"ok": False, "error": str(exc)}
    previous = s.get("ip") or _cfg.get("env_ip", "")
    changed = bool(previous) and ip != previous
    out = {"ok": True, "ip": ip, "previous_ip": previous, "changed": changed}
    if dry_run:
        old = {previous, _cfg.get("env_ip", ""), *s.get("previous_ips", [])}
        out["plan"] = plan_ip_change(old, ip, _token())
        return out
    fields = {"ip": ip, "last_check": now, "last_error": ""}
    if changed:
        fields["previous_ips"] = ([previous] + [p for p in s.get("previous_ips", []) if p != previous and p != ip])[:10]
        fields["last_change"] = now
        _record("ip_changed", f"Public IP changed from {previous} to {ip}")
    _save(**fields)
    if (changed and s.get("auto_update")) or force_apply:
        try:
            token = _token()
            old = {previous, _cfg.get("env_ip", ""), *s.get("previous_ips", [])}
            plan = plan_ip_change(old, ip, token)
            results = apply_changes(plan["changes"], token)
            failed = [r for r in results if not r["ok"]]
            out.update(plan=plan, results=results)
            summary = f"{len(results) - len(failed)} DNS record(s) updated to {ip}" + (f", {len(failed)} failed" if failed else "")
            _save(last_result={"at": now, "summary": summary, "failed": len(failed)})
            _record("dns_update_failed" if failed else "dns_updated", summary + (": " + failed[0]["error"] if failed else ""),
                    level="warn" if failed else None)
        except (CloudflareError, HTTPException) as exc:
            msg = getattr(exc, "detail", None) or str(exc)
            _save(last_error=msg, last_result={"at": now, "summary": "Cloudflare update failed", "failed": 1})
            _record("dns_update_failed", f"Cloudflare update failed: {msg}", level="warn")
            out.update(ok=False, error=msg)
    return out


async def loop():
    """Background check. Runs inside the mail service; a failed round just waits for the next one."""
    await asyncio.sleep(20)
    while True:
        try:
            s = _settings()
            interval = max(MIN_INTERVAL, int(s.get("interval_min") or 5))
            last = s.get("last_check")
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if s.get("enabled") and (not last or (datetime.now(timezone.utc) - last).total_seconds() >= interval * 60):
                await asyncio.to_thread(run_check)
        except Exception as exc:  # never let the loop die
            logger.warning(f"Dynamic IP check failed: {exc}")
        await asyncio.sleep(60)


# ---------------------------------------------------------------------------
# Push a domain's recommended records to Cloudflare
# ---------------------------------------------------------------------------

def _norm_txt(v: str) -> str:
    """Cloudflare may return TXT content quoted and split into 255-char strings: "abc" "def" -> abcdef."""
    v = (v or "").strip()
    if v.startswith('"') and v.endswith('"'):
        v = re.sub(r'"\s*"', "", v).strip('"')
    return v


def _merge_spf(existing: str, wanted: str, old_ips: set) -> str:
    have = _norm_txt(existing).split()
    want = wanted.split()
    mechs = [p for p in have[1:] if not p.lower().endswith("all") and
             not (p.lower().startswith("ip4:") and p[4:].split("/")[0] in old_ips)]
    for p in want[1:]:
        if not p.endswith("all") and p not in mechs:
            mechs.append(p)
    tail = next((p for p in have if p.lower().endswith("all")), want[-1])
    return " ".join(["v=spf1", *mechs, tail])


def plan_domain(domain: str, token: str) -> dict:
    data = _cfg["build_dns_records"](domain)
    cache = {}
    want = {r["id"]: r for r in data["records"]}
    changes, notes = [], []
    old_ips = known_ips() - {data["server_ip"]}

    def zone_or_note(fqdn):
        z = _zone_for(fqdn, token, cache)
        if not z:
            notes.append(f"{fqdn} is not in a zone this Cloudflare token can edit; add that record by hand.")
        return z

    # A record for the mail server name
    a = want["a"]
    if data["server_ip"]:
        z = zone_or_note(a["fqdn"])
        if z:
            recs = [r for r in _records(z["id"], token, "A") if r["name"].lower() == a["fqdn"].lower()]
            if not recs:
                changes.append({"action": "create", "zone_id": z["id"], "zone": z["name"], "type": "A", "name": a["fqdn"],
                                "old": "", "new": data["server_ip"], "why": "mail server name -> this server"})
            for r in recs:
                if r["content"] != data["server_ip"]:
                    changes.append({"zone_id": z["id"], "zone": z["name"], "id": r["id"], "type": "A", "name": r["name"],
                                    "old": r["content"], "new": data["server_ip"], "why": "mail server name -> this server"})
                if r.get("proxied"):
                    notes.append(f"{r['name']} is proxied (orange cloud). Mail can't pass through the proxy: switch it to DNS only.")
    else:
        notes.append("This server's IP is unknown, so the A record and SPF ip4 were skipped.")

    z = zone_or_note(domain)
    if z:
        txt = _records(z["id"], token, "TXT")
        # MX
        mx = [r for r in _records(z["id"], token, "MX") if r["name"].lower() == domain]
        if not any(r["content"].lower().rstrip(".") == want["mx"]["value"].lower() for r in mx):
            changes.append({"action": "create", "zone_id": z["id"], "zone": z["name"], "type": "MX", "name": domain,
                            "old": "", "new": want["mx"]["value"], "priority": 10, "why": "deliver mail for the domain here"})
        others = [r["content"] for r in mx if r["content"].lower().rstrip(".") != want["mx"]["value"].lower()]
        if others:
            notes.append("Other MX records exist and were left alone (" + ", ".join(others) +
                         "). Remove them at Cloudflare if mail should only come here.")
        # SPF
        spf = [r for r in txt if r["name"].lower() == domain and "v=spf1" in r.get("content", "").lower()]
        if not spf:
            changes.append({"action": "create", "zone_id": z["id"], "zone": z["name"], "type": "TXT", "name": domain,
                            "old": "", "new": want["spf"]["value"], "why": "SPF"})
        else:
            merged = _merge_spf(spf[0]["content"], want["spf"]["value"], old_ips)
            if merged != _norm_txt(spf[0]["content"]):
                changes.append({"zone_id": z["id"], "zone": z["name"], "id": spf[0]["id"], "type": "TXT", "name": domain,
                                "old": spf[0]["content"], "new": merged, "why": "SPF (keeps your other senders)"})
            if len(spf) > 1:
                notes.append("This domain has more than one SPF record; receivers treat that as an error. Delete the extras.")
        # DKIM
        dk = want["dkim"]
        cur = [r for r in txt if r["name"].lower() == dk["fqdn"].lower()]
        if not cur:
            changes.append({"action": "create", "zone_id": z["id"], "zone": z["name"], "type": "TXT", "name": dk["fqdn"],
                            "old": "", "new": dk["value"], "why": "DKIM key"})
        elif _norm_txt(cur[0]["content"]).replace(" ", "") != dk["value"].replace(" ", ""):
            changes.append({"zone_id": z["id"], "zone": z["name"], "id": cur[0]["id"], "type": "TXT", "name": dk["fqdn"],
                            "old": cur[0]["content"][:60] + "…", "new": dk["value"], "why": "DKIM key"})
        # DMARC: only created when missing; your policy is never overwritten
        dm = want["dmarc"]
        if not [r for r in txt if r["name"].lower() == dm["fqdn"].lower() and "v=dmarc1" in r.get("content", "").lower()]:
            changes.append({"action": "create", "zone_id": z["id"], "zone": z["name"], "type": "TXT", "name": dm["fqdn"],
                            "old": "", "new": dm["value"], "why": "DMARC (monitor mode)"})
    return {"domain": domain, "changes": changes, "notes": notes}


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

def _public() -> dict:
    s = _settings()
    doc = _db().settings.find_one({"_id": "ddns"}, {"token_enc": 1, "token_hint": 1}) or {}
    iso = lambda d: d.isoformat() + ("Z" if d and d.tzinfo is None else "") if isinstance(d, datetime) else d  # noqa: E731
    res = s.get("last_result") or None
    if res:
        res = {**res, "at": iso(res.get("at"))}
    return {"enabled": s["enabled"], "auto_update": s["auto_update"], "interval_min": s["interval_min"],
            "ip": s["ip"], "env_ip": _cfg.get("env_ip", ""), "current_ip": current_ip(),
            "previous_ips": s["previous_ips"], "last_check": iso(s["last_check"]), "last_change": iso(s["last_change"]),
            "last_error": s["last_error"], "last_result": res, "has_token": bool(doc.get("token_enc")),
            "token_hint": doc.get("token_hint", "")}


@router.get("/admin/ddns", dependencies=[Depends(_auth)])
def get_ddns():
    return _public()


@router.patch("/admin/ddns", dependencies=[Depends(_auth)])
async def update_ddns(request: Request):
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Invalid request")
    fields = {}
    if "token" in data:
        token = str(data["token"] or "").strip()
        if token:
            if not re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", token):
                raise HTTPException(status_code=422, detail="That doesn't look like a Cloudflare API token")
            try:
                _cf("GET", "/user/tokens/verify", token)
            except CloudflareError as exc:
                raise HTTPException(status_code=422, detail=f"Cloudflare did not accept the token: {exc}") from None
            fields["token_enc"] = _cfg["encrypt"](token)
            fields["token_hint"] = "…" + token[-4:]
        else:
            fields["token_enc"] = ""
            fields["token_hint"] = ""
            fields["enabled"] = False
    if "enabled" in data:
        fields["enabled"] = bool(data["enabled"])
    if "auto_update" in data:
        fields["auto_update"] = bool(data["auto_update"])
    if "interval_min" in data:
        try:
            fields["interval_min"] = max(MIN_INTERVAL, min(1440, int(data["interval_min"])))
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="Interval must be minutes") from None
    if fields.get("enabled") and not (fields.get("token_enc") or (_db().settings.find_one({"_id": "ddns"}) or {}).get("token_enc")):
        raise HTTPException(status_code=422, detail="Add a Cloudflare API token first")
    if fields:
        _save(**fields)
        _record("settings_changed", "Dynamic IP / Cloudflare settings changed")
    return _public()


@router.post("/admin/ddns/check", dependencies=[Depends(_auth)])
def ddns_check(preview: int = 1):
    """preview=1: find the IP and list what would change at Cloudflare. preview=0: update Cloudflare now."""
    try:
        out = run_check(dry_run=bool(preview), force_apply=not preview)
    except CloudflareError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return {**out, "settings": _public()}


@router.post("/admin/domains/{domain}/cloudflare", dependencies=[Depends(_auth)])
async def push_domain(domain: str, request: Request, apply: int = 0):
    """Compare a domain's recommended DNS with Cloudflare; apply=1 makes the listed changes."""
    domain = domain.strip().lower()
    if not _db().domains.find_one({"domain": domain}):
        raise HTTPException(status_code=404, detail="Domain not found")
    token = _token()
    try:
        plan = plan_domain(domain, token)
        if apply:
            results = apply_changes(plan["changes"], token)
            failed = [r for r in results if not r["ok"]]
            _record("dns_update_failed" if failed else "dns_updated",
                    f"{domain}: {len(results) - len(failed)} record(s) set at Cloudflare" + (f", {len(failed)} failed" if failed else ""),
                    level="warn" if failed else None)
            plan["results"] = results
    except CloudflareError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    for c in plan["changes"] + plan.get("results", []):
        c.pop("zone_id", None)
    return plan
