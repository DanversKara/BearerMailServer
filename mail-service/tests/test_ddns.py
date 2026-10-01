"""Dynamic IP detection and Cloudflare DNS updates (Cloudflare is faked in memory)."""

import re
from urllib.parse import parse_qs, urlparse

import pytest

import ddns_ext

API = {"Authorization": "Bearer test-api-key"}
TOKEN = "cf_" + "a" * 37


class FakeCloudflare:
    def __init__(self):
        self.zones = {"z1": "example.org"}
        self.records = {}
        self.n = 0
        self.calls = []

    def add(self, zone, type_, name, content, proxied=False):
        self.n += 1
        rid = f"r{self.n}"
        self.records[rid] = {"id": rid, "zone": zone, "type": type_, "name": name, "content": content, "proxied": proxied}
        return rid

    def __call__(self, method, path, token, body=None):
        assert token == TOKEN
        self.calls.append((method, path, body))
        u = urlparse(path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/user/tokens/verify":
            return {"success": True, "result": {"status": "active"}}
        if u.path == "/zones":
            return {"success": True, "result": [{"id": z, "name": n} for z, n in self.zones.items() if n == q["name"]]}
        m = re.fullmatch(r"/zones/(\w+)/dns_records(?:/(\w+))?", u.path)
        zone, rid = m.group(1), m.group(2)
        if method == "GET":
            res = [r for r in self.records.values() if r["zone"] == zone and r["type"] == q["type"]]
            return {"success": True, "result": res, "result_info": {"total_pages": 1}}
        if method == "PATCH":
            self.records[rid]["content"] = body["content"]
            return {"success": True, "result": self.records[rid]}
        if method == "POST":
            self.add(zone, body["type"], body["name"], body["content"], body.get("proxied", False))
            return {"success": True, "result": {}}
        raise AssertionError(path)


@pytest.fixture
def cf(client, monkeypatch, mock_mongo):
    fake = FakeCloudflare()
    monkeypatch.setattr(ddns_ext, "_cf", fake)
    monkeypatch.setitem(ddns_ext._cfg, "env_ip", "52.0.0.5")
    import bearer_ext
    monkeypatch.setattr(bearer_ext._cfg, "server_ip", "52.0.0.5")
    mock_mongo.domains.update_one({"domain": "example.org"}, {"$set": {"domain": "example.org", "is_active": True,
                                                                        "mail_host": "mail.example.org"}}, upsert=True)
    return fake


def set_ip(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr(ddns_ext, "_fetch", lambda url, timeout=8: next(it))


def test_detect_ip_needs_agreement(monkeypatch):
    set_ip(monkeypatch, "fl=1\nip=54.0.0.7\nts=1", "54.0.0.7")
    assert ddns_ext.detect_public_ip() == "54.0.0.7"
    set_ip(monkeypatch, "ip=54.0.0.7", "54.0.0.8")
    with pytest.raises(RuntimeError, match="disagree"):
        ddns_ext.detect_public_ip()
    set_ip(monkeypatch, "ip=192.168.8.100", "10.0.0.1")  # private addresses are never accepted
    with pytest.raises(RuntimeError):
        ddns_ext.detect_public_ip()


def test_spf_swap_keeps_everything_else():
    spf = '"v=spf1 ip4:52.0.0.5 ip4:52.0.0.50 include:spf.mailjet.com ~all"'
    assert ddns_ext._swap_spf(spf, {"52.0.0.5"}, "54.0.0.7") == \
        '"v=spf1 ip4:54.0.0.7 ip4:52.0.0.50 include:spf.mailjet.com ~all"'
    assert ddns_ext._merge_spf("v=spf1 ip4:52.0.0.5 include:_spf.google.com -all",
                               "v=spf1 ip4:54.0.0.7 include:spf.mailjet.com ~all", {"52.0.0.5"}) == \
        "v=spf1 include:_spf.google.com ip4:54.0.0.7 include:spf.mailjet.com -all"


def test_settings_token_and_ip_change_updates_cloudflare(client, cf, monkeypatch, mock_mongo):
    a = cf.add("z1", "A", "mail.example.org", "52.0.0.5")
    apex = cf.add("z1", "A", "example.org", "52.0.0.5", proxied=True)
    other = cf.add("z1", "A", "vps.example.org", "192.0.2.44")
    spf = cf.add("z1", "TXT", "example.org", "v=spf1 ip4:52.0.0.5 include:spf.mailjet.com ~all")
    cf.add("z1", "TXT", "example.org", "google-site-verification=abc")

    r = client.patch("/admin/ddns", headers=API, json={"enabled": True})
    assert r.status_code == 422  # token first
    r = client.patch("/admin/ddns", headers=API, json={"token": TOKEN, "enabled": True, "interval_min": 1})
    assert r.status_code == 200 and r.json()["has_token"] and r.json()["interval_min"] == ddns_ext.MIN_INTERVAL
    assert TOKEN not in str(mock_mongo.settings.find_one({"_id": "ddns"}))  # stored encrypted

    # Same IP: nothing to do
    set_ip(monkeypatch, "ip=52.0.0.5", "52.0.0.5")
    out = client.post("/admin/ddns/check", params={"preview": 1}, headers=API).json()
    assert out["changed"] is False and out["plan"]["changes"] == []

    # The IP changes: the background round updates Cloudflare and the app's own DNS page
    set_ip(monkeypatch, "ip=54.0.0.7", "54.0.0.7")
    out = ddns_ext.run_check()
    assert out["changed"] and all(x["ok"] for x in out["results"])
    assert cf.records[a]["content"] == "54.0.0.7"
    assert cf.records[apex]["content"] == "54.0.0.7" and cf.records[apex]["proxied"] is True
    assert cf.records[other]["content"] == "192.0.2.44"
    assert cf.records[spf]["content"] == "v=spf1 ip4:54.0.0.7 include:spf.mailjet.com ~all"
    dns = client.get("/admin/domains/example.org/dns", headers=API).json()
    assert dns["server_ip"] == "54.0.0.7"
    assert "52.0.0.5" in ddns_ext.known_ips()
    kinds = {e["kind"] for e in mock_mongo.security_events.find()}
    assert {"ip_changed", "dns_updated"} <= kinds


def test_auto_update_off_only_records(client, cf, monkeypatch, mock_mongo):
    a = cf.add("z1", "A", "mail.example.org", "52.0.0.5")
    client.patch("/admin/ddns", headers=API, json={"token": TOKEN, "enabled": True, "auto_update": False})
    set_ip(monkeypatch, "ip=54.0.0.9", "54.0.0.9")
    out = ddns_ext.run_check()
    assert out["changed"] and "results" not in out and cf.records[a]["content"] == "52.0.0.5"
    # "Update now" fixes it, also when the A record holds an address the app never knew
    cf.records[a]["content"] = "192.0.2.200"
    set_ip(monkeypatch, "ip=54.0.0.9", "54.0.0.9")
    client.post("/admin/ddns/check", params={"preview": 0}, headers=API)
    assert cf.records[a]["content"] == "54.0.0.9"


def test_push_domain_records(client, cf, monkeypatch, mock_mongo):
    client.patch("/admin/ddns", headers=API, json={"token": TOKEN})
    cf.add("z1", "TXT", "example.org", '"v=spf1 include:_spf.google.com ~all"')
    cf.add("z1", "MX", "example.org", "aspmx.l.google.com")
    plan = client.post("/admin/domains/example.org/cloudflare", headers=API).json()
    kinds = {(c["type"], c["name"]) for c in plan["changes"]}
    assert ("A", "mail.example.org") in kinds and ("MX", "example.org") in kinds
    assert any(c["name"].endswith("._domainkey.example.org") for c in plan["changes"])
    assert any("_dmarc" in c["name"] for c in plan["changes"])
    spf = next(c for c in plan["changes"] if c["type"] == "TXT" and c["name"] == "example.org")
    assert "include:_spf.google.com" in spf["new"] and "ip4:52.0.0.5" in spf["new"]
    assert any("Other MX" in n for n in plan["notes"])
    assert all("zone_id" not in c for c in plan["changes"])

    r = client.post("/admin/domains/example.org/cloudflare", params={"apply": 1}, headers=API).json()
    assert all(x["ok"] for x in r["results"])
    again = client.post("/admin/domains/example.org/cloudflare", headers=API).json()
    assert again["changes"] == []  # everything in place now
    dmarc = [x for x in cf.records.values() if x["name"] == "_dmarc.example.org"]
    assert len(dmarc) == 1 and dmarc[0]["content"].startswith("v=DMARC1")


def test_bad_token_and_auth(client, monkeypatch):
    assert client.get("/admin/ddns").status_code in (401, 403)
    assert client.patch("/admin/ddns", headers=API, json={"token": "x"}).status_code == 422

    def refuse(*a, **k):
        raise ddns_ext.CloudflareError("Invalid API Token")
    monkeypatch.setattr(ddns_ext, "_cf", refuse)
    r = client.patch("/admin/ddns", headers=API, json={"token": TOKEN})
    assert r.status_code == 422 and "Invalid API Token" in r.json()["detail"]
