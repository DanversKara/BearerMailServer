"""SMTP keys (Setup > APIs): personal keys that send through the admin's provider without revealing it."""

import smtplib
import ssl
import subprocess
from datetime import datetime, timezone

import bcrypt
import pytest

import bearer_ext
import relay_ext

API = {"Authorization": "Bearer test-api-key"}


class FakeProvider:
    def __init__(self):
        self.sent = []
        self.providers = []

    def open(self, p):
        self.providers.append(p["name"])
        return self

    def sendmail(self, frm, to, data):
        self.sent.append((frm, list(to), data))

    def quit(self):
        pass


@pytest.fixture
def world(client, mock_mongo, monkeypatch):
    now = datetime.now(timezone.utc)
    for addr in ("jane@test.local", "sam@test.local"):
        mock_mongo.accounts.insert_one({"address": addr, "password_hash": bcrypt.hashpw(b"pw-123456789", bcrypt.gensalt(4)).decode(),
                                        "is_active": True, "created_at": now})
    mock_mongo.aliases.insert_one({"address": "shop@test.local", "deliver_to": "jane@test.local", "enabled": True, "created_at": now})
    mj = mock_mongo.smtp_providers.insert_one({"name": "Mailjet", "host": "in-v3.mailjet.com", "port": 587, "security": "starttls",
                                               "username": "PUBLIC", "password_enc": bearer_ext.encrypt_secret("REAL-SECRET"),
                                               "is_default": True, "owner": None, "created_at": now}).inserted_id
    brevo = mock_mongo.smtp_providers.insert_one({"name": "Brevo", "host": "smtp-relay.brevo.com", "port": 587, "security": "starttls",
                                                  "username": "u", "password_enc": "", "is_default": False, "owner": None,
                                                  "created_at": now}).inserted_id
    fake = FakeProvider()
    monkeypatch.setattr(bearer_ext, "_open_smtp", fake.open)
    relay_ext._sent_times.clear()
    relay_ext._auth_failures.clear()
    return {"fake": fake, "mailjet": str(mj), "brevo": str(brevo)}


def _raw(frm="jane@test.local", to="friend@else.example", extra=""):
    return (f"From: Jane <{frm}>\r\nTo: {to}\r\n{extra}Subject: Hello\r\n\r\nHi there\r\n").encode()


def new_key(client, owner="jane@test.local", **kw):
    r = client.post("/admin/relay-keys", headers=API, json={"owner": owner, "label": "Thunderbird", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_key_is_shown_once_and_stored_hashed(client, world, mock_mongo):
    made = new_key(client)
    assert made["username"].startswith("bm-") and made["password"].startswith("bmk_")
    doc = mock_mongo.relay_keys.find_one({"username": made["username"]})
    assert made["password"] not in str(doc)
    listing = client.get("/admin/relay-keys", headers=API).json()
    assert "password" not in str(listing["keys"]) and made["password"] not in str(listing)
    # The provider's real secret is never part of any answer
    assert "REAL-SECRET" not in str(listing) and "REAL-SECRET" not in str(made)


def test_send_with_key_goes_through_provider(client, world, mock_mongo):
    made = new_key(client)
    k, acc = relay_ext.authenticate(made["username"], made["password"], ip="198.51.100.4")
    out = relay_ext.deliver(k, acc, "jane@test.local", ["friend@else.example"], _raw(extra="Bcc: secret@else.example\r\n"))
    assert out["provider"] == "Mailjet"
    frm, to, data = world["fake"].sent[0]
    assert frm == "jane@test.local" and to == ["friend@else.example"]
    assert b"Bcc" not in data and b"Message-ID" in data
    assert mock_mongo.sent_messages.find_one({"owner": "jane@test.local"})["subject"] == "Hello"
    assert mock_mongo.relay_keys.find_one({"username": made["username"]})["sent_count"] == 1
    # Aliases that deliver into the mailbox are fine too
    relay_ext.deliver(k, acc, "shop@test.local", ["friend@else.example"], _raw(frm="shop@test.local"))


def test_key_cannot_spoof_other_senders(client, world):
    made = new_key(client)
    k, acc = relay_ext.authenticate(made["username"], made["password"])
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.deliver(k, acc, "sam@test.local", ["x@else.example"], _raw(frm="sam@test.local"))
    # Envelope is Jane's but the visible From header says Sam
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw(frm="sam@test.local"))
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.deliver(k, acc, "ceo@bank.example", ["x@else.example"], _raw(frm="ceo@bank.example"))
    assert world["fake"].sent == []


def test_wrong_password_and_revoked_key(client, world):
    made = new_key(client)
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.authenticate(made["username"], "bmk_wrong")
    k, acc = relay_ext.authenticate(made["username"], made["password"])
    client.post(f"/admin/relay-keys/{made['key']['id']}/revoke", headers=API, json={})
    with pytest.raises(relay_ext.RelayRefused, match="revoked"):
        relay_ext.authenticate(made["username"], made["password"])
    # A session that signed in before the revoke cannot send either
    with pytest.raises(relay_ext.RelayRefused, match="revoked"):
        relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    # Other keys keep working
    other = new_key(client)
    relay_ext.authenticate(other["username"], other["password"])


def test_password_guessing_is_throttled(client, world):
    made = new_key(client)
    for _ in range(relay_ext._AUTH_FAIL_MAX):
        with pytest.raises(relay_ext.RelayRefused):
            relay_ext.authenticate(made["username"], "nope", ip="203.0.113.50")
    with pytest.raises(relay_ext.RelayTemporary):
        relay_ext.authenticate(made["username"], made["password"], ip="203.0.113.50")


def test_hourly_limit_and_send_permission(client, world, mock_mongo):
    made = new_key(client, hourly_limit=2)
    k, acc = relay_ext.authenticate(made["username"], made["password"])
    relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    with pytest.raises(relay_ext.RelayTemporary, match="limit"):
        relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"send": False}})
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.authenticate(made["username"], made["password"])


def test_provider_permissions_are_respected(client, world):
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"smtp_providers": [world["brevo"]]}})
    assert client.post("/admin/relay-keys", headers=API, json={"owner": "jane@test.local", "provider_id": world["mailjet"]}).status_code == 422
    made = new_key(client)
    k, acc = relay_ext.authenticate(made["username"], made["password"])
    assert relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())["provider"] == "Brevo"
    pinned = new_key(client, provider_id=world["brevo"])
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"smtp_providers": [world["mailjet"]]}})
    k2, acc2 = relay_ext.authenticate(pinned["username"], pinned["password"])
    with pytest.raises(relay_ext.RelayRefused, match="no longer available"):
        relay_ext.deliver(k2, acc2, "jane@test.local", ["x@else.example"], _raw())


def test_self_service_keys(client, world):
    r = client.post("/admin/users/jane@test.local/relay-keys", headers=API, json={"label": "Phone"})
    assert r.status_code == 201
    kid = r.json()["key"]["id"]
    info = client.get("/admin/users/jane@test.local/relay-keys", headers=API).json()
    assert len(info["keys"]) == 1 and info["can_create"] is True
    # Sam cannot see or revoke Jane's key
    assert client.get("/admin/users/sam@test.local/relay-keys", headers=API).json()["keys"] == []
    assert client.post(f"/admin/users/sam@test.local/relay-keys/{kid}/revoke", headers=API).status_code == 404
    assert client.post(f"/admin/users/jane@test.local/relay-keys/{kid}/revoke", headers=API).json()["revoked"] is True
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"smtp_keys": False}})
    assert client.post("/admin/users/jane@test.local/relay-keys", headers=API, json={}).status_code == 403
    for _ in range(relay_ext.SELF_SERVICE_MAX_KEYS):
        new_key(client, owner="sam@test.local")
    assert client.post("/admin/users/sam@test.local/relay-keys", headers=API, json={}).status_code == 409


def test_revoke_all_for_one_user(client, world):
    a, b, c = new_key(client), new_key(client), new_key(client, owner="sam@test.local")
    assert client.post("/admin/relay-keys/revoke-all", headers=API, json={"owner": "jane@test.local"}).json()["revoked"] == 2
    for made in (a, b):
        with pytest.raises(relay_ext.RelayRefused):
            relay_ext.authenticate(made["username"], made["password"])
    relay_ext.authenticate(c["username"], c["password"])


def test_http_api(client, world):
    made = new_key(client)
    body = {"username": made["username"], "password": made["password"], "from_email": "jane@test.local",
            "to": ["friend@else.example"], "subject": "Report", "text": "Numbers", "client_ip": "198.51.100.9"}
    r = client.post("/admin/relay/send", headers=API, json=body)
    assert r.status_code == 200 and r.json()["provider"] == "Mailjet"
    assert client.post("/admin/relay/send", headers=API, json={**body, "password": "bad"}).status_code == 401
    assert client.post("/admin/relay/send", headers=API, json={**body, "from_email": "sam@test.local"}).status_code == 403
    assert client.post("/admin/relay/send", json=body).status_code in (401, 403)  # needs the internal API key


def test_connect_info_mentions_submission(client, world):
    info = client.get("/admin/connect-info", headers=API).json()
    assert "submission" in info and "enabled" in info["submission"]


@pytest.fixture
def cert(tmp_path):
    key, crt = tmp_path / "privkey.pem", tmp_path / "fullchain.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return str(crt), str(key)


def test_submission_ports_end_to_end(client, world, cert, monkeypatch):
    monkeypatch.setattr(relay_ext, "SUBMISSION_PORT", 25870)
    monkeypatch.setattr(relay_ext, "SUBMISSIONS_PORT", 24650)
    relay_ext.start_submission_servers(cert[0], cert[1], "localhost")
    assert relay_ext.submission_info()["ports"] == [25870, 24650]
    made = new_key(client)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 587: AUTH is refused before STARTTLS, so passwords never travel in the clear
    s = smtplib.SMTP("127.0.0.1", 25870, timeout=10)
    s.ehlo()
    with pytest.raises(smtplib.SMTPException):
        s.login(made["username"], made["password"])
    s.starttls(context=ctx)
    s.ehlo()
    with pytest.raises(smtplib.SMTPAuthenticationError):
        s.login(made["username"], "bmk_wrong")
    s.login(made["username"], made["password"])
    with pytest.raises(smtplib.SMTPSenderRefused):
        s.sendmail("sam@test.local", ["x@else.example"], _raw(frm="sam@test.local"))
    s.sendmail("jane@test.local", ["x@else.example"], _raw())
    s.quit()

    # 465: TLS from the first byte
    s = smtplib.SMTP_SSL("127.0.0.1", 24650, timeout=10, context=ctx)
    s.login(made["username"], made["password"])
    s.sendmail("shop@test.local", ["x@else.example"], _raw(frm="shop@test.local"))
    s.quit()
    assert [m[0] for m in world["fake"].sent] == ["jane@test.local", "shop@test.local"]

    # Without signing in nothing is relayed
    s = smtplib.SMTP_SSL("127.0.0.1", 24650, timeout=10, context=ctx)
    with pytest.raises(smtplib.SMTPException):
        s.sendmail("jane@test.local", ["x@else.example"], _raw())
    s.close()


def test_submission_stays_off_without_certificate(tmp_path):
    relay_ext.start_submission_servers(str(tmp_path / "missing.pem"), str(tmp_path / "missing.key"), "localhost")
    info = relay_ext.submission_info()
    assert info["enabled"] is False and "certificate" in info["reason"]


# ---- app passwords (Gmail style: email + 16-letter code, for IMAP and sending) ----

def test_app_password_signs_in_with_email(client, world, mock_mongo):
    made = client.post("/admin/users/jane@test.local/app-passwords", headers=API, json={"label": "Thunderbird"}).json()
    pw = made["password"]
    assert len(pw) == 19 and pw.count(" ") == 3 and made["username"] == "jane@test.local"
    # Same hash the IMAP server computes (tests in imap-server/test/auth.test.js use the same formula)
    assert relay_ext._hash(relay_ext.normalize_app_password("ABCD efgh JKMN pqrs")) == \
        "ee8be3a2221a237728d1aeaff8db8d961a86516297ca1145591a1a800d0a77c7"
    k, acc = relay_ext.authenticate("Jane@test.local", pw.upper().replace(" ", ""))
    assert k["kind"] == "app_password" and acc["address"] == "jane@test.local"
    relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    # Not usable as an SMTP-key username, and not listed among SMTP keys
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.authenticate(k["username"], pw)
    assert client.get("/admin/users/jane@test.local/relay-keys", headers=API).json()["keys"] == []
    info = client.get("/admin/users/jane@test.local/app-passwords", headers=API).json()
    assert len(info["app_passwords"]) == 1 and info["only"] is False
    # Sam cannot revoke Jane's; Jane can
    aid = made["app_password"]["id"]
    assert client.post(f"/admin/users/sam@test.local/app-passwords/{aid}/revoke", headers=API).status_code == 404
    assert client.post(f"/admin/users/jane@test.local/app-passwords/{aid}/revoke", headers=API).json()["revoked"] is True
    with pytest.raises(relay_ext.RelayRefused, match="revoked"):
        relay_ext.authenticate("jane@test.local", pw)


def test_mailbox_password_and_app_passwords_only(client, world, mock_mongo):
    k, acc = relay_ext.authenticate("jane@test.local", "pw-123456789")
    assert k["kind"] == "mailbox_password"
    relay_ext.deliver(k, acc, "jane@test.local", ["x@else.example"], _raw())
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.authenticate("jane@test.local", "wrong-password")
    client.post("/admin/users/jane@test.local/app-passwords-only", headers=API, json={"only": True})
    with pytest.raises(relay_ext.RelayRefused, match="app password"):
        relay_ext.authenticate("jane@test.local", "pw-123456789")
    client.post("/admin/users/jane@test.local/app-passwords-only", headers=API, json={"only": False})
    relay_ext.authenticate("jane@test.local", "pw-123456789")
    client.post("/admin/auth/app-passwords-required", headers=API, json={"required": True})
    assert client.get("/admin/auth/mode", headers=API).json()["app_passwords_required"] is True
    with pytest.raises(relay_ext.RelayRefused):
        relay_ext.authenticate("sam@test.local", "pw-123456789")
    # The admin can switch off sending with the real password for one person
    client.post("/admin/auth/app-passwords-required", headers=API, json={"required": False})
    client.post(f"/admin/relay-keys/{k['_id']}/revoke", headers=API, json={})
    with pytest.raises(relay_ext.RelayRefused, match="mailbox password"):
        relay_ext.authenticate("jane@test.local", "pw-123456789")
