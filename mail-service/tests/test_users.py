"""Multi-account mode: roles, permissions, per-user two-factor, own aliases and SMTP providers."""

import time
from datetime import datetime, timezone

import bcrypt
import pytest

import users_ext

API = {"Authorization": "Bearer test-api-key"}


@pytest.fixture
def people(client, mock_mongo):
    now = datetime.now(timezone.utc)
    for addr, pw in (("boss@test.local", "boss-password-1"), ("jane@test.local", "jane-password-1"), ("sam@example.test", "sam-password-1")):
        mock_mongo.accounts.insert_one({"address": addr, "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt(4)).decode(),
                                        "is_active": True, "created_at": now})
    shared = mock_mongo.smtp_providers.insert_one({"name": "Mailjet", "host": "in-v3.mailjet.com", "port": 587, "security": "starttls",
                                                   "username": "u", "password_enc": "", "is_default": True, "created_at": now})
    other = mock_mongo.smtp_providers.insert_one({"name": "Brevo", "host": "smtp-relay.brevo.com", "port": 587, "security": "starttls",
                                                  "username": "u", "password_enc": "", "is_default": False, "created_at": now})
    return {"shared": str(shared.inserted_id), "other": str(other.inserted_id)}


def test_switching_modes(client, people):
    assert client.get("/admin/auth/mode", headers=API).json()["mode"] == "single"
    assert client.post("/admin/auth/mode", headers=API, json={"mode": "multi", "admin": "nobody@test.local"}).status_code == 422
    assert client.post("/admin/auth/mode", headers=API, json={"mode": "multi", "admin": "boss@test.local", "password": "short"}).status_code == 422
    r = client.post("/admin/auth/mode", headers=API, json={"mode": "multi", "admin": "boss@test.local", "password": "a-new-admin-pass"})
    assert r.json()["mode"] == "multi"
    assert client.post("/admin/users/login", headers=API, json={"address": "boss@test.local", "password": "a-new-admin-pass"}).json()["role"] == "admin"
    assert client.post("/admin/auth/mode", headers=API, json={"mode": "single"}).json()["mode"] == "single"


def test_login_checks_password_and_active(client, people, mock_mongo):
    ok = client.post("/admin/users/login", headers=API, json={"address": "jane@test.local", "password": "jane-password-1"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["role"] == "user" and body["addresses"] == ["jane@test.local"]
    assert body["permissions"]["send"] is True and body["permissions"]["own_smtp"] is False
    assert client.post("/admin/users/login", headers=API, json={"address": "jane@test.local", "password": "nope"}).status_code == 401
    assert client.post("/admin/users/login", headers=API, json={"address": {"$gt": ""}, "password": "x"}).status_code == 401
    mock_mongo.accounts.update_one({"address": "jane@test.local"}, {"$set": {"is_active": False}})
    assert client.post("/admin/users/login", headers=API, json={"address": "jane@test.local", "password": "jane-password-1"}).status_code == 403


def test_cannot_remove_the_last_admin(client, people):
    client.post("/admin/auth/mode", headers=API, json={"mode": "multi", "admin": "boss@test.local"})
    assert client.patch("/admin/users/boss@test.local", headers=API, json={"role": "user"}).status_code == 409
    assert client.patch("/admin/users/boss@test.local", headers=API, json={"is_active": False}).status_code == 409
    client.patch("/admin/users/jane@test.local", headers=API, json={"role": "admin"})
    assert client.patch("/admin/users/boss@test.local", headers=API, json={"role": "user"}).status_code == 200


def test_permissions_are_validated(client, people):
    assert client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"send": "yes"}}).status_code == 422
    r = client.patch("/admin/users/jane@test.local", headers=API,
                     json={"permissions": {"smtp_providers": [people["other"], "not-a-provider"], "max_aliases": 2, "own_smtp": True}})
    perms = r.json()["permissions"]
    assert perms["smtp_providers"] == [people["other"]] and perms["max_aliases"] == 2 and perms["own_smtp"] is True


def test_per_user_two_factor(client, people):
    secret = client.post("/admin/users/jane@test.local/2fa/setup", headers=API).json()["secret"]
    assert client.post("/admin/users/jane@test.local/2fa/enable", headers=API, json={"code": "000000"}).status_code == 400
    code = users_ext._hotp(secret, int(time.time() // 30))
    codes = client.post("/admin/users/jane@test.local/2fa/enable", headers=API, json={"code": code}).json()["recovery_codes"]
    assert len(codes) == 10
    assert client.post("/admin/users/login", headers=API, json={"address": "jane@test.local", "password": "jane-password-1"}).json()["two_factor"]
    # The code used to turn it on cannot be replayed to sign in
    assert client.post("/admin/users/jane@test.local/2fa/verify", headers=API, json={"code": code}).status_code == 401
    next_code = users_ext._hotp(secret, int(time.time() // 30) + 1)
    assert client.post("/admin/users/jane@test.local/2fa/verify", headers=API, json={"code": next_code}).json()["method"] == "totp"
    assert client.post("/admin/users/jane@test.local/2fa/verify", headers=API, json={"code": codes[0]}).json()["method"] == "recovery"
    assert client.post("/admin/users/jane@test.local/2fa/verify", headers=API, json={"code": codes[0]}).status_code == 401
    client.patch("/admin/users/jane@test.local", headers=API, json={"reset_two_factor": True})
    assert client.get("/admin/users/jane@test.local", headers=API).json()["two_factor"] is False


def test_change_own_password(client, people):
    assert client.post("/admin/users/jane@test.local/password", headers=API, json={"current": "bad", "new": "brand-new-password"}).status_code == 403
    assert client.post("/admin/users/jane@test.local/password", headers=API, json={"current": "jane-password-1", "new": "short"}).status_code == 422
    assert client.post("/admin/users/jane@test.local/password", headers=API, json={"current": "jane-password-1", "new": "brand-new-password"}).status_code == 200
    assert client.post("/admin/users/login", headers=API, json={"address": "jane@test.local", "password": "brand-new-password"}).status_code == 200
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"change_password": False}})
    assert client.post("/admin/users/jane@test.local/password", headers=API, json={"current": "brand-new-password", "new": "another-password-1"}).status_code == 403


def test_own_aliases_only(client, people, mock_mongo):
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"max_aliases": 1}})
    a = client.post("/admin/users/jane@test.local/aliases", headers=API, json={"local": "shop", "label": "Amazon"})
    assert a.status_code == 201 and a.json()["address"] == "shop@test.local" and a.json()["deliver_to"] == "jane@test.local"
    assert client.post("/admin/users/jane@test.local/aliases", headers=API, json={"random": True}).status_code == 403  # limit
    assert client.get("/admin/users/jane@test.local", headers=API).json()["addresses"] == ["jane@test.local", "shop@test.local"]
    # Sam cannot touch Jane's alias
    assert client.patch("/admin/users/sam@example.test/aliases/shop@test.local", headers=API, json={"enabled": False}).status_code == 404
    assert client.delete("/admin/users/sam@example.test/aliases/shop@test.local", headers=API).status_code == 404
    assert client.delete("/admin/users/jane@test.local/aliases/shop@test.local", headers=API).status_code == 200
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"aliases": False}})
    assert client.post("/admin/users/jane@test.local/aliases", headers=API, json={"local": "x"}).status_code == 403


def test_private_smtp_providers_stay_private(client, people, mock_mongo):
    assert client.post("/admin/users/jane@test.local/smtp-providers", headers=API,
                       json={"name": "Mine", "host": "smtp.jane.example", "port": 587}).status_code == 403
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"own_smtp": True, "smtp_providers": []}})
    mine = client.post("/admin/users/jane@test.local/smtp-providers", headers=API,
                       json={"name": "Mine", "host": "smtp.jane.example", "port": 587, "username": "j", "password": "p"}).json()
    assert mine["owner"] == "jane@test.local"
    # Not on the admin's list, not usable by Sam, not the default for anyone
    assert all(p["name"] != "Mine" for p in client.get("/admin/smtp-providers", headers=API).json()["providers"])
    sam = mock_mongo.accounts.find_one({"address": "sam@example.test"})
    assert all(p["name"] != "Mine" for p in users_ext.allowed_providers(sam))
    jane = mock_mongo.accounts.find_one({"address": "jane@test.local"})
    assert [p["name"] for p in users_ext.allowed_providers(jane)] == ["Mine"]
    assert client.delete(f"/admin/users/sam@example.test/smtp-providers/{mine['id']}", headers=API).status_code == 404


def test_sending_rules(client, people, mock_mongo, monkeypatch):
    import bearer_ext
    sent = []

    class FakeSMTP:
        def sendmail(self, frm, to, data):
            sent.append(frm)

        def quit(self):
            pass

    monkeypatch.setattr(bearer_ext, "_open_smtp", lambda p: sent.append(p["name"]) or FakeSMTP())
    msg = {"to": "x@elsewhere.example", "subject": "hi", "text": "hello"}
    # Jane may send as herself
    assert client.post("/admin/send", headers=API, json={**msg, "from_email": "jane@test.local", "as_user": "jane@test.local"}).status_code == 200
    # ...but not as Sam or the boss
    assert client.post("/admin/send", headers=API, json={**msg, "from_email": "boss@test.local", "as_user": "jane@test.local"}).status_code == 403
    # Only through providers she is allowed
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"smtp_providers": [people["other"]]}})
    sent.clear()
    client.post("/admin/send", headers=API, json={**msg, "from_email": "jane@test.local", "as_user": "jane@test.local"})
    assert sent[0] == "Brevo"
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"send": False}})
    assert client.post("/admin/send", headers=API, json={**msg, "from_email": "jane@test.local", "as_user": "jane@test.local"}).status_code == 403
