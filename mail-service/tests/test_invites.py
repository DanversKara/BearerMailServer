"""Tests for invite codes and public sign-up (POST /signup)."""

from datetime import datetime, timedelta, timezone

API = {"Authorization": "Bearer test-api-key"}


def _make_invite(client, **kwargs):
    body = {"max_uses": 1, "expires_in_days": 7, "note": "test"}
    body.update(kwargs)
    r = client.post("/admin/invites", headers=API, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_create_invite_defaults(client):
    inv = _make_invite(client)
    assert inv["code"]
    assert len(inv["code"].replace("-", "")) == 16
    assert inv["status"] == "active"
    assert inv["uses"] == 0
    assert inv["uses_left"] == 1
    assert inv["expires_at"]


def test_create_invite_never_expires(client):
    inv = _make_invite(client, expires_in_days=None)
    assert inv["expires_at"] is None


def test_create_invite_validation(client):
    r = client.post("/admin/invites", headers=API, json={"max_uses": 0})
    assert r.status_code == 422
    r = client.post("/admin/invites", headers=API, json={"max_uses": 10001})
    assert r.status_code == 422
    r = client.post("/admin/invites", headers=API, json={"expires_in_days": -1})
    assert r.status_code == 422


def test_invite_admin_auth_required(client):
    r = client.post("/admin/invites", json={})
    assert r.status_code in (401, 403)
    r = client.get("/admin/invites")
    assert r.status_code in (401, 403)


def test_list_invites(client):
    _make_invite(client, note="one")
    _make_invite(client, note="two")
    r = client.get("/admin/invites", headers=API)
    assert r.status_code == 200
    notes = [i["note"] for i in r.json()["invites"]]
    assert "one" in notes and "two" in notes


def test_signup_happy_path(client):
    inv = _make_invite(client)
    r = client.post("/signup", json={
        "code": inv["code"].lower().replace("-", ""),  # normalization: lowercase, no dashes
        "address": "newbie@test.local",
        "password": "a-very-secret-password",
    })
    assert r.status_code == 201, r.text
    assert r.json()["address"] == "newbie@test.local"
    # the new account can sign in
    r = client.post("/token", json={"address": "newbie@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 200


def test_signup_single_use_enforced(client):
    inv = _make_invite(client, max_uses=1)
    r = client.post("/signup", json={"code": inv["code"], "address": "first@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 201
    r = client.post("/signup", json={"code": inv["code"], "address": "second@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 410


def test_signup_multi_use(client):
    inv = _make_invite(client, max_uses=2)
    for who in ("a@test.local", "b@test.local"):
        r = client.post("/signup", json={"code": inv["code"], "address": who, "password": "a-very-secret-password"})
        assert r.status_code == 201, r.text
    r = client.post("/signup", json={"code": inv["code"], "address": "c@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 410
    # list shows it as used up
    r = client.get("/admin/invites", headers=API)
    got = [i for i in r.json()["invites"] if i["code"] == inv["code"]][0]
    assert got["status"] == "used up"
    assert got["uses"] == 2


def test_signup_unknown_code(client):
    r = client.post("/signup", json={"code": "NOPE-NOPE-NOPE-NOPE", "address": "x@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 404


def test_signup_expired_code(client, mock_mongo):
    inv = _make_invite(client, expires_in_days=1)
    mock_mongo.invites.update_one(
        {"code": inv["code"].replace("-", "")},
        {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(hours=1)}},
    )
    r = client.post("/signup", json={"code": inv["code"], "address": "x@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 410
    assert "expired" in r.json()["detail"].lower()


def test_signup_revoked_code(client):
    inv = _make_invite(client)
    r = client.delete(f"/admin/invites/{inv['code']}", headers=API)
    assert r.status_code == 200
    r = client.post("/signup", json={"code": inv["code"], "address": "x@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 410


def test_signup_address_taken(client):
    inv = _make_invite(client, max_uses=5)
    r = client.post("/signup", json={"code": inv["code"], "address": "taken@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 201
    r = client.post("/signup", json={"code": inv["code"], "address": "taken@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 422
    # the failed attempt did not burn a use
    r = client.get("/admin/invites", headers=API)
    got = [i for i in r.json()["invites"] if i["code"] == inv["code"]][0]
    assert got["uses"] == 1


def test_signup_bad_domain(client):
    inv = _make_invite(client, max_uses=5)
    r = client.post("/signup", json={"code": inv["code"], "address": "x@evil.example", "password": "a-very-secret-password"})
    assert r.status_code == 422


def test_signup_reserved_address(client):
    inv = _make_invite(client, max_uses=5)
    r = client.post("/signup", json={"code": inv["code"], "address": "admin@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 422


def test_signup_password_policy(client):
    inv = _make_invite(client, max_uses=5)
    r = client.post("/signup", json={"code": inv["code"], "address": "x@test.local", "password": "short"})
    assert r.status_code == 422
    r = client.post("/signup", json={"code": inv["code"], "address": "x@test.local"})
    assert r.status_code == 422


def test_signup_missing_fields(client):
    r = client.post("/signup", json={})
    assert r.status_code == 422


def _set_mode(client, mode):
    r = client.post("/admin/signup/mode", headers=API, json={"mode": mode})
    assert r.status_code == 200, r.text
    return r.json()["mode"]


def test_signup_mode_defaults_to_invite(client):
    r = client.get("/admin/signup/mode", headers=API)
    assert r.status_code == 200
    assert r.json()["mode"] == "invite"
    r = client.get("/signup/mode")
    assert r.status_code == 200
    assert r.json()["mode"] == "invite"


def test_signup_mode_auth_required(client):
    r = client.get("/admin/signup/mode")
    assert r.status_code in (401, 403)
    r = client.post("/admin/signup/mode", json={"mode": "open"})
    assert r.status_code in (401, 403)


def test_signup_mode_validation(client):
    r = client.post("/admin/signup/mode", headers=API, json={"mode": "everyone"})
    assert r.status_code == 422
    r = client.post("/admin/signup/mode", headers=API, json={})
    assert r.status_code == 422


def test_signup_open_mode_no_code_needed(client):
    assert _set_mode(client, "open") == "open"
    r = client.post("/signup", json={"address": "freestuff@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 201, r.text
    r = client.post("/token", json={"address": "freestuff@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 200
    assert _set_mode(client, "invite") == "invite"


def test_signup_closed_mode_refuses(client):
    assert _set_mode(client, "closed") == "closed"
    inv = _make_invite(client)
    r = client.post("/signup", json={"code": inv["code"], "address": "x@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 403
    r = client.post("/signup", json={"address": "y@test.local", "password": "a-very-secret-password"})
    assert r.status_code == 403
    assert _set_mode(client, "invite") == "invite"


def test_signup_mode_roundtrip(client):
    for mode in ("open", "closed", "invite"):
        assert _set_mode(client, mode) == mode
        r = client.get("/signup/mode")
        assert r.json()["mode"] == mode
