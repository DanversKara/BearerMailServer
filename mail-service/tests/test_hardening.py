"""Audit fixes: closed registration, alias hijack, disabled accounts, alias-scoped tokens, limits."""
from unittest.mock import patch

ADMIN = {"X-API-Key": "test-api-key"}


def token(client, address, password):
    return client.post("/token", json={"address": address, "password": password}).json()["token"]


def test_public_registration_is_closed_by_default(client):
    with patch("app.ALLOW_PUBLIC_REGISTRATION", False):
        body = {"address": "new@test.local", "password": "password123"}
        assert client.post("/accounts", json=body).status_code == 403
        assert client.post("/accounts", json=body, headers=ADMIN).status_code == 201


def test_cannot_register_an_alias_address_or_reserved_name(client):
    client.post("/admin/accounts", json={"address": "me@test.local", "password": "supersecret1"}, headers=ADMIN)
    client.post("/admin/aliases", json={"address": "shop@test.local", "deliver_to": "me@test.local"}, headers=ADMIN)
    assert client.post("/accounts", json={"address": "shop@test.local", "password": "password123"}).status_code == 422
    assert client.post("/accounts", json={"address": "postmaster@test.local", "password": "password123"}).status_code == 422
    assert client.post("/admin/accounts", json={"address": "shop@test.local", "password": "supersecret1"}, headers=ADMIN).status_code == 409


def test_disabled_or_deleted_account_loses_access_immediately(client):
    client.post("/admin/accounts", json={"address": "me@test.local", "password": "supersecret1"}, headers=ADMIN)
    tok = token(client, "me@test.local", "supersecret1")
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/messages", headers=h).status_code == 200
    client.patch("/admin/accounts/me@test.local", json={"is_active": False}, headers=ADMIN)
    assert client.get("/messages", headers=h).status_code == 401
    assert client.post("/token", json={"address": "me@test.local", "password": "supersecret1"}).status_code == 401


def test_alias_token_cannot_touch_mail_outside_its_alias(client, mock_mongo):
    from bson import ObjectId
    client.post("/admin/accounts", json={"address": "me@test.local", "password": "supersecret1"}, headers=ADMIN)
    client.post("/admin/aliases", json={"address": "shop@test.local", "deliver_to": "me@test.local"}, headers=ADMIN)
    oid = ObjectId()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    mock_mongo.messages.insert_one({"_id": oid, "to_addresses": ["me@test.local"], "subject": "private", "is_deleted": False,
                                    "created_at": now, "updated_at": now, "from_address": "x@y.z", "text": "hi", "html": "", "attachments": [], "seen": False})
    alias_tok = client.post("/admin/token", json={"address": "shop@test.local"}, headers=ADMIN).json()["token"]
    h = {"Authorization": f"Bearer {alias_tok}"}
    assert client.get(f"/messages/{oid}", headers=h).status_code == 404
    assert client.delete(f"/messages/{oid}", headers=h).status_code == 404
    mailbox_tok = token(client, "me@test.local", "supersecret1")
    assert client.get(f"/messages/{oid}", headers={"Authorization": f"Bearer {mailbox_tok}"}).status_code == 200


def test_limit_is_clamped(client):
    client.post("/admin/accounts", json={"address": "me@test.local", "password": "supersecret1"}, headers=ADMIN)
    h = {"Authorization": f"Bearer {token(client, 'me@test.local', 'supersecret1')}"}
    assert client.get("/messages?limit=0", headers=h).status_code == 200
    assert client.get("/messages?limit=-5", headers=h).status_code == 200


def test_changing_provider_host_requires_the_password_again(client):
    pid = client.post("/admin/smtp-providers", json={"name": "P", "host": "smtp.one.test", "username": "u", "password": "secret"}, headers=ADMIN).json()["id"]
    assert client.patch(f"/admin/smtp-providers/{pid}", json={"host": "smtp.evil.test"}, headers=ADMIN).status_code == 422
    assert client.patch(f"/admin/smtp-providers/{pid}", json={"host": "smtp.two.test", "password": "secret2"}, headers=ADMIN).status_code == 200
    assert client.patch(f"/admin/smtp-providers/{pid}", json={"name": "Renamed"}, headers=ADMIN).status_code == 200


def test_api_key_with_non_ascii_is_a_403_not_a_crash():
    import pytest
    from fastapi import HTTPException
    from app import _require_api_key

    class Req:
        headers = {"X-API-Key": "k\u00e9y\u2603", "Authorization": ""}

    with pytest.raises(HTTPException) as exc:
        _require_api_key(Req())
    assert exc.value.status_code == 403
