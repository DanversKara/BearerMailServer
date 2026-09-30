"""NoSQL-operator and odd-type payloads must be refused, never reach a query, and never crash the service."""
import pytest

ADMIN = {"X-API-Key": "test-api-key"}
OPERATORS = [{"$gt": ""}, {"$ne": None}, {"$regex": ".*"}, ["a", "b"], 12345, True]


def make_mailbox(client, address="me@test.local", password="supersecret1"):
    r = client.post("/admin/accounts", json={"address": address, "password": password}, headers=ADMIN)
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("bad", OPERATORS)
def test_login_rejects_operator_payloads(client, bad):
    make_mailbox(client)
    for body in ({"address": bad, "password": "supersecret1"}, {"address": "me@test.local", "password": bad},
                 {"address": bad, "password": bad}):
        r = client.post("/token", json=body)
        assert r.status_code in (401, 422), (body, r.status_code)


def test_login_rejects_non_object_bodies(client):
    for raw in ("[]", '"x"', "1", "null", "not json"):
        r = client.post("/token", content=raw, headers={"Content-Type": "application/json"})
        assert r.status_code == 422


@pytest.mark.parametrize("bad", OPERATORS)
def test_admin_token_and_accounts_ignore_operators(client, bad):
    make_mailbox(client)
    assert client.post("/admin/token", json={"address": bad}, headers=ADMIN).status_code == 404
    assert client.post("/admin/accounts", json={"address": bad, "password": "supersecret1"}, headers=ADMIN).status_code == 422
    assert client.post("/admin/accounts", json={"address": "x@test.local", "password": bad}, headers=ADMIN).status_code == 422
    assert client.patch("/admin/accounts/me@test.local", json={"password": bad}, headers=ADMIN).status_code == 422


def test_batch_ids_must_be_strings(client):
    make_mailbox(client)
    tok = client.post("/token", json={"address": "me@test.local", "password": "supersecret1"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/messages/batch", json={"action": "delete", "message_ids": [{"$ne": None}, 5]}, headers=h)
    assert r.status_code == 422
    r = client.post("/messages/batch", json={"action": {"$gt": ""}, "message_ids": ["5f9d88b9c2a3f10a8c8e4b21"]}, headers=h)
    assert r.status_code in (200, 400, 422)


def test_wildcard_operator_login_does_not_authenticate_anyone(client):
    make_mailbox(client, "a@test.local")
    make_mailbox(client, "b@test.local")
    r = client.post("/token", json={"address": {"$ne": ""}, "password": {"$ne": ""}})
    assert r.status_code in (401, 422) and "token" not in r.text
