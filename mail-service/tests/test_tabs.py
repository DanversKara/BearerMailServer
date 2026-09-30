"""Inbox tabs: automatic sorting, move-to-tab rules, custom tabs and flood warning."""

import asyncio
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

import tabs_ext


def mail(frm, subject, body="hello", **headers):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = "testuser@test.local"
    m["Subject"] = subject
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(body)
    return m


@pytest.mark.parametrize("frm,subject,body,headers,expected", [
    ("security@verizon.example", "Your SIM card was changed", "", {}, "security"),
    ("no-reply@accounts.google.com", "Security alert: new sign-in on Windows", "", {}, "security"),
    ("noreply@bank.example", "Your password has been changed", "", {}, "security"),
    ("noreply@shop.example", "Your verification code", "", {}, "security"),
    ("noreply@github.com", "[GitHub] Please verify your device", "", {}, "security"),
    ("no-reply@amazon.example", "Was this you? New order placed", "", {}, "security"),
    ("news@shop.example", "Confirm your subscription to the Weekly Digest", "", {"List_Unsubscribe": "<mailto:u@x>"}, "updates"),
    ("deals@store.example", "40% off everything this weekend", "Shop now, free shipping",
     {"List_Unsubscribe": "<mailto:u@x>"}, "promotions"),
    ("notification@facebookmail.com", "Alice commented on your photo", "", {}, "social"),
    ("members@linkedin.com", "You appeared in 5 searches", "", {}, "social"),
    ("list@googlegroups.com", "[rust-users] Borrow checker question", "", {"List_Id": "<rust.googlegroups.com>", "List_Post": "<mailto:x>"}, "forums"),
    ("registrar@state.edu", "Spring registration opens Monday", "", {}, "school"),
    ("ship-confirm@amazon.example", "Your order has shipped", "", {"List_Unsubscribe": "<mailto:u@x>"}, "updates"),
    ("alice@friend.example", "Dinner on Friday?", "Are you free?", {}, "primary"),
])
def test_classify(frm, subject, body, headers, expected):
    m = mail(frm, subject, body or "hello", **headers)
    assert tabs_ext.classify(m, frm, subject, body) == expected


def test_forged_security_mail_is_not_trusted():
    assert tabs_ext.classify(None, "x@evil.example", "Your password was changed", "", verdict="fail") == "primary"


def deliver(msg, to="testuser@test.local"):
    from app import MailHandler
    envelope = SimpleNamespace(content=msg.as_bytes(), rcpt_tos=[to], mail_from="x@example.org")
    session = SimpleNamespace(peer=("127.0.0.1", 25000), rcpt_count=1, mail_from="x@example.org")
    assert asyncio.run(MailHandler().handle_DATA(None, session, envelope)).startswith("250")


def test_tabs_list_move_and_rules(client, auth_header, mock_mongo):
    deliver(mail("alice@friend.example", "Lunch?"))
    deliver(mail("deals@store.example", "50% off sale ends tonight", "shop now free shipping", List_Unsubscribe="<mailto:u@x>"))
    deliver(mail("noreply@carrier.example", "New device activated on your account"))

    tabs = {t["id"]: t for t in client.get("/messages/tabs", headers=auth_header).json()["tabs"]}
    assert tabs["primary"]["total"] == 1 and tabs["promotions"]["total"] == 1 and tabs["security"]["total"] == 1
    assert tabs["security"]["unread"] == 1

    primary = client.get("/messages", params={"tab": "primary"}, headers=auth_header).json()["hydra:member"]
    assert [m["subject"] for m in primary] == ["Lunch?"]
    assert len(client.get("/messages", headers=auth_header).json()["hydra:member"]) == 3  # no tab = everything

    # Favorites for Alice, now and for future mail
    r = client.post("/messages/tabs/move", headers=auth_header,
                    json={"message_ids": [primary[0]["id"]], "tab": "favorites", "rule": "sender"})
    assert r.status_code == 200 and r.json()["new_rules"] == ["alice@friend.example"]
    deliver(mail("alice@friend.example", "Photos"))
    fav = client.get("/messages", params={"tab": "favorites"}, headers=auth_header).json()["hydra:member"]
    assert {m["subject"] for m in fav} == {"Lunch?", "Photos"} and all(m["tab"] == "favorites" for m in fav)
    assert client.get("/messages", params={"tab": "primary"}, headers=auth_header).json()["hydra:totalItems"] == 0

    # Custom tab + domain rule
    r = client.post("/messages/tabs/settings", headers=auth_header, json={"add_tab": "Taxes"}).json()
    tax = r["tab_id"]
    promo = client.get("/messages", params={"tab": "promotions"}, headers=auth_header).json()["hydra:member"][0]
    client.post("/messages/tabs/move", headers=auth_header, json={"message_ids": [promo["id"]], "tab": tax, "rule": "domain"})
    deliver(mail("other@store.example", "Another 20% off"))
    assert client.get("/messages", params={"tab": tax}, headers=auth_header).json()["hydra:totalItems"] == 2

    # Hiding a tab puts its mail back in Primary; removing a custom tab drops its rules
    client.post("/messages/tabs/settings", headers=auth_header, json={"hidden": ["security"]})
    subjects = {m["subject"] for m in client.get("/messages", params={"tab": "primary"}, headers=auth_header).json()["hydra:member"]}
    assert "New device activated on your account" in subjects
    r = client.post("/messages/tabs/settings", headers=auth_header, json={"remove_tab": tax}).json()
    assert all(x["tab"] != tax for x in r["rules"])
    assert client.get("/messages", params={"tab": "promotions"}, headers=auth_header).json()["hydra:totalItems"] == 1

    # Turning tabs off shows everything in one list
    client.post("/messages/tabs/settings", headers=auth_header, json={"enabled": False})
    assert client.get("/messages", params={"tab": "favorites"}, headers=auth_header).json()["hydra:totalItems"] == 5


def test_tabs_are_per_mailbox(client, auth_header, mock_mongo):
    client.post("/accounts", json={"address": "other@test.local", "password": "otherpass123"})
    other = {"Authorization": "Bearer " + client.post("/token", json={"address": "other@test.local", "password": "otherpass123"}).json()["token"]}
    from app import MailHandler
    m = mail("alice@friend.example", "Hi both")
    envelope = SimpleNamespace(content=m.as_bytes(), rcpt_tos=["testuser@test.local", "other@test.local"], mail_from="a@x")
    asyncio.run(MailHandler().handle_DATA(None, SimpleNamespace(peer=("127.0.0.1", 1), rcpt_count=2, mail_from="a@x"), envelope))
    mid = client.get("/messages", headers=auth_header).json()["hydra:member"][0]["id"]
    client.post("/messages/tabs/move", headers=auth_header, json={"message_ids": [mid], "tab": "work"})
    assert client.get("/messages", params={"tab": "work"}, headers=auth_header).json()["hydra:totalItems"] == 1
    assert client.get("/messages", params={"tab": "primary"}, headers=other).json()["hydra:totalItems"] == 1
    # And one mailbox can't move another's mail
    r = client.post("/messages/tabs/move", headers=other, json={"message_ids": ["0" * 24], "tab": "work"})
    assert r.json()["moved"] == 0


def test_old_mail_is_sorted_and_flood_is_reported(client, auth_header, mock_mongo):
    now = datetime.now(timezone.utc)
    for i in range(tabs_ext.FLOOD_THRESHOLD + 5):
        mock_mongo.messages.insert_one({"to_addresses": ["testuser@test.local"], "from": {"address": f"n{i}@list{i}.example"},
                                        "subject": f"Welcome to list {i}", "text": "", "html": "", "created_at": now - timedelta(minutes=5),
                                        "is_deleted": False, "seen": False})
    mock_mongo.messages.insert_one({"to_addresses": ["testuser@test.local"], "from": {"address": "noreply@carrier.example"},
                                    "subject": "Your SIM was moved to a new phone", "text": "", "html": "", "created_at": now,
                                    "is_deleted": False, "seen": False})
    data = client.get("/messages/tabs", headers=auth_header).json()
    assert data["flood"]["count"] >= tabs_ext.FLOOD_THRESHOLD and data["flood"]["security"] == 1
    assert {t["id"]: t["total"] for t in data["tabs"]}["security"] == 1
    assert mock_mongo.security_events.find_one({"kind": "mail_flood"}) is not None


def test_bad_requests(client, auth_header):
    assert client.post("/messages/tabs/move", headers=auth_header, json={"message_ids": [], "tab": "nope"}).status_code == 422
    assert client.post("/messages/tabs/settings", headers=auth_header, json={"remove_tab": "primary"}).status_code == 422
    assert client.post("/messages/tabs/settings", headers=auth_header, json={"add_tab": "  "}).status_code == 422


def test_first_list_sorts_old_mail(client, auth_header, mock_mongo):
    now = datetime.now(timezone.utc)
    for frm, subj in (("alice@friend.example", "Dinner?"), ("noreply@bank.example", "Your password was changed")):
        mock_mongo.messages.insert_one({"to_addresses": ["testuser@test.local"], "from": {"address": frm}, "subject": subj,
                                        "text": "", "html": "", "created_at": now, "is_deleted": False, "seen": False})
    primary = client.get("/messages", params={"tab": "primary"}, headers=auth_header).json()["hydra:member"]
    assert [m["subject"] for m in primary] == ["Dinner?"]
