"""Tests for the BearerMail extensions: mailboxes, aliases, DNS, SMTP providers, sending."""

import asyncio
import socket
from email import message_from_bytes
from email.message import EmailMessage
from types import SimpleNamespace

ADMIN = {"X-API-Key": "test-api-key"}


def deliver(rcpt, subject="Hello", sender="someone@external.com"):
    from app import MailHandler

    mail = EmailMessage()
    mail["From"], mail["To"], mail["Subject"] = sender, rcpt, subject
    mail.set_content("body text")
    envelope = SimpleNamespace(content=mail.as_bytes(), rcpt_tos=[rcpt], mail_from=sender)
    session = SimpleNamespace(peer=("127.0.0.1", 25000), rcpt_count=1, mail_from=sender)
    return asyncio.run(MailHandler().handle_DATA(None, session, envelope))


def make_mailbox(client, address="me@test.local", password="supersecret1"):
    r = client.post("/admin/accounts", json={"address": address, "password": password}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return address, password


def bearer(client, address, password):
    tok = client.post("/token", json={"address": address, "password": password}).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


class TestAuth:
    def test_admin_endpoints_need_api_key(self, client):
        for path in ["/admin/accounts", "/admin/aliases", "/admin/smtp-providers", "/admin/connect-info"]:
            assert client.get(path).status_code == 403


class TestMailboxes:
    def test_create_list_reset_delete(self, client):
        addr, pw = make_mailbox(client)
        assert bearer(client, addr, pw)
        assert [a["address"] for a in client.get("/admin/accounts", headers=ADMIN).json()["accounts"]] == [addr]
        assert client.patch(f"/admin/accounts/{addr}", json={"password": "another-pass-9"}, headers=ADMIN).status_code == 200
        assert client.post("/token", json={"address": addr, "password": pw}).status_code == 401
        assert bearer(client, addr, "another-pass-9")
        assert client.delete(f"/admin/accounts/{addr}", headers=ADMIN).status_code == 200
        assert client.get("/admin/accounts", headers=ADMIN).json()["accounts"] == []

    def test_rejects_weak_password_and_unknown_domain(self, client):
        assert client.post("/admin/accounts", json={"address": "a@test.local", "password": "short"}, headers=ADMIN).status_code == 422
        assert client.post("/admin/accounts", json={"address": "a@nope.example", "password": "longenough1"}, headers=ADMIN).status_code == 422


class TestAliasesAndRouting:
    def test_alias_delivers_into_main_mailbox(self, client, mock_mongo):
        addr, pw = make_mailbox(client)
        assert client.post("/admin/aliases", json={"address": "shop@test.local", "deliver_to": addr}, headers=ADMIN).status_code == 201
        assert deliver("shop@test.local", "Order shipped") == "250 Message accepted for delivery"
        stored = mock_mongo.messages.find_one({"subject": "Order shipped"})
        assert set(stored["to_addresses"]) == {"shop@test.local", addr}
        assert stored["to"][0]["address"] == "shop@test.local"
        assert client.get("/messages", headers=bearer(client, addr, pw)).json()["hydra:totalItems"] == 1

    def test_random_alias(self, client):
        addr, _ = make_mailbox(client)
        r = client.post("/admin/aliases", json={"random": True, "domain": "test.local", "prefix": "news",
                                                "deliver_to": addr}, headers=ADMIN)
        assert r.status_code == 201
        assert r.json()["address"].startswith("news-") and r.json()["address"].endswith("@test.local")

    def test_alias_scoped_token_only_sees_alias_mail(self, client):
        addr, _ = make_mailbox(client)
        for a in ("a@test.local", "b@test.local"):
            client.post("/admin/aliases", json={"address": a, "deliver_to": addr}, headers=ADMIN)
        deliver("a@test.local", "for A")
        deliver("b@test.local", "for B")
        tok = client.post("/admin/token", json={"address": "a@test.local"}, headers=ADMIN).json()
        assert tok["kind"] == "alias" and tok["mailbox"] == addr
        msgs = client.get("/messages", headers={"Authorization": f"Bearer {tok['token']}"}).json()
        assert [m["subject"] for m in msgs["hydra:member"]] == ["for A"]
        full = client.post("/admin/token", json={"address": addr}, headers=ADMIN).json()
        assert client.get("/messages", headers={"Authorization": f"Bearer {full['token']}"}).json()["hydra:totalItems"] == 2

    def test_disabled_alias_is_rejected_at_rcpt(self, client):
        from app import MailHandler

        addr, _ = make_mailbox(client)
        client.post("/admin/aliases", json={"address": "off@test.local", "deliver_to": addr}, headers=ADMIN)
        client.patch("/admin/aliases/off@test.local", json={"enabled": False}, headers=ADMIN)
        envelope = SimpleNamespace(rcpt_tos=[], mail_from="x@external.com")
        session = SimpleNamespace(peer=("127.0.0.1", 1), rcpt_count=0, mail_from="x@external.com")
        assert asyncio.run(MailHandler().handle_RCPT(None, session, envelope, "off@test.local", [])).startswith("550")

    def test_domain_catch_all(self, client, mock_mongo):
        addr, _ = make_mailbox(client)
        r = client.patch("/admin/domains/test.local", json={"catch_all_to": addr}, headers=ADMIN)
        assert r.status_code == 200 and r.json()["catch_all_to"] == addr
        deliver("anything-at-all@test.local", "caught")
        assert addr in mock_mongo.messages.find_one({"subject": "caught"})["to_addresses"]

    def test_alias_needs_existing_mailbox(self, client):
        r = client.post("/admin/aliases", json={"address": "x@test.local", "deliver_to": "ghost@test.local"}, headers=ADMIN)
        assert r.status_code == 422


class TestDns:
    def test_records(self, client, monkeypatch):
        import bearer_ext
        monkeypatch.setattr(bearer_ext._cfg, "server_ip", "203.0.113.10")
        data = client.get("/admin/domains/test.local/dns", headers=ADMIN).json()
        by_id = {r["id"]: r for r in data["records"]}
        assert by_id["mx"]["value"] == "mail.test.local" and by_id["mx"]["priority"] == 10
        assert by_id["a"]["value"] == "203.0.113.10"
        assert by_id["spf"]["value"] == "v=spf1 ip4:203.0.113.10 ~all"
        assert by_id["dkim"]["fqdn"] == "bearer._domainkey.test.local"
        assert by_id["dkim"]["value"].startswith("v=DKIM1; k=rsa; p=MII")
        assert by_id["dmarc"]["value"].startswith("v=DMARC1;")

    def test_dkim_key_stable_and_private_key_hidden(self, client):
        a = client.get("/admin/domains/test.local/dns", headers=ADMIN).json()
        b = client.get("/admin/domains/test.local/dns", headers=ADMIN).json()
        assert a["records"][3]["value"] == b["records"][3]["value"]
        assert all("dkim_private_enc" not in d for d in client.get("/admin/domains", headers=ADMIN).json()["domains"])

    def test_spf_includes_linked_provider(self, client):
        client.post("/admin/smtp-providers", json={"name": "Mailjet", "host": "in-v3.mailjet.com", "username": "k",
                                                    "password": "s", "spf_include": "spf.mailjet.com"}, headers=ADMIN)
        spf = [r for r in client.get("/admin/domains/test.local/dns", headers=ADMIN).json()["records"] if r["id"] == "spf"][0]
        assert "include:spf.mailjet.com" in spf["value"]

    def test_check_reports_ok_missing_mismatch(self, client, monkeypatch):
        import bearer_ext
        monkeypatch.setattr(bearer_ext._cfg, "server_ip", "203.0.113.10")
        recs = {r["id"]: r for r in client.get("/admin/domains/test.local/dns", headers=ADMIN).json()["records"]}

        def fake_lookup(name, rtype):
            if rtype == "MX":
                return ["10 mail.test.local"]
            if rtype == "A":
                return ["198.51.100.7"]
            if name.startswith("_dmarc"):
                return []
            if name.startswith("bearer._domainkey"):
                return [recs["dkim"]["value"]]
            return ["v=spf1 ip4:203.0.113.10 ~all"]

        monkeypatch.setattr(bearer_ext, "_lookup", fake_lookup)
        res = client.post("/admin/domains/test.local/dns/check", headers=ADMIN).json()
        assert {r["id"]: r["status"] for r in res["results"]} == {"a": "mismatch", "mx": "ok", "spf": "ok", "dkim": "ok", "dmarc": "missing"}
        assert res["all_ok"] is False

    def test_provider_records_saved_on_domain(self, client):
        rec = {"type": "CNAME", "name": "mailjet._domainkey", "value": "abc.dkim.mailjet.com", "note": "DKIM"}
        assert client.patch("/admin/domains/test.local", json={"extra_dns_records": [rec]}, headers=ADMIN).status_code == 200
        assert client.get("/admin/domains/test.local/dns", headers=ADMIN).json()["provider_records"][0]["value"] == "abc.dkim.mailjet.com"


class TestProviders:
    def test_password_is_encrypted_and_hidden(self, client, mock_mongo):
        r = client.post("/admin/smtp-providers", json={"name": "Mailjet", "host": "in-v3.mailjet.com", "username": "apikey1",
                                                        "password": "s3cret-value"}, headers=ADMIN)
        assert r.status_code == 201
        assert r.json()["has_password"] is True and "password" not in r.json() and r.json()["is_default"] is True
        assert "s3cret-value" not in str(mock_mongo.smtp_providers.find_one({}))
        assert "s3cret-value" not in client.get("/admin/smtp-providers", headers=ADMIN).text

    def test_update_keeps_password_when_blank(self, client, mock_mongo):
        pid = client.post("/admin/smtp-providers", json={"name": "P", "host": "smtp.example.com", "username": "u",
                                                          "password": "pw-1"}, headers=ADMIN).json()["id"]
        before = mock_mongo.smtp_providers.find_one({})["password_enc"]
        client.patch(f"/admin/smtp-providers/{pid}", json={"name": "P2", "password": ""}, headers=ADMIN)
        after = mock_mongo.smtp_providers.find_one({})
        assert after["password_enc"] == before and after["name"] == "P2"

    def test_presets(self, client):
        ids = [p["id"] for p in client.get("/admin/smtp-presets", headers=ADMIN).json()["presets"]]
        assert "mailjet" in ids and "custom" in ids

    def test_delete_clears_references(self, client, mock_mongo):
        addr, _ = make_mailbox(client)
        pid = client.post("/admin/smtp-providers", json={"name": "P", "host": "h.example.com"}, headers=ADMIN).json()["id"]
        client.post("/admin/aliases", json={"address": "z@test.local", "deliver_to": addr, "send_via": pid}, headers=ADMIN)
        client.delete(f"/admin/smtp-providers/{pid}", headers=ADMIN)
        assert mock_mongo.aliases.find_one({"address": "z@test.local"})["send_via"] is None


class LocalSmtp:
    """Real aiosmtpd server on localhost so the actual smtplib path is exercised."""

    def __init__(self, user="apikey", password="secret"):
        from aiosmtpd.controller import Controller
        from aiosmtpd.smtp import AuthResult, LoginPassword

        self.messages = []
        outer = self

        class Handler:
            async def handle_DATA(self, server, session, envelope):
                outer.messages.append(SimpleNamespace(rcpt_tos=list(envelope.rcpt_tos), data=envelope.content))
                return "250 OK"

        def authenticator(server, session, envelope, mechanism, auth_data):
            ok = isinstance(auth_data, LoginPassword) and auth_data.login == user.encode() \
                and auth_data.password == password.encode()
            return AuthResult(success=ok, handled=False)

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.controller = Controller(Handler(), hostname="127.0.0.1", port=self.port, authenticator=authenticator,
                                     auth_required=True, auth_require_tls=False)

    def __enter__(self):
        self.controller.start()
        return self

    def __exit__(self, *a):
        self.controller.stop()


def add_local_provider(client, port, password="secret", **extra):
    return client.post("/admin/smtp-providers", json={"name": "Local", "host": "127.0.0.1", "port": port,
                                                      "security": "none", "username": "apikey", "password": password,
                                                      **extra}, headers=ADMIN)


class TestSending:
    def test_provider_test_button(self, client):
        with LocalSmtp() as smtp:
            pid = add_local_provider(client, smtp.port).json()["id"]
            assert client.post(f"/admin/smtp-providers/{pid}/test", json={}, headers=ADMIN).json()["success"] is True
            bad = add_local_provider(client, smtp.port, password="wrong").json()["id"]
            res = client.post(f"/admin/smtp-providers/{bad}/test", json={}, headers=ADMIN).json()
            assert res["success"] is False and "Authentication failed" in res["message"]

    def test_send_from_alias_and_store_in_sent(self, client):
        addr, pw = make_mailbox(client)
        client.post("/admin/aliases", json={"address": "shop@test.local", "deliver_to": addr, "from_name": "Shop Me"}, headers=ADMIN)
        with LocalSmtp() as smtp:
            add_local_provider(client, smtp.port)
            r = client.post("/admin/send", json={"from_email": "shop@test.local", "to": ["buyer@external.com"],
                                                 "subject": "Re: order", "text": "thanks", "html": "<p>thanks</p>",
                                                 "attachments": [{"filename": "a.txt", "content": "aGk="}]}, headers=ADMIN)
            assert r.status_code == 200, r.text
            sent = message_from_bytes(smtp.messages[0].data)
            assert "Shop Me" in sent["From"] and "shop@test.local" in sent["From"]
            assert smtp.messages[0].rcpt_tos == ["buyer@external.com"]
            assert any(p.get_filename() == "a.txt" for p in sent.walk())
        lst = client.get("/sent", headers=bearer(client, addr, pw)).json()
        assert lst["hydra:totalItems"] == 1 and lst["hydra:member"][0]["from_address"] == "shop@test.local"

    def test_sender_must_be_mailbox_or_alias(self, client):
        make_mailbox(client)
        with LocalSmtp() as smtp:
            add_local_provider(client, smtp.port)
            r = client.post("/admin/send", json={"from_email": "random@test.local", "to": "a@external.com",
                                                 "subject": "s", "text": "t"}, headers=ADMIN)
            assert r.status_code == 422 and "not a mailbox or alias" in r.json()["detail"]
            assert client.post("/admin/send", json={"from_email": "me@gmail.com", "to": "a@external.com",
                                                    "subject": "s", "text": "t"}, headers=ADMIN).status_code == 422

    def test_no_provider_gives_clear_error(self, client):
        addr, _ = make_mailbox(client)
        r = client.post("/admin/send", json={"from_email": addr, "to": "a@external.com", "subject": "s", "text": "t"}, headers=ADMIN)
        assert r.status_code == 400 and "No SMTP provider" in r.json()["detail"]

    def test_alias_specific_provider_wins(self, client):
        addr, _ = make_mailbox(client)
        with LocalSmtp() as default_smtp, LocalSmtp() as alias_smtp:
            add_local_provider(client, default_smtp.port)
            alias_pid = add_local_provider(client, alias_smtp.port).json()["id"]
            client.post("/admin/aliases", json={"address": "vip@test.local", "deliver_to": addr, "send_via": alias_pid}, headers=ADMIN)
            r = client.post("/admin/send", json={"from_email": "vip@test.local", "to": "a@external.com",
                                                 "subject": "s", "text": "t"}, headers=ADMIN)
            assert r.status_code == 200
            assert len(alias_smtp.messages) == 1 and len(default_smtp.messages) == 0

    def test_dkim_signature_added_when_enabled(self, client):
        addr, _ = make_mailbox(client)
        client.get("/admin/domains/test.local/dns", headers=ADMIN)
        with LocalSmtp() as smtp:
            add_local_provider(client, smtp.port, sign_dkim=True)
            r = client.post("/admin/send", json={"from_email": addr, "to": "a@external.com",
                                                 "subject": "signed", "text": "hello"}, headers=ADMIN)
            assert r.status_code == 200, r.text
            assert b"DKIM-Signature:" in smtp.messages[0].data and b"d=test.local" in smtp.messages[0].data

    def test_header_injection_is_rejected(self, client):
        addr, _ = make_mailbox(client)
        with LocalSmtp() as smtp:
            add_local_provider(client, smtp.port)
            r = client.post("/admin/send", json={"from_email": addr, "to": "a@external.com",
                                                 "subject": "hi\r\nBcc: evil@x.com", "text": "t"}, headers=ADMIN)
            assert r.status_code == 422 and smtp.messages == []


class TestConnectInfo:
    def test_connect_info(self, client):
        addr, _ = make_mailbox(client)
        client.post("/admin/smtp-providers", json={"name": "P", "host": "smtp.example.com", "username": "u", "password": "p"}, headers=ADMIN)
        info = client.get("/admin/connect-info", headers=ADMIN).json()
        assert info["imap"]["host"] == "mail.test.local" and info["imap"]["port"] == 993
        assert info["mailboxes"] == [addr]
        assert "password" not in info["smtp_providers"][0]


def test_report_that_is_only_a_zip_becomes_an_attachment(client, mock_mongo):
    """DMARC reports (Google, Microsoft) are a bare application/zip message, not text."""
    import zipfile
    from io import BytesIO
    from app import MailHandler

    make_mailbox(client)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("google.com!test.local!1!2.xml", "<feedback/>")
    raw = (b"From: noreply-dmarc-support@google.com\r\nTo: me@test.local\r\nSubject: Report domain: test.local\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: application/zip; name=\"google.com!test.local!1!2.zip\"\r\n"
           b"Content-Disposition: attachment; filename=\"google.com!test.local!1!2.zip\"\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n") + __import__("base64").encodebytes(buf.getvalue())
    envelope = SimpleNamespace(content=raw, rcpt_tos=["me@test.local"], mail_from="noreply-dmarc-support@google.com")
    session = SimpleNamespace(peer=("127.0.0.1", 25000), rcpt_count=1, mail_from=envelope.mail_from)
    assert asyncio.run(MailHandler().handle_DATA(None, session, envelope)).startswith("250")
    doc = mock_mongo.messages.find_one({"subject": "Report domain: test.local"})
    assert doc["text"] == "" and doc["has_attachments"]
    att = doc["attachments"][0]
    assert att["filename"].endswith(".zip") and att["content"] == buf.getvalue()


def test_each_domain_can_have_its_own_mail_server_name(client, mock_mongo):
    from datetime import datetime, timezone
    mock_mongo.domains.insert_one({"domain": "newdomain.test", "is_active": True, "created_at": datetime.now(timezone.utc)})
    dns = client.get("/admin/domains/newdomain.test/dns", headers=ADMIN).json()
    mx = next(r for r in dns["records"] if r["id"] == "mx")
    assert mx["value"] == "mail.test.local" and dns["mail_host_warning"] == ""  # SMTP_HOSTNAME from the test env
    assert client.patch("/admin/domains/newdomain.test", json={"mail_host": "bad host"}, headers=ADMIN).status_code == 422
    client.patch("/admin/domains/newdomain.test", json={"mail_host": "Mail.NewDomain.test."}, headers=ADMIN)
    dns = client.get("/admin/domains/newdomain.test/dns", headers=ADMIN).json()
    recs = {r["id"]: r for r in dns["records"]}
    assert recs["mx"]["value"] == "mail.newdomain.test" and recs["a"]["name"] == "mail" and recs["a"]["fqdn"] == "mail.newdomain.test"
    assert "newdomain.test" in recs["dmarc"]["value"]
    assert client.get("/admin/connect-info", params={"domain": "newdomain.test"}, headers=ADMIN).json()["imap"]["host"] == "mail.newdomain.test"
    # The old domain is removed: its name is flagged on domains still using it
    mock_mongo.domains.update_many({"domain": {"$in": ["test.local"]}}, {"$set": {"is_active": False}})
    client.patch("/admin/domains/newdomain.test", json={"mail_host": ""}, headers=ADMIN)
    assert "not on any of your active domains" in client.get("/admin/domains/newdomain.test/dns", headers=ADMIN).json()["mail_host_warning"]
