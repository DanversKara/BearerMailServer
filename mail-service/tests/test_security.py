"""Tests for sender checks, the attachment scan and the security log / block list."""

import asyncio
import io
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import mail_auth
import security_ext

API = {"Authorization": "Bearer test-api-key"}


# ---------------------------------------------------------------------------
# Sender checks
# ---------------------------------------------------------------------------

def test_org_domain_handles_two_label_suffixes():
    assert mail_auth.org_domain("mail.news.example.com") == "example.com"
    assert mail_auth.org_domain("a.b.example.co.uk") == "example.co.uk"
    assert mail_auth.org_domain("example.com") == "example.com"


def test_dmarc_passes_with_aligned_dkim():
    with patch.object(mail_auth, "lookup_dmarc", return_value=({"p": "reject"}, "paypal.com")):
        res = mail_auth.check_dmarc("paypal.com", {"result": "fail", "domain": "x.example"},
                                    {"passed": ["mail.paypal.com"]})
    assert res["result"] == "pass"


def test_dmarc_fails_when_nothing_aligns():
    with patch.object(mail_auth, "lookup_dmarc", return_value=({"p": "reject"}, "paypal.com")):
        res = mail_auth.check_dmarc("paypal.com", {"result": "pass", "domain": "evil.example"}, {"passed": ["evil.example"]})
    assert res["result"] == "fail" and res["policy"] == "reject"


def test_dmarc_strict_alignment():
    with patch.object(mail_auth, "lookup_dmarc", return_value=({"p": "none", "aspf": "s"}, "example.com")):
        res = mail_auth.check_dmarc("example.com", {"result": "pass", "domain": "bounce.example.com"}, {"passed": []})
    assert res["result"] == "fail"


def test_dmarc_none_without_record():
    with patch.object(mail_auth, "lookup_dmarc", return_value=(None, "")):
        assert mail_auth.check_dmarc("example.com", {}, {})["result"] == "none"


def test_local_connections_are_not_checked():
    from email import message_from_bytes
    msg = message_from_bytes(b"From: a@b.example\r\nSubject: x\r\n\r\nhi")
    res = mail_auth.evaluate_sender(b"", msg, "172.18.0.5", "helo", "a@b.example")
    assert res["skipped"] is True
    assert mail_auth.auth_verdict(res) == ""


def test_auth_verdict():
    assert mail_auth.auth_verdict({"dmarc": "fail"}) == "fail"
    assert mail_auth.auth_verdict({"spf": "fail", "dkim": "none", "dmarc": "none"}) == "fail"
    assert mail_auth.auth_verdict({"spf": "fail", "dkim": "pass", "dmarc": "none"}) == "pass"
    assert mail_auth.auth_verdict({"spf": "none", "dkim": "none", "dmarc": "none"}) == "warn"
    assert mail_auth.auth_verdict(None) == ""


# ---------------------------------------------------------------------------
# Attachment scan
# ---------------------------------------------------------------------------

def _zip(files: dict, encrypt_flag=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypt_flag:  # set the "encrypted" bit in every local and central header
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (i := raw.find(sig, start)) != -1:
                raw[i + off] |= 1
                start = i + 4
    return bytes(raw)


def test_scan_disguised_program():
    r = mail_auth.scan_attachment("invoice.pdf.exe", "application/octet-stream", b"MZ\x90\x00")
    assert r["risk"] == "high"
    assert any("disguised" in x for x in r["reasons"])


def test_scan_program_with_harmless_name():
    r = mail_auth.scan_attachment("photo.jpg", "image/jpeg", b"MZ\x90\x00" + b"\x00" * 50)
    assert r["risk"] == "high"


def test_scan_macro_document():
    data = _zip({"[Content_Types].xml": "<x/>", "word/vbaProject.bin": b"\x00"})
    r = mail_auth.scan_attachment("report.docx", "", data)
    assert r["risk"] == "high" and any("macros" in x for x in r["reasons"])


def test_scan_remote_template_phones_home():
    rels = b'<Relationships><Relationship Id="r1" Type="http://schemas/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>'
    data = _zip({"[Content_Types].xml": "<x/>", "word/_rels/settings.xml.rels": rels})
    r = mail_auth.scan_attachment("cv.docx", "", data)
    assert r["phones_home"] and r["risk"] == "high"


def test_scan_remote_image_in_document_phones_home():
    rels = b'<Relationships><Relationship Id="r2" Type="http://schemas/image" Target="https://track.example/p.png" TargetMode="External"/></Relationships>'
    data = _zip({"[Content_Types].xml": "<x/>", "word/_rels/document.xml.rels": rels})
    r = mail_auth.scan_attachment("letter.docx", "", data)
    assert r["phones_home"] and r["risk"] == "medium"


def test_scan_pdf_javascript_and_links():
    assert mail_auth.scan_attachment("a.pdf", "", b"%PDF-1.7\n/OpenAction << /JS (app.alert(1)) >>")["risk"] == "high"
    r = mail_auth.scan_attachment("b.pdf", "", b"%PDF-1.7\n/OpenAction << /S /URI /URI (https://x.example) >>")
    assert r["phones_home"]
    assert mail_auth.scan_attachment("c.pdf", "", b"%PDF-1.7\nplain text")["risk"] == "info"


def test_scan_encrypted_zip_and_program_inside():
    assert mail_auth.scan_attachment("a.zip", "", _zip({"doc.txt": "x"}, encrypt_flag=True))["risk"] == "medium"
    assert mail_auth.scan_attachment("b.zip", "", _zip({"setup.exe": "MZ"}))["risk"] == "high"


def test_scan_html_attachment_phishing():
    r = mail_auth.scan_attachment("login.html", "text/html", b'<html><form><input type="password"></form><img src="https://x.example/p.gif"></html>')
    assert r["risk"] == "high" and r["phones_home"]


def test_scan_plain_files_are_fine():
    assert mail_auth.scan_attachment("notes.txt", "text/plain", b"hello")["risk"] == "info"
    assert mail_auth.scan_attachment("pic.png", "image/png", b"\x89PNG\r\n\x1a\n")["risk"] == "info"


def test_read_receipt_detected():
    from email import message_from_bytes
    msg = message_from_bytes(b"From: a@b.example\r\nDisposition-Notification-To: Boss <boss@b.example>\r\n\r\nhi")
    assert mail_auth.read_receipt_request(msg) == "boss@b.example"


# ---------------------------------------------------------------------------
# Delivery stores the results
# ---------------------------------------------------------------------------

def test_smtp_stores_scan_and_reply_to(client, mock_mongo, test_account):
    from app import MailHandler
    address = test_account[0]
    raw = (
        "From: Shop <news@shop.example>\r\nTo: {0}\r\nSubject: Deal\r\nReply-To: other@elsewhere.example\r\n"
        "Disposition-Notification-To: news@shop.example\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n'
        "--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"bill.pdf.exe\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\nTVqQAA==\r\n--b--\r\n"
    ).format(address).encode()
    envelope = SimpleNamespace(content=raw, rcpt_tos=[address], mail_from="news@shop.example")
    session = SimpleNamespace(peer=("127.0.0.1", 25000), rcpt_count=1, mail_from="news@shop.example", host_name="x")
    assert asyncio.run(MailHandler().handle_DATA(None, session, envelope)).startswith("250")
    doc = mock_mongo.messages.find_one({"subject": "Deal"})
    assert doc["reply_to"] == "other@elsewhere.example"
    assert doc["scan"]["read_receipt_to"] == "news@shop.example"
    assert doc["scan"]["risky_attachments"] == 1
    assert doc["auth"]["skipped"] is True  # local test connection

    token = test_account[2]
    listed = client.get("/messages", headers={"Authorization": f"Bearer {token}"}).json()["hydra:member"][0]
    assert listed["riskyAttachments"] == 1
    detail = client.get(f"/messages/{doc['_id']}", headers={"Authorization": f"Bearer {token}"}).json()
    assert detail["scan"]["attachments"][0]["risk"] == "high"
    assert detail["replyTo"] == "other@elsewhere.example"
    assert mock_mongo.security_events.find_one({"source": "smtp", "kind": "message_received"})


def test_old_messages_are_scanned_when_opened(client, mock_mongo, test_account, sample_message):
    from bson import ObjectId
    mock_mongo.messages.update_one({"_id": ObjectId(sample_message)}, {"$set": {"attachments": [
        {"id": "a1", "filename": "tool.scr", "content_type": "application/octet-stream", "size": 2, "content": b"MZ"}]}})
    detail = client.get(f"/messages/{sample_message}", headers={"Authorization": f"Bearer {test_account[2]}"}).json()
    assert detail["scan"]["attachments"][0]["risk"] == "high"
    assert mock_mongo.messages.find_one({"_id": ObjectId(sample_message)})["scan"]["version"] == mail_auth.SCAN_VERSION


# ---------------------------------------------------------------------------
# Security log, block list, settings
# ---------------------------------------------------------------------------

def test_events_require_api_key(client):
    assert client.get("/admin/security/events").status_code == 403
    assert client.post("/admin/security/events", json={"source": "web", "kind": "login_ok"}).status_code == 403


def test_repeated_events_are_grouped(client, mock_mongo):
    for _ in range(3):
        assert client.post("/admin/security/events", headers=API,
                           json={"source": "imap", "kind": "login_failed", "ip": "203.0.113.5", "user": "a@test.local"}).status_code == 200
    events = client.get("/admin/security/events?source=imap", headers=API).json()["events"]
    assert len(events) == 1 and events[0]["count"] == 3
    assert events[0]["label"] == "Wrong mailbox password"
    summary = client.get("/admin/security/summary", headers=API).json()
    assert summary["sources"]["imap"]["kinds"]["login_failed"] == 3
    assert summary["suspicious_ips"][0]["ip"] == "203.0.113.5"


def test_unknown_event_rejected(client):
    assert client.post("/admin/security/events", headers=API, json={"source": "nope", "kind": "x"}).status_code == 422


def test_level_filter(client):
    client.post("/admin/security/events", headers=API, json={"source": "web", "kind": "login_ok", "ip": "198.51.100.1"})
    client.post("/admin/security/events", headers=API, json={"source": "web", "kind": "login_2fa_failed", "ip": "198.51.100.2"})
    alerts = client.get("/admin/security/events?level=alert", headers=API).json()["events"]
    assert [e["kind"] for e in alerts] == ["login_2fa_failed"]


def test_blocklist_rules(client):
    assert client.post("/admin/security/blocklist", headers=API, json={"ip": "10.0.0.5"}).status_code == 422
    assert client.post("/admin/security/blocklist", headers=API, json={"ip": "not-an-ip"}).status_code == 422
    assert client.post("/admin/security/blocklist", headers=API, json={"ip": "203.0.0.0/8"}).status_code == 422
    assert client.post("/admin/security/blocklist", headers=API,
                       json={"ip": "203.0.113.0/24", "protect": ["203.0.113.9"]}).status_code == 409
    resp = client.post("/admin/security/blocklist", headers=API, json={"ip": "203.0.113.0/24", "reason": "scanner"})
    assert resp.status_code == 200
    assert security_ext.is_blocked("203.0.113.77")
    assert not security_ext.is_blocked("198.51.100.1")
    assert client.delete("/admin/security/blocklist/203.0.113.0/24", headers=API).status_code == 200
    assert not security_ext.is_blocked("203.0.113.77")


def test_settings_validation_and_defaults(client):
    s = client.get("/admin/security/settings", headers=API).json()
    assert s["privacy"]["block_remote_images"] is True
    assert client.patch("/admin/security/settings", headers=API, json={"privacy": {"block_remote_images": "yes"}}).status_code == 422
    s = client.patch("/admin/security/settings", headers=API,
                     json={"privacy": {"trusted_senders": ["News@Shop.example", " @friend.example "]}}).json()
    assert s["privacy"]["trusted_senders"] == ["@friend.example", "news@shop.example"]


def test_new_ip_login_sends_alert(client, mock_mongo):
    client.patch("/admin/security/settings", headers=API,
                 json={"alerts": {"enabled": True, "to": "me@elsewhere.example", "from": "a@test.local"}})
    sent = []
    security_ext._cfg["send_mail"] = lambda frm, to, subject, body: sent.append(subject)
    with patch("threading.Thread") as thread:
        thread.side_effect = lambda target, args, daemon: SimpleNamespace(start=lambda: target(*args))
        security_ext.record("web", "login_ok", ip="198.51.100.10")   # first ever: remembered, no alert
        security_ext.record("web", "login_ok", ip="198.51.100.10")   # known
        security_ext.record("web", "login_ok", ip="192.0.2.44")      # new address
    assert sent == ["BearerMail: new sign-in to the web app"]


def test_imap_sessions_and_kick(client, mock_mongo):
    from datetime import datetime, timezone
    mock_mongo.imap_sessions.insert_one({"_id": "a" * 24, "user": "u@test.local", "ip": "203.0.113.1", "client": "Thunderbird 128",
                                         "login_at": datetime.now(timezone.utc), "last_seen": datetime.now(timezone.utc)})
    sessions = client.get("/admin/security/imap-sessions", headers=API).json()["sessions"]
    assert sessions[0]["client"] == "Thunderbird 128"
    assert client.post(f"/admin/security/imap-sessions/{'a' * 24}/kick", headers=API).status_code == 200
    assert mock_mongo.imap_sessions.find_one({"_id": "a" * 24})["kick"] is True


@pytest.mark.parametrize("helo", ["relay.example"])
def test_relay_attempt_logged(client, mock_mongo, helo):
    from app import MailHandler
    envelope = SimpleNamespace(rcpt_tos=[], mail_from="x@spam.example")
    session = SimpleNamespace(peer=("203.0.113.50", 4000), rcpt_count=0, mail_from="x@spam.example", host_name=helo)
    status = asyncio.run(MailHandler().handle_RCPT(None, session, envelope, "victim@gmail.com", []))
    assert status.startswith("550")
    ev = mock_mongo.security_events.find_one({"kind": "relay_attempt"})
    assert ev["ip"] == "203.0.113.50"
