"""Drive, storage quota, share links and calendar."""

from datetime import datetime, timezone

import bcrypt
import pytest

import bearer_ext
import drive_ext

API = {"Authorization": "Bearer test-api-key"}
ICS = b"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//EN
METHOD:REQUEST
BEGIN:VEVENT
UID:meeting-42@example.org
DTSTART:20261015T160000Z
DTEND:20261015T170000Z
SUMMARY:Project review
LOCATION:Room 4
ORGANIZER:mailto:boss@example.org
ATTENDEE:mailto:jane@test.local
END:VEVENT
END:VCALENDAR
"""


@pytest.fixture
def jane(client, mock_mongo):
    now = datetime.now(timezone.utc)
    for addr in ("jane@test.local", "sam@test.local"):
        mock_mongo.accounts.insert_one({"address": addr, "password_hash": bcrypt.hashpw(b"pw-123456789", bcrypt.gensalt(4)).decode(),
                                        "is_active": True, "created_at": now})
    mock_mongo.aliases.insert_one({"address": "shop@test.local", "deliver_to": "jane@test.local", "enabled": True, "created_at": now})
    mid = mock_mongo.messages.insert_one({
        "to_addresses": ["shop@test.local"], "from": {"address": "boss@example.org", "name": "Boss"},
        "to": [{"address": "shop@test.local", "name": ""}], "subject": "Café meeting — agenda", "text": "Hello Jane,\n\nSee you there.",
        "html": "<p>Hello <b>Jane</b></p>", "size": 3000, "created_at": now, "is_deleted": False, "seen": False,
        "attachments": [{"id": "a1", "filename": "invite.ics", "content_type": "text/calendar", "size": len(ICS), "content": ICS},
                        {"id": "a2", "filename": "notes.txt", "content_type": "text/plain", "size": 5, "content": b"notes"}],
    }).inserted_id
    return {"message_id": str(mid)}


def upload(client, owner, name, data, folder="/"):
    r = client.post(f"/admin/drive/{owner}/files", params={"name": name, "folder": folder, "content_type": "text/plain"},
                    headers=API, content=data)
    assert r.status_code == 201, r.text
    return r.json()


def test_upload_list_download_rename_delete(client, jane):
    f = upload(client, "jane@test.local", "report.txt", b"x" * (drive_ext.CHUNK * 2 + 10), folder="/Work")
    assert f["size"] == drive_ext.CHUNK * 2 + 10 and f["folder"] == "/Work"
    same = upload(client, "jane@test.local", "report.txt", b"second", folder="/Work")
    assert same["name"] == "report (1).txt"
    root = client.get("/admin/drive/jane@test.local", headers=API).json()
    assert [x["name"] for x in root["folders"]] == ["Work"] and root["files"] == []
    work = client.get("/admin/drive/jane@test.local", params={"folder": "/Work"}, headers=API).json()
    assert {x["name"] for x in work["files"]} == {"report.txt", "report (1).txt"}
    body = client.get(f"/admin/drive/jane@test.local/files/{f['id']}/content", headers=API)
    assert body.content == b"x" * (drive_ext.CHUNK * 2 + 10) and "attachment" in body.headers["content-disposition"]
    # An alias reaches the same Drive; another mailbox does not
    assert client.get(f"/admin/drive/shop@test.local/files/{f['id']}", headers=API).status_code == 200
    assert client.get(f"/admin/drive/sam@test.local/files/{f['id']}", headers=API).status_code == 404
    moved = client.patch(f"/admin/drive/jane@test.local/files/{f['id']}", headers=API, json={"name": "final.txt", "folder": "/"}).json()
    assert moved["name"] == "final.txt" and moved["folder"] == "/"
    client.post("/admin/drive/jane@test.local/folders/rename", headers=API, json={"path": "/Work", "name": "Job"})
    assert client.get("/admin/drive/jane@test.local", params={"folder": "/Job"}, headers=API).json()["files"][0]["name"] == "report (1).txt"
    assert client.delete("/admin/drive/jane@test.local/folders", params={"path": "/Job"}, headers=API).status_code == 409
    assert client.delete("/admin/drive/jane@test.local/folders", params={"path": "/Job", "recursive": 1}, headers=API).json()["deleted_files"] == 1
    assert client.delete(f"/admin/drive/jane@test.local/files/{f['id']}", headers=API).status_code == 200
    assert client.get("/admin/drive/jane@test.local", headers=API).json()["files"] == []


def test_names_and_folders_are_cleaned(client, jane):
    f = upload(client, "jane@test.local", "../../etc/passwd", b"hi", folder="//a///b/")
    assert "/" not in f["name"] and f["folder"] == "/a/b"
    assert client.post("/admin/drive/jane@test.local/files", params={"name": "x", "folder": "/a/../b"}, headers=API, content=b"1").status_code == 422
    assert client.post("/admin/drive/jane@test.local/files", params={"name": "x", "folder": "/.."}, headers=API, content=b"1").status_code == 422


def test_storage_and_quota(client, jane, mock_mongo):
    s = client.get("/admin/storage/jane@test.local", headers=API).json()
    assert s["mail"] == 3000 and s["drive"] == 0 and s["quota"] == drive_ext.DEFAULT_QUOTA_MB * 1024 * 1024
    client.post("/admin/storage/jane@test.local/quota", headers=API, json={"quota_mb": 1})
    upload(client, "jane@test.local", "small.bin", b"1" * 1000)
    r = client.post("/admin/drive/jane@test.local/files", params={"name": "big.bin"}, headers=API, content=b"1" * (1024 * 1024))
    assert r.status_code == 507
    s = client.get("/admin/storage/jane@test.local", headers=API).json()
    assert s["drive"] == 1000 and s["percent"] > 0
    # A refused upload leaves nothing behind
    assert mock_mongo.drive_files.count_documents({"name": "big.bin"}) == 0
    client.post("/admin/storage/jane@test.local/quota", headers=API, json={"quota_mb": 0})
    assert client.get("/admin/storage/jane@test.local", headers=API).json()["unlimited"] is True


@pytest.mark.parametrize("fmt,magic", [("pdf", b"%PDF"), ("docx", b"PK"), ("eml", b"From:"), ("txt", b"Subject: Caf")])
def test_save_email_to_drive(client, jane, fmt, magic):
    r = client.post("/admin/drive/jane@test.local/from-message", headers=API, json={"message_id": jane["message_id"], "format": fmt})
    assert r.status_code == 201, r.text
    f = r.json()
    assert f["folder"] == "/Saved emails" and f["name"].endswith("." + fmt)
    data = client.get(f"/admin/drive/jane@test.local/files/{f['id']}/content", headers=API).content
    assert data.startswith(magic)
    # Sam cannot save Jane's mail
    assert client.post("/admin/drive/sam@test.local/from-message", headers=API, json={"message_id": jane["message_id"]}).status_code == 404


def test_save_attachment_and_attach_from_drive(client, jane, monkeypatch):
    f = client.post("/admin/drive/jane@test.local/from-attachment", headers=API,
                    json={"message_id": jane["message_id"], "attachment_id": "a2"}).json()
    assert f["name"] == "notes.txt" and f["folder"] == "/Attachments"
    sent = []

    class FakeSMTP:
        def sendmail(self, frm, to, data):
            sent.append(data)

        def quit(self):
            pass

    monkeypatch.setattr(bearer_ext, "_open_smtp", lambda p: FakeSMTP())
    import app as svc
    svc.db.smtp_providers.insert_one({"name": "P", "host": "h", "port": 587, "security": "starttls", "username": "u", "password_enc": "",
                                      "is_default": True, "owner": None, "created_at": datetime.now(timezone.utc)})
    msg = {"to": "x@else.example", "subject": "files", "text": "see attached", "from_email": "jane@test.local", "drive_files": [f["id"]]}
    assert client.post("/admin/send", headers=API, json=msg).status_code == 200
    assert b"notes.txt" in sent[0]
    # Another mailbox's file cannot be attached
    assert client.post("/admin/send", headers=API, json={**msg, "from_email": "sam@test.local"}).status_code == 404


def test_share_links(client, jane):
    f = upload(client, "jane@test.local", "photo.txt", b"pixels")
    open_link = client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "file", "target_id": f["id"]}).json()
    assert len(open_link["code"]) == 8 and open_link["has_password"] is False
    info = client.get(f"/admin/shares/{open_link['code']}", headers=API).json()
    assert info["name"] == "photo.txt" and info["size"] == 6 and "owner" not in info
    assert client.get(f"/admin/shares/{open_link['code']}/content", headers=API).content == b"pixels"
    locked = client.post("/admin/drive/jane@test.local/shares", headers=API,
                         json={"kind": "file", "target_id": f["id"], "password": "sesame", "expires_days": 7}).json()
    assert locked["has_password"] and locked["expires_at"]
    assert client.post(f"/admin/shares/{locked['code']}/check", headers=API, json={"password": "nope"}).status_code == 403
    assert client.post(f"/admin/shares/{locked['code']}/check", headers=API, json={"password": "sesame"}).status_code == 200
    # Sam cannot share Jane's file or turn off her link
    assert client.post("/admin/drive/sam@test.local/shares", headers=API, json={"kind": "file", "target_id": f["id"]}).status_code == 404
    assert client.delete(f"/admin/drive/sam@test.local/shares/{open_link['code']}", headers=API).status_code == 404
    assert client.delete(f"/admin/drive/jane@test.local/shares/{open_link['code']}", headers=API).status_code == 200
    assert client.get(f"/admin/shares/{open_link['code']}", headers=API).status_code == 404
    # Deleting the file turns its links off
    client.delete(f"/admin/drive/jane@test.local/files/{f['id']}", headers=API)
    assert client.get(f"/admin/shares/{locked['code']}", headers=API).status_code == 404
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"share_links": False}})
    g = upload(client, "jane@test.local", "again.txt", b"1")
    assert client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "file", "target_id": g["id"]}).status_code == 403


def test_calendar_crud_and_ics(client, jane):
    e = client.post("/admin/calendar/jane@test.local", headers=API,
                    json={"title": "Dentist", "start": "2026-10-20T09:00:00-07:00", "end": "2026-10-20T10:00:00-07:00",
                          "attendees": "a@b.example, bad-address", "location": "Main St"}).json()
    assert e["start"].startswith("2026-10-20T16:00:00") and e["attendees"] == ["a@b.example"]
    listed = client.get("/admin/calendar/jane@test.local", params={"start": "2026-10-01", "end": "2026-11-01"}, headers=API).json()["events"]
    assert [x["title"] for x in listed] == ["Dentist"]
    assert client.get("/admin/calendar/jane@test.local", params={"start": "2026-11-01", "end": "2026-12-01"}, headers=API).json()["events"] == []
    upd = client.patch(f"/admin/calendar/jane@test.local/{e['id']}", headers=API, json={"title": "Dentist (moved)", "all_day": True, "start": "2026-10-21"}).json()
    assert upd["all_day"] and upd["start"].startswith("2026-10-21T00:00:00") and upd["end"].startswith("2026-10-22")
    ics = client.get(f"/admin/calendar/jane@test.local/{e['id']}/ics", headers=API).text
    assert "BEGIN:VEVENT" in ics and "SUMMARY:Dentist (moved)" in ics and "DTSTART;VALUE=DATE:20261021" in ics
    assert client.get(f"/admin/calendar/sam@test.local/{e['id']}", headers=API).status_code == 404
    assert client.post("/admin/calendar/jane@test.local", headers=API, json={"title": "x", "start": "2026-10-20T10:00:00Z", "end": "2026-10-20T09:00:00Z"}).status_code == 422
    assert client.delete(f"/admin/calendar/jane@test.local/{e['id']}", headers=API).status_code == 200


def test_import_invite_from_email_and_share_event(client, jane):
    r = client.post("/admin/calendar/jane@test.local/from-message", headers=API, json={"message_id": jane["message_id"]}).json()
    assert len(r["imported"]) == 1
    ev = r["imported"][0]
    assert ev["title"] == "Project review" and ev["location"] == "Room 4" and ev["start"].startswith("2026-10-15T16:00:00")
    # Importing again updates instead of duplicating
    client.post("/admin/calendar/jane@test.local/from-message", headers=API, json={"message_id": jane["message_id"]})
    assert len(client.get("/admin/calendar/jane@test.local", headers=API).json()["events"]) == 1
    link = client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "event", "target_id": ev["id"]}).json()
    info = client.get(f"/admin/shares/{link['code']}", headers=API).json()
    assert info["event"]["title"] == "Project review"
    assert b"BEGIN:VCALENDAR" in client.get(f"/admin/shares/{link['code']}/content", headers=API).content


def test_suggestion_when_no_invite(client, jane, mock_mongo):
    mid = mock_mongo.messages.insert_one({"to_addresses": ["jane@test.local"], "from": {"address": "a@b.example", "name": ""},
                                          "subject": "Lunch Friday?", "text": "Noon at the usual place", "attachments": [],
                                          "created_at": datetime.now(timezone.utc)}).inserted_id
    r = client.post("/admin/calendar/jane@test.local/from-message", headers=API, json={"message_id": str(mid)}).json()
    assert r["imported"] == [] and r["suggestion"]["title"] == "Lunch Friday?" and r["suggestion"]["attendees"] == ["a@b.example"]


def test_invite_attached_to_outgoing_mail(client, jane, monkeypatch):
    sent = []

    class FakeSMTP:
        def sendmail(self, frm, to, data):
            sent.append(data)

        def quit(self):
            pass

    monkeypatch.setattr(bearer_ext, "_open_smtp", lambda p: FakeSMTP())
    import app as svc
    svc.db.smtp_providers.insert_one({"name": "P", "host": "h", "port": 587, "security": "starttls", "username": "u", "password_enc": "",
                                      "is_default": True, "owner": None, "created_at": datetime.now(timezone.utc)})
    e = client.post("/admin/calendar/jane@test.local", headers=API, json={"title": "Kickoff", "start": "2026-11-02T15:00:00Z"}).json()
    r = client.post("/admin/send", headers=API, json={"to": "guest@else.example", "subject": "Invite", "text": "Join us",
                                                     "from_email": "jane@test.local", "event_id": e["id"]})
    assert r.status_code == 200, r.text
    raw = sent[0].decode()
    assert "text/calendar" in raw and "method=\"REQUEST\"" in raw.replace("method=REQUEST", 'method="REQUEST"')
    assert client.get(f"/admin/calendar/jane@test.local/{e['id']}", headers=API).json()["attendees"] == ["guest@else.example"]


def test_domains_are_granted_per_user_and_links_use_the_domains_web_address(client, jane, mock_mongo):
    from datetime import datetime, timezone
    for d in ("second.test", "secret.test"):
        mock_mongo.domains.insert_one({"domain": d, "is_active": True, "created_at": datetime.now(timezone.utc)})
    # Only her own domain until the admin grants more
    info = client.get("/admin/users/jane@test.local/aliases", headers=API).json()
    assert info["domains"] == ["test.local"]
    assert client.post("/admin/users/jane@test.local/aliases", headers=API, json={"local": "x", "domain": "secret.test"}).status_code == 403
    client.patch("/admin/users/jane@test.local", headers=API, json={"permissions": {"domains": ["second.test", "nope.test"]}})
    assert client.get("/admin/users/jane@test.local", headers=API).json()["domains"] == ["second.test", "test.local"]
    assert client.post("/admin/users/jane@test.local/aliases", headers=API, json={"local": "x", "domain": "second.test"}).json()["address"] == "x@second.test"
    # Web addresses per domain
    assert client.patch("/admin/domains/test.local", headers=API, json={"web_host": "mail.test.local/"}).json()["web_host"] == "https://mail.test.local"
    assert client.patch("/admin/domains/second.test", headers=API, json={"web_host": "https://web.second.test"}).status_code == 200
    assert client.patch("/admin/domains/secret.test", headers=API, json={"web_host": "https://x.test/path"}).status_code == 422
    client.patch("/admin/domains/secret.test", headers=API, json={"web_host": "https://web.secret.test"})
    hosts = client.get("/admin/drive/jane@test.local/share-hosts", headers=API).json()
    assert hosts["default"] == "test.local" and [h["domain"] for h in hosts["hosts"]] == ["second.test", "test.local"]
    f = upload(client, "jane@test.local", "a.txt", b"1")
    s1 = client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "file", "target_id": f["id"]}).json()
    assert s1["web_host"] == "https://mail.test.local"
    s2 = client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "file", "target_id": f["id"], "domain": "second.test"}).json()
    assert s2["web_host"] == "https://web.second.test"
    assert client.post("/admin/drive/jane@test.local/shares", headers=API, json={"kind": "file", "target_id": f["id"], "domain": "secret.test"}).status_code == 403
    # A domain that is switched off no longer appears in links (the web app falls back to PUBLIC_URL)
    mock_mongo.domains.update_one({"domain": "second.test"}, {"$set": {"is_active": False}})
    listed = client.get("/admin/drive/jane@test.local/shares", headers=API).json()["shares"]
    assert {s["code"]: s["web_host"] for s in listed}[s2["code"]] is None


def test_upload_in_parts_retry_and_finish(client, jane, monkeypatch):
    monkeypatch.setattr(drive_ext, "UPLOAD_PART", 3 * drive_ext.CHUNK)  # small parts for the test
    data = bytes(range(256)) * (drive_ext.CHUNK * 7 // 256) + b"tail"
    base = "/admin/drive/jane@test.local/uploads"
    start = client.post(base, headers=API, json={"name": "big.bin", "folder": "/", "size": len(data)}).json()
    uid, part = start["upload_id"], start["part_size"]
    assert start["parts"] == 3
    # Not visible while uploading
    assert client.get("/admin/drive/jane@test.local", headers=API).json()["files"] == []
    # Part 0, then a retry of part 0 is accepted as a duplicate, a skipped part is refused
    r = client.put(f"{base}/{uid}", params={"part": 0}, headers=API, content=data[:part])
    assert r.json()["received"] == part
    assert client.put(f"{base}/{uid}", params={"part": 0}, headers=API, content=data[:part]).json()["duplicate"]
    assert client.put(f"{base}/{uid}", params={"part": 2}, headers=API, content=b"x").status_code == 409
    # Finishing early is refused
    assert client.post(f"{base}/{uid}/finish", headers=API).status_code == 409
    for i in (1, 2):
        assert client.put(f"{base}/{uid}", params={"part": i}, headers=API, content=data[i * part:(i + 1) * part]).status_code == 200
    f = client.post(f"{base}/{uid}/finish", headers=API).json()
    assert f["name"] == "big.bin" and f["size"] == len(data)
    got = client.get(f"/admin/drive/jane@test.local/files/{f['id']}/content", headers=API)
    assert got.content == data


def test_upload_parts_limits_and_cancel(client, jane, mock_mongo, monkeypatch):
    monkeypatch.setattr(drive_ext, "UPLOAD_PART", drive_ext.CHUNK)
    base = "/admin/drive/jane@test.local/uploads"
    assert client.post(base, headers=API, json={"name": "x", "size": (drive_ext.DRIVE_MAX_FILE_MB + 1) * 1024 * 1024}).status_code == 413
    mock_mongo.accounts.update_one({"address": "jane@test.local"}, {"$set": {"quota_mb": 1}})
    assert client.post(base, headers=API, json={"name": "x", "size": 2 * 1024 * 1024}).status_code == 507
    mock_mongo.accounts.update_one({"address": "jane@test.local"}, {"$unset": {"quota_mb": ""}})
    uid = client.post(base, headers=API, json={"name": "x", "size": 10}).json()["upload_id"]
    assert client.put(f"{base}/{uid}", params={"part": 0}, headers=API, content=b"y" * 11).status_code == 422  # more than declared
    assert client.put(f"{base}/{uid}", params={"part": 0}, headers=API, content=b"y" * (drive_ext.CHUNK + 1)).status_code == 413
    # Someone else's mailbox can't touch it
    assert client.put(f"/admin/drive/sam@test.local/uploads/{uid}", params={"part": 0}, headers=API, content=b"y").status_code == 404
    assert client.delete(f"{base}/{uid}", headers=API).json()["cancelled"]
    assert mock_mongo.drive_files.count_documents({"name": "x"}) == 0


def test_separate_drive_and_mailbox_limits(client, jane, mock_mongo):
    from types import SimpleNamespace
    import asyncio
    from app import MailHandler

    r = client.patch("/admin/users/jane@test.local", headers=API, json={"drive_quota_mb": 1, "mail_quota_mb": 1})
    assert r.status_code == 200 and r.json()["drive_quota_mb"] == 1 and r.json()["mail_quota_mb"] == 1
    assert client.patch("/admin/users/jane@test.local", headers=API, json={"mail_quota_mb": 0}).status_code == 422
    # Drive limit: 1 MB, even though the total quota (5 GB default) has room
    upload(client, "jane@test.local", "small.txt", b"x" * 1000)
    r = client.post("/admin/drive/jane@test.local/files", params={"name": "big.bin", "size": 2 * 1024 * 1024},
                    headers=API, content=b"y" * (2 * 1024 * 1024))
    assert r.status_code == 507 and "Drive limit" in r.json()["detail"]
    u = client.get("/admin/storage/jane@test.local", headers=API).json()
    assert u["drive_quota"] == 1024 * 1024 and u["mail_quota"] == 1024 * 1024 and not u["mail_full"]
    # Drive off (0): nothing can be added
    client.patch("/admin/users/jane@test.local", headers=API, json={"drive_quota_mb": 0})
    assert client.post("/admin/drive/jane@test.local/uploads", headers=API, json={"name": "a", "size": 1}).status_code == 507

    # Mailbox limit: once full, new mail to the mailbox (or its alias) is refused at RCPT
    def rcpt(addr):
        env = SimpleNamespace(rcpt_tos=[], mail_from="x@example.org")
        sess = SimpleNamespace(peer=("127.0.0.1", 2500), rcpt_count=0, mail_from="x@example.org")
        return asyncio.run(MailHandler().handle_RCPT(None, sess, env, addr, []))
    assert rcpt("jane@test.local").startswith("250")
    mock_mongo.messages.insert_one({"to_addresses": ["jane@test.local"], "size": 2 * 1024 * 1024, "subject": "big",
                                    "created_at": datetime.now(timezone.utc), "is_deleted": False})
    assert rcpt("jane@test.local").startswith("552")
    assert rcpt("shop@test.local").startswith("552")
    assert rcpt("sam@test.local").startswith("250")
    # Removing the limit lets mail in again
    client.patch("/admin/users/jane@test.local", headers=API, json={"mail_quota_mb": None})
    assert rcpt("jane@test.local").startswith("250")
