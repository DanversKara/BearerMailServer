"""Web app in multi-account mode: who may open, send from and manage what."""

from unittest.mock import Mock
from urllib.parse import unquote

import pytest

from test_app import load_app


class FakeService:
    """Stands in for the mail service's /admin/auth and /admin/users endpoints."""

    def __init__(self):
        self.mode = "multi"
        self.users = {
            "jane@x.test": {"password": "jane-pass-123", "role": "user", "addresses": ["jane@x.test", "shop@x.test"],
                            "permissions": {"send": True, "external_accounts": False, "change_password": True}},
            "boss@x.test": {"password": "boss-pass-123", "role": "admin", "addresses": ["boss@x.test"],
                            "permissions": {"send": True, "external_accounts": True}},
        }
        self.calls = []

    def __call__(self, method, path, **kw):
        self.calls.append((method, path, kw.get("json")))
        resp = Mock()
        resp.status_code = 200
        if path == "/admin/auth/mode":
            resp.json.return_value = {"mode": self.mode}
        elif path == "/admin/users/login":
            body = kw["json"]
            u = self.users.get(body["address"])
            if not u or u["password"] != body["password"]:
                resp.status_code = 401
                resp.json.return_value = {"detail": "Wrong email or password"}
            else:
                resp.json.return_value = self.profile(body["address"])
        elif path.startswith("/admin/users/") and method == "GET" and path.count("/") == 3:
            address = unquote(path.rsplit("/", 1)[1])
            if address in self.users:
                resp.json.return_value = self.profile(address)
            else:
                resp.status_code = 404
                resp.json.return_value = {}
        else:
            resp.json.return_value = {"ok": True}
        return resp

    def profile(self, address):
        u = self.users[address]
        return {"address": address, "role": u["role"], "addresses": u["addresses"], "permissions": u["permissions"],
                "is_active": u.get("is_active", True), "two_factor": False}


@pytest.fixture
def svc():
    return FakeService()


@pytest.fixture
def viewer(monkeypatch, tmp_path, svc):
    module = load_app(monkeypatch, DATA_DIR=str(tmp_path), LOGIN_RATE_LIMIT_MAX="50")
    module.security_reporter.report = Mock()
    module.security_reporter.blocked = Mock(return_value=False)
    module._privacy_cache.update(ts=1e18, value={})
    monkeypatch.setattr(module, "_svc", svc)
    return module


def sign_in(viewer, email, password):
    c = viewer.app.test_client()
    resp = c.post("/login", data={"email": email, "password": password})
    return c, resp


def test_login_page_asks_for_email(viewer):
    assert b'name="email"' in viewer.app.test_client().get("/login").data


def test_user_signs_in_with_mailbox(viewer):
    c, resp = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert resp.status_code == 302
    page = c.get("/").data
    assert b'"role": "user"' in page and b"jane@x.test" in page
    _, bad = sign_in(viewer, "jane@x.test", "wrong")
    assert bad.status_code == 401


def test_shared_password_no_longer_works(viewer):
    _, resp = sign_in(viewer, "", "viewer-pass")
    assert resp.status_code == 401
    _, resp = sign_in(viewer, "admin", "viewer-pass")  # emergency admin is off by default
    assert resp.status_code == 401


def test_emergency_admin_when_enabled(viewer, monkeypatch):
    monkeypatch.setattr(viewer, "ALLOW_EMERGENCY_ADMIN", True)
    c, resp = sign_in(viewer, "admin", "viewer-pass")
    assert resp.status_code == 302
    assert c.get("/api/users").status_code == 200


def test_user_cannot_open_other_mailboxes(viewer, monkeypatch):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    upstream = Mock()
    monkeypatch.setattr(viewer.http_session, "post", upstream)
    monkeypatch.setattr(viewer.http_session, "get", upstream)
    for path in ("/api/inbox/query", "/api/inbox/detail", "/api/inbox/search", "/api/inbox/batch", "/api/inbox/delete",
                 "/api/trash/query", "/api/sent/query", "/api/sent/detail", "/api/inbox/restore"):
        r = c.post(path, json={"email": "boss@x.test", "message_id": "m1", "query": "x", "action": "delete", "message_ids": ["m1"]})
        assert r.status_code == 403, path
    assert c.get("/api/inbox/attachment/m1/a1?email=boss@x.test").status_code == 403
    assert c.get("/api/inbox/source/m1?email=BOSS@x.test").status_code == 403
    upstream.assert_not_called()


def test_user_can_open_own_mailbox_and_alias(viewer, monkeypatch):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    token = Mock(status_code=200)
    token.json.return_value = {"token": "t"}
    listing = Mock(status_code=200)
    listing.json.return_value = {"hydra:member": [], "hydra:totalItems": 0}
    monkeypatch.setattr(viewer.http_session, "post", Mock(return_value=token))
    monkeypatch.setattr(viewer.http_session, "get", Mock(return_value=listing))
    assert c.post("/api/inbox/query", json={"email": "jane@x.test"}).get_json()["success"] is True
    assert c.post("/api/inbox/query", json={"email": "Shop@x.test"}).get_json()["success"] is True


def test_send_is_limited_to_own_addresses_and_tagged(viewer, monkeypatch):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    ok = Mock(status_code=200)
    ok.json.return_value = {"message_id": "x"}
    post = Mock(return_value=ok)
    monkeypatch.setattr(viewer.http_session, "post", post)
    msg = {"to": "a@b.example", "subject": "s", "text": "t"}
    assert c.post("/api/send", json={**msg, "from_email": "boss@x.test"}).status_code == 403
    assert c.post("/api/send", json={**msg, "from_email": "shop@x.test"}).get_json()["success"] is True
    assert post.call_args.kwargs["json"]["as_user"] == "jane@x.test"


def test_user_cannot_use_admin_endpoints(viewer, monkeypatch):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    monkeypatch.setattr(viewer.http_session, "request", Mock())
    for method, path in (("GET", "/api/admin/accounts"), ("GET", "/api/users"), ("POST", "/api/users/mode"),
                         ("POST", "/api/domains"), ("GET", "/api/security/overview"), ("POST", "/api/branding/logo/app_light"),
                         ("GET", "/api/security/external-accounts")):
        assert c.open(path, method=method, json={}).status_code == 403, path
    # External accounts are off for Jane
    assert c.get("/imap/api/accounts").status_code == 403


def test_admin_user_can_manage(viewer, monkeypatch):
    c, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    upstream = Mock(status_code=200)
    upstream.json.return_value = {"accounts": []}
    monkeypatch.setattr(viewer.http_session, "request", Mock(return_value=upstream))
    assert c.get("/api/admin/accounts").status_code == 200
    assert c.get("/api/users").status_code == 200


def test_disabled_user_is_signed_out(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.get("/api/me").status_code == 200
    svc.users["jane@x.test"]["is_active"] = False
    viewer._user_cache.clear()
    assert c.get("/api/me").status_code == 401


def test_switching_back_to_single_ends_personal_sessions(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.get("/api/me").status_code == 200
    svc.mode = "single"
    viewer._mode_cache["ts"] = 0
    assert c.get("/api/me").status_code == 401


def test_mode_is_remembered_if_mail_service_is_down(viewer, monkeypatch):
    viewer.auth_mode(force=True)  # learns "multi"

    def down(*a, **k):
        raise ConnectionError("down")

    monkeypatch.setattr(viewer, "_svc", down)
    viewer._mode_cache.update(mode=None, ts=0)
    assert viewer.auth_mode() == "multi"  # never falls back to the shared password


def test_switching_to_multi_needs_shared_password(monkeypatch, tmp_path):
    single = FakeService()
    single.mode = "single"
    module = load_app(monkeypatch, DATA_DIR=str(tmp_path), LOGIN_RATE_LIMIT_MAX="50")
    module.security_reporter.report = Mock()
    module.security_reporter.blocked = Mock(return_value=False)
    monkeypatch.setattr(module, "_svc", single)
    c = module.app.test_client()
    c.post("/login", data={"password": "viewer-pass"})
    assert c.post("/api/users/mode", json={"mode": "multi", "admin": "boss@x.test", "confirm": "wrong"}).status_code == 403
    assert c.post("/api/users/mode", json={"mode": "multi", "admin": "boss@x.test", "confirm": "viewer-pass"}).status_code == 200
    assert ("POST", "/admin/auth/mode", {"mode": "multi", "admin": "boss@x.test", "password": None}) in single.calls


# ---- privacy between accounts, stealth sign-in, SMTP keys ----

def test_admin_cannot_open_users_mailboxes_directly(viewer, monkeypatch):
    c, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    upstream = Mock()
    monkeypatch.setattr(viewer.http_session, "post", upstream)
    monkeypatch.setattr(viewer.http_session, "get", upstream)
    assert c.post("/api/inbox/query", json={"email": "jane@x.test"}).status_code == 403
    assert c.post("/api/send", json={"from_email": "jane@x.test", "to": "a@b.example", "subject": "s", "text": "t"}).status_code == 403
    upstream.assert_not_called()


def _stealth_into_jane(viewer, svc):
    c, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    svc.calls.clear()
    r = c.post("/api/users/jane@x.test/stealth")
    assert r.status_code == 200, r.get_json()
    return c


def test_stealth_view_is_read_only_and_invisible(viewer, svc, monkeypatch):
    c = _stealth_into_jane(viewer, svc)
    me = c.get("/api/me").get_json()
    assert me["address"] == "jane@x.test" and me["stealth"] is True and me["impersonator"] == "boss@x.test"
    assert me["role"] == "user"
    # Jane is not told: no "last sign-in" update, no new session in her list
    assert not any(path.endswith("/signed-in") for _m, path, _b in svc.calls)
    assert all(s["user"] != "jane@x.test" for s in viewer.security_store.list_sessions())

    token = Mock(status_code=200)
    token.json.return_value = {"token": "t"}
    detail = Mock(status_code=200)
    detail.json.return_value = {"id": "m1", "html": "", "subject": "s"}
    get = Mock(return_value=detail)
    monkeypatch.setattr(viewer.http_session, "post", Mock(return_value=token))
    monkeypatch.setattr(viewer.http_session, "get", get)
    assert c.post("/api/inbox/detail", json={"email": "jane@x.test", "message_id": "m1"}).get_json()["success"] is True
    assert get.call_args.kwargs["params"] == {"peek": 1}  # opening a message does not mark it read

    for method, path, body in (("POST", "/api/send", {"from_email": "jane@x.test", "to": "a@b.example", "subject": "s", "text": "t"}),
                               ("POST", "/api/inbox/delete", {"email": "jane@x.test", "message_id": "m1"}),
                               ("POST", "/api/inbox/batch", {"email": "jane@x.test", "action": "read", "message_ids": ["m1"]}),
                               ("POST", "/api/inbox/tabs/move", {"email": "jane@x.test", "message_ids": ["m1"], "tab": "work"}),
                               ("POST", "/api/inbox/tabs/settings", {"email": "jane@x.test", "add_tab": "Spy"}),
                               ("POST", "/api/me/password", {"current": "x", "new": "y"}),
                               ("POST", "/api/me/2fa/setup", {}), ("POST", "/api/me/relay-keys", {}),
                               ("POST", "/api/me/sessions/revoke-others", {}), ("GET", "/imap/api/accounts", None)):
        assert c.open(path, method=method, json=body).status_code == 403, path
    # Setup pages for admins are closed while viewing as Jane
    assert c.get("/api/users").status_code == 403

    assert c.post("/api/stealth/end").status_code == 200
    back = c.get("/api/me").get_json()
    assert back["address"] == "boss@x.test" and back["stealth"] is False
    assert c.get("/api/users").status_code == 200


def test_only_admins_use_stealth_and_not_on_admins(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.post("/api/users/boss@x.test/stealth").status_code == 403
    svc.users["amy@x.test"] = {"password": "amy-pass-1234", "role": "admin", "addresses": ["amy@x.test"], "permissions": {}}
    b, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    assert b.post("/api/users/amy@x.test/stealth").status_code == 403
    assert b.post("/api/users/boss@x.test/stealth").status_code == 400


def test_stealth_ends_when_admin_loses_admin_role(viewer, svc):
    c = _stealth_into_jane(viewer, svc)
    svc.users["boss@x.test"]["role"] = "user"
    viewer._user_cache.clear()
    assert c.get("/api/me").status_code == 401


def test_emergency_admin_stealth_and_return(viewer, svc, monkeypatch):
    monkeypatch.setattr(viewer, "ALLOW_EMERGENCY_ADMIN", True)
    c, _ = sign_in(viewer, "admin", "viewer-pass")
    assert c.post("/api/users/jane@x.test/stealth").status_code == 200
    assert c.get("/api/me").get_json()["impersonator"] == "emergency admin"
    c.post("/api/stealth/end")
    assert c.get("/api/me").get_json()["kind"] == "emergency"


def test_api_v1_send_uses_smtp_key(viewer, svc, monkeypatch):
    c = viewer.app.test_client()
    assert c.post("/api/v1/send", json={"to": "a@b.example"}).status_code == 401
    r = c.post("/api/v1/send", json={"from": "jane@x.test", "to": ["a@b.example"], "subject": "s", "text": "t"},
               headers={"Authorization": "Bearer bm-abc:bmk_secret"})
    assert r.status_code == 200
    method, path, body = svc.calls[-1]
    assert path == "/admin/relay/send" and body["username"] == "bm-abc" and body["password"] == "bmk_secret"
    assert body["from_email"] == "jane@x.test"


def test_users_manage_only_their_own_keys(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.get("/api/me/relay-keys").status_code == 200
    assert c.post("/api/me/relay-keys", json={"label": "Phone", "owner": "boss@x.test"}).status_code == 200
    method, path, body = svc.calls[-1]
    assert path == "/admin/users/jane%40x.test/relay-keys" or path == "/admin/users/jane@x.test/relay-keys"
    assert "owner" not in body
    assert c.get("/api/admin/relay-keys").status_code == 403


def test_app_passwords_are_personal(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.post("/api/me/app-passwords", json={"label": "Phone", "owner": "boss@x.test"}).status_code == 200
    method, path, body = svc.calls[-1]
    assert "jane" in path and path.endswith("/app-passwords") and body == {"label": "Phone", "by": "jane@x.test"}
    # Turning "app passwords only" on is free; turning it off asks for the password
    assert c.post("/api/me/app-passwords-only", json={"only": True}).status_code == 200
    assert c.post("/api/me/app-passwords-only", json={"only": False, "password": "nope"}).status_code == 403
    assert c.post("/api/me/app-passwords-only", json={"only": False, "password": "jane-pass-123"}).status_code == 200
    # Only admins decide for everyone
    assert c.post("/api/users/app-passwords-required", json={"required": True}).status_code == 403
    b, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    assert b.post("/api/users/app-passwords-required", json={"required": True}).status_code == 200


# ---- Drive, calendar, share links ----

def test_drive_is_always_your_own(viewer, svc):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.get("/api/drive?email=boss@x.test&folder=/Work").status_code == 200
    method, path, _ = svc.calls[-1]
    assert path == "/admin/drive/jane%40x.test" or path == "/admin/drive/jane@x.test"
    c.post("/api/calendar", json={"email": "boss@x.test", "title": "x", "start": "2026-10-01"})
    method, path, body = svc.calls[-1]
    assert "jane" in path and "email" not in body
    c.post("/api/drive/shares", json={"kind": "file", "target_id": "a" * 24})
    assert "jane" in svc.calls[-1][1]


def test_emergency_admin_needs_a_mailbox_for_drive(viewer, monkeypatch):
    monkeypatch.setattr(viewer, "ALLOW_EMERGENCY_ADMIN", True)
    c, _ = sign_in(viewer, "admin", "viewer-pass")
    assert c.get("/api/drive?email=jane@x.test").status_code == 400


def test_upload_is_streamed_to_the_mail_service(viewer, monkeypatch):
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    seen = {}

    def fake_post(url, params=None, data=None, headers=None, timeout=None):
        seen.update(url=url, params=params, body=b"".join(data), headers=headers)
        r = Mock(status_code=201)
        r.json.return_value = {"id": "f1", "name": params["name"]}
        return r

    monkeypatch.setattr(viewer.internal_http, "post", fake_post)
    r = c.post("/api/drive/upload?name=notes.txt&folder=/Docs", data=b"hello drive", headers={"Content-Type": "application/octet-stream", "X-File-Type": "text/plain"})
    assert r.status_code == 200 and r.get_json()["file"]["name"] == "notes.txt"
    assert seen["body"] == b"hello drive" and "jane" in seen["url"] and seen["params"]["content_type"] == "text/plain"
    assert "Content-Length" not in seen["headers"] and seen["params"]["size"] == "11"
    monkeypatch.setattr(viewer, "DRIVE_MAX_FILE_MB", 0)
    big = c.post("/api/drive/upload?name=big", data=b"x" * 2048)
    assert big.status_code == 413


def _share_svc(password=None, kind="file"):
    def fake(method, path, **kw):
        r = Mock(status_code=200)
        if path.endswith("/check"):
            r.status_code = 200 if (kw.get("json") or {}).get("password") == password else 403
            r.json.return_value = {}
        elif path.startswith("/admin/shares/"):
            r.json.return_value = {"code": "Abc12345", "kind": kind, "name": "photo.jpg", "size": 2048, "has_password": bool(password),
                                   "shared_by": "Jane", "expires_at": None,
                                   "event": {"title": "Party", "start": "2026-10-10T18:00:00+00:00", "end": "2026-10-10T20:00:00+00:00", "all_day": False}}
        else:
            r.json.return_value = {}
        return r
    return fake


def test_public_share_page_with_password(viewer, monkeypatch):
    monkeypatch.setattr(viewer, "_svc", _share_svc(password="sesame"))
    body = Mock(status_code=200, headers={"Content-Type": "image/jpeg", "Content-Disposition": 'inline; filename="photo.jpg"', "Content-Length": "4"})
    body.iter_content.return_value = [b"JPEG"]
    monkeypatch.setattr(viewer, "_svc_stream", lambda path, params=None: body)
    c = viewer.app.test_client()  # not signed in
    page = c.get("/s/Abc12345")
    assert page.status_code == 200 and b"protected" in page.data and b"photo.jpg" not in page.data
    assert c.get("/s/Abc12345/download").status_code == 302  # back to the password form
    assert c.post("/s/Abc12345", data={"password": "wrong"}).status_code == 403
    assert c.post("/s/Abc12345", data={"password": "sesame"}).status_code == 302
    assert b"photo.jpg" in c.get("/s/Abc12345").data
    dl = c.get("/s/Abc12345/download")
    assert dl.status_code == 200 and dl.data == b"JPEG" and dl.headers["Content-Disposition"].startswith("attachment")
    assert "sandbox" in dl.headers["Content-Security-Policy"]
    assert c.get("/s/bad!code").status_code == 404


def test_event_share_page(viewer, monkeypatch):
    monkeypatch.setattr(viewer, "_svc", _share_svc(kind="event"))
    page = viewer.app.test_client().get("/s/Abc12345")
    assert page.status_code == 200 and b"Party" in page.data and b".ics" in page.data


def test_share_links_get_a_full_url(viewer, svc, monkeypatch):
    monkeypatch.setattr(viewer, "PUBLIC_URL", "https://mail.example.org")
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")

    def fake(method, path, **kw):
        if "/shares" not in path:
            return svc(method, path, **kw)
        r = Mock(status_code=201 if method == "POST" else 200)
        r.json.return_value = {"code": "Zz12Zz12", "kind": "file"}
        return r

    monkeypatch.setattr(viewer, "_svc", fake)
    assert c.post("/api/drive/shares", json={"kind": "file", "target_id": "a" * 24}).get_json()["url"] == "https://mail.example.org/s/Zz12Zz12"


def test_dmarc_reports_are_admin_only(viewer, svc, monkeypatch):
    upstream = Mock(status_code=200)
    upstream.json.return_value = {"reports": []}
    monkeypatch.setattr(viewer.http_session, "request", Mock(return_value=upstream))
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert c.get("/api/admin/dmarc/summary").status_code == 403
    b, _ = sign_in(viewer, "boss@x.test", "boss-pass-123")
    assert b.get("/api/admin/dmarc/summary?days=30").status_code == 200
    assert b.post("/api/admin/dmarc/import", json={}).status_code == 200


def test_users_only_see_their_granted_domains(viewer, svc, monkeypatch):
    svc.users["jane@x.test"]["domains"] = ["x.test", "extra.test"]
    real_profile = svc.profile
    svc.profile = lambda a: {**real_profile(a), "domains": svc.users[a].get("domains", [])}
    listing = Mock(status_code=200)
    listing.json.return_value = {"hydra:member": [{"domain": d, "isActive": True} for d in ("x.test", "extra.test", "secret.test")]}
    monkeypatch.setattr(viewer.http_session, "get", Mock(return_value=listing))
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")
    assert [d["domain"] for d in c.get("/api/domains").get_json()["domains"]] == ["x.test", "extra.test"]


def test_share_link_uses_the_domains_web_address(viewer, svc, monkeypatch):
    monkeypatch.setattr(viewer, "PUBLIC_URL", "https://old.example.org")
    c, _ = sign_in(viewer, "jane@x.test", "jane-pass-123")

    def fake(method, path, **kw):
        if "/shares" not in path:
            return svc(method, path, **kw)
        r = Mock(status_code=201)
        r.json.return_value = {"code": "Zz12Zz12", "kind": "file", "web_host": "https://mail.new.test"}
        return r

    monkeypatch.setattr(viewer, "_svc", fake)
    assert c.post("/api/drive/shares", json={"kind": "file", "target_id": "a" * 24, "domain": "new.test"}).get_json()["url"] == "https://mail.new.test/s/Zz12Zz12"
