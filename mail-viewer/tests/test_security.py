"""Web app: two-factor sign-in, server-side sessions, headers, block list and the email privacy pass."""

from unittest.mock import Mock

import pytest

from test_app import load_app

import email_privacy
import security as sec


@pytest.fixture
def viewer(monkeypatch, tmp_path):
    module = load_app(monkeypatch, DATA_DIR=str(tmp_path), LOGIN_RATE_LIMIT_MAX="20")
    module.security_reporter.report = Mock()
    module.security_reporter.blocked = Mock(return_value=False)
    module._privacy_cache.update(ts=1e18, value={"strip_link_tracking": True})
    return module


@pytest.fixture
def client(viewer):
    with viewer.app.test_client() as c:
        yield c


def login(c):
    return c.post("/login", data={"password": "viewer-pass"})


# ---------------------------------------------------------------- TOTP

def test_totp_matches_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert sec.totp_now(secret, at=59) == "287082"
    assert sec.totp_match(secret, "287082", at=59) == 1
    assert sec.totp_match(secret, "000000", at=59) is None


def test_qr_is_inline_svg():
    assert sec.qr_svg("otpauth://totp/x?secret=ABC").lstrip().startswith("<svg")


# ---------------------------------------------------------------- sessions

def test_logout_really_ends_the_session(client, viewer):
    login(client)
    cookie = client.get_cookie("session").value
    assert client.get("/").status_code == 200
    client.post("/logout")
    # Replaying the old cookie no longer works, because the server forgot the session.
    client.set_cookie("session", cookie)
    assert client.get("/", follow_redirects=False).status_code == 302


def test_sign_out_other_sessions(viewer):
    a, b = viewer.app.test_client(), viewer.app.test_client()
    login(a)
    login(b)
    assert b.get("/api/security/overview").status_code == 200
    assert a.post("/api/security/sessions/revoke-others").get_json()["ended"] == 1
    assert b.get("/api/security/overview").status_code == 401
    assert a.get("/api/security/overview").status_code == 200


def test_overview_lists_sessions(client):
    login(client)
    data = client.get("/api/security/overview").get_json()
    assert data["two_factor"]["enabled"] is False
    assert len(data["sessions"]) == 1 and data["sessions"][0]["current"] is True


# ---------------------------------------------------------------- two-factor

def _enable_2fa(client):
    setup = client.post("/api/security/2fa/setup").get_json()
    code = sec.totp_now(setup["secret"])
    resp = client.post("/api/security/2fa/enable", json={"code": code, "password": "viewer-pass"})
    assert resp.status_code == 200, resp.get_json()
    return setup["secret"], resp.get_json()["recovery_codes"]


def test_enable_needs_password(client):
    login(client)
    setup = client.post("/api/security/2fa/setup").get_json()
    resp = client.post("/api/security/2fa/enable", json={"code": sec.totp_now(setup["secret"]), "password": "wrong"})
    assert resp.status_code == 403


def test_login_with_two_factor(viewer):
    c = viewer.app.test_client()
    login(c)
    secret, codes = _enable_2fa(c)
    assert len(codes) == 10

    fresh = viewer.app.test_client()
    resp = login(fresh)
    assert resp.status_code == 200 and b'name="code"' in resp.data
    assert fresh.get("/api/security/overview").status_code == 401  # password alone is not enough
    login(fresh)
    assert fresh.post("/login/verify", data={"code": "000000"}).status_code == 401
    ok = fresh.post("/login/verify", data={"code": sec.totp_now(secret)})
    assert ok.status_code == 302
    assert fresh.get("/").status_code == 200

    # The same code cannot be replayed
    again = viewer.app.test_client()
    login(again)
    assert again.post("/login/verify", data={"code": sec.totp_now(secret)}).status_code == 401


def test_recovery_code_works_once(viewer):
    c = viewer.app.test_client()
    login(c)
    _secret, codes = _enable_2fa(c)
    first = viewer.app.test_client()
    login(first)
    assert first.post("/login/verify", data={"code": codes[0]}).status_code == 302
    second = viewer.app.test_client()
    login(second)
    assert second.post("/login/verify", data={"code": codes[0]}).status_code == 401


def test_code_step_expires(viewer, monkeypatch):
    c = viewer.app.test_client()
    login(c)
    secret, _ = _enable_2fa(c)
    fresh = viewer.app.test_client()
    login(fresh)
    with fresh.session_transaction() as s:
        s["pw_ok_at"] = 1.0
    assert fresh.post("/login/verify", data={"code": sec.totp_now(secret)}).status_code == 401


def test_verify_without_password_step_is_refused(client):
    assert client.post("/login/verify", data={"code": "123456"}).status_code == 401


def test_secret_is_encrypted_on_disk(viewer, tmp_path):
    c = viewer.app.test_client()
    login(c)
    secret, _ = _enable_2fa(c)
    assert secret not in (tmp_path / "security.json").read_text()


# ---------------------------------------------------------------- headers, block list

def test_content_security_policy(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "img-src 'self' data: blob:" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp


def test_no_third_party_assets_in_pages(client):
    login(client)
    for page in (client.get("/login").data, client.get("/").data):
        assert b"cdn.jsdelivr.net" not in page
        assert b"fonts.googleapis.com" not in page


def test_blocked_address_gets_403(client, viewer):
    viewer.security_reporter.blocked = Mock(return_value=True)
    assert client.get("/login").status_code == 403


def test_blocklist_proxy_adds_own_address(client, viewer, monkeypatch):
    login(client)
    upstream = Mock(status_code=200)
    upstream.json.return_value = {"ok": True}
    request = Mock(return_value=upstream)
    monkeypatch.setattr(viewer.http_session, "request", request)
    client.post("/api/admin/security/blocklist", json={"ip": "203.0.113.5"}, environ_base={"REMOTE_ADDR": "198.51.100.3"})
    assert request.call_args.kwargs["json"]["protect"] == ["198.51.100.3"]


def test_failed_login_is_reported(client, viewer):
    client.post("/login", data={"password": "nope"})
    viewer.security_reporter.report.assert_called()
    assert viewer.security_reporter.report.call_args.args[0] == "login_failed"


# ---------------------------------------------------------------- email privacy

def test_remote_images_are_held_back_and_trackers_marked(viewer):
    html, report = email_privacy.protect_html(
        '<p>x</p><img src="https://cdn.example.com/a.png" width="600">'
        '<img src="https://t.sendgrid.net/wf/open?u=1" width="1" height="1">'
        '<img src="data:image/png;base64,AAAA">')
    assert 'src="https://' not in html
    assert "data-bm-src=" in html and 'src="data:image/png' in html
    assert report["remote_images"] == 2 and len(report["trackers"]) == 1


def test_inline_css_cannot_load_images():
    html, report = email_privacy.protect_html('<div style="color:red;background:url(https://t.example/p.gif)">x</div>')
    assert "url(" not in html and "color:red" in html
    assert report["css_blocked"] == 1


def test_deceptive_links_flagged_and_tracking_removed():
    html, report = email_privacy.protect_html(
        '<a href="http://198.51.100.7/x">https://www.paypal.com/</a>'
        '<a href="https://shop.example/p?utm_source=n&amp;id=5">Shop</a>'
        '<a href="https://nodejs.org">Node.js</a>'
        '<a href="javascript:alert(1)">x</a>')
    levels = [w["level"] for w in report["link_warnings"]]
    assert levels == ["high"]
    assert "utm_source" not in html and "id=5" in html
    assert "javascript:" not in html
    assert report["links_cleaned"] == 1


def test_detail_endpoint_returns_privacy_report(client, viewer, monkeypatch):
    login(client)
    token = Mock(status_code=200)
    token.json.return_value = {"token": "t"}
    detail = Mock(status_code=200)
    detail.json.return_value = {"id": "m1", "subject": "s", "html": '<img src="https://t.sendgrid.net/wf/open?x=1" width="1" height="1">',
                                "attachments": [{"id": "a1", "filename": "x.exe", "size": 2}],
                                "scan": {"attachments": [{"id": "a1", "risk": "high", "reasons": ["program"], "phones_home": False}]}}
    monkeypatch.setattr(viewer.http_session, "post", Mock(return_value=token))
    monkeypatch.setattr(viewer.http_session, "get", Mock(return_value=detail))
    monkeypatch.setattr(viewer, "_is_proxyable_image_url", lambda url: True)
    data = client.post("/api/inbox/detail", json={"email": "a@test.local", "message_id": "m1"}).get_json()["detail"]
    assert len(data["privacy"]["trackers"]) == 1
    assert data["attachments"][0]["risk"] == "high"
