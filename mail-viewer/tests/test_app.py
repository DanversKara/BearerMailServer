import base64
import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))  # app.py imports email_privacy and security from its own folder
MODULE_NAME = "mail_viewer_app_under_test"


def load_app(monkeypatch, **env):
    defaults = {
        "ENVIRONMENT": "development",
        "SECRET_KEY": "test-secret-key",
        "ACCESS_PASSWORD": "viewer-pass",
        "DUCKMAIL_API_KEY": "test-api-key",
        "DUCKMAIL_BASE_URL": "http://mail-service.test",
        "IMAP_MAIL_BASE_URL": "http://imap-mail.test",
        "AUTO_CREATE_ACCOUNTS": "0",
        "LOGIN_RATE_LIMIT_MAX": "2",
        "LOGIN_RATE_LIMIT_WINDOW": "300",
        "SENSITIVE_RATE_LIMIT_MAX": "2",
        "SENSITIVE_RATE_LIMIT_WINDOW": "60",
        "DATA_DIR": tempfile.mkdtemp(prefix="bearermail-viewer-test-"),
    }
    defaults.update(env)
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)

    sys.modules.pop(MODULE_NAME, None)
    spec = importlib.util.spec_from_file_location(MODULE_NAME, APP_DIR / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    return module


@pytest.fixture
def viewer(monkeypatch):
    module = load_app(monkeypatch)
    return module


@pytest.fixture
def client(viewer):
    with viewer.app.test_client() as test_client:
        yield test_client


def login(test_client):
    return test_client.post("/login", data={"password": "viewer-pass"})


def test_login_required_blocks_json(client):
    resp = client.post("/api/inbox/query", json={"email": "user@test.local"})
    assert resp.status_code == 401
    assert resp.get_json()["message"] == "Unauthorized"


def test_login_uses_rate_limit(client):
    assert client.post("/login", data={"password": "bad"}).status_code == 401
    assert client.post("/login", data={"password": "bad"}).status_code == 401
    resp = client.post("/login", data={"password": "bad"})
    assert resp.status_code == 429


def test_rate_limit_ignores_spoofed_forwarded_for(client):
    # One proxy in front: only the LAST X-Forwarded-For entry (added by the proxy) counts.
    for i in range(2):
        client.post("/login", data={"password": "bad"}, headers={"X-Forwarded-For": f"9.9.9.{i}, 5.5.5.5"})
    resp = client.post("/login", data={"password": "bad"}, headers={"X-Forwarded-For": "9.9.9.99, 5.5.5.5"})
    assert resp.status_code == 429


def test_non_ascii_password_is_a_normal_failure(client):
    assert client.post("/login", data={"password": "p\u00e4ss\u2603"}).status_code == 401


def test_logout_requires_post_and_clears_session(client):
    login(client)
    assert client.get("/logout").status_code == 302
    client.post("/logout")
    assert client.get("/", follow_redirects=False).status_code == 302
    assert "/login" in client.get("/", follow_redirects=False).headers["Location"]


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_image_proxy_rejects_private_address(client, viewer, monkeypatch):
    login(client)
    monkeypatch.setattr(viewer.socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 0))])
    resp = client.get("/api/image-proxy?url=http://internal.local/image.png")
    assert resp.status_code == 400


def test_sanitize_email_html_removes_script(viewer):
    html = viewer._sanitize_email_html('<div onclick="alert(1)"><script>alert(1)</script><b>ok</b></div>')
    assert "script" not in html.lower()
    assert "onclick" not in html.lower()
    assert "<b>ok</b>" in html


def test_inbox_query_does_not_auto_create_when_disabled(client, viewer, monkeypatch):
    login(client)
    post = Mock(return_value=Mock(status_code=401))
    monkeypatch.setattr(viewer.http_session, "post", post)

    resp = client.post("/api/inbox/query", json={"email": "new@test.local"})

    assert resp.status_code == 200
    assert resp.get_json()["success"] is False
    assert "No mailbox or alias" in resp.get_json()["message"]
    assert post.call_count == 2  # admin token lookup, then legacy login; nothing is created


def test_inbox_query_auto_create_enabled(monkeypatch):
    module = load_app(monkeypatch, AUTO_CREATE_ACCOUNTS="1")
    module.app.config.update(TESTING=True)
    with module.app.test_client() as test_client:
        login(test_client)
        admin_1, token_resp_1 = Mock(status_code=404), Mock(status_code=401)
        create_resp = Mock(status_code=201)
        admin_2, token_resp_2 = Mock(status_code=404), Mock(status_code=200)
        token_resp_2.json.return_value = {"token": "token-1"}
        module.http_session.post = Mock(side_effect=[admin_1, token_resp_1, create_resp, admin_2, token_resp_2])
        mail_resp = Mock(status_code=200)
        mail_resp.json.return_value = {"hydra:member": [], "hydra:totalItems": 0}
        module.http_session.get = Mock(return_value=mail_resp)

        resp = test_client.post("/api/inbox/query", json={"email": "new@test.local"})

    assert resp.status_code == 200
    assert resp.get_json()["success"] is True
    assert module.http_session.post.call_count == 5


def test_send_requires_api_key(monkeypatch):
    module = load_app(monkeypatch, DUCKMAIL_API_KEY="")
    with module.app.test_client() as test_client:
        login(test_client)
        resp = test_client.post("/api/send", json={})
    assert resp.status_code == 503 and resp.get_json()["success"] is False


def test_sanitize_email_html_moves_style_into_one_clean_block(viewer):
    html = (
        '<style>.a{color:red}</style><p class="a">one</p>'
        '<STYLE type="text/css">.b{color:blue}</STYLE><p class="b">two</p>'
    )
    cleaned = viewer._sanitize_email_html(html)
    # two <style> blocks merge and the CSS no longer shows as body text
    assert cleaned.count("<style>") == 1
    assert cleaned.startswith("<style>")
    assert ".a{color:red}" in cleaned and ".b{color:blue}" in cleaned
    assert "one" in cleaned and "two" in cleaned


def test_sanitize_stylesheet_keeps_media_queries(viewer):
    css = "@media (prefers-color-scheme: dark) { .dark-img { display: block !important; } }"
    out = viewer._sanitize_stylesheet(css)
    assert "@media (prefers-color-scheme: dark)" in out
    assert "display:block !important" in out


def test_sanitize_stylesheet_blocks_external_fetches(viewer):
    css = (
        '@import url("https://evil.test/x.css");'
        '@font-face { font-family: X; src: url(https://evil.test/f.woff); }'
        '.tracker { background: url(https://evil.test/pixel.png); color: red; }'
        '.ok { color: green; }'
    )
    out = viewer._sanitize_stylesheet(css)
    assert "evil.test" not in out
    assert "@import" not in out and "@font-face" not in out
    # the url() declaration is dropped, safe ones stay
    assert "color:red" in out
    assert ".ok{color:green}" in out


def test_sanitize_stylesheet_drops_scripting_and_unknown_properties(viewer):
    css = '.a { width: expression(alert(1)); behavior: url(#x); position: fixed; color: red; }'
    out = viewer._sanitize_stylesheet(css)
    assert "expression" not in out and "behavior" not in out
    assert "position" not in out  # not on the allow-list
    assert "color:red" in out


def test_sanitize_email_html_blocks_style_rawtext_escape(viewer):
    html = '<style>a{color:red}</style x>{color:red}</style><p>body</p>'
    cleaned = viewer._sanitize_email_html(html)
    assert "<img" not in cleaned
    assert "</style x>" not in cleaned
    # a style block must not contain a "<" that could close rawtext early
    style_block = cleaned.split("</style>")[0]
    assert "<" not in style_block[len("<style>"):]


def test_sanitize_email_html_still_drops_script_and_title(viewer):
    html = '<title>t</title><script>var leak = 1;</script><p>three</p><style>.c{color:green}'
    cleaned = viewer._sanitize_email_html(html)
    assert "var leak" not in cleaned
    assert "t</p>" not in cleaned and ">t<" not in cleaned
    assert "color:green" not in cleaned  # an unclosed <style> is dropped entirely
    assert "three" in cleaned


def test_sanitize_email_html_keeps_class_and_id_for_selectors(viewer):
    html = '<style>.hide{display:none}</style><div class="hide" id="pre">preheader</div>'
    cleaned = viewer._sanitize_email_html(html)
    # without a class there is no match target
    assert 'class="hide"' in cleaned
    assert 'id="pre"' in cleaned
    assert ".hide{display:none}" in cleaned


def test_sanitize_email_html_keeps_inline_styles(viewer):
    cleaned = viewer._sanitize_email_html('<p style="color: red;">kept</p>')
    assert "color" in cleaned
    assert "kept" in cleaned


def test_extract_code_finds_six_digits(viewer):
    assert viewer._extract_code("Your verification code is 123456, valid for 5 minutes") == "123456"
    assert viewer._extract_code("Subject", "", "code: 987654") == "987654"


def test_extract_code_returns_none_without_match(viewer):
    assert viewer._extract_code("no digits here") is None
    assert viewer._extract_code("order 1234567 shipped") is None
    assert viewer._extract_code() is None


def test_inbox_detail_includes_extracted_code(client, viewer, monkeypatch):
    login(client)
    token_resp = Mock(status_code=200)
    token_resp.json.return_value = {"token": "token-1"}
    monkeypatch.setattr(viewer.http_session, "post", Mock(return_value=token_resp))
    detail_resp = Mock(status_code=200)
    detail_resp.json.return_value = {"subject": "Verify", "text": "your code is 246810", "html": ""}
    monkeypatch.setattr(viewer.http_session, "get", Mock(return_value=detail_resp))

    resp = client.post("/api/inbox/detail", json={"email": "a@test.local", "message_id": "m1"})

    assert resp.get_json()["detail"]["extracted_code"] == "246810"


def test_inbox_source_returns_404_when_upstream_missing(client, viewer, monkeypatch):
    login(client)
    token_resp = Mock(status_code=200)
    token_resp.json.return_value = {"token": "token-1"}
    monkeypatch.setattr(viewer.http_session, "post", Mock(return_value=token_resp))
    get = Mock(return_value=Mock(status_code=404))
    monkeypatch.setattr(viewer.http_session, "get", get)

    resp = client.get("/api/inbox/source/m1?email=a@test.local")

    assert resp.status_code == 404
    assert resp.get_json()["message"] == "Raw message download is unavailable"
    assert get.call_count == 3  # all three candidate paths were probed


def test_send_rejects_oversized_attachment(monkeypatch):
    module = load_app(monkeypatch, MAX_ATTACHMENT_BYTES="16")
    module.app.config.update(TESTING=True)
    post = Mock()
    module.http_session.post = post
    with module.app.test_client() as test_client:
        login(test_client)
        oversized = base64.b64encode(b"x" * 64).decode()
        resp = test_client.post("/api/send", json={
            "from_email": "a@test.local",
            "to": "b@test.local",
            "subject": "hi",
            "text": "body",
            "attachments": [{"filename": "big.bin", "content": oversized}],
        })

    assert resp.get_json()["success"] is False
    assert "per-file limit" in resp.get_json()["message"]
    post.assert_not_called()


def test_send_rejects_invalid_base64_attachment(monkeypatch):
    module = load_app(monkeypatch)
    module.app.config.update(TESTING=True)
    module.http_session.post = Mock()
    with module.app.test_client() as test_client:
        login(test_client)
        resp = test_client.post("/api/send", json={
            "from_email": "a@test.local",
            "to": "b@test.local",
            "subject": "hi",
            "text": "body",
            "attachments": [{"filename": "bad.bin", "content": "not-base64!!!"}],
        })

    assert resp.get_json()["success"] is False
    assert "not valid base64" in resp.get_json()["message"]


def test_send_forwards_attachments_to_mail_service(monkeypatch):
    module = load_app(monkeypatch)
    module.app.config.update(TESTING=True)
    send_resp = Mock(status_code=200)
    send_resp.json.return_value = {"success": True, "message_id": "<abc@test.local>"}
    post = Mock(return_value=send_resp)
    module.http_session.post = post
    content = base64.b64encode(b"hello").decode()
    with module.app.test_client() as test_client:
        login(test_client)
        resp = test_client.post("/api/send", json={
            "from_email": "a@test.local",
            "to": "b@test.local",
            "subject": "hi",
            "text": "body",
            "attachments": [{"filename": "../../etc/passwd", "content": content}],
        })

    assert resp.get_json()["success"] is True
    assert post.call_args_list[0].args[0].endswith("/admin/send")
    payload = post.call_args_list[0].kwargs["json"]
    assert payload["attachments"] == [{"filename": "passwd", "content": content}]
    assert payload["from_email"] == "a@test.local" and payload["to"] == ["b@test.local"]


def test_payload_too_large_returns_json(monkeypatch):
    module = load_app(monkeypatch, MAX_CONTENT_LENGTH="128")
    module.app.config.update(TESTING=True)
    with module.app.test_client() as test_client:
        login(test_client)
        resp = test_client.post("/api/send", json={"text": "x" * 500})

    assert resp.status_code == 413
    assert resp.get_json()["success"] is False


def test_domain_proxy_masks_internal_exception(client, viewer, monkeypatch):
    login(client)
    monkeypatch.setattr(viewer.http_session, "get", Mock(side_effect=RuntimeError("boom secret")))

    resp = client.get("/api/domains")

    assert resp.status_code == 502
    assert resp.get_json()["message"] == "Could not load domains"


def test_admin_proxy_adds_api_key_and_allowlists(client, viewer, monkeypatch):
    login(client)
    upstream = Mock(status_code=200)
    upstream.json.return_value = {"aliases": []}
    request = Mock(return_value=upstream)
    monkeypatch.setattr(viewer.http_session, "request", request)
    ok = client.get("/api/admin/aliases")
    assert ok.status_code == 200 and ok.get_json() == {"success": True, "aliases": []}
    assert request.call_args.args[:2] == ("GET", "http://mail-service.test/admin/aliases")
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer test-api-key"
    assert client.get("/api/admin/token").status_code == 404
    assert client.get("/api/admin/accounts/../../token").status_code == 404


def test_admin_proxy_requires_login_and_json(client, viewer, monkeypatch):
    assert client.get("/api/admin/aliases").status_code in (302, 401)
    login(client)
    monkeypatch.setattr(viewer.http_session, "request", Mock())
    assert client.post("/api/admin/aliases", data="x=1", content_type="text/plain").status_code == 415


def test_admin_proxy_surfaces_upstream_error(client, viewer, monkeypatch):
    login(client)
    upstream = Mock(status_code=422)
    upstream.json.return_value = {"detail": "Domain 'x.com' is not an active domain. Add it first."}
    monkeypatch.setattr(viewer.http_session, "request", Mock(return_value=upstream))
    resp = client.post("/api/admin/aliases", json={"address": "a@x.com"})
    assert resp.status_code == 422 and "not an active domain" in resp.get_json()["message"]


def test_token_helper_prefers_admin_token(viewer, monkeypatch):
    admin = Mock(status_code=200)
    admin.json.return_value = {"token": "admin-tok"}
    post = Mock(return_value=admin)
    monkeypatch.setattr(viewer.http_session, "post", post)
    token, err = viewer._get_mail_token("alias@test.local")
    assert token == "admin-tok" and err is None and post.call_args.args[0].endswith("/admin/token")


def test_session_cookie_flags(client):
    resp = client.post("/login", data={"password": "viewer-pass"})
    cookie = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_default_backend_is_not_a_third_party_address(monkeypatch):
    monkeypatch.delenv("DUCKMAIL_BASE_URL", raising=False)
    module = load_app(monkeypatch)
    assert "161.33.195.3" not in module.DUCKMAIL_BASE_URL
    assert module.DUCKMAIL_BASE_URL.startswith("http://mail-service")


def test_refuses_public_default_secrets_and_empty_login_password(monkeypatch):
    with pytest.raises(RuntimeError):
        load_app(monkeypatch, SECRET_KEY="mail-viewer-secret-key-change-me")
    with pytest.raises(RuntimeError):
        load_app(monkeypatch, ACCESS_PASSWORD="")


def test_admin_proxy_rejects_dot_segments(client, viewer):
    login(client)
    for path in ("accounts/..", "smtp-providers/../test", "domains/../dns", "accounts/."):
        assert client.get(f"/api/admin/{path}").status_code == 404


def test_image_proxy_checks_every_redirect_hop(client, viewer, monkeypatch):
    login(client)
    seen = []

    class R:
        def __init__(self, status, location=""):
            self.status_code, self.headers, self.ok = status, ({"Location": location} if location else {"Content-Type": "image/png"}), status == 200
            self.url = ""

        def close(self):
            pass

        def iter_content(self, n):
            yield b"png"

    def fake_get(url, **kw):
        seen.append(url)
        assert kw.get("allow_redirects") is False
        return R(302, "http://169.254.169.254/latest/meta-data") if "start" in url else R(200)

    def fake_addrinfo(host, *a, **k):
        ip = "169.254.169.254" if host.startswith("169.") else "93.184.216.34"
        return [(None, None, None, None, (ip, 0))]

    monkeypatch.setattr(viewer.http_session, "get", fake_get)
    monkeypatch.setattr(viewer.socket, "getaddrinfo", fake_addrinfo)
    resp = client.get("/api/image-proxy?url=http://cdn.example.org/start.png")
    assert resp.status_code == 502
    assert seen == ["http://cdn.example.org/start.png"]  # the internal address was never requested


def test_imap_proxy_adds_bridge_token_and_blocks_host_switch(client, viewer, monkeypatch):
    login(client)
    monkeypatch.setattr(viewer, "BRIDGE_TOKEN", "bridge-secret")
    calls = []

    class R:
        status_code, headers, content, text, encoding = 200, {"Content-Type": "application/json"}, b"{}", "{}", "utf-8"

    monkeypatch.setattr(viewer.http_session, "request", lambda **kw: calls.append(kw) or R())
    assert client.get("/imap/api/accounts").status_code == 200
    assert calls[-1]["headers"]["X-Bridge-Token"] == "bridge-secret"
    assert calls[-1]["url"].startswith("http://imap-mail.test/")
    assert client.get("/imap/http://evil.test/x").status_code == 404
