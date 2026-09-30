import io

from test_app import load_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
SVG_OK = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>'


def _login(client):
    client.post("/login", data={"password": "viewer-pass"})


def _client(monkeypatch, tmp_path):
    module = load_app(monkeypatch, DATA_DIR=str(tmp_path))
    return module.app.test_client()


def test_logo_requires_login(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    r = c.post("/api/branding/logo", data={"logo": (io.BytesIO(PNG), "l.png")}, content_type="multipart/form-data")
    assert r.status_code in (302, 401)


def test_upload_serve_and_show_on_pages(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    assert c.get("/branding/logo").status_code == 404
    _login(c)
    r = c.post("/api/branding/logo", data={"logo": (io.BytesIO(PNG), "l.png")}, content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json()["success"]
    got = c.get("/branding/logo")
    assert got.status_code == 200 and got.mimetype == "image/png" and got.data == PNG
    assert got.headers["X-Content-Type-Options"] == "nosniff"
    assert b"brand-logo" in c.get("/").data
    # public on purpose: the login page shows it before sign-in
    anon = c.application.test_client()
    assert b"/branding/logo" in anon.get("/login").data


def test_rejects_wrong_types_and_scripts(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    _login(c)
    def up(data, name="x"):
        return c.post("/api/branding/logo", data={"logo": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    assert up(b"<html><script>alert(1)</script></html>", "x.png").status_code == 400
    assert up(b"MZ\x90\x00 not an image").status_code == 400
    assert up(b'<svg xmlns="x"><script>alert(1)</script></svg>').status_code == 400
    assert up(b'<svg xmlns="x" onload="alert(1)"></svg>').status_code == 400
    assert up(SVG_OK, "ok.svg").status_code == 200
    assert c.get("/branding/logo").mimetype == "image/svg+xml"


def test_size_limit_and_remove(monkeypatch, tmp_path):
    module = load_app(monkeypatch, DATA_DIR=str(tmp_path), LOGO_MAX_BYTES="100")
    c = module.app.test_client()
    _login(c)
    r = c.post("/api/branding/logo", data={"logo": (io.BytesIO(PNG + b"\x00" * 200), "big.png")}, content_type="multipart/form-data")
    assert r.status_code == 413
    ok = c.post("/api/branding/logo", data={"logo": (io.BytesIO(PNG), "l.png")}, content_type="multipart/form-data")
    assert ok.status_code == 200
    assert c.delete("/api/branding/logo").get_json()["success"]
    assert c.get("/branding/logo").status_code == 404
    assert b"brand-logo" not in c.get("/").data


def test_theme_assets_are_wired(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    _login(c)
    page = c.get("/").data
    assert b"theme.js" in page and b"theme.css" in page
    assert c.get("/static/theme.js").status_code == 200 and c.get("/static/theme.css").status_code == 200
    assert b'id="auto-refresh-toggle" checked' in page


def _up(c, slot, data=PNG):
    return c.post(f"/api/branding/logo/{slot}", data={"logo": (io.BytesIO(data), "l.png")}, content_type="multipart/form-data")


def test_slots_fall_back_and_show_the_right_logo_per_mode(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    _login(c)
    assert _up(c, "app_light").status_code == 200
    page = c.get("/").data
    # only one logo uploaded: both modes use it
    assert page.count(b"/branding/logo/app_light") == 2
    assert _up(c, "app_dark", PNG + b"\x01").status_code == 200
    page = c.get("/").data
    assert b'logo-for-dark" src="/branding/logo/app_dark' in page
    assert b'logo-for-light" src="/branding/logo/app_light' in page
    # login page has no logo of its own: it borrows the same-mode app logo
    login = c.application.test_client().get("/login").data
    assert b'logo-for-dark" src="/branding/logo/app_dark' in login
    assert _up(c, "login_dark", PNG + b"\x02").status_code == 200
    login = c.application.test_client().get("/login").data
    assert b"/branding/logo/login_dark" in login
    status = c.get("/api/branding").get_json()["slots"]
    assert status == {"app_light": True, "app_dark": True, "login_light": False, "login_dark": True}
    assert c.delete("/api/branding/logo/app_dark").get_json()["success"]
    assert c.get("/branding/logo/app_dark").status_code == 404


def test_unknown_slot_rejected_and_no_path_traversal(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    _login(c)
    assert _up(c, "evil").status_code == 404
    assert c.get("/branding/logo/..%2Fapp").status_code == 404
    assert c.get("/branding/logo/logo").status_code == 404


def test_logo_from_earlier_version_still_shows(monkeypatch, tmp_path):
    (tmp_path / "logo.bin").write_bytes(PNG)
    (tmp_path / "logo.type").write_text("image/png")
    c = _client(monkeypatch, tmp_path)
    assert c.get("/branding/logo").status_code == 200
    _login(c)
    assert b"brand-logo" in c.get("/").data


def test_logout_button_and_notify_script_present(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    _login(c)
    page = c.get("/").data
    assert b'action="/logout"' in page and b"notify.js" in page
    assert c.get("/static/notify.js").status_code == 200
